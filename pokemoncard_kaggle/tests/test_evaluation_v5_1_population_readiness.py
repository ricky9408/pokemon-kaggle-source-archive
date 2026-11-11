from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.evaluation_v5_1_population_readiness import (
    PopulationReadinessError,
    audit_population_readiness,
    render_json,
)


def _write_team(scout: Path, team_id: str, submission_ids: list[str], *, active: list[bool] | None = None) -> None:
    team = scout / f"team_{team_id}"
    team.mkdir(parents=True, exist_ok=True)
    lines = ["id,active\n"]
    for index, submission_id in enumerate(submission_ids):
        enabled = True if active is None else active[index]
        lines.append(f"{submission_id},{str(enabled).lower()}\n")
    (team / "team_submissions.csv").write_text("".join(lines), encoding="ascii")


def test_twenty_shadow_accounts_do_not_establish_production_population(tmp_path: Path) -> None:
    scout = tmp_path / "scout"
    scout.mkdir()
    for index in range(20):
        _write_team(scout, str(1000 + index), [str(5000 + index)])

    report = audit_population_readiness([scout])

    assert report["distinct_team_account_id_count"] == 20
    assert report["active_submission_id_count"] == 20
    assert report["active_submission_row_count"] == 20
    assert report["team_directory_count"] == 20
    assert report["shadow_account_cluster_count"] == 20
    assert report["shadow_population_feasible"] is True
    assert report["shadow_evidence_use"] == "VETO_ONLY_NON_AUTHORITATIVE"
    assert report["production_verified_family_count"] == 0
    assert report["production_population_feasible"] is False
    assert report["required_family_count"] == 20
    assert report["required_games_per_family"] == 200
    assert report["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert report["authority"] is False
    assert report["holdout_access_authorized"] is False
    assert report["submission_authorized"] is False


def test_counts_are_distinct_across_multiple_scouts_and_active_rows_only(tmp_path: Path) -> None:
    first = tmp_path / "first_scout"
    second = tmp_path / "second_scout"
    first.mkdir()
    second.mkdir()
    _write_team(first, "42", ["100", "101"], active=[True, False])
    _write_team(second, "42", ["100", "102"], active=[True, True])
    _write_team(second, "43", ["103"])

    report = audit_population_readiness([second, first])

    assert report["distinct_team_account_ids"] == ["42", "43"]
    assert report["active_submission_ids"] == ["100", "102", "103"]
    assert report["active_submission_row_count"] == 4
    assert report["team_submissions_file_count"] == 3


def test_json_is_deterministic_and_does_not_read_outside_explicit_scout(tmp_path: Path) -> None:
    scout = tmp_path / "scout"
    scout.mkdir()
    _write_team(scout, "7", ["70"])
    outside = tmp_path / "outside"
    outside.mkdir()
    _write_team(outside, "999", ["9990"])

    first = audit_population_readiness([scout])
    second = audit_population_readiness([scout])

    assert render_json(first) == render_json(second)
    assert "9990" not in first["active_submission_ids"]
    assert json.loads(render_json(first)) == first


@pytest.mark.parametrize("kind", ["symlink", "forbidden", "escape"])
def test_unsafe_scout_inputs_fail_closed(tmp_path: Path, kind: str) -> None:
    if kind == "symlink":
        real = tmp_path / "real_scout"
        real.mkdir()
        _write_team(real, "1", ["10"])
        scout = tmp_path / "scout_link"
        scout.symlink_to(real, target_is_directory=True)
    elif kind == "forbidden":
        scout = tmp_path / "sealed_scout"
        scout.mkdir()
    else:
        scout = tmp_path / "missing" / ".." / "scout"

    with pytest.raises(PopulationReadinessError):
        audit_population_readiness([scout])


def test_symlink_inside_scout_is_rejected(tmp_path: Path) -> None:
    scout = tmp_path / "scout"
    scout.mkdir()
    outside = tmp_path / "outside.csv"
    outside.write_text("id\n123\n", encoding="ascii")
    (scout / "team_1").mkdir()
    (scout / "team_1" / "team_submissions.csv").symlink_to(outside)

    with pytest.raises(PopulationReadinessError, match="symlink"):
        audit_population_readiness([scout])
