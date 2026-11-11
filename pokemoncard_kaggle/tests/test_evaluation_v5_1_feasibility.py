from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation_v5_1.feasibility import (
    CONSTRAINTS_SCHEMA,
    DECISION_COUNTS_SATISFIED,
    DECISION_INFEASIBLE,
    FeasibilityError,
    audit_feasibility,
    render_json,
    write_report_atomic,
)


CONSTRAINTS = {
    "schema": CONSTRAINTS_SCHEMA,
    "required_independent_families": 20,
    "maximum_final_submissions": 1,
    "reserved_final_submissions": 1,
    "authorized_nonfinal_research_submissions": 0,
    "currently_active_owned_exact_archives": 2,
    "currently_active_owned_independent_components": 1,
    "one_new_independent_family_per_submission_upper_bound": 1,
    "external_exact_pair_intake_available": False,
}
STATUS = {
    "schema": "evaluation_v5_1_status_v1",
    "prospective_required_family_count": 20,
    "prospective_authenticated_independent_family_count": 0,
    "paired_evidence_authenticated_unit_count": 0,
    "prospective_production_verifier_available": False,
    "submission_authorized": False,
}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _inputs(tmp_path: Path, *, constraints: dict[str, object] | None = None, status: dict[str, object] | None = None) -> tuple[Path, Path]:
    constraints_path = tmp_path / "constraints.json"
    status_path = tmp_path / "status.json"
    _write_json(constraints_path, CONSTRAINTS if constraints is None else constraints)
    _write_json(status_path, STATUS if status is None else status)
    return constraints_path, status_path


def test_current_case_is_structurally_infeasible_and_negative_authority(tmp_path: Path) -> None:
    constraints_path, status_path = _inputs(tmp_path)

    report = audit_feasibility(constraints_path, status_path)

    assert report["authenticated_count"] == 0
    assert len(report["constraints_sha256"]) == 64
    assert len(report["status_sha256"]) == 64
    assert report["current_potential_owned_independent_components"] == 1
    assert report["remaining_nonfinal_submission_capacity"] == 0
    assert report[
        "maximum_self_controlled_independent_family_upper_bound_before_reserved_final_submission"
    ] == 1
    assert report["authenticated_shortfall"] == 20
    assert report[
        "structural_shortfall_even_if_current_owned_components_became_authenticated"
    ] == 19
    assert report["minimum_additional_independently_authenticated_external_pairs_needed"] == 19
    assert report["minimum_additional_nonfinal_submissions_needed_if_no_external_pairs"] == 19
    assert report["production_feasible_now"] is False
    assert report["production_feasible_before_final_submission"] is False
    assert report["decision"] == DECISION_INFEASIBLE
    assert all(value is False for key, value in report.items() if key.endswith("authorized") or key.endswith("authority") or key.endswith("gate_open"))
    assert "SUBMIT_AUTHORIZED" not in render_json(report)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("required_independent_families", 21),
        ("currently_active_owned_independent_components", 3),
    ],
)
def test_contradictory_constraint_counts_are_rejected(tmp_path: Path, field: str, value: int) -> None:
    constraints = dict(CONSTRAINTS)
    constraints[field] = value
    constraints_path, status_path = _inputs(tmp_path, constraints=constraints)

    with pytest.raises(FeasibilityError):
        audit_feasibility(constraints_path, status_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prospective_required_family_count", True),
        ("prospective_authenticated_independent_family_count", True),
        ("paired_evidence_authenticated_unit_count", True),
        ("submission_authorized", 1),
    ],
)
def test_boolean_as_int_and_wrong_boolean_types_are_rejected(
    tmp_path: Path, field: str, value: object
) -> None:
    status = dict(STATUS)
    status[field] = value
    constraints_path, status_path = _inputs(tmp_path, status=status)

    with pytest.raises(FeasibilityError):
        audit_feasibility(constraints_path, status_path)


@pytest.mark.parametrize("name", ["sealed", "holdout", "SEALED_archive"])
def test_forbidden_path_components_are_rejected_before_reading(tmp_path: Path, name: str) -> None:
    forbidden = tmp_path / name
    forbidden.mkdir()
    constraints_path = forbidden / "constraints.json"
    status_path = tmp_path / "status.json"
    _write_json(constraints_path, CONSTRAINTS)
    _write_json(status_path, STATUS)

    with pytest.raises(FeasibilityError, match="forbidden"):
        audit_feasibility(constraints_path, status_path)


def test_symlinked_input_and_output_paths_are_rejected(tmp_path: Path) -> None:
    constraints_path, status_path = _inputs(tmp_path)
    linked_status = tmp_path / "linked-status.json"
    linked_status.symlink_to(status_path)

    with pytest.raises(FeasibilityError, match="symlink"):
        audit_feasibility(constraints_path, linked_status)

    report = audit_feasibility(constraints_path, status_path)
    linked_output = tmp_path / "linked-output.json"
    linked_output.symlink_to(tmp_path / "missing-output.json")
    with pytest.raises(FeasibilityError, match="symlink"):
        write_report_atomic(linked_output, report)


def test_mathematically_sufficient_future_counts_never_grant_authority(tmp_path: Path) -> None:
    future_status = {
        "schema": "evaluation_v5_1_status_v1",
        "prospective_required_family_count": 20,
        "prospective_authenticated_independent_family_count": 20,
        "paired_evidence_authenticated_unit_count": 20,
        "prospective_production_verifier_available": True,
        "submission_authorized": True,
    }
    constraints_path, status_path = _inputs(tmp_path, status=future_status)

    report = audit_feasibility(constraints_path, status_path)

    assert report["mathematical_counts_satisfied"] is True
    assert report["decision"] == DECISION_COUNTS_SATISFIED
    assert report["production_feasible_now"] is False
    assert report["production_feasible_before_final_submission"] is False
    for key, value in report.items():
        if key.endswith("authorized") or key.endswith("authority") or key.endswith("gate_open"):
            assert value is False, key
    assert "SUBMIT_AUTHORIZED" not in render_json(report)


def test_output_is_deterministic_and_written_atomically(tmp_path: Path) -> None:
    constraints_path, status_path = _inputs(tmp_path)
    report = audit_feasibility(constraints_path, status_path)
    output = tmp_path / "report.json"

    write_report_atomic(output, report)
    first = output.read_bytes()
    write_report_atomic(output, report)
    second = output.read_bytes()

    assert first == second == render_json(report).encode("ascii")
    assert json.loads(first) == report
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_exact_schema_rejects_unknown_or_missing_keys(tmp_path: Path) -> None:
    constraints = dict(CONSTRAINTS)
    constraints["extra"] = False
    constraints_path, status_path = _inputs(tmp_path, constraints=constraints)
    with pytest.raises(FeasibilityError, match="keys are not exact"):
        audit_feasibility(constraints_path, status_path)

    missing_status = dict(STATUS)
    del missing_status["submission_authorized"]
    constraints_path, status_path = _inputs(tmp_path, status=missing_status)
    with pytest.raises(FeasibilityError, match="missing required keys"):
        audit_feasibility(constraints_path, status_path)


def test_real_status_schema_allows_unrelated_documented_fields(tmp_path: Path) -> None:
    status = {**STATUS, "decision": "NO_SUBMIT_IDENTIFIABILITY", "authority": False}
    constraints_path, status_path = _inputs(tmp_path, status=status)

    report = audit_feasibility(constraints_path, status_path)

    assert report["decision"] == DECISION_INFEASIBLE


def test_wrong_status_schema_is_rejected(tmp_path: Path) -> None:
    status = {**STATUS, "schema": "not-the-v5.1-status-schema"}
    constraints_path, status_path = _inputs(tmp_path, status=status)

    with pytest.raises(FeasibilityError, match="status.schema"):
        audit_feasibility(constraints_path, status_path)
