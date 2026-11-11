from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation_v6_2.integration_v622 import canonical_json_bytes
from tests.test_evaluation_v6_2_release_v624 import _fixture


CLI = Path(__file__).parents[1] / "tools" / "evaluation_v6_2_5_release.py"


def _run_cli(*args: str) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def _run_main(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict[str, object]]:
    from tools import evaluation_v6_2_5_release as cli

    exit_code = cli.main(list(args))
    return exit_code, json.loads(capsys.readouterr().out)


def _assert_no_authority(report: dict[str, object]) -> None:
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["unit_upload_permits"] == []
    assert report["sealed_holdout_accessed"] is False


def _assert_fail_closed(report: dict[str, object]) -> None:
    assert report["state"] == "POPULATION_INFEASIBLE"
    # Argument-parser failures have the smaller CLI error shape; assessment
    # failures include these additional verifier-state bits.
    for field in (
        "external_authentication_verified",
        "semantic_artifact_verification_complete",
        "population_feasible",
        "independence_ground_truth_proven",
    ):
        if field in report:
            assert report[field] is False
    _assert_no_authority(report)


def _assessment_args(fixture: object, replay_db: Path | None = None) -> tuple[str, ...]:
    # These fields are supplied by the completed v6.2.4 fixture helpers.
    return (
        "assess",
        str(fixture.root_path),  # type: ignore[attr-defined]
        str(fixture.release_authorization_path),  # type: ignore[attr-defined]
        str(fixture.bundle_path),  # type: ignore[attr-defined]
        str(fixture.packet_path),  # type: ignore[attr-defined]
        "--challenge-replay-db",
        str(replay_db or fixture.challenge_replay_db_path),  # type: ignore[attr-defined]
        "--expected-challenge-nonce",
        str(fixture.verification_challenge_nonce),  # type: ignore[attr-defined]
    )


def test_inspect_root_is_authority_pending(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    exit_code, report = _run_cli("inspect-root", str(fixture.root_path))

    assert exit_code == 0
    assert report["schema"] == "eval.v6.2.5.release-cli-result"
    assert report["state"] == "RELEASE_ROOT_STRUCTURALLY_VALID_AUTHORITY_PENDING"
    assert report["bootstrap_trust_configured"] is False
    assert report["recruitment_intake_authorized"] is False
    _assert_no_authority(report)


@pytest.mark.parametrize("kind", ["malformed", "noncanonical", "symlink"])
def test_inspect_root_rejects_malformed_noncanonical_and_symlink_inputs(
    tmp_path: Path, kind: str
) -> None:
    fixture = _fixture(tmp_path / "fixture")
    root_path = tmp_path / f"{kind}-root.json"
    if kind == "malformed":
        root_path.write_bytes(b"{")
    elif kind == "noncanonical":
        root_path.write_bytes(canonical_json_bytes(fixture.root) + b"\n")
    else:
        root_path.symlink_to(fixture.root_path)

    exit_code, report = _run_cli("inspect-root", str(root_path))

    assert exit_code == 2
    _assert_fail_closed(report)


def test_assess_requires_authorization_and_replay_db_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, report = _run_main(
        capsys,
        "assess",
        "root.json",
        "authorization.json",
        "bundle.json",
        "packet.json",
    )

    assert exit_code == 2
    _assert_fail_closed(report)


def test_assess_missing_required_file_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fixture = _fixture(tmp_path)
    missing = tmp_path / "missing-authorization.json"
    args = list(_assessment_args(fixture))
    args[2] = str(missing)

    exit_code, report = _run_main(capsys, *args)

    assert exit_code == 2
    _assert_fail_closed(report)


def test_assess_is_permanently_retired_and_does_not_consume_local_replay_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    from evaluation_v6_2 import release_v625

    monkeypatch.setattr(release_v625, "BOOTSTRAP_TRUST_CONFIG", fixture.bootstrap)  # type: ignore[attr-defined]
    args = _assessment_args(fixture)

    first_exit, first = _run_main(capsys, *args)
    second_exit, second = _run_main(capsys, *args)

    assert first_exit == 2
    _assert_fail_closed(first)
    assert "retired" in str(first["failure"])
    assert second_exit == 2
    _assert_fail_closed(second)
    assert second == first
    assert not fixture.challenge_replay_db_path.exists()


@pytest.mark.parametrize("kind", ["malformed", "noncanonical", "symlink"])
def test_assess_rejects_unsafe_authorization_inputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    fixture = _fixture(tmp_path / "fixture")
    from evaluation_v6_2 import release_v625

    monkeypatch.setattr(release_v625, "BOOTSTRAP_TRUST_CONFIG", fixture.bootstrap)  # type: ignore[attr-defined]
    authorization = tmp_path / f"{kind}-authorization.json"
    if kind == "malformed":
        authorization.write_bytes(b"{")
    elif kind == "noncanonical":
        authorization.write_bytes(canonical_json_bytes(fixture.release_authorization) + b"\n")  # type: ignore[attr-defined]
    else:
        authorization.symlink_to(fixture.release_authorization_path)  # type: ignore[attr-defined]

    args = list(_assessment_args(fixture, tmp_path / f"{kind}.sqlite"))
    args[2] = str(authorization)
    exit_code, report = _run_main(capsys, *args)

    assert exit_code == 2
    _assert_fail_closed(report)
