from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_sha256
from tests.test_evaluation_v6_3_hybrid_trust import _profile_fixture


CLI = Path(__file__).parents[1] / "tools" / "evaluation_v6_3_status.py"


def _run(*args: str) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def _assert_zero_authority(report: dict[str, object]) -> None:
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["permits"] == []
    assert report["calibration_slots_remaining"] == 16
    assert report["production_slots_remaining"] == 1


def test_status_is_external_evidence_absent_and_zero_authority() -> None:
    code, report = _run("status")
    assert code == 2
    assert report["state"] == "V6_3_HYBRID_PROFILE_IMPLEMENTED_EXTERNAL_EVIDENCE_ABSENT"
    _assert_zero_authority(report)


def test_valid_candidate_profile_is_structural_only(tmp_path: Path) -> None:
    profile, _, _ = _profile_fixture()
    path = tmp_path / "candidate-profile.json"
    path.write_bytes(canonical_json_bytes(profile))
    code, report = _run("assess-profile", str(path), "--expected-sha256", canonical_sha256(profile))
    assert code == 0
    assert report["hybrid_profile_structurally_valid"] is True
    assert report["offline_conformance_only"] is True
    _assert_zero_authority(report)


def test_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    profile, _, _ = _profile_fixture()
    path = tmp_path / "candidate-profile.json"
    path.write_bytes(canonical_json_bytes(profile))
    code, report = _run("assess-profile", str(path), "--expected-sha256", "0" * 64)
    assert code == 2
    assert report["hybrid_profile_structurally_valid"] is False
    _assert_zero_authority(report)


def test_noncanonical_profile_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "candidate-profile.json"
    path.write_text('{ "schema": "not-canonical" }')
    code, report = _run("assess-profile", str(path))
    assert code == 2
    assert report["state"] == "V6_3_STATUS_INPUT_INVALID"
    _assert_zero_authority(report)


def test_symlink_profile_fails_closed(tmp_path: Path) -> None:
    profile, _, _ = _profile_fixture()
    target = tmp_path / "target.json"
    target.write_bytes(canonical_json_bytes(profile))
    link = tmp_path / "candidate-profile.json"
    link.symlink_to(target)
    code, report = _run("assess-profile", str(link))
    assert code == 2
    assert "non-symlink" in str(report["detail"])
    _assert_zero_authority(report)


def test_group_writable_profile_fails_closed(tmp_path: Path) -> None:
    profile, _, _ = _profile_fixture()
    path = tmp_path / "candidate-profile.json"
    path.write_bytes(canonical_json_bytes(profile))
    path.chmod(0o660)
    code, report = _run("assess-profile", str(path))
    assert code == 2
    assert "group- or world-writable" in str(report["detail"])
    _assert_zero_authority(report)


def test_holdout_path_is_forbidden(tmp_path: Path) -> None:
    directory = tmp_path / "sealed-holdout"
    directory.mkdir()
    profile, _, _ = _profile_fixture()
    path = directory / "candidate-profile.json"
    path.write_bytes(canonical_json_bytes(profile))
    code, report = _run("assess-profile", str(path))
    assert code == 2
    assert "sealed or holdout" in str(report["detail"])
    _assert_zero_authority(report)
