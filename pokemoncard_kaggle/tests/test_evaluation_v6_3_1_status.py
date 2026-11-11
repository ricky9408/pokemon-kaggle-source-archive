from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation_v6_3_1 import status
from evaluation_v6_3_1 import policy


CLI = Path(__file__).parents[1] / "tools" / "evaluation_v6_3_1_status.py"


def _assert_closed(report: dict[str, object]) -> None:
    assert report["state"] == "POPULATION_INFEASIBLE"
    assert report["candidate_policy_pinned"] is False
    assert report["policy_pin_present"] is False
    assert report["policy_pin_sha256"] is None
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == []
    assert report["calibration_slots_remaining"] == 16
    assert report["production_slots_remaining"] == 1


def test_unpinned_status_is_fixed_zero_authority() -> None:
    assert policy.PINNED_V631_POLICY is None
    _assert_closed(status.compose_status())


def test_caller_paths_and_override_are_not_read_or_authoritative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = tmp_path / "sealed-holdout" / "evidence.json"
    forbidden.parent.mkdir()
    forbidden.write_text('{"production_upload_authorized":true}')

    def fail_read(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("status attempted to read caller evidence")

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    monkeypatch.setenv("V631_AUTHORITY_OVERRIDE", "true")
    monkeypatch.setenv("V631_POLICY_PIN", "attacker-pin")
    report = status.compose_status()
    _assert_closed(report)


def test_cli_rejects_paths_and_authority_override(tmp_path: Path) -> None:
    forbidden = tmp_path / "campaign-evidence.json"
    forbidden.write_text('{"production_upload_authorized":true}')
    result = subprocess.run(
        [
            sys.executable,
            str(CLI),
            "status",
            "--population-path",
            str(forbidden),
            "--campaign-path",
            str(forbidden),
            "--evidence-path",
            str(forbidden),
            "--authority-override",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "usage:" in result.stderr
    assert result.returncode == 2
    assert result.stdout == ""


def test_cli_status_emits_zero_authority() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI), "status"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stderr == ""
    assert result.returncode == 2
    _assert_closed(json.loads(result.stdout))
