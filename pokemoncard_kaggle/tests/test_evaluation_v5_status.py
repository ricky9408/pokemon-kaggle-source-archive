from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from tools.evaluation_v5_status import (
    REASON_CANDIDATE_PRODUCTION_GATE_MISSING,
    REASON_ENGINE_CAPABILITY_GAP,
    REASON_EXTERNAL_TRUST_ROOTS_UNCONFIGURED,
    REASON_EXTERNAL_COHORT_MISSING,
    REASON_CAMPAIGN_ANCHOR_MISSING,
    REASON_IMPLEMENTATION_BINDING_MISSING,
    REASON_RFC3161_ANCHORS_MISSING,
    REASON_SIGNED_ENGINE_EVIDENCE_MISSING,
    REASON_SIGNED_HOST_EVIDENCE_MISSING,
    REASON_SIGNED_PROVENANCE_EVIDENCE_MISSING,
    REASON_SIGNED_SAFETY_EVIDENCE_MISSING,
    build_status,
)


ROOT = Path(__file__).parents[1]


def test_current_repository_is_reported_closed_without_authority() -> None:
    report = build_status(ROOT)

    assert report["schema"] == "evaluation_v5_status_v1"
    assert report["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert report["authority"] == {
        "candidate_development": False,
        "sealed_holdout_access": False,
        "submission": False,
    }
    assert report["submission_authorized"] is False
    assert report["sealed_holdout_access"] is False
    assert report["inspected_sealed_holdout"] is False
    assert report["checks"]["architecture_binding"]["status"] == "PASS"
    assert REASON_ENGINE_CAPABILITY_GAP in report["closed_reasons"]
    assert REASON_IMPLEMENTATION_BINDING_MISSING in report["closed_reasons"]
    assert REASON_EXTERNAL_TRUST_ROOTS_UNCONFIGURED in report["closed_reasons"]
    assert REASON_CAMPAIGN_ANCHOR_MISSING in report["closed_reasons"]
    assert REASON_SIGNED_ENGINE_EVIDENCE_MISSING in report["closed_reasons"]
    assert REASON_SIGNED_HOST_EVIDENCE_MISSING in report["closed_reasons"]
    assert REASON_SIGNED_PROVENANCE_EVIDENCE_MISSING in report["closed_reasons"]
    assert REASON_SIGNED_SAFETY_EVIDENCE_MISSING in report["closed_reasons"]
    assert REASON_RFC3161_ANCHORS_MISSING in report["closed_reasons"]
    assert REASON_EXTERNAL_COHORT_MISSING in report["closed_reasons"]
    assert REASON_CANDIDATE_PRODUCTION_GATE_MISSING in report["closed_reasons"]


def test_invalid_architecture_binding_is_an_integrity_closure(tmp_path: Path) -> None:
    strategy = tmp_path / "strategy"
    strategy.mkdir()
    binding = json.loads(
        (ROOT / "strategy/evaluation_v5_architecture_binding_20260713.json").read_text()
    )
    binding["gate_state"] = "OPEN"
    (strategy / "evaluation_v5_architecture_binding_20260713.json").write_text(json.dumps(binding))

    report = build_status(tmp_path)

    assert report["decision"] == "NO_SUBMIT_INTEGRITY"
    assert report["checks"]["architecture_binding"]["reason"] == "architecture_binding_invalid"
    assert report["submission_authorized"] is False
    assert report["sealed_holdout_access"] is False


def test_cli_is_read_only_and_emits_machine_report() -> None:
    result = subprocess.run(
        [sys.executable, "tools/evaluation_v5_status.py", "--repo-root", str(ROOT), "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    report = json.loads(result.stdout)
    assert report["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert report["read_only"] is True
    assert report["submission_authorized"] is False
    assert report["sealed_holdout_access"] is False
