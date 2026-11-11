from __future__ import annotations

import json
from pathlib import Path

from evaluation_v5.binding import verify_binding
from evaluation_v5.engine_capabilities import (
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _json(relative_path: str) -> object:
    return json.loads((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def test_frozen_architecture_binding_matches_repository_bytes() -> None:
    binding = _json("strategy/evaluation_v5_architecture_binding_20260713.json")
    verified = verify_binding(REPO_ROOT, binding)

    assert verified["protocol_id"] == "MCI_TRANSFER_V1"
    assert verified["gate_state"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert verified["authority"] == {
        "candidate_development": False,
        "sealed_holdout_access": False,
        "submission": False,
    }


def test_current_engine_manifest_closes_all_six_features() -> None:
    manifest = validate_engine_capability_manifest(
        _json("strategy/evaluation_v5_current_engine_capability_manifest_20260713.json")
    )
    audit = audit_engine_capabilities(manifest)

    assert audit["decision"] == "NO_LOCAL_FEATURE_EXTRACTION"
    assert audit["local_feature_extraction"] is False
    assert len(audit["missing_features"]) == 6
    assert audit["authority"] is False
    assert audit["submission_authorized"] is False
    assert audit["holdout_access_authorized"] is False
