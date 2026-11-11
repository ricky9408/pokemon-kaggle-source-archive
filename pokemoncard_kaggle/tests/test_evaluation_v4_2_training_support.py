from __future__ import annotations

import copy
from pathlib import Path

import pytest

from evaluation_v4_2.training_support import (
    MANIFEST_SCHEMA,
    TrainingSupportError,
    audit_training_support,
    build_training_manifest,
    validate_training_manifest,
    validate_training_support_audit,
)


def _content() -> dict[str, object]:
    records: list[dict[str, object]] = []
    for index in range(20):
        day = index // 4 + 1
        records.append(
            {
                "unit_id": f"unit-{index:02d}",
                "archive_sha256": f"{index + 1:064x}",
                "ancestry_id": f"ancestry-{index:02d}",
                "family_id": f"family-{index % 5}",
                "submitted_at_utc": f"2026-06-{day:02d}T00:00:00.000000Z",
                "mature_window_start_utc": f"2026-06-{day:02d}T01:00:00.000000Z",
                "mature_window_end_utc": f"2026-06-{day:02d}T23:00:00.000000Z",
                "outcome_artifact_sha256": f"{index + 101:064x}",
                "simulation_feature_sha256": f"{index + 201:064x}",
                "source_artifact_sha256s": [f"{index + 301:064x}"],
                "mature_public_value": 800.0 + index,
                "outcome_ticks": 10,
                "watched_hours": 48.0,
                "outcome_state": "MEASURED",
                "provenance_state": "VERIFIED",
                "simulation_feature_state": "RECOMPUTED_FROM_RAW_PANEL",
                "sealed_holdout_accessed": False,
            }
        )
    return {
        "schema": MANIFEST_SCHEMA,
        "manifest_id": "mature-public-training-v1",
        "cutoff_utc": "2026-06-30T00:00:00.000000Z",
        "burned_artifact_sha256s": ["f" * 64],
        "validation_ancestry_ids": [],
        "sealed_holdout_id": "sealed-50-game-holdout",
        "records": records,
        "state": "FROZEN",
    }


def test_supported_ancestry_time_manifest_allows_training() -> None:
    manifest = build_training_manifest(_content())
    audit = audit_training_support(manifest)
    assert validate_training_manifest(manifest) == manifest
    assert audit["decision"] == "TRAINER_ALLOWED"
    assert audit["model_fitting_authorized"] is True
    assert audit["eligible_ancestry_roots"] == 20
    assert len([fold for fold in audit["forward_folds"] if fold["passed"]]) == 3
    assert audit["sealed_holdout_accessed"] is False
    assert audit["kaggle_quota_authorized"] is False
    assert audit["production_submission_authorized"] is False
    assert validate_training_support_audit(audit, manifest) == audit


def test_unknown_provenance_and_missing_raw_features_force_null_model() -> None:
    content = _content()
    for record in content["records"]:  # type: ignore[index]
        record["provenance_state"] = "UNKNOWN"
        record["simulation_feature_state"] = "MISSING"
        record["simulation_feature_sha256"] = None
    audit = audit_training_support(build_training_manifest(content))
    assert audit["decision"] == "NULL_MODEL_ONLY"
    assert audit["eligible_ancestry_roots"] == 0
    assert {
        "ANCESTRY_PROVENANCE_UNKNOWN",
        "RAW_SIMULATION_FEATURE_MISSING",
    } <= set(audit["record_receipts"][0]["blockers"])


def test_burned_dependency_or_validation_overlap_is_ineligible() -> None:
    content = _content()
    content["records"][0]["source_artifact_sha256s"] = ["f" * 64]  # type: ignore[index]
    content["validation_ancestry_ids"] = ["ancestry-01"]
    audit = audit_training_support(build_training_manifest(content))
    assert audit["decision"] == "NULL_MODEL_ONLY"
    assert "BURNED_ARTIFACT_DEPENDENCY" in audit["record_receipts"][0]["blockers"]
    assert "VALIDATION_ANCESTRY_OVERLAP" in audit["record_receipts"][1]["blockers"]


def test_drift_short_watch_and_holdout_access_are_fatal_to_records() -> None:
    content = _content()
    first = content["records"][0]  # type: ignore[index]
    first["outcome_state"] = "DRIFT"
    first["watched_hours"] = 2.0
    first["outcome_ticks"] = 2
    first["sealed_holdout_accessed"] = True
    audit = audit_training_support(build_training_manifest(content))
    blockers = set(audit["record_receipts"][0]["blockers"])
    assert {
        "MATURE_OUTCOME_DRIFT",
        "MATURE_WATCH_WINDOW_TOO_SHORT",
        "MATURE_OUTCOME_TICKS_TOO_FEW",
        "SEALED_HOLDOUT_ACCESSED",
    } <= blockers
    assert next(check for check in audit["checks"] if check["name"] == "sealed_holdout_untouched")["passed"] is False


def test_hash_tamper_and_field_injection_are_rejected() -> None:
    manifest = build_training_manifest(_content())
    tampered = copy.deepcopy(manifest)
    tampered["records"][0]["mature_public_value"] = 9999.0
    with pytest.raises(TrainingSupportError, match="content_sha256 mismatch"):
        validate_training_manifest(tampered)
    injected = _content()
    injected["records"][0]["selector_score"] = 1.0  # type: ignore[index]
    with pytest.raises(TrainingSupportError, match="fields must exactly"):
        build_training_manifest(injected)
    audit = audit_training_support(manifest)
    audit["eligible_ancestry_roots"] = 999
    with pytest.raises(TrainingSupportError, match="exact recomputed"):
        validate_training_support_audit(audit, manifest)


def test_audit_has_no_filesystem_side_effects(tmp_path: Path) -> None:
    before = list(tmp_path.iterdir())
    first = audit_training_support(build_training_manifest(_content()))
    second = audit_training_support(build_training_manifest(_content()))
    assert first == second
    assert list(tmp_path.iterdir()) == before == []
