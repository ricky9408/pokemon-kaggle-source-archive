"""Outcome-free support audit for a future mature-public-value predictor.

The module never fits coefficients.  It decides whether an as-of manifest has
enough unburned, provenance-verified ancestry/time support to permit training.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from numbers import Real
import re
from typing import Any, Mapping


MANIFEST_SCHEMA = "evaluation_v4_2_training_manifest_v1"
AUDIT_SCHEMA = "evaluation_v4_2_training_support_audit_v1"

MIN_ANCESTRY_ROOTS = 20
MIN_FAMILIES = 5
MIN_TIME_BLOCKS = 4
MIN_ROOTS_PER_FAMILY = 2
MIN_VALID_FORWARD_FOLDS = 3
MIN_FORWARD_TRAIN_ROOTS = 8
MIN_FORWARD_TEST_ROOTS = 2
MIN_WATCHED_HOURS = 24.0
MIN_OUTCOME_TICKS = 6

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "manifest_id",
        "cutoff_utc",
        "burned_artifact_sha256s",
        "validation_ancestry_ids",
        "sealed_holdout_id",
        "records",
        "state",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_RECORD_FIELDS = frozenset(
    {
        "unit_id",
        "archive_sha256",
        "ancestry_id",
        "family_id",
        "submitted_at_utc",
        "mature_window_start_utc",
        "mature_window_end_utc",
        "outcome_artifact_sha256",
        "simulation_feature_sha256",
        "source_artifact_sha256s",
        "mature_public_value",
        "outcome_ticks",
        "watched_hours",
        "outcome_state",
        "provenance_state",
        "simulation_feature_state",
        "sealed_holdout_accessed",
    }
)


class TrainingSupportError(ValueError):
    """A mature-outcome training manifest or audit is malformed."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TrainingSupportError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TrainingSupportError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise TrainingSupportError(f"{label} must be a non-empty trimmed string")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise TrainingSupportError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise TrainingSupportError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise TrainingSupportError(f"{label} must be canonical UTC") from exc
    if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise TrainingSupportError(f"{label} must be canonical UTC")
    return value


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise TrainingSupportError(f"{label} must be finite")
    return float(value)


def _sorted_unique_strings(value: object, *, label: str, sha: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise TrainingSupportError(f"{label} must be a list")
    normalized = [(_sha(item, label=f"{label} item") if sha else _identifier(item, label=f"{label} item")) for item in value]
    if normalized != sorted(set(normalized)):
        raise TrainingSupportError(f"{label} must be sorted and unique")
    return normalized


def _normalize_record(value: object, index: int) -> dict[str, Any]:
    raw = _exact(value, _RECORD_FIELDS, label=f"training record {index}")
    submitted = _utc(raw["submitted_at_utc"], label="submitted_at_utc")
    window_start = _utc(raw["mature_window_start_utc"], label="mature_window_start_utc")
    window_end = _utc(raw["mature_window_end_utc"], label="mature_window_end_utc")
    if not submitted <= window_start <= window_end:
        raise TrainingSupportError("mature window chronology is invalid")
    feature_state = raw["simulation_feature_state"]
    if feature_state not in {"MISSING", "RECOMPUTED_FROM_RAW_PANEL"}:
        raise TrainingSupportError("simulation_feature_state is invalid")
    feature_sha = raw["simulation_feature_sha256"]
    if feature_state == "MISSING":
        if feature_sha is not None:
            raise TrainingSupportError("missing simulation feature must have null SHA")
    else:
        _sha(feature_sha, label="simulation_feature_sha256")
    if raw["outcome_state"] not in {"DRIFT", "MEASURED"}:
        raise TrainingSupportError("outcome_state is invalid")
    if raw["provenance_state"] not in {"UNKNOWN", "VERIFIED"}:
        raise TrainingSupportError("provenance_state is invalid")
    ticks = raw["outcome_ticks"]
    if isinstance(ticks, bool) or not isinstance(ticks, int) or ticks < 0:
        raise TrainingSupportError("outcome_ticks must be a nonnegative integer")
    if not isinstance(raw["sealed_holdout_accessed"], bool):
        raise TrainingSupportError("sealed_holdout_accessed must be boolean")
    return {
        "unit_id": _identifier(raw["unit_id"], label="unit_id"),
        "archive_sha256": _sha(raw["archive_sha256"], label="archive_sha256"),
        "ancestry_id": _identifier(raw["ancestry_id"], label="ancestry_id"),
        "family_id": _identifier(raw["family_id"], label="family_id"),
        "submitted_at_utc": submitted,
        "mature_window_start_utc": window_start,
        "mature_window_end_utc": window_end,
        "outcome_artifact_sha256": _sha(raw["outcome_artifact_sha256"], label="outcome_artifact_sha256"),
        "simulation_feature_sha256": feature_sha,
        "source_artifact_sha256s": _sorted_unique_strings(
            raw["source_artifact_sha256s"], label="source_artifact_sha256s", sha=True
        ),
        "mature_public_value": _number(raw["mature_public_value"], label="mature_public_value"),
        "outcome_ticks": ticks,
        "watched_hours": _number(raw["watched_hours"], label="watched_hours"),
        "outcome_state": raw["outcome_state"],
        "provenance_state": raw["provenance_state"],
        "simulation_feature_state": feature_state,
        "sealed_holdout_accessed": raw["sealed_holdout_accessed"],
    }


def _normalize_content(value: object) -> dict[str, Any]:
    raw = _exact(value, _CONTENT_FIELDS, label="training manifest content")
    if raw["schema"] != MANIFEST_SCHEMA:
        raise TrainingSupportError("training manifest schema mismatch")
    records = raw["records"]
    if not isinstance(records, list) or not records:
        raise TrainingSupportError("training manifest records must be non-empty")
    normalized_records = [_normalize_record(record, index) for index, record in enumerate(records)]
    normalized_records.sort(key=lambda row: (row["submitted_at_utc"], row["unit_id"]))
    if normalized_records != records:
        raise TrainingSupportError("training records must be canonical and sorted")
    unit_ids = [record["unit_id"] for record in normalized_records]
    if len(unit_ids) != len(set(unit_ids)):
        raise TrainingSupportError("training unit_id values must be unique")
    cutoff = _utc(raw["cutoff_utc"], label="cutoff_utc")
    if any(record["mature_window_end_utc"] > cutoff for record in normalized_records):
        raise TrainingSupportError("training outcomes cross the frozen cutoff")
    if raw["state"] != "FROZEN":
        raise TrainingSupportError("training manifest state must be FROZEN")
    return {
        "schema": MANIFEST_SCHEMA,
        "manifest_id": _identifier(raw["manifest_id"], label="manifest_id"),
        "cutoff_utc": cutoff,
        "burned_artifact_sha256s": _sorted_unique_strings(
            raw["burned_artifact_sha256s"], label="burned_artifact_sha256s", sha=True
        ),
        "validation_ancestry_ids": _sorted_unique_strings(
            raw["validation_ancestry_ids"], label="validation_ancestry_ids"
        ),
        "sealed_holdout_id": _identifier(raw["sealed_holdout_id"], label="sealed_holdout_id"),
        "records": normalized_records,
        "state": "FROZEN",
    }


def build_training_manifest(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise TrainingSupportError("training manifest builder accepts hash-free content")
    normalized = _normalize_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def validate_training_manifest(value: object) -> dict[str, Any]:
    raw = _exact(value, _FIELDS, label="training manifest")
    content = {field: raw[field] for field in _CONTENT_FIELDS}
    normalized = _normalize_content(content)
    digest = _sha(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(normalized):
        raise TrainingSupportError("training manifest content_sha256 mismatch")
    return {**normalized, "content_sha256": digest}


def _record_blockers(record: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if record["provenance_state"] != "VERIFIED":
        blockers.append("ANCESTRY_PROVENANCE_UNKNOWN")
    if record["simulation_feature_state"] != "RECOMPUTED_FROM_RAW_PANEL":
        blockers.append("RAW_SIMULATION_FEATURE_MISSING")
    if record["outcome_state"] != "MEASURED":
        blockers.append("MATURE_OUTCOME_DRIFT")
    if record["watched_hours"] < MIN_WATCHED_HOURS:
        blockers.append("MATURE_WATCH_WINDOW_TOO_SHORT")
    if record["outcome_ticks"] < MIN_OUTCOME_TICKS:
        blockers.append("MATURE_OUTCOME_TICKS_TOO_FEW")
    if record["sealed_holdout_accessed"]:
        blockers.append("SEALED_HOLDOUT_ACCESSED")
    if record["ancestry_id"] in manifest["validation_ancestry_ids"]:
        blockers.append("VALIDATION_ANCESTRY_OVERLAP")
    if set(record["source_artifact_sha256s"]) & set(manifest["burned_artifact_sha256s"]):
        blockers.append("BURNED_ARTIFACT_DEPENDENCY")
    return blockers


def audit_training_support(value: object) -> dict[str, Any]:
    manifest = validate_training_manifest(value)
    record_receipts: list[dict[str, Any]] = []
    eligible_records: list[dict[str, Any]] = []
    for record in manifest["records"]:
        blockers = _record_blockers(record, manifest)
        record_receipts.append({"unit_id": record["unit_id"], "eligible": not blockers, "blockers": blockers})
        if not blockers:
            eligible_records.append(record)

    roots: dict[str, dict[str, Any]] = {}
    family_conflicts: set[str] = set()
    for record in eligible_records:
        ancestry = record["ancestry_id"]
        root = roots.setdefault(
            ancestry,
            {
                "ancestry_id": ancestry,
                "family_id": record["family_id"],
                "block": record["mature_window_end_utc"][:10],
                "units": [],
            },
        )
        if root["family_id"] != record["family_id"]:
            family_conflicts.add(ancestry)
        root["block"] = max(root["block"], record["mature_window_end_utc"][:10])
        root["units"].append(record["unit_id"])
    for ancestry in family_conflicts:
        roots.pop(ancestry, None)

    root_rows = sorted(roots.values(), key=lambda row: (row["block"], row["ancestry_id"]))
    family_counts = Counter(row["family_id"] for row in root_rows)
    blocks = sorted({row["block"] for row in root_rows})
    folds: list[dict[str, Any]] = []
    for block in blocks:
        train = sorted(row["ancestry_id"] for row in root_rows if row["block"] < block)
        test = sorted(row["ancestry_id"] for row in root_rows if row["block"] == block)
        passed = len(train) >= MIN_FORWARD_TRAIN_ROOTS and len(test) >= MIN_FORWARD_TEST_ROOTS
        folds.append({"test_block": block, "train_ancestry_ids": train, "test_ancestry_ids": test, "passed": passed})
    valid_folds = sum(fold["passed"] for fold in folds)
    checks = [
        {"name": "eligible_ancestry_roots", "passed": len(root_rows) >= MIN_ANCESTRY_ROOTS, "detail": f"observed={len(root_rows)} required={MIN_ANCESTRY_ROOTS}"},
        {"name": "family_coverage", "passed": len(family_counts) >= MIN_FAMILIES, "detail": f"observed={len(family_counts)} required={MIN_FAMILIES}"},
        {"name": "roots_per_family", "passed": bool(family_counts) and min(family_counts.values()) >= MIN_ROOTS_PER_FAMILY, "detail": json.dumps(dict(sorted(family_counts.items())))},
        {"name": "time_blocks", "passed": len(blocks) >= MIN_TIME_BLOCKS, "detail": f"observed={len(blocks)} required={MIN_TIME_BLOCKS}"},
        {"name": "forward_folds", "passed": valid_folds >= MIN_VALID_FORWARD_FOLDS, "detail": f"observed={valid_folds} required={MIN_VALID_FORWARD_FOLDS}"},
        {"name": "family_consistency", "passed": not family_conflicts, "detail": f"conflicts={sorted(family_conflicts)}"},
        {"name": "sealed_holdout_untouched", "passed": all(not record["sealed_holdout_accessed"] for record in manifest["records"]), "detail": manifest["sealed_holdout_id"]},
    ]
    allowed = all(check["passed"] for check in checks)
    content = {
        "schema": AUDIT_SCHEMA,
        "manifest_content_sha256": manifest["content_sha256"],
        "record_receipts": record_receipts,
        "eligible_units": len(eligible_records),
        "eligible_ancestry_roots": len(root_rows),
        "family_counts": dict(sorted(family_counts.items())),
        "time_blocks": blocks,
        "forward_folds": folds,
        "checks": checks,
        "decision": "TRAINER_ALLOWED" if allowed else "NULL_MODEL_ONLY",
        "model_fitting_authorized": allowed,
        "sealed_holdout_accessed": False,
        "kaggle_quota_authorized": False,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_training_support_audit(value: object, manifest: object) -> dict[str, Any]:
    expected = audit_training_support(manifest)
    if not isinstance(value, Mapping) or dict(value) != expected:
        raise TrainingSupportError("training support audit is not the exact recomputed result")
    return expected


__all__ = [
    "AUDIT_SCHEMA",
    "MANIFEST_SCHEMA",
    "TrainingSupportError",
    "audit_training_support",
    "build_training_manifest",
    "canonical_json_bytes",
    "canonical_sha256",
    "validate_training_manifest",
    "validate_training_support_audit",
]
