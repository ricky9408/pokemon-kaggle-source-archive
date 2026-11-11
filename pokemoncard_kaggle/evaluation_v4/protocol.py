"""Strict, outcome-free protocol and ancestry split for selector v4."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


PROTOCOL_SCHEMA = "whole_policy_selector_protocol_v1"
MANIFEST_SCHEMA = "whole_policy_selector_manifest_v1"
BURNED_PANEL_ID = "f4414154ee58038ac1da"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PROTOCOL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "frozen_at_utc",
        "selector_code_sha256",
        "split_salt_sha256",
        "burned_panel_ids",
        "sealed_holdout_id",
        "estimand",
        "setup_games",
        "horizon_games",
        "minimums",
        "thresholds",
        "bootstrap_samples",
        "seed",
        "state",
    }
)
_MINIMUMS = {"min_lineages": 16, "min_families": 4, "min_blocks": 3}
_THRESHOLDS = {
    "macro_lineage_logloss_lift_min": 0.015,
    "lineage_bootstrap_positive_probability_min": 0.95,
    "lineage_bootstrap_q10_lift_min": 0.0,
    "residual_pairwise_concordance_min": 0.65,
    "positive_unit_fraction_min": 0.8,
    "family_lift_floor": -0.01,
    "calibration_slope_lower_bound_min": 0.0,
    "max_candidate_visited_ood_mass": 0.10,
    "candidate_posterior_mean_lift_min": 0.03,
    "candidate_posterior_positive_probability_min": 0.95,
    "candidate_posterior_q10_lift_min": 0.0,
    "worst_family_q10_lift_min": -0.02,
    "engine_variant_mean_lift_min": 0.0,
}
_LINEAGE_FIELDS = frozenset(
    {
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "lineage_id",
        "ancestry_id",
        "family_id",
        "first_seen_utc",
    }
)
_MANIFEST_FIELDS = frozenset({"schema", "protocol_id", "protocol_sha256", "records", "counts", "content_sha256"})
_MANIFEST_RECORD_FIELDS = _LINEAGE_FIELDS | {"split"}
_COUNT_FIELDS = frozenset(
    {
        "lineages",
        "ancestries",
        "families",
        "train_lineages",
        "tune_lineages",
        "local_test_lineages",
    }
)


class ProtocolError(ValueError):
    """A frozen protocol or its outcome-free lineage input is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole JSON encoding used for content bindings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProtocolError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ProtocolError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ProtocolError(f"{label} is not a valid UTC timestamp") from exc
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if value != normalized:
        raise ProtocolError(f"{label} must be canonical UTC")
    return value


def _integer(value: object, *, label: str, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value <= 0):
        qualifier = "positive integer" if positive else "integer"
        raise ProtocolError(f"{label} must be a {qualifier}")
    return value


def _exact_numbers(value: object, expected: Mapping[str, float | int], *, label: str) -> dict[str, float | int]:
    fields = frozenset(expected)
    mapping = _exact_fields(value, fields, label=label)
    normalized: dict[str, float | int] = {}
    for field, required in expected.items():
        actual = mapping[field]
        if isinstance(actual, bool) or not isinstance(actual, (int, float)) or not math.isfinite(float(actual)):
            raise ProtocolError(f"{label}.{field} must be a finite number")
        if float(actual) != float(required):
            raise ProtocolError(f"{label}.{field} must equal frozen value {required}")
        normalized[field] = required
    return normalized


def validate_protocol(protocol: object) -> dict[str, Any]:
    """Validate and normalize the exact frozen v4 protocol schema."""
    value = _exact_fields(protocol, _PROTOCOL_FIELDS, label="protocol")
    if value["schema"] != PROTOCOL_SCHEMA:
        raise ProtocolError(f"protocol schema must be {PROTOCOL_SCHEMA!r}")
    burned = value["burned_panel_ids"]
    if not isinstance(burned, list) or not burned:
        raise ProtocolError("burned_panel_ids must be a non-empty list")
    burned_ids = [_identifier(item, label="burned_panel_ids item") for item in burned]
    if burned_ids != sorted(set(burned_ids)):
        raise ProtocolError("burned_panel_ids must be sorted and unique")
    if BURNED_PANEL_ID not in burned_ids:
        raise ProtocolError(f"burned_panel_ids must include {BURNED_PANEL_ID}")
    if value["estimand"] != "next24_win_plus_half_draw":
        raise ProtocolError("estimand must be next24_win_plus_half_draw")
    if _integer(value["setup_games"], label="setup_games") != 8:
        raise ProtocolError("setup_games must equal 8")
    if _integer(value["horizon_games"], label="horizon_games") != 24:
        raise ProtocolError("horizon_games must equal 24")
    if value["state"] != "FROZEN":
        raise ProtocolError("state must be FROZEN")
    return {
        "schema": PROTOCOL_SCHEMA,
        "protocol_id": _identifier(value["protocol_id"], label="protocol_id"),
        "frozen_at_utc": _canonical_utc(value["frozen_at_utc"], label="frozen_at_utc"),
        "selector_code_sha256": _sha256(value["selector_code_sha256"], label="selector_code_sha256"),
        "split_salt_sha256": _sha256(value["split_salt_sha256"], label="split_salt_sha256"),
        "burned_panel_ids": burned_ids,
        "sealed_holdout_id": _identifier(value["sealed_holdout_id"], label="sealed_holdout_id"),
        "estimand": "next24_win_plus_half_draw",
        "setup_games": 8,
        "horizon_games": 24,
        "minimums": _exact_numbers(value["minimums"], _MINIMUMS, label="minimums"),
        "thresholds": _exact_numbers(value["thresholds"], _THRESHOLDS, label="thresholds"),
        "bootstrap_samples": _integer(value["bootstrap_samples"], label="bootstrap_samples", positive=True),
        "seed": _integer(value["seed"], label="seed"),
        "state": "FROZEN",
    }


def _validate_lineage_record(record: object) -> dict[str, str]:
    value = _exact_fields(record, _LINEAGE_FIELDS, label="lineage record")
    return {
        "archive_sha256": _sha256(value["archive_sha256"], label="archive_sha256"),
        "policy_content_sha256": _sha256(value["policy_content_sha256"], label="policy_content_sha256"),
        "deck_sha256": _sha256(value["deck_sha256"], label="deck_sha256"),
        "lineage_id": _identifier(value["lineage_id"], label="lineage_id"),
        "ancestry_id": _identifier(value["ancestry_id"], label="ancestry_id"),
        "family_id": _identifier(value["family_id"], label="family_id"),
        "first_seen_utc": _canonical_utc(value["first_seen_utc"], label="first_seen_utc"),
    }


def validate_lineage_records(records: Iterable[object]) -> list[dict[str, str]]:
    """Validate executable lineage bindings without accepting outcome metadata."""
    try:
        raw_records = list(records)
    except TypeError as exc:
        raise ProtocolError("lineage records must be iterable") from exc
    if not raw_records:
        raise ProtocolError("at least one lineage record is required")
    normalized = [_validate_lineage_record(record) for record in raw_records]
    lineages: dict[str, tuple[str, str, str, str, str]] = {}
    ancestry_families: dict[str, str] = {}
    archive_bindings: dict[str, tuple[str, str]] = {}
    policy_bindings: dict[str, tuple[str, str]] = {}
    for record in normalized:
        lineage = record["lineage_id"]
        binding = (
            record["archive_sha256"],
            record["policy_content_sha256"],
            record["deck_sha256"],
            record["ancestry_id"],
            record["family_id"],
        )
        if lineage in lineages:
            if lineages[lineage] != binding:
                raise ProtocolError(f"lineage_id {lineage!r} has conflicting hashes, ancestry, or family")
            raise ProtocolError(f"lineage_id {lineage!r} is duplicated")
        lineages[lineage] = binding
        ancestry = record["ancestry_id"]
        family = record["family_id"]
        if ancestry in ancestry_families and ancestry_families[ancestry] != family:
            raise ProtocolError(f"ancestry_id {ancestry!r} has conflicting families")
        ancestry_families[ancestry] = family
        identity = (lineage, ancestry)
        for field, bindings in (
            ("archive_sha256", archive_bindings),
            ("policy_content_sha256", policy_bindings),
        ):
            digest = record[field]
            if digest in bindings and bindings[digest] != identity:
                raise ProtocolError(f"{field} {digest!r} is bound to multiple lineages or ancestries")
            bindings[digest] = identity
    return sorted(normalized, key=lambda item: (item["ancestry_id"], item["lineage_id"]))


def assign_ancestry_split(split_salt_sha256: str, ancestry_id: str) -> str:
    """Assign an ancestry group to the fixed 60/20/20 split."""
    salt = _sha256(split_salt_sha256, label="split_salt_sha256")
    ancestry = _identifier(ancestry_id, label="ancestry_id")
    fraction = int.from_bytes(
        hashlib.sha256(f"{salt}:{ancestry}".encode("ascii")).digest(), "big"
    ) / float(1 << 256)
    if fraction < 0.60:
        return "train"
    if fraction < 0.80:
        return "tune"
    return "local_test"


def build_manifest(protocol: object, lineage_records: Iterable[object]) -> dict[str, Any]:
    """Build a deterministic, ancestry-safe manifest from outcome-free records."""
    frozen = validate_protocol(protocol)
    records = validate_lineage_records(lineage_records)
    ancestry_splits = {
        record["ancestry_id"]: assign_ancestry_split(frozen["split_salt_sha256"], record["ancestry_id"])
        for record in records
    }
    assigned = [{**record, "split": ancestry_splits[record["ancestry_id"]]} for record in records]
    _assert_no_leakage(assigned)
    counts = {
        "lineages": len(assigned),
        "ancestries": len(ancestry_splits),
        "families": len({record["family_id"] for record in assigned}),
        "train_lineages": sum(record["split"] == "train" for record in assigned),
        "tune_lineages": sum(record["split"] == "tune" for record in assigned),
        "local_test_lineages": sum(record["split"] == "local_test" for record in assigned),
    }
    content = {
        "schema": MANIFEST_SCHEMA,
        "protocol_id": frozen["protocol_id"],
        "protocol_sha256": canonical_sha256(frozen),
        "records": assigned,
        "counts": counts,
    }
    manifest = {**content, "content_sha256": canonical_sha256(content)}
    validate_manifest(manifest, frozen)
    return manifest


def _assert_no_leakage(records: Iterable[Mapping[str, str]]) -> None:
    splits_by_ancestry: dict[str, set[str]] = {}
    for record in records:
        ancestry = record["ancestry_id"]
        split = record["split"]
        splits_by_ancestry.setdefault(ancestry, set()).add(split)
    leaked = [ancestry for ancestry, splits in splits_by_ancestry.items() if len(splits) != 1]
    if leaked:
        raise ProtocolError(f"ancestry split leakage: {sorted(leaked)}")


def validate_manifest(manifest: object, protocol: object) -> dict[str, Any]:
    """Verify a manifest against its frozen protocol and recomputed split."""
    frozen = validate_protocol(protocol)
    value = _exact_fields(manifest, _MANIFEST_FIELDS, label="manifest")
    if value["schema"] != MANIFEST_SCHEMA:
        raise ProtocolError(f"manifest schema must be {MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != frozen["protocol_id"]:
        raise ProtocolError("manifest protocol_id mismatch")
    if value["protocol_sha256"] != canonical_sha256(frozen):
        raise ProtocolError("manifest protocol_sha256 mismatch")
    records = value["records"]
    if not isinstance(records, list):
        raise ProtocolError("manifest records must be a list")
    clean_records: list[dict[str, str]] = []
    for record in records:
        assigned = _exact_fields(record, _MANIFEST_RECORD_FIELDS, label="manifest record")
        clean = _validate_lineage_record({field: assigned[field] for field in _LINEAGE_FIELDS})
        if assigned["split"] not in {"train", "tune", "local_test"}:
            raise ProtocolError("manifest record split is invalid")
        clean_records.append({**clean, "split": assigned["split"]})
    validated = validate_lineage_records(
        [{field: record[field] for field in _LINEAGE_FIELDS} for record in clean_records]
    )
    split_by_lineage = {record["lineage_id"]: record["split"] for record in clean_records}
    clean_records = [{**record, "split": split_by_lineage[record["lineage_id"]]} for record in validated]
    for record in clean_records:
        expected_split = assign_ancestry_split(frozen["split_salt_sha256"], record["ancestry_id"])
        if record["split"] != expected_split:
            raise ProtocolError(f"manifest split mismatch for lineage_id {record['lineage_id']!r}")
    _assert_no_leakage(clean_records)
    counts = _exact_fields(value["counts"], _COUNT_FIELDS, label="manifest counts")
    expected_counts = {
        "lineages": len(clean_records),
        "ancestries": len({record["ancestry_id"] for record in clean_records}),
        "families": len({record["family_id"] for record in clean_records}),
        "train_lineages": sum(record["split"] == "train" for record in clean_records),
        "tune_lineages": sum(record["split"] == "tune" for record in clean_records),
        "local_test_lineages": sum(record["split"] == "local_test" for record in clean_records),
    }
    if any(isinstance(value, bool) or not isinstance(value, int) for value in counts.values()):
        raise ProtocolError("manifest counts must be integers")
    if dict(counts) != expected_counts:
        raise ProtocolError("manifest counts do not match records")
    content = {
        "schema": MANIFEST_SCHEMA,
        "protocol_id": _identifier(value["protocol_id"], label="manifest protocol_id"),
        "protocol_sha256": _sha256(value["protocol_sha256"], label="manifest protocol_sha256"),
        "records": clean_records,
        "counts": expected_counts,
    }
    if value["content_sha256"] != canonical_sha256(content):
        raise ProtocolError("manifest content_sha256 mismatch")
    return {**content, "content_sha256": value["content_sha256"]}


def write_manifest_once(path: str | Path, manifest: Mapping[str, Any], protocol: object) -> Path:
    """Create a manifest exactly once; existing receipts are never overwritten."""
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"manifest already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(validate_manifest(manifest, protocol)) + b"\n"
    try:
        with target.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"manifest already exists: {target}") from None
    return target
