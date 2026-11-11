"""Fail-closed preregistration validator for the v6.2.1 calibration campaign.

This module intentionally validates only pre-upload, non-outcome artifacts.  It
cannot issue a unit permit, calibration upload authority, or production
submission authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


PROTOCOL_SCHEMA = "evaluation_v6_2_1_protocol_v1"
POPULATION_MANIFEST_SCHEMA = "evaluation_v6_2_1_population_manifest_v1"
PREREGISTRATION_ROOT_SCHEMA = "evaluation_v6_2_1_preregistration_root_v1"

SLOTS = ("D01", "D02", "D03", "D04", "D05", "D06", "DR01", "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "CR01")
DEV_PRIMARY_SLOTS = SLOTS[:6]
DEV_RESERVE_SLOT = "DR01"
CONFIRM_PRIMARY_SLOTS = SLOTS[7:15]
CONFIRM_RESERVE_SLOT = "CR01"
FEATURE_NAMES = (
    "early_prize_tempo_t2",
    "board_readiness_t2_t4",
    "damage_efficiency_t4",
    "recovery_rate",
    "resource_viability",
    "seat_robustness",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINAL_RE = re.compile(r"final", re.IGNORECASE)
_SEALED_RE = re.compile(r"sealed[_. -]*holdout", re.IGNORECASE)

_PROTOCOL_FIELDS = frozenset(
    {
        "schema", "protocol_id", "N", "population_size", "dev_primary_count", "confirm_primary_count",
        "dev_reserve_count", "confirm_reserve_count", "production_slots", "one_at_a_time",
        "latest_two_required", "daily_calibration_upload_max", "poll_offsets_minutes",
        "poll_window_minutes", "poll_retry_seconds", "poll_sync_max_skew_seconds",
        "precomplete_deadline_hours", "naming_forbidden_substring", "feature_names",
        "dev_min_wins", "dev_oof_mae_ratio_max", "dev_beta_posterior_min",
        "dev_successful_folds_required", "confirm_sign_wins_min", "confirm_mae_ratio_max",
        "confirm_const_mae_ratio_max", "confirm_concordance_min", "canonical_epsilon",
        "research_only", "upload_authorized", "production_authorized", "state",
    }
)
_POPULATION_FIELDS = frozenset({"schema", "protocol_id", "protocol_sha256", "records", "content_sha256"})
_RECORD_FIELDS = frozenset(
    {
        "archive_hash", "role", "upload_order", "lineage_time_block_id", "source_family_id",
        "intervention_family_id", "production_eligibility_flag", "production_ineligibility_reason",
    }
)
_ROOT_FIELDS = frozenset(
    {
        "schema", "protocol_sha256", "population_content_sha256", "feature_vectors_sha256",
        "artifact_hashes", "merkle_root", "upload_authorized", "production_authorized", "state",
    }
)
_REQUIRED_ARTIFACTS = frozenset(
    {
        "analysis_bundle", "ancestry_graph", "calibration_ledger", "controls_manifest", "custody_root",
        "executor_bundle", "independence_report", "local_evidence_root", "local_panel",
        "poll_collector_spec", "production_ledger", "sol_preupload_review",
    }
)


class ProtocolError(ValueError):
    """A v6.2.1 preregistration artifact violates a binding requirement."""


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-finite JSON number is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json_loads(payload: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate object keys and non-finite numbers."""

    try:
        return json.loads(payload, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole deterministic ASCII JSON representation for bindings."""

    try:
        return json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ProtocolError("value is not finite canonical JSON") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProtocolError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ProtocolError(f"{label} must be a non-empty trimmed string")
    if _SEALED_RE.search(value):
        raise ProtocolError(f"{label} must not reference a sealed-holdout path")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, *, label: str, expected: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ProtocolError(f"{label} must equal frozen value {expected}")
    return value


def _number(value: object, *, label: str, expected: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ProtocolError(f"{label} must be a finite number")
    if float(value) != expected:
        raise ProtocolError(f"{label} must equal frozen value {expected}")
    return expected


def validate_protocol(protocol: object) -> dict[str, Any]:
    """Validate every fixed v6.2.1 campaign constant, without upload authority."""

    value = _exact_fields(protocol, _PROTOCOL_FIELDS, label="protocol")
    exact_ints = {
        "N": 16, "population_size": 16, "dev_primary_count": 6, "confirm_primary_count": 8,
        "dev_reserve_count": 1, "confirm_reserve_count": 1, "production_slots": 1,
        "daily_calibration_upload_max": 3, "poll_window_minutes": 10, "poll_retry_seconds": 60,
        "poll_sync_max_skew_seconds": 60, "precomplete_deadline_hours": 12,
        "dev_min_wins": 4, "dev_successful_folds_required": 6, "confirm_sign_wins_min": 7,
        "confirm_concordance_min": 20,
    }
    normalized: dict[str, Any] = {
        "schema": PROTOCOL_SCHEMA,
        "protocol_id": _identifier(value["protocol_id"], label="protocol_id"),
        **{name: _integer(value[name], label=name, expected=expected) for name, expected in exact_ints.items()},
        "one_at_a_time": True,
        "latest_two_required": True,
        "poll_offsets_minutes": [60, 120, 240, 480],
        "naming_forbidden_substring": "final",
        "feature_names": list(FEATURE_NAMES),
        "dev_oof_mae_ratio_max": _number(value["dev_oof_mae_ratio_max"], label="dev_oof_mae_ratio_max", expected=0.90),
        "dev_beta_posterior_min": _number(value["dev_beta_posterior_min"], label="dev_beta_posterior_min", expected=0.90),
        "confirm_mae_ratio_max": _number(value["confirm_mae_ratio_max"], label="confirm_mae_ratio_max", expected=0.80),
        "confirm_const_mae_ratio_max": _number(value["confirm_const_mae_ratio_max"], label="confirm_const_mae_ratio_max", expected=0.95),
        "canonical_epsilon": _number(value["canonical_epsilon"], label="canonical_epsilon", expected=0.000001),
        "research_only": True,
        "upload_authorized": False,
        "production_authorized": False,
        "state": "PREREGISTRATION_LOCKED",
    }
    if value["schema"] != PROTOCOL_SCHEMA:
        raise ProtocolError(f"protocol schema must be {PROTOCOL_SCHEMA!r}")
    if value["one_at_a_time"] is not True or value["latest_two_required"] is not True:
        raise ProtocolError("one-at-a-time and latest-two protections must be true")
    if value["poll_offsets_minutes"] != [60, 120, 240, 480]:
        raise ProtocolError("poll_offsets_minutes must be [60, 120, 240, 480]")
    if value["naming_forbidden_substring"] != "final":
        raise ProtocolError("naming_forbidden_substring must be final")
    if value["feature_names"] != list(FEATURE_NAMES):
        raise ProtocolError("feature_names must be the fixed six local evaluator features")
    if value["research_only"] is not True or value["upload_authorized"] is not False or value["production_authorized"] is not False:
        raise ProtocolError("v6.2.1 preregistration carries no upload or production authority")
    if value["state"] != "PREREGISTRATION_LOCKED":
        raise ProtocolError("state must be PREREGISTRATION_LOCKED")
    return normalized


def _expected_slot(slot: str) -> tuple[str, int]:
    if slot in DEV_PRIMARY_SLOTS:
        return "DEV_PRIMARY", SLOTS.index(slot) + 1
    if slot == DEV_RESERVE_SLOT:
        return "DEV_RESERVE", 7
    if slot in CONFIRM_PRIMARY_SLOTS:
        return "CONFIRM_PRIMARY", SLOTS.index(slot) + 1
    if slot == CONFIRM_RESERVE_SLOT:
        return "CONFIRM_RESERVE", 16
    raise ProtocolError(f"unknown required slot {slot}")


def _validate_record(record: object, *, slot: str) -> dict[str, Any]:
    value = _exact_fields(record, _RECORD_FIELDS, label=f"population record {slot}")
    expected_role, expected_order = _expected_slot(slot)
    if value["role"] != expected_role or value["upload_order"] != expected_order:
        raise ProtocolError(f"{slot} has an invalid fixed role or upload_order")
    eligibility = value["production_eligibility_flag"]
    if not isinstance(eligibility, bool):
        raise ProtocolError(f"{slot}.production_eligibility_flag must be boolean")
    reason = value["production_ineligibility_reason"]
    if eligibility:
        if expected_role != "DEV_PRIMARY":
            raise ProtocolError(f"only DEV primaries may be production-eligible base candidates")
        if reason is not None:
            raise ProtocolError(f"{slot} production-eligible rows must not have an ineligibility reason")
    elif not isinstance(reason, str) or not reason.strip():
        raise ProtocolError(f"{slot} production-ineligible rows require a non-empty reason")
    return {
        "archive_hash": _sha256(value["archive_hash"], label=f"{slot}.archive_hash"),
        "role": expected_role,
        "upload_order": expected_order,
        "lineage_time_block_id": _identifier(value["lineage_time_block_id"], label=f"{slot}.lineage_time_block_id"),
        "source_family_id": _identifier(value["source_family_id"], label=f"{slot}.source_family_id"),
        "intervention_family_id": _identifier(value["intervention_family_id"], label=f"{slot}.intervention_family_id"),
        "production_eligibility_flag": eligibility,
        "production_ineligibility_reason": None if eligibility else _identifier(
            reason, label=f"{slot}.production_ineligibility_reason"
        ),
    }


def _active_slots(primary: tuple[str, ...], reserve: str) -> tuple[tuple[str, ...], ...]:
    return (primary,) + tuple(tuple(reserve if item == replaced else item for item in primary) for replaced in primary)


def _validate_diversity(records: Mapping[str, Mapping[str, Any]]) -> None:
    dev_sets = _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT)
    confirm_sets = _active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT)
    for slots in dev_sets:
        if len({records[slot]["intervention_family_id"] for slot in slots}) < 3:
            raise ProtocolError("every active DEV reserve scenario requires at least three intervention families")
    for slots in confirm_sets:
        if len({records[slot]["intervention_family_id"] for slot in slots}) < 4:
            raise ProtocolError("every active CONFIRM reserve scenario requires at least four intervention families")
    for dev_slots in dev_sets:
        for confirm_slots in confirm_sets:
            active = dev_slots + confirm_slots
            if len({records[slot]["intervention_family_id"] for slot in active}) < 5:
                raise ProtocolError("every allowed reserve substitution requires at least five intervention families")


def _normalize_records(records: Iterable[object]) -> list[dict[str, Any]]:
    try:
        raw = list(records)
    except TypeError as exc:
        raise ProtocolError("population records must be iterable") from exc
    if len(raw) != 16:
        raise ProtocolError("population must contain exactly 16 records")
    by_slot: dict[str, object] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            raise ProtocolError("population record must be an object")
        # Slot is external to the frozen row fields: list position is the immutable slot assignment.
        slot = SLOTS[len(by_slot)] if len(by_slot) < len(SLOTS) else ""
        by_slot[slot] = item
    normalized = {slot: _validate_record(by_slot[slot], slot=slot) for slot in SLOTS}
    for field in ("archive_hash", "lineage_time_block_id", "source_family_id"):
        values = [normalized[slot][field] for slot in SLOTS]
        if len(values) != len(set(values)):
            raise ProtocolError(f"all 16 {field} values must be distinct")
    _validate_diversity(normalized)
    return [normalized[slot] for slot in SLOTS]


def _population_content(protocol: Mapping[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": POPULATION_MANIFEST_SCHEMA,
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": canonical_sha256(protocol),
        "records": records,
    }


def build_population_manifest(protocol: object, records: Iterable[object]) -> dict[str, Any]:
    """Build the fixed 16-slot calibration population, including reserve checks."""

    frozen = validate_protocol(protocol)
    normalized = _normalize_records(records)
    content = _population_content(frozen, normalized)
    manifest = {**content, "content_sha256": canonical_sha256(content)}
    return validate_population_manifest(manifest, frozen)


def validate_population_manifest(manifest: object, protocol: object) -> dict[str, Any]:
    frozen = validate_protocol(protocol)
    value = _exact_fields(manifest, _POPULATION_FIELDS, label="population manifest")
    if value["schema"] != POPULATION_MANIFEST_SCHEMA or value["protocol_id"] != frozen["protocol_id"]:
        raise ProtocolError("population manifest schema or protocol_id mismatch")
    if value["protocol_sha256"] != canonical_sha256(frozen):
        raise ProtocolError("population manifest protocol_sha256 mismatch")
    if not isinstance(value["records"], list):
        raise ProtocolError("population manifest records must be a list")
    records = _normalize_records(value["records"])
    content = _population_content(frozen, records)
    if value["content_sha256"] != canonical_sha256(content):
        raise ProtocolError("population manifest content_sha256 mismatch")
    return {**content, "content_sha256": value["content_sha256"]}


def validate_feature_vectors(feature_vectors: object, population_manifest: object, protocol: object) -> dict[str, dict[str, float]]:
    """Prove CONFIRM/CR feature containment for every possible active DEV set."""

    frozen = validate_protocol(protocol)
    validate_population_manifest(population_manifest, frozen)
    if not isinstance(feature_vectors, Mapping) or set(feature_vectors) != set(SLOTS):
        raise ProtocolError("feature_vectors must contain exactly the 16 canonical slots")
    normalized: dict[str, dict[str, float]] = {}
    expected_features = set(FEATURE_NAMES)
    for slot in SLOTS:
        vector = feature_vectors[slot]
        if not isinstance(vector, Mapping) or set(vector) != expected_features:
            raise ProtocolError(f"{slot} feature vector must contain exactly the six fixed features")
        normalized[slot] = {}
        for name in FEATURE_NAMES:
            number = vector[name]
            if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(float(number)):
                raise ProtocolError(f"{slot}.{name} must be finite")
            normalized[slot][name] = float(number)
    for dev_slots in _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT):
        for name in FEATURE_NAMES:
            lower = min(normalized[slot][name] for slot in dev_slots)
            upper = max(normalized[slot][name] for slot in dev_slots)
            for slot in CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,):
                if not lower <= normalized[slot][name] <= upper:
                    raise ProtocolError(f"{slot}.{name} is outside support for active DEV scenario {','.join(dev_slots)}")
    return normalized


def merkle_root(leaves: Mapping[str, str]) -> str:
    """Return a deterministic domain-separated SHA-256 Merkle root."""

    if not isinstance(leaves, Mapping) or not leaves:
        raise ProtocolError("Merkle leaves must be a non-empty mapping")
    if any(not isinstance(label, str) or not label for label in leaves):
        raise ProtocolError("Merkle leaf labels must be non-empty strings")
    try:
        ordered = sorted(leaves.items())
        nodes = [
            hashlib.sha256(b"leaf\x00" + label.encode("ascii") + bytes.fromhex(_sha256(digest, label=label))).digest()
            for label, digest in ordered
        ]
    except UnicodeEncodeError as exc:
        raise ProtocolError("Merkle leaf labels must be ASCII") from exc
    while len(nodes) > 1:
        if len(nodes) % 2:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(b"node\x00" + nodes[index] + nodes[index + 1]).digest() for index in range(0, len(nodes), 2)]
    return nodes[0].hex()


def build_preregistration_root(
    protocol: object,
    population_manifest: object,
    feature_vectors: object,
    artifact_hashes: Mapping[str, str],
) -> dict[str, Any]:
    """Compose a Merkle-bound preregistration receipt with no upload authority."""

    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    vectors = validate_feature_vectors(feature_vectors, population, frozen)
    if not isinstance(artifact_hashes, Mapping) or set(artifact_hashes) != _REQUIRED_ARTIFACTS:
        raise ProtocolError("artifact_hashes must contain exactly the required preregistration artifacts")
    artifacts = {key: _sha256(artifact_hashes[key], label=f"artifact_hashes.{key}") for key in sorted(_REQUIRED_ARTIFACTS)}
    leaves = {
        "protocol": canonical_sha256(frozen),
        "population": population["content_sha256"],
        "feature_vectors": canonical_sha256(vectors),
        **{f"artifact:{name}": digest for name, digest in artifacts.items()},
    }
    return {
        "schema": PREREGISTRATION_ROOT_SCHEMA,
        "protocol_sha256": leaves["protocol"],
        "population_content_sha256": leaves["population"],
        "feature_vectors_sha256": leaves["feature_vectors"],
        "artifact_hashes": artifacts,
        "merkle_root": merkle_root(leaves),
        "upload_authorized": False,
        "production_authorized": False,
        "state": "PREREGISTRATION_ONLY_NO_UPLOAD_AUTHORITY",
    }


def validate_preregistration_root(
    root: object, protocol: object, population_manifest: object, feature_vectors: object
) -> dict[str, Any]:
    value = _exact_fields(root, _ROOT_FIELDS, label="preregistration root")
    expected = build_preregistration_root(protocol, population_manifest, feature_vectors, value["artifact_hashes"])
    if dict(value) != expected:
        raise ProtocolError("preregistration root is not the deterministic non-authorizing composition")
    return expected


def validate_submission_name(name: object) -> str:
    """Reject reserved production-style names and unsafe path-like upload names."""

    value = _identifier(name, label="submission name")
    if _FINAL_RE.search(value):
        raise ProtocolError("submission name must not contain final")
    if "/" in value or "\\" in value or ".." in value:
        raise ProtocolError("submission name must not be a path")
    return value


def _safe_write_path(path: str | Path) -> Path:
    raw = os.fspath(path)
    parts = Path(raw).parts
    if ".." in parts or _SEALED_RE.search(raw) or {part.casefold() for part in parts} & {"sealed", "holdout"}:
        raise ProtocolError("write path must not traverse or reference sealed-holdout storage")
    target = Path(raw)
    for parent in (target, *target.parents):
        if parent.exists() and parent.is_symlink():
            raise ProtocolError("symlink paths are forbidden for immutable artifacts")
    return target


def _write_once(path: str | Path, payload: Mapping[str, Any], *, label: str) -> Path:
    target = _safe_write_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"{label} already exists: {target}")
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"{label} already exists: {target}") from None
    return target


def read_canonical_json_file(path: str | Path) -> Any:
    """Read an immutable-artifact JSON file after applying filesystem guards."""

    target = _safe_write_path(path)
    if not target.exists() or target.is_symlink():
        raise ProtocolError("artifact file is missing or symlinked")
    try:
        return canonical_json_loads(target.read_bytes())
    except OSError as exc:
        raise ProtocolError("unable to read artifact file") from exc


def write_protocol_once(path: str | Path, protocol: object) -> Path:
    return _write_once(path, validate_protocol(protocol), label="protocol")


def write_population_manifest_once(path: str | Path, manifest: object, protocol: object) -> Path:
    return _write_once(path, validate_population_manifest(manifest, protocol), label="population manifest")


def write_preregistration_root_once(
    path: str | Path, root: object, protocol: object, population_manifest: object, feature_vectors: object
) -> Path:
    return _write_once(path, validate_preregistration_root(root, protocol, population_manifest, feature_vectors), label="preregistration root")
