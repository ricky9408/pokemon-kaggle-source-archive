"""Pure, fail-closed v6.2.2 preregistration integration bindings.

This module verifies immutable preregistration material only.  In particular,
it never issues a permit, an upload authorization, or an executor command.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any


POPULATION_RECORD_SCHEMA = "eval.v6.2.2.population-record"
FEATURE_RECORD_SCHEMA = "eval.v6.2.2.feature-record"
ATTESTATION_SCHEMA = "eval.v6.2.2.attestation"
PREREG_ROOT_SCHEMA = "eval.v6.2.2.prereg-root"
INTEGRATION_VERDICT_SCHEMA = "eval.v6.2.2.integration-verdict"
FEATURE_SCHEMA_ID = "v6.2.2-mechanics-6"

SLOTS = (
    "D01", "D02", "D03", "D04", "D05", "D06", "DR01",
    "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "CR01",
)
DEV_PRIMARY_SLOTS = SLOTS[:6]
CONFIRM_PRIMARY_SLOTS = SLOTS[7:15]
DEV_RESERVE_SLOT = "DR01"
CONFIRM_RESERVE_SLOT = "CR01"
FEATURE_NAMES = (
    "early_prize_tempo_t2",
    "board_readiness_t2_t4",
    "damage_efficiency_t4",
    "recovery_rate",
    "resource_viability",
    "seat_robustness",
)
REQUIRED_PREREG_FILES = (
    "protocol_v6_2_2.json",
    "population_manifest.jsonl",
    "features_manifest.jsonl",
    "ancestry_attestations.jsonl",
    "safety_receipts.jsonl",
    "controls_manifest.json",
    "local_panel.json",
    "analysis_bundle.json",
    "executor_policy.json",
    "poll_collector_spec.json",
    "ledger_genesis.json",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DECIMAL_STRING_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$|^-(?:[1-9][0-9]*)(?:\.[0-9]+)?$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SEALED_RE = re.compile(r"sealed[_. -]*holdout|holdout", re.IGNORECASE)


class IntegrationError(ValueError):
    """A v6.2.2 preregistration input violated the immutable contract."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IntegrationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise IntegrationError(f"floating-point literal is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise IntegrationError(f"non-finite JSON number is forbidden: {value}")


def canonical_json_loads(payload: str | bytes | bytearray) -> Any:
    """Parse JSON while rejecting duplicate keys, floats, and non-finite values."""

    try:
        return json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrationError("invalid JSON") from exc


def _json_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise IntegrationError("JSON strings must not contain surrogate code points")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise IntegrationError("integer exceeds the interoperable RFC 8785 safe range")
        return str(value)
    if isinstance(value, float):
        raise IntegrationError("floating-point values are forbidden; use decimal strings")
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise IntegrationError("JSON object keys must be strings")
        ordered_keys = sorted(value, key=lambda key: key.encode("utf-16be"))
        return "{" + ",".join(_json_string(key) + ":" + _canonical_json(value[key]) for key in ordered_keys) + "}"
    raise IntegrationError("value is not canonical JSON")


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC-8785-shaped UTF-8 JSON with integer-only number literals."""

    try:
        return _canonical_json(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IntegrationError("canonical JSON must be UTF-8 encodable") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise IntegrationError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise IntegrationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise IntegrationError(f"{label} must be a non-empty trimmed string")
    if _SEALED_RE.search(value):
        raise IntegrationError(f"{label} must not reference the sealed holdout")
    return value


def _role_for_slot(slot: str) -> tuple[str, int]:
    if slot in DEV_PRIMARY_SLOTS:
        return "DEV_PRIMARY", SLOTS.index(slot) + 1
    if slot == DEV_RESERVE_SLOT:
        return "DEV_RESERVE", 7
    if slot in CONFIRM_PRIMARY_SLOTS:
        return "CONFIRM_PRIMARY", SLOTS.index(slot) + 1
    if slot == CONFIRM_RESERVE_SLOT:
        return "CONFIRM_RESERVE", 16
    raise IntegrationError(f"unknown slot {slot}")


def _active_slots(primary: tuple[str, ...], reserve: str) -> tuple[tuple[str, ...], ...]:
    return (primary,) + tuple(tuple(reserve if slot == failed else slot for slot in primary) for failed in primary)


def _canonical_file_bytes(path: Path, *, jsonl: bool) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise IntegrationError(f"unable to read {path.name}") from exc
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw:
        raise IntegrationError(f"{path.name} must be UTF-8 without BOM and LF framed")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrationError(f"{path.name} is not valid UTF-8") from exc
    if jsonl:
        if not raw.endswith(b"\n") or raw == b"\n":
            raise IntegrationError(f"{path.name} must be non-empty JSONL with one final LF")
        lines = raw[:-1].split(b"\n")
        if any(not line for line in lines):
            raise IntegrationError(f"{path.name} must not contain blank JSONL lines")
        canonical = b"".join(canonical_json_bytes(canonical_json_loads(line)) + b"\n" for line in lines)
    else:
        if raw.endswith(b"\n"):
            raise IntegrationError(f"{path.name} JSON must not contain framing whitespace")
        canonical = canonical_json_bytes(canonical_json_loads(raw))
    if raw != canonical:
        raise IntegrationError(f"{path.name} is not canonical JSON framing")
    return raw


def _read_json(path: Path) -> Mapping[str, Any]:
    value = _parse_json_bytes(_canonical_file_bytes(path, jsonl=False), path.name)
    return value


def _parse_json_bytes(raw: bytes, label: str) -> Mapping[str, Any]:
    value = canonical_json_loads(raw)
    if not isinstance(value, Mapping):
        raise IntegrationError(f"{label} must contain a JSON object")
    return value


def _read_jsonl(path: Path) -> list[tuple[Mapping[str, Any], bytes]]:
    return _parse_jsonl_bytes(_canonical_file_bytes(path, jsonl=True), path.name)


def _parse_jsonl_bytes(raw: bytes, label: str) -> list[tuple[Mapping[str, Any], bytes]]:
    rows: list[tuple[Mapping[str, Any], bytes]] = []
    for line in raw[:-1].split(b"\n"):
        value = canonical_json_loads(line)
        if not isinstance(value, Mapping):
            raise IntegrationError(f"{label} rows must be JSON objects")
        rows.append((value, line))
    return rows


def _validate_population_row(row: Mapping[str, Any], expected_slot: str) -> dict[str, Any]:
    value = _exact_fields(
        row,
        frozenset({"schema", "slot_id", "role", "slot_order", "archive", "identity", "attestations", "feature_binding", "base"}),
        f"population record {expected_slot}",
    )
    expected_role, expected_order = _role_for_slot(expected_slot)
    if value["schema"] != POPULATION_RECORD_SCHEMA or value["slot_id"] != expected_slot:
        raise IntegrationError(f"population record must be the canonical {expected_slot} row")
    if value["role"] != expected_role or value["slot_order"] != expected_order:
        raise IntegrationError(f"{expected_slot} role and slot_order are derived and fixed")
    archive = _exact_fields(
        value["archive"],
        frozenset({"archive_sha256", "package_sha256", "source_tree_sha256", "linux_amd64_build_sha256", "build_recipe_sha256", "build_container_digest"}),
        f"{expected_slot}.archive",
    )
    identity = _exact_fields(
        value["identity"],
        frozenset({"agent_id", "lineage_time_block_id", "source_family_id", "intervention_family_id"}),
        f"{expected_slot}.identity",
    )
    attestations = _exact_fields(
        value["attestations"],
        frozenset({"archive_source_equality_receipt_sha256", "ancestry_attestation_sha256", "linux_repro_receipt_sha256", "safety_receipt_sha256"}),
        f"{expected_slot}.attestations",
    )
    feature_binding = _exact_fields(
        value["feature_binding"],
        frozenset({"feature_record_sha256", "local_evidence_root_sha256", "feature_schema_id"}),
        f"{expected_slot}.feature_binding",
    )
    base = _exact_fields(value["base"], frozenset({"base_candidate", "base_ineligibility_code"}), f"{expected_slot}.base")
    if not isinstance(base["base_candidate"], bool):
        raise IntegrationError(f"{expected_slot}.base_candidate must be boolean")
    if base["base_candidate"]:
        if expected_role != "DEV_PRIMARY" or base["base_ineligibility_code"] is not None:
            raise IntegrationError(f"{expected_slot} base candidates must be DEV primaries with null ineligibility")
    elif not isinstance(base["base_ineligibility_code"], str) or not base["base_ineligibility_code"].strip():
        raise IntegrationError(f"{expected_slot} non-base rows need a base_ineligibility_code")
    if not isinstance(archive["build_container_digest"], str) or _CONTAINER_RE.fullmatch(archive["build_container_digest"]) is None:
        raise IntegrationError(f"{expected_slot}.archive.build_container_digest must be sha256:<digest>")
    if feature_binding["feature_schema_id"] != FEATURE_SCHEMA_ID:
        raise IntegrationError(f"{expected_slot} feature_schema_id must be {FEATURE_SCHEMA_ID}")
    return {
        "slot_id": expected_slot,
        "role": expected_role,
        "archive": {key: _sha256(archive[key], f"{expected_slot}.archive.{key}") for key in archive if key != "build_container_digest"} | {"build_container_digest": archive["build_container_digest"]},
        "identity": {key: _identifier(identity[key], f"{expected_slot}.identity.{key}") for key in identity},
        "attestations": {key: _sha256(attestations[key], f"{expected_slot}.attestations.{key}") for key in attestations},
        "feature_binding": {
            "feature_record_sha256": _sha256(feature_binding["feature_record_sha256"], f"{expected_slot}.feature_record_sha256"),
            "local_evidence_root_sha256": _sha256(feature_binding["local_evidence_root_sha256"], f"{expected_slot}.local_evidence_root_sha256"),
            "feature_schema_id": FEATURE_SCHEMA_ID,
        },
        "base_candidate": base["base_candidate"],
    }


def validate_population_records(rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Validate the one and only 16-row population and reserve diversity rules."""

    if len(rows) != len(SLOTS):
        raise IntegrationError("population_manifest.jsonl must contain exactly 16 rows")
    records = {slot: _validate_population_row(row, slot) for slot, row in zip(SLOTS, rows)}
    for key, location in (("archive_sha256", "archive"), ("source_family_id", "identity"), ("lineage_time_block_id", "identity")):
        values = [records[slot][location][key] for slot in SLOTS]
        if len(values) != len(set(values)):
            raise IntegrationError(f"all 16 {key} values must be pairwise distinct")
    expected_base_slots = set(DEV_PRIMARY_SLOTS)
    actual_base_slots = {slot for slot, record in records.items() if record["base_candidate"]}
    if actual_base_slots != expected_base_slots:
        raise IntegrationError("all and only the six DEV primaries must be base candidates")
    _validate_intervention_diversity(records)
    return records


def _validate_intervention_diversity(records: Mapping[str, Mapping[str, Any]]) -> None:
    scenarios = (
        (_active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT), 3, "DEV"),
        (_active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT), 4, "CONFIRM"),
    )
    for active_sets, minimum, tranche in scenarios:
        for active in active_sets:
            if len({records[slot]["identity"]["intervention_family_id"] for slot in active}) < minimum:
                raise IntegrationError(f"{tranche} intervention diversity fails under an allowed reserve replacement")
    for dev_active in _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT):
        for confirm_active in _active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT):
            active = dev_active + confirm_active
            if len({records[slot]["identity"]["intervention_family_id"] for slot in active}) < 5:
                raise IntegrationError("overall intervention diversity fails under an allowed reserve replacement")


def _decimal(value: Any, label: str) -> Decimal:
    if isinstance(value, bool):
        raise IntegrationError(f"{label} must be an integer or decimal string")
    if isinstance(value, int):
        return Decimal(value)
    if not isinstance(value, str) or _DECIMAL_STRING_RE.fullmatch(value) is None:
        raise IntegrationError(f"{label} must be an integer or canonical decimal string")
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise IntegrationError(f"{label} is not a decimal") from exc


def _validate_features(rows: list[tuple[Mapping[str, Any], bytes]], records: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Decimal]]:
    if len(rows) != len(SLOTS):
        raise IntegrationError("features_manifest.jsonl must contain exactly 16 rows")
    vectors: dict[str, dict[str, Decimal]] = {}
    for expected_slot, (row, raw) in zip(SLOTS, rows):
        value = _exact_fields(row, frozenset({"schema", "slot_id", "feature_schema_id", "features"}), f"feature record {expected_slot}")
        if value["schema"] != FEATURE_RECORD_SCHEMA or value["slot_id"] != expected_slot or value["feature_schema_id"] != FEATURE_SCHEMA_ID:
            raise IntegrationError(f"feature record must be the canonical {expected_slot} row")
        features = _exact_fields(value["features"], frozenset(FEATURE_NAMES), f"{expected_slot}.features")
        digest = hashlib.sha256(raw).hexdigest()
        if digest != records[expected_slot]["feature_binding"]["feature_record_sha256"]:
            raise IntegrationError(f"{expected_slot} feature record hash is not rooted by its population row")
        vectors[expected_slot] = {name: _decimal(features[name], f"{expected_slot}.{name}") for name in FEATURE_NAMES}
    for dev_active in _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT):
        for name in FEATURE_NAMES:
            lower = min(vectors[slot][name] for slot in dev_active)
            upper = max(vectors[slot][name] for slot in dev_active)
            for slot in CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,):
                if not lower <= vectors[slot][name] <= upper:
                    raise IntegrationError(f"{slot}.{name} is outside DEV support under an allowed reserve replacement")
    return vectors


def _validate_attestation_rows(
    rows: list[tuple[Mapping[str, Any], bytes]],
    records: Mapping[str, Mapping[str, Any]],
    *,
    kinds: tuple[str, ...],
    label: str,
) -> None:
    if len(rows) != len(SLOTS) * len(kinds):
        raise IntegrationError(f"{label} must contain one canonical PASS receipt per slot and kind")
    found: set[tuple[str, str]] = set()
    expected_subject = {
        "ARCHIVE_SOURCE_EQUALITY": "source_tree_sha256",
        "ANCESTRY": "source_tree_sha256",
        "LINUX_REPRO": "linux_amd64_build_sha256",
        "SAFETY": "archive_sha256",
    }
    expected_hash_key = {
        "ARCHIVE_SOURCE_EQUALITY": "archive_source_equality_receipt_sha256",
        "ANCESTRY": "ancestry_attestation_sha256",
        "LINUX_REPRO": "linux_repro_receipt_sha256",
        "SAFETY": "safety_receipt_sha256",
    }
    for row, raw in rows:
        value = _exact_fields(row, frozenset({"schema", "slot_id", "archive_sha256", "kind", "subject_sha256", "status"}), f"{label} receipt")
        slot = value["slot_id"]
        kind = value["kind"]
        if value["schema"] != ATTESTATION_SCHEMA or slot not in records or kind not in kinds or value["status"] != "PASS":
            raise IntegrationError(f"{label} contains an invalid receipt")
        key = (slot, kind)
        if key in found:
            raise IntegrationError(f"{label} contains duplicate {slot}/{kind} receipt")
        found.add(key)
        archive = records[slot]["archive"]
        if _sha256(value["archive_sha256"], f"{label}.{slot}.archive_sha256") != archive["archive_sha256"]:
            raise IntegrationError(f"{label} receipt archive does not match {slot}")
        if _sha256(value["subject_sha256"], f"{label}.{slot}.subject_sha256") != archive[expected_subject[kind]]:
            raise IntegrationError(f"{label} receipt subject does not match {slot}")
        if hashlib.sha256(raw).hexdigest() != records[slot]["attestations"][expected_hash_key[kind]]:
            raise IntegrationError(f"{label} receipt hash is not rooted by {slot}")
    if found != {(slot, kind) for slot in SLOTS for kind in kinds}:
        raise IntegrationError(f"{label} is missing a required PASS receipt")


def leaf_hash(path: str, content: bytes) -> str:
    """Compute the exact v6.2.2 domain-separated leaf digest."""

    if not isinstance(path, str) or not path or "\\" in path:
        raise IntegrationError("Merkle paths must be non-empty POSIX paths")
    encoded = path.encode("utf-8")
    if len(encoded) > 0xFFFFFFFF or len(content) > 0xFFFFFFFFFFFFFFFF:
        raise IntegrationError("Merkle path or content is too large")
    return hashlib.sha256(b"\x00" + len(encoded).to_bytes(4, "big") + encoded + len(content).to_bytes(8, "big") + content).hexdigest()


def prereg_merkle(files: Mapping[str, bytes]) -> tuple[str, list[dict[str, str]]]:
    """Return the normative root and path-sorted leaf receipt entries."""

    if set(files) != set(REQUIRED_PREREG_FILES):
        raise IntegrationError("Merkle input must contain exactly the required preregistration files")
    ordered = sorted(files.items(), key=lambda item: item[0].encode("utf-8"))
    leaves = [{"path": path, "leaf_sha256": leaf_hash(path, content)} for path, content in ordered]
    nodes = [bytes.fromhex(entry["leaf_sha256"]) for entry in leaves]
    while len(nodes) > 1:
        next_nodes: list[bytes] = []
        for index in range(0, len(nodes), 2):
            if index + 1 == len(nodes):
                next_nodes.append(hashlib.sha256(b"\x02" + nodes[index]).digest())
            else:
                next_nodes.append(hashlib.sha256(b"\x01" + nodes[index] + nodes[index + 1]).digest())
        nodes = next_nodes
    return nodes[0].hex(), leaves


def deterministic_submission_token(prereg_root_sha256: str, slot_id: str, archive_sha256: str) -> str:
    """Derive the specified 16-character advisory token; it is not a permit."""

    _sha256(prereg_root_sha256, "prereg_root_sha256")
    _sha256(archive_sha256, "archive_sha256")
    _role_for_slot(slot_id)
    digest = hashlib.sha256(b"EVAL621" + bytes.fromhex(prereg_root_sha256) + slot_id.encode("ascii") + bytes.fromhex(archive_sha256)).digest()
    return base64.b32encode(digest).decode("ascii").lower()[:16]


def deterministic_submission_name(prereg_root_sha256: str, slot_id: str, archive_sha256: str) -> str:
    token = deterministic_submission_token(prereg_root_sha256, slot_id, archive_sha256)
    name = f"cal-v621-{slot_id.lower()}-{token}"
    if re.fullmatch(r"[a-z0-9-]+", name) is None or "final" in name:
        raise IntegrationError("derived submission name is invalid")
    return name


def _bundle_files(bundle_dir: str | Path) -> dict[str, bytes]:
    root = Path(bundle_dir)
    if not root.is_dir() or root.is_symlink():
        raise IntegrationError("prereg_bundle must be a real directory")
    actual: set[str] = set()
    for child in root.rglob("*"):
        if child.is_symlink():
            raise IntegrationError("prereg_bundle must not contain symlinks")
        if child.is_dir():
            raise IntegrationError("prereg_bundle must contain only the required top-level files")
        try:
            relative = child.relative_to(root).as_posix()
        except ValueError as exc:
            raise IntegrationError("bundle file escapes prereg_bundle") from exc
        if PurePosixPath(relative).parts != (relative,) or relative not in REQUIRED_PREREG_FILES:
            actual.add(relative)
        else:
            actual.add(relative)
    if actual != set(REQUIRED_PREREG_FILES):
        missing = sorted(set(REQUIRED_PREREG_FILES) - actual)
        extra = sorted(actual - set(REQUIRED_PREREG_FILES))
        raise IntegrationError(f"prereg_bundle files must exactly match the required set (missing={missing}, extra={extra})")
    result: dict[str, bytes] = {}
    for name in REQUIRED_PREREG_FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise IntegrationError(f"required bundle file is missing or unsafe: {name}")
        result[name] = _canonical_file_bytes(path, jsonl=name.endswith(".jsonl"))
    return result


def _validate_root_receipt(receipt_path: str | Path, root_sha256: str, leaves: list[dict[str, str]]) -> Mapping[str, Any]:
    path = Path(receipt_path)
    if path.is_symlink():
        raise IntegrationError("prereg root receipt must not be symlinked")
    value = _read_json(path)
    receipt = _exact_fields(value, frozenset({"schema", "root_sha256", "files", "published_at_utc"}), "prereg root receipt")
    if receipt["schema"] != PREREG_ROOT_SCHEMA or _sha256(receipt["root_sha256"], "root_sha256") != root_sha256:
        raise IntegrationError("prereg root receipt does not match the computed root")
    if not isinstance(receipt["files"], list) or receipt["files"] != leaves:
        raise IntegrationError("prereg root receipt leaf list does not match the computed tree")
    if not isinstance(receipt["published_at_utc"], str) or _RFC3339_UTC_RE.fullmatch(receipt["published_at_utc"]) is None:
        raise IntegrationError("prereg root receipt published_at_utc must be RFC3339 UTC")
    try:
        datetime.strptime(receipt["published_at_utc"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise IntegrationError("prereg root receipt published_at_utc is not a real UTC instant") from exc
    return receipt


def validate_prereg_bundle(bundle_dir: str | Path, prereg_root_receipt: str | Path) -> dict[str, Any]:
    """Validate structural/root integrity without claiming evidence authenticity.

    Rooted caller assertions are not independently authenticated ancestry,
    custody, safety, or semantic artifact evidence.  A separate signed
    verification layer must establish those facts before the population can be
    called feasible or any permit machinery can run.
    """

    files = _bundle_files(bundle_dir)
    population_rows = [row for row, _ in _parse_jsonl_bytes(files["population_manifest.jsonl"], "population_manifest.jsonl")]
    records = validate_population_records(population_rows)
    feature_rows = _parse_jsonl_bytes(files["features_manifest.jsonl"], "features_manifest.jsonl")
    _validate_features(feature_rows, records)
    _validate_attestation_rows(
        _parse_jsonl_bytes(files["ancestry_attestations.jsonl"], "ancestry_attestations.jsonl"), records,
        kinds=("ARCHIVE_SOURCE_EQUALITY", "ANCESTRY", "LINUX_REPRO"), label="ancestry_attestations.jsonl",
    )
    _validate_attestation_rows(
        _parse_jsonl_bytes(files["safety_receipts.jsonl"], "safety_receipts.jsonl"), records,
        kinds=("SAFETY",), label="safety_receipts.jsonl",
    )
    root, leaves = prereg_merkle(files)
    _validate_root_receipt(prereg_root_receipt, root, leaves)
    names = {
        slot: deterministic_submission_name(root, slot, records[slot]["archive"]["archive_sha256"])
        for slot in SLOTS
    }
    return {
        "schema": INTEGRATION_VERDICT_SCHEMA,
        "state": "STRUCTURAL_BUNDLE_VALID_REQUIRES_EXTERNAL_AUTHENTICATION",
        "prereg_root_sha256": root,
        "submission_names": names,
        "external_authentication_verified": False,
        "semantic_artifact_verification_complete": False,
        "population_feasible": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
    }


def assess_prereg_bundle(bundle_dir: str | Path, prereg_root_receipt: str | Path) -> dict[str, Any]:
    """Return a fail-closed feasibility verdict without ever authorizing an upload."""

    try:
        return validate_prereg_bundle(bundle_dir, prereg_root_receipt)
    except IntegrationError as exc:
        return {
            "schema": INTEGRATION_VERDICT_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "failure": str(exc),
            "external_authentication_verified": False,
            "semantic_artifact_verification_complete": False,
            "population_feasible": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
        }
