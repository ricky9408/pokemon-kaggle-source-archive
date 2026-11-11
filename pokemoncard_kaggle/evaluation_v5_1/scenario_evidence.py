"""Fail-closed, research-only G03 source-engine natural-trace verifier.

G03 accepts a trace only when the exact raw source-execution envelope and an
independent trace-attestor countersignature both bind it.  This proves local
mechanics provenance, not a hosted execution, executor identity outside the
pinned key material, hosted RNG fidelity, candidate quality, or submission
authority.  Cross-engine observations remain the separate G04 concern.
"""

from __future__ import annotations

from collections.abc import Mapping
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import re
from decimal import Decimal, ROUND_HALF_EVEN
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import PROTOCOL_ID
from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .exact_gate_v2 import (
    ExactGateV2Error,
    decode_byte_evidence,
    dependency_closure_root,
    parse_final_bundle,
    strict_canonical_json,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)


SCENARIO_PLAN_SCHEMA = "evaluation_v5_1_natural_game_plan_v3"
EXECUTION_RECEIPT_SCHEMA = "evaluation_v5_1_natural_game_receipt_v4"
SCENARIO_EVIDENCE_SCHEMA = "evaluation_v5_1_natural_game_evidence_audit_v3"
SOURCE_TRACE_RECEIPT_SCHEMA = "evaluation_v5_1_source_trace_receipt_v1"
G03_EXECUTION_ENVELOPE_SCHEMA = "evaluation_v5_1_g03_source_execution_envelope_v1"
G03_EXECUTION_PAYLOAD_SCHEMA = "evaluation_v5_1_g03_source_execution_payload_v1"
G03_TRACE_ATTESTATION_ENVELOPE_SCHEMA = "evaluation_v5_1_g03_trace_attestation_envelope_v1"
G03_TRACE_ATTESTATION_SCHEMA = "evaluation_v5_1_g03_trace_attestation_v1"
G03_G02_DEPENDENCY_BUNDLE_SCHEMA = "evaluation_v5_1_g03_g02_dependency_bundle_v1"
G03_EXECUTION_ENVELOPE_MEDIA_TYPE = "application/vnd.ptcg.g03-source-execution-envelope+json"
G03_TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE = "application/vnd.ptcg.g03-trace-attestation-envelope+json"
G03_EXECUTION_PAYLOAD_MEDIA_TYPE = "application/vnd.ptcg.g03-source-execution-payload+json"
G03_TRACE_MEDIA_TYPE = "application/vnd.ptcg.g03-natural-trace+json"
G03_STATE_MEDIA_TYPE = "application/vnd.ptcg.g03-natural-state+json"
G03_INVENTORY_MEDIA_TYPE = "application/vnd.ptcg.g03-execution-inventory+json"
G03_G02_BUNDLE_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-bundle+json"
G03_G02_AUTHORITY_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-authority-payload+json"
G03_EXECUTION_DOMAIN = b"PTCG/G03/SOURCE_EXECUTION/v1\0"
G03_TRACE_ATTESTATION_DOMAIN = b"PTCG/G03/TRACE_ATTESTATION/v1\0"
G03_RUNNER_PATH = "/opt/evaluation-v5.1/bin/g03-natural-game-runner"
G03_RUNNER_ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin", "TZ": "UTC"}
MAX_G03_BYTE_EVIDENCE = 16 * 1024 * 1024
NATURAL_TEMPLATE = "natural_start"
AGGREGATION_FORMULA = "family_seat_seed_balanced_mean_v2"
SEED_DERIVATION_SCHEME = "sha256_source_natural_seed_v3"
FAILURE_RULE = "zero_on_failure"
FEATURE_REGISTRY = ("A2", "P4", "E2", "K1", "S1", "R4")
MODEL_FEATURES = ("A2", "P4", "E2", "K1", "S1")
EFFICACY_FEATURES = ("E2", "K1", "S1")
SUPPORT_FEATURES = MODEL_FEATURES
TERMINAL_CATEGORIES = ("completed", "exception", "forbidden_action", "illegal", "timeout")
EVENT_TYPES = frozenset(
    {
        "GAME_START", "TURN_START", "ACTION_REQUESTED", "ACTION_CHOSEN",
        "MANUAL_ENERGY_ATTACHED", "ATTACK_DECLARED", "DAMAGE_APPLIED",
        "PRIZE_TAKEN", "POKEMON_KO", "ACTIVE_PROMOTED", "FORCED_SWITCH",
        "RUN_AWAY_DRAW_ATTEMPT", "ILLEGAL_ACTION", "POLICY_EXCEPTION",
        "TIMEOUT", "GAME_END",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_PLAN_FIELDS = frozenset({
    "schema", "protocol_id", "candidate_archive_sha256", "deck_sha256", "policy_sha256",
    "seed_commitment_sha256", "engine_bindings", "opponent_packages", "era_calendar",
    "scheduled_terminal_categories", "evidence_partition", "cells",
})
_ENGINE_FIELDS = frozenset({"engine_sha256", "container_sha256"})
_OPPONENT_FIELDS = frozenset({"package_sha256", "family_id", "lineage_id"})
_ERA_FIELDS = frozenset({"era", "starts_at_utc", "ends_at_utc"})
_CELL_FIELDS = frozenset({
    "cell_id", "template", "engine_id",
    "opponent_package_id", "state_constructor_sha256", "seat", "seed_derivation",
    "attempt_index", "failure_rule", "aggregation_formula",
})
_SEED_FIELDS = frozenset({"scheme", "seed_index"})
_RECEIPT_FIELDS = frozenset({
    "schema", "protocol_id", "scenario_plan_sha256", "candidate_archive_sha256",
    "deck_sha256", "policy_sha256", "engine_bindings", "g02_dependency_bundle_sha256", "cells",
})
_RECEIPT_CELL_FIELDS = frozenset({
    "cell_id", "state_blob_sha256", "trace_blob_sha256", "result_blob_sha256", "safety_blob_sha256",
    "execution_envelope", "trace_attestation_envelope",
})
_EVENT_FIELDS = frozenset({"event_type", "event_index", "previous_event_sha256", "payload", "event_sha256"})
_SOURCE_TRACE_RECEIPT_FIELDS = frozenset({
    "schema", "protocol_id", "scenario_sha256", "game_id", "archive_id", "lineage_id",
    "scenario_plan", "cell_id", "state", "trace", "result", "safety",
})
_G03_KEY_FIELDS = frozenset({"role", "key_id", "principal_id", "custodian_id", "algorithm", "public_A_ed25519_base64"})
_G03_SIGNED_ENVELOPE_FIELDS = frozenset({"schema", "signer_key_id", "payload", "signature_A_ed25519_base64", "signature_R_ed25519_base64", "signature_S_ed25519_base64"})
_G03_EXECUTION_FIELDS = frozenset({
    "schema", "protocol_id", "scenario_plan_sha256", "cell_id", "candidate_archive_sha256", "deck_sha256", "policy_sha256",
    "engine_sha256", "container_sha256", "platform_os", "platform_arch", "runner_image_sha256", "runner_binary_sha256",
    "runner_image", "runner_binary", "argv", "env", "input_state", "pre_run_inventory", "post_run_inventory",
    "attempt_index", "retry_count", "replacement_count", "intervention_count", "rng_state_injection_count", "forced_state_count",
    "restore_count", "carryover_count", "started_at_utc", "ended_at_utc", "exit_code", "status",
    "raw_trace", "executor_key_id", "executor_principal_id", "executor_custodian_id",
})
_G03_ATTESTATION_FIELDS = frozenset({
    "schema", "protocol_id", "scenario_plan_sha256", "cell_id", "execution_envelope_sha256", "execution_envelope_decoded_length",
    "execution_payload_sha256", "execution_payload_decoded_length", "raw_trace_sha256", "raw_trace_decoded_length",
    "raw_trace_media_type", "independent_trace_root_sha256", "attested_at_utc", "trace_attestor_key_id",
    "trace_attestor_principal_id", "trace_attestor_custodian_id",
})
_G03_G02_BUNDLE_FIELDS = frozenset({"schema", "exact_g02_final_bundle", "g02_authority_payload", "transitive_dependencies", "transitive_edges"})
_G03_G02_IDENTITY_FIELDS = frozenset({
    "schema_version", "protocol_id", "campaign_root", "evaluation_id", "evaluation_nonce", "gate_id", "input_bundle_root",
    "direct_dependencies", "dependency_closure_root", "decision",
})
_G03_INVENTORY_PRE_FIELDS = frozenset({"schema", "cell_id", "state_blob_sha256", "argv", "env"})
_G03_INVENTORY_POST_FIELDS = frozenset({"schema", "cell_id", "pre_run_inventory_sha256", "trace_blob_sha256", "working_tree_clean", "created_paths", "modified_paths", "deleted_paths"})
_Q12 = Decimal("0.000000000001")


class ScenarioEvidenceError(ValueError):
    """Natural-game evidence does not satisfy the frozen v5.1 protocol."""


class _DuplicateJSONKey(ValueError):
    pass


ExecutorSignatureVerifier = Callable[[bytes, str, Mapping[str, Any]], bool]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_blob(raw: bytes, label: str) -> Mapping[str, Any]:
    if type(raw) is not bytes:
        raise ScenarioEvidenceError(f"{label} must be immutable bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                           parse_constant=lambda text: (_ for _ in ()).throw(ValueError(text)))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ScenarioEvidenceError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ScenarioEvidenceError(f"{label} must be a JSON object")
    return value


def _fields(value: object, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ScenarioEvidenceError(f"{label} fields must exactly be {sorted(expected)}")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ScenarioEvidenceError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise ScenarioEvidenceError(f"{label} must be a non-empty trimmed string")
    return value


def _utc(value: object, label: str) -> tuple[str, datetime]:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise ScenarioEvidenceError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ScenarioEvidenceError(f"{label} must be a real UTC timestamp") from exc
    return value, parsed


def _q12(value: Decimal) -> str:
    return format(value.quantize(_Q12, rounding=ROUND_HALF_EVEN), "f")


def _calendar(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ScenarioEvidenceError("era_calendar must be non-empty")
    result: list[dict[str, str]] = []
    previous: datetime | None = None
    names: set[str] = set()
    for index, item in enumerate(value):
        raw = _fields(item, _ERA_FIELDS, f"era_calendar[{index}]")
        era = _text(raw["era"], "era name")
        start, start_dt = _utc(raw["starts_at_utc"], "era start")
        end, end_dt = _utc(raw["ends_at_utc"], "era end")
        if era in names or start_dt >= end_dt or (previous is not None and start_dt != previous):
            raise ScenarioEvidenceError("era calendar must be ordered, non-overlapping, and gap-free")
        names.add(era)
        previous = end_dt
        result.append({"era": era, "starts_at_utc": start, "ends_at_utc": end})
    return result


def validate_scenario_plan(value: object) -> dict[str, Any]:
    """Validate the exact natural-game plan; feature names are not configurable."""

    plan = _fields(value, _PLAN_FIELDS, "scenario plan")
    if plan["schema"] != SCENARIO_PLAN_SCHEMA or plan["protocol_id"] != PROTOCOL_ID:
        raise ScenarioEvidenceError("scenario plan schema or protocol is invalid")
    if plan["scheduled_terminal_categories"] != list(TERMINAL_CATEGORIES):
        raise ScenarioEvidenceError("scheduled terminal categories must be the frozen complete set")
    if plan["evidence_partition"] not in {"DEV", "RESEARCH"}:
        raise ScenarioEvidenceError("evidence_partition must be DEV or RESEARCH")
    engines = plan["engine_bindings"]
    if not isinstance(engines, Mapping) or set(engines) != {"pinned_source"}:
        raise ScenarioEvidenceError("G03 requires exactly one pinned source engine binding")
    checked_engines = {
        "pinned_source": {field: _sha(_fields(engines["pinned_source"], _ENGINE_FIELDS, "pinned_source")[field], f"pinned_source.{field}") for field in _ENGINE_FIELDS}
    }
    opponents = plan["opponent_packages"]
    if not isinstance(opponents, Mapping) or not opponents:
        raise ScenarioEvidenceError("opponent packages must be non-empty")
    checked_opponents: dict[str, dict[str, str]] = {}
    for key, item in opponents.items():
        name = _text(key, "opponent package id")
        raw = _fields(item, _OPPONENT_FIELDS, f"opponent {name}")
        checked_opponents[name] = {
            "package_sha256": _sha(raw["package_sha256"], "opponent package hash"),
            "family_id": _text(raw["family_id"], "family id"),
            "lineage_id": _text(raw["lineage_id"], "lineage id"),
        }
    cells_raw = plan["cells"]
    if not isinstance(cells_raw, list) or not cells_raw:
        raise ScenarioEvidenceError("cells must be a non-empty list")
    cells: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    retries: set[tuple[object, ...]] = set()
    for index, item in enumerate(cells_raw):
        raw = _fields(item, _CELL_FIELDS, f"cell {index}")
        cell_id = _text(raw["cell_id"], "cell id")
        if cell_id in identifiers or raw["template"] != NATURAL_TEMPLATE:
            raise ScenarioEvidenceError("cells must be unique natural-start source episodes")
        if raw["engine_id"] != "pinned_source" or raw["opponent_package_id"] not in checked_opponents:
            raise ScenarioEvidenceError("cell engine or opponent package is invalid")
        if type(raw["seat"]) is not int or raw["seat"] not in (0, 1) or raw["attempt_index"] != 0:
            raise ScenarioEvidenceError("cell seat is invalid or attempts/retries are forbidden")
        seed = _fields(raw["seed_derivation"], _SEED_FIELDS, "seed derivation")
        if seed["scheme"] != SEED_DERIVATION_SCHEME or type(seed["seed_index"]) is not int or seed["seed_index"] < 0:
            raise ScenarioEvidenceError("seed derivation is invalid")
        if raw["failure_rule"] != FAILURE_RULE or raw["aggregation_formula"] != AGGREGATION_FORMULA:
            raise ScenarioEvidenceError("failure/aggregation formula is not frozen")
        state_constructor = _sha(raw["state_constructor_sha256"], "state constructor hash")
        retry_key = (raw["opponent_package_id"], state_constructor, raw["seat"], seed["seed_index"])
        if retry_key in retries:
            raise ScenarioEvidenceError("retry replacement is forbidden")
        retries.add(retry_key)
        identifiers.add(cell_id)
        cells.append({
            "cell_id": cell_id, "template": NATURAL_TEMPLATE, "engine_id": "pinned_source",
            "opponent_package_id": raw["opponent_package_id"], "state_constructor_sha256": state_constructor,
            "seat": raw["seat"], "seed_derivation": {"scheme": SEED_DERIVATION_SCHEME, "seed_index": seed["seed_index"]},
            "attempt_index": 0, "failure_rule": FAILURE_RULE, "aggregation_formula": AGGREGATION_FORMULA,
        })
    return {
        "schema": SCENARIO_PLAN_SCHEMA, "protocol_id": PROTOCOL_ID,
        "candidate_archive_sha256": _sha(plan["candidate_archive_sha256"], "archive hash"),
        "deck_sha256": _sha(plan["deck_sha256"], "deck hash"),
        "policy_sha256": _sha(plan["policy_sha256"], "policy hash"),
        "seed_commitment_sha256": _sha(plan["seed_commitment_sha256"], "seed commitment"),
        "engine_bindings": checked_engines, "opponent_packages": checked_opponents,
        "era_calendar": _calendar(plan["era_calendar"]),
        "scheduled_terminal_categories": list(TERMINAL_CATEGORIES), "evidence_partition": plan["evidence_partition"], "cells": cells,
    }


def scenario_plan_sha256(value: object) -> str:
    return canonical_sha256(validate_scenario_plan(value))


def derive_cell_seed(plan: Mapping[str, Any], cell: Mapping[str, Any]) -> int:
    """Derive a source natural-game seed from the frozen schedule."""
    material = {"scheme": SEED_DERIVATION_SCHEME, "seed_commitment_sha256": plan["seed_commitment_sha256"],
                "opponent_package_id": cell["opponent_package_id"], "state_constructor_sha256": cell["state_constructor_sha256"],
                "seat": cell["seat"], "seed_index": cell["seed_derivation"]["seed_index"]}
    return int.from_bytes(hashlib.sha256(canonical_json_bytes(material)).digest()[:8], "big")


def canonical_execution_receipt_bytes(value: object) -> bytes:
    if not isinstance(value, Mapping):
        raise ScenarioEvidenceError("execution receipt must be an object")
    unsigned = dict(value)
    unsigned.pop("executor_signature", None)
    return canonical_json_bytes(unsigned)


def _byte_evidence(value: object, *, media_type: str, label: str, expected_sha256: str | None = None) -> bytes:
    try:
        raw = decode_byte_evidence(value, expected_media_type=media_type, expected_sha256=expected_sha256)
    except ExactGateV2Error as exc:
        raise ScenarioEvidenceError(f"{label} byte evidence is invalid: {exc}") from exc
    if len(raw) > MAX_G03_BYTE_EVIDENCE:
        raise ScenarioEvidenceError(f"{label} exceeds the G03 byte bound")
    return raw


def _canonical_object(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = strict_canonical_json(raw, label=label)
    except ExactGateV2Error as exc:
        raise ScenarioEvidenceError(f"{label} is not exact canonical JSON") from exc
    if not isinstance(value, Mapping):
        raise ScenarioEvidenceError(f"{label} must be a JSON object")
    return value


def _base64(value: object, *, label: str, length: int) -> bytes:
    if type(value) is not str:
        raise ScenarioEvidenceError(f"{label} must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ScenarioEvidenceError(f"{label} must be canonical base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise ScenarioEvidenceError(f"{label} has an invalid encoding length")
    return raw


def _identity(value: object, label: str) -> str:
    if type(value) is not str or _IDENTITY_RE.fullmatch(value) is None:
        raise ScenarioEvidenceError(f"{label} is not a canonical identity")
    return value


def _custody_key(value: object, *, role: str, pinned_public_key: bytes) -> dict[str, Any]:
    raw = _fields(value, _G03_KEY_FIELDS, f"{role} key")
    if raw["role"] != role or raw["algorithm"] != "Ed25519":
        raise ScenarioEvidenceError(f"{role} key role or algorithm is invalid")
    public_key = _base64(raw["public_A_ed25519_base64"], label=f"{role} public A", length=32)
    try:
        derived_key_id = validate_ed25519_public_key(public_key)
        validate_ed25519_public_key(pinned_public_key)
    except ExactGateV2Error as exc:
        raise ScenarioEvidenceError(f"{role} public A encoding is invalid") from exc
    if public_key != pinned_public_key or raw["key_id"] != derived_key_id:
        raise ScenarioEvidenceError(f"{role} key is not pinned to its derived key ID")
    return {
        "role": role,
        "key_id": derived_key_id,
        "principal_id": _identity(raw["principal_id"], f"{role} principal"),
        "custodian_id": _identity(raw["custodian_id"], f"{role} custodian"),
        "public_key": public_key,
    }


def _verify_signed_envelope(
    value: object,
    *,
    media_type: str,
    schema: str,
    key: Mapping[str, Any],
    domain: bytes,
    label: str,
) -> tuple[Mapping[str, Any], bytes, bytes]:
    envelope_raw = _byte_evidence(value, media_type=media_type, label=label)
    envelope = _fields(_canonical_object(envelope_raw, label), _G03_SIGNED_ENVELOPE_FIELDS, label)
    if envelope["schema"] != schema or envelope["signer_key_id"] != key["key_id"]:
        raise ScenarioEvidenceError(f"{label} schema or signer key ID is invalid")
    payload_raw = _byte_evidence(envelope["payload"], media_type=(G03_EXECUTION_PAYLOAD_MEDIA_TYPE if schema == G03_EXECUTION_ENVELOPE_SCHEMA else "application/vnd.ptcg.g03-trace-attestation+json"), label=f"{label} payload")
    payload = _canonical_object(payload_raw, f"{label} payload")
    signature_a = _base64(envelope["signature_A_ed25519_base64"], label=f"{label} signature A", length=32)
    signature = _base64(envelope["signature_R_ed25519_base64"], label=f"{label} signature R", length=32) + _base64(envelope["signature_S_ed25519_base64"], label=f"{label} signature S", length=32)
    if signature_a != key["public_key"]:
        raise ScenarioEvidenceError(f"{label} signature A does not match its pinned signer")
    try:
        validate_ed25519_signature_encoding(signature)
        Ed25519PublicKey.from_public_bytes(key["public_key"]).verify(signature, domain + len(payload_raw).to_bytes(8, "big") + payload_raw)
    except (ExactGateV2Error, InvalidSignature, ValueError) as exc:
        raise ScenarioEvidenceError(f"{label} Ed25519 A/R/S signature is invalid") from exc
    return payload, payload_raw, envelope_raw


def _validate_g02_dependency_bundle(value: object) -> str:
    """Derive G02 identity from exact bytes; caller-provided summaries are ignored."""

    raw = _fields(value, _G03_G02_BUNDLE_FIELDS, "G02 dependency bundle")
    if raw["schema"] != G03_G02_DEPENDENCY_BUNDLE_SCHEMA:
        raise ScenarioEvidenceError("G02 dependency bundle schema is invalid")
    bundle_raw = _byte_evidence(raw["exact_g02_final_bundle"], media_type=G03_G02_BUNDLE_MEDIA_TYPE, label="exact G02 final bundle")
    try:
        authority_envelope_raw, _validator_envelope_raw, _ = parse_final_bundle(bundle_raw)
    except ExactGateV2Error as exc:
        raise ScenarioEvidenceError("exact G02 final bundle is malformed") from exc
    authority_envelope = _canonical_object(authority_envelope_raw, "G02 authority envelope")
    authority_payload_raw = _byte_evidence(raw["g02_authority_payload"], media_type=G03_G02_AUTHORITY_MEDIA_TYPE, label="G02 authority payload")
    if not isinstance(authority_envelope.get("payload"), Mapping):
        raise ScenarioEvidenceError("G02 authority envelope payload is malformed")
    envelope_payload_raw = _byte_evidence(authority_envelope["payload"], media_type=G03_G02_AUTHORITY_MEDIA_TYPE, label="embedded G02 authority payload")
    if authority_payload_raw != envelope_payload_raw:
        raise ScenarioEvidenceError("G02 authority payload does not come from the exact final bundle")
    identity = _fields(_canonical_object(authority_payload_raw, "G02 authority payload"), _G03_G02_IDENTITY_FIELDS, "G02 authority identity")
    if identity["protocol_id"] != PROTOCOL_ID or identity["gate_id"] != "G02_ENGINE_EVENT_CAPABILITY" or identity["decision"] != "PASS_RESEARCH_ONLY":
        raise ScenarioEvidenceError("G02 authority identity is not a passing G02 mechanics record")
    for field in ("campaign_root", "evaluation_nonce", "input_bundle_root", "dependency_closure_root"):
        _sha(identity[field], f"G02 authority {field}")
    _identity(identity["evaluation_id"], "G02 authority evaluation ID")
    direct = identity["direct_dependencies"]
    if not isinstance(direct, list) or [
        item.get("gate_id") if isinstance(item, Mapping) else None for item in direct
    ] != ["G01_CONSTITUTION_AND_CODE_FREEZE"]:
        raise ScenarioEvidenceError(
            "G02 authority direct dependencies differ from the registered DAG"
        )
    if any(not isinstance(item, Mapping) or item.get("decision") != "PASS_RESEARCH_ONLY" for item in direct):
        raise ScenarioEvidenceError("passing G02 mechanics evidence contains a failed direct dependency")
    nodes = raw["transitive_dependencies"]
    edges = raw["transitive_edges"]
    if not isinstance(nodes, list) or not isinstance(edges, list) or len(nodes) > 16 or len(edges) > 256:
        raise ScenarioEvidenceError("G02 dependency closure is not bounded")
    try:
        closure_root = dependency_closure_root(nodes, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY")
    except ExactGateV2Error as exc:
        raise ScenarioEvidenceError("G02 dependency closure is invalid") from exc
    if closure_root != identity["dependency_closure_root"]:
        raise ScenarioEvidenceError("G02 dependency closure root was not recursively recomputed")
    by_gate = {item.get("gate_id"): item for item in nodes if isinstance(item, Mapping)}
    if len(by_gate) != len(nodes) or any(by_gate.get(item["gate_id"]) != item for item in direct):
        raise ScenarioEvidenceError("G02 direct dependencies do not match the recursively supplied closure")
    node_ids = set(by_gate)
    adjacency: dict[str, list[str]] = {"G02_ENGINE_EVENT_CAPABILITY": []}
    adjacency.update({gate: [] for gate in node_ids})
    for edge in edges:
        if not isinstance(edge, Mapping):
            raise ScenarioEvidenceError("G02 dependency edge is malformed")
        parent, child = edge.get("gate_id"), edge.get("dependency_gate_id")
        if parent not in adjacency or child not in node_ids:
            raise ScenarioEvidenceError("G02 dependency edge escapes the supplied recursive closure")
        adjacency[parent].append(child)
    if adjacency["G02_ENGINE_EVENT_CAPABILITY"] != [item["gate_id"] for item in direct]:
        raise ScenarioEvidenceError("G02 recursive closure does not expose its exact direct dependencies")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(gate: str) -> None:
        if gate in visiting:
            raise ScenarioEvidenceError("G02 recursive dependency closure contains a cycle")
        if gate in visited:
            return
        visiting.add(gate)
        for child in adjacency[gate]:
            visit(child)
        visiting.remove(gate)
        visited.add(gate)

    visit("G02_ENGINE_EVENT_CAPABILITY")
    if visited != {"G02_ENGINE_EVENT_CAPABILITY", *node_ids}:
        raise ScenarioEvidenceError("G02 recursive dependency closure contains an unreachable identity")
    return hashlib.sha256(bundle_raw).hexdigest()


def _validate_receipt(value: object, plan: Mapping[str, Any], plan_hash: str, g02_bundle_sha256: str) -> dict[str, dict[str, Any]]:
    receipt = _fields(value, _RECEIPT_FIELDS, "execution receipt")
    if receipt["schema"] != EXECUTION_RECEIPT_SCHEMA or receipt["protocol_id"] != PROTOCOL_ID:
        raise ScenarioEvidenceError("receipt schema or protocol is invalid")
    for field, expected in (("scenario_plan_sha256", plan_hash), ("candidate_archive_sha256", plan["candidate_archive_sha256"]), ("deck_sha256", plan["deck_sha256"]), ("policy_sha256", plan["policy_sha256"])):
        if _sha(receipt[field], field) != expected:
            raise ScenarioEvidenceError("receipt does not bind exact archive/deck/policy/plan hashes")
    if receipt["engine_bindings"] != plan["engine_bindings"]:
        raise ScenarioEvidenceError("receipt engine/container bindings differ from the plan")
    if _sha(receipt["g02_dependency_bundle_sha256"], "G02 dependency bundle hash") != g02_bundle_sha256:
        raise ScenarioEvidenceError("receipt does not bind the exact recursively verified G02 bundle")
    entries = receipt["cells"]
    if not isinstance(entries, list) or len(entries) != len(plan["cells"]):
        raise ScenarioEvidenceError("receipt must enumerate every scheduled cell exactly once")
    result: dict[str, dict[str, Any]] = {}
    for item in entries:
        raw = _fields(item, _RECEIPT_CELL_FIELDS, "receipt cell")
        cell_id = _text(raw["cell_id"], "receipt cell id")
        if cell_id in result:
            raise ScenarioEvidenceError("duplicate/retried receipt cell")
        result[cell_id] = {
            **{name: _sha(raw[name], name) for name in ("state_blob_sha256", "trace_blob_sha256", "result_blob_sha256", "safety_blob_sha256")},
            "execution_envelope": raw["execution_envelope"], "trace_attestation_envelope": raw["trace_attestation_envelope"],
        }
    if set(result) != {cell["cell_id"] for cell in plan["cells"]}:
        raise ScenarioEvidenceError("receipt has omitted or replacement cells")
    return result


def _raw_blob(blobs: Mapping[str, bytes], digest: str, label: str) -> bytes:
    try:
        raw = blobs[digest]
    except (KeyError, TypeError) as exc:
        raise ScenarioEvidenceError(f"missing {label} blob") from exc
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
        raise ScenarioEvidenceError(f"{label} blob hash mismatch")
    return raw


def _blob(blobs: Mapping[str, bytes], digest: str, label: str) -> Mapping[str, Any]:
    raw = _raw_blob(blobs, digest, label)
    return _parse_blob(raw, label)


def _expected_state(plan: Mapping[str, Any], plan_hash: str, cell: Mapping[str, Any]) -> dict[str, Any]:
    engine = plan["engine_bindings"][cell["engine_id"]]
    opponent = plan["opponent_packages"][cell["opponent_package_id"]]
    return {
        "schema": "evaluation_v5_1_natural_game_state_v2", "scenario_plan_sha256": plan_hash,
        "cell_id": cell["cell_id"], "candidate_archive_sha256": plan["candidate_archive_sha256"],
        "deck_sha256": plan["deck_sha256"], "policy_sha256": plan["policy_sha256"],
        "engine_sha256": engine["engine_sha256"], "container_sha256": engine["container_sha256"],
        "opponent_package_sha256": opponent["package_sha256"], "state_constructor_sha256": cell["state_constructor_sha256"],
        "seat": cell["seat"], "deterministic_seed": derive_cell_seed(plan, cell), "template": NATURAL_TEMPLATE,
    }


def _event_payload(event_type: str, payload: object) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ScenarioEvidenceError("event payload must be an object")
    required: dict[str, frozenset[str]] = {
        "GAME_START": frozenset(), "TURN_START": frozenset({"owner", "own_turn"}),
        "ACTION_REQUESTED": frozenset({"observation_sha256", "legal_actions_sha256"}), "ACTION_CHOSEN": frozenset({"action_sha256"}),
        "MANUAL_ENERGY_ATTACHED": frozenset({"pokemon_id", "pokemon_kind"}), "ATTACK_DECLARED": frozenset({"attacker_id", "owner"}),
        "DAMAGE_APPLIED": frozenset({"attacker_id", "source_owner", "amount"}), "PRIZE_TAKEN": frozenset({"owner", "count"}),
        "POKEMON_KO": frozenset({"owner", "was_active"}), "ACTIVE_PROMOTED": frozenset({"owner", "pokemon_id"}),
        "FORCED_SWITCH": frozenset({"owner"}), "RUN_AWAY_DRAW_ATTEMPT": frozenset({"pokemon_id", "sole_pokemon_in_play"}),
        "ILLEGAL_ACTION": frozenset(), "POLICY_EXCEPTION": frozenset(), "TIMEOUT": frozenset(), "GAME_END": frozenset({"terminal_category"}),
    }
    if set(payload) != required[event_type]:
        raise ScenarioEvidenceError(f"{event_type} payload fields are not exact")
    if event_type in {"TURN_START", "ATTACK_DECLARED", "PRIZE_TAKEN", "POKEMON_KO", "ACTIVE_PROMOTED", "FORCED_SWITCH", "DAMAGE_APPLIED"}:
        owner = payload.get("owner", payload.get("source_owner"))
        if owner not in {"self", "opponent"}:
            raise ScenarioEvidenceError("event owner is invalid")
    if event_type == "TURN_START" and (type(payload["own_turn"]) is not int or payload["own_turn"] < 0):
        raise ScenarioEvidenceError("TURN_START own_turn is invalid")
    if event_type in {"ACTION_REQUESTED", "ACTION_CHOSEN"}:
        for value in payload.values(): _sha(value, "action primitive hash")
    if event_type in {"MANUAL_ENERGY_ATTACHED", "ATTACK_DECLARED", "DAMAGE_APPLIED", "ACTIVE_PROMOTED", "RUN_AWAY_DRAW_ATTEMPT"}:
        _text(payload.get("pokemon_id", payload.get("attacker_id")), "pokemon id")
    if event_type == "MANUAL_ENERGY_ATTACHED" and payload["pokemon_kind"] not in {"combatant", "dunsparce_engine"}:
        raise ScenarioEvidenceError("manual attachment pokemon kind is invalid")
    if event_type == "DAMAGE_APPLIED" and (type(payload["amount"]) is not int or payload["amount"] < 0):
        raise ScenarioEvidenceError("damage amount is invalid")
    if event_type == "PRIZE_TAKEN" and (type(payload["count"]) is not int or not 0 <= payload["count"] <= 6):
        raise ScenarioEvidenceError("prize count is invalid")
    if event_type == "POKEMON_KO" and type(payload["was_active"]) is not bool:
        raise ScenarioEvidenceError("KO active flag is invalid")
    if event_type == "RUN_AWAY_DRAW_ATTEMPT" and type(payload["sole_pokemon_in_play"]) is not bool:
        raise ScenarioEvidenceError("Run Away sole-Pokemon flag is invalid")
    if event_type == "GAME_END" and payload["terminal_category"] not in TERMINAL_CATEGORIES:
        raise ScenarioEvidenceError("GAME_END terminal category is invalid")
    return payload


def _events(trace: Mapping[str, Any], cell: Mapping[str, Any], state_hash: str, plan_hash: str) -> list[tuple[str, Mapping[str, Any]]]:
    raw = _fields(trace, frozenset({"schema", "scenario_plan_sha256", "cell_id", "state_blob_sha256", "template", "events"}), "trace")
    if raw["schema"] != "evaluation_v5_1_natural_game_trace_v2" or raw["scenario_plan_sha256"] != plan_hash or raw["cell_id"] != cell["cell_id"] or raw["state_blob_sha256"] != state_hash or raw["template"] != NATURAL_TEMPLATE:
        raise ScenarioEvidenceError("trace does not bind exact planned state")
    if not isinstance(raw["events"], list) or not raw["events"]:
        raise ScenarioEvidenceError("trace must contain events")
    previous = state_hash
    result: list[tuple[str, Mapping[str, Any]]] = []
    game_end = 0
    for index, item in enumerate(raw["events"]):
        event = _fields(item, _EVENT_FIELDS, f"event {index}")
        event_type = event["event_type"]
        if event_type not in EVENT_TYPES or event["event_index"] != index or _sha(event["previous_event_sha256"], "previous event hash") != previous:
            raise ScenarioEvidenceError("event vocabulary, index, or hash chain is invalid")
        payload = _event_payload(event_type, event["payload"])
        unsigned = {"event_type": event_type, "event_index": index, "previous_event_sha256": previous, "payload": dict(payload)}
        digest = canonical_sha256(unsigned)
        if _sha(event["event_sha256"], "event hash") != digest:
            raise ScenarioEvidenceError("event hash chain is broken")
        if event_type == "GAME_END": game_end += 1
        previous = digest
        result.append((event_type, payload))
    if game_end != 1 or result[0][0] != "GAME_START" or result[-1][0] != "GAME_END":
        raise ScenarioEvidenceError("trace must have one terminal GAME_END without replacement")
    return result


def _validate_cell_provenance(
    *,
    refs: Mapping[str, Any],
    blobs: Mapping[str, bytes],
    plan: Mapping[str, Any],
    plan_hash: str,
    cell: Mapping[str, Any],
    executor_key: Mapping[str, Any],
    attestor_key: Mapping[str, Any],
) -> None:
    """Bind raw state/trace bytes to two independent, pinned G03 signatures."""

    state_raw = _raw_blob(blobs, refs["state_blob_sha256"], "state")
    trace_raw = _raw_blob(blobs, refs["trace_blob_sha256"], "trace")
    # Exact canonical parsing is deliberate: a parsed-equivalent, hand-authored
    # JSON object is never evidence unless these precise bytes were signed.
    state = _canonical_object(state_raw, "raw source state")
    trace = _canonical_object(trace_raw, "raw source trace")
    if dict(state) != _expected_state(plan, plan_hash, cell):
        raise ScenarioEvidenceError("raw source state differs from the planned cell")
    events = _events(trace, cell, refs["state_blob_sha256"], plan_hash)
    trace_root = trace["events"][-1]["event_sha256"]

    execution, execution_payload_raw, execution_envelope_raw = _verify_signed_envelope(
        refs["execution_envelope"], media_type=G03_EXECUTION_ENVELOPE_MEDIA_TYPE,
        schema=G03_EXECUTION_ENVELOPE_SCHEMA, key=executor_key,
        domain=G03_EXECUTION_DOMAIN, label=f"{cell['cell_id']} source execution envelope",
    )
    payload = _fields(execution, _G03_EXECUTION_FIELDS, "source execution payload")
    engine = plan["engine_bindings"]["pinned_source"]
    expected_bindings = {
        "schema": G03_EXECUTION_PAYLOAD_SCHEMA, "protocol_id": PROTOCOL_ID,
        "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"],
        "candidate_archive_sha256": plan["candidate_archive_sha256"], "deck_sha256": plan["deck_sha256"], "policy_sha256": plan["policy_sha256"],
        "engine_sha256": engine["engine_sha256"], "container_sha256": engine["container_sha256"],
        "platform_os": "linux", "platform_arch": "amd64", "runner_image_sha256": engine["container_sha256"],
        "runner_binary_sha256": engine["engine_sha256"], "argv": [G03_RUNNER_PATH, "--input", "/input/state.json", "--raw-trace-output", "/output/trace.json"],
        "env": G03_RUNNER_ENV, "exit_code": 0, "status": "SUCCEEDED",
        "executor_key_id": executor_key["key_id"], "executor_principal_id": executor_key["principal_id"], "executor_custodian_id": executor_key["custodian_id"],
    }
    if any(payload[field] != expected for field, expected in expected_bindings.items()):
        raise ScenarioEvidenceError("source execution payload binding, platform, argv, or environment is invalid")
    for field in ("attempt_index", "retry_count", "replacement_count", "intervention_count", "rng_state_injection_count", "forced_state_count", "restore_count", "carryover_count"):
        if payload[field] != 0:
            raise ScenarioEvidenceError(f"source execution {field} must be an explicit zero receipt")
    started_text, started = _utc(payload["started_at_utc"], "source execution started_at_utc")
    ended_text, ended = _utc(payload["ended_at_utc"], "source execution ended_at_utc")
    if ended <= started:
        raise ScenarioEvidenceError("source execution chronology is invalid")
    image = _byte_evidence(payload["runner_image"], media_type="application/octet-stream", label="source runner image", expected_sha256=engine["container_sha256"])
    binary = _byte_evidence(payload["runner_binary"], media_type="application/octet-stream", label="source runner binary", expected_sha256=engine["engine_sha256"])
    if not image or not binary:
        raise ScenarioEvidenceError("source runner image and binary must be non-empty")
    if _byte_evidence(payload["input_state"], media_type=G03_STATE_MEDIA_TYPE, label="source execution input state") != state_raw:
        raise ScenarioEvidenceError("source execution input bytes are not the exact planned state bytes")
    if _byte_evidence(payload["raw_trace"], media_type=G03_TRACE_MEDIA_TYPE, label="source execution raw trace") != trace_raw:
        raise ScenarioEvidenceError("hand-authored trace claim is not backed by the signed execution receipt")
    pre_raw = _byte_evidence(payload["pre_run_inventory"], media_type=G03_INVENTORY_MEDIA_TYPE, label="source pre-run inventory")
    pre = _fields(_canonical_object(pre_raw, "source pre-run inventory"), _G03_INVENTORY_PRE_FIELDS, "source pre-run inventory")
    if dict(pre) != {"schema": "evaluation_v5_1_g03_pre_run_inventory_v1", "cell_id": cell["cell_id"], "state_blob_sha256": refs["state_blob_sha256"], "argv": expected_bindings["argv"], "env": G03_RUNNER_ENV}:
        raise ScenarioEvidenceError("source pre-run inventory is not the frozen input inventory")
    post_raw = _byte_evidence(payload["post_run_inventory"], media_type=G03_INVENTORY_MEDIA_TYPE, label="source post-run inventory")
    post = _fields(_canonical_object(post_raw, "source post-run inventory"), _G03_INVENTORY_POST_FIELDS, "source post-run inventory")
    expected_post = {
        "schema": "evaluation_v5_1_g03_post_run_inventory_v1", "cell_id": cell["cell_id"],
        "pre_run_inventory_sha256": hashlib.sha256(pre_raw).hexdigest(), "trace_blob_sha256": refs["trace_blob_sha256"],
        "working_tree_clean": True, "created_paths": [], "modified_paths": [], "deleted_paths": [],
    }
    if dict(post) != expected_post:
        raise ScenarioEvidenceError("source post-run inventory is not a clean exact output inventory")

    attestation, attestation_payload_raw, attestation_envelope_raw = _verify_signed_envelope(
        refs["trace_attestation_envelope"], media_type=G03_TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
        schema=G03_TRACE_ATTESTATION_ENVELOPE_SCHEMA, key=attestor_key,
        domain=G03_TRACE_ATTESTATION_DOMAIN, label=f"{cell['cell_id']} trace attestation envelope",
    )
    attested = _fields(attestation, _G03_ATTESTATION_FIELDS, "trace attestation payload")
    expected_attestation = {
        "schema": G03_TRACE_ATTESTATION_SCHEMA, "protocol_id": PROTOCOL_ID, "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"],
        "execution_envelope_sha256": hashlib.sha256(execution_envelope_raw).hexdigest(), "execution_envelope_decoded_length": len(execution_envelope_raw),
        "execution_payload_sha256": hashlib.sha256(execution_payload_raw).hexdigest(), "execution_payload_decoded_length": len(execution_payload_raw),
        "raw_trace_sha256": refs["trace_blob_sha256"], "raw_trace_decoded_length": len(trace_raw), "raw_trace_media_type": G03_TRACE_MEDIA_TYPE,
        "independent_trace_root_sha256": trace_root, "trace_attestor_key_id": attestor_key["key_id"],
        "trace_attestor_principal_id": attestor_key["principal_id"], "trace_attestor_custodian_id": attestor_key["custodian_id"],
        "attested_at_utc": attested["attested_at_utc"],
    }
    if dict(attested) != expected_attestation:
        raise ScenarioEvidenceError("trace attestation is not bound to the exact execution envelope and raw trace")
    _, attested_at = _utc(attested["attested_at_utc"], "trace attested_at_utc")
    if attested_at < ended:
        raise ScenarioEvidenceError("trace attestation precedes source execution end")
    if started_text == ended_text or not events:
        raise ScenarioEvidenceError("source execution did not produce a natural trace")


def _measure(events: list[tuple[str, Mapping[str, Any]]]) -> tuple[dict[str, str], dict[str, dict[str, int]]]:
    own_turn = 0
    a2 = False
    prizes = 0
    attachments: list[tuple[str, int, bool]] = []
    recoveries: dict[str, list[dict[str, object]]] = {"K1": [], "S1": []}
    safety = True
    declared: set[tuple[int, str]] = set()
    for kind, payload in events:
        if kind == "TURN_START" and payload["owner"] == "self": own_turn = payload["own_turn"]
        if kind in {"ILLEGAL_ACTION", "POLICY_EXCEPTION", "TIMEOUT"} and own_turn <= 4: safety = False
        if kind == "MANUAL_ENERGY_ATTACHED" and own_turn <= 3:
            if payload["pokemon_kind"] == "dunsparce_engine": safety = False
            attachments.append((payload["pokemon_id"], own_turn, False))
        if kind == "RUN_AWAY_DRAW_ATTEMPT" and payload["sole_pokemon_in_play"]: safety = False
        if kind == "GAME_END" and payload["terminal_category"] != "completed" and own_turn <= 4: safety = False
        if kind == "PRIZE_TAKEN" and payload["owner"] == "self" and own_turn <= 4: prizes += payload["count"]
        if kind == "POKEMON_KO" and payload["owner"] == "self" and payload["was_active"] and own_turn < 4:
            recoveries["K1"].append({"target": own_turn + 1, "success": False})
        if kind == "FORCED_SWITCH" and payload["owner"] == "self" and own_turn < 4:
            recoveries["S1"].append({"target": own_turn + 1, "success": False})
        if kind == "ATTACK_DECLARED" and payload["owner"] == "self":
            declared.add((own_turn, payload["attacker_id"]))
        if kind == "DAMAGE_APPLIED" and payload["source_owner"] == "self" and payload["amount"] > 0 and (own_turn, payload["attacker_id"]) in declared:
            if own_turn <= 2: a2 = True
            for index, (pokemon_id, attached_turn, success) in enumerate(attachments):
                if not success and payload["attacker_id"] == pokemon_id and attached_turn < own_turn <= attached_turn + 2:
                    attachments[index] = (pokemon_id, attached_turn, True)
            for rows in recoveries.values():
                for row in rows:
                    if row["target"] == own_turn: row["success"] = True
    support = {
        "A2": {"n": 1, "s": int(a2)},
        "P4": {"n": 1, "s": int(prizes > 0)},
        "E2": {"n": len(attachments), "s": sum(success for _, _, success in attachments)},
        "K1": {"n": len(recoveries["K1"]), "s": sum(bool(row["success"]) for row in recoveries["K1"])},
        "S1": {"n": len(recoveries["S1"]), "s": sum(bool(row["success"]) for row in recoveries["S1"])},
    }
    values = {
        "A2": _q12(Decimal(int(a2))),
        "P4": _q12(Decimal(min(prizes, 6)) / Decimal(6)),
        "R4": _q12(Decimal(int(safety))),
    }
    for name in EFFICACY_FEATURES:
        row = support[name]
        values[name] = _q12((Decimal(row["s"]) + Decimal("0.5")) / (Decimal(row["n"]) + Decimal(1)))
    return values, support


def _era(timestamp: object, calendar: list[Mapping[str, str]]) -> str:
    text, instant = _utc(timestamp, "result.created_at_utc")
    for item in calendar:
        _, start = _utc(item["starts_at_utc"], "era start")
        _, end = _utc(item["ends_at_utc"], "era end")
        if start <= instant < end: return item["era"]
    raise ScenarioEvidenceError(f"game {text} is outside the era calendar")


def _mean(rows: list[tuple[str, int, int, str]]) -> str:
    grouped: dict[str, dict[int, dict[int, list[Decimal]]]] = {}
    for family, seat, seed, value in rows:
        grouped.setdefault(family, {}).setdefault(seat, {}).setdefault(seed, []).append(Decimal(value))
    family_means: list[Decimal] = []
    for family in sorted(grouped):
        seats = grouped[family]
        if set(seats) != {0, 1}: raise ScenarioEvidenceError("source cells are not seat-balanced")
        family_means.append(sum((sum((sum(values) / len(values) for values in seats[seat].values()), Decimal(0)) / len(seats[seat]) for seat in (0, 1)), Decimal(0)) / Decimal(2))
    if not family_means: raise ScenarioEvidenceError("no source feature cells")
    return _q12(sum(family_means, Decimal(0)) / len(family_means))


def derive_source_trace_receipt(value: object) -> dict[str, Any]:
    """Derive one DEV-row feature record from its embedded source trace only.

    This has no signature or authority behavior.  G05 authenticates the
    canonical envelope before calling it, then compares every row scalar to
    this result.  There is intentionally no input feature or support field.
    """
    raw = _fields(value, _SOURCE_TRACE_RECEIPT_FIELDS, "source trace receipt")
    if raw["schema"] != SOURCE_TRACE_RECEIPT_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise ScenarioEvidenceError("source trace receipt schema or protocol is invalid")
    scenario_sha256 = _sha(raw["scenario_sha256"], "source trace receipt scenario sha256")
    game_id = _text(raw["game_id"], "source trace receipt game id")
    archive_id = _text(raw["archive_id"], "source trace receipt archive id")
    lineage_id = _text(raw["lineage_id"], "source trace receipt lineage id")
    plan = validate_scenario_plan(raw["scenario_plan"])
    if plan["evidence_partition"] != "DEV" or len(plan["cells"]) != 1:
        raise ScenarioEvidenceError("source trace receipt requires one DEV source episode")
    plan_hash = canonical_sha256(plan)
    cell = plan["cells"][0]
    if raw["cell_id"] != cell["cell_id"]:
        raise ScenarioEvidenceError("source trace receipt cell is not the scheduled source cell")
    state = _fields(raw["state"], frozenset({
        "schema", "scenario_plan_sha256", "cell_id", "candidate_archive_sha256", "deck_sha256", "policy_sha256",
        "engine_sha256", "container_sha256", "opponent_package_sha256", "state_constructor_sha256", "seat", "deterministic_seed", "template",
    }), "source trace state")
    if dict(state) != _expected_state(plan, plan_hash, cell):
        raise ScenarioEvidenceError("source trace receipt state differs from its natural plan")
    state_hash = canonical_sha256(state)
    trace = _fields(raw["trace"], frozenset({"schema", "scenario_plan_sha256", "cell_id", "state_blob_sha256", "template", "events"}), "source trace")
    values, support = _measure(_events(trace, cell, state_hash, plan_hash))
    trace_hash = canonical_sha256(trace)
    result = _fields(raw["result"], frozenset({"schema", "scenario_plan_sha256", "cell_id", "trace_blob_sha256", "status", "created_at_utc"}), "source trace result")
    if result["schema"] != "evaluation_v5_1_natural_game_result_v3" or result["scenario_plan_sha256"] != plan_hash or result["cell_id"] != cell["cell_id"] or result["trace_blob_sha256"] != trace_hash or result["status"] not in {"OK", "FAIL"}:
        raise ScenarioEvidenceError("source trace result does not bind its trace")
    terminal = trace["events"][-1]["payload"]["terminal_category"]
    if (result["status"] == "OK") != (terminal == "completed"):
        raise ScenarioEvidenceError("source trace result status and terminal category disagree")
    _utc(result["created_at_utc"], "source trace result created_at_utc")
    result_hash = canonical_sha256(result)
    safety = _fields(raw["safety"], frozenset({"schema", "scenario_plan_sha256", "cell_id", "result_blob_sha256", "status"}), "source trace safety")
    if safety["schema"] != "evaluation_v5_1_natural_game_safety_v3" or safety["scenario_plan_sha256"] != plan_hash or safety["cell_id"] != cell["cell_id"] or safety["result_blob_sha256"] != result_hash or safety["status"] not in {"SAFE", "UNSAFE"}:
        raise ScenarioEvidenceError("source trace safety does not bind its result")
    if (safety["status"] == "SAFE") != (values["R4"] == "1.000000000000"):
        raise ScenarioEvidenceError("source trace safety status disagrees with derived R4")
    return {
        "scenario_sha256": scenario_sha256, "game_id": game_id, "archive_id": archive_id, "lineage_id": lineage_id,
        "scenario_plan_sha256": plan_hash, "source_engine_sha256": plan["engine_bindings"]["pinned_source"]["engine_sha256"],
        "source_container_sha256": plan["engine_bindings"]["pinned_source"]["container_sha256"],
        "seat": cell["seat"], "server_start_utc": result["created_at_utc"], "features": values, "support": support,
        "trace_root_sha256": trace["events"][-1]["event_sha256"],
    }


def _closed(decision: str, reason: str) -> dict[str, Any]:
    content = {"schema": SCENARIO_EVIDENCE_SCHEMA, "protocol_id": PROTOCOL_ID, "authority": False,
               "candidate_development_authorized": False, "sealed_holdout_access": False,
               "release_authorized": False, "submission_authorized": False, "decision": decision, "reason": reason}
    return {**content, "result_sha256": canonical_sha256(content)}


def verify_scenario_evidence(
    *,
    scenario_plan: object,
    execution_receipt: object,
    blobs: Mapping[str, bytes],
    g02_dependency_bundle: object,
    source_executor_key: object,
    trace_attestor_key: object,
    pinned_source_executor_public_key: bytes,
    pinned_trace_attestor_public_key: bytes,
) -> dict[str, Any]:
    """Verify exact G03 mechanics provenance and derive fixed research features.

    This verifier has no external identity oracle.  Pinned public keys establish
    only that supplied bytes were signed by those keys; they do not establish
    who operated the host, whether it was Kaggle, or any hosted RNG identity.
    Its result is permanently non-authoritative for candidates, holdouts, and
    submission.
    """
    try:
        g02_bundle_sha256 = _validate_g02_dependency_bundle(g02_dependency_bundle)
        executor_key = _custody_key(source_executor_key, role="source_executor", pinned_public_key=pinned_source_executor_public_key)
        attestor_key = _custody_key(trace_attestor_key, role="trace_attestor", pinned_public_key=pinned_trace_attestor_public_key)
        for field in ("key_id", "principal_id", "custodian_id", "public_key"):
            if executor_key[field] == attestor_key[field]:
                raise ScenarioEvidenceError(f"source executor and trace attestor must have distinct {field}")
        plan = validate_scenario_plan(scenario_plan)
        plan_hash = canonical_sha256(plan)
        receipt = _validate_receipt(execution_receipt, plan, plan_hash, g02_bundle_sha256)
        records: dict[str, tuple[dict[str, str], dict[str, dict[str, int]], str]] = {}
        for cell in plan["cells"]:
            refs = receipt[cell["cell_id"]]
            _validate_cell_provenance(refs=refs, blobs=blobs, plan=plan, plan_hash=plan_hash, cell=cell, executor_key=executor_key, attestor_key=attestor_key)
            state = _blob(blobs, refs["state_blob_sha256"], "state")
            if dict(state) != _expected_state(plan, plan_hash, cell): raise ScenarioEvidenceError("state differs from planned cell")
            trace = _blob(blobs, refs["trace_blob_sha256"], "trace")
            values, support = _measure(_events(trace, cell, refs["state_blob_sha256"], plan_hash))
            result = _fields(_blob(blobs, refs["result_blob_sha256"], "result"), frozenset({"schema", "scenario_plan_sha256", "cell_id", "trace_blob_sha256", "status", "created_at_utc"}), "result")
            if result["schema"] != "evaluation_v5_1_natural_game_result_v3" or result["scenario_plan_sha256"] != plan_hash or result["cell_id"] != cell["cell_id"] or result["trace_blob_sha256"] != refs["trace_blob_sha256"] or result["status"] not in {"OK", "FAIL"}: raise ScenarioEvidenceError("result does not bind trace")
            execution_payload, _execution_payload_raw, _execution_envelope_raw = _verify_signed_envelope(
                refs["execution_envelope"], media_type=G03_EXECUTION_ENVELOPE_MEDIA_TYPE,
                schema=G03_EXECUTION_ENVELOPE_SCHEMA, key=executor_key,
                domain=G03_EXECUTION_DOMAIN, label=f"{cell['cell_id']} source execution envelope",
            )
            if result["created_at_utc"] != execution_payload["ended_at_utc"]:
                raise ScenarioEvidenceError("result timestamp is not bound to the signed source execution end")
            terminal = trace["events"][-1]["payload"]["terminal_category"]
            if (result["status"] == "OK") != (terminal == "completed"): raise ScenarioEvidenceError("result status and terminal category disagree")
            safety = _fields(_blob(blobs, refs["safety_blob_sha256"], "safety"), frozenset({"schema", "scenario_plan_sha256", "cell_id", "result_blob_sha256", "status"}), "safety")
            if safety["schema"] != "evaluation_v5_1_natural_game_safety_v3" or safety["scenario_plan_sha256"] != plan_hash or safety["cell_id"] != cell["cell_id"] or safety["result_blob_sha256"] != refs["result_blob_sha256"] or safety["status"] not in {"SAFE", "UNSAFE"}: raise ScenarioEvidenceError("safety does not bind result")
            if (safety["status"] == "SAFE") != (values["R4"] == "1.000000000000"): raise ScenarioEvidenceError("safety status and derived R4 disagree")
            records[cell["cell_id"]] = (values, support, _era(result["created_at_utc"], plan["era_calendar"]))
        if any(records[cell["cell_id"]][0]["R4"] != "1.000000000000" for cell in plan["cells"]):
            return _closed("OPERATIONAL_SAFETY_VETO", "R4 natural-game safety rule failed")
        aggregates = {name: [] for name in FEATURE_REGISTRY}
        support_totals = {name: {"n": 0, "s": 0, "lineages": set()} for name in SUPPORT_FEATURES}
        eras: list[dict[str, str]] = []
        for cell in plan["cells"]:
            values, support, era = records[cell["cell_id"]]
            eras.append({"cell_id": cell["cell_id"], "era": era})
            opponent = plan["opponent_packages"][cell["opponent_package_id"]]
            key = (opponent["family_id"], cell["seat"], cell["seed_derivation"]["seed_index"])
            for name in FEATURE_REGISTRY: aggregates[name].append((*key, values[name]))
            for name in SUPPORT_FEATURES:
                support_totals[name]["n"] += support[name]["n"]; support_totals[name]["s"] += support[name]["s"]
                if support[name]["n"] > 0: support_totals[name]["lineages"].add(opponent["lineage_id"])
        features = {name: _mean(aggregates[name]) for name in FEATURE_REGISTRY}
        support_audit = {name: {"numerator": row["s"], "denominator": row["n"], "lineages": len(row["lineages"]), "jeffreys_rate": _q12((Decimal(row["s"]) + Decimal("0.5")) / (Decimal(row["n"]) + Decimal(1)))} for name, row in support_totals.items()}
        eligible = {name: (row["denominator"] > 0 if name in {"A2", "P4"} else row["denominator"] >= 500 and row["lineages"] >= 10) for name, row in support_audit.items()}
        if plan["evidence_partition"] == "DEV" and sum(eligible.values()) < 3:
            return _closed("DEV_SUPPORT_INSUFFICIENT", "fewer than three efficacy features meet DEV support")
        content = {"schema": SCENARIO_EVIDENCE_SCHEMA, "protocol_id": PROTOCOL_ID, "authority": False,
                   "candidate_development_authorized": False, "sealed_holdout_access": False,
                   "release_authorized": False, "submission_authorized": False,
                   "decision": "SCENARIO_EVIDENCE_VERIFIED_RESEARCH_ONLY", "reason": None, "scenario_plan_sha256": plan_hash,
                   "execution_receipt_sha256": canonical_sha256(execution_receipt), "g02_dependency_bundle_sha256": g02_bundle_sha256,
                   "feature_registry": list(FEATURE_REGISTRY), "model_feature_names": [name for name in MODEL_FEATURES if name != "R4"],
                   "features": features, "support_audit": support_audit, "efficacy_eligible": eligible, "safety_only_features": ["R4"], "game_eras": eras}
        return {**content, "result_sha256": canonical_sha256(content)}
    except (CanonicalJSONError, ScenarioEvidenceError, KeyError, TypeError, ValueError) as exc:
        return _closed("SCENARIO_EVIDENCE_INVALID", str(exc))


audit_scenario_evidence = verify_scenario_evidence

__all__ = ["AGGREGATION_FORMULA", "EFFICACY_FEATURES", "EVENT_TYPES", "EXECUTION_RECEIPT_SCHEMA", "FAILURE_RULE", "FEATURE_REGISTRY", "G03_EXECUTION_DOMAIN", "G03_EXECUTION_ENVELOPE_MEDIA_TYPE", "G03_EXECUTION_ENVELOPE_SCHEMA", "G03_EXECUTION_PAYLOAD_MEDIA_TYPE", "G03_EXECUTION_PAYLOAD_SCHEMA", "G03_G02_AUTHORITY_MEDIA_TYPE", "G03_G02_BUNDLE_MEDIA_TYPE", "G03_G02_DEPENDENCY_BUNDLE_SCHEMA", "G03_INVENTORY_MEDIA_TYPE", "G03_RUNNER_ENV", "G03_RUNNER_PATH", "G03_STATE_MEDIA_TYPE", "G03_TRACE_ATTESTATION_DOMAIN", "G03_TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE", "G03_TRACE_ATTESTATION_ENVELOPE_SCHEMA", "G03_TRACE_ATTESTATION_SCHEMA", "G03_TRACE_MEDIA_TYPE", "MODEL_FEATURES", "NATURAL_TEMPLATE", "PROTOCOL_ID", "SCENARIO_EVIDENCE_SCHEMA", "SCENARIO_PLAN_SCHEMA", "SEED_DERIVATION_SCHEME", "SOURCE_TRACE_RECEIPT_SCHEMA", "SUPPORT_FEATURES", "ScenarioEvidenceError", "TERMINAL_CATEGORIES", "audit_scenario_evidence", "canonical_execution_receipt_bytes", "derive_cell_seed", "derive_source_trace_receipt", "scenario_plan_sha256", "validate_scenario_plan", "verify_scenario_evidence"]
