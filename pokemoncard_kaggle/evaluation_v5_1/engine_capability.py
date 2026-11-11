"""Exact, fail-closed G02 engine-event capability evidence.

G02 establishes only that the two frozen engines expose one common event
language.  It is deliberately not a claim of hosted fidelity and it has no
candidate, holdout, release, or submission authority.  An engine-specific
executor signs the exact execution payload, then a separately pinned trace
attestor countersigns the canonical executor-envelope bytes and its own parser
result.  This module reruns that parser before a case can contribute to the
local research-only result.  Final authority belongs exclusively to the shared
exact-gate v2 service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from .exact_gate_v2 import (
    FAIL_DECISION,
    PASS_DECISION,
    ExactGateV2Error,
    decode_byte_evidence,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
    verify_exact_gate_v2,
)


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
GATE_ID = "G02_ENGINE_EVENT_CAPABILITY"
G02_EVIDENCE_SCHEMA = "evaluation_v5_1_g02_engine_event_capability_evidence_v3"
G02_EVENT_SCHEMA_DOCUMENT = "evaluation_v5_1_g02_event_schema_document_v1"
G02_TRACE_SCHEMA = "evaluation_v5_1_g02_engine_event_trace_v1"
G02_CORPUS_SCHEMA = "evaluation_v5_1_g02_engine_event_corpus_v3"
G02_EXECUTION_PAYLOAD_SCHEMA = "evaluation_v5_1_g02_execution_payload_v2"
G02_EXECUTION_RECEIPT_SCHEMA = "evaluation_v5_1_g02_execution_receipt_v2"
G02_TRACE_CASE_SCHEMA = G02_EXECUTION_RECEIPT_SCHEMA
G02_RECOMPUTED_OUTPUT_SCHEMA = "evaluation_v5_1_g02_recomputed_outputs_v3"
G02_ATTESTOR_PARSER_RESULT_SCHEMA = "evaluation_v5_1_g02_attestor_parser_result_v1"
G02_POSITIVE_INPUT_SCHEMA = "evaluation_v5_1_g02_engine_emission_input_v1"
G02_RUN_RESULT_SCHEMA = "evaluation_v5_1_g02_runner_result_v1"
G02_INVENTORY_SCHEMA = "evaluation_v5_1_g02_execution_inventory_v1"
G02_POST_RUN_INVENTORY_SCHEMA = "evaluation_v5_1_g02_post_run_inventory_v1"
G02_EXECUTOR_ENVELOPE_MEDIA_TYPE = (
    "application/vnd.ptcg.g02-executor-envelope+json"
)

RUNNER_BINARY_PATH = "/opt/evaluation-v5.1/bin/g02-engine-event-runner"
RUNNER_ENVIRONMENT = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}

# This ordering is part of the frozen wire contract.  Do not sort it.
EVENT_VOCABULARY = (
    "GAME_START",
    "TURN_START",
    "ACTION_REQUESTED",
    "ACTION_CHOSEN",
    "MANUAL_ENERGY_ATTACHED",
    "ATTACK_DECLARED",
    "DAMAGE_APPLIED",
    "PRIZE_TAKEN",
    "POKEMON_KO",
    "ACTIVE_PROMOTED",
    "FORCED_SWITCH",
    "RUN_AWAY_DRAW_ATTEMPT",
    "ILLEGAL_ACTION",
    "POLICY_EXCEPTION",
    "TIMEOUT",
    "GAME_END",
)

# An actor is the seat whose policy/action caused the event.  Events without
# actor fields are lifecycle/terminal facts, so an unscoped actor cannot be
# silently invented by a parser.
EVENT_FIELD_SETS: dict[str, tuple[str, ...]] = {
    "GAME_START": ("event_id", "event_type"),
    "TURN_START": ("actor_seat", "event_id", "event_type", "is_canary"),
    "ACTION_REQUESTED": (
        "actor_seat", "event_id", "event_type", "is_canary", "request_id"
    ),
    "ACTION_CHOSEN": (
        "actor_seat", "event_id", "event_type", "is_canary", "request_id"
    ),
    "MANUAL_ENERGY_ATTACHED": (
        "actor_seat", "event_id", "event_type", "is_canary", "pokemon_id", "request_id"
    ),
    "ATTACK_DECLARED": (
        "actor_seat", "attack_id", "event_id", "event_type", "is_canary", "pokemon_id", "request_id"
    ),
    "DAMAGE_APPLIED": (
        "actor_seat", "cause_attack_id", "damage_amount", "event_id", "event_type", "is_canary", "pokemon_id"
    ),
    "PRIZE_TAKEN": (
        "actor_seat", "cause_attack_id", "event_id", "event_type", "is_canary", "pokemon_id"
    ),
    "POKEMON_KO": (
        "actor_seat", "cause_attack_id", "event_id", "event_type", "is_canary", "pokemon_id"
    ),
    "ACTIVE_PROMOTED": (
        "actor_seat", "event_id", "event_type", "is_canary", "pokemon_id"
    ),
    "FORCED_SWITCH": (
        "actor_seat", "cause_attack_id", "event_id", "event_type", "is_canary", "pokemon_id"
    ),
    "RUN_AWAY_DRAW_ATTEMPT": (
        "actor_seat", "event_id", "event_type", "is_canary", "pokemon_id", "request_id"
    ),
    "ILLEGAL_ACTION": (
        "actor_seat", "event_id", "event_type", "is_canary", "request_id"
    ),
    "POLICY_EXCEPTION": (
        "actor_seat", "event_id", "event_type", "is_canary", "request_id"
    ),
    "TIMEOUT": (
        "actor_seat", "event_id", "event_type", "is_canary", "request_id"
    ),
    "GAME_END": ("event_id", "event_type", "outcome", "terminal_identity"),
}

# A terminal identity is not an arbitrary explanatory string.  Its outcome is
# frozen too, which prevents a trace from relabelling an exception as a win.
TERMINAL_OUTCOMES = {
    "CANARY_WIN_BY_PRIZES": "CANARY_WIN",
    "CANARY_WIN_BY_KO": "CANARY_WIN",
    "OPPONENT_WIN_BY_PRIZES": "OPPONENT_WIN",
    "OPPONENT_WIN_BY_KO": "OPPONENT_WIN",
    "DRAW": "DRAW",
    "TIMEOUT": "TERMINAL_FAILURE",
    "POLICY_EXCEPTION": "TERMINAL_FAILURE",
    "ILLEGAL_ACTION": "TERMINAL_FAILURE",
}
TERMINAL_IDENTITIES = tuple(TERMINAL_OUTCOMES)
NEGATIVE_CASE_CLASSES = (
    "UNKNOWN_EVENT",
    "DUPLICATE_EVENT_ID",
    "NONMONOTONIC_EVENT_ID",
    "MALFORMED_ACTOR_SCOPE",
    "CONFLICTING_TERMINAL",
    "DUPLICATE_TERMINAL",
    "REQUEST_CAUSAL_MISMATCH",
    "ATTACK_CAUSAL_MISMATCH",
    "BAD_DAMAGE",
    "MISSING_TERMINAL",
)
NEGATIVE_CLASS_FAILURE_CODES = {
    "UNKNOWN_EVENT": "FAIL_G02_UNKNOWN_EVENT",
    "DUPLICATE_EVENT_ID": "FAIL_G02_DUPLICATE_EVENT_ID",
    "NONMONOTONIC_EVENT_ID": "FAIL_G02_NONMONOTONIC_EVENT_ID",
    "MALFORMED_ACTOR_SCOPE": "FAIL_G02_MALFORMED_ACTOR_SCOPE",
    "CONFLICTING_TERMINAL": "FAIL_G02_CONFLICTING_TERMINAL",
    "DUPLICATE_TERMINAL": "FAIL_G02_DUPLICATE_TERMINAL",
    "REQUEST_CAUSAL_MISMATCH": "FAIL_G02_REQUEST_CAUSAL_MISMATCH",
    "ATTACK_CAUSAL_MISMATCH": "FAIL_G02_ATTACK_CAUSAL_MISMATCH",
    "BAD_DAMAGE": "FAIL_G02_BAD_DAMAGE_AMOUNT",
    "MISSING_TERMINAL": "FAIL_G02_MISSING_TERMINAL",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_ARTIFACT_FIELDS = frozenset(
    {"engine_sha256", "package_sha256", "parser_sha256", "container_sha256"}
)
_ARTIFACT_BYTE_FIELDS = frozenset({"engine", "package", "parser", "container"})
_RUNNER_ARTIFACT_FIELDS = frozenset(
    {"runner_image_sha256", "runner_binary_sha256"}
)
_DEPENDENCY_FIELDS = frozenset({"gate_id", "result_root"})
_KEY_FIELDS = frozenset(
    {
        "role",
        "key_id",
        "principal_id",
        "custodian_id",
        "algorithm",
        "public_key_base64",
        "valid_from_utc",
        "valid_until_utc",
        "revoked",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "dependency_roots",
        "campaign_registry_hash",
        "evidence_manifest_root",
        "verifier_module_digest",
        "g00_frozen_at_utc",
        "g01_frozen_at_utc",
        "g02_frozen_at_utc",
        "event_schema",
        "positive_corpus",
        "negative_corpus",
        "source_artifacts",
        "wrapper_artifacts",
        "runner_artifacts",
        "source_executor_key",
        "wrapper_executor_key",
        "trace_attestor_key",
        "execution_receipt_envelopes",
    }
)
_EXECUTION_PAYLOAD_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "g00_result_root",
        "g01_result_root",
        "g00_frozen_at_utc",
        "g01_frozen_at_utc",
        "g02_frozen_at_utc",
        "event_schema_sha256",
        "case_id",
        "corpus_kind",
        "runner_mode",
        "negative_class",
        "engine",
        "engine_sha256",
        "package_sha256",
        "parser_sha256",
        "container_sha256",
        "artifact_bytes",
        "runner_image_sha256",
        "runner_image_bytes",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "argv",
        "env",
        "canary_seat",
        "input_fixture",
        "working_tree_input_inventory_root",
        "post_run_inventory_root",
        "post_run_inventory",
        "execution_nonce",
        "platform_os",
        "platform_arch",
        "isolated_execution",
        "working_tree_clean",
        "retry_count",
        "intervention_count",
        "started_at_utc",
        "ended_at_utc",
        "exit_code",
        "status",
        "stdout",
        "stderr",
        "emitted_trace",
        "executor_role",
        "executor_key_id",
        "executor_principal_id",
        "executor_custodian_id",
        "executor_signed_at_utc",
    }
)
_EXECUTION_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "case_id",
        "engine",
        "execution_nonce",
        "executor_role",
        "executor_key_id",
        "executor_principal_id",
        "executor_custodian_id",
        "executor_envelope",
        "executor_envelope_sha256",
        "execution_payload_sha256",
        "emitted_trace_sha256",
        "parser_result",
        "trace_attestor_key_id",
        "trace_attestor_principal_id",
        "trace_attestor_custodian_id",
        "attested_at_utc",
    }
)
_PARSER_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "disposition",
        "failure_code",
        "event_types",
        "terminal_identity",
        "outcome",
    }
)
class EngineCapabilityError(ValueError):
    """A G02 event artifact is malformed, unbound, or semantically invalid."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise EngineCapabilityError(code)


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(f"FAIL_G02_{label.upper()}_FIELDS")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        _fail(f"FAIL_G02_{label.upper()}_SHA256")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        _fail(f"FAIL_G02_{label.upper()}_IDENTIFIER")
    return value


def _seat(value: object, label: str) -> int:
    if type(value) is not int or value not in {0, 1}:
        _fail(f"FAIL_G02_{label.upper()}_SEAT")
    return value


def _pokemon_id(value: object) -> int:
    if type(value) is not int or value < 0:
        _fail("FAIL_G02_POKEMON_ID")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        _fail(f"FAIL_G02_{label.upper()}_TIMESTAMP")
    try:
        instant = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        _fail(f"FAIL_G02_{label.upper()}_TIMESTAMP")
    if instant.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        _fail(f"FAIL_G02_{label.upper()}_TIMESTAMP")
    return instant


def _parse_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail("FAIL_G02_DUPLICATE_JSON_KEY")
        value[key] = item
    return value


def _parse_canonical_json(raw: bytes, label: str) -> Any:
    if type(raw) is not bytes:
        _fail(f"FAIL_G02_{label.upper()}_BYTES")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_parse_pairs,
            parse_constant=lambda _item: _fail("FAIL_G02_NONFINITE_JSON"),
        )
    except EngineCapabilityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        _fail(f"FAIL_G02_{label.upper()}_JSON")
    try:
        if canonical_json_bytes(value) != raw:
            _fail("FAIL_G02_NONCANONICAL_JSON_BYTES")
    except CanonicalJSONError:
        _fail("FAIL_G02_NONCANONICAL_JSON_BYTES")
    return value


def _decode_json_evidence(value: object, label: str) -> tuple[Any, str]:
    try:
        raw = decode_byte_evidence(value, expected_media_type="application/json")
    except ExactGateV2Error as exc:
        _fail(f"FAIL_G02_{label.upper()}_BYTE_EVIDENCE_{_error_suffix(exc)}")
    parsed = _parse_canonical_json(raw, label)
    if type(value) is not dict:
        _fail(f"FAIL_G02_{label.upper()}_BYTE_EVIDENCE")
    return parsed, _sha256(value["sha256"], label)


def _error_suffix(exc: Exception) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(exc).upper()).strip("_")[:80] or "INVALID"


def _validate_envelope_crypto_encoding(
    envelope: object,
    *,
    public_key: bytes,
    label: str,
) -> None:
    try:
        validate_ed25519_public_key(public_key)
    except ExactGateV2Error:
        _fail(f"FAIL_G02_{label.upper()}_PUBLIC_KEY_ENCODING")
    if type(envelope) is not dict:
        _fail(f"FAIL_G02_{label.upper()}_SIGNATURE_ENCODING")
    encoded = envelope.get("signature_ed25519_base64")
    if type(encoded) is not str:
        _fail(f"FAIL_G02_{label.upper()}_SIGNATURE_ENCODING")
    try:
        signature = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        _fail(f"FAIL_G02_{label.upper()}_SIGNATURE_ENCODING")
    if base64.b64encode(signature).decode("ascii") != encoded:
        _fail(f"FAIL_G02_{label.upper()}_SIGNATURE_ENCODING")
    try:
        validate_ed25519_signature_encoding(signature)
    except ExactGateV2Error:
        _fail(f"FAIL_G02_{label.upper()}_SIGNATURE_ENCODING")


def _reject_private_or_authority(value: object, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                _fail("FAIL_G02_NONSTRING_KEY")
            lowered = key.lower()
            if ("private" in lowered and "key" in lowered) or lowered in {
                "secret_key",
                "signing_seed",
                "private_seed",
            }:
                _fail("FAIL_G02_PRIVATE_KEY_MATERIAL")
            if (
                child is True
                and (
                    key in {
                        "authority",
                        "candidate_development_authorized",
                        "sealed_holdout_access_authorized",
                        "submission_authorized",
                        "release_authorized",
                    }
                    or "submission" in lowered
                    or "holdout" in lowered
                    or "candidate" in lowered
                    or "release" in lowered
                )
            ):
                _fail("FAIL_G02_FORBIDDEN_AUTHORITY_CLAIM")
            _reject_private_or_authority(child, path=f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _reject_private_or_authority(child, path=f"{path}[{index}]")


def derive_event_schema_document() -> dict[str, Any]:
    """Return the one JSON document permitted as raw event-schema evidence."""

    return {
        "schema_version": G02_EVENT_SCHEMA_DOCUMENT,
        "event_vocabulary": list(EVENT_VOCABULARY),
        "event_fields": {
            event_type: list(EVENT_FIELD_SETS[event_type])
            for event_type in EVENT_VOCABULARY
        },
        "terminal_outcomes": dict(TERMINAL_OUTCOMES),
    }


def _validate_event_schema(value: object) -> None:
    expected = derive_event_schema_document()
    fields = frozenset(expected)
    raw = _exact(value, fields, "event_schema")
    if raw != expected:
        _fail("FAIL_G02_EVENT_SCHEMA_NOT_EXACT")


def _validate_actor(event: Mapping[str, Any], canary_seat: int) -> int:
    seat = _seat(event["actor_seat"], "actor")
    if type(event["is_canary"]) is not bool or event["is_canary"] is not (seat == canary_seat):
        _fail("FAIL_G02_MALFORMED_ACTOR_SCOPE")
    return seat


def parse_engine_event_trace(raw: bytes, *, canary_seat: int) -> dict[str, Any]:
    """Strictly parse one canonical trace and recompute its terminal result.

    The return value contains only values independently derived from the raw
    trace.  It is intentionally not a game simulator; G02 verifies that the
    frozen primitive protocol is expressible and causally scoped.
    """

    canary_seat = _seat(canary_seat, "canary")
    trace = _parse_canonical_json(raw, "trace")
    trace = _exact(trace, frozenset({"schema_version", "events"}), "trace")
    if trace["schema_version"] != G02_TRACE_SCHEMA:
        _fail("FAIL_G02_TRACE_SCHEMA")
    events = trace["events"]
    if type(events) is not list or not events:
        _fail("FAIL_G02_TRACE_EVENTS")

    previous_event_id = -1
    seen_event_ids: set[int] = set()
    requests: dict[str, int] = {}
    chosen_requests: set[tuple[int, str]] = set()
    attacks: dict[str, int] = {}
    seen_terminal: dict[str, str] | None = None
    event_types: list[str] = []

    for index, raw_event in enumerate(events):
        if type(raw_event) is not dict:
            _fail("FAIL_G02_EVENT_FIELDS")
        event_type = raw_event.get("event_type")
        if type(event_type) is not str or event_type not in EVENT_FIELD_SETS:
            _fail("FAIL_G02_UNKNOWN_EVENT")
        event = _exact(raw_event, frozenset(EVENT_FIELD_SETS[event_type]), "event")
        event_id = event["event_id"]
        if type(event_id) is not int or event_id < 0:
            _fail("FAIL_G02_EVENT_ID")
        if event_id in seen_event_ids:
            _fail("FAIL_G02_DUPLICATE_EVENT_ID")
        if event_id <= previous_event_id:
            _fail("FAIL_G02_NONMONOTONIC_EVENT_ID")
        seen_event_ids.add(event_id)
        previous_event_id = event_id

        if index == 0 and event_type != "GAME_START":
            _fail("FAIL_G02_TRACE_MISSING_GAME_START")
        if index > 0 and event_type == "GAME_START":
            _fail("FAIL_G02_DUPLICATE_GAME_START")
        if seen_terminal is not None and event_type != "GAME_END":
            _fail("FAIL_G02_EVENT_AFTER_TERMINAL")

        if event_type in {"GAME_START", "GAME_END"}:
            pass
        else:
            actor = _validate_actor(event, canary_seat)
            if event_type in {
                "MANUAL_ENERGY_ATTACHED",
                "ATTACK_DECLARED",
                "DAMAGE_APPLIED",
                "PRIZE_TAKEN",
                "POKEMON_KO",
                "ACTIVE_PROMOTED",
                "FORCED_SWITCH",
                "RUN_AWAY_DRAW_ATTEMPT",
            }:
                _pokemon_id(event["pokemon_id"])

            if event_type == "ACTION_REQUESTED":
                request_id = _identifier(event["request_id"], "request")
                if request_id in requests:
                    _fail("FAIL_G02_REQUEST_CAUSAL_MISMATCH")
                requests[request_id] = actor
            elif event_type == "ACTION_CHOSEN":
                request_id = _identifier(event["request_id"], "request")
                if requests.get(request_id) != actor or (actor, request_id) in chosen_requests:
                    _fail("FAIL_G02_REQUEST_CAUSAL_MISMATCH")
                chosen_requests.add((actor, request_id))
            elif event_type in {
                "MANUAL_ENERGY_ATTACHED",
                "ATTACK_DECLARED",
                "RUN_AWAY_DRAW_ATTEMPT",
                "ILLEGAL_ACTION",
                "POLICY_EXCEPTION",
                "TIMEOUT",
            }:
                request_id = _identifier(event["request_id"], "request")
                if (actor, request_id) not in chosen_requests:
                    _fail("FAIL_G02_REQUEST_CAUSAL_MISMATCH")
                if event_type == "ATTACK_DECLARED":
                    attack_id = _identifier(event["attack_id"], "attack")
                    if attack_id in attacks:
                        _fail("FAIL_G02_ATTACK_CAUSAL_MISMATCH")
                    attacks[attack_id] = actor
            elif event_type in {
                "DAMAGE_APPLIED",
                "PRIZE_TAKEN",
                "POKEMON_KO",
                "FORCED_SWITCH",
            }:
                attack_id = _identifier(event["cause_attack_id"], "cause_attack")
                if attacks.get(attack_id) != actor:
                    _fail("FAIL_G02_ATTACK_CAUSAL_MISMATCH")
                if event_type == "DAMAGE_APPLIED":
                    damage = event["damage_amount"]
                    if type(damage) is not int or damage < 0:
                        _fail("FAIL_G02_BAD_DAMAGE_AMOUNT")

        if event_type == "GAME_END":
            terminal_identity = event["terminal_identity"]
            outcome = event["outcome"]
            if type(terminal_identity) is not str or terminal_identity not in TERMINAL_OUTCOMES:
                _fail("FAIL_G02_TERMINAL_IDENTITY")
            if outcome != TERMINAL_OUTCOMES[terminal_identity]:
                _fail("FAIL_G02_TERMINAL_OUTCOME_MISMATCH")
            terminal = {"terminal_identity": terminal_identity, "outcome": outcome}
            if seen_terminal is not None:
                if terminal == seen_terminal:
                    _fail("FAIL_G02_DUPLICATE_TERMINAL")
                _fail("FAIL_G02_CONFLICTING_TERMINAL")
            seen_terminal = terminal

        event_types.append(event_type)

    if seen_terminal is None:
        _fail("FAIL_G02_MISSING_TERMINAL")
    return {
        "event_types": event_types,
        "terminal_identity": seen_terminal["terminal_identity"],
        "outcome": seen_terminal["outcome"],
    }


def derive_execution_argv(
    *, case_id: str, engine: str, canary_seat: int, corpus_kind: str
) -> list[str]:
    """Return the only command line permitted for one G02 execution."""

    case_id = _identifier(case_id, "case")
    if engine not in {"source", "wrapper"}:
        _fail("FAIL_G02_CASE_ENGINE")
    canary_seat = _seat(canary_seat, "case_canary")
    if corpus_kind not in {"positive", "negative"}:
        _fail("FAIL_G02_TRACE_CORPUS_KIND")
    mode = "emit-engine-trace" if corpus_kind == "positive" else "parse-negative-fixture"
    return [
        RUNNER_BINARY_PATH,
        "--mode",
        mode,
        "--engine",
        engine,
        "--case-id",
        case_id,
        "--canary-seat",
        str(canary_seat),
        "--input",
        "/inputs/case.json",
        "--trace-output",
        "/outputs/trace.json",
    ]


def derive_positive_input_fixture_bytes(
    *, case_id: str, engine: str, canary_seat: int
) -> bytes:
    """Derive the frozen engine-runner input for a positive execution case."""

    if engine not in {"source", "wrapper"}:
        _fail("FAIL_G02_CASE_ENGINE")
    return canonical_json_bytes(
        {
            "schema_version": G02_POSITIVE_INPUT_SCHEMA,
            "case_id": _identifier(case_id, "case"),
            "engine": engine,
            "canary_seat": _seat(canary_seat, "case_canary"),
            "natural_start": True,
            "interventions": [],
        }
    )


def _fixture_actor(
    event_id: int, event_type: str, *, seat: int = 0, **fields: object
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "actor_seat": seat,
        "is_canary": seat == 0,
        **fields,
    }


def _negative_fixture_base() -> dict[str, object]:
    return {
        "schema_version": G02_TRACE_SCHEMA,
        "events": [
            {"event_id": 0, "event_type": "GAME_START"},
            _fixture_actor(1, "TURN_START"),
            _fixture_actor(2, "ACTION_REQUESTED", request_id="request-1"),
            _fixture_actor(3, "ACTION_CHOSEN", request_id="request-1"),
            _fixture_actor(
                4,
                "MANUAL_ENERGY_ATTACHED",
                request_id="request-1",
                pokemon_id=101,
            ),
            _fixture_actor(
                5,
                "ATTACK_DECLARED",
                request_id="request-1",
                attack_id="attack-1",
                pokemon_id=101,
            ),
            _fixture_actor(
                6,
                "DAMAGE_APPLIED",
                cause_attack_id="attack-1",
                pokemon_id=202,
                damage_amount=100,
            ),
            _fixture_actor(7, "PRIZE_TAKEN", cause_attack_id="attack-1", pokemon_id=202),
            _fixture_actor(8, "POKEMON_KO", cause_attack_id="attack-1", pokemon_id=202),
            _fixture_actor(9, "ACTIVE_PROMOTED", seat=1, pokemon_id=202),
            _fixture_actor(10, "FORCED_SWITCH", cause_attack_id="attack-1", pokemon_id=202),
            _fixture_actor(
                11,
                "RUN_AWAY_DRAW_ATTEMPT",
                request_id="request-1",
                pokemon_id=101,
            ),
            _fixture_actor(12, "ILLEGAL_ACTION", request_id="request-1"),
            _fixture_actor(13, "POLICY_EXCEPTION", request_id="request-1"),
            _fixture_actor(14, "TIMEOUT", request_id="request-1"),
            {
                "event_id": 15,
                "event_type": "GAME_END",
                "terminal_identity": "CANARY_WIN_BY_PRIZES",
                "outcome": "CANARY_WIN",
            },
        ],
    }


def derive_negative_fixture_bytes(negative_class: str) -> bytes:
    """Return one exact frozen malformed input for the parser runner."""

    if negative_class not in NEGATIVE_CLASS_FAILURE_CODES:
        _fail("FAIL_G02_NEGATIVE_CASE_CLASS")
    trace = deepcopy(_negative_fixture_base())
    events = trace["events"]
    if type(events) is not list:  # pragma: no cover - module-owned fixture invariant
        _fail("FAIL_G02_INTERNAL_FIXTURE")
    if negative_class == "UNKNOWN_EVENT":
        events[1]["event_type"] = "NOT_A_FROZEN_EVENT"
    elif negative_class == "DUPLICATE_EVENT_ID":
        events[2]["event_id"] = 1
    elif negative_class == "NONMONOTONIC_EVENT_ID":
        events[1]["event_id"] = 2
        events[2]["event_id"] = 1
    elif negative_class == "MALFORMED_ACTOR_SCOPE":
        events[1]["is_canary"] = False
    elif negative_class == "CONFLICTING_TERMINAL":
        events.append(
            {
                "event_id": 16,
                "event_type": "GAME_END",
                "terminal_identity": "DRAW",
                "outcome": "DRAW",
            }
        )
    elif negative_class == "DUPLICATE_TERMINAL":
        events.append(deepcopy(events[-1]))
        events[-1]["event_id"] = 16
    elif negative_class == "REQUEST_CAUSAL_MISMATCH":
        events[4]["request_id"] = "unknown-request"
    elif negative_class == "ATTACK_CAUSAL_MISMATCH":
        events[6]["cause_attack_id"] = "unknown-attack"
    elif negative_class == "BAD_DAMAGE":
        events[6]["damage_amount"] = -1
    elif negative_class == "MISSING_TERMINAL":
        events.pop()
    return canonical_json_bytes(trace)


def _validate_artifacts(value: object, label: str) -> dict[str, str]:
    raw = _exact(value, _ARTIFACT_FIELDS, label)
    return {
        field: _sha256(raw[field], f"{label}_{field}")
        for field in sorted(_ARTIFACT_FIELDS)
    }


def _validate_runner_artifacts(value: object) -> dict[str, str]:
    raw = _exact(value, _RUNNER_ARTIFACT_FIELDS, "runner_artifacts")
    return {
        field: _sha256(raw[field], field) for field in sorted(_RUNNER_ARTIFACT_FIELDS)
    }


def _decode_bytes(
    value: object,
    *,
    label: str,
    media_type: str,
    expected_sha256: str | None = None,
) -> bytes:
    try:
        return decode_byte_evidence(
            value,
            expected_media_type=media_type,
            expected_sha256=expected_sha256,
        )
    except ExactGateV2Error as exc:
        _fail(f"FAIL_G02_{label.upper()}_BYTE_EVIDENCE_{_error_suffix(exc)}")


def _dependencies(value: object) -> list[dict[str, str]]:
    if type(value) is not list or len(value) != 2:
        _fail("FAIL_G02_DEPENDENCY_ROOTS")
    expected_gates = ("G00_TRUST_ROOTS", "G01_CONSTITUTION_AND_CODE_FREEZE")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        row = _exact(item, _DEPENDENCY_FIELDS, "dependency")
        if row["gate_id"] != expected_gates[index]:
            _fail("FAIL_G02_DEPENDENCY_ROOTS")
        result.append(
            {"gate_id": expected_gates[index], "result_root": _sha256(row["result_root"], "dependency")}
        )
    return result


def _custody_key(
    value: object,
    *,
    expected_role: str,
    pinned_public_key: bytes,
) -> dict[str, Any]:
    label = expected_role
    raw = _exact(value, _KEY_FIELDS, f"{label}_key")
    if raw["role"] != expected_role:
        _fail(f"FAIL_G02_{label.upper()}_ROLE")
    key_id = _identifier(raw["key_id"], f"{label}_key")
    principal_id = _identifier(raw["principal_id"], f"{label}_principal")
    custodian_id = _identifier(raw["custodian_id"], f"{label}_custodian")
    if raw["algorithm"] != "Ed25519":
        _fail(f"FAIL_G02_{label.upper()}_ALGORITHM")
    if type(raw["public_key_base64"]) is not str:
        _fail(f"FAIL_G02_{label.upper()}_PUBLIC_KEY")
    try:
        public_key = base64.b64decode(raw["public_key_base64"], validate=True)
    except (ValueError, TypeError):
        _fail(f"FAIL_G02_{label.upper()}_PUBLIC_KEY")
    if len(public_key) != 32 or base64.b64encode(public_key).decode("ascii") != raw["public_key_base64"]:
        _fail(f"FAIL_G02_{label.upper()}_PUBLIC_KEY")
    try:
        expected_key_id = validate_ed25519_public_key(public_key)
    except ExactGateV2Error:
        _fail(f"FAIL_G02_{label.upper()}_PUBLIC_KEY_ENCODING")
    if type(pinned_public_key) is not bytes or len(pinned_public_key) != 32 or public_key != pinned_public_key:
        _fail(f"FAIL_G02_{label.upper()}_PIN_MISMATCH")
    if key_id != expected_key_id:
        _fail(f"FAIL_G02_{label.upper()}_KEY_ID_BINDING")
    valid_from = _timestamp(raw["valid_from_utc"], f"{label}_valid_from")
    valid_until = _timestamp(raw["valid_until_utc"], f"{label}_valid_until")
    if valid_from >= valid_until:
        _fail(f"FAIL_G02_{label.upper()}_VALIDITY")
    if raw["revoked"] is not False:
        _fail(f"FAIL_G02_{label.upper()}_KEY_REVOKED")
    return {
        "role": expected_role,
        "key_id": key_id,
        "principal_id": principal_id,
        "custodian_id": custodian_id,
        "public_key": public_key,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def _custody_keys(
    evidence: Mapping[str, Any],
    *,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
) -> dict[str, dict[str, Any]]:
    keys = {
        "source_executor": _custody_key(
            evidence["source_executor_key"],
            expected_role="source_executor",
            pinned_public_key=source_executor_public_key,
        ),
        "wrapper_executor": _custody_key(
            evidence["wrapper_executor_key"],
            expected_role="wrapper_executor",
            pinned_public_key=wrapper_executor_public_key,
        ),
        "trace_attestor": _custody_key(
            evidence["trace_attestor_key"],
            expected_role="trace_attestor",
            pinned_public_key=trace_attestor_public_key,
        ),
    }
    if len({key["public_key"] for key in keys.values()}) != len(keys) or len(
        {key["key_id"] for key in keys.values()}
    ) != len(keys):
        _fail("FAIL_G02_CUSTODY_KEY_REUSE")
    if len({key["principal_id"] for key in keys.values()}) != len(keys):
        _fail("FAIL_G02_CUSTODY_PRINCIPAL_REUSE")
    if len({key["custodian_id"] for key in keys.values()}) != len(keys):
        _fail("FAIL_G02_CUSTODY_CUSTODIAN_REUSE")
    return keys


def _validate_corpus(value: object, kind: str) -> tuple[list[dict[str, Any]], str]:
    corpus, corpus_sha256 = _decode_json_evidence(value, f"{kind}_corpus")
    raw = _exact(corpus, frozenset({"schema_version", "corpus_kind", "cases"}), "corpus")
    if raw["schema_version"] != G02_CORPUS_SCHEMA or raw["corpus_kind"] != kind:
        _fail("FAIL_G02_CORPUS_SCHEMA")
    if type(raw["cases"]) is not list or not raw["cases"]:
        _fail("FAIL_G02_CORPUS_CASES")
    cases: list[dict[str, Any]] = []
    previous_case_id = ""
    common = {
        "case_id",
        "engine",
        "canary_seat",
        "execution_receipt_sha256",
        "emitted_trace_sha256",
    }
    fields = frozenset(common if kind == "positive" else common | {"negative_class", "fixture_sha256"})
    for item in raw["cases"]:
        case = _exact(item, fields, "corpus_case")
        case_id = _identifier(case["case_id"], "case")
        if case_id <= previous_case_id:
            _fail("FAIL_G02_CORPUS_CASE_ORDER")
        previous_case_id = case_id
        if case["engine"] not in {"source", "wrapper"}:
            _fail("FAIL_G02_CASE_ENGINE")
        normalized: dict[str, Any] = {
            "case_id": case_id,
            "engine": case["engine"],
            "canary_seat": _seat(case["canary_seat"], "case_canary"),
            "execution_receipt_sha256": _sha256(
                case["execution_receipt_sha256"], "execution_receipt"
            ),
            "emitted_trace_sha256": _sha256(
                case["emitted_trace_sha256"], "emitted_trace"
            ),
        }
        if kind == "negative":
            negative_class = case["negative_class"]
            if negative_class not in NEGATIVE_CLASS_FAILURE_CODES:
                _fail("FAIL_G02_NEGATIVE_CASE_CLASS")
            normalized["negative_class"] = negative_class
            fixture_sha256 = hashlib.sha256(
                derive_negative_fixture_bytes(negative_class)
            ).hexdigest()
            if case["fixture_sha256"] != fixture_sha256:
                _fail("FAIL_G02_NEGATIVE_FIXTURE_NOT_FROZEN")
            normalized["fixture_sha256"] = fixture_sha256
        cases.append(normalized)
    return cases, corpus_sha256


def _expected_artifacts(engine: str, source: Mapping[str, str], wrapper: Mapping[str, str]) -> Mapping[str, str]:
    return source if engine == "source" else wrapper


def derive_execution_inventory_root(payload: Mapping[str, Any]) -> str:
    """Recompute the immutable pre/post execution inventory root."""

    return canonical_sha256(
        {
            "schema_version": G02_INVENTORY_SCHEMA,
            "case_id": payload["case_id"],
            "engine": payload["engine"],
            "engine_sha256": payload["engine_sha256"],
            "package_sha256": payload["package_sha256"],
            "parser_sha256": payload["parser_sha256"],
            "container_sha256": payload["container_sha256"],
            "artifact_bytes": payload["artifact_bytes"],
            "runner_image_sha256": payload["runner_image_sha256"],
            "runner_image_bytes": payload["runner_image_bytes"],
            "runner_binary_sha256": payload["runner_binary_sha256"],
            "runner_binary_bytes": payload["runner_binary_bytes"],
            "argv": payload["argv"],
            "env": payload["env"],
            "input_fixture": payload["input_fixture"],
            "platform_os": payload["platform_os"],
            "platform_arch": payload["platform_arch"],
        }
    )


def derive_post_run_inventory_bytes(*, case_id: str, inventory_root: str) -> bytes:
    """Derive the exact clean post-run workspace inventory statement."""

    return canonical_json_bytes(
        {
            "schema_version": G02_POST_RUN_INVENTORY_SCHEMA,
            "case_id": _identifier(case_id, "case"),
            "inventory_root": _sha256(inventory_root, "post_run_inventory"),
            "working_tree_clean": True,
            "created_paths": [],
            "modified_paths": [],
            "deleted_paths": [],
        }
    )


def _expected_stdout(
    *,
    case_id: str,
    corpus_kind: str,
    emitted_trace_sha256: str,
    negative_class: str,
) -> bytes:
    result: dict[str, Any] = {
        "schema_version": G02_RUN_RESULT_SCHEMA,
        "case_id": case_id,
        "emitted_trace_sha256": emitted_trace_sha256,
        "status": "SUCCEEDED" if corpus_kind == "positive" else "EXPECTED_REJECTION",
    }
    if corpus_kind == "negative":
        result["failure_code"] = NEGATIVE_CLASS_FAILURE_CODES[negative_class]
        result["fixture_sha256"] = hashlib.sha256(
            derive_negative_fixture_bytes(negative_class)
        ).hexdigest()
    return canonical_json_bytes(result)


def _derive_attestor_parser_result(
    *,
    emitted_trace: bytes,
    canary_seat: int,
    corpus_kind: str,
    negative_class: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if corpus_kind == "positive":
        try:
            parsed = parse_engine_event_trace(
                emitted_trace,
                canary_seat=canary_seat,
            )
        except EngineCapabilityError:
            _fail("FAIL_G02_POSITIVE_EXECUTION_TRACE_REJECTED")
        return (
            {
                "schema_version": G02_ATTESTOR_PARSER_RESULT_SCHEMA,
                "disposition": "ACCEPTED",
                "failure_code": "",
                "event_types": parsed["event_types"],
                "terminal_identity": parsed["terminal_identity"],
                "outcome": parsed["outcome"],
            },
            parsed,
        )
    try:
        parse_engine_event_trace(emitted_trace, canary_seat=canary_seat)
    except EngineCapabilityError as exc:
        if exc.code != NEGATIVE_CLASS_FAILURE_CODES[negative_class]:
            _fail("FAIL_G02_NEGATIVE_FIXTURE_FAILURE_MISMATCH")
        return (
            {
                "schema_version": G02_ATTESTOR_PARSER_RESULT_SCHEMA,
                "disposition": "REJECTED",
                "failure_code": exc.code,
                "event_types": [],
                "terminal_identity": "",
                "outcome": "",
            },
            None,
        )
    _fail("FAIL_G02_NEGATIVE_FIXTURE_ACCEPTED")


def _validate_execution_receipt(
    envelope: object,
    *,
    evidence: Mapping[str, Any],
    source_artifacts: Mapping[str, str],
    wrapper_artifacts: Mapping[str, str],
    runner_artifacts: Mapping[str, str],
    event_schema_sha256: str,
    executors: Mapping[str, Mapping[str, Any]],
    attestor: Mapping[str, Any],
    g00_time: datetime,
    g01_time: datetime,
    g02_time: datetime,
) -> dict[str, Any]:
    _validate_envelope_crypto_encoding(
        envelope,
        public_key=attestor["public_key"],
        label="trace_attestor",
    )
    try:
        payload = verify_envelope(
            envelope,
            expected_artifact_schema=G02_EXECUTION_RECEIPT_SCHEMA,
            pinned_public_key_bytes=attestor["public_key"],
        )
    except EnvelopeError:
        _fail("FAIL_G02_EXECUTION_RECEIPT_SIGNATURE")
    payload = _exact(payload, _EXECUTION_RECEIPT_FIELDS, "execution_receipt")
    if payload["schema_version"] != G02_EXECUTION_RECEIPT_SCHEMA:
        _fail("FAIL_G02_EXECUTION_RECEIPT_SCHEMA")

    if (
        payload["trace_attestor_key_id"] != attestor["key_id"]
        or payload["trace_attestor_principal_id"] != attestor["principal_id"]
        or payload["trace_attestor_custodian_id"] != attestor["custodian_id"]
    ):
        _fail("FAIL_G02_TRACE_ATTESTOR_IDENTITY_BINDING")
    engine = payload["engine"]
    if engine not in {"source", "wrapper"}:
        _fail("FAIL_G02_CASE_ENGINE")
    executor = executors[engine]
    if (
        payload["executor_role"] != executor["role"]
        or payload["executor_key_id"] != executor["key_id"]
        or payload["executor_principal_id"] != executor["principal_id"]
        or payload["executor_custodian_id"] != executor["custodian_id"]
    ):
        _fail("FAIL_G02_EXECUTOR_IDENTITY_BINDING")

    executor_envelope_bytes = _decode_bytes(
        payload["executor_envelope"],
        label="executor_envelope",
        media_type=G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
    )
    executor_envelope_sha256 = hashlib.sha256(executor_envelope_bytes).hexdigest()
    if payload["executor_envelope_sha256"] != executor_envelope_sha256:
        _fail("FAIL_G02_EXECUTOR_ENVELOPE_HASH")
    executor_envelope = _parse_canonical_json(
        executor_envelope_bytes,
        "executor_envelope",
    )
    _validate_envelope_crypto_encoding(
        executor_envelope,
        public_key=executor["public_key"],
        label="executor",
    )
    try:
        execution_payload = verify_envelope(
            executor_envelope,
            expected_artifact_schema=G02_EXECUTION_PAYLOAD_SCHEMA,
            pinned_public_key_bytes=executor["public_key"],
        )
    except EnvelopeError:
        _fail("FAIL_G02_EXECUTOR_SIGNATURE")
    execution_payload = _exact(
        execution_payload,
        _EXECUTION_PAYLOAD_FIELDS,
        "execution_payload",
    )
    if execution_payload["schema_version"] != G02_EXECUTION_PAYLOAD_SCHEMA:
        _fail("FAIL_G02_EXECUTION_PAYLOAD_SCHEMA")
    execution_payload_sha256 = canonical_sha256(execution_payload)
    if payload["execution_payload_sha256"] != execution_payload_sha256:
        _fail("FAIL_G02_EXECUTION_PAYLOAD_HASH")

    case_id = _identifier(execution_payload["case_id"], "execution_case")
    corpus_kind = execution_payload["corpus_kind"]
    if corpus_kind not in {"positive", "negative"}:
        _fail("FAIL_G02_TRACE_CORPUS_KIND")
    if (
        payload["case_id"] != case_id
        or payload["engine"] != execution_payload["engine"]
        or payload["execution_nonce"] != execution_payload["execution_nonce"]
    ):
        _fail("FAIL_G02_EXECUTION_RECEIPT_BINDING")
    canary_seat = _seat(execution_payload["canary_seat"], "case_canary")

    expected_common = {
        "campaign_root": evidence["campaign_root"],
        "evaluation_id": evidence["evaluation_id"],
        "frozen_spec_hash": evidence["frozen_spec_hash"],
        "g00_result_root": evidence["dependency_roots"][0]["result_root"],
        "g01_result_root": evidence["dependency_roots"][1]["result_root"],
        "g00_frozen_at_utc": evidence["g00_frozen_at_utc"],
        "g01_frozen_at_utc": evidence["g01_frozen_at_utc"],
        "g02_frozen_at_utc": evidence["g02_frozen_at_utc"],
        "event_schema_sha256": event_schema_sha256,
        "executor_role": executor["role"],
        "executor_key_id": executor["key_id"],
        "executor_principal_id": executor["principal_id"],
        "executor_custodian_id": executor["custodian_id"],
    }
    for field, expected in expected_common.items():
        if execution_payload[field] != expected:
            _fail("FAIL_G02_EXECUTION_BINDING_MISMATCH")

    artifacts = _expected_artifacts(engine, source_artifacts, wrapper_artifacts)
    for field, expected in artifacts.items():
        if execution_payload[field] != expected:
            _fail("FAIL_G02_EXECUTION_ARTIFACT_MISMATCH")
    artifact_bytes = _exact(
        execution_payload["artifact_bytes"],
        _ARTIFACT_BYTE_FIELDS,
        "artifact_bytes",
    )
    hash_fields = {
        "engine": "engine_sha256",
        "package": "package_sha256",
        "parser": "parser_sha256",
        "container": "container_sha256",
    }
    for artifact_name, hash_field in hash_fields.items():
        _decode_bytes(
            artifact_bytes[artifact_name],
            label=f"{artifact_name}_artifact",
            media_type="application/octet-stream",
            expected_sha256=artifacts[hash_field],
        )

    for field, expected in runner_artifacts.items():
        if execution_payload[field] != expected:
            _fail("FAIL_G02_RUNNER_ARTIFACT_MISMATCH")
    _decode_bytes(
        execution_payload["runner_image_bytes"],
        label="runner_image",
        media_type="application/octet-stream",
        expected_sha256=runner_artifacts["runner_image_sha256"],
    )
    _decode_bytes(
        execution_payload["runner_binary_bytes"],
        label="runner_binary",
        media_type="application/octet-stream",
        expected_sha256=runner_artifacts["runner_binary_sha256"],
    )

    expected_argv = derive_execution_argv(
        case_id=case_id,
        engine=engine,
        canary_seat=canary_seat,
        corpus_kind=corpus_kind,
    )
    if (
        type(execution_payload["argv"]) is not list
        or execution_payload["argv"] != expected_argv
    ):
        _fail("FAIL_G02_EXECUTION_ARGV")
    if (
        type(execution_payload["env"]) is not dict
        or execution_payload["env"] != RUNNER_ENVIRONMENT
    ):
        _fail("FAIL_G02_EXECUTION_ENV")
    if (
        execution_payload["platform_os"] != "linux"
        or execution_payload["platform_arch"] != "amd64"
    ):
        _fail("FAIL_G02_EXECUTION_PLATFORM")
    if (
        execution_payload["isolated_execution"] is not True
        or execution_payload["working_tree_clean"] is not True
    ):
        _fail("FAIL_G02_EXECUTION_ISOLATION")
    for field in ("retry_count", "intervention_count"):
        if type(execution_payload[field]) is not int or execution_payload[field] != 0:
            _fail(f"FAIL_G02_EXECUTION_{field.upper()}")

    negative_class = execution_payload["negative_class"]
    if corpus_kind == "positive":
        if (
            negative_class != ""
            or execution_payload["runner_mode"] != "ENGINE_EMISSION"
        ):
            _fail("FAIL_G02_EXECUTION_MODE")
        expected_input = derive_positive_input_fixture_bytes(
            case_id=case_id, engine=engine, canary_seat=canary_seat
        )
    else:
        if (
            negative_class not in NEGATIVE_CLASS_FAILURE_CODES
            or execution_payload["runner_mode"] != "PARSER_NEGATIVE_FIXTURE"
        ):
            _fail("FAIL_G02_EXECUTION_MODE")
        expected_input = derive_negative_fixture_bytes(negative_class)
    input_bytes = _decode_bytes(
        execution_payload["input_fixture"],
        label="input_fixture",
        media_type="application/json",
    )
    _parse_canonical_json(input_bytes, "input_fixture")
    if input_bytes != expected_input:
        _fail("FAIL_G02_EXECUTION_INPUT_FIXTURE")

    expected_inventory_root = derive_execution_inventory_root(execution_payload)
    if execution_payload["working_tree_input_inventory_root"] != expected_inventory_root:
        _fail("FAIL_G02_EXECUTION_WORKSPACE_INVENTORY")
    if execution_payload["post_run_inventory_root"] != expected_inventory_root:
        _fail("FAIL_G02_EXECUTION_POST_RUN_INVENTORY")
    post_run_inventory = _decode_bytes(
        execution_payload["post_run_inventory"],
        label="post_run_inventory",
        media_type="application/json",
    )
    _parse_canonical_json(post_run_inventory, "post_run_inventory")
    if post_run_inventory != derive_post_run_inventory_bytes(
        case_id=case_id, inventory_root=expected_inventory_root
    ):
        _fail("FAIL_G02_EXECUTION_POST_RUN_INVENTORY")
    nonce = _sha256(execution_payload["execution_nonce"], "execution_nonce")

    started = _timestamp(execution_payload["started_at_utc"], "execution_started")
    ended = _timestamp(execution_payload["ended_at_utc"], "execution_ended")
    executor_signed_at = _timestamp(
        execution_payload["executor_signed_at_utc"],
        "executor_signed",
    )
    attested_at = _timestamp(payload["attested_at_utc"], "trace_attested")
    if not (
        g01_time <= started < ended <= executor_signed_at < attested_at <= g02_time
    ) or started < g00_time:
        _fail("FAIL_G02_EXECUTION_FREEZE_CHRONOLOGY")
    if not executor["valid_from"] <= executor_signed_at < executor["valid_until"]:
        _fail("FAIL_G02_EXECUTOR_KEY_STALE")
    if not attestor["valid_from"] <= attested_at < attestor["valid_until"]:
        _fail("FAIL_G02_TRACE_ATTESTOR_KEY_STALE")

    expected_status = "SUCCEEDED" if corpus_kind == "positive" else "EXPECTED_REJECTION"
    if (
        type(execution_payload["exit_code"]) is not int
        or execution_payload["exit_code"] != 0
    ):
        _fail("FAIL_G02_EXECUTION_EXIT")
    if execution_payload["status"] != expected_status:
        _fail("FAIL_G02_EXECUTION_STATUS")
    stderr = _decode_bytes(
        execution_payload["stderr"],
        label="stderr",
        media_type="text/plain",
    )
    if stderr != b"":
        _fail("FAIL_G02_EXECUTION_STDERR")
    emitted_trace = _decode_bytes(
        execution_payload["emitted_trace"],
        label="emitted_trace",
        media_type="application/json",
    )
    _parse_canonical_json(emitted_trace, "emitted_trace")
    emitted_trace_sha256 = hashlib.sha256(emitted_trace).hexdigest()
    if payload["emitted_trace_sha256"] != emitted_trace_sha256:
        _fail("FAIL_G02_ATTESTED_TRACE_HASH")
    stdout = _decode_bytes(
        execution_payload["stdout"],
        label="stdout",
        media_type="application/json",
    )
    _parse_canonical_json(stdout, "stdout")
    if stdout != _expected_stdout(
        case_id=case_id,
        corpus_kind=corpus_kind,
        emitted_trace_sha256=emitted_trace_sha256,
        negative_class=negative_class,
    ):
        _fail("FAIL_G02_EXECUTION_STDOUT")

    if corpus_kind == "negative" and emitted_trace != input_bytes:
        _fail("FAIL_G02_NEGATIVE_EXECUTION_OUTPUT_MISMATCH")
    expected_parser_result, parsed = _derive_attestor_parser_result(
        emitted_trace=emitted_trace,
        canary_seat=canary_seat,
        corpus_kind=corpus_kind,
        negative_class=negative_class,
    )
    parser_result = _exact(
        payload["parser_result"],
        _PARSER_RESULT_FIELDS,
        "attestor_parser_result",
    )
    if parser_result != expected_parser_result:
        _fail("FAIL_G02_ATTESTOR_PARSER_RESULT")

    receipt_sha256 = canonical_sha256(envelope)
    corpus_row: dict[str, Any] = {
        "case_id": case_id,
        "engine": engine,
        "canary_seat": canary_seat,
        "execution_receipt_sha256": receipt_sha256,
        "emitted_trace_sha256": emitted_trace_sha256,
    }
    if corpus_kind == "negative":
        corpus_row["negative_class"] = negative_class
        corpus_row["fixture_sha256"] = hashlib.sha256(input_bytes).hexdigest()
    return {
        "case_id": case_id,
        "corpus_kind": corpus_kind,
        "engine": engine,
        "execution_nonce": nonce,
        "receipt_sha256": receipt_sha256,
        "executor_envelope_sha256": executor_envelope_sha256,
        "corpus_row": corpus_row,
        "parsed": parsed,
        "negative_class": negative_class,
    }


def _verify_execution_cases(
    envelopes: object,
    *,
    positive_cases: Sequence[Mapping[str, Any]],
    negative_cases: Sequence[Mapping[str, Any]],
    evidence: Mapping[str, Any],
    source_artifacts: Mapping[str, str],
    wrapper_artifacts: Mapping[str, str],
    runner_artifacts: Mapping[str, str],
    event_schema_sha256: str,
    executors: Mapping[str, Mapping[str, Any]],
    attestor: Mapping[str, Any],
    g00_time: datetime,
    g01_time: datetime,
    g02_time: datetime,
) -> dict[str, Any]:
    expected_count = len(positive_cases) + len(negative_cases)
    if type(envelopes) is not list or len(envelopes) != expected_count:
        _fail("FAIL_G02_EXECUTION_RECEIPT_CLOSURE")
    seen: set[str] = set()
    positive_events = {"source": set(), "wrapper": set()}
    positive_terminals = {"source": set(), "wrapper": set()}
    negative_classes = {"source": set(), "wrapper": set()}
    derived_cases = {"positive": [], "negative": []}
    nonces = {"source": [], "wrapper": []}
    executor_envelopes = {"source": [], "wrapper": []}
    receipts: list[dict[str, str]] = []
    accepted = 0
    rejected = 0
    previous_case_id = ""

    for envelope in envelopes:
        execution = _validate_execution_receipt(
            envelope,
            evidence=evidence,
            source_artifacts=source_artifacts,
            wrapper_artifacts=wrapper_artifacts,
            runner_artifacts=runner_artifacts,
            event_schema_sha256=event_schema_sha256,
            executors=executors,
            attestor=attestor,
            g00_time=g00_time,
            g01_time=g01_time,
            g02_time=g02_time,
        )
        case_id = execution["case_id"]
        if case_id <= previous_case_id or case_id in seen:
            _fail("FAIL_G02_EXECUTION_CASE_ORDER")
        previous_case_id = case_id
        seen.add(case_id)
        derived_cases[execution["corpus_kind"]].append(execution["corpus_row"])
        nonces[execution["engine"]].append(execution["execution_nonce"])
        executor_envelopes[execution["engine"]].append(
            {
                "case_id": case_id,
                "executor_envelope_sha256": execution[
                    "executor_envelope_sha256"
                ],
            }
        )
        receipts.append(
            {"case_id": case_id, "execution_receipt_sha256": execution["receipt_sha256"]}
        )
        if execution["corpus_kind"] == "negative":
            rejected += 1
            negative_classes[execution["engine"]].add(execution["negative_class"])
            continue
        accepted += 1
        parsed = execution["parsed"]
        positive_events[execution["engine"]].update(parsed["event_types"])
        positive_terminals[execution["engine"]].add(parsed["terminal_identity"])

    if derived_cases["positive"] != list(positive_cases):
        _fail("FAIL_G02_POSITIVE_CORPUS_MEMBERSHIP")
    if derived_cases["negative"] != list(negative_cases):
        _fail("FAIL_G02_NEGATIVE_CORPUS_MEMBERSHIP")
    all_nonces = [*nonces["source"], *nonces["wrapper"]]
    if len(all_nonces) != len(set(all_nonces)):
        _fail("FAIL_G02_EXECUTION_NONCE_REUSE")
    if set(nonces["source"]) & set(nonces["wrapper"]):
        _fail("FAIL_G02_CROSS_ENGINE_NONCE_REUSE")
    expected_events = set(EVENT_VOCABULARY)
    expected_terminals = set(TERMINAL_IDENTITIES)
    expected_negative_classes = set(NEGATIVE_CASE_CLASSES)
    for engine in ("source", "wrapper"):
        if negative_classes[engine] != expected_negative_classes:
            _fail("FAIL_G02_NEGATIVE_CORPUS_COVERAGE")
        if positive_events[engine] != expected_events:
            _fail("FAIL_G02_POSITIVE_EVENT_COVERAGE")
        if positive_terminals[engine] != expected_terminals:
            _fail("FAIL_G02_POSITIVE_TERMINAL_COVERAGE")
    return {
        "positive_event_types_by_engine": {
            engine: [event for event in EVENT_VOCABULARY if event in positive_events[engine]]
            for engine in ("source", "wrapper")
        },
        "positive_terminal_identities_by_engine": {
            engine: [identity for identity in TERMINAL_IDENTITIES if identity in positive_terminals[engine]]
            for engine in ("source", "wrapper")
        },
        "negative_case_classes": list(NEGATIVE_CASE_CLASSES),
        "execution_case_ids": sorted(seen),
        "execution_receipt_root_sha256": canonical_sha256(receipts),
        "source_execution_nonce_root_sha256": canonical_sha256(nonces["source"]),
        "wrapper_execution_nonce_root_sha256": canonical_sha256(nonces["wrapper"]),
        "source_executor_envelope_root_sha256": canonical_sha256(
            executor_envelopes["source"]
        ),
        "wrapper_executor_envelope_root_sha256": canonical_sha256(
            executor_envelopes["wrapper"]
        ),
        "executor_signature_verified_case_count": expected_count,
        "attestor_signature_verified_case_count": expected_count,
        "parser_rerun_case_count": expected_count,
        "accepted_case_count": accepted,
        "rejected_case_count": rejected,
    }


def _validate_evidence(
    evidence: object,
    *,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
    expected_bindings: Mapping[str, Any] | None,
) -> dict[str, Any]:
    _reject_private_or_authority(evidence)
    raw = _exact(evidence, _EVIDENCE_FIELDS, "evidence")
    if raw["schema_version"] != G02_EVIDENCE_SCHEMA:
        _fail("FAIL_G02_EVIDENCE_SCHEMA")
    _sha256(raw["campaign_root"], "campaign_root")
    _identifier(raw["evaluation_id"], "evaluation")
    _sha256(raw["frozen_spec_hash"], "frozen_spec")
    dependencies = _dependencies(raw["dependency_roots"])
    for field in (
        "campaign_registry_hash",
        "evidence_manifest_root",
        "verifier_module_digest",
    ):
        _sha256(raw[field], field)
    g00_time = _timestamp(raw["g00_frozen_at_utc"], "g00_freeze")
    g01_time = _timestamp(raw["g01_frozen_at_utc"], "g01_freeze")
    g02_time = _timestamp(raw["g02_frozen_at_utc"], "g02_freeze")
    if not g00_time < g01_time <= g02_time:
        _fail("FAIL_G02_FREEZE_CHRONOLOGY")
    if expected_bindings is not None:
        for field in (
            "campaign_root",
            "evaluation_id",
            "frozen_spec_hash",
            "campaign_registry_hash",
            "evidence_manifest_root",
            "verifier_module_digest",
        ):
            if raw[field] != expected_bindings[field]:
                _fail("FAIL_G02_FINAL_BINDING_MISMATCH")
        if dependencies != expected_bindings["dependency_roots"]:
            _fail("FAIL_G02_FINAL_BINDING_MISMATCH")

    event_schema, event_schema_sha256 = _decode_json_evidence(raw["event_schema"], "event_schema")
    _validate_event_schema(event_schema)
    source_artifacts = _validate_artifacts(raw["source_artifacts"], "source_artifacts")
    wrapper_artifacts = _validate_artifacts(raw["wrapper_artifacts"], "wrapper_artifacts")
    if source_artifacts == wrapper_artifacts:
        _fail("FAIL_G02_ENGINE_ARTIFACTS_NOT_INDEPENDENT")
    runner_artifacts = _validate_runner_artifacts(raw["runner_artifacts"])
    custody = _custody_keys(
        raw,
        source_executor_public_key=source_executor_public_key,
        wrapper_executor_public_key=wrapper_executor_public_key,
        trace_attestor_public_key=trace_attestor_public_key,
    )
    executors = {
        "source": custody["source_executor"],
        "wrapper": custody["wrapper_executor"],
    }
    attestor = custody["trace_attestor"]
    positive_cases, positive_corpus_sha256 = _validate_corpus(raw["positive_corpus"], "positive")
    negative_cases, negative_corpus_sha256 = _validate_corpus(raw["negative_corpus"], "negative")
    all_cases = sorted([*positive_cases, *negative_cases], key=lambda case: case["case_id"])
    if len({case["case_id"] for case in all_cases}) != len(all_cases):
        _fail("FAIL_G02_CORPUS_CASE_DUPLICATE")
    execution_outputs = _verify_execution_cases(
        raw["execution_receipt_envelopes"],
        positive_cases=positive_cases,
        negative_cases=negative_cases,
        evidence=raw,
        source_artifacts=source_artifacts,
        wrapper_artifacts=wrapper_artifacts,
        runner_artifacts=runner_artifacts,
        event_schema_sha256=event_schema_sha256,
        executors=executors,
        attestor=attestor,
        g00_time=g00_time,
        g01_time=g01_time,
        g02_time=g02_time,
    )
    return {
        "event_schema_sha256": event_schema_sha256,
        "positive_corpus_sha256": positive_corpus_sha256,
        "negative_corpus_sha256": negative_corpus_sha256,
        "source_artifacts": source_artifacts,
        "wrapper_artifacts": wrapper_artifacts,
        "runner_artifacts": runner_artifacts,
        **execution_outputs,
    }


def _evidence_hash(value: object) -> str:
    try:
        return canonical_sha256(value)
    except CanonicalJSONError:
        # Evidence that cannot be canonically represented cannot be signed into
        # an exact final result.  This sentinel is only returned in the local
        # failure output; final gate construction will reject non-JSON input.
        return hashlib.sha256(b"evaluation_v5_1:g02:noncanonical-evidence").hexdigest()


def _failure_outputs(evidence_sha256: str, code: str) -> dict[str, Any]:
    return {
        "schema_version": G02_RECOMPUTED_OUTPUT_SCHEMA,
        "gate_id": GATE_ID,
        "evidence_sha256": evidence_sha256,
        "event_schema_sha256": None,
        "positive_corpus_sha256": None,
        "negative_corpus_sha256": None,
        "source_artifacts": None,
        "wrapper_artifacts": None,
        "runner_artifacts": None,
        "positive_event_types_by_engine": {"source": [], "wrapper": []},
        "positive_terminal_identities_by_engine": {"source": [], "wrapper": []},
        "negative_case_classes": [],
        "execution_case_ids": [],
        "execution_receipt_root_sha256": None,
        "source_execution_nonce_root_sha256": None,
        "wrapper_execution_nonce_root_sha256": None,
        "source_executor_envelope_root_sha256": None,
        "wrapper_executor_envelope_root_sha256": None,
        "executor_signature_verified_case_count": 0,
        "attestor_signature_verified_case_count": 0,
        "parser_rerun_case_count": 0,
        "accepted_case_count": 0,
        "rejected_case_count": 0,
        "decision": FAIL_DECISION,
        "failure_codes": [code],
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def derive_engine_event_capability_outputs(
    evidence: object,
    *,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
    expected_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute G02 from raw evidence without trusting any signed boolean.

    Malformed evidence yields a structured fail-closed output.  Callers that
    need a local exception for a specific parser/corpus error can use
    :func:`parse_engine_event_trace` or
    :func:`validate_engine_event_capability_evidence` directly.
    """

    evidence_sha256 = _evidence_hash(evidence)
    try:
        validated = _validate_evidence(
            evidence,
            source_executor_public_key=source_executor_public_key,
            wrapper_executor_public_key=wrapper_executor_public_key,
            trace_attestor_public_key=trace_attestor_public_key,
            expected_bindings=expected_bindings,
        )
    except EngineCapabilityError as exc:
        return _failure_outputs(evidence_sha256, exc.code)
    return {
        "schema_version": G02_RECOMPUTED_OUTPUT_SCHEMA,
        "gate_id": GATE_ID,
        "evidence_sha256": evidence_sha256,
        "event_schema_sha256": validated["event_schema_sha256"],
        "positive_corpus_sha256": validated["positive_corpus_sha256"],
        "negative_corpus_sha256": validated["negative_corpus_sha256"],
        "source_artifacts": validated["source_artifacts"],
        "wrapper_artifacts": validated["wrapper_artifacts"],
        "runner_artifacts": validated["runner_artifacts"],
        "positive_event_types_by_engine": validated["positive_event_types_by_engine"],
        "positive_terminal_identities_by_engine": validated[
            "positive_terminal_identities_by_engine"
        ],
        "negative_case_classes": validated["negative_case_classes"],
        "execution_case_ids": validated["execution_case_ids"],
        "execution_receipt_root_sha256": validated[
            "execution_receipt_root_sha256"
        ],
        "source_execution_nonce_root_sha256": validated[
            "source_execution_nonce_root_sha256"
        ],
        "wrapper_execution_nonce_root_sha256": validated[
            "wrapper_execution_nonce_root_sha256"
        ],
        "source_executor_envelope_root_sha256": validated[
            "source_executor_envelope_root_sha256"
        ],
        "wrapper_executor_envelope_root_sha256": validated[
            "wrapper_executor_envelope_root_sha256"
        ],
        "executor_signature_verified_case_count": validated[
            "executor_signature_verified_case_count"
        ],
        "attestor_signature_verified_case_count": validated[
            "attestor_signature_verified_case_count"
        ],
        "parser_rerun_case_count": validated["parser_rerun_case_count"],
        "accepted_case_count": validated["accepted_case_count"],
        "rejected_case_count": validated["rejected_case_count"],
        "decision": PASS_DECISION,
        "failure_codes": [],
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def validate_engine_event_capability_evidence(
    evidence: object,
    *,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
) -> dict[str, Any]:
    """Validate raw G02 evidence and return its normalized derived facts."""

    return _validate_evidence(
        evidence,
        source_executor_public_key=source_executor_public_key,
        wrapper_executor_public_key=wrapper_executor_public_key,
        trace_attestor_public_key=trace_attestor_public_key,
        expected_bindings=None,
    )


def derive_engine_event_capability_gate_payload(
    *,
    evidence: object,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    dependency_roots: Sequence[Mapping[str, str]],
    campaign_registry_hash: str,
    evidence_manifest_root: str,
    verifier_module_digest: str,
) -> dict[str, Any]:
    """Reject the retired caller-assembled final-payload path.

    The shared exact-gate v2 service must derive final payloads from its
    root-authenticated registry, closed evidence manifest, and hermetic G02
    verifier execution.  Retaining this deterministic failure shim prevents
    older callers from silently recreating local authority.
    """

    del (
        evidence,
        source_executor_public_key,
        wrapper_executor_public_key,
        trace_attestor_public_key,
        campaign_root,
        evaluation_id,
        frozen_spec_hash,
        dependency_roots,
        campaign_registry_hash,
        evidence_manifest_root,
        verifier_module_digest,
    )
    _fail("FAIL_G02_EXACT_GATE_V2_SERVICE_REQUIRED")


def derive_engine_event_capability_countersignature_payload(
    authority_envelope: object,
) -> dict[str, Any]:
    """Reject the retired module-local countersignature path."""

    del authority_envelope
    _fail("FAIL_G02_EXACT_GATE_V2_SERVICE_REQUIRED")


def verify_engine_event_capability_gate(
    *,
    evidence: object,
    final_bundle: object,
    source_executor_public_key: bytes,
    wrapper_executor_public_key: bytes,
    trace_attestor_public_key: bytes,
) -> dict[str, Any]:
    """Recompute local evidence, then defer final authority to exact-gate v2.

    A malformed local evidence universe fails before final-bundle handling.  A
    locally valid universe still cannot certify itself: only the shared v2
    verifier may resolve authority, validate both exact envelopes, and dispatch
    the registered content-addressed hermetic G02 verifier.
    """

    outputs = derive_engine_event_capability_outputs(
        evidence,
        source_executor_public_key=source_executor_public_key,
        wrapper_executor_public_key=wrapper_executor_public_key,
        trace_attestor_public_key=trace_attestor_public_key,
    )
    if outputs["decision"] != PASS_DECISION:
        return outputs
    return verify_exact_gate_v2(gate_id=GATE_ID, final_bundle=final_bundle)


# G02 spelling is provided for callers that name validators after their gate.
derive_g02_engine_event_capability_outputs = derive_engine_event_capability_outputs
derive_g02_engine_event_capability_gate_payload = derive_engine_event_capability_gate_payload
verify_g02_engine_event_capability_gate = verify_engine_event_capability_gate


__all__ = [
    "EVENT_FIELD_SETS",
    "EVENT_VOCABULARY",
    "G02_ATTESTOR_PARSER_RESULT_SCHEMA",
    "G02_CORPUS_SCHEMA",
    "G02_EVIDENCE_SCHEMA",
    "G02_EVENT_SCHEMA_DOCUMENT",
    "G02_EXECUTION_PAYLOAD_SCHEMA",
    "G02_EXECUTION_RECEIPT_SCHEMA",
    "G02_EXECUTOR_ENVELOPE_MEDIA_TYPE",
    "G02_INVENTORY_SCHEMA",
    "G02_POST_RUN_INVENTORY_SCHEMA",
    "G02_POSITIVE_INPUT_SCHEMA",
    "G02_RECOMPUTED_OUTPUT_SCHEMA",
    "G02_RUN_RESULT_SCHEMA",
    "G02_TRACE_CASE_SCHEMA",
    "G02_TRACE_SCHEMA",
    "GATE_ID",
    "NEGATIVE_CASE_CLASSES",
    "NEGATIVE_CLASS_FAILURE_CODES",
    "PROTOCOL_ID",
    "RUNNER_BINARY_PATH",
    "RUNNER_ENVIRONMENT",
    "TERMINAL_IDENTITIES",
    "TERMINAL_OUTCOMES",
    "EngineCapabilityError",
    "derive_engine_event_capability_gate_payload",
    "derive_engine_event_capability_countersignature_payload",
    "derive_engine_event_capability_outputs",
    "derive_event_schema_document",
    "derive_execution_argv",
    "derive_execution_inventory_root",
    "derive_g02_engine_event_capability_gate_payload",
    "derive_g02_engine_event_capability_outputs",
    "derive_negative_fixture_bytes",
    "derive_post_run_inventory_bytes",
    "derive_positive_input_fixture_bytes",
    "parse_engine_event_trace",
    "validate_engine_event_capability_evidence",
    "verify_engine_event_capability_gate",
    "verify_g02_engine_event_capability_gate",
]
