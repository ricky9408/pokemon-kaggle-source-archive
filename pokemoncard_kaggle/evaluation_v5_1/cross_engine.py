"""Frozen G04 cross-engine gross-distortion verifier.

G04 is diagnostic and has permanent zero submission authority.  A valid panel
contains one independently authenticated seed row and one independently
authenticated raw-trace leaf for every scheduled episode.  No aggregate or
run-length summary is evidence authority: all metrics are independently parsed
here from exact raw bytes emitted by a typed, signed execution receipt.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from fractions import Fraction
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import PROTOCOL_ID
from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .engine_capability import EVENT_FIELD_SETS as G02_EVENT_FIELD_SETS
from .engine_capability import TERMINAL_OUTCOMES as G02_TERMINAL_OUTCOMES
from .envelope import EnvelopeError, verify_envelope
from .exact_gate_v2 import (
    ExactGateV2Error,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)


INPUT_SCHEMA = "evaluation_v5_1_g04_cross_engine_panel_v4"
RESULT_SCHEMA = "evaluation_v5_1_g04_cross_engine_result_v4"
MANIFEST_SCHEMA = "evaluation_v5_1_g04_cross_engine_manifest_v4"
SEED_AUDIT_SCHEMA = "evaluation_v5_1_g04_seed_audit_v4"
ARITHMETIC_RECEIPT_SCHEMA = "evaluation_v5_1_g04_mpfr_receipt_v4"
MEASUREMENT_RECEIPT_SCHEMA = "evaluation_v5_1_g04_measurement_receipt_v4"
SEED_INVENTORY_SCHEMA = "evaluation_v5_1_g04_seed_inventory_v2"
SEED_INVENTORY_FREEZE_SCHEMA = "evaluation_v5_1_g04_seed_inventory_freeze_v2"
SEED_UNIQUENESS_SCHEMA = "evaluation_v5_1_g04_seed_uniqueness_proof_v2"
SEED_DERIVATION_SCHEMA = "evaluation_v5_1_g04_domain_separated_seed_derivation_v2"
SEED_COMMITMENT_SCHEMA = "evaluation_v5_1_g04_seed_commitment_v2"
EXECUTION_RECEIPT_SCHEMA = "evaluation_v5_1_g04_slot_execution_receipt_v1"
EXECUTION_ENVELOPE_SCHEMA = "evaluation_v5_1_g04_exact_execution_envelope_v1"
TRACE_ATTESTATION_SCHEMA = "evaluation_v5_1_g04_independent_trace_attestation_v1"
TRACE_ATTESTATION_ENVELOPE_SCHEMA = (
    "evaluation_v5_1_g04_exact_trace_attestation_envelope_v1"
)
RAW_TRACE_SCHEMA = "evaluation_v5_1_g04_raw_execution_trace_v1"
CANONICAL_TRACE_SCHEMA = "evaluation_v5_1_g04_canonical_primitive_trace_v1"
EXECUTION_INPUT_SCHEMA = "evaluation_v5_1_g04_slot_execution_input_v1"
WORKSPACE_PRE_INVENTORY_SCHEMA = "evaluation_v5_1_g04_workspace_pre_inventory_v1"
POST_RUN_INVENTORY_SCHEMA = "evaluation_v5_1_g04_post_run_inventory_v1"
RUN_RESULT_SCHEMA = "evaluation_v5_1_g04_slot_run_result_v1"
FINAL_AUTHORITY_SCHEMA = "evaluation_v5_1_g04_final_authority_v2"
FINAL_VALIDATOR_SCHEMA = "evaluation_v5_1_g04_final_validator_countersignature_v2"

EXECUTION_ENVELOPE_DOMAIN = b"EVAL_V5_1_G04_SLOT_EXECUTION_ENVELOPE_V1\0"
TRACE_ATTESTATION_ENVELOPE_DOMAIN = (
    b"EVAL_V5_1_G04_TRACE_ATTESTATION_ENVELOPE_V1\0"
)
EXECUTION_PAYLOAD_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g04-slot-execution-receipt+json"
)
EXECUTION_ENVELOPE_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g04-slot-execution-envelope+json"
)
TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g04-trace-attestation+json"
)
TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g04-trace-attestation-envelope+json"
)
RAW_TRACE_MEDIA_TYPE = "application/vnd.evaluation-v5-1.g04-raw-trace+json"
CANONICAL_TRACE_MEDIA_TYPE = (
    "application/vnd.evaluation-v5-1.g04-canonical-primitive-trace+json"
)
RUNNER_BINARY_PATH = "/opt/evaluation-v5.1/bin/g04-cross-engine-runner"
RUNNER_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TZ": "UTC",
}
INPUT_ROOT = "/g04/input"
WORKSPACE_ROOT = "/g04/workspace"
OUTPUT_ROOT = "/g04/output"

CANARY_COUNT = 4
OPPONENT_COUNT = 4
SEATS = ("canary_first", "canary_second")
ENGINES = ("source", "wrapper")
EPISODES_PER_CELL = 6_250
CELL_COUNT = CANARY_COUNT * OPPONENT_COUNT * len(SEATS)

EVENT_METRICS = (
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
DERIVED_EPISODE_METRICS = (
    "clean_terminal",
    "decisive_clean_terminal",
    "canary_acted",
    "opponent_acted",
    "canary_win",
    "opponent_win",
    "draw",
    "any_illegal_action",
    "terminal_failure",
    "natural_start_invalid",
)
CONDITIONAL_METRICS = (
    "canary_win_given_decisive_clean_terminal",
    "draw_given_clean_terminal",
    "all_canary_actions_legal_given_canary_acted",
    "all_opponent_actions_legal_given_opponent_acted",
)
CONDITIONAL_DENOMINATORS = {
    "canary_win_given_decisive_clean_terminal": "decisive_clean_terminal",
    "draw_given_clean_terminal": "clean_terminal",
    "all_canary_actions_legal_given_canary_acted": "canary_acted",
    "all_opponent_actions_legal_given_opponent_acted": "opponent_acted",
}
COMPARISONS_PER_CELL = (
    len(EVENT_METRICS) + len(DERIVED_EPISODE_METRICS) + len(CONDITIONAL_METRICS)
)
COMPARISON_COUNT = CELL_COUNT * COMPARISONS_PER_CELL
ALPHA_NUMERATOR = 1
ALPHA_DENOMINATOR = 20
INCIDENCE_MARGIN = Fraction(6, 100)
CONDITIONAL_MARGIN = Fraction(8, 100)
CONDITIONAL_SUPPORT_FLOOR = 1_650
PREFIX = {
    "start_event": "GAME_START",
    "end_marker": "CANARY_FOURTH_OWN_TURN_END",
    "canary_own_turn_count": 4,
}
FROZEN_MPFR_BACKEND_ID = "gmpy2-mpfr-256-rndu-v1"
HOEFFDING_FORMULA = "sqrt(0.5*(1/n_src+1/n_wrap)*ln(40*K))"
RADIUS_DECIMAL_DIGITS = 80

# The operational verifier pins raw Ed25519 public keys.  Tests replace the
# entire registry with isolated fixture keys; a panel also binds its registry
# digest, so a caller cannot select keys inside an evidence artifact.
PINNED_ROLE_PUBLIC_KEYS: Mapping[str, bytes] = {
    "source_executor": bytes.fromhex(
        "5854f412c33f59c2101a8a75092d3d9036fd6dc684a4cf477366da46d886cdcc"
    ),
    "wrapper_executor": bytes.fromhex(
        "6d1330c450e720602cfde9961c7b44efcb9e7d6b505c8fc2a1a3c779733d9a46"
    ),
    "trace_attestor": bytes.fromhex(
        "928699d461bc8a00033f60794f6c6c21877d53bc0801fdf10b82641b0216ef7c"
    ),
    "evaluation_authority": bytes.fromhex(
        "95853c6b785e0f3ea3bdda386321f82f38fa788e74d95c88ea53eb69c07f465c"
    ),
    "validator": bytes.fromhex(
        "37f60742361d3c2cb965b8db1a115fe7940860721b4989933659df8f65013b54"
    ),
}

_ROLE_NAMES = frozenset(PINNED_ROLE_PUBLIC_KEYS)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RADIUS_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)\.[0-9]{80}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_EVENT_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+\-/]{0,126}$")
_BYTE_WRAPPER_FIELDS = frozenset(
    {"base64", "decoded_length", "sha256", "media_type"}
)
_SIGNED_ENVELOPE_FIELDS = frozenset(
    {"schema", "payload", "signer_key_id", "signature_ed25519_base64"}
)
_ACTOR_SEATS = (0, 1)
_OUTCOMES = ("CANARY_WIN", "OPPONENT_WIN", "DRAW")
_TRACE_STATUSES = ("recorded", "missing_record", "harness_crash")
_TERMINAL_EVENTS = ("GAME_END", "TIMEOUT", "POLICY_EXCEPTION")
_ACTOR_EVENTS = frozenset(EVENT_METRICS) - {"GAME_START", "GAME_END"}
_POKEMON_EVENTS = frozenset(
    {
        "MANUAL_ENERGY_ATTACHED",
        "ATTACK_DECLARED",
        "DAMAGE_APPLIED",
        "PRIZE_TAKEN",
        "POKEMON_KO",
        "ACTIVE_PROMOTED",
        "FORCED_SWITCH",
        "RUN_AWAY_DRAW_ATTEMPT",
    }
)
_CHOSEN_REQUEST_EVENTS = frozenset(
    {
        "MANUAL_ENERGY_ATTACHED",
        "ATTACK_DECLARED",
        "RUN_AWAY_DRAW_ATTEMPT",
        "ILLEGAL_ACTION",
        "POLICY_EXCEPTION",
        "TIMEOUT",
    }
)
_ATTACK_CAUSED_EVENTS = frozenset(
    {"DAMAGE_APPLIED", "PRIZE_TAKEN", "POKEMON_KO", "FORCED_SWITCH"}
)
_FROZEN_ARTIFACT_FIELDS = {
    "source_build_sha256",
    "source_package_sha256",
    "source_model_sha256",
    "source_container_sha256",
    "wrapper_build_sha256",
    "wrapper_package_sha256",
    "wrapper_model_sha256",
    "wrapper_container_sha256",
    "trace_parser_sha256",
    "deck_config_root_sha256",
    "event_adapter_sha256",
    "condition_manifest_sha256",
    "metric_extractor_sha256",
    "runner_image_sha256",
    "runner_binary_sha256",
    "schedule_sha256",
    "seed_derivation_sha256",
    "arithmetic_container_sha256",
    "role_registry_sha256",
    "g05_final_authority_envelope_sha256",
}
_EXECUTION_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "manifest_sha256",
        "cell_id",
        "engine",
        "seat",
        "episode_index",
        "seed_hex",
        "seed_commitment_sha256",
        "seed_inventory_payload_sha256",
        "seed_inventory_executor_envelope_sha256",
        "seed_inventory_freeze_envelope_sha256",
        "seed_uniqueness_proof_envelope_sha256",
        "platform_os",
        "platform_arch",
        "runner_image_sha256",
        "runner_image_bytes",
        "runner_binary_sha256",
        "runner_binary_bytes",
        "build_sha256",
        "package_sha256",
        "model_sha256",
        "parser_sha256",
        "container_sha256",
        "argv",
        "env",
        "input_root",
        "workspace_root",
        "output_root",
        "input_fixture",
        "input_inventory_root_sha256",
        "workspace_pre_inventory_root_sha256",
        "workspace_pre_inventory",
        "isolated_execution",
        "network_disabled",
        "input_root_read_only",
        "workspace_created_for_slot",
        "working_tree_clean",
        "started_at_utc",
        "ended_at_utc",
        "attempt_index",
        "retry_count",
        "replacement_count",
        "intervention_count",
        "rng_state_injection_count",
        "forced_state_count",
        "restore_count",
        "carryover_count",
        "exit_code",
        "status",
        "stdout",
        "stderr",
        "raw_trace",
        "emitted_canonical_primitive_trace",
        "post_run_inventory_root_sha256",
        "post_run_inventory",
    }
)
_TRACE_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "manifest_sha256",
        "cell_id",
        "engine",
        "seat",
        "episode_index",
        "seed_commitment_sha256",
        "execution_envelope_sha256",
        "execution_envelope_decoded_length",
        "execution_payload_sha256",
        "execution_payload_decoded_length",
        "raw_trace_sha256",
        "raw_trace_decoded_length",
        "raw_trace_media_type",
        "parser_sha256",
        "container_sha256",
        "independent_canonical_primitive_trace",
        "attested_at_utc",
    }
)
_RAW_TRACE_FIELDS = frozenset(
    {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "manifest_sha256",
        "cell_id",
        "engine",
        "seat",
        "episode_index",
        "seed_commitment_sha256",
        "trace_status",
        "primitive_events",
        "prefix_boundary",
        "natural_start_evidence",
    }
)

if tuple(G02_EVENT_FIELD_SETS) != EVENT_METRICS:
    raise RuntimeError("G04 primitive inventory diverges from the frozen G02 vocabulary")


class CrossEngineValidationError(ValueError):
    """A purported G04 artifact does not meet the frozen contract."""


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CrossEngineValidationError(f"{label}_must_be_lowercase_sha256")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise CrossEngineValidationError(f"{label}_must_be_nonempty_trimmed_string")
    return value


def _exact(value: object, fields: set[str] | frozenset[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != set(fields):
        raise CrossEngineValidationError(f"{label}_fields_must_exactly_match_frozen_schema")
    return value


def _nonnegative_int(value: object, label: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise CrossEngineValidationError(f"{label}_must_be_a_bounded_nonnegative_integer")
    return value


def _positive_int(value: object, label: str, maximum: int | None = None) -> int:
    result = _nonnegative_int(value, label, maximum)
    if result == 0:
        raise CrossEngineValidationError(f"{label}_must_be_positive")
    return result


def _no_floats(value: object, path: str = "$") -> None:
    if type(value) is float:
        raise CrossEngineValidationError(f"float_or_rounding_ambiguity_at_{path}")
    if isinstance(value, Mapping):
        for key, item in value.items():
            _no_floats(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            _no_floats(item, f"{path}[{index}]")


def _content_hash(value: Mapping[str, Any], label: str) -> None:
    supplied = _sha(value.get("content_sha256"), f"{label}.content_sha256")
    actual = canonical_sha256(
        {key: item for key, item in value.items() if key != "content_sha256"}
    )
    if supplied != actual:
        raise CrossEngineValidationError(f"{label}_content_sha256_mismatch")


def _utc(value: object, label: str) -> int:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise CrossEngineValidationError(f"{label}_must_be_canonical_whole_second_utc")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CrossEngineValidationError(f"{label}_must_be_a_real_utc_timestamp") from exc
    return int(parsed.timestamp())


@lru_cache(maxsize=64)
def _validated_ed25519_key_id(public_key: bytes) -> str:
    return validate_ed25519_public_key(public_key)


def _strict_ed25519_key_id(public_key: bytes, label: str) -> str:
    try:
        return _validated_ed25519_key_id(public_key)
    except ExactGateV2Error as exc:
        raise CrossEngineValidationError(
            f"{label}_strict_ed25519_public_key_invalid:{exc}"
        ) from exc


def _role_key(role: str) -> bytes:
    registry = PINNED_ROLE_PUBLIC_KEYS
    if type(registry) is not dict or set(registry) != _ROLE_NAMES:
        raise CrossEngineValidationError("implementation_pinned_role_registry_is_invalid")
    keys = list(registry.values())
    if any(type(key) is not bytes or len(key) != 32 for key in keys) or len(set(keys)) != len(keys):
        raise CrossEngineValidationError("implementation_pinned_role_registry_is_invalid")
    key = registry[role]
    _strict_ed25519_key_id(key, f"pinned_role.{role}")
    return key


def _role_registry_sha256() -> str:
    return canonical_sha256(
        {role: _role_key(role).hex() for role in sorted(_ROLE_NAMES)}
    )


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CrossEngineValidationError("canonical_json_contains_duplicate_key")
        value[key] = item
    return value


def _forbidden_json_number(_value: str) -> Any:
    raise CrossEngineValidationError("canonical_json_floats_or_nonfinite_numbers_forbidden")


def _strict_canonical_json(raw: bytes, label: str) -> Any:
    if type(raw) is not bytes:
        raise CrossEngineValidationError(f"{label}_must_be_exact_bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_rejecting_object,
            parse_int=int,
            parse_float=_forbidden_json_number,
            parse_constant=_forbidden_json_number,
        )
    except CrossEngineValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CrossEngineValidationError(f"{label}_must_be_strict_utf8_json") from exc
    _no_floats(value)
    try:
        recoded = canonical_json_bytes(value)
    except CanonicalJSONError as exc:
        raise CrossEngineValidationError(f"{label}_must_be_canonical_json") from exc
    if recoded != raw:
        raise CrossEngineValidationError(f"{label}_bytes_must_be_canonical_json")
    return value


def _encode_byte_evidence(raw: bytes, media_type: str) -> dict[str, object]:
    """Create the exact-byte wrapper used by G04 fixtures and external producers."""

    if type(raw) is not bytes:
        raise CrossEngineValidationError("byte_evidence_must_be_bytes")
    if type(media_type) is not str or _MEDIA_TYPE.fullmatch(media_type) is None:
        raise CrossEngineValidationError("byte_evidence_media_type_is_invalid")
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def _decode_byte_evidence(
    value: object,
    *,
    label: str,
    expected_media_type: str | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    wrapper = _exact(value, _BYTE_WRAPPER_FIELDS, label)
    encoded = wrapper["base64"]
    if type(encoded) is not str:
        raise CrossEngineValidationError(f"{label}_base64_must_be_a_string")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CrossEngineValidationError(f"{label}_base64_is_invalid") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise CrossEngineValidationError(f"{label}_base64_is_not_canonical")
    length = wrapper["decoded_length"]
    if type(length) is not int or length < 0 or length != len(raw):
        raise CrossEngineValidationError(f"{label}_decoded_length_mismatch")
    digest = _sha(wrapper["sha256"], f"{label}.sha256")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise CrossEngineValidationError(f"{label}_sha256_mismatch")
    media_type = wrapper["media_type"]
    if type(media_type) is not str or _MEDIA_TYPE.fullmatch(media_type) is None:
        raise CrossEngineValidationError(f"{label}_media_type_is_invalid")
    if expected_media_type is not None and media_type != expected_media_type:
        raise CrossEngineValidationError(f"{label}_media_type_mismatch")
    if expected_sha256 is not None and digest != _sha(expected_sha256, f"{label}.expected_sha256"):
        raise CrossEngineValidationError(f"{label}_does_not_match_frozen_sha256")
    return raw


def _signer_key_id(public_key: bytes) -> str:
    return _strict_ed25519_key_id(public_key, "signed_envelope.signer")


def _strict_signature_bytes(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise CrossEngineValidationError(f"{label}_signature_must_be_base64")
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CrossEngineValidationError(f"{label}_signature_must_be_base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != value:
        raise CrossEngineValidationError(f"{label}_signature_must_encode_64_bytes")
    try:
        validate_ed25519_signature_encoding(signature)
    except ExactGateV2Error as exc:
        raise CrossEngineValidationError(
            f"{label}_strict_ed25519_signature_invalid:{exc}"
        ) from exc
    return signature


def _exact_signature_message(domain: bytes, payload_wrapper: object) -> bytes:
    wrapper = _exact(payload_wrapper, _BYTE_WRAPPER_FIELDS, "signed_payload")
    _decode_byte_evidence(wrapper, label="signed_payload")
    encoded_wrapper = canonical_json_bytes(dict(wrapper))
    return domain + len(encoded_wrapper).to_bytes(8, "big") + encoded_wrapper


def _verify_exact_signed_envelope(
    value: object,
    *,
    expected_envelope_schema: str,
    expected_envelope_media_type: str,
    expected_payload_media_type: str,
    role: str,
    domain: bytes,
    label: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    envelope_raw = _decode_byte_evidence(
        value,
        label=f"{label}.envelope_bytes",
        expected_media_type=expected_envelope_media_type,
    )
    envelope = _exact(
        _strict_canonical_json(envelope_raw, f"{label}.envelope"),
        _SIGNED_ENVELOPE_FIELDS,
        f"{label}.envelope",
    )
    if envelope["schema"] != expected_envelope_schema:
        raise CrossEngineValidationError(f"{label}_envelope_schema_mismatch")
    public_key = _role_key(role)
    if envelope["signer_key_id"] != _signer_key_id(public_key):
        raise CrossEngineValidationError(f"{label}_signer_key_id_mismatch")
    payload_raw = _decode_byte_evidence(
        envelope["payload"],
        label=f"{label}.payload_bytes",
        expected_media_type=expected_payload_media_type,
    )
    signature = _strict_signature_bytes(
        envelope["signature_ed25519_base64"], label
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            _exact_signature_message(domain, envelope["payload"]),
        )
    except (InvalidSignature, ValueError) as exc:
        raise CrossEngineValidationError(f"{label}_signature_invalid") from exc
    payload = _strict_canonical_json(payload_raw, f"{label}.payload")
    if type(payload) is not dict:
        raise CrossEngineValidationError(f"{label}_payload_must_be_an_object")
    return dict(payload), payload_raw, envelope_raw


def _verify_envelope(value: object, schema: str, role: str, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CrossEngineValidationError(f"{label}_signature_invalid:envelope_not_an_object")
    _strict_signature_bytes(value.get("signature_ed25519_base64"), label)
    try:
        return verify_envelope(
            value,
            expected_artifact_schema=schema,
            pinned_public_key_bytes=_role_key(role),
        )
    except EnvelopeError as exc:
        raise CrossEngineValidationError(f"{label}_signature_invalid:{exc}") from exc


def _merkle_root(values: Sequence[object]) -> str:
    """Return an ordered, domain-separated binary Merkle root."""

    if not values:
        return hashlib.sha256(b"\x02").hexdigest()
    level = [
        hashlib.sha256(b"\x00" + bytes.fromhex(canonical_sha256(value))).digest()
        for value in values
    ]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(b"\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def _root(rows: list[dict[str, str]]) -> str:
    """Canonical root for a small, named catalog of already rooted objects."""

    return canonical_sha256(sorted(rows, key=lambda row: row["cell_id"]))


def _cell_id(canary_id: str, opponent_id: str, seat: str) -> str:
    return f"{canary_id}|{opponent_id}|{seat}"


def _manifest_cell_ids(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            _cell_id(canary["canary_id"], opponent["opponent_id"], seat)
            for canary in manifest["canaries"]
            for opponent in manifest["opponents"]
            for seat in SEATS
        )
    )


def _validate_manifest(value: object) -> dict[str, Any]:
    raw = _exact(value, {"schema", "canaries", "opponents", "seats", "prefix"}, "manifest")
    if raw["schema"] != MANIFEST_SCHEMA:
        raise CrossEngineValidationError("manifest_schema_mismatch")
    if raw["prefix"] != PREFIX:
        raise CrossEngineValidationError("prefix_must_match_the_frozen_fourth_turn_boundary")
    if type(raw["seats"]) is not list or tuple(raw["seats"]) != SEATS:
        raise CrossEngineValidationError("manifest_seats_must_match_the_frozen_schedule")

    def people(rows: object, kind: str, count: int) -> list[dict[str, str]]:
        if type(rows) is not list or len(rows) != count:
            raise CrossEngineValidationError(f"manifest_must_contain_exactly_{count}_{kind}s")
        normalized: list[dict[str, str]] = []
        seen: set[str] = set()
        fields = {f"{kind}_id", "archive_sha256"}
        for index, value in enumerate(rows):
            row = _exact(value, fields, f"manifest.{kind}[{index}]")
            ident = _identifier(row[f"{kind}_id"], f"manifest.{kind}[{index}].id")
            if ident in seen or "|" in ident:
                raise CrossEngineValidationError(f"duplicate_or_ambiguous_{kind}_id")
            seen.add(ident)
            normalized.append(
                {
                    f"{kind}_id": ident,
                    "archive_sha256": _sha(
                        row["archive_sha256"], f"manifest.{kind}[{index}].archive"
                    ),
                }
            )
        ordered = sorted(normalized, key=lambda row: row[f"{kind}_id"])
        if normalized != ordered:
            raise CrossEngineValidationError(f"manifest_{kind}s_must_be_canonically_ordered")
        return normalized

    return {
        "schema": MANIFEST_SCHEMA,
        "canaries": people(raw["canaries"], "canary", CANARY_COUNT),
        "opponents": people(raw["opponents"], "opponent", OPPONENT_COUNT),
        "seats": list(SEATS),
        "prefix": dict(PREFIX),
    }


def _derive_seed_hex(
    seed_root_hex: str,
    campaign_root: str,
    spec_sha256: str,
    engine: str,
    cell_id: str,
    episode_index: int,
) -> str:
    binding = {
        "schema": SEED_DERIVATION_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "engine_domain": engine,
        "cell_id": cell_id,
        "episode_index": episode_index,
    }
    return hashlib.sha256(
        b"EVAL_V5_1_G04_SEED_V2\0"
        + bytes.fromhex(seed_root_hex)
        + canonical_json_bytes(binding)
    ).hexdigest()


def _seed_commitment(
    seed_hex: str,
    campaign_root: str,
    spec_sha256: str,
    engine: str,
    cell_id: str,
    episode_index: int,
) -> str:
    return canonical_sha256(
        {
            "schema": SEED_COMMITMENT_SCHEMA,
            "campaign_root_sha256": campaign_root,
            "spec_sha256": spec_sha256,
            "engine": engine,
            "cell_id": cell_id,
            "episode_index": episode_index,
            "seed_hex": seed_hex,
        }
    )


def _validate_seed_inventory(
    value: object,
    *,
    engine: str,
    campaign_root: str,
    spec_sha256: str,
    cell_ids: tuple[str, ...],
) -> dict[str, Any]:
    raw = _exact(
        value,
        {"executor_envelope", "freeze_countersignature_envelope"},
        f"seed_audit.{engine}_inventory",
    )
    executor_role = f"{engine}_executor"
    payload = _verify_envelope(
        raw["executor_envelope"], SEED_INVENTORY_SCHEMA, executor_role, f"{engine}_seed_inventory"
    )
    fields = {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "engine",
        "created_at_utc",
        "seed_derivation_schema",
        "seed_root_hex",
        "cell_count",
        "episodes_per_cell",
        "row_count",
        "rows",
        "stream_roots",
        "inventory_merkle_root_sha256",
    }
    payload = dict(_exact(payload, fields, f"{engine}_seed_inventory.payload"))
    if payload["schema"] != SEED_INVENTORY_SCHEMA:
        raise CrossEngineValidationError("seed_inventory_payload_schema_mismatch")
    if (
        payload["campaign_root_sha256"] != campaign_root
        or payload["spec_sha256"] != spec_sha256
        or payload["engine"] != engine
        or payload["seed_derivation_schema"] != SEED_DERIVATION_SCHEMA
    ):
        raise CrossEngineValidationError("seed_inventory_campaign_spec_or_engine_binding_mismatch")
    created_at = _utc(payload["created_at_utc"], f"{engine}_seed_inventory.created_at_utc")
    seed_root = _sha(payload["seed_root_hex"], f"{engine}_seed_inventory.seed_root_hex")
    expected_rows = CELL_COUNT * EPISODES_PER_CELL
    if (
        payload["cell_count"] != CELL_COUNT
        or payload["episodes_per_cell"] != EPISODES_PER_CELL
        or payload["row_count"] != expected_rows
    ):
        raise CrossEngineValidationError("seed_inventory_must_have_exactly_6250_rows_per_cell")
    rows = payload["rows"]
    if type(rows) is not list or len(rows) != expected_rows:
        raise CrossEngineValidationError("seed_inventory_row_count_mismatch")

    index: dict[tuple[str, int], dict[str, Any]] = {}
    all_seeds: set[str] = set()
    offset = 0
    for cell_id in cell_ids:
        stream_rows: list[Mapping[str, Any]] = []
        for episode_index in range(EPISODES_PER_CELL):
            row = _exact(
                rows[offset],
                {"cell_id", "episode_index", "seed_hex", "seed_commitment_sha256"},
                f"{engine}_seed_inventory.rows[{offset}]",
            )
            if row["cell_id"] != cell_id or row["episode_index"] != episode_index:
                raise CrossEngineValidationError("seed_inventory_slots_must_be_exact_and_canonically_ordered")
            seed_hex = _sha(row["seed_hex"], f"{engine}_seed_inventory.rows[{offset}].seed_hex")
            expected_seed = _derive_seed_hex(
                seed_root, campaign_root, spec_sha256, engine, cell_id, episode_index
            )
            if seed_hex != expected_seed:
                raise CrossEngineValidationError("seed_inventory_seed_derivation_mismatch")
            commitment = _sha(
                row["seed_commitment_sha256"],
                f"{engine}_seed_inventory.rows[{offset}].seed_commitment_sha256",
            )
            if commitment != _seed_commitment(
                seed_hex, campaign_root, spec_sha256, engine, cell_id, episode_index
            ):
                raise CrossEngineValidationError("seed_inventory_commitment_mismatch")
            if seed_hex in all_seeds:
                raise CrossEngineValidationError("seed_inventory_contains_duplicate_seed_bytes")
            all_seeds.add(seed_hex)
            normalized = dict(row)
            index[(cell_id, episode_index)] = normalized
            stream_rows.append(normalized)
            offset += 1

        stream_index = cell_ids.index(cell_id)
        stream_roots = payload["stream_roots"]
        if type(stream_roots) is not list or len(stream_roots) != CELL_COUNT:
            raise CrossEngineValidationError("seed_inventory_stream_root_inventory_mismatch")
        stream = _exact(
            stream_roots[stream_index],
            {"cell_id", "seed_count", "seed_merkle_root_sha256"},
            f"{engine}_seed_inventory.stream_roots[{stream_index}]",
        )
        if stream != {
            "cell_id": cell_id,
            "seed_count": EPISODES_PER_CELL,
            "seed_merkle_root_sha256": _merkle_root(stream_rows),
        }:
            raise CrossEngineValidationError("seed_inventory_stream_merkle_root_mismatch")

    inventory_root = _merkle_root(rows)
    if payload["inventory_merkle_root_sha256"] != inventory_root:
        raise CrossEngineValidationError("seed_inventory_merkle_root_mismatch")

    freeze = _verify_envelope(
        raw["freeze_countersignature_envelope"],
        SEED_INVENTORY_FREEZE_SCHEMA,
        "trace_attestor",
        f"{engine}_seed_inventory_freeze",
    )
    freeze_fields = {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "engine",
        "executor_envelope_sha256",
        "inventory_payload_sha256",
        "inventory_merkle_root_sha256",
        "row_count",
        "frozen_at_utc",
    }
    freeze = dict(_exact(freeze, freeze_fields, f"{engine}_seed_inventory_freeze.payload"))
    expected_freeze = {
        "schema": SEED_INVENTORY_FREEZE_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "engine": engine,
        "executor_envelope_sha256": canonical_sha256(raw["executor_envelope"]),
        "inventory_payload_sha256": canonical_sha256(payload),
        "inventory_merkle_root_sha256": inventory_root,
        "row_count": expected_rows,
        "frozen_at_utc": freeze["frozen_at_utc"],
    }
    if freeze != expected_freeze:
        raise CrossEngineValidationError("seed_inventory_freeze_binding_mismatch")
    frozen_at = _utc(freeze["frozen_at_utc"], f"{engine}_seed_inventory_freeze.frozen_at_utc")
    if frozen_at < created_at:
        raise CrossEngineValidationError("seed_inventory_freeze_precedes_inventory_creation")
    return {
        "raw": dict(raw),
        "payload": payload,
        "index": index,
        "seeds": all_seeds,
        "created_at": created_at,
        "frozen_at": frozen_at,
        "freeze_payload": freeze,
    }


def _validate_seed_audit(
    value: object,
    *,
    manifest: Mapping[str, Any],
    campaign_root: str,
    spec_sha256: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], int]:
    raw = _exact(
        value,
        {
            "schema",
            "campaign_root_sha256",
            "spec_sha256",
            "source_inventory",
            "wrapper_inventory",
            "uniqueness_proof_envelope",
            "content_sha256",
        },
        "seed_audit",
    )
    _content_hash(raw, "seed_audit")
    if raw["schema"] != SEED_AUDIT_SCHEMA:
        raise CrossEngineValidationError("seed_audit_schema_mismatch")
    if raw["campaign_root_sha256"] != campaign_root or raw["spec_sha256"] != spec_sha256:
        raise CrossEngineValidationError("seed_audit_campaign_or_spec_binding_mismatch")
    cell_ids = _manifest_cell_ids(manifest)
    inventories = {
        engine: _validate_seed_inventory(
            raw[f"{engine}_inventory"],
            engine=engine,
            campaign_root=campaign_root,
            spec_sha256=spec_sha256,
            cell_ids=cell_ids,
        )
        for engine in ENGINES
    }
    source = inventories["source"]
    wrapper = inventories["wrapper"]
    if source["payload"]["seed_root_hex"] == wrapper["payload"]["seed_root_hex"]:
        raise CrossEngineValidationError("source_and_wrapper_seed_roots_must_be_independent")
    overlap = source["seeds"] & wrapper["seeds"]
    if overlap:
        raise CrossEngineValidationError("source_and_wrapper_seed_streams_must_be_disjoint")

    proof = _verify_envelope(
        raw["uniqueness_proof_envelope"],
        SEED_UNIQUENESS_SCHEMA,
        "validator",
        "seed_uniqueness_proof",
    )
    proof_fields = {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "source_inventory_envelope_sha256",
        "source_freeze_envelope_sha256",
        "wrapper_inventory_envelope_sha256",
        "wrapper_freeze_envelope_sha256",
        "source_inventory_merkle_root_sha256",
        "wrapper_inventory_merkle_root_sha256",
        "row_count_per_engine",
        "total_row_count",
        "duplicate_seed_count",
        "cross_engine_overlap_count",
        "all_streams_pairwise_disjoint",
        "verified_at_utc",
    }
    proof = dict(_exact(proof, proof_fields, "seed_uniqueness_proof.payload"))
    expected_count = CELL_COUNT * EPISODES_PER_CELL
    expected_proof = {
        "schema": SEED_UNIQUENESS_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "source_inventory_envelope_sha256": canonical_sha256(
            raw["source_inventory"]["executor_envelope"]
        ),
        "source_freeze_envelope_sha256": canonical_sha256(
            raw["source_inventory"]["freeze_countersignature_envelope"]
        ),
        "wrapper_inventory_envelope_sha256": canonical_sha256(
            raw["wrapper_inventory"]["executor_envelope"]
        ),
        "wrapper_freeze_envelope_sha256": canonical_sha256(
            raw["wrapper_inventory"]["freeze_countersignature_envelope"]
        ),
        "source_inventory_merkle_root_sha256": source["payload"][
            "inventory_merkle_root_sha256"
        ],
        "wrapper_inventory_merkle_root_sha256": wrapper["payload"][
            "inventory_merkle_root_sha256"
        ],
        "row_count_per_engine": expected_count,
        "total_row_count": 2 * expected_count,
        "duplicate_seed_count": 0,
        "cross_engine_overlap_count": 0,
        "all_streams_pairwise_disjoint": True,
        "verified_at_utc": proof["verified_at_utc"],
    }
    if proof != expected_proof:
        raise CrossEngineValidationError("seed_uniqueness_proof_binding_or_count_mismatch")
    verified_at = _utc(proof["verified_at_utc"], "seed_uniqueness_proof.verified_at_utc")
    if verified_at < max(source["frozen_at"], wrapper["frozen_at"]):
        raise CrossEngineValidationError("seed_uniqueness_proof_precedes_inventory_freeze")
    uniqueness_envelope_sha256 = canonical_sha256(raw["uniqueness_proof_envelope"])
    for inventory in inventories.values():
        inventory["uniqueness_proof_envelope_sha256"] = uniqueness_envelope_sha256
    return dict(raw), inventories, verified_at


def _execution_argv(engine: str, cell_id: str, episode_index: int) -> list[str]:
    return [
        RUNNER_BINARY_PATH,
        "--engine",
        engine,
        "--cell-id",
        cell_id,
        "--episode-index",
        str(episode_index),
        "--input",
        f"{INPUT_ROOT}/slot.json",
        "--raw-trace-output",
        f"{OUTPUT_ROOT}/raw-trace.json",
        "--canonical-trace-output",
        f"{OUTPUT_ROOT}/canonical-trace.json",
    ]


def _execution_input_bytes(
    *,
    campaign_root: str,
    spec_sha256: str,
    manifest_sha256: str,
    cell_id: str,
    engine: str,
    seat: str,
    episode_index: int,
    seed_hex: str,
    seed_commitment_sha256: str,
    artifacts: Mapping[str, str],
) -> bytes:
    return canonical_json_bytes(
        {
            "schema": EXECUTION_INPUT_SCHEMA,
            "campaign_root_sha256": campaign_root,
            "spec_sha256": spec_sha256,
            "manifest_sha256": manifest_sha256,
            "cell_id": cell_id,
            "engine": engine,
            "seat": seat,
            "episode_index": episode_index,
            "seed_hex": seed_hex,
            "seed_commitment_sha256": seed_commitment_sha256,
            "prefix": PREFIX,
            "build_sha256": artifacts[f"{engine}_build_sha256"],
            "package_sha256": artifacts[f"{engine}_package_sha256"],
            "model_sha256": artifacts[f"{engine}_model_sha256"],
            "parser_sha256": artifacts["trace_parser_sha256"],
            "container_sha256": artifacts[f"{engine}_container_sha256"],
            "runner_image_sha256": artifacts["runner_image_sha256"],
            "runner_binary_sha256": artifacts["runner_binary_sha256"],
        }
    )


def _execution_input_inventory_root(payload: Mapping[str, Any]) -> str:
    fixture = _exact(payload["input_fixture"], _BYTE_WRAPPER_FIELDS, "input_fixture")
    return canonical_sha256(
        {
            "schema": "evaluation_v5_1_g04_input_inventory_root_v1",
            "platform": {"os": payload["platform_os"], "arch": payload["platform_arch"]},
            "input_root": payload["input_root"],
            "workspace_root": payload["workspace_root"],
            "output_root": payload["output_root"],
            "argv": payload["argv"],
            "env": payload["env"],
            "input_fixture": dict(fixture),
            "runner_image_sha256": payload["runner_image_sha256"],
            "runner_binary_sha256": payload["runner_binary_sha256"],
            "build_sha256": payload["build_sha256"],
            "package_sha256": payload["package_sha256"],
            "model_sha256": payload["model_sha256"],
            "parser_sha256": payload["parser_sha256"],
            "container_sha256": payload["container_sha256"],
        }
    )


def _workspace_pre_inventory_bytes(input_inventory_root: str) -> bytes:
    return canonical_json_bytes(
        {
            "schema": WORKSPACE_PRE_INVENTORY_SCHEMA,
            "input_inventory_root_sha256": input_inventory_root,
            "input_root": INPUT_ROOT,
            "workspace_root": WORKSPACE_ROOT,
            "output_root": OUTPUT_ROOT,
            "input_root_read_only": True,
            "workspace_created_for_slot": True,
            "workspace_entries": [],
            "output_entries": [],
            "modified_input_paths": [],
            "unexpected_paths": [],
        }
    )


def _expected_execution_stdout_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schema": RUN_RESULT_SCHEMA,
            "campaign_root_sha256": payload["campaign_root_sha256"],
            "spec_sha256": payload["spec_sha256"],
            "cell_id": payload["cell_id"],
            "engine": payload["engine"],
            "episode_index": payload["episode_index"],
            "status": "SUCCEEDED",
            "raw_trace_sha256": payload["raw_trace"]["sha256"],
            "raw_trace_decoded_length": payload["raw_trace"]["decoded_length"],
            "canonical_trace_sha256": payload["emitted_canonical_primitive_trace"][
                "sha256"
            ],
            "canonical_trace_decoded_length": payload[
                "emitted_canonical_primitive_trace"
            ]["decoded_length"],
        }
    )


def _post_run_inventory_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "schema": POST_RUN_INVENTORY_SCHEMA,
            "input_inventory_root_sha256": payload["input_inventory_root_sha256"],
            "workspace_pre_inventory_root_sha256": payload[
                "workspace_pre_inventory_root_sha256"
            ],
            "input_root_unchanged": True,
            "workspace_clean": True,
            "created_outputs": [
                {
                    "path": "canonical-trace.json",
                    "sha256": payload["emitted_canonical_primitive_trace"]["sha256"],
                    "decoded_length": payload["emitted_canonical_primitive_trace"][
                        "decoded_length"
                    ],
                },
                {
                    "path": "raw-trace.json",
                    "sha256": payload["raw_trace"]["sha256"],
                    "decoded_length": payload["raw_trace"]["decoded_length"],
                },
                {
                    "path": "stderr.txt",
                    "sha256": payload["stderr"]["sha256"],
                    "decoded_length": payload["stderr"]["decoded_length"],
                },
                {
                    "path": "stdout.json",
                    "sha256": payload["stdout"]["sha256"],
                    "decoded_length": payload["stdout"]["decoded_length"],
                },
            ],
            "modified_input_paths": [],
            "modified_workspace_paths": [],
            "deleted_paths": [],
            "unexpected_paths": [],
        }
    )


def _raw_trace_bytes(
    *,
    campaign_root: str,
    spec_sha256: str,
    manifest_sha256: str,
    cell_id: str,
    engine: str,
    seat: str,
    episode_index: int,
    seed_commitment_sha256: str,
    trace_status: str,
    primitive_events: Sequence[Mapping[str, Any]],
    prefix_boundary: Mapping[str, Any],
    natural_start_evidence: Mapping[str, Any] | None,
) -> bytes:
    return canonical_json_bytes(
        {
            "schema": RAW_TRACE_SCHEMA,
            "campaign_root_sha256": campaign_root,
            "spec_sha256": spec_sha256,
            "manifest_sha256": manifest_sha256,
            "cell_id": cell_id,
            "engine": engine,
            "seat": seat,
            "episode_index": episode_index,
            "seed_commitment_sha256": seed_commitment_sha256,
            "trace_status": trace_status,
            "primitive_events": list(primitive_events),
            "prefix_boundary": dict(prefix_boundary),
            "natural_start_evidence": natural_start_evidence,
        }
    )


def _canonical_primitive_trace_bytes(
    *,
    raw_trace_sha256: str,
    raw_trace_decoded_length: int,
    parser_sha256: str,
    raw_trace: Mapping[str, Any],
    metrics: Mapping[str, Any],
) -> bytes:
    return canonical_json_bytes(
        {
            "schema": CANONICAL_TRACE_SCHEMA,
            "campaign_root_sha256": raw_trace["campaign_root_sha256"],
            "spec_sha256": raw_trace["spec_sha256"],
            "manifest_sha256": raw_trace["manifest_sha256"],
            "cell_id": raw_trace["cell_id"],
            "engine": raw_trace["engine"],
            "seat": raw_trace["seat"],
            "episode_index": raw_trace["episode_index"],
            "seed_commitment_sha256": raw_trace["seed_commitment_sha256"],
            "raw_trace_sha256": raw_trace_sha256,
            "raw_trace_decoded_length": raw_trace_decoded_length,
            "parser_sha256": parser_sha256,
            "trace_status": raw_trace["trace_status"],
            "primitive_events": metrics["normalized_events"],
            "prefix_boundary": metrics["normalized_boundary"],
            "natural_start_evidence": metrics["normalized_natural_start_evidence"],
        }
    )


def _nullable_identifier(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, label)


def _event_identifier(value: object, label: str) -> str:
    if type(value) is not str or _EVENT_IDENTIFIER.fullmatch(value) is None:
        raise CrossEngineValidationError(f"{label}_must_match_the_frozen_g02_identifier_grammar")
    return value


def _natural_start_invalid(value: object, label: str) -> bool:
    fields = {
        "reset_path",
        "expected_actor_seat",
        "observed_actor_seat",
        "first_observation_legal",
        "prior_state_cleared",
        "initialization_succeeded",
        "transition_before_first_legitimate_action",
    }
    start = _exact(value, fields, label)
    if start["reset_path"] != "ordinary_new_game" or start["expected_actor_seat"] != 0:
        raise CrossEngineValidationError("natural_start_must_use_the_ordinary_protocol_path")
    observed = start["observed_actor_seat"]
    if observed is not None and (type(observed) is not int or observed not in _ACTOR_SEATS):
        raise CrossEngineValidationError("natural_start_observed_actor_seat_is_invalid")
    for field in (
        "first_observation_legal",
        "prior_state_cleared",
        "initialization_succeeded",
        "transition_before_first_legitimate_action",
    ):
        if type(start[field]) is not bool:
            raise CrossEngineValidationError("natural_start_observations_must_be_binary")
    return bool(
        observed != start["expected_actor_seat"]
        or not start["first_observation_legal"]
        or not start["prior_state_cleared"]
        or not start["initialization_succeeded"]
        or start["transition_before_first_legitimate_action"]
    )


def _normalize_events(
    value: object,
    *,
    seat: str,
    label: str,
) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise CrossEngineValidationError(f"{label}_must_be_an_ordered_event_list")
    normalized: list[dict[str, Any]] = []
    previous_id = -1
    canary_seat = 0 if seat == "canary_first" else 1
    requested: dict[str, int] = {}
    chosen_requests: set[tuple[int, str]] = set()
    declared_attacks: dict[str, int] = {}
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise CrossEngineValidationError("primitive_event_must_be_a_plain_object")
        event_type = item.get("event_type")
        if event_type not in G02_EVENT_FIELD_SETS:
            raise CrossEngineValidationError("unknown_primitive_event_type")
        event = _exact(
            item,
            set(G02_EVENT_FIELD_SETS[event_type]),
            f"{label}[{index}]",
        )
        event_id = _nonnegative_int(event["event_id"], f"{label}[{index}].event_id")
        if event_id <= previous_id:
            raise CrossEngineValidationError("primitive_event_ids_must_be_monotonic_and_unique")
        previous_id = event_id

        if event_type in _ACTOR_EVENTS:
            actor_seat = event["actor_seat"]
            is_canary = event["is_canary"]
            if type(actor_seat) is not int or actor_seat not in _ACTOR_SEATS or type(is_canary) is not bool:
                raise CrossEngineValidationError("actor_events_require_actor_seat_and_binary_is_canary")
            if is_canary is not (actor_seat == canary_seat):
                raise CrossEngineValidationError("event_actor_seat_and_is_canary_disagree")

        if event_type in _POKEMON_EVENTS:
            _nonnegative_int(event["pokemon_id"], f"{label}[{index}].pokemon_id")

        if event_type == "ACTION_REQUESTED":
            request_id = _event_identifier(event["request_id"], f"{label}[{index}].request_id")
            if request_id in requested:
                raise CrossEngineValidationError("request_ids_must_be_unique_per_actor")
            requested[request_id] = event["actor_seat"]
        elif event_type == "ACTION_CHOSEN":
            request_id = _event_identifier(event["request_id"], f"{label}[{index}].request_id")
            key = (event["actor_seat"], request_id)
            if requested.get(request_id) != event["actor_seat"] or key in chosen_requests:
                raise CrossEngineValidationError("action_events_must_reference_a_prior_request")
            chosen_requests.add(key)
        elif event_type in _CHOSEN_REQUEST_EVENTS:
            request_id = _event_identifier(event["request_id"], f"{label}[{index}].request_id")
            if (event["actor_seat"], request_id) not in chosen_requests:
                raise CrossEngineValidationError("action_events_must_reference_a_chosen_request")
            if event_type == "ATTACK_DECLARED":
                attack_id = _event_identifier(event["attack_id"], f"{label}[{index}].attack_id")
                if attack_id in declared_attacks:
                    raise CrossEngineValidationError("attack_ids_must_be_unique")
                declared_attacks[attack_id] = event["actor_seat"]
        elif event_type in _ATTACK_CAUSED_EVENTS:
            cause_attack_id = _event_identifier(
                event["cause_attack_id"], f"{label}[{index}].cause_attack_id"
            )
            if declared_attacks.get(cause_attack_id) != event["actor_seat"]:
                raise CrossEngineValidationError("attack_caused_event_must_reference_a_prior_actor_attack")

        if event_type == "DAMAGE_APPLIED":
            _nonnegative_int(event["damage_amount"], f"{label}[{index}].damage_amount")

        if event_type == "GAME_END":
            terminal_identity = event["terminal_identity"]
            outcome = event["outcome"]
            if terminal_identity not in G02_TERMINAL_OUTCOMES:
                raise CrossEngineValidationError("game_end_terminal_identity_is_invalid")
            if outcome != G02_TERMINAL_OUTCOMES[terminal_identity]:
                raise CrossEngineValidationError("game_end_terminal_identity_and_outcome_disagree")
            if outcome not in _OUTCOMES:
                raise CrossEngineValidationError("g04_game_end_must_be_a_clean_outcome_identity")

        normalized.append(dict(event))

    return normalized


def _derive_trace_metrics(
    trace_status: object,
    events_value: object,
    boundary_value: object,
    natural_start_evidence: object,
    *,
    seat: str,
    label: str = "trace",
) -> dict[str, Any]:
    if trace_status not in _TRACE_STATUSES:
        raise CrossEngineValidationError("trace_status_not_in_frozen_inventory")
    boundary_fields = {
        "start_event_id",
        "end_event_id",
        "end_reason",
        "canary_turn_start_event_ids",
        "excluded_next_turn_start_event_id",
    }
    boundary = dict(_exact(boundary_value, boundary_fields, f"{label}.prefix_boundary"))
    events = _normalize_events(events_value, seat=seat, label=f"{label}.events")

    if trace_status != "recorded":
        expected_reason = "MISSING_RECORD" if trace_status == "missing_record" else "HARNESS_CRASH"
        if natural_start_evidence is not None or events or boundary != {
            "start_event_id": None,
            "end_event_id": None,
            "end_reason": expected_reason,
            "canary_turn_start_event_ids": [],
            "excluded_next_turn_start_event_id": None,
        }:
            raise CrossEngineValidationError("missing_or_crashed_trace_must_be_an_exact_signed_tombstone")
        natural_invalid = False
    else:
        natural_invalid = _natural_start_invalid(
            natural_start_evidence, f"{label}.natural_start_evidence"
        )
        if not events or events[0]["event_type"] != "GAME_START":
            raise CrossEngineValidationError("recorded_trace_must_begin_with_exactly_one_game_start")
        if sum(event["event_type"] == "GAME_START" for event in events) != 1:
            raise CrossEngineValidationError("recorded_trace_must_have_exactly_one_game_start")
        if boundary["start_event_id"] != events[0]["event_id"] or boundary["end_event_id"] != events[-1]["event_id"]:
            raise CrossEngineValidationError("prefix_boundary_event_ids_do_not_bind_the_ordered_trace")
        canary_turn_ids = [
            event["event_id"]
            for event in events
            if event["event_type"] == "TURN_START" and event["is_canary"] is True
        ]
        if boundary["canary_turn_start_event_ids"] != canary_turn_ids or len(canary_turn_ids) > 4:
            raise CrossEngineValidationError("prefix_boundary_canary_turn_markers_are_invalid")
        terminal_positions = [
            index for index, event in enumerate(events) if event["event_type"] in _TERMINAL_EVENTS
        ]
        if terminal_positions and terminal_positions != [len(events) - 1]:
            raise CrossEngineValidationError("terminal_event_must_be_unique_and_end_the_prefix")
        reason = boundary["end_reason"]
        excluded = boundary["excluded_next_turn_start_event_id"]
        if natural_invalid:
            if (
                len(events) != 1
                or events[0]["event_type"] != "GAME_START"
                or terminal_positions
                or reason != "NATURAL_START_INVALID"
                or excluded is not None
            ):
                raise CrossEngineValidationError(
                    "natural_start_invalid_must_be_an_exact_start_tombstone"
                )
        elif events[-1]["event_type"] in _TERMINAL_EVENTS:
            if reason != events[-1]["event_type"] or excluded is not None:
                raise CrossEngineValidationError("terminal_prefix_boundary_marker_mismatch")
        else:
            if reason != PREFIX["end_marker"] or len(canary_turn_ids) != 4:
                raise CrossEngineValidationError("nonterminal_prefix_must_end_at_the_frozen_fourth_turn_boundary")
            if type(excluded) is not int or excluded <= events[-1]["event_id"]:
                raise CrossEngineValidationError("fourth_turn_prefix_requires_the_excluded_next_turn_marker")
        if len(canary_turn_ids) == 4:
            fourth = canary_turn_ids[-1]
            if any(
                event["event_type"] == "TURN_START" and event["event_id"] > fourth
                for event in events
            ):
                raise CrossEngineValidationError("prefix_includes_a_turn_start_after_the_canary_fourth_turn")
        if not natural_invalid:
            turn_starts = [event for event in events if event["event_type"] == "TURN_START"]
            if turn_starts and turn_starts[0]["actor_seat"] != 0:
                raise CrossEngineValidationError("natural_start_first_turn_actor_is_invalid")

    event_counts = {name: 0 for name in EVENT_METRICS}
    for event in events:
        event_counts[event["event_type"]] += 1
    if event_counts["GAME_END"] > 1:
        raise CrossEngineValidationError("duplicate_game_end_event")
    if event_counts["TIMEOUT"] > 1 or event_counts["POLICY_EXCEPTION"] > 1:
        raise CrossEngineValidationError("duplicate_terminal_failure_event")
    if event_counts["TIMEOUT"] and event_counts["POLICY_EXCEPTION"]:
        raise CrossEngineValidationError("timeout_and_policy_exception_are_mutually_exclusive")
    if (event_counts["TIMEOUT"] or event_counts["POLICY_EXCEPTION"]) and event_counts["GAME_END"]:
        raise CrossEngineValidationError("timeout_or_policy_exception_excludes_game_end")

    incidence = {name: int(event_counts[name] > 0) for name in EVENT_METRICS}
    failure = bool(
        trace_status != "recorded"
        or natural_invalid
        or incidence["TIMEOUT"]
        or incidence["POLICY_EXCEPTION"]
    )
    clean = bool(event_counts["GAME_END"] == 1 and not failure)
    outcome = None
    if clean:
        outcome = next(event["outcome"] for event in events if event["event_type"] == "GAME_END")
    canary_acted = any(
        event["event_type"] == "ACTION_CHOSEN" and event["is_canary"] is True
        for event in events
    )
    opponent_acted = any(
        event["event_type"] == "ACTION_CHOSEN" and event["is_canary"] is False
        for event in events
    )
    canary_illegal = any(
        event["event_type"] == "ILLEGAL_ACTION" and event["is_canary"] is True
        for event in events
    )
    opponent_illegal = any(
        event["event_type"] == "ILLEGAL_ACTION" and event["is_canary"] is False
        for event in events
    )
    derived = {
        "clean_terminal": int(clean),
        "decisive_clean_terminal": int(clean and outcome in {"CANARY_WIN", "OPPONENT_WIN"}),
        "canary_acted": int(canary_acted),
        "opponent_acted": int(opponent_acted),
        "canary_win": int(clean and outcome == "CANARY_WIN"),
        "opponent_win": int(clean and outcome == "OPPONENT_WIN"),
        "draw": int(clean and outcome == "DRAW"),
        "any_illegal_action": incidence["ILLEGAL_ACTION"],
        "terminal_failure": int(failure),
        "natural_start_invalid": int(natural_invalid),
    }
    return {
        "event_incidence": incidence,
        "derived": derived,
        "canary_illegal": int(canary_illegal),
        "opponent_illegal": int(opponent_illegal),
        "canary_acted_with_illegal": int(canary_acted and canary_illegal),
        "opponent_acted_with_illegal": int(opponent_acted and opponent_illegal),
        "missing_record": int(trace_status == "missing_record"),
        "harness_crash": int(trace_status == "harness_crash"),
        "prefix_censored": int(not clean and not failure),
        "normalized_events": events,
        "normalized_boundary": boundary,
        "normalized_natural_start_evidence": natural_start_evidence,
    }


def _validate_measurement_leaf(
    value: object,
    *,
    engine: str,
    cell_id: str,
    seat: str,
    episode_index: int,
    campaign_root: str,
    spec_sha256: str,
    manifest_sha256: str,
    artifacts: Mapping[str, str],
    inventory: Mapping[str, Any],
    inventory_verified_at: int,
) -> dict[str, Any]:
    raw = _exact(
        value,
        {"execution_envelope_bytes", "trace_attestation_envelope_bytes"},
        f"{cell_id}.{engine}.measurement_leaves[{episode_index}]",
    )
    label = f"{cell_id}.{engine}.leaf[{episode_index}]"
    payload, execution_payload_raw, execution_envelope_raw = (
        _verify_exact_signed_envelope(
            raw["execution_envelope_bytes"],
            expected_envelope_schema=EXECUTION_ENVELOPE_SCHEMA,
            expected_envelope_media_type=EXECUTION_ENVELOPE_MEDIA_TYPE,
            expected_payload_media_type=EXECUTION_PAYLOAD_MEDIA_TYPE,
            role=f"{engine}_executor",
            domain=EXECUTION_ENVELOPE_DOMAIN,
            label=f"{label}.execution",
        )
    )
    payload = dict(_exact(payload, _EXECUTION_RECEIPT_FIELDS, f"{label}.execution.payload"))
    if payload["schema"] != EXECUTION_RECEIPT_SCHEMA:
        raise CrossEngineValidationError("slot_execution_receipt_schema_mismatch")
    expected_bindings = {
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest_sha256": manifest_sha256,
        "cell_id": cell_id,
        "engine": engine,
        "seat": seat,
        "episode_index": episode_index,
        "seed_hex": inventory["seed_hex"],
        "seed_commitment_sha256": inventory["seed_commitment_sha256"],
        "seed_inventory_payload_sha256": canonical_sha256(
            inventory["inventory_payload"]
        ),
        "seed_inventory_executor_envelope_sha256": canonical_sha256(
            inventory["inventory_record"]["executor_envelope"]
        ),
        "seed_inventory_freeze_envelope_sha256": canonical_sha256(
            inventory["inventory_record"]["freeze_countersignature_envelope"]
        ),
        "seed_uniqueness_proof_envelope_sha256": inventory[
            "uniqueness_proof_envelope_sha256"
        ],
        "build_sha256": artifacts[f"{engine}_build_sha256"],
        "package_sha256": artifacts[f"{engine}_package_sha256"],
        "model_sha256": artifacts[f"{engine}_model_sha256"],
        "parser_sha256": artifacts["trace_parser_sha256"],
        "container_sha256": artifacts[f"{engine}_container_sha256"],
        "runner_image_sha256": artifacts["runner_image_sha256"],
        "runner_binary_sha256": artifacts["runner_binary_sha256"],
    }
    if any(payload[field] != expected for field, expected in expected_bindings.items()):
        raise CrossEngineValidationError("slot_execution_inventory_or_artifact_binding_mismatch")

    if payload["platform_os"] != "linux" or payload["platform_arch"] != "amd64":
        raise CrossEngineValidationError("slot_execution_requires_linux_amd64")
    _decode_byte_evidence(
        payload["runner_image_bytes"],
        label=f"{label}.runner_image",
        expected_media_type="application/octet-stream",
        expected_sha256=artifacts["runner_image_sha256"],
    )
    _decode_byte_evidence(
        payload["runner_binary_bytes"],
        label=f"{label}.runner_binary",
        expected_media_type="application/octet-stream",
        expected_sha256=artifacts["runner_binary_sha256"],
    )
    if payload["argv"] != _execution_argv(engine, cell_id, episode_index):
        raise CrossEngineValidationError("slot_execution_argv_not_in_frozen_allowlist")
    if payload["env"] != RUNNER_ENVIRONMENT:
        raise CrossEngineValidationError("slot_execution_env_not_in_frozen_allowlist")
    if (
        payload["input_root"] != INPUT_ROOT
        or payload["workspace_root"] != WORKSPACE_ROOT
        or payload["output_root"] != OUTPUT_ROOT
    ):
        raise CrossEngineValidationError("slot_execution_root_paths_mismatch")
    expected_input = _execution_input_bytes(
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
        manifest_sha256=manifest_sha256,
        cell_id=cell_id,
        engine=engine,
        seat=seat,
        episode_index=episode_index,
        seed_hex=inventory["seed_hex"],
        seed_commitment_sha256=inventory["seed_commitment_sha256"],
        artifacts=artifacts,
    )
    input_bytes = _decode_byte_evidence(
        payload["input_fixture"],
        label=f"{label}.input_fixture",
        expected_media_type="application/json",
    )
    _strict_canonical_json(input_bytes, f"{label}.input_fixture")
    if input_bytes != expected_input:
        raise CrossEngineValidationError("slot_execution_input_fixture_mismatch")
    input_inventory_root = _execution_input_inventory_root(payload)
    if payload["input_inventory_root_sha256"] != input_inventory_root:
        raise CrossEngineValidationError("slot_execution_input_inventory_root_mismatch")
    expected_pre_inventory = _workspace_pre_inventory_bytes(input_inventory_root)
    pre_inventory = _decode_byte_evidence(
        payload["workspace_pre_inventory"],
        label=f"{label}.workspace_pre_inventory",
        expected_media_type="application/json",
    )
    _strict_canonical_json(pre_inventory, f"{label}.workspace_pre_inventory")
    if (
        pre_inventory != expected_pre_inventory
        or payload["workspace_pre_inventory_root_sha256"]
        != hashlib.sha256(expected_pre_inventory).hexdigest()
    ):
        raise CrossEngineValidationError("slot_execution_workspace_pre_inventory_mismatch")
    required_true = (
        "isolated_execution",
        "network_disabled",
        "input_root_read_only",
        "workspace_created_for_slot",
        "working_tree_clean",
    )
    if any(payload[field] is not True for field in required_true):
        raise CrossEngineValidationError("slot_execution_isolation_or_cleanliness_violation")
    for field in (
        "attempt_index",
        "retry_count",
        "replacement_count",
        "intervention_count",
        "rng_state_injection_count",
        "forced_state_count",
        "restore_count",
        "carryover_count",
    ):
        if payload[field] != 0:
            raise CrossEngineValidationError(f"slot_execution_{field}_must_equal_zero")

    started_at = _utc(payload["started_at_utc"], f"{label}.started_at_utc")
    ended_at = _utc(payload["ended_at_utc"], f"{label}.ended_at_utc")
    if started_at <= inventory_verified_at or ended_at <= started_at:
        raise CrossEngineValidationError("slot_execution_chronology_or_inventory_freeze_violation")
    if payload["exit_code"] != 0 or payload["status"] != "SUCCEEDED":
        raise CrossEngineValidationError("slot_execution_exit_status_mismatch")

    raw_trace_bytes = _decode_byte_evidence(
        payload["raw_trace"],
        label=f"{label}.raw_trace",
        expected_media_type=RAW_TRACE_MEDIA_TYPE,
    )
    raw_trace = dict(
        _exact(
            _strict_canonical_json(raw_trace_bytes, f"{label}.raw_trace"),
            _RAW_TRACE_FIELDS,
            f"{label}.raw_trace",
        )
    )
    raw_trace_bindings = {
        "schema": RAW_TRACE_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest_sha256": manifest_sha256,
        "cell_id": cell_id,
        "engine": engine,
        "seat": seat,
        "episode_index": episode_index,
        "seed_commitment_sha256": inventory["seed_commitment_sha256"],
    }
    if any(raw_trace[field] != expected for field, expected in raw_trace_bindings.items()):
        raise CrossEngineValidationError("raw_trace_slot_or_seed_binding_mismatch")
    metrics = _derive_trace_metrics(
        raw_trace["trace_status"],
        raw_trace["primitive_events"],
        raw_trace["prefix_boundary"],
        raw_trace["natural_start_evidence"],
        seat=seat,
        label=f"{label}.independent_raw_parse",
    )
    canonical_trace_bytes = _canonical_primitive_trace_bytes(
        raw_trace_sha256=hashlib.sha256(raw_trace_bytes).hexdigest(),
        raw_trace_decoded_length=len(raw_trace_bytes),
        parser_sha256=artifacts["trace_parser_sha256"],
        raw_trace=raw_trace,
        metrics=metrics,
    )
    emitted_canonical_trace = _decode_byte_evidence(
        payload["emitted_canonical_primitive_trace"],
        label=f"{label}.emitted_canonical_primitive_trace",
        expected_media_type=CANONICAL_TRACE_MEDIA_TYPE,
    )
    _strict_canonical_json(
        emitted_canonical_trace, f"{label}.emitted_canonical_primitive_trace"
    )
    if emitted_canonical_trace != canonical_trace_bytes:
        raise CrossEngineValidationError(
            "emitted_canonical_trace_not_recomputed_from_exact_raw_bytes"
        )
    stdout = _decode_byte_evidence(
        payload["stdout"],
        label=f"{label}.stdout",
        expected_media_type="application/json",
    )
    _strict_canonical_json(stdout, f"{label}.stdout")
    if stdout != _expected_execution_stdout_bytes(payload):
        raise CrossEngineValidationError("slot_execution_stdout_mismatch")
    stderr = _decode_byte_evidence(
        payload["stderr"],
        label=f"{label}.stderr",
        expected_media_type="text/plain",
    )
    if stderr != b"":
        raise CrossEngineValidationError("slot_execution_stderr_must_be_empty")
    post_inventory = _decode_byte_evidence(
        payload["post_run_inventory"],
        label=f"{label}.post_run_inventory",
        expected_media_type="application/json",
    )
    _strict_canonical_json(post_inventory, f"{label}.post_run_inventory")
    expected_post_inventory = _post_run_inventory_bytes(payload)
    if (
        post_inventory != expected_post_inventory
        or payload["post_run_inventory_root_sha256"]
        != hashlib.sha256(expected_post_inventory).hexdigest()
    ):
        raise CrossEngineValidationError("slot_execution_post_run_inventory_mismatch")

    attestation, attestation_payload_raw, _attestation_envelope_raw = (
        _verify_exact_signed_envelope(
            raw["trace_attestation_envelope_bytes"],
            expected_envelope_schema=TRACE_ATTESTATION_ENVELOPE_SCHEMA,
            expected_envelope_media_type=TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
            expected_payload_media_type=TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
            role="trace_attestor",
            domain=TRACE_ATTESTATION_ENVELOPE_DOMAIN,
            label=f"{label}.trace_attestation",
        )
    )
    attestation = dict(
        _exact(attestation, _TRACE_ATTESTATION_FIELDS, f"{label}.trace_attestation.payload")
    )
    independently_parsed = _decode_byte_evidence(
        attestation["independent_canonical_primitive_trace"],
        label=f"{label}.trace_attestation.independent_canonical_primitive_trace",
        expected_media_type=CANONICAL_TRACE_MEDIA_TYPE,
    )
    _strict_canonical_json(
        independently_parsed,
        f"{label}.trace_attestation.independent_canonical_primitive_trace",
    )
    if independently_parsed != canonical_trace_bytes:
        raise CrossEngineValidationError(
            "trace_attestor_did_not_independently_parse_exact_raw_bytes"
        )
    expected_attestation = {
        "schema": TRACE_ATTESTATION_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest_sha256": manifest_sha256,
        "cell_id": cell_id,
        "engine": engine,
        "seat": seat,
        "episode_index": episode_index,
        "seed_commitment_sha256": inventory["seed_commitment_sha256"],
        "execution_envelope_sha256": hashlib.sha256(execution_envelope_raw).hexdigest(),
        "execution_envelope_decoded_length": len(execution_envelope_raw),
        "execution_payload_sha256": hashlib.sha256(execution_payload_raw).hexdigest(),
        "execution_payload_decoded_length": len(execution_payload_raw),
        "raw_trace_sha256": hashlib.sha256(raw_trace_bytes).hexdigest(),
        "raw_trace_decoded_length": len(raw_trace_bytes),
        "raw_trace_media_type": RAW_TRACE_MEDIA_TYPE,
        "parser_sha256": artifacts["trace_parser_sha256"],
        "container_sha256": artifacts[f"{engine}_container_sha256"],
        "independent_canonical_primitive_trace": _encode_byte_evidence(
            canonical_trace_bytes, CANONICAL_TRACE_MEDIA_TYPE
        ),
        "attested_at_utc": attestation["attested_at_utc"],
    }
    if attestation != expected_attestation:
        raise CrossEngineValidationError("trace_attestation_exact_execution_binding_mismatch")
    attested_at = _utc(attestation["attested_at_utc"], f"{label}.attested_at_utc")
    if attested_at < ended_at:
        raise CrossEngineValidationError("trace_attestation_precedes_execution_end")
    return {
        "raw": dict(raw),
        "payload": payload,
        "metrics": metrics,
        "started_at": started_at,
        "ended_at": ended_at,
        "attested_at": attested_at,
        "raw_trace_sha256": hashlib.sha256(raw_trace_bytes).hexdigest(),
    }


def _counts(value: object, names: Sequence[str], label: str) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(names):
        raise CrossEngineValidationError(f"{label}_metric_inventory_must_be_exact")
    return {
        name: _nonnegative_int(value[name], f"{label}.{name}", EPISODES_PER_CELL)
        for name in names
    }


def _assert_aggregate_identities(claims: Mapping[str, Any]) -> None:
    event = claims["event_incidence_counts"]
    derived = claims["derived_episode_metric_counts"]
    eligibility = claims["eligibility_counts"]
    conditional = claims["conditional_success_counts"]
    actor_illegal = claims["actor_illegal_action_episode_counts"]
    acted_illegal = claims["actor_acted_with_illegal_action_counts"]
    if derived["canary_win"] + derived["opponent_win"] + derived["draw"] != derived["clean_terminal"]:
        raise CrossEngineValidationError("clean_terminal_outcome_partition_identity_failed")
    if derived["decisive_clean_terminal"] != derived["canary_win"] + derived["opponent_win"]:
        raise CrossEngineValidationError("decisive_clean_terminal_identity_failed")
    if derived["any_illegal_action"] != event["ILLEGAL_ACTION"]:
        raise CrossEngineValidationError("illegal_action_incidence_identity_failed")
    expected_eligibility = {
        metric: derived[denominator]
        for metric, denominator in CONDITIONAL_DENOMINATORS.items()
    }
    if eligibility != expected_eligibility:
        raise CrossEngineValidationError("conditional_eligibility_does_not_bind_derived_denominators")
    expected_conditional = {
        "canary_win_given_decisive_clean_terminal": derived["canary_win"],
        "draw_given_clean_terminal": derived["draw"],
        "all_canary_actions_legal_given_canary_acted": derived["canary_acted"]
        - acted_illegal["canary"],
        "all_opponent_actions_legal_given_opponent_acted": derived["opponent_acted"]
        - acted_illegal["opponent"],
    }
    if conditional != expected_conditional:
        raise CrossEngineValidationError("conditional_success_counts_not_exactly_derived_from_actor_traces")
    if acted_illegal["canary"] > actor_illegal["canary"] or acted_illegal["opponent"] > actor_illegal["opponent"]:
        raise CrossEngineValidationError("actor_illegal_intersection_identity_failed")
    expected_terminal_failures = (
        claims["missing_record_count"]
        + claims["harness_crash_count"]
        + derived["natural_start_invalid"]
        + event["TIMEOUT"]
        + event["POLICY_EXCEPTION"]
    )
    if derived["terminal_failure"] != expected_terminal_failures:
        raise CrossEngineValidationError("terminal_failure_partition_identity_failed")
    if derived["natural_start_invalid"] > derived["terminal_failure"]:
        raise CrossEngineValidationError("natural_start_invalid_must_imply_terminal_failure")
    if derived["clean_terminal"] + derived["terminal_failure"] + claims["prefix_censored_count"] != claims["episode_count"]:
        raise CrossEngineValidationError("clean_failure_censored_partition_identity_failed")
    if derived["clean_terminal"] != event["GAME_END"]:
        raise CrossEngineValidationError("clean_terminal_game_end_identity_failed")


def _validate_engine_receipt(
    value: object,
    *,
    expected_engine: str,
    cell_id: str,
    seat: str,
    campaign_root: str,
    spec_sha256: str,
    manifest_sha256: str,
    artifacts: Mapping[str, str],
    inventory: Mapping[str, Any],
    inventory_verified_at: int,
) -> dict[str, Any]:
    fields = {
        "engine",
        "episode_count",
        "natural_start_count",
        "retry_count",
        "replacement_count",
        "intervention_count",
        "rng_state_injection_count",
        "forced_state_count",
        "restore_count",
        "carryover_count",
        "prefix",
        "seed_inventory_payload_sha256",
        "measurement_leaves",
        "measurement_leaf_count",
        "measurement_leaf_merkle_root_sha256",
        "event_log_merkle_root_sha256",
        "event_incidence_counts",
        "derived_episode_metric_counts",
        "eligibility_counts",
        "conditional_success_counts",
        "actor_illegal_action_episode_counts",
        "actor_acted_with_illegal_action_counts",
        "missing_record_count",
        "harness_crash_count",
        "prefix_censored_count",
    }
    raw = _exact(value, fields, f"{cell_id}.{expected_engine}")
    if raw["engine"] != expected_engine:
        raise CrossEngineValidationError("engine_receipt_wrong_engine")
    if raw["episode_count"] != EPISODES_PER_CELL or raw["natural_start_count"] != EPISODES_PER_CELL:
        raise CrossEngineValidationError("engine_receipt_must_contain_6250_natural_start_episodes")
    for field in (
        "retry_count",
        "replacement_count",
        "intervention_count",
        "rng_state_injection_count",
        "forced_state_count",
        "restore_count",
        "carryover_count",
    ):
        if raw[field] != 0:
            raise CrossEngineValidationError(f"{field}_must_equal_zero")
    if raw["prefix"] != PREFIX:
        raise CrossEngineValidationError("engine_receipt_prefix_mismatch")
    inventory_payload = inventory["payload"]
    if raw["seed_inventory_payload_sha256"] != canonical_sha256(inventory_payload):
        raise CrossEngineValidationError("engine_receipt_not_bound_to_signed_seed_inventory")
    leaves = raw["measurement_leaves"]
    if type(leaves) is not list or len(leaves) != EPISODES_PER_CELL:
        raise CrossEngineValidationError("engine_receipt_requires_one_authenticated_leaf_per_inventory_slot")

    event_counts = {name: 0 for name in EVENT_METRICS}
    derived_counts = {name: 0 for name in DERIVED_EPISODE_METRICS}
    actor_illegal = {"canary": 0, "opponent": 0}
    acted_illegal = {"canary": 0, "opponent": 0}
    missing = harness = censored = 0
    validated_leaves: list[dict[str, Any]] = []
    trace_rows: list[dict[str, Any]] = []
    for episode_index, leaf in enumerate(leaves):
        row = inventory["index"][(cell_id, episode_index)]
        checked = _validate_measurement_leaf(
            leaf,
            engine=expected_engine,
            cell_id=cell_id,
            seat=seat,
            episode_index=episode_index,
            campaign_root=campaign_root,
            spec_sha256=spec_sha256,
            manifest_sha256=manifest_sha256,
            artifacts=artifacts,
            inventory={
                **row,
                "inventory_payload": inventory_payload,
                "inventory_record": inventory["raw"],
                "uniqueness_proof_envelope_sha256": inventory[
                    "uniqueness_proof_envelope_sha256"
                ],
            },
            inventory_verified_at=inventory_verified_at,
        )
        validated_leaves.append(checked)
        metrics = checked["metrics"]
        for name in EVENT_METRICS:
            event_counts[name] += metrics["event_incidence"][name]
        for name in DERIVED_EPISODE_METRICS:
            derived_counts[name] += metrics["derived"][name]
        actor_illegal["canary"] += metrics["canary_illegal"]
        actor_illegal["opponent"] += metrics["opponent_illegal"]
        acted_illegal["canary"] += metrics["canary_acted_with_illegal"]
        acted_illegal["opponent"] += metrics["opponent_acted_with_illegal"]
        missing += metrics["missing_record"]
        harness += metrics["harness_crash"]
        censored += metrics["prefix_censored"]
        trace_rows.append(
            {
                "episode_index": episode_index,
                "raw_trace_sha256": checked["raw_trace_sha256"],
            }
        )

    eligibility = {
        metric: derived_counts[denominator]
        for metric, denominator in CONDITIONAL_DENOMINATORS.items()
    }
    conditional = {
        "canary_win_given_decisive_clean_terminal": derived_counts["canary_win"],
        "draw_given_clean_terminal": derived_counts["draw"],
        "all_canary_actions_legal_given_canary_acted": derived_counts["canary_acted"]
        - acted_illegal["canary"],
        "all_opponent_actions_legal_given_opponent_acted": derived_counts["opponent_acted"]
        - acted_illegal["opponent"],
    }
    expected_claims = {
        "event_incidence_counts": event_counts,
        "derived_episode_metric_counts": derived_counts,
        "eligibility_counts": eligibility,
        "conditional_success_counts": conditional,
        "actor_illegal_action_episode_counts": actor_illegal,
        "actor_acted_with_illegal_action_counts": acted_illegal,
        "missing_record_count": missing,
        "harness_crash_count": harness,
        "prefix_censored_count": censored,
    }
    supplied_claims = {
        "event_incidence_counts": _counts(
            raw["event_incidence_counts"], EVENT_METRICS, f"{cell_id}.{expected_engine}.event"
        ),
        "derived_episode_metric_counts": _counts(
            raw["derived_episode_metric_counts"],
            DERIVED_EPISODE_METRICS,
            f"{cell_id}.{expected_engine}.derived",
        ),
        "eligibility_counts": _counts(
            raw["eligibility_counts"], CONDITIONAL_METRICS, f"{cell_id}.{expected_engine}.eligibility"
        ),
        "conditional_success_counts": _counts(
            raw["conditional_success_counts"],
            CONDITIONAL_METRICS,
            f"{cell_id}.{expected_engine}.conditional",
        ),
        "actor_illegal_action_episode_counts": _counts(
            raw["actor_illegal_action_episode_counts"],
            ("canary", "opponent"),
            f"{cell_id}.{expected_engine}.actor_illegal",
        ),
        "actor_acted_with_illegal_action_counts": _counts(
            raw["actor_acted_with_illegal_action_counts"],
            ("canary", "opponent"),
            f"{cell_id}.{expected_engine}.acted_illegal",
        ),
        "missing_record_count": _nonnegative_int(raw["missing_record_count"], "missing_record_count", EPISODES_PER_CELL),
        "harness_crash_count": _nonnegative_int(raw["harness_crash_count"], "harness_crash_count", EPISODES_PER_CELL),
        "prefix_censored_count": _nonnegative_int(raw["prefix_censored_count"], "prefix_censored_count", EPISODES_PER_CELL),
    }
    if supplied_claims != expected_claims:
        raise CrossEngineValidationError("engine_aggregate_claims_not_recomputed_from_signed_raw_events")
    expected_leaf_root = _merkle_root(leaves)
    expected_log_root = _merkle_root(trace_rows)
    if raw["measurement_leaf_count"] != EPISODES_PER_CELL:
        raise CrossEngineValidationError("measurement_leaf_count_mismatch")
    if raw["measurement_leaf_merkle_root_sha256"] != expected_leaf_root:
        raise CrossEngineValidationError("measurement_leaf_merkle_root_mismatch")
    if raw["event_log_merkle_root_sha256"] != expected_log_root:
        raise CrossEngineValidationError("event_log_merkle_root_mismatch")
    normalized = dict(raw)
    _assert_aggregate_identities(normalized)
    return normalized


def _validate_cells(
    value: object,
    *,
    manifest: Mapping[str, Any],
    campaign_root: str,
    spec_sha256: str,
    artifacts: Mapping[str, str],
    inventories: Mapping[str, Mapping[str, Any]],
    inventory_verified_at: int,
) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != CELL_COUNT:
        raise CrossEngineValidationError("panel_must_contain_exactly_32_cells")
    expected_ids = _manifest_cell_ids(manifest)
    manifest_hash = canonical_sha256(manifest)
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        raw = _exact(item, {"canary_id", "opponent_id", "seat", "source", "wrapper"}, f"cells[{index}]")
        canary = _identifier(raw["canary_id"], f"cells[{index}].canary_id")
        opponent = _identifier(raw["opponent_id"], f"cells[{index}].opponent_id")
        seat = raw["seat"]
        cell_id = _cell_id(canary, opponent, seat)
        if seat not in SEATS or cell_id != expected_ids[index]:
            raise CrossEngineValidationError("unknown_omitted_or_noncanonical_frozen_cell")
        source = _validate_engine_receipt(
            raw["source"],
            expected_engine="source",
            cell_id=cell_id,
            seat=seat,
            campaign_root=campaign_root,
            spec_sha256=spec_sha256,
            manifest_sha256=manifest_hash,
            artifacts=artifacts,
            inventory=inventories["source"],
            inventory_verified_at=inventory_verified_at,
        )
        wrapper = _validate_engine_receipt(
            raw["wrapper"],
            expected_engine="wrapper",
            cell_id=cell_id,
            seat=seat,
            campaign_root=campaign_root,
            spec_sha256=spec_sha256,
            manifest_sha256=manifest_hash,
            artifacts=artifacts,
            inventory=inventories["wrapper"],
            inventory_verified_at=inventory_verified_at,
        )
        normalized.append(
            {"canary_id": canary, "opponent_id": opponent, "seat": seat, "source": source, "wrapper": wrapper}
        )
    return normalized


def _validate_arithmetic_receipt(value: object) -> dict[str, Any]:
    fields = {
        "schema",
        "backend_id",
        "backend_version",
        "mpfr_version",
        "precision_bits",
        "rounding",
        "verified_backend",
        "backend_module_sha256",
        "backend_container_sha256",
        "comparison_count",
        "familywise_alpha",
        "hoeffding_formula",
        "radius_decimal_digits",
        "content_sha256",
    }
    raw = _exact(value, fields, "arithmetic_receipt")
    _content_hash(raw, "arithmetic_receipt")
    if raw["schema"] != ARITHMETIC_RECEIPT_SCHEMA or raw["backend_id"] != FROZEN_MPFR_BACKEND_ID:
        raise CrossEngineValidationError("arithmetic_receipt_does_not_name_frozen_mpfr_backend")
    if type(raw["backend_version"]) is not str or not raw["backend_version"] or type(raw["mpfr_version"]) is not str or not raw["mpfr_version"]:
        raise CrossEngineValidationError("arithmetic_receipt_backend_version_missing")
    if raw["precision_bits"] != 256 or raw["rounding"] != "RNDU" or raw["verified_backend"] is not True:
        raise CrossEngineValidationError("arithmetic_receipt_must_prove_mpfr_256_rndu")
    if raw["comparison_count"] != COMPARISON_COUNT or raw["familywise_alpha"] != {"numerator": 1, "denominator": 20}:
        raise CrossEngineValidationError("arithmetic_receipt_must_bind_frozen_k_and_familywise_alpha")
    if raw["hoeffding_formula"] != HOEFFDING_FORMULA:
        raise CrossEngineValidationError("arithmetic_receipt_must_bind_frozen_hoeffding_formula")
    if raw["radius_decimal_digits"] != RADIUS_DECIMAL_DIGITS:
        raise CrossEngineValidationError("arithmetic_receipt_must_bind_exact_radius_encoding")
    _sha(raw["backend_module_sha256"], "arithmetic_receipt.backend_module_sha256")
    _sha(raw["backend_container_sha256"], "arithmetic_receipt.backend_container_sha256")
    return dict(raw)


def _ordered_measurement_root(cells: Sequence[Mapping[str, Any]]) -> str:
    rows: list[dict[str, str]] = []
    for cell in cells:
        cell_id = _cell_id(cell["canary_id"], cell["opponent_id"], cell["seat"])
        for engine in ENGINES:
            rows.append(
                {
                    "cell_id": f"{cell_id}|{engine}",
                    "root": cell[engine]["measurement_leaf_merkle_root_sha256"],
                }
            )
    return _root(rows)


def _aggregate_projection(cells: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    projection: list[dict[str, Any]] = []
    for cell in cells:
        row: dict[str, Any] = {
            "canary_id": cell["canary_id"],
            "opponent_id": cell["opponent_id"],
            "seat": cell["seat"],
        }
        for engine in ENGINES:
            receipt = cell[engine]
            row[engine] = {
                key: value
                for key, value in receipt.items()
                if key != "measurement_leaves"
            }
        projection.append(row)
    return projection


def _measurement_chronology(cells: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    executions: list[tuple[int, str]] = []
    attestations: list[tuple[int, str]] = []
    for cell in cells:
        for engine in ENGINES:
            for leaf in cell[engine]["measurement_leaves"]:
                execution, _, _ = _verify_exact_signed_envelope(
                    leaf["execution_envelope_bytes"],
                    expected_envelope_schema=EXECUTION_ENVELOPE_SCHEMA,
                    expected_envelope_media_type=EXECUTION_ENVELOPE_MEDIA_TYPE,
                    expected_payload_media_type=EXECUTION_PAYLOAD_MEDIA_TYPE,
                    role=f"{engine}_executor",
                    domain=EXECUTION_ENVELOPE_DOMAIN,
                    label="measurement_chronology.execution",
                )
                trace, _, _ = _verify_exact_signed_envelope(
                    leaf["trace_attestation_envelope_bytes"],
                    expected_envelope_schema=TRACE_ATTESTATION_ENVELOPE_SCHEMA,
                    expected_envelope_media_type=TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
                    expected_payload_media_type=TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
                    role="trace_attestor",
                    domain=TRACE_ATTESTATION_ENVELOPE_DOMAIN,
                    label="measurement_chronology.trace_attestation",
                )
                executed = execution["started_at_utc"]
                attested = trace["attested_at_utc"]
                executions.append((_utc(executed, "measurement.started_at_utc"), executed))
                attestations.append((_utc(attested, "measurement.attested_at_utc"), attested))
    return min(executions)[1], max(attestations)[1]


def _validate_measurement_receipt(
    value: object,
    *,
    cells: list[dict[str, Any]],
    artifacts: Mapping[str, str],
) -> dict[str, Any]:
    fields = {
        "schema",
        "metric_extractor_sha256",
        "event_adapter_sha256",
        "condition_manifest_sha256",
        "aggregate_counts_sha256",
        "ordered_episode_log_root_sha256",
        "episode_count",
        "measurement_leaf_count",
        "unknown_event_count",
        "malformed_prefix_count",
        "omitted_metric_count",
        "duplicate_episode_count",
        "missing_record_count",
        "harness_crash_count",
        "prefix_censored_count",
        "first_execution_at_utc",
        "last_trace_attested_at_utc",
        "content_sha256",
    }
    raw = _exact(value, fields, "measurement_receipt")
    _content_hash(raw, "measurement_receipt")
    if raw["schema"] != MEASUREMENT_RECEIPT_SCHEMA:
        raise CrossEngineValidationError("measurement_receipt_schema_mismatch")
    if (
        raw["metric_extractor_sha256"] != artifacts["metric_extractor_sha256"]
        or raw["event_adapter_sha256"] != artifacts["event_adapter_sha256"]
        or raw["condition_manifest_sha256"] != artifacts["condition_manifest_sha256"]
    ):
        raise CrossEngineValidationError("measurement_receipt_artifact_binding_mismatch")
    if raw["aggregate_counts_sha256"] != canonical_sha256(_aggregate_projection(cells)):
        raise CrossEngineValidationError("measurement_receipt_aggregate_counts_mismatch")
    expected_count = 2 * CELL_COUNT * EPISODES_PER_CELL
    if raw["episode_count"] != expected_count or raw["measurement_leaf_count"] != expected_count:
        raise CrossEngineValidationError("measurement_receipt_episode_and_leaf_count_mismatch")
    if raw["ordered_episode_log_root_sha256"] != _ordered_measurement_root(cells):
        raise CrossEngineValidationError("measurement_receipt_ordered_episode_log_root_mismatch")
    for counter in ("unknown_event_count", "malformed_prefix_count", "omitted_metric_count", "duplicate_episode_count"):
        if raw[counter] != 0:
            raise CrossEngineValidationError(f"measurement_receipt_{counter}_must_equal_zero")
    expected_missing = sum(cell[engine]["missing_record_count"] for cell in cells for engine in ENGINES)
    expected_harness = sum(cell[engine]["harness_crash_count"] for cell in cells for engine in ENGINES)
    expected_censored = sum(cell[engine]["prefix_censored_count"] for cell in cells for engine in ENGINES)
    if (
        raw["missing_record_count"] != expected_missing
        or raw["harness_crash_count"] != expected_harness
        or raw["prefix_censored_count"] != expected_censored
    ):
        raise CrossEngineValidationError("measurement_receipt_integrity_counter_mismatch")
    first_execution, last_attested = _measurement_chronology(cells)
    if raw["first_execution_at_utc"] != first_execution or raw["last_trace_attested_at_utc"] != last_attested:
        raise CrossEngineValidationError("measurement_receipt_chronology_mismatch")
    return dict(raw)


def _backend() -> tuple[tuple[Any, str] | None, str | None]:
    spec = importlib.util.find_spec("gmpy2")
    if spec is None or spec.origin is None or not os.path.isfile(spec.origin):
        return None, "mpfr_256_rndu_backend_unavailable"
    try:
        import gmpy2  # type: ignore[import-not-found]

        if not all(hasattr(gmpy2, name) for name in ("RoundUp", "RoundDown", "mpfr", "mpz")):
            return None, "mpfr_256_rndu_backend_unavailable"
        with open(spec.origin, "rb") as module_file:
            module_hash = hashlib.sha256(module_file.read()).hexdigest()
        return (gmpy2, module_hash), None
    except (ImportError, OSError):
        return None, "mpfr_256_rndu_backend_unavailable"


def _mpfr_context(gmpy2: Any, context: Any) -> Any:
    factory = getattr(gmpy2, "context", None)
    return factory(context) if factory is not None else gmpy2.local_context(context)


def _radius(gmpy2: Any, source_n: int, wrapper_n: int) -> Any:
    context = gmpy2.get_context().copy()
    context.precision = 256
    context.round = gmpy2.RoundUp
    with _mpfr_context(gmpy2, context):
        source = gmpy2.mpfr(source_n)
        wrapper = gmpy2.mpfr(wrapper_n)
        return gmpy2.sqrt(
            (gmpy2.mpfr(1) / 2)
            * ((gmpy2.mpfr(1) / source) + (gmpy2.mpfr(1) / wrapper))
            * gmpy2.log(gmpy2.mpfr(40 * COMPARISON_COUNT))
        )


def _encode_radius(gmpy2: Any, radius: Any) -> str:
    context = gmpy2.get_context().copy()
    context.precision = 640
    context.round = gmpy2.RoundUp
    scale_int = 10**RADIUS_DECIMAL_DIGITS
    with _mpfr_context(gmpy2, context):
        scaled = gmpy2.mpfr(radius) * gmpy2.mpfr(scale_int)
        encoded_int = int(gmpy2.mpz(gmpy2.ceil(scaled)))
    whole, fractional = divmod(encoded_int, scale_int)
    return f"{whole}.{fractional:0{RADIUS_DECIMAL_DIGITS}d}"


def _mpfr_leq(gmpy2: Any, gap: Fraction, radius: Any, threshold: Fraction) -> bool:
    up = gmpy2.get_context().copy()
    up.precision = 256
    up.round = gmpy2.RoundUp
    down = gmpy2.get_context().copy()
    down.precision = 256
    down.round = gmpy2.RoundDown
    with _mpfr_context(gmpy2, up):
        margin = gmpy2.mpfr(gap.numerator) / gmpy2.mpfr(gap.denominator) + radius
    with _mpfr_context(gmpy2, down):
        conservative_threshold = gmpy2.mpfr(threshold.numerator) / gmpy2.mpfr(threshold.denominator)
    return bool(margin <= conservative_threshold)


def _verified_backend(receipt: Mapping[str, Any]) -> tuple[Any | None, str | None]:
    backend, unavailable = _backend()
    if unavailable is not None or backend is None:
        return None, unavailable or "mpfr_256_rndu_backend_unavailable"
    gmpy2, module_hash = backend
    mpfr_version = str(gmpy2.mpfr_version()) if hasattr(gmpy2, "mpfr_version") else ""
    if (
        receipt["backend_module_sha256"] != module_hash
        or receipt["backend_version"] != str(gmpy2.version())
        or receipt["mpfr_version"] != mpfr_version
    ):
        return None, "arithmetic_receipt_does_not_verify_local_frozen_mpfr_backend"
    try:
        encoded = _encode_radius(gmpy2, _radius(gmpy2, EPISODES_PER_CELL, EPISODES_PER_CELL))
        if _RADIUS_DECIMAL.fullmatch(encoded) is None:
            raise ValueError("noncanonical radius")
    except Exception:
        return None, "mpfr_256_rndu_radius_recomputation_failed"
    return gmpy2, None


def _comparison(
    cell: Mapping[str, Any],
    kind: str,
    metric: str,
    numerator_name: str,
    denominator_name: str,
    threshold: Fraction,
    gmpy2: Any | None,
) -> dict[str, Any]:
    source = cell["source"]
    wrapper = cell["wrapper"]
    sn = source[numerator_name][metric]
    wn = wrapper[numerator_name][metric]
    if denominator_name == "episode_count":
        sd = source[denominator_name]
        wd = wrapper[denominator_name]
    else:
        sd = source[denominator_name][metric]
        wd = wrapper[denominator_name][metric]
    support_ok = kind != "conditional" or (
        sd >= CONDITIONAL_SUPPORT_FLOOR and wd >= CONDITIONAL_SUPPORT_FLOOR
    )
    if sd == 0 or wd == 0:
        gap = None
        radius = None
        radius_text = None
        margin_ok = False
    else:
        gap = abs(Fraction(sn, sd) - Fraction(wn, wd))
        radius = _radius(gmpy2, sd, wd) if gmpy2 is not None else None
        radius_text = _encode_radius(gmpy2, radius) if gmpy2 is not None else None
        margin_ok = gmpy2 is not None and _mpfr_leq(gmpy2, gap, radius, threshold)
    return {
        "cell_id": _cell_id(cell["canary_id"], cell["opponent_id"], cell["seat"]),
        "kind": kind,
        "metric": metric,
        "source": {"numerator": sn, "denominator": sd},
        "wrapper": {"numerator": wn, "denominator": wd},
        "absolute_gap": None
        if gap is None
        else {"numerator": gap.numerator, "denominator": gap.denominator},
        "radius_upper": radius_text,
        "threshold": {"numerator": threshold.numerator, "denominator": threshold.denominator},
        "support_ok": support_ok,
        "margin_ok": margin_ok,
        "passed": support_ok and margin_ok,
    }


def _result_protocol() -> dict[str, Any]:
    return {
        "alpha": {"numerator": ALPHA_NUMERATOR, "denominator": ALPHA_DENOMINATOR},
        "bonferroni_comparisons": COMPARISON_COUNT,
        "episodes_per_cell_per_engine": EPISODES_PER_CELL,
        "conditional_support_floor": CONDITIONAL_SUPPORT_FLOOR,
        "incidence_margin": {
            "numerator": INCIDENCE_MARGIN.numerator,
            "denominator": INCIDENCE_MARGIN.denominator,
        },
        "conditional_margin": {
            "numerator": CONDITIONAL_MARGIN.numerator,
            "denominator": CONDITIONAL_MARGIN.denominator,
        },
        "paired_seeds": False,
        "radius_decimal_digits": RADIUS_DECIMAL_DIGITS,
    }


def _result_payload_sha256(result: Mapping[str, Any]) -> str:
    excluded = {
        "content_sha256",
        "result_payload_sha256",
        "final_authority_envelope",
        "validator_countersignature_envelope",
    }
    return canonical_sha256({key: value for key, value in result.items() if key not in excluded})


def _finish_result(result: dict[str, Any]) -> dict[str, Any]:
    result["result_payload_sha256"] = _result_payload_sha256(result)
    result["content_sha256"] = canonical_sha256(
        {key: value for key, value in result.items() if key != "content_sha256"}
    )
    return result


def _failed(reason: str) -> dict[str, Any]:
    return _finish_result(
        {
            "schema": RESULT_SCHEMA,
            "input_schema": INPUT_SCHEMA,
            "authority": False,
            "authority_level": 0,
            "submission_authorized": False,
            "production_submission_authorized": False,
            "holdout_accessed": False,
            "diagnostic_only": True,
            "integrity_pass": False,
            "arithmetic_verified": False,
            "passed": False,
            "decision": "FAIL_CLOSED",
            "reasons": [reason],
            "counts": {"cells": 0, "comparisons": 0, "expected_comparisons": COMPARISON_COUNT},
            "protocol": _result_protocol(),
            "campaign_root_sha256": None,
            "spec_sha256": None,
            "panel_content_sha256": None,
            "artifact_hashes": None,
            "comparisons": [],
            "final_authority_envelope": None,
            "validator_countersignature_envelope": None,
        }
    )


def validate_cross_engine_panel(value: object) -> dict[str, Any]:
    """Verify the exact signed seed inventories and raw episode leaves."""

    _no_floats(value)
    fields = {
        "schema",
        "protocol_id",
        "campaign_root_sha256",
        "spec_sha256",
        "manifest",
        "frozen_artifacts",
        "artifact_hashes",
        "seed_audit",
        "cells",
        "measurement_receipt",
        "arithmetic_receipt",
        "content_sha256",
    }
    raw = _exact(value, fields, "panel")
    _content_hash(raw, "panel")
    if raw["schema"] != INPUT_SCHEMA:
        raise CrossEngineValidationError("panel_schema_mismatch")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise CrossEngineValidationError("panel_protocol_mismatch")
    campaign_root = _sha(raw["campaign_root_sha256"], "panel.campaign_root_sha256")
    spec_sha256 = _sha(raw["spec_sha256"], "panel.spec_sha256")
    artifacts_raw = _exact(raw["frozen_artifacts"], _FROZEN_ARTIFACT_FIELDS, "frozen_artifacts")
    artifacts = {
        field: _sha(artifacts_raw[field], f"frozen_artifacts.{field}")
        for field in sorted(_FROZEN_ARTIFACT_FIELDS)
    }
    if artifacts["role_registry_sha256"] != _role_registry_sha256():
        raise CrossEngineValidationError("frozen_role_registry_does_not_match_implementation_pinned_keys")
    manifest = _validate_manifest(raw["manifest"])
    seed_audit, inventories, inventory_verified_at = _validate_seed_audit(
        raw["seed_audit"],
        manifest=manifest,
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
    )
    cells = _validate_cells(
        raw["cells"],
        manifest=manifest,
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
        artifacts=artifacts,
        inventories=inventories,
        inventory_verified_at=inventory_verified_at,
    )
    arithmetic = _validate_arithmetic_receipt(raw["arithmetic_receipt"])
    if arithmetic["backend_container_sha256"] != artifacts["arithmetic_container_sha256"]:
        raise CrossEngineValidationError("arithmetic_receipt_container_binding_mismatch")
    measurement = _validate_measurement_receipt(
        raw["measurement_receipt"], cells=cells, artifacts=artifacts
    )
    hash_fields = {
        "manifest_sha256",
        "frozen_artifacts_sha256",
        "cells_sha256",
        "seed_audit_sha256",
        "measurement_receipt_sha256",
        "arithmetic_receipt_sha256",
        "source_seed_inventory_sha256",
        "wrapper_seed_inventory_sha256",
        "source_log_merkle_root_sha256",
        "wrapper_log_merkle_root_sha256",
    }
    hashes = _exact(raw["artifact_hashes"], hash_fields, "artifact_hashes")
    expected_hashes = {
        "manifest_sha256": canonical_sha256(manifest),
        "frozen_artifacts_sha256": canonical_sha256(artifacts),
        "cells_sha256": canonical_sha256(cells),
        "seed_audit_sha256": canonical_sha256(seed_audit),
        "measurement_receipt_sha256": canonical_sha256(measurement),
        "arithmetic_receipt_sha256": canonical_sha256(arithmetic),
        "source_seed_inventory_sha256": canonical_sha256(seed_audit["source_inventory"]),
        "wrapper_seed_inventory_sha256": canonical_sha256(seed_audit["wrapper_inventory"]),
        "source_log_merkle_root_sha256": _root(
            [
                {
                    "cell_id": _cell_id(cell["canary_id"], cell["opponent_id"], cell["seat"]),
                    "root": cell["source"]["event_log_merkle_root_sha256"],
                }
                for cell in cells
            ]
        ),
        "wrapper_log_merkle_root_sha256": _root(
            [
                {
                    "cell_id": _cell_id(cell["canary_id"], cell["opponent_id"], cell["seat"]),
                    "root": cell["wrapper"]["event_log_merkle_root_sha256"],
                }
                for cell in cells
            ]
        ),
    }
    if dict(hashes) != expected_hashes:
        raise CrossEngineValidationError("artifact_hashes_or_ordered_log_roots_mismatch")
    return {
        "protocol_id": PROTOCOL_ID,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "panel_content_sha256": raw["content_sha256"],
        "manifest": manifest,
        "frozen_artifacts": artifacts,
        "seed_audit": seed_audit,
        "cells": cells,
        "measurement_receipt": measurement,
        "arithmetic_receipt": arithmetic,
        "artifact_hashes": expected_hashes,
    }


def evaluate_cross_engine_g04(value: object) -> dict[str, Any]:
    """Evaluate G04 locally; the returned unsigned result has zero authority."""

    try:
        panel = validate_cross_engine_panel(value)
    except (CrossEngineValidationError, CanonicalJSONError) as exc:
        return _failed(str(exc))
    gmpy2, backend_error = _verified_backend(panel["arithmetic_receipt"])
    reasons: list[str] = [] if backend_error is None else [backend_error]
    if panel["measurement_receipt"]["missing_record_count"]:
        reasons.append("missing_measurement_record_integrity_failure")
    if panel["measurement_receipt"]["harness_crash_count"]:
        reasons.append("measurement_harness_crash_integrity_failure")
    comparisons: list[dict[str, Any]] = []
    for cell in panel["cells"]:
        for metric in EVENT_METRICS:
            comparisons.append(
                _comparison(
                    cell,
                    "incidence",
                    metric,
                    "event_incidence_counts",
                    "episode_count",
                    INCIDENCE_MARGIN,
                    gmpy2,
                )
            )
        for metric in DERIVED_EPISODE_METRICS:
            comparisons.append(
                _comparison(
                    cell,
                    "derived",
                    metric,
                    "derived_episode_metric_counts",
                    "episode_count",
                    INCIDENCE_MARGIN,
                    gmpy2,
                )
            )
        for metric in CONDITIONAL_METRICS:
            comparisons.append(
                _comparison(
                    cell,
                    "conditional",
                    metric,
                    "conditional_success_counts",
                    "eligibility_counts",
                    CONDITIONAL_MARGIN,
                    gmpy2,
                )
            )
    if len(comparisons) != COMPARISON_COUNT:
        reasons.append("comparison_count_must_equal_frozen_k")
    if any(not row["support_ok"] for row in comparisons):
        reasons.append("conditional_support_floor_failure")
    if gmpy2 is not None and any(
        row["support_ok"] and not row["margin_ok"] for row in comparisons
    ):
        reasons.append("hoeffding_radius_or_margin_failure")
    passed = not reasons and all(row["passed"] for row in comparisons)
    return _finish_result(
        {
            "schema": RESULT_SCHEMA,
            "input_schema": INPUT_SCHEMA,
            "authority": False,
            "authority_level": 0,
            "submission_authorized": False,
            "production_submission_authorized": False,
            "holdout_accessed": False,
            "diagnostic_only": True,
            "integrity_pass": not bool(
                panel["measurement_receipt"]["missing_record_count"]
                or panel["measurement_receipt"]["harness_crash_count"]
            ),
            "arithmetic_verified": gmpy2 is not None,
            "passed": passed,
            "decision": "PASS_RESEARCH_ONLY" if passed else "FAIL_CLOSED",
            "reasons": sorted(set(reasons)),
            "counts": {
                "cells": len(panel["cells"]),
                "comparisons": len(comparisons),
                "expected_comparisons": COMPARISON_COUNT,
            },
            "protocol": _result_protocol(),
            "campaign_root_sha256": panel["campaign_root_sha256"],
            "spec_sha256": panel["spec_sha256"],
            "panel_content_sha256": panel["panel_content_sha256"],
            "artifact_hashes": panel["artifact_hashes"],
            "comparisons": comparisons,
            "final_authority_envelope": None,
            "validator_countersignature_envelope": None,
        }
    )


def _validate_comparison_rows(
    panel: Mapping[str, Any], result: Mapping[str, Any], gmpy2: Any
) -> None:
    rows = result["comparisons"]
    if type(rows) is not list or len(rows) != COMPARISON_COUNT:
        raise CrossEngineValidationError("cross_engine_result_must_contain_frozen_comparison_count")
    expected_rows: list[tuple[Mapping[str, Any], str, str, str, str, Fraction]] = []
    for cell in panel["cells"]:
        expected_rows.extend(
            (cell, "incidence", metric, "event_incidence_counts", "episode_count", INCIDENCE_MARGIN)
            for metric in EVENT_METRICS
        )
        expected_rows.extend(
            (cell, "derived", metric, "derived_episode_metric_counts", "episode_count", INCIDENCE_MARGIN)
            for metric in DERIVED_EPISODE_METRICS
        )
        expected_rows.extend(
            (cell, "conditional", metric, "conditional_success_counts", "eligibility_counts", CONDITIONAL_MARGIN)
            for metric in CONDITIONAL_METRICS
        )
    comparison_fields = {
        "cell_id",
        "kind",
        "metric",
        "source",
        "wrapper",
        "absolute_gap",
        "radius_upper",
        "threshold",
        "support_ok",
        "margin_ok",
        "passed",
    }
    for index, (row_value, expected) in enumerate(zip(rows, expected_rows)):
        row = _exact(row_value, comparison_fields, f"cross_engine_result.comparisons[{index}]")
        cell, kind, metric, numerator_name, denominator_name, threshold = expected
        cell_id = _cell_id(cell["canary_id"], cell["opponent_id"], cell["seat"])
        if row["cell_id"] != cell_id or row["kind"] != kind or row["metric"] != metric:
            raise CrossEngineValidationError("cross_engine_result_comparison_inventory_or_order_mismatch")
        source = cell["source"]
        wrapper = cell["wrapper"]
        sn = source[numerator_name][metric]
        wn = wrapper[numerator_name][metric]
        sd = source[denominator_name] if denominator_name == "episode_count" else source[denominator_name][metric]
        wd = wrapper[denominator_name] if denominator_name == "episode_count" else wrapper[denominator_name][metric]
        if row["source"] != {"numerator": sn, "denominator": sd} or row["wrapper"] != {"numerator": wn, "denominator": wd}:
            raise CrossEngineValidationError("cross_engine_result_comparison_counts_mismatch")
        if sd == 0 or wd == 0:
            raise CrossEngineValidationError("cross_engine_result_zero_denominator_cannot_pass")
        gap = abs(Fraction(sn, sd) - Fraction(wn, wd))
        if row["absolute_gap"] != {"numerator": gap.numerator, "denominator": gap.denominator}:
            raise CrossEngineValidationError("cross_engine_result_absolute_gap_mismatch")
        if row["threshold"] != {"numerator": threshold.numerator, "denominator": threshold.denominator}:
            raise CrossEngineValidationError("cross_engine_result_threshold_mismatch")
        if kind == "conditional" and (sd < CONDITIONAL_SUPPORT_FLOOR or wd < CONDITIONAL_SUPPORT_FLOOR):
            raise CrossEngineValidationError("cross_engine_result_conditional_support_failure")
        radius = _radius(gmpy2, sd, wd)
        expected_radius = _encode_radius(gmpy2, radius)
        if type(row["radius_upper"]) is not str or _RADIUS_DECIMAL.fullmatch(row["radius_upper"]) is None:
            raise CrossEngineValidationError("cross_engine_result_radius_is_not_exact_80_digit_upward_decimal")
        if row["radius_upper"] != expected_radius:
            raise CrossEngineValidationError("cross_engine_result_radius_does_not_equal_local_mpfr_recomputation")
        if not _mpfr_leq(gmpy2, gap, radius, threshold):
            raise CrossEngineValidationError("cross_engine_result_recomputed_margin_does_not_pass")
        if row["support_ok"] is not True or row["margin_ok"] is not True or row["passed"] is not True:
            raise CrossEngineValidationError("cross_engine_result_contains_a_failed_comparison")


def _validate_final_signatures(panel: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    authority = _verify_envelope(
        result["final_authority_envelope"],
        FINAL_AUTHORITY_SCHEMA,
        "evaluation_authority",
        "final_g04_authority",
    )
    authority_fields = {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "panel_content_sha256",
        "result_payload_sha256",
        "g05_final_authority_envelope_sha256",
        "decision",
        "issued_at_utc",
    }
    authority = dict(_exact(authority, authority_fields, "final_g04_authority.payload"))
    expected_authority = {
        "schema": FINAL_AUTHORITY_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "panel_content_sha256": panel["panel_content_sha256"],
        "result_payload_sha256": result["result_payload_sha256"],
        "g05_final_authority_envelope_sha256": panel["frozen_artifacts"][
            "g05_final_authority_envelope_sha256"
        ],
        "decision": "PASS_RESEARCH_ONLY",
        "issued_at_utc": authority["issued_at_utc"],
    }
    if authority != expected_authority:
        raise CrossEngineValidationError("final_g04_authority_binding_mismatch")
    issued_at = _utc(authority["issued_at_utc"], "final_g04_authority.issued_at_utc")
    last_attested = _utc(
        panel["measurement_receipt"]["last_trace_attested_at_utc"],
        "measurement_receipt.last_trace_attested_at_utc",
    )
    if issued_at <= last_attested:
        raise CrossEngineValidationError("final_g04_authority_signature_precedes_measurement_close")

    validator = _verify_envelope(
        result["validator_countersignature_envelope"],
        FINAL_VALIDATOR_SCHEMA,
        "validator",
        "final_g04_validator_countersignature",
    )
    validator_fields = {
        "schema",
        "campaign_root_sha256",
        "spec_sha256",
        "panel_content_sha256",
        "result_payload_sha256",
        "authority_envelope_sha256",
        "validated_at_utc",
    }
    validator = dict(_exact(validator, validator_fields, "final_g04_validator.payload"))
    expected_validator = {
        "schema": FINAL_VALIDATOR_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "panel_content_sha256": panel["panel_content_sha256"],
        "result_payload_sha256": result["result_payload_sha256"],
        "authority_envelope_sha256": canonical_sha256(result["final_authority_envelope"]),
        "validated_at_utc": validator["validated_at_utc"],
    }
    if validator != expected_validator:
        raise CrossEngineValidationError("final_g04_validator_countersignature_binding_mismatch")
    if _utc(validator["validated_at_utc"], "final_g04_validator.validated_at_utc") <= issued_at:
        raise CrossEngineValidationError("final_g04_validator_must_countersign_after_authority")


def validate_cross_engine_result_receipt(panel_value: object, result_value: object) -> dict[str, Any]:
    """Verify a clean result, local MPFR arithmetic, and both final signatures."""

    panel = validate_cross_engine_panel(panel_value)
    gmpy2, backend_error = _verified_backend(panel["arithmetic_receipt"])
    if backend_error is not None or gmpy2 is None:
        raise CrossEngineValidationError(backend_error or "mpfr_256_rndu_backend_unavailable")
    fields = {
        "schema",
        "input_schema",
        "authority",
        "authority_level",
        "submission_authorized",
        "production_submission_authorized",
        "holdout_accessed",
        "diagnostic_only",
        "integrity_pass",
        "arithmetic_verified",
        "passed",
        "decision",
        "reasons",
        "counts",
        "protocol",
        "campaign_root_sha256",
        "spec_sha256",
        "panel_content_sha256",
        "artifact_hashes",
        "comparisons",
        "result_payload_sha256",
        "final_authority_envelope",
        "validator_countersignature_envelope",
        "content_sha256",
    }
    result = _exact(result_value, fields, "cross_engine_result")
    _content_hash(result, "cross_engine_result")
    if result["schema"] != RESULT_SCHEMA or result["input_schema"] != INPUT_SCHEMA:
        raise CrossEngineValidationError("cross_engine_result_schema_mismatch")
    false_fields = (
        "authority",
        "submission_authorized",
        "production_submission_authorized",
        "holdout_accessed",
    )
    if any(result[field] is not False for field in false_fields) or result["authority_level"] != 0 or result["diagnostic_only"] is not True:
        raise CrossEngineValidationError("cross_engine_result_claims_authority")
    if (
        result["integrity_pass"] is not True
        or result["arithmetic_verified"] is not True
        or result["passed"] is not True
        or result["decision"] != "PASS_RESEARCH_ONLY"
        or result["reasons"] != []
    ):
        raise CrossEngineValidationError("cross_engine_result_is_not_a_clean_research_pass")
    if (
        result["campaign_root_sha256"] != panel["campaign_root_sha256"]
        or result["spec_sha256"] != panel["spec_sha256"]
        or result["panel_content_sha256"] != panel["panel_content_sha256"]
        or result["artifact_hashes"] != panel["artifact_hashes"]
    ):
        raise CrossEngineValidationError("cross_engine_result_panel_binding_mismatch")
    if result["counts"] != {
        "cells": CELL_COUNT,
        "comparisons": COMPARISON_COUNT,
        "expected_comparisons": COMPARISON_COUNT,
    }:
        raise CrossEngineValidationError("cross_engine_result_counts_mismatch")
    if result["protocol"] != _result_protocol():
        raise CrossEngineValidationError("cross_engine_result_protocol_mismatch")
    _validate_comparison_rows(panel, result, gmpy2)
    if result["result_payload_sha256"] != _result_payload_sha256(result):
        raise CrossEngineValidationError("cross_engine_result_payload_sha256_mismatch")
    _validate_final_signatures(panel, result)
    return dict(result)


evaluate_cross_engine = evaluate_cross_engine_g04

__all__ = [
    "ALPHA_DENOMINATOR",
    "ALPHA_NUMERATOR",
    "ARITHMETIC_RECEIPT_SCHEMA",
    "CANARY_COUNT",
    "CELL_COUNT",
    "COMPARISON_COUNT",
    "COMPARISONS_PER_CELL",
    "CONDITIONAL_DENOMINATORS",
    "CONDITIONAL_MARGIN",
    "CONDITIONAL_METRICS",
    "CONDITIONAL_SUPPORT_FLOOR",
    "CANONICAL_TRACE_MEDIA_TYPE",
    "CANONICAL_TRACE_SCHEMA",
    "CrossEngineValidationError",
    "DERIVED_EPISODE_METRICS",
    "ENGINES",
    "EPISODES_PER_CELL",
    "EVENT_METRICS",
    "FINAL_AUTHORITY_SCHEMA",
    "FINAL_VALIDATOR_SCHEMA",
    "FROZEN_MPFR_BACKEND_ID",
    "HOEFFDING_FORMULA",
    "INCIDENCE_MARGIN",
    "INPUT_SCHEMA",
    "MANIFEST_SCHEMA",
    "MEASUREMENT_RECEIPT_SCHEMA",
    "EXECUTION_ENVELOPE_DOMAIN",
    "EXECUTION_ENVELOPE_MEDIA_TYPE",
    "EXECUTION_ENVELOPE_SCHEMA",
    "EXECUTION_PAYLOAD_MEDIA_TYPE",
    "EXECUTION_RECEIPT_SCHEMA",
    "OPPONENT_COUNT",
    "PINNED_ROLE_PUBLIC_KEYS",
    "PREFIX",
    "RADIUS_DECIMAL_DIGITS",
    "RAW_TRACE_MEDIA_TYPE",
    "RAW_TRACE_SCHEMA",
    "RESULT_SCHEMA",
    "SEATS",
    "SEED_AUDIT_SCHEMA",
    "SEED_COMMITMENT_SCHEMA",
    "SEED_DERIVATION_SCHEMA",
    "SEED_INVENTORY_FREEZE_SCHEMA",
    "SEED_INVENTORY_SCHEMA",
    "SEED_UNIQUENESS_SCHEMA",
    "TRACE_ATTESTATION_ENVELOPE_DOMAIN",
    "TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE",
    "TRACE_ATTESTATION_ENVELOPE_SCHEMA",
    "TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE",
    "TRACE_ATTESTATION_SCHEMA",
    "evaluate_cross_engine",
    "evaluate_cross_engine_g04",
    "validate_cross_engine_panel",
    "validate_cross_engine_result_receipt",
]
