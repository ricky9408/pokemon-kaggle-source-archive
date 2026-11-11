from __future__ import annotations

import base64
from copy import deepcopy
from decimal import Decimal, ROUND_CEILING, localcontext
from functools import lru_cache
import hashlib

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import evaluation_v5_1.cross_engine as cross_engine
from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.cross_engine import (
    ARITHMETIC_RECEIPT_SCHEMA,
    CELL_COUNT,
    COMPARISON_COUNT,
    CONDITIONAL_METRICS,
    CONDITIONAL_SUPPORT_FLOOR as FROZEN_CONDITIONAL_SUPPORT_FLOOR,
    DERIVED_EPISODE_METRICS,
    EPISODES_PER_CELL as FROZEN_EPISODES_PER_CELL,
    EVENT_METRICS,
    EXECUTION_ENVELOPE_DOMAIN,
    EXECUTION_ENVELOPE_MEDIA_TYPE,
    EXECUTION_ENVELOPE_SCHEMA,
    EXECUTION_PAYLOAD_MEDIA_TYPE,
    EXECUTION_RECEIPT_SCHEMA,
    FINAL_AUTHORITY_SCHEMA,
    FINAL_VALIDATOR_SCHEMA,
    FROZEN_MPFR_BACKEND_ID,
    HOEFFDING_FORMULA,
    INPUT_SCHEMA,
    MANIFEST_SCHEMA,
    PREFIX,
    RADIUS_DECIMAL_DIGITS,
    SEATS,
    SEED_AUDIT_SCHEMA,
    SEED_DERIVATION_SCHEMA,
    SEED_INVENTORY_FREEZE_SCHEMA,
    SEED_INVENTORY_SCHEMA,
    SEED_UNIQUENESS_SCHEMA,
    TRACE_ATTESTATION_ENVELOPE_DOMAIN,
    TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
    TRACE_ATTESTATION_ENVELOPE_SCHEMA,
    TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
    TRACE_ATTESTATION_SCHEMA,
    evaluate_cross_engine_g04,
)
from evaluation_v5_1.envelope import build_envelope, signing_payload


_TEST_EPISODES = 4
_CAMPAIGN = "1" * 64
_SPEC = "2" * 64
_CREATED = "2026-07-14T00:00:00Z"
_FROZEN = "2026-07-14T00:01:00Z"
_UNIQUE = "2026-07-14T00:02:00Z"
_STARTED = "2026-07-14T00:03:00Z"
_ENDED = "2026-07-14T00:03:30Z"
_ATTESTED = "2026-07-14T00:04:00Z"
_AUTHORITY_ISSUED = "2026-07-14T00:05:00Z"
_VALIDATED = "2026-07-14T00:06:00Z"
_RUNNER_IMAGE_BYTES = b"synthetic-g04-linux-amd64-runner-image-v1"
_RUNNER_BINARY_BYTES = b"synthetic-g04-linux-amd64-runner-binary-v1"
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_IDENTITY_POINT = b"\x01" + bytes(31)
_SMALL_ORDER_POINT = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0"
    "d5dfac05d3c63339b13802886d53fc05"
)
_MIXED_ORDER_PUBLIC_KEY = bytes.fromhex(
    "15dc1dd2b33e5951a68f162ad4270ee9"
    "8706173c33fc838e182c9c61aaf450a3"
)
_MIXED_ORDER_R = bytes.fromhex(
    "4a792dafabb32afbe7438de5af677162"
    "d3cb80f56c850a04dad7c539da592de3"
)

_ROLE_SEEDS = {
    "source_executor": 11,
    "wrapper_executor": 12,
    "trace_attestor": 13,
    "evaluation_authority": 14,
    "validator": 15,
}
_PRIVATE_KEYS = {
    role: Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    for role, seed in _ROLE_SEEDS.items()
}
_PUBLIC_KEYS = {
    role: private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    for role, private in _PRIVATE_KEYS.items()
}

_REAL_BACKEND = cross_engine._backend
_REAL_RADIUS = cross_engine._radius
_REAL_ENCODE_RADIUS = cross_engine._encode_radius
_REAL_MPFR_LEQ = cross_engine._mpfr_leq


def _sign(schema: str, payload: dict[str, object], role: str) -> dict[str, object]:
    digest = canonical_sha256(payload)
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=_PUBLIC_KEYS[role],
        signature=_PRIVATE_KEYS[role].sign(signing_payload(schema, digest)),
    )


def _sign_exact_envelope(
    *,
    envelope_schema: str,
    envelope_media_type: str,
    payload: dict[str, object],
    payload_media_type: str,
    domain: bytes,
    role: str,
) -> dict[str, object]:
    payload_wrapper = cross_engine._encode_byte_evidence(
        canonical_json_bytes(payload), payload_media_type
    )
    signature = _PRIVATE_KEYS[role].sign(
        cross_engine._exact_signature_message(domain, payload_wrapper)
    )
    envelope = {
        "schema": envelope_schema,
        "payload": payload_wrapper,
        "signer_key_id": cross_engine._signer_key_id(_PUBLIC_KEYS[role]),
        "signature_ed25519_base64": base64.b64encode(signature).decode("ascii"),
    }
    return cross_engine._encode_byte_evidence(
        canonical_json_bytes(envelope), envelope_media_type
    )


def _decode_exact_payload(wrapper: dict[str, object]) -> dict[str, object]:
    envelope_raw = cross_engine._decode_byte_evidence(
        wrapper, label="fixture.envelope"
    )
    envelope = cross_engine._strict_canonical_json(envelope_raw, "fixture.envelope")
    payload_raw = cross_engine._decode_byte_evidence(
        envelope["payload"], label="fixture.payload"
    )
    return cross_engine._strict_canonical_json(payload_raw, "fixture.payload")


def _invalid_signature_bytes(signature: bytes, defect: str) -> bytes:
    mutated = bytearray(signature)
    if defect == "identity_r":
        mutated[:32] = _IDENTITY_POINT
    elif defect == "small_order_r":
        mutated[:32] = _SMALL_ORDER_POINT
    elif defect == "mixed_order_r":
        mutated[:32] = _MIXED_ORDER_R
    elif defect == "s_equal_l":
        mutated[32:] = _ED25519_L.to_bytes(32, "little")
    elif defect == "s_above_l":
        mutated[32:] = (_ED25519_L + 1).to_bytes(32, "little")
    else:  # pragma: no cover - callers use the frozen inventory below.
        raise AssertionError(defect)
    return bytes(mutated)


def _mutate_exact_envelope_signature(
    wrapper: dict[str, object], defect: str
) -> dict[str, object]:
    envelope_raw = cross_engine._decode_byte_evidence(
        wrapper, label="fixture.envelope"
    )
    envelope = cross_engine._strict_canonical_json(envelope_raw, "fixture.envelope")
    signature = base64.b64decode(envelope["signature_ed25519_base64"], validate=True)
    envelope["signature_ed25519_base64"] = base64.b64encode(
        _invalid_signature_bytes(signature, defect)
    ).decode("ascii")
    return cross_engine._encode_byte_evidence(
        canonical_json_bytes(envelope), wrapper["media_type"]
    )


def _mutate_common_envelope_signature(
    envelope: dict[str, object], defect: str
) -> None:
    signature = base64.b64decode(envelope["signature_ed25519_base64"], validate=True)
    envelope["signature_ed25519_base64"] = base64.b64encode(
        _invalid_signature_bytes(signature, defect)
    ).decode("ascii")


def _hashed(value: dict[str, object]) -> dict[str, object]:
    return {**value, "content_sha256": canonical_sha256(value)}


class _FakeBackend:
    @staticmethod
    def version() -> str:
        return "synthetic"

    @staticmethod
    def mpfr_version() -> str:
        return "synthetic-mpfr"


def _small_radius(_backend: object, _source_n: int, _wrapper_n: int) -> Decimal:
    return Decimal("0.01")


def _decimal_encode(_backend: object, radius: Decimal) -> str:
    with localcontext() as context:
        context.prec = 160
        quantum = Decimal(1).scaleb(-RADIUS_DECIMAL_DIGITS)
        return format(radius.quantize(quantum, rounding=ROUND_CEILING), "f")


def _decimal_leq(
    _backend: object, gap: object, radius: Decimal, threshold: object
) -> bool:
    with localcontext() as context:
        context.prec = 120
        gap_decimal = Decimal(gap.numerator) / Decimal(gap.denominator)
        threshold_decimal = Decimal(threshold.numerator) / Decimal(threshold.denominator)
        return gap_decimal + radius <= threshold_decimal


def _configure_small_contract() -> None:
    """Keep cryptographic fixture tests small without changing frozen source constants."""

    cross_engine.PINNED_ROLE_PUBLIC_KEYS = dict(_PUBLIC_KEYS)
    cross_engine.EPISODES_PER_CELL = _TEST_EPISODES
    cross_engine.CONDITIONAL_SUPPORT_FLOOR = 1
    cross_engine._backend = lambda: ((_FakeBackend(), "d" * 64), None)
    cross_engine._radius = _small_radius
    cross_engine._encode_radius = _decimal_encode
    cross_engine._mpfr_leq = _decimal_leq


def _manifest() -> dict[str, object]:
    return {
        "schema": MANIFEST_SCHEMA,
        "canaries": [
            {"canary_id": f"canary-{index}", "archive_sha256": f"{index + 1:064x}"}
            for index in range(4)
        ],
        "opponents": [
            {"opponent_id": f"opponent-{index}", "archive_sha256": f"{index + 9:064x}"}
            for index in range(4)
        ],
        "seats": list(SEATS),
        "prefix": dict(PREFIX),
    }


def _artifacts() -> dict[str, str]:
    return {
        "source_build_sha256": "3" * 64,
        "source_package_sha256": "4" * 64,
        "source_model_sha256": "5" * 64,
        "source_container_sha256": "6" * 64,
        "wrapper_build_sha256": "7" * 64,
        "wrapper_package_sha256": "8" * 64,
        "wrapper_model_sha256": "9" * 64,
        "wrapper_container_sha256": "a" * 64,
        "trace_parser_sha256": "b" * 64,
        "deck_config_root_sha256": "c" * 64,
        "event_adapter_sha256": "d" * 64,
        "condition_manifest_sha256": "e" * 64,
        "metric_extractor_sha256": "f" * 64,
        "runner_image_sha256": hashlib.sha256(_RUNNER_IMAGE_BYTES).hexdigest(),
        "runner_binary_sha256": hashlib.sha256(_RUNNER_BINARY_BYTES).hexdigest(),
        "schedule_sha256": "1" * 64,
        "seed_derivation_sha256": "2" * 64,
        "arithmetic_container_sha256": "3" * 64,
        "role_registry_sha256": cross_engine._role_registry_sha256(),
        "g05_final_authority_envelope_sha256": "4" * 64,
    }


def _inventory(
    engine: str,
    cell_ids: tuple[str, ...],
    *,
    campaign_root: str,
    spec_sha256: str,
) -> tuple[dict[str, object], dict[tuple[str, int], dict[str, object]]]:
    root = "a" * 64 if engine == "source" else "b" * 64
    rows: list[dict[str, object]] = []
    by_slot: dict[tuple[str, int], dict[str, object]] = {}
    stream_roots: list[dict[str, object]] = []
    for cell_id in cell_ids:
        stream_rows: list[dict[str, object]] = []
        for episode_index in range(cross_engine.EPISODES_PER_CELL):
            seed_hex = cross_engine._derive_seed_hex(
                root,
                campaign_root,
                spec_sha256,
                engine,
                cell_id,
                episode_index,
            )
            row = {
                "cell_id": cell_id,
                "episode_index": episode_index,
                "seed_hex": seed_hex,
                "seed_commitment_sha256": cross_engine._seed_commitment(
                    seed_hex,
                    campaign_root,
                    spec_sha256,
                    engine,
                    cell_id,
                    episode_index,
                ),
            }
            rows.append(row)
            stream_rows.append(row)
            by_slot[(cell_id, episode_index)] = row
        stream_roots.append(
            {
                "cell_id": cell_id,
                "seed_count": cross_engine.EPISODES_PER_CELL,
                "seed_merkle_root_sha256": cross_engine._merkle_root(stream_rows),
            }
        )
    payload = {
        "schema": SEED_INVENTORY_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "engine": engine,
        "created_at_utc": _CREATED,
        "seed_derivation_schema": SEED_DERIVATION_SCHEMA,
        "seed_root_hex": root,
        "cell_count": CELL_COUNT,
        "episodes_per_cell": cross_engine.EPISODES_PER_CELL,
        "row_count": len(rows),
        "rows": rows,
        "stream_roots": stream_roots,
        "inventory_merkle_root_sha256": cross_engine._merkle_root(rows),
    }
    executor = _sign(SEED_INVENTORY_SCHEMA, payload, f"{engine}_executor")
    freeze_payload = {
        "schema": SEED_INVENTORY_FREEZE_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "engine": engine,
        "executor_envelope_sha256": canonical_sha256(executor),
        "inventory_payload_sha256": canonical_sha256(payload),
        "inventory_merkle_root_sha256": payload["inventory_merkle_root_sha256"],
        "row_count": len(rows),
        "frozen_at_utc": _FROZEN,
    }
    record = {
        "executor_envelope": executor,
        "freeze_countersignature_envelope": _sign(
            SEED_INVENTORY_FREEZE_SCHEMA, freeze_payload, "trace_attestor"
        ),
    }
    return record, by_slot


def _seed_audit(
    manifest: dict[str, object], *, campaign_root: str, spec_sha256: str
) -> tuple[
    dict[str, object],
    dict[str, dict[tuple[str, int], dict[str, object]]],
]:
    cell_ids = cross_engine._manifest_cell_ids(manifest)
    source, source_rows = _inventory(
        "source", cell_ids, campaign_root=campaign_root, spec_sha256=spec_sha256
    )
    wrapper, wrapper_rows = _inventory(
        "wrapper", cell_ids, campaign_root=campaign_root, spec_sha256=spec_sha256
    )
    source_payload = source["executor_envelope"]["payload"]
    wrapper_payload = wrapper["executor_envelope"]["payload"]
    row_count = CELL_COUNT * cross_engine.EPISODES_PER_CELL
    proof = {
        "schema": SEED_UNIQUENESS_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "source_inventory_envelope_sha256": canonical_sha256(
            source["executor_envelope"]
        ),
        "source_freeze_envelope_sha256": canonical_sha256(
            source["freeze_countersignature_envelope"]
        ),
        "wrapper_inventory_envelope_sha256": canonical_sha256(
            wrapper["executor_envelope"]
        ),
        "wrapper_freeze_envelope_sha256": canonical_sha256(
            wrapper["freeze_countersignature_envelope"]
        ),
        "source_inventory_merkle_root_sha256": source_payload[
            "inventory_merkle_root_sha256"
        ],
        "wrapper_inventory_merkle_root_sha256": wrapper_payload[
            "inventory_merkle_root_sha256"
        ],
        "row_count_per_engine": row_count,
        "total_row_count": 2 * row_count,
        "duplicate_seed_count": 0,
        "cross_engine_overlap_count": 0,
        "all_streams_pairwise_disjoint": True,
        "verified_at_utc": _UNIQUE,
    }
    audit = _hashed(
        {
            "schema": SEED_AUDIT_SCHEMA,
            "campaign_root_sha256": campaign_root,
            "spec_sha256": spec_sha256,
            "source_inventory": source,
            "wrapper_inventory": wrapper,
            "uniqueness_proof_envelope": _sign(
                SEED_UNIQUENESS_SCHEMA, proof, "validator"
            ),
        }
    )
    return audit, {"source": source_rows, "wrapper": wrapper_rows}


def _event(
    event_id: int,
    event_type: str,
    *,
    actor_seat: int | None = None,
    is_canary: bool | None = None,
    pokemon_id: int | None = None,
    request_id: str | None = None,
    attack_id: str | None = None,
    cause_attack_id: str | None = None,
    damage_amount: int | None = None,
    outcome: str | None = None,
    terminal_identity: str | None = None,
) -> dict[str, object]:
    available = {
        "event_id": event_id,
        "event_type": event_type,
        "actor_seat": actor_seat,
        "is_canary": is_canary,
        "pokemon_id": pokemon_id,
        "request_id": request_id,
        "attack_id": attack_id,
        "cause_attack_id": cause_attack_id,
        "damage_amount": damage_amount,
        "outcome": outcome,
        "terminal_identity": terminal_identity,
    }
    return {
        field: available[field]
        for field in cross_engine.G02_EVENT_FIELD_SETS[event_type]
    }


def _valid_start() -> dict[str, object]:
    return {
        "reset_path": "ordinary_new_game",
        "expected_actor_seat": 0,
        "observed_actor_seat": 0,
        "first_observation_legal": True,
        "prior_state_cleared": True,
        "initialization_succeeded": True,
        "transition_before_first_legitimate_action": False,
    }


def _clean_trace(seat: str, outcome: str) -> tuple[list[dict[str, object]], dict[str, object]]:
    first_canary = seat == "canary_first"
    events = [
        _event(1, "GAME_START"),
        _event(2, "TURN_START", actor_seat=0, is_canary=first_canary),
        _event(
            3,
            "ACTION_REQUESTED",
            actor_seat=0,
            is_canary=first_canary,
            request_id="request-first",
        ),
        _event(
            4,
            "ACTION_CHOSEN",
            actor_seat=0,
            is_canary=first_canary,
            request_id="request-first",
        ),
        _event(5, "TURN_START", actor_seat=1, is_canary=not first_canary),
        _event(
            6,
            "ACTION_REQUESTED",
            actor_seat=1,
            is_canary=not first_canary,
            request_id="request-second",
        ),
        _event(
            7,
            "ACTION_CHOSEN",
            actor_seat=1,
            is_canary=not first_canary,
            request_id="request-second",
        ),
        _event(
            8,
            "GAME_END",
            outcome=outcome,
            terminal_identity={
                "CANARY_WIN": "CANARY_WIN_BY_PRIZES",
                "OPPONENT_WIN": "OPPONENT_WIN_BY_PRIZES",
                "DRAW": "DRAW",
            }[outcome],
        ),
    ]
    canary_turn = 2 if first_canary else 5
    return events, {
        "start_event_id": 1,
        "end_event_id": 8,
        "end_reason": "GAME_END",
        "canary_turn_start_event_ids": [canary_turn],
        "excluded_next_turn_start_event_id": None,
    }


def _build_leaf(
    engine: str,
    cell_id: str,
    seat: str,
    episode_index: int,
    seed_row: dict[str, object],
    inventory_record: dict[str, object],
    uniqueness_proof_envelope: dict[str, object],
    manifest: dict[str, object],
    artifacts: dict[str, str],
    *,
    campaign_root: str,
    spec_sha256: str,
    trace_status: str,
    events: list[dict[str, object]],
    boundary: dict[str, object],
    natural_start_evidence: dict[str, object] | None,
) -> dict[str, object]:
    inventory_payload = inventory_record["executor_envelope"]["payload"]
    manifest_sha256 = canonical_sha256(manifest)
    raw_trace_bytes = cross_engine._raw_trace_bytes(
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
        manifest_sha256=manifest_sha256,
        cell_id=cell_id,
        engine=engine,
        seat=seat,
        episode_index=episode_index,
        seed_commitment_sha256=seed_row["seed_commitment_sha256"],
        trace_status=trace_status,
        primitive_events=events,
        prefix_boundary=boundary,
        natural_start_evidence=natural_start_evidence,
    )
    raw_trace = cross_engine._strict_canonical_json(raw_trace_bytes, "fixture.raw_trace")
    metrics = cross_engine._derive_trace_metrics(
        trace_status,
        events,
        boundary,
        natural_start_evidence,
        seat=seat,
        label="fixture.raw_trace",
    )
    canonical_trace_bytes = cross_engine._canonical_primitive_trace_bytes(
        raw_trace_sha256=hashlib.sha256(raw_trace_bytes).hexdigest(),
        raw_trace_decoded_length=len(raw_trace_bytes),
        parser_sha256=artifacts["trace_parser_sha256"],
        raw_trace=raw_trace,
        metrics=metrics,
    )
    input_bytes = cross_engine._execution_input_bytes(
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
        manifest_sha256=manifest_sha256,
        cell_id=cell_id,
        engine=engine,
        seat=seat,
        episode_index=episode_index,
        seed_hex=seed_row["seed_hex"],
        seed_commitment_sha256=seed_row["seed_commitment_sha256"],
        artifacts=artifacts,
    )
    payload = {
        "schema": EXECUTION_RECEIPT_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest_sha256": manifest_sha256,
        "cell_id": cell_id,
        "engine": engine,
        "seat": seat,
        "episode_index": episode_index,
        "seed_hex": seed_row["seed_hex"],
        "seed_commitment_sha256": seed_row["seed_commitment_sha256"],
        "seed_inventory_payload_sha256": canonical_sha256(inventory_payload),
        "seed_inventory_executor_envelope_sha256": canonical_sha256(
            inventory_record["executor_envelope"]
        ),
        "seed_inventory_freeze_envelope_sha256": canonical_sha256(
            inventory_record["freeze_countersignature_envelope"]
        ),
        "seed_uniqueness_proof_envelope_sha256": canonical_sha256(
            uniqueness_proof_envelope
        ),
        "platform_os": "linux",
        "platform_arch": "amd64",
        "runner_image_sha256": artifacts["runner_image_sha256"],
        "runner_image_bytes": cross_engine._encode_byte_evidence(
            _RUNNER_IMAGE_BYTES, "application/octet-stream"
        ),
        "runner_binary_sha256": artifacts["runner_binary_sha256"],
        "runner_binary_bytes": cross_engine._encode_byte_evidence(
            _RUNNER_BINARY_BYTES, "application/octet-stream"
        ),
        "build_sha256": artifacts[f"{engine}_build_sha256"],
        "package_sha256": artifacts[f"{engine}_package_sha256"],
        "model_sha256": artifacts[f"{engine}_model_sha256"],
        "parser_sha256": artifacts["trace_parser_sha256"],
        "container_sha256": artifacts[f"{engine}_container_sha256"],
        "argv": cross_engine._execution_argv(engine, cell_id, episode_index),
        "env": dict(cross_engine.RUNNER_ENVIRONMENT),
        "input_root": cross_engine.INPUT_ROOT,
        "workspace_root": cross_engine.WORKSPACE_ROOT,
        "output_root": cross_engine.OUTPUT_ROOT,
        "input_fixture": cross_engine._encode_byte_evidence(
            input_bytes, "application/json"
        ),
        "input_inventory_root_sha256": "",
        "workspace_pre_inventory_root_sha256": "",
        "workspace_pre_inventory": {},
        "isolated_execution": True,
        "network_disabled": True,
        "input_root_read_only": True,
        "workspace_created_for_slot": True,
        "working_tree_clean": True,
        "started_at_utc": _STARTED,
        "ended_at_utc": _ENDED,
        "attempt_index": 0,
        "retry_count": 0,
        "replacement_count": 0,
        "intervention_count": 0,
        "rng_state_injection_count": 0,
        "forced_state_count": 0,
        "restore_count": 0,
        "carryover_count": 0,
        "exit_code": 0,
        "status": "SUCCEEDED",
        "stdout": {},
        "stderr": cross_engine._encode_byte_evidence(b"", "text/plain"),
        "raw_trace": cross_engine._encode_byte_evidence(
            raw_trace_bytes, cross_engine.RAW_TRACE_MEDIA_TYPE
        ),
        "emitted_canonical_primitive_trace": cross_engine._encode_byte_evidence(
            canonical_trace_bytes, cross_engine.CANONICAL_TRACE_MEDIA_TYPE
        ),
        "post_run_inventory_root_sha256": "",
        "post_run_inventory": {},
    }
    payload["input_inventory_root_sha256"] = (
        cross_engine._execution_input_inventory_root(payload)
    )
    pre_inventory = cross_engine._workspace_pre_inventory_bytes(
        payload["input_inventory_root_sha256"]
    )
    payload["workspace_pre_inventory"] = cross_engine._encode_byte_evidence(
        pre_inventory, "application/json"
    )
    payload["workspace_pre_inventory_root_sha256"] = hashlib.sha256(
        pre_inventory
    ).hexdigest()
    payload["stdout"] = cross_engine._encode_byte_evidence(
        cross_engine._expected_execution_stdout_bytes(payload), "application/json"
    )
    post_inventory = cross_engine._post_run_inventory_bytes(payload)
    payload["post_run_inventory"] = cross_engine._encode_byte_evidence(
        post_inventory, "application/json"
    )
    payload["post_run_inventory_root_sha256"] = hashlib.sha256(
        post_inventory
    ).hexdigest()
    execution = _sign_exact_envelope(
        envelope_schema=EXECUTION_ENVELOPE_SCHEMA,
        envelope_media_type=EXECUTION_ENVELOPE_MEDIA_TYPE,
        payload=payload,
        payload_media_type=EXECUTION_PAYLOAD_MEDIA_TYPE,
        domain=EXECUTION_ENVELOPE_DOMAIN,
        role=f"{engine}_executor",
    )
    execution_raw = cross_engine._decode_byte_evidence(
        execution, label="fixture.execution_envelope"
    )
    attestation = {
        "schema": TRACE_ATTESTATION_SCHEMA,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest_sha256": manifest_sha256,
        "cell_id": cell_id,
        "engine": engine,
        "seat": seat,
        "episode_index": episode_index,
        "seed_commitment_sha256": seed_row["seed_commitment_sha256"],
        "execution_envelope_sha256": hashlib.sha256(execution_raw).hexdigest(),
        "execution_envelope_decoded_length": len(execution_raw),
        "execution_payload_sha256": hashlib.sha256(
            canonical_json_bytes(payload)
        ).hexdigest(),
        "execution_payload_decoded_length": len(canonical_json_bytes(payload)),
        "raw_trace_sha256": hashlib.sha256(raw_trace_bytes).hexdigest(),
        "raw_trace_decoded_length": len(raw_trace_bytes),
        "raw_trace_media_type": cross_engine.RAW_TRACE_MEDIA_TYPE,
        "parser_sha256": artifacts["trace_parser_sha256"],
        "container_sha256": artifacts[f"{engine}_container_sha256"],
        "independent_canonical_primitive_trace": cross_engine._encode_byte_evidence(
            canonical_trace_bytes, cross_engine.CANONICAL_TRACE_MEDIA_TYPE
        ),
        "attested_at_utc": _ATTESTED,
    }
    return {
        "execution_envelope_bytes": execution,
        "trace_attestation_envelope_bytes": _sign_exact_envelope(
            envelope_schema=TRACE_ATTESTATION_ENVELOPE_SCHEMA,
            envelope_media_type=TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
            payload=attestation,
            payload_media_type=TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
            domain=TRACE_ATTESTATION_ENVELOPE_DOMAIN,
            role="trace_attestor",
        ),
    }


def _leaf(
    engine: str,
    cell_id: str,
    seat: str,
    episode_index: int,
    seed_row: dict[str, object],
    inventory_record: dict[str, object],
    uniqueness_proof_envelope: dict[str, object],
    manifest: dict[str, object],
    artifacts: dict[str, str],
    *,
    campaign_root: str,
    spec_sha256: str,
) -> dict[str, object]:
    outcome = "CANARY_WIN" if episode_index % 2 == 0 else "OPPONENT_WIN"
    events, boundary = _clean_trace(seat, outcome)
    return _build_leaf(
        engine,
        cell_id,
        seat,
        episode_index,
        seed_row,
        inventory_record,
        uniqueness_proof_envelope,
        manifest,
        artifacts,
        campaign_root=campaign_root,
        spec_sha256=spec_sha256,
        trace_status="recorded",
        events=events,
        boundary=boundary,
        natural_start_evidence=_valid_start(),
    )


def _claims_from_leaves(
    leaves: list[dict[str, object]], seat: str
) -> dict[str, object]:
    event_counts = {name: 0 for name in EVENT_METRICS}
    derived = {name: 0 for name in DERIVED_EPISODE_METRICS}
    actor_illegal = {"canary": 0, "opponent": 0}
    acted_illegal = {"canary": 0, "opponent": 0}
    missing = harness = censored = 0
    trace_rows: list[dict[str, object]] = []
    for episode_index, leaf in enumerate(leaves):
        payload = _decode_exact_payload(leaf["execution_envelope_bytes"])
        raw_trace_bytes = cross_engine._decode_byte_evidence(
            payload["raw_trace"], label="fixture.raw_trace"
        )
        raw_trace = cross_engine._strict_canonical_json(
            raw_trace_bytes, "fixture.raw_trace"
        )
        metrics = cross_engine._derive_trace_metrics(
            raw_trace["trace_status"],
            raw_trace["primitive_events"],
            raw_trace["prefix_boundary"],
            raw_trace["natural_start_evidence"],
            seat=seat,
        )
        for name in EVENT_METRICS:
            event_counts[name] += metrics["event_incidence"][name]
        for name in DERIVED_EPISODE_METRICS:
            derived[name] += metrics["derived"][name]
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
                "raw_trace_sha256": hashlib.sha256(raw_trace_bytes).hexdigest(),
            }
        )
    eligibility = {
        metric: derived[denominator]
        for metric, denominator in cross_engine.CONDITIONAL_DENOMINATORS.items()
    }
    conditional = {
        "canary_win_given_decisive_clean_terminal": derived["canary_win"],
        "draw_given_clean_terminal": derived["draw"],
        "all_canary_actions_legal_given_canary_acted": derived["canary_acted"]
        - acted_illegal["canary"],
        "all_opponent_actions_legal_given_opponent_acted": derived["opponent_acted"]
        - acted_illegal["opponent"],
    }
    return {
        "measurement_leaf_count": len(leaves),
        "measurement_leaf_merkle_root_sha256": cross_engine._merkle_root(leaves),
        "event_log_merkle_root_sha256": cross_engine._merkle_root(trace_rows),
        "event_incidence_counts": event_counts,
        "derived_episode_metric_counts": derived,
        "eligibility_counts": eligibility,
        "conditional_success_counts": conditional,
        "actor_illegal_action_episode_counts": actor_illegal,
        "actor_acted_with_illegal_action_counts": acted_illegal,
        "missing_record_count": missing,
        "harness_crash_count": harness,
        "prefix_censored_count": censored,
    }


def _engine(
    engine: str,
    cell_id: str,
    seat: str,
    seed_rows: dict[tuple[str, int], dict[str, object]],
    inventory_record: dict[str, object],
    uniqueness_proof_envelope: dict[str, object],
    manifest: dict[str, object],
    artifacts: dict[str, str],
    *,
    campaign_root: str,
    spec_sha256: str,
) -> dict[str, object]:
    inventory_payload = inventory_record["executor_envelope"]["payload"]
    leaves = [
        _leaf(
            engine,
            cell_id,
            seat,
            episode_index,
            seed_rows[(cell_id, episode_index)],
            inventory_record,
            uniqueness_proof_envelope,
            manifest,
            artifacts,
            campaign_root=campaign_root,
            spec_sha256=spec_sha256,
        )
        for episode_index in range(cross_engine.EPISODES_PER_CELL)
    ]
    return {
        "engine": engine,
        "episode_count": cross_engine.EPISODES_PER_CELL,
        "natural_start_count": cross_engine.EPISODES_PER_CELL,
        "retry_count": 0,
        "replacement_count": 0,
        "intervention_count": 0,
        "rng_state_injection_count": 0,
        "forced_state_count": 0,
        "restore_count": 0,
        "carryover_count": 0,
        "prefix": dict(PREFIX),
        "seed_inventory_payload_sha256": canonical_sha256(inventory_payload),
        "measurement_leaves": leaves,
        **_claims_from_leaves(leaves, seat),
    }


def _arithmetic_receipt() -> dict[str, object]:
    return _hashed(
        {
            "schema": ARITHMETIC_RECEIPT_SCHEMA,
            "backend_id": FROZEN_MPFR_BACKEND_ID,
            "backend_version": "synthetic",
            "mpfr_version": "synthetic-mpfr",
            "precision_bits": 256,
            "rounding": "RNDU",
            "verified_backend": True,
            "backend_module_sha256": "d" * 64,
            "backend_container_sha256": "3" * 64,
            "comparison_count": COMPARISON_COUNT,
            "familywise_alpha": {"numerator": 1, "denominator": 20},
            "hoeffding_formula": HOEFFDING_FORMULA,
            "radius_decimal_digits": RADIUS_DECIMAL_DIGITS,
        }
    )


def _log_root(cells: list[dict[str, object]], engine: str) -> str:
    return cross_engine._root(
        [
            {
                "cell_id": f"{cell['canary_id']}|{cell['opponent_id']}|{cell['seat']}",
                "root": cell[engine]["event_log_merkle_root_sha256"],
            }
            for cell in cells
        ]
    )


def _measurement_receipt(
    cells: list[dict[str, object]], artifacts: dict[str, str]
) -> dict[str, object]:
    first, last = cross_engine._measurement_chronology(cells)
    return _hashed(
        {
            "schema": cross_engine.MEASUREMENT_RECEIPT_SCHEMA,
            "metric_extractor_sha256": artifacts["metric_extractor_sha256"],
            "event_adapter_sha256": artifacts["event_adapter_sha256"],
            "condition_manifest_sha256": artifacts["condition_manifest_sha256"],
            "aggregate_counts_sha256": canonical_sha256(
                cross_engine._aggregate_projection(cells)
            ),
            "ordered_episode_log_root_sha256": cross_engine._ordered_measurement_root(
                cells
            ),
            "episode_count": 2 * CELL_COUNT * cross_engine.EPISODES_PER_CELL,
            "measurement_leaf_count": 2 * CELL_COUNT * cross_engine.EPISODES_PER_CELL,
            "unknown_event_count": 0,
            "malformed_prefix_count": 0,
            "omitted_metric_count": 0,
            "duplicate_episode_count": 0,
            "missing_record_count": sum(
                cell[engine]["missing_record_count"]
                for cell in cells
                for engine in cross_engine.ENGINES
            ),
            "harness_crash_count": sum(
                cell[engine]["harness_crash_count"]
                for cell in cells
                for engine in cross_engine.ENGINES
            ),
            "prefix_censored_count": sum(
                cell[engine]["prefix_censored_count"]
                for cell in cells
                for engine in cross_engine.ENGINES
            ),
            "first_execution_at_utc": first,
            "last_trace_attested_at_utc": last,
        }
    )


@lru_cache(maxsize=8)
def _panel_template(campaign_root: str, spec_sha256: str) -> dict[str, object]:
    _configure_small_contract()
    manifest = _manifest()
    artifacts = _artifacts()
    audit, seed_rows = _seed_audit(
        manifest, campaign_root=campaign_root, spec_sha256=spec_sha256
    )
    cells: list[dict[str, object]] = []
    for canary in manifest["canaries"]:
        for opponent in manifest["opponents"]:
            for seat in SEATS:
                cell_id = f"{canary['canary_id']}|{opponent['opponent_id']}|{seat}"
                cells.append(
                    {
                        "canary_id": canary["canary_id"],
                        "opponent_id": opponent["opponent_id"],
                        "seat": seat,
                        "source": _engine(
                            "source",
                            cell_id,
                            seat,
                            seed_rows["source"],
                            audit["source_inventory"],
                            audit["uniqueness_proof_envelope"],
                            manifest,
                            artifacts,
                            campaign_root=campaign_root,
                            spec_sha256=spec_sha256,
                        ),
                        "wrapper": _engine(
                            "wrapper",
                            cell_id,
                            seat,
                            seed_rows["wrapper"],
                            audit["wrapper_inventory"],
                            audit["uniqueness_proof_envelope"],
                            manifest,
                            artifacts,
                            campaign_root=campaign_root,
                            spec_sha256=spec_sha256,
                        ),
                    }
                )
    arithmetic = _arithmetic_receipt()
    measurement = _measurement_receipt(cells, artifacts)
    body = {
        "schema": INPUT_SCHEMA,
        "protocol_id": cross_engine.PROTOCOL_ID,
        "campaign_root_sha256": campaign_root,
        "spec_sha256": spec_sha256,
        "manifest": manifest,
        "frozen_artifacts": artifacts,
        "artifact_hashes": {
            "manifest_sha256": canonical_sha256(manifest),
            "frozen_artifacts_sha256": canonical_sha256(artifacts),
            "cells_sha256": canonical_sha256(cells),
            "seed_audit_sha256": canonical_sha256(audit),
            "measurement_receipt_sha256": canonical_sha256(measurement),
            "arithmetic_receipt_sha256": canonical_sha256(arithmetic),
            "source_seed_inventory_sha256": canonical_sha256(
                audit["source_inventory"]
            ),
            "wrapper_seed_inventory_sha256": canonical_sha256(
                audit["wrapper_inventory"]
            ),
            "source_log_merkle_root_sha256": _log_root(cells, "source"),
            "wrapper_log_merkle_root_sha256": _log_root(cells, "wrapper"),
        },
        "seed_audit": audit,
        "cells": cells,
        "measurement_receipt": measurement,
        "arithmetic_receipt": arithmetic,
    }
    return _hashed(body)


def _panel() -> dict[str, object]:
    _configure_small_contract()
    return deepcopy(_panel_template(_CAMPAIGN, _SPEC))


def _rehash_panel(panel: dict[str, object]) -> None:
    """Used by gate-DAG fixtures when rebinding their campaign before signing."""

    _configure_small_contract()
    inventory_campaign = panel["seed_audit"]["source_inventory"]["executor_envelope"][
        "payload"
    ]["campaign_root_sha256"]
    if inventory_campaign != panel["campaign_root_sha256"]:
        replacement = deepcopy(
            _panel_template(panel["campaign_root_sha256"], panel["spec_sha256"])
        )
        panel.clear()
        panel.update(replacement)
        return
    panel["content_sha256"] = canonical_sha256(
        {key: value for key, value in panel.items() if key != "content_sha256"}
    )


def _refresh_panel(panel: dict[str, object]) -> None:
    cells = panel["cells"]
    for cell in cells:
        for engine in cross_engine.ENGINES:
            claims = _claims_from_leaves(cell[engine]["measurement_leaves"], cell["seat"])
            cell[engine].update(claims)
    panel["measurement_receipt"] = _measurement_receipt(
        cells, panel["frozen_artifacts"]
    )
    hashes = panel["artifact_hashes"]
    hashes["cells_sha256"] = canonical_sha256(cells)
    hashes["measurement_receipt_sha256"] = canonical_sha256(
        panel["measurement_receipt"]
    )
    hashes["source_log_merkle_root_sha256"] = _log_root(cells, "source")
    hashes["wrapper_log_merkle_root_sha256"] = _log_root(cells, "wrapper")
    _rehash_panel(panel)


def _resign_leaf(
    panel: dict[str, object],
    *,
    cell_index: int = 0,
    engine: str = "source",
    episode_index: int = 0,
    mutate,
) -> None:
    leaf = panel["cells"][cell_index][engine]["measurement_leaves"][episode_index]
    payload = deepcopy(_decode_exact_payload(leaf["execution_envelope_bytes"]))
    mutate(payload)
    execution = _sign_exact_envelope(
        envelope_schema=EXECUTION_ENVELOPE_SCHEMA,
        envelope_media_type=EXECUTION_ENVELOPE_MEDIA_TYPE,
        payload=payload,
        payload_media_type=EXECUTION_PAYLOAD_MEDIA_TYPE,
        domain=EXECUTION_ENVELOPE_DOMAIN,
        role=f"{engine}_executor",
    )
    execution_raw = cross_engine._decode_byte_evidence(
        execution, label="fixture.execution_envelope"
    )
    attestation = deepcopy(
        _decode_exact_payload(leaf["trace_attestation_envelope_bytes"])
    )
    attestation["execution_envelope_sha256"] = hashlib.sha256(execution_raw).hexdigest()
    attestation["execution_envelope_decoded_length"] = len(execution_raw)
    payload_raw = canonical_json_bytes(payload)
    attestation["execution_payload_sha256"] = hashlib.sha256(payload_raw).hexdigest()
    attestation["execution_payload_decoded_length"] = len(payload_raw)
    leaf["execution_envelope_bytes"] = execution
    leaf["trace_attestation_envelope_bytes"] = _sign_exact_envelope(
        envelope_schema=TRACE_ATTESTATION_ENVELOPE_SCHEMA,
        envelope_media_type=TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
        payload=attestation,
        payload_media_type=TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
        domain=TRACE_ATTESTATION_ENVELOPE_DOMAIN,
        role="trace_attestor",
    )


def _replace_raw_trace(
    panel: dict[str, object],
    *,
    mutate,
    cell_index: int = 0,
    engine: str = "source",
    episode_index: int = 0,
) -> None:
    cell = panel["cells"][cell_index]
    cell_id = f"{cell['canary_id']}|{cell['opponent_id']}|{cell['seat']}"
    leaf = cell[engine]["measurement_leaves"][episode_index]
    execution = _decode_exact_payload(leaf["execution_envelope_bytes"])
    raw_bytes = cross_engine._decode_byte_evidence(
        execution["raw_trace"], label="fixture.raw_trace"
    )
    raw_trace = deepcopy(
        cross_engine._strict_canonical_json(raw_bytes, "fixture.raw_trace")
    )
    mutate(raw_trace)
    inventory_record = panel["seed_audit"][f"{engine}_inventory"]
    seed_row = next(
        row
        for row in inventory_record["executor_envelope"]["payload"]["rows"]
        if row["cell_id"] == cell_id and row["episode_index"] == episode_index
    )
    replacement = _build_leaf(
        engine,
        cell_id,
        cell["seat"],
        episode_index,
        seed_row,
        inventory_record,
        panel["seed_audit"]["uniqueness_proof_envelope"],
        panel["manifest"],
        panel["frozen_artifacts"],
        campaign_root=panel["campaign_root_sha256"],
        spec_sha256=panel["spec_sha256"],
        trace_status=raw_trace["trace_status"],
        events=raw_trace["primitive_events"],
        boundary=raw_trace["prefix_boundary"],
        natural_start_evidence=raw_trace["natural_start_evidence"],
    )
    leaf.clear()
    leaf.update(replacement)


def _external_pass_result(panel: dict[str, object]) -> dict[str, object]:
    _configure_small_contract()
    result = evaluate_cross_engine_g04(panel)
    assert result["decision"] == "PASS_RESEARCH_ONLY", result["reasons"]
    authority_payload = {
        "schema": FINAL_AUTHORITY_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "panel_content_sha256": panel["content_sha256"],
        "result_payload_sha256": result["result_payload_sha256"],
        "g05_final_authority_envelope_sha256": panel["frozen_artifacts"][
            "g05_final_authority_envelope_sha256"
        ],
        "decision": "PASS_RESEARCH_ONLY",
        "issued_at_utc": _AUTHORITY_ISSUED,
    }
    authority = _sign(
        FINAL_AUTHORITY_SCHEMA, authority_payload, "evaluation_authority"
    )
    validator_payload = {
        "schema": FINAL_VALIDATOR_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "panel_content_sha256": panel["content_sha256"],
        "result_payload_sha256": result["result_payload_sha256"],
        "authority_envelope_sha256": canonical_sha256(authority),
        "validated_at_utc": _VALIDATED,
    }
    result["final_authority_envelope"] = authority
    result["validator_countersignature_envelope"] = _sign(
        FINAL_VALIDATOR_SCHEMA, validator_payload, "validator"
    )
    result["content_sha256"] = canonical_sha256(
        {key: value for key, value in result.items() if key != "content_sha256"}
    )
    return result


def _rehash_result(result: dict[str, object], *, payload: bool = False) -> None:
    if payload:
        result["result_payload_sha256"] = cross_engine._result_payload_sha256(result)
    result["content_sha256"] = canonical_sha256(
        {key: value for key, value in result.items() if key != "content_sha256"}
    )


def test_sol_inventory_familywise_constants_and_names_are_frozen() -> None:
    assert FROZEN_EPISODES_PER_CELL == 6_250
    assert FROZEN_CONDITIONAL_SUPPORT_FLOOR == 1_650
    assert len(EVENT_METRICS) == 16
    assert DERIVED_EPISODE_METRICS == (
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
    assert CONDITIONAL_METRICS == (
        "canary_win_given_decisive_clean_terminal",
        "draw_given_clean_terminal",
        "all_canary_actions_legal_given_canary_acted",
        "all_opponent_actions_legal_given_opponent_acted",
    )
    assert cross_engine.COMPARISONS_PER_CELL == 30
    assert COMPARISON_COUNT == 960
    assert (cross_engine.ALPHA_NUMERATOR, cross_engine.ALPHA_DENOMINATOR) == (1, 20)


def test_exact_signed_leaf_per_slot_panel_validates() -> None:
    panel = _panel()
    checked = cross_engine.validate_cross_engine_panel(panel)
    assert len(checked["cells"]) == 32
    assert all(
        len(cell[engine]["measurement_leaves"]) == _TEST_EPISODES
        for cell in checked["cells"]
        for engine in cross_engine.ENGINES
    )
    assert "measurement_runs" not in panel["cells"][0]["source"]
    leaf = panel["cells"][0]["source"]["measurement_leaves"][0]
    first_leaf = _decode_exact_payload(leaf["execution_envelope_bytes"])
    raw_trace = cross_engine._strict_canonical_json(
        cross_engine._decode_byte_evidence(
            first_leaf["raw_trace"], label="fixture.raw_trace"
        ),
        "fixture.raw_trace",
    )
    assert first_leaf["raw_trace"]["sha256"] != first_leaf[
        "emitted_canonical_primitive_trace"
    ]["sha256"]
    assert set(raw_trace["primitive_events"][0]) == set(
        cross_engine.G02_EVENT_FIELD_SETS["GAME_START"]
    )
    assert first_leaf["seed_uniqueness_proof_envelope_sha256"] == canonical_sha256(
        panel["seed_audit"]["uniqueness_proof_envelope"]
    )
    assert checked["cells"][0]["source"]["derived_episode_metric_counts"][
        "clean_terminal"
    ] == _TEST_EPISODES


def test_compressed_self_attested_measurements_and_old_schema_are_rejected() -> None:
    panel = _panel()
    source = panel["cells"][0]["source"]
    source["measurement_runs"] = [{"episode_count": _TEST_EPISODES}]
    source.pop("measurement_leaves")
    _rehash_panel(panel)
    assert "fields_must_exactly_match_frozen_schema" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]

    panel = _panel()
    panel["schema"] = "evaluation_v5_1_g04_cross_engine_panel_v3"
    _rehash_panel(panel)
    assert evaluate_cross_engine_g04(panel)["reasons"] == ["panel_schema_mismatch"]


def test_leaf_requires_pinned_executor_and_trace_attestor_signatures() -> None:
    panel = _panel()
    leaf = panel["cells"][0]["source"]["measurement_leaves"][0]
    envelope_raw = cross_engine._decode_byte_evidence(
        leaf["execution_envelope_bytes"], label="fixture.execution"
    )
    envelope = cross_engine._strict_canonical_json(envelope_raw, "fixture.execution")
    payload = _decode_exact_payload(leaf["execution_envelope_bytes"])
    payload["package_sha256"] = "0" * 64
    envelope["payload"] = cross_engine._encode_byte_evidence(
        canonical_json_bytes(payload), EXECUTION_PAYLOAD_MEDIA_TYPE
    )
    leaf["execution_envelope_bytes"] = cross_engine._encode_byte_evidence(
        canonical_json_bytes(envelope), EXECUTION_ENVELOPE_MEDIA_TYPE
    )
    _rehash_panel(panel)
    assert "signature_invalid" in evaluate_cross_engine_g04(panel)["reasons"][0]

    panel = _panel()
    panel["cells"][0]["source"]["measurement_leaves"][0].pop(
        "trace_attestation_envelope_bytes"
    )
    _rehash_panel(panel)
    assert "fields_must_exactly_match_frozen_schema" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]


@pytest.mark.parametrize(
    "role",
    (
        "source_executor",
        "wrapper_executor",
        "trace_attestor",
        "evaluation_authority",
        "validator",
    ),
)
@pytest.mark.parametrize(
    "public_key, reason",
    (
        (_IDENTITY_POINT, "small order"),
        (_SMALL_ORDER_POINT, "small order"),
        (_MIXED_ORDER_PUBLIC_KEY, "prime-order subgroup"),
    ),
    ids=("identity", "small-order", "mixed-order"),
)
def test_all_g04_role_keys_require_strict_prime_subgroup_encoding(
    monkeypatch: pytest.MonkeyPatch,
    role: str,
    public_key: bytes,
    reason: str,
) -> None:
    _configure_small_contract()
    registry = dict(_PUBLIC_KEYS)
    registry[role] = public_key
    monkeypatch.setattr(cross_engine, "PINNED_ROLE_PUBLIC_KEYS", registry)
    with pytest.raises(cross_engine.CrossEngineValidationError, match=reason):
        cross_engine._role_key(role)


@pytest.mark.parametrize("envelope_kind", ("execution", "attestation"))
@pytest.mark.parametrize(
    "defect, reason",
    (
        ("identity_r", "signature R has small order"),
        ("small_order_r", "signature R has small order"),
        ("mixed_order_r", "signature R is not in the prime-order subgroup"),
        ("s_equal_l", "signature scalar is noncanonical"),
        ("s_above_l", "signature scalar is noncanonical"),
    ),
)
def test_exact_execution_and_attestation_envelopes_reject_strict_signature_defects(
    envelope_kind: str, defect: str, reason: str
) -> None:
    _configure_small_contract()
    if envelope_kind == "execution":
        schema = EXECUTION_ENVELOPE_SCHEMA
        envelope_media = EXECUTION_ENVELOPE_MEDIA_TYPE
        payload_media = EXECUTION_PAYLOAD_MEDIA_TYPE
        domain = EXECUTION_ENVELOPE_DOMAIN
        role = "source_executor"
    else:
        schema = TRACE_ATTESTATION_ENVELOPE_SCHEMA
        envelope_media = TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE
        payload_media = TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE
        domain = TRACE_ATTESTATION_ENVELOPE_DOMAIN
        role = "trace_attestor"
    wrapper = _sign_exact_envelope(
        envelope_schema=schema,
        envelope_media_type=envelope_media,
        payload={"schema": "strict-signature-fixture"},
        payload_media_type=payload_media,
        domain=domain,
        role=role,
    )
    wrapper = _mutate_exact_envelope_signature(wrapper, defect)
    with pytest.raises(cross_engine.CrossEngineValidationError, match=reason):
        cross_engine._verify_exact_signed_envelope(
            wrapper,
            expected_envelope_schema=schema,
            expected_envelope_media_type=envelope_media,
            expected_payload_media_type=payload_media,
            role=role,
            domain=domain,
            label=f"strict_{envelope_kind}",
        )


@pytest.mark.parametrize(
    "schema, role",
    (
        (FINAL_AUTHORITY_SCHEMA, "evaluation_authority"),
        (FINAL_VALIDATOR_SCHEMA, "validator"),
    ),
)
@pytest.mark.parametrize(
    "defect, reason",
    (
        ("identity_r", "signature R has small order"),
        ("small_order_r", "signature R has small order"),
        ("mixed_order_r", "signature R is not in the prime-order subgroup"),
        ("s_equal_l", "signature scalar is noncanonical"),
        ("s_above_l", "signature scalar is noncanonical"),
    ),
)
def test_final_authority_and_validator_envelopes_reject_strict_signature_defects(
    schema: str, role: str, defect: str, reason: str
) -> None:
    _configure_small_contract()
    envelope = _sign(schema, {"schema": "strict-final-signature-fixture"}, role)
    _mutate_common_envelope_signature(envelope, defect)
    with pytest.raises(cross_engine.CrossEngineValidationError, match=reason):
        cross_engine._verify_envelope(envelope, schema, role, f"strict_{role}")


def test_handcrafted_signed_event_claim_without_exact_execution_bytes_is_rejected() -> None:
    panel = _panel()
    events, boundary = _clean_trace("canary_first", "CANARY_WIN")
    handcrafted = {
        "schema": EXECUTION_RECEIPT_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "raw_trace_sha256": canonical_sha256({"events": events}),
        "primitive_events": events,
        "prefix_boundary": boundary,
    }
    countersignature = {
        "schema": TRACE_ATTESTATION_SCHEMA,
        "campaign_root_sha256": panel["campaign_root_sha256"],
        "spec_sha256": panel["spec_sha256"],
        "handcrafted_payload_sha256": canonical_sha256(handcrafted),
    }
    panel["cells"][0]["source"]["measurement_leaves"][0] = {
        "execution_envelope_bytes": _sign(
            EXECUTION_RECEIPT_SCHEMA, handcrafted, "source_executor"
        ),
        "trace_attestation_envelope_bytes": _sign(
            TRACE_ATTESTATION_SCHEMA, countersignature, "trace_attestor"
        ),
    }
    _rehash_panel(panel)
    result = evaluate_cross_engine_g04(panel)
    assert result["passed"] is False
    assert "envelope_bytes_fields_must_exactly_match_frozen_schema" in result[
        "reasons"
    ][0]


def _mutate_execution_component(payload: dict[str, object], component: str) -> None:
    if component == "platform":
        payload["platform_arch"] = "arm64"
    elif component == "argv":
        payload["argv"] = [*payload["argv"], "--unfrozen-flag"]
    elif component == "env":
        payload["env"] = {**payload["env"], "UNFROZEN": "1"}
    elif component == "workspace_root":
        payload["workspace_root"] = "/tmp/caller-selected-workspace"
    elif component == "runner_image":
        payload["runner_image_bytes"] = cross_engine._encode_byte_evidence(
            b"mutated-runner-image", "application/octet-stream"
        )
    elif component == "runner_binary":
        payload["runner_binary_bytes"] = cross_engine._encode_byte_evidence(
            b"mutated-runner-binary", "application/octet-stream"
        )
    elif component == "input_fixture":
        payload["input_fixture"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes({}), "application/json"
        )
    elif component == "input_inventory_root":
        payload["input_inventory_root_sha256"] = "0" * 64
    elif component == "workspace_pre_inventory":
        payload["workspace_pre_inventory"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes({}), "application/json"
        )
        payload["workspace_pre_inventory_root_sha256"] = hashlib.sha256(
            canonical_json_bytes({})
        ).hexdigest()
    elif component == "stdout":
        payload["stdout"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes({}), "application/json"
        )
    elif component == "stderr":
        payload["stderr"] = cross_engine._encode_byte_evidence(
            b"mutated stderr", "text/plain"
        )
    elif component == "canonical_output":
        payload["emitted_canonical_primitive_trace"] = (
            cross_engine._encode_byte_evidence(
                canonical_json_bytes({}), cross_engine.CANONICAL_TRACE_MEDIA_TYPE
            )
        )
    elif component == "raw_trace":
        raw_bytes = cross_engine._decode_byte_evidence(
            payload["raw_trace"], label="fixture.raw_trace"
        )
        raw_trace = cross_engine._strict_canonical_json(raw_bytes, "fixture.raw_trace")
        raw_trace["episode_index"] += 1
        payload["raw_trace"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes(raw_trace), cross_engine.RAW_TRACE_MEDIA_TYPE
        )
    elif component == "post_run_inventory":
        payload["post_run_inventory"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes({}), "application/json"
        )
        payload["post_run_inventory_root_sha256"] = hashlib.sha256(
            canonical_json_bytes({})
        ).hexdigest()
    elif component == "post_run_inventory_root":
        payload["post_run_inventory_root_sha256"] = "0" * 64
    elif component == "parser_hash":
        payload["parser_sha256"] = "0" * 64
    elif component == "container_hash":
        payload["container_sha256"] = "0" * 64
    elif component == "retry":
        payload["retry_count"] = 1
    elif component == "exit_status":
        payload["exit_code"] = 1
    else:  # pragma: no cover - the parameter inventory below is frozen.
        raise AssertionError(component)


@pytest.mark.parametrize(
    "component, reason",
    [
        ("platform", "slot_execution_requires_linux_amd64"),
        ("argv", "slot_execution_argv_not_in_frozen_allowlist"),
        ("env", "slot_execution_env_not_in_frozen_allowlist"),
        ("workspace_root", "slot_execution_root_paths_mismatch"),
        ("runner_image", "runner_image_does_not_match_frozen_sha256"),
        ("runner_binary", "runner_binary_does_not_match_frozen_sha256"),
        ("input_fixture", "slot_execution_input_fixture_mismatch"),
        ("input_inventory_root", "slot_execution_input_inventory_root_mismatch"),
        ("workspace_pre_inventory", "workspace_pre_inventory_mismatch"),
        ("stdout", "slot_execution_stdout_mismatch"),
        ("stderr", "slot_execution_stderr_must_be_empty"),
        ("canonical_output", "emitted_canonical_trace_not_recomputed"),
        ("raw_trace", "raw_trace_slot_or_seed_binding_mismatch"),
        ("post_run_inventory", "slot_execution_post_run_inventory_mismatch"),
        ("post_run_inventory_root", "slot_execution_post_run_inventory_mismatch"),
        ("parser_hash", "slot_execution_inventory_or_artifact_binding_mismatch"),
        ("container_hash", "slot_execution_inventory_or_artifact_binding_mismatch"),
        ("retry", "slot_execution_retry_count_must_equal_zero"),
        ("exit_status", "slot_execution_exit_status_mismatch"),
    ],
)
def test_validly_resigned_execution_component_mutations_fail_closed(
    component: str, reason: str
) -> None:
    panel = _panel()
    _resign_leaf(
        panel,
        mutate=lambda payload: _mutate_execution_component(payload, component),
    )
    _rehash_panel(panel)
    result = evaluate_cross_engine_g04(panel)
    assert result["passed"] is False
    assert reason in result["reasons"][0]


def test_caller_authored_event_list_outside_raw_bytes_has_no_authority() -> None:
    panel = _panel()

    def add_claim(payload: dict[str, object]) -> None:
        payload["primitive_events"] = [_event(1, "GAME_START")]

    _resign_leaf(panel, mutate=add_claim)
    _rehash_panel(panel)
    assert "execution.payload_fields_must_exactly_match_frozen_schema" in (
        evaluate_cross_engine_g04(panel)["reasons"][0]
    )


def test_trace_attestor_binds_exact_execution_envelope_bytes() -> None:
    panel = _panel()
    leaf = panel["cells"][0]["source"]["measurement_leaves"][0]
    payload = _decode_exact_payload(leaf["execution_envelope_bytes"])
    payload["ended_at_utc"] = "2026-07-14T00:03:31Z"
    leaf["execution_envelope_bytes"] = _sign_exact_envelope(
        envelope_schema=EXECUTION_ENVELOPE_SCHEMA,
        envelope_media_type=EXECUTION_ENVELOPE_MEDIA_TYPE,
        payload=payload,
        payload_media_type=EXECUTION_PAYLOAD_MEDIA_TYPE,
        domain=EXECUTION_ENVELOPE_DOMAIN,
        role="source_executor",
    )
    _rehash_panel(panel)
    assert "trace_attestation_exact_execution_binding_mismatch" in (
        evaluate_cross_engine_g04(panel)["reasons"][0]
    )


def test_trace_attestor_independent_parse_must_equal_exact_raw_bytes() -> None:
    panel = _panel()
    leaf = panel["cells"][0]["source"]["measurement_leaves"][0]
    attestation = _decode_exact_payload(leaf["trace_attestation_envelope_bytes"])
    attestation["independent_canonical_primitive_trace"] = (
        cross_engine._encode_byte_evidence(
            canonical_json_bytes({}), cross_engine.CANONICAL_TRACE_MEDIA_TYPE
        )
    )
    leaf["trace_attestation_envelope_bytes"] = _sign_exact_envelope(
        envelope_schema=TRACE_ATTESTATION_ENVELOPE_SCHEMA,
        envelope_media_type=TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE,
        payload=attestation,
        payload_media_type=TRACE_ATTESTATION_PAYLOAD_MEDIA_TYPE,
        domain=TRACE_ATTESTATION_ENVELOPE_DOMAIN,
        role="trace_attestor",
    )
    _rehash_panel(panel)
    assert "trace_attestor_did_not_independently_parse_exact_raw_bytes" in (
        evaluate_cross_engine_g04(panel)["reasons"][0]
    )


def test_signed_seed_inventory_derivation_and_freeze_chronology_are_verified() -> None:
    panel = _panel()
    inventory = panel["seed_audit"]["source_inventory"]
    payload = deepcopy(inventory["executor_envelope"]["payload"])
    payload["rows"][0]["seed_hex"] = "f" * 64
    inventory["executor_envelope"] = _sign(
        SEED_INVENTORY_SCHEMA, payload, "source_executor"
    )
    panel["seed_audit"]["content_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in panel["seed_audit"].items()
            if key != "content_sha256"
        }
    )
    _rehash_panel(panel)
    assert "seed_inventory_seed_derivation_mismatch" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]

    panel = _panel()

    def early(payload: dict[str, object]) -> None:
        payload["started_at_utc"] = _FROZEN

    _resign_leaf(panel, mutate=early)
    _rehash_panel(panel)
    assert "chronology_or_inventory_freeze_violation" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]

    panel = _panel()

    def wrong_uniqueness_proof(payload: dict[str, object]) -> None:
        payload["seed_uniqueness_proof_envelope_sha256"] = "0" * 64

    _resign_leaf(panel, mutate=wrong_uniqueness_proof)
    _rehash_panel(panel)
    assert "slot_execution_inventory_or_artifact_binding_mismatch" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]


@pytest.mark.parametrize(
    "mutator, reason",
    [
        (lambda panel: panel["cells"].pop(), "exactly_32_cells"),
        (
            lambda panel: panel["cells"][0]["source"].__setitem__("retry_count", 1),
            "retry_count_must_equal_zero",
        ),
        (
            lambda panel: panel["cells"][0]["source"]["event_incidence_counts"].pop(
                "GAME_END"
            ),
            "metric_inventory_must_be_exact",
        ),
    ],
)
def test_schedule_count_and_primitive_inventory_tampering_fail_closed(
    mutator, reason: str
) -> None:
    panel = _panel()
    mutator(panel)
    _rehash_panel(panel)
    result = evaluate_cross_engine_g04(panel)
    assert result["passed"] is False
    assert reason in result["reasons"][0]


@pytest.mark.parametrize("metric", CONDITIONAL_METRICS)
def test_all_conditional_numerators_are_exactly_derived(metric: str) -> None:
    panel = _panel()
    claims = panel["cells"][0]["source"]["conditional_success_counts"]
    claims[metric] += -1 if claims[metric] == _TEST_EPISODES else 1
    _rehash_panel(panel)
    assert "not_recomputed_from_signed_raw_events" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]


def test_actor_scoped_illegal_event_exactly_derives_legality_numerator() -> None:
    panel = _panel()

    def add_illegal(payload: dict[str, object]) -> None:
        events = payload["primitive_events"]
        for event in events:
            if event["event_id"] >= 5:
                event["event_id"] += 1
        events.insert(
            4,
            _event(
                5,
                "ILLEGAL_ACTION",
                actor_seat=0,
                is_canary=True,
                request_id="request-first",
            ),
        )
        payload["prefix_boundary"]["end_event_id"] = 9

    _replace_raw_trace(panel, mutate=add_illegal)
    _refresh_panel(panel)
    checked = cross_engine.validate_cross_engine_panel(panel)["cells"][0]["source"]
    assert checked["actor_illegal_action_episode_counts"]["canary"] == 1
    assert checked["actor_acted_with_illegal_action_counts"]["canary"] == 1
    assert checked["conditional_success_counts"][
        "all_canary_actions_legal_given_canary_acted"
    ] == _TEST_EPISODES - 1
    assert checked["derived_episode_metric_counts"]["any_illegal_action"] == checked[
        "event_incidence_counts"
    ]["ILLEGAL_ACTION"]


def test_terminal_failure_and_clean_outcome_identities_are_event_derived() -> None:
    panel = _panel()

    def policy_exception(payload: dict[str, object]) -> None:
        events = [
            _event(1, "GAME_START"),
            _event(2, "TURN_START", actor_seat=0, is_canary=True),
            _event(
                3,
                "ACTION_REQUESTED",
                actor_seat=0,
                is_canary=True,
                request_id="policy-request",
            ),
            _event(
                4,
                "ACTION_CHOSEN",
                actor_seat=0,
                is_canary=True,
                request_id="policy-request",
            ),
            _event(
                5,
                "POLICY_EXCEPTION",
                actor_seat=0,
                is_canary=True,
                request_id="policy-request",
            ),
        ]
        payload["primitive_events"] = events
        payload["prefix_boundary"] = {
            "start_event_id": 1,
            "end_event_id": 5,
            "end_reason": "POLICY_EXCEPTION",
            "canary_turn_start_event_ids": [2],
            "excluded_next_turn_start_event_id": None,
        }

    _replace_raw_trace(panel, mutate=policy_exception)
    _refresh_panel(panel)
    source = cross_engine.validate_cross_engine_panel(panel)["cells"][0]["source"]
    derived = source["derived_episode_metric_counts"]
    assert source["event_incidence_counts"]["POLICY_EXCEPTION"] == 1
    assert derived["terminal_failure"] == 1
    assert derived["clean_terminal"] == _TEST_EPISODES - 1
    assert derived["canary_win"] + derived["opponent_win"] + derived["draw"] == derived[
        "clean_terminal"
    ]
    assert derived["decisive_clean_terminal"] == derived["canary_win"] + derived[
        "opponent_win"
    ]


def test_natural_start_invalid_is_derived_from_raw_start_observation() -> None:
    panel = _panel()

    def invalid_start(payload: dict[str, object]) -> None:
        start = _valid_start()
        start["first_observation_legal"] = False
        payload["primitive_events"] = [_event(1, "GAME_START")]
        payload["natural_start_evidence"] = start
        payload["prefix_boundary"] = {
            "start_event_id": 1,
            "end_event_id": 1,
            "end_reason": "NATURAL_START_INVALID",
            "canary_turn_start_event_ids": [],
            "excluded_next_turn_start_event_id": None,
        }

    _replace_raw_trace(panel, mutate=invalid_start)
    _refresh_panel(panel)
    derived = cross_engine.validate_cross_engine_panel(panel)["cells"][0]["source"][
        "derived_episode_metric_counts"
    ]
    assert derived["natural_start_invalid"] == 1
    assert derived["terminal_failure"] == 1

    panel["cells"][0]["source"]["derived_episode_metric_counts"][
        "start_mismatch"
    ] = panel["cells"][0]["source"]["derived_episode_metric_counts"].pop(
        "natural_start_invalid"
    )
    _rehash_panel(panel)
    assert "metric_inventory_must_be_exact" in evaluate_cross_engine_g04(panel)["reasons"][0]


def test_natural_start_invalid_cannot_coexist_with_a_terminal_trace() -> None:
    panel = _panel()

    def invalid_terminal(payload: dict[str, object]) -> None:
        raw_bytes = cross_engine._decode_byte_evidence(
            payload["raw_trace"], label="fixture.raw_trace"
        )
        raw_trace = cross_engine._strict_canonical_json(raw_bytes, "fixture.raw_trace")
        raw_trace["natural_start_evidence"]["first_observation_legal"] = False
        payload["raw_trace"] = cross_engine._encode_byte_evidence(
            canonical_json_bytes(raw_trace), cross_engine.RAW_TRACE_MEDIA_TYPE
        )

    _resign_leaf(panel, mutate=invalid_terminal)
    _rehash_panel(panel)
    assert "natural_start_invalid_must_be_an_exact_start_tombstone" in (
        evaluate_cross_engine_g04(panel)["reasons"][0]
    )


def test_fourth_turn_censoring_is_not_misclassified_as_terminal_failure() -> None:
    panel = _panel()

    def censored(payload: dict[str, object]) -> None:
        events = [_event(1, "GAME_START")]
        for event_id, actor in enumerate(
            (0, 1, 0, 1, 0, 1, 0),
            start=2,
        ):
            events.append(
                _event(
                    event_id,
                    "TURN_START",
                    actor_seat=actor,
                    is_canary=actor == 0,
                )
            )
        payload["primitive_events"] = events
        payload["prefix_boundary"] = {
            "start_event_id": 1,
            "end_event_id": 8,
            "end_reason": PREFIX["end_marker"],
            "canary_turn_start_event_ids": [2, 4, 6, 8],
            "excluded_next_turn_start_event_id": 9,
        }

    _replace_raw_trace(panel, mutate=censored)
    _refresh_panel(panel)
    source = cross_engine.validate_cross_engine_panel(panel)["cells"][0]["source"]
    assert source["prefix_censored_count"] == 1
    assert source["derived_episode_metric_counts"]["terminal_failure"] == 0
    assert (
        source["derived_episode_metric_counts"]["clean_terminal"]
        + source["derived_episode_metric_counts"]["terminal_failure"]
        + source["prefix_censored_count"]
        == _TEST_EPISODES
    )


def test_unsigned_result_is_rejected_and_dual_signed_result_validates() -> None:
    panel = _panel()
    unsigned = evaluate_cross_engine_g04(panel)
    assert unsigned["decision"] == "PASS_RESEARCH_ONLY"
    with pytest.raises(cross_engine.CrossEngineValidationError, match="signature_invalid"):
        cross_engine.validate_cross_engine_result_receipt(panel, unsigned)

    signed = _external_pass_result(panel)
    assert cross_engine.validate_cross_engine_result_receipt(panel, signed) == signed
    assert signed["authority"] is False
    assert signed["submission_authorized"] is False


def test_final_authority_and_validator_countersignatures_are_both_bound() -> None:
    panel = _panel()
    result = _external_pass_result(panel)
    result["final_authority_envelope"]["payload"]["spec_sha256"] = "0" * 64
    _rehash_result(result)
    with pytest.raises(cross_engine.CrossEngineValidationError, match="signature_invalid"):
        cross_engine.validate_cross_engine_result_receipt(panel, result)

    result = _external_pass_result(panel)
    result["validator_countersignature_envelope"] = None
    _rehash_result(result)
    with pytest.raises(cross_engine.CrossEngineValidationError, match="signature_invalid"):
        cross_engine.validate_cross_engine_result_receipt(panel, result)


def test_backend_unavailable_fails_closed_and_cannot_accept_claimed_radius(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    panel = _panel()
    signed = _external_pass_result(panel)
    signed["comparisons"][0]["radius_upper"] = "0." + ("0" * 79) + "1"
    _rehash_result(signed, payload=True)
    monkeypatch.setattr(
        cross_engine,
        "_backend",
        lambda: (None, "mpfr_256_rndu_backend_unavailable"),
    )
    result = evaluate_cross_engine_g04(panel)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["arithmetic_verified"] is False
    with pytest.raises(cross_engine.CrossEngineValidationError, match="backend_unavailable"):
        cross_engine.validate_cross_engine_result_receipt(panel, signed)


def test_result_count_and_radius_tampering_are_recomputed() -> None:
    panel = _panel()
    result = _external_pass_result(panel)
    result["comparisons"][0]["source"]["numerator"] -= 1
    _rehash_result(result, payload=True)
    with pytest.raises(cross_engine.CrossEngineValidationError, match="counts_mismatch"):
        cross_engine.validate_cross_engine_result_receipt(panel, result)

    result = _external_pass_result(panel)
    result["comparisons"][0]["radius_upper"] = "0." + ("0" * 79) + "1"
    _rehash_result(result, payload=True)
    with pytest.raises(
        cross_engine.CrossEngineValidationError, match="does_not_equal_local_mpfr"
    ):
        cross_engine.validate_cross_engine_result_receipt(panel, result)


def test_retired_k_and_alpha_are_rejected() -> None:
    panel = _panel()
    panel["arithmetic_receipt"]["comparison_count"] = 704
    panel["arithmetic_receipt"]["familywise_alpha"] = {
        "numerator": 1,
        "denominator": 100,
    }
    panel["arithmetic_receipt"]["content_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in panel["arithmetic_receipt"].items()
            if key != "content_sha256"
        }
    )
    _rehash_panel(panel)
    assert "frozen_k_and_familywise_alpha" in evaluate_cross_engine_g04(panel)["reasons"][0]

    panel = _panel()
    result = _external_pass_result(panel)
    result["protocol"]["alpha"] = {"numerator": 1, "denominator": 100}
    _rehash_result(result, payload=True)
    with pytest.raises(cross_engine.CrossEngineValidationError, match="protocol_mismatch"):
        cross_engine.validate_cross_engine_result_receipt(panel, result)


def test_conditional_n_1000_cannot_pass_but_n_1650_can() -> None:
    backend, unavailable = _REAL_BACKEND()
    if unavailable is None and backend is not None:
        gmpy2, _ = backend
        radius_1000 = _REAL_RADIUS(gmpy2, 1_000, 1_000)
        radius_1650 = _REAL_RADIUS(gmpy2, 1_650, 1_650)
        assert not _REAL_MPFR_LEQ(
            gmpy2, cross_engine.Fraction(0, 1), radius_1000, cross_engine.Fraction(8, 100)
        )
        assert _REAL_MPFR_LEQ(
            gmpy2, cross_engine.Fraction(0, 1), radius_1650, cross_engine.Fraction(8, 100)
        )
        assert _REAL_ENCODE_RADIUS(gmpy2, radius_1650).startswith(
            "0.0799841375886714"
        )
        return
    with localcontext() as context:
        context.prec = 100
        log_term = Decimal(38_400).ln()
        assert (log_term / Decimal(1_000)).sqrt() > Decimal("0.08")
        assert (log_term / Decimal(1_650)).sqrt() <= Decimal("0.08")


def test_real_mpfr_unconditional_radius_has_exact_upward_80_digit_encoding() -> None:
    backend, unavailable = _REAL_BACKEND()
    if unavailable is not None or backend is None:
        pytest.skip("frozen MPFR backend is unavailable in this environment")
    gmpy2, _ = backend
    encoded = _REAL_ENCODE_RADIUS(
        gmpy2, _REAL_RADIUS(gmpy2, FROZEN_EPISODES_PER_CELL, FROZEN_EPISODES_PER_CELL)
    )
    assert Decimal(encoded).quantize(Decimal("0.0000000000000001")) == Decimal(
        "0.0410965939972175"
    )
    assert len(encoded.split(".")[1]) == 80


def test_missing_or_duplicate_leaf_slot_cannot_be_hidden_by_rehashing() -> None:
    panel = _panel()
    leaves = panel["cells"][0]["source"]["measurement_leaves"]
    leaves.pop()
    _rehash_panel(panel)
    assert "one_authenticated_leaf_per_inventory_slot" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]

    panel = _panel()
    leaves = panel["cells"][0]["source"]["measurement_leaves"]
    leaves[1] = deepcopy(leaves[0])
    _rehash_panel(panel)
    assert "inventory_or_artifact_binding_mismatch" in evaluate_cross_engine_g04(panel)[
        "reasons"
    ][0]
