from __future__ import annotations

import base64
from collections.abc import Callable
from copy import deepcopy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.engine_capability import (
    EVENT_VOCABULARY,
    G02_ATTESTOR_PARSER_RESULT_SCHEMA,
    G02_CORPUS_SCHEMA,
    G02_EVIDENCE_SCHEMA,
    G02_EXECUTION_PAYLOAD_SCHEMA,
    G02_EXECUTION_RECEIPT_SCHEMA,
    G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
    G02_RUN_RESULT_SCHEMA,
    G02_TRACE_SCHEMA,
    NEGATIVE_CASE_CLASSES,
    NEGATIVE_CLASS_FAILURE_CODES,
    RUNNER_ENVIRONMENT,
    TERMINAL_IDENTITIES,
    TERMINAL_OUTCOMES,
    EngineCapabilityError,
    derive_engine_event_capability_gate_payload,
    derive_engine_event_capability_outputs,
    derive_event_schema_document,
    derive_execution_argv,
    derive_execution_inventory_root,
    derive_negative_fixture_bytes,
    derive_post_run_inventory_bytes,
    derive_positive_input_fixture_bytes,
    parse_engine_event_trace,
    verify_engine_event_capability_gate,
)
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.exact_gate_v2 import (
    AUTHORITY_DOMAIN,
    AUTHORITY_ENVELOPE_SCHEMA,
    AUTHORITY_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_MEDIA_TYPE,
    FINAL_BUNDLE_SCHEMA,
    VALIDATOR_DOMAIN,
    VALIDATOR_ENVELOPE_SCHEMA,
    VALIDATOR_MEDIA_TYPE,
    VALIDATOR_PAYLOAD_MEDIA_TYPE,
    encode_byte_evidence,
    signature_message,
    strict_canonical_json,
    _decode_ed25519_point,
    _ed25519_add,
)


_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_IDENTITY_ENCODING = b"\x01" + bytes(31)
_ORDER_EIGHT_ENCODING = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0"
    "d5dfac05d3c63339b13802886d53fc05"
)


def _private(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _signed(
    schema: str, payload: dict[str, object], private_key: Ed25519PrivateKey
) -> dict[str, object]:
    public_key = _public(private_key)
    signature = private_key.sign(signing_payload(schema, canonical_sha256(payload)))
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public_key,
        signature=signature,
    )


def _hash(value: int) -> str:
    return f"{value:064x}"


def _bytes(raw: bytes, media_type: str = "application/octet-stream") -> dict[str, object]:
    return encode_byte_evidence(raw, media_type=media_type)


def _key_id(private_key: Ed25519PrivateKey) -> str:
    return f"ed25519-sha256:{hashlib.sha256(_public(private_key)).hexdigest()}"


def _key_record(
    *,
    role: str,
    principal_id: str,
    custodian_id: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, object]:
    return {
        "role": role,
        "key_id": _key_id(private_key),
        "principal_id": principal_id,
        "custodian_id": custodian_id,
        "algorithm": "Ed25519",
        "public_key_base64": base64.b64encode(_public(private_key)).decode("ascii"),
        "valid_from_utc": "2026-07-01T00:00:00.000000Z",
        "valid_until_utc": "2026-07-15T00:00:00.000000Z",
        "revoked": False,
    }


def _encode_ed25519_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _mixed_order_encoding(encoded: bytes) -> bytes:
    prime_point = _decode_ed25519_point(
        encoded,
        label="G02 adversarial prime-order point",
        reject_small_order=True,
    )
    torsion = _decode_ed25519_point(
        _ORDER_EIGHT_ENCODING,
        label="G02 adversarial torsion point",
        reject_small_order=False,
    )
    return _encode_ed25519_point(_ed25519_add(prime_point, torsion))


def _adversarial_point_encoding(kind: str, valid_encoding: bytes) -> bytes:
    if kind == "noncanonical":
        return _ED25519_P.to_bytes(32, "little")
    if kind == "small_order":
        return _IDENTITY_ENCODING
    assert kind == "mixed_order"
    return _mixed_order_encoding(valid_encoding)


def _adversarial_signature(encoded: str, kind: str) -> str:
    signature = bytearray(base64.b64decode(encoded, validate=True))
    if kind == "s_out_of_range":
        signature[32:] = _ED25519_L.to_bytes(32, "little")
    else:
        signature[:32] = _adversarial_point_encoding(kind, bytes(signature[:32]))
    return base64.b64encode(signature).decode("ascii")


def _v2_signed_envelope_bytes(
    *,
    schema: str,
    payload_media_type: str,
    domain: bytes,
    private_key: Ed25519PrivateKey,
) -> bytes:
    public_key = _public(private_key)
    payload_wrapper = _bytes(
        canonical_json_bytes({"decision": "PASS_RESEARCH_ONLY"}),
        payload_media_type,
    )
    return canonical_json_bytes(
        {
            "schema_version": schema,
            "signer_key_id": (
                f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"
            ),
            "payload": payload_wrapper,
            "signature_ed25519_base64": base64.b64encode(
                private_key.sign(
                    signature_message(domain=domain, payload_wrapper=payload_wrapper)
                )
            ).decode("ascii"),
        }
    )


def _caller_signed_false_pass_bundle() -> dict[str, object]:
    authority = _v2_signed_envelope_bytes(
        schema=AUTHORITY_ENVELOPE_SCHEMA,
        payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
        domain=AUTHORITY_DOMAIN,
        private_key=_private(11),
    )
    validator = _v2_signed_envelope_bytes(
        schema=VALIDATOR_ENVELOPE_SCHEMA,
        payload_media_type=VALIDATOR_PAYLOAD_MEDIA_TYPE,
        domain=VALIDATOR_DOMAIN,
        private_key=_private(12),
    )
    return {
        "schema_version": FINAL_BUNDLE_SCHEMA,
        "authority_envelope": _bytes(authority, AUTHORITY_MEDIA_TYPE),
        "validator_envelope": _bytes(validator, VALIDATOR_MEDIA_TYPE),
    }


def _actor(
    event_id: int, event_type: str, *, seat: int = 0, **fields: object
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "event_type": event_type,
        "actor_seat": seat,
        "is_canary": seat == 0,
        **fields,
    }


def _trace(terminal_identity: str) -> dict[str, object]:
    return {
        "schema_version": G02_TRACE_SCHEMA,
        "events": [
            {"event_id": 0, "event_type": "GAME_START"},
            _actor(1, "TURN_START"),
            _actor(2, "ACTION_REQUESTED", request_id="request-1"),
            _actor(3, "ACTION_CHOSEN", request_id="request-1"),
            _actor(4, "MANUAL_ENERGY_ATTACHED", request_id="request-1", pokemon_id=101),
            _actor(
                5,
                "ATTACK_DECLARED",
                request_id="request-1",
                attack_id="attack-1",
                pokemon_id=101,
            ),
            _actor(
                6,
                "DAMAGE_APPLIED",
                cause_attack_id="attack-1",
                pokemon_id=202,
                damage_amount=100,
            ),
            _actor(7, "PRIZE_TAKEN", cause_attack_id="attack-1", pokemon_id=202),
            _actor(8, "POKEMON_KO", cause_attack_id="attack-1", pokemon_id=202),
            _actor(9, "ACTIVE_PROMOTED", seat=1, pokemon_id=202),
            _actor(10, "FORCED_SWITCH", cause_attack_id="attack-1", pokemon_id=202),
            _actor(
                11,
                "RUN_AWAY_DRAW_ATTEMPT",
                request_id="request-1",
                pokemon_id=101,
            ),
            _actor(12, "ILLEGAL_ACTION", request_id="request-1"),
            _actor(13, "POLICY_EXCEPTION", request_id="request-1"),
            _actor(14, "TIMEOUT", request_id="request-1"),
            {
                "event_id": 15,
                "event_type": "GAME_END",
                "terminal_identity": terminal_identity,
                "outcome": TERMINAL_OUTCOMES[terminal_identity],
            },
        ],
    }


def _artifact_material(engine: str) -> tuple[dict[str, str], dict[str, object]]:
    raw = {
        name: f"{engine}:{name}:exact-bytes".encode("ascii")
        for name in ("engine", "package", "parser", "container")
    }
    wrapped = {name: _bytes(value) for name, value in raw.items()}
    hashes = {
        "engine_sha256": wrapped["engine"]["sha256"],
        "package_sha256": wrapped["package"]["sha256"],
        "parser_sha256": wrapped["parser"]["sha256"],
        "container_sha256": wrapped["container"]["sha256"],
    }
    return hashes, wrapped


def _stdout(
    *, case_id: str, corpus_kind: str, trace_sha256: str, negative_class: str
) -> bytes:
    value: dict[str, object] = {
        "schema_version": G02_RUN_RESULT_SCHEMA,
        "case_id": case_id,
        "emitted_trace_sha256": trace_sha256,
        "status": "SUCCEEDED" if corpus_kind == "positive" else "EXPECTED_REJECTION",
    }
    if corpus_kind == "negative":
        value["failure_code"] = NEGATIVE_CLASS_FAILURE_CODES[negative_class]
        value["fixture_sha256"] = hashlib.sha256(
            derive_negative_fixture_bytes(negative_class)
        ).hexdigest()
    return canonical_json_bytes(value)


def _observed_parser_result(emitted_trace: bytes) -> dict[str, object]:
    try:
        parsed = parse_engine_event_trace(emitted_trace, canary_seat=0)
        return {
            "schema_version": G02_ATTESTOR_PARSER_RESULT_SCHEMA,
            "disposition": "ACCEPTED",
            "failure_code": "",
            "event_types": parsed["event_types"],
            "terminal_identity": parsed["terminal_identity"],
            "outcome": parsed["outcome"],
        }
    except EngineCapabilityError as exc:
        return {
            "schema_version": G02_ATTESTOR_PARSER_RESULT_SCHEMA,
            "disposition": "REJECTED",
            "failure_code": exc.code,
            "event_types": [],
            "terminal_identity": "",
            "outcome": "",
        }


def _parser_result(
    *, emitted_trace: bytes, corpus_kind: str, negative_class: str
) -> dict[str, object]:
    result = _observed_parser_result(emitted_trace)
    if corpus_kind == "positive":
        assert result["disposition"] == "ACCEPTED"
    else:
        assert result["disposition"] == "REJECTED"
        assert result["failure_code"] == NEGATIVE_CLASS_FAILURE_CODES[negative_class]
    return result


def _execution_payload(
    evidence: dict[str, object],
    *,
    case_id: str,
    corpus_kind: str,
    engine: str,
    emitted_trace: bytes,
    nonce: str,
    negative_class: str = "",
) -> dict[str, object]:
    artifacts = evidence[f"{engine}_artifacts"]
    runner = evidence["runner_artifacts"]
    assert isinstance(artifacts, dict)
    assert isinstance(runner, dict)
    artifact_hashes, artifact_bytes = _artifact_material(engine)
    assert artifacts == artifact_hashes
    dependencies = evidence["dependency_roots"]
    event_schema = evidence["event_schema"]
    assert isinstance(dependencies, list)
    assert isinstance(event_schema, dict)
    executor_key = evidence[f"{engine}_executor_key"]
    assert isinstance(executor_key, dict)
    input_bytes = (
        derive_positive_input_fixture_bytes(case_id=case_id, engine=engine, canary_seat=0)
        if corpus_kind == "positive"
        else derive_negative_fixture_bytes(negative_class)
    )
    trace_wrapper = _bytes(emitted_trace, "application/json")
    runner_image = _bytes(b"g02-runner-image-manifest")
    runner_binary = _bytes(b"g02-runner-binary")
    assert runner["runner_image_sha256"] == runner_image["sha256"]
    assert runner["runner_binary_sha256"] == runner_binary["sha256"]
    payload: dict[str, object] = {
        "schema_version": G02_EXECUTION_PAYLOAD_SCHEMA,
        "campaign_root": evidence["campaign_root"],
        "evaluation_id": evidence["evaluation_id"],
        "frozen_spec_hash": evidence["frozen_spec_hash"],
        "g00_result_root": dependencies[0]["result_root"],
        "g01_result_root": dependencies[1]["result_root"],
        "g00_frozen_at_utc": evidence["g00_frozen_at_utc"],
        "g01_frozen_at_utc": evidence["g01_frozen_at_utc"],
        "g02_frozen_at_utc": evidence["g02_frozen_at_utc"],
        "event_schema_sha256": event_schema["sha256"],
        "case_id": case_id,
        "corpus_kind": corpus_kind,
        "runner_mode": (
            "ENGINE_EMISSION" if corpus_kind == "positive" else "PARSER_NEGATIVE_FIXTURE"
        ),
        "negative_class": negative_class,
        "engine": engine,
        **artifacts,
        "artifact_bytes": artifact_bytes,
        **runner,
        "runner_image_bytes": runner_image,
        "runner_binary_bytes": runner_binary,
        "argv": derive_execution_argv(
            case_id=case_id, engine=engine, canary_seat=0, corpus_kind=corpus_kind
        ),
        "env": dict(RUNNER_ENVIRONMENT),
        "canary_seat": 0,
        "input_fixture": _bytes(input_bytes, "application/json"),
        "working_tree_input_inventory_root": "",
        "post_run_inventory_root": "",
        "post_run_inventory": _bytes(b"", "application/json"),
        "execution_nonce": nonce,
        "platform_os": "linux",
        "platform_arch": "amd64",
        "isolated_execution": True,
        "working_tree_clean": True,
        "retry_count": 0,
        "intervention_count": 0,
        "started_at_utc": "2026-07-12T00:00:00.000000Z",
        "ended_at_utc": "2026-07-12T00:00:01.000000Z",
        "exit_code": 0,
        "status": "SUCCEEDED" if corpus_kind == "positive" else "EXPECTED_REJECTION",
        "stdout": _bytes(
            _stdout(
                case_id=case_id,
                corpus_kind=corpus_kind,
                trace_sha256=trace_wrapper["sha256"],
                negative_class=negative_class,
            ),
            "application/json",
        ),
        "stderr": _bytes(b"", "text/plain"),
        "emitted_trace": trace_wrapper,
        "executor_role": executor_key["role"],
        "executor_key_id": executor_key["key_id"],
        "executor_principal_id": executor_key["principal_id"],
        "executor_custodian_id": executor_key["custodian_id"],
        "executor_signed_at_utc": "2026-07-12T00:00:02.000000Z",
    }
    inventory = derive_execution_inventory_root(payload)
    payload["working_tree_input_inventory_root"] = inventory
    payload["post_run_inventory_root"] = inventory
    payload["post_run_inventory"] = _bytes(
        derive_post_run_inventory_bytes(case_id=case_id, inventory_root=inventory),
        "application/json",
    )
    return payload


def _receipt_for_execution(
    execution_payload: dict[str, object],
    *,
    evidence: dict[str, object],
    keys: dict[str, Ed25519PrivateKey],
) -> dict[str, object]:
    engine = execution_payload["engine"]
    assert isinstance(engine, str)
    executor_envelope = _signed(
        G02_EXECUTION_PAYLOAD_SCHEMA,
        execution_payload,
        keys[f"{engine}_executor"],
    )
    executor_envelope_bytes = canonical_json_bytes(executor_envelope)
    emitted_trace = execution_payload["emitted_trace"]
    assert isinstance(emitted_trace, dict)
    emitted_raw = base64.b64decode(emitted_trace["base64"], validate=True)
    trace_key = evidence["trace_attestor_key"]
    executor_key = evidence[f"{engine}_executor_key"]
    assert isinstance(trace_key, dict)
    assert isinstance(executor_key, dict)
    receipt_payload: dict[str, object] = {
        "schema_version": G02_EXECUTION_RECEIPT_SCHEMA,
        "case_id": execution_payload["case_id"],
        "engine": engine,
        "execution_nonce": execution_payload["execution_nonce"],
        "executor_role": executor_key["role"],
        "executor_key_id": executor_key["key_id"],
        "executor_principal_id": executor_key["principal_id"],
        "executor_custodian_id": executor_key["custodian_id"],
        "executor_envelope": _bytes(
            executor_envelope_bytes,
            G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
        ),
        "executor_envelope_sha256": hashlib.sha256(
            executor_envelope_bytes
        ).hexdigest(),
        "execution_payload_sha256": canonical_sha256(execution_payload),
        "emitted_trace_sha256": hashlib.sha256(emitted_raw).hexdigest(),
        "parser_result": _parser_result(
            emitted_trace=emitted_raw,
            corpus_kind=execution_payload["corpus_kind"],  # type: ignore[arg-type]
            negative_class=execution_payload["negative_class"],  # type: ignore[arg-type]
        ),
        "trace_attestor_key_id": trace_key["key_id"],
        "trace_attestor_principal_id": trace_key["principal_id"],
        "trace_attestor_custodian_id": trace_key["custodian_id"],
        "attested_at_utc": "2026-07-13T00:00:00.000000Z",
    }
    return _signed(G02_EXECUTION_RECEIPT_SCHEMA, receipt_payload, keys["trace"])


def _corpus(kind: str, rows: list[dict[str, object]]) -> dict[str, object]:
    return _bytes(
        canonical_json_bytes(
            {"schema_version": G02_CORPUS_SCHEMA, "corpus_kind": kind, "cases": rows}
        ),
        "application/json",
    )


def _receipt_row(envelope: dict[str, object]) -> tuple[str, dict[str, object]]:
    receipt = envelope["payload"]
    assert isinstance(receipt, dict)
    executor_wrapper = receipt["executor_envelope"]
    assert isinstance(executor_wrapper, dict)
    executor_envelope = strict_canonical_json(
        base64.b64decode(executor_wrapper["base64"], validate=True),
        label="test executor envelope",
    )
    assert isinstance(executor_envelope, dict)
    payload = executor_envelope["payload"]
    assert isinstance(payload, dict)
    emitted = payload["emitted_trace"]
    input_fixture = payload["input_fixture"]
    assert isinstance(emitted, dict)
    assert isinstance(input_fixture, dict)
    row: dict[str, object] = {
        "case_id": payload["case_id"],
        "engine": payload["engine"],
        "canary_seat": payload["canary_seat"],
        "execution_receipt_sha256": canonical_sha256(envelope),
        "emitted_trace_sha256": emitted["sha256"],
    }
    if payload["corpus_kind"] == "negative":
        row["negative_class"] = payload["negative_class"]
        row["fixture_sha256"] = input_fixture["sha256"]
    return payload["corpus_kind"], row  # type: ignore[return-value]


def _regenerate_unsigned_corpora(evidence: dict[str, object]) -> None:
    rows: dict[str, list[dict[str, object]]] = {"positive": [], "negative": []}
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    for envelope in envelopes:
        kind, row = _receipt_row(envelope)
        rows[kind].append(row)
    for kind in rows:
        rows[kind].sort(key=lambda row: row["case_id"])
        evidence[f"{kind}_corpus"] = _corpus(kind, rows[kind])


def _evidence() -> tuple[dict[str, object], dict[str, Ed25519PrivateKey]]:
    keys = {
        "source_executor": _private(21),
        "wrapper_executor": _private(22),
        "trace": _private(23),
    }
    source_hashes, _ = _artifact_material("source")
    wrapper_hashes, _ = _artifact_material("wrapper")
    runner_image = _bytes(b"g02-runner-image-manifest")
    runner_binary = _bytes(b"g02-runner-binary")
    evidence: dict[str, object] = {
        "schema_version": G02_EVIDENCE_SCHEMA,
        "campaign_root": _hash(101),
        "evaluation_id": "g02-fixture",
        "frozen_spec_hash": _hash(102),
        "dependency_roots": [
            {"gate_id": "G00_TRUST_ROOTS", "result_root": _hash(103)},
            {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "result_root": _hash(104)},
        ],
        "campaign_registry_hash": _hash(105),
        "evidence_manifest_root": _hash(106),
        "verifier_module_digest": _hash(107),
        "g00_frozen_at_utc": "2026-07-10T00:00:00.000000Z",
        "g01_frozen_at_utc": "2026-07-11T00:00:00.000000Z",
        "g02_frozen_at_utc": "2026-07-14T00:00:00.000000Z",
        "event_schema": _bytes(
            canonical_json_bytes(derive_event_schema_document()), "application/json"
        ),
        "positive_corpus": _corpus("positive", []),
        "negative_corpus": _corpus("negative", []),
        "source_artifacts": source_hashes,
        "wrapper_artifacts": wrapper_hashes,
        "runner_artifacts": {
            "runner_image_sha256": runner_image["sha256"],
            "runner_binary_sha256": runner_binary["sha256"],
        },
        "source_executor_key": _key_record(
            role="source_executor",
            principal_id="principal-source-executor",
            custodian_id="custodian-source-executor",
            private_key=keys["source_executor"],
        ),
        "wrapper_executor_key": _key_record(
            role="wrapper_executor",
            principal_id="principal-wrapper-executor",
            custodian_id="custodian-wrapper-executor",
            private_key=keys["wrapper_executor"],
        ),
        "trace_attestor_key": _key_record(
            role="trace_attestor",
            principal_id="principal-trace-attestor",
            custodian_id="custodian-trace-attestor",
            private_key=keys["trace"],
        ),
        "execution_receipt_envelopes": [],
    }
    payloads: list[dict[str, object]] = []
    nonce_index = 1000
    for engine in ("source", "wrapper"):
        for index, terminal_identity in enumerate(TERMINAL_IDENTITIES):
            payloads.append(
                _execution_payload(
                    evidence,
                    case_id=f"positive-{engine}-{index:02d}",
                    corpus_kind="positive",
                    engine=engine,
                    emitted_trace=canonical_json_bytes(_trace(terminal_identity)),
                    nonce=_hash(nonce_index),
                )
            )
            nonce_index += 1
    for engine in ("source", "wrapper"):
        for index, negative_class in enumerate(NEGATIVE_CASE_CLASSES):
            fixture = derive_negative_fixture_bytes(negative_class)
            payloads.append(
                _execution_payload(
                    evidence,
                    case_id=f"negative-{engine}-{index:02d}",
                    corpus_kind="negative",
                    engine=engine,
                    emitted_trace=fixture,
                    nonce=_hash(nonce_index),
                    negative_class=negative_class,
                )
            )
            nonce_index += 1
    evidence["execution_receipt_envelopes"] = [
        _receipt_for_execution(payload, evidence=evidence, keys=keys)
        for payload in sorted(payloads, key=lambda item: item["case_id"])
    ]
    _regenerate_unsigned_corpora(evidence)
    return evidence, keys


def _executor_envelope_at(
    evidence: dict[str, object], index: int = 0
) -> dict[str, object]:
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    receipt = envelopes[index]["payload"]
    assert isinstance(receipt, dict)
    wrapper = receipt["executor_envelope"]
    assert isinstance(wrapper, dict)
    parsed = strict_canonical_json(
        base64.b64decode(wrapper["base64"], validate=True),
        label="test executor envelope",
    )
    assert isinstance(parsed, dict)
    return parsed


def _execution_payload_at(
    evidence: dict[str, object], index: int = 0
) -> dict[str, object]:
    executor_envelope = _executor_envelope_at(evidence, index)
    payload = executor_envelope["payload"]
    assert isinstance(payload, dict)
    return deepcopy(payload)


def _replace_signed_execution(
    evidence: dict[str, object],
    keys: dict[str, Ed25519PrivateKey],
    payload: dict[str, object],
    *,
    index: int = 0,
) -> None:
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    envelopes[index] = _receipt_for_execution(payload, evidence=evidence, keys=keys)
    _regenerate_unsigned_corpora(evidence)


def _unsigned_mutation(
    evidence: dict[str, object],
    mutate: Callable[[dict[str, object]], None],
    *,
    index: int = 0,
) -> None:
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    envelope = envelopes[index]
    receipt = envelope["payload"]
    assert isinstance(receipt, dict)
    executor_envelope = _executor_envelope_at(evidence, index)
    execution_payload = executor_envelope["payload"]
    assert isinstance(execution_payload, dict)
    mutate(execution_payload)
    executor_envelope["payload_sha256"] = canonical_sha256(execution_payload)
    executor_envelope_bytes = canonical_json_bytes(executor_envelope)
    receipt["executor_envelope"] = _bytes(
        executor_envelope_bytes,
        G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
    )
    receipt["executor_envelope_sha256"] = hashlib.sha256(
        executor_envelope_bytes
    ).hexdigest()
    receipt["execution_payload_sha256"] = canonical_sha256(execution_payload)
    receipt["case_id"] = execution_payload["case_id"]
    receipt["engine"] = execution_payload["engine"]
    receipt["execution_nonce"] = execution_payload["execution_nonce"]
    emitted = execution_payload["emitted_trace"]
    assert isinstance(emitted, dict)
    emitted_raw = base64.b64decode(emitted["base64"], validate=True)
    receipt["emitted_trace_sha256"] = hashlib.sha256(emitted_raw).hexdigest()
    receipt["parser_result"] = _observed_parser_result(emitted_raw)
    envelope["payload_sha256"] = canonical_sha256(receipt)
    _regenerate_unsigned_corpora(evidence)


def _mutate_emitted_bytes_and_stdout(payload: dict[str, object]) -> None:
    emitted_trace = _bytes(canonical_json_bytes(_trace("DRAW")), "application/json")
    payload["emitted_trace"] = emitted_trace
    payload["stdout"] = _bytes(
        _stdout(
            case_id=payload["case_id"],  # type: ignore[arg-type]
            corpus_kind=payload["corpus_kind"],  # type: ignore[arg-type]
            trace_sha256=emitted_trace["sha256"],  # type: ignore[arg-type]
            negative_class=payload["negative_class"],  # type: ignore[arg-type]
        ),
        "application/json",
    )


def _derive(
    evidence: dict[str, object],
    keys: dict[str, Ed25519PrivateKey],
) -> dict[str, object]:
    return derive_engine_event_capability_outputs(
        evidence,
        source_executor_public_key=_public(keys["source_executor"]),
        wrapper_executor_public_key=_public(keys["wrapper_executor"]),
        trace_attestor_public_key=_public(keys["trace"]),
    )


def test_g02_requires_complete_signed_executions_and_has_no_local_authority() -> None:
    evidence, keys = _evidence()
    outputs = _derive(evidence, keys)
    assert outputs["decision"] == "PASS_RESEARCH_ONLY"
    assert outputs["failure_codes"] == []
    assert outputs["positive_event_types_by_engine"]["source"] == list(EVENT_VOCABULARY)
    assert outputs["positive_terminal_identities_by_engine"]["wrapper"] == list(
        TERMINAL_IDENTITIES
    )
    assert outputs["negative_case_classes"] == list(NEGATIVE_CASE_CLASSES)
    assert outputs["execution_receipt_root_sha256"]
    assert outputs["source_executor_envelope_root_sha256"]
    assert outputs["wrapper_executor_envelope_root_sha256"]
    assert outputs["parser_rerun_case_count"] == (
        2 * (len(TERMINAL_IDENTITIES) + len(NEGATIVE_CASE_CLASSES))
    )
    assert outputs["executor_signature_verified_case_count"] == outputs[
        "parser_rerun_case_count"
    ]
    assert outputs["attestor_signature_verified_case_count"] == outputs[
        "parser_rerun_case_count"
    ]
    for field in (
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "release_authorized",
        "submission_authorized",
    ):
        assert outputs[field] is False

    result = verify_engine_event_capability_gate(
        evidence=evidence,
        final_bundle=_caller_signed_false_pass_bundle(),
        source_executor_public_key=_public(keys["source_executor"]),
        wrapper_executor_public_key=_public(keys["wrapper_executor"]),
        trace_attestor_public_key=_public(keys["trace"]),
    )
    assert result["decision"] == "REJECTED_INVALID_ENVELOPE"
    assert result["failure_codes"] == ["VERIFIER_NOT_ALLOWLISTED"]

    with pytest.raises(
        EngineCapabilityError, match="EXACT_GATE_V2_SERVICE_REQUIRED"
    ):
        derive_engine_event_capability_gate_payload(
            evidence=evidence,
            source_executor_public_key=_public(keys["source_executor"]),
            wrapper_executor_public_key=_public(keys["wrapper_executor"]),
            trace_attestor_public_key=_public(keys["trace"]),
            campaign_root=evidence["campaign_root"],  # type: ignore[arg-type]
            evaluation_id=evidence["evaluation_id"],  # type: ignore[arg-type]
            frozen_spec_hash=evidence["frozen_spec_hash"],  # type: ignore[arg-type]
            dependency_roots=evidence["dependency_roots"],  # type: ignore[arg-type]
            campaign_registry_hash=evidence["campaign_registry_hash"],  # type: ignore[arg-type]
            evidence_manifest_root=evidence["evidence_manifest_root"],  # type: ignore[arg-type]
            verifier_module_digest=evidence["verifier_module_digest"],  # type: ignore[arg-type]
        )


def test_attestor_signed_handcrafted_execution_without_executor_signature_fails() -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    receipt = deepcopy(envelopes[0]["payload"])
    execution_payload = _execution_payload_at(evidence)
    handcrafted_bytes = canonical_json_bytes(execution_payload)
    receipt["executor_envelope"] = _bytes(
        handcrafted_bytes,
        G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
    )
    receipt["executor_envelope_sha256"] = hashlib.sha256(
        handcrafted_bytes
    ).hexdigest()
    receipt["execution_payload_sha256"] = canonical_sha256(execution_payload)
    envelopes[0] = _signed(G02_EXECUTION_RECEIPT_SCHEMA, receipt, keys["trace"])
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTOR_SIGNATURE_ENCODING"]


@pytest.mark.parametrize(
    "mutate",
    [
        _mutate_emitted_bytes_and_stdout,
        lambda payload: payload["argv"].append("--unfrozen"),
        lambda payload: payload["env"].__setitem__("LD_PRELOAD", "/tmp/inject.so"),
        lambda payload: payload.__setitem__("working_tree_input_inventory_root", _hash(900)),
        lambda payload: payload.__setitem__("status", "FAILED"),
        lambda payload: payload.__setitem__("retry_count", 1),
    ],
    ids=("output", "argv", "env", "workspace", "status", "retry"),
)
def test_execution_mutation_cannot_be_rescued_by_unsigned_corpus_summary(mutate) -> None:
    evidence, keys = _evidence()
    _unsigned_mutation(evidence, mutate)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTION_RECEIPT_SIGNATURE"]


def test_signed_semantic_execution_mutations_fail_closed() -> None:
    mutations = {
        "argv": (lambda payload: payload["argv"].append("--unfrozen"), "EXECUTION_ARGV"),
        "env": (
            lambda payload: payload["env"].__setitem__("LD_PRELOAD", "/tmp/inject.so"),
            "EXECUTION_ENV",
        ),
        "workspace": (
            lambda payload: payload.__setitem__("post_run_inventory_root", _hash(901)),
            "POST_RUN_INVENTORY",
        ),
        "status": (lambda payload: payload.__setitem__("status", "FAILED"), "STATUS"),
        "retry": (lambda payload: payload.__setitem__("retry_count", 1), "RETRY_COUNT"),
    }
    for name, (mutate, reason) in mutations.items():
        evidence, keys = _evidence()
        payload = _execution_payload_at(evidence)
        mutate(payload)
        _replace_signed_execution(evidence, keys, payload)
        failed = _derive(evidence, keys)
        if name == "argv":
            assert "EXECUTION_ARGV" in failed["failure_codes"][0]
        else:
            assert reason in failed["failure_codes"][0]


def test_signed_wrong_negative_execution_result_fails_closed() -> None:
    evidence, keys = _evidence()
    payload = _execution_payload_at(evidence)
    emitted_trace = payload["emitted_trace"]
    assert isinstance(emitted_trace, dict)
    payload["stdout"] = _bytes(
        _stdout(
            case_id=payload["case_id"],  # type: ignore[arg-type]
            corpus_kind="negative",
            trace_sha256=emitted_trace["sha256"],  # type: ignore[arg-type]
            negative_class="DUPLICATE_EVENT_ID",
        ),
        "application/json",
    )
    _replace_signed_execution(evidence, keys, payload)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTION_STDOUT"]


def test_negative_case_must_use_exact_frozen_parser_fixture() -> None:
    evidence, keys = _evidence()
    payload = _execution_payload_at(evidence)
    payload["input_fixture"] = _bytes(
        canonical_json_bytes(_trace("DRAW")), "application/json"
    )
    inventory = derive_execution_inventory_root(payload)
    payload["working_tree_input_inventory_root"] = inventory
    payload["post_run_inventory_root"] = inventory
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    envelopes[0] = _receipt_for_execution(payload, evidence=evidence, keys=keys)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTION_INPUT_FIXTURE"]


def test_omitted_negative_execution_and_mutated_raw_wrapper_fail_closed() -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    del envelopes[0]
    _regenerate_unsigned_corpora(evidence)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_NEGATIVE_CORPUS_COVERAGE"]

    evidence, keys = _evidence()
    evidence["positive_corpus"]["base64"] += "="  # type: ignore[index]
    failed = _derive(evidence, keys)
    assert failed["decision"] == "FAIL_CLOSED"
    assert "BYTE_EVIDENCE" in failed["failure_codes"][0]


def test_campaign_replay_and_signed_artifact_identity_drift_fail_closed() -> None:
    for field, value in (
        ("campaign_root", _hash(998)),
        ("g02_frozen_at_utc", "2026-07-15T00:00:00.000000Z"),
    ):
        evidence, keys = _evidence()
        evidence[field] = value
        failed = _derive(evidence, keys)
        assert failed["failure_codes"] == [
            "FAIL_G02_EXECUTION_BINDING_MISMATCH"
        ]

    for field in ("parser_sha256", "package_sha256"):
        evidence, keys = _evidence()
        payload = _execution_payload_at(evidence)
        payload[field] = _hash(999)
        _replace_signed_execution(evidence, keys, payload)
        failed = _derive(evidence, keys)
        assert failed["failure_codes"] == [
            "FAIL_G02_EXECUTION_ARTIFACT_MISMATCH"
        ]


def test_nonce_is_unique_and_disjoint_across_engines() -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    source_nonce = next(
        envelope["payload"]["execution_nonce"]
        for envelope in envelopes
        if envelope["payload"]["engine"] == "source"
    )
    wrapper_index = next(
        index
        for index, envelope in enumerate(envelopes)
        if envelope["payload"]["engine"] == "wrapper"
    )
    payload = _execution_payload_at(evidence, wrapper_index)
    payload["execution_nonce"] = source_nonce
    _replace_signed_execution(evidence, keys, payload, index=wrapper_index)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTION_NONCE_REUSE"]


def test_executor_and_attestor_key_reuse_fails_before_receipt_validation() -> None:
    evidence, keys = _evidence()
    reused = keys["source_executor"]
    evidence["trace_attestor_key"] = _key_record(
        role="trace_attestor",
        principal_id="principal-trace-attestor",
        custodian_id="custodian-trace-attestor",
        private_key=reused,
    )
    keys["trace"] = reused
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_CUSTODY_KEY_REUSE"]


@pytest.mark.parametrize(
    ("role", "evidence_field", "key_name"),
    (
        ("source_executor", "source_executor_key", "source_executor"),
        ("wrapper_executor", "wrapper_executor_key", "wrapper_executor"),
        ("trace_attestor", "trace_attestor_key", "trace"),
    ),
)
@pytest.mark.parametrize("point_kind", ("noncanonical", "small_order", "mixed_order"))
def test_g02_rejects_non_prime_subgroup_public_keys_before_verification(
    role: str,
    evidence_field: str,
    key_name: str,
    point_kind: str,
) -> None:
    evidence, keys = _evidence()
    bad_public = _adversarial_point_encoding(point_kind, _public(keys[key_name]))
    key_record = evidence[evidence_field]
    assert isinstance(key_record, dict)
    key_record["public_key_base64"] = base64.b64encode(bad_public).decode("ascii")
    key_record["key_id"] = f"ed25519-sha256:{hashlib.sha256(bad_public).hexdigest()}"
    pins = {
        "source_executor": _public(keys["source_executor"]),
        "wrapper_executor": _public(keys["wrapper_executor"]),
        "trace": _public(keys["trace"]),
    }
    pins[key_name] = bad_public
    failed = derive_engine_event_capability_outputs(
        evidence,
        source_executor_public_key=pins["source_executor"],
        wrapper_executor_public_key=pins["wrapper_executor"],
        trace_attestor_public_key=pins["trace"],
    )
    assert failed["failure_codes"] == [
        f"FAIL_G02_{role.upper()}_PUBLIC_KEY_ENCODING"
    ]


@pytest.mark.parametrize("signer", ("source", "wrapper", "trace_attestor"))
@pytest.mark.parametrize(
    "signature_kind",
    ("noncanonical", "small_order", "mixed_order", "s_out_of_range"),
)
def test_g02_rejects_noncanonical_signature_encodings_before_verification(
    signer: str,
    signature_kind: str,
) -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    if signer == "trace_attestor":
        envelope = deepcopy(envelopes[0])
        envelope["signature_ed25519_base64"] = _adversarial_signature(
            envelope["signature_ed25519_base64"],  # type: ignore[arg-type]
            signature_kind,
        )
        envelopes[0] = envelope
        expected = "FAIL_G02_TRACE_ATTESTOR_SIGNATURE_ENCODING"
    else:
        index = next(
            position
            for position, receipt in enumerate(envelopes)
            if receipt["payload"]["engine"] == signer
        )
        receipt = deepcopy(envelopes[index]["payload"])
        executor_envelope = _executor_envelope_at(evidence, index)
        executor_envelope["signature_ed25519_base64"] = _adversarial_signature(
            executor_envelope["signature_ed25519_base64"],  # type: ignore[arg-type]
            signature_kind,
        )
        executor_bytes = canonical_json_bytes(executor_envelope)
        receipt["executor_envelope"] = _bytes(
            executor_bytes,
            G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
        )
        receipt["executor_envelope_sha256"] = hashlib.sha256(
            executor_bytes
        ).hexdigest()
        envelopes[index] = _signed(
            G02_EXECUTION_RECEIPT_SCHEMA,
            receipt,
            keys["trace"],
        )
        expected = "FAIL_G02_EXECUTOR_SIGNATURE_ENCODING"
    _regenerate_unsigned_corpora(evidence)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == [expected]


@pytest.mark.parametrize(
    ("field", "failure_code"),
    (
        ("principal_id", "FAIL_G02_CUSTODY_PRINCIPAL_REUSE"),
        ("custodian_id", "FAIL_G02_CUSTODY_CUSTODIAN_REUSE"),
    ),
)
def test_executor_and_attestor_custody_identity_reuse_fails(
    field: str,
    failure_code: str,
) -> None:
    evidence, keys = _evidence()
    source_key = evidence["source_executor_key"]
    trace_key = evidence["trace_attestor_key"]
    assert isinstance(source_key, dict)
    assert isinstance(trace_key, dict)
    trace_key[field] = source_key[field]
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == [failure_code]


def test_executor_signature_must_precede_trace_attestation() -> None:
    evidence, keys = _evidence()
    payload = _execution_payload_at(evidence)
    payload["executor_signed_at_utc"] = "2026-07-13T00:00:00.000000Z"
    _replace_signed_execution(evidence, keys, payload)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTION_FREEZE_CHRONOLOGY"]


def test_attestor_countersignature_cannot_rescue_mutated_executor_envelope() -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    receipt = deepcopy(envelopes[0]["payload"])
    executor_envelope = _executor_envelope_at(evidence)
    execution_payload = executor_envelope["payload"]
    assert isinstance(execution_payload, dict)
    execution_payload["retry_count"] = 1
    executor_envelope["payload_sha256"] = canonical_sha256(execution_payload)
    mutated_bytes = canonical_json_bytes(executor_envelope)
    receipt["executor_envelope"] = _bytes(
        mutated_bytes,
        G02_EXECUTOR_ENVELOPE_MEDIA_TYPE,
    )
    receipt["executor_envelope_sha256"] = hashlib.sha256(mutated_bytes).hexdigest()
    receipt["execution_payload_sha256"] = canonical_sha256(execution_payload)
    envelopes[0] = _signed(G02_EXECUTION_RECEIPT_SCHEMA, receipt, keys["trace"])
    _regenerate_unsigned_corpora(evidence)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_EXECUTOR_SIGNATURE"]


def test_attestor_parser_result_is_recomputed_from_executor_bytes() -> None:
    evidence, keys = _evidence()
    envelopes = evidence["execution_receipt_envelopes"]
    assert isinstance(envelopes, list)
    receipt = deepcopy(envelopes[0]["payload"])
    parser_result = receipt["parser_result"]
    assert isinstance(parser_result, dict)
    parser_result["failure_code"] = "FAIL_G02_BAD_DAMAGE_AMOUNT"
    envelopes[0] = _signed(G02_EXECUTION_RECEIPT_SCHEMA, receipt, keys["trace"])
    _regenerate_unsigned_corpora(evidence)
    failed = _derive(evidence, keys)
    assert failed["failure_codes"] == ["FAIL_G02_ATTESTOR_PARSER_RESULT"]


def test_event_parser_still_rejects_duplicate_json_and_noncanonical_bytes() -> None:
    duplicate = (
        b'{"events":[],"events":[],"schema_version":"evaluation_v5_1_g02_engine_event_trace_v1"}'
    )
    with pytest.raises(EngineCapabilityError, match="DUPLICATE_JSON_KEY"):
        parse_engine_event_trace(duplicate, canary_seat=0)
    noncanonical = canonical_json_bytes(_trace("DRAW")).replace(b",", b", ", 1)
    with pytest.raises(EngineCapabilityError, match="NONCANONICAL_JSON_BYTES"):
        parse_engine_event_trace(noncanonical, canary_seat=0)


def test_stale_revoked_or_wrong_trace_role_fails_closed() -> None:
    for field, value, reason in (
        ("role", "validator", "TRACE_ATTESTOR_ROLE"),
        ("valid_until_utc", "2026-07-13T00:00:00.000000Z", "KEY_STALE"),
        ("revoked", True, "KEY_REVOKED"),
    ):
        evidence, keys = _evidence()
        evidence["trace_attestor_key"][field] = value  # type: ignore[index]
        failed = _derive(evidence, keys)
        assert reason in failed["failure_codes"][0]


def test_final_verifier_recomputes_receipts_before_shared_v2_dispatch() -> None:
    evidence, keys = _evidence()
    _unsigned_mutation(evidence, lambda payload: payload.__setitem__("retry_count", 1))
    result = verify_engine_event_capability_gate(
        evidence=evidence,
        final_bundle={},
        source_executor_public_key=_public(keys["source_executor"]),
        wrapper_executor_public_key=_public(keys["wrapper_executor"]),
        trace_attestor_public_key=_public(keys["trace"]),
    )
    assert result["decision"] == "FAIL_CLOSED"
    assert result["failure_codes"] == ["FAIL_G02_EXECUTION_RECEIPT_SIGNATURE"]
