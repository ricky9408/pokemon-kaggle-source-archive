from __future__ import annotations

from hashlib import sha256
import hmac

import pytest

import evaluation_v6_3_1.unified_rng_resume as resume_module
from evaluation_v6_3_1.unified_rng_protocol import (
    PROTOCOL_VERSION,
    DS_STATE,
    ZERO_ID,
    UnifiedRngProtocolError,
    canonical_cbor_encode,
    derive_stream_id,
)
from evaluation_v6_3_1.unified_rng_resume import (
    CHECKPOINT_EVENT_TYPE,
    DS_EVENT_302,
    DS_RESUME_CAP,
    DS_RESUME_COMMIT,
    DS_RESUME_PROOF,
    DS_RESUME_SESSION,
    PRIVATE_RESUME_CAPSULE,
    DurableCheckpoint,
    InMemoryResumeVerifier,
    UnifiedRngResumeError,
    build_checkpoint_core,
    build_private_resume_capsule,
    checkpoint_event_hash,
    decode_private_resume_capsule,
    derive_resume_capability,
    derive_resume_capability_commitment,
    derive_resume_capability_proof,
    derive_session_resume_key,
    verify_resume_capability,
    verify_resume_capability_commitment,
    verify_resume_capability_proof,
    verify_session_resume_key,
)


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


SECRET = _root("evaluator-secret")
SESSION = _root("session")
RUN_ROOT = _root("run-root")
STATE_ROOT = _root("gateway-state")
SITE = _root("site")
OBJECT = _root("object")
STREAM = derive_stream_id(SESSION, SITE, OBJECT, 7, 3)


def _trace_prefix(session_id: bytes) -> tuple[bytes, bytes, bytes]:
    stream = derive_stream_id(session_id, SITE, OBJECT, 7, 3)
    records: list[bytes] = []
    previous_global = ZERO_ID
    previous_stream = ZERO_ID
    for sequence in range(17):
        if sequence == 0:
            event_type = 3
            payload = [SITE, OBJECT, 7, 3]
            stream_previous = ZERO_ID
        else:
            event_type = 4
            payload = [ZERO_ID, sequence - 1, sequence]
            stream_previous = previous_stream
        event = [
            PROTOCOL_VERSION,
            event_type,
            session_id,
            sequence,
            previous_global,
            stream,
            stream_previous,
            ZERO_ID,
            ZERO_ID,
            payload,
        ]
        raw = canonical_cbor_encode(event)
        current = sha256(DS_EVENT_302 + raw).digest()
        records.append(raw)
        previous_global = current
        previous_stream = current
    return b"".join(records), previous_global, previous_stream


def _checkpoint(
    *,
    session_id: bytes = SESSION,
    offset: int | None = None,
    latest: bool = True,
    successor: bool = False,
):
    prefix, prefix_head, prefix_stream_head = _trace_prefix(session_id)
    declared_offset = len(prefix) if offset is None else offset
    stream = derive_stream_id(session_id, SITE, OBJECT, 7, 3)
    rows = [[stream, 16, 0, 0, 0, prefix_stream_head]]
    state_root = sha256(
        DS_STATE
        + canonical_cbor_encode(
            [session_id, 0, 18, declared_offset, rows]
        )
    ).digest()
    core = build_checkpoint_core(session_id, 0, 0, 18, declared_offset, state_root)
    key = derive_session_resume_key(SECRET, session_id, RUN_ROOT)
    capability = derive_resume_capability(key, core)
    commitment = derive_resume_capability_commitment(core, capability)
    event = [
        PROTOCOL_VERSION,
        CHECKPOINT_EVENT_TYPE,
        session_id,
        17,
        prefix_head,
        bytes(32),
        bytes(32),
        bytes(32),
        bytes(32),
        [0, 0, 18, declared_offset, rows, commitment, state_root],
    ]
    event_bytes = canonical_cbor_encode(event)
    assert core.next_global_sequence == event[3] + 1
    checkpoint = DurableCheckpoint(
        core,
        checkpoint_event_hash(event_bytes),
        commitment,
        event_bytes,
        prefix + event_bytes,
        latest,
        successor,
    )
    capsule = build_private_resume_capsule(
        session_id,
        0,
        checkpoint.checkpoint_event_hash,
        state_root,
        capability,
    )
    proof = derive_resume_capability_proof(
        session_id,
        0,
        checkpoint.checkpoint_event_hash,
        0,
        1,
        state_root,
        capability,
    )
    return core, capability, commitment, checkpoint, capsule, proof


def _verifier(
    checkpoint: DurableCheckpoint,
    capsule,
) -> InMemoryResumeVerifier:
    return InMemoryResumeVerifier(
        SECRET,
        RUN_ROOT,
        checkpoint,
        capsule,
    )


def _assert_code(code: str, fn, *args, **kwargs) -> None:
    with pytest.raises(UnifiedRngResumeError) as raised:
        fn(*args, **kwargs)
    assert raised.value.code == code


def test_exact_resume_derivations_use_frozen_domains_and_cbor() -> None:
    core, capability, commitment, checkpoint, capsule, proof = _checkpoint()
    expected_key = hmac.new(
        SECRET,
        DS_RESUME_SESSION + canonical_cbor_encode([PROTOCOL_VERSION, SESSION, RUN_ROOT]),
        "sha256",
    ).digest()
    assert derive_session_resume_key(SECRET, SESSION, RUN_ROOT) == expected_key
    assert capability == hmac.new(
        expected_key,
        DS_RESUME_CAP + core.to_bytes(),
        "sha256",
    ).digest()
    assert commitment == sha256(
        DS_RESUME_COMMIT
        + canonical_cbor_encode(
            [PROTOCOL_VERSION, SESSION, core.checkpoint_id, core.gateway_state_root, capability]
        )
    ).digest()
    assert proof == sha256(
        DS_RESUME_PROOF
        + canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                SESSION,
                core.checkpoint_id,
                checkpoint.checkpoint_event_hash,
                0,
                1,
                core.gateway_state_root,
                capability,
            ]
        )
    ).digest()
    assert capsule.as_array() == [
        PROTOCOL_VERSION,
        PRIVATE_RESUME_CAPSULE,
        SESSION,
        core.checkpoint_id,
        checkpoint.checkpoint_event_hash,
        core.gateway_state_root,
        capability,
    ]
    assert "resume_capability" not in repr(capsule) or "<redacted>" in repr(capsule)


def test_independent_node_resume_vectors() -> None:
    core = build_checkpoint_core(SESSION, 9, 4, 18, 123, STATE_ROOT)
    session_key = derive_session_resume_key(SECRET, SESSION, RUN_ROOT)
    capability = derive_resume_capability(session_key, core)
    commitment = derive_resume_capability_commitment(core, capability)
    proof = derive_resume_capability_proof(
        SESSION,
        9,
        _root("checkpoint-event-hash"),
        4,
        5,
        STATE_ROOT,
        capability,
    )
    assert session_key.hex() == "da9d105f3a1e19164199d4e3847d5056d255933c365013e00bbb0607b1598974"
    assert capability.hex() == "d5d37913e5034c2050def562553342a53d314b25d473d00068d7730b000bab6a"
    assert commitment.hex() == "f74bb0efb8f118b8170245c81c256b04c30af42b275566da656879384c9e9e64"
    assert proof.hex() == "e767248c2ce3e80c5ee3661b6b385e0b866fda723ef2b52ff12527c2fecfc3d9"


def test_wrong_run_root_or_session_key_context_fails_closed() -> None:
    key = derive_session_resume_key(SECRET, SESSION, RUN_ROOT)
    _assert_code("RNG_RESUME_SESSION_KEY_CONTEXT_INVALID", verify_session_resume_key, key, SECRET, SESSION, _root("wrong-run"))
    _assert_code("RNG_RESUME_SESSION_KEY_CONTEXT_INVALID", verify_session_resume_key, key, SECRET, _root("wrong-session"), RUN_ROOT)


def test_forged_commitment_and_capability_are_rejected() -> None:
    core, capability, commitment, *_ = _checkpoint()
    _assert_code("RNG_RESUME_CAPABILITY_COMMITMENT_MISMATCH", verify_resume_capability_commitment, _root("forged"), core, capability)
    _assert_code("RNG_RESUME_CAPABILITY_DERIVATION_MISMATCH", verify_resume_capability, _root("forged"), derive_session_resume_key(SECRET, SESSION, RUN_ROOT), core)


def test_private_capsule_schema_and_premature_disclosure_fail_closed() -> None:
    core, *_prefix, checkpoint, capsule, _proof = _checkpoint()
    _assert_code(
        "RNG_RESUME_CAPABILITY_PREMATURE_DISCLOSURE",
        build_private_resume_capsule,
        SESSION,
        core.checkpoint_id,
        checkpoint.checkpoint_event_hash,
        core.gateway_state_root,
        capsule.resume_capability,
        checkpoint_durable=False,
    )
    bad = canonical_cbor_encode(
        [
            PROTOCOL_VERSION,
            99,
            SESSION,
            core.checkpoint_id,
            checkpoint.checkpoint_event_hash,
            core.gateway_state_root,
            capsule.resume_capability,
        ]
    )
    _assert_code("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", decode_private_resume_capsule, bad)
    _assert_code("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", decode_private_resume_capsule, capsule.to_bytes()[:-1])


def test_forged_proof_generation_and_offset_do_not_consume_capability() -> None:
    _core, capability, _commitment, checkpoint, capsule, proof = _checkpoint()
    verifier = _verifier(checkpoint, capsule)
    _assert_code(
        "RNG_RESUME_PROOF_MISMATCH",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=_root("forged-proof"),
    )
    assert verifier.state == "UNUSED"
    _assert_code(
        "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
        actual_trace_bytes=b"\xff" + checkpoint.durable_trace_bytes[1:],
    )
    assert verifier.state == "UNUSED"
    _assert_code(
        "RNG_TRACE_TRAILING_PARTIAL_EVENT",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
        actual_trace_bytes=checkpoint.durable_trace_bytes + b"\x8a",
    )
    assert verifier.state == "UNUSED"
    _assert_code(
        "RNG_RESUME_CAPABILITY_DERIVATION_MISMATCH",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
        resume_capability_opening=_root("forged-opening"),
    )
    assert verifier.state == "UNUSED"
    _assert_code(
        "RNG_RESTORE_REGISTRY_GENERATION_INVALID",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=2,
        resume_capability_proof=proof,
    )
    assert verifier.state == "UNUSED"
    _assert_code(
        "RNG_RESTORE_TRACE_LENGTH_MISMATCH",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
        actual_trace_bytes=checkpoint.durable_trace_bytes + b"trailing",
    )
    assert verifier.state == "UNUSED"


def test_successful_restore_is_single_use_and_invalidates_handles() -> None:
    core, capability, _commitment, checkpoint, capsule, proof = _checkpoint(
        session_id=_root("single-use-session")
    )
    verifier = _verifier(checkpoint, capsule)
    copied_verifier = _verifier(checkpoint, capsule.to_bytes())
    transition = verifier.restore(
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
    )
    assert transition.restore_payload == (
        core.checkpoint_id,
        checkpoint.checkpoint_event_hash,
        0,
        1,
        core.gateway_state_root,
        capability,
        proof,
        len(checkpoint.durable_trace_bytes),
    )
    assert verifier.state == "CONSUMED"
    assert verifier.registry_generation == 1
    assert verifier.handles_valid is False
    assert verifier.sensitive_material_destroyed is True
    assert copied_verifier.state == "CONSUMED"
    assert copied_verifier.registry_generation == 1
    assert copied_verifier.handles_valid is False
    _assert_code(
        "RNG_RESUME_CAPABILITY_REUSED",
        copied_verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
    )


def test_process_registry_is_not_caller_selectable() -> None:
    _core, _capability, _commitment, checkpoint, capsule, _proof = _checkpoint()
    assert not hasattr(resume_module, "InMemoryResumeRegistry")
    with pytest.raises(TypeError):
        InMemoryResumeVerifier(
            SECRET,
            RUN_ROOT,
            checkpoint,
            capsule,
            registry=object(),  # type: ignore[call-arg]
        )


def test_canonical_but_schema_invalid_trace_prefix_is_rejected() -> None:
    session_id = _root("schema-invalid-session")
    stream = derive_stream_id(session_id, SITE, OBJECT, 7, 3)
    invalid_event = canonical_cbor_encode(
        [
            PROTOCOL_VERSION,
            3,
            session_id,
            0,
            ZERO_ID,
            stream,
            ZERO_ID,
            ZERO_ID,
            ZERO_ID,
            [],
        ]
    )
    invalid_hash = sha256(DS_EVENT_302 + invalid_event).digest()
    offset = len(invalid_event)
    state_root = sha256(
        DS_STATE + canonical_cbor_encode([session_id, 0, 2, offset, []])
    ).digest()
    core = build_checkpoint_core(session_id, 0, 0, 2, offset, state_root)
    key = derive_session_resume_key(SECRET, session_id, RUN_ROOT)
    capability = derive_resume_capability(key, core)
    commitment = derive_resume_capability_commitment(core, capability)
    checkpoint_event = canonical_cbor_encode(
        [
            PROTOCOL_VERSION,
            CHECKPOINT_EVENT_TYPE,
            session_id,
            1,
            invalid_hash,
            ZERO_ID,
            ZERO_ID,
            ZERO_ID,
            ZERO_ID,
            [0, 0, 2, offset, [], commitment, state_root],
        ]
    )
    checkpoint_hash = checkpoint_event_hash(checkpoint_event)
    checkpoint = DurableCheckpoint(
        core,
        checkpoint_hash,
        commitment,
        checkpoint_event,
        invalid_event + checkpoint_event,
    )
    capsule = build_private_resume_capsule(
        session_id,
        0,
        checkpoint_hash,
        state_root,
        capability,
    )
    proof = derive_resume_capability_proof(
        session_id,
        0,
        checkpoint_hash,
        0,
        1,
        state_root,
        capability,
    )
    verifier = _verifier(checkpoint, capsule)
    _assert_code(
        "RNG_CANONICAL_CBOR_MISMATCH",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
    )


def test_wrong_checkpoint_status_and_offset_are_rejected() -> None:
    _core, _capability, _commitment, checkpoint, capsule, proof = _checkpoint(latest=False)
    verifier = _verifier(checkpoint, capsule)
    _assert_code(
        "RNG_RESTORE_CHECKPOINT_NOT_LATEST",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
    )

    _core, _capability, _commitment, checkpoint, capsule, proof = _checkpoint(successor=True)
    verifier = _verifier(checkpoint, capsule)
    _assert_code(
        "RNG_RESTORE_CHECKPOINT_SUCCESSOR_EXISTS",
        verifier.restore,
        old_registry_generation=0,
        new_registry_generation=1,
        resume_capability_proof=proof,
    )


def test_checkpoint_event_hash_is_canonical_event_hash() -> None:
    _core, _capability, _commitment, checkpoint, _capsule, _proof = _checkpoint()
    assert checkpoint_event_hash(checkpoint.checkpoint_event_bytes) == sha256(
        DS_EVENT_302 + checkpoint.checkpoint_event_bytes
    ).digest()
    with pytest.raises(UnifiedRngProtocolError):
        canonical_cbor_encode({"not": "normative"})
