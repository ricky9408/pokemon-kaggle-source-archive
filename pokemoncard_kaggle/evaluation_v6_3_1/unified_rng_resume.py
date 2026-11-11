"""Offline, zero-authority resume capability conformance for V631-RNG-3A/1.

This module implements only the resume records and an in-memory, single-use
restore transition from the 2026-07-21 Sol amendment.  It has no file, gateway,
upload, holdout, or campaign authority.  ``PROTOCOL_VERSION`` is imported from
the parent protocol module so its 631302 migration remains one source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
from threading import Lock
from typing import Any, Final

from .unified_rng_protocol import (
    CanonicalCborTruncated,
    DS_EVENT_302,
    DS_RESUME_CAP,
    DS_RESUME_COMMIT,
    DS_RESUME_PROOF,
    DS_RESUME_SESSION,
    PROTOCOL_VERSION,
    RETIRED_PROTOCOL_VERSION,
    UINT64_MAX,
    ZERO_ID,
    UnifiedRngProtocolError,
    canonical_cbor_decode,
    canonical_cbor_decode_prefix,
    canonical_cbor_encode,
)


ZERO32: Final = ZERO_ID
CHECKPOINT_EVENT_TYPE: Final = 10
PRIVATE_RESUME_CAPSULE: Final = 14
PRIVATE_RESUME_CAPSULE_TYPE: Final = PRIVATE_RESUME_CAPSULE

class UnifiedRngResumeError(UnifiedRngProtocolError):
    """A resume record or local restore transition failed closed."""


def _fail(code: str, message: str) -> UnifiedRngResumeError:
    return UnifiedRngResumeError(code, message)


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", f"{label} must be a 32-byte bstr")
    return value


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", f"{label} must be a uint64")
    return value


def _array(value: bytes | list[Any], size: int, label: str) -> list[Any]:
    if type(value) is bytes:
        try:
            value = canonical_cbor_decode(value)
        except UnifiedRngProtocolError as exc:
            raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", f"{label} is not canonical CBOR") from exc
    if type(value) is not list or len(value) != size:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", f"{label} must have {size} array fields")
    return value


def _version(value: Any, label: str) -> None:
    if value == RETIRED_PROTOCOL_VERSION:
        raise _fail("RNG_PROTOCOL_631301_RETIRED", f"{label} uses retired protocol 631301")
    if value != PROTOCOL_VERSION:
        raise _fail("RNG_EVENT_ENVELOPE_VERSION_MISMATCH", f"{label} has the retired or mixed protocol version")


def _digest(domain: bytes, value: list[Any]) -> bytes:
    return sha256(domain + canonical_cbor_encode(value)).digest()


def _hmac(key: bytes, domain: bytes, value: list[Any]) -> bytes:
    return hmac.new(key, domain + canonical_cbor_encode(value), "sha256").digest()


def _constant_time_equal(actual: bytes, expected: bytes, code: str, message: str) -> None:
    if not hmac.compare_digest(actual, expected):
        raise _fail(code, message)


@dataclass(frozen=True, slots=True)
class CheckpointCore:
    """The exact seven-field checkpoint core from amendment section 3.2."""

    session_id: bytes
    checkpoint_id: int
    registry_generation: int
    next_global_sequence: int
    trace_byte_offset: int
    gateway_state_root: bytes

    def __post_init__(self) -> None:
        _root(self.session_id, "session_id")
        _u64(self.checkpoint_id, "checkpoint_id")
        _u64(self.registry_generation, "registry_generation")
        _u64(self.next_global_sequence, "next_global_sequence")
        _u64(self.trace_byte_offset, "trace_byte_offset")
        _root(self.gateway_state_root, "gateway_state_root")

    def as_array(self) -> list[Any]:
        return [
            PROTOCOL_VERSION,
            self.session_id,
            self.checkpoint_id,
            self.registry_generation,
            self.next_global_sequence,
            self.trace_byte_offset,
            self.gateway_state_root,
        ]

    def to_bytes(self) -> bytes:
        return canonical_cbor_encode(self.as_array())


def build_checkpoint_core(
    session_id: bytes,
    checkpoint_id: int,
    registry_generation: int,
    next_global_sequence: int,
    trace_byte_offset: int,
    gateway_state_root: bytes,
) -> CheckpointCore:
    return CheckpointCore(
        session_id,
        checkpoint_id,
        registry_generation,
        next_global_sequence,
        trace_byte_offset,
        gateway_state_root,
    )


make_checkpoint_core = build_checkpoint_core


def decode_checkpoint_core(raw: bytes | list[Any]) -> CheckpointCore:
    fields = _array(raw, 7, "checkpoint_core")
    _version(fields[0], "checkpoint_core")
    return CheckpointCore(
        _root(fields[1], "session_id"),
        _u64(fields[2], "checkpoint_id"),
        _u64(fields[3], "registry_generation"),
        _u64(fields[4], "next_global_sequence"),
        _u64(fields[5], "trace_byte_offset"),
        _root(fields[6], "gateway_state_root"),
    )


def checkpoint_core(
    session_id: bytes,
    checkpoint_id: int,
    registry_generation: int,
    next_global_sequence: int,
    trace_byte_offset: int,
    gateway_state_root: bytes,
) -> list[Any]:
    """Return the normative checkpoint-core array."""
    return build_checkpoint_core(
        session_id,
        checkpoint_id,
        registry_generation,
        next_global_sequence,
        trace_byte_offset,
        gateway_state_root,
    ).as_array()


def _coerce_core(value: CheckpointCore | bytes | list[Any]) -> CheckpointCore:
    return value if isinstance(value, CheckpointCore) else decode_checkpoint_core(value)


def derive_session_resume_key(
    evaluator_secret: bytes,
    session_id: bytes,
    run_binding_root: bytes,
) -> bytes:
    """Derive the non-serializable session key bound to one run context."""
    return _hmac(
        _root(evaluator_secret, "evaluator_secret"),
        DS_RESUME_SESSION,
        [PROTOCOL_VERSION, _root(session_id, "session_id"), _root(run_binding_root, "run_binding_root")],
    )


def verify_session_resume_key(
    supplied_key: bytes,
    evaluator_secret: bytes,
    session_id: bytes,
    run_binding_root: bytes,
) -> bool:
    expected = derive_session_resume_key(evaluator_secret, session_id, run_binding_root)
    _constant_time_equal(
        _root(supplied_key, "session_resume_key"),
        expected,
        "RNG_RESUME_SESSION_KEY_CONTEXT_INVALID",
        "session_resume_key is bound to a different evaluator, session, or run root",
    )
    return True


def derive_resume_capability(
    session_resume_key: bytes,
    core: CheckpointCore | bytes | list[Any],
) -> bytes:
    record = _coerce_core(core)
    return _hmac(_root(session_resume_key, "session_resume_key"), DS_RESUME_CAP, record.as_array())


def verify_resume_capability(
    supplied_capability: bytes,
    session_resume_key: bytes,
    core: CheckpointCore | bytes | list[Any],
) -> bool:
    expected = derive_resume_capability(session_resume_key, core)
    _constant_time_equal(
        _root(supplied_capability, "resume_capability"),
        expected,
        "RNG_RESUME_CAPABILITY_DERIVATION_MISMATCH",
        "resume_capability does not derive from the session key and checkpoint core",
    )
    return True


def derive_resume_capability_commitment(
    core: CheckpointCore | bytes | list[Any],
    resume_capability: bytes,
) -> bytes:
    record = _coerce_core(core)
    return _digest(
        DS_RESUME_COMMIT,
        [PROTOCOL_VERSION, record.session_id, record.checkpoint_id, record.gateway_state_root, _root(resume_capability, "resume_capability")],
    )


resume_capability_commitment = derive_resume_capability_commitment


def verify_resume_capability_commitment(
    supplied_commitment: bytes,
    core: CheckpointCore | bytes | list[Any],
    resume_capability: bytes,
) -> bool:
    expected = derive_resume_capability_commitment(core, resume_capability)
    _constant_time_equal(
        _root(supplied_commitment, "resume_capability_commitment"),
        expected,
        "RNG_RESUME_CAPABILITY_COMMITMENT_MISMATCH",
        "checkpoint commitment does not bind the supplied resume capability",
    )
    return True


@dataclass(frozen=True, slots=True, repr=False)
class PrivateResumeCapsule:
    """Private plaintext capsule; its repr never discloses the capability."""

    session_id: bytes
    checkpoint_id: int
    checkpoint_event_hash: bytes
    gateway_state_root: bytes
    resume_capability: bytes

    def __post_init__(self) -> None:
        _root(self.session_id, "session_id")
        _u64(self.checkpoint_id, "checkpoint_id")
        _root(self.checkpoint_event_hash, "checkpoint_event_hash")
        _root(self.gateway_state_root, "gateway_state_root")
        _root(self.resume_capability, "resume_capability")

    def __repr__(self) -> str:
        return (
            "PrivateResumeCapsule(session_id=<redacted>, checkpoint_id="
            f"{self.checkpoint_id}, checkpoint_event_hash=<redacted>, "
            "gateway_state_root=<redacted>, resume_capability=<redacted>)"
        )

    def as_array(self) -> list[Any]:
        return [
            PROTOCOL_VERSION,
            PRIVATE_RESUME_CAPSULE,
            self.session_id,
            self.checkpoint_id,
            self.checkpoint_event_hash,
            self.gateway_state_root,
            self.resume_capability,
        ]

    def to_bytes(self) -> bytes:
        return canonical_cbor_encode(self.as_array())


def build_private_resume_capsule(
    session_id: bytes,
    checkpoint_id: int,
    checkpoint_event_hash: bytes,
    gateway_state_root: bytes,
    resume_capability: bytes,
    *,
    checkpoint_durable: bool = True,
) -> PrivateResumeCapsule:
    if type(checkpoint_durable) is not bool:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "checkpoint_durable must be a boolean")
    if not checkpoint_durable:
        raise _fail(
            "RNG_RESUME_CAPABILITY_PREMATURE_DISCLOSURE",
            "a private capsule cannot be created before the checkpoint event is durable",
        )
    return PrivateResumeCapsule(
        session_id,
        checkpoint_id,
        checkpoint_event_hash,
        gateway_state_root,
        resume_capability,
    )


make_private_resume_capsule = build_private_resume_capsule


def decode_private_resume_capsule(raw: bytes | list[Any]) -> PrivateResumeCapsule:
    fields = _array(raw, 7, "private resume capsule")
    _version(fields[0], "private resume capsule")
    if fields[1] != PRIVATE_RESUME_CAPSULE:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "wrong private resume capsule type")
    return PrivateResumeCapsule(
        _root(fields[2], "session_id"),
        _u64(fields[3], "checkpoint_id"),
        _root(fields[4], "checkpoint_event_hash"),
        _root(fields[5], "gateway_state_root"),
        _root(fields[6], "resume_capability"),
    )


def verify_private_resume_capsule(
    capsule: PrivateResumeCapsule | bytes | list[Any],
    *,
    core: CheckpointCore | bytes | list[Any],
    checkpoint_event_hash: bytes,
) -> bool:
    record = capsule if isinstance(capsule, PrivateResumeCapsule) else decode_private_resume_capsule(capsule)
    checkpoint = _coerce_core(core)
    if record.session_id != checkpoint.session_id or record.checkpoint_id != checkpoint.checkpoint_id:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "capsule is bound to a different checkpoint")
    if record.gateway_state_root != checkpoint.gateway_state_root:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "capsule is bound to a different state root")
    _constant_time_equal(
        record.checkpoint_event_hash,
        _root(checkpoint_event_hash, "checkpoint_event_hash"),
        "RNG_RESUME_CAPABILITY_CAPSULE_INVALID",
        "capsule is bound to a different checkpoint event",
    )
    return True


def derive_resume_capability_proof(
    session_id: bytes,
    checkpoint_id: int,
    checkpoint_event_hash: bytes,
    old_registry_generation: int,
    new_registry_generation: int,
    gateway_state_root: bytes,
    resume_capability: bytes,
) -> bytes:
    session = _root(session_id, "session_id")
    checkpoint = _u64(checkpoint_id, "checkpoint_id")
    event_hash = _root(checkpoint_event_hash, "checkpoint_event_hash")
    old = _u64(old_registry_generation, "old_registry_generation")
    new = _u64(new_registry_generation, "new_registry_generation")
    root = _root(gateway_state_root, "gateway_state_root")
    capability = _root(resume_capability, "resume_capability")
    return _digest(
        DS_RESUME_PROOF,
        [PROTOCOL_VERSION, session, checkpoint, event_hash, old, new, root, capability],
    )


resume_capability_proof = derive_resume_capability_proof


def verify_resume_capability_proof(
    supplied_proof: bytes,
    session_id: bytes,
    checkpoint_id: int,
    checkpoint_event_hash: bytes,
    old_registry_generation: int,
    new_registry_generation: int,
    gateway_state_root: bytes,
    resume_capability: bytes,
) -> bool:
    expected = derive_resume_capability_proof(
        session_id,
        checkpoint_id,
        checkpoint_event_hash,
        old_registry_generation,
        new_registry_generation,
        gateway_state_root,
        resume_capability,
    )
    _constant_time_equal(
        _root(supplied_proof, "resume_capability_proof"),
        expected,
        "RNG_RESUME_PROOF_MISMATCH",
        "restore proof does not bind the checkpoint and generation transition",
    )
    return True


def checkpoint_event_hash(event: bytes | list[Any]) -> bytes:
    """Hash one canonical 631302 checkpoint event exactly as the amendment does."""
    if type(event) is list:
        raw = canonical_cbor_encode(event)
    elif type(event) is bytes:
        try:
            canonical_cbor_decode(event)
        except UnifiedRngProtocolError as exc:
            raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event is not canonical CBOR") from exc
        raw = event
    else:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event must be canonical CBOR")
    return sha256(DS_EVENT_302 + raw).digest()


def build_restore_payload(
    checkpoint_id: int,
    checkpoint_event_hash: bytes,
    old_registry_generation: int,
    new_registry_generation: int,
    gateway_state_root: bytes,
    resume_capability_opening: bytes,
    resume_capability_proof: bytes,
    restored_trace_byte_offset: int,
) -> list[Any]:
    return [
        _u64(checkpoint_id, "checkpoint_id"),
        _root(checkpoint_event_hash, "checkpoint_event_hash"),
        _u64(old_registry_generation, "old_registry_generation"),
        _u64(new_registry_generation, "new_registry_generation"),
        _root(gateway_state_root, "gateway_state_root"),
        _root(resume_capability_opening, "resume_capability_opening"),
        _root(resume_capability_proof, "resume_capability_proof"),
        _u64(restored_trace_byte_offset, "restored_trace_byte_offset"),
    ]


restore_payload = build_restore_payload


@dataclass(frozen=True, slots=True)
class DurableCheckpoint:
    """The minimal durable checkpoint evidence accepted by the local verifier."""

    core: CheckpointCore
    checkpoint_event_hash: bytes
    resume_capability_commitment: bytes
    checkpoint_event_bytes: bytes
    durable_trace_bytes: bytes
    is_latest: bool = True
    successor_exists: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.core, CheckpointCore):
            raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "core must be CheckpointCore")
        _root(self.checkpoint_event_hash, "checkpoint_event_hash")
        _root(self.resume_capability_commitment, "resume_capability_commitment")
        if type(self.checkpoint_event_bytes) is not bytes:
            raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event must be bytes")
        if type(self.durable_trace_bytes) is not bytes:
            raise _fail("RNG_RESTORE_TRACE_LENGTH_MISMATCH", "durable trace must be bytes")
        if type(self.is_latest) is not bool or type(self.successor_exists) is not bool:
            raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "checkpoint status flags must be booleans")


def _validate_durable_trace(
    checkpoint: DurableCheckpoint,
    trace_bytes: bytes,
) -> None:
    """Validate exact CBOR boundaries and the global chain through checkpoint."""

    if not trace_bytes:
        raise _fail("RNG_RESTORE_TRACE_LENGTH_MISMATCH", "durable trace is empty")
    offset = 0
    expected_sequence = 0
    previous_hash = ZERO32
    versions: set[int] = set()
    last_start = -1
    last_raw = b""
    last_fields: list[Any] | None = None
    last_hash = ZERO32
    while offset < len(trace_bytes):
        start = offset
        try:
            fields, offset = canonical_cbor_decode_prefix(trace_bytes, offset)
        except CanonicalCborTruncated as exc:
            raise _fail(
                "RNG_TRACE_TRAILING_PARTIAL_EVENT",
                "durable trace ends inside a canonical event",
            ) from exc
        except UnifiedRngProtocolError as exc:
            raise _fail(
                "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                "durable trace contains a noncanonical event",
            ) from exc
        if len(fields) != 10 or type(fields[0]) is not int:
            raise _fail(
                "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                "durable trace contains a non-event array",
            )
        versions.add(fields[0])
        if len(versions) > 1:
            raise _fail("RNG_MIXED_PROTOCOL_SESSION", "durable trace mixes protocol versions")
        if fields[0] == RETIRED_PROTOCOL_VERSION:
            raise _fail("RNG_PROTOCOL_631301_RETIRED", "durable trace uses retired protocol 631301")
        if fields[0] != PROTOCOL_VERSION:
            raise _fail(
                "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
                "durable trace uses an unsupported protocol version",
            )
        if type(fields[1]) is not int or not 3 <= fields[1] <= 12 or type(fields[9]) is not list:
            raise _fail(
                "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                "durable trace contains an invalid event type or payload",
            )
        for index in (2, 4, 5, 6, 7, 8):
            if type(fields[index]) is not bytes or len(fields[index]) != 32:
                raise _fail(
                    "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                    "durable trace contains an invalid event hash/context field",
                )
        if fields[2] != checkpoint.core.session_id:
            raise _fail(
                "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                "durable trace changes session identity",
            )
        if type(fields[3]) is not int or fields[3] != expected_sequence:
            raise _fail(
                "RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH",
                "durable trace global sequence is not contiguous",
            )
        if not hmac.compare_digest(fields[4], previous_hash):
            raise _fail(
                "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                "durable trace global hash chain is broken",
            )
        raw = trace_bytes[start:offset]
        current_hash = sha256(DS_EVENT_302 + raw).digest()
        previous_hash = current_hash
        expected_sequence += 1
        last_start = start
        last_raw = raw
        last_fields = fields
        last_hash = current_hash

    if (
        last_fields is None
        or last_fields[1] != CHECKPOINT_EVENT_TYPE
        or last_start != checkpoint.core.trace_byte_offset
        or last_raw != checkpoint.checkpoint_event_bytes
    ):
        raise _fail(
            "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
            "durable trace does not end at the exact checkpoint event",
        )
    _constant_time_equal(
        checkpoint.checkpoint_event_hash,
        last_hash,
        "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
        "durable trace checkpoint hash does not match its bytes",
    )


@dataclass(frozen=True, slots=True)
class RestoreTransition:
    """The complete local result of one successful restore transaction."""

    restore_payload: tuple[Any, ...]
    old_registry_generation: int
    new_registry_generation: int
    handles_invalidated: bool
    state: str = "CONSUMED"
    authority: str = "NO_UPLOAD"

    def __post_init__(self) -> None:
        if self.authority != "NO_UPLOAD" or not self.handles_invalidated or self.state != "CONSUMED":
            raise _fail("RNG_RESTORE_ATOMICITY_FAILURE", "restore transition cannot carry authority")


@dataclass(slots=True)
class _RegistryRecord:
    checkpoint_event_hash: bytes
    resume_capability_commitment: bytes
    registry_generation: int
    state: str = "UNUSED"


class _InMemoryResumeRegistry:
    """Shared process-local capability state for conformance testing.

    Every verifier for the same session/checkpoint is registered here
    automatically; callers cannot select or partition this registry.  This
    closes duplicate verifier instances inside one execution boundary.  It is
    not durable storage and therefore cannot close Package 3A's cross-process
    crash/custody requirement.
    """

    __slots__ = ("_records", "_lock")

    def __init__(self) -> None:
        self._records: dict[tuple[bytes, int], _RegistryRecord] = {}
        self._lock = Lock()

    @staticmethod
    def _key(checkpoint: DurableCheckpoint) -> tuple[bytes, int]:
        return checkpoint.core.session_id, checkpoint.core.checkpoint_id

    def register(self, checkpoint: DurableCheckpoint) -> None:
        key = self._key(checkpoint)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = _RegistryRecord(
                    checkpoint.checkpoint_event_hash,
                    checkpoint.resume_capability_commitment,
                    checkpoint.core.registry_generation,
                )
                return
            if (
                existing.checkpoint_event_hash != checkpoint.checkpoint_event_hash
                or existing.resume_capability_commitment
                != checkpoint.resume_capability_commitment
            ):
                raise _fail(
                    "RNG_RESUME_CAPABILITY_CAPSULE_INVALID",
                    "checkpoint identity is already registered with different evidence",
                )

    def snapshot(self, checkpoint: DurableCheckpoint) -> tuple[str, int]:
        key = self._key(checkpoint)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise _fail(
                    "RNG_RESUME_CAPABILITY_CAPSULE_INVALID",
                    "checkpoint is absent from the shared resume registry",
                )
            return record.state, record.registry_generation

    def consume(
        self,
        checkpoint: DurableCheckpoint,
        *,
        old_registry_generation: int,
        new_registry_generation: int,
    ) -> None:
        key = self._key(checkpoint)
        with self._lock:
            record = self._records.get(key)
            if record is None:
                raise _fail(
                    "RNG_RESUME_CAPABILITY_CAPSULE_INVALID",
                    "checkpoint is absent from the shared resume registry",
                )
            if record.state != "UNUSED":
                raise _fail(
                    "RNG_RESUME_CAPABILITY_REUSED",
                    "resume capability has already been consumed",
                )
            if (
                record.registry_generation != old_registry_generation
                or new_registry_generation != old_registry_generation + 1
            ):
                raise _fail(
                    "RNG_RESTORE_REGISTRY_GENERATION_INVALID",
                    "shared registry generation does not match the restore transition",
                )
            record.registry_generation = new_registry_generation
            record.state = "CONSUMED"


_PROCESS_RESUME_REGISTRY = _InMemoryResumeRegistry()


class InMemoryResumeVerifier:
    """Fail-closed local verifier sharing one explicit capability registry."""

    __slots__ = (
        "_evaluator_secret",
        "_run_binding_root",
        "_checkpoint",
        "_capsule",
        "_consumed",
        "_transition",
        "_lock",
    )

    def __init__(
        self,
        evaluator_secret: bytes,
        run_binding_root: bytes,
        checkpoint: DurableCheckpoint,
        capsule: PrivateResumeCapsule | bytes | list[Any],
    ) -> None:
        self._evaluator_secret = _root(evaluator_secret, "evaluator_secret")
        self._run_binding_root = _root(run_binding_root, "run_binding_root")
        if not isinstance(checkpoint, DurableCheckpoint):
            raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "checkpoint evidence is not a DurableCheckpoint")
        self._checkpoint = checkpoint
        self._capsule = capsule if isinstance(capsule, PrivateResumeCapsule) else decode_private_resume_capsule(capsule)
        _PROCESS_RESUME_REGISTRY.register(checkpoint)
        self._consumed = False
        self._transition: RestoreTransition | None = None
        self._lock = Lock()

    @property
    def state(self) -> str:
        return _PROCESS_RESUME_REGISTRY.snapshot(self._checkpoint)[0]

    @property
    def registry_generation(self) -> int:
        return _PROCESS_RESUME_REGISTRY.snapshot(self._checkpoint)[1]

    @property
    def handles_valid(self) -> bool:
        return _PROCESS_RESUME_REGISTRY.snapshot(self._checkpoint)[0] == "UNUSED"

    @property
    def transition(self) -> RestoreTransition | None:
        return self._transition

    @property
    def sensitive_material_destroyed(self) -> bool:
        return self._consumed and self._evaluator_secret is None and self._capsule is None

    def restore(
        self,
        *,
        old_registry_generation: int,
        new_registry_generation: int,
        resume_capability_proof: bytes,
        resume_capability_opening: bytes | None = None,
        actual_trace_bytes: bytes | None = None,
    ) -> RestoreTransition:
        """Validate all evidence, then atomically consume the in-memory capability."""
        with self._lock:
            if _PROCESS_RESUME_REGISTRY.snapshot(self._checkpoint)[0] != "UNUSED":
                raise _fail("RNG_RESUME_CAPABILITY_REUSED", "resume capability has already been consumed")
            checkpoint = self._checkpoint
            if not checkpoint.is_latest:
                raise _fail("RNG_RESTORE_CHECKPOINT_NOT_LATEST", "restore must reference the newest checkpoint")
            if checkpoint.successor_exists:
                raise _fail("RNG_RESTORE_CHECKPOINT_SUCCESSOR_EXISTS", "checkpoint already has a successor event")

            capsule = self._capsule
            verify_private_resume_capsule(
                capsule,
                core=checkpoint.core,
                checkpoint_event_hash=checkpoint.checkpoint_event_hash,
            )
            event = _validate_checkpoint_event(checkpoint, capsule)
            actual_trace = checkpoint.durable_trace_bytes if actual_trace_bytes is None else actual_trace_bytes
            if type(actual_trace) is not bytes:
                raise _fail("RNG_RESTORE_TRACE_LENGTH_MISMATCH", "actual durable trace must be bytes")
            checkpoint_end = checkpoint.core.trace_byte_offset + len(event)
            if len(actual_trace) != checkpoint_end:
                if len(actual_trace) > checkpoint_end:
                    try:
                        canonical_cbor_decode_prefix(actual_trace, checkpoint_end)
                    except CanonicalCborTruncated as exc:
                        raise _fail(
                            "RNG_TRACE_TRAILING_PARTIAL_EVENT",
                            "durable trace ends inside an event after checkpoint",
                        ) from exc
                    except UnifiedRngProtocolError:
                        pass
                raise _fail(
                    "RNG_RESTORE_TRACE_LENGTH_MISMATCH",
                    "durable trace contains bytes after the checkpoint event",
                )
            if actual_trace[checkpoint.core.trace_byte_offset:] != event:
                raise _fail(
                    "RNG_RESTORE_TRACE_OFFSET_MISMATCH",
                    "checkpoint event is not at its declared trace offset",
                )
            _validate_durable_trace(checkpoint, actual_trace)
            try:
                # Deferred import keeps the formula module acyclic at import
                # time while reusing the one exact event-schema/state verifier.
                from .unified_rng_events import verify_checkpoint_trace_prefix

                verified_prefix = verify_checkpoint_trace_prefix(
                    actual_trace,
                    expected_session_id=checkpoint.core.session_id,
                    evaluator_secret=self._evaluator_secret,
                    expected_run_binding_root=self._run_binding_root,
                )
            except UnifiedRngProtocolError as exc:
                raise _fail(exc.code, str(exc)) from exc
            if (
                verified_prefix.trace_root != checkpoint.checkpoint_event_hash
                or verified_prefix.trace_byte_length != checkpoint_end
            ):
                raise _fail(
                    "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
                    "exact event verification disagrees with checkpoint evidence",
                )

            old = _u64(old_registry_generation, "old_registry_generation")
            new = _u64(new_registry_generation, "new_registry_generation")
            if old != checkpoint.core.registry_generation or new != old + 1:
                raise _fail(
                    "RNG_RESTORE_REGISTRY_GENERATION_INVALID",
                    "restore must increment the checkpoint registry generation exactly once",
                )

            session_key = derive_session_resume_key(
                self._evaluator_secret,
                checkpoint.core.session_id,
                self._run_binding_root,
            )
            opening = capsule.resume_capability if resume_capability_opening is None else resume_capability_opening
            verify_resume_capability(opening, session_key, checkpoint.core)
            verify_resume_capability_commitment(
                checkpoint.resume_capability_commitment,
                checkpoint.core,
                opening,
            )
            verify_resume_capability_proof(
                resume_capability_proof,
                checkpoint.core.session_id,
                checkpoint.core.checkpoint_id,
                checkpoint.checkpoint_event_hash,
                old,
                new,
                checkpoint.core.gateway_state_root,
                opening,
            )
            payload = tuple(
                build_restore_payload(
                    checkpoint.core.checkpoint_id,
                    checkpoint.checkpoint_event_hash,
                    old,
                    new,
                    checkpoint.core.gateway_state_root,
                    opening,
                    resume_capability_proof,
                    checkpoint_end,
                )
            )

            # Build the transition before the one atomic shared-registry state change.
            transition = RestoreTransition(payload, old, new, True)
            _PROCESS_RESUME_REGISTRY.consume(
                checkpoint,
                old_registry_generation=old,
                new_registry_generation=new,
            )
            # No fallible operation follows the registry transition.
            self._consumed = True
            self._transition = transition
            self._capsule = None
            self._evaluator_secret = None
            self._run_binding_root = None
            return transition


ResumeCapabilityVerifier = InMemoryResumeVerifier
ResumeState = InMemoryResumeVerifier


def _validate_checkpoint_event(checkpoint: DurableCheckpoint, capsule: PrivateResumeCapsule) -> bytes:
    try:
        fields = canonical_cbor_decode(checkpoint.checkpoint_event_bytes)
    except UnifiedRngProtocolError as exc:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event is not canonical CBOR") from exc
    if type(fields) is not list or len(fields) != 10:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event has the wrong envelope shape")
    if fields[0] == RETIRED_PROTOCOL_VERSION:
        raise _fail("RNG_PROTOCOL_631301_RETIRED", "checkpoint event uses retired protocol 631301")
    if fields[0] != PROTOCOL_VERSION:
        raise _fail("RNG_EVENT_ENVELOPE_VERSION_MISMATCH", "checkpoint event uses an unsupported protocol version")
    if fields[1] != CHECKPOINT_EVENT_TYPE:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "resume evidence does not reference a checkpoint event")
    if fields[2] != checkpoint.core.session_id:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "checkpoint event has the wrong session")
    _u64(fields[3], "checkpoint global_sequence")
    for index, label in ((4, "previous_global_event_hash"), (5, "stream_id"), (6, "previous_stream_event_hash"), (7, "branch_context_id"), (8, "previous_branch_chain_hash")):
        _root(fields[index], label)
    if fields[5] != ZERO32 or fields[6] != ZERO32 or fields[7] != ZERO32 or fields[8] != ZERO32:
        raise _fail(
            "RNG_BRANCH_CONTEXT_MISMATCH",
            "session-wide checkpoint events must use zero stream and branch context fields",
        )
    payload = fields[9]
    if type(payload) is not list or len(payload) != 7:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint event payload has the wrong shape")
    if payload[0] != checkpoint.core.checkpoint_id or payload[1] != checkpoint.core.registry_generation:
        raise _fail("RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH", "checkpoint identity or generation is inconsistent")
    if payload[2] != checkpoint.core.next_global_sequence:
        raise _fail("RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH", "checkpoint next sequence is inconsistent")
    if payload[3] != checkpoint.core.trace_byte_offset:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint payload offset is inconsistent")
    if type(payload[4]) is not list:
        raise _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint stream states are not an array")
    if payload[5] != checkpoint.resume_capability_commitment or payload[6] != checkpoint.core.gateway_state_root:
        raise _fail("RNG_RESUME_CAPABILITY_COMMITMENT_MISMATCH", "checkpoint event does not bind its resume commitment")
    if checkpoint.core.next_global_sequence != fields[3] + 1:
        raise _fail("RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH", "checkpoint next sequence is not event sequence plus one")
    expected_hash = checkpoint_event_hash(checkpoint.checkpoint_event_bytes)
    _constant_time_equal(
        checkpoint.checkpoint_event_hash,
        expected_hash,
        "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH",
        "checkpoint event hash does not match its canonical bytes",
    )
    if capsule.checkpoint_event_hash != checkpoint.checkpoint_event_hash:
        raise _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "capsule is bound to a different checkpoint event")
    return checkpoint.checkpoint_event_bytes


__all__ = [
    "CHECKPOINT_EVENT_TYPE",
    "DS_EVENT_302",
    "DS_RESUME_CAP",
    "DS_RESUME_COMMIT",
    "DS_RESUME_PROOF",
    "DS_RESUME_SESSION",
    "PRIVATE_RESUME_CAPSULE",
    "PRIVATE_RESUME_CAPSULE_TYPE",
    "CheckpointCore",
    "DurableCheckpoint",
    "InMemoryResumeVerifier",
    "PrivateResumeCapsule",
    "RestoreTransition",
    "ResumeCapabilityVerifier",
    "ResumeState",
    "UnifiedRngResumeError",
    "build_checkpoint_core",
    "build_private_resume_capsule",
    "build_restore_payload",
    "checkpoint_core",
    "checkpoint_event_hash",
    "decode_checkpoint_core",
    "decode_private_resume_capsule",
    "derive_resume_capability",
    "derive_resume_capability_commitment",
    "derive_resume_capability_proof",
    "derive_session_resume_key",
    "make_checkpoint_core",
    "make_private_resume_capsule",
    "resume_capability_commitment",
    "resume_capability_proof",
    "restore_payload",
    "verify_private_resume_capsule",
    "verify_resume_capability",
    "verify_resume_capability_commitment",
    "verify_resume_capability_proof",
    "verify_session_resume_key",
]
