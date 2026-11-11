"""Offline validators for the V631-RNG-3A/1 runtime event protocol.

This module validates only canonical event bytes and the state transitions
which can be reconstructed from an event sequence.  It deliberately contains
no process ownership, persistence, gateway state, campaign authority, or
compatibility path.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Final, Mapping, NoReturn

from .unified_rng_protocol import (
    CanonicalCborTruncated,
    DS_BRANCH_ID,
    DS_BRANCH_FINAL,
    DS_BRANCH_GENESIS,
    DS_BRANCH_LEAF,
    DS_BRANCH_STEP,
    DS_EVENT_302,
    DS_STATE,
    PROTOCOL_VERSION,
    RETIRED_PROTOCOL_VERSION,
    UINT64_MAX,
    UnifiedRngProtocolError,
    ZERO_ID,
    canonical_cbor_decode,
    canonical_cbor_decode_prefix,
    canonical_cbor_encode,
    derive_stream_id,
)
from .unified_rng_resume import (
    build_checkpoint_core,
    derive_resume_capability,
    derive_session_resume_key,
    verify_resume_capability,
    verify_resume_capability_commitment,
    verify_resume_capability_proof,
)


EVENT_STREAM_BIND: Final = 3
EVENT_RAW_DRAW: Final = 4
EVENT_BOUNDED_SAMPLE: Final = 5
EVENT_SHUFFLE: Final = 6
EVENT_BRANCH_FORK: Final = 7
EVENT_BRANCH_COMMIT: Final = 8
EVENT_BRANCH_ABORT: Final = 9
EVENT_CHECKPOINT: Final = 10
EVENT_RESTORE: Final = 11
EVENT_SESSION_CLOSE: Final = 12

# Short names are useful when constructing arrays by hand and are kept as
# integer protocol constants, never as a second wire representation.
STREAM_BIND = EVENT_STREAM_BIND
RAW_DRAW = EVENT_RAW_DRAW
BOUNDED_SAMPLE = EVENT_BOUNDED_SAMPLE
SHUFFLE = EVENT_SHUFFLE
BRANCH_FORK = EVENT_BRANCH_FORK
BRANCH_COMMIT = EVENT_BRANCH_COMMIT
BRANCH_ABORT = EVENT_BRANCH_ABORT
CHECKPOINT = EVENT_CHECKPOINT
RESTORE = EVENT_RESTORE
SESSION_CLOSE = EVENT_SESSION_CLOSE

UINT64_SPACE: Final = 1 << 64
SESSION_EVENT_TYPES: Final = frozenset({EVENT_CHECKPOINT, EVENT_RESTORE, EVENT_SESSION_CLOSE})
STREAM_EVENT_TYPES: Final = frozenset({
    EVENT_STREAM_BIND,
    EVENT_RAW_DRAW,
    EVENT_BOUNDED_SAMPLE,
    EVENT_SHUFFLE,
    EVENT_BRANCH_FORK,
    EVENT_BRANCH_COMMIT,
    EVENT_BRANCH_ABORT,
})


class UnifiedRngEventError(UnifiedRngProtocolError):
    """A V631-RNG-3A/1 event or event sequence failed closed."""


UnifiedRngEventsError = UnifiedRngEventError


def _fail(code: str, message: str) -> UnifiedRngEventError:
    raise UnifiedRngEventError(code, message)


def _uint(value: Any, label: str, maximum: int = UINT64_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must be an unsigned integer")
    return value


def _bstr(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must be a 32-byte bstr")
    return value


def _array(value: Any, length: int, label: str) -> list[Any]:
    if type(value) is not list or len(value) != length:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must have {length} array fields")
    return value


def _digest(domain: bytes, value: bytes) -> bytes:
    return sha256(domain + value).digest()


def _raise_as_event_error(exc: UnifiedRngProtocolError) -> NoReturn:
    if isinstance(exc, UnifiedRngEventError):
        raise exc
    raise UnifiedRngEventError(exc.code, str(exc)) from exc


def _decode_value(value: RuntimeEvent | bytes | list[Any]) -> list[Any]:
    if isinstance(value, RuntimeEvent):
        return value.as_array()
    if type(value) is bytes:
        return canonical_cbor_decode(value)
    if type(value) is list:
        return value
    _fail("RNG_CANONICAL_CBOR_MISMATCH", "event must be a canonical CBOR byte string or array")


def _freeze_cbor_tree(value: Any) -> Any:
    """Detach and recursively freeze an already validated arrays-only CBOR tree."""

    if type(value) is list:
        return tuple(_freeze_cbor_tree(item) for item in value)
    if type(value) in (int, bytes):
        return value
    _fail("RNG_CANONICAL_CBOR_MISMATCH", "event payload contains a noncanonical CBOR value")


def _thaw_cbor_tree(value: Any) -> Any:
    """Return a fresh arrays-only CBOR tree for encoding or external inspection."""

    if type(value) is tuple:
        return [_thaw_cbor_tree(item) for item in value]
    if type(value) in (int, bytes):
        return value
    if type(value) is list:
        return [_thaw_cbor_tree(item) for item in value]
    _fail("RNG_CANONICAL_CBOR_MISMATCH", "event payload contains a noncanonical CBOR value")


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """The exact 631302 ten-field event envelope, without an embedded hash."""

    event_type: int
    session_id: bytes
    global_sequence: int
    previous_global_event_hash: bytes
    stream_id: bytes
    previous_stream_event_hash: bytes
    branch_context_id: bytes
    previous_branch_chain_hash: bytes
    payload: tuple[Any, ...]

    def __post_init__(self) -> None:
        candidate = [
            PROTOCOL_VERSION,
            self.event_type,
            self.session_id,
            self.global_sequence,
            self.previous_global_event_hash,
            self.stream_id,
            self.previous_stream_event_hash,
            self.branch_context_id,
            self.previous_branch_chain_hash,
            _thaw_cbor_tree(self.payload),
        ]
        validate_event_envelope(candidate)
        object.__setattr__(self, "payload", _freeze_cbor_tree(candidate[9]))

    def as_array(self) -> list[Any]:
        return [
            PROTOCOL_VERSION,
            self.event_type,
            self.session_id,
            self.global_sequence,
            self.previous_global_event_hash,
            self.stream_id,
            self.previous_stream_event_hash,
            self.branch_context_id,
            self.previous_branch_chain_hash,
            _thaw_cbor_tree(self.payload),
        ]

    def to_bytes(self) -> bytes:
        validate_event_envelope(self.as_array())
        return canonical_cbor_encode(self.as_array())

    def event_hash(self) -> bytes:
        return _digest(DS_EVENT_302, self.to_bytes())

    @classmethod
    def from_array(cls, value: list[Any]) -> "RuntimeEvent":
        fields = validate_event_envelope(value)
        return cls(
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            fields[5],
            fields[6],
            fields[7],
            fields[8],
            fields[9],
        )

    @classmethod
    def from_bytes(cls, value: bytes) -> "RuntimeEvent":
        return cls.from_array(canonical_cbor_decode(value))


def build_event(
    event_type: int,
    session_id: bytes,
    global_sequence: int,
    previous_global_event_hash: bytes,
    stream_id: bytes,
    previous_stream_event_hash: bytes,
    branch_context_id: bytes,
    previous_branch_chain_hash: bytes,
    payload: list[Any],
) -> RuntimeEvent:
    """Build one envelope after applying all stateless schema checks."""

    return RuntimeEvent(
        event_type,
        session_id,
        global_sequence,
        previous_global_event_hash,
        stream_id,
        previous_stream_event_hash,
        branch_context_id,
        previous_branch_chain_hash,
        payload,
    )


make_event = build_event


def event_hash(event: RuntimeEvent | bytes | list[Any]) -> bytes:
    """Return H(DS_EVENT_302 || C(event)) for one exact envelope."""

    record = RuntimeEvent.from_array(_decode_value(event))
    return record.event_hash()


def decode_trace_events(trace_bytes: bytes) -> tuple[RuntimeEvent, ...]:
    """Decode the exact separator-free 631302 event byte stream.

    Every byte must belong to one complete canonical event.  In particular,
    an otherwise valid prefix followed by a truncated CBOR value is rejected
    with the amendment's dedicated trailing-partial-event code.
    """

    if type(trace_bytes) is not bytes or not trace_bytes:
        _fail("RNG_EVENT_CHAIN_MISMATCH", "trace must be non-empty bytes")
    arrays: list[list[Any]] = []
    offset = 0
    while offset < len(trace_bytes):
        try:
            value, next_offset = canonical_cbor_decode_prefix(trace_bytes, offset)
        except CanonicalCborTruncated as exc:
            raise UnifiedRngEventError(
                "RNG_TRACE_TRAILING_PARTIAL_EVENT",
                "trace ends inside a canonical event",
            ) from exc
        except UnifiedRngProtocolError as exc:
            raise UnifiedRngEventError(exc.code, str(exc)) from exc
        if next_offset <= offset:  # pragma: no cover - decoder invariant
            _fail("RNG_CANONICAL_CBOR_MISMATCH", "trace decoder did not advance")
        arrays.append(value)
        offset = next_offset

    versions = {array[0] for array in arrays if array}
    if len(versions) > 1:
        _fail("RNG_MIXED_PROTOCOL_SESSION", "trace mixes protocol versions")
    if versions == {RETIRED_PROTOCOL_VERSION}:
        _fail("RNG_PROTOCOL_631301_RETIRED", "trace uses retired protocol 631301")
    return tuple(RuntimeEvent.from_array(array) for array in arrays)


decode_trace = decode_trace_events


def verify_trace_bytes(
    trace_bytes: bytes,
    *,
    expected_session_id: bytes | None = None,
    evaluator_secret: bytes | None = None,
    expected_run_binding_root: bytes | None = None,
) -> VerifiedEventChain:
    """Decode and fully verify the authoritative concatenated trace bytes."""

    result = verify_event_chain(
        decode_trace_events(trace_bytes),
        expected_session_id=expected_session_id,
        evaluator_secret=evaluator_secret,
        expected_run_binding_root=expected_run_binding_root,
    )
    if result.trace_byte_length != len(trace_bytes):  # pragma: no cover - construction invariant
        _fail("RNG_RESTORE_TRACE_LENGTH_MISMATCH", "verified events do not cover every trace byte")
    return result


def derive_event_stream_id(
    session_id: bytes,
    site_id: bytes,
    object_instance_id: bytes,
    purpose_code: int,
    stream_ordinal: int,
) -> bytes:
    """Derive the stream ID from the protocol core's canonical derivation."""

    return derive_stream_id(session_id, site_id, object_instance_id, purpose_code, stream_ordinal)


derive_bound_stream_id = derive_event_stream_id


def stream_bind_payload(
    site_id: bytes,
    object_instance_id: bytes,
    purpose_code: int,
    stream_ordinal: int,
) -> list[Any]:
    _bstr(site_id, "site_id")
    _bstr(object_instance_id, "object_instance_id")
    _uint(purpose_code, "purpose_code", 0xFFFF)
    _uint(stream_ordinal, "stream_ordinal", 0xFFFFFFFF)
    return [site_id, object_instance_id, purpose_code, stream_ordinal]


def raw_draw_payload(branch_id: bytes, raw_counter: int, raw_value: int) -> list[Any]:
    _bstr(branch_id, "branch_id")
    _uint(raw_counter, "raw_counter")
    _uint(raw_value, "raw_value")
    return [branch_id, raw_counter, raw_value]


def bounded_sample_payload(
    branch_id: bytes,
    upper_exclusive: int,
    first_raw_counter: int,
    raw_draw_count: int,
    accepted_raw_counter: int,
    result: int,
) -> list[Any]:
    payload = [branch_id, upper_exclusive, first_raw_counter, raw_draw_count, accepted_raw_counter, result]
    _validate_bounded_payload(payload)
    return payload


def shuffle_payload(
    branch_id: bytes,
    shuffle_id: int,
    counter_start: int,
    counter_end_exclusive: int,
    before_instance_ids: list[bytes],
    permutation_output_to_input: list[int],
    after_instance_ids: list[bytes],
) -> list[Any]:
    payload = [
        branch_id,
        shuffle_id,
        counter_start,
        counter_end_exclusive,
        before_instance_ids,
        permutation_output_to_input,
        after_instance_ids,
    ]
    _validate_shuffle_payload(payload)
    return payload


def branch_fork_payload(
    parent_branch_id: bytes,
    branch_id: bytes,
    branch_ordinal: int,
    purpose_id: bytes,
    parent_raw_counter: int,
    parent_next_shuffle_id: int,
    parent_state_root: bytes,
) -> list[Any]:
    payload = [parent_branch_id, branch_id, branch_ordinal, purpose_id, parent_raw_counter, parent_next_shuffle_id, parent_state_root]
    _validate_branch_fork_payload(payload)
    return payload


def branch_commit_payload(
    branch_id: bytes,
    branch_raw_counter: int,
    branch_next_shuffle_id: int,
    branch_trace_root: bytes,
    result_root: bytes,
    parent_state_before: bytes,
    parent_state_after: bytes,
) -> list[Any]:
    payload = [branch_id, branch_raw_counter, branch_next_shuffle_id, branch_trace_root, result_root, parent_state_before, parent_state_after]
    _validate_branch_end_payload(payload, EVENT_BRANCH_COMMIT)
    return payload


def branch_abort_payload(
    branch_id: bytes,
    branch_raw_counter: int,
    branch_next_shuffle_id: int,
    branch_trace_root: bytes,
    abort_reason: int,
    parent_state_before: bytes,
    parent_state_after: bytes,
) -> list[Any]:
    payload = [branch_id, branch_raw_counter, branch_next_shuffle_id, branch_trace_root, abort_reason, parent_state_before, parent_state_after]
    _validate_branch_end_payload(payload, EVENT_BRANCH_ABORT)
    return payload


def checkpoint_payload(
    checkpoint_id: int,
    registry_generation: int,
    next_global_sequence: int,
    trace_byte_offset: int,
    stream_states: list[list[Any]],
    resume_capability_commitment: bytes,
    gateway_state_root: bytes,
) -> list[Any]:
    payload = [checkpoint_id, registry_generation, next_global_sequence, trace_byte_offset, stream_states, resume_capability_commitment, gateway_state_root]
    _validate_checkpoint_payload(payload)
    return payload


def restore_payload(
    checkpoint_id: int,
    checkpoint_event_hash: bytes,
    old_registry_generation: int,
    new_registry_generation: int,
    gateway_state_root: bytes,
    resume_capability_opening: bytes,
    resume_capability_proof: bytes,
    restored_trace_byte_offset: int,
) -> list[Any]:
    payload = [
        checkpoint_id,
        checkpoint_event_hash,
        old_registry_generation,
        new_registry_generation,
        gateway_state_root,
        resume_capability_opening,
        resume_capability_proof,
        restored_trace_byte_offset,
    ]
    _validate_restore_payload(payload)
    return payload


def session_close_payload(
    seed_commitment_root: bytes,
    run_binding_root: bytes,
    event_count: int,
    stream_summaries: list[list[Any]],
    latest_checkpoint_event_hash: bytes,
    canonical_trace_manifest_root: bytes,
    end_engine_state_root: bytes,
    open_branch_count: int,
    close_code: int,
) -> list[Any]:
    payload = [seed_commitment_root, run_binding_root, event_count, stream_summaries, latest_checkpoint_event_hash, canonical_trace_manifest_root, end_engine_state_root, open_branch_count, close_code]
    _validate_session_close_payload(payload)
    return payload


def validate_event_envelope(value: RuntimeEvent | bytes | list[Any]) -> list[Any]:
    """Validate one event's envelope and payload without chain context."""

    record = _decode_value(value)
    if type(record) is not list or not record:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", "runtime event must be an array")
    if record[0] == RETIRED_PROTOCOL_VERSION:
        _fail("RNG_PROTOCOL_631301_RETIRED", "runtime event uses retired protocol 631301")
    if record[0] != PROTOCOL_VERSION:
        _fail("RNG_EVENT_ENVELOPE_VERSION_MISMATCH", "runtime event version is not 631302")
    if len(record) == 8:
        _fail("RNG_EVENT_BRANCH_FIELD_MISSING", "631302 event is missing branch-chain fields")
    _array(record, 10, "runtime event")
    event_type = _uint(record[1], "event_type", 0xFF)
    _bstr(record[2], "session_id")
    _uint(record[3], "global_sequence")
    _bstr(record[4], "previous_global_event_hash")
    stream_id = _bstr(record[5], "stream_id")
    previous_stream_hash = _bstr(record[6], "previous_stream_event_hash")
    branch_context_id = _bstr(record[7], "branch_context_id")
    previous_branch_hash = _bstr(record[8], "previous_branch_chain_hash")
    if event_type not in STREAM_EVENT_TYPES | SESSION_EVENT_TYPES:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", "event_type is outside V631-RNG-3A/1 events 3..12")
    if event_type in SESSION_EVENT_TYPES and any(
        item != ZERO_ID
        for item in (stream_id, previous_stream_hash, branch_context_id, previous_branch_hash)
    ):
        _fail("RNG_BRANCH_CONTEXT_MISMATCH", "session-wide events must use zero stream and branch fields")
    if event_type in STREAM_EVENT_TYPES and stream_id == ZERO_ID:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", "stream events require a nonzero stream ID")
    if event_type == EVENT_STREAM_BIND and any(
        item != ZERO_ID
        for item in (previous_stream_hash, branch_context_id, previous_branch_hash)
    ):
        _fail("RNG_BRANCH_CONTEXT_MISMATCH", "STREAM_BIND must begin stream and branch chains at zero")
    if branch_context_id == ZERO_ID and previous_branch_hash != ZERO_ID:
        _fail("RNG_BRANCH_PREDECESSOR_MISMATCH", "zero branch context requires a zero predecessor")
    if branch_context_id != ZERO_ID and previous_branch_hash == ZERO_ID:
        _fail("RNG_BRANCH_PREDECESSOR_MISMATCH", "nonzero branch context requires its current chain head")
    payload = record[9]
    if type(payload) is not list:
        _fail("RNG_CANONICAL_CBOR_MISMATCH", "event payload must be an array")
    _validate_payload(event_type, payload)
    if event_type == EVENT_STREAM_BIND:
        site_id, object_instance_id, purpose_code, stream_ordinal = payload
        expected_stream_id = derive_stream_id(record[2], site_id, object_instance_id, purpose_code, stream_ordinal)
        if stream_id != expected_stream_id:
            _fail("RNG_CALLER_SUPPLIED_STREAM_ID", "STREAM_BIND stream_id is not compiler-derived")
    elif event_type in (EVENT_RAW_DRAW, EVENT_BOUNDED_SAMPLE, EVENT_SHUFFLE):
        if payload[0] != branch_context_id:
            _fail("RNG_BRANCH_CONTEXT_MISMATCH", "payload branch_id differs from the envelope context")
    elif event_type == EVENT_BRANCH_FORK:
        if payload[0] != branch_context_id:
            _fail("RNG_BRANCH_CONTEXT_MISMATCH", "fork parent differs from the envelope context")
    return record


def _validate_payload(event_type: int, payload: list[Any]) -> None:
    if event_type == EVENT_STREAM_BIND:
        _validate_stream_bind_payload(payload)
    elif event_type == EVENT_RAW_DRAW:
        _validate_raw_payload(payload)
    elif event_type == EVENT_BOUNDED_SAMPLE:
        _validate_bounded_payload(payload)
    elif event_type == EVENT_SHUFFLE:
        _validate_shuffle_payload(payload)
    elif event_type == EVENT_BRANCH_FORK:
        _validate_branch_fork_payload(payload)
    elif event_type in (EVENT_BRANCH_COMMIT, EVENT_BRANCH_ABORT):
        _validate_branch_end_payload(payload, event_type)
    elif event_type == EVENT_CHECKPOINT:
        _validate_checkpoint_payload(payload)
    elif event_type == EVENT_RESTORE:
        _validate_restore_payload(payload)
    elif event_type == EVENT_SESSION_CLOSE:
        _validate_session_close_payload(payload)
    else:  # pragma: no cover - guarded by validate_event_envelope
        _fail("RNG_CANONICAL_CBOR_MISMATCH", "unsupported event type")


def _validate_stream_bind_payload(payload: list[Any]) -> None:
    fields = _array(payload, 4, "STREAM_BIND payload")
    _bstr(fields[0], "site_id")
    _bstr(fields[1], "object_instance_id")
    _uint(fields[2], "purpose_code", 0xFFFF)
    _uint(fields[3], "stream_ordinal", 0xFFFFFFFF)


def _validate_raw_payload(payload: list[Any]) -> None:
    fields = _array(payload, 3, "RAW_DRAW payload")
    _bstr(fields[0], "branch_id")
    _uint(fields[1], "raw_counter")
    _uint(fields[2], "raw_value")


def _validate_bounded_payload(payload: list[Any]) -> None:
    fields = _array(payload, 6, "BOUNDED_SAMPLE payload")
    _bstr(fields[0], "branch_id")
    upper = _uint(fields[1], "upper_exclusive")
    if upper == 0:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "upper_exclusive must be in 1..2^64-1")
    first = _uint(fields[2], "first_raw_counter")
    count = _uint(fields[3], "raw_draw_count", 0xFFFFFFFF)
    if count == 0:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "raw_draw_count must be at least one")
    accepted = _uint(fields[4], "accepted_raw_counter")
    if first > UINT64_MAX - (count - 1) or accepted != first + count - 1:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "accepted_raw_counter is not the exact interval endpoint")
    result = _uint(fields[5], "result")
    if result >= upper:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "result must be below upper_exclusive")


def _validate_shuffle_payload(payload: list[Any]) -> None:
    fields = _array(payload, 7, "SHUFFLE payload")
    _bstr(fields[0], "branch_id")
    _uint(fields[1], "shuffle_id")
    start = _uint(fields[2], "counter_start")
    end = _uint(fields[3], "counter_end_exclusive")
    if end < start:
        _fail("RNG_SHUFFLE_INVALID", "counter interval is reversed")
    before, permutation, after = fields[4], fields[5], fields[6]
    if type(before) is not list or type(permutation) is not list or type(after) is not list:
        _fail("RNG_SHUFFLE_INVALID", "shuffle arrays must be definite arrays")
    if not (len(before) == len(permutation) == len(after)):
        _fail("RNG_SHUFFLE_INVALID", "shuffle arrays must have equal length")
    for index, item in enumerate(before):
        _bstr(item, f"before_instance_ids[{index}]")
    for index, item in enumerate(after):
        _bstr(item, f"after_instance_ids[{index}]")
    if len(set(before)) != len(before) or len(set(after)) != len(after):
        _fail("RNG_DUPLICATE_CARD_INSTANCE_ID", "shuffle instance IDs must be unique")
    if set(before) != set(after):
        _fail("RNG_SHUFFLE_INVALID", "shuffle must preserve the instance-ID set")
    for index, item in enumerate(permutation):
        _uint(item, f"permutation_output_to_input[{index}]", 0xFFFFFFFF)
        if item >= len(before):
            _fail("RNG_SHUFFLE_INVALID", "permutation index is outside the input range")
    if len(set(permutation)) != len(permutation):
        _fail("RNG_SHUFFLE_INVALID", "permutation must be a bijection")


def _validate_branch_fork_payload(payload: list[Any]) -> None:
    fields = _array(payload, 7, "BRANCH_FORK payload")
    parent, branch = _bstr(fields[0], "parent_branch_id"), _bstr(fields[1], "branch_id")
    if branch == ZERO_ID or branch == parent:
        _fail("RNG_BRANCH_ID_INVALID", "branch_id must be a new nonzero branch ID")
    _uint(fields[2], "branch_ordinal")
    _bstr(fields[3], "purpose_id")
    _uint(fields[4], "parent_raw_counter")
    _uint(fields[5], "parent_next_shuffle_id")
    _bstr(fields[6], "parent_state_root")


def _validate_branch_end_payload(payload: list[Any], event_type: int) -> None:
    fields = _array(payload, 7, "branch lifecycle payload")
    branch = _bstr(fields[0], "branch_id")
    if branch == ZERO_ID:
        _fail("RNG_BRANCH_ID_INVALID", "branch lifecycle events cannot target the authoritative branch")
    _uint(fields[1], "branch_raw_counter")
    _uint(fields[2], "branch_next_shuffle_id")
    _bstr(fields[3], "branch_trace_root")
    if event_type == EVENT_BRANCH_ABORT:
        _uint(fields[4], "abort_reason", 0xFFFF)
    else:
        _bstr(fields[4], "result_root")
    _bstr(fields[5], "parent_state_before")
    _bstr(fields[6], "parent_state_after")
    if fields[5] != fields[6]:
        _fail("RNG_BRANCH_PARENT_STATE_MUTATED", "branch lifecycle cannot change parent state")


def _validate_stream_state_row(row: Any, label: str) -> None:
    fields = _array(row, 6, label)
    _bstr(fields[0], f"{label}.stream_id")
    _uint(fields[1], f"{label}.raw_counter")
    _uint(fields[2], f"{label}.next_shuffle_id")
    _uint(fields[3], f"{label}.next_branch_ordinal")
    _uint(fields[4], f"{label}.stream_generation")
    _bstr(fields[5], f"{label}.stream_event_hash")


def _validate_checkpoint_payload(payload: list[Any]) -> None:
    fields = _array(payload, 7, "CHECKPOINT payload")
    _uint(fields[0], "checkpoint_id")
    _uint(fields[1], "registry_generation")
    _uint(fields[2], "next_global_sequence")
    _uint(fields[3], "trace_byte_offset")
    if type(fields[4]) is not list:
        _fail("RNG_CHECKPOINT_INVALID", "stream_states must be an array")
    for index, row in enumerate(fields[4]):
        _validate_stream_state_row(row, f"stream_states[{index}]")
    _validate_sorted_unique_rows(fields[4], "stream_states")
    _bstr(fields[5], "resume_capability_commitment")
    _bstr(fields[6], "gateway_state_root")


def _validate_restore_payload(payload: list[Any]) -> None:
    if type(payload) is list and len(payload) == 7:
        _fail("RNG_PROTOCOL_631301_RETIRED", "the seven-field restore payload is retired")
    fields = _array(payload, 8, "RESTORE payload")
    _uint(fields[0], "checkpoint_id")
    _bstr(fields[1], "checkpoint_event_hash")
    old = _uint(fields[2], "old_registry_generation")
    new = _uint(fields[3], "new_registry_generation")
    if old == UINT64_MAX or new != old + 1:
        _fail("RNG_RESTORE_REGISTRY_GENERATION_INVALID", "registry generation must advance exactly once")
    _bstr(fields[4], "gateway_state_root")
    _bstr(fields[5], "resume_capability_opening")
    _bstr(fields[6], "resume_capability_proof")
    _uint(fields[7], "restored_trace_byte_offset")


def _validate_session_close_payload(payload: list[Any]) -> None:
    fields = _array(payload, 9, "SESSION_CLOSE payload")
    _bstr(fields[0], "seed_commitment_root")
    _bstr(fields[1], "run_binding_root")
    _uint(fields[2], "event_count")
    if type(fields[3]) is not list:
        _fail("RNG_SESSION_CLOSE_INVALID", "stream_summaries must be an array")
    for index, row in enumerate(fields[3]):
        if type(row) is not list or len(row) != 5:
            _fail("RNG_SESSION_CLOSE_INVALID", f"stream_summaries[{index}] must have five fields")
        _bstr(row[0], f"stream_summaries[{index}].stream_id")
        _uint(row[1], f"stream_summaries[{index}].raw_counter")
        _uint(row[2], f"stream_summaries[{index}].next_shuffle_id")
        _uint(row[3], f"stream_summaries[{index}].next_branch_ordinal")
        _bstr(row[4], f"stream_summaries[{index}].stream_event_hash")
    _validate_sorted_unique_rows(fields[3], "stream_summaries")
    _bstr(fields[4], "latest_checkpoint_event_hash")
    _bstr(fields[5], "canonical_trace_manifest_root")
    _bstr(fields[6], "end_engine_state_root")
    _uint(fields[7], "open_branch_count", 0xFFFFFFFF)
    _uint(fields[8], "close_code", 0xFFFF)
    if fields[8] == 0 and fields[7] != 0:
        _fail("RNG_SESSION_CLOSE_INVALID", "normal close cannot report open branches")


def _validate_sorted_unique_rows(rows: list[list[Any]], label: str) -> None:
    ids = [row[0] for row in rows]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        _fail("RNG_CANONICAL_CBOR_MISMATCH", f"{label} must be sorted bytewise with unique stream IDs")


@dataclass(slots=True)
class _BranchState:
    branch_id: bytes
    parent_branch_id: bytes
    genesis: bytes
    head: bytes
    event_count: int = 0
    raw_counter: int = 0
    next_shuffle_id: int = 0
    next_branch_ordinal: int = 0
    open: bool = True


@dataclass(slots=True)
class _StreamState:
    stream_id: bytes
    event_hash: bytes = ZERO_ID
    raw_counter: int = 0
    next_shuffle_id: int = 0
    next_branch_ordinal: int = 0
    generation: int = 0
    history: list[RuntimeEvent] = field(default_factory=list)
    branches: dict[bytes, _BranchState] = field(default_factory=dict)
    branch_stack: list[bytes] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class VerifiedEventChain:
    """Read-only result of a complete in-memory event-chain verification."""

    events: tuple[RuntimeEvent, ...]
    event_hashes: tuple[bytes, ...]
    stream_event_hashes: Mapping[bytes, bytes]
    trace_root: bytes
    trace_byte_length: int
    closed: bool

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass(slots=True)
class _Checkpoint:
    checkpoint_id: int
    event_hash: bytes
    registry_generation: int
    next_global_sequence: int
    trace_byte_offset: int
    checkpoint_end_offset: int
    stream_states: list[list[Any]]
    resume_capability_commitment: bytes
    resume_capability: bytes
    gateway_state_root: bytes
    restored: bool = False


def _branch_for(stream: _StreamState, branch_id: bytes) -> _BranchState | None:
    if branch_id == ZERO_ID:
        return None
    branch = stream.branches.get(branch_id)
    if branch is None:
        _fail("RNG_BRANCH_CONTEXT_MISMATCH", "branch is not known in this stream")
    if not branch.open:
        _fail("RNG_BRANCH_EVENT_AFTER_CLOSE", "event references a closed branch")
    return branch


def _top_branch_id(stream: _StreamState) -> bytes:
    return ZERO_ID if not stream.branch_stack else stream.branch_stack[-1]


def _branch_leaf(event: RuntimeEvent) -> bytes:
    return _digest(
        DS_BRANCH_LEAF,
        canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                event.event_type,
                event.session_id,
                event.stream_id,
                event.branch_context_id,
                event.as_array()[9],
            ]
        ),
    )


def _branch_genesis(
    session_id: bytes,
    stream_id: bytes,
    parent_branch_id: bytes,
    child_branch_id: bytes,
    fork_leaf: bytes,
) -> bytes:
    return _digest(
        DS_BRANCH_GENESIS,
        canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                session_id,
                stream_id,
                parent_branch_id,
                child_branch_id,
                fork_leaf,
            ]
        ),
    )


def _branch_step(branch: _BranchState, event: RuntimeEvent, leaf: bytes) -> bytes:
    return _digest(
        DS_BRANCH_STEP,
        canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                event.session_id,
                event.stream_id,
                event.branch_context_id,
                event.previous_branch_chain_hash,
                leaf,
            ]
        ),
    )


def _branch_final(session_id: bytes, stream_id: bytes, branch: _BranchState) -> bytes:
    return _digest(
        DS_BRANCH_FINAL,
        canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                session_id,
                stream_id,
                branch.branch_id,
                branch.parent_branch_id,
                branch.genesis,
                branch.head,
                branch.event_count,
                branch.raw_counter,
                branch.next_shuffle_id,
                branch.next_branch_ordinal,
            ]
        ),
    )


def _counter_state(stream: _StreamState, branch_id: bytes) -> tuple[int, int]:
    branch = _branch_for(stream, branch_id)
    if branch is None:
        return stream.raw_counter, stream.next_shuffle_id
    return branch.raw_counter, branch.next_shuffle_id


def _set_raw_counter(stream: _StreamState, branch_id: bytes, value: int) -> None:
    branch = _branch_for(stream, branch_id)
    if value > UINT64_MAX:
        _fail("RNG_COUNTER_WRAPAROUND", "raw counter wrapped")
    if branch is None:
        stream.raw_counter = value
    else:
        branch.raw_counter = value


def _set_shuffle_id(stream: _StreamState, branch_id: bytes, value: int) -> None:
    branch = _branch_for(stream, branch_id)
    if value > UINT64_MAX:
        _fail("RNG_COUNTER_WRAPAROUND", "shuffle ID wrapped")
    if branch is None:
        stream.next_shuffle_id = value
    else:
        branch.next_shuffle_id = value


def _branch_summary(stream: _StreamState) -> int:
    return sum(1 for branch in stream.branches.values() if branch.open)


def _validate_nonterminal_branch_context(stream: _StreamState, event: RuntimeEvent) -> None:
    expected_context = _top_branch_id(stream)
    if event.branch_context_id != expected_context:
        referenced = stream.branches.get(event.branch_context_id)
        if referenced is not None and not referenced.open:
            _fail("RNG_BRANCH_EVENT_AFTER_CLOSE", "event references a closed branch")
        _fail(
            "RNG_SAME_STREAM_BRANCH_INTERLEAVING_INVALID",
            "same-stream event does not execute in the current top branch",
        )
    if expected_context != ZERO_ID:
        branch = _branch_for(stream, expected_context)
        if branch is None or event.previous_branch_chain_hash != branch.head:
            _fail("RNG_BRANCH_PREDECESSOR_MISMATCH", "branch predecessor is not the current branch head")


def _validate_terminal_branch_context(stream: _StreamState, event: RuntimeEvent) -> _BranchState:
    child_id = event.payload[0]
    referenced = stream.branches.get(child_id)
    if referenced is not None and not referenced.open:
        _fail("RNG_BRANCH_EVENT_AFTER_CLOSE", "terminal event references a closed branch")
    if child_id in stream.branch_stack and stream.branch_stack[-1] != child_id:
        _fail(
            "RNG_BRANCH_DESCENDANT_OPEN_AT_TERMINATION",
            "a branch cannot terminate while its descendant is open",
        )
    if not stream.branch_stack or stream.branch_stack[-1] != child_id:
        _fail("RNG_BRANCH_STACK_VIOLATION", "terminal event does not target the current top branch")
    child = _branch_for(stream, child_id)
    if child is None or child.parent_branch_id != event.branch_context_id:
        _fail("RNG_BRANCH_TERMINAL_PARENT_MISMATCH", "terminal event context is not the child parent")
    expected_parent = ZERO_ID if len(stream.branch_stack) == 1 else stream.branch_stack[-2]
    if child.parent_branch_id != expected_parent:
        _fail("RNG_BRANCH_STACK_VIOLATION", "child parent is not adjacent in the LIFO branch stack")
    if expected_parent == ZERO_ID:
        if event.previous_branch_chain_hash != ZERO_ID:
            _fail("RNG_BRANCH_PREDECESSOR_MISMATCH", "authoritative parent has no branch predecessor")
    else:
        parent = _branch_for(stream, expected_parent)
        if parent is None or event.previous_branch_chain_hash != parent.head:
            _fail("RNG_BRANCH_PREDECESSOR_MISMATCH", "terminal event does not link to the parent head")
    return child


def _advance_branch_context(stream: _StreamState, event: RuntimeEvent, leaf: bytes) -> None:
    if event.branch_context_id == ZERO_ID:
        return
    branch = _branch_for(stream, event.branch_context_id)
    if branch is None:
        _fail("RNG_BRANCH_EVENT_AFTER_CLOSE", "event references a missing or closed branch")
    if branch.event_count == UINT64_MAX:
        _fail("RNG_COUNTER_WRAPAROUND", "branch event count wrapped")
    branch.head = _branch_step(branch, event, leaf)
    branch.event_count += 1


def _state_root(session_id: bytes, generation: int, next_sequence: int, offset: int, rows: list[list[Any]]) -> bytes:
    return _digest(DS_STATE, canonical_cbor_encode([session_id, generation, next_sequence, offset, rows]))


def _validate_bounded_against_history(stream: _StreamState, event: RuntimeEvent) -> None:
    branch_id, upper, first, count, accepted, result = event.payload
    history = stream.history
    if len(history) < count:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "bounded sample does not have enough preceding RAW_DRAW events")
    referenced = history[-count:]
    for index, raw_event in enumerate(referenced):
        if raw_event.event_type != EVENT_RAW_DRAW or raw_event.payload[0] != branch_id:
            _fail("RNG_BOUNDED_SAMPLE_INVALID", "bounded sample raw draws are not contiguous and immediately preceding")
        expected_counter = first + index
        if raw_event.payload[1] != expected_counter:
            _fail("RNG_BOUNDED_SAMPLE_INVALID", "bounded sample raw interval is not contiguous")
        limit = UINT64_SPACE - (UINT64_SPACE % upper)
        raw_value = raw_event.payload[2]
        if index < count - 1 and raw_value < limit:
            _fail("RNG_BOUNDED_SAMPLE_INVALID", "rejected raw draw is below the rejection limit")
        if index == count - 1 and raw_value >= limit:
            _fail("RNG_BOUNDED_SAMPLE_INVALID", "accepted raw draw is at or above the rejection limit")
    if referenced[-1].payload[1] != accepted or result != referenced[-1].payload[2] % upper:
        _fail("RNG_BOUNDED_SAMPLE_INVALID", "bounded result does not match the accepted raw draw")


def _validate_shuffle_against_history(stream: _StreamState, event: RuntimeEvent) -> None:
    branch_id, _shuffle_id, start, end, before, permutation, after = event.payload
    n = len(before)
    if n < 2:
        if start != end:
            _fail("RNG_SHUFFLE_INVALID", "empty and singleton shuffles consume no bounded samples")
        return
    cursor = len(stream.history)
    reversed_bounded: list[RuntimeEvent] = []
    for _ in range(n - 1):
        if cursor == 0 or stream.history[cursor - 1].event_type != EVENT_BOUNDED_SAMPLE:
            _fail(
                "RNG_SHUFFLE_INVALID",
                "every Fisher-Yates draw group must end in a bounded sample",
            )
        bounded = stream.history[cursor - 1]
        cursor -= 1
        raw_draw_count = bounded.payload[3]
        if cursor < raw_draw_count:
            _fail("RNG_SHUFFLE_INVALID", "bounded sample raw-draw group is truncated")
        raw_group = stream.history[cursor - raw_draw_count:cursor]
        if any(
            raw.event_type != EVENT_RAW_DRAW or raw.payload[0] != branch_id
            for raw in raw_group
        ):
            _fail(
                "RNG_SHUFFLE_INVALID",
                "Fisher-Yates bounded samples must be preceded by their exact raw draws",
            )
        cursor -= raw_draw_count
        reversed_bounded.append(bounded)
    bounded_events = list(reversed(reversed_bounded))
    expected_permutation = list(range(n))
    first_counter: int | None = None
    previous_end: int | None = None
    for offset, bounded in enumerate(bounded_events):
        payload = bounded.payload
        if payload[0] != branch_id or payload[1] != n - offset:
            _fail("RNG_SHUFFLE_INVALID", "Fisher-Yates bounded sample interval is invalid")
        if first_counter is None:
            first_counter = payload[2]
        if previous_end is not None and payload[2] != previous_end:
            _fail("RNG_SHUFFLE_INVALID", "Fisher-Yates raw intervals are not contiguous")
        previous_end = payload[4] + 1
        j = payload[5]
        i = n - 1 - offset
        if j > i:
            _fail("RNG_SHUFFLE_INVALID", "Fisher-Yates result is outside its interval")
        expected_permutation[i], expected_permutation[j] = expected_permutation[j], expected_permutation[i]
    if first_counter != start or previous_end != end or list(permutation) != expected_permutation:
        _fail("RNG_SHUFFLE_INVALID", "shuffle counters or permutation do not match preceding samples")
    if [before[index] for index in permutation] != list(after):
        _fail("RNG_SHUFFLE_INVALID", "shuffle orientation must be after[j] = before[permutation[j]]")


def verify_event_chain(
    events: Iterable[RuntimeEvent | bytes | list[Any]],
    *,
    expected_session_id: bytes | None = None,
    evaluator_secret: bytes | None = None,
    expected_run_binding_root: bytes | None = None,
    _allow_checkpoint_terminal: bool = False,
) -> VerifiedEventChain:
    """Verify global/stream chains and all event-specific state transitions."""

    raw_events = tuple(events)
    if not raw_events:
        _fail("RNG_EVENT_CHAIN_MISMATCH", "event chain cannot be empty")
    if expected_session_id is not None:
        _bstr(expected_session_id, "expected_session_id")
    arrays = tuple(_decode_value(item) for item in raw_events)
    versions = {array[0] for array in arrays if type(array) is list and array}
    if len(versions) > 1:
        _fail("RNG_MIXED_PROTOCOL_SESSION", "event chain mixes protocol versions")
    if versions == {RETIRED_PROTOCOL_VERSION}:
        _fail("RNG_PROTOCOL_631301_RETIRED", "event chain uses retired protocol 631301")
    decoded = tuple(RuntimeEvent.from_array(array) for array in arrays)
    session_id = decoded[0].session_id
    if expected_session_id is not None and session_id != expected_session_id:
        _fail("RNG_EVENT_CHAIN_MISMATCH", "event chain session ID differs from expected session")
    streams: dict[bytes, _StreamState] = {}
    global_previous = ZERO_ID
    hashes: list[bytes] = []
    checkpoints: dict[int, _Checkpoint] = {}
    latest_checkpoint: _Checkpoint | None = None
    generation = 0
    next_checkpoint_id = 0
    closed = False
    trace_byte_length = 0

    for expected_sequence, event in enumerate(decoded):
        if closed:
            _fail("RNG_EVENT_CHAIN_MISMATCH", "events cannot follow SESSION_CLOSE")
        if event.session_id != session_id or event.global_sequence != expected_sequence:
            _fail("RNG_EVENT_CHAIN_MISMATCH", "global sequence or session ID is not exact")
        if event.previous_global_event_hash != global_previous:
            _fail("RNG_EVENT_CHAIN_MISMATCH", "previous global event hash does not link")
        event_bytes = event.to_bytes()
        current_hash = event.event_hash()
        if event.event_type == EVENT_STREAM_BIND:
            site, object_id, purpose, ordinal = event.payload
            expected_stream_id = derive_stream_id(session_id, site, object_id, purpose, ordinal)
            if event.stream_id != expected_stream_id:
                _fail("RNG_CALLER_SUPPLIED_STREAM_ID", "STREAM_BIND stream_id is not compiler-derived")
            if event.previous_stream_event_hash != ZERO_ID or event.stream_id in streams:
                _fail("RNG_STREAM_BIND_DUPLICATE", "stream binding must be unique and first in its stream")
            streams[event.stream_id] = _StreamState(event.stream_id, event_hash=current_hash, history=[event])
        elif event.event_type in STREAM_EVENT_TYPES:
            stream = streams.get(event.stream_id)
            if stream is None:
                _fail("RNG_STREAM_CHAIN_MISMATCH", "stream event precedes its STREAM_BIND")
            if event.previous_stream_event_hash != stream.event_hash:
                _fail("RNG_STREAM_CHAIN_MISMATCH", "previous stream event hash does not link")
            leaf = _branch_leaf(event)
            if event.event_type in (EVENT_BRANCH_COMMIT, EVENT_BRANCH_ABORT):
                _validate_terminal_branch_context(stream, event)
            else:
                _validate_nonterminal_branch_context(stream, event)
            _apply_stream_event(stream, event, session_id, leaf)
            stream.history.append(event)
            stream.event_hash = current_hash
            _advance_branch_context(stream, event, leaf)
        else:
            if event.stream_id != ZERO_ID or event.previous_stream_event_hash != ZERO_ID:
                _fail("RNG_EVENT_CHAIN_MISMATCH", "session-wide event has a stream chain field")
            if event.event_type == EVENT_CHECKPOINT:
                checkpoint = _apply_checkpoint(
                    event,
                    current_hash,
                    streams,
                    generation,
                    expected_sequence,
                    latest_checkpoint,
                    next_checkpoint_id,
                    session_id,
                    trace_byte_length,
                    len(event_bytes),
                    evaluator_secret,
                    expected_run_binding_root,
                )
                checkpoints[checkpoint.checkpoint_id] = checkpoint
                latest_checkpoint = checkpoint
                next_checkpoint_id += 1
            elif event.event_type == EVENT_RESTORE:
                generation = _apply_restore(
                    event,
                    current_hash,
                    streams,
                    generation,
                    expected_sequence,
                    latest_checkpoint,
                    checkpoints,
                    trace_byte_length,
                    evaluator_secret,
                    expected_run_binding_root,
                )
            else:
                _apply_session_close(
                    event,
                    streams,
                    expected_sequence,
                    latest_checkpoint,
                    expected_run_binding_root,
                )
                closed = True
        global_previous = current_hash
        hashes.append(current_hash)
        trace_byte_length += len(event_bytes)

    if not closed and not (
        _allow_checkpoint_terminal
        and decoded[-1].event_type == EVENT_CHECKPOINT
    ):
        _fail("RNG_EVENT_CHAIN_MISMATCH", "event chain must terminate with SESSION_CLOSE")
    stream_hashes = MappingProxyType({stream_id: stream.event_hash for stream_id, stream in streams.items()})
    return VerifiedEventChain(decoded, tuple(hashes), stream_hashes, hashes[-1], trace_byte_length, closed)


def verify_checkpoint_trace_prefix(
    trace_bytes: bytes,
    *,
    expected_session_id: bytes,
    evaluator_secret: bytes,
    expected_run_binding_root: bytes,
) -> VerifiedEventChain:
    """Fully verify a durable trace whose literal last event is CHECKPOINT."""

    result = verify_event_chain(
        decode_trace_events(trace_bytes),
        expected_session_id=expected_session_id,
        evaluator_secret=evaluator_secret,
        expected_run_binding_root=expected_run_binding_root,
        _allow_checkpoint_terminal=True,
    )
    if result.events[-1].event_type != EVENT_CHECKPOINT:
        _fail("RNG_RESTORE_CHECKPOINT_NOT_LATEST", "durable trace does not end in CHECKPOINT")
    return result


verify_chain = verify_event_chain
validate_event = validate_event_envelope
compute_event_hash = event_hash
decode_event = RuntimeEvent.from_bytes


def _apply_stream_event(
    stream: _StreamState,
    event: RuntimeEvent,
    session_id: bytes,
    leaf: bytes,
) -> None:
    payload = event.payload
    if event.event_type == EVENT_RAW_DRAW:
        branch_id, counter, _raw = payload
        current, _ = _counter_state(stream, branch_id)
        if current == UINT64_MAX or counter != current:
            _fail("RNG_COUNTER_WRAPAROUND" if current == UINT64_MAX else "RNG_COUNTER_GAP", "RAW_DRAW counter is not the next exact counter")
        _set_raw_counter(stream, branch_id, current + 1)
    elif event.event_type == EVENT_BOUNDED_SAMPLE:
        branch_id, _upper, first, count, _accepted, _result = payload
        current, _ = _counter_state(stream, branch_id)
        if first + count > current:
            _fail("RNG_BOUNDED_SAMPLE_INVALID", "bounded sample references raw draws not present in the stream")
        _validate_bounded_against_history(stream, event)
    elif event.event_type == EVENT_SHUFFLE:
        branch_id, shuffle_id, _start, _end, _before, _permutation, _after = payload
        _current_raw, current_shuffle = _counter_state(stream, branch_id)
        if current_shuffle == UINT64_MAX or shuffle_id != current_shuffle:
            _fail("RNG_CALLER_SUPPLIED_SHUFFLE_ID" if shuffle_id != current_shuffle else "RNG_COUNTER_WRAPAROUND", "shuffle ID is not the next gateway counter")
        _validate_shuffle_against_history(stream, event)
        _set_shuffle_id(stream, branch_id, current_shuffle + 1)
    elif event.event_type == EVENT_BRANCH_FORK:
        parent_id, child_id, ordinal, purpose_id, parent_raw, parent_shuffle, parent_state_root = payload
        if child_id in stream.branches or child_id == ZERO_ID:
            _fail("RNG_BRANCH_ID_INVALID", "branch ID is already in use")
        parent = _branch_for(stream, parent_id)
        parent_raw_current, parent_shuffle_current = _counter_state(stream, parent_id)
        if parent_raw != parent_raw_current or parent_shuffle != parent_shuffle_current:
            _fail("RNG_BRANCH_PARENT_STATE_MUTATED", "fork does not describe the exact parent state")
        parent_ordinal = stream.next_branch_ordinal if parent is None else parent.next_branch_ordinal
        if ordinal != parent_ordinal:
            _fail("RNG_COUNTER_GAP", "branch ordinal is not the next exact counter")
        expected_child = _digest(
            DS_BRANCH_ID,
            session_id + stream.stream_id + parent_id + ordinal.to_bytes(8, "big") + purpose_id + parent_state_root,
        )
        if child_id != expected_child:
            _fail("RNG_BRANCH_ID_INVALID", "branch ID is not derived from the fork payload")
        if parent is None:
            if stream.next_branch_ordinal == UINT64_MAX:
                _fail("RNG_COUNTER_WRAPAROUND", "branch ordinal wrapped")
            stream.next_branch_ordinal += 1
        else:
            if parent.next_branch_ordinal == UINT64_MAX:
                _fail("RNG_COUNTER_WRAPAROUND", "branch ordinal wrapped")
            parent.next_branch_ordinal += 1
        genesis = _branch_genesis(session_id, stream.stream_id, parent_id, child_id, leaf)
        stream.branches[child_id] = _BranchState(
            branch_id=child_id,
            parent_branch_id=parent_id,
            genesis=genesis,
            head=genesis,
        )
        stream.branch_stack.append(child_id)
    elif event.event_type in (EVENT_BRANCH_COMMIT, EVENT_BRANCH_ABORT):
        branch_id, branch_raw, branch_shuffle, branch_trace_root = payload[:4]
        branch = _branch_for(stream, branch_id)
        if branch is None or branch_raw != branch.raw_counter or branch_shuffle != branch.next_shuffle_id:
            _fail("RNG_BRANCH_FINAL_STATE_MISMATCH", "branch end payload is not the exact current branch state")
        if any(item.open and item.parent_branch_id == branch_id for item in stream.branches.values()):
            _fail(
                "RNG_BRANCH_DESCENDANT_OPEN_AT_TERMINATION",
                "a branch cannot end while a child branch is open",
            )
        if branch_trace_root != _branch_final(session_id, stream.stream_id, branch):
            _fail("RNG_BRANCH_TRACE_ROOT_MISMATCH", "branch terminal root is not independently derived")
        branch.open = False
        popped = stream.branch_stack.pop()
        if popped != branch_id:  # pragma: no cover - validated before dispatch
            _fail("RNG_BRANCH_STACK_VIOLATION", "branch stack changed during termination")


def _apply_checkpoint(
    event: RuntimeEvent,
    current_hash: bytes,
    streams: Mapping[bytes, _StreamState],
    generation: int,
    expected_sequence: int,
    latest_checkpoint: _Checkpoint | None,
    expected_checkpoint_id: int,
    session_id: bytes,
    trace_byte_offset_before: int,
    event_byte_length: int,
    evaluator_secret: bytes | None,
    expected_run_binding_root: bytes | None,
) -> _Checkpoint:
    checkpoint_id, row_generation, next_sequence, offset, rows, commitment, root = event.payload
    rows_as_lists = _thaw_cbor_tree(rows)
    if any(_branch_summary(stream) for stream in streams.values()):
        _fail("RNG_CHECKPOINT_WITH_OPEN_BRANCH", "checkpoint cannot be taken with an open branch")
    if row_generation != generation or checkpoint_id != expected_checkpoint_id:
        _fail("RNG_CHECKPOINT_INVALID", "checkpoint counters or registry generation are not exact")
    if next_sequence != expected_sequence + 1:
        _fail("RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH", "checkpoint next sequence is not exact")
    if offset != trace_byte_offset_before:
        _fail("RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH", "checkpoint offset is not the first byte of the checkpoint event")
    expected_rows = [
        [stream_id, stream.raw_counter, stream.next_shuffle_id, stream.next_branch_ordinal, generation, stream.event_hash]
        for stream_id, stream in sorted(streams.items())
    ]
    if rows_as_lists != expected_rows:
        _fail("RNG_CHECKPOINT_INVALID", "checkpoint stream states do not match the event chains")
    if root != _state_root(session_id, generation, next_sequence, offset, rows_as_lists):
        _fail("RNG_CHECKPOINT_INVALID", "gateway_state_root does not match checkpoint state")
    if evaluator_secret is None or expected_run_binding_root is None:
        _fail(
            "RNG_RESUME_SESSION_KEY_CONTEXT_INVALID",
            "checkpoint verification requires the exact evaluator secret and run binding root",
        )
    try:
        core = build_checkpoint_core(
            session_id,
            checkpoint_id,
            generation,
            next_sequence,
            offset,
            root,
        )
        session_key = derive_session_resume_key(
            evaluator_secret,
            session_id,
            expected_run_binding_root,
        )
        resume_capability = derive_resume_capability(session_key, core)
        verify_resume_capability_commitment(commitment, core, resume_capability)
    except UnifiedRngProtocolError as exc:
        _raise_as_event_error(exc)
    return _Checkpoint(
        checkpoint_id,
        current_hash,
        generation,
        next_sequence,
        offset,
        offset + event_byte_length,
        rows_as_lists,
        commitment,
        resume_capability,
        root,
    )


def _apply_restore(
    event: RuntimeEvent,
    _current_hash: bytes,
    streams: Mapping[bytes, _StreamState],
    generation: int,
    expected_sequence: int,
    latest_checkpoint: _Checkpoint | None,
    checkpoints: Mapping[int, _Checkpoint],
    trace_byte_offset_before: int,
    evaluator_secret: bytes | None,
    expected_run_binding_root: bytes | None,
) -> int:
    (
        checkpoint_id,
        checkpoint_hash,
        old_generation,
        new_generation,
        root,
        resume_opening,
        resume_proof,
        offset,
    ) = event.payload
    checkpoint = checkpoints.get(checkpoint_id)
    if checkpoint is None or latest_checkpoint is not checkpoint:
        _fail("RNG_RESTORE_CHECKPOINT_NOT_LATEST", "restore must reference the newest durable checkpoint")
    if checkpoint.restored:
        _fail("RNG_RESUME_CAPABILITY_REUSED", "checkpoint restore capability was already consumed")
    if checkpoint.event_hash != checkpoint_hash:
        _fail("RNG_RESUME_CAPABILITY_CAPSULE_INVALID", "restore references a forged checkpoint hash")
    if expected_sequence != checkpoint.next_global_sequence:
        _fail("RNG_RESTORE_CHECKPOINT_SUCCESSOR_EXISTS", "checkpoint already has a successor event")
    if old_generation != generation or new_generation != generation + 1:
        _fail("RNG_RESTORE_REGISTRY_GENERATION_INVALID", "restore generation transition is not exact")
    if root != checkpoint.gateway_state_root:
        _fail("RNG_RESTORE_INVALID", "restore state root does not match the checkpoint")
    if trace_byte_offset_before != checkpoint.checkpoint_end_offset:
        _fail("RNG_RESTORE_TRACE_LENGTH_MISMATCH", "durable trace does not end exactly after the checkpoint")
    if offset != checkpoint.checkpoint_end_offset:
        _fail("RNG_RESTORE_TRACE_OFFSET_MISMATCH", "restore offset is not the checkpoint end offset")
    if evaluator_secret is None or expected_run_binding_root is None:
        _fail(
            "RNG_RESUME_SESSION_KEY_CONTEXT_INVALID",
            "restore verification requires the exact evaluator secret and run binding root",
        )
    try:
        core = build_checkpoint_core(
            event.session_id,
            checkpoint.checkpoint_id,
            checkpoint.registry_generation,
            checkpoint.next_global_sequence,
            checkpoint.trace_byte_offset,
            checkpoint.gateway_state_root,
        )
        session_key = derive_session_resume_key(
            evaluator_secret,
            event.session_id,
            expected_run_binding_root,
        )
        verify_resume_capability(resume_opening, session_key, core)
        verify_resume_capability_commitment(
            checkpoint.resume_capability_commitment,
            core,
            resume_opening,
        )
        verify_resume_capability_proof(
            resume_proof,
            event.session_id,
            checkpoint.checkpoint_id,
            checkpoint.event_hash,
            old_generation,
            new_generation,
            checkpoint.gateway_state_root,
            resume_opening,
        )
    except UnifiedRngProtocolError as exc:
        _raise_as_event_error(exc)
    for stream_id, stream in streams.items():
        row = next((item for item in checkpoint.stream_states if item[0] == stream_id), None)
        if row is None or row[1:] != [stream.raw_counter, stream.next_shuffle_id, stream.next_branch_ordinal, generation, stream.event_hash]:
            _fail("RNG_RESTORE_INVALID", "restore stream state does not match the checkpoint")
    checkpoint.restored = True
    for stream in streams.values():
        stream.generation = new_generation
    return new_generation


def _apply_session_close(
    event: RuntimeEvent,
    streams: Mapping[bytes, _StreamState],
    expected_sequence: int,
    latest_checkpoint: _Checkpoint | None,
    expected_run_binding_root: bytes | None,
) -> None:
    seed_root, run_root, event_count, summaries, latest_hash, _manifest, _engine, open_count, close_code = event.payload
    del seed_root
    if expected_run_binding_root is not None and run_root != expected_run_binding_root:
        _fail("RNG_SESSION_CLOSE_INVALID", "session close references a different run binding root")
    summaries_as_lists = _thaw_cbor_tree(summaries)
    if event_count != expected_sequence + 1:
        _fail("RNG_SESSION_CLOSE_INVALID", "event_count does not equal global sequence plus one")
    actual_open = sum(_branch_summary(stream) for stream in streams.values())
    if open_count != actual_open:
        _fail("RNG_SESSION_CLOSE_INVALID", "open_branch_count does not match the branch state")
    if close_code == 0 and actual_open != 0:
        _fail("RNG_SESSION_CLOSE_INVALID", "normal close requires no open branches")
    expected_summaries = [
        [stream_id, stream.raw_counter, stream.next_shuffle_id, stream.next_branch_ordinal, stream.event_hash]
        for stream_id, stream in sorted(streams.items())
    ]
    if summaries_as_lists != expected_summaries:
        _fail("RNG_SESSION_CLOSE_INVALID", "stream summaries do not match the stream chains")
    expected_latest = ZERO_ID if latest_checkpoint is None else latest_checkpoint.event_hash
    if latest_hash != expected_latest:
        _fail("RNG_SESSION_CLOSE_INVALID", "latest checkpoint hash is not exact")


__all__ = [
    "EVENT_STREAM_BIND", "EVENT_RAW_DRAW", "EVENT_BOUNDED_SAMPLE", "EVENT_SHUFFLE",
    "EVENT_BRANCH_FORK", "EVENT_BRANCH_COMMIT", "EVENT_BRANCH_ABORT", "EVENT_CHECKPOINT",
    "EVENT_RESTORE", "EVENT_SESSION_CLOSE", "STREAM_BIND", "RAW_DRAW", "BOUNDED_SAMPLE",
    "SHUFFLE", "BRANCH_FORK", "BRANCH_COMMIT", "BRANCH_ABORT", "CHECKPOINT", "RESTORE",
    "SESSION_CLOSE", "UINT64_SPACE", "UnifiedRngEventError", "UnifiedRngEventsError",
    "RuntimeEvent", "VerifiedEventChain", "build_event", "make_event", "event_hash",
    "compute_event_hash", "decode_event", "decode_trace", "decode_trace_events", "verify_trace_bytes",
    "derive_event_stream_id", "derive_bound_stream_id", "stream_bind_payload", "raw_draw_payload",
    "bounded_sample_payload", "shuffle_payload", "branch_fork_payload", "branch_commit_payload",
    "branch_abort_payload", "checkpoint_payload", "restore_payload", "session_close_payload",
    "validate_event_envelope", "validate_event", "verify_checkpoint_trace_prefix",
    "verify_event_chain", "verify_chain",
]
