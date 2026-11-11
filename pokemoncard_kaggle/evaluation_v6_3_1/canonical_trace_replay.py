"""Bounded, offline conformance for the v6.3.1 canonical engine trace.

This is Packages 1 and 2 of the frozen architecture: fixed-array CBOR
headers/events, stable semantic identities, append-only framing, and an
adapter-based event-application replayer.  It is intentionally not an engine,
an attestation service, a permit verifier, or a campaign interface.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import struct
from typing import Any, Protocol

from .canonical_trace_codec import (
    CanonicalTraceCodecError,
    canonical_cbor_decode,
    canonical_cbor_encode,
)
from .common import freeze, zero_authority


TRACE_SCHEMA_VERSION = 1
HEADER_FIELD_COUNT = 24
EVENT_CORE_FIELD_COUNT = 15
EVENT_PAYLOAD_FIELD_COUNT = 3
ROOT_BYTES = 32

NONE = 0
MUTATION = 1

# Complete frozen taxonomy. Numeric codes keep canonical records independent
# from spelling; the rooted taxonomy artifact fixes their external meaning.
TRACE_BEGIN = 1
GAME_CONSTRUCTED = 2
SEED_DESCRIPTOR_BOUND = 3
PLAYER_PROCESS_BOUND = 4
DECK_INSTANTIATED = 5
SETUP_BEGIN = 6
MULLIGAN_BEGIN = 7
MULLIGAN_DECISION = 8
MULLIGAN_CARD_RETURN = 9
MULLIGAN_REDRAW = 10
MULLIGAN_END = 11
SETUP_ACTIVE_REQUIRED = 12
SETUP_ACTIVE_PLACED = 13
SETUP_BENCH_SELECTION = 14
SETUP_BENCH_PLACED = 15
PRIZE_SETUP_BEGIN = 16
PRIZE_SETUP_END = 17
STARTING_PLAYER_SELECTED = 18
BATTLE_START = 19
TURN_START = 20
MANDATORY_PROCESSING_COMPLETE = 21
FIRST_DECISION_CHECKPOINT = 22
TURN_END = 23
ROUND_BARRIER = 24
TRACE_END = 25
TRACE_ABORT = 26

SELECTION_PUSH = 30
LEGAL_OPTION_SET = 31
AGENT_REQUEST = 32
AGENT_RESPONSE = 33
CHOICE_ACCEPTED = 34
CHOICE_REJECTED = 35
FORCED_CHOICE = 36
SELECTION_POP = 37

ACTION_BEGIN = 40
ACTION_COMMIT = 41
ACTION_END = 42
EFFECT_BEGIN = 43
EFFECT_END = 44
COST_PLAN_CREATED = 45
COST_COMPONENT_PAID = 46
COST_PLAN_CLOSED = 47
ATTACK_DECLARE = 48
ATTACK_RESOLUTION_BEGIN = 49
ATTACK_RESOLUTION_END = 50

RNG_STREAM_BOUND = 60
RNG_DRAW = 61
RNG_BOUNDED_SAMPLE = 62
SHUFFLE_BEGIN = 63
SHUFFLE_APPLIED = 64
RANDOM_CHOICE_RESOLVED = 65
COIN_FLIP_RESOLVED = 66

RAW_DRAW_ALGORITHM_ID = "V631/SHA256-CBOR-COUNTER-RAW-UINT64/V2"
BOUNDED_SAMPLING_ALGORITHM_ID = "V631/UINT64-REJECTION-MODULO/V2"
SHUFFLE_ALGORITHM_ID = "V631/FISHER-YATES-UINT64-REJECTION/V2"
RAW_DRAW_BIT_COUNT = 64
UINT64_SPACE = 1 << 64

CARD_INSTANCE_CREATED = 70
CARD_MOVE = 71
ZONE_REORDER = 72
POKEMON_ENTITY_CREATED = 73
POKEMON_ENTITY_REMOVED = 74
EVOLUTION_STACK_CHANGED = 75
ATTACHMENT_CHANGED = 76

DAMAGE_CALCULATION = 80
DAMAGE_MODIFIER_APPLIED = 81
HP_CHANGE = 82
STATUS_CHANGE = 83
SEMANTIC_PROPERTY_CHANGE = 84

PRIZE_TRANSACTION_BEGIN = 90
PRIZE_CARD_ASSIGNED = 91
PRIZE_CARD_TAKEN = 92
PRIZE_TRANSACTION_END = 93

AGENT_PROCESS_START = 100
AGENT_ENTROPY_GRANTED = 101
AGENT_RESOURCE_OUTCOME = 102
AGENT_PROTOCOL_VIOLATION = 103
AGENT_PROCESS_EXIT = 104

TERMINAL_CANDIDATE = 110
TERMINAL_SET = 111
RESULT_EMITTED = 112

_MUTATION_EVENTS = frozenset({
    CARD_INSTANCE_CREATED, CARD_MOVE, ZONE_REORDER, POKEMON_ENTITY_CREATED,
    POKEMON_ENTITY_REMOVED, EVOLUTION_STACK_CHANGED, ATTACHMENT_CHANGED,
    HP_CHANGE, STATUS_CHANGE, SEMANTIC_PROPERTY_CHANGE, TERMINAL_SET,
})
_ORCHESTRATION_EVENTS = frozenset({
    TRACE_BEGIN, GAME_CONSTRUCTED, SEED_DESCRIPTOR_BOUND, PLAYER_PROCESS_BOUND,
    DECK_INSTANTIATED, SETUP_BEGIN, MULLIGAN_BEGIN, MULLIGAN_DECISION,
    MULLIGAN_CARD_RETURN, MULLIGAN_REDRAW, MULLIGAN_END, SETUP_ACTIVE_REQUIRED,
    SETUP_ACTIVE_PLACED, SETUP_BENCH_SELECTION, SETUP_BENCH_PLACED,
    PRIZE_SETUP_BEGIN, PRIZE_SETUP_END, STARTING_PLAYER_SELECTED, BATTLE_START,
    TURN_START, MANDATORY_PROCESSING_COMPLETE, FIRST_DECISION_CHECKPOINT,
    TURN_END, ROUND_BARRIER, TRACE_END, TRACE_ABORT, SELECTION_PUSH,
    LEGAL_OPTION_SET, AGENT_REQUEST, AGENT_RESPONSE, CHOICE_ACCEPTED,
    CHOICE_REJECTED, FORCED_CHOICE, SELECTION_POP, ACTION_BEGIN, ACTION_COMMIT,
    ACTION_END, EFFECT_BEGIN, EFFECT_END, COST_PLAN_CREATED, COST_COMPONENT_PAID,
    COST_PLAN_CLOSED, ATTACK_DECLARE, ATTACK_RESOLUTION_BEGIN,
    ATTACK_RESOLUTION_END, RNG_STREAM_BOUND, RNG_DRAW, RNG_BOUNDED_SAMPLE,
    SHUFFLE_BEGIN, SHUFFLE_APPLIED, RANDOM_CHOICE_RESOLVED, COIN_FLIP_RESOLVED,
    DAMAGE_CALCULATION, DAMAGE_MODIFIER_APPLIED, PRIZE_TRANSACTION_BEGIN,
    PRIZE_CARD_ASSIGNED, PRIZE_CARD_TAKEN, PRIZE_TRANSACTION_END,
    AGENT_PROCESS_START, AGENT_ENTROPY_GRANTED, AGENT_RESOURCE_OUTCOME,
    AGENT_PROTOCOL_VIOLATION, AGENT_PROCESS_EXIT, TERMINAL_CANDIDATE,
    RESULT_EMITTED,
})
_EVENT_TRANSITIONS = {event_type: MUTATION for event_type in _MUTATION_EVENTS}
_EVENT_TRANSITIONS.update({event_type: NONE for event_type in _ORCHESTRATION_EVENTS})

CANONICAL_OPTION_ID_ORDER = 3
_SNAPSHOT_EVENTS = frozenset(
    {TRACE_BEGIN, BATTLE_START, FIRST_DECISION_CHECKPOINT, TURN_END, ROUND_BARRIER, TERMINAL_SET, TRACE_END}
)
_ROOT_FIELDS = (
    "trace_schema_root", "state_schema_root", "event_taxonomy_root",
    "mutation_coverage_policy_root", "opened_engine_source_root", "derivative_source_root",
    "derivative_diff_root", "derivative_build_root", "ruleset_root", "card_catalog_root",
    "model_root", "population_root", "candidate_archive_sha256", "control_archive_sha256",
    "candidate_deck_root", "control_deck_root", "agent_process_manifest_roots",
    "agent_sandbox_policy_root", "seed_descriptor_root",
)


class CanonicalTraceReplayError(ValueError):
    """A trace violates a frozen fail-closed conformance rule."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> CanonicalTraceReplayError:
    return CanonicalTraceReplayError(code, message)


def _digest(domain: bytes, *parts: bytes) -> bytes:
    return sha256(domain + b"".join(parts)).digest()


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != ROOT_BYTES:
        raise _fail("TRACE_HEADER_INVALID", f"{label} must be a 32-byte digest")
    return value


def _u16(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise _fail("TRACE_HEADER_INVALID", f"{label} must be uint16")
    return value


def _u64(value: Any, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise _fail("TRACE_HEADER_INVALID", f"{label} must be uint64")
    return value


def _stable_id(domain: bytes, *parts: bytes) -> bytes:
    return _digest(domain, *parts)


def card_definition_id(canonical_card_definition: Any) -> bytes:
    return _stable_id(b"V631/CARD-DEFINITION", canonical_cbor_encode(canonical_card_definition))


def card_instance_id(game_id: bytes, owner_player_id: int, canonical_initial_deck_position: int) -> bytes:
    _root(game_id, "game_id")
    if type(owner_player_id) is not int or type(canonical_initial_deck_position) is not int or owner_player_id not in (0, 1) or not 0 <= canonical_initial_deck_position <= 0xFFFF:
        raise _fail("TRACE_ENTITY_ID_COLLISION", "card identity inputs are out of range")
    return _stable_id(b"V631/CARD-INSTANCE", game_id, bytes((owner_player_id,)), canonical_initial_deck_position.to_bytes(2, "big"))


def pokemon_entity_id(game_id: bytes, owner_player_id: int, owner_spawn_counter: int) -> bytes:
    _root(game_id, "game_id")
    if type(owner_player_id) is not int or type(owner_spawn_counter) is not int or owner_player_id not in (0, 1) or not 0 <= owner_spawn_counter <= 0xFFFFFFFF:
        raise _fail("TRACE_ENTITY_ID_COLLISION", "pokemon identity inputs are out of range")
    return _stable_id(b"V631/POKEMON-ENTITY", game_id, bytes((owner_player_id,)), owner_spawn_counter.to_bytes(4, "big"))


def selection_frame_id(game_id: bytes, selection_push_counter: int) -> bytes:
    _root(game_id, "game_id")
    _u64(selection_push_counter, "selection_push_counter")
    return _stable_id(b"V631/SELECTION", game_id, selection_push_counter.to_bytes(8, "big"))


def action_instance_id(game_id: bytes, action_commit_counter: int) -> bytes:
    _root(game_id, "game_id")
    _u64(action_commit_counter, "action_commit_counter")
    return _stable_id(b"V631/ACTION", game_id, action_commit_counter.to_bytes(8, "big"))


def effect_instance_id(game_id: bytes, creation_event_sequence: int, local_effect_ordinal: int) -> bytes:
    _root(game_id, "game_id")
    _u64(creation_event_sequence, "creation_event_sequence")
    if type(local_effect_ordinal) is not int or not 0 <= local_effect_ordinal <= 0xFFFFFFFF:
        raise _fail("TRACE_ENTITY_ID_COLLISION", "local_effect_ordinal must be uint32")
    return _stable_id(b"V631/EFFECT", game_id, creation_event_sequence.to_bytes(8, "big"), local_effect_ordinal.to_bytes(4, "big"))


def attack_instance_id(action_id: bytes, attack_definition_id: bytes) -> bytes:
    _root(action_id, "action_instance_id")
    _root(attack_definition_id, "attack_definition_id")
    return _stable_id(b"V631/ATTACK", action_id, attack_definition_id)


def mutation_id(game_id: bytes, event_sequence: int, mutation_family: int) -> bytes:
    _root(game_id, "game_id")
    _u64(event_sequence, "event_sequence")
    if type(mutation_family) is not int or not 0 <= mutation_family <= 0xFFFF:
        raise _fail("TRACE_ENTITY_ID_COLLISION", "mutation_family must be uint16")
    return _stable_id(b"V631/MUTATION", game_id, event_sequence.to_bytes(8, "big"), mutation_family.to_bytes(2, "big"))


def legal_option_id(frame_id: bytes, canonical_option: Any) -> bytes:
    _root(frame_id, "selection_frame_id")
    return _stable_id(b"V631/LEGAL-OPTION", frame_id, canonical_cbor_encode(canonical_option))


def state_root(state_schema_root: bytes, canonical_state: Any) -> bytes:
    _root(state_schema_root, "state_schema_root")
    return _digest(b"V631/STATE", state_schema_root, canonical_cbor_encode(canonical_state))


def mutation_counter_root(state_schema_root: bytes, counters: Any) -> bytes:
    _root(state_schema_root, "state_schema_root")
    return _digest(b"V631/MUTATION/COUNTERS", state_schema_root, canonical_cbor_encode(counters))


def _sequence_root(values: Any) -> bytes:
    return _digest(b"V631/SEQUENCE", canonical_cbor_encode(values))


def _permutation_root(values: Any) -> bytes:
    return _digest(b"V631/SHUFFLE/PERMUTATION", canonical_cbor_encode(values))


@dataclass(frozen=True, slots=True)
class TraceHeader:
    """Fixed-position header binding every Package 1 required root/input."""

    trace_schema_root: bytes
    state_schema_root: bytes
    event_taxonomy_root: bytes
    mutation_coverage_policy_root: bytes
    opened_engine_source_root: bytes
    derivative_source_root: bytes
    derivative_diff_root: bytes
    derivative_build_root: bytes
    ruleset_root: bytes
    card_catalog_root: bytes
    model_root: bytes
    population_root: bytes
    candidate_archive_sha256: bytes
    control_archive_sha256: bytes
    candidate_deck_root: bytes
    control_deck_root: bytes
    agent_process_manifest_roots: tuple[bytes, bytes]
    agent_sandbox_policy_root: bytes
    seed_descriptor_root: bytes
    common_seed_id: int
    candidate_seat: int
    game_id: bytes | None = None
    synthetic_fixture: bool = False

    def _validate_bindings(self) -> None:
        roots = [getattr(self, field) for field in _ROOT_FIELDS[:16]]
        for label, value in zip(_ROOT_FIELDS[:16], roots):
            _root(value, label)
        manifests = self.agent_process_manifest_roots
        if type(manifests) is not tuple or len(manifests) != 2:
            raise _fail("TRACE_HEADER_INVALID", "agent_process_manifest_roots must contain exactly two roots")
        _root(manifests[0], "candidate agent manifest")
        _root(manifests[1], "control agent manifest")
        _root(self.agent_sandbox_policy_root, "agent_sandbox_policy_root")
        _root(self.seed_descriptor_root, "seed_descriptor_root")
        _u16(self.common_seed_id, "common_seed_id")
        if type(self.candidate_seat) is not int or self.candidate_seat not in (0, 1):
            raise _fail("TRACE_HEADER_INVALID", "candidate_seat must be a non-boolean 0 or 1")
        if self.game_id is not None:
            _root(self.game_id, "game_id")
        if type(self.synthetic_fixture) is not bool:
            raise _fail("TRACE_HEADER_INVALID", "synthetic_fixture must be boolean")

    def computed_game_id(self) -> bytes:
        self._validate_bindings()
        return _digest(
            b"V631/GAME", self.model_root, self.population_root, self.candidate_archive_sha256,
            self.control_archive_sha256, _u16(self.common_seed_id, "common_seed_id").to_bytes(2, "big"),
            bytes((self.candidate_seat,)),
        )

    def canonical_array(self) -> list[Any]:
        self._validate_bindings()
        game = self.computed_game_id()
        if self.game_id is not None and self.game_id != game:
            raise _fail("TRACE_HEADER_INVALID", "header game_id does not bind its frozen inputs")
        roots = [getattr(self, field) for field in _ROOT_FIELDS[:16]]
        manifests = self.agent_process_manifest_roots
        return [
            TRACE_SCHEMA_VERSION, *roots, list(manifests), self.agent_sandbox_policy_root,
            self.seed_descriptor_root, self.common_seed_id, self.candidate_seat, game, self.synthetic_fixture,
        ]

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_encode(self.canonical_array())

    def header_hash(self) -> bytes:
        return _digest(b"V631/TRACE/HEADER", self.canonical_bytes())

    def genesis_hash(self) -> bytes:
        return _digest(b"V631/TRACE/GENESIS", self.header_hash())

    @classmethod
    def from_array(cls, value: Any) -> "TraceHeader":
        if type(value) is not list or len(value) != HEADER_FIELD_COUNT or value[0] != TRACE_SCHEMA_VERSION:
            raise _fail("TRACE_HEADER_INVALID", "header must be the frozen fixed-position array")
        if type(value[17]) is not list or len(value[17]) != 2:
            raise _fail("TRACE_HEADER_INVALID", "header agent manifests are malformed")
        header = cls(
            *value[1:17], tuple(value[17]), value[18], value[19], value[20], value[21], value[22], value[23]
        )
        header.canonical_array()
        return header


@dataclass(frozen=True, slots=True)
class TraceEvent:
    core: tuple[Any, ...]
    event_hash: bytes

    @property
    def sequence(self) -> int:
        return self.core[1]

    @property
    def event_type(self) -> int:
        return self.core[2]

    @property
    def transition_mode(self) -> int:
        return self.core[3]

    @property
    def payload(self) -> tuple[Any, Any, Any]:
        return self.core[13]


@dataclass(frozen=True, slots=True)
class ParsedTrace:
    header: TraceHeader
    header_hash: bytes
    events: tuple[TraceEvent, ...]
    terminal_state_root: bytes
    terminal_result_root: bytes
    trace_root: bytes
    authority: bool = False
    upload_authorized: bool = False
    calibration_upload_authorized: bool = False
    production_upload_authorized: bool = False
    holdout_access_authorized: bool = False
    sealed_holdout_access_authorized: bool = False
    agent_modification_authorized: bool = False
    campaign_authorized: bool = False
    permits: tuple[str, ...] = ()


class EventApplicationAdapter(Protocol):
    """Independent state-transition implementation; no boolean receipts exist."""

    def initial_state(self, header: TraceHeader) -> tuple[Any, Any]: ...

    def apply_event(self, state: Any, counters: Any, event: TraceEvent) -> tuple[Any, Any]: ...


def _frame(value: Any) -> bytes:
    encoded = canonical_cbor_encode(value)
    if len(encoded) > 0xFFFFFFFF:
        raise _fail("TRACE_TRUNCATED", "frame cannot exceed uint32 length")
    return struct.pack(">I", len(encoded)) + encoded


def _decode_frames(raw: bytes) -> list[Any]:
    if type(raw) is not bytes or not raw:
        raise _fail("TRACE_TRUNCATED", "trace must contain a header frame")
    offset, values = 0, []
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise _fail("TRACE_TRUNCATED", "uint32 frame length is truncated")
        size = struct.unpack(">I", raw[offset:offset + 4])[0]
        offset += 4
        if size == 0 or size > len(raw) - offset:
            raise _fail("TRACE_TRUNCATED", "frame payload is truncated")
        frame = raw[offset:offset + size]
        offset += size
        try:
            value = canonical_cbor_decode(frame)
            if canonical_cbor_encode(value) != frame:
                raise _fail("TRACE_NONCANONICAL_ENCODING", "frame is not canonical CBOR")
        except CanonicalTraceCodecError as exc:
            raise _fail(exc.code, str(exc)) from exc
        values.append(value)
    return values


def _event_hash(header_hash: bytes, core: Sequence[Any]) -> bytes:
    return _digest(b"V631/TRACE/EVENT", header_hash, canonical_cbor_encode(list(core)))


def _as_root(value: Any, code: str, label: str) -> bytes:
    if type(value) is not bytes or len(value) != ROOT_BYTES:
        raise _fail(code, f"{label} must be a 32-byte digest")
    return value


def _optional_id(value: Any, label: str) -> None:
    if value is not None:
        _as_root(value, "TRACE_NONCANONICAL_ENCODING", label)


def _event_from_record(value: Any, header_hash: bytes) -> TraceEvent:
    if type(value) is not list or len(value) != 2 or type(value[0]) is not list:
        raise _fail("TRACE_NONCANONICAL_ENCODING", "event record must be [event_core, event_hash]")
    core, claimed_hash = value
    if len(core) != EVENT_CORE_FIELD_COUNT or core[0] != TRACE_SCHEMA_VERSION:
        raise _fail("TRACE_NONCANONICAL_ENCODING", "event core does not have the frozen layout")
    if type(core[1]) is not int or isinstance(core[1], bool) or core[1] < 0:
        raise _fail("TRACE_SEQUENCE_GAP", "event sequence must be uint64")
    if type(core[2]) is not int or isinstance(core[2], bool) or type(core[3]) is not int or core[3] not in (NONE, MUTATION):
        raise _fail("TRACE_NONCANONICAL_ENCODING", "event taxonomy or transition mode is invalid")
    expected_mode = _EVENT_TRANSITIONS.get(core[2])
    if expected_mode is None:
        raise _fail("TRACE_SCHEMA_ROOT_MISMATCH", "event code is absent from the frozen taxonomy")
    if core[3] != expected_mode:
        raise _fail("TRACE_MUTATION_SITE_UNCOVERED", "event transition class disagrees with frozen taxonomy")
    for index, label in ((4, "previous_event_hash"), (9, "before_state_root"), (10, "after_state_root"), (11, "counter_before_root"), (12, "counter_after_root")):
        _as_root(core[index], "TRACE_NONCANONICAL_ENCODING", label)
    for index, label in ((5, "transaction_id"), (6, "selection_frame_id"), (7, "action_instance_id"), (8, "effect_instance_id")):
        _optional_id(core[index], label)
    if type(core[13]) is not list or len(core[13]) != EVENT_PAYLOAD_FIELD_COUNT:
        raise _fail("TRACE_NONCANONICAL_ENCODING", "event payload must be [semantic, state_snapshot, counter_snapshot]")
    if type(core[13][0]) is not list:
        raise _fail("TRACE_NONCANONICAL_ENCODING", "semantic event payload must be a fixed-position array")
    if core[14] is not None:
        error = core[14]
        if type(error) is not list or len(error) != 7 or error[1] != "FATAL":
            raise _fail("TRACE_NONCANONICAL_ENCODING", "error payload must use the frozen fatal array")
        if type(error[0]) is not str or not error[0] or type(error[2]) is not str or not error[2]:
            raise _fail("TRACE_NONCANONICAL_ENCODING", "error code and source site must be canonical text")
        if error[3] is not None and (type(error[3]) is not int or error[3] < 0):
            raise _fail("TRACE_NONCANONICAL_ENCODING", "error related sequence is invalid")
        _as_root(error[5], "TRACE_NONCANONICAL_ENCODING", "error context root")
        if error[6] is not None:
            _as_root(error[6], "TRACE_NONCANONICAL_ENCODING", "error diagnostic root")
    actual_hash = _event_hash(header_hash, core)
    if claimed_hash != actual_hash:
        raise _fail("TRACE_EVENT_HASH_MISMATCH", "event hash is stale")
    return TraceEvent(tuple(core), actual_hash)


def _snapshot_roots(header: TraceHeader, event: TraceEvent) -> None:
    semantic, state, counters = event.payload
    del semantic
    if event.event_type in _SNAPSHOT_EVENTS and (state is None or counters is None):
        raise _fail("TRACE_STATE_ROOT_MISMATCH", "required checkpoint snapshot is absent")
    if state is not None and state_root(header.state_schema_root, state) != event.core[10]:
        raise _fail("TRACE_STATE_ROOT_MISMATCH", "snapshot after-state root is stale")
    if counters is not None and mutation_counter_root(header.state_schema_root, counters) != event.core[12]:
        raise _fail("TRACE_MUTATION_COUNTER_IMBALANCE", "snapshot counter root is stale")


def _validate_selection(header: TraceHeader, event: TraceEvent, stack: list[bytes], options: dict[bytes, tuple[bytes, ...]], frames: dict[bytes, tuple[Any, ...]], choices: dict[bytes, int]) -> None:
    semantic = event.payload[0]
    frame = event.core[6]
    if event.event_type == SELECTION_PUSH:
        if type(frame) is not bytes or len(frame) != ROOT_BYTES or frame in frames or frame != selection_frame_id(header.computed_game_id(), len(frames)):
            raise _fail("TRACE_SELECTION_STACK_IMBALANCE", "selection push identity is invalid or reused")
        if type(semantic) is not list or len(semantic) != 8:
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "selection push schema is invalid")
        parent, _actor, _kind, minimum, maximum, optional, forced, pre_root = semantic
        if parent != (stack[-1] if stack else None) or pre_root != event.core[9]:
            raise _fail("TRACE_SELECTION_STACK_IMBALANCE", "selection parent or pre-state is stale")
        if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum or type(optional) is not bool or type(forced) is not bool:
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "selection cardinality is invalid")
        stack.append(frame); frames[frame] = tuple(semantic)
    elif event.event_type == LEGAL_OPTION_SET:
        if not stack or frame != stack[-1] or type(semantic) is not list or len(semantic) != 2:
            raise _fail("TRACE_STALE_SELECTION_RESPONSE", "legal option set is outside the current frame")
        listed, order_policy = semantic
        if type(listed) is not list:
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "legal options must be an ordered array")
        ids: list[bytes] = []
        for record in listed:
            if type(record) is not list or len(record) != 2:
                raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "legal option record is malformed")
            option_id, option = record
            if option_id != legal_option_id(frame, option):
                raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "legal option identity is stale")
            ids.append(option_id)
        if len(set(ids)) != len(ids):
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "legal option identity is duplicated")
        if order_policy != CANONICAL_OPTION_ID_ORDER or ids != sorted(ids):
            raise _fail("TRACE_OPTION_ORDER_MISMATCH", "canonical option order is stale")
        minimum, maximum, optional, forced = frames[frame][3], frames[frame][4], frames[frame][5], frames[frame][6]
        if not ids and minimum > 0:
            raise _fail("TRACE_ZERO_OPTION_REQUIRED_SELECTION", "required selection has no legal option")
        if forced and (minimum != 1 or maximum != 1 or len(ids) != 1):
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "forced selection must expose exactly one choice")
        if optional and not any(option == ["CANCEL"] for _id, option in listed):
            raise _fail("TRACE_LEGAL_OPTION_SET_INCOMPLETE", "optional selection lacks canonical cancel option")
        options[frame] = tuple(ids)
    elif event.event_type in (CHOICE_ACCEPTED, FORCED_CHOICE):
        if not stack or frame != stack[-1] or frame not in options or type(semantic) is not list:
            raise _fail("TRACE_STALE_SELECTION_RESPONSE", "choice does not target current legal options")
        if event.event_type == FORCED_CHOICE and not frames[frame][6]:
            raise _fail("TRACE_CHOICE_NOT_IN_OPTION_SET", "forced choice does not target a forced frame")
        chosen = semantic
        if not chosen or any(value not in options[frame] for value in chosen):
            raise _fail("TRACE_CHOICE_NOT_IN_OPTION_SET", "choice is absent from exact option set")
        if len(set(chosen)) != len(chosen):
            raise _fail("TRACE_CHOICE_NOT_IN_OPTION_SET", "choice duplicates an option")
        minimum, maximum = frames[frame][3], frames[frame][4]
        if not minimum <= len(chosen) <= maximum:
            raise _fail("TRACE_CHOICE_NOT_IN_OPTION_SET", "choice count violates selection frame")
        choices[frame] = len(chosen)
    elif event.event_type == SELECTION_POP:
        if not stack or frame != stack[-1]:
            raise _fail("TRACE_SELECTION_STACK_IMBALANCE", "selection pop violates LIFO")
        minimum, _maximum, _optional, forced = frames[frame][3], frames[frame][4], frames[frame][5], frames[frame][6]
        if (minimum > 0 or forced) and choices.get(frame, 0) == 0:
            raise _fail("TRACE_CHOICE_NOT_IN_OPTION_SET", "required selection frame popped without a choice")
        stack.pop()


def _validate_rng(event: TraceEvent, streams: dict[bytes, int], draws: dict[int, tuple[bytes, int, int, int]]) -> None:
    semantic = event.payload[0]
    if event.event_type == RNG_STREAM_BOUND:
        if type(semantic) is not list or len(semantic) != 4:
            raise _fail("TRACE_RNG_SITE_UNCOVERED", "RNG stream binding is malformed")
        stream, commitment, algorithm, counter = semantic
        if type(stream) is not bytes or len(stream) != ROOT_BYTES or type(commitment) is not bytes or len(commitment) != ROOT_BYTES:
            raise _fail("TRACE_RNG_SITE_UNCOVERED", "RNG stream identity or commitment is not rooted")
        if algorithm != RAW_DRAW_ALGORITHM_ID:
            raise _fail("TRACE_RNG_RAW_DRAW_MISMATCH", "RNG stream generator algorithm is not frozen")
        if stream in streams or type(counter) is not int or isinstance(counter, bool) or counter < 0:
            raise _fail("TRACE_RNG_COUNTER_GAP", "RNG stream counter is invalid")
        streams[stream] = counter
    elif event.event_type == RNG_DRAW:
        if type(semantic) is not list or len(semantic) != 6:
            raise _fail("TRACE_RNG_RAW_DRAW_MISMATCH", "RNG draw schema is invalid")
        stream, before, bits, raw, after, _site = semantic
        if type(stream) is not bytes or len(stream) != ROOT_BYTES or stream not in streams:
            raise _fail("TRACE_RNG_SITE_UNCOVERED", "RNG draw uses an unknown or unrooted stream")
        if bits != RAW_DRAW_BIT_COUNT or type(raw) is not bytes or len(raw) != 8:
            raise _fail("TRACE_RNG_RAW_DRAW_MISMATCH", "RNG raw output does not match requested bit count")
        if (
            type(before) is not int
            or isinstance(before, bool)
            or type(after) is not int
            or isinstance(after, bool)
            or before != streams[stream]
            or after != before + 1
            or type(_site) is not bytes
            or len(_site) != ROOT_BYTES
        ):
            raise _fail("TRACE_RNG_COUNTER_GAP", "RNG draw counter is discontinuous")
        streams[stream] = after; draws[event.sequence] = (stream, before, after, int.from_bytes(raw, "big"))
    elif event.event_type == RNG_BOUNDED_SAMPLE:
        if type(semantic) is not list or len(semantic) != 11:
            raise _fail("TRACE_BOUNDED_SAMPLE_MISMATCH", "bounded sample schema is invalid")
        algorithm, stream, upper, threshold, sequences, rejected, acceptance, accepted, mapped, before, after = semantic
        if (
            algorithm != BOUNDED_SAMPLING_ALGORITHM_ID
            or type(stream) is not bytes
            or len(stream) != ROOT_BYTES
            or stream not in streams
            or type(upper) is not int
            or isinstance(upper, bool)
            or upper <= 0
            or upper >= UINT64_SPACE
            or type(threshold) is not int
            or isinstance(threshold, bool)
            or type(sequences) is not list
            or not sequences
            or any(type(sequence) is not int or isinstance(sequence, bool) or sequence < 0 for sequence in sequences)
            or type(rejected) is not list
            or any(type(value) is not int or isinstance(value, bool) or value < 0 for value in rejected)
            or type(acceptance) is not list
            or any(type(value) is not bool for value in acceptance)
            or type(accepted) is not int
            or isinstance(accepted, bool)
            or accepted < 0
            or type(mapped) is not int
            or isinstance(mapped, bool)
            or mapped < 0
            or type(before) is not int
            or isinstance(before, bool)
            or type(after) is not int
            or isinstance(after, bool)
        ):
            raise _fail("TRACE_BOUNDED_SAMPLE_MISMATCH", "bounded sample input is invalid")
        referenced = [draws.get(sequence) for sequence in sequences]
        if any(value is None for value in referenced):
            raise _fail("TRACE_RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample references an unknown raw draw")
        typed_draws = [value for value in referenced if value is not None]
        actual = [value[3] for value in typed_draws]
        expected_threshold = UINT64_SPACE % upper
        if (
            any(value[0] != stream for value in typed_draws)
            or typed_draws[0][1] != before
            or typed_draws[-1][2] != after
            or any(left[2] != right[1] for left, right in zip(typed_draws, typed_draws[1:]))
            or rejected != actual[:-1]
            or threshold != expected_threshold
            or acceptance != [False] * len(rejected) + [True]
            or any(value >= expected_threshold for value in rejected)
            or accepted != actual[-1]
            or accepted < expected_threshold
            or mapped != accepted % upper
            or after - before != len(sequences)
        ):
            raise _fail("TRACE_RNG_REJECTION_ACCOUNTING_MISMATCH", "bounded sample does not account for raw draws")
    elif event.event_type == SHUFFLE_APPLIED:
        if type(semantic) is not list or len(semantic) != 10:
            raise _fail("TRACE_SHUFFLE_INPUT_MISMATCH", "shuffle schema is invalid")
        shuffle, zone, inputs, input_root, algorithm, rng_range, permutation, permutation_root, outputs, output_root = semantic
        if (
            type(shuffle) is not bytes
            or len(shuffle) != ROOT_BYTES
            or type(zone) is not str
            or not zone
            or zone.strip() != zone
            or algorithm != SHUFFLE_ALGORITHM_ID
            or type(inputs) is not list
            or type(outputs) is not list
            or any(type(card) is not bytes or len(card) != ROOT_BYTES for card in inputs + outputs)
        ):
            raise _fail("TRACE_SHUFFLE_INPUT_MISMATCH", "shuffle identity, algorithm, or card instances are invalid")
        if input_root != _sequence_root(inputs) or output_root != _sequence_root(outputs):
            raise _fail("TRACE_SHUFFLE_INPUT_MISMATCH", "shuffle sequence roots are stale")
        if type(permutation) is not list or permutation_root != _permutation_root(permutation) or sorted(permutation) != list(range(len(inputs))):
            raise _fail("TRACE_SHUFFLE_PERMUTATION_MISMATCH", "shuffle permutation is invalid")
        if (
            outputs != [inputs[index] for index in permutation]
            or type(rng_range) is not list
            or (
                len(inputs) >= 2
                and (
                    len(rng_range) != 2
                    or any(type(item) is not int or isinstance(item, bool) or item < 0 for item in rng_range)
                    or rng_range[0] > rng_range[1]
                    or any(sequence not in draws for sequence in range(rng_range[0], rng_range[1] + 1))
                )
            )
            or (len(inputs) < 2 and rng_range != [])
        ):
            raise _fail("TRACE_SHUFFLE_PERMUTATION_MISMATCH", "shuffle output disagrees with permutation")


def parse_canonical_trace(raw: bytes) -> ParsedTrace:
    """Validate framing, chain, snapshots, lifecycle, selection, and RNG data."""
    frames = _decode_frames(raw)
    if len(frames) < 2:
        raise _fail("TRACE_END_MISSING", "trace has no event frames")
    header = TraceHeader.from_array(frames[0])
    header_hash = header.header_hash()
    events = tuple(_event_from_record(record, header_hash) for record in frames[1:])
    previous, previous_state, previous_counters = header.genesis_hash(), None, None
    selection_stack: list[bytes] = []
    options: dict[bytes, tuple[bytes, ...]] = {}
    selection_frames: dict[bytes, tuple[Any, ...]] = {}
    selection_choices: dict[bytes, int] = {}
    actions: list[bytes] = []
    effects: list[bytes] = []
    streams: dict[bytes, int] = {}
    draws: dict[int, tuple[bytes, int, int, int]] = {}
    mutation_ids: set[bytes] = set()
    terminal: TraceEvent | None = None
    trace_begin_count = 0
    trace_end_count = 0
    for expected, event in enumerate(events):
        core = event.core
        if core[1] != expected:
            raise _fail("TRACE_SEQUENCE_GAP", "event sequence is not contiguous")
        if core[4] != previous:
            raise _fail("TRACE_PREVIOUS_HASH_MISMATCH", "previous event hash is stale")
        if previous_state is not None and core[9] != previous_state:
            raise _fail("TRACE_STATE_ROOT_MISMATCH", "event before-state root does not chain")
        if previous_counters is not None and core[11] != previous_counters:
            raise _fail("TRACE_MUTATION_COUNTER_IMBALANCE", "event counter-before root does not chain")
        previous = event.event_hash
        previous_state, previous_counters = core[10], core[12]
        _snapshot_roots(header, event)
        if core[14] is not None:
            raise _fail("TRACE_ABORTED", "fatal trace-integrity error is present")
        if event.event_type == TRACE_BEGIN:
            trace_begin_count += 1
        if event.event_type == TRACE_END:
            trace_end_count += 1
        if terminal is not None and event.event_type not in (RESULT_EMITTED, TRACE_END):
            raise _fail("TRACE_EVENT_AFTER_TERMINAL", "semantic event follows terminal closure")
        if event.transition_mode == NONE:
            if core[9] != core[10] or core[11] != core[12]:
                raise _fail("TRACE_STATE_ROOT_MISMATCH", "NONE event changes state or counters")
        else:
            if core[5] is None:
                raise _fail("TRACE_MUTATION_TICKET_MISSING", "mutation event lacks transaction")
            if core[9] == core[10]:
                raise _fail("TRACE_DECLARED_MUTATION_NO_EFFECT", "mutation event does not change semantic state")
            if core[11] == core[12]:
                raise _fail("TRACE_MUTATION_COUNTER_IMBALANCE", "mutation event does not advance its counter")
            semantic = event.payload[0]
            if type(semantic) is not list or len(semantic) < 2 or type(semantic[0]) is not bytes or len(semantic[0]) != ROOT_BYTES or type(semantic[1]) is not int or isinstance(semantic[1], bool):
                raise _fail("TRACE_MUTATION_TICKET_MISSING", "mutation payload lacks stable mutation identity")
            if semantic[0] != mutation_id(header.computed_game_id(), event.sequence, semantic[1]):
                raise _fail("TRACE_MUTATION_TICKET_MISSING", "mutation identity does not bind sequence and family")
            if semantic[0] in mutation_ids:
                raise _fail("TRACE_MUTATION_TICKET_DUPLICATE", "mutation identity was reused")
            mutation_ids.add(semantic[0])
        _validate_selection(header, event, selection_stack, options, selection_frames, selection_choices)
        _validate_rng(event, streams, draws)
        action, effect = core[7], core[8]
        if event.event_type == ACTION_BEGIN:
            if type(action) is not bytes or len(action) != ROOT_BYTES: raise _fail("TRACE_ACTION_SCOPE_IMBALANCE", "action begin lacks ID")
            actions.append(action)
        elif event.event_type == ACTION_END:
            if not actions or action != actions[-1]: raise _fail("TRACE_ACTION_SCOPE_IMBALANCE", "action end is not LIFO")
            actions.pop()
        elif event.event_type == EFFECT_BEGIN:
            if type(effect) is not bytes or len(effect) != ROOT_BYTES: raise _fail("TRACE_ACTION_SCOPE_IMBALANCE", "effect begin lacks ID")
            effects.append(effect)
        elif event.event_type == EFFECT_END:
            if not effects or effect != effects[-1]: raise _fail("TRACE_ACTION_SCOPE_IMBALANCE", "effect end is not LIFO")
            effects.pop()
        if event.event_type == TERMINAL_SET:
            if terminal is not None or event.transition_mode != MUTATION or type(event.payload[0]) is not list or len(event.payload[0]) < 3:
                raise _fail("TRACE_TERMINAL_BALANCE_FAILURE", "terminal set is malformed")
            _as_root(event.payload[0][2], "TRACE_TERMINAL_PROVENANCE_INCOMPLETE", "terminal result root")
            terminal = event
        if event.event_type == TRACE_ABORT:
            raise _fail("TRACE_ABORTED", "aborted trace cannot be accepted")
    if not events or events[0].event_type != TRACE_BEGIN or trace_begin_count != 1:
        raise _fail("TRACE_INITIAL_STATE_INVALID", "TRACE_BEGIN must be first")
    if terminal is None:
        raise _fail("TRACE_TERMINAL_BALANCE_FAILURE", "trace has no terminal result")
    if events[-1].event_type != TRACE_END or trace_end_count != 1:
        raise _fail("TRACE_END_MISSING", "TRACE_END must be final")
    if selection_stack or actions or effects:
        raise _fail("TRACE_SELECTION_STACK_IMBALANCE" if selection_stack else "TRACE_ACTION_SCOPE_IMBALANCE", "trace closes with an open scope")
    terminal_result = terminal.payload[0][2]
    trace_end = events[-1]
    if trace_end.payload[0] != [terminal_result, terminal.core[10]] or trace_end.core[9] != terminal.core[10] or trace_end.core[10] != terminal.core[10]:
        raise _fail("TRACE_TERMINAL_BALANCE_FAILURE", "TRACE_END does not bind terminal result and state")
    trace_root = _digest(b"V631/TRACE/ROOT", header_hash, events[-1].event_hash, len(events).to_bytes(8, "big"), terminal.core[10], terminal_result)
    return ParsedTrace(header, header_hash, events, terminal.core[10], terminal_result, trace_root)


def replay_canonical_trace(raw: bytes, adapter: EventApplicationAdapter) -> ParsedTrace:
    """Run independent event application and compare every recorded state root."""
    parsed = parse_canonical_trace(raw)
    state, counters = adapter.initial_state(parsed.header)
    for event in parsed.events:
        if state_root(parsed.header.state_schema_root, state) != event.core[9] or mutation_counter_root(parsed.header.state_schema_root, counters) != event.core[11]:
            raise _fail("TRACE_INITIAL_STATE_INVALID" if event.sequence == 0 else "TRACE_TRANSACTION_REPLAY_MISMATCH", f"event {event.sequence} before roots do not replay")
        state, counters = adapter.apply_event(state, counters, event)
        if state_root(parsed.header.state_schema_root, state) != event.core[10] or mutation_counter_root(parsed.header.state_schema_root, counters) != event.core[12]:
            raise _fail("TRACE_TRANSACTION_REPLAY_MISMATCH", f"event {event.sequence} does not replay")
    return parsed


class CanonicalTraceWriter:
    """Small append-only writer for test/opened-engine conformance wiring."""

    def __init__(self, header: TraceHeader, initial_state: Any, initial_counters: Any) -> None:
        if not header.synthetic_fixture:
            raise _fail("TRACE_CALLER_AUTHORED_INPUT_FORBIDDEN", "the Python writer is private synthetic-fixture support only")
        self.header = header
        self._state, self._counters = initial_state, initial_counters
        self._events: list[TraceEvent] = []

    def append(
        self, event_type: int, transition_mode: int, semantic_payload: Any, *, state: Any | None = None,
        counters: Any | None = None, transaction_id: Any = None, selection_id: bytes | None = None,
        action_id: bytes | None = None, effect_id: bytes | None = None, error_payload: Any = None,
        snapshot: bool | None = None,
    ) -> TraceEvent:
        if _EVENT_TRANSITIONS.get(event_type) != transition_mode:
            raise _fail("TRACE_MUTATION_SITE_UNCOVERED", "fixture event violates frozen transition taxonomy")
        before_state, before_counter = state_root(self.header.state_schema_root, self._state), mutation_counter_root(self.header.state_schema_root, self._counters)
        next_state = self._state if state is None else state
        next_counters = self._counters if counters is None else counters
        after_state, after_counter = state_root(self.header.state_schema_root, next_state), mutation_counter_root(self.header.state_schema_root, next_counters)
        sequence = len(self._events)
        previous = self.header.genesis_hash() if not self._events else self._events[-1].event_hash
        include_snapshot = event_type in _SNAPSHOT_EVENTS if snapshot is None else snapshot
        payload = [semantic_payload, next_state if include_snapshot else None, next_counters if include_snapshot else None]
        core = [TRACE_SCHEMA_VERSION, sequence, event_type, transition_mode, previous, transaction_id, selection_id, action_id, effect_id, before_state, after_state, before_counter, after_counter, payload, error_payload]
        event = TraceEvent(tuple(core), _event_hash(self.header.header_hash(), core))
        self._events.append(event); self._state, self._counters = next_state, next_counters
        return event

    def to_bytes(self) -> bytes:
        return _frame(self.header.canonical_array()) + b"".join(_frame([list(event.core), event.event_hash]) for event in self._events)


@dataclass(frozen=True, slots=True)
class AuditOrigin:
    origin_id: str
    trace_bytes: bytes


def verify_ab_conformance(origin_a: AuditOrigin, origin_b: AuditOrigin, replayer_a: EventApplicationAdapter, replayer_b: EventApplicationAdapter) -> Mapping[str, Any]:
    """Require distinct origins and all four independent event-application replays."""
    if type(origin_a.origin_id) is not str or type(origin_b.origin_id) is not str or not origin_a.origin_id or origin_a.origin_id == origin_b.origin_id:
        raise _fail("TRACE_INDEPENDENT_ORIGIN_MISSING", "two distinct audit origins are required")
    parsed_a, parsed_b = parse_canonical_trace(origin_a.trace_bytes), parse_canonical_trace(origin_b.trace_bytes)
    if parsed_a.header.synthetic_fixture or parsed_b.header.synthetic_fixture:
        raise _fail("TRACE_CALLER_AUTHORED_INPUT_FORBIDDEN", "private synthetic fixtures cannot enter the A/B path")
    if parsed_a.header.derivative_build_root != parsed_b.header.derivative_build_root:
        raise _fail("TRACE_AB_BUILD_DIVERGENCE", "A/B derivative builds differ")
    if (parsed_a.header.trace_schema_root, parsed_a.header.state_schema_root, parsed_a.header.event_taxonomy_root) != (parsed_b.header.trace_schema_root, parsed_b.header.state_schema_root, parsed_b.header.event_taxonomy_root):
        raise _fail("TRACE_AB_SCHEMA_DIVERGENCE", "A/B schemas differ")
    if parsed_a.trace_root != parsed_b.trace_root or parsed_a.terminal_state_root != parsed_b.terminal_state_root or parsed_a.terminal_result_root != parsed_b.terminal_result_root:
        raise _fail("TRACE_AB_SEMANTIC_ROOT_DIVERGENCE", "A/B semantic traces differ")
    try:
        for trace in (origin_a.trace_bytes, origin_b.trace_bytes):
            replay_canonical_trace(trace, replayer_a)
            replay_canonical_trace(trace, replayer_b)
    except CanonicalTraceReplayError as exc:
        raise _fail("TRACE_CROSS_REPLAY_FAILURE", f"cross replay failed: {exc.code}") from exc
    return freeze(zero_authority("OFFLINE_AB_REPLAY_CONFORMANT", detail="Four-way structural replay passed; external custody is not authenticated.", extra={"trace_root": parsed_a.trace_root.hex(), "four_way_replay_passed": True, "external_custody_authenticated": False, "authority": False, "upload_authorized": False, "holdout_access_authorized": False}))


def _encode_private_synthetic_fixture_trace(writer: CanonicalTraceWriter) -> bytes:
    """Private test-only fixture encoder. Its header marker blocks A/B use."""
    if not writer.header.synthetic_fixture:
        raise _fail("TRACE_CALLER_AUTHORED_INPUT_FORBIDDEN", "fixture encoder requires a fixture-marked header")
    return writer.to_bytes()


__all__ = [
    "ACTION_BEGIN", "ACTION_COMMIT", "ACTION_END", "AGENT_ENTROPY_GRANTED", "AGENT_PROCESS_EXIT",
    "AGENT_PROCESS_START", "AGENT_PROTOCOL_VIOLATION", "AGENT_REQUEST", "AGENT_RESPONSE",
    "AGENT_RESOURCE_OUTCOME", "ATTACHMENT_CHANGED", "ATTACK_DECLARE", "ATTACK_RESOLUTION_BEGIN",
    "ATTACK_RESOLUTION_END", "AuditOrigin", "BATTLE_START", "CANONICAL_OPTION_ID_ORDER",
    "CARD_INSTANCE_CREATED", "CARD_MOVE", "CHOICE_ACCEPTED", "CHOICE_REJECTED", "COIN_FLIP_RESOLVED",
    "COST_COMPONENT_PAID", "COST_PLAN_CLOSED", "COST_PLAN_CREATED", "CanonicalTraceReplayError",
    "DAMAGE_CALCULATION", "DAMAGE_MODIFIER_APPLIED", "DECK_INSTANTIATED", "EFFECT_BEGIN", "EFFECT_END",
    "EVOLUTION_STACK_CHANGED", "EventApplicationAdapter", "FIRST_DECISION_CHECKPOINT", "FORCED_CHOICE",
    "GAME_CONSTRUCTED", "HP_CHANGE", "LEGAL_OPTION_SET", "MANDATORY_PROCESSING_COMPLETE", "MULLIGAN_BEGIN",
    "MULLIGAN_CARD_RETURN", "MULLIGAN_DECISION", "MULLIGAN_END", "MULLIGAN_REDRAW", "MUTATION", "NONE",
    "PLAYER_PROCESS_BOUND", "POKEMON_ENTITY_CREATED", "POKEMON_ENTITY_REMOVED", "PRIZE_CARD_ASSIGNED",
    "PRIZE_CARD_TAKEN", "PRIZE_SETUP_BEGIN", "PRIZE_SETUP_END", "PRIZE_TRANSACTION_BEGIN", "PRIZE_TRANSACTION_END",
    "BOUNDED_SAMPLING_ALGORITHM_ID", "ParsedTrace", "RANDOM_CHOICE_RESOLVED", "RAW_DRAW_ALGORITHM_ID", "RAW_DRAW_BIT_COUNT", "RESULT_EMITTED", "RNG_BOUNDED_SAMPLE", "RNG_DRAW",
    "RNG_STREAM_BOUND", "ROUND_BARRIER", "SEED_DESCRIPTOR_BOUND", "SELECTION_POP", "SELECTION_PUSH",
    "SEMANTIC_PROPERTY_CHANGE", "SETUP_ACTIVE_PLACED", "SETUP_ACTIVE_REQUIRED", "SETUP_BENCH_PLACED",
    "SETUP_BENCH_SELECTION", "SETUP_BEGIN", "SHUFFLE_ALGORITHM_ID", "SHUFFLE_APPLIED", "SHUFFLE_BEGIN", "STARTING_PLAYER_SELECTED",
    "STATUS_CHANGE", "TERMINAL_CANDIDATE", "TERMINAL_SET", "TRACE_ABORT", "TRACE_BEGIN", "TRACE_END",
    "TURN_END", "TURN_START", "TraceEvent", "TraceHeader", "ZONE_REORDER", "action_instance_id", "attack_instance_id",
    "card_definition_id", "card_instance_id", "effect_instance_id", "legal_option_id", "mutation_counter_root",
    "mutation_id", "parse_canonical_trace", "pokemon_entity_id", "replay_canonical_trace", "selection_frame_id",
    "state_root", "verify_ab_conformance",
]
