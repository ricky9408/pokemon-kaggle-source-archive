from __future__ import annotations

from hashlib import sha256
import struct

import pytest

import evaluation_v6_3_1.canonical_trace_replay as trace
from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _header(*, fixture: bool = True, build: bytes | None = None) -> trace.TraceHeader:
    return trace.TraceHeader(
        *[_root(f"root-{index}") for index in range(7)],
        build or _root("build"),
        *[_root(f"root-{index}") for index in range(8, 16)],
        (_root("candidate-agent"), _root("control-agent")), _root("sandbox"), _root("seed"), 17, 0,
        synthetic_fixture=fixture,
    )


class _Adapter:
    def initial_state(self, _header: trace.TraceHeader):
        return {"phase": "new", "value": 0}, [0]

    def apply_event(self, state, counters, event: trace.TraceEvent):
        if event.transition_mode == trace.NONE:
            return state, counters
        if event.event_type == trace.TERMINAL_SET:
            _mutation, _family, _result, operation, value = event.payload[0]
        else:
            _mutation, _family, operation, value = event.payload[0]
        assert operation == "set-value"
        return {"phase": "terminal" if event.event_type == trace.TERMINAL_SET else "game", "value": value}, [counters[0] + 1]


class _DivergentAdapter(_Adapter):
    def apply_event(self, state, counters, event):
        state, counters = super().apply_event(state, counters, event)
        if event.transition_mode == trace.MUTATION:
            return {**state, "value": state["value"] + 1}, counters
        return state, counters


def _writer(*, fixture: bool = True, value: int = 7) -> trace.CanonicalTraceWriter:
    writer = trace.CanonicalTraceWriter(_header(fixture=fixture), {"phase": "new", "value": 0}, [0])
    writer.append(trace.TRACE_BEGIN, trace.NONE, ["begin"])
    mutation = trace.mutation_id(writer.header.computed_game_id(), 1, 1)
    writer.append(trace.SEMANTIC_PROPERTY_CHANGE, trace.MUTATION, [mutation, 1, "set-value", value], state={"phase": "game", "value": value}, counters=[1], transaction_id=_root("setup-transaction"))
    terminal_mutation = trace.mutation_id(writer.header.computed_game_id(), 2, 2)
    terminal_state = {"phase": "terminal", "value": value}
    writer.append(trace.TERMINAL_SET, trace.MUTATION, [terminal_mutation, 2, _root("result"), "set-value", value], state=terminal_state, counters=[2], transaction_id=_root("terminal-transaction"))
    writer.append(trace.TRACE_END, trace.NONE, [_root("result"), trace.state_root(writer.header.state_schema_root, terminal_state)])
    return writer


def _raw(*, fixture: bool = True, value: int = 7) -> bytes:
    writer = _writer(fixture=fixture, value=value)
    return trace._encode_private_synthetic_fixture_trace(writer)


def _externalized_fixture_raw(*, value: int = 7) -> bytes:
    """Models an externally generated non-fixture byte stream for A/B tests."""
    frames = _frames(_raw(value=value))
    header = frames[0]
    assert isinstance(header, list)
    header[23] = False
    parsed_header = trace.TraceHeader.from_array(header)
    previous = parsed_header.genesis_hash()
    for index, record in enumerate(frames[1:], start=1):
        assert isinstance(record, list)
        record[0][4] = previous
        record[1] = trace._event_hash(parsed_header.header_hash(), record[0])
        previous = record[1]
    return _encode_frames(frames)


def _assert_code(code: str, function, *args) -> None:
    with pytest.raises(trace.CanonicalTraceReplayError) as raised:
        function(*args)
    assert raised.value.code == code


def _frames(raw: bytes) -> list[object]:
    return trace._decode_frames(raw)


def _encode_frames(frames: list[object]) -> bytes:
    return b"".join(trace._frame(frame) for frame in frames)


def _rehash_event(frames: list[object], index: int) -> None:
    header = trace.TraceHeader.from_array(frames[0])
    record = frames[index]
    assert isinstance(record, list)
    record[1] = trace._event_hash(header.header_hash(), record[0])


def _rechain_events(frames: list[object]) -> None:
    header = trace.TraceHeader.from_array(frames[0])
    previous = header.genesis_hash()
    for index, record in enumerate(frames[1:], start=1):
        assert isinstance(record, list)
        record[0][4] = previous
        _rehash_event(frames, index)
        previous = record[1]


def test_golden_framing_header_hash_genesis_and_final_root() -> None:
    raw = _raw()
    first_size = struct.unpack(">I", raw[:4])[0]
    assert canonical_cbor_decode(raw[4:4 + first_size]) == _header().canonical_array()
    parsed = trace.replay_canonical_trace(raw, _Adapter())
    assert parsed.header_hash == sha256(b"V631/TRACE/HEADER" + _header().canonical_bytes()).digest()
    assert parsed.events[0].core[4] == sha256(b"V631/TRACE/GENESIS" + parsed.header_hash).digest()
    assert parsed.trace_root == sha256(
        b"V631/TRACE/ROOT" + parsed.header_hash + parsed.events[-1].event_hash
        + len(parsed.events).to_bytes(8, "big") + parsed.terminal_state_root + parsed.terminal_result_root
    ).digest()


@pytest.mark.parametrize("kind", ("deletion", "insertion", "reorder"))
def test_framing_tampering_fails_closed(kind: str) -> None:
    frames = _frames(_raw())
    if kind == "deletion":
        del frames[2]
    elif kind == "insertion":
        frames.insert(2, frames[1])
    else:
        frames[2], frames[3] = frames[3], frames[2]
    _assert_code("TRACE_SEQUENCE_GAP" if kind != "reorder" else "TRACE_SEQUENCE_GAP", trace.parse_canonical_trace, _encode_frames(frames))


def test_stale_roots_and_missing_required_snapshot_fail_closed() -> None:
    frames = _frames(_raw())
    event = frames[3]
    assert isinstance(event, list)
    event[0][10] = _root("stale")
    _rehash_event(frames, 3)
    trailing = frames[4]
    assert isinstance(trailing, list)
    trailing[0][4] = event[1]
    _rehash_event(frames, 4)
    _assert_code("TRACE_STATE_ROOT_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    begin = frames[1]
    assert isinstance(begin, list)
    begin[0][13][0] = {"extension": "map"}
    _rechain_events(frames)
    _assert_code("TRACE_NONCANONICAL_ENCODING", trace.parse_canonical_trace, _encode_frames(frames))


def test_taxonomy_transition_adjacency_and_mutation_tickets_fail_closed() -> None:
    frames = _frames(_raw())
    unknown = frames[2]
    assert isinstance(unknown, list)
    unknown[0][2] = 99
    _rechain_events(frames)
    _assert_code("TRACE_SCHEMA_ROOT_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    mismatch = frames[2]
    assert isinstance(mismatch, list)
    mismatch[0][3] = trace.NONE
    _rechain_events(frames)
    _assert_code("TRACE_MUTATION_SITE_UNCOVERED", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    terminal = frames[3]
    assert isinstance(terminal, list)
    terminal[0][9] = _root("broken-adjacent-state")
    _rechain_events(frames)
    _assert_code("TRACE_STATE_ROOT_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    terminal = frames[3]
    assert isinstance(terminal, list)
    terminal[0][11] = _root("broken-adjacent-counters")
    _rechain_events(frames)
    _assert_code("TRACE_MUTATION_COUNTER_IMBALANCE", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    mutation = frames[2]
    assert isinstance(mutation, list)
    mutation[0][5] = b"short"
    _rechain_events(frames)
    _assert_code("TRACE_NONCANONICAL_ENCODING", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    mutation = frames[2]
    assert isinstance(mutation, list)
    mutation[0][13][0][0] = _root("wrong-mutation-id")
    _rechain_events(frames)
    _assert_code("TRACE_MUTATION_TICKET_MISSING", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    mutation = frames[2]
    assert isinstance(mutation, list)
    mutation[0][10] = mutation[0][9]
    _rechain_events(frames)
    _assert_code("TRACE_DECLARED_MUTATION_NO_EFFECT", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    mutation = frames[2]
    assert isinstance(mutation, list)
    mutation[0][12] = mutation[0][11]
    _rechain_events(frames)
    _assert_code("TRACE_MUTATION_COUNTER_IMBALANCE", trace.parse_canonical_trace, _encode_frames(frames))


def test_writer_is_fixture_only_and_trace_end_binds_terminal_exactly() -> None:
    _assert_code(
        "TRACE_CALLER_AUTHORED_INPUT_FORBIDDEN", trace.CanonicalTraceWriter,
        _header(fixture=False), {"phase": "new", "value": 0}, [0],
    )
    assert "CanonicalTraceWriter" not in trace.__all__

    frames = _frames(_raw())
    trace_end = frames[-1]
    assert isinstance(trace_end, list)
    trace_end[0][13][0][0] = _root("wrong-result")
    _rechain_events(frames)
    _assert_code("TRACE_TERMINAL_BALANCE_FAILURE", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_raw())
    event = frames[1]
    assert isinstance(event, list)
    event[0][13][1] = None
    _rehash_event(frames, 1)
    _assert_code("TRACE_STATE_ROOT_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))


def test_stable_identity_helpers_are_domain_separated_and_never_repr_based() -> None:
    game = _header().computed_game_id()
    assert trace.card_instance_id(game, 0, 0) != trace.card_instance_id(game, 0, 1)
    assert trace.pokemon_entity_id(game, 1, 2) == trace.pokemon_entity_id(game, 1, 2)
    assert trace.action_instance_id(game, 3) != trace.selection_frame_id(game, 3)
    assert trace.legal_option_id(trace.selection_frame_id(game, 1), ["X", 1]) == trace.legal_option_id(trace.selection_frame_id(game, 1), ["X", 1])


def test_private_fixture_marker_is_rejected_from_ab_path() -> None:
    fixture = _raw(fixture=True)
    _assert_code(
        "TRACE_CALLER_AUTHORED_INPUT_FORBIDDEN", trace.verify_ab_conformance,
        trace.AuditOrigin("audit-a", fixture), trace.AuditOrigin("audit-b", fixture), _Adapter(), _Adapter(),
    )


def _selection_raw(*, zero_required: bool = False, reordered: bool = False, stale_choice: bool = False, pop_without_choice: bool = False) -> bytes:
    writer = trace.CanonicalTraceWriter(_header(), {"phase": "new", "value": 0}, [0])
    writer.append(trace.TRACE_BEGIN, trace.NONE, ["begin"])
    frame = trace.selection_frame_id(writer.header.computed_game_id(), 0)
    writer.append(trace.SELECTION_PUSH, trace.NONE, [None, 0, 1, 1, 1, False, False, trace.state_root(writer.header.state_schema_root, {"phase": "new", "value": 0})], selection_id=frame)
    one, two = ["A"], ["B"]
    options = [[trace.legal_option_id(frame, one), one], [trace.legal_option_id(frame, two), two]]
    options.sort(key=lambda record: record[0])
    if zero_required:
        options = []
    elif reordered:
        options.reverse()
    writer.append(trace.LEGAL_OPTION_SET, trace.NONE, [options, trace.CANONICAL_OPTION_ID_ORDER], selection_id=frame)
    if not zero_required and not pop_without_choice:
        choice = _root("not-an-option") if stale_choice else options[0][0]
        writer.append(trace.CHOICE_ACCEPTED, trace.NONE, [choice], selection_id=frame)
    if not zero_required:
        writer.append(trace.SELECTION_POP, trace.NONE, ["pop"], selection_id=frame)
    terminal_mutation = trace.mutation_id(writer.header.computed_game_id(), len(writer._events), 2)
    terminal_state = {"phase": "terminal", "value": 7}
    writer.append(trace.TERMINAL_SET, trace.MUTATION, [terminal_mutation, 2, _root("result"), "set-value", 7], state=terminal_state, counters=[1], transaction_id=_root("terminal-transaction"))
    writer.append(trace.TRACE_END, trace.NONE, [_root("result"), trace.state_root(writer.header.state_schema_root, terminal_state)])
    return trace._encode_private_synthetic_fixture_trace(writer)


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        (_selection_raw(zero_required=True), "TRACE_ZERO_OPTION_REQUIRED_SELECTION"),
        (_selection_raw(reordered=True), "TRACE_OPTION_ORDER_MISMATCH"),
        (_selection_raw(stale_choice=True), "TRACE_CHOICE_NOT_IN_OPTION_SET"),
        (_selection_raw(pop_without_choice=True), "TRACE_CHOICE_NOT_IN_OPTION_SET"),
    ),
)
def test_selection_invariants_fail_closed(raw: bytes, code: str) -> None:
    _assert_code(code, trace.parse_canonical_trace, raw)


def _rng_raw(*, gap: bool = False, rejection_bad: bool = False, shuffle_bad: bool = False) -> bytes:
    writer = trace.CanonicalTraceWriter(_header(), {"phase": "new", "value": 0}, [0])
    writer.append(trace.TRACE_BEGIN, trace.NONE, ["begin"])
    stream = _root("shuffle-stream")
    upper = (1 << 63) + 1
    threshold = (1 << 64) % upper
    rejected = threshold - 1
    accepted = threshold
    writer.append(trace.RNG_STREAM_BOUND, trace.NONE, [stream, _root("seed-commit"), trace.RAW_DRAW_ALGORITHM_ID, 0])
    writer.append(trace.RNG_DRAW, trace.NONE, [stream, 1 if gap else 0, 64, rejected.to_bytes(8, "big"), 2 if gap else 1, _root("site")])
    writer.append(trace.RNG_DRAW, trace.NONE, [stream, 1 if not gap else 2, 64, accepted.to_bytes(8, "big"), 2 if not gap else 3, _root("site")])
    writer.append(
        trace.RNG_BOUNDED_SAMPLE,
        trace.NONE,
        [
            trace.BOUNDED_SAMPLING_ALGORITHM_ID,
            stream,
            upper,
            (1 << 64) % upper,
            [2, 3],
            [accepted] if rejection_bad else [rejected],
            [False, True],
            accepted,
            accepted % upper,
            0,
            2,
        ],
    )
    cards, permutation = [_root("card-a"), _root("card-b"), _root("card-c")], [2, 0, 1]
    output = [cards[index] for index in permutation]
    bad_output = [cards[0], cards[1], cards[2]]
    writer.append(trace.SHUFFLE_APPLIED, trace.NONE, [_root("shuffle-id"), "deck", cards, trace._sequence_root(cards), trace.SHUFFLE_ALGORITHM_ID, [2, 3], permutation, trace._permutation_root(permutation), bad_output if shuffle_bad else output, trace._sequence_root(bad_output if shuffle_bad else output)])
    terminal_mutation = trace.mutation_id(writer.header.computed_game_id(), len(writer._events), 2)
    terminal_state = {"phase": "terminal", "value": 7}
    writer.append(trace.TERMINAL_SET, trace.MUTATION, [terminal_mutation, 2, _root("result"), "set-value", 7], state=terminal_state, counters=[1], transaction_id=_root("terminal-transaction"))
    writer.append(trace.TRACE_END, trace.NONE, [_root("result"), trace.state_root(writer.header.state_schema_root, terminal_state)])
    return trace._encode_private_synthetic_fixture_trace(writer)


@pytest.mark.parametrize(
    ("raw", "code"),
    (
        (_rng_raw(gap=True), "TRACE_RNG_COUNTER_GAP"),
        (_rng_raw(rejection_bad=True), "TRACE_RNG_REJECTION_ACCOUNTING_MISMATCH"),
        (_rng_raw(shuffle_bad=True), "TRACE_SHUFFLE_PERMUTATION_MISMATCH"),
    ),
)
def test_rng_and_shuffle_invariants_fail_closed(raw: bytes, code: str) -> None:
    _assert_code(code, trace.parse_canonical_trace, raw)


def test_rng_roots_raw_lengths_and_shuffle_references_fail_closed() -> None:
    frames = _frames(_rng_raw())
    bound = frames[2]
    assert isinstance(bound, list)
    bound[0][13][0][0] = b"short-stream"
    _rechain_events(frames)
    _assert_code("TRACE_RNG_SITE_UNCOVERED", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_rng_raw())
    draw = frames[3]
    assert isinstance(draw, list)
    draw[0][13][0][3] = b""
    _rechain_events(frames)
    _assert_code("TRACE_RNG_RAW_DRAW_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_rng_raw())
    draw = frames[3]
    assert isinstance(draw, list)
    draw[0][13][0][1] = False
    draw[0][13][0][4] = True
    _rechain_events(frames)
    _assert_code("TRACE_RNG_COUNTER_GAP", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_rng_raw())
    bounded = frames[5]
    assert isinstance(bounded, list)
    bounded[0][13][0][5] = "not-an-integer"
    _rechain_events(frames)
    _assert_code("TRACE_BOUNDED_SAMPLE_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))

    frames = _frames(_rng_raw())
    shuffle = frames[6]
    assert isinstance(shuffle, list)
    shuffle[0][13][0][5] = [4, 4]
    _rechain_events(frames)
    _assert_code("TRACE_SHUFFLE_PERMUTATION_MISMATCH", trace.parse_canonical_trace, _encode_frames(frames))


def test_event_application_replay_rejects_mutation_divergence() -> None:
    _assert_code("TRACE_TRANSACTION_REPLAY_MISMATCH", trace.replay_canonical_trace, _raw(), _DivergentAdapter())


def test_parsed_trace_and_ab_result_are_explicitly_zero_authority() -> None:
    parsed = trace.parse_canonical_trace(_raw())
    for field in (
        "authority", "upload_authorized", "calibration_upload_authorized",
        "production_upload_authorized", "holdout_access_authorized", "agent_modification_authorized",
    ):
        assert getattr(parsed, field) is False


def test_ab_requires_distinct_origins_and_four_way_replay() -> None:
    raw = _externalized_fixture_raw()
    _assert_code(
        "TRACE_INDEPENDENT_ORIGIN_MISSING", trace.verify_ab_conformance,
        trace.AuditOrigin("same", raw), trace.AuditOrigin("same", raw), _Adapter(), _Adapter(),
    )
    report = trace.verify_ab_conformance(
        trace.AuditOrigin("audit-a", raw), trace.AuditOrigin("audit-b", raw), _Adapter(), _Adapter(),
    )
    assert report["four_way_replay_passed"] is True
    for field in ("authority", "upload_authorized", "holdout_access_authorized", "agent_modification_authorized", "calibration_upload_authorized", "production_upload_authorized"):
        assert report[field] is False


def test_ab_semantic_divergence_and_cross_replay_failure_fail_closed() -> None:
    _assert_code(
        "TRACE_AB_SEMANTIC_ROOT_DIVERGENCE", trace.verify_ab_conformance,
        trace.AuditOrigin("audit-a", _externalized_fixture_raw(value=7)), trace.AuditOrigin("audit-b", _externalized_fixture_raw(value=8)), _Adapter(), _Adapter(),
    )
    _assert_code(
        "TRACE_CROSS_REPLAY_FAILURE", trace.verify_ab_conformance,
        trace.AuditOrigin("audit-a", _externalized_fixture_raw()), trace.AuditOrigin("audit-b", _externalized_fixture_raw()), _Adapter(), _DivergentAdapter(),
    )
