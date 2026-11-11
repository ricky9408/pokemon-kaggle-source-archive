from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import hmac

import pytest

from evaluation_v6_3_1.unified_rng_events import (
    BRANCH_COMMIT,
    BRANCH_FORK,
    CHECKPOINT,
    SESSION_CLOSE,
    UnifiedRngEventError,
    branch_commit_payload,
    branch_fork_payload,
    bounded_sample_payload,
    build_event,
    checkpoint_payload,
    decode_trace_events,
    derive_event_stream_id,
    event_hash,
    raw_draw_payload,
    restore_payload,
    session_close_payload,
    shuffle_payload,
    stream_bind_payload,
    validate_event_envelope,
    verify_event_chain,
    verify_checkpoint_trace_prefix,
    verify_trace_bytes,
)
from evaluation_v6_3_1.unified_rng_protocol import (
    DS_BRANCH_FINAL,
    DS_BRANCH_GENESIS,
    DS_BRANCH_ID,
    DS_BRANCH_LEAF,
    DS_BRANCH_STEP,
    DS_EVENT_302,
    DS_RESUME_CAP,
    DS_RESUME_COMMIT,
    DS_RESUME_PROOF,
    DS_RESUME_SESSION,
    DS_STATE,
    PROTOCOL_VERSION,
    ZERO_ID,
    canonical_cbor_encode,
)


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _digest(domain: bytes, value: list) -> bytes:
    return sha256(domain + canonical_cbor_encode(value)).digest()


SESSION = _root("session")
SITE = _root("site")
OBJECT = _root("object")
STREAM = derive_event_stream_id(SESSION, SITE, OBJECT, 7, 3)
SITE_B = _root("site-b")
OBJECT_B = _root("object-b")
STREAM_B = derive_event_stream_id(SESSION, SITE_B, OBJECT_B, 8, 4)
CARD_A, CARD_B = _root("card-a"), _root("card-b")
EVALUATOR_SECRET = _root("evaluator-secret")
RUN_BINDING_ROOT = _root("run-binding-root")


def _append(
    events: list,
    event_type: int,
    stream_id: bytes,
    payload: list,
    *,
    branch_context_id: bytes = ZERO_ID,
    previous_branch_chain_hash: bytes = ZERO_ID,
) -> None:
    previous_global = ZERO_ID if not events else event_hash(events[-1])
    previous_stream = ZERO_ID
    if stream_id != ZERO_ID:
        for prior in reversed(events):
            if prior.stream_id == stream_id:
                previous_stream = event_hash(prior)
                break
    events.append(
        build_event(
            event_type,
            SESSION,
            len(events),
            previous_global,
            stream_id,
            previous_stream,
            branch_context_id,
            previous_branch_chain_hash,
            payload,
        )
    )


def _branch_leaf(event) -> bytes:
    return _digest(
        DS_BRANCH_LEAF,
        [
            PROTOCOL_VERSION,
            event.event_type,
            event.session_id,
            event.stream_id,
            event.branch_context_id,
            event.as_array()[9],
        ],
    )


def _branch_step(branch_id: bytes, previous: bytes, event) -> bytes:
    return _digest(
        DS_BRANCH_STEP,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            branch_id,
            previous,
            _branch_leaf(event),
        ],
    )


def _resume_capability(
    checkpoint_id: int,
    generation: int,
    next_sequence: int,
    offset: int,
    gateway_root: bytes,
) -> bytes:
    session_key = hmac.new(
        EVALUATOR_SECRET,
        DS_RESUME_SESSION
        + canonical_cbor_encode([PROTOCOL_VERSION, SESSION, RUN_BINDING_ROOT]),
        "sha256",
    ).digest()
    return hmac.new(
        session_key,
        DS_RESUME_CAP
        + canonical_cbor_encode(
            [
                PROTOCOL_VERSION,
                SESSION,
                checkpoint_id,
                generation,
                next_sequence,
                offset,
                gateway_root,
            ]
        ),
        "sha256",
    ).digest()


def _chain_with_all_events() -> list:
    events: list = []
    _append(events, 3, STREAM, stream_bind_payload(SITE, OBJECT, 7, 3))
    _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, 0, 7))
    _append(events, 5, STREAM, bounded_sample_payload(ZERO_ID, 4, 0, 1, 0, 3))
    _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, 1, 0))
    _append(events, 5, STREAM, bounded_sample_payload(ZERO_ID, 2, 1, 1, 1, 0))
    _append(
        events,
        6,
        STREAM,
        shuffle_payload(
            ZERO_ID,
            0,
            1,
            2,
            [CARD_A, CARD_B],
            [1, 0],
            [CARD_B, CARD_A],
        ),
    )

    parent_state = _root("parent-state")
    purpose = _root("search")
    child = sha256(
        DS_BRANCH_ID
        + SESSION
        + STREAM
        + ZERO_ID
        + (0).to_bytes(8, "big")
        + purpose
        + parent_state
    ).digest()
    _append(
        events,
        BRANCH_FORK,
        STREAM,
        branch_fork_payload(
            ZERO_ID,
            child,
            0,
            purpose,
            2,
            1,
            parent_state,
        ),
    )
    fork_leaf = _branch_leaf(events[-1])
    child_genesis = _digest(
        DS_BRANCH_GENESIS,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            ZERO_ID,
            child,
            fork_leaf,
        ],
    )
    _append(
        events,
        4,
        STREAM,
        raw_draw_payload(child, 0, 11),
        branch_context_id=child,
        previous_branch_chain_hash=child_genesis,
    )
    child_head = _branch_step(child, child_genesis, events[-1])
    child_trace_root = _digest(
        DS_BRANCH_FINAL,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            child,
            ZERO_ID,
            child_genesis,
            child_head,
            1,
            1,
            0,
            0,
        ],
    )
    _append(
        events,
        BRANCH_COMMIT,
        STREAM,
        branch_commit_payload(
            child,
            1,
            0,
            child_trace_root,
            _root("result"),
            parent_state,
            parent_state,
        ),
    )

    rows = [[STREAM, 2, 1, 1, 0, event_hash(events[-1])]]
    checkpoint_offset = sum(len(event.to_bytes()) for event in events)
    checkpoint_root = sha256(
        DS_STATE
        + canonical_cbor_encode(
            [
                SESSION,
                0,
                len(events) + 1,
                checkpoint_offset,
                rows,
            ]
        )
    ).digest()
    capability = _resume_capability(
        0,
        0,
        len(events) + 1,
        checkpoint_offset,
        checkpoint_root,
    )
    commitment = _digest(
        DS_RESUME_COMMIT,
        [PROTOCOL_VERSION, SESSION, 0, checkpoint_root, capability],
    )
    _append(
        events,
        CHECKPOINT,
        ZERO_ID,
        checkpoint_payload(
            0,
            0,
            len(events) + 1,
            checkpoint_offset,
            rows,
            commitment,
            checkpoint_root,
        ),
    )
    checkpoint_hash = event_hash(events[-1])
    restore_offset = checkpoint_offset + len(events[-1].to_bytes())
    proof = _digest(
        DS_RESUME_PROOF,
        [
            PROTOCOL_VERSION,
            SESSION,
            0,
            checkpoint_hash,
            0,
            1,
            checkpoint_root,
            capability,
        ],
    )
    _append(
        events,
        11,
        ZERO_ID,
        restore_payload(
            0,
            checkpoint_hash,
            0,
            1,
            checkpoint_root,
            capability,
            proof,
            restore_offset,
        ),
    )
    summaries = [[STREAM, 2, 1, 1, event_hash(events[8])]]
    _append(
        events,
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            _root("seed"),
            RUN_BINDING_ROOT,
            len(events) + 1,
            summaries,
            event_hash(events[9]),
            _root("manifest"),
            _root("engine"),
            0,
            0,
        ),
    )
    return events


def _nested_interleaved_chain() -> list:
    events: list = []
    _append(events, 3, STREAM, stream_bind_payload(SITE, OBJECT, 7, 3))
    _append(events, 3, STREAM_B, stream_bind_payload(SITE_B, OBJECT_B, 8, 4))

    root_parent_state = _root("root-parent-state")
    outer_purpose = _root("outer-search")
    outer = sha256(
        DS_BRANCH_ID
        + SESSION
        + STREAM
        + ZERO_ID
        + (0).to_bytes(8, "big")
        + outer_purpose
        + root_parent_state
    ).digest()
    _append(
        events,
        BRANCH_FORK,
        STREAM,
        branch_fork_payload(
            ZERO_ID,
            outer,
            0,
            outer_purpose,
            0,
            0,
            root_parent_state,
        ),
    )
    outer_genesis = _digest(
        DS_BRANCH_GENESIS,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            ZERO_ID,
            outer,
            _branch_leaf(events[-1]),
        ],
    )

    # Other streams may interleave without entering or perturbing this branch.
    _append(events, 4, STREAM_B, raw_draw_payload(ZERO_ID, 0, 17))

    inner_parent_state = _root("inner-parent-state")
    inner_purpose = _root("inner-search")
    inner = sha256(
        DS_BRANCH_ID
        + SESSION
        + STREAM
        + outer
        + (0).to_bytes(8, "big")
        + inner_purpose
        + inner_parent_state
    ).digest()
    _append(
        events,
        BRANCH_FORK,
        STREAM,
        branch_fork_payload(
            outer,
            inner,
            0,
            inner_purpose,
            0,
            0,
            inner_parent_state,
        ),
        branch_context_id=outer,
        previous_branch_chain_hash=outer_genesis,
    )
    outer_head_after_fork = _branch_step(outer, outer_genesis, events[-1])
    inner_genesis = _digest(
        DS_BRANCH_GENESIS,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            outer,
            inner,
            _branch_leaf(events[-1]),
        ],
    )
    _append(
        events,
        4,
        STREAM,
        raw_draw_payload(inner, 0, 23),
        branch_context_id=inner,
        previous_branch_chain_hash=inner_genesis,
    )
    inner_head = _branch_step(inner, inner_genesis, events[-1])
    inner_root = _digest(
        DS_BRANCH_FINAL,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            inner,
            outer,
            inner_genesis,
            inner_head,
            1,
            1,
            0,
            0,
        ],
    )
    _append(
        events,
        9,
        STREAM,
        [
            inner,
            1,
            0,
            inner_root,
            7,
            inner_parent_state,
            inner_parent_state,
        ],
        branch_context_id=outer,
        previous_branch_chain_hash=outer_head_after_fork,
    )
    outer_head_after_abort = _branch_step(
        outer,
        outer_head_after_fork,
        events[-1],
    )
    _append(
        events,
        4,
        STREAM,
        raw_draw_payload(outer, 0, 29),
        branch_context_id=outer,
        previous_branch_chain_hash=outer_head_after_abort,
    )
    outer_head_after_raw = _branch_step(
        outer,
        outer_head_after_abort,
        events[-1],
    )
    outer_root = _digest(
        DS_BRANCH_FINAL,
        [
            PROTOCOL_VERSION,
            SESSION,
            STREAM,
            outer,
            ZERO_ID,
            outer_genesis,
            outer_head_after_raw,
            3,
            1,
            0,
            1,
        ],
    )
    _append(
        events,
        BRANCH_COMMIT,
        STREAM,
        branch_commit_payload(
            outer,
            1,
            0,
            outer_root,
            _root("outer-result"),
            root_parent_state,
            root_parent_state,
        ),
    )

    summaries = sorted(
        [
            [STREAM, 0, 0, 1, event_hash(events[-1])],
            [STREAM_B, 1, 0, 0, event_hash(events[3])],
        ]
    )
    _append(
        events,
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            _root("seed"),
            RUN_BINDING_ROOT,
            len(events) + 1,
            summaries,
            ZERO_ID,
            _root("manifest"),
            _root("engine"),
            0,
            0,
        ),
    )
    return events


def _shuffle_chain(size: int) -> list:
    events: list = []
    _append(events, 3, STREAM, stream_bind_payload(SITE, OBJECT, 7, 3))
    before = [_root(f"shuffle-card-{index}") for index in range(size)]
    permutation = list(range(size))
    counter = 0
    for index in range(size - 1, 0, -1):
        _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, counter, 0))
        _append(
            events,
            5,
            STREAM,
            bounded_sample_payload(ZERO_ID, index + 1, counter, 1, counter, 0),
        )
        permutation[index], permutation[0] = permutation[0], permutation[index]
        counter += 1
    after = [before[index] for index in permutation]
    _append(
        events,
        6,
        STREAM,
        shuffle_payload(ZERO_ID, 0, 0, counter, before, permutation, after),
    )
    summaries = [[STREAM, counter, 1, 0, event_hash(events[-1])]]
    _append(
        events,
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            _root("seed"),
            RUN_BINDING_ROOT,
            len(events) + 1,
            summaries,
            ZERO_ID,
            _root("manifest"),
            _root("engine"),
            0,
            0,
        ),
    )
    return events


def _reseal(arrays: list[list]) -> list:
    result = []
    previous_global = ZERO_ID
    stream_previous: dict[bytes, bytes] = {}
    for sequence, array in enumerate(arrays):
        array[3] = sequence
        array[4] = previous_global
        if array[1] in (3, 4, 5, 6, 7, 8, 9):
            array[6] = stream_previous.get(array[5], ZERO_ID)
        else:
            array[5] = ZERO_ID
            array[6] = ZERO_ID
            array[7] = ZERO_ID
            array[8] = ZERO_ID
        current = build_event(
            array[1],
            array[2],
            array[3],
            array[4],
            array[5],
            array[6],
            array[7],
            array[8],
            array[9],
        )
        result.append(current)
        current_hash = event_hash(current)
        previous_global = current_hash
        if current.stream_id != ZERO_ID:
            stream_previous[current.stream_id] = current_hash
    return result


def _verify(events):
    return verify_event_chain(
        events,
        expected_session_id=SESSION,
        evaluator_secret=EVALUATOR_SECRET,
        expected_run_binding_root=RUN_BINDING_ROOT,
    )


def test_exact_array_envelope_hash_and_all_event_types() -> None:
    events = _chain_with_all_events()
    first = events[0]
    assert first.as_array()[:2] == [PROTOCOL_VERSION, 3]
    assert len(first.as_array()) == 10
    assert first.to_bytes() == canonical_cbor_encode(first.as_array())
    assert event_hash(first) == sha256(DS_EVENT_302 + first.to_bytes()).digest()
    assert [event.event_type for event in events] == [
        3,
        4,
        5,
        4,
        5,
        6,
        7,
        4,
        8,
        10,
        11,
        12,
    ]
    verified = _verify(events)
    assert verified.closed is True
    assert verified.event_count == 12
    assert verified.trace_root == event_hash(events[-1])
    assert verified.trace_byte_length == sum(len(event.to_bytes()) for event in events)
    assert verified.stream_event_hashes[STREAM] == event_hash(events[8])

    trace = b"".join(event.to_bytes() for event in events)
    decoded = decode_trace_events(trace)
    assert decoded == tuple(events)
    assert _verify(decoded).trace_root == verified.trace_root
    assert verify_trace_bytes(
        trace,
        expected_session_id=SESSION,
        evaluator_secret=EVALUATOR_SECRET,
        expected_run_binding_root=RUN_BINDING_ROOT,
    ).trace_byte_length == len(trace)
    checkpoint_trace = b"".join(event.to_bytes() for event in events[:10])
    checkpoint_prefix = verify_checkpoint_trace_prefix(
        checkpoint_trace,
        expected_session_id=SESSION,
        evaluator_secret=EVALUATOR_SECRET,
        expected_run_binding_root=RUN_BINDING_ROOT,
    )
    assert checkpoint_prefix.closed is False
    assert checkpoint_prefix.event_count == 10
    assert checkpoint_prefix.trace_root == event_hash(events[9])


def test_independent_node_event_and_branch_vectors() -> None:
    assert STREAM.hex() == "1089879e074c5fef54c5520f7070fd1470ad57378797c26dca34d52d00f79674"
    events: list = []
    _append(events, 3, STREAM, stream_bind_payload(SITE, OBJECT, 7, 3))
    assert event_hash(events[-1]).hex() == "0584594b8a564bc97415efa344d2bcea961ed61c5ce586c06df4db5b25953bd8"

    purpose = _root("search")
    parent_state = _root("parent-state")
    child = sha256(
        DS_BRANCH_ID
        + SESSION
        + STREAM
        + ZERO_ID
        + (0).to_bytes(8, "big")
        + purpose
        + parent_state
    ).digest()
    assert child.hex() == "dcbdc1f84c7fe79766d948073bb6d81a483cb928c7404001a2e8fc2ee6fd180b"
    _append(
        events,
        BRANCH_FORK,
        STREAM,
        branch_fork_payload(ZERO_ID, child, 0, purpose, 0, 0, parent_state),
    )
    assert event_hash(events[-1]).hex() == "7aec1b86027a9ed027d036af37933fb1519c2211cd65c24e94744f415e578fb3"
    genesis = bytes.fromhex(
        "3801480d0edfac0004eacccc397c5703ea3943a5e9b8a579dcb95bee00fb848a"
    )
    _append(
        events,
        4,
        STREAM,
        raw_draw_payload(child, 0, 11),
        branch_context_id=child,
        previous_branch_chain_hash=genesis,
    )
    assert event_hash(events[-1]).hex() == "9e077768f8fc3a73f77f5adf2a6d6dd13958fd024c997a00ba47ad5a86526b4f"
    branch_root = bytes.fromhex(
        "a7801bf1a15d3129d5a6bbb3dc86eeff108090889477c8e743e7940ab70ee941"
    )
    _append(
        events,
        BRANCH_COMMIT,
        STREAM,
        branch_commit_payload(
            child,
            1,
            0,
            branch_root,
            _root("result"),
            parent_state,
            parent_state,
        ),
    )
    _append(
        events,
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            _root("seed"),
            RUN_BINDING_ROOT,
            len(events) + 1,
            [[STREAM, 0, 0, 1, event_hash(events[-1])]],
            ZERO_ID,
            _root("manifest"),
            _root("engine"),
            0,
            0,
        ),
    )
    assert _verify(events).closed is True


def test_runtime_event_payload_is_detached_and_deeply_immutable() -> None:
    payload = shuffle_payload(
        ZERO_ID,
        0,
        0,
        0,
        [CARD_A, CARD_B],
        [0, 1],
        [CARD_A, CARD_B],
    )
    event = build_event(
        6,
        SESSION,
        0,
        ZERO_ID,
        STREAM,
        ZERO_ID,
        ZERO_ID,
        ZERO_ID,
        payload,
    )
    original_bytes = event.to_bytes()

    payload[4][0] = _root("caller-mutation")
    detached = event.as_array()
    detached[9][4][0] = _root("returned-array-mutation")

    assert event.to_bytes() == original_bytes
    assert event.payload[4][0] == CARD_A
    with pytest.raises(TypeError):
        event.payload[4][0] = _root("internal-mutation")


def test_nested_lifo_branches_allow_only_cross_stream_interleaving() -> None:
    events = _nested_interleaved_chain()
    verified = _verify(events)
    assert verified.closed is True
    assert verified.event_count == 10

    arrays = [event.as_array() for event in events]
    arrays[3][5] = STREAM
    arrays[3][9] = raw_draw_payload(ZERO_ID, 0, 17)
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(arrays))
    assert raised.value.code == "RNG_SAME_STREAM_BRANCH_INTERLEAVING_INVALID"


def test_stream_bind_derivation_and_duplicate_id_fail_closed() -> None:
    events = _chain_with_all_events()
    forged = [event.as_array() for event in events]
    forged[0][9][3] = 4
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(forged))
    assert raised.value.code == "RNG_CALLER_SUPPLIED_STREAM_ID"

    duplicate = deepcopy(events[:1])
    duplicate.append(
        build_event(
            3,
            SESSION,
            1,
            event_hash(duplicate[-1]),
            STREAM,
            ZERO_ID,
            ZERO_ID,
            ZERO_ID,
            stream_bind_payload(SITE, OBJECT, 7, 3),
        )
    )
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(duplicate)
    assert raised.value.code == "RNG_STREAM_BIND_DUPLICATE"


@pytest.mark.parametrize(
    ("mutation", "code"),
    (
        (lambda values: values.reverse(), "RNG_EVENT_CHAIN_MISMATCH"),
        (
            lambda values: values[3].__setitem__(4, _root("wrong-global-prev")),
            "RNG_EVENT_CHAIN_MISMATCH",
        ),
        (
            lambda values: values[1].__setitem__(6, _root("wrong-stream-prev")),
            "RNG_STREAM_CHAIN_MISMATCH",
        ),
        (
            lambda values: values[7].__setitem__(8, _root("wrong-branch-prev")),
            "RNG_BRANCH_PREDECESSOR_MISMATCH",
        ),
    ),
)
def test_reordering_and_chain_mismatch(mutation, code: str) -> None:
    values = [event.as_array() for event in _chain_with_all_events()]
    mutation(values)
    candidate = [
        build_event(v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9])
        for v in values
    ]
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(candidate)
    assert raised.value.code == code


def test_bounded_wrong_interval_and_rejection_bound_are_liars() -> None:
    values = [event.as_array() for event in _chain_with_all_events()]
    values[2][9][2] = 1
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_BOUNDED_SAMPLE_INVALID"

    values = [event.as_array() for event in _chain_with_all_events()]
    values[4][9][5] = 1
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_BOUNDED_SAMPLE_INVALID"


def test_duplicate_shuffle_instance_id_is_rejected_before_chain_verification() -> None:
    with pytest.raises(UnifiedRngEventError) as raised:
        shuffle_payload(
            ZERO_ID,
            0,
            0,
            0,
            [CARD_A, CARD_A],
            [0, 1],
            [CARD_A, CARD_A],
        )
    assert raised.value.code == "RNG_DUPLICATE_CARD_INSTANCE_ID"


@pytest.mark.parametrize("size", range(9))
def test_fisher_yates_receipt_groups_verify_for_every_size_through_eight(size: int) -> None:
    verified = _verify(_shuffle_chain(size))
    assert verified.closed is True


def test_shuffle_receipt_walk_supports_rejection_sampling_groups() -> None:
    events: list = []
    _append(events, 3, STREAM, stream_bind_payload(SITE, OBJECT, 7, 3))
    _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, 0, (1 << 64) - 1))
    _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, 1, 1))
    _append(events, 5, STREAM, bounded_sample_payload(ZERO_ID, 3, 0, 2, 1, 1))
    _append(events, 4, STREAM, raw_draw_payload(ZERO_ID, 2, 0))
    _append(events, 5, STREAM, bounded_sample_payload(ZERO_ID, 2, 2, 1, 2, 0))
    cards = [_root(f"rejection-card-{index}") for index in range(3)]
    permutation = [2, 0, 1]
    _append(
        events,
        6,
        STREAM,
        shuffle_payload(
            ZERO_ID,
            0,
            0,
            3,
            cards,
            permutation,
            [cards[index] for index in permutation],
        ),
    )
    _append(
        events,
        SESSION_CLOSE,
        ZERO_ID,
        session_close_payload(
            _root("seed"),
            RUN_BINDING_ROOT,
            len(events) + 1,
            [[STREAM, 3, 1, 0, event_hash(events[-1])]],
            ZERO_ID,
            _root("manifest"),
            _root("engine"),
            0,
            0,
        ),
    )
    assert _verify(events).closed is True


def test_branch_root_checkpoint_offset_and_restore_offset_fail_closed() -> None:
    values = [event.as_array() for event in _chain_with_all_events()]
    values[8][9][3] = _root("lied-about-branch-root")
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_BRANCH_TRACE_ROOT_MISMATCH"

    values = [event.as_array() for event in _chain_with_all_events()]
    values[9][9][3] += 1
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_CHECKPOINT_TRACE_OFFSET_MISMATCH"

    values = [event.as_array() for event in _chain_with_all_events()]
    values[10][9][7] += 1
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_RESTORE_TRACE_OFFSET_MISMATCH"


def test_checkpoint_sequence_and_retired_restore_shape_have_exact_codes() -> None:
    values = [event.as_array() for event in _chain_with_all_events()]
    values[9][9][2] += 1
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_CHECKPOINT_NEXT_SEQUENCE_MISMATCH"

    values = [event.as_array() for event in _chain_with_all_events()]
    values[10][9] = values[10][9][:-1]
    with pytest.raises(UnifiedRngEventError) as raised:
        _reseal(values)
    assert raised.value.code == "RNG_PROTOCOL_631301_RETIRED"


def test_closed_branch_and_resume_opening_fail_with_exact_codes() -> None:
    events = _chain_with_all_events()
    child_id = events[6].payload[1]
    closed_reference = list(events[:9])
    _append(
        closed_reference,
        4,
        STREAM,
        raw_draw_payload(child_id, 1, 19),
        branch_context_id=child_id,
        previous_branch_chain_hash=_root("closed-child-head"),
    )
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(closed_reference)
    assert raised.value.code == "RNG_BRANCH_EVENT_AFTER_CLOSE"

    values = [event.as_array() for event in events]
    values[10][9][5] = _root("forged-opening")
    with pytest.raises(UnifiedRngEventError) as raised:
        _verify(_reseal(values))
    assert raised.value.code == "RNG_RESUME_CAPABILITY_DERIVATION_MISMATCH"

    with pytest.raises(UnifiedRngEventError) as raised:
        verify_event_chain(events, expected_session_id=SESSION)
    assert raised.value.code == "RNG_RESUME_SESSION_KEY_CONTEXT_INVALID"


def test_trace_parser_rejects_partial_and_mixed_protocol_suffixes() -> None:
    events = _chain_with_all_events()
    trace = b"".join(event.to_bytes() for event in events)
    with pytest.raises(UnifiedRngEventError) as raised:
        decode_trace_events(trace + b"\x8a")
    assert raised.value.code == "RNG_TRACE_TRAILING_PARTIAL_EVENT"

    retired = [
        631301,
        3,
        SESSION,
        0,
        ZERO_ID,
        STREAM,
        ZERO_ID,
        stream_bind_payload(SITE, OBJECT, 7, 3),
    ]
    with pytest.raises(UnifiedRngEventError) as raised:
        decode_trace_events(events[0].to_bytes() + canonical_cbor_encode(retired))
    assert raised.value.code == "RNG_MIXED_PROTOCOL_SESSION"


def test_strict_envelope_retires_631301_and_requires_branch_fields() -> None:
    old = [
        631301,
        3,
        SESSION,
        0,
        ZERO_ID,
        STREAM,
        ZERO_ID,
        stream_bind_payload(SITE, OBJECT, 7, 3),
    ]
    with pytest.raises(UnifiedRngEventError) as raised:
        validate_event_envelope(old)
    assert raised.value.code == "RNG_PROTOCOL_631301_RETIRED"

    missing = [
        PROTOCOL_VERSION,
        3,
        SESSION,
        0,
        ZERO_ID,
        STREAM,
        ZERO_ID,
        stream_bind_payload(SITE, OBJECT, 7, 3),
    ]
    with pytest.raises(UnifiedRngEventError) as raised:
        validate_event_envelope(missing)
    assert raised.value.code == "RNG_EVENT_BRANCH_FIELD_MISSING"

    with pytest.raises(UnifiedRngEventError):
        build_event(
            3,
            SESSION,
            0,
            ZERO_ID,
            STREAM,
            ZERO_ID,
            ZERO_ID,
            ZERO_ID,
            [SITE, OBJECT, True, 3],
        )
