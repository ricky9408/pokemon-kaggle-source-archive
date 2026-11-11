from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode
from evaluation_v6_3_1.rng_branch_trace import (
    BOUNDED_KIND,
    BRANCH_ROOT_DOMAIN,
    NO_UPLOAD,
    RAW_KIND,
    SHUFFLE_KIND,
    RngBranchTraceError,
    RngBranchTraceSession,
    cpp_shuffle_card_ids,
    derive_child_neutral_branch_id,
    derive_operation_id,
    derive_public_branch_id,
    derive_root_neutral_branch_id,
    derive_semantic_request_root,
    replay_session,
    session_header_hash,
)
from evaluation_v6_3_1.rng_seed_protocol import SeedMaterial, derive_evaluator_secret_commitment


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _material(candidate: str = "candidate-a", control: str = "control-a", seat: int = 0) -> SeedMaterial:
    protocol, model, population, secret = _root("protocol"), _root("model"), _root("population"), _root("secret")
    return SeedMaterial(protocol, model, population, _root(candidate), _root(control), 41, seat, secret, derive_evaluator_secret_commitment(secret, protocol, model, population, 41))


def _assert_code(code: str, fn, *args) -> None:
    with pytest.raises(RngBranchTraceError) as raised:
        fn(*args)
    assert raised.value.code == code


def _reseal_branch(envelope: list[object], branch_index: int) -> None:
    header = envelope[2]
    branch = envelope[3][branch_index]
    events = branch[12]
    previous = events[0][0][3] if events else sha256(
        b"V631/RNG/BRANCH/GENESIS/V2"
        + canonical_cbor_encode([header, branch[3]])
    ).digest()
    for sequence, event in enumerate(events):
        core = event[0]
        core[1] = sequence
        core[3] = previous
        event[1] = sha256(
            b"V631/RNG/EVENT/V2"
            + header
            + canonical_cbor_encode(core)
        ).digest()
        previous = event[1]
    branch[11] = len(events)
    branch[13] = sha256(
        BRANCH_ROOT_DOMAIN
        + canonical_cbor_encode(
            [
                header,
                branch[1],
                branch[2],
                branch[3],
                len(events),
                previous,
            ]
        )
    ).digest()


def _complete() -> tuple[SeedMaterial, RngBranchTraceSession, list[object]]:
    material, session = _material(), RngBranchTraceSession(_material())
    root = session.make_search_root()
    session.activate_search_branch(root)
    session.record_raw("SETUP", _root("root-site"))
    session.commit_search_branch(root)
    semantic = derive_semantic_request_root("STEP", [9, -2])
    child = session.fork_search_step(root, [9, -2])
    assert child == derive_child_neutral_branch_id(material, root, semantic, 0)
    session.activate_search_branch(child)
    output, shuffle = session.record_shuffle_from_cpp_indices("SHUFFLE", [3, 4, 63], _root("shuffle-site"), "DECK")
    assert sorted(output) == [3, 4, 63]
    assert shuffle[0][2] == SHUFFLE_KIND
    session.commit_search_branch(child)
    envelope = session.seal()
    return material, session, envelope


def test_v2_ids_are_neutral_by_request_but_public_ids_are_run_bound() -> None:
    left, right = _material(), _material("candidate-b", "control-b", 1)
    root = derive_root_neutral_branch_id(left, 7)
    assert root == derive_root_neutral_branch_id(right, 7)
    semantic = derive_semantic_request_root("STEP", [1, -1])
    child = derive_child_neutral_branch_id(left, root, semantic, 4)
    assert child == derive_child_neutral_branch_id(right, root, semantic, 4)
    assert derive_public_branch_id(left, child) != derive_public_branch_id(right, child)
    assert session_header_hash(left) != session_header_hash(right)


def test_exact_cpp_vectors_replay_with_numeric_kinds_and_five_streams() -> None:
    material, session, envelope = _complete()
    assert envelope[:3] == [2, 0, session_header_hash(material)]
    assert all(len(branch) == 14 for branch in envelope[3])
    assert [event[0][2] for branch in envelope[3] for event in branch[12]] == [RAW_KIND, RAW_KIND, BOUNDED_KIND, RAW_KIND, BOUNDED_KIND, SHUFFLE_KIND]
    child_events = envelope[3][2][12]
    shuffle_payload = child_events[-1][0][5]
    assert len(child_events[0][0][5]) == 9
    assert len(child_events[3][0][5]) == len(shuffle_payload) == 15
    assert shuffle_payload[5] == "DECK"
    assert shuffle_payload[9] == "output[position]=input[permutation[position]]"
    assert shuffle_payload[12] == [cpp_shuffle_card_ids(material, [3, 4, 63])[index] for index in shuffle_payload[10]]
    report = replay_session(envelope, material)
    assert report["authority"] == NO_UPLOAD
    assert report["production_upload_authorized"] is False


def test_operation_ids_are_derived_and_branch_lifecycle_fails_closed() -> None:
    material, session = _material(), RngBranchTraceSession(_material())
    root = session.make_search_root()
    authoritative = session.record_raw("COIN", _root("authoritative-site"))
    assert authoritative[0][5][1:3] == [bytes(32), bytes(32)]
    session.activate_search_branch(root)
    event = session.record_raw("COIN", _root("site"))
    assert event[0][4] == derive_operation_id(session.session_header_hash, derive_public_branch_id(material, root), 0, RAW_KIND, _root("site"))
    session.commit_search_branch(root)
    _assert_code("BRANCH_TRACE_LIFECYCLE_INVALID", session.activate_search_branch, root)
    child = session.fork_search_step(root, [])
    _assert_code("BRANCH_TRACE_LIFECYCLE_INVALID", session.release_search_branch, child)


@pytest.mark.parametrize(
    ("mutate", "code"),
    (
        (lambda envelope: envelope.__setitem__(2, _root("wrong-header")), "BRANCH_TRACE_KDF_MISMATCH"),
        (lambda envelope: envelope[3].reverse(), "BRANCH_TRACE_ORDER_INVALID"),
        (lambda envelope: envelope[3][2][12][0][0].__setitem__(4, _root("reused-operation")), "BRANCH_TRACE_KDF_MISMATCH"),
        (lambda envelope: envelope[3][2][12][-1][0][5].__setitem__(9, "reversed"), "BRANCH_TRACE_ROOT_MISMATCH"),
        (lambda envelope: envelope[3][2][12][0][0][5].__setitem__(7, b"\0" * 8), "BRANCH_TRACE_ROOT_MISMATCH"),
    ),
)
def test_replayer_fails_closed_on_tampering_order_and_semantic_reuse(mutate, code: str) -> None:
    material, _session, envelope = _complete()
    forged = deepcopy(envelope)
    mutate(forged)
    _assert_code(code, replay_session, forged, material)


def test_replayer_rejects_reference_reuse() -> None:
    material, _session, envelope = _complete()
    replay_session(envelope, material)
    reused = deepcopy(envelope)
    bounded = next(item for item in reused[3][2][12] if item[0][2] == BOUNDED_KIND)
    bounded[0][5][7].append(bounded[0][5][7][0])
    _assert_code("BRANCH_TRACE_ROOT_MISMATCH", replay_session, reused, material)


@pytest.mark.parametrize("mutation", ("delete", "insert"))
def test_embedded_event_deletion_and_insertion_fail_closed(mutation: str) -> None:
    material, _session, envelope = _complete()
    forged = deepcopy(envelope)
    events = forged[3][2][12]
    if mutation == "delete":
        events.pop()
    else:
        events.insert(0, deepcopy(events[0]))
    _assert_code("BRANCH_TRACE_ROOT_MISMATCH", replay_session, forged, material)


def test_authoritative_raw_bounded_and_progressive_checkpoints() -> None:
    material, session = _material(), RngBranchTraceSession(_material())
    root = session.make_search_root()
    session.activate_search_branch(root)
    session.record_raw("SEARCH", _root("search-site"))
    session.commit_search_branch(root)

    session.record_raw("SETUP", _root("authoritative-raw"))
    first = session.seal()
    session.record_bounded("COIN", 2, _root("authoritative-bounded"))
    second = session.seal()

    first_authoritative, second_authoritative = first[3][0], second[3][0]
    assert first[:2] == [2, 0]
    assert second[:2] == [2, 1]
    assert first_authoritative[10] == second_authoritative[10] == 0
    assert [event[0][2] for event in first_authoritative[12]] == [RAW_KIND]
    assert [event[0][2] for event in second_authoritative[12]] == [RAW_KIND, RAW_KIND, BOUNDED_KIND]
    assert len(first_authoritative[12]) == 1
    assert first[3][1] == second[3][1]
    replay_session(first, material)
    replay_session(second, material)


def test_replayer_rejects_rehashed_boolean_integer_type_confusion() -> None:
    material, session = _material(), RngBranchTraceSession(_material())
    session.record_bounded("COIN", 1, _root("bounded-site"))
    envelope = session.seal()
    bounded = envelope[3][0][12][-1]
    assert bounded[0][5][11] == 0
    bounded[0][5][11] = False
    _reseal_branch(envelope, 0)
    _assert_code("BRANCH_TRACE_SCHEMA_INVALID", replay_session, envelope, material)


def test_replayer_rejects_rehashed_noncontiguous_bounded_raw_reference() -> None:
    material, session = _material(), RngBranchTraceSession(_material())
    standalone = session.record_raw("COIN", _root("bounded-site"))
    session.record_bounded("COIN", 1, _root("bounded-site"))
    envelope = session.seal()
    events = envelope[3][0][12]
    bounded = events[-1][0][5]
    standalone_payload = standalone[0][5]
    bounded[7] = [standalone[0][4]]
    bounded[8] = []
    bounded[9] = [True]
    bounded[10] = int.from_bytes(standalone_payload[7], "big")
    bounded[11] = 0
    bounded[12] = standalone_payload[5]
    bounded[13] = standalone_payload[6]
    _reseal_branch(envelope, 0)
    _assert_code("BRANCH_TRACE_ORDER_INVALID", replay_session, envelope, material)


def test_session_requires_authoritative_snapshot_and_contiguous_branch_ordinals() -> None:
    material, session = _material(), RngBranchTraceSession(_material())
    root = session.make_search_root()
    session.activate_search_branch(root)
    session.commit_search_branch(root)
    first = session.fork_search_step(root, [7])
    session.activate_search_branch(first)
    session.commit_search_branch(first)
    second = session.fork_search_step(root, [7])
    session.activate_search_branch(second)
    session.commit_search_branch(second)
    envelope = session.seal()

    missing_authoritative = deepcopy(envelope)
    missing_authoritative[3] = [
        branch for branch in missing_authoritative[3] if branch[10] != 0
    ]
    _assert_code(
        "BRANCH_TRACE_REFERENCE_INVALID",
        replay_session,
        missing_authoritative,
        material,
    )

    ordinal_gap = deepcopy(envelope)
    ordinal_gap[3] = [
        branch
        for branch in ordinal_gap[3]
        if branch[2] != first
    ]
    _assert_code("BRANCH_TRACE_ORDER_INVALID", replay_session, ordinal_gap, material)


def test_child_depth_must_be_exactly_parent_depth_plus_one() -> None:
    material, _session, envelope = _complete()
    forged = deepcopy(envelope)
    child_index = next(
        index
        for index, branch in enumerate(forged[3])
        if branch[10] != 0 and not branch[4]
    )
    forged[3][child_index][1] += 1
    _reseal_branch(forged, child_index)
    _assert_code("BRANCH_TRACE_LIFECYCLE_INVALID", replay_session, forged, material)
