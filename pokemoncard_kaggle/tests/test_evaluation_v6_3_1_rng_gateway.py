from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from itertools import product
from math import factorial

import pytest

from evaluation_v6_3_1.rng_gateway import (
    BOUNDED_SAMPLING_ALGORITHM_ID,
    BoundedSampleEvidence,
    DeterministicRngGateway,
    RNG_BOUNDED_SAMPLE,
    RNG_DRAW,
    RNG_STREAM_BOUND,
    RawDrawEvidence,
    RAW_DRAW_DOMAIN,
    RngGatewayError,
    SHUFFLE_APPLIED,
    STREAM_COIN,
    STREAM_AGENT_ENTROPY_PLAYER_0,
    STREAM_SETUP,
    STREAM_SHUFFLE,
    SeedMaterial,
    ShuffleEvidence,
    SourceSite,
    StreamBinding,
    build_rng_coverage_manifest,
    validate_rng_coverage_manifest,
    validate_trace_rng_payload,
)
from evaluation_v6_3_1.rng_seed_protocol import derive_evaluator_secret_commitment


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _seed() -> SeedMaterial:
    protocol = _root("protocol")
    model = _root("model")
    population = _root("population")
    secret = _root("evaluator-secret")
    return SeedMaterial(
        protocol,
        model,
        population,
        _root("candidate"),
        _root("control"),
        42,
        1,
        secret,
        derive_evaluator_secret_commitment(secret, protocol, model, population, 42),
    )


def _site(source_root: bytes) -> SourceSite:
    return SourceSite(source_root, "engine/Game.cpp", "game.random-choice", _root("game.random-choice-site"))


def _gateway() -> tuple[DeterministicRngGateway, SourceSite]:
    source_root = _root("opened-source")
    site = _site(source_root)
    return DeterministicRngGateway(_seed(), source_root, (site,)), site


def _assert_code(code: str, func, *args, **kwargs) -> None:
    with pytest.raises(RngGatewayError) as raised:
        func(*args, **kwargs)
    assert raised.value.code == code


def test_seed_binding_stream_determinism_and_domain_separation() -> None:
    material = _seed()
    assert material.seed_material_root() == material.seed_material_root()

    left, site = _gateway()
    right, _ = _gateway()
    left_setup = left.bind_stream(STREAM_SETUP)
    right_setup = right.bind_stream(STREAM_SETUP)
    assert left_setup == right_setup
    assert left_setup.stream_id != left.bind_stream(STREAM_COIN).stream_id
    assert left_setup.stream_seed_commitment != left.bind_stream(STREAM_COIN).stream_seed_commitment
    draw = left.draw_raw_uint64(STREAM_SETUP, site, 9)
    assert draw == right.draw_raw_uint64(STREAM_SETUP, site, 9)
    stream_seed = material.stream_seed(STREAM_SETUP)
    assert left_setup.stream_seed_commitment == material.stream_seed_commitment(STREAM_SETUP)
    assert left_setup.stream_seed_commitment != stream_seed
    from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode

    assert draw.raw_output_bytes == sha256(
        RAW_DRAW_DOMAIN + canonical_cbor_encode([stream_seed, 0])
    ).digest()[:8]
    assert type(draw.source_site_id) is bytes and len(draw.source_site_id) == 32


def test_reserved_agent_entropy_stream_requires_future_broker() -> None:
    gateway, _ = _gateway()
    _assert_code(
        "RNG_AGENT_STREAM_BROKER_REQUIRED",
        gateway.bind_stream,
        STREAM_AGENT_ENTROPY_PLAYER_0,
    )


def test_raw_draw_counter_gaps_reuse_and_source_site_are_fail_closed() -> None:
    gateway, site = _gateway()
    first = gateway.draw_raw_uint64(STREAM_SETUP, site, 3)
    second = gateway.draw_raw_uint64(STREAM_SETUP, site, 7)
    assert (first.counter_before, first.counter_after, second.counter_before, second.counter_after) == (0, 1, 1, 2)
    _assert_code("RNG_EVENT_SEQUENCE_REUSED", gateway.draw_raw_uint64, STREAM_SETUP, site, 3)

    verifier, _ = _gateway()
    verifier.bind_stream(STREAM_SETUP)
    _assert_code("RNG_COUNTER_GAP", verifier.verify_raw_draw, replace(first, counter_before=1, counter_after=2))
    _assert_code("RNG_RAW_DRAW_MISMATCH", verifier.verify_raw_draw, replace(first, raw_output_bytes=b"\0" * 8))
    outside = SourceSite(_root("other-source"), "engine/Game.cpp", "game.random-choice", _root("outside-site"))
    _assert_code("RNG_SOURCE_SITE_UNCOVERED", gateway.draw_raw_uint64, STREAM_SETUP, outside, 8)


def test_unbiased_bounded_sampling_records_exact_rejection_edge_cases() -> None:
    stream = StreamBinding(STREAM_SETUP, _root("stream"), _root("commit"))
    upper = (1 << 63) + 1
    threshold = (1 << 64) % upper
    rejected = RawDrawEvidence(10, stream.stream_id, 0, (threshold - 1).to_bytes(8, "big"), 1, _root("site"))
    accepted = RawDrawEvidence(11, stream.stream_id, 1, threshold.to_bytes(8, "big"), 2, _root("site"))
    evidence = BoundedSampleEvidence(stream.stream_id, upper, (rejected, accepted))
    assert evidence.rejected_raw_values == (threshold - 1,)
    assert evidence.accepted_raw_value == threshold
    assert evidence.mapped_result == threshold % upper
    assert evidence.trace_payload()[0] == BOUNDED_SAMPLING_ALGORITHM_ID
    assert evidence.trace_payload()[3] == threshold
    assert evidence.trace_payload()[6] == [False, True]

    _assert_code("RNG_REJECTION_ACCOUNTING_MISMATCH", BoundedSampleEvidence, stream.stream_id, upper, (rejected,))
    _assert_code("RNG_TYPE_INVALID", BoundedSampleEvidence, stream.stream_id, True, (accepted,))


def test_rejection_sampling_is_uniform_for_every_small_width_boundary() -> None:
    for bit_width in range(1, 11):
        space = 1 << bit_width
        for upper in range(1, space):
            threshold = space % upper
            counts = [0] * upper
            for raw in range(threshold, space):
                counts[raw % upper] += 1
            assert len(set(counts)) == 1
            assert sum(counts) == space - threshold


@pytest.mark.parametrize(
    "upper",
    [1, 2, 3, (1 << 32) - 1, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, (1 << 64) - 1],
)
def test_uint64_rejection_threshold_and_mapping_edge_vectors(upper: int) -> None:
    threshold = (1 << 64) % upper
    stream = _root("edge-stream")
    site = _root("edge-site")
    draw = RawDrawEvidence(
        0,
        stream,
        0,
        threshold.to_bytes(8, "big"),
        1,
        site,
    )
    evidence = BoundedSampleEvidence(stream, upper, (draw,))
    assert evidence.trace_payload()[3] == threshold
    assert evidence.accepted_raw_value == threshold
    assert evidence.mapped_result == threshold % upper
    assert 0 <= evidence.mapped_result < upper


def test_event_payloads_are_strict_and_replay_compatible() -> None:
    gateway, site = _gateway()
    binding = gateway.bind_stream(STREAM_SETUP)
    draw = gateway.draw_raw_uint64(STREAM_SETUP, site, 3)
    sample = gateway.bounded_sample_from_draws(7, (draw,))
    validate_trace_rng_payload(RNG_STREAM_BOUND, binding.trace_payload())
    validate_trace_rng_payload(RNG_DRAW, draw.trace_payload(), source_site_ids=(site.source_site_id,))
    validate_trace_rng_payload(RNG_BOUNDED_SAMPLE, sample.trace_payload(), draws_by_sequence={draw.event_sequence: draw})

    malformed = draw.trace_payload()
    malformed[2] = True
    _assert_code("RNG_TRACE_PAYLOAD_INVALID", validate_trace_rng_payload, RNG_DRAW, malformed, source_site_ids=(site.source_site_id,))
    bad_bounded = sample.trace_payload()
    bad_bounded[5] = [draw.raw_uint64]
    _assert_code("RNG_REJECTION_ACCOUNTING_MISMATCH", validate_trace_rng_payload, RNG_BOUNDED_SAMPLE, bad_bounded, draws_by_sequence={draw.event_sequence: draw})


def test_fisher_yates_permutation_and_draw_evidence_are_exact() -> None:
    gateway, site = _gateway()
    cards = tuple(_root(f"card-{index}") for index in range(4))
    shuffle = gateway.shuffle(_root("shuffle"), "deck.player-0", cards, site, ((20,), (21,), (22,)))
    assert sorted(shuffle.permutation) == list(range(4))
    assert shuffle.output_cards == tuple(cards[index] for index in shuffle.permutation)
    assert shuffle.rng_event_range == [20, 22]
    validate_trace_rng_payload(SHUFFLE_APPLIED, shuffle.trace_payload())
    _assert_code("RNG_SHUFFLE_INVALID", replace, shuffle, permutation=(False, True, 2, 3))

    _assert_code(
        "RNG_SHUFFLE_INVALID",
        gateway.shuffle,
        _root("another-shuffle"),
        "deck.player-0",
        cards,
        site,
        ((30,), (32,), (33,)),
    )

    for size in (0, 1):
        no_op_cards = tuple(_root(f"no-op-{index}") for index in range(size))
        no_op = gateway.shuffle(
            _root(f"no-op-shuffle-{size}"),
            "deck.player-0",
            no_op_cards,
            site,
            (),
        )
        assert no_op.permutation == tuple(range(size))
        assert no_op.output_cards == no_op_cards
        assert no_op.rng_event_range == []
        validate_trace_rng_payload(SHUFFLE_APPLIED, no_op.trace_payload())


def test_fisher_yates_exhaustively_covers_every_permutation_through_size_eight() -> None:
    stream = _root("exhaustive-stream")
    site = _root("exhaustive-site")
    for size in range(9):
        cards = tuple(_root(f"exhaustive-card-{index}") for index in range(size))
        observed: set[tuple[int, ...]] = set()
        bounds = tuple(range(size, 1, -1))
        for choices in product(*(range(upper) for upper in bounds)):
            samples: list[BoundedSampleEvidence] = []
            counter = 0
            for upper, choice in zip(bounds, choices):
                threshold = (1 << 64) % upper
                raw = threshold + choice
                draw = RawDrawEvidence(
                    counter,
                    stream,
                    counter,
                    raw.to_bytes(8, "big"),
                    counter + 1,
                    site,
                )
                samples.append(BoundedSampleEvidence(stream, upper, (draw,)))
                counter += 1
            permutation = list(range(size))
            for index, sample in zip(range(size - 1, 0, -1), samples):
                permutation[index], permutation[sample.mapped_result] = (
                    permutation[sample.mapped_result],
                    permutation[index],
                )
            frozen_permutation = tuple(permutation)
            evidence = ShuffleEvidence(
                _root("exhaustive-shuffle"),
                "deck.player-0",
                cards,
                tuple(samples),
                frozen_permutation,
                tuple(cards[index] for index in frozen_permutation),
            )
            validate_trace_rng_payload(SHUFFLE_APPLIED, evidence.trace_payload())
            observed.add(frozen_permutation)
        assert len(observed) == factorial(size)


def test_malformed_evidence_and_bool_as_int_are_rejected() -> None:
    _assert_code("RNG_TYPE_INVALID", RawDrawEvidence, False, _root("stream"), 0, b"\0" * 8, 1, _root("site"))
    _assert_code("RNG_COUNTER_GAP", RawDrawEvidence, 0, _root("stream"), 0, b"\0" * 8, 2, _root("site"))
    _assert_code("RNG_SOURCE_SITE_INVALID", SourceSite, _root("source"), "../Game.cpp", "site", _root("site"))


def test_coverage_manifest_is_explicitly_incomplete_and_zero_authority() -> None:
    source = _root("opened-source")
    sites = (
        SourceSite(source, "engine/Game.cpp", "game.random-choice", _root("game-site")),
        SourceSite(source, "engine/Select.cpp", "select.coin-flip", _root("coin-site")),
    )
    manifest = build_rng_coverage_manifest(source, sites)
    checked = validate_rng_coverage_manifest(manifest, expected_source_root=source)
    assert checked["ast_completeness_claimed"] is False
    assert checked["ir_completeness_claimed"] is False
    assert checked["uncovered_entropy_absence_proven"] is False
    assert checked["authority"] is False
    assert checked["upload_authorized"] is False
    assert checked["permits"] == ()

    mutable = dict(manifest)
    mutable["ast_completeness_claimed"] = True
    _assert_code("RNG_COVERAGE_AUTHORITY_CLAIM", validate_rng_coverage_manifest, mutable)

    gateway, _ = _gateway()
    report = gateway.zero_authority_report()
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["ast_completeness_claimed"] is False
