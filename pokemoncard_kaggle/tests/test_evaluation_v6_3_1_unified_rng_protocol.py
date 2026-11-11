from __future__ import annotations

from dataclasses import FrozenInstanceError
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation_v6_3_1.unified_rng_protocol import (
    AUTHORITY,
    BASE_BINDING_SPEC_SHA256,
    BINDING_SPEC_SHA256,
    CanonicalCborTruncated,
    EVENT_AMENDMENT_SPEC_SHA256,
    PROTOCOL_VERSION,
    RunBinding,
    ZERO_ID,
    UnifiedRngProtocolError,
    ascii_label,
    build_run_binding,
    build_seed_commitment,
    build_seed_reveal,
    canonical_cbor_decode,
    canonical_cbor_decode_prefix,
    canonical_cbor_encode,
    decode_run_binding,
    decode_seed_commitment,
    decode_seed_reveal,
    derive_authoritative_raw_value,
    derive_branch_raw_value,
    derive_evaluator_secret,
    derive_match_id,
    derive_schedule_seed,
    derive_share_commitment,
    derive_stream_id,
    derive_stream_key,
    run_binding_root,
    seed_commitment_root,
    seed_reveal_root,
    verify_run_binding,
    verify_seed_reveal,
    zero_authority_report,
)


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def test_binding_spec_bytes_are_frozen() -> None:
    base_spec = (
        Path(__file__).resolve().parents[1]
        / "strategy"
        / "evaluation_v6_3_1_sol_unified_rng_protocol_20260721.md"
    )
    amendment_spec = (
        Path(__file__).resolve().parents[1]
        / "strategy"
        / "evaluation_v6_3_1_sol_event_amendment_1_20260721.md"
    )
    assert sha256(base_spec.read_bytes()).hexdigest() == BASE_BINDING_SPEC_SHA256
    assert sha256(amendment_spec.read_bytes()).hexdigest() == EVENT_AMENDMENT_SPEC_SHA256
    assert BINDING_SPEC_SHA256 == EVENT_AMENDMENT_SPEC_SHA256


ROOTS = [_root(label) for label in ("campaign", "model", "engine", "schedule", "archive-a", "archive-b", "rules", "catalog", "deck-a", "deck-b", "manifest")]
CAMPAIGN, MODEL, ENGINE, SCHEDULE, ARCHIVE_A, ARCHIVE_B, RULES, CATALOG, DECK_A, DECK_B, MANIFEST = ROOTS
NONCE_A, NONCE_B = _root("nonce-a"), _root("nonce-b")
SHARE_A, SHARE_B = _root("share-a"), _root("share-b")


def _commitment():
    return build_seed_commitment(
        CAMPAIGN, MODEL, ENGINE, SCHEDULE,
        derive_share_commitment(CAMPAIGN, SCHEDULE, NONCE_A, SHARE_A),
        derive_share_commitment(CAMPAIGN, SCHEDULE, NONCE_B, SHARE_B),
        NONCE_A, NONCE_B,
    )


def test_strict_array_cbor_golden_vectors_and_rejection() -> None:
    assert canonical_cbor_encode([0, 23, 24, 255, 256, 65536, 2**64 - 1, b"x", []]) == bytes.fromhex(
        "890017181818ff1901001a000100001bffffffffffffffff417880"
    )
    assert canonical_cbor_decode(bytes.fromhex("82018102")) == [1, [2]]
    for raw in (b"\xa0", b"\x65hello", b"\xc0\x80", b"\xfb\x00\x00\x00\x00\x00\x00\x00\x00", b"\x9f\x80\xff", b"\x18\x17", b"\x81\x01\x00"):
        with pytest.raises(UnifiedRngProtocolError) as raised:
            canonical_cbor_decode(raw)
        assert raised.value.code in {"RNG_CANONICAL_CBOR_MISMATCH", "RNG_TEXT_OR_NFC_POLICY_VIOLATION"}
    with pytest.raises(UnifiedRngProtocolError):
        canonical_cbor_encode({1: 2})
    with pytest.raises(UnifiedRngProtocolError):
        canonical_cbor_encode(True)


def test_prefix_decoder_walks_exact_concatenation_and_identifies_truncation() -> None:
    first = canonical_cbor_encode([1, [2]])
    second = canonical_cbor_encode([b"three"])
    trace = first + second
    value, offset = canonical_cbor_decode_prefix(trace)
    assert value == [1, [2]]
    assert offset == len(first)
    value, offset = canonical_cbor_decode_prefix(trace, offset)
    assert value == [b"three"]
    assert offset == len(trace)
    with pytest.raises(UnifiedRngProtocolError):
        canonical_cbor_decode(trace)
    with pytest.raises(CanonicalCborTruncated):
        canonical_cbor_decode_prefix(first[:-1])


def test_widths_types_and_ascii_labels_fail_closed() -> None:
    with pytest.raises(UnifiedRngProtocolError):
        ascii_label("TEXT")
    with pytest.raises(UnifiedRngProtocolError):
        ascii_label(b"cafe\xcc\x81")
    with pytest.raises(UnifiedRngProtocolError):
        build_seed_commitment(b"short", *ROOTS[1:4], *ROOTS[4:6], NONCE_A, NONCE_B)
    with pytest.raises(UnifiedRngProtocolError):
        build_run_binding(_root("seed-root"), SCHEDULE, True, ARCHIVE_A, ARCHIVE_B, 0, ENGINE, RULES, CATALOG, DECK_A, DECK_B, MANIFEST)
    with pytest.raises(UnifiedRngProtocolError):
        derive_schedule_seed(_root("secret"), SCHEDULE, 2**32)


def test_seed_commitment_reveal_and_exact_golden_roots() -> None:
    commitment = _commitment()
    assert commitment.to_bytes().hex() == (
        "8a1a0009a2060158203dc260b2472062d9c57bd930b02f23831d917b8f3e3234b6d63964a53c31d3aa58209372c470eeadd5ecd9c3c74c2b3cb633f8e2f2fad799250a0f70d652b6b825e45820ed9f6f25068608efd412958da4dfc19328ca3511251fa6d5f9c42baf230e32f858205f72005e81c4ecbd5aa3588e80e3daf0df068ce0cf5638944508a0165fea609a58202a71285beb4e7da28034af623611d267b61ad3204abbede32194fc94a45b68f85820ecefd9ff3c1371ae55f96e0701f23211391ead31ab3be0355da66d416ed95a285820e0f5d528756fc4ff08935427ad65df76e4ebb9acd1f3057048fc2441c76a22965820f77bc5bbeb582a896437512e59599ec85ddf5c8c1902aa3ae10dfa0bb2d6d54c"
    )
    assert seed_commitment_root(commitment).hex() == "6da6c1f426bd2ad37015c8ee049b055a19e38eb22c9541bf1de4cb8ee94bcc28"
    panel_close = _root("panel-close")
    reveal_manifest = _root("reveal-manifest")
    reveal = build_seed_reveal(seed_commitment_root(commitment), panel_close, SHARE_A, SHARE_B, reveal_manifest)
    assert reveal.to_bytes().hex() == (
        "871a0009a2060d58206da6c1f426bd2ad37015c8ee049b055a19e38eb22c9541bf1de4cb8ee94bcc2858204ec1c088d38a889e25f940546e3bbfc6724859eef0ce71860c8930bd7b9345f858203c6874d11e6e9fb715f5969dbdaccf82f158f11c556ba0a8d744e92fc6f7c48358208c098714bc14df68724ae5b409df7b5a94fbaacf43f8eb2390d8f77099f299b158205054f118795c1dda1372abd1377aeea3bf6870b725db97f97297d41ed49fac35"
    )
    assert seed_reveal_root(reveal).hex() == "a1dcb02f8e9332a49a8c27dfe8049a6fdf3e2957aa1fba7fc8e79c5717134f9d"
    assert verify_seed_reveal(
        reveal,
        commitment,
        expected_panel_execution_close_root=panel_close,
        expected_reveal_manifest_root=reveal_manifest,
    ) == derive_evaluator_secret(seed_commitment_root(commitment), SHARE_A, SHARE_B)
    forged = build_seed_reveal(reveal.seed_commitment_root, reveal.panel_execution_close_root, _root("wrong"), SHARE_B, reveal.reveal_manifest_root)
    with pytest.raises(UnifiedRngProtocolError) as raised:
        verify_seed_reveal(
            forged,
            commitment,
            expected_panel_execution_close_root=panel_close,
            expected_reveal_manifest_root=reveal_manifest,
        )
    assert raised.value.code == "RNG_SECRET_COMMITMENT_MISMATCH"
    for expected_close, expected_manifest in (
        (_root("wrong-close"), reveal_manifest),
        (panel_close, _root("wrong-manifest")),
    ):
        with pytest.raises(UnifiedRngProtocolError) as raised:
            verify_seed_reveal(
                reveal,
                commitment,
                expected_panel_execution_close_root=expected_close,
                expected_reveal_manifest_root=expected_manifest,
            )
        assert raised.value.code == "RNG_SECRET_COMMITMENT_MISMATCH"


def test_run_binding_match_id_and_golden_root() -> None:
    commitment_root = seed_commitment_root(_commitment())
    binding = build_run_binding(commitment_root, SCHEDULE, 17, ARCHIVE_A, ARCHIVE_B, 0, ENGINE, RULES, CATALOG, DECK_A, DECK_B, MANIFEST)
    assert binding.match_id == derive_match_id(SCHEDULE, 17, ARCHIVE_A, ARCHIVE_B, 0)
    assert run_binding_root(binding).hex() == "04a0d85f9ed88c50809272b1936c264840d0113ff8eb1706d33aca50a91c189b"
    assert verify_run_binding(binding, _commitment()) == run_binding_root(binding)
    swapped = build_run_binding(commitment_root, SCHEDULE, 17, ARCHIVE_A, ARCHIVE_B, 1, ENGINE, RULES, CATALOG, DECK_A, DECK_B, MANIFEST)
    assert swapped.match_id != binding.match_id
    with pytest.raises(UnifiedRngProtocolError) as raised:
        RunBinding(
            binding.seed_commitment_root,
            binding.panel_schedule_root,
            _root("forged-match-id"),
            binding.common_seed_id,
            binding.candidate_archive_sha256,
            binding.control_archive_sha256,
            binding.candidate_seat,
            binding.engine_binary_sha256,
            binding.ruleset_sha256,
            binding.card_catalog_sha256,
            binding.candidate_deck_root,
            binding.control_deck_root,
            binding.run_manifest_root,
        )
    assert raised.value.code == "RNG_RUN_BINDING_MISMATCH"
    wrong_schedule_binding = build_run_binding(
        commitment_root,
        _root("wrong-schedule"),
        17,
        ARCHIVE_A,
        ARCHIVE_B,
        0,
        ENGINE,
        RULES,
        CATALOG,
        DECK_A,
        DECK_B,
        MANIFEST,
    )
    with pytest.raises(UnifiedRngProtocolError) as raised:
        verify_run_binding(wrong_schedule_binding, _commitment())
    assert raised.value.code == "RNG_RUN_BINDING_MISMATCH"


def test_schedule_and_raw_kdf_are_candidate_seat_and_run_neutral() -> None:
    commitment = _commitment()
    close_root = _root("close")
    reveal_manifest = _root("manifest")
    secret = verify_seed_reveal(
        build_seed_reveal(seed_commitment_root(commitment), close_root, SHARE_A, SHARE_B, reveal_manifest),
        commitment,
        expected_panel_execution_close_root=close_root,
        expected_reveal_manifest_root=reveal_manifest,
    )
    schedule_seed = derive_schedule_seed(secret, SCHEDULE, 17)
    assert schedule_seed.hex() == "212b1a4d1b09ebe4926ee6ed58ff100196cb5570ce1203c48f0ad2ac8abcc9df"
    stream_key = derive_stream_key(schedule_seed, _root("site"), _root("object"), 7, 3)
    assert stream_key.hex() == "3ef0ea56137f0260cc0c510fc49cb6faf3527fbf03a4c1f18ab00bc7a3b2803d"
    assert derive_stream_id(_root("session-a"), _root("site"), _root("object"), 7, 3).hex() == "efe647a030f83efdb9549c4c3aff5398a4313e4da52c5c3ae783419d662098d2"
    assert derive_authoritative_raw_value(stream_key, 0) == 0x3672716795E5BB88
    assert derive_authoritative_raw_value(stream_key, 1) == 0x2609BBC0EEB97270
    branch = _root("branch")
    assert derive_branch_raw_value(stream_key, branch, 0) == 0xEAC5C01DE290B7E1
    assert derive_branch_raw_value(stream_key, branch, 0) != derive_authoritative_raw_value(stream_key, 0)
    for seat, candidate, control in ((0, ARCHIVE_A, ARCHIVE_B), (1, ARCHIVE_B, ARCHIVE_A)):
        other = build_run_binding(seed_commitment_root(commitment), SCHEDULE, 17, candidate, control, seat, ENGINE, RULES, CATALOG, DECK_A, DECK_B, MANIFEST)
        assert derive_schedule_seed(secret, other.panel_schedule_root, other.common_seed_id) == schedule_seed
        assert derive_authoritative_raw_value(stream_key, 0) == 0x3672716795E5BB88
    with pytest.raises(UnifiedRngProtocolError):
        derive_branch_raw_value(stream_key, ZERO_ID, 0)


def test_public_reports_are_immutable_and_have_no_authority() -> None:
    report = zero_authority_report("OFFLINE_CONFORMANCE_ONLY", "local proof boundary")
    assert report.authority == AUTHORITY
    assert report.as_dict()["production_upload_authorized"] is False
    assert report.as_dict()["publication_timing_authenticated"] is False
    assert report.as_dict()["permits"] == ()
    with pytest.raises(FrozenInstanceError):
        report.detail = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        report.as_dict()["authority"] = "AUTHORIZED"  # type: ignore[index]
    assert PROTOCOL_VERSION == 631302


def test_all_top_level_record_decoders_reject_retired_631301() -> None:
    commitment = _commitment()
    binding = build_run_binding(
        seed_commitment_root(commitment),
        SCHEDULE,
        17,
        ARCHIVE_A,
        ARCHIVE_B,
        0,
        ENGINE,
        RULES,
        CATALOG,
        DECK_A,
        DECK_B,
        MANIFEST,
    )
    reveal = build_seed_reveal(
        seed_commitment_root(commitment),
        _root("panel-close"),
        SHARE_A,
        SHARE_B,
        _root("reveal-manifest"),
    )
    for decoder, record in (
        (decode_seed_commitment, commitment.as_array()),
        (decode_run_binding, binding.as_array()),
        (decode_seed_reveal, reveal.as_array()),
    ):
        record[0] = 631301
        with pytest.raises(UnifiedRngProtocolError) as raised:
            decoder(record)
        assert raised.value.code == "RNG_PROTOCOL_631301_RETIRED"
