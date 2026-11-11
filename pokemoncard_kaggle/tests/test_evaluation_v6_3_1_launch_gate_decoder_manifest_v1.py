from __future__ import annotations

from hashlib import sha256

import pytest

import evaluation_v6_3_1.launch_gate_decoder_manifest_v1 as manifest


def _fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, bytes]:
    """Build a complete synthetic byte fixture without invoking an x86 decoder."""

    page = bytearray(b"\x00" * manifest.GATE_PAGE_SIZE)
    rows: list[list[object]] = []

    page[0:4] = b"\xf3\x0f\x1e\xfa"
    rows.append([0, 4, 1, [0, [], [], [], 0, 0, 0, 1048672, bytes(page[0:4])]])

    mov = b"\x48\x89\xc0"
    offset = 4
    for _ in range(289):
        page[offset : offset + 3] = mov
        rows.append(
            [
                offset,
                3,
                2,
                [0, [[0, 1, 2], [0, 1, 1]], [], [], 0, 0, 0, 67, mov],
            ]
        )
        offset += 3

    page[offset : offset + 2] = b"\x0f\x05"
    rows.append(
        [
            offset,
            2,
            9,
            [
                0,
                [],
                [[0, 1, 1], [0, 8, 1], [0, 7, 1], [0, 3, 1], [0, 11, 1], [0, 9, 1], [0, 10, 1]],
                [[0, 1, 2], [0, 2, 4], [0, 12, 4]],
                0,
                0,
                63,
                1048576,
                b"\x0f\x05",
            ],
        ]
    )
    offset += 2

    page[offset] = 0xC3
    rows.append(
        [
            offset,
            1,
            10,
            [
                0,
                [],
                [[0, 5, 1], [3, 1, 64, 64, 5, 0, 1, 0, 0, -1, 5, 0]],
                [[0, 5, 2], [0, 17, 2]],
                0,
                0,
                0,
                0,
                b"\xc3",
            ],
        ]
    )
    assert offset == 873

    cfg = [[0, 4, [873]], [873, 3, []]]
    wrapper = [manifest.PROTOCOL_ID, manifest.WIRE_VERSION, b"placeholder", 874, rows, cfg]
    page_digest = sha256(bytes(page)).digest()
    wrapper[2] = page_digest
    monkeypatch.setattr(manifest, "GATE_PAGE_SHA256", page_digest)
    return bytes(page), manifest.encode_canonical_cbor_v1(wrapper)


def test_positive_fixture_validates_and_derives_standalone_hashes(monkeypatch: pytest.MonkeyPatch) -> None:
    page, output = _fixture(monkeypatch)

    result = manifest.validate_launch_gate_decoder_manifest_v1(page, output)

    assert result.valid
    assert result.wrapper_bytes == output
    assert result.instruction_manifest_sha256 == sha256(result.instruction_manifest_bytes).digest()
    assert result.cfg_manifest_sha256 == sha256(result.cfg_manifest_bytes).digest()
    assert result.authority is False
    assert result.calibration_upload_authority is False
    assert result.production_upload_authority is False
    assert result.sealed_holdout_access_authority is False
    assert result.agent_modification_authority is False
    assert result.zero_authority is True


def test_agreement_requires_exact_file_bytes_without_normalization(monkeypatch: pytest.MonkeyPatch) -> None:
    page, output = _fixture(monkeypatch)
    agreement = manifest.compare_launch_gate_decoder_outputs_v1(page, output, output + b"\x00")

    assert not agreement.valid
    assert agreement.issues[0].code == manifest.OUTPUT_BYTE_MISMATCH
    assert agreement.authority is False


def test_identical_completed_outputs_produce_only_diagnostic_agreement(monkeypatch: pytest.MonkeyPatch) -> None:
    page, output = _fixture(monkeypatch)
    agreement = manifest.compare_launch_gate_decoder_outputs_v1(page, output, output)

    assert agreement.valid
    assert agreement.first is not None and agreement.second is not None
    assert agreement.first.wrapper_bytes == agreement.second.wrapper_bytes == output
    assert agreement.production_upload_authority is False
    assert agreement.zero_authority is True


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda value: value.__setitem__(0, 631303), manifest.WRAPPER_INVALID),
        (lambda value: value[4][1].__setitem__(2, 11), manifest.INSTRUCTION_INVALID),
        (lambda value: value[4][1].__setitem__(2, 0), manifest.INSTRUCTION_INVALID),
    ],
)
def test_representative_wrapper_and_opcode_mutations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutate,
    expected: str,
) -> None:
    page, output = _fixture(monkeypatch)
    value = manifest.decode_canonical_cbor_v1(output)
    mutate(value)
    mutated = manifest.encode_canonical_cbor_v1(value)
    result = manifest.validate_launch_gate_decoder_manifest_v1(page, mutated)

    assert not result.valid
    assert result.issues[0].code == expected


def test_raw_page_slice_and_cfg_order_mutations_fail_even_with_fresh_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    page, output = _fixture(monkeypatch)
    value = manifest.decode_canonical_cbor_v1(output)
    value[4][1][3][8] = b"\x90\x89\xc0"
    mutated = manifest.encode_canonical_cbor_v1(value)
    result = manifest.validate_launch_gate_decoder_manifest_v1(page, mutated)
    assert not result.valid
    assert result.issues[0].code == manifest.RAW_BYTES_INVALID

    value = manifest.decode_canonical_cbor_v1(output)
    value[5][0][2] = [872]
    mutated = manifest.encode_canonical_cbor_v1(value)
    result = manifest.validate_launch_gate_decoder_manifest_v1(page, mutated)
    assert not result.valid
    assert result.issues[0].code == manifest.CFG_INVALID


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value[4][1][3].__setitem__(7, value[4][1][3][7] & ~(1 << 6)),
        lambda value: value[4][1][3].__setitem__(7, value[4][1][3][7] | (1 << 7)),
        lambda value: value[4][1][3].__setitem__(7, value[4][1][3][7] | (1 << 16)),
    ],
)
def test_modrm_sib_and_destination_zero_extension_mutations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutate,
) -> None:
    page, output = _fixture(monkeypatch)
    value = manifest.decode_canonical_cbor_v1(output)
    mutate(value)
    mutated = manifest.encode_canonical_cbor_v1(value)

    result = manifest.validate_launch_gate_decoder_manifest_v1(page, mutated)

    assert not result.valid
    assert result.issues[0].code == manifest.ATTRIBUTE_INVALID


@pytest.mark.parametrize("provenance", [0, 6])
def test_unknown_provenance_ids_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    provenance: int,
) -> None:
    page, output = _fixture(monkeypatch)
    value = manifest.decode_canonical_cbor_v1(output)
    value[4][-1][3][2][1][10] = provenance
    mutated = manifest.encode_canonical_cbor_v1(value)

    result = manifest.validate_launch_gate_decoder_manifest_v1(page, mutated)

    assert not result.valid
    assert result.issues[0].code == manifest.OPERAND_INVALID


def test_cbor_profile_rejects_maps_text_booleans_and_nonminimal_lengths() -> None:
    for raw in (b"\xa0", b"\x61a", b"\xf5", b"\x81\x18\x00", b"\x9f\x00\xff"):
        with pytest.raises(manifest.LaunchGateDecoderManifestError):
            manifest.decode_canonical_cbor_v1(raw)


def test_standalone_encoder_does_not_accept_tuple_or_textual_hashes() -> None:
    with pytest.raises(manifest.LaunchGateDecoderManifestError):
        manifest.encode_canonical_cbor_v1((1,))
    with pytest.raises(manifest.LaunchGateDecoderManifestError):
        manifest.encode_canonical_cbor_v1([manifest.PROTOCOL_ID, "91fce3"])
