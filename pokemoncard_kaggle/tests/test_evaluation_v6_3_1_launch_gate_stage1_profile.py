from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import struct

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode
import evaluation_v6_3_1.launch_gate_decoder_manifest_v1 as decoder_manifest
import evaluation_v6_3_1.launch_gate_stage1_profile as profile_module
from evaluation_v6_3_1.launch_gate_stage1_packer import END_BR64, EMPTY_PATH_OFFSET, pack_stage1_trailer
from evaluation_v6_3_1.launch_gate_stage1_profile import (
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORIZED,
    LAUNCH_GATE_IMAGE_PROFILE_FIELD_COUNT,
    NO_UPLOAD,
    PRODUCTION_UPLOAD_AUTHORIZED,
    SUPERVISOR_BUILD_PROFILE_FIELD_COUNT,
    ZERO_AUTHORITY,
    LaunchGateImageProfileV1,
    LaunchGateStage1ProfileError,
    SupervisorBuildProfileV1,
    build_launch_gate_image_profile,
    build_supervisor_build_profile,
    validate_restricted_canonical_cbor,
)
from evaluation_v6_3_1.launch_gate_stage1_validation import (
    LaunchGateTrailerValidationResultV1,
    validate_launch_gate_trailer_v1,
)


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")


def _page_and_decoder_output(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, bytes]:
    page = bytearray(b"\xcc" * 4096)
    page[-1] = 0
    rows: list[list[object]] = []

    page[0:4] = b"\xf3\x0f\x1e\xfa"
    rows.append([0, 4, 1, [0, [], [], [], 0, 0, 0, 1048672, bytes(page[0:4])]])

    mov = b"\x48\x89\xc0"
    offset = 4
    for _ in range(289):
        page[offset : offset + 3] = mov
        rows.append([offset, 3, 2, [0, [[0, 1, 2], [0, 1, 1]], [], [], 0, 0, 0, 67, mov]])
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
    raw_page = bytes(page)
    digest = sha256(raw_page).digest()
    monkeypatch.setattr(decoder_manifest, "GATE_PAGE_SHA256", digest)
    monkeypatch.setattr(profile_module, "PINNED_GATE_PAGE_SHA256", digest)
    output = decoder_manifest.encode_canonical_cbor_v1(
        [631302, 1, digest, 874, rows, [[0, 4, [873]], [873, 3, []]]]
    )
    return raw_page, output


def _base_elf() -> bytes:
    raw = bytearray(0x1903)
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)
    raw[: ELF_HEADER.size] = ELF_HEADER.pack(
        ident,
        3,
        62,
        1,
        0x1100,
        ELF_HEADER.size,
        0,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        2,
        0,
        0,
        0,
    )
    PROGRAM_HEADER.pack_into(raw, ELF_HEADER.size, 1, 4, 0, 0, 0, 0x1000, 0x1000, 0x1000)
    PROGRAM_HEADER.pack_into(
        raw,
        ELF_HEADER.size + PROGRAM_HEADER.size,
        1,
        5,
        0x1000,
        0x1000,
        0x1000,
        0x800,
        0x800,
        0x1000,
    )
    return bytes(raw)


def _validated_trailer(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[LaunchGateTrailerValidationResultV1, bytes, bytes, bytes, bytes, bytes]:
    base = _base_elf()
    page, decoder_output = _page_and_decoder_output(monkeypatch)
    packed = pack_stage1_trailer(base, page, 874)
    validated = validate_launch_gate_trailer_v1(
        base,
        packed.final_image,
        page,
        gate_code_size=874,
    )
    assert validated.valid
    program_headers = base[ELF_HEADER.size : ELF_HEADER.size + 2 * PROGRAM_HEADER.size]
    return (
        validated,
        base,
        program_headers,
        page,
        packed.final_image,
        decoder_output,
    )


def _image_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[LaunchGateImageProfileV1, bytes, bytes, bytes, bytes, bytes]:
    trailer, base, program_headers, page, final_image, decoder_output = _validated_trailer(monkeypatch)
    agreement = decoder_manifest.compare_launch_gate_decoder_outputs_v1(
        page,
        decoder_output,
        decoder_output,
    )
    assert agreement.valid and agreement.first is not None
    assert agreement.first.instruction_manifest_bytes is not None
    assert agreement.first.cfg_manifest_bytes is not None
    profile = build_launch_gate_image_profile(
        validated_trailer=trailer,
        base_elf=base,
        gate_page=page,
        final_image=final_image,
        decoder_agreement=agreement,
    )
    return (
        profile,
        base,
        page,
        final_image,
        agreement.first.instruction_manifest_bytes,
        agreement.first.cfg_manifest_bytes,
    )


def test_image_profile_is_exact_19_field_canonical_array_with_raw_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile, _base, _page, _final, instruction_manifest, cfg_manifest = _image_profile(monkeypatch)

    assert len(profile.as_array()) == LAUNCH_GATE_IMAGE_PROFILE_FIELD_COUNT == 19
    assert profile.as_array()[15] == sha256(instruction_manifest).digest()
    assert profile.as_array()[16] == sha256(cfg_manifest).digest()
    encoded = profile.canonical_cbor()
    assert LaunchGateImageProfileV1.from_canonical_cbor(encoded) == profile
    assert profile.sha256() == sha256(encoded).digest()
    assert all(len(value) == 32 for value in (profile.as_array()[5], profile.as_array()[7], *profile.as_array()[13:17], profile.as_array()[18]))


def test_build_profile_is_literal_section4_14_field_canonical_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image, base, page, final_image, _instruction, _cfg = _image_profile(monkeypatch)
    manifests = [canonical_cbor_encode([[index, b"manifest"]]) for index in range(6)]
    gate_object = b"relocation-free-object"
    monkeypatch.setattr(profile_module, "PINNED_GATE_OBJECT_SIZE", len(gate_object))
    monkeypatch.setattr(profile_module, "PINNED_GATE_OBJECT_SHA256", sha256(gate_object).digest())
    profile = build_supervisor_build_profile(
        toolchain_manifest_cbor=manifests[0],
        source_manifest_cbor=manifests[1],
        build_command_manifest_cbor=manifests[2],
        build_environment_manifest_cbor=manifests[3],
        ordered_link_input_manifest_cbor=manifests[4],
        validator_manifest_cbor=manifests[5],
        launch_gate_source=b".text.launch_gate_v1",
        launch_gate_object=gate_object,
        launch_gate_page=page,
        supervisor_base=base,
        final_supervisor_image=final_image,
        launch_gate_image_profile=image,
    )

    # The Section-4 literal array is 14 fields despite an external request
    # calling it 16 fields; adding data would alter the frozen wire format.
    assert len(profile.as_array()) == SUPERVISOR_BUILD_PROFILE_FIELD_COUNT == 14
    assert SupervisorBuildProfileV1.from_canonical_cbor(profile.canonical_cbor()) == profile
    assert profile.launch_gate_image_profile_sha256 == image.sha256()


@pytest.mark.parametrize(
    "value",
    [
        {b"map": 1},
        ["text"],
        [-1],
        [True],
        [1.0],
        b"not-cbor",
    ],
)
def test_restricted_cbor_rejects_forbidden_values(value: object) -> None:
    # The shared canonical encoder refuses floats itself.  Feed a raw
    # definite-length half-float array so this layer proves its own rejection.
    raw = b"\x81\xf9\x3c\x00" if value == [1.0] else (value if type(value) is bytes else canonical_cbor_encode(value))
    with pytest.raises(LaunchGateStage1ProfileError):
        validate_restricted_canonical_cbor(raw, label="manifest")


def test_image_profile_rejects_unvalidated_or_mismatched_trailer_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trailer, base, program_headers, page, final_image, decoder_output = _validated_trailer(monkeypatch)
    agreement = decoder_manifest.compare_launch_gate_decoder_outputs_v1(page, decoder_output, decoder_output)
    assert agreement.valid
    invalid = LaunchGateTrailerValidationResultV1(
        valid=False, scope="fixture", issues=(), evidence=trailer.evidence
    )
    with pytest.raises(LaunchGateStage1ProfileError, match="PROFILE_TRAILER_NOT_VALIDATED"):
        build_launch_gate_image_profile(
            validated_trailer=invalid,
            base_elf=base,
            gate_page=page,
            final_image=final_image,
            decoder_agreement=agreement,
        )
    with pytest.raises(LaunchGateStage1ProfileError, match="PROFILE_BASE_EVIDENCE_MISMATCH"):
        build_launch_gate_image_profile(
            validated_trailer=trailer,
            base_elf=base + b"x",
            gate_page=page,
            final_image=final_image,
            decoder_agreement=agreement,
        )

    assert trailer.evidence is not None
    forged_evidence = replace(
        trailer.evidence,
        base_program_header_table_sha256=b"\x00" * 32,
    )
    forged = replace(trailer, evidence=forged_evidence)
    with pytest.raises(LaunchGateStage1ProfileError, match="PROFILE_PROGRAM_HEADER_EVIDENCE_MISMATCH"):
        build_launch_gate_image_profile(
            validated_trailer=forged,
            base_elf=base,
            gate_page=page,
            final_image=final_image,
            decoder_agreement=agreement,
        )


def test_profile_decoders_fail_closed_on_counts_constants_and_hash_widths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image, _base, _page, _final, _instruction, _cfg = _image_profile(monkeypatch)
    fields = image.as_array()
    for mutation in (
        fields[:-1],
        [631303, *fields[1:]],
        [*fields[:2], 63, *fields[3:]],
        [*fields[:5], b"short", *fields[6:]],
        [*fields[:12], 4094, *fields[13:]],
    ):
        with pytest.raises(LaunchGateStage1ProfileError):
            LaunchGateImageProfileV1.from_canonical_cbor(canonical_cbor_encode(mutation))


def test_profile_builder_rebinds_artifacts_and_has_no_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image, base, page, final_image, _instruction, _cfg = _image_profile(monkeypatch)
    manifest = canonical_cbor_encode([])
    gate_object = b"object"
    monkeypatch.setattr(profile_module, "PINNED_GATE_OBJECT_SIZE", len(gate_object))
    monkeypatch.setattr(profile_module, "PINNED_GATE_OBJECT_SHA256", sha256(gate_object).digest())
    with pytest.raises(LaunchGateStage1ProfileError, match="PROFILE_BUILD_FINAL_MISMATCH"):
        build_supervisor_build_profile(
            toolchain_manifest_cbor=manifest,
            source_manifest_cbor=manifest,
            build_command_manifest_cbor=manifest,
            build_environment_manifest_cbor=manifest,
            ordered_link_input_manifest_cbor=manifest,
            validator_manifest_cbor=manifest,
            launch_gate_source=b"source",
            launch_gate_object=gate_object,
            launch_gate_page=page,
            supervisor_base=base,
            final_supervisor_image=final_image[:-1] + b"x",
            launch_gate_image_profile=image,
        )
    assert ZERO_AUTHORITY is True
    assert AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORIZED is False
    assert PRODUCTION_UPLOAD_AUTHORIZED is False
    assert NO_UPLOAD == "NO_UPLOAD"


def test_corrected_profile_pins_are_exact_and_exclude_rewritten_object() -> None:
    assert profile_module.PINNED_GATE_CODE_SIZE == 874
    assert profile_module.PINNED_GATE_OBJECT_SIZE == 8688
    assert profile_module.PINNED_GATE_OBJECT_SHA256.hex() == (
        "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
    )
    assert profile_module.PINNED_GATE_OBJECT_SHA256.hex() != (
        "03415b9a358835c76fe310017486bdc0e1ecb430945858583c2ada1398448e9c"
    )
    assert profile_module.PINNED_GATE_PAGE_SHA256.hex() == (
        "91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"
    )
