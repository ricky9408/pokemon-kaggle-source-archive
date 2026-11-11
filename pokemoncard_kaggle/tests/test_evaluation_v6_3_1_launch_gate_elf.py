from __future__ import annotations

import hashlib
import struct

import pytest

from evaluation_v6_3_1.launch_gate_elf import (
    DT_NEEDED,
    PT_DYNAMIC,
    PT_INTERP,
    PT_LOAD,
    UNMET_CONTROL_FLOW,
    UNMET_DISASSEMBLY,
    UNMET_RELOCATION,
    validate_launch_gate_elf,
)


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
DYNAMIC_ENTRY = struct.Struct("<qQ")
PHOFF = 64
PHNUM = 5
TARGET_OFFSET = 0x1000
TARGET_LENGTH = 0x1000
ENTRY_OFFSET = 0x40
NORMAL_EXECUTABLE_OFFSET = 0x2000
WRITABLE_OFFSET = 0x3000
DYNAMIC_OFFSET = 0x3F00
IMAGE_LENGTH = 0x4000


def _valid_image() -> bytes:
    image = bytearray(IMAGE_LENGTH)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    image[:64] = ELF_HEADER.pack(
        ident,
        3,
        62,
        1,
        NORMAL_EXECUTABLE_OFFSET + 0x100,
        PHOFF,
        0,
        0,
        64,
        56,
        PHNUM,
        0,
        0,
        0,
    )
    headers = (
        (PT_LOAD, 4, 0x0000, 0x0000, 0x0000, 0x1000, 0x1000, 0x1000),
        (PT_LOAD, 5, TARGET_OFFSET, TARGET_OFFSET, TARGET_OFFSET, TARGET_LENGTH, TARGET_LENGTH, 0x1000),
        (PT_LOAD, 5, NORMAL_EXECUTABLE_OFFSET, NORMAL_EXECUTABLE_OFFSET, NORMAL_EXECUTABLE_OFFSET, 0x1000, 0x1000, 0x1000),
        (PT_LOAD, 6, WRITABLE_OFFSET, WRITABLE_OFFSET, WRITABLE_OFFSET, 0x1000, 0x1000, 0x1000),
        (PT_DYNAMIC, 4, DYNAMIC_OFFSET, DYNAMIC_OFFSET, DYNAMIC_OFFSET, DYNAMIC_ENTRY.size, DYNAMIC_ENTRY.size, 8),
    )
    for index, header in enumerate(headers):
        start = PHOFF + index * PROGRAM_HEADER.size
        image[start : start + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(*header)
    image[TARGET_OFFSET:TARGET_OFFSET + TARGET_LENGTH] = bytes(range(256)) * 16
    image[NORMAL_EXECUTABLE_OFFSET:NORMAL_EXECUTABLE_OFFSET + 0x1000] = b"N" * 0x1000
    DYNAMIC_ENTRY.pack_into(image, DYNAMIC_OFFSET, 0, 0)
    return bytes(image)


def _profile(image: bytes) -> dict[str, object]:
    return {
        "file_offset": TARGET_OFFSET,
        "mapping_length": TARGET_LENGTH,
        "entry_offset": ENTRY_OFFSET,
        "expected_gate_sha256": hashlib.sha256(image[TARGET_OFFSET:TARGET_OFFSET + TARGET_LENGTH]).hexdigest(),
    }


def _minimal_profile() -> dict[str, object]:
    return {
        "file_offset": 0,
        "mapping_length": 1,
        "entry_offset": 0,
        "expected_gate_sha256": "0" * 64,
    }


def _mutate_header(image: bytes, index: int, **changes: int) -> bytes:
    mutated = bytearray(image)
    start = PHOFF + index * PROGRAM_HEADER.size
    values = list(PROGRAM_HEADER.unpack_from(mutated, start))
    fields = {
        "p_type": 0,
        "p_flags": 1,
        "p_offset": 2,
        "p_vaddr": 3,
        "p_paddr": 4,
        "p_filesz": 5,
        "p_memsz": 6,
        "p_align": 7,
    }
    for name, value in changes.items():
        values[fields[name]] = value
    mutated[start : start + PROGRAM_HEADER.size] = PROGRAM_HEADER.pack(*values)
    return bytes(mutated)


def _issue_codes(result) -> set[str]:
    return {issue.code for issue in result.issues}


def test_exact_gate_profile_separates_gate_entry_from_elf_entry() -> None:
    image = _valid_image()
    result = validate_launch_gate_elf(image, **_profile(image))

    assert result.verified
    assert result.scope == "ELF_STRUCTURAL_BYTES_ONLY"
    assert result.issues == ()
    assert result.file_size == len(image)
    assert result.file_offset == TARGET_OFFSET
    assert result.mapping_length == TARGET_LENGTH
    assert result.entry_offset == ENTRY_OFFSET
    assert result.gate_entry_address == TARGET_OFFSET + ENTRY_OFFSET
    assert result.gate_segment is not None
    assert result.gate_segment.p_offset == TARGET_OFFSET
    assert result.elf_entry == NORMAL_EXECUTABLE_OFFSET + 0x100
    assert result.elf_entry_segment is not None
    assert result.elf_entry_segment.p_offset == NORMAL_EXECUTABLE_OFFSET
    expected_digest = hashlib.sha256(image[TARGET_OFFSET:0x2000]).hexdigest()
    assert result.expected_gate_sha256 == expected_digest
    assert result.gate_sha256 == expected_digest
    assert result.unmet_checks == (
        UNMET_DISASSEMBLY,
        UNMET_RELOCATION,
        UNMET_CONTROL_FLOW,
    )
    assert not result.disassembly_proven
    assert not result.relocation_safety_proven
    assert not result.control_flow_proven
    assert not hasattr(result, "upload_authority")
    assert not hasattr(result, "campaign_authority")


def test_separate_non_overlapping_rx_load_is_allowed() -> None:
    image = _valid_image()
    result = validate_launch_gate_elf(image, **_profile(image))
    assert result.verified
    assert result.elf_entry_segment is not None
    assert result.elf_entry_segment.p_flags == 5
    assert result.elf_entry_segment.index != result.gate_segment.index


@pytest.mark.parametrize(
    ("mutated", "expected"),
    [
        (b"short", "ELF_TRUNCATED_HEADER"),
        (b"not-an-elf" + bytes(100), "ELF_BAD_MAGIC"),
    ],
)
def test_truncated_and_bad_magic_inputs_fail_closed(mutated: bytes, expected: str) -> None:
    result = validate_launch_gate_elf(mutated, **_minimal_profile())
    assert not result.verified
    assert expected in _issue_codes(result)


def test_program_header_table_overlapping_elf_header_is_rejected() -> None:
    image = bytearray(_valid_image())
    struct.pack_into("<Q", image, 32, 32)
    result = validate_launch_gate_elf(image, **_profile(bytes(image)))
    assert not result.verified
    assert "ELF_PROGRAM_HEADER_OFFSET" in _issue_codes(result)


def test_section_header_table_overlapping_program_headers_is_rejected() -> None:
    image = bytearray(_valid_image())
    struct.pack_into("<Q", image, 40, 128)
    struct.pack_into("<HHH", image, 58, 64, 1, 0)
    result = validate_launch_gate_elf(image, **_profile(bytes(image)))
    assert not result.verified
    assert "ELF_HEADER_OVERLAP" in _issue_codes(result)


@pytest.mark.parametrize(
    ("mutated", "expected"),
    [
        (_mutate_header(_valid_image(), 1, p_align=2048), "ELF_GATE_PAGE_ALIGNMENT"),
        (_mutate_header(_valid_image(), 1, p_memsz=0x1001), "ELF_GATE_SIZE_PROFILE"),
        (_mutate_header(_valid_image(), 2, p_offset=TARGET_OFFSET), "ELF_GATE_LOAD_NOT_UNIQUE"),
        (_mutate_header(_valid_image(), 1, p_offset=0x1100), "ELF_LOAD_ALIGNMENT_INVALID"),
    ],
)
def test_gate_segment_mutations_fail_closed(mutated: bytes, expected: str) -> None:
    result = validate_launch_gate_elf(mutated, **_profile(_valid_image()))
    assert not result.verified
    assert expected in _issue_codes(result)


def test_gate_entry_offset_is_not_elf_entry_and_must_be_in_mapping() -> None:
    image = _valid_image()
    result = validate_launch_gate_elf(
        image,
        file_offset=TARGET_OFFSET,
        mapping_length=TARGET_LENGTH,
        entry_offset=TARGET_LENGTH,
        expected_gate_sha256=_profile(image)["expected_gate_sha256"],
    )
    assert not result.verified
    assert "ELF_GATE_ENTRY_OFFSET_INVALID" in _issue_codes(result)


@pytest.mark.parametrize(
    ("elf_entry", "expected"),
    [
        (TARGET_OFFSET + ENTRY_OFFSET, "ELF_ENTRY_IN_GATE"),
        (WRITABLE_OFFSET + 0x100, "ELF_ENTRY_EXECUTABLE_MAPPING"),
    ],
)
def test_elf_entry_must_be_in_different_executable_load(elf_entry: int, expected: str) -> None:
    image = bytearray(_valid_image())
    struct.pack_into("<Q", image, 24, elf_entry)
    result = validate_launch_gate_elf(bytes(image), **_profile(bytes(image)))
    assert not result.verified
    assert expected in _issue_codes(result)


def test_dynamic_table_without_dt_needed_is_allowed() -> None:
    result = validate_launch_gate_elf(_valid_image(), **_profile(_valid_image()))
    assert result.verified


def test_dt_needed_is_rejected_but_dynamic_metadata_is_parsed() -> None:
    image = bytearray(_valid_image())
    DYNAMIC_ENTRY.pack_into(image, DYNAMIC_OFFSET, DT_NEEDED, 1)
    result = validate_launch_gate_elf(bytes(image), **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_DYNAMIC_DEPENDENCY" in _issue_codes(result)


def test_unterminated_or_misaligned_dynamic_table_is_rejected() -> None:
    image = bytearray(_valid_image())
    DYNAMIC_ENTRY.pack_into(image, DYNAMIC_OFFSET, 0x6FFFFFFB, 0)
    result = validate_launch_gate_elf(bytes(image), **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_DYNAMIC_UNTERMINATED" in _issue_codes(result)

    malformed = _mutate_header(_valid_image(), 4, p_filesz=8, p_memsz=8)
    result = validate_launch_gate_elf(malformed, **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_DYNAMIC_TABLE_INVALID" in _issue_codes(result)


def test_interpreter_is_rejected() -> None:
    mutated = _mutate_header(_valid_image(), 4, p_type=PT_INTERP)
    result = validate_launch_gate_elf(mutated, **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_INTERPRETER_PRESENT" in _issue_codes(result)


def test_writable_load_overlap_is_rejected() -> None:
    mutated = _mutate_header(_valid_image(), 3, p_offset=TARGET_OFFSET)
    result = validate_launch_gate_elf(mutated, **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_GATE_WRITABLE_OVERLAP" in _issue_codes(result)


def test_writable_virtual_overlap_is_rejected() -> None:
    mutated = _mutate_header(
        _valid_image(),
        3,
        p_vaddr=TARGET_OFFSET,
        p_paddr=TARGET_OFFSET,
    )
    result = validate_launch_gate_elf(mutated, **_profile(_valid_image()))
    assert not result.verified
    assert "ELF_GATE_WRITABLE_OVERLAP" in _issue_codes(result)


def test_gate_mapping_length_must_cover_complete_pages() -> None:
    image = _mutate_header(
        _valid_image(),
        1,
        p_filesz=TARGET_LENGTH - 1,
        p_memsz=TARGET_LENGTH - 1,
    )
    profile = {
        "file_offset": TARGET_OFFSET,
        "mapping_length": TARGET_LENGTH - 1,
        "entry_offset": ENTRY_OFFSET,
        "expected_gate_sha256": hashlib.sha256(
            image[TARGET_OFFSET : TARGET_OFFSET + TARGET_LENGTH - 1]
        ).hexdigest(),
    }
    result = validate_launch_gate_elf(image, **profile)
    assert not result.verified
    assert "ELF_GATE_PAGE_ALIGNMENT" in _issue_codes(result)


def test_elf_entry_must_be_file_backed() -> None:
    image = _mutate_header(
        _valid_image(),
        2,
        p_filesz=0x100,
        p_memsz=0x1000,
    )
    mutated = bytearray(image)
    struct.pack_into("<Q", mutated, 24, NORMAL_EXECUTABLE_OFFSET + 0x100)
    result = validate_launch_gate_elf(bytes(mutated), **_profile(bytes(mutated)))
    assert not result.verified
    assert "ELF_ENTRY_EXECUTABLE_MAPPING" in _issue_codes(result)


def test_exact_range_and_expected_digest_are_required() -> None:
    image = _valid_image()
    subrange = validate_launch_gate_elf(
        image,
        file_offset=TARGET_OFFSET + 0x100,
        mapping_length=0x20,
        entry_offset=0,
        expected_gate_sha256=_profile(image)["expected_gate_sha256"],
    )
    assert not subrange.verified
    assert "ELF_GATE_LOAD_NOT_UNIQUE" in _issue_codes(subrange)

    mutated = bytearray(image)
    mutated[TARGET_OFFSET + 1] ^= 1
    digest = validate_launch_gate_elf(mutated, **_profile(image))
    assert not digest.verified
    assert "ELF_GATE_DIGEST_MISMATCH" in _issue_codes(digest)


def test_expected_digest_must_be_canonical_hex() -> None:
    result = validate_launch_gate_elf(
        _valid_image(),
        file_offset=TARGET_OFFSET,
        mapping_length=TARGET_LENGTH,
        entry_offset=ENTRY_OFFSET,
        expected_gate_sha256="not-a-digest",
    )
    assert not result.verified
    assert "ELF_EXPECTED_DIGEST_INVALID" in _issue_codes(result)
