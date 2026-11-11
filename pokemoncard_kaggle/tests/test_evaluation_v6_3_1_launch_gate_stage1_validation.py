from __future__ import annotations

import struct

import pytest

from evaluation_v6_3_1.launch_gate_stage1_validation import (
    AGENT_MODIFICATION_AUTHORITY,
    AUTHORITY,
    CALIBRATION_UPLOAD_AUTHORITY,
    ENDBR64,
    PAGE_SIZE,
    PRODUCTION_UPLOAD_AUTHORITY,
    UNMET_CFG_PROOF,
    UNMET_DUAL_BUILD,
    UNMET_INSTRUCTION_DECODERS,
    ZERO_AUTHORITY,
    validate_launch_gate_object_v1,
    validate_launch_gate_trailer_v1,
)


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
DYNAMIC = struct.Struct("<qQ")


def _ident() -> bytes:
    return b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + bytes(7)


def _gate_page(code_size: int = 4) -> bytes:
    return ENDBR64 + b"\xcc" * (PAGE_SIZE - 1 - code_size) + b"\x00"


def _base_elf(
    *,
    interpreter: bool = False,
    needed: bool = False,
    needed_after_null: bool = False,
) -> bytes:
    length = 0x1903
    raw = bytearray(length)
    phoff = ELF_HEADER.size
    phnum = 3
    raw[: ELF_HEADER.size] = ELF_HEADER.pack(
        _ident(),
        3,
        62,
        1,
        0x1100,
        phoff,
        0,
        0,
        ELF_HEADER.size,
        PROGRAM_HEADER.size,
        phnum,
        0,
        0,
        0,
    )
    dynamic_size = DYNAMIC.size * (2 if needed_after_null else 1)
    headers = [
        (1, 4, 0, 0, 0, 0x1000, 0x1000, 0x1000),
        (1, 5, 0x1000, 0x1000, 0x1000, 0x800, 0x800, 0x1000),
        (
            3 if interpreter else 2,
            4,
            0x800,
            0x800,
            0x800,
            dynamic_size,
            dynamic_size,
            8,
        ),
    ]
    for index, header in enumerate(headers):
        PROGRAM_HEADER.pack_into(raw, phoff + index * PROGRAM_HEADER.size, *header)
    DYNAMIC.pack_into(raw, 0x800, 1 if needed else 0, 1 if needed else 0)
    if needed_after_null:
        DYNAMIC.pack_into(raw, 0x800 + DYNAMIC.size, 1, 1)
    return bytes(raw)


def _pack(base: bytes, gate: bytes) -> bytes:
    offset = (len(base) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
    return base + b"\x00" * (offset - len(base)) + gate


def _issue(result) -> str:
    assert result.issues
    return result.issues[0].code


def _object(gate: bytes, *, weak_gate: bool = False) -> bytes:
    section_names = (
        b"\x00.text\x00.text.launch_gate_v1\x00.note.GNU-stack\x00.symtab\x00.strtab\x00.shstrtab\x00"
    )
    section_name_offsets = {
        b".text": section_names.index(b".text"),
        b".text.launch_gate_v1": section_names.index(b".text.launch_gate_v1"),
        b".note.GNU-stack": section_names.index(b".note.GNU-stack"),
        b".symtab": section_names.index(b".symtab"),
        b".strtab": section_names.index(b".strtab"),
        b".shstrtab": section_names.index(b".shstrtab"),
    }
    symbol_names = b"\x00launch_gate_v1\x00"
    gate_offset = PAGE_SIZE
    symtab_offset = gate_offset + PAGE_SIZE
    symbols = b"".join(
        (
            SYMBOL.pack(0, 0, 0, 0, 0, 0),
            SYMBOL.pack(0, 3, 0, 2, 0, 0),
            SYMBOL.pack(1, (2 if weak_gate else 1) << 4 | 2, 0, 2, 0, 4),
        )
    )
    strtab_offset = symtab_offset + len(symbols)
    shstrtab_offset = strtab_offset + len(symbol_names)
    shoff = (shstrtab_offset + len(section_names) + 7) & ~7
    shnum = 7
    raw = bytearray(shoff + shnum * SECTION_HEADER.size)
    raw[: ELF_HEADER.size] = ELF_HEADER.pack(
        _ident(),
        1,
        62,
        1,
        0,
        0,
        shoff,
        0,
        ELF_HEADER.size,
        0,
        0,
        SECTION_HEADER.size,
        shnum,
        6,
    )
    raw[gate_offset : gate_offset + PAGE_SIZE] = gate
    raw[symtab_offset : symtab_offset + len(symbols)] = symbols
    raw[strtab_offset : strtab_offset + len(symbol_names)] = symbol_names
    raw[shstrtab_offset : shstrtab_offset + len(section_names)] = section_names

    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (
            section_name_offsets[b".text"],
            1,
            0x6,
            0,
            0x40,
            0,
            0,
            0,
            4,
            0,
        ),
        (
            section_name_offsets[b".text.launch_gate_v1"],
            1,
            0x6,
            0,
            gate_offset,
            PAGE_SIZE,
            0,
            0,
            PAGE_SIZE,
            0,
        ),
        (
            section_name_offsets[b".note.GNU-stack"],
            1,
            0,
            0,
            gate_offset + PAGE_SIZE,
            0,
            0,
            0,
            1,
            0,
        ),
        (
            section_name_offsets[b".symtab"],
            2,
            0,
            0,
            symtab_offset,
            len(symbols),
            5,
            2,
            8,
            SYMBOL.size,
        ),
        (
            section_name_offsets[b".strtab"],
            3,
            0,
            0,
            strtab_offset,
            len(symbol_names),
            0,
            0,
            1,
            0,
        ),
        (
            section_name_offsets[b".shstrtab"],
            3,
            0,
            0,
            shstrtab_offset,
            len(section_names),
            0,
            0,
            1,
            0,
        ),
    )
    for index, section in enumerate(sections):
        SECTION_HEADER.pack_into(raw, shoff + index * SECTION_HEADER.size, *section)
    return bytes(raw)


def test_trailer_validation_proves_only_static_byte_layout() -> None:
    base = _base_elf()
    gate = _gate_page()
    result = validate_launch_gate_trailer_v1(base, _pack(base, gate), gate, gate_code_size=4)

    assert result.valid
    assert result.evidence is not None
    assert result.evidence.base_length == len(base)
    assert result.evidence.gate_file_offset == 0x2000
    assert result.evidence.final_length == 0x3000
    assert result.evidence.base_e_entry == 0x1100
    assert result.unmet_checks == (
        UNMET_INSTRUCTION_DECODERS,
        UNMET_CFG_PROOF,
        UNMET_DUAL_BUILD,
    )
    assert not result.instruction_decoders_proven
    assert not result.cfg_proven
    assert not result.dual_build_proven
    assert not result.authority
    assert not result.calibration_upload_authority
    assert not result.production_upload_authority


def test_module_authority_is_hard_false() -> None:
    assert ZERO_AUTHORITY is True
    assert AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert AGENT_MODIFICATION_AUTHORITY is False


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("prefix", "TRAILER_BASE_PREFIX_CHANGED"),
        ("padding", "TRAILER_ALIGNMENT_PADDING_INVALID"),
        ("gate", "TRAILER_GATE_PAGE_MISMATCH"),
        ("trailing", "TRAILER_FINAL_LENGTH_INVALID"),
    ],
)
def test_trailer_mutations_fail_closed(mutation: str, expected: str) -> None:
    base = _base_elf()
    gate = _gate_page()
    final = bytearray(_pack(base, gate))
    if mutation == "prefix":
        final[0x1000] ^= 1
    elif mutation == "padding":
        final[len(base)] = 1
    elif mutation == "gate":
        final[0x2000 + 4] ^= 1
    else:
        final.append(0)
    result = validate_launch_gate_trailer_v1(base, bytes(final), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == expected


@pytest.mark.parametrize(
    ("gate", "code_size", "expected"),
    [
        (b"x" * PAGE_SIZE, 4, "GATE_CET_ENTRY_INVALID"),
        (ENDBR64 + b"\x90" + b"\xcc" * (PAGE_SIZE - 6) + b"\x00", 4, "GATE_PADDING_INVALID"),
        (ENDBR64 + b"\xcc" * (PAGE_SIZE - 4), 4, "GATE_EMPTY_PATH_INVALID"),
        (_gate_page(), PAGE_SIZE, "GATE_CODE_SIZE_INVALID"),
    ],
)
def test_gate_page_profile_mutations_fail_closed(gate: bytes, code_size: int, expected: str) -> None:
    base = _base_elf()
    result = validate_launch_gate_trailer_v1(
        base,
        _pack(base, gate),
        gate,
        gate_code_size=code_size,
    )
    assert not result.valid
    assert _issue(result) == expected


def test_interpreter_and_needed_dependency_fail_closed() -> None:
    gate = _gate_page()
    interp = _base_elf(interpreter=True)
    result = validate_launch_gate_trailer_v1(interp, _pack(interp, gate), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "ELF_INTERPRETER_PRESENT"

    needed = _base_elf(needed=True)
    result = validate_launch_gate_trailer_v1(needed, _pack(needed, gate), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "ELF_DYNAMIC_DEPENDENCY"

    hidden_needed = _base_elf(needed_after_null=True)
    result = validate_launch_gate_trailer_v1(
        hidden_needed,
        _pack(hidden_needed, gate),
        gate,
        gate_code_size=4,
    )
    assert not result.valid
    assert _issue(result) == "ELF_DYNAMIC_DEPENDENCY"


def test_gate_object_exact_section_and_symbol_profile() -> None:
    gate = _gate_page()
    result = validate_launch_gate_object_v1(_object(gate), gate, gate_code_size=4)
    assert result.valid
    assert result.evidence is not None
    assert result.evidence.gate_section_index == 2
    assert result.evidence.gate_symbol_index == 2
    assert result.unmet_checks == (
        UNMET_INSTRUCTION_DECODERS,
        UNMET_CFG_PROOF,
        UNMET_DUAL_BUILD,
    )
    assert not result.authority


def test_gate_object_rejects_weak_gate_symbol() -> None:
    gate = _gate_page()
    result = validate_launch_gate_object_v1(_object(gate, weak_gate=True), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_FORBIDDEN_SYMBOL"


@pytest.mark.parametrize("visibility", [1, 2, 3])
def test_gate_object_rejects_nondefault_gate_symbol_visibility(visibility: int) -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    symtab = SECTION_HEADER.unpack_from(raw, shoff + 4 * SECTION_HEADER.size)
    gate_symbol_offset = symtab[4] + 2 * SYMBOL.size
    gate_symbol = list(SYMBOL.unpack_from(raw, gate_symbol_offset))
    gate_symbol[2] = visibility
    SYMBOL.pack_into(raw, gate_symbol_offset, *gate_symbol)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_GLOBAL_SYMBOL_INVALID"


def test_gate_object_rejects_relocation_section() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    note = list(SECTION_HEADER.unpack_from(raw, shoff + 3 * SECTION_HEADER.size))
    note[1] = 4
    SECTION_HEADER.pack_into(raw, shoff + 3 * SECTION_HEADER.size, *note)
    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_RELOCATION_PRESENT"


def test_gate_object_rejects_extra_allocated_section() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    note = list(SECTION_HEADER.unpack_from(raw, shoff + 3 * SECTION_HEADER.size))
    note[2] = 0x2
    SECTION_HEADER.pack_into(raw, shoff + 3 * SECTION_HEADER.size, *note)
    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EXTRA_ALLOCATED_SECTION"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (1, 8),
        (2, 0x7),
        (3, 1),
        (4, 0x41),
        (5, 1),
        (6, 1),
        (7, 1),
        (8, 8),
        (9, 1),
    ],
)
def test_gate_object_rejects_each_empty_text_tuple_mutation(field: int, value: int) -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    empty_text = list(SECTION_HEADER.unpack_from(raw, shoff + SECTION_HEADER.size))
    empty_text[field] = value
    SECTION_HEADER.pack_into(raw, shoff + SECTION_HEADER.size, *empty_text)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_TUPLE_INVALID"


def test_gate_object_rejects_renamed_or_duplicate_empty_text() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    empty_text = list(SECTION_HEADER.unpack_from(raw, shoff + SECTION_HEADER.size))
    empty_text[0] = 0
    SECTION_HEADER.pack_into(raw, shoff + SECTION_HEADER.size, *empty_text)
    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_NOT_UNIQUE"

    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    note = list(SECTION_HEADER.unpack_from(raw, shoff + 3 * SECTION_HEADER.size))
    text_name_offset = SECTION_HEADER.unpack_from(raw, shoff + SECTION_HEADER.size)[0]
    note[0] = text_name_offset
    SECTION_HEADER.pack_into(raw, shoff + 3 * SECTION_HEADER.size, *note)
    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)
    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_NOT_UNIQUE"


def test_gate_object_rejects_nonsection_symbol_defined_in_empty_text() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    symtab = SECTION_HEADER.unpack_from(raw, shoff + 4 * SECTION_HEADER.size)
    symbol_offset = symtab[4] + SYMBOL.size
    symbol = list(SYMBOL.unpack_from(raw, symbol_offset))
    symbol[1] = 0
    symbol[3] = 1
    SYMBOL.pack_into(raw, symbol_offset, *symbol)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_SYMBOL_INVALID"


def test_gate_object_accepts_at_most_one_exact_empty_text_section_symbol() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    symtab = SECTION_HEADER.unpack_from(raw, shoff + 4 * SECTION_HEADER.size)
    symbol_offset = symtab[4] + SYMBOL.size
    symbol = list(SYMBOL.unpack_from(raw, symbol_offset))
    symbol[3] = 1
    SYMBOL.pack_into(raw, symbol_offset, *symbol)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert result.valid


def test_gate_object_rejects_empty_text_group_membership() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    raw[0x80:0x88] = struct.pack("<II", 1, 1)
    note = list(SECTION_HEADER.unpack_from(raw, shoff + 3 * SECTION_HEADER.size))
    note[1] = 17
    note[4] = 0x80
    note[5] = 8
    note[6] = 4
    note[7] = 2
    note[8] = 4
    note[9] = 4
    SECTION_HEADER.pack_into(raw, shoff + 3 * SECTION_HEADER.size, *note)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_GROUP_MEMBER"


def test_gate_object_rejects_nonempty_section_owning_empty_text_offset() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    note = list(SECTION_HEADER.unpack_from(raw, shoff + 3 * SECTION_HEADER.size))
    note[4] = 0x40
    note[5] = 1
    SECTION_HEADER.pack_into(raw, shoff + 3 * SECTION_HEADER.size, *note)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_EMPTY_TEXT_OFFSET_OVERLAP"


def test_gate_object_rejects_overlapping_nonempty_section_ranges() -> None:
    gate = _gate_page()
    raw = bytearray(_object(gate))
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    symtab = SECTION_HEADER.unpack_from(raw, shoff + 4 * SECTION_HEADER.size)
    strtab = list(SECTION_HEADER.unpack_from(raw, shoff + 5 * SECTION_HEADER.size))
    strtab[4] = symtab[4] + 1
    SECTION_HEADER.pack_into(raw, shoff + 5 * SECTION_HEADER.size, *strtab)

    result = validate_launch_gate_object_v1(bytes(raw), gate, gate_code_size=4)

    assert not result.valid
    assert _issue(result) == "GATE_OBJECT_FILE_RANGE_OVERLAP"
