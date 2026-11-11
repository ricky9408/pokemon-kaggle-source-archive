"""Offline Stage-1 validation for the authenticated LaunchGateV1 trailer.

This module implements the byte-level ELF and relocatable-object portions of
``V631302_STAGE1_AUTHENTICATED_TRAILER_LAUNCH_GATE_FREEZE_1`` as narrowly
amended by ``V631302_STAGE1_EMPTY_TEXT_AND_LLVM16_TOOLING_ERRATUM_1``.  It
deliberately does not decode x86 instructions, construct a control-flow graph,
execute the gate, issue a permit, or represent campaign authority.

The append-only packer lives in a different module and shares no ELF parsing
code with this validator.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Final


PROTOCOL_ID: Final = 631302
PAGE_SIZE: Final = 4096
ENDBR64: Final = b"\xf3\x0f\x1e\xfa"

ZERO_AUTHORITY: Final = True
AUTHORITY: Final = False
CALIBRATION_UPLOAD_AUTHORITY: Final = False
PRODUCTION_UPLOAD_AUTHORITY: Final = False
AGENT_MODIFICATION_AUTHORITY: Final = False

ELFCLASS64: Final = 2
ELFDATA2LSB: Final = 1
EV_CURRENT: Final = 1
ET_REL: Final = 1
ET_DYN: Final = 3
EM_X86_64: Final = 62

PT_LOAD: Final = 1
PT_DYNAMIC: Final = 2
PT_INTERP: Final = 3
PF_X: Final = 1

DT_NULL: Final = 0
DT_NEEDED: Final = 1

SHT_NULL: Final = 0
SHT_PROGBITS: Final = 1
SHT_SYMTAB: Final = 2
SHT_STRTAB: Final = 3
SHT_RELA: Final = 4
SHT_NOBITS: Final = 8
SHT_REL: Final = 9
SHT_DYNSYM: Final = 11
SHT_GROUP: Final = 17

SHF_WRITE: Final = 0x1
SHF_ALLOC: Final = 0x2
SHF_EXECINSTR: Final = 0x4
SHF_INFO_LINK: Final = 0x40
SHF_LINK_ORDER: Final = 0x80
SHF_GROUP: Final = 0x200
SHF_TLS: Final = 0x400

STB_LOCAL: Final = 0
STB_GLOBAL: Final = 1
STB_WEAK: Final = 2
STT_NOTYPE: Final = 0
STT_OBJECT: Final = 1
STT_FUNC: Final = 2
STT_SECTION: Final = 3
STT_FILE: Final = 4
STT_TLS: Final = 6
STT_GNU_IFUNC: Final = 10
STV_DEFAULT: Final = 0

SHN_UNDEF: Final = 0
SHN_LORESERVE: Final = 0xFF00
SHN_ABS: Final = 0xFFF1
SHN_COMMON: Final = 0xFFF2
SHN_XINDEX: Final = 0xFFFF

_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
_SYMBOL = struct.Struct("<IBBHQQ")
_DYNAMIC = struct.Struct("<qQ")
_GROUP_WORD = struct.Struct("<I")
_MAX_U64 = (1 << 64) - 1
_MAX_DYNAMIC_BYTES = 1 << 20

STATIC_LAYOUT_SCOPE: Final = "STAGE1_TRAILER_ELF_AND_OBJECT_BYTES_ONLY"
UNMET_INSTRUCTION_DECODERS: Final = "TWO_INDEPENDENT_X86_DECODERS_NOT_PROVEN"
UNMET_CFG_PROOF: Final = "SYSCALL_AND_CONTROL_FLOW_PROOF_NOT_PROVEN"
UNMET_DUAL_BUILD: Final = "DUAL_BUILD_REPRODUCIBILITY_NOT_PROVEN"
UNMET_CHECKS: Final = (
    UNMET_INSTRUCTION_DECODERS,
    UNMET_CFG_PROOF,
    UNMET_DUAL_BUILD,
)


class LaunchGateStage1ValidationError(ValueError):
    """One fail-closed Stage-1 validation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class LaunchGateStage1Issue:
    code: str
    message: str


@dataclass(frozen=True)
class ProgramHeaderV1:
    index: int
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_align: int

    @property
    def file_end(self) -> int:
        return self.p_offset + self.p_filesz

    @property
    def memory_end(self) -> int:
        return self.p_vaddr + self.p_memsz


@dataclass(frozen=True)
class SectionHeaderV1:
    index: int
    name_offset: int
    sh_type: int
    sh_flags: int
    sh_addr: int
    sh_offset: int
    sh_size: int
    sh_link: int
    sh_info: int
    sh_addralign: int
    sh_entsize: int
    name: bytes = b""

    @property
    def file_end(self) -> int:
        return self.sh_offset + self.sh_size


@dataclass(frozen=True)
class ParsedELF64V1:
    raw: bytes
    e_type: int
    e_machine: int
    e_entry: int
    e_phoff: int
    e_phentsize: int
    e_phnum: int
    e_shoff: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int
    elf_header_bytes: bytes
    program_header_bytes: bytes
    program_headers: tuple[ProgramHeaderV1, ...]
    section_headers: tuple[SectionHeaderV1, ...]


@dataclass(frozen=True)
class LaunchGateTrailerEvidenceV1:
    base_length: int
    base_sha256: bytes
    base_e_entry: int
    base_program_header_table_sha256: bytes
    gate_file_offset: int
    gate_code_size: int
    gate_code_sha256: bytes
    gate_page_sha256: bytes
    final_length: int
    final_sha256: bytes
    executable_entry_segment_index: int


@dataclass(frozen=True)
class LaunchGateTrailerValidationResultV1:
    valid: bool
    scope: str
    issues: tuple[LaunchGateStage1Issue, ...]
    unmet_checks: tuple[str, ...] = UNMET_CHECKS
    evidence: LaunchGateTrailerEvidenceV1 | None = None
    instruction_decoders_proven: bool = False
    cfg_proven: bool = False
    dual_build_proven: bool = False
    authority: bool = False
    calibration_upload_authority: bool = False
    production_upload_authority: bool = False


@dataclass(frozen=True)
class LaunchGateObjectEvidenceV1:
    object_sha256: bytes
    gate_page_sha256: bytes
    gate_code_size: int
    gate_section_index: int
    gate_symbol_index: int


@dataclass(frozen=True)
class LaunchGateObjectValidationResultV1:
    valid: bool
    scope: str
    issues: tuple[LaunchGateStage1Issue, ...]
    unmet_checks: tuple[str, ...] = UNMET_CHECKS
    evidence: LaunchGateObjectEvidenceV1 | None = None
    authority: bool = False
    calibration_upload_authority: bool = False
    production_upload_authority: bool = False


def _fail(code: str, message: str) -> None:
    raise LaunchGateStage1ValidationError(code, message)


def _bytes(value: object, label: str) -> bytes:
    if type(value) is bytes:
        return value
    if isinstance(value, (bytearray, memoryview)):
        try:
            return bytes(value)
        except (BufferError, TypeError, ValueError) as exc:
            _fail("STAGE1_INPUT_INVALID", f"{label} is not a readable byte buffer: {exc}")
    _fail("STAGE1_INPUT_INVALID", f"{label} must be bytes-like")


def _checked_end(offset: int, length: int, limit: int, label: str) -> int:
    if type(offset) is not int or type(length) is not int:
        _fail("ELF_INTEGER_INVALID", f"{label} is not integer-valued")
    if offset < 0 or length < 0 or offset > _MAX_U64 or length > _MAX_U64:
        _fail("ELF_INTEGER_INVALID", f"{label} is outside uint64")
    if offset > _MAX_U64 - length:
        _fail("ELF_INTEGER_OVERFLOW", f"{label} overflows uint64")
    end = offset + length
    if end > limit:
        _fail("ELF_RANGE_TRUNCATED", f"{label} exceeds the containing byte string")
    return end


def _align_up(value: int, alignment: int) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        _fail("STAGE1_ALIGNMENT_INVALID", "alignment request is invalid")
    remainder = value % alignment
    return value if remainder == 0 else value + alignment - remainder


def _read_c_string(table: bytes, offset: int, label: str) -> bytes:
    if offset < 0 or offset >= len(table):
        _fail("ELF_STRING_OFFSET_INVALID", f"{label} offset is outside its string table")
    end = table.find(b"\x00", offset)
    if end < 0:
        _fail("ELF_STRING_UNTERMINATED", f"{label} lacks a terminating NUL")
    return table[offset:end]


def _parse_elf64(raw: bytes, *, expected_type: int) -> ParsedELF64V1:
    if len(raw) < _ELF_HEADER.size:
        _fail("ELF_HEADER_TRUNCATED", "ELF header is truncated")
    fields = _ELF_HEADER.unpack_from(raw, 0)
    ident = fields[0]
    if ident[:4] != b"\x7fELF":
        _fail("ELF_MAGIC_INVALID", "ELF magic is invalid")
    if ident[4] != ELFCLASS64 or ident[5] != ELFDATA2LSB:
        _fail("ELF_IDENTITY_INVALID", "ELF must be 64-bit little-endian")
    if ident[6] != EV_CURRENT or fields[3] != EV_CURRENT:
        _fail("ELF_VERSION_INVALID", "ELF version is not current")

    (
        _ident,
        e_type,
        e_machine,
        _version,
        e_entry,
        e_phoff,
        e_shoff,
        _flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = fields
    if e_type != expected_type:
        _fail("ELF_TYPE_INVALID", f"ELF type {e_type} does not match {expected_type}")
    if e_machine != EM_X86_64:
        _fail("ELF_MACHINE_INVALID", "ELF machine is not EM_X86_64")
    if e_ehsize != _ELF_HEADER.size:
        _fail("ELF_HEADER_SIZE_INVALID", "ELF header size is not 64 bytes")

    if e_phnum == SHN_XINDEX:
        _fail("ELF_EXTENDED_INDEX_UNSUPPORTED", "extended program-header count is forbidden")
    if e_phnum:
        if e_phentsize != _PROGRAM_HEADER.size or e_phoff < _ELF_HEADER.size or e_phoff % 8:
            _fail("ELF_PROGRAM_HEADER_INVALID", "program-header table metadata is invalid")
        ph_end = _checked_end(
            e_phoff,
            e_phnum * e_phentsize,
            len(raw),
            "program-header table",
        )
        ph_bytes = raw[e_phoff:ph_end]
    else:
        if e_phoff != 0 or e_phentsize != 0:
            _fail("ELF_PROGRAM_HEADER_INVALID", "empty program-header metadata is inconsistent")
        ph_bytes = b""

    if e_shoff == 0:
        if e_shnum != 0 or e_shentsize != 0 or e_shstrndx != 0:
            _fail("ELF_SECTION_HEADER_INVALID", "empty section-header metadata is inconsistent")
        section_headers: tuple[SectionHeaderV1, ...] = ()
    else:
        if (
            e_shnum == 0
            or e_shnum == SHN_XINDEX
            or e_shentsize != _SECTION_HEADER.size
            or e_shoff % 8
        ):
            _fail("ELF_SECTION_HEADER_INVALID", "section-header table metadata is invalid")
        _checked_end(e_shoff, e_shnum * e_shentsize, len(raw), "section-header table")
        if e_shstrndx == SHN_XINDEX or e_shstrndx >= e_shnum:
            _fail("ELF_SECTION_NAME_INDEX_INVALID", "section-name table index is invalid")
        parsed_sections: list[SectionHeaderV1] = []
        for index in range(e_shnum):
            values = _SECTION_HEADER.unpack_from(raw, e_shoff + index * e_shentsize)
            parsed_sections.append(SectionHeaderV1(index, *values))
        names_header = parsed_sections[e_shstrndx]
        if names_header.sh_type != SHT_STRTAB:
            _fail("ELF_SECTION_NAME_TABLE_INVALID", "section-name table is not SHT_STRTAB")
        names_end = _checked_end(
            names_header.sh_offset,
            names_header.sh_size,
            len(raw),
            "section-name table",
        )
        names = raw[names_header.sh_offset:names_end]
        section_headers = tuple(
            SectionHeaderV1(
                section.index,
                section.name_offset,
                section.sh_type,
                section.sh_flags,
                section.sh_addr,
                section.sh_offset,
                section.sh_size,
                section.sh_link,
                section.sh_info,
                section.sh_addralign,
                section.sh_entsize,
                _read_c_string(names, section.name_offset, f"section {section.index} name"),
            )
            for section in parsed_sections
        )

    program_headers: list[ProgramHeaderV1] = []
    for index in range(e_phnum):
        values = _PROGRAM_HEADER.unpack_from(raw, e_phoff + index * e_phentsize)
        header = ProgramHeaderV1(index, *values)
        _checked_end(header.p_offset, header.p_filesz, len(raw), f"program header {index}")
        if header.p_memsz < header.p_filesz:
            _fail("ELF_PROGRAM_MEMORY_SIZE_INVALID", f"program header {index} has memsz < filesz")
        if header.p_vaddr > _MAX_U64 - header.p_memsz:
            _fail("ELF_PROGRAM_MEMORY_OVERFLOW", f"program header {index} memory range overflows")
        if header.p_align not in (0, 1):
            if header.p_align & (header.p_align - 1):
                _fail("ELF_PROGRAM_ALIGNMENT_INVALID", f"program header {index} alignment is invalid")
            if header.p_offset % header.p_align != header.p_vaddr % header.p_align:
                _fail("ELF_PROGRAM_ALIGNMENT_INVALID", f"program header {index} offset/address mismatch")
        program_headers.append(header)

    return ParsedELF64V1(
        raw=raw,
        e_type=e_type,
        e_machine=e_machine,
        e_entry=e_entry,
        e_phoff=e_phoff,
        e_phentsize=e_phentsize,
        e_phnum=e_phnum,
        e_shoff=e_shoff,
        e_shentsize=e_shentsize,
        e_shnum=e_shnum,
        e_shstrndx=e_shstrndx,
        elf_header_bytes=raw[: _ELF_HEADER.size],
        program_header_bytes=ph_bytes,
        program_headers=tuple(program_headers),
        section_headers=section_headers,
    )


def _validate_dynamic(base: ParsedELF64V1) -> None:
    for header in base.program_headers:
        if header.p_type != PT_DYNAMIC:
            continue
        if (
            header.p_filesz == 0
            or header.p_filesz > _MAX_DYNAMIC_BYTES
            or header.p_filesz % _DYNAMIC.size
        ):
            _fail("ELF_DYNAMIC_INVALID", "PT_DYNAMIC is not one bounded complete table")
        terminated = False
        for offset in range(0, header.p_filesz, _DYNAMIC.size):
            tag, _value = _DYNAMIC.unpack_from(base.raw, header.p_offset + offset)
            if tag == DT_NEEDED:
                _fail("ELF_DYNAMIC_DEPENDENCY", "PT_DYNAMIC contains DT_NEEDED")
            if tag == DT_NULL:
                terminated = True
        if not terminated:
            _fail("ELF_DYNAMIC_UNTERMINATED", "PT_DYNAMIC has no bounded DT_NULL")


def _validate_gate_page(gate: bytes, gate_code_size: int) -> None:
    if type(gate_code_size) is not int or not (len(ENDBR64) <= gate_code_size < PAGE_SIZE):
        _fail("GATE_CODE_SIZE_INVALID", "gate_code_size is outside the one-page code range")
    if len(gate) != PAGE_SIZE:
        _fail("GATE_PAGE_SIZE_INVALID", "gate page is not exactly 4096 bytes")
    if gate[: len(ENDBR64)] != ENDBR64:
        _fail("GATE_CET_ENTRY_INVALID", "gate page does not start with endbr64")
    if gate[gate_code_size : PAGE_SIZE - 1] != b"\xcc" * (PAGE_SIZE - 1 - gate_code_size):
        _fail("GATE_PADDING_INVALID", "gate padding is not exact 0xCC")
    if gate[-1:] != b"\x00":
        _fail("GATE_EMPTY_PATH_INVALID", "gate byte 4095 is not NUL")


def _validate_base_ranges(base: ParsedELF64V1) -> int:
    if not base.program_headers:
        _fail("ELF_PROGRAM_HEADER_MISSING", "static PIE has no program headers")
    if any(header.p_type == PT_INTERP for header in base.program_headers):
        _fail("ELF_INTERPRETER_PRESENT", "base ELF contains PT_INTERP")
    _validate_dynamic(base)

    for header in base.program_headers:
        if header.file_end > len(base.raw):
            _fail("ELF_PROGRAM_TRAILER_REFERENCE", "program header references trailer bytes")
    if base.e_shoff:
        sh_end = _checked_end(
            base.e_shoff,
            base.e_shnum * base.e_shentsize,
            len(base.raw),
            "section-header table",
        )
        if sh_end > len(base.raw):
            _fail("ELF_SECTION_TRAILER_REFERENCE", "section-header table references trailer bytes")
    for section in base.section_headers:
        if section.sh_type == SHT_NOBITS or section.sh_size == 0:
            continue
        end = _checked_end(
            section.sh_offset,
            section.sh_size,
            len(base.raw),
            f"section {section.index}",
        )
        if end > len(base.raw):
            _fail("ELF_SECTION_TRAILER_REFERENCE", "file-backed section references trailer bytes")

    executable = tuple(
        header
        for header in base.program_headers
        if header.p_type == PT_LOAD
        and header.p_flags & PF_X
        and header.p_vaddr <= base.e_entry < header.p_vaddr + header.p_filesz
    )
    if len(executable) != 1:
        _fail("ELF_ENTRY_AMBIGUOUS", "e_entry is not in exactly one file-backed executable PT_LOAD")
    return executable[0].index


def validate_launch_gate_trailer_v1(
    base_image: bytes | bytearray | memoryview,
    final_image: bytes | bytearray | memoryview,
    gate_page: bytes | bytearray | memoryview,
    *,
    gate_code_size: int,
) -> LaunchGateTrailerValidationResultV1:
    """Validate one exact base ELF plus append-only authenticated gate page."""

    try:
        base_raw = _bytes(base_image, "base_image")
        final_raw = _bytes(final_image, "final_image")
        gate_raw = _bytes(gate_page, "gate_page")
        _validate_gate_page(gate_raw, gate_code_size)
        base = _parse_elf64(base_raw, expected_type=ET_DYN)
        entry_segment = _validate_base_ranges(base)

        gate_offset = _align_up(len(base_raw), PAGE_SIZE)
        expected_length = gate_offset + PAGE_SIZE
        if len(final_raw) != expected_length:
            _fail("TRAILER_FINAL_LENGTH_INVALID", "final image has the wrong exact length")
        if final_raw[: len(base_raw)] != base_raw:
            _fail("TRAILER_BASE_PREFIX_CHANGED", "packer changed a base ELF byte")
        if final_raw[len(base_raw) : gate_offset] != b"\x00" * (gate_offset - len(base_raw)):
            _fail("TRAILER_ALIGNMENT_PADDING_INVALID", "alignment padding is not all zero")
        if final_raw[gate_offset:] != gate_raw:
            _fail("TRAILER_GATE_PAGE_MISMATCH", "appended gate page is not byte-identical")

        rounded_load_end = max(
            _align_up(header.file_end, PAGE_SIZE)
            for header in base.program_headers
            if header.p_type == PT_LOAD
        )
        if gate_offset < rounded_load_end:
            _fail("TRAILER_GATE_OVERLAPS_LOAD_PAGE", "gate shares a rounded PT_LOAD file page")

        final_prefix = _parse_elf64(final_raw[: len(base_raw)], expected_type=ET_DYN)
        if final_prefix.elf_header_bytes != base.elf_header_bytes:
            _fail("TRAILER_ELF_HEADER_CHANGED", "final ELF header differs from base")
        if final_prefix.program_header_bytes != base.program_header_bytes:
            _fail("TRAILER_PROGRAM_HEADERS_CHANGED", "final program-header table differs from base")
        if final_prefix.e_entry != base.e_entry:
            _fail("TRAILER_ENTRY_CHANGED", "final e_entry differs from base")

        evidence = LaunchGateTrailerEvidenceV1(
            base_length=len(base_raw),
            base_sha256=sha256(base_raw).digest(),
            base_e_entry=base.e_entry,
            base_program_header_table_sha256=sha256(base.program_header_bytes).digest(),
            gate_file_offset=gate_offset,
            gate_code_size=gate_code_size,
            gate_code_sha256=sha256(gate_raw[:gate_code_size]).digest(),
            gate_page_sha256=sha256(gate_raw).digest(),
            final_length=len(final_raw),
            final_sha256=sha256(final_raw).digest(),
            executable_entry_segment_index=entry_segment,
        )
        return LaunchGateTrailerValidationResultV1(
            valid=True,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(),
            evidence=evidence,
        )
    except LaunchGateStage1ValidationError as exc:
        return LaunchGateTrailerValidationResultV1(
            valid=False,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(LaunchGateStage1Issue(exc.code, str(exc)),),
        )
    except (OverflowError, struct.error, TypeError, ValueError) as exc:
        return LaunchGateTrailerValidationResultV1(
            valid=False,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(LaunchGateStage1Issue("STAGE1_MALFORMED", f"malformed Stage-1 input: {exc}"),),
        )


def _validate_object_sections(
    parsed: ParsedELF64V1,
    gate_page: bytes,
) -> tuple[SectionHeaderV1, SectionHeaderV1]:
    if not parsed.section_headers:
        _fail("GATE_OBJECT_SECTION_TABLE_MISSING", "gate object has no section table")
    null_section = parsed.section_headers[0]
    if (
        null_section.name_offset,
        null_section.sh_type,
        null_section.sh_flags,
        null_section.sh_addr,
        null_section.sh_offset,
        null_section.sh_size,
        null_section.sh_link,
        null_section.sh_info,
        null_section.sh_addralign,
        null_section.sh_entsize,
        null_section.name,
    ) != (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b""):
        _fail("GATE_OBJECT_NULL_SECTION_INVALID", "section zero is not the exact ELF null section")

    owned_ranges: list[tuple[int, int, str]] = [
        (0, _ELF_HEADER.size, "ELF header"),
        (
            parsed.e_shoff,
            parsed.e_shoff + parsed.e_shnum * parsed.e_shentsize,
            "section-header table",
        ),
    ]
    for section in parsed.section_headers:
        if section.sh_type == SHT_NOBITS or section.sh_size == 0:
            continue
        section_end = _checked_end(
            section.sh_offset,
            section.sh_size,
            len(parsed.raw),
            f"object section {section.index}",
        )
        owned_ranges.append(
            (section.sh_offset, section_end, f"section {section.index} {section.name!r}")
        )
    owned_ranges.sort(key=lambda item: (item[0], item[1], item[2]))
    for previous, current in zip(owned_ranges, owned_ranges[1:]):
        if current[0] < previous[1]:
            _fail(
                "GATE_OBJECT_FILE_RANGE_OVERLAP",
                f"{previous[2]} overlaps {current[2]}",
            )

    gate_sections = tuple(
        section for section in parsed.section_headers if section.name == b".text.launch_gate_v1"
    )
    if len(gate_sections) != 1:
        _fail("GATE_OBJECT_SECTION_NOT_UNIQUE", "object lacks one unique gate section")
    gate = gate_sections[0]
    if gate.sh_type != SHT_PROGBITS:
        _fail("GATE_OBJECT_SECTION_TYPE_INVALID", "gate section is not SHT_PROGBITS")
    if gate.sh_flags != SHF_ALLOC | SHF_EXECINSTR:
        _fail("GATE_OBJECT_SECTION_FLAGS_INVALID", "gate section flags are not exact AX")
    if (
        gate.sh_addr != 0
        or gate.sh_offset % PAGE_SIZE
        or gate.sh_addralign != PAGE_SIZE
        or gate.sh_size != PAGE_SIZE
        or gate.sh_link != 0
        or gate.sh_info != 0
        or gate.sh_entsize != 0
    ):
        _fail("GATE_OBJECT_SECTION_LAYOUT_INVALID", "gate section is not exact aligned page")
    gate_end = _checked_end(gate.sh_offset, gate.sh_size, len(parsed.raw), "gate section")
    if parsed.raw[gate.sh_offset:gate_end] != gate_page:
        _fail("GATE_OBJECT_PAGE_MISMATCH", "object gate section differs from gate page")

    empty_text_sections = tuple(
        section for section in parsed.section_headers if section.name == b".text"
    )
    if len(empty_text_sections) != 1:
        _fail("GATE_OBJECT_EMPTY_TEXT_NOT_UNIQUE", "object lacks one unique empty .text section")
    empty_text = empty_text_sections[0]
    empty_text_tuple = (
        empty_text.sh_type,
        empty_text.sh_flags,
        empty_text.sh_addr,
        empty_text.sh_offset,
        empty_text.sh_size,
        empty_text.sh_link,
        empty_text.sh_info,
        empty_text.sh_addralign,
        empty_text.sh_entsize,
    )
    if empty_text_tuple != (
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        0,
        0x40,
        0,
        0,
        0,
        4,
        0,
    ):
        _fail(
            "GATE_OBJECT_EMPTY_TEXT_TUPLE_INVALID",
            "empty .text does not match the exact Clang 16 integrated-assembler tuple",
        )

    for section in parsed.section_headers:
        if section.sh_addralign not in (0, 1) and section.sh_addralign & (section.sh_addralign - 1):
            _fail("GATE_OBJECT_SECTION_ALIGNMENT_INVALID", "object section alignment is not a power of two")
        if section.sh_type != SHT_NOBITS:
            section_end = _checked_end(
                section.sh_offset,
                section.sh_size,
                len(parsed.raw),
                f"object section {section.index}",
            )
            if section.sh_size and section.sh_addralign > 1 and section.sh_offset % section.sh_addralign:
                _fail("GATE_OBJECT_SECTION_ALIGNMENT_INVALID", "object section offset violates alignment")
            if (
                section.index != empty_text.index
                and section.sh_size
                and section.sh_offset <= empty_text.sh_offset < section_end
            ):
                _fail(
                    "GATE_OBJECT_EMPTY_TEXT_OFFSET_OVERLAP",
                    "a nonempty section owns the empty .text file offset",
                )
        if section.sh_type in (SHT_REL, SHT_RELA):
            _fail("GATE_OBJECT_RELOCATION_PRESENT", "gate object contains a relocation section")
        if section.sh_type == SHT_DYNSYM:
            _fail("GATE_OBJECT_DYNSYM_PRESENT", "gate object contains a dynamic symbol table")
        if section.sh_flags & SHF_ALLOC and section.index not in (gate.index, empty_text.index):
            _fail(
                "GATE_OBJECT_EXTRA_ALLOCATED_SECTION",
                "gate object contains an allocated section other than the gate and exact empty .text",
            )
        if section.sh_type == SHT_GROUP:
            if section.sh_size == 0 or section.sh_size % _GROUP_WORD.size:
                _fail("GATE_OBJECT_GROUP_INVALID", "section group has an invalid word range")
            group_end = _checked_end(
                section.sh_offset,
                section.sh_size,
                len(parsed.raw),
                f"section group {section.index}",
            )
            members = tuple(
                _GROUP_WORD.unpack_from(parsed.raw, offset)[0]
                for offset in range(section.sh_offset + _GROUP_WORD.size, group_end, _GROUP_WORD.size)
            )
            if empty_text.index in members:
                _fail("GATE_OBJECT_EMPTY_TEXT_GROUP_MEMBER", "empty .text belongs to a section group")
        if section.sh_flags & SHF_LINK_ORDER and section.sh_link == empty_text.index:
            _fail("GATE_OBJECT_EMPTY_TEXT_LINK_ORDER", "link-order section refers to empty .text")
        if section.sh_flags & SHF_INFO_LINK and section.sh_info == empty_text.index:
            _fail("GATE_OBJECT_EMPTY_TEXT_INFO_LINK", "info-link section refers to empty .text")
        if section.index == empty_text.index and section.sh_flags & SHF_GROUP:
            _fail("GATE_OBJECT_EMPTY_TEXT_GROUP_FLAG", "empty .text carries SHF_GROUP")
        lowered = section.name.lower()
        if any(
            token in lowered
            for token in (
                b".got",
                b".plt",
                b".tls",
                b".init",
                b".fini",
                b".ctor",
                b".dtor",
                b".eh_frame",
                b".unwind",
                b".exception",
            )
        ):
            _fail("GATE_OBJECT_FORBIDDEN_SECTION", f"forbidden object section {section.name!r}")
        if section.sh_flags & (SHF_WRITE | SHF_TLS):
            _fail("GATE_OBJECT_WRITABLE_OR_TLS_SECTION", "gate object contains writable or TLS section")
        if section.name == b".note.GNU-stack":
            if section.sh_flags != 0 or section.sh_size != 0:
                _fail("GATE_OBJECT_STACK_NOTE_INVALID", ".note.GNU-stack is not empty non-executable")
    return gate, empty_text


def _validate_object_symbols(
    parsed: ParsedELF64V1,
    gate: SectionHeaderV1,
    empty_text: SectionHeaderV1,
    gate_code_size: int,
) -> int:
    symbol_tables = tuple(
        section for section in parsed.section_headers if section.sh_type == SHT_SYMTAB
    )
    if len(symbol_tables) != 1:
        _fail("GATE_OBJECT_SYMBOL_TABLE_INVALID", "object must contain one symbol table")
    table = symbol_tables[0]
    if table.sh_entsize != _SYMBOL.size or table.sh_size % _SYMBOL.size:
        _fail("GATE_OBJECT_SYMBOL_TABLE_INVALID", "symbol table entry shape is invalid")
    if table.sh_link >= len(parsed.section_headers):
        _fail("GATE_OBJECT_SYMBOL_STRING_TABLE_INVALID", "symbol string table index is invalid")
    strings_header = parsed.section_headers[table.sh_link]
    if strings_header.sh_type != SHT_STRTAB:
        _fail("GATE_OBJECT_SYMBOL_STRING_TABLE_INVALID", "symbol names do not reference SHT_STRTAB")
    strings_end = _checked_end(
        strings_header.sh_offset,
        strings_header.sh_size,
        len(parsed.raw),
        "symbol string table",
    )
    strings = parsed.raw[strings_header.sh_offset:strings_end]
    table_end = _checked_end(table.sh_offset, table.sh_size, len(parsed.raw), "symbol table")
    entries = tuple(
        _SYMBOL.unpack_from(parsed.raw, offset)
        for offset in range(table.sh_offset, table_end, _SYMBOL.size)
    )
    if not entries or entries[0] != (0, 0, 0, 0, 0, 0):
        _fail("GATE_OBJECT_NULL_SYMBOL_INVALID", "first symbol is not the mandatory null symbol")

    gate_globals: list[int] = []
    empty_text_section_symbols = 0
    for index, (name_offset, info, other, shndx, value, size) in enumerate(entries[1:], 1):
        name = _read_c_string(strings, name_offset, f"symbol {index} name")
        binding = info >> 4
        symbol_type = info & 0x0F
        if binding == STB_WEAK or symbol_type in (STT_GNU_IFUNC, STT_TLS):
            _fail("GATE_OBJECT_FORBIDDEN_SYMBOL", f"symbol {name!r} has forbidden binding/type")
        if shndx in (SHN_UNDEF, SHN_ABS, SHN_COMMON, SHN_XINDEX) or shndx >= SHN_LORESERVE:
            _fail("GATE_OBJECT_FORBIDDEN_SYMBOL_INDEX", f"symbol {name!r} is undefined or special")
        if shndx >= len(parsed.section_headers):
            _fail("GATE_OBJECT_SYMBOL_INDEX_INVALID", f"symbol {name!r} section index is invalid")
        if shndx == empty_text.index:
            if (
                binding != STB_LOCAL
                or symbol_type != STT_SECTION
                or other != STV_DEFAULT
                or value != 0
                or size != 0
            ):
                _fail(
                    "GATE_OBJECT_EMPTY_TEXT_SYMBOL_INVALID",
                    "only one exact local default-visibility section symbol may refer to empty .text",
                )
            empty_text_section_symbols += 1
            if empty_text_section_symbols > 1:
                _fail(
                    "GATE_OBJECT_EMPTY_TEXT_SYMBOL_INVALID",
                    "more than one section symbol refers to empty .text",
                )
            continue
        if binding == STB_GLOBAL:
            if (
                name != b"launch_gate_v1"
                or symbol_type != STT_FUNC
                or other != STV_DEFAULT
                or shndx != gate.index
                or value != 0
                or size != gate_code_size
            ):
                _fail("GATE_OBJECT_GLOBAL_SYMBOL_INVALID", "global symbol is not the exact gate function")
            gate_globals.append(index)
        elif binding == STB_LOCAL:
            if symbol_type != STT_SECTION:
                if (
                    other != STV_DEFAULT
                    or shndx != gate.index
                    or value >= gate_code_size
                    or value + size > gate_code_size
                ):
                    _fail("GATE_OBJECT_LOCAL_SYMBOL_INVALID", f"local symbol {name!r} lies outside code")
            elif other != STV_DEFAULT:
                _fail("GATE_OBJECT_LOCAL_SYMBOL_INVALID", "local section symbol visibility is not default")
        else:
            _fail("GATE_OBJECT_SYMBOL_BINDING_INVALID", f"symbol {name!r} binding is forbidden")
    if len(gate_globals) != 1:
        _fail("GATE_OBJECT_GLOBAL_SYMBOL_INVALID", "object lacks one exact global gate function")
    return gate_globals[0]


def validate_launch_gate_object_v1(
    object_bytes: bytes | bytearray | memoryview,
    gate_page: bytes | bytearray | memoryview,
    *,
    gate_code_size: int,
) -> LaunchGateObjectValidationResultV1:
    """Validate the exact relocatable gate object and extracted page bytes."""

    try:
        raw = _bytes(object_bytes, "object_bytes")
        gate_raw = _bytes(gate_page, "gate_page")
        _validate_gate_page(gate_raw, gate_code_size)
        parsed = _parse_elf64(raw, expected_type=ET_REL)
        if parsed.program_headers:
            _fail("GATE_OBJECT_PROGRAM_HEADER_PRESENT", "relocatable gate object has program headers")
        gate, empty_text = _validate_object_sections(parsed, gate_raw)
        symbol_index = _validate_object_symbols(parsed, gate, empty_text, gate_code_size)
        evidence = LaunchGateObjectEvidenceV1(
            object_sha256=sha256(raw).digest(),
            gate_page_sha256=sha256(gate_raw).digest(),
            gate_code_size=gate_code_size,
            gate_section_index=gate.index,
            gate_symbol_index=symbol_index,
        )
        return LaunchGateObjectValidationResultV1(
            valid=True,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(),
            evidence=evidence,
        )
    except LaunchGateStage1ValidationError as exc:
        return LaunchGateObjectValidationResultV1(
            valid=False,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(LaunchGateStage1Issue(exc.code, str(exc)),),
        )
    except (OverflowError, struct.error, TypeError, ValueError) as exc:
        return LaunchGateObjectValidationResultV1(
            valid=False,
            scope=STATIC_LAYOUT_SCOPE,
            issues=(LaunchGateStage1Issue("STAGE1_MALFORMED", f"malformed Stage-1 input: {exc}"),),
        )


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "ENDBR64",
    "LaunchGateObjectEvidenceV1",
    "LaunchGateObjectValidationResultV1",
    "LaunchGateStage1Issue",
    "LaunchGateStage1ValidationError",
    "LaunchGateTrailerEvidenceV1",
    "LaunchGateTrailerValidationResultV1",
    "PAGE_SIZE",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "PROTOCOL_ID",
    "STATIC_LAYOUT_SCOPE",
    "UNMET_CFG_PROOF",
    "UNMET_CHECKS",
    "UNMET_DUAL_BUILD",
    "UNMET_INSTRUCTION_DECODERS",
    "ZERO_AUTHORITY",
    "validate_launch_gate_object_v1",
    "validate_launch_gate_trailer_v1",
]
