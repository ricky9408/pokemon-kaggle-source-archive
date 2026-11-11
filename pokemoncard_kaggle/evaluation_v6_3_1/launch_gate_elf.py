"""Pure structural validation for the LaunchGateV1 ELF profile.

This module parses only ELF64 little-endian program metadata from bytes.  It
does not disassemble the image, inspect relocations, prove control flow, or
connect to a campaign, permit, upload, holdout, or agent-modification path.
The result therefore describes structural byte evidence only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Final


ELFCLASS64: Final = 2
ELFDATA2LSB: Final = 1
EV_CURRENT: Final = 1
ET_DYN: Final = 3
EM_X86_64: Final = 62
PT_LOAD: Final = 1
PT_DYNAMIC: Final = 2
PT_INTERP: Final = 3
DT_NULL: Final = 0
DT_NEEDED: Final = 1
PF_X: Final = 1
PF_W: Final = 2
PF_R: Final = 4
PF_RX: Final = PF_R | PF_X
PAGE_SIZE: Final = 4096
SHN_XINDEX: Final = 0xFFFF

STRUCTURAL_SCOPE: Final = "ELF_STRUCTURAL_BYTES_ONLY"
UNMET_DISASSEMBLY: Final = "DISASSEMBLY_NOT_PERFORMED"
UNMET_RELOCATION: Final = "RELOCATION_SAFETY_NOT_PROVEN"
UNMET_CONTROL_FLOW: Final = "CONTROL_FLOW_NOT_PROVEN"
UNMET_CHECKS: Final = (
    UNMET_DISASSEMBLY,
    UNMET_RELOCATION,
    UNMET_CONTROL_FLOW,
)

_ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
_SECTION_HEADER_SIZE = 64
_PROGRAM_HEADER_SIZE = 56
_ELF_HEADER_SIZE = 64
_MAX_U64 = (1 << 64) - 1
_DYNAMIC_ENTRY_SIZE = 16
_MAX_DYNAMIC_BYTES = 1 << 20


@dataclass(frozen=True)
class LaunchGateIssue:
    """One fail-closed structural issue."""

    code: str
    message: str


@dataclass(frozen=True)
class LaunchGateProgramHeader:
    """The bounded, integer-only fields of one ELF64 program header."""

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
class LaunchGateELFResult:
    """Structural result; no campaign or upload authority is represented."""

    verified: bool
    scope: str
    issues: tuple[LaunchGateIssue, ...]
    unmet_checks: tuple[str, ...] = UNMET_CHECKS
    file_size: int | None = None
    file_offset: int | None = None
    mapping_length: int | None = None
    entry_offset: int | None = None
    expected_gate_sha256: str | None = None
    gate_segment: LaunchGateProgramHeader | None = None
    gate_sha256: str | None = None
    elf_entry: int | None = None
    elf_entry_segment: LaunchGateProgramHeader | None = None
    gate_entry_address: int | None = None
    disassembly_proven: bool = False
    relocation_safety_proven: bool = False
    control_flow_proven: bool = False


class _InvalidELF(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _invalid(code: str, message: str) -> None:
    raise _InvalidELF(code, message)


def _checked_end(offset: int, length: int, file_size: int, label: str) -> int:
    if offset < 0 or length < 0 or offset > _MAX_U64 or length > _MAX_U64:
        _invalid("ELF_RANGE_INVALID", f"{label} contains an invalid integer")
    if offset > _MAX_U64 - length:
        _invalid("ELF_RANGE_OVERFLOW", f"{label} overflows uint64")
    end = offset + length
    if end > file_size:
        _invalid("ELF_RANGE_TRUNCATED", f"{label} exceeds the image")
    return end


def _overlaps(left_start: int, left_end: int, right_start: int, right_end: int) -> bool:
    return left_start < right_end and right_start < left_end


def _header_range_is_valid(
    start: int,
    length: int,
    file_size: int,
    label: str,
) -> tuple[int, int]:
    end = _checked_end(start, length, file_size, label)
    if start < _ELF_HEADER_SIZE:
        _invalid("ELF_HEADER_OVERLAP", f"{label} overlaps the ELF header")
    return start, end


def _as_bytes(image: object) -> bytes:
    if isinstance(image, bytes):
        return image
    if isinstance(image, (bytearray, memoryview)):
        try:
            return bytes(image)
        except (BufferError, TypeError, ValueError) as exc:
            _invalid("ELF_INPUT_INVALID", f"image is not a readable byte buffer: {exc}")
    _invalid("ELF_INPUT_INVALID", "image must be bytes-like")


def _canonical_sha256(value: object) -> str:
    if type(value) is not str or len(value) != 64:
        _invalid("ELF_EXPECTED_DIGEST_INVALID", "expected gate SHA-256 must be 64 hex characters")
    if any(character not in "0123456789abcdefABCDEF" for character in value):
        _invalid("ELF_EXPECTED_DIGEST_INVALID", "expected gate SHA-256 is not hexadecimal")
    return value.lower()


def _validate_dynamic_tables(
    image: bytes,
    headers: tuple[LaunchGateProgramHeader, ...],
) -> None:
    for header in headers:
        if header.p_type != PT_DYNAMIC:
            continue
        if (
            header.p_filesz == 0
            or header.p_filesz > _MAX_DYNAMIC_BYTES
            or header.p_filesz % _DYNAMIC_ENTRY_SIZE != 0
        ):
            _invalid("ELF_DYNAMIC_TABLE_INVALID", f"PT_DYNAMIC {header.index} is not a bounded Elf64_Dyn table")
        terminated = False
        for offset in range(0, header.p_filesz, _DYNAMIC_ENTRY_SIZE):
            tag, _value = struct.unpack_from("<qQ", image, header.p_offset + offset)
            if tag == DT_NEEDED:
                _invalid("ELF_DYNAMIC_DEPENDENCY", f"PT_DYNAMIC {header.index} contains DT_NEEDED")
            if tag == DT_NULL:
                terminated = True
                break
        if not terminated:
            _invalid("ELF_DYNAMIC_UNTERMINATED", f"PT_DYNAMIC {header.index} lacks DT_NULL")


def _parse_program_headers(image: bytes) -> tuple[dict[str, int], tuple[LaunchGateProgramHeader, ...]]:
    file_size = len(image)
    if file_size < _ELF_HEADER_SIZE:
        _invalid("ELF_TRUNCATED_HEADER", "ELF header is truncated")

    fields = _ELF_HEADER.unpack_from(image, 0)
    ident = fields[0]
    if ident[:4] != b"\x7fELF":
        _invalid("ELF_BAD_MAGIC", "ELF magic is invalid")
    if ident[4] != ELFCLASS64:
        _invalid("ELF_BAD_CLASS", "ELF class is not ELF64")
    if ident[5] != ELFDATA2LSB:
        _invalid("ELF_BAD_ENDIAN", "ELF data encoding is not little-endian")
    if ident[6] != EV_CURRENT or fields[3] != EV_CURRENT:
        _invalid("ELF_BAD_VERSION", "ELF version is not current")

    (
        _ident,
        e_type,
        e_machine,
        _e_version,
        e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = fields
    if e_type != ET_DYN:
        _invalid("ELF_BAD_TYPE", "ELF type is not ET_DYN")
    if e_machine != EM_X86_64:
        _invalid("ELF_BAD_MACHINE", "ELF machine is not EM_X86_64")
    if e_ehsize != _ELF_HEADER_SIZE:
        _invalid("ELF_BAD_HEADER_SIZE", "ELF header size is not ELF64-sized")
    if e_phentsize != _PROGRAM_HEADER_SIZE:
        _invalid("ELF_BAD_PROGRAM_HEADER_SIZE", "program-header entry size is invalid")
    if e_phnum == 0 or e_phnum == SHN_XINDEX:
        _invalid("ELF_PROGRAM_HEADERS_MISSING", "ELF has no supported program-header table")
    if e_phoff < _ELF_HEADER_SIZE or e_phoff % 8 != 0:
        _invalid("ELF_PROGRAM_HEADER_OFFSET", "program-header table offset is invalid")

    ph_table_length = e_phnum * _PROGRAM_HEADER_SIZE
    ph_start, ph_end = _header_range_is_valid(
        e_phoff,
        ph_table_length,
        file_size,
        "program-header table",
    )

    if e_shoff == 0 and (e_shnum != 0 or e_shentsize != 0):
        _invalid("ELF_SECTION_TABLE_MALFORMED", "section-header table fields are inconsistent")
    if e_shoff != 0:
        if e_shnum == 0 or e_shentsize != _SECTION_HEADER_SIZE or e_shoff % 8 != 0:
            _invalid("ELF_SECTION_TABLE_MALFORMED", "section-header table is malformed")
        sh_start, sh_end = _header_range_is_valid(
            e_shoff,
            e_shnum * _SECTION_HEADER_SIZE,
            file_size,
            "section-header table",
        )
        if _overlaps(sh_start, sh_end, ph_start, ph_end):
            _invalid("ELF_HEADER_OVERLAP", "section and program-header tables overlap")
        if e_shstrndx != 0 and e_shstrndx >= e_shnum:
            _invalid("ELF_SECTION_INDEX_INVALID", "section-string-table index is out of range")
    elif e_shstrndx != 0:
        _invalid("ELF_SECTION_TABLE_MALFORMED", "section-string-table index lacks a table")

    headers: list[LaunchGateProgramHeader] = []
    for index in range(e_phnum):
        offset = e_phoff + index * _PROGRAM_HEADER_SIZE
        values = _PROGRAM_HEADER.unpack_from(image, offset)
        header = LaunchGateProgramHeader(index, *values)
        _checked_end(header.p_offset, header.p_filesz, file_size, f"program header {index} file range")
        if header.p_type == PT_LOAD:
            if header.p_memsz < header.p_filesz:
                _invalid("ELF_LOAD_SIZE_INVALID", f"PT_LOAD {index} has p_memsz < p_filesz")
            if header.p_vaddr > _MAX_U64 - header.p_memsz:
                _invalid("ELF_LOAD_RANGE_OVERFLOW", f"PT_LOAD {index} virtual range overflows uint64")
            if header.p_align not in (0, 1):
                if header.p_align & (header.p_align - 1):
                    _invalid("ELF_LOAD_ALIGNMENT_INVALID", f"PT_LOAD {index} p_align is not a power of two")
                if header.p_offset % header.p_align != header.p_vaddr % header.p_align:
                    _invalid("ELF_LOAD_ALIGNMENT_INVALID", f"PT_LOAD {index} offset and address are misaligned")
        headers.append(header)

    return {"entry": e_entry, "ph_start": ph_start, "ph_end": ph_end}, tuple(headers)


def validate_launch_gate_elf(
    image: bytes | bytearray | memoryview,
    *,
    file_offset: int,
    mapping_length: int,
    entry_offset: int,
    expected_gate_sha256: str,
) -> LaunchGateELFResult:
    """Validate the structural LaunchGateV1 profile for an exact byte image.

    The four profile fields identify one exact gate PT_LOAD and its profile
    entry offset.  The ELF ``e_entry`` is intentionally validated separately:
    it must belong to a different executable PT_LOAD.
    """

    try:
        raw = _as_bytes(image)
        expected_digest = _canonical_sha256(expected_gate_sha256)
        if (
            type(file_offset) is not int
            or type(mapping_length) is not int
            or type(entry_offset) is not int
        ):
            _invalid("ELF_REQUEST_INVALID", "profile offsets and lengths must be integers")
        if file_offset < 0 or mapping_length <= 0:
            _invalid("ELF_REQUEST_INVALID", "file offset must be non-negative and mapping length positive")
        if entry_offset < 0 or entry_offset >= mapping_length:
            _invalid("ELF_GATE_ENTRY_OFFSET_INVALID", "gate entry offset is outside the gate mapping")
        gate_end = _checked_end(file_offset, mapping_length, len(raw), "gate file range")
        metadata, headers = _parse_program_headers(raw)

        for header in headers:
            if header.p_type == PT_INTERP:
                _invalid("ELF_INTERPRETER_PRESENT", f"unsupported PT_INTERP at index {header.index}")
        _validate_dynamic_tables(raw, headers)

        loads = tuple(header for header in headers if header.p_type == PT_LOAD)
        gate_candidates = tuple(
            header
            for header in loads
            if header.p_flags == PF_RX
            and header.p_offset == file_offset
            and header.p_filesz == mapping_length
        )
        if len(gate_candidates) != 1:
            _invalid(
                "ELF_GATE_LOAD_NOT_UNIQUE",
                "exactly one PF_R|PF_X PT_LOAD must match the gate file range",
            )
        target = gate_candidates[0]
        if target.file_end != gate_end:
            _invalid("ELF_GATE_RANGE_MISMATCH", "gate PT_LOAD does not exactly match the profile range")
        if target.p_offset % PAGE_SIZE != 0 or target.p_vaddr % PAGE_SIZE != 0:
            _invalid("ELF_GATE_PAGE_ALIGNMENT", "gate PT_LOAD is not page-aligned")
        if mapping_length % PAGE_SIZE != 0:
            _invalid("ELF_GATE_PAGE_ALIGNMENT", "gate PT_LOAD length is not page-aligned")
        if target.p_align < PAGE_SIZE:
            _invalid("ELF_GATE_PAGE_ALIGNMENT", "gate PT_LOAD p_align is smaller than the LaunchGate page size")
        if target.p_filesz != target.p_memsz:
            _invalid("ELF_GATE_SIZE_PROFILE", "gate PT_LOAD must have p_filesz == p_memsz")

        for header in loads:
            if header.index == target.index:
                continue
            if _overlaps(file_offset, gate_end, header.p_offset, header.file_end):
                if header.p_flags & PF_W:
                    _invalid("ELF_GATE_WRITABLE_OVERLAP", "gate PT_LOAD overlaps a writable PT_LOAD")
                _invalid("ELF_GATE_NOT_DEDICATED", "gate PT_LOAD overlaps another PT_LOAD")
            if _overlaps(target.p_vaddr, target.memory_end, header.p_vaddr, header.memory_end):
                if header.p_flags & PF_W:
                    _invalid(
                        "ELF_GATE_WRITABLE_OVERLAP",
                        "gate PT_LOAD virtual range overlaps a writable PT_LOAD",
                    )
                _invalid(
                    "ELF_GATE_NOT_DEDICATED",
                    "gate PT_LOAD virtual range overlaps another PT_LOAD",
                )

        executable_matches = tuple(
            header
            for header in loads
            if header.p_flags & PF_X
            and header.p_vaddr <= metadata["entry"] < header.p_vaddr + header.p_filesz
        )
        if any(header.index == target.index for header in executable_matches):
            _invalid("ELF_ENTRY_IN_GATE", "ELF e_entry must not lie in the gate PT_LOAD")
        if len(executable_matches) != 1:
            _invalid(
                "ELF_ENTRY_EXECUTABLE_MAPPING",
                "ELF e_entry must lie in exactly one different executable PT_LOAD",
            )
        entry_segment = executable_matches[0]
        segment_bytes = raw[file_offset:gate_end]
        actual_digest = sha256(segment_bytes).hexdigest()
        if actual_digest != expected_digest:
            _invalid("ELF_GATE_DIGEST_MISMATCH", "gate PT_LOAD SHA-256 does not match the expected digest")
        return LaunchGateELFResult(
            verified=True,
            scope=STRUCTURAL_SCOPE,
            issues=(),
            file_size=len(raw),
            file_offset=file_offset,
            mapping_length=mapping_length,
            entry_offset=entry_offset,
            expected_gate_sha256=expected_digest,
            gate_segment=target,
            gate_sha256=actual_digest,
            elf_entry=metadata["entry"],
            elf_entry_segment=entry_segment,
            gate_entry_address=target.p_vaddr + entry_offset,
        )
    except _InvalidELF as error:
        file_size = len(image) if isinstance(image, (bytes, bytearray, memoryview)) else None
        return LaunchGateELFResult(
            verified=False,
            scope=STRUCTURAL_SCOPE,
            issues=(LaunchGateIssue(error.code, error.message),),
            file_size=file_size,
        )
    except (struct.error, OverflowError, ValueError, TypeError) as error:
        file_size = len(image) if isinstance(image, (bytes, bytearray, memoryview)) else None
        return LaunchGateELFResult(
            verified=False,
            scope=STRUCTURAL_SCOPE,
            issues=(LaunchGateIssue("ELF_MALFORMED", f"malformed ELF input: {error}"),),
            file_size=file_size,
        )


validate_elf64_launch_gate = validate_launch_gate_elf


__all__ = [
    "EM_X86_64",
    "ET_DYN",
    "ELFCLASS64",
    "ELFDATA2LSB",
    "PAGE_SIZE",
    "PF_R",
    "PF_W",
    "PF_X",
    "PF_RX",
    "PT_DYNAMIC",
    "PT_INTERP",
    "PT_LOAD",
    "DT_NEEDED",
    "DT_NULL",
    "STRUCTURAL_SCOPE",
    "UNMET_CHECKS",
    "UNMET_CONTROL_FLOW",
    "UNMET_DISASSEMBLY",
    "UNMET_RELOCATION",
    "LaunchGateELFResult",
    "LaunchGateIssue",
    "LaunchGateProgramHeader",
    "validate_elf64_launch_gate",
    "validate_launch_gate_elf",
]
