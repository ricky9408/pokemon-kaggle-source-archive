"""Host checks for the zero-authority, frozen LaunchGate V1 ABI."""

from __future__ import annotations

import re
import struct
import subprocess
import tempfile
from pathlib import Path

import pytest


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "evaluation_v6_3_1"
    / "native"
    / "capture_v2"
    / "LaunchGateV1.S"
)

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_REL = 9
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_FUNC = 2


def _source() -> str:
    return SOURCE.read_text(encoding="ascii")


def _code_lines(source: str) -> list[str]:
    lines = []
    for line in source.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith((".", "#")) and not line.endswith(":"):
            lines.append(line)
    return lines


def _assemble_object(tmp: Path) -> bytes:
    clang = subprocess.run(
        [
            "clang",
            "--target=x86_64-unknown-linux-gnu",
            "-c",
            "-x",
            "assembler",
            "-fintegrated-as",
            "-Wa,--noexecstack",
            str(SOURCE),
            "-o",
            str(tmp / "LaunchGateV1.o"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if clang.returncode != 0:
        pytest.fail(clang.stderr)
    return (tmp / "LaunchGateV1.o").read_bytes()


def _parse_sections(image: bytes) -> tuple[dict[str, object], ...]:
    header = ELF_HEADER.unpack_from(image)
    e_shoff, e_shentsize, e_shnum, e_shstrndx = (
        header[6],
        header[11],
        header[12],
        header[13],
    )
    assert e_shentsize == SECTION_HEADER.size
    raw = [
        SECTION_HEADER.unpack_from(image, e_shoff + index * e_shentsize)
        for index in range(e_shnum)
    ]
    string_header = raw[e_shstrndx]
    string_table = image[
        string_header[4] : string_header[4] + string_header[5]
    ]

    sections: list[dict[str, object]] = []
    for index, fields in enumerate(raw):
        name_offset, section_type, flags, _addr, offset, size, link, _info, alignment, _entsize = fields
        end = offset + size
        name_end = string_table.find(b"\0", name_offset)
        name = string_table[name_offset:name_end].decode("ascii")
        sections.append(
            {
                "index": index,
                "name": name,
                "type": section_type,
                "flags": flags,
                "offset": offset,
                "size": size,
                "link": link,
                "align": alignment,
                "bytes": image[offset:end],
            }
        )
    return tuple(sections)


def _section(sections: tuple[dict[str, object], ...], name: str) -> dict[str, object]:
    matches = [section for section in sections if section["name"] == name]
    assert len(matches) == 1
    return matches[0]


def _symbols(
    image: bytes, sections: tuple[dict[str, object], ...]
) -> tuple[dict[str, object], ...]:
    symbols: list[dict[str, object]] = []
    for section in sections:
        if section["type"] != SHT_SYMTAB:
            continue
        string_table = sections[int(section["link"])]
        strings = string_table["bytes"]
        entry_size = SYMBOL.size
        assert section["size"] % entry_size == 0
        raw = section["bytes"]
        for offset in range(0, len(raw), entry_size):
            name_offset, info, other, shndx, value, size = SYMBOL.unpack_from(raw, offset)
            end = strings.find(b"\0", name_offset)
            symbols.append(
                {
                    "name": strings[name_offset:end].decode("ascii"),
                    "binding": info >> 4,
                    "type": info & 0x0F,
                    "other": other,
                    "shndx": shndx,
                    "value": value,
                    "size": size,
                }
            )
    return tuple(symbols)


def test_frozen_abi_layout_and_trailer_contract_are_documented():
    source = _source()
    for marker in (
        "The input record itself must be a non-wrapping",
        "LaunchGateInputV1, 64 bytes",
        "LaunchGateResultV1, 48 bytes",
        "5..INT32_MAX",
        "LG_E_RECORD",
        "LG_E_GETPID",
        ".section .text.launch_gate_v1",
        ".p2align 12",
        "endbr64",
        ".fill 4095-(.-launch_gate_v1), 1, 0xcc",
        ".Lempty_path:",
        ".byte 0x00",
    ):
        assert marker in source
    assert "empty_path_ptr" not in source
    assert ".globl launch_gate_v1_text_start" not in source
    assert ".globl launch_gate_v1_text_end" not in source


def test_exact_syscall_sequence_and_clone_validation_are_explicit():
    source = _source()
    offsets = {
        name: source.index(f"movl    ${number}, %eax")
        for name, number in (
            ("getpid", 39),
            ("clone3", 435),
            ("prctl", 157),
            ("getppid", 110),
            ("execveat", 322),
            ("exit_group", 231),
        )
    }
    assert offsets["getpid"] < offsets["clone3"] < offsets["prctl"]
    assert offsets["prctl"] < offsets["getppid"] < offsets["execveat"]
    assert offsets["execveat"] < offsets["exit_group"]
    assert source.count("cmpq    $0x1000, 0(%r10)") == 2
    assert source.count("cmpq    %rax, 8(%r10)") == 2
    for offset in (16, 24, 40, 48, 56, 64, 72, 80):
        assert source.count(f"cmpq    $0, {offset}(%r10)") == 2
    assert source.count("cmpq    $17, 32(%r10)") == 2
    assert source.count("movl    $88, %esi") == 1
    assert "cmpq    $5, 32(%r9)" in source
    assert "cmpq    $0x7fffffff, 32(%r9)" in source
    assert "leaq    .Lempty_path(%rip), %rsi" in source
    assert "movq    48(%r9), %r10" in source
    assert "movq    48(%r9), %rsi" not in source


def test_result_initialization_publication_and_return_semantics():
    source = _source()
    for marker in (
        "cmpq    $0, 0(%r8)",
        "cmpq    $0, 8(%r8)",
        "cmpq    $0, 16(%r8)",
        "cmpq    $0, 24(%r8)",
        "cmpq    $0, 32(%r8)",
        "cmpq    $0, 40(%r8)",
        "movq    $1, 0(%r8)",
        "movl    $-1, 16(%r8)",
        "movl    $0, 20(%r8)",
        "movq    $3, 0(%r8)",
        "xorl    %eax, %eax",
        "movq    $-4096, %rax",
        "movq    $-4097, %rax",
    ):
        assert marker in source
    assert len(re.findall(r"(?m)^\s*ret(?:q)?\s*$", source)) == 1
    success = source.split("# Positive parent branch", 1)[1].split(
        ".Lrecord_failure_preinit:", 1
    )[0]
    assert success.index("movq    $3, 0(%r8)") < success.index("xorl    %eax, %eax")
    assert success.index("xorl    %eax, %eax") < success.index("jmp     .Lparent_return")


def test_forbidden_surface_and_register_contract_are_absent():
    source = _source()
    code_lines = _code_lines(source)
    code = "\n".join(code_lines).lower()
    forbidden = {
        "call",
        "push",
        "pop",
        "leave",
        "enter",
        "int",
        "sysenter",
        "iret",
        "wrfsbase",
        "rdfsbase",
    }
    for line in code_lines:
        assert line.split(None, 1)[0].lower() not in forbidden, line
    assert not re.search(r"@(?:plt|got|gotpcrel)", code)
    assert ".extern" not in source.lower()
    assert ".include" not in source.lower()
    assert "%rsp" not in code
    assert not re.search(r"%(?:rbx|rbp|r1[2-5])(?:[dwb])?\b", code)
    assert code.count("%r9") >= 2
    child = source.split(".Lchild_path:", 1)[1].split(".Lchild_exit_127:", 1)[0]
    assert not re.search(
        r"(?:movq|movl|movw|movb|xorl)\s+%[^,]+,\s*[^#\n]*\(%r(?:8|9|10)\)",
        child,
    )
    assert "testq   %rax, %rax\n    jne     .Lchild_exit_127" in child
    assert "testq   %rax, %rax\n    jle     .Lchild_exit_127" in child
    assert "cmpq    24(%r8), %rax\n    jne     .Lchild_exit_127" in child


def test_r9_is_the_only_state_relied_on_across_each_syscall():
    source = _source()
    getpid_tail = source.split("movl    $39, %eax", 1)[1].split(
        "# Duplicate the complete clone_args validation", 1
    )[0]
    assert "syscall\n    testq   %rax, %rax\n    jle     .L_getpid_failure\n    movq    16(%r9), %r8" in getpid_tail

    clone_tail = source.split("movl    $435, %eax", 1)[1].split(
        ".Lrecord_failure_preinit:", 1
    )[0]
    assert "jz      .Lchild_path\n\n    # Positive parent branch" in clone_tail
    assert "# Positive parent branch: publish child PID, status, then state last.\n    movq    16(%r9), %r8" in clone_tail

    getppid_tail = source.split("movl    $110, %eax", 1)[1].split(
        "# __NR_execveat", 1
    )[0]
    assert "syscall\n    testq   %rax, %rax\n    jle     .Lchild_exit_127\n    movq    16(%r9), %r8" in getppid_tail


def test_assembled_section_is_exactly_one_page_with_authenticated_trailer():
    with tempfile.TemporaryDirectory(prefix="launch-gate-v1-") as temporary:
        image = _assemble_object(Path(temporary))
    sections = _parse_sections(image)
    gate = _section(sections, ".text.launch_gate_v1")
    page = gate["bytes"]
    assert gate["type"] == 1
    assert gate["flags"] == SHF_ALLOC | SHF_EXECINSTR
    assert gate["align"] == 4096
    assert gate["size"] == 4096
    assert page[:4] == b"\xf3\x0f\x1e\xfa"
    assert page[4095] == 0

    symbols = _symbols(image, sections)
    functions = [
        symbol
        for symbol in symbols
        if symbol["binding"] == STB_GLOBAL and symbol["type"] == STT_FUNC
    ]
    assert [symbol["name"] for symbol in functions] == ["launch_gate_v1"]
    gate_symbol = functions[0]
    code_size = int(gate_symbol["size"])
    assert gate_symbol["value"] == 0
    assert 4 <= code_size < 4095
    assert page[code_size:4095] == b"\xcc" * (4095 - code_size)

    lea = b"\x48\x8d\x35"
    lea_offset = page.find(lea)
    assert lea_offset >= 0
    displacement = struct.unpack_from("<i", page, lea_offset + 3)[0]
    assert lea_offset + 7 + displacement == 4095

    assert not any(section["type"] in (SHT_REL, SHT_RELA) for section in sections)
    allocated = [
        section
        for section in sections
        if int(section["flags"]) & SHF_ALLOC and int(section["size"]) > 0
    ]
    assert [section["name"] for section in allocated] == [".text.launch_gate_v1"]
