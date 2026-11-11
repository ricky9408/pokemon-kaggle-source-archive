from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
NATIVE = ROOT / "evaluation_v6_3_1/native/capture_v2"
SOURCE = NATIVE / "Stage1ExtractionChildGateV1.S"
HEADER = NATIVE / "Stage1ExtractionChildGateV1.h"
HARNESS = ROOT / "tests/native/Stage1ExtractionChildGateLinkHarness.cpp"
SECTION = ".text.stage1_extraction_child_gate_v1"
SYMBOL = "stage1_extraction_child_gate_v1"
CANDIDATE_GATE_SHA256 = "74008569477e71db4d4d94ae10d7958395115b3f03645e0d964825673021a2f3"

ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SYMBOL_ENTRY = struct.Struct("<IBBHQQ")
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_REL = 9
SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4
SECCOMP_SHA256 = "123051e7323f8daef935d7ee73ef62fff8117c6a035c75e99c919cf8a900d7a6"


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = _run([docker, "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"])
    return result.returncode == 0 and result.stdout.strip() == f"{IMAGE} amd64"


@pytest.fixture(scope="module")
def gate_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-extraction-child-gate")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -fno-optimize-sibling-calls -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -I/repo/evaluation_v6_3_1/native/capture_v2'
/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler -fintegrated-as -Wa,--noexecstack /repo/evaluation_v6_3_1/native/capture_v2/Stage1ExtractionChildGateV1.S -o /out/Stage1ExtractionChildGateV1.o
/usr/bin/clang++-16 $flags -c /repo/tests/native/Stage1ExtractionChildGateLinkHarness.cpp -o /out/link-harness.o
/usr/bin/g++ -static-pie -Wl,--build-id=none -Wl,-z,noexecstack /out/Stage1ExtractionChildGateV1.o /out/link-harness.o -o /out/link-harness
objdump -d /out/Stage1ExtractionChildGateV1.o > /out/object.disassembly
objdump -d /out/link-harness > /out/linked.disassembly
chmod 0444 /out/Stage1ExtractionChildGateV1.o /out/object.disassembly /out/linked.disassembly
chmod 0555 /out/link-harness
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={ROOT},dst=/repo,readonly",
            "--mount",
            f"type=bind,src={output},dst=/out",
            IMAGE,
            "/bin/sh",
            "-lc",
            script,
        ]
    )
    assert result.returncode == 0, result.stderr
    return (
        output / "Stage1ExtractionChildGateV1.o",
        output / "link-harness",
        output / "object.disassembly",
    )


@pytest.fixture(scope="module")
def custodian_gate_artifacts(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path, Path]:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-custodian-child-gate")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -fno-optimize-sibling-calls -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -I/repo/evaluation_v6_3_1/native/capture_v2'
/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler -fintegrated-as -Wa,--noexecstack /repo/evaluation_v6_3_1/native/capture_v2/Stage1ExtractionChildGateV1.S -o /out/Stage1ExtractionChildGateV1.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1ExtractionCustodianV1.cpp -o /out/custodian.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1SeccompFilterV1.cpp -o /out/seccomp.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1PidfdChildLifecycleV1.cpp -o /out/pidfd.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/tools/stage1_extraction_custodian_v1_main.cpp -o /out/main.o
/usr/bin/g++ -static-pie -Wl,--build-id=none -Wl,-z,noexecstack /out/custodian.o /out/seccomp.o /out/pidfd.o /out/Stage1ExtractionChildGateV1.o /out/main.o -o /out/Stage1ExtractionCustodianV1
objdump -d /out/Stage1ExtractionCustodianV1 > /out/custodian.disassembly
chmod 0444 /out/Stage1ExtractionChildGateV1.o /out/custodian.disassembly
chmod 0555 /out/Stage1ExtractionCustodianV1
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={ROOT},dst=/repo,readonly",
            "--mount",
            f"type=bind,src={output},dst=/out",
            IMAGE,
            "/bin/sh",
            "-lc",
            script,
        ]
    )
    assert result.returncode == 0, result.stderr
    return (
        output / "Stage1ExtractionChildGateV1.o",
        output / "Stage1ExtractionCustodianV1",
        output / "custodian.disassembly",
    )


@dataclass(frozen=True)
class _Section:
    index: int
    name: str
    type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class _Symbol:
    name: str
    info: int
    visibility: int
    section_index: int
    value: int
    size: int


@dataclass(frozen=True)
class _Elf:
    bytes_value: bytes
    file_type: int
    machine: int
    sections: tuple[_Section, ...]
    symbols: tuple[_Symbol, ...]
    program_headers: tuple[tuple[int, int, int, int, int, int, int, int], ...]


def _cstring(table: bytes, offset: int) -> str:
    assert 0 <= offset < len(table)
    end = table.find(b"\0", offset)
    assert end >= 0
    return table[offset:end].decode("ascii")


def _parse_elf(path: Path) -> _Elf:
    data = path.read_bytes()
    assert len(data) >= ELF_HEADER.size
    values = ELF_HEADER.unpack_from(data)
    ident = values[0]
    assert ident[:7] == b"\x7fELF\x02\x01\x01"
    file_type, machine = values[1:3]
    program_offset, section_offset = values[5:7]
    program_entry_size, program_count = values[9:11]
    section_entry_size, section_count, section_names_index = values[11:14]
    assert section_entry_size == SECTION_HEADER.size
    raw_sections = [
        SECTION_HEADER.unpack_from(data, section_offset + index * section_entry_size)
        for index in range(section_count)
    ]
    names_header = raw_sections[section_names_index]
    names = data[names_header[4] : names_header[4] + names_header[5]]
    sections = tuple(
        _Section(
            index=index,
            name=_cstring(names, row[0]) if row[0] else "",
            type=row[1],
            flags=row[2],
            address=row[3],
            offset=row[4],
            size=row[5],
            link=row[6],
            info=row[7],
            alignment=row[8],
            entry_size=row[9],
        )
        for index, row in enumerate(raw_sections)
    )
    symbols: list[_Symbol] = []
    for section in sections:
        if section.type != SHT_SYMTAB:
            continue
        assert section.entry_size == SYMBOL_ENTRY.size
        string_section = sections[section.link]
        strings = data[string_section.offset : string_section.offset + string_section.size]
        assert section.size % section.entry_size == 0
        for offset in range(section.offset, section.offset + section.size, section.entry_size):
            name, info, other, index, value, size = SYMBOL_ENTRY.unpack_from(data, offset)
            symbols.append(
                _Symbol(
                    name=_cstring(strings, name) if name else "",
                    info=info,
                    visibility=other & 0x3,
                    section_index=index,
                    value=value,
                    size=size,
                )
            )
    program_headers: list[tuple[int, int, int, int, int, int, int, int]] = []
    if program_count:
        assert program_entry_size == PROGRAM_HEADER.size
        program_headers = [
            PROGRAM_HEADER.unpack_from(data, program_offset + index * program_entry_size)
            for index in range(program_count)
        ]
    return _Elf(data, file_type, machine, sections, tuple(symbols), tuple(program_headers))


def _section_bytes(elf: _Elf, section: _Section) -> bytes:
    return elf.bytes_value[section.offset : section.offset + section.size]


def _symbol_bytes(elf: _Elf, symbol: _Symbol) -> bytes:
    section = elf.sections[symbol.section_index]
    offset = section.offset + symbol.value - section.address
    return elf.bytes_value[offset : offset + symbol.size]


def _target(elf: _Elf) -> tuple[_Section, _Symbol]:
    sections = [section for section in elf.sections if section.name == SECTION]
    assert len(sections) == 1
    return sections[0], _target_symbol(elf)


def _target_symbol(elf: _Elf) -> _Symbol:
    symbols = [symbol for symbol in elf.symbols if symbol.name == SYMBOL]
    assert len(symbols) == 1
    return symbols[0]


def test_private_abi_is_explicitly_candidate_only_and_layout_bound() -> None:
    header = HEADER.read_text(encoding="ascii")
    assert "kStage1ExtractionChildGateCandidateOnly = true" in header
    assert "kStage1ExtractionChildGateAuthority = false" in header
    assert "sizeof(Stage1ExtractionChildGateInputV1) == 128u" in header
    assert "sizeof(Stage1ExtractionChildGateResultV1) == 24u" in header
    assert "parent_receipt_saved_fd" in header
    assert "parent_diagnostic_saved_fd" in header
    assert "extern \"C\" long stage1_extraction_child_gate_v1" in header


@pytest.mark.docker_smoke
def test_gate_object_has_one_exact_hidden_function_and_no_relocations(
    gate_artifacts: tuple[Path, Path, Path],
) -> None:
    object_path, _, _ = gate_artifacts
    elf = _parse_elf(object_path)
    section, symbol = _target(elf)
    assert elf.file_type == 1
    assert elf.machine == 62
    assert section.flags == SHF_ALLOC | SHF_EXECINSTR
    assert section.alignment == 64
    assert section.size > 0
    assert symbol.section_index == section.index
    assert symbol.value == 0
    assert symbol.size == section.size
    assert symbol.info >> 4 == 1
    assert symbol.info & 0xF == 2
    assert symbol.visibility == 2
    assert all(
        candidate.type not in {SHT_REL, SHT_RELA} or candidate.info != section.index
        for candidate in elf.sections
    )
    assert [candidate.name for candidate in elf.symbols if candidate.name] == [SYMBOL]
    assert hashlib.sha256(_section_bytes(elf, section)).hexdigest() == CANDIDATE_GATE_SHA256


@pytest.mark.docker_smoke
def test_linked_gate_bytes_are_identical_and_live_in_one_nonwritable_rx_load(
    gate_artifacts: tuple[Path, Path, Path],
) -> None:
    object_path, linked_path, _ = gate_artifacts
    object_elf = _parse_elf(object_path)
    linked_elf = _parse_elf(linked_path)
    _, object_symbol = _target(object_elf)
    linked_symbol = _target_symbol(linked_elf)
    object_bytes = _symbol_bytes(object_elf, object_symbol)
    linked_bytes = _symbol_bytes(linked_elf, linked_symbol)
    assert linked_bytes == object_bytes
    containing = [
        row
        for row in linked_elf.program_headers
        if row[0] == PT_LOAD
        and row[3] <= linked_symbol.value
        and linked_symbol.value + linked_symbol.size <= row[3] + row[6]
    ]
    assert len(containing) == 1
    assert containing[0][1] & PF_X
    assert not containing[0][1] & PF_W
    assert not any(
        candidate.name != SYMBOL
        and candidate.section_index != 0
        and linked_symbol.value < candidate.value < linked_symbol.value + linked_symbol.size
        for candidate in linked_elf.symbols
    )


@pytest.mark.docker_smoke
def test_actual_custodian_link_preserves_gate_bytes_and_has_one_inbound_call(
    custodian_gate_artifacts: tuple[Path, Path, Path],
) -> None:
    object_path, custodian_path, disassembly_path = custodian_gate_artifacts
    object_elf = _parse_elf(object_path)
    custodian_elf = _parse_elf(custodian_path)
    _, object_symbol = _target(object_elf)
    linked_symbol = _target_symbol(custodian_elf)
    assert _symbol_bytes(custodian_elf, linked_symbol) == _symbol_bytes(object_elf, object_symbol)
    assert hashlib.sha256(_symbol_bytes(custodian_elf, linked_symbol)).hexdigest() == CANDIDATE_GATE_SHA256
    containing = [
        row
        for row in custodian_elf.program_headers
        if row[0] == PT_LOAD
        and row[3] <= linked_symbol.value
        and linked_symbol.value + linked_symbol.size <= row[3] + row[6]
    ]
    assert len(containing) == 1
    assert containing[0][1] & PF_X
    assert not containing[0][1] & PF_W
    assert not any(
        candidate.name != SYMBOL
        and candidate.section_index != 0
        and linked_symbol.value < candidate.value < linked_symbol.value + linked_symbol.size
        for candidate in custodian_elf.symbols
    )
    disassembly = disassembly_path.read_text(encoding="ascii")
    inbound = [
        line
        for line in disassembly.splitlines()
        if re.search(r"\bcall\w*\s+[^<]*<stage1_extraction_child_gate_v1>", line)
    ]
    assert len(inbound) == 1
    linked_rows = _instructions(disassembly)
    inbound_control_flow = [
        (address, mnemonic, target)
        for address, (mnemonic, _, target) in linked_rows.items()
        if not (linked_symbol.value <= address < linked_symbol.value + linked_symbol.size)
        and target is not None
        and linked_symbol.value <= target < linked_symbol.value + linked_symbol.size
    ]
    assert len(inbound_control_flow) == 1
    assert inbound_control_flow[0][1].startswith("call")
    assert inbound_control_flow[0][2] == linked_symbol.value


@pytest.mark.docker_smoke
def test_actual_custodian_link_places_exact_seccomp_bytes_in_one_read_only_load(
    custodian_gate_artifacts: tuple[Path, Path, Path],
) -> None:
    _, custodian_path, _ = custodian_gate_artifacts
    elf = _parse_elf(custodian_path)
    candidates = [
        symbol
        for symbol in elf.symbols
        if "kStage1SeccompFilterV1" in symbol.name
    ]
    assert len(candidates) == 1
    symbol = candidates[0]
    assert symbol.size == 344
    assert hashlib.sha256(_symbol_bytes(elf, symbol)).hexdigest() == SECCOMP_SHA256
    containing = [
        row
        for row in elf.program_headers
        if row[0] == PT_LOAD
        and row[3] <= symbol.value
        and symbol.value + symbol.size <= row[3] + row[6]
    ]
    assert len(containing) == 1
    assert containing[0][1] & PF_R
    assert not containing[0][1] & PF_W


def _instructions(disassembly: str) -> dict[int, tuple[str, str, int | None]]:
    rows: dict[int, tuple[str, str, int | None]] = {}
    pattern = re.compile(
        r"^\s*([0-9a-f]+):\s+(?:(?:[0-9a-f]{2})\s+)+\s*([a-z][a-z0-9]*)\s*(.*?)\s*$"
    )
    for line in disassembly.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        operand = match.group(3)
        target_match = re.match(r"([0-9a-f]+)\s+<", operand)
        target = int(target_match.group(1), 16) if target_match else None
        rows[address] = (mnemonic, operand, target)
    return rows


def _reachable(
    rows: dict[int, tuple[str, str, int | None]],
    start: int,
    range_start: int,
    range_end: int,
) -> set[int]:
    ordered = sorted(rows)
    following = {first: second for first, second in zip(ordered, ordered[1:])}
    result: set[int] = set()
    pending = [start]
    while pending:
        address = pending.pop()
        if address in result:
            continue
        assert range_start <= address < range_end
        assert address in rows
        result.add(address)
        mnemonic, _, target = rows[address]
        if mnemonic in {"ret", "ud2"}:
            continue
        if mnemonic == "jmp":
            assert target is not None and range_start <= target < range_end
            pending.append(target)
            continue
        if mnemonic.startswith("j"):
            assert target is not None and range_start <= target < range_end
            pending.append(target)
            assert address in following and following[address] < range_end
            pending.append(following[address])
            continue
        assert address in following and following[address] < range_end
        pending.append(following[address])
    return result


def _find_unique_instruction(
    rows: dict[int, tuple[str, str, int | None]],
    mnemonic: str,
    operand: str,
) -> int:
    matches = [
        address
        for address, (actual_mnemonic, actual_operand, _) in rows.items()
        if actual_mnemonic == mnemonic and actual_operand == operand
    ]
    assert len(matches) == 1
    return matches[0]


def _syscall_numbers(rows: dict[int, tuple[str, str, int | None]]) -> tuple[int, ...]:
    ordered = sorted(rows)
    numbers: list[int] = []
    for offset, address in enumerate(ordered):
        if rows[address][0] != "syscall":
            continue
        number: int | None = None
        for previous in reversed(ordered[:offset]):
            mnemonic, operand, _ = rows[previous]
            if mnemonic == "syscall":
                break
            if operand.endswith(",%eax"):
                if mnemonic == "xor" and operand == "%eax,%eax":
                    number = 0
                    break
                if mnemonic == "mov" and operand.startswith("$0x"):
                    number = int(operand[1:].split(",", 1)[0], 16)
                    break
        assert number is not None
        numbers.append(number)
    return tuple(numbers)


def _gate_semantics_are_exact(
    rows: dict[int, tuple[str, str, int | None]],
) -> bool:
    try:
        ordered = sorted(rows)
        assert _syscall_numbers(rows) == (
            435,
            3,
            3,
            3,
            3,
            3,
            3,
            0,
            81,
            332,
            157,
            317,
            1,
            0,
            322,
            231,
        )
        for operand in (
            "0x14(%r12),%rdi",
            "0x18(%r12),%rdi",
            "0x20(%r12),%rdi",
            "0x24(%r12),%rdi",
            "0x28(%r12),%rdi",
            "0x2c(%r12),%rdi",
        ):
            _find_unique_instruction(rows, "movslq", operand)
        for mnemonic, operand in (
            ("push", "%r12"),
            ("push", "%r13"),
            ("pop", "%r13"),
            ("pop", "%r12"),
            ("cmpb", "$0x47,(%rsi)"),
            ("movslq", "0x30(%r12),%rdi"),
            ("mov", "0x40(%r12),%r8"),
            ("mov", "$0xffffffffffffff9c,%rdi"),
            ("mov", "$0x1000,%edx"),
            ("mov", "$0x17ff,%r10d"),
            ("cmp", "0x68(%r12),%rax"),
            ("cmp", "0x70(%r12),%rax"),
            ("cmp", "0x78(%r12),%eax"),
            ("cmp", "0x7c(%r12),%eax"),
            ("mov", "$0x26,%edi"),
            ("mov", "$0x1,%esi"),
            ("mov", "0x50(%r12),%rdx"),
            ("movb", "$0x52,(%rsi)"),
            ("movslq", "0x1c(%r12),%rdi"),
            ("cmpb", "$0x43,(%rsi)"),
            ("movslq", "0x34(%r12),%rdi"),
            ("mov", "0x58(%r12),%rdx"),
            ("mov", "0x60(%r12),%r10"),
            ("mov", "$0x1000,%r8d"),
            ("mov", "$0x7f,%edi"),
        ):
            _find_unique_instruction(rows, mnemonic, operand)
        assert sum(
            1
            for mnemonic, operand, _ in rows.values()
            if mnemonic == "mov" and operand == "0x38(%r12),%rsi"
        ) == 5
        assert sum(
            1
            for mnemonic, operand, _ in rows.values()
            if mnemonic == "mov" and operand == "0x48(%r12),%rsi"
        ) == 2
        assert rows[ordered[-1]][0] == "ud2"
        return True
    except (AssertionError, ValueError):
        return False


@pytest.mark.docker_smoke
def test_gate_control_flow_has_one_parent_ret_and_no_child_path_to_it(
    gate_artifacts: tuple[Path, Path, Path],
) -> None:
    object_path, _, disassembly_path = gate_artifacts
    object_elf = _parse_elf(object_path)
    _, symbol = _target(object_elf)
    rows = _instructions(disassembly_path.read_text(encoding="ascii"))
    assert rows
    assert not any(mnemonic.startswith("call") for mnemonic, _, _ in rows.values())
    assert not any(
        mnemonic == "jmp" and (target is None or "*" in operand)
        for mnemonic, operand, target in rows.values()
    )
    rets = [address for address, (mnemonic, _, _) in rows.items() if mnemonic == "ret"]
    assert len(rets) == 1
    clone_syscalls = [
        address
        for address, (mnemonic, _, _) in rows.items()
        if mnemonic == "syscall"
        and any(
            previous < address
            and rows[previous][0] == "mov"
            and "$0x1b3,%eax" in rows[previous][1]
            for previous in rows
        )
    ]
    assert clone_syscalls
    clone_address = min(clone_syscalls)
    ordered_after = [address for address in sorted(rows) if address > clone_address]
    zero_branches = [
        target
        for address in ordered_after[:6]
        for mnemonic, _, target in [rows[address]]
        if mnemonic in {"je", "jz"} and target is not None
    ]
    assert len(zero_branches) == 1
    child_reachable = _reachable(rows, zero_branches[0], symbol.value, symbol.value + symbol.size)
    assert rets[0] not in child_reachable
    assert any(rows[address][0] == "ud2" for address in child_reachable)
    assert all(
        target is None or target in rows
        for mnemonic, _, target in rows.values()
        if mnemonic.startswith("j")
    )


@pytest.mark.docker_smoke
def test_gate_machine_code_has_the_exact_ordered_syscall_and_private_abi_semantics(
    gate_artifacts: tuple[Path, Path, Path],
) -> None:
    _, _, disassembly_path = gate_artifacts
    rows = _instructions(disassembly_path.read_text(encoding="ascii"))
    assert _gate_semantics_are_exact(rows)


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("mnemonic", "operand", "replacement"),
    [
        ("mov", "$0x1b3,%eax", "$0x39,%eax"),
        ("movslq", "0x14(%r12),%rdi", "0x10(%r12),%rdi"),
        ("mov", "0x50(%r12),%rdx", "0x48(%r12),%rdx"),
        ("cmpb", "$0x43,(%rsi)", "$0x44,(%rsi)"),
        ("pop", "%r13", "%r12"),
    ],
)
def test_gate_semantic_validator_rejects_targeted_machine_code_mutations(
    gate_artifacts: tuple[Path, Path, Path],
    mnemonic: str,
    operand: str,
    replacement: str,
) -> None:
    _, _, disassembly_path = gate_artifacts
    rows = _instructions(disassembly_path.read_text(encoding="ascii"))
    address = _find_unique_instruction(rows, mnemonic, operand)
    mutated = dict(rows)
    mutated[address] = (mnemonic, replacement, rows[address][2])
    assert not _gate_semantics_are_exact(mutated)


@pytest.mark.docker_smoke
def test_negative_parent_return_preserves_callee_saved_registers(
    gate_artifacts: tuple[Path, Path, Path],
) -> None:
    _, linked_path, _ = gate_artifacts
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={linked_path.parent},dst=/out,readonly",
            IMAGE,
            "/out/link-harness",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_source_contains_only_one_gate_and_never_reuses_later_launch_gate() -> None:
    source = SOURCE.read_text(encoding="ascii")
    assert source.count(".globl stage1_extraction_child_gate_v1") == 1
    assert source.count("\n    ret\n") == 1
    assert "call" not in source.lower().replace("syscall", "")
    assert "LaunchGateV1" not in source
    assert "waitpid" not in source
    assert "fork" not in source.lower()
    child_close_prefix = source.split(".Lchild:", 1)[1].split(
        "# Consume the exact parent release byte", 1
    )[0]
    assert child_close_prefix.count("movl $3, %eax") == 6
    for offset in (20, 24, 32, 36, 40, 44):
        assert f"movslq {offset}(%r12), %rdi" in child_close_prefix
