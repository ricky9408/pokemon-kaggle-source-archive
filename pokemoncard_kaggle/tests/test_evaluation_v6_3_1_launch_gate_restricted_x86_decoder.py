"""Focused checks for the independent, zero-authority restricted x86 decoder."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evaluation_v6_3_1/native/capture_v2/tools/launch_gate_restricted_x86_decoder_v1.cpp"
ASSEMBLY = ROOT / "evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S"


def _source() -> str:
    return SOURCE.read_text(encoding="ascii")


def _compiler() -> str | None:
    return shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")


def _build_binary(tmp_path: Path) -> Path:
    compiler = _compiler()
    if compiler is None:
        pytest.skip("no C++ compiler available")
    binary = tmp_path / "launch_gate_restricted_x86_decoder_v1"
    result = subprocess.run(
        [compiler, "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(binary)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return binary


def _gate_page(tmp_path: Path) -> Path:
    clang = shutil.which("clang")
    objcopy = shutil.which("objcopy")
    obj = tmp_path / "LaunchGateV1.o"
    page = tmp_path / "LaunchGateV1.page"
    if clang is None or objcopy is None:
        if shutil.which("docker") is None:
            pytest.skip("clang/GNU objcopy or the pinned Linux diagnostic image is required")
        generated = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{ROOT}:/work:ro",
                "-v",
                f"{tmp_path}:/out",
                "pokemon-v631302-clang16-dev:20260802",
                "sh",
                "-lc",
                "/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler "
                "-fintegrated-as -Wa,--noexecstack /work/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S "
                "-o /out/LaunchGateV1.o && "
                "objcopy -O binary --only-section=.text.launch_gate_v1 /out/LaunchGateV1.o /out/LaunchGateV1.page",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert generated.returncode == 0, generated.stderr
        assert page.stat().st_size == 4096
        return page
    assembled = subprocess.run(
        [
            clang,
            "--target=x86_64-unknown-linux-gnu",
            "-c",
            "-x",
            "assembler",
            "-fintegrated-as",
            "-Wa,--noexecstack",
            str(ASSEMBLY),
            "-o",
            str(obj),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert assembled.returncode == 0, assembled.stderr
    extracted = subprocess.run(
        [objcopy, "-O", "binary", "--only-section=.text.launch_gate_v1", str(obj), str(page)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert extracted.returncode == 0, extracted.stderr
    assert page.stat().st_size == 4096
    return page


def _run(binary: Path, page: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), str(page), "874", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )


def _read_head(data: bytes) -> tuple[int, int, bytes, int]:
    # The fixed wrapper begins [631302, 1, bytes(32), 874, ...].
    assert data[0] == 0x86
    assert data[1] == 0x1A
    assert int.from_bytes(data[2:6], "big") == 631302
    assert data[6] == 0x01
    assert data[7] == 0x58
    assert data[8] == 0x20
    page_hash = data[9:41]
    assert len(page_hash) == 32
    assert data[41] == 0x19
    assert int.from_bytes(data[42:44], "big") == 874
    return 631302, 1, page_hash, 874


def test_source_is_standalone_restricted_decoder_with_its_own_cbor_and_no_llvm_or_text_path():
    source = _source()
    for marker in (
        "recursively_decode",
        "build_cfg",
        "class Cbor final",
        "class Sha256 final",
        "LAUNCH_GATE_RESTRICTED_X86_PROVENANCE_UNKNOWN",
        "LAUNCH_GATE_RESTRICTED_X86_OPCODE_FORBIDDEN",
        "LAUNCH_GATE_RESTRICTED_X86_REDUNDANT_REX",
        "constexpr bool kZeroAuthority = true;",
        "Zero-authority diagnostic output only.",
    ):
        assert marker in source
    for forbidden in (
        "llvm/",
        "LLVM",
        "launch_gate_llvm_mc_decoder",
        "objdump",
        "disassembly text",
        "system(",
        "popen(",
    ):
        assert forbidden not in source


def test_source_fixes_closed_wire_ids_and_rejects_unknown_forms():
    source = _source()
    for marker in (
        "constexpr std::uint64_t kCodeSize = 874u;",
        "enum class Opcode",
        "Endbr64 = 1",
        "Ret = 10",
        "kAttrOpcodeMap0f",
        "kAttrDest32ZeroExtend",
        "LAUNCH_GATE_RESTRICTED_X86_HIGH_BYTE_REGISTER_FORBIDDEN",
        "LAUNCH_GATE_RESTRICTED_X86_ABSOLUTE_ADDRESS_FORBIDDEN",
        "LAUNCH_GATE_RESTRICTED_X86_BRANCH_INSTRUCTION_INTERIOR",
        "LAUNCH_GATE_RESTRICTED_X86_REACHABILITY_COVERAGE_INCOMPLETE",
    ):
        assert marker in source
    assert "return 0; // Zero-authority diagnostic output only." in source


def test_local_diagnostic_decodes_gate_and_mutations_fail_closed(tmp_path: Path):
    binary = _build_binary(tmp_path)
    page = _gate_page(tmp_path)
    output = tmp_path / "manifest.cbor"
    result = _run(binary, page, output)
    assert result.returncode == 0, result.stderr
    data = output.read_bytes()
    assert len(data) > 43
    assert _read_head(data)[:2] == (631302, 1)
    assert _read_head(data)[2] == hashlib.sha256(page.read_bytes()).digest()
    assert not data.endswith(b"\n")

    malformed_prefix = tmp_path / "bad-prefix.page"
    prefix_bytes = bytearray(page.read_bytes())
    prefix_bytes[0] = 0xF2
    malformed_prefix.write_bytes(prefix_bytes)
    rejected_prefix = _run(binary, malformed_prefix, tmp_path / "bad-prefix.cbor")
    assert rejected_prefix.returncode == 65
    assert "LAUNCH_GATE_RESTRICTED_X86_PREFIX_FORBIDDEN" in rejected_prefix.stderr

    malformed_trailer = tmp_path / "bad-trailer.page"
    trailer_bytes = bytearray(page.read_bytes())
    trailer_bytes[874] = 0
    malformed_trailer.write_bytes(trailer_bytes)
    rejected_trailer = _run(binary, malformed_trailer, tmp_path / "bad-trailer.cbor")
    assert rejected_trailer.returncode == 65
    assert "LAUNCH_GATE_RESTRICTED_X86_TRAILER_INVALID" in rejected_trailer.stderr


def test_output_path_rejects_preexisting_file_without_mutation(tmp_path: Path):
    binary = _build_binary(tmp_path)
    page = _gate_page(tmp_path)
    output = tmp_path / "preexisting.cbor"
    original = b"do not replace this file\n"
    output.write_bytes(original)

    result = _run(binary, page, output)

    assert result.returncode == 74
    assert "LAUNCH_GATE_RESTRICTED_X86_OUTPUT_OPEN_FAILED" in result.stderr
    assert output.read_bytes() == original


def test_output_path_rejects_symlink_without_following_or_mutating_target(tmp_path: Path):
    binary = _build_binary(tmp_path)
    page = _gate_page(tmp_path)
    target = tmp_path / "symlink-target.cbor"
    target_bytes = b"keep the symlink target unchanged\n"
    target.write_bytes(target_bytes)
    output = tmp_path / "symlink.cbor"
    output.symlink_to(target)

    result = _run(binary, page, output)

    assert result.returncode == 74
    assert "LAUNCH_GATE_RESTRICTED_X86_OUTPUT_OPEN_FAILED" in result.stderr
    assert output.is_symlink()
    assert output.read_bytes() == target_bytes
    assert target.read_bytes() == target_bytes


def test_linux_amd64_diagnostic_compile_when_docker_is_available(tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("docker is unavailable")
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            f"{ROOT}:/work:ro",
            "pokemon-v631302-clang16-dev:20260802",
            "sh",
            "-lc",
            "/usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu -std=c++20 -O2 -Wall -Wextra -Werror "
            "/work/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_restricted_x86_decoder_v1.cpp "
            "-o /tmp/launch_gate_restricted_x86_decoder_v1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
