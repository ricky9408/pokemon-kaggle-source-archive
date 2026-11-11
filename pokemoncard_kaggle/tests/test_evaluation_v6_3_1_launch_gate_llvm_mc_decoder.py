"""Focused zero-authority checks for the frozen Stage-1 LLVM-MC decoder wire."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp"
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"


def _source() -> str:
    return SOURCE.read_text(encoding="ascii")


def _docker_available() -> bool:
    return subprocess.run(
        ["docker", "image", "inspect", IMAGE], check=False, capture_output=True, text=True
    ).returncode == 0


def test_decoder_uses_llvm16_boundaries_but_no_textual_or_llvm_id_wire_data() -> None:
    source = _source()
    assert "LLVM_VERSION_MAJOR != 16 || LLVM_VERSION_MINOR != 0 || LLVM_VERSION_PATCH != 6" in source
    assert "getInstruction(raw_instance" in source
    assert "MCDisassembler::Success" in source
    assert "normalize(slice(page, offset, llvm_length), offset)" in source
    assert "MCInstPrinter" not in source
    assert "LLVMDisasmInstruction" not in source
    assert "llvm-objdump" not in source
    assert "getName(" not in source
    assert "llvm_opcode" not in source
    assert "register_name" not in source


def test_decoder_fails_closed_on_unpinned_loaded_llvm_implementation() -> None:
    source = _source()
    pinned_digest = ", ".join(
        f"0x{byte:02x}u" for byte in bytes.fromhex(
            "f62d254b7f2bf42df8c8b07d46ee3bb4c2cafeca436b2e6bc6ccbe4581f58f40"
        )
    )
    for marker in (
        "#include <link.h>",
        "::dl_iterate_phdr(observe_loaded_llvm, &observation)",
        'kCanonicalLlvmPath = "/usr/lib/x86_64-linux-gnu/libLLVM-16.so.1"',
        "O_RDONLY | O_CLOEXEC | O_NOFOLLOW",
        "LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_ABSENT",
        "LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_WRONG_PATH",
        "LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_DUPLICATE",
        "LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_HASH_MISMATCH",
        "LAUNCH_GATE_LLVM_MC_RUNTIME_SYMBOL_ORIGIN_INVALID",
        'std::strncmp(basename, "libclang", 8u) == 0',
        '"LLVMInitializeX86TargetInfo"',
        '"LLVMInitializeX86TargetMC"',
        '"LLVMInitializeX86Disassembler"',
        "::dlsym(RTLD_DEFAULT, symbol_name)",
        "::dladdr(symbol, &symbol_info)",
        "verify_loaded_llvm_custody();",
    ):
        assert marker in source
    assert pinned_digest in " ".join(source.split())
    custody_hash = source[
        source.index("std::array<std::uint8_t, 32u> sha256_regular_file"):
        source.index("void verify_loaded_llvm_custody()")
    ]
    assert "IndependentSha256 hasher;" in custody_hash
    assert "llvm::SHA256" not in custody_hash


def test_decoder_binds_closed_wire_schema_and_ordered_set_cfg() -> None:
    source = _source()
    for marker in (
        "constexpr std::uint64_t kProtocolId = 631302u;",
        "constexpr std::uint64_t kCodeSize = 874u;",
        "enum class Opcode",
        "enum class Access",
        "cbor.array(4u); cbor.uint(offset); cbor.uint(instruction.length)",
        "cbor.array(9u);",
        "cbor.array(3u); cbor.uint(block.start);",
        "std::set<std::uint64_t> pending{0u};",
        "std::array<std::int64_t, kCodeSize> owners{}",
        "build_cfg(decoded, flows)",
        "wrapper.array(6u);",
        "wrapper.append(instruction_manifest); wrapper.append(cfg_manifest);",
        "write_exact_output(argv[3], wrapper.value());",
    ):
        assert marker in source
    assert "NORMALIZED_SCHEMA_UNSPECIFIED" not in source
    assert "kExitSchemaContractGap" not in source


def test_decoder_handles_sib_absent_index_as_addressing_no_register_only() -> None:
    source = _source()
    assert "MC NoRegister" in source
    assert "absent_index = index_low == 4u" in source
    assert "index_raw = absent_index ? 0u" in source
    assert "if (absent_index) scale = 1u;" in source
    assert "LAUNCH_GATE_LLVM_MC_RSP_INDEX_FORBIDDEN" in source


def test_decoder_has_fail_closed_output_and_provenance_boundaries() -> None:
    source = _source()
    for marker in (
        "O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW",
        "LAUNCH_GATE_LLVM_MC_OUTPUT_CREATE_FAILED",
        "LAUNCH_GATE_LLVM_MC_PROVENANCE_UNRESOLVED",
        "LAUNCH_GATE_LLVM_MC_GATE_PROVENANCE_INVALID",
        "LAUNCH_GATE_LLVM_MC_DECODE_OVERLAP",
        "LAUNCH_GATE_LLVM_MC_SUCCESSOR_INTERIOR_INVALID",
        "LAUNCH_GATE_LLVM_MC_BLOCK_COVERAGE_INVALID",
    ):
        assert marker in source


def test_diagnostic_compile_in_immutable_image_when_available(tmp_path: Path) -> None:
    if not _docker_available():
        pytest.skip("immutable LLVM16 diagnostic image is unavailable")
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{ROOT}:/work:ro", IMAGE,
            "sh", "-lc",
            " ".join((
                "cd /tmp;",
                "/usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu",
                "-std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti",
                "-fno-ident -fvisibility=hidden -ffile-prefix-map=/work=.",
                "-fmacro-prefix-map=/work=. -I/opt/llvm-build/include -I/opt/llvm-src/llvm/include -c",
                "/work/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp",
                "-o launch_gate_llvm_mc_decoder_v1.o",
            )),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_diagnostic_current_gate_decode_is_canonical_but_has_zero_authority(
    tmp_path: Path,
) -> None:
    """Exercise one current-page diagnostic run, not a production evidence path."""
    if not _docker_available():
        pytest.skip("immutable LLVM16 diagnostic image is unavailable")
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--platform", "linux/amd64",
            "-v", f"{ROOT}:/repo:ro", "-v", f"{tmp_path}:/work", IMAGE,
            "sh", "-lc",
            " ".join((
                "set -eu;",
                "mkdir -p /work/stage1/gate-extract;",
                "chmod 700 /work/stage1 /work/stage1/gate-extract;",
                "cd /work/stage1/gate-extract;",
                "/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c",
                "/repo/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S -o LaunchGateV1.o;",
                "chmod 444 LaunchGateV1.o;",
                "/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 HOME=/nonexistent DEBUGINFOD_URLS=",
                "/usr/bin/objcopy --input-target=elf64-x86-64 --output-target=elf64-x86-64 --dump-section",
                ".text.launch_gate_v1=LaunchGateV1.page.tmp LaunchGateV1.o LaunchGateV1.objcopy-discard.o;",
                "/usr/bin/clang++-16 --target=x86_64-unknown-linux-gnu -std=c++20 -O2",
                "-fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -fvisibility=hidden",
                "-I/opt/llvm-build/include -I/opt/llvm-src/llvm/include",
                "/repo/evaluation_v6_3_1/native/capture_v2/tools/launch_gate_llvm_mc_decoder_v1.cpp",
                "/usr/lib/x86_64-linux-gnu/libLLVM-16.so.1 -ldl -lz -ltinfo -o decoder;",
                "./decoder LaunchGateV1.page.tmp 874 /work/decoder.cbor;",
                "cp /usr/lib/x86_64-linux-gnu/libLLVM-16.so.1 /work/libLLVM-16.so.1;",
                "if LD_PRELOAD=/work/libLLVM-16.so.1 ./decoder LaunchGateV1.page.tmp 874 /work/preloaded.cbor 2>/work/preloaded.stderr; then exit 1; fi;",
                "test ! -e /work/preloaded.cbor;",
                "grep -qx LAUNCH_GATE_LLVM_MC_RUNTIME_LIBRARY_WRONG_PATH /work/preloaded.stderr",
            )),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    raw = (tmp_path / "decoder.cbor").read_bytes()
    decoded = canonical_cbor_decode(raw)
    assert canonical_cbor_encode(decoded) == raw
    assert decoded[:4] == [631302, 1, bytes.fromhex("91fce3ca09e908b9e51d73e887f67a14ba7b5c250180cb613f871666f12277f5"), 874]
    assert isinstance(decoded[4], list) and isinstance(decoded[5], list)
    assert [row[0] for row in decoded[4]] == sorted(row[0] for row in decoded[4])
    assert [row[0] for row in decoded[5]] == sorted(row[0] for row in decoded[5])
