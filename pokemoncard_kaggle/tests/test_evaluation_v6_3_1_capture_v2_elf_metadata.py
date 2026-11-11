from __future__ import annotations

import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True)


@pytest.fixture(scope="module")
def elf_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 ELF metadata test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-elf-metadata")
    prefix = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work:rw",
        "-w",
        "/work",
        IMAGE,
    ]
    harness_build = _run(
        prefix
        + [
            "clang++-16",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            "-fexceptions",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/ElfMetadata.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_elf_metadata_harness.cpp",
            "-lpthread",
            "-o",
            "/work/elf-metadata-harness",
        ]
    )
    assert harness_build.returncode == 0, harness_build.stderr

    shared_build = _run(
        prefix
        + [
            "clang++-16",
            "-std=c++20",
            "-shared",
            "-fPIC",
            "/src/tests/native/v631302_elf_fixture.cpp",
            "-Wl,-soname,libclang-cpp.so.16",
            "-Wl,--build-id=0x01020304",
            "-o",
            "/work/libfixture.so",
        ]
    )
    assert shared_build.returncode == 0, shared_build.stderr

    plain_build = _run(
        prefix
        + [
            "clang++-16",
            "-std=c++20",
            "-shared",
            "-fPIC",
            "/src/tests/native/v631302_elf_fixture.cpp",
            "-Wl,--build-id=none",
            "-o",
            "/work/libplain.so",
        ]
    )
    assert plain_build.returncode == 0, plain_build.stderr
    return docker, work


def _harness_run(
    harness: tuple[str, Path], mode: str, filename: str
) -> subprocess.CompletedProcess[str]:
    docker, work = harness
    return _run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "/work/elf-metadata-harness",
            mode,
            f"/work/{filename}",
        ]
    )


def _conflicting_build_id_elf() -> bytes:
    elf_header_size = 64
    program_header_size = 56
    note_offset = elf_header_size + program_header_size

    def note(descriptor: bytes) -> bytes:
        return struct.pack("<III", 4, len(descriptor), 3) + b"GNU\0" + descriptor

    notes = note(b"\x01\x02\x03\x04") + note(b"\x05\x06\x07\x08")
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        elf_header_size,
        0,
        0,
        elf_header_size,
        program_header_size,
        1,
        64,
        0,
        0,
    )
    program = struct.pack(
        "<IIQQQQQQ", 4, 4, note_offset, 0, 0, len(notes), len(notes), 4
    )
    return header + program + notes


def _duplicate_interpreter_elf() -> bytes:
    elf_header_size = 64
    program_header_size = 56
    interpreter = b"/lib64/ld-linux-x86-64.so.2\0"
    first_offset = elf_header_size + 2 * program_header_size
    second_offset = first_offset + len(interpreter)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        elf_header_size,
        0,
        0,
        elf_header_size,
        program_header_size,
        2,
        64,
        0,
        0,
    )
    program = b"".join(
        struct.pack(
            "<IIQQQQQQ", 3, 4, offset, 0, 0, len(interpreter), len(interpreter), 1
        )
        for offset in (first_offset, second_offset)
    )
    return header + program + interpreter + interpreter


def _partially_mapped_string_table_elf() -> bytes:
    elf_header_size = 64
    program_header_size = 56
    program_count = 2
    dynamic_offset = elf_header_size + program_count * program_header_size
    dynamic = b"".join(
        (
            struct.pack("<qQ", 5, 250),
            struct.pack("<qQ", 10, 20),
            struct.pack("<qQ", 14, 0),
            struct.pack("<qQ", 0, 0),
        )
    )
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        elf_header_size,
        0,
        0,
        elf_header_size,
        program_header_size,
        program_count,
        64,
        0,
        0,
    )
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 256, 256, 4096)
    dynamic_header = struct.pack(
        "<IIQQQQQQ",
        2,
        4,
        dynamic_offset,
        dynamic_offset,
        dynamic_offset,
        len(dynamic),
        len(dynamic),
        8,
    )
    image = bytearray(header + load + dynamic_header + dynamic)
    image.extend(bytes(280 - len(image)))
    image[250:258] = b"libx.so\0"
    return bytes(image)


def test_elf_metadata_extracts_exact_soname_and_build_id(
    elf_harness: tuple[str, Path],
) -> None:
    result = _harness_run(elf_harness, "inspect", "libfixture.so")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == (
        "elf_metadata_ok interp= "
        "soname=6c6962636c616e672d6370702e736f2e3136 "
        "build_id=01020304 zero_authority=1\n"
    )


def test_elf_metadata_preserves_absence_as_empty_bytes(
    elf_harness: tuple[str, Path],
) -> None:
    result = _harness_run(elf_harness, "inspect", "libplain.so")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "elf_metadata_ok interp= soname= build_id= zero_authority=1\n"


def test_elf_metadata_extracts_the_executable_interpreter(
    elf_harness: tuple[str, Path],
) -> None:
    result = _harness_run(elf_harness, "inspect", "elf-metadata-harness")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"elf_metadata_ok interp=[0-9a-f]+ soname= build_id=[0-9a-f]* zero_authority=1\n",
        result.stdout,
    )
    interpreter_hex = result.stdout.split("interp=", 1)[1].split(" ", 1)[0]
    assert bytes.fromhex(interpreter_hex).startswith(b"/")


def test_elf_metadata_rejects_conflicting_gnu_build_ids(
    elf_harness: tuple[str, Path],
) -> None:
    _, work = elf_harness
    (work / "conflicting.elf").write_bytes(_conflicting_build_id_elf())
    result = _harness_run(elf_harness, "reject", "conflicting.elf")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"elf_metadata_rejected reject failure=9 zero_authority=1\n", result.stdout
    )


@pytest.mark.parametrize(
    ("filename", "contents"),
    [
        ("duplicate-interpreter.elf", _duplicate_interpreter_elf()),
        ("partial-string-table.elf", _partially_mapped_string_table_elf()),
    ],
)
def test_elf_metadata_rejects_ambiguous_or_unmapped_metadata(
    elf_harness: tuple[str, Path], filename: str, contents: bytes
) -> None:
    _, work = elf_harness
    (work / filename).write_bytes(contents)
    result = _harness_run(elf_harness, "reject", filename)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "elf_metadata_rejected reject failure=9 zero_authority=1\n"


@pytest.mark.parametrize("mode", ["reject", "timeout", "relaxed-limit"])
def test_elf_metadata_fails_closed_on_invalid_input_or_deadline(
    elf_harness: tuple[str, Path], mode: str
) -> None:
    _, work = elf_harness
    if mode == "reject":
        (work / "not-elf.bin").write_bytes(b"not an ELF file")
        filename = "not-elf.bin"
    else:
        filename = "libfixture.so"
    result = _harness_run(elf_harness, mode, filename)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    expected_failure = {"reject": 9, "timeout": 18, "relaxed-limit": 1}[mode]
    assert result.stdout == (
        f"elf_metadata_rejected {mode} failure={expected_failure} zero_authority=1\n"
    )
