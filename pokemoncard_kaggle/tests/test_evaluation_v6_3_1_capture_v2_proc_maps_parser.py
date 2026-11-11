from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True)


@pytest.fixture(scope="module")
def maps_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 proc-maps test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")
    work = tmp_path_factory.mktemp("capture-v2-proc-maps")
    result = _run(
        [
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
            "/src/evaluation_v6_3_1/native/capture_v2/ProcMapsParser.cpp",
            "/src/tests/native/v631302_proc_maps_parser_harness.cpp",
            "-o",
            "/work/proc-maps-harness",
        ]
    )
    assert result.returncode == 0, result.stderr
    return docker, work


def _harness_run(
    harness: tuple[str, Path], mode: str
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
            "/work/proc-maps-harness",
            mode,
        ]
    )


def test_proc_maps_parser_extracts_only_file_backed_executable_rows(
    maps_harness: tuple[str, Path],
) -> None:
    result = _harness_run(maps_harness, "valid")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == (
        "proc_maps_ok rows=2 first_offset=4096 "
        "second_path=/lib/libclang-cpp.so.16 zero_authority=1\n"
    )


@pytest.mark.parametrize(
    "mode",
    [
        "deleted",
        "nonabsolute",
        "escape",
        "order",
        "duplicate-start",
        "overlap",
        "unterminated",
    ],
)
def test_proc_maps_parser_fails_closed_on_ambiguous_snapshots(
    maps_harness: tuple[str, Path], mode: str
) -> None:
    result = _harness_run(maps_harness, mode)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    assert re.fullmatch(
        rf"proc_maps_rejected {mode} failure=9 zero_authority=1\n", result.stdout
    )
