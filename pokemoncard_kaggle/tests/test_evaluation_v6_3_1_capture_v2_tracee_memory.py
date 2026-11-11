from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True)


@pytest.fixture(scope="module")
def tracee_memory_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 tracee-memory test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-tracee-memory")
    prefix = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "--security-opt",
        "seccomp=unconfined",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work:rw",
        "-w",
        "/work",
        IMAGE,
    ]
    compile_result = _run(
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
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/TraceeMemory.cpp",
            "/src/tests/native/v631302_tracee_memory_harness.cpp",
            "-o",
            "/work/tracee-memory-harness",
        ]
    )
    assert compile_result.returncode == 0, compile_result.stderr
    return docker, work


def test_tracee_memory_strict_linux_amd64(
    tracee_memory_harness: tuple[str, Path],
) -> None:
    docker, work = tracee_memory_harness
    result = _run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--security-opt",
            "seccomp=unconfined",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "/work/tracee-memory-harness",
        ]
    )
    if result.returncode == 77:
        assert result.stdout.startswith(
            "tracee_memory_harness_skipped process_vm_readv_unavailable=1 errno="
        ), (result.stdout, result.stderr)
        pytest.skip("the Docker Linux/amd64 kernel forbids process_vm_readv")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "tracee_memory_harness_ok zero_authority=1\n"
