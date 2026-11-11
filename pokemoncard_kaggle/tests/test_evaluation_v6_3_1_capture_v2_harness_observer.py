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
def harness_observer_binaries(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 HarnessObserver test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-harness-observer")
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
    sources = [
        "/src/evaluation_v6_3_1/native/capture_v2/HarnessObserver.cpp",
        "/src/evaluation_v6_3_1/native/capture_v2/ElfMetadata.cpp",
        "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
        "/src/tests/native/v631302_harness_observer_harness.cpp",
    ]
    result = _run(
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
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            *sources,
            "-L/opt/llvm-build/lib",
            "-lLLVMSupport",
            "-lLLVMDemangle",
            "-lz",
            "-l:libzstd.so.1",
            "-ltinfo",
            "-lpthread",
            "-ldl",
            "-lm",
            "-o",
            "/work/harness-observer",
        ]
    )
    assert result.returncode == 0, result.stderr

    return docker, work


def _harness_run(
    binaries: tuple[str, Path], mode: str, *, static: bool = False
) -> subprocess.CompletedProcess[str]:
    docker, work = binaries
    executable = "harness-observer-static" if static else "harness-observer"
    return _run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "--cap-add",
            "SYS_ADMIN",
            "--security-opt",
            "seccomp=unconfined",
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            f"/work/{executable}",
            mode,
        ]
    )


def test_harness_observer_captures_the_direct_dynamic_elf_topology(
    harness_observer_binaries: tuple[str, Path],
) -> None:
    result = _harness_run(harness_observer_binaries, "observe")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"harness_observer_ok entry_bytes=[1-9][0-9]* loader_bytes=[1-9][0-9]* "
        r"duplicate_supervisor=1 zero_authority=1\n",
        result.stdout,
    )


@pytest.mark.parametrize("mode", ["expectation-mismatch", "expired", "invalid-limits"])
def test_harness_observer_fails_closed_on_adversarial_inputs(
    harness_observer_binaries: tuple[str, Path], mode: str
) -> None:
    result = _harness_run(harness_observer_binaries, mode)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    assert re.fullmatch(
        rf"harness_observer_rejected {mode} failure=[0-9]+ zero_authority=1\n",
        result.stdout,
    )


def test_harness_observer_rejects_static_elf_entry(
    harness_observer_binaries: tuple[str, Path],
) -> None:
    docker, work = harness_observer_binaries
    static_build = _run(
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
            "-static",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/HarnessObserver.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/ElfMetadata.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_harness_observer_harness.cpp",
            "-L/opt/llvm-build/lib",
            "-lLLVMSupport",
            "-lLLVMDemangle",
            "-lz",
            "-l:libzstd.a",
            "-ltinfo",
            "-lpthread",
            "-ldl",
            "-lm",
            "-o",
            "/work/harness-observer-static",
        ]
    )
    if static_build.returncode != 0:
        pytest.skip(f"the pinned image cannot link static harness fixture: {static_build.stderr}")
    result = _harness_run(harness_observer_binaries, "observe", static=True)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"harness_observer_rejected observe failure=[0-9]+ zero_authority=1\n",
        result.stdout,
    )
