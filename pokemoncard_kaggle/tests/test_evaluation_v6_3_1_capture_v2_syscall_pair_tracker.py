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
def docker() -> str:
    executable = shutil.which("docker")
    if executable is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 syscall pair tracker test")
    image = _run([executable, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    return executable


def test_syscall_pair_tracker_strict_linux_amd64_build_and_harness(
    docker: str, tmp_path: Path
) -> None:
    work = tmp_path / "work"
    work.mkdir()
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
    compile_result = _run(
        prefix
        + [
            "clang++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/SyscallPairTracker.cpp",
            "/src/tests/native/v631302_syscall_pair_tracker_harness.cpp",
            "-o",
            "/work/syscall_pair_tracker_harness",
        ]
    )
    assert compile_result.returncode == 0, compile_result.stderr

    run_result = _run(prefix + ["/work/syscall_pair_tracker_harness"])
    assert run_result.returncode == 0, run_result.stderr
    assert "syscall_pair_tracker_harness_ok zero_authority=1" in run_result.stdout
