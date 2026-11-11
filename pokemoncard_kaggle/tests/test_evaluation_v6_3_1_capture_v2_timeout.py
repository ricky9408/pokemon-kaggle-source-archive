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
def timeout_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    executable = shutil.which("docker")
    if executable is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 timeout test")
    image = _run([executable, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    work = tmp_path_factory.mktemp("capture-v2-timeout") / "work"
    work.mkdir()
    prefix = [
        executable,
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
            "clang++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_timeout_harness.cpp",
            "-o",
            "/work/timeout_harness",
        ]
    )
    assert compile_result.returncode == 0, compile_result.stderr
    return executable, work


def _prefix(docker: str, work: Path) -> list[str]:
    return [
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


def test_monotonic_deadline_strict_linux_amd64(
    timeout_harness: tuple[str, Path],
) -> None:
    docker, work = timeout_harness
    run_result = _run(_prefix(docker, work) + ["/work/timeout_harness", "deadline"])
    assert run_result.returncode == 0, run_result.stderr
    assert "timeout_deadline_harness_ok zero_authority=1" in run_result.stdout


def test_timeout_termination_strict_linux_amd64_pidfd_harness(
    timeout_harness: tuple[str, Path],
) -> None:
    docker, work = timeout_harness

    run_result = _run(_prefix(docker, work) + ["/work/timeout_harness"])
    if run_result.returncode == 77 and "pidfd_unavailable=1" in run_result.stdout:
        pytest.skip("the Docker kernel does not expose pidfd_open")
    assert run_result.returncode == 0, run_result.stderr
    assert "timeout_harness_ok zero_authority=1" in run_result.stdout
