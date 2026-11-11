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
def pidfd_opened_file_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 pidfd opened-file test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-pidfd-opened-file")
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
            "-fexceptions",
            "-I/opt/llvm-src/llvm/include",
            "-I/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/PidfdOpenedFile.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_pidfd_opened_file_harness.cpp",
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
            "/work/pidfd-opened-file-harness",
        ]
    )
    assert compile_result.returncode == 0, compile_result.stderr
    return docker, work


def test_pidfd_opened_file_strict_linux_amd64(
    pidfd_opened_file_harness: tuple[str, Path],
) -> None:
    docker, work = pidfd_opened_file_harness
    run_result = _run(
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
            "/work/pidfd-opened-file-harness",
        ]
    )
    if run_result.returncode == 77:
        assert (
            "pidfd_opened_file_harness_skipped pidfd_unavailable=1\n" == run_result.stdout
            or "pidfd_opened_file_harness_skipped pidfd_getfd_unavailable=1\n"
            == run_result.stdout
        )
        pytest.skip("the Docker Linux/amd64 kernel does not permit the pidfd path")
    assert run_result.returncode == 0, (run_result.stdout, run_result.stderr)
    assert run_result.stdout == "pidfd_opened_file_harness_ok zero_authority=1\n"
