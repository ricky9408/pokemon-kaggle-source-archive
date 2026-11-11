from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
SOURCE = ROOT / "evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.cpp"
HEADER = ROOT / "evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.h"
HARNESS = ROOT / "tests/native/v631302_workdir_custody_harness.cpp"


def _run(command: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


@pytest.fixture(scope="module")
def workdir_custody_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 work-directory custody test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-workdir-custody")
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
    built = _run(
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
            "-DV631302_CUSTODY_TEST_NONCE_INJECTION",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_workdir_custody_harness.cpp",
            "-o",
            "/work/workdir-custody-harness",
        ]
    )
    assert built.returncode == 0, built.stderr
    return docker, work


def test_workdir_custody_strict_linux_amd64_harness(
    workdir_custody_harness: tuple[str, Path],
) -> None:
    docker, work = workdir_custody_harness
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
            f"{work}:/work:ro",
            IMAGE,
            "/work/workdir-custody-harness",
        ]
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "workdir_custody_harness_ok zero_authority=1"


def test_workdir_custody_uses_only_fd_capability_handoff() -> None:
    source = SOURCE.read_text(encoding="ascii")
    header = HEADER.read_text(encoding="ascii")
    assert "SCM_RIGHTS" in source
    assert "SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC" in source
    assert "SO_PASSCRED" in source
    assert "getrandom(" in source
    assert "shutdown(endpoint_.get(), SHUT_WR)" in source
    assert "POLLRDHUP" in source
    assert "MSG_CMSG_CLOEXEC" in source
    assert "openat(" in source
    assert "create_production(MonotonicDeadline deadline)" in header
    assert "create_production(\n        MonotonicDeadline deadline,\n        WorkDirectorySessionNonce" not in header
    assert "session_nonce()" not in header
    assert "pidfd_getfd" not in source
    assert "/proc/" not in source
    assert "pathname" not in header.lower()
