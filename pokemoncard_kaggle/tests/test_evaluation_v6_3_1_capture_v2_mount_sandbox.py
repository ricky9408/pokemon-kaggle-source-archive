from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


@pytest.fixture(scope="module")
def mount_sandbox_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 mount-sandbox test")
    image = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")
    work = tmp_path_factory.mktemp("capture-v2-mount-sandbox")
    compile_command = [
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
        "-fexceptions",
        "-I/opt/llvm-src/llvm/include",
        "-I/opt/llvm-build/include",
        "-I/src/evaluation_v6_3_1/native/capture_v2",
        "/src/evaluation_v6_3_1/native/capture_v2/RetainedInputs.cpp",
        "/src/evaluation_v6_3_1/native/capture_v2/MountSandbox.cpp",
        "/src/tests/native/v631302_mount_sandbox_harness.cpp",
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
        "/work/mount-sandbox-harness",
    ]
    built = subprocess.run(
        compile_command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert built.returncode == 0, built.stderr
    return docker, work


def _run(harness: tuple[str, Path], mode: str) -> subprocess.CompletedProcess[str]:
    docker, work = harness
    return subprocess.run(
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
            "/work/mount-sandbox-harness",
            mode,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )


def test_mount_sandbox_materializes_seals_and_enters_private_root(
    mount_sandbox_harness: tuple[str, Path],
) -> None:
    result = _run(mount_sandbox_harness, "valid")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "mount_sandbox_ok zero_authority=1" in result.stdout


@pytest.mark.parametrize(
    "mode",
    ["invalid-workdir", "tiny-tmpfs", "nonempty-stage", "bad-stage-mode", "stage-symlink"],
)
def test_mount_sandbox_rejects_invalid_preconditions(
    mount_sandbox_harness: tuple[str, Path], mode: str
) -> None:
    result = _run(mount_sandbox_harness, mode)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
