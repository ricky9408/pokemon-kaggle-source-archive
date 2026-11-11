from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"

CAPTURE_V2_SOURCES = [
    "CaptureOutcome.cpp",
    "CaptureSession.cpp",
    "NativePrelaunchHandoff.cpp",
    "ElfMetadata.cpp",
    "FdTracker.cpp",
    "HarnessObserver.cpp",
    "LaunchEngine.cpp",
    "LaunchHandshake.cpp",
    "MountSandbox.cpp",
    "NamespaceIdentityObserver.cpp",
    "OpenPathResolver.cpp",
    "PidfdOpenedFile.cpp",
    "PipePump.cpp",
    "PrelaunchContext.cpp",
    "PrivateBridgeEncoder.cpp",
    "ProcInspector.cpp",
    "ProcMapsParser.cpp",
    "PtraceExecAuthenticator.cpp",
    "PtraceOpenSupervisor.cpp",
    "ReceiptStreamParser.cpp",
    "RetainedInputs.cpp",
    "RuntimeObserver.cpp",
    "SyscallPairTracker.cpp",
    "Timeout.cpp",
    "TraceeMemory.cpp",
    "WorkDirectoryCustody.cpp",
]


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


@pytest.fixture(scope="module")
def capture_session_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 CaptureSession test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-session")
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
    sources = [f"/src/evaluation_v6_3_1/native/capture_v2/{name}" for name in CAPTURE_V2_SOURCES]
    build = _run(
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
            "-Wno-sign-conversion",
            "-fexceptions",
            "-DEVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            *sources,
            "/src/tests/native/v631302_capture_session_harness.cpp",
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
            "/work/capture-session-harness",
        ]
    )
    assert build.returncode == 0, build.stderr
    return docker, work


def test_capture_session_validation_failure_is_linux_amd64_zero_authority(
    capture_session_harness: tuple[str, Path],
) -> None:
    docker, work = capture_session_harness
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
            "/work/capture-session-harness",
        ],
        timeout=45,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "capture_session_harness_ok zero_authority=1"


@pytest.mark.skip(
    reason="requires a capable Linux/amd64 kernel and complete external custody/runtime evidence"
)
def test_capable_kernel_positive_capture_session_path_is_not_simulated() -> None:
    pass
