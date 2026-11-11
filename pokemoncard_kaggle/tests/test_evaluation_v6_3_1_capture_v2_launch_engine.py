from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


@pytest.fixture(scope="module")
def launch_engine_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 LaunchEngine test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-launch-engine")
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
    tracee_compile = [
            "clang++-16",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            # RawCborWriter.cpp is existing production code whose bitwise
            # promotion warnings are outside this test-only change.
            "-Wno-sign-conversion",
            "-static",
            "-Wl,--build-id=0x63130201",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "-I/src/evaluation_v6_3_1/native/m0_diagnostic_collector",
            "/src/evaluation_v6_3_1/native/capture_v2/CollectorReceipt.cpp",
            "/src/evaluation_v6_3_1/native/m0_diagnostic_collector/RawCborWriter.cpp",
            "/src/tests/native/v631302_launch_tracee.cpp",
    ]
    tracee_build = _run(
        prefix
        + tracee_compile
        + [
            "-o",
            "/work/tracee",
        ],
    )
    assert tracee_build.returncode == 0, tracee_build.stderr
    tracee_notes = _run(prefix + ["readelf", "-n", "/work/tracee"])
    assert tracee_notes.returncode == 0, tracee_notes.stderr
    assert "Build ID: 63130201" in tracee_notes.stdout
    rejected_modes = {
        "hang": 1,
        "fork": 2,
        "eventfd": 3,
        "chdir": 4,
        "fd3-alias": 5,
        "exit-open-receipt": 6,
    }
    for mode, code in rejected_modes.items():
        mode_build = _run(
            prefix
            + tracee_compile
            + [
                f"-DV631302_TRACEE_MODE={code}",
                "-o",
                f"/work/tracee-{mode}",
            ],
        )
        assert mode_build.returncode == 0, (mode, mode_build.stderr)

    primary_fixture_build = _run(
        prefix
        + [
            "clang-16",
            "-shared",
            "-fPIC",
            "-nostdlib",
            "/src/tests/native/v631302_runtime_primary_fixture.c",
            "-Wl,-soname,libclang-cpp.so.16",
            "-Wl,--build-id=0x63130216",
            "-o",
            "/work/libclang-cpp.so.16",
        ],
    )
    assert primary_fixture_build.returncode == 0, primary_fixture_build.stderr

    runtime_tracee_build = _run(
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
            "-DV631302_RUNTIME_PRIMARY_FIXTURE=1",
            "-nodefaultlibs",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "-I/src/evaluation_v6_3_1/native/m0_diagnostic_collector",
            "/src/evaluation_v6_3_1/native/capture_v2/CollectorReceipt.cpp",
            "/src/evaluation_v6_3_1/native/m0_diagnostic_collector/RawCborWriter.cpp",
            "/src/tests/native/v631302_launch_tracee.cpp",
            "-L/work",
            "-Wl,--no-as-needed",
            "-Wl,-rpath,/lib",
            "-Wl,--dynamic-linker=/lib/ld-linux-x86-64.so.2",
            "-Wl,--build-id=0x63130201",
            "-l:libclang-cpp.so.16",
            "-Wl,-Bstatic",
            "-lstdc++",
            "-lm",
            "-lgcc",
            "-lgcc_eh",
            "-Wl,-Bdynamic",
            "-lc",
            "-ldl",
            "-lpthread",
            "-o",
            "/work/runtime-tracee",
        ],
    )
    assert runtime_tracee_build.returncode == 0, runtime_tracee_build.stderr
    runtime_notes = _run(prefix + ["readelf", "-n", "/work/runtime-tracee"])
    assert runtime_notes.returncode == 0, runtime_notes.stderr
    assert "Build ID: 63130201" in runtime_notes.stdout

    runtime_dynamic = _run(prefix + ["readelf", "-d", "/work/runtime-tracee"])
    assert runtime_dynamic.returncode == 0, runtime_dynamic.stderr
    for needed in (
        "Shared library: [libclang-cpp.so.16]",
        "Shared library: [libc.so.6]",
        "Shared library: [ld-linux-x86-64.so.2]",
        "Library runpath: [/lib]",
    ):
        assert needed in runtime_dynamic.stdout
    assert "libstdc++" not in runtime_dynamic.stdout
    assert "libgcc" not in runtime_dynamic.stdout
    assert "libm.so.6" not in runtime_dynamic.stdout

    runtime_program = _run(prefix + ["readelf", "-l", "/work/runtime-tracee"])
    assert runtime_program.returncode == 0, runtime_program.stderr
    assert "[Requesting program interpreter: /lib/ld-linux-x86-64.so.2]" in runtime_program.stdout

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
            "-Wno-sign-conversion",
            "-fexceptions",
            "-DEVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/PrelaunchContext.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/LaunchEngine.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/NamespaceIdentityObserver.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/MountSandbox.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/RetainedInputs.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PipePump.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/LaunchHandshake.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/ProcInspector.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PtraceExecAuthenticator.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/FdTracker.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/SyscallPairTracker.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PidfdOpenedFile.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/TraceeMemory.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/OpenPathResolver.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/ElfMetadata.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/ProcMapsParser.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/RuntimeObserver.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PtraceOpenSupervisor.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/ReceiptStreamParser.cpp",
            "/src/tests/native/v631302_launch_engine_harness.cpp",
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
            "/work/launch-engine-harness",
        ],
        timeout=180,
    )
    assert harness_build.returncode == 0, harness_build.stderr
    return docker, work


def test_launch_engine_strict_linux_amd64_functional_harness(
    launch_engine_harness: tuple[str, Path],
) -> None:
    docker, work = launch_engine_harness
    result = _run(
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
            f"{work}:/work:rw",
            IMAGE,
            "/work/launch-engine-harness",
        ],
        timeout=45,
    )
    if result.returncode == 77 and "launch_engine_skipped" in result.stdout:
        pytest.skip(result.stdout.strip())
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "launch_engine_harness_ok zero_authority=1" in result.stdout
