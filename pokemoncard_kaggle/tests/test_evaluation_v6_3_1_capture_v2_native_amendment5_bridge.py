from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
HARNESS = "v631302_private_bridge_v3_fixture_harness.cpp"

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
    "ProductionCaptureBridge.cpp",
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


def _run(command: list[str], *, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


def _run_container(
    docker: str,
    arguments: list[str],
    *,
    cidfile: Path,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    cidfile.unlink(missing_ok=True)
    command = [docker, "run", "--cidfile", str(cidfile), *arguments]
    try:
        return _run(command, timeout=timeout)
    finally:
        if cidfile.exists():
            container_id = cidfile.read_text(encoding="ascii").strip()
            if container_id:
                subprocess.run(
                    [docker, "rm", "--force", container_id],
                    check=False,
                    text=True,
                    capture_output=True,
                    timeout=30,
                )
        cidfile.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def reference_fixture_module() -> ModuleType:
    source = ROOT / "tests/test_evaluation_v6_3_1_capture_v2_assembler.py"
    spec = importlib.util.spec_from_file_location("_capture_v2_amendment5_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def production_bridge_harness(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 production bridge tests")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-production-bridge-amendment5")
    prefix = [
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
        f"/src/evaluation_v6_3_1/native/capture_v2/{name}"
        for name in CAPTURE_V2_SOURCES
    ]
    build = _run_container(
        docker,
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
            "-DEVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY",
            "-DEVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY",
            "-DEVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            *sources,
            f"/src/tests/native/{HARNESS}",
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
            "/work/production-bridge-amendment5-harness",
        ],
        cidfile=work / "build.cid",
        timeout=240,
    )
    assert build.returncode == 0, build.stderr
    return docker, work


@pytest.mark.parametrize(
    "mode",
    [
        "production-success",
        "production-session-failure",
        "production-encoder-failure",
    ],
)
def test_production_bridge_is_single_run_single_move_and_failure_disjoint(
    production_bridge_harness: tuple[str, Path],
    reference_fixture_module: ModuleType,
    mode: str,
) -> None:
    docker, work = production_bridge_harness
    source_artifact = reference_fixture_module._expectations()
    value = reference_fixture_module._bridge_value(source_artifact)
    fixture = work / mode
    fixture.mkdir()
    profile = fixture / "collector-profile.cbor"
    stdout = fixture / "collector-stdout.cbor"
    receipt = fixture / "receipt.bin"
    root = fixture / "prelaunch-root.bin"
    profile.write_bytes(source_artifact.collector_profile_cbor_bytes)
    stdout.write_bytes(value[7][0])
    receipt.write_bytes(value[5][0])
    root.write_bytes(source_artifact.validated_prelaunch_expectations_root)
    profile.chmod(0o444)
    stdout.chmod(0o444)

    result = _run_container(
        docker,
        [
            "--rm",
            "--network",
            "none",
            "--platform",
            "linux/amd64",
            "-v",
            f"{work}:/work:rw",
            IMAGE,
            "/work/production-bridge-amendment5-harness",
            f"/work/{fixture.name}/{profile.name}",
            f"/work/{fixture.name}/{stdout.name}",
            f"/work/{fixture.name}/{receipt.name}",
            f"/work/{fixture.name}/{root.name}",
            f"/work/{fixture.name}/unused-a.cbor",
            f"/work/{fixture.name}/unused-b.cbor",
            mode,
        ],
        cidfile=work / f"{mode}.cid",
        timeout=90,
    )
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    assert result.stdout.strip() == (
        f"production_bridge_ok case={mode} zero_authority=1"
    )
