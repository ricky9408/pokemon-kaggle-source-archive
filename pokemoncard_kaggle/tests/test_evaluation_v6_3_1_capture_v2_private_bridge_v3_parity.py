"""Zero-authority fixture parity for the native Private Bridge V3 handoff."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
from types import ModuleType

import pytest

from evaluation_v6_3_1.capture_v2_assembler import (
    CAPTURE_V2_ASSEMBLY_FAILED,
    CaptureV2AssemblyError,
    _bridge_decode,
    assemble_production_capture_v2,
)


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
    return subprocess.run(
        command, check=False, text=True, capture_output=True, timeout=timeout
    )


@pytest.fixture(scope="module")
def reference_fixture_module() -> ModuleType:
    source = ROOT / "tests/test_evaluation_v6_3_1_capture_v2_assembler.py"
    spec = importlib.util.spec_from_file_location("_capture_v2_reference_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def native_private_bridge_v3_harness(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 Bridge V3 fixture parity")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("private-bridge-v3-fixture")
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
        f"/src/evaluation_v6_3_1/native/capture_v2/{name}"
        for name in CAPTURE_V2_SOURCES
    ]
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
            "-DEVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY",
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
            "/work/private-bridge-v3-fixture-harness",
        ]
    )
    assert build.returncode == 0, build.stderr
    return docker, work


def _reference(reference_fixture_module: ModuleType) -> tuple[object, list[object], bytes]:
    source_artifact = reference_fixture_module._expectations()
    value = reference_fixture_module._bridge_value(source_artifact)
    return source_artifact, value, reference_fixture_module._bridge_encode(value)


def _run_native_fixture(
    native_private_bridge_v3_harness: tuple[str, Path],
    source_artifact: object,
    value: list[object],
    fixture_name: str,
) -> tuple[bytes, bytes]:
    docker, work = native_private_bridge_v3_harness
    fixture_dir = work / fixture_name
    fixture_dir.mkdir()
    profile = fixture_dir / "collector-profile.cbor"
    stdout = fixture_dir / "collector-stdout.cbor"
    receipt = fixture_dir / "receipt.bin"
    root = fixture_dir / "prelaunch-root.bin"
    bridge_a = fixture_dir / "bridge-a.cbor"
    bridge_b = fixture_dir / "bridge-b.cbor"
    profile.write_bytes(source_artifact.collector_profile_cbor_bytes)
    stdout.write_bytes(value[7][0])
    receipt.write_bytes(value[5][0])
    root.write_bytes(source_artifact.validated_prelaunch_expectations_root)

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
            f"{work}:/work:rw",
            IMAGE,
            "/work/private-bridge-v3-fixture-harness",
            f"/work/{fixture_dir.name}/collector-profile.cbor",
            f"/work/{fixture_dir.name}/collector-stdout.cbor",
            f"/work/{fixture_dir.name}/receipt.bin",
            f"/work/{fixture_dir.name}/prelaunch-root.bin",
            f"/work/{fixture_dir.name}/bridge-a.cbor",
            f"/work/{fixture_dir.name}/bridge-b.cbor",
        ],
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "private_bridge_v3_fixture_harness_ok zero_authority=1"
    return bridge_a.read_bytes(), bridge_b.read_bytes()


def _run_native_contract_case(
    native_private_bridge_v3_harness: tuple[str, Path],
    source_artifact: object,
    value: list[object],
    mode: str,
) -> None:
    docker, work = native_private_bridge_v3_harness
    fixture_dir = work / f"contract-{mode}"
    fixture_dir.mkdir()
    profile = fixture_dir / "collector-profile.cbor"
    stdout = fixture_dir / "collector-stdout.cbor"
    receipt = fixture_dir / "receipt.bin"
    root = fixture_dir / "prelaunch-root.bin"
    profile.write_bytes(source_artifact.collector_profile_cbor_bytes)
    stdout.write_bytes(value[7][0])
    receipt.write_bytes(value[5][0])
    root.write_bytes(source_artifact.validated_prelaunch_expectations_root)

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
            f"{work}:/work:rw",
            IMAGE,
            "/work/private-bridge-v3-fixture-harness",
            f"/work/{fixture_dir.name}/collector-profile.cbor",
            f"/work/{fixture_dir.name}/collector-stdout.cbor",
            f"/work/{fixture_dir.name}/receipt.bin",
            f"/work/{fixture_dir.name}/prelaunch-root.bin",
            f"/work/{fixture_dir.name}/unused-a.cbor",
            f"/work/{fixture_dir.name}/unused-b.cbor",
            mode,
        ],
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == (
        f"private_bridge_v3_contract_ok case={mode} zero_authority=1"
    )


def _assert_rejected(raw: bytes, artifact: object) -> None:
    with pytest.raises(CaptureV2AssemblyError) as raised:
        assemble_production_capture_v2(raw, artifact)
    assert raised.value.code == CAPTURE_V2_ASSEMBLY_FAILED


def test_native_private_bridge_v3_fixture_matches_python_and_is_repeatable(
    native_private_bridge_v3_harness: tuple[str, Path],
    reference_fixture_module: ModuleType,
    tmp_path: Path,
) -> None:
    source_artifact, reference_value, reference_bridge = _reference(
        reference_fixture_module
    )
    native_a, native_b = _run_native_fixture(
        native_private_bridge_v3_harness,
        source_artifact,
        reference_value,
        "fixture",
    )

    # The assembler gets a separately frozen artifact, never an object that
    # participated in native fixture creation or a bridge-derived substitute.
    independent_artifact = reference_fixture_module._expectations()
    assert independent_artifact is not source_artifact
    assert native_a == native_b == reference_bridge

    public_reference = assemble_production_capture_v2(
        reference_bridge, independent_artifact
    )
    public_a = assemble_production_capture_v2(native_a, independent_artifact)
    public_b = assemble_production_capture_v2(native_b, independent_artifact)
    assert public_a == public_b == public_reference


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "profile-label",
        "stdout",
        "invariant",
        "size",
        "allocation",
        "internal",
    ],
)
def test_native_private_bridge_v3_noexcept_result_and_fd_consumption_contract(
    native_private_bridge_v3_harness: tuple[str, Path],
    reference_fixture_module: ModuleType,
    mode: str,
) -> None:
    source_artifact, reference_value, _ = _reference(reference_fixture_module)
    _run_native_contract_case(
        native_private_bridge_v3_harness,
        source_artifact,
        reference_value,
        mode,
    )


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        pytest.param(
            "label-as-bytes",
            lambda value: value[2].__setitem__(0, b"collector-build"),
            id="swapped-label-type",
        ),
        pytest.param(
            "descriptor-as-text",
            lambda value: value[2].__setitem__(1, "00ab"),
            id="swapped-descriptor-type",
        ),
        pytest.param(
            "absolute-cwd",
            lambda value: value[4][0].__setitem__(3, "/work"),
            id="absolute-cwd",
        ),
        pytest.param(
            "bare-stdout",
            lambda value: value.__setitem__(7, value[7][0]),
            id="bare-stdout",
        ),
        pytest.param(
            "empty-stdout",
            lambda value: value[7].__setitem__(0, b""),
            id="empty-stdout",
        ),
        pytest.param(
            "mismatched-root",
            lambda value: value[4].__setitem__(1, bytes(32)),
            id="mismatched-root",
        ),
        pytest.param(
            "v2",
            lambda value: value.__setitem__(1, 2),
            id="v2-rejected",
        ),
        pytest.param(
            "pre-erratum-v3",
            lambda value: value.__setitem__(4, value[4][0]),
            id="pre-erratum-execution-shape",
        ),
    ],
)
def test_production_assembler_rejects_native_bridge_v3_negative_shapes(
    native_private_bridge_v3_harness: tuple[str, Path],
    reference_fixture_module: ModuleType,
    tmp_path: Path,
    name: str,
    mutate,
) -> None:
    source_artifact, reference_value, _ = _reference(reference_fixture_module)
    native_a, _ = _run_native_fixture(
        native_private_bridge_v3_harness,
        source_artifact,
        reference_value,
        name,
    )
    value = _bridge_decode(native_a)
    mutate(value)
    _assert_rejected(reference_fixture_module._bridge_encode(value), source_artifact)


@pytest.mark.skip(
    reason=(
        "requires a capable external Linux/amd64 kernel and two real successful "
        "production clone3/pidfd capture executions; fixture parity is not custody evidence"
    )
)
def test_real_native_to_python_private_bridge_v3_parity_is_not_simulated() -> None:
    pass
