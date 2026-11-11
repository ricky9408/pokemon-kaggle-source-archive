from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.capture_v2_native_handoff_v1 import (
    derive_direct_in_process_clang_collector_launch_contract_v2,
    encode_raw_prelaunch_request_v1,
    to_native_prelaunch_handoff,
)
from evaluation_v6_3_1.capture_v2_prelaunch_expectations import (
    VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2,
)
from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from tests.test_evaluation_v6_3_1_capture_v2_native_handoff_v1 import _artifact


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True, timeout=timeout)


@pytest.fixture(scope="module")
def native_amendment5_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 Amendment 5 tests")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-native-amendment5")
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
            "-fexceptions",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PrelaunchContext.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/NativePrelaunchHandoff.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_native_amendment5_harness.cpp",
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
            "/work/native-amendment5-harness",
        ]
    )
    assert build.returncode == 0, build.stderr
    return docker, work


def _native(
    harness: tuple[str, Path], mode: str, handoff: bytes
) -> subprocess.CompletedProcess[str]:
    docker, work = harness
    argument = handoff.hex()
    if len(argument) > 100_000:
        handoff_file = work / f"handoff-{sha256(handoff).hexdigest()}.bin"
        handoff_file.write_bytes(handoff)
        argument = f"@/work/{handoff_file.name}"
    return _run(
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
            "/work/native-amendment5-harness",
            mode,
            argument,
        ]
    )


def _raw_value() -> list[object]:
    return eir_canonical_cbor_decode(encode_raw_prelaunch_request_v1(_artifact()))


def _handoff_from_raw(
    raw: list[object], *, root: bytes | None = None
) -> bytes:
    raw_bytes = eir_canonical_cbor_encode(raw)
    if root is None:
        expectations = [631302, 2, 1, *raw[2:]]
        root = sha256(
            VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2
            + eir_canonical_cbor_encode(expectations)
        ).digest()
    return eir_canonical_cbor_encode([631302, 1, root, raw_bytes])


def _parse_native_output(stdout: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def test_native_matches_python_v2_root_context_and_launch(
    native_amendment5_harness: tuple[str, Path],
) -> None:
    artifact = _artifact()
    handoff = to_native_prelaunch_handoff(artifact)
    expected = derive_direct_in_process_clang_collector_launch_contract_v2(artifact)
    result = _native(native_amendment5_harness, "accept", handoff)
    assert result.returncode == 0, (result.stdout, result.stderr)
    parsed = _parse_native_output(result.stdout)
    assert parsed["status"] == "accepted"
    assert parsed["absolute_primary"] == expected.absolute_primary
    assert parsed["context_hex"] == expected.capture_context_hex
    assert int(parsed["launch_argc"]) == len(expected.argv)
    assert tuple(
        bytes.fromhex(parsed[f"launch_{index}"]).decode("utf-8")
        for index in range(len(expected.argv))
    ) == expected.argv
    assert "bin/clang-tool" not in [row[0] for row in eir_canonical_cbor_decode(artifact.public_file_rows_cbor_bytes)]


@pytest.mark.parametrize(
    "mutation",
    [
        "fake_clang_row",
        "profile_libclang_sha",
        "wrong_libclang_path",
        "wrong_libclang_object",
        "wrong_clang_major",
        "logical_argv0",
        "empty_argv_item",
        "wrong_collector_mode",
        "wrong_primary_roles",
    ],
)
def test_native_rejects_corrected_projection_mutations(
    native_amendment5_harness: tuple[str, Path], mutation: str
) -> None:
    raw = _raw_value()
    profile = eir_canonical_cbor_decode(raw[4])
    rows = eir_canonical_cbor_decode(raw[10])
    argv = list(raw[11])
    if mutation == "fake_clang_row":
        rows.insert(1, ["bin/clang-tool", [9], 0o555, 31, bytes.fromhex("91" * 32)])
    elif mutation == "profile_libclang_sha":
        profile[2] = bytes.fromhex("92" * 32)
    elif mutation == "wrong_libclang_path":
        rows[3][0] = "lib/libclang-cpp.so.15"
    elif mutation == "wrong_libclang_object":
        rows[3][4] = bytes.fromhex("93" * 32)
    elif mutation == "wrong_clang_major":
        profile[3] = 17
    elif mutation == "logical_argv0":
        argv[0] = "/bin/collector"
    elif mutation == "empty_argv_item":
        argv[5] = ""
    elif mutation == "wrong_collector_mode":
        rows[0][2] = 0o444
    elif mutation == "wrong_primary_roles":
        rows[4][1] = [2]
    raw[4] = eir_canonical_cbor_encode(profile)
    raw[10] = eir_canonical_cbor_encode(rows)
    raw[11] = argv
    result = _native(native_amendment5_harness, "reject", _handoff_from_raw(raw))
    assert result.returncode == 0, (mutation, result.stdout, result.stderr)
    assert "status=rejected" in result.stdout


def test_native_rejects_stale_v2_root(
    native_amendment5_harness: tuple[str, Path],
) -> None:
    artifact = _artifact()
    raw = _raw_value()
    argv = list(raw[11])
    argv[-1], argv[-2] = argv[-2], argv[-1]
    raw[11] = argv
    result = _native(
        native_amendment5_harness,
        "reject",
        _handoff_from_raw(raw, root=artifact.validated_prelaunch_expectations_root),
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "status=rejected" in result.stdout


@pytest.mark.parametrize("field", [4, 5, 6, 7])
def test_native_keeps_profile_fields_4_to_7_structural_only(
    native_amendment5_harness: tuple[str, Path], field: int
) -> None:
    raw = _raw_value()
    profile = eir_canonical_cbor_decode(raw[4])
    replacements: dict[int, object] = {
        4: int(profile[4]) + 1,
        5: [["opaque-native-structure"]],
        6: bytes.fromhex("a5" * 32),
        7: [[0, "opaque-native-structure"]],
    }
    profile[field] = replacements[field]
    raw[4] = eir_canonical_cbor_encode(profile)
    result = _native(native_amendment5_harness, "accept", _handoff_from_raw(raw))
    assert result.returncode == 0, (field, result.stdout, result.stderr)
    assert "status=accepted" in result.stdout
