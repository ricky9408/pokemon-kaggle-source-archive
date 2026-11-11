from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import pytest

from evaluation_v6_3_1.capture_v2_native_handoff_v1 import (
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
def native_prelaunch_handoff_harness(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 native handoff test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-native-prelaunch-handoff")
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
            "/work/native-prelaunch-handoff-harness",
        ]
    )
    assert build.returncode == 0, build.stderr
    return docker, work


def _raw_value() -> list[object]:
    return eir_canonical_cbor_decode(encode_raw_prelaunch_request_v1(_artifact()))


def _handoff_from_raw(raw: list[object], *, root: bytes | None = None) -> bytes:
    raw_bytes = eir_canonical_cbor_encode(raw)
    if root is None:
        expectations = [631302, 2, 1, *raw[2:]]
        root = sha256(
            VALIDATED_PRELAUNCH_EXPECTATIONS_DOMAIN_V2
            + eir_canonical_cbor_encode(expectations)
        ).digest()
    return eir_canonical_cbor_encode([631302, 1, root, raw_bytes])


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
            "/work/native-prelaunch-handoff-harness",
            mode,
            argument,
        ]
    )


def _invalid_handoff(mutation: str) -> bytes:
    artifact = _artifact()
    raw = _raw_value()
    if mutation == "outer_noncanonical":
        canonical = to_native_prelaunch_handoff(artifact)
        assert canonical[0] == 0x84
        return b"\x98\x04" + canonical[1:]
    if mutation == "outer_width":
        return eir_canonical_cbor_encode(
            [631302, 1, artifact.validated_prelaunch_expectations_root]
        )
    if mutation == "root_short":
        return _handoff_from_raw(raw, root=b"\xa5" * 31)
    if mutation == "raw_width":
        raw.pop()
    elif mutation == "raw_protocol":
        raw[0] = 0
    elif mutation == "label_empty":
        raw[2] = ""
    elif mutation == "label_mismatch":
        profile = eir_canonical_cbor_decode(raw[4])
        profile[1] = "collector-profile-mismatch"
        raw[4] = eir_canonical_cbor_encode(profile)
    elif mutation == "descriptor_empty":
        raw[3] = b""
    elif mutation == "profile_noncanonical":
        raw[4] = b"\x98\x08"
    elif mutation == "grammar_zero":
        raw[5] = 0
    elif mutation == "grammar_digest":
        raw[6] = b"\xff" * 32
    elif mutation == "path_profile":
        raw[7] = eir_canonical_cbor_encode([2, "/src", "/work", "/bix"])
    elif mutation == "cwd":
        raw[8] = "work/"
    elif mutation == "primary":
        raw[9] = "src/Other.cpp"
    elif mutation in {
        "no_collector",
        "two_collectors",
        "no_primary",
        "two_primaries",
        "duplicate_roles",
    }:
        rows = eir_canonical_cbor_decode(raw[10])
        if mutation == "no_collector":
            rows[0][1] = [3]
        elif mutation == "two_collectors":
            rows[1][1] = [1]
        elif mutation == "no_primary":
            rows[4][1] = [3]
        elif mutation == "two_primaries":
            rows[3][1] = [2, 7, 8]
        else:
            rows[0][1] = [1, 1]
        raw[10] = eir_canonical_cbor_encode(rows)
    elif mutation == "argv_empty":
        raw[11] = []
    elif mutation == "argv_collector":
        argv = list(raw[11])
        argv[0] = "/bin/collector"
        raw[11] = argv
    elif mutation == "argv_primary_missing":
        argv = list(raw[11])
        argv[argv.index("/src/Export.cpp")] = "/src/Other.cpp"
        raw[11] = argv
    elif mutation == "argv_empty_argument":
        raw[11] = [*raw[11], ""]
    elif mutation in {"harness_zero", "harness_build_id_over"}:
        harness = raw[12]
        if mutation == "harness_zero":
            harness[1][0] = 0
        else:
            harness[2][2] = b"\x03" * 65_536
        raw[12] = harness
    else:  # pragma: no cover - protects the mutation table itself
        raise AssertionError(f"unknown mutation: {mutation}")
    return _handoff_from_raw(raw)


def test_native_prelaunch_handoff_accepts_exact_corrected_handoff(
    native_prelaunch_handoff_harness: tuple[str, Path],
) -> None:
    result = _native(
        native_prelaunch_handoff_harness,
        "accept",
        to_native_prelaunch_handoff(_artifact()),
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "native_amendment5_harness_ok zero_authority=1" in result.stdout


def test_native_prelaunch_handoff_retains_empty_harness_build_id(
    native_prelaunch_handoff_harness: tuple[str, Path],
) -> None:
    raw = _raw_value()
    harness = raw[12]
    harness[1][2] = b""
    raw[12] = harness
    result = _native(
        native_prelaunch_handoff_harness, "accept", _handoff_from_raw(raw)
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


@pytest.mark.parametrize(
    "mutation",
    [
        "outer_noncanonical",
        "outer_width",
        "root_short",
        "raw_width",
        "raw_protocol",
        "label_empty",
        "label_mismatch",
        "descriptor_empty",
        "profile_noncanonical",
        "grammar_zero",
        "grammar_digest",
        "path_profile",
        "cwd",
        "primary",
        "no_collector",
        "two_collectors",
        "no_primary",
        "two_primaries",
        "duplicate_roles",
        "argv_empty",
        "argv_collector",
        "argv_primary_missing",
        "argv_empty_argument",
        "harness_zero",
        "harness_build_id_over",
    ],
)
def test_native_prelaunch_handoff_rejects_malformed_or_retired_inputs(
    native_prelaunch_handoff_harness: tuple[str, Path], mutation: str
) -> None:
    result = _native(
        native_prelaunch_handoff_harness, "reject", _invalid_handoff(mutation)
    )
    assert result.returncode == 0, (mutation, result.stdout, result.stderr)
    assert "status=rejected" in result.stdout
