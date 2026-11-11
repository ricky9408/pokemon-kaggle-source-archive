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
def prelaunch_context_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 PrelaunchContext test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-prelaunch-context")
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
            "-Wno-sign-conversion",
            "-fexceptions",
            "-DEVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY",
            "-isystem",
            "/opt/llvm-src/llvm/include",
            "-isystem",
            "/opt/llvm-build/include",
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/evaluation_v6_3_1/native/capture_v2/WorkDirectoryCustody.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/PrelaunchContext.cpp",
            "/src/evaluation_v6_3_1/native/capture_v2/Timeout.cpp",
            "/src/tests/native/v631302_prelaunch_context_harness.cpp",
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
            "/work/prelaunch-context-harness",
        ],
    )
    assert build.returncode == 0, build.stderr
    return docker, work


@pytest.mark.parametrize(
    "mutation",
    [
        "ok",
        "ownership",
        "digest",
        "grammar",
        "grammar_digest",
        "noncanonical_cbor",
        "cbor_map",
        "profile_label_mismatch",
        "profile_label_empty",
        "profile_label_nul",
        "label_ascii_max",
        "label_ascii_over",
        "label_non_ascii",
        "profile_label_non_ascii",
        "descriptor_oversize",
        "path",
        "relative",
        "primary",
        "argv",
        "rows",
        "harness",
        "harness_empty",
        "custody_missing",
    ],
)
def test_prelaunch_context_strict_linux_amd64_harness(
    prelaunch_context_harness: tuple[str, Path], mutation: str
) -> None:
    docker, work = prelaunch_context_harness
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
            "/work/prelaunch-context-harness",
            mutation,
        ]
    )
    assert result.returncode == 0, (mutation, result.stdout, result.stderr)
    assert f"prelaunch_context_harness_ok mutation={mutation} zero_authority=1" in result.stdout
