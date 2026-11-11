from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


@pytest.fixture(scope="module")
def retained_inputs_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 retained-input test")
    image = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-retained-inputs")
    command = [
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
        "/src/tests/native/v631302_retained_inputs_harness.cpp",
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
        "/work/retained-inputs-harness",
    ]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
            "-v",
            f"{work}:/work:ro",
            IMAGE,
            "/work/retained-inputs-harness",
            mode,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_retained_inputs_hash_and_copy_from_one_retained_descriptor(
    retained_inputs_harness: tuple[str, Path],
) -> None:
    result = _run(retained_inputs_harness, "valid")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    source_digest = hashlib.sha256(b"int value = 7;\n").hexdigest()
    assert lines == [
        f"bin/collector 15 {hashlib.sha256(b'collector-bytes').hexdigest()}",
        f"src/fixture.cc 15 {source_digest}",
        "single-materialization-enforced",
    ]


@pytest.mark.parametrize(
    ("mode", "failure_code"),
    [
        ("symlink", 3),
        ("hardlink", 4),
        ("writable", 4),
        ("duplicate-namespace", 1),
        ("unsafe-path", 2),
        ("wrong-mode", 1),
        ("missing-primary", 1),
        ("unsorted", 1),
        ("alias-destination", 6),
        ("mutate", 5),
    ],
)
def test_retained_inputs_fail_closed(
    retained_inputs_harness: tuple[str, Path], mode: str, failure_code: int
) -> None:
    result = _run(retained_inputs_harness, mode)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.startswith(f"{failure_code}:")
