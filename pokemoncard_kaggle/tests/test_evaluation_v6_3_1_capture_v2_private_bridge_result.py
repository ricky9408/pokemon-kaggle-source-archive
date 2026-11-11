"""Exact move-only Result API for the zero-authority Bridge V3 encoder."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command, check=False, text=True, capture_output=True, timeout=timeout
    )


@pytest.fixture(scope="module")
def result_harness(tmp_path_factory: pytest.TempPathFactory) -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 result harness")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    work = tmp_path_factory.mktemp("private-bridge-result")
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
            "-I/src/evaluation_v6_3_1/native/capture_v2",
            "/src/tests/native/v631302_private_bridge_result_harness.cpp",
            "-o",
            "/work/private-bridge-result-harness",
        ]
    )
    assert build.returncode == 0, build.stderr
    return prefix + ["/work/private-bridge-result-harness"]


def test_result_success_failure_and_move_are_allocation_free(
    result_harness: list[str],
) -> None:
    result = _run(result_harness)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "private_bridge_result_ok zero_authority=1"


@pytest.mark.parametrize(
    "mode",
    ["error-on-value", "value-on-error", "source-after-move", "value-after-take"],
)
def test_invalid_result_access_terminates(
    result_harness: list[str], mode: str
) -> None:
    result = _run(result_harness + [mode], timeout=30)
    assert result.returncode == 86
