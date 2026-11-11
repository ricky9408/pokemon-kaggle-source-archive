from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, text=True, capture_output=True)


@pytest.fixture(scope="module")
def proc_inspector_harness(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 proc-inspector test")
    image = _run([docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE])
    if image.returncode != 0 or image.stdout.strip() != "amd64":
        pytest.skip("the pinned Linux/amd64 Clang 16 image is unavailable")

    work = tmp_path_factory.mktemp("capture-v2-proc-inspector")
    compile_result = _run(
        [
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
            "/src/evaluation_v6_3_1/native/capture_v2/ProcInspector.cpp",
            "/src/tests/native/v631302_proc_inspector_harness.cpp",
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
            "/work/proc-inspector-harness",
        ]
    )
    assert compile_result.returncode == 0, compile_result.stderr
    return docker, work


def _harness_run(harness: tuple[str, Path], mode: str) -> subprocess.CompletedProcess[str]:
    docker, work = harness
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
            "/work/proc-inspector-harness",
            mode,
        ]
    )


def test_proc_inspector_authenticates_only_the_exact_stopped_process(
    proc_inspector_harness: tuple[str, Path],
) -> None:
    result = _harness_run(proc_inspector_harness, "valid")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"proc_inspector_ok pid=\d+ argv=\d+ size=\d+ digest=[0-9a-f]{64} cwd=\d+:\d+ cwd_link=/\S+ uid=0 gid=0 caps0=1 nnp=1 zero_authority=1\n",
        result.stdout,
    )


@pytest.mark.parametrize(
    "mode",
    ["argv", "environment", "digest", "length", "cwd", "running", "privileges"],
)
def test_proc_inspector_fails_closed_on_identity_mutations(
    proc_inspector_harness: tuple[str, Path], mode: str
) -> None:
    result = _harness_run(proc_inspector_harness, mode)
    assert result.returncode == 0, (mode, result.stdout, result.stderr)
    assert re.fullmatch(
        rf"proc_inspector_rejected {mode} failure=\d+ terminal_failed=1\n", result.stdout
    )


def test_proc_inspector_treats_cwd_link_as_diagnostic_only(
    proc_inspector_harness: tuple[str, Path],
) -> None:
    result = _harness_run(proc_inspector_harness, "cwd-path")
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert re.fullmatch(
        r"proc_inspector_ok pid=\d+ argv=\d+ size=\d+ digest=[0-9a-f]{64} cwd=\d+:\d+ cwd_link=/\S+ uid=0 gid=0 caps0=1 nnp=1 zero_authority=1\n",
        result.stdout,
    )
