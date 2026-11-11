from __future__ import annotations

from pathlib import Path
import hashlib
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
NATIVE = ROOT / "evaluation_v6_3_1/native/capture_v2"
SOURCE = NATIVE / "Stage1SeccompFilterV1.cpp"
HEADER = NATIVE / "Stage1SeccompFilterV1.h"
HARNESS = ROOT / "tests/native/Stage1SeccompFilterHarness.cpp"
EXPECTED_SHA256 = "123051e7323f8daef935d7ee73ef62fff8117c6a035c75e99c919cf8a900d7a6"


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = _run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"])
    return result.returncode == 0 and result.stdout.strip() == f"{IMAGE} amd64"


@pytest.fixture(scope="module")
def native_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-seccomp-filter")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion'
/usr/bin/clang++-16 $flags -I/repo/evaluation_v6_3_1/native/capture_v2 /repo/evaluation_v6_3_1/native/capture_v2/Stage1SeccompFilterV1.cpp /repo/tests/native/Stage1SeccompFilterHarness.cpp -o /out/seccomp-filter-harness
chmod 0555 /out/seccomp-filter-harness
"""
    result = _run([
        "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
        "--mount", f"type=bind,src={ROOT},dst=/repo,readonly",
        "--mount", f"type=bind,src={output},dst=/out", IMAGE, "/bin/sh", "-lc", script,
    ])
    assert result.returncode == 0, result.stderr
    return output / "seccomp-filter-harness"


def _invoke(harness: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _run([
        "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
        "--mount", f"type=bind,src={harness.parent},dst=/out,readonly", IMAGE,
        "/out/seccomp-filter-harness", *args,
    ])


def test_frozen_source_declares_zero_authority_and_no_builder() -> None:
    header = HEADER.read_text(encoding="ascii")
    source = SOURCE.read_text(encoding="ascii")
    assert "kStage1SeccompV1ZeroAuthority = true" in header
    assert "kStage1SeccompV1UploadAuthority = false" in header
    assert "const sock_filter kStage1SeccompFilterV1" in source
    assert "std::memset(output, 0, sizeof(*output))" in source
    assert "initialize_stage1_seccomp_program_v1" in source
    assert "seccomp(" not in source
    assert "SECCOMP_SET_MODE_FILTER" not in source
    assert "generate" not in source.lower()


def test_erratum_digest_is_anchored_by_the_frozen_hex() -> None:
    expected = bytes.fromhex(
        "2000000004000000150001003e0000c006000000000000802000000000000000"
        "4500000100000040060000000000008015000001380000000600000000000080"
        "15000001390000000600000000000080150000013a0000000600000000000080"
        "1500000150000000060000000000008015000001510000000600000000000080"
        "150000019b000000060000000000008015000001a50000000600000000000080"
        "15000001a6000000060000000000008015000001100100000600000000000080"
        "1500000134010000060000000000008015000001ac0100000600000000000080"
        "15000001ad010000060000000000008015000001ae0100000600000000000080"
        "15000001af010000060000000000008015000001b00100000600000000000080"
        "15000001b1010000060000000000008015000001b30100000600000000000080"
        "15000001ba0100000600000000000080060000000000ff7f"
    )
    assert len(expected) == 344
    assert hashlib.sha256(expected).hexdigest() == EXPECTED_SHA256


@pytest.mark.docker_smoke
def test_linux_amd64_harness_accepts_exact_program(native_harness: Path) -> None:
    result = _invoke(native_harness)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "instructions=43 bytes=344 descriptor_valid=1 raw_first=32 raw_last=127 zero_authority=1\n"
    assert result.stderr == ""


@pytest.mark.docker_smoke
def test_linux_amd64_harness_validates_canonical_program(native_harness: Path) -> None:
    result = _invoke(native_harness, "validate")
    assert result.returncode == 0, result.stderr


@pytest.mark.docker_smoke
@pytest.mark.parametrize("source", ["actual", "exact", "padded-hex"])
def test_linux_amd64_harness_validates_read_only_filter_mapping(
    native_harness: Path, source: str
) -> None:
    result = _invoke(native_harness, "mapping", source)
    assert result.returncode == 0, (source, result.stdout, result.stderr)


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    "mutation",
    ["writable", "unreadable", "duplicate", "split", "missing", "malformed", "unterminated"],
)
def test_filter_mapping_mutations_are_rejected(
    native_harness: Path, mutation: str
) -> None:
    result = _invoke(native_harness, "mapping", mutation)
    assert result.returncode == 0, (mutation, result.stdout, result.stderr)


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    "mutation",
    [
        "code",
        "jt",
        "jf",
        "constant",
        "architecture",
        "architecture-reversed",
        "x32-constant",
        "x32-jump",
        "denied-order",
        "denied-duplicate",
        "kill-action",
        "jump-offset-above-one",
        "backward-style-jump",
        "final-action",
        "count",
        "pointer",
        "padding",
    ],
)
def test_mutations_are_rejected(native_harness: Path, mutation: str) -> None:
    result = _invoke(native_harness, "mutate", mutation)
    assert result.returncode == 0, (mutation, result.stdout, result.stderr)
