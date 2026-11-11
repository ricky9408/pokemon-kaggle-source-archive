from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
RECEIPT = ROOT / "evaluation_artifacts/capture_v2_receipt_checkpoint_20260803/evidence/phase_receipt.bin"
TRACE = ROOT / "evaluation_artifacts/capture_v2_receipt_checkpoint_20260803/evidence/phase_write_trace.bin"


@pytest.fixture(scope="module")
def receipt_parser_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped pinned Linux/amd64 receipt parser test")
    inspected = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if inspected.returncode != 0 or inspected.stdout.strip() != b"amd64":
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    work = tmp_path_factory.mktemp("v631302-receipt-stream-parser")
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
        "clang++",
        "-std=c++20",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wpedantic",
        "-I/src/evaluation_v6_3_1/native/capture_v2",
        "/src/evaluation_v6_3_1/native/capture_v2/ReceiptStreamParser.cpp",
        "/src/tests/native/v631302_receipt_stream_parser_harness.cpp",
        "-o",
        "/work/receipt-stream-parser-harness",
    ]
    built = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert built.returncode == 0, built.stderr.decode("utf-8", errors="replace")
    return work / "receipt-stream-parser-harness"


def _run(harness: Path, mode: str) -> subprocess.CompletedProcess[bytes]:
    docker = shutil.which("docker")
    assert docker is not None
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
            f"{ROOT}:/src:ro",
            "-v",
            f"{harness.parent}:/work:ro",
            IMAGE,
            "/work/receipt-stream-parser-harness",
            "/src/evaluation_artifacts/capture_v2_receipt_checkpoint_20260803/evidence/phase_receipt.bin",
            "/src/evaluation_artifacts/capture_v2_receipt_checkpoint_20260803/evidence/phase_write_trace.bin",
            mode,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.mark.parametrize("mode", ["valid", "chunked", "phase_mapping", "after_eof"])
def test_receipt_stream_parser_accepts_existing_amendment10_evidence(
    receipt_parser_harness: Path, mode: str
) -> None:
    result = _run(receipt_parser_harness, mode)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


@pytest.mark.parametrize(
    "mode",
    [
        "bad_magic",
        "noncanonical",
        "truncated",
        "extra",
        "sequence",
        "reordered_phase",
        "duplicate_phase",
        "final_path",
        "bad_path",
        "nul_argv",
        "short_phase",
        "writev_phase",
        "pipebuf_phase",
        "stream_write_disagreement",
        "zero_write",
        "overlong_write",
    ],
)
def test_receipt_stream_parser_fails_closed_on_wire_and_write_mutations(
    receipt_parser_harness: Path, mode: str
) -> None:
    result = _run(receipt_parser_harness, mode)
    assert result.returncode == 0, (
        mode,
        result.stdout.decode("utf-8", errors="replace"),
        result.stderr.decode("utf-8", errors="replace"),
    )
