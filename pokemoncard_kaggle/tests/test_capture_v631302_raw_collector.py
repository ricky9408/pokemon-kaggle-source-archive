from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import stat
import sys

import pytest

from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)
from tools.capture_v631302_raw_collector import (
    CAPTURE_DOMAIN,
    CaptureError,
    run_capture,
)


def _executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="ascii")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _inputs(tmp_path: Path, *, collector_stderr: bool = False) -> argparse.Namespace:
    raw = eir_canonical_cbor_encode([631302, 1, [["VarDecl"]]])
    collector = _executable(
        tmp_path / "collector",
        f"#!{sys.executable}\n"
        "import sys\n"
        + ("sys.stderr.write('bad')\n" if collector_stderr else "")
        + f"sys.stdout.buffer.write(bytes.fromhex('{raw.hex()}'))\n",
    )
    clang = _executable(tmp_path / "clang-16", "#!/bin/sh\nprintf '16.0.6\\n'\n")
    primary = tmp_path / "Export.cpp"
    primary.write_text("int main() { return 0; }\n", encoding="ascii")
    driver = tmp_path / "driver.cbor"
    cc1 = tmp_path / "cc1.cbor"
    path_profile = tmp_path / "path.cbor"
    driver.write_bytes(eir_canonical_cbor_encode([631302, 1, [["driver"]]]))
    cc1.write_bytes(eir_canonical_cbor_encode([631302, 1, [["cc1"]]]))
    path_profile.write_bytes(eir_canonical_cbor_encode([631302, 1, "/source", "/work"]))
    return argparse.Namespace(
        collector=collector,
        collector_build_id="V631302_TEST_COLLECTOR_V1",
        clang=clang,
        working_directory=tmp_path,
        primary_source=primary,
        source_root_sha256=hashlib.sha256(b"source").hexdigest(),
        runtime_root_sha256=hashlib.sha256(b"runtime").hexdigest(),
        driver_input_manifest=driver,
        cc1_input_manifest=cc1,
        path_normalization_profile=path_profile,
        compiler_argument=["-std=c++20", "-fsyntax-only"],
        environment=[],
        output_raw=tmp_path / "raw.cbor",
        output_capture=tmp_path / "capture.cbor",
    )


def test_capture_binds_exact_producer_invocation_raw_and_harness(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    raw, capture_bytes, capture_root = run_capture(args)
    capture = eir_canonical_cbor_decode(capture_bytes)
    assert args.output_raw.read_bytes() == raw
    assert args.output_capture.read_bytes() == capture_bytes
    assert capture[0:2] == [631302, 1]
    assert capture[2][2] == "V631302_TEST_COLLECTOR_V1"
    assert capture[3][2] == 16
    assert capture[5] == [len(raw), hashlib.sha256(raw).digest()]
    assert capture[7] == 0
    assert capture[8] == [0, hashlib.sha256(b"").digest()]
    assert capture_root == hashlib.sha256(
        eir_canonical_cbor_encode([CAPTURE_DOMAIN, capture])
    ).digest()


def test_capture_fails_closed_without_publishing_partial_outputs(tmp_path: Path) -> None:
    args = _inputs(tmp_path, collector_stderr=True)
    with pytest.raises(CaptureError, match="collector failed closed"):
        run_capture(args)
    assert not args.output_raw.exists()
    assert not args.output_capture.exists()


def test_capture_rejects_noncanonical_input_manifest(tmp_path: Path) -> None:
    args = _inputs(tmp_path)
    args.driver_input_manifest.write_bytes(b"\x98\x01\x00")
    with pytest.raises(CaptureError, match="driver input manifest is not canonical CBOR"):
        run_capture(args)
