#!/usr/bin/env python3
"""Capture one exact zero-authority V631302 raw-collector execution.

The output binds producer, toolchain, invocation inputs, raw bytes, harness,
exit status, and stderr into the Amendment-7 RAW_COLLECTOR_CAPTURE_V1 shape.
It does not grant campaign, upload, or diagnostic-collector authority.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence

from evaluation_v6_3_1.eir_prebinding import (
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
)


PROTOCOL = 631302
CAPTURE_VERSION = 1
HARNESS_BUILD_ID = "V631302_RAW_COLLECTOR_CAPTURE_HARNESS_V1"
CAPTURE_DOMAIN = b"V631302_RAW_COLLECTOR_CAPTURE_V1"
EMPTY_SHA256 = hashlib.sha256(b"").digest()


class CaptureError(RuntimeError):
    pass


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _digest(value: str, label: str) -> bytes:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CaptureError(f"{label} must be a lowercase SHA-256")
    return bytes.fromhex(value)


def _regular_file(path: Path, label: str) -> tuple[Path, bytes]:
    resolved = path.resolve(strict=True)
    status = resolved.stat()
    if not resolved.is_file() or status.st_size < 0:
        raise CaptureError(f"{label} must be a regular file")
    return resolved, resolved.read_bytes()


def _canonical_file(path: Path, label: str) -> tuple[bytes, object]:
    _, raw = _regular_file(path, label)
    try:
        value = eir_canonical_cbor_decode(raw)
    except Exception as exc:  # noqa: BLE001 - normalized to one fail-closed error.
        raise CaptureError(f"{label} is not canonical CBOR") from exc
    if eir_canonical_cbor_encode(value) != raw:
        raise CaptureError(f"{label} is not byte-canonical")
    return raw, value


def _environment(rows: Sequence[str]) -> tuple[dict[str, str], list[list[str]]]:
    parsed: dict[str, str] = {}
    for row in rows:
        key, separator, value = row.partition("=")
        if not separator or not key or "\x00" in key or "\x00" in value or "=" in key:
            raise CaptureError("environment rows must be KEY=VALUE without NUL bytes")
        if key in parsed:
            raise CaptureError(f"duplicate environment key: {key}")
        parsed[key] = value
    ordered = [[key, parsed[key]] for key in sorted(parsed)]
    return dict(ordered), ordered


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--collector-build-id", required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--working-directory", type=Path, required=True)
    parser.add_argument("--primary-source", type=Path, required=True)
    parser.add_argument("--source-root-sha256", required=True)
    parser.add_argument("--runtime-root-sha256", required=True)
    parser.add_argument("--driver-input-manifest", type=Path, required=True)
    parser.add_argument("--cc1-input-manifest", type=Path, required=True)
    parser.add_argument("--path-normalization-profile", type=Path, required=True)
    parser.add_argument("--compiler-argument", action="append", default=[])
    parser.add_argument("--environment", action="append", default=[])
    parser.add_argument(
        "--structural-test-no-fd3-receipt",
        action="store_true",
        help=(
            "invoke a structural-test build with its explicit retired V1 no-FD3 "
            "switch; this can never produce Capture V2 evidence"
        ),
    )
    parser.add_argument("--output-raw", type=Path, required=True)
    parser.add_argument("--output-capture", type=Path, required=True)
    return parser


def run_capture(args: argparse.Namespace) -> tuple[bytes, bytes, bytes]:
    collector_path, collector_bytes = _regular_file(args.collector, "collector")
    clang_path, clang_bytes = _regular_file(args.clang, "clang")
    primary_path, primary_bytes = _regular_file(args.primary_source, "primary source")
    harness_path, harness_bytes = _regular_file(Path(__file__), "capture harness")
    working_directory = args.working_directory.resolve(strict=True)
    if not working_directory.is_dir():
        raise CaptureError("working directory must be a directory")

    driver_raw, driver_inputs = _canonical_file(
        args.driver_input_manifest, "driver input manifest"
    )
    cc1_raw, cc1_inputs = _canonical_file(args.cc1_input_manifest, "cc1 input manifest")
    path_raw, path_profile = _canonical_file(
        args.path_normalization_profile, "path normalization profile"
    )
    source_root = _digest(args.source_root_sha256, "source root")
    runtime_root = _digest(args.runtime_root_sha256, "runtime root")
    environment, environment_rows = _environment(args.environment)

    version = subprocess.run(
        [str(clang_path), "-dumpversion"],
        cwd=working_directory,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if version.returncode != 0 or version.stderr or not version.stdout.decode("ascii").startswith("16"):
        raise CaptureError("clang identity does not report major version 16 cleanly")

    invocation = [
        str(collector_path),
        "--protocol=631302",
        "--level=2",
        f"--primary-source={primary_path}",
    ]
    if getattr(args, "structural_test_no_fd3_receipt", False):
        invocation.append("--test-no-fd3-receipt")
    invocation.extend(["--", *args.compiler_argument])
    invocation_evidence = [
        PROTOCOL,
        CAPTURE_VERSION,
        [len(collector_bytes), _sha256(collector_bytes), args.collector_build_id],
        [len(clang_bytes), _sha256(clang_bytes), 16],
        [len(driver_raw), _sha256(driver_raw), driver_inputs],
        [len(cc1_raw), _sha256(cc1_raw), cc1_inputs],
        [str(primary_path), len(primary_bytes), _sha256(primary_bytes)],
        [source_root, runtime_root],
        str(working_directory),
        [len(path_raw), _sha256(path_raw), path_profile],
        invocation,
        environment_rows,
    ]
    invocation_root = _sha256(
        eir_canonical_cbor_encode(
            [b"V631302_COLLECTOR_INVOCATION_EVIDENCE_V1", invocation_evidence]
        )
    )

    completed = subprocess.run(
        invocation,
        cwd=working_directory,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0 or completed.stderr:
        raise CaptureError(
            f"collector failed closed: status={completed.returncode}, "
            f"stderr_length={len(completed.stderr)}"
        )
    try:
        raw_value = eir_canonical_cbor_decode(completed.stdout)
    except Exception as exc:  # noqa: BLE001 - normalized to one fail-closed error.
        raise CaptureError("collector stdout is not one canonical CBOR item") from exc
    if eir_canonical_cbor_encode(raw_value) != completed.stdout:
        raise CaptureError("collector stdout is not byte-canonical")

    collector_record = [len(collector_bytes), _sha256(collector_bytes), args.collector_build_id]
    clang_record = [len(clang_bytes), _sha256(clang_bytes), 16]
    raw_record = [len(completed.stdout), _sha256(completed.stdout)]
    harness_record = [len(harness_bytes), _sha256(harness_bytes), HARNESS_BUILD_ID]
    stderr_record = [len(completed.stderr), _sha256(completed.stderr)]
    capture = [
        PROTOCOL,
        CAPTURE_VERSION,
        collector_record,
        clang_record,
        invocation_root,
        raw_record,
        harness_record,
        completed.returncode,
        stderr_record,
    ]
    capture_bytes = eir_canonical_cbor_encode(capture)
    capture_root = _sha256(eir_canonical_cbor_encode([CAPTURE_DOMAIN, capture]))

    _atomic_write(args.output_raw, completed.stdout)
    _atomic_write(args.output_capture, capture_bytes)
    return completed.stdout, capture_bytes, capture_root


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        raw, capture, root = run_capture(args)
    except (CaptureError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 66
    print(f"raw_collector_byte_length={len(raw)}")
    print(f"raw_collector_sha256={_sha256(raw).hex()}")
    print(f"raw_collector_capture_byte_length={len(capture)}")
    print(f"raw_collector_capture_sha256={_sha256(capture).hex()}")
    print(f"raw_collector_capture_root={root.hex()}")
    print("authority=NO_UPLOAD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
