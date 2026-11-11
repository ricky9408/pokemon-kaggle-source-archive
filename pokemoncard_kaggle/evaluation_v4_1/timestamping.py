"""RFC 3161 verification for prospective v4.1 registrations.

The module never requests a timestamp and never treats one as performance
evidence.  It verifies that exact registration bytes existed by a trusted TSA
time and exposes that time for strict pre-upload / pre-game chronology checks.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Sequence


RECEIPT_SCHEMA = "rfc3161_registration_anchor_v1"
_GRANTED_RE = re.compile(r"^Status:\s+Granted\.$", re.MULTILINE)
_POLICY_RE = re.compile(r"^Policy OID:\s+(\S+)\s*$", re.MULTILINE)
_SERIAL_RE = re.compile(r"^Serial number:\s+(\S+)\s*$", re.MULTILINE)
_TIME_RE = re.compile(r"^Time stamp:\s+(.+ GMT)\s*$", re.MULTILINE)
_HASH_RE = re.compile(r"^Hash Algorithm:\s+sha256\s*$", re.MULTILINE)


class TimestampVerificationError(ValueError):
    """An RFC 3161 token or its chronology is invalid."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TimestampVerificationError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise TimestampVerificationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise TimestampVerificationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _run(
    command: Sequence[str],
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TimestampVerificationError(f"timestamp verifier failed to execute: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "verification failed").strip()
        raise TimestampVerificationError(detail)
    return result


def verify_rfc3161_token(
    *,
    data_path: str | Path,
    token_path: str | Path,
    ca_file: str | Path,
    openssl_bin: str = "openssl",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Verify a SHA-256 RFC 3161 token against exact data bytes and a CA file."""

    data = Path(data_path)
    token = Path(token_path)
    trust = Path(ca_file)
    for path, label in ((data, "data"), (token, "token"), (trust, "CA file")):
        if not path.is_file():
            raise TimestampVerificationError(f"{label} is not a regular file: {path}")
    if not openssl_bin:
        raise TimestampVerificationError("openssl_bin must be a non-empty executable name")
    executable = Path(openssl_bin)
    if not executable.is_absolute() and executable.name != openssl_bin:
        raise TimestampVerificationError(
            "openssl_bin must be a bare name or an independently verified absolute path"
        )

    verify = _run(
        (
            openssl_bin,
            "ts",
            "-verify",
            "-data",
            str(data),
            "-in",
            str(token),
            "-CAfile",
            str(trust),
        ),
        runner=runner,
    )
    if "Verification: OK" not in (verify.stdout + verify.stderr):
        raise TimestampVerificationError("OpenSSL did not emit Verification: OK")

    detail = _run(
        (openssl_bin, "ts", "-reply", "-in", str(token), "-text"),
        runner=runner,
    ).stdout
    if _GRANTED_RE.search(detail) is None or _HASH_RE.search(detail) is None:
        raise TimestampVerificationError("timestamp response is not a granted SHA-256 token")
    policy = _POLICY_RE.search(detail)
    serial = _SERIAL_RE.search(detail)
    granted = _TIME_RE.search(detail)
    if policy is None or serial is None or granted is None:
        raise TimestampVerificationError("timestamp response is missing policy, serial, or time")
    try:
        granted_at = datetime.strptime(granted.group(1), "%b %d %H:%M:%S %Y GMT").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TimestampVerificationError("timestamp response time is invalid") from exc

    version = _run((openssl_bin, "version"), runner=runner).stdout.strip()
    return {
        "schema": RECEIPT_SCHEMA,
        "verified": True,
        "scope": "existence_and_chronology_only",
        "data_path": str(data),
        "data_sha256": _sha256_file(data),
        "token_path": str(token),
        "token_sha256": _sha256_file(token),
        "ca_file": str(trust),
        "ca_file_sha256": _sha256_file(trust),
        "tsa_policy_oid": policy.group(1),
        "tsa_serial": serial.group(1),
        "granted_at_utc": _canonical_utc(granted_at),
        "openssl_version": version,
        "performance_evidence": False,
        "production_submission_authorized": False,
    }


def verify_anchor_chronology(
    receipt: dict[str, Any],
    *,
    submission_created_at_utc: str,
    first_game_created_at_utc: str,
) -> dict[str, str]:
    """Require TSA grant < hosted submission creation < first eligible game."""

    if receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("verified") is not True:
        raise TimestampVerificationError("a verified RFC 3161 receipt is required")
    granted = _parse_utc(receipt.get("granted_at_utc"), label="granted_at_utc")
    submitted = _parse_utc(submission_created_at_utc, label="submission_created_at_utc")
    first_game = _parse_utc(first_game_created_at_utc, label="first_game_created_at_utc")
    if not granted < submitted:
        raise TimestampVerificationError("timestamp grant must be strictly before submission creation")
    if not submitted < first_game:
        raise TimestampVerificationError("submission creation must be strictly before first eligible game")
    return {
        "granted_at_utc": _canonical_utc(granted),
        "submission_created_at_utc": _canonical_utc(submitted),
        "first_game_created_at_utc": _canonical_utc(first_game),
    }


def write_receipt_once(
    path: str | Path,
    *,
    data_path: str | Path,
    token_path: str | Path,
    ca_file: str | Path,
    openssl_bin: str = "openssl",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    """Verify raw bytes and persist the resulting receipt exactly once."""

    import json

    receipt = verify_rfc3161_token(
        data_path=data_path,
        token_path=token_path,
        ca_file=ca_file,
        openssl_bin=openssl_bin,
        runner=runner,
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False).encode("ascii") + b"\n"
    try:
        with target.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"timestamp receipt already exists: {target}") from None
    return target


__all__ = [
    "RECEIPT_SCHEMA",
    "TimestampVerificationError",
    "verify_anchor_chronology",
    "verify_rfc3161_token",
    "write_receipt_once",
]
