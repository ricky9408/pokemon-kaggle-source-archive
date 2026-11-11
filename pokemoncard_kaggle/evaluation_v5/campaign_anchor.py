"""Raw RFC 3161 preregistration anchors for an evaluation v5 campaign.

This anchor is deliberately independent from archive custody.  It proves only
that one canonical, outcome-free campaign payload was timestamped before the
campaign opened.  Verification always starts with the raw token and CA bytes;
no persisted timestamp receipt is accepted as evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from evaluation_v4_1.timestamping import TimestampVerificationError, verify_rfc3161_token

from .canonical import canonical_json_bytes, canonical_sha256
from .cohort import PROTOCOL_ID


ANCHOR_PAYLOAD_SCHEMA = "evaluation_v5_rfc3161_campaign_anchor_payload_v1"
VERIFIED_ANCHOR_SCHEMA = "evaluation_v5_rfc3161_campaign_anchor_verified_v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "protocol",
        "architecture_binding_sha256",
        "implementation_binding_sha256",
        "campaign_sha256",
        "trust_roots_snapshot_sha256",
        "campaign_opened_at_utc",
    }
)


class CampaignAnchorError(ValueError):
    """A campaign preregistration anchor is malformed or unverifiable."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CampaignAnchorError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise CampaignAnchorError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_utc(value: object, *, label: str) -> tuple[datetime, str]:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise CampaignAnchorError(f"{label} must be canonical six-microsecond UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CampaignAnchorError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise CampaignAnchorError(f"{label} must be canonical six-microsecond UTC")
    return parsed, value


def build_campaign_anchor_payload(
    *,
    architecture_binding_sha256: str,
    implementation_binding_sha256: str,
    campaign_sha256: str,
    trust_roots_snapshot_sha256: str,
    campaign_opened_at_utc: str,
) -> dict[str, str]:
    """Build the exact outcome-free payload intended for RFC 3161 timestamping."""

    return validate_campaign_anchor_payload(
        {
            "schema": ANCHOR_PAYLOAD_SCHEMA,
            "protocol": PROTOCOL_ID,
            "architecture_binding_sha256": architecture_binding_sha256,
            "implementation_binding_sha256": implementation_binding_sha256,
            "campaign_sha256": campaign_sha256,
            "trust_roots_snapshot_sha256": trust_roots_snapshot_sha256,
            "campaign_opened_at_utc": campaign_opened_at_utc,
        }
    )


def validate_campaign_anchor_payload(value: object) -> dict[str, str]:
    """Validate an exact campaign payload without adding or dropping fields."""

    raw = _exact_fields(value, _PAYLOAD_FIELDS, label="campaign anchor payload")
    if type(raw["schema"]) is not str or raw["schema"] != ANCHOR_PAYLOAD_SCHEMA:
        raise CampaignAnchorError(f"payload schema must be {ANCHOR_PAYLOAD_SCHEMA!r}")
    if type(raw["protocol"]) is not str or raw["protocol"] != PROTOCOL_ID:
        raise CampaignAnchorError(f"payload protocol must be {PROTOCOL_ID!r}")
    result = {"schema": ANCHOR_PAYLOAD_SCHEMA, "protocol": PROTOCOL_ID}
    for field in (
        "architecture_binding_sha256",
        "implementation_binding_sha256",
        "campaign_sha256",
        "trust_roots_snapshot_sha256",
    ):
        result[field] = _sha256(raw[field], label=field)
    _, result["campaign_opened_at_utc"] = _canonical_utc(
        raw["campaign_opened_at_utc"], label="campaign_opened_at_utc"
    )
    return result


def canonical_campaign_anchor_payload_bytes(value: object) -> bytes:
    """Return the only byte representation that may be timestamped."""

    return canonical_json_bytes(validate_campaign_anchor_payload(value))


def campaign_anchor_payload_sha256(value: object) -> str:
    """Return the SHA-256 identity of a validated campaign payload."""

    return hashlib.sha256(canonical_campaign_anchor_payload_bytes(value)).hexdigest()


def _write_once(path: str | Path, payload: bytes) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise CampaignAnchorError(f"campaign anchor payload already exists: {target}") from exc
    except OSError as exc:
        raise CampaignAnchorError(f"cannot create campaign anchor payload: {exc}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CampaignAnchorError("cannot durably write campaign anchor payload")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as exc:
        raise CampaignAnchorError(f"cannot durably write campaign anchor payload: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        parent_descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise CampaignAnchorError(f"cannot durably flush campaign anchor parent: {exc}") from exc
    return target


def write_campaign_anchor_payload_once(path: str | Path, payload: object) -> Path:
    """Create one canonical payload file, refusing replacement or overwrite."""

    return _write_once(path, canonical_campaign_anchor_payload_bytes(payload))


def build_and_write_campaign_anchor_payload_once(
    path: str | Path,
    **payload_fields: str,
) -> Path:
    """Build and durably create a campaign payload exactly once."""

    return write_campaign_anchor_payload_once(path, build_campaign_anchor_payload(**payload_fields))


def _safe_regular_path(path: str | Path, *, label: str) -> Path:
    if not isinstance(path, (str, Path)) or not str(path) or "\x00" in str(path):
        raise CampaignAnchorError(f"{label} path is invalid")
    raw = Path(path)
    try:
        entry = raw.lstat()
    except OSError as exc:
        raise CampaignAnchorError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(entry.st_mode):
        raise CampaignAnchorError(f"{label} must not be a symlink")
    if not stat.S_ISREG(entry.st_mode):
        raise CampaignAnchorError(f"{label} is not a regular file")
    try:
        return raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CampaignAnchorError(f"cannot normalize {label}: {exc}") from exc


def _read_regular_bytes(path: str | Path, *, label: str) -> tuple[Path, bytes, str]:
    normalized = _safe_regular_path(path, label=label)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(normalized, flags)
    except OSError as exc:
        raise CampaignAnchorError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CampaignAnchorError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CampaignAnchorError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(descriptor)
    before_stat = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_stat = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_stat != after_stat or len(data) != before.st_size:
        raise CampaignAnchorError(f"{label} changed while it was read")
    return normalized, data, hashlib.sha256(data).hexdigest()


def _load_canonical_payload(path: str | Path) -> tuple[Path, dict[str, str], bytes, str]:
    normalized, raw, digest = _read_regular_bytes(path, label="payload")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignAnchorError("payload is not ASCII JSON") from exc
    checked = validate_campaign_anchor_payload(value)
    if raw != canonical_json_bytes(checked):
        raise CampaignAnchorError("payload bytes are not canonical")
    return normalized, checked, raw, digest


def verify_campaign_anchor(
    *,
    payload_path: str | Path,
    token_path: str | Path,
    ca_file: str | Path,
    expected_ca_file_sha256: str,
    expected_tsa_policy_oid: str,
    openssl_bin: str = "openssl",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Verify one raw RFC 3161 campaign anchor before campaign opening.

    ``expected_ca_file_sha256`` and ``expected_tsa_policy_oid`` are supplied by
    an independently pinned trust-root configuration.  The returned record is
    evidence of existence and chronology only; it grants no authority.
    """

    expected_ca = _sha256(expected_ca_file_sha256, label="expected CA SHA-256")
    if type(expected_tsa_policy_oid) is not str or not expected_tsa_policy_oid:
        raise CampaignAnchorError("expected TSA policy OID must be a non-empty string")

    payload_file, payload, payload_bytes, payload_sha = _load_canonical_payload(payload_path)
    token_file, token_bytes, token_sha = _read_regular_bytes(token_path, label="token")
    ca_path, ca_bytes, ca_sha = _read_regular_bytes(ca_file, label="CA file")
    if ca_sha != expected_ca:
        raise CampaignAnchorError("CA file SHA-256 does not match the pinned expected hash")
    try:
        receipt = verify_rfc3161_token(
            data_path=payload_file,
            token_path=token_file,
            ca_file=ca_path,
            openssl_bin=openssl_bin,
            runner=runner,
        )
    except TimestampVerificationError as exc:
        raise CampaignAnchorError(f"RFC 3161 verification failed: {exc}") from exc
    if not isinstance(receipt, Mapping) or receipt.get("verified") is not True:
        raise CampaignAnchorError("raw RFC 3161 verification did not produce a verified result")
    if receipt.get("data_sha256") != payload_sha:
        raise CampaignAnchorError("RFC 3161 data hash does not bind the canonical payload")
    if receipt.get("token_sha256") != token_sha or receipt.get("ca_file_sha256") != ca_sha:
        raise CampaignAnchorError("RFC 3161 verification did not bind exact token and CA bytes")
    if receipt.get("tsa_policy_oid") != expected_tsa_policy_oid:
        raise CampaignAnchorError("RFC 3161 TSA policy does not match the pinned policy OID")

    # Re-open every input after the external verifier returns to detect replacement.
    _, payload_after, payload_after_sha = _read_regular_bytes(payload_file, label="payload")
    _, token_after, token_after_sha = _read_regular_bytes(token_file, label="token")
    _, ca_after, ca_after_sha = _read_regular_bytes(ca_path, label="CA file")
    if (
        payload_after != payload_bytes
        or payload_after_sha != payload_sha
        or token_after != token_bytes
        or token_after_sha != token_sha
        or ca_after != ca_bytes
        or ca_after_sha != ca_sha
    ):
        raise CampaignAnchorError("campaign anchor input changed during RFC 3161 verification")

    if type(receipt.get("tsa_serial")) is not str or not receipt["tsa_serial"]:
        raise CampaignAnchorError("verified TSA serial is absent")
    granted, granted_text = _canonical_utc(receipt.get("granted_at_utc"), label="TSA granted_at_utc")
    opened, opened_text = _canonical_utc(
        payload["campaign_opened_at_utc"], label="campaign_opened_at_utc"
    )
    if not granted < opened:
        raise CampaignAnchorError("TSA grant must be strictly before campaign opening")

    content: dict[str, Any] = {
        "schema": VERIFIED_ANCHOR_SCHEMA,
        "protocol": PROTOCOL_ID,
        "verified": True,
        "payload_schema": payload["schema"],
        "payload_sha256": payload_sha,
        "token_sha256": token_sha,
        "ca_file_sha256": ca_sha,
        "tsa_policy_oid": expected_tsa_policy_oid,
        "tsa_serial": receipt["tsa_serial"],
        "granted_at_utc": granted_text,
        "architecture_binding_sha256": payload["architecture_binding_sha256"],
        "implementation_binding_sha256": payload["implementation_binding_sha256"],
        "campaign_sha256": payload["campaign_sha256"],
        "trust_roots_snapshot_sha256": payload["trust_roots_snapshot_sha256"],
        "campaign_opened_at_utc": opened_text,
        "authority": False,
        "submission": False,
        "holdout": False,
    }
    return {**content, "evidence_sha256": canonical_sha256(content)}


verify_campaign_preregistration_anchor = verify_campaign_anchor


__all__ = [
    "ANCHOR_PAYLOAD_SCHEMA",
    "CampaignAnchorError",
    "VERIFIED_ANCHOR_SCHEMA",
    "build_and_write_campaign_anchor_payload_once",
    "build_campaign_anchor_payload",
    "canonical_campaign_anchor_payload_bytes",
    "campaign_anchor_payload_sha256",
    "validate_campaign_anchor_payload",
    "verify_campaign_anchor",
    "verify_campaign_preregistration_anchor",
    "write_campaign_anchor_payload_once",
]
