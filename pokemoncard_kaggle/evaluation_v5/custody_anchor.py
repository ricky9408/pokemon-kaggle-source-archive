"""Authority-free RFC 3161 custody anchors for v5 external registrations.

An anchor proves only that the exact, outcome-free registration payload existed
at a TSA grant time.  It does not select an archive, inspect a holdout, or
authorize a submission.  In particular, this module never accepts a saved
JSON "receipt": every verification starts from raw token bytes and the CA
bundle, and invokes :func:`evaluation_v4_1.timestamping.verify_rfc3161_token`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
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
from .cohort import PROTOCOL_ID, validate_registry


ANCHOR_PAYLOAD_SCHEMA = "evaluation_v5_rfc3161_custody_anchor_payload_v1"
VERIFIED_ANCHOR_SCHEMA = "evaluation_v5_rfc3161_custody_anchor_verified_v1"
BATCH_AUDIT_SCHEMA = "evaluation_v5_rfc3161_custody_anchor_audit_v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "protocol",
        "campaign_sha256",
        "implementation_binding_sha256",
        "signed_ancestry_manifest_sha256",
        "archive_registration_sha256",
        "registry_chain_hash_at_registration",
        "model_input_sha256",
        "registered_at_utc",
    }
)
_ANCHOR_PATH_FIELDS = frozenset({"payload_path", "token_path", "ca_file"})


class CustodyAnchorError(ValueError):
    """An external registration custody anchor is malformed or unverifiable."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CustodyAnchorError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise CustodyAnchorError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_utc(value: object, *, label: str) -> tuple[datetime, str]:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise CustodyAnchorError(f"{label} must be canonical six-microsecond UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CustodyAnchorError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise CustodyAnchorError(f"{label} must be canonical six-microsecond UTC")
    return parsed, value


def build_custody_anchor_payload(
    *,
    campaign_sha256: str,
    implementation_binding_sha256: str,
    signed_ancestry_manifest_sha256: str,
    archive_registration_sha256: str,
    registry_chain_hash_at_registration: str,
    model_input_sha256: str,
    registered_at_utc: str,
) -> dict[str, str]:
    """Build the exact outcome-free bytes which an RFC 3161 token must bind."""

    return validate_custody_anchor_payload(
        {
            "schema": ANCHOR_PAYLOAD_SCHEMA,
            "protocol": PROTOCOL_ID,
            "campaign_sha256": campaign_sha256,
            "implementation_binding_sha256": implementation_binding_sha256,
            "signed_ancestry_manifest_sha256": signed_ancestry_manifest_sha256,
            "archive_registration_sha256": archive_registration_sha256,
            "registry_chain_hash_at_registration": registry_chain_hash_at_registration,
            "model_input_sha256": model_input_sha256,
            "registered_at_utc": registered_at_utc,
        }
    )


def validate_custody_anchor_payload(value: object) -> dict[str, str]:
    """Validate an exact canonical custody payload without adding any fields."""

    raw = _exact_fields(value, _PAYLOAD_FIELDS, label="custody anchor payload")
    if raw["schema"] != ANCHOR_PAYLOAD_SCHEMA or type(raw["schema"]) is not str:
        raise CustodyAnchorError(f"payload schema must be {ANCHOR_PAYLOAD_SCHEMA!r}")
    if raw["protocol"] != PROTOCOL_ID or type(raw["protocol"]) is not str:
        raise CustodyAnchorError(f"payload protocol must be {PROTOCOL_ID!r}")
    result = {"schema": ANCHOR_PAYLOAD_SCHEMA, "protocol": PROTOCOL_ID}
    for field in (
        "campaign_sha256",
        "implementation_binding_sha256",
        "signed_ancestry_manifest_sha256",
        "archive_registration_sha256",
        "registry_chain_hash_at_registration",
        "model_input_sha256",
    ):
        result[field] = _sha256(raw[field], label=field)
    _, result["registered_at_utc"] = _canonical_utc(
        raw["registered_at_utc"], label="registered_at_utc"
    )
    return result


def canonical_custody_anchor_payload_bytes(value: object) -> bytes:
    """Return the sole byte representation allowed to be timestamped."""

    return canonical_json_bytes(validate_custody_anchor_payload(value))


def custody_anchor_payload_sha256(value: object) -> str:
    """Return the SHA-256 identity of a validated anchor payload."""

    return hashlib.sha256(canonical_custody_anchor_payload_bytes(value)).hexdigest()


def _create_once_bytes(path: str | Path, payload: bytes) -> Path:
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
        raise CustodyAnchorError(f"custody anchor payload already exists: {target}") from exc
    except OSError as exc:
        raise CustodyAnchorError(f"cannot create custody anchor payload: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise CustodyAnchorError(f"cannot durably write custody anchor payload: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        parent_descriptor = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise CustodyAnchorError(f"cannot durably flush custody anchor payload parent: {exc}") from exc
    return target


def write_custody_anchor_payload_once(path: str | Path, payload: object) -> Path:
    """Create one canonical payload file with ``O_EXCL`` and durable writes."""

    return _create_once_bytes(path, canonical_custody_anchor_payload_bytes(payload))


def build_and_write_custody_anchor_payload_once(
    path: str | Path,
    **payload_fields: str,
) -> Path:
    """Build and durably create an outcome-free anchor payload exactly once."""

    return write_custody_anchor_payload_once(
        path, build_custody_anchor_payload(**payload_fields)
    )


def _safe_regular_path(path: str | Path, *, label: str) -> Path:
    if not isinstance(path, (str, Path)) or not str(path) or "\x00" in str(path):
        raise CustodyAnchorError(f"{label} path is invalid")
    raw = Path(path)
    try:
        entry = raw.lstat()
    except OSError as exc:
        raise CustodyAnchorError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(entry.st_mode):
        raise CustodyAnchorError(f"{label} must not be a symlink")
    if not stat.S_ISREG(entry.st_mode):
        raise CustodyAnchorError(f"{label} is not a regular file")
    try:
        return raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise CustodyAnchorError(f"cannot normalize {label}: {exc}") from exc


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
        raise CustodyAnchorError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CustodyAnchorError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or len(data) != before.st_size:
        raise CustodyAnchorError(f"{label} changed while it was read")
    return normalized, data, hashlib.sha256(data).hexdigest()


def _load_canonical_payload(path: str | Path) -> tuple[Path, dict[str, str], bytes, str]:
    normalized, raw, digest = _read_regular_bytes(path, label="payload")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CustodyAnchorError("payload is not ASCII JSON") from exc
    checked = validate_custody_anchor_payload(value)
    expected = canonical_json_bytes(checked)
    if raw != expected:
        raise CustodyAnchorError("payload bytes are not canonical")
    return normalized, checked, raw, digest


def _verified_content(
    payload: Mapping[str, str],
    *,
    payload_sha256: str,
    token_sha256: str,
    ca_file_sha256: str,
    tsa_policy_oid: object,
    tsa_serial: object,
    granted_at_utc: object,
    first_hosted_game_at_utc: str,
) -> dict[str, Any]:
    if type(tsa_policy_oid) is not str or not tsa_policy_oid:
        raise CustodyAnchorError("verified TSA policy is absent")
    if type(tsa_serial) is not str or not tsa_serial:
        raise CustodyAnchorError("verified TSA serial is absent")
    granted, granted_text = _canonical_utc(granted_at_utc, label="TSA granted_at_utc")
    registered, registered_text = _canonical_utc(
        payload["registered_at_utc"], label="registered_at_utc"
    )
    first_game, first_game_text = _canonical_utc(
        first_hosted_game_at_utc, label="first_hosted_game_at_utc"
    )
    if not granted < registered:
        raise CustodyAnchorError("TSA grant must be strictly before registration")
    if not registered < first_game:
        raise CustodyAnchorError("registration must be strictly before first hosted game")
    return {
        "schema": VERIFIED_ANCHOR_SCHEMA,
        "protocol": PROTOCOL_ID,
        "verified": True,
        "payload_schema": payload["schema"],
        "payload_sha256": payload_sha256,
        "token_sha256": token_sha256,
        "ca_file_sha256": ca_file_sha256,
        "tsa_policy_oid": tsa_policy_oid,
        "tsa_serial": tsa_serial,
        "granted_at_utc": granted_text,
        "campaign_sha256": payload["campaign_sha256"],
        "implementation_binding_sha256": payload["implementation_binding_sha256"],
        "signed_ancestry_manifest_sha256": payload["signed_ancestry_manifest_sha256"],
        "archive_registration_sha256": payload["archive_registration_sha256"],
        "registry_chain_hash_at_registration": payload["registry_chain_hash_at_registration"],
        "model_input_sha256": payload["model_input_sha256"],
        "registered_at_utc": registered_text,
        "first_hosted_game_at_utc": first_game_text,
        "authority": False,
        "submission": False,
        "holdout": False,
    }


def verify_custody_anchor(
    *,
    payload_path: str | Path,
    token_path: str | Path,
    ca_file: str | Path,
    first_hosted_game_at_utc: str,
    openssl_bin: str = "openssl",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Cryptographically verify one raw RFC 3161 custody anchor.

    There is intentionally no ``receipt`` parameter.  The returned evidence
    is derived afresh from the raw token and CA verification result.
    """

    payload_file, payload, payload_bytes, payload_sha = _load_canonical_payload(payload_path)
    token_file, _, token_sha = _read_regular_bytes(token_path, label="token")
    ca_path, _, ca_sha = _read_regular_bytes(ca_file, label="CA file")
    try:
        receipt = verify_rfc3161_token(
            data_path=payload_file,
            token_path=token_file,
            ca_file=ca_path,
            openssl_bin=openssl_bin,
            runner=runner,
        )
    except TimestampVerificationError as exc:
        raise CustodyAnchorError(f"RFC 3161 verification failed: {exc}") from exc
    if not isinstance(receipt, Mapping) or receipt.get("verified") is not True:
        raise CustodyAnchorError("raw RFC 3161 verification did not produce a verified result")
    if receipt.get("data_sha256") != payload_sha:
        raise CustodyAnchorError("RFC 3161 receipt data_sha256 does not bind the canonical payload")
    if receipt.get("token_sha256") != token_sha or receipt.get("ca_file_sha256") != ca_sha:
        raise CustodyAnchorError("RFC 3161 verification did not bind the exact token and CA bytes")
    # Detect replacement after the path-based OpenSSL invocation before using its result.
    _, payload_after, payload_after_sha = _read_regular_bytes(payload_file, label="payload")
    _, token_after, token_after_sha = _read_regular_bytes(token_file, label="token")
    _, ca_after, ca_after_sha = _read_regular_bytes(ca_path, label="CA file")
    if (
        payload_after != payload_bytes
        or payload_after_sha != payload_sha
        or token_after_sha != token_sha
        or ca_after_sha != ca_sha
    ):
        raise CustodyAnchorError("anchor input changed during RFC 3161 verification")
    content = _verified_content(
        payload,
        payload_sha256=payload_sha,
        token_sha256=token_sha,
        ca_file_sha256=ca_sha,
        tsa_policy_oid=receipt.get("tsa_policy_oid"),
        tsa_serial=receipt.get("tsa_serial"),
        granted_at_utc=receipt.get("granted_at_utc"),
        first_hosted_game_at_utc=first_hosted_game_at_utc,
    )
    return {**content, "evidence_sha256": canonical_sha256(content)}


def _anchor_paths(value: object, *, index: int) -> dict[str, str | Path]:
    raw = _exact_fields(value, _ANCHOR_PATH_FIELDS, label=f"anchor {index}")
    for field in _ANCHOR_PATH_FIELDS:
        if not isinstance(raw[field], (str, Path)):
            raise CustodyAnchorError(f"anchor {index} {field} must be a path")
    return {field: raw[field] for field in _ANCHOR_PATH_FIELDS}


def verify_custody_anchor_batch(
    *,
    registry: Mapping[str, Any],
    anchors: Sequence[Mapping[str, str | Path]],
    campaign_sha256: str,
    implementation_binding_sha256: str,
    signed_ancestry_manifest_sha256: str,
    first_hosted_game_at_utc_by_archive: Mapping[str, str],
    openssl_bin: str = "openssl",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Verify exactly one outcome-free anchor for every registry archive."""

    checked_registry = validate_registry(registry)
    expected_campaign = _sha256(campaign_sha256, label="campaign_sha256")
    expected_implementation = _sha256(
        implementation_binding_sha256, label="implementation_binding_sha256"
    )
    expected_ancestry = _sha256(
        signed_ancestry_manifest_sha256, label="signed_ancestry_manifest_sha256"
    )
    if not isinstance(anchors, Sequence) or isinstance(anchors, (str, bytes)):
        raise CustodyAnchorError("anchors must be a sequence")
    expected_by_archive: dict[str, tuple[dict[str, Any], str]] = {
        record["archive_sha256"]: (record, checked_registry["chain_hashes"][index])
        for index, record in enumerate(checked_registry["records"])
    }
    if set(first_hosted_game_at_utc_by_archive) != set(expected_by_archive):
        raise CustodyAnchorError("first hosted game timestamps must be present for exactly every registry archive")
    verified: list[dict[str, Any]] = []
    seen_archives: set[str] = set()
    for index, item in enumerate(anchors):
        paths = _anchor_paths(item, index=index)
        _, payload, _, payload_sha256 = _load_canonical_payload(paths["payload_path"])
        matches = [
            archive
            for archive, (registration, chain) in expected_by_archive.items()
            if payload["archive_registration_sha256"] == canonical_sha256(registration)
            and payload["registry_chain_hash_at_registration"] == chain
        ]
        if len(matches) != 1:
            raise CustodyAnchorError("anchor does not bind one exact registry registration")
        archive = matches[0]
        if archive in seen_archives:
            raise CustodyAnchorError(f"duplicate custody anchor for archive {archive}")
        registration, chain = expected_by_archive[archive]
        if payload["campaign_sha256"] != expected_campaign:
            raise CustodyAnchorError("anchor campaign binding does not match")
        if payload["implementation_binding_sha256"] != expected_implementation:
            raise CustodyAnchorError("anchor implementation binding does not match")
        if payload["signed_ancestry_manifest_sha256"] != expected_ancestry:
            raise CustodyAnchorError("anchor ancestry binding does not match")
        if payload["model_input_sha256"] != registration["model_input_sha256"]:
            raise CustodyAnchorError("anchor model input binding does not match registration")
        if payload["registered_at_utc"] != registration["registered_at_utc"]:
            raise CustodyAnchorError("anchor registration timestamp does not match registry")
        if payload["archive_registration_sha256"] != canonical_sha256(registration) or payload[
            "registry_chain_hash_at_registration"
        ] != chain:
            raise CustodyAnchorError("anchor registration or chain binding does not match registry")
        verified_anchor = verify_custody_anchor(
            **paths,
            first_hosted_game_at_utc=first_hosted_game_at_utc_by_archive[archive],
            openssl_bin=openssl_bin,
            runner=runner,
        )
        immutable_bindings = {
            "payload_sha256": payload_sha256,
            "campaign_sha256": payload["campaign_sha256"],
            "implementation_binding_sha256": payload[
                "implementation_binding_sha256"
            ],
            "signed_ancestry_manifest_sha256": payload[
                "signed_ancestry_manifest_sha256"
            ],
            "archive_registration_sha256": payload[
                "archive_registration_sha256"
            ],
            "registry_chain_hash_at_registration": payload[
                "registry_chain_hash_at_registration"
            ],
            "model_input_sha256": payload["model_input_sha256"],
            "registered_at_utc": payload["registered_at_utc"],
        }
        if any(
            verified_anchor.get(field) != expected
            for field, expected in immutable_bindings.items()
        ):
            raise CustodyAnchorError(
                "custody anchor paths changed between registry matching and verification"
            )
        verified.append(verified_anchor)
        seen_archives.add(archive)
    if seen_archives != set(expected_by_archive):
        missing = sorted(set(expected_by_archive) - seen_archives)
        raise CustodyAnchorError(f"missing custody anchor for registry archives: {missing}")
    ordered = sorted(verified, key=lambda item: item["archive_registration_sha256"])
    content = {
        "schema": BATCH_AUDIT_SCHEMA,
        "protocol": PROTOCOL_ID,
        "registry_sha256": canonical_sha256(checked_registry),
        "campaign_sha256": expected_campaign,
        "implementation_binding_sha256": expected_implementation,
        "signed_ancestry_manifest_sha256": expected_ancestry,
        "anchors": ordered,
        "authority": False,
        "submission": False,
        "holdout": False,
    }
    return {**content, "evidence_sha256": canonical_sha256(content)}


# Concise aliases for callers that use the protocol's shorter terminology.
build_anchor_payload = build_custody_anchor_payload
validate_anchor_payload = validate_custody_anchor_payload
write_anchor_payload_once = write_custody_anchor_payload_once
verify_anchor = verify_custody_anchor
verify_anchor_batch = verify_custody_anchor_batch


__all__ = [
    "ANCHOR_PAYLOAD_SCHEMA",
    "BATCH_AUDIT_SCHEMA",
    "CustodyAnchorError",
    "VERIFIED_ANCHOR_SCHEMA",
    "build_anchor_payload",
    "build_and_write_custody_anchor_payload_once",
    "build_custody_anchor_payload",
    "canonical_custody_anchor_payload_bytes",
    "custody_anchor_payload_sha256",
    "validate_anchor_payload",
    "validate_custody_anchor_payload",
    "verify_anchor",
    "verify_anchor_batch",
    "verify_custody_anchor",
    "verify_custody_anchor_batch",
    "write_anchor_payload_once",
    "write_custody_anchor_payload_once",
]
