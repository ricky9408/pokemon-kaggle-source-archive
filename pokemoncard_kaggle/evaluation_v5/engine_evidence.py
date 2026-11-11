"""Authority-free, signed evidence checks for engine capability claims.

This module is intentionally a verifier, not an attester.  A valid receipt
only confirms that a pre-existing ``engine_capabilities`` claim is fully bound
to inspected local bytes; it cannot make a false capability true or grant any
submission, public-score, or holdout authority.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .charter import PROTOCOL_ID
from .engine_capabilities import (
    CAPABILITY_NAMES,
    HASH_NAMES,
    REQUIRED_BACKENDS,
    EngineCapabilityManifest,
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)


ENGINE_EVIDENCE_MANIFEST_SCHEMA = "evaluation_v5_engine_evidence_manifest_v1"
ENGINE_EVIDENCE_AUDIT_SCHEMA = "evaluation_v5_engine_evidence_audit_v1"
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "reviewed_at",
        "engine_capability_manifest_sha256",
        "signer_public_key_fingerprint_sha256",
        "receipts",
        "signature_ed25519_base64",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "backend",
        "capability",
        "reviewed_at",
        "backend_identity_sha256",
        "auditor_executable_sha256",
        "audit_transcript_sha256",
        "evidence_files",
    }
)
_EVIDENCE_FILE_FIELDS = frozenset({"path", "sha256"})


class EngineEvidenceError(ValueError):
    """A signed capability-evidence manifest is malformed or unverified."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise EngineEvidenceError(f"{label} must be a lowercase SHA-256 hex string")
    return value


def _require_timestamp(value: object, label: str) -> str:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise EngineEvidenceError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EngineEvidenceError(f"{label} must be a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise EngineEvidenceError(f"{label} must be a canonical UTC timestamp")
    return value


def _require_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise EngineEvidenceError(f"{label} must be a nonempty repo-relative path")
    if "\\" in value or value.startswith("/") or value.endswith("/") or "//" in value:
        raise EngineEvidenceError(f"{label} must use POSIX repo-relative path syntax")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise EngineEvidenceError(f"{label} must not traverse outside the repository")
    return value


def _canonical_base64(value: object, label: str, expected_length: int) -> bytes:
    if type(value) is not str:
        raise EngineEvidenceError(f"{label} must be a canonical base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EngineEvidenceError(f"{label} must be a canonical base64 string") from exc
    if len(decoded) != expected_length or base64.b64encode(decoded).decode("ascii") != value:
        raise EngineEvidenceError(f"{label} must be canonical {expected_length}-byte base64")
    return decoded


def _canonical_receipt_order(receipts: list[dict[str, Any]]) -> bool:
    expected = sorted(
        receipts,
        key=lambda item: (REQUIRED_BACKENDS.index(item["backend"]), CAPABILITY_NAMES.index(item["capability"])),
    )
    return receipts == expected


def _validate_evidence_files(value: object) -> list[dict[str, str]]:
    if type(value) is not list or not value:
        raise EngineEvidenceError("evidence_files must be a nonempty ordered list")
    files: list[dict[str, str]] = []
    paths: set[str] = set()
    for index, entry in enumerate(value):
        if type(entry) is not dict or set(entry) != _EVIDENCE_FILE_FIELDS:
            raise EngineEvidenceError(f"evidence_files[{index}] fields are not exact")
        path = _require_relative_path(entry["path"], f"evidence_files[{index}].path")
        digest = _require_sha256(entry["sha256"], f"evidence_files[{index}].sha256")
        if path in paths:
            raise EngineEvidenceError("evidence_files must not contain duplicate paths")
        paths.add(path)
        files.append({"path": path, "sha256": digest})
    if files != sorted(files, key=lambda entry: entry["path"]):
        raise EngineEvidenceError("evidence_files must be ordered by path")
    return files


def _validate_receipt(value: object, reviewed_at: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _RECEIPT_FIELDS:
        raise EngineEvidenceError("receipt fields are not exact")
    backend = value["backend"]
    capability = value["capability"]
    if type(backend) is not str or backend not in REQUIRED_BACKENDS:
        raise EngineEvidenceError("receipt backend is unknown")
    if type(capability) is not str or capability not in CAPABILITY_NAMES:
        raise EngineEvidenceError("receipt capability is unknown")
    if _require_timestamp(value["reviewed_at"], "receipt.reviewed_at") != reviewed_at:
        raise EngineEvidenceError("receipt reviewed_at must equal manifest reviewed_at")
    identities = value["backend_identity_sha256"]
    if type(identities) is not dict or set(identities) != set(HASH_NAMES):
        raise EngineEvidenceError("receipt backend_identity_sha256 fields are not exact")
    normalized_identities = {
        name: _require_sha256(identities[name], f"backend_identity_sha256.{name}")
        for name in HASH_NAMES
    }
    auditor = _require_sha256(value["auditor_executable_sha256"], "auditor_executable_sha256")
    transcript = _require_sha256(value["audit_transcript_sha256"], "audit_transcript_sha256")
    if auditor != normalized_identities["auditor_executable_sha256"]:
        raise EngineEvidenceError("receipt auditor hash disagrees with backend identity")
    if transcript != normalized_identities["audit_transcript_sha256"]:
        raise EngineEvidenceError("receipt transcript hash disagrees with backend identity")
    return {
        "backend": backend,
        "capability": capability,
        "reviewed_at": reviewed_at,
        "backend_identity_sha256": normalized_identities,
        "auditor_executable_sha256": auditor,
        "audit_transcript_sha256": transcript,
        "evidence_files": _validate_evidence_files(value["evidence_files"]),
    }


def _unsigned_manifest(value: object) -> tuple[dict[str, Any], bytes, bytes]:
    if type(value) is not dict or set(value) != _TOP_LEVEL_FIELDS:
        raise EngineEvidenceError("evidence manifest fields are not exact")
    if value["schema"] != ENGINE_EVIDENCE_MANIFEST_SCHEMA:
        raise EngineEvidenceError(f"schema must be {ENGINE_EVIDENCE_MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != PROTOCOL_ID:
        raise EngineEvidenceError(f"protocol_id must be {PROTOCOL_ID!r}")
    reviewed_at = _require_timestamp(value["reviewed_at"], "reviewed_at")
    manifest_hash = _require_sha256(
        value["engine_capability_manifest_sha256"], "engine_capability_manifest_sha256"
    )
    fingerprint = _require_sha256(
        value["signer_public_key_fingerprint_sha256"], "signer_public_key_fingerprint_sha256"
    )
    if type(value["receipts"]) is not list:
        raise EngineEvidenceError("receipts must be a list")
    receipts = [_validate_receipt(receipt, reviewed_at) for receipt in value["receipts"]]
    if not _canonical_receipt_order(receipts):
        raise EngineEvidenceError("receipts must be in canonical backend/capability order")
    keys = [(receipt["backend"], receipt["capability"]) for receipt in receipts]
    if len(keys) != len(set(keys)):
        raise EngineEvidenceError("receipts must not contain duplicate backend/capability pairs")
    signature = _canonical_base64(
        value["signature_ed25519_base64"], "signature_ed25519_base64", ED25519_SIGNATURE_BYTES
    )
    unsigned = {
        "schema": ENGINE_EVIDENCE_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "reviewed_at": reviewed_at,
        "engine_capability_manifest_sha256": manifest_hash,
        "signer_public_key_fingerprint_sha256": fingerprint,
        "receipts": receipts,
    }
    try:
        payload = canonical_json_bytes(unsigned)
    except CanonicalJSONError as exc:
        raise EngineEvidenceError(f"evidence manifest is not canonical JSON: {exc}") from exc
    return unsigned, payload, signature


def engine_evidence_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the exact canonical bytes that an Ed25519 signer must sign."""

    _, payload, _ = _unsigned_manifest(dict(value))
    return payload


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    root = os.fspath(repo_root)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(root, flags)
    except OSError as exc:
        raise EngineEvidenceError("repository root must be an opened non-symlink directory") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise EngineEvidenceError("repository root must be a directory")
    return fd


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def _digest_opened_file(root_fd: int, relative_path: str) -> str:
    current_fd = os.dup(root_fd)
    try:
        parts = relative_path.split("/")
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd
        )
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise EngineEvidenceError(f"evidence file {relative_path!r} is not a regular file")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(file_fd)
            if not _same_file_state(before, after):
                raise EngineEvidenceError(f"evidence file {relative_path!r} changed while being read")
            return digest.hexdigest()
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise EngineEvidenceError(f"unable to securely open evidence file {relative_path!r}") from exc
    finally:
        os.close(current_fd)


def _verify_file_bindings(repo_root: str | os.PathLike[str], receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    root_fd = _open_repo_root(repo_root)
    verified: list[dict[str, Any]] = []
    try:
        for receipt in receipts:
            files: list[dict[str, str]] = []
            for entry in receipt["evidence_files"]:
                actual = _digest_opened_file(root_fd, entry["path"])
                if actual != entry["sha256"]:
                    raise EngineEvidenceError(f"evidence file digest mismatch for {entry['path']!r}")
                files.append({"path": entry["path"], "sha256": actual})
            digests = {entry["sha256"] for entry in files}
            if receipt["auditor_executable_sha256"] not in digests:
                raise EngineEvidenceError("receipt evidence files do not bind the auditor executable bytes")
            if receipt["audit_transcript_sha256"] not in digests:
                raise EngineEvidenceError("receipt evidence files do not bind the audit transcript bytes")
            verified.append(
                {
                    "backend": receipt["backend"],
                    "capability": receipt["capability"],
                    "receipt_sha256": canonical_sha256(receipt),
                    "evidence_files": files,
                }
            )
    finally:
        os.close(root_fd)
    return verified


def _empty_audit(reason: str, manifest_sha256: str | None = None) -> dict[str, Any]:
    return {
        "schema": ENGINE_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "engine_capability_manifest_sha256": manifest_sha256,
        "signed_manifest_sha256": None,
        "signer_public_key_fingerprint_sha256": None,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": False,
        "decision": "ENGINE_EVIDENCE_INCOMPLETE",
        "local_feature_extraction": False,
        "failure_reason": reason,
        "receipts": [],
        "engine_capability_audit": None,
    }


def audit_engine_evidence(
    capability_manifest: EngineCapabilityManifest | Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
) -> dict[str, Any]:
    """Verify signed, file-bound receipts without conferring any authority.

    ``pinned_public_key`` is a caller-owned 32-byte Ed25519 trust anchor.  Its
    SHA-256 fingerprint must be present in the signed manifest.  Invalid input
    returns a deterministic closed audit rather than a partially trusted result.
    """

    manifest_hash: str | None = None
    try:
        checked_manifest = validate_engine_capability_manifest(capability_manifest)
        manifest_hash = checked_manifest.manifest_sha256
    except Exception as exc:
        return _empty_audit(f"invalid engine capability manifest: {exc}")
    try:
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise EngineEvidenceError("pinned_public_key must be exactly 32 bytes")
        unsigned, payload, signature = _unsigned_manifest(dict(evidence_manifest))
        if unsigned["engine_capability_manifest_sha256"] != checked_manifest.manifest_sha256:
            raise EngineEvidenceError("evidence manifest does not bind this engine capability manifest")
        pinned_fingerprint = hashlib.sha256(pinned_public_key).hexdigest()
        if unsigned["signer_public_key_fingerprint_sha256"] != pinned_fingerprint:
            raise EngineEvidenceError("evidence manifest signer fingerprint does not match pinned key")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise EngineEvidenceError("Ed25519 evidence manifest signature did not verify") from exc

        expected_pairs = [
            (backend_name, capability)
            for backend_name in REQUIRED_BACKENDS
            for capability in CAPABILITY_NAMES
            if getattr(checked_manifest.backends[backend_name], capability)
        ]
        actual_pairs = [(receipt["backend"], receipt["capability"]) for receipt in unsigned["receipts"]]
        if actual_pairs != expected_pairs:
            raise EngineEvidenceError("receipts must exactly cover the true engine capabilities")
        for receipt in unsigned["receipts"]:
            backend = checked_manifest.backends[receipt["backend"]]
            expected_identities = {name: getattr(backend, name) for name in HASH_NAMES}
            if receipt["backend_identity_sha256"] != expected_identities:
                raise EngineEvidenceError("receipt backend identity does not match engine capability manifest")
            receipt_hash = canonical_sha256(receipt)
            if backend.capability_evidence_sha256[receipt["capability"]] != receipt_hash:
                raise EngineEvidenceError("receipt hash does not match capability_evidence_sha256")
        verified_receipts = _verify_file_bindings(repo_root, unsigned["receipts"])
        capability_audit = audit_engine_capabilities(checked_manifest)
    except Exception as exc:
        return _empty_audit(str(exc), manifest_hash)

    base_feasible = capability_audit["local_feature_extraction"]
    feature_feasibility = {
        feature: {
            **details,
            "feasible": bool(details["feasible"]),
        }
        for feature, details in capability_audit["feature_feasibility"].items()
    }
    return {
        "schema": ENGINE_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "engine_capability_manifest_sha256": checked_manifest.manifest_sha256,
        "signed_manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signer_public_key_fingerprint_sha256": hashlib.sha256(pinned_public_key).hexdigest(),
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": True,
        "decision": capability_audit["decision"],
        "local_feature_extraction": base_feasible,
        "failure_reason": None,
        "receipts": verified_receipts,
        "engine_capability_audit": capability_audit,
        "feature_feasibility": feature_feasibility,
    }


audit = audit_engine_evidence


__all__ = [
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "ENGINE_EVIDENCE_AUDIT_SCHEMA",
    "ENGINE_EVIDENCE_MANIFEST_SCHEMA",
    "EngineEvidenceError",
    "audit",
    "audit_engine_evidence",
    "engine_evidence_signing_payload",
]
