"""Authority-free verification of signed ancestry provenance evidence.

The ancestry manifest is supplied in its validated signed form.  This module
does not decide whether that ancestry is admissible; it only binds every
declared provenance-evidence digest to one regular file in a repository and
checks a separately signed, ancestry-bound index.  The caller supplies the
Ed25519 verification key, so no key or authority is selected here.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .ancestry import (
    ANCESTRY_MANIFEST_SCHEMA,
    ANCESTRY_PROTOCOL_ID,
    validate_signed_population_manifest,
)
from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256


PROVENANCE_EVIDENCE_INDEX_MANIFEST_SCHEMA = (
    "evaluation_v5_provenance_evidence_index_manifest_v1"
)
# Compatibility spelling for callers that treat the index as the evidence
# manifest itself.
PROVENANCE_EVIDENCE_MANIFEST_SCHEMA = PROVENANCE_EVIDENCE_INDEX_MANIFEST_SCHEMA
PROVENANCE_EVIDENCE_AUDIT_SCHEMA = "evaluation_v5_provenance_evidence_audit_v1"
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ED25519_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "signed_ancestry_manifest_sha256",
        "signer_public_key_fingerprint_sha256",
        "evidence_files",
        "signature_ed25519_base64",
    }
)
_EVIDENCE_FILE_FIELDS = frozenset({"path", "sha256"})
_ANCESTRY_SIGNED_FIELDS = frozenset({"schema", "protocol_id", "records", "auditor_signature_ed25519"})
_ANCESTRY_RECORD_FIELDS = frozenset(
    {
        "archive_sha256",
        "policy_sha256",
        "source_tree_sha256",
        "direct_parent_policy_sha256s",
        "teacher_checkpoint_sha256s",
        "declared_provenance_evidence_sha256s",
        "ancestry_complete",
        "review_timestamp_utc",
    }
)


class ProvenanceEvidenceError(ValueError):
    """A signed provenance-evidence index is malformed or does not verify."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ProvenanceEvidenceError(f"{label} must be a lowercase SHA-256 hex string")
    return value


def _require_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ProvenanceEvidenceError(f"{label} must be a nonempty repo-relative path")
    if "\\" in value or "\x00" in value or value.startswith("/") or value.endswith("/"):
        raise ProvenanceEvidenceError(f"{label} must use POSIX repo-relative path syntax")
    if "//" in value:
        raise ProvenanceEvidenceError(f"{label} must use POSIX repo-relative path syntax")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ProvenanceEvidenceError(f"{label} must not traverse outside the repository")
    return value


def _canonical_base64(value: object, label: str, expected_length: int) -> bytes:
    if type(value) is not str:
        raise ProvenanceEvidenceError(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ProvenanceEvidenceError(f"{label} must be canonical base64") from exc
    if len(decoded) != expected_length or base64.b64encode(decoded).decode("ascii") != value:
        raise ProvenanceEvidenceError(f"{label} must be canonical {expected_length}-byte base64")
    return decoded


def _normalise_hash_list(value: object, label: str) -> list[str]:
    if type(value) is not list:
        raise ProvenanceEvidenceError(f"{label} must be a JSON list")
    values = [_require_sha256(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if len(values) != len(set(values)):
        raise ProvenanceEvidenceError(f"{label} must not contain duplicates")
    return sorted(values)


def _validated_signed_ancestry(value: object) -> dict[str, Any]:
    """Re-encode the shape of the already authenticated ancestry result.

    ``validate_signed_population_manifest`` returns this normalized signed
    representation.  Re-normalizing here makes the ancestry hash independent
    of incidental input ordering while deliberately leaving authentication of
    the ancestry signer to that validator and the outer gate.
    """

    if not isinstance(value, Mapping) or set(value) != _ANCESTRY_SIGNED_FIELDS:
        raise ProvenanceEvidenceError("signed ancestry manifest fields are not exact")
    if value["schema"] != ANCESTRY_MANIFEST_SCHEMA:
        raise ProvenanceEvidenceError("signed ancestry manifest schema is invalid")
    if value["protocol_id"] != ANCESTRY_PROTOCOL_ID:
        raise ProvenanceEvidenceError("signed ancestry manifest protocol is invalid")
    signature = value["auditor_signature_ed25519"]
    if type(signature) is not str or _ED25519_SIGNATURE_RE.fullmatch(signature) is None:
        raise ProvenanceEvidenceError("signed ancestry manifest signature is invalid")
    records_value = value["records"]
    if type(records_value) is not list or not records_value:
        raise ProvenanceEvidenceError("signed ancestry manifest records must be nonempty")

    records: list[dict[str, Any]] = []
    for index, item in enumerate(records_value):
        if not isinstance(item, Mapping) or set(item) != _ANCESTRY_RECORD_FIELDS:
            raise ProvenanceEvidenceError(f"ancestry record {index} fields are not exact")
        if type(item["ancestry_complete"]) is not bool:
            raise ProvenanceEvidenceError("ancestry_complete must be exactly boolean")
        record = {
            "archive_sha256": _require_sha256(item["archive_sha256"], "archive_sha256"),
            "policy_sha256": _require_sha256(item["policy_sha256"], "policy_sha256"),
            "source_tree_sha256": _require_sha256(item["source_tree_sha256"], "source_tree_sha256"),
            "direct_parent_policy_sha256s": _normalise_hash_list(
                item["direct_parent_policy_sha256s"], "direct_parent_policy_sha256s"
            ),
            "teacher_checkpoint_sha256s": _normalise_hash_list(
                item["teacher_checkpoint_sha256s"], "teacher_checkpoint_sha256s"
            ),
            "declared_provenance_evidence_sha256s": _normalise_hash_list(
                item["declared_provenance_evidence_sha256s"],
                "declared_provenance_evidence_sha256s",
            ),
            "ancestry_complete": item["ancestry_complete"],
            "review_timestamp_utc": item["review_timestamp_utc"],
        }
        if not record["declared_provenance_evidence_sha256s"]:
            raise ProvenanceEvidenceError(
                "declared_provenance_evidence_sha256s must not be empty"
            )
        records.append(record)

    archives = [record["archive_sha256"] for record in records]
    if len(archives) != len(set(archives)):
        raise ProvenanceEvidenceError("signed ancestry manifest has duplicate archives")
    return {
        "schema": ANCESTRY_MANIFEST_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "records": sorted(records, key=lambda record: record["archive_sha256"]),
        "auditor_signature_ed25519": signature,
    }


def signed_ancestry_manifest_sha256(ancestry_manifest: Mapping[str, Any]) -> str:
    """Return the canonical hash used to bind an evidence index to ancestry."""

    return canonical_sha256(_validated_signed_ancestry(ancestry_manifest))


def _validated_index(value: object) -> tuple[dict[str, Any], bytes, bytes]:
    if not isinstance(value, Mapping) or set(value) != _TOP_LEVEL_FIELDS:
        raise ProvenanceEvidenceError("evidence-index manifest fields are not exact")
    if value["schema"] != PROVENANCE_EVIDENCE_INDEX_MANIFEST_SCHEMA:
        raise ProvenanceEvidenceError("evidence-index manifest schema is invalid")
    if value["protocol_id"] != ANCESTRY_PROTOCOL_ID:
        raise ProvenanceEvidenceError("evidence-index manifest protocol is invalid")
    ancestry_hash = _require_sha256(
        value["signed_ancestry_manifest_sha256"], "signed_ancestry_manifest_sha256"
    )
    fingerprint = _require_sha256(
        value["signer_public_key_fingerprint_sha256"],
        "signer_public_key_fingerprint_sha256",
    )
    if type(value["evidence_files"]) is not list or not value["evidence_files"]:
        raise ProvenanceEvidenceError("evidence_files must be a nonempty list")
    files: list[dict[str, str]] = []
    paths: set[str] = set()
    digests: set[str] = set()
    for index, item in enumerate(value["evidence_files"]):
        if not isinstance(item, Mapping) or set(item) != _EVIDENCE_FILE_FIELDS:
            raise ProvenanceEvidenceError(f"evidence_files[{index}] fields are not exact")
        path = _require_relative_path(item["path"], f"evidence_files[{index}].path")
        digest = _require_sha256(item["sha256"], f"evidence_files[{index}].sha256")
        if path in paths:
            raise ProvenanceEvidenceError("evidence_files must not contain duplicate paths")
        if digest in digests:
            raise ProvenanceEvidenceError("evidence_files must not contain duplicate digests")
        paths.add(path)
        digests.add(digest)
        files.append({"path": path, "sha256": digest})
    if files != sorted(files, key=lambda item: item["path"]):
        raise ProvenanceEvidenceError("evidence_files must be in canonical path order")

    signature = _canonical_base64(
        value["signature_ed25519_base64"],
        "signature_ed25519_base64",
        ED25519_SIGNATURE_BYTES,
    )
    unsigned = {
        "schema": PROVENANCE_EVIDENCE_INDEX_MANIFEST_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "signed_ancestry_manifest_sha256": ancestry_hash,
        "signer_public_key_fingerprint_sha256": fingerprint,
        "evidence_files": files,
    }
    try:
        payload = canonical_json_bytes(unsigned)
    except CanonicalJSONError as exc:
        raise ProvenanceEvidenceError("evidence-index manifest is not canonical JSON") from exc
    return unsigned, payload, signature


def provenance_evidence_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the canonical unsigned bytes an evidence-index signer signs."""

    return _validated_index(value)[1]


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    except AttributeError as exc:
        raise ProvenanceEvidenceError("platform lacks required no-follow open flags") from exc
    try:
        root_fd = os.open(os.fspath(repo_root), flags)
    except OSError as exc:
        raise ProvenanceEvidenceError("repository root must be an opened non-symlink directory") from exc
    try:
        root_stat = os.fstat(root_fd)
    except OSError:
        os.close(root_fd)
        raise
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(root_fd)
        raise ProvenanceEvidenceError("repository root must be a directory")
    return root_fd


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _digest_opened_file(root_fd: int, relative_path: str) -> str:
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        directory_flags = flags | os.O_DIRECTORY
    except AttributeError as exc:
        raise ProvenanceEvidenceError("platform lacks required no-follow open flags") from exc

    current_fd = os.dup(root_fd)
    try:
        parts = relative_path.split("/")
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            if not stat.S_ISDIR(os.fstat(current_fd).st_mode):
                raise ProvenanceEvidenceError(f"evidence path component {part!r} is not a directory")
        file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ProvenanceEvidenceError(f"evidence file {relative_path!r} is not regular")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            after = os.fstat(file_fd)
            if not _same_file_state(before, after):
                raise ProvenanceEvidenceError(f"evidence file {relative_path!r} changed while being read")
            return digest.hexdigest()
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise ProvenanceEvidenceError(f"unable to securely open evidence file {relative_path!r}") from exc
    finally:
        os.close(current_fd)


def _declared_evidence_hashes(ancestry: Mapping[str, Any]) -> set[str]:
    return {
        digest
        for record in ancestry["records"]
        for digest in record["declared_provenance_evidence_sha256s"]
    }


def _closed_result(
    reason: str,
    *,
    signed_ancestry_sha256: str | None = None,
    signed_evidence_index_payload_sha256: str | None = None,
    signer_fingerprint: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": PROVENANCE_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": False,
        "failure_reason": reason,
        "signed_ancestry_manifest_sha256": signed_ancestry_sha256,
        "signed_evidence_index_payload_sha256": signed_evidence_index_payload_sha256,
        "signer_public_key_fingerprint_sha256": signer_fingerprint,
        "verified_files": [],
    }


def audit_provenance_evidence(
    ancestry_manifest: Mapping[str, Any],
    evidence_index_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
    pinned_ancestry_public_key_hex: str,
) -> dict[str, Any]:
    """Verify an ancestry-bound evidence index without granting authority.

    The ancestry manifest must already have passed the ancestry signer check.
    The evidence-index signer key is supplied by the caller and is not selected
    or trusted by this function.  Invalid input always returns the same small,
    closed result shape.
    """

    signed_ancestry_sha256: str | None = None
    signed_evidence_index_payload_sha256: str | None = None
    signer_fingerprint: str | None = None
    try:
        ancestry = validate_signed_population_manifest(
            ancestry_manifest,
            pinned_public_key_hex=pinned_ancestry_public_key_hex,
        )
        ancestry = _validated_signed_ancestry(ancestry)
        signed_ancestry_sha256 = canonical_sha256(ancestry)
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise ProvenanceEvidenceError("pinned_public_key must be exactly 32 bytes")
        unsigned, payload, signature = _validated_index(evidence_index_manifest)
        signed_evidence_index_payload_sha256 = hashlib.sha256(payload).hexdigest()
        signer_fingerprint = hashlib.sha256(pinned_public_key).hexdigest()
        if unsigned["signer_public_key_fingerprint_sha256"] != signer_fingerprint:
            raise ProvenanceEvidenceError("evidence-index signer fingerprint does not match pinned key")
        if unsigned["signed_ancestry_manifest_sha256"] != signed_ancestry_sha256:
            raise ProvenanceEvidenceError("evidence-index manifest does not bind this signed ancestry manifest")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise ProvenanceEvidenceError("Ed25519 evidence-index signature did not verify") from exc

        expected = _declared_evidence_hashes(ancestry)
        indexed = {entry["sha256"] for entry in unsigned["evidence_files"]}
        if indexed != expected:
            raise ProvenanceEvidenceError("evidence-index coverage is not exactly the declared token set")

        root_fd = _open_repo_root(repo_root)
        verified_files: list[dict[str, str]] = []
        try:
            for entry in unsigned["evidence_files"]:
                actual = _digest_opened_file(root_fd, entry["path"])
                if actual != entry["sha256"]:
                    raise ProvenanceEvidenceError(
                        f"evidence file digest mismatch for {entry['path']!r}"
                    )
                verified_files.append({"path": entry["path"], "sha256": actual})
        finally:
            os.close(root_fd)
    except Exception as exc:
        return _closed_result(
            str(exc),
            signed_ancestry_sha256=signed_ancestry_sha256,
            signed_evidence_index_payload_sha256=signed_evidence_index_payload_sha256,
            signer_fingerprint=signer_fingerprint,
        )

    return {
        "schema": PROVENANCE_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": True,
        "failure_reason": None,
        "signed_ancestry_manifest_sha256": signed_ancestry_sha256,
        "signed_evidence_index_payload_sha256": signed_evidence_index_payload_sha256,
        "signer_public_key_fingerprint_sha256": signer_fingerprint,
        "verified_files": verified_files,
    }


verify_provenance_evidence = audit_provenance_evidence
audit_provenance_evidence_index = audit_provenance_evidence
provenance_evidence_index_signing_payload = provenance_evidence_signing_payload
audit = audit_provenance_evidence


__all__ = [
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "PROVENANCE_EVIDENCE_AUDIT_SCHEMA",
    "PROVENANCE_EVIDENCE_INDEX_MANIFEST_SCHEMA",
    "PROVENANCE_EVIDENCE_MANIFEST_SCHEMA",
    "ProvenanceEvidenceError",
    "audit",
    "audit_provenance_evidence",
    "audit_provenance_evidence_index",
    "provenance_evidence_index_signing_payload",
    "provenance_evidence_signing_payload",
    "signed_ancestry_manifest_sha256",
    "verify_provenance_evidence",
]
