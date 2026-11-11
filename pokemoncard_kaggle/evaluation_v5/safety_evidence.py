"""Authority-free verification of signed operational-safety evidence.

The signer is not a trust root.  This module verifies a caller-supplied
Ed25519 signature and binds the claim to bytes that are present in the
repository, but it never grants holdout, submission, or any other authority.
The outer protocol must compare the returned signer fingerprint with its own
hardcoded trust root.
"""

from __future__ import annotations

import base64
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes
from .charter import PROTOCOL_ID


OPERATIONAL_SAFETY_MANIFEST_SCHEMA = "evaluation_v5_operational_safety_manifest_v1"
OPERATIONAL_SAFETY_AUDIT_SCHEMA = "evaluation_v5_operational_safety_audit_v1"
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
PRODUCTION_MIN_TESTED_CALLS = 50_000

OUTCOME_NAMES = (
    "win",
    "loss",
    "draw",
    "crash",
    "illegal",
    "malformed",
    "runtime",
    "timeout",
)
FAILURE_OUTCOMES = frozenset(OUTCOME_NAMES[3:])

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_sha256",
        "archive_sha256s",
        "runner_executable",
        "container",
        "runtime",
        "call_log",
        "tested_calls",
        "outcome_counts",
        "signer_public_key_fingerprint_sha256",
        "signature_ed25519_base64",
    }
)
_UNSIGNED_FIELDS = _TOP_LEVEL_FIELDS - {"signature_ed25519_base64"}
_BOUND_FILE_FIELDS = frozenset({"path", "sha256"})
_CALL_FIELDS = frozenset({"archive_sha256", "call_index", "outcome"})


class OperationalSafetyError(ValueError):
    """The signed operational-safety evidence is malformed or unverified."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise OperationalSafetyError(f"{label} must be a lowercase SHA-256 hex string")
    return value


def _require_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise OperationalSafetyError(f"{label} must be a nonempty repo-relative path")
    if "\\" in value or "\x00" in value or value.startswith("/") or value.endswith("/"):
        raise OperationalSafetyError(f"{label} must use POSIX repo-relative path syntax")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise OperationalSafetyError(f"{label} must not traverse outside the repository")
    if Path(value).is_absolute():
        raise OperationalSafetyError(f"{label} must be repo-relative")
    return value


def _require_base64(value: object, label: str, length: int) -> bytes:
    if type(value) is not str:
        raise OperationalSafetyError(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise OperationalSafetyError(f"{label} must be canonical base64") from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise OperationalSafetyError(f"{label} must be canonical {length}-byte base64")
    return decoded


def _validate_bound_file(value: object, label: str) -> dict[str, str]:
    if type(value) is not dict or set(value) != _BOUND_FILE_FIELDS:
        raise OperationalSafetyError(f"{label} fields are not exact")
    return {
        "path": _require_relative_path(value["path"], f"{label}.path"),
        "sha256": _require_sha256(value["sha256"], f"{label}.sha256"),
    }


def _validate_unsigned_manifest(value: object) -> tuple[dict[str, Any], bytes]:
    if type(value) is not dict:
        raise OperationalSafetyError("operational-safety manifest must be a dict")
    if set(value) not in (_UNSIGNED_FIELDS, _TOP_LEVEL_FIELDS):
        raise OperationalSafetyError("operational-safety manifest fields are not exact")
    if value["schema"] != OPERATIONAL_SAFETY_MANIFEST_SCHEMA:
        raise OperationalSafetyError(f"schema must be {OPERATIONAL_SAFETY_MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != PROTOCOL_ID:
        raise OperationalSafetyError(f"protocol_id must be {PROTOCOL_ID!r}")

    campaign = _require_sha256(value["campaign_sha256"], "campaign_sha256")
    archives_value = value["archive_sha256s"]
    if type(archives_value) is not list or not archives_value:
        raise OperationalSafetyError("archive_sha256s must be a nonempty list")
    archives = [_require_sha256(item, "archive_sha256s item") for item in archives_value]
    if archives != sorted(archives) or len(archives) != len(set(archives)):
        raise OperationalSafetyError("archive_sha256s must be a sorted exact set")

    bound_files = {
        "runner_executable": _validate_bound_file(value["runner_executable"], "runner_executable"),
        "container": _validate_bound_file(value["container"], "container"),
        "runtime": _validate_bound_file(value["runtime"], "runtime"),
        "call_log": _validate_bound_file(value["call_log"], "call_log"),
    }
    paths = [entry["path"] for entry in bound_files.values()]
    if len(paths) != len(set(paths)):
        raise OperationalSafetyError("bound artifact paths must be distinct")

    tested_calls = value["tested_calls"]
    if type(tested_calls) is not int or tested_calls < 0:
        raise OperationalSafetyError("tested_calls must be a nonnegative integer")
    outcome_counts_value = value["outcome_counts"]
    if type(outcome_counts_value) is not dict or set(outcome_counts_value) != set(OUTCOME_NAMES):
        raise OperationalSafetyError("outcome_counts fields are not exact")
    outcome_counts: dict[str, int] = {}
    for outcome in OUTCOME_NAMES:
        count = outcome_counts_value[outcome]
        if type(count) is not int or count < 0:
            raise OperationalSafetyError(f"outcome_counts.{outcome} must be a nonnegative integer")
        outcome_counts[outcome] = count
    if sum(outcome_counts.values()) != tested_calls:
        raise OperationalSafetyError("declared outcome counts do not sum to tested_calls")

    fingerprint = _require_sha256(
        value["signer_public_key_fingerprint_sha256"],
        "signer_public_key_fingerprint_sha256",
    )
    unsigned = {
        "schema": OPERATIONAL_SAFETY_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_sha256": campaign,
        "archive_sha256s": archives,
        **bound_files,
        "tested_calls": tested_calls,
        "outcome_counts": outcome_counts,
        "signer_public_key_fingerprint_sha256": fingerprint,
    }
    try:
        payload = canonical_json_bytes(unsigned)
    except CanonicalJSONError as exc:
        raise OperationalSafetyError(f"manifest is not canonical JSON: {exc}") from exc
    return unsigned, payload


def operational_safety_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the canonical bytes that an Ed25519 signer must sign."""

    _, payload = _validate_unsigned_manifest(dict(value))
    return payload


@dataclass(slots=True)
class _CallLogSummary:
    tested_calls: int
    outcome_counts: dict[str, int]
    archives: set[str]
    calls_by_archive: dict[str, int]
    sha256: str


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OperationalSafetyError("platform does not provide O_NOFOLLOW")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    try:
        fd = os.open(os.fspath(repo_root), flags)
    except OSError as exc:
        raise OperationalSafetyError("repository root must be an opened non-symlink directory") from exc
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise OperationalSafetyError("repository root must be a directory")
    return fd


def _open_relative_regular_file(root_fd: int, relative_path: str) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise OperationalSafetyError("platform does not provide O_NOFOLLOW")
    current_fd = os.dup(root_fd)
    file_fd = -1
    try:
        parts = relative_path.split("/")
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow,
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current_fd)
        os.close(current_fd)
        current_fd = -1
        return file_fd
    except OSError as exc:
        if file_fd >= 0:
            os.close(file_fd)
        raise OperationalSafetyError(f"unable to securely open {relative_path!r}") from exc
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _digest_file(root_fd: int, entry: Mapping[str, str]) -> str:
    file_fd = _open_relative_regular_file(root_fd, entry["path"])
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise OperationalSafetyError(f"bound file {entry['path']!r} is not regular")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(file_fd)
        if not _same_file_state(before, after):
            raise OperationalSafetyError(f"bound file {entry['path']!r} changed while being read")
        return digest.hexdigest()
    except OSError as exc:
        raise OperationalSafetyError(f"unable to read bound file {entry['path']!r}") from exc
    finally:
        os.close(file_fd)


def _reject_duplicate_json_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _parse_call(raw_line: bytes, expected_archives: set[str]) -> tuple[str, int, str]:
    if not raw_line.endswith(b"\n"):
        raise OperationalSafetyError("call log must end every record with LF")
    try:
        parsed = json.loads(raw_line, object_pairs_hook=_reject_duplicate_json_key)
        canonical = canonical_json_bytes(parsed) + b"\n"
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, CanonicalJSONError) as exc:
        raise OperationalSafetyError("call log contains malformed or non-canonical JSON") from exc
    if canonical != raw_line:
        raise OperationalSafetyError("call log is not canonical JSONL")
    if type(parsed) is not dict or set(parsed) != _CALL_FIELDS:
        raise OperationalSafetyError("call log record fields are not exact")
    archive = _require_sha256(parsed["archive_sha256"], "call archive_sha256")
    if archive not in expected_archives:
        raise OperationalSafetyError("call log contains an unbound archive")
    call_index = parsed["call_index"]
    if type(call_index) is not int or call_index < 0:
        raise OperationalSafetyError("call_index must be a nonnegative integer")
    outcome = parsed["outcome"]
    if type(outcome) is not str or outcome not in OUTCOME_NAMES:
        raise OperationalSafetyError("call outcome is unknown")
    return archive, call_index, outcome


def _stream_call_log(root_fd: int, entry: Mapping[str, str], expected_archives: set[str]) -> _CallLogSummary:
    """Stream a log while retaining an fd for the before/after fstat check."""

    file_fd = _open_relative_regular_file(root_fd, entry["path"])
    before = os.fstat(file_fd)
    if not stat.S_ISREG(before.st_mode):
        os.close(file_fd)
        raise OperationalSafetyError(f"call log {entry['path']!r} is not regular")
    seen_indexes: set[tuple[str, int]] = set()
    archives: set[str] = set()
    counts: Counter[str] = Counter()
    digest = hashlib.sha256()
    try:
        with os.fdopen(os.dup(file_fd), "rb", closefd=True) as stream:
            for raw_line in stream:
                digest.update(raw_line)
                archive, call_index, outcome = _parse_call(raw_line, expected_archives)
                key = (archive, call_index)
                if key in seen_indexes:
                    raise OperationalSafetyError("call log contains duplicate per-archive call index")
                seen_indexes.add(key)
                archives.add(archive)
                counts[outcome] += 1
        after = os.fstat(file_fd)
        if not _same_file_state(before, after):
            raise OperationalSafetyError(f"call log {entry['path']!r} changed while being read")
        return _CallLogSummary(
            tested_calls=len(seen_indexes),
            outcome_counts=dict(counts),
            archives=archives,
            calls_by_archive=dict(Counter(archive for archive, _ in seen_indexes)),
            sha256=digest.hexdigest(),
        )
    except OSError as exc:
        raise OperationalSafetyError(f"unable to stream call log {entry['path']!r}") from exc
    finally:
        os.close(file_fd)


def _empty_audit(reason: str, pinned_fingerprint: str | None = None) -> dict[str, Any]:
    return {
        "schema": OPERATIONAL_SAFETY_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": False,
        "decision": "OPERATIONAL_SAFETY_INCOMPLETE",
        "failure_reason": reason,
        "signer_public_key_fingerprint_sha256": None,
        "pinned_public_key_fingerprint_sha256": pinned_fingerprint,
        "signed_manifest_sha256": None,
        "campaign_sha256": None,
        "archive_sha256s": [],
        "tested_calls": None,
        "outcome_counts": None,
        "calls_by_archive": {},
        "bound_files": [],
    }


def _audit_operational_safety_evidence(
    evidence_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
    minimum_tested_calls: int,
) -> dict[str, Any]:
    """Implementation with a private minimum override used by focused tests."""

    pinned_fingerprint: str | None = None
    try:
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise OperationalSafetyError("pinned_public_key must be exactly 32 bytes")
        pinned_fingerprint = hashlib.sha256(pinned_public_key).hexdigest()
        if type(minimum_tested_calls) is not int or minimum_tested_calls < 0:
            raise OperationalSafetyError("minimum_tested_calls must be a nonnegative integer")
        unsigned, payload = _validate_unsigned_manifest(dict(evidence_manifest))
        if unsigned["signer_public_key_fingerprint_sha256"] != pinned_fingerprint:
            raise OperationalSafetyError("manifest signer fingerprint does not match pinned key")
        signature = _require_base64(
            evidence_manifest["signature_ed25519_base64"],
            "signature_ed25519_base64",
            ED25519_SIGNATURE_BYTES,
        )
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise OperationalSafetyError("Ed25519 operational-safety signature did not verify") from exc

        root_fd = _open_repo_root(repo_root)
        try:
            bound_files = [
                unsigned["runner_executable"],
                unsigned["container"],
                unsigned["runtime"],
            ]
            for entry in bound_files:
                actual = _digest_file(root_fd, entry)
                if actual != entry["sha256"]:
                    raise OperationalSafetyError(f"bound file digest mismatch for {entry['path']!r}")
            summary = _stream_call_log(root_fd, unsigned["call_log"], set(unsigned["archive_sha256s"]))
        finally:
            os.close(root_fd)

        if summary.sha256 != unsigned["call_log"]["sha256"]:
            raise OperationalSafetyError("call log digest mismatch")
        if summary.archives != set(unsigned["archive_sha256s"]):
            raise OperationalSafetyError("call log archive coverage is not exact")
        if summary.tested_calls < minimum_tested_calls:
            raise OperationalSafetyError("recomputed tested_calls is below the minimum")
        if unsigned["tested_calls"] != summary.tested_calls:
            raise OperationalSafetyError("declared tested_calls does not match the call log")
        actual_counts = {outcome: summary.outcome_counts.get(outcome, 0) for outcome in OUTCOME_NAMES}
        if unsigned["outcome_counts"] != actual_counts:
            raise OperationalSafetyError("declared outcome_counts do not match the call log")
        if any(actual_counts[outcome] for outcome in FAILURE_OUTCOMES):
            raise OperationalSafetyError("call log contains crash, illegal, malformed, runtime, or timeout outcomes")
    except Exception as exc:
        return _empty_audit(str(exc), pinned_fingerprint)

    return {
        "schema": OPERATIONAL_SAFETY_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": True,
        "decision": "OPERATIONAL_SAFETY_VERIFIED",
        "failure_reason": None,
        "signer_public_key_fingerprint_sha256": pinned_fingerprint,
        "pinned_public_key_fingerprint_sha256": pinned_fingerprint,
        "signed_manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "campaign_sha256": unsigned["campaign_sha256"],
        "archive_sha256s": unsigned["archive_sha256s"],
        "tested_calls": summary.tested_calls,
        "outcome_counts": actual_counts,
        "calls_by_archive": {
            archive: summary.calls_by_archive[archive] for archive in sorted(summary.calls_by_archive)
        },
        "bound_files": [
            {"path": entry["path"], "sha256": entry["sha256"]}
            for entry in (
                unsigned["runner_executable"],
                unsigned["container"],
                unsigned["runtime"],
                unsigned["call_log"],
            )
        ],
    }


def audit_operational_safety_evidence(
    evidence_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
) -> dict[str, Any]:
    """Verify production operational-safety evidence at the fixed 50k floor."""

    return _audit_operational_safety_evidence(
        evidence_manifest,
        repo_root,
        pinned_public_key=pinned_public_key,
        minimum_tested_calls=PRODUCTION_MIN_TESTED_CALLS,
    )


verify_operational_safety_evidence = audit_operational_safety_evidence
audit = audit_operational_safety_evidence


__all__ = [
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "FAILURE_OUTCOMES",
    "OPERATIONAL_SAFETY_AUDIT_SCHEMA",
    "OPERATIONAL_SAFETY_MANIFEST_SCHEMA",
    "OperationalSafetyError",
    "OUTCOME_NAMES",
    "PRODUCTION_MIN_TESTED_CALLS",
    "audit",
    "audit_operational_safety_evidence",
    "operational_safety_signing_payload",
    "verify_operational_safety_evidence",
]
