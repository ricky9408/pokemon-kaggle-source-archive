"""Authority-free signed evidence for a development-only model fit.

The signer in this module is a provenance witness, not an authority.  A valid
audit says only that two exact local files were authenticated and that the
frozen development fitter reproduces the supplied fit result byte-for-byte.
It never opens a holdout, selects a submission, or turns local capability into
hosted-equivalence evidence.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes
from .charter import PROTOCOL_ID
from .development_fit import (
    DEVELOPMENT_FIT_RESULT_SCHEMA,
    fit_development_models,
    validate_development_rows,
)
from .engine_capabilities import (
    EngineCapabilityError,
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)


DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA = "evaluation_v5_development_fit_evidence_manifest_v1"
DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA = "evaluation_v5_development_fit_evidence_audit_v1"
AUTHORITY = False
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64

# B_STAR is the frozen comparator selection performed by fit_development_models:
# LOLO archive-balanced log loss, followed by lexical comparator identity.
B_STAR_SELECTION_RULE = "minimum_lineage_out_archive_balanced_log_loss_then_lexical_identity"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "reviewed_at",
        "created_at_utc",
        "development_rows_path",
        "development_rows_sha256",
        "fit_result_path",
        "fit_result_sha256",
        "engine_capability_manifest_sha256",
        "implementation_binding_manifest_sha256",
        "signer_public_key_fingerprint_sha256",
        "signature_ed25519_base64",
    }
)


class DevelopmentEvidenceError(ValueError):
    """A signed development-fit evidence manifest is invalid or incomplete."""


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant {value!r}")


def _parse_json(content: bytes, label: str) -> Any:
    try:
        return json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DevelopmentEvidenceError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DevelopmentEvidenceError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise DevelopmentEvidenceError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise DevelopmentEvidenceError(f"{label} must be a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise DevelopmentEvidenceError(f"{label} must be canonical UTC with six fractional digits")
    return value, parsed


def _relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise DevelopmentEvidenceError(f"{label} must be a normalized repo-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise DevelopmentEvidenceError(f"{label} must be a normalized repo-relative POSIX path")
    return value


def _base64(value: object, label: str, length: int) -> bytes:
    if type(value) is not str:
        raise DevelopmentEvidenceError(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise DevelopmentEvidenceError(f"{label} must be canonical base64") from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise DevelopmentEvidenceError(f"{label} must be canonical {length}-byte base64")
    return decoded


def _unsigned_manifest(value: object) -> tuple[dict[str, Any], bytes, bytes]:
    if not isinstance(value, Mapping) or set(value) not in (
        _MANIFEST_FIELDS,
        _MANIFEST_FIELDS - {"signature_ed25519_base64"},
    ):
        raise DevelopmentEvidenceError("development evidence manifest fields are not exact")
    if value["schema"] != DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA:
        raise DevelopmentEvidenceError(f"schema must be {DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != PROTOCOL_ID:
        raise DevelopmentEvidenceError(f"protocol_id must be {PROTOCOL_ID!r}")
    reviewed_at, reviewed_dt = _timestamp(value["reviewed_at"], "reviewed_at")
    created_at, created_dt = _timestamp(value["created_at_utc"], "created_at_utc")
    if reviewed_dt < created_dt:
        raise DevelopmentEvidenceError("reviewed_at cannot precede created_at_utc")
    rows_path = _relative_path(value["development_rows_path"], "development_rows_path")
    fit_path = _relative_path(value["fit_result_path"], "fit_result_path")
    if rows_path == fit_path:
        raise DevelopmentEvidenceError("development rows and fit result must be different files")
    unsigned = {
        "schema": DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "reviewed_at": reviewed_at,
        "created_at_utc": created_at,
        "development_rows_path": rows_path,
        "development_rows_sha256": _sha256(
            value["development_rows_sha256"], "development_rows_sha256"
        ),
        "fit_result_path": fit_path,
        "fit_result_sha256": _sha256(value["fit_result_sha256"], "fit_result_sha256"),
        "engine_capability_manifest_sha256": _sha256(
            value["engine_capability_manifest_sha256"], "engine_capability_manifest_sha256"
        ),
        "implementation_binding_manifest_sha256": _sha256(
            value["implementation_binding_manifest_sha256"],
            "implementation_binding_manifest_sha256",
        ),
        "signer_public_key_fingerprint_sha256": _sha256(
            value["signer_public_key_fingerprint_sha256"],
            "signer_public_key_fingerprint_sha256",
        ),
    }
    signature = (
        _base64(
            value["signature_ed25519_base64"],
            "signature_ed25519_base64",
            ED25519_SIGNATURE_BYTES,
        )
        if "signature_ed25519_base64" in value
        else b""
    )
    try:
        payload = canonical_json_bytes(unsigned)
    except CanonicalJSONError as exc:
        raise DevelopmentEvidenceError(f"manifest is not canonical JSON: {exc}") from exc
    return unsigned, payload, signature


def development_evidence_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the exact canonical bytes signed by the development reviewer."""

    return _unsigned_manifest(dict(value))[1]


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(repo_root), flags)
    except OSError as exc:
        raise DevelopmentEvidenceError("repository root must be an opened non-symlink directory") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise DevelopmentEvidenceError("repository root must be a directory")
    return descriptor


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_opened_file(root_fd: int, relative_path: str) -> tuple[bytes, str]:
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
                raise DevelopmentEvidenceError(f"evidence file {relative_path!r} is not regular")
            digest = hashlib.sha256()
            content = bytearray()
            while True:
                block = os.read(file_fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                content.extend(block)
            after = os.fstat(file_fd)
            if not _same_file_state(before, after):
                raise DevelopmentEvidenceError(f"evidence file {relative_path!r} changed while being read")
            return bytes(content), digest.hexdigest()
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise DevelopmentEvidenceError(f"unable to securely open evidence file {relative_path!r}") from exc
    finally:
        os.close(current_fd)


def _read_canonical_json(root_fd: int, path: str, expected_hash: str, label: str) -> tuple[Any, bytes]:
    content, actual_hash = _read_opened_file(root_fd, path)
    if actual_hash != expected_hash:
        raise DevelopmentEvidenceError(f"{label} digest mismatch")
    parsed = _parse_json(content, label)
    try:
        if canonical_json_bytes(parsed) != content:
            raise DevelopmentEvidenceError(f"{label} is not an exact canonical JSON file")
    except CanonicalJSONError as exc:
        raise DevelopmentEvidenceError(f"{label} is not canonical JSON: {exc}") from exc
    return parsed, content


def _first_fit_mismatch(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> str:
    if actual.get("mci_manifest") != expected.get("mci_manifest"):
        return "MCI manifest mismatch"
    if actual.get("comparator_manifest") != expected.get("comparator_manifest"):
        return "comparator manifest mismatch"
    if actual.get("selected_comparator_identity") != expected.get("selected_comparator_identity"):
        return "B_STAR comparator selection mismatch"
    actual_cv = actual.get("cv_report")
    expected_cv = expected.get("cv_report")
    if isinstance(actual_cv, Mapping) and isinstance(expected_cv, Mapping):
        if actual_cv.get("selection_basis") != expected_cv.get("selection_basis"):
            return "B_STAR selection rule mismatch"
    return "fit result does not match byte-for-byte recomputation"


def _empty_audit(
    reason: str,
    *,
    engine_hash: str | None = None,
    implementation_hash: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "engine_capability_manifest_sha256": engine_hash,
        "implementation_binding_manifest_sha256": implementation_hash,
        "signed_manifest_sha256": None,
        "signer_public_key_fingerprint_sha256": None,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": False,
        "decision": "DEVELOPMENT_EVIDENCE_INCOMPLETE",
        "local_feature_extraction": False,
        "failure_reason": reason,
        "b_star_selection": None,
    }


def audit_development_fit_evidence(
    capability_manifest: object,
    evidence_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
    implementation_binding_manifest_sha256: str,
) -> dict[str, Any]:
    """Authenticate and replay a development fit without conferring authority.

    ``capability_manifest`` and ``implementation_binding_manifest_sha256`` are
    caller-supplied bindings.  The implementation manifest bytes are not
    rediscovered here: its exact canonical hash is the boundary this auditor
    consumes.  Both evidence files are opened relative to a no-follow root
    descriptor and are checked for mutation while being read.
    """

    try:
        checked_engine = validate_engine_capability_manifest(capability_manifest)
        engine_hash = checked_engine.manifest_sha256
        implementation_hash = _sha256(
            implementation_binding_manifest_sha256,
            "implementation_binding_manifest_sha256",
        )
    except (EngineCapabilityError, DevelopmentEvidenceError, TypeError, ValueError) as exc:
        return _empty_audit(f"invalid supplied binding: {exc}")

    try:
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise DevelopmentEvidenceError("pinned_public_key must be exactly 32 bytes")
        unsigned, payload, signature = _unsigned_manifest(dict(evidence_manifest))
        if unsigned["engine_capability_manifest_sha256"] != engine_hash:
            raise DevelopmentEvidenceError("evidence manifest does not bind the engine capability manifest")
        if unsigned["implementation_binding_manifest_sha256"] != implementation_hash:
            raise DevelopmentEvidenceError("evidence manifest does not bind the implementation manifest")
        fingerprint = hashlib.sha256(pinned_public_key).hexdigest()
        if unsigned["signer_public_key_fingerprint_sha256"] != fingerprint:
            raise DevelopmentEvidenceError("evidence manifest signer fingerprint does not match pinned key")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise DevelopmentEvidenceError("Ed25519 development evidence signature did not verify") from exc

        root_fd = _open_repo_root(repo_root)
        try:
            rows_value, rows_bytes = _read_canonical_json(
                root_fd,
                unsigned["development_rows_path"],
                unsigned["development_rows_sha256"],
                "development rows",
            )
            if not isinstance(rows_value, list):
                raise DevelopmentEvidenceError("development rows must be a JSON list")
            checked_rows = validate_development_rows(
                rows_value, engine_manifest_sha256=engine_hash
            )
            # The file must already be in the fitter's canonical game-id order
            # and number representation; normalization here must be byte-stable.
            if canonical_json_bytes(checked_rows) != rows_bytes:
                raise DevelopmentEvidenceError(
                    "development rows are not the exact canonical DEV_BURNED representation"
                )
            fit_value, fit_bytes = _read_canonical_json(
                root_fd,
                unsigned["fit_result_path"],
                unsigned["fit_result_sha256"],
                "fit result",
            )
        finally:
            os.close(root_fd)

        if not isinstance(fit_value, Mapping):
            raise DevelopmentEvidenceError("fit result must be a JSON object")
        if fit_value.get("schema") != DEVELOPMENT_FIT_RESULT_SCHEMA:
            raise DevelopmentEvidenceError("fit result schema mismatch")
        if fit_value.get("protocol_id") != PROTOCOL_ID:
            raise DevelopmentEvidenceError("fit result protocol mismatch")

        recomputed = fit_development_models(
            checked_rows,
            engine_capability_manifest=checked_engine,
            development_evidence_sha256=unsigned["development_rows_sha256"],
            executable_sha256=implementation_hash,
            created_at_utc=unsigned["created_at_utc"],
        )
        recomputed_bytes = canonical_json_bytes(recomputed)
        if recomputed_bytes != fit_bytes:
            raise DevelopmentEvidenceError(_first_fit_mismatch(fit_value, recomputed))

        capability_audit = audit_engine_capabilities(checked_engine)
        local_feature_extraction = bool(capability_audit["local_feature_extraction"])
        selected = fit_value.get("selected_comparator_identity")
        result = {
            "schema": DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "engine_capability_manifest_sha256": engine_hash,
            "implementation_binding_manifest_sha256": implementation_hash,
            "signed_manifest_sha256": hashlib.sha256(payload).hexdigest(),
            "signer_public_key_fingerprint_sha256": fingerprint,
            "development_rows_sha256": unsigned["development_rows_sha256"],
            "fit_result_sha256": unsigned["fit_result_sha256"],
            "authority": False,
            "submission_authorized": False,
            "holdout_access_authorized": False,
            # A capability-closed fit is authenticated evidence of closure,
            # not complete development-fit evidence.
            "evidence_complete": local_feature_extraction,
            "decision": capability_audit["decision"] if not local_feature_extraction else "DEVELOPMENT_ONLY",
            "local_feature_extraction": local_feature_extraction,
            "failure_reason": None if local_feature_extraction else "NO_LOCAL_FEATURE_EXTRACTION",
            "b_star_selection": {
                "rule": B_STAR_SELECTION_RULE,
                "selected_comparator_identity": selected,
            }
            if local_feature_extraction
            else None,
        }
        return result
    except Exception as exc:
        return _empty_audit(
            str(exc), engine_hash=engine_hash, implementation_hash=implementation_hash
        )


audit = audit_development_fit_evidence
audit_development_evidence = audit_development_fit_evidence
verify_development_fit_evidence = audit_development_fit_evidence
development_fit_evidence_signing_payload = development_evidence_signing_payload


__all__ = [
    "B_STAR_SELECTION_RULE",
    "AUTHORITY",
    "DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA",
    "DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA",
    "DevelopmentEvidenceError",
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "audit",
    "audit_development_evidence",
    "audit_development_fit_evidence",
    "development_evidence_signing_payload",
    "development_fit_evidence_signing_payload",
    "verify_development_fit_evidence",
]
