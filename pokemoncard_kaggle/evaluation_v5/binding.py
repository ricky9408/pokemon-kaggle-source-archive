"""Verification of the frozen v5 architecture/document binding.

The architecture JSON is an identity manifest, not an authorization token.  This
module verifies the exact frozen mapping and then hashes the bytes of each
bound document below the supplied repository root.  It deliberately does not
read any payload referenced by the v5 firewall.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

from .canonical import canonical_sha256


PROTOCOL_ID = "MCI_TRANSFER_V1"
BINDING_SCHEMA_VERSION = 1
BINDING_CREATED_AT = "2026-07-13T17:54:27Z"
BINDING_GATE_STATE = "NO_SUBMIT_IDENTIFIABILITY"
ARCHITECTURE_DOCUMENTS = (
    ("strategy/evaluation_v5_external_cohort_protocol_20260713.md", "bc410e33f5a97b81e0748c63c4d88035ce067438de02462c60fefb124fe90817"),
    ("strategy/evaluation_v5_preregistration_20260713.md", "03a56eb57a7d7e049d6d7f839771917b046fa52e303664fe5ae5dc9db6236160"),
    ("strategy/evaluation_v5_scenario_contract_20260713.md", "afced384be4aa7ebc3c51ffa13b4d0473c283501357e1fbe27ee0621ec4b8e0b"),
    ("strategy/evaluation_v5_sol_review_20260713.md", "8065fac03512a419e905b7c12716463dd3c15ffca792901f19a97105aa71f511"),
)

_AUTHORITY = {"candidate_development": False, "sealed_holdout_access": False, "submission": False}
_FIELDS = frozenset({"authority", "created_at", "documents", "gate_state", "protocol_id", "schema_version"})
_DOCUMENT_FIELDS = frozenset({"path", "sha256"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BindingVerificationError(ValueError):
    """The architecture binding is malformed or does not match repository bytes."""


ArchitectureBindingError = BindingVerificationError


def sha256_file(path: Path) -> str:
    """Hash file bytes without decoding or normalizing them."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            import os

            before = os.fstat(handle.fileno())
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise BindingVerificationError("bound document cannot be read") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise BindingVerificationError("bound document mutated while it was hashed")
    return digest.hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise BindingVerificationError(f"{label} fields are not exact")
    return value


def _validate_relative_path(value: object) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise BindingVerificationError("document path is not a safe relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BindingVerificationError("document path is not a safe relative POSIX path")
    if path.as_posix() != value:
        raise BindingVerificationError("document path is not normalized")
    return value


def _validate_digest(value: object) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise BindingVerificationError("document SHA-256 is invalid")
    return value


def validate_binding(value: object) -> dict[str, Any]:
    """Validate the exact frozen architecture mapping without touching files."""

    raw = _exact_fields(value, _FIELDS, label="architecture binding")
    if raw["schema_version"] != BINDING_SCHEMA_VERSION or type(raw["schema_version"]) is not int:
        raise BindingVerificationError("architecture binding schema version mismatch")
    if raw["protocol_id"] != PROTOCOL_ID:
        raise BindingVerificationError("architecture binding protocol mismatch")
    if raw["created_at"] != BINDING_CREATED_AT:
        raise BindingVerificationError("architecture binding creation timestamp mismatch")
    if raw["gate_state"] != BINDING_GATE_STATE:
        raise BindingVerificationError("architecture binding gate state is not closed")
    if raw["authority"] != _AUTHORITY:
        raise BindingVerificationError("architecture binding authority is not fully closed")
    if not isinstance(raw["authority"], Mapping) or set(raw["authority"]) != set(_AUTHORITY):
        raise BindingVerificationError("architecture binding authority fields are not exact")
    if not isinstance(raw["documents"], list) or len(raw["documents"]) != len(ARCHITECTURE_DOCUMENTS):
        raise BindingVerificationError("architecture binding document set is not exact")

    documents: list[dict[str, str]] = []
    for index, item in enumerate(raw["documents"]):
        document = _exact_fields(item, _DOCUMENT_FIELDS, label=f"document {index}")
        documents.append({"path": _validate_relative_path(document["path"]), "sha256": _validate_digest(document["sha256"])})
    expected_documents = [{"path": path, "sha256": digest} for path, digest in ARCHITECTURE_DOCUMENTS]
    if documents != expected_documents:
        raise BindingVerificationError("architecture binding documents differ from the frozen set")
    return {
        "authority": dict(_AUTHORITY),
        "created_at": BINDING_CREATED_AT,
        "documents": documents,
        "gate_state": BINDING_GATE_STATE,
        "protocol_id": PROTOCOL_ID,
        "schema_version": BINDING_SCHEMA_VERSION,
    }


def _bound_path(repo_root: Path, relative_path: str) -> Path:
    current = repo_root
    for component in PurePosixPath(relative_path).parts:
        current = current / component
        if current.is_symlink():
            raise BindingVerificationError("bound document path contains a symlink")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(repo_root)
    except (OSError, ValueError) as exc:
        raise BindingVerificationError("bound document escapes the repository root") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise BindingVerificationError("bound document is not a regular file")
    return resolved


def verify_binding(repo_root: str | Path, binding: object) -> dict[str, Any]:
    """Validate the frozen mapping and the current bytes of every bound document."""

    checked = validate_binding(binding)
    root = Path(repo_root)
    try:
        root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BindingVerificationError("repository root does not exist") from exc
    if not root.is_dir():
        raise BindingVerificationError("repository root is not a directory")

    verified_documents: list[dict[str, str]] = []
    for document in checked["documents"]:
        path = _bound_path(root, document["path"])
        actual = sha256_file(path)
        if actual != document["sha256"]:
            raise BindingVerificationError("bound document bytes do not match SHA-256")
        verified_documents.append(dict(document))
    return {**checked, "documents": verified_documents}


verify_architecture_binding = verify_binding


def binding_sha256(value: object) -> str:
    """Return the canonical identity hash of a validated architecture binding."""

    return canonical_sha256(validate_binding(value))


__all__ = [
    "ARCHITECTURE_DOCUMENTS",
    "ArchitectureBindingError",
    "BINDING_CREATED_AT",
    "BINDING_GATE_STATE",
    "BINDING_SCHEMA_VERSION",
    "BindingVerificationError",
    "PROTOCOL_ID",
    "binding_sha256",
    "sha256_file",
    "validate_binding",
    "verify_architecture_binding",
    "verify_binding",
]
