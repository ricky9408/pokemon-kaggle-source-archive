"""Domain-separated signed envelope for v5.1 evidence artifacts.

The envelope proves byte identity and signer possession only.  Verification
does not grant research, holdout, candidate-development, or submission
authority; those capabilities must come from independently pinned custodians.
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .exact_gate_v2 import (
    ExactGateV2Error,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)


ENVELOPE_SCHEMA = "evaluation_v5_1_signed_envelope_v1"
DOMAIN_PREFIX = b"EVAL_V5_1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset(
    {
        "schema",
        "artifact_schema",
        "payload",
        "payload_sha256",
        "signer_key_fingerprint_sha256",
        "signature_ed25519_base64",
    }
)


class EnvelopeError(ValueError):
    """An evidence envelope is malformed, unbound, or has a bad signature."""


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise EnvelopeError(f"{label} must be lowercase SHA-256 hex")
    return value


def _signature_bytes(value: object) -> bytes:
    if type(value) is not str:
        raise EnvelopeError("signature_ed25519_base64 must be a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise EnvelopeError("signature_ed25519_base64 is not canonical base64") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise EnvelopeError("signature_ed25519_base64 must encode exactly 64 bytes")
    return decoded


def _validate_public_key(public_key: bytes, label: str) -> None:
    try:
        validate_ed25519_public_key(public_key)
    except ExactGateV2Error as exc:
        raise EnvelopeError(f"{label} is not a strict Ed25519 public key: {exc}") from exc


def _validate_signature_encoding(signature: bytes) -> None:
    try:
        validate_ed25519_signature_encoding(signature)
    except ExactGateV2Error as exc:
        raise EnvelopeError(f"signature is not a strict Ed25519 encoding: {exc}") from exc


def signing_payload(artifact_schema: str, payload_sha256: str) -> bytes:
    """Return the only bytes an evidence signer may sign."""

    if type(artifact_schema) is not str or not artifact_schema:
        raise EnvelopeError("artifact_schema must be a nonempty string")
    if "\0" in artifact_schema:
        raise EnvelopeError("artifact_schema must not contain NUL")
    digest = _require_sha256(payload_sha256, "payload_sha256")
    try:
        schema_bytes = artifact_schema.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EnvelopeError("artifact_schema must be ASCII") from exc
    return DOMAIN_PREFIX + schema_bytes + b"\0" + digest.encode("ascii")


def build_envelope(
    *,
    artifact_schema: str,
    payload: Mapping[str, Any],
    signer_public_key_bytes: bytes,
    signature: bytes,
) -> dict[str, Any]:
    """Build a canonical envelope from an already generated signature."""

    if type(payload) is not dict:
        raise EnvelopeError("payload must be a plain JSON object")
    if type(signer_public_key_bytes) is not bytes or len(signer_public_key_bytes) != 32:
        raise EnvelopeError("signer public key must be exactly 32 bytes")
    if type(signature) is not bytes or len(signature) != 64:
        raise EnvelopeError("signature must be exactly 64 bytes")
    _validate_public_key(signer_public_key_bytes, "signer public key")
    _validate_signature_encoding(signature)
    try:
        payload_digest = canonical_sha256(payload)
    except CanonicalJSONError as exc:
        raise EnvelopeError(f"payload is not canonical JSON: {exc}") from exc
    return {
        "schema": ENVELOPE_SCHEMA,
        "artifact_schema": artifact_schema,
        "payload": dict(payload),
        "payload_sha256": payload_digest,
        "signer_key_fingerprint_sha256": hashlib.sha256(signer_public_key_bytes).hexdigest(),
        "signature_ed25519_base64": base64.b64encode(signature).decode("ascii"),
    }


def verify_envelope(
    value: object,
    *,
    expected_artifact_schema: str,
    pinned_public_key_bytes: bytes,
) -> dict[str, Any]:
    """Verify exact fields, canonical payload hash, pinned key, and signature.

    The returned payload is a defensive JSON copy.  The caller must still
    validate its artifact-specific exact-field schema.
    """

    if type(value) is not dict or set(value) != _FIELDS:
        raise EnvelopeError("envelope fields are not exact")
    if value["schema"] != ENVELOPE_SCHEMA:
        raise EnvelopeError(f"schema must be {ENVELOPE_SCHEMA!r}")
    if value["artifact_schema"] != expected_artifact_schema:
        raise EnvelopeError("artifact_schema does not match the expected schema")
    if type(pinned_public_key_bytes) is not bytes or len(pinned_public_key_bytes) != 32:
        raise EnvelopeError("pinned public key must be exactly 32 bytes")
    _validate_public_key(pinned_public_key_bytes, "pinned public key")
    expected_fingerprint = hashlib.sha256(pinned_public_key_bytes).hexdigest()
    fingerprint = _require_sha256(
        value["signer_key_fingerprint_sha256"], "signer_key_fingerprint_sha256"
    )
    if fingerprint != expected_fingerprint:
        raise EnvelopeError("signer key does not match the implementation-pinned key")
    if type(value["payload"]) is not dict:
        raise EnvelopeError("payload must be a plain JSON object")
    try:
        actual_payload_sha256 = canonical_sha256(value["payload"])
    except CanonicalJSONError as exc:
        raise EnvelopeError(f"payload is not canonical JSON: {exc}") from exc
    claimed_payload_sha256 = _require_sha256(value["payload_sha256"], "payload_sha256")
    if actual_payload_sha256 != claimed_payload_sha256:
        raise EnvelopeError("payload_sha256 does not match canonical payload bytes")
    signature = _signature_bytes(value["signature_ed25519_base64"])
    _validate_signature_encoding(signature)
    try:
        Ed25519PublicKey.from_public_bytes(pinned_public_key_bytes).verify(
            signature,
            signing_payload(expected_artifact_schema, claimed_payload_sha256),
        )
    except (InvalidSignature, ValueError) as exc:
        raise EnvelopeError("Ed25519 signature verification failed") from exc
    return dict(value["payload"])


__all__ = [
    "DOMAIN_PREFIX",
    "ENVELOPE_SCHEMA",
    "EnvelopeError",
    "build_envelope",
    "signing_payload",
    "verify_envelope",
]
