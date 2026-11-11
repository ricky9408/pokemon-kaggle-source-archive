"""Out-of-band trust roots for one preregistered v5 campaign.

These values intentionally start unset. A campaign cannot validate by supplying
its own auditor keys or TSA trust root. Before an external campaign starts,
independent reviewers must freeze the exact values here and rebuild the
implementation manifest. A separate RFC 3161 campaign anchor binds that
implementation to the one campaign digest without creating a self-hash cycle.
Changing any value is a new implementation and a new campaign.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical import canonical_sha256


PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256: str | None = None
PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256: str | None = None
PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256: str | None = None
PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256: str | None = None
PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256: str | None = None
PINNED_CUSTODY_CA_FILE_SHA256: str | None = None
PINNED_CUSTODY_TSA_POLICY_OID: str | None = None
PINNED_OPENSSL_EXECUTABLE_SHA256: str | None = None

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class TrustRootError(ValueError):
    """Required independent campaign trust roots are absent or mismatched."""


def _configured_digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise TrustRootError(f"{label} is not independently configured")
    return value


def validate_campaign_trust_roots(
    campaign: dict[str, Any],
    *,
    ancestry_public_key_hex: str,
    engine_evidence_public_key: bytes,
    host_evidence_public_key: bytes,
    safety_evidence_public_key: bytes,
    provenance_evidence_public_key: bytes,
) -> dict[str, str]:
    """Verify campaign inputs against implementation-pinned external roots."""

    try:
        ancestry_key = bytes.fromhex(ancestry_public_key_hex)
    except (TypeError, ValueError) as exc:
        raise TrustRootError("ancestry auditor public key is invalid") from exc
    if len(ancestry_key) != 32:
        raise TrustRootError("ancestry auditor public key must be 32 bytes")
    supplied_keys = {
        "engine_evidence_signer_public_key_sha256": engine_evidence_public_key,
        "host_evidence_signer_public_key_sha256": host_evidence_public_key,
        "safety_evidence_signer_public_key_sha256": safety_evidence_public_key,
        "provenance_evidence_signer_public_key_sha256": provenance_evidence_public_key,
    }
    if any(type(key) is not bytes or len(key) != 32 for key in supplied_keys.values()):
        raise TrustRootError("every evidence public key must be 32 bytes")

    expected = {
        "ancestry_auditor_public_key_sha256": _configured_digest(
            PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256,
            "ancestry auditor trust root",
        ),
        "engine_evidence_signer_public_key_sha256": _configured_digest(
            PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256,
            "engine evidence trust root",
        ),
        "host_evidence_signer_public_key_sha256": _configured_digest(
            PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256,
            "host evidence trust root",
        ),
        "safety_evidence_signer_public_key_sha256": _configured_digest(
            PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256,
            "safety evidence trust root",
        ),
        "provenance_evidence_signer_public_key_sha256": _configured_digest(
            PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256,
            "provenance evidence trust root",
        ),
        "custody_ca_file_sha256": _configured_digest(
            PINNED_CUSTODY_CA_FILE_SHA256,
            "RFC3161 CA trust root",
        ),
        "openssl_executable_sha256": _configured_digest(
            PINNED_OPENSSL_EXECUTABLE_SHA256,
            "OpenSSL executable trust root",
        ),
    }
    policy = PINNED_CUSTODY_TSA_POLICY_OID
    if type(policy) is not str or not policy or policy.strip() != policy:
        raise TrustRootError("RFC3161 TSA policy trust root is not independently configured")
    expected["custody_tsa_policy_oid"] = policy

    actual_key_hashes = {
        "ancestry_auditor_public_key_sha256": hashlib.sha256(ancestry_key).hexdigest(),
        **{field: hashlib.sha256(key).hexdigest() for field, key in supplied_keys.items()},
    }
    for field, expected_value in expected.items():
        if field == "openssl_executable_sha256":
            continue
        if campaign.get(field) != expected_value:
            raise TrustRootError(f"campaign {field} does not match the independent trust root")
    for field, actual in actual_key_hashes.items():
        if actual != expected[field]:
            raise TrustRootError(f"supplied {field} key does not match the independent trust root")
    snapshot = {"schema": "evaluation_v5_external_trust_roots_v1", **expected}
    expected["trust_roots_snapshot_sha256"] = canonical_sha256(snapshot)
    if campaign.get("trust_roots_snapshot_sha256") != expected["trust_roots_snapshot_sha256"]:
        raise TrustRootError("campaign trust-roots snapshot does not match")
    return expected


__all__ = [
    "PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256",
    "PINNED_CUSTODY_CA_FILE_SHA256",
    "PINNED_CUSTODY_TSA_POLICY_OID",
    "PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256",
    "PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256",
    "PINNED_OPENSSL_EXECUTABLE_SHA256",
    "PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256",
    "PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256",
    "TrustRootError",
    "validate_campaign_trust_roots",
]
