"""Shared fail-closed primitives for evaluation v6.3.

The v6.3 package intentionally has no uploader and no permit issuer.  These
helpers validate canonical, signed evidence but never turn structural evidence
into campaign or production authority.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_sha256


SIGNATURE_SCHEMA = "eval.v6.3.signature"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KEY_ID_RE = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.\d+)?$")


class V63Error(ValueError):
    """A v6.3 artifact failed with a stable, machine-readable state."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> V63Error:
    return V63Error(code, message)


def exact(
    value: Any,
    fields: frozenset[str],
    label: str,
    *,
    code: str,
) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise fail(code, f"{label} fields must exactly be {sorted(fields)}")
    return value


def identifier(value: Any, label: str, *, code: str) -> str:
    if (
        type(value) is not str
        or not value
        or value.strip() != value
        or "\0" in value
    ):
        raise fail(code, f"{label} must be a nonempty trimmed string without NUL")
    return value


def sha256(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def decimal_string(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or DECIMAL_RE.fullmatch(value) is None:
        raise fail(code, f"{label} must be a canonical nonnegative decimal string")
    return value


def canonical_integer(value: Any, label: str, *, code: str, minimum: int = 0) -> int:
    if type(value) is not str or not value.isdigit() or (len(value) > 1 and value[0] == "0"):
        raise fail(code, f"{label} must be a canonical nonnegative integer string")
    parsed = int(value)
    if parsed < minimum:
        raise fail(code, f"{label} must be at least {minimum}")
    return parsed


def utc(value: Any, label: str, *, code: str) -> datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise fail(code, f"{label} must be canonical second-resolution UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise fail(code, f"{label} is not a valid UTC timestamp") from exc


def canonical_string_list(
    value: Any,
    label: str,
    *,
    code: str,
    expected_count: int | None = None,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if type(value) is not list:
        raise fail(code, f"{label} must be a list")
    parsed = tuple(identifier(item, f"{label} item", code=code) for item in value)
    if expected_count is not None and len(parsed) != expected_count:
        raise fail(code, f"{label} must contain exactly {expected_count} entries")
    if not allow_empty and not parsed:
        raise fail(code, f"{label} must not be empty")
    if tuple(sorted(parsed)) != parsed or len(set(parsed)) != len(parsed):
        raise fail(code, f"{label} must be unique and canonically sorted")
    return parsed


def canonical_base64(
    value: Any,
    label: str,
    *,
    code: str,
    expected_length: int | None = None,
) -> bytes:
    if type(value) is not str:
        raise fail(code, f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise fail(code, f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise fail(code, f"{label} is not canonical base64")
    if expected_length is not None and len(decoded) != expected_length:
        raise fail(code, f"{label} must decode to {expected_length} bytes")
    return decoded


def key_id_for_public_key(public_key: bytes) -> str:
    return "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()


def signing_message(domain: bytes, core: Mapping[str, Any]) -> bytes:
    if not domain or not domain.endswith(b"\0"):
        raise ValueError("signature domain must be nonempty and NUL terminated")
    return domain + canonical_json_bytes(core)


def verify_signature_envelope(
    envelope: Any,
    *,
    core: Mapping[str, Any],
    domain: bytes,
    identity: Mapping[str, Any],
    expected_party_id: str,
    code: str,
) -> str:
    item = exact(
        envelope,
        frozenset({"schema", "party_id", "key_id", "signature_base64"}),
        f"signature for {expected_party_id}",
        code=code,
    )
    if item["schema"] != SIGNATURE_SCHEMA or item["party_id"] != expected_party_id:
        raise fail(code, f"signature for {expected_party_id} has the wrong schema or party")
    public_key = canonical_base64(
        identity["role_public_key_base64"],
        f"{expected_party_id} public key",
        code=code,
        expected_length=32,
    )
    key_id = identifier(item["key_id"], "signature key id", code=code)
    if KEY_ID_RE.fullmatch(key_id) is None or key_id != identity["role_key_id"]:
        raise fail(code, f"signature for {expected_party_id} uses the wrong key")
    if key_id_for_public_key(public_key) != key_id:
        raise fail(code, f"public key for {expected_party_id} does not match role_key_id")
    signature = canonical_base64(
        item["signature_base64"],
        f"{expected_party_id} signature",
        code=code,
        expected_length=64,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            signing_message(domain, core),
        )
    except (InvalidSignature, ValueError) as exc:
        raise fail(code, f"signature for {expected_party_id} is invalid") from exc
    return key_id


def verify_signature_set(
    signatures: Any,
    *,
    core: Mapping[str, Any],
    domain: bytes,
    identities: Mapping[str, Mapping[str, Any]],
    required_party_ids: Sequence[str],
    code: str,
) -> tuple[str, ...]:
    if type(signatures) is not list or len(signatures) != len(required_party_ids):
        raise fail(code, f"exactly {len(required_party_ids)} signatures are required")
    by_party: dict[str, Any] = {}
    observed_order: list[str] = []
    for envelope in signatures:
        if type(envelope) is not dict:
            raise fail(code, "signature envelope must be an object")
        party_id = envelope.get("party_id")
        if party_id in by_party:
            raise fail(code, "duplicate signature party")
        by_party[party_id] = envelope
        observed_order.append(party_id)
    required = tuple(sorted(required_party_ids))
    if tuple(sorted(by_party)) != required:
        raise fail(code, f"signature parties must exactly be {list(required)}")
    if tuple(observed_order) != required:
        raise fail(code, "signature envelopes must be canonically sorted by party_id")
    key_ids = []
    for party_id in required:
        if party_id not in identities:
            raise fail(code, f"unknown signature party {party_id}")
        key_ids.append(
            verify_signature_envelope(
                by_party[party_id],
                core=core,
                domain=domain,
                identity=identities[party_id],
                expected_party_id=party_id,
                code=code,
            )
        )
    return tuple(key_ids)


def zero_authority(state: str, *, detail: str, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema": "eval.v6.3.zero-authority-verdict",
        "state": state,
        "detail": detail,
        "candidate_policy_pinned": False,
        "external_services_provisioned": False,
        "population_authenticated": False,
        "recruitment_intake_authorized": False,
        "prereg_root_publication_authorized": False,
        "local_campaign_panel_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
        "calibration_slots_remaining": 16,
        "production_slots_remaining": 1,
    }
    if extra:
        overlap = set(report).intersection(extra)
        if overlap:
            raise ValueError(f"zero-authority extension overlaps protected fields: {sorted(overlap)}")
        report.update(extra)
    return report


__all__ = [
    "DECIMAL_RE",
    "KEY_ID_RE",
    "SHA256_RE",
    "SIGNATURE_SCHEMA",
    "UTC_RE",
    "V63Error",
    "canonical_base64",
    "canonical_integer",
    "canonical_json_bytes",
    "canonical_sha256",
    "canonical_string_list",
    "decimal_string",
    "exact",
    "fail",
    "identifier",
    "key_id_for_public_key",
    "sha256",
    "signing_message",
    "utc",
    "verify_signature_envelope",
    "verify_signature_set",
    "zero_authority",
]
