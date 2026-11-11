"""Fail-closed G09 blind campaign activation verification.

This verifier authenticates only source evidence and recomputes an
authority-free research audit.  It deliberately has no candidate, holdout,
release, or submission authority.  Activation comes only from a signed trigger,
a prospectively committed two-close WORM log, and a signed recipient-key reveal;
caller time never authorizes unseal.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
G09_GATE_ID = "G09_BLIND_CAMPAIGN_ACTIVATION"
G09_AUDIT_SCHEMA = "evaluation_v5_1_g09_blind_activation_audit_v1"
G09_REGISTRY_SCHEMA = "evaluation_v5_1_g09_campaign_role_registry_v1"
G09_ROSTER_SCHEMA = "evaluation_v5_1_g09_expected_g08_roster_v1"
G09_ACTIVATION_RULE_SCHEMA = "evaluation_v5_1_g09_activation_rule_v1"
G09_THRESHOLD_POLICY_SCHEMA = "evaluation_v5_1_g09_threshold_public_key_policy_v1"
G09_ROSTER_COMMITMENT_SCHEMA = "evaluation_v5_1_g09_roster_commitment_v1"
G09_NONCE_COMMITMENT_SCHEMA = "evaluation_v5_1_g09_nonce_commitment_v1"
G09_PACKAGE_COMMITMENT_SCHEMA = "evaluation_v5_1_g09_package_commitment_v1"
G09_NONCE_REVEAL_SCHEMA = "evaluation_v5_1_g09_nonce_reveal_v1"
G09_SHARE_RELEASE_SCHEMA = "evaluation_v5_1_g09_key_share_release_v1"
G09_ACCESS_EVENT_SCHEMA = "evaluation_v5_1_g09_access_event_v1"
G09_V2_DEPENDENCIES_SCHEMA = "evaluation_v5_1_g09_common_v2_dependencies_v1"
G09_ACTIVATION_TRIGGER_SCHEMA = "evaluation_v5_1_g09_activation_trigger_v1"
G09_LOG_GENESIS_SCHEMA = "evaluation_v5_1_g09_log_genesis_v1"
G09_LOG_RECEIPT_SCHEMA = "evaluation_v5_1_g09_log_worm_publication_receipt_v1"
G09_LOG_CLOSE_SCHEMA = "evaluation_v5_1_g09_log_close_v1"
G09_RECIPIENT_KEY_REVEAL_SCHEMA = "evaluation_v5_1_g09_recipient_key_reveal_v1"
G09_WORM_PROVIDER_RECEIPT_SCHEMA = (
    "evaluation_v5_1_g09_worm_provider_receipt_v1"
)
G09_WORM_PUBLICATION_MEDIA_TYPE = (
    "application/vnd.ptcg.g09-worm-publication-receipt+json"
)

THRESHOLD_SCHEME = "X25519_HKDF_SHA256_AES256GCM_SHAMIR_GF256_V1"
_ZERO_HASH = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_BYTE_EVIDENCE_FIELDS = frozenset({"base64", "decoded_length", "sha256", "media_type"})

_REGISTRY_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "roles",
        "content_sha256",
    }
)
_REGISTRY_ROLE_FIELDS = frozenset(
    {
        "role",
        "principal_id",
        "key_id",
        "algorithm",
        "public_key_base64",
        "not_before_utc",
        "not_after_utc",
        "revoked_at_utc",
        "compromised_at_utc",
    }
)
_ROSTER_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "campaign_registry_hash",
        "g08_result_root",
        "selected_archives",
        "content_sha256",
    }
)
_ROSTER_ROW_FIELDS = frozenset({"family_id", "archive_sha256"})
_ACTIVATION_RULE_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "campaign_registry_hash",
        "g08_result_root",
        "activation_time_utc",
        "rule_id",
        "common_v2_dependencies_sha256",
        "threshold_policy_sha256",
        "blind_commitment_set_root_sha256",
        "log_genesis_root_sha256",
        "recipient_private_key_reveal_commitment_sha256",
        "activation_trigger_commitment_sha256",
        "require_no_pre_activation_quorum",
        "require_no_pre_activation_plaintext_or_access",
        "issued_at_utc",
        "role",
        "key_id",
        "content_sha256",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "campaign_registry_hash",
        "g08_result_root",
        "activation_time_utc",
        "policy_id",
        "scheme",
        "threshold",
        "activation_recipient_public_key_base64",
        "activation_recipient_private_key_reveal_commitment_sha256",
        "share_commitments",
        "issued_at_utc",
        "role",
        "key_id",
        "content_sha256",
    }
)
_SHARE_COMMITMENT_FIELDS = frozenset(
    {"custodian_role", "share_index", "share_commitment_sha256"}
)
_SOURCE_BINDING_FIELDS = frozenset(
    {
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "campaign_registry_hash",
        "g08_result_root",
    }
)
_ROSTER_COMMITMENT_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "family_id",
        "archive_sha256",
        "package_sha256",
        "roster_commitment_sha256",
        "committed_at_utc",
        "role",
        "key_id",
    }
)
_NONCE_COMMITMENT_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "family_id",
        "archive_sha256",
        "package_sha256",
        "nonce_commitment_sha256",
        "committed_at_utc",
        "role",
        "key_id",
    }
)
_PACKAGE_COMMITMENT_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "family_id",
        "archive_sha256",
        "package_sha256",
        "nonce_commitment_sha256",
        "ciphertext",
        "aad",
        "package_commitment_sha256",
        "committed_at_utc",
        "role",
        "key_id",
    }
)
_NONCE_REVEAL_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "family_id",
        "archive_sha256",
        "package_sha256",
        "nonce",
        "revealed_at_utc",
        "role",
        "key_id",
    }
)
_SHARE_RELEASE_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "threshold_policy_sha256",
        "custodian_role",
        "share_index",
        "share_commitment_sha256",
        "ephemeral_public_key_base64",
        "seal_nonce",
        "sealed_share",
        "released_at_utc",
        "role",
        "key_id",
    }
)
_ACCESS_EVENT_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "threshold_policy_sha256",
        "blind_commitment_set_root_sha256",
        "log_id",
        "log_genesis_root_sha256",
        "preactivation_close_root_sha256",
        "activation_trigger_envelope_sha256",
        "sequence",
        "cursor",
        "previous_cursor",
        "event_id",
        "previous_envelope_sha256",
        "event_type",
        "occurred_at_utc",
        "role",
        "key_id",
        "details",
    }
)
_SHARE_EVENT_DETAILS = frozenset({"release_envelope_sha256", "share_index"})
_NONCE_REVEAL_EVENT_DETAILS = frozenset(
    {
        "nonce_reveal_envelope_sha256",
        "family_id",
        "archive_sha256",
        "package_sha256",
    }
)
_PACKAGE_EVENT_DETAILS = frozenset(
    {"family_id", "archive_sha256", "package_sha256"}
)
_KEY_REVEAL_EVENT_DETAILS = frozenset(
    {
        "recipient_key_reveal_envelope_sha256",
        "recipient_private_key_reveal_commitment_sha256",
    }
)
_EVENT_ROLE = {
    "RECIPIENT_KEY_REVEAL": "activation_service",
    "NONCE_REVEAL": "registrar",
    "SHARE_RELEASE": "custodian",
    "SHARE_DECRYPT": "activation_service",
    "PACKAGE_DECRYPT": "activation_service",
    "PACKAGE_ACCESS": "evidence_custodian",
}

_V2_DEPENDENCIES_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root",
        "evaluation_id",
        "frozen_spec_hash",
        "campaign_registry_hash",
        "g08_result_root",
        "g08_roster_sha256",
        "direct_dependencies",
        "content_sha256",
    }
)
_V2_DEPENDENCY_FIELDS = frozenset(
    {"gate_id", "bundle_sha256", "authority_payload_sha256", "decision"}
)
_LOG_RECEIPT_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "log_id",
        "phase",
        "prior_receipt_envelope_sha256",
        "causal_predecessor_root_sha256",
        "activation_trigger_envelope_sha256",
        "blind_commitment_set_root_sha256",
        "first_sequence",
        "next_sequence",
        "cursor_start",
        "cursor_end",
        "range_start_sequence",
        "range_end_sequence_exclusive",
        "event_count",
        "last_event_envelope_sha256",
        "event_hashes_root_sha256",
        "worm_object_root_sha256",
        "publication_receipt",
        "published_at_utc",
        "role",
        "key_id",
    }
)
_WORM_PUBLICATION_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "provider",
        "immutable_object_id",
        "retention_mode",
        "generation",
        "prior_publication_receipt_sha256",
        "log_id",
        "phase",
        "first_sequence",
        "next_sequence",
        "cursor_start",
        "cursor_end",
        "range_start_sequence",
        "range_end_sequence_exclusive",
        "event_count",
        "last_event_envelope_sha256",
        "event_hashes_root_sha256",
        "worm_object_root_sha256",
        "causal_predecessor_root_sha256",
        "activation_trigger_envelope_sha256",
        "blind_commitment_set_root_sha256",
        "published_at_utc",
        "role",
        "key_id",
    }
)
_LOG_GENESIS_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "common_v2_dependencies_sha256",
        "threshold_policy_sha256",
        "blind_commitment_set_root_sha256",
        "activation_time_utc",
        "log_id",
        "first_sequence",
        "cursor_start",
        "range_start_sequence",
        "previous_event_sha256",
        "genesis_receipt_envelope_sha256",
        "recipient_private_key_reveal_commitment_sha256",
        "genesis_root_sha256",
        "committed_at_utc",
        "role",
        "key_id",
    }
)
_ACTIVATION_TRIGGER_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "activation_rule_sha256",
        "common_v2_dependencies_sha256",
        "threshold_policy_sha256",
        "blind_commitment_set_root_sha256",
        "log_genesis_root_sha256",
        "recipient_private_key_reveal_commitment_sha256",
        "trigger_id",
        "trigger_release_nonce",
        "activation_trigger_commitment_sha256",
        "triggered_at_utc",
        "role",
        "key_id",
    }
)
_LOG_CLOSE_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "close_kind",
        "log_id",
        "log_genesis_root_sha256",
        "activation_trigger_envelope_sha256",
        "predecessor_close_root_sha256",
        "worm_receipt_envelope_sha256",
        "first_sequence",
        "next_sequence",
        "cursor_start",
        "cursor_end",
        "range_start_sequence",
        "range_end_sequence_exclusive",
        "event_count",
        "last_event_envelope_sha256",
        "event_hashes_root_sha256",
        "close_root_sha256",
        "closed_at_utc",
        "role",
        "key_id",
    }
)
_RECIPIENT_KEY_REVEAL_FIELDS = _SOURCE_BINDING_FIELDS | frozenset(
    {
        "threshold_policy_sha256",
        "activation_trigger_envelope_sha256",
        "preactivation_close_root_sha256",
        "recipient_private_key_reveal_commitment_sha256",
        "activation_recipient_private_key",
        "revealed_at_utc",
        "role",
        "key_id",
    }
)


class BlindActivationError(ValueError):
    """A G09 evidence bundle cannot support a blind activation pass."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise BlindActivationError(code, message)


def _exact(value: object, fields: frozenset[str], label: str, code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(code, f"{label} fields are not exact")
    return value


def _decode_byte_evidence(value: object, *, expected_media_type: str) -> bytes:
    """Decode one strict, hash-bound byte wrapper without common-gate code."""

    record = _exact(value, _BYTE_EVIDENCE_FIELDS, "byte evidence", "INVALID_BYTE_EVIDENCE")
    encoded = record["base64"]
    if type(encoded) is not str:
        _fail("INVALID_BYTE_EVIDENCE", "byte evidence base64 must be a string")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BlindActivationError("INVALID_BYTE_EVIDENCE", "byte evidence base64 is invalid") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        _fail("INVALID_BYTE_EVIDENCE", "byte evidence base64 is not canonical")
    if type(record["decoded_length"]) is not int or record["decoded_length"] != len(raw):
        _fail("INVALID_BYTE_EVIDENCE", "byte evidence decoded length mismatch")
    if hashlib.sha256(raw).hexdigest() != _sha256(
        record["sha256"], "byte evidence sha256", "INVALID_BYTE_EVIDENCE"
    ):
        _fail("INVALID_BYTE_EVIDENCE", "byte evidence SHA-256 mismatch")
    if record["media_type"] != expected_media_type or _MEDIA_TYPE_RE.fullmatch(expected_media_type) is None:
        _fail("INVALID_BYTE_EVIDENCE", "byte evidence media type mismatch")
    return raw


def _sha256(value: object, label: str, code: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _identifier(value: object, label: str, code: str) -> str:
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        _fail(code, f"{label} must be a canonical identifier")
    return value


def _nonnegative_int(value: object, label: str, code: str) -> int:
    if type(value) is not int or value < 0:
        _fail(code, f"{label} must be a nonnegative integer")
    return value


def _utc(value: object, label: str, code: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        _fail(code, f"{label} must be canonical UTC with microseconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise BlindActivationError(code, f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        _fail(code, f"{label} must be canonical UTC with microseconds")
    return parsed


def _utc_text(value: object, label: str, code: str) -> str:
    _utc(value, label, code)
    return value  # type: ignore[return-value]


def _canonical_b64(value: object, label: str, code: str, *, length: int | None = None) -> bytes:
    if type(value) is not str or _B64_RE.fullmatch(value) is None:
        _fail(code, f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error is intentionally implementation-private.
        raise BlindActivationError(code, f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        _fail(code, f"{label} must be canonical base64")
    if length is not None and len(decoded) != length:
        _fail(code, f"{label} must decode to {length} bytes")
    return decoded


def _canonical_json_evidence(value: object, label: str) -> tuple[dict[str, Any] | list[Any], bytes, str]:
    try:
        raw = _decode_byte_evidence(value, expected_media_type="application/json")
    except Exception as exc:
        raise BlindActivationError("INVALID_BYTE_EVIDENCE", f"{label}: {exc}") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BlindActivationError("NONCANONICAL_JSON", f"{label} is not strict JSON") from exc
    if type(parsed) not in {dict, list}:
        _fail("NONCANONICAL_JSON", f"{label} must contain a JSON object or list")
    try:
        if canonical_json_bytes(parsed) != raw:
            _fail("NONCANONICAL_JSON", f"{label} is not canonical JSON bytes")
    except Exception as exc:
        if isinstance(exc, BlindActivationError):
            raise
        raise BlindActivationError("NONCANONICAL_JSON", f"{label} is not canonical JSON") from exc
    return parsed, raw, hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _hash_domain(domain: str, **bindings: object) -> str:
    return canonical_sha256({"domain": domain, **bindings})


def _binding(
    *,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
) -> dict[str, str]:
    return {
        "protocol_id": PROTOCOL_ID,
        "campaign_root": _sha256(campaign_root, "campaign_root", "INVALID_BINDING"),
        "evaluation_id": _identifier(evaluation_id, "evaluation_id", "INVALID_BINDING"),
        "frozen_spec_hash": _sha256(frozen_spec_hash, "frozen_spec_hash", "INVALID_BINDING"),
        "campaign_registry_hash": _sha256(
            campaign_registry_hash, "campaign_registry_hash", "INVALID_BINDING"
        ),
        "g08_result_root": _sha256(g08_result_root, "g08_result_root", "INVALID_BINDING"),
    }


def _normalize_expected_binding(expected: Mapping[str, str], code: str) -> dict[str, str]:
    if not isinstance(expected, Mapping) or set(expected) != _SOURCE_BINDING_FIELDS:
        _fail(code, "expected source binding fields are not exact")
    if expected["protocol_id"] != PROTOCOL_ID:
        _fail(code, "expected source binding protocol is not frozen v5.1")
    return _binding(
        campaign_root=expected["campaign_root"],
        evaluation_id=expected["evaluation_id"],
        frozen_spec_hash=expected["frozen_spec_hash"],
        campaign_registry_hash=expected["campaign_registry_hash"],
        g08_result_root=expected["g08_result_root"],
    )


def _assert_binding(payload: Mapping[str, Any], expected: Mapping[str, str], label: str) -> None:
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            _fail("BINDING_MISMATCH", f"{label} does not bind {field}")


def derive_roster_commitment(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    family_id: str,
    archive_sha256: str,
    package_sha256: str,
) -> str:
    """Derive the domain-separated pre-activation roster commitment."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return _hash_domain(
        "G09/ROSTER_COMMITMENT/v1",
        **binding,
        family_id=_identifier(family_id, "family_id", "INVALID_COMMITMENT"),
        archive_sha256=_sha256(archive_sha256, "archive_sha256", "INVALID_COMMITMENT"),
        package_sha256=_sha256(package_sha256, "package_sha256", "INVALID_COMMITMENT"),
    )


def derive_nonce_commitment(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    family_id: str,
    archive_sha256: str,
    package_sha256: str,
    nonce: bytes,
) -> str:
    """Commit an AES-GCM nonce without exposing it before activation."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    if type(nonce) is not bytes or len(nonce) != 12:
        _fail("INVALID_NONCE", "package nonce must be exactly 12 bytes")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return _hash_domain(
        "G09/NONCE_COMMITMENT/v1",
        **binding,
        family_id=_identifier(family_id, "family_id", "INVALID_COMMITMENT"),
        archive_sha256=_sha256(archive_sha256, "archive_sha256", "INVALID_COMMITMENT"),
        package_sha256=_sha256(package_sha256, "package_sha256", "INVALID_COMMITMENT"),
        nonce_base64=base64.b64encode(nonce).decode("ascii"),
    )


def derive_package_aad(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    family_id: str,
    archive_sha256: str,
    package_sha256: str,
    nonce_commitment_sha256: str,
) -> bytes:
    """Return the exact canonical AAD required for a blinded package."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return canonical_json_bytes(
        {
            "domain": "G09/PACKAGE_AAD/v1",
            **binding,
            "family_id": _identifier(family_id, "family_id", "INVALID_AAD"),
            "archive_sha256": _sha256(archive_sha256, "archive_sha256", "INVALID_AAD"),
            "package_sha256": _sha256(package_sha256, "package_sha256", "INVALID_AAD"),
            "nonce_commitment_sha256": _sha256(
                nonce_commitment_sha256, "nonce_commitment_sha256", "INVALID_AAD"
            ),
        }
    )


def derive_package_commitment(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    family_id: str,
    archive_sha256: str,
    package_sha256: str,
    nonce_commitment_sha256: str,
    ciphertext_sha256: str,
    aad_sha256: str,
) -> str:
    """Bind each blinded ciphertext to exactly one selected archive/package."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return _hash_domain(
        "G09/PACKAGE_COMMITMENT/v1",
        **binding,
        family_id=_identifier(family_id, "family_id", "INVALID_COMMITMENT"),
        archive_sha256=_sha256(archive_sha256, "archive_sha256", "INVALID_COMMITMENT"),
        package_sha256=_sha256(package_sha256, "package_sha256", "INVALID_COMMITMENT"),
        nonce_commitment_sha256=_sha256(
            nonce_commitment_sha256, "nonce_commitment_sha256", "INVALID_COMMITMENT"
        ),
        ciphertext_sha256=_sha256(ciphertext_sha256, "ciphertext_sha256", "INVALID_COMMITMENT"),
        aad_sha256=_sha256(aad_sha256, "aad_sha256", "INVALID_COMMITMENT"),
    )


def derive_share_commitment(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    policy_id: str,
    custodian_role: str,
    share_index: int,
    share: bytes,
) -> str:
    """Commit one Shamir share under the public threshold policy identity."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    if type(share_index) is not int or not 1 <= share_index <= 255:
        _fail("INVALID_SHARE", "share_index must be in 1..255")
    if type(share) is not bytes or len(share) != 32:
        _fail("INVALID_SHARE", "threshold share must be exactly 32 bytes")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return _hash_domain(
        "G09/SHARE_COMMITMENT/v1",
        **binding,
        policy_id=_identifier(policy_id, "policy_id", "INVALID_SHARE"),
        custodian_role=_identifier(custodian_role, "custodian_role", "INVALID_SHARE"),
        share_index=share_index,
        share_base64=base64.b64encode(share).decode("ascii"),
    )


def derive_recipient_private_key_reveal_commitment(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    policy_id: str,
    activation_recipient_private_key: bytes,
) -> str:
    """Commit the recipient private-key reveal without exposing the key."""

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    if type(activation_recipient_private_key) is not bytes or len(activation_recipient_private_key) != 32:
        _fail("INVALID_RECIPIENT_KEY", "activation recipient private key must be 32 bytes")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    return _hash_domain(
        "G09/RECIPIENT_PRIVATE_KEY_REVEAL_COMMITMENT/v1",
        **binding,
        policy_id=_identifier(policy_id, "policy_id", "INVALID_RECIPIENT_KEY"),
        private_key_base64=base64.b64encode(activation_recipient_private_key).decode("ascii"),
    )


def derive_log_event_hashes_root(event_hashes: Sequence[str]) -> str:
    if type(event_hashes) not in {list, tuple}:
        _fail("INVALID_LOG_CLOSE", "event hashes must be a list or tuple")
    hashes = [
        _sha256(value, "event envelope sha256", "INVALID_LOG_CLOSE")
        for value in event_hashes
    ]
    return _hash_domain("G09/LOG_EVENT_HASHES/v1", event_hashes=hashes)


def derive_log_worm_root(
    *,
    log_id: str,
    causal_predecessor_root_sha256: str,
    event_hashes: Sequence[str],
) -> str:
    return _hash_domain(
        "G09/LOG_WORM_OBJECT/v1",
        log_id=_identifier(log_id, "log_id", "INVALID_LOG_RECEIPT"),
        causal_predecessor_root_sha256=_sha256(
            causal_predecessor_root_sha256,
            "causal_predecessor_root_sha256",
            "INVALID_LOG_RECEIPT",
        ),
        event_hashes_root_sha256=derive_log_event_hashes_root(event_hashes),
        event_count=len(event_hashes),
    )


def derive_blind_commitment_set_root(
    *,
    expected: Mapping[str, str],
    common_v2_dependencies_sha256: str,
    expected_g08_roster_sha256: str,
    threshold_policy_evidence_sha256: str,
    roster_commitments_evidence_sha256: str,
    nonce_commitments_evidence_sha256: str,
    package_commitments_evidence_sha256: str,
) -> str:
    """Commit the exact preactivation blinded evidence byte universe."""

    return _hash_domain(
        "G09/BLIND_COMMITMENT_SET/v1",
        **_normalize_expected_binding(expected, "INVALID_BLIND_COMMITMENT_SET"),
        common_v2_dependencies_sha256=_sha256(
            common_v2_dependencies_sha256,
            "common v2 dependencies evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
        expected_g08_roster_sha256=_sha256(
            expected_g08_roster_sha256,
            "expected G08 roster evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
        threshold_policy_evidence_sha256=_sha256(
            threshold_policy_evidence_sha256,
            "threshold policy evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
        roster_commitments_evidence_sha256=_sha256(
            roster_commitments_evidence_sha256,
            "roster commitments evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
        nonce_commitments_evidence_sha256=_sha256(
            nonce_commitments_evidence_sha256,
            "nonce commitments evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
        package_commitments_evidence_sha256=_sha256(
            package_commitments_evidence_sha256,
            "package commitments evidence",
            "INVALID_BLIND_COMMITMENT_SET",
        ),
    )


def derive_log_genesis_root(
    *,
    expected: Mapping[str, str],
    common_v2_dependencies_sha256: str,
    threshold_policy_sha256: str,
    blind_commitment_set_root_sha256: str,
    activation_time_utc: str,
    log_id: str,
    first_sequence: int,
    cursor_start: str,
    range_start_sequence: int,
    previous_event_sha256: str,
    genesis_receipt_envelope_sha256: str,
    recipient_private_key_reveal_commitment_sha256: str,
    committed_at_utc: str,
) -> str:
    first_sequence = _nonnegative_int(
        first_sequence, "first_sequence", "INVALID_LOG_GENESIS"
    )
    range_start_sequence = _nonnegative_int(
        range_start_sequence, "range_start_sequence", "INVALID_LOG_GENESIS"
    )
    return _hash_domain(
        "G09/LOG_GENESIS/v1",
        **_normalize_expected_binding(expected, "INVALID_LOG_GENESIS"),
        common_v2_dependencies_sha256=_sha256(
            common_v2_dependencies_sha256,
            "common_v2_dependencies_sha256",
            "INVALID_LOG_GENESIS",
        ),
        threshold_policy_sha256=_sha256(
            threshold_policy_sha256, "threshold_policy_sha256", "INVALID_LOG_GENESIS"
        ),
        blind_commitment_set_root_sha256=_sha256(
            blind_commitment_set_root_sha256,
            "blind_commitment_set_root_sha256",
            "INVALID_LOG_GENESIS",
        ),
        activation_time_utc=_utc_text(
            activation_time_utc, "activation_time_utc", "INVALID_LOG_GENESIS"
        ),
        log_id=_identifier(log_id, "log_id", "INVALID_LOG_GENESIS"),
        first_sequence=first_sequence,
        cursor_start=_identifier(cursor_start, "cursor_start", "INVALID_LOG_GENESIS"),
        range_start_sequence=range_start_sequence,
        previous_event_sha256=_sha256(
            previous_event_sha256, "previous_event_sha256", "INVALID_LOG_GENESIS"
        ),
        genesis_receipt_envelope_sha256=_sha256(
            genesis_receipt_envelope_sha256,
            "genesis_receipt_envelope_sha256",
            "INVALID_LOG_GENESIS",
        ),
        recipient_private_key_reveal_commitment_sha256=_sha256(
            recipient_private_key_reveal_commitment_sha256,
            "recipient key reveal commitment",
            "INVALID_LOG_GENESIS",
        ),
        committed_at_utc=_utc_text(
            committed_at_utc, "committed_at_utc", "INVALID_LOG_GENESIS"
        ),
    )


def derive_activation_trigger_commitment(
    *,
    expected: Mapping[str, str],
    common_v2_dependencies_sha256: str,
    threshold_policy_sha256: str,
    log_genesis_root_sha256: str,
    recipient_private_key_reveal_commitment_sha256: str,
    trigger_id: str,
    trigger_release_nonce: bytes,
    triggered_at_utc: str,
) -> str:
    if type(trigger_release_nonce) is not bytes or len(trigger_release_nonce) != 32:
        _fail("INVALID_ACTIVATION_TRIGGER", "trigger release nonce must be 32 bytes")
    return _hash_domain(
        "G09/ACTIVATION_TRIGGER_COMMITMENT/v1",
        **_normalize_expected_binding(expected, "INVALID_ACTIVATION_TRIGGER"),
        common_v2_dependencies_sha256=_sha256(
            common_v2_dependencies_sha256,
            "common_v2_dependencies_sha256",
            "INVALID_ACTIVATION_TRIGGER",
        ),
        threshold_policy_sha256=_sha256(
            threshold_policy_sha256,
            "threshold_policy_sha256",
            "INVALID_ACTIVATION_TRIGGER",
        ),
        log_genesis_root_sha256=_sha256(
            log_genesis_root_sha256,
            "log_genesis_root_sha256",
            "INVALID_ACTIVATION_TRIGGER",
        ),
        recipient_private_key_reveal_commitment_sha256=_sha256(
            recipient_private_key_reveal_commitment_sha256,
            "recipient key reveal commitment",
            "INVALID_ACTIVATION_TRIGGER",
        ),
        trigger_id=_identifier(trigger_id, "trigger_id", "INVALID_ACTIVATION_TRIGGER"),
        trigger_release_nonce_base64=base64.b64encode(trigger_release_nonce).decode("ascii"),
        triggered_at_utc=_utc_text(
            triggered_at_utc, "triggered_at_utc", "INVALID_ACTIVATION_TRIGGER"
        ),
    )


def derive_log_close_root(
    *,
    expected: Mapping[str, str],
    close_kind: str,
    log_id: str,
    log_genesis_root_sha256: str,
    activation_trigger_envelope_sha256: str,
    predecessor_close_root_sha256: str,
    worm_receipt_envelope_sha256: str,
    first_sequence: int,
    next_sequence: int,
    cursor_start: str,
    cursor_end: str,
    range_start_sequence: int,
    range_end_sequence_exclusive: int,
    event_count: int,
    last_event_envelope_sha256: str,
    event_hashes_root_sha256: str,
    closed_at_utc: str,
) -> str:
    if type(close_kind) is not str or close_kind not in {
        "PREACTIVATION_ZERO_ACCESS",
        "POSTACTIVATION_TERMINAL",
    }:
        _fail("INVALID_LOG_CLOSE", "log close kind is not allowlisted")
    numeric = {
        "first_sequence": first_sequence,
        "next_sequence": next_sequence,
        "range_start_sequence": range_start_sequence,
        "range_end_sequence_exclusive": range_end_sequence_exclusive,
        "event_count": event_count,
    }
    checked_numeric = {
        field: _nonnegative_int(value, field, "INVALID_LOG_CLOSE")
        for field, value in numeric.items()
    }
    if (
        checked_numeric["first_sequence"]
        != checked_numeric["range_start_sequence"]
        or checked_numeric["next_sequence"]
        != checked_numeric["range_end_sequence_exclusive"]
        or checked_numeric["next_sequence"] < checked_numeric["first_sequence"]
        or checked_numeric["event_count"]
        != checked_numeric["next_sequence"] - checked_numeric["first_sequence"]
    ):
        _fail("INVALID_LOG_CLOSE", "log close sequence and range counters are inconsistent")
    return _hash_domain(
        "G09/LOG_CLOSE/v1",
        **_normalize_expected_binding(expected, "INVALID_LOG_CLOSE"),
        close_kind=close_kind,
        log_id=_identifier(log_id, "log_id", "INVALID_LOG_CLOSE"),
        log_genesis_root_sha256=_sha256(
            log_genesis_root_sha256, "log genesis root", "INVALID_LOG_CLOSE"
        ),
        activation_trigger_envelope_sha256=_sha256(
            activation_trigger_envelope_sha256,
            "activation trigger envelope",
            "INVALID_LOG_CLOSE",
        ),
        predecessor_close_root_sha256=_sha256(
            predecessor_close_root_sha256,
            "predecessor close root",
            "INVALID_LOG_CLOSE",
        ),
        worm_receipt_envelope_sha256=_sha256(
            worm_receipt_envelope_sha256,
            "worm receipt envelope",
            "INVALID_LOG_CLOSE",
        ),
        first_sequence=checked_numeric["first_sequence"],
        next_sequence=checked_numeric["next_sequence"],
        cursor_start=_identifier(cursor_start, "cursor_start", "INVALID_LOG_CLOSE"),
        cursor_end=_identifier(cursor_end, "cursor_end", "INVALID_LOG_CLOSE"),
        range_start_sequence=checked_numeric["range_start_sequence"],
        range_end_sequence_exclusive=checked_numeric[
            "range_end_sequence_exclusive"
        ],
        event_count=checked_numeric["event_count"],
        last_event_envelope_sha256=_sha256(
            last_event_envelope_sha256, "last event envelope", "INVALID_LOG_CLOSE"
        ),
        event_hashes_root_sha256=_sha256(
            event_hashes_root_sha256, "event hashes root", "INVALID_LOG_CLOSE"
        ),
        closed_at_utc=_utc_text(closed_at_utc, "closed_at_utc", "INVALID_LOG_CLOSE"),
    )


def _gf_mul(left: int, right: int) -> int:
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        if left & 0x100:
            left ^= 0x11B
        right >>= 1
    return product


def _gf_pow(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    return result


def _gf_inverse(value: int) -> int:
    if value == 0:
        _fail("INVALID_SHARE", "zero has no finite-field inverse")
    return _gf_pow(value, 254)


def derive_threshold_shares(
    secret: bytes,
    *,
    threshold: int,
    share_count: int,
    coefficient_material: bytes,
) -> list[tuple[int, bytes]]:
    """Deterministically split a 32-byte AES key for testable G09 evidence.

    This is a verifier fixture helper, not an evidence artifact constructor.
    ``coefficient_material`` must be independently generated in production.
    """

    if type(secret) is not bytes or len(secret) != 32:
        _fail("INVALID_SHARE", "threshold secret must be exactly 32 bytes")
    if type(coefficient_material) is not bytes or not coefficient_material:
        _fail("INVALID_SHARE", "coefficient_material must be non-empty bytes")
    if (
        type(threshold) is not int
        or type(share_count) is not int
        or not 2 <= threshold <= share_count <= 255
    ):
        _fail("INVALID_SHARE", "threshold and share_count must satisfy 2 <= threshold <= share_count <= 255")
    coefficients: list[list[int]] = [[byte] for byte in secret]
    for byte_index in range(32):
        for degree in range(1, threshold):
            coefficients[byte_index].append(
                hashlib.sha256(
                    b"G09/SHAMIR/COEFFICIENT/v1\0"
                    + coefficient_material
                    + byte_index.to_bytes(2, "big")
                    + degree.to_bytes(2, "big")
                ).digest()[0]
            )
    shares: list[tuple[int, bytes]] = []
    for index in range(1, share_count + 1):
        encoded = bytearray()
        for polynomial in coefficients:
            value = 0
            for coefficient in reversed(polynomial):
                value = _gf_mul(value, index) ^ coefficient
            encoded.append(value)
        shares.append((index, bytes(encoded)))
    return shares


def reconstruct_threshold_secret(shares: Sequence[tuple[int, bytes]], *, threshold: int) -> bytes:
    """Reconstruct one AES-256 key and reject inconsistent released shares."""

    if type(threshold) is not int or not 2 <= threshold <= 255:
        _fail("INVALID_SHARE", "threshold must be in 2..255")
    if type(shares) not in {list, tuple} or len(shares) < threshold:
        _fail("INSUFFICIENT_SHARES", "a reconstructable threshold share set is required")
    normalized = sorted(shares, key=lambda item: item[0])
    indexes = [item[0] for item in normalized]
    if any(type(index) is not int or not 1 <= index <= 255 for index in indexes):
        _fail("INVALID_SHARE", "share indexes must be in 1..255")
    if len(set(indexes)) != len(indexes):
        _fail("DUPLICATE_SHARE", "threshold share indexes must be unique")
    if any(type(share) is not bytes or len(share) != 32 for _, share in normalized):
        _fail("INVALID_SHARE", "threshold shares must be exactly 32 bytes")
    selected = normalized[:threshold]

    def interpolate(target: int) -> bytes:
        weights: list[int] = []
        for point_index, (x_i, _) in enumerate(selected):
            basis = 1
            for other_index, (x_j, _) in enumerate(selected):
                if point_index == other_index:
                    continue
                basis = _gf_mul(
                    basis,
                    _gf_mul(target ^ x_j, _gf_inverse(x_i ^ x_j)),
                )
            weights.append(basis)
        result = bytearray()
        for byte_index in range(32):
            value = 0
            for (_, share), basis in zip(selected, weights, strict=True):
                value ^= _gf_mul(share[byte_index], basis)
            result.append(value)
        return bytes(result)

    for index, share in normalized:
        if interpolate(index) != share:
            _fail(
                "INCONSISTENT_THRESHOLD_SHARES",
                "released shares do not reconstruct one degree-bounded threshold secret",
            )
    return interpolate(0)


def derive_share_seal_aad(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    threshold_policy_sha256: str,
    custodian_role: str,
    share_index: int,
    share_commitment_sha256: str,
) -> bytes:
    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    binding = _binding(
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        campaign_registry_hash=campaign_registry_hash,
        g08_result_root=g08_result_root,
    )
    if type(share_index) is not int or not 1 <= share_index <= 255:
        _fail("INVALID_SHARE", "share_index must be in 1..255")
    return canonical_json_bytes(
        {
            "domain": "G09/SHARE_SEAL_AAD/v1",
            **binding,
            "threshold_policy_sha256": _sha256(
                threshold_policy_sha256, "threshold_policy_sha256", "INVALID_SHARE"
            ),
            "custodian_role": _identifier(custodian_role, "custodian_role", "INVALID_SHARE"),
            "share_index": share_index,
            "share_commitment_sha256": _sha256(
                share_commitment_sha256, "share_commitment_sha256", "INVALID_SHARE"
            ),
        }
    )


def seal_threshold_share(
    share: bytes,
    *,
    activation_recipient_public_key: bytes,
    ephemeral_private_key: bytes,
    nonce: bytes,
    aad: bytes,
) -> dict[str, object]:
    """Seal a 32-byte share to the public activation recipient key.

    Explicit ephemeral material makes fixtures reproducible; it must not be
    reused in a real ceremony.
    """

    if type(share) is not bytes or len(share) != 32:
        _fail("INVALID_SHARE", "threshold share must be exactly 32 bytes")
    if type(activation_recipient_public_key) is not bytes or len(activation_recipient_public_key) != 32:
        _fail("INVALID_SEAL", "activation recipient public key must be 32 bytes")
    if type(ephemeral_private_key) is not bytes or len(ephemeral_private_key) != 32:
        _fail("INVALID_SEAL", "ephemeral private key must be 32 bytes")
    if type(nonce) is not bytes or len(nonce) != 12:
        _fail("INVALID_SEAL", "share seal nonce must be 12 bytes")
    if type(aad) is not bytes:
        _fail("INVALID_SEAL", "share seal AAD must be bytes")
    try:
        ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        recipient = X25519PublicKey.from_public_bytes(activation_recipient_public_key)
        shared = ephemeral.exchange(recipient)
    except ValueError as exc:
        raise BlindActivationError("INVALID_SEAL", "X25519 share seal key is invalid") from exc
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"G09/SHARE_SEAL/v1\0" + aad).derive(shared)
    ciphertext = AESGCM(key).encrypt(nonce, share, aad)
    return {
        "ephemeral_public_key_base64": base64.b64encode(
            ephemeral.public_key().public_bytes_raw()
        ).decode("ascii"),
        "seal_nonce": {
            "base64": base64.b64encode(nonce).decode("ascii"),
            "decoded_length": len(nonce),
            "sha256": hashlib.sha256(nonce).hexdigest(),
            "media_type": "application/octet-stream",
        },
        "sealed_share": {
            "base64": base64.b64encode(ciphertext).decode("ascii"),
            "decoded_length": len(ciphertext),
            "sha256": hashlib.sha256(ciphertext).hexdigest(),
            "media_type": "application/octet-stream",
        },
    }


def _validate_v2_dependencies(
    evidence: object,
    *,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    diagnostic_campaign_registry_hash: str | None,
    diagnostic_g08_result_root: str | None,
) -> tuple[dict[str, str], str, list[dict[str, Any]], str]:
    parsed, _, digest = _canonical_json_evidence(
        evidence, "common_v2_dependencies"
    )
    record = _exact(
        parsed,
        _V2_DEPENDENCIES_FIELDS,
        "common v2 dependencies",
        "INVALID_V2_DEPENDENCIES",
    )
    if record["schema"] != G09_V2_DEPENDENCIES_SCHEMA or record["protocol_id"] != PROTOCOL_ID:
        _fail("INVALID_V2_DEPENDENCIES", "common v2 dependency schema or protocol mismatch")
    if record["campaign_root"] != _sha256(campaign_root, "campaign_root", "INVALID_BINDING"):
        _fail("BINDING_MISMATCH", "common v2 dependencies do not bind campaign_root")
    if record["evaluation_id"] != _identifier(evaluation_id, "evaluation_id", "INVALID_BINDING"):
        _fail("BINDING_MISMATCH", "common v2 dependencies do not bind evaluation_id")
    if record["frozen_spec_hash"] != _sha256(frozen_spec_hash, "frozen_spec_hash", "INVALID_BINDING"):
        _fail("BINDING_MISMATCH", "common v2 dependencies do not bind frozen_spec_hash")
    registry_hash = _sha256(
        record["campaign_registry_hash"],
        "dependency campaign_registry_hash",
        "INVALID_V2_DEPENDENCIES",
    )
    g08_root = _sha256(
        record["g08_result_root"], "dependency g08_result_root", "INVALID_V2_DEPENDENCIES"
    )
    g08_roster_sha256 = _sha256(
        record["g08_roster_sha256"],
        "dependency G08 roster sha256",
        "INVALID_V2_DEPENDENCIES",
    )
    if diagnostic_campaign_registry_hash is not None and _sha256(
        diagnostic_campaign_registry_hash,
        "diagnostic campaign_registry_hash",
        "INVALID_BINDING",
    ) != registry_hash:
        _fail("V2_DEPENDENCY_MISMATCH", "diagnostic registry hash disagrees with v2 dependency")
    if diagnostic_g08_result_root is not None and _sha256(
        diagnostic_g08_result_root, "diagnostic g08_result_root", "INVALID_BINDING"
    ) != g08_root:
        _fail("V2_DEPENDENCY_MISMATCH", "diagnostic G08 root disagrees with v2 dependency")
    dependencies = record["direct_dependencies"]
    if type(dependencies) is not list or len(dependencies) != 2:
        _fail("INVALID_V2_DEPENDENCIES", "G09 requires exact G00 and G08 v2 dependencies")
    checked: list[dict[str, Any]] = []
    expected_gates = ["G00_TRUST_ROOTS", "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION"]
    for expected_gate, value in zip(expected_gates, dependencies, strict=True):
        item = _exact(
            value,
            _V2_DEPENDENCY_FIELDS,
            "common v2 dependency",
            "INVALID_V2_DEPENDENCIES",
        )
        if item["gate_id"] != expected_gate or item["decision"] != "PASS_RESEARCH_ONLY":
            _fail("INVALID_V2_DEPENDENCIES", "common v2 dependencies are not exact passed G00/G08 records")
        checked.append(
            {
                "gate_id": expected_gate,
                "bundle_sha256": _sha256(
                    item["bundle_sha256"], "dependency bundle_sha256", "INVALID_V2_DEPENDENCIES"
                ),
                "authority_payload_sha256": _sha256(
                    item["authority_payload_sha256"],
                    "dependency authority_payload_sha256",
                    "INVALID_V2_DEPENDENCIES",
                ),
                "decision": item["decision"],
            }
        )
    if checked[1]["bundle_sha256"] != g08_root:
        _fail(
            "V2_DEPENDENCY_MISMATCH",
            "G08 result root is not the exact common-v2 G08 bundle root",
        )
    core = {key: value for key, value in record.items() if key != "content_sha256"}
    if record["content_sha256"] != canonical_sha256(core):
        _fail("INVALID_V2_DEPENDENCIES", "common v2 dependency content hash mismatch")
    return (
        _binding(
            campaign_root=campaign_root,
            evaluation_id=evaluation_id,
            frozen_spec_hash=frozen_spec_hash,
            campaign_registry_hash=registry_hash,
            g08_result_root=g08_root,
        ),
        digest,
        checked,
        g08_roster_sha256,
    )


def _validate_registry(
    evidence: object,
    *,
    expected: Mapping[str, str],
) -> tuple[dict[str, dict[str, Any]], str]:
    parsed, raw, raw_hash = _canonical_json_evidence(evidence, "campaign_registry")
    registry = _exact(parsed, _REGISTRY_FIELDS, "campaign registry", "INVALID_REGISTRY")
    if registry["schema"] != G09_REGISTRY_SCHEMA:
        _fail("INVALID_REGISTRY", "campaign registry schema mismatch")
    _assert_binding(
        {
            **registry,
            "campaign_registry_hash": expected["campaign_registry_hash"],
            "g08_result_root": expected["g08_result_root"],
        },
        expected,
        "campaign registry",
    )
    if raw_hash != expected["campaign_registry_hash"]:
        _fail("REGISTRY_HASH_MISMATCH", "campaign registry bytes do not match campaign_registry_hash")
    core = {key: value for key, value in registry.items() if key != "content_sha256"}
    if registry["content_sha256"] != canonical_sha256(core):
        _fail("INVALID_REGISTRY", "campaign registry content hash mismatch")
    roles = registry["roles"]
    if type(roles) is not list or not roles:
        _fail("INVALID_REGISTRY", "campaign registry roles must be a non-empty list")
    keys: dict[str, dict[str, Any]] = {}
    fingerprints: set[bytes] = set()
    principals: set[str] = set()
    prior = ""
    for row in roles:
        role = _exact(row, _REGISTRY_ROLE_FIELDS, "campaign registry role", "INVALID_REGISTRY")
        name = _identifier(role["role"], "registry role", "INVALID_REGISTRY")
        principal = _identifier(
            role["principal_id"], "registry principal_id", "INVALID_REGISTRY"
        )
        key_id = _identifier(role["key_id"], "registry key_id", "INVALID_REGISTRY")
        marker = f"{name}\0{key_id}"
        if marker <= prior:
            _fail("INVALID_REGISTRY", "campaign registry roles must be uniquely sorted")
        prior = marker
        if role["algorithm"] != "Ed25519":
            _fail("INVALID_REGISTRY", "campaign registry source keys must use Ed25519")
        if principal in principals:
            _fail("INVALID_REGISTRY", "campaign registry source roles must be independent principals")
        principals.add(principal)
        public = _canonical_b64(role["public_key_base64"], "registry public key", "INVALID_REGISTRY", length=32)
        if public in fingerprints:
            _fail("INVALID_REGISTRY", "campaign registry public keys must be role-separated")
        fingerprints.add(public)
        start = _utc(role["not_before_utc"], "registry not_before_utc", "INVALID_REGISTRY")
        end = _utc(role["not_after_utc"], "registry not_after_utc", "INVALID_REGISTRY")
        if start >= end:
            _fail("INVALID_REGISTRY", "registry key validity must increase")
        revoked = role["revoked_at_utc"]
        if revoked is not None:
            revoked_at = _utc(revoked, "registry revoked_at_utc", "INVALID_REGISTRY")
            if revoked_at < start:
                _fail("INVALID_REGISTRY", "registry revocation predates key validity")
        compromised = role["compromised_at_utc"]
        if compromised is not None:
            compromised_at = _utc(
                compromised, "registry compromised_at_utc", "INVALID_REGISTRY"
            )
            if compromised_at < start:
                _fail("INVALID_REGISTRY", "registry compromise predates key validity")
        if name in keys:
            _fail("INVALID_REGISTRY", "campaign registry role names must be unique")
        keys[name] = {**role, "public_key": public}
    for required in (
        "registrar",
        "activation_service",
        "evidence_custodian",
        "worm_publication_service",
    ):
        if required not in keys:
            _fail("INVALID_REGISTRY", f"campaign registry lacks {required} key")
    return keys, raw_hash


def _key_for_event(
    registry: Mapping[str, Mapping[str, Any]],
    *,
    role: object,
    key_id: object,
    at_utc: object,
    expected_role: str | None,
    label: str,
) -> bytes:
    role_text = _identifier(role, f"{label} role", "INVALID_ROLE")
    if expected_role is None:
        allowed = True
    elif expected_role == "custodian":
        allowed = role_text.startswith("custodian_")
    else:
        allowed = role_text == expected_role
    if not allowed:
        _fail("WRONG_ROLE", f"{label} is not signed by the required role")
    key = registry.get(role_text)
    if key is None or key["key_id"] != _identifier(key_id, f"{label} key_id", "INVALID_ROLE"):
        _fail("UNKNOWN_KEY", f"{label} key is not registered for its role")
    at = _utc(at_utc, f"{label} time", "INVALID_CHRONOLOGY")
    if not _utc(key["not_before_utc"], "key not_before_utc", "INVALID_REGISTRY") <= at < _utc(
        key["not_after_utc"], "key not_after_utc", "INVALID_REGISTRY"
    ):
        _fail("STALE_KEY", f"{label} signing key is outside its validity interval")
    revoked = key["revoked_at_utc"]
    if revoked is not None and at >= _utc(revoked, "key revoked_at_utc", "INVALID_REGISTRY"):
        _fail("REVOKED_KEY", f"{label} signing key was revoked")
    compromised = key["compromised_at_utc"]
    if compromised is not None and at >= _utc(
        compromised, "key compromised_at_utc", "INVALID_REGISTRY"
    ):
        _fail("COMPROMISED_KEY", f"{label} signing key was compromised")
    return key["public_key"]


def _verify_source_envelope(
    envelope: object,
    *,
    schema: str,
    fields: frozenset[str],
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    expected_role: str | None,
    timestamp_field: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    if type(envelope) is not dict:
        _fail("INVALID_SOURCE_ENVELOPE", f"{label} must be an envelope object")
    untrusted_payload = envelope.get("payload")
    if type(untrusted_payload) is not dict:
        _fail("INVALID_SOURCE_ENVELOPE", f"{label} payload is missing")
    public_key = _key_for_event(
        registry,
        role=untrusted_payload.get("role"),
        key_id=untrusted_payload.get("key_id"),
        at_utc=untrusted_payload.get(timestamp_field),
        expected_role=expected_role,
        label=label,
    )
    try:
        payload = verify_envelope(
            envelope, expected_artifact_schema=schema, pinned_public_key_bytes=public_key
        )
    except EnvelopeError as exc:
        raise BlindActivationError("INVALID_SOURCE_SIGNATURE", f"{label} signature failed: {exc}") from exc
    record = _exact(payload, fields, label, "INVALID_SOURCE_RECORD")
    _assert_binding(record, expected, label)
    _key_for_event(
        registry,
        role=record["role"],
        key_id=record["key_id"],
        at_utc=record[timestamp_field],
        expected_role=expected_role,
        label=label,
    )
    return record, canonical_sha256(envelope)


def _canonical_envelope_list(value: object, label: str) -> tuple[list[dict[str, Any]], str]:
    parsed, _, digest = _canonical_json_evidence(value, label)
    if type(parsed) is not list or any(type(item) is not dict for item in parsed):
        _fail("INVALID_SOURCE_EVIDENCE", f"{label} must be a canonical list of envelopes")
    return parsed, digest  # type: ignore[return-value]


def _validate_expected_roster(
    evidence: object,
    *,
    expected: Mapping[str, str],
) -> tuple[dict[str, str], str]:
    parsed, _, digest = _canonical_json_evidence(evidence, "expected_g08_roster")
    roster = _exact(parsed, _ROSTER_FIELDS, "expected G08 roster", "INVALID_ROSTER")
    if roster["schema"] != G09_ROSTER_SCHEMA:
        _fail("INVALID_ROSTER", "expected G08 roster schema mismatch")
    _assert_binding(roster, expected, "expected G08 roster")
    core = {key: value for key, value in roster.items() if key != "content_sha256"}
    if roster["content_sha256"] != canonical_sha256(core):
        _fail("INVALID_ROSTER", "expected G08 roster content hash mismatch")
    rows = roster["selected_archives"]
    if type(rows) is not list or not rows:
        _fail("INVALID_ROSTER", "expected G08 roster must select archives")
    result: dict[str, str] = {}
    prior = ""
    for row in rows:
        item = _exact(row, _ROSTER_ROW_FIELDS, "expected G08 roster row", "INVALID_ROSTER")
        family = _identifier(item["family_id"], "family_id", "INVALID_ROSTER")
        archive = _sha256(item["archive_sha256"], "archive_sha256", "INVALID_ROSTER")
        if archive <= prior:
            _fail("INVALID_ROSTER", "expected G08 roster archives must be uniquely sorted")
        prior = archive
        if archive in result or family in result.values():
            _fail("INVALID_ROSTER", "expected G08 roster contains archive or family aliases")
        result[archive] = family
    return result, digest


def _validate_activation_rule(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time_utc: str,
) -> tuple[dict[str, Any], str]:
    parsed, _, digest = _canonical_json_evidence(evidence, "activation_rule")
    if type(parsed) is not dict:
        _fail("INVALID_ACTIVATION_RULE", "activation rule must be a signed envelope")
    rule, _ = _verify_source_envelope(
        parsed,
        schema=G09_ACTIVATION_RULE_SCHEMA,
        fields=_ACTIVATION_RULE_FIELDS,
        registry=registry,
        expected=expected,
        expected_role="registrar",
        timestamp_field="issued_at_utc",
        label="activation rule",
    )
    if rule["schema"] != G09_ACTIVATION_RULE_SCHEMA:
        _fail("INVALID_ACTIVATION_RULE", "activation rule schema mismatch")
    _assert_binding(rule, expected, "activation rule")
    _utc_text(rule["activation_time_utc"], "activation_time_utc", "INVALID_ACTIVATION_RULE")
    if rule["activation_time_utc"] != activation_time_utc:
        _fail("ACTIVATION_TIME_MISMATCH", "activation rule does not bind the requested activation time")
    if rule["rule_id"] != "G09_BLIND_ACTIVATION_TIME_V1":
        _fail("INVALID_ACTIVATION_RULE", "activation rule_id is not frozen G09 rule")
    if rule["require_no_pre_activation_quorum"] is not True or rule[
        "require_no_pre_activation_plaintext_or_access"
    ] is not True:
        _fail("INVALID_ACTIVATION_RULE", "activation rule weakens a required fail-closed control")
    if _utc(rule["issued_at_utc"], "activation rule issued_at_utc", "INVALID_ACTIVATION_RULE") >= _utc(
        activation_time_utc, "activation_time_utc", "INVALID_ACTIVATION_RULE"
    ):
        _fail("INVALID_CHRONOLOGY", "activation rule was not issued before activation")
    for field in (
        "common_v2_dependencies_sha256",
        "threshold_policy_sha256",
        "blind_commitment_set_root_sha256",
        "log_genesis_root_sha256",
        "recipient_private_key_reveal_commitment_sha256",
        "activation_trigger_commitment_sha256",
    ):
        _sha256(rule[field], field, "INVALID_ACTIVATION_RULE")
    core = {key: value for key, value in rule.items() if key != "content_sha256"}
    if rule["content_sha256"] != canonical_sha256(core):
        _fail("INVALID_ACTIVATION_RULE", "activation rule content hash mismatch")
    return rule, digest


def _validate_policy(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
    activation_time_utc: str,
) -> tuple[dict[str, Any], str, bytes, dict[int, dict[str, Any]]]:
    parsed, _, digest = _canonical_json_evidence(evidence, "threshold_public_key_policy")
    if type(parsed) is not dict:
        _fail("INVALID_THRESHOLD_POLICY", "threshold policy must be a signed envelope")
    record, envelope_hash = _verify_source_envelope(
        parsed,
        schema=G09_THRESHOLD_POLICY_SCHEMA,
        fields=_POLICY_FIELDS,
        registry=registry,
        expected=expected,
        expected_role="registrar",
        timestamp_field="issued_at_utc",
        label="threshold policy",
    )
    if record["schema"] != G09_THRESHOLD_POLICY_SCHEMA:
        _fail("INVALID_THRESHOLD_POLICY", "threshold policy payload schema mismatch")
    if record["activation_time_utc"] != activation_time_utc:
        _fail("ACTIVATION_TIME_MISMATCH", "threshold policy activation time mismatch")
    if _utc(record["issued_at_utc"], "threshold policy issued_at_utc", "INVALID_THRESHOLD_POLICY") >= activation_time:
        _fail("INVALID_CHRONOLOGY", "threshold policy was not issued before activation")
    if record["scheme"] != THRESHOLD_SCHEME:
        _fail("UNSUPPORTED_THRESHOLD_SCHEME", "threshold policy scheme is not pinned")
    threshold = record["threshold"]
    if type(threshold) is not int or not 2 <= threshold <= 255:
        _fail("INVALID_THRESHOLD_POLICY", "threshold policy threshold must be in 2..255")
    recipient = _canonical_b64(
        record["activation_recipient_public_key_base64"],
        "activation recipient public key",
        "INVALID_THRESHOLD_POLICY",
        length=32,
    )
    try:
        X25519PublicKey.from_public_bytes(recipient)
    except ValueError as exc:
        raise BlindActivationError("INVALID_THRESHOLD_POLICY", "activation recipient key is invalid") from exc
    _sha256(
        record["activation_recipient_private_key_reveal_commitment_sha256"],
        "activation recipient private-key reveal commitment",
        "INVALID_THRESHOLD_POLICY",
    )
    core = {key: value for key, value in record.items() if key != "content_sha256"}
    if record["content_sha256"] != canonical_sha256(core):
        _fail("INVALID_THRESHOLD_POLICY", "threshold policy content hash mismatch")
    shares = record["share_commitments"]
    if type(shares) is not list or len(shares) < threshold:
        _fail("INVALID_THRESHOLD_POLICY", "threshold policy has insufficient committed shares")
    commitments: dict[int, dict[str, Any]] = {}
    prior = 0
    roles: set[str] = set()
    for row in shares:
        item = _exact(row, _SHARE_COMMITMENT_FIELDS, "share commitment", "INVALID_THRESHOLD_POLICY")
        role = _identifier(item["custodian_role"], "custodian_role", "INVALID_THRESHOLD_POLICY")
        index = item["share_index"]
        if type(index) is not int or not 1 <= index <= 255 or index <= prior:
            _fail("INVALID_THRESHOLD_POLICY", "share commitments must be uniquely index-sorted")
        prior = index
        if not role.startswith("custodian_") or role not in registry or role in roles:
            _fail("INVALID_THRESHOLD_POLICY", "share commitment custodian roles must be registered and unique")
        roles.add(role)
        commitments[index] = {
            "custodian_role": role,
            "share_index": index,
            "share_commitment_sha256": _sha256(
                item["share_commitment_sha256"], "share_commitment_sha256", "INVALID_THRESHOLD_POLICY"
            ),
        }
    return record, envelope_hash, recipient, commitments


def _verify_dual_source_records(
    evidence: object,
    *,
    schema: str,
    fields: frozenset[str],
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    timestamp_field: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, str], str]:
    envelopes, digest = _canonical_envelope_list(evidence, label)
    if len(envelopes) != 2:
        _fail("MISSING_DUAL_CLOSE", f"{label} requires exactly two independent signatures")
    records: dict[str, dict[str, Any]] = {}
    hashes: dict[str, str] = {}
    for envelope in envelopes:
        untrusted = envelope.get("payload")
        role = untrusted.get("role") if type(untrusted) is dict else None
        if (
            type(role) is not str
            or role not in {"activation_service", "evidence_custodian"}
            or role in records
        ):
            _fail("WRONG_ROLE", f"{label} requires activation_service and evidence_custodian")
        record, envelope_hash = _verify_source_envelope(
            envelope,
            schema=schema,
            fields=fields,
            registry=registry,
            expected=expected,
            expected_role=role,
            timestamp_field=timestamp_field,
            label=label,
        )
        records[role] = record
        hashes[role] = envelope_hash
    left = {key: value for key, value in records["activation_service"].items() if key not in {"role", "key_id"}}
    right = {key: value for key, value in records["evidence_custodian"].items() if key not in {"role", "key_id"}}
    if left != right:
        _fail("DUAL_SIGNATURE_MISMATCH", f"{label} signatures do not bind the same exact core")
    return records["activation_service"], hashes, digest


def _validate_log_receipts(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
) -> tuple[dict[str, tuple[dict[str, Any], str, dict[str, Any]]], str]:
    envelopes, digest = _canonical_envelope_list(evidence, "worm_publication_receipts")
    if len(envelopes) != 3:
        _fail(
            "MISSING_LOG_RECEIPT",
            "exact genesis, preactivation, and terminal WORM publication receipts are required",
        )
    receipts: dict[str, tuple[dict[str, Any], str, dict[str, Any]]] = {}
    for envelope in envelopes:
        record, envelope_hash = _verify_source_envelope(
            envelope,
            schema=G09_LOG_RECEIPT_SCHEMA,
            fields=_LOG_RECEIPT_FIELDS,
            registry=registry,
            expected=expected,
            expected_role="evidence_custodian",
            timestamp_field="published_at_utc",
            label="WORM publication receipt",
        )
        phase = record["phase"]
        if (
            type(phase) is not str
            or phase not in {"GENESIS", "PREACTIVATION", "TERMINAL"}
            or phase in receipts
        ):
            _fail(
                "INVALID_LOG_RECEIPT",
                "WORM receipts must contain unique genesis, preactivation, and terminal phases",
            )
        _identifier(record["log_id"], "log_id", "INVALID_LOG_RECEIPT")
        for field in (
            "prior_receipt_envelope_sha256",
            "causal_predecessor_root_sha256",
            "activation_trigger_envelope_sha256",
            "blind_commitment_set_root_sha256",
            "last_event_envelope_sha256",
            "event_hashes_root_sha256",
            "worm_object_root_sha256",
        ):
            _sha256(record[field], field, "INVALID_LOG_RECEIPT")
        for field in (
            "first_sequence",
            "next_sequence",
            "range_start_sequence",
            "range_end_sequence_exclusive",
            "event_count",
        ):
            if type(record[field]) is not int or record[field] < 0:
                _fail("INVALID_LOG_RECEIPT", f"{field} must be a nonnegative integer")
        _identifier(record["cursor_start"], "cursor_start", "INVALID_LOG_RECEIPT")
        _identifier(record["cursor_end"], "cursor_end", "INVALID_LOG_RECEIPT")
        try:
            publication_raw = _decode_byte_evidence(
                record["publication_receipt"],
                expected_media_type=G09_WORM_PUBLICATION_MEDIA_TYPE,
            )
            publication_envelope = json.loads(
                publication_raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs
            )
        except (BlindActivationError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise BlindActivationError(
                "INVALID_LOG_RECEIPT", "WORM publication receipt bytes are invalid"
            ) from exc
        try:
            if canonical_json_bytes(publication_envelope) != publication_raw:
                _fail(
                    "NONCANONICAL_JSON",
                    "WORM publication receipt bytes are not canonical JSON",
                )
        except BlindActivationError:
            raise
        except Exception as exc:
            raise BlindActivationError(
                "NONCANONICAL_JSON",
                "WORM publication receipt bytes are not canonical JSON",
            ) from exc
        publication, publication_hash = _verify_source_envelope(
            publication_envelope,
            schema=G09_WORM_PROVIDER_RECEIPT_SCHEMA,
            fields=_WORM_PUBLICATION_FIELDS,
            registry=registry,
            expected=expected,
            expected_role="worm_publication_service",
            timestamp_field="published_at_utc",
            label="WORM provider receipt",
        )
        if publication_hash != record["publication_receipt"]["sha256"]:
            _fail(
                "LOG_RECEIPT_MISMATCH",
                "WORM provider envelope hash does not match its raw byte wrapper",
            )
        for field in (
            "log_id",
            "phase",
            "first_sequence",
            "next_sequence",
            "cursor_start",
            "cursor_end",
            "range_start_sequence",
            "range_end_sequence_exclusive",
            "event_count",
            "last_event_envelope_sha256",
            "event_hashes_root_sha256",
            "worm_object_root_sha256",
            "causal_predecessor_root_sha256",
            "activation_trigger_envelope_sha256",
            "blind_commitment_set_root_sha256",
            "published_at_utc",
        ):
            if publication[field] != record[field]:
                _fail(
                    "LOG_RECEIPT_MISMATCH",
                    f"signed receipt and raw WORM publication disagree on {field}",
                )
        _identifier(publication["provider"], "WORM provider", "INVALID_LOG_RECEIPT")
        _identifier(
            publication["immutable_object_id"],
            "WORM immutable_object_id",
            "INVALID_LOG_RECEIPT",
        )
        if publication["retention_mode"] != "COMPLIANCE_WORM":
            _fail("INVALID_LOG_RECEIPT", "publication is not a compliance-mode WORM receipt")
        if type(publication["generation"]) is not int or publication["generation"] < 0:
            _fail("INVALID_LOG_RECEIPT", "WORM publication generation is invalid")
        _sha256(
            publication["prior_publication_receipt_sha256"],
            "prior WORM publication receipt",
            "INVALID_LOG_RECEIPT",
        )
        published = _utc(record["published_at_utc"], "receipt published_at_utc", "INVALID_LOG_RECEIPT")
        if phase == "GENESIS" and published >= activation_time:
            _fail("INVALID_CHRONOLOGY", "genesis WORM receipt was not published before activation")
        if phase == "PREACTIVATION" and published != activation_time:
            _fail(
                "ACTIVATION_TIME_MISMATCH",
                "preactivation WORM snapshot was not published at the exact signed trigger",
            )
        if phase == "TERMINAL" and published < activation_time:
            _fail("INVALID_CHRONOLOGY", "terminal WORM receipt predates activation")
        receipts[phase] = (record, envelope_hash, publication)

    genesis = receipts["GENESIS"]
    preactivation = receipts["PREACTIVATION"]
    terminal = receipts["TERMINAL"]
    provider_object = {
        (item[2]["provider"], item[2]["immutable_object_id"]) for item in receipts.values()
    }
    if len(provider_object) != 1:
        _fail("LOG_RESET_OR_PREFIX_OMISSION", "WORM receipts do not address one immutable object")
    if len(
        {
            item[0]["blind_commitment_set_root_sha256"]
            for item in receipts.values()
        }
    ) != 1:
        _fail(
            "LOG_RESET_OR_PREFIX_OMISSION",
            "WORM receipt chain does not preserve one blinded commitment root",
        )
    expected_chain = (
        (genesis, 0, _ZERO_HASH, _ZERO_HASH),
        (
            preactivation,
            1,
            genesis[1],
            genesis[0]["publication_receipt"]["sha256"],
        ),
        (
            terminal,
            2,
            preactivation[1],
            preactivation[0]["publication_receipt"]["sha256"],
        ),
    )
    for item, generation, prior_envelope, prior_publication in expected_chain:
        record, _, publication = item
        if (
            publication["generation"] != generation
            or record["prior_receipt_envelope_sha256"] != prior_envelope
            or publication["prior_publication_receipt_sha256"] != prior_publication
        ):
            _fail(
                "LOG_RESET_OR_PREFIX_OMISSION",
                "WORM receipt generation or causal predecessor chain is broken",
            )
    return receipts, digest


def _validate_log_genesis(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
    activation_time_utc: str,
    dependencies_sha256: str,
    threshold_policy_sha256: str,
    blind_commitment_set_root_sha256: str,
    recipient_commitment_sha256: str,
    genesis_receipt: tuple[Mapping[str, Any], str, Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, str], str]:
    record, signatures, digest = _verify_dual_source_records(
        evidence,
        schema=G09_LOG_GENESIS_SCHEMA,
        fields=_LOG_GENESIS_FIELDS,
        registry=registry,
        expected=expected,
        timestamp_field="committed_at_utc",
        label="log genesis",
    )
    receipt, receipt_hash, _ = genesis_receipt
    if record["common_v2_dependencies_sha256"] != dependencies_sha256:
        _fail("V2_DEPENDENCY_MISMATCH", "log genesis does not bind common v2 dependencies")
    if record["threshold_policy_sha256"] != threshold_policy_sha256:
        _fail("POLICY_MISMATCH", "log genesis does not bind threshold policy")
    if record["blind_commitment_set_root_sha256"] != blind_commitment_set_root_sha256:
        _fail(
            "BLIND_COMMITMENT_SET_MISMATCH",
            "log genesis does not bind exact blinded commitment evidence",
        )
    if record["activation_time_utc"] != activation_time_utc:
        _fail("ACTIVATION_TIME_MISMATCH", "log genesis activation time mismatch")
    if record["recipient_private_key_reveal_commitment_sha256"] != recipient_commitment_sha256:
        _fail("RECIPIENT_KEY_COMMITMENT_MISMATCH", "log genesis does not bind recipient-key commitment")
    if record["genesis_receipt_envelope_sha256"] != receipt_hash:
        _fail("LOG_RECEIPT_MISMATCH", "log genesis does not bind genesis WORM receipt")
    _nonnegative_int(
        record["first_sequence"], "genesis first_sequence", "INVALID_LOG_GENESIS"
    )
    _nonnegative_int(
        record["range_start_sequence"],
        "genesis range_start_sequence",
        "INVALID_LOG_GENESIS",
    )
    if (
        record["first_sequence"] != 0
        or record["range_start_sequence"] != 0
        or record["cursor_start"] != "cursor-0"
        or record["previous_event_sha256"] != _ZERO_HASH
    ):
        _fail("INVALID_LOG_GENESIS", "log genesis does not freeze the exact zero-based range")
    if (
        receipt["phase"] != "GENESIS"
        or receipt["log_id"] != record["log_id"]
        or receipt["first_sequence"] != 0
        or receipt["next_sequence"] != 0
        or receipt["range_start_sequence"] != 0
        or receipt["range_end_sequence_exclusive"] != 0
        or receipt["event_count"] != 0
        or receipt["cursor_start"] != "cursor-0"
        or receipt["cursor_end"] != "cursor-0"
        or receipt["prior_receipt_envelope_sha256"] != _ZERO_HASH
        or receipt["causal_predecessor_root_sha256"] != _ZERO_HASH
        or receipt["activation_trigger_envelope_sha256"] != _ZERO_HASH
        or receipt["blind_commitment_set_root_sha256"]
        != blind_commitment_set_root_sha256
        or receipt["last_event_envelope_sha256"] != _ZERO_HASH
        or receipt["event_hashes_root_sha256"] != derive_log_event_hashes_root([])
        or receipt["worm_object_root_sha256"]
        != derive_log_worm_root(
            log_id=record["log_id"],
            causal_predecessor_root_sha256=_ZERO_HASH,
            event_hashes=[],
        )
    ):
        _fail("INVALID_LOG_RECEIPT", "genesis WORM receipt is not the exact empty log range")
    committed = _utc(record["committed_at_utc"], "genesis committed_at_utc", "INVALID_LOG_GENESIS")
    if committed >= activation_time:
        _fail("INVALID_CHRONOLOGY", "log genesis was not committed before activation")
    derived = derive_log_genesis_root(
        expected=expected,
        common_v2_dependencies_sha256=dependencies_sha256,
        threshold_policy_sha256=threshold_policy_sha256,
        blind_commitment_set_root_sha256=blind_commitment_set_root_sha256,
        activation_time_utc=activation_time_utc,
        log_id=record["log_id"],
        first_sequence=record["first_sequence"],
        cursor_start=record["cursor_start"],
        range_start_sequence=record["range_start_sequence"],
        previous_event_sha256=record["previous_event_sha256"],
        genesis_receipt_envelope_sha256=receipt_hash,
        recipient_private_key_reveal_commitment_sha256=recipient_commitment_sha256,
        committed_at_utc=record["committed_at_utc"],
    )
    if record["genesis_root_sha256"] != derived:
        _fail("INVALID_LOG_GENESIS", "log genesis root does not recompute")
    return record, signatures, digest


def _validate_activation_trigger(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time_utc: str,
    activation_rule_sha256: str,
    activation_rule: Mapping[str, Any],
    dependencies_sha256: str,
    threshold_policy_sha256: str,
    blind_commitment_set_root_sha256: str,
    log_genesis_root_sha256: str,
    recipient_commitment_sha256: str,
) -> tuple[dict[str, Any], str, str]:
    parsed, _, digest = _canonical_json_evidence(evidence, "activation_trigger")
    if type(parsed) is not dict:
        _fail("INVALID_ACTIVATION_TRIGGER", "activation trigger must be a signed envelope")
    record, envelope_hash = _verify_source_envelope(
        parsed,
        schema=G09_ACTIVATION_TRIGGER_SCHEMA,
        fields=_ACTIVATION_TRIGGER_FIELDS,
        registry=registry,
        expected=expected,
        expected_role="activation_service",
        timestamp_field="triggered_at_utc",
        label="activation trigger",
    )
    if record["triggered_at_utc"] != activation_time_utc:
        _fail("ACTIVATION_TIME_MISMATCH", "signed trigger is not at the exact frozen activation time")
    required = {
        "activation_rule_sha256": activation_rule_sha256,
        "common_v2_dependencies_sha256": dependencies_sha256,
        "threshold_policy_sha256": threshold_policy_sha256,
        "blind_commitment_set_root_sha256": blind_commitment_set_root_sha256,
        "log_genesis_root_sha256": log_genesis_root_sha256,
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment_sha256,
    }
    for field, value in required.items():
        if record[field] != value:
            _fail("ACTIVATION_TRIGGER_MISMATCH", f"activation trigger does not bind {field}")
    try:
        nonce = _decode_byte_evidence(
            record["trigger_release_nonce"], expected_media_type="application/octet-stream"
        )
    except BlindActivationError as exc:
        raise BlindActivationError("INVALID_ACTIVATION_TRIGGER", str(exc)) from exc
    derived = derive_activation_trigger_commitment(
        expected=expected,
        common_v2_dependencies_sha256=dependencies_sha256,
        threshold_policy_sha256=threshold_policy_sha256,
        log_genesis_root_sha256=log_genesis_root_sha256,
        recipient_private_key_reveal_commitment_sha256=recipient_commitment_sha256,
        trigger_id=record["trigger_id"],
        trigger_release_nonce=nonce,
        triggered_at_utc=record["triggered_at_utc"],
    )
    if record["activation_trigger_commitment_sha256"] != derived or activation_rule[
        "activation_trigger_commitment_sha256"
    ] != derived:
        _fail("ACTIVATION_TRIGGER_COMMITMENT_MISMATCH", "signed trigger does not satisfy frozen commitment")
    return record, envelope_hash, digest


def _validate_preactivation_receipt(
    receipt: tuple[Mapping[str, Any], str, Mapping[str, Any]],
    *,
    genesis_receipt_envelope_sha256: str,
    log_id: str,
    log_genesis_root_sha256: str,
    activation_trigger_envelope_sha256: str,
    blind_commitment_set_root_sha256: str,
    activation_time_utc: str,
) -> tuple[Mapping[str, Any], str]:
    record, envelope_hash, _ = receipt
    if (
        record["phase"] != "PREACTIVATION"
        or record["log_id"] != log_id
        or record["prior_receipt_envelope_sha256"]
        != genesis_receipt_envelope_sha256
        or record["causal_predecessor_root_sha256"]
        != log_genesis_root_sha256
        or record["activation_trigger_envelope_sha256"]
        != activation_trigger_envelope_sha256
        or record["blind_commitment_set_root_sha256"]
        != blind_commitment_set_root_sha256
        or record["first_sequence"] != 0
        or record["next_sequence"] != 0
        or record["range_start_sequence"] != 0
        or record["range_end_sequence_exclusive"] != 0
        or record["event_count"] != 0
        or record["cursor_start"] != "cursor-0"
        or record["cursor_end"] != "cursor-0"
        or record["last_event_envelope_sha256"] != _ZERO_HASH
        or record["event_hashes_root_sha256"] != derive_log_event_hashes_root([])
        or record["worm_object_root_sha256"]
        != derive_log_worm_root(
            log_id=log_id,
            causal_predecessor_root_sha256=log_genesis_root_sha256,
            event_hashes=[],
        )
    ):
        _fail(
            "LOG_RESET_OR_PREFIX_OMISSION",
            "preactivation WORM snapshot is not the exact committed zero-access range",
        )
    if record["published_at_utc"] != activation_time_utc:
        _fail(
            "ACTIVATION_TIME_MISMATCH",
            "preactivation WORM snapshot is not at the signed trigger",
        )
    return record, envelope_hash


def _validate_log_close(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    close_kind: str,
    log_id: str,
    log_genesis_root_sha256: str,
    activation_trigger_envelope_sha256: str,
    predecessor_close_root_sha256: str,
    worm_receipt_envelope_sha256: str,
    first_sequence: int,
    next_sequence: int,
    cursor_start: str,
    cursor_end: str,
    event_hashes: Sequence[str],
    last_event_envelope_sha256: str,
    exact_close_time_utc: str | None,
) -> tuple[dict[str, Any], dict[str, str], str]:
    record, signatures, digest = _verify_dual_source_records(
        evidence,
        schema=G09_LOG_CLOSE_SCHEMA,
        fields=_LOG_CLOSE_FIELDS,
        registry=registry,
        expected=expected,
        timestamp_field="closed_at_utc",
        label=f"{close_kind} log close",
    )
    for field in (
        "first_sequence",
        "next_sequence",
        "range_start_sequence",
        "range_end_sequence_exclusive",
        "event_count",
    ):
        _nonnegative_int(record[field], f"log close {field}", "INVALID_LOG_CLOSE")
    event_root = derive_log_event_hashes_root(event_hashes)
    required = {
        "close_kind": close_kind,
        "log_id": log_id,
        "log_genesis_root_sha256": log_genesis_root_sha256,
        "activation_trigger_envelope_sha256": activation_trigger_envelope_sha256,
        "predecessor_close_root_sha256": predecessor_close_root_sha256,
        "worm_receipt_envelope_sha256": worm_receipt_envelope_sha256,
        "first_sequence": first_sequence,
        "next_sequence": next_sequence,
        "cursor_start": cursor_start,
        "cursor_end": cursor_end,
        "range_start_sequence": first_sequence,
        "range_end_sequence_exclusive": next_sequence,
        "event_count": len(event_hashes),
        "last_event_envelope_sha256": last_event_envelope_sha256,
        "event_hashes_root_sha256": event_root,
    }
    for field, value in required.items():
        if record[field] != value:
            _fail("LOG_CLOSE_MISMATCH", f"{close_kind} close does not bind exact {field}")
    if exact_close_time_utc is not None and record["closed_at_utc"] != exact_close_time_utc:
        _fail("ACTIVATION_TIME_MISMATCH", "preactivation zero-access close is not at exact trigger")
    derived = derive_log_close_root(
        expected=expected,
        close_kind=close_kind,
        log_id=log_id,
        log_genesis_root_sha256=log_genesis_root_sha256,
        activation_trigger_envelope_sha256=activation_trigger_envelope_sha256,
        predecessor_close_root_sha256=predecessor_close_root_sha256,
        worm_receipt_envelope_sha256=worm_receipt_envelope_sha256,
        first_sequence=first_sequence,
        next_sequence=next_sequence,
        cursor_start=cursor_start,
        cursor_end=cursor_end,
        range_start_sequence=first_sequence,
        range_end_sequence_exclusive=next_sequence,
        event_count=len(event_hashes),
        last_event_envelope_sha256=last_event_envelope_sha256,
        event_hashes_root_sha256=event_root,
        closed_at_utc=record["closed_at_utc"],
    )
    if record["close_root_sha256"] != derived:
        _fail("LOG_CLOSE_MISMATCH", f"{close_kind} close root does not recompute")
    return record, signatures, digest


def _validate_recipient_key_reveal(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
    threshold_policy_sha256: str,
    policy: Mapping[str, Any],
    recipient_public_key: bytes,
    activation_trigger_envelope_sha256: str,
    preactivation_close_root_sha256: str,
) -> tuple[dict[str, Any], bytes, str, str]:
    parsed, _, digest = _canonical_json_evidence(evidence, "recipient_key_reveal")
    if type(parsed) is not dict:
        _fail("INVALID_RECIPIENT_KEY_REVEAL", "recipient-key reveal must be a signed envelope")
    record, envelope_hash = _verify_source_envelope(
        parsed,
        schema=G09_RECIPIENT_KEY_REVEAL_SCHEMA,
        fields=_RECIPIENT_KEY_REVEAL_FIELDS,
        registry=registry,
        expected=expected,
        expected_role="activation_service",
        timestamp_field="revealed_at_utc",
        label="recipient-key reveal",
    )
    if record["threshold_policy_sha256"] != threshold_policy_sha256:
        _fail("POLICY_MISMATCH", "recipient-key reveal does not bind threshold policy")
    if record["activation_trigger_envelope_sha256"] != activation_trigger_envelope_sha256:
        _fail("ACTIVATION_TRIGGER_MISMATCH", "recipient-key reveal does not bind activation trigger")
    if record["preactivation_close_root_sha256"] != preactivation_close_root_sha256:
        _fail("LOG_CLOSE_MISMATCH", "recipient-key reveal does not bind zero-access close")
    _postactivation(
        record["revealed_at_utc"],
        label="recipient-key reveal",
        activation=activation_time,
        code="EARLY_RECIPIENT_KEY_REVEAL",
    )
    private_key = _decode_byte_evidence(
        record["activation_recipient_private_key"],
        expected_media_type="application/octet-stream",
    )
    commitment = derive_recipient_private_key_reveal_commitment(
        **expected,
        policy_id=policy["policy_id"],
        activation_recipient_private_key=private_key,
    )
    if commitment != record["recipient_private_key_reveal_commitment_sha256"] or commitment != policy[
        "activation_recipient_private_key_reveal_commitment_sha256"
    ]:
        _fail("RECIPIENT_KEY_COMMITMENT_MISMATCH", "recipient private-key reveal does not satisfy commitment")
    try:
        actual_public = X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()
    except ValueError as exc:
        raise BlindActivationError("INVALID_RECIPIENT_KEY_REVEAL", "recipient private key is invalid") from exc
    if actual_public != recipient_public_key:
        _fail("ACTIVATION_PRIVATE_KEY_MISMATCH", "recipient private-key reveal does not match policy public key")
    return record, private_key, envelope_hash, digest


def _preactivation(value: object, *, label: str, activation: datetime) -> str:
    text = _utc_text(value, label, "INVALID_CHRONOLOGY")
    if _utc(text, label, "INVALID_CHRONOLOGY") >= activation:
        _fail("INVALID_CHRONOLOGY", f"{label} must be before activation")
    return text


def _postactivation(value: object, *, label: str, activation: datetime, code: str = "EARLY_ACCESS") -> str:
    text = _utc_text(value, label, "INVALID_CHRONOLOGY")
    if _utc(text, label, "INVALID_CHRONOLOGY") < activation:
        _fail(code, f"{label} predates activation")
    return text


def _validate_commitment_records(
    evidence: object,
    *,
    schema: str,
    fields: frozenset[str],
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    roster: Mapping[str, str],
    activation_time: datetime,
    label: str,
) -> tuple[dict[str, dict[str, Any]], str]:
    envelopes, digest = _canonical_envelope_list(evidence, label)
    by_archive: dict[str, dict[str, Any]] = {}
    for envelope in envelopes:
        record, _ = _verify_source_envelope(
            envelope,
            schema=schema,
            fields=fields,
            registry=registry,
            expected=expected,
            expected_role="registrar",
            timestamp_field="committed_at_utc",
            label=label,
        )
        archive = _sha256(record["archive_sha256"], "archive_sha256", "INVALID_COMMITMENT")
        family = _identifier(record["family_id"], "family_id", "INVALID_COMMITMENT")
        if roster.get(archive) != family:
            _fail("ROSTER_SET_MISMATCH", f"{label} has an extra, omitted, or aliased archive")
        if record["package_sha256"] != archive:
            _fail("PACKAGE_REPLACEMENT", f"{label} package hash does not equal its selected archive hash")
        if archive in by_archive:
            _fail("DUPLICATE_ARCHIVE", f"{label} has duplicate archive evidence")
        _preactivation(record["committed_at_utc"], label=f"{label} committed_at_utc", activation=activation_time)
        by_archive[archive] = record
    if set(by_archive) != set(roster):
        _fail("ROSTER_SET_MISMATCH", f"{label} is not exact G08 roster set")
    return by_archive, digest


def _validate_nonce_reveals(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    roster: Mapping[str, str],
    activation_time: datetime,
    nonce_commitments: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, tuple[dict[str, Any], bytes, str]], str]:
    envelopes, digest = _canonical_envelope_list(evidence, "nonce_reveals")
    results: dict[str, tuple[dict[str, Any], bytes, str]] = {}
    for envelope in envelopes:
        record, envelope_hash = _verify_source_envelope(
            envelope,
            schema=G09_NONCE_REVEAL_SCHEMA,
            fields=_NONCE_REVEAL_FIELDS,
            registry=registry,
            expected=expected,
            expected_role="registrar",
            timestamp_field="revealed_at_utc",
            label="nonce reveal",
        )
        archive = _sha256(record["archive_sha256"], "archive_sha256", "INVALID_NONCE")
        family = _identifier(record["family_id"], "family_id", "INVALID_NONCE")
        if roster.get(archive) != family or archive in results:
            _fail("ROSTER_SET_MISMATCH", "nonce reveals are not an exact selected archive set")
        if record["package_sha256"] != archive:
            _fail("PACKAGE_REPLACEMENT", "nonce reveal package hash does not match selected archive")
        _postactivation(
            record["revealed_at_utc"],
            label="nonce reveal",
            activation=activation_time,
            code="EARLY_NONCE_REVEAL",
        )
        try:
            nonce = _decode_byte_evidence(record["nonce"], expected_media_type="application/octet-stream")
        except Exception as exc:
            raise BlindActivationError("INVALID_NONCE", f"nonce reveal is invalid: {exc}") from exc
        if len(nonce) != 12:
            _fail("INVALID_NONCE", "revealed package nonce must be 12 bytes")
        commitment = nonce_commitments[archive]
        expected_commitment = derive_nonce_commitment(
            **expected,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
            nonce=nonce,
        )
        if commitment["nonce_commitment_sha256"] != expected_commitment:
            _fail("BAD_NONCE_REVEAL", "nonce reveal does not satisfy its committed nonce")
        results[archive] = (record, nonce, envelope_hash)
    if set(results) != set(roster):
        _fail("ROSTER_SET_MISMATCH", "nonce reveals are not exact G08 roster set")
    return results, digest


def _validate_packages(
    package_bytes: object,
    *,
    roster: Mapping[str, str],
) -> tuple[dict[str, bytes], dict[str, str]]:
    if type(package_bytes) is not dict:
        _fail("INVALID_PACKAGE_EVIDENCE", "package_bytes must map selected archive hashes to byte wrappers")
    if set(package_bytes) != set(roster):
        _fail("ROSTER_SET_MISMATCH", "package bytes have an extra, missing, or aliased archive")
    packages: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    for archive in sorted(roster):
        try:
            raw = _decode_byte_evidence(package_bytes[archive], expected_media_type="application/octet-stream")
        except Exception as exc:
            raise BlindActivationError("INVALID_PACKAGE_EVIDENCE", f"package {archive}: {exc}") from exc
        if hashlib.sha256(raw).hexdigest() != archive:
            _fail("PACKAGE_HASH_MISMATCH", "exact package bytes do not hash to selected archive")
        packages[archive] = raw
        digests[archive] = hashlib.sha256(raw).hexdigest()
    return packages, digests


def _decode_share_release(
    record: Mapping[str, Any],
    *,
    recipient_private_key: bytes,
    expected: Mapping[str, str],
) -> bytes:
    if type(recipient_private_key) is not bytes or len(recipient_private_key) != 32:
        _fail("ACTIVATION_PRIVATE_KEY_REQUIRED", "activation private key must be exactly 32 bytes after activation")
    try:
        nonce = _decode_byte_evidence(record["seal_nonce"], expected_media_type="application/octet-stream")
        ciphertext = _decode_byte_evidence(record["sealed_share"], expected_media_type="application/octet-stream")
    except Exception as exc:
        raise BlindActivationError("INVALID_SHARE_RELEASE", f"sealed share evidence is invalid: {exc}") from exc
    if len(nonce) != 12 or len(ciphertext) < 16:
        _fail("INVALID_SHARE_RELEASE", "sealed share nonce or ciphertext length is invalid")
    ephemeral_public = _canonical_b64(
        record["ephemeral_public_key_base64"], "ephemeral public key", "INVALID_SHARE_RELEASE", length=32
    )
    aad = derive_share_seal_aad(
        **expected,
        threshold_policy_sha256=record["threshold_policy_sha256"],
        custodian_role=record["custodian_role"],
        share_index=record["share_index"],
        share_commitment_sha256=record["share_commitment_sha256"],
    )
    try:
        private = X25519PrivateKey.from_private_bytes(recipient_private_key)
        shared = private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"G09/SHARE_SEAL/v1\0" + aad).derive(shared)
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise BlindActivationError("SHARE_DECRYPTION_FAILED", "sealed threshold share cannot be decrypted") from exc


def _validate_share_release_records(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
    threshold_policy_sha256: str,
    policy: Mapping[str, Any],
    policy_commitments: Mapping[int, Mapping[str, Any]],
) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]], str]:
    envelopes, digest = _canonical_envelope_list(evidence, "key_share_releases")
    releases: dict[int, dict[str, Any]] = {}
    records_by_envelope: dict[str, dict[str, Any]] = {}
    for envelope in envelopes:
        record, envelope_hash = _verify_source_envelope(
            envelope,
            schema=G09_SHARE_RELEASE_SCHEMA,
            fields=_SHARE_RELEASE_FIELDS,
            registry=registry,
            expected=expected,
            expected_role="custodian",
            timestamp_field="released_at_utc",
            label="key share release",
        )
        _postactivation(
            record["released_at_utc"],
            label="key share release",
            activation=activation_time,
            code="EARLY_SHARE_RELEASE",
        )
        if record["threshold_policy_sha256"] != threshold_policy_sha256:
            _fail("POLICY_MISMATCH", "key share release does not bind threshold policy")
        index = record["share_index"]
        if type(index) is not int:
            _fail(
                "DUPLICATE_SHARE",
                "key share release index is missing, duplicate, or uncommitted",
            )
        commitment = policy_commitments.get(index)
        if commitment is None or index in releases:
            _fail("DUPLICATE_SHARE", "key share release index is missing, duplicate, or uncommitted")
        if record["custodian_role"] != commitment["custodian_role"] or record["role"] != commitment["custodian_role"]:
            _fail("WRONG_ROLE", "key share release signer is not its committed custodian")
        if record["share_commitment_sha256"] != commitment["share_commitment_sha256"]:
            _fail("SHARE_COMMITMENT_MISMATCH", "key share release commitment mismatch")
        releases[index] = record
        records_by_envelope[envelope_hash] = record
    threshold = policy["threshold"]
    if len(releases) < threshold:
        _fail("INSUFFICIENT_SHARES", "no threshold quorum was released after activation")
    return releases, records_by_envelope, digest


def _decrypt_share_release_records(
    releases: Mapping[int, Mapping[str, Any]],
    *,
    recipient_private_key: bytes,
    recipient_public_key: bytes,
    expected: Mapping[str, str],
    policy: Mapping[str, Any],
) -> list[tuple[int, bytes]]:
    shares: list[tuple[int, bytes]] = []
    for index in sorted(releases):
        record = releases[index]
        share = _decode_share_release(
            record, recipient_private_key=recipient_private_key, expected=expected
        )
        if len(share) != 32:
            _fail("INVALID_SHARE_RELEASE", "decrypted threshold share is not 32 bytes")
        expected_commitment = derive_share_commitment(
            **expected,
            policy_id=policy["policy_id"],
            custodian_role=record["custodian_role"],
            share_index=index,
            share=share,
        )
        if expected_commitment != record["share_commitment_sha256"]:
            _fail("SHARE_COMMITMENT_MISMATCH", "decrypted threshold share does not match commitment")
        shares.append((index, share))
    try:
        actual_public = X25519PrivateKey.from_private_bytes(recipient_private_key).public_key().public_bytes_raw()
    except ValueError as exc:
        raise BlindActivationError("ACTIVATION_PRIVATE_KEY_REQUIRED", "activation private key is invalid") from exc
    if actual_public != recipient_public_key:
        _fail("ACTIVATION_PRIVATE_KEY_MISMATCH", "activation private key does not match public threshold policy")
    return shares


def _validate_access_log(
    evidence: object,
    *,
    registry: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, str],
    activation_time: datetime,
    threshold_policy_sha256: str,
    releases_by_envelope: Mapping[str, Mapping[str, Any]],
    threshold: int,
    nonce_reveals: Mapping[str, tuple[Mapping[str, Any], bytes, str]],
    roster: Mapping[str, str],
    log_id: str,
    log_genesis_root_sha256: str,
    preactivation_close_root_sha256: str,
    activation_trigger_envelope_sha256: str,
    blind_commitment_set_root_sha256: str,
    recipient_reveal: Mapping[str, Any],
    recipient_reveal_envelope_sha256: str,
) -> tuple[str, list[str], datetime]:
    envelopes, digest = _canonical_envelope_list(evidence, "access_log")
    if not envelopes:
        _fail("BROKEN_LOG_CHAIN", "access log cannot be empty")
    prior_hash = preactivation_close_root_sha256
    prior_time = activation_time
    event_ids: set[str] = set()
    recipient_reveals = 0
    logged_nonce_reveals: set[str] = set()
    released: set[str] = set()
    decrypted_shares: set[str] = set()
    decrypted_packages: set[str] = set()
    accessed_packages: set[str] = set()
    event_hashes: list[str] = []
    for sequence, envelope in enumerate(envelopes):
        record, envelope_hash = _verify_source_envelope(
            envelope,
            schema=G09_ACCESS_EVENT_SCHEMA,
            fields=_ACCESS_EVENT_FIELDS,
            registry=registry,
            expected=expected,
            expected_role=None,
            timestamp_field="occurred_at_utc",
            label="access event",
        )
        _nonnegative_int(
            record["sequence"], "access event sequence", "BROKEN_LOG_CHAIN"
        )
        if record["threshold_policy_sha256"] != threshold_policy_sha256:
            _fail("POLICY_MISMATCH", "access event does not bind threshold policy")
        if (
            record["log_id"] != log_id
            or record["log_genesis_root_sha256"] != log_genesis_root_sha256
            or record["preactivation_close_root_sha256"] != preactivation_close_root_sha256
            or record["activation_trigger_envelope_sha256"]
            != activation_trigger_envelope_sha256
            or record["blind_commitment_set_root_sha256"]
            != blind_commitment_set_root_sha256
        ):
            _fail("LOG_RESET_OR_PREFIX_OMISSION", "access event is detached from committed log genesis/close/trigger")
        if record["sequence"] != sequence or record["previous_envelope_sha256"] != prior_hash:
            _fail("BROKEN_LOG_CHAIN", "access log sequence or hash chain is broken")
        if record["previous_cursor"] != f"cursor-{sequence}" or record["cursor"] != f"cursor-{sequence + 1}":
            _fail("BROKEN_LOG_CURSOR", "access log cursor range is not exact and contiguous")
        event_id = _identifier(record["event_id"], "access event_id", "BROKEN_LOG_CHAIN")
        if event_id != f"event-{sequence}" or event_id in event_ids:
            _fail(
                "BROKEN_LOG_CHAIN",
                "access log event ids must be exact, contiguous, and unique",
            )
        event_ids.add(event_id)
        event_type = record["event_type"]
        if type(event_type) is not str:
            _fail("UNKNOWN_ACCESS_EVENT", "access log event type must be a string")
        expected_role = _EVENT_ROLE.get(event_type)
        if expected_role is None:
            _fail("UNKNOWN_ACCESS_EVENT", "access log event type is not allowlisted")
        _key_for_event(
            registry,
            role=record["role"],
            key_id=record["key_id"],
            at_utc=record["occurred_at_utc"],
            expected_role=expected_role,
            label="access event",
        )
        _postactivation(record["occurred_at_utc"], label=f"{event_type} event", activation=activation_time)
        occurred = _utc(record["occurred_at_utc"], "access event occurred_at_utc", "INVALID_CHRONOLOGY")
        if occurred < prior_time:
            _fail("INVALID_CHRONOLOGY", "access event timestamps are not monotonic")
        prior_time = occurred
        details = record["details"]
        if event_type == "RECIPIENT_KEY_REVEAL":
            detail = _exact(
                details,
                _KEY_REVEAL_EVENT_DETAILS,
                "recipient-key reveal event",
                "INVALID_ACCESS_EVENT",
            )
            if (
                sequence != 0
                or detail["recipient_key_reveal_envelope_sha256"]
                != recipient_reveal_envelope_sha256
                or detail["recipient_private_key_reveal_commitment_sha256"]
                != recipient_reveal["recipient_private_key_reveal_commitment_sha256"]
                or record["occurred_at_utc"] != recipient_reveal["revealed_at_utc"]
            ):
                _fail(
                    "RECIPIENT_KEY_REVEAL_EVENT_MISMATCH",
                    "recipient-key reveal is not the first exact causal event",
                )
            recipient_reveals += 1
        elif event_type == "NONCE_REVEAL":
            detail = _exact(
                details,
                _NONCE_REVEAL_EVENT_DETAILS,
                "nonce reveal event",
                "INVALID_ACCESS_EVENT",
            )
            archive = _sha256(
                detail["archive_sha256"],
                "nonce reveal event archive",
                "INVALID_ACCESS_EVENT",
            )
            reveal = nonce_reveals.get(archive)
            if (
                reveal is None
                or archive in logged_nonce_reveals
                or detail["family_id"] != roster.get(archive)
                or detail["package_sha256"] != archive
                or detail["nonce_reveal_envelope_sha256"] != reveal[2]
                or record["occurred_at_utc"] != reveal[0]["revealed_at_utc"]
            ):
                _fail(
                    "ACCESS_LOG_MISMATCH",
                    "nonce reveal event is missing, duplicate, aliased, or detached",
                )
            logged_nonce_reveals.add(archive)
        elif event_type in {"SHARE_RELEASE", "SHARE_DECRYPT"}:
            detail = _exact(details, _SHARE_EVENT_DETAILS, "share access event", "INVALID_ACCESS_EVENT")
            if type(detail["share_index"]) is not int or not 1 <= detail["share_index"] <= 255:
                _fail("INVALID_ACCESS_EVENT", "share event index must be in 1..255")
            release_hash = _sha256(
                detail["release_envelope_sha256"],
                "release_envelope_sha256",
                "INVALID_ACCESS_EVENT",
            )
            release = releases_by_envelope.get(release_hash)
            if release is None or detail["share_index"] != release["share_index"]:
                _fail("ACCESS_LOG_MISMATCH", "share access event does not reference exact release")
            if event_type == "SHARE_RELEASE":
                if release_hash in released or record["role"] != release["custodian_role"]:
                    _fail("ACCESS_LOG_MISMATCH", "share release event is duplicate or wrong-role")
                if record["occurred_at_utc"] != release["released_at_utc"]:
                    _fail("ACCESS_LOG_MISMATCH", "share release timestamp does not match record")
                released.add(release_hash)
            else:
                if release_hash not in released:
                    _fail(
                        "ACCESS_LOG_CAUSALITY",
                        "share decrypt event precedes its exact share release event",
                    )
                if release_hash in decrypted_shares:
                    _fail("ACCESS_LOG_MISMATCH", "share decrypt event is duplicate")
                if occurred < _utc(
                    release["released_at_utc"],
                    "share release time",
                    "INVALID_CHRONOLOGY",
                ):
                    _fail(
                        "ACCESS_LOG_CAUSALITY",
                        "share decrypt event predates its signed share release",
                    )
                decrypted_shares.add(release_hash)
        elif event_type in {"PACKAGE_DECRYPT", "PACKAGE_ACCESS"}:
            detail = _exact(details, _PACKAGE_EVENT_DETAILS, "package access event", "INVALID_ACCESS_EVENT")
            archive = _sha256(detail["archive_sha256"], "archive_sha256", "INVALID_ACCESS_EVENT")
            if roster.get(archive) != detail["family_id"] or detail["package_sha256"] != archive:
                _fail("ROSTER_SET_MISMATCH", "package access event is extra, aliased, or replacement")
            target = decrypted_packages if event_type == "PACKAGE_DECRYPT" else accessed_packages
            if archive in target:
                _fail("ACCESS_LOG_MISMATCH", "package event is duplicated")
            if event_type == "PACKAGE_DECRYPT":
                if len(decrypted_shares) < threshold:
                    _fail(
                        "ACCESS_LOG_CAUSALITY",
                        "package decrypt event precedes a reconstructable share quorum",
                    )
                nonce_reveal = nonce_reveals.get(archive)
                if archive not in logged_nonce_reveals or nonce_reveal is None or occurred < _utc(
                    nonce_reveal[0]["revealed_at_utc"],
                    "nonce reveal time",
                    "INVALID_CHRONOLOGY",
                ):
                    _fail(
                        "ACCESS_LOG_CAUSALITY",
                        "package decrypt event precedes its exact nonce reveal",
                    )
            elif archive not in decrypted_packages:
                _fail(
                    "ACCESS_LOG_CAUSALITY",
                    "package access event precedes its exact package decrypt event",
                )
            target.add(archive)
        else:
            _fail("UNKNOWN_ACCESS_EVENT", "access event has no exact verifier branch")
        prior_hash = envelope_hash
        event_hashes.append(envelope_hash)
    release_set = set(releases_by_envelope)
    if recipient_reveals != 1:
        _fail("MISSING_RECIPIENT_KEY_REVEAL_EVENT", "access log must contain exactly one recipient-key reveal event")
    if logged_nonce_reveals != set(roster):
        _fail(
            "ACCESS_LOG_MISMATCH",
            "access log does not account for every exact nonce reveal",
        )
    if released != release_set or decrypted_shares != release_set:
        _fail("ACCESS_LOG_MISMATCH", "access log does not account for every signed share release/decrypt")
    if decrypted_packages != set(roster) or accessed_packages != set(roster):
        _fail("ACCESS_LOG_MISMATCH", "access log does not account for every exact package decrypt/access")
    return digest, event_hashes, prior_time


def _validate_terminal_receipt(
    receipt: tuple[Mapping[str, Any], str, Mapping[str, Any]],
    *,
    preactivation_receipt_envelope_sha256: str,
    log_id: str,
    preactivation_close_root_sha256: str,
    activation_trigger_envelope_sha256: str,
    blind_commitment_set_root_sha256: str,
    event_hashes: Sequence[str],
    last_event_time: datetime,
) -> tuple[Mapping[str, Any], str]:
    record, envelope_hash, _ = receipt
    count = len(event_hashes)
    last_hash = event_hashes[-1] if event_hashes else _ZERO_HASH
    event_root = derive_log_event_hashes_root(event_hashes)
    worm_root = derive_log_worm_root(
        log_id=log_id,
        causal_predecessor_root_sha256=preactivation_close_root_sha256,
        event_hashes=event_hashes,
    )
    expected = {
        "phase": "TERMINAL",
        "prior_receipt_envelope_sha256": preactivation_receipt_envelope_sha256,
        "causal_predecessor_root_sha256": preactivation_close_root_sha256,
        "activation_trigger_envelope_sha256": activation_trigger_envelope_sha256,
        "blind_commitment_set_root_sha256": blind_commitment_set_root_sha256,
        "first_sequence": 0,
        "next_sequence": count,
        "cursor_start": "cursor-0",
        "cursor_end": f"cursor-{count}",
        "range_start_sequence": 0,
        "range_end_sequence_exclusive": count,
        "event_count": count,
        "last_event_envelope_sha256": last_hash,
        "event_hashes_root_sha256": event_root,
        "worm_object_root_sha256": worm_root,
    }
    if record["log_id"] != log_id:
        _fail("LOG_RECEIPT_MISMATCH", "terminal receipt log id mismatch")
    for field, value in expected.items():
        if record[field] != value:
            _fail("LOG_RECEIPT_MISMATCH", f"terminal WORM receipt does not bind exact {field}")
    if _utc(record["published_at_utc"], "terminal receipt published_at_utc", "INVALID_LOG_RECEIPT") < last_event_time:
        _fail("INVALID_CHRONOLOGY", "terminal WORM receipt predates the final event")
    return record, envelope_hash


def _evidence_manifest_root(
    *,
    expected: Mapping[str, str],
    activation_time_utc: str,
    evidence_hashes: Mapping[str, str],
    package_hashes: Mapping[str, str],
) -> str:
    return _hash_domain(
        "G09/EVIDENCE_MANIFEST/v1",
        **expected,
        activation_time_utc=activation_time_utc,
        evidence_items=[
            {"name": name, "sha256": evidence_hashes[name]}
            for name in sorted(evidence_hashes)
        ],
        package_items=[
            {"archive_sha256": archive, "sha256": package_hashes[archive]}
            for archive in sorted(package_hashes)
        ],
    )


def derive_blind_activation_audit(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str | None = None,
    g08_result_root: str | None = None,
    activation_time_utc: str | None = None,
    observed_at_utc: str | None = None,
    common_v2_dependencies: object,
    campaign_registry: object,
    expected_g08_roster: object,
    activation_rule: object,
    threshold_public_key_policy: object,
    worm_publication_receipts: object,
    log_genesis_signatures: object,
    activation_trigger: object,
    preactivation_close_signatures: object,
    recipient_key_reveal: object,
    roster_commitments: object,
    blinded_package_commitments: object,
    nonce_commitments: object,
    nonce_reveals: object,
    key_share_releases: object,
    access_log: object,
    terminal_close_signatures: object,
    package_bytes: object,
    expected_evidence_manifest_root: str | None = None,
) -> dict[str, Any]:
    """Recompute G09 from a signed trigger, complete log, and raw package bytes.

    ``observed_at_utc`` and the legacy root/time arguments are diagnostic
    equality checks only.  They cannot authorize activation; the signed trigger,
    zero-access close, recipient-key reveal, and terminal close do that.
    """

    if protocol_id != PROTOCOL_ID:
        _fail("INVALID_BINDING", "protocol_id is not the frozen v5.1 protocol")
    (
        expected,
        dependencies_digest,
        direct_dependencies,
        dependency_roster_digest,
    ) = _validate_v2_dependencies(
        common_v2_dependencies,
        campaign_root=campaign_root,
        evaluation_id=evaluation_id,
        frozen_spec_hash=frozen_spec_hash,
        diagnostic_campaign_registry_hash=campaign_registry_hash,
        diagnostic_g08_result_root=g08_result_root,
    )
    if observed_at_utc is not None:
        _utc(observed_at_utc, "observed_at_utc", "INVALID_DIAGNOSTIC_TIME")
    registry, registry_digest = _validate_registry(campaign_registry, expected=expected)
    roster, roster_digest = _validate_expected_roster(expected_g08_roster, expected=expected)
    if roster_digest != dependency_roster_digest:
        _fail(
            "V2_DEPENDENCY_MISMATCH",
            "expected G08 roster bytes are not the roster pinned by common v2 dependencies",
        )
    parsed_rule, _, _ = _canonical_json_evidence(activation_rule, "activation_rule")
    untrusted_rule_payload = parsed_rule.get("payload") if type(parsed_rule) is dict else None
    if type(untrusted_rule_payload) is not dict:
        _fail("INVALID_ACTIVATION_RULE", "activation rule signed payload is missing")
    signed_activation_time = _utc_text(
        untrusted_rule_payload.get("activation_time_utc"),
        "signed activation_time_utc",
        "INVALID_ACTIVATION_RULE",
    )
    if activation_time_utc is not None and _utc_text(
        activation_time_utc, "diagnostic activation_time_utc", "INVALID_DIAGNOSTIC_TIME"
    ) != signed_activation_time:
        _fail("ACTIVATION_TIME_MISMATCH", "diagnostic activation time disagrees with signed rule")
    activation_time = _utc(
        signed_activation_time, "signed activation_time_utc", "INVALID_ACTIVATION_RULE"
    )
    rule, rule_digest = _validate_activation_rule(
        activation_rule,
        registry=registry,
        expected=expected,
        activation_time_utc=signed_activation_time,
    )
    policy, _, recipient_public, policy_commitments = _validate_policy(
        threshold_public_key_policy,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
        activation_time_utc=signed_activation_time,
    )
    policy_sha = canonical_sha256(policy)
    policy_evidence_digest = _canonical_json_evidence(
        threshold_public_key_policy, "threshold_public_key_policy"
    )[2]
    preactivation_commitment_digests = {
        "roster": _canonical_json_evidence(
            roster_commitments, "roster commitments"
        )[2],
        "nonce": _canonical_json_evidence(
            nonce_commitments, "nonce commitments"
        )[2],
        "package": _canonical_json_evidence(
            blinded_package_commitments, "blinded package commitments"
        )[2],
    }
    blind_commitment_set_root = derive_blind_commitment_set_root(
        expected=expected,
        common_v2_dependencies_sha256=dependencies_digest,
        expected_g08_roster_sha256=roster_digest,
        threshold_policy_evidence_sha256=policy_evidence_digest,
        roster_commitments_evidence_sha256=preactivation_commitment_digests[
            "roster"
        ],
        nonce_commitments_evidence_sha256=preactivation_commitment_digests[
            "nonce"
        ],
        package_commitments_evidence_sha256=preactivation_commitment_digests[
            "package"
        ],
    )
    recipient_commitment = policy[
        "activation_recipient_private_key_reveal_commitment_sha256"
    ]
    receipts, receipts_digest = _validate_log_receipts(
        worm_publication_receipts,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
    )
    genesis, _, genesis_digest = _validate_log_genesis(
        log_genesis_signatures,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
        activation_time_utc=signed_activation_time,
        dependencies_sha256=dependencies_digest,
        threshold_policy_sha256=policy_sha,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        recipient_commitment_sha256=recipient_commitment,
        genesis_receipt=receipts["GENESIS"],
    )
    genesis_root = genesis["genesis_root_sha256"]
    expected_rule_bindings = {
        "common_v2_dependencies_sha256": dependencies_digest,
        "threshold_policy_sha256": policy_sha,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "log_genesis_root_sha256": genesis_root,
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
    }
    for field, value in expected_rule_bindings.items():
        if rule[field] != value:
            _fail("ACTIVATION_RULE_BINDING_MISMATCH", f"activation rule does not bind {field}")
    trigger, trigger_hash, trigger_digest = _validate_activation_trigger(
        activation_trigger,
        registry=registry,
        expected=expected,
        activation_time_utc=signed_activation_time,
        activation_rule_sha256=rule_digest,
        activation_rule=rule,
        dependencies_sha256=dependencies_digest,
        threshold_policy_sha256=policy_sha,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        log_genesis_root_sha256=genesis_root,
        recipient_commitment_sha256=recipient_commitment,
    )
    _, genesis_receipt_hash, _ = receipts["GENESIS"]
    _, preactivation_receipt_hash = _validate_preactivation_receipt(
        receipts["PREACTIVATION"],
        genesis_receipt_envelope_sha256=genesis_receipt_hash,
        log_id=genesis["log_id"],
        log_genesis_root_sha256=genesis_root,
        activation_trigger_envelope_sha256=trigger_hash,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        activation_time_utc=trigger["triggered_at_utc"],
    )
    preclose, _, preclose_digest = _validate_log_close(
        preactivation_close_signatures,
        registry=registry,
        expected=expected,
        close_kind="PREACTIVATION_ZERO_ACCESS",
        log_id=genesis["log_id"],
        log_genesis_root_sha256=genesis_root,
        activation_trigger_envelope_sha256=trigger_hash,
        predecessor_close_root_sha256=genesis_root,
        worm_receipt_envelope_sha256=preactivation_receipt_hash,
        first_sequence=0,
        next_sequence=0,
        cursor_start="cursor-0",
        cursor_end="cursor-0",
        event_hashes=[],
        last_event_envelope_sha256=_ZERO_HASH,
        exact_close_time_utc=trigger["triggered_at_utc"],
    )
    preclose_root = preclose["close_root_sha256"]
    reveal, recipient_private_key, reveal_hash, reveal_digest = _validate_recipient_key_reveal(
        recipient_key_reveal,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
        threshold_policy_sha256=policy_sha,
        policy=policy,
        recipient_public_key=recipient_public,
        activation_trigger_envelope_sha256=trigger_hash,
        preactivation_close_root_sha256=preclose_root,
    )
    roster_records, roster_commitments_digest = _validate_commitment_records(
        roster_commitments,
        schema=G09_ROSTER_COMMITMENT_SCHEMA,
        fields=_ROSTER_COMMITMENT_FIELDS,
        registry=registry,
        expected=expected,
        roster=roster,
        activation_time=activation_time,
        label="roster commitments",
    )
    nonce_records, nonce_commitments_digest = _validate_commitment_records(
        nonce_commitments,
        schema=G09_NONCE_COMMITMENT_SCHEMA,
        fields=_NONCE_COMMITMENT_FIELDS,
        registry=registry,
        expected=expected,
        roster=roster,
        activation_time=activation_time,
        label="nonce commitments",
    )
    package_records, package_commitments_digest = _validate_commitment_records(
        blinded_package_commitments,
        schema=G09_PACKAGE_COMMITMENT_SCHEMA,
        fields=_PACKAGE_COMMITMENT_FIELDS,
        registry=registry,
        expected=expected,
        roster=roster,
        activation_time=activation_time,
        label="blinded package commitments",
    )
    if {
        "roster": roster_commitments_digest,
        "nonce": nonce_commitments_digest,
        "package": package_commitments_digest,
    } != preactivation_commitment_digests:
        _fail(
            "BLIND_COMMITMENT_SET_MISMATCH",
            "validated commitment evidence differs from prospectively derived bytes",
        )
    for archive, family in roster.items():
        roster_record = roster_records[archive]
        expected_roster_commitment = derive_roster_commitment(
            **expected,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
        )
        if roster_record["roster_commitment_sha256"] != expected_roster_commitment:
            _fail("ROSTER_COMMITMENT_MISMATCH", "roster commitment cannot bind selected archive")
        nonce_record = nonce_records[archive]
        package_record = package_records[archive]
        if package_record["nonce_commitment_sha256"] != nonce_record["nonce_commitment_sha256"]:
            _fail("COMMITMENT_MISMATCH", "package commitment does not bind nonce commitment")
        try:
            ciphertext = _decode_byte_evidence(
                package_record["ciphertext"],
                expected_media_type="application/octet-stream",
            )
            aad = _decode_byte_evidence(package_record["aad"], expected_media_type="application/json")
        except Exception as exc:
            raise BlindActivationError("INVALID_CIPHERTEXT", f"blinded package evidence is invalid: {exc}") from exc
        if len(ciphertext) < 16:
            _fail("INVALID_CIPHERTEXT", "AES-GCM ciphertext must include a tag")
        expected_aad = derive_package_aad(
            **expected,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
            nonce_commitment_sha256=nonce_record["nonce_commitment_sha256"],
        )
        if aad != expected_aad:
            _fail("AAD_MISMATCH", "package AAD is not the exact derived canonical bytes")
        expected_package_commitment = derive_package_commitment(
            **expected,
            family_id=family,
            archive_sha256=archive,
            package_sha256=archive,
            nonce_commitment_sha256=nonce_record["nonce_commitment_sha256"],
            ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
            aad_sha256=hashlib.sha256(aad).hexdigest(),
        )
        if package_record["package_commitment_sha256"] != expected_package_commitment:
            _fail("PACKAGE_COMMITMENT_MISMATCH", "package commitment does not bind ciphertext/AAD")

    nonce_records_after, nonce_reveals_digest = _validate_nonce_reveals(
        nonce_reveals,
        registry=registry,
        expected=expected,
        roster=roster,
        activation_time=activation_time,
        nonce_commitments=nonce_records,
    )
    release_records, releases_by_envelope, releases_digest = _validate_share_release_records(
        key_share_releases,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
        threshold_policy_sha256=policy_sha,
        policy=policy,
        policy_commitments=policy_commitments,
    )
    access_digest, access_event_hashes, last_event_time = _validate_access_log(
        access_log,
        registry=registry,
        expected=expected,
        activation_time=activation_time,
        threshold_policy_sha256=policy_sha,
        releases_by_envelope=releases_by_envelope,
        threshold=policy["threshold"],
        nonce_reveals=nonce_records_after,
        roster=roster,
        log_id=genesis["log_id"],
        log_genesis_root_sha256=genesis_root,
        preactivation_close_root_sha256=preclose_root,
        activation_trigger_envelope_sha256=trigger_hash,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        recipient_reveal=reveal,
        recipient_reveal_envelope_sha256=reveal_hash,
    )
    terminal_receipt, terminal_receipt_hash = _validate_terminal_receipt(
        receipts["TERMINAL"],
        preactivation_receipt_envelope_sha256=preactivation_receipt_hash,
        log_id=genesis["log_id"],
        preactivation_close_root_sha256=preclose_root,
        activation_trigger_envelope_sha256=trigger_hash,
        blind_commitment_set_root_sha256=blind_commitment_set_root,
        event_hashes=access_event_hashes,
        last_event_time=last_event_time,
    )
    terminal_close, _, terminal_close_digest = _validate_log_close(
        terminal_close_signatures,
        registry=registry,
        expected=expected,
        close_kind="POSTACTIVATION_TERMINAL",
        log_id=genesis["log_id"],
        log_genesis_root_sha256=genesis_root,
        activation_trigger_envelope_sha256=trigger_hash,
        predecessor_close_root_sha256=preclose_root,
        worm_receipt_envelope_sha256=terminal_receipt_hash,
        first_sequence=0,
        next_sequence=len(access_event_hashes),
        cursor_start="cursor-0",
        cursor_end=f"cursor-{len(access_event_hashes)}",
        event_hashes=access_event_hashes,
        last_event_envelope_sha256=access_event_hashes[-1],
        exact_close_time_utc=None,
    )
    terminal_close_time = _utc(
        terminal_close["closed_at_utc"], "terminal close time", "INVALID_LOG_CLOSE"
    )
    if terminal_close_time < _utc(
        terminal_receipt["published_at_utc"], "terminal receipt time", "INVALID_LOG_RECEIPT"
    ) or terminal_close_time < last_event_time:
        _fail("INVALID_CHRONOLOGY", "terminal close predates event or publication closure")
    shares = _decrypt_share_release_records(
        release_records,
        recipient_private_key=recipient_private_key,
        recipient_public_key=recipient_public,
        expected=expected,
        policy=policy,
    )
    data_key = reconstruct_threshold_secret(shares, threshold=policy["threshold"])
    packages, package_hashes = _validate_packages(package_bytes, roster=roster)
    for archive, family in roster.items():
        package_record = package_records[archive]
        _, nonce, _ = nonce_records_after[archive]
        try:
            ciphertext = _decode_byte_evidence(
                package_record["ciphertext"],
                expected_media_type="application/octet-stream",
            )
            aad = _decode_byte_evidence(package_record["aad"], expected_media_type="application/json")
            plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise BlindActivationError("PACKAGE_DECRYPTION_FAILED", "blinded package cannot be decrypted") from exc
        if plaintext != packages[archive] or hashlib.sha256(plaintext).hexdigest() != archive:
            _fail("PACKAGE_MISMATCH", "decrypted package bytes do not equal exact selected archive bytes")
    evidence_hashes = {
        "access_log": access_digest,
        "activation_rule": rule_digest,
        "activation_trigger": trigger_digest,
        "blinded_package_commitments": package_commitments_digest,
        "campaign_registry": registry_digest,
        "common_v2_dependencies": dependencies_digest,
        "expected_g08_roster": roster_digest,
        "key_share_releases": releases_digest,
        "log_genesis_signatures": genesis_digest,
        "nonce_commitments": nonce_commitments_digest,
        "nonce_reveals": nonce_reveals_digest,
        "preactivation_close_signatures": preclose_digest,
        "recipient_key_reveal": reveal_digest,
        "roster_commitments": roster_commitments_digest,
        "terminal_close_signatures": terminal_close_digest,
        "threshold_public_key_policy": policy_evidence_digest,
        "worm_publication_receipts": receipts_digest,
    }
    manifest_root = _evidence_manifest_root(
        expected=expected,
        activation_time_utc=signed_activation_time,
        evidence_hashes=evidence_hashes,
        package_hashes=package_hashes,
    )
    if expected_evidence_manifest_root is not None and manifest_root != _sha256(
        expected_evidence_manifest_root, "expected_evidence_manifest_root", "EVIDENCE_MANIFEST_MISMATCH"
    ):
        _fail("EVIDENCE_MANIFEST_MISMATCH", "raw G09 evidence does not equal expected manifest root")
    return {
        "schema": G09_AUDIT_SCHEMA,
        **expected,
        "activation_time_utc": signed_activation_time,
        "activation_rule_sha256": rule_digest,
        "activation_trigger_envelope_sha256": trigger_hash,
        "common_v2_direct_dependencies": direct_dependencies,
        "common_v2_dependency_binding_only": True,
        "common_v2_gate_allowlisted": False,
        "raw_evidence_recomputed": True,
        "aggregate_authority": False,
        "threshold_policy_sha256": policy_sha,
        "blind_commitment_set_root_sha256": blind_commitment_set_root,
        "log_genesis_root_sha256": genesis_root,
        "preactivation_close_root_sha256": preclose_root,
        "terminal_close_root_sha256": terminal_close["close_root_sha256"],
        "recipient_private_key_reveal_commitment_sha256": recipient_commitment,
        "evidence_manifest_root": manifest_root,
        "selected_archive_sha256s": sorted(roster),
        "selected_family_archive_pairs": [
            {"family_id": roster[archive], "archive_sha256": archive} for archive in sorted(roster)
        ],
        "released_share_indices": sorted(index for index, _ in shares),
        "threshold": policy["threshold"],
        "share_quorum_reconstructed_after_activation": True,
        "no_pre_activation_reconstructable_share_set": True,
        "no_pre_activation_plaintext_or_access": True,
        "zero_access_close_dual_signed": True,
        "terminal_log_range_closed": True,
        "recipient_private_key_reveal_verified": True,
        "ciphertext_package_set_equals_g08_roster": True,
        "decrypted_package_set_equals_g08_roster": True,
        "access_log_event_sha256s": access_event_hashes,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def derive_blind_activation_gate_payload(
    *,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    verifier_module_digest: str,
    evidence_manifest_root: str,
    **evidence: Any,
) -> dict[str, Any]:
    """Fail closed while G09 has no registered exact-gate v2 dispatcher.

    G09 raw-evidence recomputation is deliberately usable through
    :func:`derive_blind_activation_audit`; v1 common-gate payloads are
    hard-retired and cannot turn this result into a pass.
    """

    del (
        campaign_root,
        protocol_id,
        evaluation_id,
        frozen_spec_hash,
        campaign_registry_hash,
        g08_result_root,
        verifier_module_digest,
        evidence_manifest_root,
        evidence,
    )
    _fail(
        "COMMON_GATE_WRAPPER_RETIRED",
        "G09 final signing is closed because its exact-gate v2 dispatcher is unallowlisted",
    )


def verify_blind_activation(
    *,
    authority_envelope: object,
    countersignature_envelope: object,
    authority_public_key: bytes,
    validator_public_key: bytes,
    protocol_id: str = PROTOCOL_ID,
    campaign_root: str,
    evaluation_id: str,
    frozen_spec_hash: str,
    campaign_registry_hash: str,
    g08_result_root: str,
    verifier_module_digest: str,
    evidence_manifest_root: str,
    **evidence: Any,
) -> dict[str, Any]:
    """Fail closed: common authority envelopes remain unavailable for G09."""

    del (
        authority_envelope,
        countersignature_envelope,
        authority_public_key,
        validator_public_key,
        protocol_id,
        campaign_root,
        evaluation_id,
        frozen_spec_hash,
        campaign_registry_hash,
        g08_result_root,
        verifier_module_digest,
        evidence_manifest_root,
        evidence,
    )
    _fail(
        "COMMON_GATE_WRAPPER_RETIRED",
        "G09 final signing is closed because its exact-gate v2 dispatcher is unallowlisted",
    )


# G09-prefixed aliases make the public verifier contract easy to dispatch.
derive_g09_blind_activation_audit = derive_blind_activation_audit
derive_g09_blind_activation_gate_payload = derive_blind_activation_gate_payload
verify_blind_activation_evidence = derive_blind_activation_audit
verify_g09_blind_activation_evidence = derive_blind_activation_audit
verify_g09_blind_activation = verify_blind_activation


__all__ = [
    "BlindActivationError",
    "G09_ACCESS_EVENT_SCHEMA",
    "G09_ACTIVATION_RULE_SCHEMA",
    "G09_ACTIVATION_TRIGGER_SCHEMA",
    "G09_AUDIT_SCHEMA",
    "G09_GATE_ID",
    "G09_LOG_CLOSE_SCHEMA",
    "G09_LOG_GENESIS_SCHEMA",
    "G09_LOG_RECEIPT_SCHEMA",
    "G09_NONCE_COMMITMENT_SCHEMA",
    "G09_NONCE_REVEAL_SCHEMA",
    "G09_PACKAGE_COMMITMENT_SCHEMA",
    "G09_RECIPIENT_KEY_REVEAL_SCHEMA",
    "G09_REGISTRY_SCHEMA",
    "G09_ROSTER_COMMITMENT_SCHEMA",
    "G09_ROSTER_SCHEMA",
    "G09_SHARE_RELEASE_SCHEMA",
    "G09_THRESHOLD_POLICY_SCHEMA",
    "G09_V2_DEPENDENCIES_SCHEMA",
    "G09_WORM_PROVIDER_RECEIPT_SCHEMA",
    "G09_WORM_PUBLICATION_MEDIA_TYPE",
    "PROTOCOL_ID",
    "THRESHOLD_SCHEME",
    "derive_activation_trigger_commitment",
    "derive_blind_commitment_set_root",
    "derive_blind_activation_audit",
    "derive_blind_activation_gate_payload",
    "derive_g09_blind_activation_audit",
    "derive_g09_blind_activation_gate_payload",
    "derive_log_close_root",
    "derive_log_event_hashes_root",
    "derive_log_genesis_root",
    "derive_log_worm_root",
    "derive_nonce_commitment",
    "derive_package_aad",
    "derive_package_commitment",
    "derive_recipient_private_key_reveal_commitment",
    "derive_roster_commitment",
    "derive_share_commitment",
    "derive_share_seal_aad",
    "derive_threshold_shares",
    "reconstruct_threshold_secret",
    "seal_threshold_share",
    "verify_blind_activation",
    "verify_blind_activation_evidence",
    "verify_g09_blind_activation",
    "verify_g09_blind_activation_evidence",
]
