"""Fail-closed v6.2.3 population trust and recruitment verification.

This module verifies cryptographic and population-wide recruitment evidence.  It
does not publish a campaign preregistration root, issue an upload permit, access
the sealed holdout, or authorize either calibration or production uploads.

Real-world identity, non-collusion, and truthful undisclosed provenance are not
machine-provable.  The optional ``ExternalEvidenceVerifier`` is therefore an
explicit trust boundary whose implementation, build, and policy hashes must be
independently reviewed and frozen outside this module.
"""

from __future__ import annotations

import base64
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evaluation_v5_1.exact_gate_v2 import (
    ExactGateV2Error,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)

from .integration_v622 import (
    CONFIRM_PRIMARY_SLOTS,
    CONFIRM_RESERVE_SLOT,
    DEV_PRIMARY_SLOTS,
    DEV_RESERVE_SLOT,
    SLOTS,
    canonical_json_bytes,
    canonical_json_loads,
    canonical_sha256,
)


BUNDLE_SCHEMA = "eval.v6.2.3.population-trust-bundle"
CAMPAIGN_SCHEMA = "eval.v6.2.3.campaign-binding"
REGISTRY_SCHEMA = "eval.v6.2.3.trust-registry"
REVOCATION_SCHEMA = "eval.v6.2.3.revocation-log"
ENVELOPE_SCHEMA = "eval.v6.2.3.detached-envelope"
CONTRIBUTOR_SCHEMA = "eval.v6.2.3.contributor-manifest"
TECHNICAL_SCHEMA = "eval.v6.2.3.technical-audit-receipt"
LINEAGE_SCHEMA = "eval.v6.2.3.lineage-audit-receipt"
POPULATION_GRAPH_SCHEMA = "eval.v6.2.3.population-graph"
POPULATION_DECISION_SCHEMA = "eval.v6.2.3.population-decision"
EXTERNAL_CHECK_SCHEMA = "eval.v6.2.3.external-check"
EXTERNAL_CHECK_ENVELOPE_SCHEMA = "eval.v6.2.3.external-check-envelope"
VERDICT_SCHEMA = "eval.v6.2.3.population-trust-verdict"

ROLE_CONTRIBUTOR = "CONTRIBUTOR"
ROLE_TECHNICAL = "TECH_AUDITOR"
ROLE_LINEAGE = "LINEAGE_AUDITOR"
ROLE_ADJUDICATOR = "ADJUDICATOR"
ROLE_REGISTRY_ADMIN = "REGISTRY_ADMIN"
REGISTRY_ROLES = frozenset(
    {ROLE_CONTRIBUTOR, ROLE_TECHNICAL, ROLE_LINEAGE, ROLE_ADJUDICATOR}
)

DOMAIN_REGISTRY = b"EVAL-V623/REGISTRY\0"
DOMAIN_REVOCATION = b"EVAL-V623/REVOCATION\0"
DOMAIN_CONTRIBUTOR = b"EVAL-V623/CONTRIBUTOR\0"
DOMAIN_TECHNICAL = b"EVAL-V623/TECH-AUDIT\0"
DOMAIN_LINEAGE = b"EVAL-V623/LINEAGE-AUDIT\0"
DOMAIN_POPULATION = b"EVAL-V623/POPULATION-DECISION\0"
DOMAIN_TIMESTAMP = b"EVAL-V623/TIMESTAMP-SUBJECT\0"
DOMAIN_EXTERNAL_CHECK = b"EVAL-V623/EXTERNAL-CHECK\0"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_HEX_NONCE_RE = re.compile(r"^[0-9a-f]{32,256}$")
_CONTAINER_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FAMILY_RE = re.compile(r"^sf-[0-9a-f]{24}$")
_LINEAGE_RE = re.compile(r"^lt-[0-9a-f]{24}$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RELATIONS = frozenset(
    {"INDEPENDENT", "SAME_FAMILY", "DERIVED_FROM", "SHARED_SCAFFOLD", "UNKNOWN"}
)
_MAX_BUNDLE_BYTES = 64 * 1024 * 1024


class AttestationV623Error(ValueError):
    """A population trust input is malformed, unbound, or unverified."""


def read_canonical_trust_bundle(path: str | Path) -> Mapping[str, Any]:
    """Read one immutable canonical bundle without following a symlink.

    The double ``fstat`` detects replacement or mutation during the read.  JSON
    must be exact canonical bytes with no BOM, CR, or trailing newline.
    """

    target = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise AttestationV623Error(f"unable to open trust bundle safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AttestationV623Error("trust bundle must be a regular file")
        if before.st_size <= 0 or before.st_size > _MAX_BUNDLE_BYTES:
            raise AttestationV623Error("trust bundle size is empty or exceeds the 64 MiB limit")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise AttestationV623Error("trust bundle was truncated during the read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AttestationV623Error("trust bundle grew during the read")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise AttestationV623Error("trust bundle changed during the read")
    raw = b"".join(chunks)
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or raw.endswith(b"\n"):
        raise AttestationV623Error("trust bundle must use exact UTF-8 canonical JSON framing")
    try:
        parsed = canonical_json_loads(raw)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise AttestationV623Error(f"trust bundle is not valid canonical JSON: {exc}") from exc
    if type(parsed) is not dict or raw != canonical_json_bytes(parsed):
        raise AttestationV623Error("trust bundle bytes are not canonical JSON")
    return parsed


@dataclass(frozen=True)
class PinnedRegistryAdmin:
    """An independently pinned registry administrator trust root."""

    entity_id: str
    public_key: bytes
    external_identity_receipt_sha256: str

    @property
    def key_id(self) -> str:
        return _key_id(self.public_key)


@dataclass(frozen=True)
class PinnedExternalVerifier:
    """Independently reviewed signing root for external semantic decisions."""

    entity_id: str
    public_key: bytes
    verifier_id: str
    verifier_build_sha256: str
    trust_policy_sha256: str
    timestamp_policy_sha256: str
    external_identity_receipt_sha256: str

    @property
    def key_id(self) -> str:
        return _key_id(self.public_key)


class ExternalEvidenceVerifier(Protocol):
    """Separately reviewed verifier for claims Python cannot infer locally.

    Each method returns an exact ``EXTERNAL_CHECK_SCHEMA`` mapping.  No default
    permissive implementation exists.  A caller-provided implementation is a
    security boundary and must be content-addressed by the campaign binding.
    """

    def verify_identity(self, key_record: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def verify_timestamp(
        self, timestamp_subject: bytes, envelope: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    def verify_technical(
        self,
        technical_receipt: Mapping[str, Any],
        contributor_manifest: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def verify_lineage(
        self,
        lineage_receipt: Mapping[str, Any],
        contributor_manifest: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise AttestationV623Error(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\0" in value:
        raise AttestationV623Error(f"{label} must be a nonempty trimmed string without NUL")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise AttestationV623Error(f"{label} must be lowercase SHA-256 hex")
    return value


def _nonce(value: Any, label: str) -> str:
    if type(value) is not str or _HEX_NONCE_RE.fullmatch(value) is None or len(value) % 2:
        raise AttestationV623Error(f"{label} must be 16 through 128 bytes of lowercase hex")
    return value


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise AttestationV623Error(f"{label} must be canonical second-resolution UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AttestationV623Error(f"{label} is not a valid UTC timestamp") from exc
    return parsed


def _string_list(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if type(value) is not list or (not allow_empty and not value):
        raise AttestationV623Error(f"{label} must be a JSON array of strings")
    result = [_identifier(item, f"{label} item") for item in value]
    if len(result) != len(set(result)):
        raise AttestationV623Error(f"{label} must not contain duplicates")
    return result


def _public_key(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise AttestationV623Error(f"{label} must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise AttestationV623Error(f"{label} must be canonical base64") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise AttestationV623Error(f"{label} must encode exactly 32 bytes")
    try:
        validate_ed25519_public_key(raw)
    except ExactGateV2Error as exc:
        raise AttestationV623Error(f"{label} is not a strict Ed25519 key: {exc}") from exc
    return raw


def _signature(value: Any) -> bytes:
    if type(value) is not str:
        raise AttestationV623Error("signature_ed25519_base64 must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise AttestationV623Error("signature_ed25519_base64 must be canonical base64") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise AttestationV623Error("signature_ed25519_base64 must encode exactly 64 bytes")
    try:
        validate_ed25519_signature_encoding(raw)
    except ExactGateV2Error as exc:
        raise AttestationV623Error(f"signature has a non-strict Ed25519 encoding: {exc}") from exc
    return raw


def _key_id(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise AttestationV623Error("Ed25519 public key must contain exactly 32 bytes")
    try:
        validate_ed25519_public_key(public_key)
    except ExactGateV2Error as exc:
        raise AttestationV623Error(f"Ed25519 public key is invalid: {exc}") from exc
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def signing_message(domain: bytes, payload: Mapping[str, Any]) -> bytes:
    """Return the v6.2.3 domain-separated signature preimage."""

    if domain not in {
        DOMAIN_REGISTRY,
        DOMAIN_REVOCATION,
        DOMAIN_CONTRIBUTOR,
        DOMAIN_TECHNICAL,
        DOMAIN_LINEAGE,
        DOMAIN_POPULATION,
    }:
        raise AttestationV623Error("unregistered v6.2.3 signature domain")
    if type(payload) is not dict:
        raise AttestationV623Error("signed payload must be a plain JSON object")
    return domain + hashlib.sha256(canonical_json_bytes(payload)).digest()


def timestamp_subject(envelope: Mapping[str, Any], payload_message: bytes) -> bytes:
    """Bind a timestamp token to the signature, signer, time claim, and payload."""

    if type(envelope) is not dict:
        raise AttestationV623Error("timestamp envelope must be a plain JSON object")
    subject = {
        "key_id": _identifier(envelope.get("key_id"), "timestamp key_id"),
        "payload_signing_message_sha256": hashlib.sha256(payload_message).hexdigest(),
        "signature_ed25519_base64": base64.b64encode(
            _signature(envelope.get("signature_ed25519_base64"))
        ).decode("ascii"),
        "signed_at_utc": envelope.get("signed_at_utc"),
    }
    _utc(subject["signed_at_utc"], "timestamp signed_at_utc")
    return DOMAIN_TIMESTAMP + canonical_json_bytes(subject)


def external_check_signing_message(receipt: Mapping[str, Any]) -> bytes:
    """Return the only bytes the pinned external verifier may sign."""

    if type(receipt) is not dict:
        raise AttestationV623Error("external check receipt must be a plain JSON object")
    return DOMAIN_EXTERNAL_CHECK + hashlib.sha256(canonical_json_bytes(receipt)).digest()


def _verify_detached_envelope(
    envelope: Any,
    *,
    payload: Mapping[str, Any],
    artifact_schema: str,
    domain: bytes,
    public_key: bytes,
) -> tuple[str, datetime, bytes]:
    value = _exact(
        envelope,
        frozenset(
            {
                "schema",
                "artifact_schema",
                "key_id",
                "payload_sha256",
                "signed_at_utc",
                "signature_ed25519_base64",
                "timestamp_token_sha256",
            }
        ),
        "detached envelope",
    )
    if value["schema"] != ENVELOPE_SCHEMA or value["artifact_schema"] != artifact_schema:
        raise AttestationV623Error("detached envelope schema binding is invalid")
    key_id = _identifier(value["key_id"], "envelope key_id")
    if _KEY_ID_RE.fullmatch(key_id) is None or key_id != _key_id(public_key):
        raise AttestationV623Error("envelope key_id does not bind the pinned Ed25519 key")
    digest = _sha(value["payload_sha256"], "envelope payload_sha256")
    if digest != canonical_sha256(payload):
        raise AttestationV623Error("envelope payload_sha256 does not bind canonical payload bytes")
    _sha(value["timestamp_token_sha256"], "envelope timestamp_token_sha256")
    signed_at = _utc(value["signed_at_utc"], "envelope signed_at_utc")
    signature = _signature(value["signature_ed25519_base64"])
    message = signing_message(domain, payload)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise AttestationV623Error("Ed25519 signature verification failed") from exc
    return key_id, signed_at, message


def _campaign(value: Any) -> dict[str, str]:
    raw = _exact(
        value,
        frozenset(
            {
                "schema",
                "campaign_id",
                "campaign_nonce",
                "protocol_sha256",
                "slot_schedule_sha256",
                "semantic_verifier_build_sha256",
                "trust_policy_sha256",
                "timestamp_policy_sha256",
                "engine_sha256",
                "ruleset_sha256",
                "build_container_digest",
                "safety_policy_sha256",
                "dudunsparce_harness_sha256",
            }
        ),
        "campaign binding",
    )
    if raw["schema"] != CAMPAIGN_SCHEMA:
        raise AttestationV623Error(f"campaign schema must be {CAMPAIGN_SCHEMA}")
    if (
        type(raw["build_container_digest"]) is not str
        or _CONTAINER_RE.fullmatch(raw["build_container_digest"]) is None
    ):
        raise AttestationV623Error("campaign build_container_digest is invalid")
    return {
        "campaign_id": _identifier(raw["campaign_id"], "campaign_id"),
        "campaign_nonce": _nonce(raw["campaign_nonce"], "campaign_nonce"),
        "protocol_sha256": _sha(raw["protocol_sha256"], "protocol_sha256"),
        "slot_schedule_sha256": _sha(raw["slot_schedule_sha256"], "slot_schedule_sha256"),
        "semantic_verifier_build_sha256": _sha(
            raw["semantic_verifier_build_sha256"], "semantic_verifier_build_sha256"
        ),
        "trust_policy_sha256": _sha(raw["trust_policy_sha256"], "trust_policy_sha256"),
        "timestamp_policy_sha256": _sha(
            raw["timestamp_policy_sha256"], "timestamp_policy_sha256"
        ),
        "engine_sha256": _sha(raw["engine_sha256"], "engine_sha256"),
        "ruleset_sha256": _sha(raw["ruleset_sha256"], "ruleset_sha256"),
        "build_container_digest": raw["build_container_digest"],
        "safety_policy_sha256": _sha(
            raw["safety_policy_sha256"], "safety_policy_sha256"
        ),
        "dudunsparce_harness_sha256": _sha(
            raw["dudunsparce_harness_sha256"], "dudunsparce_harness_sha256"
        ),
    }


def _validate_admin_roots(
    pinned_admins: Mapping[str, PinnedRegistryAdmin],
) -> dict[str, PinnedRegistryAdmin]:
    if type(pinned_admins) is not dict or len(pinned_admins) != 3:
        raise AttestationV623Error("exactly three registry administrator roots must be pinned")
    result: dict[str, PinnedRegistryAdmin] = {}
    entities: set[str] = set()
    keys: set[bytes] = set()
    for claimed_id, admin in pinned_admins.items():
        if not isinstance(admin, PinnedRegistryAdmin):
            raise AttestationV623Error("pinned admin records must be PinnedRegistryAdmin values")
        entity = _identifier(admin.entity_id, "pinned admin entity_id")
        _sha(admin.external_identity_receipt_sha256, "pinned admin identity receipt")
        key_id = admin.key_id
        if claimed_id != key_id or key_id in result or entity in entities or admin.public_key in keys:
            raise AttestationV623Error("pinned registry administrators must have distinct bound identities")
        result[key_id] = admin
        entities.add(entity)
        keys.add(admin.public_key)
    return result


def _validate_pinned_external_verifier(
    value: PinnedExternalVerifier,
) -> PinnedExternalVerifier:
    if not isinstance(value, PinnedExternalVerifier):
        raise AttestationV623Error(
            "external verifier root must be a PinnedExternalVerifier"
        )
    _identifier(value.entity_id, "pinned external verifier entity_id")
    _identifier(value.verifier_id, "pinned external verifier verifier_id")
    _key_id(value.public_key)
    _sha(value.verifier_build_sha256, "pinned external verifier build")
    _sha(value.trust_policy_sha256, "pinned external verifier trust policy")
    _sha(value.timestamp_policy_sha256, "pinned external verifier timestamp policy")
    _sha(
        value.external_identity_receipt_sha256,
        "pinned external verifier identity receipt",
    )
    return value


def _external_check(
    value: Any,
    *,
    kind: str,
    subject_sha256: str,
    pinned_verifier: PinnedExternalVerifier,
) -> tuple[str, datetime | None]:
    wrapper = _exact(
        value,
        frozenset(
            {
                "schema",
                "key_id",
                "receipt",
                "receipt_sha256",
                "signature_ed25519_base64",
            }
        ),
        f"signed external {kind} check",
    )
    if wrapper["schema"] != EXTERNAL_CHECK_ENVELOPE_SCHEMA:
        raise AttestationV623Error("external check envelope schema is invalid")
    if wrapper["key_id"] != pinned_verifier.key_id:
        raise AttestationV623Error("external check signer is not the pinned verifier")
    if type(wrapper["receipt"]) is not dict:
        raise AttestationV623Error("external check receipt must be an object")
    claimed_receipt_sha256 = _sha(
        wrapper["receipt_sha256"], "external check receipt_sha256"
    )
    if claimed_receipt_sha256 != canonical_sha256(wrapper["receipt"]):
        raise AttestationV623Error("external check envelope does not bind its receipt")
    signature = _signature(wrapper["signature_ed25519_base64"])
    try:
        Ed25519PublicKey.from_public_bytes(pinned_verifier.public_key).verify(
            signature, external_check_signing_message(wrapper["receipt"])
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationV623Error("external check signature verification failed") from exc
    raw = _exact(
        wrapper["receipt"],
        frozenset(
            {
                "schema",
                "kind",
                "subject_sha256",
                "verifier_id",
                "verifier_build_sha256",
                "trust_policy_sha256",
                "timestamp_policy_sha256",
                "evidence_root_sha256",
                "verified",
                "trusted_time_utc",
            }
        ),
        f"external {kind} check",
    )
    if raw["schema"] != EXTERNAL_CHECK_SCHEMA or raw["kind"] != kind:
        raise AttestationV623Error(f"external {kind} check has the wrong schema or kind")
    if raw["verified"] is not True:
        raise AttestationV623Error(f"external {kind} check is not verified")
    if _sha(raw["subject_sha256"], f"external {kind} subject") != subject_sha256:
        raise AttestationV623Error(f"external {kind} check does not bind its subject")
    if raw["verifier_id"] != pinned_verifier.verifier_id:
        raise AttestationV623Error(f"external {kind} check has the wrong verifier_id")
    if _sha(raw["verifier_build_sha256"], f"external {kind} verifier build") != pinned_verifier.verifier_build_sha256:
        raise AttestationV623Error(f"external {kind} check has the wrong verifier build")
    if _sha(raw["trust_policy_sha256"], f"external {kind} trust policy") != pinned_verifier.trust_policy_sha256:
        raise AttestationV623Error(f"external {kind} check has the wrong trust policy")
    if (
        _sha(raw["timestamp_policy_sha256"], f"external {kind} timestamp policy")
        != pinned_verifier.timestamp_policy_sha256
    ):
        raise AttestationV623Error(f"external {kind} check has the wrong timestamp policy")
    if kind == "TIMESTAMP":
        trusted_time = _utc(raw["trusted_time_utc"], "external timestamp trusted_time_utc")
    else:
        if raw["trusted_time_utc"] is not None:
            raise AttestationV623Error(f"external {kind} check must not assert a trusted time")
        trusted_time = None
    return (
        _sha(raw["evidence_root_sha256"], f"external {kind} evidence root"),
        trusted_time,
    )


def _claim_timestamp_token(envelope: Mapping[str, Any], claimed: set[str]) -> None:
    token = _sha(envelope.get("timestamp_token_sha256"), "timestamp token digest")
    if token in claimed:
        raise AttestationV623Error("timestamp token digest is replayed")
    claimed.add(token)


def _verify_external_timestamp(
    verifier: ExternalEvidenceVerifier,
    pinned_verifier: PinnedExternalVerifier,
    *,
    payload_message: bytes,
    envelope: Mapping[str, Any],
) -> tuple[str, datetime]:
    subject = timestamp_subject(envelope, payload_message)
    root, trusted_time = _external_check(
        verifier.verify_timestamp(subject, envelope),
        kind="TIMESTAMP",
        subject_sha256=hashlib.sha256(subject).hexdigest(),
        pinned_verifier=pinned_verifier,
    )
    if trusted_time is None:
        raise AttestationV623Error("external timestamp check omitted trusted time")
    return root, trusted_time


def _verify_admin_approvals(
    payload: Mapping[str, Any],
    approvals: Any,
    *,
    artifact_schema: str,
    domain: bytes,
    admins: Mapping[str, PinnedRegistryAdmin],
    external_verifier: ExternalEvidenceVerifier | None,
    pinned_external_verifier: PinnedExternalVerifier | None,
    external_roots: list[str],
    timestamp_tokens: set[str],
) -> set[str]:
    if type(approvals) is not list:
        raise AttestationV623Error("registry governance approvals must be a JSON array")
    signers: set[str] = set()
    for envelope in approvals:
        if type(envelope) is not dict:
            raise AttestationV623Error("registry governance approval must be an object")
        key_id = envelope.get("key_id")
        if key_id not in admins or key_id in signers:
            raise AttestationV623Error("registry governance approval signer is unknown or duplicated")
        admin = admins[key_id]
        _claim_timestamp_token(envelope, timestamp_tokens)
        _, signed_at, message = _verify_detached_envelope(
            envelope,
            payload=payload,
            artifact_schema=artifact_schema,
            domain=domain,
            public_key=admin.public_key,
        )
        if external_verifier is not None:
            if pinned_external_verifier is None:
                raise AttestationV623Error("external verifier has no independently pinned signing root")
            timestamp_root, trusted_time = _verify_external_timestamp(
                external_verifier,
                pinned_external_verifier,
                payload_message=message,
                envelope=envelope,
            )
            external_roots.append(timestamp_root)
            if abs((trusted_time - signed_at).total_seconds()) > 300:
                raise AttestationV623Error("admin signed_at_utc differs from trusted time by over 5 minutes")
        signers.add(key_id)
    if len(signers) < 2:
        raise AttestationV623Error("registry governance requires at least two of three admin approvals")
    return signers


def _registry(
    value: Any,
    *,
    campaign: Mapping[str, str],
) -> tuple[dict[str, dict[str, Any]], Mapping[str, Any]]:
    raw = _exact(
        value,
        frozenset({"schema", "campaign_id", "campaign_nonce", "registry_epoch", "keys"}),
        "trust registry",
    )
    if raw["schema"] != REGISTRY_SCHEMA:
        raise AttestationV623Error(f"registry schema must be {REGISTRY_SCHEMA}")
    if raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"]:
        raise AttestationV623Error("registry is not bound to the campaign")
    if type(raw["registry_epoch"]) is not int or isinstance(raw["registry_epoch"], bool) or raw["registry_epoch"] < 0:
        raise AttestationV623Error("registry_epoch must be a nonnegative integer")
    if type(raw["keys"]) is not list or not raw["keys"]:
        raise AttestationV623Error("registry keys must be a nonempty array")
    result: dict[str, dict[str, Any]] = {}
    entities: dict[str, str] = {}
    public_keys: set[bytes] = set()
    canonical_order: list[tuple[str, str]] = []
    for index, item in enumerate(raw["keys"]):
        key = _exact(
            item,
            frozenset(
                {
                    "key_id",
                    "public_key_ed25519_base64",
                    "role",
                    "entity_id",
                    "valid_from_utc",
                    "valid_to_utc",
                    "status",
                    "external_identity_receipt_sha256",
                }
            ),
            f"registry key {index}",
        )
        public_key = _public_key(key["public_key_ed25519_base64"], f"registry key {index}")
        key_id = _identifier(key["key_id"], f"registry key {index} key_id")
        role = _identifier(key["role"], f"registry key {index} role")
        entity = _identifier(key["entity_id"], f"registry key {index} entity_id")
        if role not in REGISTRY_ROLES:
            raise AttestationV623Error("registry key role is not allowed")
        if key_id != _key_id(public_key) or key_id in result or public_key in public_keys:
            raise AttestationV623Error("registry key identity is duplicated or incorrectly derived")
        if entity in entities:
            raise AttestationV623Error("one entity cannot occupy multiple v6.2.3 registry roles or keys")
        valid_from = _utc(key["valid_from_utc"], f"registry key {index} valid_from_utc")
        valid_to = _utc(key["valid_to_utc"], f"registry key {index} valid_to_utc")
        if valid_from >= valid_to:
            raise AttestationV623Error("registry key validity interval is empty or reversed")
        if key["status"] not in {"ACTIVE", "REVOKED", "COMPROMISED"}:
            raise AttestationV623Error("registry key status is unknown")
        result[key_id] = {
            "key_id": key_id,
            "public_key": public_key,
            "role": role,
            "entity_id": entity,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "status": key["status"],
            "external_identity_receipt_sha256": _sha(
                key["external_identity_receipt_sha256"],
                f"registry key {index} external identity receipt",
            ),
            "raw": dict(key),
        }
        entities[entity] = role
        public_keys.add(public_key)
        canonical_order.append((role, key_id))
    if canonical_order != sorted(canonical_order):
        raise AttestationV623Error("registry keys must be sorted by role then key_id")
    if Counter(key["role"] for key in result.values())[ROLE_ADJUDICATOR] != 3:
        raise AttestationV623Error("registry must contain exactly three adjudicators")
    return result, raw


def _revocations(
    value: Any,
    *,
    campaign: Mapping[str, str],
    registry: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, str], Mapping[str, Any]]:
    raw = _exact(
        value,
        frozenset({"schema", "campaign_id", "campaign_nonce", "registry_epoch", "entries"}),
        "revocation log",
    )
    if raw["schema"] != REVOCATION_SCHEMA:
        raise AttestationV623Error(f"revocation schema must be {REVOCATION_SCHEMA}")
    if raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"]:
        raise AttestationV623Error("revocation log is not bound to the campaign")
    if type(raw["registry_epoch"]) is not int or isinstance(raw["registry_epoch"], bool) or raw["registry_epoch"] < 0:
        raise AttestationV623Error("revocation registry_epoch must be a nonnegative integer")
    if type(raw["entries"]) is not list:
        raise AttestationV623Error("revocation entries must be a JSON array")
    result: dict[str, str] = {}
    order: list[str] = []
    for index, item in enumerate(raw["entries"]):
        entry = _exact(
            item,
            frozenset({"key_id", "state", "revoked_at_utc", "reason"}),
            f"revocation entry {index}",
        )
        key_id = _identifier(entry["key_id"], f"revocation entry {index} key_id")
        if key_id not in registry or key_id in result:
            raise AttestationV623Error("revocation entry references an unknown or duplicated key")
        if entry["state"] not in {"REVOKED", "COMPROMISED"}:
            raise AttestationV623Error("revocation state must be REVOKED or COMPROMISED")
        _utc(entry["revoked_at_utc"], f"revocation entry {index} revoked_at_utc")
        _identifier(entry["reason"], f"revocation entry {index} reason")
        result[key_id] = entry["state"]
        order.append(key_id)
    if order != sorted(order):
        raise AttestationV623Error("revocation entries must be sorted by key_id")
    return result, raw


def _active_signer(
    key_id: Any,
    *,
    role: str,
    registry: Mapping[str, Mapping[str, Any]],
    revocations: Mapping[str, str],
    signed_at: datetime,
) -> Mapping[str, Any]:
    if type(key_id) is not str or key_id not in registry:
        raise AttestationV623Error("signed artifact references an unknown registry key")
    key = registry[key_id]
    if key["role"] != role:
        raise AttestationV623Error(f"signed artifact requires registry role {role}")
    if key["status"] != "ACTIVE" or key_id in revocations:
        raise AttestationV623Error("revoked or compromised keys cannot authenticate evidence")
    if not key["valid_from"] <= signed_at <= key["valid_to"]:
        raise AttestationV623Error("signature timestamp falls outside registry key validity")
    return key


def _validate_contributor_manifest(
    value: Any, *, campaign: Mapping[str, str], slot: str
) -> Mapping[str, Any]:
    raw = _exact(
        value,
        frozenset(
            {
                "schema",
                "campaign_id",
                "campaign_nonce",
                "unit_nonce",
                "slot_id",
                "contributor",
                "source",
                "archive",
                "build",
                "engine",
                "authorship_ancestry",
            }
        ),
        f"{slot} contributor manifest",
    )
    if raw["schema"] != CONTRIBUTOR_SCHEMA or raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"] or raw["slot_id"] != slot:
        raise AttestationV623Error(f"{slot} contributor manifest is not campaign-bound")
    _nonce(raw["unit_nonce"], f"{slot} unit_nonce")
    contributor = _exact(raw["contributor"], frozenset({"key_id", "entity_id"}), f"{slot} contributor")
    _identifier(contributor["key_id"], f"{slot} contributor key_id")
    _identifier(contributor["entity_id"], f"{slot} contributor entity_id")
    source = _exact(
        raw["source"],
        frozenset({"source_tree_sha256", "vcs_bundle_sha256", "commit_head", "history_root_sha256", "license"}),
        f"{slot} source",
    )
    for key in ("source_tree_sha256", "vcs_bundle_sha256", "history_root_sha256"):
        _sha(source[key], f"{slot} source {key}")
    _identifier(source["commit_head"], f"{slot} commit_head")
    _identifier(source["license"], f"{slot} license")
    archive = _exact(
        raw["archive"],
        frozenset({"archive_sha256", "package_sha256", "file_manifest_root_sha256"}),
        f"{slot} archive",
    )
    for key in archive:
        _sha(archive[key], f"{slot} archive {key}")
    build = _exact(
        raw["build"],
        frozenset({"build_recipe_sha256", "build_container_digest", "toolchain_lock_sha256", "expected_archive_sha256"}),
        f"{slot} build",
    )
    _sha(build["build_recipe_sha256"], f"{slot} build recipe")
    _sha(build["toolchain_lock_sha256"], f"{slot} toolchain lock")
    _sha(build["expected_archive_sha256"], f"{slot} expected archive")
    if type(build["build_container_digest"]) is not str or _CONTAINER_RE.fullmatch(build["build_container_digest"]) is None:
        raise AttestationV623Error(f"{slot} build container digest is invalid")
    if build["expected_archive_sha256"] != archive["archive_sha256"]:
        raise AttestationV623Error(f"{slot} build does not reproduce the declared archive")
    if build["build_container_digest"] != campaign["build_container_digest"]:
        raise AttestationV623Error(f"{slot} build container is not campaign-pinned")
    engine = _exact(raw["engine"], frozenset({"engine_version", "engine_sha256", "ruleset_sha256"}), f"{slot} engine")
    _identifier(engine["engine_version"], f"{slot} engine version")
    _sha(engine["engine_sha256"], f"{slot} engine digest")
    _sha(engine["ruleset_sha256"], f"{slot} ruleset digest")
    if (
        engine["engine_sha256"] != campaign["engine_sha256"]
        or engine["ruleset_sha256"] != campaign["ruleset_sha256"]
    ):
        raise AttestationV623Error(f"{slot} engine or ruleset is not campaign-pinned")
    ancestry = _exact(
        raw["authorship_ancestry"],
        frozenset(
            {
                "authors",
                "prior_sources",
                "forks_or_derivations",
                "codegen_tools",
                "independence_declaration",
                "development_window_utc",
                "exposure_declaration",
            }
        ),
        f"{slot} authorship ancestry",
    )
    _string_list(ancestry["authors"], f"{slot} authors", allow_empty=False)
    _string_list(ancestry["prior_sources"], f"{slot} prior_sources")
    _string_list(ancestry["forks_or_derivations"], f"{slot} forks_or_derivations")
    _string_list(ancestry["codegen_tools"], f"{slot} codegen_tools")
    _identifier(ancestry["independence_declaration"], f"{slot} independence declaration")
    _identifier(ancestry["exposure_declaration"], f"{slot} exposure declaration")
    if type(ancestry["development_window_utc"]) is not list or len(ancestry["development_window_utc"]) != 2:
        raise AttestationV623Error(f"{slot} development window must contain [start, end]")
    start = _utc(ancestry["development_window_utc"][0], f"{slot} development start")
    end = _utc(ancestry["development_window_utc"][1], f"{slot} development end")
    if start >= end:
        raise AttestationV623Error(f"{slot} development window is empty or reversed")
    return raw


def _validate_technical_receipt(
    value: Any,
    *,
    campaign: Mapping[str, str],
    slot: str,
    contributor: Mapping[str, Any],
) -> Mapping[str, Any]:
    raw = _exact(
        value,
        frozenset(
            {
                "schema",
                "campaign_id",
                "campaign_nonce",
                "unit_nonce",
                "slot_id",
                "audit_session_id",
                "contributor_manifest_sha256",
                "auditor",
                "source_checkout_sha256",
                "build_recipe_sha256",
                "build_container_digest",
                "toolchain_lock_sha256",
                "commands_manifest_sha256",
                "expected_archive_sha256",
                "produced_archive_sha256",
                "engine_sha256",
                "ruleset_sha256",
                "linux",
                "safety",
                "evidence_roots",
            }
        ),
        f"{slot} technical receipt",
    )
    if raw["schema"] != TECHNICAL_SCHEMA or raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"] or raw["unit_nonce"] != contributor["unit_nonce"] or raw["slot_id"] != slot:
        raise AttestationV623Error(f"{slot} technical receipt is not campaign/unit-bound")
    _nonce(raw["audit_session_id"], f"{slot} technical audit_session_id")
    if _sha(raw["contributor_manifest_sha256"], f"{slot} contributor manifest reference") != canonical_sha256(contributor):
        raise AttestationV623Error(f"{slot} technical receipt does not bind its contributor manifest")
    auditor = _exact(raw["auditor"], frozenset({"key_id", "entity_id"}), f"{slot} technical auditor")
    _identifier(auditor["key_id"], f"{slot} technical auditor key_id")
    _identifier(auditor["entity_id"], f"{slot} technical auditor entity_id")
    for key in (
        "source_checkout_sha256",
        "build_recipe_sha256",
        "toolchain_lock_sha256",
        "commands_manifest_sha256",
        "expected_archive_sha256",
        "produced_archive_sha256",
        "engine_sha256",
        "ruleset_sha256",
    ):
        _sha(raw[key], f"{slot} technical {key}")
    if type(raw["build_container_digest"]) is not str or _CONTAINER_RE.fullmatch(raw["build_container_digest"]) is None:
        raise AttestationV623Error(f"{slot} technical container digest is invalid")
    source = contributor["source"]
    archive = contributor["archive"]
    build = contributor["build"]
    engine = contributor["engine"]
    expected_equalities = {
        "source_checkout_sha256": source["source_tree_sha256"],
        "build_recipe_sha256": build["build_recipe_sha256"],
        "build_container_digest": build["build_container_digest"],
        "toolchain_lock_sha256": build["toolchain_lock_sha256"],
        "expected_archive_sha256": archive["archive_sha256"],
        "produced_archive_sha256": archive["archive_sha256"],
        "engine_sha256": engine["engine_sha256"],
        "ruleset_sha256": engine["ruleset_sha256"],
    }
    for key, expected in expected_equalities.items():
        if raw[key] != expected:
            raise AttestationV623Error(f"{slot} technical {key} does not match contributor evidence")
    linux = _exact(
        raw["linux"],
        frozenset({"arch", "container_digest", "startup_log_sha256", "run_log_sha256", "deterministic_handshake_sha256", "crash_count", "timeout_count"}),
        f"{slot} Linux evidence",
    )
    if linux["arch"] != "linux/amd64" or linux["container_digest"] != build["build_container_digest"]:
        raise AttestationV623Error(f"{slot} Linux evidence has the wrong architecture or container")
    for key in ("startup_log_sha256", "run_log_sha256", "deterministic_handshake_sha256"):
        _sha(linux[key], f"{slot} Linux {key}")
    for key in ("crash_count", "timeout_count"):
        if type(linux[key]) is not int or isinstance(linux[key], bool) or linux[key] != 0:
            raise AttestationV623Error(f"{slot} Linux {key} must be zero")
    safety = _exact(
        raw["safety"],
        frozenset({"policy_sha256", "evidence_root_sha256", "dudunsparce_audit_sha256", "disallowed_syscall_count", "network_violation_count", "filesystem_violation_count", "process_violation_count"}),
        f"{slot} safety evidence",
    )
    for key in ("policy_sha256", "evidence_root_sha256", "dudunsparce_audit_sha256"):
        _sha(safety[key], f"{slot} safety {key}")
    if safety["policy_sha256"] != campaign["safety_policy_sha256"]:
        raise AttestationV623Error(f"{slot} safety policy is not campaign-pinned")
    if safety["dudunsparce_audit_sha256"] != campaign["dudunsparce_harness_sha256"]:
        raise AttestationV623Error(f"{slot} Dudunsparce audit is not campaign-pinned")
    for key in ("disallowed_syscall_count", "network_violation_count", "filesystem_violation_count", "process_violation_count"):
        if type(safety[key]) is not int or isinstance(safety[key], bool) or safety[key] != 0:
            raise AttestationV623Error(f"{slot} safety {key} must be zero")
    roots = _exact(
        raw["evidence_roots"],
        frozenset({"repro_evidence_root_sha256", "linux_evidence_root_sha256", "safety_evidence_root_sha256"}),
        f"{slot} technical evidence roots",
    )
    for key in roots:
        _sha(roots[key], f"{slot} technical {key}")
    if roots["safety_evidence_root_sha256"] != safety["evidence_root_sha256"]:
        raise AttestationV623Error(f"{slot} safety root is not internally consistent")
    return raw


def _validate_lineage_receipt(
    value: Any,
    *,
    campaign: Mapping[str, str],
    slot: str,
    contributor: Mapping[str, Any],
) -> Mapping[str, Any]:
    raw = _exact(
        value,
        frozenset(
            {
                "schema",
                "campaign_id",
                "campaign_nonce",
                "unit_nonce",
                "slot_id",
                "audit_session_id",
                "contributor_manifest_sha256",
                "auditor",
                "vcs_bundle_sha256",
                "commit_graph_sha256",
                "authorship_evidence_sha256",
                "public_references_root_sha256",
                "similarity_report_root_sha256",
                "provenance_evidence_root_sha256",
                "findings",
            }
        ),
        f"{slot} lineage receipt",
    )
    if raw["schema"] != LINEAGE_SCHEMA or raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"] or raw["unit_nonce"] != contributor["unit_nonce"] or raw["slot_id"] != slot:
        raise AttestationV623Error(f"{slot} lineage receipt is not campaign/unit-bound")
    _nonce(raw["audit_session_id"], f"{slot} lineage audit_session_id")
    if _sha(raw["contributor_manifest_sha256"], f"{slot} contributor manifest reference") != canonical_sha256(contributor):
        raise AttestationV623Error(f"{slot} lineage receipt does not bind its contributor manifest")
    auditor = _exact(raw["auditor"], frozenset({"key_id", "entity_id"}), f"{slot} lineage auditor")
    _identifier(auditor["key_id"], f"{slot} lineage auditor key_id")
    _identifier(auditor["entity_id"], f"{slot} lineage auditor entity_id")
    for key in (
        "vcs_bundle_sha256",
        "commit_graph_sha256",
        "authorship_evidence_sha256",
        "public_references_root_sha256",
        "similarity_report_root_sha256",
        "provenance_evidence_root_sha256",
    ):
        _sha(raw[key], f"{slot} lineage {key}")
    if raw["vcs_bundle_sha256"] != contributor["source"]["vcs_bundle_sha256"]:
        raise AttestationV623Error(f"{slot} lineage receipt binds the wrong VCS bundle")
    if type(raw["findings"]) is not list or len(raw["findings"]) != len(SLOTS) - 1:
        raise AttestationV623Error(f"{slot} lineage receipt must compare every other slot")
    expected_others = set(SLOTS) - {slot}
    actual_others: set[str] = set()
    for index, item in enumerate(raw["findings"]):
        finding = _exact(
            item,
            frozenset({"other_slot_id", "relation", "evidence_root_sha256"}),
            f"{slot} lineage finding {index}",
        )
        other = finding["other_slot_id"]
        if other not in expected_others or other in actual_others:
            raise AttestationV623Error(f"{slot} lineage comparison set is incomplete or duplicated")
        if finding["relation"] not in _RELATIONS:
            raise AttestationV623Error(f"{slot} lineage finding relation is unknown")
        _sha(finding["evidence_root_sha256"], f"{slot} lineage finding evidence")
        actual_others.add(other)
    if actual_others != expected_others:
        raise AttestationV623Error(f"{slot} lineage receipt did not compare all other slots")
    return raw


def _validate_graph(
    value: Any,
    *,
    campaign: Mapping[str, str],
    units: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    raw = _exact(
        value,
        frozenset({"schema", "campaign_id", "campaign_nonce", "nodes", "edges"}),
        "population graph",
    )
    if raw["schema"] != POPULATION_GRAPH_SCHEMA or raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"]:
        raise AttestationV623Error("population graph is not campaign-bound")
    if type(raw["nodes"]) is not list or len(raw["nodes"]) != len(SLOTS):
        raise AttestationV623Error("population graph must contain exactly 16 nodes")
    for expected_slot, item in zip(SLOTS, raw["nodes"]):
        node = _exact(
            item,
            frozenset({"slot_id", "source_tree_sha256", "contributor_manifest_sha256", "technical_receipt_sha256", "lineage_receipt_sha256"}),
            f"population graph node {expected_slot}",
        )
        unit = units[expected_slot]
        expected = {
            "slot_id": expected_slot,
            "source_tree_sha256": unit["contributor"]["source"]["source_tree_sha256"],
            "contributor_manifest_sha256": canonical_sha256(unit["contributor"]),
            "technical_receipt_sha256": canonical_sha256(unit["technical"]),
            "lineage_receipt_sha256": canonical_sha256(unit["lineage"]),
        }
        if dict(node) != expected:
            raise AttestationV623Error(f"population graph node {expected_slot} is not evidence-bound")
    required_pairs = {
        (SLOTS[left], SLOTS[right])
        for left in range(len(SLOTS))
        for right in range(left + 1, len(SLOTS))
    }
    if type(raw["edges"]) is not list or len(raw["edges"]) != len(required_pairs):
        raise AttestationV623Error("population graph must adjudicate all 120 slot pairs")
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(raw["edges"]):
        edge = _exact(
            item,
            frozenset({"left_slot_id", "right_slot_id", "relation", "evidence_root_sha256"}),
            f"population graph edge {index}",
        )
        pair = (edge["left_slot_id"], edge["right_slot_id"])
        if pair not in required_pairs or pair in seen:
            raise AttestationV623Error("population graph edge order or uniqueness is invalid")
        if edge["relation"] not in _RELATIONS:
            raise AttestationV623Error("population graph edge relation is unknown")
        _sha(edge["evidence_root_sha256"], "population graph edge evidence")
        seen.add(pair)
    if seen != required_pairs:
        raise AttestationV623Error("population graph did not adjudicate every slot pair")
    return raw


def _cross_check_graph_against_lineage(
    graph: Mapping[str, Any], units: Mapping[str, Mapping[str, Any]]
) -> None:
    findings: dict[tuple[str, str], str] = {}
    for slot in SLOTS:
        for finding in units[slot]["lineage"]["findings"]:
            findings[(slot, finding["other_slot_id"])] = finding["relation"]
    for edge in graph["edges"]:
        left = edge["left_slot_id"]
        right = edge["right_slot_id"]
        left_relation = findings[(left, right)]
        right_relation = findings[(right, left)]
        if (
            edge["relation"] != "INDEPENDENT"
            or left_relation != "INDEPENDENT"
            or right_relation != "INDEPENDENT"
        ):
            raise AttestationV623Error(
                f"{left}/{right} has unknown, shared, derived, or conflicting lineage evidence"
            )


def _active_slots(primary: tuple[str, ...], reserve: str) -> tuple[tuple[str, ...], ...]:
    return (primary,) + tuple(
        tuple(reserve if slot == failed else slot for slot in primary) for failed in primary
    )


def _validate_intervention_diversity(assignments: Mapping[str, Mapping[str, str]]) -> None:
    scenarios = (
        (_active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT), 3, "DEV"),
        (_active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT), 4, "CONFIRM"),
    )
    for active_sets, minimum, tranche in scenarios:
        for active in active_sets:
            if len({assignments[slot]["intervention_family_id"] for slot in active}) < minimum:
                raise AttestationV623Error(
                    f"{tranche} intervention diversity fails under reserve replacement"
                )
    for dev_active in _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT):
        for confirm_active in _active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT):
            active = dev_active + confirm_active
            if len({assignments[slot]["intervention_family_id"] for slot in active}) < 5:
                raise AttestationV623Error(
                    "overall intervention diversity fails under reserve replacement"
                )


def _validate_population_decision(
    value: Any,
    *,
    campaign: Mapping[str, str],
    graph: Mapping[str, Any],
    units: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Mapping[str, str]]:
    raw = _exact(
        value,
        frozenset({"schema", "campaign_id", "campaign_nonce", "population_graph_sha256", "assignments"}),
        "population decision",
    )
    if raw["schema"] != POPULATION_DECISION_SCHEMA or raw["campaign_id"] != campaign["campaign_id"] or raw["campaign_nonce"] != campaign["campaign_nonce"]:
        raise AttestationV623Error("population decision is not campaign-bound")
    if _sha(raw["population_graph_sha256"], "population graph reference") != canonical_sha256(graph):
        raise AttestationV623Error("population decision does not bind the exact graph")
    if any(edge["relation"] != "INDEPENDENT" for edge in graph["edges"]):
        raise AttestationV623Error("unknown, shared, or derived graph edges cannot be split into independent families")
    if type(raw["assignments"]) is not list or len(raw["assignments"]) != len(SLOTS):
        raise AttestationV623Error("population decision must contain exactly 16 assignments")
    assignments: dict[str, Mapping[str, str]] = {}
    for expected_slot, item in zip(SLOTS, raw["assignments"]):
        assignment = _exact(
            item,
            frozenset({"slot_id", "source_family_id", "lineage_time_block_id", "intervention_family_id", "family_evidence_root_sha256", "lineage_evidence_root_sha256"}),
            f"population assignment {expected_slot}",
        )
        if assignment["slot_id"] != expected_slot:
            raise AttestationV623Error("population assignments must use canonical slot order")
        family_root = _sha(assignment["family_evidence_root_sha256"], f"{expected_slot} family root")
        lineage_root = _sha(assignment["lineage_evidence_root_sha256"], f"{expected_slot} lineage root")
        source_tree = units[expected_slot]["contributor"]["source"]["source_tree_sha256"]
        expected_family = "sf-" + canonical_sha256(
            {"members": [source_tree], "evidence_root": family_root}
        )[:24]
        expected_lineage = "lt-" + canonical_sha256(
            {"component": [expected_slot], "evidence_root": lineage_root}
        )[:24]
        if assignment["source_family_id"] != expected_family or _FAMILY_RE.fullmatch(assignment["source_family_id"]) is None:
            raise AttestationV623Error(f"{expected_slot} source_family_id is not auditor-derived")
        if assignment["lineage_time_block_id"] != expected_lineage or _LINEAGE_RE.fullmatch(assignment["lineage_time_block_id"]) is None:
            raise AttestationV623Error(f"{expected_slot} lineage_time_block_id is not auditor-derived")
        _identifier(assignment["intervention_family_id"], f"{expected_slot} intervention family")
        assignments[expected_slot] = dict(assignment)
    for field in ("source_family_id", "lineage_time_block_id"):
        values = [assignments[slot][field] for slot in SLOTS]
        if len(values) != len(set(values)):
            raise AttestationV623Error(f"all 16 {field} values must be pairwise distinct")
    _validate_intervention_diversity(assignments)
    return assignments


def _role_caps(units: Mapping[str, Mapping[str, Any]]) -> None:
    contributors = {slot: units[slot]["contributor_key"]["entity_id"] for slot in SLOTS}
    technical = {slot: units[slot]["technical_key"]["entity_id"] for slot in SLOTS}
    lineage = {slot: units[slot]["lineage_key"]["entity_id"] for slot in SLOTS}
    contributor_counts = Counter(contributors.values())
    if len(contributor_counts) < 13 or max(contributor_counts.values()) > 2:
        raise AttestationV623Error("contributors require at least 13 entities and at most two units each")
    dev_primary_entities = {contributors[slot] for slot in DEV_PRIMARY_SLOTS}
    confirm_entities = {contributors[slot] for slot in CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)}
    if len(dev_primary_entities) < 3:
        raise AttestationV623Error("DEV primaries require at least three contributor entities")
    if len(confirm_entities) != 9:
        raise AttestationV623Error("CONFIRM primaries and reserve require nine distinct contributors")
    dev_reserve_entity = contributors[DEV_RESERVE_SLOT]
    if dev_reserve_entity in dev_primary_entities or dev_reserve_entity in confirm_entities:
        raise AttestationV623Error("DR01 requires a fourth DEV-only contributor")
    dev_entities = dev_primary_entities | {dev_reserve_entity}
    if dev_entities & confirm_entities:
        raise AttestationV623Error("contributor entities cannot cross DEV and CONFIRM tranches")
    for role_name, values in (("technical", technical), ("lineage", lineage)):
        counts = Counter(values.values())
        if len(counts) < 4 or max(counts.values()) > 4:
            raise AttestationV623Error(f"{role_name} auditors require at least four entities and at most four units each")
    pair_counts = Counter((technical[slot], lineage[slot]) for slot in SLOTS)
    if max(pair_counts.values()) > 2:
        raise AttestationV623Error("one technical/lineage auditor pair cannot review more than two units")


def verify_population_trust_bundle(
    value: Any,
    *,
    pinned_registry_admins: Mapping[str, PinnedRegistryAdmin],
    external_verifier: ExternalEvidenceVerifier | None = None,
    pinned_external_verifier: PinnedExternalVerifier | None = None,
) -> dict[str, Any]:
    """Verify a v6.2.3 trust bundle without ever authorizing an upload.

    With no external verifier, a cryptographically valid bundle can reach only
    ``STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER``.  With a
    separately reviewed verifier whose build and policy hashes match the frozen
    campaign, all checks may reach
    ``POPULATION_AUTHENTICATED_LOCAL_EVIDENCE_PENDING``.  Neither state grants a
    permit or submission authority.
    """

    bundle = _exact(
        value,
        frozenset(
            {
                "schema",
                "campaign",
                "registry",
                "registry_approvals",
                "revocation_log",
                "revocation_approvals",
                "units",
                "population_graph",
                "population_decision",
                "population_decision_approvals",
            }
        ),
        "population trust bundle",
    )
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise AttestationV623Error(f"bundle schema must be {BUNDLE_SCHEMA}")
    if external_verifier is not None or pinned_external_verifier is not None:
        raise AttestationV623Error(
            "the v6.2.3 callback-based external verification route is retired; "
            "a code-allowlisted release root and 2-of-3 signed comprehensive "
            "verification receipts are required"
        )
    campaign = _campaign(bundle["campaign"])
    admins = _validate_admin_roots(pinned_registry_admins)
    external_roots: list[str] = []
    timestamp_tokens: set[str] = set()
    if (external_verifier is None) != (pinned_external_verifier is None):
        raise AttestationV623Error(
            "external verifier implementation and independently pinned signing root must be supplied together"
        )
    if pinned_external_verifier is not None:
        pinned_external_verifier = _validate_pinned_external_verifier(
            pinned_external_verifier
        )
        if pinned_external_verifier.verifier_build_sha256 != campaign["semantic_verifier_build_sha256"]:
            raise AttestationV623Error("external verifier build is not campaign-pinned")
        if pinned_external_verifier.trust_policy_sha256 != campaign["trust_policy_sha256"]:
            raise AttestationV623Error("external verifier trust policy is not campaign-pinned")
        if (
            pinned_external_verifier.timestamp_policy_sha256
            != campaign["timestamp_policy_sha256"]
        ):
            raise AttestationV623Error("external verifier timestamp policy is not campaign-pinned")
    admin_entities = {admin.entity_id for admin in admins.values()}
    registry, registry_payload = _registry(bundle["registry"], campaign=campaign)
    reserved_external_entities = set(admin_entities)
    if pinned_external_verifier is not None:
        reserved_external_entities.add(pinned_external_verifier.entity_id)
    if reserved_external_entities & {key["entity_id"] for key in registry.values()}:
        raise AttestationV623Error("registry administrators must be disjoint from C/T/L/A entities")
    _verify_admin_approvals(
        registry_payload,
        bundle["registry_approvals"],
        artifact_schema=REGISTRY_SCHEMA,
        domain=DOMAIN_REGISTRY,
        admins=admins,
        external_verifier=external_verifier,
        pinned_external_verifier=pinned_external_verifier,
        external_roots=external_roots,
        timestamp_tokens=timestamp_tokens,
    )
    revocations, revocation_payload = _revocations(
        bundle["revocation_log"], campaign=campaign, registry=registry
    )
    _verify_admin_approvals(
        revocation_payload,
        bundle["revocation_approvals"],
        artifact_schema=REVOCATION_SCHEMA,
        domain=DOMAIN_REVOCATION,
        admins=admins,
        external_verifier=external_verifier,
        pinned_external_verifier=pinned_external_verifier,
        external_roots=external_roots,
        timestamp_tokens=timestamp_tokens,
    )
    if type(bundle["units"]) is not list or len(bundle["units"]) != len(SLOTS):
        raise AttestationV623Error("bundle must contain exactly 16 unit evidence records")
    units: dict[str, dict[str, Any]] = {}
    unit_nonces: set[str] = set()
    audit_sessions: set[str] = set()
    used_registry_keys: set[str] = set()
    semantic_roots: list[str] = []
    for expected_slot, item in zip(SLOTS, bundle["units"]):
        unit = _exact(
            item,
            frozenset({"slot_id", "contributor_manifest", "contributor_signature", "technical_receipt", "technical_signature", "lineage_receipt", "lineage_signature"}),
            f"unit evidence {expected_slot}",
        )
        if unit["slot_id"] != expected_slot:
            raise AttestationV623Error("unit evidence records must use canonical slot order")
        contributor = _validate_contributor_manifest(
            unit["contributor_manifest"], campaign=campaign, slot=expected_slot
        )
        unit_nonce = contributor["unit_nonce"]
        if unit_nonce in unit_nonces:
            raise AttestationV623Error("unit_nonce values must be globally unique")
        unit_nonces.add(unit_nonce)
        contributor_key_id = contributor["contributor"]["key_id"]
        contributor_registry = registry.get(contributor_key_id)
        if contributor_registry is None:
            raise AttestationV623Error("contributor key is not registered")
        _claim_timestamp_token(unit["contributor_signature"], timestamp_tokens)
        _, contributor_signed_at, contributor_message = _verify_detached_envelope(
            unit["contributor_signature"],
            payload=contributor,
            artifact_schema=CONTRIBUTOR_SCHEMA,
            domain=DOMAIN_CONTRIBUTOR,
            public_key=contributor_registry["public_key"],
        )
        contributor_effective_time = contributor_signed_at
        if external_verifier is not None:
            root, contributor_effective_time = _verify_external_timestamp(
                external_verifier,
                pinned_external_verifier,
                payload_message=contributor_message,
                envelope=unit["contributor_signature"],
            )
            external_roots.append(root)
            if abs((contributor_effective_time - contributor_signed_at).total_seconds()) > 300:
                raise AttestationV623Error(
                    "contributor signed_at_utc differs from trusted time by over 5 minutes"
                )
        contributor_key = _active_signer(
            contributor_key_id,
            role=ROLE_CONTRIBUTOR,
            registry=registry,
            revocations=revocations,
            signed_at=contributor_effective_time,
        )
        if contributor["contributor"]["entity_id"] != contributor_key["entity_id"]:
            raise AttestationV623Error("contributor manifest entity does not match the registry")
        technical = _validate_technical_receipt(
            unit["technical_receipt"],
            campaign=campaign,
            slot=expected_slot,
            contributor=contributor,
        )
        technical_key_id = technical["auditor"]["key_id"]
        technical_registry = registry.get(technical_key_id)
        if technical_registry is None:
            raise AttestationV623Error("technical auditor key is not registered")
        _claim_timestamp_token(unit["technical_signature"], timestamp_tokens)
        _, technical_signed_at, technical_message = _verify_detached_envelope(
            unit["technical_signature"],
            payload=technical,
            artifact_schema=TECHNICAL_SCHEMA,
            domain=DOMAIN_TECHNICAL,
            public_key=technical_registry["public_key"],
        )
        technical_effective_time = technical_signed_at
        if external_verifier is not None:
            root, technical_effective_time = _verify_external_timestamp(
                external_verifier,
                pinned_external_verifier,
                payload_message=technical_message,
                envelope=unit["technical_signature"],
            )
            external_roots.append(root)
            if abs((technical_effective_time - technical_signed_at).total_seconds()) > 300:
                raise AttestationV623Error(
                    "technical signed_at_utc differs from trusted time by over 5 minutes"
                )
        technical_key = _active_signer(
            technical_key_id,
            role=ROLE_TECHNICAL,
            registry=registry,
            revocations=revocations,
            signed_at=technical_effective_time,
        )
        if technical["auditor"]["entity_id"] != technical_key["entity_id"]:
            raise AttestationV623Error("technical auditor entity does not match the registry")
        lineage = _validate_lineage_receipt(
            unit["lineage_receipt"],
            campaign=campaign,
            slot=expected_slot,
            contributor=contributor,
        )
        lineage_key_id = lineage["auditor"]["key_id"]
        lineage_registry = registry.get(lineage_key_id)
        if lineage_registry is None:
            raise AttestationV623Error("lineage auditor key is not registered")
        _claim_timestamp_token(unit["lineage_signature"], timestamp_tokens)
        _, lineage_signed_at, lineage_message = _verify_detached_envelope(
            unit["lineage_signature"],
            payload=lineage,
            artifact_schema=LINEAGE_SCHEMA,
            domain=DOMAIN_LINEAGE,
            public_key=lineage_registry["public_key"],
        )
        lineage_effective_time = lineage_signed_at
        if external_verifier is not None:
            root, lineage_effective_time = _verify_external_timestamp(
                external_verifier,
                pinned_external_verifier,
                payload_message=lineage_message,
                envelope=unit["lineage_signature"],
            )
            external_roots.append(root)
            if abs((lineage_effective_time - lineage_signed_at).total_seconds()) > 300:
                raise AttestationV623Error(
                    "lineage signed_at_utc differs from trusted time by over 5 minutes"
                )
        lineage_key = _active_signer(
            lineage_key_id,
            role=ROLE_LINEAGE,
            registry=registry,
            revocations=revocations,
            signed_at=lineage_effective_time,
        )
        if lineage["auditor"]["entity_id"] != lineage_key["entity_id"]:
            raise AttestationV623Error("lineage auditor entity does not match the registry")
        entities = {
            contributor_key["entity_id"],
            technical_key["entity_id"],
            lineage_key["entity_id"],
        }
        if len(entities) != 3:
            raise AttestationV623Error("C/T/L entities must be pairwise distinct for every unit")
        for session_id in (technical["audit_session_id"], lineage["audit_session_id"]):
            if session_id in audit_sessions:
                raise AttestationV623Error("audit_session_id is replayed")
            audit_sessions.add(session_id)
        used_registry_keys.update({contributor_key_id, technical_key_id, lineage_key_id})
        if external_verifier is not None:
            technical_root, technical_time = _external_check(
                    external_verifier.verify_technical(technical, contributor),
                    kind="TECHNICAL_SEMANTICS",
                    subject_sha256=canonical_sha256(technical),
                    pinned_verifier=pinned_external_verifier,
                )
            if technical_time is not None:
                raise AttestationV623Error("technical semantic check asserted a trusted time")
            semantic_roots.append(technical_root)
            lineage_root, lineage_time = _external_check(
                    external_verifier.verify_lineage(lineage, contributor),
                    kind="LINEAGE_SEMANTICS",
                    subject_sha256=canonical_sha256(lineage),
                    pinned_verifier=pinned_external_verifier,
                )
            if lineage_time is not None:
                raise AttestationV623Error("lineage semantic check asserted a trusted time")
            semantic_roots.append(lineage_root)
        units[expected_slot] = {
            "contributor": contributor,
            "technical": technical,
            "lineage": lineage,
            "contributor_key": contributor_key,
            "technical_key": technical_key,
            "lineage_key": lineage_key,
        }
    _role_caps(units)
    for field, label in (
        ("archive_sha256", "archive_sha256"),
        ("source_tree_sha256", "source_tree_sha256"),
    ):
        if field == "archive_sha256":
            values = [units[slot]["contributor"]["archive"][field] for slot in SLOTS]
        else:
            values = [units[slot]["contributor"]["source"][field] for slot in SLOTS]
        if len(values) != len(set(values)):
            raise AttestationV623Error(f"all 16 {label} values must be pairwise distinct")
    graph = _validate_graph(bundle["population_graph"], campaign=campaign, units=units)
    _cross_check_graph_against_lineage(graph, units)
    assignments = _validate_population_decision(
        bundle["population_decision"], campaign=campaign, graph=graph, units=units
    )
    del assignments
    adjudicators = {
        key_id: key for key_id, key in registry.items() if key["role"] == ROLE_ADJUDICATOR
    }
    approvals = bundle["population_decision_approvals"]
    if type(approvals) is not list:
        raise AttestationV623Error("population decision approvals must be an array")
    adjudicator_signers: set[str] = set()
    for envelope in approvals:
        if type(envelope) is not dict:
            raise AttestationV623Error("population decision approval must be an object")
        key_id = envelope.get("key_id")
        if key_id not in adjudicators or key_id in adjudicator_signers:
            raise AttestationV623Error("population adjudicator is unknown or duplicated")
        key = adjudicators[key_id]
        _claim_timestamp_token(envelope, timestamp_tokens)
        _, signed_at, message = _verify_detached_envelope(
            envelope,
            payload=bundle["population_decision"],
            artifact_schema=POPULATION_DECISION_SCHEMA,
            domain=DOMAIN_POPULATION,
            public_key=key["public_key"],
        )
        effective_time = signed_at
        if external_verifier is not None:
            root, effective_time = _verify_external_timestamp(
                external_verifier,
                pinned_external_verifier,
                payload_message=message,
                envelope=envelope,
            )
            external_roots.append(root)
            if abs((effective_time - signed_at).total_seconds()) > 300:
                raise AttestationV623Error(
                    "adjudicator signed_at_utc differs from trusted time by over 5 minutes"
                )
        _active_signer(
            key_id,
            role=ROLE_ADJUDICATOR,
            registry=registry,
            revocations=revocations,
            signed_at=effective_time,
        )
        used_registry_keys.add(key_id)
        adjudicator_signers.add(key_id)
    if len(adjudicator_signers) < 2:
        raise AttestationV623Error("population decision requires two of three adjudicators")
    if external_verifier is not None:
        for key_id in sorted(used_registry_keys):
            key = registry[key_id]
            identity_root, identity_time = _external_check(
                    external_verifier.verify_identity(key["raw"]),
                    kind="IDENTITY",
                    subject_sha256=canonical_sha256(key["raw"]),
                    pinned_verifier=pinned_external_verifier,
                )
            if identity_time is not None:
                raise AttestationV623Error("identity check asserted a trusted time")
            external_roots.append(identity_root)
    external_authentication_verified = external_verifier is not None
    semantic_complete = external_verifier is not None and len(semantic_roots) == 32
    population_feasible = external_authentication_verified and semantic_complete
    state = (
        "POPULATION_AUTHENTICATED_LOCAL_EVIDENCE_PENDING"
        if population_feasible
        else "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER"
    )
    checks = {
        "registry_valid": True,
        "all_signatures_valid": True,
        "timestamps_valid": external_authentication_verified,
        "nonces_unique": True,
        "role_separation_valid": True,
        "contributor_manifests_valid": True,
        "technical_audits_verified_16": semantic_complete,
        "lineage_audits_verified_16": semantic_complete,
        "collision_graph_adjudicated": True,
        "source_family_count_16": True,
        "lineage_time_block_count_16": True,
        "intervention_diversity_valid": True,
        "auditor_caps_valid": True,
        "no_revoked_keys_used": True,
    }
    return {
        "schema": VERDICT_SCHEMA,
        "state": state,
        "campaign_binding_sha256": canonical_sha256(bundle["campaign"]),
        "registry_sha256": canonical_sha256(bundle["registry"]),
        "revocation_log_sha256": canonical_sha256(bundle["revocation_log"]),
        "population_graph_sha256": canonical_sha256(bundle["population_graph"]),
        "population_decision_sha256": canonical_sha256(bundle["population_decision"]),
        "cryptographic_bundle_valid": True,
        "external_authentication_verified": external_authentication_verified,
        "semantic_artifact_verification_complete": semantic_complete,
        "population_feasible": population_feasible,
        "checks": checks,
        "external_evidence_root_sha256": canonical_sha256(sorted(external_roots)) if external_roots else None,
        "semantic_evidence_root_sha256": canonical_sha256(sorted(semantic_roots)) if semantic_roots else None,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }


def assess_population_trust_bundle(
    value: Any,
    *,
    pinned_registry_admins: Mapping[str, PinnedRegistryAdmin],
    external_verifier: ExternalEvidenceVerifier | None = None,
    pinned_external_verifier: PinnedExternalVerifier | None = None,
) -> dict[str, Any]:
    """Return a stable fail-closed verdict for malformed or incomplete evidence."""

    try:
        return verify_population_trust_bundle(
            value,
            pinned_registry_admins=pinned_registry_admins,
            external_verifier=external_verifier,
            pinned_external_verifier=pinned_external_verifier,
        )
    except AttestationV623Error as exc:
        return {
            "schema": VERDICT_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "failure": str(exc),
            "cryptographic_bundle_valid": False,
            "external_authentication_verified": False,
            "semantic_artifact_verification_complete": False,
            "population_feasible": False,
            "checks": {},
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
            "sealed_holdout_accessed": False,
        }


def verify_population_trust_file(
    path: str | Path,
    *,
    pinned_registry_admins: Mapping[str, PinnedRegistryAdmin],
    external_verifier: ExternalEvidenceVerifier | None = None,
    pinned_external_verifier: PinnedExternalVerifier | None = None,
) -> dict[str, Any]:
    """Securely read and verify one canonical population trust bundle file."""

    return verify_population_trust_bundle(
        read_canonical_trust_bundle(path),
        pinned_registry_admins=pinned_registry_admins,
        external_verifier=external_verifier,
        pinned_external_verifier=pinned_external_verifier,
    )


def assess_population_trust_file(
    path: str | Path,
    *,
    pinned_registry_admins: Mapping[str, PinnedRegistryAdmin],
    external_verifier: ExternalEvidenceVerifier | None = None,
    pinned_external_verifier: PinnedExternalVerifier | None = None,
) -> dict[str, Any]:
    """Securely read a bundle and convert all intake failures to NO_UPLOAD."""

    try:
        bundle = read_canonical_trust_bundle(path)
    except AttestationV623Error as exc:
        return {
            "schema": VERDICT_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "failure": str(exc),
            "cryptographic_bundle_valid": False,
            "external_authentication_verified": False,
            "semantic_artifact_verification_complete": False,
            "population_feasible": False,
            "checks": {},
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
            "sealed_holdout_accessed": False,
        }
    return assess_population_trust_bundle(
        bundle,
        pinned_registry_admins=pinned_registry_admins,
        external_verifier=external_verifier,
        pinned_external_verifier=pinned_external_verifier,
    )


__all__ = [
    "AttestationV623Error",
    "BUNDLE_SCHEMA",
    "CAMPAIGN_SCHEMA",
    "CONTRIBUTOR_SCHEMA",
    "DOMAIN_CONTRIBUTOR",
    "DOMAIN_EXTERNAL_CHECK",
    "DOMAIN_LINEAGE",
    "DOMAIN_POPULATION",
    "DOMAIN_REGISTRY",
    "DOMAIN_REVOCATION",
    "DOMAIN_TECHNICAL",
    "ENVELOPE_SCHEMA",
    "EXTERNAL_CHECK_SCHEMA",
    "EXTERNAL_CHECK_ENVELOPE_SCHEMA",
    "ExternalEvidenceVerifier",
    "LINEAGE_SCHEMA",
    "POPULATION_DECISION_SCHEMA",
    "POPULATION_GRAPH_SCHEMA",
    "PinnedRegistryAdmin",
    "PinnedExternalVerifier",
    "REGISTRY_SCHEMA",
    "REVOCATION_SCHEMA",
    "ROLE_ADJUDICATOR",
    "ROLE_CONTRIBUTOR",
    "ROLE_LINEAGE",
    "ROLE_REGISTRY_ADMIN",
    "ROLE_TECHNICAL",
    "TECHNICAL_SCHEMA",
    "VERDICT_SCHEMA",
    "assess_population_trust_bundle",
    "assess_population_trust_file",
    "external_check_signing_message",
    "read_canonical_trust_bundle",
    "signing_message",
    "timestamp_subject",
    "verify_population_trust_bundle",
    "verify_population_trust_file",
]
