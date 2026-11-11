"""Authority-free ancestry auditing for the external confirmatory cohort.

This module authenticates a complete population declaration using a caller
supplied pinned Ed25519 public key, then derives conservative independence
families from declared, signed evidence.  It deliberately does not decide
eligibility, access any holdout, or authorize a submission.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import re
from typing import Any

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json_bytes, canonical_sha256


ANCESTRY_MANIFEST_SCHEMA = "evaluation_v5_external_confirmatory_ancestry_manifest_v1"
ANCESTRY_AUDIT_SCHEMA = "evaluation_v5_external_confirmatory_ancestry_audit_v1"
ANCESTRY_PROTOCOL_ID = "MCI_TRANSFER_V1"
FAMILY_EVIDENCE_SCHEMA = "evaluation_v5_ancestry_family_evidence_v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ED25519_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_ED25519_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_RECORD_FIELDS = frozenset(
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
_UNSIGNED_MANIFEST_FIELDS = frozenset({"schema", "protocol_id", "records"})
_SIGNED_MANIFEST_FIELDS = _UNSIGNED_MANIFEST_FIELDS | {"auditor_signature_ed25519"}


class AncestryAuditError(ValueError):
    """A signed ancestry population or its audit input is invalid."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AncestryAuditError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise AncestryAuditError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_utc(value: object, *, label: str) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise AncestryAuditError(f"{label} must be canonical UTC with microseconds")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AncestryAuditError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AncestryAuditError(f"{label} must include UTC")
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if normalized != value:
        raise AncestryAuditError(f"{label} must be canonical UTC")
    return value


def _hash_list(value: object, *, label: str) -> list[str]:
    if type(value) is not list:
        raise AncestryAuditError(f"{label} must be a JSON list")
    hashes = [_sha256(item, label=f"{label}[{index}]") for index, item in enumerate(value)]
    if len(set(hashes)) != len(hashes):
        raise AncestryAuditError(f"{label} must not contain duplicates")
    return sorted(hashes)


def _normalize_record(value: object, *, index: int) -> dict[str, Any]:
    raw = _exact_fields(value, _RECORD_FIELDS, label=f"ancestry record {index}")
    if type(raw["ancestry_complete"]) is not bool:
        raise AncestryAuditError("ancestry_complete must be exactly a boolean")
    provenance_evidence = _hash_list(
        raw["declared_provenance_evidence_sha256s"],
        label="declared_provenance_evidence_sha256s",
    )
    if not provenance_evidence:
        raise AncestryAuditError(
            "declared_provenance_evidence_sha256s must contain at least one evidence hash"
        )
    return {
        "archive_sha256": _sha256(raw["archive_sha256"], label="archive_sha256"),
        "policy_sha256": _sha256(raw["policy_sha256"], label="policy_sha256"),
        "source_tree_sha256": _sha256(raw["source_tree_sha256"], label="source_tree_sha256"),
        "direct_parent_policy_sha256s": _hash_list(
            raw["direct_parent_policy_sha256s"], label="direct_parent_policy_sha256s"
        ),
        "teacher_checkpoint_sha256s": _hash_list(
            raw["teacher_checkpoint_sha256s"], label="teacher_checkpoint_sha256s"
        ),
        "declared_provenance_evidence_sha256s": provenance_evidence,
        "ancestry_complete": raw["ancestry_complete"],
        "review_timestamp_utc": _canonical_utc(raw["review_timestamp_utc"], label="review_timestamp_utc"),
    }


def _normalized_unsigned_manifest(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _UNSIGNED_MANIFEST_FIELDS, label="unsigned ancestry manifest")
    if raw["schema"] != ANCESTRY_MANIFEST_SCHEMA:
        raise AncestryAuditError(f"ancestry manifest schema must be {ANCESTRY_MANIFEST_SCHEMA!r}")
    if raw["protocol_id"] != ANCESTRY_PROTOCOL_ID:
        raise AncestryAuditError(f"ancestry manifest protocol must be {ANCESTRY_PROTOCOL_ID!r}")
    if type(raw["records"]) is not list or not raw["records"]:
        raise AncestryAuditError("ancestry manifest records must be a non-empty JSON list")
    records = [_normalize_record(item, index=index) for index, item in enumerate(raw["records"])]
    archives = [record["archive_sha256"] for record in records]
    if len(set(archives)) != len(archives):
        raise AncestryAuditError("ancestry manifest contains duplicate archive_sha256 values")
    return {
        "schema": ANCESTRY_MANIFEST_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "records": sorted(records, key=lambda record: record["archive_sha256"]),
    }


def canonical_unsigned_manifest_bytes(value: object) -> bytes:
    """Return the exact order-independent bytes an auditor must sign.

    This normalizes the population set by archive hash and normalizes each
    evidence list.  The resulting signature is therefore not sensitive to an
    incidental JSON array order, while duplicate archives remain an error.
    """

    return canonical_json_bytes(_normalized_unsigned_manifest(value))


def unsigned_manifest_sha256(value: object) -> str:
    """Return the canonical identity hash of a validated unsigned population."""

    return hashlib.sha256(canonical_unsigned_manifest_bytes(value)).hexdigest()


def _signed_manifest_sha256(value: Mapping[str, Any]) -> str:
    """Bind the normalized signed manifest, including its signature bytes."""

    return canonical_sha256(value)


def _auditor_public_key_sha256(value: str) -> str:
    """Fingerprint the exact raw Ed25519 public key supplied by the caller."""

    return hashlib.sha256(bytes.fromhex(value)).hexdigest()


def _public_key(value: object) -> Ed25519PublicKey:
    if type(value) is not str or _ED25519_PUBLIC_KEY_RE.fullmatch(value) is None:
        raise AncestryAuditError("pinned_public_key_hex must be a lowercase Ed25519 public-key hex string")
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
    except ValueError as exc:
        raise AncestryAuditError("pinned_public_key_hex is not an Ed25519 public key") from exc


def validate_signed_population_manifest(
    value: object, *, pinned_public_key_hex: str
) -> dict[str, Any]:
    """Verify an exact signed population against the explicitly pinned key."""

    raw = _exact_fields(value, _SIGNED_MANIFEST_FIELDS, label="signed ancestry manifest")
    signature = raw["auditor_signature_ed25519"]
    if type(signature) is not str or _ED25519_SIGNATURE_RE.fullmatch(signature) is None:
        raise AncestryAuditError("auditor_signature_ed25519 must be lowercase Ed25519 signature hex")
    unsigned = _normalized_unsigned_manifest(
        {"schema": raw["schema"], "protocol_id": raw["protocol_id"], "records": raw["records"]}
    )
    try:
        _public_key(pinned_public_key_hex).verify(bytes.fromhex(signature), canonical_json_bytes(unsigned))
    except InvalidSignature as exc:
        raise AncestryAuditError("auditor Ed25519 signature verification failed") from exc
    return {**unsigned, "auditor_signature_ed25519": signature}


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        while self._parent[item] != item:
            self._parent[item] = self._parent[self._parent[item]]
            item = self._parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self._parent[max(left_root, right_root)] = min(left_root, right_root)


def _family_token_groups(records: list[dict[str, Any]], union_find: _UnionFind) -> None:
    """Merge every declared common derivation signal with deterministic keys."""

    seen: dict[tuple[str, str], int] = {}
    for index, record in enumerate(records):
        tokens = [
            ("policy", record["policy_sha256"]),
            ("source", record["source_tree_sha256"]),
            *(("policy", value) for value in record["direct_parent_policy_sha256s"]),
            *(("derivation", value) for value in record["teacher_checkpoint_sha256s"]),
            *(("derivation", value) for value in record["declared_provenance_evidence_sha256s"]),
        ]
        for token in tokens:
            prior = seen.get(token)
            if prior is None:
                seen[token] = index
            else:
                union_find.union(prior, index)


def _component_descriptor(records: list[dict[str, Any]], *, unknown: bool) -> dict[str, Any]:
    if unknown:
        return {"schema": FAMILY_EVIDENCE_SCHEMA, "kind": "UNKNOWN_INCOMPLETE_ANCESTRY"}
    return {
        "schema": FAMILY_EVIDENCE_SCHEMA,
        "kind": "DECLARED_ANCESTRY_COMPONENT",
        "policy_sha256s": sorted({record["policy_sha256"] for record in records}),
        "source_tree_sha256s": sorted({record["source_tree_sha256"] for record in records}),
        "direct_parent_policy_sha256s": sorted(
            {value for record in records for value in record["direct_parent_policy_sha256s"]}
        ),
        "teacher_checkpoint_sha256s": sorted(
            {value for record in records for value in record["teacher_checkpoint_sha256s"]}
        ),
        "declared_provenance_evidence_sha256s": sorted(
            {value for record in records for value in record["declared_provenance_evidence_sha256s"]}
        ),
    }


def audit_external_confirmatory_ancestry(
    manifest: object, *, pinned_public_key_hex: str
) -> dict[str, Any]:
    """Verify a population and conservatively derive archive-to-family mapping.

    An incomplete record is connected to every other incomplete record before
    component IDs are assigned.  Consequently, any complete record linked to
    one also joins the single UNKNOWN family rather than being counted as an
    independent family.
    """

    signed = validate_signed_population_manifest(manifest, pinned_public_key_hex=pinned_public_key_hex)
    records = signed["records"]
    union_find = _UnionFind(len(records))
    _family_token_groups(records, union_find)
    incomplete = [index for index, record in enumerate(records) if not record["ancestry_complete"]]
    for index in incomplete[1:]:
        union_find.union(incomplete[0], index)

    components: dict[int, list[dict[str, Any]]] = {}
    for index, record in enumerate(records):
        components.setdefault(union_find.find(index), []).append(record)

    archive_to_family: dict[str, str] = {}
    family_descriptors: dict[str, dict[str, Any]] = {}
    for members in components.values():
        is_unknown = any(not member["ancestry_complete"] for member in members)
        descriptor = _component_descriptor(members, unknown=is_unknown)
        family_id = canonical_sha256(descriptor)
        family_descriptors[family_id] = descriptor
        for member in members:
            archive_to_family[member["archive_sha256"]] = family_id
    archive_to_family = dict(sorted(archive_to_family.items()))
    family_descriptors = dict(sorted(family_descriptors.items()))
    manifest_sha256 = unsigned_manifest_sha256(
        {
            "schema": signed["schema"],
            "protocol_id": signed["protocol_id"],
            "records": signed["records"],
        }
    )
    signed_manifest_sha256 = _signed_manifest_sha256(signed)
    auditor_public_key_sha256 = _auditor_public_key_sha256(pinned_public_key_hex)
    review_timestamps = [record["review_timestamp_utc"] for record in records]
    earliest_review_timestamp_utc = min(review_timestamps)
    latest_review_timestamp_utc = max(review_timestamps)
    counts = {
        "archive_count": len(records),
        "family_count": len(set(archive_to_family.values())),
        "complete_archive_count": len(records) - len(incomplete),
        "incomplete_archive_count": len(incomplete),
    }
    evidence_sha256 = canonical_sha256(
        {
            "manifest_sha256": manifest_sha256,
            "signed_manifest_sha256": signed_manifest_sha256,
            "auditor_public_key_sha256": auditor_public_key_sha256,
            "earliest_review_timestamp_utc": earliest_review_timestamp_utc,
            "latest_review_timestamp_utc": latest_review_timestamp_utc,
            "archive_to_family": archive_to_family,
            "family_descriptors": family_descriptors,
            "counts": counts,
        }
    )
    return {
        "schema": ANCESTRY_AUDIT_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "manifest_sha256": manifest_sha256,
        "signed_manifest_sha256": signed_manifest_sha256,
        "auditor_public_key_sha256": auditor_public_key_sha256,
        "earliest_review_timestamp_utc": earliest_review_timestamp_utc,
        "latest_review_timestamp_utc": latest_review_timestamp_utc,
        "evidence_sha256": evidence_sha256,
        "archive_to_family": archive_to_family,
        "family_descriptors": family_descriptors,
        "counts": counts,
        "authority": False,
        "submission": False,
        "holdout": False,
        "cryptography_version": cryptography.__version__,
    }


# Shorter spelling for callers which already know this is the v5 cohort audit.
audit_ancestry = audit_external_confirmatory_ancestry


__all__ = [
    "ANCESTRY_AUDIT_SCHEMA",
    "ANCESTRY_MANIFEST_SCHEMA",
    "ANCESTRY_PROTOCOL_ID",
    "AncestryAuditError",
    "FAMILY_EVIDENCE_SCHEMA",
    "audit_ancestry",
    "audit_external_confirmatory_ancestry",
    "canonical_unsigned_manifest_bytes",
    "unsigned_manifest_sha256",
    "validate_signed_population_manifest",
]
