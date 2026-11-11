"""Corrected v6.2.5 recruitment release and population trust gate.

The v6.2.3 callback route is retired.  This module accepts only exact evidence
bytes plus comprehensive receipts signed by at least two of three authorities
pinned in an externally authorized recruitment release root. The release root
itself is accepted only through a code-pinned 2-of-3 bootstrap chain, a signed
append-only transparency checkpoint, and durable one-time challenge state.

Even a successful result authorizes only the later local-evidence stage.  It
never issues an upload permit, publishes a campaign preregistration root,
accesses the sealed holdout, or authorizes calibration or production uploads.
"""

from __future__ import annotations

import base64
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from evaluation_v5_1.exact_gate_v2 import (
    ExactGateV2Error,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
)

from .attestation_v623 import (
    DOMAIN_REGISTRY,
    DOMAIN_REVOCATION,
    ENVELOPE_SCHEMA,
    PinnedRegistryAdmin,
    read_canonical_trust_bundle,
    signing_message as v623_signing_message,
    verify_population_trust_bundle,
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


RELEASE_ROOT_SCHEMA = "eval.v6.2.5.recruitment-release-root"
RELEASE_PACKET_SCHEMA = "eval.v6.2.5.population-release-packet"
EVIDENCE_MANIFEST_SCHEMA = "eval.v6.2.5.evidence-manifest"
IDENTITY_BINDING_SCHEMA = "eval.v6.2.5.identity-binding"
PRINCIPAL_BINDING_SCHEMA = "eval.v6.2.5.unit-development-principals"
PAIR_REVIEW_SCHEMA = "eval.v6.2.5.pair-lineage-review"
PAIR_LINEAGE_RECEIPT_SCHEMA = "eval.v6.2.5.pair-lineage-receipt"
PAIR_INTERVENTION_RECEIPT_SCHEMA = "eval.v6.2.5.pair-intervention-receipt"
SOURCE_GRAPH_SCHEMA = "eval.v6.2.5.source-provenance-graph"
EXPOSURE_GRAPH_SCHEMA = "eval.v6.2.5.exposure-feedback-graph"
DERIVED_ASSIGNMENT_SCHEMA = "eval.v6.2.5.derived-assignment"
TRANSPARENCY_CHECKPOINT_SCHEMA = "eval.v6.2.5.transparency-checkpoint"
TRANSPARENCY_ENVELOPE_SCHEMA = "eval.v6.2.5.transparency-envelope"
VERIFICATION_RECEIPT_SCHEMA = "eval.v6.2.5.comprehensive-verification-receipt"
VERIFICATION_ENVELOPE_SCHEMA = "eval.v6.2.5.comprehensive-verification-envelope"
VERIFIER_EXECUTION_TRANSCRIPT_SCHEMA = "eval.v6.2.5.verifier-execution-transcript"
REVOCATION_HEAD_SCHEMA = "eval.v6.2.5.revocation-head"
REVOCATION_HEAD_ENVELOPE_SCHEMA = "eval.v6.2.5.revocation-head-envelope"
RELEASE_ROOT_AUTHORIZATION_SCHEMA = "eval.v6.2.5.release-root-authorization"
RELEASE_ROOT_AUTHORIZATION_ENVELOPE_SCHEMA = "eval.v6.2.5.release-root-authorization-envelope"
INTERVENTION_GRAPH_SCHEMA = "eval.v6.2.5.intervention-graph"
VERDICT_SCHEMA = "eval.v6.2.5.population-trust-verdict"

ROLE_REGISTRY_ADMIN = "REGISTRY_ADMIN"
ROLE_EXTERNAL_VERIFIER = "EXTERNAL_VERIFIER"
ROLE_REVOCATION_AUTHORITY = "REVOCATION_AUTHORITY"
ROLE_CONTRIBUTOR = "CONTRIBUTOR"
ROLE_TECHNICAL = "TECH_AUDITOR"
ROLE_LINEAGE = "LINEAGE_AUDITOR"
ROLE_ADJUDICATOR = "ADJUDICATOR"
ROLE_BOOTSTRAP_AUTHORITY = "BOOTSTRAP_AUTHORITY"

DOMAIN_RELEASE_VERIFICATION = b"EVAL-V625/COMPREHENSIVE-VERIFICATION\0"
DOMAIN_TRANSPARENCY_CHECKPOINT = b"EVAL-V625/TRANSPARENCY-CHECKPOINT\0"
DOMAIN_REVOCATION_HEAD = b"EVAL-V625/REVOCATION-HEAD\0"
DOMAIN_RELEASE_ROOT_AUTHORIZATION = b"EVAL-V625/RELEASE-ROOT-AUTHORIZATION\0"
DOMAIN_PAIR_LINEAGE_RECEIPT = b"EVAL-V625/PAIR-LINEAGE-RECEIPT\0"
DOMAIN_PAIR_INTERVENTION_RECEIPT = b"EVAL-V625/PAIR-INTERVENTION-RECEIPT\0"

# This must become a literal, separately reviewed code-pinned object before a
# release root can be authorized. It is intentionally not populated from an
# environment variable, command-line option, packet, or runtime configuration.
# Tests may monkeypatch it, but their verifier-module hash is not a production
# authorization and cannot grant upload authority.
BOOTSTRAP_TRUST_CONFIG: Mapping[str, Any] | None = None

_TRANSPARENCY_KINDS = (
    "REGISTRY_STATE",
    "RELEASE_ROOT_AUTHORIZATION",
    "REVOCATION_HEAD",
    "VERIFICATION_CHALLENGE",
)
_CHALLENGE_DB_SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32,256}$")
_RFC3339_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
_FAMILY_RE = re.compile(r"^sf-[0-9a-f]{24}$")
_LINEAGE_RE = re.compile(r"^lt-[0-9a-f]{24}$")
_INTERVENTION_RE = re.compile(r"^if-[0-9a-f]{24}$")
_SOURCE_STATES = frozenset(
    {"INDEPENDENT", "SHARED", "DERIVED", "UNKNOWN", "CONFLICT"}
)
_EXPOSURE_STATES = frozenset(
    {"INDEPENDENT", "SHARED_FEEDBACK", "UNKNOWN", "CONFLICT"}
)
_INTERVENTION_STATES = frozenset(
    {
        "SAME_INTERVENTION",
        "OVERLAPPING_INTERVENTION",
        "DISTINCT_INTERVENTION",
        "UNKNOWN",
        "CONFLICT",
    }
)
_EVIDENCE_PURPOSES = frozenset(
    {
        "TECHNICAL_REBUILD",
        "LINUX_TRANSCRIPT",
        "SAFETY_HARNESS",
        "LINEAGE_VCS",
        "LINEAGE_SIMILARITY",
        "LINEAGE_PROVENANCE",
        "PAIR_LINEAGE_RECEIPT",
        "PAIR_INTERVENTION_RECEIPT",
        "IDENTITY_EVIDENCE",
        "REVOCATION_LOG",
        "VERIFIER_EXECUTION_TRANSCRIPT",
    }
)
_REQUIRED_UNIT_PURPOSES = frozenset(
    {
        "TECHNICAL_REBUILD",
        "LINUX_TRANSCRIPT",
        "SAFETY_HARNESS",
        "LINEAGE_VCS",
        "LINEAGE_SIMILARITY",
        "LINEAGE_PROVENANCE",
    }
)
_CHECK_FIELDS = frozenset(
    {
        "registry_valid",
        "all_signatures_valid",
        "timestamps_valid",
        "nonces_unique",
        "role_separation_valid",
        "contributor_manifests_valid",
        "technical_audits_verified_16",
        "lineage_audits_verified_16",
        "pair_lineage_reviews_verified_120",
        "pair_intervention_reviews_verified_120",
        "source_graph_derived",
        "exposure_graph_derived",
        "intervention_graph_derived",
        "development_principals_disjoint",
        "collision_graph_adjudicated",
        "intervention_diversity_valid",
        "auditor_caps_valid",
        "no_revoked_keys_used",
        "evidence_manifest_complete",
        "revocation_head_current",
    }
)
_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_PARSED_EVIDENCE_BYTES = 1024 * 1024


class ReleaseV625Error(ValueError):
    """A release root, packet, receipt, or evidence artifact failed closed."""


def _exact(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ReleaseV625Error(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\0" in value:
        raise ReleaseV625Error(f"{label} must be a nonempty trimmed string without NUL")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ReleaseV625Error(f"{label} must be lowercase SHA-256 hex")
    return value


def _nonce(value: Any, label: str) -> str:
    if type(value) is not str or _NONCE_RE.fullmatch(value) is None or len(value) % 2:
        raise ReleaseV625Error(f"{label} must be 16 through 128 bytes of lowercase hex")
    return value


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise ReleaseV625Error(f"{label} must be canonical second-resolution UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReleaseV625Error(f"{label} is not a valid UTC timestamp") from exc


def _string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if type(value) is not list or (not allow_empty and not value):
        raise ReleaseV625Error(f"{label} must be a JSON array of strings")
    result = [_identifier(item, f"{label} item") for item in value]
    if result != sorted(result) or len(result) != len(set(result)):
        raise ReleaseV625Error(f"{label} must be unique and sorted")
    return result


def _ordered_sha_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if type(value) is not list or (not allow_empty and not value):
        raise ReleaseV625Error(f"{label} must be a JSON array of SHA-256 hashes")
    if len(value) > 512:
        raise ReleaseV625Error(f"{label} is implausibly long")
    return [_sha(item, f"{label} item") for item in value]


def _public_key(value: Any, label: str) -> bytes:
    if type(value) is not str:
        raise ReleaseV625Error(f"{label} must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ReleaseV625Error(f"{label} must be canonical base64") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
        raise ReleaseV625Error(f"{label} must encode exactly 32 bytes")
    try:
        validate_ed25519_public_key(raw)
    except ExactGateV2Error as exc:
        raise ReleaseV625Error(f"{label} is not a strict Ed25519 key: {exc}") from exc
    return raw


def _key_id(public_key: bytes) -> str:
    try:
        validate_ed25519_public_key(public_key)
    except ExactGateV2Error as exc:
        raise ReleaseV625Error(f"Ed25519 public key is invalid: {exc}") from exc
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def _signature(value: Any) -> bytes:
    if type(value) is not str:
        raise ReleaseV625Error("signature must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise ReleaseV625Error("signature must be canonical base64") from exc
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != value:
        raise ReleaseV625Error("signature must encode exactly 64 bytes")
    try:
        validate_ed25519_signature_encoding(raw)
    except ExactGateV2Error as exc:
        raise ReleaseV625Error(f"signature has a non-strict Ed25519 encoding: {exc}") from exc
    return raw


def _signed_message(domain: bytes, payload: Mapping[str, Any]) -> bytes:
    return domain + hashlib.sha256(canonical_json_bytes(payload)).digest()


def transparency_leaf_hash(kind: str, payload_sha256: str) -> bytes:
    leaf = {
        "kind": _identifier(kind, "transparency leaf kind"),
        "payload_sha256": _sha(payload_sha256, "transparency leaf payload"),
    }
    return hashlib.sha256(b"\x00" + canonical_json_bytes(leaf)).digest()


def _transparency_node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ReleaseV625Error("transparency node hashes must contain 32 bytes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_transparency_inclusion(
    *,
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    audit_path_sha256s: Sequence[str],
    expected_root_sha256: str,
) -> None:
    if len(leaf_hash) != 32:
        raise ReleaseV625Error("transparency leaf hash must contain 32 bytes")
    if (
        type(leaf_index) is not int
        or isinstance(leaf_index, bool)
        or type(tree_size) is not int
        or isinstance(tree_size, bool)
        or tree_size <= 0
        or not 0 <= leaf_index < tree_size
    ):
        raise ReleaseV625Error("transparency inclusion index/tree size is invalid")
    fn = leaf_index
    sn = tree_size - 1
    root = leaf_hash
    for item in audit_path_sha256s:
        sibling = bytes.fromhex(_sha(item, "transparency inclusion sibling"))
        if fn & 1 or fn == sn:
            root = _transparency_node_hash(sibling, root)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            root = _transparency_node_hash(root, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0 or root.hex() != _sha(expected_root_sha256, "transparency root"):
        raise ReleaseV625Error("transparency inclusion proof is invalid")


def verify_transparency_consistency(
    *,
    old_tree_size: int,
    new_tree_size: int,
    old_root_sha256: str,
    new_root_sha256: str,
    consistency_path_sha256s: Sequence[str],
) -> None:
    old_root = bytes.fromhex(_sha(old_root_sha256, "old transparency root"))
    new_root = bytes.fromhex(_sha(new_root_sha256, "new transparency root"))
    if (
        type(old_tree_size) is not int
        or isinstance(old_tree_size, bool)
        or type(new_tree_size) is not int
        or isinstance(new_tree_size, bool)
        or old_tree_size < 0
        or new_tree_size < old_tree_size
    ):
        raise ReleaseV625Error("transparency consistency tree sizes are invalid")
    proof = [bytes.fromhex(_sha(item, "transparency consistency sibling")) for item in consistency_path_sha256s]
    if old_tree_size == 0:
        if proof:
            raise ReleaseV625Error("empty old transparency tree requires an empty proof")
        return
    if old_tree_size == new_tree_size:
        if proof or old_root != new_root:
            raise ReleaseV625Error("equal transparency trees have an invalid consistency proof")
        return
    fn = old_tree_size - 1
    sn = new_tree_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if not proof:
        raise ReleaseV625Error("growing transparency tree requires a consistency proof")
    if fn == 0:
        first_old = old_root
        first_new = old_root
        offset = 0
    else:
        first_old = proof[0]
        first_new = proof[0]
        offset = 1
    fr = first_old
    sr = first_new
    for sibling in proof[offset:]:
        if sn == 0:
            raise ReleaseV625Error("transparency consistency proof is too long")
        if fn & 1 or fn == sn:
            fr = _transparency_node_hash(sibling, fr)
            sr = _transparency_node_hash(sibling, sr)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = _transparency_node_hash(sr, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0 or fr != old_root or sr != new_root:
        raise ReleaseV625Error("transparency consistency proof is invalid")


def _verify_signature(
    *,
    public_key: bytes,
    signature_value: Any,
    domain: bytes,
    payload: Mapping[str, Any],
) -> None:
    signature = _signature(signature_value)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, _signed_message(domain, payload)
        )
    except (InvalidSignature, ValueError) as exc:
        raise ReleaseV625Error("Ed25519 signature verification failed") from exc


def _verify_v623_admin_approvals(
    bundle: Mapping[str, Any], release: Mapping[str, Any]
) -> None:
    admins = release["authorities"]["registry_admins"]
    for payload_key, approvals_key, artifact_schema, domain in (
        ("registry", "registry_approvals", "eval.v6.2.3.trust-registry", DOMAIN_REGISTRY),
        ("revocation_log", "revocation_approvals", "eval.v6.2.3.revocation-log", DOMAIN_REVOCATION),
    ):
        payload = bundle.get(payload_key)
        approvals = bundle.get(approvals_key)
        if type(payload) is not dict or type(approvals) is not list:
            raise ReleaseV625Error(f"campaign bundle lacks {payload_key} governance evidence")
        signers: set[str] = set()
        controls: set[str] = set()
        for index, item in enumerate(approvals):
            envelope = _exact(
                item,
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
                f"{payload_key} admin approval {index}",
            )
            if envelope["schema"] != ENVELOPE_SCHEMA or envelope["artifact_schema"] != artifact_schema:
                raise ReleaseV625Error(f"{payload_key} admin envelope schema is invalid")
            key_id = envelope["key_id"]
            authority = admins.get(key_id)
            if authority is None or key_id in signers:
                raise ReleaseV625Error(f"{payload_key} admin signer is unknown or duplicated")
            if envelope["payload_sha256"] != canonical_sha256(payload):
                raise ReleaseV625Error(f"{payload_key} admin approval does not bind payload")
            _utc(envelope["signed_at_utc"], f"{payload_key} admin signed_at_utc")
            _sha(envelope["timestamp_token_sha256"], f"{payload_key} admin timestamp token")
            signature = _signature(envelope["signature_ed25519_base64"])
            try:
                Ed25519PublicKey.from_public_bytes(authority["public_key"]).verify(
                    signature, v623_signing_message(domain, payload)
                )
            except (InvalidSignature, ValueError) as exc:
                raise ReleaseV625Error(f"{payload_key} admin signature failed") from exc
            signers.add(key_id)
            controls.add(authority["control_group_id"])
        if len(signers) < 2 or len(controls) < 2:
            raise ReleaseV625Error(f"{payload_key} requires 2-of-3 release-pinned admin control groups")


def _authority_record(value: Any, *, role: str, label: str) -> dict[str, Any]:
    raw = _exact(
        value,
        frozenset(
            {
                "key_id",
                "public_key_ed25519_base64",
                "identity_subject_id",
                "control_group_id",
                "organization_id",
                "role",
                "external_identity_receipt_sha256",
            }
        ),
        label,
    )
    if raw["role"] != role:
        raise ReleaseV625Error(f"{label} role must be {role}")
    public_key = _public_key(raw["public_key_ed25519_base64"], f"{label} public key")
    key_id = _identifier(raw["key_id"], f"{label} key_id")
    if _KEY_ID_RE.fullmatch(key_id) is None or key_id != _key_id(public_key):
        raise ReleaseV625Error(f"{label} key_id does not bind its key")
    return {
        "key_id": key_id,
        "public_key": public_key,
        "identity_subject_id": _identifier(
            raw["identity_subject_id"], f"{label} identity_subject_id"
        ),
        "control_group_id": _identifier(
            raw["control_group_id"], f"{label} control_group_id"
        ),
        "organization_id": _identifier(
            raw["organization_id"], f"{label} organization_id"
        ),
        "role": role,
        "external_identity_receipt_sha256": _sha(
            raw["external_identity_receipt_sha256"], f"{label} identity receipt"
        ),
    }


def _authority_group(value: Any, *, role: str, label: str) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) != 3:
        raise ReleaseV625Error(f"{label} must contain exactly three authorities")
    records = [_authority_record(item, role=role, label=f"{label} {index}") for index, item in enumerate(value)]
    if [record["key_id"] for record in records] != sorted(record["key_id"] for record in records):
        raise ReleaseV625Error(f"{label} must be sorted by key_id")
    for field in ("key_id", "identity_subject_id", "control_group_id", "organization_id"):
        values = [record[field] for record in records]
        if len(values) != len(set(values)):
            raise ReleaseV625Error(f"{label} requires three distinct {field} values")
    return {record["key_id"]: record for record in records}


def _runtime_module_sha256() -> str:
    path = Path(__file__)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseV625Error(f"unable to self-measure verifier module: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseV625Error("verifier module must be one regular non-hardlinked file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ReleaseV625Error("verifier module changed or truncated during measurement")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ReleaseV625Error("verifier module grew during measurement")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ReleaseV625Error("verifier module changed during self-measurement")
    return digest.hexdigest()


def _bootstrap_config() -> dict[str, Any]:
    raw = _exact(
        BOOTSTRAP_TRUST_CONFIG,
        frozenset(
            {
                "schema",
                "bootstrap_policy_sha256",
                "authorities",
                "minimum_authorization_sequence",
                "previous_authorization_root_sha256",
                "minimum_checkpoint_sequence",
                "previous_checkpoint_sha256",
                "previous_registry_epoch",
                "previous_revocation_sequence",
                "previous_transparency_tree_size",
                "previous_transparency_root_sha256",
                "challenge_replay_namespace",
                "challenge_replay_store_path_sha256",
            }
        ),
        "code-pinned bootstrap trust config",
    )
    if raw["schema"] != "eval.v6.2.5.bootstrap-trust-config":
        raise ReleaseV625Error("bootstrap trust config schema is invalid")
    authorities = _authority_group(
        raw["authorities"],
        role=ROLE_BOOTSTRAP_AUTHORITY,
        label="bootstrap authorities",
    )
    sequence = raw["minimum_authorization_sequence"]
    checkpoint_sequence = raw["minimum_checkpoint_sequence"]
    registry_epoch = raw["previous_registry_epoch"]
    revocation_sequence = raw["previous_revocation_sequence"]
    tree_size = raw["previous_transparency_tree_size"]
    for value, label in (
        (sequence, "minimum authorization sequence"),
        (checkpoint_sequence, "minimum checkpoint sequence"),
        (registry_epoch, "previous registry epoch"),
        (revocation_sequence, "previous revocation sequence"),
        (tree_size, "previous transparency tree size"),
    ):
        if type(value) is not int or isinstance(value, bool) or value < 0:
            raise ReleaseV625Error(f"{label} must be a nonnegative integer")
    if tree_size == 0:
        raise ReleaseV625Error(
            "bootstrap trust requires a nonempty previously pinned transparency tree"
        )
    return {
        "raw": raw,
        "bootstrap_policy_sha256": _sha(
            raw["bootstrap_policy_sha256"], "bootstrap policy"
        ),
        "authorities": authorities,
        "minimum_authorization_sequence": sequence,
        "previous_authorization_root_sha256": _sha(
            raw["previous_authorization_root_sha256"],
            "previous authorization root",
        ),
        "minimum_checkpoint_sequence": checkpoint_sequence,
        "previous_checkpoint_sha256": _sha(
            raw["previous_checkpoint_sha256"], "previous checkpoint"
        ),
        "previous_registry_epoch": registry_epoch,
        "previous_revocation_sequence": revocation_sequence,
        "previous_transparency_tree_size": tree_size,
        "previous_transparency_root_sha256": _sha(
            raw["previous_transparency_root_sha256"],
            "previous transparency root",
        ),
        "challenge_replay_namespace": _identifier(
            raw["challenge_replay_namespace"], "challenge replay namespace"
        ),
        "challenge_replay_store_path_sha256": _sha(
            raw["challenge_replay_store_path_sha256"],
            "challenge replay store path",
        ),
    }


def _release_root_authorization(
    value: Any,
    *,
    release: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
) -> dict[str, Any]:
    wrapper = _exact(
        value,
        frozenset({"schema", "authorization", "approvals"}),
        "release-root authorization",
    )
    if wrapper["schema"] != RELEASE_ROOT_AUTHORIZATION_ENVELOPE_SCHEMA:
        raise ReleaseV625Error("release-root authorization envelope schema is invalid")
    authorization = _exact(
        wrapper["authorization"],
        frozenset(
            {
                "schema",
                "log_id",
                "release_root_sha256",
                "release_root_schema_version",
                "source_commit_sha256",
                "source_tree_sha256",
                "reproducible_build_recipe_sha256",
                "released_module_or_binary_sha256",
                "test_evidence_root_sha256",
                "bootstrap_policy_sha256",
                "authorization_sequence",
                "issued_at_utc",
                "previous_authorization_root_sha256",
            }
        ),
        "release-root authorization payload",
    )
    if authorization["schema"] != RELEASE_ROOT_AUTHORIZATION_SCHEMA:
        raise ReleaseV625Error("release-root authorization schema is invalid")
    _identifier(authorization["log_id"], "release authorization log_id")
    if (
        authorization["release_root_sha256"] != release["sha256"]
        or authorization["release_root_schema_version"] != RELEASE_ROOT_SCHEMA
    ):
        raise ReleaseV625Error("release-root authorization does not bind the exact root")
    for field in (
        "source_commit_sha256",
        "source_tree_sha256",
        "reproducible_build_recipe_sha256",
        "released_module_or_binary_sha256",
        "test_evidence_root_sha256",
        "bootstrap_policy_sha256",
        "previous_authorization_root_sha256",
    ):
        _sha(authorization[field], f"release authorization {field}")
    if authorization["released_module_or_binary_sha256"] != _runtime_module_sha256():
        raise ReleaseV625Error("runtime verifier module hash is not release-authorized")
    if authorization["bootstrap_policy_sha256"] != bootstrap["bootstrap_policy_sha256"]:
        raise ReleaseV625Error("release authorization uses the wrong bootstrap policy")
    sequence = authorization["authorization_sequence"]
    if (
        type(sequence) is not int
        or isinstance(sequence, bool)
        or sequence != bootstrap["minimum_authorization_sequence"] + 1
    ):
        raise ReleaseV625Error("release authorization sequence is not the next monotonic value")
    if authorization["previous_authorization_root_sha256"] != bootstrap["previous_authorization_root_sha256"]:
        raise ReleaseV625Error("release authorization predecessor root is invalid")
    issued_at = _utc(authorization["issued_at_utc"], "release authorization issued_at_utc")
    if issued_at < release["issued_at"]:
        raise ReleaseV625Error("release authorization predates its release root")
    bootstrap_subjects = {
        authority["identity_subject_id"] for authority in bootstrap["authorities"].values()
    }
    bootstrap_controls = {
        authority["control_group_id"] for authority in bootstrap["authorities"].values()
    }
    release_authorities = [
        authority
        for group in release["authorities"].values()
        for authority in group.values()
    ]
    release_subjects = {
        authority["identity_subject_id"] for authority in release_authorities
    } | {release["transparency"]["identity_subject_id"]}
    release_controls = {
        authority["control_group_id"] for authority in release_authorities
    } | {release["transparency"]["control_group_id"]}
    if bootstrap_subjects & release_subjects or bootstrap_controls & release_controls:
        raise ReleaseV625Error(
            "bootstrap authorities must be independent of release and transparency authorities"
        )
    approvals = wrapper["approvals"]
    if type(approvals) is not list or not 2 <= len(approvals) <= 3:
        raise ReleaseV625Error("release authorization requires two or three approvals")
    signers: set[str] = set()
    controls: set[str] = set()
    for index, item in enumerate(approvals):
        approval = _exact(
            item,
            frozenset({"authority_key_id", "signature_ed25519_base64"}),
            f"release authorization approval {index}",
        )
        key_id = approval["authority_key_id"]
        authority = bootstrap["authorities"].get(key_id)
        if authority is None or key_id in signers:
            raise ReleaseV625Error("release authorization signer is unknown or duplicated")
        _verify_signature(
            public_key=authority["public_key"],
            signature_value=approval["signature_ed25519_base64"],
            domain=DOMAIN_RELEASE_ROOT_AUTHORIZATION,
            payload=authorization,
        )
        signers.add(key_id)
        controls.add(authority["control_group_id"])
    if len(signers) < 2 or len(controls) < 2:
        raise ReleaseV625Error("release authorization requires 2-of-3 bootstrap control groups")
    if [item["authority_key_id"] for item in approvals] != sorted(signers):
        raise ReleaseV625Error("release authorization approvals must use canonical signer order")
    return {
        "raw": wrapper,
        "authorization": authorization,
        "authorization_payload_root_sha256": canonical_sha256(authorization),
        "authorization_root_sha256": canonical_sha256(wrapper),
        "issued_at": issued_at,
        "sequence": sequence,
    }


def validate_release_root(value: Any) -> dict[str, Any]:
    """Validate a release-root structure without granting it authority."""

    raw = _exact(
        value,
        frozenset(
            {
                "schema",
                "release_id",
                "release_nonce",
                "issued_at_utc",
                "accepted_semantic_verifier_build_sha256s",
                "trust_policy_sha256",
                "timestamp_policy_sha256",
                "lineage_policy_sha256",
                "intervention_policy_sha256",
                "evidence_policy_sha256",
                "authorities",
                "transparency_log",
                "tsa_roots",
            }
        ),
        "recruitment release root",
    )
    if raw["schema"] != RELEASE_ROOT_SCHEMA:
        raise ReleaseV625Error(f"release root schema must be {RELEASE_ROOT_SCHEMA}")
    digest = canonical_sha256(raw)
    builds = raw["accepted_semantic_verifier_build_sha256s"]
    if type(builds) is not list or not builds:
        raise ReleaseV625Error("release root must pin at least one semantic verifier build")
    checked_builds = [_sha(item, "accepted semantic verifier build") for item in builds]
    if checked_builds != sorted(set(checked_builds)):
        raise ReleaseV625Error("accepted semantic verifier builds must be sorted and unique")
    authorities = _exact(
        raw["authorities"],
        frozenset({"registry_admins", "external_verifiers", "revocation_authorities"}),
        "release authorities",
    )
    groups = {
        "registry_admins": _authority_group(
            authorities["registry_admins"], role=ROLE_REGISTRY_ADMIN, label="registry admins"
        ),
        "external_verifiers": _authority_group(
            authorities["external_verifiers"], role=ROLE_EXTERNAL_VERIFIER, label="external verifiers"
        ),
        "revocation_authorities": _authority_group(
            authorities["revocation_authorities"], role=ROLE_REVOCATION_AUTHORITY, label="revocation authorities"
        ),
    }
    all_authorities = [record for group in groups.values() for record in group.values()]
    for field in ("key_id", "identity_subject_id", "control_group_id", "organization_id"):
        values = [record[field] for record in all_authorities]
        if len(values) != len(set(values)):
            raise ReleaseV625Error(f"release authority classes must be globally disjoint by {field}")
    transparency_raw = _exact(
        raw["transparency_log"],
        frozenset(
            {
                "log_id",
                "key_id",
                "public_key_ed25519_base64",
                "identity_subject_id",
                "control_group_id",
                "checkpoint_authority_receipt_sha256",
                "minimum_registry_epoch",
                "minimum_revocation_sequence",
                "maximum_checkpoint_age_seconds",
            }
        ),
        "transparency log",
    )
    transparency_key = _public_key(
        transparency_raw["public_key_ed25519_base64"], "transparency log public key"
    )
    transparency = {
        "log_id": _identifier(transparency_raw["log_id"], "transparency log_id"),
        "key_id": _identifier(transparency_raw["key_id"], "transparency key_id"),
        "public_key": transparency_key,
        "identity_subject_id": _identifier(
            transparency_raw["identity_subject_id"], "transparency identity_subject_id"
        ),
        "control_group_id": _identifier(
            transparency_raw["control_group_id"], "transparency control_group_id"
        ),
        "checkpoint_authority_receipt_sha256": _sha(
            transparency_raw["checkpoint_authority_receipt_sha256"],
            "transparency authority receipt",
        ),
    }
    if transparency["key_id"] != _key_id(transparency_key):
        raise ReleaseV625Error("transparency key_id does not bind its public key")
    if transparency["identity_subject_id"] in {record["identity_subject_id"] for record in all_authorities} or transparency["control_group_id"] in {record["control_group_id"] for record in all_authorities}:
        raise ReleaseV625Error("transparency authority must be disjoint from release authorities")
    for field in ("minimum_registry_epoch", "minimum_revocation_sequence"):
        if type(transparency_raw[field]) is not int or isinstance(transparency_raw[field], bool) or transparency_raw[field] < 0:
            raise ReleaseV625Error(f"transparency {field} must be a nonnegative integer")
        transparency[field] = transparency_raw[field]
    maximum_age = transparency_raw["maximum_checkpoint_age_seconds"]
    if type(maximum_age) is not int or isinstance(maximum_age, bool) or not 1 <= maximum_age <= 86_400:
        raise ReleaseV625Error("maximum checkpoint age must be between 1 and 86400 seconds")
    transparency["maximum_checkpoint_age_seconds"] = maximum_age
    if type(raw["tsa_roots"]) is not list or not raw["tsa_roots"]:
        raise ReleaseV625Error("release root must pin at least one TSA root")
    tsa_roots = []
    for index, item in enumerate(raw["tsa_roots"]):
        tsa = _exact(item, frozenset({"tsa_id", "ca_sha256", "policy_oid"}), f"TSA root {index}")
        tsa_roots.append(
            {
                "tsa_id": _identifier(tsa["tsa_id"], f"TSA root {index} id"),
                "ca_sha256": _sha(tsa["ca_sha256"], f"TSA root {index} CA"),
                "policy_oid": _identifier(tsa["policy_oid"], f"TSA root {index} policy OID"),
            }
        )
    if [item["tsa_id"] for item in tsa_roots] != sorted({item["tsa_id"] for item in tsa_roots}):
        raise ReleaseV625Error("TSA roots must have sorted unique IDs")
    return {
        "raw": raw,
        "sha256": digest,
        "release_id": _identifier(raw["release_id"], "release_id"),
        "release_nonce": _nonce(raw["release_nonce"], "release_nonce"),
        "issued_at": _utc(raw["issued_at_utc"], "release issued_at_utc"),
        "accepted_builds": frozenset(checked_builds),
        "trust_policy_sha256": _sha(raw["trust_policy_sha256"], "trust policy"),
        "timestamp_policy_sha256": _sha(raw["timestamp_policy_sha256"], "timestamp policy"),
        "lineage_policy_sha256": _sha(raw["lineage_policy_sha256"], "lineage policy"),
        "intervention_policy_sha256": _sha(
            raw["intervention_policy_sha256"], "intervention policy"
        ),
        "evidence_policy_sha256": _sha(raw["evidence_policy_sha256"], "evidence policy"),
        "authorities": groups,
        "transparency": transparency,
        "tsa_roots": tsa_roots,
    }


def _safe_relative_path(value: Any, label: str) -> PurePosixPath:
    text = _identifier(value, label)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or str(path) != text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReleaseV625Error(f"{label} must be a safe relative POSIX path")
    return path


def _evidence_manifest(value: Any, *, bundle: Mapping[str, Any]) -> dict[str, Any]:
    raw = _exact(value, frozenset({"schema", "entries"}), "evidence manifest")
    if raw["schema"] != EVIDENCE_MANIFEST_SCHEMA:
        raise ReleaseV625Error(f"evidence manifest schema must be {EVIDENCE_MANIFEST_SCHEMA}")
    if type(raw["entries"]) is not list or not raw["entries"]:
        raise ReleaseV625Error("evidence manifest entries must be nonempty")
    unit_nonces = {
        unit["slot_id"]: unit["contributor_manifest"]["unit_nonce"] for unit in bundle["units"]
    }
    records: list[dict[str, Any]] = []
    paths: set[str] = set()
    evidence_ids: set[str] = set()
    for index, item in enumerate(raw["entries"]):
        entry = _exact(
            item,
            frozenset(
                {
                    "evidence_id",
                    "path",
                    "media_type",
                    "byte_length",
                    "sha256",
                    "slot_id",
                    "pair_id",
                    "unit_nonce",
                    "evidence_purpose",
                    "producer_key_id",
                }
            ),
            f"evidence entry {index}",
        )
        evidence_id = _sha(entry["evidence_id"], f"evidence entry {index} evidence_id")
        path = str(_safe_relative_path(entry["path"], f"evidence entry {index} path"))
        if evidence_id in evidence_ids or path in paths:
            raise ReleaseV625Error("evidence IDs and paths must be unique")
        media_type = entry["media_type"]
        if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
            raise ReleaseV625Error("evidence media_type is invalid")
        length = entry["byte_length"]
        if type(length) is not int or isinstance(length, bool) or not 0 <= length <= _MAX_EVIDENCE_BYTES:
            raise ReleaseV625Error("evidence byte_length is invalid")
        digest = _sha(entry["sha256"], f"evidence entry {index} sha256")
        purpose = entry["evidence_purpose"]
        if purpose not in _EVIDENCE_PURPOSES:
            raise ReleaseV625Error("evidence purpose is unknown")
        slot = entry["slot_id"]
        pair = entry["pair_id"]
        nonce = entry["unit_nonce"]
        if purpose in _REQUIRED_UNIT_PURPOSES:
            if slot not in SLOTS or pair is not None or nonce != unit_nonces[slot]:
                raise ReleaseV625Error("unit evidence is not bound to its slot and unit nonce")
        elif purpose in {"PAIR_LINEAGE_RECEIPT", "PAIR_INTERVENTION_RECEIPT"}:
            if slot is not None or type(pair) is not str or nonce is not None:
                raise ReleaseV625Error("pair lineage evidence has invalid slot/pair binding")
        else:
            if slot is not None and slot not in SLOTS:
                raise ReleaseV625Error("global evidence slot_id is invalid")
            if pair is not None:
                raise ReleaseV625Error("non-pair evidence must have null pair_id")
            if nonce is not None:
                _nonce(nonce, "evidence unit_nonce")
        producer = _identifier(entry["producer_key_id"], "evidence producer_key_id")
        records.append(
            {
                "evidence_id": evidence_id,
                "path": path,
                "media_type": media_type,
                "byte_length": length,
                "sha256": digest,
                "slot_id": slot,
                "pair_id": pair,
                "unit_nonce": nonce,
                "evidence_purpose": purpose,
                "producer_key_id": producer,
            }
        )
        expected_evidence_id = canonical_sha256(
            {key: value for key, value in records[-1].items() if key != "evidence_id"}
        )
        if evidence_id != expected_evidence_id:
            raise ReleaseV625Error("evidence_id is not derived from canonical evidence metadata")
        evidence_ids.add(evidence_id)
        paths.add(path)
    if [record["path"] for record in records] != sorted(record["path"] for record in records):
        raise ReleaseV625Error("evidence manifest entries must be sorted by path")
    coverage = {(record["slot_id"], record["evidence_purpose"]) for record in records}
    for slot in SLOTS:
        missing = {purpose for purpose in _REQUIRED_UNIT_PURPOSES if (slot, purpose) not in coverage}
        if missing:
            raise ReleaseV625Error(f"{slot} is missing semantic evidence purposes: {sorted(missing)}")
    return {
        "raw": raw,
        "records": records,
        "by_id": {record["evidence_id"]: record for record in records},
        "root": canonical_sha256(raw),
    }


def _secure_evidence_inventory(
    base_dir: Path, manifest: Mapping[str, Any]
) -> tuple[str, dict[str, bytes]]:
    observed: list[dict[str, Any]] = []
    parsed_evidence: dict[str, bytes] = {}
    parsed_purposes = {
        "PAIR_LINEAGE_RECEIPT",
        "PAIR_INTERVENTION_RECEIPT",
        "VERIFIER_EXECUTION_TRANSCRIPT",
    }
    for record in manifest["records"]:
        relative = PurePosixPath(record["path"])
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        opened_directories: list[int] = []
        try:
            current_directory = os.open(base_dir, directory_flags)
            opened_directories.append(current_directory)
            for component in relative.parts[:-1]:
                current_directory = os.open(
                    component, directory_flags, dir_fd=current_directory
                )
                opened_directories.append(current_directory)
            descriptor = os.open(
                relative.parts[-1], file_flags, dir_fd=current_directory
            )
        except OSError as exc:
            for opened in reversed(opened_directories):
                os.close(opened)
            raise ReleaseV625Error(f"unable to open evidence safely: {record['path']}: {exc}") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != record["byte_length"]:
                raise ReleaseV625Error(f"evidence size/type mismatch: {record['path']}")
            digest = hashlib.sha256()
            captured = bytearray()
            remaining = before.st_size
            should_capture = record["evidence_purpose"] in parsed_purposes
            if should_capture and before.st_size > _MAX_PARSED_EVIDENCE_BYTES:
                raise ReleaseV625Error(
                    f"semantic receipt exceeds {_MAX_PARSED_EVIDENCE_BYTES} bytes: {record['path']}"
                )
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise ReleaseV625Error(f"evidence truncated during read: {record['path']}")
                digest.update(chunk)
                if should_capture:
                    captured.extend(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ReleaseV625Error(f"evidence grew during read: {record['path']}")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
            for opened in reversed(opened_directories):
                os.close(opened)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if identity_before != identity_after:
            raise ReleaseV625Error(f"evidence changed during read: {record['path']}")
        actual = digest.hexdigest()
        if actual != record["sha256"]:
            raise ReleaseV625Error(f"evidence hash mismatch: {record['path']}")
        observed.append(
            {"path": record["path"], "byte_length": before.st_size, "sha256": actual}
        )
        if should_capture:
            if record["media_type"] != "application/json":
                raise ReleaseV625Error(
                    f"semantic receipt must be canonical application/json: {record['path']}"
                )
            try:
                parsed = canonical_json_loads(bytes(captured))
            except (TypeError, ValueError) as exc:
                raise ReleaseV625Error(
                    f"semantic receipt is not strict canonical JSON: {record['path']}"
                ) from exc
            if canonical_json_bytes(parsed) != bytes(captured):
                raise ReleaseV625Error(
                    f"semantic receipt is not canonically encoded: {record['path']}"
                )
            parsed_evidence[record["evidence_id"]] = bytes(captured)
    return canonical_sha256(observed), parsed_evidence


def _identity_bindings(
    value: Any,
    *,
    bundle: Mapping[str, Any],
    release: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    if type(value) is not list or not value:
        raise ReleaseV625Error("identity bindings must be a nonempty array")
    registry_keys = {item["key_id"]: item for item in bundle["registry"]["keys"]}
    release_subjects = {
        record["identity_subject_id"]
        for group in release["authorities"].values()
        for record in group.values()
    } | {release["transparency"]["identity_subject_id"]} | {
        record["identity_subject_id"] for record in bootstrap["authorities"].values()
    }
    release_controls = {
        record["control_group_id"]
        for group in release["authorities"].values()
        for record in group.values()
    } | {release["transparency"]["control_group_id"]} | {
        record["control_group_id"] for record in bootstrap["authorities"].values()
    }
    result: dict[str, dict[str, str]] = {}
    subjects: dict[str, str] = {}
    controls: dict[str, str] = {}
    organizations: dict[str, str] = {}
    order: list[tuple[str, str]] = []
    for index, item in enumerate(value):
        raw = _exact(
            item,
            frozenset(
                {
                    "schema",
                    "key_id",
                    "role",
                    "identity_subject_id",
                    "control_group_id",
                    "organization_id",
                    "external_identity_receipt_sha256",
                }
            ),
            f"identity binding {index}",
        )
        if raw["schema"] != IDENTITY_BINDING_SCHEMA:
            raise ReleaseV625Error("identity binding schema is invalid")
        key_id = _identifier(raw["key_id"], "identity binding key_id")
        if key_id not in registry_keys or key_id in result:
            raise ReleaseV625Error("identity binding references an unknown or duplicated key")
        role = raw["role"]
        if role not in {ROLE_CONTRIBUTOR, ROLE_TECHNICAL, ROLE_LINEAGE, ROLE_ADJUDICATOR} or registry_keys[key_id]["role"] != role:
            raise ReleaseV625Error("identity binding role does not match registry role")
        subject = _identifier(raw["identity_subject_id"], "identity subject")
        control = _identifier(raw["control_group_id"], "identity control group")
        organization = _identifier(raw["organization_id"], "identity organization")
        if subject in release_subjects or control in release_controls:
            raise ReleaseV625Error("campaign identity aliases a release-root authority")
        if subject in subjects and subjects[subject] != role:
            raise ReleaseV625Error("one authenticated subject cannot occupy multiple role classes")
        if control in controls and controls[control] != role:
            raise ReleaseV625Error("one control group cannot occupy multiple role classes")
        if organization in organizations and organizations[organization] != role:
            raise ReleaseV625Error("one organization cannot occupy multiple role classes")
        identity_receipt = _sha(
            raw["external_identity_receipt_sha256"], "identity binding receipt"
        )
        if identity_receipt != registry_keys[key_id]["external_identity_receipt_sha256"]:
            raise ReleaseV625Error("identity binding receipt does not match the rooted registry")
        result[key_id] = {
            "key_id": key_id,
            "role": role,
            "identity_subject_id": subject,
            "control_group_id": control,
            "organization_id": organization,
            "external_identity_receipt_sha256": identity_receipt,
        }
        subjects[subject] = role
        controls[control] = role
        organizations[organization] = role
        order.append((role, key_id))
    if order != sorted(order):
        raise ReleaseV625Error("identity bindings must be sorted by role then key_id")
    identity_receipts = [
        binding["external_identity_receipt_sha256"] for binding in result.values()
    ]
    if len(identity_receipts) != len(set(identity_receipts)):
        raise ReleaseV625Error("identity bindings must use distinct external identity receipts")
    used_keys = set()
    for unit in bundle["units"]:
        used_keys.update(
            {
                unit["contributor_signature"]["key_id"],
                unit["technical_signature"]["key_id"],
                unit["lineage_signature"]["key_id"],
            }
        )
    used_keys.update(envelope["key_id"] for envelope in bundle["population_decision_approvals"])
    if not used_keys <= set(result):
        raise ReleaseV625Error("not every campaign signer has an authenticated identity binding")
    return result


def _validate_evidence_producers(
    manifest: Mapping[str, Any],
    identities: Mapping[str, Mapping[str, str]],
    release: Mapping[str, Any],
    bundle: Mapping[str, Any],
    revocation_head_sha256: str,
) -> None:
    external_keys = set(release["authorities"]["external_verifiers"])
    registry_admin_keys = set(release["authorities"]["registry_admins"])
    revocation_keys = set(release["authorities"]["revocation_authorities"])
    assigned_technical = {
        unit["slot_id"]: unit["technical_signature"]["key_id"] for unit in bundle["units"]
    }
    assigned_lineage = {
        unit["slot_id"]: unit["lineage_signature"]["key_id"] for unit in bundle["units"]
    }
    identity_evidence_digests = {
        record["sha256"]
        for record in manifest["records"]
        if record["evidence_purpose"] == "IDENTITY_EVIDENCE"
    }
    revocation_records = [
        record
        for record in manifest["records"]
        if record["evidence_purpose"] == "REVOCATION_LOG"
    ]
    if len(revocation_records) != 1 or revocation_records[0]["sha256"] != revocation_head_sha256:
        raise ReleaseV625Error("evidence manifest does not contain the exact current revocation log")
    for binding in identities.values():
        if binding["external_identity_receipt_sha256"] not in identity_evidence_digests:
            raise ReleaseV625Error("authenticated identity receipt bytes are absent from the manifest")
    for record in manifest["records"]:
        purpose = record["evidence_purpose"]
        producer = record["producer_key_id"]
        binding = identities.get(producer)
        if purpose in {"TECHNICAL_REBUILD", "LINUX_TRANSCRIPT", "SAFETY_HARNESS"}:
            if binding is None or binding["role"] != ROLE_TECHNICAL:
                raise ReleaseV625Error("technical evidence producer is not a technical auditor")
            if producer != assigned_technical[record["slot_id"]]:
                raise ReleaseV625Error("technical evidence was not produced by the assigned auditor")
        elif purpose in {
            "LINEAGE_VCS",
            "LINEAGE_SIMILARITY",
            "LINEAGE_PROVENANCE",
            "PAIR_LINEAGE_RECEIPT",
            "PAIR_INTERVENTION_RECEIPT",
        }:
            if binding is None or binding["role"] != ROLE_LINEAGE:
                raise ReleaseV625Error("lineage evidence producer is not a lineage auditor")
            if purpose not in {"PAIR_LINEAGE_RECEIPT", "PAIR_INTERVENTION_RECEIPT"} and producer != assigned_lineage[record["slot_id"]]:
                raise ReleaseV625Error("unit lineage evidence was not produced by the assigned auditor")
        elif purpose == "IDENTITY_EVIDENCE":
            if producer not in external_keys | registry_admin_keys:
                raise ReleaseV625Error("identity evidence producer is not release-pinned")
        elif purpose == "REVOCATION_LOG":
            if producer not in revocation_keys:
                raise ReleaseV625Error("revocation evidence producer is not release-pinned")
        elif purpose == "VERIFIER_EXECUTION_TRANSCRIPT":
            if producer not in external_keys:
                raise ReleaseV625Error("verifier transcript producer is not release-pinned")


def _principal_bindings(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    bundle: Mapping[str, Any],
    forbidden_principal_ids: set[str],
    forbidden_control_group_ids: set[str],
) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) != len(SLOTS):
        raise ReleaseV625Error("development-principal bindings must contain exactly 16 rows")
    result: dict[str, dict[str, Any]] = {}
    all_principals: set[str] = set()
    all_controls: set[str] = set()
    for expected_slot, item in zip(SLOTS, value):
        raw = _exact(
            item,
            frozenset(
                {
                    "schema",
                    "slot_id",
                    "principal_ids",
                    "control_group_ids",
                    "principal_evidence_ids",
                    "evidence_root_sha256",
                }
            ),
            f"principal binding {expected_slot}",
        )
        if raw["schema"] != PRINCIPAL_BINDING_SCHEMA or raw["slot_id"] != expected_slot:
            raise ReleaseV625Error("principal bindings must use canonical slot order")
        principals = _string_list(raw["principal_ids"], f"{expected_slot} principal_ids")
        controls = _string_list(raw["control_group_ids"], f"{expected_slot} control_group_ids")
        if set(principals) & forbidden_principal_ids or set(controls) & forbidden_control_group_ids:
            raise ReleaseV625Error(
                "development principals cannot alias bootstrap, release, or transparency authorities"
            )
        evidence_ids = _string_list(
            raw["principal_evidence_ids"], f"{expected_slot} principal_evidence_ids"
        )
        unit = next(item for item in bundle["units"] if item["slot_id"] == expected_slot)
        unit_nonce = unit["contributor_manifest"]["unit_nonce"]
        for evidence_id in evidence_ids:
            evidence = manifest["by_id"].get(evidence_id)
            if (
                evidence is None
                or evidence["evidence_purpose"] != "IDENTITY_EVIDENCE"
                or evidence["slot_id"] != expected_slot
                or evidence["unit_nonce"] != unit_nonce
            ):
                raise ReleaseV625Error(
                    "development-principal evidence is missing or not slot/unit-bound"
                )
        if all_principals & set(principals) or all_controls & set(controls):
            raise ReleaseV625Error("development principals and control groups must be pairwise disjoint across units")
        all_principals.update(principals)
        all_controls.update(controls)
        evidence_root = _sha(
            raw["evidence_root_sha256"], f"{expected_slot} principal evidence root"
        )
        expected_root = canonical_sha256(
            {
                "slot_id": expected_slot,
                "principal_ids": principals,
                "control_group_ids": controls,
                "principal_evidence_ids": evidence_ids,
            }
        )
        if evidence_root != expected_root:
            raise ReleaseV625Error(
                "development-principal evidence root is not metadata-derived"
            )
        result[expected_slot] = {
            "principal_ids": principals,
            "control_group_ids": controls,
            "principal_evidence_ids": evidence_ids,
            "evidence_root_sha256": evidence_root,
        }
    return result


def _required_pairs() -> list[tuple[str, str]]:
    return [
        (SLOTS[left], SLOTS[right])
        for left in range(len(SLOTS))
        for right in range(left + 1, len(SLOTS))
    ]


def _registry_public_keys(bundle: Mapping[str, Any]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for index, record in enumerate(bundle["registry"]["keys"]):
        key_id = _identifier(record["key_id"], f"registry key {index} key_id")
        public_key = _public_key(
            record["public_key_ed25519_base64"],
            f"registry key {index} public key",
        )
        if key_id != _key_id(public_key) or key_id in keys:
            raise ReleaseV625Error("registry public key is duplicated or misbound")
        keys[key_id] = public_key
    return keys


def _pair_lineage_receipt(
    payload_bytes: bytes,
    *,
    manifest_record: Mapping[str, Any],
    expected_pair: tuple[str, str],
    identities: Mapping[str, Mapping[str, str]],
    registry_public_keys: Mapping[str, bytes],
) -> dict[str, Any]:
    raw = _exact(
        canonical_json_loads(payload_bytes),
        frozenset(
            {
                "schema",
                "pair_id",
                "left_slot_id",
                "right_slot_id",
                "reviewer_key_id",
                "source_state",
                "exposure_state",
                "analysis_root_sha256",
                "signed_at_utc",
                "signature_ed25519_base64",
            }
        ),
        "pair lineage evidence receipt",
    )
    left, right = expected_pair
    pair_id = f"{left}:{right}"
    reviewer = raw["reviewer_key_id"]
    if (
        raw["schema"] != PAIR_LINEAGE_RECEIPT_SCHEMA
        or raw["pair_id"] != pair_id
        or (raw["left_slot_id"], raw["right_slot_id"]) != expected_pair
        or reviewer != manifest_record["producer_key_id"]
        or identities.get(reviewer, {}).get("role") != ROLE_LINEAGE
    ):
        raise ReleaseV625Error("pair lineage receipt identity or pair binding is invalid")
    if raw["source_state"] not in _SOURCE_STATES or raw["exposure_state"] not in _EXPOSURE_STATES:
        raise ReleaseV625Error("pair lineage receipt contains an unknown state")
    _sha(raw["analysis_root_sha256"], "pair lineage analysis root")
    signed_at = _utc(raw["signed_at_utc"], "pair lineage signed_at_utc")
    signed_payload = {key: value for key, value in raw.items() if key != "signature_ed25519_base64"}
    public_key = registry_public_keys.get(reviewer)
    if public_key is None:
        raise ReleaseV625Error("pair lineage reviewer public key is unavailable")
    _verify_signature(
        public_key=public_key,
        signature_value=raw["signature_ed25519_base64"],
        domain=DOMAIN_PAIR_LINEAGE_RECEIPT,
        payload=signed_payload,
    )
    return {
        "reviewer_key_id": reviewer,
        "source_state": raw["source_state"],
        "exposure_state": raw["exposure_state"],
        "signed_at": signed_at,
    }


def _pair_intervention_receipt(
    payload_bytes: bytes,
    *,
    manifest_record: Mapping[str, Any],
    expected_pair: tuple[str, str],
    identities: Mapping[str, Mapping[str, str]],
    registry_public_keys: Mapping[str, bytes],
) -> dict[str, Any]:
    raw = _exact(
        canonical_json_loads(payload_bytes),
        frozenset(
            {
                "schema",
                "pair_id",
                "left_slot_id",
                "right_slot_id",
                "reviewer_key_id",
                "intervention_state",
                "analysis_root_sha256",
                "signed_at_utc",
                "signature_ed25519_base64",
            }
        ),
        "pair intervention evidence receipt",
    )
    left, right = expected_pair
    pair_id = f"{left}:{right}"
    reviewer = raw["reviewer_key_id"]
    if (
        raw["schema"] != PAIR_INTERVENTION_RECEIPT_SCHEMA
        or raw["pair_id"] != pair_id
        or (raw["left_slot_id"], raw["right_slot_id"]) != expected_pair
        or reviewer != manifest_record["producer_key_id"]
        or identities.get(reviewer, {}).get("role") != ROLE_LINEAGE
    ):
        raise ReleaseV625Error("pair intervention receipt identity or pair binding is invalid")
    if raw["intervention_state"] not in _INTERVENTION_STATES:
        raise ReleaseV625Error("pair intervention receipt contains an unknown state")
    _sha(raw["analysis_root_sha256"], "pair intervention analysis root")
    signed_at = _utc(raw["signed_at_utc"], "pair intervention signed_at_utc")
    signed_payload = {key: value for key, value in raw.items() if key != "signature_ed25519_base64"}
    public_key = registry_public_keys.get(reviewer)
    if public_key is None:
        raise ReleaseV625Error("pair intervention reviewer public key is unavailable")
    _verify_signature(
        public_key=public_key,
        signature_value=raw["signature_ed25519_base64"],
        domain=DOMAIN_PAIR_INTERVENTION_RECEIPT,
        payload=signed_payload,
    )
    return {
        "reviewer_key_id": reviewer,
        "intervention_state": raw["intervention_state"],
        "signed_at": signed_at,
    }


def _derive_blocking_state(states: Sequence[str], *, kind: str) -> str:
    observed = set(states)
    if not observed:
        raise ReleaseV625Error(f"{kind} evidence has no reviewer findings")
    if kind == "source":
        for state in ("CONFLICT", "UNKNOWN", "DERIVED", "SHARED", "INDEPENDENT"):
            if state in observed:
                return state
    elif kind == "exposure":
        for state in ("CONFLICT", "UNKNOWN", "SHARED_FEEDBACK", "INDEPENDENT"):
            if state in observed:
                return state
    elif kind == "intervention":
        if "CONFLICT" in observed:
            return "CONFLICT"
        if "UNKNOWN" in observed:
            return "UNKNOWN"
        related = observed & {"SAME_INTERVENTION", "OVERLAPPING_INTERVENTION"}
        if related and "DISTINCT_INTERVENTION" in observed:
            return "CONFLICT"
        if "OVERLAPPING_INTERVENTION" in related:
            return "OVERLAPPING_INTERVENTION"
        if "SAME_INTERVENTION" in related:
            return "SAME_INTERVENTION"
        if observed == {"DISTINCT_INTERVENTION"}:
            return "DISTINCT_INTERVENTION"
    raise ReleaseV625Error(f"{kind} evidence contains an invalid state combination")


def _pair_reviews(
    value: Any,
    *,
    bundle: Mapping[str, Any],
    identities: Mapping[str, Mapping[str, str]],
    manifest: Mapping[str, Any],
    semantic_evidence: Mapping[str, bytes],
) -> dict[tuple[str, str], dict[str, Any]]:
    pairs = _required_pairs()
    if type(value) is not list or len(value) != len(pairs):
        raise ReleaseV625Error("pair reviews must contain exactly 120 rows")
    lineage_signers = {unit["slot_id"]: unit["lineage_signature"]["key_id"] for unit in bundle["units"]}
    public_keys = _registry_public_keys(bundle)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for expected_pair, item in zip(pairs, value):
        left, right = expected_pair
        raw = _exact(
            item,
            frozenset(
                {
                    "schema",
                    "left_slot_id",
                    "right_slot_id",
                    "reviewer_key_ids",
                    "source_state",
                    "exposure_state",
                    "intervention_state",
                    "evidence_ids",
                    "evidence_root_sha256",
                    "intervention_evidence_ids",
                    "intervention_evidence_root_sha256",
                }
            ),
            f"pair review {left}/{right}",
        )
        if raw["schema"] != PAIR_REVIEW_SCHEMA or (raw["left_slot_id"], raw["right_slot_id"]) != expected_pair:
            raise ReleaseV625Error("pair reviews must use canonical pair order")
        reviewers = _string_list(raw["reviewer_key_ids"], f"{left}/{right} reviewer_key_ids")
        if len(reviewers) < 2 or not {lineage_signers[left], lineage_signers[right]} <= set(reviewers):
            raise ReleaseV625Error("pair review must include both endpoint lineage reviewers and at least two reviewers")
        reviewer_bindings = []
        for key_id in reviewers:
            binding = identities.get(key_id)
            if binding is None or binding["role"] != ROLE_LINEAGE:
                raise ReleaseV625Error("pair reviewer is not an authenticated lineage auditor")
            reviewer_bindings.append(binding)
        for field in ("identity_subject_id", "control_group_id"):
            if len({binding[field] for binding in reviewer_bindings}) < 2:
                raise ReleaseV625Error("pair review lacks two independent lineage control groups")
        evidence_ids = _string_list(raw["evidence_ids"], f"{left}/{right} evidence_ids")
        pair_id = f"{left}:{right}"
        lineage_findings: list[dict[str, Any]] = []
        for evidence_id in evidence_ids:
            entry = manifest["by_id"].get(evidence_id)
            if entry is None or entry["evidence_purpose"] != "PAIR_LINEAGE_RECEIPT" or entry["pair_id"] != pair_id or entry["producer_key_id"] not in reviewers:
                raise ReleaseV625Error("pair review evidence is missing, misbound, or has the wrong producer")
            payload_bytes = semantic_evidence.get(evidence_id)
            if payload_bytes is None:
                raise ReleaseV625Error("pair lineage evidence bytes are unavailable")
            lineage_findings.append(
                _pair_lineage_receipt(
                    payload_bytes,
                    manifest_record=entry,
                    expected_pair=expected_pair,
                    identities=identities,
                    registry_public_keys=public_keys,
                )
            )
        if (
            len(lineage_findings) != len(reviewers)
            or {item["reviewer_key_id"] for item in lineage_findings} != set(reviewers)
        ):
            raise ReleaseV625Error("every pair reviewer must provide one signed lineage finding")
        source_state = _derive_blocking_state(
            [item["source_state"] for item in lineage_findings], kind="source"
        )
        exposure_state = _derive_blocking_state(
            [item["exposure_state"] for item in lineage_findings], kind="exposure"
        )
        if raw["source_state"] != source_state or raw["exposure_state"] != exposure_state:
            raise ReleaseV625Error("pair lineage states are not derived from signed evidence")
        if source_state != "INDEPENDENT" or exposure_state != "INDEPENDENT":
            raise ReleaseV625Error("blocking pair evidence prevents independence")
        evidence_root = _sha(raw["evidence_root_sha256"], "pair evidence root")
        if evidence_root != canonical_sha256(
            {"pair_id": pair_id, "evidence_ids": evidence_ids}
        ):
            raise ReleaseV625Error("pair review evidence root is not metadata-derived")
        intervention_evidence_ids = _string_list(
            raw["intervention_evidence_ids"],
            f"{left}/{right} intervention_evidence_ids",
        )
        intervention_findings: list[dict[str, Any]] = []
        for evidence_id in intervention_evidence_ids:
            entry = manifest["by_id"].get(evidence_id)
            if (
                entry is None
                or entry["evidence_purpose"] != "PAIR_INTERVENTION_RECEIPT"
                or entry["pair_id"] != pair_id
                or entry["producer_key_id"] not in reviewers
            ):
                raise ReleaseV625Error(
                    "pair intervention evidence is missing, misbound, or has the wrong producer"
                )
            payload_bytes = semantic_evidence.get(evidence_id)
            if payload_bytes is None:
                raise ReleaseV625Error("pair intervention evidence bytes are unavailable")
            intervention_findings.append(
                _pair_intervention_receipt(
                    payload_bytes,
                    manifest_record=entry,
                    expected_pair=expected_pair,
                    identities=identities,
                    registry_public_keys=public_keys,
                )
            )
        if (
            len(intervention_findings) != len(reviewers)
            or {item["reviewer_key_id"] for item in intervention_findings}
            != set(reviewers)
        ):
            raise ReleaseV625Error(
                "every pair reviewer must provide one signed intervention finding"
            )
        intervention_state = _derive_blocking_state(
            [item["intervention_state"] for item in intervention_findings],
            kind="intervention",
        )
        if raw["intervention_state"] != intervention_state:
            raise ReleaseV625Error(
                "pair intervention state is not derived from signed evidence"
            )
        intervention_root = _sha(
            raw["intervention_evidence_root_sha256"],
            "pair intervention evidence root",
        )
        if intervention_root != canonical_sha256(
            {"pair_id": pair_id, "evidence_ids": intervention_evidence_ids}
        ):
            raise ReleaseV625Error(
                "pair intervention evidence root is not metadata-derived"
            )
        if intervention_state in {"UNKNOWN", "CONFLICT"}:
            raise ReleaseV625Error("blocking intervention evidence prevents diversity")
        result[expected_pair] = {
            "reviewers": reviewers,
            "source_state": source_state,
            "exposure_state": exposure_state,
            "intervention_state": intervention_state,
            "evidence_ids": evidence_ids,
            "evidence_root_sha256": evidence_root,
            "intervention_evidence_ids": intervention_evidence_ids,
            "intervention_evidence_root_sha256": intervention_root,
            "signed_at_values": [
                item["signed_at"]
                for item in lineage_findings + intervention_findings
            ],
        }
    return result


def _graph(
    value: Any,
    *,
    schema: str,
    policy_sha256: str,
    pair_reviews: Mapping[tuple[str, str], Mapping[str, Any]],
    state_field: str,
) -> Mapping[str, Any]:
    label = "source graph" if schema == SOURCE_GRAPH_SCHEMA else "exposure graph"
    raw = _exact(value, frozenset({"schema", "policy_sha256", "nodes", "edges"}), label)
    if raw["schema"] != schema or _sha(raw["policy_sha256"], f"{label} policy") != policy_sha256:
        raise ReleaseV625Error(f"{label} is not policy-bound")
    if raw["nodes"] != list(SLOTS):
        raise ReleaseV625Error(f"{label} nodes must be the canonical 16 slots")
    pairs = _required_pairs()
    if type(raw["edges"]) is not list or len(raw["edges"]) != len(pairs):
        raise ReleaseV625Error(f"{label} must contain exactly 120 edges")
    for expected_pair, item in zip(pairs, raw["edges"]):
        edge = _exact(
            item,
            frozenset({"left_slot_id", "right_slot_id", "state", "evidence_root_sha256"}),
            f"{label} edge",
        )
        if (edge["left_slot_id"], edge["right_slot_id"]) != expected_pair:
            raise ReleaseV625Error(f"{label} edges must use canonical pair order")
        expected_state = pair_reviews[expected_pair][state_field]
        if edge["state"] != expected_state or edge["state"] != "INDEPENDENT":
            raise ReleaseV625Error(f"{label} contains a blocking or inconsistent edge")
        if _sha(edge["evidence_root_sha256"], f"{label} edge evidence") != pair_reviews[expected_pair]["evidence_root_sha256"]:
            raise ReleaseV625Error(f"{label} edge does not bind pair evidence")
    return raw


def _intervention_graph(
    value: Any,
    *,
    policy_sha256: str,
    pair_reviews: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[Mapping[str, Any], dict[str, tuple[str, ...]]]:
    raw = _exact(
        value,
        frozenset({"schema", "policy_sha256", "nodes", "edges"}),
        "intervention graph",
    )
    if (
        raw["schema"] != INTERVENTION_GRAPH_SCHEMA
        or _sha(raw["policy_sha256"], "intervention graph policy")
        != policy_sha256
    ):
        raise ReleaseV625Error("intervention graph is not policy-bound")
    if raw["nodes"] != list(SLOTS):
        raise ReleaseV625Error("intervention graph nodes must be canonical slots")
    pairs = _required_pairs()
    if type(raw["edges"]) is not list or len(raw["edges"]) != len(pairs):
        raise ReleaseV625Error("intervention graph must contain exactly 120 edges")
    parent = {slot: slot for slot in SLOTS}

    def find(slot: str) -> str:
        while parent[slot] != slot:
            parent[slot] = parent[parent[slot]]
            slot = parent[slot]
        return slot

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for expected_pair, item in zip(pairs, raw["edges"]):
        edge = _exact(
            item,
            frozenset({"left_slot_id", "right_slot_id", "state", "evidence_root_sha256"}),
            "intervention graph edge",
        )
        if (edge["left_slot_id"], edge["right_slot_id"]) != expected_pair:
            raise ReleaseV625Error("intervention graph edges must use canonical pair order")
        review = pair_reviews[expected_pair]
        if edge["state"] != review["intervention_state"]:
            raise ReleaseV625Error("intervention graph disagrees with pair review")
        if edge["evidence_root_sha256"] != review["intervention_evidence_root_sha256"]:
            raise ReleaseV625Error("intervention graph edge does not bind pair evidence")
        if edge["state"] in {"UNKNOWN", "CONFLICT"}:
            raise ReleaseV625Error("intervention graph contains a blocking state")
        if edge["state"] in {"SAME_INTERVENTION", "OVERLAPPING_INTERVENTION"}:
            union(*expected_pair)
    components: dict[str, list[str]] = {}
    for slot in SLOTS:
        components.setdefault(find(slot), []).append(slot)
    component_by_slot: dict[str, tuple[str, ...]] = {}
    for members in components.values():
        canonical_members = tuple(sorted(members))
        for slot in canonical_members:
            component_by_slot[slot] = canonical_members
    return raw, component_by_slot


def _derived_assignments(
    value: Any,
    *,
    release: Mapping[str, Any],
    source_graph: Mapping[str, Any],
    exposure_graph: Mapping[str, Any],
    intervention_graph: Mapping[str, Any],
    intervention_components: Mapping[str, tuple[str, ...]],
) -> dict[str, dict[str, str]]:
    if type(value) is not list or len(value) != len(SLOTS):
        raise ReleaseV625Error("derived assignments must contain exactly 16 rows")
    source_root = canonical_sha256(source_graph)
    exposure_root = canonical_sha256(exposure_graph)
    intervention_root = canonical_sha256(intervention_graph)
    result: dict[str, dict[str, str]] = {}
    for expected_slot, item in zip(SLOTS, value):
        raw = _exact(
            item,
            frozenset({"schema", "slot_id", "source_family_id", "lineage_time_block_id", "intervention_family_id"}),
            f"derived assignment {expected_slot}",
        )
        if raw["schema"] != DERIVED_ASSIGNMENT_SCHEMA or raw["slot_id"] != expected_slot:
            raise ReleaseV625Error("derived assignments must use canonical slot order")
        expected_family = "sf-" + canonical_sha256(
            {
                "policy_version": release["lineage_policy_sha256"],
                "members": [expected_slot],
                "source_graph_root": source_root,
            }
        )[:24]
        expected_lineage = "lt-" + canonical_sha256(
            {
                "policy_version": release["lineage_policy_sha256"],
                "members": [expected_slot],
                "exposure_graph_root": exposure_root,
            }
        )[:24]
        expected_intervention = "if-" + canonical_sha256(
            {
                "policy_version": release["intervention_policy_sha256"],
                "members": list(intervention_components[expected_slot]),
                "intervention_graph_root": intervention_root,
            }
        )[:24]
        if raw["source_family_id"] != expected_family or _FAMILY_RE.fullmatch(raw["source_family_id"]) is None:
            raise ReleaseV625Error("source family ID is not component-derived")
        if raw["lineage_time_block_id"] != expected_lineage or _LINEAGE_RE.fullmatch(raw["lineage_time_block_id"]) is None:
            raise ReleaseV625Error("lineage-time ID is not component-derived")
        if (
            raw["intervention_family_id"] != expected_intervention
            or _INTERVENTION_RE.fullmatch(raw["intervention_family_id"]) is None
        ):
            raise ReleaseV625Error("intervention family ID is not component-derived")
        result[expected_slot] = {
            "source_family_id": expected_family,
            "lineage_time_block_id": expected_lineage,
            "intervention_family_id": expected_intervention,
        }
    for field in ("source_family_id", "lineage_time_block_id"):
        values = [result[slot][field] for slot in SLOTS]
        if len(values) != len(set(values)):
            raise ReleaseV625Error(f"all 16 derived {field} values must be distinct")
    return result


def _active_slots(primary: tuple[str, ...], reserve: str) -> tuple[tuple[str, ...], ...]:
    return (primary,) + tuple(
        tuple(reserve if slot == failed else slot for slot in primary) for failed in primary
    )


def _intervention_diversity(assignments: Mapping[str, Mapping[str, str]]) -> None:
    for active_sets, minimum, label in (
        (_active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT), 3, "DEV"),
        (_active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT), 4, "CONFIRM"),
    ):
        for active in active_sets:
            if len({assignments[slot]["intervention_family_id"] for slot in active}) < minimum:
                raise ReleaseV625Error(f"{label} intervention diversity fails reserve replacement")
    for dev_active in _active_slots(DEV_PRIMARY_SLOTS, DEV_RESERVE_SLOT):
        for confirm_active in _active_slots(CONFIRM_PRIMARY_SLOTS, CONFIRM_RESERVE_SLOT):
            if len({assignments[slot]["intervention_family_id"] for slot in dev_active + confirm_active}) < 5:
                raise ReleaseV625Error("overall intervention diversity fails reserve replacement")


def _role_caps(
    bundle: Mapping[str, Any], identities: Mapping[str, Mapping[str, str]]
) -> None:
    signer_keys = {
        "contributor": {unit["slot_id"]: unit["contributor_signature"]["key_id"] for unit in bundle["units"]},
        "technical": {unit["slot_id"]: unit["technical_signature"]["key_id"] for unit in bundle["units"]},
        "lineage": {unit["slot_id"]: unit["lineage_signature"]["key_id"] for unit in bundle["units"]},
    }
    for identity_field in ("identity_subject_id", "control_group_id"):
        contributors = {slot: identities[key][identity_field] for slot, key in signer_keys["contributor"].items()}
        counts = Counter(contributors.values())
        if len(counts) < 13 or max(counts.values()) > 2:
            raise ReleaseV625Error(f"contributor {identity_field} caps fail")
        dev_primary = {contributors[slot] for slot in DEV_PRIMARY_SLOTS}
        confirm = {contributors[slot] for slot in CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)}
        reserve = contributors[DEV_RESERVE_SLOT]
        if len(dev_primary) < 3 or len(confirm) != 9 or reserve in dev_primary or reserve in confirm or (dev_primary | {reserve}) & confirm:
            raise ReleaseV625Error(f"contributor tranche separation fails for {identity_field}")
        for role in ("technical", "lineage"):
            values = {slot: identities[key][identity_field] for slot, key in signer_keys[role].items()}
            role_counts = Counter(values.values())
            if len(role_counts) < 4 or max(role_counts.values()) > 4:
                raise ReleaseV625Error(f"{role} auditor caps fail for {identity_field}")
    pair_counts = Counter(
        (
            identities[signer_keys["technical"][slot]]["control_group_id"],
            identities[signer_keys["lineage"][slot]]["control_group_id"],
        )
        for slot in SLOTS
    )
    if max(pair_counts.values()) > 2:
        raise ReleaseV625Error("technical/lineage control-group pair cap fails")


def _adjudicator_quorum(
    bundle: Mapping[str, Any], identities: Mapping[str, Mapping[str, str]]
) -> None:
    registry_adjudicators = {
        record["key_id"]
        for record in bundle["registry"]["keys"]
        if record["role"] == ROLE_ADJUDICATOR
    }
    if len(registry_adjudicators) != 3 or not registry_adjudicators <= set(identities):
        raise ReleaseV625Error("three authenticated adjudicators are required")
    for field in ("identity_subject_id", "control_group_id"):
        values = {identities[key_id][field] for key_id in registry_adjudicators}
        if len(values) != 3:
            raise ReleaseV625Error(f"adjudicators must occupy three distinct {field} values")
    approval_keys = [item["key_id"] for item in bundle["population_decision_approvals"]]
    if len(set(approval_keys)) < 2 or not set(approval_keys) <= registry_adjudicators:
        raise ReleaseV625Error("population decision lacks an authenticated adjudicator quorum")
    if len({identities[key]["control_group_id"] for key in approval_keys}) < 2:
        raise ReleaseV625Error("population adjudicator approvals share one control group")


def _transparency_payload_hashes(
    *,
    release_authorization: Mapping[str, Any],
    registry: Mapping[str, Any],
    registry_epoch: int,
    revocation_sequence: int,
    revocation_head: str,
    verification_challenge_nonce: str,
) -> dict[str, str]:
    return {
        "REGISTRY_STATE": canonical_sha256(
            {
                "registry_epoch": registry_epoch,
                "registry_root_sha256": canonical_sha256(registry),
            }
        ),
        "RELEASE_ROOT_AUTHORIZATION": release_authorization[
            "authorization_root_sha256"
        ],
        "REVOCATION_HEAD": canonical_sha256(
            {
                "revocation_sequence": revocation_sequence,
                "revocation_log_head_sha256": revocation_head,
            }
        ),
        "VERIFICATION_CHALLENGE": canonical_sha256(
            {"verification_challenge_nonce": verification_challenge_nonce}
        ),
    }


def _transparency_checkpoint(
    value: Any,
    *,
    release: Mapping[str, Any],
    release_authorization: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    registry: Mapping[str, Any],
    registry_epoch: int,
    revocation_sequence: int,
    revocation_head: str,
    verification_challenge_nonce: str,
) -> tuple[Mapping[str, Any], datetime]:
    wrapper = _exact(
        value,
        frozenset({"schema", "key_id", "receipt", "receipt_sha256", "signature_ed25519_base64"}),
        "transparency checkpoint envelope",
    )
    if wrapper["schema"] != TRANSPARENCY_ENVELOPE_SCHEMA or wrapper["key_id"] != release["transparency"]["key_id"]:
        raise ReleaseV625Error("transparency checkpoint signer is not release-pinned")
    receipt = _exact(
        wrapper["receipt"],
        frozenset(
            {
                "schema",
                "log_id",
                "release_root_sha256",
                "release_root_authorization_sha256",
                "authorization_sequence",
                "registry_epoch",
                "revocation_sequence",
                "revocation_log_head_sha256",
                "verification_challenge_nonce",
                "checkpoint_sequence",
                "previous_checkpoint_sha256",
                "tree_size",
                "tree_root_sha256",
                "previous_tree_size",
                "previous_tree_root_sha256",
                "inclusion_proofs",
                "consistency_proof_sha256s",
                "trusted_time_source",
                "observed_at_utc",
            }
        ),
        "transparency checkpoint receipt",
    )
    if wrapper["receipt_sha256"] != canonical_sha256(receipt):
        raise ReleaseV625Error("transparency envelope does not bind its receipt")
    if (
        receipt["schema"] != TRANSPARENCY_CHECKPOINT_SCHEMA
        or receipt["log_id"] != release["transparency"]["log_id"]
        or receipt["release_root_sha256"] != release["sha256"]
    ):
        raise ReleaseV625Error("transparency checkpoint is not release-bound")
    if (
        receipt["release_root_authorization_sha256"]
        != release_authorization["authorization_root_sha256"]
        or type(receipt["authorization_sequence"]) is not int
        or isinstance(receipt["authorization_sequence"], bool)
        or receipt["authorization_sequence"] != release_authorization["sequence"]
    ):
        raise ReleaseV625Error(
            "transparency checkpoint does not bind the release authorization"
        )
    if (
        type(receipt["registry_epoch"]) is not int
        or isinstance(receipt["registry_epoch"], bool)
        or type(receipt["revocation_sequence"]) is not int
        or isinstance(receipt["revocation_sequence"], bool)
        or receipt["registry_epoch"] != registry_epoch
        or receipt["revocation_sequence"] != revocation_sequence
        or receipt["revocation_log_head_sha256"] != revocation_head
    ):
        raise ReleaseV625Error("transparency checkpoint does not bind current registry/revocation state")
    if (
        registry_epoch < bootstrap["previous_registry_epoch"]
        or revocation_sequence < bootstrap["previous_revocation_sequence"]
    ):
        raise ReleaseV625Error(
            "transparency checkpoint regresses registry or revocation state"
        )
    if receipt["verification_challenge_nonce"] != verification_challenge_nonce:
        raise ReleaseV625Error("transparency checkpoint does not bind the invocation challenge")
    checkpoint_sequence = receipt["checkpoint_sequence"]
    if (
        type(checkpoint_sequence) is not int
        or isinstance(checkpoint_sequence, bool)
        or checkpoint_sequence <= bootstrap["minimum_checkpoint_sequence"]
    ):
        raise ReleaseV625Error("transparency checkpoint sequence is not newer than its pin")
    if receipt["previous_checkpoint_sha256"] != bootstrap["previous_checkpoint_sha256"]:
        raise ReleaseV625Error("transparency checkpoint predecessor is not code-pinned")
    tree_size = receipt["tree_size"]
    previous_tree_size = receipt["previous_tree_size"]
    if (
        type(tree_size) is not int
        or isinstance(tree_size, bool)
        or type(previous_tree_size) is not int
        or isinstance(previous_tree_size, bool)
        or previous_tree_size != bootstrap["previous_transparency_tree_size"]
        or tree_size < previous_tree_size + 2
    ):
        raise ReleaseV625Error("transparency tree size is not a strict append-only extension")
    tree_root = _sha(receipt["tree_root_sha256"], "transparency tree root")
    previous_tree_root = _sha(
        receipt["previous_tree_root_sha256"], "previous transparency tree root"
    )
    if previous_tree_root != bootstrap["previous_transparency_root_sha256"]:
        raise ReleaseV625Error("transparency predecessor root is not code-pinned")
    expected_payloads = _transparency_payload_hashes(
        release_authorization=release_authorization,
        registry=registry,
        registry_epoch=registry_epoch,
        revocation_sequence=revocation_sequence,
        revocation_head=revocation_head,
        verification_challenge_nonce=verification_challenge_nonce,
    )
    proofs = receipt["inclusion_proofs"]
    if type(proofs) is not list or len(proofs) != len(_TRANSPARENCY_KINDS):
        raise ReleaseV625Error("transparency checkpoint requires four inclusion proofs")
    observed_kinds: list[str] = []
    leaf_indices: set[int] = set()
    for index, item in enumerate(proofs):
        proof = _exact(
            item,
            frozenset(
                {"kind", "payload_sha256", "leaf_index", "audit_path_sha256s"}
            ),
            f"transparency inclusion proof {index}",
        )
        kind = _identifier(proof["kind"], "transparency inclusion kind")
        if kind not in expected_payloads:
            raise ReleaseV625Error("transparency inclusion proof kind is unknown")
        if proof["payload_sha256"] != expected_payloads[kind]:
            raise ReleaseV625Error(
                "transparency inclusion proof does not bind its current payload"
            )
        leaf_index = proof["leaf_index"]
        if type(leaf_index) is not int or isinstance(leaf_index, bool):
            raise ReleaseV625Error("transparency inclusion leaf index is invalid")
        if leaf_index in leaf_indices:
            raise ReleaseV625Error("transparency inclusion proofs reuse one leaf")
        if kind in {"RELEASE_ROOT_AUTHORIZATION", "VERIFICATION_CHALLENGE"} and leaf_index < previous_tree_size:
            raise ReleaseV625Error(
                "new release authorization and challenge must be appended after the pinned tree"
            )
        path = _ordered_sha_list(
            proof["audit_path_sha256s"],
            "transparency inclusion audit path",
            allow_empty=True,
        )
        verify_transparency_inclusion(
            leaf_hash=transparency_leaf_hash(kind, expected_payloads[kind]),
            leaf_index=leaf_index,
            tree_size=tree_size,
            audit_path_sha256s=path,
            expected_root_sha256=tree_root,
        )
        observed_kinds.append(kind)
        leaf_indices.add(leaf_index)
    if observed_kinds != list(_TRANSPARENCY_KINDS):
        raise ReleaseV625Error(
            "transparency inclusion proofs must use canonical kind order"
        )
    consistency_proof = _ordered_sha_list(
        receipt["consistency_proof_sha256s"],
        "transparency consistency proof",
        allow_empty=True,
    )
    verify_transparency_consistency(
        old_tree_size=previous_tree_size,
        new_tree_size=tree_size,
        old_root_sha256=previous_tree_root,
        new_root_sha256=tree_root,
        consistency_path_sha256s=consistency_proof,
    )
    if receipt["trusted_time_source"] != "SIGNED_TRANSPARENCY_CHECKPOINT_V1":
        raise ReleaseV625Error("transparency checkpoint lacks an accepted trusted-time source")
    _verify_signature(
        public_key=release["transparency"]["public_key"],
        signature_value=wrapper["signature_ed25519_base64"],
        domain=DOMAIN_TRANSPARENCY_CHECKPOINT,
        payload=receipt,
    )
    observed_at = _utc(receipt["observed_at_utc"], "transparency observed_at_utc")
    if release_authorization["issued_at"] > observed_at:
        raise ReleaseV625Error("release authorization postdates its transparency checkpoint")
    return receipt, observed_at


def _campaign_signature_chronology(
    bundle: Mapping[str, Any],
    *,
    release_issued_at: datetime,
    trust_opened_at: datetime,
    checkpoint_time: datetime,
    pair_reviews: Mapping[tuple[str, str], Mapping[str, Any]],
) -> None:
    governance_envelopes: list[Mapping[str, Any]] = []
    governance_envelopes.extend(bundle["registry_approvals"])
    governance_envelopes.extend(bundle["revocation_approvals"])
    for envelope in governance_envelopes:
        signed_at = _utc(envelope["signed_at_utc"], "governance evidence signed_at_utc")
        if not release_issued_at <= signed_at <= checkpoint_time:
            raise ReleaseV625Error(
                "governance evidence signature is outside release/checkpoint chronology"
            )
    envelopes: list[Mapping[str, Any]] = []
    envelopes.extend(bundle["population_decision_approvals"])
    for unit in bundle["units"]:
        envelopes.extend(
            (
                unit["contributor_signature"],
                unit["technical_signature"],
                unit["lineage_signature"],
            )
        )
    for envelope in envelopes:
        signed_at = _utc(envelope["signed_at_utc"], "campaign evidence signed_at_utc")
        if not trust_opened_at <= signed_at <= checkpoint_time:
            raise ReleaseV625Error(
                "campaign evidence signature is outside authorization/checkpoint chronology"
            )
    for review in pair_reviews.values():
        for signed_at in review["signed_at_values"]:
            if not trust_opened_at <= signed_at <= checkpoint_time:
                raise ReleaseV625Error(
                    "pair evidence signature is outside authorization/checkpoint chronology"
                )


def _revocation_head_approvals(
    value: Any,
    *,
    release: Mapping[str, Any],
    registry_epoch: int,
    revocation_sequence: int,
    revocation_head: str,
    checkpoint_time: datetime,
) -> list[str]:
    if type(value) is not list:
        raise ReleaseV625Error("revocation head approvals must be an array")
    authorities = release["authorities"]["revocation_authorities"]
    signers: set[str] = set()
    controls: set[str] = set()
    receipt_hashes: set[str] = set()
    for index, item in enumerate(value):
        wrapper = _exact(
            item,
            frozenset({"schema", "authority_key_id", "receipt", "receipt_sha256", "signature_ed25519_base64"}),
            f"revocation head envelope {index}",
        )
        if wrapper["schema"] != REVOCATION_HEAD_ENVELOPE_SCHEMA:
            raise ReleaseV625Error("revocation head envelope schema is invalid")
        key_id = wrapper["authority_key_id"]
        authority = authorities.get(key_id)
        if authority is None or key_id in signers:
            raise ReleaseV625Error("revocation authority is unknown or duplicated")
        receipt = _exact(
            wrapper["receipt"],
            frozenset(
                {
                    "schema",
                    "release_root_sha256",
                    "registry_epoch",
                    "revocation_sequence",
                    "revocation_log_head_sha256",
                    "revocation_semantics",
                    "issued_at_utc",
                }
            ),
            f"revocation head receipt {index}",
        )
        if wrapper["receipt_sha256"] != canonical_sha256(receipt):
            raise ReleaseV625Error("revocation head envelope does not bind its receipt")
        if (
            receipt["schema"] != REVOCATION_HEAD_SCHEMA
            or receipt["release_root_sha256"] != release["sha256"]
            or type(receipt["registry_epoch"]) is not int
            or type(receipt["revocation_sequence"]) is not int
            or receipt["registry_epoch"] != registry_epoch
            or receipt["revocation_sequence"] != revocation_sequence
            or receipt["revocation_log_head_sha256"] != revocation_head
        ):
            raise ReleaseV625Error("revocation head receipt is not current-state-bound")
        if receipt["revocation_semantics"] != "COMPROMISE_RETROACTIVE_ROUTINE_PROSPECTIVE_V1":
            raise ReleaseV625Error("revocation semantics are ambiguous or unrecognized")
        issued = _utc(receipt["issued_at_utc"], "revocation head issued_at_utc")
        authority_age = (checkpoint_time - issued).total_seconds()
        if not 0 <= authority_age <= release["transparency"]["maximum_checkpoint_age_seconds"]:
            raise ReleaseV625Error("revocation authority receipt is stale or later than checkpoint")
        _verify_signature(
            public_key=authority["public_key"],
            signature_value=wrapper["signature_ed25519_base64"],
            domain=DOMAIN_REVOCATION_HEAD,
            payload=receipt,
        )
        signers.add(key_id)
        controls.add(authority["control_group_id"])
        receipt_hashes.add(canonical_sha256(receipt))
    if len(signers) < 2 or len(controls) < 2:
        raise ReleaseV625Error("revocation head requires 2-of-3 distinct authority control groups")
    if len(receipt_hashes) != 1:
        raise ReleaseV625Error("revocation authorities approved different head payloads")
    return sorted(receipt_hashes)


def _unit_record_hashes(value: Any, *, bundle: Mapping[str, Any]) -> list[dict[str, str]]:
    if type(value) is not list or len(value) != len(SLOTS):
        raise ReleaseV625Error("unit_record_hashes must contain exactly 16 rows")
    result = []
    for expected_slot, item, unit in zip(SLOTS, value, bundle["units"]):
        raw = _exact(item, frozenset({"slot_id", "unit_record_sha256"}), f"unit hash {expected_slot}")
        if raw["slot_id"] != expected_slot or _sha(raw["unit_record_sha256"], "unit record hash") != canonical_sha256(unit):
            raise ReleaseV625Error("unit record hash does not bind canonical unit evidence")
        result.append(dict(raw))
    return result


def _verifier_execution_transcript(
    payload_bytes: bytes,
    *,
    manifest_record: Mapping[str, Any],
    authority: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    transcript = _exact(
        canonical_json_loads(payload_bytes),
        frozenset(
            {
                "schema",
                "authority_key_id",
                "authority_identity_subject_id",
                "authority_control_group_id",
                "verification_session_id",
                "authority_challenge_nonce",
                "verification_challenge_nonce",
                "release_root_authorization_sha256",
                "authorization_sequence",
                "recruitment_release_root_sha256",
                "campaign_bundle_root_sha256",
                "registry_epoch",
                "revocation_sequence",
                "measured_verifier_module_or_binary_sha256",
                "execution_environment_attestation_sha256",
                "check_vector",
                "started_at_utc",
                "completed_at_utc",
            }
        ),
        "verifier execution transcript",
    )
    if transcript["schema"] != VERIFIER_EXECUTION_TRANSCRIPT_SCHEMA:
        raise ReleaseV625Error("verifier execution transcript schema is invalid")
    if (
        transcript["authority_key_id"] != manifest_record["producer_key_id"]
        or transcript["authority_key_id"] != receipt["authority_key_id"]
        or transcript["authority_identity_subject_id"]
        != authority["identity_subject_id"]
        or transcript["authority_control_group_id"] != authority["control_group_id"]
    ):
        raise ReleaseV625Error("verifier transcript authority is misbound")
    receipt_fields = (
        "verification_session_id",
        "authority_challenge_nonce",
        "verification_challenge_nonce",
        "release_root_authorization_sha256",
        "authorization_sequence",
        "recruitment_release_root_sha256",
        "campaign_bundle_root_sha256",
        "registry_epoch",
        "revocation_sequence",
        "measured_verifier_module_or_binary_sha256",
        "execution_environment_attestation_sha256",
        "check_vector",
        "started_at_utc",
        "completed_at_utc",
    )
    for field in receipt_fields:
        if (
            (type(receipt[field]) is int and type(transcript[field]) is not int)
            or transcript[field] != receipt[field]
        ):
            raise ReleaseV625Error(
                f"verifier transcript does not bind receipt field {field}"
            )
    return dict(transcript)


def _verification_receipts(
    value: Any,
    *,
    release: Mapping[str, Any],
    expected: Mapping[str, Any],
    checkpoint_time: datetime,
    manifest: Mapping[str, Any],
    semantic_evidence: Mapping[str, bytes],
) -> tuple[list[str], datetime, list[dict[str, str]]]:
    if type(value) is not list:
        raise ReleaseV625Error("external verification receipts must be an array")
    authorities = release["authorities"]["external_verifiers"]
    signers: set[str] = set()
    controls: set[str] = set()
    nonces: set[str] = set()
    builds: set[str] = set()
    issued_times: list[datetime] = []
    receipt_hashes: list[str] = []
    session_ids: set[str] = set()
    authority_challenges: set[str] = set()
    transcript_roots: set[str] = set()
    environment_attestations: set[str] = set()
    check_vector_roots: set[str] = set()
    session_records: list[dict[str, str]] = []
    for index, item in enumerate(value):
        wrapper = _exact(
            item,
            frozenset({"schema", "authority_key_id", "receipt", "receipt_sha256", "signature_ed25519_base64"}),
            f"verification envelope {index}",
        )
        if wrapper["schema"] != VERIFICATION_ENVELOPE_SCHEMA:
            raise ReleaseV625Error("verification envelope schema is invalid")
        key_id = wrapper["authority_key_id"]
        authority = authorities.get(key_id)
        if authority is None or key_id in signers:
            raise ReleaseV625Error("verification authority is unknown or duplicated")
        receipt = _exact(
            wrapper["receipt"],
            frozenset(
                {
                    "schema",
                    "authority_identity_subject_id",
                    "authority_control_group_id",
                    "verification_session_id",
                    "authority_challenge_nonce",
                    "release_root_authorization_sha256",
                    "authorization_sequence",
                    "recruitment_release_root_sha256",
                    "campaign_bundle_root_sha256",
                    "registry_epoch",
                    "revocation_sequence",
                    "revocation_log_head_sha256",
                    "verification_challenge_nonce",
                    "revocation_head_receipts_root_sha256",
                    "transparency_checkpoint_sha256",
                    "transparency_tree_root_sha256",
                    "transparency_tree_size",
                    "transparency_checkpoint_sequence",
                    "release_packet_without_receipts_sha256",
                    "evidence_manifest_root_sha256",
                    "evidence_bytes_root_sha256",
                    "retrieved_evidence_byte_root_sha256",
                    "execution_transcript_root_sha256",
                    "unit_record_hashes_root_sha256",
                    "population_graph_sha256",
                    "population_decision_sha256",
                    "source_graph_root_sha256",
                    "exposure_graph_root_sha256",
                    "intervention_graph_root_sha256",
                    "pair_reviews_root_sha256",
                    "identity_bindings_root_sha256",
                    "principal_bindings_root_sha256",
                    "derived_assignments_root_sha256",
                    "semantic_verifier_build_sha256",
                    "measured_verifier_module_or_binary_sha256",
                    "execution_environment_attestation_sha256",
                    "trust_policy_sha256",
                    "timestamp_policy_sha256",
                    "check_vector",
                    "independence_adjudicated_under_policy",
                    "independence_ground_truth_proven",
                    "started_at_utc",
                    "completed_at_utc",
                    "issued_at_utc",
                    "verification_nonce",
                }
            ),
            f"verification receipt {index}",
        )
        if wrapper["receipt_sha256"] != canonical_sha256(receipt):
            raise ReleaseV625Error("verification envelope does not bind its receipt")
        if receipt["schema"] != VERIFICATION_RECEIPT_SCHEMA:
            raise ReleaseV625Error("verification receipt schema is invalid")
        if (
            receipt["authority_identity_subject_id"]
            != authority["identity_subject_id"]
            or receipt["authority_control_group_id"]
            != authority["control_group_id"]
        ):
            raise ReleaseV625Error("verification receipt authority identity is misbound")
        session_id = _nonce(receipt["verification_session_id"], "verification_session_id")
        authority_challenge = _nonce(
            receipt["authority_challenge_nonce"], "authority_challenge_nonce"
        )
        if session_id in session_ids or authority_challenge in authority_challenges:
            raise ReleaseV625Error("external verification session or authority challenge is replayed")
        retrieved_root = _sha(
            receipt["retrieved_evidence_byte_root_sha256"],
            "retrieved evidence byte root",
        )
        if retrieved_root != expected["evidence_bytes_root_sha256"]:
            raise ReleaseV625Error("external verifier retrieved different evidence bytes")
        transcript_root = _sha(
            receipt["execution_transcript_root_sha256"],
            "execution transcript root",
        )
        transcript_entries = [
            record
            for record in manifest["records"]
            if record["evidence_purpose"] == "VERIFIER_EXECUTION_TRANSCRIPT"
            and record["producer_key_id"] == key_id
            and record["sha256"] == transcript_root
        ]
        if len(transcript_entries) != 1 or transcript_root in transcript_roots:
            raise ReleaseV625Error("external verification transcript is missing or reused")
        transcript_entry = transcript_entries[0]
        if transcript_entry["unit_nonce"] != receipt["verification_challenge_nonce"]:
            raise ReleaseV625Error(
                "external verification transcript manifest entry is not challenge-bound"
            )
        transcript_bytes = semantic_evidence.get(transcript_entry["evidence_id"])
        if transcript_bytes is None:
            raise ReleaseV625Error("external verification transcript bytes are unavailable")
        for field, expected_value in expected.items():
            if (
                (type(expected_value) is int and type(receipt[field]) is not int)
                or receipt[field] != expected_value
            ):
                raise ReleaseV625Error(f"verification receipt does not bind {field}")
        build = _sha(receipt["semantic_verifier_build_sha256"], "semantic verifier build")
        if build not in release["accepted_builds"]:
            raise ReleaseV625Error("verification receipt uses an unaccepted semantic verifier build")
        measured_build = _sha(
            receipt["measured_verifier_module_or_binary_sha256"],
            "measured verifier module or binary",
        )
        if measured_build != build:
            raise ReleaseV625Error(
                "external verifier measurement does not match its accepted build"
            )
        environment_attestation = _sha(
            receipt["execution_environment_attestation_sha256"],
            "execution environment attestation",
        )
        if environment_attestation in environment_attestations:
            raise ReleaseV625Error(
                "external verification sessions reused one execution environment attestation"
            )
        if receipt["trust_policy_sha256"] != release["trust_policy_sha256"] or receipt["timestamp_policy_sha256"] != release["timestamp_policy_sha256"]:
            raise ReleaseV625Error("verification receipt uses an unpinned trust or timestamp policy")
        checks = _exact(receipt["check_vector"], _CHECK_FIELDS, "verification check vector")
        if any(value is not True for value in checks.values()):
            raise ReleaseV625Error("verification check vector is not conjunctively true")
        if receipt["independence_adjudicated_under_policy"] is not True or receipt["independence_ground_truth_proven"] is not False:
            raise ReleaseV625Error("verification receipt overstates or omits the independence claim")
        nonce = _nonce(receipt["verification_nonce"], "verification nonce")
        if nonce in nonces:
            raise ReleaseV625Error("verification nonce is replayed")
        started = _utc(receipt["started_at_utc"], "verification started_at_utc")
        completed = _utc(receipt["completed_at_utc"], "verification completed_at_utc")
        issued = _utc(receipt["issued_at_utc"], "verification issued_at_utc")
        if not checkpoint_time <= started <= completed <= issued:
            raise ReleaseV625Error("external verification session chronology is invalid")
        _verifier_execution_transcript(
            transcript_bytes,
            manifest_record=transcript_entry,
            authority=authority,
            receipt={"authority_key_id": key_id, **receipt},
        )
        age = (issued - checkpoint_time).total_seconds()
        if not 0 <= age <= release["transparency"]["maximum_checkpoint_age_seconds"]:
            raise ReleaseV625Error("revocation checkpoint is stale or later than verification")
        _verify_signature(
            public_key=authority["public_key"],
            signature_value=wrapper["signature_ed25519_base64"],
            domain=DOMAIN_RELEASE_VERIFICATION,
            payload=receipt,
        )
        signers.add(key_id)
        controls.add(authority["control_group_id"])
        nonces.add(nonce)
        session_ids.add(session_id)
        authority_challenges.add(authority_challenge)
        transcript_roots.add(transcript_root)
        environment_attestations.add(environment_attestation)
        check_vector_roots.add(canonical_sha256(checks))
        builds.add(build)
        issued_times.append(issued)
        receipt_hashes.append(canonical_sha256(receipt))
        session_records.append(
            {
                "authority_key_id": key_id,
                "verification_session_id": session_id,
                "authority_challenge_nonce": authority_challenge,
                "verification_nonce": nonce,
                "execution_transcript_root_sha256": transcript_root,
                "execution_environment_attestation_sha256": environment_attestation,
            }
        )
    if len(signers) < 2 or len(controls) < 2:
        raise ReleaseV625Error("external verification requires two of three distinct control groups")
    if len(builds) != 1:
        raise ReleaseV625Error("external verification authorities used different verifier builds")
    if len(check_vector_roots) != 1:
        raise ReleaseV625Error("external verification sessions produced different check vectors")
    return sorted(receipt_hashes), max(issued_times), sorted(
        session_records, key=lambda item: item["authority_key_id"]
    )


def _structural_bundle_roots(bundle: Mapping[str, Any]) -> dict[str, Any]:
    if type(bundle) is not dict:
        raise ReleaseV625Error("campaign trust bundle must be a JSON object")
    required = {
        "registry",
        "revocation_log",
        "units",
        "population_graph",
        "population_decision",
        "population_decision_approvals",
    }
    if not required <= set(bundle):
        raise ReleaseV625Error("campaign trust bundle is missing required rooted sections")
    if type(bundle["units"]) is not list or len(bundle["units"]) != len(SLOTS):
        raise ReleaseV625Error("campaign trust bundle must contain exactly 16 units")
    if [unit.get("slot_id") for unit in bundle["units"]] != list(SLOTS):
        raise ReleaseV625Error("campaign unit records are not in canonical slot order")
    registry_epoch = bundle["registry"].get("registry_epoch")
    if type(registry_epoch) is not int or isinstance(registry_epoch, bool) or registry_epoch < 0:
        raise ReleaseV625Error("campaign registry_epoch is invalid")
    return {
        "campaign_bundle_root_sha256": canonical_sha256(bundle),
        "registry_epoch": registry_epoch,
        "population_graph_sha256": canonical_sha256(bundle["population_graph"]),
        "population_decision_sha256": canonical_sha256(bundle["population_decision"]),
    }


def _canonical_replay_store_path(value: str | Path) -> Path:
    path = Path(value)
    if not str(path) or str(path) == ":memory:" or path.name in {"", ".", ".."}:
        raise ReleaseV625Error("challenge replay database path is invalid")
    path = path.absolute()
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise ReleaseV625Error(
            f"challenge replay database parent cannot be canonicalized: {exc}"
        ) from exc
    path = parent / path.name
    return path


def _replay_store_path_sha256(value: str | Path) -> str:
    return hashlib.sha256(
        str(_canonical_replay_store_path(value)).encode("utf-8")
    ).hexdigest()


def _secure_replay_store_path(value: str | Path) -> tuple[Path, os.stat_result]:
    path = _canonical_replay_store_path(value)
    parent = path.parent
    current = Path(path.anchor)
    for component in parent.parts[1:]:
        current = current / component
        try:
            component_stat = os.lstat(current)
        except OSError as exc:
            raise ReleaseV625Error(
                f"challenge replay database path component is unavailable: {exc}"
            ) from exc
        if stat.S_ISLNK(component_stat.st_mode):
            raise ReleaseV625Error(
                "challenge replay database path cannot traverse symlinks"
            )
    try:
        parent_stat = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise ReleaseV625Error(f"challenge replay database parent is unavailable: {exc}") from exc
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise ReleaseV625Error("challenge replay database parent must be a real directory")
    if parent_stat.st_uid != os.geteuid() or parent_stat.st_mode & 0o022:
        raise ReleaseV625Error(
            "challenge replay database parent must be owned by this user and not group/world writable"
        )
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReleaseV625Error(f"unable to open challenge replay database safely: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReleaseV625Error(
                "challenge replay database must be one regular non-hardlinked file"
            )
        if before.st_uid != os.geteuid() or before.st_mode & 0o077:
            raise ReleaseV625Error(
                "challenge replay database must be owner-only and owned by this user"
            )
    finally:
        os.close(descriptor)
    return path, before


def _validate_replay_store_schema(connection: sqlite3.Connection) -> None:
    expected_columns = {
        "replay_store_meta": ["schema_version"],
        "challenge_consumptions": [
            "challenge_nonce",
            "protocol_version",
            "replay_namespace",
            "release_root_sha256",
            "release_authorization_sha256",
            "release_packet_sha256",
            "checkpoint_sha256",
            "checkpoint_sequence",
            "transparency_tree_size",
            "consumed_at_utc",
        ],
        "verifier_session_consumptions": [
            "verification_session_id",
            "challenge_nonce",
            "authority_key_id",
            "authority_challenge_nonce",
            "verification_nonce",
            "execution_transcript_root_sha256",
            "execution_environment_attestation_sha256",
        ],
    }
    for table, names in expected_columns.items():
        rows = connection.execute(f"PRAGMA table_info('{table}')").fetchall()
        if [row[1] for row in rows] != names or not rows or rows[0][5] != 1:
            raise ReleaseV625Error(
                f"challenge replay database table {table} has an unexpected schema"
            )
    unique_sets: set[tuple[str, ...]] = set()
    for row in connection.execute(
        "PRAGMA index_list('verifier_session_consumptions')"
    ).fetchall():
        if row[2] != 1:
            continue
        columns = tuple(
            item[2]
            for item in connection.execute(
                f"PRAGMA index_info('{row[1]}')"
            ).fetchall()
        )
        unique_sets.add(columns)
    required_unique = {
        ("verification_session_id",),
        ("authority_challenge_nonce",),
        ("verification_nonce",),
        ("execution_transcript_root_sha256",),
        ("execution_environment_attestation_sha256",),
    }
    if not required_unique <= unique_sets:
        raise ReleaseV625Error(
            "challenge replay database lacks required durable uniqueness constraints"
        )
    integrity = connection.execute("PRAGMA integrity_check").fetchone()
    if integrity != ("ok",):
        raise ReleaseV625Error("challenge replay database integrity check failed")


def _consume_verification_challenge(
    *,
    replay_db_path: str | Path,
    challenge_nonce: str,
    release_root_sha256: str,
    release_authorization_sha256: str,
    release_packet_sha256: str,
    checkpoint_sha256: str,
    checkpoint_sequence: int,
    transparency_tree_size: int,
    replay_namespace: str,
    consumed_at: datetime,
    session_records: Sequence[Mapping[str, str]],
) -> None:
    path, before = _secure_replay_store_path(replay_db_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(str(path), timeout=30.0, isolation_level=None)
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_store_meta (
                schema_version INTEGER PRIMARY KEY CHECK (schema_version = 1)
            ) WITHOUT ROWID
            """
        )
        meta = connection.execute(
            "SELECT schema_version FROM replay_store_meta"
        ).fetchall()
        if not meta:
            connection.execute(
                "INSERT INTO replay_store_meta(schema_version) VALUES (?)",
                (_CHALLENGE_DB_SCHEMA_VERSION,),
            )
        elif meta != [(_CHALLENGE_DB_SCHEMA_VERSION,)]:
            raise ReleaseV625Error("challenge replay database schema version is invalid")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS challenge_consumptions (
                challenge_nonce TEXT PRIMARY KEY,
                protocol_version TEXT NOT NULL,
                replay_namespace TEXT NOT NULL,
                release_root_sha256 TEXT NOT NULL,
                release_authorization_sha256 TEXT NOT NULL,
                release_packet_sha256 TEXT NOT NULL,
                checkpoint_sha256 TEXT NOT NULL,
                checkpoint_sequence INTEGER NOT NULL,
                transparency_tree_size INTEGER NOT NULL,
                consumed_at_utc TEXT NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS verifier_session_consumptions (
                verification_session_id TEXT PRIMARY KEY,
                challenge_nonce TEXT NOT NULL,
                authority_key_id TEXT NOT NULL,
                authority_challenge_nonce TEXT NOT NULL UNIQUE,
                verification_nonce TEXT NOT NULL UNIQUE,
                execution_transcript_root_sha256 TEXT NOT NULL UNIQUE,
                execution_environment_attestation_sha256 TEXT NOT NULL UNIQUE,
                FOREIGN KEY(challenge_nonce) REFERENCES challenge_consumptions(challenge_nonce)
            ) WITHOUT ROWID
            """
        )
        _validate_replay_store_schema(connection)
        connection.execute(
            """
            INSERT INTO challenge_consumptions(
                challenge_nonce, protocol_version, replay_namespace,
                release_root_sha256,
                release_authorization_sha256, release_packet_sha256,
                checkpoint_sha256, checkpoint_sequence,
                transparency_tree_size, consumed_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_nonce,
                RELEASE_PACKET_SCHEMA,
                replay_namespace,
                release_root_sha256,
                release_authorization_sha256,
                release_packet_sha256,
                checkpoint_sha256,
                checkpoint_sequence,
                transparency_tree_size,
                consumed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            ),
        )
        for record in session_records:
            connection.execute(
                """
                INSERT INTO verifier_session_consumptions(
                    verification_session_id, challenge_nonce, authority_key_id,
                    authority_challenge_nonce, verification_nonce,
                    execution_transcript_root_sha256,
                    execution_environment_attestation_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["verification_session_id"],
                    challenge_nonce,
                    record["authority_key_id"],
                    record["authority_challenge_nonce"],
                    record["verification_nonce"],
                    record["execution_transcript_root_sha256"],
                    record["execution_environment_attestation_sha256"],
                ),
            )
        connection.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise ReleaseV625Error(
            "verification challenge or external verifier session was already consumed"
        ) from exc
    except (sqlite3.Error, ReleaseV625Error) as exc:
        if connection is not None:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        if isinstance(exc, ReleaseV625Error):
            raise
        raise ReleaseV625Error(f"challenge replay database failure: {exc}") from exc
    finally:
        if connection is not None:
            connection.close()
    try:
        after = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ReleaseV625Error(f"challenge replay database disappeared: {exc}") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_uid,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_uid,
    ) or not stat.S_ISREG(after.st_mode):
        raise ReleaseV625Error("challenge replay database identity changed during use")


def _verify_release_packet_value(
    packet: Any,
    *,
    bundle: Mapping[str, Any],
    release: Mapping[str, Any],
    release_authorization: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    evidence_base_dir: Path,
    expected_verification_challenge_nonce: str,
    challenge_replay_db_path: str | Path,
) -> dict[str, Any]:
    if (
        _replay_store_path_sha256(challenge_replay_db_path)
        != bootstrap["challenge_replay_store_path_sha256"]
    ):
        raise ReleaseV625Error("challenge replay database is not code-pinned")
    if (
        release_authorization["authorization"]["release_root_sha256"]
        != release["sha256"]
        or release_authorization["sequence"]
        != bootstrap["minimum_authorization_sequence"] + 1
    ):
        raise ReleaseV625Error("release root lacks the current bootstrap authorization")
    raw = _exact(
        packet,
        frozenset(
            {
                "schema",
                "recruitment_release_root_sha256",
                "release_root_authorization_sha256",
                "authorization_sequence",
                "campaign_bundle_root_sha256",
                "registry_epoch",
                "revocation_sequence",
                "revocation_log_head_sha256",
                "verification_challenge_nonce",
                "revocation_head_approvals",
                "transparency_checkpoint",
                "evidence_manifest",
                "unit_record_hashes",
                "identity_bindings",
                "unit_development_principals",
                "pair_reviews",
                "source_graph",
                "exposure_graph",
                "intervention_graph",
                "derived_assignments",
                "population_graph_sha256",
                "population_decision_sha256",
                "external_verification_receipts",
            }
        ),
        "population release packet",
    )
    if raw["schema"] != RELEASE_PACKET_SCHEMA:
        raise ReleaseV625Error(f"release packet schema must be {RELEASE_PACKET_SCHEMA}")
    challenge_nonce = _nonce(
        raw["verification_challenge_nonce"], "verification_challenge_nonce"
    )
    if challenge_nonce != _nonce(
        expected_verification_challenge_nonce,
        "expected_verification_challenge_nonce",
    ):
        raise ReleaseV625Error("release packet does not bind the invocation challenge")
    if raw["recruitment_release_root_sha256"] != release["sha256"]:
        raise ReleaseV625Error("release packet does not bind the authorized release root")
    if (
        raw["release_root_authorization_sha256"]
        != release_authorization["authorization_root_sha256"]
        or type(raw["authorization_sequence"]) is not int
        or isinstance(raw["authorization_sequence"], bool)
        or raw["authorization_sequence"] != release_authorization["sequence"]
    ):
        raise ReleaseV625Error("release packet does not bind its bootstrap authorization")
    bundle_roots = _structural_bundle_roots(bundle)
    pinned_admins = {
        key_id: PinnedRegistryAdmin(
            entity_id=record["identity_subject_id"],
            public_key=record["public_key"],
            external_identity_receipt_sha256=record["external_identity_receipt_sha256"],
        )
        for key_id, record in release["authorities"]["registry_admins"].items()
    }
    structural = verify_population_trust_bundle(
        bundle, pinned_registry_admins=pinned_admins
    )
    if structural["state"] != "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER":
        raise ReleaseV625Error("campaign trust bundle failed the retired-route structural verifier")
    _verify_v623_admin_approvals(bundle, release)
    if raw["campaign_bundle_root_sha256"] != bundle_roots["campaign_bundle_root_sha256"]:
        raise ReleaseV625Error("release packet does not bind the exact campaign bundle")
    if (
        type(raw["registry_epoch"]) is not int
        or isinstance(raw["registry_epoch"], bool)
        or raw["registry_epoch"] != bundle_roots["registry_epoch"]
        or raw["registry_epoch"] < release["transparency"]["minimum_registry_epoch"]
    ):
        raise ReleaseV625Error("registry epoch is stale or inconsistent")
    sequence = raw["revocation_sequence"]
    if type(sequence) is not int or isinstance(sequence, bool) or sequence < release["transparency"]["minimum_revocation_sequence"]:
        raise ReleaseV625Error("revocation sequence is stale or invalid")
    revocation_head = _sha(raw["revocation_log_head_sha256"], "revocation log head")
    if revocation_head != canonical_sha256(bundle["revocation_log"]):
        raise ReleaseV625Error("revocation head does not bind the campaign revocation log")
    if raw["population_graph_sha256"] != bundle_roots["population_graph_sha256"] or raw["population_decision_sha256"] != bundle_roots["population_decision_sha256"]:
        raise ReleaseV625Error("release packet does not bind population graph/decision")
    manifest = _evidence_manifest(raw["evidence_manifest"], bundle=bundle)
    evidence_bytes_root, semantic_evidence = _secure_evidence_inventory(
        evidence_base_dir, manifest
    )
    identities = _identity_bindings(
        raw["identity_bindings"],
        bundle=bundle,
        release=release,
        bootstrap=bootstrap,
    )
    _validate_evidence_producers(
        manifest, identities, release, bundle, revocation_head
    )
    authority_records = [
        record
        for group in release["authorities"].values()
        for record in group.values()
    ] + [release["transparency"]] + list(bootstrap["authorities"].values())
    principals = _principal_bindings(
        raw["unit_development_principals"],
        manifest=manifest,
        bundle=bundle,
        forbidden_principal_ids={
            record["identity_subject_id"] for record in authority_records
        },
        forbidden_control_group_ids={
            record["control_group_id"] for record in authority_records
        },
    )
    pair_reviews = _pair_reviews(
        raw["pair_reviews"],
        bundle=bundle,
        identities=identities,
        manifest=manifest,
        semantic_evidence=semantic_evidence,
    )
    source_graph = _graph(
        raw["source_graph"],
        schema=SOURCE_GRAPH_SCHEMA,
        policy_sha256=release["lineage_policy_sha256"],
        pair_reviews=pair_reviews,
        state_field="source_state",
    )
    exposure_graph = _graph(
        raw["exposure_graph"],
        schema=EXPOSURE_GRAPH_SCHEMA,
        policy_sha256=release["lineage_policy_sha256"],
        pair_reviews=pair_reviews,
        state_field="exposure_state",
    )
    intervention_graph, intervention_components = _intervention_graph(
        raw["intervention_graph"],
        policy_sha256=release["intervention_policy_sha256"],
        pair_reviews=pair_reviews,
    )
    assignments = _derived_assignments(
        raw["derived_assignments"],
        release=release,
        source_graph=source_graph,
        exposure_graph=exposure_graph,
        intervention_graph=intervention_graph,
        intervention_components=intervention_components,
    )
    _intervention_diversity(assignments)
    _role_caps(bundle, identities)
    _adjudicator_quorum(bundle, identities)
    unit_hashes = _unit_record_hashes(raw["unit_record_hashes"], bundle=bundle)
    checkpoint_receipt, checkpoint_time = _transparency_checkpoint(
        raw["transparency_checkpoint"],
        release=release,
        release_authorization=release_authorization,
        bootstrap=bootstrap,
        registry=bundle["registry"],
        registry_epoch=raw["registry_epoch"],
        revocation_sequence=sequence,
        revocation_head=revocation_head,
        verification_challenge_nonce=challenge_nonce,
    )
    if checkpoint_time < release["issued_at"]:
        raise ReleaseV625Error("transparency checkpoint predates the release root")
    _campaign_signature_chronology(
        bundle,
        release_issued_at=release["issued_at"],
        trust_opened_at=release_authorization["issued_at"],
        checkpoint_time=checkpoint_time,
        pair_reviews=pair_reviews,
    )
    invocation_time = datetime.now(timezone.utc)
    checkpoint_age = (invocation_time - checkpoint_time).total_seconds()
    if not -300 <= checkpoint_age <= release["transparency"]["maximum_checkpoint_age_seconds"]:
        raise ReleaseV625Error("transparency checkpoint is not fresh at verification invocation")
    revocation_receipt_hashes = _revocation_head_approvals(
        raw["revocation_head_approvals"],
        release=release,
        registry_epoch=raw["registry_epoch"],
        revocation_sequence=sequence,
        revocation_head=revocation_head,
        checkpoint_time=checkpoint_time,
    )
    expected_receipt_bindings = {
        "release_root_authorization_sha256": release_authorization[
            "authorization_root_sha256"
        ],
        "authorization_sequence": release_authorization["sequence"],
        "recruitment_release_root_sha256": release["sha256"],
        "campaign_bundle_root_sha256": bundle_roots["campaign_bundle_root_sha256"],
        "registry_epoch": raw["registry_epoch"],
        "revocation_sequence": sequence,
        "revocation_log_head_sha256": revocation_head,
        "verification_challenge_nonce": challenge_nonce,
        "revocation_head_receipts_root_sha256": canonical_sha256(
            revocation_receipt_hashes
        ),
        "transparency_checkpoint_sha256": canonical_sha256(checkpoint_receipt),
        "transparency_tree_root_sha256": checkpoint_receipt["tree_root_sha256"],
        "transparency_tree_size": checkpoint_receipt["tree_size"],
        "transparency_checkpoint_sequence": checkpoint_receipt[
            "checkpoint_sequence"
        ],
        "release_packet_without_receipts_sha256": canonical_sha256(
            {
                key: value
                for key, value in raw.items()
                if key != "external_verification_receipts"
            }
        ),
        "evidence_manifest_root_sha256": manifest["root"],
        "evidence_bytes_root_sha256": evidence_bytes_root,
        "unit_record_hashes_root_sha256": canonical_sha256(unit_hashes),
        "population_graph_sha256": bundle_roots["population_graph_sha256"],
        "population_decision_sha256": bundle_roots["population_decision_sha256"],
        "source_graph_root_sha256": canonical_sha256(source_graph),
        "exposure_graph_root_sha256": canonical_sha256(exposure_graph),
        "intervention_graph_root_sha256": canonical_sha256(intervention_graph),
        "pair_reviews_root_sha256": canonical_sha256(raw["pair_reviews"]),
        "identity_bindings_root_sha256": canonical_sha256(raw["identity_bindings"]),
        "principal_bindings_root_sha256": canonical_sha256(raw["unit_development_principals"]),
        "derived_assignments_root_sha256": canonical_sha256(raw["derived_assignments"]),
    }
    receipt_hashes, evaluated_at, session_records = _verification_receipts(
        raw["external_verification_receipts"],
        release=release,
        expected=expected_receipt_bindings,
        checkpoint_time=checkpoint_time,
        manifest=manifest,
        semantic_evidence=semantic_evidence,
    )
    if evaluated_at > invocation_time.replace(microsecond=0):
        if (evaluated_at - invocation_time).total_seconds() > 300:
            raise ReleaseV625Error("external verification receipt is implausibly future-dated")
    _consume_verification_challenge(
        replay_db_path=challenge_replay_db_path,
        challenge_nonce=challenge_nonce,
        release_root_sha256=release["sha256"],
        release_authorization_sha256=release_authorization[
            "authorization_root_sha256"
        ],
        release_packet_sha256=canonical_sha256(raw),
        checkpoint_sha256=canonical_sha256(checkpoint_receipt),
        checkpoint_sequence=checkpoint_receipt["checkpoint_sequence"],
        transparency_tree_size=checkpoint_receipt["tree_size"],
        replay_namespace=bootstrap["challenge_replay_namespace"],
        consumed_at=evaluated_at,
        session_records=session_records,
    )
    return {
        "schema": VERDICT_SCHEMA,
        "state": "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING",
        "recruitment_release_root_sha256": release["sha256"],
        "release_root_authorization_sha256": release_authorization[
            "authorization_root_sha256"
        ],
        "campaign_bundle_root_sha256": bundle_roots["campaign_bundle_root_sha256"],
        "verification_challenge_sha256": hashlib.sha256(
            bytes.fromhex(challenge_nonce)
        ).hexdigest(),
        "evidence_manifest_root_sha256": manifest["root"],
        "evidence_bytes_root_sha256": evidence_bytes_root,
        "transparency_checkpoint_sha256": canonical_sha256(checkpoint_receipt),
        "revocation_head_receipts_root_sha256": canonical_sha256(
            revocation_receipt_hashes
        ),
        "external_verification_receipt_sha256s": receipt_hashes,
        "evaluated_at_utc": evaluated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "external_authentication_verified": True,
        "semantic_artifact_verification_complete": True,
        "independence_adjudicated_under_policy": True,
        "population_feasible": True,
        "independence_ground_truth_proven": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }


def verify_population_release_files(
    *,
    release_root_path: str | Path,
    release_root_authorization_path: str | Path,
    campaign_bundle_path: str | Path,
    release_packet_path: str | Path,
    challenge_replay_db_path: str | Path,
    expected_verification_challenge_nonce: str,
) -> dict[str, Any]:
    """Verify exact canonical files and all evidence referenced by the packet."""

    bootstrap = _bootstrap_config()
    release_raw = read_canonical_trust_bundle(release_root_path)
    release = validate_release_root(release_raw)
    release_authorization_raw = read_canonical_trust_bundle(
        release_root_authorization_path
    )
    release_authorization = _release_root_authorization(
        release_authorization_raw,
        release=release,
        bootstrap=bootstrap,
    )
    bundle = read_canonical_trust_bundle(campaign_bundle_path)
    packet_path = Path(release_packet_path)
    packet = read_canonical_trust_bundle(packet_path)
    return _verify_release_packet_value(
        packet,
        bundle=bundle,
        release=release,
        release_authorization=release_authorization,
        bootstrap=bootstrap,
        evidence_base_dir=packet_path.parent,
        expected_verification_challenge_nonce=expected_verification_challenge_nonce,
        challenge_replay_db_path=challenge_replay_db_path,
    )


def assess_population_release_files(
    *,
    release_root_path: str | Path,
    release_root_authorization_path: str | Path,
    campaign_bundle_path: str | Path,
    release_packet_path: str | Path,
    challenge_replay_db_path: str | Path,
    expected_verification_challenge_nonce: str,
) -> dict[str, Any]:
    """Convert every release/evidence failure into a stable NO_UPLOAD verdict."""

    try:
        return verify_population_release_files(
            release_root_path=release_root_path,
            release_root_authorization_path=release_root_authorization_path,
            campaign_bundle_path=campaign_bundle_path,
            release_packet_path=release_packet_path,
            challenge_replay_db_path=challenge_replay_db_path,
            expected_verification_challenge_nonce=expected_verification_challenge_nonce,
        )
    except (ReleaseV625Error, ValueError, OSError, KeyError, IndexError) as exc:
        return {
            "schema": VERDICT_SCHEMA,
            "state": "POPULATION_INFEASIBLE",
            "failure": str(exc),
            "external_authentication_verified": False,
            "semantic_artifact_verification_complete": False,
            "independence_adjudicated_under_policy": False,
            "population_feasible": False,
            "independence_ground_truth_proven": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "unit_upload_permits": [],
            "sealed_holdout_accessed": False,
        }


# v6.2.5 is retained as a structural test oracle only. Its project-local replay
# database and self-attested time boundary were rejected by the binding Sol
# review, so no operational caller may reach its former positive route.
_verify_population_release_files_legacy = verify_population_release_files
_assess_population_release_files_legacy = assess_population_release_files


def verify_population_release_files(
    *,
    release_root_path: str | Path,
    release_root_authorization_path: str | Path,
    campaign_bundle_path: str | Path,
    release_packet_path: str | Path,
    challenge_replay_db_path: str | Path,
    expected_verification_challenge_nonce: str,
) -> dict[str, Any]:
    del (
        release_root_path,
        release_root_authorization_path,
        campaign_bundle_path,
        release_packet_path,
        challenge_replay_db_path,
        expected_verification_challenge_nonce,
    )
    raise ReleaseV625Error(
        "v6.2.5 is retired: external monotonic witness, trusted-time quorum, "
        "closed evidence graph, and complete runtime-TCB validation are required"
    )


def assess_population_release_files(
    *,
    release_root_path: str | Path,
    release_root_authorization_path: str | Path,
    campaign_bundle_path: str | Path,
    release_packet_path: str | Path,
    challenge_replay_db_path: str | Path,
    expected_verification_challenge_nonce: str,
) -> dict[str, Any]:
    del (
        release_root_path,
        release_root_authorization_path,
        campaign_bundle_path,
        release_packet_path,
        challenge_replay_db_path,
        expected_verification_challenge_nonce,
    )
    return {
        "schema": VERDICT_SCHEMA,
        "state": "POPULATION_INFEASIBLE",
        "failure": "v6.2.5 positive authority is permanently retired; use v6.2.6",
        "external_authentication_verified": False,
        "semantic_artifact_verification_complete": False,
        "independence_adjudicated_under_policy": False,
        "population_feasible": False,
        "independence_ground_truth_proven": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }


__all__ = [
    "BOOTSTRAP_TRUST_CONFIG",
    "DERIVED_ASSIGNMENT_SCHEMA",
    "DOMAIN_PAIR_INTERVENTION_RECEIPT",
    "DOMAIN_PAIR_LINEAGE_RECEIPT",
    "DOMAIN_RELEASE_ROOT_AUTHORIZATION",
    "DOMAIN_RELEASE_VERIFICATION",
    "DOMAIN_TRANSPARENCY_CHECKPOINT",
    "EVIDENCE_MANIFEST_SCHEMA",
    "EXPOSURE_GRAPH_SCHEMA",
    "IDENTITY_BINDING_SCHEMA",
    "INTERVENTION_GRAPH_SCHEMA",
    "PAIR_INTERVENTION_RECEIPT_SCHEMA",
    "PAIR_LINEAGE_RECEIPT_SCHEMA",
    "PAIR_REVIEW_SCHEMA",
    "PRINCIPAL_BINDING_SCHEMA",
    "RELEASE_PACKET_SCHEMA",
    "RELEASE_ROOT_AUTHORIZATION_ENVELOPE_SCHEMA",
    "RELEASE_ROOT_AUTHORIZATION_SCHEMA",
    "RELEASE_ROOT_SCHEMA",
    "ReleaseV625Error",
    "SOURCE_GRAPH_SCHEMA",
    "TRANSPARENCY_CHECKPOINT_SCHEMA",
    "TRANSPARENCY_ENVELOPE_SCHEMA",
    "VERDICT_SCHEMA",
    "VERIFICATION_ENVELOPE_SCHEMA",
    "VERIFICATION_RECEIPT_SCHEMA",
    "VERIFIER_EXECUTION_TRANSCRIPT_SCHEMA",
    "assess_population_release_files",
    "validate_release_root",
    "transparency_leaf_hash",
    "verify_transparency_consistency",
    "verify_transparency_inclusion",
    "verify_population_release_files",
]
