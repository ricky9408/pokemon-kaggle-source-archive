"""Fail-closed G00/G01 governance evidence verification.

This module deliberately verifies byte evidence supplied by its caller.  It
does not read a checkout, discover an archive, create keys, or grant any form
of release or submission authority.  A successful receipt is only evidence
that the supplied, signed governance records are internally consistent.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from . import exact_gate_v2


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"

G00_EVIDENCE_SCHEMA = "evaluation_v5_1_g00_trust_roots_evidence_v1"
G00_REGISTRY_SCHEMA = "evaluation_v5_1_campaign_registry_v2"
G00_ROOT_SCHEMA = "evaluation_v5_1_campaign_root_v2"
G00_POP_PAYLOAD_SCHEMA = "evaluation_v5_1_key_pop_payload_v2"
G00_POP_ENVELOPE_SCHEMA = "evaluation_v5_1_g00_proof_of_possession_v2"
G00_FINAL_GATE_SCHEMA = "evaluation_v5_1_g00_final_gate_v2"
G00_COUNTERSIGNATURE_SCHEMA = "evaluation_v5_1_g00_final_gate_countersignature_v2"

G01_EVIDENCE_SCHEMA = "evaluation_v5_1_g01_code_freeze_evidence_v1"
G01_CONSTITUTION_SCHEMA = "evaluation_v5_1_constitution_v1"
G01_SOURCE_ARCHIVE_SCHEMA = "evaluation_v5_1_source_archive_v1"
G01_MANIFEST_SCHEMA = "evaluation_v5_1_source_manifest_v1"
G01_DEVELOPMENT_ATTESTATION_SCHEMA = "evaluation_v5_1_development_input_attestation_v2"
G01_FINAL_GATE_SCHEMA = "evaluation_v5_1_g01_final_gate_v2"
G01_COUNTERSIGNATURE_SCHEMA = "evaluation_v5_1_g01_final_gate_countersignature_v2"

G00_DECISION = "G00_DIAGNOSTIC_VERIFIED_RESEARCH_ONLY"
G01_DECISION = "G01_DIAGNOSTIC_VERIFIED_RESEARCH_ONLY"

REQUIRED_ROLES = (
    "evaluation_authority",
    "registrar",
    "collector_a",
    "collector_b",
    "evidence_custodian",
    "trace_attestor",
    "validation_authority",
    "release_authority",
    "development_identity",
)

# Governance v2 is a hard protocol cut.  These schemas never share an
# allowlist with the diagnostic G00/G01 receipts above.
GOVERNANCE_V2_REQUIRED_ROLES = ("registry_custodian", *REQUIRED_ROLES)
GOVERNANCE_V2_GENESIS_PAYLOAD_SCHEMA = "ptcg.governance.genesis/v2"
GOVERNANCE_V2_GENESIS_ENVELOPE_SCHEMA = "ptcg.governance.genesis-envelope/v2"
GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA = "ptcg.governance.registry-epoch/v2"
GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA = "ptcg.governance.registry-epoch-envelope/v2"
GOVERNANCE_V2_ROLE_POP_SCHEMA = "ptcg.governance.role-pop/v2"
GOVERNANCE_V2_ROLE_POP_ENVELOPE_SCHEMA = "ptcg.governance.role-pop-envelope/v2"
GOVERNANCE_V2_EVALUATION_ENTRY_SCHEMA = "ptcg.governance.evaluation-entry/v2"
GOVERNANCE_V2_EVALUATION_ENTRY_ENVELOPE_SCHEMA = "ptcg.governance.evaluation-entry-envelope/v2"
GOVERNANCE_V2_FREEZE_SCHEMA = "ptcg.governance.freeze-record/v2"
GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA = "ptcg.governance.freeze-record-envelope/v2"
GOVERNANCE_V2_FREEZE_VALIDATOR_SCHEMA = "ptcg.governance.freeze-validator/v2"
GOVERNANCE_V2_FREEZE_VALIDATOR_ENVELOPE_SCHEMA = "ptcg.governance.freeze-validator-envelope/v2"
GOVERNANCE_V2_FAILURE_REGISTRY_SCHEMA = "ptcg.governance.failure-code-registry/v2"
GOVERNANCE_V2_DERIVED_SCHEMA = "ptcg.governance.derived-receipt/v2"
GOVERNANCE_V2_VERIFIED_SCHEMA = "ptcg.governance.verified-receipt/v2"
GOVERNANCE_V2_WIRE_BINDING_SCHEMA = "ptcg.governance.exact-gate-binding/v2"

GOVERNANCE_V2_GENESIS_MEDIA_TYPE = "application/vnd.ptcg.governance-genesis+json"
GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE = "application/vnd.ptcg.governance-registry-epoch+json"
GOVERNANCE_V2_ROLE_POP_MEDIA_TYPE = "application/vnd.ptcg.governance-role-pop+json"
GOVERNANCE_V2_EVALUATION_ENTRY_MEDIA_TYPE = "application/vnd.ptcg.governance-evaluation-entry+json"
GOVERNANCE_V2_FREEZE_MEDIA_TYPE = "application/vnd.ptcg.governance-freeze-record+json"
GOVERNANCE_V2_FREEZE_VALIDATOR_MEDIA_TYPE = "application/vnd.ptcg.governance-freeze-validator+json"
GOVERNANCE_V2_PUBLIC_KEY_MEDIA_TYPE = "application/vnd.ptcg.ed25519-public-key"
GOVERNANCE_V2_CAMPAIGN_NONCE_MEDIA_TYPE = "application/vnd.ptcg.campaign-nonce"

GOVERNANCE_V2_GENESIS_DOMAIN = b"PTCG/GOVERNANCE/GENESIS/v2"
GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN = b"PTCG/GOVERNANCE/REGISTRY_EPOCH/v2"
GOVERNANCE_V2_ROLE_POP_DOMAIN = b"PTCG/GOVERNANCE/ROLE_POP/v2"
GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN = b"PTCG/GOVERNANCE/EVALUATION_ENTRY/v2"
GOVERNANCE_V2_FREEZE_DOMAIN = b"PTCG/GOVERNANCE/FREEZE/v2"
GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN = b"PTCG/GOVERNANCE/FREEZE_VALIDATOR/v2"
GOVERNANCE_V2_CAMPAIGN_ROOT_DOMAIN = b"PTCG/GOVERNANCE/CAMPAIGN_ROOT/v2\0"
_GOVERNANCE_V2_SIGNING_DOMAINS = frozenset(
    {
        GOVERNANCE_V2_GENESIS_DOMAIN,
        GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        GOVERNANCE_V2_ROLE_POP_DOMAIN,
        GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN,
        GOVERNANCE_V2_FREEZE_DOMAIN,
        GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN,
    }
)

GOVERNANCE_V2_GATE_IDS = (
    "G00_TRUST_ROOTS",
    "G01_CONSTITUTION_AND_CODE_FREEZE",
    "G02_ENGINE_EVENT_CAPABILITY",
    "G03_TRACE_PROVENANCE",
    "G04_CROSS_ENGINE_OBSERVATIONAL_CONTRACT",
    "G05_DEV_SOURCE_COMPLETENESS",
    "G06_DEV_BYTE_REBUILD",
    "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE",
    "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION",
    "G09_BLIND_CAMPAIGN_ACTIVATION",
    "G10_INTERFACE_CENSUS_CLOSE",
    "G11_ONE_SHOT_TRANSFER_VALIDATION",
    "G12_EVALUATOR_UNSEAL",
    "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
    "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT",
    "G15_RELEASE_CUSTODY",
)
GOVERNANCE_V2_GATE_DEPENDENCIES = {
    "G00_TRUST_ROOTS": (),
    "G01_CONSTITUTION_AND_CODE_FREEZE": ("G00_TRUST_ROOTS",),
    "G02_ENGINE_EVENT_CAPABILITY": ("G01_CONSTITUTION_AND_CODE_FREEZE",),
    "G03_TRACE_PROVENANCE": ("G02_ENGINE_EVENT_CAPABILITY",),
    "G04_CROSS_ENGINE_OBSERVATIONAL_CONTRACT": ("G03_TRACE_PROVENANCE",),
    "G05_DEV_SOURCE_COMPLETENESS": ("G04_CROSS_ENGINE_OBSERVATIONAL_CONTRACT",),
    "G06_DEV_BYTE_REBUILD": ("G05_DEV_SOURCE_COMPLETENESS",),
    "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE": ("G06_DEV_BYTE_REBUILD",),
    "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION": (
        "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE",
    ),
    "G09_BLIND_CAMPAIGN_ACTIVATION": (
        "G00_TRUST_ROOTS",
        "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION",
    ),
    "G10_INTERFACE_CENSUS_CLOSE": ("G09_BLIND_CAMPAIGN_ACTIVATION",),
    "G11_ONE_SHOT_TRANSFER_VALIDATION": ("G10_INTERFACE_CENSUS_CLOSE",),
    "G12_EVALUATOR_UNSEAL": ("G11_ONE_SHOT_TRANSFER_VALIDATION",),
    "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION": (
        "G05_DEV_SOURCE_COMPLETENESS",
        "G12_EVALUATOR_UNSEAL",
    ),
    "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT": (
        "G12_EVALUATOR_UNSEAL",
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
    ),
    "G15_RELEASE_CUSTODY": (
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
        "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT",
    ),
}

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_NS = re.compile(r"^(?:0|[1-9][0-9]{0,20})$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_FAILURE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")

_V2_KEY_FIELDS = frozenset(
    {
        "role",
        "key_id",
        "principal_id",
        "custodian_id",
        "algorithm",
        "public_key",
        "valid_from_ns",
        "valid_until_ns",
        "status",
        "invalidate_from_ns",
    }
)
_V2_ENVELOPE_FIELDS = frozenset(
    {"schema_version", "signer_key_id", "payload", "signature_ed25519_base64"}
)
_V2_GENESIS_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_id",
        "created_at_ns",
        "issued_at_ns",
        "offline_root_key_id",
        "campaign_nonce",
        "required_roles",
        "incompatible_role_matrix",
        "registry_custodian",
    }
)
_V2_REGISTRY_EPOCH_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "epoch",
        "predecessor_epoch_hash",
        "issued_at_ns",
        "registry_status",
        "keys",
    }
)
_V2_ROLE_POP_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "role",
        "key_id",
        "principal_id",
        "custodian_id",
        "campaign_nonce",
        "issued_at_ns",
    }
)
_V2_GATE_FIELDS = frozenset(
    {
        "gate_id",
        "direct_dependencies",
        "frozen_spec_hash",
        "verifier_module_hash",
        "verifier_runtime_hash",
        "input_schema_hash",
        "output_schema_hash",
        "failure_code_registry_hash",
        "evidence_manifest_schema",
    }
)
_V2_EVALUATION_ENTRY_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "evaluation_id",
        "evaluation_nonce",
        "attempt",
        "registrar_key_id",
        "registrar_principal_id",
        "registrar_custodian_id",
        "registered_at_ns",
        "issued_at_ns",
        "gate_dag",
        "evidence_manifest_schema",
    }
)
_V2_FREEZE_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "evaluation_entry_hash",
        "evaluation_id",
        "evaluation_nonce",
        "attempt",
        "registered_at_ns",
        "freeze_at_ns",
        "issued_at_ns",
        "gate_registry_root",
        "evidence_manifest_schema",
        "evaluation_authority_key_id",
    }
)
_V2_FREEZE_VALIDATOR_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_id",
        "campaign_root",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "evaluation_entry_hash",
        "evaluation_id",
        "evaluation_nonce",
        "attempt",
        "freeze_authority_envelope_sha256",
        "freeze_authority_envelope_decoded_length",
        "freeze_authority_payload_sha256",
        "validator_key_id",
        "issued_at_ns",
    }
)
_V2_FAILURE_REGISTRY_FIELDS = frozenset(
    {"schema_version", "protocol_id", "gate_id", "codes"}
)

_BLOB_FIELDS = frozenset({"base64", "decoded_length", "sha256", "media_type"})
_G00_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_id",
        "campaign_created_at_utc",
        "issued_at_ns",
        "predecessor",
        "registry",
        "registry_sha256",
        "campaign_root_sha256",
        "proofs",
    }
)
_REGISTRY_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_id",
        "registry_epoch",
        "registry_status",
        "campaign_nonce",
        "incompatible_role_matrix",
        "keys",
    }
)
_KEY_FIELDS = frozenset(
    {
        "role",
        "key_id",
        "principal_id",
        "custodian_id",
        "algorithm",
        "public_key",
        "public_key_fingerprint_sha256",
        "not_before_utc",
        "not_after_utc",
        "revocation",
    }
)
_REVOCATION_FIELDS = frozenset({"state", "revoked_at_utc"})
_PREDECESSOR_FIELDS = frozenset({"kind", "predecessor_campaign_root_sha256", "predecessor_created_at_utc"})
_POP_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_root_sha256",
        "registry_sha256",
        "role",
        "key_id",
        "principal_id",
        "custodian_id",
        "campaign_nonce",
        "issued_at_ns",
        "registry_epoch",
        "registry_status",
    }
)
_G00_FINAL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "campaign_id",
        "campaign_root_sha256",
        "registry_sha256",
        "campaign_created_at_utc",
        "predecessor",
        "role_key_fingerprints",
        "proof_count",
        "registry_epoch",
        "registry_status",
        "issued_at_ns",
        "authority",
        "submission_authorized",
        "holdout_access",
        "sealed_holdout_access",
        "candidate_authorized",
        "candidate_development_authorized",
        "decision",
        "fail_code",
        "reason",
        "result_sha256",
    }
)
_COUNTERSIGNATURE_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "authority_envelope_sha256",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "issued_at_ns",
        "validator_key_id",
    }
)

_G01_EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_id",
        "g00_campaign_root_sha256",
        "issued_at_ns",
        "constitution",
        "source_archive",
        "manifest",
        "development_attestation_envelope",
    }
)
_CONSTITUTION_FIELDS = frozenset(
    {"schema", "protocol_id", "campaign_id", "g00_campaign_root_sha256", "claim", "frozen_components", "no_submit_conditions"}
)
_FROZEN_COMPONENT_FIELDS = frozenset(
    {
        "schemas",
        "feature_registry",
        "model_registry",
        "dev_algorithm",
        "census_parser",
        "sampling_algorithm",
        "validator_image",
        "authority_matrix",
    }
)
_SOURCE_ARCHIVE_FIELDS = frozenset({"schema", "protocol_id", "campaign_id", "files"})
_SOURCE_FILE_FIELDS = frozenset({"path", "content"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_id",
        "g00_campaign_root_sha256",
        "freeze_time_utc",
        "files",
        "lockfiles",
        "build_scripts",
        "schemas",
        "toolchain",
        "container",
        "configs",
        "exclusions",
        "seed_spec",
    }
)
_MANIFEST_FILE_FIELDS = frozenset({"path", "decoded_length", "sha256", "media_type", "classification"})
_TOOLCHAIN_FIELDS = frozenset({"path", "sha256", "container_image_sha256"})
_CONTAINER_FIELDS = frozenset({"path", "sha256", "container_image_sha256"})
_SEED_SPEC_FIELDS = frozenset({"path", "sha256", "scheme", "domain_separator"})
_EXCLUSION_FIELDS = frozenset({"path", "reason"})
_DEVELOPMENT_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "campaign_id",
        "g00_campaign_root_sha256",
        "constitution_sha256",
        "source_archive_sha256",
        "manifest_sha256",
        "freeze_time_utc",
        "development_key_id",
        "development_principal_id",
        "development_custodian_id",
        "registry_epoch",
        "registry_hash",
        "registry_status",
        "issued_at_ns",
    }
)
_G01_FINAL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "campaign_id",
        "g00_campaign_root_sha256",
        "constitution_sha256",
        "source_archive_sha256",
        "manifest_sha256",
        "source_inventory_root",
        "source_file_count",
        "manifest_file_count",
        "classification_counts",
        "freeze_time_utc",
        "development_key_fingerprint_sha256",
        "development_attestation_envelope_sha256",
        "registry_epoch",
        "registry_status",
        "issued_at_ns",
        "authority",
        "submission_authorized",
        "holdout_access",
        "sealed_holdout_access",
        "candidate_authorized",
        "candidate_development_authorized",
        "decision",
        "fail_code",
        "reason",
        "result_sha256",
    }
)

_CLASSIFICATIONS = frozenset(
    {"source", "lockfile", "build_script", "schema", "toolchain", "container", "config", "seed_spec", "excluded"}
)
_PRIVATE_MATERIAL_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)


class GovernanceValidationError(ValueError):
    """Structured reason for a rejected G00 or G01 evidence bundle."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class _DuplicateJSONKey(ValueError):
    pass


def _fail(code: str, message: str) -> None:
    raise GovernanceValidationError(code, message)


def _exact(value: object, fields: frozenset[str], label: str, code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(code, f"{label} fields are not exact")
    return value


def _sha(value: object, label: str, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _identifier(value: object, label: str, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(code, f"{label} must be a canonical identifier")
    return value


def _text(value: object, label: str, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\x00" in value:
        _fail(code, f"{label} must be a nonempty trimmed text value")
    return value


def _utc(value: object, label: str, code: str) -> tuple[datetime, str]:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        _fail(code, f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GovernanceValidationError(code, f"{label} is not a real UTC instant") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        _fail(code, f"{label} is not canonical UTC")
    return parsed, value


def _ns(value: object, label: str, code: str) -> tuple[int, str]:
    if type(value) is not str or _NS.fullmatch(value) is None:
        _fail(code, f"{label} must be canonical nonnegative decimal nanoseconds")
    return int(value), value


def _datetime_ns(value: datetime) -> int:
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return ((delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds) * 1000


def _key_valid_at_ns(key: dict[str, Any], issued_at_ns: int) -> bool:
    if not (_datetime_ns(key["not_before"]) <= issued_at_ns < _datetime_ns(key["not_after"])):
        return False
    revocation = key["revocation"]
    if revocation["state"] == "active":
        return True
    revoked_at, _ = _utc(
        revocation["revoked_at_utc"], "key revocation time", "KEY_VALIDITY_INVALID"
    )
    return issued_at_ns < _datetime_ns(revoked_at)


def _path(value: object, label: str, code: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        _fail(code, f"{label} must be a normalized relative POSIX path")
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail(code, f"{label} must be ASCII")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        _fail(code, f"{label} must be a normalized relative POSIX path")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = item
    return result


def _reject_floats(value: object, *, path: str = "$", code: str) -> None:
    if type(value) is float:
        _fail(code, f"{path} contains a forbidden JSON float")
    if type(value) is dict:
        for key, child in value.items():
            _reject_floats(child, path=f"{path}.{key}", code=code)
    elif type(value) is list:
        for index, child in enumerate(value):
            _reject_floats(child, path=f"{path}[{index}]", code=code)


def _canonical_json_blob(value: object, label: str, code: str, *, media_types: frozenset[str]) -> tuple[bytes, Any, str]:
    raw, digest = _blob(value, label, code, media_types=media_types)
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(ValueError(constant)),
        )
        _reject_floats(parsed, path=label, code=code)
        recoded = canonical_json_bytes(parsed)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, CanonicalJSONError, _DuplicateJSONKey) as exc:
        raise GovernanceValidationError(code, f"{label} is not duplicate-free canonical JSON") from exc
    if recoded != raw:
        _fail(code, f"{label} bytes are not exact canonical JSON")
    return raw, parsed, digest


def _blob(value: object, label: str, code: str, *, media_types: frozenset[str] | None = None) -> tuple[bytes, str]:
    raw = _exact(value, _BLOB_FIELDS, label, code)
    encoded = raw["base64"]
    if type(encoded) is not str:
        _fail(code, f"{label}.base64 must be a string")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GovernanceValidationError(code, f"{label}.base64 is malformed") from exc
    if base64.b64encode(decoded).decode("ascii") != encoded:
        _fail(code, f"{label}.base64 is not canonical")
    if type(raw["decoded_length"]) is not int or isinstance(raw["decoded_length"], bool) or raw["decoded_length"] < 0:
        _fail(code, f"{label}.decoded_length must be a nonnegative integer")
    if len(decoded) != raw["decoded_length"]:
        _fail(code, f"{label}.decoded_length does not bind decoded bytes")
    digest = _sha(raw["sha256"], f"{label}.sha256", code)
    if hashlib.sha256(decoded).hexdigest() != digest:
        _fail(code, f"{label}.sha256 does not bind decoded bytes")
    media_type = raw["media_type"]
    if type(media_type) is not str or _MEDIA_TYPE.fullmatch(media_type) is None:
        _fail(code, f"{label}.media_type is invalid")
    if media_types is not None and media_type not in media_types:
        _fail(code, f"{label}.media_type is not permitted")
    return decoded, digest


def _public_key(value: object, label: str, code: str) -> bytes:
    key, _ = _blob(
        value,
        label,
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.ed25519-public-key"}),
    )
    if len(key) != 32:
        _fail(code, f"{label} must decode to exactly 32 Ed25519 public-key bytes")
    return key


def _pinned_key(value: object, label: str, code: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail(code, f"{label} must be raw 32-byte Ed25519 public-key bytes")
    return value


def _predecessor(value: object, campaign_created: datetime, code: str) -> dict[str, Any]:
    raw = _exact(value, _PREDECESSOR_FIELDS, "predecessor declaration", code)
    kind = raw["kind"]
    if kind == "genesis":
        if raw["predecessor_campaign_root_sha256"] is not None or raw["predecessor_created_at_utc"] is not None:
            _fail(code, "genesis declaration must have no predecessor")
    elif kind == "successor":
        _sha(raw["predecessor_campaign_root_sha256"], "predecessor campaign root", code)
        predecessor_time, predecessor_text = _utc(raw["predecessor_created_at_utc"], "predecessor creation time", code)
        if predecessor_time >= campaign_created:
            _fail(code, "predecessor must chronologically precede this campaign")
        return {
            "kind": kind,
            "predecessor_campaign_root_sha256": raw["predecessor_campaign_root_sha256"],
            "predecessor_created_at_utc": predecessor_text,
        }
    else:
        _fail(code, "predecessor kind must be genesis or successor")
    return {"kind": "genesis", "predecessor_campaign_root_sha256": None, "predecessor_created_at_utc": None}


def _campaign_root(
    *,
    campaign_id: str,
    created_at_utc: str,
    predecessor: dict[str, Any],
    registry_sha256: str,
    campaign_nonce_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "schema": G00_ROOT_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_id": campaign_id,
            "campaign_created_at_utc": created_at_utc,
            "predecessor": predecessor,
            "registry_sha256": registry_sha256,
            "campaign_nonce_sha256": campaign_nonce_sha256,
        }
    )


def _registry(value: object, *, campaign_id: str, created_at: datetime, bootstrap_key: bytes, validator_key: bytes, code: str) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], dict[str, Any]]:
    _, parsed, digest = _canonical_json_blob(
        value,
        "campaign registry",
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.campaign-registry+json"}),
    )
    raw = _exact(parsed, _REGISTRY_FIELDS, "campaign registry", code)
    if raw["schema"] != G00_REGISTRY_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail(code, "campaign registry schema or protocol is invalid")
    if _identifier(raw["campaign_id"], "campaign registry campaign_id", code) != campaign_id:
        _fail(code, "campaign registry campaign_id does not bind the evidence")
    if type(raw["registry_epoch"]) is not int or isinstance(raw["registry_epoch"], bool) or raw["registry_epoch"] != 0:
        _fail(code, "diagnostic G00 registry must be epoch zero")
    if raw["registry_status"] != "ACTIVE":
        _fail(code, "diagnostic G00 registry status must be ACTIVE")
    campaign_nonce, campaign_nonce_sha256 = _blob(
        raw["campaign_nonce"],
        "campaign registry campaign_nonce",
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.campaign-nonce"}),
    )
    if not 16 <= len(campaign_nonce) <= 128:
        _fail(code, "campaign registry campaign_nonce must contain 16 through 128 bytes")
    matrix = raw["incompatible_role_matrix"]
    if type(matrix) is not dict or set(matrix) != set(REQUIRED_ROLES):
        _fail(code, "incompatible-role matrix must cover every required role exactly")
    for role in REQUIRED_ROLES:
        if matrix[role] != [candidate for candidate in REQUIRED_ROLES if candidate != role]:
            _fail(code, "incompatible-role matrix must be complete, symmetric, and canonically ordered")
    entries = raw["keys"]
    if type(entries) is not list or not entries:
        _fail(code, "campaign registry must contain key entries")
    normalized: list[dict[str, Any]] = []
    seen_role_key: set[tuple[str, str]] = set()
    public_keys: set[bytes] = set()
    identity_roles: dict[str, str] = {}
    active: dict[str, dict[str, Any]] = {}
    for item in entries:
        item = _exact(item, _KEY_FIELDS, "campaign registry key", code)
        role = item["role"]
        if type(role) is not str or role not in REQUIRED_ROLES:
            _fail(code, "campaign registry key role is unknown")
        key_id = _identifier(item["key_id"], "registry key_id", code)
        principal_id = _identifier(item["principal_id"], "registry principal_id", code)
        custodian_id = _identifier(item["custodian_id"], "registry custodian_id", code)
        if principal_id == custodian_id:
            _fail(code, "campaign registry aliases a role principal and custodian")
        if item["algorithm"] != "Ed25519":
            _fail(code, "campaign registry key algorithm must be Ed25519")
        public_key = _public_key(item["public_key"], "registry public_key", code)
        fingerprint = hashlib.sha256(public_key).hexdigest()
        if item["public_key_fingerprint_sha256"] != fingerprint:
            _fail(code, "campaign registry key fingerprint does not bind the public key")
        if key_id != f"ed25519-sha256:{fingerprint}":
            _fail(code, "campaign registry key_id does not derive from the public key")
        not_before, not_before_text = _utc(item["not_before_utc"], "registry key not_before_utc", code)
        not_after, not_after_text = _utc(item["not_after_utc"], "registry key not_after_utc", code)
        if not_before >= not_after:
            _fail(code, "registry key validity interval is empty or reversed")
        revocation = _exact(item["revocation"], _REVOCATION_FIELDS, "registry key revocation", code)
        if revocation["state"] == "active":
            if revocation["revoked_at_utc"] is not None:
                _fail(code, "active registry key cannot have a revocation timestamp")
            revoked_at = None
        elif revocation["state"] == "revoked":
            revoked_at, revoked_text = _utc(revocation["revoked_at_utc"], "registry key revocation time", code)
            if revoked_at < not_before:
                _fail(code, "registry key cannot be revoked before its validity interval")
            revocation = {"state": "revoked", "revoked_at_utc": revoked_text}
        else:
            _fail(code, "registry key revocation state must be active or revoked")
        identity = (role, key_id)
        if identity in seen_role_key:
            _fail(code, "campaign registry has a duplicate role/key_id")
        if public_key in public_keys:
            _fail(code, "campaign registry aliases an Ed25519 public key across entries")
        for identity_id in (principal_id, custodian_id):
            prior_role = identity_roles.get(identity_id)
            if prior_role is not None and prior_role != role:
                _fail(code, "campaign registry aliases a principal or custodian across incompatible roles")
            identity_roles[identity_id] = role
        seen_role_key.add(identity)
        public_keys.add(public_key)
        entry = {
            "role": role,
            "key_id": key_id,
            "principal_id": principal_id,
            "custodian_id": custodian_id,
            "algorithm": "Ed25519",
            "public_key": public_key,
            "public_key_fingerprint_sha256": fingerprint,
            "not_before": not_before,
            "not_after": not_after,
            "revocation": revocation,
        }
        normalized.append(entry)
        if not_before <= created_at < not_after and (
            revoked_at is None or created_at < revoked_at
        ):
            if role in active:
                _fail(code, "more than one active key occupies a role at campaign creation")
            active[role] = entry
    if [(entry["role"], entry["key_id"]) for entry in normalized] != sorted((entry["role"], entry["key_id"]) for entry in normalized):
        _fail(code, "campaign registry keys must be sorted by role and key_id")
    if set(active) != set(REQUIRED_ROLES):
        _fail(code, "campaign registry must have exactly one valid, unrevoked key for every required role")
    if active["evaluation_authority"]["public_key"] != bootstrap_key:
        _fail(code, "evaluation authority key does not match the implementation-pinned bootstrap key")
    if active["validation_authority"]["public_key"] != validator_key:
        _fail(code, "validation key does not match the independently pinned validator key")
    if bootstrap_key == validator_key:
        _fail(code, "bootstrap authority and independent validator keys must differ")
    # Preserve the byte-verified registry shape while replacing only parsed key
    # records with their checked binary public keys for signature verification.
    return {**raw, "keys": normalized}, digest, active, raw["campaign_nonce"]


def _proofs(
    value: object,
    *,
    active_roles: dict[str, dict[str, Any]],
    campaign_root: str,
    registry_sha256: str,
    campaign_nonce: dict[str, Any],
    registry_epoch: int,
    registry_status: str,
    campaign_created_ns: int,
    final_issued_at_ns: int,
    code: str,
) -> None:
    required = REQUIRED_ROLES
    if type(value) is not dict or set(value) != set(required):
        _fail(code, "proofs must contain exactly one proof-of-possession envelope for every role")
    for role in required:
        entry = active_roles.get(role)
        if entry is None:
            _fail(code, "proof role has no active registry key")
        try:
            payload = verify_envelope(
                value[role],
                expected_artifact_schema=G00_POP_ENVELOPE_SCHEMA,
                pinned_public_key_bytes=entry["public_key"],
            )
        except EnvelopeError as exc:
            raise GovernanceValidationError(code, f"{role} proof-of-possession envelope rejected: {exc}") from exc
        payload = _exact(payload, _POP_PAYLOAD_FIELDS, f"{role} proof-of-possession payload", code)
        expected = {
            "schema": G00_POP_PAYLOAD_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_root_sha256": campaign_root,
            "registry_sha256": registry_sha256,
            "role": role,
            "key_id": entry["key_id"],
            "principal_id": entry["principal_id"],
            "custodian_id": entry["custodian_id"],
            "campaign_nonce": campaign_nonce,
            "issued_at_ns": payload["issued_at_ns"],
            "registry_epoch": registry_epoch,
            "registry_status": registry_status,
        }
        issued_at_ns, _ = _ns(payload["issued_at_ns"], f"{role} PoP issued_at_ns", code)
        if not campaign_created_ns <= issued_at_ns <= final_issued_at_ns:
            _fail(code, f"{role} proof-of-possession issuance is not causally ordered")
        if not _key_valid_at_ns(entry, issued_at_ns):
            _fail(code, f"{role} proof-of-possession key is invalid at issuance")
        if payload != expected:
            _fail(code, f"{role} proof-of-possession envelope does not bind the exact campaign")


def _g00_content(*, campaign_id: str, campaign_root: str, registry_sha256: str, created_at_utc: str, predecessor: dict[str, Any], registry: dict[str, dict[str, Any]], proof_count: int, registry_epoch: int, registry_status: str, issued_at_ns: str) -> dict[str, Any]:
    return {
        "schema": G00_FINAL_GATE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": "G00_TRUST_ROOTS",
        "campaign_id": campaign_id,
        "campaign_root_sha256": campaign_root,
        "registry_sha256": registry_sha256,
        "campaign_created_at_utc": created_at_utc,
        "predecessor": predecessor,
        "role_key_fingerprints": {
            role: hashlib.sha256(registry[role]["public_key"]).hexdigest() for role in REQUIRED_ROLES
        },
        "proof_count": proof_count,
        "registry_epoch": registry_epoch,
        "registry_status": registry_status,
        "issued_at_ns": issued_at_ns,
        "authority": False,
        "submission_authorized": False,
        "holdout_access": False,
        "sealed_holdout_access": False,
        "candidate_authorized": False,
        "candidate_development_authorized": False,
        "decision": G00_DECISION,
        "fail_code": None,
        "reason": None,
    }


def _derive_g00(evidence: object, bootstrap_key: bytes, validator_key: bytes) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    raw = _exact(evidence, _G00_EVIDENCE_FIELDS, "G00 evidence", "G00_EVIDENCE_SCHEMA_INVALID")
    if raw["schema"] != G00_EVIDENCE_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail("G00_EVIDENCE_SCHEMA_INVALID", "G00 evidence schema or protocol is invalid")
    campaign_id = _identifier(raw["campaign_id"], "campaign_id", "G00_EVIDENCE_SCHEMA_INVALID")
    created_at, created_text = _utc(raw["campaign_created_at_utc"], "campaign creation time", "G00_CHRONOLOGY_INVALID")
    issued_at_ns, issued_at_text = _ns(raw["issued_at_ns"], "G00 authority issued_at_ns", "G00_CHRONOLOGY_INVALID")
    if issued_at_ns < _datetime_ns(created_at):
        _fail("G00_CHRONOLOGY_INVALID", "G00 authority issuance predates campaign creation")
    predecessor = _predecessor(raw["predecessor"], created_at, "G00_CHRONOLOGY_INVALID")
    registry, registry_digest, active_roles, campaign_nonce = _registry(
        raw["registry"],
        campaign_id=campaign_id,
        created_at=created_at,
        bootstrap_key=bootstrap_key,
        validator_key=validator_key,
        code="G00_REGISTRY_INVALID",
    )
    if _sha(raw["registry_sha256"], "G00 registry_sha256", "G00_HASH_MISMATCH") != registry_digest:
        _fail("G00_HASH_MISMATCH", "G00 registry_sha256 does not bind exact registry bytes")
    root = _campaign_root(
        campaign_id=campaign_id,
        created_at_utc=created_text,
        predecessor=predecessor,
        registry_sha256=registry_digest,
        campaign_nonce_sha256=_sha(
            campaign_nonce["sha256"], "campaign nonce sha256", "G00_REGISTRY_INVALID"
        ),
    )
    if _sha(raw["campaign_root_sha256"], "campaign_root_sha256", "G00_HASH_MISMATCH") != root:
        _fail("G00_HASH_MISMATCH", "campaign root does not bind the G00 declaration")
    if not _key_valid_at_ns(active_roles["evaluation_authority"], issued_at_ns):
        _fail("G00_CHRONOLOGY_INVALID", "evaluation-authority key is invalid at final G00 issuance")
    _proofs(
        raw["proofs"],
        active_roles=active_roles,
        campaign_root=root,
        registry_sha256=registry_digest,
        campaign_nonce=campaign_nonce,
        registry_epoch=registry["registry_epoch"],
        registry_status=registry["registry_status"],
        campaign_created_ns=_datetime_ns(created_at),
        final_issued_at_ns=issued_at_ns,
        code="G00_POP_INVALID",
    )
    content = _g00_content(
        campaign_id=campaign_id,
        campaign_root=root,
        registry_sha256=registry_digest,
        created_at_utc=created_text,
        predecessor=predecessor,
        registry=active_roles,
        proof_count=len(raw["proofs"]),
        registry_epoch=registry["registry_epoch"],
        registry_status=registry["registry_status"],
        issued_at_ns=issued_at_text,
    )
    return {**content, "result_sha256": canonical_sha256(content)}, registry, active_roles


def _closed(gate: str, code: str, reason: str) -> dict[str, Any]:
    return {
        "schema": G00_FINAL_GATE_SCHEMA if gate == "G00" else G01_FINAL_GATE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": "G00_TRUST_ROOTS" if gate == "G00" else "G01_CONSTITUTION_AND_CODE_FREEZE",
        "authority": False,
        "submission_authorized": False,
        "holdout_access": False,
        "sealed_holdout_access": False,
        "candidate_authorized": False,
        "candidate_development_authorized": False,
        "decision": f"{gate}_EVIDENCE_INVALID",
        "fail_code": code,
        "reason": reason,
    }


def derive_g00_trust_roots(*, campaign_evidence: object, pinned_bootstrap_authority_public_key: bytes, pinned_validation_public_key: bytes) -> dict[str, Any]:
    """Recompute G00 from raw evidence without trusting producer conclusions."""
    try:
        bootstrap = _pinned_key(pinned_bootstrap_authority_public_key, "pinned bootstrap authority key", "G00_PIN_INVALID")
        validator = _pinned_key(pinned_validation_public_key, "pinned validation key", "G00_PIN_INVALID")
        result, _, _ = _derive_g00(campaign_evidence, bootstrap, validator)
        return result
    except (GovernanceValidationError, CanonicalJSONError, KeyError, TypeError, ValueError, RecursionError) as exc:
        return _closed("G00", getattr(exc, "code", "G00_INTERNAL_INVALID"), str(exc))


def _final_chain(*, result: dict[str, Any], authority_envelope: object, countersignature_envelope: object, authority_schema: str, countersignature_schema: str, authority_record: dict[str, Any], validator_record: dict[str, Any], registry_hash: str, code: str) -> None:
    authority_issued_at_ns, _ = _ns(result["issued_at_ns"], "authority issued_at_ns", code)
    if not _key_valid_at_ns(authority_record, authority_issued_at_ns):
        _fail(code, "authority signing key is invalid at envelope issuance")
    try:
        authority_payload = verify_envelope(
            authority_envelope,
            expected_artifact_schema=authority_schema,
            pinned_public_key_bytes=authority_record["public_key"],
        )
    except EnvelopeError as exc:
        raise GovernanceValidationError(code, f"authority envelope rejected: {exc}") from exc
    if authority_payload != result:
        _fail(code, "authority did not sign the complete exact rederived final gate payload")
    try:
        authority_hash = canonical_sha256(authority_envelope)
    except CanonicalJSONError as exc:
        raise GovernanceValidationError(code, "authority envelope is not canonical JSON") from exc
    try:
        counter_payload = verify_envelope(
            countersignature_envelope,
            expected_artifact_schema=countersignature_schema,
            pinned_public_key_bytes=validator_record["public_key"],
        )
    except EnvelopeError as exc:
        raise GovernanceValidationError(code, f"validator countersignature envelope rejected: {exc}") from exc
    counter = _exact(counter_payload, _COUNTERSIGNATURE_FIELDS, "validator countersignature", code)
    validator_issued_at_ns, _ = _ns(counter["issued_at_ns"], "validator issued_at_ns", code)
    if (
        counter["schema"] != countersignature_schema
        or counter["protocol_id"] != PROTOCOL_ID
        or _sha(counter["authority_envelope_sha256"], "countersigned authority envelope hash", code) != authority_hash
        or counter["registry_epoch"] != result["registry_epoch"]
        or _sha(counter["registry_hash"], "countersignature registry hash", code) != registry_hash
        or counter["registry_status"] != result["registry_status"]
        or counter["validator_key_id"] != validator_record["key_id"]
    ):
        _fail(code, "validator did not countersign the exact authority envelope bytes")
    if validator_issued_at_ns < authority_issued_at_ns:
        _fail(code, "validator countersignature predates authority issuance")
    if not _key_valid_at_ns(validator_record, validator_issued_at_ns):
        _fail(code, "validator signing key is invalid at countersignature issuance")


def verify_g00_trust_roots(*, campaign_evidence: object, final_authority_envelope: object, final_validator_envelope: object, pinned_bootstrap_authority_public_key: bytes, pinned_validation_public_key: bytes) -> dict[str, Any]:
    """Verify G00 evidence and its two-signature final receipt."""
    result = derive_g00_trust_roots(
        campaign_evidence=campaign_evidence,
        pinned_bootstrap_authority_public_key=pinned_bootstrap_authority_public_key,
        pinned_validation_public_key=pinned_validation_public_key,
    )
    if result["decision"] != G00_DECISION:
        return result
    try:
        bootstrap = _pinned_key(pinned_bootstrap_authority_public_key, "pinned bootstrap authority key", "G00_PIN_INVALID")
        validator = _pinned_key(pinned_validation_public_key, "pinned validation key", "G00_PIN_INVALID")
        rederived, _, active_roles = _derive_g00(campaign_evidence, bootstrap, validator)
        if rederived != result:
            _fail("G00_FINAL_SIGNATURE_INVALID", "G00 rederivation changed before final verification")
        _final_chain(
            result=result,
            authority_envelope=final_authority_envelope,
            countersignature_envelope=final_validator_envelope,
            authority_schema=G00_FINAL_GATE_SCHEMA,
            countersignature_schema=G00_COUNTERSIGNATURE_SCHEMA,
            authority_record=active_roles["evaluation_authority"],
            validator_record=active_roles["validation_authority"],
            registry_hash=result["registry_sha256"],
            code="G00_FINAL_SIGNATURE_INVALID",
        )
        return result
    except (GovernanceValidationError, CanonicalJSONError, KeyError, TypeError, ValueError, RecursionError) as exc:
        return _closed("G00", getattr(exc, "code", "G00_INTERNAL_INVALID"), str(exc))


def _reject_private_material(path: str, content: bytes, code: str) -> None:
    lower_path = path.lower()
    if lower_path.endswith((".pem", ".p8", ".key")) or "/private/" in f"/{lower_path}/":
        _fail(code, "source archive contains a private-key path")
    if any(marker in content for marker in _PRIVATE_MATERIAL_MARKERS):
        _fail(code, "source archive contains private-key material")


def _source_archive(value: object, *, campaign_id: str, code: str) -> tuple[dict[str, dict[str, Any]], str]:
    _, parsed, digest = _canonical_json_blob(
        value,
        "source archive",
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.source-archive+json"}),
    )
    raw = _exact(parsed, _SOURCE_ARCHIVE_FIELDS, "source archive", code)
    if raw["schema"] != G01_SOURCE_ARCHIVE_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail(code, "source archive schema or protocol is invalid")
    if _identifier(raw["campaign_id"], "source archive campaign_id", code) != campaign_id:
        _fail(code, "source archive campaign_id does not bind G01")
    files = raw["files"]
    if type(files) is not list or not files:
        _fail(code, "source archive files must be a nonempty list")
    result: dict[str, dict[str, Any]] = {}
    paths: list[str] = []
    for item in files:
        item = _exact(item, _SOURCE_FILE_FIELDS, "source archive file", code)
        path = _path(item["path"], "source archive path", code)
        content, content_sha256 = _blob(item["content"], "source archive file content", code)
        _reject_private_material(path, content, code)
        if path in result:
            _fail(code, "source archive has duplicate normalized paths")
        result[path] = {
            "decoded_length": len(content),
            "sha256": content_sha256,
            "media_type": item["content"]["media_type"],
        }
        paths.append(path)
    if paths != sorted(paths):
        _fail(code, "source archive files must be sorted by normalized path")
    return result, digest


def _path_list(value: object, label: str, code: str) -> list[str]:
    if type(value) is not list or not value:
        _fail(code, f"{label} must be a nonempty path list")
    result = [_path(item, label, code) for item in value]
    if result != sorted(set(result)):
        _fail(code, f"{label} must be sorted and duplicate-free")
    return result


def _manifest(value: object, *, campaign_id: str, g00_root: str, archive: dict[str, dict[str, Any]], code: str) -> tuple[dict[str, Any], str]:
    _, parsed, digest = _canonical_json_blob(
        value,
        "source manifest",
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.source-manifest+json"}),
    )
    raw = _exact(parsed, _MANIFEST_FIELDS, "source manifest", code)
    if raw["schema"] != G01_MANIFEST_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail(code, "source manifest schema or protocol is invalid")
    if _identifier(raw["campaign_id"], "source manifest campaign_id", code) != campaign_id:
        _fail(code, "source manifest campaign_id does not bind G01")
    if _sha(raw["g00_campaign_root_sha256"], "source manifest G00 root", code) != g00_root:
        _fail(code, "source manifest does not depend on the verified G00 root")
    _, freeze_time = _utc(raw["freeze_time_utc"], "source manifest freeze time", "G01_CHRONOLOGY_INVALID")
    entries = raw["files"]
    if type(entries) is not list or not entries:
        _fail(code, "source manifest files must be a nonempty list")
    files: dict[str, dict[str, Any]] = {}
    paths: list[str] = []
    for item in entries:
        item = _exact(item, _MANIFEST_FILE_FIELDS, "source manifest file", code)
        path = _path(item["path"], "source manifest path", code)
        length = item["decoded_length"]
        if type(length) is not int or isinstance(length, bool) or length < 0:
            _fail(code, "source manifest decoded_length must be nonnegative")
        digest_value = _sha(item["sha256"], "source manifest file sha256", code)
        media_type = item["media_type"]
        if type(media_type) is not str or _MEDIA_TYPE.fullmatch(media_type) is None:
            _fail(code, "source manifest file media_type is invalid")
        classification = item["classification"]
        if type(classification) is not str or classification not in _CLASSIFICATIONS:
            _fail(code, "source manifest file classification is invalid")
        if path in files:
            _fail(code, "source manifest has duplicate normalized paths")
        files[path] = {"decoded_length": length, "sha256": digest_value, "media_type": media_type, "classification": classification}
        paths.append(path)
    if paths != sorted(paths):
        _fail(code, "source manifest files must be sorted by normalized path")
    if set(files) != set(archive):
        _fail(code, "source manifest closure has extras or omissions relative to source archive bytes")
    for path, entry in files.items():
        if {key: entry[key] for key in ("decoded_length", "sha256", "media_type")} != archive[path]:
            _fail(code, "source manifest file does not bind exact source archive bytes")
    lockfiles = _path_list(raw["lockfiles"], "lockfiles", code)
    build_scripts = _path_list(raw["build_scripts"], "build scripts", code)
    schemas = _path_list(raw["schemas"], "schemas", code)
    configs = _path_list(raw["configs"], "configs", code)
    for label, values, classification in (
        ("lockfiles", lockfiles, "lockfile"),
        ("build_scripts", build_scripts, "build_script"),
        ("schemas", schemas, "schema"),
        ("configs", configs, "config"),
    ):
        for path in values:
            if path not in files or files[path]["classification"] != classification:
                _fail(code, f"{label} reference is absent or has an incompatible manifest classification")
    toolchain = _exact(raw["toolchain"], _TOOLCHAIN_FIELDS, "toolchain reference", code)
    container = _exact(raw["container"], _CONTAINER_FIELDS, "container reference", code)
    seed_spec = _exact(raw["seed_spec"], _SEED_SPEC_FIELDS, "seed specification", code)
    for item, name, classification in (
        (toolchain, "toolchain", "toolchain"),
        (container, "container", "container"),
    ):
        path = _path(item["path"], f"{name} path", code)
        digest_value = _sha(item["sha256"], f"{name} sha256", code)
        _sha(item["container_image_sha256"], f"{name} container image sha256", code)
        if path not in files or files[path]["classification"] != classification or files[path]["sha256"] != digest_value:
            _fail(code, f"{name} reference does not bind a classified source file")
    if toolchain["container_image_sha256"] != container["container_image_sha256"]:
        _fail(code, "toolchain and container references disagree on the frozen image digest")
    seed_path = _path(seed_spec["path"], "seed specification path", code)
    seed_digest = _sha(seed_spec["sha256"], "seed specification sha256", code)
    if seed_path not in files or files[seed_path]["classification"] != "seed_spec" or files[seed_path]["sha256"] != seed_digest:
        _fail(code, "seed specification does not bind a classified source file")
    _identifier(seed_spec["scheme"], "seed specification scheme", code)
    _text(seed_spec["domain_separator"], "seed specification domain separator", code)
    exclusions = raw["exclusions"]
    if type(exclusions) is not list:
        _fail(code, "exclusions must be a list")
    exclusion_paths: list[str] = []
    for item in exclusions:
        item = _exact(item, _EXCLUSION_FIELDS, "exclusion", code)
        path = _path(item["path"], "exclusion path", code)
        _text(item["reason"], "exclusion reason", code)
        if path not in files or files[path]["classification"] != "excluded":
            _fail(code, "exclusion does not bind an excluded source file")
        exclusion_paths.append(path)
    if exclusion_paths != sorted(set(exclusion_paths)):
        _fail(code, "exclusions must be sorted and duplicate-free")
    return {
        "raw": raw,
        "files": files,
        "freeze_time_utc": freeze_time,
        "lockfiles": lockfiles,
        "build_scripts": build_scripts,
        "schemas": schemas,
        "configs": configs,
        "toolchain": toolchain,
        "container": container,
        "seed_spec": seed_spec,
    }, digest


def _constitution(value: object, *, campaign_id: str, g00_root: str, manifest: dict[str, Any], code: str) -> str:
    _, parsed, digest = _canonical_json_blob(
        value,
        "constitution",
        code,
        media_types=frozenset({"application/vnd.evaluation-v5.1.constitution+json"}),
    )
    raw = _exact(parsed, _CONSTITUTION_FIELDS, "constitution", code)
    if raw["schema"] != G01_CONSTITUTION_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail(code, "constitution schema or protocol is invalid")
    if _identifier(raw["campaign_id"], "constitution campaign_id", code) != campaign_id:
        _fail(code, "constitution campaign_id does not bind G01")
    if _sha(raw["g00_campaign_root_sha256"], "constitution G00 root", code) != g00_root:
        _fail(code, "constitution does not depend on the verified G00 root")
    _text(raw["claim"], "constitution claim", code)
    conditions = raw["no_submit_conditions"]
    if type(conditions) is not list or not conditions or any(_text(item, "no-submit condition", code) != item for item in conditions):
        _fail(code, "constitution must freeze nonempty no-submit conditions")
    if conditions != sorted(set(conditions)):
        _fail(code, "constitution no-submit conditions must be sorted and duplicate-free")
    components = _exact(raw["frozen_components"], _FROZEN_COMPONENT_FIELDS, "constitution frozen components", code)
    if _path_list(components["schemas"], "constitution schemas", code) != manifest["schemas"]:
        _fail(code, "constitution schemas do not match the complete manifest")
    for field in ("feature_registry", "model_registry", "dev_algorithm", "census_parser", "sampling_algorithm", "authority_matrix"):
        path = _path(components[field], f"constitution {field}", code)
        if path not in manifest["files"]:
            _fail(code, f"constitution {field} does not reference a manifest file")
    validator_image = _exact(
        components["validator_image"],
        frozenset({"path", "sha256", "container_image_sha256"}),
        "constitution validator image",
        code,
    )
    if (
        _path(validator_image["path"], "constitution validator image path", code) != manifest["container"]["path"]
        or _sha(validator_image["sha256"], "constitution validator image sha256", code) != manifest["container"]["sha256"]
        or _sha(validator_image["container_image_sha256"], "constitution validator container image", code) != manifest["container"]["container_image_sha256"]
    ):
        _fail(code, "constitution validator image does not match the frozen container reference")
    return digest


def _development_attestation(value: object, *, campaign_id: str, g00_root: str, constitution_sha256: str, source_archive_sha256: str, manifest_sha256: str, freeze_time_utc: str, development_key: dict[str, Any], registry_epoch: int, registry_hash: str, registry_status: str, final_issued_at_ns: int, code: str) -> str:
    try:
        payload = verify_envelope(
            value,
            expected_artifact_schema=G01_DEVELOPMENT_ATTESTATION_SCHEMA,
            pinned_public_key_bytes=development_key["public_key"],
        )
    except EnvelopeError as exc:
        raise GovernanceValidationError(code, f"development attestation envelope rejected: {exc}") from exc
    raw = _exact(payload, _DEVELOPMENT_ATTESTATION_FIELDS, "development attestation", code)
    expected = {
        "schema": G01_DEVELOPMENT_ATTESTATION_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": campaign_id,
        "g00_campaign_root_sha256": g00_root,
        "constitution_sha256": constitution_sha256,
        "source_archive_sha256": source_archive_sha256,
        "manifest_sha256": manifest_sha256,
        "freeze_time_utc": freeze_time_utc,
        "development_key_id": development_key["key_id"],
        "development_principal_id": development_key["principal_id"],
        "development_custodian_id": development_key["custodian_id"],
        "registry_epoch": registry_epoch,
        "registry_hash": registry_hash,
        "registry_status": registry_status,
        "issued_at_ns": raw["issued_at_ns"],
    }
    issued_at_ns, _ = _ns(raw["issued_at_ns"], "development attestation issued_at_ns", code)
    freeze_time, _ = _utc(freeze_time_utc, "freeze time", code)
    if not _datetime_ns(freeze_time) <= issued_at_ns <= final_issued_at_ns:
        _fail(code, "development attestation issuance is not causally ordered")
    if not _key_valid_at_ns(development_key, issued_at_ns):
        _fail(code, "development key is invalid at attestation issuance")
    if raw != expected:
        _fail(code, "development identity did not sign the exact frozen source/build inputs")
    return canonical_sha256(value)


def _g01_content(*, campaign_id: str, g00_root: str, constitution_sha256: str, source_archive_sha256: str, manifest_sha256: str, source_inventory_root: str, source_file_count: int, manifest_file_count: int, classification_counts: dict[str, int], freeze_time_utc: str, development_key: dict[str, Any], attestation_envelope_sha256: str, registry_epoch: int, registry_status: str, issued_at_ns: str) -> dict[str, Any]:
    return {
        "schema": G01_FINAL_GATE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        "campaign_id": campaign_id,
        "g00_campaign_root_sha256": g00_root,
        "constitution_sha256": constitution_sha256,
        "source_archive_sha256": source_archive_sha256,
        "manifest_sha256": manifest_sha256,
        "source_inventory_root": source_inventory_root,
        "source_file_count": source_file_count,
        "manifest_file_count": manifest_file_count,
        "classification_counts": classification_counts,
        "freeze_time_utc": freeze_time_utc,
        "development_key_fingerprint_sha256": hashlib.sha256(development_key["public_key"]).hexdigest(),
        "development_attestation_envelope_sha256": attestation_envelope_sha256,
        "registry_epoch": registry_epoch,
        "registry_status": registry_status,
        "issued_at_ns": issued_at_ns,
        "authority": False,
        "submission_authorized": False,
        "holdout_access": False,
        "sealed_holdout_access": False,
        "candidate_authorized": False,
        "candidate_development_authorized": False,
        "decision": G01_DECISION,
        "fail_code": None,
        "reason": None,
    }


def _derive_g01(evidence: object, *, g00_result: dict[str, Any], registry: dict[str, Any], active_roles: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = _exact(evidence, _G01_EVIDENCE_FIELDS, "G01 evidence", "G01_EVIDENCE_SCHEMA_INVALID")
    if raw["schema"] != G01_EVIDENCE_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        _fail("G01_EVIDENCE_SCHEMA_INVALID", "G01 evidence schema or protocol is invalid")
    campaign_id = _identifier(raw["campaign_id"], "G01 campaign_id", "G01_EVIDENCE_SCHEMA_INVALID")
    if campaign_id != g00_result["campaign_id"]:
        _fail("G01_G00_DEPENDENCY_INVALID", "G01 campaign_id does not bind verified G00")
    g00_root = _sha(raw["g00_campaign_root_sha256"], "G01 G00 root", "G01_G00_DEPENDENCY_INVALID")
    if g00_root != g00_result["campaign_root_sha256"]:
        _fail("G01_G00_DEPENDENCY_INVALID", "G01 does not bind the verified G00 campaign root")
    issued_at_ns, issued_at_text = _ns(
        raw["issued_at_ns"], "G01 authority issued_at_ns", "G01_CHRONOLOGY_INVALID"
    )
    archive, archive_sha256 = _source_archive(raw["source_archive"], campaign_id=campaign_id, code="G01_ARCHIVE_INVALID")
    manifest, manifest_sha256 = _manifest(
        raw["manifest"], campaign_id=campaign_id, g00_root=g00_root, archive=archive, code="G01_MANIFEST_INVALID"
    )
    freeze_time, freeze_text = _utc(manifest["freeze_time_utc"], "freeze time", "G01_CHRONOLOGY_INVALID")
    g00_created, _ = _utc(g00_result["campaign_created_at_utc"], "G00 campaign creation time", "G01_CHRONOLOGY_INVALID")
    if freeze_time <= g00_created:
        _fail("G01_CHRONOLOGY_INVALID", "G01 freeze time must strictly follow its verified G00 campaign")
    if issued_at_ns < _datetime_ns(freeze_time):
        _fail("G01_CHRONOLOGY_INVALID", "G01 authority issuance predates the source freeze")
    if not _key_valid_at_ns(active_roles["evaluation_authority"], issued_at_ns):
        _fail("G01_CHRONOLOGY_INVALID", "evaluation-authority key is invalid at final G01 issuance")
    development_key = active_roles["development_identity"]
    if not _key_valid_at_ns(development_key, _datetime_ns(freeze_time)):
        _fail("G01_CHRONOLOGY_INVALID", "development identity is stale, expired, or revoked at freeze time")
    constitution_sha256 = _constitution(
        raw["constitution"], campaign_id=campaign_id, g00_root=g00_root, manifest=manifest, code="G01_CONSTITUTION_INVALID"
    )
    attestation_sha256 = _development_attestation(
        raw["development_attestation_envelope"],
        campaign_id=campaign_id,
        g00_root=g00_root,
        constitution_sha256=constitution_sha256,
        source_archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
        freeze_time_utc=freeze_text,
        development_key=development_key,
        registry_epoch=registry["registry_epoch"],
        registry_hash=g00_result["registry_sha256"],
        registry_status=registry["registry_status"],
        final_issued_at_ns=issued_at_ns,
        code="G01_DEVELOPMENT_SIGNATURE_INVALID",
    )
    content = _g01_content(
        campaign_id=campaign_id,
        g00_root=g00_root,
        constitution_sha256=constitution_sha256,
        source_archive_sha256=archive_sha256,
        manifest_sha256=manifest_sha256,
        source_inventory_root=canonical_sha256(manifest["raw"]["files"]),
        source_file_count=len(archive),
        manifest_file_count=len(manifest["files"]),
        classification_counts={
            classification: sum(
                1
                for entry in manifest["files"].values()
                if entry["classification"] == classification
            )
            for classification in sorted(_CLASSIFICATIONS)
        },
        freeze_time_utc=freeze_text,
        development_key=development_key,
        attestation_envelope_sha256=attestation_sha256,
        registry_epoch=registry["registry_epoch"],
        registry_status=registry["registry_status"],
        issued_at_ns=issued_at_text,
    )
    return {**content, "result_sha256": canonical_sha256(content)}


def derive_g01_constitution_and_code_freeze(*, campaign_evidence: object, g00_final_authority_envelope: object, g00_final_validator_envelope: object, g01_evidence: object, pinned_bootstrap_authority_public_key: bytes, pinned_validation_public_key: bytes) -> dict[str, Any]:
    """Recompute the code-freeze receipt after cryptographically verifying G00."""
    try:
        bootstrap = _pinned_key(pinned_bootstrap_authority_public_key, "pinned bootstrap authority key", "G01_PIN_INVALID")
        validator = _pinned_key(pinned_validation_public_key, "pinned validation key", "G01_PIN_INVALID")
        g00_result, registry, active_roles = _derive_g00(campaign_evidence, bootstrap, validator)
        _final_chain(
            result=g00_result,
            authority_envelope=g00_final_authority_envelope,
            countersignature_envelope=g00_final_validator_envelope,
            authority_schema=G00_FINAL_GATE_SCHEMA,
            countersignature_schema=G00_COUNTERSIGNATURE_SCHEMA,
            authority_record=active_roles["evaluation_authority"],
            validator_record=active_roles["validation_authority"],
            registry_hash=g00_result["registry_sha256"],
            code="G01_G00_DEPENDENCY_INVALID",
        )
        return _derive_g01(g01_evidence, g00_result=g00_result, registry=registry, active_roles=active_roles)
    except (GovernanceValidationError, CanonicalJSONError, KeyError, TypeError, ValueError, RecursionError) as exc:
        return _closed("G01", getattr(exc, "code", "G01_INTERNAL_INVALID"), str(exc))


def verify_g01_constitution_and_code_freeze(*, campaign_evidence: object, g00_final_authority_envelope: object, g00_final_validator_envelope: object, g01_evidence: object, final_authority_envelope: object, final_validator_envelope: object, pinned_bootstrap_authority_public_key: bytes, pinned_validation_public_key: bytes) -> dict[str, Any]:
    """Verify G01 raw evidence plus its authority/validator final receipt chain."""
    result = derive_g01_constitution_and_code_freeze(
        campaign_evidence=campaign_evidence,
        g00_final_authority_envelope=g00_final_authority_envelope,
        g00_final_validator_envelope=g00_final_validator_envelope,
        g01_evidence=g01_evidence,
        pinned_bootstrap_authority_public_key=pinned_bootstrap_authority_public_key,
        pinned_validation_public_key=pinned_validation_public_key,
    )
    if result["decision"] != G01_DECISION:
        return result
    try:
        bootstrap = _pinned_key(pinned_bootstrap_authority_public_key, "pinned bootstrap authority key", "G01_PIN_INVALID")
        validator = _pinned_key(pinned_validation_public_key, "pinned validation key", "G01_PIN_INVALID")
        g00_result, registry, active_roles = _derive_g00(campaign_evidence, bootstrap, validator)
        _final_chain(
            result=g00_result,
            authority_envelope=g00_final_authority_envelope,
            countersignature_envelope=g00_final_validator_envelope,
            authority_schema=G00_FINAL_GATE_SCHEMA,
            countersignature_schema=G00_COUNTERSIGNATURE_SCHEMA,
            authority_record=active_roles["evaluation_authority"],
            validator_record=active_roles["validation_authority"],
            registry_hash=g00_result["registry_sha256"],
            code="G01_G00_DEPENDENCY_INVALID",
        )
        rederived = _derive_g01(
            g01_evidence,
            g00_result=g00_result,
            registry=registry,
            active_roles=active_roles,
        )
        if rederived != result:
            _fail("G01_FINAL_SIGNATURE_INVALID", "G01 rederivation changed before final verification")
        _final_chain(
            result=result,
            authority_envelope=final_authority_envelope,
            countersignature_envelope=final_validator_envelope,
            authority_schema=G01_FINAL_GATE_SCHEMA,
            countersignature_schema=G01_COUNTERSIGNATURE_SCHEMA,
            authority_record=active_roles["evaluation_authority"],
            validator_record=active_roles["validation_authority"],
            registry_hash=g00_result["registry_sha256"],
            code="G01_FINAL_SIGNATURE_INVALID",
        )
        return result
    except (GovernanceValidationError, CanonicalJSONError, KeyError, TypeError, ValueError, RecursionError) as exc:
        return _closed("G01", getattr(exc, "code", "G01_INTERNAL_INVALID"), str(exc))


# ---------------------------------------------------------------------------
# Governance v2 hard cut
# ---------------------------------------------------------------------------


def _v2_key_id(public_key: bytes) -> str:
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def governance_v2_signature_message(*, domain: bytes, payload_raw: bytes) -> bytes:
    """Frame exact canonical governance-v2 payload bytes for Ed25519 signing."""

    if domain not in _GOVERNANCE_V2_SIGNING_DOMAINS:
        _fail("GOVERNANCE_V2_SIGNATURE_INPUT_INVALID", "signature domain is not frozen")
    if type(payload_raw) is not bytes:
        _fail("GOVERNANCE_V2_SIGNATURE_INPUT_INVALID", "signed payload must be raw bytes")
    try:
        exact_gate_v2.strict_canonical_json(payload_raw, label="governance signed payload")
    except exact_gate_v2.ExactGateV2Error as exc:
        raise GovernanceValidationError(
            "GOVERNANCE_V2_SIGNATURE_INPUT_INVALID", str(exc)
        ) from exc
    return domain + b"\x00" + len(payload_raw).to_bytes(8, "big") + payload_raw


def _v2_raw(value: object, label: str, code: str) -> bytes:
    if type(value) is not bytes:
        _fail(code, f"{label} must be exact canonical raw bytes")
    return value


def _v2_decode_wrapper(
    value: object, *, media_type: str, label: str, code: str
) -> bytes:
    try:
        return exact_gate_v2.decode_byte_evidence(
            value, expected_media_type=media_type
        )
    except exact_gate_v2.ExactGateV2Error as exc:
        raise GovernanceValidationError(code, f"{label} rejected: {exc}") from exc


def _v2_signed_payload(
    envelope_raw: object,
    *,
    envelope_schema: str,
    payload_media_type: str,
    public_key: bytes,
    domain: bytes,
    fields: frozenset[str],
    label: str,
    code: str,
) -> tuple[bytes, dict[str, Any]]:
    raw = _v2_raw(envelope_raw, f"{label} envelope", code)
    try:
        envelope = _exact(
            exact_gate_v2.strict_canonical_json(raw, label=f"{label} envelope"),
            _V2_ENVELOPE_FIELDS,
            f"{label} envelope",
            code,
        )
        if envelope["schema_version"] != envelope_schema:
            _fail(code, f"{label} envelope schema mismatch")
        # Reuse exact-gate's strict point/subgroup and signature-encoding
        # validators while keeping governance on its own frozen domains.
        validated_key_id = exact_gate_v2.validate_ed25519_public_key(public_key)
        if envelope["signer_key_id"] != validated_key_id:
            _fail(code, f"{label} envelope key id mismatch")
        payload_raw = exact_gate_v2.decode_byte_evidence(
            envelope["payload"], expected_media_type=payload_media_type
        )
        payload = exact_gate_v2.strict_canonical_json(
            payload_raw, label=f"{label} payload"
        )
        signature_value = envelope["signature_ed25519_base64"]
        if type(signature_value) is not str:
            _fail(code, f"{label} signature must be canonical base64")
        signature = base64.b64decode(signature_value, validate=True)
        if (
            len(signature) != 64
            or base64.b64encode(signature).decode("ascii") != signature_value
        ):
            _fail(code, f"{label} signature must encode exactly 64 bytes")
        exact_gate_v2.validate_ed25519_signature_encoding(signature)
        message = governance_v2_signature_message(
            domain=domain, payload_raw=payload_raw
        )
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, binascii.Error, ValueError) as exc:
        raise GovernanceValidationError(
            code, f"{label} Ed25519 signature verification failed"
        ) from exc
    except exact_gate_v2.ExactGateV2Error as exc:
        raise GovernanceValidationError(code, f"{label} rejected: {exc}") from exc
    return payload_raw, _exact(payload, fields, f"{label} payload", code)


def _v2_key_record(
    value: object, *, expected_role: str | None, label: str, code: str
) -> dict[str, Any]:
    raw = _exact(value, _V2_KEY_FIELDS, label, code)
    role = raw["role"]
    if type(role) is not str or role not in GOVERNANCE_V2_REQUIRED_ROLES:
        _fail(code, f"{label} has an unknown role")
    if expected_role is not None and role != expected_role:
        _fail(code, f"{label} role does not match its required role")
    if raw["algorithm"] != "Ed25519":
        _fail(code, f"{label} algorithm must be Ed25519")
    public_key = _v2_decode_wrapper(
        raw["public_key"],
        media_type=GOVERNANCE_V2_PUBLIC_KEY_MEDIA_TYPE,
        label=f"{label} public key",
        code=code,
    )
    if len(public_key) != 32 or public_key == bytes(32):
        _fail(code, f"{label} public key must be a nonzero 32-byte Ed25519 key")
    key_id = _identifier(raw["key_id"], f"{label} key_id", code)
    try:
        derived_key_id = exact_gate_v2.validate_ed25519_public_key(public_key)
    except exact_gate_v2.ExactGateV2Error as exc:
        raise GovernanceValidationError(code, f"{label} public key rejected: {exc}") from exc
    if key_id != derived_key_id:
        _fail(code, f"{label} key_id is not derived from its exact public-key bytes")
    principal_id = _identifier(raw["principal_id"], f"{label} principal_id", code)
    custodian_id = _identifier(raw["custodian_id"], f"{label} custodian_id", code)
    if principal_id == custodian_id:
        _fail(code, f"{label} aliases its principal and custodian")
    valid_from_ns, valid_from_text = _ns(
        raw["valid_from_ns"], f"{label} valid_from_ns", code
    )
    valid_until_ns, valid_until_text = _ns(
        raw["valid_until_ns"], f"{label} valid_until_ns", code
    )
    if valid_from_ns >= valid_until_ns:
        _fail(code, f"{label} validity interval is empty or reversed")
    status = raw["status"]
    if status == "ACTIVE":
        if raw["invalidate_from_ns"] is not None:
            _fail(code, f"{label} active key has an invalidation time")
        invalidate_from_ns = None
        invalidate_text = None
    elif status in {"REVOKED", "COMPROMISED"}:
        invalidate_from_ns, invalidate_text = _ns(
            raw["invalidate_from_ns"], f"{label} invalidate_from_ns", code
        )
        if not valid_from_ns <= invalidate_from_ns < valid_until_ns:
            _fail(code, f"{label} invalidation is outside its validity interval")
    else:
        _fail(code, f"{label} status is unknown")
    return {
        "raw": raw,
        "role": role,
        "key_id": key_id,
        "principal_id": principal_id,
        "custodian_id": custodian_id,
        "public_key": public_key,
        "valid_from_ns": valid_from_ns,
        "valid_from_text": valid_from_text,
        "valid_until_ns": valid_until_ns,
        "valid_until_text": valid_until_text,
        "status": status,
        "invalidate_from_ns": invalidate_from_ns,
        "invalidate_text": invalidate_text,
    }


def _v2_key_valid_at(record: Mapping[str, Any], issued_at_ns: int) -> bool:
    invalidated = record["invalidate_from_ns"]
    return (
        record["valid_from_ns"] <= issued_at_ns < record["valid_until_ns"]
        and (invalidated is None or issued_at_ns < invalidated)
    )


def _v2_key_immutables(record: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        record["role"],
        record["key_id"],
        record["principal_id"],
        record["custodian_id"],
        record["public_key"],
        record["valid_from_ns"],
        record["valid_until_ns"],
    )


def _v2_role_independence(records: Sequence[Mapping[str, Any]], code: str) -> None:
    key_roles: dict[bytes, str] = {}
    identity_roles: dict[str, str] = {}
    for record in records:
        role = record["role"]
        prior_key_role = key_roles.get(record["public_key"])
        if prior_key_role is not None:
            _fail(code, "registry reuses exact key bytes across records")
        key_roles[record["public_key"]] = role
        for identity in (record["principal_id"], record["custodian_id"]):
            prior_identity_role = identity_roles.get(identity)
            if prior_identity_role is not None and prior_identity_role != role:
                _fail(code, "registry aliases a principal or custodian across incompatible roles")
            identity_roles[identity] = role


def _v2_active_roles(
    records: Sequence[dict[str, Any]], *, epoch_issued_at_ns: int, code: str
) -> dict[str, dict[str, Any]]:
    active: dict[str, dict[str, Any]] = {}
    for record in records:
        if record["status"] != "ACTIVE":
            continue
        if not _v2_key_valid_at(record, epoch_issued_at_ns):
            _fail(code, "an ACTIVE registry key is stale at its registry epoch")
        if record["role"] in active:
            _fail(code, "a registry epoch has more than one ACTIVE key for a role")
        active[record["role"]] = record
    if set(active) != set(GOVERNANCE_V2_REQUIRED_ROLES):
        _fail(code, "registry epoch must contain exactly one ACTIVE key for every role")
    return active


def _v2_genesis(
    genesis_envelope: object, pinned_root: bytes
) -> dict[str, Any]:
    payload_raw, payload = _v2_signed_payload(
        genesis_envelope,
        envelope_schema=GOVERNANCE_V2_GENESIS_ENVELOPE_SCHEMA,
        payload_media_type=GOVERNANCE_V2_GENESIS_MEDIA_TYPE,
        public_key=pinned_root,
        domain=GOVERNANCE_V2_GENESIS_DOMAIN,
        fields=_V2_GENESIS_FIELDS,
        label="governance genesis",
        code="GOVERNANCE_V2_GENESIS_INVALID",
    )
    if (
        payload["schema_version"] != GOVERNANCE_V2_GENESIS_PAYLOAD_SCHEMA
        or payload["protocol_id"] != PROTOCOL_ID
    ):
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis schema or protocol mismatch")
    campaign_id = _identifier(
        payload["campaign_id"], "genesis campaign_id", "GOVERNANCE_V2_GENESIS_INVALID"
    )
    created_at_ns, created_at_text = _ns(
        payload["created_at_ns"], "genesis created_at_ns", "GOVERNANCE_V2_GENESIS_INVALID"
    )
    issued_at_ns, issued_at_text = _ns(
        payload["issued_at_ns"], "genesis issued_at_ns", "GOVERNANCE_V2_GENESIS_INVALID"
    )
    if issued_at_ns < created_at_ns:
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis issuance predates creation")
    if payload["offline_root_key_id"] != _v2_key_id(pinned_root):
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis does not bind the pinned offline root")
    campaign_nonce = _v2_decode_wrapper(
        payload["campaign_nonce"],
        media_type=GOVERNANCE_V2_CAMPAIGN_NONCE_MEDIA_TYPE,
        label="genesis campaign nonce",
        code="GOVERNANCE_V2_GENESIS_INVALID",
    )
    if len(campaign_nonce) != 32:
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "campaign nonce must contain exactly 256 bits")
    if payload["required_roles"] != list(GOVERNANCE_V2_REQUIRED_ROLES):
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis required-role list is not exact")
    matrix = payload["incompatible_role_matrix"]
    if type(matrix) is not dict or set(matrix) != set(GOVERNANCE_V2_REQUIRED_ROLES):
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis incompatible-role matrix is not exact")
    for role in GOVERNANCE_V2_REQUIRED_ROLES:
        if matrix[role] != [candidate for candidate in GOVERNANCE_V2_REQUIRED_ROLES if candidate != role]:
            _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis incompatible-role matrix is not canonical")
    registry_custodian = _v2_key_record(
        payload["registry_custodian"],
        expected_role="registry_custodian",
        label="genesis registry custodian",
        code="GOVERNANCE_V2_GENESIS_INVALID",
    )
    if registry_custodian["status"] != "ACTIVE" or not _v2_key_valid_at(
        registry_custodian, issued_at_ns
    ):
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "genesis registry custodian is not valid at issuance")
    if registry_custodian["public_key"] == pinned_root:
        _fail("GOVERNANCE_V2_GENESIS_INVALID", "offline root and registry custodian keys must differ")
    raw = _v2_raw(genesis_envelope, "genesis envelope", "GOVERNANCE_V2_GENESIS_INVALID")
    campaign_root = hashlib.sha256(
        GOVERNANCE_V2_CAMPAIGN_ROOT_DOMAIN + len(raw).to_bytes(8, "big") + raw
    ).hexdigest()
    return {
        "raw": raw,
        "payload_raw": payload_raw,
        "payload": payload,
        "campaign_id": campaign_id,
        "campaign_root": campaign_root,
        "campaign_nonce": payload["campaign_nonce"],
        "created_at_ns": created_at_ns,
        "created_at_text": created_at_text,
        "issued_at_ns": issued_at_ns,
        "issued_at_text": issued_at_text,
        "registry_custodian": registry_custodian,
        "offline_root_public_key": pinned_root,
    }


def _v2_registry_transition(
    previous: Mapping[str, dict[str, Any]],
    current: Mapping[str, dict[str, Any]],
    *,
    code: str,
) -> None:
    if not set(previous).issubset(current):
        _fail(code, "registry epoch deletes a historical key record")
    for key_id, old in previous.items():
        new = current[key_id]
        if _v2_key_immutables(old) != _v2_key_immutables(new):
            _fail(code, "registry epoch mutates immutable key identity or validity")
        old_status = old["status"]
        new_status = new["status"]
        if old_status == "ACTIVE":
            if new_status == "ACTIVE":
                continue
            if new_status not in {"REVOKED", "COMPROMISED"}:
                _fail(code, "registry key has an invalid status transition")
        elif old_status == "REVOKED":
            if new_status not in {"REVOKED", "COMPROMISED"}:
                _fail(code, "revoked registry key was resurrected")
            if new["invalidate_from_ns"] > old["invalidate_from_ns"]:
                _fail(code, "registry epoch weakens a prior revocation time")
        elif new_status != "COMPROMISED" or new["invalidate_from_ns"] > old["invalidate_from_ns"]:
            _fail(code, "compromised registry key was weakened or resurrected")
    for key_id, record in current.items():
        if key_id not in previous and record["status"] != "ACTIVE":
            _fail(code, "new registry keys must be introduced while ACTIVE")


def _v2_registry_epochs(
    epoch_envelopes: object, *, genesis: Mapping[str, Any]
) -> dict[str, Any]:
    if (
        not isinstance(epoch_envelopes, Sequence)
        or isinstance(epoch_envelopes, (str, bytes, bytearray))
        or not epoch_envelopes
    ):
        _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry epochs must be a nonempty sequence")
    previous_hash = hashlib.sha256(genesis["raw"]).hexdigest()
    previous_issued_at_ns = genesis["issued_at_ns"]
    previous_records: dict[str, dict[str, Any]] | None = None
    previous_active = {"registry_custodian": genesis["registry_custodian"]}
    signer_audit: list[tuple[str, int]] = []
    epoch_contexts: list[dict[str, Any]] = []
    for expected_epoch, envelope_value in enumerate(epoch_envelopes):
        signer = previous_active["registry_custodian"]
        payload_raw, payload = _v2_signed_payload(
            envelope_value,
            envelope_schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
            payload_media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
            public_key=signer["public_key"],
            domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
            fields=_V2_REGISTRY_EPOCH_FIELDS,
            label=f"registry epoch {expected_epoch}",
            code="GOVERNANCE_V2_REGISTRY_INVALID",
        )
        if (
            payload["schema_version"] != GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA
            or payload["protocol_id"] != PROTOCOL_ID
            or payload["campaign_root"] != genesis["campaign_root"]
        ):
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry epoch schema, protocol, or campaign root mismatch")
        if type(payload["epoch"]) is not int or isinstance(payload["epoch"], bool) or payload["epoch"] != expected_epoch:
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry epochs are not monotonic and contiguous")
        if _sha(
            payload["predecessor_epoch_hash"],
            "registry predecessor hash",
            "GOVERNANCE_V2_REGISTRY_INVALID",
        ) != previous_hash:
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry predecessor hash chain is broken")
        issued_at_ns, issued_at_text = _ns(
            payload["issued_at_ns"],
            "registry epoch issued_at_ns",
            "GOVERNANCE_V2_REGISTRY_INVALID",
        )
        if issued_at_ns <= previous_issued_at_ns:
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry epoch time is not strictly monotonic")
        if payload["registry_status"] != "ACTIVE":
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "current registry epoch is not ACTIVE")
        if type(payload["keys"]) is not list or not payload["keys"]:
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry epoch keys must be a nonempty list")
        records = [
            _v2_key_record(
                item,
                expected_role=None,
                label="registry epoch key",
                code="GOVERNANCE_V2_REGISTRY_INVALID",
            )
            for item in payload["keys"]
        ]
        if any(
            record["public_key"] == genesis["offline_root_public_key"]
            for record in records
        ):
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "offline root key is reused by an online governance role")
        ordering = [(record["role"], record["key_id"]) for record in records]
        if ordering != sorted(ordering) or len({record["key_id"] for record in records}) != len(records):
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry keys are not unique and canonically sorted")
        _v2_role_independence(records, "GOVERNANCE_V2_REGISTRY_INVALID")
        by_id = {record["key_id"]: record for record in records}
        active = _v2_active_roles(
            records,
            epoch_issued_at_ns=issued_at_ns,
            code="GOVERNANCE_V2_REGISTRY_INVALID",
        )
        if expected_epoch == 0:
            genesis_custodian = genesis["registry_custodian"]
            current_custodian = by_id.get(genesis_custodian["key_id"])
            if current_custodian is None or _v2_key_immutables(current_custodian) != _v2_key_immutables(genesis_custodian):
                _fail("GOVERNANCE_V2_REGISTRY_INVALID", "epoch zero does not preserve the root-appointed custodian")
        else:
            if previous_records is None:
                _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry transition has no predecessor state")
            _v2_registry_transition(
                previous_records, by_id, code="GOVERNANCE_V2_REGISTRY_INVALID"
            )
        signer_in_current = by_id.get(signer["key_id"])
        if signer_in_current is None or not _v2_key_valid_at(signer_in_current, issued_at_ns):
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "registry custodian key is invalid at epoch issuance")
        raw = _v2_raw(
            envelope_value,
            f"registry epoch {expected_epoch} envelope",
            "GOVERNANCE_V2_REGISTRY_INVALID",
        )
        current_hash = hashlib.sha256(raw).hexdigest()
        signer_audit.append((signer["key_id"], issued_at_ns))
        epoch_contexts.append(
            {
                "raw": raw,
                "payload_raw": payload_raw,
                "payload": payload,
                "hash": current_hash,
                "issued_at_ns": issued_at_ns,
                "issued_at_text": issued_at_text,
                "records": records,
                "by_id": by_id,
                "active": active,
            }
        )
        previous_hash = current_hash
        previous_issued_at_ns = issued_at_ns
        previous_records = by_id
        previous_active = active
    latest = epoch_contexts[-1]
    for signer_key_id, issuance in signer_audit:
        final_record = latest["by_id"].get(signer_key_id)
        if final_record is None or not _v2_key_valid_at(final_record, issuance):
            _fail("GOVERNANCE_V2_REGISTRY_INVALID", "a later compromise invalidates a registry-epoch signature")
    return {"epochs": epoch_contexts, "latest": latest}


def _v2_gate_dag(value: object, code: str) -> tuple[list[dict[str, Any]], str]:
    if type(value) is not list or len(value) != len(GOVERNANCE_V2_GATE_IDS):
        _fail(code, "evaluation entry must freeze exactly G00 through G15")
    normalized: list[dict[str, Any]] = []
    for expected_gate, item in zip(GOVERNANCE_V2_GATE_IDS, value, strict=True):
        row = _exact(item, _V2_GATE_FIELDS, "evaluation gate registration", code)
        if row["gate_id"] != expected_gate:
            _fail(code, "evaluation gate registration order or identity is mutated")
        expected_dependencies = list(GOVERNANCE_V2_GATE_DEPENDENCIES[expected_gate])
        if row["direct_dependencies"] != expected_dependencies:
            _fail(code, "evaluation gate DAG differs from the exact registered DAG")
        for field in (
            "frozen_spec_hash",
            "verifier_module_hash",
            "verifier_runtime_hash",
            "input_schema_hash",
            "output_schema_hash",
            "failure_code_registry_hash",
        ):
            _sha(row[field], f"{expected_gate} {field}", code)
        if row["evidence_manifest_schema"] != exact_gate_v2.EVIDENCE_MANIFEST_SCHEMA:
            _fail(code, "gate registration uses an unknown evidence-manifest schema")
        normalized.append(row)
    return normalized, canonical_sha256(normalized)


def _v2_evaluation_entry(
    evaluation_entry_envelope: object,
    *,
    genesis: Mapping[str, Any],
    latest: Mapping[str, Any],
) -> dict[str, Any]:
    registrar = latest["active"]["registrar"]
    payload_raw, payload = _v2_signed_payload(
        evaluation_entry_envelope,
        envelope_schema=GOVERNANCE_V2_EVALUATION_ENTRY_ENVELOPE_SCHEMA,
        payload_media_type=GOVERNANCE_V2_EVALUATION_ENTRY_MEDIA_TYPE,
        public_key=registrar["public_key"],
        domain=GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN,
        fields=_V2_EVALUATION_ENTRY_FIELDS,
        label="prospective evaluation entry",
        code="GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    if (
        payload["schema_version"] != GOVERNANCE_V2_EVALUATION_ENTRY_SCHEMA
        or payload["protocol_id"] != PROTOCOL_ID
        or payload["campaign_root"] != genesis["campaign_root"]
        or payload["registry_epoch"] != latest["payload"]["epoch"]
        or payload["registry_hash"] != latest["hash"]
        or payload["registry_status"] != "ACTIVE"
    ):
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation entry uses stale or mismatched governance")
    evaluation_id = _identifier(
        payload["evaluation_id"],
        "evaluation entry evaluation_id",
        "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    evaluation_nonce = _sha(
        payload["evaluation_nonce"],
        "evaluation entry nonce",
        "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    if evaluation_nonce == "0" * 64:
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation nonce cannot be the all-zero 256-bit value")
    if type(payload["attempt"]) is not int or isinstance(payload["attempt"], bool) or payload["attempt"] != 0:
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation entry attempt must be integer zero")
    if (
        payload["registrar_key_id"] != registrar["key_id"]
        or payload["registrar_principal_id"] != registrar["principal_id"]
        or payload["registrar_custodian_id"] != registrar["custodian_id"]
    ):
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation entry does not bind the current registrar identity")
    registered_at_ns, registered_text = _ns(
        payload["registered_at_ns"],
        "evaluation registered_at_ns",
        "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    issued_at_ns, issued_text = _ns(
        payload["issued_at_ns"],
        "evaluation entry issued_at_ns",
        "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    if registered_at_ns != issued_at_ns or registered_at_ns <= latest["issued_at_ns"]:
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation registration must be an exact prospective issuance after the current epoch")
    if not _v2_key_valid_at(registrar, issued_at_ns):
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "registrar key is invalid at entry issuance")
    if payload["evidence_manifest_schema"] != exact_gate_v2.EVIDENCE_MANIFEST_SCHEMA:
        _fail("GOVERNANCE_V2_EVALUATION_ENTRY_INVALID", "evaluation entry has an unknown evidence-manifest schema")
    gates, gate_registry_root = _v2_gate_dag(
        payload["gate_dag"], "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID"
    )
    raw = _v2_raw(
        evaluation_entry_envelope,
        "evaluation entry envelope",
        "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID",
    )
    return {
        "raw": raw,
        "payload_raw": payload_raw,
        "payload": payload,
        "hash": hashlib.sha256(raw).hexdigest(),
        "evaluation_id": evaluation_id,
        "evaluation_nonce": evaluation_nonce,
        "registered_at_ns": registered_at_ns,
        "registered_text": registered_text,
        "issued_at_ns": issued_at_ns,
        "issued_text": issued_text,
        "gates": gates,
        "gate_by_id": {row["gate_id"]: row for row in gates},
        "gate_registry_root": gate_registry_root,
    }


def _v2_role_pops(
    role_pop_envelopes: object,
    *,
    genesis: Mapping[str, Any],
    latest: Mapping[str, Any],
    registered_at_ns: int,
) -> dict[str, int]:
    if type(role_pop_envelopes) is not dict or set(role_pop_envelopes) != set(GOVERNANCE_V2_REQUIRED_ROLES):
        _fail("GOVERNANCE_V2_POP_INVALID", "PoP set must cover every v2 role exactly")
    issuance: dict[str, int] = {}
    for role in GOVERNANCE_V2_REQUIRED_ROLES:
        record = latest["active"][role]
        _, payload = _v2_signed_payload(
            role_pop_envelopes[role],
            envelope_schema=GOVERNANCE_V2_ROLE_POP_ENVELOPE_SCHEMA,
            payload_media_type=GOVERNANCE_V2_ROLE_POP_MEDIA_TYPE,
            public_key=record["public_key"],
            domain=GOVERNANCE_V2_ROLE_POP_DOMAIN,
            fields=_V2_ROLE_POP_FIELDS,
            label=f"{role} proof of possession",
            code="GOVERNANCE_V2_POP_INVALID",
        )
        issued_at_ns, issued_text = _ns(
            payload["issued_at_ns"], f"{role} PoP issued_at_ns", "GOVERNANCE_V2_POP_INVALID"
        )
        expected = {
            "schema_version": GOVERNANCE_V2_ROLE_POP_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_root": genesis["campaign_root"],
            "registry_epoch": latest["payload"]["epoch"],
            "registry_hash": latest["hash"],
            "registry_status": "ACTIVE",
            "role": role,
            "key_id": record["key_id"],
            "principal_id": record["principal_id"],
            "custodian_id": record["custodian_id"],
            "campaign_nonce": genesis["campaign_nonce"],
            "issued_at_ns": issued_text,
        }
        if payload != expected:
            _fail("GOVERNANCE_V2_POP_INVALID", f"{role} PoP does not bind the exact current campaign and identity")
        if not latest["issued_at_ns"] <= issued_at_ns <= registered_at_ns:
            _fail("GOVERNANCE_V2_POP_INVALID", f"{role} PoP is not causally ordered before evaluation registration")
        if not _v2_key_valid_at(record, issued_at_ns):
            _fail("GOVERNANCE_V2_POP_INVALID", f"{role} PoP key is invalid at issuance")
        issuance[role] = issued_at_ns
    return issuance


def _v2_context(
    *,
    genesis_envelope: object,
    registry_epoch_envelopes: object,
    role_pop_envelopes: object,
    evaluation_entry_envelope: object,
    pinned_offline_root_public_key: object,
) -> dict[str, Any]:
    pinned_root = _pinned_key(
        pinned_offline_root_public_key,
        "pinned offline campaign root key",
        "GOVERNANCE_V2_PIN_INVALID",
    )
    genesis = _v2_genesis(genesis_envelope, pinned_root)
    registry = _v2_registry_epochs(registry_epoch_envelopes, genesis=genesis)
    entry = _v2_evaluation_entry(
        evaluation_entry_envelope, genesis=genesis, latest=registry["latest"]
    )
    pop_issuance = _v2_role_pops(
        role_pop_envelopes,
        genesis=genesis,
        latest=registry["latest"],
        registered_at_ns=entry["registered_at_ns"],
    )
    return {
        "genesis": genesis,
        "registry": registry,
        "latest": registry["latest"],
        "entry": entry,
        "pop_issuance": pop_issuance,
    }


def _v2_flags() -> dict[str, bool]:
    return {
        "authority": False,
        "submission_authorized": False,
        "holdout_access": False,
        "sealed_holdout_access": False,
        "candidate_authorized": False,
        "candidate_development_authorized": False,
    }


def _v2_receipt(context: Mapping[str, Any], *, verified: bool) -> dict[str, Any]:
    genesis = context["genesis"]
    latest = context["latest"]
    entry = context["entry"]
    content: dict[str, Any] = {
        "schema_version": GOVERNANCE_V2_VERIFIED_SCHEMA if verified else GOVERNANCE_V2_DERIVED_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": genesis["campaign_id"],
        "campaign_root": genesis["campaign_root"],
        "genesis_envelope_sha256": hashlib.sha256(genesis["raw"]).hexdigest(),
        "registry_epoch": latest["payload"]["epoch"],
        "registry_hash": latest["hash"],
        "registry_status": "ACTIVE",
        "evaluation_entry_hash": entry["hash"],
        "evaluation_id": entry["evaluation_id"],
        "evaluation_nonce": entry["evaluation_nonce"],
        "attempt": 0,
        "registered_at_ns": entry["registered_text"],
        "gate_registry_root": entry["gate_registry_root"],
        "gate_count": len(entry["gates"]),
        "role_pop_count": len(context["pop_issuance"]),
        "role_key_ids": {
            role: latest["active"][role]["key_id"]
            for role in GOVERNANCE_V2_REQUIRED_ROLES
        },
        "decision": (
            "GOVERNANCE_V2_VERIFIED_RESEARCH_ONLY"
            if verified
            else "GOVERNANCE_V2_DERIVED_RESEARCH_ONLY"
        ),
        **_v2_flags(),
    }
    if verified:
        freeze = context["freeze"]
        content.update(
            {
                "freeze_at_ns": freeze["freeze_at_text"],
                "freeze_authority_issued_at_ns": freeze["authority_issued_text"],
                "freeze_validator_issued_at_ns": freeze["validator_issued_text"],
                "freeze_authority_envelope_sha256": hashlib.sha256(
                    freeze["authority_raw"]
                ).hexdigest(),
                "freeze_validator_envelope_sha256": hashlib.sha256(
                    freeze["validator_raw"]
                ).hexdigest(),
            }
        )
    return {**content, "result_sha256": canonical_sha256(content)}


def _v2_closed(schema: str, code: str, reason: str) -> dict[str, Any]:
    content = {
        "schema_version": schema,
        "protocol_id": PROTOCOL_ID,
        "decision": "GOVERNANCE_V2_REJECTED",
        "fail_code": code,
        "reason": reason,
        **_v2_flags(),
    }
    return {**content, "result_sha256": canonical_sha256(content)}


def derive_governance_v2(
    *,
    genesis_envelope: bytes,
    registry_epoch_envelopes: Sequence[bytes],
    role_pop_envelopes: Mapping[str, bytes],
    evaluation_entry_envelope: bytes,
    pinned_offline_root_public_key: bytes,
) -> dict[str, Any]:
    """Derive the prospective v2 registration without granting authority."""

    try:
        context = _v2_context(
            genesis_envelope=genesis_envelope,
            registry_epoch_envelopes=registry_epoch_envelopes,
            role_pop_envelopes=role_pop_envelopes,
            evaluation_entry_envelope=evaluation_entry_envelope,
            pinned_offline_root_public_key=pinned_offline_root_public_key,
        )
        return _v2_receipt(context, verified=False)
    except (
        GovernanceValidationError,
        exact_gate_v2.ExactGateV2Error,
        CanonicalJSONError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        return _v2_closed(
            GOVERNANCE_V2_DERIVED_SCHEMA,
            getattr(exc, "code", "GOVERNANCE_V2_INTERNAL_INVALID"),
            str(exc),
        )


def _v2_freeze(
    context: dict[str, Any],
    *,
    freeze_authority_envelope: object,
    freeze_validator_envelope: object,
) -> dict[str, Any]:
    latest = context["latest"]
    entry = context["entry"]
    genesis = context["genesis"]
    authority = latest["active"]["evaluation_authority"]
    authority_payload_raw, authority_payload = _v2_signed_payload(
        freeze_authority_envelope,
        envelope_schema=GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA,
        payload_media_type=GOVERNANCE_V2_FREEZE_MEDIA_TYPE,
        public_key=authority["public_key"],
        domain=GOVERNANCE_V2_FREEZE_DOMAIN,
        fields=_V2_FREEZE_FIELDS,
        label="evaluation freeze authority",
        code="GOVERNANCE_V2_FREEZE_INVALID",
    )
    freeze_at_ns, freeze_at_text = _ns(
        authority_payload["freeze_at_ns"],
        "evaluation freeze_at_ns",
        "GOVERNANCE_V2_FREEZE_INVALID",
    )
    authority_issued_at_ns, authority_issued_text = _ns(
        authority_payload["issued_at_ns"],
        "freeze authority issued_at_ns",
        "GOVERNANCE_V2_FREEZE_INVALID",
    )
    expected_authority = {
        "schema_version": GOVERNANCE_V2_FREEZE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": genesis["campaign_root"],
        "registry_epoch": latest["payload"]["epoch"],
        "registry_hash": latest["hash"],
        "registry_status": "ACTIVE",
        "evaluation_entry_hash": entry["hash"],
        "evaluation_id": entry["evaluation_id"],
        "evaluation_nonce": entry["evaluation_nonce"],
        "attempt": 0,
        "registered_at_ns": entry["registered_text"],
        "freeze_at_ns": freeze_at_text,
        "issued_at_ns": authority_issued_text,
        "gate_registry_root": entry["gate_registry_root"],
        "evidence_manifest_schema": exact_gate_v2.EVIDENCE_MANIFEST_SCHEMA,
        "evaluation_authority_key_id": authority["key_id"],
    }
    if authority_payload != expected_authority:
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "authority freeze does not bind the exact prospective entry")
    if not entry["issued_at_ns"] < freeze_at_ns <= authority_issued_at_ns:
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "evaluation entry was inserted retrospectively or freeze chronology is invalid")
    if not _v2_key_valid_at(authority, authority_issued_at_ns):
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "evaluation-authority key is invalid at freeze issuance")
    authority_raw = _v2_raw(
        freeze_authority_envelope,
        "freeze authority envelope",
        "GOVERNANCE_V2_FREEZE_INVALID",
    )
    validator = latest["active"]["validation_authority"]
    validator_payload_raw, validator_payload = _v2_signed_payload(
        freeze_validator_envelope,
        envelope_schema=GOVERNANCE_V2_FREEZE_VALIDATOR_ENVELOPE_SCHEMA,
        payload_media_type=GOVERNANCE_V2_FREEZE_VALIDATOR_MEDIA_TYPE,
        public_key=validator["public_key"],
        domain=GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN,
        fields=_V2_FREEZE_VALIDATOR_FIELDS,
        label="evaluation freeze validator",
        code="GOVERNANCE_V2_FREEZE_INVALID",
    )
    validator_issued_at_ns, validator_issued_text = _ns(
        validator_payload["issued_at_ns"],
        "freeze validator issued_at_ns",
        "GOVERNANCE_V2_FREEZE_INVALID",
    )
    expected_validator = {
        "schema_version": GOVERNANCE_V2_FREEZE_VALIDATOR_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": genesis["campaign_root"],
        "registry_epoch": latest["payload"]["epoch"],
        "registry_hash": latest["hash"],
        "registry_status": "ACTIVE",
        "evaluation_entry_hash": entry["hash"],
        "evaluation_id": entry["evaluation_id"],
        "evaluation_nonce": entry["evaluation_nonce"],
        "attempt": 0,
        "freeze_authority_envelope_sha256": hashlib.sha256(authority_raw).hexdigest(),
        "freeze_authority_envelope_decoded_length": len(authority_raw),
        "freeze_authority_payload_sha256": hashlib.sha256(authority_payload_raw).hexdigest(),
        "validator_key_id": validator["key_id"],
        "issued_at_ns": validator_issued_text,
    }
    if validator_payload != expected_validator:
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "validator does not countersign the exact freeze authority bytes")
    if validator_issued_at_ns < authority_issued_at_ns:
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "freeze validator predates authority issuance")
    if not _v2_key_valid_at(validator, validator_issued_at_ns):
        _fail("GOVERNANCE_V2_FREEZE_INVALID", "validator key is invalid at freeze countersignature")
    return {
        "authority_raw": authority_raw,
        "authority_payload_raw": authority_payload_raw,
        "authority_payload": authority_payload,
        "authority_issued_at_ns": authority_issued_at_ns,
        "authority_issued_text": authority_issued_text,
        "validator_raw": _v2_raw(
            freeze_validator_envelope,
            "freeze validator envelope",
            "GOVERNANCE_V2_FREEZE_INVALID",
        ),
        "validator_payload_raw": validator_payload_raw,
        "validator_payload": validator_payload,
        "validator_issued_at_ns": validator_issued_at_ns,
        "validator_issued_text": validator_issued_text,
        "freeze_at_ns": freeze_at_ns,
        "freeze_at_text": freeze_at_text,
    }


def _v2_verified_context(
    *,
    genesis_envelope: object,
    registry_epoch_envelopes: object,
    role_pop_envelopes: object,
    evaluation_entry_envelope: object,
    freeze_authority_envelope: object,
    freeze_validator_envelope: object,
    pinned_offline_root_public_key: object,
) -> dict[str, Any]:
    context = _v2_context(
        genesis_envelope=genesis_envelope,
        registry_epoch_envelopes=registry_epoch_envelopes,
        role_pop_envelopes=role_pop_envelopes,
        evaluation_entry_envelope=evaluation_entry_envelope,
        pinned_offline_root_public_key=pinned_offline_root_public_key,
    )
    context["freeze"] = _v2_freeze(
        context,
        freeze_authority_envelope=freeze_authority_envelope,
        freeze_validator_envelope=freeze_validator_envelope,
    )
    return context


def verify_governance_v2(
    *,
    genesis_envelope: bytes,
    registry_epoch_envelopes: Sequence[bytes],
    role_pop_envelopes: Mapping[str, bytes],
    evaluation_entry_envelope: bytes,
    freeze_authority_envelope: bytes,
    freeze_validator_envelope: bytes,
    pinned_offline_root_public_key: bytes,
) -> dict[str, Any]:
    """Verify the complete v2 registration/freeze chain, with zero authority."""

    try:
        context = _v2_verified_context(
            genesis_envelope=genesis_envelope,
            registry_epoch_envelopes=registry_epoch_envelopes,
            role_pop_envelopes=role_pop_envelopes,
            evaluation_entry_envelope=evaluation_entry_envelope,
            freeze_authority_envelope=freeze_authority_envelope,
            freeze_validator_envelope=freeze_validator_envelope,
            pinned_offline_root_public_key=pinned_offline_root_public_key,
        )
        return _v2_receipt(context, verified=True)
    except (
        GovernanceValidationError,
        exact_gate_v2.ExactGateV2Error,
        CanonicalJSONError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        return _v2_closed(
            GOVERNANCE_V2_VERIFIED_SCHEMA,
            getattr(exc, "code", "GOVERNANCE_V2_INTERNAL_INVALID"),
            str(exc),
        )


def _v2_failure_registry(
    raw_value: object, *, gate: Mapping[str, Any]
) -> frozenset[str]:
    raw = _v2_raw(
        raw_value,
        "failure-code registry",
        "GOVERNANCE_V2_WIRE_INVALID",
    )
    try:
        value = exact_gate_v2.strict_canonical_json(
            raw, label="failure-code registry"
        )
    except exact_gate_v2.ExactGateV2Error as exc:
        raise GovernanceValidationError(
            "GOVERNANCE_V2_WIRE_INVALID", f"failure-code registry rejected: {exc}"
        ) from exc
    registry = _exact(
        value,
        _V2_FAILURE_REGISTRY_FIELDS,
        "failure-code registry",
        "GOVERNANCE_V2_WIRE_INVALID",
    )
    if (
        registry["schema_version"] != GOVERNANCE_V2_FAILURE_REGISTRY_SCHEMA
        or registry["protocol_id"] != PROTOCOL_ID
        or registry["gate_id"] != gate["gate_id"]
    ):
        _fail("GOVERNANCE_V2_WIRE_INVALID", "failure-code registry identity mismatch")
    if hashlib.sha256(raw).hexdigest() != gate["failure_code_registry_hash"]:
        _fail("GOVERNANCE_V2_WIRE_INVALID", "failure-code registry bytes differ from the prospective entry")
    codes = registry["codes"]
    if type(codes) is not list or codes != sorted(set(codes)) or any(
        type(item) is not str or _FAILURE_CODE.fullmatch(item) is None for item in codes
    ):
        _fail("GOVERNANCE_V2_WIRE_INVALID", "failure-code registry codes are not canonical")
    return frozenset(codes)


def _v2_reject_private_artifacts(supplied_artifacts: object) -> None:
    if type(supplied_artifacts) is not list:
        _fail("GOVERNANCE_V2_WIRE_INVALID", "supplied artifacts must be a list")
    for item in supplied_artifacts:
        if type(item) is not dict or set(item) != {"artifact_id", "path", "content"}:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "supplied artifact fields are not exact")
        path = _path(item["path"], "supplied artifact path", "GOVERNANCE_V2_WIRE_INVALID")
        content = item["content"]
        try:
            raw = exact_gate_v2.decode_byte_evidence(content)
        except exact_gate_v2.ExactGateV2Error as exc:
            raise GovernanceValidationError(
                "GOVERNANCE_V2_WIRE_INVALID", f"supplied artifact rejected: {exc}"
            ) from exc
        media_type = content["media_type"]
        if "private-key" in media_type or "pkcs8" in media_type:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "private key material is not an accepted artifact kind")
        _reject_private_material(path, raw, "GOVERNANCE_V2_WIRE_INVALID")


def verify_exact_gate_v2_governance(
    *,
    genesis_envelope: bytes,
    registry_epoch_envelopes: Sequence[bytes],
    role_pop_envelopes: Mapping[str, bytes],
    evaluation_entry_envelope: bytes,
    freeze_authority_envelope: bytes,
    freeze_validator_envelope: bytes,
    exact_gate_authority_envelope: bytes,
    exact_gate_validator_envelope: bytes,
    evidence_manifest_wrapper: object,
    supplied_artifacts: object,
    transitive_dependencies: object,
    transitive_dependency_edges: object,
    failure_code_registry_raw: bytes,
    pinned_offline_root_public_key: bytes,
) -> dict[str, Any]:
    """Bind an exact-gate v2 wire pair to verified prospective governance.

    This resolves keys and frozen hashes only.  It deliberately does not run a
    gate verifier, consume caller pass booleans, or add a common allowlist entry.
    The supplied epoch sequence proves only an internally valid registry prefix;
    it cannot prove that no later revocation or compromise epoch exists.  A
    separately trusted current-tip service must pin the authoritative registry
    head before this path can be allowlisted.
    """

    try:
        context = _v2_verified_context(
            genesis_envelope=genesis_envelope,
            registry_epoch_envelopes=registry_epoch_envelopes,
            role_pop_envelopes=role_pop_envelopes,
            evaluation_entry_envelope=evaluation_entry_envelope,
            freeze_authority_envelope=freeze_authority_envelope,
            freeze_validator_envelope=freeze_validator_envelope,
            pinned_offline_root_public_key=pinned_offline_root_public_key,
        )
        latest = context["latest"]
        entry = context["entry"]
        freeze = context["freeze"]
        authority_record = latest["active"]["evaluation_authority"]
        validator_record = latest["active"]["validation_authority"]
        authority_raw = _v2_raw(
            exact_gate_authority_envelope,
            "exact-gate authority envelope",
            "GOVERNANCE_V2_WIRE_INVALID",
        )
        try:
            authority_payload_raw = exact_gate_v2.verify_signed_payload_envelope(
                authority_raw,
                expected_schema=exact_gate_v2.AUTHORITY_ENVELOPE_SCHEMA,
                expected_payload_media_type=exact_gate_v2.AUTHORITY_PAYLOAD_MEDIA_TYPE,
                public_key=authority_record["public_key"],
                domain=exact_gate_v2.AUTHORITY_DOMAIN,
            )
        except exact_gate_v2.ExactGateV2Error as exc:
            raise GovernanceValidationError(
                "GOVERNANCE_V2_WIRE_INVALID", f"exact-gate authority envelope rejected: {exc}"
            ) from exc
        gate_hint = exact_gate_v2.strict_canonical_json(
            authority_payload_raw, label="exact-gate authority payload"
        )
        if type(gate_hint) is not dict or type(gate_hint.get("gate_id")) is not str:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate authority payload has no canonical gate identity")
        gate = entry["gate_by_id"].get(gate_hint["gate_id"])
        if gate is None:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate authority names an unregistered gate")
        frozen_codes = _v2_failure_registry(failure_code_registry_raw, gate=gate)
        authority_payload = exact_gate_v2.parse_authority_payload(
            authority_payload_raw, frozen_failure_codes=frozen_codes
        )
        authority_issued_at_ns = int(authority_payload["issued_at_ns"])
        if authority_issued_at_ns < freeze["validator_issued_at_ns"] or not _v2_key_valid_at(
            authority_record, authority_issued_at_ns
        ):
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate authority key is invalid or predates the governance freeze")
        expected_authority_bindings = {
            "campaign_root": context["genesis"]["campaign_root"],
            "freeze_registry_epoch": latest["payload"]["epoch"],
            "freeze_registry_hash": latest["hash"],
            "evaluation_entry_hash": entry["hash"],
            "evaluation_id": entry["evaluation_id"],
            "evaluation_nonce": entry["evaluation_nonce"],
            "gate_id": gate["gate_id"],
            "attempt": 0,
            "frozen_spec_hash": gate["frozen_spec_hash"],
            "input_schema_hash": gate["input_schema_hash"],
            "output_schema_hash": gate["output_schema_hash"],
            "failure_code_registry_hash": gate["failure_code_registry_hash"],
            "verifier_bundle_digest": gate["verifier_module_hash"],
            "verifier_runtime_digest": gate["verifier_runtime_hash"],
        }
        for field, expected in expected_authority_bindings.items():
            if authority_payload[field] != expected:
                _fail("GOVERNANCE_V2_WIRE_INVALID", f"exact-gate authority {field} differs from prospective registration")
        dependency_ids = [row["gate_id"] for row in authority_payload["direct_dependencies"]]
        if dependency_ids != list(GOVERNANCE_V2_GATE_DEPENDENCIES[gate["gate_id"]]):
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate direct dependencies differ from registered DAG")
        registered_edges: list[dict[str, str]] = []
        pending = [gate["gate_id"]]
        visited: set[str] = set()
        while pending:
            current_gate = pending.pop()
            if current_gate in visited:
                continue
            visited.add(current_gate)
            for dependency_gate in GOVERNANCE_V2_GATE_DEPENDENCIES[current_gate]:
                registered_edges.append(
                    {
                        "gate_id": current_gate,
                        "dependency_gate_id": dependency_gate,
                    }
                )
                pending.append(dependency_gate)
        dependency_result = exact_gate_v2.validate_registered_dependency_closure(
            current_gate_id=gate["gate_id"],
            current_decision=authority_payload["decision"],
            direct_dependencies=authority_payload["direct_dependencies"],
            registered_direct_gate_ids=GOVERNANCE_V2_GATE_DEPENDENCIES[gate["gate_id"]],
            transitive_dependencies=transitive_dependencies,
            transitive_edges=transitive_dependency_edges,
            registered_transitive_edges=registered_edges,
            expected_closure_root=authority_payload["dependency_closure_root"],
        )
        if dependency_result["forced_decision"] != authority_payload["decision"]:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate decision ignores a failed registered dependency")
        _v2_reject_private_artifacts(supplied_artifacts)
        manifest_result = exact_gate_v2.validate_evidence_manifest(
            evidence_manifest_wrapper, supplied_artifacts
        )
        manifest = manifest_result["manifest"]
        for field, expected in {
            "evaluation_entry_hash": entry["hash"],
            "evaluation_id": entry["evaluation_id"],
            "evaluation_nonce": entry["evaluation_nonce"],
            "gate_id": gate["gate_id"],
            "attempt": 0,
        }.items():
            if manifest[field] != expected:
                _fail("GOVERNANCE_V2_WIRE_INVALID", f"evidence manifest {field} differs from prospective registration")
        manifest_issued_at_ns = int(manifest["issued_at_ns"])
        if not freeze["validator_issued_at_ns"] <= manifest_issued_at_ns <= authority_issued_at_ns:
            _fail("GOVERNANCE_V2_WIRE_INVALID", "evidence manifest issuance is not causally ordered")
        if (
            authority_payload["evidence_manifest_envelope_sha256"] != manifest_result["manifest_sha256"]
            or authority_payload["evidence_manifest_root"] != manifest_result["merkle_root"]
        ):
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate authority does not bind the exact evidence manifest")
        validator_raw = _v2_raw(
            exact_gate_validator_envelope,
            "exact-gate validator envelope",
            "GOVERNANCE_V2_WIRE_INVALID",
        )
        try:
            validator_payload_raw = exact_gate_v2.verify_signed_payload_envelope(
                validator_raw,
                expected_schema=exact_gate_v2.VALIDATOR_ENVELOPE_SCHEMA,
                expected_payload_media_type=exact_gate_v2.VALIDATOR_PAYLOAD_MEDIA_TYPE,
                public_key=validator_record["public_key"],
                domain=exact_gate_v2.VALIDATOR_DOMAIN,
            )
            validator_payload = exact_gate_v2.parse_validator_payload(
                validator_payload_raw
            )
            exact_gate_v2.cross_check_validator_payload(
                authority_envelope_raw=authority_raw,
                authority_payload_raw=authority_payload_raw,
                authority_payload=authority_payload,
                validator_payload=validator_payload,
            )
        except exact_gate_v2.ExactGateV2Error as exc:
            raise GovernanceValidationError(
                "GOVERNANCE_V2_WIRE_INVALID", f"exact-gate validator envelope rejected: {exc}"
            ) from exc
        validator_issued_at_ns = int(validator_payload["issued_at_ns"])
        if (
            validator_payload["validation_registry_epoch"] != latest["payload"]["epoch"]
            or validator_payload["validation_registry_hash"] != latest["hash"]
            or not _v2_key_valid_at(validator_record, validator_issued_at_ns)
        ):
            _fail("GOVERNANCE_V2_WIRE_INVALID", "exact-gate validator uses stale governance or an invalid key")
        content = {
            "schema_version": GOVERNANCE_V2_WIRE_BINDING_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_root": context["genesis"]["campaign_root"],
            "registry_epoch": latest["payload"]["epoch"],
            "registry_hash": latest["hash"],
            "evaluation_entry_hash": entry["hash"],
            "evaluation_id": entry["evaluation_id"],
            "evaluation_nonce": entry["evaluation_nonce"],
            "gate_id": gate["gate_id"],
            "attempt": 0,
            "evidence_manifest_root": manifest_result["merkle_root"],
            "artifact_count": manifest_result["artifact_count"],
            "dependency_closure_root": authority_payload["dependency_closure_root"],
            "dependency_node_count": len(dependency_result["nodes"]),
            "failure_code_registry_hash": gate["failure_code_registry_hash"],
            "authority_payload_sha256": hashlib.sha256(authority_payload_raw).hexdigest(),
            "validator_payload_sha256": hashlib.sha256(validator_payload_raw).hexdigest(),
            "decision": "EXACT_GATE_V2_GOVERNANCE_BOUND_RESEARCH_ONLY",
            **_v2_flags(),
        }
        return {**content, "result_sha256": canonical_sha256(content)}
    except (
        GovernanceValidationError,
        exact_gate_v2.ExactGateV2Error,
        CanonicalJSONError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        return _v2_closed(
            GOVERNANCE_V2_WIRE_BINDING_SCHEMA,
            getattr(exc, "code", "GOVERNANCE_V2_WIRE_INVALID"),
            str(exc),
        )


# These names match the result-receipt convention used by the other v5.1 gates.
validate_g00_trust_roots_result_receipt = verify_g00_trust_roots
validate_g01_constitution_and_code_freeze_result_receipt = verify_g01_constitution_and_code_freeze


__all__ = [
    "G00_COUNTERSIGNATURE_SCHEMA",
    "G00_DECISION",
    "G00_EVIDENCE_SCHEMA",
    "G00_FINAL_GATE_SCHEMA",
    "G00_POP_ENVELOPE_SCHEMA",
    "G00_POP_PAYLOAD_SCHEMA",
    "G00_REGISTRY_SCHEMA",
    "G00_ROOT_SCHEMA",
    "G01_CONSTITUTION_SCHEMA",
    "G01_COUNTERSIGNATURE_SCHEMA",
    "G01_DECISION",
    "G01_DEVELOPMENT_ATTESTATION_SCHEMA",
    "G01_EVIDENCE_SCHEMA",
    "G01_FINAL_GATE_SCHEMA",
    "G01_MANIFEST_SCHEMA",
    "G01_SOURCE_ARCHIVE_SCHEMA",
    "GOVERNANCE_V2_CAMPAIGN_NONCE_MEDIA_TYPE",
    "GOVERNANCE_V2_CAMPAIGN_ROOT_DOMAIN",
    "GOVERNANCE_V2_DERIVED_SCHEMA",
    "GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN",
    "GOVERNANCE_V2_EVALUATION_ENTRY_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_EVALUATION_ENTRY_MEDIA_TYPE",
    "GOVERNANCE_V2_EVALUATION_ENTRY_SCHEMA",
    "GOVERNANCE_V2_FAILURE_REGISTRY_SCHEMA",
    "GOVERNANCE_V2_FREEZE_DOMAIN",
    "GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_FREEZE_MEDIA_TYPE",
    "GOVERNANCE_V2_FREEZE_SCHEMA",
    "GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN",
    "GOVERNANCE_V2_FREEZE_VALIDATOR_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_FREEZE_VALIDATOR_MEDIA_TYPE",
    "GOVERNANCE_V2_FREEZE_VALIDATOR_SCHEMA",
    "GOVERNANCE_V2_GATE_DEPENDENCIES",
    "GOVERNANCE_V2_GATE_IDS",
    "GOVERNANCE_V2_GENESIS_DOMAIN",
    "GOVERNANCE_V2_GENESIS_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_GENESIS_MEDIA_TYPE",
    "GOVERNANCE_V2_GENESIS_PAYLOAD_SCHEMA",
    "GOVERNANCE_V2_PUBLIC_KEY_MEDIA_TYPE",
    "GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN",
    "GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE",
    "GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA",
    "GOVERNANCE_V2_REQUIRED_ROLES",
    "GOVERNANCE_V2_ROLE_POP_DOMAIN",
    "GOVERNANCE_V2_ROLE_POP_ENVELOPE_SCHEMA",
    "GOVERNANCE_V2_ROLE_POP_MEDIA_TYPE",
    "GOVERNANCE_V2_ROLE_POP_SCHEMA",
    "GOVERNANCE_V2_VERIFIED_SCHEMA",
    "GOVERNANCE_V2_WIRE_BINDING_SCHEMA",
    "GovernanceValidationError",
    "PROTOCOL_ID",
    "REQUIRED_ROLES",
    "derive_g00_trust_roots",
    "derive_g01_constitution_and_code_freeze",
    "derive_governance_v2",
    "governance_v2_signature_message",
    "validate_g00_trust_roots_result_receipt",
    "validate_g01_constitution_and_code_freeze_result_receipt",
    "verify_g00_trust_roots",
    "verify_g01_constitution_and_code_freeze",
    "verify_governance_v2",
    "verify_exact_gate_v2_governance",
]
