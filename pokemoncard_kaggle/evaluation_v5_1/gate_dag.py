"""Pure, zero-authority composer for the frozen v5.1 gate DAG.

The composer is deliberately a small boundary verifier.  It consumes signed
v5.1 envelopes only; it does not discover files, contact a service, execute a
program, or turn a successful research result into production authority.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from .canonical import CanonicalJSONError, canonical_sha256
from .cross_engine import (
    CrossEngineValidationError,
    validate_cross_engine_result_receipt,
)
from .envelope import EnvelopeError, verify_envelope
from .hosted_dev_custody import (
    G05_DECISION,
    ROLES as G05_ROLES,
    validate_hosted_dev_custody_result_receipt,
)
from .prospective_transfer import evaluate_prospective_transfer


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
GATE_AUDIT_SCHEMA = "evaluation_v5_1_gate_audit_v1"
RESULT_SCHEMA = "evaluation_v5_1_gate_dag_result_v1"
ZERO_HASH = "0" * 64

GATE_IDS = (
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

GATE_DEPENDENCIES = {
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

# A gate may join this allowlist only after its production verifier consumes raw
# evidence, recomputes the decision, and verifies the authority signature plus
# the independent validator countersignature.  Signed booleans and checklists
# are deliberately not validators.  Keeping this explicit makes an incomplete
# migration fail closed instead of accidentally reviving the legacy composer.
# Gate-specific evidence engines such as the G05 custody verifier may already
# recompute their own source evidence.  They do not enter this allowlist until
# their output is also wrapped in the common exact-gate schema, dual-signed, and
# dispatched by this composer.  That integration has not happened yet.
EXACT_EVIDENCE_VALIDATORS: frozenset[str] = frozenset()

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BINDING_FIELDS = frozenset(
    {
        "campaign_root_sha256",
        "cohort_root_sha256",
        "statistics_spec_sha256",
        "collector_pair_sha256",
        "blind_image_sha256",
        "validator_image_sha256",
        "immutable_results_sha256",
    }
)
_EXPECTED_FIELDS = frozenset(
    {
        "protocol_id",
        *_BINDING_FIELDS,
        "cohort",
        "identities",
        "role_keys",
        "gate_signers",
    }
)
_IDENTITY_FIELDS = frozenset(
    {
        "evaluation_authority", "registrar", "collector_a", "collector_b",
        "evidence_custodian", "trace_attestor", "validator", "development",
        "release",
    }
)
_COHORT_FIELDS = frozenset(
    {"family_ids", "archive_sha256s", "family_archives", "activation_blocks"}
)
_SIGNER_FIELDS = frozenset({"identity", "public_key"})
_ROLE_KEY_FIELDS = frozenset(
    {"identity", "public_key", "algorithm", "valid_from_utc", "valid_until_utc", "revoked"}
)
_SERIALIZED_ROLE_KEY_FIELDS = frozenset({"identity", "public_key_hex"})
_SERIALIZED_BLOB_FIELDS = frozenset(
    {"base64", "decoded_length", "sha256", "media_type"}
)
_G05_BUNDLE_FIELDS = frozenset(
    {
        "role_keys",
        "frozen_spec_envelope",
        "spec_countersignature_envelope",
        "collector_c1_envelope",
        "collector_c2_envelope",
        "evidence_bundle_envelope",
        "trace_envelopes",
        "raw_blobs_base64",
        "final_audit_authority_envelope",
        "final_audit_countersignature_envelope",
    }
)
_G05_ROLE_MAP = {
    "evaluation_authority": "evaluation_authority",
    "collector_c1": "collector_a",
    "collector_c2": "collector_b",
    "evidence_custodian": "evidence_custodian",
    "trace_attestor": "trace_attestor",
    "validation_authority": "validator",
}
_PAYLOAD_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "gate_id",
        "gate_sequence",
        "previous_gate_sha256",
        "campaign_root_sha256",
        "bindings",
        "signer_identity",
        "passed",
        "authority",
        "sealed_holdout_access",
        "submission_authorized",
        "candidate_development_authorized",
        "audit_sha256",
        "audit",
    }
)
_AUTHORITY_KEYS = frozenset(
    {
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access",
        "sealed_holdout_access_authorized",
        "holdout_access",
        "holdout_accessed",
        "submission_authorized",
        "production_submission_authorized",
    }
)

# These labels make every contract gate explicit.  A signed audit must state
# every one of its gate-local checks and set them all true before it can pass.
_REQUIRED_CHECKS = {
    GATE_IDS[0]: ("trust_roots_pinned", "authority_matrix_frozen", "crypto_runtime_pinned"),
    GATE_IDS[1]: ("constitution_frozen", "code_frozen", "schemas_frozen", "no_submit_conditions_frozen"),
    GATE_IDS[2]: ("event_vocabulary_exact", "source_build_pinned", "wrapper_pinned"),
    GATE_IDS[3]: ("natural_starts_only", "trace_chain_complete", "feature_registry_frozen", "forbidden_actions_rejected"),
    GATE_IDS[4]: ("canaries_frozen", "metric_manifest_frozen", "independent_seed_streams_verified", "simultaneous_contract_passed"),
    GATE_IDS[5]: ("dual_capture_complete", "hosted_rows_derived", "trace_bindings_complete", "retired_comparators_complete", "dev_lineage_support_sufficient"),
    GATE_IDS[6]: ("independent_hosts_match", "out_of_fold_transcripts_complete", "selection_is_deterministic"),
    GATE_IDS[7]: ("claim_frozen", "statistics_spec_frozen", "validator_frozen", "no_interim_rule_frozen"),
    GATE_IDS[8]: ("frame_closed", "ancestry_complete", "random_selection_replayed", "cohort_exact"),
    GATE_IDS[9]: ("archive_hashes_pre_registered", "identity_mapping_blind", "no_replacement"),
    GATE_IDS[10]: ("two_collectors_complete", "three_closes_append_only", "first48_order_frozen"),
    GATE_IDS[11]: ("one_shot", "network_disabled", "non_collocated_custody", "statistics_pass"),
    GATE_IDS[12]: ("evaluator_unseal_after_g11",),
    GATE_IDS[13]: ("mutation_protocol_frozen", "hidden_selection_frozen"),
    GATE_IDS[14]: ("robustness_complete", "runtime_complete", "holdout_gate_complete"),
    GATE_IDS[15]: ("release_custody_complete", "adversarial_review_complete"),
}


class GateDAGError(ValueError):
    """A malformed v5.1 gate DAG input."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise GateDAGError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise GateDAGError(f"{label} must be a non-empty trimmed string")
    return value


def _public_key(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise GateDAGError(f"{label} must be a raw 32-byte Ed25519 public key")
    return value


def _utc(value: object, label: str) -> datetime:
    if type(value) is not str or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None:
        raise GateDAGError(f"{label} must be canonical whole-second RFC3339 UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise GateDAGError(f"{label} must be a real UTC timestamp") from exc


def _exact_mapping(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise GateDAGError(f"{label} fields are not exact")
    return value


def _authority_claim(value: object, *, path: str = "$") -> None:
    """Reject true capability claims anywhere in an untrusted audit mapping."""

    if type(value) is dict:
        for key, child in value.items():
            if key in _AUTHORITY_KEYS and child is not False:
                raise GateDAGError(f"{path}.{key} claims authority")
            boolean_capability_claim = (
                type(child) is bool
                and child
                and (
                    key.endswith("authority")
                    or "authorized" in key
                    or key.endswith("submission")
                    or ("holdout" in key and ("access" in key or "accessed" in key))
                )
            )
            if boolean_capability_claim:
                raise GateDAGError(f"{path}.{key} claims authority")
            _authority_claim(child, path=f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _authority_claim(child, path=f"{path}[{index}]")


def _validate_expected(expected: object) -> dict[str, Any]:
    value = _exact_mapping(expected, _EXPECTED_FIELDS, "expected bindings")
    if value["protocol_id"] != PROTOCOL_ID:
        raise GateDAGError("expected protocol does not equal MCI_FAMILY_TRANSFER_V2")
    for field in _BINDING_FIELDS:
        _hash(value[field], f"expected {field}")

    identities = _exact_mapping(value["identities"], _IDENTITY_FIELDS, "expected identities")
    for identity in identities.values():
        _text(identity, "expected identity")
    if len(set(identities.values())) != len(identities):
        raise GateDAGError("all frozen governance and evidence identities must be distinct")

    role_keys = _exact_mapping(value["role_keys"], _IDENTITY_FIELDS, "expected role keys")
    seen_role_keys: set[bytes] = set()
    for role in _IDENTITY_FIELDS:
        key_record = _exact_mapping(role_keys[role], _ROLE_KEY_FIELDS, f"role key for {role}")
        if key_record["identity"] != identities[role]:
            raise GateDAGError(f"role key identity mismatch for {role}")
        if key_record["algorithm"] != "Ed25519" or key_record["revoked"] is not False:
            raise GateDAGError(f"role key for {role} is not an active frozen Ed25519 key")
        if _utc(key_record["valid_from_utc"], f"role key {role} validity start") >= _utc(
            key_record["valid_until_utc"], f"role key {role} validity end"
        ):
            raise GateDAGError(f"role key for {role} has an invalid validity interval")
        public_key = _public_key(key_record["public_key"], f"role key for {role}")
        if public_key in seen_role_keys:
            raise GateDAGError("all frozen governance and evidence role keys must be distinct")
        seen_role_keys.add(public_key)

    cohort = _exact_mapping(value["cohort"], _COHORT_FIELDS, "expected cohort")
    family_ids = cohort["family_ids"]
    archives = cohort["archive_sha256s"]
    family_archives = cohort["family_archives"]
    blocks = cohort["activation_blocks"]
    if (
        type(family_ids) is not list
        or type(archives) is not list
        or type(family_archives) is not list
        or type(blocks) is not list
        or len(family_ids) != 20
        or len(archives) != 20
        or len(family_archives) != 20
        or len(blocks) != 4
    ):
        raise GateDAGError("expected cohort must contain exactly 20 families, archives, and four blocks")
    if len(set(family_ids)) != 20 or any(type(item) is not str for item in family_ids):
        raise GateDAGError("expected family ids must be 20 unique strings")
    if len(set(archives)) != 20 or any(_SHA256_RE.fullmatch(item or "") is None for item in archives):
        raise GateDAGError("expected archives must be 20 unique SHA-256 values")
    expected_pairs = []
    for pair in family_archives:
        row = _exact_mapping(pair, frozenset({"family_id", "archive_sha256"}), "expected family archive")
        expected_pairs.append(row)
    if expected_pairs != [
        {"family_id": family_id, "archive_sha256": archive}
        for family_id, archive in zip(family_ids, archives)
    ]:
        raise GateDAGError("expected family/archive binding is not exact")
    for block_index, block in enumerate(blocks):
        row = _exact_mapping(block, frozenset({"block", "family_ids"}), "expected activation block")
        if row["block"] != block_index or type(row["family_ids"]) is not list or len(row["family_ids"]) != 5:
            raise GateDAGError("expected activation blocks must be four ordered blocks of five")
        if row["family_ids"] != family_ids[block_index * 5 : block_index * 5 + 5]:
            raise GateDAGError("expected activation block family order is not exact")

    signers = value["gate_signers"]
    if type(signers) is not dict or set(signers) != set(GATE_IDS):
        raise GateDAGError("expected gate signers must cover G00-G15 exactly")
    for gate_id in GATE_IDS:
        signer = _exact_mapping(signers[gate_id], _SIGNER_FIELDS, f"signer for {gate_id}")
        _text(signer["identity"], f"signer identity for {gate_id}")
        _public_key(signer["public_key"], f"signer public key for {gate_id}")
    keys_by_identity: dict[str, bytes] = {}
    for signer in signers.values():
        prior = keys_by_identity.setdefault(signer["identity"], signer["public_key"])
        if prior != signer["public_key"]:
            raise GateDAGError("one signer identity cannot use multiple frozen public keys")
    required_roles = {
        GATE_IDS[0]: "evaluation_authority",
        GATE_IDS[1]: "evaluation_authority",
        GATE_IDS[2]: "validator",
        GATE_IDS[3]: "trace_attestor",
        GATE_IDS[4]: "validator",
        GATE_IDS[5]: "validator",
        GATE_IDS[6]: "validator",
        GATE_IDS[7]: "evaluation_authority",
        GATE_IDS[8]: "registrar",
        GATE_IDS[9]: "registrar",
        GATE_IDS[10]: "evidence_custodian",
        GATE_IDS[11]: "validator",
        GATE_IDS[12]: "release",
        GATE_IDS[13]: "evaluation_authority",
        GATE_IDS[14]: "validator",
        GATE_IDS[15]: "release",
    }
    for gate_id, role in required_roles.items():
        expected_signer = {
            "identity": role_keys[role]["identity"],
            "public_key": role_keys[role]["public_key"],
        }
        if signers[gate_id] != expected_signer:
            raise GateDAGError(f"{gate_id} signer must be the frozen {role} identity")
    return value


def _validate_payload(payload: object, expected: Mapping[str, Any]) -> dict[str, Any]:
    value = _exact_mapping(payload, _PAYLOAD_FIELDS, "gate payload")
    if value["schema"] != GATE_AUDIT_SCHEMA or value["protocol_id"] != PROTOCOL_ID:
        raise GateDAGError("gate payload schema or protocol mismatch")
    gate_id = value["gate_id"]
    if gate_id not in GATE_IDS:
        raise GateDAGError("unknown gate id")
    index = GATE_IDS.index(gate_id)
    if value["gate_sequence"] != index:
        raise GateDAGError(f"{gate_id} has an invalid sequence")
    previous = value["previous_gate_sha256"]
    _hash(previous, f"{gate_id}.previous_gate_sha256")
    if index == 0 and previous != ZERO_HASH:
        raise GateDAGError("G00 must have the zero predecessor hash")
    if value["campaign_root_sha256"] != expected["campaign_root_sha256"]:
        raise GateDAGError(f"{gate_id} campaign root mismatch")
    bindings = _exact_mapping(value["bindings"], _BINDING_FIELDS, f"{gate_id}.bindings")
    for field in _BINDING_FIELDS:
        if bindings[field] != expected[field]:
            raise GateDAGError(f"{gate_id} {field} mismatch")
    if value["signer_identity"] != expected["gate_signers"][gate_id]["identity"]:
        raise GateDAGError(f"{gate_id} signer identity mismatch")
    for field in (
        "passed",
        "authority",
        "sealed_holdout_access",
        "submission_authorized",
        "candidate_development_authorized",
    ):
        if type(value[field]) is not bool:
            raise GateDAGError(f"{gate_id}.{field} must be boolean")
    if value["authority"] or value["sealed_holdout_access"] or value["submission_authorized"] or value["candidate_development_authorized"]:
        raise GateDAGError(f"{gate_id} claims authority")
    audit = value["audit"]
    if type(audit) is not dict:
        raise GateDAGError(f"{gate_id}.audit must be a mapping")
    _authority_claim(audit, path=f"{gate_id}.audit")
    if value["audit_sha256"] != canonical_sha256(audit):
        raise GateDAGError(f"{gate_id} audit hash mismatch")
    checks = audit.get("checks")
    if type(checks) is not dict or set(checks) != set(_REQUIRED_CHECKS[gate_id]):
        raise GateDAGError(f"{gate_id} checks are not the frozen exact set")
    if any(check is not True for check in checks.values()):
        raise GateDAGError(f"{gate_id} contains a failed check")
    return value


def _result(
    *,
    decision: str,
    reasons: list[str],
    gate_status: list[dict[str, Any]],
    expected: Mapping[str, Any] | None,
    transfer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "decision": decision,
        "reasons": reasons,
        "gate_ids": list(GATE_IDS),
        "gates": gate_status,
        "bindings": {
            field: expected[field] for field in _BINDING_FIELDS
        } if expected is not None else None,
        "transfer": dict(transfer) if transfer is not None else None,
        "authority": False,
        "sealed_holdout_access": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "candidate_development_authorized": False,
    }
    return {**body, "result_sha256": canonical_sha256(body)}


def canonical_result_hash(result: Mapping[str, Any]) -> str:
    """Return the canonical hash of a composed result body.

    The self-hash field is excluded, so the function is also useful for
    independently checking a serialized result receipt.
    """

    if type(result) is not dict:
        raise GateDAGError("result must be a plain mapping")
    body = dict(result)
    body.pop("result_sha256", None)
    return canonical_sha256(body)


def _empty_status(gate_id: str, reason: str) -> dict[str, Any]:
    return {"gate_id": gate_id, "sequence": GATE_IDS.index(gate_id), "present": False, "passed": False, "reasons": [reason]}


def _validate_g08(audit: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if audit.get("cohort") != expected["cohort"]:
        raise GateDAGError("G08 cohort is not the exact expected 20-family roster")
    if audit.get("cohort_root_sha256") != expected["cohort_root_sha256"]:
        raise GateDAGError("G08 cohort root mismatch")


def _validate_g04(audit: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    required = {"checks", "panel", "panel_sha256", "result", "result_sha256"}
    if set(audit) != required:
        raise GateDAGError("G04 audit fields are not exact")
    if audit["panel_sha256"] != canonical_sha256(audit["panel"]):
        raise GateDAGError("G04 panel hash mismatch")
    if audit["result_sha256"] != canonical_sha256(audit["result"]):
        raise GateDAGError("G04 result hash mismatch")
    try:
        checked = validate_cross_engine_result_receipt(audit["panel"], audit["result"])
    except CrossEngineValidationError as exc:
        raise GateDAGError(f"G04 exact contract failed: {exc}") from exc
    if checked["campaign_root_sha256"] != expected["campaign_root_sha256"]:
        raise GateDAGError("G04 campaign root mismatch")


def _canonical_base64(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise GateDAGError(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GateDAGError(f"{label} must be canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise GateDAGError(f"{label} must be canonical base64")
    return decoded


def encode_g05_custody_input_bundle(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """Encode the byte-bearing G05 verifier inputs as canonical JSON evidence."""

    if not isinstance(inputs, Mapping):
        raise GateDAGError("G05 custody inputs must be a mapping")
    expected_fields = (_G05_BUNDLE_FIELDS - {"raw_blobs_base64"}) | {"raw_blobs"}
    if set(inputs) != set(expected_fields):
        raise GateDAGError("G05 custody input fields are not exact")
    role_keys = _exact_mapping(inputs["role_keys"], frozenset(G05_ROLES), "G05 role keys")
    serialized_roles: dict[str, dict[str, str]] = {}
    for role in G05_ROLES:
        record = _exact_mapping(role_keys[role], _SIGNER_FIELDS, f"G05 role key {role}")
        serialized_roles[role] = {
            "identity": _text(record["identity"], f"G05 role identity {role}"),
            "public_key_hex": _public_key(record["public_key"], f"G05 role key {role}").hex(),
        }
    raw_blobs = inputs["raw_blobs"]
    if not isinstance(raw_blobs, Mapping):
        raise GateDAGError("G05 raw blobs must be a mapping")
    serialized_blobs: dict[str, dict[str, object]] = {}
    for digest in sorted(raw_blobs):
        _hash(digest, "G05 raw blob hash")
        raw = raw_blobs[digest]
        if type(raw) is not bytes:
            raise GateDAGError("G05 raw blob must be bytes")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise GateDAGError("G05 raw blob hash mismatch")
        serialized_blobs[digest] = {
            "base64": base64.b64encode(raw).decode("ascii"),
            "decoded_length": len(raw),
            "sha256": digest,
            "media_type": "application/octet-stream",
        }
    encoded = {
        key: inputs[key]
        for key in _G05_BUNDLE_FIELDS
        if key not in {"role_keys", "raw_blobs_base64"}
    }
    encoded["role_keys"] = serialized_roles
    encoded["raw_blobs_base64"] = serialized_blobs
    canonical_sha256(encoded)
    return encoded


def _decode_g05_custody_input_bundle(value: object) -> dict[str, Any]:
    bundle = _exact_mapping(value, _G05_BUNDLE_FIELDS, "G05 custody input bundle")
    role_keys = _exact_mapping(bundle["role_keys"], frozenset(G05_ROLES), "serialized G05 role keys")
    decoded_roles: dict[str, dict[str, Any]] = {}
    for role in G05_ROLES:
        record = _exact_mapping(role_keys[role], _SERIALIZED_ROLE_KEY_FIELDS, f"serialized G05 role key {role}")
        public_key_hex = record["public_key_hex"]
        if type(public_key_hex) is not str or len(public_key_hex) != 64:
            raise GateDAGError(f"serialized G05 role key {role} is invalid")
        try:
            public_key = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            raise GateDAGError(f"serialized G05 role key {role} is invalid") from exc
        decoded_roles[role] = {
            "identity": _text(record["identity"], f"serialized G05 role identity {role}"),
            "public_key": _public_key(public_key, f"serialized G05 role key {role}"),
        }
    raw_values = bundle["raw_blobs_base64"]
    if type(raw_values) is not dict:
        raise GateDAGError("serialized G05 raw blobs must be a mapping")
    raw_blobs: dict[str, bytes] = {}
    for digest in sorted(raw_values):
        _hash(digest, "serialized G05 raw blob hash")
        record = _exact_mapping(
            raw_values[digest], _SERIALIZED_BLOB_FIELDS, f"serialized G05 raw blob {digest}"
        )
        if record["sha256"] != digest or record["media_type"] != "application/octet-stream":
            raise GateDAGError("serialized G05 raw blob metadata mismatch")
        raw = _canonical_base64(record["base64"], f"serialized G05 raw blob {digest}")
        if type(record["decoded_length"]) is not int or record["decoded_length"] != len(raw):
            raise GateDAGError("serialized G05 raw blob decoded length mismatch")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise GateDAGError("serialized G05 raw blob hash mismatch")
        raw_blobs[digest] = raw
    decoded = {
        key: bundle[key]
        for key in _G05_BUNDLE_FIELDS
        if key not in {"role_keys", "raw_blobs_base64"}
    }
    decoded["role_keys"] = decoded_roles
    decoded["raw_blobs"] = raw_blobs
    return decoded


def _validate_g05(audit: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "checks", "custody_input_bundle", "custody_input_bundle_sha256",
        "custody_result", "custody_result_sha256",
    }
    if set(audit) != required:
        raise GateDAGError("G05 audit fields are not exact")
    if audit["custody_input_bundle_sha256"] != canonical_sha256(audit["custody_input_bundle"]):
        raise GateDAGError("G05 custody input bundle hash mismatch")
    decoded = _decode_g05_custody_input_bundle(audit["custody_input_bundle"])
    for g05_role, expected_role in _G05_ROLE_MAP.items():
        frozen_role = expected["role_keys"][expected_role]
        expected_g05_role = {
            "identity": frozen_role["identity"],
            "public_key": frozen_role["public_key"],
        }
        if decoded["role_keys"][g05_role] != expected_g05_role:
            raise GateDAGError(f"G05 {g05_role} is not the frozen {expected_role}")
    frozen_payload = decoded["frozen_spec_envelope"].get("payload") if type(decoded["frozen_spec_envelope"]) is dict else None
    if type(frozen_payload) is not dict or frozen_payload.get("evaluation_id") != expected["campaign_root_sha256"]:
        raise GateDAGError("G05 frozen evaluation id does not bind the campaign root")
    computed = validate_hosted_dev_custody_result_receipt(
        **decoded,
        development_public_key=expected["role_keys"]["development"]["public_key"],
    )
    if audit["custody_result"] != computed or audit["custody_result_sha256"] != canonical_sha256(computed):
        raise GateDAGError("G05 custody result is not the exact recomputed result")
    if computed.get("decision") != G05_DECISION:
        raise GateDAGError("G05 exact custody verification failed")
    if computed.get("verifier_container_sha256") != expected["validator_image_sha256"]:
        raise GateDAGError("G05 verifier image does not match the frozen validator image")
    rows = computed.get("rows")
    if type(rows) is not list or len({row.get("canary_lineage_id") for row in rows if type(row) is dict}) < 15:
        raise GateDAGError("G05 has fewer than 15 complete DEV lineage components")
    return computed


def _validate_g10(audit: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    pair = _exact_mapping(audit.get("collector_pair"), frozenset({"collector_a", "collector_b", "collector_pair_sha256"}), "G10 collector pair")
    if pair["collector_a"] != expected["identities"]["collector_a"] or pair["collector_b"] != expected["identities"]["collector_b"] or pair["collector_pair_sha256"] != expected["collector_pair_sha256"]:
        raise GateDAGError("G10 collector pair mismatch")


def _validate_g11(audit: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "prospective_evidence",
        "prospective_evidence_sha256",
        "statistics_spec_sha256",
        "immutable_results_sha256",
        "prospective_result",
        "prospective_result_sha256",
    }
    if set(audit) != {"checks", *required}:
        raise GateDAGError("G11 audit fields are not exact")
    if audit["statistics_spec_sha256"] != expected["statistics_spec_sha256"] or audit["immutable_results_sha256"] != expected["immutable_results_sha256"]:
        raise GateDAGError("G11 statistics or immutable-results binding mismatch")
    if audit["prospective_evidence_sha256"] != canonical_sha256(audit["prospective_evidence"]):
        raise GateDAGError("G11 prospective-evidence hash mismatch")
    if audit["immutable_results_sha256"] != canonical_sha256(audit["prospective_evidence"]):
        raise GateDAGError("G11 immutable results are not the exact prospective panel")
    computed = evaluate_prospective_transfer(audit["prospective_evidence"])
    if audit["prospective_result"] != computed or audit["prospective_result_sha256"] != canonical_sha256(computed):
        raise GateDAGError("G11 prospective result is not the frozen derived result")
    if computed["decision"] != "PROSPECTIVE_SELECTOR_VALIDATED_RESEARCH_ONLY":
        raise GateDAGError("G11 exact transfer criteria failed")
    return computed


def compose_gate_dag(
    gate_audits: Sequence[object],
    *,
    expected_bindings: Mapping[str, Any],
) -> dict[str, Any]:
    """Compose the signed G00-G15 chain without granting any authority."""

    statuses = [_empty_status(gate_id, "gate_not_processed") for gate_id in GATE_IDS]
    expected: dict[str, Any] | None = None
    try:
        expected = _validate_expected(expected_bindings)
        missing_exact_validators = [
            gate_id for gate_id in GATE_IDS if gate_id not in EXACT_EVIDENCE_VALIDATORS
        ]
        if missing_exact_validators:
            raise GateDAGError(
                "FAIL_UNVERIFIED_EVIDENCE: exact validator modules missing for "
                + ",".join(missing_exact_validators)
            )
        if type(gate_audits) not in {list, tuple} or len(gate_audits) != len(GATE_IDS):
            raise GateDAGError("exactly one signed audit is required for each G00-G15 gate")
        payloads: list[dict[str, Any]] = []
        payload_hashes: list[str] = []
        seen: set[str] = set()
        for position, envelope in enumerate(gate_audits):
            if type(envelope) is not dict or type(envelope.get("payload")) is not dict:
                raise GateDAGError("gate audits must be signed v5.1 envelopes")
            gate_id = envelope["payload"].get("gate_id")
            if gate_id not in GATE_IDS:
                raise GateDAGError("unknown gate or missing gate id")
            if gate_id in seen:
                raise GateDAGError(f"duplicate gate {gate_id}")
            seen.add(gate_id)
            if gate_id != GATE_IDS[position]:
                raise GateDAGError("gate sequence is reordered")
            signer = expected["gate_signers"][gate_id]
            payload = verify_envelope(
                envelope,
                expected_artifact_schema=GATE_AUDIT_SCHEMA,
                pinned_public_key_bytes=signer["public_key"],
            )
            checked = _validate_payload(payload, expected)
            payloads.append(checked)
            payload_hashes.append(canonical_sha256(checked))
            statuses[position] = {
                "gate_id": gate_id,
                "sequence": position,
                "present": True,
                "passed": bool(checked["passed"]),
                "signer_identity": checked["signer_identity"],
                "audit_sha256": checked["audit_sha256"],
                "reasons": [],
            }
        for index, payload in enumerate(payloads):
            expected_previous = ZERO_HASH if index == 0 else payload_hashes[index - 1]
            if payload["previous_gate_sha256"] != expected_previous:
                raise GateDAGError(f"{payload['gate_id']} predecessor hash mismatch")
            if not payload["passed"]:
                raise GateDAGError(f"{payload['gate_id']} audit failed")
            if index and not payloads[index - 1]["passed"]:
                raise GateDAGError(f"{payload['gate_id']} bypasses a failed dependency")
        _validate_g04(payloads[4]["audit"], expected)
        _validate_g05(payloads[5]["audit"], expected)
        _validate_g08(payloads[8]["audit"], expected)
        _validate_g10(payloads[10]["audit"], expected)
        transfer = _validate_g11(payloads[11]["audit"], expected)
        if payloads[11]["passed"] is not True:
            raise GateDAGError("G11 passed flag is not true for the derived transfer result")
        statuses[11]["decision"] = "EVALUATOR_VALIDATED_RESEARCH_ONLY"
        for index in range(12, 16):
            if payloads[index]["audit"].get("after_g11") is not True:
                raise GateDAGError(f"{payloads[index]['gate_id']} is not explicitly downstream of G11")
        transfer_receipt = {
            "decision": "EVALUATOR_VALIDATED_RESEARCH_ONLY",
            "statistics_decision": transfer["decision"],
            "statistics_result": transfer,
            "statistics_result_sha256": canonical_sha256(transfer),
            "authority": False,
            "sealed_holdout_access": False,
            "submission_authorized": False,
        }
        return _result(
            decision="RELEASE_CUSTODY_VERIFIED_RESEARCH_ONLY",
            reasons=[],
            gate_status=statuses,
            expected=expected,
            transfer=transfer_receipt,
        )
    except (GateDAGError, EnvelopeError, CanonicalJSONError, CrossEngineValidationError, KeyError, TypeError, ValueError) as exc:
        reason = str(exc) or "invalid_gate_dag"
        return _result(
            decision="FAIL_CLOSED",
            reasons=[reason],
            gate_status=statuses,
            expected=expected,
        )


__all__ = [
    "GATE_AUDIT_SCHEMA",
    "GATE_DEPENDENCIES",
    "GATE_IDS",
    "EXACT_EVIDENCE_VALIDATORS",
    "GateDAGError",
    "PROTOCOL_ID",
    "RESULT_SCHEMA",
    "canonical_result_hash",
    "compose_gate_dag",
    "encode_g05_custody_input_bundle",
]
