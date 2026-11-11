"""Research-only G12/G13 production-candidate contract.

This module is intentionally a verifier, never a capability service.  It can
validate signed, exact-byte claims about evaluator readiness and DEV selection,
but cannot decrypt, invoke, release, mutate a replay slot, create a candidate,
or authorize a holdout/release/submission.  The production valid-only service
key registry is deliberately empty, so locally supplied evidence is always
blocked before either state machine can reach a ready/selected state.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from functools import cmp_to_key
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json_bytes, canonical_sha256
from .exact_gate_v2 import (
    DEPENDENCY_FAILURE_CODE,
    FAIL_DECISION,
    PASS_DECISION,
    ExactGateV2Error,
    decode_byte_evidence,
    strict_canonical_json,
    validate_ed25519_public_key,
    validate_ed25519_signature_encoding,
    validate_registered_dependency_closure,
    verify_exact_gate_v2,
)


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
G12_GATE_ID = "G12_EVALUATOR_UNSEAL"
G13_GATE_ID = "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION"
G12_INPUT_SCHEMA = "ptcg.g12.evaluator-readiness-input/v1"
G13_INPUT_SCHEMA = "ptcg.g13.dev-candidate-freeze-input/v1"
ROLE_KEY_SCHEMA = "ptcg.production-candidate.role-key/v1"
G12_RELEASE_SCHEMA = "ptcg.g12.custodian-release/v1"
G13_DEPOSIT_SCHEMA = "ptcg.g13.archive-deposit/v1"
G12_SIGNED_MEDIA_TYPE = "application/vnd.ptcg.g12-signed-payload+json"
G13_SIGNED_MEDIA_TYPE = "application/vnd.ptcg.g13-signed-payload+json"
ED25519_MEDIA_TYPE = "application/vnd.ptcg.ed25519-public-key"
G12_DOMAIN = b"PTCG/PRODUCTION_CANDIDATE/G12/CUSTODIAN_RELEASE/v1\0"
G13_DOMAIN = b"PTCG/PRODUCTION_CANDIDATE/G13/ARCHIVE_DEPOSIT/v1\0"

EVALUATOR_SEALED = "EVALUATOR_SEALED"
EVALUATOR_UNSEALING = "EVALUATOR_UNSEALING"
EVALUATOR_READY_LOCKED = "EVALUATOR_READY_LOCKED"
EVALUATOR_BURNED = "EVALUATOR_BURNED"
DEV_MUTABLE = "DEV_MUTABLE"
CANDIDATE_FREEZE_PENDING = "CANDIDATE_FREEZE_PENDING"
CANDIDATE_SELECTED_LOCKED = "CANDIDATE_SELECTED_LOCKED"
CANDIDATE_FREEZE_BURNED = "CANDIDATE_FREEZE_BURNED"

# There is intentionally no local trust anchor. Adding one is a separately
# reviewed production change, not a runtime option or an allowlist edit.
TRUSTED_VALID_ONLY_SERVICE_KEYS: Mapping[str, bytes] = MappingProxyType({})

G12_FAILURE_CODES = frozenset(
    {
        DEPENDENCY_FAILURE_CODE,
        "G12_INVALID_EVIDENCE",
        "G12_G11_BINDING_MISMATCH",
        "G12_G11_BUNDLE_INVALID",
        "G12_REGISTRATION_MISMATCH",
        "G12_CIPHERTEXT_MISMATCH",
        "G12_PROVENANCE_INVALID",
        "G12_ROLE_SEPARATION",
        "G12_CUSTODY_QUORUM_INVALID",
        "G12_UNSEAL_TRANSCRIPT_INVALID",
        "G12_DECRYPTION_OR_MANIFEST_INVALID",
        "G12_DIGEST_MISMATCH",
        "G12_RUNNER_MEASUREMENT_MISMATCH",
        "G12_PREMATURE_INVOCATION",
        "G12_FORBIDDEN_ACCESS_OR_EGRESS",
        "G12_INVALID_STATE",
        "G12_FREEZE_CONFLICT",
        "G12_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE",
    }
)
G13_FAILURE_CODES = frozenset(
    {
        DEPENDENCY_FAILURE_CODE,
        "G13_INVALID_EVIDENCE",
        "G13_G05_BINDING_MISMATCH",
        "G13_G12_BINDING_MISMATCH",
        "G13_UNVERIFIED_DEV",
        "G13_FREEZE_MISMATCH",
        "G13_UNIVERSE_MISMATCH",
        "G13_MUTATION_OR_BUILD_MISMATCH",
        "G13_DUPLICATE_CANDIDATE_OR_ARCHIVE",
        "G13_FORBIDDEN_INPUT_OR_ACCESS",
        "G13_EVALUATOR_HOLDOUT_LEAKAGE",
        "G13_STATISTICS_INCOMPLETE",
        "G13_RANKING_OR_TIEBREAK_MISMATCH",
        "G13_NONDETERMINISM",
        "G13_MANUAL_OVERRIDE",
        "G13_SELECTION_MISMATCH",
        "G13_CUSTODY_MISMATCH",
        "G13_FREEZE_CONFLICT",
        "G13_INVALID_STATE",
        "G13_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_METRIC = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SIGNED_FIELDS = frozenset(
    {"schema_version", "signer_key_id", "payload", "signature_ed25519_base64"}
)
_ROLE_KEY_FIELDS = frozenset(
    {"schema_version", "role", "principal_id", "custodian_id", "public_key"}
)
_G12_FIELDS = frozenset(
    {
        "schema_version", "protocol_id", "campaign_root", "evaluation_id",
        "evaluation_nonce", "gate_id", "attempt", "registered_dependency_gate_ids",
        "direct_dependencies", "transitive_dependencies", "transitive_edges",
        "registered_transitive_edges", "dependency_closure_root", "g11_bundle",
        "registration", "evaluator_ciphertext", "publisher_provenance",
        "role_keys", "custodian_releases", "runner_evidence", "access_audit",
        "transition", "freeze_replay", "input_bundle_root",
    }
)
_G13_FIELDS = frozenset(
    {
        "schema_version", "protocol_id", "campaign_root", "evaluation_id",
        "evaluation_nonce", "gate_id", "attempt", "registered_dependency_gate_ids",
        "direct_dependencies", "transitive_dependencies", "transitive_edges",
        "registered_transitive_edges", "dependency_closure_root", "registration",
        "role_keys", "mutation_universe", "candidates", "selection_spec",
        "selection_transcript", "custody_deposits", "access_audit", "transition",
        "freeze_replay", "input_bundle_root",
    }
)
_G12_REGISTRATION_FIELDS = frozenset(
    {
        "g11_bundle_sha256", "g11_authority_payload_sha256",
        "evaluator_ciphertext_sha256", "expected_plaintext_manifest_root",
        "publisher_provenance_root", "runner_measurement_sha256",
        "g12_runner_key_id",
    }
)
_PROVENANCE_FIELDS = frozenset(
    {"publisher_id", "capture_sha256s", "provenance_root", "official_publisher_evidence"}
)
_RUNNER_FIELDS = frozenset(
    {
        "runner_key_id", "measurement_sha256", "runtime_sha256", "registered_evaluator_sha256",
        "interface_loaded", "evaluator_invocations", "plaintext_exports",
    }
)
_ACCESS_FIELDS = frozenset(
    {
        "candidate_reads", "holdout_reads", "evaluator_calls", "plaintext_exports",
        "network_egress", "mutable_mounts", "downloads", "symlink_or_aliases",
    }
)
_G12_TRANSITION_FIELDS = frozenset(
    {"from_state", "to_state", "unseal_started", "replay_key", "history_root"}
)
_G13_REGISTRATION_FIELDS = frozenset(
    {
        "g05_bundle_sha256", "g12_bundle_sha256", "dev_root_sha256",
        "mutation_universe_root", "selection_spec_sha256", "max_candidate_count",
    }
)
_UNIVERSE_FIELDS = frozenset(
    {"schema_version", "base_source_sha256", "base_model_sha256", "mutation_program_sha256",
     "mutation_config_sha256", "budget", "seed_sha256s", "forbidden_input_classes",
     "universe_root"}
)
_CANDIDATE_FIELDS = frozenset(
    {"candidate_id", "source_sha256", "model_sha256", "config_sha256", "build_recipe_sha256",
     "dependency_lock_sha256", "archive", "dev_bundle_sha256", "build_log_sha256",
     "statistics", "lineage_root"}
)
_STATISTICS_FIELDS = frozenset({"schema_version", "metrics", "statistics_root"})
_METRIC_FIELDS = frozenset(
    {"metric", "numerator", "denominator", "excluded", "intermediate_root"}
)
_SELECTION_SPEC_FIELDS = frozenset(
    {"schema_version", "metric_order", "tie_break", "max_candidate_count"}
)
_SELECTION_METRIC_FIELDS = frozenset({"metric", "direction"})
_TRANSCRIPT_FIELDS = frozenset(
    {"ranked_candidate_ids", "selected_candidate_id", "selected_archive_sha256",
     "selected_archive_length", "selection_root", "manual_override"}
)
_G13_TRANSITION_FIELDS = frozenset(
    {"from_state", "to_state", "freeze_started", "replay_key", "history_root"}
)
_DEPOSIT_FIELDS = frozenset(
    {"schema_version", "campaign_root", "evaluation_id", "evaluation_nonce", "archive_sha256",
     "archive_length", "selection_root", "custodian_role", "custodian_id"}
)


class ProductionCandidateError(ValueError):
    """A G12/G13 contract invariant did not validate."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def _fail(code: str, message: str = "") -> None:
    raise ProductionCandidateError(code, message)


def _exact(value: object, fields: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(code, "fields are not exact")
    return value


def _sha(value: object, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code, "SHA-256 is not lowercase hex")
    return value


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(code, "identifier is not canonical")
    return value


def _u64(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        _fail(code, "value is not a uint64")
    return value


def _hash_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    for field in fields:
        _sha(value[field], code)


def _raw(wrapper: object, *, code: str, media_type: str | None = None) -> bytes:
    try:
        return decode_byte_evidence(wrapper, expected_media_type=media_type)
    except ExactGateV2Error as exc:
        _fail(code, str(exc))


def _signed_payload(
    value: object,
    *,
    expected_schema: str,
    expected_media_type: str,
    public_key: bytes,
    domain: bytes,
    code: str,
) -> dict[str, Any]:
    envelope = _exact(value, _SIGNED_FIELDS, code)
    if envelope["schema_version"] != expected_schema:
        _fail(code, "signed schema mismatch")
    try:
        key_id = validate_ed25519_public_key(public_key)
    except ExactGateV2Error as exc:
        _fail(code, str(exc))
    if envelope["signer_key_id"] != key_id:
        _fail(code, "derived signer key ID mismatch")
    raw = _raw(envelope["payload"], code=code, media_type=expected_media_type)
    try:
        payload = strict_canonical_json(raw, label="production-candidate signed payload")
    except ExactGateV2Error as exc:
        _fail(code, str(exc))
    encoded = envelope["signature_ed25519_base64"]
    if type(encoded) is not str:
        _fail(code, "signature is not canonical base64")
    try:
        signature = base64.b64decode(encoded, validate=True)
        if base64.b64encode(signature).decode("ascii") != encoded:
            _fail(code, "signature base64 is noncanonical")
        validate_ed25519_signature_encoding(signature)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, domain + len(raw).to_bytes(8, "big") + raw
        )
    except (binascii.Error, ExactGateV2Error, InvalidSignature, ValueError) as exc:
        _fail(code, f"signature verification failed: {exc}")
    if type(payload) is not dict:
        _fail(code, "signed payload must be an object")
    return payload


def _role_keys(value: object, *, required_roles: Sequence[str], code: str) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) != len(required_roles):
        _fail(code, "role key count is not exact")
    records: dict[str, dict[str, Any]] = {}
    principals: set[str] = set()
    custodians: set[str] = set()
    key_ids: set[str] = set()
    for item in value:
        row = _exact(item, _ROLE_KEY_FIELDS, code)
        if row["schema_version"] != ROLE_KEY_SCHEMA:
            _fail(code, "role-key schema mismatch")
        role = _identifier(row["role"], code)
        principal = _identifier(row["principal_id"], code)
        custodian = _identifier(row["custodian_id"], code)
        raw = _raw(row["public_key"], code=code, media_type=ED25519_MEDIA_TYPE)
        try:
            key_id = validate_ed25519_public_key(raw)
        except ExactGateV2Error as exc:
            _fail(code, str(exc))
        if role in records or principal in principals or custodian in custodians or key_id in key_ids:
            _fail(code, "roles, principals, custodians, and keys must be distinct")
        records[role] = {"principal_id": principal, "custodian_id": custodian, "public_key": raw, "key_id": key_id}
        principals.add(principal)
        custodians.add(custodian)
        key_ids.add(key_id)
    if tuple(sorted(records)) != tuple(sorted(required_roles)):
        _fail(code, "role set is not frozen")
    return records


def _dependencies(
    evidence: Mapping[str, Any], *, gate_id: str, registered: Sequence[str], code: str
) -> dict[str, Any]:
    if evidence.get("registered_dependency_gate_ids") != list(registered):
        _fail(code, "caller dependency registration differs from frozen DAG")
    try:
        result = validate_registered_dependency_closure(
            current_gate_id=gate_id,
            current_decision=PASS_DECISION,
            direct_dependencies=evidence["direct_dependencies"],
            registered_direct_gate_ids=registered,
            transitive_dependencies=evidence["transitive_dependencies"],
            transitive_edges=evidence["transitive_edges"],
            registered_transitive_edges=evidence["registered_transitive_edges"],
            expected_closure_root=evidence["dependency_closure_root"],
        )
    except (ExactGateV2Error, KeyError) as exc:
        _fail(code, str(exc))
    return result


def _validate_g11_bundle(
    wrapper: object, expected_sha: str, expected_authority_payload_sha: str
) -> None:
    raw = _raw(wrapper, code="G12_G11_BUNDLE_INVALID", media_type="application/vnd.ptcg.exact-gate-final-bundle+json")
    if hashlib.sha256(raw).hexdigest() != _sha(expected_sha, "G12_G11_BUNDLE_INVALID"):
        _fail("G12_G11_BINDING_MISMATCH", "G11 final bundle hash mismatch")
    try:
        bundle = strict_canonical_json(raw, label="G11 final bundle")
        bundle = _exact(
            bundle,
            frozenset({"schema_version", "authority_envelope", "validator_envelope"}),
            "G12_G11_BUNDLE_INVALID",
        )
        if bundle["schema_version"] != "ptcg.exact_gate.bundle/v2":
            _fail("G12_G11_BUNDLE_INVALID", "G11 final bundle schema mismatch")
        authority_raw = _raw(
            bundle["authority_envelope"],
            code="G12_G11_BUNDLE_INVALID",
            media_type="application/vnd.ptcg.exact-gate-authority+json",
        )
        authority = _exact(
            strict_canonical_json(authority_raw, label="G11 authority envelope"),
            _SIGNED_FIELDS,
            "G12_G11_BUNDLE_INVALID",
        )
        authority_payload = _raw(
            authority["payload"],
            code="G12_G11_BUNDLE_INVALID",
            media_type="application/vnd.ptcg.exact-gate-authority-payload+json",
        )
        if hashlib.sha256(authority_payload).hexdigest() != _sha(
            expected_authority_payload_sha, "G12_G11_BINDING_MISMATCH"
        ):
            _fail("G12_G11_BINDING_MISMATCH", "G11 authority payload hash mismatch")
        # This uses exact_gate_v2's hermetic verifier; a local rejected result is
        # never treated as a dependency pass.
        verdict = verify_exact_gate_v2(gate_id="G11_ONE_SHOT_TRANSFER_VALIDATION", final_bundle=bundle)
    except ExactGateV2Error as exc:
        _fail("G12_G11_BUNDLE_INVALID", str(exc))
    if verdict["bundle_sha256"] != expected_sha:
        _fail("G12_G11_BINDING_MISMATCH", "G11 verifier changed byte identity")
    if verdict["decision"] == PASS_DECISION:
        return
    if verdict.get("failure_codes") != ["VERIFIER_NOT_ALLOWLISTED"]:
        _fail("G12_G11_BUNDLE_INVALID", "G11 bundle is not structurally valid")


def _result(
    *, gate_id: str, structural_valid: bool, failure_codes: Sequence[str], state: str,
    input_bundle_root: str, dependency_result: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    codes = sorted(set(failure_codes))
    return {
        "protocol_id": PROTOCOL_ID,
        "gate_id": gate_id,
        "decision": FAIL_DECISION if codes else PASS_DECISION,
        "structural_validation_complete": structural_valid,
        "failure_codes": codes,
        "state": state,
        "input_bundle_root": input_bundle_root,
        "dependency_bundle_hashes": [] if dependency_result is None else [
            row["bundle_sha256"] for row in dependency_result["nodes"]
        ],
        "candidate_development_authorized": False,
        "evaluator_unseal_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def _transition_started(
    transition: Mapping[str, Any] | None, field: str
) -> bool:
    """Treat every claimed transition except exact false as already started."""

    return transition is not None and transition.get(field) is not False


def validate_g12_synthetic_structure(evidence: object) -> dict[str, Any]:
    """Validate synthetic G12 shape without authenticating its G11 dependency."""

    root = hashlib.sha256(b"").hexdigest()
    # Preserve an already-claimed irreversible start even when an earlier
    # evidence field is malformed; accepting a pre-transition retry would be
    # less safe than burning the claimed slot.
    claimed_transition = evidence.get("transition") if type(evidence) is dict else None
    transition: Mapping[str, Any] | None = (
        claimed_transition if type(claimed_transition) is dict else None
    )
    dependency: dict[str, Any] | None = None
    try:
        item = _exact(evidence, _G12_FIELDS, "G12_INVALID_EVIDENCE")
        if item["schema_version"] != G12_INPUT_SCHEMA or item["protocol_id"] != PROTOCOL_ID or item["gate_id"] != G12_GATE_ID or item["attempt"] != 0:
            _fail("G12_INVALID_EVIDENCE", "G12 identity or one-shot attempt mismatch")
        _hash_fields(item, ("campaign_root", "evaluation_nonce", "dependency_closure_root", "input_bundle_root"), "G12_INVALID_EVIDENCE")
        _identifier(item["evaluation_id"], "G12_INVALID_EVIDENCE")
        root = item["input_bundle_root"]
        dependency = _dependencies(item, gate_id=G12_GATE_ID, registered=("G11_ONE_SHOT_TRANSFER_VALIDATION",), code="G12_G11_BINDING_MISMATCH")
        if dependency["forced_decision"] == FAIL_DECISION:
            _fail(DEPENDENCY_FAILURE_CODE, "G12 dependency failed")
        registration = _exact(item["registration"], _G12_REGISTRATION_FIELDS, "G12_G11_BINDING_MISMATCH")
        _hash_fields(registration, tuple(field for field in registration if field.endswith("sha256") or field.endswith("_root")), "G12_G11_BINDING_MISMATCH")
        dependency_by_gate = {
            row["gate_id"]: row for row in dependency["nodes"]
        }
        g11_dependency = dependency_by_gate["G11_ONE_SHOT_TRANSFER_VALIDATION"]
        if (
            registration["g11_bundle_sha256"]
            != g11_dependency["bundle_sha256"]
            or registration["g11_authority_payload_sha256"]
            != g11_dependency["authority_payload_sha256"]
        ):
            _fail(
                "G12_G11_BINDING_MISMATCH",
                "G11 registration differs from recursive dependency bytes",
            )
        _validate_g11_bundle(
            item["g11_bundle"],
            registration["g11_bundle_sha256"],
            registration["g11_authority_payload_sha256"],
        )
        ciphertext = _raw(item["evaluator_ciphertext"], code="G12_CIPHERTEXT_MISMATCH")
        if hashlib.sha256(ciphertext).hexdigest() != registration["evaluator_ciphertext_sha256"]:
            _fail("G12_CIPHERTEXT_MISMATCH", "ciphertext hash differs from G11 registration")
        provenance = _exact(item["publisher_provenance"], _PROVENANCE_FIELDS, "G12_PROVENANCE_INVALID")
        _identifier(provenance["publisher_id"], "G12_PROVENANCE_INVALID")
        if type(provenance["capture_sha256s"]) is not list or len(provenance["capture_sha256s"]) < 2 or provenance["capture_sha256s"] != sorted(set(provenance["capture_sha256s"])):
            _fail("G12_PROVENANCE_INVALID", "two independent prospectively sealed captures are required")
        for capture in provenance["capture_sha256s"]:
            _sha(capture, "G12_PROVENANCE_INVALID")
        _sha(provenance["provenance_root"], "G12_PROVENANCE_INVALID")
        if (
            provenance["official_publisher_evidence"] is not True
            or provenance["provenance_root"]
            != registration["publisher_provenance_root"]
        ):
            _fail(
                "G12_PROVENANCE_INVALID",
                "publisher provenance is not official and registration-bound",
            )
        roles = _role_keys(item["role_keys"], required_roles=("evaluator_publisher", "evaluator_custodian_1", "evaluator_custodian_2", "evaluator_custodian_3", "runner_operator", "exact_gate_authority", "validator"), code="G12_ROLE_SEPARATION")
        if registration["g12_runner_key_id"] != roles["runner_operator"]["key_id"]:
            _fail("G12_RUNNER_MEASUREMENT_MISMATCH", "registered runner key differs")
        releases = item["custodian_releases"]
        if type(releases) is not list or len(releases) != 2:
            _fail("G12_CUSTODY_QUORUM_INVALID", "exactly two releases are required")
        released: set[str] = set()
        for envelope in releases:
            # The role is first authenticated from the signed canonical payload.
            matched = None
            for role in ("evaluator_custodian_1", "evaluator_custodian_2", "evaluator_custodian_3"):
                try:
                    payload = _signed_payload(envelope, expected_schema=G12_RELEASE_SCHEMA, expected_media_type=G12_SIGNED_MEDIA_TYPE, public_key=roles[role]["public_key"], domain=G12_DOMAIN, code="G12_CUSTODY_QUORUM_INVALID")
                    matched = (role, payload)
                    break
                except ProductionCandidateError:
                    continue
            if matched is None:
                _fail("G12_CUSTODY_QUORUM_INVALID", "release signer is not a registered custodian")
            role, payload = matched
            fields = frozenset({"schema_version", "campaign_root", "evaluation_id", "evaluation_nonce", "ciphertext_sha256", "runner_measurement_sha256", "custodian_role", "custodian_id"})
            payload = _exact(payload, fields, "G12_CUSTODY_QUORUM_INVALID")
            if payload["schema_version"] != G12_RELEASE_SCHEMA or payload["campaign_root"] != item["campaign_root"] or payload["evaluation_id"] != item["evaluation_id"] or payload["evaluation_nonce"] != item["evaluation_nonce"] or payload["ciphertext_sha256"] != registration["evaluator_ciphertext_sha256"] or payload["runner_measurement_sha256"] != registration["runner_measurement_sha256"] or payload["custodian_role"] != role or payload["custodian_id"] != roles[role]["custodian_id"] or role in released:
                _fail("G12_CUSTODY_QUORUM_INVALID", "custodian release binding mismatch")
            released.add(role)
        runner = _exact(item["runner_evidence"], _RUNNER_FIELDS, "G12_RUNNER_MEASUREMENT_MISMATCH")
        _hash_fields(runner, ("measurement_sha256", "runtime_sha256", "registered_evaluator_sha256"), "G12_RUNNER_MEASUREMENT_MISMATCH")
        if runner["runner_key_id"] != roles["runner_operator"]["key_id"] or runner["measurement_sha256"] != registration["runner_measurement_sha256"] or runner["registered_evaluator_sha256"] != registration["evaluator_ciphertext_sha256"] or runner["interface_loaded"] is not True or runner["evaluator_invocations"] != 0 or runner["plaintext_exports"] != 0:
            _fail("G12_RUNNER_MEASUREMENT_MISMATCH", "runner evidence is not locked readiness")
        audit = _exact(item["access_audit"], _ACCESS_FIELDS, "G12_FORBIDDEN_ACCESS_OR_EGRESS")
        if any(audit[field] != 0 for field in audit):
            _fail("G12_FORBIDDEN_ACCESS_OR_EGRESS", "G12 access audit is nonzero")
        transition = _exact(item["transition"], _G12_TRANSITION_FIELDS, "G12_INVALID_STATE")
        if transition["from_state"] != EVALUATOR_SEALED or transition["to_state"] != EVALUATOR_READY_LOCKED or type(transition["unseal_started"]) is not bool:
            _fail("G12_INVALID_STATE", "G12 transition is not frozen")
        _identifier(transition["replay_key"], "G12_FREEZE_CONFLICT")
        _sha(transition["history_root"], "G12_FREEZE_CONFLICT")
        replay = _exact(item["freeze_replay"], frozenset({"replay_key", "input_bundle_root", "conflicting_input_bundle_roots"}), "G12_FREEZE_CONFLICT")
        if replay["replay_key"] != transition["replay_key"] or replay["input_bundle_root"] != root or type(replay["conflicting_input_bundle_roots"]) is not list:
            _fail("G12_FREEZE_CONFLICT", "freeze replay binding mismatch")
        if replay["conflicting_input_bundle_roots"]:
            _fail("G12_FREEZE_CONFLICT", "immutable replay service reported conflict")
        # Every local, structurally complete record remains blocked until a
        # separately installed, pinned, valid-only external service exists.
        return _result(gate_id=G12_GATE_ID, structural_valid=True, failure_codes=["G12_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"], state=EVALUATOR_BURNED if _transition_started(transition, "unseal_started") else EVALUATOR_SEALED, input_bundle_root=root, dependency_result=dependency)
    except ProductionCandidateError as exc:
        state = EVALUATOR_BURNED if _transition_started(transition, "unseal_started") else EVALUATOR_SEALED
        return _result(gate_id=G12_GATE_ID, structural_valid=False, failure_codes=[exc.code], state=state, input_bundle_root=root, dependency_result=dependency)


def _statistics(candidate: Mapping[str, Any], metric_order: Sequence[Mapping[str, Any]]) -> dict[str, tuple[int, int]]:
    stats = _exact(candidate["statistics"], _STATISTICS_FIELDS, "G13_STATISTICS_INCOMPLETE")
    if stats["schema_version"] != "ptcg.g13.sufficient-statistics/v1" or type(stats["metrics"]) is not list or not stats["metrics"]:
        _fail("G13_STATISTICS_INCOMPLETE", "statistics schema mismatch")
    by_metric: dict[str, tuple[int, int]] = {}
    for entry in stats["metrics"]:
        row = _exact(entry, _METRIC_FIELDS, "G13_STATISTICS_INCOMPLETE")
        metric = row["metric"]
        if type(metric) is not str or _METRIC.fullmatch(metric) is None or metric in by_metric:
            _fail("G13_STATISTICS_INCOMPLETE", "metric is invalid or duplicate")
        numerator, denominator, excluded = (_u64(row[key], "G13_STATISTICS_INCOMPLETE") for key in ("numerator", "denominator", "excluded"))
        if denominator == 0 or excluded > denominator or numerator > denominator - excluded:
            _fail("G13_STATISTICS_INCOMPLETE", "metric counts are inconsistent")
        _sha(row["intermediate_root"], "G13_STATISTICS_INCOMPLETE")
        by_metric[metric] = (numerator, denominator - excluded)
    if set(by_metric) != {row["metric"] for row in metric_order}:
        _fail("G13_STATISTICS_INCOMPLETE", "statistics omit frozen ranking metrics")
    _sha(stats["statistics_root"], "G13_STATISTICS_INCOMPLETE")
    if canonical_sha256(
        {
            "schema_version": stats["schema_version"],
            "metrics": stats["metrics"],
        }
    ) != stats["statistics_root"]:
        _fail(
            "G13_STATISTICS_INCOMPLETE",
            "statistics root does not bind exact sufficient statistics",
        )
    return by_metric


def _rank(candidates: Sequence[Mapping[str, Any]], spec: Mapping[str, Any]) -> list[str]:
    metric_order = spec["metric_order"]
    stats = {row["candidate_id"]: _statistics(row, metric_order) for row in candidates}

    def compare(left: Mapping[str, Any], right: Mapping[str, Any]) -> int:
        for rule in metric_order:
            name, direction = rule["metric"], rule["direction"]
            ln, ld = stats[left["candidate_id"]][name]
            rn, rd = stats[right["candidate_id"]][name]
            comparison = (ln * rd > rn * ld) - (ln * rd < rn * ld)
            if comparison:
                return -comparison if direction == "DESC" else comparison
        return -1 if left["candidate_id"] < right["candidate_id"] else (1 if left["candidate_id"] > right["candidate_id"] else 0)
    return [row["candidate_id"] for row in sorted(candidates, key=cmp_to_key(compare))]


def validate_g13_synthetic_structure(evidence: object, *, g12_result: Mapping[str, Any]) -> dict[str, Any]:
    """Recompute synthetic DEV selection; never lock or authorize candidate bytes."""

    root = hashlib.sha256(b"").hexdigest()
    # A claimed freeze start is terminal on every later validation failure.
    claimed_transition = evidence.get("transition") if type(evidence) is dict else None
    transition: Mapping[str, Any] | None = (
        claimed_transition if type(claimed_transition) is dict else None
    )
    dependency: dict[str, Any] | None = None
    try:
        item = _exact(evidence, _G13_FIELDS, "G13_INVALID_EVIDENCE")
        if item["schema_version"] != G13_INPUT_SCHEMA or item["protocol_id"] != PROTOCOL_ID or item["gate_id"] != G13_GATE_ID or item["attempt"] != 0:
            _fail("G13_INVALID_EVIDENCE", "G13 identity or one-shot attempt mismatch")
        _hash_fields(item, ("campaign_root", "evaluation_nonce", "dependency_closure_root", "input_bundle_root"), "G13_INVALID_EVIDENCE")
        _identifier(item["evaluation_id"], "G13_INVALID_EVIDENCE")
        root = item["input_bundle_root"]
        dependency = _dependencies(item, gate_id=G13_GATE_ID, registered=("G05_DEV_SOURCE_COMPLETENESS", G12_GATE_ID), code="G13_G12_BINDING_MISMATCH")
        if dependency["forced_decision"] == FAIL_DECISION:
            _fail(DEPENDENCY_FAILURE_CODE, "G13 dependency failed")
        registration = _exact(item["registration"], _G13_REGISTRATION_FIELDS, "G13_UNIVERSE_MISMATCH")
        _hash_fields(registration, tuple(field for field in registration if field.endswith("sha256") or field.endswith("_root")), "G13_UNIVERSE_MISMATCH")
        dependency_by_gate = {
            row["gate_id"]: row for row in dependency["nodes"]
        }
        if (
            registration["g05_bundle_sha256"]
            != dependency_by_gate["G05_DEV_SOURCE_COMPLETENESS"]["bundle_sha256"]
            or registration["g12_bundle_sha256"]
            != dependency_by_gate[G12_GATE_ID]["bundle_sha256"]
        ):
            _fail(
                "G13_G12_BINDING_MISMATCH",
                "registered dependency hashes are not gate-specific",
            )
        # A local result can disqualify a run, never qualify it. A forged PASS
        # continues only into the final external-service block below.
        if g12_result.get("gate_id") != G12_GATE_ID or g12_result.get("decision") != PASS_DECISION:
            _fail("G13_G12_BINDING_MISMATCH", "G12 is not an externally verified pass")
        roles = _role_keys(item["role_keys"], required_roles=("builder", "selector", "archive_custodian_1", "archive_custodian_2", "g13_runner"), code="G13_FORBIDDEN_INPUT_OR_ACCESS")
        universe = _exact(item["mutation_universe"], _UNIVERSE_FIELDS, "G13_UNIVERSE_MISMATCH")
        if universe["schema_version"] != "ptcg.g13.dev-mutation-universe/v1":
            _fail("G13_UNIVERSE_MISMATCH", "mutation universe schema mismatch")
        _hash_fields(universe, ("base_source_sha256", "base_model_sha256", "mutation_program_sha256", "mutation_config_sha256", "universe_root"), "G13_UNIVERSE_MISMATCH")
        if _u64(universe["budget"], "G13_UNIVERSE_MISMATCH") == 0 or type(universe["seed_sha256s"]) is not list or not universe["seed_sha256s"] or universe["seed_sha256s"] != sorted(set(universe["seed_sha256s"])) or type(universe["forbidden_input_classes"]) is not list or not universe["forbidden_input_classes"]:
            _fail("G13_UNIVERSE_MISMATCH", "mutation universe is incomplete")
        for seed in universe["seed_sha256s"]:
            _sha(seed, "G13_UNIVERSE_MISMATCH")
        if canonical_sha256({key: value for key, value in universe.items() if key != "universe_root"}) != universe["universe_root"] or universe["universe_root"] != registration["mutation_universe_root"]:
            _fail("G13_UNIVERSE_MISMATCH", "mutation universe root mismatch")
        spec = _exact(item["selection_spec"], _SELECTION_SPEC_FIELDS, "G13_RANKING_OR_TIEBREAK_MISMATCH")
        if spec["schema_version"] != "ptcg.g13.selection-spec/v1" or spec["tie_break"] != "CANDIDATE_ID_ASC" or spec["max_candidate_count"] != registration["max_candidate_count"] or canonical_sha256(spec) != registration["selection_spec_sha256"]:
            _fail("G13_RANKING_OR_TIEBREAK_MISMATCH", "selection spec mismatch")
        if type(spec["metric_order"]) is not list or not spec["metric_order"] or len(spec["metric_order"]) > 16:
            _fail("G13_RANKING_OR_TIEBREAK_MISMATCH", "metric order missing")
        previous = ""
        for rule in spec["metric_order"]:
            rule = _exact(rule, _SELECTION_METRIC_FIELDS, "G13_RANKING_OR_TIEBREAK_MISMATCH")
            if type(rule["metric"]) is not str or _METRIC.fullmatch(rule["metric"]) is None or rule["metric"] <= previous or rule["direction"] not in {"ASC", "DESC"}:
                _fail("G13_RANKING_OR_TIEBREAK_MISMATCH", "metric order is noncanonical")
            previous = rule["metric"]
        candidates = item["candidates"]
        if type(candidates) is not list or not candidates or len(candidates) > registration["max_candidate_count"]:
            _fail("G13_MUTATION_OR_BUILD_MISMATCH", "candidate count is invalid")
        normalized: list[dict[str, Any]] = []
        ids: set[str] = set()
        archive_hashes: set[str] = set()
        for candidate in candidates:
            row = _exact(candidate, _CANDIDATE_FIELDS, "G13_MUTATION_OR_BUILD_MISMATCH")
            candidate_id = _identifier(row["candidate_id"], "G13_MUTATION_OR_BUILD_MISMATCH")
            if candidate_id in ids:
                _fail("G13_DUPLICATE_CANDIDATE_OR_ARCHIVE", "candidate IDs are duplicate")
            ids.add(candidate_id)
            _hash_fields(row, ("source_sha256", "model_sha256", "config_sha256", "build_recipe_sha256", "dependency_lock_sha256", "dev_bundle_sha256", "build_log_sha256", "lineage_root"), "G13_MUTATION_OR_BUILD_MISMATCH")
            archive = _raw(row["archive"], code="G13_MUTATION_OR_BUILD_MISMATCH")
            archive_hash = hashlib.sha256(archive).hexdigest()
            if archive_hash in archive_hashes:
                _fail("G13_DUPLICATE_CANDIDATE_OR_ARCHIVE", "archive hash is duplicate")
            archive_hashes.add(archive_hash)
            normalized.append({**row, "archive_sha256": archive_hash, "archive_length": len(archive)})
        ranking = _rank(normalized, spec)
        transcript = _exact(item["selection_transcript"], _TRANSCRIPT_FIELDS, "G13_SELECTION_MISMATCH")
        if transcript["manual_override"] is not False:
            _fail("G13_MANUAL_OVERRIDE", "manual selection override is forbidden")
        if transcript["ranked_candidate_ids"] != ranking or transcript["selected_candidate_id"] != ranking[0]:
            _fail("G13_RANKING_OR_TIEBREAK_MISMATCH", "selector transcript is nondeterministic or overridden")
        chosen = next(row for row in normalized if row["candidate_id"] == ranking[0])
        if transcript["selected_archive_sha256"] != chosen["archive_sha256"] or transcript["selected_archive_length"] != chosen["archive_length"] or canonical_sha256({key: value for key, value in transcript.items() if key != "selection_root"}) != transcript["selection_root"]:
            _fail("G13_SELECTION_MISMATCH", "selected archive is not exact")
        deposits = item["custody_deposits"]
        if type(deposits) is not list or len(deposits) != 2:
            _fail("G13_CUSTODY_MISMATCH", "two matching deposits are required")
        deposited: set[str] = set()
        for envelope in deposits:
            matched = None
            for role in ("archive_custodian_1", "archive_custodian_2"):
                try:
                    payload = _signed_payload(envelope, expected_schema=G13_DEPOSIT_SCHEMA, expected_media_type=G13_SIGNED_MEDIA_TYPE, public_key=roles[role]["public_key"], domain=G13_DOMAIN, code="G13_CUSTODY_MISMATCH")
                    matched = (role, payload)
                    break
                except ProductionCandidateError:
                    continue
            if matched is None:
                _fail("G13_CUSTODY_MISMATCH", "deposit signer is not a registered custodian")
            role, payload = matched
            payload = _exact(payload, _DEPOSIT_FIELDS, "G13_CUSTODY_MISMATCH")
            if payload["schema_version"] != G13_DEPOSIT_SCHEMA or payload["campaign_root"] != item["campaign_root"] or payload["evaluation_id"] != item["evaluation_id"] or payload["evaluation_nonce"] != item["evaluation_nonce"] or payload["archive_sha256"] != chosen["archive_sha256"] or payload["archive_length"] != chosen["archive_length"] or payload["selection_root"] != transcript["selection_root"] or payload["custodian_role"] != role or payload["custodian_id"] != roles[role]["custodian_id"] or role in deposited:
                _fail("G13_CUSTODY_MISMATCH", "custody deposit binding mismatch")
            deposited.add(role)
        audit = _exact(item["access_audit"], _ACCESS_FIELDS, "G13_FORBIDDEN_INPUT_OR_ACCESS")
        if any(audit[field] != 0 for field in audit):
            _fail("G13_FORBIDDEN_INPUT_OR_ACCESS", "G13 accessed evaluator, holdout, or external input")
        transition = _exact(item["transition"], _G13_TRANSITION_FIELDS, "G13_INVALID_STATE")
        if transition["from_state"] != DEV_MUTABLE or transition["to_state"] != CANDIDATE_SELECTED_LOCKED or type(transition["freeze_started"]) is not bool:
            _fail("G13_INVALID_STATE", "G13 transition is not frozen")
        _identifier(transition["replay_key"], "G13_FREEZE_CONFLICT")
        _sha(transition["history_root"], "G13_FREEZE_CONFLICT")
        replay = _exact(item["freeze_replay"], frozenset({"replay_key", "input_bundle_root", "conflicting_input_bundle_roots"}), "G13_FREEZE_CONFLICT")
        if replay["replay_key"] != transition["replay_key"] or replay["input_bundle_root"] != root or type(replay["conflicting_input_bundle_roots"]) is not list:
            _fail("G13_FREEZE_CONFLICT", "freeze replay binding mismatch")
        if replay["conflicting_input_bundle_roots"]:
            _fail("G13_FREEZE_CONFLICT", "immutable replay service reported conflict")
        # `g12_result` is deliberately diagnostic only. A caller-controlled
        # mapping cannot satisfy an irreversible dependency; only the absent
        # pinned valid-only service could bind this G12 bundle to a PASS.
        return _result(gate_id=G13_GATE_ID, structural_valid=True, failure_codes=["G13_G12_BINDING_MISMATCH", "G13_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"], state=CANDIDATE_FREEZE_BURNED if _transition_started(transition, "freeze_started") else DEV_MUTABLE, input_bundle_root=root, dependency_result=dependency)
    except ProductionCandidateError as exc:
        state = CANDIDATE_FREEZE_BURNED if _transition_started(transition, "freeze_started") else DEV_MUTABLE
        return _result(gate_id=G13_GATE_ID, structural_valid=False, failure_codes=[exc.code], state=state, input_bundle_root=root, dependency_result=dependency)


def _hard_close_untrusted_structure(result: Mapping[str, Any], *, code: str) -> dict[str, Any]:
    """Preserve syntax diagnostics while preventing a caller from claiming closure."""

    return {
        **result,
        "decision": FAIL_DECISION,
        "syntax_validation_complete": result.get("structural_validation_complete") is True,
        "structural_validation_complete": False,
        "failure_codes": sorted(set(result.get("failure_codes", [])) | {code}),
        "candidate_development_authorized": False,
        "evaluator_unseal_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def validate_g12_evaluator_readiness(evidence: object) -> dict[str, Any]:
    """Production-shaped G12 entry point; unverified G11 makes closure false."""

    return _hard_close_untrusted_structure(
        validate_g12_synthetic_structure(evidence),
        code="G12_G11_BINDING_MISMATCH",
    )


def validate_g13_candidate_freeze(evidence: object, *, g12_result: Mapping[str, Any]) -> dict[str, Any]:
    """Production-shaped G13 entry point; no caller mapping can establish G12."""

    return _hard_close_untrusted_structure(
        validate_g13_synthetic_structure(evidence, g12_result=g12_result),
        code="G13_G12_BINDING_MISMATCH",
    )


__all__ = [
    "CANDIDATE_FREEZE_BURNED", "CANDIDATE_SELECTED_LOCKED", "DEV_MUTABLE",
    "EVALUATOR_BURNED", "EVALUATOR_READY_LOCKED", "EVALUATOR_SEALED",
    "G12_FAILURE_CODES", "G12_GATE_ID", "G12_INPUT_SCHEMA", "G13_FAILURE_CODES",
    "G13_GATE_ID", "G13_INPUT_SCHEMA", "ProductionCandidateError",
    "TRUSTED_VALID_ONLY_SERVICE_KEYS", "validate_g12_evaluator_readiness",
    "validate_g12_synthetic_structure", "validate_g13_candidate_freeze",
    "validate_g13_synthetic_structure",
]
