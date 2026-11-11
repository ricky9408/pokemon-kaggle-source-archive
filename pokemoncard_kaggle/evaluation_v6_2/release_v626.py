"""Service-bound v6.2.6 population trust composer.

The positive state in this module is intentionally non-authoritative: it only
allows later local-evidence work. It cannot issue a calibration or production
permit and cannot access the sealed holdout. Production assessment also fails
closed while the literal external trust policy remains unpinned.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any

from .evidence_v626 import (
    EVIDENCE_FAILURE_STATES,
    EvidenceGraph,
    EvidenceV626Error,
    require_root,
    validate_evidence_graph,
    validate_execution_transcript,
    validate_pair_analysis,
    validate_population_derivation,
    validate_principal_assignment,
    validate_runtime_manifest,
)
from .integration_v622 import canonical_json_bytes, canonical_sha256
from .trust_v626 import (
    FAILURE_STATES,
    TrustV626Error,
    detect_witness_forks,
    fail_closed_verdict,
    validate_close_time_quorum,
    validate_open_time_quorum,
    validate_time_window,
    validate_trust_policy,
    validate_witness_head,
    validate_witness_transition,
    verify_authority_signature,
)
from .witness_client_v626 import WitnessAcquisition
from .time_client_v626 import TrustedTimeAcquisition


VERIFIER_RECEIPT_SCHEMA = "eval.v6.2.6.comprehensive-verifier-receipt"
VERIFIER_ENVELOPE_SCHEMA = "eval.v6.2.6.comprehensive-verifier-envelope"
VERDICT_SCHEMA = "eval.v6.2.6.population-trust-verdict"
CONFORMANCE_PACKET_SCHEMA = "eval.v6.2.6.external-conformance-packet"
DOMAIN_CONFORMANCE_PACKET = b"EVAL-V626/EXTERNAL-CONFORMANCE-PACKET\0"
DOMAIN_VERIFIER_RECEIPT = b"EVAL-V626/COMPREHENSIVE-VERIFIER-RECEIPT\0"

# These literals remain None until a separately reviewed release pins an exact
# policy object and its digest. Tests exercise the pure verifier by supplying an
# explicit policy; the production entrypoint never accepts runtime overrides.
PINNED_EXTERNAL_TRUST_POLICY: Mapping[str, Any] | None = None
PINNED_EXTERNAL_TRUST_POLICY_SHA256: str | None = None

V626_FAILURE_STATES = FAILURE_STATES | EVIDENCE_FAILURE_STATES | frozenset(
    {
        "INDEPENDENT_RUN_POLICY_NOT_SATISFIED",
        "EXTERNAL_VERIFIER_DISAGREEMENT",
        "POPULATION_INFEASIBLE",
        "EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE",
    }
)

REQUIRED_CHECK_VECTOR = frozenset(
    {
        "registry_valid",
        "revocation_opening_state_valid",
        "evidence_graph_valid",
        "semantic_artifact_verification_complete",
        "identity_authenticated_under_policy",
        "principal_assignment_authenticated_under_policy",
        "pair_analysis_complete",
        "population_semantics_valid",
        "runtime_tcb_valid",
        "role_separation_valid",
        "population_feasible",
    }
)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32,256}$")


class ReleaseV626Error(ValueError):
    """A composed v6.2.6 population release failed closed."""

    def __init__(self, code: str, message: str) -> None:
        if code not in V626_FAILURE_STATES:
            raise ValueError(f"unknown v6.2.6 release failure state: {code}")
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> ReleaseV626Error:
    return ReleaseV626Error(code, message)


def _exact(value: Any, fields: frozenset[str], label: str, *, code: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _fail(code, f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\0" in value:
        raise _fail(code, f"{label} must be a nonempty trimmed string without NUL")
    return value


def _sha(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _nonce(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _NONCE_RE.fullmatch(value) is None or len(value) % 2:
        raise _fail(code, f"{label} must be 16 through 128 bytes of lowercase hex")
    return value


def _decimal(value: Any, label: str, *, code: str) -> int:
    if type(value) is not str or not value.isdigit() or (len(value) > 1 and value[0] == "0"):
        raise _fail(code, f"{label} must be a canonical nonnegative decimal string")
    return int(value)


def _sha_list(value: Any, label: str, *, exact_count: int | None = None) -> tuple[str, ...]:
    code = "EXTERNAL_VERIFIER_DISAGREEMENT"
    if type(value) is not list or (exact_count is not None and len(value) != exact_count):
        raise _fail(code, f"{label} must be a list with the required count")
    parsed = tuple(_sha(item, label, code=code) for item in value)
    if tuple(sorted(parsed)) != parsed or len(set(parsed)) != len(parsed):
        raise _fail(code, f"{label} must be sorted and unique")
    return parsed


def _check_vector(value: Any) -> dict[str, bool]:
    code = "EXTERNAL_VERIFIER_DISAGREEMENT"
    if type(value) is not dict or set(value) != REQUIRED_CHECK_VECTOR:
        raise _fail(code, f"verifier check vector must exactly contain {sorted(REQUIRED_CHECK_VECTOR)}")
    if any(flag is not True for flag in value.values()):
        raise _fail("POPULATION_INFEASIBLE", "every comprehensive verifier check must be true")
    return dict(value)


_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "verifier_authority_key_id",
        "verifier_authority_subject_id",
        "verifier_authority_control_group_id",
        "verifier_authority_organization_id",
        "release_root_sha256",
        "campaign_bundle_root_sha256",
        "evidence_graph_root_sha256",
        "verification_packet_root_sha256",
        "population_analysis_root_sha256",
        "runtime_manifest_root_sha256",
        "execution_transcript_root_sha256",
        "environment_attestation_root_sha256",
        "session_id",
        "authority_challenge",
        "verification_nonce",
        "registry_epoch",
        "revocation_sequence",
        "revocation_head_sha256",
        "accepted_verifier_build_root_sha256",
        "runtime_tcb_policy_sha256",
        "check_vector",
    }
)


def _verification_receipts(
    values: Any,
    *,
    graph: EvidenceGraph,
    policy: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], tuple[str, ...]]:
    code = "INDEPENDENT_RUN_POLICY_NOT_SATISFIED"
    if type(values) is not list or len(values) != 2:
        raise _fail(code, "exactly two comprehensive verifier receipts are required")
    parsed: list[dict[str, Any]] = []
    envelope_hashes: list[str] = []
    for index, raw in enumerate(values):
        envelope = _exact(
            raw,
            frozenset({"schema", "payload", "signature_base64"}),
            f"verifier envelope[{index}]",
            code=code,
        )
        if envelope["schema"] != VERIFIER_ENVELOPE_SCHEMA:
            raise _fail(code, "verifier envelope schema mismatch")
        payload = _exact(envelope["payload"], _RECEIPT_FIELDS, f"verifier receipt[{index}]", code=code)
        if payload["schema"] != VERIFIER_RECEIPT_SCHEMA:
            raise _fail(code, "verifier receipt schema mismatch")
        key_id = _identifier(payload["verifier_authority_key_id"], "verifier authority key id", code=code)
        if key_id not in policy["verifier_authorities"]:
            raise _fail(code, "verifier authority is not release-pinned")
        authority = policy["verifier_authorities"][key_id]
        for field, authority_field in (
            ("verifier_authority_subject_id", "subject_id"),
            ("verifier_authority_control_group_id", "control_group_id"),
            ("verifier_authority_organization_id", "organization_id"),
        ):
            if payload[field] != authority[authority_field]:
                raise _fail(code, f"{field} does not match the release-pinned verifier")
        for field, expected_value in expected.items():
            if payload.get(field) != expected_value:
                raise _fail("EXTERNAL_VERIFIER_DISAGREEMENT", f"verifier receipt {field} does not match the common binding")
        for field in (
            "release_root_sha256",
            "campaign_bundle_root_sha256",
            "evidence_graph_root_sha256",
            "verification_packet_root_sha256",
            "population_analysis_root_sha256",
            "runtime_manifest_root_sha256",
            "execution_transcript_root_sha256",
            "environment_attestation_root_sha256",
            "revocation_head_sha256",
            "accepted_verifier_build_root_sha256",
            "runtime_tcb_policy_sha256",
        ):
            _sha(payload[field], f"verifier receipt {field}", code=code)
        registry_epoch = _decimal(payload["registry_epoch"], "verifier registry epoch", code=code)
        revocation_sequence = _decimal(payload["revocation_sequence"], "verifier revocation sequence", code=code)
        session_id = _identifier(payload["session_id"], "verifier session id", code=code)
        authority_challenge = _nonce(payload["authority_challenge"], "verifier authority challenge", code=code)
        verification_nonce = _nonce(payload["verification_nonce"], "verifier nonce", code=code)
        checks = _check_vector(payload["check_vector"])
        verify_authority_signature(
            authority,
            DOMAIN_VERIFIER_RECEIPT,
            payload,
            envelope["signature_base64"],
            code="EXTERNAL_VERIFIER_DISAGREEMENT",
        )
        runtime = validate_runtime_manifest(
            graph,
            payload["runtime_manifest_root_sha256"],
            accepted_verifier_build_root_sha256=policy["accepted_verifier_build_root_sha256"],
            runtime_tcb_policy_sha256=policy["runtime_tcb_policy_sha256"],
        )
        external_authorities = [
            policy["log_authority"],
            *policy["witness_cosigners"].values(),
            *policy["time_authorities"].values(),
            *policy["verifier_authorities"].values(),
        ]
        forbidden_controls = set(policy["project_control_group_ids"]) | {
            item["control_group_id"] for item in external_authorities
        }
        if runtime.runtime_custodian_control_group_id in forbidden_controls:
            raise _fail(code, "runtime custodian control group aliases project or trust authority control")
        if runtime.runtime_custodian_subject_id in {item["subject_id"] for item in external_authorities}:
            raise _fail(code, "runtime custodian subject aliases a trust authority")
        if runtime.runtime_custodian_organization_id in {item["organization_id"] for item in external_authorities}:
            raise _fail(code, "runtime custodian organization aliases a trust authority")
        transcript = validate_execution_transcript(
            graph,
            payload["execution_transcript_root_sha256"],
            runtime_manifest_root_sha256=payload["runtime_manifest_root_sha256"],
        )
        environment_node = require_root(
            graph,
            payload["environment_attestation_root_sha256"],
            frozenset({"ENVIRONMENT_ATTESTATION"}),
            label="environment attestation root",
        )
        if environment_node["payload_sha256"] is None:
            raise _fail("VERIFIER_TCB_MANIFEST_INCOMPLETE", "environment attestation lacks a closed payload")
        if transcript.session_id != session_id or transcript.authority_challenge != authority_challenge or transcript.verification_nonce != verification_nonce:
            raise _fail("VERIFIER_TCB_MISMATCH", "receipt and transcript session bindings disagree")
        parsed.append(
            {
                "authority": authority,
                "payload": payload,
                "runtime": runtime,
                "transcript": transcript,
                "checks": checks,
                "registry_epoch": registry_epoch,
                "revocation_sequence": revocation_sequence,
            }
        )
        envelope_hashes.append(canonical_sha256(envelope))
    first, second = parsed
    distinct_pairs = (
        (first["authority"]["key_id"], second["authority"]["key_id"], "verifier key"),
        (first["authority"]["subject_id"], second["authority"]["subject_id"], "verifier subject"),
        (first["authority"]["control_group_id"], second["authority"]["control_group_id"], "verifier control group"),
        (first["authority"]["organization_id"], second["authority"]["organization_id"], "verifier organization"),
        (first["runtime"].runtime_custodian_control_group_id, second["runtime"].runtime_custodian_control_group_id, "runtime custodian control group"),
        (first["runtime"].runtime_custodian_subject_id, second["runtime"].runtime_custodian_subject_id, "runtime custodian subject"),
        (first["runtime"].runtime_custodian_organization_id, second["runtime"].runtime_custodian_organization_id, "runtime custodian organization"),
        (first["payload"]["session_id"], second["payload"]["session_id"], "session id"),
        (first["payload"]["authority_challenge"], second["payload"]["authority_challenge"], "authority challenge"),
        (first["payload"]["verification_nonce"], second["payload"]["verification_nonce"], "verification nonce"),
        (first["payload"]["execution_transcript_root_sha256"], second["payload"]["execution_transcript_root_sha256"], "transcript root"),
        (first["payload"]["environment_attestation_root_sha256"], second["payload"]["environment_attestation_root_sha256"], "environment root"),
    )
    for left, right, label in distinct_pairs:
        if left == right:
            raise _fail(code, f"independent runs reuse {label}")
    common_fields = (
        "release_root_sha256",
        "campaign_bundle_root_sha256",
        "evidence_graph_root_sha256",
        "verification_packet_root_sha256",
        "population_analysis_root_sha256",
        "registry_epoch",
        "revocation_sequence",
        "revocation_head_sha256",
        "accepted_verifier_build_root_sha256",
        "runtime_tcb_policy_sha256",
        "check_vector",
    )
    if any(first["payload"][field] != second["payload"][field] for field in common_fields):
        raise _fail("EXTERNAL_VERIFIER_DISAGREEMENT", "external verifier receipts disagree on common roots or checks")
    return parsed, tuple(sorted(envelope_hashes))


def _positive_verdict(
    *,
    policy_sha256: str,
    release_root_sha256: str,
    campaign_bundle_root_sha256: str,
    verification_packet_root_sha256: str,
    population_decision_root_sha256: str,
    evidence_graph_root_sha256: str,
    opening_witness_head_sha256: str,
    witness_transition_sha256: str,
    closing_witness_head_sha256: str,
    opening_time_receipt_sha256s: tuple[str, ...],
    closing_time_receipt_sha256s: tuple[str, ...],
    verifier_receipt_sha256s: tuple[str, ...],
    check_vector_sha256: str,
    component_ids: Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    packet = {
        "schema": CONFORMANCE_PACKET_SCHEMA,
        "state": "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING",
        "external_authentication_verified": True,
        "semantic_artifact_verification_complete": True,
        "independence_adjudicated_under_policy": True,
        "independent_verifier_runs_attested_under_policy": True,
        "runtime_tcb_attested_under_policy": True,
        "population_feasible": True,
        "population_feasible_under_pinned_policy": True,
        "independence_ground_truth_proven": False,
        "independent_runtime_execution_cryptographically_proven": False,
        "physical_host_separation_proven": False,
        "absence_of_verifier_collusion_proven": False,
        "runtime_tcb_loaded_state_cryptographically_proven": False,
        "local_process_output_authoritative": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
        "external_trust_policy_sha256": policy_sha256,
        "release_root_sha256": release_root_sha256,
        "campaign_bundle_root_sha256": campaign_bundle_root_sha256,
        "verification_packet_root_sha256": verification_packet_root_sha256,
        "population_decision_root_sha256": population_decision_root_sha256,
        "evidence_graph_root_sha256": evidence_graph_root_sha256,
        "opening_witness_head_sha256": opening_witness_head_sha256,
        "witness_transition_sha256": witness_transition_sha256,
        "closing_witness_head_sha256": closing_witness_head_sha256,
        "opening_time_receipt_sha256s": list(opening_time_receipt_sha256s),
        "closing_time_receipt_sha256s": list(closing_time_receipt_sha256s),
        "verifier_receipt_sha256s": list(verifier_receipt_sha256s),
        "check_vector_sha256": check_vector_sha256,
        "component_ids": {key: list(value) for key, value in sorted(component_ids.items())},
    }
    packet["external_conformance_packet_sha256"] = external_conformance_packet_sha256(packet)
    return packet


def external_conformance_packet_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("external_conformance_packet_sha256", None)
    return hashlib.sha256(DOMAIN_CONFORMANCE_PACKET + canonical_json_bytes(payload)).hexdigest()


def verify_population_trust(
    *,
    trust_policy: Mapping[str, Any],
    trust_policy_sha256: str,
    witness_transition: Mapping[str, Any],
    opening_witness_head: Mapping[str, Any],
    closing_witness_head: Mapping[str, Any],
    opening_time_receipts: list[Mapping[str, Any]],
    closing_time_receipts: list[Mapping[str, Any]],
    nodes_jsonl: bytes,
    edges_jsonl: bytes,
    payload_manifest_jsonl: bytes,
    payloads: Mapping[str, bytes],
    evidence_graph_root_sha256: str,
    campaign_bundle_root_sha256: str,
    verification_packet_root_sha256: str,
    invocation_challenge_sha256: str,
    population_analysis_root_sha256: str,
    evidence_input_graph_root_sha256: str,
    pair_classification_graph_root_sha256: str,
    component_assignment_root_sha256: str,
    pair_analysis_root_sha256s: list[str],
    principal_assignment_root_sha256s: list[str],
    verification_receipts: list[Mapping[str, Any]],
    observed_witness_transitions: list[Mapping[str, Any]] | None = None,
    live_witness_acquisition: WitnessAcquisition | None = None,
    live_time_acquisition: TrustedTimeAcquisition | None = None,
) -> dict[str, Any]:
    policy = validate_trust_policy(trust_policy, expected_sha256=trust_policy_sha256)
    if live_witness_acquisition is None:
        raise _fail(
            "LIVE_EXTERNAL_STATE_NOT_ACQUIRED",
            "a signed artifact pack cannot replace live witness head/CAS acquisition",
        )
    if canonical_sha256(live_witness_acquisition.opening_head_envelope) != canonical_sha256(opening_witness_head):
        raise _fail("OPENING_HEAD_TRANSITION_MISMATCH", "artifact opening head differs from the live external acquisition")
    if canonical_sha256(live_witness_acquisition.transition_envelope) != canonical_sha256(witness_transition):
        raise _fail("OPENING_CLOSING_CONSISTENCY_FAILURE", "artifact transition differs from the live external CAS result")
    if canonical_sha256(live_witness_acquisition.closing_head_envelope) != canonical_sha256(closing_witness_head):
        raise _fail("CLOSING_HEAD_TRANSITION_MISMATCH", "artifact closing head differs from the live external acquisition")
    if live_time_acquisition is None:
        raise _fail(
            "LIVE_EXTERNAL_STATE_NOT_ACQUIRED",
            "signed time files cannot replace live opening and closing time quorum acquisition",
        )
    if tuple(sorted(canonical_sha256(item) for item in live_time_acquisition.opening_receipts)) != tuple(
        sorted(canonical_sha256(item) for item in opening_time_receipts)
    ):
        raise _fail("TRUSTED_TIME_QUORUM_INVALID", "artifact opening time receipts differ from live acquisition")
    if tuple(sorted(canonical_sha256(item) for item in live_time_acquisition.closing_receipts)) != tuple(
        sorted(canonical_sha256(item) for item in closing_time_receipts)
    ):
        raise _fail("TRUSTED_TIME_QUORUM_INVALID", "artifact closing time receipts differ from live acquisition")
    graph = validate_evidence_graph(
        nodes_jsonl=nodes_jsonl,
        edges_jsonl=edges_jsonl,
        payload_manifest_jsonl=payload_manifest_jsonl,
        payloads=payloads,
        expected_root_sha256=evidence_graph_root_sha256,
        expected_policy_sha256=policy["evidence_policy_sha256"],
    )
    require_root(graph, campaign_bundle_root_sha256, frozenset({"CAMPAIGN_BUNDLE"}), label="campaign bundle root")
    require_root(graph, verification_packet_root_sha256, frozenset({"VERIFICATION_PACKET"}), label="verification packet root")
    require_root(graph, population_analysis_root_sha256, frozenset({"POPULATION_DECISION_ROOT"}), label="population decision root")
    for root in pair_analysis_root_sha256s:
        validate_pair_analysis(graph, root)
    for root in principal_assignment_root_sha256s:
        validate_principal_assignment(
            graph,
            root,
            approved_identity_issuers=policy["identity_issuers"],
        )
    component_ids = validate_population_derivation(
        graph,
        evidence_input_graph_root_sha256=evidence_input_graph_root_sha256,
        pair_classification_graph_root_sha256=pair_classification_graph_root_sha256,
        component_assignment_root_sha256=component_assignment_root_sha256,
        population_decision_root_sha256=population_analysis_root_sha256,
    )
    witness = validate_witness_transition(witness_transition, policy=policy)
    try:
        opening_head_nonce = opening_witness_head["payload"]["response_nonce"]
        closing_head_nonce = closing_witness_head["payload"]["response_nonce"]
    except (KeyError, TypeError) as exc:
        raise _fail("MONOTONIC_WITNESS_UNAVAILABLE", "witness head receipt is malformed") from exc
    opening_head = validate_witness_head(
        opening_witness_head,
        policy=policy,
        expected_response_nonce=opening_head_nonce,
    )
    closing_head = validate_witness_head(
        closing_witness_head,
        policy=policy,
        expected_response_nonce=closing_head_nonce,
    )
    if (
        opening_head.checkpoint_tree_size != witness.previous_checkpoint_tree_size
        or opening_head.checkpoint_root_sha256 != witness.previous_checkpoint_root_sha256
        or closing_head.checkpoint_tree_size != witness.checkpoint_tree_size
        or closing_head.checkpoint_root_sha256 != witness_transition["payload"]["checkpoint"]["root_sha256"]
    ):
        raise _fail("OPENING_CLOSING_CONSISTENCY_FAILURE", "signed witness heads and transition checkpoints disagree")
    if opening_head.state_sha256 != witness.previous_state_sha256 or opening_head.sequence != witness.previous_sequence:
        raise _fail("OPENING_HEAD_TRANSITION_MISMATCH", "signed opening witness head does not match the transition predecessor")
    if closing_head.state_sha256 != witness.new_state_sha256 or closing_head.sequence != witness.new_sequence:
        raise _fail("CLOSING_HEAD_TRANSITION_MISMATCH", "signed closing witness head does not match the transition successor")
    observed = [witness]
    for item in observed_witness_transitions or []:
        candidate = validate_witness_transition(item, policy=policy)
        if candidate.transition_sha256 != witness.transition_sha256:
            observed.append(candidate)
    detect_witness_forks(observed)
    challenge = _sha(invocation_challenge_sha256, "invocation challenge sha256", code="MONOTONIC_CAS_REJECTED")
    campaign_root = _sha(campaign_bundle_root_sha256, "campaign bundle root", code="EXTERNAL_VERIFIER_DISAGREEMENT")
    packet_root = _sha(verification_packet_root_sha256, "verification packet root", code="EXTERNAL_VERIFIER_DISAGREEMENT")
    graph_root = _sha(evidence_graph_root_sha256, "evidence graph root", code="EXTERNAL_VERIFIER_DISAGREEMENT")
    population_root = _sha(population_analysis_root_sha256, "population analysis root", code="EXTERNAL_VERIFIER_DISAGREEMENT")
    if witness_transition["payload"]["request"]["invocation_challenge_sha256"] != challenge:
        raise _fail("CHALLENGE_ALREADY_REDEEMED", "witness transition redeemed a different challenge")
    if witness_transition["payload"]["request"]["campaign_bundle_root_sha256"] != campaign_root or witness_transition["payload"]["request"]["evidence_graph_root_sha256"] != graph_root or witness_transition["payload"]["request"]["verification_packet_root_sha256"] != packet_root:
        raise _fail("MONOTONIC_CAS_REJECTED", "witness transition does not bind the campaign, evidence, and packet roots")
    receipt_expected = {
        "release_root_sha256": policy["release_root_sha256"],
        "campaign_bundle_root_sha256": campaign_root,
        "evidence_graph_root_sha256": graph_root,
        "verification_packet_root_sha256": packet_root,
        "population_analysis_root_sha256": population_root,
        "registry_epoch": str(witness.previous_registry_epoch),
        "revocation_sequence": str(witness.previous_revocation_sequence),
        "revocation_head_sha256": witness.previous_revocation_head_sha256,
        "accepted_verifier_build_root_sha256": policy["accepted_verifier_build_root_sha256"],
        "runtime_tcb_policy_sha256": policy["runtime_tcb_policy_sha256"],
    }
    receipts, receipt_hashes = _verification_receipts(
        verification_receipts,
        graph=graph,
        policy=policy,
        expected=receipt_expected,
    )
    if witness.revocation_sequence != witness.previous_revocation_sequence or witness.revocation_head_sha256 != witness.previous_revocation_head_sha256:
        raise _fail("REVOCATION_STATE_ADVANCED_REVERIFY_REQUIRED", "closing revocation state advanced; complete reevaluation under the closing head is required")
    opening_expected = {
        "campaign_bundle_root_sha256": campaign_root,
        "invocation_challenge_sha256": challenge,
        "expected_witness_state_sha256": witness.previous_state_sha256,
        "expected_witness_sequence": str(witness.previous_sequence),
        "checkpoint_sha256": canonical_sha256(opening_witness_head),
        "checkpoint_tree_size": str(witness.previous_checkpoint_tree_size),
        "registry_epoch": str(witness.previous_registry_epoch),
        "revocation_sequence": str(witness.previous_revocation_sequence),
        "revocation_head_sha256": witness.previous_revocation_head_sha256,
    }
    opening = validate_open_time_quorum(opening_time_receipts, policy=policy, expected=opening_expected)
    transcript_roots = tuple(sorted(item["payload"]["execution_transcript_root_sha256"] for item in receipts))
    runtime_roots = tuple(sorted(item["payload"]["runtime_manifest_root_sha256"] for item in receipts))
    closing_expected = {
        "campaign_bundle_root_sha256": campaign_root,
        "invocation_challenge_sha256": challenge,
        "checkpoint_sha256": witness.checkpoint_sha256,
        "checkpoint_tree_size": str(witness.checkpoint_tree_size),
        "registry_epoch": str(witness.registry_epoch),
        "revocation_sequence": str(witness.revocation_sequence),
        "revocation_head_sha256": witness.revocation_head_sha256,
        "witness_transition_sha256": witness.transition_sha256,
        "new_witness_state_sha256": witness.new_state_sha256,
        "comprehensive_verifier_receipt_sha256s": list(receipt_hashes),
        "transcript_root_sha256s": list(transcript_roots),
        "runtime_manifest_root_sha256s": list(runtime_roots),
        "evidence_graph_root_sha256": graph_root,
    }
    closing = validate_close_time_quorum(closing_time_receipts, policy=policy, expected=closing_expected)
    validate_time_window(opening=opening, closing=closing, checkpoint_observed_at=witness.checkpoint_observed_at)
    return _positive_verdict(
        policy_sha256=trust_policy_sha256,
        release_root_sha256=policy["release_root_sha256"],
        campaign_bundle_root_sha256=campaign_root,
        verification_packet_root_sha256=packet_root,
        population_decision_root_sha256=population_root,
        evidence_graph_root_sha256=graph_root,
        opening_witness_head_sha256=canonical_sha256(opening_witness_head),
        witness_transition_sha256=witness.transition_sha256,
        closing_witness_head_sha256=canonical_sha256(closing_witness_head),
        opening_time_receipt_sha256s=tuple(sorted(canonical_sha256(item) for item in opening_time_receipts)),
        closing_time_receipt_sha256s=tuple(sorted(canonical_sha256(item) for item in closing_time_receipts)),
        verifier_receipt_sha256s=receipt_hashes,
        check_vector_sha256=canonical_sha256(receipts[0]["checks"]),
        component_ids=component_ids,
    )


def assess_population_trust(**kwargs: Any) -> dict[str, Any]:
    try:
        return verify_population_trust(**kwargs)
    except (TrustV626Error, EvidenceV626Error, ReleaseV626Error) as exc:
        return fail_closed_verdict(exc.code, reason=str(exc))
    except Exception as exc:
        return fail_closed_verdict("POPULATION_INFEASIBLE", reason=f"unexpected verifier failure: {type(exc).__name__}: {exc}")


def verify_external_conformance_packet(
    packet: Mapping[str, Any],
    **artifact_kwargs: Any,
) -> dict[str, Any]:
    """Independently revalidate one packet without creating new authority."""

    if type(packet) is not dict or packet.get("schema") != CONFORMANCE_PACKET_SCHEMA:
        raise _fail("EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE", "external conformance packet schema is absent or invalid")
    packet_hash = packet.get("external_conformance_packet_sha256")
    if type(packet_hash) is not str or packet_hash != external_conformance_packet_sha256(packet):
        raise _fail("EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE", "external conformance packet hash is absent or invalid")
    required = (
        "trust_policy",
        "trust_policy_sha256",
        "opening_witness_head",
        "witness_transition",
        "closing_witness_head",
    )
    if any(field not in artifact_kwargs for field in required):
        raise _fail("EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE", "external conformance packet revalidation inputs are incomplete")
    policy = validate_trust_policy(
        artifact_kwargs["trust_policy"],
        expected_sha256=artifact_kwargs["trust_policy_sha256"],
    )
    opening_envelope = artifact_kwargs["opening_witness_head"]
    transition_envelope = artifact_kwargs["witness_transition"]
    closing_envelope = artifact_kwargs["closing_witness_head"]
    try:
        opening_nonce = opening_envelope["payload"]["response_nonce"]
        closing_nonce = closing_envelope["payload"]["response_nonce"]
    except (KeyError, TypeError) as exc:
        raise _fail("EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE", "witness head packet binding is malformed") from exc
    transition = validate_witness_transition(transition_envelope, policy=policy)
    acquisition = WitnessAcquisition(
        opening_head_envelope=opening_envelope,
        opening_head=validate_witness_head(
            opening_envelope,
            policy=policy,
            expected_response_nonce=opening_nonce,
        ),
        transition=transition,
        closing_head=validate_witness_head(
            closing_envelope,
            policy=policy,
            expected_response_nonce=closing_nonce,
        ),
        closing_head_envelope=closing_envelope,
        transition_envelope=transition_envelope,
    )
    revalidation_inputs = dict(artifact_kwargs)
    revalidation_inputs.pop("live_witness_acquisition", None)
    revalidation_inputs.pop("live_time_acquisition", None)
    time_acquisition = TrustedTimeAcquisition(
        opening_receipts=tuple(revalidation_inputs["opening_time_receipts"]),
        closing_receipts=tuple(revalidation_inputs["closing_time_receipts"]),
    )
    expected = verify_population_trust(
        **revalidation_inputs,
        live_witness_acquisition=acquisition,
        live_time_acquisition=time_acquisition,
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(packet):
        raise _fail("EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE", "packet content differs from independent recomputation")
    return {
        "schema": "eval.v6.2.6.external-conformance-revalidation",
        "state": "EXTERNAL_CONFORMANCE_PACKET_REVALIDATED_NO_NEW_AUTHORITY",
        "external_conformance_packet_sha256": packet_hash,
        "local_process_output_authoritative": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
    }


def assess_production_population_trust(**kwargs: Any) -> dict[str, Any]:
    if PINNED_EXTERNAL_TRUST_POLICY is None or PINNED_EXTERNAL_TRUST_POLICY_SHA256 is None:
        return fail_closed_verdict(
            "BOOTSTRAP_CONFIG_ABSENT",
            reason="v6.2.6 has no separately reviewed code-pinned external trust policy",
        )
    return assess_population_trust(
        trust_policy=PINNED_EXTERNAL_TRUST_POLICY,
        trust_policy_sha256=PINNED_EXTERNAL_TRUST_POLICY_SHA256,
        **kwargs,
    )


__all__ = [
    "DOMAIN_VERIFIER_RECEIPT",
    "DOMAIN_CONFORMANCE_PACKET",
    "CONFORMANCE_PACKET_SCHEMA",
    "PINNED_EXTERNAL_TRUST_POLICY",
    "PINNED_EXTERNAL_TRUST_POLICY_SHA256",
    "REQUIRED_CHECK_VECTOR",
    "ReleaseV626Error",
    "V626_FAILURE_STATES",
    "VERDICT_SCHEMA",
    "VERIFIER_ENVELOPE_SCHEMA",
    "VERIFIER_RECEIPT_SCHEMA",
    "assess_population_trust",
    "assess_production_population_trust",
    "external_conformance_packet_sha256",
    "verify_external_conformance_packet",
    "verify_population_trust",
]
