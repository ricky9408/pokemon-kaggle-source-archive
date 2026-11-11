from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_2 import provisioning_v626 as provisioning
from evaluation_v6_2 import evidence_v626 as evidence
from evaluation_v6_2 import trust_v626 as trust
from evaluation_v6_2.integration_v622 import (
    canonical_json_bytes,
    canonical_json_loads,
    canonical_sha256,
)
from tests.test_evaluation_v6_2_release_v626 import (
    _GraphBuilder,
    _authority,
    _build_fixture as _trust_fixture,
    _digest,
    _key,
    _key_id,
    _sign,
)


@dataclass
class ProvisioningFixture:
    kwargs: dict[str, Any]
    packet: dict[str, Any]
    reviewer_private: dict[str, Ed25519PrivateKey]


def _payload(
    label: str,
    service_id: str,
    artifact_node_id: str,
) -> dict[str, str]:
    return {
        "schema": provisioning.SERVICE_CUSTODY_EVIDENCE_SCHEMA,
        "service_id": service_id,
        "evidence_kind": label,
        "artifact_node_id": artifact_node_id,
    }


def _build_provisioning_fixture(
    *,
    endpoint_binding_tamper: bool = False,
    custody_service_binding_tamper: bool = False,
    runtime_service_binding_tamper: bool = False,
    open_review_finding: bool = False,
    root_metadata_tamper: bool = False,
    wrong_custody_edge_relation: bool = False,
    omit_audit_retention: bool = False,
    noncanonical_endpoint: bool = False,
    runtime_trust_alias: bool = False,
    reviewer_key_alias: bool = False,
    reviewer_identity_signature_tamper: bool = False,
    reviewer_service_alias: bool = False,
) -> ProvisioningFixture:
    trust_fixture = _trust_fixture()
    policy = deepcopy(trust_fixture.policy)
    policy_sha = canonical_sha256(policy)
    reviewer_private = {
        f"reviewer-{index}": _key(f"v626-custody-reviewer-{index}")
        for index in range(3)
    }
    if reviewer_key_alias:
        reviewer_private["reviewer-0"] = trust_fixture.private["log"]
    reviewer_authorities = [
        _authority(
            reviewer_private[f"reviewer-{index}"],
            provisioning.ROLE_CUSTODY_REVIEWER,
            f"custody-reviewer-{index}",
        )
        for index in range(3)
    ]
    if reviewer_service_alias:
        reviewer_authorities[0]["organization_id"] = policy["log_authority"]["organization_id"]
    reviewer_key_by_id = {
        authority["key_id"]: reviewer_private[f"reviewer-{index}"]
        for index, authority in enumerate(reviewer_authorities)
    }
    reviewer_authorities.sort(key=lambda authority: authority["key_id"])

    authorities = [
        policy["log_authority"],
        *policy["witness_cosigner_authorities"],
        *policy["time_authorities"],
        *policy["verifier_authorities"],
        *policy["identity_issuer_authorities"],
    ]
    roster: list[dict[str, Any]] = []
    for authority in authorities:
        roster.append(
            {
                "role": authority["role"],
                "authority_key_id": authority["key_id"],
                "subject_id": authority["subject_id"],
                "control_group_id": authority["control_group_id"],
                "organization_id": authority["organization_id"],
            }
        )
    for index in range(2):
        alias = runtime_trust_alias and index == 0
        roster.append(
            {
                "role": provisioning.ROLE_RUNTIME_CUSTODIAN,
                "authority_key_id": None,
                "subject_id": (
                    policy["log_authority"]["subject_id"]
                    if alias
                    else f"subject-runtime-custodian-{index}"
                ),
                "control_group_id": (
                    policy["log_authority"]["control_group_id"]
                    if alias
                    else f"control-runtime-custodian-{index}"
                ),
                "organization_id": (
                    policy["log_authority"]["organization_id"]
                    if alias
                    else f"organization-runtime-custodian-{index}"
                ),
            }
        )
    roster.sort(key=lambda item: (item["role"], item["subject_id"]))

    builder = _GraphBuilder(policy["evidence_policy_sha256"])

    def source_artifact(service_id: str, evidence_kind: str, document: bytes) -> str:
        return builder.add(
            "CUSTODY_SOURCE_ARTIFACT",
            payload={
                "schema": provisioning.CUSTODY_SOURCE_ARTIFACT_SCHEMA,
                "service_id": service_id,
                "evidence_kind": evidence_kind,
                "media_type": "application/octet-stream",
                "document_base64": base64.b64encode(document).decode("ascii"),
                "document_sha256": hashlib.sha256(document).hexdigest(),
            },
        )

    service_records: list[dict[str, Any]] = []
    for index, item in enumerate(roster):
        service_id = f"svc-{index:02d}-{item['role'].lower().replace('_', '-')}"
        endpoint = (
            f"urn:runtime-custodian:{index}"
            if item["role"] == provisioning.ROLE_RUNTIME_CUSTODIAN
            else (
                f"https://authority-{index}.independent.example/v626/"
                if noncanonical_endpoint and index == 0
                else f"https://authority-{index}.independent.example/v626"
            )
        )
        endpoint_document = f"endpoint-certificate-or-key:{service_id}:{endpoint}".encode()
        endpoint_pin = hashlib.sha256(endpoint_document).hexdigest()
        child_types = set(provisioning._CUSTODY_CHILD_TYPES)
        if item["role"] != provisioning.ROLE_RUNTIME_CUSTODIAN:
            child_types.add("SIGNING_KEY_CUSTODY_EVIDENCE")
        custody_children: list[str] = []
        for node_type in sorted(child_types):
            if omit_audit_retention and index == 0 and node_type == "AUDIT_LOG_RETENTION_EVIDENCE":
                continue
            if node_type == "ENDPOINT_PIN_EVIDENCE":
                artifact_node_id = source_artifact(
                    service_id,
                    node_type,
                    endpoint_document,
                )
                payload = {
                    "schema": provisioning.ENDPOINT_PIN_EVIDENCE_SCHEMA,
                    "service_id": service_id,
                    "endpoint_uri": endpoint,
                    "endpoint_pin_sha256": (
                        _digest("incorrect-endpoint-pin")
                        if endpoint_binding_tamper and index == 0
                        else endpoint_pin
                    ),
                    "certificate_or_key_artifact_node_id": artifact_node_id,
                }
            else:
                payload_service_id = (
                    "svc-incorrect"
                    if custody_service_binding_tamper and index == 0
                    else service_id
                )
                artifact_node_id = source_artifact(
                    service_id,
                    node_type,
                    f"custody-document:{service_id}:{node_type}".encode(),
                )
                payload = _payload(node_type, payload_service_id, artifact_node_id)
            custody_children.append(
                builder.add(node_type, payload=payload, children=[artifact_node_id])
            )
        custody_root = builder.add(
            "SERVICE_CUSTODY_ROOT",
            children=custody_children,
            metadata={
                "service_id": (
                    "svc-incorrect"
                    if root_metadata_tamper and index == 0
                    else service_id
                )
            },
        )
        runtime_documents = {
            "SERVICE_SOURCE_REVISION": f"source:{service_id}".encode(),
            "SERVICE_BUILD_MANIFEST": f"build:{service_id}".encode(),
            "SERVICE_DEPLOYMENT_MANIFEST": f"deployment:{service_id}".encode(),
            "SERVICE_RUNTIME_CONFIGURATION": f"runtime-config:{service_id}".encode(),
        }
        runtime_artifact_nodes = [
            source_artifact(service_id, kind, document)
            for kind, document in runtime_documents.items()
        ]
        runtime_root = builder.add(
            "SERVICE_RUNTIME_MANIFEST",
            children=runtime_artifact_nodes,
            payload={
                "schema": provisioning.SERVICE_RUNTIME_MANIFEST_SCHEMA,
                "service_id": (
                    "svc-incorrect"
                    if runtime_service_binding_tamper and index == 0
                    else service_id
                ),
                "source_revision_sha256": hashlib.sha256(
                    runtime_documents["SERVICE_SOURCE_REVISION"]
                ).hexdigest(),
                "build_manifest_sha256": hashlib.sha256(
                    runtime_documents["SERVICE_BUILD_MANIFEST"]
                ).hexdigest(),
                "deployment_manifest_sha256": hashlib.sha256(
                    runtime_documents["SERVICE_DEPLOYMENT_MANIFEST"]
                ).hexdigest(),
                "runtime_configuration_sha256": hashlib.sha256(
                    runtime_documents["SERVICE_RUNTIME_CONFIGURATION"]
                ).hexdigest(),
            },
        )
        service_records.append(
            {
                "schema": provisioning.SERVICE_RECORD_SCHEMA,
                "service_id": service_id,
                "role": item["role"],
                "authority_key_id": item["authority_key_id"],
                "subject_id": item["subject_id"],
                "control_group_id": item["control_group_id"],
                "organization_id": item["organization_id"],
                "endpoint_uri": endpoint,
                "endpoint_pin_sha256": endpoint_pin,
                "custody_evidence_root_sha256": custody_root,
                "service_runtime_manifest_root_sha256": runtime_root,
            }
        )
    service_records.sort(key=lambda item: item["service_id"])
    reviewer_identity_roots: list[dict[str, str]] = []
    issuer_authorities = policy["identity_issuer_authorities"]
    for reviewer_index, reviewer in enumerate(reviewer_authorities):
        issuer_index = reviewer_index % len(issuer_authorities)
        issuer = issuer_authorities[issuer_index]
        identity_service_id = f"reviewer:{reviewer['key_id']}"
        identity_artifact = source_artifact(
            identity_service_id,
            "CUSTODY_REVIEWER_IDENTITY",
            f"reviewer-identity-document:{reviewer['key_id']}".encode(),
        )
        identity_payload = {
            "schema": provisioning.CUSTODY_REVIEWER_IDENTITY_SCHEMA,
            "candidate_trust_policy_sha256": policy_sha,
            "reviewer_key_id": reviewer["key_id"],
            "reviewer_subject_id": reviewer["subject_id"],
            "reviewer_control_group_id": reviewer["control_group_id"],
            "reviewer_organization_id": reviewer["organization_id"],
            "issuer_key_id": issuer["key_id"],
            "identity_artifact_node_id": identity_artifact,
            "issued_at_utc": f"2026-07-16T11:{reviewer_index:02d}:00Z",
        }
        identity_root = builder.add(
            "CUSTODY_REVIEWER_IDENTITY_BINDING",
            children=[identity_artifact],
            metadata={"reviewer_key_id": reviewer["key_id"]},
            payload={
                "schema": provisioning.CUSTODY_REVIEWER_IDENTITY_ENVELOPE_SCHEMA,
                "payload": identity_payload,
                "signature_base64": _sign(
                    (
                        _key("incorrect-reviewer-identity-issuer")
                        if reviewer_identity_signature_tamper and reviewer_index == 0
                        else trust_fixture.private[f"issuer-{issuer_index}"]
                    ),
                    provisioning.DOMAIN_CUSTODY_REVIEWER_IDENTITY,
                    identity_payload,
                ),
            },
        )
        reviewer_identity_roots.append(
            {
                "reviewer_key_id": reviewer["key_id"],
                "identity_root_sha256": identity_root,
            }
        )
    findings_roots: dict[tuple[str, int], str] = {}
    for service in service_records:
        service_sha = canonical_sha256(service)
        for reviewer_index in range(2):
            reviewer = reviewer_authorities[reviewer_index]
            findings_roots[(service_sha, reviewer_index)] = builder.add(
                "CUSTODY_REVIEW_FINDINGS",
                payload={
                    "schema": provisioning.CUSTODY_REVIEW_FINDINGS_SCHEMA,
                    "service_record_sha256": service_sha,
                    "reviewer_key_id": reviewer["key_id"],
                    "verdict": "PASS",
                    "findings": (
                        ["unresolved custody finding"]
                        if open_review_finding
                        and service is service_records[0]
                        and reviewer_index == 0
                        else []
                    ),
                },
            )
    nodes, edges, manifest, payloads, graph_root = builder.files()
    if wrong_custody_edge_relation:
        first_custody_root = service_records[0]["custody_evidence_root_sha256"]
        edge_items = [
            canonical_json_loads(line)
            for line in edges.removesuffix(b"\n").split(b"\n")
        ]
        target = next(item for item in edge_items if item["from_node_id"] == first_custody_root)
        target["relation"] = "BINDS"
        edge_items.sort(
            key=lambda item: (
                item["from_node_id"],
                item["relation"],
                item["to_node_id"],
                item["policy_clause"],
            )
        )
        edges = b"".join(canonical_json_bytes(item) + b"\n" for item in edge_items)
        graph_root = evidence.evidence_graph_root(nodes, edges, manifest)

    reviews: list[dict[str, Any]] = []
    review_challenge = _digest("v626-provisioning-review-challenge")
    for service in service_records:
        service_sha = canonical_sha256(service)
        for reviewer_index in range(2):
            authority = reviewer_authorities[reviewer_index]
            payload = {
                "schema": provisioning.CUSTODY_REVIEW_SCHEMA,
                "candidate_trust_policy_sha256": policy_sha,
                "evidence_graph_root_sha256": graph_root,
                "service_record_sha256": service_sha,
                "reviewer_key_id": authority["key_id"],
                "reviewer_subject_id": authority["subject_id"],
                "reviewer_control_group_id": authority["control_group_id"],
                "reviewer_organization_id": authority["organization_id"],
                "review_challenge_sha256": review_challenge,
                "reviewed_at_utc": f"2026-07-16T12:{reviewer_index:02d}:00Z",
                "verdict": "PASS",
                "findings_root_sha256": findings_roots[(service_sha, reviewer_index)],
            }
            reviews.append(
                {
                    "schema": provisioning.CUSTODY_REVIEW_ENVELOPE_SCHEMA,
                    "payload": payload,
                    "signature_base64": _sign(
                        reviewer_key_by_id[authority["key_id"]],
                        provisioning.DOMAIN_CUSTODY_REVIEW,
                        payload,
                    ),
                }
            )
    reviews.sort(
        key=lambda envelope: (
            envelope["payload"]["service_record_sha256"],
            envelope["payload"]["reviewer_key_id"],
        )
    )
    packet = {
        "schema": provisioning.PROVISIONING_PACKET_SCHEMA,
        "candidate_trust_policy_sha256": policy_sha,
        "evidence_graph_root_sha256": graph_root,
        "custody_reviewer_authorities": reviewer_authorities,
        "custody_reviewer_identity_root_sha256s": reviewer_identity_roots,
        "custody_reviewer_quorum": "2",
        "review_challenge_sha256": review_challenge,
        "service_records": service_records,
        "custody_review_envelopes": reviews,
    }
    return ProvisioningFixture(
        kwargs={
            "candidate_trust_policy": policy,
            "candidate_trust_policy_sha256": policy_sha,
            "provisioning_packet": packet,
            "nodes_jsonl": nodes,
            "edges_jsonl": edges,
            "payload_manifest_jsonl": manifest,
            "payloads": payloads,
        },
        packet=packet,
        reviewer_private=reviewer_private,
    )


@pytest.fixture
def provisioning_fixture() -> ProvisioningFixture:
    return _build_provisioning_fixture()


def _assert_no_authority(verdict: dict[str, Any]) -> None:
    assert verdict["candidate_policy_pinned"] is False
    assert verdict["external_authentication_verified"] is False
    assert verdict["population_feasible"] is False
    assert verdict["recruitment_intake_authorized"] is False
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["permits"] == []
    assert verdict["sealed_holdout_accessed"] is False
    assert verdict["local_process_output_authoritative"] is False


def test_complete_candidate_package_only_opens_independent_pin_review(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    verdict = provisioning.verify_external_provisioning_readiness(
        **provisioning_fixture.kwargs
    )
    assert (
        verdict["state"]
        == "CANDIDATE_EXTERNAL_SERVICES_PACKET_STRUCTURALLY_COMPLETE_REQUIRES_LIVE_CHALLENGE_AND_POLICY_PIN_REVIEW"
    )
    assert verdict["service_count"] == 14
    assert verdict["provisioning_evidence_complete"] is False
    assert verdict["offline_packet_structurally_complete"] is True
    assert verdict["underlying_custody_artifacts_closed"] is True
    assert verdict["review_challenge_single_use_verified"] is False
    assert verdict["candidate_policy_ready_for_independent_review"] is True
    _assert_no_authority(verdict)


def test_current_status_is_evidence_absent_and_no_authority() -> None:
    verdict = provisioning.current_external_provisioning_status()
    assert verdict["state"] == "EXTERNAL_PROVISIONING_EVIDENCE_ABSENT"
    _assert_no_authority(verdict)


def test_missing_service_fails_role_roster(provisioning_fixture: ProvisioningFixture) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    kwargs["provisioning_packet"]["service_records"].pop()
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] == "SERVICE_ROSTER_INCOMPLETE"
    _assert_no_authority(verdict)


def test_endpoint_evidence_mismatch_fails_closed() -> None:
    fixture = _build_provisioning_fixture(endpoint_binding_tamper=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE"
    _assert_no_authority(verdict)


@pytest.mark.parametrize(
    "fixture",
    [
        lambda: _build_provisioning_fixture(custody_service_binding_tamper=True),
        lambda: _build_provisioning_fixture(runtime_service_binding_tamper=True),
    ],
)
def test_service_specific_evidence_cannot_be_reused_across_services(fixture: Any) -> None:
    verdict = provisioning.assess_external_provisioning_readiness(**fixture().kwargs)
    assert verdict["state"] == "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE"
    _assert_no_authority(verdict)


@pytest.mark.parametrize(
    "fixture",
    [
        lambda: _build_provisioning_fixture(root_metadata_tamper=True),
        lambda: _build_provisioning_fixture(wrong_custody_edge_relation=True),
        lambda: _build_provisioning_fixture(omit_audit_retention=True),
    ],
)
def test_custody_root_requires_exact_service_bound_closure(fixture: Any) -> None:
    verdict = provisioning.assess_external_provisioning_readiness(**fixture().kwargs)
    assert verdict["state"] == "SERVICE_CUSTODY_EVIDENCE_INCOMPLETE"
    _assert_no_authority(verdict)


def test_service_endpoint_must_be_canonical() -> None:
    fixture = _build_provisioning_fixture(noncanonical_endpoint=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "PROVISIONING_PACKET_INVALID"
    _assert_no_authority(verdict)


def test_reviewer_service_organization_alias_fails() -> None:
    fixture = _build_provisioning_fixture(reviewer_service_alias=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "CUSTODY_SEPARATION_INVALID"
    _assert_no_authority(verdict)


def test_runtime_custodian_cannot_alias_trust_authority() -> None:
    fixture = _build_provisioning_fixture(runtime_trust_alias=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "CUSTODY_SEPARATION_INVALID"
    _assert_no_authority(verdict)


def test_custody_reviewer_key_cannot_alias_trust_authority() -> None:
    fixture = _build_provisioning_fixture(reviewer_key_alias=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "CUSTODY_SEPARATION_INVALID"
    _assert_no_authority(verdict)


def test_reviewer_identity_requires_candidate_issuer_signature() -> None:
    fixture = _build_provisioning_fixture(reviewer_identity_signature_tamper=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "CUSTODY_SEPARATION_INVALID"
    _assert_no_authority(verdict)


def test_reviewer_roster_must_be_canonically_sorted(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    kwargs["provisioning_packet"]["custody_reviewer_authorities"].reverse()
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] == "PROVISIONING_PACKET_INVALID"
    _assert_no_authority(verdict)


def test_missing_review_and_signature_tamper_fail_quorum(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    missing = deepcopy(provisioning_fixture.kwargs)
    first_service_sha = canonical_sha256(
        missing["provisioning_packet"]["service_records"][0]
    )
    missing["provisioning_packet"]["custody_review_envelopes"] = [
        review
        for review in missing["provisioning_packet"]["custody_review_envelopes"]
        if not (
            review["payload"]["service_record_sha256"] == first_service_sha
            and review["payload"]["reviewer_key_id"]
            == missing["provisioning_packet"]["custody_reviewer_authorities"][1]["key_id"]
        )
    ]
    missing_verdict = provisioning.assess_external_provisioning_readiness(**missing)
    assert missing_verdict["state"] == "CUSTODY_REVIEW_QUORUM_INVALID"

    tampered = deepcopy(provisioning_fixture.kwargs)
    tampered["provisioning_packet"]["custody_review_envelopes"][0][
        "signature_base64"
    ] = base64.b64encode(b"\0" * 64).decode("ascii")
    tampered_verdict = provisioning.assess_external_provisioning_readiness(**tampered)
    assert tampered_verdict["state"] == "CUSTODY_REVIEW_QUORUM_INVALID"
    _assert_no_authority(tampered_verdict)


def test_open_review_finding_cannot_be_presented_as_clean_pass() -> None:
    fixture = _build_provisioning_fixture(open_review_finding=True)
    verdict = provisioning.assess_external_provisioning_readiness(**fixture.kwargs)
    assert verdict["state"] == "CUSTODY_REVIEW_QUORUM_INVALID"
    _assert_no_authority(verdict)


def test_review_cannot_be_replayed_under_a_different_packet_challenge(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    kwargs["provisioning_packet"]["review_challenge_sha256"] = _digest(
        "different-review-challenge"
    )
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] == "CUSTODY_REVIEW_QUORUM_INVALID"
    _assert_no_authority(verdict)


def test_service_record_must_match_candidate_policy(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    target = next(
        record
        for record in kwargs["provisioning_packet"]["service_records"]
        if record["role"] != provisioning.ROLE_RUNTIME_CUSTODIAN
    )
    target["subject_id"] = "subject-policy-mismatch"
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] == "SERVICE_POLICY_MISMATCH"
    _assert_no_authority(verdict)


def test_custody_payload_tamper_fails_graph_closure(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    digest = next(iter(kwargs["payloads"]))
    kwargs["payloads"][digest] += b"tamper"
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] == "EVIDENCE_GRAPH_HASH_MISMATCH"
    _assert_no_authority(verdict)


def test_underlying_custody_artifact_must_be_present_in_closed_manifest(
    provisioning_fixture: ProvisioningFixture,
) -> None:
    kwargs = deepcopy(provisioning_fixture.kwargs)
    digest = next(iter(kwargs["payloads"]))
    del kwargs["payloads"][digest]
    verdict = provisioning.assess_external_provisioning_readiness(**kwargs)
    assert verdict["state"] in {
        "EVIDENCE_GRAPH_DANGLING",
        "EVIDENCE_GRAPH_HASH_MISMATCH",
    }
    _assert_no_authority(verdict)


def test_every_failure_state_has_zero_authority() -> None:
    for state in provisioning.PROVISIONING_FAILURE_STATES:
        verdict = provisioning.fail_closed_provisioning_verdict(state, "test")
        _assert_no_authority(verdict)


def test_unknown_failure_label_cannot_create_a_misleading_state() -> None:
    verdict = provisioning.fail_closed_provisioning_verdict("SUBMIT_AUTHORIZED", "test")
    assert verdict["state"] == "PROVISIONING_PACKET_INVALID"
    _assert_no_authority(verdict)
