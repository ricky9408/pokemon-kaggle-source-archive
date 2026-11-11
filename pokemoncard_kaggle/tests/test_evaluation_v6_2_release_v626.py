from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evaluation_v6_2 import evidence_v626 as evidence
from evaluation_v6_2 import release_v625 as v625
from evaluation_v6_2 import release_v626 as release
from evaluation_v6_2 import trust_v626 as trust
from evaluation_v6_2.witness_client_v626 import WitnessAcquisition, acquire_witness_transition
from evaluation_v6_2.time_client_v626 import (
    TrustedTimeAcquisition,
    acquire_trusted_time_quorums,
)
from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_sha256


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key_id(private: Ed25519PrivateKey) -> str:
    return "ed25519-sha256:" + hashlib.sha256(_public(private)).hexdigest()


def _authority(private: Ed25519PrivateKey, role: str, label: str) -> dict[str, str]:
    public = _public(private)
    return {
        "schema": trust.AUTHORITY_SCHEMA,
        "key_id": "ed25519-sha256:" + hashlib.sha256(public).hexdigest(),
        "public_key_base64": base64.b64encode(public).decode("ascii"),
        "subject_id": f"subject-{label}",
        "role": role,
        "control_group_id": f"control-{label}",
        "organization_id": f"organization-{label}",
    }


def _sign(private: Ed25519PrivateKey, domain: bytes, payload: dict[str, Any]) -> str:
    message = domain + hashlib.sha256(canonical_json_bytes(payload)).digest()
    return base64.b64encode(private.sign(message)).decode("ascii")


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Fixture:
    kwargs: dict[str, Any]
    policy: dict[str, Any]
    private: dict[str, Ed25519PrivateKey]


class _GraphBuilder:
    def __init__(self, policy_sha256: str) -> None:
        self.policy_sha256 = policy_sha256
        self.nodes: dict[str, dict[str, Any]] = {}
        self.payloads: dict[str, bytes] = {}
        self.media_types: dict[str, str] = {}

    def add(
        self,
        node_type: str,
        *,
        children: list[str] | None = None,
        payload: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        producer_subject_id: str | None = None,
        producer_role: str | None = None,
        slot_id: str | None = None,
        pair_id: str | None = None,
        unit_nonce: str | None = None,
    ) -> str:
        payload_bytes = canonical_json_bytes(payload) if payload is not None else None
        payload_sha = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes is not None else None
        if payload_bytes is not None:
            self.payloads[payload_sha] = payload_bytes
            self.media_types[payload_sha] = "application/json"
        node = {
            "schema": evidence.EVIDENCE_NODE_SCHEMA,
            "node_id": "0" * 64,
            "node_type": node_type,
            "policy_sha256": self.policy_sha256,
            "payload_sha256": payload_sha,
            "payload_byte_length": str(len(payload_bytes)) if payload_bytes is not None else None,
            "producer_subject_id": producer_subject_id,
            "producer_role": producer_role,
            "slot_id": slot_id,
            "pair_id": pair_id,
            "unit_nonce": unit_nonce,
            "child_node_ids": sorted(children or []),
            "metadata": metadata or {},
        }
        node["node_id"] = evidence.evidence_node_id(node)
        self.nodes[node["node_id"]] = node
        return node["node_id"]

    def files(self) -> tuple[bytes, bytes, bytes, dict[str, bytes], str]:
        nodes = [self.nodes[key] for key in sorted(self.nodes)]
        edges: list[dict[str, Any]] = []
        for node in nodes:
            for child in node["child_node_ids"]:
                edges.append(
                    {
                        "schema": evidence.EVIDENCE_EDGE_SCHEMA,
                        "from_node_id": node["node_id"],
                        "relation": "CONTAINS",
                        "to_node_id": child,
                        "policy_clause": "v6.2.6-closed-graph",
                    }
                )
        edges.sort(key=lambda item: (item["from_node_id"], item["relation"], item["to_node_id"], item["policy_clause"]))
        manifest = [
            {
                "schema": evidence.EVIDENCE_PAYLOAD_SCHEMA,
                "payload_sha256": digest,
                "payload_byte_length": str(len(self.payloads[digest])),
                "media_type": self.media_types[digest],
            }
            for digest in sorted(self.payloads)
        ]
        jsonl = lambda values: b"".join(canonical_json_bytes(value) + b"\n" for value in values)
        nodes_bytes = jsonl(nodes)
        edges_bytes = jsonl(edges)
        manifest_bytes = jsonl(manifest)
        root = evidence.evidence_graph_root(nodes_bytes, edges_bytes, manifest_bytes)
        return nodes_bytes, edges_bytes, manifest_bytes, dict(self.payloads), root


def _runtime_nodes(builder: _GraphBuilder, index: int) -> tuple[str, str, str, str, str, str]:
    def manifest(kind: str) -> dict[str, Any]:
        return {
            "schema": "eval.v6.2.6.hash-manifest",
            "kind": kind,
            "entries": [
                {
                    "name": f"{kind.lower()}-{index}",
                    "sha256": _digest(f"{kind}-{index}"),
                    "byte_length": "32",
                }
            ],
        }

    python_root = builder.add("PYTHON_MODULE_MANIFEST", payload=manifest("PYTHON_MODULE_MANIFEST"), metadata={"index": index})
    native_root = builder.add("NATIVE_LIBRARY_MANIFEST", payload=manifest("NATIVE_LIBRARY_MANIFEST"), metadata={"index": index})
    crypto_root = builder.add("CRYPTO_LIBRARY_MANIFEST", payload=manifest("CRYPTO_LIBRARY_MANIFEST"), metadata={"index": index})
    config_root = builder.add("POLICY_CONFIG_MANIFEST", payload=manifest("POLICY_CONFIG_MANIFEST"), metadata={"index": index})
    env_allow_root = builder.add("ENVIRONMENT_ALLOWLIST", payload=manifest("ENVIRONMENT_ALLOWLIST"), metadata={"index": index})
    network_root = builder.add("NETWORK_ENDPOINT_POLICY", payload=manifest("NETWORK_ENDPOINT_POLICY"), metadata={"index": index})
    return python_root, native_root, crypto_root, config_root, env_allow_root, network_root


def _build_fixture(
    *,
    runtime_custodian_alias: bool = False,
    component_id_tamper: bool = False,
    derivation_stage_violation: bool = False,
    unpinned_identity_issuer: bool = False,
) -> Fixture:
    private = {
        "log": _key("v626-log"),
        **{f"witness-{index}": _key(f"v626-witness-{index}") for index in range(3)},
        **{f"time-{index}": _key(f"v626-time-{index}") for index in range(3)},
        **{f"verifier-{index}": _key(f"v626-verifier-{index}") for index in range(3)},
        **{f"issuer-{index}": _key(f"v626-issuer-{index}") for index in range(2)},
    }
    evidence_policy_sha = _digest("v626-evidence-policy")
    policy = {
        "schema": trust.TRUST_POLICY_SCHEMA,
        "namespace": "pokemon-population-v626",
        "release_root_sha256": _digest("v626-release-root"),
        "release_sequence": "1",
        "previous_release_root_sha256": _digest("v625-retired-release-root"),
        "bootstrap_authorization_root_sha256": _digest("v626-bootstrap-authorization"),
        "witness_policy_sha256": _digest("v626-witness-policy"),
        "time_policy_sha256": _digest("v626-time-policy"),
        "evidence_policy_sha256": evidence_policy_sha,
        "runtime_tcb_policy_sha256": _digest("v626-runtime-tcb-policy"),
        "accepted_verifier_build_root_sha256": _digest("v626-verifier-build"),
        "project_control_group_ids": ["control-project-owner", "control-project-auditor"],
        "log_authority": _authority(private["log"], trust.ROLE_LOG_AUTHORITY, "log"),
        "witness_cosigner_authorities": [
            _authority(private[f"witness-{index}"], trust.ROLE_WITNESS_COSIGNER, f"witness-{index}")
            for index in range(3)
        ],
        "time_authorities": [
            _authority(private[f"time-{index}"], trust.ROLE_TIME_AUTHORITY, f"time-{index}")
            for index in range(3)
        ],
        "verifier_authorities": [
            _authority(private[f"verifier-{index}"], trust.ROLE_EXTERNAL_VERIFIER, f"verifier-{index}")
            for index in range(3)
        ],
        "identity_issuer_authorities": [
            _authority(private[f"issuer-{index}"], trust.ROLE_IDENTITY_ISSUER, f"issuer-{index}")
            for index in range(2)
        ],
        "witness_cosigner_quorum": "2",
        "time_authority_quorum": "2",
        "verifier_quorum": "2",
    }
    policy_sha = canonical_sha256(policy)
    builder = _GraphBuilder(evidence_policy_sha)
    campaign_root = builder.add("CAMPAIGN_BUNDLE")
    packet_root = builder.add("VERIFICATION_PACKET")

    pair_id = "pair-000"
    endpoints = ["slot-a", "slot-b"]
    reviewers = ["reviewer-a", "reviewer-b"]
    pair_children = [
        builder.add("LINEAGE_RECEIPT", pair_id=pair_id, slot_id=slot_id)
        for slot_id in endpoints
    ]
    pair_children.extend(
        builder.add(
            "INTERVENTION_RECEIPT",
            pair_id=pair_id,
            producer_subject_id=reviewer,
            producer_role="LINEAGE_AUDITOR",
        )
        for reviewer in reviewers
    )
    pair_children.extend(
        builder.add(node_type, pair_id=pair_id)
        for node_type in sorted(
            evidence.PAIR_REQUIRED_CHILD_TYPES
            - {"LINEAGE_RECEIPT", "INTERVENTION_RECEIPT"}
        )
    )
    pair_root = builder.add(
        "PAIR_ANALYSIS_ROOT",
        children=pair_children,
        pair_id=pair_id,
        metadata={
            "endpoint_slot_ids": endpoints,
            "required_reviewer_subject_ids": reviewers,
        },
    )

    issuer_authority = policy["identity_issuer_authorities"][0]
    issuer_key_id = (
        "ed25519-sha256:" + _digest("unapproved-identity-issuer")
        if unpinned_identity_issuer
        else issuer_authority["key_id"]
    )
    issuer = builder.add(
        "ISSUER_AUTHORITY_RECEIPT",
        metadata={
            "issuer_key_id": issuer_key_id,
            "issuer_subject_id": issuer_authority["subject_id"],
            "issuer_control_group_id": issuer_authority["control_group_id"],
            "issuer_organization_id": issuer_authority["organization_id"],
        },
    )
    identity_evidence = builder.add(
        "UNDERLYING_IDENTITY_EVIDENCE",
        children=[issuer],
        metadata={
            "assurance": "HIGH",
            "issuer_control_group_id": issuer_authority["control_group_id"],
        },
    )
    registry_record = builder.add("REGISTRY_RECORD")
    identity_binding = builder.add("IDENTITY_BINDING", children=[identity_evidence, registry_record])
    principal_root = builder.add("PRINCIPAL_ASSIGNMENT", children=[identity_binding])
    pair_classification_root = builder.add(
        "PAIR_CLASSIFICATION_GRAPH_ROOT",
        children=[pair_root],
    )
    assignment_nodes: list[str] = []
    for component_kind in ("SOURCE_FAMILY", "LINEAGE_TIME", "INTERVENTION_FAMILY"):
        component_id = evidence.component_assignment_id(
            component_kind=component_kind,
            member_slot_ids=endpoints,
            pair_classification_graph_root_sha256=pair_classification_root,
        )
        if component_id_tamper and component_kind == "SOURCE_FAMILY":
            component_id = "sf-" + "0" * 24
        assignment_nodes.append(
            builder.add(
                "COMPONENT_ASSIGNMENT",
                metadata={
                    "component_kind": component_kind,
                    "component_id": component_id,
                    "member_slot_ids": endpoints,
                    "pair_classification_graph_root_sha256": pair_classification_root,
                },
            )
        )
    evidence_input_children = [*pair_children, principal_root]
    if derivation_stage_violation:
        evidence_input_children.append(assignment_nodes[0])
    evidence_input_root = builder.add(
        "EVIDENCE_INPUT_GRAPH_ROOT",
        children=evidence_input_children,
    )
    component_assignment_root = builder.add(
        "COMPONENT_ASSIGNMENT_ROOT",
        children=assignment_nodes,
        metadata={
            "pair_classification_graph_root_sha256": pair_classification_root,
        },
    )
    population_root = builder.add(
        "POPULATION_DECISION_ROOT",
        children=[evidence_input_root, pair_classification_root, component_assignment_root],
        metadata={
            "evidence_input_graph_root_sha256": evidence_input_root,
            "pair_classification_graph_root_sha256": pair_classification_root,
            "component_assignment_root_sha256": component_assignment_root,
        },
    )

    runtime_roots: list[str] = []
    transcript_roots: list[str] = []
    environment_roots: list[str] = []
    session_values: list[tuple[str, str, str]] = []
    for index in range(2):
        custodian_index = 0 if runtime_custodian_alias and index == 1 else index
        support = _runtime_nodes(builder, index)
        runtime_payload = {
            "schema": evidence.RUNTIME_MANIFEST_SCHEMA,
            "verifier_source_commit_sha256": _digest(f"source-commit-{index}"),
            "verifier_source_tree_sha256": _digest(f"source-tree-{index}"),
            "entrypoint_module_sha256": _digest(f"entrypoint-{index}"),
            "transitive_python_manifest_root_sha256": support[0],
            "interpreter_executable_sha256": _digest(f"interpreter-{index}"),
            "interpreter_version": "CPython 3.11.13",
            "native_library_manifest_root_sha256": support[1],
            "dependency_lock_sha256": _digest(f"lock-{index}"),
            "cryptographic_library_manifest_root_sha256": support[2],
            "evidence_loader_sha256": _digest(f"loader-{index}"),
            "canonicalization_implementation_sha256": _digest(f"canonicalizer-{index}"),
            "container_image_digest": "sha256:" + _digest(f"container-{index}"),
            "kernel_declaration": "linux-6.8",
            "architecture": "linux/amd64",
            "policy_config_root_sha256": support[3],
            "command_line_sha256": _digest(f"command-{index}"),
            "working_directory_identity": f"workdir-{index}",
            "environment_allowlist_root_sha256": support[4],
            "network_endpoint_policy_root_sha256": support[5],
            "runtime_custodian_subject_id": f"runtime-subject-{custodian_index}",
            "runtime_custodian_control_group_id": f"runtime-control-{custodian_index}",
            "runtime_custodian_organization_id": f"runtime-organization-{custodian_index}",
            "accepted_verifier_build_root_sha256": policy["accepted_verifier_build_root_sha256"],
            "runtime_tcb_policy_sha256": policy["runtime_tcb_policy_sha256"],
        }
        runtime_root = builder.add("RUNTIME_MANIFEST", children=list(support), payload=runtime_payload)
        runtime_roots.append(runtime_root)
        session_id = f"session-{index}"
        authority_challenge = (f"{index + 1:02x}" * 16)
        verification_nonce = (f"{index + 17:02x}" * 16)
        events = [
            {
                "sequence": str(event_index),
                "event_type": event_type,
                "artifact_root_sha256": None,
                "detail_sha256": _digest(f"event-{index}-{event_index}"),
            }
            for event_index, event_type in enumerate(evidence.REQUIRED_TRANSCRIPT_EVENTS)
        ]
        transcript_payload = {
            "schema": evidence.EXECUTION_TRANSCRIPT_SCHEMA,
            "session_id": session_id,
            "authority_challenge": authority_challenge,
            "verification_nonce": verification_nonce,
            "runtime_manifest_root_sha256": runtime_root,
            "events": events,
        }
        transcript_root = builder.add("EXECUTION_TRANSCRIPT", children=[runtime_root], payload=transcript_payload)
        transcript_roots.append(transcript_root)
        environment_roots.append(
            builder.add(
                "ENVIRONMENT_ATTESTATION",
                payload={
                    "schema": "eval.v6.2.6.environment-attestation",
                    "index": str(index),
                    "environment_sha256": _digest(f"environment-{index}"),
                },
                metadata={"index": index},
            )
        )
        session_values.append((session_id, authority_challenge, verification_nonce))

    nodes_bytes, edges_bytes, manifest_bytes, payloads, graph_root = builder.files()
    challenge = _digest("v626-invocation-challenge")
    previous_leaf = hashlib.sha256(b"v626-previous-log-leaf").digest()
    previous_state = {
        "schema": trust.MONOTONIC_STATE_SCHEMA,
        "namespace": policy["namespace"],
        "release_root_sha256": policy["release_root_sha256"],
        "sequence": "7",
        "state_sha256": "0" * 64,
        "authorization_sequence": "4",
        "authorization_root_sha256": _digest("authorization-root"),
        "checkpoint_tree_size": "1",
        "checkpoint_root_sha256": previous_leaf.hex(),
        "registry_epoch": "5",
        "revocation_sequence": "3",
        "revocation_head_sha256": _digest("revocation-head"),
        "last_redeemed_challenge_sha256": _digest("previous-challenge"),
        "previous_state_sha256": _digest("state-six"),
    }
    previous_state["state_sha256"] = trust.monotonic_state_sha256(previous_state)
    request = {
        "schema": trust.REDEMPTION_REQUEST_SCHEMA,
        "namespace": policy["namespace"],
        "release_root_sha256": policy["release_root_sha256"],
        "expected_sequence": previous_state["sequence"],
        "expected_state_sha256": previous_state["state_sha256"],
        "invocation_challenge_sha256": challenge,
        "campaign_bundle_root_sha256": campaign_root,
        "evidence_graph_root_sha256": graph_root,
        "verification_packet_root_sha256": packet_root,
        "request_nonce": "ab" * 16,
    }
    request_leaf = hashlib.sha256(trust.DOMAIN_LOG_LEAF + canonical_json_bytes(request)).digest()
    new_root = v625._transparency_node_hash(previous_leaf, request_leaf)
    checkpoint = {
        "schema": trust.LOG_CHECKPOINT_SCHEMA,
        "log_id": "external-log-v626",
        "tree_size": "2",
        "root_sha256": new_root.hex(),
        "previous_tree_size": "1",
        "previous_root_sha256": previous_leaf.hex(),
        "leaf_index": "1",
        "leaf_sha256": request_leaf.hex(),
        "inclusion_proof": [previous_leaf.hex()],
        "consistency_proof": [request_leaf.hex()],
        "observed_at": "2026-07-16T10:00:30Z",
    }
    new_state = {
        **previous_state,
        "sequence": "8",
        "state_sha256": "0" * 64,
        "checkpoint_tree_size": checkpoint["tree_size"],
        "checkpoint_root_sha256": checkpoint["root_sha256"],
        "last_redeemed_challenge_sha256": challenge,
        "previous_state_sha256": previous_state["state_sha256"],
    }
    new_state["state_sha256"] = trust.monotonic_state_sha256(new_state)
    transition_payload = {
        "schema": trust.WITNESS_TRANSITION_SCHEMA,
        "previous_state": previous_state,
        "request": request,
        "new_state": new_state,
        "checkpoint": checkpoint,
    }
    transition = {
        "schema": trust.WITNESS_ENVELOPE_SCHEMA,
        "payload": transition_payload,
        "signatures": [
            {
                "key_id": _key_id(private[label]),
                "signature_base64": _sign(private[label], trust.DOMAIN_WITNESS_TRANSITION, transition_payload),
            }
            for label in ("log", "witness-0", "witness-1")
        ],
    }

    def witness_head(state: dict[str, Any], nonce: str) -> dict[str, Any]:
        payload = {
            "schema": trust.WITNESS_HEAD_SCHEMA,
            "namespace": policy["namespace"],
            "release_root_sha256": policy["release_root_sha256"],
            "state": deepcopy(state),
            "response_nonce": nonce,
        }
        return {
            "schema": trust.WITNESS_HEAD_ENVELOPE_SCHEMA,
            "payload": payload,
            "signatures": [
                {
                    "key_id": _key_id(private[label]),
                    "signature_base64": _sign(private[label], trust.DOMAIN_WITNESS_HEAD, payload),
                }
                for label in ("log", "witness-0", "witness-1")
            ],
        }

    opening_witness_head = witness_head(previous_state, "51" * 16)
    closing_witness_head = witness_head(new_state, "52" * 16)
    witness_validation = trust.validate_witness_transition(
        transition,
        policy=trust.validate_trust_policy(policy, expected_sha256=policy_sha),
    )
    parsed_policy = trust.validate_trust_policy(policy, expected_sha256=policy_sha)
    acquired_opening = deepcopy(opening_witness_head)
    acquired_transition = deepcopy(transition)
    acquired_closing = deepcopy(closing_witness_head)
    live_acquisition = WitnessAcquisition(
        opening_head_envelope=acquired_opening,
        opening_head=trust.validate_witness_head(
            acquired_opening,
            policy=parsed_policy,
            expected_response_nonce=acquired_opening["payload"]["response_nonce"],
        ),
        transition=witness_validation,
        closing_head=trust.validate_witness_head(
            acquired_closing,
            policy=parsed_policy,
            expected_response_nonce=acquired_closing["payload"]["response_nonce"],
        ),
        closing_head_envelope=acquired_closing,
        transition_envelope=acquired_transition,
    )

    checks = {name: True for name in release.REQUIRED_CHECK_VECTOR}
    receipt_envelopes: list[dict[str, Any]] = []
    for index in range(2):
        authority = policy["verifier_authorities"][index]
        receipt_payload = {
            "schema": release.VERIFIER_RECEIPT_SCHEMA,
            "verifier_authority_key_id": authority["key_id"],
            "verifier_authority_subject_id": authority["subject_id"],
            "verifier_authority_control_group_id": authority["control_group_id"],
            "verifier_authority_organization_id": authority["organization_id"],
            "release_root_sha256": policy["release_root_sha256"],
            "campaign_bundle_root_sha256": campaign_root,
            "evidence_graph_root_sha256": graph_root,
            "verification_packet_root_sha256": packet_root,
            "population_analysis_root_sha256": population_root,
            "runtime_manifest_root_sha256": runtime_roots[index],
            "execution_transcript_root_sha256": transcript_roots[index],
            "environment_attestation_root_sha256": environment_roots[index],
            "session_id": session_values[index][0],
            "authority_challenge": session_values[index][1],
            "verification_nonce": session_values[index][2],
            "registry_epoch": previous_state["registry_epoch"],
            "revocation_sequence": previous_state["revocation_sequence"],
            "revocation_head_sha256": previous_state["revocation_head_sha256"],
            "accepted_verifier_build_root_sha256": policy["accepted_verifier_build_root_sha256"],
            "runtime_tcb_policy_sha256": policy["runtime_tcb_policy_sha256"],
            "check_vector": checks,
        }
        receipt_envelopes.append(
            {
                "schema": release.VERIFIER_ENVELOPE_SCHEMA,
                "payload": receipt_payload,
                "signature_base64": _sign(private[f"verifier-{index}"], release.DOMAIN_VERIFIER_RECEIPT, receipt_payload),
            }
        )
    receipt_hashes = sorted(canonical_sha256(item) for item in receipt_envelopes)
    transition_sha = witness_validation.transition_sha256
    open_base = {
        "time_policy_sha256": policy["time_policy_sha256"],
        "release_root_sha256": policy["release_root_sha256"],
        "campaign_bundle_root_sha256": campaign_root,
        "invocation_challenge_sha256": challenge,
        "expected_witness_state_sha256": previous_state["state_sha256"],
        "expected_witness_sequence": previous_state["sequence"],
        "checkpoint_sha256": canonical_sha256(opening_witness_head),
        "checkpoint_tree_size": previous_state["checkpoint_tree_size"],
        "registry_epoch": previous_state["registry_epoch"],
        "revocation_sequence": previous_state["revocation_sequence"],
        "revocation_head_sha256": previous_state["revocation_head_sha256"],
    }
    close_base = {
        "time_policy_sha256": policy["time_policy_sha256"],
        "release_root_sha256": policy["release_root_sha256"],
        "campaign_bundle_root_sha256": campaign_root,
        "invocation_challenge_sha256": challenge,
        "checkpoint_sha256": witness_validation.checkpoint_sha256,
        "checkpoint_tree_size": str(witness_validation.checkpoint_tree_size),
        "registry_epoch": new_state["registry_epoch"],
        "revocation_sequence": new_state["revocation_sequence"],
        "revocation_head_sha256": new_state["revocation_head_sha256"],
        "witness_transition_sha256": transition_sha,
        "new_witness_state_sha256": new_state["state_sha256"],
        "comprehensive_verifier_receipt_sha256s": receipt_hashes,
        "transcript_root_sha256s": sorted(transcript_roots),
        "runtime_manifest_root_sha256s": sorted(runtime_roots),
        "evidence_graph_root_sha256": graph_root,
    }

    def time_receipts(schema: str, domain: bytes, base: dict[str, Any], start: datetime) -> list[dict[str, Any]]:
        receipts: list[dict[str, Any]] = []
        for index, offset in enumerate((0, 5)):
            authority = policy["time_authorities"][index]
            lower = start + timedelta(seconds=offset)
            upper = start + timedelta(seconds=20 + offset)
            payload = {
                "schema": schema,
                **base,
                "authority_key_id": authority["key_id"],
                "authority_subject_id": authority["subject_id"],
                "authority_control_group_id": authority["control_group_id"],
                "authority_organization_id": authority["organization_id"],
                "receipt_nonce": (f"{index + (32 if schema == trust.TIME_CLOSE_SCHEMA else 16):02x}" * 16),
                "time_lower_utc": _utc(lower),
                "time_upper_utc": _utc(upper),
            }
            receipts.append(
                {
                    "schema": trust.TIME_ENVELOPE_SCHEMA,
                    "payload": payload,
                    "signature_base64": _sign(private[f"time-{index}"], domain, payload),
                }
            )
        return receipts

    opening = time_receipts(
        trust.TIME_OPEN_SCHEMA,
        trust.DOMAIN_TIME_OPEN,
        open_base,
        datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc),
    )
    closing = time_receipts(
        trust.TIME_CLOSE_SCHEMA,
        trust.DOMAIN_TIME_CLOSE,
        close_base,
        datetime(2026, 7, 16, 10, 1, 0, tzinfo=timezone.utc),
    )
    live_time_acquisition = TrustedTimeAcquisition(
        opening_receipts=tuple(deepcopy(opening)),
        closing_receipts=tuple(deepcopy(closing)),
    )
    kwargs = {
        "trust_policy": policy,
        "trust_policy_sha256": policy_sha,
        "witness_transition": transition,
        "opening_witness_head": opening_witness_head,
        "closing_witness_head": closing_witness_head,
        "opening_time_receipts": opening,
        "closing_time_receipts": closing,
        "nodes_jsonl": nodes_bytes,
        "edges_jsonl": edges_bytes,
        "payload_manifest_jsonl": manifest_bytes,
        "payloads": payloads,
        "evidence_graph_root_sha256": graph_root,
        "campaign_bundle_root_sha256": campaign_root,
        "verification_packet_root_sha256": packet_root,
        "invocation_challenge_sha256": challenge,
        "population_analysis_root_sha256": population_root,
        "evidence_input_graph_root_sha256": evidence_input_root,
        "pair_classification_graph_root_sha256": pair_classification_root,
        "component_assignment_root_sha256": component_assignment_root,
        "pair_analysis_root_sha256s": [pair_root],
        "principal_assignment_root_sha256s": [principal_root],
        "verification_receipts": receipt_envelopes,
        "live_witness_acquisition": live_acquisition,
        "live_time_acquisition": live_time_acquisition,
    }
    return Fixture(kwargs=kwargs, policy=policy, private=private)


@pytest.fixture
def v626_fixture() -> Fixture:
    return _build_fixture()


def test_synthetic_external_services_reach_non_authoritative_positive_state(v626_fixture: Fixture) -> None:
    verdict = release.verify_population_trust(**v626_fixture.kwargs)
    assert verdict["state"] == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING"
    assert verdict["external_authentication_verified"] is True
    assert verdict["semantic_artifact_verification_complete"] is True
    assert verdict["population_feasible"] is True
    assert verdict["population_feasible_under_pinned_policy"] is True
    assert verdict["independence_ground_truth_proven"] is False
    assert verdict["independent_runtime_execution_cryptographically_proven"] is False
    assert verdict["physical_host_separation_proven"] is False
    assert verdict["absence_of_verifier_collusion_proven"] is False
    assert verdict["runtime_tcb_loaded_state_cryptographically_proven"] is False
    assert verdict["local_process_output_authoritative"] is False
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["permits"] == []
    assert verdict["sealed_holdout_accessed"] is False
    assert verdict["external_conformance_packet_sha256"] == release.external_conformance_packet_sha256(verdict)

    revalidated = release.verify_external_conformance_packet(
        verdict,
        **v626_fixture.kwargs,
    )
    assert revalidated["state"] == "EXTERNAL_CONFORMANCE_PACKET_REVALIDATED_NO_NEW_AUTHORITY"
    assert revalidated["local_process_output_authoritative"] is False
    assert revalidated["calibration_upload_authorized"] is False
    assert revalidated["production_upload_authorized"] is False


def test_production_path_is_closed_without_literal_policy(v626_fixture: Fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "PINNED_EXTERNAL_TRUST_POLICY", None)
    monkeypatch.setattr(release, "PINNED_EXTERNAL_TRUST_POLICY_SHA256", None)
    kwargs = dict(v626_fixture.kwargs)
    kwargs.pop("trust_policy")
    kwargs.pop("trust_policy_sha256")
    verdict = release.assess_production_population_trust(**kwargs)
    assert verdict["state"] == "BOOTSTRAP_CONFIG_ABSENT"
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False


def test_signed_time_files_without_live_time_acquisition_fail(v626_fixture: Fixture) -> None:
    kwargs = dict(v626_fixture.kwargs)
    kwargs.pop("live_time_acquisition")
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "LIVE_EXTERNAL_STATE_NOT_ACQUIRED"
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False


def test_forged_local_positive_boolean_is_not_an_external_packet(v626_fixture: Fixture) -> None:
    forged = {
        "schema": release.CONFORMANCE_PACKET_SCHEMA,
        "state": "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING",
        "population_feasible": True,
    }
    with pytest.raises(release.ReleaseV626Error) as exc:
        release.verify_external_conformance_packet(forged, **v626_fixture.kwargs)
    assert exc.value.code == "EXTERNAL_CONFORMANCE_PACKET_INCOMPLETE"


def test_runtime_policy_mutation_cannot_change_external_policy_digest(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    kwargs["trust_policy"]["project_control_group_ids"].append("control-mutated-process")
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "RELEASE_ROOT_UNAUTHORIZED"


def test_principal_identity_chain_must_end_in_pinned_issuer() -> None:
    fixture = _build_fixture(unpinned_identity_issuer=True)
    verdict = release.assess_population_trust(**fixture.kwargs)
    assert verdict["state"] == "PRINCIPAL_IDENTITY_EVIDENCE_INSUFFICIENT"


@pytest.mark.parametrize(
    ("mutator", "expected_state"),
    [
        (lambda value: value["witness_transition"]["payload"]["request"].__setitem__("expected_sequence", "6"), "MONOTONIC_CAS_REJECTED"),
        (lambda value: value["witness_transition"]["payload"]["new_state"].__setitem__("last_redeemed_challenge_sha256", _digest("other")), "MONOTONIC_CAS_REJECTED"),
        (lambda value: value["witness_transition"]["signatures"].pop(), "WITNESS_QUORUM_DISAGREEMENT"),
        (lambda value: value.__setitem__("opening_time_receipts", value["opening_time_receipts"][:1]), "TRUSTED_TIME_QUORUM_INVALID"),
        (lambda value: value["verification_receipts"][1]["payload"].__setitem__("session_id", value["verification_receipts"][0]["payload"]["session_id"]), "EXTERNAL_VERIFIER_DISAGREEMENT"),
    ],
)
def test_adversarial_bindings_fail_closed(v626_fixture: Fixture, mutator: Any, expected_state: str) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    mutator(kwargs)
    _sync_live_envelopes(kwargs)
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] in {expected_state, "MONOTONIC_CAS_REJECTED", "EXTERNAL_VERIFIER_DISAGREEMENT"}
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["permits"] == []


def test_nonintersecting_time_quorum_fails(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    payload = kwargs["opening_time_receipts"][1]["payload"]
    payload["time_lower_utc"] = "2026-07-16T10:02:00Z"
    payload["time_upper_utc"] = "2026-07-16T10:02:20Z"
    payload["receipt_nonce"] = "77" * 16
    kwargs["opening_time_receipts"][1]["signature_base64"] = _sign(
        v626_fixture.private["time-1"], trust.DOMAIN_TIME_OPEN, payload
    )
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "TRUSTED_TIME_QUORUM_INVALID"


def test_time_window_staleness_future_skew_and_duration_fail_closed() -> None:
    opening = trust.TrustedInterval(
        lower=datetime(2026, 7, 16, 10, 0, 0, tzinfo=timezone.utc),
        upper=datetime(2026, 7, 16, 10, 0, 10, tzinfo=timezone.utc),
        authority_key_ids=("a", "b"),
    )
    too_late = trust.TrustedInterval(
        lower=datetime(2026, 7, 16, 11, 0, 1, tzinfo=timezone.utc),
        upper=datetime(2026, 7, 16, 11, 0, 2, tzinfo=timezone.utc),
        authority_key_ids=("a", "b"),
    )
    with pytest.raises(trust.TrustV626Error) as duration:
        trust.validate_time_window(
            opening=opening,
            closing=too_late,
            checkpoint_observed_at=datetime(2026, 7, 16, 10, 30, 0, tzinfo=timezone.utc),
        )
    assert duration.value.code == "VERIFICATION_WINDOW_EXPIRED"

    closing = trust.TrustedInterval(
        lower=datetime(2026, 7, 16, 10, 1, 0, tzinfo=timezone.utc),
        upper=datetime(2026, 7, 16, 10, 1, 10, tzinfo=timezone.utc),
        authority_key_ids=("a", "b"),
    )
    with pytest.raises(trust.TrustV626Error) as stale:
        trust.validate_time_window(
            opening=opening,
            closing=closing,
            checkpoint_observed_at=datetime(2026, 7, 15, 9, 0, 0, tzinfo=timezone.utc),
        )
    assert stale.value.code == "CHECKPOINT_STALE"
    with pytest.raises(trust.TrustV626Error) as future:
        trust.validate_time_window(
            opening=opening,
            closing=closing,
            checkpoint_observed_at=datetime(2026, 7, 16, 10, 1, 41, tzinfo=timezone.utc),
        )
    assert future.value.code == "CHECKPOINT_FUTURE_SKEW"


def test_authority_control_alias_is_rejected(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    policy = kwargs["trust_policy"]
    policy["time_authorities"][1]["control_group_id"] = policy["time_authorities"][0]["control_group_id"]
    kwargs["trust_policy_sha256"] = canonical_sha256(policy)
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "RELEASE_ROOT_UNAUTHORIZED"


def test_observed_same_sequence_or_predecessor_fork_is_rejected(v626_fixture: Fixture) -> None:
    policy = trust.validate_trust_policy(
        v626_fixture.policy,
        expected_sha256=v626_fixture.kwargs["trust_policy_sha256"],
    )
    original = trust.validate_witness_transition(
        v626_fixture.kwargs["witness_transition"],
        policy=policy,
    )
    same_sequence = replace(original, new_state_sha256=_digest("forked-state"))
    with pytest.raises(trust.TrustV626Error) as sequence_fork:
        trust.detect_witness_forks([original, same_sequence])
    assert sequence_fork.value.code == "MONOTONIC_FORK_DETECTED"
    same_predecessor = replace(
        original,
        new_sequence=original.new_sequence + 1,
        new_state_sha256=_digest("forked-successor"),
        invocation_challenge_sha256=_digest("forked-challenge"),
    )
    with pytest.raises(trust.TrustV626Error) as predecessor_fork:
        trust.detect_witness_forks([original, same_predecessor])
    assert predecessor_fork.value.code == "MONOTONIC_FORK_DETECTED"


def test_payload_tamper_fails_closed(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    digest = next(iter(kwargs["payloads"]))
    kwargs["payloads"][digest] += b" "
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "EVIDENCE_GRAPH_HASH_MISMATCH"


def test_runtime_module_manifest_tamper_fails_closed(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    nodes = [
        evidence.canonical_json_loads(line)
        for line in kwargs["nodes_jsonl"][:-1].split(b"\n")
    ]
    python_node = next(node for node in nodes if node["node_type"] == "PYTHON_MODULE_MANIFEST")
    digest = python_node["payload_sha256"]
    kwargs["payloads"][digest] += b"tamper"
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "EVIDENCE_GRAPH_HASH_MISMATCH"


def test_pair_analysis_child_with_unmanifested_payload_fails() -> None:
    fixture = _build_fixture()
    values = [
        evidence.canonical_json_loads(line)
        for line in fixture.kwargs["nodes_jsonl"][:-1].split(b"\n")
    ]
    child = next(node for node in values if node["node_type"] == "PAIR_STATE_DERIVATION")
    child["payload_sha256"] = _digest("missing-pair-analysis-payload")
    child["payload_byte_length"] = "17"
    child["node_id"] = evidence.evidence_node_id(child)
    values.sort(key=lambda node: node["node_id"])
    with pytest.raises(evidence.EvidenceV626Error) as exc:
        evidence._validate_nodes(values, fixture.kwargs["payloads"])
    assert exc.value.code == "EVIDENCE_GRAPH_DANGLING"


def _resign_head(fixture: Fixture, head: dict[str, Any]) -> None:
    for index, label in enumerate(("log", "witness-0", "witness-1")):
        head["signatures"][index]["signature_base64"] = _sign(
            fixture.private[label], trust.DOMAIN_WITNESS_HEAD, head["payload"]
        )


def _sync_live_envelopes(kwargs: dict[str, Any]) -> None:
    acquisition = kwargs["live_witness_acquisition"]
    kwargs["live_witness_acquisition"] = replace(
        acquisition,
        opening_head_envelope=deepcopy(kwargs["opening_witness_head"]),
        transition_envelope=deepcopy(kwargs["witness_transition"]),
        closing_head_envelope=deepcopy(kwargs["closing_witness_head"]),
    )


def test_opening_and_closing_head_transition_mismatches_are_explicit(v626_fixture: Fixture) -> None:
    opening_kwargs = deepcopy(v626_fixture.kwargs)
    opening = opening_kwargs["opening_witness_head"]
    opening["payload"]["state"]["authorization_sequence"] = "5"
    opening["payload"]["state"]["state_sha256"] = trust.monotonic_state_sha256(opening["payload"]["state"])
    _resign_head(v626_fixture, opening)
    _sync_live_envelopes(opening_kwargs)
    opening_verdict = release.assess_population_trust(**opening_kwargs)
    assert opening_verdict["state"] == "OPENING_HEAD_TRANSITION_MISMATCH"

    closing_kwargs = deepcopy(v626_fixture.kwargs)
    closing = closing_kwargs["closing_witness_head"]
    closing["payload"]["state"]["authorization_sequence"] = "5"
    closing["payload"]["state"]["state_sha256"] = trust.monotonic_state_sha256(closing["payload"]["state"])
    _resign_head(v626_fixture, closing)
    _sync_live_envelopes(closing_kwargs)
    closing_verdict = release.assess_population_trust(**closing_kwargs)
    assert closing_verdict["state"] == "CLOSING_HEAD_TRANSITION_MISMATCH"


def test_differently_rooted_historical_opening_checkpoint_fails_consistency(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    opening = kwargs["opening_witness_head"]
    opening["payload"]["state"]["checkpoint_root_sha256"] = _digest("different-valid-historical-root")
    opening["payload"]["state"]["state_sha256"] = trust.monotonic_state_sha256(opening["payload"]["state"])
    _resign_head(v626_fixture, opening)
    _sync_live_envelopes(kwargs)
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "OPENING_CLOSING_CONSISTENCY_FAILURE"


def test_valid_but_superseded_opening_witness_head_fails(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    kwargs["opening_witness_head"] = deepcopy(kwargs["closing_witness_head"])
    kwargs["opening_witness_head"]["payload"]["response_nonce"] = "61" * 16
    _resign_head(v626_fixture, kwargs["opening_witness_head"])
    _sync_live_envelopes(kwargs)
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] in {
        "OPENING_HEAD_TRANSITION_MISMATCH",
        "OPENING_CLOSING_CONSISTENCY_FAILURE",
    }


def test_component_ids_are_recomputed_and_derivation_stages_are_acyclic() -> None:
    tampered = _build_fixture(component_id_tamper=True)
    tampered_verdict = release.assess_population_trust(**tampered.kwargs)
    assert tampered_verdict["state"] == "COMPONENT_ID_RECOMPUTATION_MISMATCH"

    circular = _build_fixture(derivation_stage_violation=True)
    circular_verdict = release.assess_population_trust(**circular.kwargs)
    assert circular_verdict["state"] == "COMPONENT_DERIVATION_CIRCULAR"


def test_same_runtime_custodian_fails_independent_run_policy() -> None:
    fixture = _build_fixture(runtime_custodian_alias=True)
    verdict = release.assess_population_trust(**fixture.kwargs)
    assert verdict["state"] == "INDEPENDENT_RUN_POLICY_NOT_SATISFIED"


def test_prohibited_cycle_detector_fails_closed() -> None:
    synthetic = {
        "a": {"child_node_ids": ["b"]},
        "b": {"child_node_ids": ["a"]},
    }
    with pytest.raises(evidence.EvidenceV626Error, match="cycle") as exc:
        evidence._reject_cycles(synthetic)
    assert exc.value.code == "EVIDENCE_GRAPH_PROHIBITED_CYCLE"


def test_revocation_advancement_requires_complete_closing_reevaluation(v626_fixture: Fixture) -> None:
    kwargs = deepcopy(v626_fixture.kwargs)
    transition = kwargs["witness_transition"]
    transition["payload"]["new_state"]["revocation_sequence"] = "4"
    transition["payload"]["new_state"]["state_sha256"] = trust.monotonic_state_sha256(transition["payload"]["new_state"])
    for index, label in enumerate(("log", "witness-0", "witness-1")):
        transition["signatures"][index]["signature_base64"] = _sign(
            v626_fixture.private[label], trust.DOMAIN_WITNESS_TRANSITION, transition["payload"]
        )
    closing_head = kwargs["closing_witness_head"]
    closing_head["payload"]["state"] = transition["payload"]["new_state"]
    for index, label in enumerate(("log", "witness-0", "witness-1")):
        closing_head["signatures"][index]["signature_base64"] = _sign(
            v626_fixture.private[label], trust.DOMAIN_WITNESS_HEAD, closing_head["payload"]
        )
    _sync_live_envelopes(kwargs)
    verdict = release.assess_population_trust(**kwargs)
    assert verdict["state"] == "REVOCATION_STATE_ADVANCED_REVERIFY_REQUIRED"


def test_all_declared_failure_states_are_no_authority() -> None:
    for state in sorted(release.V626_FAILURE_STATES):
        verdict = trust.fail_closed_verdict(state, reason="adversarial test")
        assert verdict["external_authentication_verified"] is False
        assert verdict["population_feasible"] is False
        assert verdict["calibration_upload_authorized"] is False
        assert verdict["production_upload_authorized"] is False
        assert verdict["permits"] == []
        assert verdict["sealed_holdout_accessed"] is False


def test_local_cache_deletion_cannot_reuse_external_witness_challenge(
    v626_fixture: Fixture,
    tmp_path: Path,
) -> None:
    parsed_policy = trust.validate_trust_policy(
        v626_fixture.policy,
        expected_sha256=v626_fixture.kwargs["trust_policy_sha256"],
    )
    transition = v626_fixture.kwargs["witness_transition"]
    previous_state = transition["payload"]["previous_state"]
    new_state = transition["payload"]["new_state"]
    request = transition["payload"]["request"]

    class FakeExternalWitness:
        def __init__(self) -> None:
            self.state = previous_state
            self.used: set[str] = set()

        def _head(self, nonce: str) -> dict[str, Any]:
            payload = {
                "schema": trust.WITNESS_HEAD_SCHEMA,
                "namespace": parsed_policy["namespace"],
                "release_root_sha256": parsed_policy["release_root_sha256"],
                "state": self.state,
                "response_nonce": nonce,
            }
            return {
                "schema": trust.WITNESS_HEAD_ENVELOPE_SCHEMA,
                "payload": payload,
                "signatures": [
                    {
                        "key_id": _key_id(v626_fixture.private[label]),
                        "signature_base64": _sign(
                            v626_fixture.private[label], trust.DOMAIN_WITNESS_HEAD, payload
                        ),
                    }
                    for label in ("log", "witness-0", "witness-1")
                ],
            }

        def read_head(
            self,
            *,
            namespace: str,
            release_root_sha256: str,
            response_nonce: str,
        ) -> dict[str, Any]:
            assert namespace == parsed_policy["namespace"]
            assert release_root_sha256 == parsed_policy["release_root_sha256"]
            return self._head(response_nonce)

        def compare_and_append(self, candidate: dict[str, Any]) -> dict[str, Any]:
            challenge = candidate["invocation_challenge_sha256"]
            if challenge in self.used:
                raise trust.TrustV626Error("CHALLENGE_ALREADY_REDEEMED", "challenge is already redeemed")
            if candidate != request or candidate["expected_state_sha256"] != self.state["state_sha256"]:
                raise trust.TrustV626Error("MONOTONIC_CAS_REJECTED", "stale external CAS")
            self.used.add(challenge)
            self.state = new_state
            return transition

    service = FakeExternalWitness()
    first = acquire_witness_transition(
        transport=service,
        policy=parsed_policy,
        redemption_request=request,
    )
    assert first.transition.new_state_sha256 == new_state["state_sha256"]

    local_cache = tmp_path / "project-cache.sqlite"
    local_cache.write_bytes(b"project-controlled cache")
    local_cache.unlink()
    with pytest.raises(trust.TrustV626Error) as replay:
        acquire_witness_transition(
            transport=service,
            policy=parsed_policy,
            redemption_request=request,
        )
    assert replay.value.code in {"MONOTONIC_CAS_REJECTED", "CHALLENGE_ALREADY_REDEEMED"}


def test_live_time_transport_acquires_both_quorums(v626_fixture: Fixture) -> None:
    parsed_policy = trust.validate_trust_policy(
        v626_fixture.policy,
        expected_sha256=v626_fixture.kwargs["trust_policy_sha256"],
    )
    opening_receipts = v626_fixture.kwargs["opening_time_receipts"]
    closing_receipts = v626_fixture.kwargs["closing_time_receipts"]
    excluded = {
        "schema",
        "time_policy_sha256",
        "release_root_sha256",
        "authority_key_id",
        "authority_subject_id",
        "authority_control_group_id",
        "authority_organization_id",
        "receipt_nonce",
        "time_lower_utc",
        "time_upper_utc",
    }
    opening_binding = {
        key: value
        for key, value in opening_receipts[0]["payload"].items()
        if key not in excluded
    }
    closing_binding = {
        key: value
        for key, value in closing_receipts[0]["payload"].items()
        if key not in excluded
    }

    class FakeTimeTransport:
        def request_opening_quorum(self, binding: dict[str, Any]) -> list[dict[str, Any]]:
            assert binding == opening_binding
            return opening_receipts

        def request_closing_quorum(self, binding: dict[str, Any]) -> list[dict[str, Any]]:
            assert binding == closing_binding
            return closing_receipts

    acquisition = acquire_trusted_time_quorums(
        transport=FakeTimeTransport(),
        policy=parsed_policy,
        opening_binding=opening_binding,
        closing_binding=closing_binding,
        checkpoint_observed_at=datetime(2026, 7, 16, 10, 0, 30, tzinfo=timezone.utc),
    )
    assert len(acquisition.opening_receipts) == 2
    assert len(acquisition.closing_receipts) == 2
