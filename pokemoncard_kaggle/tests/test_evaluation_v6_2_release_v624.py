from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sqlite3
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evaluation_v6_2 import release_v625 as v625
from evaluation_v6_2.integration_v622 import SLOTS, canonical_json_bytes, canonical_sha256
from tests import test_evaluation_v6_2_attestation_v623 as v623


VERIFICATION_CHALLENGE_NONCE = "cd" * 16

# Keep the historical alias importable for the CLI harness while all calls in
# this module exercise the current v6.2.5 implementation.
v624 = v625


@pytest.fixture(autouse=True)
def _restore_bootstrap_trust_config() -> object:
    original = v625.BOOTSTRAP_TRUST_CONFIG
    try:
        yield
    finally:
        v625.BOOTSTRAP_TRUST_CONFIG = original


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("ascii")).digest())


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key_id(private: Ed25519PrivateKey) -> str:
    return "ed25519-sha256:" + hashlib.sha256(_public(private)).hexdigest()


def _sign(private: Ed25519PrivateKey, domain: bytes, payload: dict[str, object]) -> str:
    message = domain + hashlib.sha256(canonical_json_bytes(payload)).digest()
    return base64.b64encode(private.sign(message)).decode("ascii")


def _write_json(path: Path, value: object) -> None:
    payload = canonical_json_bytes(value)
    assert not payload.endswith(b"\n")
    path.write_bytes(payload)


def _merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        raise AssertionError("test Merkle tree requires leaves")
    level = list(leaves)
    while len(level) > 1:
        level = [
            v625._transparency_node_hash(level[index], level[index + 1])
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def _inclusion_path(leaves: list[bytes], index: int) -> list[str]:
    path: list[str] = []
    level = list(leaves)
    position = index
    while len(level) > 1:
        sibling = position - 1 if position % 2 else position + 1
        path.append(level[sibling].hex())
        level = [
            v625._transparency_node_hash(level[offset], level[offset + 1])
            for offset in range(0, len(level), 2)
        ]
        position //= 2
    return path


def _authority(private: Ed25519PrivateKey, role: str, label: str) -> dict[str, object]:
    return {
        "key_id": _key_id(private),
        "public_key_ed25519_base64": base64.b64encode(_public(private)).decode("ascii"),
        "identity_subject_id": f"release-subject-{label}",
        "control_group_id": f"release-control-{label}",
        "organization_id": f"release-org-{label}",
        "role": role,
        "external_identity_receipt_sha256": _digest(f"release-identity:{label}"),
    }


def _make_release_root(
    bundle: dict[str, object],
    *,
    issued_at: str,
    maximum_checkpoint_age_seconds: int = 86_400,
    same_external_control_group: bool = False,
) -> tuple[dict[str, object], dict[str, dict[str, Ed25519PrivateKey]]]:
    private = {
        "registry_admins": {str(i): _key(f"admin-{i}") for i in range(3)},
        "external_verifiers": {str(i): _key(f"external-{i}") for i in range(3)},
        "revocation_authorities": {str(i): _key(f"revocation-{i}") for i in range(3)},
        "transparency": {"0": _key("transparency")},
    }
    authorities: dict[str, list[dict[str, object]]] = {}
    for group, role in (
        ("registry_admins", v624.ROLE_REGISTRY_ADMIN),
        ("external_verifiers", v624.ROLE_EXTERNAL_VERIFIER),
        ("revocation_authorities", v624.ROLE_REVOCATION_AUTHORITY),
    ):
        records = [_authority(private[group][str(i)], role, f"{group}-{i}") for i in range(3)]
        if same_external_control_group and group == "external_verifiers":
            records[1]["control_group_id"] = records[0]["control_group_id"]
        authorities[group] = sorted(records, key=lambda item: str(item["key_id"]))
    transparency_private = private["transparency"]["0"]
    root = {
        "schema": v624.RELEASE_ROOT_SCHEMA,
        "release_id": "release-v624-test",
        "release_nonce": "ab" * 16,
        "issued_at_utc": issued_at,
        "accepted_semantic_verifier_build_sha256s": [
            bundle["campaign"]["semantic_verifier_build_sha256"]  # type: ignore[index]
        ],
        "trust_policy_sha256": _digest("v624-trust-policy"),
        "timestamp_policy_sha256": _digest("v624-timestamp-policy"),
        "lineage_policy_sha256": _digest("v624-lineage-policy"),
        "intervention_policy_sha256": _digest("v625-intervention-policy"),
        "evidence_policy_sha256": _digest("v624-evidence-policy"),
        "authorities": authorities,
        "transparency_log": {
            "log_id": "transparency-log-v624",
            "key_id": _key_id(transparency_private),
            "public_key_ed25519_base64": base64.b64encode(_public(transparency_private)).decode("ascii"),
            "identity_subject_id": "transparency-subject",
            "control_group_id": "transparency-control",
            "checkpoint_authority_receipt_sha256": _digest("transparency-authority-receipt"),
            "minimum_registry_epoch": 1,
            "minimum_revocation_sequence": 1,
            "maximum_checkpoint_age_seconds": maximum_checkpoint_age_seconds,
        },
        "tsa_roots": [
            {
                "tsa_id": "tsa-v624",
                "ca_sha256": _digest("tsa-ca"),
                "policy_oid": "1.2.3.4.624",
            }
        ],
    }
    return root, private


def _make_bootstrap_config(
    replay_db_path: Path | None = None,
) -> tuple[dict[str, object], dict[str, Ed25519PrivateKey]]:
    private = {str(index): _key(f"bootstrap-{index}") for index in range(3)}
    authorities = sorted(
        (_authority(private[str(index)], v625.ROLE_BOOTSTRAP_AUTHORITY, f"bootstrap-{index}") for index in range(3)),
        key=lambda item: str(item["key_id"]),
    )
    config = {
        "schema": "eval.v6.2.5.bootstrap-trust-config",
        "bootstrap_policy_sha256": _digest("v625-bootstrap-policy"),
        "authorities": authorities,
        "minimum_authorization_sequence": 0,
        "previous_authorization_root_sha256": _digest("previous-release-authorization"),
        "minimum_checkpoint_sequence": 0,
        "previous_checkpoint_sha256": _digest("previous-checkpoint"),
        "previous_registry_epoch": 1,
        "previous_revocation_sequence": 1,
        "previous_transparency_tree_size": 4,
        "previous_transparency_root_sha256": "0" * 64,
        "challenge_replay_namespace": "v625-test-replay",
        "challenge_replay_store_path_sha256": hashlib.sha256(
            str(
                (replay_db_path or Path("/tmp/v625-test-replay.sqlite3")).parent.resolve()
                / (replay_db_path or Path("/tmp/v625-test-replay.sqlite3")).name
            ).encode()
        ).hexdigest(),
    }
    return config, private


def _make_release_authorization(
    root: dict[str, object],
    bootstrap: dict[str, object],
    bootstrap_private: dict[str, Ed25519PrivateKey],
) -> dict[str, object]:
    authorization = {
        "schema": v625.RELEASE_ROOT_AUTHORIZATION_SCHEMA,
        "release_root_sha256": canonical_sha256(root),
        "release_root_schema_version": v625.RELEASE_ROOT_SCHEMA,
        "log_id": "bootstrap-authorization-log-v625",
        "source_commit_sha256": _digest("v625-source-commit"),
        "source_tree_sha256": _digest("v625-source-tree"),
        "reproducible_build_recipe_sha256": _digest("v625-build-recipe"),
        "released_module_or_binary_sha256": hashlib.sha256(
            Path(v625.__file__).read_bytes()
        ).hexdigest(),
        "test_evidence_root_sha256": _digest("v625-test-evidence"),
        "bootstrap_policy_sha256": bootstrap["bootstrap_policy_sha256"],
        "authorization_sequence": 1,
        "issued_at_utc": v623._SIGNED_AT,
        "previous_authorization_root_sha256": bootstrap["previous_authorization_root_sha256"],
    }
    approvals = []
    by_key = {str(item["key_id"]): item for item in bootstrap["authorities"]}  # type: ignore[index]
    for key_id in sorted(by_key)[:2]:
        approvals.append(
            {
                "authority_key_id": key_id,
                "signature_ed25519_base64": _sign(
                    bootstrap_private[next(index for index in bootstrap_private if _key_id(bootstrap_private[index]) == key_id)],
                    v625.DOMAIN_RELEASE_ROOT_AUTHORIZATION,
                    authorization,
                ),
            }
        )
    return {
        "schema": v625.RELEASE_ROOT_AUTHORIZATION_ENVELOPE_SCHEMA,
        "authorization": authorization,
        "approvals": approvals,
    }


def _admin_approvals(bundle: dict[str, object]) -> None:
    # Re-root the v623 registry identity receipts, then re-sign both rooted payloads.
    for record in bundle["registry"]["keys"]:  # type: ignore[index]
        record["external_identity_receipt_sha256"] = _digest(  # type: ignore[index]
            f"identity-receipt:{record['key_id']}"
        )
    for field, schema, domain, label in (
        ("registry", v623.REGISTRY_SCHEMA, v623.DOMAIN_REGISTRY, "registry"),
        ("revocation_log", v623.REVOCATION_SCHEMA, v623.DOMAIN_REVOCATION, "revocation"),
    ):
        bundle[f"{label}_approvals"] = [
            v623._envelope(
                bundle[field],
                artifact_schema=schema,
                domain=domain,
                private=_key(f"admin-{index}"),
                label=f"{label}:{index}",
            )
            for index in (0, 1)
        ]


def _identity_bindings(bundle: dict[str, object]) -> list[dict[str, object]]:
    bindings = []
    for record in bundle["registry"]["keys"]:  # type: ignore[index]
        bindings.append(
            {
                "schema": v624.IDENTITY_BINDING_SCHEMA,
                "key_id": record["key_id"],
                "role": record["role"],
                "identity_subject_id": f"campaign-subject-{record['entity_id']}",
                "control_group_id": f"campaign-control-{record['entity_id']}",
                "organization_id": f"campaign-org-{record['entity_id']}",
                "external_identity_receipt_sha256": record["external_identity_receipt_sha256"],
            }
        )
    return sorted(bindings, key=lambda item: (str(item["role"]), str(item["key_id"])))


def _build_packet(
    root: dict[str, object],
    bundle: dict[str, object],
    root_private: dict[str, dict[str, Ed25519PrivateKey]],
    base: Path,
    *,
    checkpoint_at: str,
    verified_at: str,
    verification_challenge_nonce: str,
    bootstrap: dict[str, object],
    bootstrap_private: dict[str, Ed25519PrivateKey],
    pair_source_state: str = "INDEPENDENT",
    pair_exposure_state: str = "INDEPENDENT",
) -> dict[str, object]:
    release = v625.validate_release_root(root)
    identities = _identity_bindings(bundle)
    entries: list[dict[str, object]] = []

    def add_evidence(
        path: str,
        *,
        slot: str | None,
        pair: str | None,
        nonce: str | None,
        purpose: str,
        producer: str,
        content: bytes | None = None,
        media_type: str = "application/octet-stream",
    ) -> str:
        content = content if content is not None else f"v624-evidence:{path}".encode("ascii")
        target = base / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        metadata = {
            "path": path,
            "media_type": media_type,
            "byte_length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "slot_id": slot,
            "pair_id": pair,
            "unit_nonce": nonce,
            "evidence_purpose": purpose,
            "producer_key_id": producer,
        }
        evidence_id = canonical_sha256(metadata)
        entries.append({"evidence_id": evidence_id, **metadata})
        return evidence_id

    unit_by_slot = {str(unit["slot_id"]): unit for unit in bundle["units"]}
    technical_keys = {
        slot: str(unit["technical_signature"]["key_id"]) for slot, unit in unit_by_slot.items()
    }
    lineage_keys = {
        slot: str(unit["lineage_signature"]["key_id"]) for slot, unit in unit_by_slot.items()
    }
    unit_purposes = (
        ("TECHNICAL_REBUILD", technical_keys),
        ("LINUX_TRANSCRIPT", technical_keys),
        ("SAFETY_HARNESS", technical_keys),
        ("LINEAGE_VCS", lineage_keys),
        ("LINEAGE_SIMILARITY", lineage_keys),
        ("LINEAGE_PROVENANCE", lineage_keys),
    )
    for slot in SLOTS:
        nonce = str(unit_by_slot[slot]["contributor_manifest"]["unit_nonce"])
        for purpose, producers in unit_purposes:
            add_evidence(
                f"evidence/unit/{slot}/{purpose.lower()}.bin",
                slot=slot,
                pair=None,
                nonce=nonce,
                purpose=purpose,
                producer=producers[slot],
            )
    pair_evidence: dict[str, str] = {}
    pair_reviews: list[dict[str, object]] = []
    for left_index, left in enumerate(SLOTS):
        for right in SLOTS[left_index + 1 :]:
            pair_id = f"{left}:{right}"
            pair_review_evidence: list[str] = []
            intervention_review_evidence: list[str] = []
            reviewers = set((lineage_keys[left], lineage_keys[right]))
            if len(reviewers) < 2:
                reviewers.add(next(key for key in lineage_keys.values() if key not in reviewers))
            reviewers = sorted(reviewers)
            for reviewer_index, reviewer in enumerate(reviewers):
                lineage_payload = {
                    "schema": v625.PAIR_LINEAGE_RECEIPT_SCHEMA,
                    "pair_id": pair_id,
                    "left_slot_id": left,
                    "right_slot_id": right,
                    "reviewer_key_id": reviewer,
                    "source_state": pair_source_state,
                    "exposure_state": pair_exposure_state,
                    "analysis_root_sha256": _digest(f"lineage-analysis:{pair_id}:{reviewer}"),
                    "signed_at_utc": checkpoint_at,
                }
                lineage_payload["signature_ed25519_base64"] = _sign(
                    next(private for private in root_private.get("lineage", {}).values() if _key_id(private) == reviewer),
                    v625.DOMAIN_PAIR_LINEAGE_RECEIPT,
                    {key: value for key, value in lineage_payload.items() if key != "signature_ed25519_base64"},
                )
                lineage_id = add_evidence(
                    f"evidence/pair/{left}_{right}_lineage_{reviewer_index}.json",
                    slot=None,
                    pair=pair_id,
                    nonce=None,
                    purpose="PAIR_LINEAGE_RECEIPT",
                    producer=reviewer,
                    content=canonical_json_bytes(lineage_payload),
                    media_type="application/json",
                )
                pair_review_evidence.append(lineage_id)
                intervention_payload = {
                    "schema": v625.PAIR_INTERVENTION_RECEIPT_SCHEMA,
                    "pair_id": pair_id,
                    "left_slot_id": left,
                    "right_slot_id": right,
                    "reviewer_key_id": reviewer,
                    "intervention_state": "DISTINCT_INTERVENTION",
                    "analysis_root_sha256": _digest(f"intervention-analysis:{pair_id}:{reviewer}"),
                    "signed_at_utc": checkpoint_at,
                }
                intervention_payload["signature_ed25519_base64"] = _sign(
                    next(private for private in root_private.get("lineage", {}).values() if _key_id(private) == reviewer),
                    v625.DOMAIN_PAIR_INTERVENTION_RECEIPT,
                    {key: value for key, value in intervention_payload.items() if key != "signature_ed25519_base64"},
                )
                intervention_id = add_evidence(
                    f"evidence/pair/{left}_{right}_intervention_{reviewer_index}.json",
                    slot=None,
                    pair=pair_id,
                    nonce=None,
                    purpose="PAIR_INTERVENTION_RECEIPT",
                    producer=reviewer,
                    content=canonical_json_bytes(intervention_payload),
                    media_type="application/json",
                )
                intervention_review_evidence.append(intervention_id)
            pair_review_evidence.sort()
            intervention_review_evidence.sort()
            assert len(pair_review_evidence) == len(reviewers)
            assert len(intervention_review_evidence) == len(reviewers)
            assert {
                next(item["producer_key_id"] for item in entries if item["evidence_id"] == evidence_id)
                for evidence_id in pair_review_evidence
            } == set(reviewers)
            assert {
                next(item["producer_key_id"] for item in entries if item["evidence_id"] == evidence_id)
                for evidence_id in intervention_review_evidence
            } == set(reviewers)
            pair_reviews.append(
                {
                    "schema": v624.PAIR_REVIEW_SCHEMA,
                    "left_slot_id": left,
                    "right_slot_id": right,
                    "reviewer_key_ids": reviewers,
                    "source_state": pair_source_state,
                    "exposure_state": pair_exposure_state,
                    "intervention_state": "DISTINCT_INTERVENTION",
                    "evidence_ids": pair_review_evidence,
                    "evidence_root_sha256": canonical_sha256(
                        {"pair_id": pair_id, "evidence_ids": pair_review_evidence}
                    ),
                    "intervention_evidence_ids": intervention_review_evidence,
                    "intervention_evidence_root_sha256": canonical_sha256(
                        {"pair_id": pair_id, "evidence_ids": intervention_review_evidence}
                    ),
                }
            )
    identity_producer = _key_id(root_private["external_verifiers"]["0"])
    principal_evidence_by_slot: dict[str, str] = {}
    contributor_identity_keys: set[str] = set()
    for slot in SLOTS:
        contributor_key = str(unit_by_slot[slot]["contributor_signature"]["key_id"])
        contributor_identity_keys.add(contributor_key)
        identity_bytes = f"identity-receipt:{contributor_key}".encode("ascii")
        principal_evidence_by_slot[slot] = add_evidence(
            f"evidence/identity/principal-{slot}.bin",
            slot=slot,
            pair=None,
            nonce=str(unit_by_slot[slot]["contributor_manifest"]["unit_nonce"]),
            purpose="IDENTITY_EVIDENCE",
            producer=identity_producer,
            content=identity_bytes,
        )
    for record in identities:
        key_id = str(record["key_id"])
        if key_id in contributor_identity_keys:
            continue
        identity_bytes = f"identity-receipt:{key_id}".encode("ascii")
        add_evidence(
            f"evidence/identity/{key_id.replace(':', '_')}.bin",
            slot=None,
            pair=None,
            nonce=None,
            purpose="IDENTITY_EVIDENCE",
            producer=identity_producer,
            content=identity_bytes,
        )
    registry_epoch = int(bundle["registry"]["registry_epoch"])  # type: ignore[index]
    sequence = 1
    revocation_head = canonical_sha256(bundle["revocation_log"])
    add_evidence(
        "evidence/revocation/revocation-log.json",
        slot=None,
        pair=None,
        nonce=None,
        purpose="REVOCATION_LOG",
        producer=_key_id(root_private["revocation_authorities"]["0"]),
        content=canonical_json_bytes(bundle["revocation_log"]),
    )
    transcript_ids: dict[str, str] = {}
    transcript_meta = {field: True for field in v625._CHECK_FIELDS}
    build_sha = str(bundle["campaign"]["semantic_verifier_build_sha256"])
    for index in (0, 1):
        private = root_private["external_verifiers"][str(index)]
        key_id = _key_id(private)
        authority = next(
            item for item in root["authorities"]["external_verifiers"]  # type: ignore[index]
            if item["key_id"] == key_id
        )
        transcript = {
            "schema": v625.VERIFIER_EXECUTION_TRANSCRIPT_SCHEMA,
            "authority_key_id": key_id,
            "authority_identity_subject_id": authority["identity_subject_id"],
            "authority_control_group_id": authority["control_group_id"],
            "verification_session_id": f"{index + 11:032x}",
            "authority_challenge_nonce": f"{index + 21:032x}",
            "verification_challenge_nonce": verification_challenge_nonce,
            "release_root_authorization_sha256": canonical_sha256(
                _make_release_authorization(root, bootstrap, bootstrap_private)
            ),
            "authorization_sequence": 1,
            "recruitment_release_root_sha256": release["sha256"],
            "campaign_bundle_root_sha256": canonical_sha256(bundle),
            "registry_epoch": registry_epoch,
            "revocation_sequence": sequence,
            "measured_verifier_module_or_binary_sha256": build_sha,
            "execution_environment_attestation_sha256": _digest(f"environment:{index}"),
            "check_vector": transcript_meta,
            "started_at_utc": checkpoint_at,
            "completed_at_utc": checkpoint_at,
        }
        transcript_id = add_evidence(
            f"evidence/transcript/external-{index}.json",
            slot=None,
            pair=None,
            nonce=verification_challenge_nonce,
            purpose="VERIFIER_EXECUTION_TRANSCRIPT",
            producer=key_id,
            content=canonical_json_bytes(transcript),
            media_type="application/json",
        )
        transcript_ids[key_id] = transcript_id
    entries.sort(key=lambda item: str(item["path"]))
    manifest = {"schema": v624.EVIDENCE_MANIFEST_SCHEMA, "entries": entries}

    principals = []
    for slot in SLOTS:
        principal_ids = [f"principal-{slot}"]
        control_group_ids = [f"development-control-{slot}"]
        principal_evidence_ids = [principal_evidence_by_slot[slot]]
        principals.append(
            {
                "schema": v624.PRINCIPAL_BINDING_SCHEMA,
                "slot_id": slot,
                "principal_ids": principal_ids,
                "control_group_ids": control_group_ids,
                "principal_evidence_ids": principal_evidence_ids,
                "evidence_root_sha256": canonical_sha256(
                    {
                        "slot_id": slot,
                        "principal_ids": principal_ids,
                        "control_group_ids": control_group_ids,
                        "principal_evidence_ids": principal_evidence_ids,
                    }
                ),
            }
        )
    source_edges = []
    exposure_edges = []
    for review in pair_reviews:
        source_edges.append(
            {
                "left_slot_id": review["left_slot_id"],
                "right_slot_id": review["right_slot_id"],
                "state": review["source_state"],
                "evidence_root_sha256": review["evidence_root_sha256"],
            }
        )
        exposure_edges.append(
            {
                "left_slot_id": review["left_slot_id"],
                "right_slot_id": review["right_slot_id"],
                "state": review["exposure_state"],
                "evidence_root_sha256": review["evidence_root_sha256"],
            }
        )
    source_graph = {
        "schema": v624.SOURCE_GRAPH_SCHEMA,
        "policy_sha256": root["lineage_policy_sha256"],
        "nodes": list(SLOTS),
        "edges": source_edges,
    }
    exposure_graph = {
        "schema": v624.EXPOSURE_GRAPH_SCHEMA,
        "policy_sha256": root["lineage_policy_sha256"],
        "nodes": list(SLOTS),
        "edges": exposure_edges,
    }
    intervention_graph = {
        "schema": v625.INTERVENTION_GRAPH_SCHEMA,
        "policy_sha256": root["intervention_policy_sha256"],
        "nodes": list(SLOTS),
        "edges": [
            {
                "left_slot_id": review["left_slot_id"],
                "right_slot_id": review["right_slot_id"],
                "state": review["intervention_state"],
                "evidence_root_sha256": review["intervention_evidence_root_sha256"],
            }
            for review in pair_reviews
        ],
    }
    assignments = []
    source_root = canonical_sha256(source_graph)
    exposure_root = canonical_sha256(exposure_graph)
    intervention_root = canonical_sha256(intervention_graph)
    for index, slot in enumerate(SLOTS):
        assignments.append(
            {
                "schema": v624.DERIVED_ASSIGNMENT_SCHEMA,
                "slot_id": slot,
                "source_family_id": "sf-"
                + canonical_sha256(
                    {
                        "policy_version": root["lineage_policy_sha256"],
                        "members": [slot],
                        "source_graph_root": source_root,
                    }
                )[:24],
                "lineage_time_block_id": "lt-"
                + canonical_sha256(
                    {
                        "policy_version": root["lineage_policy_sha256"],
                        "members": [slot],
                        "exposure_graph_root": exposure_root,
                    }
                )[:24],
                "intervention_family_id": "if-"
                + canonical_sha256(
                    {
                        "policy_version": root["intervention_policy_sha256"],
                        "members": [slot],
                        "intervention_graph_root": intervention_root,
                    }
                )[:24],
            }
        )
    unit_hashes = [
        {"slot_id": slot, "unit_record_sha256": canonical_sha256(unit_by_slot[slot])}
        for slot in SLOTS
    ]
    release_authorization = _make_release_authorization(root, bootstrap, bootstrap_private)
    payload_hashes = {
        "REGISTRY_STATE": canonical_sha256(
            {"registry_epoch": registry_epoch, "registry_root_sha256": canonical_sha256(bundle["registry"])}
        ),
        "RELEASE_ROOT_AUTHORIZATION": canonical_sha256(release_authorization),
        "REVOCATION_HEAD": canonical_sha256(
            {"revocation_sequence": sequence, "revocation_log_head_sha256": revocation_head}
        ),
        "VERIFICATION_CHALLENGE": canonical_sha256(
            {"verification_challenge_nonce": verification_challenge_nonce}
        ),
    }
    leaves = [
        v625.transparency_leaf_hash(f"PREVIOUS_{index}", _digest(f"previous-leaf-{index}"))
        for index in range(4)
    ] + [v625.transparency_leaf_hash(kind, payload_hashes[kind]) for kind in v625._TRANSPARENCY_KINDS]
    tree_root = _merkle_root(leaves)
    previous_root = _merkle_root(leaves[:4])
    bootstrap["previous_transparency_root_sha256"] = previous_root
    checkpoint = {
        "schema": v624.TRANSPARENCY_CHECKPOINT_SCHEMA,
        "log_id": release["transparency"]["log_id"],
        "release_root_sha256": release["sha256"],
        "release_root_authorization_sha256": canonical_sha256(release_authorization),
        "authorization_sequence": release_authorization["authorization"]["authorization_sequence"],
        "registry_epoch": registry_epoch,
        "revocation_sequence": sequence,
        "revocation_log_head_sha256": revocation_head,
        "verification_challenge_nonce": verification_challenge_nonce,
        "checkpoint_sequence": 1,
        "previous_checkpoint_sha256": bootstrap["previous_checkpoint_sha256"],
        "tree_size": len(leaves),
        "tree_root_sha256": tree_root,
        "previous_tree_size": 4,
        "previous_tree_root_sha256": previous_root,
        "inclusion_proofs": [
            {
                "kind": kind,
                "payload_sha256": payload_hashes[kind],
                "leaf_index": 4 + index,
                "audit_path_sha256s": _inclusion_path(leaves, 4 + index),
            }
            for index, kind in enumerate(v625._TRANSPARENCY_KINDS)
        ],
        "consistency_proof_sha256s": [_merkle_root(leaves[4:])],
        "trusted_time_source": "SIGNED_TRANSPARENCY_CHECKPOINT_V1",
        "observed_at_utc": checkpoint_at,
    }
    transparency_private = root_private["transparency"]["0"]
    checkpoint_envelope = {
        "schema": v624.TRANSPARENCY_ENVELOPE_SCHEMA,
        "key_id": release["transparency"]["key_id"],
        "receipt": checkpoint,
        "receipt_sha256": canonical_sha256(checkpoint),
        "signature_ed25519_base64": _sign(transparency_private, v624.DOMAIN_TRANSPARENCY_CHECKPOINT, checkpoint),
    }
    revocation_receipts = []
    for index in (0, 1):
        receipt = {
            "schema": v624.REVOCATION_HEAD_SCHEMA,
            "release_root_sha256": release["sha256"],
            "registry_epoch": registry_epoch,
            "revocation_sequence": sequence,
            "revocation_log_head_sha256": revocation_head,
            "revocation_semantics": "COMPROMISE_RETROACTIVE_ROUTINE_PROSPECTIVE_V1",
            "issued_at_utc": checkpoint_at,
        }
        private = root_private["revocation_authorities"][str(index)]
        revocation_receipts.append(
            {
                "schema": v624.REVOCATION_HEAD_ENVELOPE_SCHEMA,
                "authority_key_id": _key_id(private),
                "receipt": receipt,
                "receipt_sha256": canonical_sha256(receipt),
                "signature_ed25519_base64": _sign(private, v624.DOMAIN_REVOCATION_HEAD, receipt),
            }
        )
    expected = {
        "release_root_authorization_sha256": canonical_sha256(release_authorization),
        "authorization_sequence": 1,
        "recruitment_release_root_sha256": release["sha256"],
        "campaign_bundle_root_sha256": canonical_sha256(bundle),
        "registry_epoch": registry_epoch,
        "revocation_sequence": sequence,
        "revocation_log_head_sha256": revocation_head,
        "verification_challenge_nonce": verification_challenge_nonce,
        "revocation_head_receipts_root_sha256": canonical_sha256(
            sorted({canonical_sha256(item["receipt"]) for item in revocation_receipts})
        ),
        "transparency_checkpoint_sha256": canonical_sha256(checkpoint),
        "evidence_manifest_root_sha256": canonical_sha256(manifest),
        "evidence_bytes_root_sha256": canonical_sha256(
            [
                {
                    "path": item["path"],
                    "byte_length": item["byte_length"],
                    "sha256": item["sha256"],
                }
                for item in entries
            ]
        ),
        "unit_record_hashes_root_sha256": canonical_sha256(unit_hashes),
        "population_graph_sha256": canonical_sha256(bundle["population_graph"]),
        "population_decision_sha256": canonical_sha256(bundle["population_decision"]),
        "source_graph_root_sha256": source_root,
        "exposure_graph_root_sha256": exposure_root,
        "intervention_graph_root_sha256": canonical_sha256(intervention_graph),
        "pair_reviews_root_sha256": canonical_sha256(pair_reviews),
        "identity_bindings_root_sha256": canonical_sha256(identities),
        "principal_bindings_root_sha256": canonical_sha256(principals),
        "derived_assignments_root_sha256": canonical_sha256(assignments),
    }
    packet = {
        "schema": v624.RELEASE_PACKET_SCHEMA,
        "recruitment_release_root_sha256": release["sha256"],
        "release_root_authorization_sha256": canonical_sha256(release_authorization),
        "authorization_sequence": 1,
        "campaign_bundle_root_sha256": canonical_sha256(bundle),
        "registry_epoch": registry_epoch,
        "revocation_sequence": sequence,
        "revocation_log_head_sha256": revocation_head,
        "verification_challenge_nonce": verification_challenge_nonce,
        "revocation_head_approvals": revocation_receipts,
        "transparency_checkpoint": checkpoint_envelope,
        "evidence_manifest": manifest,
        "unit_record_hashes": unit_hashes,
        "identity_bindings": identities,
        "unit_development_principals": principals,
        "pair_reviews": pair_reviews,
        "source_graph": source_graph,
        "exposure_graph": exposure_graph,
        "intervention_graph": intervention_graph,
        "derived_assignments": assignments,
        "population_graph_sha256": canonical_sha256(bundle["population_graph"]),
        "population_decision_sha256": canonical_sha256(bundle["population_decision"]),
        "external_verification_receipts": [],
    }
    expected["release_packet_without_receipts_sha256"] = canonical_sha256(
        {key: value for key, value in packet.items() if key != "external_verification_receipts"}
    )
    external_receipts = []
    for index in (0, 1):
        private = root_private["external_verifiers"][str(index)]
        key_id = _key_id(private)
        transcript_entry = next(item for item in entries if item["evidence_id"] == transcript_ids[key_id])
        transcript_root = str(transcript_entry["sha256"])
        receipt = {
            "schema": v624.VERIFICATION_RECEIPT_SCHEMA,
            **expected,
            "semantic_verifier_build_sha256": bundle["campaign"]["semantic_verifier_build_sha256"],  # type: ignore[index]
            "trust_policy_sha256": root["trust_policy_sha256"],
            "timestamp_policy_sha256": root["timestamp_policy_sha256"],
            "authority_identity_subject_id": next(
                item["identity_subject_id"]
                for item in root["authorities"]["external_verifiers"]  # type: ignore[index]
                if item["key_id"] == key_id
            ),
            "authority_control_group_id": next(
                item["control_group_id"]
                for item in root["authorities"]["external_verifiers"]  # type: ignore[index]
                if item["key_id"] == key_id
            ),
            "verification_session_id": f"{index + 11:032x}",
            "authority_challenge_nonce": f"{index + 21:032x}",
            "transparency_tree_root_sha256": checkpoint["tree_root_sha256"],
            "transparency_tree_size": checkpoint["tree_size"],
            "transparency_checkpoint_sequence": checkpoint["checkpoint_sequence"],
            "retrieved_evidence_byte_root_sha256": expected["evidence_bytes_root_sha256"],
            "execution_transcript_root_sha256": transcript_root,
            "measured_verifier_module_or_binary_sha256": bundle["campaign"]["semantic_verifier_build_sha256"],
            "execution_environment_attestation_sha256": _digest(f"environment:{index}"),
            "check_vector": {field: True for field in v624._CHECK_FIELDS},
            "independence_adjudicated_under_policy": True,
            "independence_ground_truth_proven": False,
            "issued_at_utc": verified_at,
            "verification_nonce": f"{index + 1:032x}",
            "started_at_utc": checkpoint_at,
            "completed_at_utc": checkpoint_at,
        }
        external_receipts.append(
            {
                "schema": v624.VERIFICATION_ENVELOPE_SCHEMA,
                "authority_key_id": _key_id(private),
                "receipt": receipt,
                "receipt_sha256": canonical_sha256(receipt),
                "signature_ed25519_base64": _sign(private, v624.DOMAIN_RELEASE_VERIFICATION, receipt),
            }
        )
    packet["external_verification_receipts"] = external_receipts
    return packet


@dataclass
class _ReleaseFixture:
    root: dict[str, object]
    release_authorization: dict[str, object]
    bootstrap: dict[str, object]
    bundle: dict[str, object]
    packet: dict[str, object]
    root_private: dict[str, dict[str, Ed25519PrivateKey]]
    root_path: Path
    release_authorization_path: Path
    bundle_path: Path
    packet_path: Path
    challenge_replay_db_path: Path
    evidence_path: Path
    verification_challenge_nonce: str


def _fixture(
    tmp_path: Path,
    *,
    same_external_control_group: bool = False,
    checkpoint_age_seconds: int = 0,
    maximum_checkpoint_age_seconds: int = 86_400,
    verification_challenge_nonce: str = VERIFICATION_CHALLENGE_NONCE,
    pair_source_state: str = "INDEPENDENT",
    pair_exposure_state: str = "INDEPENDENT",
) -> _ReleaseFixture:
    invocation_time = datetime.now(timezone.utc).replace(microsecond=0)
    checkpoint_time = invocation_time - timedelta(seconds=checkpoint_age_seconds)
    checkpoint_at = _utc_text(checkpoint_time)
    verified_at = _utc_text(invocation_time)
    v623_fixture = v623._make_fixture()
    bundle = deepcopy(v623_fixture.bundle)
    _admin_approvals(bundle)
    challenge_replay_db_path = tmp_path / "replay.sqlite3"
    bootstrap, bootstrap_private = _make_bootstrap_config(challenge_replay_db_path)
    root, root_private = _make_release_root(
        bundle,
        issued_at=v623._SIGNED_AT,
        maximum_checkpoint_age_seconds=maximum_checkpoint_age_seconds,
        same_external_control_group=same_external_control_group,
    )
    root_private["bootstrap"] = bootstrap_private
    root_private["lineage"] = {
        key_id: private
        for key_id, private in v623_fixture.private_by_key_id.items()
        if key_id in {
            str(unit["lineage_signature"]["key_id"]) for unit in bundle["units"]
        }
    }
    v625.BOOTSTRAP_TRUST_CONFIG = bootstrap
    packet = _build_packet(
        root,
        bundle,
        root_private,
        tmp_path,
        checkpoint_at=checkpoint_at,
        verified_at=verified_at,
        verification_challenge_nonce=verification_challenge_nonce,
        bootstrap=bootstrap,
        bootstrap_private=bootstrap_private,
        pair_source_state=pair_source_state,
        pair_exposure_state=pair_exposure_state,
    )
    root_path = tmp_path / "release-root.json"
    release_authorization_path = tmp_path / "release-root-authorization.json"
    bundle_path = tmp_path / "campaign-bundle.json"
    packet_path = tmp_path / "release-packet.json"
    release_authorization = _make_release_authorization(root, bootstrap, bootstrap_private)
    _write_json(root_path, root)
    _write_json(release_authorization_path, release_authorization)
    _write_json(bundle_path, bundle)
    _write_json(packet_path, packet)
    evidence_path = tmp_path / str(packet["evidence_manifest"]["entries"][0]["path"])  # type: ignore[index]
    return _ReleaseFixture(
        root,
        release_authorization,
        bootstrap,
        bundle,
        packet,
        root_private,
        root_path,
        release_authorization_path,
        bundle_path,
        packet_path,
        challenge_replay_db_path,
        evidence_path,
        verification_challenge_nonce,
    )


def _assert_no_authority(verdict: dict[str, object]) -> None:
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["production_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []
    assert verdict["sealed_holdout_accessed"] is False


def _verify_files(
    fixture: _ReleaseFixture,
    *,
    release_root_path: Path | None = None,
    expected_challenge: str | None = None,
) -> dict[str, object]:
    return v624._verify_population_release_files_legacy(
        release_root_path=release_root_path or fixture.root_path,
        release_root_authorization_path=fixture.release_authorization_path,
        campaign_bundle_path=fixture.bundle_path,
        release_packet_path=fixture.packet_path,
        challenge_replay_db_path=fixture.challenge_replay_db_path,
        expected_verification_challenge_nonce=(
            expected_challenge or fixture.verification_challenge_nonce
        ),
    )


def _replay_store_path_sha256(path: Path) -> str:
    canonical = path.parent.resolve(strict=True) / path.name
    return hashlib.sha256(str(canonical).encode("utf-8")).hexdigest()


def test_full_release_packet_passes_local_evidence_gate_and_has_no_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    monkeypatch.setattr(v625, "BOOTSTRAP_TRUST_CONFIG", fixture.bootstrap)
    assert fixture.bundle["schema"] == v623.BUNDLE_SCHEMA
    assert len(fixture.packet["evidence_manifest"]["entries"]) == 16 * 6 + 4 * 120 + 27 + 1 + 2  # type: ignore[index]
    assert sum(item["pair_id"] is not None for item in fixture.packet["evidence_manifest"]["entries"]) == 4 * 120  # type: ignore[index]
    transcript_entries = [
        item
        for item in fixture.packet["evidence_manifest"]["entries"]  # type: ignore[index]
        if item["evidence_purpose"] == "VERIFIER_EXECUTION_TRANSCRIPT"
    ]
    assert len(transcript_entries) == 2
    assert {item["unit_nonce"] for item in transcript_entries} == {
        fixture.verification_challenge_nonce
    }
    verdict = _verify_files(fixture)
    assert verdict["state"] == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING"
    assert verdict["external_authentication_verified"] is True
    assert verdict["semantic_artifact_verification_complete"] is True
    assert verdict["independence_adjudicated_under_policy"] is True
    assert verdict["population_feasible"] is True
    assert verdict["independence_ground_truth_proven"] is False
    _assert_no_authority(verdict)
    assert fixture.bootstrap["challenge_replay_store_path_sha256"] == _replay_store_path_sha256(  # type: ignore[arg-type]
        fixture.challenge_replay_db_path
    )
    assert fixture.release_authorization["authorization"]["released_module_or_binary_sha256"] == hashlib.sha256(  # type: ignore[index]
        Path(v625.__file__).read_bytes()
    ).hexdigest()
    connection = sqlite3.connect(fixture.challenge_replay_db_path)
    try:
        assert connection.execute(
            "SELECT replay_namespace FROM challenge_consumptions"
        ).fetchone() == (fixture.bootstrap["challenge_replay_namespace"],)
    finally:
        connection.close()
    assert fixture.challenge_replay_db_path.stat().st_mode & 0o077 == 0


def test_bootstrap_is_three_authority_and_adversarial_bootstrap_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    assert len(fixture.bootstrap["authorities"]) == 3  # type: ignore[arg-type]
    monkeypatch.setattr(v625, "BOOTSTRAP_TRUST_CONFIG", None)
    verdict = v625._assess_population_release_files_legacy(
        release_root_path=fixture.root_path,
        release_root_authorization_path=fixture.release_authorization_path,
        campaign_bundle_path=fixture.bundle_path,
        release_packet_path=fixture.packet_path,
        challenge_replay_db_path=fixture.challenge_replay_db_path,
        expected_verification_challenge_nonce=fixture.verification_challenge_nonce,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    _assert_no_authority(verdict)

    config = deepcopy(fixture.bootstrap)
    config["authorities"][1]["control_group_id"] = config["authorities"][0]["control_group_id"]  # type: ignore[index]
    monkeypatch.setattr(v625, "BOOTSTRAP_TRUST_CONFIG", config)
    verdict = v625._assess_population_release_files_legacy(
        release_root_path=fixture.root_path,
        release_root_authorization_path=fixture.release_authorization_path,
        campaign_bundle_path=fixture.bundle_path,
        release_packet_path=fixture.packet_path,
        challenge_replay_db_path=tmp_path / "bad-bootstrap.sqlite3",
        expected_verification_challenge_nonce=fixture.verification_challenge_nonce,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    _assert_no_authority(verdict)

    config = deepcopy(fixture.bootstrap)
    config["challenge_replay_store_path_sha256"] = _digest("wrong-replay-path")
    monkeypatch.setattr(v625, "BOOTSTRAP_TRUST_CONFIG", config)
    verdict = v625._assess_population_release_files_legacy(
        release_root_path=fixture.root_path,
        release_root_authorization_path=fixture.release_authorization_path,
        campaign_bundle_path=fixture.bundle_path,
        release_packet_path=fixture.packet_path,
        challenge_replay_db_path=tmp_path / "wrong.sqlite3",
        expected_verification_challenge_nonce=fixture.verification_challenge_nonce,
    )
    assert verdict["state"] == "POPULATION_INFEASIBLE"
    _assert_no_authority(verdict)


def test_release_authorization_and_root_adversaries_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    broken = deepcopy(fixture.release_authorization)
    broken["authorization"]["released_module_or_binary_sha256"] = "0" * 64  # type: ignore[index]
    _write_json(fixture.release_authorization_path, broken)
    with pytest.raises(v625.ReleaseV625Error, match="runtime verifier module hash|signature|authorization"):
        _verify_files(fixture)

    root = deepcopy(fixture.root)
    root["authorities"]["external_verifiers"][1]["control_group_id"] = root["authorities"]["external_verifiers"][0]["control_group_id"]  # type: ignore[index]
    root_path = tmp_path / "bad-root.json"
    _write_json(root_path, root)
    with pytest.raises(v625.ReleaseV625Error):
        _verify_files(fixture, release_root_path=root_path)


def test_transparency_inclusion_and_consistency_proofs_are_real_and_tamper_evident(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    receipt = fixture.packet["transparency_checkpoint"]["receipt"]  # type: ignore[index]
    for proof in receipt["inclusion_proofs"]:  # type: ignore[index]
        v625.verify_transparency_inclusion(
            leaf_hash=v625.transparency_leaf_hash(proof["kind"], proof["payload_sha256"]),
            leaf_index=proof["leaf_index"],
            tree_size=receipt["tree_size"],
            audit_path_sha256s=proof["audit_path_sha256s"],
            expected_root_sha256=receipt["tree_root_sha256"],
        )
    v625.verify_transparency_consistency(
        old_tree_size=receipt["previous_tree_size"],
        new_tree_size=receipt["tree_size"],
        old_root_sha256=receipt["previous_tree_root_sha256"],
        new_root_sha256=receipt["tree_root_sha256"],
        consistency_path_sha256s=receipt["consistency_proof_sha256s"],
    )
    with pytest.raises(v625.ReleaseV625Error):
        v625.verify_transparency_inclusion(
            leaf_hash=v625.transparency_leaf_hash(receipt["inclusion_proofs"][0]["kind"], receipt["inclusion_proofs"][0]["payload_sha256"]),
            leaf_index=receipt["inclusion_proofs"][0]["leaf_index"],
            tree_size=receipt["tree_size"],
            audit_path_sha256s=["0" * 64],
            expected_root_sha256=receipt["tree_root_sha256"],
        )
    with pytest.raises(v625.ReleaseV625Error):
        v625.verify_transparency_consistency(
            old_tree_size=receipt["previous_tree_size"],
            new_tree_size=receipt["tree_size"],
            old_root_sha256=receipt["previous_tree_root_sha256"],
            new_root_sha256=receipt["tree_root_sha256"],
            consistency_path_sha256s=["0" * 64],
        )


def test_intervention_graph_and_signed_receipts_are_bound(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    assert len(fixture.packet["intervention_graph"]["edges"]) == 120  # type: ignore[index]
    packet = deepcopy(fixture.packet)
    packet["intervention_graph"]["edges"][0]["state"] = "SAME_INTERVENTION"  # type: ignore[index]
    _write_json(fixture.packet_path, packet)
    with pytest.raises(v625.ReleaseV625Error, match="intervention"):
        _verify_files(fixture)


def _resign_verification_receipt(
    packet: dict[str, object], fixture: _ReleaseFixture, index: int
) -> None:
    envelope = packet["external_verification_receipts"][index]  # type: ignore[index]
    receipt = envelope["receipt"]
    envelope["receipt_sha256"] = canonical_sha256(receipt)
    private = fixture.root_private["external_verifiers"][str(index)]
    envelope["signature_ed25519_base64"] = _sign(private, v625.DOMAIN_RELEASE_VERIFICATION, receipt)


def test_transcript_and_session_replay_adversaries_fail_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    packet = deepcopy(fixture.packet)
    packet["external_verification_receipts"][1]["receipt"]["verification_session_id"] = packet["external_verification_receipts"][0]["receipt"]["verification_session_id"]  # type: ignore[index]
    _resign_verification_receipt(packet, fixture, 1)
    _write_json(fixture.packet_path, packet)
    with pytest.raises(v625.ReleaseV625Error, match="session|replayed|transcript"):
        _verify_files(fixture)


def test_evidence_byte_tamper_and_symlink_fail_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture.evidence_path.write_bytes(b"tampered")
    with pytest.raises(v625.ReleaseV625Error, match="evidence hash mismatch|size/type mismatch"):
        _verify_files(fixture)

    fixture = _fixture(tmp_path / "symlink")
    target = fixture.evidence_path.with_name("other.bin")
    target.write_bytes(b"other")
    fixture.evidence_path.unlink()
    fixture.evidence_path.symlink_to(target)
    with pytest.raises(v625.ReleaseV625Error, match="unable to open evidence safely"):
        _verify_files(fixture)


def test_replay_across_calls_and_failed_validation_do_not_consume(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    packet = deepcopy(fixture.packet)
    packet["verification_challenge_nonce"] = "ef" * 16
    _write_json(fixture.packet_path, packet)
    with pytest.raises(v625.ReleaseV625Error):
        _verify_files(fixture)
    _write_json(fixture.packet_path, fixture.packet)
    first = _verify_files(fixture)
    assert first["state"] == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING"
    with pytest.raises(v625.ReleaseV625Error, match="already consumed|replayed"):
        _verify_files(fixture)


def test_concurrent_same_challenge_consumes_exactly_once(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    barrier = threading.Barrier(2)
    outcomes: list[object] = []

    def verify() -> None:
        barrier.wait()
        try:
            outcomes.append(_verify_files(fixture))
        except Exception as exc:  # noqa: BLE001 - assert one durable replay failure.
            outcomes.append(exc)

    threads = [threading.Thread(target=verify) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert sum(isinstance(item, v625.ReleaseV625Error) for item in outcomes) == 1


def test_assess_is_stably_infeasible_and_no_authority_on_malformed_packet(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _write_json(fixture.packet_path, {"schema": v625.RELEASE_PACKET_SCHEMA})
    kwargs = {
        "release_root_path": fixture.root_path,
        "release_root_authorization_path": fixture.release_authorization_path,
        "campaign_bundle_path": fixture.bundle_path,
        "release_packet_path": fixture.packet_path,
        "challenge_replay_db_path": fixture.challenge_replay_db_path,
        "expected_verification_challenge_nonce": fixture.verification_challenge_nonce,
    }
    first = v625._assess_population_release_files_legacy(**kwargs)
    second = v625._assess_population_release_files_legacy(**kwargs)
    assert first == second
    assert first["state"] == "POPULATION_INFEASIBLE"
    _assert_no_authority(first)
