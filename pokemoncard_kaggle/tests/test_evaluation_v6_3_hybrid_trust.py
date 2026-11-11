from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3.common import (
    SIGNATURE_SCHEMA,
    V63Error,
    key_id_for_public_key,
    signing_message,
)
from evaluation_v6_3 import hybrid_trust as trust


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("utf-8")).digest())


def _identity(party_id: str, role: str, private: Ed25519PrivateKey) -> dict[str, Any]:
    public = private.public_key().public_bytes_raw()
    return {
        "schema": trust.PARTY_IDENTITY_SCHEMA,
        "party_id": party_id,
        "role": role,
        "legal_organization_id": f"legal-org-{party_id.lower()}",
        "identity_subject_id": f"identity-{party_id.lower()}",
        "control_group_id": f"control-{party_id.lower()}",
        "provider_name": f"provider-{party_id.lower()}",
        "provider_account_id": f"account-{party_id.lower()}",
        "provider_organization_id": f"provider-org-{party_id.lower()}",
        "account_owner_ids": [f"owner-{party_id.lower()}"],
        "project_access_role": "NONE",
        "project_admin": False,
        "project_owner": False,
        "project_maintainer": False,
        "project_write": False,
        "project_secrets_access": False,
        "project_runner_admin": False,
        "project_artifact_delete": False,
        "role_key_id": key_id_for_public_key(public),
        "role_public_key_base64": base64.b64encode(public).decode("ascii"),
        "role_key_custodian": f"key-custodian-{party_id.lower()}",
        "recovery_control_group": f"recovery-{party_id.lower()}",
        "parent_control_group_ids": [f"parent-{party_id.lower()}"],
    }


def _profile_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Ed25519PrivateKey]]:
    private = {party: _key(f"v63-{party}") for party in "ABCDE"}
    identities = {
        "A": _identity("A", "AUDIT_BRANCH", private["A"]),
        "B": _identity("B", "AUDIT_BRANCH", private["B"]),
        "C": _identity("C", "CUSTODY_REVIEWER", private["C"]),
        "D": _identity("D", "TIME_AUTHORITY", private["D"]),
        "E": _identity("E", "TIME_AUTHORITY", private["E"]),
    }
    profile = {
        "schema": trust.HYBRID_PROFILE_SCHEMA,
        "profile_id": trust.PROFILE_ID,
        "policy_status": trust.POLICY_STATUS,
        "project_control_group_ids": ["project-control"],
        "audit_branches": [
            {
                "schema": trust.AUDIT_BRANCH_SCHEMA,
                "branch_id": branch,
                "identity": identities[branch],
                "assigned_roles": list(trust.AUDIT_ROLES),
                "runtime_endpoint": f"https://audit-{branch.lower()}.example/v63",
                "runtime_pin_sha256": _digest(f"runtime-{branch}"),
            }
            for branch in ("A", "B")
        ],
        "custody_reviewer": {
            "schema": trust.CUSTODY_REVIEWER_SCHEMA,
            "reviewer_id": "C",
            "identity": identities["C"],
            "assigned_roles": [
                "ACCOUNT_CUSTODY_REVIEWER",
                "CONFLICT_ADJUDICATOR",
                "IDENTITY_REVIEWER",
            ],
        },
        "time_authorities": [
            {
                "schema": trust.TIME_AUTHORITY_SCHEMA,
                "authority_id": party,
                "identity": identities[party],
                "tsa_endpoint": f"https://tsa-{party.lower()}.example/rfc3161",
                "transport_security_mode": "SIGNED_RFC3161_RESPONSE",
                "endpoint_pin_sha256": _digest(f"tsa-endpoint-{party}"),
                "certificate_root_sha256": _digest(f"tsa-root-{party}"),
                "revocation_policy_root_sha256": _digest(f"tsa-revocation-{party}"),
            }
            for party in ("D", "E")
        ],
        "public_roots": {
            "schema": trust.PUBLIC_ROOTS_SCHEMA,
            "ethereum": {
                "schema": trust.ETHEREUM_POLICY_SCHEMA,
                "chain_id": "1",
                "contract_address": "0x" + "12" * 20,
                "deployment_transaction_hash": "0x" + "34" * 32,
                "deployed_bytecode_sha256": _digest("bytecode"),
                "source_tree_sha256": _digest("contract-source"),
                "compiler_settings_sha256": _digest("compiler"),
                "constructor_arguments_sha256": _digest("constructor"),
                "storage_layout_sha256": _digest("storage"),
                "abi_sha256": _digest("abi"),
                "state_machine_spec_sha256": _digest("state-machine"),
                "ownerless": True,
                "non_upgradeable": True,
                "proxy": False,
                "delegatecall": False,
                "arbitrary_external_call": False,
                "overwrite_or_delete": False,
                "emergency_reset": False,
                "challenge_ids_content_derived": True,
                "open_rejects_existing": True,
                "close_requires_open": True,
                "second_close_rejects": True,
                "zero_result_root_rejected": True,
                "minimum_rpc_observations": "2",
                "local_receipt_proof_required": True,
                "finality_required": True,
            },
            "drand": {
                "schema": trust.DRAND_POLICY_SCHEMA,
                "network_chain_hash": "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
                "network_public_key_hex": "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
                "minimum_independent_relays": "2",
                "future_round_commitment_required": True,
                "signature_verification_required": True,
                "exact_round_match_required": True,
                "silent_fallback_forbidden": True,
            },
        },
        "source_disclosure_policy": {
            "schema": trust.SOURCE_POLICY_SCHEMA,
            "eligible_modes": list(trust.ELIGIBLE_SOURCE_MODES),
            "auditor_branch_ids": ["A", "B"],
            "withheld_eligible": False,
            "private_dual_auditor_escrow_required": True,
        },
        "population_requirements": {
            "schema": trust.POPULATION_REQUIREMENTS_SCHEMA,
            "slot_count": "16",
            "source_family_count": "16",
            "lineage_time_block_count": "16",
            "development_principal_control_group_count": "16",
            "shared_strategic_scaffold_forbidden": True,
        },
        "quorums": {
            "schema": trust.QUORUMS_SCHEMA,
            "audit_branches": "2/2",
            "time_authorities": "2/2",
            "custody_reviewers": "1",
            "ethereum_rpc_providers": "2",
            "drand_relays": "2",
        },
        "hosted_transport_policy": {
            "schema": trust.HOSTED_TRANSPORT_POLICY_SCHEMA,
            "competition_ref": "pokemon-tcg-ai-battle",
            "account_team_identifier": "team-garlictoday",
            "allowed_kaggle_hosts": ["api.kaggle.com", "www.kaggle.com"],
            "peer_policy_pin_sha256": _digest("tls-policy"),
            "hostname_verification_required": True,
            "certificate_chain_capture_required": True,
            "spki_capture_required": True,
        },
        "crypto_runtime_policy": {
            "schema": trust.CRYPTO_RUNTIME_POLICY_SCHEMA,
            "drand_verifier_script_sha256": "69a42cfd846a32a9403c5f5fc57a1efb63299373871ccf2d023aa21cf2486e12",
            "drand_verifier_package_sha256": "bf362e0016798f809eb333f0f9589419e8fe38f3c1cade01dfd48833dba77e82",
            "drand_verifier_lock_sha256": "294fdefce98916f000a0c2ae21b27d988103c4bf0cd036a3543b4c89379a4a5a",
            "drand_client_version": "1.4.2",
            "node_executable_sha256": "19fa44ac565968cd4dbf38277854c829e441598f0872223881002efb471b40e9",
            "node_version": "v26.5.0",
            "dependency_tree_sha256": "fbcaf38ddf92f05b063097e3b695cbc4e11d06bcc46fb5498965b7a8d9f03993",
            "rfc3161_openssl_binary_sha256": _digest("candidate-openssl-binary"),
            "rfc3161_openssl_version": "CANDIDATE_UNPINNED",
            "ethereum_live_verifier_status": "NOT_IMPLEMENTED",
        },
    }
    return profile, trust.validate_hybrid_trust_profile(profile), private


def _signed_source(
    value: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    core = {key: value[key] for key in value if key != "signatures"}
    value["signatures"] = [
        {
            "schema": SIGNATURE_SCHEMA,
            "party_id": party,
            "key_id": key_id_for_public_key(private[party].public_key().public_bytes_raw()),
            "signature_base64": base64.b64encode(
                private[party].sign(signing_message(trust.DOMAIN_SOURCE_DISCLOSURE, core))
            ).decode("ascii"),
        }
        for party in ("A", "B", "C")
    ]
    return value


def test_valid_profile_is_five_organization_zero_authority() -> None:
    profile, parsed, _ = _profile_fixture()
    assert set(parsed["identities"]) == set("ABCDE")
    report = trust.assess_hybrid_trust_profile(profile)
    assert report["state"].startswith("V6_3_HYBRID_PROFILE_STRUCTURALLY_VALID")
    assert report["named_organization_count"] == 5
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["permits"] == []


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda value: value["audit_branches"][0]["identity"].__setitem__("project_write", True), "PROJECT_CONTROL_ALIAS"),
        (lambda value: value["audit_branches"][1]["identity"].__setitem__("parent_control_group_ids", ["parent-a"]), "AUDIT_BRANCH_INDEPENDENCE_INVALID"),
        (lambda value: value["custody_reviewer"]["identity"].__setitem__("legal_organization_id", "legal-org-a"), "CUSTODY_SEPARATION_INVALID"),
        (lambda value: value["custody_reviewer"]["identity"].__setitem__("account_owner_ids", ["owner-a"]), "CUSTODY_SEPARATION_INVALID"),
        (lambda value: value["time_authorities"][1]["identity"].__setitem__("control_group_id", "control-d"), "TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (lambda value: value["time_authorities"][1]["identity"].__setitem__("legal_organization_id", "legal-org-d"), "TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (lambda value: value["public_roots"]["ethereum"].__setitem__("proxy", True), "ETHEREUM_CONTRACT_POLICY_INVALID"),
    ],
)
def test_profile_rejects_independence_and_contract_aliases(mutator: Any, expected_code: str) -> None:
    profile, _, _ = _profile_fixture()
    mutator(profile)
    with pytest.raises(V63Error) as caught:
        trust.validate_hybrid_trust_profile(profile)
    assert caught.value.code == expected_code


def _ethereum_bundle(profile: dict[str, Any]) -> dict[str, Any]:
    challenge = _digest("challenge")
    opening = _digest("opening")
    result = _digest("result")
    open_tx = {
        "schema": trust.ETHEREUM_TX_SCHEMA,
        "transaction_hash": "0x" + "56" * 32,
        "block_hash": "0x" + "67" * 32,
        "block_number": "100",
        "finalized": True,
        "challenge_id": challenge,
        "from_state": "UNSEEN",
        "to_state": "OPEN",
        "bound_value_sha256": opening,
    }
    close_tx = {
        "schema": trust.ETHEREUM_TX_SCHEMA,
        "transaction_hash": "0x" + "78" * 32,
        "block_hash": "0x" + "89" * 32,
        "block_number": "101",
        "finalized": True,
        "challenge_id": challenge,
        "from_state": "OPEN",
        "to_state": "CLOSED",
        "bound_value_sha256": result,
    }
    expected = {
        "chain_id": "1",
        "contract_address": profile["public_roots"]["ethereum"]["contract_address"],
        "challenge_id": challenge,
        "state": "CLOSED",
        "opening_commitment_sha256": opening,
        "result_root_sha256": result,
        "open_transaction_hash": open_tx["transaction_hash"],
        "close_transaction_hash": close_tx["transaction_hash"],
        "open_block_hash": open_tx["block_hash"],
        "close_block_hash": close_tx["block_hash"],
    }
    return {
        "schema": trust.ETHEREUM_BUNDLE_SCHEMA,
        "profile_sha256": profile["sha256"],
        "chain_id": "1",
        "contract_address": expected["contract_address"],
        "challenge_id": challenge,
        "opening_commitment_sha256": opening,
        "result_root_sha256": result,
        "open_receipt": open_tx,
        "close_receipt": close_tx,
        "rpc_observations": [
            {
                "schema": trust.ETHEREUM_RPC_SCHEMA,
                "provider_id": f"rpc-{index}",
                "provider_control_group_id": f"rpc-control-{index}",
                "observed_at": f"2026-07-16T12:0{index}:00Z",
                **expected,
            }
            for index in (1, 2)
        ],
        "local_receipt_proof_valid": True,
    }


def test_ethereum_bundle_requires_finality_and_two_agreeing_providers() -> None:
    _, profile, _ = _profile_fixture()
    bundle = _ethereum_bundle(profile)
    result = trust.validate_synthetic_ethereum_transition_fixture(bundle, profile=profile)
    assert result["rpc_provider_ids"] == ("rpc-1", "rpc-2")
    broken = deepcopy(bundle)
    broken["close_receipt"]["finalized"] = False
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_ethereum_transition_fixture(broken, profile=profile)
    assert caught.value.code == "ETHEREUM_FINALITY_INVALID"
    broken = deepcopy(bundle)
    broken["rpc_observations"][1]["result_root_sha256"] = _digest("conflict")
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_ethereum_transition_fixture(broken, profile=profile)
    assert caught.value.code == "ETHEREUM_PROVIDER_DISAGREEMENT"
    broken = deepcopy(bundle)
    broken["close_receipt"]["transaction_hash"] = broken["open_receipt"]["transaction_hash"]
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_ethereum_transition_fixture(broken, profile=profile)
    assert caught.value.code == "ETHEREUM_TRANSITION_INVALID"


def _drand_receipt(profile: dict[str, Any]) -> dict[str, Any]:
    base = {
        "network_chain_hash": profile["public_roots"]["drand"]["network_chain_hash"],
        "round": "500",
        "randomness_sha256": _digest("randomness"),
        "signature_sha256": _digest("signature"),
    }
    return {
        "schema": trust.DRAND_RECEIPT_SCHEMA,
        "profile_sha256": profile["sha256"],
        "network_chain_hash": base["network_chain_hash"],
        "committed_round": "500",
        "returned_round": "500",
        "commitment_observed_at": "2026-07-16T11:00:00Z",
        "round_timestamp": "2026-07-16T12:00:00Z",
        "randomness_sha256": base["randomness_sha256"],
        "signature_sha256": base["signature_sha256"],
        "previous_signature_sha256": _digest("previous"),
        "signature_verified": True,
        "relay_observations": [
            {
                "schema": trust.DRAND_RELAY_SCHEMA,
                "relay_id": f"relay-{index}",
                "relay_control_group_id": f"relay-control-{index}",
                **base,
                "observed_at": f"2026-07-16T12:00:0{index}Z",
            }
            for index in (1, 2)
        ],
    }


def test_drand_requires_committed_exact_round_and_independent_relays() -> None:
    _, profile, _ = _profile_fixture()
    receipt = _drand_receipt(profile)
    assert trust.validate_synthetic_drand_receipt_fixture(receipt, profile=profile)["round"] == 500
    broken = deepcopy(receipt)
    broken["returned_round"] = "501"
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_drand_receipt_fixture(broken, profile=profile)
    assert caught.value.code == "DRAND_RECEIPT_INVALID"
    broken = deepcopy(receipt)
    broken["relay_observations"][1]["relay_control_group_id"] = "relay-control-1"
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_drand_receipt_fixture(broken, profile=profile)
    assert caught.value.code == "DRAND_RELAY_DISAGREEMENT"


def _time_receipts(profile: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "schema": trust.TIME_RECEIPT_SCHEMA,
            "profile_sha256": profile["sha256"],
            "authority_id": party,
            "payload_sha256": _digest("payload"),
            "campaign_nonce_sha256": _digest("nonce"),
            "review_challenge_sha256": _digest("challenge"),
            "tsa_policy_oid": f"1.2.3.{index}",
            "serial_number": str(index),
            "gen_time": f"2026-07-16T12:00:0{index}Z",
            "nonce": "123456",
            "signer_certificate_chain_sha256": _digest(f"chain-{party}"),
            "token_sha256": _digest(f"token-{party}"),
            "signature_verified": True,
            "certificate_valid_at_gen_time": True,
            "revocation_checked_under_frozen_policy": True,
        }
        for index, party in enumerate(("D", "E"), start=1)
    ]


def test_time_quorum_is_two_of_two_and_same_payload() -> None:
    _, profile, _ = _profile_fixture()
    receipts = _time_receipts(profile)
    assert trust.validate_synthetic_time_quorum_fixture(receipts, profile=profile)["authority_ids"] == ("D", "E")
    broken = deepcopy(receipts)
    broken[1]["payload_sha256"] = _digest("other")
    with pytest.raises(V63Error) as caught:
        trust.validate_synthetic_time_quorum_fixture(broken, profile=profile)
    assert caught.value.code == "TIME_QUORUM_INVALID"


def test_private_source_requires_both_auditor_escrows() -> None:
    _, profile, private = _profile_fixture()
    disclosure = {
        "schema": trust.SOURCE_DISCLOSURE_SCHEMA,
        "profile_sha256": profile["sha256"],
        "campaign_root_sha256": _digest("campaign"),
        "slot_id": "D01",
        "archive_sha256": _digest("archive-D01"),
        "archive_byte_length": "4096",
        "package_sha256": _digest("package-D01"),
        "mode": "PRIVATE_DUAL_AUDITOR_ESCROW",
        "source_tree_sha256": _digest("source-D01"),
        "source_family_id": "family-D01",
        "lineage_time_block_id": "lineage-D01",
        "development_principal_control_group_id": "development-D01",
        "live_challenge_sha256": _digest("challenge-D01"),
        "public_source_root_sha256": None,
        "auditor_escrow_receipts": {"A": _digest("escrow-a"), "B": _digest("escrow-b")},
    }
    _signed_source(disclosure, private)
    assert trust.validate_source_disclosure(disclosure, profile=profile).mode.startswith("PRIVATE")
    disclosure["auditor_escrow_receipts"].pop("B")
    with pytest.raises(V63Error) as caught:
        trust.validate_source_disclosure(disclosure, profile=profile)
    assert caught.value.code == "SOURCE_ESCROW_INCOMPLETE"


def test_population_source_disclosures_bind_all_16_unique_components() -> None:
    _, profile, private = _profile_fixture()
    validated = []
    for slot in trust.SLOTS:
        disclosure = {
            "schema": trust.SOURCE_DISCLOSURE_SCHEMA,
            "profile_sha256": profile["sha256"],
            "campaign_root_sha256": _digest("campaign"),
            "slot_id": slot,
            "archive_sha256": _digest(f"archive-{slot}"),
            "archive_byte_length": "4096",
            "package_sha256": _digest(f"package-{slot}"),
            "mode": "PRIVATE_DUAL_AUDITOR_ESCROW",
            "source_tree_sha256": _digest(f"source-{slot}"),
            "source_family_id": f"family-{slot}",
            "lineage_time_block_id": f"lineage-{slot}",
            "development_principal_control_group_id": f"development-{slot}",
            "live_challenge_sha256": _digest(f"challenge-{slot}"),
            "public_source_root_sha256": None,
            "auditor_escrow_receipts": {"A": _digest(f"escrow-a-{slot}"), "B": _digest(f"escrow-b-{slot}")},
        }
        validated.append(trust.validate_source_disclosure(_signed_source(disclosure, private), profile=profile))
    result = trust.validate_population_source_disclosures(validated)
    assert result["source_family_count"] == 16
    assert result["calibration_upload_authorized"] is False
    duplicate = list(validated)
    duplicate_disclosure = {
        "schema": trust.SOURCE_DISCLOSURE_SCHEMA,
        "profile_sha256": profile["sha256"],
        "campaign_root_sha256": _digest("campaign"),
        "slot_id": "CR01",
        "archive_sha256": _digest("archive-CR01-duplicate-test"),
        "archive_byte_length": "4096",
        "package_sha256": _digest("package-CR01-duplicate-test"),
        "mode": "PRIVATE_DUAL_AUDITOR_ESCROW",
        "source_tree_sha256": _digest("source-CR01-duplicate-test"),
        "source_family_id": duplicate[0].source_family_id,
        "lineage_time_block_id": "lineage-CR01-duplicate-test",
        "development_principal_control_group_id": "development-CR01-duplicate-test",
        "live_challenge_sha256": _digest("challenge-CR01-duplicate-test"),
        "public_source_root_sha256": None,
        "auditor_escrow_receipts": {"A": _digest("escrow-a-CR01-duplicate"), "B": _digest("escrow-b-CR01-duplicate")},
    }
    duplicate[-1] = trust.validate_source_disclosure(
        _signed_source(duplicate_disclosure, private),
        profile=profile,
    )
    with pytest.raises(V63Error) as caught:
        trust.validate_population_source_disclosures(duplicate)
    assert caught.value.code == "SOURCE_ESCROW_INCOMPLETE"


def test_live_crypto_verifiers_are_explicitly_fail_closed() -> None:
    _, profile, _ = _profile_fixture()
    with pytest.raises(V63Error) as caught:
        trust.verify_live_ethereum_transition(profile=profile, raw_evidence=b"ethereum")
    assert caught.value.code == "LIVE_CRYPTOGRAPHIC_VERIFIER_NOT_IMPLEMENTED"


def test_malformed_profile_assessment_returns_zero_authority() -> None:
    raw, _, _ = _profile_fixture()
    raw["audit_branches"][0]["identity"]["project_access_role"] = []
    report = trust.assess_hybrid_trust_profile(raw)
    assert report["state"] == "PROJECT_CONTROL_ALIAS"
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
