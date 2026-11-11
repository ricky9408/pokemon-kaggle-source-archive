from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
from types import MappingProxyType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3.common import V63Error, key_id_for_public_key
from evaluation_v6_3_1 import policy


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _identity(
    party: str,
    role: str,
    private: Ed25519PrivateKey,
) -> dict[str, Any]:
    public = private.public_key().public_bytes_raw()
    is_time = role == "RFC3161_TIME_AUTHORITY"
    return {
        "schema": policy.IDENTITY_SCHEMA,
        "party_id": party,
        "role": role,
        "legal_organization_id": f"org-{party}",
        "identity_subject_id": f"subject-{party}",
        "control_group_id": f"control-{party}",
        "provider_name": f"provider-{party}",
        "provider_account_id": f"account-{party}",
        "provider_organization_id": f"provider-org-{party}",
        "runtime_admin_control_group_id": f"runtime-{party}",
        "account_owner_ids": [f"owner-{party}"],
        "role_key_id": key_id_for_public_key(public),
        "role_public_key_base64": base64.b64encode(public).decode("ascii"),
        "role_key_custodian_id": f"key-custodian-{party}",
        "endpoint": f"http{'s' if party == 'E' else ''}://tsa-{party.lower()}.example/timestamp" if is_time else None,
        "tsa_policy_oid": f"1.2.3.4.{1 if party == 'D' else 2}" if is_time else None,
        "trust_root_sha256": _digest(f"trust-{party}") if is_time else None,
        "tsa_signer_spki_sha256": _digest(f"signer-spki-{party}") if is_time else None,
        "revocation_policy_root_sha256": _digest(f"revocation-{party}") if is_time else None,
        "revocation_issuer_spki_sha256": _digest(f"revocation-spki-{party}") if is_time else None,
        "identity_evidence_root_sha256": _digest(f"identity-{party}") if is_time else None,
        "project_controlled": False,
        "contributes_campaign_agents": False,
        "outcome_contingent_compensation": False,
    }


def _profile_with_keys() -> tuple[dict[str, Any], dict[str, Ed25519PrivateKey]]:
    keys = {party: Ed25519PrivateKey.generate() for party in ("A", "B", "D", "E")}
    profile = {
        "schema": policy.POLICY_SCHEMA,
        "profile_id": "pokemon-v631-candidate",
        "policy_status": "CANDIDATE_UNPINNED",
        "project_control_group_ids": ["project-control"],
        "audit_branches": [
            _identity("A", "AUDIT_BRANCH", keys["A"]),
            _identity("B", "AUDIT_BRANCH", keys["B"]),
        ],
        "time_authorities": [
            _identity("D", "RFC3161_TIME_AUTHORITY", keys["D"]),
            _identity("E", "RFC3161_TIME_AUTHORITY", keys["E"]),
        ],
        "drand": {
            "schema": policy.DRAND_POLICY_SCHEMA,
            "network": "mainnet",
            "chain_hash": _digest("drand-chain"),
            "public_key_base64": base64.b64encode(b"d" * 96).decode("ascii"),
            "period_seconds": "3",
            "genesis_time": "1595431050",
            "live_verifier_root_sha256": _digest("drand-verifier"),
            "group_hash": _digest("drand-group"),
            "scheme_id": "bls-unchained-g1-rfc9380",
            "beacon_id": "quicknet",
        },
        "kaggle": {
            "schema": policy.KAGGLE_POLICY_SCHEMA,
            "competition_ref": "pokemon-tcg-ai-battle",
            "account_team_identifier": "team-garlictoday",
            "allowed_hosts": ["api.kaggle.com", "www.kaggle.com"],
            "peer_policy_root_sha256": _digest("kaggle-peer-policy"),
        },
        "artifact_roots": {
            "schema": policy.ARTIFACT_ROOTS_SCHEMA,
            "population_spec_sha256": _digest("population-spec"),
            "statistics_spec_sha256": _digest("statistics-spec"),
            "hosted_custody_spec_sha256": _digest("custody-spec"),
            "permit_spec_sha256": _digest("permit-spec"),
            "code_root_sha256": _digest("code-root"),
            "build_root_sha256": _digest("build-root"),
        },
        "budgets": {
            "schema": policy.BUDGET_SCHEMA,
            "calibration_max_uploads": "16",
            "production_reserved_uploads": "1",
        },
        "crypto_runtime": {
            "schema": policy.CRYPTO_RUNTIME_POLICY_SCHEMA,
            "openssl_executable_path": "/runtime/openssl",
            "openssl_executable_sha256": _digest("openssl"),
            "node_executable_path": "/runtime/node",
            "node_executable_sha256": _digest("node"),
            "rfc3161_imprint_oid": "2.16.840.1.101.3.4.2.1",
        },
    }
    return profile, keys


def _profile() -> dict[str, Any]:
    return _profile_with_keys()[0]


def test_candidate_policy_is_immutable_and_zero_authority() -> None:
    raw = _profile()
    parsed = policy.validate_candidate_policy(raw)
    assert parsed["kaggle"]["account_team_identifier"] == "team-garlictoday"
    with pytest.raises(TypeError):
        parsed["kaggle"]["account_team_identifier"] = "other"  # type: ignore[index]
    report = policy.assess_candidate_policy(raw)
    assert report["state"] == "V631_POLICY_STRUCTURALLY_VALID_EXTERNAL_ROSTER_AND_PIN_ABSENT"
    assert report["candidate_policy_structurally_valid"] is True
    assert report["authority"] == "NO_UPLOAD"
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["production_slots_remaining"] == 1
    assert report["permits"] == []


def test_require_validated_policy_rejects_dataclass_replace_and_copied_sentinel() -> None:
    parsed = policy.validate_candidate_policy(_profile())
    altered = dict(parsed._data)
    altered["sha256"] = "0" * 64
    replaced = replace(parsed, _data=MappingProxyType(altered))
    copied = policy.ValidatedV631Policy(MappingProxyType(altered), parsed._construction_token)
    for forged in (replaced, copied):
        with pytest.raises(V63Error) as caught:
            policy.require_validated_policy(forged)
        assert caught.value.code == "V631_POLICY_INVALID"


def test_require_validated_policy_revalidates_issued_state() -> None:
    parsed = policy.validate_candidate_policy(_profile())
    reissued = policy.require_validated_policy(parsed)
    assert reissued is not parsed
    assert reissued["sha256"] == parsed["sha256"]
    assert reissued["raw"] == parsed["raw"]
    copied = policy.ValidatedV631Policy(parsed._data, parsed._construction_token)
    copied_reissued = policy.require_validated_policy(copied)
    assert copied_reissued is not copied
    assert copied_reissued["sha256"] == parsed["sha256"]


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("budgets", "calibration_max_uploads"), "15", "V631_POLICY_INVALID"),
        (("kaggle", "competition_ref"), "other", "V631_POLICY_INVALID"),
        (("audit_branches", 0, "project_controlled"), True, "V631_EXTERNAL_ROSTER_INVALID"),
        (("audit_branches", 0, "contributes_campaign_agents"), True, "V631_EXTERNAL_ROSTER_INVALID"),
        (("time_authorities", 1, "tsa_policy_oid"), "1.2.3.4.1", "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("time_authorities", 1, "trust_root_sha256"), _digest("trust-D"), "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("time_authorities", 1, "tsa_signer_spki_sha256"), _digest("signer-spki-D"), "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("time_authorities", 1, "revocation_policy_root_sha256"), _digest("revocation-D"), "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("time_authorities", 1, "revocation_issuer_spki_sha256"), _digest("revocation-spki-D"), "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("time_authorities", 1, "identity_evidence_root_sha256"), _digest("identity-D"), "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID"),
        (("crypto_runtime", "rfc3161_imprint_oid"), "1.3.14.3.2.26", "V631_POLICY_INVALID"),
    ],
)
def test_candidate_policy_rejects_authority_and_boundary_mutations(
    path: tuple[Any, ...],
    value: Any,
    code: str,
) -> None:
    raw = _profile()
    target: Any = raw
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(V63Error) as caught:
        policy.validate_candidate_policy(raw)
    assert caught.value.code == code


def test_candidate_policy_rejects_shared_external_control() -> None:
    raw = _profile()
    raw["audit_branches"][1]["control_group_id"] = raw["audit_branches"][0]["control_group_id"]
    with pytest.raises(V63Error) as caught:
        policy.validate_candidate_policy(raw)
    assert caught.value.code == "V631_AUDITOR_INDEPENDENCE_INVALID"


@pytest.mark.parametrize(
    ("target_field", "source_field"),
    [
        ("runtime_admin_control_group_id", "control_group_id"),
        ("account_owner_ids", "provider_account_id"),
        ("role_key_custodian_id", "identity_subject_id"),
    ],
)
def test_candidate_policy_rejects_cross_field_control_aliases(
    target_field: str,
    source_field: str,
) -> None:
    raw = _profile()
    source = raw["audit_branches"][0][source_field]
    raw["audit_branches"][1][target_field] = [source] if target_field == "account_owner_ids" else source
    with pytest.raises(V63Error) as caught:
        policy.validate_candidate_policy(raw)
    assert caught.value.code == "V631_AUDITOR_INDEPENDENCE_INVALID"


def test_candidate_policy_rejects_project_control_alias() -> None:
    raw = _profile()
    raw["audit_branches"][0]["runtime_admin_control_group_id"] = "project-control"
    with pytest.raises(V63Error) as caught:
        policy.validate_candidate_policy(raw)
    assert caught.value.code == "V631_PROJECT_CONTROL_ALIAS"


def test_current_status_is_literal_no_pin_zero_authority() -> None:
    assert policy.PINNED_V631_POLICY is None
    report = policy.current_status()
    assert report["state"] == "V631_LOCAL_IMPLEMENTATION_INCOMPLETE_EXTERNAL_EVIDENCE_ABSENT"
    assert report["candidate_policy_pinned"] is False
    assert report["calibration_slots_remaining"] == 16
    assert report["production_slots_remaining"] == 1
    assert report["sealed_holdout_accessed"] is False
    assert report["authority"] == "NO_UPLOAD"
