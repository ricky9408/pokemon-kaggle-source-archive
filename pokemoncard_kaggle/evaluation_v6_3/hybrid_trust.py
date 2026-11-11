"""Hybrid five-organization trust profile for evaluation v6.3.

This replaces the infeasible v6.2.6 fourteen-organization operating model.  It
implements Sol's HYBRID_NAMED_COLLABORATORS_REQUIRED ruling as a strict,
outcome-free conformance boundary.  Passing this module proves only structural
compatibility with the candidate profile; it never pins policy or authorizes a
campaign action.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
import re
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from evaluation_v6_2.integration_v622 import SLOTS

from .common import (
    KEY_ID_RE,
    V63Error,
    canonical_base64,
    canonical_integer,
    canonical_sha256,
    canonical_string_list,
    exact,
    fail,
    identifier,
    key_id_for_public_key,
    sha256,
    utc,
    verify_signature_set,
    zero_authority,
)


HYBRID_PROFILE_SCHEMA = "eval.v6.3.hybrid-trust-profile"
PARTY_IDENTITY_SCHEMA = "eval.v6.3.party-identity"
AUDIT_BRANCH_SCHEMA = "eval.v6.3.audit-branch"
CUSTODY_REVIEWER_SCHEMA = "eval.v6.3.custody-reviewer"
TIME_AUTHORITY_SCHEMA = "eval.v6.3.time-authority"
PUBLIC_ROOTS_SCHEMA = "eval.v6.3.public-roots"
ETHEREUM_POLICY_SCHEMA = "eval.v6.3.ethereum-policy"
DRAND_POLICY_SCHEMA = "eval.v6.3.drand-policy"
SOURCE_POLICY_SCHEMA = "eval.v6.3.source-disclosure-policy"
POPULATION_REQUIREMENTS_SCHEMA = "eval.v6.3.population-requirements"
QUORUMS_SCHEMA = "eval.v6.3.quorums"
HOSTED_TRANSPORT_POLICY_SCHEMA = "eval.v6.3.hosted-transport-policy"
CRYPTO_RUNTIME_POLICY_SCHEMA = "eval.v6.3.crypto-runtime-policy"
SOURCE_DISCLOSURE_SCHEMA = "eval.v6.3.source-disclosure"
ETHEREUM_BUNDLE_SCHEMA = "eval.v6.3.ethereum-transition-bundle"
ETHEREUM_TX_SCHEMA = "eval.v6.3.ethereum-transaction-receipt"
ETHEREUM_RPC_SCHEMA = "eval.v6.3.ethereum-rpc-observation"
DRAND_RECEIPT_SCHEMA = "eval.v6.3.drand-receipt"
DRAND_RELAY_SCHEMA = "eval.v6.3.drand-relay-observation"
TIME_RECEIPT_SCHEMA = "eval.v6.3.rfc3161-receipt"
SOURCE_DISCLOSURE_SIGNATURE_SCHEMA = "eval.v6.3.source-disclosure-signature"
DOMAIN_SOURCE_DISCLOSURE = b"EVAL-V63/SOURCE-DISCLOSURE\0"

PROFILE_ID = "v6.3-hybrid"
POLICY_STATUS = "CANDIDATE_UNPINNED"

AUDIT_ROLES = (
    "CAMPAIGN_EVIDENCE_CUSTODIAN",
    "LINEAGE_INTERVENTION_REVIEWER",
    "RUNTIME_CUSTODIAN",
    "SEMANTIC_VERIFIER",
    "TECHNICAL_SOURCE_AUDITOR",
)
ELIGIBLE_SOURCE_MODES = ("PRIVATE_DUAL_AUDITOR_ESCROW", "PUBLIC")

ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
ETH_TX_RE = re.compile(r"^0x[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]+$")


FAILURE_STATES = frozenset(
    {
        "HYBRID_PROFILE_INVALID",
        "PROJECT_CONTROL_ALIAS",
        "AUDIT_BRANCH_INDEPENDENCE_INVALID",
        "CUSTODY_SEPARATION_INVALID",
        "TIME_AUTHORITY_INDEPENDENCE_INVALID",
        "ETHEREUM_CONTRACT_POLICY_INVALID",
        "ETHEREUM_TRANSITION_INVALID",
        "ETHEREUM_FINALITY_INVALID",
        "ETHEREUM_PROVIDER_DISAGREEMENT",
        "DRAND_RECEIPT_INVALID",
        "DRAND_RELAY_DISAGREEMENT",
        "TIME_QUORUM_INVALID",
        "SOURCE_ESCROW_INCOMPLETE",
        "LIVE_CRYPTOGRAPHIC_VERIFIER_NOT_IMPLEMENTED",
    }
)


_PROFILE_SENTINEL = object()
_SOURCE_SENTINEL = object()


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) in {list, tuple}:
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class ValidatedHybridProfile(Mapping[str, Any]):
    """Immutable output of the exact candidate-profile validator."""

    _data: Mapping[str, Any]
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _PROFILE_SENTINEL:
            raise ValueError("ValidatedHybridProfile can only be created by validate_hybrid_trust_profile")

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


def _validated_profile(value: Any) -> ValidatedHybridProfile:
    if type(value) is not ValidatedHybridProfile:
        raise fail("HYBRID_PROFILE_INVALID", "downstream evidence requires an immutable validated hybrid profile")
    return value


@dataclass(frozen=True)
class ValidatedSourceDisclosure:
    receipt_sha256: str
    profile_sha256: str
    campaign_root_sha256: str
    slot_id: str
    archive_sha256: str
    archive_byte_length: int
    source_tree_sha256: str
    source_family_id: str
    lineage_time_block_id: str
    development_principal_control_group_id: str
    live_challenge_sha256: str
    mode: str
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _SOURCE_SENTINEL:
            raise ValueError("ValidatedSourceDisclosure can only be created by validate_source_disclosure")


_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "party_id",
        "role",
        "legal_organization_id",
        "identity_subject_id",
        "control_group_id",
        "provider_name",
        "provider_account_id",
        "provider_organization_id",
        "account_owner_ids",
        "project_access_role",
        "project_admin",
        "project_owner",
        "project_maintainer",
        "project_write",
        "project_secrets_access",
        "project_runner_admin",
        "project_artifact_delete",
        "role_key_id",
        "role_public_key_base64",
        "role_key_custodian",
        "recovery_control_group",
        "parent_control_group_ids",
    }
)


def _https_endpoint(value: Any, label: str, *, code: str) -> str:
    endpoint = identifier(value, label, code=code)
    parsed = urlparse(endpoint)
    try:
        port = parsed.port
    except ValueError as exc:
        raise fail(code, f"{label} port is invalid") from exc
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or host != host.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in endpoint
    ):
        raise fail(code, f"{label} must be canonical absolute HTTPS")
    canonical_netloc = host if port in {None, 443} else f"{host}:{port}"
    if parsed.netloc != canonical_netloc or port == 443:
        raise fail(code, f"{label} authority is not canonical")
    path = parsed.path or "/"
    if parsed.path != path or "//" in path or "/../" in path or "/./" in path:
        raise fail(code, f"{label} path is not canonical")
    return endpoint


def _rfc3161_endpoint(value: Any, label: str, *, code: str) -> str:
    endpoint = identifier(value, label, code=code)
    parsed = urlparse(endpoint)
    try:
        port = parsed.port
    except ValueError as exc:
        raise fail(code, f"{label} port is invalid") from exc
    host = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or host != host.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in endpoint
    ):
        raise fail(code, f"{label} must be canonical absolute HTTP(S)")
    default_port = 80 if parsed.scheme == "http" else 443
    canonical_netloc = host if port in {None, default_port} else f"{host}:{port}"
    if parsed.netloc != canonical_netloc or port == default_port:
        raise fail(code, f"{label} authority is not canonical")
    path = parsed.path or "/"
    if parsed.path != path or "//" in path or "/../" in path or "/./" in path:
        raise fail(code, f"{label} path is not canonical")
    return endpoint


def _identity(value: Any, *, expected_party_id: str, expected_role: str) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(value, _IDENTITY_FIELDS, f"identity {expected_party_id}", code=code)
    if (
        item["schema"] != PARTY_IDENTITY_SCHEMA
        or item["party_id"] != expected_party_id
        or item["role"] != expected_role
    ):
        raise fail(code, f"identity {expected_party_id} has the wrong schema, party, or role")
    owners = canonical_string_list(item["account_owner_ids"], "account_owner_ids", code=code)
    parents = canonical_string_list(
        item["parent_control_group_ids"],
        "parent_control_group_ids",
        code=code,
        allow_empty=True,
    )
    access_role = item["project_access_role"]
    if type(access_role) is not str or access_role not in {"NONE", "READ_ONLY"}:
        raise fail("PROJECT_CONTROL_ALIAS", "project access must be NONE or READ_ONLY")
    access_bits = (
        "project_admin",
        "project_owner",
        "project_maintainer",
        "project_write",
        "project_secrets_access",
        "project_runner_admin",
        "project_artifact_delete",
    )
    if any(item[field] is not False for field in access_bits):
        raise fail("PROJECT_CONTROL_ALIAS", "all project privilege bits must be false")
    public_key = canonical_base64(
        item["role_public_key_base64"],
        "role_public_key_base64",
        code=code,
        expected_length=32,
    )
    key_id = identifier(item["role_key_id"], "role_key_id", code=code)
    if KEY_ID_RE.fullmatch(key_id) is None or key_id_for_public_key(public_key) != key_id:
        raise fail(code, "role_key_id does not match role_public_key_base64")
    parsed = {
        field: identifier(item[field], field, code=code)
        for field in (
            "party_id",
            "role",
            "legal_organization_id",
            "identity_subject_id",
            "control_group_id",
            "provider_name",
            "provider_account_id",
            "provider_organization_id",
            "role_key_id",
            "role_key_custodian",
            "recovery_control_group",
        )
    }
    parsed.update(
        {
            "raw": dict(item),
            "account_owner_ids": owners,
            "parent_control_group_ids": parents,
            "role_public_key_base64": item["role_public_key_base64"],
            "project_access_role": access_role,
        }
    )
    return parsed


def _audit_branch(value: Any, expected_id: str) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "branch_id",
                "identity",
                "assigned_roles",
                "runtime_endpoint",
                "runtime_pin_sha256",
            }
        ),
        f"audit branch {expected_id}",
        code=code,
    )
    if item["schema"] != AUDIT_BRANCH_SCHEMA or item["branch_id"] != expected_id:
        raise fail(code, f"audit branch {expected_id} schema or id mismatch")
    roles = canonical_string_list(
        item["assigned_roles"],
        "audit assigned roles",
        code=code,
        expected_count=len(AUDIT_ROLES),
    )
    if roles != AUDIT_ROLES:
        raise fail(code, "audit branch must carry the exact colocated v6.3 role set")
    return {
        "branch_id": expected_id,
        "identity": _identity(item["identity"], expected_party_id=expected_id, expected_role="AUDIT_BRANCH"),
        "assigned_roles": roles,
        "runtime_endpoint": _https_endpoint(item["runtime_endpoint"], "runtime endpoint", code=code),
        "runtime_pin_sha256": sha256(item["runtime_pin_sha256"], "runtime pin", code=code),
    }


def _custody_reviewer(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset({"schema", "reviewer_id", "identity", "assigned_roles"}),
        "custody reviewer",
        code=code,
    )
    if item["schema"] != CUSTODY_REVIEWER_SCHEMA or item["reviewer_id"] != "C":
        raise fail(code, "custody reviewer schema or id mismatch")
    roles = canonical_string_list(item["assigned_roles"], "custody roles", code=code)
    expected = ("ACCOUNT_CUSTODY_REVIEWER", "CONFLICT_ADJUDICATOR", "IDENTITY_REVIEWER")
    if roles != expected:
        raise fail(code, "custody reviewer has the wrong role set")
    return {
        "reviewer_id": "C",
        "identity": _identity(item["identity"], expected_party_id="C", expected_role="CUSTODY_REVIEWER"),
        "assigned_roles": roles,
    }


def _time_authority(value: Any, expected_id: str) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "authority_id",
                "identity",
                "tsa_endpoint",
                "transport_security_mode",
                "endpoint_pin_sha256",
                "certificate_root_sha256",
                "revocation_policy_root_sha256",
            }
        ),
        f"time authority {expected_id}",
        code=code,
    )
    if item["schema"] != TIME_AUTHORITY_SCHEMA or item["authority_id"] != expected_id:
        raise fail(code, f"time authority {expected_id} schema or id mismatch")
    if item["transport_security_mode"] != "SIGNED_RFC3161_RESPONSE":
        raise fail(code, "TSA transport must rely on verified signed RFC3161 responses")
    return {
        "authority_id": expected_id,
        "identity": _identity(item["identity"], expected_party_id=expected_id, expected_role="TIME_AUTHORITY"),
        "tsa_endpoint": _rfc3161_endpoint(item["tsa_endpoint"], "TSA endpoint", code=code),
        "transport_security_mode": item["transport_security_mode"],
        "endpoint_pin_sha256": sha256(item["endpoint_pin_sha256"], "TSA endpoint pin", code=code),
        "certificate_root_sha256": sha256(item["certificate_root_sha256"], "TSA certificate root", code=code),
        "revocation_policy_root_sha256": sha256(
            item["revocation_policy_root_sha256"],
            "TSA revocation policy root",
            code=code,
        ),
    }


_ETHEREUM_FIELDS = frozenset(
    {
        "schema",
        "chain_id",
        "contract_address",
        "deployment_transaction_hash",
        "deployed_bytecode_sha256",
        "source_tree_sha256",
        "compiler_settings_sha256",
        "constructor_arguments_sha256",
        "storage_layout_sha256",
        "abi_sha256",
        "state_machine_spec_sha256",
        "ownerless",
        "non_upgradeable",
        "proxy",
        "delegatecall",
        "arbitrary_external_call",
        "overwrite_or_delete",
        "emergency_reset",
        "challenge_ids_content_derived",
        "open_rejects_existing",
        "close_requires_open",
        "second_close_rejects",
        "zero_result_root_rejected",
        "minimum_rpc_observations",
        "local_receipt_proof_required",
        "finality_required",
    }
)


def _ethereum_policy(value: Any) -> dict[str, Any]:
    code = "ETHEREUM_CONTRACT_POLICY_INVALID"
    item = exact(value, _ETHEREUM_FIELDS, "Ethereum policy", code=code)
    if item["schema"] != ETHEREUM_POLICY_SCHEMA or item["chain_id"] != "1":
        raise fail(code, "Ethereum policy must target chain_id 1")
    if type(item["contract_address"]) is not str or ETH_ADDRESS_RE.fullmatch(item["contract_address"]) is None:
        raise fail(code, "contract_address must be lowercase Ethereum hex")
    if type(item["deployment_transaction_hash"]) is not str or ETH_TX_RE.fullmatch(item["deployment_transaction_hash"]) is None:
        raise fail(code, "deployment_transaction_hash must be lowercase Ethereum hex")
    for field in (
        "deployed_bytecode_sha256",
        "source_tree_sha256",
        "compiler_settings_sha256",
        "constructor_arguments_sha256",
        "storage_layout_sha256",
        "abi_sha256",
        "state_machine_spec_sha256",
    ):
        sha256(item[field], field, code=code)
    required_true = (
        "ownerless",
        "non_upgradeable",
        "challenge_ids_content_derived",
        "open_rejects_existing",
        "close_requires_open",
        "second_close_rejects",
        "zero_result_root_rejected",
        "local_receipt_proof_required",
        "finality_required",
    )
    required_false = (
        "proxy",
        "delegatecall",
        "arbitrary_external_call",
        "overwrite_or_delete",
        "emergency_reset",
    )
    if any(item[field] is not True for field in required_true) or any(
        item[field] is not False for field in required_false
    ):
        raise fail(code, "Ethereum contract safety properties are not exact")
    if item["minimum_rpc_observations"] != "2":
        raise fail(code, "Ethereum policy requires exactly two independent RPC observations")
    return dict(item)


def _drand_policy(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    fields = frozenset(
        {
            "schema",
            "network_chain_hash",
            "network_public_key_hex",
            "minimum_independent_relays",
            "future_round_commitment_required",
            "signature_verification_required",
            "exact_round_match_required",
            "silent_fallback_forbidden",
        }
    )
    item = exact(value, fields, "drand policy", code=code)
    if item["schema"] != DRAND_POLICY_SCHEMA:
        raise fail(code, "drand policy schema mismatch")
    sha256(item["network_chain_hash"], "drand network chain hash", code=code)
    if (
        type(item["network_public_key_hex"]) is not str
        or not item["network_public_key_hex"]
        or HEX_RE.fullmatch(item["network_public_key_hex"]) is None
        or len(item["network_public_key_hex"]) not in {96, 192}
    ):
        raise fail(code, "drand network public key must be lowercase even-length hex")
    if item["minimum_independent_relays"] != "2" or any(
        item[field] is not True
        for field in (
            "future_round_commitment_required",
            "signature_verification_required",
            "exact_round_match_required",
            "silent_fallback_forbidden",
        )
    ):
        raise fail(code, "drand policy requirements are not exact")
    return dict(item)


def _public_roots(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(value, frozenset({"schema", "ethereum", "drand"}), "public roots", code=code)
    if item["schema"] != PUBLIC_ROOTS_SCHEMA:
        raise fail(code, "public roots schema mismatch")
    return {"ethereum": _ethereum_policy(item["ethereum"]), "drand": _drand_policy(item["drand"])}


def _source_policy(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "eligible_modes",
                "auditor_branch_ids",
                "withheld_eligible",
                "private_dual_auditor_escrow_required",
            }
        ),
        "source disclosure policy",
        code=code,
    )
    modes = canonical_string_list(item["eligible_modes"], "eligible source modes", code=code, expected_count=2)
    auditors = canonical_string_list(item["auditor_branch_ids"], "source auditors", code=code, expected_count=2)
    if (
        item["schema"] != SOURCE_POLICY_SCHEMA
        or modes != ELIGIBLE_SOURCE_MODES
        or auditors != ("A", "B")
        or item["withheld_eligible"] is not False
        or item["private_dual_auditor_escrow_required"] is not True
    ):
        raise fail(code, "source disclosure policy does not match the v6.3 ruling")
    return dict(item)


def _population_requirements(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "slot_count",
                "source_family_count",
                "lineage_time_block_count",
                "development_principal_control_group_count",
                "shared_strategic_scaffold_forbidden",
            }
        ),
        "population requirements",
        code=code,
    )
    if item["schema"] != POPULATION_REQUIREMENTS_SCHEMA:
        raise fail(code, "population requirements schema mismatch")
    if any(item[field] != "16" for field in (
        "slot_count",
        "source_family_count",
        "lineage_time_block_count",
        "development_principal_control_group_count",
    )) or item["shared_strategic_scaffold_forbidden"] is not True:
        raise fail(code, "population requirements must preserve 16 independent components")
    return dict(item)


def _quorums(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "audit_branches",
                "time_authorities",
                "custody_reviewers",
                "ethereum_rpc_providers",
                "drand_relays",
            }
        ),
        "quorums",
        code=code,
    )
    expected = {
        "schema": QUORUMS_SCHEMA,
        "audit_branches": "2/2",
        "time_authorities": "2/2",
        "custody_reviewers": "1",
        "ethereum_rpc_providers": "2",
        "drand_relays": "2",
    }
    if dict(item) != expected:
        raise fail(code, "v6.3 quorums must match the binding profile exactly")
    return dict(item)


def _hosted_transport_policy(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "competition_ref",
                "account_team_identifier",
                "allowed_kaggle_hosts",
                "peer_policy_pin_sha256",
                "hostname_verification_required",
                "certificate_chain_capture_required",
                "spki_capture_required",
            }
        ),
        "hosted transport policy",
        code=code,
    )
    hosts = canonical_string_list(
        item["allowed_kaggle_hosts"],
        "allowed Kaggle hosts",
        code=code,
        expected_count=2,
    )
    account_team_identifier = identifier(
        item["account_team_identifier"],
        "Kaggle account/team identifier",
        code=code,
    )
    if (
        item["schema"] != HOSTED_TRANSPORT_POLICY_SCHEMA
        or item["competition_ref"] != "pokemon-tcg-ai-battle"
        or hosts != ("api.kaggle.com", "www.kaggle.com")
        or any(
            item[field] is not True
            for field in (
                "hostname_verification_required",
                "certificate_chain_capture_required",
                "spki_capture_required",
            )
        )
    ):
        raise fail(code, "hosted transport policy does not match the v6.3 Kaggle boundary")
    return {
        **dict(item),
        "account_team_identifier": account_team_identifier,
        "allowed_kaggle_hosts": hosts,
        "peer_policy_pin_sha256": sha256(
            item["peer_policy_pin_sha256"],
            "Kaggle peer policy pin",
            code=code,
        ),
    }


def _crypto_runtime_policy(value: Any) -> dict[str, Any]:
    code = "HYBRID_PROFILE_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "drand_verifier_script_sha256",
                "drand_verifier_package_sha256",
                "drand_verifier_lock_sha256",
                "drand_client_version",
                "node_executable_sha256",
                "node_version",
                "dependency_tree_sha256",
                "rfc3161_openssl_binary_sha256",
                "rfc3161_openssl_version",
                "ethereum_live_verifier_status",
            }
        ),
        "crypto runtime policy",
        code=code,
    )
    if item["schema"] != CRYPTO_RUNTIME_POLICY_SCHEMA:
        raise fail(code, "crypto runtime policy schema mismatch")
    for field in (
        "drand_verifier_script_sha256",
        "drand_verifier_package_sha256",
        "drand_verifier_lock_sha256",
        "rfc3161_openssl_binary_sha256",
        "node_executable_sha256",
        "dependency_tree_sha256",
    ):
        sha256(item[field], field, code=code)
    for field in ("drand_client_version", "node_version", "rfc3161_openssl_version"):
        identifier(item[field], field, code=code)
    if item["ethereum_live_verifier_status"] != "NOT_IMPLEMENTED":
        raise fail(code, "Ethereum live verifier must remain explicitly NOT_IMPLEMENTED")
    return dict(item)


def validate_hybrid_trust_profile(value: Any, *, expected_sha256: str | None = None) -> ValidatedHybridProfile:
    code = "HYBRID_PROFILE_INVALID"
    fields = frozenset(
        {
            "schema",
            "profile_id",
            "policy_status",
            "project_control_group_ids",
            "audit_branches",
            "custody_reviewer",
            "time_authorities",
            "public_roots",
            "source_disclosure_policy",
            "population_requirements",
            "quorums",
            "hosted_transport_policy",
            "crypto_runtime_policy",
        }
    )
    profile = exact(value, fields, "hybrid trust profile", code=code)
    if (
        profile["schema"] != HYBRID_PROFILE_SCHEMA
        or profile["profile_id"] != PROFILE_ID
        or profile["policy_status"] != POLICY_STATUS
    ):
        raise fail(code, "hybrid profile schema, id, or unpinned status mismatch")
    if expected_sha256 is not None:
        expected = sha256(expected_sha256, "expected profile hash", code=code)
        if canonical_sha256(profile) != expected:
            raise fail(code, "hybrid profile hash mismatch")
    project_groups = canonical_string_list(
        profile["project_control_group_ids"],
        "project control groups",
        code=code,
    )
    if type(profile["audit_branches"]) is not list or len(profile["audit_branches"]) != 2:
        raise fail(code, "exactly two audit branches are required")
    branches = [_audit_branch(profile["audit_branches"][index], branch_id) for index, branch_id in enumerate(("A", "B"))]
    reviewer = _custody_reviewer(profile["custody_reviewer"])
    if type(profile["time_authorities"]) is not list or len(profile["time_authorities"]) != 2:
        raise fail(code, "exactly two time authorities are required")
    times = [_time_authority(profile["time_authorities"][index], authority_id) for index, authority_id in enumerate(("D", "E"))]
    parties = [branch["identity"] for branch in branches] + [reviewer["identity"]] + [item["identity"] for item in times]
    uniqueness_fields = (
        "party_id",
        "legal_organization_id",
        "identity_subject_id",
        "control_group_id",
        "provider_account_id",
        "provider_organization_id",
        "role_key_id",
        "role_key_custodian",
        "recovery_control_group",
    )
    for field in uniqueness_fields:
        if len({party[field] for party in parties}) != 5:
            if parties[0][field] == parties[1][field]:
                failure = "AUDIT_BRANCH_INDEPENDENCE_INVALID"
            elif parties[3][field] == parties[4][field]:
                failure = "TIME_AUTHORITY_INDEPENDENCE_INVALID"
            else:
                failure = "CUSTODY_SEPARATION_INVALID"
            raise fail(failure, f"all five named parties must have distinct {field}")
    project_aliases = set(project_groups)
    for party in parties:
        candidate_values = {
            party["legal_organization_id"],
            party["identity_subject_id"],
            party["control_group_id"],
            party["provider_account_id"],
            party["provider_organization_id"],
            party["role_key_custodian"],
            party["recovery_control_group"],
            *party["account_owner_ids"],
            *party["parent_control_group_ids"],
        }
        if project_aliases.intersection(candidate_values):
            raise fail("PROJECT_CONTROL_ALIAS", "a named external party aliases project control")
    a, b = parties[0], parties[1]
    a_control = {a["control_group_id"], a["recovery_control_group"], *a["parent_control_group_ids"]}
    b_control = {b["control_group_id"], b["recovery_control_group"], *b["parent_control_group_ids"]}
    if a_control.intersection(b_control) or set(a["account_owner_ids"]).intersection(b["account_owner_ids"]):
        raise fail("AUDIT_BRANCH_INDEPENDENCE_INVALID", "audit branches A and B share parent, recovery, or owner control")
    for left_index, left in enumerate(parties):
        left_control = {
            left["legal_organization_id"],
            left["control_group_id"],
            left["recovery_control_group"],
            left["role_key_custodian"],
            *left["account_owner_ids"],
            *left["parent_control_group_ids"],
        }
        for right in parties[left_index + 1 :]:
            right_control = {
                right["legal_organization_id"],
                right["control_group_id"],
                right["recovery_control_group"],
                right["role_key_custodian"],
                *right["account_owner_ids"],
                *right["parent_control_group_ids"],
            }
            if left_control.intersection(right_control):
                if {left["party_id"], right["party_id"]} == {"A", "B"}:
                    failure = "AUDIT_BRANCH_INDEPENDENCE_INVALID"
                elif {left["party_id"], right["party_id"]} == {"D", "E"}:
                    failure = "TIME_AUTHORITY_INDEPENDENCE_INVALID"
                else:
                    failure = "CUSTODY_SEPARATION_INVALID"
                raise fail(failure, f"parties {left['party_id']} and {right['party_id']} share control-plane identifiers")
    parsed = {
        "raw": dict(profile),
        "sha256": canonical_sha256(profile),
        "project_control_group_ids": project_groups,
        "audit_branches": tuple(branches),
        "custody_reviewer": reviewer,
        "time_authorities": tuple(times),
        "public_roots": _public_roots(profile["public_roots"]),
        "source_disclosure_policy": _source_policy(profile["source_disclosure_policy"]),
        "population_requirements": _population_requirements(profile["population_requirements"]),
        "quorums": _quorums(profile["quorums"]),
        "hosted_transport_policy": _hosted_transport_policy(profile["hosted_transport_policy"]),
        "crypto_runtime_policy": _crypto_runtime_policy(profile["crypto_runtime_policy"]),
        "identities": {party["party_id"]: party for party in parties},
    }
    return ValidatedHybridProfile(_freeze(parsed), _PROFILE_SENTINEL)


def validate_source_disclosure(value: Any, *, profile: ValidatedHybridProfile) -> ValidatedSourceDisclosure:
    profile = _validated_profile(profile)
    code = "SOURCE_ESCROW_INCOMPLETE"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "profile_sha256",
                "campaign_root_sha256",
                "slot_id",
                "archive_sha256",
                "archive_byte_length",
                "package_sha256",
                "mode",
                "source_tree_sha256",
                "source_family_id",
                "lineage_time_block_id",
                "development_principal_control_group_id",
                "live_challenge_sha256",
                "public_source_root_sha256",
                "auditor_escrow_receipts",
                "signatures",
            }
        ),
        "source disclosure",
        code=code,
    )
    if (
        type(item["mode"]) is not str
        or item["schema"] != SOURCE_DISCLOSURE_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["mode"] not in ELIGIBLE_SOURCE_MODES
    ):
        raise fail(code, "source disclosure schema or mode is ineligible")
    slot_id = identifier(item["slot_id"], "slot id", code=code)
    if slot_id not in SLOTS:
        raise fail(code, "source disclosure slot is outside the frozen 16-slot population")
    campaign_root = sha256(item["campaign_root_sha256"], "campaign root", code=code)
    archive = sha256(item["archive_sha256"], "archive hash", code=code)
    archive_length = canonical_integer(item["archive_byte_length"], "archive byte length", code=code, minimum=1)
    sha256(item["package_sha256"], "package hash", code=code)
    source_root = sha256(item["source_tree_sha256"], "source tree", code=code)
    source_family = identifier(item["source_family_id"], "source family id", code=code)
    lineage = identifier(item["lineage_time_block_id"], "lineage-time block id", code=code)
    development_control = identifier(
        item["development_principal_control_group_id"],
        "development-principal control group id",
        code=code,
    )
    if development_control in profile["project_control_group_ids"]:
        raise fail("PROJECT_CONTROL_ALIAS", "development-principal control group aliases project control")
    live_challenge = sha256(item["live_challenge_sha256"], "live challenge", code=code)
    receipts = item["auditor_escrow_receipts"]
    public_root = item["public_source_root_sha256"]
    if item["mode"] == "PUBLIC":
        public_root = sha256(public_root, "public source root", code=code)
        if public_root != source_root:
            raise fail(code, "public source root must equal the declared source tree root")
        if receipts != {}:
            raise fail(code, "public source mode must not claim private escrow receipts")
    else:
        if public_root is not None:
            raise fail(code, "private escrow mode must not claim a public source root")
        if type(receipts) is not dict or set(receipts) != {"A", "B"}:
            raise fail(code, "private source escrow requires receipts from A and B")
        receipts = {branch: sha256(receipts[branch], f"escrow receipt {branch}", code=code) for branch in ("A", "B")}
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_SOURCE_DISCLOSURE,
        identities=profile["identities"],
        required_party_ids=("A", "B", "C"),
        code=code,
    )
    return ValidatedSourceDisclosure(
        receipt_sha256=canonical_sha256(item),
        profile_sha256=profile["sha256"],
        campaign_root_sha256=campaign_root,
        slot_id=slot_id,
        archive_sha256=archive,
        archive_byte_length=archive_length,
        source_tree_sha256=source_root,
        source_family_id=source_family,
        lineage_time_block_id=lineage,
        development_principal_control_group_id=development_control,
        live_challenge_sha256=live_challenge,
        mode=item["mode"],
        _construction_token=_SOURCE_SENTINEL,
    )


def validate_population_source_disclosures(
    disclosures: Any,
) -> dict[str, Any]:
    code = "SOURCE_ESCROW_INCOMPLETE"
    if type(disclosures) is not list or len(disclosures) != len(SLOTS):
        raise fail(code, "population requires exactly 16 validated source disclosures")
    if any(type(item) is not ValidatedSourceDisclosure for item in disclosures):
        raise fail(code, "population source inputs must be outputs of validate_source_disclosure")
    if tuple(item.slot_id for item in disclosures) != SLOTS:
        raise fail(code, "population source disclosures must follow the canonical 16-slot order")
    for field in (
        "archive_sha256",
        "source_family_id",
        "lineage_time_block_id",
        "development_principal_control_group_id",
    ):
        if len({getattr(item, field) for item in disclosures}) != len(SLOTS):
            raise fail(code, f"population source disclosures must have 16 distinct {field} values")
    if len({item.profile_sha256 for item in disclosures}) != 1 or len(
        {item.campaign_root_sha256 for item in disclosures}
    ) != 1:
        raise fail(code, "all population disclosures must bind one profile and campaign")
    return {
        "schema": "eval.v6.3.population-source-disclosure-verdict",
        "slot_count": 16,
        "source_family_count": 16,
        "lineage_time_block_count": 16,
        "development_principal_control_group_count": 16,
        "archive_count": 16,
        "independence_adjudicated_under_policy": True,
        "independence_ground_truth_proven": False,
        "offline_conformance_only": True,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
    }


_TX_FIELDS = frozenset(
    {
        "schema",
        "transaction_hash",
        "block_hash",
        "block_number",
        "finalized",
        "challenge_id",
        "from_state",
        "to_state",
        "bound_value_sha256",
    }
)


def _eth_tx(value: Any, *, label: str, expected_from: str, expected_to: str, challenge_id: str, bound_value: str) -> dict[str, Any]:
    code = "ETHEREUM_TRANSITION_INVALID"
    item = exact(value, _TX_FIELDS, label, code=code)
    if (
        item["schema"] != ETHEREUM_TX_SCHEMA
        or item["from_state"] != expected_from
        or item["to_state"] != expected_to
        or item["challenge_id"] != challenge_id
        or item["bound_value_sha256"] != bound_value
    ):
        raise fail(code, f"{label} does not encode the required transition")
    if type(item["transaction_hash"]) is not str or ETH_TX_RE.fullmatch(item["transaction_hash"]) is None:
        raise fail(code, f"{label} transaction hash is invalid")
    if type(item["block_hash"]) is not str or ETH_TX_RE.fullmatch(item["block_hash"]) is None:
        raise fail(code, f"{label} block hash is invalid")
    block_number = canonical_integer(item["block_number"], f"{label} block number", code=code, minimum=1)
    if item["finalized"] is not True:
        raise fail("ETHEREUM_FINALITY_INVALID", f"{label} is not finalized")
    return {**dict(item), "block_number_int": block_number}


def validate_synthetic_ethereum_transition_fixture(value: Any, *, profile: ValidatedHybridProfile) -> dict[str, Any]:
    profile = _validated_profile(profile)
    code = "ETHEREUM_TRANSITION_INVALID"
    fields = frozenset(
        {
            "schema",
            "profile_sha256",
            "chain_id",
            "contract_address",
            "challenge_id",
            "opening_commitment_sha256",
            "result_root_sha256",
            "open_receipt",
            "close_receipt",
            "rpc_observations",
            "local_receipt_proof_valid",
        }
    )
    item = exact(value, fields, "Ethereum transition bundle", code=code)
    policy = profile["public_roots"]["ethereum"]
    if (
        item["schema"] != ETHEREUM_BUNDLE_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["chain_id"] != policy["chain_id"]
        or item["contract_address"] != policy["contract_address"]
    ):
        raise fail(code, "Ethereum transition bundle is not bound to the profile")
    challenge_id = sha256(item["challenge_id"], "challenge id", code=code)
    opening = sha256(item["opening_commitment_sha256"], "opening commitment", code=code)
    result = sha256(item["result_root_sha256"], "result root", code=code)
    if result == "0" * 64:
        raise fail(code, "result root must not be zero")
    open_tx = _eth_tx(item["open_receipt"], label="open receipt", expected_from="UNSEEN", expected_to="OPEN", challenge_id=challenge_id, bound_value=opening)
    close_tx = _eth_tx(item["close_receipt"], label="close receipt", expected_from="OPEN", expected_to="CLOSED", challenge_id=challenge_id, bound_value=result)
    if open_tx["transaction_hash"] == close_tx["transaction_hash"] or close_tx["block_number_int"] < open_tx["block_number_int"]:
        raise fail(code, "Ethereum transitions are duplicated or out of order")
    if item["local_receipt_proof_valid"] is not True:
        raise fail("ETHEREUM_FINALITY_INVALID", "local receipt/proof path is not verified")
    observations = item["rpc_observations"]
    if type(observations) is not list or len(observations) != 2:
        raise fail("ETHEREUM_PROVIDER_DISAGREEMENT", "exactly two RPC observations are required")
    parsed_observations = []
    expected = {
        "chain_id": item["chain_id"],
        "contract_address": item["contract_address"],
        "challenge_id": challenge_id,
        "state": "CLOSED",
        "opening_commitment_sha256": opening,
        "result_root_sha256": result,
        "open_transaction_hash": open_tx["transaction_hash"],
        "close_transaction_hash": close_tx["transaction_hash"],
        "open_block_hash": open_tx["block_hash"],
        "close_block_hash": close_tx["block_hash"],
    }
    rpc_fields = frozenset({"schema", "provider_id", "provider_control_group_id", "observed_at", *expected})
    for index, observation in enumerate(observations):
        parsed = exact(observation, rpc_fields, f"RPC observation {index}", code="ETHEREUM_PROVIDER_DISAGREEMENT")
        if parsed["schema"] != ETHEREUM_RPC_SCHEMA or any(parsed[field] != expected[field] for field in expected):
            raise fail("ETHEREUM_PROVIDER_DISAGREEMENT", "RPC observations disagree with the finalized bundle")
        parsed_observations.append(
            {
                **dict(parsed),
                "provider_id": identifier(parsed["provider_id"], "RPC provider id", code=code),
                "provider_control_group_id": identifier(parsed["provider_control_group_id"], "RPC provider control group", code=code),
                "observed_at_dt": utc(parsed["observed_at"], "RPC observed_at", code=code),
            }
        )
    if [row["provider_id"] for row in parsed_observations] != sorted(row["provider_id"] for row in parsed_observations):
        raise fail("ETHEREUM_PROVIDER_DISAGREEMENT", "RPC observations must be sorted by provider_id")
    for field in ("provider_id", "provider_control_group_id"):
        if len({row[field] for row in parsed_observations}) != 2:
            raise fail("ETHEREUM_PROVIDER_DISAGREEMENT", f"RPC observations must have distinct {field}")
    if set(profile["project_control_group_ids"]).intersection(row["provider_control_group_id"] for row in parsed_observations):
        raise fail("PROJECT_CONTROL_ALIAS", "Ethereum RPC provider is project-controlled")
    return {
        "challenge_id": challenge_id,
        "opening_commitment_sha256": opening,
        "result_root_sha256": result,
        "open_transaction_hash": open_tx["transaction_hash"],
        "close_transaction_hash": close_tx["transaction_hash"],
        "rpc_provider_ids": tuple(row["provider_id"] for row in parsed_observations),
        "offline_conformance_only": True,
    }


def validate_synthetic_drand_receipt_fixture(value: Any, *, profile: ValidatedHybridProfile) -> dict[str, Any]:
    profile = _validated_profile(profile)
    code = "DRAND_RECEIPT_INVALID"
    fields = frozenset(
        {
            "schema",
            "profile_sha256",
            "network_chain_hash",
            "committed_round",
            "returned_round",
            "commitment_observed_at",
            "round_timestamp",
            "randomness_sha256",
            "signature_sha256",
            "previous_signature_sha256",
            "signature_verified",
            "relay_observations",
        }
    )
    item = exact(value, fields, "drand receipt", code=code)
    policy = profile["public_roots"]["drand"]
    if (
        item["schema"] != DRAND_RECEIPT_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["network_chain_hash"] != policy["network_chain_hash"]
    ):
        raise fail(code, "drand receipt is not bound to the profile")
    committed_round = canonical_integer(item["committed_round"], "committed round", code=code, minimum=1)
    returned_round = canonical_integer(item["returned_round"], "returned round", code=code, minimum=1)
    if returned_round != committed_round:
        raise fail(code, "drand returned round differs from the committed round")
    committed_at = utc(item["commitment_observed_at"], "commitment_observed_at", code=code)
    round_time = utc(item["round_timestamp"], "round_timestamp", code=code)
    if committed_at >= round_time or item["signature_verified"] is not True:
        raise fail(code, "drand round was not future-committed or signature verification failed")
    randomness = sha256(item["randomness_sha256"], "drand randomness", code=code)
    signature = sha256(item["signature_sha256"], "drand signature", code=code)
    if item["previous_signature_sha256"] is not None:
        sha256(item["previous_signature_sha256"], "previous drand signature", code=code)
    relay_fields = frozenset(
        {
            "schema",
            "relay_id",
            "relay_control_group_id",
            "network_chain_hash",
            "round",
            "randomness_sha256",
            "signature_sha256",
            "observed_at",
        }
    )
    relays = item["relay_observations"]
    if type(relays) is not list or len(relays) != 2:
        raise fail("DRAND_RELAY_DISAGREEMENT", "exactly two drand relay observations are required")
    parsed_relays = []
    for index, relay in enumerate(relays):
        parsed = exact(relay, relay_fields, f"drand relay {index}", code="DRAND_RELAY_DISAGREEMENT")
        if (
            parsed["schema"] != DRAND_RELAY_SCHEMA
            or parsed["network_chain_hash"] != policy["network_chain_hash"]
            or parsed["round"] != item["returned_round"]
            or parsed["randomness_sha256"] != randomness
            or parsed["signature_sha256"] != signature
        ):
            raise fail("DRAND_RELAY_DISAGREEMENT", "drand relays disagree on signed output")
        parsed_relays.append(
            {
                "relay_id": identifier(parsed["relay_id"], "relay id", code=code),
                "relay_control_group_id": identifier(parsed["relay_control_group_id"], "relay control group", code=code),
                "observed_at": utc(parsed["observed_at"], "relay observed_at", code=code),
            }
        )
    if [row["relay_id"] for row in parsed_relays] != sorted(row["relay_id"] for row in parsed_relays):
        raise fail("DRAND_RELAY_DISAGREEMENT", "drand relays must be sorted by relay_id")
    for field in ("relay_id", "relay_control_group_id"):
        if len({row[field] for row in parsed_relays}) != 2:
            raise fail("DRAND_RELAY_DISAGREEMENT", f"drand relays must have distinct {field}")
    if set(profile["project_control_group_ids"]).intersection(row["relay_control_group_id"] for row in parsed_relays):
        raise fail("PROJECT_CONTROL_ALIAS", "drand relay is project-controlled")
    return {
        "round": returned_round,
        "randomness_sha256": randomness,
        "signature_sha256": signature,
        "relay_ids": tuple(row["relay_id"] for row in parsed_relays),
        "offline_conformance_only": True,
    }


def validate_synthetic_time_quorum_fixture(receipts: Any, *, profile: ValidatedHybridProfile) -> dict[str, Any]:
    profile = _validated_profile(profile)
    code = "TIME_QUORUM_INVALID"
    if type(receipts) is not list or len(receipts) != 2:
        raise fail(code, "exactly two RFC3161 receipts are required")
    fields = frozenset(
        {
            "schema",
            "profile_sha256",
            "authority_id",
            "payload_sha256",
            "campaign_nonce_sha256",
            "review_challenge_sha256",
            "tsa_policy_oid",
            "serial_number",
            "gen_time",
            "nonce",
            "signer_certificate_chain_sha256",
            "token_sha256",
            "signature_verified",
            "certificate_valid_at_gen_time",
            "revocation_checked_under_frozen_policy",
        }
    )
    parsed = []
    expected_ids = ("D", "E")
    for index, authority_id in enumerate(expected_ids):
        item = exact(receipts[index], fields, f"time receipt {authority_id}", code=code)
        if (
            item["schema"] != TIME_RECEIPT_SCHEMA
            or item["profile_sha256"] != profile["sha256"]
            or item["authority_id"] != authority_id
        ):
            raise fail(code, f"time receipt {authority_id} is not bound to the profile")
        for field in ("payload_sha256", "campaign_nonce_sha256", "review_challenge_sha256", "signer_certificate_chain_sha256", "token_sha256"):
            sha256(item[field], field, code=code)
        for field in ("tsa_policy_oid", "serial_number", "nonce"):
            identifier(item[field], field, code=code)
        if any(item[field] is not True for field in (
            "signature_verified",
            "certificate_valid_at_gen_time",
            "revocation_checked_under_frozen_policy",
        )):
            raise fail(code, f"time receipt {authority_id} did not pass cryptographic policy checks")
        parsed.append({**dict(item), "gen_time_dt": utc(item["gen_time"], "TSA gen_time", code=code)})
    for field in ("payload_sha256", "campaign_nonce_sha256", "review_challenge_sha256", "nonce"):
        if parsed[0][field] != parsed[1][field]:
            raise fail(code, f"time receipts disagree on {field}")
    if abs(parsed[1]["gen_time_dt"] - parsed[0]["gen_time_dt"]) > timedelta(seconds=120):
        raise fail(code, "time receipts differ by more than 120 seconds")
    time_orgs = [item["identity"]["legal_organization_id"] for item in profile["time_authorities"]]
    if len(set(time_orgs)) != 2:
        raise fail("TIME_AUTHORITY_INDEPENDENCE_INVALID", "time authorities share an organization")
    return {
        "payload_sha256": parsed[0]["payload_sha256"],
        "review_challenge_sha256": parsed[0]["review_challenge_sha256"],
        "authority_ids": expected_ids,
        "token_sha256s": tuple(item["token_sha256"] for item in parsed),
        "offline_conformance_only": True,
    }


def verify_live_ethereum_transition(*, raw_evidence: bytes, profile: ValidatedHybridProfile) -> None:
    _validated_profile(profile)
    if type(raw_evidence) is not bytes:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_NOT_IMPLEMENTED", "raw Ethereum evidence must be bytes")
    raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_NOT_IMPLEMENTED", "Ethereum receipt/storage/finality verification is not implemented")


def assess_hybrid_trust_profile(value: Any, *, expected_sha256: str | None = None) -> dict[str, Any]:
    try:
        parsed = validate_hybrid_trust_profile(value, expected_sha256=expected_sha256)
    except V63Error as exc:
        return zero_authority(
            exc.code,
            detail=str(exc),
            extra={"hybrid_profile_structurally_valid": False},
        )
    except (KeyError, TypeError, IndexError) as exc:
        return zero_authority(
            "HYBRID_PROFILE_INVALID",
            detail=f"malformed hybrid profile: {exc}",
            extra={"hybrid_profile_structurally_valid": False},
        )
    return zero_authority(
        "V6_3_HYBRID_PROFILE_STRUCTURALLY_VALID_REQUIRES_EXTERNAL_PROVISIONING_AND_POLICY_PIN",
        detail="Candidate v6.3 profile passes offline structure only; no live service, challenge, population, or hosted evidence was acquired.",
        extra={
            "hybrid_profile_structurally_valid": True,
            "hybrid_profile_sha256": parsed["sha256"],
            "named_organization_count": 5,
            "audit_branch_count": 2,
            "trusted_time_organization_count": 2,
            "public_network_domains": ["DRAND", "ETHEREUM_MAINNET"],
            "offline_conformance_only": True,
        },
    )


def current_hybrid_status() -> dict[str, Any]:
    return zero_authority(
        "V6_3_HYBRID_PROFILE_IMPLEMENTED_EXTERNAL_EVIDENCE_ABSENT",
        detail="The v6.3 schemas and offline validators exist, but no candidate policy is pinned and no external trust evidence is present.",
        extra={
            "hybrid_profile_structurally_valid": False,
            "offline_conformance_only": True,
        },
    )


__all__ = [
    "AUDIT_BRANCH_SCHEMA",
    "AUDIT_ROLES",
    "CUSTODY_REVIEWER_SCHEMA",
    "CRYPTO_RUNTIME_POLICY_SCHEMA",
    "DRAND_POLICY_SCHEMA",
    "DRAND_RECEIPT_SCHEMA",
    "DRAND_RELAY_SCHEMA",
    "ELIGIBLE_SOURCE_MODES",
    "ETHEREUM_BUNDLE_SCHEMA",
    "ETHEREUM_POLICY_SCHEMA",
    "ETHEREUM_RPC_SCHEMA",
    "ETHEREUM_TX_SCHEMA",
    "HYBRID_PROFILE_SCHEMA",
    "HOSTED_TRANSPORT_POLICY_SCHEMA",
    "PARTY_IDENTITY_SCHEMA",
    "POLICY_STATUS",
    "PROFILE_ID",
    "PUBLIC_ROOTS_SCHEMA",
    "QUORUMS_SCHEMA",
    "SOURCE_DISCLOSURE_SCHEMA",
    "SOURCE_POLICY_SCHEMA",
    "TIME_AUTHORITY_SCHEMA",
    "TIME_RECEIPT_SCHEMA",
    "assess_hybrid_trust_profile",
    "current_hybrid_status",
    "ValidatedHybridProfile",
    "ValidatedSourceDisclosure",
    "validate_hybrid_trust_profile",
    "validate_source_disclosure",
    "validate_population_source_disclosures",
    "validate_synthetic_drand_receipt_fixture",
    "validate_synthetic_ethereum_transition_fixture",
    "validate_synthetic_time_quorum_fixture",
    "verify_live_ethereum_transition",
]
