"""Candidate policy validator for the simplified v6.3.1 trust plane.

The production pin is intentionally literal ``None``. Structural validation is
useful for review, but cannot open intake, campaign, holdout, or upload paths.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from evaluation_v6_2.integration_v622 import canonical_json_loads

from .common import (
    V63Error,
    canonical_base64,
    canonical_integer,
    canonical_json_bytes,
    canonical_sha256,
    canonical_string_list,
    exact,
    fail,
    freeze,
    identifier,
    key_id_for_public_key,
    sha256,
    zero_authority,
)


POLICY_SCHEMA = "eval.v6.3.1.policy-candidate"
IDENTITY_SCHEMA = "eval.v6.3.1.external-identity"
DRAND_POLICY_SCHEMA = "eval.v6.3.1.drand-policy"
KAGGLE_POLICY_SCHEMA = "eval.v6.3.1.kaggle-policy"
ARTIFACT_ROOTS_SCHEMA = "eval.v6.3.1.artifact-roots"
BUDGET_SCHEMA = "eval.v6.3.1.budgets"
CRYPTO_RUNTIME_POLICY_SCHEMA = "eval.v6.3.1.crypto-runtime-policy"

PINNED_V631_POLICY: None = None

_POLICY_SENTINEL = object()
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
        "runtime_admin_control_group_id",
        "account_owner_ids",
        "role_key_id",
        "role_public_key_base64",
        "role_key_custodian_id",
        "endpoint",
        "tsa_policy_oid",
        "trust_root_sha256",
        "tsa_signer_spki_sha256",
        "revocation_policy_root_sha256",
        "revocation_issuer_spki_sha256",
        "identity_evidence_root_sha256",
        "project_controlled",
        "contributes_campaign_agents",
        "outcome_contingent_compensation",
    }
)


@dataclass(frozen=True)
class ValidatedV631Policy(Mapping[str, Any]):
    _data: Mapping[str, Any]
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _POLICY_SENTINEL:
            raise ValueError("ValidatedV631Policy can only be created by validate_candidate_policy")

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


def require_validated_policy(value: Any) -> ValidatedV631Policy:
    code = "V631_POLICY_INVALID"
    if type(value) is not ValidatedV631Policy or value._construction_token is not _POLICY_SENTINEL:
        raise fail(code, "downstream evidence requires a verifier-created v6.3.1 policy")
    try:
        raw_bytes = canonical_json_bytes(value._data["raw"])
        raw = canonical_json_loads(raw_bytes)
        reparsed = validate_candidate_policy(raw)
    except Exception as exc:
        raise fail(code, "validated policy failed canonical consumer-side revalidation") from exc
    if not _deep_equal(value._data, reparsed._data):
        raise fail(code, "validated policy state differs from its canonical raw policy")
    return reparsed


def _deep_equal(left: Any, right: Any) -> bool:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(_deep_equal(left[key], right[key]) for key in left)
    if type(left) is tuple and type(right) is tuple:
        return len(left) == len(right) and all(_deep_equal(a, b) for a, b in zip(left, right, strict=True))
    return type(left) is type(right) and left == right


def _endpoint(value: Any, *, label: str, code: str) -> str:
    endpoint = identifier(value, label, code=code)
    parsed = urlparse(endpoint)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise fail(code, f"{label} must be a canonical HTTP(S) endpoint")
    return endpoint


def _identity(value: Any, *, expected_party: str, expected_role: str) -> dict[str, Any]:
    code = "V631_EXTERNAL_ROSTER_INVALID"
    item = exact(value, _IDENTITY_FIELDS, f"identity {expected_party}", code=code)
    if (
        item["schema"] != IDENTITY_SCHEMA
        or item["party_id"] != expected_party
        or item["role"] != expected_role
    ):
        raise fail(code, f"identity {expected_party} has the wrong schema, party, or role")
    parsed = {
        key: identifier(item[key], f"{expected_party}.{key}", code=code)
        for key in (
            "legal_organization_id",
            "identity_subject_id",
            "control_group_id",
            "provider_name",
            "provider_account_id",
            "provider_organization_id",
            "runtime_admin_control_group_id",
            "role_key_id",
            "role_key_custodian_id",
        )
    }
    owners = canonical_string_list(
        item["account_owner_ids"],
        f"{expected_party}.account_owner_ids",
        code=code,
    )
    public_key = canonical_base64(
        item["role_public_key_base64"],
        f"{expected_party}.role_public_key_base64",
        code=code,
        expected_length=32,
    )
    if parsed["role_key_id"] != key_id_for_public_key(public_key):
        raise fail(code, f"identity {expected_party} key id does not match its public key")
    if any(
        item[field] is not False
        for field in (
            "project_controlled",
            "contributes_campaign_agents",
            "outcome_contingent_compensation",
        )
    ):
        raise fail(code, f"identity {expected_party} violates independence or compensation policy")
    if expected_role == "RFC3161_TIME_AUTHORITY":
        endpoint = _endpoint(item["endpoint"], label=f"{expected_party}.endpoint", code=code)
        tsa_policy_oid = identifier(item["tsa_policy_oid"], f"{expected_party}.tsa_policy_oid", code=code)
        trust_root = sha256(item["trust_root_sha256"], f"{expected_party}.trust_root", code=code)
        signer_spki = sha256(
            item["tsa_signer_spki_sha256"],
            f"{expected_party}.tsa_signer_spki",
            code=code,
        )
        revocation_root = sha256(
            item["revocation_policy_root_sha256"],
            f"{expected_party}.revocation_policy_root",
            code=code,
        )
        revocation_issuer_spki = sha256(
            item["revocation_issuer_spki_sha256"],
            f"{expected_party}.revocation_issuer_spki",
            code=code,
        )
        identity_root = sha256(
            item["identity_evidence_root_sha256"],
            f"{expected_party}.identity_evidence_root",
            code=code,
        )
    else:
        tsa_fields = (
            "endpoint",
            "tsa_policy_oid",
            "trust_root_sha256",
            "tsa_signer_spki_sha256",
            "revocation_policy_root_sha256",
            "revocation_issuer_spki_sha256",
            "identity_evidence_root_sha256",
        )
        if any(item[field] is not None for field in tsa_fields):
            raise fail(code, f"audit identity {expected_party} must not claim TSA fields")
        endpoint = tsa_policy_oid = trust_root = signer_spki = revocation_root = revocation_issuer_spki = identity_root = None
    return {
        **dict(item),
        **parsed,
        "account_owner_ids": owners,
        "role_public_key_bytes": public_key,
        "endpoint": endpoint,
        "tsa_policy_oid": tsa_policy_oid,
        "trust_root_sha256": trust_root,
        "tsa_signer_spki_sha256": signer_spki,
        "revocation_policy_root_sha256": revocation_root,
        "revocation_issuer_spki_sha256": revocation_issuer_spki,
        "identity_evidence_root_sha256": identity_root,
    }


def _drand(value: Any) -> dict[str, Any]:
    code = "V631_POLICY_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "network",
                "chain_hash",
                "public_key_base64",
                "period_seconds",
                "genesis_time",
                "live_verifier_root_sha256",
                "group_hash",
                "scheme_id",
                "beacon_id",
            }
        ),
        "drand policy",
        code=code,
    )
    if item["schema"] != DRAND_POLICY_SCHEMA or item["network"] != "mainnet":
        raise fail(code, "drand policy must use the pinned mainnet domain")
    return {
        **dict(item),
        "chain_hash": sha256(item["chain_hash"], "drand chain hash", code=code),
        "public_key_bytes": canonical_base64(
            item["public_key_base64"],
            "drand public key",
            code=code,
            expected_length=96,
        ),
        "period_seconds_int": canonical_integer(
            item["period_seconds"],
            "drand period",
            code=code,
            minimum=1,
        ),
        "genesis_time_int": canonical_integer(
            item["genesis_time"],
            "drand genesis time",
            code=code,
            minimum=1,
        ),
        "live_verifier_root_sha256": sha256(
            item["live_verifier_root_sha256"],
            "drand live verifier root",
            code=code,
        ),
        "group_hash": sha256(item["group_hash"], "drand group hash", code=code),
        "scheme_id": identifier(item["scheme_id"], "drand scheme id", code=code),
        "beacon_id": identifier(item["beacon_id"], "drand beacon id", code=code),
    }


def _absolute_executable_path(value: Any, *, label: str, code: str) -> str:
    path = identifier(value, label, code=code)
    parsed = Path(path)
    if not parsed.is_absolute() or str(parsed) != path or ".." in parsed.parts:
        raise fail(code, f"{label} must be a normalized absolute path")
    return path


def _crypto_runtime(value: Any) -> dict[str, Any]:
    code = "V631_POLICY_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "openssl_executable_path",
                "openssl_executable_sha256",
                "node_executable_path",
                "node_executable_sha256",
                "rfc3161_imprint_oid",
            }
        ),
        "crypto runtime policy",
        code=code,
    )
    if item["schema"] != CRYPTO_RUNTIME_POLICY_SCHEMA or item["rfc3161_imprint_oid"] != "2.16.840.1.101.3.4.2.1":
        raise fail(code, "crypto runtime policy must pin the SHA-256 RFC3161 imprint OID")
    return {
        **dict(item),
        "openssl_executable_path": _absolute_executable_path(
            item["openssl_executable_path"], label="OpenSSL executable", code=code
        ),
        "openssl_executable_sha256": sha256(
            item["openssl_executable_sha256"], "OpenSSL executable", code=code
        ),
        "node_executable_path": _absolute_executable_path(
            item["node_executable_path"], label="Node executable", code=code
        ),
        "node_executable_sha256": sha256(
            item["node_executable_sha256"], "Node executable", code=code
        ),
    }


def _kaggle(value: Any) -> dict[str, Any]:
    code = "V631_POLICY_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "competition_ref",
                "account_team_identifier",
                "allowed_hosts",
                "peer_policy_root_sha256",
            }
        ),
        "Kaggle policy",
        code=code,
    )
    hosts = canonical_string_list(item["allowed_hosts"], "Kaggle allowed hosts", code=code, expected_count=2)
    if item["schema"] != KAGGLE_POLICY_SCHEMA or item["competition_ref"] != "pokemon-tcg-ai-battle":
        raise fail(code, "Kaggle policy uses the wrong competition")
    return {
        **dict(item),
        "account_team_identifier": identifier(
            item["account_team_identifier"],
            "Kaggle account/team identifier",
            code=code,
        ),
        "allowed_hosts": hosts,
        "peer_policy_root_sha256": sha256(
            item["peer_policy_root_sha256"],
            "Kaggle peer policy root",
            code=code,
        ),
    }


def _artifact_roots(value: Any) -> dict[str, Any]:
    code = "V631_POLICY_INVALID"
    fields = frozenset(
        {
            "schema",
            "population_spec_sha256",
            "statistics_spec_sha256",
            "hosted_custody_spec_sha256",
            "permit_spec_sha256",
            "code_root_sha256",
            "build_root_sha256",
        }
    )
    item = exact(value, fields, "artifact roots", code=code)
    if item["schema"] != ARTIFACT_ROOTS_SCHEMA:
        raise fail(code, "artifact roots schema mismatch")
    return {
        **dict(item),
        **{field: sha256(item[field], field, code=code) for field in fields if field != "schema"},
    }


def _budgets(value: Any) -> dict[str, Any]:
    code = "V631_POLICY_INVALID"
    item = exact(
        value,
        frozenset({"schema", "calibration_max_uploads", "production_reserved_uploads"}),
        "budgets",
        code=code,
    )
    if (
        item["schema"] != BUDGET_SCHEMA
        or item["calibration_max_uploads"] != "16"
        or item["production_reserved_uploads"] != "1"
    ):
        raise fail(code, "v6.3.1 budgets must be exactly calibration=16 and production=1")
    return dict(item)


def _require_global_separation(parties: list[dict[str, Any]], project_groups: tuple[str, ...]) -> None:
    code = "V631_AUDITOR_INDEPENDENCE_INVALID"
    fields = (
        "legal_organization_id",
        "identity_subject_id",
        "control_group_id",
        "provider_account_id",
        "provider_organization_id",
        "runtime_admin_control_group_id",
        "role_key_id",
        "role_key_custodian_id",
    )
    for field in fields:
        values = [party[field] for party in parties]
        if len(set(values)) != len(values):
            raise fail(code, f"external parties are not globally distinct by {field}")
    project = set(project_groups)
    control_sets: list[tuple[str, set[str]]] = []
    for party in parties:
        controlled = {
            party["legal_organization_id"],
            party["identity_subject_id"],
            party["control_group_id"],
            party["provider_account_id"],
            party["provider_organization_id"],
            party["runtime_admin_control_group_id"],
            party["role_key_id"],
            party["role_key_custodian_id"],
            *party["account_owner_ids"],
        }
        if project.intersection(controlled):
            raise fail("V631_PROJECT_CONTROL_ALIAS", f"party {party['party_id']} aliases project control")
        control_sets.append((party["party_id"], controlled))
    for index, (left_id, left) in enumerate(control_sets):
        for right_id, right in control_sets[index + 1 :]:
            overlap = left.intersection(right)
            if overlap:
                raise fail(
                    code,
                    f"external parties {left_id} and {right_id} share control-plane identifiers",
                )


def validate_candidate_policy(value: Any, *, expected_sha256: str | None = None) -> ValidatedV631Policy:
    code = "V631_POLICY_INVALID"
    item = exact(
        value,
        frozenset(
            {
                "schema",
                "profile_id",
                "policy_status",
                "project_control_group_ids",
                "audit_branches",
                "time_authorities",
                "drand",
                "kaggle",
                "artifact_roots",
                "budgets",
                "crypto_runtime",
            }
        ),
        "v6.3.1 candidate policy",
        code=code,
    )
    if item["schema"] != POLICY_SCHEMA or item["policy_status"] != "CANDIDATE_UNPINNED":
        raise fail(code, "v6.3.1 policy must remain an unpinned candidate")
    profile_id = identifier(item["profile_id"], "profile id", code=code)
    project_groups = canonical_string_list(
        item["project_control_group_ids"],
        "project control groups",
        code=code,
    )
    if type(item["audit_branches"]) is not list or len(item["audit_branches"]) != 2:
        raise fail(code, "exactly Audit A and B are required")
    if type(item["time_authorities"]) is not list or len(item["time_authorities"]) != 2:
        raise fail(code, "exactly time authorities D and E are required")
    audits = [
        _identity(raw, expected_party=party, expected_role="AUDIT_BRANCH")
        for raw, party in zip(item["audit_branches"], ("A", "B"), strict=True)
    ]
    times = [
        _identity(raw, expected_party=party, expected_role="RFC3161_TIME_AUTHORITY")
        for raw, party in zip(item["time_authorities"], ("D", "E"), strict=True)
    ]
    parties = audits + times
    _require_global_separation(parties, project_groups)
    independent_tsa_fields = (
        "endpoint",
        "tsa_policy_oid",
        "trust_root_sha256",
        "tsa_signer_spki_sha256",
        "revocation_policy_root_sha256",
        "revocation_issuer_spki_sha256",
        "identity_evidence_root_sha256",
    )
    if any(times[0][field] == times[1][field] for field in independent_tsa_fields):
        raise fail(
            "V631_TIME_AUTHORITY_INDEPENDENCE_INVALID",
            "time authorities share an endpoint, policy, certificate, revocation, or identity pin",
        )
    digest = canonical_sha256(item)
    if expected_sha256 is not None and digest != sha256(expected_sha256, "expected policy hash", code=code):
        raise fail(code, "candidate policy digest does not match the expected pin")
    parsed = {
        "raw": dict(item),
        "sha256": digest,
        "profile_id": profile_id,
        "project_control_group_ids": project_groups,
        "audit_branches": tuple(audits),
        "time_authorities": tuple(times),
        "identities": {party["party_id"]: party for party in parties},
        "drand": _drand(item["drand"]),
        "kaggle": _kaggle(item["kaggle"]),
        "artifact_roots": _artifact_roots(item["artifact_roots"]),
        "budgets": _budgets(item["budgets"]),
        "crypto_runtime": _crypto_runtime(item["crypto_runtime"]),
    }
    return ValidatedV631Policy(freeze(parsed), _POLICY_SENTINEL)


def assess_candidate_policy(value: Any, *, expected_sha256: str | None = None) -> dict[str, Any]:
    try:
        parsed = validate_candidate_policy(value, expected_sha256=expected_sha256)
    except V63Error as exc:
        report = zero_authority(exc.code, detail=str(exc))
        report["authority"] = "NO_UPLOAD"
        return report
    except (KeyError, TypeError, IndexError) as exc:
        report = zero_authority("V631_POLICY_INVALID", detail=f"malformed candidate policy: {exc}")
        report["authority"] = "NO_UPLOAD"
        return report
    report = zero_authority(
        "V631_POLICY_STRUCTURALLY_VALID_EXTERNAL_ROSTER_AND_PIN_ABSENT",
        detail="The candidate policy is structurally valid but external identities are not authenticated and the literal production pin remains None.",
        extra={"authority": "NO_UPLOAD", "candidate_policy_sha256": parsed["sha256"]},
    )
    report["candidate_policy_structurally_valid"] = True
    return report


def current_status() -> dict[str, Any]:
    if PINNED_V631_POLICY is not None:  # pragma: no cover - release constant is literal None
        raise RuntimeError("the repository must not carry a locally activated v6.3.1 policy")
    return zero_authority(
        "V631_LOCAL_IMPLEMENTATION_INCOMPLETE_EXTERNAL_EVIDENCE_ABSENT",
        detail="PINNED_V631_POLICY is None; campaign inputs are not read and no authority exists.",
        extra={"authority": "NO_UPLOAD"},
    )


__all__ = [
    "ARTIFACT_ROOTS_SCHEMA",
    "BUDGET_SCHEMA",
    "CRYPTO_RUNTIME_POLICY_SCHEMA",
    "DRAND_POLICY_SCHEMA",
    "IDENTITY_SCHEMA",
    "KAGGLE_POLICY_SCHEMA",
    "PINNED_V631_POLICY",
    "POLICY_SCHEMA",
    "ValidatedV631Policy",
    "assess_candidate_policy",
    "current_status",
    "require_validated_policy",
    "validate_candidate_policy",
]
