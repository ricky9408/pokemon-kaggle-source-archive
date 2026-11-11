from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import inspect
from pathlib import Path
import shutil
import subprocess
from types import MappingProxyType
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads
from evaluation_v6_3.common import V63Error, key_id_for_public_key
from evaluation_v6_3_1 import live_crypto, policy


def _b64(value: str) -> bytes:
    return base64.b64decode(value)


PRECOMMIT = _b64("eyJhX3ByZXZpb3VzX2pvdXJuYWxfaGVhZF9zaGEyNTYiOiJkMDdkNmNhZjNkMDIwOTM4OTczNDBhMzQ1YWI0NmUxZDkzYjA0NDk0YzA3NGFjNDllZGExOWM1NjFlYzBhMzc3IiwiYXJjaGl2ZV9zaGEyNTYiOiIwZWIzZTM2YmZiMjRkY2Q5YmIxZDFiZWNlMTUzMTIxNmI1OTUzOWE4ZmRlMTdlZTgwMjI0YWYwNjUzYzkyYWEzIiwiYXNzaWdubWVudF9yb290X3NoYTI1NiI6ImNlN2E3YzEwYjBkZmQ5NjgwOGNjYTY0Yzg4Y2Y1YzVlMTNiNzc3NTI4M2JkYzkyNDc2Nzg4N2JmYTMyYzhmYTEiLCJiX3ByZXZpb3VzX2pvdXJuYWxfaGVhZF9zaGEyNTYiOiJjN2VkYTdmOWMzMDE3Y2I2M2QxNTIxMTNiN2ZkMjI0OTljOWVmMTc0NTQ5YjJlM2VlNWJjZmNlMDc4NjY4YjMxIiwiY2FtcGFpZ25fcm9vdF9zaGEyNTYiOiIzZGMyNjBiMjQ3MjA2MmQ5YzU3YmQ5MzBiMDJmMjM4MzFkOTE3YjhmM2UzMjM0YjZkNjM5NjRhNTNjMzFkM2FhIiwiY29tbWl0dGVkX2RyYW5kX3JvdW5kIjoiMzA0NzE0NTAiLCJwb2xpY3lfc2hhMjU2IjoiMWUyNWQ2ODgyMjIxNjljNTcxMDg0Y2M4YWU3YWYwZTRkYjk4MWY0N2ZjZDMwNmVjZmMxYjg1NjYwZWYwZGEyNyIsInByZXJlZ2lzdHJhdGlvbl9yb290X3NoYTI1NiI6IjNlOGFjNTIzNmJhM2NiNWM1MDE4ZWI1ZGRhNmYxNTZkMDJlZWY3NTNiZjI0MjBiYzczNTkzZDg2MTM2NWQwNWUiLCJzY2hlbWEiOiJldmFsLnY2LjMuMS5saXZlLWNyeXB0by1wcmVjb21taXQiLCJzbG90X2lkIjoiRDAxIn0=")
QUERY = _b64("MEQCAQEwMTANBglghkgBZQMEAgEFAAQgY6NdRCKq7HyCLfcPVyvH058Ba8EMPKuttOn6v6LIQTECCQCCR6J/lizZqQEB/w==")
BEACON = _b64("eyJyYW5kb21uZXNzIjoiNGRkYjFjZWZmMTlkZjk5YjRlNTk3NTkyZjM5Zjg3ZDNiMmUyOWQxNjFiN2EzODAyZDI3ODhkZDk0YjgxZGZmNCIsInJvdW5kIjozMDQ3MTQ1MCwic2lnbmF0dXJlIjoiYTcyYmY4NDkxNWI4ZDhiNjViNDM1ZDhhNzE2ZTYzZGEwMzg2ODVjOWE2MmNkNGQ2NzI4OTBhYTY0ZmY3MDFmYmNmMGVlY2NkMTRkN2U3YmJiN2Q3NDc3MzU0MWRiMzRkIn0=")
D_RESPONSE = _b64("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")
E_RESPONSE = _b64("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")
D_ROOT = _b64("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURLVENDQWhHZ0F3SUJBZ0lVTEU0YVJNL2FCR2lwT1I5NnkxbTQ4VkJRYUNRd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0hERWFNQmdHQTFVRUF3d1JWall6TVNCQmRXUnBkQ0JTYjI5MElHUXdIaGNOTWpZd056RTJNVFl3TVRJMwpXaGNOTXpZd056RXpNVFl3TVRJM1dqQWNNUm93R0FZRFZRUUREQkZXTmpNeElFRjFaR2wwSUZKdmIzUWdaRENDCkFTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSlcxOWI3em5hL1pwOEhoZG4wUGFBY3EKYldsZmowczZrMUYyaTNBUy9qUitMYkFsRGlYRWc2RHhNMmJ5YWpZZkxyRVA2RDB3ejcxelJ0ME4xQ3lXNDBYVwpQWXAwdm9kcVp1VlNIVkJCTkZlcDJWMnVyMFBFQURIRTdvSHR5dnJqcGVuNFFFTjdCRklJRWJ5ZFdOenR5UTFaCm5GTXJGSnU1Rml3MmZQaDg5YUN0emNVdmE2cTJVVm5iSS9oVWpPNDYxamJCNTdRMVIzOFNjYjMxZ3p4YWFXNHQKZkNBYXAra0F6N1RHRVB5eStPaGlkbjlGZFRtRjlINVpTVitMc3hubysrSHZrT09YZFRPdjZ6TCtxazRPMzExQQpXUmhqYnh3VDZSdnF4WGVLOXJBNDNKTGtHOFZVTTJZRGpGazc0bWVlbTFWOU12K1ZaRUNQRnZtd0piZ01oVGtDCkF3RUFBYU5qTUdFd0hRWURWUjBPQkJZRUZLUlNjYmxQOG5JRjJZUDJ1RDVQM0RqMUxiaHdNQjhHQTFVZEl3UVkKTUJhQUZLUlNjYmxQOG5JRjJZUDJ1RDVQM0RqMUxiaHdNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUApBUUgvQkFRREFnRUdNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUFNY2ZJWDhXUDdOT2haZnZmck9BZXFPWUtaCjRud1YxTDhSMUs3Tlh5UG1LblZXYmYrUklic2sxajlPYzdFWkVSbXN6NGh6UldnNnhVMWFyMnZTanVoUDdNL0IKR2lwcXM4ZERkZUVoamptWmJSZGsvc0VFeUxvM2EzK2tNSjhjVU5obDgzazRCeGdLa3pZTVRSaVhndjBBNThLQgo4bkFWR3lsY29maDZuM3RaOE9hRUlZVGVIT2c5cGRYNTlSWHZmT1RaZDcxcWg3YXN3Y01waEdrbjliaDkzS1RkClR1VVYyZnU2Wm93UXI3MmJiS0xzV0MvLy92aXg2SUZzSkFvUUViVGllVGtUWEZ5THhRZkJqem8rMkZ5anlUWWUKYzc2RXFYdWxLbyt0SlNrZnRtUGh0M1hSTHkyUWxQT0NnZXVaZ1dCeG5lYzkrSjJoam5XaVZOd3Z0UDFxCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K")
E_ROOT = _b64("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURLVENDQWhHZ0F3SUJBZ0lVQWRhK05abFhqN0xabHRibWJTL0FXY0Z2VE1Jd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0hERWFNQmdHQTFVRUF3d1JWall6TVNCQmRXUnBkQ0JTYjI5MElHVXdIaGNOTWpZd056RTJNVFl3TVRJMwpXaGNOTXpZd056RXpNVFl3TVRJM1dqQWNNUm93R0FZRFZRUUREQkZXTmpNeElFRjFaR2wwSUZKdmIzUWdaVENDCkFTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTDR2aTFmcXo0OElZWXc0MTJ5cTAvM0QKMXNEZ0VsNTBkZHVoYllSbmJUTXdNY2pXNk1nQmlIZFRtdmZSOElXTHNuOTQvNzBnVFk4MmZ0M1d5akoyaXdUNQo4RWhFcE84YlR1L1hueFcwN3R6ZFhZUytBRUZFeEFiOXZCQjFOQnRLR01UanBKejZYTHE4akQycXp4WFlVNGd2CnMrZTRiaHBXYUY3OWI2V3VxTzRsZUJ3RTlCRnJUeEl1Rm4zVi8wcVk0R0FybU9zNytMQThKMGltVWlYSFBMdlkKcWlIUENaNFdqSlk4b2duVEpHdzJZOFF5T3MvSmlOcUUzTUNHV1VTbWlXUDZrUndnU09WdzJQYm9kc2YxMno5OApManlUZHU4N0w3YUcyVThtRDJFQXpjUTVGa1cxL3ZxY1d6K0w4OUE5YUN3THd4NVV6bEJDQWc2V0czeTMrNThDCkF3RUFBYU5qTUdFd0hRWURWUjBPQkJZRUZBQ1h2engrZHZWU1R4Q3l0RXpnV2E1eGpYeFdNQjhHQTFVZEl3UVkKTUJhQUZBQ1h2engrZHZWU1R4Q3l0RXpnV2E1eGpYeFdNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEZ1lEVlIwUApBUUgvQkFRREFnRUdNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUNHVXRDMWNmRHRmOS9PVEhyckoxOXRPaCs5ClR6T1V2MFdVcHQ3OTV5R2Zaa3piMldrYi9JUmtrRWNkU0U5N3dDeTlHY1crakprQ3pzUmljWTcxdExQaDJ6T2gKU0FKUTNqdWpkMzB1anU2NFFJTlpucGhHaG9qWGtWWVc3TlNqWkNsUUd2NUxrMUJoYlFJbWxNZWMwN20zTGlIaQpBY1EwNFYzQlVTNmE4SFB0VlRCUXR2ZXArOHgxQjJFWTMzYURKNmdxS3RkM1lqZTlPTjhxeWV4OTl2RFQ5dC9YCitrb3pvUEFSbXBpbEV2NWtxVWhGNUJFdHNaRm51a1R0MFJhMEJmMWhteGthZ2l5NHlReERGbm1zUFh2S2xmc3oKMHN3LzAzME92YzhlTkRBOWxBejg1VHdQRUViZkZqdzZRcmpycGFuU3Q0bDFJbHNtVmJ2NVlzY0wrVXBnCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _certificate_sha256(pem: bytes) -> str:
    certificate = x509.load_pem_x509_certificate(pem)
    return hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()


def _root_spki_sha256(pem: bytes) -> str:
    certificate = x509.load_pem_x509_certificate(pem)
    spki = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _role_key(party: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(f"role-{party}".encode("ascii")).digest())


def _identity(party: str, role: str) -> dict[str, Any]:
    public = _role_key(party).public_key().public_bytes_raw()
    is_time = role == "RFC3161_TIME_AUTHORITY"
    root = D_ROOT if party == "D" else E_ROOT
    signer_spki = {
        "D": "cbbdb8da1a7a920f75d806dc33dbe2d62c28230d9dcf28e26dc949f2aadc076b",
        "E": "c9b16a39e4f94bda8642ae0525d09b0c130d0da3e7a8de3c5f6fe8a86e09f321",
    }
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
        "role_key_custodian_id": f"custodian-{party}",
        "endpoint": f"https://tsa-{party.lower()}.example/timestamp" if is_time else None,
        "tsa_policy_oid": f"1.2.3.4.{1 if party == 'D' else 2}" if is_time else None,
        "trust_root_sha256": _certificate_sha256(root) if is_time else None,
        "tsa_signer_spki_sha256": signer_spki[party] if is_time else None,
        "revocation_policy_root_sha256": _digest(f"revocation-{party}") if is_time else None,
        "revocation_issuer_spki_sha256": _root_spki_sha256(root) if is_time else None,
        "identity_evidence_root_sha256": _digest(f"identity-{party}") if is_time else None,
        "project_controlled": False,
        "contributes_campaign_agents": False,
        "outcome_contingent_compensation": False,
    }


def _policy_raw() -> dict[str, Any]:
    openssl = Path(shutil.which("openssl") or "").resolve()
    node = Path(shutil.which("node") or "").resolve()
    return {
        "schema": policy.POLICY_SCHEMA,
        "profile_id": "v631-fixed-live-crypto",
        "policy_status": "CANDIDATE_UNPINNED",
        "project_control_group_ids": ["project-control"],
        "audit_branches": [_identity("A", "AUDIT_BRANCH"), _identity("B", "AUDIT_BRANCH")],
        "time_authorities": [_identity("D", "RFC3161_TIME_AUTHORITY"), _identity("E", "RFC3161_TIME_AUTHORITY")],
        "drand": {
            "schema": policy.DRAND_POLICY_SCHEMA,
            "network": "mainnet",
            "chain_hash": live_crypto.QUICKNET_CHAIN_HASH,
            "public_key_base64": base64.b64encode(bytes.fromhex(live_crypto.QUICKNET_PUBLIC_KEY_HEX)).decode("ascii"),
            "period_seconds": str(live_crypto.QUICKNET_PERIOD_SECONDS),
            "genesis_time": str(live_crypto.QUICKNET_GENESIS_TIME),
            "live_verifier_root_sha256": live_crypto.drand_verifier_root_sha256(),
            "group_hash": live_crypto.QUICKNET_GROUP_HASH,
            "scheme_id": live_crypto.QUICKNET_SCHEME_ID,
            "beacon_id": live_crypto.QUICKNET_BEACON_ID,
        },
        "kaggle": {"schema": policy.KAGGLE_POLICY_SCHEMA, "competition_ref": "pokemon-tcg-ai-battle", "account_team_identifier": "team-garlictoday", "allowed_hosts": ["api.kaggle.com", "www.kaggle.com"], "peer_policy_root_sha256": _digest("peer-policy")},
        "artifact_roots": {"schema": policy.ARTIFACT_ROOTS_SCHEMA, "population_spec_sha256": _digest("population"), "statistics_spec_sha256": _digest("statistics"), "hosted_custody_spec_sha256": _digest("custody"), "permit_spec_sha256": _digest("permit"), "code_root_sha256": _digest("code"), "build_root_sha256": _digest("build")},
        "budgets": {"schema": policy.BUDGET_SCHEMA, "calibration_max_uploads": "16", "production_reserved_uploads": "1"},
        "crypto_runtime": {"schema": policy.CRYPTO_RUNTIME_POLICY_SCHEMA, "openssl_executable_path": str(openssl), "openssl_executable_sha256": _file_sha256(openssl), "node_executable_path": str(node), "node_executable_sha256": _file_sha256(node), "rfc3161_imprint_oid": live_crypto.SHA256_OID},
    }


def _policy(raw: dict[str, Any] | None = None) -> policy.ValidatedV631Policy:
    return policy.validate_candidate_policy(raw or _policy_raw())


def _rfc_kwargs(candidate: policy.ValidatedV631Policy) -> dict[str, Any]:
    return {"raw_precommit": PRECOMMIT, "raw_query": QUERY, "raw_responses": (D_RESPONSE, E_RESPONSE), "root_certificates_pem": (D_ROOT, E_ROOT), "policy": candidate}


def test_real_crypto_mechanics_remain_explicitly_unavailable_and_no_upload() -> None:
    candidate = _policy()
    assert candidate["sha256"] == "1e25d688222169c571084cc8ae7af0e4db981f47fcd306ecfc1b85660ef0da27"
    report = live_crypto.verify_live_rfc3161_quorum(**_rfc_kwargs(candidate))
    assert report["state"] == "REVOCATION_EVIDENCE_MISSING/IDENTITY_UNVERIFIED"
    assert report["authority"] == "NO_UPLOAD"
    assert report["rfc3161_mechanics_verified"] is True
    assert report["revocation_evidence_verified"] is False
    assert report["external_tsa_identity_verified"] is False
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["permits"] == []
    with pytest.raises(TypeError):
        replace(report, state="LIVE")


def test_drand_reverifies_raw_rfc_evidence_and_still_returns_no_upload() -> None:
    candidate = _policy()
    assert "rfc3161_quorum" not in inspect.signature(live_crypto.verify_live_drand_receipt).parameters
    report = live_crypto.verify_live_drand_receipt(raw_beacon=BEACON, **_rfc_kwargs(candidate))
    assert report["state"] == "REVOCATION_EVIDENCE_MISSING/IDENTITY_UNVERIFIED"
    assert report["authority"] == "NO_UPLOAD"
    assert report["verified_stage"] == "RFC3161_AND_DRAND_MECHANICS_ONLY"
    assert report["drand_round"] == "30471450"
    assert report["drand_signature_mechanics_verified"] is True


@pytest.mark.parametrize("mutation", ("response", "nonce", "root", "signer", "policy"))
def test_rfc3161_rejects_mutation_and_identity_substitution(mutation: str) -> None:
    raw = _policy_raw()
    kwargs = _rfc_kwargs(_policy(raw))
    if mutation == "response":
        damaged = bytearray(D_RESPONSE); damaged[-1] ^= 1; kwargs["raw_responses"] = (bytes(damaged), E_RESPONSE)
    elif mutation == "nonce":
        damaged = bytearray(QUERY); damaged[QUERY.index(bytes.fromhex("8247a27f962cd9a9"))] ^= 1; kwargs["raw_query"] = bytes(damaged)
    elif mutation == "root":
        kwargs["root_certificates_pem"] = (E_ROOT, D_ROOT)
    elif mutation == "signer":
        raw["time_authorities"][0]["tsa_signer_spki_sha256"] = _digest("wrong-signer")
        kwargs["policy"] = _policy(raw)
    else:
        raw["profile_id"] = "substituted-policy"
        kwargs["policy"] = _policy(raw)
    with pytest.raises(V63Error):
        live_crypto.verify_live_rfc3161_quorum(**kwargs)


@pytest.mark.parametrize("field", ("campaign_root_sha256", "preregistration_root_sha256", "assignment_root_sha256", "archive_sha256", "slot_id", "a_previous_journal_head_sha256", "b_previous_journal_head_sha256", "committed_drand_round"))
def test_exact_precommit_rejects_campaign_and_binding_substitution(field: str) -> None:
    candidate = _policy()
    changed = canonical_json_loads(PRECOMMIT)
    changed[field] = "C01" if field == "slot_id" else "30471451" if field == "committed_drand_round" else _digest(f"changed-{field}")
    kwargs = _rfc_kwargs(candidate); kwargs["raw_precommit"] = canonical_json_bytes(changed)
    with pytest.raises(V63Error) as caught:
        live_crypto.verify_live_rfc3161_quorum(**kwargs)
    assert caught.value.code == "V631_LIVE_RFC3161_INVALID"


def test_precommit_and_beacon_duplicate_keys_are_rejected() -> None:
    candidate = _policy()
    duplicate_precommit = PRECOMMIT[:-1] + b',"slot_id":"D01"}'
    kwargs = _rfc_kwargs(candidate); kwargs["raw_precommit"] = duplicate_precommit
    with pytest.raises(V63Error):
        live_crypto.verify_live_rfc3161_quorum(**kwargs)
    beacon = canonical_json_loads(BEACON)
    duplicate_beacon = canonical_json_bytes(beacon)[:-1] + b',"round":30471450}'
    with pytest.raises(V63Error):
        live_crypto.verify_live_drand_receipt(raw_beacon=duplicate_beacon, **_rfc_kwargs(candidate))


def test_arbitrary_canonical_precommit_is_rejected() -> None:
    kwargs = _rfc_kwargs(_policy())
    kwargs["raw_precommit"] = b'{"committed_drand_round":"30471450"}'
    with pytest.raises(V63Error):
        live_crypto.verify_live_rfc3161_quorum(**kwargs)


@pytest.mark.parametrize("artifact", ("tree", "openssl", "node"))
def test_runtime_artifact_replacement_fails_closed(monkeypatch: pytest.MonkeyPatch, artifact: str) -> None:
    candidate = _policy()
    if artifact == "tree":
        monkeypatch.setattr(live_crypto, "_tree_sha256", lambda root: "0" * 64)
    else:
        original = live_crypto._file_sha256
        target = candidate["crypto_runtime"][f"{artifact}_executable_path"]
        monkeypatch.setattr(live_crypto, "_file_sha256", lambda path: "0" * 64 if str(path) == target else original(path))
    with pytest.raises(V63Error) as caught:
        live_crypto.verify_live_rfc3161_quorum(**_rfc_kwargs(candidate))
    assert caught.value.code == "V631_CRYPTO_RUNTIME_UNAVAILABLE"


def test_live_consumer_rejects_replaced_policy_state() -> None:
    candidate = _policy()
    altered = dict(candidate._data)
    altered["sha256"] = "0" * 64
    forged = replace(candidate, _data=MappingProxyType(altered))
    with pytest.raises(V63Error) as caught:
        live_crypto.verify_live_rfc3161_quorum(**_rfc_kwargs(forged))
    assert caught.value.code == "V631_POLICY_INVALID"


def test_symlinked_runtime_executable_is_rejected(tmp_path: Path) -> None:
    raw = _policy_raw()
    link = tmp_path / "openssl"
    link.symlink_to(raw["crypto_runtime"]["openssl_executable_path"])
    raw["crypto_runtime"]["openssl_executable_path"] = str(link)
    candidate = _policy(raw)
    with pytest.raises(V63Error) as caught:
        live_crypto.verify_live_rfc3161_quorum(**_rfc_kwargs(candidate))
    assert caught.value.code == "V631_CRYPTO_RUNTIME_UNAVAILABLE"


def test_alternative_imprint_algorithm_is_rejected(tmp_path: Path) -> None:
    candidate = _policy()
    precommit_path = tmp_path / "precommit.json"
    query_path = tmp_path / "sha1.tsq"
    precommit_path.write_bytes(PRECOMMIT)
    completed = subprocess.run(
        [candidate["crypto_runtime"]["openssl_executable_path"], "ts", "-query", "-data", str(precommit_path), "-sha1", "-cert", "-out", str(query_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=live_crypto._sanitized_environment(),
    )
    assert completed.returncode == 0
    kwargs = _rfc_kwargs(candidate); kwargs["raw_query"] = query_path.read_bytes()
    with pytest.raises(V63Error) as caught:
        live_crypto.verify_live_rfc3161_quorum(**kwargs)
    assert caught.value.code == "V631_LIVE_RFC3161_INVALID"


@pytest.mark.parametrize("field,replacement", (("group_hash", "0" * 64), ("scheme_id", "other-scheme"), ("beacon_id", "other-beacon"), ("live_verifier_root_sha256", "0" * 64)))
def test_quicknet_policy_and_verifier_root_substitution_fails_closed(field: str, replacement: str) -> None:
    raw = _policy_raw(); raw["drand"][field] = replacement; candidate = _policy(raw)
    with pytest.raises(V63Error):
        live_crypto.verify_live_drand_receipt(raw_beacon=BEACON, **_rfc_kwargs(candidate))


def test_drand_round_and_signature_mutation_fail_closed() -> None:
    candidate = _policy()
    for field in ("round", "signature"):
        beacon = canonical_json_loads(BEACON)
        beacon[field] = 30471451 if field == "round" else "00" * 48
        with pytest.raises(V63Error):
            live_crypto.verify_live_drand_receipt(raw_beacon=canonical_json_bytes(beacon), **_rfc_kwargs(candidate))


def test_module_exposes_no_typed_live_proof_or_permit_surface() -> None:
    assert not hasattr(live_crypto, "LiveRFC3161Quorum")
    assert not hasattr(live_crypto, "LiveDrandVerification")
    source = inspect.getsource(live_crypto)
    assert "OfflineSynthetic" not in source
    assert "SUBMIT_AUTHORIZED" not in source
