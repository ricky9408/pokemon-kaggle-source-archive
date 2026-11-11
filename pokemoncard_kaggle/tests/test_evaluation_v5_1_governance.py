from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.exact_gate_v2 import (
    AUTHORITY_DOMAIN,
    AUTHORITY_ENVELOPE_SCHEMA,
    AUTHORITY_PAYLOAD_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_SCHEMA,
    EVIDENCE_MANIFEST_SCHEMA,
    MANIFEST_MEDIA_TYPE,
    PASS_DECISION,
    PROTOCOL_ID,
    VALIDATOR_DOMAIN,
    VALIDATOR_ENVELOPE_SCHEMA,
    VALIDATOR_PAYLOAD_MEDIA_TYPE,
    VALIDATOR_PAYLOAD_SCHEMA,
    dependency_closure_root,
    encode_byte_evidence,
    evidence_merkle_root,
)
from evaluation_v5_1.governance import (
    G00_COUNTERSIGNATURE_SCHEMA,
    G00_DECISION,
    G00_EVIDENCE_SCHEMA,
    G00_FINAL_GATE_SCHEMA,
    G00_POP_ENVELOPE_SCHEMA,
    G00_POP_PAYLOAD_SCHEMA,
    G00_REGISTRY_SCHEMA,
    G00_ROOT_SCHEMA,
    G01_CONSTITUTION_SCHEMA,
    G01_COUNTERSIGNATURE_SCHEMA,
    G01_DECISION,
    G01_DEVELOPMENT_ATTESTATION_SCHEMA,
    G01_EVIDENCE_SCHEMA,
    G01_FINAL_GATE_SCHEMA,
    G01_MANIFEST_SCHEMA,
    G01_SOURCE_ARCHIVE_SCHEMA,
    GOVERNANCE_V2_CAMPAIGN_NONCE_MEDIA_TYPE,
    GOVERNANCE_V2_CAMPAIGN_ROOT_DOMAIN,
    GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN,
    GOVERNANCE_V2_EVALUATION_ENTRY_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_EVALUATION_ENTRY_MEDIA_TYPE,
    GOVERNANCE_V2_EVALUATION_ENTRY_SCHEMA,
    GOVERNANCE_V2_FAILURE_REGISTRY_SCHEMA,
    GOVERNANCE_V2_FREEZE_DOMAIN,
    GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_FREEZE_MEDIA_TYPE,
    GOVERNANCE_V2_FREEZE_SCHEMA,
    GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN,
    GOVERNANCE_V2_FREEZE_VALIDATOR_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_FREEZE_VALIDATOR_MEDIA_TYPE,
    GOVERNANCE_V2_FREEZE_VALIDATOR_SCHEMA,
    GOVERNANCE_V2_GATE_DEPENDENCIES,
    GOVERNANCE_V2_GATE_IDS,
    GOVERNANCE_V2_GENESIS_DOMAIN,
    GOVERNANCE_V2_GENESIS_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_GENESIS_MEDIA_TYPE,
    GOVERNANCE_V2_GENESIS_PAYLOAD_SCHEMA,
    GOVERNANCE_V2_PUBLIC_KEY_MEDIA_TYPE,
    GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
    GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
    GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA,
    GOVERNANCE_V2_REQUIRED_ROLES,
    GOVERNANCE_V2_ROLE_POP_DOMAIN,
    GOVERNANCE_V2_ROLE_POP_ENVELOPE_SCHEMA,
    GOVERNANCE_V2_ROLE_POP_MEDIA_TYPE,
    GOVERNANCE_V2_ROLE_POP_SCHEMA,
    REQUIRED_ROLES,
    derive_g00_trust_roots,
    derive_g01_constitution_and_code_freeze,
    derive_governance_v2,
    governance_v2_signature_message,
    verify_exact_gate_v2_governance,
    verify_g00_trust_roots,
    verify_g01_constitution_and_code_freeze,
    verify_governance_v2,
)


def test_governance_registers_reviewed_multi_parent_gate_dag() -> None:
    assert GOVERNANCE_V2_GATE_DEPENDENCIES["G09_BLIND_CAMPAIGN_ACTIVATION"] == (
        "G00_TRUST_ROOTS",
        "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION",
    )
    assert GOVERNANCE_V2_GATE_DEPENDENCIES[
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION"
    ] == ("G05_DEV_SOURCE_COMPLETENESS", "G12_EVALUATOR_UNSEAL")
    assert GOVERNANCE_V2_GATE_DEPENDENCIES[
        "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT"
    ] == (
        "G12_EVALUATOR_UNSEAL",
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
    )
    assert GOVERNANCE_V2_GATE_DEPENDENCIES["G15_RELEASE_CUSTODY"] == (
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
        "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT",
    )


Key = tuple[Ed25519PrivateKey, bytes]
Mutation = Callable[[dict[str, Any]], None]

CREATED = "2026-07-14T00:00:00.000000Z"
FREEZE = "2026-07-14T01:00:00.000000Z"
G00_POP_NS = "1783987230000000000"
G00_ISSUED_NS = "1783987260000000000"
G00_VALIDATOR_NS = "1783987270000000000"
G01_DEVELOPMENT_NS = "1783990810000000000"
G01_ISSUED_NS = "1783990860000000000"
G01_VALIDATOR_NS = "1783990920000000000"
IMAGE = "c" * 64

V2_CREATED_NS = "1000"
V2_GENESIS_NS = "1100"
V2_EPOCH_NS = "2000"
V2_POP_NS = "3000"
V2_ENTRY_NS = "4000"
V2_FREEZE_NS = "5000"
V2_FREEZE_AUTHORITY_NS = "5100"
V2_FREEZE_VALIDATOR_NS = "5200"
V2_MANIFEST_NS = "6000"
V2_AUTHORITY_NS = "7000"
V2_VALIDATOR_NS = "7100"


def _key(seed: int) -> Key:
    private = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"governance-test-key-{seed}".encode()).digest()
    )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _key_id(public: bytes) -> str:
    return f"ed25519-sha256:{hashlib.sha256(public).hexdigest()}"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _blob(raw: bytes, media_type: str) -> dict[str, object]:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def _wrapped_json(value: object, media_type: str) -> dict[str, object]:
    return _blob(canonical_json_bytes(value), media_type)


def _signed_v1(schema: str, payload: dict[str, object], key: Key) -> dict[str, object]:
    private, public = key
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _signed_raw(
    payload: dict[str, object],
    *,
    schema: str,
    media_type: str,
    domain: bytes,
    key: Key,
) -> bytes:
    private, public = key
    payload_raw = canonical_json_bytes(payload)
    wrapper = encode_byte_evidence(payload_raw, media_type=media_type)
    try:
        message = (
            governance_v2_signature_message(domain=domain, payload_raw=payload_raw)
            if domain.startswith(b"PTCG/GOVERNANCE/")
            else domain + b"\x00" + len(payload_raw).to_bytes(8, "big") + payload_raw
        )
    except ValueError:
        # Adversarial fixtures must be able to sign bytes that the public
        # construction helper correctly refuses.
        message = domain + b"\x00" + len(payload_raw).to_bytes(8, "big") + payload_raw
    envelope = {
        "schema_version": schema,
        "signer_key_id": _key_id(public),
        "payload": wrapper,
        "signature_ed25519_base64": base64.b64encode(
            private.sign(message)
        ).decode("ascii"),
    }
    return canonical_json_bytes(envelope)


def _assert_zero_authority(result: dict[str, object]) -> None:
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    if "holdout_access" in result:
        assert result["holdout_access"] is False
    assert result["sealed_holdout_access"] is False
    if "candidate_authorized" in result:
        assert result["candidate_authorized"] is False
    assert result["candidate_development_authorized"] is False


def _v1_registry(keys: dict[str, Key]) -> dict[str, object]:
    rows = []
    for role in sorted(REQUIRED_ROLES):
        public = keys[role][1]
        fingerprint = hashlib.sha256(public).hexdigest()
        rows.append(
            {
                "role": role,
                "key_id": _key_id(public),
                "principal_id": f"principal-{role}",
                "custodian_id": f"custodian-{role}",
                "algorithm": "Ed25519",
                "public_key": _blob(
                    public, "application/vnd.evaluation-v5.1.ed25519-public-key"
                ),
                "public_key_fingerprint_sha256": fingerprint,
                "not_before_utc": "2026-07-13T00:00:00.000000Z",
                "not_after_utc": "2027-07-14T00:00:00.000000Z",
                "revocation": {"state": "active", "revoked_at_utc": None},
            }
        )
    return {
        "schema": G00_REGISTRY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "registry_epoch": 0,
        "registry_status": "ACTIVE",
        "campaign_nonce": _blob(
            b"N" * 32, "application/vnd.evaluation-v5.1.campaign-nonce"
        ),
        "incompatible_role_matrix": {
            role: [other for other in REQUIRED_ROLES if other != role]
            for role in REQUIRED_ROLES
        },
        "keys": rows,
    }


def _v1_root(registry_sha256: str, nonce_sha256: str) -> str:
    return canonical_sha256(
        {
            "schema": G00_ROOT_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_id": "campaign-v51",
            "campaign_created_at_utc": CREATED,
            "predecessor": {
                "kind": "genesis",
                "predecessor_campaign_root_sha256": None,
                "predecessor_created_at_utc": None,
            },
            "registry_sha256": registry_sha256,
            "campaign_nonce_sha256": nonce_sha256,
        }
    )


def _v1_g00(registry_mutation: Mutation | None = None) -> tuple[dict[str, Any], dict[str, Key]]:
    keys = {role: _key(index + 1) for index, role in enumerate(REQUIRED_ROLES)}
    registry = _v1_registry(keys)
    if registry_mutation is not None:
        registry_mutation(registry)
    registry_bytes = canonical_json_bytes(registry)
    registry_sha256 = hashlib.sha256(registry_bytes).hexdigest()
    root = _v1_root(registry_sha256, registry["campaign_nonce"]["sha256"])  # type: ignore[index]
    rows = {row["role"]: row for row in registry["keys"]}  # type: ignore[index]
    proofs = {}
    for role in REQUIRED_ROLES:
        row = rows[role]
        proofs[role] = _signed_v1(
            G00_POP_ENVELOPE_SCHEMA,
            {
                "schema": G00_POP_PAYLOAD_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "campaign_root_sha256": root,
                "registry_sha256": registry_sha256,
                "role": role,
                "key_id": row["key_id"],
                "principal_id": row["principal_id"],
                "custodian_id": row["custodian_id"],
                "campaign_nonce": registry["campaign_nonce"],
                "issued_at_ns": G00_POP_NS,
                "registry_epoch": 0,
                "registry_status": "ACTIVE",
            },
            keys[role],
        )
    evidence = {
        "schema": G00_EVIDENCE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "campaign_created_at_utc": CREATED,
        "issued_at_ns": G00_ISSUED_NS,
        "predecessor": {
            "kind": "genesis",
            "predecessor_campaign_root_sha256": None,
            "predecessor_created_at_utc": None,
        },
        "registry": _blob(
            registry_bytes, "application/vnd.evaluation-v5.1.campaign-registry+json"
        ),
        "registry_sha256": registry_sha256,
        "campaign_root_sha256": root,
        "proofs": proofs,
    }
    result = derive_g00_trust_roots(
        campaign_evidence=evidence,
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    bundle: dict[str, Any] = {
        "evidence": evidence,
        "result": result,
        "registry": registry,
        "root": root,
    }
    if result["decision"] == G00_DECISION:
        authority = _signed_v1(
            G00_FINAL_GATE_SCHEMA, result, keys["evaluation_authority"]
        )
        validator = _signed_v1(
            G00_COUNTERSIGNATURE_SCHEMA,
            {
                "schema": G00_COUNTERSIGNATURE_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "authority_envelope_sha256": canonical_sha256(authority),
                "registry_epoch": 0,
                "registry_hash": registry_sha256,
                "registry_status": "ACTIVE",
                "issued_at_ns": G00_VALIDATOR_NS,
                "validator_key_id": _key_id(keys["validation_authority"][1]),
            },
            keys["validation_authority"],
        )
        bundle.update({"authority": authority, "validator": validator})
    return bundle, keys


def _verify_v1_g00(bundle: dict[str, Any], keys: dict[str, Key]) -> dict[str, Any]:
    return verify_g00_trust_roots(
        campaign_evidence=bundle["evidence"],
        final_authority_envelope=bundle["authority"],
        final_validator_envelope=bundle["validator"],
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )


def _v1_g01(bundle: dict[str, Any], keys: dict[str, Key]) -> dict[str, Any]:
    raw_files = {
        "build/run.sh": (b"#!/bin/sh\nexit 0\n", "build_script", "text/x-shellscript"),
        "config/freeze.json": (b'{"freeze":true}', "config", "application/json"),
        "container/validator.json": (b'{"image":"frozen"}', "container", "application/json"),
        "excluded/notes.txt": (b"not evaluated\n", "excluded", "text/plain"),
        "lock/requirements.lock": (b"cryptography==44.0.0\n", "lockfile", "text/plain"),
        "schema/all.json": (b"{}", "schema", "application/json"),
        "seed/spec.json": (b'{"seed":"frozen"}', "seed_spec", "application/json"),
        "src/evaluator.py": (b"def evaluate(): return 0\n", "source", "text/x-python"),
        "toolchain/python.json": (b'{"python":"3.11"}', "toolchain", "application/json"),
    }
    archive_files = [
        {"path": path, "content": _blob(content, media_type)}
        for path, (content, _, media_type) in sorted(raw_files.items())
    ]
    source_archive = {
        "schema": G01_SOURCE_ARCHIVE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "files": archive_files,
    }
    manifest_files = [
        {
            "path": item["path"],
            "decoded_length": item["content"]["decoded_length"],
            "sha256": item["content"]["sha256"],
            "media_type": item["content"]["media_type"],
            "classification": raw_files[item["path"]][1],
        }
        for item in archive_files
    ]
    digest = {row["path"]: row["sha256"] for row in manifest_files}
    manifest = {
        "schema": G01_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "g00_campaign_root_sha256": bundle["root"],
        "freeze_time_utc": FREEZE,
        "files": manifest_files,
        "lockfiles": ["lock/requirements.lock"],
        "build_scripts": ["build/run.sh"],
        "schemas": ["schema/all.json"],
        "toolchain": {
            "path": "toolchain/python.json",
            "sha256": digest["toolchain/python.json"],
            "container_image_sha256": IMAGE,
        },
        "container": {
            "path": "container/validator.json",
            "sha256": digest["container/validator.json"],
            "container_image_sha256": IMAGE,
        },
        "configs": ["config/freeze.json"],
        "exclusions": [{"path": "excluded/notes.txt", "reason": "non-runtime note"}],
        "seed_spec": {
            "path": "seed/spec.json",
            "sha256": digest["seed/spec.json"],
            "scheme": "sha256-counter",
            "domain_separator": "EVAL_V5_1",
        },
    }
    constitution = {
        "schema": G01_CONSTITUTION_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "g00_campaign_root_sha256": bundle["root"],
        "claim": "frozen descriptive claim",
        "frozen_components": {
            "schemas": ["schema/all.json"],
            "feature_registry": "schema/all.json",
            "model_registry": "schema/all.json",
            "dev_algorithm": "schema/all.json",
            "census_parser": "schema/all.json",
            "sampling_algorithm": "schema/all.json",
            "validator_image": {
                "path": "container/validator.json",
                "sha256": digest["container/validator.json"],
                "container_image_sha256": IMAGE,
            },
            "authority_matrix": "schema/all.json",
        },
        "no_submit_conditions": ["no holdout access", "no submission"],
    }
    archive_blob = _wrapped_json(
        source_archive, "application/vnd.evaluation-v5.1.source-archive+json"
    )
    manifest_blob = _wrapped_json(
        manifest, "application/vnd.evaluation-v5.1.source-manifest+json"
    )
    constitution_blob = _wrapped_json(
        constitution, "application/vnd.evaluation-v5.1.constitution+json"
    )
    registry_hash = bundle["result"]["registry_sha256"]
    development = _signed_v1(
        G01_DEVELOPMENT_ATTESTATION_SCHEMA,
        {
            "schema": G01_DEVELOPMENT_ATTESTATION_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_id": "campaign-v51",
            "g00_campaign_root_sha256": bundle["root"],
            "constitution_sha256": constitution_blob["sha256"],
            "source_archive_sha256": archive_blob["sha256"],
            "manifest_sha256": manifest_blob["sha256"],
            "freeze_time_utc": FREEZE,
            "development_key_id": _key_id(keys["development_identity"][1]),
            "development_principal_id": "principal-development_identity",
            "development_custodian_id": "custodian-development_identity",
            "registry_epoch": 0,
            "registry_hash": registry_hash,
            "registry_status": "ACTIVE",
            "issued_at_ns": G01_DEVELOPMENT_NS,
        },
        keys["development_identity"],
    )
    evidence = {
        "schema": G01_EVIDENCE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-v51",
        "g00_campaign_root_sha256": bundle["root"],
        "issued_at_ns": G01_ISSUED_NS,
        "constitution": constitution_blob,
        "source_archive": archive_blob,
        "manifest": manifest_blob,
        "development_attestation_envelope": development,
    }
    result = derive_g01_constitution_and_code_freeze(
        campaign_evidence=bundle["evidence"],
        g00_final_authority_envelope=bundle["authority"],
        g00_final_validator_envelope=bundle["validator"],
        g01_evidence=evidence,
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    result_bundle: dict[str, Any] = {
        "evidence": evidence,
        "result": result,
        "source_archive": source_archive,
        "manifest": manifest,
        "constitution": constitution,
    }
    if result["decision"] == G01_DECISION:
        authority = _signed_v1(
            G01_FINAL_GATE_SCHEMA, result, keys["evaluation_authority"]
        )
        validator = _signed_v1(
            G01_COUNTERSIGNATURE_SCHEMA,
            {
                "schema": G01_COUNTERSIGNATURE_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "authority_envelope_sha256": canonical_sha256(authority),
                "registry_epoch": 0,
                "registry_hash": registry_hash,
                "registry_status": "ACTIVE",
                "issued_at_ns": G01_VALIDATOR_NS,
                "validator_key_id": _key_id(keys["validation_authority"][1]),
            },
            keys["validation_authority"],
        )
        result_bundle.update({"authority": authority, "validator": validator})
    return result_bundle


def _derive_v1_g01(
    g00: dict[str, Any], g01: dict[str, Any], keys: dict[str, Key]
) -> dict[str, Any]:
    return derive_g01_constitution_and_code_freeze(
        campaign_evidence=g00["evidence"],
        g00_final_authority_envelope=g00["authority"],
        g00_final_validator_envelope=g00["validator"],
        g01_evidence=g01["evidence"],
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )


def test_v1_g00_g01_success_is_diagnostic_and_zero_authority() -> None:
    g00, keys = _v1_g00()
    assert g00["result"]["decision"] == G00_DECISION
    result = _verify_v1_g00(g00, keys)
    assert result["decision"] == G00_DECISION
    assert "PASS" not in result["decision"]
    _assert_zero_authority(result)

    g01 = _v1_g01(g00, keys)
    assert g01["result"]["decision"] == G01_DECISION, g01["result"].get("reason")
    result = verify_g01_constitution_and_code_freeze(
        campaign_evidence=g00["evidence"],
        g00_final_authority_envelope=g00["authority"],
        g00_final_validator_envelope=g00["validator"],
        g01_evidence=g01["evidence"],
        final_authority_envelope=g01["authority"],
        final_validator_envelope=g01["validator"],
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == G01_DECISION
    assert "PASS" not in result["decision"]
    assert result["source_file_count"] == result["manifest_file_count"] == 9
    assert sum(result["classification_counts"].values()) == 9
    _assert_zero_authority(result)


@pytest.mark.parametrize("role", ["collector_b", "release_authority"])
def test_v1_g00_requires_pop_for_every_arbitrary_role(role: str) -> None:
    g00, keys = _v1_g00()
    bad = copy.deepcopy(g00["evidence"])
    del bad["proofs"][role]
    result = derive_g00_trust_roots(
        campaign_evidence=bad,
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == "G00_EVIDENCE_INVALID"
    assert result["fail_code"] == "G00_POP_INVALID"
    _assert_zero_authority(result)


def test_v1_rejects_forged_signatures_timeless_receipts_and_authority_claims() -> None:
    g00, keys = _v1_g00()
    forged = copy.deepcopy(g00)
    forged["evidence"]["proofs"]["collector_a"]["signature_ed25519_base64"] = "A" * 88
    assert _verify_v1_g00(forged, keys)["decision"] == "G00_EVIDENCE_INVALID"

    timeless = copy.deepcopy(g00["evidence"])
    del timeless["issued_at_ns"]
    result = derive_g00_trust_roots(
        campaign_evidence=timeless,
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == "G00_EVIDENCE_INVALID"

    claimed = copy.deepcopy(g00)
    payload = copy.deepcopy(claimed["authority"]["payload"])
    payload["authority"] = True
    claimed["authority"] = _signed_v1(
        G00_FINAL_GATE_SCHEMA, payload, keys["evaluation_authority"]
    )
    result = _verify_v1_g00(claimed, keys)
    assert result["decision"] == "G00_EVIDENCE_INVALID"
    _assert_zero_authority(result)


@pytest.mark.parametrize(
    "mutation",
    ["reused_key", "reused_principal", "reused_custodian", "cross_alias", "bad_key_id", "revoked", "expired"],
)
def test_v1_registry_rejects_aliases_derived_id_and_invalid_keys(mutation: str) -> None:
    g00, keys = _v1_g00()
    bad = copy.deepcopy(g00["evidence"])
    registry = json.loads(base64.b64decode(bad["registry"]["base64"]))
    rows = registry["keys"]
    if mutation == "reused_key":
        rows[1]["public_key"] = copy.deepcopy(rows[0]["public_key"])
        rows[1]["public_key_fingerprint_sha256"] = rows[0]["public_key_fingerprint_sha256"]
        rows[1]["key_id"] = rows[0]["key_id"]
    elif mutation == "reused_principal":
        rows[1]["principal_id"] = rows[0]["principal_id"]
    elif mutation == "reused_custodian":
        rows[1]["custodian_id"] = rows[0]["custodian_id"]
    elif mutation == "cross_alias":
        rows[1]["custodian_id"] = rows[0]["principal_id"]
    elif mutation == "bad_key_id":
        rows[1]["key_id"] = f"ed25519-sha256:{'0' * 64}"
    elif mutation == "revoked":
        rows[1]["revocation"] = {
            "state": "revoked",
            "revoked_at_utc": CREATED,
        }
    else:
        rows[1]["not_after_utc"] = "2026-07-13T23:59:59.000000Z"
    bad["registry"] = _wrapped_json(
        registry, "application/vnd.evaluation-v5.1.campaign-registry+json"
    )
    bad["registry_sha256"] = bad["registry"]["sha256"]
    bad["campaign_root_sha256"] = _v1_root(
        bad["registry_sha256"], registry["campaign_nonce"]["sha256"]
    )
    result = derive_g00_trust_roots(
        campaign_evidence=bad,
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == "G00_EVIDENCE_INVALID"
    assert result["fail_code"] == "G00_REGISTRY_INVALID"


def test_v1_g00_checks_authority_validity_at_final_issuance() -> None:
    def expire_authority(registry: dict[str, Any]) -> None:
        row = next(
            item for item in registry["keys"] if item["role"] == "evaluation_authority"
        )
        row["not_after_utc"] = "2026-07-14T00:00:45.000000Z"

    g00, _ = _v1_g00(expire_authority)
    assert g00["result"]["decision"] == "G00_EVIDENCE_INVALID"
    assert g00["result"]["fail_code"] == "G00_CHRONOLOGY_INVALID"


def test_v1_g00_checks_validator_validity_at_countersignature_issuance() -> None:
    def expire_validator(registry: dict[str, Any]) -> None:
        row = next(
            item for item in registry["keys"] if item["role"] == "validation_authority"
        )
        row["not_after_utc"] = "2026-07-14T00:01:05.000000Z"

    g00, keys = _v1_g00(expire_validator)
    assert g00["result"]["decision"] == G00_DECISION
    result = _verify_v1_g00(g00, keys)
    assert result["decision"] == "G00_EVIDENCE_INVALID"
    assert result["fail_code"] == "G00_FINAL_SIGNATURE_INVALID"


def test_v1_g01_rejects_forged_developer_signature_and_authority_claim() -> None:
    g00, keys = _v1_g00()
    g01 = _v1_g01(g00, keys)
    forged = copy.deepcopy(g01)
    forged["evidence"]["development_attestation_envelope"][
        "signature_ed25519_base64"
    ] = "A" * 88
    result = _derive_v1_g01(g00, forged, keys)
    assert result["decision"] == "G01_EVIDENCE_INVALID"

    claimed = copy.deepcopy(g01)
    payload = copy.deepcopy(claimed["authority"]["payload"])
    payload["authority"] = True
    claimed["authority"] = _signed_v1(
        G01_FINAL_GATE_SCHEMA, payload, keys["evaluation_authority"]
    )
    result = verify_g01_constitution_and_code_freeze(
        campaign_evidence=g00["evidence"],
        g00_final_authority_envelope=g00["authority"],
        g00_final_validator_envelope=g00["validator"],
        g01_evidence=claimed["evidence"],
        final_authority_envelope=claimed["authority"],
        final_validator_envelope=claimed["validator"],
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == "G01_EVIDENCE_INVALID"
    _assert_zero_authority(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "traversal",
        "alias",
        "duplicate",
        "symlink",
        "orphan",
        "noncanonical_base64",
        "hash",
        "private",
        "legacy",
        "chronology",
    ],
)
def test_v1_g01_rejects_nonclosed_or_noncanonical_source_freeze(mutation: str) -> None:
    g00, keys = _v1_g00()
    g01 = _v1_g01(g00, keys)
    bad = copy.deepcopy(g01)
    if mutation in {
        "traversal",
        "alias",
        "duplicate",
        "symlink",
        "orphan",
        "noncanonical_base64",
        "hash",
        "private",
    }:
        archive = json.loads(
            base64.b64decode(bad["evidence"]["source_archive"]["base64"])
        )
        if mutation == "traversal":
            archive["files"][0]["path"] = "../escape.py"
        elif mutation == "alias":
            archive["files"][0]["path"] = "build//run.sh"
        elif mutation == "duplicate":
            archive["files"].append(copy.deepcopy(archive["files"][0]))
        elif mutation == "symlink":
            archive["files"][0]["symlink_target"] = "../outside"
        elif mutation == "orphan":
            archive["files"].append(
                {"path": "src/orphan.py", "content": _blob(b"pass\n", "text/x-python")}
            )
            archive["files"].sort(key=lambda item: item["path"])
        elif mutation == "noncanonical_base64":
            archive["files"][0]["content"]["base64"] += "\n"
        elif mutation == "hash":
            archive["files"][0]["content"]["sha256"] = "0" * 64
        else:
            archive["files"].append(
                {
                    "path": "keys/private.pem",
                    "content": _blob(b"-----BEGIN PRIVATE KEY-----\n", "text/plain"),
                }
            )
            archive["files"].sort(key=lambda item: item["path"])
        bad["evidence"]["source_archive"] = _wrapped_json(
            archive, "application/vnd.evaluation-v5.1.source-archive+json"
        )
    elif mutation == "legacy":
        constitution = json.loads(
            base64.b64decode(bad["evidence"]["constitution"]["base64"])
        )
        constitution["schema"] = "evaluation_v5_1_constitution_v0"
        bad["evidence"]["constitution"] = _wrapped_json(
            constitution, "application/vnd.evaluation-v5.1.constitution+json"
        )
    else:
        manifest = json.loads(base64.b64decode(bad["evidence"]["manifest"]["base64"]))
        manifest["freeze_time_utc"] = CREATED
        bad["evidence"]["manifest"] = _wrapped_json(
            manifest, "application/vnd.evaluation-v5.1.source-manifest+json"
        )
    result = _derive_v1_g01(g00, bad, keys)
    assert result["decision"] == "G01_EVIDENCE_INVALID"
    _assert_zero_authority(result)


@pytest.mark.parametrize("signer", ["development_identity", "evaluation_authority", "validation_authority"])
def test_v1_g01_checks_each_role_key_at_its_issuance(signer: str) -> None:
    expiry = {
        "development_identity": "2026-07-14T00:30:00.000000Z",
        "evaluation_authority": "2026-07-14T01:00:30.000000Z",
        "validation_authority": "2026-07-14T01:01:30.000000Z",
    }[signer]

    def expire_signer(registry: dict[str, Any]) -> None:
        row = next(item for item in registry["keys"] if item["role"] == signer)
        row["not_after_utc"] = expiry

    g00, keys = _v1_g00(expire_signer)
    assert g00["result"]["decision"] == G00_DECISION
    g01 = _v1_g01(g00, keys)
    if signer != "validation_authority":
        assert g01["result"]["decision"] == "G01_EVIDENCE_INVALID"
        return
    assert g01["result"]["decision"] == G01_DECISION, g01["result"].get("reason")
    result = verify_g01_constitution_and_code_freeze(
        campaign_evidence=g00["evidence"],
        g00_final_authority_envelope=g00["authority"],
        g00_final_validator_envelope=g00["validator"],
        g01_evidence=g01["evidence"],
        final_authority_envelope=g01["authority"],
        final_validator_envelope=g01["validator"],
        pinned_bootstrap_authority_public_key=keys["evaluation_authority"][1],
        pinned_validation_public_key=keys["validation_authority"][1],
    )
    assert result["decision"] == "G01_EVIDENCE_INVALID"
    assert result["fail_code"] == "G01_FINAL_SIGNATURE_INVALID"


def _v2_key_record(role: str, key: Key) -> dict[str, object]:
    return {
        "role": role,
        "key_id": _key_id(key[1]),
        "principal_id": f"principal:{role}",
        "custodian_id": f"custodian:{role}",
        "algorithm": "Ed25519",
        "public_key": encode_byte_evidence(
            key[1], media_type=GOVERNANCE_V2_PUBLIC_KEY_MEDIA_TYPE
        ),
        "valid_from_ns": "1",
        "valid_until_ns": "9999999999999999999",
        "status": "ACTIVE",
        "invalidate_from_ns": None,
    }


def _active_test_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["role"]: record for record in records if record["status"] == "ACTIVE"}


def _v2_bundle(
    epoch_mutation: Callable[[list[dict[str, Any]], dict[str, Key]], None] | None = None,
    second_epoch_mutation: Callable[[list[dict[str, Any]], dict[str, Key]], None]
    | None = None,
    entry_mutation: Mutation | None = None,
) -> dict[str, Any]:
    root_key = _key(100)
    keys = {
        role: _key(110 + index)
        for index, role in enumerate(GOVERNANCE_V2_REQUIRED_ROLES)
    }
    records = [
        _v2_key_record(role, keys[role]) for role in GOVERNANCE_V2_REQUIRED_ROLES
    ]
    genesis_custodian = copy.deepcopy(
        next(record for record in records if record["role"] == "registry_custodian")
    )
    nonce = encode_byte_evidence(
        bytes(range(32)), media_type=GOVERNANCE_V2_CAMPAIGN_NONCE_MEDIA_TYPE
    )
    genesis_payload = {
        "schema_version": GOVERNANCE_V2_GENESIS_PAYLOAD_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_id": "campaign-governance-v2",
        "created_at_ns": V2_CREATED_NS,
        "issued_at_ns": V2_GENESIS_NS,
        "offline_root_key_id": _key_id(root_key[1]),
        "campaign_nonce": nonce,
        "required_roles": list(GOVERNANCE_V2_REQUIRED_ROLES),
        "incompatible_role_matrix": {
            role: [other for other in GOVERNANCE_V2_REQUIRED_ROLES if other != role]
            for role in GOVERNANCE_V2_REQUIRED_ROLES
        },
        "registry_custodian": genesis_custodian,
    }
    genesis = _signed_raw(
        genesis_payload,
        schema=GOVERNANCE_V2_GENESIS_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_GENESIS_MEDIA_TYPE,
        domain=GOVERNANCE_V2_GENESIS_DOMAIN,
        key=root_key,
    )
    campaign_root = hashlib.sha256(
        GOVERNANCE_V2_CAMPAIGN_ROOT_DOMAIN
        + len(genesis).to_bytes(8, "big")
        + genesis
    ).hexdigest()
    if epoch_mutation is not None:
        epoch_mutation(records, keys)
    records.sort(key=lambda record: (record["role"], record["key_id"]))
    epoch_payload = {
        "schema_version": GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": campaign_root,
        "epoch": 0,
        "predecessor_epoch_hash": hashlib.sha256(genesis).hexdigest(),
        "issued_at_ns": V2_EPOCH_NS,
        "registry_status": "ACTIVE",
        "keys": records,
    }
    epoch = _signed_raw(
        epoch_payload,
        schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
        domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        key=keys["registry_custodian"],
    )
    epoch_hash = hashlib.sha256(epoch).hexdigest()
    epochs = [epoch]
    epoch_payloads = [epoch_payload]
    current_epoch = 0
    if second_epoch_mutation is not None:
        prior_active = _active_test_records(records)
        second_records = copy.deepcopy(records)
        second_epoch_mutation(second_records, keys)
        second_records.sort(key=lambda record: (record["role"], record["key_id"]))
        prior_key_by_id = {_key_id(key[1]): key for key in keys.values()}
        second_payload = {
            "schema_version": GOVERNANCE_V2_REGISTRY_EPOCH_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "campaign_root": campaign_root,
            "epoch": 1,
            "predecessor_epoch_hash": epoch_hash,
            "issued_at_ns": "2500",
            "registry_status": "ACTIVE",
            "keys": second_records,
        }
        second_epoch = _signed_raw(
            second_payload,
            schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
            media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
            domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
            key=prior_key_by_id[prior_active["registry_custodian"]["key_id"]],
        )
        records = second_records
        epoch_payload = second_payload
        epoch_hash = hashlib.sha256(second_epoch).hexdigest()
        epochs.append(second_epoch)
        epoch_payloads.append(second_payload)
        current_epoch = 1
    failure_registries: dict[str, bytes] = {}
    gate_dag = []
    for gate_id in GOVERNANCE_V2_GATE_IDS:
        failure_registry = canonical_json_bytes(
            {
                "schema_version": GOVERNANCE_V2_FAILURE_REGISTRY_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "gate_id": gate_id,
                "codes": ["GATE_REJECTED"],
            }
        )
        failure_registries[gate_id] = failure_registry
        gate_dag.append(
            {
                "gate_id": gate_id,
                "direct_dependencies": list(GOVERNANCE_V2_GATE_DEPENDENCIES[gate_id]),
                "frozen_spec_hash": _hash(f"{gate_id}:spec"),
                "verifier_module_hash": _hash(f"{gate_id}:module"),
                "verifier_runtime_hash": _hash(f"{gate_id}:runtime"),
                "input_schema_hash": _hash(f"{gate_id}:input"),
                "output_schema_hash": _hash(f"{gate_id}:output"),
                "failure_code_registry_hash": hashlib.sha256(failure_registry).hexdigest(),
                "evidence_manifest_schema": EVIDENCE_MANIFEST_SCHEMA,
            }
        )
    active = _active_test_records(records)
    entry_payload = {
        "schema_version": GOVERNANCE_V2_EVALUATION_ENTRY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": campaign_root,
        "registry_epoch": current_epoch,
        "registry_hash": epoch_hash,
        "registry_status": "ACTIVE",
        "evaluation_id": "evaluation-v2-0001",
        "evaluation_nonce": hashlib.sha256(b"prospective-evaluation-nonce").hexdigest(),
        "attempt": 0,
        "registrar_key_id": active["registrar"]["key_id"],
        "registrar_principal_id": active["registrar"]["principal_id"],
        "registrar_custodian_id": active["registrar"]["custodian_id"],
        "registered_at_ns": V2_ENTRY_NS,
        "issued_at_ns": V2_ENTRY_NS,
        "gate_dag": gate_dag,
        "evidence_manifest_schema": EVIDENCE_MANIFEST_SCHEMA,
    }
    if entry_mutation is not None:
        entry_mutation(entry_payload)
    key_by_id = {_key_id(key[1]): key for key in keys.values()}
    registrar_key = key_by_id[active["registrar"]["key_id"]]
    entry = _signed_raw(
        entry_payload,
        schema=GOVERNANCE_V2_EVALUATION_ENTRY_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_EVALUATION_ENTRY_MEDIA_TYPE,
        domain=GOVERNANCE_V2_EVALUATION_ENTRY_DOMAIN,
        key=registrar_key,
    )
    entry_hash = hashlib.sha256(entry).hexdigest()
    pops = {}
    for role in GOVERNANCE_V2_REQUIRED_ROLES:
        record = active[role]
        pops[role] = _signed_raw(
            {
                "schema_version": GOVERNANCE_V2_ROLE_POP_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "campaign_root": campaign_root,
                "registry_epoch": current_epoch,
                "registry_hash": epoch_hash,
                "registry_status": "ACTIVE",
                "role": role,
                "key_id": record["key_id"],
                "principal_id": record["principal_id"],
                "custodian_id": record["custodian_id"],
                "campaign_nonce": nonce,
                "issued_at_ns": V2_POP_NS,
            },
            schema=GOVERNANCE_V2_ROLE_POP_ENVELOPE_SCHEMA,
            media_type=GOVERNANCE_V2_ROLE_POP_MEDIA_TYPE,
            domain=GOVERNANCE_V2_ROLE_POP_DOMAIN,
            key=key_by_id[record["key_id"]],
        )
    freeze_payload = {
        "schema_version": GOVERNANCE_V2_FREEZE_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": campaign_root,
        "registry_epoch": current_epoch,
        "registry_hash": epoch_hash,
        "registry_status": "ACTIVE",
        "evaluation_entry_hash": entry_hash,
        "evaluation_id": entry_payload["evaluation_id"],
        "evaluation_nonce": entry_payload["evaluation_nonce"],
        "attempt": entry_payload["attempt"],
        "registered_at_ns": entry_payload["registered_at_ns"],
        "freeze_at_ns": V2_FREEZE_NS,
        "issued_at_ns": V2_FREEZE_AUTHORITY_NS,
        "gate_registry_root": canonical_sha256(gate_dag),
        "evidence_manifest_schema": EVIDENCE_MANIFEST_SCHEMA,
        "evaluation_authority_key_id": active["evaluation_authority"]["key_id"],
    }
    freeze_authority = _signed_raw(
        freeze_payload,
        schema=GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_FREEZE_MEDIA_TYPE,
        domain=GOVERNANCE_V2_FREEZE_DOMAIN,
        key=key_by_id[active["evaluation_authority"]["key_id"]],
    )
    freeze_payload_raw = canonical_json_bytes(freeze_payload)
    validator_key = key_by_id[active["validation_authority"]["key_id"]]
    freeze_validator_payload = {
        "schema_version": GOVERNANCE_V2_FREEZE_VALIDATOR_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": campaign_root,
        "registry_epoch": current_epoch,
        "registry_hash": epoch_hash,
        "registry_status": "ACTIVE",
        "evaluation_entry_hash": entry_hash,
        "evaluation_id": entry_payload["evaluation_id"],
        "evaluation_nonce": entry_payload["evaluation_nonce"],
        "attempt": entry_payload["attempt"],
        "freeze_authority_envelope_sha256": hashlib.sha256(freeze_authority).hexdigest(),
        "freeze_authority_envelope_decoded_length": len(freeze_authority),
        "freeze_authority_payload_sha256": hashlib.sha256(freeze_payload_raw).hexdigest(),
        "validator_key_id": active["validation_authority"]["key_id"],
        "issued_at_ns": V2_FREEZE_VALIDATOR_NS,
    }
    freeze_validator = _signed_raw(
        freeze_validator_payload,
        schema=GOVERNANCE_V2_FREEZE_VALIDATOR_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_FREEZE_VALIDATOR_MEDIA_TYPE,
        domain=GOVERNANCE_V2_FREEZE_VALIDATOR_DOMAIN,
        key=validator_key,
    )
    return {
        "root_key": root_key,
        "keys": keys,
        "key_by_id": key_by_id,
        "records": records,
        "active": active,
        "genesis": genesis,
        "genesis_payload": genesis_payload,
        "campaign_root": campaign_root,
        "epochs": epochs,
        "epoch_payload": epoch_payload,
        "epoch_payloads": epoch_payloads,
        "current_epoch": current_epoch,
        "epoch_hash": epoch_hash,
        "pops": pops,
        "entry": entry,
        "entry_payload": entry_payload,
        "entry_hash": entry_hash,
        "failure_registries": failure_registries,
        "freeze_authority": freeze_authority,
        "freeze_payload": freeze_payload,
        "freeze_validator": freeze_validator,
        "freeze_validator_payload": freeze_validator_payload,
    }


def _verify_v2(bundle: dict[str, Any]) -> dict[str, Any]:
    return verify_governance_v2(
        genesis_envelope=bundle["genesis"],
        registry_epoch_envelopes=bundle["epochs"],
        role_pop_envelopes=bundle["pops"],
        evaluation_entry_envelope=bundle["entry"],
        freeze_authority_envelope=bundle["freeze_authority"],
        freeze_validator_envelope=bundle["freeze_validator"],
        pinned_offline_root_public_key=bundle["root_key"][1],
    )


def test_governance_v2_derives_and_verifies_success_with_zero_authority() -> None:
    bundle = _v2_bundle()
    derived = derive_governance_v2(
        genesis_envelope=bundle["genesis"],
        registry_epoch_envelopes=bundle["epochs"],
        role_pop_envelopes=bundle["pops"],
        evaluation_entry_envelope=bundle["entry"],
        pinned_offline_root_public_key=bundle["root_key"][1],
    )
    assert derived["decision"] == "GOVERNANCE_V2_DERIVED_RESEARCH_ONLY"
    assert derived["gate_count"] == 16
    assert derived["role_pop_count"] == len(GOVERNANCE_V2_REQUIRED_ROLES)
    _assert_zero_authority(derived)

    verified = _verify_v2(bundle)
    assert verified["decision"] == "GOVERNANCE_V2_VERIFIED_RESEARCH_ONLY"
    assert "PASS" not in verified["decision"]
    _assert_zero_authority(verified)


def test_governance_v2_accepts_monotonic_authority_rotation() -> None:
    def rotate_authority(records: list[dict[str, Any]], keys: dict[str, Key]) -> None:
        old = next(row for row in records if row["role"] == "evaluation_authority")
        old["status"] = "REVOKED"
        old["invalidate_from_ns"] = "2600"
        replacement = _key(260)
        keys["evaluation-authority-rotation"] = replacement
        records.append(_v2_key_record("evaluation_authority", replacement))

    result = _verify_v2(_v2_bundle(second_epoch_mutation=rotate_authority))
    assert result["decision"] == "GOVERNANCE_V2_VERIFIED_RESEARCH_ONLY"
    assert result["registry_epoch"] == 1
    _assert_zero_authority(result)


def test_governance_v2_rejects_missing_role_pop() -> None:
    bundle = _v2_bundle()
    del bundle["pops"]["trace_attestor"]
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_POP_INVALID"


@pytest.mark.parametrize("alias_kind", ["custodian", "principal_cross_custodian"])
def test_governance_v2_rejects_principal_and_custodian_aliasing(alias_kind: str) -> None:
    bundle = _v2_bundle()
    payload = copy.deepcopy(bundle["epoch_payload"])
    if alias_kind == "custodian":
        payload["keys"][1]["custodian_id"] = payload["keys"][0]["custodian_id"]
    else:
        payload["keys"][1]["custodian_id"] = payload["keys"][0]["principal_id"]
    bundle["epochs"][0] = _signed_raw(
        payload,
        schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
        domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        key=bundle["keys"]["registry_custodian"],
    )
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_REGISTRY_INVALID"


def test_governance_v2_derives_every_key_id_from_public_key_bytes() -> None:
    bundle = _v2_bundle()
    payload = copy.deepcopy(bundle["epoch_payload"])
    payload["keys"][0]["key_id"] = f"ed25519-sha256:{'0' * 64}"
    payload["keys"].sort(key=lambda record: (record["role"], record["key_id"]))
    bundle["epochs"][0] = _signed_raw(
        payload,
        schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
        domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        key=bundle["keys"]["registry_custodian"],
    )
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_REGISTRY_INVALID"


def test_governance_v2_rejects_reused_role_key_bytes() -> None:
    def reuse_key(records: list[dict[str, Any]], _keys: dict[str, Key]) -> None:
        source = next(row for row in records if row["role"] == "collector_a")
        target = next(row for row in records if row["role"] == "collector_b")
        target["public_key"] = copy.deepcopy(source["public_key"])
        target["key_id"] = source["key_id"]

    result = _verify_v2(_v2_bundle(epoch_mutation=reuse_key))
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_REGISTRY_INVALID"


def test_governance_v2_rejects_stale_registrar_at_entry_issuance() -> None:
    def make_stale(records: list[dict[str, Any]], _keys: dict[str, Key]) -> None:
        record = next(row for row in records if row["role"] == "registrar")
        record["valid_until_ns"] = "3500"

    result = _verify_v2(_v2_bundle(epoch_mutation=make_stale))
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID"


@pytest.mark.parametrize("status", ["REVOKED", "COMPROMISED"])
def test_governance_v2_rejects_invalidated_registry_signer_at_issuance(status: str) -> None:
    def invalidate_custodian(records: list[dict[str, Any]], keys: dict[str, Key]) -> None:
        old = next(row for row in records if row["role"] == "registry_custodian")
        old["status"] = status
        old["invalidate_from_ns"] = "1900"
        replacement = _key(250 if status == "REVOKED" else 251)
        keys[f"replacement-{status}"] = replacement
        records.append(_v2_key_record("registry_custodian", replacement))

    result = _verify_v2(_v2_bundle(epoch_mutation=invalidate_custodian))
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_REGISTRY_INVALID"


def test_governance_v2_rejects_broken_predecessor_chain() -> None:
    bundle = _v2_bundle()
    payload = copy.deepcopy(bundle["epoch_payload"])
    payload["predecessor_epoch_hash"] = "0" * 64
    bundle["epochs"][0] = _signed_raw(
        payload,
        schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
        domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        key=bundle["keys"]["registry_custodian"],
    )
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_REGISTRY_INVALID"


def test_governance_v2_rejects_entry_bound_to_old_registry_epoch() -> None:
    bundle = _v2_bundle()
    epoch_one_payload = copy.deepcopy(bundle["epoch_payload"])
    epoch_one_payload["epoch"] = 1
    epoch_one_payload["predecessor_epoch_hash"] = bundle["epoch_hash"]
    epoch_one_payload["issued_at_ns"] = "2500"
    epoch_one = _signed_raw(
        epoch_one_payload,
        schema=GOVERNANCE_V2_REGISTRY_EPOCH_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_REGISTRY_EPOCH_MEDIA_TYPE,
        domain=GOVERNANCE_V2_REGISTRY_EPOCH_DOMAIN,
        key=bundle["keys"]["registry_custodian"],
    )
    bundle["epochs"].append(epoch_one)
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID"


@pytest.mark.parametrize("mutation", ["attempt", "dag_cycle", "legacy_schema", "float"])
def test_governance_v2_rejects_unregistered_attempt_dag_and_schema(mutation: str) -> None:
    def mutate(entry: dict[str, Any]) -> None:
        if mutation == "attempt":
            entry["attempt"] = 1
        elif mutation == "dag_cycle":
            entry["gate_dag"][2]["direct_dependencies"] = [
                entry["gate_dag"][2]["gate_id"]
            ]
        elif mutation == "legacy_schema":
            entry["schema_version"] = "ptcg.governance.evaluation-entry/v1"
        else:
            entry["gate_dag"][0]["unexpected_float"] = 1.5

    bundle = _v2_bundle(entry_mutation=mutate)
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_EVALUATION_ENTRY_INVALID"


def test_governance_v2_rejects_retrospective_evaluation_insertion() -> None:
    bundle = _v2_bundle()
    payload = copy.deepcopy(bundle["freeze_payload"])
    payload["freeze_at_ns"] = V2_ENTRY_NS
    bundle["freeze_authority"] = _signed_raw(
        payload,
        schema=GOVERNANCE_V2_FREEZE_ENVELOPE_SCHEMA,
        media_type=GOVERNANCE_V2_FREEZE_MEDIA_TYPE,
        domain=GOVERNANCE_V2_FREEZE_DOMAIN,
        key=bundle["key_by_id"][bundle["active"]["evaluation_authority"]["key_id"]],
    )
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_FREEZE_INVALID"


@pytest.mark.parametrize("mutation", ["forged", "base64", "hash"])
def test_governance_v2_rejects_forged_or_noncanonical_genesis_bytes(mutation: str) -> None:
    bundle = _v2_bundle()
    envelope = json.loads(bundle["genesis"])
    if mutation == "forged":
        envelope["signature_ed25519_base64"] = base64.b64encode(bytes(64)).decode()
    elif mutation == "base64":
        envelope["payload"]["base64"] += "\n"
    else:
        envelope["payload"]["sha256"] = "0" * 64
    bundle["genesis"] = canonical_json_bytes(envelope)
    result = _verify_v2(bundle)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_GENESIS_INVALID"


def _wire_bundle(
    governance: dict[str, Any],
    *,
    gate_index: int = 0,
    authority_mutation: Mutation | None = None,
    artifact_path: str = "evidence/input.bin",
    artifact_bytes: bytes = b"exact evidence bytes",
) -> dict[str, Any]:
    gate = governance["entry_payload"]["gate_dag"][gate_index]
    transitive_dependencies = [
        {
            "gate_id": gate_id,
            "bundle_sha256": _hash(f"{gate_id}:bundle"),
            "authority_payload_sha256": _hash(f"{gate_id}:authority-payload"),
            "decision": PASS_DECISION,
        }
        for gate_id in GOVERNANCE_V2_GATE_IDS[:gate_index]
    ]
    transitive_dependency_edges = [
        {
            "gate_id": GOVERNANCE_V2_GATE_IDS[index],
            "dependency_gate_id": GOVERNANCE_V2_GATE_IDS[index - 1],
        }
        for index in range(1, gate_index + 1)
    ]
    direct_dependencies = (
        [] if gate_index == 0 else [copy.deepcopy(transitive_dependencies[-1])]
    )
    content = encode_byte_evidence(artifact_bytes, media_type="application/octet-stream")
    entries = [
        {
            "artifact_id": "input-evidence",
            "path": artifact_path,
            "decoded_length": content["decoded_length"],
            "sha256": content["sha256"],
            "media_type": content["media_type"],
        }
    ]
    manifest = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA,
        "evaluation_entry_hash": governance["entry_hash"],
        "evaluation_id": governance["entry_payload"]["evaluation_id"],
        "evaluation_nonce": governance["entry_payload"]["evaluation_nonce"],
        "gate_id": gate["gate_id"],
        "attempt": 0,
        "issued_at_ns": V2_MANIFEST_NS,
        "entries": entries,
        "merkle_root": evidence_merkle_root(entries),
    }
    manifest_raw = canonical_json_bytes(manifest)
    manifest_wrapper = encode_byte_evidence(manifest_raw, media_type=MANIFEST_MEDIA_TYPE)
    authority_payload = {
        "schema_version": AUTHORITY_PAYLOAD_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": governance["campaign_root"],
        "freeze_registry_epoch": governance["current_epoch"],
        "freeze_registry_hash": governance["epoch_hash"],
        "evaluation_entry_hash": governance["entry_hash"],
        "evaluation_id": governance["entry_payload"]["evaluation_id"],
        "evaluation_nonce": governance["entry_payload"]["evaluation_nonce"],
        "gate_id": gate["gate_id"],
        "attempt": 0,
        "frozen_spec_hash": gate["frozen_spec_hash"],
        "input_schema_hash": gate["input_schema_hash"],
        "output_schema_hash": gate["output_schema_hash"],
        "failure_code_registry_hash": gate["failure_code_registry_hash"],
        "evidence_manifest_envelope_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "evidence_manifest_root": manifest["merkle_root"],
        "verifier_bundle_digest": gate["verifier_module_hash"],
        "verifier_runtime_digest": gate["verifier_runtime_hash"],
        "direct_dependencies": direct_dependencies,
        "dependency_closure_root": dependency_closure_root(
            transitive_dependencies,
            transitive_dependency_edges,
            current_gate_id=gate["gate_id"],
        ),
        "input_bundle_root": _hash("input-bundle-root"),
        "recomputed_outputs": {"artifact_count": 1},
        "decision": PASS_DECISION,
        "failure_codes": [],
        "issued_at_ns": V2_AUTHORITY_NS,
    }
    if authority_mutation is not None:
        authority_mutation(authority_payload)
    evaluation_key = governance["key_by_id"][
        governance["active"]["evaluation_authority"]["key_id"]
    ]
    authority = _signed_raw(
        authority_payload,
        schema=AUTHORITY_ENVELOPE_SCHEMA,
        media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
        domain=AUTHORITY_DOMAIN,
        key=evaluation_key,
    )
    authority_payload_raw = canonical_json_bytes(authority_payload)
    validator_payload = {
        "schema_version": VALIDATOR_PAYLOAD_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": authority_payload["campaign_root"],
        "validation_registry_epoch": governance["current_epoch"],
        "validation_registry_hash": governance["epoch_hash"],
        "evaluation_id": authority_payload["evaluation_id"],
        "evaluation_nonce": authority_payload["evaluation_nonce"],
        "gate_id": authority_payload["gate_id"],
        "attempt": authority_payload["attempt"],
        "authority_envelope_sha256": hashlib.sha256(authority).hexdigest(),
        "authority_envelope_decoded_length": len(authority),
        "authority_payload_sha256": hashlib.sha256(authority_payload_raw).hexdigest(),
        "input_bundle_root": authority_payload["input_bundle_root"],
        "verifier_bundle_digest": authority_payload["verifier_bundle_digest"],
        "verifier_runtime_digest": authority_payload["verifier_runtime_digest"],
        "validator_recomputed_outputs_sha256": canonical_sha256(
            authority_payload["recomputed_outputs"]
        ),
        "validator_failure_codes_sha256": canonical_sha256(
            authority_payload["failure_codes"]
        ),
        "decision": authority_payload["decision"],
        "issued_at_ns": V2_VALIDATOR_NS,
    }
    validator_key = governance["key_by_id"][
        governance["active"]["validation_authority"]["key_id"]
    ]
    validator = _signed_raw(
        validator_payload,
        schema=VALIDATOR_ENVELOPE_SCHEMA,
        media_type=VALIDATOR_PAYLOAD_MEDIA_TYPE,
        domain=VALIDATOR_DOMAIN,
        key=validator_key,
    )
    return {
        "authority": authority,
        "validator": validator,
        "manifest_wrapper": manifest_wrapper,
        "artifacts": [
            {"artifact_id": "input-evidence", "path": artifact_path, "content": content}
        ],
        "transitive_dependencies": transitive_dependencies,
        "transitive_dependency_edges": transitive_dependency_edges,
        "failure_registry": governance["failure_registries"][gate["gate_id"]],
    }


def _verify_wire(governance: dict[str, Any], wire: dict[str, Any]) -> dict[str, Any]:
    return verify_exact_gate_v2_governance(
        genesis_envelope=governance["genesis"],
        registry_epoch_envelopes=governance["epochs"],
        role_pop_envelopes=governance["pops"],
        evaluation_entry_envelope=governance["entry"],
        freeze_authority_envelope=governance["freeze_authority"],
        freeze_validator_envelope=governance["freeze_validator"],
        exact_gate_authority_envelope=wire["authority"],
        exact_gate_validator_envelope=wire["validator"],
        evidence_manifest_wrapper=wire["manifest_wrapper"],
        supplied_artifacts=wire["artifacts"],
        transitive_dependencies=wire["transitive_dependencies"],
        transitive_dependency_edges=wire["transitive_dependency_edges"],
        failure_code_registry_raw=wire["failure_registry"],
        pinned_offline_root_public_key=governance["root_key"][1],
    )


def test_exact_gate_v2_wire_is_bound_without_accepting_signed_pass_authority() -> None:
    governance = _v2_bundle()
    result = _verify_wire(governance, _wire_bundle(governance))
    assert result["decision"] == "EXACT_GATE_V2_GOVERNANCE_BOUND_RESEARCH_ONLY"
    assert "PASS" not in result["decision"]
    assert result["artifact_count"] == 1
    assert result["dependency_node_count"] == 0
    _assert_zero_authority(result)


def test_exact_gate_v2_g01_wire_binds_registered_transitive_dag() -> None:
    governance = _v2_bundle()
    result = _verify_wire(governance, _wire_bundle(governance, gate_index=1))
    assert result["decision"] == "EXACT_GATE_V2_GOVERNANCE_BOUND_RESEARCH_ONLY"
    assert result["gate_id"] == "G01_CONSTITUTION_AND_CODE_FREEZE"
    assert result["dependency_node_count"] == 1
    _assert_zero_authority(result)


@pytest.mark.parametrize("mutation", ["nonce", "attempt", "gate", "closure"])
def test_exact_gate_v2_wire_rejects_unregistered_nonce_attempt_gate_and_closure(mutation: str) -> None:
    governance = _v2_bundle()

    def mutate(payload: dict[str, Any]) -> None:
        if mutation == "nonce":
            payload["evaluation_nonce"] = _hash("unregistered-nonce")
        elif mutation == "attempt":
            payload["attempt"] = 1
        elif mutation == "gate":
            payload["gate_id"] = "G00_NOT_REGISTERED"
        else:
            payload["dependency_closure_root"] = _hash("arbitrary-closure-root")

    result = _verify_wire(governance, _wire_bundle(governance, authority_mutation=mutate))
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_WIRE_INVALID"
    _assert_zero_authority(result)


def test_exact_gate_v2_wire_rejects_private_key_artifact_kind() -> None:
    governance = _v2_bundle()
    wire = _wire_bundle(
        governance,
        artifact_path="keys/private.pem",
        artifact_bytes=b"-----BEGIN PRIVATE KEY-----\n",
    )
    result = _verify_wire(governance, wire)
    assert result["decision"] == "GOVERNANCE_V2_REJECTED"
    assert result["fail_code"] == "GOVERNANCE_V2_WIRE_INVALID"
    _assert_zero_authority(result)
