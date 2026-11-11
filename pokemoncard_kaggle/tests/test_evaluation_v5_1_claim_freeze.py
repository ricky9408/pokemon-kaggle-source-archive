from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.claim_freeze import (
    COUNTERSIGNATURE_SCHEMA,
    DECISION,
    VALIDATOR_MEDIA_TYPE,
    build_normative_claim_evidence,
    derive_claim_freeze_audit,
    verify_claim_freeze,
    wrap_canonical_bytes,
)
from evaluation_v5_1.envelope import build_envelope, signing_payload


FREEZE_TIME = "2026-07-14T00:04:00.000000Z"
COUNTERSIGN_TIME = "2026-07-14T00:05:00.000000Z"


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return (
        private,
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def _role(identity: str, public: bytes) -> dict[str, object]:
    return {
        "identity": identity,
        "key_id": f"{identity}:{hashlib.sha256(public).hexdigest()[:16]}",
        "algorithm": "Ed25519",
        "public_key_ed25519_base64": base64.b64encode(public).decode("ascii"),
        "valid_from_utc": "2026-07-01T00:00:00.000000Z",
        "valid_until_utc": "2026-08-01T00:00:00.000000Z",
        "revoked": False,
    }


def _signed(schema: str, payload: dict[str, object], private: Ed25519PrivateKey, public: bytes) -> dict[str, object]:
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _document(evidence: dict[str, object], evidence_id: str) -> dict[str, object]:
    wrapper = evidence[evidence_id]
    assert isinstance(wrapper, dict)
    return json.loads(base64.b64decode(wrapper["base64"]).decode("utf-8"))


def _replace_document(evidence: dict[str, object], evidence_id: str, document: dict[str, object]) -> None:
    evidence[evidence_id] = wrap_canonical_bytes(
        canonical_json_bytes(document), media_type="application/jcs+json"
    )
    if evidence_id == "claim_manifest":
        return
    manifest = _document(evidence, "claim_manifest")
    for descriptor in manifest["documents"]:
        if descriptor["evidence_id"] == evidence_id:
            wrapper = evidence[evidence_id]
            assert isinstance(wrapper, dict)
            descriptor["sha256"] = wrapper["sha256"]
            descriptor["decoded_length"] = wrapper["decoded_length"]
            descriptor["media_type"] = wrapper["media_type"]
            break
    else:
        raise AssertionError(f"missing descriptor for {evidence_id}")
    _replace_document(evidence, "claim_manifest", manifest)


def _counter_payload(authority_envelope: object, campaign_root: str) -> dict[str, object]:
    authority_bytes = canonical_json_bytes(authority_envelope)
    return {
        "schema": COUNTERSIGNATURE_SCHEMA,
        "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "gate_id": "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE",
        "campaign_root_sha256": campaign_root,
        "authority_envelope_sha256": hashlib.sha256(authority_bytes).hexdigest(),
        "authority_envelope_jcs": wrap_canonical_bytes(
            authority_bytes, media_type="application/jcs+json"
        ),
        "countersigned_at_utc": COUNTERSIGN_TIME,
    }


def _fixture(campaign_root: str = "a" * 64) -> dict[str, object]:
    authority_private, authority_public = _keypair()
    validator_private, validator_public = _keypair()
    roles = {
        "evaluation_authority": _role("evaluation-authority", authority_public),
        "independent_validator": _role("independent-validator", validator_public),
    }
    validator_artifact = b"frozen validator module bytes v1"
    roots = {
        "campaign_root_sha256": campaign_root,
        "campaign_created_at_utc": "2026-07-14T00:00:00.000000Z",
        "g00_root_sha256": "b" * 64,
        "g00_frozen_at_utc": "2026-07-14T00:01:00.000000Z",
        "g01_root_sha256": "c" * 64,
        "g01_frozen_at_utc": "2026-07-14T00:02:00.000000Z",
        "frozen_spec_sha256": "d" * 64,
        "spec_frozen_at_utc": "2026-07-14T00:03:00.000000Z",
        "campaign_registry_sha256": "e" * 64,
        "validator_artifact_sha256": hashlib.sha256(validator_artifact).hexdigest(),
    }
    evidence = build_normative_claim_evidence(
        dependency_roots=roots,
        trusted_role_registry=roles,
        freeze_time_utc=FREEZE_TIME,
        validator_artifact=validator_artifact,
    )
    audit = derive_claim_freeze_audit(
        dependency_roots=roots,
        trusted_role_registry=roles,
        evidence_blobs=evidence,
        finalized_at_utc=FREEZE_TIME,
    )
    assert audit["decision"] == DECISION
    authority = _signed("evaluation_v5_1_g07_final_gate_v1", audit, authority_private, authority_public)
    counter = _signed(
        COUNTERSIGNATURE_SCHEMA,
        _counter_payload(authority, campaign_root),
        validator_private,
        validator_public,
    )
    return {
        "roots": roots,
        "roles": roles,
        "evidence": evidence,
        "authority_private": authority_private,
        "authority_public": authority_public,
        "validator_private": validator_private,
        "validator_public": validator_public,
        "authority": authority,
        "counter": counter,
    }


def _verify(fixture: dict[str, object]) -> dict[str, object]:
    return verify_claim_freeze(
        dependency_roots=fixture["roots"],
        trusted_role_registry=fixture["roles"],
        evidence_blobs=fixture["evidence"],
        finalized_at_utc=FREEZE_TIME,
        final_authority_envelope=fixture["authority"],
        final_validator_countersignature_envelope=fixture["counter"],
    )


def _assert_closed(result: dict[str, object]) -> None:
    assert result["decision"] == "FAIL_CLOSED"
    assert result["authority"] is False
    assert result["candidate_development_authorized"] is False
    assert result["sealed_holdout_access_authorized"] is False
    assert result["release_authorized"] is False
    assert result["submission_authorized"] is False
    assert result["failure_codes"]


def test_honest_dual_signed_claim_freeze_passes_zero_authority() -> None:
    result = _verify(_fixture())
    assert result["decision"] == DECISION
    assert result["failure_codes"] == []
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    assert result["recomputed_outputs"]["producer_pass_flags_authoritative"] is False
    assert result["validator_artifact_sha256"]


def test_wrong_dependency_roots_and_chronology_fail_closed() -> None:
    fixture = _fixture()
    roots = deepcopy(fixture["roots"])
    roots["g01_root_sha256"] = "e" * 64
    fixture["roots"] = roots
    _assert_closed(_verify(fixture))

    fixture = _fixture()
    roots = deepcopy(fixture["roots"])
    roots["spec_frozen_at_utc"] = "2026-07-14T00:05:00.000000Z"
    fixture["roots"] = roots
    _assert_closed(_verify(fixture))


def test_validator_artifact_and_campaign_registry_are_g01_g00_pinned() -> None:
    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    evidence["validator_artifact"] = wrap_canonical_bytes(
        b"different validator bytes", media_type=VALIDATOR_MEDIA_TYPE
    )
    manifest = _document(evidence, "claim_manifest")
    for descriptor in manifest["documents"]:
        if descriptor["evidence_id"] == "validator_artifact":
            descriptor.update(
                {
                    "sha256": evidence["validator_artifact"]["sha256"],
                    "decoded_length": evidence["validator_artifact"]["decoded_length"],
                    "media_type": evidence["validator_artifact"]["media_type"],
                }
            )
    _replace_document(evidence, "claim_manifest", manifest)
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert "G01-pinned validator digest" in result["failure_codes"][0]["detail"]

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    role_registry = _document(evidence, "role_registry")
    role_registry["campaign_registry_sha256"] = "f" * 64
    _replace_document(evidence, "role_registry", role_registry)
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))


def test_role_key_ids_must_be_distinct() -> None:
    fixture = _fixture()
    roles = deepcopy(fixture["roles"])
    roles["independent_validator"]["key_id"] = roles["evaluation_authority"]["key_id"]
    fixture["roles"] = roles
    _assert_closed(_verify(fixture))


def test_cycle_undeclared_and_hidden_claims_fail_closed() -> None:
    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    graph = _document(evidence, "dependency_graph")
    graph["claims"][3]["depends_on"] = ["C01_PRIMARY_TRANSFER_EFFECT"]
    _replace_document(evidence, "dependency_graph", graph)
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert result["failure_codes"][0]["code"] == "G07_CLAIM_DEPENDENCY_CYCLE"

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    graph = _document(evidence, "dependency_graph")
    graph["claims"][0]["depends_on"].append("C99_UNDECLARED")
    _replace_document(evidence, "dependency_graph", graph)
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert result["failure_codes"][0]["code"] == "G07_UNDECLARED_CLAIM_REFERENCE"

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    manifest = _document(evidence, "claim_manifest")
    manifest["claims"].append(
        {"claim_id": "C99_HIDDEN", "kind": "hidden", "normative_text": "no", "depends_on": []}
    )
    _replace_document(evidence, "claim_manifest", manifest)
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))


def test_threshold_multiplicity_exclusion_and_producer_flag_mutations_fail_closed() -> None:
    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    thresholds = _document(evidence, "thresholds")
    thresholds["required_successes"] = 14
    _replace_document(evidence, "thresholds", thresholds)
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    multiplicity = _document(evidence, "multiplicity_correction")
    multiplicity["allocations"][0]["alpha"] = "0.030000000000"
    _replace_document(evidence, "multiplicity_correction", multiplicity)
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert result["failure_codes"][0]["code"] == "G07_MULTIPLICITY_INVALID"

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    exclusions = _document(evidence, "exclusions")
    exclusions["excluded_partitions"] = ["DEV_BURNED", "SEALED_50"]
    _replace_document(evidence, "exclusions", exclusions)
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert result["failure_codes"][0]["code"] == "G07_EXCLUSION_POLICY_MUTATED"

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    requirements = _document(evidence, "evidence_requirements")
    requirements["producer_pass_flags_authoritative"] = True
    _replace_document(evidence, "evidence_requirements", requirements)
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))


def test_stale_revoked_and_wrong_signer_are_rejected() -> None:
    fixture = _fixture()
    roles = deepcopy(fixture["roles"])
    roles["evaluation_authority"]["valid_until_utc"] = "2026-07-14T00:03:00.000000Z"
    fixture["roles"] = roles
    _assert_closed(_verify(fixture))

    fixture = _fixture()
    roles = deepcopy(fixture["roles"])
    roles["independent_validator"]["revoked"] = True
    fixture["roles"] = roles
    _assert_closed(_verify(fixture))

    fixture = _fixture()
    other_private, other_public = _keypair()
    audit = derive_claim_freeze_audit(
        dependency_roots=fixture["roots"],
        trusted_role_registry=fixture["roles"],
        evidence_blobs=fixture["evidence"],
        finalized_at_utc=FREEZE_TIME,
    )
    bad_authority = _signed("evaluation_v5_1_g07_final_gate_v1", audit, other_private, other_public)
    fixture["authority"] = bad_authority
    fixture["counter"] = _signed(
        COUNTERSIGNATURE_SCHEMA,
        _counter_payload(bad_authority, fixture["roots"]["campaign_root_sha256"]),
        fixture["validator_private"],
        fixture["validator_public"],
    )
    _assert_closed(_verify(fixture))


def test_malformed_base64_and_byte_mutation_are_rejected() -> None:
    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    evidence["population"]["base64"] = "%%%"
    fixture["evidence"] = evidence
    result = _verify(fixture)
    _assert_closed(result)
    assert result["failure_codes"][0]["code"] == "G07_MALFORMED_BYTE_EVIDENCE"

    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    wrapper = evidence["validator_artifact"]
    raw = base64.b64decode(wrapper["base64"])
    wrapper["base64"] = base64.b64encode(raw + b"!").decode("ascii")
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))


def test_signature_replay_and_signed_false_decision_do_not_bypass_recomputation() -> None:
    original = _fixture("a" * 64)
    replay_target = _fixture("f" * 64)
    replay_target["authority"] = original["authority"]
    replay_target["counter"] = original["counter"]
    _assert_closed(_verify(replay_target))

    fixture = _fixture()
    audit = derive_claim_freeze_audit(
        dependency_roots=fixture["roots"],
        trusted_role_registry=fixture["roles"],
        evidence_blobs=fixture["evidence"],
        finalized_at_utc=FREEZE_TIME,
    )
    false_payload = deepcopy(audit)
    false_payload["decision"] = "FAIL_CLOSED"
    false_payload["failure_codes"] = [{"code": "PRODUCER_FALSE", "detail": "signed but irrelevant"}]
    authority = _signed(
        "evaluation_v5_1_g07_final_gate_v1",
        false_payload,
        fixture["authority_private"],
        fixture["authority_public"],
    )
    fixture["authority"] = authority
    fixture["counter"] = _signed(
        COUNTERSIGNATURE_SCHEMA,
        _counter_payload(authority, fixture["roots"]["campaign_root_sha256"]),
        fixture["validator_private"],
        fixture["validator_public"],
    )
    _assert_closed(_verify(fixture))


def test_validator_artifact_media_type_is_exact() -> None:
    fixture = _fixture()
    evidence = deepcopy(fixture["evidence"])
    wrapper = evidence["validator_artifact"]
    assert wrapper["media_type"] == VALIDATOR_MEDIA_TYPE
    wrapper["media_type"] = "application/octet-stream"
    fixture["evidence"] = evidence
    _assert_closed(_verify(fixture))
