from __future__ import annotations

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.exact_gate import (
    EXACT_GATE_COUNTERSIGNATURE_SCHEMA,
    EXACT_GATE_PAYLOAD_SCHEMA,
    ExactGateError,
    PASS_DECISION,
    decode_byte_evidence,
    derive_countersignature_payload,
    derive_exact_gate_payload,
    encode_byte_evidence,
    verify_exact_gate_dual_signature,
)


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _hash(seed: int) -> str:
    return f"{seed:064x}"


def _envelope(schema: str, payload: dict[str, object], private: Ed25519PrivateKey, public: bytes) -> dict[str, object]:
    digest = canonical_sha256(payload)
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, digest)),
    )


def _fixture() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    authority_private, authority_public = _key(1)
    validator_private, validator_public = _key(2)
    kwargs: dict[str, object] = {
        "campaign_root": _hash(1),
        "evaluation_id": "campaign-2026-07-14",
        "gate_id": "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE",
        "frozen_spec_hash": _hash(2),
        "dependency_roots": [
            {"gate_id": "G00_TRUST_ROOTS", "result_root": _hash(3)},
            {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "result_root": _hash(4)},
        ],
        "campaign_registry_hash": _hash(5),
        "evidence_manifest_root": _hash(6),
        "verifier_module_digest": _hash(7),
        "recomputed_outputs": {"claim_count": 1, "acyclic": True},
        "decision": PASS_DECISION,
        "failure_codes": [],
    }
    payload = derive_exact_gate_payload(**kwargs)  # type: ignore[arg-type]
    authority_envelope = _envelope(
        EXACT_GATE_PAYLOAD_SCHEMA, payload, authority_private, authority_public
    )
    countersignature_payload = derive_countersignature_payload(authority_envelope)
    countersignature_envelope = _envelope(
        EXACT_GATE_COUNTERSIGNATURE_SCHEMA,
        countersignature_payload,
        validator_private,
        validator_public,
    )
    verify_kwargs = {
        "authority_envelope": authority_envelope,
        "countersignature_envelope": countersignature_envelope,
        "authority_public_key": authority_public,
        "validator_public_key": validator_public,
        **{f"expected_{key}": value for key, value in kwargs.items() if key not in {"recomputed_outputs", "decision", "failure_codes"}},
        "recomputed_outputs": kwargs["recomputed_outputs"],
        "expected_decision": kwargs["decision"],
        "expected_failure_codes": kwargs["failure_codes"],
    }
    return authority_envelope, countersignature_envelope, verify_kwargs


def test_byte_evidence_round_trip_and_metadata_binding() -> None:
    wrapped = encode_byte_evidence(b"exact bytes\x00", media_type="application/octet-stream")
    assert decode_byte_evidence(
        wrapped,
        expected_media_type="application/octet-stream",
        expected_sha256=wrapped["sha256"],
    ) == b"exact bytes\x00"

    for field, replacement in (
        ("decoded_length", 1),
        ("sha256", _hash(99)),
        ("media_type", "text/plain"),
        ("base64", "not canonical"),
    ):
        mutated = dict(wrapped)
        mutated[field] = replacement
        with pytest.raises(ExactGateError):
            decode_byte_evidence(
                mutated,
                expected_media_type="application/octet-stream",
                expected_sha256=wrapped["sha256"],
            )


def test_exact_gate_v1_dual_signature_is_permanently_retired() -> None:
    authority_envelope, countersignature_envelope, kwargs = _fixture()
    with pytest.raises(ExactGateError, match="v1 is retired"):
        verify_exact_gate_dual_signature(**kwargs)  # type: ignore[arg-type]

    mutated = dict(kwargs)
    mutated["recomputed_outputs"] = {"claim_count": 1, "acyclic": False}
    with pytest.raises(ExactGateError, match="v1 is retired"):
        verify_exact_gate_dual_signature(**mutated)  # type: ignore[arg-type]


def test_wrong_countersignature_and_signature_replay_fail() -> None:
    authority_envelope, countersignature_envelope, kwargs = _fixture()
    wrong_private, wrong_public = _key(3)
    payload = derive_countersignature_payload(authority_envelope)
    wrong = _envelope(
        EXACT_GATE_COUNTERSIGNATURE_SCHEMA, payload, wrong_private, wrong_public
    )
    with pytest.raises(ValueError):
        verify_exact_gate_dual_signature(
            **{**kwargs, "countersignature_envelope": wrong}  # type: ignore[arg-type]
        )

    replayed = deepcopy(countersignature_envelope)
    replayed["payload"]["gate_id"] = "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION"  # type: ignore[index]
    with pytest.raises(ValueError):
        verify_exact_gate_dual_signature(
            **{**kwargs, "countersignature_envelope": replayed}  # type: ignore[arg-type]
        )


def test_private_material_and_capability_claims_are_rejected() -> None:
    base = dict(
        campaign_root=_hash(1),
        evaluation_id="campaign",
        gate_id="G00_TRUST_ROOTS",
        frozen_spec_hash=_hash(2),
        dependency_roots=[],
        campaign_registry_hash=_hash(3),
        evidence_manifest_root=_hash(4),
        verifier_module_digest=_hash(5),
        decision=PASS_DECISION,
        failure_codes=[],
    )
    for output in (
        {"private_key": "forbidden"},
        {"nested": {"submission_authorized": True}},
    ):
        with pytest.raises(ExactGateError):
            derive_exact_gate_payload(recomputed_outputs=output, **base)


def test_dependency_and_failure_code_canonicalization_is_fail_closed() -> None:
    common = dict(
        campaign_root=_hash(1),
        evaluation_id="campaign",
        gate_id="G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE",
        frozen_spec_hash=_hash(2),
        campaign_registry_hash=_hash(3),
        evidence_manifest_root=_hash(4),
        verifier_module_digest=_hash(5),
        recomputed_outputs={},
        decision=PASS_DECISION,
        failure_codes=[],
    )
    with pytest.raises(ExactGateError, match="sorted"):
        derive_exact_gate_payload(
            dependency_roots=[
                {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "result_root": _hash(7)},
                {"gate_id": "G00_TRUST_ROOTS", "result_root": _hash(6)},
            ],
            **common,
        )
    with pytest.raises(ExactGateError, match="failure codes"):
        derive_exact_gate_payload(
            dependency_roots=[],
            failure_codes=["IMPOSSIBLE_PASS"],
            **{key: value for key, value in common.items() if key != "failure_codes"},
        )
