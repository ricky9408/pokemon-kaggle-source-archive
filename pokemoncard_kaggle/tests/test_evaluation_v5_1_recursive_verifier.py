from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1 import recursive_verifier
from evaluation_v5_1.canonical import canonical_json_bytes
from evaluation_v5_1.exact_gate_v2 import (
    AUTHORITY_ENVELOPE_SCHEMA,
    AUTHORITY_DOMAIN,
    AUTHORITY_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_MEDIA_TYPE,
    ExactGateV2Error,
    FINAL_BUNDLE_SCHEMA,
    VALIDATOR_ENVELOPE_SCHEMA,
    VALIDATOR_MEDIA_TYPE,
    VALIDATOR_PAYLOAD_MEDIA_TYPE,
    encode_byte_evidence,
    signature_message,
    verify_signed_payload_envelope,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _envelope(*, schema: str, media_type: str, payload: dict[str, object]) -> bytes:
    return canonical_json_bytes(
        {
            "schema_version": schema,
            "signer_key_id": f"ed25519-sha256:{_hash(schema)}",
            "payload": encode_byte_evidence(canonical_json_bytes(payload), media_type=media_type),
            "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )


def _bundle(gate_id: str, direct_dependencies: list[dict[str, object]], *, decision: str = "PASS_RESEARCH_ONLY", failure_codes: list[str] | None = None, outputs: dict[str, object] | None = None) -> bytes:
    payload = {
        "gate_id": gate_id,
        "campaign_root": _hash("campaign"),
        "evaluation_id": "evaluation-20260714",
        "evaluation_nonce": _hash("nonce"),
        "attempt": 0,
        "direct_dependencies": direct_dependencies,
        "input_bundle_root": _hash(f"input:{gate_id}"),
        "verifier_bundle_digest": _hash(f"module:{gate_id}"),
        "verifier_runtime_digest": _hash(f"runtime:{gate_id}"),
        "recomputed_outputs": outputs if outputs is not None else {"gate": gate_id},
        "failure_codes": failure_codes if failure_codes is not None else [],
        "decision": decision,
    }
    authority = _envelope(
        schema=AUTHORITY_ENVELOPE_SCHEMA,
        media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
        payload=payload,
    )
    validator = _envelope(
        schema=VALIDATOR_ENVELOPE_SCHEMA,
        media_type=VALIDATOR_PAYLOAD_MEDIA_TYPE,
        payload={"gate_id": gate_id},
    )
    return canonical_json_bytes(
        {
            "schema_version": FINAL_BUNDLE_SCHEMA,
            "authority_envelope": encode_byte_evidence(authority, media_type=AUTHORITY_MEDIA_TYPE),
            "validator_envelope": encode_byte_evidence(validator, media_type=VALIDATOR_MEDIA_TYPE),
        }
    )


def _authority_payload_from_envelope(authority_envelope: bytes) -> dict[str, object]:
    _, payload = recursive_verifier._decode_payload_from_envelope(  # type: ignore[attr-defined]
        authority_envelope,
        expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
        expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
        label="fixture authority",
    )
    return payload


def _authority_payload(raw_bundle: bytes) -> dict[str, object]:
    return _authority_payload_from_envelope(
        recursive_verifier.exact_gate_v2.parse_final_bundle(raw_bundle)[0]
    )


def test_shared_strict_envelope_path_rejects_forged_and_mixed_order_signatures() -> None:
    private = Ed25519PrivateKey.from_private_bytes(bytes([19]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload = encode_byte_evidence(
        canonical_json_bytes({"proof": "exact"}), media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE
    )
    alternate_payload = encode_byte_evidence(
        canonical_json_bytes({"proof": "forged"}), media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE
    )
    envelope = {
        "schema_version": AUTHORITY_ENVELOPE_SCHEMA,
        "signer_key_id": f"ed25519-sha256:{hashlib.sha256(public).hexdigest()}",
        "payload": payload,
        "signature_ed25519_base64": base64.b64encode(
            private.sign(signature_message(domain=AUTHORITY_DOMAIN, payload_wrapper=alternate_payload))
        ).decode("ascii"),
    }
    forged = canonical_json_bytes(envelope)
    with pytest.raises(ExactGateV2Error):
        verify_signed_payload_envelope(
            forged,
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
            public_key=public,
            domain=AUTHORITY_DOMAIN,
        )
    mixed_order = json.dumps(
        {
            "signature_ed25519_base64": envelope["signature_ed25519_base64"],
            "payload": envelope["payload"],
            "signer_key_id": envelope["signer_key_id"],
            "schema_version": envelope["schema_version"],
        },
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(ExactGateV2Error):
        verify_signed_payload_envelope(
            mixed_order,
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
            public_key=public,
            domain=AUTHORITY_DOMAIN,
        )


def _fixture() -> dict[str, object]:
    g00 = _bundle("G00_TRUST_ROOTS", [])
    g00_payload = _authority_payload(g00)
    g01 = _bundle(
        "G01_CONSTITUTION_AND_CODE_FREEZE",
        [
            {
                "gate_id": "G00_TRUST_ROOTS",
                "bundle_sha256": hashlib.sha256(g00).hexdigest(),
                "authority_payload_sha256": hashlib.sha256(canonical_json_bytes(g00_payload)).hexdigest(),
                "decision": "PASS_RESEARCH_ONLY",
            }
        ],
    )
    raw_gate_bundles = [
        {"gate_id": "G00_TRUST_ROOTS", "final_bundle": g00},
        {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "final_bundle": g01},
    ]
    material = {
        "genesis_envelope": b"genesis",
        "registry_epoch_envelopes": [],
        "role_pop_envelopes": {},
        "evaluation_entry_envelope": b"entry",
        "freeze_authority_envelope": b"freeze-authority",
        "freeze_validator_envelope": b"freeze-validator",
        "evidence_manifest_wrapper": {},
        "supplied_artifacts": [],
        "failure_code_registry_raw": b"registry",
        "pinned_offline_root_public_key": bytes(32),
    }
    return {
        "raw_gate_bundles": raw_gate_bundles,
        "governance_material_by_gate": {
            "G00_TRUST_ROOTS": deepcopy(material),
            "G01_CONSTITUTION_AND_CODE_FREEZE": deepcopy(material),
        },
    }


def _receipt(*, bundle: bytes, kind: str, executor_id: str, runtime: str | None = None, outputs: dict[str, object] | None = None) -> bytes:
    payload = _authority_payload(bundle)
    return canonical_json_bytes(
        {
            "schema_version": recursive_verifier.HERMETIC_RECEIPT_SCHEMA,
            "receipt_kind": kind,
            "executor_id": executor_id,
            "gate_id": payload["gate_id"],
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
            "input_bundle_root": payload["input_bundle_root"],
            "verifier_bundle_digest": payload["verifier_bundle_digest"],
            "verifier_runtime_digest": runtime if runtime is not None else payload["verifier_runtime_digest"],
            "recomputed_outputs": outputs if outputs is not None else payload["recomputed_outputs"],
            "failure_codes": payload["failure_codes"],
            "decision": payload["decision"],
        }
    )


class _Hermetic:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def verify_hermetic_execution_receipt(self, *, receipt_raw: bytes, gate_id: str, bundle_sha256: str, verifier_bundle_digest: str, verifier_runtime_digest: str) -> None:
        del receipt_raw, bundle_sha256, verifier_bundle_digest, verifier_runtime_digest
        self.calls.append(gate_id)


class _Replay:
    def __init__(self, *, conflict: bool = False) -> None:
        self.conflict = conflict

    def verify_valid_only_replay_receipt(self, **_: object) -> None:
        if self.conflict:
            raise ValueError("replay conflict")


def _patch_governance(monkeypatch: pytest.MonkeyPatch) -> None:
    def verified(**kwargs: object) -> dict[str, object]:
        authority = kwargs["exact_gate_authority_envelope"]
        payload = _authority_payload_from_envelope(authority)  # type: ignore[arg-type]
        return {
            "decision": "EXACT_GATE_V2_GOVERNANCE_BOUND_RESEARCH_ONLY",
            "gate_id": payload["gate_id"],
            "campaign_root": payload["campaign_root"],
            "evaluation_id": payload["evaluation_id"],
            "evaluation_nonce": payload["evaluation_nonce"],
            "attempt": payload["attempt"],
            "registry_epoch": 7,
            "registry_hash": _hash("tip"),
            "result_sha256": _hash(str(payload["gate_id"])),
            "authority": False,
            "submission_authorized": False,
            "holdout_access": False,
            "sealed_holdout_access": False,
            "candidate_authorized": False,
            "candidate_development_authorized": False,
        }

    monkeypatch.setattr(recursive_verifier.governance, "verify_exact_gate_v2_governance", verified)


def _replay_receipt(bundle: bytes, *, epoch: int = 7) -> bytes:
    payload = _authority_payload(bundle)
    return canonical_json_bytes(
        {
            "schema_version": recursive_verifier.REPLAY_RECEIPT_SCHEMA,
            "service_id": "trusted-replay",
            "campaign_root": payload["campaign_root"],
            "evaluation_id": payload["evaluation_id"],
            "evaluation_nonce": payload["evaluation_nonce"],
            "gate_id": payload["gate_id"],
            "attempt": 0,
            "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
            "registry_epoch": epoch,
            "registry_hash": _hash("tip"),
            "status": "VALID_ONLY_REPLAY_ACCEPTED",
        }
    )


def _call(monkeypatch: pytest.MonkeyPatch, fixture: dict[str, object], *, hermetic: _Hermetic | None = None, replay: _Replay | None = None, authority_receipts: dict[str, bytes] | None = None, validator_receipts: dict[str, bytes] | None = None, replay_receipt: bytes | None = None) -> dict[str, object]:
    _patch_governance(monkeypatch)
    bundles = {row["gate_id"]: row["final_bundle"] for row in fixture["raw_gate_bundles"]}  # type: ignore[index]
    authority_receipts = authority_receipts or {gate: _receipt(bundle=bundle, kind="AUTHORITY", executor_id=f"authority-{gate}") for gate, bundle in bundles.items()}
    validator_receipts = validator_receipts or {gate: _receipt(bundle=bundle, kind="VALIDATOR", executor_id=f"validator-{gate}") for gate, bundle in bundles.items()}
    return recursive_verifier._build_synthetic_recursive_audit(  # type: ignore[attr-defined]
        target_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE",
        raw_gate_bundles=fixture["raw_gate_bundles"],
        governance_material_by_gate=fixture["governance_material_by_gate"],
        authority_execution_receipts=authority_receipts,
        validator_execution_receipts=validator_receipts,
        hermetic_receipt_verifier=hermetic or _Hermetic(),
        replay_service=replay or _Replay(),
        replay_service_receipt=replay_receipt or _replay_receipt(bundles["G01_CONSTITUTION_AND_CODE_FREEZE"]),
    )


def test_recursive_audit_is_zero_authority_and_uses_two_independent_receipts(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture()
    hermetic = _Hermetic()
    result = _call(monkeypatch, fixture, hermetic=hermetic)
    assert result["decision"] == recursive_verifier.RESEARCH_AUDIT_DECISION
    assert "PASS" not in result["decision"]
    assert result["reachable_gate_ids"] == ["G00_TRUST_ROOTS", "G01_CONSTITUTION_AND_CODE_FREEZE"]
    assert set(result["authority_execution_receipt_sha256_by_gate"]) == set(result["reachable_gate_ids"])
    assert set(result["validator_execution_receipt_sha256_by_gate"]) == set(result["reachable_gate_ids"])
    assert hermetic.calls == ["G00_TRUST_ROOTS", "G00_TRUST_ROOTS", "G01_CONSTITUTION_AND_CODE_FREEZE", "G01_CONSTITUTION_AND_CODE_FREEZE"]
    for flag in ("authority", "submission_authorized", "holdout_access", "sealed_holdout_access", "candidate_authorized", "candidate_development_authorized"):
        assert result[flag] is False


def test_fake_universe_or_attacker_keys_fail_closed() -> None:
    fixture = _fixture()
    with pytest.raises(recursive_verifier.RecursiveExactVerificationError):
        bundles = {
            row["gate_id"]: row["final_bundle"]
            for row in fixture["raw_gate_bundles"]  # type: ignore[index]
        }
        recursive_verifier._build_synthetic_recursive_audit(  # type: ignore[attr-defined]
            target_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE",
            raw_gate_bundles=fixture["raw_gate_bundles"],
            governance_material_by_gate=fixture["governance_material_by_gate"],
            authority_execution_receipts={
                gate: _receipt(bundle=bundle, kind="AUTHORITY", executor_id=f"authority-{gate}")
                for gate, bundle in bundles.items()
            },
            validator_execution_receipts={
                gate: _receipt(bundle=bundle, kind="VALIDATOR", executor_id=f"validator-{gate}")
                for gate, bundle in bundles.items()
            },
            hermetic_receipt_verifier=_Hermetic(), replay_service=_Replay(),
            replay_service_receipt=_replay_receipt(bundles["G01_CONSTITUTION_AND_CODE_FREEZE"]),
        )


def test_production_entry_point_rejects_caller_supplied_trust_services() -> None:
    fixture = _fixture()
    bundles = {
        row["gate_id"]: row["final_bundle"]
        for row in fixture["raw_gate_bundles"]  # type: ignore[index]
    }
    with pytest.raises(
        recursive_verifier.RecursiveExactVerificationError,
        match="independently pinned hermetic and replay trust services are unavailable",
    ):
        recursive_verifier.verify_recursive_exact_v2(
            target_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE",
            raw_gate_bundles=fixture["raw_gate_bundles"],
            governance_material_by_gate=fixture["governance_material_by_gate"],
            authority_execution_receipts={
                gate: _receipt(bundle=bundle, kind="AUTHORITY", executor_id=f"authority-{gate}")
                for gate, bundle in bundles.items()
            },
            validator_execution_receipts={
                gate: _receipt(bundle=bundle, kind="VALIDATOR", executor_id=f"validator-{gate}")
                for gate, bundle in bundles.items()
            },
            hermetic_receipt_verifier=_Hermetic(),
            replay_service=_Replay(),
            replay_service_receipt=_replay_receipt(
                bundles["G01_CONSTITUTION_AND_CODE_FREEZE"]
            ),
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "substitution", "omitted_edge", "extra_edge", "cycle"])
def test_raw_closure_rejects_missing_extra_substituted_and_wrong_edges(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    fixture = _fixture()
    if mutation == "missing":
        fixture["raw_gate_bundles"] = fixture["raw_gate_bundles"][1:]  # type: ignore[index]
    elif mutation == "extra":
        fixture["raw_gate_bundles"].append(deepcopy(fixture["raw_gate_bundles"][0]))  # type: ignore[index]
    else:
        g00 = fixture["raw_gate_bundles"][0]["final_bundle"]  # type: ignore[index]
        assert isinstance(g00, bytes)
        if mutation == "substitution":
            direct = [{"gate_id": "G00_TRUST_ROOTS", "bundle_sha256": _hash("wrong"), "authority_payload_sha256": _hash("wrong-payload"), "decision": "PASS_RESEARCH_ONLY"}]
            g01 = _bundle("G01_CONSTITUTION_AND_CODE_FREEZE", direct)
        elif mutation == "omitted_edge":
            g01 = _bundle("G01_CONSTITUTION_AND_CODE_FREEZE", [])
        elif mutation == "extra_edge":
            direct = [{"gate_id": "G00_TRUST_ROOTS", "bundle_sha256": hashlib.sha256(g00).hexdigest(), "authority_payload_sha256": hashlib.sha256(canonical_json_bytes(_authority_payload(g00))).hexdigest(), "decision": "PASS_RESEARCH_ONLY"}, {"gate_id": "G02_ENGINE_EVENT_CAPABILITY", "bundle_sha256": _hash("extra"), "authority_payload_sha256": _hash("extra-payload"), "decision": "PASS_RESEARCH_ONLY"}]
            g01 = _bundle("G01_CONSTITUTION_AND_CODE_FREEZE", direct)
        else:
            g01 = _bundle("G01_CONSTITUTION_AND_CODE_FREEZE", [{"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "bundle_sha256": _hash("cycle"), "authority_payload_sha256": _hash("cycle-payload"), "decision": "PASS_RESEARCH_ONLY"}])
        fixture["raw_gate_bundles"][1]["final_bundle"] = g01  # type: ignore[index]
    with pytest.raises(recursive_verifier.RecursiveExactVerificationError):
        _call(monkeypatch, fixture)


@pytest.mark.parametrize("case", ["runtime", "executors", "replay_conflict", "stale_tip", "dependency_failure"])
def test_receipt_replay_and_dependency_failures_are_fail_closed(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    fixture = _fixture()
    bundles = {row["gate_id"]: row["final_bundle"] for row in fixture["raw_gate_bundles"]}  # type: ignore[index]
    kwargs: dict[str, object] = {}
    if case == "runtime":
        receipts = {gate: _receipt(bundle=bundle, kind="AUTHORITY", executor_id=f"authority-{gate}") for gate, bundle in bundles.items()}
        receipts["G01_CONSTITUTION_AND_CODE_FREEZE"] = _receipt(bundle=bundles["G01_CONSTITUTION_AND_CODE_FREEZE"], kind="AUTHORITY", executor_id="authority-G01", runtime=_hash("wrong-runtime"))
        kwargs["authority_receipts"] = receipts
    elif case == "executors":
        kwargs["validator_receipts"] = {gate: _receipt(bundle=bundle, kind="VALIDATOR", executor_id=f"authority-{gate}") for gate, bundle in bundles.items()}
    elif case == "replay_conflict":
        kwargs["replay"] = _Replay(conflict=True)
    elif case == "stale_tip":
        kwargs["replay_receipt"] = _replay_receipt(bundles["G01_CONSTITUTION_AND_CODE_FREEZE"], epoch=6)
    else:
        g00 = _bundle("G00_TRUST_ROOTS", [], decision="FAIL_CLOSED", failure_codes=["BASE_FAILURE"])
        g00_payload = _authority_payload(g00)
        g01 = _bundle("G01_CONSTITUTION_AND_CODE_FREEZE", [{"gate_id": "G00_TRUST_ROOTS", "bundle_sha256": hashlib.sha256(g00).hexdigest(), "authority_payload_sha256": hashlib.sha256(canonical_json_bytes(g00_payload)).hexdigest(), "decision": "FAIL_CLOSED"}])
        fixture["raw_gate_bundles"] = [{"gate_id": "G00_TRUST_ROOTS", "final_bundle": g00}, {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "final_bundle": g01}]
    with pytest.raises(recursive_verifier.RecursiveExactVerificationError):
        _call(monkeypatch, fixture, **kwargs)  # type: ignore[arg-type]
