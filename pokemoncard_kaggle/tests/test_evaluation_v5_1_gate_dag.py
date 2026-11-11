from __future__ import annotations

from copy import deepcopy

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from evaluation_v5_1.canonical import canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.gate_dag import (
    GATE_AUDIT_SCHEMA,
    GATE_DEPENDENCIES,
    GATE_IDS,
    PROTOCOL_ID,
    _REQUIRED_CHECKS,
    _authority_claim,
    _validate_g04,
    canonical_result_hash,
    compose_gate_dag,
)
from evaluation_v5_1.statistics import INPUT_SCHEMA, evaluate_primary_gate
from tests.test_evaluation_v5_1_cross_engine import (
    _external_pass_result as _g04_external_pass_result,
    _panel as _g04_panel,
    _rehash_panel as _rehash_g04_panel,
)


_GATE_ROLES = {
    GATE_IDS[0]: "evaluation_authority", GATE_IDS[1]: "evaluation_authority",
    GATE_IDS[2]: "validator", GATE_IDS[3]: "trace_attestor",
    GATE_IDS[4]: "validator", GATE_IDS[5]: "validator",
    GATE_IDS[6]: "validator", GATE_IDS[7]: "evaluation_authority",
    GATE_IDS[8]: "registrar", GATE_IDS[9]: "registrar",
    GATE_IDS[10]: "evidence_custodian", GATE_IDS[11]: "validator",
    GATE_IDS[12]: "release", GATE_IDS[13]: "evaluation_authority",
    GATE_IDS[14]: "validator", GATE_IDS[15]: "release",
}
_ROLE_SEEDS = {
    "evaluation_authority": 41, "registrar": 42, "collector_a": 43,
    "collector_b": 44, "evidence_custodian": 45, "trace_attestor": 46,
    "validator": 47, "release": 48, "development": 49,
}


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, public


def _hash(seed: int) -> str:
    return f"{seed:064x}"


def _expected() -> dict[str, object]:
    family_ids = [f"family-{index:02d}" for index in range(20)]
    archives = [_hash(index + 100) for index in range(20)]
    return {
        "protocol_id": PROTOCOL_ID,
        "campaign_root_sha256": _hash(1),
        "cohort_root_sha256": _hash(2),
        "statistics_spec_sha256": _hash(3),
        "collector_pair_sha256": _hash(4),
        "blind_image_sha256": _hash(5),
        "validator_image_sha256": _hash(6),
        "immutable_results_sha256": _hash(7),
        "cohort": {
            "family_ids": family_ids,
            "archive_sha256s": archives,
            "family_archives": [
                {"family_id": family_id, "archive_sha256": archive}
                for family_id, archive in zip(family_ids, archives)
            ],
            "activation_blocks": [
                {"block": block, "family_ids": family_ids[block * 5 : block * 5 + 5]}
                for block in range(4)
            ],
        },
        "identities": {
            "evaluation_authority": "evaluation-authority-key",
            "registrar": "registrar-key",
            "collector_a": "collector-a-key",
            "collector_b": "collector-b-key",
            "evidence_custodian": "evidence-custodian-key",
            "trace_attestor": "trace-attestor-key",
            "validator": "validator-key",
            "development": "development-key",
            "release": "release-key",
        },
        "role_keys": {},
        "gate_signers": {},
    }


def _rows(*, successes: int = 20, negative_block: bool = False, catastrophic: int = 0, unresolved: int = 0) -> list[dict[str, object]]:
    rows = []
    for index in range(20):
        lift = "0.020000000000" if index < successes else "0.000000000000"
        if negative_block and index == 0:
            lift = "-0.030000000000"
        if negative_block and 1 <= index < 5:
            lift = "-0.010000000000"
        if index < catastrophic:
            lift = "-0.060000000000"
        rows.append({
            "archive_sha256": _hash(index + 100),
            "family_id": f"family-{index:02d}",
            "activation_block": index // 5,
            "lift": lift,
            "unresolved_rows": unresolved if index == 0 else 0,
        })
    return rows


def _fixture(*, rows: list[dict[str, object]] | None = None) -> tuple[list[dict[str, object]], dict[str, object]]:
    expected = _expected()
    gate_private: dict[str, Ed25519PrivateKey] = {}
    for role, seed in _ROLE_SEEDS.items():
        _, public = _key(seed)
        expected["role_keys"][role] = {
            "identity": expected["identities"][role],
            "public_key": public,
            "algorithm": "Ed25519",
            "valid_from_utc": "2026-07-14T00:00:00Z",
            "valid_until_utc": "2027-07-14T00:00:00Z",
            "revoked": False,
        }  # type: ignore[index]
    for gate_id in GATE_IDS:
        role = _GATE_ROLES[gate_id]
        private, public = _key(_ROLE_SEEDS[role])
        gate_private[gate_id] = private
        assert public == expected["role_keys"][role]["public_key"]  # type: ignore[index]
        expected["gate_signers"][gate_id] = {
            "identity": expected["role_keys"][role]["identity"],
            "public_key": expected["role_keys"][role]["public_key"],
        }  # type: ignore[index]
    rows = _rows() if rows is None else rows
    stats_input = {"schema": INPUT_SCHEMA, "families": rows}
    stats = evaluate_primary_gate(stats_input)
    expected["immutable_results_sha256"] = canonical_sha256(stats_input)
    envelopes = []
    previous = "0" * 64
    for index, gate_id in enumerate(GATE_IDS):
        checks = {name: True for name in _REQUIRED_CHECKS[gate_id]}
        audit: dict[str, object] = {"checks": checks}
        if index == 4:
            panel = _g04_panel()
            panel["campaign_root_sha256"] = expected["campaign_root_sha256"]
            _rehash_g04_panel(panel)
            result = _g04_external_pass_result(panel)
            audit = {
                "checks": checks,
                "panel": panel,
                "panel_sha256": canonical_sha256(panel),
                "result": result,
                "result_sha256": canonical_sha256(result),
            }
        if index == 8:
            audit.update({"cohort": deepcopy(expected["cohort"]), "cohort_root_sha256": expected["cohort_root_sha256"]})
        if index == 10:
            audit["collector_pair"] = {"collector_a": expected["identities"]["collector_a"], "collector_b": expected["identities"]["collector_b"], "collector_pair_sha256": expected["collector_pair_sha256"]}  # type: ignore[index]
        if index == 11:
            audit = {
                "checks": checks,
                "family_results": stats_input,
                "family_results_sha256": canonical_sha256(stats_input),
                "statistics_spec_sha256": expected["statistics_spec_sha256"],
                "immutable_results_sha256": canonical_sha256(stats_input),
                "statistics_result": stats,
                "statistics_result_sha256": canonical_sha256(stats),
            }
        if index >= 12:
            audit["after_g11"] = True
        payload = {
            "schema": GATE_AUDIT_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "gate_id": gate_id,
            "gate_sequence": index,
            "previous_gate_sha256": previous,
            "campaign_root_sha256": expected["campaign_root_sha256"],
            "bindings": {field: expected[field] for field in ("campaign_root_sha256", "cohort_root_sha256", "statistics_spec_sha256", "collector_pair_sha256", "blind_image_sha256", "validator_image_sha256", "immutable_results_sha256")},
            "signer_identity": expected["gate_signers"][gate_id]["identity"],  # type: ignore[index]
            "passed": True,
            "authority": False,
            "sealed_holdout_access": False,
            "submission_authorized": False,
            "candidate_development_authorized": False,
            "audit_sha256": canonical_sha256(audit),
            "audit": audit,
        }
        private = gate_private[gate_id]
        envelope = build_envelope(
            artifact_schema=GATE_AUDIT_SCHEMA,
            payload=payload,
            signer_public_key_bytes=expected["gate_signers"][gate_id]["public_key"],  # type: ignore[index]
            signature=private.sign(signing_payload(GATE_AUDIT_SCHEMA, canonical_sha256(payload))),
        )
        envelopes.append(envelope)
        previous = canonical_sha256(payload)
    return envelopes, expected


def _assert_closed(result: dict[str, object]) -> None:
    assert result["decision"] == "FAIL_CLOSED"
    assert result["authority"] is False
    assert result["sealed_holdout_access"] is False
    assert result["submission_authorized"] is False
    assert result["result_sha256"] == canonical_result_hash(result)


def test_registered_gate_dag_matches_reviewed_multi_parent_contract() -> None:
    assert GATE_DEPENDENCIES["G09_BLIND_CAMPAIGN_ACTIVATION"] == (
        "G00_TRUST_ROOTS",
        "G08_EXTERNAL_FRAME_CLOSE_AND_RANDOM_SELECTION",
    )
    assert GATE_DEPENDENCIES["G12_EVALUATOR_UNSEAL"] == (
        "G11_ONE_SHOT_TRANSFER_VALIDATION",
    )
    assert GATE_DEPENDENCIES["G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION"] == (
        "G05_DEV_SOURCE_COMPLETENESS",
        "G12_EVALUATOR_UNSEAL",
    )
    assert GATE_DEPENDENCIES["G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT"] == (
        "G12_EVALUATOR_UNSEAL",
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
    )
    assert GATE_DEPENDENCIES["G15_RELEASE_CUSTODY"] == (
        "G13_CANDIDATE_MUTATION_AND_HIDDEN_SELECTION",
        "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT",
    )


def test_legacy_signed_boolean_chain_is_unverified_evidence() -> None:
    envelopes, expected = _fixture()
    result = compose_gate_dag(envelopes, expected_bindings=expected)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["gate_ids"] == list(GATE_IDS)
    assert result["reasons"] and result["reasons"][0].startswith(
        "FAIL_UNVERIFIED_EVIDENCE:"
    )
    assert result["transfer"] is None
    assert result["authority"] is False
    assert result["sealed_holdout_access"] is False
    assert result["submission_authorized"] is False
    assert result["result_sha256"] == canonical_result_hash(result)


def test_forged_early_authority_is_rejected() -> None:
    envelopes, expected = _fixture()
    payload = deepcopy(envelopes[0]["payload"])
    payload["authority"] = True
    envelopes[0] = build_envelope(artifact_schema=GATE_AUDIT_SCHEMA, payload=payload, signer_public_key_bytes=expected["gate_signers"][GATE_IDS[0]]["public_key"], signature=_key(_ROLE_SEEDS[_GATE_ROLES[GATE_IDS[0]]])[0].sign(signing_payload(GATE_AUDIT_SCHEMA, canonical_sha256(payload))))  # type: ignore[index]
    _assert_closed(compose_gate_dag(envelopes, expected_bindings=expected))


def test_missing_reordered_and_duplicate_gates_fail_closed() -> None:
    envelopes, expected = _fixture()
    _assert_closed(compose_gate_dag(envelopes[:-1], expected_bindings=expected))
    reordered = list(envelopes)
    reordered[1], reordered[2] = reordered[2], reordered[1]
    _assert_closed(compose_gate_dag(reordered, expected_bindings=expected))
    duplicate = list(envelopes)
    duplicate[1] = duplicate[0]
    _assert_closed(compose_gate_dag(duplicate, expected_bindings=expected))


def test_hash_swapping_fails_closed() -> None:
    envelopes, expected = _fixture()
    swapped = deepcopy(envelopes)
    swapped[8]["payload"]["bindings"]["cohort_root_sha256"] = _hash(999)
    _assert_closed(compose_gate_dag(swapped, expected_bindings=expected))


def test_transfer_requires_exact_15_of_20_and_all_conjunctive_checks() -> None:
    for rows in (
        _rows(successes=14),
        _rows(negative_block=True),
        _rows(catastrophic=2),
        _rows(unresolved=1),
    ):
        envelopes, expected = _fixture(rows=rows)
        _assert_closed(compose_gate_dag(envelopes, expected_bindings=expected))


def test_g12_before_g11_cannot_bypass_dependency() -> None:
    envelopes, expected = _fixture()
    reordered = list(envelopes)
    reordered[11], reordered[12] = reordered[12], reordered[11]
    _assert_closed(compose_gate_dag(reordered, expected_bindings=expected))


def test_audit_provenance_authority_label_is_not_a_capability_claim() -> None:
    _authority_claim({"signature_authority": "kaggle", "observer_authority": "collector-a"})


def test_truthy_boolean_authority_alias_is_rejected() -> None:
    try:
        _authority_claim({"release_authority": True})
    except ValueError as exc:
        assert "claims authority" in str(exc)
    else:
        raise AssertionError("truthy capability claim was accepted")


def test_validator_and_release_gate_signers_are_role_bound() -> None:
    envelopes, expected = _fixture()
    expected["gate_signers"][GATE_IDS[11]]["identity"] = "unbound-validator"  # type: ignore[index]
    _assert_closed(compose_gate_dag(envelopes, expected_bindings=expected))


def test_malformed_expected_binding_cannot_break_fail_closed_result() -> None:
    envelopes, expected = _fixture()
    expected["campaign_root_sha256"] = b"not-canonical"
    result = compose_gate_dag(envelopes, expected_bindings=expected)
    _assert_closed(result)
    assert result["bindings"] is None


def test_g04_recomputes_exact_panel_counts_instead_of_trusting_checks() -> None:
    _, expected = _fixture()
    panel = _g04_panel()
    panel["campaign_root_sha256"] = expected["campaign_root_sha256"]
    _rehash_g04_panel(panel)
    result = _g04_external_pass_result(panel)
    result["comparisons"][0]["source"]["numerator"] -= 1
    result["content_sha256"] = canonical_sha256({key: value for key, value in result.items() if key != "content_sha256"})
    audit = {
        "checks": {name: True for name in _REQUIRED_CHECKS[GATE_IDS[4]]},
        "panel": panel, "panel_sha256": canonical_sha256(panel),
        "result": result, "result_sha256": canonical_sha256(result),
    }
    with pytest.raises(ValueError, match="counts_mismatch"):
        _validate_g04(audit, expected)
