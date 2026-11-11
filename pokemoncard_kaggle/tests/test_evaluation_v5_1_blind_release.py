from __future__ import annotations

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.blind_release import (
    ANALYSIS_RESULT_SCHEMA,
    PUBLICATION_RECEIPT_SCHEMA,
    RELEASE_APPROVAL_SCHEMA,
    RELEASE_REQUEST_SCHEMA,
    BlindReleaseError,
    verify_published_analysis_result,
    verify_release_quorum,
    verify_release_request,
)
from evaluation_v5_1.canonical import canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload


PROTOCOL = "MCI_FAMILY_TRANSFER_V2"


def _key() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public


def _signed(schema: str, payload: dict[str, object], key: tuple[Ed25519PrivateKey, bytes]):
    private, public = key
    signature = private.sign(signing_payload(schema, canonical_sha256(payload)))
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=signature,
    )


def _request() -> dict[str, object]:
    fields = {
        "campaign_root_sha256": "1" * 64,
        "claim_manifest_root_sha256": "2" * 64,
        "dev_fit_root_sha256": "3" * 64,
        "frame_root_sha256": "4" * 64,
        "selection_root_sha256": "5" * 64,
        "prediction_ciphertext_sha256": "6" * 64,
        "outcome_ciphertext_sha256": "7" * 64,
        "census_root_sha256": "8" * 64,
        "validator_image_sha256": "9" * 64,
        "validator_source_sha256": "a" * 64,
        "output_schema_sha256": "b" * 64,
        "single_use_nonce_sha256": "c" * 64,
    }
    return {
        "protocol_id": PROTOCOL,
        **fields,
        "not_before_utc": "2026-09-01T00:00:00.000000Z",
        "expected_run_counter": 0,
    }


def _approval(request: dict[str, object], approver: str, key):
    return _signed(
        RELEASE_APPROVAL_SCHEMA,
        {
            "protocol_id": PROTOCOL,
            "release_request_sha256": canonical_sha256(request),
            "approver_id": approver,
            "decision": "APPROVE_RESEARCH_ANALYSIS_ONCE",
        },
        key,
    )


def _result(request: dict[str, object]) -> dict[str, object]:
    result = {
        "protocol_id": PROTOCOL,
        "release_request_sha256": canonical_sha256(request),
        "single_use_nonce_sha256": request["single_use_nonce_sha256"],
        "validator_image_sha256": request["validator_image_sha256"],
        "run_counter_before": 0,
        "run_counter_after": 1,
        "network_disabled": True,
        "interactive_access": False,
        "debug_surface_present": False,
        "dev_fit_code_present": False,
        "candidate_code_present": False,
        "family_count": 20,
        "family_success_count": 15,
        "exact_p_value": "0.020694732666",
        "mean_logloss_lift": "0.012000000000",
        "activation_block_means": ["0.010000000000"] * 4,
        "catastrophic_family_count": 1,
        "unresolved_rows": 0,
        "primary_claim_pass": True,
        "all_conjunctive_gates_pass": True,
        "status": "PASS_RESEARCH_ONLY",
        "executed_at_utc": "2026-09-01T00:00:01.000000Z",
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
    }
    return {
        **result,
        "validation_receipt_sha256": canonical_sha256(result),
    }


def _publication(request: dict[str, object], result: dict[str, object] | None = None) -> dict[str, object]:
    result = _result(request) if result is None else result
    return {
        "protocol_id": PROTOCOL,
        "release_request_sha256": canonical_sha256(request),
        "validation_receipt_sha256": result["validation_receipt_sha256"],
        "registry_entry_sha256": "e" * 64,
        "published": True,
    }


def _rebind_result(result: dict[str, object]) -> None:
    core = {key: value for key, value in result.items() if key != "validation_receipt_sha256"}
    result["validation_receipt_sha256"] = canonical_sha256(core)


def test_two_of_three_quorum_is_hash_only_and_zero_authority() -> None:
    registry = _key()
    quorum = {name: _key() for name in ("quorum_1", "quorum_2", "quorum_3")}
    request = _request()
    checked = verify_release_request(
        _signed(RELEASE_REQUEST_SCHEMA, request, registry),
        pinned_registry_key=registry[1],
        expected_protocol_id=PROTOCOL,
        expected_bindings={
            key: value
            for key, value in request.items()
            if key.endswith("_sha256")
        },
    )
    audit = verify_release_quorum(
        checked,
        [
            _approval(request, "quorum_1", quorum["quorum_1"]),
            _approval(request, "quorum_3", quorum["quorum_3"]),
        ],
        pinned_quorum_keys={name: key[1] for name, key in quorum.items()},
        expected_protocol_id=PROTOCOL,
    )
    assert audit["analysis_capability_verified"] is True
    assert audit["submission_authorized"] is False


def test_one_approval_duplicate_and_wrong_request_fail() -> None:
    quorum = {name: _key() for name in ("quorum_1", "quorum_2", "quorum_3")}
    request = _request()
    one = _approval(request, "quorum_1", quorum["quorum_1"])
    keys = {name: key[1] for name, key in quorum.items()}
    with pytest.raises(BlindReleaseError, match="at least two"):
        verify_release_quorum(request, [one], pinned_quorum_keys=keys, expected_protocol_id=PROTOCOL)
    with pytest.raises(BlindReleaseError, match="duplicate"):
        verify_release_quorum(request, [one, one], pinned_quorum_keys=keys, expected_protocol_id=PROTOCOL)
    other = deepcopy(request)
    other["campaign_root_sha256"] = "f" * 64
    with pytest.raises(BlindReleaseError, match="exact release request"):
        verify_release_quorum(
            request,
            [_approval(other, "quorum_1", quorum["quorum_1"]), _approval(other, "quorum_2", quorum["quorum_2"])],
            pinned_quorum_keys=keys,
            expected_protocol_id=PROTOCOL,
        )


def test_published_pass_is_one_shot_zero_authority() -> None:
    analyzer, registry = _key(), _key()
    request, result = _request(), None
    result = _result(request)
    audit = verify_published_analysis_result(
        _signed(ANALYSIS_RESULT_SCHEMA, result, analyzer),
        _signed(PUBLICATION_RECEIPT_SCHEMA, _publication(request, result), registry),
        pinned_analyzer_key=analyzer[1],
        pinned_registry_key=registry[1],
        expected_protocol_id=PROTOCOL,
        release_request=request,
        expected_analysis_container_sha256="9" * 64,
    )
    assert audit["evaluator_validated_research_only"] is True
    assert audit["candidate_development_authorized"] is False
    assert audit["submission_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("run_counter_after", 2, "run counter"),
        ("network_disabled", False, "network"),
        ("interactive_access", True, "interactive"),
        ("debug_surface_present", True, "debug"),
        ("dev_fit_code_present", True, "dev_fit"),
        ("candidate_code_present", True, "candidate_code"),
        ("submission_authorized", True, "illegally sets submission"),
    ],
)
def test_capability_or_authority_escalation_fails(field: str, value: object, match: str) -> None:
    analyzer, registry = _key(), _key()
    request = _request()
    result = _result(request)
    result[field] = value
    _rebind_result(result)
    with pytest.raises(BlindReleaseError, match=match):
        verify_published_analysis_result(
            _signed(ANALYSIS_RESULT_SCHEMA, result, analyzer),
            _signed(PUBLICATION_RECEIPT_SCHEMA, _publication(request, result), registry),
            pinned_analyzer_key=analyzer[1],
            pinned_registry_key=registry[1],
            expected_protocol_id=PROTOCOL,
            release_request=request,
            expected_analysis_container_sha256="9" * 64,
        )


def test_threshold_and_status_inconsistency_fail() -> None:
    analyzer, registry = _key(), _key()
    request = _request()
    result = _result(request)
    result["family_success_count"] = 14
    _rebind_result(result)
    with pytest.raises(BlindReleaseError, match="exact_p_value"):
        verify_published_analysis_result(
            _signed(ANALYSIS_RESULT_SCHEMA, result, analyzer),
            _signed(PUBLICATION_RECEIPT_SCHEMA, _publication(request, result), registry),
            pinned_analyzer_key=analyzer[1],
            pinned_registry_key=registry[1],
            expected_protocol_id=PROTOCOL,
            release_request=request,
            expected_analysis_container_sha256="9" * 64,
        )


def test_request_requires_counter_zero_and_exact_hash_bindings() -> None:
    registry = _key()
    request = _request()
    request["expected_run_counter"] = 1
    with pytest.raises(BlindReleaseError, match="counter zero"):
        verify_release_request(
            _signed(RELEASE_REQUEST_SCHEMA, request, registry),
            pinned_registry_key=registry[1],
            expected_protocol_id=PROTOCOL,
            expected_bindings={
                key: value
                for key, value in request.items()
                if key.endswith("_sha256")
            },
        )


def test_forged_exact_p_value_and_unbound_result_hash_fail() -> None:
    analyzer, registry = _key(), _key()
    request = _request()
    result = _result(request)
    result["exact_p_value"] = "0.000000000001"
    core = {key: value for key, value in result.items() if key != "validation_receipt_sha256"}
    result["validation_receipt_sha256"] = canonical_sha256(core)
    with pytest.raises(BlindReleaseError, match="exact binomial"):
        verify_published_analysis_result(
            _signed(ANALYSIS_RESULT_SCHEMA, result, analyzer),
            _signed(PUBLICATION_RECEIPT_SCHEMA, _publication(request, result), registry),
            pinned_analyzer_key=analyzer[1],
            pinned_registry_key=registry[1],
            expected_protocol_id=PROTOCOL,
            release_request=request,
            expected_analysis_container_sha256="9" * 64,
        )

    result = _result(request)
    result["mean_logloss_lift"] = "0.020000000000"
    with pytest.raises(BlindReleaseError, match="does not bind"):
        verify_published_analysis_result(
            _signed(ANALYSIS_RESULT_SCHEMA, result, analyzer),
            _signed(PUBLICATION_RECEIPT_SCHEMA, _publication(request, result), registry),
            pinned_analyzer_key=analyzer[1],
            pinned_registry_key=registry[1],
            expected_protocol_id=PROTOCOL,
            release_request=request,
            expected_analysis_container_sha256="9" * 64,
        )
