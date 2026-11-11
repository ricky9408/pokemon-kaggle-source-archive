from __future__ import annotations

import base64
from copy import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3.common import SIGNATURE_SCHEMA, V63Error, canonical_sha256, key_id_for_public_key, signing_message
from evaluation_v6_3_1 import hosted_custody as hosted
from evaluation_v6_3_1 import permit
from tests.test_evaluation_v6_3_1_permit import _chain


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signatures(
    core: dict[str, Any],
    parties: tuple[str, ...],
    domain: bytes,
    keys: dict[str, Ed25519PrivateKey],
) -> list[dict[str, str]]:
    return [
        {
            "schema": SIGNATURE_SCHEMA,
            "party_id": party,
            "key_id": key_id_for_public_key(keys[party].public_key().public_bytes_raw()),
            "signature_base64": base64.b64encode(keys[party].sign(signing_message(domain, core))).decode("ascii"),
        }
        for party in sorted(parties)
    ]


def _signed(value: dict[str, Any], parties: tuple[str, ...], domain: bytes, keys: dict[str, Ed25519PrivateKey]) -> dict[str, Any]:
    value["signatures"] = _signatures({key: value[key] for key in value if key != "signatures"}, parties, domain, keys)
    return value


def _tls(policy: Any) -> dict[str, Any]:
    return {
        "schema": hosted.TLS_PEER_SCHEMA,
        "hostname": "api.kaggle.com",
        "certificate_chain_sha256": _digest("tls-chain"),
        "spki_sha256": _digest("tls-spki"),
        "peer_policy_root_sha256": policy["kaggle"]["peer_policy_root_sha256"],
        "authenticated": True,
    }


def _permit_chain() -> tuple[Any, dict[str, Ed25519PrivateKey], permit.OfflineCalibrationPermitCandidate]:
    validated_policy, keys, precommit, challenge, raw_permit = _chain()
    validated_permit = permit.validate_dual_calibration_permit(
        raw_permit, policy=validated_policy, precommit=precommit, challenge=challenge
    )
    return validated_policy, keys, validated_permit


def _binding(policy: Any, keys: dict[str, Ed25519PrivateKey], calibration_permit: permit.OfflineCalibrationPermitCandidate) -> dict[str, Any]:
    value = {
        "schema": hosted.SUBMISSION_BINDING_SCHEMA,
        "policy_sha256": policy["sha256"],
        "permit_sha256": calibration_permit.receipt_sha256,
        "permit_id": calibration_permit.permit_id,
        "archive_sha256": calibration_permit.archive_sha256,
        "submission_ref": "submission-ref-631",
        "file_name": calibration_permit.expected_file_name,
        "message": calibration_permit.expected_message,
        "permit_issued_at": _utc(calibration_permit.issued_at),
        "permit_expires_at": _utc(calibration_permit.expires_at),
        "observed_at": _utc(calibration_permit.issued_at + timedelta(seconds=1)),
        "permit_atomically_consumed": False,
        "authenticated_terminal_journal_heads": False,
        "replay_absence_verified": False,
    }
    return _signed(value, ("A", "B"), hosted.DOMAIN_SUBMISSION_BINDING, keys)


def _complete(policy: Any, keys: dict[str, Ed25519PrivateKey], binding: Any) -> dict[str, Any]:
    observations: dict[str, dict[str, Any]] = {}
    for party, observed_at in (("A", "2026-07-16T15:00:00Z"), ("B", "2026-07-16T15:01:00Z")):
        observation = {
            "schema": hosted.COMPLETE_OBSERVATION_SCHEMA,
            "policy_sha256": policy["sha256"],
            "submission_binding_sha256": binding.receipt_sha256,
            "collector_party_id": party,
            "submission_ref": binding.submission_ref,
            "file_name": binding.file_name,
            "message": binding.message,
            "status": "COMPLETE",
            "observed_at": observed_at,
            "raw_response_sha256": _digest(f"complete-{party}"),
            "tls_peer_identity": _tls(policy),
        }
        observations[party] = _signed(observation, (party,), hosted.DOMAIN_COMPLETE_OBSERVATION, keys)
    return _signed(
        {
            "schema": hosted.COMPLETE_AGREEMENT_SCHEMA,
            "collector_a_observation": observations["A"],
            "collector_b_observation": observations["B"],
        },
        ("A", "B"), hosted.DOMAIN_COMPLETE_AGREEMENT, keys,
    )


def _poll(
    *, policy: Any, keys: dict[str, Ed25519PrivateKey], binding: Any, t0: datetime,
    party: str, index: int, score: str, cutoff: str, extra_seconds: int = 0,
) -> dict[str, Any]:
    start = t0 + timedelta(minutes=hosted.POLL_OFFSETS_MINUTES[index])
    party_offset = 0 if party == "A" else 10
    value = {
        "schema": hosted.HOSTED_POLL_SCHEMA,
        "policy_sha256": policy["sha256"],
        "submission_binding_sha256": binding.receipt_sha256,
        "collector_party_id": party,
        "poll_index": str(index),
        "scheduled_window_start": _utc(start),
        "scheduled_window_end": _utc(start + timedelta(seconds=hosted.POLL_WINDOW_SECONDS)),
        "submission_ref": binding.submission_ref,
        "file_name": binding.file_name,
        "message": binding.message,
        "status": "COMPLETE",
        "submission_response_sha256": _digest(f"submission-{party}-{index}"),
        "leaderboard_response_sha256": _digest(f"leaderboard-{party}-{index}"),
        "score_observed_at": _utc(start + timedelta(seconds=5 + party_offset + extra_seconds)),
        "leaderboard_observed_at": _utc(start + timedelta(seconds=20 + party_offset + extra_seconds)),
        "parsed_score": score,
        "parsed_rank10_cutoff": cutoff,
        "tls_peer_identity": _tls(policy),
    }
    return _signed(value, (party,), hosted.DOMAIN_HOSTED_POLL, keys)


def _agreement(poll_a: dict[str, Any], poll_b: dict[str, Any], index: int, keys: dict[str, Ed25519PrivateKey]) -> dict[str, Any]:
    value = {
        "schema": hosted.DUAL_AGREEMENT_SCHEMA,
        "poll_index": str(index),
        "collector_receipt_sha256s": {"A": canonical_sha256(poll_a), "B": canonical_sha256(poll_b)},
        "parsed_equality_vector": {
            "file_name": True, "message": True, "parsed_rank10_cutoff": True,
            "parsed_score": True, "status": True, "submission_ref": True,
        },
        "local_timestamp_skews_seconds": {"A": "15", "B": "15"},
        "cross_collector_skew_seconds": "10",
        "accepted_attempt_index": "1",
        "agreement_result": "AGREE",
    }
    return _signed(value, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, keys)


def _valid_chain() -> tuple[Any, dict[str, Ed25519PrivateKey], Any, Any, list[Any]]:
    policy, keys, calibration_permit = _permit_chain()
    binding = hosted.validate_submission_binding(_binding(policy, keys, calibration_permit), policy=policy, permit=calibration_permit)
    complete = hosted.validate_complete_agreement(_complete(policy, keys, binding), policy=policy, binding=binding)
    agreements = []
    for index, score, cutoff in ((1, "600", "900"), (2, "1000", "1100"), (3, "700", "1000"), (4, "1200", "1250")):
        poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=index, score=score, cutoff=cutoff)
        poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=index, score=score, cutoff=cutoff)
        agreements.append(hosted.validate_dual_collector_agreement(
            _agreement(poll_a, poll_b, index, keys), policy=policy, binding=binding, complete=complete,
            collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=index,
        ))
    return policy, keys, binding, complete, agreements


def test_exact_four_poll_endpoint_is_unforgeable_and_zero_authority() -> None:
    policy, _, binding, complete, agreements = _valid_chain()
    endpoint = hosted.validate_hosted_endpoint(policy=policy, binding=binding, complete=complete, agreements=agreements)
    assert endpoint.yobs == Decimal("-200")
    assert endpoint.yobs_string == "-200"
    assert endpoint.poll_receipt_roots == tuple(item.receipt_sha256 for item in agreements)
    assert endpoint.archive_sha256 == binding.archive_sha256
    assert endpoint.offline_candidate_only is True
    assert all(getattr(endpoint, field) is False for field in (
        "permit_atomically_consumed", "authenticated_terminal_journal_heads", "replay_absence_verified",
        "calibration_upload_authorized", "production_upload_authorized", "sealed_holdout_access_authorized",
        "agent_modification_authorized", "sealed_holdout_accessed",
        "host_signed_archive_digest", "host_signed_execution_receipt", "host_signed_outcome_receipt",
        "exact_archive_persisted_by_host_proven", "exact_archive_executed_by_host_proven",
        "hosted_observations_nonrepudiable",
    ))
    with pytest.raises(ValueError):
        replace(endpoint, yobs=Decimal("999"))
    report = hosted.assess_hosted_endpoint(policy=policy, binding=binding, complete=complete, agreements=agreements)
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == []


def test_one_hour_boundary_rejects_placeholder_before_maturity_and_accepts_600_at_boundary() -> None:
    policy, keys, binding, complete, _ = _valid_chain()
    early = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="600", cutoff="900")
    early["score_observed_at"] = _utc(complete.t0 + timedelta(minutes=59, seconds=59))
    _signed(early, ("A",), hosted.DOMAIN_HOSTED_POLL, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            _agreement(early, _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="600", cutoff="900"), 1, keys),
            policy=policy, binding=binding, complete=complete, collector_a_poll=early,
            collector_b_poll=_poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="600", cutoff="900"), expected_poll_index=1,
        )
    assert caught.value.code == "V631_POLL_OUTSIDE_WINDOW"


def test_requires_all_four_polls() -> None:
    policy, _, binding, complete, agreements = _valid_chain()
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_endpoint(policy=policy, binding=binding, complete=complete, agreements=agreements[:3])
    assert caught.value.code == "V631_MATURE_POLL_MISSING"


def test_rejects_window_and_timestamp_skew() -> None:
    policy, keys, binding, complete, _ = _valid_chain()
    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="700", cutoff="900")
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="700", cutoff="900", extra_seconds=130)
    agreement = _agreement(poll_a, poll_b, 1, keys)
    agreement["cross_collector_skew_seconds"] = "140"
    _signed(agreement, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(agreement, policy=policy, binding=binding, complete=complete, collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=1)
    assert caught.value.code == "V631_DUAL_COLLECTOR_DISAGREEMENT"
    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="700", cutoff="900")
    poll_a["leaderboard_observed_at"] = _utc(complete.t0 + timedelta(minutes=61, seconds=10))
    _signed(poll_a, ("A",), hosted.DOMAIN_HOSTED_POLL, keys)
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="700", cutoff="900")
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(_agreement(poll_a, poll_b, 1, keys), policy=policy, binding=binding, complete=complete, collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=1)
    assert caught.value.code == "V631_CUTOFF_NOT_SYNCHRONIZED"

    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="700", cutoff="900")
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="700", cutoff="900")
    for poll in (poll_a, poll_b):
        poll["score_observed_at"] = _utc(complete.t0 + timedelta(minutes=70))
        poll["leaderboard_observed_at"] = _utc(complete.t0 + timedelta(minutes=70))
        _signed(poll, (poll["collector_party_id"],), hosted.DOMAIN_HOSTED_POLL, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            _agreement(poll_a, poll_b, 1, keys),
            policy=policy,
            binding=binding,
            complete=complete,
            collector_a_poll=poll_a,
            collector_b_poll=poll_b,
            expected_poll_index=1,
        )
    assert caught.value.code == "V631_POLL_OUTSIDE_WINDOW"


def test_rejects_a_b_value_disagreement_and_out_of_domain_values() -> None:
    policy, keys, binding, complete, _ = _valid_chain()
    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="700", cutoff="900")
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="701", cutoff="900")
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(_agreement(poll_a, poll_b, 1, keys), policy=policy, binding=binding, complete=complete, collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=1)
    assert caught.value.code == "V631_DUAL_COLLECTOR_DISAGREEMENT"
    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="10000.01", cutoff="900")
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="10000.01", cutoff="900")
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(_agreement(poll_a, poll_b, 1, keys), policy=policy, binding=binding, complete=complete, collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=1)
    assert caught.value.code == "V631_HOSTED_VALUE_DOMAIN_INVALID"


def test_rejects_stale_or_tampered_poll_receipt_roots() -> None:
    policy, keys, binding, complete, _ = _valid_chain()
    poll_a = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="A", index=1, score="700", cutoff="900")
    poll_b = _poll(policy=policy, keys=keys, binding=binding, t0=complete.t0, party="B", index=1, score="700", cutoff="900")
    agreement = _agreement(poll_a, poll_b, 1, keys)
    agreement["collector_receipt_sha256s"]["A"] = _digest("stale-root")
    _signed(agreement, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(agreement, policy=policy, binding=binding, complete=complete, collector_a_poll=poll_a, collector_b_poll=poll_b, expected_poll_index=1)
    assert caught.value.code == "V631_DUAL_COLLECTOR_DISAGREEMENT"


@pytest.mark.parametrize("at_expiry", [False, True])
def test_binding_observation_must_be_strictly_inside_permit_window(at_expiry: bool) -> None:
    policy, keys, calibration_permit = _permit_chain()
    raw = _binding(policy, keys, calibration_permit)
    raw["observed_at"] = _utc(
        calibration_permit.expires_at
        if at_expiry
        else calibration_permit.issued_at - timedelta(seconds=1)
    )
    _signed(raw, ("A", "B"), hosted.DOMAIN_SUBMISSION_BINDING, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(raw, policy=policy, permit=calibration_permit)
    assert caught.value.code == "V631_SUBMISSION_BINDING_INVALID"


@pytest.mark.parametrize(
    "field",
    [
        "permit_atomically_consumed",
        "authenticated_terminal_journal_heads",
        "replay_absence_verified",
    ],
)
def test_offline_binding_rejects_live_consumption_or_replay_claims(field: str) -> None:
    policy, keys, calibration_permit = _permit_chain()
    raw = _binding(policy, keys, calibration_permit)
    raw[field] = True
    _signed(raw, ("A", "B"), hosted.DOMAIN_SUBMISSION_BINDING, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(raw, policy=policy, permit=calibration_permit)
    assert caught.value.code == "V631_SUBMISSION_BINDING_INVALID"


def test_creator_only_artifacts_reject_dataclass_replace_mutations() -> None:
    policy, _, binding, complete, agreements = _valid_chain()
    endpoint = hosted.validate_hosted_endpoint(
        policy=policy,
        binding=binding,
        complete=complete,
        agreements=agreements,
    )
    mutations = (
        lambda: replace(binding, receipt_sha256=_digest("other-binding-receipt")),
        lambda: replace(binding, permit_sha256=_digest("other-permit")),
        lambda: replace(binding, permit_id="other-permit-id"),
        lambda: replace(binding, archive_sha256=_digest("other-archive")),
        lambda: replace(binding, submission_ref="other-submission"),
        lambda: replace(binding, file_name="other.tar.gz"),
        lambda: replace(binding, message="other-message"),
        lambda: replace(binding, permit_issued_at=binding.permit_issued_at + timedelta(seconds=1)),
        lambda: replace(binding, permit_expires_at=binding.permit_expires_at + timedelta(seconds=1)),
        lambda: replace(binding, observed_at=binding.observed_at + timedelta(seconds=1)),
        lambda: replace(complete, submission_binding_sha256=_digest("other-binding")),
        lambda: replace(complete, receipt_sha256=_digest("other-complete-receipt")),
        lambda: replace(complete, t0=complete.t0 + timedelta(seconds=1)),
        lambda: replace(complete, observation_receipt_sha256s=(_digest("a"), _digest("b"))),
        lambda: replace(agreements[0], score="9999"),
        lambda: replace(agreements[0], receipt_sha256=_digest("other-poll-receipt")),
        lambda: replace(agreements[0], rank10_cutoff="1"),
        lambda: replace(
            agreements[0],
            collector_receipt_sha256s=(_digest("poll-a"), _digest("poll-b")),
        ),
        lambda: replace(endpoint, archive_sha256=_digest("endpoint-archive")),
        lambda: replace(endpoint, receipt_sha256=_digest("other-endpoint-receipt")),
        lambda: replace(endpoint, submission_ref="endpoint-submission"),
        lambda: replace(endpoint, t0=endpoint.t0 + timedelta(seconds=1)),
        lambda: replace(endpoint, poll_receipt_roots=tuple(reversed(endpoint.poll_receipt_roots))),
        lambda: replace(endpoint, yobs=Decimal("0")),
    )
    for mutate in mutations:
        with pytest.raises(ValueError):
            mutate()


def test_consumers_revalidate_retained_receipts_after_low_level_field_mutation() -> None:
    policy, keys, binding, complete, agreements = _valid_chain()

    forged_binding = copy(binding)
    object.__setattr__(forged_binding, "submission_ref", "forged-submission")
    with pytest.raises(V63Error) as caught:
        hosted.validate_complete_agreement(
            _complete(policy, keys, forged_binding),
            policy=policy,
            binding=forged_binding,
        )
    assert caught.value.code == "V631_TYPED_ARTIFACT_INTEGRITY_INVALID"

    forged_complete = copy(complete)
    object.__setattr__(forged_complete, "t0", complete.t0 + timedelta(seconds=1))
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_endpoint(
            policy=policy,
            binding=binding,
            complete=forged_complete,
            agreements=agreements,
        )
    assert caught.value.code == "V631_TYPED_ARTIFACT_INTEGRITY_INVALID"

    forged_poll = copy(agreements[0])
    object.__setattr__(forged_poll, "score", "9999")
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_endpoint(
            policy=policy,
            binding=binding,
            complete=complete,
            agreements=[forged_poll, *agreements[1:]],
        )
    assert caught.value.code == "V631_TYPED_ARTIFACT_INTEGRITY_INVALID"

    forged_roots = copy(agreements[0])
    object.__setattr__(
        forged_roots,
        "collector_receipt_sha256s",
        (_digest("forged-a"), _digest("forged-b")),
    )
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_endpoint(
            policy=policy,
            binding=binding,
            complete=complete,
            agreements=[forged_roots, *agreements[1:]],
        )
    assert caught.value.code == "V631_TYPED_ARTIFACT_INTEGRITY_INVALID"


def test_fractional_midpoint_skew_uses_exact_120_second_boundary() -> None:
    policy, keys, binding, complete, _ = _valid_chain()
    start = complete.t0 + timedelta(minutes=hosted.POLL_OFFSETS_MINUTES[1])

    poll_a = _poll(
        policy=policy,
        keys=keys,
        binding=binding,
        t0=complete.t0,
        party="A",
        index=1,
        score="700",
        cutoff="900",
    )
    poll_b = _poll(
        policy=policy,
        keys=keys,
        binding=binding,
        t0=complete.t0,
        party="B",
        index=1,
        score="700",
        cutoff="900",
    )
    poll_a["score_observed_at"] = poll_a["leaderboard_observed_at"] = _utc(start)
    poll_b["score_observed_at"] = poll_b["leaderboard_observed_at"] = _utc(
        start + timedelta(seconds=120)
    )
    _signed(poll_a, ("A",), hosted.DOMAIN_HOSTED_POLL, keys)
    _signed(poll_b, ("B",), hosted.DOMAIN_HOSTED_POLL, keys)
    agreement = _agreement(poll_a, poll_b, 1, keys)
    agreement["local_timestamp_skews_seconds"] = {"A": "0", "B": "0"}
    agreement["cross_collector_skew_seconds"] = "120"
    _signed(agreement, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, keys)
    accepted = hosted.validate_dual_collector_agreement(
        agreement,
        policy=policy,
        binding=binding,
        complete=complete,
        collector_a_poll=poll_a,
        collector_b_poll=poll_b,
        expected_poll_index=1,
    )
    assert accepted.poll_index == 1

    poll_b["leaderboard_observed_at"] = _utc(start + timedelta(seconds=121))
    _signed(poll_b, ("B",), hosted.DOMAIN_HOSTED_POLL, keys)
    agreement = _agreement(poll_a, poll_b, 1, keys)
    agreement["local_timestamp_skews_seconds"] = {"A": "0", "B": "1"}
    agreement["cross_collector_skew_seconds"] = "120.5"
    _signed(agreement, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, keys)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            agreement,
            policy=policy,
            binding=binding,
            complete=complete,
            collector_a_poll=poll_a,
            collector_b_poll=poll_b,
            expected_poll_index=1,
        )
    assert caught.value.code == "V631_DUAL_COLLECTOR_DISAGREEMENT"


def test_all_creator_outputs_are_explicit_offline_candidates() -> None:
    policy, _, binding, complete, agreements = _valid_chain()
    endpoint = hosted.validate_hosted_endpoint(
        policy=policy,
        binding=binding,
        complete=complete,
        agreements=agreements,
    )
    assert type(binding).__name__ == "OfflineSubmissionBindingCandidate"
    assert type(complete).__name__ == "OfflineCompleteAgreementCandidate"
    assert type(agreements[0]).__name__ == "OfflinePollAgreementCandidate"
    assert type(endpoint).__name__ == "OfflineHostedEndpointCandidate"
    assert all(
        artifact.offline_candidate_only is True
        for artifact in (binding, complete, agreements[0], endpoint)
    )
    assert all(
        getattr(artifact, field) is False
        for artifact in (binding, complete, agreements[0], endpoint)
        for field in (
            "permit_atomically_consumed",
            "authenticated_terminal_journal_heads",
            "replay_absence_verified",
        )
    )
    assert not any(
        hasattr(hosted, name)
        for name in (
            "ValidatedSubmissionBinding",
            "ValidatedCompleteAgreement",
            "ValidatedPollAgreement",
            "VerifiedHostedEndpoint",
        )
    )
