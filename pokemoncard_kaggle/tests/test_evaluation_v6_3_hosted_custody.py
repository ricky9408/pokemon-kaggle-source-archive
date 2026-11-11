from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3.common import SIGNATURE_SCHEMA, V63Error, canonical_sha256, signing_message
from evaluation_v6_3 import hosted_custody as hosted
from tests.test_evaluation_v6_3_hybrid_trust import _digest, _profile_fixture


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _signatures(
    core: dict[str, Any],
    parties: tuple[str, ...],
    domain: bytes,
    private: dict[str, Ed25519PrivateKey],
) -> list[dict[str, str]]:
    return [
        {
            "schema": SIGNATURE_SCHEMA,
            "party_id": party,
            "key_id": "ed25519-sha256:" + hashlib.sha256(private[party].public_key().public_bytes_raw()).hexdigest(),
            "signature_base64": base64.b64encode(private[party].sign(signing_message(domain, core))).decode("ascii"),
        }
        for party in sorted(parties)
    ]


def _signed(
    value: dict[str, Any],
    parties: tuple[str, ...],
    domain: bytes,
    private: dict[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    value["signatures"] = _signatures(
        {key: value[key] for key in value if key != "signatures"},
        parties,
        domain,
        private,
    )
    return value


def _tls() -> dict[str, Any]:
    return {
        "schema": hosted.TLS_PEER_SCHEMA,
        "hostname": "api.kaggle.com",
        "certificate_chain_sha256": _digest("tls-chain"),
        "spki_sha256": _digest("tls-spki"),
        "peer_policy_pin_sha256": _digest("tls-policy"),
        "authenticated": True,
    }


def _authorization(
    profile: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    campaign = _digest("campaign")
    archive = _digest("archive")
    challenge = _digest("live-challenge")
    token = hosted.submission_token(
        campaign_root_sha256=campaign,
        slot_id="D01",
        archive_sha256=archive,
        live_challenge_sha256=challenge,
    )
    value = {
        "schema": hosted.UPLOAD_AUTHORIZATION_SCHEMA,
        "profile_sha256": profile["sha256"],
        "campaign_root_sha256": campaign,
        "slot_id": "D01",
        "competition_ref": "pokemon-tcg-ai-battle",
        "account_team_identifier": profile["hosted_transport_policy"]["account_team_identifier"],
        "archive_sha256": archive,
        "archive_byte_length": "4096",
        "package_sha256": _digest("package"),
        "source_tree_sha256": _digest("source"),
        "build_recipe_sha256": _digest("build"),
        "linux_amd64_reproducibility_receipt_root_sha256": _digest("linux-repro"),
        "live_challenge_sha256": challenge,
        "approved_extension": ".tar.gz",
        "expected_file_name": f"cal-d01-{token}.tar.gz",
        "expected_message": f"cal-d01-{token}",
        "submission_token": token,
        "uploader_party_id": "A",
        "witness_party_id": "B",
        "custody_reviewer_party_id": "C",
        "uploader_build_root_sha256": _digest("uploader-build"),
        "uploader_runtime_root_sha256": _digest("uploader-runtime"),
        "upload_window_start": "2026-07-16T11:00:00Z",
        "upload_window_end": "2026-07-16T11:30:00Z",
        "pre_upload_history_root_a_sha256": hosted.submission_history_root([]),
        "pre_upload_history_root_b_sha256": hosted.submission_history_root([]),
    }
    return _signed(value, ("A", "B", "C"), hosted.DOMAIN_UPLOAD_AUTHORIZATION, private)


def _file_identity(archive_sha256: str) -> dict[str, Any]:
    return {
        "schema": hosted.FILE_IDENTITY_SCHEMA,
        "path_token_sha256": _digest("path-token"),
        "device_id": "1",
        "inode": "2",
        "file_size": "4096",
        "mtime_ns": "100",
        "sha256": archive_sha256,
    }


def _transport(
    authorization: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    identity = _file_identity(authorization["archive_sha256"])
    value = {
        "schema": hosted.UPLOAD_TRANSPORT_SCHEMA,
        "authorization_sha256": canonical_sha256(authorization),
        "archive_file_identity_before": deepcopy(identity),
        "archive_file_identity_after": deepcopy(identity),
        "streamed_archive_sha256": authorization["archive_sha256"],
        "streamed_archive_byte_length": "4096",
        "request_response_transcript_root_sha256": _digest("transcript"),
        "tls_peer_identity": _tls(),
        "raw_upload_response_evidence_id": "upload-response-1",
        "raw_upload_response_header_sha256": _digest("response-header"),
        "raw_upload_response_body_sha256": _digest("response-body"),
        "raw_upload_response_byte_length": "128",
        "upload_start": "2026-07-16T11:05:00Z",
        "upload_end": "2026-07-16T11:06:00Z",
        "uploader_party_id": "A",
        "host_signed_archive_digest_present": False,
    }
    return _signed(value, ("A",), hosted.DOMAIN_UPLOAD_TRANSPORT, private)


def _record(authorization: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": hosted.SUBMISSION_RECORD_SCHEMA,
        "ref": "submission-ref-1",
        "file_name": authorization["expected_file_name"],
        "date": "2026-07-16T11:05:30Z",
        "description": authorization["expected_message"],
        "status": "PENDING",
        "public_score": None,
    }


def _binding(
    authorization: dict[str, Any],
    transport: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
) -> dict[str, Any]:
    record = _record(authorization)
    pre_records: list[dict[str, Any]] = []
    post_records = [deepcopy(record)]
    value = {
        "schema": hosted.SUBMISSION_BINDING_SCHEMA,
        "authorization_sha256": canonical_sha256(authorization),
        "transport_receipt_sha256": canonical_sha256(transport),
        "collector_a_pre_history_root_sha256": authorization["pre_upload_history_root_a_sha256"],
        "collector_a_post_history_root_sha256": hosted.submission_history_root(post_records),
        "collector_b_pre_history_root_sha256": authorization["pre_upload_history_root_b_sha256"],
        "collector_b_post_history_root_sha256": hosted.submission_history_root(post_records),
        "collector_a_pre_records": deepcopy(pre_records),
        "collector_a_post_records": deepcopy(post_records),
        "collector_b_pre_records": deepcopy(pre_records),
        "collector_b_post_records": deepcopy(post_records),
        "collector_a_new_records": [deepcopy(record)],
        "collector_b_new_records": [deepcopy(record)],
        "matched_submission_ref": record["ref"],
        "exact_matching_decision": "EXACTLY_ONE",
    }
    return _signed(value, ("A", "B"), hosted.DOMAIN_SUBMISSION_BINDING, private)


def _validated_chain() -> tuple[
    dict[str, Any],
    dict[str, Ed25519PrivateKey],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    raw_transport = _transport(raw_authorization, private)
    transport = hosted.validate_upload_transport(
        raw_transport,
        profile=profile,
        authorization=authorization,
    )
    raw_binding = _binding(raw_authorization, raw_transport, private)
    binding = hosted.validate_submission_binding(
        raw_binding,
        profile=profile,
        authorization=authorization,
        transport=transport,
    )
    return profile, private, authorization, transport, binding


def _complete_agreement(
    profile: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
    binding: dict[str, Any],
) -> dict[str, Any]:
    observations = {}
    for party, observed_at in (("A", "2026-07-16T12:00:00Z"), ("B", "2026-07-16T12:01:00Z")):
        value = {
            "schema": hosted.COMPLETE_OBSERVATION_SCHEMA,
            "profile_sha256": profile["sha256"],
            "binding_receipt_sha256": binding["sha256"],
            "collector_party_id": party,
            "submission_ref": binding["matched_submission_ref"],
            "status": "COMPLETE",
            "observed_at": observed_at,
            "raw_response_sha256": _digest(f"complete-{party}"),
            "tls_peer_identity": _tls(),
        }
        observations[party] = _signed(value, (party,), hosted.DOMAIN_COMPLETE_OBSERVATION, private)
    agreement = {
        "schema": hosted.COMPLETE_AGREEMENT_SCHEMA,
        "collector_a_observation": observations["A"],
        "collector_b_observation": observations["B"],
    }
    return _signed(agreement, ("A", "B"), hosted.DOMAIN_COMPLETE_AGREEMENT, private)


def _poll(
    *,
    profile: dict[str, Any],
    binding: dict[str, Any],
    private: dict[str, Ed25519PrivateKey],
    t0: datetime,
    party: str,
    index: int,
    score: str,
    cutoff: str,
    extra_seconds: int = 0,
) -> dict[str, Any]:
    start = t0 + timedelta(minutes=hosted.POLL_OFFSETS_MINUTES[index])
    party_offset = 0 if party == "A" else 10
    score_time = start + timedelta(seconds=5 + party_offset + extra_seconds)
    leaderboard_time = start + timedelta(seconds=20 + party_offset + extra_seconds)
    value = {
        "schema": hosted.HOSTED_POLL_SCHEMA,
        "profile_sha256": profile["sha256"],
        "binding_receipt_sha256": binding["sha256"],
        "collector_party_id": party,
        "poll_index": str(index),
        "scheduled_window_start": _utc(start),
        "scheduled_window_end": _utc(start + timedelta(seconds=600)),
        "submission_ref": binding["matched_submission_ref"],
        "file_name": binding["file_name"],
        "description": binding["description"],
        "status": "COMPLETE",
        "submission_response_sha256": _digest(f"submission-{party}-{index}"),
        "leaderboard_response_sha256": _digest(f"leaderboard-{party}-{index}"),
        "score_observed_at": _utc(score_time),
        "leaderboard_observed_at": _utc(leaderboard_time),
        "parsed_score": score,
        "parsed_rank10_cutoff": cutoff,
        "tls_peer_identity": _tls(),
    }
    return _signed(value, (party,), hosted.DOMAIN_HOSTED_POLL, private)


def _agreement(
    *,
    poll_a: dict[str, Any],
    poll_b: dict[str, Any],
    index: int,
    private: dict[str, Ed25519PrivateKey],
    cross_skew: str = "10",
) -> dict[str, Any]:
    value = {
        "schema": hosted.DUAL_AGREEMENT_SCHEMA,
        "poll_index": str(index),
        "collector_receipt_sha256s": {"A": canonical_sha256(poll_a), "B": canonical_sha256(poll_b)},
        "parsed_equality_vector": {
            "description": True,
            "file_name": True,
            "parsed_rank10_cutoff": True,
            "parsed_score": True,
            "status": True,
            "submission_ref": True,
        },
        "local_timestamp_skews_seconds": {"A": "15", "B": "15"},
        "cross_collector_skew_seconds": cross_skew,
        "accepted_attempt_index": "1",
        "agreement_result": "AGREE",
    }
    return _signed(value, ("A", "B"), hosted.DOMAIN_DUAL_AGREEMENT, private)


def _poll_agreements() -> tuple[
    dict[str, Any],
    dict[str, Ed25519PrivateKey],
    dict[str, Any],
    datetime,
    list[dict[str, Any]],
]:
    profile, private, _, _, binding = _validated_chain()
    complete = hosted.validate_complete_agreement(
        _complete_agreement(profile, private, binding),
        profile=profile,
        binding=binding,
    )
    t0 = complete["t0"]
    agreements = []
    for index, score in enumerate(("900", "910", "920", "930"), start=1):
        poll_a = _poll(profile=profile, binding=binding, private=private, t0=t0, party="A", index=index, score=score, cutoff="1100")
        poll_b = _poll(profile=profile, binding=binding, private=private, t0=t0, party="B", index=index, score=score, cutoff="1100")
        agreements.append(
            hosted.validate_dual_collector_agreement(
                _agreement(poll_a=poll_a, poll_b=poll_b, index=index, private=private),
                profile=profile,
                binding=binding,
                t0=t0,
                collector_a_poll=poll_a,
                collector_b_poll=poll_b,
                expected_poll_index=index,
            )
        )
    return profile, private, binding, t0, agreements


def _limitations() -> dict[str, Any]:
    return {
        "schema": hosted.LIMITATIONS_SCHEMA,
        "host_signed_archive_digest": False,
        "host_signed_execution_receipt": False,
        "host_signed_outcome_receipt": False,
        "exact_archive_persisted_by_host_proven": False,
        "exact_archive_executed_by_host_proven": False,
        "hosted_observations_nonrepudiable": False,
        "evidence_class": hosted.EVIDENCE_CLASS,
    }


def test_complete_hosted_chain_builds_only_research_endpoint() -> None:
    _, _, _, _, agreements = _poll_agreements()
    endpoint = hosted.validate_four_poll_endpoint(agreements)
    assert endpoint["poll_count"] == 4
    assert endpoint["yobs_median_score_minus_rank10_cutoff"] == "-185"
    report = hosted.assess_observational_hosted_endpoint(limitations=_limitations(), agreements=agreements)
    assert report["observational_endpoint_structurally_valid"] is True
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["permits"] == []


def test_project_controlled_uploader_is_rejected() -> None:
    raw_profile, _, private = _profile_fixture()
    raw_profile["audit_branches"][0]["identity"]["project_access_role"] = "READ_ONLY"
    from evaluation_v6_3.hybrid_trust import validate_hybrid_trust_profile

    profile = validate_hybrid_trust_profile(raw_profile)
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_authorization(_authorization(profile, private), profile=profile)
    assert caught.value.code == "UPLOAD_OPERATOR_NOT_AUDITOR_CONTROLLED"


def test_authorization_cannot_be_reused_for_another_archive() -> None:
    _, profile, private = _profile_fixture()
    authorization = _authorization(profile, private)
    authorization["archive_sha256"] = _digest("other-archive")
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_authorization(authorization, profile=profile)
    assert caught.value.code == "UPLOAD_AUTHORIZATION_INVALID"


@pytest.mark.parametrize("field", ["competition_ref", "account_team_identifier"])
def test_authorization_is_bound_to_profile_transport_and_account(field: str) -> None:
    _, profile, private = _profile_fixture()
    authorization = _authorization(profile, private)
    authorization[field] = "wrong-profile-value"
    _signed(authorization, ("A", "B", "C"), hosted.DOMAIN_UPLOAD_AUTHORIZATION, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_authorization(authorization, profile=profile)
    assert caught.value.code == "UPLOAD_AUTHORIZATION_INVALID"


def test_authorization_requires_canonical_signature_order() -> None:
    _, profile, private = _profile_fixture()
    authorization = _authorization(profile, private)
    authorization["signatures"].reverse()
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_authorization(authorization, profile=profile)
    assert caught.value.code == "UPLOAD_AUTHORIZATION_INVALID"


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda value: value["archive_file_identity_after"].__setitem__("mtime_ns", "101"), "UPLOAD_TOCTOU_DETECTED"),
        (lambda value: value.__setitem__("streamed_archive_sha256", _digest("mutated-stream")), "ARCHIVE_UPLOAD_HASH_MISMATCH"),
        (lambda value: value.__setitem__("streamed_archive_byte_length", "4095"), "UPLOAD_STREAM_LENGTH_MISMATCH"),
        (lambda value: value["tls_peer_identity"].__setitem__("hostname", "evil.example"), "TLS_PEER_AUTHENTICATION_FAILED"),
        (lambda value: value["tls_peer_identity"].__setitem__("peer_policy_pin_sha256", _digest("wrong-peer-policy")), "TLS_PEER_AUTHENTICATION_FAILED"),
        (lambda value: value.__setitem__("raw_upload_response_body_sha256", None), "UPLOAD_RESPONSE_UNAVAILABLE"),
        (lambda value: value.__setitem__("host_signed_archive_digest_present", True), "HOST_CUSTODY_CLAIM_OVERSTATED"),
    ],
)
def test_transport_rejects_toctou_stream_tls_response_and_overclaim(mutation: Any, expected_code: str) -> None:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    transport = _transport(raw_authorization, private)
    mutation(transport)
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_transport(transport, profile=profile, authorization=authorization)
    assert caught.value.code == expected_code


@pytest.mark.parametrize(
    ("records", "expected_code"),
    [([], "SUBMISSION_BINDING_ZERO_MATCH"), (["duplicate"], "SUBMISSION_BINDING_AMBIGUOUS")],
)
def test_submission_binding_requires_exactly_one_record(records: list[str], expected_code: str) -> None:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    raw_transport = _transport(raw_authorization, private)
    transport = hosted.validate_upload_transport(raw_transport, profile=profile, authorization=authorization)
    binding = _binding(raw_authorization, raw_transport, private)
    if not records:
        for party in ("a", "b"):
            binding[f"collector_{party}_post_records"] = []
            binding[f"collector_{party}_post_history_root_sha256"] = hosted.submission_history_root([])
            binding[f"collector_{party}_new_records"] = []
    else:
        duplicate = deepcopy(binding["collector_a_new_records"][0])
        duplicate["ref"] = "submission-ref-2"
        for party in ("a", "b"):
            binding[f"collector_{party}_post_records"].append(deepcopy(duplicate))
            binding[f"collector_{party}_post_history_root_sha256"] = hosted.submission_history_root(binding[f"collector_{party}_post_records"])
            binding[f"collector_{party}_new_records"].append(deepcopy(duplicate))
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(binding, profile=profile, authorization=authorization, transport=transport)
    assert caught.value.code == expected_code


def test_submission_binding_rejects_metadata_disagreement() -> None:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    raw_transport = _transport(raw_authorization, private)
    transport = hosted.validate_upload_transport(raw_transport, profile=profile, authorization=authorization)
    binding = _binding(raw_authorization, raw_transport, private)
    binding["collector_b_new_records"][0]["description"] = "wrong"
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(binding, profile=profile, authorization=authorization, transport=transport)
    assert caught.value.code == "SUBMISSION_METADATA_MISMATCH"


def test_submission_binding_must_reuse_signed_pre_history_roots() -> None:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    raw_transport = _transport(raw_authorization, private)
    transport = hosted.validate_upload_transport(raw_transport, profile=profile, authorization=authorization)
    binding = _binding(raw_authorization, raw_transport, private)
    binding["collector_a_pre_history_root_sha256"] = _digest("substituted-pre-history")
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(binding, profile=profile, authorization=authorization, transport=transport)
    assert caught.value.code == "SUBMISSION_METADATA_MISMATCH"


def test_preexisting_matching_record_cannot_be_bound_as_new() -> None:
    _, profile, private = _profile_fixture()
    raw_authorization = _authorization(profile, private)
    record = _record(raw_authorization)
    pre_root = hosted.submission_history_root([record])
    raw_authorization["pre_upload_history_root_a_sha256"] = pre_root
    raw_authorization["pre_upload_history_root_b_sha256"] = pre_root
    _signed(raw_authorization, ("A", "B", "C"), hosted.DOMAIN_UPLOAD_AUTHORIZATION, private)
    authorization = hosted.validate_upload_authorization(raw_authorization, profile=profile)
    raw_transport = _transport(raw_authorization, private)
    transport = hosted.validate_upload_transport(raw_transport, profile=profile, authorization=authorization)
    binding = _binding(raw_authorization, raw_transport, private)
    for party in ("a", "b"):
        binding[f"collector_{party}_pre_records"] = [deepcopy(record)]
        binding[f"collector_{party}_post_records"] = [deepcopy(record)]
        binding[f"collector_{party}_pre_history_root_sha256"] = pre_root
        binding[f"collector_{party}_post_history_root_sha256"] = pre_root
        binding[f"collector_{party}_new_records"] = []
    with pytest.raises(V63Error) as caught:
        hosted.validate_submission_binding(binding, profile=profile, authorization=authorization, transport=transport)
    assert caught.value.code == "SUBMISSION_BINDING_ZERO_MATCH"


def test_complete_requires_two_observations_within_120_seconds() -> None:
    profile, private, _, _, binding = _validated_chain()
    agreement = _complete_agreement(profile, private, binding)
    agreement["collector_b_observation"]["observed_at"] = "2026-07-16T12:03:00Z"
    _signed(agreement["collector_b_observation"], ("B",), hosted.DOMAIN_COMPLETE_OBSERVATION, private)
    _signed(agreement, ("A", "B"), hosted.DOMAIN_COMPLETE_AGREEMENT, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_complete_agreement(agreement, profile=profile, binding=binding)
    assert caught.value.code == "COMPLETE_OBSERVATION_DISAGREEMENT"


def test_poll_rejects_local_and_cross_collector_skew() -> None:
    profile, private, _, _, binding = _validated_chain()
    complete = hosted.validate_complete_agreement(_complete_agreement(profile, private, binding), profile=profile, binding=binding)
    t0 = complete["t0"]
    poll_a = _poll(profile=profile, binding=binding, private=private, t0=t0, party="A", index=1, score="900", cutoff="1100")
    poll_b = _poll(profile=profile, binding=binding, private=private, t0=t0, party="B", index=1, score="900", cutoff="1100")
    poll_a["leaderboard_observed_at"] = _utc(t0 + timedelta(minutes=61, seconds=10))
    _signed(poll_a, ("A",), hosted.DOMAIN_HOSTED_POLL, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            _agreement(poll_a=poll_a, poll_b=poll_b, index=1, private=private),
            profile=profile,
            binding=binding,
            t0=t0,
            collector_a_poll=poll_a,
            collector_b_poll=poll_b,
            expected_poll_index=1,
        )
    assert caught.value.code == "CUTOFF_NOT_SYNCHRONIZED"
    poll_a = _poll(profile=profile, binding=binding, private=private, t0=t0, party="A", index=1, score="900", cutoff="1100")
    poll_b = _poll(profile=profile, binding=binding, private=private, t0=t0, party="B", index=1, score="900", cutoff="1100", extra_seconds=130)
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            _agreement(poll_a=poll_a, poll_b=poll_b, index=1, private=private, cross_skew="140"),
            profile=profile,
            binding=binding,
            t0=t0,
            collector_a_poll=poll_a,
            collector_b_poll=poll_b,
            expected_poll_index=1,
        )
    assert caught.value.code == "DUAL_COLLECTOR_DISAGREEMENT"


def test_poll_rejects_score_disagreement_and_pre_maturity_600() -> None:
    profile, private, _, _, binding = _validated_chain()
    complete = hosted.validate_complete_agreement(_complete_agreement(profile, private, binding), profile=profile, binding=binding)
    t0 = complete["t0"]
    poll_a = _poll(profile=profile, binding=binding, private=private, t0=t0, party="A", index=1, score="900", cutoff="1100")
    poll_b = _poll(profile=profile, binding=binding, private=private, t0=t0, party="B", index=1, score="901", cutoff="1100")
    with pytest.raises(V63Error) as caught:
        hosted.validate_dual_collector_agreement(
            _agreement(poll_a=poll_a, poll_b=poll_b, index=1, private=private),
            profile=profile,
            binding=binding,
            t0=t0,
            collector_a_poll=poll_a,
            collector_b_poll=poll_b,
            expected_poll_index=1,
        )
    assert caught.value.code == "DUAL_COLLECTOR_DISAGREEMENT"
    poll = _poll(profile=profile, binding=binding, private=private, t0=t0, party="A", index=1, score="600.0", cutoff="1100")
    poll["score_observed_at"] = _utc(t0 + timedelta(minutes=59))
    _signed(poll, ("A",), hosted.DOMAIN_HOSTED_POLL, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_poll(poll, profile=profile, binding=binding, t0=t0, expected_party_id="A", expected_poll_index=1)
    assert caught.value.code == "POLL_OUTSIDE_WINDOW"


def test_three_of_four_cannot_form_endpoint_and_preserves_zero_authority() -> None:
    _, _, _, _, agreements = _poll_agreements()
    with pytest.raises(V63Error) as caught:
        hosted.validate_four_poll_endpoint(agreements[:3])
    assert caught.value.code == "MATURE_POLL_MISSING"
    report = hosted.assess_observational_hosted_endpoint(limitations=_limitations(), agreements=agreements[:3])
    assert report["state"] == "MATURE_POLL_MISSING"
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False


def test_endpoint_rejects_unvalidated_agreement_dictionaries() -> None:
    forged = [
        {"poll_index": index, "score": "9999", "rank10_cutoff": "1"}
        for index in range(1, 5)
    ]
    with pytest.raises(V63Error) as caught:
        hosted.validate_four_poll_endpoint(forged)  # type: ignore[arg-type]
    assert caught.value.code == "HOSTED_EVIDENCE_INCOMPLETE"
    malformed = [
        hosted.ValidatedPollAgreement(
            receipt_sha256=_digest(f"agreement-{index}"),
            poll_index=index,
            score="not-a-score",
            rank10_cutoff="1",
            cross_collector_skew_seconds=0,
        )
        for index in range(1, 5)
    ]
    report = hosted.assess_observational_hosted_endpoint(limitations=_limitations(), agreements=malformed)
    assert report["state"] == "HOSTED_EVIDENCE_INCOMPLETE"
    assert report["production_upload_authorized"] is False


def test_hosted_boundary_rejects_unvalidated_profile_mapping() -> None:
    _, profile, private = _profile_fixture()
    forged_profile = dict(profile)
    with pytest.raises(V63Error) as caught:
        hosted.validate_upload_authorization(_authorization(forged_profile, private), profile=forged_profile)  # type: ignore[arg-type]
    assert caught.value.code == "UPLOAD_AUTHORIZATION_INVALID"


def test_out_of_band_upload_invalidates_account_chronology() -> None:
    profile, private, _, _, binding = _validated_chain()
    complete = hosted.validate_complete_agreement(_complete_agreement(profile, private, binding), profile=profile, binding=binding)
    t0 = complete["t0"]
    record = _record(_authorization(profile, private))

    def snapshots(party: str) -> list[dict[str, Any]]:
        times = [
            datetime(2026, 7, 16, 11, 4, tzinfo=timezone.utc),
            datetime(2026, 7, 16, 11, 59, tzinfo=timezone.utc),
            t0 + timedelta(minutes=60, seconds=30),
            t0 + timedelta(minutes=120, seconds=30),
            t0 + timedelta(minutes=240, seconds=30),
            t0 + timedelta(minutes=480, seconds=30),
        ]
        if party == "B":
            times = [value + timedelta(seconds=30) for value in times]
        checkpoints = ("PRE_UPLOAD", "POST_BINDING", "T1", "T2", "T3", "T4")
        return [
            {
                "schema": hosted.ACCOUNT_SNAPSHOT_SCHEMA,
                "checkpoint": checkpoint,
                "observed_at": _utc(observed_at),
                "raw_response_sha256": _digest(f"account-{party}-{checkpoint}"),
                "canonical_records_root_sha256": hosted.submission_history_root([] if index == 0 else [record]),
                "records": [] if index == 0 else [deepcopy(record)],
            }
            for index, (checkpoint, observed_at) in enumerate(zip(checkpoints, times, strict=True))
        ]

    value = {
        "schema": hosted.ACCOUNT_CHRONOLOGY_SCHEMA,
        "profile_sha256": profile["sha256"],
        "binding_receipt_sha256": binding["sha256"],
        "monitoring_start": "2026-07-16T11:00:00Z",
        "monitoring_end": "2026-07-16T20:10:00Z",
        "collector_a_snapshots": snapshots("A"),
        "collector_b_snapshots": snapshots("B"),
    }
    _signed(value, ("A", "B", "C"), hosted.DOMAIN_ACCOUNT_CHRONOLOGY, private)
    assert hosted.validate_account_chronology(value, profile=profile, binding=binding, t0=t0)["monitoring_end"] == datetime(2026, 7, 16, 20, 10, tzinfo=timezone.utc)
    reordered = deepcopy(value)
    reordered["collector_a_snapshots"][1]["observed_at"] = _utc(t0 + timedelta(seconds=90))
    reordered["collector_b_snapshots"][1]["observed_at"] = _utc(t0 + timedelta(seconds=120))
    reordered["collector_a_snapshots"][2]["observed_at"] = _utc(t0 + timedelta(seconds=60))
    reordered["collector_b_snapshots"][2]["observed_at"] = _utc(t0 + timedelta(seconds=90))
    _signed(reordered, ("A", "B", "C"), hosted.DOMAIN_ACCOUNT_CHRONOLOGY, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_account_chronology(reordered, profile=profile, binding=binding, t0=t0)
    assert caught.value.code == "OUT_OF_BAND_UPLOAD_DETECTED"
    unexpected = deepcopy(record)
    unexpected["ref"] = "submission-ref-2"
    for field in ("collector_a_snapshots", "collector_b_snapshots"):
        value[field][3]["records"].append(deepcopy(unexpected))
        value[field][3]["canonical_records_root_sha256"] = hosted.submission_history_root(value[field][3]["records"])
    _signed(value, ("A", "B", "C"), hosted.DOMAIN_ACCOUNT_CHRONOLOGY, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_account_chronology(value, profile=profile, binding=binding, t0=t0)
    assert caught.value.code == "OUT_OF_BAND_UPLOAD_DETECTED"


def test_episode_link_requires_explicit_submission_id_mapping() -> None:
    profile, private, _, _, binding = _validated_chain()
    value = {
        "schema": hosted.EPISODE_CHRONOLOGY_SCHEMA,
        "profile_sha256": profile["sha256"],
        "binding_receipt_sha256": binding["sha256"],
        "matched_submission_ref": binding["matched_submission_ref"],
        "collector_a_raw_episode_root_sha256": _digest("episodes-a"),
        "collector_b_raw_episode_root_sha256": _digest("episodes-b"),
        "explicit_submission_id_mapping_evidence_sha256": None,
        "explicit_submission_id": None,
        "ordered_episode_records": [],
        "episode_link_status": "UNIDENTIFIED",
        "no_inferred_join": True,
    }
    _signed(value, ("A", "B"), hosted.DOMAIN_EPISODE_CHRONOLOGY, private)
    result = hosted.validate_episode_chronology(value, profile=profile, binding=binding)
    assert result["episode_claims_authorized"] is False
    value["ordered_episode_records"] = [{"inferred": True}]
    _signed(value, ("A", "B"), hosted.DOMAIN_EPISODE_CHRONOLOGY, private)
    with pytest.raises(V63Error) as caught:
        hosted.validate_episode_chronology(value, profile=profile, binding=binding)
    assert caught.value.code == "EPISODE_LINK_UNIDENTIFIED"


def test_host_limitations_reject_execution_or_signature_overclaim() -> None:
    limitations = _limitations()
    assert hosted.validate_hosted_limitations(limitations)["evidence_class"] == hosted.EVIDENCE_CLASS
    limitations["exact_archive_executed_by_host_proven"] = True
    with pytest.raises(V63Error) as caught:
        hosted.validate_hosted_limitations(limitations)
    assert caught.value.code == "HOST_CUSTODY_CLAIM_OVERSTATED"
