from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_3.common import SIGNATURE_SCHEMA, V63Error, canonical_sha256, key_id_for_public_key, signing_message
from evaluation_v6_3_1 import permit, policy
from tests.test_evaluation_v6_3_1_policy import _digest, _profile_with_keys


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


def _timestamp_fixture(
    validated_policy: policy.ValidatedV631Policy,
    precommit: permit.ValidatedPermitPrecommit,
) -> dict[str, Any]:
    d_oid, e_oid = (
        identity["tsa_policy_oid"] for identity in validated_policy["time_authorities"]
    )
    return {
        "schema": permit.TIMESTAMP_FIXTURE_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "precommit_sha256": precommit["sha256"],
        "payload_sha256": precommit["sha256"],
        "nonce": "v631-precommit-1",
        "d_policy_oid": d_oid,
        "e_policy_oid": e_oid,
        "d_token_sha256": _digest("tsa-d-token"),
        "e_token_sha256": _digest("tsa-e-token"),
        "d_gen_time": "2026-07-16T14:00:30Z",
        "e_gen_time": "2026-07-16T14:01:00Z",
        "d_signature_verified": True,
        "e_signature_verified": True,
    }


def _validated_timestamp(
    validated_policy: policy.ValidatedV631Policy,
    precommit: permit.ValidatedPermitPrecommit,
) -> permit.OfflineSyntheticTimestampQuorum:
    return permit.validate_synthetic_precommit_timestamp_fixture(
        _timestamp_fixture(validated_policy, precommit),
        policy=validated_policy,
        precommit=precommit,
    )


def _round_at(validated_policy: policy.ValidatedV631Policy, value: datetime) -> int:
    drand = validated_policy["drand"]
    offset = int(value.timestamp()) - drand["genesis_time_int"]
    assert offset >= 0 and offset % drand["period_seconds_int"] == 0
    return offset // drand["period_seconds_int"] + 1


def _empty_journal_state(
    validated_policy: policy.ValidatedV631Policy,
    campaign_root_sha256: str,
) -> permit.OfflineDualJournalPrefix:
    return permit.validate_offline_dual_journal_prefix(
        [],
        [],
        policy=validated_policy,
        campaign_root_sha256=campaign_root_sha256,
    )


def _consumption_entry(
    validated_policy: policy.ValidatedV631Policy,
    keys: dict[str, Ed25519PrivateKey],
    *,
    branch: str,
    sequence: int,
    previous_head: str,
    campaign_root: str,
    slot_id: str,
    archive_sha256: str,
    permit_receipt_sha256: str,
    created_at: str,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": permit.CALIBRATION_JOURNAL_ENTRY_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": campaign_root,
        "branch_party_id": branch,
        "journal_sequence": str(sequence),
        "previous_head_sha256": previous_head,
        "event_type": "CALIBRATION_PERMIT_CONSUMED",
        "permit_sequence": str(sequence),
        "slot_id": slot_id,
        "archive_sha256": archive_sha256,
        "permit_receipt_sha256": permit_receipt_sha256,
        "created_at": created_at,
    }
    return {
        **core,
        "signature": _signatures(core, (branch,), permit.DOMAIN_JOURNAL, keys)[0],
    }


def _chain() -> tuple[
    policy.ValidatedV631Policy,
    dict[str, Ed25519PrivateKey],
    permit.ValidatedPermitPrecommit,
    permit.OfflineSyntheticChallenge,
    dict[str, Any],
]:
    raw_policy, keys = _profile_with_keys()
    validated_policy = policy.validate_candidate_policy(raw_policy)
    campaign = _digest("campaign-v631")
    archive = _digest("archive-v631")
    assignment_root = _digest("assignment-v631")
    preregistration_root = _digest("preregistration-v631")
    readiness_root = _digest("readiness-v631")
    expires_at = "2026-07-16T14:19:00Z"
    round_number = _round_at(
        validated_policy,
        datetime(2026, 7, 16, 14, 4, tzinfo=timezone.utc),
    )
    sequence = 1
    slot = "D01"
    token = permit._content_token(  # type: ignore[attr-defined]
        campaign_root=campaign,
        sequence=sequence,
        slot_id=slot,
        archive_sha256=archive,
        assignment_root_sha256=assignment_root,
        preregistration_root_sha256=preregistration_root,
        readiness_snapshot_sha256=readiness_root,
        expires_at=expires_at,
        a_head=permit.GENESIS_SHA256,
        b_head=permit.GENESIS_SHA256,
    )
    raw_precommit = {
        "schema": permit.PRECOMMIT_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": campaign,
        "assignment_root_sha256": assignment_root,
        "preregistration_root_sha256": preregistration_root,
        "readiness_snapshot_sha256": readiness_root,
        "permit_sequence": "1",
        "slot_id": slot,
        "archive_sha256": archive,
        "competition_ref": "pokemon-tcg-ai-battle",
        "account_team_identifier": "team-garlictoday",
        "expected_file_name": f"cal-d01-{token}.tar.gz",
        "expected_message": f"cal-d01-{token}",
        "a_previous_journal_head_sha256": permit.GENESIS_SHA256,
        "b_previous_journal_head_sha256": permit.GENESIS_SHA256,
        "committed_drand_round": str(round_number),
        "precommit_created_at": "2026-07-16T14:00:00Z",
        "expires_at": expires_at,
        "calibration_budget_remaining_before": "16",
        "production_slots_remaining": "1",
    }
    precommit = permit.validate_permit_precommit(
        raw_precommit,
        policy=validated_policy,
        journal_state=_empty_journal_state(validated_policy, campaign),
    )
    timestamp_quorum = _validated_timestamp(validated_policy, precommit)
    challenge = permit.validate_synthetic_live_challenge_fixture(
        {
            "schema": permit.LIVE_CHALLENGE_SCHEMA,
            "policy_sha256": validated_policy["sha256"],
            "campaign_root_sha256": campaign,
            "slot_id": slot,
            "precommit_sha256": precommit["sha256"],
            "timestamp_quorum_receipt_sha256": timestamp_quorum.receipt_sha256,
            "drand_chain_hash": validated_policy["drand"]["chain_hash"],
            "drand_round": str(round_number),
            "randomness_sha256": _digest("randomness"),
            "drand_signature_sha256": _digest("signature"),
            "signature_verified": True,
            "observed_at": "2026-07-16T14:05:00Z",
        },
        policy=validated_policy,
        precommit=precommit,
        timestamp_quorum=timestamp_quorum,
    )
    issued = datetime(2026, 7, 16, 14, 6, tzinfo=timezone.utc)
    raw_permit: dict[str, Any] = {
        "schema": permit.PERMIT_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": campaign,
        "assignment_root_sha256": assignment_root,
        "preregistration_root_sha256": preregistration_root,
        "readiness_snapshot_sha256": readiness_root,
        "precommit_sha256": precommit["sha256"],
        "challenge_sha256": challenge.challenge_sha256,
        "permit_sequence": "1",
        "slot_id": slot,
        "archive_sha256": archive,
        "competition_ref": "pokemon-tcg-ai-battle",
        "account_team_identifier": "team-garlictoday",
        "expected_file_name": precommit["expected_file_name"],
        "expected_message": precommit["expected_message"],
        "a_previous_journal_head_sha256": permit.GENESIS_SHA256,
        "b_previous_journal_head_sha256": permit.GENESIS_SHA256,
        "issued_at": _utc(issued),
        "expires_at": precommit["expires_at"],
        "permit_id": "",
        "signatures": [],
    }
    core = {key: raw_permit[key] for key in raw_permit if key not in {"permit_id", "signatures"}}
    raw_permit["signatures"] = _signatures(core, ("A", "B"), permit.DOMAIN_PERMIT, keys)
    raw_permit["permit_id"] = canonical_sha256(
        {
            "domain": "V631/PERMIT-ID",
            "core_sha256": canonical_sha256(core),
            "signature_set_sha256": canonical_sha256(raw_permit["signatures"]),
        }
    )
    return validated_policy, keys, precommit, challenge, raw_permit


def test_dual_permit_is_structurally_valid_but_zero_authority() -> None:
    validated_policy, _, precommit, challenge, raw_permit = _chain()
    parsed = permit.validate_dual_calibration_permit(
        raw_permit,
        policy=validated_policy,
        precommit=precommit,
        challenge=challenge,
    )
    assert parsed.slot_id == "D01"
    assert parsed.offline_conformance_only is True
    report = permit.assess_dual_permit(
        raw_permit,
        policy=validated_policy,
        precommit=precommit,
        challenge=challenge,
    )
    assert report["state"] == "V631_DUAL_PERMIT_STRUCTURALLY_VALID_REQUIRES_LIVE_EXTERNAL_JOURNALS_AND_PIN"
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["production_slots_remaining"] == 1
    assert report["permits"] == []


def test_dual_permit_rejects_caller_reconstructed_precommit_mapping() -> None:
    validated_policy, _, precommit, challenge, raw_permit = _chain()
    forged_mapping = dict(precommit)
    with pytest.raises(V63Error) as caught:
        permit.validate_dual_calibration_permit(
            raw_permit,
            policy=validated_policy,
            precommit=forged_mapping,  # type: ignore[arg-type]
            challenge=challenge,
        )
    assert caught.value.code == "V631_DUAL_PERMIT_INVALID"


def test_complete_dual_journals_derive_budget_heads_and_consumed_indexes() -> None:
    raw_policy, keys = _profile_with_keys()
    validated_policy = policy.validate_candidate_policy(raw_policy)
    campaign = _digest("journal-campaign")
    archive = _digest("journal-archive")
    permit_receipt = _digest("journal-permit")
    a_entry = _consumption_entry(
        validated_policy,
        keys,
        branch="A",
        sequence=1,
        previous_head=permit.GENESIS_SHA256,
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=archive,
        permit_receipt_sha256=permit_receipt,
        created_at="2026-07-16T14:10:00Z",
    )
    b_entry = _consumption_entry(
        validated_policy,
        keys,
        branch="B",
        sequence=1,
        previous_head=permit.GENESIS_SHA256,
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=archive,
        permit_receipt_sha256=permit_receipt,
        created_at="2026-07-16T14:10:30Z",
    )
    state = permit.validate_offline_dual_journal_prefix(
        [a_entry], [b_entry], policy=validated_policy, campaign_root_sha256=campaign
    )
    assert state.next_permit_sequence == 2
    assert state.calibration_budget_remaining == 15
    assert state.production_slots_remaining == 1
    assert state.consumed_slot_ids == ("D01",)
    assert state.consumed_archive_sha256s == (archive,)
    assert state.heads == (canonical_sha256(a_entry), canonical_sha256(b_entry))


def test_complete_dual_journals_reject_fork_disagreement_and_replay() -> None:
    raw_policy, keys = _profile_with_keys()
    validated_policy = policy.validate_candidate_policy(raw_policy)
    campaign = _digest("journal-campaign-negative")
    archive = _digest("journal-archive-negative")
    receipt = _digest("journal-permit-negative")
    a1 = _consumption_entry(
        validated_policy,
        keys,
        branch="A",
        sequence=1,
        previous_head=permit.GENESIS_SHA256,
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=archive,
        permit_receipt_sha256=receipt,
        created_at="2026-07-16T14:10:00Z",
    )
    b1 = _consumption_entry(
        validated_policy,
        keys,
        branch="B",
        sequence=1,
        previous_head=permit.GENESIS_SHA256,
        campaign_root=campaign,
        slot_id="D02",
        archive_sha256=archive,
        permit_receipt_sha256=receipt,
        created_at="2026-07-16T14:10:00Z",
    )
    with pytest.raises(V63Error) as caught:
        permit.validate_offline_dual_journal_prefix(
            [a1], [b1], policy=validated_policy, campaign_root_sha256=campaign
        )
    assert caught.value.code == "V631_JOURNAL_PREFIX_INVALID"

    a2 = _consumption_entry(
        validated_policy,
        keys,
        branch="A",
        sequence=2,
        previous_head=canonical_sha256(a1),
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=_digest("journal-archive-2"),
        permit_receipt_sha256=_digest("journal-permit-2"),
        created_at="2026-07-16T14:20:00Z",
    )
    b1_matching = _consumption_entry(
        validated_policy,
        keys,
        branch="B",
        sequence=1,
        previous_head=permit.GENESIS_SHA256,
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=archive,
        permit_receipt_sha256=receipt,
        created_at="2026-07-16T14:10:00Z",
    )
    b2 = _consumption_entry(
        validated_policy,
        keys,
        branch="B",
        sequence=2,
        previous_head=canonical_sha256(b1_matching),
        campaign_root=campaign,
        slot_id="D01",
        archive_sha256=_digest("journal-archive-2"),
        permit_receipt_sha256=_digest("journal-permit-2"),
        created_at="2026-07-16T14:20:00Z",
    )
    with pytest.raises(V63Error) as caught:
        permit.validate_offline_dual_journal_prefix(
            [a1, a2],
            [b1_matching, b2],
            policy=validated_policy,
            campaign_root_sha256=campaign,
        )
    assert caught.value.code == "V631_JOURNAL_PREFIX_INVALID"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("archive_sha256", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
        ("assignment_root_sha256", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
        ("preregistration_root_sha256", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
        ("readiness_snapshot_sha256", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
        ("competition_ref", "other", "V631_DUAL_PERMIT_INVALID"),
        ("account_team_identifier", "other", "V631_DUAL_PERMIT_INVALID"),
        ("challenge_sha256", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
        ("permit_id", "0" * 64, "V631_DUAL_PERMIT_INVALID"),
    ],
)
def test_dual_permit_rejects_substitution(field: str, value: str, code: str) -> None:
    validated_policy, _, precommit, challenge, raw_permit = _chain()
    raw_permit[field] = value
    with pytest.raises(V63Error) as caught:
        permit.validate_dual_calibration_permit(
            raw_permit,
            policy=validated_policy,
            precommit=precommit,
            challenge=challenge,
        )
    assert caught.value.code == code


def test_precommit_preserves_budgets_and_content_derived_name() -> None:
    validated_policy, _, precommit, _, _ = _chain()
    broken = dict(precommit["raw"]) if "raw" in precommit else {
        key: precommit[key]
        for key in permit._PRECOMMIT_FIELDS  # type: ignore[attr-defined]
    }
    broken["production_slots_remaining"] = "0"
    with pytest.raises(V63Error) as caught:
        permit.validate_permit_precommit(
            broken,
            policy=validated_policy,
            journal_state=_empty_journal_state(
                validated_policy, precommit["campaign_root_sha256"]
            ),
        )
    assert caught.value.code == "V631_PERMIT_PRECOMMIT_INVALID"
    broken["production_slots_remaining"] = "1"
    broken["expected_message"] = "final"
    with pytest.raises(V63Error) as caught:
        permit.validate_permit_precommit(
            broken,
            policy=validated_policy,
            journal_state=_empty_journal_state(
                validated_policy, precommit["campaign_root_sha256"]
            ),
        )
    assert caught.value.code == "V631_PERMIT_PRECOMMIT_INVALID"
    broken["expected_message"] = precommit["expected_message"]
    broken["expires_at"] = "2026-07-16T14:20:00Z"
    with pytest.raises(V63Error) as caught:
        permit.validate_permit_precommit(
            broken,
            policy=validated_policy,
            journal_state=_empty_journal_state(
                validated_policy, precommit["campaign_root_sha256"]
            ),
        )
    assert caught.value.code == "V631_PERMIT_PRECOMMIT_INVALID"


def test_challenge_requires_exact_future_round_and_campaign_binding() -> None:
    validated_policy, _, precommit, _, _ = _chain()
    timestamp_quorum = _validated_timestamp(validated_policy, precommit)
    raw = {
        "schema": permit.LIVE_CHALLENGE_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "slot_id": precommit["slot_id"],
        "precommit_sha256": precommit["sha256"],
        "timestamp_quorum_receipt_sha256": timestamp_quorum.receipt_sha256,
        "drand_chain_hash": validated_policy["drand"]["chain_hash"],
        "drand_round": str(precommit["committed_drand_round_int"] - 1),
        "randomness_sha256": _digest("randomness"),
        "drand_signature_sha256": _digest("signature"),
        "signature_verified": True,
        "observed_at": "2026-07-16T14:05:00Z",
    }
    with pytest.raises(V63Error) as caught:
        permit.validate_synthetic_live_challenge_fixture(
            raw,
            policy=validated_policy,
            precommit=precommit,
            timestamp_quorum=timestamp_quorum,
        )
    assert caught.value.code == "V631_LIVE_CHALLENGE_INVALID"


def test_challenge_binds_timestamp_receipt_and_requires_a_future_round() -> None:
    validated_policy, _, precommit, _, _ = _chain()
    raw_timestamp = _timestamp_fixture(validated_policy, precommit)
    timestamp_quorum = permit.validate_synthetic_precommit_timestamp_fixture(
        raw_timestamp,
        policy=validated_policy,
        precommit=precommit,
    )
    raw_challenge = {
        "schema": permit.LIVE_CHALLENGE_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "slot_id": precommit["slot_id"],
        "precommit_sha256": precommit["sha256"],
        "timestamp_quorum_receipt_sha256": "0" * 64,
        "drand_chain_hash": validated_policy["drand"]["chain_hash"],
        "drand_round": precommit["committed_drand_round"],
        "randomness_sha256": _digest("randomness"),
        "drand_signature_sha256": _digest("signature"),
        "signature_verified": True,
        "observed_at": "2026-07-16T14:05:00Z",
    }
    with pytest.raises(V63Error) as caught:
        permit.validate_synthetic_live_challenge_fixture(
            raw_challenge,
            policy=validated_policy,
            precommit=precommit,
            timestamp_quorum=timestamp_quorum,
        )
    assert caught.value.code == "V631_LIVE_CHALLENGE_INVALID"

    raw_timestamp["d_gen_time"] = "2026-07-16T14:04:01Z"
    raw_timestamp["e_gen_time"] = "2026-07-16T14:04:02Z"
    late_timestamp_quorum = permit.validate_synthetic_precommit_timestamp_fixture(
        raw_timestamp,
        policy=validated_policy,
        precommit=precommit,
    )
    raw_challenge["timestamp_quorum_receipt_sha256"] = late_timestamp_quorum.receipt_sha256
    with pytest.raises(V63Error) as caught:
        permit.validate_synthetic_live_challenge_fixture(
            raw_challenge,
            policy=validated_policy,
            precommit=precommit,
            timestamp_quorum=late_timestamp_quorum,
        )
    assert caught.value.code == "V631_LIVE_CHALLENGE_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payload_sha256", "0" * 64),
        ("d_policy_oid", "1.2.3"),
        ("e_signature_verified", False),
        ("e_token_sha256", _digest("tsa-d-token")),
        ("d_gen_time", "2026-07-16T13:59:59Z"),
    ],
)
def test_timestamp_quorum_rejects_substitution(field: str, value: Any) -> None:
    validated_policy, _, precommit, _, _ = _chain()
    raw = _timestamp_fixture(validated_policy, precommit)
    raw[field] = value
    with pytest.raises(V63Error) as caught:
        permit.validate_synthetic_precommit_timestamp_fixture(
            raw,
            policy=validated_policy,
            precommit=precommit,
        )
    assert caught.value.code == "V631_TIMESTAMP_QUORUM_INVALID"


def test_journal_successor_binds_branch_previous_head_and_sequence() -> None:
    validated_policy, keys, precommit, _, _ = _chain()
    raw: dict[str, Any] = {
        "schema": permit.JOURNAL_ENTRY_SCHEMA,
        "policy_sha256": validated_policy["sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "branch_party_id": "A",
        "sequence": "1",
        "previous_head_sha256": permit.GENESIS_SHA256,
        "event_type": "PERMIT_PRECOMMIT",
        "event_sha256": precommit["sha256"],
        "created_at": "2026-07-16T14:00:01Z",
        "signature": {},
    }
    core = {key: raw[key] for key in raw if key != "signature"}
    raw["signature"] = _signatures(core, ("A",), permit.DOMAIN_JOURNAL, keys)[0]
    parsed = permit.validate_journal_successor(
        raw,
        policy=validated_policy,
        campaign_root_sha256=precommit["campaign_root_sha256"],
        expected_branch="A",
        expected_sequence=1,
        expected_previous_head=permit.GENESIS_SHA256,
        expected_event_type="PERMIT_PRECOMMIT",
        expected_event_sha256=precommit["sha256"],
    )
    assert parsed["sequence_int"] == 1
    broken = deepcopy(raw)
    broken["previous_head_sha256"] = _digest("other-head")
    with pytest.raises(V63Error) as caught:
        permit.validate_journal_successor(
            broken,
            policy=validated_policy,
            campaign_root_sha256=precommit["campaign_root_sha256"],
            expected_branch="A",
            expected_sequence=1,
            expected_previous_head=permit.GENESIS_SHA256,
            expected_event_type="PERMIT_PRECOMMIT",
            expected_event_sha256=precommit["sha256"],
        )
    assert caught.value.code == "V631_AUDITOR_JOURNAL_INVALID"


def test_validated_types_cannot_be_forged() -> None:
    with pytest.raises(ValueError):
        permit.ValidatedPermitPrecommit(
            fields={},
            offline_conformance_only=True,
            _construction_token=object(),
        )
    with pytest.raises(ValueError):
        permit.OfflineSyntheticTimestampQuorum(
            receipt_sha256=_digest("receipt"),
            precommit_sha256=_digest("precommit"),
            campaign_root_sha256=_digest("campaign"),
            token_sha256s=(_digest("token-d"), _digest("token-e")),
            policy_oids=("1.2.3", "1.2.4"),
            nonce="nonce",
            gen_times=(datetime.now(timezone.utc), datetime.now(timezone.utc)),
            offline_fixture_only=True,
            _construction_token=object(),
        )
    with pytest.raises(ValueError):
        permit.OfflineSyntheticChallenge(
            receipt_sha256=_digest("receipt"),
            precommit_sha256=_digest("precommit"),
            campaign_root_sha256=_digest("campaign"),
            timestamp_quorum_receipt_sha256=_digest("timestamp-quorum"),
            slot_id="D01",
            committed_round=1,
            round_scheduled_at=datetime.now(timezone.utc),
            randomness_sha256=_digest("random"),
            drand_signature_sha256=_digest("signature"),
            challenge_sha256=_digest("challenge"),
            observed_at=datetime.now(timezone.utc),
            offline_fixture_only=True,
            _construction_token=object(),
        )


def test_verifier_issued_artifacts_reject_replace_and_low_level_mutation() -> None:
    validated_policy, _, precommit, challenge, raw_permit = _chain()
    parsed_permit = permit.validate_dual_calibration_permit(
        raw_permit,
        policy=validated_policy,
        precommit=precommit,
        challenge=challenge,
    )

    altered_precommit = replace(
        precommit,
        fields={**dict(precommit.fields), "archive_sha256": _digest("substituted-archive")},
    )
    with pytest.raises(V63Error) as caught:
        permit.validate_dual_calibration_permit(
            raw_permit,
            policy=validated_policy,
            precommit=altered_precommit,
            challenge=challenge,
        )
    assert caught.value.code == "V631_DUAL_PERMIT_INVALID"

    altered_challenge = replace(challenge, challenge_sha256=_digest("substituted-challenge"))
    with pytest.raises(V63Error) as caught:
        permit.validate_dual_calibration_permit(
            raw_permit,
            policy=validated_policy,
            precommit=precommit,
            challenge=altered_challenge,
        )
    assert caught.value.code == "V631_DUAL_PERMIT_INVALID"

    journal = _empty_journal_state(validated_policy, precommit["campaign_root_sha256"])
    altered_journal = replace(journal, next_permit_sequence=2)
    raw_precommit = {
        key: precommit[key]
        for key in permit._PRECOMMIT_FIELDS  # type: ignore[attr-defined]
    }
    with pytest.raises(V63Error) as caught:
        permit.validate_permit_precommit(
            raw_precommit,
            policy=validated_policy,
            journal_state=altered_journal,
        )
    assert caught.value.code == "V631_PERMIT_PRECOMMIT_INVALID"

    altered_permit = replace(parsed_permit, archive_sha256=_digest("substituted-permit-archive"))
    with pytest.raises(V63Error) as caught:
        permit.require_offline_calibration_permit_candidate(altered_permit)
    assert caught.value.code == "V631_DUAL_PERMIT_INVALID"

    object.__setattr__(parsed_permit, "permit_sequence", 2)
    with pytest.raises(V63Error) as caught:
        permit.require_offline_calibration_permit_candidate(parsed_permit)
    assert caught.value.code == "V631_DUAL_PERMIT_INVALID"
