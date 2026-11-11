"""Offline verifier for v6.3.1 dual-auditor calibration-permit candidates.

This module has no Kaggle client, credential handler, uploader, mutable replay
store, or production-permit type. A structurally valid receipt remains
non-authoritative while ``PINNED_V631_POLICY`` is ``None`` and until the two
external journals are independently acquired live.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .common import (
    V63Error,
    canonical_integer,
    canonical_sha256,
    exact,
    fail,
    freeze,
    sha256,
    utc,
    verify_signature_set,
    zero_authority,
)
from .policy import ValidatedV631Policy, require_validated_policy


PRECOMMIT_SCHEMA = "eval.v6.3.1.permit-precommit"
LIVE_CHALLENGE_SCHEMA = "eval.v6.3.1.synthetic-live-challenge-fixture"
TIMESTAMP_FIXTURE_SCHEMA = "eval.v6.3.1.synthetic-precommit-timestamp-fixture"
PERMIT_SCHEMA = "eval.v6.3.1.calibration-permit"
JOURNAL_ENTRY_SCHEMA = "eval.v6.3.1.auditor-journal-entry"
CALIBRATION_JOURNAL_ENTRY_SCHEMA = "eval.v6.3.1.calibration-consumption-journal-entry"

DOMAIN_PERMIT = b"EVAL-V631/CALIBRATION-PERMIT\0"
DOMAIN_JOURNAL = b"EVAL-V631/AUDITOR-JOURNAL\0"

SLOTS = (
    *(f"D{index:02d}" for index in range(1, 7)),
    "DR01",
    *(f"C{index:02d}" for index in range(1, 9)),
    "CR01",
)
GENESIS_SHA256 = "0" * 64
PERMIT_TTL_SECONDS = 900

_PRECOMMIT_SENTINEL = object()
_CHALLENGE_SENTINEL = object()
_TIMESTAMP_SENTINEL = object()
_PERMIT_SENTINEL = object()
_DUAL_JOURNAL_SENTINEL = object()

_ISSUED_PRECOMMITS: dict[int, tuple[object, str]] = {}
_ISSUED_CHALLENGES: dict[int, tuple[object, str]] = {}
_ISSUED_TIMESTAMPS: dict[int, tuple[object, str]] = {}
_ISSUED_PERMITS: dict[int, tuple[object, str]] = {}
_ISSUED_DUAL_JOURNALS: dict[int, tuple[object, str]] = {}


@dataclass(frozen=True)
class ValidatedPermitPrecommit(Mapping[str, Any]):
    """Verifier-created immutable precommit used only by offline conformance code."""

    fields: Mapping[str, Any]
    offline_conformance_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _PRECOMMIT_SENTINEL:
            raise ValueError(
                "ValidatedPermitPrecommit can only be created by validate_permit_precommit"
            )
        if self.offline_conformance_only is not True:
            raise ValueError("v6.3.1 precommit candidates must remain offline-only")

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def __iter__(self):
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)


@dataclass(frozen=True)
class OfflineSyntheticChallenge:
    receipt_sha256: str
    precommit_sha256: str
    campaign_root_sha256: str
    timestamp_quorum_receipt_sha256: str
    slot_id: str
    committed_round: int
    round_scheduled_at: datetime
    randomness_sha256: str
    drand_signature_sha256: str
    challenge_sha256: str
    observed_at: datetime
    offline_fixture_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _CHALLENGE_SENTINEL:
            raise ValueError(
                "OfflineSyntheticChallenge can only be created by the synthetic fixture verifier"
            )


@dataclass(frozen=True)
class OfflineSyntheticTimestampQuorum:
    receipt_sha256: str
    precommit_sha256: str
    campaign_root_sha256: str
    token_sha256s: tuple[str, str]
    policy_oids: tuple[str, str]
    nonce: str
    gen_times: tuple[datetime, datetime]
    offline_fixture_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _TIMESTAMP_SENTINEL:
            raise ValueError(
                "OfflineSyntheticTimestampQuorum can only be created by the synthetic fixture verifier"
            )


@dataclass(frozen=True)
class OfflineCalibrationPermitCandidate:
    receipt_sha256: str
    permit_id: str
    precommit_sha256: str
    challenge_sha256: str
    campaign_root_sha256: str
    assignment_root_sha256: str
    preregistration_root_sha256: str
    readiness_snapshot_sha256: str
    permit_sequence: int
    slot_id: str
    archive_sha256: str
    expected_file_name: str
    expected_message: str
    issued_at: datetime
    expires_at: datetime
    journal_heads: tuple[str, str]
    offline_conformance_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _PERMIT_SENTINEL:
            raise ValueError(
                "OfflineCalibrationPermitCandidate can only be created by the offline permit verifier"
            )


@dataclass(frozen=True)
class OfflineDualJournalPrefix:
    """State derived from caller-provided, mutually consistent synthetic A/B prefixes."""

    campaign_root_sha256: str
    next_permit_sequence: int
    calibration_budget_remaining: int
    production_slots_remaining: int
    heads: tuple[str, str]
    consumed_slot_ids: tuple[str, ...]
    consumed_archive_sha256s: tuple[str, ...]
    receipt_sha256: str
    offline_conformance_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _DUAL_JOURNAL_SENTINEL:
            raise ValueError(
                "OfflineDualJournalPrefix can only be created by validate_offline_dual_journal_prefix"
            )
        if self.offline_conformance_only is not True:
            raise ValueError("v6.3.1 journal state must remain offline-only")


def _fingerprint_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if isinstance(value, Mapping):
        return {key: _fingerprint_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_fingerprint_value(item) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    raise TypeError(f"unsupported typed-artifact field: {type(value).__name__}")


def _artifact_fingerprint(value: Any) -> str:
    if type(value) is ValidatedPermitPrecommit:
        payload = {
            "type": "ValidatedPermitPrecommit",
            "fields": _fingerprint_value(value.fields),
            "offline_conformance_only": value.offline_conformance_only,
        }
    elif type(value) is OfflineSyntheticChallenge:
        payload = {
            "type": "OfflineSyntheticChallenge",
            **{
                name: _fingerprint_value(getattr(value, name))
                for name in (
                    "receipt_sha256",
                    "precommit_sha256",
                    "campaign_root_sha256",
                    "timestamp_quorum_receipt_sha256",
                    "slot_id",
                    "committed_round",
                    "round_scheduled_at",
                    "randomness_sha256",
                    "drand_signature_sha256",
                    "challenge_sha256",
                    "observed_at",
                    "offline_fixture_only",
                )
            },
        }
    elif type(value) is OfflineSyntheticTimestampQuorum:
        payload = {
            "type": "OfflineSyntheticTimestampQuorum",
            **{
                name: _fingerprint_value(getattr(value, name))
                for name in (
                    "receipt_sha256",
                    "precommit_sha256",
                    "campaign_root_sha256",
                    "token_sha256s",
                    "policy_oids",
                    "nonce",
                    "gen_times",
                    "offline_fixture_only",
                )
            },
        }
    elif type(value) is OfflineCalibrationPermitCandidate:
        payload = {
            "type": "OfflineCalibrationPermitCandidate",
            **{
                name: _fingerprint_value(getattr(value, name))
                for name in (
                    "receipt_sha256",
                    "permit_id",
                    "precommit_sha256",
                    "challenge_sha256",
                    "campaign_root_sha256",
                    "assignment_root_sha256",
                    "preregistration_root_sha256",
                    "readiness_snapshot_sha256",
                    "permit_sequence",
                    "slot_id",
                    "archive_sha256",
                    "expected_file_name",
                    "expected_message",
                    "issued_at",
                    "expires_at",
                    "journal_heads",
                    "offline_conformance_only",
                )
            },
        }
    elif type(value) is OfflineDualJournalPrefix:
        payload = {
            "type": "OfflineDualJournalPrefix",
            **{
                name: _fingerprint_value(getattr(value, name))
                for name in (
                    "campaign_root_sha256",
                    "next_permit_sequence",
                    "calibration_budget_remaining",
                    "production_slots_remaining",
                    "heads",
                    "consumed_slot_ids",
                    "consumed_archive_sha256s",
                    "receipt_sha256",
                    "offline_conformance_only",
                )
            },
        }
    else:
        raise TypeError("unsupported typed permit artifact")
    return canonical_sha256(payload)


def _issue(value: Any, registry: dict[int, tuple[object, str]]) -> Any:
    registry[id(value)] = (value, _artifact_fingerprint(value))
    return value


def _require_issued(
    value: Any,
    expected_type: type,
    registry: Mapping[int, tuple[object, str]],
    *,
    code: str,
    label: str,
) -> Any:
    record = registry.get(id(value))
    if type(value) is not expected_type or record is None or record[0] is not value:
        raise fail(code, f"{label} was not issued by its verifier")
    expected_token = {
        ValidatedPermitPrecommit: _PRECOMMIT_SENTINEL,
        OfflineSyntheticChallenge: _CHALLENGE_SENTINEL,
        OfflineSyntheticTimestampQuorum: _TIMESTAMP_SENTINEL,
        OfflineCalibrationPermitCandidate: _PERMIT_SENTINEL,
        OfflineDualJournalPrefix: _DUAL_JOURNAL_SENTINEL,
    }[expected_type]
    if value._construction_token is not expected_token:
        raise fail(code, f"{label} construction token was mutated")
    try:
        fingerprint = _artifact_fingerprint(value)
    except (TypeError, ValueError, AttributeError) as exc:
        raise fail(code, f"{label} is malformed") from exc
    if fingerprint != record[1]:
        raise fail(code, f"{label} was mutated after verification")
    return value


def require_offline_calibration_permit_candidate(
    value: Any,
    *,
    code: str = "V631_DUAL_PERMIT_INVALID",
) -> OfflineCalibrationPermitCandidate:
    """Require the exact immutable offline permit object issued by this module."""

    return _require_issued(
        value,
        OfflineCalibrationPermitCandidate,
        _ISSUED_PERMITS,
        code=code,
        label="offline calibration permit candidate",
    )


_PRECOMMIT_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "assignment_root_sha256",
        "preregistration_root_sha256",
        "readiness_snapshot_sha256",
        "permit_sequence",
        "slot_id",
        "archive_sha256",
        "competition_ref",
        "account_team_identifier",
        "expected_file_name",
        "expected_message",
        "a_previous_journal_head_sha256",
        "b_previous_journal_head_sha256",
        "committed_drand_round",
        "precommit_created_at",
        "expires_at",
        "calibration_budget_remaining_before",
        "production_slots_remaining",
    }
)


def _content_token(
    *,
    campaign_root: str,
    sequence: int,
    slot_id: str,
    archive_sha256: str,
    assignment_root_sha256: str,
    preregistration_root_sha256: str,
    readiness_snapshot_sha256: str,
    expires_at: str,
    a_head: str,
    b_head: str,
) -> str:
    return canonical_sha256(
        {
            "domain": "V631/SUBMISSION-TOKEN",
            "campaign_root_sha256": campaign_root,
            "permit_sequence": sequence,
            "slot_id": slot_id,
            "archive_sha256": archive_sha256,
            "assignment_root_sha256": assignment_root_sha256,
            "preregistration_root_sha256": preregistration_root_sha256,
            "readiness_snapshot_sha256": readiness_snapshot_sha256,
            "expires_at": expires_at,
            "a_previous_journal_head_sha256": a_head,
            "b_previous_journal_head_sha256": b_head,
        }
    )[:24]


_CALIBRATION_JOURNAL_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "branch_party_id",
        "journal_sequence",
        "previous_head_sha256",
        "event_type",
        "permit_sequence",
        "slot_id",
        "archive_sha256",
        "permit_receipt_sha256",
        "created_at",
        "signature",
    }
)


def _validate_calibration_journal_branch(
    values: Any,
    *,
    policy: ValidatedV631Policy,
    campaign_root_sha256: str,
    branch_party_id: str,
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    code = "V631_JOURNAL_PREFIX_INVALID"
    if type(values) not in {list, tuple}:
        raise fail(code, f"{branch_party_id} journal prefix must be an ordered list")
    previous_head = GENESIS_SHA256
    parsed: list[Mapping[str, Any]] = []
    for expected_sequence, raw in enumerate(values, start=1):
        item = exact(
            raw,
            _CALIBRATION_JOURNAL_FIELDS,
            f"journal prefix {branch_party_id} entry {expected_sequence}",
            code=code,
        )
        if (
            item["schema"] != CALIBRATION_JOURNAL_ENTRY_SCHEMA
            or item["policy_sha256"] != policy["sha256"]
            or item["campaign_root_sha256"] != campaign_root_sha256
            or item["branch_party_id"] != branch_party_id
            or item["previous_head_sha256"] != previous_head
            or item["event_type"] != "CALIBRATION_PERMIT_CONSUMED"
        ):
            raise fail(code, "journal branch contains a fork, rollback, or foreign event")
        journal_sequence = canonical_integer(
            item["journal_sequence"], "journal sequence", code=code, minimum=1
        )
        permit_sequence = canonical_integer(
            item["permit_sequence"], "permit sequence", code=code, minimum=1
        )
        if journal_sequence != expected_sequence or permit_sequence != expected_sequence:
            raise fail(code, "journal sequence must be contiguous and equal permit consumption order")
        if item["slot_id"] not in SLOTS:
            raise fail(code, "journal contains an unknown calibration slot")
        archive = sha256(item["archive_sha256"], "journal archive", code=code)
        permit_receipt = sha256(
            item["permit_receipt_sha256"], "journal permit receipt", code=code
        )
        created_at = utc(item["created_at"], "journal created_at", code=code)
        core = {key: item[key] for key in item if key != "signature"}
        verify_signature_set(
            [item["signature"]],
            core=core,
            domain=DOMAIN_JOURNAL,
            identities=policy["identities"],
            required_party_ids=(branch_party_id,),
            code=code,
        )
        previous_head = canonical_sha256(item)
        parsed.append(
            freeze(
                {
                    **dict(item),
                    "journal_sequence_int": journal_sequence,
                    "permit_sequence_int": permit_sequence,
                    "archive_sha256": archive,
                    "permit_receipt_sha256": permit_receipt,
                    "created_at_dt": created_at,
                    "head_sha256": previous_head,
                }
            )
        )
    return tuple(parsed), previous_head


def validate_offline_dual_journal_prefix(
    a_entries: Any,
    b_entries: Any,
    *,
    policy: ValidatedV631Policy,
    campaign_root_sha256: str,
) -> OfflineDualJournalPrefix:
    """Check a synthetic A/B prefix; this is never proof of live completeness."""

    policy = require_validated_policy(policy)
    code = "V631_JOURNAL_PREFIX_INVALID"
    campaign_root = sha256(campaign_root_sha256, "campaign root", code=code)
    a_parsed, a_head = _validate_calibration_journal_branch(
        a_entries,
        policy=policy,
        campaign_root_sha256=campaign_root,
        branch_party_id="A",
    )
    b_parsed, b_head = _validate_calibration_journal_branch(
        b_entries,
        policy=policy,
        campaign_root_sha256=campaign_root,
        branch_party_id="B",
    )
    if len(a_parsed) != len(b_parsed):
        raise fail(code, "A/B journal prefixes have different lengths")
    slots: list[str] = []
    archives: list[str] = []
    for a_item, b_item in zip(a_parsed, b_parsed, strict=True):
        fields = (
            "permit_sequence_int",
            "slot_id",
            "archive_sha256",
            "permit_receipt_sha256",
            "event_type",
        )
        if any(a_item[field] != b_item[field] for field in fields):
            raise fail(code, "A/B journals disagree about a consumed calibration permit")
        if abs(a_item["created_at_dt"] - b_item["created_at_dt"]) > timedelta(seconds=120):
            raise fail(code, "A/B consumption records differ by more than 120 seconds")
        slots.append(a_item["slot_id"])
        archives.append(a_item["archive_sha256"])
    if len(set(slots)) != len(slots) or len(set(archives)) != len(archives):
        raise fail(code, "a calibration slot or archive was consumed more than once")
    if len(slots) > 16:
        raise fail(code, "calibration journal exceeds the 16-upload budget")
    next_sequence = len(slots) + 1
    receipt = canonical_sha256(
        {
            "schema": "eval.v6.3.1.complete-dual-journal-state",
            "policy_sha256": policy["sha256"],
            "campaign_root_sha256": campaign_root,
            "a_head_sha256": a_head,
            "b_head_sha256": b_head,
            "consumed_slot_ids": slots,
            "consumed_archive_sha256s": archives,
            "next_permit_sequence": next_sequence,
            "calibration_budget_remaining": 16 - len(slots),
            "production_slots_remaining": 1,
        }
    )
    return _issue(
        OfflineDualJournalPrefix(
            campaign_root_sha256=campaign_root,
            next_permit_sequence=next_sequence,
            calibration_budget_remaining=16 - len(slots),
            production_slots_remaining=1,
            heads=(a_head, b_head),
            consumed_slot_ids=tuple(slots),
            consumed_archive_sha256s=tuple(archives),
            receipt_sha256=receipt,
            offline_conformance_only=True,
            _construction_token=_DUAL_JOURNAL_SENTINEL,
        ),
        _ISSUED_DUAL_JOURNALS,
    )


def validate_permit_precommit(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    journal_state: OfflineDualJournalPrefix,
) -> ValidatedPermitPrecommit:
    policy = require_validated_policy(policy)
    code = "V631_PERMIT_PRECOMMIT_INVALID"
    _require_issued(
        journal_state,
        OfflineDualJournalPrefix,
        _ISSUED_DUAL_JOURNALS,
        code=code,
        label="offline dual-journal prefix",
    )
    item = exact(value, _PRECOMMIT_FIELDS, "permit precommit", code=code)
    if item["schema"] != PRECOMMIT_SCHEMA or item["policy_sha256"] != policy["sha256"]:
        raise fail(code, "permit precommit is not bound to the candidate policy")
    campaign_root = sha256(item["campaign_root_sha256"], "campaign root", code=code)
    if campaign_root != journal_state.campaign_root_sha256:
        raise fail(code, "precommit campaign differs from the complete journal state")
    archive = sha256(item["archive_sha256"], "archive hash", code=code)
    assignment_root = sha256(item["assignment_root_sha256"], "assignment root", code=code)
    preregistration_root = sha256(
        item["preregistration_root_sha256"],
        "preregistration root",
        code=code,
    )
    readiness_root = sha256(
        item["readiness_snapshot_sha256"],
        "readiness snapshot root",
        code=code,
    )
    a_head = sha256(item["a_previous_journal_head_sha256"], "A previous journal head", code=code)
    b_head = sha256(item["b_previous_journal_head_sha256"], "B previous journal head", code=code)
    sequence = canonical_integer(item["permit_sequence"], "permit sequence", code=code, minimum=1)
    if sequence > 16:
        raise fail(code, "permit sequence exceeds the calibration budget")
    slot_id = item["slot_id"]
    if type(slot_id) is not str or slot_id not in SLOTS:
        raise fail(code, "permit slot is outside the frozen population")
    if sequence != journal_state.next_permit_sequence:
        raise fail(code, "permit sequence is not the next unconsumed journal sequence")
    if slot_id in journal_state.consumed_slot_ids or archive in journal_state.consumed_archive_sha256s:
        raise fail(code, "precommit attempts to replay a consumed calibration slot or archive")
    if item["competition_ref"] != policy["kaggle"]["competition_ref"] or item[
        "account_team_identifier"
    ] != policy["kaggle"]["account_team_identifier"]:
        raise fail(code, "permit precommit uses the wrong Kaggle competition or account")
    remaining = canonical_integer(
        item["calibration_budget_remaining_before"],
        "calibration budget remaining",
        code=code,
        minimum=1,
    )
    if (
        remaining != journal_state.calibration_budget_remaining
        or remaining != 17 - sequence
        or item["production_slots_remaining"] != "1"
        or journal_state.production_slots_remaining != 1
    ):
        raise fail(code, "permit precommit violates the disjoint calibration/production ledgers")
    if (a_head, b_head) != journal_state.heads:
        raise fail(code, "precommit journal heads were not derived from the complete A/B histories")
    committed_round = canonical_integer(
        item["committed_drand_round"],
        "committed drand round",
        code=code,
        minimum=1,
    )
    created_at = utc(item["precommit_created_at"], "precommit created_at", code=code)
    expires_at = utc(item["expires_at"], "permit expires_at", code=code)
    round_scheduled_at = datetime.fromtimestamp(
        policy["drand"]["genesis_time_int"]
        + (committed_round - 1) * policy["drand"]["period_seconds_int"],
        tz=timezone.utc,
    )
    if created_at >= round_scheduled_at:
        raise fail(code, "permit precommit must precede the selected future drand round")
    if expires_at != round_scheduled_at + timedelta(seconds=PERMIT_TTL_SECONDS):
        raise fail(code, "permit expiry must be exactly 15 minutes after the selected round")
    token = _content_token(
        campaign_root=campaign_root,
        sequence=sequence,
        slot_id=slot_id,
        archive_sha256=archive,
        assignment_root_sha256=assignment_root,
        preregistration_root_sha256=preregistration_root,
        readiness_snapshot_sha256=readiness_root,
        expires_at=item["expires_at"],
        a_head=a_head,
        b_head=b_head,
    )
    expected_name = f"cal-{slot_id.lower()}-{token}.tar.gz"
    expected_message = f"cal-{slot_id.lower()}-{token}"
    if item["expected_file_name"] != expected_name or item["expected_message"] != expected_message:
        raise fail(code, "permit precommit filename or message is not content-derived")
    if "final" in expected_name.casefold() or "final" in expected_message.casefold():
        raise fail(code, "submission naming must not contain final")
    return _issue(
        ValidatedPermitPrecommit(
            fields=freeze(
                {
                    **dict(item),
                    "sha256": canonical_sha256(item),
                    "campaign_root_sha256": campaign_root,
                    "archive_sha256": archive,
                    "assignment_root_sha256": assignment_root,
                    "preregistration_root_sha256": preregistration_root,
                    "readiness_snapshot_sha256": readiness_root,
                    "permit_sequence_int": sequence,
                    "committed_drand_round_int": committed_round,
                    "precommit_created_at_dt": created_at,
                    "expires_at_dt": expires_at,
                    "round_scheduled_at_dt": round_scheduled_at,
                    "a_previous_journal_head_sha256": a_head,
                    "b_previous_journal_head_sha256": b_head,
                }
            ),
            offline_conformance_only=True,
            _construction_token=_PRECOMMIT_SENTINEL,
        ),
        _ISSUED_PRECOMMITS,
    )


_CHALLENGE_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "slot_id",
        "precommit_sha256",
        "timestamp_quorum_receipt_sha256",
        "drand_chain_hash",
        "drand_round",
        "randomness_sha256",
        "drand_signature_sha256",
        "signature_verified",
        "observed_at",
    }
)

_TIMESTAMP_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "precommit_sha256",
        "payload_sha256",
        "nonce",
        "d_policy_oid",
        "e_policy_oid",
        "d_token_sha256",
        "e_token_sha256",
        "d_gen_time",
        "e_gen_time",
        "d_signature_verified",
        "e_signature_verified",
    }
)


def validate_synthetic_precommit_timestamp_fixture(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    precommit: ValidatedPermitPrecommit,
) -> OfflineSyntheticTimestampQuorum:
    """Validate an offline D/E timestamp fixture without granting authority."""
    policy = require_validated_policy(policy)
    code = "V631_TIMESTAMP_QUORUM_INVALID"
    _require_issued(
        precommit,
        ValidatedPermitPrecommit,
        _ISSUED_PRECOMMITS,
        code=code,
        label="permit precommit",
    )
    item = exact(value, _TIMESTAMP_FIELDS, "synthetic precommit timestamp", code=code)
    expected_oids = tuple(identity["tsa_policy_oid"] for identity in policy["time_authorities"])
    if (
        item["schema"] != TIMESTAMP_FIXTURE_SCHEMA
        or item["policy_sha256"] != policy["sha256"]
        or item["campaign_root_sha256"] != precommit["campaign_root_sha256"]
        or item["precommit_sha256"] != precommit["sha256"]
        or item["payload_sha256"] != precommit["sha256"]
        or (item["d_policy_oid"], item["e_policy_oid"]) != expected_oids
        or item["d_signature_verified"] is not True
        or item["e_signature_verified"] is not True
    ):
        raise fail(code, "timestamp fixture is not a verified 2/2 quorum over the exact precommit")
    token_hashes = (
        sha256(item["d_token_sha256"], "D timestamp token", code=code),
        sha256(item["e_token_sha256"], "E timestamp token", code=code),
    )
    if token_hashes[0] == token_hashes[1]:
        raise fail(code, "D and E timestamp tokens must be distinct")
    if type(item["nonce"]) is not str or not item["nonce"] or item["nonce"].strip() != item["nonce"]:
        raise fail(code, "timestamp nonce must be canonical and nonempty")
    gen_times = (
        utc(item["d_gen_time"], "D genTime", code=code),
        utc(item["e_gen_time"], "E genTime", code=code),
    )
    if any(time <= precommit["precommit_created_at_dt"] for time in gen_times):
        raise fail(code, "timestamp tokens must postdate the precommit")
    if abs(gen_times[1] - gen_times[0]) > timedelta(seconds=120):
        raise fail(code, "D/E timestamp genTimes differ by more than 120 seconds")
    return _issue(
        OfflineSyntheticTimestampQuorum(
            receipt_sha256=canonical_sha256(item),
            precommit_sha256=precommit["sha256"],
            campaign_root_sha256=precommit["campaign_root_sha256"],
            token_sha256s=token_hashes,
            policy_oids=expected_oids,
            nonce=item["nonce"],
            gen_times=gen_times,
            offline_fixture_only=True,
            _construction_token=_TIMESTAMP_SENTINEL,
        ),
        _ISSUED_TIMESTAMPS,
    )


def validate_synthetic_live_challenge_fixture(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    precommit: ValidatedPermitPrecommit,
    timestamp_quorum: OfflineSyntheticTimestampQuorum,
) -> OfflineSyntheticChallenge:
    """Validate a synthetic fixture only; it can never advance authority."""
    policy = require_validated_policy(policy)
    code = "V631_LIVE_CHALLENGE_INVALID"
    _require_issued(
        precommit,
        ValidatedPermitPrecommit,
        _ISSUED_PRECOMMITS,
        code=code,
        label="permit precommit",
    )
    _require_issued(
        timestamp_quorum,
        OfflineSyntheticTimestampQuorum,
        _ISSUED_TIMESTAMPS,
        code=code,
        label="synthetic timestamp quorum",
    )
    if (
        timestamp_quorum.precommit_sha256 != precommit["sha256"]
        or timestamp_quorum.offline_fixture_only is not True
    ):
        raise fail(code, "challenge requires a verifier-created 2/2 precommit timestamp quorum")
    item = exact(value, _CHALLENGE_FIELDS, "synthetic live challenge", code=code)
    if (
        item["schema"] != LIVE_CHALLENGE_SCHEMA
        or item["policy_sha256"] != policy["sha256"]
        or item["campaign_root_sha256"] != precommit["campaign_root_sha256"]
        or item["slot_id"] != precommit["slot_id"]
        or item["precommit_sha256"] != precommit["sha256"]
        or item["timestamp_quorum_receipt_sha256"] != timestamp_quorum.receipt_sha256
        or item["drand_chain_hash"] != policy["drand"]["chain_hash"]
    ):
        raise fail(code, "live challenge is not bound to policy, campaign, slot, and precommit")
    round_number = canonical_integer(item["drand_round"], "drand round", code=code, minimum=1)
    if round_number != precommit["committed_drand_round_int"] or item["signature_verified"] is not True:
        raise fail(code, "drand round differs from the future commitment or is unverified")
    randomness = sha256(item["randomness_sha256"], "drand randomness", code=code)
    signature = sha256(item["drand_signature_sha256"], "drand signature", code=code)
    observed_at = utc(item["observed_at"], "challenge observed_at", code=code)
    round_scheduled_at = datetime.fromtimestamp(
        policy["drand"]["genesis_time_int"]
        + (round_number - 1) * policy["drand"]["period_seconds_int"],
        tz=timezone.utc,
    )
    if max(timestamp_quorum.gen_times) >= round_scheduled_at:
        raise fail(code, "selected drand round was not in the future after both timestamp tokens")
    if observed_at < round_scheduled_at:
        raise fail(code, "challenge claims to observe the drand round before its scheduled time")
    challenge = canonical_sha256(
        {
            "domain": "V631/PERMIT-CHALLENGE",
            "precommit_sha256": precommit["sha256"],
            "timestamp_quorum_receipt_sha256": timestamp_quorum.receipt_sha256,
            "drand_chain_hash": item["drand_chain_hash"],
            "drand_round": round_number,
            "randomness_sha256": randomness,
            "drand_signature_sha256": signature,
        }
    )
    return _issue(
        OfflineSyntheticChallenge(
            receipt_sha256=canonical_sha256(item),
            precommit_sha256=precommit["sha256"],
            campaign_root_sha256=precommit["campaign_root_sha256"],
            timestamp_quorum_receipt_sha256=timestamp_quorum.receipt_sha256,
            slot_id=precommit["slot_id"],
            committed_round=round_number,
            round_scheduled_at=round_scheduled_at,
            randomness_sha256=randomness,
            drand_signature_sha256=signature,
            challenge_sha256=challenge,
            observed_at=observed_at,
            offline_fixture_only=True,
            _construction_token=_CHALLENGE_SENTINEL,
        ),
        _ISSUED_CHALLENGES,
    )


_PERMIT_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "assignment_root_sha256",
        "preregistration_root_sha256",
        "readiness_snapshot_sha256",
        "precommit_sha256",
        "challenge_sha256",
        "permit_sequence",
        "slot_id",
        "archive_sha256",
        "competition_ref",
        "account_team_identifier",
        "expected_file_name",
        "expected_message",
        "a_previous_journal_head_sha256",
        "b_previous_journal_head_sha256",
        "issued_at",
        "expires_at",
        "permit_id",
        "signatures",
    }
)


def validate_dual_calibration_permit(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    precommit: ValidatedPermitPrecommit,
    challenge: OfflineSyntheticChallenge,
) -> OfflineCalibrationPermitCandidate:
    policy = require_validated_policy(policy)
    code = "V631_DUAL_PERMIT_INVALID"
    _require_issued(
        precommit,
        ValidatedPermitPrecommit,
        _ISSUED_PRECOMMITS,
        code=code,
        label="permit precommit",
    )
    _require_issued(
        challenge,
        OfflineSyntheticChallenge,
        _ISSUED_CHALLENGES,
        code=code,
        label="synthetic challenge",
    )
    item = exact(value, _PERMIT_FIELDS, "dual calibration permit", code=code)
    for field in (
        "policy_sha256",
        "campaign_root_sha256",
        "assignment_root_sha256",
        "preregistration_root_sha256",
        "readiness_snapshot_sha256",
        "permit_sequence",
        "slot_id",
        "archive_sha256",
        "competition_ref",
        "account_team_identifier",
        "expected_file_name",
        "expected_message",
        "a_previous_journal_head_sha256",
        "b_previous_journal_head_sha256",
        "expires_at",
    ):
        if item[field] != precommit[field]:
            raise fail(code, f"permit field {field} differs from the precommit")
    if (
        item["schema"] != PERMIT_SCHEMA
        or item["precommit_sha256"] != precommit["sha256"]
        or item["challenge_sha256"] != challenge.challenge_sha256
        or challenge.precommit_sha256 != precommit["sha256"]
        or challenge.offline_fixture_only is not True
    ):
        raise fail(code, "permit is not bound to the validated precommit and challenge")
    issued_at = utc(item["issued_at"], "permit issued_at", code=code)
    expires_at = utc(item["expires_at"], "permit expires_at", code=code)
    if (
        issued_at < challenge.observed_at
        or issued_at >= expires_at
        or expires_at != precommit["expires_at_dt"]
        or challenge.observed_at >= expires_at
    ):
        raise fail(code, "permit timing or precommitted 15-minute expiry is invalid")
    core = {key: item[key] for key in item if key not in {"permit_id", "signatures"}}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_PERMIT,
        identities=policy["identities"],
        required_party_ids=("A", "B"),
        code=code,
    )
    expected_id = canonical_sha256(
        {
            "domain": "V631/PERMIT-ID",
            "core_sha256": canonical_sha256(core),
            "signature_set_sha256": canonical_sha256(item["signatures"]),
        }
    )
    if item["permit_id"] != expected_id:
        raise fail(code, "permit id is not derived from its signed core")
    return _issue(
        OfflineCalibrationPermitCandidate(
            receipt_sha256=canonical_sha256(item),
            permit_id=expected_id,
            precommit_sha256=precommit["sha256"],
            challenge_sha256=challenge.challenge_sha256,
            campaign_root_sha256=precommit["campaign_root_sha256"],
            assignment_root_sha256=precommit["assignment_root_sha256"],
            preregistration_root_sha256=precommit["preregistration_root_sha256"],
            readiness_snapshot_sha256=precommit["readiness_snapshot_sha256"],
            permit_sequence=precommit["permit_sequence_int"],
            slot_id=precommit["slot_id"],
            archive_sha256=precommit["archive_sha256"],
            expected_file_name=precommit["expected_file_name"],
            expected_message=precommit["expected_message"],
            issued_at=issued_at,
            expires_at=expires_at,
            journal_heads=(
                precommit["a_previous_journal_head_sha256"],
                precommit["b_previous_journal_head_sha256"],
            ),
            offline_conformance_only=True,
            _construction_token=_PERMIT_SENTINEL,
        ),
        _ISSUED_PERMITS,
    )


_JOURNAL_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "branch_party_id",
        "sequence",
        "previous_head_sha256",
        "event_type",
        "event_sha256",
        "created_at",
        "signature",
    }
)


def validate_journal_successor(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    campaign_root_sha256: str,
    expected_branch: str,
    expected_sequence: int,
    expected_previous_head: str,
    expected_event_type: str,
    expected_event_sha256: str,
) -> Mapping[str, Any]:
    policy = require_validated_policy(policy)
    code = "V631_AUDITOR_JOURNAL_INVALID"
    if expected_branch not in {"A", "B"}:
        raise ValueError("journal branch must be A or B")
    item = exact(value, _JOURNAL_FIELDS, f"journal successor {expected_branch}", code=code)
    if (
        item["schema"] != JOURNAL_ENTRY_SCHEMA
        or item["policy_sha256"] != policy["sha256"]
        or item["campaign_root_sha256"] != campaign_root_sha256
        or item["branch_party_id"] != expected_branch
        or item["previous_head_sha256"] != expected_previous_head
        or item["event_type"] != expected_event_type
        or item["event_sha256"] != expected_event_sha256
    ):
        raise fail(code, "journal successor does not bind the expected branch transition")
    sequence = canonical_integer(item["sequence"], "journal sequence", code=code, minimum=1)
    if sequence != expected_sequence:
        raise fail(code, "journal sequence is reused, skipped, or rolled back")
    created_at = utc(item["created_at"], "journal created_at", code=code)
    core = {key: item[key] for key in item if key != "signature"}
    verify_signature_set(
        [item["signature"]],
        core=core,
        domain=DOMAIN_JOURNAL,
        identities=policy["identities"],
        required_party_ids=(expected_branch,),
        code=code,
    )
    return freeze(
        {
            **dict(item),
            "head_sha256": canonical_sha256(item),
            "sequence_int": sequence,
            "created_at_dt": created_at,
        }
    )


def assess_dual_permit(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    precommit: ValidatedPermitPrecommit,
    challenge: OfflineSyntheticChallenge,
) -> dict[str, Any]:
    try:
        parsed = validate_dual_calibration_permit(
            value,
            policy=policy,
            precommit=precommit,
            challenge=challenge,
        )
    except V63Error as exc:
        return zero_authority(exc.code, detail=str(exc))
    return zero_authority(
        "V631_DUAL_PERMIT_STRUCTURALLY_VALID_REQUIRES_LIVE_EXTERNAL_JOURNALS_AND_PIN",
        detail="The signed permit is an offline conformance artifact only; no pinned policy or live external replay state exists.",
        extra={
            "structural_permit_id": parsed.permit_id,
            "structural_slot_id": parsed.slot_id,
            "offline_conformance_only": True,
        },
    )


__all__ = [
    "DOMAIN_JOURNAL",
    "DOMAIN_PERMIT",
    "CALIBRATION_JOURNAL_ENTRY_SCHEMA",
    "GENESIS_SHA256",
    "JOURNAL_ENTRY_SCHEMA",
    "LIVE_CHALLENGE_SCHEMA",
    "PERMIT_SCHEMA",
    "PERMIT_TTL_SECONDS",
    "PRECOMMIT_SCHEMA",
    "SLOTS",
    "OfflineCalibrationPermitCandidate",
    "OfflineDualJournalPrefix",
    "OfflineSyntheticChallenge",
    "OfflineSyntheticTimestampQuorum",
    "ValidatedPermitPrecommit",
    "assess_dual_permit",
    "require_offline_calibration_permit_candidate",
    "validate_dual_calibration_permit",
    "validate_offline_dual_journal_prefix",
    "validate_journal_successor",
    "validate_permit_precommit",
    "validate_synthetic_live_challenge_fixture",
    "validate_synthetic_precommit_timestamp_fixture",
]
