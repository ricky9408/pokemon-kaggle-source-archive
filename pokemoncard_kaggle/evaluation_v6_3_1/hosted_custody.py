"""Read-only A/B hosted endpoint verifier for Evaluation v6.3.1.

Every artifact produced here is explicitly an offline candidate. Kaggle does
not provide a host-signed archive digest, execution receipt, or outcome
receipt, and an observed submission record does not prove permit consumption
or replay absence. This module has no Kaggle client, uploader, credentials,
network access, holdout reader, permit issuer, live composer, or authority path.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
import json
from typing import Any

from evaluation_v6_3.common import decimal_string

from .common import (
    V63Error,
    canonical_integer,
    canonical_json_bytes,
    canonical_sha256,
    exact,
    fail,
    identifier,
    sha256,
    utc,
    verify_signature_set,
    zero_authority,
)
from .permit import (
    OfflineCalibrationPermitCandidate,
    require_offline_calibration_permit_candidate,
)
from .policy import ValidatedV631Policy, require_validated_policy


SUBMISSION_BINDING_SCHEMA = "eval.v6.3.1.hosted-submission-binding"
COMPLETE_OBSERVATION_SCHEMA = "eval.v6.3.1.hosted-complete-observation"
COMPLETE_AGREEMENT_SCHEMA = "eval.v6.3.1.hosted-complete-agreement"
TLS_PEER_SCHEMA = "eval.v6.3.1.hosted-tls-peer"
HOSTED_POLL_SCHEMA = "eval.v6.3.1.hosted-poll-receipt"
DUAL_AGREEMENT_SCHEMA = "eval.v6.3.1.hosted-dual-collector-agreement"
HOSTED_ENDPOINT_SCHEMA = "eval.v6.3.1.offline-candidate-hosted-endpoint"

DOMAIN_SUBMISSION_BINDING = b"EVAL-V631/HOSTED-SUBMISSION-BINDING\0"
DOMAIN_COMPLETE_OBSERVATION = b"EVAL-V631/HOSTED-COMPLETE-OBSERVATION\0"
DOMAIN_COMPLETE_AGREEMENT = b"EVAL-V631/HOSTED-COMPLETE-AGREEMENT\0"
DOMAIN_HOSTED_POLL = b"EVAL-V631/HOSTED-POLL-RECEIPT\0"
DOMAIN_DUAL_AGREEMENT = b"EVAL-V631/HOSTED-DUAL-COLLECTOR-AGREEMENT\0"

POLL_OFFSETS_MINUTES = {1: 60, 2: 120, 3: 240, 4: 480}
POLL_WINDOW_SECONDS = 600
MAX_SCORE_OR_CUTOFF = Decimal("10000")

_BINDING_SENTINEL = object()
_COMPLETE_SENTINEL = object()
_POLL_SENTINEL = object()
_ENDPOINT_SENTINEL = object()


_BINDING_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "permit_sha256",
        "permit_id",
        "archive_sha256",
        "submission_ref",
        "file_name",
        "message",
        "permit_issued_at",
        "permit_expires_at",
        "observed_at",
        "permit_atomically_consumed",
        "authenticated_terminal_journal_heads",
        "replay_absence_verified",
        "signatures",
    }
)
_COMPLETE_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "submission_binding_sha256",
        "collector_party_id",
        "submission_ref",
        "file_name",
        "message",
        "status",
        "observed_at",
        "raw_response_sha256",
        "tls_peer_identity",
        "signatures",
    }
)
_COMPLETE_AGREEMENT_FIELDS = frozenset(
    {"schema", "collector_a_observation", "collector_b_observation", "signatures"}
)
_TLS_FIELDS = frozenset(
    {
        "schema",
        "hostname",
        "certificate_chain_sha256",
        "spki_sha256",
        "peer_policy_root_sha256",
        "authenticated",
    }
)
_POLL_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "submission_binding_sha256",
        "collector_party_id",
        "poll_index",
        "scheduled_window_start",
        "scheduled_window_end",
        "submission_ref",
        "file_name",
        "message",
        "status",
        "submission_response_sha256",
        "leaderboard_response_sha256",
        "score_observed_at",
        "leaderboard_observed_at",
        "parsed_score",
        "parsed_rank10_cutoff",
        "tls_peer_identity",
        "signatures",
    }
)
_AGREEMENT_FIELDS = frozenset(
    {
        "schema",
        "poll_index",
        "collector_receipt_sha256s",
        "parsed_equality_vector",
        "local_timestamp_skews_seconds",
        "cross_collector_skew_seconds",
        "accepted_attempt_index",
        "agreement_result",
        "signatures",
    }
)
_ENDPOINT_CORE_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "submission_binding_sha256",
        "complete_agreement_sha256",
        "poll_receipt_roots",
        "archive_sha256",
        "submission_ref",
        "file_name",
        "message",
        "binding_observed_at",
        "t0",
        "yobs",
        "offline_candidate_only",
        "permit_atomically_consumed",
        "authenticated_terminal_journal_heads",
        "replay_absence_verified",
        "calibration_upload_authorized",
        "production_upload_authorized",
        "sealed_holdout_access_authorized",
        "agent_modification_authorized",
        "sealed_holdout_accessed",
        "host_signed_archive_digest",
        "host_signed_execution_receipt",
        "host_signed_outcome_receipt",
        "exact_archive_persisted_by_host_proven",
        "exact_archive_executed_by_host_proven",
        "hosted_observations_nonrepudiable",
    }
)


def _canonical_receipt_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value)


def _decode_canonical_receipt(value: Any, *, label: str) -> dict[str, Any]:
    if type(value) is not bytes:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", f"{label} must retain canonical receipt bytes")
    try:
        parsed = json.loads(value.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", f"{label} is not canonical JSON") from exc
    if type(parsed) is not dict or canonical_json_bytes(parsed) != value:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", f"{label} is not an exact canonical receipt")
    return parsed


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _timedelta_decimal_seconds(value: timedelta) -> Decimal:
    total_microseconds = (
        value.days * 86_400_000_000 + value.seconds * 1_000_000 + value.microseconds
    )
    return Decimal(abs(total_microseconds)) / Decimal(1_000_000)


def _exact_host_value(value: Any, *, label: str) -> tuple[str, Decimal]:
    code = "V631_HOSTED_VALUE_DOMAIN_INVALID"
    rendered = decimal_string(value, label, code=code)
    try:
        parsed = Decimal(rendered)
    except InvalidOperation as exc:  # pragma: no cover - decimal_string excludes this
        raise fail(code, f"{label} is not an exact decimal") from exc
    if parsed > MAX_SCORE_OR_CUTOFF:
        raise fail(code, f"{label} must be in [0, 10000]")
    return rendered, parsed


def _identities(policy: ValidatedV631Policy) -> Mapping[str, Mapping[str, Any]]:
    policy = require_validated_policy(policy)
    identities = policy["identities"]
    if set(identities) != {"A", "B", "D", "E"}:
        raise fail(
            "V631_HOSTED_EVIDENCE_INVALID",
            "validated policy does not expose the v6.3.1 A/B identity set",
        )
    return identities


def _tls_peer(value: Any, *, policy: ValidatedV631Policy) -> None:
    code = "V631_TLS_PEER_AUTHENTICATION_FAILED"
    item = exact(value, _TLS_FIELDS, "Kaggle TLS peer evidence", code=code)
    kaggle = policy["kaggle"]
    if (
        item["schema"] != TLS_PEER_SCHEMA
        or item["hostname"] not in kaggle["allowed_hosts"]
        or item["peer_policy_root_sha256"] != kaggle["peer_policy_root_sha256"]
        or item["authenticated"] is not True
    ):
        raise fail(code, "Kaggle TLS peer evidence is not policy-bound and authenticated")
    for field in ("certificate_chain_sha256", "spki_sha256", "peer_policy_root_sha256"):
        sha256(item[field], field, code=code)


@dataclass(frozen=True)
class OfflineSubmissionBindingCandidate:
    receipt_sha256: str
    policy_sha256: str
    permit_sha256: str
    permit_id: str
    archive_sha256: str
    submission_ref: str
    file_name: str
    message: str
    permit_issued_at: datetime
    permit_expires_at: datetime
    observed_at: datetime
    permit_atomically_consumed: bool
    authenticated_terminal_journal_heads: bool
    replay_absence_verified: bool
    offline_candidate_only: bool
    signed_receipt_bytes: bytes
    _construction_token: InitVar[object]

    def __post_init__(self, _construction_token: object) -> None:
        if _construction_token is not _BINDING_SENTINEL:
            raise ValueError(
                "OfflineSubmissionBindingCandidate can only be created by the offline binding verifier"
            )
        _assert_binding_artifact_integrity(self)


@dataclass(frozen=True)
class OfflineCompleteAgreementCandidate:
    receipt_sha256: str
    submission_binding_sha256: str
    t0: datetime
    observation_receipt_sha256s: tuple[str, str]
    permit_atomically_consumed: bool
    authenticated_terminal_journal_heads: bool
    replay_absence_verified: bool
    offline_candidate_only: bool
    signed_receipt_bytes: bytes
    _construction_token: InitVar[object]

    def __post_init__(self, _construction_token: object) -> None:
        if _construction_token is not _COMPLETE_SENTINEL:
            raise ValueError(
                "OfflineCompleteAgreementCandidate can only be created by the offline COMPLETE verifier"
            )
        _assert_complete_artifact_integrity(self)


@dataclass(frozen=True)
class OfflinePollAgreementCandidate:
    receipt_sha256: str
    poll_index: int
    score: str
    rank10_cutoff: str
    collector_receipt_sha256s: tuple[str, str]
    permit_atomically_consumed: bool
    authenticated_terminal_journal_heads: bool
    replay_absence_verified: bool
    offline_candidate_only: bool
    signed_agreement_receipt_bytes: bytes
    collector_poll_receipt_bytes: tuple[bytes, bytes]
    _construction_token: InitVar[object]

    def __post_init__(self, _construction_token: object) -> None:
        if _construction_token is not _POLL_SENTINEL:
            raise ValueError(
                "OfflinePollAgreementCandidate can only be created by the offline dual-collector verifier"
            )
        _assert_poll_artifact_integrity(self)


@dataclass(frozen=True)
class OfflineHostedEndpointCandidate:
    """Exact four-poll observational endpoint with no authority or live claim."""

    receipt_sha256: str
    policy_sha256: str
    submission_binding_sha256: str
    complete_agreement_sha256: str
    poll_receipt_roots: tuple[str, str, str, str]
    archive_sha256: str
    submission_ref: str
    file_name: str
    message: str
    binding_observed_at: datetime
    t0: datetime
    yobs: Decimal
    yobs_string: str
    offline_candidate_only: bool
    permit_atomically_consumed: bool
    authenticated_terminal_journal_heads: bool
    replay_absence_verified: bool
    calibration_upload_authorized: bool
    production_upload_authorized: bool
    sealed_holdout_access_authorized: bool
    agent_modification_authorized: bool
    sealed_holdout_accessed: bool
    host_signed_archive_digest: bool
    host_signed_execution_receipt: bool
    host_signed_outcome_receipt: bool
    exact_archive_persisted_by_host_proven: bool
    exact_archive_executed_by_host_proven: bool
    hosted_observations_nonrepudiable: bool
    canonical_core_bytes: bytes
    _construction_token: InitVar[object]

    def __post_init__(self, _construction_token: object) -> None:
        if _construction_token is not _ENDPOINT_SENTINEL:
            raise ValueError(
                "OfflineHostedEndpointCandidate can only be created by the offline endpoint verifier"
            )
        _assert_endpoint_artifact_integrity(self)


def _assert_binding_artifact_integrity(value: OfflineSubmissionBindingCandidate) -> None:
    item = _decode_canonical_receipt(value.signed_receipt_bytes, label="binding signed receipt")
    if set(item) != _BINDING_FIELDS:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "binding retained receipt fields changed")
    issued = utc(item["permit_issued_at"], "retained permit issued_at", code="V631_TYPED_ARTIFACT_INTEGRITY_INVALID")
    expires = utc(item["permit_expires_at"], "retained permit expires_at", code="V631_TYPED_ARTIFACT_INTEGRITY_INVALID")
    observed = utc(item["observed_at"], "retained binding observed_at", code="V631_TYPED_ARTIFACT_INTEGRITY_INVALID")
    expected = (
        canonical_sha256(item),
        item["policy_sha256"],
        item["permit_sha256"],
        item["permit_id"],
        item["archive_sha256"],
        item["submission_ref"],
        item["file_name"],
        item["message"],
        issued,
        expires,
        observed,
        item["permit_atomically_consumed"],
        item["authenticated_terminal_journal_heads"],
        item["replay_absence_verified"],
        True,
    )
    actual = (
        value.receipt_sha256,
        value.policy_sha256,
        value.permit_sha256,
        value.permit_id,
        value.archive_sha256,
        value.submission_ref,
        value.file_name,
        value.message,
        value.permit_issued_at,
        value.permit_expires_at,
        value.observed_at,
        value.permit_atomically_consumed,
        value.authenticated_terminal_journal_heads,
        value.replay_absence_verified,
        value.offline_candidate_only,
    )
    if actual != expected:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "binding fields differ from its retained signed receipt")
    if any(
        flag is not False
        for flag in (
            value.permit_atomically_consumed,
            value.authenticated_terminal_journal_heads,
            value.replay_absence_verified,
        )
    ):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "offline binding cannot claim consumption or replay protection")
    if not (issued <= observed < expires):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "binding observation is outside the retained permit window")


def _assert_complete_artifact_integrity(value: OfflineCompleteAgreementCandidate) -> None:
    item = _decode_canonical_receipt(value.signed_receipt_bytes, label="COMPLETE signed receipt")
    if set(item) != _COMPLETE_AGREEMENT_FIELDS:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "COMPLETE retained receipt fields changed")
    a = item["collector_a_observation"]
    b = item["collector_b_observation"]
    if type(a) is not dict or type(b) is not dict:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "COMPLETE observations are not retained objects")
    expected = (
        canonical_sha256(item),
        a.get("submission_binding_sha256"),
        min(
            utc(a.get("observed_at"), "retained A COMPLETE time", code="V631_TYPED_ARTIFACT_INTEGRITY_INVALID"),
            utc(b.get("observed_at"), "retained B COMPLETE time", code="V631_TYPED_ARTIFACT_INTEGRITY_INVALID"),
        ),
        (canonical_sha256(a), canonical_sha256(b)),
        False,
        False,
        False,
        True,
    )
    actual = (
        value.receipt_sha256,
        value.submission_binding_sha256,
        value.t0,
        value.observation_receipt_sha256s,
        value.permit_atomically_consumed,
        value.authenticated_terminal_journal_heads,
        value.replay_absence_verified,
        value.offline_candidate_only,
    )
    if actual != expected or b.get("submission_binding_sha256") != value.submission_binding_sha256:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "COMPLETE fields differ from its retained signed receipt")


def _assert_poll_artifact_integrity(value: OfflinePollAgreementCandidate) -> None:
    agreement = _decode_canonical_receipt(
        value.signed_agreement_receipt_bytes,
        label="dual-collector signed agreement receipt",
    )
    if set(agreement) != _AGREEMENT_FIELDS or len(value.collector_poll_receipt_bytes) != 2:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "poll retained receipt shape changed")
    poll_a = _decode_canonical_receipt(value.collector_poll_receipt_bytes[0], label="collector A poll receipt")
    poll_b = _decode_canonical_receipt(value.collector_poll_receipt_bytes[1], label="collector B poll receipt")
    roots = (canonical_sha256(poll_a), canonical_sha256(poll_b))
    expected_roots = agreement.get("collector_receipt_sha256s")
    expected = (
        canonical_sha256(agreement),
        int(agreement.get("poll_index", "-1")),
        poll_a.get("parsed_score"),
        poll_a.get("parsed_rank10_cutoff"),
        roots,
        False,
        False,
        False,
        True,
    )
    actual = (
        value.receipt_sha256,
        value.poll_index,
        value.score,
        value.rank10_cutoff,
        value.collector_receipt_sha256s,
        value.permit_atomically_consumed,
        value.authenticated_terminal_journal_heads,
        value.replay_absence_verified,
        value.offline_candidate_only,
    )
    if (
        actual != expected
        or expected_roots != {"A": roots[0], "B": roots[1]}
        or poll_b.get("parsed_score") != value.score
        or poll_b.get("parsed_rank10_cutoff") != value.rank10_cutoff
    ):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "poll fields differ from retained signed receipts")


def _endpoint_core_from_artifact(value: OfflineHostedEndpointCandidate) -> dict[str, Any]:
    return {
        "schema": HOSTED_ENDPOINT_SCHEMA,
        "policy_sha256": value.policy_sha256,
        "submission_binding_sha256": value.submission_binding_sha256,
        "complete_agreement_sha256": value.complete_agreement_sha256,
        "poll_receipt_roots": list(value.poll_receipt_roots),
        "archive_sha256": value.archive_sha256,
        "submission_ref": value.submission_ref,
        "file_name": value.file_name,
        "message": value.message,
        "binding_observed_at": value.binding_observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "t0": value.t0.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "yobs": value.yobs_string,
        "offline_candidate_only": value.offline_candidate_only,
        "permit_atomically_consumed": value.permit_atomically_consumed,
        "authenticated_terminal_journal_heads": value.authenticated_terminal_journal_heads,
        "replay_absence_verified": value.replay_absence_verified,
        "calibration_upload_authorized": value.calibration_upload_authorized,
        "production_upload_authorized": value.production_upload_authorized,
        "sealed_holdout_access_authorized": value.sealed_holdout_access_authorized,
        "agent_modification_authorized": value.agent_modification_authorized,
        "sealed_holdout_accessed": value.sealed_holdout_accessed,
        "host_signed_archive_digest": value.host_signed_archive_digest,
        "host_signed_execution_receipt": value.host_signed_execution_receipt,
        "host_signed_outcome_receipt": value.host_signed_outcome_receipt,
        "exact_archive_persisted_by_host_proven": value.exact_archive_persisted_by_host_proven,
        "exact_archive_executed_by_host_proven": value.exact_archive_executed_by_host_proven,
        "hosted_observations_nonrepudiable": value.hosted_observations_nonrepudiable,
    }


def _assert_endpoint_artifact_integrity(value: OfflineHostedEndpointCandidate) -> None:
    core = _decode_canonical_receipt(value.canonical_core_bytes, label="endpoint canonical core")
    expected_core = _endpoint_core_from_artifact(value)
    if set(core) != _ENDPOINT_CORE_FIELDS or core != expected_core:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "endpoint fields differ from its canonical core")
    if value.receipt_sha256 != canonical_sha256(core) or value.yobs != Decimal(value.yobs_string):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "endpoint root or exact Decimal differs from its canonical core")
    false_fields = (
        value.permit_atomically_consumed,
        value.authenticated_terminal_journal_heads,
        value.replay_absence_verified,
        value.calibration_upload_authorized,
        value.production_upload_authorized,
        value.sealed_holdout_access_authorized,
        value.agent_modification_authorized,
        value.sealed_holdout_accessed,
        value.host_signed_archive_digest,
        value.host_signed_execution_receipt,
        value.host_signed_outcome_receipt,
        value.exact_archive_persisted_by_host_proven,
        value.exact_archive_executed_by_host_proven,
        value.hosted_observations_nonrepudiable,
    )
    if value.offline_candidate_only is not True or any(field is not False for field in false_fields):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "offline endpoint contains an authority or live-custody claim")


def _validate_binding_receipt(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    permit: OfflineCalibrationPermitCandidate | None,
) -> dict[str, Any]:
    code = "V631_SUBMISSION_BINDING_INVALID"
    item = exact(value, _BINDING_FIELDS, "hosted submission binding", code=code)
    if item["schema"] != SUBMISSION_BINDING_SCHEMA or item["policy_sha256"] != policy["sha256"]:
        raise fail(code, "submission binding is not policy-bound")
    archive = sha256(item["archive_sha256"], "archive hash", code=code)
    submission_ref = identifier(item["submission_ref"], "submission ref", code=code)
    permit_issued_at = utc(item["permit_issued_at"], "permit issued_at", code=code)
    permit_expires_at = utc(item["permit_expires_at"], "permit expires_at", code=code)
    observed_at = utc(item["observed_at"], "binding observed_at", code=code)
    if not (permit_issued_at <= observed_at < permit_expires_at):
        raise fail(code, "binding observation must be inside the permit issued/expires window")
    if any(
        item[field] is not False
        for field in (
            "permit_atomically_consumed",
            "authenticated_terminal_journal_heads",
            "replay_absence_verified",
        )
    ):
        raise fail(code, "offline binding must not claim permit consumption, terminal journals, or replay absence")
    if permit is not None:
        permit = require_offline_calibration_permit_candidate(permit, code=code)
        if permit.offline_conformance_only is not True:
            raise fail(code, "submission binding requires a verifier-created offline permit candidate")
        if (
            item["permit_sha256"] != permit.receipt_sha256
            or item["permit_id"] != permit.permit_id
            or archive != permit.archive_sha256
            or item["file_name"] != permit.expected_file_name
            or item["message"] != permit.expected_message
            or permit_issued_at != permit.issued_at
            or permit_expires_at != permit.expires_at
        ):
            raise fail(code, "submission binding differs from the exact permit-derived identity or window")
    else:
        sha256(item["permit_sha256"], "permit receipt hash", code=code)
        identifier(item["permit_id"], "permit id", code=code)
        identifier(item["file_name"], "file name", code=code)
        identifier(item["message"], "message", code=code)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_SUBMISSION_BINDING,
        identities=_identities(policy),
        required_party_ids=("A", "B"),
        code=code,
    )
    return {
        "receipt_sha256": canonical_sha256(item),
        "policy_sha256": policy["sha256"],
        "permit_sha256": item["permit_sha256"],
        "permit_id": item["permit_id"],
        "archive_sha256": archive,
        "submission_ref": submission_ref,
        "file_name": item["file_name"],
        "message": item["message"],
        "permit_issued_at": permit_issued_at,
        "permit_expires_at": permit_expires_at,
        "observed_at": observed_at,
        "signed_receipt_bytes": _canonical_receipt_bytes(item),
    }


def validate_submission_binding(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    permit: OfflineCalibrationPermitCandidate,
) -> OfflineSubmissionBindingCandidate:
    """Verify an A/B-signed offline observation of a permit-bound identity.

    Success means only that the observation was signed inside the stated permit
    time window. It does not prove atomic permit consumption or replay absence.
    """

    policy = require_validated_policy(policy)
    parsed = _validate_binding_receipt(value, policy=policy, permit=permit)
    return OfflineSubmissionBindingCandidate(
        **parsed,
        permit_atomically_consumed=False,
        authenticated_terminal_journal_heads=False,
        replay_absence_verified=False,
        offline_candidate_only=True,
        _construction_token=_BINDING_SENTINEL,
    )


def _require_binding(
    value: Any,
    *,
    policy: ValidatedV631Policy,
) -> OfflineSubmissionBindingCandidate:
    if type(value) is not OfflineSubmissionBindingCandidate:
        raise fail("V631_HOSTED_EVIDENCE_INVALID", "hosted evidence requires an offline binding candidate")
    _assert_binding_artifact_integrity(value)
    parsed = _validate_binding_receipt(
        _decode_canonical_receipt(value.signed_receipt_bytes, label="binding signed receipt"),
        policy=policy,
        permit=None,
    )
    comparable = (
        parsed["receipt_sha256"],
        parsed["policy_sha256"],
        parsed["permit_sha256"],
        parsed["permit_id"],
        parsed["archive_sha256"],
        parsed["submission_ref"],
        parsed["file_name"],
        parsed["message"],
        parsed["permit_issued_at"],
        parsed["permit_expires_at"],
        parsed["observed_at"],
    )
    actual = (
        value.receipt_sha256,
        value.policy_sha256,
        value.permit_sha256,
        value.permit_id,
        value.archive_sha256,
        value.submission_ref,
        value.file_name,
        value.message,
        value.permit_issued_at,
        value.permit_expires_at,
        value.observed_at,
    )
    if comparable != actual:
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "binding failed consumer-side revalidation")
    return value


def _complete_observation(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    expected_party_id: str,
) -> tuple[str, datetime]:
    code = "V631_COMPLETE_OBSERVATION_DISAGREEMENT"
    item = exact(
        value,
        _COMPLETE_OBSERVATION_FIELDS,
        f"COMPLETE observation {expected_party_id}",
        code=code,
    )
    if (
        item["schema"] != COMPLETE_OBSERVATION_SCHEMA
        or item["policy_sha256"] != policy["sha256"]
        or item["submission_binding_sha256"] != binding.receipt_sha256
        or item["collector_party_id"] != expected_party_id
        or item["submission_ref"] != binding.submission_ref
        or item["file_name"] != binding.file_name
        or item["message"] != binding.message
        or item["status"] != "COMPLETE"
    ):
        raise fail(code, f"COMPLETE observation {expected_party_id} is not bound to the exact submission")
    sha256(item["raw_response_sha256"], "COMPLETE raw response", code=code)
    _tls_peer(item["tls_peer_identity"], policy=policy)
    observed_at = utc(item["observed_at"], "COMPLETE observed_at", code=code)
    if observed_at < binding.observed_at:
        raise fail(code, "COMPLETE observation predates the signed submission binding observation")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_COMPLETE_OBSERVATION,
        identities=_identities(policy),
        required_party_ids=(expected_party_id,),
        code=code,
    )
    return canonical_sha256(item), observed_at


def _validate_complete_receipt(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
) -> dict[str, Any]:
    code = "V631_COMPLETE_OBSERVATION_DISAGREEMENT"
    item = exact(value, _COMPLETE_AGREEMENT_FIELDS, "COMPLETE agreement", code=code)
    if item["schema"] != COMPLETE_AGREEMENT_SCHEMA:
        raise fail(code, "COMPLETE agreement schema mismatch")
    a_root, a_time = _complete_observation(
        item["collector_a_observation"], policy=policy, binding=binding, expected_party_id="A"
    )
    b_root, b_time = _complete_observation(
        item["collector_b_observation"], policy=policy, binding=binding, expected_party_id="B"
    )
    if abs(a_time - b_time) > timedelta(seconds=120):
        raise fail(code, "A and B COMPLETE observations differ by more than 120 seconds")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_COMPLETE_AGREEMENT,
        identities=_identities(policy),
        required_party_ids=("A", "B"),
        code=code,
    )
    return {
        "receipt_sha256": canonical_sha256(item),
        "submission_binding_sha256": binding.receipt_sha256,
        "t0": min(a_time, b_time),
        "observation_receipt_sha256s": (a_root, b_root),
        "signed_receipt_bytes": _canonical_receipt_bytes(item),
    }


def validate_complete_agreement(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
) -> OfflineCompleteAgreementCandidate:
    """Verify independent A/B COMPLETE observations and derive earliest t0."""

    policy = require_validated_policy(policy)
    binding = _require_binding(binding, policy=policy)
    parsed = _validate_complete_receipt(value, policy=policy, binding=binding)
    return OfflineCompleteAgreementCandidate(
        **parsed,
        permit_atomically_consumed=False,
        authenticated_terminal_journal_heads=False,
        replay_absence_verified=False,
        offline_candidate_only=True,
        _construction_token=_COMPLETE_SENTINEL,
    )


def _require_complete(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
) -> OfflineCompleteAgreementCandidate:
    if type(value) is not OfflineCompleteAgreementCandidate:
        raise fail("V631_HOSTED_EVIDENCE_INVALID", "endpoint requires an offline COMPLETE candidate")
    _assert_complete_artifact_integrity(value)
    parsed = _validate_complete_receipt(
        _decode_canonical_receipt(value.signed_receipt_bytes, label="COMPLETE signed receipt"),
        policy=policy,
        binding=binding,
    )
    if (
        parsed["receipt_sha256"] != value.receipt_sha256
        or parsed["submission_binding_sha256"] != value.submission_binding_sha256
        or parsed["t0"] != value.t0
        or parsed["observation_receipt_sha256s"] != value.observation_receipt_sha256s
    ):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "COMPLETE failed consumer-side revalidation")
    return value


def _validate_poll(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    t0: datetime,
    expected_party_id: str,
    expected_poll_index: int,
) -> dict[str, Any]:
    code = "V631_POLL_OUTSIDE_WINDOW"
    item = exact(
        value,
        _POLL_FIELDS,
        f"poll {expected_poll_index} collector {expected_party_id}",
        code=code,
    )
    if expected_poll_index not in POLL_OFFSETS_MINUTES:
        raise fail(code, "poll index must be exactly 1, 2, 3, or 4")
    index = canonical_integer(item["poll_index"], "poll index", code=code, minimum=1)
    if (
        item["schema"] != HOSTED_POLL_SCHEMA
        or item["policy_sha256"] != policy["sha256"]
        or item["submission_binding_sha256"] != binding.receipt_sha256
        or item["collector_party_id"] != expected_party_id
        or index != expected_poll_index
        or item["submission_ref"] != binding.submission_ref
        or item["file_name"] != binding.file_name
        or item["message"] != binding.message
        or item["status"] != "COMPLETE"
    ):
        raise fail(
            "V631_DUAL_COLLECTOR_DISAGREEMENT",
            "poll does not identify the exact bound COMPLETE submission",
        )
    window_start = t0 + timedelta(minutes=POLL_OFFSETS_MINUTES[index])
    window_end = window_start + timedelta(seconds=POLL_WINDOW_SECONDS)
    if utc(item["scheduled_window_start"], "scheduled window start", code=code) != window_start or utc(
        item["scheduled_window_end"], "scheduled window end", code=code
    ) != window_end:
        raise fail(code, "poll window differs from the frozen COMPLETE-relative schedule")
    score_time = utc(item["score_observed_at"], "score observed_at", code=code)
    cutoff_time = utc(item["leaderboard_observed_at"], "leaderboard observed_at", code=code)
    if not (window_start <= score_time < window_end and window_start <= cutoff_time < window_end):
        raise fail(code, "score and rank-10 observations must be inside the exact ten-minute window")
    local_delta = abs(score_time - cutoff_time)
    if local_delta > timedelta(seconds=60):
        raise fail(
            "V631_CUTOFF_NOT_SYNCHRONIZED",
            "score and rank-10 cutoff observations differ by more than 60 seconds",
        )
    score, _ = _exact_host_value(item["parsed_score"], label="parsed score")
    cutoff, _ = _exact_host_value(item["parsed_rank10_cutoff"], label="parsed rank-10 cutoff")
    for field in ("submission_response_sha256", "leaderboard_response_sha256"):
        sha256(item[field], field, code="V631_HOSTED_EVIDENCE_INVALID")
    _tls_peer(item["tls_peer_identity"], policy=policy)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_HOSTED_POLL,
        identities=_identities(policy),
        required_party_ids=(expected_party_id,),
        code="V631_DUAL_COLLECTOR_DISAGREEMENT",
    )
    return {
        "receipt_sha256": canonical_sha256(item),
        "score": score,
        "cutoff": cutoff,
        "local_skew_seconds": _timedelta_decimal_seconds(local_delta),
        "midpoint": min(score_time, cutoff_time) + local_delta / 2,
    }


def _validate_dual_agreement_receipts(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    complete: OfflineCompleteAgreementCandidate,
    collector_a_poll: Any,
    collector_b_poll: Any,
    expected_poll_index: int,
) -> dict[str, Any]:
    code = "V631_DUAL_COLLECTOR_DISAGREEMENT"
    item = exact(value, _AGREEMENT_FIELDS, f"dual collector agreement {expected_poll_index}", code=code)
    if (
        item["schema"] != DUAL_AGREEMENT_SCHEMA
        or item["agreement_result"] != "AGREE"
        or canonical_integer(item["poll_index"], "agreement poll index", code=code, minimum=1)
        != expected_poll_index
    ):
        raise fail(code, "dual collector agreement schema, result, or index mismatch")
    a = _validate_poll(
        collector_a_poll,
        policy=policy,
        binding=binding,
        t0=complete.t0,
        expected_party_id="A",
        expected_poll_index=expected_poll_index,
    )
    b = _validate_poll(
        collector_b_poll,
        policy=policy,
        binding=binding,
        t0=complete.t0,
        expected_party_id="B",
        expected_poll_index=expected_poll_index,
    )
    expected_receipts = {"A": a["receipt_sha256"], "B": b["receipt_sha256"]}
    if type(item["collector_receipt_sha256s"]) is not dict or item["collector_receipt_sha256s"] != expected_receipts:
        raise fail(code, "dual collector agreement receipt roots are stale or tampered")
    expected_equality = {
        "file_name": True,
        "message": True,
        "parsed_rank10_cutoff": True,
        "parsed_score": True,
        "status": True,
        "submission_ref": True,
    }
    if (
        item["parsed_equality_vector"] != expected_equality
        or a["score"] != b["score"]
        or a["cutoff"] != b["cutoff"]
    ):
        raise fail(code, "A and B disagree on the exact parsed submission, score, or rank-10 cutoff")
    expected_local_skews = {
        "A": _canonical_decimal(a["local_skew_seconds"]),
        "B": _canonical_decimal(b["local_skew_seconds"]),
    }
    if item["local_timestamp_skews_seconds"] != expected_local_skews:
        raise fail(
            "V631_CUTOFF_NOT_SYNCHRONIZED",
            "reported local timestamp skews do not match the receipts",
        )
    cross_delta = abs(a["midpoint"] - b["midpoint"])
    cross_seconds = _timedelta_decimal_seconds(cross_delta)
    if (
        cross_delta > timedelta(seconds=120)
        or item["cross_collector_skew_seconds"] != _canonical_decimal(cross_seconds)
    ):
        raise fail(
            code,
            "A/B poll midpoints differ by more than 120 exact seconds or the skew is misstated",
        )
    canonical_integer(item["accepted_attempt_index"], "accepted attempt index", code=code, minimum=1)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_DUAL_AGREEMENT,
        identities=_identities(policy),
        required_party_ids=("A", "B"),
        code=code,
    )
    return {
        "receipt_sha256": canonical_sha256(item),
        "poll_index": expected_poll_index,
        "score": a["score"],
        "rank10_cutoff": a["cutoff"],
        "collector_receipt_sha256s": (a["receipt_sha256"], b["receipt_sha256"]),
        "signed_agreement_receipt_bytes": _canonical_receipt_bytes(item),
        "collector_poll_receipt_bytes": (
            _canonical_receipt_bytes(collector_a_poll),
            _canonical_receipt_bytes(collector_b_poll),
        ),
    }


def validate_dual_collector_agreement(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    complete: OfflineCompleteAgreementCandidate,
    collector_a_poll: Any,
    collector_b_poll: Any,
    expected_poll_index: int,
) -> OfflinePollAgreementCandidate:
    """Verify one exact A/B poll pair as an offline candidate artifact."""

    policy = require_validated_policy(policy)
    binding = _require_binding(binding, policy=policy)
    complete = _require_complete(complete, policy=policy, binding=binding)
    parsed = _validate_dual_agreement_receipts(
        value,
        policy=policy,
        binding=binding,
        complete=complete,
        collector_a_poll=collector_a_poll,
        collector_b_poll=collector_b_poll,
        expected_poll_index=expected_poll_index,
    )
    return OfflinePollAgreementCandidate(
        **parsed,
        permit_atomically_consumed=False,
        authenticated_terminal_journal_heads=False,
        replay_absence_verified=False,
        offline_candidate_only=True,
        _construction_token=_POLL_SENTINEL,
    )


def _require_poll(
    value: Any,
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    complete: OfflineCompleteAgreementCandidate,
    expected_poll_index: int,
) -> OfflinePollAgreementCandidate:
    if type(value) is not OfflinePollAgreementCandidate:
        raise fail("V631_HOSTED_EVIDENCE_INVALID", "endpoint requires offline poll agreement candidates")
    _assert_poll_artifact_integrity(value)
    agreement = _decode_canonical_receipt(
        value.signed_agreement_receipt_bytes,
        label="dual-collector signed agreement receipt",
    )
    poll_a = _decode_canonical_receipt(value.collector_poll_receipt_bytes[0], label="collector A poll receipt")
    poll_b = _decode_canonical_receipt(value.collector_poll_receipt_bytes[1], label="collector B poll receipt")
    parsed = _validate_dual_agreement_receipts(
        agreement,
        policy=policy,
        binding=binding,
        complete=complete,
        collector_a_poll=poll_a,
        collector_b_poll=poll_b,
        expected_poll_index=expected_poll_index,
    )
    if (
        parsed["receipt_sha256"] != value.receipt_sha256
        or parsed["poll_index"] != value.poll_index
        or parsed["score"] != value.score
        or parsed["rank10_cutoff"] != value.rank10_cutoff
        or parsed["collector_receipt_sha256s"] != value.collector_receipt_sha256s
    ):
        raise fail("V631_TYPED_ARTIFACT_INTEGRITY_INVALID", "poll failed consumer-side revalidation")
    return value


def _endpoint_core(
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    complete: OfflineCompleteAgreementCandidate,
    roots: tuple[str, str, str, str],
    yobs_string: str,
) -> dict[str, Any]:
    return {
        "schema": HOSTED_ENDPOINT_SCHEMA,
        "policy_sha256": policy["sha256"],
        "submission_binding_sha256": binding.receipt_sha256,
        "complete_agreement_sha256": complete.receipt_sha256,
        "poll_receipt_roots": list(roots),
        "archive_sha256": binding.archive_sha256,
        "submission_ref": binding.submission_ref,
        "file_name": binding.file_name,
        "message": binding.message,
        "binding_observed_at": binding.observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "t0": complete.t0.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "yobs": yobs_string,
        "offline_candidate_only": True,
        "permit_atomically_consumed": False,
        "authenticated_terminal_journal_heads": False,
        "replay_absence_verified": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "sealed_holdout_accessed": False,
        "host_signed_archive_digest": False,
        "host_signed_execution_receipt": False,
        "host_signed_outcome_receipt": False,
        "exact_archive_persisted_by_host_proven": False,
        "exact_archive_executed_by_host_proven": False,
        "hosted_observations_nonrepudiable": False,
    }


def validate_hosted_endpoint(
    *,
    policy: ValidatedV631Policy,
    binding: OfflineSubmissionBindingCandidate,
    complete: OfflineCompleteAgreementCandidate,
    agreements: Sequence[OfflinePollAgreementCandidate],
) -> OfflineHostedEndpointCandidate:
    """Create the exact four-poll offline observational endpoint candidate."""

    policy = require_validated_policy(policy)
    binding = _require_binding(binding, policy=policy)
    complete = _require_complete(complete, policy=policy, binding=binding)
    if type(agreements) not in {list, tuple} or len(agreements) != 4:
        raise fail("V631_MATURE_POLL_MISSING", "exactly four mature dual-collected polls are required")
    checked = tuple(
        _require_poll(
            agreement,
            policy=policy,
            binding=binding,
            complete=complete,
            expected_poll_index=index,
        )
        for index, agreement in enumerate(agreements, start=1)
    )
    if [item.poll_index for item in checked] != [1, 2, 3, 4]:
        raise fail("V631_MATURE_POLL_MISSING", "mature poll agreements must be ordered exactly 1 through 4")
    gaps: list[Decimal] = []
    for agreement in checked:
        _, score = _exact_host_value(agreement.score, label="offline candidate score")
        _, cutoff = _exact_host_value(
            agreement.rank10_cutoff,
            label="offline candidate rank-10 cutoff",
        )
        gaps.append(score - cutoff)
    ordered = sorted(gaps)
    yobs = (ordered[1] + ordered[2]) / Decimal(2)
    yobs_string = _canonical_decimal(yobs)
    roots = tuple(item.receipt_sha256 for item in checked)
    core = _endpoint_core(
        policy=policy,
        binding=binding,
        complete=complete,
        roots=roots,
        yobs_string=yobs_string,
    )
    return OfflineHostedEndpointCandidate(
        receipt_sha256=canonical_sha256(core),
        policy_sha256=policy["sha256"],
        submission_binding_sha256=binding.receipt_sha256,
        complete_agreement_sha256=complete.receipt_sha256,
        poll_receipt_roots=roots,
        archive_sha256=binding.archive_sha256,
        submission_ref=binding.submission_ref,
        file_name=binding.file_name,
        message=binding.message,
        binding_observed_at=binding.observed_at,
        t0=complete.t0,
        yobs=yobs,
        yobs_string=yobs_string,
        offline_candidate_only=True,
        permit_atomically_consumed=False,
        authenticated_terminal_journal_heads=False,
        replay_absence_verified=False,
        calibration_upload_authorized=False,
        production_upload_authorized=False,
        sealed_holdout_access_authorized=False,
        agent_modification_authorized=False,
        sealed_holdout_accessed=False,
        host_signed_archive_digest=False,
        host_signed_execution_receipt=False,
        host_signed_outcome_receipt=False,
        exact_archive_persisted_by_host_proven=False,
        exact_archive_executed_by_host_proven=False,
        hosted_observations_nonrepudiable=False,
        canonical_core_bytes=canonical_json_bytes(core),
        _construction_token=_ENDPOINT_SENTINEL,
    )


def validate_four_poll_endpoint(**kwargs: Any) -> OfflineHostedEndpointCandidate:
    """Compatibility name for the exact four-poll offline endpoint verifier."""

    return validate_hosted_endpoint(**kwargs)


def assess_hosted_endpoint(**kwargs: Any) -> dict[str, Any]:
    """Assess offline evidence without creating any upload or replay authority."""

    try:
        endpoint = validate_hosted_endpoint(**kwargs)
    except V63Error as exc:
        return zero_authority(exc.code, detail=str(exc))
    return zero_authority(
        "V631_OFFLINE_HOSTED_ENDPOINT_CANDIDATE_OBSERVATIONAL_ONLY",
        detail=(
            "The offline candidate does not prove permit consumption, replay absence, "
            "exact archive persistence, or execution and cannot authorize an upload."
        ),
        extra={
            "hosted_endpoint_candidate_receipt_sha256": endpoint.receipt_sha256,
            "offline_candidate_only": True,
            "permit_atomically_consumed": False,
            "authenticated_terminal_journal_heads": False,
            "replay_absence_verified": False,
            "observational_yobs": endpoint.yobs_string,
        },
    )


__all__ = [
    "COMPLETE_AGREEMENT_SCHEMA",
    "COMPLETE_OBSERVATION_SCHEMA",
    "DOMAIN_COMPLETE_AGREEMENT",
    "DOMAIN_COMPLETE_OBSERVATION",
    "DOMAIN_DUAL_AGREEMENT",
    "DOMAIN_HOSTED_POLL",
    "DOMAIN_SUBMISSION_BINDING",
    "DUAL_AGREEMENT_SCHEMA",
    "HOSTED_ENDPOINT_SCHEMA",
    "HOSTED_POLL_SCHEMA",
    "MAX_SCORE_OR_CUTOFF",
    "OfflineCompleteAgreementCandidate",
    "OfflineHostedEndpointCandidate",
    "OfflinePollAgreementCandidate",
    "OfflineSubmissionBindingCandidate",
    "POLL_OFFSETS_MINUTES",
    "POLL_WINDOW_SECONDS",
    "SUBMISSION_BINDING_SCHEMA",
    "TLS_PEER_SCHEMA",
    "assess_hosted_endpoint",
    "validate_complete_agreement",
    "validate_dual_collector_agreement",
    "validate_four_poll_endpoint",
    "validate_hosted_endpoint",
    "validate_submission_binding",
]
