"""Auditor-controlled Kaggle evidence boundary for evaluation v6.3.

Kaggle does not expose a host-signed archive digest, execution receipt, or
outcome signature.  This module therefore validates only Sol's weaker
AUDITOR_UPLOAD_TLS_DUAL_COLLECTOR_OBSERVATIONAL chain.  It contains no network
client, uploader, credential handler, permit issuer, or production gate.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
import hashlib
from typing import Any

from evaluation_v6_2.integration_v622 import SLOTS

from .common import (
    V63Error,
    canonical_integer,
    canonical_sha256,
    decimal_string,
    exact,
    fail,
    identifier,
    sha256,
    utc,
    verify_signature_set,
    zero_authority,
)
from .hybrid_trust import ValidatedHybridProfile


UPLOAD_AUTHORIZATION_SCHEMA = "eval.v6.3.hosted-upload-authorization"
FILE_IDENTITY_SCHEMA = "eval.v6.3.file-identity"
TLS_PEER_SCHEMA = "eval.v6.3.tls-peer-evidence"
UPLOAD_TRANSPORT_SCHEMA = "eval.v6.3.upload-transport-receipt"
SUBMISSION_RECORD_SCHEMA = "eval.v6.3.kaggle-submission-record"
HISTORY_SNAPSHOT_SCHEMA = "eval.v6.3.submission-history-snapshot"
SUBMISSION_BINDING_SCHEMA = "eval.v6.3.submission-binding-receipt"
COMPLETE_OBSERVATION_SCHEMA = "eval.v6.3.complete-observation"
COMPLETE_AGREEMENT_SCHEMA = "eval.v6.3.complete-agreement"
HOSTED_POLL_SCHEMA = "eval.v6.3.hosted-poll-receipt"
DUAL_AGREEMENT_SCHEMA = "eval.v6.3.dual-collector-agreement"
EPISODE_CHRONOLOGY_SCHEMA = "eval.v6.3.episode-chronology-receipt"
EPISODE_RECORD_SCHEMA = "eval.v6.3.episode-record"
ACCOUNT_CHRONOLOGY_SCHEMA = "eval.v6.3.account-chronology-receipt"
ACCOUNT_SNAPSHOT_SCHEMA = "eval.v6.3.account-history-snapshot"
LIMITATIONS_SCHEMA = "eval.v6.3.hosted-evidence-limitations"

EVIDENCE_CLASS = "AUDITOR_UPLOAD_TLS_DUAL_COLLECTOR_OBSERVATIONAL"
KAGGLE_HOSTS = frozenset({"api.kaggle.com", "www.kaggle.com"})
POLL_OFFSETS_MINUTES = {1: 60, 2: 120, 3: 240, 4: 480}
POLL_WINDOW_SECONDS = 600

DOMAIN_UPLOAD_AUTHORIZATION = b"EVAL-V63/HOSTED-UPLOAD-AUTHORIZATION\0"
DOMAIN_UPLOAD_TRANSPORT = b"EVAL-V63/UPLOAD-TRANSPORT-RECEIPT\0"
DOMAIN_SUBMISSION_BINDING = b"EVAL-V63/SUBMISSION-BINDING-RECEIPT\0"
DOMAIN_COMPLETE_OBSERVATION = b"EVAL-V63/COMPLETE-OBSERVATION\0"
DOMAIN_COMPLETE_AGREEMENT = b"EVAL-V63/COMPLETE-AGREEMENT\0"
DOMAIN_HOSTED_POLL = b"EVAL-V63/HOSTED-POLL-RECEIPT\0"
DOMAIN_DUAL_AGREEMENT = b"EVAL-V63/DUAL-COLLECTOR-AGREEMENT\0"
DOMAIN_EPISODE_CHRONOLOGY = b"EVAL-V63/EPISODE-CHRONOLOGY\0"
DOMAIN_ACCOUNT_CHRONOLOGY = b"EVAL-V63/ACCOUNT-CHRONOLOGY\0"


FAILURE_STATES = frozenset(
    {
        "UPLOAD_OPERATOR_NOT_AUDITOR_CONTROLLED",
        "UPLOAD_AUTHORIZATION_INVALID",
        "ARCHIVE_UPLOAD_HASH_MISMATCH",
        "UPLOAD_TOCTOU_DETECTED",
        "UPLOAD_STREAM_LENGTH_MISMATCH",
        "TLS_PEER_AUTHENTICATION_FAILED",
        "UPLOAD_RESPONSE_UNAVAILABLE",
        "SUBMISSION_BINDING_ZERO_MATCH",
        "SUBMISSION_BINDING_AMBIGUOUS",
        "SUBMISSION_METADATA_MISMATCH",
        "COMPLETE_OBSERVATION_DISAGREEMENT",
        "COLLECTOR_INDEPENDENCE_INVALID",
        "DUAL_COLLECTOR_DISAGREEMENT",
        "POLL_OUTSIDE_WINDOW",
        "CUTOFF_NOT_SYNCHRONIZED",
        "MATURE_POLL_MISSING",
        "OUT_OF_BAND_UPLOAD_DETECTED",
        "EPISODE_LINK_UNIDENTIFIED",
        "HOST_CUSTODY_CLAIM_OVERSTATED",
        "HOSTED_EVIDENCE_INCOMPLETE",
    }
)


@dataclass(frozen=True)
class ValidatedPollAgreement:
    """Output of the signed, schedule-aware dual-collector validator."""

    receipt_sha256: str
    poll_index: int
    score: str
    rank10_cutoff: str
    cross_collector_skew_seconds: int


_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema",
        "profile_sha256",
        "campaign_root_sha256",
        "slot_id",
        "competition_ref",
        "account_team_identifier",
        "archive_sha256",
        "archive_byte_length",
        "package_sha256",
        "source_tree_sha256",
        "build_recipe_sha256",
        "linux_amd64_reproducibility_receipt_root_sha256",
        "live_challenge_sha256",
        "approved_extension",
        "expected_file_name",
        "expected_message",
        "submission_token",
        "uploader_party_id",
        "witness_party_id",
        "custody_reviewer_party_id",
        "uploader_build_root_sha256",
        "uploader_runtime_root_sha256",
        "upload_window_start",
        "upload_window_end",
        "pre_upload_history_root_a_sha256",
        "pre_upload_history_root_b_sha256",
        "signatures",
    }
)


def submission_token(
    *,
    campaign_root_sha256: str,
    slot_id: str,
    archive_sha256: str,
    live_challenge_sha256: str,
) -> str:
    """Return the content-derived 20-character v6.3 submission token."""

    digest = hashlib.sha256(
        b"EVAL-V63/KAGGLE-SUBMISSION"
        + campaign_root_sha256.encode("ascii")
        + slot_id.encode("ascii")
        + archive_sha256.encode("ascii")
        + live_challenge_sha256.encode("ascii")
    ).digest()
    return base64.b32encode(digest).decode("ascii")[:20].lower()


def _profile_identities(profile: ValidatedHybridProfile) -> Mapping[str, Mapping[str, Any]]:
    if type(profile) is not ValidatedHybridProfile:
        raise fail("UPLOAD_AUTHORIZATION_INVALID", "hosted evidence requires an immutable validated hybrid profile")
    identities = profile.get("identities")
    if not isinstance(identities, Mapping) or set(identities) != {"A", "B", "C", "D", "E"}:
        raise fail("UPLOAD_AUTHORIZATION_INVALID", "parsed v6.3 profile identities are unavailable")
    return identities


def validate_upload_authorization(value: Any, *, profile: ValidatedHybridProfile) -> dict[str, Any]:
    code = "UPLOAD_AUTHORIZATION_INVALID"
    item = exact(value, _AUTHORIZATION_FIELDS, "hosted upload authorization", code=code)
    if item["schema"] != UPLOAD_AUTHORIZATION_SCHEMA or item["profile_sha256"] != profile["sha256"]:
        raise fail(code, "upload authorization is not bound to the v6.3 profile")
    transport_policy = profile.get("hosted_transport_policy")
    identities = _profile_identities(profile)
    if not isinstance(transport_policy, Mapping):
        raise fail(code, "parsed v6.3 hosted transport policy is unavailable")
    expected_competition = transport_policy.get("competition_ref")
    expected_account = transport_policy.get("account_team_identifier")
    if (
        item["competition_ref"] != expected_competition
        or item["account_team_identifier"] != expected_account
    ):
        raise fail(code, "upload authorization competition or account is not profile-bound")
    slot_id = identifier(item["slot_id"], "slot id", code=code)
    if slot_id not in SLOTS:
        raise fail(code, "slot id is outside the frozen 16-slot population")
    campaign_root = sha256(item["campaign_root_sha256"], "campaign root", code=code)
    archive = sha256(item["archive_sha256"], "archive hash", code=code)
    challenge = sha256(item["live_challenge_sha256"], "live challenge", code=code)
    for field in (
        "package_sha256",
        "source_tree_sha256",
        "build_recipe_sha256",
        "linux_amd64_reproducibility_receipt_root_sha256",
        "uploader_build_root_sha256",
        "uploader_runtime_root_sha256",
        "pre_upload_history_root_a_sha256",
        "pre_upload_history_root_b_sha256",
    ):
        sha256(item[field], field, code=code)
    archive_length = canonical_integer(item["archive_byte_length"], "archive byte length", code=code, minimum=1)
    for field in ("competition_ref", "account_team_identifier"):
        identifier(item[field], field, code=code)
    if item["approved_extension"] != ".tar.gz":
        raise fail(code, "only the frozen .tar.gz extension is approved")
    token = submission_token(
        campaign_root_sha256=campaign_root,
        slot_id=slot_id,
        archive_sha256=archive,
        live_challenge_sha256=challenge,
    )
    expected_name = f"cal-{slot_id.lower()}-{token}.tar.gz"
    expected_message = f"cal-{slot_id.lower()}-{token}"
    if (
        item["submission_token"] != token
        or item["expected_file_name"] != expected_name
        or item["expected_message"] != expected_message
    ):
        raise fail(code, "content-derived token, filename, or message mismatch")
    if "final" in expected_name.lower() or "final" in expected_message.lower():
        raise fail(code, "submitted names must not contain final")
    if (
        item["uploader_party_id"] != "A"
        or item["witness_party_id"] != "B"
        or item["custody_reviewer_party_id"] != "C"
    ):
        raise fail("UPLOAD_OPERATOR_NOT_AUDITOR_CONTROLLED", "upload custody must be A/B/C")
    if identities["A"]["project_access_role"] != "NONE":
        raise fail("UPLOAD_OPERATOR_NOT_AUDITOR_CONTROLLED", "uploader A must grant the project no runtime access")
    start = utc(item["upload_window_start"], "upload window start", code=code)
    end = utc(item["upload_window_end"], "upload window end", code=code)
    if end <= start or end - start > timedelta(hours=1):
        raise fail(code, "upload window must be positive and no longer than one hour")
    core = {key: item[key] for key in item if key != "signatures"}
    key_ids = verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_UPLOAD_AUTHORIZATION,
        identities=identities,
        required_party_ids=("A", "B", "C"),
        code=code,
    )
    return {
        "raw": dict(item),
        "core": core,
        "sha256": canonical_sha256(item),
        "slot_id": slot_id,
        "campaign_root_sha256": campaign_root,
        "archive_sha256": archive,
        "archive_byte_length": archive_length,
        "live_challenge_sha256": challenge,
        "expected_file_name": expected_name,
        "expected_message": expected_message,
        "upload_window_start": start,
        "upload_window_end": end,
        "signer_key_ids": key_ids,
    }


_FILE_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "path_token_sha256",
        "device_id",
        "inode",
        "file_size",
        "mtime_ns",
        "sha256",
    }
)


def _file_identity(value: Any, *, label: str) -> dict[str, Any]:
    code = "UPLOAD_TOCTOU_DETECTED"
    item = exact(value, _FILE_IDENTITY_FIELDS, label, code=code)
    if item["schema"] != FILE_IDENTITY_SCHEMA:
        raise fail(code, f"{label} schema mismatch")
    sha256(item["path_token_sha256"], f"{label} path token", code=code)
    sha256(item["sha256"], f"{label} hash", code=code)
    for field in ("device_id", "inode", "file_size", "mtime_ns"):
        canonical_integer(item[field], f"{label} {field}", code=code)
    return dict(item)


_TLS_FIELDS = frozenset(
    {
        "schema",
        "hostname",
        "certificate_chain_sha256",
        "spki_sha256",
        "peer_policy_pin_sha256",
        "authenticated",
    }
)


def _tls_peer(value: Any, *, profile: ValidatedHybridProfile) -> dict[str, Any]:
    if type(profile) is not ValidatedHybridProfile:
        raise fail("TLS_PEER_AUTHENTICATION_FAILED", "TLS evidence requires an immutable validated hybrid profile")
    code = "TLS_PEER_AUTHENTICATION_FAILED"
    item = exact(value, _TLS_FIELDS, "TLS peer evidence", code=code)
    transport_policy = profile.get("hosted_transport_policy")
    if not isinstance(transport_policy, Mapping):
        raise fail(code, "parsed v6.3 hosted transport policy is unavailable")
    if (
        item["schema"] != TLS_PEER_SCHEMA
        or item["hostname"] not in transport_policy["allowed_kaggle_hosts"]
        or item["peer_policy_pin_sha256"] != transport_policy["peer_policy_pin_sha256"]
        or item["authenticated"] is not True
    ):
        raise fail(code, "Kaggle TLS peer identity is not authenticated")
    for field in ("certificate_chain_sha256", "spki_sha256", "peer_policy_pin_sha256"):
        sha256(item[field], field, code=code)
    return dict(item)


_TRANSPORT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "archive_file_identity_before",
        "archive_file_identity_after",
        "streamed_archive_sha256",
        "streamed_archive_byte_length",
        "request_response_transcript_root_sha256",
        "tls_peer_identity",
        "raw_upload_response_evidence_id",
        "raw_upload_response_header_sha256",
        "raw_upload_response_body_sha256",
        "raw_upload_response_byte_length",
        "upload_start",
        "upload_end",
        "uploader_party_id",
        "host_signed_archive_digest_present",
        "signatures",
    }
)


def validate_upload_transport(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    item = exact(value, _TRANSPORT_FIELDS, "upload transport receipt", code="HOSTED_EVIDENCE_INCOMPLETE")
    if item["schema"] != UPLOAD_TRANSPORT_SCHEMA or item["authorization_sha256"] != authorization["sha256"]:
        raise fail("UPLOAD_AUTHORIZATION_INVALID", "transport receipt is not bound to the authorization")
    if item["uploader_party_id"] != "A":
        raise fail("UPLOAD_OPERATOR_NOT_AUDITOR_CONTROLLED", "transport uploader must be auditor A")
    if item["host_signed_archive_digest_present"] is not False:
        raise fail("HOST_CUSTODY_CLAIM_OVERSTATED", "Kaggle does not expose a host-signed archive digest")
    before = _file_identity(item["archive_file_identity_before"], label="file identity before")
    after = _file_identity(item["archive_file_identity_after"], label="file identity after")
    if before != after:
        raise fail("UPLOAD_TOCTOU_DETECTED", "archive file identity changed during upload")
    if before["sha256"] != authorization["archive_sha256"] or int(before["file_size"]) != authorization["archive_byte_length"]:
        raise fail("ARCHIVE_UPLOAD_HASH_MISMATCH", "pre-stream archive identity differs from authorization")
    if item["streamed_archive_sha256"] != authorization["archive_sha256"]:
        raise fail("ARCHIVE_UPLOAD_HASH_MISMATCH", "streamed file-part hash differs from authorization")
    streamed_length = canonical_integer(item["streamed_archive_byte_length"], "streamed archive length", code="UPLOAD_STREAM_LENGTH_MISMATCH", minimum=1)
    if streamed_length != authorization["archive_byte_length"]:
        raise fail("UPLOAD_STREAM_LENGTH_MISMATCH", "streamed file-part length differs from authorization")
    sha256(item["request_response_transcript_root_sha256"], "upload transcript root", code="HOSTED_EVIDENCE_INCOMPLETE")
    _tls_peer(item["tls_peer_identity"], profile=profile)
    response_id = identifier(item["raw_upload_response_evidence_id"], "raw upload response evidence id", code="UPLOAD_RESPONSE_UNAVAILABLE")
    for field in ("raw_upload_response_header_sha256", "raw_upload_response_body_sha256"):
        sha256(item[field], field, code="UPLOAD_RESPONSE_UNAVAILABLE")
    response_length = canonical_integer(item["raw_upload_response_byte_length"], "raw upload response length", code="UPLOAD_RESPONSE_UNAVAILABLE", minimum=1)
    start = utc(item["upload_start"], "upload start", code="UPLOAD_AUTHORIZATION_INVALID")
    end = utc(item["upload_end"], "upload end", code="UPLOAD_AUTHORIZATION_INVALID")
    if (
        end < start
        or start < authorization["upload_window_start"]
        or end > authorization["upload_window_end"]
    ):
        raise fail("UPLOAD_AUTHORIZATION_INVALID", "upload occurred outside the authorized window")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_UPLOAD_TRANSPORT,
        identities=_profile_identities(profile),
        required_party_ids=("A",),
        code="UPLOAD_RESPONSE_UNAVAILABLE",
    )
    return {
        "raw": dict(item),
        "sha256": canonical_sha256(item),
        "upload_start": start,
        "upload_end": end,
        "raw_upload_response_evidence_id": response_id,
        "raw_upload_response_byte_length": response_length,
        "streamed_archive_byte_length": streamed_length,
    }


_RECORD_FIELDS = frozenset(
    {"schema", "ref", "file_name", "date", "description", "status", "public_score"}
)


def _submission_record(value: Any, *, label: str) -> dict[str, Any]:
    code = "SUBMISSION_METADATA_MISMATCH"
    item = exact(value, _RECORD_FIELDS, label, code=code)
    if item["schema"] != SUBMISSION_RECORD_SCHEMA:
        raise fail(code, f"{label} schema mismatch")
    parsed = {
        field: identifier(item[field], f"{label} {field}", code=code)
        for field in ("ref", "file_name", "description", "status")
    }
    if item["public_score"] is not None:
        decimal_string(item["public_score"], f"{label} public score", code=code)
    parsed.update({"raw": dict(item), "date": utc(item["date"], f"{label} date", code=code)})
    return parsed


_BINDING_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "transport_receipt_sha256",
        "collector_a_pre_history_root_sha256",
        "collector_a_post_history_root_sha256",
        "collector_b_pre_history_root_sha256",
        "collector_b_post_history_root_sha256",
        "collector_a_pre_records",
        "collector_a_post_records",
        "collector_b_pre_records",
        "collector_b_post_records",
        "collector_a_new_records",
        "collector_b_new_records",
        "matched_submission_ref",
        "exact_matching_decision",
        "signatures",
    }
)


def submission_history_root(records: Any) -> str:
    """Hash one normalized complete Kaggle submission-history snapshot."""

    if type(records) is not list:
        raise fail("HOSTED_EVIDENCE_INCOMPLETE", "submission history records must be a list")
    parsed = [_submission_record(row, label=f"history record {index}") for index, row in enumerate(records)]
    refs = [row["ref"] for row in parsed]
    if refs != sorted(refs) or len(set(refs)) != len(refs):
        raise fail("HOSTED_EVIDENCE_INCOMPLETE", "submission history records must have unique refs sorted canonically")
    return canonical_sha256({"schema": HISTORY_SNAPSHOT_SCHEMA, "records": records})


def _validated_history(records: Any, *, label: str) -> tuple[list[dict[str, Any]], str]:
    root = submission_history_root(records)
    parsed = [_submission_record(row, label=f"{label} record {index}") for index, row in enumerate(records)]
    return parsed, root


def validate_submission_binding(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    authorization: Mapping[str, Any],
    transport: Mapping[str, Any],
) -> dict[str, Any]:
    item = exact(value, _BINDING_FIELDS, "submission binding receipt", code="HOSTED_EVIDENCE_INCOMPLETE")
    if (
        item["schema"] != SUBMISSION_BINDING_SCHEMA
        or item["authorization_sha256"] != authorization["sha256"]
        or item["transport_receipt_sha256"] != transport["sha256"]
    ):
        raise fail("SUBMISSION_METADATA_MISMATCH", "submission binding roots do not match authorization and transport")
    history: dict[str, list[dict[str, Any]]] = {}
    for party, phase, root_field, records_field in (
        ("A", "pre", "collector_a_pre_history_root_sha256", "collector_a_pre_records"),
        ("A", "post", "collector_a_post_history_root_sha256", "collector_a_post_records"),
        ("B", "pre", "collector_b_pre_history_root_sha256", "collector_b_pre_records"),
        ("B", "post", "collector_b_post_history_root_sha256", "collector_b_post_records"),
    ):
        parsed_records, derived_root = _validated_history(item[records_field], label=f"collector {party} {phase} history")
        if item[root_field] != derived_root:
            raise fail("SUBMISSION_METADATA_MISMATCH", f"collector {party} {phase} history root does not bind its complete parsed records")
        history[f"{party}_{phase}"] = parsed_records
    if (
        item["collector_a_pre_history_root_sha256"]
        != authorization["raw"]["pre_upload_history_root_a_sha256"]
        or item["collector_b_pre_history_root_sha256"]
        != authorization["raw"]["pre_upload_history_root_b_sha256"]
    ):
        raise fail("SUBMISSION_METADATA_MISMATCH", "binding pre-upload history roots differ from the signed authorization")
    if item["collector_a_pre_records"] != item["collector_b_pre_records"] or item["collector_a_post_records"] != item["collector_b_post_records"]:
        raise fail("SUBMISSION_METADATA_MISMATCH", "collectors disagree on complete pre/post submission histories")
    pre_refs = {row["ref"] for row in history["A_pre"]}
    post_by_ref = {row["ref"]: row for row in history["A_post"]}
    if not pre_refs.issubset(post_by_ref):
        raise fail("SUBMISSION_METADATA_MISMATCH", "post-upload history lost pre-existing submission refs")
    derived_new_records = [post_by_ref[ref]["raw"] for ref in sorted(set(post_by_ref) - pre_refs)]
    if item["exact_matching_decision"] != "EXACTLY_ONE":
        raise fail("SUBMISSION_METADATA_MISMATCH", "binding decision must be EXACTLY_ONE")
    collector_records: dict[str, list[dict[str, Any]]] = {}
    for party_id, field in (("A", "collector_a_new_records"), ("B", "collector_b_new_records")):
        values = item[field]
        if type(values) is not list:
            raise fail("HOSTED_EVIDENCE_INCOMPLETE", f"collector {party_id} records must be a list")
        collector_records[party_id] = [_submission_record(row, label=f"collector {party_id} record {index}") for index, row in enumerate(values)]
        if values != derived_new_records:
            raise fail("SUBMISSION_METADATA_MISMATCH", f"collector {party_id} new records are not the exact pre/post history difference")
    if any(len(records) == 0 for records in collector_records.values()):
        raise fail("SUBMISSION_BINDING_ZERO_MATCH", "a collector observed no new submission record")
    if any(len(records) > 1 for records in collector_records.values()):
        raise fail("SUBMISSION_BINDING_AMBIGUOUS", "a collector observed multiple own-project records")
    record_a = collector_records["A"][0]
    record_b = collector_records["B"][0]
    if record_a["raw"] != record_b["raw"]:
        raise fail("SUBMISSION_METADATA_MISMATCH", "collectors disagree on the new submission record")
    record = record_a
    lower = transport["upload_start"] - timedelta(seconds=120)
    upper = transport["upload_end"] + timedelta(seconds=600)
    if (
        record["file_name"] != authorization["expected_file_name"]
        or record["description"] != authorization["expected_message"]
        or not lower <= record["date"] <= upper
        or record["ref"] != item["matched_submission_ref"]
    ):
        raise fail("SUBMISSION_METADATA_MISMATCH", "new record does not match filename, message, time window, or ref")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_SUBMISSION_BINDING,
        identities=_profile_identities(profile),
        required_party_ids=("A", "B"),
        code="SUBMISSION_METADATA_MISMATCH",
    )
    return {
        "raw": dict(item),
        "sha256": canonical_sha256(item),
        "matched_submission_ref": record["ref"],
        "file_name": record["file_name"],
        "description": record["description"],
        "record_date": record["date"],
        "upload_start": transport["upload_start"],
        "upload_end": transport["upload_end"],
    }


_COMPLETE_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "profile_sha256",
        "binding_receipt_sha256",
        "collector_party_id",
        "submission_ref",
        "status",
        "observed_at",
        "raw_response_sha256",
        "tls_peer_identity",
        "signatures",
    }
)


def _complete_observation(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
    expected_party_id: str,
) -> dict[str, Any]:
    code = "COMPLETE_OBSERVATION_DISAGREEMENT"
    item = exact(value, _COMPLETE_OBSERVATION_FIELDS, f"COMPLETE observation {expected_party_id}", code=code)
    if (
        item["schema"] != COMPLETE_OBSERVATION_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["binding_receipt_sha256"] != binding["sha256"]
        or item["collector_party_id"] != expected_party_id
        or item["submission_ref"] != binding["matched_submission_ref"]
        or item["status"] != "COMPLETE"
    ):
        raise fail(code, f"COMPLETE observation {expected_party_id} is not bound correctly")
    sha256(item["raw_response_sha256"], "COMPLETE raw response", code=code)
    _tls_peer(item["tls_peer_identity"], profile=profile)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_COMPLETE_OBSERVATION,
        identities=_profile_identities(profile),
        required_party_ids=(expected_party_id,),
        code=code,
    )
    return {"raw": dict(item), "sha256": canonical_sha256(item), "observed_at": utc(item["observed_at"], "COMPLETE observed_at", code=code)}


def validate_complete_agreement(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    code = "COMPLETE_OBSERVATION_DISAGREEMENT"
    item = exact(
        value,
        frozenset({"schema", "collector_a_observation", "collector_b_observation", "signatures"}),
        "COMPLETE agreement",
        code=code,
    )
    if item["schema"] != COMPLETE_AGREEMENT_SCHEMA:
        raise fail(code, "COMPLETE agreement schema mismatch")
    a = _complete_observation(item["collector_a_observation"], profile=profile, binding=binding, expected_party_id="A")
    b = _complete_observation(item["collector_b_observation"], profile=profile, binding=binding, expected_party_id="B")
    if abs(a["observed_at"] - b["observed_at"]) > timedelta(seconds=120):
        raise fail(code, "collectors did not observe COMPLETE within 120 seconds")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_COMPLETE_AGREEMENT,
        identities=_profile_identities(profile),
        required_party_ids=("A", "B"),
        code=code,
    )
    return {
        "raw": dict(item),
        "sha256": canonical_sha256(item),
        "t0": min(a["observed_at"], b["observed_at"]),
        "collector_observation_sha256s": (a["sha256"], b["sha256"]),
    }


_POLL_FIELDS = frozenset(
    {
        "schema",
        "profile_sha256",
        "binding_receipt_sha256",
        "collector_party_id",
        "poll_index",
        "scheduled_window_start",
        "scheduled_window_end",
        "submission_ref",
        "file_name",
        "description",
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


def validate_hosted_poll(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
    t0: datetime,
    expected_party_id: str,
    expected_poll_index: int,
) -> dict[str, Any]:
    code = "POLL_OUTSIDE_WINDOW"
    item = exact(value, _POLL_FIELDS, f"poll {expected_poll_index} collector {expected_party_id}", code="HOSTED_EVIDENCE_INCOMPLETE")
    if expected_poll_index not in POLL_OFFSETS_MINUTES:
        raise fail(code, "poll index must be 1 through 4")
    poll_index = canonical_integer(item["poll_index"], "poll index", code=code, minimum=1)
    if (
        item["schema"] != HOSTED_POLL_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["binding_receipt_sha256"] != binding["sha256"]
        or item["collector_party_id"] != expected_party_id
        or poll_index != expected_poll_index
        or item["submission_ref"] != binding["matched_submission_ref"]
        or item["file_name"] != binding["file_name"]
        or item["description"] != binding["description"]
        or item["status"] != "COMPLETE"
    ):
        raise fail("DUAL_COLLECTOR_DISAGREEMENT", "poll identity or submission metadata mismatch")
    expected_start = t0 + timedelta(minutes=POLL_OFFSETS_MINUTES[poll_index])
    expected_end = expected_start + timedelta(seconds=POLL_WINDOW_SECONDS)
    provided_start = utc(item["scheduled_window_start"], "scheduled window start", code=code)
    provided_end = utc(item["scheduled_window_end"], "scheduled window end", code=code)
    if provided_start != expected_start or provided_end != expected_end:
        raise fail(code, "poll window differs from the frozen COMPLETE-relative schedule")
    score_time = utc(item["score_observed_at"], "score observed_at", code=code)
    leaderboard_time = utc(item["leaderboard_observed_at"], "leaderboard observed_at", code=code)
    if not (expected_start <= score_time <= expected_end and expected_start <= leaderboard_time <= expected_end):
        raise fail(code, "poll observation is outside its ten-minute window")
    local_skew = abs(int((score_time - leaderboard_time).total_seconds()))
    if local_skew > 60:
        raise fail("CUTOFF_NOT_SYNCHRONIZED", "score and rank-10 cutoff were collected more than 60 seconds apart")
    score = decimal_string(item["parsed_score"], "parsed score", code="DUAL_COLLECTOR_DISAGREEMENT")
    cutoff = decimal_string(item["parsed_rank10_cutoff"], "parsed rank-10 cutoff", code="DUAL_COLLECTOR_DISAGREEMENT")
    for field in ("submission_response_sha256", "leaderboard_response_sha256"):
        sha256(item[field], field, code="HOSTED_EVIDENCE_INCOMPLETE")
    _tls_peer(item["tls_peer_identity"], profile=profile)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_HOSTED_POLL,
        identities=_profile_identities(profile),
        required_party_ids=(expected_party_id,),
        code="DUAL_COLLECTOR_DISAGREEMENT",
    )
    midpoint = min(score_time, leaderboard_time) + abs(score_time - leaderboard_time) / 2
    return {
        "raw": dict(item),
        "sha256": canonical_sha256(item),
        "party_id": expected_party_id,
        "poll_index": poll_index,
        "score": score,
        "rank10_cutoff": cutoff,
        "score_time": score_time,
        "leaderboard_time": leaderboard_time,
        "local_skew_seconds": local_skew,
        "midpoint": midpoint,
    }


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


def validate_dual_collector_agreement(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
    t0: datetime,
    collector_a_poll: Any,
    collector_b_poll: Any,
    expected_poll_index: int,
) -> dict[str, Any]:
    code = "DUAL_COLLECTOR_DISAGREEMENT"
    item = exact(value, _AGREEMENT_FIELDS, f"dual collector agreement {expected_poll_index}", code=code)
    if item["schema"] != DUAL_AGREEMENT_SCHEMA or item["agreement_result"] != "AGREE":
        raise fail(code, "dual collector agreement schema or result mismatch")
    if canonical_integer(item["poll_index"], "agreement poll index", code=code, minimum=1) != expected_poll_index:
        raise fail(code, "dual collector agreement poll index mismatch")
    a = validate_hosted_poll(
        collector_a_poll,
        profile=profile,
        binding=binding,
        t0=t0,
        expected_party_id="A",
        expected_poll_index=expected_poll_index,
    )
    b = validate_hosted_poll(
        collector_b_poll,
        profile=profile,
        binding=binding,
        t0=t0,
        expected_party_id="B",
        expected_poll_index=expected_poll_index,
    )
    receipt_hashes = item["collector_receipt_sha256s"]
    if type(receipt_hashes) is not dict or receipt_hashes != {"A": a["sha256"], "B": b["sha256"]}:
        raise fail(code, "agreement does not bind the two collector receipts")
    equality = item["parsed_equality_vector"]
    expected_equality = {
        "description": True,
        "file_name": True,
        "parsed_rank10_cutoff": True,
        "parsed_score": True,
        "status": True,
        "submission_ref": True,
    }
    actual_equal = (
        a["score"] == b["score"]
        and a["rank10_cutoff"] == b["rank10_cutoff"]
        and a["raw"]["submission_ref"] == b["raw"]["submission_ref"]
        and a["raw"]["file_name"] == b["raw"]["file_name"]
        and a["raw"]["description"] == b["raw"]["description"]
        and a["raw"]["status"] == b["raw"]["status"]
    )
    if equality != expected_equality or not actual_equal:
        raise fail(code, "collectors disagree on canonical parsed values")
    local_skews = item["local_timestamp_skews_seconds"]
    expected_local_skews = {"A": str(a["local_skew_seconds"]), "B": str(b["local_skew_seconds"])}
    if local_skews != expected_local_skews:
        raise fail("CUTOFF_NOT_SYNCHRONIZED", "reported local timestamp skews are incorrect")
    cross_skew = abs(int((a["midpoint"] - b["midpoint"]).total_seconds()))
    if cross_skew > 120 or item["cross_collector_skew_seconds"] != str(cross_skew):
        raise fail(code, "collector midpoints differ by more than 120 seconds or skew is misstated")
    canonical_integer(item["accepted_attempt_index"], "accepted attempt index", code=code, minimum=1)
    identities = _profile_identities(profile)
    if (
        identities["A"]["control_group_id"] == identities["B"]["control_group_id"]
        or identities["A"]["provider_account_id"] == identities["B"]["provider_account_id"]
    ):
        raise fail("COLLECTOR_INDEPENDENCE_INVALID", "collectors share a control group or runtime account")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_DUAL_AGREEMENT,
        identities=identities,
        required_party_ids=("A", "B"),
        code=code,
    )
    return ValidatedPollAgreement(
        receipt_sha256=canonical_sha256(item),
        poll_index=expected_poll_index,
        score=a["score"],
        rank10_cutoff=a["rank10_cutoff"],
        cross_collector_skew_seconds=cross_skew,
    )


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def validate_four_poll_endpoint(agreements: Sequence[ValidatedPollAgreement]) -> dict[str, Any]:
    if type(agreements) not in {list, tuple} or len(agreements) != 4:
        raise fail("MATURE_POLL_MISSING", "exactly four mature dual-collector polls are required")
    if any(type(item) is not ValidatedPollAgreement for item in agreements):
        raise fail("HOSTED_EVIDENCE_INCOMPLETE", "endpoint inputs must be outputs of the dual-collector validator")
    if [item.poll_index for item in agreements] != [1, 2, 3, 4]:
        raise fail("MATURE_POLL_MISSING", "mature polls must be complete and ordered 1 through 4")
    deltas = [
        Decimal(decimal_string(item.score, "validated poll score", code="HOSTED_EVIDENCE_INCOMPLETE"))
        - Decimal(decimal_string(item.rank10_cutoff, "validated poll rank-10 cutoff", code="HOSTED_EVIDENCE_INCOMPLETE"))
        for item in agreements
    ]
    ordered = sorted(deltas)
    median = (ordered[1] + ordered[2]) / Decimal(2)
    return {
        "schema": "eval.v6.3.observational-hosted-endpoint",
        "evidence_class": EVIDENCE_CLASS,
        "poll_count": 4,
        "poll_deltas": [_canonical_decimal(value) for value in deltas],
        "yobs_median_score_minus_rank10_cutoff": _canonical_decimal(median),
        "conditional_on_custody_success": True,
        "exact_host_execution_claimed": False,
    }


_LIMITATION_FIELDS = frozenset(
    {
        "schema",
        "host_signed_archive_digest",
        "host_signed_execution_receipt",
        "host_signed_outcome_receipt",
        "exact_archive_persisted_by_host_proven",
        "exact_archive_executed_by_host_proven",
        "hosted_observations_nonrepudiable",
        "evidence_class",
    }
)


def validate_hosted_limitations(value: Any) -> dict[str, Any]:
    code = "HOST_CUSTODY_CLAIM_OVERSTATED"
    item = exact(value, _LIMITATION_FIELDS, "hosted evidence limitations", code=code)
    if item["schema"] != LIMITATIONS_SCHEMA or item["evidence_class"] != EVIDENCE_CLASS:
        raise fail(code, "hosted evidence class is overstated or incorrect")
    false_fields = set(_LIMITATION_FIELDS) - {"schema", "evidence_class"}
    if any(item[field] is not False for field in false_fields):
        raise fail(code, "Kaggle host custody or nonrepudiation is overstated")
    return dict(item)


_EPISODE_FIELDS = frozenset(
    {
        "schema",
        "profile_sha256",
        "binding_receipt_sha256",
        "matched_submission_ref",
        "collector_a_raw_episode_root_sha256",
        "collector_b_raw_episode_root_sha256",
        "explicit_submission_id_mapping_evidence_sha256",
        "explicit_submission_id",
        "ordered_episode_records",
        "episode_link_status",
        "no_inferred_join",
        "signatures",
    }
)


def validate_episode_chronology(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    code = "EPISODE_LINK_UNIDENTIFIED"
    item = exact(value, _EPISODE_FIELDS, "episode chronology", code=code)
    if (
        item["schema"] != EPISODE_CHRONOLOGY_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["binding_receipt_sha256"] != binding["sha256"]
        or item["matched_submission_ref"] != binding["matched_submission_ref"]
        or item["no_inferred_join"] is not True
    ):
        raise fail(code, "episode chronology is not exactly bound or forbids no inferred join")
    for field in ("collector_a_raw_episode_root_sha256", "collector_b_raw_episode_root_sha256"):
        sha256(item[field], field, code=code)
    status = item["episode_link_status"]
    records = item["ordered_episode_records"]
    if status == "UNIDENTIFIED":
        if (
            item["explicit_submission_id_mapping_evidence_sha256"] is not None
            or item["explicit_submission_id"] is not None
            or records != []
        ):
            raise fail(code, "unidentified episode link must not claim mapped records")
    elif status == "LINKED":
        mapping_root = sha256(item["explicit_submission_id_mapping_evidence_sha256"], "submissionId mapping evidence", code=code)
        submission_id = identifier(item["explicit_submission_id"], "explicit submissionId", code=code)
        if type(records) is not list:
            raise fail(code, "ordered episode records must be a list")
        parsed_records = []
        record_fields = frozenset(
            {
                "schema",
                "episode_id",
                "create_time",
                "end_time",
                "state",
                "type",
                "submission_id",
                "index",
                "reward",
                "team_name",
                "team_id",
            }
        )
        for index, record in enumerate(records):
            parsed = exact(record, record_fields, f"episode record {index}", code=code)
            if parsed["schema"] != EPISODE_RECORD_SCHEMA or parsed["submission_id"] != submission_id:
                raise fail(code, "episode record lacks the explicit submissionId mapping")
            create_time = utc(parsed["create_time"], "episode create_time", code=code)
            end_time = utc(parsed["end_time"], "episode end_time", code=code)
            if end_time < create_time:
                raise fail(code, "episode ends before it starts")
            for field in ("episode_id", "state", "type", "index", "reward", "team_name", "team_id"):
                identifier(parsed[field], f"episode {field}", code=code)
            parsed_records.append((create_time, parsed["episode_id"]))
        if parsed_records != sorted(parsed_records):
            raise fail(code, "episode records are not in hosted chronological order")
    else:
        raise fail(code, "episode_link_status must be LINKED or UNIDENTIFIED")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_EPISODE_CHRONOLOGY,
        identities=_profile_identities(profile),
        required_party_ids=("A", "B"),
        code=code,
    )
    return {
        "episode_link_status": status,
        "episode_claims_authorized": status == "LINKED",
        "record_count": len(records),
        "mapping_evidence_sha256": item["explicit_submission_id_mapping_evidence_sha256"],
    }


_ACCOUNT_FIELDS = frozenset(
    {
        "schema",
        "profile_sha256",
        "binding_receipt_sha256",
        "monitoring_start",
        "monitoring_end",
        "collector_a_snapshots",
        "collector_b_snapshots",
        "signatures",
    }
)

_ACCOUNT_SNAPSHOT_FIELDS = frozenset(
    {
        "schema",
        "checkpoint",
        "observed_at",
        "raw_response_sha256",
        "canonical_records_root_sha256",
        "records",
    }
)
_ACCOUNT_CHECKPOINTS = ("PRE_UPLOAD", "POST_BINDING", "T1", "T2", "T3", "T4")


def _account_snapshot(value: Any, *, expected_checkpoint: str, party_id: str) -> dict[str, Any]:
    code = "OUT_OF_BAND_UPLOAD_DETECTED"
    item = exact(value, _ACCOUNT_SNAPSHOT_FIELDS, f"account snapshot {party_id}/{expected_checkpoint}", code=code)
    if item["schema"] != ACCOUNT_SNAPSHOT_SCHEMA or item["checkpoint"] != expected_checkpoint:
        raise fail(code, f"account snapshot {party_id}/{expected_checkpoint} schema or checkpoint mismatch")
    sha256(item["raw_response_sha256"], "account snapshot raw response", code=code)
    parsed, derived_root = _validated_history(item["records"], label=f"account snapshot {party_id}/{expected_checkpoint}")
    if item["canonical_records_root_sha256"] != derived_root:
        raise fail(code, f"account snapshot {party_id}/{expected_checkpoint} root does not bind complete records")
    return {
        "raw": dict(item),
        "records": parsed,
        "records_raw": item["records"],
        "observed_at": utc(item["observed_at"], "account snapshot observed_at", code=code),
    }


def validate_account_chronology(
    value: Any,
    *,
    profile: ValidatedHybridProfile,
    binding: Mapping[str, Any],
    t0: datetime,
) -> dict[str, Any]:
    code = "OUT_OF_BAND_UPLOAD_DETECTED"
    item = exact(value, _ACCOUNT_FIELDS, "account chronology", code=code)
    if (
        item["schema"] != ACCOUNT_CHRONOLOGY_SCHEMA
        or item["profile_sha256"] != profile["sha256"]
        or item["binding_receipt_sha256"] != binding["sha256"]
    ):
        raise fail(code, "account chronology is not bound to the hosted unit")
    start = utc(item["monitoring_start"], "monitoring start", code=code)
    end = utc(item["monitoring_end"], "monitoring end", code=code)
    if start > binding["upload_start"] or end < t0 + timedelta(minutes=480, seconds=POLL_WINDOW_SECONDS):
        raise fail(code, "account chronology does not cover pre-upload through t4")
    snapshots: dict[str, list[dict[str, Any]]] = {}
    for party_id, field in (("A", "collector_a_snapshots"), ("B", "collector_b_snapshots")):
        values = item[field]
        if type(values) is not list or len(values) != len(_ACCOUNT_CHECKPOINTS):
            raise fail(code, f"collector {party_id} must provide all six complete history snapshots")
        snapshots[party_id] = [
            _account_snapshot(value, expected_checkpoint=checkpoint, party_id=party_id)
            for value, checkpoint in zip(values, _ACCOUNT_CHECKPOINTS, strict=True)
        ]
    for index, checkpoint in enumerate(_ACCOUNT_CHECKPOINTS):
        a = snapshots["A"][index]
        b = snapshots["B"][index]
        if a["records_raw"] != b["records_raw"] or abs(a["observed_at"] - b["observed_at"]) > timedelta(seconds=120):
            raise fail(code, f"collectors disagree on complete account history at {checkpoint}")
    pre = snapshots["A"][0]
    if pre["observed_at"] > binding["upload_start"] or pre["observed_at"] < start:
        raise fail(code, "PRE_UPLOAD account snapshot is outside the monitored pre-upload interval")
    post = snapshots["A"][1]
    if post["observed_at"] < binding["record_date"] or post["observed_at"] > t0 + timedelta(seconds=120):
        raise fail(code, "POST_BINDING account snapshot is outside the binding/COMPLETE interval")
    checkpoint_times = [snapshot["observed_at"] for snapshot in snapshots["A"]]
    if not (
        checkpoint_times[0] < checkpoint_times[1]
        <= checkpoint_times[2]
        <= checkpoint_times[3]
        <= checkpoint_times[4]
        <= checkpoint_times[5]
    ):
        raise fail(code, "account checkpoints are not strictly ordered before POST_BINDING and nondecreasing thereafter")
    for index in range(1, 5):
        snapshot = snapshots["A"][index + 1]
        window_start = t0 + timedelta(minutes=POLL_OFFSETS_MINUTES[index])
        window_end = window_start + timedelta(seconds=POLL_WINDOW_SECONDS)
        if not window_start <= snapshot["observed_at"] <= window_end:
            raise fail(code, f"T{index} account snapshot is outside the frozen poll window")
    pre_refs = {row["ref"] for row in pre["records"]}
    if binding["matched_submission_ref"] in pre_refs:
        raise fail("SUBMISSION_BINDING_ZERO_MATCH", "matched submission ref already existed before upload")
    allowed_refs = pre_refs | {binding["matched_submission_ref"]}
    for checkpoint_index, snapshot in enumerate(snapshots["A"][1:], start=1):
        refs = {row["ref"] for row in snapshot["records"]}
        if not pre_refs.issubset(refs) or binding["matched_submission_ref"] not in refs:
            raise fail(code, f"account history at {_ACCOUNT_CHECKPOINTS[checkpoint_index]} lost expected refs")
        unexpected = refs - allowed_refs
        if unexpected:
            raise fail(code, f"out-of-band submission refs observed: {sorted(unexpected)}")
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_ACCOUNT_CHRONOLOGY,
        identities=_profile_identities(profile),
        required_party_ids=("A", "B", "C"),
        code=code,
    )
    return {"sha256": canonical_sha256(item), "monitoring_start": start, "monitoring_end": end}


def assess_observational_hosted_endpoint(
    *,
    limitations: Any,
    agreements: Sequence[ValidatedPollAgreement],
    episode_chronology: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compose a zero-authority research result from already validated inputs."""

    try:
        validate_hosted_limitations(limitations)
        endpoint = validate_four_poll_endpoint(agreements)
    except V63Error as exc:
        return zero_authority(
            exc.code,
            detail=str(exc),
            extra={"observational_endpoint_structurally_valid": False},
        )
    episode_status = "NOT_PROVIDED"
    if episode_chronology is not None:
        episode_status = str(episode_chronology.get("episode_link_status", "UNIDENTIFIED"))
    return zero_authority(
        "V6_3_OBSERVATIONAL_ENDPOINT_STRUCTURALLY_VALID_RESEARCH_ONLY",
        detail="Four mature dual-collector polls compose the weaker observational endpoint; external policy pinning, population, and campaign authority remain absent.",
        extra={
            "observational_endpoint_structurally_valid": True,
            "hosted_endpoint": endpoint,
            "episode_link_status": episode_status,
            "offline_conformance_only": True,
        },
    )


__all__ = [
    "ACCOUNT_CHRONOLOGY_SCHEMA",
    "ACCOUNT_SNAPSHOT_SCHEMA",
    "COMPLETE_AGREEMENT_SCHEMA",
    "COMPLETE_OBSERVATION_SCHEMA",
    "DOMAIN_ACCOUNT_CHRONOLOGY",
    "DOMAIN_COMPLETE_AGREEMENT",
    "DOMAIN_COMPLETE_OBSERVATION",
    "DOMAIN_DUAL_AGREEMENT",
    "DOMAIN_EPISODE_CHRONOLOGY",
    "DOMAIN_HOSTED_POLL",
    "DOMAIN_SUBMISSION_BINDING",
    "DOMAIN_UPLOAD_AUTHORIZATION",
    "DOMAIN_UPLOAD_TRANSPORT",
    "DUAL_AGREEMENT_SCHEMA",
    "EPISODE_CHRONOLOGY_SCHEMA",
    "EPISODE_RECORD_SCHEMA",
    "EVIDENCE_CLASS",
    "FILE_IDENTITY_SCHEMA",
    "HOSTED_POLL_SCHEMA",
    "HISTORY_SNAPSHOT_SCHEMA",
    "KAGGLE_HOSTS",
    "LIMITATIONS_SCHEMA",
    "POLL_OFFSETS_MINUTES",
    "SUBMISSION_BINDING_SCHEMA",
    "SUBMISSION_RECORD_SCHEMA",
    "TLS_PEER_SCHEMA",
    "UPLOAD_AUTHORIZATION_SCHEMA",
    "UPLOAD_TRANSPORT_SCHEMA",
    "ValidatedPollAgreement",
    "assess_observational_hosted_endpoint",
    "submission_token",
    "submission_history_root",
    "validate_account_chronology",
    "validate_complete_agreement",
    "validate_dual_collector_agreement",
    "validate_episode_chronology",
    "validate_four_poll_endpoint",
    "validate_hosted_limitations",
    "validate_hosted_poll",
    "validate_submission_binding",
    "validate_upload_authorization",
    "validate_upload_transport",
]
