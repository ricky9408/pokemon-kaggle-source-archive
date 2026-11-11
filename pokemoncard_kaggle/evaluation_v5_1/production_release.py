"""Fail-closed, research-only G14/G15 protocol core.

This is deliberately *not* a holdout runner, credential client, or submission
service.  It validates canonical, hash-only audit descriptions and models the
irreversible state transitions a separately reviewed trusted service would
need.  In particular it never opens a holdout, contacts Kaggle, or turns a
valid-looking receipt into authority.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from .exact_gate_v2 import FAIL_DECISION, REJECTED_DECISION, verify_exact_gate_v2


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
G14_GATE_ID = "G14_CANDIDATE_ROBUSTNESS_RUNTIME_AND_HOLDOUT"
G15_GATE_ID = "G15_RELEASE_CUSTODY"
G14_AUDIT_SCHEMA = "ptcg.g14.opaque-holdout-audit/v1"
G15_BASELINE_SCHEMA = "ptcg.g15.dual-history-baseline/v1"
G15_SCAN_SCHEMA = "ptcg.g15.full-history-scan/v1"
G15_DESCRIPTOR_SCHEMA = "ptcg.g15.request-descriptor/v1"
G15_RELEASE_EVIDENCE_SCHEMA = "ptcg.g15.release-evidence/v1"

MARKER_PREFIX = "PTCGv5.1-"
MARKER_DOMAIN = b"PTCG/SUBMISSION-MARKER/v1"
AUTHORIZATION_DOMAIN = b"PTCG/SUBMISSION-AUTH/v2"
G14_G15_EXACT_V2_FAILURE = "G14_G15_EXACT_V2_NOT_ALLOWLISTED"

# Deliberately immutable and empty.  Supplying a key at runtime is not a way to
# make this research module an authority service.
TRUSTED_VALID_ONLY_SERVICE_KEYS: Mapping[str, bytes] = MappingProxyType({})

HOLDOUT_SEALED = "HOLDOUT_SEALED"
HOLDOUT_CONSUMED_RUNNING = "HOLDOUT_CONSUMED_RUNNING"
HOLDOUT_CONSUMED_COMPLETE = "HOLDOUT_CONSUMED_COMPLETE"
HOLDOUT_CONSUMED_FAILED = "HOLDOUT_CONSUMED_FAILED"
UNREGISTERED = "UNREGISTERED"
AUTHORIZED_UNUSED = "AUTHORIZED_UNUSED"
PREFLIGHT_LOCKED = "PREFLIGHT_LOCKED"
CONSUMED_PENDING = "CONSUMED_PENDING"
REQUEST_SENT = "REQUEST_SENT"
CONSUMED_UNSENT = "CONSUMED_UNSENT"
CONFIRMED = "CONFIRMED"
REJECTED = "REJECTED"
AMBIGUOUS = "AMBIGUOUS"
CONFLICTED = "CONFLICTED"

G14_FAILURE_CODES = frozenset(
    {
        "G14_INVALID_EVIDENCE",
        "G14_G12_BINDING_MISMATCH",
        "G14_G13_BINDING_MISMATCH",
        "G14_ARCHIVE_BINDING_MISMATCH",
        "G14_RUNTIME_AUDIT_INVALID",
        "G14_HOLDOUT_COMMITMENT_INVALID",
        "G14_HOLDOUT_ACCESS_FORBIDDEN",
        "G14_HOLDOUT_TRANSITION_INVALID",
        "G14_HOLDOUT_ALREADY_CONSUMED",
        "G14_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE",
    }
)
G15_FAILURE_CODES = frozenset(
    {
        "G15_INVALID_EVIDENCE",
        "G15_G13_BINDING_MISMATCH",
        "G15_G14_BINDING_MISMATCH",
        "G15_ARCHIVE_BINDING_MISMATCH",
        "G15_ENVELOPE_INVALID",
        "G15_BASELINE_PROSPECTIVITY_INVALID",
        "G15_BASELINE_STALE_OR_PARTIAL",
        "G15_BASELINE_CAPTURE_INVALID",
        "G15_BASELINE_COLLECTOR_SEPARATION_INVALID",
        "G15_BASELINE_HISTORY_CHANGED",
        "G15_AUTHORIZATION_BINDING_INVALID",
        "G15_SECOND_AUTHORIZATION_CONFLICT",
        "G15_INVALID_STATE_TRANSITION",
        "G15_MUTEX_CONFLICT",
        "G15_DESCRIPTOR_INVALID",
        "G15_REDIRECT_OR_RETRY_FORBIDDEN",
        "G15_CAPABILITY_CONSUMED",
        "G15_RESPONSE_ID_MISMATCH",
        "G15_MARKER_MISMATCH",
        "G15_POST_CAPTURE_INVALID",
        "G15_CONCURRENT_SUBMISSION_CONFLICT",
        "G15_TIMEOUT_AMBIGUOUS",
        "G15_EXECUTION_AMBIGUOUS",
        "G15_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE",
    }
)

_SHA256 = set("0123456789abcdef")
_ID_ALLOWED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:@/-")
_G14_FIELDS = frozenset(
    {
        "schema_version", "protocol_id", "campaign_root", "evaluation_id",
        "evaluation_nonce", "gate_id", "attempt", "archive_sha256",
        "archive_length", "g12_bundle_sha256", "g13_bundle_sha256", "g13_selected_archive_sha256",
        "g13_selected_archive_length", "g14_input_root",
        "runtime_digest", "holdout_ciphertext_sha256", "holdout_commitment_root",
        "phase1_audit", "holdout_summary",
    }
)
_PHASE1_FIELDS = frozenset(
    {
        "scheduled_calls", "executed_calls", "unique_calls", "process_starts",
        "restarts", "crashes", "timeouts", "ooms", "schema_errors",
        "forbidden_io", "network_egress", "nondeterminism", "resource_violations",
    }
)
_HOLDOUT_SUMMARY_FIELDS = frozenset(
    {"expected_records", "completed_records", "unique_records", "excluded_records", "retries", "score_statistics_root"}
)
_SCAN_FIELDS = frozenset(
    {
        "schema_version", "collector_id", "principal_id", "credential_key_id",
        "host_id", "network_id", "scan_number", "started_at_ns", "ended_at_ns",
        "cursor_chain", "reported_total", "records", "raw_response_hashes",
        "scan_root",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "submission_id",
        "competition_id",
        "team_id",
        "server_created_at_ns",
        "submission_description",
    }
)
_BASELINE_FIELDS = frozenset(
    {
        "schema_version", "campaign_root", "evaluation_id", "evaluation_nonce",
        "competition_id", "team_id", "registration_ns", "review_not_before_ns",
        "post_capture_deadline_ns", "scans", "baseline_root", "baseline_count",
    }
)
_DESCRIPTOR_FIELDS = frozenset(
    {
        "schema_version", "campaign_root", "evaluation_id", "evaluation_nonce",
        "authorization_id", "competition_id", "team_id", "archive_sha256",
        "archive_length", "g13_bundle_sha256", "g14_bundle_sha256", "g15_input_root",
        "baseline_root", "baseline_registration_sha256", "baseline_identity_root",
        "baseline_count", "marker", "method", "redirect_policy",
        "automatic_retry", "request_descriptor_sha256", "multipart_body_sha256",
        "endpoint_origin", "endpoint_path", "tls_policy_sha256",
        "request_body_media_type", "executor_digest", "runtime_digest",
    }
)
_RELEASE_FIELDS = frozenset(
    {
        "schema_version", "campaign_root", "evaluation_id", "evaluation_nonce",
        "archive_sha256", "archive_length", "g13_bundle_sha256", "g14_bundle_sha256",
        "g14_tested_archive_sha256", "g14_tested_archive_length",
        "g15_input_root", "competition_id", "team_id", "submission_nonce",
        "baseline_root", "baseline_registration_sha256", "baseline_identity_root",
        "baseline_count", "release_intent_sha256", "marker",
        "authorization_id", "endpoint_origin", "endpoint_path", "tls_policy_sha256",
    }
)


class ProductionReleaseError(ValueError):
    """A fixed G14/G15 protocol failure."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def _fail(code: str, message: str = "") -> None:
    if code not in G14_FAILURE_CODES | G15_FAILURE_CODES:
        raise AssertionError(f"unregistered production-release failure code: {code}")
    raise ProductionReleaseError(code, message)


def _exact(value: object, fields: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        _fail(code, "fields are not exact")
    return value


def _sha(value: object, code: str) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in _SHA256 for char in value):
        _fail(code, "SHA-256 must be lowercase hexadecimal")
    return value


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or not value or len(value) > 256 or any(char not in _ID_ALLOWED for char in value):
        _fail(code, "identifier is not canonical")
    return value


def _description(value: object, code: str) -> str:
    if type(value) is not str:
        _fail(code, "submission description is not text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(code, "submission description is not valid UTF-8")
    if len(encoded) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(code, "submission description is not canonical bounded text")
    return value


def _marker(value: object, code: str) -> str:
    if (
        type(value) is not str
        or not value.startswith(MARKER_PREFIX)
        or len(value) != len(MARKER_PREFIX) + 64
        or any(char not in _SHA256 for char in value[len(MARKER_PREFIX):])
    ):
        _fail(code, "authorization marker is not canonical")
    return value


def _u64(value: object, code: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        _fail(code, "value is not uint64")
    return value


def _length_prefixed(parts: Sequence[bytes], domain: bytes) -> str:
    body = bytearray(domain)
    for part in parts:
        body.extend(len(part).to_bytes(8, "big"))
        body.extend(part)
    return hashlib.sha256(bytes(body)).hexdigest()


def _ascii(value: str, code: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        _fail(code, "value must be ASCII")
        raise AssertionError from exc


def derive_authorization_marker(*, campaign_root: str, evaluation_id: str, evaluation_nonce: str, submission_nonce: str) -> str:
    """Derive the immutable, exact submission-description marker."""

    digest = _length_prefixed(
        [_ascii(_sha(campaign_root, "G15_AUTHORIZATION_BINDING_INVALID"), "G15_AUTHORIZATION_BINDING_INVALID"),
         _ascii(_identifier(evaluation_id, "G15_AUTHORIZATION_BINDING_INVALID"), "G15_AUTHORIZATION_BINDING_INVALID"),
         _ascii(_sha(evaluation_nonce, "G15_AUTHORIZATION_BINDING_INVALID"), "G15_AUTHORIZATION_BINDING_INVALID"),
         _ascii(_sha(submission_nonce, "G15_AUTHORIZATION_BINDING_INVALID"), "G15_AUTHORIZATION_BINDING_INVALID")],
        MARKER_DOMAIN,
    )
    return MARKER_PREFIX + digest


def derive_authorization_id(
    *, campaign_root: str, evaluation_id: str, evaluation_nonce: str, competition_id: str,
    team_id: str, archive_sha256: str, archive_length: int, g13_bundle_sha256: str,
    g14_bundle_sha256: str, g15_input_root: str, release_intent_sha256: str,
    submission_nonce: str, baseline_registration_sha256: str,
    baseline_identity_root: str, baseline_count: int, marker: str,
) -> str:
    """Derive the non-circular G15 authorization identity.

    The G15 final-bundle hash intentionally is not an input: binding it here
    would make a self-referential authorization preimage.
    """

    code = "G15_AUTHORIZATION_BINDING_INVALID"
    record = {
        "campaign_root": _sha(campaign_root, code),
        "evaluation_id": _identifier(evaluation_id, code),
        "evaluation_nonce": _sha(evaluation_nonce, code),
        "submission_nonce": _sha(submission_nonce, code),
        "competition_id": _identifier(competition_id, code),
        "kaggle_team_id": _identifier(team_id, code),
        "selected_archive_sha256": _sha(archive_sha256, code),
        "selected_archive_length": _u64(archive_length, code),
        "g13_bundle_sha256": _sha(g13_bundle_sha256, code),
        "g14_bundle_sha256": _sha(g14_bundle_sha256, code),
        "g15_input_bundle_root": _sha(g15_input_root, code),
        "release_intent_hash": _sha(release_intent_sha256, code),
        "submission_history_baseline_registration_hash": _sha(
            baseline_registration_sha256, code
        ),
        "submission_history_baseline_identity_root": _sha(
            baseline_identity_root, code
        ),
        "submission_history_baseline_count": _u64(baseline_count, code),
        "authorization_marker": _marker(marker, code),
    }
    raw = canonical_json_bytes(record)
    return hashlib.sha256(
        AUTHORIZATION_DOMAIN + b"\0" + len(raw).to_bytes(8, "big") + raw
    ).hexdigest()


def _authority_flags() -> dict[str, bool]:
    return {
        "authority": False,
        "evaluator_unseal_authorized": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def _receipt(gate_id: str, code: str | None, **extra: Any) -> dict[str, Any]:
    return {
        "protocol_id": PROTOCOL_ID,
        "gate_id": gate_id,
        "decision": FAIL_DECISION,
        "structural_validation_complete": code is None,
        "failure_codes": ([code] if code else ["G14_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE" if gate_id == G14_GATE_ID else "G15_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"]),
        **extra,
        **_authority_flags(),
    }


def validate_g14_opaque_holdout_audit(evidence: object) -> dict[str, Any]:
    """Validate G14 counters only; the 50 holdout records are never accepted."""

    try:
        item = _exact(evidence, _G14_FIELDS, "G14_INVALID_EVIDENCE")
        if item["schema_version"] != G14_AUDIT_SCHEMA or item["protocol_id"] != PROTOCOL_ID or item["gate_id"] != G14_GATE_ID or item["attempt"] != 0:
            _fail("G14_INVALID_EVIDENCE", "G14 identity mismatch")
        for field in ("campaign_root", "evaluation_nonce", "archive_sha256", "g12_bundle_sha256", "g13_bundle_sha256", "g13_selected_archive_sha256", "g14_input_root", "runtime_digest", "holdout_ciphertext_sha256", "holdout_commitment_root"):
            _sha(item[field], "G14_INVALID_EVIDENCE")
        _identifier(item["evaluation_id"], "G14_INVALID_EVIDENCE")
        _u64(item["archive_length"], "G14_INVALID_EVIDENCE")
        if item["archive_sha256"] != item["g13_selected_archive_sha256"] or item["archive_length"] != _u64(item["g13_selected_archive_length"], "G14_ARCHIVE_BINDING_MISMATCH"):
            _fail("G14_ARCHIVE_BINDING_MISMATCH", "G14 archive is not the exact G13-selected archive")
        phase = _exact(item["phase1_audit"], _PHASE1_FIELDS, "G14_RUNTIME_AUDIT_INVALID")
        for field in phase:
            _u64(phase[field], "G14_RUNTIME_AUDIT_INVALID")
        if (phase["scheduled_calls"], phase["executed_calls"], phase["unique_calls"], phase["process_starts"]) != (50_000, 50_000, 50_000, 1):
            _fail("G14_RUNTIME_AUDIT_INVALID", "required call order or single-process invariant failed")
        if any(phase[field] != 0 for field in _PHASE1_FIELDS - {"scheduled_calls", "executed_calls", "unique_calls", "process_starts"}):
            _fail("G14_RUNTIME_AUDIT_INVALID", "runtime audit contains a prohibited event")
        summary = _exact(item["holdout_summary"], _HOLDOUT_SUMMARY_FIELDS, "G14_HOLDOUT_COMMITMENT_INVALID")
        for field in ("expected_records", "completed_records", "unique_records", "excluded_records", "retries"):
            _u64(summary[field], "G14_HOLDOUT_COMMITMENT_INVALID")
        _sha(summary["score_statistics_root"], "G14_HOLDOUT_COMMITMENT_INVALID")
        if tuple(summary[field] for field in ("expected_records", "completed_records", "unique_records", "excluded_records", "retries")) != (50, 50, 50, 0, 0):
            _fail("G14_HOLDOUT_COMMITMENT_INVALID", "holdout summary must describe exactly 50 unique unretried records")
        return _receipt(G14_GATE_ID, None, archive_sha256=item["archive_sha256"], g13_bundle_sha256=item["g13_bundle_sha256"], input_bundle_root=item["g14_input_root"], holdout_accessed=False)
    except ProductionReleaseError as exc:
        return _receipt(G14_GATE_ID, exc.code, holdout_accessed=False)


def _record_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: record[field]
        for field in (
            "submission_id",
            "competition_id",
            "team_id",
            "server_created_at_ns",
            "submission_description",
        )
    }


def _validate_scan(value: object) -> dict[str, Any]:
    scan = _exact(value, _SCAN_FIELDS, "G15_BASELINE_CAPTURE_INVALID")
    if scan["schema_version"] != G15_SCAN_SCHEMA:
        _fail("G15_BASELINE_CAPTURE_INVALID", "scan schema mismatch")
    for field in ("collector_id", "principal_id", "credential_key_id", "host_id", "network_id"):
        _identifier(scan[field], "G15_BASELINE_CAPTURE_INVALID")
    if scan["scan_number"] not in (1, 2):
        _fail("G15_BASELINE_CAPTURE_INVALID", "each collector has scan one and two")
    start, end = _u64(scan["started_at_ns"], "G15_BASELINE_CAPTURE_INVALID"), _u64(scan["ended_at_ns"], "G15_BASELINE_CAPTURE_INVALID")
    if end < start:
        _fail("G15_BASELINE_CAPTURE_INVALID", "scan end predates scan start")
    chain = scan["cursor_chain"]
    if type(chain) is not list or len(chain) < 2 or chain[0] != "FIRST" or chain[-1] != "TERMINAL" or len(chain) != len(set(chain)) or any(type(cursor) is not str for cursor in chain):
        _fail("G15_BASELINE_CAPTURE_INVALID", "cursor chain is not complete and unique")
    total = _u64(scan["reported_total"], "G15_BASELINE_CAPTURE_INVALID")
    records = scan["records"]
    if type(records) is not list or len(records) != total:
        _fail("G15_BASELINE_STALE_OR_PARTIAL", "reported total does not equal complete history")
    projections: list[dict[str, Any]] = []
    for record_value in records:
        record = _exact(record_value, _RECORD_FIELDS, "G15_BASELINE_CAPTURE_INVALID")
        for field in ("submission_id", "competition_id", "team_id"):
            _identifier(record[field], "G15_BASELINE_CAPTURE_INVALID")
        _u64(record["server_created_at_ns"], "G15_BASELINE_CAPTURE_INVALID")
        _description(record["submission_description"], "G15_BASELINE_CAPTURE_INVALID")
        projections.append(_record_projection(record))
    if projections != sorted(projections, key=lambda row: (row["server_created_at_ns"], row["submission_id"])) or len({row["submission_id"] for row in projections}) != len(projections):
        _fail("G15_BASELINE_CAPTURE_INVALID", "history projection is not canonically sorted and unique")
    hashes = scan["raw_response_hashes"]
    if type(hashes) is not list or len(hashes) < 2:
        _fail("G15_BASELINE_CAPTURE_INVALID", "raw list/detail response hashes are incomplete")
    for digest in hashes:
        _sha(digest, "G15_BASELINE_CAPTURE_INVALID")
    _sha(scan["scan_root"], "G15_BASELINE_CAPTURE_INVALID")
    expected = canonical_sha256({key: scan[key] for key in scan if key != "scan_root"})
    if scan["scan_root"] != expected:
        _fail("G15_BASELINE_CAPTURE_INVALID", "scan root does not bind its complete capture")
    return scan


def _validate_g15_history_capture(value: object, *, phase: str) -> dict[str, Any]:
    """Validate a frozen or live four-scan full-history capture without I/O."""

    if phase not in {"frozen", "live"}:
        raise AssertionError("history capture phase is not registered")

    baseline = _exact(value, _BASELINE_FIELDS, "G15_BASELINE_PROSPECTIVITY_INVALID")
    if baseline["schema_version"] != G15_BASELINE_SCHEMA:
        _fail("G15_BASELINE_PROSPECTIVITY_INVALID", "baseline schema mismatch")
    for field in ("campaign_root", "evaluation_nonce", "baseline_root"):
        _sha(baseline[field], "G15_BASELINE_PROSPECTIVITY_INVALID")
    for field in ("evaluation_id", "competition_id", "team_id"):
        _identifier(baseline[field], "G15_BASELINE_PROSPECTIVITY_INVALID")
    registration, review, deadline = (_u64(baseline[field], "G15_BASELINE_PROSPECTIVITY_INVALID") for field in ("registration_ns", "review_not_before_ns", "post_capture_deadline_ns"))
    if deadline <= review or review < registration:
        _fail("G15_BASELINE_PROSPECTIVITY_INVALID", "registration/review/deadline order is invalid")
    scans_value = baseline["scans"]
    if type(scans_value) is not list or len(scans_value) != 4:
        _fail("G15_BASELINE_CAPTURE_INVALID", "exactly four scans are required")
    scans = [_validate_scan(scan) for scan in scans_value]
    collectors: dict[str, list[dict[str, Any]]] = {}
    for scan in scans:
        collectors.setdefault(scan["collector_id"], []).append(scan)
    if len(collectors) != 2 or any(len(group) != 2 for group in collectors.values()):
        _fail("G15_BASELINE_COLLECTOR_SEPARATION_INVALID", "collectors are not two independently captured pairs")
    all_started, all_ended = [], []
    projection_roots: set[str] = set()
    for group in collectors.values():
        group.sort(key=lambda scan: scan["scan_number"])
        if [scan["scan_number"] for scan in group] != [1, 2]:
            _fail("G15_BASELINE_CAPTURE_INVALID", "collector scan numbers are invalid")
        for field in ("principal_id", "credential_key_id", "host_id", "network_id"):
            if len({scan[field] for scan in group}) != 1:
                _fail("G15_BASELINE_COLLECTOR_SEPARATION_INVALID", f"collector changed {field} between scans")
        gap = group[1]["started_at_ns"] - group[0]["ended_at_ns"]
        if not 60_000_000_000 <= gap <= 120_000_000_000:
            _fail("G15_BASELINE_STALE_OR_PARTIAL", "paired scans are not 60-120 seconds apart")
        for scan in group:
            all_started.append(scan["started_at_ns"])
            all_ended.append(scan["ended_at_ns"])
            projection_roots.add(canonical_sha256([_record_projection(record) for record in scan["records"]]))
    representative_scans = [group[0] for group in collectors.values()]
    for field in ("principal_id", "credential_key_id", "host_id", "network_id"):
        if len({scan[field] for scan in representative_scans}) != 2:
            _fail("G15_BASELINE_COLLECTOR_SEPARATION_INVALID", f"collectors share {field}")
    capture_started, capture_ended = min(all_started), max(all_ended)
    if capture_ended - capture_started > 15 * 60_000_000_000:
        _fail("G15_BASELINE_STALE_OR_PARTIAL", "captures exceed the 15-minute collection window")
    if phase == "frozen":
        if capture_started < registration or capture_ended > review:
            _fail("G15_BASELINE_STALE_OR_PARTIAL", "frozen capture is outside registration and review")
    elif capture_started < review or capture_ended > deadline:
        _fail("G15_BASELINE_STALE_OR_PARTIAL", "live capture is outside review and post-capture deadline")
    if len(projection_roots) != 1:
        _fail("G15_BASELINE_CAPTURE_INVALID", "the four complete history projections differ")
    count = len(scans[0]["records"])
    if _u64(baseline["baseline_count"], "G15_BASELINE_PROSPECTIVITY_INVALID") != count:
        _fail("G15_BASELINE_STALE_OR_PARTIAL", "baseline count differs from full scans")
    root_input = {key: baseline[key] for key in baseline if key != "baseline_root"}
    if baseline["baseline_root"] != canonical_sha256(root_input):
        _fail("G15_BASELINE_PROSPECTIVITY_INVALID", "baseline root mismatch")
    projection = [_record_projection(record) for record in scans[0]["records"]]
    if any(row["competition_id"] != baseline["competition_id"] or row["team_id"] != baseline["team_id"] for row in projection):
        _fail("G15_BASELINE_CAPTURE_INVALID", "history contains a record outside the frozen target")
    contract_root = canonical_sha256(
        {
            field: baseline[field]
            for field in (
                "campaign_root",
                "evaluation_id",
                "evaluation_nonce",
                "competition_id",
                "team_id",
                "registration_ns",
                "review_not_before_ns",
                "post_capture_deadline_ns",
            )
        }
    )
    identity_root = canonical_sha256(projection)
    baseline_registration_sha256 = canonical_sha256(
        {
            "contract_root": contract_root,
            "baseline_root": baseline["baseline_root"],
            "baseline_identity_root": identity_root,
            "baseline_count": count,
        }
    )
    return {
        "root": baseline["baseline_root"],
        "count": count,
        "projection": projection,
        "deadline_ns": deadline,
        "contract_root": contract_root,
        "identity_root": identity_root,
        "baseline_registration_sha256": baseline_registration_sha256,
        "capture_started_ns": capture_started,
        "capture_ended_ns": capture_ended,
        "source_authenticated": False,
    }


def validate_g15_history_baseline(value: object) -> dict[str, Any]:
    """Validate the prospective frozen baseline; live captures use a separate window."""

    return _validate_g15_history_capture(value, phase="frozen")


def validate_g15_release_evidence(value: object, *, pinned_public_key_bytes: bytes | None = None, envelope: object | None = None) -> dict[str, Any]:
    """Validate G15 bindings.  Any accepted envelope uses shared strict crypto."""

    try:
        if envelope is not None:
            if pinned_public_key_bytes is None:
                _fail("G15_ENVELOPE_INVALID", "a pinned key is required for an envelope")
            try:
                value = verify_envelope(envelope, expected_artifact_schema=G15_RELEASE_EVIDENCE_SCHEMA, pinned_public_key_bytes=pinned_public_key_bytes)
            except EnvelopeError as exc:
                _fail("G15_ENVELOPE_INVALID", str(exc))
        item = _exact(value, _RELEASE_FIELDS, "G15_INVALID_EVIDENCE")
        if item["schema_version"] != G15_RELEASE_EVIDENCE_SCHEMA:
            _fail("G15_INVALID_EVIDENCE", "release evidence schema mismatch")
        for field in ("campaign_root", "evaluation_nonce", "archive_sha256", "g13_bundle_sha256", "g14_bundle_sha256", "g14_tested_archive_sha256", "g15_input_root", "submission_nonce", "baseline_root", "baseline_registration_sha256", "baseline_identity_root", "release_intent_sha256", "authorization_id", "tls_policy_sha256"):
            _sha(item[field], "G15_INVALID_EVIDENCE")
        _marker(item["marker"], "G15_INVALID_EVIDENCE")
        for field in ("evaluation_id", "competition_id", "team_id", "endpoint_origin", "endpoint_path"):
            _identifier(item[field], "G15_INVALID_EVIDENCE")
        if item["endpoint_origin"] != "https://www.kaggle.com" or not item["endpoint_path"].startswith("/api/"):
            _fail("G15_INVALID_EVIDENCE", "release target is not the frozen Kaggle API origin/path")
        _u64(item["archive_length"], "G15_INVALID_EVIDENCE")
        if item["archive_sha256"] != item["g14_tested_archive_sha256"] or item["archive_length"] != _u64(item["g14_tested_archive_length"], "G15_ARCHIVE_BINDING_MISMATCH"):
            _fail("G15_ARCHIVE_BINDING_MISMATCH", "G15 archive is not the exact G14-tested archive")
        _u64(item["baseline_count"], "G15_INVALID_EVIDENCE")
        marker = derive_authorization_marker(campaign_root=item["campaign_root"], evaluation_id=item["evaluation_id"], evaluation_nonce=item["evaluation_nonce"], submission_nonce=item["submission_nonce"])
        if item["marker"] != marker:
            _fail("G15_AUTHORIZATION_BINDING_INVALID", "marker differs from the domain-separated binding")
        expected = derive_authorization_id(**{key: item[key] for key in ("campaign_root", "evaluation_id", "evaluation_nonce", "submission_nonce", "competition_id", "team_id", "archive_sha256", "archive_length", "g13_bundle_sha256", "g14_bundle_sha256", "g15_input_root", "release_intent_sha256", "baseline_registration_sha256", "baseline_identity_root", "baseline_count", "marker")})
        if item["authorization_id"] != expected:
            _fail("G15_AUTHORIZATION_BINDING_INVALID", "authorization ID differs or circular G15 hash was used")
        return _receipt(G15_GATE_ID, None, authorization_id=item["authorization_id"], archive_sha256=item["archive_sha256"], g13_bundle_sha256=item["g13_bundle_sha256"], g14_bundle_sha256=item["g14_bundle_sha256"])
    except ProductionReleaseError as exc:
        return _receipt(G15_GATE_ID, exc.code)


def validate_g15_request_descriptor(
    value: object,
    *,
    release_evidence: Mapping[str, Any],
    archive_bytes: bytes,
    multipart_body: bytes,
) -> dict[str, Any]:
    """Validate the complete request descriptor before a capability may consume."""

    item = _exact(value, _DESCRIPTOR_FIELDS, "G15_DESCRIPTOR_INVALID")
    if item["schema_version"] != G15_DESCRIPTOR_SCHEMA:
        _fail("G15_DESCRIPTOR_INVALID", "descriptor schema mismatch")
    for field in ("campaign_root", "evaluation_nonce", "authorization_id", "archive_sha256", "g13_bundle_sha256", "g14_bundle_sha256", "g15_input_root", "baseline_root", "baseline_registration_sha256", "baseline_identity_root", "request_descriptor_sha256", "multipart_body_sha256", "tls_policy_sha256", "executor_digest", "runtime_digest"):
        _sha(item[field], "G15_DESCRIPTOR_INVALID")
    _marker(item["marker"], "G15_DESCRIPTOR_INVALID")
    for field in ("evaluation_id", "competition_id", "team_id", "endpoint_origin", "endpoint_path"):
        _identifier(item[field], "G15_DESCRIPTOR_INVALID")
    for field in ("archive_length", "baseline_count"):
        _u64(item[field], "G15_DESCRIPTOR_INVALID")
    if item["method"] != "POST" or item["redirect_policy"] != "error" or item["automatic_retry"] is not False:
        _fail("G15_REDIRECT_OR_RETRY_FORBIDDEN", "only a single POST with redirects and retries disabled is permitted")
    if item["request_body_media_type"] != "multipart/form-data":
        _fail("G15_DESCRIPTOR_INVALID", "request body media type is not frozen")
    for field in ("campaign_root", "evaluation_id", "evaluation_nonce", "authorization_id", "competition_id", "team_id", "archive_sha256", "archive_length", "g13_bundle_sha256", "g14_bundle_sha256", "g15_input_root", "baseline_root", "baseline_registration_sha256", "baseline_identity_root", "baseline_count", "marker", "endpoint_origin", "endpoint_path", "tls_policy_sha256"):
        if item[field] != release_evidence[field]:
            _fail("G15_DESCRIPTOR_INVALID", f"descriptor {field} differs from release evidence")
    if type(archive_bytes) is not bytes or type(multipart_body) is not bytes:
        _fail("G15_DESCRIPTOR_INVALID", "request and archive must be exact raw bytes")
    if len(archive_bytes) != item["archive_length"] or hashlib.sha256(archive_bytes).hexdigest() != item["archive_sha256"]:
        _fail("G15_DESCRIPTOR_INVALID", "archive bytes differ from the selected archive")
    if hashlib.sha256(multipart_body).hexdigest() != item["multipart_body_sha256"] or multipart_body.count(archive_bytes) != 1:
        _fail("G15_DESCRIPTOR_INVALID", "multipart bytes do not bind the selected archive exactly once")
    expected_descriptor_sha256 = canonical_sha256(
        {key: item[key] for key in item if key != "request_descriptor_sha256"}
    )
    if item["request_descriptor_sha256"] != expected_descriptor_sha256:
        _fail("G15_DESCRIPTOR_INVALID", "request descriptor hash mismatch")
    return item


@dataclass(frozen=True)
class CampaignKey:
    campaign_root: str
    evaluation_id: str
    evaluation_nonce: str


class SyntheticReleaseStateMachine:
    """Synthetic conformance model; it is never a trusted capability service."""

    def __init__(self, path: str) -> None:
        self._connection = sqlite3.connect(path, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("CREATE TABLE IF NOT EXISTS production_release_state (campaign_root TEXT NOT NULL, evaluation_id TEXT NOT NULL, evaluation_nonce TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, authorization_id TEXT, payload_sha256 TEXT NOT NULL, registered_release_sha256 TEXT, capture_end_ns INTEGER, PRIMARY KEY (campaign_root, evaluation_id, evaluation_nonce, kind))")
        columns = {row[1] for row in self._connection.execute("PRAGMA table_info(production_release_state)")}
        if "capture_end_ns" not in columns:
            self._connection.execute("ALTER TABLE production_release_state ADD COLUMN capture_end_ns INTEGER")
        if "registered_release_sha256" not in columns:
            self._connection.execute("ALTER TABLE production_release_state ADD COLUMN registered_release_sha256 TEXT")

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _key(evidence: Mapping[str, Any]) -> CampaignKey:
        return CampaignKey(evidence["campaign_root"], evidence["evaluation_id"], evidence["evaluation_nonce"])

    def _transition(self, *, key: CampaignKey, kind: str, expected: Sequence[str], target: str, authorization_id: str | None, payload: object, registered_release_sha256: str | None = None, capture_end_ns: int | None = None) -> str:
        digest = canonical_sha256(payload)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute("SELECT state, authorization_id FROM production_release_state WHERE campaign_root=? AND evaluation_id=? AND evaluation_nonce=? AND kind=?", (key.campaign_root, key.evaluation_id, key.evaluation_nonce, kind)).fetchone()
            if row is None:
                if UNREGISTERED not in expected:
                    _fail("G14_HOLDOUT_TRANSITION_INVALID" if kind == "g14" else "G15_INVALID_STATE_TRANSITION")
                self._connection.execute("INSERT INTO production_release_state VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (key.campaign_root, key.evaluation_id, key.evaluation_nonce, kind, target, authorization_id, digest, registered_release_sha256, capture_end_ns))
            else:
                state, old_authorization = row
                if kind == "g15" and old_authorization is not None and authorization_id is not None and old_authorization != authorization_id:
                    self._connection.execute("UPDATE production_release_state SET state=?, payload_sha256=? WHERE campaign_root=? AND evaluation_id=? AND evaluation_nonce=? AND kind=?", (CONFLICTED, digest, key.campaign_root, key.evaluation_id, key.evaluation_nonce, kind))
                    # A conflicting authorization is terminal even though the
                    # caller receives an error.  Commit it before raising so a
                    # process restart cannot turn conflict into a fresh slot.
                    self._connection.execute("COMMIT")
                    raise ProductionReleaseError("G15_SECOND_AUTHORIZATION_CONFLICT")
                if state not in expected:
                    _fail("G14_HOLDOUT_ALREADY_CONSUMED" if kind == "g14" else "G15_INVALID_STATE_TRANSITION")
                self._connection.execute("UPDATE production_release_state SET state=?, payload_sha256=?, registered_release_sha256=COALESCE(?, registered_release_sha256), capture_end_ns=COALESCE(?, capture_end_ns) WHERE campaign_root=? AND evaluation_id=? AND evaluation_nonce=? AND kind=?", (target, digest, registered_release_sha256, capture_end_ns, key.campaign_root, key.evaluation_id, key.evaluation_nonce, kind))
            self._connection.execute("COMMIT")
            return target
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def begin_g14_holdout_audit(self, evidence: Mapping[str, Any]) -> str:
        # Validation accepts only ciphertext/commitment hashes and counters.
        result = validate_g14_opaque_holdout_audit(evidence)
        if result["structural_validation_complete"] is not True:
            _fail(result["failure_codes"][0])
        return self._transition(key=self._key(evidence), kind="g14", expected=(UNREGISTERED,), target=HOLDOUT_CONSUMED_RUNNING, authorization_id=None, payload=evidence)

    def finish_g14_holdout_audit(self, evidence: Mapping[str, Any], *, completed: bool) -> str:
        return self._transition(key=self._key(evidence), kind="g14", expected=(HOLDOUT_CONSUMED_RUNNING,), target=HOLDOUT_CONSUMED_COMPLETE if completed else HOLDOUT_CONSUMED_FAILED, authorization_id=None, payload=evidence)

    def register_authorization(self, evidence: Mapping[str, Any]) -> str:
        result = validate_g15_release_evidence(evidence)
        if result["structural_validation_complete"] is not True:
            _fail(result["failure_codes"][0])
        return self._transition(key=self._key(evidence), kind="g15", expected=(UNREGISTERED,), target=AUTHORIZED_UNUSED, authorization_id=evidence["authorization_id"], payload=evidence, registered_release_sha256=canonical_sha256(evidence))

    @staticmethod
    def _release_only(evidence: Mapping[str, Any]) -> dict[str, Any]:
        try:
            return {field: evidence[field] for field in _RELEASE_FIELDS}
        except KeyError as exc:
            _fail("G15_AUTHORIZATION_BINDING_INVALID", f"release field is missing: {exc}")
            raise AssertionError from exc

    def _assert_registered_release(self, evidence: Mapping[str, Any]) -> None:
        release = self._release_only(evidence)
        result = validate_g15_release_evidence(release)
        if result["structural_validation_complete"] is not True:
            _fail(result["failure_codes"][0])
        key = self._key(release)
        row = self._connection.execute(
            "SELECT authorization_id, registered_release_sha256 FROM production_release_state WHERE campaign_root=? AND evaluation_id=? AND evaluation_nonce=? AND kind='g15'",
            (key.campaign_root, key.evaluation_id, key.evaluation_nonce),
        ).fetchone()
        if row is None or row[0] != release["authorization_id"] or row[1] != canonical_sha256(release):
            _fail("G15_AUTHORIZATION_BINDING_INVALID", "release evidence differs from the registered bytes")

    def lock_preflight(self, evidence: Mapping[str, Any], *, current_baseline: object) -> str:
        self._assert_registered_release(evidence)
        frozen = validate_g15_history_baseline(evidence["baseline"])
        if (
            frozen["root"] != evidence["baseline_root"]
            or frozen["baseline_registration_sha256"] != evidence["baseline_registration_sha256"]
            or frozen["identity_root"] != evidence["baseline_identity_root"]
            or frozen["count"] != evidence["baseline_count"]
        ):
            _fail("G15_AUTHORIZATION_BINDING_INVALID", "preflight baseline differs from frozen G15 evidence")
        current = _validate_g15_history_capture(current_baseline, phase="live")
        if frozen["contract_root"] != current["contract_root"] or frozen["projection"] != current["projection"]:
            self._transition(key=self._key(evidence), kind="g15", expected=(AUTHORIZED_UNUSED,), target=CONFLICTED, authorization_id=evidence["authorization_id"], payload=current_baseline)
            _fail("G15_CONCURRENT_SUBMISSION_CONFLICT")
        return self._transition(key=self._key(evidence), kind="g15", expected=(AUTHORIZED_UNUSED,), target=PREFLIGHT_LOCKED, authorization_id=evidence["authorization_id"], payload=current_baseline, capture_end_ns=current["capture_ended_ns"])

    def consume_before_network(self, evidence: Mapping[str, Any], descriptor: object, *, archive_bytes: bytes, multipart_body: bytes) -> str:
        self._assert_registered_release(evidence)
        # This validation intentionally occurs before the atomic consumed state.
        validate_g15_request_descriptor(
            descriptor,
            release_evidence=evidence,
            archive_bytes=archive_bytes,
            multipart_body=multipart_body,
        )
        return self._transition(key=self._key(evidence), kind="g15", expected=(PREFLIGHT_LOCKED,), target=CONSUMED_PENDING, authorization_id=evidence["authorization_id"], payload=descriptor)

    def record_request_outcome(self, evidence: Mapping[str, Any], *, outcome: str) -> str:
        self._assert_registered_release(evidence)
        mapping = {"sent": REQUEST_SENT, "pretransmission_failure": CONSUMED_UNSENT, "timeout": AMBIGUOUS, "connection_lost": AMBIGUOUS, "crash": AMBIGUOUS, "rejected": REJECTED}
        if outcome not in mapping:
            _fail("G15_EXECUTION_AMBIGUOUS")
        return self._transition(key=self._key(evidence), kind="g15", expected=(CONSUMED_PENDING,), target=mapping[outcome], authorization_id=evidence["authorization_id"], payload={"outcome": outcome})

    def confirm_post_capture(self, evidence: Mapping[str, Any], *, post_baseline: object, response_submission_id: str | None, timed_out: bool = False) -> str:
        self._assert_registered_release(evidence)
        if timed_out:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=AMBIGUOUS, authorization_id=evidence["authorization_id"], payload={"timeout": True})
        before = validate_g15_history_baseline(evidence["baseline"])
        if (
            before["root"] != evidence["baseline_root"]
            or before["baseline_registration_sha256"] != evidence["baseline_registration_sha256"]
            or before["identity_root"] != evidence["baseline_identity_root"]
            or before["count"] != evidence["baseline_count"]
        ):
            _fail("G15_AUTHORIZATION_BINDING_INVALID", "post-capture baseline differs from frozen G15 evidence")
        try:
            after = _validate_g15_history_capture(post_baseline, phase="live")
        except ProductionReleaseError:
            # A malformed, incomplete, or disagreeing post-capture cannot prove
            # absence.  The consumed request is therefore terminally unknown.
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=AMBIGUOUS, authorization_id=evidence["authorization_id"], payload={"post_capture": "invalid"})
        row = self._connection.execute(
            "SELECT capture_end_ns FROM production_release_state WHERE campaign_root=? AND evaluation_id=? AND evaluation_nonce=? AND kind='g15'",
            (evidence["campaign_root"], evidence["evaluation_id"], evidence["evaluation_nonce"]),
        ).fetchone()
        preflight_ended = None if row is None else row[0]
        if after["contract_root"] != before["contract_root"] or preflight_ended is None or after["capture_started_ns"] <= preflight_ended or after["capture_ended_ns"] > before["deadline_ns"]:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=AMBIGUOUS, authorization_id=evidence["authorization_id"], payload={"post_capture": "deadline"})
        added = [row for row in after["projection"] if row not in before["projection"]]
        removed = [row for row in before["projection"] if row not in after["projection"]]
        if not removed and not added:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=AMBIGUOUS, authorization_id=evidence["authorization_id"], payload=after)
        if removed or len(added) != 1:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=CONFLICTED, authorization_id=evidence["authorization_id"], payload=after)
        row = added[0]
        if row["competition_id"] != evidence["competition_id"] or row["team_id"] != evidence["team_id"] or row["submission_description"] != evidence["marker"]:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=CONFLICTED, authorization_id=evidence["authorization_id"], payload=after)
        if response_submission_id is None or row["submission_id"] != response_submission_id:
            return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=CONFLICTED, authorization_id=evidence["authorization_id"], payload=after)
        return self._transition(key=self._key(evidence), kind="g15", expected=(REQUEST_SENT,), target=CONFIRMED, authorization_id=evidence["authorization_id"], payload=after)


class ResearchOnlyReleaseLedger(SyntheticReleaseStateMachine):
    """Production-shaped facade that cannot mutate without installed trust services."""

    @staticmethod
    def _unavailable(gate_id: str) -> None:
        _fail(
            "G14_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"
            if gate_id == G14_GATE_ID
            else "G15_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"
        )

    def begin_g14_holdout_audit(self, evidence: Mapping[str, Any]) -> str:
        del evidence
        self._unavailable(G14_GATE_ID)
        raise AssertionError

    def finish_g14_holdout_audit(self, evidence: Mapping[str, Any], *, completed: bool) -> str:
        del evidence, completed
        self._unavailable(G14_GATE_ID)
        raise AssertionError

    def register_authorization(self, evidence: Mapping[str, Any]) -> str:
        del evidence
        self._unavailable(G15_GATE_ID)
        raise AssertionError

    def lock_preflight(self, evidence: Mapping[str, Any], *, current_baseline: object) -> str:
        del evidence, current_baseline
        self._unavailable(G15_GATE_ID)
        raise AssertionError

    def consume_before_network(self, evidence: Mapping[str, Any], descriptor: object, *, archive_bytes: bytes, multipart_body: bytes) -> str:
        del evidence, descriptor, archive_bytes, multipart_body
        self._unavailable(G15_GATE_ID)
        raise AssertionError

    def record_request_outcome(self, evidence: Mapping[str, Any], *, outcome: str) -> str:
        del evidence, outcome
        self._unavailable(G15_GATE_ID)
        raise AssertionError

    def confirm_post_capture(self, evidence: Mapping[str, Any], *, post_baseline: object, response_submission_id: str | None, timed_out: bool = False) -> str:
        del evidence, post_baseline, response_submission_id, timed_out
        self._unavailable(G15_GATE_ID)
        raise AssertionError


def verify_production_release_exact_v2(*, gate_id: str, final_bundle: object) -> dict[str, Any]:
    """Parse through exact-v2, then remain hard-closed pending authentic integration."""

    if gate_id not in {G14_GATE_ID, G15_GATE_ID}:
        raise ProductionReleaseError("G15_INVALID_EVIDENCE", "wrapper only applies to G14/G15")
    result = verify_exact_gate_v2(gate_id=gate_id, final_bundle=final_bundle)
    return {
        "protocol_id": PROTOCOL_ID,
        "gate_id": gate_id,
        "decision": REJECTED_DECISION,
        "bundle_sha256": result.get("bundle_sha256"),
        "failure_codes": [G14_G15_EXACT_V2_FAILURE],
        "detail": "production G14/G15 dependencies and allowlisting are unavailable",
        **_authority_flags(),
    }


__all__ = [
    "AMBIGUOUS", "AUTHORIZED_UNUSED", "CampaignKey", "CONFIRMED", "CONFLICTED",
    "CONSUMED_PENDING", "CONSUMED_UNSENT", "G14_AUDIT_SCHEMA", "G14_FAILURE_CODES",
    "G14_GATE_ID", "G15_BASELINE_SCHEMA", "G15_DESCRIPTOR_SCHEMA", "G15_FAILURE_CODES",
    "G15_GATE_ID", "G15_RELEASE_EVIDENCE_SCHEMA", "G15_SCAN_SCHEMA", "HOLDOUT_CONSUMED_COMPLETE",
    "HOLDOUT_CONSUMED_FAILED", "HOLDOUT_CONSUMED_RUNNING", "HOLDOUT_SEALED", "MARKER_DOMAIN", "MARKER_PREFIX",
    "PREFLIGHT_LOCKED", "ProductionReleaseError", "REJECTED", "REQUEST_SENT",
    "ResearchOnlyReleaseLedger", "SyntheticReleaseStateMachine", "TRUSTED_VALID_ONLY_SERVICE_KEYS", "derive_authorization_id",
    "derive_authorization_marker", "validate_g14_opaque_holdout_audit", "validate_g15_history_baseline",
    "validate_g15_release_evidence", "validate_g15_request_descriptor", "verify_production_release_exact_v2",
]
