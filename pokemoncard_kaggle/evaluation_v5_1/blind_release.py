"""Verify the capability boundary around one blind v5.1 validation run.

There is intentionally no decryption, fitting, transfer-analysis, candidate,
holdout, or submission function in this module. It verifies only signed,
hash-bound release and publication receipts. Real non-collocation, key custody,
and monotonic hardware state remain external facts.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
import re
from typing import Any

from .canonical import canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from .statistics import exact_binomial_upper_tail_numerator


RELEASE_REQUEST_SCHEMA = "evaluation_v5_1_release_request_v2"
RELEASE_APPROVAL_SCHEMA = "evaluation_v5_1_release_approval_v2"
ANALYSIS_RESULT_SCHEMA = "evaluation_v5_1_validation_receipt_v2"
PUBLICATION_RECEIPT_SCHEMA = "evaluation_v5_1_publication_receipt_v2"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{12}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_REQUEST_FIELDS = frozenset(
    {
        "protocol_id",
        "campaign_root_sha256",
        "claim_manifest_root_sha256",
        "dev_fit_root_sha256",
        "frame_root_sha256",
        "selection_root_sha256",
        "prediction_ciphertext_sha256",
        "outcome_ciphertext_sha256",
        "census_root_sha256",
        "validator_image_sha256",
        "validator_source_sha256",
        "output_schema_sha256",
        "single_use_nonce_sha256",
        "not_before_utc",
        "expected_run_counter",
    }
)
_APPROVAL_FIELDS = frozenset(
    {"protocol_id", "release_request_sha256", "approver_id", "decision"}
)
_RESULT_FIELDS = frozenset(
    {
        "protocol_id",
        "release_request_sha256",
        "single_use_nonce_sha256",
        "validator_image_sha256",
        "validation_receipt_sha256",
        "run_counter_before",
        "run_counter_after",
        "network_disabled",
        "interactive_access",
        "debug_surface_present",
        "dev_fit_code_present",
        "candidate_code_present",
        "family_count",
        "family_success_count",
        "exact_p_value",
        "mean_logloss_lift",
        "activation_block_means",
        "catastrophic_family_count",
        "unresolved_rows",
        "primary_claim_pass",
        "all_conjunctive_gates_pass",
        "status",
        "executed_at_utc",
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "submission_authorized",
    }
)
_PUBLICATION_FIELDS = frozenset(
    {
        "protocol_id",
        "release_request_sha256",
        "validation_receipt_sha256",
        "registry_entry_sha256",
        "published",
    }
)


class BlindReleaseError(ValueError):
    """A release, execution, or publication receipt is malformed or unbound."""


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise BlindReleaseError(f"{label} must be lowercase SHA-256 hex")
    return value


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise BlindReleaseError(f"{label} fields are not exact")
    return value


def _timestamp(value: object, label: str) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise BlindReleaseError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise BlindReleaseError(f"{label} must be a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise BlindReleaseError(f"{label} must be canonical UTC")
    return value


def _decimal12(value: object, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise BlindReleaseError(f"{label} must be a canonical 12-decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise BlindReleaseError(f"{label} is not a finite decimal") from exc
    if not parsed.is_finite() or format(parsed, ".12f") != value:
        raise BlindReleaseError(f"{label} must be a canonical finite decimal")
    return parsed


def verify_release_request(
    envelope: object,
    *,
    pinned_registry_key: bytes,
    expected_protocol_id: str,
    expected_bindings: Mapping[str, str],
) -> dict[str, Any]:
    try:
        payload = verify_envelope(
            envelope,
            expected_artifact_schema=RELEASE_REQUEST_SCHEMA,
            pinned_public_key_bytes=pinned_registry_key,
        )
    except EnvelopeError as exc:
        raise BlindReleaseError(f"release request envelope failed: {exc}") from exc
    request = _exact(payload, _REQUEST_FIELDS, "release request")
    if request["protocol_id"] != expected_protocol_id:
        raise BlindReleaseError("release request protocol mismatch")
    hash_fields = _REQUEST_FIELDS - {
        "protocol_id",
        "not_before_utc",
        "expected_run_counter",
    }
    for field in hash_fields:
        actual = _sha256(request[field], field)
        if field in expected_bindings and actual != expected_bindings[field]:
            raise BlindReleaseError(f"release request {field} mismatch")
    if set(expected_bindings) != hash_fields:
        raise BlindReleaseError("expected bindings must contain every hash-bound request field exactly")
    _timestamp(request["not_before_utc"], "not_before_utc")
    if request["expected_run_counter"] != 0:
        raise BlindReleaseError("release request must bind run counter zero")
    return request


def verify_release_quorum(
    request: Mapping[str, Any],
    approval_envelopes: Sequence[object],
    *,
    pinned_quorum_keys: Mapping[str, bytes],
    expected_protocol_id: str,
) -> dict[str, Any]:
    if set(pinned_quorum_keys) != {"quorum_1", "quorum_2", "quorum_3"}:
        raise BlindReleaseError("exactly three implementation-pinned quorum keys are required")
    keys = list(pinned_quorum_keys.values())
    if any(type(key) is not bytes or len(key) != 32 for key in keys) or len(set(keys)) != 3:
        raise BlindReleaseError("quorum public keys must be three distinct 32-byte keys")
    request_value = _exact(dict(request), _REQUEST_FIELDS, "release request")
    request_hash = canonical_sha256(request_value)
    if type(approval_envelopes) not in {list, tuple}:
        raise BlindReleaseError("approval envelopes must be an ordered sequence")
    approvers: set[str] = set()
    for envelope in approval_envelopes:
        matches: list[tuple[str, dict[str, Any]]] = []
        for approver_id, public_key in pinned_quorum_keys.items():
            try:
                payload = verify_envelope(
                    envelope,
                    expected_artifact_schema=RELEASE_APPROVAL_SCHEMA,
                    pinned_public_key_bytes=public_key,
                )
            except EnvelopeError:
                continue
            matches.append((approver_id, payload))
        if len(matches) != 1:
            raise BlindReleaseError("approval must match exactly one pinned quorum key")
        approver_id, payload = matches[0]
        approval = _exact(payload, _APPROVAL_FIELDS, "release approval")
        if approval["protocol_id"] != expected_protocol_id:
            raise BlindReleaseError("release approval protocol mismatch")
        if approval["approver_id"] != approver_id:
            raise BlindReleaseError("approval identity does not match its signing key")
        if approval["release_request_sha256"] != request_hash:
            raise BlindReleaseError("approval does not bind the exact release request")
        if approval["decision"] != "APPROVE_RESEARCH_ANALYSIS_ONCE":
            raise BlindReleaseError("approval decision is not one-shot")
        if approver_id in approvers:
            raise BlindReleaseError("duplicate quorum approval")
        approvers.add(approver_id)
    if len(approvers) < 2:
        raise BlindReleaseError("at least two distinct quorum approvals are required")
    return {
        "schema": "evaluation_v5_1_release_quorum_audit_v2",
        "protocol_id": expected_protocol_id,
        "release_request_sha256": request_hash,
        "approved_by": sorted(approvers),
        "analysis_capability_verified": True,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "external_non_collocation_required": True,
    }


def _verify_result_contract(result: dict[str, Any], request: Mapping[str, Any]) -> None:
    for field in (
        "candidate_development_authorized",
        "sealed_holdout_access_authorized",
        "submission_authorized",
    ):
        if result[field] is not False:
            raise BlindReleaseError(f"analysis result illegally sets {field}")
    if result["run_counter_before"] != 0 or result["run_counter_after"] != 1:
        raise BlindReleaseError("validator monotonic run counter must transition 0 to 1")
    if request["expected_run_counter"] != result["run_counter_before"]:
        raise BlindReleaseError("validator run counter does not match the request")
    if result["network_disabled"] is not True:
        raise BlindReleaseError("validator network must be disabled")
    for field in (
        "interactive_access",
        "debug_surface_present",
        "dev_fit_code_present",
        "candidate_code_present",
    ):
        if result[field] is not False:
            raise BlindReleaseError(f"validator capability boundary failed: {field}")
    if type(result["family_count"]) is not int or type(result["family_success_count"]) is not int:
        raise BlindReleaseError("family counts must be integers")
    if not 0 <= result["family_success_count"] <= result["family_count"]:
        raise BlindReleaseError("family success count is invalid")
    if type(result["catastrophic_family_count"]) is not int or result["catastrophic_family_count"] < 0:
        raise BlindReleaseError("catastrophic family count is invalid")
    if type(result["unresolved_rows"]) is not int or result["unresolved_rows"] < 0:
        raise BlindReleaseError("unresolved row count is invalid")
    p_value = _decimal12(result["exact_p_value"], "exact_p_value")
    mean_lift = _decimal12(result["mean_logloss_lift"], "mean_logloss_lift")
    blocks = result["activation_block_means"]
    if type(blocks) is not list or len(blocks) != 4:
        raise BlindReleaseError("activation_block_means must contain exactly four values")
    block_values = [_decimal12(value, "activation block mean") for value in blocks]
    with localcontext() as context:
        context.prec = 50
        expected_p_value = Decimal(
            exact_binomial_upper_tail_numerator(
                result["family_count"], result["family_success_count"]
            )
        ) / Decimal(1 << result["family_count"])
    if result["exact_p_value"] != format(expected_p_value, ".12f"):
        raise BlindReleaseError("exact_p_value does not equal the frozen exact binomial tail")
    for field in ("primary_claim_pass", "all_conjunctive_gates_pass"):
        if type(result[field]) is not bool:
            raise BlindReleaseError(f"{field} must be boolean")

    computed_primary = (
        result["family_count"] == 20
        and result["family_success_count"] >= 15
        and p_value <= Decimal("0.025000000000")
    )
    computed_conjunctive = (
        mean_lift >= Decimal("0.010000000000")
        and all(value >= 0 for value in block_values)
        and result["catastrophic_family_count"] <= 1
        and result["unresolved_rows"] == 0
    )
    if result["primary_claim_pass"] is not computed_primary:
        raise BlindReleaseError("primary claim flag is inconsistent with frozen criteria")
    if result["all_conjunctive_gates_pass"] is not computed_conjunctive:
        raise BlindReleaseError("conjunctive flag is inconsistent with frozen criteria")
    expected_status = "PASS_RESEARCH_ONLY" if computed_primary and computed_conjunctive else "FAIL_RESEARCH_ONLY"
    if result["status"] != expected_status:
        raise BlindReleaseError("analysis status is inconsistent with frozen criteria")
    executed = datetime.strptime(
        _timestamp(result["executed_at_utc"], "executed_at_utc"),
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    not_before = datetime.strptime(
        _timestamp(request["not_before_utc"], "not_before_utc"),
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    if executed < not_before:
        raise BlindReleaseError("analysis executed before the frozen not-before time")


def verify_published_analysis_result(
    result_envelope: object,
    publication_envelope: object,
    *,
    pinned_analyzer_key: bytes,
    pinned_registry_key: bytes,
    expected_protocol_id: str,
    release_request: Mapping[str, Any],
    expected_analysis_container_sha256: str,
) -> dict[str, Any]:
    try:
        result_payload = verify_envelope(
            result_envelope,
            expected_artifact_schema=ANALYSIS_RESULT_SCHEMA,
            pinned_public_key_bytes=pinned_analyzer_key,
        )
        publication_payload = verify_envelope(
            publication_envelope,
            expected_artifact_schema=PUBLICATION_RECEIPT_SCHEMA,
            pinned_public_key_bytes=pinned_registry_key,
        )
    except EnvelopeError as exc:
        raise BlindReleaseError(f"analysis publication envelope failed: {exc}") from exc
    result = _exact(result_payload, _RESULT_FIELDS, "analysis result")
    publication = _exact(publication_payload, _PUBLICATION_FIELDS, "publication receipt")
    request = _exact(dict(release_request), _REQUEST_FIELDS, "release request")
    request_hash = canonical_sha256(request)
    if result["protocol_id"] != expected_protocol_id:
        raise BlindReleaseError("analysis result protocol mismatch")
    if result["release_request_sha256"] != request_hash:
        raise BlindReleaseError("analysis result does not bind the release request")
    if result["single_use_nonce_sha256"] != request["single_use_nonce_sha256"]:
        raise BlindReleaseError("analysis result does not consume the frozen nonce")
    expected_image = _sha256(expected_analysis_container_sha256, "expected validator image")
    if result["validator_image_sha256"] != expected_image or expected_image != request["validator_image_sha256"]:
        raise BlindReleaseError("validator image hash mismatch")
    receipt_hash = _sha256(result["validation_receipt_sha256"], "validation_receipt_sha256")
    result_core = {key: value for key, value in result.items() if key != "validation_receipt_sha256"}
    if receipt_hash != canonical_sha256(result_core):
        raise BlindReleaseError("validation receipt hash does not bind the exact analysis result")
    _verify_result_contract(result, request)

    if publication["protocol_id"] != expected_protocol_id:
        raise BlindReleaseError("publication protocol mismatch")
    if publication["release_request_sha256"] != request_hash:
        raise BlindReleaseError("publication does not bind the release request")
    if publication["validation_receipt_sha256"] != receipt_hash:
        raise BlindReleaseError("publication does not bind the validation receipt")
    _sha256(publication["registry_entry_sha256"], "registry_entry_sha256")
    if publication["published"] is not True:
        raise BlindReleaseError("analysis result was not published")
    return {
        "schema": "evaluation_v5_1_published_validation_audit_v2",
        "protocol_id": expected_protocol_id,
        "release_request_sha256": request_hash,
        "validation_receipt_sha256": receipt_hash,
        "status": result["status"],
        "evaluator_validated_research_only": result["status"] == "PASS_RESEARCH_ONLY",
        "published": True,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "external_non_collocation_required": True,
    }


__all__ = [
    "ANALYSIS_RESULT_SCHEMA",
    "BlindReleaseError",
    "PUBLICATION_RECEIPT_SCHEMA",
    "RELEASE_APPROVAL_SCHEMA",
    "RELEASE_REQUEST_SCHEMA",
    "verify_published_analysis_result",
    "verify_release_quorum",
    "verify_release_request",
]
