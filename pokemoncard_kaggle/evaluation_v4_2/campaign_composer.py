"""Exact-set, local-only composition for v4.2 sandbox campaigns.

This module is intentionally the only campaign-level composition surface.  It
reopens the authenticated campaign journal and its content-addressed evidence,
then (only for a complete successful campaign) reopens every planned v4 arm
through the stable ``compose_witnessed_arm`` packet.  It never accepts caller
receipts, subsets, paths, callbacks, or an alternate plan.

The resulting panel is a root-local diagnostic artifact.  It is not a
scientific result, public-transfer result, external attestation, holdout
release, anchor, or submission authorization.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
from typing import Any

from .campaign_journal import (
    BURN,
    NEVER_STARTED,
    POPEN_OBSERVED,
    SUCCESS,
    VETO,
    CampaignJournal,
)
from .campaign_preparation import (
    CampaignPreparationError,
    validate_campaign_prepared_manifest,
)
from .campaign_protocol import validate_campaign_plan
from .parent_arm_claim import (
    ParentArmClaimError,
    build_parent_bound_child_claim,
    child_attempt_id,
    parent_bound_child_claim_sha256,
    validate_parent_bound_child_claim,
)
from .sandbox_binding import FALSE_AUTHORITY_FLAGS
from .witness_journal import canonical_json_bytes, canonical_sha256
from tools.run_evaluation_v4_2_sandbox_arm import (
    WITNESSED_ARM_SCHEMA as V4_WITNESSED_ARM_SCHEMA,
    compose_witnessed_arm,
)


ARM_TERMINAL_EVIDENCE_SCHEMA = "evaluation_v4_2_campaign_arm_terminal_evidence_v2"
CAMPAIGN_TERMINAL_MANIFEST_SCHEMA = "evaluation_v4_2_campaign_terminal_manifest_v2"
PRELAUNCH_VETO_MANIFEST_SCHEMA = "evaluation_v4_2_prelaunch_veto_manifest_v1"
WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA = (
    "evaluation_v4_2_witnessed_complete_campaign_panel_v1"
)
CAMPAIGN_VETO_SCHEMA = "evaluation_v4_2_campaign_veto_v1"

ROOT_LOCAL_COMPLETE_SET_DIAGNOSTIC_ONLY = "ROOT_LOCAL_COMPLETE_SET_DIAGNOSTIC_ONLY"
NO_OUTCOME_USE = "NO_OUTCOME_USE"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
LOCAL_WITNESS_AUTHORITY = "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")

# These close campaign-level authority independently of the narrower flags
# carried by CampaignJournal and the per-arm sandbox witness.
_CLOSED_AUTHORITY_FLAGS = {
    "external_authority": False,
    "remote_attestation_verified": False,
    "native_platform_verified": False,
    "latency_parity_allowed": False,
    "latency_metrics_admissible": False,
    "randomization_allowed": False,
    "global_one_shot_verified": False,
    "dedicated_principal_verified": False,
    "external_witness_verified": False,
    "referee_rules_correctness_verified": False,
    "scientific_authority": False,
    "scientific_selector_admissible": False,
    "scientific_outcome_use_authorized": False,
    "public_transfer_outcome_use_authorized": False,
    "outcome_usable": False,
    "outcome_use_authorized": False,
    "holdout_access_authorized": False,
    "holdout_accessed": False,
    "anchor_allowed": False,
    "candidate_level_authority": False,
    "panel_authority": False,
    "submission_authorized": False,
    "submit_authorized": False,
    "production_submission_authorized": False,
}

_ARM_TERMINAL_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "allocation_id",
        "logical_attempt_id",
        "terminal_status",
        "launch_state",
        "sandbox_arm_claim_sha256",
        "child_attempt_id",
        "parent_bound_child_claim_sha256",
        "child_claim_event_sha256",
        "child_start_event_sha256",
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "immutable_terminal_event_sha256",
        "arm_terminal_evidence_sha256",
        "witnessed_arm_content_sha256",
        "status",
        "host_outcome",
        "authority",
        "root_local_campaign_one_shot",
        *_CLOSED_AUTHORITY_FLAGS,
    }
)
_ARM_TERMINAL_FIELDS = _ARM_TERMINAL_CONTENT_FIELDS | {"content_sha256"}

_DISPOSITION_FIELDS = frozenset(
    {"allocation_id", "terminal_status", "launch_state", "terminal_evidence_sha256"}
)
_TERMINAL_MANIFEST_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "plan_evidence_sha256",
        "terminal_status",
        "allocation_dispositions",
        "disposition_count",
        "authority",
        "root_local_campaign_one_shot",
        *_CLOSED_AUTHORITY_FLAGS,
    }
)
_TERMINAL_MANIFEST_FIELDS = _TERMINAL_MANIFEST_CONTENT_FIELDS | {"content_sha256"}

_PRELAUNCH_VETO_MANIFEST_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "plan_evidence_sha256",
        "terminal_status",
        "allocation_ids",
        "disposition_count",
        "allocation_terminal_status",
        "allocation_launch_state",
        "authority",
        "root_local_campaign_one_shot",
        *_CLOSED_AUTHORITY_FLAGS,
    }
)
_PRELAUNCH_VETO_MANIFEST_FIELDS = _PRELAUNCH_VETO_MANIFEST_CONTENT_FIELDS | {
    "content_sha256"
}

_PANEL_ROW_FIELDS = frozenset(
    {
        "engine_id",
        "opponent_id",
        "seed",
        "seat",
        "candidate_allocation_id",
        "baseline_allocation_id",
        "candidate_terminal_evidence_sha256",
        "baseline_terminal_evidence_sha256",
        "candidate_witnessed_arm_content_sha256",
        "baseline_witnessed_arm_content_sha256",
        "candidate_outcome",
        "baseline_outcome",
    }
)
_PANEL_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "campaign_terminal_evidence_sha256",
        "campaign_terminal_manifest_content_sha256",
        "paired_cell_count",
        "rows",
        "row_set_sha256",
        "local_complete_set_outcomes_usable",
        "outcome_use_scope",
        "authority",
        "root_local_campaign_one_shot",
        *_CLOSED_AUTHORITY_FLAGS,
    }
)
_PANEL_FIELDS = _PANEL_CONTENT_FIELDS | {"content_sha256"}

_VETO_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "campaign_terminal_evidence_sha256",
        "campaign_terminal_manifest_content_sha256",
        "terminal_status",
        "outcomes_omitted",
        "local_complete_set_outcomes_usable",
        "outcome_use_scope",
        "authority",
        "root_local_campaign_one_shot",
        *_CLOSED_AUTHORITY_FLAGS,
    }
)
_VETO_FIELDS = _VETO_CONTENT_FIELDS | {"content_sha256"}

_V4_WITNESSED_ARM_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "attempt_id",
        "authority_id",
        "arm_witness_root_id",
        "one_shot_key_sha256",
        "terminal_event_sha256",
        "terminal_status",
        "terminal_evidence_sha256",
        "prepared_evidence_sha256",
        "started_evidence_sha256",
        "reopened_file_count",
        "reopened_manifest_sha256",
        "transcript_sha256",
        "status",
        "fault",
        "host_outcome",
        "winner_role",
        "witness_chain_verified",
        "global_one_shot_within_authority",
        "root_local_one_shot_enforced",
        "canonical_external_journal_required",
        "receipt_artifacts_reopened",
        "transcript_chain_recomputed",
        "terminal_outcome_recomputed",
        "cross_policy_isolation_configuration_verified",
        "cross_policy_isolation_verified",
        "cross_policy_noninterference_proven",
        "sandbox_escape_absence_proven",
        "referee_rules_correctness_verified",
        "policy_execution_successful",
        "outcome_usable",
        "panel_parent_claim_verified",
        "parent_campaign_gate_required",
        "authority",
        "external_witness_verified",
        "scientific_selector_admissible",
        *FALSE_AUTHORITY_FLAGS,
    }
)
_V4_WITNESSED_ARM_FIELDS = _V4_WITNESSED_ARM_CONTENT_FIELDS | {"content_sha256"}


class CampaignCompositionError(ValueError):
    """A campaign cannot be rebuilt as one exact complete evidence set."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise CampaignCompositionError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignCompositionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or _TOKEN_RE.fullmatch(value) is None:
        raise CampaignCompositionError(f"{label} must be a non-empty safe token")
    return value


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CampaignCompositionError(f"{label} must be a positive integer")
    return value


def _seed(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63:
        raise CampaignCompositionError(f"{label} must be a non-negative signed-63-bit integer")
    return value


def _outcome(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, float) or not math.isfinite(value):
        raise CampaignCompositionError(f"{label} must be a finite canonical float")
    if value not in {0.0, 0.5, 1.0}:
        raise CampaignCompositionError(f"{label} must be one of 0.0, 0.5, or 1.0")
    return value


def _closed_authority(value: Mapping[str, Any], *, label: str) -> None:
    if value.get("authority") != DEVELOPMENT_AUTHORITY:
        raise CampaignCompositionError(f"{label}.authority must remain DEVELOPMENT_ONLY")
    if value.get("root_local_campaign_one_shot") is not True:
        raise CampaignCompositionError(f"{label}.root_local_campaign_one_shot must be true")
    for field, expected in _CLOSED_AUTHORITY_FLAGS.items():
        if value.get(field) is not expected:
            raise CampaignCompositionError(f"{label}.{field} must remain false")


def _self_hashed(
    value: object,
    *,
    fields: frozenset[str],
    content_fields: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    raw = _exact_fields(value, fields, label=label)
    digest = _digest(raw["content_sha256"], label=f"{label}.content_sha256")
    content = {field: raw[field] for field in content_fields}
    if digest != canonical_sha256(content):
        raise CampaignCompositionError(f"{label}.content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise CampaignCompositionError(f"{label} is not canonical")
    return raw


def _canonical_cas_object(payload: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise CampaignCompositionError(f"{label} has duplicate JSON keys")
            result[key] = item
        return result

    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignCompositionError(f"{label} is not canonical ASCII JSON: {exc}") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != payload:
        raise CampaignCompositionError(f"{label} is not canonical JSON")
    return value


def _arm_ref_or_none(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label=label)


def validate_witnessed_arm_packet(value: object) -> dict[str, Any]:
    """Validate the stable, self-hashed v4 ``compose_witnessed_arm`` packet."""

    raw = _self_hashed(
        value,
        fields=_V4_WITNESSED_ARM_FIELDS,
        content_fields=_V4_WITNESSED_ARM_CONTENT_FIELDS,
        label="v4 witnessed arm packet",
    )
    if raw["schema"] != V4_WITNESSED_ARM_SCHEMA:
        raise CampaignCompositionError("v4 witnessed arm packet schema mismatch")
    _token(raw["attempt_id"], label="v4 witnessed arm packet.attempt_id")
    for field in (
        "authority_id",
        "arm_witness_root_id",
        "one_shot_key_sha256",
        "terminal_event_sha256",
        "terminal_evidence_sha256",
        "prepared_evidence_sha256",
        "started_evidence_sha256",
        "reopened_manifest_sha256",
    ):
        _digest(raw[field], label=f"v4 witnessed arm packet.{field}")
    if raw["terminal_status"] not in {SUCCESS, "FAILURE", BURN}:
        raise CampaignCompositionError("v4 witnessed arm packet terminal_status is invalid")
    if raw["status"] != raw["terminal_status"]:
        raise CampaignCompositionError("v4 witnessed arm packet status differs from terminal_status")
    if isinstance(raw["reopened_file_count"], bool) or not isinstance(raw["reopened_file_count"], int) or raw["reopened_file_count"] < 0:
        raise CampaignCompositionError("v4 witnessed arm packet reopened_file_count is invalid")
    if raw["fault"] is not None and not isinstance(raw["fault"], str):
        raise CampaignCompositionError("v4 witnessed arm packet fault is invalid")
    if raw["winner_role"] not in {None, "candidate_policy", "opponent_policy"}:
        raise CampaignCompositionError("v4 witnessed arm packet winner_role is invalid")
    for field in (
        "witness_chain_verified",
        "root_local_one_shot_enforced",
        "canonical_external_journal_required",
        "receipt_artifacts_reopened",
        "cross_policy_isolation_verified",
        "cross_policy_noninterference_proven",
        "sandbox_escape_absence_proven",
        "referee_rules_correctness_verified",
        "outcome_usable",
        "panel_parent_claim_verified",
        "external_witness_verified",
        "scientific_selector_admissible",
    ):
        if not isinstance(raw[field], bool):
            raise CampaignCompositionError(f"v4 witnessed arm packet.{field} must be boolean")
    if raw["authority"] != LOCAL_WITNESS_AUTHORITY:
        raise CampaignCompositionError("v4 witnessed arm packet authority mismatch")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if raw[field] is not expected:
            raise CampaignCompositionError(f"v4 witnessed arm packet.{field} must remain false")
    for field in (
        "global_one_shot_within_authority",
        "cross_policy_isolation_verified",
        "cross_policy_noninterference_proven",
        "sandbox_escape_absence_proven",
        "referee_rules_correctness_verified",
        "outcome_usable",
        "panel_parent_claim_verified",
        "external_witness_verified",
        "scientific_selector_admissible",
    ):
        if raw[field] is not False:
            raise CampaignCompositionError(f"v4 witnessed arm packet.{field} must remain false")
    if raw["parent_campaign_gate_required"] is not True:
        raise CampaignCompositionError("v4 witnessed arm packet parent campaign gate must remain required")

    success = raw["status"] == SUCCESS
    if success:
        _digest(raw["transcript_sha256"], label="v4 witnessed arm packet.transcript_sha256")
        _outcome(raw["host_outcome"], label="v4 witnessed arm packet.host_outcome")
        expected_outcome = {
            "candidate_policy": 1.0,
            "opponent_policy": 0.0,
            None: 0.5,
        }[raw["winner_role"]]
        if raw["host_outcome"] != expected_outcome:
            raise CampaignCompositionError(
                "successful v4 witnessed arm packet winner_role and host_outcome disagree"
            )
        for field in (
            "transcript_chain_recomputed",
            "terminal_outcome_recomputed",
            "cross_policy_isolation_configuration_verified",
            "policy_execution_successful",
        ):
            if raw[field] is not True:
                raise CampaignCompositionError(f"successful v4 witnessed arm packet.{field} must be true")
    else:
        if raw["transcript_sha256"] is not None or raw["host_outcome"] is not None or raw["winner_role"] is not None:
            raise CampaignCompositionError("non-successful v4 witnessed arm packet exposes an outcome")
        for field in (
            "transcript_chain_recomputed",
            "terminal_outcome_recomputed",
            "cross_policy_isolation_configuration_verified",
            "policy_execution_successful",
        ):
            if raw[field] is not False:
                raise CampaignCompositionError(f"non-successful v4 witnessed arm packet.{field} must be false")
    return dict(raw)


def _build_arm_terminal_evidence(
    *,
    campaign_id: str,
    allocation_id: str,
    logical_attempt_id: str,
    terminal_status: str,
    launch_state: str,
    sandbox_arm_claim_sha256: str,
    child_attempt_id: str | None = None,
    parent_bound_child_claim_sha256: str | None = None,
    child_claim_event_sha256: str | None = None,
    child_start_event_sha256: str | None = None,
    witnessed_arm: object | None = None,
) -> dict[str, Any]:
    """Build immutable CAS evidence for one exact campaign allocation.

    Executors may call this before ``CampaignJournal.terminal_arm``.  A
    successful allocation must include the already recomposed v4 arm packet;
    failures and burns deliberately carry no arm outcome.
    """

    campaign = _digest(campaign_id, label="campaign_id")
    allocation = _token(allocation_id, label="allocation_id")
    attempt = _token(logical_attempt_id, label="logical_attempt_id")
    claim = _digest(sandbox_arm_claim_sha256, label="sandbox_arm_claim_sha256")
    if terminal_status not in {SUCCESS, "FAILURE", BURN}:
        raise CampaignCompositionError("terminal_status is invalid")
    if launch_state not in {"NEVER_STARTED", "START_DURABLE_POPEN_UNCERTAIN", POPEN_OBSERVED}:
        raise CampaignCompositionError("launch_state is invalid")
    if terminal_status in {SUCCESS, "FAILURE"} and launch_state != POPEN_OBSERVED:
        raise CampaignCompositionError("SUCCESS/FAILURE allocation requires POPEN_OBSERVED")

    if terminal_status == SUCCESS:
        for label, value in (
            ("child_attempt_id", child_attempt_id),
            ("parent_bound_child_claim_sha256", parent_bound_child_claim_sha256),
            ("child_claim_event_sha256", child_claim_event_sha256),
            ("child_start_event_sha256", child_start_event_sha256),
        ):
            if value is None:
                raise CampaignCompositionError(f"successful allocation requires {label}")
        witnessed = validate_witnessed_arm_packet(witnessed_arm)
        child_attempt = _digest(child_attempt_id, label="child_attempt_id")
        if witnessed["attempt_id"] != child_attempt:
            raise CampaignCompositionError("witnessed arm attempt does not match child_attempt_id")
        if witnessed["status"] != SUCCESS or witnessed["terminal_status"] != SUCCESS:
            raise CampaignCompositionError("successful allocation requires a successful witnessed arm")
        arm_values: dict[str, Any] = {
            "arm_witness_authority_id": witnessed["authority_id"],
            "arm_witness_root_id": witnessed["arm_witness_root_id"],
            "immutable_terminal_event_sha256": witnessed["terminal_event_sha256"],
            "arm_terminal_evidence_sha256": witnessed["terminal_evidence_sha256"],
            "witnessed_arm_content_sha256": witnessed["content_sha256"],
            "status": witnessed["status"],
            "host_outcome": witnessed["host_outcome"],
        }
    else:
        if witnessed_arm is not None:
            raise CampaignCompositionError("non-success allocation may not carry a witnessed arm outcome")
        arm_values = {
            "arm_witness_authority_id": None,
            "arm_witness_root_id": None,
            "immutable_terminal_event_sha256": None,
            "arm_terminal_evidence_sha256": None,
            "witnessed_arm_content_sha256": None,
            "status": None,
            "host_outcome": None,
        }
        child_attempt = None
        if any(
            value is not None
            for value in (
                child_attempt_id,
                parent_bound_child_claim_sha256,
                child_claim_event_sha256,
                child_start_event_sha256,
            )
        ):
            raise CampaignCompositionError("non-success allocation may not carry child success evidence")
    content = {
        "schema": ARM_TERMINAL_EVIDENCE_SCHEMA,
        "campaign_id": campaign,
        "allocation_id": allocation,
        "logical_attempt_id": attempt,
        "terminal_status": terminal_status,
        "launch_state": launch_state,
        "sandbox_arm_claim_sha256": claim,
        "child_attempt_id": child_attempt,
        "parent_bound_child_claim_sha256": _arm_ref_or_none(
            parent_bound_child_claim_sha256,
            label="parent_bound_child_claim_sha256",
        ),
        "child_claim_event_sha256": _arm_ref_or_none(
            child_claim_event_sha256,
            label="child_claim_event_sha256",
        ),
        "child_start_event_sha256": _arm_ref_or_none(
            child_start_event_sha256,
            label="child_start_event_sha256",
        ),
        **arm_values,
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **_CLOSED_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_arm_terminal_evidence(value: object) -> dict[str, Any]:
    """Validate a self-hashed per-allocation terminal evidence object."""

    raw = _self_hashed(
        value,
        fields=_ARM_TERMINAL_FIELDS,
        content_fields=_ARM_TERMINAL_CONTENT_FIELDS,
        label="arm terminal evidence",
    )
    if raw["schema"] != ARM_TERMINAL_EVIDENCE_SCHEMA:
        raise CampaignCompositionError("arm terminal evidence schema mismatch")
    _digest(raw["campaign_id"], label="arm terminal evidence.campaign_id")
    _token(raw["allocation_id"], label="arm terminal evidence.allocation_id")
    _token(raw["logical_attempt_id"], label="arm terminal evidence.logical_attempt_id")
    _digest(raw["sandbox_arm_claim_sha256"], label="arm terminal evidence.sandbox_arm_claim_sha256")
    if raw["terminal_status"] not in {SUCCESS, "FAILURE", BURN}:
        raise CampaignCompositionError("arm terminal evidence terminal_status is invalid")
    if raw["launch_state"] not in {"NEVER_STARTED", "START_DURABLE_POPEN_UNCERTAIN", POPEN_OBSERVED}:
        raise CampaignCompositionError("arm terminal evidence launch_state is invalid")
    if raw["terminal_status"] in {SUCCESS, "FAILURE"} and raw["launch_state"] != POPEN_OBSERVED:
        raise CampaignCompositionError("SUCCESS/FAILURE arm terminal evidence requires POPEN_OBSERVED")
    _closed_authority(raw, label="arm terminal evidence")

    arm_fields = (
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "immutable_terminal_event_sha256",
        "arm_terminal_evidence_sha256",
        "witnessed_arm_content_sha256",
    )
    success = raw["terminal_status"] == SUCCESS
    if success:
        if raw["launch_state"] != POPEN_OBSERVED or raw["status"] != SUCCESS:
            raise CampaignCompositionError("successful arm terminal evidence has an invalid disposition")
        for field in arm_fields:
            _digest(raw[field], label=f"arm terminal evidence.{field}")
        for field in (
            "child_attempt_id",
            "parent_bound_child_claim_sha256",
            "child_claim_event_sha256",
            "child_start_event_sha256",
        ):
            _digest(raw[field], label=f"arm terminal evidence.{field}")
        _outcome(raw["host_outcome"], label="arm terminal evidence.host_outcome")
    else:
        if raw["status"] is not None or raw["host_outcome"] is not None:
            raise CampaignCompositionError("non-success arm terminal evidence exposes an outcome")
        if any(raw[field] is not None for field in arm_fields):
            raise CampaignCompositionError("non-success arm terminal evidence carries an arm witness")
        if any(
            raw[field] is not None
            for field in (
                "child_attempt_id",
                "parent_bound_child_claim_sha256",
                "child_claim_event_sha256",
                "child_start_event_sha256",
            )
        ):
            raise CampaignCompositionError("non-success arm terminal evidence carries child success evidence")
    return dict(raw)


def _state_dispositions(campaign_state: Mapping[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    allocation_ids = campaign_state.get("allocation_ids")
    dispositions = campaign_state.get("dispositions")
    if not isinstance(allocation_ids, list) or not allocation_ids:
        raise CampaignCompositionError("campaign state has no allocation_ids")
    if not isinstance(dispositions, Mapping) or set(dispositions) != set(allocation_ids):
        raise CampaignCompositionError("campaign state dispositions do not exactly cover allocation_ids")
    checked_ids = [_token(value, label=f"campaign state allocation_ids[{index}]") for index, value in enumerate(allocation_ids)]
    if len(set(checked_ids)) != len(checked_ids):
        raise CampaignCompositionError("campaign state allocation_ids are duplicated")
    result: list[dict[str, Any]] = []
    for allocation_id in checked_ids:
        item = dispositions[allocation_id]
        if not isinstance(item, Mapping):
            raise CampaignCompositionError("campaign state disposition must be an object")
        terminal_status = item.get("terminal_status")
        launch_state = item.get("launch_state")
        if terminal_status not in {SUCCESS, "FAILURE", BURN} or launch_state not in {
            "NEVER_STARTED",
            "START_DURABLE_POPEN_UNCERTAIN",
            POPEN_OBSERVED,
        }:
            raise CampaignCompositionError("campaign state disposition is invalid")
        result.append(
            {
                "allocation_id": allocation_id,
                "terminal_status": terminal_status,
                "launch_state": launch_state,
                "terminal_evidence_sha256": _digest(
                    item.get("terminal_evidence_sha256"),
                    label="campaign state terminal_evidence_sha256",
                ),
            }
        )
    return checked_ids, result


def build_campaign_terminal_manifest(
    campaign_state: Mapping[str, Any],
    *,
    campaign_root_id: str,
    terminal_status: str | None = None,
) -> dict[str, Any]:
    """Build the exact manifest that a terminal campaign journal must seal."""

    if not isinstance(campaign_state, Mapping):
        raise CampaignCompositionError("campaign_state must be an object")
    campaign_id = _digest(campaign_state.get("campaign_id"), label="campaign state campaign_id")
    authority_id = _digest(campaign_state.get("authority_id"), label="campaign state authority_id")
    root_id = _digest(campaign_root_id, label="campaign_root_id")
    plan_sha256 = _digest(campaign_state.get("plan_sha256"), label="campaign state plan_sha256")
    plan_evidence_sha256 = _digest(
        campaign_state.get("plan_evidence_sha256"), label="campaign state plan_evidence_sha256"
    )
    state_kind = campaign_state.get("state")
    state_terminal_status = campaign_state.get("terminal_status")
    selected_terminal_status = terminal_status if terminal_status is not None else state_terminal_status
    if state_kind not in {"STARTED", "TERMINAL"} or selected_terminal_status not in {SUCCESS, VETO}:
        raise CampaignCompositionError("campaign terminal manifest requires a terminal campaign disposition")
    if state_kind == "STARTED" and terminal_status is None:
        raise CampaignCompositionError("started campaign state requires an explicit terminal_status")
    if state_kind == "TERMINAL" and selected_terminal_status != state_terminal_status:
        raise CampaignCompositionError("terminal campaign state disagrees with terminal_status")
    allocation_ids, dispositions = _state_dispositions(campaign_state)
    all_success = all(item["terminal_status"] == SUCCESS for item in dispositions)
    if (selected_terminal_status == SUCCESS) != all_success:
        raise CampaignCompositionError("campaign state terminal_status disagrees with dispositions")
    if selected_terminal_status == SUCCESS and any(
        item["launch_state"] != POPEN_OBSERVED for item in dispositions
    ):
        raise CampaignCompositionError("successful campaign has an allocation without POPEN_OBSERVED")
    content = {
        "schema": CAMPAIGN_TERMINAL_MANIFEST_SCHEMA,
        "campaign_id": campaign_id,
        "campaign_authority_id": authority_id,
        "campaign_root_id": root_id,
        "plan_sha256": plan_sha256,
        "plan_evidence_sha256": plan_evidence_sha256,
        "terminal_status": selected_terminal_status,
        "allocation_dispositions": dispositions,
        "disposition_count": len(allocation_ids),
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **_CLOSED_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_campaign_terminal_manifest(value: object) -> dict[str, Any]:
    """Validate the self-hashed terminal manifest without trusting journal state."""

    raw = _self_hashed(
        value,
        fields=_TERMINAL_MANIFEST_FIELDS,
        content_fields=_TERMINAL_MANIFEST_CONTENT_FIELDS,
        label="campaign terminal manifest",
    )
    if raw["schema"] != CAMPAIGN_TERMINAL_MANIFEST_SCHEMA:
        raise CampaignCompositionError("campaign terminal manifest schema mismatch")
    for field in (
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "plan_evidence_sha256",
    ):
        _digest(raw[field], label=f"campaign terminal manifest.{field}")
    if raw["terminal_status"] not in {SUCCESS, VETO}:
        raise CampaignCompositionError("campaign terminal manifest terminal_status is invalid")
    _closed_authority(raw, label="campaign terminal manifest")
    count = _positive_int(raw["disposition_count"], label="campaign terminal manifest.disposition_count")
    if not isinstance(raw["allocation_dispositions"], list) or len(raw["allocation_dispositions"]) != count:
        raise CampaignCompositionError("campaign terminal manifest disposition_count mismatch")
    dispositions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value_item in enumerate(raw["allocation_dispositions"]):
        item = _exact_fields(value_item, _DISPOSITION_FIELDS, label=f"allocation_dispositions[{index}]")
        allocation_id = _token(item["allocation_id"], label=f"allocation_dispositions[{index}].allocation_id")
        if allocation_id in seen:
            raise CampaignCompositionError("campaign terminal manifest allocation dispositions are duplicated")
        seen.add(allocation_id)
        status = item["terminal_status"]
        launch_state = item["launch_state"]
        if status not in {SUCCESS, "FAILURE", BURN} or launch_state not in {
            "NEVER_STARTED",
            "START_DURABLE_POPEN_UNCERTAIN",
            POPEN_OBSERVED,
        }:
            raise CampaignCompositionError("campaign terminal manifest disposition is invalid")
        dispositions.append(
            {
                "allocation_id": allocation_id,
                "terminal_status": status,
                "launch_state": launch_state,
                "terminal_evidence_sha256": _digest(
                    item["terminal_evidence_sha256"],
                    label=f"allocation_dispositions[{index}].terminal_evidence_sha256",
                ),
            }
        )
    all_success = all(item["terminal_status"] == SUCCESS for item in dispositions)
    if (raw["terminal_status"] == SUCCESS) != all_success:
        raise CampaignCompositionError("campaign terminal manifest status disagrees with dispositions")
    if raw["terminal_status"] == SUCCESS and any(
        item["launch_state"] != POPEN_OBSERVED for item in dispositions
    ):
        raise CampaignCompositionError(
            "campaign terminal manifest successful allocation lacks POPEN_OBSERVED"
        )
    return dict(raw)


def build_prelaunch_veto_manifest(
    campaign_state: Mapping[str, Any],
    *,
    campaign_root_id: str,
) -> dict[str, Any]:
    """Build a non-circular terminal manifest for a campaign vetoed before WAVE_START.

    A prelaunch journal event represents every allocation as a never-started
    burn, but there are deliberately no per-arm terminal events.  Reusing the
    campaign terminal evidence digest as each arm digest would make the normal
    terminal manifest self-referential.  This separate exact manifest binds the
    complete allocation set and the uniform fail-closed disposition without
    pretending that per-arm evidence exists.
    """

    if not isinstance(campaign_state, Mapping):
        raise CampaignCompositionError("campaign_state must be an object")
    state_kind = campaign_state.get("state")
    if state_kind not in {"CLAIMED", "PREPARED", "STARTED", "TERMINAL"}:
        raise CampaignCompositionError("prelaunch veto manifest has an invalid campaign state")
    if campaign_state.get("started_waves") not in ([], ()):  # exact prelaunch boundary
        raise CampaignCompositionError("prelaunch veto manifest requires no started wave")
    if state_kind == "TERMINAL" and campaign_state.get("terminal_status") != VETO:
        raise CampaignCompositionError("prelaunch terminal campaign must be VETO")

    raw_ids = campaign_state.get("allocation_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        raise CampaignCompositionError("prelaunch veto manifest requires allocation_ids")
    allocation_ids = [
        _token(value, label=f"prelaunch allocation_ids[{index}]")
        for index, value in enumerate(raw_ids)
    ]
    if len(set(allocation_ids)) != len(allocation_ids):
        raise CampaignCompositionError("prelaunch allocation_ids are duplicated")

    dispositions = campaign_state.get("dispositions")
    if not isinstance(dispositions, Mapping):
        raise CampaignCompositionError("prelaunch campaign dispositions must be an object")
    if dispositions:
        if set(dispositions) != set(allocation_ids):
            raise CampaignCompositionError("terminal prelaunch dispositions are incomplete")
        for allocation_id in allocation_ids:
            disposition = dispositions[allocation_id]
            if (
                not isinstance(disposition, Mapping)
                or disposition.get("terminal_status") != BURN
                or disposition.get("launch_state") != NEVER_STARTED
            ):
                raise CampaignCompositionError(
                    "terminal prelaunch dispositions must all be NEVER_STARTED burns"
                )

    content = {
        "schema": PRELAUNCH_VETO_MANIFEST_SCHEMA,
        "campaign_id": _digest(campaign_state.get("campaign_id"), label="campaign state campaign_id"),
        "campaign_authority_id": _digest(
            campaign_state.get("authority_id"), label="campaign state authority_id"
        ),
        "campaign_root_id": _digest(campaign_root_id, label="campaign_root_id"),
        "plan_sha256": _digest(campaign_state.get("plan_sha256"), label="campaign state plan_sha256"),
        "plan_evidence_sha256": _digest(
            campaign_state.get("plan_evidence_sha256"), label="campaign state plan_evidence_sha256"
        ),
        "terminal_status": VETO,
        "allocation_ids": allocation_ids,
        "disposition_count": len(allocation_ids),
        "allocation_terminal_status": BURN,
        "allocation_launch_state": NEVER_STARTED,
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **_CLOSED_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_prelaunch_veto_manifest(value: object) -> dict[str, Any]:
    """Validate the exact zero-outcome evidence used by ``veto_prelaunch``."""

    raw = _self_hashed(
        value,
        fields=_PRELAUNCH_VETO_MANIFEST_FIELDS,
        content_fields=_PRELAUNCH_VETO_MANIFEST_CONTENT_FIELDS,
        label="prelaunch veto manifest",
    )
    if raw["schema"] != PRELAUNCH_VETO_MANIFEST_SCHEMA:
        raise CampaignCompositionError("prelaunch veto manifest schema mismatch")
    for field in (
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "plan_evidence_sha256",
    ):
        _digest(raw[field], label=f"prelaunch veto manifest.{field}")
    if raw["terminal_status"] != VETO:
        raise CampaignCompositionError("prelaunch veto terminal_status must be VETO")
    if raw["allocation_terminal_status"] != BURN:
        raise CampaignCompositionError("prelaunch allocation status must be BURN")
    if raw["allocation_launch_state"] != NEVER_STARTED:
        raise CampaignCompositionError("prelaunch allocation launch state must be NEVER_STARTED")
    if not isinstance(raw["allocation_ids"], list) or not raw["allocation_ids"]:
        raise CampaignCompositionError("prelaunch veto manifest allocation_ids are invalid")
    allocation_ids = [
        _token(value, label=f"prelaunch allocation_ids[{index}]")
        for index, value in enumerate(raw["allocation_ids"])
    ]
    if len(set(allocation_ids)) != len(allocation_ids):
        raise CampaignCompositionError("prelaunch veto manifest allocations are duplicated")
    count = _positive_int(raw["disposition_count"], label="prelaunch disposition_count")
    if count != len(allocation_ids):
        raise CampaignCompositionError("prelaunch veto disposition_count mismatch")
    _closed_authority(raw, label="prelaunch veto manifest")
    return dict(raw)


def _normalize_panel_row(value: object, *, label: str) -> dict[str, Any]:
    raw = _exact_fields(value, _PANEL_ROW_FIELDS, label=label)
    seat = raw["seat"]
    if seat not in {"policy_first", "policy_second"}:
        raise CampaignCompositionError(f"{label}.seat is invalid")
    candidate = _token(raw["candidate_allocation_id"], label=f"{label}.candidate_allocation_id")
    baseline = _token(raw["baseline_allocation_id"], label=f"{label}.baseline_allocation_id")
    if candidate == baseline:
        raise CampaignCompositionError(f"{label} candidate and baseline allocation IDs coincide")
    return {
        "engine_id": _token(raw["engine_id"], label=f"{label}.engine_id"),
        "opponent_id": _token(raw["opponent_id"], label=f"{label}.opponent_id"),
        "seed": _seed(raw["seed"], label=f"{label}.seed"),
        "seat": seat,
        "candidate_allocation_id": candidate,
        "baseline_allocation_id": baseline,
        "candidate_terminal_evidence_sha256": _digest(
            raw["candidate_terminal_evidence_sha256"],
            label=f"{label}.candidate_terminal_evidence_sha256",
        ),
        "baseline_terminal_evidence_sha256": _digest(
            raw["baseline_terminal_evidence_sha256"],
            label=f"{label}.baseline_terminal_evidence_sha256",
        ),
        "candidate_witnessed_arm_content_sha256": _digest(
            raw["candidate_witnessed_arm_content_sha256"],
            label=f"{label}.candidate_witnessed_arm_content_sha256",
        ),
        "baseline_witnessed_arm_content_sha256": _digest(
            raw["baseline_witnessed_arm_content_sha256"],
            label=f"{label}.baseline_witnessed_arm_content_sha256",
        ),
        "candidate_outcome": _outcome(raw["candidate_outcome"], label=f"{label}.candidate_outcome"),
        "baseline_outcome": _outcome(raw["baseline_outcome"], label=f"{label}.baseline_outcome"),
    }


def _build_witnessed_complete_campaign_panel(
    *,
    campaign_id: str,
    campaign_authority_id: str,
    campaign_root_id: str,
    plan_sha256: str,
    campaign_terminal_evidence_sha256: str,
    campaign_terminal_manifest_content_sha256: str,
    paired_cell_count: int,
    rows: object,
) -> dict[str, Any]:
    """Build the only outcome-bearing local complete-set campaign artifact."""

    count = _positive_int(paired_cell_count, label="paired_cell_count")
    if not isinstance(rows, list) or len(rows) != count:
        raise CampaignCompositionError("rows must exactly cover paired_cell_count")
    normalized = [_normalize_panel_row(item, label=f"rows[{index}]") for index, item in enumerate(rows)]
    keys = [
        (item["engine_id"], item["opponent_id"], item["seed"], item["seat"])
        for item in normalized
    ]
    if len(set(keys)) != len(keys):
        raise CampaignCompositionError("campaign panel has duplicate paired cells")
    if keys != sorted(keys):
        raise CampaignCompositionError("campaign panel rows are not canonically sorted")
    content = {
        "schema": WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA,
        "campaign_id": _digest(campaign_id, label="campaign_id"),
        "campaign_authority_id": _digest(campaign_authority_id, label="campaign_authority_id"),
        "campaign_root_id": _digest(campaign_root_id, label="campaign_root_id"),
        "plan_sha256": _digest(plan_sha256, label="plan_sha256"),
        "campaign_terminal_evidence_sha256": _digest(
            campaign_terminal_evidence_sha256, label="campaign_terminal_evidence_sha256"
        ),
        "campaign_terminal_manifest_content_sha256": _digest(
            campaign_terminal_manifest_content_sha256,
            label="campaign_terminal_manifest_content_sha256",
        ),
        "paired_cell_count": count,
        "rows": normalized,
        "row_set_sha256": canonical_sha256(normalized),
        "local_complete_set_outcomes_usable": True,
        "outcome_use_scope": ROOT_LOCAL_COMPLETE_SET_DIAGNOSTIC_ONLY,
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **_CLOSED_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def _validate_witnessed_complete_campaign_panel_structure(value: object) -> dict[str, Any]:
    """Validate a self-hashed, complete, root-local diagnostic panel."""

    raw = _self_hashed(
        value,
        fields=_PANEL_FIELDS,
        content_fields=_PANEL_CONTENT_FIELDS,
        label="witnessed complete campaign panel",
    )
    if raw["schema"] != WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA:
        raise CampaignCompositionError("witnessed complete campaign panel schema mismatch")
    for field in (
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "campaign_terminal_evidence_sha256",
        "campaign_terminal_manifest_content_sha256",
        "row_set_sha256",
    ):
        _digest(raw[field], label=f"witnessed complete campaign panel.{field}")
    _closed_authority(raw, label="witnessed complete campaign panel")
    if raw["local_complete_set_outcomes_usable"] is not True:
        raise CampaignCompositionError("complete campaign panel local outcome use must be true")
    if raw["outcome_use_scope"] != ROOT_LOCAL_COMPLETE_SET_DIAGNOSTIC_ONLY:
        raise CampaignCompositionError("complete campaign panel outcome use scope is invalid")
    count = _positive_int(raw["paired_cell_count"], label="paired_cell_count")
    if not isinstance(raw["rows"], list) or len(raw["rows"]) != count:
        raise CampaignCompositionError("complete campaign panel row count mismatch")
    rows = [_normalize_panel_row(item, label=f"rows[{index}]") for index, item in enumerate(raw["rows"])]
    keys = [
        (item["engine_id"], item["opponent_id"], item["seed"], item["seat"])
        for item in rows
    ]
    if len(set(keys)) != len(keys) or keys != sorted(keys):
        raise CampaignCompositionError("complete campaign panel rows are not a canonical exact set")
    if raw["row_set_sha256"] != canonical_sha256(rows):
        raise CampaignCompositionError("complete campaign panel row_set_sha256 mismatch")
    return dict(raw)


def _build_campaign_veto(
    *,
    campaign_id: str,
    campaign_authority_id: str,
    campaign_root_id: str,
    plan_sha256: str,
    campaign_terminal_evidence_sha256: str,
    campaign_terminal_manifest_content_sha256: str,
    terminal_status: str,
) -> dict[str, Any]:
    """Build the sole result type for a non-success campaign: no rows, no outcomes."""

    if terminal_status != VETO:
        raise CampaignCompositionError("campaign veto terminal_status must be VETO")
    content = {
        "schema": CAMPAIGN_VETO_SCHEMA,
        "campaign_id": _digest(campaign_id, label="campaign_id"),
        "campaign_authority_id": _digest(campaign_authority_id, label="campaign_authority_id"),
        "campaign_root_id": _digest(campaign_root_id, label="campaign_root_id"),
        "plan_sha256": _digest(plan_sha256, label="plan_sha256"),
        "campaign_terminal_evidence_sha256": _digest(
            campaign_terminal_evidence_sha256, label="campaign_terminal_evidence_sha256"
        ),
        "campaign_terminal_manifest_content_sha256": _digest(
            campaign_terminal_manifest_content_sha256,
            label="campaign_terminal_manifest_content_sha256",
        ),
        "terminal_status": terminal_status,
        "outcomes_omitted": True,
        "local_complete_set_outcomes_usable": False,
        "outcome_use_scope": NO_OUTCOME_USE,
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **_CLOSED_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_campaign_veto(value: object) -> dict[str, Any]:
    """Validate a self-hashed veto that intentionally contains no outcomes."""

    raw = _self_hashed(
        value,
        fields=_VETO_FIELDS,
        content_fields=_VETO_CONTENT_FIELDS,
        label="campaign veto",
    )
    if raw["schema"] != CAMPAIGN_VETO_SCHEMA:
        raise CampaignCompositionError("campaign veto schema mismatch")
    for field in (
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "plan_sha256",
        "campaign_terminal_evidence_sha256",
        "campaign_terminal_manifest_content_sha256",
    ):
        _digest(raw[field], label=f"campaign veto.{field}")
    if raw["terminal_status"] != VETO:
        raise CampaignCompositionError("campaign veto terminal_status is invalid")
    if raw["outcomes_omitted"] is not True or raw["local_complete_set_outcomes_usable"] is not False:
        raise CampaignCompositionError("campaign veto must omit outcomes")
    if raw["outcome_use_scope"] != NO_OUTCOME_USE:
        raise CampaignCompositionError("campaign veto outcome use scope is invalid")
    _closed_authority(raw, label="campaign veto")
    return dict(raw)


def _planned_allocations(
    plan: Mapping[str, Any], campaign_state: Mapping[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str, int, str], dict[str, dict[str, Any]]], int]:
    allocations = plan.get("allocations")
    logical_plan = plan.get("logical_execution_plan")
    if not isinstance(allocations, list) or not allocations:
        raise CampaignCompositionError("campaign plan allocations must be a non-empty list")
    if not isinstance(logical_plan, Mapping):
        raise CampaignCompositionError("campaign plan logical_execution_plan must be an object")
    paired_cell_count = _positive_int(
        logical_plan.get("paired_cell_count"), label="logical_execution_plan.paired_cell_count"
    )
    if len(allocations) != paired_cell_count * 2:
        raise CampaignCompositionError("campaign allocations do not exactly contain both policy labels per cell")
    declared_count = plan.get("allocation_count")
    if declared_count is not None and declared_count != len(allocations):
        raise CampaignCompositionError("campaign plan allocation_count mismatch")

    state_ids, _ = _state_dispositions(campaign_state)
    planned: dict[str, dict[str, Any]] = {}
    grouped: dict[tuple[str, str, int, str], dict[str, dict[str, Any]]] = {}
    expected_refs: list[dict[str, Any]] = []
    for index, allocation in enumerate(allocations):
        if not isinstance(allocation, Mapping):
            raise CampaignCompositionError(f"allocations[{index}] must be an object")
        allocation_id = _token(allocation.get("allocation_id"), label=f"allocations[{index}].allocation_id")
        logical_attempt_id = _token(
            allocation.get("logical_attempt_id"), label=f"allocations[{index}].logical_attempt_id"
        )
        claim = _digest(
            allocation.get("sandbox_arm_claim_sha256"),
            label=f"allocations[{index}].sandbox_arm_claim_sha256",
        )
        task = allocation.get("task")
        if not isinstance(task, Mapping):
            raise CampaignCompositionError(f"allocations[{index}].task must be an object")
        label = task.get("policy_label")
        if label not in {"candidate", "baseline"}:
            raise CampaignCompositionError(f"allocations[{index}].task.policy_label is invalid")
        cell = (
            _token(task.get("engine_id"), label=f"allocations[{index}].task.engine_id"),
            _token(task.get("opponent_id"), label=f"allocations[{index}].task.opponent_id"),
            _seed(task.get("seed"), label=f"allocations[{index}].task.seed"),
            task.get("seat"),
        )
        if cell[3] not in {"policy_first", "policy_second"}:
            raise CampaignCompositionError(f"allocations[{index}].task.seat is invalid")
        wave = allocation.get("wave")
        slot = allocation.get("slot")
        if isinstance(wave, bool) or not isinstance(wave, int) or wave < 0:
            raise CampaignCompositionError(f"allocations[{index}].wave is invalid")
        if isinstance(slot, bool) or not isinstance(slot, int) or slot < 0:
            raise CampaignCompositionError(f"allocations[{index}].slot is invalid")
        if allocation_id in planned:
            raise CampaignCompositionError("campaign plan allocation IDs are duplicated")
        if label in grouped.setdefault(cell, {}):
            raise CampaignCompositionError("campaign plan has duplicate policy allocation for a paired cell")
        entry = {
            "allocation_id": allocation_id,
            "logical_attempt_id": logical_attempt_id,
            "sandbox_arm_claim_sha256": claim,
            "task": dict(task),
            "wave": wave,
            "slot": slot,
        }
        planned[allocation_id] = entry
        grouped[cell][label] = entry
        expected_refs.append({"allocation_id": allocation_id, "wave": wave, "slot": slot})
    if list(planned) != state_ids or set(planned) != set(state_ids):
        raise CampaignCompositionError("campaign plan and journal allocation IDs differ")
    state_refs = campaign_state.get("allocation_refs")
    if state_refs != expected_refs:
        raise CampaignCompositionError("campaign plan and journal allocation references differ")
    if len(grouped) != paired_cell_count or any(set(pair) != {"candidate", "baseline"} for pair in grouped.values()):
        raise CampaignCompositionError("campaign plan is not an exact candidate/baseline paired grid")
    return planned, grouped, paired_cell_count


def _reopen_terminal_evidence(
    campaign_journal: CampaignJournal,
    campaign_id: str,
    allocation_id: str,
    disposition: Mapping[str, Any],
    allocation: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        payload = campaign_journal.read_terminal_evidence(campaign_id, allocation_id)
    except Exception as exc:
        raise CampaignCompositionError(
            f"could not reopen terminal evidence for allocation {allocation_id}: {exc}"
        ) from exc
    digest = hashlib.sha256(payload).hexdigest()
    if digest != disposition["terminal_evidence_sha256"]:
        raise CampaignCompositionError("terminal evidence hash differs from campaign journal disposition")
    evidence = validate_arm_terminal_evidence(
        _canonical_cas_object(payload, label=f"terminal evidence {allocation_id}")
    )
    if (
        evidence["campaign_id"] != campaign_id
        or evidence["allocation_id"] != allocation_id
        or evidence["logical_attempt_id"] != allocation["logical_attempt_id"]
        or evidence["terminal_status"] != disposition["terminal_status"]
        or evidence["launch_state"] != disposition["launch_state"]
        or evidence["sandbox_arm_claim_sha256"] != allocation["sandbox_arm_claim_sha256"]
    ):
        raise CampaignCompositionError("terminal evidence does not bind its exact campaign allocation")
    return evidence


def _verify_arm_claim_in_terminal_evidence(
    arm_journal: object,
    arm_packet: Mapping[str, Any],
    expected_claim: str,
) -> None:
    evidence_store = getattr(arm_journal, "evidence", None)
    read = getattr(evidence_store, "read", None)
    if not callable(read):
        raise CampaignCompositionError("arm journal does not expose a readable evidence CAS")
    try:
        payload = read(arm_packet["terminal_evidence_sha256"])
    except Exception as exc:
        raise CampaignCompositionError(f"could not reopen v4 arm terminal evidence: {exc}") from exc
    terminal = _canonical_cas_object(payload, label="v4 arm terminal evidence")
    if terminal.get("arm_claim_sha256") != expected_claim:
        raise CampaignCompositionError("v4 arm terminal evidence does not bind sandbox_arm_claim_sha256")


def _recompose_success_arm(
    arm_journal: object,
    allocation: Mapping[str, Any],
    terminal_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    attempt_id = terminal_evidence["child_attempt_id"]
    try:
        packet = validate_witnessed_arm_packet(compose_witnessed_arm(arm_journal, attempt_id))
    except CampaignCompositionError:
        raise
    except Exception as exc:
        raise CampaignCompositionError(
            f"could not recompose planned arm {attempt_id}: {exc}"
        ) from exc
    if packet["attempt_id"] != attempt_id or packet["status"] != SUCCESS or packet["terminal_status"] != SUCCESS:
        raise CampaignCompositionError("recomposed arm does not have the planned successful terminal status")
    if (
        packet["authority_id"] != getattr(arm_journal, "authority_id", None)
        or packet["arm_witness_root_id"] != getattr(arm_journal, "root_id", None)
    ):
        raise CampaignCompositionError(
            "recomposed arm does not belong to the campaign-owned witness namespace"
        )
    bindings = (
        ("arm_witness_authority_id", "authority_id"),
        ("arm_witness_root_id", "arm_witness_root_id"),
        ("immutable_terminal_event_sha256", "terminal_event_sha256"),
        ("arm_terminal_evidence_sha256", "terminal_evidence_sha256"),
        ("witnessed_arm_content_sha256", "content_sha256"),
        ("status", "status"),
        ("host_outcome", "host_outcome"),
    )
    for evidence_field, packet_field in bindings:
        if terminal_evidence[evidence_field] != packet[packet_field]:
            raise CampaignCompositionError(
                f"terminal evidence {evidence_field} differs from recomposed v4 arm packet"
            )
    _verify_arm_claim_in_terminal_evidence(
        arm_journal,
        packet,
        terminal_evidence["parent_bound_child_claim_sha256"],
    )
    return packet


def _reopen_prepared_allocations(
    campaign_journal: CampaignJournal,
    campaign_id: str,
    plan: Mapping[str, Any],
    state: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    digest = _digest(state.get("prepared_manifest_sha256"), label="prepared_manifest_sha256")
    try:
        payload = campaign_journal.read_evidence(digest)
        prepared = validate_campaign_prepared_manifest(
            _canonical_cas_object(payload, label="campaign prepared manifest"),
            plan,
            state,
        )
    except CampaignCompositionError:
        raise
    except CampaignPreparationError as exc:
        raise CampaignCompositionError(f"campaign preparation is invalid: {exc}") from exc
    except Exception as exc:
        raise CampaignCompositionError(f"could not reopen campaign preparation: {exc}") from exc
    if hashlib.sha256(payload).hexdigest() != digest:
        raise CampaignCompositionError("prepared manifest hash differs from campaign journal state")
    if prepared["campaign_id"] != campaign_id:
        raise CampaignCompositionError("prepared manifest campaign_id differs from campaign journal")
    allocations = prepared["allocations"]
    if not isinstance(allocations, list):
        raise CampaignCompositionError("prepared manifest allocations are invalid")
    by_id = {item["allocation_id"]: item for item in allocations}
    if len(by_id) != len(allocations):
        raise CampaignCompositionError("prepared manifest allocations are duplicated")
    return by_id


def _verify_child_claim_and_start(
    campaign_journal: CampaignJournal,
    state: Mapping[str, Any],
    allocation: Mapping[str, Any],
    prepared_allocation: Mapping[str, Any],
    disposition: Mapping[str, Any],
    terminal_evidence: Mapping[str, Any],
    arm_journal: object,
) -> None:
    """Verify the private child claim and its CLAIM -> START -> TERMINAL path."""

    allocation_id = allocation["allocation_id"]
    expected_attempt_id = child_attempt_id(state["campaign_id"], allocation_id)
    if terminal_evidence["child_attempt_id"] != expected_attempt_id:
        raise CampaignCompositionError("terminal evidence child_attempt_id is not campaign-derived")
    bound_arms = state.get("bound_arms")
    if not isinstance(bound_arms, Mapping) or allocation_id not in bound_arms:
        raise CampaignCompositionError("successful allocation lacks ARM_BOUND")
    bound = bound_arms[allocation_id]
    if not isinstance(bound, Mapping):
        raise CampaignCompositionError("ARM_BOUND record is invalid")
    expected_bound_claim = build_parent_bound_child_claim(prepared_allocation, state)
    try:
        validate_parent_bound_child_claim(expected_bound_claim, prepared_allocation, state)
    except ParentArmClaimError as exc:
        raise CampaignCompositionError(f"parent-bound child claim is invalid: {exc}") from exc
    expected_claim_sha256 = parent_bound_child_claim_sha256(expected_bound_claim)
    expected = {
        "campaign_id": state["campaign_id"],
        "allocation_id": allocation_id,
        "wave": allocation["wave"],
        "child_attempt_id": expected_attempt_id,
        "child_claim_sha256": expected_claim_sha256,
    }
    for field, value in expected.items():
        if bound.get(field) != value:
            raise CampaignCompositionError(f"ARM_BOUND {field} differs from parent-bound child claim")
    if terminal_evidence["parent_bound_child_claim_sha256"] != expected_claim_sha256:
        raise CampaignCompositionError("terminal evidence parent-bound child claim differs from ARM_BOUND")
    claim_event_sha256 = _digest(bound.get("child_claim_event_sha256"), label="ARM_BOUND.child_claim_event_sha256")
    if terminal_evidence["child_claim_event_sha256"] != claim_event_sha256:
        raise CampaignCompositionError("terminal evidence child CLAIM differs from ARM_BOUND")
    state_dispositions = state.get("dispositions")
    if not isinstance(state_dispositions, Mapping) or not isinstance(
        state_dispositions.get(allocation_id), Mapping
    ):
        raise CampaignCompositionError("campaign state lacks allocation disposition")
    if state_dispositions[allocation_id].get("arm_bound_event_sha256") != bound.get("event_sha256"):
        raise CampaignCompositionError("allocation disposition ARM_BOUND differs from campaign state")

    try:
        events = arm_journal.events()
        child_state = arm_journal.state(expected_attempt_id)
    except Exception as exc:
        raise CampaignCompositionError(f"could not reopen campaign-owned child witness: {exc}") from exc
    claim_index = start_index = terminal_index = None
    for index, event in enumerate(events):
        payload = event.get("payload")
        if not isinstance(payload, Mapping) or payload.get("attempt_id") != expected_attempt_id:
            continue
        if event.get("event_type") == "CLAIM" and event.get("event_sha256") == claim_event_sha256:
            if payload.get("claim_sha256") != expected_claim_sha256:
                raise CampaignCompositionError("child CLAIM does not carry the parent-bound child claim")
            claim_index = index
        elif event.get("event_type") == "START":
            start_index = index
            if event.get("event_sha256") != terminal_evidence["child_start_event_sha256"]:
                raise CampaignCompositionError("terminal evidence child START differs from child witness")
        elif event.get("event_type") == "TERMINAL":
            terminal_index = index
    if claim_index is None or start_index is None or terminal_index is None:
        raise CampaignCompositionError("successful child lacks required CLAIM, START, or TERMINAL evidence")
    if not claim_index < start_index < terminal_index:
        raise CampaignCompositionError("child witness CLAIM, START, and TERMINAL chronology is invalid")
    if (
        child_state.get("claim_sha256") != expected_claim_sha256
        or child_state.get("terminal_status") != SUCCESS
        or child_state.get("terminal_event_sha256") != terminal_evidence["immutable_terminal_event_sha256"]
    ):
        raise CampaignCompositionError("child witness terminal state differs from campaign allocation")


def compose_campaign(
    campaign_journal: CampaignJournal,
    campaign_id: str,
) -> dict[str, Any]:
    """Compose one exact campaign from journals only.

    This is deliberately the only composition entry point.  The plan, every
    allocation terminal evidence object, and the terminal manifest are read
    from the campaign CAS.  A successful campaign recomposes *every* planned
    arm by its logical attempt ID; a VETO/BURN emits only ``campaign_veto``.
    """

    if not isinstance(campaign_journal, CampaignJournal):
        # Tests can still use a real subclass, but an arbitrary receipt-like
        # object must not impersonate the authenticated campaign journal.
        raise CampaignCompositionError("campaign_journal must be a CampaignJournal")
    checked_campaign_id = _digest(campaign_id, label="campaign_id")
    try:
        campaign_journal.verify()
        plan = validate_campaign_plan(campaign_journal.read_campaign_plan(checked_campaign_id))
        state = campaign_journal.state(checked_campaign_id)
    except CampaignCompositionError:
        raise
    except Exception as exc:
        raise CampaignCompositionError(f"campaign journal could not be reopened: {exc}") from exc
    if not isinstance(plan, Mapping) or not isinstance(state, Mapping):
        raise CampaignCompositionError("campaign journal did not return objects")
    if state.get("campaign_id") != checked_campaign_id or state.get("state") != "TERMINAL":
        raise CampaignCompositionError("campaign journal is not terminal for the requested campaign")
    if state.get("authority_id") != campaign_journal.authority_id:
        raise CampaignCompositionError("campaign journal authority_id changed")
    if state.get("plan_sha256") != plan.get("content_sha256"):
        raise CampaignCompositionError("reopened campaign plan hash differs from journal state")
    terminal_status = state.get("terminal_status")
    if terminal_status not in {SUCCESS, VETO}:
        raise CampaignCompositionError("campaign terminal status is invalid")

    # The child witness is campaign-owned implementation state, never a
    # caller-supplied or public mutable handle.
    arm_journal = campaign_journal._arm_journal
    if (
        state.get("arm_witness_authority_id") != arm_journal.authority_id
        or state.get("arm_witness_root_id") != arm_journal.root_id
    ):
        raise CampaignCompositionError(
            "campaign state does not bind its owned arm witness namespace"
        )

    planned, grouped, paired_cell_count = _planned_allocations(plan, state)
    _, dispositions = _state_dispositions(state)
    disposition_by_id = {item["allocation_id"]: item for item in dispositions}

    # Validate the terminal campaign evidence before choosing the VETO path.
    # A VETO is intentionally zero-row and may not reopen arm terminal or
    # outcome evidence.  Prelaunch VETO uses its own non-circular complete-set
    # manifest because no per-arm terminal events exist at that boundary.
    try:
        terminal_payload = campaign_journal.read_evidence(state["terminal_evidence_sha256"])
    except Exception as exc:
        raise CampaignCompositionError(f"could not reopen campaign terminal manifest: {exc}") from exc
    if hashlib.sha256(terminal_payload).hexdigest() != state["terminal_evidence_sha256"]:
        raise CampaignCompositionError("campaign terminal manifest hash differs from journal state")
    terminal_object = _canonical_cas_object(terminal_payload, label="campaign terminal manifest")
    prelaunch_veto = terminal_status == VETO and not state.get("started_waves")
    if prelaunch_veto:
        terminal_manifest = validate_prelaunch_veto_manifest(terminal_object)
        expected_manifest = build_prelaunch_veto_manifest(
            state,
            campaign_root_id=campaign_journal.root_id,
        )
    else:
        terminal_manifest = validate_campaign_terminal_manifest(terminal_object)
        expected_manifest = build_campaign_terminal_manifest(
            state,
            campaign_root_id=campaign_journal.root_id,
        )
    if terminal_manifest != expected_manifest:
        raise CampaignCompositionError("campaign terminal manifest does not exactly match journal state")

    if terminal_status != SUCCESS:
        return _build_campaign_veto(
            campaign_id=checked_campaign_id,
            campaign_authority_id=campaign_journal.authority_id,
            campaign_root_id=campaign_journal.root_id,
            plan_sha256=plan["content_sha256"],
            campaign_terminal_evidence_sha256=state["terminal_evidence_sha256"],
            campaign_terminal_manifest_content_sha256=terminal_manifest["content_sha256"],
            terminal_status=terminal_status,
        )

    if any(
        item["terminal_status"] != SUCCESS or item["launch_state"] != POPEN_OBSERVED
        for item in dispositions
    ):
        raise CampaignCompositionError(
            "successful campaign requires every allocation SUCCESS with POPEN_OBSERVED"
        )
    prepared_by_id = _reopen_prepared_allocations(
        campaign_journal,
        checked_campaign_id,
        plan,
        state,
    )
    if set(prepared_by_id) != set(planned):
        raise CampaignCompositionError("prepared manifest does not exactly cover campaign allocations")
    terminal_evidence_by_id = {
        allocation_id: _reopen_terminal_evidence(
            campaign_journal,
            checked_campaign_id,
            allocation_id,
            disposition_by_id[allocation_id],
            allocation,
        )
        for allocation_id, allocation in planned.items()
    }
    for allocation_id, allocation in planned.items():
        _verify_child_claim_and_start(
            campaign_journal,
            state,
            allocation,
            prepared_by_id[allocation_id],
            disposition_by_id[allocation_id],
            terminal_evidence_by_id[allocation_id],
            arm_journal,
        )
    packets = {
        allocation_id: _recompose_success_arm(
            arm_journal,
            allocation,
            terminal_evidence_by_id[allocation_id],
        )
        for allocation_id, allocation in planned.items()
    }
    rows: list[dict[str, Any]] = []
    for cell in sorted(grouped):
        candidate = grouped[cell]["candidate"]
        baseline = grouped[cell]["baseline"]
        candidate_evidence = terminal_evidence_by_id[candidate["allocation_id"]]
        baseline_evidence = terminal_evidence_by_id[baseline["allocation_id"]]
        # Policy labels from the frozen allocation task decide the columns.
        # Sandbox roles are intentionally never consulted for this mapping.
        rows.append(
            {
                "engine_id": cell[0],
                "opponent_id": cell[1],
                "seed": cell[2],
                "seat": cell[3],
                "candidate_allocation_id": candidate["allocation_id"],
                "baseline_allocation_id": baseline["allocation_id"],
                "candidate_terminal_evidence_sha256": disposition_by_id[candidate["allocation_id"]][
                    "terminal_evidence_sha256"
                ],
                "baseline_terminal_evidence_sha256": disposition_by_id[baseline["allocation_id"]][
                    "terminal_evidence_sha256"
                ],
                "candidate_witnessed_arm_content_sha256": packets[candidate["allocation_id"]][
                    "content_sha256"
                ],
                "baseline_witnessed_arm_content_sha256": packets[baseline["allocation_id"]][
                    "content_sha256"
                ],
                "candidate_outcome": candidate_evidence["host_outcome"],
                "baseline_outcome": baseline_evidence["host_outcome"],
            }
        )
    return _build_witnessed_complete_campaign_panel(
        campaign_id=checked_campaign_id,
        campaign_authority_id=campaign_journal.authority_id,
        campaign_root_id=campaign_journal.root_id,
        plan_sha256=plan["content_sha256"],
        campaign_terminal_evidence_sha256=state["terminal_evidence_sha256"],
        campaign_terminal_manifest_content_sha256=terminal_manifest["content_sha256"],
        paired_cell_count=paired_cell_count,
        rows=rows,
    )


def validate_witnessed_complete_campaign_panel(
    campaign_journal: CampaignJournal,
    campaign_id: str,
    value: object,
) -> dict[str, Any]:
    """Validate only by recomposing the exact authenticated campaign."""

    checked = _validate_witnessed_complete_campaign_panel_structure(value)
    expected = compose_campaign(campaign_journal, campaign_id)
    if expected.get("schema") != WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA:
        raise CampaignCompositionError(
            "requested campaign does not have a successful complete panel"
        )
    if checked != expected:
        raise CampaignCompositionError(
            "panel differs from the authenticated complete campaign"
        )
    return checked


WITNESSED_CAMPAIGN_PANEL_SCHEMA = WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA


__all__ = [
    "ARM_TERMINAL_EVIDENCE_SCHEMA",
    "CAMPAIGN_TERMINAL_MANIFEST_SCHEMA",
    "CAMPAIGN_VETO_SCHEMA",
    "PRELAUNCH_VETO_MANIFEST_SCHEMA",
    "CampaignCompositionError",
    "DEVELOPMENT_AUTHORITY",
    "NO_OUTCOME_USE",
    "ROOT_LOCAL_COMPLETE_SET_DIAGNOSTIC_ONLY",
    "V4_WITNESSED_ARM_SCHEMA",
    "WITNESSED_CAMPAIGN_PANEL_SCHEMA",
    "WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA",
    "build_campaign_terminal_manifest",
    "build_prelaunch_veto_manifest",
    "compose_campaign",
    "validate_arm_terminal_evidence",
    "validate_campaign_terminal_manifest",
    "validate_prelaunch_veto_manifest",
    "validate_campaign_veto",
    "validate_witnessed_arm_packet",
    "validate_witnessed_complete_campaign_panel",
]
