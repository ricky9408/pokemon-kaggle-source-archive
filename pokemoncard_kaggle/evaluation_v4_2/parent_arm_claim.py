"""Parent-bound child claim records for exclusive v4.2 campaigns.

Preparation freezes a template with placeholders.  Only after the durable
parent WAVE_START may the parent instantiate a child claim.  The SHA-256 of
that canonical claim is carried by every sandbox frame, so standalone or
pre-run arms cannot be adopted after the fact.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
from typing import Any

from .sandbox_binding import FALSE_AUTHORITY_FLAGS, canonical_sha256


CHILD_CLAIM_TEMPLATE_SCHEMA = "evaluation_v4_2_child_claim_template_v1"
PARENT_BOUND_CHILD_CLAIM_SCHEMA = "evaluation_v4_2_parent_bound_child_claim_v1"
PARENT_CHILD_CAMPAIGN_SCHEMA = "evaluation_v4_2_parent_child_campaign_identity_v1"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
SANDBOX_ROLES = ("referee", "candidate_policy", "opponent_policy")
COMMAND_PLACEHOLDERS = frozenset(
    {
        "$SNAPSHOT",
        "$CHILD_CLAIM_SHA256",
        "$ARM_BOUND_EVENT_SHA256",
        "$CHILD_START_EVENT_SHA256",
        "$SESSION_ID",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")
_TEMPLATE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "plan_sha256",
        "runner_binding_content_sha256",
        "parent_claim_event_sha256",
        "campaign_authority_id",
        "campaign_root_id",
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "allocation_id",
        "ordinal",
        "wave",
        "slot",
        "logical_attempt_id",
        "child_attempt_id",
        "logical_claim_content_sha256",
        "base_sandbox_arm_claim_sha256",
        "bundle_manifest_sha256",
        "bundle_tree_sha256",
        "bundle_task_spec_sha256",
        "runtime_bundle_sha256",
        "worker_source_sha256",
        "snapshot_manifest_sha256",
        "snapshot_tree_sha256",
        "container_names",
        "normalized_command_templates",
        "command_template_sha256s",
        "normalized_policy_identity_sha256",
        "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
)
_TEMPLATE_FIELDS = _TEMPLATE_CONTENT_FIELDS | {"content_sha256"}
_BOUND_FIELDS = frozenset(
    {
        "schema",
        "scope",
        "campaign_id",
        "campaign_authority_id",
        "campaign_root_id",
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "plan_sha256",
        "runner_binding_content_sha256",
        "parent_claim_event_sha256",
        "prepared_manifest_sha256",
        "parent_prepare_event_sha256",
        "parent_start_evidence_sha256",
        "parent_start_event_sha256",
        "parent_wave_start_event_sha256",
        "wave_runtime_verification_sha256",
        "allocation_id",
        "ordinal",
        "wave",
        "slot",
        "logical_attempt_id",
        "child_attempt_id",
        "prepared_allocation_content_sha256",
        "child_claim_template_sha256",
        "base_sandbox_arm_claim_sha256",
        "normalized_policy_identity_sha256",
        "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
)


class ParentArmClaimError(ValueError):
    """A parent/child claim binding is incomplete or non-canonical."""


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ParentArmClaimError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ParentArmClaimError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _token(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or _TOKEN_RE.fullmatch(value) is None
    ):
        raise ParentArmClaimError(f"{label} must be a non-empty safe token")
    return value


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ParentArmClaimError(f"{label} must be a non-negative integer")
    return value


def _closed(value: Mapping[str, Any], *, label: str) -> None:
    if value.get("authority") != DEVELOPMENT_AUTHORITY:
        raise ParentArmClaimError(f"{label}.authority must remain DEVELOPMENT_ONLY")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if value.get(field) is not expected:
            raise ParentArmClaimError(f"{label}.{field} must remain false")


def child_attempt_id(campaign_id: str, allocation_id: str) -> str:
    campaign = _digest(campaign_id, label="campaign_id")
    allocation = _token(allocation_id, label="allocation_id")
    return canonical_sha256(
        {
            "schema": "evaluation_v4_2_child_attempt_identity_v1",
            "campaign_id": campaign,
            "allocation_id": allocation,
        }
    )


def deterministic_parent_container_names(campaign_id: str, allocation_id: str) -> dict[str, str]:
    attempt = child_attempt_id(campaign_id, allocation_id)
    token = hashlib.sha256(attempt.encode("ascii")).hexdigest()[:32]
    return {
        "referee": f"ev42-parent-{token}-referee",
        "candidate_policy": f"ev42-parent-{token}-candidate",
        "opponent_policy": f"ev42-parent-{token}-opponent",
    }


def _command_templates(value: object) -> tuple[dict[str, list[str]], dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != set(SANDBOX_ROLES):
        raise ParentArmClaimError("normalized_command_templates must have exact sandbox roles")
    templates: dict[str, list[str]] = {}
    digests: dict[str, str] = {}
    for role in SANDBOX_ROLES:
        command = value[role]
        if not isinstance(command, list) or not command or not all(
            isinstance(token, str) and token for token in command
        ):
            raise ParentArmClaimError(f"normalized command template for {role} is invalid")
        used = {
            placeholder
            for placeholder in COMMAND_PLACEHOLDERS
            if any(placeholder in token for token in command)
        }
        if used != COMMAND_PLACEHOLDERS:
            raise ParentArmClaimError(
                f"normalized command template for {role} lacks exact parent placeholders"
            )
        for token in command:
            placeholder_tokens = set(re.findall(r"\$[A-Z][A-Z0-9_]*", token))
            if placeholder_tokens - COMMAND_PLACEHOLDERS or (
                "$" in token and not placeholder_tokens
            ):
                raise ParentArmClaimError(
                    f"normalized command template for {role} has an unknown placeholder"
                )
        templates[role] = list(command)
        digests[role] = canonical_sha256(command)
    return templates, digests


def build_child_claim_template(
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
    allocation: Mapping[str, Any],
    *,
    snapshot_manifest_sha256: str,
    snapshot_tree_sha256: str,
    normalized_command_templates: Mapping[str, list[str]],
) -> dict[str, Any]:
    templates, command_digests = _command_templates(normalized_command_templates)
    campaign_id = _digest(campaign_state.get("campaign_id"), label="campaign_id")
    allocation_id = _token(allocation.get("allocation_id"), label="allocation_id")
    content = {
        "schema": CHILD_CLAIM_TEMPLATE_SCHEMA,
        "campaign_id": campaign_id,
        "plan_sha256": _digest(plan.get("content_sha256"), label="plan_sha256"),
        "runner_binding_content_sha256": _digest(
            plan.get("runner_binding_content_sha256"), label="runner_binding_content_sha256"
        ),
        "parent_claim_event_sha256": _digest(
            campaign_state.get("claim_event_sha256"), label="parent_claim_event_sha256"
        ),
        "campaign_authority_id": _digest(
            campaign_state.get("authority_id"), label="campaign_authority_id"
        ),
        "campaign_root_id": _digest(
            campaign_state.get("root_id"), label="campaign_root_id"
        ),
        "arm_witness_authority_id": _digest(
            campaign_state.get("arm_witness_authority_id"), label="arm_witness_authority_id"
        ),
        "arm_witness_root_id": _digest(
            campaign_state.get("arm_witness_root_id"), label="arm_witness_root_id"
        ),
        "allocation_id": allocation_id,
        "ordinal": _integer(allocation.get("ordinal"), label="ordinal"),
        "wave": _integer(allocation.get("wave"), label="wave"),
        "slot": _integer(allocation.get("slot"), label="slot"),
        "logical_attempt_id": _token(
            allocation.get("logical_attempt_id"), label="logical_attempt_id"
        ),
        "child_attempt_id": child_attempt_id(campaign_id, allocation_id),
        "logical_claim_content_sha256": _digest(
            allocation.get("logical_claim_content_sha256"),
            label="logical_claim_content_sha256",
        ),
        "base_sandbox_arm_claim_sha256": _digest(
            allocation.get("sandbox_arm_claim_sha256"),
            label="base_sandbox_arm_claim_sha256",
        ),
        "bundle_manifest_sha256": _digest(
            allocation.get("bundle_manifest_sha256"), label="bundle_manifest_sha256"
        ),
        "bundle_tree_sha256": _digest(
            allocation.get("bundle_tree_sha256"), label="bundle_tree_sha256"
        ),
        "bundle_task_spec_sha256": _digest(
            allocation.get("bundle_task_spec_sha256"), label="bundle_task_spec_sha256"
        ),
        "runtime_bundle_sha256": _digest(
            allocation.get("runtime_bundle_sha256"), label="runtime_bundle_sha256"
        ),
        "worker_source_sha256": _digest(
            allocation.get("worker_source_sha256"), label="worker_source_sha256"
        ),
        "snapshot_manifest_sha256": _digest(
            snapshot_manifest_sha256, label="snapshot_manifest_sha256"
        ),
        "snapshot_tree_sha256": _digest(snapshot_tree_sha256, label="snapshot_tree_sha256"),
        "container_names": deterministic_parent_container_names(campaign_id, allocation_id),
        "normalized_command_templates": templates,
        "command_template_sha256s": command_digests,
        "normalized_policy_identity_sha256": _digest(
            allocation.get("normalized_policy_identity_sha256"),
            label="normalized_policy_identity_sha256",
        ),
        "authority": DEVELOPMENT_AUTHORITY,
        **dict(FALSE_AUTHORITY_FLAGS),
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_child_claim_template(
    value: object,
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
    allocation: Mapping[str, Any],
) -> dict[str, Any]:
    raw = _exact(value, _TEMPLATE_FIELDS, label="child claim template")
    content = {field: raw[field] for field in _TEMPLATE_CONTENT_FIELDS}
    digest = _digest(raw["content_sha256"], label="child claim template.content_sha256")
    if canonical_sha256(content) != digest or dict(raw) != {**content, "content_sha256": digest}:
        raise ParentArmClaimError("child claim template content hash mismatch")
    if raw["schema"] != CHILD_CLAIM_TEMPLATE_SCHEMA:
        raise ParentArmClaimError("child claim template schema mismatch")
    _closed(raw, label="child claim template")
    rebuilt = build_child_claim_template(
        plan,
        campaign_state,
        allocation,
        snapshot_manifest_sha256=raw["snapshot_manifest_sha256"],
        snapshot_tree_sha256=raw["snapshot_tree_sha256"],
        normalized_command_templates=raw["normalized_command_templates"],
    )
    if dict(raw) != rebuilt:
        raise ParentArmClaimError("child claim template differs from campaign allocation")
    return dict(raw)


def build_parent_bound_child_claim(
    template: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
) -> dict[str, Any]:
    wave = _integer(template.get("wave"), label="template.wave")
    wave_events = campaign_state.get("wave_start_event_sha256s")
    wave_runtime = campaign_state.get("wave_runtime_verification_sha256s")
    if not isinstance(wave_events, Mapping) or not isinstance(wave_runtime, Mapping):
        raise ParentArmClaimError("campaign state lacks wave authorization evidence")
    claim = {
        "schema": PARENT_BOUND_CHILD_CLAIM_SCHEMA,
        "scope": "parent_bound_campaign_arm",
        "campaign_id": _digest(template.get("campaign_id"), label="campaign_id"),
        "campaign_authority_id": _digest(
            template.get("campaign_authority_id"), label="campaign_authority_id"
        ),
        "campaign_root_id": _digest(template.get("campaign_root_id"), label="campaign_root_id"),
        "arm_witness_authority_id": _digest(
            template.get("arm_witness_authority_id"), label="arm_witness_authority_id"
        ),
        "arm_witness_root_id": _digest(
            template.get("arm_witness_root_id"), label="arm_witness_root_id"
        ),
        "plan_sha256": _digest(template.get("plan_sha256"), label="plan_sha256"),
        "runner_binding_content_sha256": _digest(
            template.get("runner_binding_content_sha256"), label="runner_binding_content_sha256"
        ),
        "parent_claim_event_sha256": _digest(
            template.get("parent_claim_event_sha256"), label="parent_claim_event_sha256"
        ),
        "prepared_manifest_sha256": _digest(
            campaign_state.get("prepared_manifest_sha256"), label="prepared_manifest_sha256"
        ),
        "parent_prepare_event_sha256": _digest(
            campaign_state.get("prepare_event_sha256"), label="parent_prepare_event_sha256"
        ),
        "parent_start_evidence_sha256": _digest(
            campaign_state.get("start_evidence_sha256"), label="parent_start_evidence_sha256"
        ),
        "parent_start_event_sha256": _digest(
            campaign_state.get("start_event_sha256"), label="parent_start_event_sha256"
        ),
        "parent_wave_start_event_sha256": _digest(
            wave_events.get(str(wave)), label="parent_wave_start_event_sha256"
        ),
        "wave_runtime_verification_sha256": _digest(
            wave_runtime.get(str(wave)), label="wave_runtime_verification_sha256"
        ),
        "allocation_id": _token(template.get("allocation_id"), label="allocation_id"),
        "ordinal": _integer(template.get("ordinal"), label="ordinal"),
        "wave": wave,
        "slot": _integer(template.get("slot"), label="slot"),
        "logical_attempt_id": _token(
            template.get("logical_attempt_id"), label="logical_attempt_id"
        ),
        "child_attempt_id": _digest(template.get("child_attempt_id"), label="child_attempt_id"),
        "prepared_allocation_content_sha256": _digest(
            template.get("content_sha256"), label="prepared_allocation_content_sha256"
        ),
        "child_claim_template_sha256": _digest(
            template.get("content_sha256"), label="child_claim_template_sha256"
        ),
        "base_sandbox_arm_claim_sha256": _digest(
            template.get("base_sandbox_arm_claim_sha256"),
            label="base_sandbox_arm_claim_sha256",
        ),
        "normalized_policy_identity_sha256": _digest(
            template.get("normalized_policy_identity_sha256"),
            label="normalized_policy_identity_sha256",
        ),
        "authority": DEVELOPMENT_AUTHORITY,
        **dict(FALSE_AUTHORITY_FLAGS),
    }
    _exact(claim, _BOUND_FIELDS, label="parent-bound child claim")
    return claim


def validate_parent_bound_child_claim(
    value: object,
    template: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
) -> dict[str, Any]:
    raw = _exact(value, _BOUND_FIELDS, label="parent-bound child claim")
    if raw["schema"] != PARENT_BOUND_CHILD_CLAIM_SCHEMA:
        raise ParentArmClaimError("parent-bound child claim schema mismatch")
    _closed(raw, label="parent-bound child claim")
    expected = build_parent_bound_child_claim(template, campaign_state)
    if dict(raw) != expected:
        raise ParentArmClaimError("parent-bound child claim differs from durable parent events")
    return dict(raw)


def parent_bound_child_claim_sha256(value: Mapping[str, Any]) -> str:
    _exact(value, _BOUND_FIELDS, label="parent-bound child claim")
    return canonical_sha256(value)


def parent_child_campaign_sha256(campaign_id: str, allocation_id: str) -> str:
    return canonical_sha256(
        {
            "schema": PARENT_CHILD_CAMPAIGN_SCHEMA,
            "campaign_id": _digest(campaign_id, label="campaign_id"),
            "allocation_id": _token(allocation_id, label="allocation_id"),
        }
    )


__all__ = [
    "CHILD_CLAIM_TEMPLATE_SCHEMA",
    "COMMAND_PLACEHOLDERS",
    "PARENT_BOUND_CHILD_CLAIM_SCHEMA",
    "PARENT_CHILD_CAMPAIGN_SCHEMA",
    "ParentArmClaimError",
    "build_child_claim_template",
    "build_parent_bound_child_claim",
    "child_attempt_id",
    "deterministic_parent_container_names",
    "parent_bound_child_claim_sha256",
    "parent_child_campaign_sha256",
    "validate_child_claim_template",
    "validate_parent_bound_child_claim",
]
