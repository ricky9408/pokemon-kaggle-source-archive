"""Exact, outcome-free preparation manifest for a v4.2 parent campaign."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .parent_arm_claim import (
    CHILD_CLAIM_TEMPLATE_SCHEMA,
    ParentArmClaimError,
    build_child_claim_template,
    validate_child_claim_template,
)
from .sandbox_binding import FALSE_AUTHORITY_FLAGS
from .witness_journal import canonical_sha256


PREPARED_ALLOCATION_SCHEMA = CHILD_CLAIM_TEMPLATE_SCHEMA
PREPARED_MANIFEST_SCHEMA = "evaluation_v4_2_campaign_prepared_manifest_v2"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "plan_sha256",
        "runner_binding_content_sha256",
        "parent_claim_event_sha256",
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "allocations",
        "prepared_allocation_count",
        "allocation_set_sha256",
        "authority",
        "root_local_campaign_one_shot",
        *FALSE_AUTHORITY_FLAGS,
    }
)
_MANIFEST_FIELDS = _MANIFEST_CONTENT_FIELDS | {"content_sha256"}


class CampaignPreparationError(ValueError):
    """A prepared campaign is incomplete or differs from its frozen plan."""


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise CampaignPreparationError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignPreparationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CampaignPreparationError(f"{label} must be an integer >= {minimum}")
    return value


def _closed(value: Mapping[str, Any], *, label: str) -> None:
    if value.get("authority") != DEVELOPMENT_AUTHORITY:
        raise CampaignPreparationError(f"{label}.authority must remain DEVELOPMENT_ONLY")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if value.get(field) is not expected:
            raise CampaignPreparationError(f"{label}.{field} must remain false")


def build_prepared_allocation(
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
    allocation: Mapping[str, Any],
    *,
    snapshot_manifest_sha256: str,
    snapshot_tree_sha256: str,
    normalized_command_templates: Mapping[str, list[str]],
) -> dict[str, Any]:
    """Build the exact prepare-time child claim template for one allocation."""

    try:
        return build_child_claim_template(
            plan,
            campaign_state,
            allocation,
            snapshot_manifest_sha256=snapshot_manifest_sha256,
            snapshot_tree_sha256=snapshot_tree_sha256,
            normalized_command_templates=normalized_command_templates,
        )
    except ParentArmClaimError as exc:
        raise CampaignPreparationError(str(exc)) from exc


def validate_prepared_allocation(
    value: object,
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
    allocation: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        return validate_child_claim_template(value, plan, campaign_state, allocation)
    except ParentArmClaimError as exc:
        raise CampaignPreparationError(str(exc)) from exc


def build_campaign_prepared_manifest(
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
    prepared_allocations: list[Mapping[str, Any]],
) -> dict[str, Any]:
    allocations = plan.get("allocations")
    if not isinstance(allocations, list) or len(prepared_allocations) != len(allocations):
        raise CampaignPreparationError("prepared allocations must cover the exact plan")
    checked = [
        validate_prepared_allocation(item, plan, campaign_state, allocation)
        for item, allocation in zip(prepared_allocations, allocations, strict=True)
    ]
    content = {
        "schema": PREPARED_MANIFEST_SCHEMA,
        "campaign_id": _digest(campaign_state.get("campaign_id"), label="campaign_id"),
        "plan_sha256": _digest(plan.get("content_sha256"), label="plan_sha256"),
        "runner_binding_content_sha256": _digest(
            plan.get("runner_binding_content_sha256"), label="runner_binding_content_sha256"
        ),
        "parent_claim_event_sha256": _digest(
            campaign_state.get("claim_event_sha256"), label="parent_claim_event_sha256"
        ),
        "arm_witness_authority_id": _digest(
            campaign_state.get("arm_witness_authority_id"), label="arm_witness_authority_id"
        ),
        "arm_witness_root_id": _digest(
            campaign_state.get("arm_witness_root_id"), label="arm_witness_root_id"
        ),
        "allocations": checked,
        "prepared_allocation_count": len(checked),
        "allocation_set_sha256": canonical_sha256(
            [item["content_sha256"] for item in checked]
        ),
        "authority": DEVELOPMENT_AUTHORITY,
        "root_local_campaign_one_shot": True,
        **dict(FALSE_AUTHORITY_FLAGS),
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_campaign_prepared_manifest(
    value: object,
    plan: Mapping[str, Any],
    campaign_state: Mapping[str, Any],
) -> dict[str, Any]:
    raw = _exact(value, _MANIFEST_FIELDS, label="prepared manifest")
    content = {field: raw[field] for field in _MANIFEST_CONTENT_FIELDS}
    digest = _digest(raw["content_sha256"], label="prepared manifest.content_sha256")
    if canonical_sha256(content) != digest or dict(raw) != {**content, "content_sha256": digest}:
        raise CampaignPreparationError("prepared manifest content hash mismatch")
    if raw["schema"] != PREPARED_MANIFEST_SCHEMA:
        raise CampaignPreparationError("prepared manifest schema mismatch")
    _closed(raw, label="prepared manifest")
    if raw["root_local_campaign_one_shot"] is not True:
        raise CampaignPreparationError("prepared manifest root-local marker must be true")
    allocations = plan.get("allocations")
    if not isinstance(allocations, list) or not isinstance(raw["allocations"], list):
        raise CampaignPreparationError("prepared manifest allocations are invalid")
    count = _integer(raw["prepared_allocation_count"], label="prepared_allocation_count", minimum=1)
    if count != len(allocations) or len(raw["allocations"]) != count:
        raise CampaignPreparationError("prepared manifest does not cover the exact plan")
    checked = [
        validate_prepared_allocation(item, plan, campaign_state, allocation)
        for item, allocation in zip(raw["allocations"], allocations, strict=True)
    ]
    expected = {
        "campaign_id": campaign_state.get("campaign_id"),
        "plan_sha256": plan.get("content_sha256"),
        "runner_binding_content_sha256": plan.get("runner_binding_content_sha256"),
        "parent_claim_event_sha256": campaign_state.get("claim_event_sha256"),
        "arm_witness_authority_id": campaign_state.get("arm_witness_authority_id"),
        "arm_witness_root_id": campaign_state.get("arm_witness_root_id"),
    }
    for field, expected_value in expected.items():
        actual = _digest(raw[field], label=f"prepared manifest.{field}")
        if actual != expected_value:
            raise CampaignPreparationError(f"prepared manifest {field} differs from campaign")
    expected_set = canonical_sha256([item["content_sha256"] for item in checked])
    if raw["allocation_set_sha256"] != expected_set:
        raise CampaignPreparationError("prepared manifest allocation_set_sha256 mismatch")
    return dict(raw)


__all__ = [
    "CampaignPreparationError",
    "PREPARED_ALLOCATION_SCHEMA",
    "PREPARED_MANIFEST_SCHEMA",
    "build_campaign_prepared_manifest",
    "build_prepared_allocation",
    "validate_campaign_prepared_manifest",
    "validate_prepared_allocation",
]
