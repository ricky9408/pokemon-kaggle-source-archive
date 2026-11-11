"""Pure identity and claim bindings for one development-only v4.2 arm.

This module validates the complete container-arm task before deriving any
identity.  It intentionally has no filesystem, clock, subprocess, Docker, or
network surface.
"""

from __future__ import annotations

from collections.abc import Mapping
import math
import re
from types import MappingProxyType
from typing import Any

from .sandbox_protocol import canonical_sha256


ARM_CAMPAIGN_SCHEMA = "evaluation_v4_2_development_single_arm_campaign_v2"
TASK_SCHEMA = "evaluation_v4_2_container_arm_task_v1"
AUTHORITY = "DEVELOPMENT_ONLY"
PARENT_GATE_STATEMENT = (
    "Gate mode requires a separate parent campaign claim covering the complete "
    "execution plan, durably STARTED before any child arm launches, with child "
    "arm identities reserved in PREPARED."
)
FALSE_AUTHORITY_FLAGS = MappingProxyType(
    {
        "external_authority": False,
        "remote_attestation_verified": False,
        "native_platform_verified": False,
        "latency_parity_allowed": False,
        "latency_metrics_admissible": False,
        "randomization_allowed": False,
        "submit_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "candidate_level_authority": False,
        "panel_authority": False,
    }
)

_TASK_FIELDS = frozenset(
    {
        "schema",
        "policy_label",
        "policy_archive_sha256",
        "policy_policy_content_sha256",
        "policy_main_sha256",
        "policy_deck_sha256",
        "opponent_id",
        "opponent_archive_sha256",
        "opponent_policy_content_sha256",
        "opponent_main_sha256",
        "opponent_deck_sha256",
        "engine_id",
        "engine_binary_sha256",
        "engine_runtime_tree_sha256",
        "seed",
        "seat",
        "max_steps",
        "max_action_seconds",
    }
)
_POLICY_LABELS = frozenset({"candidate", "baseline"})
_SEATS = frozenset({"policy_first", "policy_second"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_FIELDS = frozenset(
    {
        "policy_archive_sha256",
        "policy_policy_content_sha256",
        "policy_main_sha256",
        "policy_deck_sha256",
        "opponent_archive_sha256",
        "opponent_policy_content_sha256",
        "opponent_main_sha256",
        "opponent_deck_sha256",
        "engine_binary_sha256",
        "engine_runtime_tree_sha256",
    }
)


class SandboxBindingError(ValueError):
    """A single-arm task, identity, or claim binding is malformed."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value, key=repr) if isinstance(value, Mapping) else type(value).__name__
        raise SandboxBindingError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SandboxBindingError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SandboxBindingError(f"{label} must be a non-empty trimmed string")
    return value


def _validate_task(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _TASK_FIELDS, label="task")
    if raw["schema"] != TASK_SCHEMA:
        raise SandboxBindingError(f"task schema must be {TASK_SCHEMA!r}")
    if not isinstance(raw["policy_label"], str) or raw["policy_label"] not in _POLICY_LABELS:
        raise SandboxBindingError("task policy_label must be candidate or baseline")
    if not isinstance(raw["seat"], str) or raw["seat"] not in _SEATS:
        raise SandboxBindingError("task seat must be policy_first or policy_second")
    for field in _DIGEST_FIELDS:
        _digest(raw[field], label=f"task {field}")
    _identifier(raw["opponent_id"], label="task opponent_id")
    _identifier(raw["engine_id"], label="task engine_id")
    seed = raw["seed"]
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**63:
        raise SandboxBindingError("task seed must be a non-negative signed-63-bit integer")
    max_steps = raw["max_steps"]
    if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps <= 0:
        raise SandboxBindingError("task max_steps must be a positive integer")
    max_action_seconds = raw["max_action_seconds"]
    if (
        not isinstance(max_action_seconds, float)
        or not math.isfinite(max_action_seconds)
        or max_action_seconds <= 0.0
    ):
        raise SandboxBindingError("task max_action_seconds must be a positive finite float")
    return dict(raw)


def _require_bundle_manifest(value: object) -> str:
    return _digest(value, label="bundle_manifest_sha256")


def policy_identity_sha256(task: Mapping[str, Any], prefix: str = "policy") -> str:
    """Hash policy content identity, independent of archive packaging and label."""

    normalized = _validate_task(task)
    if prefix not in {"policy", "opponent"}:
        raise SandboxBindingError("policy identity prefix is invalid")
    content = {
        "schema": "evaluation_v4_2_normalized_policy_identity_v1",
        "policy_content_sha256": _digest(
            normalized[f"{prefix}_policy_content_sha256"],
            label=f"{prefix}_policy_content_sha256",
        ),
        "main_sha256": _digest(
            normalized[f"{prefix}_main_sha256"], label=f"{prefix}_main_sha256"
        ),
        "deck_sha256": _digest(
            normalized[f"{prefix}_deck_sha256"], label=f"{prefix}_deck_sha256"
        ),
    }
    return canonical_sha256(content)


def build_arm_campaign(task: Mapping[str, Any], bundle_manifest_sha256: str) -> dict[str, Any]:
    """Build the identity of one development-only arm."""

    normalized = _validate_task(task)
    _require_bundle_manifest(bundle_manifest_sha256)
    identity = {
        "candidate_policy_identity_sha256": policy_identity_sha256(normalized, "policy"),
        "opponent_policy_identity_sha256": policy_identity_sha256(normalized, "opponent"),
        "engine_binary_sha256": normalized["engine_binary_sha256"],
        "engine_runtime_tree_sha256": normalized["engine_runtime_tree_sha256"],
        "seed": normalized["seed"],
        "seat": normalized["seat"],
        "max_steps": normalized["max_steps"],
        "max_action_seconds": normalized["max_action_seconds"],
    }
    return {
        "schema": ARM_CAMPAIGN_SCHEMA,
        "scope": "single_arm",
        "authority": AUTHORITY,
        "arm_identity": identity,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": PARENT_GATE_STATEMENT,
        "bundle_manifest_bound_in_claim": True,
        **FALSE_AUTHORITY_FLAGS,
    }


def arm_campaign_sha256(task: Mapping[str, Any], bundle_manifest_sha256: str) -> str:
    return canonical_sha256(build_arm_campaign(task, bundle_manifest_sha256))


def build_arm_claim(task: Mapping[str, Any], bundle_manifest_sha256: str) -> dict[str, Any]:
    """Build the canonical journal claim for one development-only arm."""

    campaign = build_arm_campaign(task, bundle_manifest_sha256)
    campaign_sha256 = canonical_sha256(campaign)
    content = {
        "schema": "evaluation_v4_2_development_single_arm_claim_v2",
        "scope": "single_arm",
        "campaign_sha256": campaign_sha256,
        "arm_campaign": campaign,
        "bundle_manifest_sha256": _require_bundle_manifest(bundle_manifest_sha256),
        "panel_parent_claim_verified": False,
        "authority": AUTHORITY,
        **FALSE_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}
