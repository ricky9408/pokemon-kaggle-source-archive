"""Pure, fail-closed campaign contract for the v4.2 three-sandbox runner.

The logical execution plan remains the sole source of the 1,536 evaluation
arms.  This module binds those logical arms to exact input bundles and to the
separate referee/candidate/opponent sandbox runner.  It deliberately performs
no filesystem, clock, process, container, or network work.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import math
from numbers import Real
import re
from typing import Any

from .analysis_contract import validate_analysis_contract
from .execution_plan import arm_protocol_id, validate_execution_plan
from .sandbox_protocol import (
    MAX_AGGREGATE_OUTPUT_BYTES,
    MAX_FRAME_SIZE,
    MAX_PAYLOAD_SIZE,
    MAX_STDERR_BYTES,
    sandbox_execution_spec,
    validate_sandbox_execution_spec,
)

from .sandbox_binding import build_arm_claim, canonical_sha256, policy_identity_sha256


RUNNER_BINDING_SCHEMA = "evaluation_v4_2_three_sandbox_runner_binding_v2"
CAMPAIGN_PLAN_SCHEMA = "evaluation_v4_2_three_sandbox_campaign_plan_v1"
ALLOCATION_SCHEMA = "evaluation_v4_2_three_sandbox_campaign_allocation_v1"
BUNDLE_MANIFEST_SCHEMA = "evaluation_v4_2_container_input_bundle_v1"
TASK_SCHEMA = "evaluation_v4_2_container_arm_task_v1"

DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
STATE_FROZEN = "FROZEN"
REQUIRED_PLATFORM = "linux/amd64"
REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CANONICAL_WAVES_V1 = "canonical_waves_v1"
FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY = "finish_started_wave_then_veto_no_retry"
LEGACY_CONTAINER_PROTOCOL_EXECUTION_ALLOWED = False
SANDBOX_ROLES = ("referee", "candidate_policy", "opponent_policy")
CODE_MANIFEST_KEYS = frozenset(
    {
        "parent_executor",
        "arm_runner",
        "analysis_contract",
        "campaign_protocol",
        "campaign_journal",
        "campaign_preparation",
        "campaign_runtime",
        "campaign_composer",
        "parent_arm_claim",
        "witness_journal",
        "sandbox_protocol",
        "sandbox_binding",
        "sandbox_worker_source",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[^\s@]+@sha256:([0-9a-f]{64})$")
_RUNNER_BUILD_FIELDS = frozenset(
    {
        "parent_runner_sha256",
        "arm_runner_sha256",
        "journal_sha256",
        "sandbox_protocol_sha256",
        "composer_sha256",
        "code_manifest",
        "python_executable_sha256",
        "python_executable_path_sha256",
        "python_version_sha256",
        "python_platform_sha256",
        "docker_cli_sha256",
        "docker_cli_path_sha256",
        "docker_version_sha256",
        "oci_image",
        "image_digest_sha256",
        "image_manifest_raw_sha256",
        "image_config_sha256",
        "image_layer_sha256s",
        "arm_deadline_seconds",
        "action_deadline_seconds",
        "docker_call_timeout_seconds",
        "scheduler_width",
    }
)
_RUNNER_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "sandbox_execution_spec",
        "sandbox_execution_spec_sha256",
        "parent_runner_sha256",
        "arm_runner_sha256",
        "journal_sha256",
        "sandbox_protocol_sha256",
        "composer_sha256",
        "code_manifest",
        "python_executable_sha256",
        "python_executable_path_sha256",
        "python_version_sha256",
        "python_platform_sha256",
        "docker_cli_sha256",
        "docker_cli_path_sha256",
        "docker_version_sha256",
        "oci_image",
        "image_digest_sha256",
        "image_manifest_media_type",
        "image_manifest_raw_sha256",
        "image_config_sha256",
        "image_layer_sha256s",
        "platform",
        "role_command_templates",
        "role_mount_contracts",
        "role_environment",
        "container_runtime_contract",
        "resource_caps",
        "deadline_caps",
        "frame_caps",
        "stdout_limit_bytes",
        "stderr_limit_bytes",
        "scheduler_width",
        "scheduler_policy",
        "failure_policy",
        "authority",
        "scientific_authority",
        "external_authority",
        "anchor_allowed",
        "outcome_usable",
        "outcome_use_authorized",
        "submission_authorized",
        "production_submission_authorized",
        "submit_authorized",
        "state",
    }
)
_RUNNER_FIELDS = _RUNNER_CONTENT_FIELDS | {"content_sha256"}
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
_BUNDLE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "task",
        "task_spec_sha256",
        "bundle_tree_sha256",
        "runtime_bundle_sha256",
        "worker_source_sha256",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_BUNDLE_FIELDS = _BUNDLE_CONTENT_FIELDS | {"content_sha256"}
_ALLOCATION_FIELDS = frozenset(
    {
        "schema",
        "ordinal",
        "wave",
        "slot",
        "canonical_arm_id",
        "logical_attempt_id",
        "logical_claim_content_sha256",
        "logical_container_protocol_sha256",
        "logical_task_spec_sha256",
        "bundle_manifest_sha256",
        "bundle_tree_sha256",
        "bundle_task_spec_sha256",
        "runtime_bundle_sha256",
        "worker_source_sha256",
        "bundle_manifest",
        "task",
        "sandbox_arm_claim_sha256",
        "normalized_policy_identity_sha256",
        "allocation_id",
    }
)
_CAMPAIGN_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "logical_execution_plan_content_sha256",
        "logical_execution_plan",
        "legacy_container_protocol_execution_allowed",
        "runner_binding_content_sha256",
        "runner_binding",
        "analysis_contract_content_sha256",
        "analysis_contract",
        "scheduler_width",
        "scheduler_policy",
        "failure_policy",
        "allocations",
        "allocation_set_sha256",
        "allocation_count",
        "candidate_normalized_policy_identity_sha256",
        "baseline_normalized_policy_identity_sha256",
        "authority",
        "scientific_authority",
        "external_authority",
        "anchor_allowed",
        "outcome_usable",
        "outcome_use_authorized",
        "submission_authorized",
        "production_submission_authorized",
        "submit_authorized",
        "state",
    }
)
_CAMPAIGN_FIELDS = _CAMPAIGN_CONTENT_FIELDS | {"content_sha256"}

ROLE_COMMAND_TEMPLATES = {
    "referee": [
        "python",
        "/input/runtime/sandbox_arm.py",
        "referee-worker",
        "--session-id",
        "{session_id}",
        "--arm-claim-sha256",
        "{parent_bound_child_claim_sha256}",
        "--task",
        "/input/task.json",
        "--left-deck",
        "{left_deck_path}",
        "--right-deck",
        "{right_deck_path}",
        "--engine",
        "/input/engine",
    ],
    "candidate_policy": [
        "python",
        "/input/runtime/sandbox_arm.py",
        "policy-worker",
        "--role",
        "candidate_policy",
        "--session-id",
        "{session_id}",
        "--arm-claim-sha256",
        "{parent_bound_child_claim_sha256}",
        "--policy-dir",
        "/input/policy",
    ],
    "opponent_policy": [
        "python",
        "/input/runtime/sandbox_arm.py",
        "policy-worker",
        "--role",
        "opponent_policy",
        "--session-id",
        "{session_id}",
        "--arm-claim-sha256",
        "{parent_bound_child_claim_sha256}",
        "--policy-dir",
        "/input/opponent",
    ],
}
ROLE_MOUNT_CONTRACTS = {
    "referee": [
        {"source_id": "engine", "target": "/input/engine", "read_only": True, "private": True},
        {"source_id": "decks", "target": "/input/decks", "read_only": True, "private": True},
        {"source_id": "task", "target": "/input/task.json", "read_only": True, "private": True},
        {"source_id": "runtime", "target": "/input/runtime", "read_only": True, "private": True},
    ],
    "candidate_policy": [
        {"source_id": "policy", "target": "/input/policy", "read_only": True, "private": True},
        {"source_id": "runtime", "target": "/input/runtime", "read_only": True, "private": True},
    ],
    "opponent_policy": [
        {"source_id": "opponent", "target": "/input/opponent", "read_only": True, "private": True},
        {"source_id": "runtime", "target": "/input/runtime", "read_only": True, "private": True},
    ],
}
SANDBOX_ENVIRONMENT = {
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONPATH": "/input/runtime",
}
ROLE_ENVIRONMENT = {role: dict(SANDBOX_ENVIRONMENT) for role in SANDBOX_ROLES}
RESOURCE_CAPS = {
    "network_mode": "none",
    "read_only_rootfs": True,
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "container_user": "65534:65534",
    "ipc_mode": "private",
    "cpu_limit_millicores": 1000,
    "memory_limit_bytes": 512 * 1024 * 1024,
    "memory_swap_limit_bytes": 512 * 1024 * 1024,
    "pids_limit": 64,
    "tmpfs_target": "/tmp",
    "tmpfs_size_bytes": 64 * 1024 * 1024,
    "tmpfs_options": ["rw", "noexec", "nosuid", "nodev"],
}
CONTAINER_RUNTIME_CONTRACT = {
    "docker_cli": "docker",
    "execution_scope": "exclusive_parent_bound_campaign_arms_only",
    "standalone_execution_admissible": False,
    "pull_policy": "never",
    "interactive": True,
    "tty": False,
    "workdir": "/tmp",
    "container_name_derivation": "sha256_campaign_child_attempt_id_first_32_hex_v1",
    "session_id_derivation": "parent_claim_arm_bound_child_start_sha256_tuple_v1",
    "label_templates": {
        "evaluation_v4_2.role": "{role}",
        "evaluation_v4_2.session_id": "{session_id}",
        "evaluation_v4_2.claim_sha256": "{parent_bound_child_claim_sha256}",
        "evaluation_v4_2.arm_bound_event_sha256": "{arm_bound_event_sha256}",
        "evaluation_v4_2.child_start_event_sha256": "{child_start_event_sha256}",
    },
    "ulimits": [
        {"name": "core", "soft": 0, "hard": 0},
        {"name": "nofile", "soft": 256, "hard": 256},
        {"name": "nproc", "soft": 64, "hard": 64},
    ],
    "tmpfs_mode": 700,
    "tmpfs_uid": 65534,
    "tmpfs_gid": 65534,
}


class CampaignProtocolError(ValueError):
    """A three-sandbox runner binding or campaign plan is unsafe or malformed."""


def _canonical_copy(value: object) -> Any:
    try:
        return json.loads(json.dumps(value, allow_nan=False, ensure_ascii=True, sort_keys=True))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CampaignProtocolError(f"value is not canonical JSON: {exc}") from exc


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise CampaignProtocolError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignProtocolError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _validate_code_manifest(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != CODE_MANIFEST_KEYS:
        raise CampaignProtocolError(
            "code_manifest must contain the exact parent evaluation source set"
        )
    return {
        key: _sha256(value[key], label=f"code_manifest.{key}")
        for key in sorted(CODE_MANIFEST_KEYS)
    }


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(
        character.isspace() for character in value
    ):
        raise CampaignProtocolError(f"{label} must be a non-empty token without whitespace")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CampaignProtocolError(f"{label} must be a positive integer")
    return value


def _positive_float(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not isinstance(value, float):
        raise CampaignProtocolError(f"{label} must be a positive canonical float")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise CampaignProtocolError(f"{label} must be a positive finite float")
    return result


def _false(value: object, *, label: str) -> bool:
    if value is not False:
        raise CampaignProtocolError(f"{label} must be false")
    return False


def _validate_oci(
    *,
    image: object,
    image_digest: object,
    manifest_raw: object,
    config: object,
    layers: object,
) -> dict[str, Any]:
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise CampaignProtocolError("oci_image must be digest-pinned with @sha256:<digest>")
    digest = _sha256(image_digest, label="image_digest_sha256")
    if _IMAGE_RE.fullmatch(image).group(1) != digest:  # type: ignore[union-attr]
        raise CampaignProtocolError("OCI image digest does not match image_digest_sha256")
    raw = _sha256(manifest_raw, label="image_manifest_raw_sha256")
    if raw != digest:
        raise CampaignProtocolError("raw OCI manifest digest must match the image digest")
    if not isinstance(layers, list) or not layers:
        raise CampaignProtocolError("image_layer_sha256s must be a non-empty ordered list")
    checked_layers = [_sha256(item, label=f"image_layer_sha256s[{index}]") for index, item in enumerate(layers)]
    return {
        "oci_image": image,
        "image_digest_sha256": digest,
        "image_manifest_raw_sha256": raw,
        "image_config_sha256": _sha256(config, label="image_config_sha256"),
        "image_layer_sha256s": checked_layers,
    }


def _runner_static_content(
    *,
    sandbox_spec: Mapping[str, Any],
    arm_deadline_seconds: float,
    action_deadline_seconds: float,
    docker_call_timeout_seconds: float,
) -> dict[str, Any]:
    if sandbox_spec["output_limit_bytes"] != MAX_AGGREGATE_OUTPUT_BYTES:
        raise CampaignProtocolError("sandbox execution spec output limit differs from the runner cap")
    if sandbox_spec["stderr_limit_bytes"] != MAX_STDERR_BYTES:
        raise CampaignProtocolError("sandbox execution spec stderr limit differs from the runner cap")
    return {
        "sandbox_execution_spec": _canonical_copy(sandbox_spec),
        "sandbox_execution_spec_sha256": canonical_sha256(sandbox_spec),
        "image_manifest_media_type": REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE,
        "platform": REQUIRED_PLATFORM,
        "role_command_templates": _canonical_copy(ROLE_COMMAND_TEMPLATES),
        "role_mount_contracts": _canonical_copy(ROLE_MOUNT_CONTRACTS),
        "role_environment": _canonical_copy(ROLE_ENVIRONMENT),
        "container_runtime_contract": _canonical_copy(CONTAINER_RUNTIME_CONTRACT),
        "resource_caps": _canonical_copy(RESOURCE_CAPS),
        "deadline_caps": {
            "arm_deadline_seconds": arm_deadline_seconds,
            "arm_deadline_enforcement": "external",
            "action_deadline_seconds": action_deadline_seconds,
            "action_deadline_enforcement": "external",
            "docker_call_timeout_seconds": docker_call_timeout_seconds,
            "docker_call_timeout_enforcement": "host_subprocess_timeout",
        },
        "frame_caps": {
            "max_frame_size": MAX_FRAME_SIZE,
            "max_payload_size": MAX_PAYLOAD_SIZE,
        },
        "stdout_limit_bytes": MAX_AGGREGATE_OUTPUT_BYTES,
        "stderr_limit_bytes": MAX_STDERR_BYTES,
        "scheduler_policy": CANONICAL_WAVES_V1,
        "failure_policy": FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY,
        "authority": DEVELOPMENT_AUTHORITY,
        "scientific_authority": False,
        "external_authority": False,
        "anchor_allowed": False,
        "outcome_usable": False,
        "outcome_use_authorized": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "submit_authorized": False,
        "state": STATE_FROZEN,
    }


def _validate_runner_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _RUNNER_CONTENT_FIELDS, label="runner binding content")
    if raw["schema"] != RUNNER_BINDING_SCHEMA:
        raise CampaignProtocolError(f"runner binding schema must be {RUNNER_BINDING_SCHEMA!r}")
    try:
        spec = validate_sandbox_execution_spec(raw["sandbox_execution_spec"])
    except ValueError as exc:
        raise CampaignProtocolError(f"sandbox execution spec is invalid: {exc}") from exc
    spec_hash = _sha256(raw["sandbox_execution_spec_sha256"], label="sandbox_execution_spec_sha256")
    if spec_hash != canonical_sha256(spec):
        raise CampaignProtocolError("sandbox execution spec hash mismatch")
    arm_deadline = _positive_float(
        raw["deadline_caps"].get("arm_deadline_seconds")
        if isinstance(raw["deadline_caps"], Mapping)
        else None,
        label="deadline_caps.arm_deadline_seconds",
    )
    action_deadline = _positive_float(
        raw["deadline_caps"].get("action_deadline_seconds")
        if isinstance(raw["deadline_caps"], Mapping)
        else None,
        label="deadline_caps.action_deadline_seconds",
    )
    docker_call_timeout = _positive_float(
        raw["deadline_caps"].get("docker_call_timeout_seconds")
        if isinstance(raw["deadline_caps"], Mapping)
        else None,
        label="deadline_caps.docker_call_timeout_seconds",
    )
    if arm_deadline <= action_deadline:
        raise CampaignProtocolError("arm deadline must exceed the action deadline")
    expected_static = _runner_static_content(
        sandbox_spec=spec,
        arm_deadline_seconds=arm_deadline,
        action_deadline_seconds=action_deadline,
        docker_call_timeout_seconds=docker_call_timeout,
    )
    for key, expected in expected_static.items():
        if raw[key] != expected:
            raise CampaignProtocolError(f"runner binding {key} differs from the frozen three-sandbox contract")
    oci = _validate_oci(
        image=raw["oci_image"],
        image_digest=raw["image_digest_sha256"],
        manifest_raw=raw["image_manifest_raw_sha256"],
        config=raw["image_config_sha256"],
        layers=raw["image_layer_sha256s"],
    )
    scheduler_width = _positive_integer(raw["scheduler_width"], label="scheduler_width")
    code_manifest = _validate_code_manifest(raw["code_manifest"])
    legacy_code_bindings = {
        "parent_runner_sha256": "parent_executor",
        "arm_runner_sha256": "arm_runner",
        "journal_sha256": "campaign_journal",
        "sandbox_protocol_sha256": "sandbox_protocol",
        "composer_sha256": "campaign_composer",
    }
    for legacy_field, manifest_field in legacy_code_bindings.items():
        if raw[legacy_field] != code_manifest[manifest_field]:
            raise CampaignProtocolError(
                f"runner binding {legacy_field} differs from code_manifest.{manifest_field}"
            )
    return {
        "schema": RUNNER_BINDING_SCHEMA,
        **expected_static,
        "parent_runner_sha256": _sha256(raw["parent_runner_sha256"], label="parent_runner_sha256"),
        "arm_runner_sha256": _sha256(raw["arm_runner_sha256"], label="arm_runner_sha256"),
        "journal_sha256": _sha256(raw["journal_sha256"], label="journal_sha256"),
        "sandbox_protocol_sha256": _sha256(
            raw["sandbox_protocol_sha256"], label="sandbox_protocol_sha256"
        ),
        "composer_sha256": _sha256(raw["composer_sha256"], label="composer_sha256"),
        "code_manifest": code_manifest,
        "python_executable_sha256": _sha256(
            raw["python_executable_sha256"], label="python_executable_sha256"
        ),
        "python_executable_path_sha256": _sha256(
            raw["python_executable_path_sha256"], label="python_executable_path_sha256"
        ),
        "python_version_sha256": _sha256(
            raw["python_version_sha256"], label="python_version_sha256"
        ),
        "python_platform_sha256": _sha256(
            raw["python_platform_sha256"], label="python_platform_sha256"
        ),
        "docker_cli_sha256": _sha256(raw["docker_cli_sha256"], label="docker_cli_sha256"),
        "docker_cli_path_sha256": _sha256(
            raw["docker_cli_path_sha256"], label="docker_cli_path_sha256"
        ),
        "docker_version_sha256": _sha256(
            raw["docker_version_sha256"], label="docker_version_sha256"
        ),
        **oci,
        "scheduler_width": scheduler_width,
    }


def build_runner_binding(content: Mapping[str, Any]) -> dict[str, Any]:
    """Seal the exact runner surface for the trusted three-sandbox host broker."""

    raw = _exact_fields(content, _RUNNER_BUILD_FIELDS, label="runner binding build input")
    arm_deadline = _positive_float(raw["arm_deadline_seconds"], label="arm_deadline_seconds")
    action_deadline = _positive_float(raw["action_deadline_seconds"], label="action_deadline_seconds")
    docker_call_timeout = _positive_float(
        raw["docker_call_timeout_seconds"], label="docker_call_timeout_seconds"
    )
    if arm_deadline <= action_deadline:
        raise CampaignProtocolError("arm deadline must exceed the action deadline")
    try:
        spec = validate_sandbox_execution_spec(sandbox_execution_spec())
    except ValueError as exc:  # Defensive: the frozen spec must validate itself.
        raise CampaignProtocolError(f"frozen sandbox execution spec is invalid: {exc}") from exc
    oci = _validate_oci(
        image=raw["oci_image"],
        image_digest=raw["image_digest_sha256"],
        manifest_raw=raw["image_manifest_raw_sha256"],
        config=raw["image_config_sha256"],
        layers=raw["image_layer_sha256s"],
    )
    code_manifest = _validate_code_manifest(raw["code_manifest"])
    legacy_code_bindings = {
        "parent_runner_sha256": "parent_executor",
        "arm_runner_sha256": "arm_runner",
        "journal_sha256": "campaign_journal",
        "sandbox_protocol_sha256": "sandbox_protocol",
        "composer_sha256": "campaign_composer",
    }
    for legacy_field, manifest_field in legacy_code_bindings.items():
        if raw[legacy_field] != code_manifest[manifest_field]:
            raise CampaignProtocolError(
                f"runner binding {legacy_field} differs from code_manifest.{manifest_field}"
            )
    normalized = {
        "schema": RUNNER_BINDING_SCHEMA,
        **_runner_static_content(
            sandbox_spec=spec,
            arm_deadline_seconds=arm_deadline,
            action_deadline_seconds=action_deadline,
            docker_call_timeout_seconds=docker_call_timeout,
        ),
        "parent_runner_sha256": _sha256(raw["parent_runner_sha256"], label="parent_runner_sha256"),
        "arm_runner_sha256": _sha256(raw["arm_runner_sha256"], label="arm_runner_sha256"),
        "journal_sha256": _sha256(raw["journal_sha256"], label="journal_sha256"),
        "sandbox_protocol_sha256": _sha256(
            raw["sandbox_protocol_sha256"], label="sandbox_protocol_sha256"
        ),
        "composer_sha256": _sha256(raw["composer_sha256"], label="composer_sha256"),
        "code_manifest": code_manifest,
        "python_executable_sha256": _sha256(
            raw["python_executable_sha256"], label="python_executable_sha256"
        ),
        "python_executable_path_sha256": _sha256(
            raw["python_executable_path_sha256"], label="python_executable_path_sha256"
        ),
        "python_version_sha256": _sha256(
            raw["python_version_sha256"], label="python_version_sha256"
        ),
        "python_platform_sha256": _sha256(
            raw["python_platform_sha256"], label="python_platform_sha256"
        ),
        "docker_cli_sha256": _sha256(raw["docker_cli_sha256"], label="docker_cli_sha256"),
        "docker_cli_path_sha256": _sha256(
            raw["docker_cli_path_sha256"], label="docker_cli_path_sha256"
        ),
        "docker_version_sha256": _sha256(
            raw["docker_version_sha256"], label="docker_version_sha256"
        ),
        **oci,
        "scheduler_width": _positive_integer(raw["scheduler_width"], label="scheduler_width"),
    }
    return validate_runner_binding({**normalized, "content_sha256": canonical_sha256(normalized)})


def validate_runner_binding(value: object) -> dict[str, Any]:
    """Validate an exact, self-hashed three-sandbox runner binding."""

    raw = _exact_fields(value, _RUNNER_FIELDS, label="runner binding")
    content = _validate_runner_content({field: raw[field] for field in _RUNNER_CONTENT_FIELDS})
    digest = _sha256(raw["content_sha256"], label="runner binding content_sha256")
    if digest != canonical_sha256(content):
        raise CampaignProtocolError("runner binding content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise CampaignProtocolError("runner binding is not canonical")
    return expected


def _validate_task(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _TASK_FIELDS, label="bundle task")
    if raw["schema"] != TASK_SCHEMA:
        raise CampaignProtocolError(f"bundle task schema must be {TASK_SCHEMA!r}")
    label = raw["policy_label"]
    if label not in {"candidate", "baseline"}:
        raise CampaignProtocolError("bundle task policy_label must be candidate or baseline")
    seat = raw["seat"]
    if seat not in {"policy_first", "policy_second"}:
        raise CampaignProtocolError("bundle task seat is invalid")
    for field in (
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
    ):
        _sha256(raw[field], label=f"bundle task {field}")
    return {
        "schema": TASK_SCHEMA,
        "policy_label": label,
        "policy_archive_sha256": raw["policy_archive_sha256"],
        "policy_policy_content_sha256": raw["policy_policy_content_sha256"],
        "policy_main_sha256": raw["policy_main_sha256"],
        "policy_deck_sha256": raw["policy_deck_sha256"],
        "opponent_id": _token(raw["opponent_id"], label="bundle task opponent_id"),
        "opponent_archive_sha256": raw["opponent_archive_sha256"],
        "opponent_policy_content_sha256": raw["opponent_policy_content_sha256"],
        "opponent_main_sha256": raw["opponent_main_sha256"],
        "opponent_deck_sha256": raw["opponent_deck_sha256"],
        "engine_id": _token(raw["engine_id"], label="bundle task engine_id"),
        "engine_binary_sha256": raw["engine_binary_sha256"],
        "engine_runtime_tree_sha256": raw["engine_runtime_tree_sha256"],
        "seed": _non_negative_seed(raw["seed"]),
        "seat": seat,
        "max_steps": _positive_integer(raw["max_steps"], label="bundle task max_steps"),
        "max_action_seconds": _positive_float(
            raw["max_action_seconds"], label="bundle task max_action_seconds"
        ),
    }


def _non_negative_seed(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**63:
        raise CampaignProtocolError("bundle task seed must be a non-negative signed-63-bit integer")
    return value


def _validate_bundle_manifest(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _BUNDLE_FIELDS, label="bundle manifest")
    if raw["schema"] != BUNDLE_MANIFEST_SCHEMA:
        raise CampaignProtocolError(f"bundle manifest schema must be {BUNDLE_MANIFEST_SCHEMA!r}")
    task = _validate_task(raw["task"])
    task_digest = _sha256(raw["task_spec_sha256"], label="bundle manifest task_spec_sha256")
    if task_digest != canonical_sha256(task):
        raise CampaignProtocolError("bundle manifest task_spec_sha256 mismatch")
    content = {
        "schema": BUNDLE_MANIFEST_SCHEMA,
        "task": task,
        "task_spec_sha256": task_digest,
        "bundle_tree_sha256": _sha256(raw["bundle_tree_sha256"], label="bundle_tree_sha256"),
        "runtime_bundle_sha256": _sha256(
            raw["runtime_bundle_sha256"], label="runtime_bundle_sha256"
        ),
        "worker_source_sha256": _sha256(
            raw["worker_source_sha256"], label="worker_source_sha256"
        ),
        "authority": raw["authority"],
        "anchor_allowed": _false(raw["anchor_allowed"], label="bundle manifest anchor_allowed"),
        "production_submission_authorized": _false(
            raw["production_submission_authorized"],
            label="bundle manifest production_submission_authorized",
        ),
    }
    if content["authority"] != DEVELOPMENT_AUTHORITY:
        raise CampaignProtocolError("bundle manifest authority must remain DEVELOPMENT_ONLY")
    digest = _sha256(raw["content_sha256"], label="bundle manifest content_sha256")
    if digest != canonical_sha256(content):
        raise CampaignProtocolError("bundle manifest content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise CampaignProtocolError("bundle manifest is not canonical")
    return expected


def _expected_task(plan: Mapping[str, Any], claim: Mapping[str, Any]) -> dict[str, Any]:
    policy = (
        plan["candidate_identity"]
        if claim["policy_label"] == "candidate"
        else plan["baseline_identity"]
    )
    opponents = {item["opponent_id"]: item for item in plan["opponent_roster"]}
    engines = {item["engine_id"]: item for item in plan["engine_roster"]}
    opponent = opponents.get(claim["opponent_id"])
    engine = engines.get(claim["engine_id"])
    if opponent is None or engine is None:
        raise CampaignProtocolError("logical claim names an opponent or engine absent from the logical plan")
    return {
        "schema": TASK_SCHEMA,
        "policy_label": claim["policy_label"],
        "policy_archive_sha256": policy["archive_sha256"],
        "policy_policy_content_sha256": policy["policy_content_sha256"],
        "policy_main_sha256": policy["main_sha256"],
        "policy_deck_sha256": policy["deck_sha256"],
        "opponent_id": opponent["opponent_id"],
        "opponent_archive_sha256": opponent["archive_sha256"],
        "opponent_policy_content_sha256": opponent["policy_content_sha256"],
        "opponent_main_sha256": plan["opponent_main_sha256s"][opponent["opponent_id"]],
        "opponent_deck_sha256": opponent["deck_sha256"],
        "engine_id": engine["engine_id"],
        "engine_binary_sha256": engine["binary_sha256"],
        "engine_runtime_tree_sha256": engine["runtime_tree_sha256"],
        "seed": claim["seed"],
        "seat": claim["seat"],
        "max_steps": claim["max_steps"],
        "max_action_seconds": plan["contrast_protocol"]["max_action_seconds"],
    }


def _validate_runner_against_plan(plan: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    contrast = plan["contrast_protocol"]
    deadlines = binding["deadline_caps"]
    if deadlines["arm_deadline_seconds"] != contrast["worker_timeout_seconds"]:
        raise CampaignProtocolError("runner arm deadline does not match the logical contrast protocol")
    if deadlines["action_deadline_seconds"] != contrast["max_action_seconds"]:
        raise CampaignProtocolError("runner action deadline does not match the logical contrast protocol")
    for protocol in plan["container_protocols"]:
        for field in (
            "oci_image",
            "image_digest_sha256",
            "image_manifest_media_type",
            "image_manifest_raw_sha256",
            "image_config_sha256",
            "image_layer_sha256s",
            "platform",
        ):
            if protocol[field] != binding[field]:
                raise CampaignProtocolError("runner binding OCI identity drifts from the logical plan")
        if protocol["arm_deadline_seconds"] != deadlines["arm_deadline_seconds"]:
            raise CampaignProtocolError("runner binding arm deadline drifts from a logical protocol")
        if protocol["action_deadline_seconds"] != deadlines["action_deadline_seconds"]:
            raise CampaignProtocolError("runner binding action deadline drifts from a logical protocol")


def _allocation_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {field: value[field] for field in _ALLOCATION_FIELDS if field != "allocation_id"}


def _build_allocation(
    *,
    plan: Mapping[str, Any],
    binding: Mapping[str, Any],
    claim: Mapping[str, Any],
    manifest: Mapping[str, Any],
    ordinal: int,
) -> dict[str, Any]:
    task = manifest["task"]
    expected_task = _expected_task(plan, claim)
    if task != expected_task:
        raise CampaignProtocolError("bundle task does not exactly bind its logical claim and plan identities")
    if manifest["content_sha256"] != claim["bundle_manifest_sha256"]:
        raise CampaignProtocolError("bundle manifest hash does not match the logical claim")
    if manifest["task_spec_sha256"] != claim["task_spec_sha256"]:
        raise CampaignProtocolError("bundle task hash does not match the logical claim")
    policy = plan["candidate_identity"] if claim["policy_label"] == "candidate" else plan["baseline_identity"]
    if task["policy_archive_sha256"] != policy["archive_sha256"]:
        raise CampaignProtocolError("bundle task archive bytes do not match the logical policy identity")
    arm_id = arm_protocol_id(
        claim["policy_label"], claim["engine_id"], claim["opponent_id"], claim["seed"], claim["seat"]
    )
    allocation = {
        "schema": ALLOCATION_SCHEMA,
        "ordinal": ordinal,
        "wave": ordinal // binding["scheduler_width"],
        "slot": ordinal % binding["scheduler_width"],
        "canonical_arm_id": arm_id,
        "logical_attempt_id": claim["attempt_id"],
        "logical_claim_content_sha256": claim["content_sha256"],
        "logical_container_protocol_sha256": claim["container_protocol_sha256"],
        "logical_task_spec_sha256": claim["task_spec_sha256"],
        "bundle_manifest_sha256": manifest["content_sha256"],
        "bundle_tree_sha256": manifest["bundle_tree_sha256"],
        "bundle_task_spec_sha256": manifest["task_spec_sha256"],
        "runtime_bundle_sha256": manifest["runtime_bundle_sha256"],
        "worker_source_sha256": manifest["worker_source_sha256"],
        "bundle_manifest": manifest,
        "task": task,
        "sandbox_arm_claim_sha256": canonical_sha256(
            build_arm_claim(task, manifest["content_sha256"])
        ),
        "normalized_policy_identity_sha256": policy_identity_sha256(task),
    }
    return {**allocation, "allocation_id": canonical_sha256(_allocation_identity(allocation))}


def _bundle_manifests_for_plan(
    plan: Mapping[str, Any], bundle_manifests: object
) -> dict[str, dict[str, Any]]:
    if not isinstance(bundle_manifests, Mapping):
        raise CampaignProtocolError("bundle_manifests must be keyed by logical attempt_id")
    expected_ids = [claim["attempt_id"] for claim in plan["claims"]]
    if set(bundle_manifests) != set(expected_ids) or len(bundle_manifests) != len(expected_ids):
        raise CampaignProtocolError("bundle manifests must exactly cover the logical claim attempt_ids")
    normalized: dict[str, dict[str, Any]] = {}
    for attempt_id in expected_ids:
        if attempt_id not in bundle_manifests:
            raise CampaignProtocolError("bundle manifests must exactly cover the logical claim attempt_ids")
        normalized[attempt_id] = _validate_bundle_manifest(bundle_manifests[attempt_id])
    return normalized


def _validate_allocation(
    *,
    value: object,
    plan: Mapping[str, Any],
    binding: Mapping[str, Any],
    claim: Mapping[str, Any],
    ordinal: int,
) -> dict[str, Any]:
    raw = _exact_fields(value, _ALLOCATION_FIELDS, label=f"allocation[{ordinal}]")
    if raw["schema"] != ALLOCATION_SCHEMA:
        raise CampaignProtocolError("allocation schema is invalid")
    manifest = _validate_bundle_manifest(raw["bundle_manifest"])
    expected = _build_allocation(
        plan=plan,
        binding=binding,
        claim=claim,
        manifest=manifest,
        ordinal=ordinal,
    )
    if dict(raw) != expected:
        raise CampaignProtocolError("allocation is not the canonical logical-claim binding")
    return expected


def _validate_campaign_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _CAMPAIGN_CONTENT_FIELDS, label="campaign plan content")
    if raw["schema"] != CAMPAIGN_PLAN_SCHEMA:
        raise CampaignProtocolError(f"campaign plan schema must be {CAMPAIGN_PLAN_SCHEMA!r}")
    try:
        plan = validate_execution_plan(raw["logical_execution_plan"])
    except ValueError as exc:
        raise CampaignProtocolError(f"logical execution plan is invalid: {exc}") from exc
    plan_hash = _sha256(
        raw["logical_execution_plan_content_sha256"], label="logical_execution_plan_content_sha256"
    )
    if plan_hash != plan["content_sha256"]:
        raise CampaignProtocolError("campaign plan logical execution plan hash mismatch")
    if raw["legacy_container_protocol_execution_allowed"] is not LEGACY_CONTAINER_PROTOCOL_EXECUTION_ALLOWED:
        raise CampaignProtocolError("legacy container protocol execution must remain disabled")
    try:
        binding = validate_runner_binding(raw["runner_binding"])
    except ValueError as exc:
        raise CampaignProtocolError(f"runner binding is invalid: {exc}") from exc
    binding_hash = _sha256(raw["runner_binding_content_sha256"], label="runner_binding_content_sha256")
    if binding_hash != binding["content_sha256"]:
        raise CampaignProtocolError("campaign plan runner binding hash mismatch")
    try:
        analysis_contract = validate_analysis_contract(raw["analysis_contract"])
    except ValueError as exc:
        raise CampaignProtocolError(f"analysis contract is invalid: {exc}") from exc
    analysis_hash = _sha256(
        raw["analysis_contract_content_sha256"], label="analysis_contract_content_sha256"
    )
    if analysis_hash != analysis_contract["content_sha256"]:
        raise CampaignProtocolError("campaign plan analysis contract hash mismatch")
    _validate_runner_against_plan(plan, binding)
    if raw["scheduler_width"] != binding["scheduler_width"]:
        raise CampaignProtocolError("campaign scheduler_width differs from the runner binding")
    if raw["scheduler_policy"] != CANONICAL_WAVES_V1:
        raise CampaignProtocolError("campaign scheduler policy must be canonical_waves_v1")
    if raw["failure_policy"] != FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY:
        raise CampaignProtocolError("campaign failure policy must finish started wave then veto without retry")
    if raw["scheduler_policy"] != binding["scheduler_policy"] or raw["failure_policy"] != binding["failure_policy"]:
        raise CampaignProtocolError("campaign scheduler contract differs from the runner binding")
    allocations = raw["allocations"]
    if not isinstance(allocations, list) or len(allocations) != plan["arm_count"]:
        raise CampaignProtocolError("campaign allocations must contain exactly one entry per logical claim")
    checked_allocations = [
        _validate_allocation(
            value=allocation,
            plan=plan,
            binding=binding,
            claim=plan["claims"][index],
            ordinal=index,
        )
        for index, allocation in enumerate(allocations)
    ]
    if checked_allocations != allocations:
        raise CampaignProtocolError("campaign allocations are not canonical")
    if len({item["allocation_id"] for item in checked_allocations}) != len(checked_allocations):
        raise CampaignProtocolError("campaign allocation ids must form a bijection")
    if raw["allocation_set_sha256"] != canonical_sha256(checked_allocations):
        raise CampaignProtocolError("campaign allocation_set_sha256 mismatch")
    if raw["allocation_count"] != len(checked_allocations):
        raise CampaignProtocolError("campaign allocation_count mismatch")
    candidate_identities = {
        item["normalized_policy_identity_sha256"]
        for item in checked_allocations
        if item["task"]["policy_label"] == "candidate"
    }
    baseline_identities = {
        item["normalized_policy_identity_sha256"]
        for item in checked_allocations
        if item["task"]["policy_label"] == "baseline"
    }
    if len(candidate_identities) != 1 or len(baseline_identities) != 1:
        raise CampaignProtocolError("normalized candidate and baseline policy identities must each be unique")
    candidate_identity = next(iter(candidate_identities))
    baseline_identity = next(iter(baseline_identities))
    if raw["candidate_normalized_policy_identity_sha256"] != candidate_identity:
        raise CampaignProtocolError("candidate normalized policy identity mismatch")
    if raw["baseline_normalized_policy_identity_sha256"] != baseline_identity:
        raise CampaignProtocolError("baseline normalized policy identity mismatch")
    if candidate_identity == baseline_identity:
        raise CampaignProtocolError("candidate and baseline normalized policy identities must differ")
    if raw["authority"] != DEVELOPMENT_AUTHORITY:
        raise CampaignProtocolError("campaign authority must remain DEVELOPMENT_ONLY")
    for field in (
        "scientific_authority",
        "external_authority",
        "anchor_allowed",
        "outcome_usable",
        "outcome_use_authorized",
        "submission_authorized",
        "production_submission_authorized",
        "submit_authorized",
    ):
        _false(raw[field], label=f"campaign {field}")
    if raw["state"] != STATE_FROZEN:
        raise CampaignProtocolError("campaign state must be FROZEN")
    return {
        "schema": CAMPAIGN_PLAN_SCHEMA,
        "logical_execution_plan_content_sha256": plan_hash,
        "logical_execution_plan": plan,
        "legacy_container_protocol_execution_allowed": False,
        "runner_binding_content_sha256": binding_hash,
        "runner_binding": binding,
        "analysis_contract_content_sha256": analysis_hash,
        "analysis_contract": analysis_contract,
        "scheduler_width": binding["scheduler_width"],
        "scheduler_policy": CANONICAL_WAVES_V1,
        "failure_policy": FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY,
        "allocations": checked_allocations,
        "allocation_set_sha256": raw["allocation_set_sha256"],
        "allocation_count": len(checked_allocations),
        "candidate_normalized_policy_identity_sha256": candidate_identity,
        "baseline_normalized_policy_identity_sha256": baseline_identity,
        "authority": DEVELOPMENT_AUTHORITY,
        "scientific_authority": False,
        "external_authority": False,
        "anchor_allowed": False,
        "outcome_usable": False,
        "outcome_use_authorized": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "submit_authorized": False,
        "state": STATE_FROZEN,
    }


def build_campaign_plan(
    logical_execution_plan: object,
    bundle_manifests: Mapping[str, object],
    runner_binding: object,
    analysis_contract: object,
) -> dict[str, Any]:
    """Bind every logical claim to its bundle, runner, and frozen analysis."""

    try:
        plan = validate_execution_plan(logical_execution_plan)
    except ValueError as exc:
        raise CampaignProtocolError(f"logical execution plan is invalid: {exc}") from exc
    try:
        binding = validate_runner_binding(runner_binding)
    except ValueError as exc:
        raise CampaignProtocolError(f"runner binding is invalid: {exc}") from exc
    try:
        analysis = validate_analysis_contract(analysis_contract)
    except ValueError as exc:
        raise CampaignProtocolError(f"analysis contract is invalid: {exc}") from exc
    _validate_runner_against_plan(plan, binding)
    manifests = _bundle_manifests_for_plan(plan, bundle_manifests)
    allocations = [
        _build_allocation(
            plan=plan,
            binding=binding,
            claim=claim,
            manifest=manifests[claim["attempt_id"]],
            ordinal=ordinal,
        )
        for ordinal, claim in enumerate(plan["claims"])
    ]
    candidate_identities = {
        item["normalized_policy_identity_sha256"]
        for item in allocations
        if item["task"]["policy_label"] == "candidate"
    }
    baseline_identities = {
        item["normalized_policy_identity_sha256"]
        for item in allocations
        if item["task"]["policy_label"] == "baseline"
    }
    if len(candidate_identities) != 1 or len(baseline_identities) != 1:
        raise CampaignProtocolError("logical plan does not yield one normalized identity per policy")
    content = {
        "schema": CAMPAIGN_PLAN_SCHEMA,
        "logical_execution_plan_content_sha256": plan["content_sha256"],
        "logical_execution_plan": plan,
        "legacy_container_protocol_execution_allowed": False,
        "runner_binding_content_sha256": binding["content_sha256"],
        "runner_binding": binding,
        "analysis_contract_content_sha256": analysis["content_sha256"],
        "analysis_contract": analysis,
        "scheduler_width": binding["scheduler_width"],
        "scheduler_policy": CANONICAL_WAVES_V1,
        "failure_policy": FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY,
        "allocations": allocations,
        "allocation_set_sha256": canonical_sha256(allocations),
        "allocation_count": len(allocations),
        "candidate_normalized_policy_identity_sha256": next(iter(candidate_identities)),
        "baseline_normalized_policy_identity_sha256": next(iter(baseline_identities)),
        "authority": DEVELOPMENT_AUTHORITY,
        "scientific_authority": False,
        "external_authority": False,
        "anchor_allowed": False,
        "outcome_usable": False,
        "outcome_use_authorized": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "submit_authorized": False,
        "state": STATE_FROZEN,
    }
    return validate_campaign_plan({**content, "content_sha256": canonical_sha256(content)})


def validate_campaign_plan(value: object) -> dict[str, Any]:
    """Validate an exact, self-hashed, full-grid three-sandbox campaign plan."""

    raw = _exact_fields(value, _CAMPAIGN_FIELDS, label="campaign plan")
    content = _validate_campaign_content({field: raw[field] for field in _CAMPAIGN_CONTENT_FIELDS})
    digest = _sha256(raw["content_sha256"], label="campaign plan content_sha256")
    if digest != canonical_sha256(content):
        raise CampaignProtocolError("campaign plan content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise CampaignProtocolError("campaign plan is not canonical")
    return expected


compile_runner_binding = build_runner_binding
compile_campaign_plan = build_campaign_plan
build_three_sandbox_runner_binding = build_runner_binding
build_three_sandbox_campaign_plan = build_campaign_plan
validate_three_sandbox_runner_binding = validate_runner_binding
validate_three_sandbox_campaign_plan = validate_campaign_plan


__all__ = [
    "ALLOCATION_SCHEMA",
    "BUNDLE_MANIFEST_SCHEMA",
    "CAMPAIGN_PLAN_SCHEMA",
    "CANONICAL_WAVES_V1",
    "CONTAINER_RUNTIME_CONTRACT",
    "CampaignProtocolError",
    "DEVELOPMENT_AUTHORITY",
    "FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY",
    "LEGACY_CONTAINER_PROTOCOL_EXECUTION_ALLOWED",
    "REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE",
    "REQUIRED_PLATFORM",
    "ROLE_COMMAND_TEMPLATES",
    "ROLE_ENVIRONMENT",
    "ROLE_MOUNT_CONTRACTS",
    "RUNNER_BINDING_SCHEMA",
    "SANDBOX_ENVIRONMENT",
    "SANDBOX_ROLES",
    "STATE_FROZEN",
    "TASK_SCHEMA",
    "build_campaign_plan",
    "build_runner_binding",
    "build_three_sandbox_campaign_plan",
    "build_three_sandbox_runner_binding",
    "compile_campaign_plan",
    "compile_runner_binding",
    "validate_campaign_plan",
    "validate_runner_binding",
    "validate_three_sandbox_campaign_plan",
    "validate_three_sandbox_runner_binding",
]
