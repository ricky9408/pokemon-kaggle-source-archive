"""Pure, fail-closed contract for one Linux/amd64 Docker arm.

This module only validates and seals declarative input.  It deliberately has no
Docker, filesystem, clock, network, or subprocess surface.  A sealed protocol
is an execution contract, not an attestation and not an authority to submit.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from numbers import Real
from typing import Any


CONTAINER_PROTOCOL_SCHEMA = "evaluation_v4_2_linux_amd64_docker_per_arm_protocol_v2"
REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
REQUIRED_PLATFORM = "linux/amd64"
REQUIRED_NETWORK_MODE = "none"
REQUIRED_ARM_DEADLINE_ENFORCEMENT = "external_watchdog"
REQUIRED_ACTION_DEADLINE_ENFORCEMENT = "exact_per_action"
REQUIRED_RETRY_POLICY = "none"
REQUIRED_CONTAINER_SCOPE = "one_arm_per_container"
REQUIRED_COMMAND = [
    "python",
    "/input/runtime/container_arm.py",
    "worker",
    "--task",
    "/input/task.json",
]
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
STATE_FROZEN = "FROZEN"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_RE = re.compile(r"^[^\s@]+@sha256:([0-9a-f]{64})$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "arm_id",
        "arm_kind",
        "bundle_manifest_sha256",
        "task_spec_sha256",
        "oci_image",
        "image_digest_sha256",
        "image_manifest_media_type",
        "image_manifest_raw_sha256",
        "image_config_sha256",
        "image_layer_sha256s",
        "platform",
        "network_mode",
        "read_only_rootfs",
        "cap_drop",
        "no_new_privileges",
        "input_mounts",
        "scratch_tmpfs",
        "cpu_limit_millicores",
        "memory_limit_bytes",
        "pids_limit",
        "max_steps",
        "output_limit_bytes",
        "arm_deadline_seconds",
        "arm_deadline_enforcement",
        "action_deadline_seconds",
        "action_deadline_enforcement",
        "retry_policy",
        "container_scope",
        "runtime_sha256",
        "security_sha256",
        "source_sha256",
        "command",
        "authority",
        "research_only",
        "external_authority",
        "submission_authorized",
        "anchor_allowed",
        "production_submission_authorized",
        "state",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_MOUNT_FIELDS = frozenset({"source_id", "source_sha256", "target", "read_only", "private"})
_TMPFS_FIELDS = frozenset({"target", "size_bytes", "read_only", "private"})


class ContainerProtocolError(ValueError):
    """A Docker per-arm protocol is malformed or attempts authority escalation."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical JSON encoding used by protocol self hashes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContainerProtocolError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash a value after canonical JSON serialization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ContainerProtocolError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or any(
        character.isspace() for character in value
    ):
        raise ContainerProtocolError(f"{label} must be a non-empty token without whitespace")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ContainerProtocolError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _positive_integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContainerProtocolError(f"{label} must be a positive integer, not a boolean")
    if value <= 0:
        raise ContainerProtocolError(f"{label} must be positive")
    return value


def _positive_float(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ContainerProtocolError(f"{label} must be a positive finite number")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ContainerProtocolError(f"{label} must be positive and finite")
    if not isinstance(value, float):
        raise ContainerProtocolError(f"{label} must use canonical float form")
    return result


def _true(value: object, *, label: str) -> bool:
    if value is not True:
        raise ContainerProtocolError(f"{label} must be true")
    return True


def _false(value: object, *, label: str) -> bool:
    if value is not False:
        raise ContainerProtocolError(f"{label} must be false")
    return False


def _absolute_target(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or value == "/":
        raise ContainerProtocolError(f"{label} must be a non-root absolute path")
    if value.strip() != value or "//" in value or "/../" in f"{value}/" or value.endswith("/"):
        raise ContainerProtocolError(f"{label} must be a normalized absolute path")
    return value


def _validate_mounts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ContainerProtocolError("input_mounts must be a non-empty list")
    mounts: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        raw = _exact_fields(item, _MOUNT_FIELDS, label=f"input_mounts[{index}]")
        mounts.append(
            {
                "source_id": _identifier(raw["source_id"], label=f"input_mounts[{index}].source_id"),
                "source_sha256": _sha256(
                    raw["source_sha256"], label=f"input_mounts[{index}].source_sha256"
                ),
                "target": _absolute_target(raw["target"], label=f"input_mounts[{index}].target"),
                "read_only": _true(raw["read_only"], label=f"input_mounts[{index}].read_only"),
                "private": _true(raw["private"], label=f"input_mounts[{index}].private"),
            }
        )
    targets = [mount["target"] for mount in mounts]
    if targets != sorted(set(targets)):
        raise ContainerProtocolError("input_mounts must be sorted by unique target")
    return mounts


def _validate_tmpfs(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _TMPFS_FIELDS, label="scratch_tmpfs")
    target = _absolute_target(raw["target"], label="scratch_tmpfs.target")
    if target != "/tmp":
        raise ContainerProtocolError("scratch_tmpfs.target must be '/tmp'")
    return {
        "target": target,
        "size_bytes": _positive_integer(raw["size_bytes"], label="scratch_tmpfs.size_bytes"),
        "read_only": _false(raw["read_only"], label="scratch_tmpfs.read_only"),
        "private": _true(raw["private"], label="scratch_tmpfs.private"),
    }


def _validate_command(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ContainerProtocolError("command must be a non-empty list")
    command: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or item != item.strip():
            raise ContainerProtocolError(f"command[{index}] must be a non-empty trimmed string")
        command.append(item)
    return command


def _validate_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _CONTENT_FIELDS, label="container protocol content")
    if raw["schema"] != CONTAINER_PROTOCOL_SCHEMA:
        raise ContainerProtocolError(f"schema must be {CONTAINER_PROTOCOL_SCHEMA!r}")

    image = raw["oci_image"]
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise ContainerProtocolError("oci_image must be digest-pinned with @sha256:<digest>")
    image_digest = _sha256(raw["image_digest_sha256"], label="image_digest_sha256")
    if _IMAGE_RE.fullmatch(image).group(1) != image_digest:  # type: ignore[union-attr]
        raise ContainerProtocolError("image_digest_sha256 must match the OCI image digest")

    layers = raw["image_layer_sha256s"]
    if not isinstance(layers, list) or not layers:
        raise ContainerProtocolError("image_layer_sha256s must be a non-empty ordered list")
    normalized_layers = [
        _sha256(value, label=f"image_layer_sha256s[{index}]")
        for index, value in enumerate(layers)
    ]
    normalized = {
        "schema": CONTAINER_PROTOCOL_SCHEMA,
        "arm_id": _identifier(raw["arm_id"], label="arm_id"),
        "arm_kind": _identifier(raw["arm_kind"], label="arm_kind"),
        "bundle_manifest_sha256": _sha256(
            raw["bundle_manifest_sha256"], label="bundle_manifest_sha256"
        ),
        "task_spec_sha256": _sha256(raw["task_spec_sha256"], label="task_spec_sha256"),
        "oci_image": image,
        "image_digest_sha256": image_digest,
        "image_manifest_media_type": raw["image_manifest_media_type"],
        "image_manifest_raw_sha256": _sha256(
            raw["image_manifest_raw_sha256"], label="image_manifest_raw_sha256"
        ),
        "image_config_sha256": _sha256(
            raw["image_config_sha256"], label="image_config_sha256"
        ),
        "image_layer_sha256s": normalized_layers,
        "platform": raw["platform"],
        "network_mode": raw["network_mode"],
        "read_only_rootfs": _true(raw["read_only_rootfs"], label="read_only_rootfs"),
        "cap_drop": raw["cap_drop"],
        "no_new_privileges": _true(raw["no_new_privileges"], label="no_new_privileges"),
        "input_mounts": _validate_mounts(raw["input_mounts"]),
        "scratch_tmpfs": _validate_tmpfs(raw["scratch_tmpfs"]),
        "cpu_limit_millicores": _positive_integer(
            raw["cpu_limit_millicores"], label="cpu_limit_millicores"
        ),
        "memory_limit_bytes": _positive_integer(
            raw["memory_limit_bytes"], label="memory_limit_bytes"
        ),
        "pids_limit": _positive_integer(raw["pids_limit"], label="pids_limit"),
        "max_steps": _positive_integer(raw["max_steps"], label="max_steps"),
        "output_limit_bytes": _positive_integer(
            raw["output_limit_bytes"], label="output_limit_bytes"
        ),
        "arm_deadline_seconds": _positive_float(
            raw["arm_deadline_seconds"], label="arm_deadline_seconds"
        ),
        "arm_deadline_enforcement": raw["arm_deadline_enforcement"],
        "action_deadline_seconds": _positive_float(
            raw["action_deadline_seconds"], label="action_deadline_seconds"
        ),
        "action_deadline_enforcement": raw["action_deadline_enforcement"],
        "retry_policy": raw["retry_policy"],
        "container_scope": raw["container_scope"],
        "runtime_sha256": _sha256(raw["runtime_sha256"], label="runtime_sha256"),
        "security_sha256": _sha256(raw["security_sha256"], label="security_sha256"),
        "source_sha256": _sha256(raw["source_sha256"], label="source_sha256"),
        "command": _validate_command(raw["command"]),
        "authority": raw["authority"],
        "research_only": _true(raw["research_only"], label="research_only"),
        "external_authority": _false(raw["external_authority"], label="external_authority"),
        "submission_authorized": _false(
            raw["submission_authorized"], label="submission_authorized"
        ),
        "anchor_allowed": _false(raw["anchor_allowed"], label="anchor_allowed"),
        "production_submission_authorized": _false(
            raw["production_submission_authorized"],
            label="production_submission_authorized",
        ),
        "state": raw["state"],
    }

    if normalized["image_manifest_media_type"] != REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE:
        raise ContainerProtocolError(
            f"image manifest media type must be {REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE!r}"
        )
    if normalized["image_manifest_raw_sha256"] != image_digest:
        raise ContainerProtocolError("raw image manifest digest must match the pinned OCI digest")
    if normalized["platform"] != REQUIRED_PLATFORM:
        raise ContainerProtocolError(f"platform must be {REQUIRED_PLATFORM!r}")
    if normalized["network_mode"] != REQUIRED_NETWORK_MODE:
        raise ContainerProtocolError(f"network_mode must be {REQUIRED_NETWORK_MODE!r}")
    if normalized["cap_drop"] != ["ALL"]:
        raise ContainerProtocolError("cap_drop must be exactly ['ALL']")
    if not isinstance(normalized["cap_drop"], list) or any(
        not isinstance(item, str) for item in normalized["cap_drop"]
    ):
        raise ContainerProtocolError("cap_drop must be a list of strings")
    if normalized["arm_deadline_enforcement"] != REQUIRED_ARM_DEADLINE_ENFORCEMENT:
        raise ContainerProtocolError("arm deadline must be externally enforced")
    if normalized["action_deadline_enforcement"] != REQUIRED_ACTION_DEADLINE_ENFORCEMENT:
        raise ContainerProtocolError("action deadline must be exact per-action")
    if normalized["arm_deadline_seconds"] <= normalized["action_deadline_seconds"]:
        raise ContainerProtocolError("arm deadline must exceed the per-action deadline")
    if normalized["retry_policy"] != REQUIRED_RETRY_POLICY:
        raise ContainerProtocolError("retry_policy must be 'none'")
    if normalized["container_scope"] != REQUIRED_CONTAINER_SCOPE:
        raise ContainerProtocolError("container_scope must be one_arm_per_container")
    if normalized["command"] != REQUIRED_COMMAND:
        raise ContainerProtocolError(f"command must exactly be {REQUIRED_COMMAND!r}")
    if normalized["authority"] != DEVELOPMENT_AUTHORITY:
        raise ContainerProtocolError("authority must remain DEVELOPMENT_ONLY")
    if normalized["state"] != STATE_FROZEN:
        raise ContainerProtocolError("state must be FROZEN")
    return normalized


def validate_container_protocol(value: object) -> dict[str, Any]:
    """Validate an exact, canonical, self-hash-checked protocol."""

    raw = _exact_fields(value, _FIELDS, label="container protocol")
    content = _validate_content({field: raw[field] for field in _CONTENT_FIELDS})
    digest = _sha256(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(content):
        raise ContainerProtocolError("container protocol content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise ContainerProtocolError("container protocol is not canonical")
    return expected


def compile_container_protocol(content: Mapping[str, Any]) -> dict[str, Any]:
    """Compile hash-free exact content into a sealed execution protocol."""

    if not isinstance(content, Mapping):
        raise ContainerProtocolError("container protocol content must be a mapping")
    if "content_sha256" in content:
        raise ContainerProtocolError("compiler accepts hash-free container protocol content")
    normalized = _validate_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


# Keep naming discoverable for callers that use either build or Docker-specific
# terminology; all aliases share one wire format and one validation path.
build_container_protocol = compile_container_protocol
compile_docker_per_arm_protocol = compile_container_protocol
build_docker_per_arm_protocol = compile_container_protocol
validate_docker_per_arm_protocol = validate_container_protocol


__all__ = [
    "CONTAINER_PROTOCOL_SCHEMA",
    "DEVELOPMENT_AUTHORITY",
    "REQUIRED_ACTION_DEADLINE_ENFORCEMENT",
    "REQUIRED_ARM_DEADLINE_ENFORCEMENT",
    "REQUIRED_CONTAINER_SCOPE",
    "REQUIRED_COMMAND",
    "REQUIRED_IMAGE_MANIFEST_MEDIA_TYPE",
    "REQUIRED_NETWORK_MODE",
    "REQUIRED_PLATFORM",
    "REQUIRED_RETRY_POLICY",
    "STATE_FROZEN",
    "ContainerProtocolError",
    "build_container_protocol",
    "build_docker_per_arm_protocol",
    "canonical_json_bytes",
    "canonical_sha256",
    "compile_container_protocol",
    "compile_docker_per_arm_protocol",
    "validate_container_protocol",
    "validate_docker_per_arm_protocol",
]
