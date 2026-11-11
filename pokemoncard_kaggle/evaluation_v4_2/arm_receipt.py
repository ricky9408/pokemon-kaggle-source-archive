"""Strict one-shot claim and receipt schemas for v4.2 container arms.

These receipts make accidental retries, row substitution, and silent runtime
changes detectable.  They are evidence under a trusted-host Docker model, not
cryptographic remote attestation and never grant submission authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import math
from numbers import Real
import re
from typing import Any, Mapping

from .simulation_design import canonical_sha256


ATTEMPT_CLAIM_SCHEMA = "evaluation_v4_2_container_arm_claim_v1"
ARM_RECEIPT_SCHEMA = "evaluation_v4_2_container_arm_receipt_v1"
WORKER_RESULT_SCHEMA = "evaluation_v4_2_container_worker_result_v1"
CONTAINER_AUTHORITY = "LOCAL_DOCKER_EXECUTION_EVIDENCE_ONLY"
MAX_ATTEMPTS = 1
RETRY_ORDINAL = 0
POLICY_LABELS = frozenset({"candidate", "baseline"})
SEATS = frozenset({"policy_first", "policy_second"})
TERMINAL_STATUSES = frozenset(
    {"SUCCESS", "FAILURE", "TIMEOUT", "OUTPUT_LIMIT", "OOM_KILLED"}
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

_CLAIM_BASE_FIELDS = frozenset(
    {
        "schema",
        "execution_design_sha256",
        "container_protocol_sha256",
        "bundle_manifest_sha256",
        "task_spec_sha256",
        "template_content_sha256",
        "contrast_protocol_sha256",
        "candidate_archive_sha256",
        "baseline_archive_sha256",
        "policy_label",
        "policy_archive_sha256",
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
        "max_attempts",
        "retry_ordinal",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_CLAIM_CONTENT_FIELDS = _CLAIM_BASE_FIELDS | frozenset({"task_key", "attempt_id"})
_CLAIM_FIELDS = _CLAIM_CONTENT_FIELDS | frozenset({"content_sha256"})

_WORKER_RESULT_FIELDS = frozenset(
    {
        "schema",
        "policy_label",
        "opponent_id",
        "seed",
        "seat",
        "policy_left",
        "outcome",
        "winner",
        "steps",
        "max_policy_action_seconds",
        "max_opponent_action_seconds",
        "transcript_sha256",
        "error",
    }
)

_RECEIPT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "claim_content_sha256",
        "attempt_id",
        "container_protocol_sha256",
        "image_manifest_sha256",
        "image_config_sha256",
        "container_id",
        "observed_container_spec_sha256",
        "docker_daemon_fingerprint_sha256",
        "docker_inspect_sha256",
        "input_bundle_sha256",
        "runtime_bundle_sha256",
        "launcher_source_sha256",
        "command_sha256",
        "started_at_utc",
        "finished_at_utc",
        "duration_seconds",
        "external_deadline_seconds",
        "output_limit_bytes",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_size_bytes",
        "stderr_size_bytes",
        "exit_code",
        "oom_killed",
        "deadline_exceeded",
        "output_limit_exceeded",
        "terminal_status",
        "worker_result",
        "launcher_error",
        "authority",
        "remote_attestation_verified",
        "docker_daemon_reports_amd64",
        "native_platform_verified",
        "latency_parity_allowed",
        "randomization_allowed",
        "submit_authorized",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_RECEIPT_FIELDS = _RECEIPT_CONTENT_FIELDS | frozenset({"content_sha256"})


class ArmReceiptError(ValueError):
    """A container arm claim or receipt is malformed or self-inconsistent."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ArmReceiptError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ArmReceiptError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ArmReceiptError(f"{label} must be a non-empty trimmed string")
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ArmReceiptError(f"{label} must be an integer at least {minimum}")
    return value


def _finite(value: object, *, label: str, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ArmReceiptError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0.0) or (not positive and result < 0.0):
        qualifier = "positive " if positive else "non-negative "
        raise ArmReceiptError(f"{label} must be a finite {qualifier}number")
    return result


def _timestamp(value: object, *, label: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise ArmReceiptError(f"{label} must use canonical UTC microsecond form")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ArmReceiptError(f"{label} is not a valid timestamp") from exc
    if parsed.tzinfo != timezone.utc:
        raise ArmReceiptError(f"{label} must be UTC")
    return value, parsed


def _authority(raw: Mapping[str, Any]) -> None:
    if raw["authority"] != CONTAINER_AUTHORITY:
        raise ArmReceiptError(f"authority must be {CONTAINER_AUTHORITY!r}")
    if raw["anchor_allowed"] is not False:
        raise ArmReceiptError("anchor_allowed must be false")
    if raw["production_submission_authorized"] is not False:
        raise ArmReceiptError("production_submission_authorized must be false")


def _claim_base(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _CLAIM_BASE_FIELDS, label="arm claim base")
    if raw["schema"] != ATTEMPT_CLAIM_SCHEMA:
        raise ArmReceiptError(f"claim schema must be {ATTEMPT_CLAIM_SCHEMA!r}")
    normalized = {
        "schema": ATTEMPT_CLAIM_SCHEMA,
        "execution_design_sha256": _sha256(
            raw["execution_design_sha256"], label="execution_design_sha256"
        ),
        "container_protocol_sha256": _sha256(
            raw["container_protocol_sha256"], label="container_protocol_sha256"
        ),
        "bundle_manifest_sha256": _sha256(
            raw["bundle_manifest_sha256"], label="bundle_manifest_sha256"
        ),
        "task_spec_sha256": _sha256(raw["task_spec_sha256"], label="task_spec_sha256"),
        "template_content_sha256": _sha256(
            raw["template_content_sha256"], label="template_content_sha256"
        ),
        "contrast_protocol_sha256": _sha256(
            raw["contrast_protocol_sha256"], label="contrast_protocol_sha256"
        ),
        "candidate_archive_sha256": _sha256(
            raw["candidate_archive_sha256"], label="candidate_archive_sha256"
        ),
        "baseline_archive_sha256": _sha256(
            raw["baseline_archive_sha256"], label="baseline_archive_sha256"
        ),
        "policy_label": raw["policy_label"],
        "policy_archive_sha256": _sha256(
            raw["policy_archive_sha256"], label="policy_archive_sha256"
        ),
        "opponent_id": _identifier(raw["opponent_id"], label="opponent_id"),
        "opponent_archive_sha256": _sha256(
            raw["opponent_archive_sha256"], label="opponent_archive_sha256"
        ),
        "opponent_policy_content_sha256": _sha256(
            raw["opponent_policy_content_sha256"],
            label="opponent_policy_content_sha256",
        ),
        "opponent_main_sha256": _sha256(
            raw["opponent_main_sha256"], label="opponent_main_sha256"
        ),
        "opponent_deck_sha256": _sha256(
            raw["opponent_deck_sha256"], label="opponent_deck_sha256"
        ),
        "engine_id": _identifier(raw["engine_id"], label="engine_id"),
        "engine_binary_sha256": _sha256(
            raw["engine_binary_sha256"], label="engine_binary_sha256"
        ),
        "engine_runtime_tree_sha256": _sha256(
            raw["engine_runtime_tree_sha256"], label="engine_runtime_tree_sha256"
        ),
        "seed": _integer(raw["seed"], label="seed"),
        "seat": raw["seat"],
        "max_steps": _integer(raw["max_steps"], label="max_steps", minimum=1),
        "max_attempts": raw["max_attempts"],
        "retry_ordinal": raw["retry_ordinal"],
        "authority": raw["authority"],
        "anchor_allowed": raw["anchor_allowed"],
        "production_submission_authorized": raw["production_submission_authorized"],
    }
    if normalized["seed"] >= 2**63:
        raise ArmReceiptError("seed must fit a signed 63-bit integer")
    if normalized["policy_label"] not in POLICY_LABELS:
        raise ArmReceiptError(f"policy_label must be one of {sorted(POLICY_LABELS)}")
    expected_policy = (
        normalized["candidate_archive_sha256"]
        if normalized["policy_label"] == "candidate"
        else normalized["baseline_archive_sha256"]
    )
    if normalized["policy_archive_sha256"] != expected_policy:
        raise ArmReceiptError("policy_archive_sha256 does not match policy_label")
    if normalized["seat"] not in SEATS:
        raise ArmReceiptError(f"seat must be one of {sorted(SEATS)}")
    if normalized["max_attempts"] != MAX_ATTEMPTS:
        raise ArmReceiptError(f"max_attempts must equal {MAX_ATTEMPTS}")
    if normalized["retry_ordinal"] != RETRY_ORDINAL:
        raise ArmReceiptError(f"retry_ordinal must equal {RETRY_ORDINAL}")
    _authority(normalized)
    return normalized


def _derive_task_key(base: Mapping[str, Any]) -> str:
    return canonical_sha256({"namespace": ATTEMPT_CLAIM_SCHEMA, "task": dict(base)})


def _derive_attempt_id(task_key: str) -> str:
    return hashlib.sha256(
        b"evaluation-v4.2-container-attempt-v1\0" + task_key.encode("ascii")
    ).hexdigest()


def build_attempt_claim(base: Mapping[str, Any]) -> dict[str, Any]:
    """Build one deterministic, retry-free arm claim from exact task bytes."""

    normalized = _claim_base(base)
    task_key = _derive_task_key(normalized)
    content = {
        **normalized,
        "task_key": task_key,
        "attempt_id": _derive_attempt_id(task_key),
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_attempt_claim(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _CLAIM_FIELDS, label="arm claim")
    base = _claim_base({field: raw[field] for field in _CLAIM_BASE_FIELDS})
    expected = build_attempt_claim(base)
    if dict(raw) != expected:
        raise ArmReceiptError("arm claim is not canonical or its derived identity changed")
    return expected


def validate_worker_result(value: object, claim: Mapping[str, Any]) -> dict[str, Any]:
    raw = _exact_fields(value, _WORKER_RESULT_FIELDS, label="worker result")
    if raw["schema"] != WORKER_RESULT_SCHEMA:
        raise ArmReceiptError(f"worker result schema must be {WORKER_RESULT_SCHEMA!r}")
    result = {
        "schema": WORKER_RESULT_SCHEMA,
        "policy_label": raw["policy_label"],
        "opponent_id": raw["opponent_id"],
        "seed": raw["seed"],
        "seat": raw["seat"],
        "policy_left": raw["policy_left"],
        "outcome": _finite(raw["outcome"], label="worker_result.outcome"),
        "winner": raw["winner"],
        "steps": _integer(raw["steps"], label="worker_result.steps", minimum=1),
        "max_policy_action_seconds": _finite(
            raw["max_policy_action_seconds"],
            label="worker_result.max_policy_action_seconds",
        ),
        "max_opponent_action_seconds": _finite(
            raw["max_opponent_action_seconds"],
            label="worker_result.max_opponent_action_seconds",
        ),
        "transcript_sha256": _sha256(
            raw["transcript_sha256"], label="worker_result.transcript_sha256"
        ),
        "error": raw["error"],
    }
    if result["policy_label"] != claim["policy_label"]:
        raise ArmReceiptError("worker result policy_label does not match claim")
    if result["opponent_id"] != claim["opponent_id"]:
        raise ArmReceiptError("worker result opponent_id does not match claim")
    if result["seed"] != claim["seed"] or result["seat"] != claim["seat"]:
        raise ArmReceiptError("worker result seed/seat does not match claim")
    if result["policy_left"] is not (claim["seat"] == "policy_first"):
        raise ArmReceiptError("worker result policy_left does not match seat")
    if result["outcome"] not in (0.0, 0.5, 1.0):
        raise ArmReceiptError("worker result outcome must be 0, 0.5, or 1")
    if isinstance(result["winner"], bool) or result["winner"] not in (0, 1, 2):
        raise ArmReceiptError("worker result winner must be 0, 1, or 2")
    if result["error"] is not None:
        raise ArmReceiptError("successful worker result error must be null")
    if result["winner"] == 2:
        expected_outcome = 0.5
    else:
        policy_won = (result["winner"] == 0) is result["policy_left"]
        expected_outcome = 1.0 if policy_won else 0.0
    if result["outcome"] != expected_outcome:
        raise ArmReceiptError("worker result outcome is inconsistent with winner and seat")
    return result


def _receipt_content(value: object, claim: Mapping[str, Any]) -> dict[str, Any]:
    raw = _exact_fields(value, _RECEIPT_CONTENT_FIELDS, label="arm receipt content")
    if raw["schema"] != ARM_RECEIPT_SCHEMA:
        raise ArmReceiptError(f"receipt schema must be {ARM_RECEIPT_SCHEMA!r}")
    if raw["claim_content_sha256"] != claim["content_sha256"]:
        raise ArmReceiptError("receipt claim_content_sha256 does not match claim")
    if raw["attempt_id"] != claim["attempt_id"]:
        raise ArmReceiptError("receipt attempt_id does not match claim")
    if raw["container_protocol_sha256"] != claim["container_protocol_sha256"]:
        raise ArmReceiptError("receipt container protocol does not match claim")

    started_text, started = _timestamp(raw["started_at_utc"], label="started_at_utc")
    finished_text, finished = _timestamp(raw["finished_at_utc"], label="finished_at_utc")
    if finished < started:
        raise ArmReceiptError("finished_at_utc precedes started_at_utc")
    duration = _finite(raw["duration_seconds"], label="duration_seconds")
    elapsed = (finished - started).total_seconds()
    if abs(duration - elapsed) > 1.0:
        raise ArmReceiptError("duration_seconds disagrees with wall-clock timestamps")

    exit_code = raw["exit_code"]
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        raise ArmReceiptError("exit_code must be an integer or null")
    container_id = raw["container_id"]
    if container_id is not None and (
        not isinstance(container_id, str) or _CONTAINER_ID_RE.fullmatch(container_id) is None
    ):
        raise ArmReceiptError("container_id must be a 64-character lowercase hex ID or null")
    for label in ("oom_killed", "deadline_exceeded", "output_limit_exceeded"):
        if not isinstance(raw[label], bool):
            raise ArmReceiptError(f"{label} must be boolean")
    status = raw["terminal_status"]
    if status not in TERMINAL_STATUSES:
        raise ArmReceiptError(f"terminal_status must be one of {sorted(TERMINAL_STATUSES)}")
    launcher_error = raw["launcher_error"]
    if launcher_error is not None and (
        not isinstance(launcher_error, str) or not launcher_error.strip()
    ):
        raise ArmReceiptError("launcher_error must be a non-empty string or null")

    normalized: dict[str, Any] = {
        "schema": ARM_RECEIPT_SCHEMA,
        "claim_content_sha256": claim["content_sha256"],
        "attempt_id": claim["attempt_id"],
        "container_protocol_sha256": claim["container_protocol_sha256"],
        "image_manifest_sha256": _sha256(
            raw["image_manifest_sha256"], label="image_manifest_sha256"
        ),
        "image_config_sha256": _sha256(
            raw["image_config_sha256"], label="image_config_sha256"
        ),
        "container_id": container_id,
        "observed_container_spec_sha256": _sha256(
            raw["observed_container_spec_sha256"],
            label="observed_container_spec_sha256",
        ),
        "docker_daemon_fingerprint_sha256": _sha256(
            raw["docker_daemon_fingerprint_sha256"],
            label="docker_daemon_fingerprint_sha256",
        ),
        "docker_inspect_sha256": _sha256(
            raw["docker_inspect_sha256"], label="docker_inspect_sha256"
        ),
        "input_bundle_sha256": _sha256(
            raw["input_bundle_sha256"], label="input_bundle_sha256"
        ),
        "runtime_bundle_sha256": _sha256(
            raw["runtime_bundle_sha256"], label="runtime_bundle_sha256"
        ),
        "launcher_source_sha256": _sha256(
            raw["launcher_source_sha256"], label="launcher_source_sha256"
        ),
        "command_sha256": _sha256(raw["command_sha256"], label="command_sha256"),
        "started_at_utc": started_text,
        "finished_at_utc": finished_text,
        "duration_seconds": duration,
        "external_deadline_seconds": _finite(
            raw["external_deadline_seconds"],
            label="external_deadline_seconds",
            positive=True,
        ),
        "output_limit_bytes": _integer(
            raw["output_limit_bytes"], label="output_limit_bytes", minimum=1
        ),
        "stdout_sha256": _sha256(raw["stdout_sha256"], label="stdout_sha256"),
        "stderr_sha256": _sha256(raw["stderr_sha256"], label="stderr_sha256"),
        "stdout_size_bytes": _integer(
            raw["stdout_size_bytes"], label="stdout_size_bytes"
        ),
        "stderr_size_bytes": _integer(
            raw["stderr_size_bytes"], label="stderr_size_bytes"
        ),
        "exit_code": exit_code,
        "oom_killed": raw["oom_killed"],
        "deadline_exceeded": raw["deadline_exceeded"],
        "output_limit_exceeded": raw["output_limit_exceeded"],
        "terminal_status": status,
        "worker_result": raw["worker_result"],
        "launcher_error": launcher_error,
        "authority": raw["authority"],
        "remote_attestation_verified": raw["remote_attestation_verified"],
        "docker_daemon_reports_amd64": raw["docker_daemon_reports_amd64"],
        "native_platform_verified": raw["native_platform_verified"],
        "latency_parity_allowed": raw["latency_parity_allowed"],
        "randomization_allowed": raw["randomization_allowed"],
        "submit_authorized": raw["submit_authorized"],
        "anchor_allowed": raw["anchor_allowed"],
        "production_submission_authorized": raw["production_submission_authorized"],
    }
    _authority(normalized)
    for label in (
        "remote_attestation_verified",
        "docker_daemon_reports_amd64",
        "native_platform_verified",
        "latency_parity_allowed",
        "randomization_allowed",
        "submit_authorized",
    ):
        if not isinstance(normalized[label], bool):
            raise ArmReceiptError(f"{label} must be boolean")
    if normalized["remote_attestation_verified"] is not False:
        raise ArmReceiptError("remote_attestation_verified must be false")
    if normalized["native_platform_verified"] is not False:
        raise ArmReceiptError("native_platform_verified must remain false in local receipts")
    if normalized["latency_parity_allowed"] is not False:
        raise ArmReceiptError("latency_parity_allowed must remain false in local receipts")
    if normalized["randomization_allowed"] is not False:
        raise ArmReceiptError("randomization_allowed must be false")
    if normalized["submit_authorized"] is not False:
        raise ArmReceiptError("submit_authorized must be false")
    if normalized["stdout_size_bytes"] + normalized["stderr_size_bytes"] > normalized[
        "output_limit_bytes"
    ] and not normalized["output_limit_exceeded"]:
        raise ArmReceiptError("captured output exceeds limit without output_limit_exceeded")

    success = status == "SUCCESS"
    if success:
        if (
            exit_code != 0
            or normalized["oom_killed"]
            or normalized["deadline_exceeded"]
            or normalized["output_limit_exceeded"]
            or launcher_error is not None
            or container_id is None
        ):
            raise ArmReceiptError("SUCCESS receipt contains a terminal failure condition")
        result = validate_worker_result(raw["worker_result"], claim)
        if result["max_policy_action_seconds"] > normalized["external_deadline_seconds"]:
            raise ArmReceiptError("worker policy timing exceeds external arm deadline")
        normalized["worker_result"] = result
    else:
        if raw["worker_result"] is not None:
            raise ArmReceiptError("failed receipt worker_result must be null")
        if launcher_error is None:
            raise ArmReceiptError("failed receipt must include launcher_error")
        expected_status = "FAILURE"
        if normalized["oom_killed"]:
            expected_status = "OOM_KILLED"
        elif normalized["output_limit_exceeded"]:
            expected_status = "OUTPUT_LIMIT"
        elif normalized["deadline_exceeded"]:
            expected_status = "TIMEOUT"
        if status != expected_status:
            raise ArmReceiptError(
                f"terminal_status {status!r} conflicts with failure flags; expected {expected_status!r}"
            )
    return normalized


def build_arm_receipt(content: Mapping[str, Any], claim: Mapping[str, Any]) -> dict[str, Any]:
    """Build a self-hashed receipt for an already claimed one-shot attempt."""

    verified_claim = validate_attempt_claim(claim)
    normalized = _receipt_content(content, verified_claim)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def validate_arm_receipt(value: object, claim: Mapping[str, Any]) -> dict[str, Any]:
    verified_claim = validate_attempt_claim(claim)
    raw = _exact_fields(value, _RECEIPT_FIELDS, label="arm receipt")
    normalized = _receipt_content(
        {field: raw[field] for field in _RECEIPT_CONTENT_FIELDS}, verified_claim
    )
    digest = _sha256(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(normalized):
        raise ArmReceiptError("arm receipt content_sha256 mismatch")
    expected = {**normalized, "content_sha256": digest}
    if dict(raw) != expected:
        raise ArmReceiptError("arm receipt is not canonical")
    return expected


__all__ = [
    "ARM_RECEIPT_SCHEMA",
    "ATTEMPT_CLAIM_SCHEMA",
    "CONTAINER_AUTHORITY",
    "MAX_ATTEMPTS",
    "POLICY_LABELS",
    "RETRY_ORDINAL",
    "TERMINAL_STATUSES",
    "WORKER_RESULT_SCHEMA",
    "ArmReceiptError",
    "build_arm_receipt",
    "build_attempt_claim",
    "validate_arm_receipt",
    "validate_attempt_claim",
    "validate_worker_result",
]
