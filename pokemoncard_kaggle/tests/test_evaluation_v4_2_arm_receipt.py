from __future__ import annotations

import copy
import hashlib

import pytest

from evaluation_v4_2.arm_receipt import (
    ARM_RECEIPT_SCHEMA,
    ATTEMPT_CLAIM_SCHEMA,
    CONTAINER_AUTHORITY,
    WORKER_RESULT_SCHEMA,
    ArmReceiptError,
    build_arm_receipt,
    build_attempt_claim,
    validate_arm_receipt,
    validate_attempt_claim,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _claim_base(policy_label: str = "candidate") -> dict[str, object]:
    candidate = _sha("candidate")
    baseline = _sha("baseline")
    return {
        "schema": ATTEMPT_CLAIM_SCHEMA,
        "execution_design_sha256": _sha("design"),
        "container_protocol_sha256": _sha("container-protocol"),
        "bundle_manifest_sha256": _sha("bundle-manifest"),
        "task_spec_sha256": _sha("task-spec"),
        "template_content_sha256": _sha("template"),
        "contrast_protocol_sha256": _sha("contrast"),
        "candidate_archive_sha256": candidate,
        "baseline_archive_sha256": baseline,
        "policy_label": policy_label,
        "policy_archive_sha256": candidate if policy_label == "candidate" else baseline,
        "opponent_id": "opponent-01",
        "opponent_archive_sha256": _sha("opponent-archive"),
        "opponent_policy_content_sha256": _sha("opponent-policy"),
        "opponent_main_sha256": _sha("opponent-main"),
        "opponent_deck_sha256": _sha("opponent-deck"),
        "engine_id": "engine-v4",
        "engine_binary_sha256": _sha("engine-binary"),
        "engine_runtime_tree_sha256": _sha("engine-tree"),
        "seed": 1234,
        "seat": "policy_first",
        "max_steps": 600,
        "max_attempts": 1,
        "retry_ordinal": 0,
        "authority": CONTAINER_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def _worker_result() -> dict[str, object]:
    return {
        "schema": WORKER_RESULT_SCHEMA,
        "policy_label": "candidate",
        "opponent_id": "opponent-01",
        "seed": 1234,
        "seat": "policy_first",
        "policy_left": True,
        "outcome": 1.0,
        "winner": 0,
        "steps": 42,
        "max_policy_action_seconds": 0.02,
        "max_opponent_action_seconds": 0.03,
        "transcript_sha256": _sha("transcript"),
        "error": None,
    }


def _success_content(claim: dict[str, object]) -> dict[str, object]:
    return {
        "schema": ARM_RECEIPT_SCHEMA,
        "claim_content_sha256": claim["content_sha256"],
        "attempt_id": claim["attempt_id"],
        "container_protocol_sha256": claim["container_protocol_sha256"],
        "image_manifest_sha256": _sha("image-manifest"),
        "image_config_sha256": _sha("image-config"),
        "container_id": _sha("container-id"),
        "observed_container_spec_sha256": _sha("container-spec"),
        "docker_daemon_fingerprint_sha256": _sha("daemon"),
        "docker_inspect_sha256": _sha("inspect"),
        "input_bundle_sha256": _sha("input-bundle"),
        "runtime_bundle_sha256": _sha("runtime-bundle"),
        "launcher_source_sha256": _sha("launcher"),
        "command_sha256": _sha("command"),
        "started_at_utc": "2026-07-12T06:00:00.000000Z",
        "finished_at_utc": "2026-07-12T06:00:01.000000Z",
        "duration_seconds": 1.0,
        "external_deadline_seconds": 30.0,
        "output_limit_bytes": 65536,
        "stdout_sha256": _sha("stdout"),
        "stderr_sha256": _sha("stderr"),
        "stdout_size_bytes": 100,
        "stderr_size_bytes": 0,
        "exit_code": 0,
        "oom_killed": False,
        "deadline_exceeded": False,
        "output_limit_exceeded": False,
        "terminal_status": "SUCCESS",
        "worker_result": _worker_result(),
        "launcher_error": None,
        "authority": CONTAINER_AUTHORITY,
        "remote_attestation_verified": False,
        "docker_daemon_reports_amd64": False,
        "native_platform_verified": False,
        "latency_parity_allowed": False,
        "randomization_allowed": False,
        "submit_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def test_claim_is_deterministic_and_self_hashed() -> None:
    left = build_attempt_claim(_claim_base())
    right = build_attempt_claim(dict(reversed(list(_claim_base().items()))))

    assert left == right
    assert validate_attempt_claim(left) == left
    assert left["task_key"] != left["attempt_id"]


def test_claim_rejects_retry_or_policy_identity_substitution() -> None:
    with pytest.raises(ArmReceiptError, match="max_attempts"):
        build_attempt_claim({**_claim_base(), "max_attempts": 2})
    with pytest.raises(ArmReceiptError, match="policy_archive_sha256"):
        build_attempt_claim({**_claim_base(), "policy_archive_sha256": _sha("wrong")})


def test_success_receipt_round_trip_and_result_binding() -> None:
    claim = build_attempt_claim(_claim_base())
    receipt = build_arm_receipt(_success_content(claim), claim)

    assert validate_arm_receipt(receipt, claim) == receipt
    assert receipt["terminal_status"] == "SUCCESS"
    assert receipt["worker_result"]["outcome"] == 1.0


def test_success_receipt_rejects_forged_outcome_or_failure_flags() -> None:
    claim = build_attempt_claim(_claim_base())
    bad = _success_content(claim)
    bad["worker_result"] = {**_worker_result(), "outcome": 0.0}
    with pytest.raises(ArmReceiptError, match="inconsistent"):
        build_arm_receipt(bad, claim)

    with pytest.raises(ArmReceiptError, match="failure condition"):
        build_arm_receipt({**_success_content(claim), "oom_killed": True}, claim)


def test_failure_receipt_is_terminal_and_cannot_hide_a_result() -> None:
    claim = build_attempt_claim(_claim_base())
    failed = {
        **_success_content(claim),
        "container_id": None,
        "exit_code": None,
        "deadline_exceeded": True,
        "terminal_status": "TIMEOUT",
        "worker_result": None,
        "launcher_error": "external_watchdog_timeout",
    }
    receipt = build_arm_receipt(failed, claim)
    assert validate_arm_receipt(receipt, claim)["terminal_status"] == "TIMEOUT"

    hidden = {**failed, "worker_result": _worker_result()}
    with pytest.raises(ArmReceiptError, match="worker_result must be null"):
        build_arm_receipt(hidden, claim)


def test_receipt_rejects_unknown_fields_and_self_hash_tampering() -> None:
    claim = build_attempt_claim(_claim_base())
    receipt = build_arm_receipt(_success_content(claim), claim)
    with pytest.raises(ArmReceiptError, match="exactly"):
        validate_arm_receipt({**receipt, "forged": True}, claim)

    tampered = copy.deepcopy(receipt)
    tampered["stdout_size_bytes"] = 101
    with pytest.raises(ArmReceiptError, match="content_sha256"):
        validate_arm_receipt(tampered, claim)
