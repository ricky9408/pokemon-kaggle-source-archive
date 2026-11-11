from __future__ import annotations

import copy
import hashlib

import pytest

import evaluation_v4_2.local_panel as local_panel
from evaluation_v4_2.arm_receipt import (
    ARM_RECEIPT_SCHEMA,
    ATTEMPT_CLAIM_SCHEMA,
    CONTAINER_AUTHORITY,
    WORKER_RESULT_SCHEMA,
    build_arm_receipt,
    build_attempt_claim,
)
from evaluation_v4_2.local_panel import LocalPanelError, compose_local_panel, validate_local_panel


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _claim(label: str) -> dict[str, object]:
    candidate = _sha("candidate")
    baseline = _sha("baseline")
    return build_attempt_claim(
        {
            "schema": ATTEMPT_CLAIM_SCHEMA,
            "execution_design_sha256": _sha("design"),
            "container_protocol_sha256": _sha(f"protocol-{label}"),
            "bundle_manifest_sha256": _sha(f"bundle-manifest-{label}"),
            "task_spec_sha256": _sha(f"task-spec-{label}"),
            "template_content_sha256": _sha("template"),
            "contrast_protocol_sha256": _sha("contrast"),
            "candidate_archive_sha256": candidate,
            "baseline_archive_sha256": baseline,
            "policy_label": label,
            "policy_archive_sha256": candidate if label == "candidate" else baseline,
            "opponent_id": "opponent-01",
            "opponent_archive_sha256": _sha("opponent-archive"),
            "opponent_policy_content_sha256": _sha("opponent-policy"),
            "opponent_main_sha256": _sha("opponent-main"),
            "opponent_deck_sha256": _sha("opponent-deck"),
            "engine_id": "engine-a",
            "engine_binary_sha256": _sha("engine-binary"),
            "engine_runtime_tree_sha256": _sha("engine-runtime"),
            "seed": 17,
            "seat": "policy_first",
            "max_steps": 600,
            "max_attempts": 1,
            "retry_ordinal": 0,
            "authority": CONTAINER_AUTHORITY,
            "anchor_allowed": False,
            "production_submission_authorized": False,
        }
    )


def _receipt(claim: dict[str, object], *, outcome: float, native: bool = False) -> dict[str, object]:
    winner = 0 if outcome == 1.0 else 1 if outcome == 0.0 else 2
    result = {
        "schema": WORKER_RESULT_SCHEMA,
        "policy_label": claim["policy_label"],
        "opponent_id": claim["opponent_id"],
        "seed": claim["seed"],
        "seat": claim["seat"],
        "policy_left": True,
        "outcome": outcome,
        "winner": winner,
        "steps": 10,
        "max_policy_action_seconds": 0.01,
        "max_opponent_action_seconds": 0.02,
        "transcript_sha256": _sha(f"transcript-{claim['policy_label']}"),
        "error": None,
    }
    return build_arm_receipt(
        {
            "schema": ARM_RECEIPT_SCHEMA,
            "claim_content_sha256": claim["content_sha256"],
            "attempt_id": claim["attempt_id"],
            "container_protocol_sha256": claim["container_protocol_sha256"],
            "image_manifest_sha256": _sha("image-manifest"),
            "image_config_sha256": _sha("image-config"),
            "container_id": _sha(f"container-{claim['policy_label']}"),
            "observed_container_spec_sha256": _sha("observed-spec"),
            "docker_daemon_fingerprint_sha256": _sha("daemon"),
            "docker_inspect_sha256": _sha(f"inspect-{claim['policy_label']}"),
            "input_bundle_sha256": _sha(f"bundle-{claim['policy_label']}"),
            "runtime_bundle_sha256": _sha("runtime"),
            "launcher_source_sha256": _sha("launcher"),
            "command_sha256": _sha(f"command-{claim['policy_label']}"),
            "started_at_utc": "2026-07-12T06:00:00.000000Z",
            "finished_at_utc": "2026-07-12T06:00:01.000000Z",
            "duration_seconds": 1.0,
            "external_deadline_seconds": 30.0,
            "output_limit_bytes": 65536,
            "stdout_sha256": _sha(f"stdout-{claim['policy_label']}"),
            "stderr_sha256": _sha("empty-stderr"),
            "stdout_size_bytes": 100,
            "stderr_size_bytes": 0,
            "exit_code": 0,
            "oom_killed": False,
            "deadline_exceeded": False,
            "output_limit_exceeded": False,
            "terminal_status": "SUCCESS",
            "worker_result": result,
            "launcher_error": None,
            "authority": CONTAINER_AUTHORITY,
            "remote_attestation_verified": False,
            "docker_daemon_reports_amd64": native,
            "native_platform_verified": False,
            "latency_parity_allowed": False,
            "randomization_allowed": False,
            "submit_authorized": False,
            "anchor_allowed": False,
            "production_submission_authorized": False,
        },
        claim,
    )


def _plan() -> dict[str, object]:
    claims = [_claim("candidate"), _claim("baseline")]
    return {
        "content_sha256": _sha("plan"),
        "claims": claims,
        "container_protocols": [
            {
                "content_sha256": claim["container_protocol_sha256"],
                "image_digest_sha256": _sha("image-manifest"),
                "image_config_sha256": _sha("image-config"),
                "runtime_sha256": _sha("runtime"),
                "source_sha256": _sha("launcher"),
                "arm_deadline_seconds": 30.0,
                "action_deadline_seconds": 1.0,
                "input_mounts": [
                    {"source_sha256": _sha(f"bundle-{claim['policy_label']}")}
                ],
            }
            for claim in claims
        ],
        "paired_cell_count": 1,
        "arm_count": 2,
    }


def _patch_plan_validator(monkeypatch: pytest.MonkeyPatch, plan: dict[str, object]) -> None:
    monkeypatch.setattr(local_panel, "validate_execution_plan", lambda value: plan)


def test_composer_derives_one_exact_pair_and_keeps_authority_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    _patch_plan_validator(monkeypatch, plan)
    candidate, baseline = plan["claims"]
    receipts = [_receipt(candidate, outcome=1.0), _receipt(baseline, outcome=0.0)]

    panel = compose_local_panel(plan, receipts)

    assert panel["paired_cell_count"] == 1
    assert panel["rows"][0]["candidate_outcome"] == 1.0
    assert panel["rows"][0]["baseline_outcome"] == 0.0
    assert panel["mechanics_outcomes_available"] is True
    assert panel["mechanics_outcomes_admissible"] is False
    assert panel["local_custody_complete"] is False
    assert panel["external_witness_verified"] is False
    assert panel["global_one_shot_verified"] is False
    assert panel["trusted_policy_code_required"] is True
    assert panel["cross_policy_isolation_verified"] is False
    assert panel["latency_metrics_admissible"] is False
    assert panel["scientific_selector_admissible"] is False
    assert panel["submit_authorized"] is False
    assert validate_local_panel(panel, plan) == panel


def test_missing_duplicate_or_replacement_receipts_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    _patch_plan_validator(monkeypatch, plan)
    candidate, baseline = plan["claims"]
    candidate_receipt = _receipt(candidate, outcome=1.0)
    baseline_receipt = _receipt(baseline, outcome=0.0)

    with pytest.raises(LocalPanelError, match="count"):
        compose_local_panel(plan, [candidate_receipt])
    with pytest.raises(LocalPanelError, match="duplicate|expected claim"):
        compose_local_panel(plan, [candidate_receipt, candidate_receipt])

    changed = copy.deepcopy(baseline_receipt)
    changed["claim_content_sha256"] = candidate["content_sha256"]
    with pytest.raises(LocalPanelError):
        compose_local_panel(plan, [candidate_receipt, changed])


def test_runtime_posture_must_be_uniform(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _plan()
    _patch_plan_validator(monkeypatch, plan)
    candidate, baseline = plan["claims"]
    left = _receipt(candidate, outcome=1.0, native=False)
    right = _receipt(baseline, outcome=0.0, native=True)
    with pytest.raises(LocalPanelError, match="runtime/security posture"):
        compose_local_panel(plan, [left, right])


def test_panel_tampering_is_recomputed(monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _plan()
    _patch_plan_validator(monkeypatch, plan)
    candidate, baseline = plan["claims"]
    panel = compose_local_panel(
        plan,
        [_receipt(candidate, outcome=1.0), _receipt(baseline, outcome=0.0)],
    )
    panel["rows"][0]["candidate_outcome"] = 0.0
    with pytest.raises(LocalPanelError, match="derived field|content_sha256"):
        validate_local_panel(panel, plan)
