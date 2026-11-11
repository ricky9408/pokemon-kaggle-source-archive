from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from evaluation_v4_2.parent_arm_claim import (
    ParentArmClaimError,
    build_child_claim_template,
    build_parent_bound_child_claim,
    child_attempt_id,
    parent_bound_child_claim_sha256,
    parent_child_campaign_sha256,
    validate_child_claim_template,
    validate_parent_bound_child_claim,
)
from evaluation_v4_2.witness_journal import canonical_json_bytes


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _plan() -> dict[str, object]:
    return {
        "content_sha256": _sha("plan"),
        "runner_binding_content_sha256": _sha("runner"),
    }


def _allocation() -> dict[str, object]:
    return {
        "allocation_id": "allocation-0",
        "ordinal": 0,
        "wave": 0,
        "slot": 0,
        "logical_attempt_id": "logical-attempt-reused-across-campaigns",
        "logical_claim_content_sha256": _sha("logical-claim"),
        "sandbox_arm_claim_sha256": _sha("base-arm-claim"),
        "bundle_manifest_sha256": _sha("bundle-manifest"),
        "bundle_tree_sha256": _sha("bundle-tree"),
        "bundle_task_spec_sha256": _sha("task"),
        "runtime_bundle_sha256": _sha("runtime"),
        "worker_source_sha256": _sha("worker"),
        "normalized_policy_identity_sha256": _sha("policy"),
    }


def _state(*, campaign: str = "campaign-a", started: bool = True) -> dict[str, object]:
    value: dict[str, object] = {
        "campaign_id": _sha(campaign),
        "authority_id": _sha("campaign-authority"),
        "root_id": _sha("campaign-root"),
        "claim_event_sha256": _sha("claim-event"),
        "arm_witness_authority_id": _sha("arm-authority"),
        "arm_witness_root_id": _sha("arm-root"),
    }
    if started:
        value.update(
            {
                "prepared_manifest_sha256": _sha("prepared-manifest"),
                "prepare_event_sha256": _sha("prepare-event"),
                "start_evidence_sha256": _sha("start-evidence"),
                "start_event_sha256": _sha("start-event"),
                "wave_start_event_sha256s": {"0": _sha("wave-event")},
                "wave_runtime_verification_sha256s": {"0": _sha("wave-runtime")},
            }
        )
    return value


def _commands() -> dict[str, list[str]]:
    shared = [
        "$SNAPSHOT",
        "$CHILD_CLAIM_SHA256",
        "$ARM_BOUND_EVENT_SHA256",
        "$CHILD_START_EVENT_SHA256",
        "$SESSION_ID",
    ]
    return {
        "referee": ["docker", "run", "referee", *shared],
        "candidate_policy": ["docker", "run", "candidate", *shared],
        "opponent_policy": ["docker", "run", "opponent", *shared],
    }


def _template(*, state: dict[str, object] | None = None) -> dict[str, object]:
    return build_child_claim_template(
        _plan(),
        state or _state(),
        _allocation(),
        snapshot_manifest_sha256=_sha("snapshot-manifest"),
        snapshot_tree_sha256=_sha("snapshot-tree"),
        normalized_command_templates=_commands(),
    )


def test_template_and_bound_claim_are_exact_parent_derivations() -> None:
    state = _state()
    template = _template(state=state)
    assert validate_child_claim_template(template, _plan(), state, _allocation()) == template

    claim = build_parent_bound_child_claim(template, state)
    assert validate_parent_bound_child_claim(claim, template, state) == claim
    assert claim["scope"] == "parent_bound_campaign_arm"
    assert claim["parent_wave_start_event_sha256"] == _sha("wave-event")
    assert parent_bound_child_claim_sha256(claim) == hashlib.sha256(
        canonical_json_bytes(claim)
    ).hexdigest()


def test_wave_event_and_runtime_are_unavailable_before_durable_start() -> None:
    template = _template(state=_state(started=False))
    with pytest.raises(ParentArmClaimError, match="wave authorization|SHA-256"):
        build_parent_bound_child_claim(template, _state(started=False))


def test_claim_cannot_be_reused_after_parent_event_or_campaign_change() -> None:
    state = _state()
    template = _template(state=state)
    claim = build_parent_bound_child_claim(template, state)

    changed = deepcopy(state)
    changed["wave_start_event_sha256s"]["0"] = _sha("other-wave")
    with pytest.raises(ParentArmClaimError, match="durable parent events"):
        validate_parent_bound_child_claim(claim, template, changed)

    other_state = _state(campaign="campaign-b")
    other_template = _template(state=other_state)
    assert other_template["child_attempt_id"] != template["child_attempt_id"]
    assert parent_child_campaign_sha256(
        str(other_state["campaign_id"]), "allocation-0"
    ) != parent_child_campaign_sha256(str(state["campaign_id"]), "allocation-0")


def test_command_templates_reject_missing_or_unknown_parent_placeholders() -> None:
    commands = _commands()
    commands["referee"].remove("$CHILD_START_EVENT_SHA256")
    with pytest.raises(ParentArmClaimError, match="lacks exact parent placeholders"):
        build_child_claim_template(
            _plan(),
            _state(),
            _allocation(),
            snapshot_manifest_sha256=_sha("snapshot-manifest"),
            snapshot_tree_sha256=_sha("snapshot-tree"),
            normalized_command_templates=commands,
        )

    commands = _commands()
    commands["referee"].append("$UNKNOWN")
    with pytest.raises(ParentArmClaimError, match="unknown placeholder"):
        build_child_claim_template(
            _plan(),
            _state(),
            _allocation(),
            snapshot_manifest_sha256=_sha("snapshot-manifest"),
            snapshot_tree_sha256=_sha("snapshot-tree"),
            normalized_command_templates=commands,
        )


def test_command_templates_accept_known_placeholders_inside_docker_arguments() -> None:
    commands = {
        role: [
            "docker",
            "run",
            "--mount",
            "type=bind,source=$SNAPSHOT/runtime,target=/input/runtime,readonly",
            "--label",
            "evaluation_v4_2.claim_sha256=$CHILD_CLAIM_SHA256",
            "--label",
            "evaluation_v4_2.arm_bound=$ARM_BOUND_EVENT_SHA256",
            "--label",
            "evaluation_v4_2.child_start=$CHILD_START_EVENT_SHA256",
            "--label",
            "evaluation_v4_2.session=$SESSION_ID",
        ]
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    template = build_child_claim_template(
        _plan(),
        _state(),
        _allocation(),
        snapshot_manifest_sha256=_sha("snapshot-manifest"),
        snapshot_tree_sha256=_sha("snapshot-tree"),
        normalized_command_templates=commands,
    )
    assert template["normalized_command_templates"] == commands


def test_child_attempt_id_ignores_reused_logical_attempt_id() -> None:
    assert child_attempt_id(_sha("campaign-a"), "allocation-0") != child_attempt_id(
        _sha("campaign-b"), "allocation-0"
    )
