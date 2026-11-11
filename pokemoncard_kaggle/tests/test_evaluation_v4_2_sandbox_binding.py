from __future__ import annotations

import math

import pytest

from evaluation_v4_2.sandbox_binding import (
    FALSE_AUTHORITY_FLAGS,
    SandboxBindingError,
    arm_campaign_sha256,
    build_arm_campaign,
    build_arm_claim,
    policy_identity_sha256,
)
from evaluation_v4_2.sandbox_protocol import canonical_sha256
import tools.run_evaluation_v4_2_sandbox_arm as runner


def _task() -> dict[str, object]:
    return {
        "schema": "evaluation_v4_2_container_arm_task_v1",
        "policy_label": "candidate",
        "policy_archive_sha256": "1" * 64,
        "policy_policy_content_sha256": "2" * 64,
        "policy_main_sha256": "3" * 64,
        "policy_deck_sha256": "4" * 64,
        "opponent_id": "opponent-1",
        "opponent_archive_sha256": "5" * 64,
        "opponent_policy_content_sha256": "6" * 64,
        "opponent_main_sha256": "7" * 64,
        "opponent_deck_sha256": "8" * 64,
        "engine_id": "engine-1",
        "engine_binary_sha256": "9" * 64,
        "engine_runtime_tree_sha256": "a" * 64,
        "seed": 4,
        "seat": "policy_first",
        "max_steps": 20,
        "max_action_seconds": 0.25,
    }


def test_hashes_are_canonical_and_runner_api_matches_package() -> None:
    task = _task()
    campaign = build_arm_campaign(task, "b" * 64)
    claim = build_arm_claim(task, "b" * 64)

    assert policy_identity_sha256(task) == (
        "73018559d9d001e86150d5a7ee56611d6f200cbce792a421eda7c4ae629aee8f"
    )
    assert arm_campaign_sha256(task, "b" * 64) == (
        "77a2a8071da3e6db48b02fb1f95b2f2b9c1e318e0e24b4f3c73aaadb42ceab03"
    )
    assert arm_campaign_sha256(task, "b" * 64) == canonical_sha256(campaign)
    assert claim["campaign_sha256"] == canonical_sha256(campaign)
    assert claim["content_sha256"] == (
        "3ac700a54f5a95ac64e62a3b858b67bb0048e31e38cf636497f1299643a6e8b4"
    )
    assert claim["content_sha256"] == canonical_sha256(
        {key: value for key, value in claim.items() if key != "content_sha256"}
    )
    assert runner.build_arm_campaign(task, "b" * 64) == campaign
    assert runner.build_arm_claim(task, "b" * 64) == claim


def test_archive_repackaging_and_labels_are_ignored_by_content_identity() -> None:
    task = _task()
    aliased = {
        **task,
        "policy_label": "baseline",
        "policy_archive_sha256": "b" * 64,
        "opponent_archive_sha256": "c" * 64,
        "opponent_id": "renamed-opponent",
        "engine_id": "renamed-engine",
    }

    assert policy_identity_sha256(task) == policy_identity_sha256(aliased)
    assert build_arm_campaign(task, "d" * 64) == build_arm_campaign(aliased, "e" * 64)
    assert build_arm_claim(task, "d" * 64) != build_arm_claim(aliased, "e" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_policy_content_sha256", "f" * 64),
        ("opponent_policy_content_sha256", "f" * 64),
        ("engine_binary_sha256", "f" * 64),
        ("engine_runtime_tree_sha256", "f" * 64),
        ("seed", 5),
        ("seat", "policy_second"),
        ("max_steps", 21),
        ("max_action_seconds", 0.5),
    ],
)
def test_campaign_hash_is_sensitive_to_arm_identity_mutations(field: str, value: object) -> None:
    task = _task()
    mutated = {**task, field: value}
    assert arm_campaign_sha256(task, "b" * 64) != arm_campaign_sha256(mutated, "b" * 64)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_label", "unknown"),
        ("seat", "unknown"),
        ("seed", -1),
        ("seed", 2**63),
        ("seed", True),
        ("max_steps", 0),
        ("max_steps", True),
        ("max_action_seconds", 0.0),
        ("max_action_seconds", 1),
        ("max_action_seconds", math.inf),
        ("policy_main_sha256", "A" * 64),
        ("engine_binary_sha256", None),
    ],
)
def test_malformed_task_values_are_rejected(field: str, value: object) -> None:
    with pytest.raises(SandboxBindingError):
        build_arm_campaign({**_task(), field: value}, "b" * 64)


def test_task_fields_must_be_exact() -> None:
    task = _task()
    with pytest.raises(SandboxBindingError, match="exactly"):
        build_arm_campaign({key: value for key, value in task.items() if key != "seed"}, "b" * 64)
    with pytest.raises(SandboxBindingError, match="exactly"):
        build_arm_campaign({**task, "unknown": 1}, "b" * 64)


def test_bundle_digest_and_prefix_are_validated() -> None:
    with pytest.raises(SandboxBindingError):
        build_arm_claim(_task(), "not-a-digest")
    with pytest.raises(SandboxBindingError):
        policy_identity_sha256(_task(), "candidate")


def test_authority_is_closed_for_campaign_and_claim() -> None:
    campaign = build_arm_campaign(_task(), "b" * 64)
    claim = build_arm_claim(_task(), "b" * 64)
    for document in (campaign, claim):
        assert document["authority"] == "DEVELOPMENT_ONLY"
        assert document["panel_parent_claim_verified"] is False
        assert document.keys() >= FALSE_AUTHORITY_FLAGS.keys()
        assert all(document[field] is False for field in FALSE_AUTHORITY_FLAGS)
    assert campaign["parent_campaign_gate_required"] is True
    assert campaign["bundle_manifest_bound_in_claim"] is True
    campaign["submit_authorized"] = True
    assert build_arm_campaign(_task(), "b" * 64)["submit_authorized"] is False


def test_runner_legacy_exception_surface_is_preserved() -> None:
    with pytest.raises(runner.SandboxArmError):
        runner.build_arm_claim({**_task(), "seat": "bad"}, "b" * 64)
