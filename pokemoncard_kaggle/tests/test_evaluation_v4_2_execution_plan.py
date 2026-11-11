from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from evaluation_v4_2.container_protocol import (
    CONTAINER_PROTOCOL_SCHEMA,
    build_container_protocol,
    canonical_sha256 as container_sha256,
)
from evaluation_v4_2.contrast_protocol import (
    ARM_EXECUTION_MODE,
    CONTRAST_PROTOCOL_SCHEMA,
    FAILURE_POLICY,
    REQUIRED_PLATFORM,
    build_contrast_protocol,
)
from evaluation_v4_2.execution_plan import (
    DEVELOPMENT_AUTHORITY,
    EXECUTION_PLAN_SCHEMA,
    ExecutionPlanError,
    arm_protocol_id,
    build_execution_plan,
    canonical_sha256,
    validate_execution_plan,
)
from evaluation_v4_2.simulation_design import (
    SEED_DERIVATION_ALGORITHM,
    TEMPLATE_SCHEMA,
    build_simulation_template,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _template() -> dict[str, object]:
    opponents = []
    for index in range(12):
        opponents.append(
            {
                "opponent_id": f"opponent-{index:02d}",
                "archive_sha256": _sha(f"opponent-archive-{index}"),
                "policy_content_sha256": _sha(f"opponent-policy-{index}"),
                "deck_sha256": _sha(f"opponent-deck-{index}"),
                "family_id": f"family-{index % 5}",
                "rating_layer": ("top" if index < 4 else "mid" if index < 8 else "low"),
                "weight": 1.0 / 12,
                "ood_mass": 1.0 if index >= 8 else 0.0,
            }
        )
    return {
        "schema": TEMPLATE_SCHEMA,
        "protocol_sha256": _sha("protocol"),
        "scientific_plan_sha256": _sha("scientific-plan"),
        "runner_code_sha256": _sha("runner"),
        "dependency_lock_sha256": _sha("lock"),
        "runtime_binding_sha256": _sha("runtime-binding"),
        "engine_roster": [
            {
                "engine_id": "engine-a",
                "binary_sha256": _sha("engine-a"),
                "runtime_tree_sha256": _sha("engine-runtime-a"),
            },
            {
                "engine_id": "engine-b",
                "binary_sha256": _sha("engine-b"),
                "runtime_tree_sha256": _sha("engine-runtime-b"),
            },
        ],
        "opponent_roster": opponents,
        "seed_beacon_sha256": _sha("seed-beacon"),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "state": "FROZEN",
    }


def _identities() -> tuple[dict[str, str], dict[str, str]]:
    candidate = {
        "archive_sha256": _sha("candidate-archive"),
        "policy_content_sha256": _sha("candidate-policy"),
        "main_sha256": _sha("candidate-main"),
        "deck_sha256": _sha("candidate-deck"),
    }
    baseline = {
        "archive_sha256": _sha("baseline-archive"),
        "policy_content_sha256": _sha("baseline-policy"),
        "main_sha256": _sha("baseline-main"),
        "deck_sha256": _sha("baseline-deck"),
    }
    return candidate, baseline


def _contrast(baseline: dict[str, str]) -> dict[str, object]:
    return build_contrast_protocol(
        {
            "schema": CONTRAST_PROTOCOL_SCHEMA,
            "baseline_archive_sha256": baseline["archive_sha256"],
            "baseline_policy_content_sha256": baseline["policy_content_sha256"],
            "baseline_main_sha256": baseline["main_sha256"],
            "baseline_deck_sha256": baseline["deck_sha256"],
            "max_steps": 600,
            "worker_timeout_seconds": 30.0,
            "max_action_seconds": 1.0,
            "workers": 2,
            "platform": REQUIRED_PLATFORM,
            "arm_execution_mode": ARM_EXECUTION_MODE,
            "failure_policy": FAILURE_POLICY,
            "engine_count": 2,
            "opponent_count": 12,
            "seed_count": 16,
            "seats": ["policy_first", "policy_second"],
            "population_readiness_sha256": _sha("readiness"),
        }
    )


def _protocols(template: dict[str, object], contrast: dict[str, object]) -> list[dict[str, object]]:
    image_digest = _sha("image")
    base = {
        "schema": CONTAINER_PROTOCOL_SCHEMA,
        "arm_id": "placeholder",
        "arm_kind": "candidate",
        "bundle_manifest_sha256": _sha("bundle-manifest"),
        "task_spec_sha256": _sha("task-spec"),
        "oci_image": f"registry.example/evaluator@sha256:{image_digest}",
        "image_digest_sha256": image_digest,
        "image_manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "image_manifest_raw_sha256": image_digest,
        "image_config_sha256": _sha("image-config"),
        "image_layer_sha256s": [_sha("layer-1"), _sha("layer-2")],
        "platform": "linux/amd64",
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "input_mounts": [
            {
                "source_id": "frozen-inputs",
                "source_sha256": _sha("frozen-inputs"),
                "target": "/inputs",
                "read_only": True,
                "private": True,
            }
        ],
        "scratch_tmpfs": {
            "target": "/tmp",
            "size_bytes": 64 * 1024 * 1024,
            "read_only": False,
            "private": True,
        },
        "cpu_limit_millicores": 1000,
        "memory_limit_bytes": 512 * 1024 * 1024,
        "pids_limit": 128,
        "max_steps": 600,
        "output_limit_bytes": 1024 * 1024,
        "arm_deadline_seconds": contrast["worker_timeout_seconds"],
        "arm_deadline_enforcement": "external_watchdog",
        "action_deadline_seconds": contrast["max_action_seconds"],
        "action_deadline_enforcement": "exact_per_action",
        "retry_policy": "none",
        "container_scope": "one_arm_per_container",
        "runtime_sha256": _sha("runtime"),
        "security_sha256": _sha("security"),
        "source_sha256": _sha("source"),
        "command": [
            "python",
            "/input/runtime/container_arm.py",
            "worker",
            "--task",
            "/input/task.json",
        ],
        "authority": "DEVELOPMENT_ONLY",
        "research_only": True,
        "external_authority": False,
        "submission_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "state": "FROZEN",
    }
    protocols = []
    for engine in template["engine_roster"]:  # type: ignore[union-attr]
        for opponent in template["opponent_roster"]:  # type: ignore[union-attr]
            for seed in template["seeds"]:  # type: ignore[index]
                for seat in ("policy_first", "policy_second"):
                    for policy in ("candidate", "baseline"):
                        content = {
                            **base,
                            "arm_id": arm_protocol_id(
                                policy, engine["engine_id"], opponent["opponent_id"], seed, seat  # type: ignore[index]
                            ),
                            "arm_kind": policy,
                            "bundle_manifest_sha256": _sha(
                                f"manifest:{policy}:{engine['engine_id']}:"
                                f"{opponent['opponent_id']}:{seed}:{seat}"
                            ),
                            "task_spec_sha256": _sha(
                                f"task:{policy}:{engine['engine_id']}:"
                                f"{opponent['opponent_id']}:{seed}:{seat}"
                            ),
                            "input_mounts": [
                                {
                                    "source_id": "frozen-inputs",
                                    "source_sha256": _sha(
                                        f"inputs:{policy}:{engine['engine_id']}:"
                                        f"{opponent['opponent_id']}:{seed}:{seat}"
                                    ),
                                    "target": "/inputs",
                                    "read_only": True,
                                    "private": True,
                                }
                            ],
                        }
                        protocols.append(build_container_protocol(content))
    return protocols


def _reseal_protocol(protocol: dict[str, object]) -> dict[str, object]:
    content = {key: value for key, value in protocol.items() if key != "content_sha256"}
    return {**content, "content_sha256": container_sha256(content)}


def _inputs() -> tuple[dict[str, object], dict[str, object], dict[str, str], list[dict[str, object]]]:
    template = build_simulation_template(_template())
    candidate, baseline = _identities()
    contrast = _contrast(baseline)
    mains = {
        opponent["opponent_id"]: _sha(f"opponent-main-{index}")
        for index, opponent in enumerate(template["opponent_roster"])  # type: ignore[index]
    }
    return template, contrast, mains, _protocols(template, contrast)


def test_builds_exact_two_by_twelve_full_grid_and_self_hashes() -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()
    plan = build_execution_plan(template, contrast, candidate, baseline, mains, protocols)

    assert plan["schema"] == EXECUTION_PLAN_SCHEMA
    assert plan["paired_cell_count"] == 768
    assert plan["arm_count"] == 1536
    assert len(plan["claims"]) == 1536
    assert len({claim["attempt_id"] for claim in plan["claims"]}) == 1536  # type: ignore[union-attr]
    assert all(
        claim["execution_design_sha256"] == plan["execution_design_sha256"]
        for claim in plan["claims"]  # type: ignore[union-attr]
    )
    assert plan["authority"] == DEVELOPMENT_AUTHORITY
    assert plan["anchor_allowed"] is False
    assert plan["production_submission_authorized"] is False
    assert plan["content_sha256"] == canonical_sha256(
        {key: value for key, value in plan.items() if key != "content_sha256"}
    )
    assert validate_execution_plan(plan) == plan


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate"])
def test_protocol_set_must_be_exact_unique_and_complete(mutation: str) -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()
    changed = list(protocols)
    if mutation == "missing":
        changed.pop()
    elif mutation == "extra":
        changed.append(protocols[0])
    else:
        changed[-1] = deepcopy(protocols[0])
    with pytest.raises(ExecutionPlanError, match="exactly|duplicate|missing"):
        build_execution_plan(template, contrast, candidate, baseline, mains, changed)


def test_protocol_arm_kind_and_id_must_bind_to_the_same_grid_arm() -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()
    bad = deepcopy(protocols)
    bad[0]["arm_kind"] = "baseline" if bad[0]["arm_kind"] == "candidate" else "candidate"
    bad[0] = _reseal_protocol(bad[0])
    with pytest.raises(ExecutionPlanError, match="arm_kind|arm_id"):
        build_execution_plan(template, contrast, candidate, baseline, mains, bad)

    bad = deepcopy(protocols)
    bad[0]["arm_id"] = "candidate:wrong:wrong:0:policy_first"
    bad[0] = _reseal_protocol(bad[0])
    with pytest.raises(ExecutionPlanError, match="extra|mismatched|missing"):
        build_execution_plan(template, contrast, candidate, baseline, mains, bad)


def test_deadline_baseline_and_nonuniform_settings_are_bound() -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()

    bad_contrast = deepcopy(contrast)
    bad_contrast["content_sha256"] = "0" * 64
    bad_contrast["max_action_seconds"] = 2.0
    with pytest.raises(ExecutionPlanError, match="contrast protocol|content_sha256"):
        build_execution_plan(template, bad_contrast, candidate, baseline, mains, protocols)

    bad_baseline = dict(baseline)
    bad_baseline["main_sha256"] = _sha("wrong-baseline-main")
    with pytest.raises(ExecutionPlanError, match="baseline identity"):
        build_execution_plan(template, contrast, candidate, bad_baseline, mains, protocols)

    bad_protocols = deepcopy(protocols)
    bad_protocols[1]["memory_limit_bytes"] = 1024
    bad_protocols[1] = _reseal_protocol(bad_protocols[1])
    with pytest.raises(ExecutionPlanError, match="uniform"):
        build_execution_plan(template, contrast, candidate, baseline, mains, bad_protocols)


def test_plan_tampering_and_authority_escalation_are_rejected() -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()
    plan = build_execution_plan(template, contrast, candidate, baseline, mains, protocols)

    forged = deepcopy(plan)
    forged["anchor_allowed"] = True
    forged["content_sha256"] = canonical_sha256(
        {key: value for key, value in forged.items() if key != "content_sha256"}
    )
    with pytest.raises(ExecutionPlanError, match="authority|anchor"):
        validate_execution_plan(forged)

    forged = deepcopy(plan)
    forged["claims"][0]["opponent_main_sha256"] = _sha("forged-main")  # type: ignore[index]
    with pytest.raises(ExecutionPlanError, match="content_sha256|claim"):
        validate_execution_plan(forged)


def test_unknown_plan_fields_are_rejected() -> None:
    template, contrast, mains, protocols = _inputs()
    candidate, baseline = _identities()
    plan = build_execution_plan(template, contrast, candidate, baseline, mains, protocols)
    with pytest.raises(ExecutionPlanError, match="exactly"):
        validate_execution_plan({**plan, "unexpected": True})
