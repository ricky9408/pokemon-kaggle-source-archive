from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib

import pytest

from evaluation_v4_2.analysis_contract import (
    ANALYSIS_CONTRACT_SCHEMA,
    FIRST_GAMES_PER_ARCHIVE,
    HOLDOUT_OPENING_RULE,
    MECHANISM_FAMILIES,
    PUBLIC_ENDPOINT,
    SELECTOR_PROTOCOL,
    STOPPING_RULE,
    THRESHOLDS,
    TRAINING_ROOTS,
    VALIDATION_PAIRS,
    VALIDATION_ROOTS,
    build_analysis_contract,
)
from evaluation_v4_2.campaign_protocol import (
    CANONICAL_WAVES_V1,
    FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY,
    CampaignProtocolError,
    build_campaign_plan,
    build_runner_binding,
    validate_campaign_plan,
    validate_runner_binding,
)
from evaluation_v4_2.container_protocol import (
    CONTAINER_PROTOCOL_SCHEMA,
    build_container_protocol,
)
from evaluation_v4_2.contrast_protocol import (
    ARM_EXECUTION_MODE,
    CONTRAST_PROTOCOL_SCHEMA,
    FAILURE_POLICY,
    REQUIRED_PLATFORM,
    build_contrast_protocol,
)
from evaluation_v4_2.execution_plan import arm_protocol_id, build_execution_plan
from evaluation_v4_2.sandbox_binding import canonical_sha256, policy_identity_sha256
from evaluation_v4_2.sandbox_protocol import sandbox_execution_spec
from evaluation_v4_2.simulation_design import (
    SEED_DERIVATION_ALGORITHM,
    TEMPLATE_SCHEMA,
    build_simulation_template,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _candidate_identities() -> tuple[dict[str, str], dict[str, str]]:
    return (
        {
            "archive_sha256": _sha("candidate-archive"),
            "policy_content_sha256": _sha("candidate-policy"),
            "main_sha256": _sha("candidate-main"),
            "deck_sha256": _sha("candidate-deck"),
        },
        {
            "archive_sha256": _sha("baseline-archive"),
            "policy_content_sha256": _sha("baseline-policy"),
            "main_sha256": _sha("baseline-main"),
            "deck_sha256": _sha("baseline-deck"),
        },
    )


def _analysis_contract() -> dict[str, object]:
    return build_analysis_contract(
        {
            "schema": ANALYSIS_CONTRACT_SCHEMA,
            "analysis_id": "external-natural-intervention-v1",
            "feature_extractor_sha256": _sha("feature-extractor"),
            "predictor_model_sha256": _sha("predictor-model"),
            "analysis_program_sha256": _sha("analysis-program"),
            "decision_rule_sha256": _sha("decision-rule"),
            "alpha_ledger_sha256": _sha("alpha-ledger"),
            "holdout_rule_sha256": _sha("holdout-rule"),
            "training_manifest_sha256": _sha("training-manifest"),
            "burn_denylist_sha256": _sha("burn-denylist"),
            "selector_protocol": SELECTOR_PROTOCOL,
            "public_endpoint": PUBLIC_ENDPOINT,
            "training_roots": TRAINING_ROOTS,
            "validation_roots": VALIDATION_ROOTS,
            "validation_pairs": VALIDATION_PAIRS,
            "mechanism_families": MECHANISM_FAMILIES,
            "first_games_per_archive": FIRST_GAMES_PER_ARCHIVE,
            "thresholds": THRESHOLDS,
            "stopping_rule": STOPPING_RULE,
            "holdout_opening_rule": HOLDOUT_OPENING_RULE,
            "authority": "DEVELOPMENT_ONLY",
            "scientific_authority": False,
            "external_authority": False,
            "holdout_authorized": False,
            "submission_authorized": False,
            "state": "FROZEN",
        }
    )


def _template_source() -> dict[str, object]:
    opponents = [
        {
            "opponent_id": f"opponent-{index:02d}",
            "archive_sha256": _sha(f"opponent-archive-{index}"),
            "policy_content_sha256": _sha(f"opponent-policy-{index}"),
            "deck_sha256": _sha(f"opponent-deck-{index}"),
            "family_id": f"family-{index % 5}",
            "rating_layer": "top" if index < 4 else "mid" if index < 8 else "low",
            "weight": 1.0 / 12,
            "ood_mass": 1.0 if index >= 8 else 0.0,
        }
        for index in range(12)
    ]
    return {
        "schema": TEMPLATE_SCHEMA,
        "protocol_sha256": _sha("template-protocol"),
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


def _task(
    *,
    policy_label: str,
    candidate: dict[str, str],
    baseline: dict[str, str],
    opponent: dict[str, object],
    opponent_main_sha256: str,
    engine: dict[str, object],
    seed: int,
    seat: str,
    max_steps: int,
    max_action_seconds: float,
) -> dict[str, object]:
    policy = candidate if policy_label == "candidate" else baseline
    return {
        "schema": "evaluation_v4_2_container_arm_task_v1",
        "policy_label": policy_label,
        "policy_archive_sha256": policy["archive_sha256"],
        "policy_policy_content_sha256": policy["policy_content_sha256"],
        "policy_main_sha256": policy["main_sha256"],
        "policy_deck_sha256": policy["deck_sha256"],
        "opponent_id": opponent["opponent_id"],
        "opponent_archive_sha256": opponent["archive_sha256"],
        "opponent_policy_content_sha256": opponent["policy_content_sha256"],
        "opponent_main_sha256": opponent_main_sha256,
        "opponent_deck_sha256": opponent["deck_sha256"],
        "engine_id": engine["engine_id"],
        "engine_binary_sha256": engine["binary_sha256"],
        "engine_runtime_tree_sha256": engine["runtime_tree_sha256"],
        "seed": seed,
        "seat": seat,
        "max_steps": max_steps,
        "max_action_seconds": max_action_seconds,
    }


def _manifest(task: dict[str, object], label: str) -> dict[str, object]:
    content = {
        "schema": "evaluation_v4_2_container_input_bundle_v1",
        "task": task,
        "task_spec_sha256": canonical_sha256(task),
        "bundle_tree_sha256": _sha(f"bundle-tree:{label}"),
        "runtime_bundle_sha256": _sha(f"runtime-bundle:{label}"),
        "worker_source_sha256": _sha(f"worker-source:{label}"),
        "authority": "DEVELOPMENT_ONLY",
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def _protocol(
    *,
    arm_id: str,
    policy_label: str,
    manifest: dict[str, object],
    contrast: dict[str, object],
    label: str,
) -> dict[str, object]:
    image_digest = _sha("sandbox-image")
    return build_container_protocol(
        {
            "schema": CONTAINER_PROTOCOL_SCHEMA,
            "arm_id": arm_id,
            "arm_kind": policy_label,
            "bundle_manifest_sha256": manifest["content_sha256"],
            "task_spec_sha256": manifest["task_spec_sha256"],
            "oci_image": f"registry.example/evaluator@sha256:{image_digest}",
            "image_digest_sha256": image_digest,
            "image_manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
            "image_manifest_raw_sha256": image_digest,
            "image_config_sha256": _sha("sandbox-config"),
            "image_layer_sha256s": [_sha("sandbox-layer-1"), _sha("sandbox-layer-2")],
            "platform": "linux/amd64",
            "network_mode": "none",
            "read_only_rootfs": True,
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "input_mounts": [
                {
                    "source_id": "frozen-inputs",
                    "source_sha256": _sha(f"inputs:{label}"),
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
            "pids_limit": 64,
            "max_steps": contrast["max_steps"],
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
    )


def _runner_binding(contrast: dict[str, object]) -> dict[str, object]:
    image_digest = _sha("sandbox-image")
    code_manifest = {
        "analysis_contract": _sha("code-analysis-contract"),
        "parent_executor": _sha("code-parent-executor"),
        "arm_runner": _sha("code-arm-runner"),
        "campaign_protocol": _sha("code-campaign-protocol"),
        "campaign_journal": _sha("code-campaign-journal"),
        "campaign_preparation": _sha("code-campaign-preparation"),
        "campaign_runtime": _sha("code-campaign-runtime"),
        "campaign_composer": _sha("code-campaign-composer"),
        "parent_arm_claim": _sha("code-parent-arm-claim"),
        "witness_journal": _sha("code-witness-journal"),
        "sandbox_protocol": _sha("code-sandbox-protocol"),
        "sandbox_binding": _sha("code-sandbox-binding"),
        "sandbox_worker_source": _sha("code-sandbox-worker-source"),
    }
    return build_runner_binding(
        {
            "parent_runner_sha256": code_manifest["parent_executor"],
            "arm_runner_sha256": code_manifest["arm_runner"],
            "journal_sha256": code_manifest["campaign_journal"],
            "sandbox_protocol_sha256": code_manifest["sandbox_protocol"],
            "composer_sha256": code_manifest["campaign_composer"],
            "code_manifest": code_manifest,
            "python_executable_sha256": _sha("python-executable"),
            "python_executable_path_sha256": _sha("python-path"),
            "python_version_sha256": _sha("python-version"),
            "python_platform_sha256": _sha("python-platform"),
            "docker_cli_sha256": _sha("docker-cli"),
            "docker_cli_path_sha256": _sha("docker-path"),
            "docker_version_sha256": _sha("docker-version"),
            "oci_image": f"registry.example/evaluator@sha256:{image_digest}",
            "image_digest_sha256": image_digest,
            "image_manifest_raw_sha256": image_digest,
            "image_config_sha256": _sha("sandbox-config"),
            "image_layer_sha256s": [_sha("sandbox-layer-1"), _sha("sandbox-layer-2")],
            "arm_deadline_seconds": contrast["worker_timeout_seconds"],
            "action_deadline_seconds": contrast["max_action_seconds"],
            "docker_call_timeout_seconds": 15.0,
            "scheduler_width": 16,
        }
    )


@lru_cache(maxsize=1)
def _full_fixture() -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, object], dict[str, object]]:
    template = build_simulation_template(_template_source())
    candidate, baseline = _candidate_identities()
    contrast = _contrast(baseline)
    opponent_mains = {
        opponent["opponent_id"]: _sha(f"opponent-main:{opponent['opponent_id']}")
        for opponent in template["opponent_roster"]
    }
    manifests: dict[str, dict[str, object]] = {}
    protocols: list[dict[str, object]] = []
    for engine in template["engine_roster"]:
        for opponent in template["opponent_roster"]:
            for seed in template["seeds"]:
                for seat in ("policy_first", "policy_second"):
                    for policy_label in ("candidate", "baseline"):
                        arm_id = arm_protocol_id(
                            policy_label,
                            engine["engine_id"],
                            opponent["opponent_id"],
                            seed,
                            seat,
                        )
                        task = _task(
                            policy_label=policy_label,
                            candidate=candidate,
                            baseline=baseline,
                            opponent=opponent,
                            opponent_main_sha256=opponent_mains[opponent["opponent_id"]],
                            engine=engine,
                            seed=seed,
                            seat=seat,
                            max_steps=contrast["max_steps"],
                            max_action_seconds=contrast["max_action_seconds"],
                        )
                        manifest = _manifest(task, arm_id)
                        protocols.append(
                            _protocol(
                                arm_id=arm_id,
                                policy_label=policy_label,
                                manifest=manifest,
                                contrast=contrast,
                                label=arm_id,
                            )
                        )
                        manifests[arm_id] = manifest
    plan = build_execution_plan(
        template,
        contrast,
        candidate,
        baseline,
        opponent_mains,
        protocols,
    )
    by_arm_id = {protocol["arm_id"]: manifest for protocol, manifest in zip(protocols, manifests.values())}
    manifests_by_attempt = {
        claim["attempt_id"]: by_arm_id[
            arm_protocol_id(
                claim["policy_label"],
                claim["engine_id"],
                claim["opponent_id"],
                claim["seed"],
                claim["seat"],
            )
        ]
        for claim in plan["claims"]
    }
    binding = _runner_binding(contrast)
    campaign = build_campaign_plan(plan, manifests_by_attempt, binding, _analysis_contract())
    return plan, manifests_by_attempt, binding, campaign


@pytest.fixture(scope="module")
def full_fixture() -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, object], dict[str, object]]:
    return _full_fixture()


def _reseal(value: dict[str, object]) -> dict[str, object]:
    content = {key: item for key, item in value.items() if key != "content_sha256"}
    return {**content, "content_sha256": canonical_sha256(content)}


def test_builds_exact_full_grid_campaign_and_self_hashes(full_fixture) -> None:
    plan, manifests, binding, campaign = full_fixture

    assert plan["paired_cell_count"] == 768
    assert plan["arm_count"] == 1536
    assert len(manifests) == 1536
    assert campaign["allocation_count"] == 1536
    assert len(campaign["allocations"]) == 1536
    assert campaign["scheduler_policy"] == CANONICAL_WAVES_V1
    assert campaign["failure_policy"] == FINISH_STARTED_WAVE_THEN_VETO_NO_RETRY
    assert campaign["legacy_container_protocol_execution_allowed"] is False
    assert campaign["allocations"][0]["ordinal"] == 0
    assert campaign["allocations"][0]["wave"] == 0
    assert campaign["allocations"][0]["slot"] == 0
    assert campaign["allocations"][16]["wave"] == 1
    assert campaign["allocations"][16]["slot"] == 0
    assert len({item["allocation_id"] for item in campaign["allocations"]}) == 1536
    assert campaign["runner_binding_content_sha256"] == binding["content_sha256"]
    assert validate_campaign_plan(campaign) == campaign


@pytest.mark.parametrize("mutation", ("omission", "bundle_swap"))
def test_builder_rejects_incomplete_or_swapped_bundle_coverage(full_fixture, mutation: str) -> None:
    plan, manifests, binding, _ = full_fixture
    bad = deepcopy(manifests)
    keys = list(bad)
    if mutation == "omission":
        bad.pop(keys[0])
    else:
        bad[keys[0]], bad[keys[1]] = bad[keys[1]], bad[keys[0]]
    with pytest.raises(CampaignProtocolError, match="exactly cover|logical claim|manifest hash"):
        build_campaign_plan(plan, bad, binding, _analysis_contract())


@pytest.mark.parametrize("mutation", ("duplicate", "reorder"))
def test_allocations_are_an_ordered_bijection(full_fixture, mutation: str) -> None:
    _, _, _, campaign = full_fixture
    bad = deepcopy(campaign)
    if mutation == "duplicate":
        bad["allocations"][1] = deepcopy(bad["allocations"][0])
    else:
        bad["allocations"] = list(reversed(bad["allocations"]))
    bad = _reseal(bad)
    with pytest.raises(CampaignProtocolError, match="allocation|canonical|logical claim"):
        validate_campaign_plan(bad)


@pytest.mark.parametrize("field", ("seed", "seat", "policy_label"))
def test_task_identity_mutations_are_rejected(full_fixture, field: str) -> None:
    _, _, _, campaign = full_fixture
    bad = deepcopy(campaign)
    allocation = bad["allocations"][0]
    task = allocation["task"]
    task[field] = (
        task["seed"] + 1
        if field == "seed"
        else "policy_second"
        if field == "seat"
        else "baseline"
    )
    allocation["bundle_manifest"]["task"] = task
    allocation["bundle_manifest"] = _reseal(allocation["bundle_manifest"])
    allocation["bundle_manifest_sha256"] = allocation["bundle_manifest"]["content_sha256"]
    allocation["bundle_task_spec_sha256"] = allocation["bundle_manifest"]["task_spec_sha256"]
    bad["allocations"][0] = allocation
    bad["allocation_set_sha256"] = canonical_sha256(bad["allocations"])
    bad = _reseal(bad)
    with pytest.raises(CampaignProtocolError, match="task_spec|logical claim|allocation"):
        validate_campaign_plan(bad)


def test_normalized_identity_ignores_label_and_archive_but_campaign_binds_archive(full_fixture) -> None:
    _, _, _, campaign = full_fixture
    task = deepcopy(campaign["allocations"][0]["task"])
    aliased = {
        **task,
        "policy_label": "baseline",
        "policy_archive_sha256": _sha("repacked-archive"),
    }
    assert policy_identity_sha256(task) == policy_identity_sha256(aliased)

    bad = deepcopy(campaign)
    allocation = bad["allocations"][0]
    allocation["task"] = aliased
    allocation["bundle_manifest"]["task"] = aliased
    allocation["bundle_manifest"] = _reseal(allocation["bundle_manifest"])
    allocation["bundle_manifest_sha256"] = allocation["bundle_manifest"]["content_sha256"]
    allocation["bundle_task_spec_sha256"] = allocation["bundle_manifest"]["task_spec_sha256"]
    bad["allocations"][0] = allocation
    bad["allocation_set_sha256"] = canonical_sha256(bad["allocations"])
    bad = _reseal(bad)
    with pytest.raises(CampaignProtocolError, match="logical claim|task_spec|allocation"):
        validate_campaign_plan(bad)


def test_legacy_protocol_drift_and_authority_escalation_are_rejected(full_fixture) -> None:
    _, _, _, campaign = full_fixture
    legacy = deepcopy(campaign)
    legacy["legacy_container_protocol_execution_allowed"] = True
    with pytest.raises(CampaignProtocolError, match="legacy"):
        validate_campaign_plan(_reseal(legacy))

    escalated = deepcopy(campaign)
    escalated["outcome_usable"] = True
    with pytest.raises(CampaignProtocolError, match="outcome_usable"):
        validate_campaign_plan(_reseal(escalated))


def test_runner_spec_output_caps_and_unknown_fields_are_fail_closed(full_fixture) -> None:
    _, _, binding, campaign = full_fixture
    spec = sandbox_execution_spec()
    assert binding["stdout_limit_bytes"] == spec["output_limit_bytes"]
    assert binding["stderr_limit_bytes"] == spec["stderr_limit_bytes"]
    assert binding["deadline_caps"]["docker_call_timeout_seconds"] == 15.0
    assert binding["container_runtime_contract"]["pull_policy"] == "never"
    assert binding["container_runtime_contract"]["execution_scope"] == (
        "exclusive_parent_bound_campaign_arms_only"
    )
    assert binding["container_runtime_contract"]["standalone_execution_admissible"] is False
    assert binding["container_runtime_contract"]["session_id_derivation"] == (
        "parent_claim_arm_bound_child_start_sha256_tuple_v1"
    )
    assert binding["container_runtime_contract"]["ulimits"][-1] == {
        "name": "nproc",
        "soft": 64,
        "hard": 64,
    }

    bad_binding = deepcopy(binding)
    bad_binding["stdout_limit_bytes"] = spec["output_limit_bytes"] - 1
    with pytest.raises(CampaignProtocolError, match="stdout_limit_bytes"):
        validate_runner_binding(_reseal(bad_binding))

    code_drift = deepcopy(binding)
    code_drift["code_manifest"]["parent_executor"] = _sha("other-parent-executor")
    with pytest.raises(CampaignProtocolError, match="parent_runner_sha256 differs"):
        validate_runner_binding(_reseal(code_drift))

    code_drift["parent_runner_sha256"] = _sha("other-parent-executor")
    code_drift = _reseal(code_drift)
    assert validate_runner_binding(code_drift)["code_manifest"]["parent_executor"] == _sha(
        "other-parent-executor"
    )
    assert code_drift["content_sha256"] != binding["content_sha256"]

    missing_code = deepcopy(binding)
    missing_code["code_manifest"].pop("parent_arm_claim")
    with pytest.raises(CampaignProtocolError, match="exact parent evaluation source set"):
        validate_runner_binding(_reseal(missing_code))

    with pytest.raises(CampaignProtocolError, match="exactly"):
        validate_campaign_plan({**campaign, "unexpected": False})
    with pytest.raises(CampaignProtocolError, match="exactly"):
        validate_runner_binding({**binding, "unexpected": False})


def test_self_hash_tamper_is_rejected(full_fixture) -> None:
    _, _, _, campaign = full_fixture
    bad = deepcopy(campaign)
    bad["content_sha256"] = "0" * 64
    with pytest.raises(CampaignProtocolError, match="content_sha256"):
        validate_campaign_plan(bad)
