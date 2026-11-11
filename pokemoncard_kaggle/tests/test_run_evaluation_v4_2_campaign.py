from __future__ import annotations

import fcntl
import os
from pathlib import Path
import threading

import pytest

import evaluation_v4_2.campaign_journal as journal_module
import evaluation_v4_2.campaign_composer as composer_module
from evaluation_v4_2.campaign_journal import (
    BURN,
    NEVER_STARTED,
    START_DURABLE_POPEN_UNCERTAIN,
    SUCCESS,
    VETO,
    CampaignJournal,
)
from evaluation_v4_2.parent_arm_claim import child_attempt_id
from evaluation_v4_2.campaign_runtime import build_current_runner_binding
from evaluation_v4_2.witness_journal import canonical_sha256
from tools.run_evaluation_v4_2_container_arm import prepare_input_bundle, validate_input_bundle
from tools.run_evaluation_v4_2_campaign import CampaignExecutor, CampaignExecutorError, _Dependencies
import tools.run_evaluation_v4_2_sandbox_arm as sandbox_runner


KEY = b"campaign-executor-test-key"
EPOCH = "e" * 64


def _digest(number: int) -> str:
    return f"{number:064x}"


def _plan() -> dict[str, object]:
    allocations = []
    for ordinal in range(4):
        allocation_id = f"a{ordinal}"
        allocations.append(
            {
                "allocation_id": allocation_id,
                "ordinal": ordinal,
                "wave": ordinal // 2,
                "slot": ordinal % 2,
                "logical_attempt_id": f"logical-{allocation_id}",
                "logical_claim_content_sha256": _digest(10 + ordinal),
                "sandbox_arm_claim_sha256": _digest(20 + ordinal),
                "bundle_manifest_sha256": _digest(30 + ordinal),
                "bundle_tree_sha256": _digest(40 + ordinal),
                "bundle_task_spec_sha256": _digest(50 + ordinal),
                "runtime_bundle_sha256": _digest(60 + ordinal),
                "worker_source_sha256": _digest(70 + ordinal),
                "normalized_policy_identity_sha256": _digest(80 + ordinal),
                "task": {"policy_label": "candidate", "seed": ordinal},
            }
        )
    return {
        "content_sha256": "a" * 64,
        "candidate_normalized_identity_sha256": "c" * 64,
        "runner_binding_content_sha256": "d" * 64,
        "runner_binding": {
            "scheduler_width": 2,
            "oci_image": "registry.example/image@sha256:" + "b" * 64,
            "resource_caps": {
                "cpu_limit_millicores": 1000,
                "memory_limit_bytes": 1024,
                "pids_limit": 16,
                "tmpfs_size_bytes": 1024,
            },
        },
        "allocations": allocations,
    }


@pytest.fixture(autouse=True)
def tiny_campaign_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(journal_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(
        journal_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda value, **_kwargs: value,
    )


def _journal(path: Path) -> CampaignJournal:
    return CampaignJournal(path, KEY, key_id="executor-key", domain="tests.executor")


def _bundle_dirs(tmp_path: Path) -> dict[str, str]:
    result = {}
    for allocation in _plan()["allocations"]:
        path = tmp_path / "bundles" / allocation["allocation_id"]
        path.mkdir(parents=True)
        result[allocation["allocation_id"]] = str(path)
    return result


def _dependencies(
    *,
    arm_outcomes: dict[str, str],
    calls: list[str],
    runtime_calls: list[tuple[str, int | None]],
    runtime_fault: tuple[str, int | None] | None = None,
    arm_barrier: threading.Barrier | None = None,
) -> _Dependencies:
    def bundle_validator():
        def validate(path: Path):
            allocation_id = path.name
            ordinal = int(allocation_id[1:])
            allocation = _plan()["allocations"][ordinal]
            return {
                "content_sha256": allocation["bundle_manifest_sha256"],
                "task": allocation["task"],
            }

        return validate

    def snapshot_manifest(_bundle: Path, manifest: dict[str, object]):
        ordinal = int(manifest["task"]["seed"])
        return {"tree_sha256": _digest(100 + ordinal)}

    def templates(*_args, **_kwargs):
        placeholders = [
            "$SNAPSHOT",
            "$CHILD_CLAIM_SHA256",
            "$ARM_BOUND_EVENT_SHA256",
            "$CHILD_START_EVENT_SHA256",
            "$SESSION_ID",
        ]
        return {role: ["docker", "run", role, *placeholders] for role in ("referee", "candidate_policy", "opponent_policy")}

    def runtime(_binding, **kwargs):
        marker = (kwargs["phase"], kwargs.get("wave"))
        runtime_calls.append(marker)
        if marker == runtime_fault:
            raise RuntimeError("injected runtime verification fault")
        return {"phase": kwargs["phase"], "wave": kwargs.get("wave")}

    def arm_executor(_bundle, *, campaign_journal, campaign_id, allocation_id, **_kwargs):
        calls.append(allocation_id)
        if arm_barrier is not None:
            arm_barrier.wait(timeout=5)
        child_id = child_attempt_id(campaign_id, allocation_id)
        claim_sha256 = canonical_sha256({"allocation_id": allocation_id})
        arm_journal = campaign_journal._arm_journal
        child_claim = arm_journal.claim(child_id, claim_sha256)
        campaign_journal.bind_arm(
            campaign_id,
            allocation_id,
            child_id,
            claim_sha256,
            child_claim["event_sha256"],
        )
        if arm_outcomes[allocation_id] == "RAISE_AFTER_BOUND":
            raise RuntimeError("injected post-bound fault")
        arm_journal.prepare(child_id, evidence={"scope": "parent_bound_campaign_arm"})
        arm_journal.start(child_id, evidence={"scope": "parent_bound_campaign_arm"})
        if arm_outcomes[allocation_id] == "RAISE_AFTER_START":
            raise RuntimeError("injected post-start fault")
        terminal_status = arm_outcomes[allocation_id]
        launch_state = "POPEN_OBSERVED"
        arm_journal.terminal(
            child_id,
            terminal_status,
            evidence={
                "scope": "parent_bound_campaign_arm",
                "terminal_status": terminal_status,
                "launch_state": launch_state,
            },
        )
        if terminal_status != SUCCESS:
            return {
                "terminal_status": terminal_status,
                "launch_state": launch_state,
                "child_attempt_id": child_id,
            }
        return {
            "terminal_status": SUCCESS,
            "launch_state": launch_state,
            "child_attempt_id": child_id,
            "parent_binding": {
                "parent_bound_child_claim_sha256": claim_sha256,
                "child_claim_event_sha256": child_claim["event_sha256"],
                "child_start_event_sha256": _digest(200 + int(allocation_id[1:])),
            },
        }

    def arm_composer(_arm_journal, attempt_id):
        return {"attempt_id": attempt_id, "status": SUCCESS}

    def terminal_evidence(**kwargs):
        return {"allocation_id": kwargs["allocation_id"], "terminal_status": kwargs["terminal_status"]}

    def campaign_terminal(_state, *, terminal_status, **_kwargs):
        return {"terminal_status": terminal_status}

    def campaign_composer(campaign_journal, campaign_id):
        state = campaign_journal.state(campaign_id)
        return {"campaign_id": campaign_id, "status": state["terminal_status"]}

    return _Dependencies(
        plan_validator=lambda value: value,
        bundle_validator=bundle_validator,
        snapshot_manifest_predictor=snapshot_manifest,
        template_builder=templates,
        runtime_verifier=runtime,
        arm_executor=arm_executor,
        arm_composer=arm_composer,
        arm_terminal_builder=terminal_evidence,
        campaign_terminal_builder=campaign_terminal,
        campaign_composer=campaign_composer,
    )


def _executor(
    *,
    outcomes: dict[str, str],
    calls: list[str],
    runtime_calls: list[tuple[str, int | None]],
    runtime_fault: tuple[str, int | None] | None = None,
    arm_barrier: threading.Barrier | None = None,
) -> CampaignExecutor:
    return CampaignExecutor(
        dependencies=_dependencies(
            arm_outcomes=outcomes,
            calls=calls,
            runtime_calls=runtime_calls,
            runtime_fault=runtime_fault,
            arm_barrier=arm_barrier,
        )
    )


def test_process_wide_lock_is_nonblocking(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    lock_path = journal.root / "execution.lock"
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        executor = _executor(outcomes={f"a{i}": SUCCESS for i in range(4)}, calls=[], runtime_calls=[])
        with pytest.raises(CampaignExecutorError, match="another process"):
            executor.run(
                journal=journal,
                plan=_plan(),
                allocation_bundle_dirs=_bundle_dirs(tmp_path),
                evaluation_epoch_sha256=EPOCH,
                output_root=tmp_path / "out",
            )


def test_existing_nonterminal_campaign_is_recovery_only_and_never_launches(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    plan = _plan()
    campaign_id = journal.claim_campaign(plan, EPOCH)["payload"]["campaign_id"]
    # A durable, incomplete claim is deliberately not resumed from preparation.
    calls: list[str] = []
    executor = _executor(outcomes={f"a{i}": SUCCESS for i in range(4)}, calls=calls, runtime_calls=[])

    result = executor.run(
        journal=journal,
        plan=plan,
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    assert result["status"] == VETO
    assert calls == []
    state = journal.state(campaign_id)
    assert state["state"] == "TERMINAL"
    assert all(item["terminal_status"] == BURN for item in state["dispositions"].values())
    assert all(item["launch_state"] == NEVER_STARTED for item in state["dispositions"].values())


def test_all_success_runs_canonical_waves_and_runtime_boundaries(tmp_path: Path) -> None:
    calls: list[str] = []
    runtime_calls: list[tuple[str, int | None]] = []
    executor = _executor(outcomes={f"a{i}": SUCCESS for i in range(4)}, calls=calls, runtime_calls=runtime_calls)
    journal = _journal(tmp_path / "journal")

    result = executor.run(
        journal=journal,
        plan=_plan(),
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    assert result["status"] == SUCCESS
    assert set(calls[:2]) == {"a0", "a1"}
    assert set(calls[2:]) == {"a2", "a3"}
    assert runtime_calls[0] == ("campaign_start", None)
    assert ("wave_start", 0) in runtime_calls
    assert ("wave_start", 1) in runtime_calls
    assert [phase for phase, _wave in runtime_calls].count("pre_arm_start") == 0
    campaign_id = result["campaign_id"]
    assert not (tmp_path / "out" / campaign_id / "prepared").exists()
    state = journal.state(campaign_id)
    assert state["terminal_status"] == SUCCESS
    assert all(item["terminal_status"] == SUCCESS for item in state["dispositions"].values())


def test_each_canonical_wave_uses_the_frozen_scheduler_width(tmp_path: Path) -> None:
    calls: list[str] = []
    barrier = threading.Barrier(2)
    executor = _executor(
        outcomes={f"a{i}": SUCCESS for i in range(4)},
        calls=calls,
        runtime_calls=[],
        arm_barrier=barrier,
    )

    result = executor.run(
        journal=_journal(tmp_path / "journal"),
        plan=_plan(),
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    assert result["status"] == SUCCESS
    assert set(calls[:2]) == {"a0", "a1"}
    assert set(calls[2:]) == {"a2", "a3"}


def test_first_non_success_finishes_started_wave_then_burns_future_and_vetoes(tmp_path: Path) -> None:
    calls: list[str] = []
    runtime_calls: list[tuple[str, int | None]] = []
    outcomes = {"a0": "FAILURE", "a1": SUCCESS, "a2": SUCCESS, "a3": SUCCESS}
    executor = _executor(outcomes=outcomes, calls=calls, runtime_calls=runtime_calls)
    journal = _journal(tmp_path / "journal")

    result = executor.run(
        journal=journal,
        plan=_plan(),
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    assert result["status"] == VETO
    assert set(calls) == {"a0", "a1"}
    state = journal.state(result["campaign_id"])
    assert state["terminal_status"] == VETO
    assert state["dispositions"]["a0"]["terminal_status"] == "FAILURE"
    assert state["dispositions"]["a0"]["launch_state"] == "POPEN_OBSERVED"
    assert state["dispositions"]["a1"]["terminal_status"] == SUCCESS
    for allocation_id in ("a2", "a3"):
        assert state["dispositions"][allocation_id]["terminal_status"] == BURN
        assert state["dispositions"][allocation_id]["launch_state"] == NEVER_STARTED
    assert ("wave_start", 1) not in runtime_calls


@pytest.mark.parametrize(
    ("injected", "expected_launch_state"),
    [
        ("RAISE_AFTER_BOUND", NEVER_STARTED),
        ("RAISE_AFTER_START", START_DURABLE_POPEN_UNCERTAIN),
    ],
)
def test_exception_launch_state_uses_child_start_not_arm_bound(
    tmp_path: Path,
    injected: str,
    expected_launch_state: str,
) -> None:
    calls: list[str] = []
    outcomes = {"a0": injected, "a1": SUCCESS, "a2": SUCCESS, "a3": SUCCESS}
    journal = _journal(tmp_path / "journal")

    result = _executor(outcomes=outcomes, calls=calls, runtime_calls=[]).run(
        journal=journal,
        plan=_plan(),
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    state = journal.state(result["campaign_id"])
    assert set(calls) == {"a0", "a1"}
    assert state["dispositions"]["a0"]["terminal_status"] == BURN
    assert state["dispositions"]["a0"]["launch_state"] == expected_launch_state
    assert state["dispositions"]["a1"]["terminal_status"] == SUCCESS


@pytest.mark.parametrize(
    ("wave", "expected_calls"),
    [
        (0, []),
        (1, ["a0", "a1"]),
    ],
)
def test_wave_runtime_failure_vetoes_without_launching_that_wave(
    tmp_path: Path,
    wave: int,
    expected_calls: list[str],
) -> None:
    calls: list[str] = []
    journal = _journal(tmp_path / "journal")
    executor = _executor(
        outcomes={f"a{i}": SUCCESS for i in range(4)},
        calls=calls,
        runtime_calls=[],
        runtime_fault=("wave_start", wave),
    )

    result = executor.run(
        journal=journal,
        plan=_plan(),
        allocation_bundle_dirs=_bundle_dirs(tmp_path),
        evaluation_epoch_sha256=EPOCH,
        output_root=tmp_path / "out",
    )

    assert result["status"] == VETO
    assert set(calls) == set(expected_calls)
    state = journal.state(result["campaign_id"])
    assert state["terminal_status"] == VETO
    future = ("a0", "a1", "a2", "a3") if wave == 0 else ("a2", "a3")
    for allocation_id in future:
        assert state["dispositions"][allocation_id]["terminal_status"] == BURN
        assert state["dispositions"][allocation_id]["launch_state"] == NEVER_STARTED


@pytest.mark.docker_smoke
@pytest.mark.skipif(
    os.environ.get("EVALUATION_V4_2_PARENT_DOCKER_SMOKE") != "1",
    reason="opt-in parent campaign Docker smoke",
)
def test_real_parent_campaign_runs_two_bound_arms_and_recomposes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise the real parent, runtime verifier, three sandboxes, CAS, and composer.

    The production logical-plan validator deliberately requires the complete
    1,536-arm grid.  This opt-in integration uses a two-arm same-policy identity
    contrast solely to prove the execution path; it monkeypatches only that
    grid-size validator and retains DEVELOPMENT_ONLY authority throughout.
    """

    source = (
        Path(__file__).resolve().parents[1]
        / "evaluation_artifacts"
        / "evaluation_v4_2"
        / "sandbox_smoke_v7_second_20260712T1641"
        / "bundle"
    )
    if not source.is_dir():
        pytest.skip("real v4.2 source bundle is absent")
    source_task = validate_input_bundle(source)["task"]
    bundles: dict[str, Path] = {}
    manifests: dict[str, dict[str, object]] = {}
    for slot, label in enumerate(("candidate", "baseline")):
        destination = tmp_path / "bundles" / label
        manifests[label] = prepare_input_bundle(
            policy_archive=source / "custody" / "policy.tar.gz",
            opponent_archive=source / "custody" / "opponent.tar.gz",
            engine_dir=source / "engine",
            output_dir=destination,
            policy_label=label,
            opponent_id=source_task["opponent_id"],
            engine_id=source_task["engine_id"],
            seed=source_task["seed"],
            seat=source_task["seat"],
            max_steps=source_task["max_steps"],
            max_action_seconds=source_task["max_action_seconds"],
        )
        bundles[label] = destination

    binding = build_current_runner_binding(
        repository_root=Path(__file__).resolve().parents[1],
        oci_image=sandbox_runner.DEFAULT_IMAGE,
        scheduler_width=2,
        arm_deadline_seconds=sandbox_runner.DEFAULT_ARM_DEADLINE_SECONDS,
        action_deadline_seconds=1.0,
        docker_call_timeout_seconds=sandbox_runner.DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
    )
    allocations: list[dict[str, object]] = []
    for slot, label in enumerate(("candidate", "baseline")):
        manifest = manifests[label]
        task = manifest["task"]
        allocations.append(
            {
                "allocation_id": f"smoke-{label}",
                "ordinal": slot,
                "wave": 0,
                "slot": slot,
                "logical_attempt_id": f"smoke-logical-{label}",
                "logical_claim_content_sha256": canonical_sha256(
                    {"scope": "smoke", "policy_label": label}
                ),
                "sandbox_arm_claim_sha256": canonical_sha256(
                    sandbox_runner.build_arm_claim(task, manifest["content_sha256"])
                ),
                "bundle_manifest_sha256": manifest["content_sha256"],
                "bundle_tree_sha256": manifest["bundle_tree_sha256"],
                "bundle_task_spec_sha256": manifest["task_spec_sha256"],
                "runtime_bundle_sha256": manifest["runtime_bundle_sha256"],
                "worker_source_sha256": manifest["worker_source_sha256"],
                "normalized_policy_identity_sha256": sandbox_runner.policy_identity_sha256(task),
                "task": task,
            }
        )
    plan_content = {
        "candidate_normalized_identity_sha256": allocations[0][
            "normalized_policy_identity_sha256"
        ],
        "runner_binding_content_sha256": binding["content_sha256"],
        "runner_binding": binding,
        "logical_execution_plan": {"paired_cell_count": 1},
        "allocations": allocations,
    }
    plan = {**plan_content, "content_sha256": canonical_sha256(plan_content)}
    monkeypatch.setattr(journal_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(composer_module, "validate_campaign_plan", lambda value: value)

    journal = CampaignJournal(tmp_path / "journal", b"real-parent-smoke-key")
    result = CampaignExecutor(
        dependencies=_Dependencies(plan_validator=lambda value: value)
    ).run(
        journal=journal,
        plan=plan,
        allocation_bundle_dirs={
            allocations[0]["allocation_id"]: str(bundles["candidate"]),
            allocations[1]["allocation_id"]: str(bundles["baseline"]),
        },
        evaluation_epoch_sha256="9" * 64,
        output_root=tmp_path / "output",
    )

    assert result["schema"] == composer_module.WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA
    assert result["paired_cell_count"] == 1
    assert len(result["rows"]) == 1
    assert result["rows"][0]["candidate_outcome"] == result["rows"][0]["baseline_outcome"]
    assert composer_module.compose_campaign(journal, result["campaign_id"]) == result


@pytest.mark.docker_smoke
@pytest.mark.skipif(
    os.environ.get("EVALUATION_V4_2_PARENT_DOCKER_SMOKE") != "1",
    reason="opt-in parent campaign Docker smoke",
)
def test_real_parent_campaign_vetoes_an_abrupt_policy_exit_without_rows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Exercise a real child-process crash through the exclusive parent path."""

    source = (
        Path(__file__).resolve().parents[1]
        / "evaluation_artifacts"
        / "evaluation_v4_2"
        / "sandbox_adversarial_os_exit_20260712T1641"
        / "bundle"
    )
    if not source.is_dir():
        pytest.skip("real adversarial v4.2 source bundle is absent")
    candidate_manifest = validate_input_bundle(source)
    task = candidate_manifest["task"]
    healthy_source = (
        Path(__file__).resolve().parents[1]
        / "evaluation_artifacts"
        / "evaluation_v4_2"
        / "sandbox_smoke_v7_second_20260712T1641"
        / "bundle"
    )
    if not healthy_source.is_dir():
        pytest.skip("real healthy v4.2 source bundle is absent")
    baseline_dir = tmp_path / "bundles" / "baseline"
    baseline_manifest = prepare_input_bundle(
        policy_archive=healthy_source / "custody" / "policy.tar.gz",
        opponent_archive=source / "custody" / "opponent.tar.gz",
        engine_dir=source / "engine",
        output_dir=baseline_dir,
        policy_label="baseline",
        opponent_id=task["opponent_id"],
        engine_id=task["engine_id"],
        seed=task["seed"],
        seat=task["seat"],
        max_steps=task["max_steps"],
        max_action_seconds=task["max_action_seconds"],
    )
    binding = build_current_runner_binding(
        repository_root=Path(__file__).resolve().parents[1],
        oci_image=sandbox_runner.DEFAULT_IMAGE,
        scheduler_width=2,
        arm_deadline_seconds=sandbox_runner.DEFAULT_ARM_DEADLINE_SECONDS,
        action_deadline_seconds=1.0,
        docker_call_timeout_seconds=sandbox_runner.DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
    )
    allocations = []
    bundle_dirs: dict[str, str] = {}
    for slot, (label, manifest, bundle_dir) in enumerate(
        (
            ("candidate", candidate_manifest, source),
            ("baseline", baseline_manifest, baseline_dir),
        )
    ):
        allocation_task = manifest["task"]
        allocation_id = f"smoke-os-exit-{label}"
        allocations.append(
            {
                "allocation_id": allocation_id,
                "ordinal": slot,
                "wave": 0,
                "slot": slot,
                "logical_attempt_id": f"smoke-logical-os-exit-{label}",
                "logical_claim_content_sha256": canonical_sha256(
                    {"scope": "smoke", "failure": "os_exit", "policy_label": label}
                ),
                "sandbox_arm_claim_sha256": canonical_sha256(
                    sandbox_runner.build_arm_claim(
                        allocation_task, manifest["content_sha256"]
                    )
                ),
                "bundle_manifest_sha256": manifest["content_sha256"],
                "bundle_tree_sha256": manifest["bundle_tree_sha256"],
                "bundle_task_spec_sha256": manifest["task_spec_sha256"],
                "runtime_bundle_sha256": manifest["runtime_bundle_sha256"],
                "worker_source_sha256": manifest["worker_source_sha256"],
                "normalized_policy_identity_sha256": sandbox_runner.policy_identity_sha256(
                    allocation_task
                ),
                "task": allocation_task,
            }
        )
        bundle_dirs[allocation_id] = str(bundle_dir)
    plan_content = {
        "candidate_normalized_identity_sha256": allocations[0][
            "normalized_policy_identity_sha256"
        ],
        "runner_binding_content_sha256": binding["content_sha256"],
        "runner_binding": binding,
        "logical_execution_plan": {"paired_cell_count": 1},
        "allocations": allocations,
    }
    plan = {**plan_content, "content_sha256": canonical_sha256(plan_content)}
    monkeypatch.setattr(journal_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(composer_module, "validate_campaign_plan", lambda value: value)

    journal = CampaignJournal(tmp_path / "journal", b"real-parent-os-exit-key")
    result = CampaignExecutor(
        dependencies=_Dependencies(plan_validator=lambda value: value)
    ).run(
        journal=journal,
        plan=plan,
        allocation_bundle_dirs=bundle_dirs,
        evaluation_epoch_sha256="8" * 64,
        output_root=tmp_path / "output",
    )

    assert result["schema"] == composer_module.CAMPAIGN_VETO_SCHEMA
    assert result["terminal_status"] == VETO
    assert result["outcomes_omitted"] is True
    assert "rows" not in result
    dispositions = journal.state(result["campaign_id"])["dispositions"]
    disposition = dispositions[
        allocations[0]["allocation_id"]
    ]
    assert disposition["terminal_status"] != SUCCESS
    assert dispositions[allocations[1]["allocation_id"]]["terminal_status"] == SUCCESS
    assert composer_module.compose_campaign(journal, result["campaign_id"]) == result
