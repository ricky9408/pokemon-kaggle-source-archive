from __future__ import annotations

from copy import deepcopy
import inspect
from pathlib import Path

import pytest

import evaluation_v4_2.campaign_composer as composer
import evaluation_v4_2.campaign_journal as campaign_journal_module
from evaluation_v4_2.campaign_journal import (
    BURN,
    FAILURE,
    NEVER_STARTED,
    POPEN_OBSERVED,
    START_DURABLE_POPEN_UNCERTAIN,
    SUCCESS,
    VETO,
    CampaignJournal,
)
from evaluation_v4_2.campaign_preparation import (
    build_campaign_prepared_manifest,
    build_prepared_allocation,
)
from evaluation_v4_2.parent_arm_claim import (
    build_parent_bound_child_claim,
    child_attempt_id,
    parent_bound_child_claim_sha256,
)
from evaluation_v4_2.sandbox_binding import FALSE_AUTHORITY_FLAGS
from evaluation_v4_2.witness_journal import canonical_sha256


KEY = b"campaign-composer-test-key"
EPOCH = "e" * 64
CANDIDATE = "c" * 64


def _digest(number: int) -> str:
    return f"{number:064x}"


def _reseal(value: dict[str, object]) -> dict[str, object]:
    content = {key: item for key, item in value.items() if key != "content_sha256"}
    return {**content, "content_sha256": canonical_sha256(content)}


def _task(*, policy_label: str, seed: int, seat: str = "policy_first") -> dict[str, object]:
    return {
        "policy_label": policy_label,
        "engine_id": "engine-a",
        "opponent_id": "opponent-a",
        "seed": seed,
        "seat": seat,
    }


def _plan() -> dict[str, object]:
    allocations: list[dict[str, object]] = []
    for ordinal, (seed, label) in enumerate(
        ((11, "candidate"), (11, "baseline"), (17, "candidate"), (17, "baseline"))
    ):
        allocations.append(
            {
                "allocation_id": f"a{ordinal}",
                "ordinal": ordinal,
                "logical_attempt_id": f"logical-attempt-{ordinal}",
                "logical_claim_content_sha256": _digest(90 + ordinal),
                "sandbox_arm_claim_sha256": _digest(100 + ordinal),
                "bundle_manifest_sha256": _digest(110 + ordinal),
                "bundle_tree_sha256": _digest(120 + ordinal),
                "bundle_task_spec_sha256": _digest(130 + ordinal),
                "runtime_bundle_sha256": _digest(140 + ordinal),
                "worker_source_sha256": _digest(150 + ordinal),
                "normalized_policy_identity_sha256": _digest(160 + ordinal),
                "wave": ordinal // 2,
                "slot": ordinal % 2,
                "task": _task(policy_label=label, seed=seed),
            }
        )
    return {
        "content_sha256": _digest(1),
        "candidate_normalized_identity_sha256": CANDIDATE,
        "logical_execution_plan": {"paired_cell_count": 2},
        "allocation_count": len(allocations),
        "allocations": allocations,
        "runner_binding_content_sha256": _digest(50),
        "runner_binding": {"scheduler_width": 2},
    }


@pytest.fixture(autouse=True)
def tiny_plan_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(campaign_journal_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(
        campaign_journal_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda value, **_kwargs: value,
    )
    monkeypatch.setattr(composer, "validate_campaign_plan", lambda value: value)


def _campaign_journal(path: Path) -> CampaignJournal:
    return CampaignJournal(path, KEY, key_id="composer-key", domain="tests.composer")


def _commands() -> dict[str, list[str]]:
    placeholders = [
        "$SNAPSHOT",
        "$CHILD_CLAIM_SHA256",
        "$ARM_BOUND_EVENT_SHA256",
        "$CHILD_START_EVENT_SHA256",
        "$SESSION_ID",
    ]
    return {
        role: ["docker", "run", role, *placeholders]
        for role in ("referee", "candidate_policy", "opponent_policy")
    }


def _prepared_manifest(campaign: CampaignJournal, campaign_id: str) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    plan = campaign.read_campaign_plan(campaign_id)
    state = campaign.state(campaign_id)
    prepared = [
        build_prepared_allocation(
            plan,
            state,
            allocation,
            snapshot_manifest_sha256=campaign.evidence.put(
                {"schema": "test-snapshot", "allocation_id": allocation["allocation_id"]}
            ),
            snapshot_tree_sha256=_digest(1000 + index),
            normalized_command_templates=_commands(),
        )
        for index, allocation in enumerate(plan["allocations"])
    ]
    return (
        build_campaign_prepared_manifest(plan, state, prepared),
        {item["allocation_id"]: item for item in prepared},
    )


def _arm_packet(
    *,
    attempt_id: str,
    terminal_evidence_sha256: str,
    terminal_event_sha256: str,
    prepared_evidence_sha256: str,
    started_evidence_sha256: str,
    authority_id: str,
    root_id: str,
    outcome: float,
    winner_role: str | None,
    serial: int,
) -> dict[str, object]:
    content: dict[str, object] = {
        "schema": composer.V4_WITNESSED_ARM_SCHEMA,
        "attempt_id": attempt_id,
        "authority_id": authority_id,
        "arm_witness_root_id": root_id,
        "one_shot_key_sha256": _digest(400 + serial),
        "terminal_event_sha256": terminal_event_sha256,
        "terminal_status": SUCCESS,
        "terminal_evidence_sha256": terminal_evidence_sha256,
        "prepared_evidence_sha256": prepared_evidence_sha256,
        "started_evidence_sha256": started_evidence_sha256,
        "reopened_file_count": 1,
        "reopened_manifest_sha256": _digest(800 + serial),
        "transcript_sha256": _digest(900 + serial),
        "status": SUCCESS,
        "fault": None,
        "host_outcome": outcome,
        "winner_role": winner_role,
        "witness_chain_verified": True,
        "global_one_shot_within_authority": False,
        "root_local_one_shot_enforced": True,
        "canonical_external_journal_required": True,
        "receipt_artifacts_reopened": True,
        "transcript_chain_recomputed": True,
        "terminal_outcome_recomputed": True,
        "cross_policy_isolation_configuration_verified": True,
        "cross_policy_isolation_verified": False,
        "cross_policy_noninterference_proven": False,
        "sandbox_escape_absence_proven": False,
        "referee_rules_correctness_verified": False,
        "policy_execution_successful": True,
        "outcome_usable": False,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY",
        "external_witness_verified": False,
        "scientific_selector_admissible": False,
        **dict(FALSE_AUTHORITY_FLAGS),
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def _bind_child(
    campaign: CampaignJournal,
    campaign_id: str,
    allocation: dict[str, object],
    prepared: dict[str, object],
) -> tuple[str, str, str]:
    child_id = child_attempt_id(campaign_id, str(allocation["allocation_id"]))
    bound_claim = build_parent_bound_child_claim(prepared, campaign.state(campaign_id))
    claim_sha256 = parent_bound_child_claim_sha256(bound_claim)
    child_claim = campaign._arm_journal.claim(child_id, claim_sha256)
    bound = campaign.bind_arm(
        campaign_id,
        allocation["allocation_id"],
        child_id,
        claim_sha256,
        child_claim["event_sha256"],
    )
    return child_id, claim_sha256, bound["event_sha256"]


def _seal_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    statuses: list[str] | None = None,
    corrupt_terminal_manifest: bool = False,
) -> tuple[CampaignJournal, str, dict[str, dict[str, object]]]:
    plan = _plan()
    campaign = _campaign_journal(tmp_path / "campaign")
    campaign_id = campaign.claim_campaign(plan, EPOCH)["payload"]["campaign_id"]
    manifest, prepared = _prepared_manifest(campaign, campaign_id)
    campaign.prepare_campaign(campaign_id, manifest)
    campaign.start_campaign(campaign_id, {"phase": "campaign-start"})
    selected_statuses = statuses or [SUCCESS] * len(plan["allocations"])
    packets: dict[str, dict[str, object]] = {}
    stopped = False

    for wave in (0, 1):
        wave_items = [
            (index, allocation, selected_statuses[index])
            for index, allocation in enumerate(plan["allocations"])
            if allocation["wave"] == wave
        ]
        if stopped:
            for _, allocation, _ in wave_items:
                evidence = composer._build_arm_terminal_evidence(
                    campaign_id=campaign_id,
                    allocation_id=allocation["allocation_id"],
                    logical_attempt_id=allocation["logical_attempt_id"],
                    terminal_status=BURN,
                    launch_state=NEVER_STARTED,
                    sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
                )
                campaign.terminal_arm(
                    campaign_id, allocation["allocation_id"], BURN, NEVER_STARTED, evidence
                )
            continue
        campaign.start_wave(
            campaign_id,
            wave,
            runtime_verification={"phase": "runtime-verification", "wave": wave},
        )
        for index, allocation, status in wave_items:
            child_id, claim_sha256, _ = _bind_child(
                campaign, campaign_id, allocation, prepared[allocation["allocation_id"]]
            )
            if status == SUCCESS:
                child = campaign._arm_journal
                child.prepare(child_id, {"phase": "child-prepare", "allocation_id": allocation["allocation_id"]})
                child_start = child.start(child_id, {"phase": "child-start", "allocation_id": allocation["allocation_id"]})
                terminal_digest = child.evidence.put(
                    {"arm_claim_sha256": claim_sha256}
                )
                child_terminal = child.terminal(child_id, SUCCESS, {"result": "success"})
                child_state = child.state(child_id)
                outcome = 1.0 if allocation["task"]["policy_label"] == "candidate" else 0.0
                packet = _arm_packet(
                    attempt_id=child_id,
                    terminal_evidence_sha256=terminal_digest,
                    terminal_event_sha256=child_terminal["event_sha256"],
                    prepared_evidence_sha256=child_state["prepared_evidence_sha256"],
                    started_evidence_sha256=child_state["started_evidence_sha256"],
                    authority_id=child.authority_id,
                    root_id=child.root_id,
                    outcome=outcome,
                    winner_role="candidate_policy" if outcome == 1.0 else "opponent_policy",
                    serial=index,
                )
                packets[child_id] = packet
                evidence = composer._build_arm_terminal_evidence(
                    campaign_id=campaign_id,
                    allocation_id=allocation["allocation_id"],
                    logical_attempt_id=allocation["logical_attempt_id"],
                    terminal_status=SUCCESS,
                    launch_state=POPEN_OBSERVED,
                    sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
                    child_attempt_id=child_id,
                    parent_bound_child_claim_sha256=claim_sha256,
                    child_claim_event_sha256=campaign.state(campaign_id)["bound_arms"][allocation["allocation_id"]]["child_claim_event_sha256"],
                    child_start_event_sha256=child_start["event_sha256"],
                    witnessed_arm=packet,
                )
                campaign.terminal_arm(
                    campaign_id, allocation["allocation_id"], SUCCESS, POPEN_OBSERVED, evidence
                )
            else:
                evidence = composer._build_arm_terminal_evidence(
                    campaign_id=campaign_id,
                    allocation_id=allocation["allocation_id"],
                    logical_attempt_id=allocation["logical_attempt_id"],
                    terminal_status=status,
                    launch_state=START_DURABLE_POPEN_UNCERTAIN if status == BURN else POPEN_OBSERVED,
                    sandbox_arm_claim_sha256=allocation["sandbox_arm_claim_sha256"],
                )
                campaign.terminal_arm(
                    campaign_id,
                    allocation["allocation_id"],
                    status,
                    START_DURABLE_POPEN_UNCERTAIN if status == BURN else POPEN_OBSERVED,
                    evidence,
                )
                stopped = True

    terminal_status = SUCCESS if not stopped else VETO
    terminal_manifest = composer.build_campaign_terminal_manifest(
        campaign.state(campaign_id), campaign_root_id=campaign.root_id, terminal_status=terminal_status
    )
    if corrupt_terminal_manifest:
        terminal_manifest = _reseal({**terminal_manifest, "plan_evidence_sha256": _digest(8888)})
    campaign.terminal_campaign(campaign_id, terminal_status, terminal_manifest)
    monkeypatch.setattr(composer, "compose_witnessed_arm", lambda _journal, attempt: packets[attempt])
    return campaign, campaign_id, packets


def test_compose_campaign_emits_exact_success_pairs_and_uses_campaign_child_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, campaign_id, packets = _seal_campaign(tmp_path, monkeypatch)

    result = composer.compose_campaign(campaign, campaign_id)

    assert result["schema"] == composer.WITNESSED_COMPLETE_CAMPAIGN_PANEL_SCHEMA
    assert result["paired_cell_count"] == 2
    assert result["local_complete_set_outcomes_usable"] is True
    assert all(value["candidate_outcome"] == 1.0 for value in result["rows"])
    assert all(value["baseline_outcome"] == 0.0 for value in result["rows"])
    assert set(packets) == {child_attempt_id(campaign_id, f"a{index}") for index in range(4)}
    assert composer.validate_witnessed_complete_campaign_panel(campaign, campaign_id, result) == result


def test_veto_validates_plan_and_manifest_without_reopening_arm_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, campaign_id, _ = _seal_campaign(
        tmp_path, monkeypatch, statuses=[FAILURE, BURN, BURN, BURN]
    )
    monkeypatch.setattr(
        composer,
        "_reopen_terminal_evidence",
        lambda *_args: pytest.fail("VETO must not reopen per-arm terminal evidence"),
    )
    monkeypatch.setattr(
        composer,
        "compose_witnessed_arm",
        lambda *_args: pytest.fail("VETO must not reopen arm outcomes"),
    )

    result = composer.compose_campaign(campaign, campaign_id)

    assert result["schema"] == composer.CAMPAIGN_VETO_SCHEMA
    assert result["terminal_status"] == VETO
    assert result["outcomes_omitted"] is True
    assert "rows" not in result
    assert composer.validate_campaign_veto(result) == result


def test_prelaunch_veto_recomposes_from_exact_non_circular_manifest(tmp_path: Path) -> None:
    campaign = _campaign_journal(tmp_path / "prelaunch")
    campaign_id = campaign.claim_campaign(_plan(), EPOCH)["payload"]["campaign_id"]
    manifest = composer.build_prelaunch_veto_manifest(
        campaign.state(campaign_id),
        campaign_root_id=campaign.root_id,
    )
    campaign.veto_prelaunch(campaign_id, manifest)

    result = composer.compose_campaign(campaign, campaign_id)

    assert result["schema"] == composer.CAMPAIGN_VETO_SCHEMA
    assert result["terminal_status"] == VETO
    assert result["outcomes_omitted"] is True
    assert composer.compose_campaign(campaign, campaign_id) == result


def test_prelaunch_veto_rejects_generic_terminal_evidence(tmp_path: Path) -> None:
    campaign = _campaign_journal(tmp_path / "generic-prelaunch")
    campaign_id = campaign.claim_campaign(_plan(), EPOCH)["payload"]["campaign_id"]
    campaign.veto_prelaunch(campaign_id, {"campaign_id": campaign_id, "terminal_status": VETO})

    with pytest.raises(composer.CampaignCompositionError, match="prelaunch veto manifest"):
        composer.compose_campaign(campaign, campaign_id)


@pytest.mark.parametrize("mutation", ["terminal", "outcome"])
def test_success_rejects_invalid_recomposed_child_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    campaign, campaign_id, packets = _seal_campaign(tmp_path, monkeypatch)
    child_id = child_attempt_id(campaign_id, "a0")
    packets[child_id] = _reseal(
        {
            **packets[child_id],
            ("terminal_event_sha256" if mutation == "terminal" else "host_outcome"):
                _digest(5557) if mutation == "terminal" else 0.0,
        }
    )

    with pytest.raises(composer.CampaignCompositionError):
        composer.compose_campaign(campaign, campaign_id)


def test_corrupt_terminal_manifest_fails_closed_before_any_panel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    campaign, campaign_id, _ = _seal_campaign(tmp_path, monkeypatch, corrupt_terminal_manifest=True)

    with pytest.raises(composer.CampaignCompositionError, match="terminal manifest does not exactly match"):
        composer.compose_campaign(campaign, campaign_id)


def test_public_surface_has_no_child_handle_or_panel_builder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    campaign, campaign_id, _ = _seal_campaign(tmp_path, monkeypatch)
    panel = composer.compose_campaign(campaign, campaign_id)
    escalated = _reseal({**panel, "submission_authorized": True})
    with pytest.raises(composer.CampaignCompositionError, match="submission_authorized"):
        composer.validate_witnessed_complete_campaign_panel(campaign, campaign_id, escalated)

    assert not hasattr(campaign, "arm_journal")
    assert list(inspect.signature(composer.compose_campaign).parameters) == ["campaign_journal", "campaign_id"]
    assert not hasattr(composer, "build_witnessed_complete_campaign_panel")
    assert not hasattr(composer, "build_witnessed_campaign_panel")
    with pytest.raises(TypeError):
        composer.compose_campaign(campaign, campaign_id, plan=_plan())


def test_valid_draw_packet_maps_none_to_half() -> None:
    packet = _arm_packet(
        attempt_id="d" * 64,
        terminal_evidence_sha256=_digest(7000),
        terminal_event_sha256=_digest(7001),
        prepared_evidence_sha256=_digest(7002),
        started_evidence_sha256=_digest(7003),
        authority_id=_digest(7004),
        root_id=_digest(7005),
        outcome=0.5,
        winner_role=None,
        serial=70,
    )
    assert composer.validate_witnessed_arm_packet(packet)["host_outcome"] == 0.5


def test_composition_is_stable_after_unrelated_child_journal_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign, campaign_id, _ = _seal_campaign(tmp_path, monkeypatch)
    before = composer.compose_campaign(campaign, campaign_id)
    campaign._arm_journal.claim("unrelated-child-attempt", claim_sha256=_digest(6789))
    assert composer.compose_campaign(campaign, campaign_id) == before
