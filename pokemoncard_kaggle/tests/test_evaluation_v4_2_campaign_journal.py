from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import evaluation_v4_2.campaign_journal as campaign_module
from evaluation_v4_2.campaign_journal import (
    BURN,
    FAILURE,
    NEVER_STARTED,
    POPEN_OBSERVED,
    START_DURABLE_POPEN_UNCERTAIN,
    SUCCESS,
    VETO,
    CampaignJournal,
    CampaignJournalError,
    JournalIntegrityError,
    TransitionError,
)
from evaluation_v4_2.campaign_preparation import (
    CampaignPreparationError,
    build_campaign_prepared_manifest,
    build_prepared_allocation,
    validate_campaign_prepared_manifest,
)
from evaluation_v4_2.parent_arm_claim import child_attempt_id
from evaluation_v4_2.witness_journal import canonical_sha256


KEY = b"campaign-journal-test-key"
EPOCH = "d" * 64
CANDIDATE = "c" * 64


def _plan() -> dict[str, object]:
    allocations = []
    for ordinal, (allocation_id, wave, slot) in enumerate(
        (("a0", 0, 0), ("a1", 0, 1), ("a2", 1, 0), ("a3", 1, 1))
    ):
        allocations.append(
            {
                "allocation_id": allocation_id,
                "ordinal": ordinal,
                "wave": wave,
                "slot": slot,
                "logical_attempt_id": f"attempt-{allocation_id}",
                "logical_claim_content_sha256": f"{50 + ordinal:064x}",
                "sandbox_arm_claim_sha256": f"{100 + ordinal:064x}",
                "bundle_manifest_sha256": f"{200 + ordinal:064x}",
                "bundle_tree_sha256": f"{300 + ordinal:064x}",
                "bundle_task_spec_sha256": f"{400 + ordinal:064x}",
                "runtime_bundle_sha256": f"{500 + ordinal:064x}",
                "worker_source_sha256": f"{600 + ordinal:064x}",
                "normalized_policy_identity_sha256": f"{650 + ordinal:064x}",
            }
        )
    return {
        "content_sha256": "a" * 64,
        "candidate_normalized_identity_sha256": CANDIDATE,
        "runner_binding_content_sha256": "f" * 64,
        "allocations": allocations,
        "runner_binding": {"scheduler_width": 2},
    }


@pytest.fixture(autouse=True)
def synthetic_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(campaign_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(
        campaign_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda value, **_kwargs: value,
    )


def _journal(path: Path) -> CampaignJournal:
    return CampaignJournal(path, KEY, key_id="campaign-test-key", domain="tests.campaign")


def _claim(journal: CampaignJournal) -> str:
    return journal.claim_campaign(_plan(), EPOCH)["payload"]["campaign_id"]


def _command_templates() -> dict[str, list[str]]:
    return {
        role: [
            "/usr/bin/docker",
            "run",
            role,
            "$SNAPSHOT",
            "$CHILD_CLAIM_SHA256",
            "$ARM_BOUND_EVENT_SHA256",
            "$CHILD_START_EVENT_SHA256",
            "$SESSION_ID",
        ]
        for role in ("referee", "candidate_policy", "opponent_policy")
    }


def _prepared_manifest(journal: CampaignJournal, campaign_id: str) -> dict[str, object]:
    plan = journal.read_campaign_plan(campaign_id)
    state = journal.state(campaign_id)
    prepared = []
    for index, allocation in enumerate(plan["allocations"]):
        snapshot_digest = journal.evidence.put(
            {"schema": "test-snapshot", "allocation_id": allocation["allocation_id"]}
        )
        prepared.append(
            build_prepared_allocation(
                plan,
                state,
                allocation,
                snapshot_manifest_sha256=snapshot_digest,
                snapshot_tree_sha256=f"{700 + index:064x}",
                normalized_command_templates=_command_templates(),
            )
        )
    return build_campaign_prepared_manifest(plan, state, prepared)


def _prepare(journal: CampaignJournal, campaign_id: str) -> None:
    journal.prepare_campaign(campaign_id, _prepared_manifest(journal, campaign_id))


def _start(journal: CampaignJournal, campaign_id: str) -> None:
    journal.start_campaign(campaign_id, {"phase": "campaign-start", "campaign_id": campaign_id})


def _wave(journal: CampaignJournal, campaign_id: str, wave: int) -> None:
    journal.start_wave(
        campaign_id,
        wave,
        runtime_verification={"phase": "runtime-verification", "wave": wave},
    )


def _claim_child(
    journal: CampaignJournal, campaign_id: str, allocation_id: str
) -> tuple[str, str, str]:
    attempt_id = child_attempt_id(campaign_id, allocation_id)
    claim_sha256 = f"{2000 + int(allocation_id[1:]):064x}"
    event = journal._arm_journal.claim(attempt_id, claim_sha256)
    return attempt_id, claim_sha256, event["event_sha256"]


def _bind(journal: CampaignJournal, campaign_id: str, allocation_id: str) -> dict[str, object]:
    attempt_id, claim_sha256, event_sha256 = _claim_child(
        journal, campaign_id, allocation_id
    )
    return journal.bind_arm(
        campaign_id,
        allocation_id,
        attempt_id,
        claim_sha256,
        event_sha256,
    )


def test_claim_exposes_only_read_only_child_identity_and_campaign_root_id(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    state = journal.state(campaign_id)

    assert not hasattr(journal, "arm_journal")
    assert state["root_id"] == journal.root_id
    assert state["arm_witness_authority_id"] == journal.arm_witness_authority_id
    assert state["arm_witness_root_id"] == journal.arm_witness_root_id
    assert state["claim_event_sha256"] == journal.events()[0]["event_sha256"]
    assert state["global_one_shot_verified"] is False
    assert state["submission_authorized"] is False


def test_campaign_start_requires_non_null_cas_evidence(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)

    with pytest.raises(CampaignJournalError, match="evidence"):
        journal.start_campaign(campaign_id)
    with pytest.raises(CampaignJournalError, match="lowercase SHA"):
        journal.start_campaign(campaign_id, evidence_sha256="missing")

    start = journal.start_campaign(campaign_id, {"start": "durable"})
    assert start["payload"]["start_evidence_sha256"]
    assert journal.state(campaign_id)["start_event_sha256"] == start["event_sha256"]


def test_campaign_start_rejects_semantically_invalid_runtime_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    monkeypatch.setattr(
        campaign_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("runtime drift")),
    )

    with pytest.raises(JournalIntegrityError, match="runtime drift"):
        journal.start_campaign(campaign_id, {"phase": "campaign-start"})
    assert journal.state(campaign_id)["state"] == "PREPARED"


def test_wave_start_requires_runtime_verification_cas_and_exports_string_keyed_map(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)

    with pytest.raises(CampaignJournalError, match="evidence"):
        journal.start_wave(campaign_id, 0)
    digest = journal.evidence.put({"runtime": "verified", "wave": 0})
    wave = journal.start_wave(campaign_id, 0, runtime_verification_sha256=digest)
    state = journal.state(campaign_id)
    assert wave["payload"]["runtime_verification_sha256"] == digest
    assert state["wave_runtime_verification_sha256s"] == {"0": digest}
    assert state["wave_start_event_sha256s"] == {"0": wave["event_sha256"]}


def test_wave_start_rejects_semantically_invalid_runtime_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    def validate_runtime(value, *, phase, **_kwargs):
        if phase == "wave_start":
            raise ValueError("wave runtime drift")
        return value

    monkeypatch.setattr(
        campaign_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        validate_runtime,
    )

    with pytest.raises(JournalIntegrityError, match="wave runtime drift"):
        journal.start_wave(
            campaign_id,
            0,
            runtime_verification={"phase": "runtime-verification", "wave": 0},
        )
    assert journal.state(campaign_id)["started_waves"] == []


def test_arm_bound_is_exact_after_wave_and_before_terminal(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)

    with pytest.raises(TransitionError, match="prior ARM_BOUND"):
        journal.terminal_arm(campaign_id, "a0", SUCCESS, POPEN_OBSERVED)
    bound = _bind(journal, campaign_id, "a0")
    terminal = journal.terminal_arm(campaign_id, "a0", SUCCESS, POPEN_OBSERVED)
    state = journal.state(campaign_id)

    assert bound["event_type"] == "ARM_BOUND"
    assert set(bound["payload"]) == {
        "campaign_id", "allocation_id", "wave", "child_attempt_id",
        "child_claim_sha256", "child_claim_event_sha256",
    }
    assert journal.events().index(bound) < journal.events().index(terminal)
    assert state["arm_bound_event_sha256s"] == {"a0": bound["event_sha256"]}
    assert state["dispositions"]["a0"]["arm_bound_event_sha256"] == bound["event_sha256"]


def test_arm_bound_rejects_missing_foreign_or_duplicate_child_claim(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)
    attempt_id, claim_sha256, event_sha256 = _claim_child(journal, campaign_id, "a0")

    with pytest.raises(TransitionError, match="owned arm witness"):
        journal.bind_arm(campaign_id, "a0", attempt_id, claim_sha256, "0" * 64)
    with pytest.raises(TransitionError, match="differs"):
        journal.bind_arm(campaign_id, "a0", "attempt-a1", claim_sha256, event_sha256)

    journal.bind_arm(campaign_id, "a0", attempt_id, claim_sha256, event_sha256)
    with pytest.raises(TransitionError, match="retries"):
        journal.bind_arm(campaign_id, "a0", attempt_id, claim_sha256, event_sha256)


def test_launch_states_enforce_active_crash_phase_and_future_remainder(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)
    _bind(journal, campaign_id, "a0")
    _bind(journal, campaign_id, "a1")

    with pytest.raises(TransitionError, match="POPEN_OBSERVED"):
        journal.terminal_arm(campaign_id, "a0", SUCCESS, NEVER_STARTED)
    with pytest.raises(TransitionError, match="non-observed"):
        journal.terminal_arm(campaign_id, "a0", BURN, POPEN_OBSERVED)

    journal.terminal_arm(campaign_id, "a0", BURN, START_DURABLE_POPEN_UNCERTAIN)
    journal.terminal_arm(campaign_id, "a1", FAILURE, POPEN_OBSERVED)
    with pytest.raises(TransitionError, match="NEVER_STARTED"):
        journal.terminal_arm(campaign_id, "a2", BURN, START_DURABLE_POPEN_UNCERTAIN)
    journal.terminal_arm(campaign_id, "a2", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a3", BURN, NEVER_STARTED)
    journal.terminal_campaign(campaign_id, VETO)

    state = journal.state(campaign_id)
    assert state["dispositions"]["a0"]["launch_state"] == START_DURABLE_POPEN_UNCERTAIN
    assert state["dispositions"]["a2"]["launch_state"] == NEVER_STARTED


def test_pre_arm_runtime_failure_burns_active_and_future_allocations_without_launch(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)

    journal.terminal_arm(campaign_id, "a0", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a1", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a2", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a3", BURN, NEVER_STARTED)
    journal.terminal_campaign(campaign_id, VETO)

    state = journal.state(campaign_id)
    assert state["terminal_status"] == VETO
    assert all(
        item["terminal_status"] == BURN and item["launch_state"] == NEVER_STARTED
        for item in state["dispositions"].values()
    )


def test_recovery_can_burn_canonical_future_after_a_completed_successful_wave(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)
    for allocation_id in ("a0", "a1"):
        _bind(journal, campaign_id, allocation_id)
        journal.terminal_arm(campaign_id, allocation_id, SUCCESS, POPEN_OBSERVED)

    with pytest.raises(TransitionError, match="canonical next"):
        journal.terminal_arm(campaign_id, "a3", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a2", BURN, NEVER_STARTED)
    journal.terminal_arm(campaign_id, "a3", BURN, NEVER_STARTED)
    journal.terminal_campaign(campaign_id, VETO)
    assert journal.state(campaign_id)["terminal_status"] == VETO


@pytest.mark.parametrize("phase", ["CLAIMED", "PREPARED", "STARTED"])
def test_prelaunch_veto_consumes_every_allocation_without_launches(
    tmp_path: Path, phase: str
) -> None:
    journal = _journal(tmp_path / phase.lower())
    campaign_id = _claim(journal)
    if phase != "CLAIMED":
        _prepare(journal, campaign_id)
    if phase == "STARTED":
        _start(journal, campaign_id)

    event = journal.veto_prelaunch(campaign_id, {"reason": "crash-recovery", "phase": phase})
    state = journal.state(campaign_id)
    assert event["event_type"] == "CAMPAIGN_TERMINAL"
    assert state["state"] == "TERMINAL"
    assert state["terminal_status"] == VETO
    assert all(
        item["terminal_status"] == BURN and item["launch_state"] == NEVER_STARTED
        for item in state["dispositions"].values()
    )
    with pytest.raises(TransitionError):
        journal.veto_prelaunch(campaign_id)


def test_success_requires_bound_popen_observed_allocation_and_no_retries(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    with pytest.raises(TransitionError, match="one-shot"):
        journal.claim_campaign(_plan(), EPOCH)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)

    for wave, allocation_ids in ((0, ("a0", "a1")), (1, ("a2", "a3"))):
        _wave(journal, campaign_id, wave)
        for allocation_id in allocation_ids:
            _bind(journal, campaign_id, allocation_id)
            journal.terminal_arm(campaign_id, allocation_id, SUCCESS, POPEN_OBSERVED)

    terminal = journal.terminal_campaign(campaign_id, SUCCESS)
    assert terminal["payload"]["terminal_status"] == SUCCESS
    with pytest.raises(TransitionError, match="TERMINAL"):
        journal.terminal_campaign(campaign_id, SUCCESS)


def test_replay_rejects_tampered_required_runtime_or_start_evidence(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    _prepare(journal, campaign_id)
    _start(journal, campaign_id)
    _wave(journal, campaign_id, 0)
    events = deepcopy(journal.events())
    events[-1]["payload"]["runtime_verification_sha256"] = "0" * 64
    # The event signature fails first, which is the required fail-closed behavior.
    journal._journal_path.write_bytes(
        b"".join(campaign_module.canonical_json_bytes(event) + b"\n" for event in events)
    )
    with pytest.raises(JournalIntegrityError):
        _journal(tmp_path / "root").verify()


def test_prepare_rejects_identifier_only_manifest_and_resealed_plan_drift(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    plan = journal.read_campaign_plan(campaign_id)
    state = journal.state(campaign_id)

    with pytest.raises(CampaignPreparationError, match="child claim template"):
        build_campaign_prepared_manifest(
            plan,
            state,
            [{"allocation_id": item["allocation_id"]} for item in plan["allocations"]],
        )

    manifest = _prepared_manifest(journal, campaign_id)
    changed = deepcopy(manifest)
    changed_child = changed["allocations"][0]
    changed_child["bundle_tree_sha256"] = "9" * 64
    child_content = {
        key: value for key, value in changed_child.items() if key != "content_sha256"
    }
    changed_child["content_sha256"] = canonical_sha256(child_content)
    changed["allocation_set_sha256"] = canonical_sha256(
        [item["content_sha256"] for item in changed["allocations"]]
    )
    manifest_content = {key: value for key, value in changed.items() if key != "content_sha256"}
    changed["content_sha256"] = canonical_sha256(manifest_content)
    with pytest.raises(CampaignPreparationError, match="differs from campaign allocation"):
        validate_campaign_prepared_manifest(changed, plan, state)


def test_prepare_rejects_snapshot_manifest_missing_from_campaign_cas(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "root")
    campaign_id = _claim(journal)
    plan = journal.read_campaign_plan(campaign_id)
    state = journal.state(campaign_id)
    prepared = []
    for index, allocation in enumerate(plan["allocations"]):
        snapshot_digest = (
            "8" * 64
            if index == 0
            else journal.evidence.put(
                {"schema": "test-snapshot", "allocation_id": allocation["allocation_id"]}
            )
        )
        prepared.append(
            build_prepared_allocation(
                plan,
                state,
                allocation,
                snapshot_manifest_sha256=snapshot_digest,
                snapshot_tree_sha256=f"{1700 + index:064x}",
                normalized_command_templates=_command_templates(),
            )
        )
    manifest = build_campaign_prepared_manifest(plan, state, prepared)
    with pytest.raises(JournalIntegrityError, match="snapshot_manifest_sha256"):
        journal.prepare_campaign(campaign_id, manifest)


def test_real_campaign_preparation_covers_all_1536_allocations(tmp_path: Path) -> None:
    from tests.test_evaluation_v4_2_campaign_protocol import _full_fixture

    _, _, _, plan = _full_fixture()
    journal = _journal(tmp_path / "real")
    campaign_id = journal.claim_campaign(plan, EPOCH)["payload"]["campaign_id"]
    state = journal.state(campaign_id)
    prepared = []
    for allocation in plan["allocations"]:
        snapshot_digest = journal.evidence.put(
            {
                "schema": "test-real-snapshot",
                "allocation_id": allocation["allocation_id"],
                "bundle_manifest_sha256": allocation["bundle_manifest_sha256"],
            }
        )
        prepared.append(
            build_prepared_allocation(
                plan,
                state,
                allocation,
                snapshot_manifest_sha256=snapshot_digest,
                snapshot_tree_sha256=allocation["bundle_tree_sha256"],
                normalized_command_templates=_command_templates(),
            )
        )
    manifest = build_campaign_prepared_manifest(plan, state, prepared)
    journal.prepare_campaign(campaign_id, manifest)
    assert manifest["prepared_allocation_count"] == 1536
    assert len(journal.state(campaign_id)["allocation_ids"]) == 1536
