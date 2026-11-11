from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evaluation_v6_2.executor import (
    CalibrationCampaignExecutor,
    ExecutorError,
    REQUIRED_VERIFIER_PASSES,
)


BASE = datetime(2026, 7, 16, 0, 0, tzinfo=timezone.utc)


def _text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _population(*, final_name: bool = False) -> list[dict[str, object]]:
    ids = [*(f"D{i:02d}" for i in range(1, 7)), "DR01", *(f"C{i:02d}" for i in range(1, 9)), "CR01"]
    return [
        {
            "slot_id": unit_id,
            "archive_hash": f"{index + 1:064x}",
            "role": "DEV" if unit_id.startswith("D") else "CONFIRM",
            "upload_order": index + 1,
            "lineage_time_block_id": f"block-{index}",
            "source_family_id": f"source-{index}",
            "intervention_family_id": f"intervention-{index % 5}",
            "production_eligibility_flag": False,
            "production_ineligibility_reason": "calibration-only",
            "submission_name": "calibration-final" if final_name and index == 0 else f"calibration-{unit_id.lower()}",
            "unique_token": f"token-{index:02d}",
        }
        for index, unit_id in enumerate(ids)
    ]


def _receipt(**extra: object) -> dict[str, object]:
    return {"status": "PASS", **extra}


def _verifier() -> dict[str, object]:
    return _receipt(
        frozen=True,
        prereg_root_sha256="c" * 64,
        verifier_outputs={key: "PASS" for key in REQUIRED_VERIFIER_PASSES},
    )


def _inject_retired_intent(
    executor: CalibrationCampaignExecutor,
    *,
    at: datetime,
) -> dict[str, object]:
    """Exercise post-permit transitions without reopening retired authority."""
    state = executor._state()
    if state["active_unit_id"] is not None:
        raise ExecutorError("an active unit exists")
    unit_id = executor._next_unit_id(state)
    if unit_id is None:
        raise ExecutorError("no sequential campaign unit")
    row = state["units"][unit_id]["row"]
    permit: dict[str, object] = {
        "schema": "retired-test-fixture-only",
        "slot_id": unit_id,
        "archive_hash": row["archive_hash"],
        "unique_token": row["unique_token"],
    }
    executor._acquire_project_lock(unit_id)
    executor._append(
        "UPLOAD_INTENT_WRITTEN",
        {"unit_id": unit_id, "permit": permit},
        _text(at),
    )
    return permit


def _executor(tmp_path: Path, name: str = "campaign") -> CalibrationCampaignExecutor:
    return CalibrationCampaignExecutor(
        state_path=tmp_path / f"{name}.jsonl",
        campaign_id=name,
        project_lock_path=tmp_path / "project-upload-lock.json",
    )


def _dev_ready(executor: CalibrationCampaignExecutor) -> None:
    executor.freeze_population(_population(), now=_text(BASE))
    executor.lock_preregistration(_receipt(prereg_root_sha256="c" * 64), now=_text(BASE + timedelta(seconds=1)))
    executor.lock_local_evidence(_receipt(), now=_text(BASE + timedelta(seconds=2)))
    executor.open_dev_queue(now=_text(BASE + timedelta(seconds=3)))


def _bound_complete(executor: CalibrationCampaignExecutor, *, at: datetime = BASE + timedelta(minutes=1)) -> tuple[dict[str, object], datetime]:
    permit = _inject_retired_intent(executor, at=at)
    executor.reconcile_upload_matches(
        [{"unique_token": permit["unique_token"], "submission_ref": f"ref-{permit['slot_id']}"}],
        now=_text(at + timedelta(seconds=1)),
    )
    completed = at + timedelta(seconds=2)
    executor.observe_submission_status({"status": "COMPLETE", "observed_at_utc": _text(completed)}, now=_text(completed))
    return permit, completed


def _poll(ref: str, completed: datetime, ordinal: int, *, cutoff: float = 1000.0, skew_seconds: int = 0) -> dict[str, object]:
    observed = completed + timedelta(minutes=(60, 120, 240, 480)[ordinal - 1])
    return {
        "observed_at_utc": _text(observed),
        "score_observed_at_utc": _text(observed),
        "leaderboard_observed_at_utc": _text(observed + timedelta(seconds=skew_seconds)),
        "score": 600.0,
        "top10_cutoff": cutoff,
        "score_body_sha256": "a" * 64,
        "leaderboard_body_sha256": "b" * 64,
        "latest_two_submission_refs": [ref],
    }


def test_restart_preserves_complete_and_hash_chained_journal(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    _dev_ready(executor)
    permit, completed = _bound_complete(executor)

    restarted = _executor(tmp_path)
    status = restarted.status()

    assert status["state"] == "MATURITY_WAIT"
    assert status["units"][permit["slot_id"]]["first_observed_complete_at_utc"] == _text(completed)
    assert len((tmp_path / "campaign.jsonl").read_text(encoding="ascii").splitlines()) == 7
    assert status["production_budget_remaining"] == 1


def test_retired_permit_path_and_concurrent_project_unit_are_rejected(tmp_path: Path) -> None:
    executor = _executor(tmp_path, "one")
    _dev_ready(executor)
    _inject_retired_intent(executor, at=BASE + timedelta(minutes=1))
    with pytest.raises(ExecutorError, match="signed v6.2.2"):
        executor.issue_upload_permit(_verifier(), own_uploads_today=0, now=_text(BASE + timedelta(minutes=2)))

    other = _executor(tmp_path, "two")
    _dev_ready(other)
    with pytest.raises(ExecutorError, match="project-wide upload lock"):
        _inject_retired_intent(other, at=BASE + timedelta(minutes=3))


def test_duplicate_ambiguity_never_retries_and_closes_campaign(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    _dev_ready(executor)
    permit = _inject_retired_intent(executor, at=BASE + timedelta(minutes=1))
    status = executor.reconcile_upload_matches([], now=_text(BASE + timedelta(minutes=2)))
    assert status["state"] == "UPLOAD_AMBIGUOUS"
    status = executor.reconcile_upload_matches(
        [
            {"unique_token": permit["unique_token"], "submission_ref": "a"},
            {"unique_token": permit["unique_token"], "submission_ref": "b"},
        ],
        now=_text(BASE + timedelta(minutes=3)),
    )
    assert status["state"] == "CAMPAIGN_INCONCLUSIVE_UPLOAD_AMBIGUOUS"
    with pytest.raises(ExecutorError, match="unresolved upload intent"):
        executor.reconcile_upload_matches([], now=_text(BASE + timedelta(minutes=4)))


def test_poll_window_duplicate_fifth_skew_and_missing_cutoff_fail_closed(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    _dev_ready(executor)
    permit, completed = _bound_complete(executor)
    ref = f"ref-{permit['slot_id']}"
    early = _poll(ref, completed, 1)
    early["observed_at_utc"] = _text(completed + timedelta(minutes=59, seconds=59))
    with pytest.raises(ExecutorError, match="outside"):
        executor.record_poll(early, now=early["observed_at_utc"])
    bad_skew = _poll(ref, completed, 1, skew_seconds=61)
    with pytest.raises(ExecutorError, match="skew"):
        executor.record_poll(bad_skew, now=bad_skew["observed_at_utc"])
    missing_cutoff = _poll(ref, completed, 1)
    missing_cutoff.pop("top10_cutoff")
    with pytest.raises(ExecutorError, match="top10_cutoff"):
        executor.record_poll(missing_cutoff, now=missing_cutoff["observed_at_utc"])
    first = _poll(ref, completed, 1)
    executor.record_poll(first, now=first["observed_at_utc"])
    with pytest.raises(ExecutorError, match="outside"):
        executor.record_poll(first, now=first["observed_at_utc"])
    for ordinal in (2, 3, 4):
        item = _poll(ref, completed, ordinal)
        executor.record_poll(item, now=item["observed_at_utc"])
    assert executor.status()["state"] == "ENDPOINT_CLOSED"
    with pytest.raises(ExecutorError, match="not currently expected"):
        executor.record_poll(_poll(ref, completed, 4), now=_text(completed + timedelta(minutes=480)))


def test_late_poll_quota_latest_two_and_regime_break_are_terminal(tmp_path: Path) -> None:
    executor = _executor(tmp_path, "late")
    _dev_ready(executor)
    with pytest.raises(ExecutorError, match="signed v6.2.2"):
        executor.issue_upload_permit(_verifier(), own_uploads_today=4, now=_text(BASE + timedelta(minutes=1)))
    permit, completed = _bound_complete(executor, at=BASE + timedelta(minutes=2))
    ref = f"ref-{permit['slot_id']}"
    late = _poll(ref, completed, 1)
    late["observed_at_utc"] = _text(completed + timedelta(minutes=70, seconds=1))
    with pytest.raises(ExecutorError, match="outside"):
        executor.record_poll(late, now=late["observed_at_utc"])
    displaced = _poll(ref, completed, 1)
    displaced["latest_two_submission_refs"] = ["someone-else"]
    assert executor.record_poll(displaced, now=displaced["observed_at_utc"])["state"] == "CAMPAIGN_INTEGRITY_FAIL"

    regime = _executor(tmp_path, "regime")
    _dev_ready(regime)
    permit, completed = _bound_complete(regime, at=BASE + timedelta(minutes=3))
    ref = f"ref-{permit['slot_id']}"
    one = _poll(ref, completed, 1, cutoff=1000)
    regime.record_poll(one, now=one["observed_at_utc"])
    two = _poll(ref, completed, 2, cutoff=1100)
    assert regime.record_poll(two, now=two["observed_at_utc"])["state"] == "CAMPAIGN_INCONCLUSIVE_REGIME_BREAK"


def test_second_pre_maturity_failure_exhausts_tranche_reserve(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    _dev_ready(executor)
    _, first_time = _bound_complete(executor)
    executor.record_pre_maturity_failure(
        {"verified_technical_failure": True, "kind": "complete-to-error"},
        now=_text(first_time + timedelta(minutes=1)),
    )
    assert executor.status()["state"] == "DEV_QUEUE_READY"
    _, second_time = _bound_complete(executor, at=first_time + timedelta(minutes=2))
    status = executor.record_pre_maturity_failure(
        {"verified_technical_failure": True, "kind": "complete-to-error"},
        now=_text(second_time + timedelta(minutes=1)),
    )
    assert status["state"] == "CAMPAIGN_INCONCLUSIVE"
    assert status["production_budget_remaining"] == 1


def test_population_rejects_final_name_and_production_never_changes(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    with pytest.raises(ExecutorError, match="must not contain 'final'"):
        executor.freeze_population(_population(final_name=True), now=_text(BASE))
    _dev_ready(executor)
    assert executor.status()["calibration_budget_remaining"] == 16
    assert executor.status()["production_budget_remaining"] == 1
