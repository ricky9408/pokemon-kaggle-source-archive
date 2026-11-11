from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import evaluation_v4_1.executor as executor_module
import evaluation_v4_1.kaggle_evidence as kaggle_evidence_module
from evaluation_v4_1.authorization import guard_research_submission, validate_usage_ledger
from evaluation_v4_1.chronology import build_pair_completion_barrier, build_submission_receipt
from evaluation_v4_1.executor import ExecutorError, VOIP5CalibrationExecutor
from tests.test_evaluation_v4_1_chronology import _fixture


@pytest.fixture(autouse=True)
def _authenticated_preflight_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def preflight(**kwargs: object) -> dict[str, object]:
        nonlocal calls
        checked = f"2026-07-11T09:{30 + calls * 6:02d}:00.000000Z"
        calls += 1
        return {
            "checked_at_utc": checked,
            "archive_name": kwargs["archive_name"],
            "submission_description": kwargs["submission_description"],
        }

    monkeypatch.setattr(
        executor_module,
        "authenticated_upload_preflight",
        preflight,
    )
    monkeypatch.setattr(
        executor_module,
        "validate_authenticated_upload_preflight",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        executor_module,
        "validate_hosted_observation",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        executor_module,
        "submit_exact_archive_once",
        lambda **_: {"invoked_at_utc": "2026-07-11T09:30:30.000000Z"},
    )

    hosted_calls = 0

    def observe(**kwargs: object) -> dict[str, object]:
        nonlocal hosted_calls
        hosted_calls += 1
        member_index = int(str(kwargs["submission_description"]).rsplit("-", 1)[1])
        return {
            "archive_name": kwargs["archive_name"],
            "archive_sha256": kwargs["archive_sha256"],
            "submission_description": kwargs["submission_description"],
            "submission_ref": str(12344 + member_index),
            "submission_created_at_utc": f"2026-07-11T09:03:{(member_index - 1) * 10:02d}.000000Z",
            "submission_status": "SubmissionStatus.PENDING",
            "observed_at_utc": f"2026-07-11T09:{26 + hosted_calls * 6:02d}:00.000000Z",
        }

    monkeypatch.setattr(executor_module, "observe_hosted_submission", observe)

    def completed_receipt(**kwargs: object) -> dict[str, object]:
        hosted = kwargs["hosted_observation"]
        archive = Path(kwargs["local_archive"])
        return build_submission_receipt(
            authorization=kwargs["authorization"],
            permit=kwargs["permit"],
            usage_ledger_path=kwargs["usage_ledger_path"],
            artifacts=kwargs["artifacts"],
            authenticated_submissions_csv=archive.parent / "submissions.csv",
            local_archive=archive,
            submission_ref=hosted["submission_ref"],
            expected_description=kwargs["submission_description"],
            first_observed_complete_at_utc=hosted["observed_at_utc"],
        )

    monkeypatch.setattr(
        executor_module,
        "build_live_completed_submission_receipt",
        completed_receipt,
    )


def _executor(tmp_path: Path, fixture: dict[str, object]) -> VOIP5CalibrationExecutor:
    state_path = tmp_path / "executor.jsonl"
    ledger_path = Path(fixture["ledger"])
    if not state_path.exists() and ledger_path.exists():
        ledger_path.unlink()
    return VOIP5CalibrationExecutor(
        state_path=state_path,
        ledger_path=ledger_path,
        authorization=fixture["authorization"],
        artifacts=fixture["artifacts"],
    )


def _reconcile(
    executor: VOIP5CalibrationExecutor,
    fixture: dict[str, object],
    *,
    index: int,
    now: str = "2026-07-11T09:31:00.000000Z",
) -> dict[str, object]:
    lineage_uuid = fixture["authorization"]["archive_assignments"][index]["lineage_uuid"]
    evidence = fixture["pair_evidence"][lineage_uuid]
    original_receipt = evidence["submission_receipt"]
    usage_sequence = index + 1
    current_state = executor.status()["current_pair"][index % 2]
    if current_state["hosted"] is None:
        executor.upload_exact_archive(
            usage_sequence=usage_sequence,
            local_archive=evidence["local_archive"],
            submission_description=original_receipt["submission_description"],
        )
    return executor.reconcile_completed_submission(usage_sequence=usage_sequence)


def test_prepare_issues_only_exact_nonproduction_next_permit(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)

    permits = executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")

    assert [permit["slot"] for permit in permits] == [1, 2]
    assert all(permit["pair_id"] == "pair-01" for permit in permits)
    assert all(permit["research_only"] is True for permit in permits)
    assert all(permit["production_submission_authorized"] is False for permit in permits)
    assert executor.status()["state"] == "PAIR_ISSUED"
    with pytest.raises(ExecutorError, match="fully reconcile"):
        executor.prepare_pair(now="2026-07-11T09:02:01.000000Z")


def test_restart_reconciles_consumed_permit_without_another_slot(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    request = executor._expected_request(0, None)

    # This models the narrow crash window after guard_research_submission fsyncs
    # its ledger event and before the executor fsyncs its ISSUE event.
    lock = executor._with_lock()
    try:
        events = executor._read_events()
        executor._append(events, "PREPARE", request, "2026-07-11T09:02:00.000000Z")
    finally:
        import fcntl

        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
    consumed = guard_research_submission(
        fixture["authorization"],
        executor.ledger_path,
        artifacts=fixture["artifacts"],
        **{key: request[key] for key in request if key != "prior_pair_barrier_content_sha256"},
        now="2026-07-11T09:02:00.000000Z",
    )

    restarted = _executor(tmp_path, fixture)
    permits = restarted.resume_pair(now="2026-07-11T09:02:01.000000Z")
    receipt = _reconcile(restarted, fixture, index=0)
    _reconcile(restarted, fixture, index=1, now="2026-07-11T09:33:00.000000Z")

    assert receipt["permit_content_sha256"] == consumed["content_sha256"]
    assert permits[0]["content_sha256"] == consumed["content_sha256"]
    assert len(validate_usage_ledger(restarted.ledger_path, fixture["authorization"], artifacts=fixture["artifacts"])) == 2
    assert restarted.status()["state"] == "READY"


def test_upload_claim_is_one_shot_across_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")
    evidence = next(iter(fixture["pair_evidence"].values()))
    receipt = evidence["submission_receipt"]
    with pytest.raises(ExecutorError, match="claimed and hosted"):
        executor.reconcile_completed_submission(usage_sequence=1)
    submit_calls = 0

    def submit(**_: object) -> dict[str, object]:
        nonlocal submit_calls
        submit_calls += 1
        return {"invoked_at_utc": "2026-07-11T09:30:30.000000Z"}

    monkeypatch.setattr(executor_module, "submit_exact_archive_once", submit)
    monkeypatch.setattr(
        executor_module,
        "observe_hosted_submission",
        lambda **_: (_ for _ in ()).throw(RuntimeError("history propagation delay")),
    )
    with pytest.raises(ExecutorError, match="not yet uniquely hosted"):
        executor.upload_exact_archive(
            usage_sequence=1,
            local_archive=evidence["local_archive"],
            submission_description=receipt["submission_description"],
        )
    restarted = _executor(tmp_path, fixture)
    assert restarted.status()["state"] == "PAIR_UPLOAD_PARTIAL"
    with pytest.raises(ExecutorError, match="already claimed"):
        restarted.upload_exact_archive(
            usage_sequence=1,
            local_archive=evidence["local_archive"],
            submission_description=receipt["submission_description"],
        )
    monkeypatch.setattr(
        executor_module,
        "observe_hosted_submission",
        lambda **kwargs: {
            "archive_name": kwargs["archive_name"],
            "archive_sha256": kwargs["archive_sha256"],
            "submission_description": kwargs["submission_description"],
            "submission_ref": receipt["submission_ref"],
            "submission_created_at_utc": receipt["submission_created_at_utc"],
            "submission_status": "SubmissionStatus.PENDING",
            "observed_at_utc": "2026-07-11T09:32:00.000000Z",
        },
    )
    assert restarted.recover_claimed_upload(usage_sequence=1)["submission_ref"] == receipt["submission_ref"]
    assert restarted.reconcile_completed_submission(usage_sequence=1)["submission_ref"] == receipt["submission_ref"]
    assert submit_calls == 1
    assert restarted.status()["state"] == "PAIR_HOSTED_PARTIAL"


def test_executor_keeps_exact_bytes_when_path_swaps_after_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")
    evidence = next(iter(fixture["pair_evidence"].values()))
    archive = evidence["local_archive"]
    authorized_bytes = archive.read_bytes()
    observed: list[bytes] = []

    def swapping_preflight(**kwargs: object) -> dict[str, object]:
        archive.write_bytes(b"unauthorized replacement after parent read")
        return {
            "checked_at_utc": "2026-07-11T09:30:00.000000Z",
            "archive_name": kwargs["archive_name"],
            "submission_description": kwargs["submission_description"],
        }

    def exact_submit(**kwargs: object) -> dict[str, object]:
        observed.append(kwargs["archive_bytes"])
        return {"invoked_at_utc": "2026-07-11T09:30:30.000000Z"}

    monkeypatch.setattr(executor_module, "authenticated_upload_preflight", swapping_preflight)
    monkeypatch.setattr(executor_module, "submit_exact_archive_once", exact_submit)
    executor.upload_exact_archive(
        usage_sequence=1,
        local_archive=archive,
        submission_description=evidence["submission_receipt"]["submission_description"],
    )
    assert observed == [authorized_bytes]
    assert archive.read_bytes() != authorized_bytes


def test_pair_two_requires_exact_preceding_raw_pair_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    permits: dict[str, dict[str, object]] = {}
    receipts: dict[str, dict[str, object]] = {}
    pair_permits = executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")
    for index in (0, 1):
        permit = pair_permits[index]
        receipt = _reconcile(
            executor,
            fixture,
            index=index,
            now=f"2026-07-11T09:{31 + index * 2:02d}:00.000000Z",
        )
        lineage_uuid = permit["lineage_uuid"]
        permits[lineage_uuid] = permit
        receipts[lineage_uuid] = receipt

    evidence = {}
    for lineage_uuid, original in fixture["pair_evidence"].items():
        evidence[lineage_uuid] = {**original, "permit": permits[lineage_uuid], "submission_receipt": receipts[lineage_uuid]}
    barrier = build_pair_completion_barrier(
        authorization=fixture["authorization"],
        pair_id="pair-01",
        usage_ledger_path=executor.ledger_path,
        artifacts=fixture["artifacts"],
        member_evidence_by_lineage_uuid=evidence,
    )

    with pytest.raises(ExecutorError, match="lacks a direct authenticated Kaggle capture"):
        executor.prepare_pair(now="2026-07-11T09:34:00.000000Z")
    assert executor.status()["state"] == "READY"
    manifest = {
        lineage_uuid: {
            "permit": row["permit"],
            "submission_receipt": row["submission_receipt"],
            "authenticated_submissions_csv": str(row["authenticated_submissions_csv"]),
            "local_archive": str(row["local_archive"]),
            "submission_directory": str(row["submission_directory"]),
            "team_name": row["team_name"],
        }
        for lineage_uuid, row in evidence.items()
    }
    capture = {
        "pair_id": "pair-01",
        "captured_at_utc": "2026-07-11T09:40:00.000000Z",
        "pair_completion_barrier": barrier,
        "member_evidence_manifest": manifest,
    }
    online_snapshot = {
        "pair_id": "pair-01",
        "pair_completion_barrier": barrier,
    }
    monkeypatch.setattr(executor_module, "capture_authenticated_pair", lambda **_: capture)
    monkeypatch.setattr(
        executor_module,
        "validate_authenticated_pair_capture",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        kaggle_evidence_module,
        "validate_authenticated_pair_capture",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        executor_module,
        "reverify_authenticated_pair_capture_online",
        lambda value, **_: online_snapshot,
    )
    monkeypatch.setattr(
        kaggle_evidence_module,
        "reverify_authenticated_pair_capture_online",
        lambda value, **_: online_snapshot,
    )
    monkeypatch.setattr(
        kaggle_evidence_module,
        "validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        executor_module,
        "validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    executor.capture_completed_pair(
        team_name="GarlicToday",
        capture_directory=tmp_path / "capture-pair-01",
    )
    permits = executor.prepare_pair(now="2026-07-11T09:41:00.000000Z")
    assert all(permit["pair_id"] == "pair-02" for permit in permits)
    assert all(
        permit["prior_pair_barrier_content_sha256"] == barrier["content_sha256"]
        for permit in permits
    )
    assert all(permit["production_submission_authorized"] is False for permit in permits)


def test_tampered_journal_and_wrong_authenticated_binding_fail_closed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")

    evidence = next(iter(fixture["pair_evidence"].values()))
    wrong_root = tmp_path / "wrong"
    wrong_root.mkdir()
    wrong_archive = wrong_root / evidence["local_archive"].name
    wrong_archive.write_bytes(b"wrong archive bytes")
    with pytest.raises(ExecutorError, match="frozen SHA-256"):
        executor.upload_exact_archive(
            usage_sequence=1,
            local_archive=wrong_archive,
            submission_description=evidence["submission_receipt"]["submission_description"],
        )
    executor.upload_exact_archive(
        usage_sequence=1,
        local_archive=evidence["local_archive"],
        submission_description=evidence["submission_receipt"]["submission_description"],
    )
    evidence["local_archive"].write_bytes(b"replacement after durable byte custody")
    claim = executor.status()["current_pair"][0]["claim"]
    assert claim["production_submission_authorized"] is False
    assert executor.status()["state"] == "PAIR_HOSTED_PARTIAL"
    with pytest.raises(ExecutorError, match="already claimed"):
        executor.upload_exact_archive(
            usage_sequence=1,
            local_archive=evidence["local_archive"],
            submission_description=evidence["submission_receipt"]["submission_description"],
        )

    journal = tmp_path / "executor.jsonl"
    event = json.loads(journal.read_text(encoding="ascii").splitlines()[0])
    event["payload"]["archive_name"] = "tampered.tar.gz"
    journal.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    with pytest.raises(ExecutorError, match="event_sha256 mismatch"):
        executor.status()


def test_executor_refuses_upload_after_wall_clock_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    executor = _executor(tmp_path, fixture)
    executor.prepare_pair(now="2026-07-11T09:02:00.000000Z")
    evidence = next(iter(fixture["pair_evidence"].values()))
    monkeypatch.setattr(
        executor_module,
        "_wall_now",
        lambda: datetime(2026, 7, 12, 9, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(ExecutorError, match="wall-clock upload window"):
        executor.upload_exact_archive(
            usage_sequence=1,
            local_archive=evidence["local_archive"],
            submission_description=evidence["submission_receipt"]["submission_description"],
        )
