from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import threading

import pytest

import evaluation_v4_2.witness_journal as witness_module
from evaluation_v4_2.witness_journal import (
    AUTHORITY,
    CompositionError,
    EvidenceError,
    JournalIntegrityError,
    TransitionError,
    WitnessJournal,
    WitnessJournalError,
    compose_terminal_evidence,
)


KEY = b"witness-test-key"


def _claim_in_process(arguments: tuple[str, str, str]) -> str:
    root, attempt_id, claim_sha256 = arguments
    journal = WitnessJournal(root, KEY, key_id="test-key", domain="tests.witness")
    try:
        journal.claim(attempt_id, claim_sha256)
    except TransitionError:
        return "duplicate"
    return "ok"


def _journal(path: Path) -> WitnessJournal:
    return WitnessJournal(path, KEY, key_id="test-key", domain="tests.witness")


def _claim(journal: WitnessJournal, name: str = "attempt") -> str:
    digest = hashlib.sha256(name.encode("ascii")).hexdigest()
    journal.claim(name, digest, artifact_root=journal.root / "caller-artifacts")
    return digest


def _started(journal: WitnessJournal, name: str = "attempt") -> None:
    _claim(journal, name)
    journal.prepare(name)
    journal.start(name)


def test_state_machine_and_closed_authority(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    _started(journal)
    event = journal.terminal("attempt", "FAILURE", {"result": "burn"})

    assert journal.state("attempt")["state"] == "TERMINAL"
    assert event["payload"]["terminal_status"] == "FAILURE"
    composed = journal.compose_attempt("attempt")
    assert composed["evidence"] == {"result": "burn"}
    assert composed["authority"] == AUTHORITY
    assert all(composed[name] is False for name in (
        "remote_attestation_verified", "native_platform_verified",
        "latency_parity_allowed", "randomization_allowed", "submit_authorized",
        "anchor_allowed", "production_submission_authorized",
    ))


def test_composed_attempt_identity_is_stable_after_later_journal_events(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "journal")
    _started(journal, "first")
    journal.terminal("first", "SUCCESS", {"result": "first"})
    first = journal.compose_attempt("first")

    _started(journal, "second")
    journal.terminal("second", "SUCCESS", {"result": "second"})
    recomposed = journal.compose_attempt("first")

    assert recomposed == first
    assert recomposed["root_id"] == journal.root_id
    assert recomposed["terminal_event_sha256"] == journal.state("first")[
        "terminal_event_sha256"
    ]


def test_concurrent_duplicate_claim_across_journal_objects(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    left, right = _journal(path), _journal(path)
    claim_sha = hashlib.sha256(b"same claim").hexdigest()
    outcomes: list[object] = []

    def do_claim(journal: WitnessJournal, attempt_id: str) -> None:
        try:
            journal.claim(attempt_id, claim_sha)
            outcomes.append("ok")
        except TransitionError:
            outcomes.append("duplicate")

    threads = [threading.Thread(target=do_claim, args=(left, "a")), threading.Thread(target=do_claim, args=(right, "b"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["duplicate", "ok"]
    assert len(_journal(path).events()) == 1


def test_concurrent_duplicate_claim_across_processes(tmp_path: Path) -> None:
    root = str(tmp_path / "journal")
    claim_sha = hashlib.sha256(b"same process claim").hexdigest()
    with ProcessPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                _claim_in_process,
                [(root, "process-a", claim_sha), (root, "process-b", claim_sha)],
            )
        )
    assert sorted(results) == ["duplicate", "ok"]
    assert len(_journal(Path(root)).events()) == 1


def test_duplicate_claim_across_caller_artifact_roots(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    digest = hashlib.sha256(b"one").hexdigest()
    journal.claim("first", digest, artifact_root=tmp_path / "caller-a")
    with pytest.raises(TransitionError):
        journal.claim("second", digest, artifact_root=tmp_path / "caller-b")


def test_illegal_transitions_and_terminal_idempotency_are_rejected(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    with pytest.raises(TransitionError):
        journal.start("missing")
    _claim(journal)
    with pytest.raises(TransitionError):
        journal.start("attempt")
    journal.prepare("attempt")
    with pytest.raises(TransitionError):
        journal.prepare("attempt")
    journal.start("attempt")
    journal.terminal("attempt", "BURN", b"burn evidence")
    with pytest.raises(TransitionError):
        journal.terminal("attempt", "BURN", b"same evidence")


def test_truncation_head_mismatch_and_event_tamper_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "journal"
    journal = _journal(path)
    _claim(journal)
    journal.verify()
    journal._journal_path.write_bytes(journal._journal_path.read_bytes()[:-1])
    with pytest.raises(JournalIntegrityError):
        _journal(path).verify()

    path = tmp_path / "head-mismatch"
    journal = _journal(path)
    _claim(journal)
    head = json.loads(journal._head_path.read_text(encoding="ascii"))
    head["high_water_sequence"] = 99
    journal._head_path.write_bytes(json.dumps(head, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    with pytest.raises(JournalIntegrityError):
        _journal(path).verify()

    path = tmp_path / "event-tamper"
    journal = _journal(path)
    _claim(journal)
    event = json.loads(journal._journal_path.read_text(encoding="ascii"))
    event["payload"]["claim_sha256"] = "f" * 64
    journal._journal_path.write_bytes(json.dumps(event, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
    with pytest.raises(JournalIntegrityError):
        _journal(path).verify()


def test_evidence_is_immutable_and_rehashed_on_read(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    digest = journal.evidence.put(b"immutable")
    assert journal.evidence.put(b"immutable", digest=digest) == digest
    evidence_path = journal.root / "evidence" / digest
    assert evidence_path.stat().st_mode & 0o777 == 0o400
    evidence_path.chmod(0o600)
    evidence_path.write_bytes(b"changed")
    with pytest.raises(EvidenceError):
        journal.evidence.read(digest)


def test_evidence_install_crash_leaves_no_partial_digest_object(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "journal")
    payload = b"fully durable before install"
    digest = hashlib.sha256(payload).hexdigest()
    original_link = witness_module.os.link

    def crash_before_install(*args: object, **kwargs: object) -> None:
        raise OSError("simulated crash before CAS link")

    monkeypatch.setattr(witness_module.os, "link", crash_before_install)
    with pytest.raises(OSError, match="simulated crash"):
        journal.evidence.put(payload)
    assert not (journal.evidence.root / digest).exists()
    assert list(journal.evidence.root.iterdir()) == []

    monkeypatch.setattr(witness_module.os, "link", original_link)
    assert journal.evidence.put(payload) == digest
    assert journal.evidence.read(digest) == payload


def test_claim_plan_is_path_independent_and_attempt_id_is_witness_derived(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path / "journal")
    campaign = hashlib.sha256(b"campaign").hexdigest()
    candidate = hashlib.sha256(b"candidate").hexdigest()
    first = journal.claim_plan(
        campaign,
        candidate,
        claim={"plan": "frozen"},
        metadata={"export_root": "/caller/a"},
    )
    expected_key = journal.one_shot_key(campaign, candidate)
    assert first["payload"]["one_shot_key_sha256"] == expected_key
    assert first["payload"]["attempt_id"] != expected_key
    with pytest.raises(TransitionError, match="already claimed"):
        journal.claim_plan(
            campaign,
            candidate,
            claim={"plan": "different caller payload"},
            metadata={"export_root": "/caller/b"},
        )
    with pytest.raises(WitnessJournalError, match="override"):
        _journal(tmp_path / "other").claim_plan(
            campaign,
            candidate,
            claim={"plan": "frozen"},
            metadata={"campaign_sha256": "f" * 64},
        )


def test_same_local_authority_key_does_not_enforce_one_shot_across_roots(
    tmp_path: Path,
) -> None:
    campaign = hashlib.sha256(b"campaign").hexdigest()
    candidate = hashlib.sha256(b"candidate").hexdigest()
    left = _journal(tmp_path / "left")
    right = _journal(tmp_path / "right")
    assert left.authority_id == right.authority_id
    left.claim_plan(campaign, candidate, claim={"plan": "same"})
    right.claim_plan(campaign, candidate, claim={"plan": "same"})
    assert len(left.events()) == len(right.events()) == 1


def test_prepare_and_start_bind_durable_evidence(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    _claim(journal)
    prepared = journal.prepare("attempt", {"containers": ["referee", "left", "right"]})
    started = journal.start("attempt", {"release": "durable-before-launch"})
    state = journal.state("attempt")
    assert prepared["payload"]["evidence_sha256"] == state["prepared_evidence_sha256"]
    assert started["payload"]["evidence_sha256"] == state["started_evidence_sha256"]
    assert journal.evidence.read(state["prepared_evidence_sha256"])
    assert journal.evidence.read(state["started_evidence_sha256"])


def test_copying_signed_journal_to_another_root_fails_root_binding(tmp_path: Path) -> None:
    source = _journal(tmp_path / "source")
    _claim(source)
    destination_root = tmp_path / "destination"
    destination_root.mkdir()
    (destination_root / "journal.jsonl").write_bytes(source._journal_path.read_bytes())
    (destination_root / "head.json").write_bytes(source._head_path.read_bytes())
    with pytest.raises(JournalIntegrityError, match="root|domain"):
        _journal(destination_root).verify()


def test_orphan_evidence_after_event_crash_is_unreachable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    _started(journal)
    original = journal._append_event

    def crash(*args: object, **kwargs: object) -> object:
        raise OSError("simulated crash before journal event")

    monkeypatch.setattr(journal, "_append_event", crash)
    with pytest.raises(OSError):
        journal.terminal("attempt", "SUCCESS", {"ok": True})
    monkeypatch.setattr(journal, "_append_event", original)
    assert journal.state("attempt")["state"] == "STARTED"
    with pytest.raises(CompositionError):
        journal.compose_attempt("attempt")
    assert len(list((journal.root / "evidence").iterdir())) == 1


def test_recovery_advances_missing_or_authenticated_prefix_head(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_write_atomic = witness_module._write_atomic

    def crash_head(*args: object, **kwargs: object) -> None:
        raise OSError("head crash")

    missing_root = tmp_path / "missing-head"
    missing = _journal(missing_root)
    monkeypatch.setattr(witness_module, "_write_atomic", crash_head)
    with pytest.raises(OSError, match="head crash"):
        _claim(missing)
    assert missing._journal_path.exists()
    assert not missing._head_path.exists()
    with pytest.raises(JournalIntegrityError, match="no signed high-water"):
        _journal(missing_root).verify()

    monkeypatch.setattr(witness_module, "_write_atomic", original_write_atomic)
    recovered = _journal(missing_root)
    assert recovered.recover()["events"] == 1
    assert recovered.state("attempt")["state"] == "CLAIMED"

    prefix_root = tmp_path / "prefix-head"
    prefix = _journal(prefix_root)
    _claim(prefix)
    monkeypatch.setattr(witness_module, "_write_atomic", crash_head)
    with pytest.raises(OSError, match="head crash"):
        prefix.prepare("attempt", {"prepared": True})
    with pytest.raises(JournalIntegrityError, match="high-water"):
        _journal(prefix_root).verify()

    monkeypatch.setattr(witness_module, "_write_atomic", original_write_atomic)
    recovered_prefix = _journal(prefix_root)
    assert recovered_prefix.recover()["events"] == 2
    assert recovered_prefix.state("attempt")["state"] == "PREPARED"


def test_composer_refuses_nonterminal_missing_evidence_and_receipt_objects(tmp_path: Path) -> None:
    journal = _journal(tmp_path / "journal")
    _started(journal)
    with pytest.raises(CompositionError):
        journal.compose_attempt("attempt")
    journal.terminal("attempt", "SUCCESS")
    with pytest.raises(CompositionError):
        journal.compose_attempt("attempt")
    with pytest.raises(CompositionError):
        compose_terminal_evidence(journal, "attempt", {"fake": "receipt"})
