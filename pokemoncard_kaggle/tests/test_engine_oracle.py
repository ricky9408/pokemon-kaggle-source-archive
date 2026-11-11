import json
from pathlib import Path

import pytest

from evaluation_v3.engine_oracle import (
    VERDICT_REFERENCE_ONLY,
    VERDICT_UNSUPPORTED,
    canonical_action_hash,
    canonical_state_hash,
    compare_engine_runs,
    load_native_root,
    locate_omniscient_visualize_state,
    ProbeFailure,
    run_branch_isolated,
    unsupported_receipt,
    write_create_once_json,
)
from tools.run_engine_oracle_probe import DEFAULT_ROOT_ID


def _ok(transcript: str) -> dict:
    return {
        "status": "ok",
        "branch_transcripts": {"recorded": transcript, "alternative": transcript + "-alt"},
        "repeat_transcripts": {"recorded": transcript, "alternative": transcript + "-alt"},
    }


def test_canonical_hashes_ignore_transport_but_bind_action_meaning() -> None:
    first = {"current": {"turn": 4}, "search_begin_input": "private", "remainingOverageTime": 1}
    second = {"remainingOverageTime": 999, "current": {"turn": 4}, "search_begin_input": "other"}

    assert canonical_state_hash(first) == canonical_state_hash(second)
    select = {"minCount": 1, "maxCount": 1, "option": [{"type": 7, "index": 0}, {"type": 14}]}
    assert canonical_action_hash(select, [0]) != canonical_action_hash(select, [1])


def test_transcript_disagreement_is_unsupported() -> None:
    result = compare_engine_runs({"sample": _ok("a"), "clean": _ok("b")})

    assert result["verdict"] == VERDICT_UNSUPPORTED
    assert "disagreement" in result["disagreement_reasons"][0]


def test_missing_hosted_identity_is_reference_only_at_best() -> None:
    result = compare_engine_runs({"sample": _ok("same"), "clean": _ok("same")}, hosted_binary_provenance=None)

    assert result["verdict"] == VERDICT_REFERENCE_ONLY
    assert "hosted-public binary provenance is absent" in result["verdict_reason"]
    assert "hosted" not in result["verdict"].lower()


def test_create_once_json_refuses_overwrite_without_native_binaries(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    payload = {"verdict": VERDICT_UNSUPPORTED, "reason": "no native binaries required for this test"}

    write_create_once_json(output, payload)
    assert json.loads(output.read_text()) == payload
    with pytest.raises(FileExistsError):
        write_create_once_json(output, payload)


def test_preflight_failure_receipt_is_written_without_native_binaries(tmp_path: Path) -> None:
    output = tmp_path / "unsupported.json"
    receipt = unsupported_receipt(
        reason="ProbeFailure: missing native binary: /missing/libcg.so",
        stage="native_preflight_or_execution",
        sample_library=tmp_path / "missing" / "libcg.so",
    )

    write_create_once_json(output, receipt)

    written = json.loads(output.read_text())
    assert written["verdict"] == VERDICT_UNSUPPORTED
    assert written["disagreement_reasons"] == ["ProbeFailure: missing native binary: /missing/libcg.so"]
    assert written["identities_available"]["kaggle_sample_library"]["exists"] is False


def test_frozen_root_maps_to_exact_known_omniscient_visualize_index() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    replay = json.loads(
        (root_dir / "scouting/live_top_20260710T1135_top20_e16/06_nasuo445_16371722/submission_54337127/episode-85178405-replay.json").read_text()
    )
    root = load_native_root(
        root_dir / "evaluation_artifacts/branch_bridge_v2/native_roots.jsonl",
        episode_id="85178405",
        root_id=DEFAULT_ROOT_ID,
    )

    visual = locate_omniscient_visualize_state(replay, root)

    assert root["step_index"] == 31
    assert root["recorded_selection"] == [6]
    assert visual["visualize_index"] == 30


def test_native_branch_worker_timeout_is_fail_closed(tmp_path: Path) -> None:
    worker = tmp_path / "sleep_worker.py"
    worker.write_text("import time; time.sleep(5)\n", encoding="utf-8")
    library = tmp_path / "libcg.so"
    library.write_bytes(b"not loaded by the sleeping fixture")

    with pytest.raises(ProbeFailure, match="timed out"):
        run_branch_isolated(
            library,
            {"current": {}, "select": {}},
            {},
            [],
            timeout_seconds=0.05,
            worker_script=worker,
        )


def test_native_branch_worker_crash_is_fail_closed(tmp_path: Path) -> None:
    worker = tmp_path / "crash_worker.py"
    worker.write_text("import os; os._exit(17)\n", encoding="utf-8")
    library = tmp_path / "libcg.so"
    library.write_bytes(b"not loaded by the crash fixture")

    with pytest.raises(ProbeFailure, match="exited 17"):
        run_branch_isolated(
            library,
            {"current": {}, "select": {}},
            {},
            [],
            timeout_seconds=1.0,
            worker_script=worker,
        )
