from __future__ import annotations

import json
from pathlib import Path

from evaluation_v2.safety_burnin import SafetyLimits, load_observation_corpus, run_burnin


def _observation() -> dict:
    return {
        "select": {
            "minCount": 1,
            "maxCount": 1,
            "option": [{"type": 1}, {"type": 2}],
        }
    }


def test_burnin_passes_instrumented_deterministic_agent() -> None:
    counters = {"fallbacks": 0}
    result = run_burnin(
        lambda observation: [0],
        [json.dumps(_observation())],
        calls=10,
        repeat_checks=1,
        fallback_count=lambda: counters["fallbacks"],
        limits=SafetyLimits(min_calls=10, min_repeat_checks=1),
    )
    assert result["passed"]
    assert result["illegal"] == 0


def test_uninstrumented_fallback_fails_closed() -> None:
    result = run_burnin(
        lambda observation: [0],
        [json.dumps(_observation())],
        calls=1,
        repeat_checks=1,
        limits=SafetyLimits(min_calls=1, min_repeat_checks=1),
    )
    assert not result["passed"]


def test_corpus_deduplicates_and_filters_deck(tmp_path: Path) -> None:
    dataset = tmp_path / "rows.jsonl"
    rows = [
        {"deck_hash": "keep", "observation": _observation()},
        {"deck_hash": "keep", "observation": _observation()},
        {"deck_hash": "drop", "observation": {"select": {"option": [{"type": 3}]}}},
    ]
    dataset.write_text("".join(json.dumps(row) + "\n" for row in rows))
    assert len(load_observation_corpus([dataset], deck_hash="keep")) == 1
