import json
from pathlib import Path

from tools.train_cohort_option_forest import load_main_rows


def _row(episode: int, step: int, context: str = "MAIN") -> dict:
    return {
        "episode_id": episode,
        "player_index": 0,
        "step_index": step,
        "context": context,
        "option_count": 2,
        "action": [1],
    }


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_load_main_rows_merges_and_deduplicates_sources(tmp_path: Path) -> None:
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    duplicate = _row(1, 2)
    _write(first, [duplicate, _row(2, 3, "TO_HAND")])
    _write(second, [duplicate, _row(3, 4)])

    rows = load_main_rows([first, second])

    assert [(row["episode_id"], row["step_index"]) for row in rows] == [(1, 2), (3, 4)]
