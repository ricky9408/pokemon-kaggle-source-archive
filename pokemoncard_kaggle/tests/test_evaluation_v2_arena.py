from __future__ import annotations

import csv
from pathlib import Path

from evaluation_v2.arena import merge_arena_csvs, summarize_arena


def test_arena_compares_candidate_and_baseline_on_shared_opponents(tmp_path: Path) -> None:
    path = tmp_path / "arena.csv"
    fields = ["anchor", "opponent", "anchor_result", "error"]
    rows = []
    for label, results in {"candidate": ["win", "win"], "baseline": ["win", "loss"]}.items():
        for result in results:
            rows.append({"anchor": label, "opponent": "shared", "anchor_result": result, "error": ""})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    evidence = summarize_arena(path, candidate="candidate", baseline="baseline", seed=4)
    assert evidence.shared_opponents == 1
    assert evidence.matchup_deltas["shared"] == 0.5
    assert evidence.errors == 0


def test_merge_keeps_independent_duplicate_looking_games(tmp_path: Path) -> None:
    fields = ["anchor", "opponent", "anchor_result", "error"]
    paths = [tmp_path / "one.csv", tmp_path / "two.csv"]
    for path in paths:
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerow({"anchor": "candidate", "opponent": "shared", "anchor_result": "win", "error": ""})
    output = tmp_path / "combined.csv"
    assert merge_arena_csvs(paths, output) == 2
    assert len(list(csv.DictReader(output.open()))) == 2
