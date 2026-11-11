#!/usr/bin/env python3
"""Evaluate a frozen external value head on later cohort decisions."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from math import log
from pathlib import Path
import sys
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.value_head import PublicValueHead


def auc(scores: Iterable[float], labels: Iterable[int]) -> float | None:
    pairs = sorted(zip(scores, labels), key=lambda item: item[0])
    positives = sum(label for _, label in pairs)
    negatives = len(pairs) - positives
    if not positives or not negatives:
        return None
    rank_sum = 0.0
    index = 0
    while index < len(pairs):
        end = index + 1
        while end < len(pairs) and pairs[end][0] == pairs[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in pairs[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    model = PublicValueHead.load(args.model)
    rows = [json.loads(line) for line in args.decisions.read_text().splitlines() if line.strip()]
    scored: list[tuple[int, float, int]] = []
    for row in rows:
        if not row.get("options"):
            continue
        probability = model.score_row(row)
        label = int(float(row.get("teacher_reward", row.get("terminal_reward", 0.0))) > 0.0)
        scored.append((int(row["episode_id"]), probability, label))
    by_episode: dict[int, list[tuple[float, int]]] = defaultdict(list)
    for episode, probability, label in scored:
        by_episode[episode].append((probability, label))
    episode_scores = [sum(value for value, _ in values) / len(values) for values in by_episode.values()]
    episode_labels = [values[0][1] for values in by_episode.values()]
    epsilon = 1e-9
    result = {
        "schema_version": 1,
        "decisions": len(scored),
        "episodes": len(by_episode),
        "decision_auc": auc((value for _, value, _ in scored), (label for _, _, label in scored)),
        "episode_auc": auc(episode_scores, episode_labels),
        "positive_rate": sum(label for _, _, label in scored) / len(scored),
        "log_loss": -sum(
            label * log(max(epsilon, probability)) + (1 - label) * log(max(epsilon, 1.0 - probability))
            for _, probability, label in scored
        )
        / len(scored),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
