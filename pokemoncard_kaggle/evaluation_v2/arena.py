"""Differential, matchup-robust summaries for cabt stress leagues."""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from .statistics import BetaBinomialSummary, RobustMixtureSummary, beta_binomial_summary, robust_matchup_mixture


@dataclass(frozen=True)
class ArenaEvidence:
    candidate: str
    baseline: str
    shared_opponents: int
    candidate_games: int
    baseline_games: int
    errors: int
    matchup_deltas: dict[str, float]
    candidate_posteriors: dict[str, dict[str, float]]
    robust: RobustMixtureSummary

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["robust"] = asdict(self.robust)
        return value


def merge_arena_csvs(paths: list[Path], output: Path) -> int:
    """Concatenate independent arena replicates without deduplicating outcomes."""
    if len(paths) < 2:
        raise ValueError("at least two arena replicates are required")
    fieldnames: list[str] | None = None
    rows: list[dict[str, str]] = []
    for path in paths:
        with path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ValueError(f"arena CSV has no header: {path}")
            if fieldnames is None:
                fieldnames = reader.fieldnames
            elif reader.fieldnames != fieldnames:
                raise ValueError("arena CSV headers differ")
            rows.extend(reader)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames or [])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _entry_result(row: dict[str, str], label: str) -> float | None:
    if row.get("error"):
        return None
    anchor = row["anchor"]
    result = row["anchor_result"]
    if label == anchor:
        return 1.0 if result == "win" else 0.5 if result == "draw" else 0.0 if result == "loss" else None
    if label == row["opponent"]:
        return 0.0 if result == "win" else 0.5 if result == "draw" else 1.0 if result == "loss" else None
    return None


def summarize_arena(path: Path, *, candidate: str, baseline: str, seed: int) -> ArenaEvidence:
    rows = list(csv.DictReader(path.open(newline="")))
    errors = sum(bool(row.get("error")) for row in rows)
    scores: dict[str, dict[str, list[float]]] = {
        candidate: defaultdict(list),
        baseline: defaultdict(list),
    }
    for row in rows:
        pair_labels = {row["anchor"], row["opponent"]}
        for label in (candidate, baseline):
            if label not in pair_labels:
                continue
            opponent = next(iter(pair_labels - {label}))
            if opponent in {candidate, baseline}:
                continue
            result = _entry_result(row, label)
            if result is not None:
                scores[label][opponent].append(result)
    shared = sorted(set(scores[candidate]) & set(scores[baseline]))
    if not shared:
        raise ValueError("arena contains no shared opponents for candidate and baseline")
    deltas: dict[str, float] = {}
    counts: dict[str, float] = {}
    posteriors: dict[str, dict[str, float]] = {}
    for opponent in shared:
        candidate_values = scores[candidate][opponent]
        baseline_values = scores[baseline][opponent]
        deltas[opponent] = sum(candidate_values) / len(candidate_values) - sum(baseline_values) / len(baseline_values)
        counts[opponent] = float(min(len(candidate_values), len(baseline_values)))
        wins = sum(value == 1.0 for value in candidate_values)
        losses = sum(value == 0.0 for value in candidate_values)
        draws = sum(value == 0.5 for value in candidate_values)
        posterior = beta_binomial_summary(wins, losses, draws, seed=seed + len(posteriors))
        posteriors[opponent] = asdict(posterior)
    robust = robust_matchup_mixture(deltas, counts, epsilon=0.15, seed=seed)
    return ArenaEvidence(
        candidate=candidate,
        baseline=baseline,
        shared_opponents=len(shared),
        candidate_games=sum(len(values) for values in scores[candidate].values()),
        baseline_games=sum(len(values) for values in scores[baseline].values()),
        errors=errors,
        matchup_deltas=deltas,
        candidate_posteriors=posteriors,
        robust=robust,
    )
