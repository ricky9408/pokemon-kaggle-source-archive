#!/usr/bin/env python3
"""Score candidates with a human-style meta forecast.

This is intentionally simple: estimate the expected field share for each
opponent lane, multiply by the candidate's matchup win rate, and compare the
result with a 50/50 baseline. It is a lightweight way to encode the deck-building
method "pick the field, estimate matchups, then calculate the deck score".
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Lane:
    opponent: str
    tier: str
    population: float
    raw_weight: float


@dataclass
class Result:
    candidate: str
    opponent: str
    wins: int
    losses: int
    draws: int
    unfinished: int
    win_rate: float


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def read_results(path: Path) -> tuple[dict[tuple[str, str], Result], dict[str, float], list[str]]:
    results: dict[tuple[str, str], Result] = {}
    weights: dict[str, float] = {}
    candidates: list[str] = []
    seen_candidates: set[str] = set()
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            candidate = row["candidate"]
            opponent = row["opponent"]
            if candidate not in seen_candidates:
                seen_candidates.add(candidate)
                candidates.append(candidate)
            weights[opponent] = max(weights.get(opponent, 0.0), float(row.get("weight") or 0.0))
            results[(candidate, opponent)] = Result(
                candidate=candidate,
                opponent=opponent,
                wins=int(float(row.get("wins") or 0)),
                losses=int(float(row.get("losses") or 0)),
                draws=int(float(row.get("draws") or 0)),
                unfinished=int(float(row.get("unfinished") or 0)),
                win_rate=float(row.get("win_rate") or 0.0),
            )
    return results, weights, candidates


def infer_tiers(weights: dict[str, float], total_population: float) -> list[Lane]:
    total_weight = sum(max(weight, 0.0) for weight in weights.values()) or 1.0
    lanes: list[Lane] = []
    cumulative = 0.0
    for opponent, weight in sorted(weights.items(), key=lambda item: item[1], reverse=True):
        share_before = cumulative / total_weight
        cumulative += max(weight, 0.0)
        if share_before < 0.50:
            tier = "Tier1"
        elif share_before < 0.80:
            tier = "Tier2"
        else:
            tier = "Tier3"
        lanes.append(
            Lane(
                opponent=opponent,
                tier=tier,
                population=total_population * max(weight, 0.0) / total_weight,
                raw_weight=weight,
            )
        )
    return lanes


def read_tier_config(path: Path) -> list[Lane]:
    lanes: list[Lane] = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            opponent = row["opponent"]
            population = float(row.get("population") or row.get("weight") or 0.0)
            lanes.append(
                Lane(
                    opponent=opponent,
                    tier=row.get("tier") or "Tier?",
                    population=population,
                    raw_weight=float(row.get("weight") or population),
                )
            )
    return lanes


def matchup_label(win_rate: float) -> str:
    if win_rate >= 0.65:
        return "very favorable"
    if win_rate >= 0.55:
        return "favorable"
    if win_rate >= 0.45:
        return "even"
    if win_rate >= 0.35:
        return "unfavorable"
    return "very unfavorable"


def score_candidates(
    results: dict[tuple[str, str], Result],
    lanes: list[Lane],
    candidates: list[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    rows: list[dict[str, object]] = []
    detail_rows: list[dict[str, object]] = []
    total_population = sum(lane.population for lane in lanes) or 1.0
    by_tier_population: dict[str, float] = defaultdict(float)
    for lane in lanes:
        by_tier_population[lane.tier] += lane.population

    for candidate in candidates:
        score = 0.0
        covered_population = 0.0
        worst_lane = ("", 1.0, 0.0)
        tier_score: dict[str, float] = defaultdict(float)
        tier_covered: dict[str, float] = defaultdict(float)
        favorable_population = 0.0
        unfavorable_population = 0.0
        for lane in lanes:
            result = results.get((candidate, lane.opponent))
            if result is None:
                continue
            contribution = lane.population * result.win_rate
            score += contribution
            covered_population += lane.population
            tier_score[lane.tier] += contribution
            tier_covered[lane.tier] += lane.population
            if result.win_rate < worst_lane[1]:
                worst_lane = (lane.opponent, result.win_rate, lane.population)
            label = matchup_label(result.win_rate)
            if result.win_rate >= 0.55:
                favorable_population += lane.population
            elif result.win_rate < 0.45:
                unfavorable_population += lane.population
            detail_rows.append(
                {
                    "candidate": candidate,
                    "opponent": lane.opponent,
                    "tier": lane.tier,
                    "population": lane.population,
                    "raw_weight": lane.raw_weight,
                    "win_rate": result.win_rate,
                    "wins": result.wins,
                    "losses": result.losses,
                    "draws": result.draws,
                    "unfinished": result.unfinished,
                    "label": label,
                    "expected_wins": contribution,
                }
            )
        baseline = covered_population * 0.5
        tier_avgs = {
            tier: (tier_score[tier] / tier_covered[tier])
            for tier in sorted(tier_covered)
            if tier_covered[tier] > 0
        }
        rows.append(
            {
                "candidate": candidate,
                "meta_score": score,
                "baseline": baseline,
                "edge_vs_50": score - baseline,
                "expected_win_rate": score / covered_population if covered_population else 0.0,
                "covered_population": covered_population,
                "coverage": covered_population / total_population,
                "favorable_population": favorable_population,
                "unfavorable_population": unfavorable_population,
                "worst_opponent": worst_lane[0],
                "worst_win_rate": worst_lane[1],
                "worst_population": worst_lane[2],
                "tier_avgs": tier_avgs,
            }
        )
    rows.sort(key=lambda row: (row["meta_score"], row["expected_win_rate"]), reverse=True)
    detail_rows.sort(key=lambda row: (row["candidate"], -float(row["population"])))
    return rows, detail_rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def render_report(
    args: argparse.Namespace,
    lanes: list[Lane],
    rows: list[dict[str, object]],
    detail_rows: list[dict[str, object]],
) -> str:
    total_population = sum(lane.population for lane in lanes) or 1.0
    lines = [
        "# Human Meta Score",
        "",
        f"Generated: {timestamp()}",
        "",
        "## Method",
        "",
        "This applies the human deck-building method from the provided Pokemon TCG article:",
        "",
        "1. Make a tier/field estimate.",
        "2. Estimate each candidate's matchup into every tier lane.",
        "3. Score each candidate as `population * win_rate` and compare with a 50/50 baseline.",
        "",
        "This is a strategy prior, not a public-score gate. It should be used to decide what to improve next.",
        "",
        "## Inputs",
        "",
        f"- Results: `{args.results}`",
        f"- Tier config: `{args.tier_config or 'inferred from gauntlet weights'}`",
        f"- Total population scale: {args.total_population:g}",
        "",
        "## Candidate Scores",
        "",
        "| Rank | Candidate | Meta score | Expected WR | Edge vs 50 | Fav pop | Unfav pop | Worst lane | Tier avgs |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for rank, row in enumerate(rows, start=1):
        tier_avgs = ", ".join(f"{tier}:{value:.3f}" for tier, value in row["tier_avgs"].items())
        lines.append(
            f"| {rank} | `{row['candidate']}` | {row['meta_score']:.2f} | "
            f"{row['expected_win_rate']:.3f} | {row['edge_vs_50']:+.2f} | "
            f"{row['favorable_population']:.1f} | {row['unfavorable_population']:.1f} | "
            f"`{row['worst_opponent']}` {row['worst_win_rate']:.3f} | {tier_avgs} |"
        )

    lines.extend(
        [
            "",
            "## Tier Lanes",
            "",
            "| Tier | Opponent lane | Population | Share | Raw weight |",
            "| --- | --- | ---: | ---: | ---: |",
        ]
    )
    for lane in sorted(lanes, key=lambda item: (-item.population, item.opponent)):
        lines.append(
            f"| {lane.tier} | `{lane.opponent}` | {lane.population:.2f} | "
            f"{lane.population / total_population:.3f} | {lane.raw_weight:.2f} |"
        )

    lines.extend(
        [
            "",
            "## Biggest Problem Lanes",
            "",
            "| Candidate | Tier | Opponent lane | Population | Win rate | Label |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    problem_rows = [
        row
        for row in detail_rows
        if float(row["win_rate"]) < 0.45
    ]
    problem_rows.sort(key=lambda row: (-float(row["population"]), float(row["win_rate"])))
    for row in problem_rows[:24]:
        lines.append(
            f"| `{row['candidate']}` | {row['tier']} | `{row['opponent']}` | "
            f"{float(row['population']):.2f} | {float(row['win_rate']):.3f} | {row['label']} |"
        )

    lines.extend(
        [
            "",
            "## Usage",
            "",
            "- Treat the top score as the most coherent local field plan, not as a public leaderboard prediction.",
            "- A candidate with high score but a large Tier1 hole should be patched before packaging.",
            "- Re-run after every fresh scout, because the tier estimate is the fragile assumption.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, required=True, help="Aggregate gauntlet CSV")
    parser.add_argument("--tier-config", type=Path, default=None, help="Optional CSV: opponent,tier,population")
    parser.add_argument("--total-population", type=float, default=100.0)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--detail-output", type=Path, default=None)
    parser.add_argument("--score-output", type=Path, default=None)
    args = parser.parse_args()

    results, weights, candidates = read_results(args.results)
    lanes = read_tier_config(args.tier_config) if args.tier_config else infer_tiers(weights, args.total_population)
    rows, detail_rows = score_candidates(results, lanes, candidates)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(args, lanes, rows, detail_rows), encoding="utf-8")
    if args.score_output:
        args.score_output.parent.mkdir(parents=True, exist_ok=True)
        serial_rows = []
        for row in rows:
            out = dict(row)
            out["tier_avgs"] = ";".join(f"{tier}:{value:.4f}" for tier, value in row["tier_avgs"].items())
            serial_rows.append(out)
        write_csv(args.score_output, serial_rows)
    if args.detail_output:
        args.detail_output.parent.mkdir(parents=True, exist_ok=True)
        write_csv(args.detail_output, detail_rows)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
