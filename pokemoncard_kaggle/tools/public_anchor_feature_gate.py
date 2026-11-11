#!/usr/bin/env python3
"""Gate offline strategy features against public-anchor lanes.

This is deliberately stricter than a plain action-imitation report. A timing
feature that improves aggregate top-1 can still be unsafe if its gains come
from thin or contradicted lanes. This tool evaluates a small runtime-shaped
feature against:

* all decision rows,
* deterministic holdouts,
* public-anchor tiers, and
* concrete archetype/deck-hash lanes.

It never submits and never treats the local full-game simulator as predictive.
The intended use is to decide whether a strategy feature can remain in the
offline ML/RL curriculum or must be demoted to research-only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_ability_attack_predicates import EvalStats, eligible_case, parse_predicate, update_stats  # noqa: E402
from public_anchor_policy_targets import build_lanes, anchor_tier, load_anchor_status  # noqa: E402
from train_action_ranker import load_rows, pct, ranked_options, stable_bucket, valid_single_label  # noqa: E402


DEFAULT_EXCEPTIONS = [
    "opp_active=878 & opp_bench=<=4",
    "archetype=alakazam-hammer & prizes=6|5",
]

DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]


@dataclass
class FeatureStats:
    stats: EvalStats = field(default_factory=EvalStats)
    suppressed: int = 0
    prevented_regressions: int = 0
    lost_fixes: int = 0
    neutral_suppressed: int = 0

    @property
    def top1_delta(self) -> int:
        return self.stats.guard_top1 - self.stats.base_top1

    @property
    def top1_before(self) -> float:
        return self.stats.base_top1 / self.stats.total if self.stats.total else 0.0

    @property
    def top1_after(self) -> float:
        return self.stats.guard_top1 / self.stats.total if self.stats.total else 0.0

    @property
    def net_fixes(self) -> int:
        return self.stats.fixes - self.stats.regressions


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def holdout_hit(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def lane_key(row: dict[str, Any]) -> tuple[str, str]:
    return row_value(row, "archetype"), row_value(row, "deck_hash")


def code_cell(value: str) -> str:
    return f"`{value.replace('|', '&#124;')}`"


def fmt(value: float) -> str:
    return f"{value:.3f}"


def apply_timing_feature(
    row: dict[str, Any],
    weights: dict[str, float],
    base_predicate: Any,
    exceptions: tuple[Any, ...],
) -> tuple[list[int], list[int], bool, bool, bool, Any | None]:
    case, base_rank = eligible_case(row, weights)
    if not base_rank:
        base_rank = ranked_options(weights, row)
    eligible = case is not None and base_predicate.fn(case)
    if case is None or not eligible:
        return base_rank, base_rank, eligible, False, False, case
    if any(predicate.fn(case) for predicate in exceptions):
        return base_rank, base_rank, eligible, False, True, case
    ability = case.ability_index
    rank = [ability] + [index for index in base_rank if index != ability]
    return base_rank, rank, eligible, True, False, case


def update_feature_stats(
    feature_stats: FeatureStats,
    row: dict[str, Any],
    label: int | None,
    base_rank: list[int],
    feature_rank: list[int],
    eligible: bool,
    fired: bool,
    suppressed: bool,
    case: Any | None,
) -> None:
    update_stats(feature_stats.stats, label, base_rank, feature_rank, fired, eligible)
    if suppressed and case is not None:
        feature_stats.suppressed += 1
        feature_stats.prevented_regressions += int(case.outcome == "regression")
        feature_stats.lost_fixes += int(case.outcome == "fix")
        feature_stats.neutral_suppressed += int(case.outcome == "neutral")


def evaluate(args: argparse.Namespace) -> tuple[
    FeatureStats,
    dict[str, FeatureStats],
    dict[str, FeatureStats],
    dict[str, FeatureStats],
    dict[str, Any],
]:
    rows = load_rows(args.decisions)
    payload = json.loads(args.model.read_text(encoding="utf-8"))
    weights = {str(key): float(value) for key, value in payload["weights"].items()}
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    base_predicate = parse_predicate(args.base_predicate)
    exceptions = tuple(parse_predicate(raw) for raw in args.exception)

    overall = FeatureStats()
    holdouts = {key: FeatureStats() for key in args.holdout_key}
    tiers: dict[str, FeatureStats] = defaultdict(FeatureStats)
    lane_stats: dict[str, FeatureStats] = defaultdict(FeatureStats)

    for row in rows:
        label = valid_single_label(row)
        if label is None:
            update_feature_stats(overall, row, None, [], [], False, False, False, None)
            continue
        base_rank, feature_rank, eligible, fired, suppressed, case = apply_timing_feature(
            row, weights, base_predicate, exceptions
        )
        update_feature_stats(overall, row, label, base_rank, feature_rank, eligible, fired, suppressed, case)

        lane = lanes[lane_key(row)]
        tier, _candidates = anchor_tier(lane, anchors, args.min_public_episodes, args.min_public_teams)
        update_feature_stats(tiers[tier], row, label, base_rank, feature_rank, eligible, fired, suppressed, case)

        lane_name = f"{lane.archetype}:{lane.deck_hash}"
        update_feature_stats(lane_stats[lane_name], row, label, base_rank, feature_rank, eligible, fired, suppressed, case)

        for key in args.holdout_key:
            if holdout_hit(row, key, args.holdout_mod, args.holdout_bucket):
                update_feature_stats(holdouts[key], row, label, base_rank, feature_rank, eligible, fired, suppressed, case)

    meta = {
        "rows": len(rows),
        "feature_name": args.feature_name,
        "exceptions": [predicate.name for predicate in exceptions],
        "base_predicate": base_predicate.name,
        "lanes": lanes,
    }
    return overall, holdouts, dict(tiers), dict(lane_stats), meta


def stats_table_row(name: str, stats: FeatureStats) -> str:
    raw = stats.stats
    return (
        f"| {code_cell(name)} | {raw.total} | {fmt(stats.top1_before)} | {fmt(stats.top1_after)} | "
        f"{stats.top1_delta:+d} | {pct(raw.base_top3, raw.total)} | {pct(raw.guard_top3, raw.total)} | "
        f"{raw.eligible} | {raw.fired} | {raw.changed} | {raw.fixes} | {raw.regressions} | "
        f"{stats.suppressed} | {stats.prevented_regressions} / {stats.lost_fixes} |"
    )


def sort_stats(items: dict[str, FeatureStats]) -> list[tuple[str, FeatureStats]]:
    return sorted(
        items.items(),
        key=lambda item: (
            -item[1].stats.fired,
            item[1].top1_delta,
            item[0],
        ),
    )


def decide(
    overall: FeatureStats,
    holdouts: dict[str, FeatureStats],
    tiers: dict[str, FeatureStats],
    lane_stats: dict[str, FeatureStats],
    args: argparse.Namespace,
) -> tuple[str, list[str]]:
    notes: list[str] = []
    if overall.top1_delta < 0:
        notes.append("Overall public-action top-1 delta is negative.")
    if overall.net_fixes < 0:
        notes.append("Overall fixes minus regressions is negative.")
    for key, stats in holdouts.items():
        if stats.top1_delta < 0:
            notes.append(f"Holdout `{key}` has negative top-1 delta ({stats.top1_delta}).")
    public_supported = [
        ("tier:" + name, stats)
        for name, stats in tiers.items()
        if name in {"submit-eligible-candidate", "exact-public-replay-supported", "single-team-public-replay-supported"}
        and stats.stats.fired >= args.min_group_fires
    ]
    contradicted = [
        ("tier:" + name, stats)
        for name, stats in tiers.items()
        if name == "candidate-public-contradicted" and stats.stats.fired >= args.min_group_fires
    ]
    if not public_supported:
        notes.append("No public-supported tier has enough feature fires to validate the signal.")
    for name, stats in public_supported + contradicted:
        if stats.top1_delta < 0:
            notes.append(f"{name} has negative top-1 delta ({stats.top1_delta}).")
        if stats.net_fixes < 0:
            notes.append(f"{name} has negative net fixes ({stats.net_fixes}).")

    important_lanes = [
        (name, stats)
        for name, stats in lane_stats.items()
        if stats.stats.fired >= args.min_group_fires
    ]
    for name, stats in important_lanes:
        if stats.top1_delta <= -args.max_lane_regression:
            notes.append(f"Lane `{name}` exceeds allowed regression with top-1 delta {stats.top1_delta}.")

    if notes:
        return "research-only", notes + ["Keep the feature behind offline ML/RL curriculum gates; do not package it."]
    return "offline-feature-accepted", [
        "The feature is non-negative overall, on deterministic holdouts, and on public-anchor tiers with enough coverage.",
        "This is still strategy-feature evidence only; public-score backtest and public-anchor gates remain submit-facing blockers.",
    ]


def render_report(
    args: argparse.Namespace,
    overall: FeatureStats,
    holdouts: dict[str, FeatureStats],
    tiers: dict[str, FeatureStats],
    lane_stats: dict[str, FeatureStats],
    meta: dict[str, Any],
) -> str:
    decision, notes = decide(overall, holdouts, tiers, lane_stats, args)
    lines = [
        "# Public-Anchor Strategy Feature Gate",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "- Runtime premise: deterministic offline analysis; no network or LLM at play time.",
        "- Submission status: no submission made.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Anchor status: `{args.anchor_status}`",
        f"- Feature: `{args.feature_name}`",
        f"- Base predicate: `{meta['base_predicate']}`",
        "- Exceptions:",
    ]
    for exception in meta["exceptions"]:
        lines.append(f"  - `{exception}`")
    lines.extend(
        [
            f"- Rows loaded: {meta['rows']}",
            f"- Public replay support thresholds: episodes >= {args.min_public_episodes}, teams >= {args.min_public_teams}",
            "",
            "## Overall",
            "",
            "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            stats_table_row("all rows", overall),
            "",
            "## Holdouts",
            "",
            "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, stats in holdouts.items():
        lines.append(stats_table_row(name, stats))
    lines.extend(
        [
            "",
            "## Public-Anchor Tiers",
            "",
            "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, stats in sort_stats(tiers):
        lines.append(stats_table_row(name, stats))

    lines.extend(
        [
            "",
            "## Top Fired Lanes",
            "",
            "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, stats in sort_stats(lane_stats)[: args.lane_limit]:
        if stats.stats.fired == 0 and stats.stats.eligible == 0:
            continue
        lines.append(stats_table_row(name, stats))
    lines.extend(["", "## Decision", "", f"- Status: **{decision}**"])
    for note in notes:
        lines.append(f"- {note}")
    lines.extend(
        [
            "",
            "## Use In Workflow",
            "",
            "- `offline-feature-accepted` means the feature may remain in behavior-cloning, value-model, or RL curriculum experiments.",
            "- It does not make an agent package submit-safe.",
            "- Submit-facing promotion still requires public-anchor eligibility and a trusted public-score backtest metric.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(
    path: Path,
    overall: FeatureStats,
    holdouts: dict[str, FeatureStats],
    tiers: dict[str, FeatureStats],
    lane_stats: dict[str, FeatureStats],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "group_type",
                "group",
                "n",
                "base_top1",
                "feature_top1",
                "delta_top1_count",
                "base_top3",
                "feature_top3",
                "eligible",
                "fires",
                "changes",
                "fixes",
                "regressions",
                "suppressed",
                "prevented_regressions",
                "lost_fixes",
            ]
        )
        groups = [("overall", "all rows", overall)]
        groups += [("holdout", key, stats) for key, stats in holdouts.items()]
        groups += [("anchor_tier", key, stats) for key, stats in sort_stats(tiers)]
        groups += [("lane", key, stats) for key, stats in sort_stats(lane_stats)]
        for group_type, group, stats in groups:
            raw = stats.stats
            writer.writerow(
                [
                    group_type,
                    group,
                    raw.total,
                    f"{stats.top1_before:.6f}",
                    f"{stats.top1_after:.6f}",
                    stats.top1_delta,
                    f"{raw.base_top3 / raw.total:.6f}" if raw.total else "0.000000",
                    f"{raw.guard_top3 / raw.total:.6f}" if raw.total else "0.000000",
                    raw.eligible,
                    raw.fired,
                    raw.changed,
                    raw.fixes,
                    raw.regressions,
                    stats.suppressed,
                    stats.prevented_regressions,
                    stats.lost_fixes,
                ]
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--anchor-status", required=True, type=Path)
    parser.add_argument("--feature-name", default="dudunsparce_timing_boost4_stable_exceptions")
    parser.add_argument("--base-predicate", default="all")
    parser.add_argument("--exception", action="append", default=[])
    parser.add_argument("--holdout-key", action="append", choices=DEFAULT_HOLDOUT_KEYS, default=[])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-group-fires", type=int, default=10)
    parser.add_argument("--max-lane-regression", type=int, default=5)
    parser.add_argument("--lane-limit", type=int, default=20)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_feature_gate.md"))
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()

    if not args.exception:
        args.exception = list(DEFAULT_EXCEPTIONS)
    if not args.holdout_key:
        args.holdout_key = list(DEFAULT_HOLDOUT_KEYS)
    if args.csv_out is None:
        args.csv_out = args.report_out.with_suffix(".csv")

    overall, holdouts, tiers, lane_stats, meta = evaluate(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, overall, holdouts, tiers, lane_stats, meta), encoding="utf-8")
    write_csv(args.csv_out, overall, holdouts, tiers, lane_stats)
    decision, notes = decide(overall, holdouts, tiers, lane_stats, args)
    print(f"decision={decision} report={args.report_out} csv={args.csv_out}")
    for note in notes:
        print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
