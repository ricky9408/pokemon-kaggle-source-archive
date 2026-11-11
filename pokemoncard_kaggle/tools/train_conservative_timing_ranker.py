#!/usr/bin/env python3
"""Tune a tiny conservative timing ranker around accepted strategy features.

The repo's broad action rankers overfit easily. This tool keeps the baseline
action-ranker frozen and tunes only one interpretable scalar feature:

    Prefer legal ``ABILITY Dudunsparce(66)`` before the base top-1 ATTACK.

The accepted stable exception predicates can suppress that boost. This is an
offline ML/value-model probe, not a runtime policy patch or submit selector.
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluate_ability_attack_predicates import eligible_case, parse_predicate
from mine_ability_attack_guard import Case, load_model
from train_action_ranker import load_rows, option_features, pct, ranked_options, score, stable_bucket, valid_single_label


DEFAULT_EXCEPTIONS = [
    "opp_active=878 & opp_bench=<=4",
    "archetype=alakazam-hammer & prizes=6|5",
]

DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]
DEFAULT_BOOSTS = [0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 999.0]


@dataclass(frozen=True)
class Variant:
    name: str
    boost: float
    suppress_exceptions: bool


@dataclass
class EvalStats:
    total: int = 0
    skipped: int = 0
    eligible: int = 0
    fires: int = 0
    suppressed: int = 0
    changed: int = 0
    base_top1: int = 0
    model_top1: int = 0
    base_top3: int = 0
    model_top3: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0

    @property
    def delta_top1(self) -> int:
        return self.model_top1 - self.base_top1


@dataclass
class VariantResult:
    variant: Variant
    all_rows: EvalStats
    holdouts: dict[str, EvalStats]
    group_stats: dict[str, EvalStats]
    changes: Counter[str]


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def in_holdout(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def base_scores(weights: dict[str, float], row: dict[str, Any]) -> list[float]:
    option_count = int(row.get("option_count") or 0)
    return [score(weights, option_features(row, index)) for index in range(option_count)]


def rank_from_scores(scores: list[float]) -> list[int]:
    ranked = [(value, -index, index) for index, value in enumerate(scores)]
    ranked.sort(reverse=True)
    return [index for _value, _neg, index in ranked]


def exception_fires(case: Case, predicates: list[Any]) -> bool:
    return any(predicate.fn(case) for predicate in predicates)


def model_rank(
    row: dict[str, Any],
    weights: dict[str, float],
    variant: Variant,
    exceptions: list[Any],
) -> tuple[list[int], list[int], Case | None, bool, bool]:
    case, base_rank = eligible_case(row, weights)
    if not base_rank:
        base_rank = ranked_options(weights, row)
    if case is None:
        return base_rank, base_rank, None, False, False
    suppressed = variant.suppress_exceptions and exception_fires(case, exceptions)
    if suppressed:
        return base_rank, base_rank, case, False, True
    scores = base_scores(weights, row)
    if case.ability_index < len(scores):
        scores[case.ability_index] += variant.boost
    return base_rank, rank_from_scores(scores), case, True, False


def update_stats(stats: EvalStats, label: int | None, base_rank: list[int], rank: list[int], case: Case | None, fired: bool, suppressed: bool) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.eligible += int(case is not None)
    stats.fires += int(fired)
    stats.suppressed += int(suppressed)
    base_hit = bool(base_rank and base_rank[0] == label)
    model_hit = bool(rank and rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.model_top1 += int(model_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.model_top3 += int(label in rank[:3])
    changed = bool(base_rank and rank and base_rank[0] != rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and model_hit)
    stats.regressions += int(changed and base_hit and not model_hit)
    stats.neutral_changes += int(changed and base_hit == model_hit)


def evaluate(rows: list[dict[str, Any]], weights: dict[str, float], variant: Variant, exceptions: list[Any], args: argparse.Namespace) -> VariantResult:
    all_stats = EvalStats()
    holdouts = {key: EvalStats() for key in args.holdout_key}
    groups: dict[str, EvalStats] = defaultdict(EvalStats)
    changes: Counter[str] = Counter()
    for row in rows:
        label = valid_single_label(row)
        base_rank, rank, case, fired, suppressed = model_rank(row, weights, variant, exceptions)
        update_stats(all_stats, label, base_rank, rank, case, fired, suppressed)
        group = f"{row_value(row, 'archetype')} vs {row_value(row, 'opponent_archetype')}"
        update_stats(groups[group], label, base_rank, rank, case, fired, suppressed)
        for key in args.holdout_key:
            if in_holdout(row, key, args.holdout_mod, args.holdout_bucket):
                update_stats(holdouts[key], label, base_rank, rank, case, fired, suppressed)
        if label is not None and base_rank and rank and base_rank[0] != rank[0]:
            options = row.get("options") or []
            public = options[label] if label < len(options) else str(label)
            before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
            after = options[rank[0]] if rank[0] < len(options) else str(rank[0])
            outcome = "fix" if rank[0] == label and base_rank[0] != label else "regress" if base_rank[0] == label else "neutral"
            changes[f"{outcome}: public={public} | base={before} | model={after}"] += 1
    return VariantResult(variant=variant, all_rows=all_stats, holdouts=holdouts, group_stats=dict(groups), changes=changes)


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | "
        f"{pct(stats.model_top1, stats.total)} | {stats.delta_top1:+d} | "
        f"{pct(stats.base_top3, stats.total)} | {pct(stats.model_top3, stats.total)} | "
        f"{stats.eligible} | {stats.fires} | {stats.suppressed} | {stats.changed} | "
        f"{stats.fixes} | {stats.regressions} | {stats.neutral_changes} |"
    )


def candidate_ok(result: VariantResult, args: argparse.Namespace) -> bool:
    if result.all_rows.delta_top1 < args.min_all_delta:
        return False
    if result.all_rows.regressions > result.all_rows.fixes:
        return False
    for stats in result.holdouts.values():
        if stats.delta_top1 < args.min_holdout_delta:
            return False
        if stats.regressions > args.max_holdout_regressions and stats.regressions > stats.fixes:
            return False
    return True


def choose_best(results: list[VariantResult], args: argparse.Namespace) -> VariantResult | None:
    candidates = [result for result in results if candidate_ok(result, args)]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda result: (
            min(stats.delta_top1 for stats in result.holdouts.values()),
            result.all_rows.delta_top1,
            result.all_rows.fixes - result.all_rows.regressions,
            -result.variant.boost,
            int(result.variant.suppress_exceptions),
        ),
    )


def write_csv(path: Path, results: list[VariantResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "variant",
                "boost",
                "suppress_exceptions",
                "split",
                "n",
                "base_top1",
                "model_top1",
                "delta_top1",
                "base_top3",
                "model_top3",
                "eligible",
                "fires",
                "suppressed",
                "changed",
                "fixes",
                "regressions",
                "neutral_changes",
            ]
        )
        for result in results:
            for split, stats in [("all", result.all_rows), *result.holdouts.items()]:
                writer.writerow(
                    [
                        result.variant.name,
                        result.variant.boost,
                        int(result.variant.suppress_exceptions),
                        split,
                        stats.total,
                        f"{stats.base_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        f"{stats.model_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        stats.delta_top1,
                        f"{stats.base_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        f"{stats.model_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        stats.eligible,
                        stats.fires,
                        stats.suppressed,
                        stats.changed,
                        stats.fixes,
                        stats.regressions,
                        stats.neutral_changes,
                    ]
                )


def render(args: argparse.Namespace, rows: list[dict[str, Any]], variants: list[Variant], results: list[VariantResult], exceptions: list[Any]) -> str:
    best = choose_best(results, args)
    lines = [
        "# Conservative Timing Ranker",
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
        "- Runtime premise: deterministic offline training/evaluation only; no network or LLM at play time.",
        "- Submission status: no submission made.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Frozen base model: `{args.model}`",
        f"- Rows loaded: {len(rows)}",
        f"- Boost grid: {', '.join(str(item) for item in args.boost)}",
        f"- Holdouts: {', '.join(args.holdout_key)} with sha1(value) % {args.holdout_mod} == {args.holdout_bucket}",
        "- Stable exception suppressors:",
    ]
    for predicate in exceptions:
        lines.append(f"  - `{predicate.name.replace('|', '&#124;')}`")
    lines.extend(
        [
            "",
            "## All Rows",
            "",
            "| Variant | N | Base Top-1 | Model Top-1 | Delta | Base Top-3 | Model Top-3 | Eligible | Fires | Suppressed | Changes | Fixes | Regressions | Neutral |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in results:
        lines.append(stats_row(result.variant.name, result.all_rows))
    for key in args.holdout_key:
        lines.extend(
            [
                "",
                f"## Holdout: `{key}`",
                "",
                "| Variant | N | Base Top-1 | Model Top-1 | Delta | Base Top-3 | Model Top-3 | Eligible | Fires | Suppressed | Changes | Fixes | Regressions | Neutral |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for result in results:
            lines.append(stats_row(result.variant.name, result.holdouts[key]))

    lines.extend(["", "## Decision", ""])
    if best is None:
        lines.append("- Status: **research-only**")
        lines.append("- No scalar boost cleared the configured no-regression gate across all holdouts.")
    else:
        lines.append("- Status: **offline-feature-accepted**")
        lines.append(f"- Best stable scalar feature: `{best.variant.name}`.")
        lines.append(
            f"- All rows top-1 {pct(best.all_rows.base_top1, best.all_rows.total)} -> "
            f"{pct(best.all_rows.model_top1, best.all_rows.total)} with {best.all_rows.fixes} fixes / "
            f"{best.all_rows.regressions} regressions."
        )
        lines.append("- This remains a value/ranker feature only; public-anchor and public-score backtest gates still control submit eligibility.")
        lines.append("")
        lines.append("## Best Variant Group Deltas")
        lines.append("")
        lines.append("| Group | N | Base Top-1 | Model Top-1 | Fires | Fixes | Regressions |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        groups = [
            (name, stats)
            for name, stats in best.group_stats.items()
            if stats.total >= args.min_group_n and stats.changed
        ]
        groups.sort(key=lambda item: (item[1].delta_top1, item[1].fires), reverse=True)
        for name, stats in groups[: args.limit]:
            lines.append(
                f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | "
                f"{pct(stats.model_top1, stats.total)} | {stats.fires} | {stats.fixes} | {stats.regressions} |"
            )
        if not groups:
            lines.append("| - | 0 | 0.000 | 0.000 | 0 | 0 | 0 |")
        lines.append("")
        lines.append("## Largest Best-Variant Top-1 Changes")
        lines.append("")
        for text, count in best.changes.most_common(args.limit):
            lines.append(f"- {count}: {text}")
        if not best.changes:
            lines.append("- No top-1 changes.")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- A finite boost that matches the forced overlay is a smaller, auditable value feature; it is not a hard-coded agent branch.",
            "- Prefer the smallest boost that preserves all-holdout lift and avoids exception regressions.",
            "- Any future runtime implementation must be rechecked against public anchors and the local-vs-public backtest gate.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--boost", type=float, action="append", default=[])
    parser.add_argument("--exception", action="append", default=[])
    parser.add_argument("--holdout-key", action="append", default=[])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-all-delta", type=int, default=1)
    parser.add_argument("--min-holdout-delta", type=int, default=0)
    parser.add_argument("--max-holdout-regressions", type=int, default=0)
    parser.add_argument("--min-group-n", type=int, default=50)
    parser.add_argument("--limit", type=int, default=16)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/conservative_timing_ranker.md"))
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()

    if not args.boost:
        args.boost = list(DEFAULT_BOOSTS)
    if not args.exception:
        args.exception = list(DEFAULT_EXCEPTIONS)
    if not args.holdout_key:
        args.holdout_key = list(DEFAULT_HOLDOUT_KEYS)
    if args.csv_out is None:
        args.csv_out = args.report_out.with_suffix(".csv")

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    exceptions = [parse_predicate(raw) for raw in args.exception]
    variants = [
        Variant(f"boost={boost:g} no-exceptions", boost=boost, suppress_exceptions=False)
        for boost in args.boost
    ]
    variants.extend(
        Variant(f"boost={boost:g} stable-exceptions", boost=boost, suppress_exceptions=True)
        for boost in args.boost
    )
    results = [evaluate(rows, weights, variant, exceptions, args) for variant in variants]
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, rows, variants, results, exceptions), encoding="utf-8")
    write_csv(args.csv_out, results)
    best = choose_best(results, args)
    if best is None:
        print(f"decision=research-only report={args.report_out} csv={args.csv_out}")
    else:
        print(f"decision=offline-feature-accepted best={best.variant.name} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
