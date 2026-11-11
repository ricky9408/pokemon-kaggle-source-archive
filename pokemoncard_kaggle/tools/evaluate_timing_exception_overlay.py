#!/usr/bin/env python3
"""Evaluate the accepted Dudunsparce timing motif plus exception features.

This is an offline public-action imitation check. It deliberately does not
choose submissions. The goal is to test whether the current accepted strategy
signal, "prefer Dudunsparce ability before attacking", remains stable when the
small mined exception features are applied together across multiple holdout
splits.
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evaluate_ability_attack_predicates import EvalStats, eligible_case, parse_predicate, update_stats
from mine_ability_attack_guard import Case, load_model
from train_action_ranker import load_rows, pct, ranked_options, stable_bucket, valid_single_label


DEFAULT_EXCEPTIONS = [
    "opp_active=878 & opp_bench=<=4",
    "active=743 & prizes=6|5",
    "attack=1072 & prizes=6|5",
    "archetype=alakazam-hammer & prizes=6|5",
]

DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]


@dataclass(frozen=True)
class Variant:
    name: str
    exception_predicates: tuple[Any, ...] = ()
    is_base: bool = False


@dataclass
class OverlayStats:
    stats: EvalStats = field(default_factory=EvalStats)
    suppressed: int = 0
    prevented_regressions: int = 0
    lost_fixes: int = 0
    neutral_suppressed: int = 0


@dataclass
class VariantResult:
    variant: Variant
    all_rows: OverlayStats
    holdouts: dict[str, OverlayStats]


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def in_holdout(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def escape_cell(text: str) -> str:
    return text.replace("|", "&#124;")


def code_cell(text: str) -> str:
    return f"`{escape_cell(text)}`"


def apply_variant(base_rank: list[int], case: Case | None, variant: Variant, base_predicate: Any) -> tuple[list[int], bool, bool]:
    if variant.is_base or case is None or not base_predicate.fn(case):
        return base_rank, False, False
    if any(predicate.fn(case) for predicate in variant.exception_predicates):
        return base_rank, False, True
    ability = case.ability_index
    return [ability] + [index for index in base_rank if index != ability], True, False


def update_overlay(overlay: OverlayStats, label: int | None, base_rank: list[int], rank: list[int], fired: bool, eligible: bool, suppressed: bool, case: Case | None) -> None:
    update_stats(overlay.stats, label, base_rank, rank, fired, eligible)
    if suppressed and case is not None:
        overlay.suppressed += 1
        overlay.prevented_regressions += int(case.outcome == "regression")
        overlay.lost_fixes += int(case.outcome == "fix")
        overlay.neutral_suppressed += int(case.outcome == "neutral")


def evaluate(rows: list[dict[str, Any]], weights: dict[str, float], variants: list[Variant], base_predicate: Any, args: argparse.Namespace) -> list[VariantResult]:
    results = [
        VariantResult(
            variant=variant,
            all_rows=OverlayStats(),
            holdouts={key: OverlayStats() for key in args.holdout_key},
        )
        for variant in variants
    ]
    for row in rows:
        label = valid_single_label(row)
        if label is None:
            for result in results:
                update_overlay(result.all_rows, None, [], [], False, False, False, None)
            continue
        case, base_rank = eligible_case(row, weights)
        if not base_rank:
            base_rank = ranked_options(weights, row)
        eligible = case is not None and base_predicate.fn(case)
        for result in results:
            rank, fired, suppressed = apply_variant(base_rank, case, result.variant, base_predicate)
            update_overlay(result.all_rows, label, base_rank, rank, fired, eligible, suppressed, case)
            for key in args.holdout_key:
                if in_holdout(row, key, args.holdout_mod, args.holdout_bucket):
                    update_overlay(result.holdouts[key], label, base_rank, rank, fired, eligible, suppressed, case)
    return results


def top1(stats: OverlayStats) -> float:
    return stats.stats.guard_top1 / stats.stats.total if stats.stats.total else 0.0


def top1_delta(stats: OverlayStats) -> int:
    return stats.stats.guard_top1 - stats.stats.base_top1


def result_row(name: str, stats: OverlayStats) -> str:
    raw = stats.stats
    return (
        f"| {code_cell(name)} | {raw.total} | {pct(raw.base_top1, raw.total)} | "
        f"{pct(raw.guard_top1, raw.total)} | {top1_delta(stats):+d} | "
        f"{pct(raw.base_top3, raw.total)} | {pct(raw.guard_top3, raw.total)} | "
        f"{raw.eligible} | {raw.fired} | {raw.changed} | {raw.fixes} | {raw.regressions} | "
        f"{stats.suppressed} | {stats.prevented_regressions} / {stats.lost_fixes} |"
    )


def choose_decision(results: list[VariantResult]) -> tuple[str, list[str]]:
    base = next(result for result in results if result.variant.name == "base ranker")
    broad = next(result for result in results if result.variant.name == "broad ability-before-attack")
    cumulative = next((result for result in results if result.variant.name == "accepted exceptions cumulative"), None)
    notes: list[str] = []
    if cumulative is None:
        return "feature-only", ["No cumulative exception variant was evaluated."]

    broad_all = top1(broad.all_rows)
    cumulative_all = top1(cumulative.all_rows)
    base_all = top1(base.all_rows)
    if cumulative_all < base_all:
        notes.append("Cumulative exceptions fall below the base ranker on all rows.")
    if cumulative_all < broad_all:
        notes.append("Cumulative exceptions reduce all-row top-1 versus the broad ability-before-attack overlay.")
    for key, stats in cumulative.holdouts.items():
        if top1(stats) < top1(broad.holdouts[key]):
            notes.append(f"Cumulative exceptions reduce `{key}` holdout top-1 versus broad overlay.")
    if cumulative.all_rows.stats.regressions > cumulative.all_rows.stats.fixes:
        notes.append("Cumulative exceptions still have more regressions than fixes.")
    if not notes:
        return "offline-feature-accepted", [
            "Cumulative exceptions preserve or improve broad-overlay top-1 on all tested splits.",
            "Keep this as an offline value/ranker feature only; public-score gates still control submit eligibility.",
        ]
    return "research-only", notes + ["Do not hard-code or package this overlay yet."]


def render(args: argparse.Namespace, rows: list[dict[str, Any]], exceptions: list[Any], results: list[VariantResult]) -> str:
    decision, notes = choose_decision(results)
    lines = [
        "# Timing Exception Overlay Evaluation",
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
        "- Runtime premise: deterministic offline analysis only; no network or LLM at play time.",
        "- Submission status: no submission made.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Rows loaded: {len(rows)}",
        f"- Base positive motif: `{escape_cell(args.base_predicate)}`",
        f"- Holdouts: {', '.join(args.holdout_key)} with sha1(value) % {args.holdout_mod} == {args.holdout_bucket}",
        "- Accepted exception candidates:",
    ]
    for exception in exceptions:
        lines.append(f"  - `{escape_cell(exception.name)}`")
    lines.extend(
        [
            "",
            "## All Rows",
            "",
            "| Variant | N | Base Top-1 | Overlay Top-1 | Delta | Base Top-3 | Overlay Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in results:
        lines.append(result_row(result.variant.name, result.all_rows))

    for key in args.holdout_key:
        lines.extend(
            [
                "",
                f"## Holdout: `{key}`",
                "",
                "| Variant | N | Base Top-1 | Overlay Top-1 | Delta | Base Top-3 | Overlay Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for result in results:
            lines.append(result_row(result.variant.name, result.holdouts[key]))

    lines.extend(["", "## Decision", "", f"- Status: **{decision}**"])
    for note in notes:
        lines.append(f"- {note}")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Positive action-imitation lift is strategy-feature evidence, not submit evidence.",
            "- A runtime agent branch still requires public-anchor eligibility and public-score backtest correlation.",
            "- If an exception wins one split but loses another, keep it as a model feature or negative-control signal rather than hard-coding it.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: list[VariantResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "variant",
                "split",
                "n",
                "base_top1",
                "overlay_top1",
                "delta_top1_count",
                "base_top3",
                "overlay_top3",
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
        for result in results:
            rows = [("all", result.all_rows), *result.holdouts.items()]
            for split, overlay in rows:
                stats = overlay.stats
                writer.writerow(
                    [
                        result.variant.name,
                        split,
                        stats.total,
                        f"{stats.base_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        f"{stats.guard_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        stats.guard_top1 - stats.base_top1,
                        f"{stats.base_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        f"{stats.guard_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        stats.eligible,
                        stats.fired,
                        stats.changed,
                        stats.fixes,
                        stats.regressions,
                        overlay.suppressed,
                        overlay.prevented_regressions,
                        overlay.lost_fixes,
                    ]
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--base-predicate", default="all")
    parser.add_argument("--exception", action="append", default=[])
    parser.add_argument("--holdout-key", action="append", choices=DEFAULT_HOLDOUT_KEYS, default=[])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/timing_exception_overlay.md"))
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()

    if not args.exception:
        args.exception = list(DEFAULT_EXCEPTIONS)
    if not args.holdout_key:
        args.holdout_key = list(DEFAULT_HOLDOUT_KEYS)
    if args.csv_out is None:
        args.csv_out = args.report_out.with_suffix(".csv")

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    base_predicate = parse_predicate(args.base_predicate)
    exceptions = [parse_predicate(raw) for raw in args.exception]
    variants = [
        Variant("base ranker", is_base=True),
        Variant("broad ability-before-attack"),
    ]
    variants.extend(Variant(f"exception only: {predicate.name}", (predicate,)) for predicate in exceptions)
    variants.append(Variant("accepted exceptions cumulative", tuple(exceptions)))

    results = evaluate(rows, weights, variants, base_predicate, args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, rows, exceptions, results), encoding="utf-8")
    write_csv(args.csv_out, results)
    decision, notes = choose_decision(results)
    print(f"decision={decision} report={args.report_out} csv={args.csv_out}")
    for note in notes:
        print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
