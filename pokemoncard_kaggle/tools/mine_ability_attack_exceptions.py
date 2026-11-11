#!/usr/bin/env python3
"""Mine exceptions for the Dudunsparce ability-before-attack motif.

The current best strategy feature is: when the base policy wants to attack while
Dudunsparce ability is legal, public play often uses Dudunsparce first. This
tool mines the opposite boundary: runtime-observable predicates where forcing
the ability would erase a correct attack. It evaluates each exception as
"apply ability-before-attack unless this exception fires".
"""

from __future__ import annotations

import argparse
import os
import socket
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from evaluate_ability_attack_predicates import EvalStats, eligible_case, parse_predicate, row_holdout, update_stats
from mine_ability_attack_guard import Case, collect_cases, feature_map, load_model
from train_action_ranker import load_rows, pct, ranked_options, stable_bucket, valid_single_label


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[Case], bool]


@dataclass
class ExceptionStats:
    total: int = 0
    prevented_regressions: int = 0
    lost_fixes: int = 0
    neutral: int = 0

    @property
    def net(self) -> int:
        return self.prevented_regressions - self.lost_fixes

    @property
    def precision(self) -> float:
        den = self.prevented_regressions + self.lost_fixes
        return self.prevented_regressions / den if den else 0.0


@dataclass
class OverlayEval:
    stats: EvalStats
    suppressed: int = 0
    prevented_regressions: int = 0
    lost_fixes: int = 0
    neutral_suppressed: int = 0


def row_value(row: dict, key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def make_exception_predicates(cases: list[Case], min_atom_count: int) -> list[Predicate]:
    values: dict[str, Counter[str]] = {}
    for case in cases:
        for key, value in feature_map(case).items():
            if key == "reward":
                continue
            values.setdefault(key, Counter())[value] += 1

    atoms: list[Predicate] = []
    for key, counter in sorted(values.items()):
        for value, count in counter.items():
            if count < min_atom_count:
                continue
            atoms.append(Predicate(f"{key}={value}", lambda case, k=key, v=value: feature_map(case).get(k) == v))

    predicates: list[Predicate] = list(atoms)
    for left_index, left in enumerate(atoms):
        for right in atoms[left_index + 1 :]:
            left_key = left.name.split("=", 1)[0]
            right_key = right.name.split("=", 1)[0]
            if left_key == right_key:
                continue
            predicates.append(
                Predicate(
                    f"{left.name} & {right.name}",
                    lambda case, l=left.fn, r=right.fn: l(case) and r(case),
                )
            )
    return predicates


def case_holdout(case: Case, args: argparse.Namespace) -> bool:
    value = row_value(case.row, args.holdout_key)
    return stable_bucket(value, args.holdout_mod) == args.holdout_bucket


def score_exception(cases: list[Case], predicate: Predicate) -> ExceptionStats:
    stats = ExceptionStats()
    for case in cases:
        if not predicate.fn(case):
            continue
        stats.total += 1
        if case.outcome == "regression":
            stats.prevented_regressions += 1
        elif case.outcome == "fix":
            stats.lost_fixes += 1
        else:
            stats.neutral += 1
    return stats


def select_candidates(cases: list[Case], predicates: list[Predicate], args: argparse.Namespace) -> list[tuple[Predicate, ExceptionStats]]:
    scored: list[tuple[Predicate, ExceptionStats]] = []
    for predicate in predicates:
        stats = score_exception(cases, predicate)
        if stats.total < args.min_total:
            continue
        if stats.prevented_regressions < args.min_prevented:
            continue
        if stats.net < args.min_net:
            continue
        if stats.precision < args.min_precision:
            continue
        scored.append((predicate, stats))
    scored.sort(
        key=lambda item: (
            item[1].net,
            item[1].precision,
            item[1].prevented_regressions,
            -item[1].lost_fixes,
            item[1].total,
        ),
        reverse=True,
    )
    return scored[: args.candidate_limit]


def guarded_rank(base_rank: list[int], case: Case | None, base_predicate: Predicate, exception: Predicate | None) -> tuple[list[int], bool, bool]:
    if case is None or not base_predicate.fn(case):
        return base_rank, False, False
    if exception is not None and exception.fn(case):
        return base_rank, False, True
    ability = case.ability_index
    return [ability] + [index for index in base_rank if index != ability], True, False


def evaluate_overlay(rows: list[dict], weights: dict[str, float], base_predicate: Predicate, exception: Predicate | None, args: argparse.Namespace) -> tuple[OverlayEval, OverlayEval]:
    all_eval = OverlayEval(EvalStats())
    holdout_eval = OverlayEval(EvalStats())
    for row in rows:
        label = valid_single_label(row)
        if label is None:
            update_stats(all_eval.stats, None, [], [], False, False)
            continue
        case, base_rank = eligible_case(row, weights)
        if not base_rank:
            base_rank = ranked_options(weights, row)
        guard_rank, fired, suppressed = guarded_rank(base_rank, case, base_predicate, exception)
        eligible = case is not None and base_predicate.fn(case)
        update_stats(all_eval.stats, label, base_rank, guard_rank, fired, eligible)
        if suppressed and case is not None:
            all_eval.suppressed += 1
            all_eval.prevented_regressions += int(case.outcome == "regression")
            all_eval.lost_fixes += int(case.outcome == "fix")
            all_eval.neutral_suppressed += int(case.outcome == "neutral")
        if row_holdout(row, args):
            update_stats(holdout_eval.stats, label, base_rank, guard_rank, fired, eligible)
            if suppressed and case is not None:
                holdout_eval.suppressed += 1
                holdout_eval.prevented_regressions += int(case.outcome == "regression")
                holdout_eval.lost_fixes += int(case.outcome == "fix")
                holdout_eval.neutral_suppressed += int(case.outcome == "neutral")
    return all_eval, holdout_eval


def eval_row(name: str, overlay: OverlayEval) -> str:
    stats = overlay.stats
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | "
        f"{pct(stats.guard_top1, stats.total)} | {pct(stats.base_top3, stats.total)} | "
        f"{pct(stats.guard_top3, stats.total)} | {stats.eligible} | {stats.fired} | "
        f"{stats.changed} | {stats.fixes} | {stats.regressions} | {overlay.suppressed} | "
        f"{overlay.prevented_regressions} / {overlay.lost_fixes} |"
    )


def render_report(
    args: argparse.Namespace,
    rows: list[dict],
    train_cases: list[Case],
    holdout_cases: list[Case],
    base_predicate: Predicate,
    candidates: list[tuple[Predicate, ExceptionStats]],
    evaluations: list[tuple[Predicate | None, ExceptionStats | None, OverlayEval, OverlayEval]],
) -> str:
    lines: list[str] = [
        "# Ability-Before-Attack Exception Miner",
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
        "- Strategy premise: keep the accepted Dudunsparce ability-before-attack timing motif, but mine exceptions before any hard policy branch.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Rows loaded: {len(rows)}",
        f"- Base positive predicate: `{base_predicate.name}`",
        f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}",
        f"- Train/holdout eligible cases: {len(train_cases)} / {len(holdout_cases)}",
        "",
        "## Candidate Exception Predicates",
        "",
        "| Rank | Predicate | Train Total | Prevented Regressions | Lost Fixes | Neutral | Net | Precision | Holdout Prevented / Lost |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for index, (predicate, stats) in enumerate(candidates, start=1):
        holdout_stats = score_exception(holdout_cases, predicate)
        lines.append(
            f"| {index} | `{predicate.name}` | {stats.total} | {stats.prevented_regressions} | "
            f"{stats.lost_fixes} | {stats.neutral} | {stats.net} | {stats.precision:.3f} | "
            f"{holdout_stats.prevented_regressions} / {holdout_stats.lost_fixes} |"
        )
    if not candidates:
        lines.append("| 0 | - | 0 | 0 | 0 | 0 | 0 | 0.000 | 0 / 0 |")
    lines.extend(
        [
            "",
            "## Overlay Evaluation",
            "",
            "| Variant | N | Base Top-1 | Guard Top-1 | Base Top-3 | Guard Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Suppressed | Prevented / Lost |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for predicate, _stats, all_eval, holdout_eval in evaluations:
        name = "broad ability-before-attack" if predicate is None else f"exception: {predicate.name}"
        lines.append(eval_row(f"{name} all", all_eval))
        lines.append(eval_row(f"{name} holdout", holdout_eval))
    lines.extend(["", "## Interpretation", ""])
    best = None
    for predicate, stats, all_eval, holdout_eval in evaluations:
        if predicate is None:
            continue
        if best is None:
            best = (predicate, stats, all_eval, holdout_eval)
            continue
        current = (holdout_eval.stats.guard_top1 - best[3].stats.guard_top1, all_eval.stats.guard_top1 - best[2].stats.guard_top1)
        if current > (0, 0):
            best = (predicate, stats, all_eval, holdout_eval)
    if best is None:
        lines.append("- No exception predicate cleared the train-side filters. Keep the existing positive motif as feature-only.")
    else:
        predicate, stats, all_eval, holdout_eval = best
        broad_all = evaluations[0][2]
        broad_holdout = evaluations[0][3]
        all_delta = all_eval.stats.guard_top1 - broad_all.stats.guard_top1
        holdout_delta = holdout_eval.stats.guard_top1 - broad_holdout.stats.guard_top1
        if all_delta >= 0 and holdout_delta >= 0:
            lines.append(
                f"- Best exception `{predicate.name}` does not reduce top-1 versus the broad overlay on all/holdout rows "
                f"(delta {all_delta:+d} / {holdout_delta:+d}); keep it as a candidate exception feature."
            )
        else:
            lines.append(
                f"- Best exception `{predicate.name}` is not safe enough yet: top-1 delta versus broad overlay is "
                f"{all_delta:+d} all / {holdout_delta:+d} holdout."
            )
    lines.append("- This is still an offline strategy feature report. Do not package or submit from it without public-anchor and public-score backtest gates.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/ability_attack_exception_miner.md"))
    parser.add_argument("--base-predicate", default="all")
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source"], default="opponent_team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-atom-count", type=int, default=12)
    parser.add_argument("--min-total", type=int, default=12)
    parser.add_argument("--min-prevented", type=int, default=4)
    parser.add_argument("--min-net", type=int, default=1)
    parser.add_argument("--min-precision", type=float, default=0.55)
    parser.add_argument("--candidate-limit", type=int, default=12)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    base_predicate = parse_predicate(args.base_predicate)
    cases = [case for case in collect_cases(rows, weights) if base_predicate.fn(case)]
    train_cases = [case for case in cases if not case_holdout(case, args)]
    holdout_cases = [case for case in cases if case_holdout(case, args)]
    predicates = make_exception_predicates(train_cases, args.min_atom_count)
    candidates = select_candidates(train_cases, predicates, args)

    evaluations: list[tuple[Predicate | None, ExceptionStats | None, OverlayEval, OverlayEval]] = []
    broad_all, broad_holdout = evaluate_overlay(rows, weights, base_predicate, None, args)
    evaluations.append((None, None, broad_all, broad_holdout))
    for predicate, stats in candidates[: args.candidate_limit]:
        all_eval, holdout_eval = evaluate_overlay(rows, weights, base_predicate, predicate, args)
        evaluations.append((predicate, stats, all_eval, holdout_eval))

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, rows, train_cases, holdout_cases, base_predicate, candidates, evaluations),
        encoding="utf-8",
    )
    print(f"cases={len(cases)} train={len(train_cases)} holdout={len(holdout_cases)} candidates={len(candidates)} report={args.report_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
