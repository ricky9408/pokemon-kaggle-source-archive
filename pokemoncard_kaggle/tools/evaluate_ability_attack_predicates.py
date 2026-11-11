#!/usr/bin/env python3
"""Evaluate Dudunsparce ability-before-attack predicates as soft overlays.

This is a public-action imitation evaluator, not a submit selector. It tests
mined predicates from ``mine_ability_attack_guard.py`` by applying a tiny
action-ranker overlay only on MAIN states where the base ranker currently puts
an ATTACK above a legal Dudunsparce ability.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mine_ability_attack_guard import Case, card_id, feature_map, load_model
from train_action_ranker import (
    load_rows,
    option_parts,
    pct,
    ranked_options,
    stable_bucket,
    valid_single_label,
)


@dataclass
class EvalStats:
    total: int = 0
    skipped: int = 0
    base_top1: int = 0
    guard_top1: int = 0
    base_top3: int = 0
    guard_top3: int = 0
    eligible: int = 0
    fired: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[Case], bool]


def parse_predicate(raw: str) -> Predicate:
    text = raw.strip()
    if not text or text == "all":
        return Predicate("all", lambda _case: True)
    atoms = [part.strip() for part in text.split("&") if part.strip()]
    parsed: list[tuple[str, str]] = []
    for atom in atoms:
        if "=" not in atom:
            raise ValueError(f"Predicate atom must be key=value: {atom!r}")
        key, value = atom.split("=", 1)
        parsed.append((key.strip(), value.strip()))
    return Predicate(text, lambda case, parts=tuple(parsed): all(feature_map(case).get(key) == value for key, value in parts))


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def reward_bucket(value: Any) -> str:
    if value == 1:
        return "win"
    if value == -1:
        return "loss"
    if value == 0:
        return "draw"
    return "unknown"


def row_holdout(row: dict[str, Any], args: argparse.Namespace) -> bool:
    value = row_value(row, args.holdout_key)
    return stable_bucket(value, args.holdout_mod) == args.holdout_bucket


def eligible_case(row: dict[str, Any], weights: dict[str, float]) -> tuple[Case | None, list[int]]:
    label = valid_single_label(row)
    if label is None or row_value(row, "context") != "MAIN":
        return None, []
    ranking = ranked_options(weights, row)
    if not ranking:
        return None, []
    options = [str(option) for option in (row.get("options") or [])]
    ability_indices = [
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ABILITY" and card_id(text) == "66"
    ]
    attack_indices = [
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ATTACK"
    ]
    if not ability_indices or not attack_indices:
        return None, ranking
    base_top = ranking[0]
    if base_top not in attack_indices:
        return None, ranking
    ability_index = ability_indices[0]
    public_text = options[label] if label < len(options) else str(label)
    if label == ability_index:
        outcome = "fix"
    elif label in attack_indices:
        outcome = "regression"
    else:
        outcome = "neutral"
    return (
        Case(
            row=row,
            label=label,
            base_top=base_top,
            ability_index=ability_index,
            attack_index=base_top,
            outcome=outcome,
            public_text=public_text,
            base_text=options[base_top],
            ability_text=options[ability_index],
            attack_text=options[base_top],
        ),
        ranking,
    )


def guarded_rank(case: Case | None, base_rank: list[int], predicate: Predicate) -> tuple[list[int], bool]:
    if case is None or not predicate.fn(case):
        return base_rank, False
    ability = case.ability_index
    return [ability] + [index for index in base_rank if index != ability], True


def update_stats(stats: EvalStats, label: int | None, base_rank: list[int], guard_rank: list[int], fired: bool, eligible: bool) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.eligible += int(eligible)
    stats.fired += int(fired)
    base_hit = bool(base_rank and base_rank[0] == label)
    guard_hit = bool(guard_rank and guard_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.guard_top1 += int(guard_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.guard_top3 += int(label in guard_rank[:3])
    changed = bool(base_rank and guard_rank and base_rank[0] != guard_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and guard_hit)
    stats.regressions += int(changed and base_hit and not guard_hit)
    stats.neutral_changes += int(changed and base_hit == guard_hit)


def evaluate_one(rows: list[dict[str, Any]], weights: dict[str, float], predicate: Predicate, args: argparse.Namespace) -> tuple[EvalStats, EvalStats, dict[str, EvalStats], Counter[str], Counter[str]]:
    all_stats = EvalStats()
    holdout_stats = EvalStats()
    groups: dict[str, EvalStats] = defaultdict(EvalStats)
    fire_features: Counter[str] = Counter()
    changes: Counter[str] = Counter()
    for row in rows:
        label = valid_single_label(row)
        if label is None:
            update_stats(all_stats, None, [], [], False, False)
            continue
        case, base_rank = eligible_case(row, weights)
        if not base_rank:
            base_rank = ranked_options(weights, row)
        guard_rank, fired = guarded_rank(case, base_rank, predicate)
        eligible = case is not None
        update_stats(all_stats, label, base_rank, guard_rank, fired, eligible)
        group = f"{row_value(row, 'archetype')} vs {row_value(row, 'opponent_archetype')}"
        update_stats(groups[group], label, base_rank, guard_rank, fired, eligible)
        if row_holdout(row, args):
            update_stats(holdout_stats, label, base_rank, guard_rank, fired, eligible)
        if fired and case is not None:
            features = feature_map(case)
            fire_features.update(
                [
                    f"archetype={features['archetype']}",
                    f"opponent={features['opponent']}",
                    f"active={features['active']}",
                    f"attack={features['attack']}",
                    f"bench={features['bench']}",
                    f"hand={features['hand']}",
                    f"turn={features['turn']}",
                    f"reward={reward_bucket(row.get('terminal_reward'))}",
                ]
            )
            if base_rank and guard_rank and base_rank[0] != guard_rank[0]:
                options = row.get("options") or []
                selected = options[label] if label < len(options) else str(label)
                before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
                after = options[guard_rank[0]] if guard_rank[0] < len(options) else str(guard_rank[0])
                outcome = "fix" if guard_rank[0] == label and base_rank[0] != label else "regress" if base_rank[0] == label else "neutral"
                changes[f"{outcome}: public={selected} | base={before} | guard={after}"] += 1
    return all_stats, holdout_stats, dict(groups), fire_features, changes


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | {pct(stats.guard_top1, stats.total)} | "
        f"{pct(stats.base_top3, stats.total)} | {pct(stats.guard_top3, stats.total)} | {stats.eligible} | "
        f"{stats.fired} | {stats.changed} | {stats.fixes} | {stats.regressions} |"
    )


def render(args: argparse.Namespace, rows: list[dict[str, Any]], results: list[tuple[Predicate, EvalStats, EvalStats, dict[str, EvalStats], Counter[str], Counter[str]]]) -> str:
    lines: list[str] = [
        "# Ability-Attack Predicate Overlay Evaluation",
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
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Rows loaded: {len(rows)}",
        f"- Predicate count: {len(results)}",
        f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}",
        "- Overlay: if predicate fires, rank legal `ABILITY Dudunsparce(66)` above the base top-1 ATTACK.",
        "",
        "## Summary",
        "",
        "| Predicate | N | Base Top-1 | Guard Top-1 | Base Top-3 | Guard Top-3 | Eligible | Fires | Changes | Fixes | Regressions |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for predicate, all_stats, _holdout, _groups, _features, _changes in results:
        lines.append(stats_row(predicate.name, all_stats))
    lines.extend(["", "## Heldout Teams", "", "| Predicate | N | Base Top-1 | Guard Top-1 | Base Top-3 | Guard Top-3 | Eligible | Fires | Changes | Fixes | Regressions |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for predicate, _all_stats, holdout, _groups, _features, _changes in results:
        lines.append(stats_row(predicate.name, holdout))
    for predicate, all_stats, holdout, groups, features, changes in results:
        lines.extend(["", f"## Predicate Detail: `{predicate.name}`", ""])
        lines.append(f"- All delta top-1: {all_stats.guard_top1 - all_stats.base_top1:+d} ({pct(all_stats.guard_top1, all_stats.total)} vs {pct(all_stats.base_top1, all_stats.total)})")
        lines.append(f"- Heldout delta top-1: {holdout.guard_top1 - holdout.base_top1:+d} ({pct(holdout.guard_top1, holdout.total)} vs {pct(holdout.base_top1, holdout.total)})")
        lines.append(f"- Changes: {all_stats.changed}; fixes={all_stats.fixes}; regressions={all_stats.regressions}; neutral={all_stats.neutral_changes}")
        lines.append("")
        lines.append("Top fired features:")
        for feature, count in features.most_common(args.limit):
            lines.append(f"- {count}: `{feature}`")
        if not features:
            lines.append("- none")
        lines.append("")
        lines.append("Top group deltas:")
        eligible_groups = [item for item in groups.items() if item[1].fired]
        eligible_groups.sort(key=lambda item: (item[1].guard_top1 - item[1].base_top1, item[1].fired), reverse=True)
        for group, stats in eligible_groups[: args.limit]:
            lines.append(
                f"- `{group}` N={stats.total} fires={stats.fired} top1 {pct(stats.base_top1, stats.total)} -> {pct(stats.guard_top1, stats.total)} "
                f"fixes={stats.fixes} regressions={stats.regressions}"
            )
        if not eligible_groups:
            lines.append("- none")
        lines.append("")
        lines.append("Largest top-1 changes:")
        for text, count in changes.most_common(args.limit):
            lines.append(f"- {count}: {text}")
        if not changes:
            lines.append("- none")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Prefer predicates that improve all-row and heldout top-1 while keeping regressions lower than fixes.",
            "- A predicate with positive broad action imitation but weak heldout evidence should stay research-only.",
            "- This evaluates public-action imitation, not public-score rank correlation; submit gates remain closed unless public-anchor and backtest gates clear.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--predicate", action="append", required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/ability_attack_predicate_eval.md"))
    parser.add_argument("--holdout-key", choices=["team", "opponent_team", "episode_id", "source"], default="team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--limit", type=int, default=12)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    predicates = [parse_predicate(raw) for raw in args.predicate]
    results = []
    for predicate in predicates:
        results.append((predicate, *evaluate_one(rows, weights, predicate, args)))
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, rows, results), encoding="utf-8")
    for predicate, all_stats, holdout, _groups, _features, _changes in results:
        print(
            "{name}: all {base}->{guard} fires={fires} fixes={fixes} regressions={regs}; heldout {hbase}->{hguard} report={report}".format(
                name=predicate.name,
                base=pct(all_stats.base_top1, all_stats.total),
                guard=pct(all_stats.guard_top1, all_stats.total),
                fires=all_stats.fired,
                fixes=all_stats.fixes,
                regs=all_stats.regressions,
                hbase=pct(holdout.base_top1, holdout.total),
                hguard=pct(holdout.guard_top1, holdout.total),
                report=args.report_out,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
