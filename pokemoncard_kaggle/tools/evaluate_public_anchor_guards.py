#!/usr/bin/env python3
"""Evaluate public-anchored guard rules as a tiny action-ranker overlay.

This is intentionally offline and diagnostic. It does not claim public-score
predictiveness; it measures whether transparent strategy guards improve replay
action agreement on held-out public-anchor decisions before any agent code is
changed.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy_gap_miner import motif, row_group  # noqa: E402
from train_action_ranker import load_rows, option_features, option_parts, pct, score, valid_single_label  # noqa: E402
from train_public_anchor_target_model import (  # noqa: E402
    PairExample,
    collect_examples,
    is_holdout,
    load_base_model,
    load_targets,
)


@dataclass(frozen=True)
class GuardRule:
    name: str
    scope: str
    prefer_motif: str
    avoid_motif: str
    context: str = ""
    opponent_archetype: str = ""
    prefer_type: str = ""
    avoid_type: str = ""


@dataclass
class EvalStats:
    total: int = 0
    skipped: int = 0
    base_top1: int = 0
    guard_top1: int = 0
    base_top3: int = 0
    guard_top3: int = 0
    fired: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0


@dataclass
class PairStats:
    total: int = 0
    base_pair: int = 0
    guard_pair: int = 0
    base_top1: int = 0
    guard_top1: int = 0
    fired: int = 0
    changed: int = 0


@dataclass
class RuleEffect:
    fires: int = 0
    changes: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0


def load_rules(path: Path, only_opponent_specific: bool, rule_names: set[str]) -> list[GuardRule]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rules = []
    for raw in payload.get("rules", []):
        rule = GuardRule(
            name=str(raw.get("name") or ""),
            scope=str(raw.get("scope") or ""),
            prefer_motif=str(raw.get("prefer_motif") or ""),
            avoid_motif=str(raw.get("avoid_motif") or ""),
            context=str(raw.get("context") or ""),
            opponent_archetype=str(raw.get("opponent_archetype") or ""),
            prefer_type=str(raw.get("prefer_type") or ""),
            avoid_type=str(raw.get("avoid_type") or ""),
        )
        if only_opponent_specific and not rule.opponent_archetype:
            continue
        if rule_names and rule.name not in rule_names:
            continue
        rules.append(rule)
    return rules


def option_motif(text: str) -> str:
    return motif(text)


def option_type(text: str) -> str:
    return option_parts(text)["type"] or "UNKNOWN"


def rule_matches_context(rule: GuardRule, row: dict[str, Any]) -> bool:
    if rule.context and row_group(row, "context") != rule.context:
        return False
    if rule.opponent_archetype and row_group(row, "opponent_archetype") != rule.opponent_archetype:
        return False
    return True


def option_matches(rule: GuardRule, text: str, side: str) -> bool:
    if side == "prefer":
        if rule.prefer_type:
            return option_type(text) == rule.prefer_type
        return option_motif(text) == rule.prefer_motif
    if rule.avoid_type:
        return option_type(text) == rule.avoid_type
    return option_motif(text) == rule.avoid_motif


def rank_base(weights: dict[str, float], row: dict[str, Any]) -> list[int]:
    option_count = int(row.get("option_count") or 0)
    scored = [
        (score(weights, option_features(row, index)), -index, index)
        for index in range(option_count)
    ]
    scored.sort(reverse=True)
    return [index for _score, _neg_index, index in scored]


def rank_with_guards(
    weights: dict[str, float],
    row: dict[str, Any],
    rules: list[GuardRule],
    bonus: float,
) -> tuple[list[int], str]:
    options = row.get("options") or []
    option_count = int(row.get("option_count") or 0)
    if option_count <= 0:
        return [], ""
    base_scores = [score(weights, option_features(row, index)) for index in range(option_count)]
    base_order = sorted(range(option_count), key=lambda index: (base_scores[index], -index), reverse=True)
    if not base_order:
        return [], ""
    base_top = base_order[0]
    fired_rule = ""
    adjusted = list(base_scores)
    for rule in rules:
        if not rule_matches_context(rule, row):
            continue
        prefer = [index for index, text in enumerate(options[:option_count]) if option_matches(rule, str(text), "prefer")]
        avoid = [index for index, text in enumerate(options[:option_count]) if option_matches(rule, str(text), "avoid")]
        if prefer and base_top in avoid:
            for index in prefer:
                adjusted[index] += bonus
            for index in avoid:
                adjusted[index] -= bonus
            fired_rule = rule.name
            break
    guarded = sorted(range(option_count), key=lambda index: (adjusted[index], -index), reverse=True)
    return guarded, fired_rule


def update_stats(stats: EvalStats, label: int | None, base_rank: list[int], guard_rank: list[int], fired_rule: str) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    base_hit = bool(base_rank and base_rank[0] == label)
    guard_hit = bool(guard_rank and guard_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.guard_top1 += int(guard_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.guard_top3 += int(label in guard_rank[:3])
    stats.fired += int(bool(fired_rule))
    changed = bool(base_rank and guard_rank and base_rank[0] != guard_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and guard_hit)
    stats.regressions += int(changed and base_hit and not guard_hit)
    stats.neutral_changes += int(changed and base_hit == guard_hit)


def eval_rows(
    rows: list[dict[str, Any]],
    weights: dict[str, float],
    rules: list[GuardRule],
    args: argparse.Namespace,
) -> tuple[EvalStats, dict[str, EvalStats], Counter[str], Counter[str], dict[str, RuleEffect]]:
    overall = EvalStats()
    groups: dict[str, EvalStats] = defaultdict(EvalStats)
    rule_fires: Counter[str] = Counter()
    changes: Counter[str] = Counter()
    rule_effects: dict[str, RuleEffect] = defaultdict(RuleEffect)
    for row in rows:
        label = valid_single_label(row)
        base_rank = [] if label is None else rank_base(weights, row)
        guard_rank, fired_rule = ([], "") if label is None else rank_with_guards(weights, row, rules, args.guard_bonus)
        update_stats(overall, label, base_rank, guard_rank, fired_rule)
        key = f"{row_group(row, 'archetype')} vs {row_group(row, 'opponent_archetype')}"
        update_stats(groups[key], label, base_rank, guard_rank, fired_rule)
        if fired_rule:
            rule_fires[fired_rule] += 1
            effect = rule_effects[fired_rule]
            effect.fires += 1
        if label is not None and base_rank and guard_rank and base_rank[0] != guard_rank[0]:
            if fired_rule:
                effect = rule_effects[fired_rule]
                effect.changes += 1
                base_hit = base_rank[0] == label
                guard_hit = guard_rank[0] == label
                effect.fixes += int(not base_hit and guard_hit)
                effect.regressions += int(base_hit and not guard_hit)
                effect.neutral_changes += int(base_hit == guard_hit)
            options = row.get("options") or []
            before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
            after = options[guard_rank[0]] if guard_rank[0] < len(options) else str(guard_rank[0])
            selected = options[label] if label < len(options) else str(label)
            outcome = "fix" if guard_rank[0] == label and base_rank[0] != label else "regress" if base_rank[0] == label else "neutral"
            changes[f"{outcome}: {fired_rule}: public={selected} | base={before} | guard={after}"] += 1
    return overall, dict(groups), rule_fires, changes, dict(rule_effects)


def eval_pair_examples(
    examples: list[PairExample],
    weights: dict[str, float],
    rules: list[GuardRule],
    args: argparse.Namespace,
) -> tuple[PairStats, dict[str, PairStats], Counter[str]]:
    overall = PairStats()
    by_gap: dict[str, PairStats] = defaultdict(PairStats)
    fires: Counter[str] = Counter()
    for example in examples:
        base_rank = rank_base(weights, example.row)
        guard_rank, fired_rule = rank_with_guards(weights, example.row, rules, args.guard_bonus)
        base_pos = base_rank.index(example.public_index) if example.public_index in base_rank else 9999
        base_neg = base_rank.index(example.competitor_index) if example.competitor_index in base_rank else 9999
        guard_pos = guard_rank.index(example.public_index) if example.public_index in guard_rank else 9999
        guard_neg = guard_rank.index(example.competitor_index) if example.competitor_index in guard_rank else 9999
        for stats in (overall, by_gap[example.target.gap]):
            stats.total += 1
            stats.base_pair += int(base_pos < base_neg)
            stats.guard_pair += int(guard_pos < guard_neg)
            stats.base_top1 += int(bool(base_rank) and base_rank[0] == example.public_index)
            stats.guard_top1 += int(bool(guard_rank) and guard_rank[0] == example.public_index)
            stats.fired += int(bool(fired_rule))
            stats.changed += int(bool(base_rank and guard_rank and base_rank[0] != guard_rank[0]))
        if fired_rule:
            fires[fired_rule] += 1
    return overall, dict(by_gap), fires


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | {pct(stats.guard_top1, stats.total)} | "
        f"{pct(stats.base_top3, stats.total)} | {pct(stats.guard_top3, stats.total)} | {stats.fired} | "
        f"{stats.changed} | {stats.fixes} | {stats.regressions} |"
    )


def pair_row(name: str, stats: PairStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_pair, stats.total)} | {pct(stats.guard_pair, stats.total)} | "
        f"{pct(stats.base_top1, stats.total)} | {pct(stats.guard_top1, stats.total)} | {stats.fired} | {stats.changed} |"
    )


def render_report(
    args: argparse.Namespace,
    row_count: int,
    rules: list[GuardRule],
    all_stats: EvalStats,
    holdout_stats: EvalStats,
    group_stats: dict[str, EvalStats],
    rule_fires: Counter[str],
    changes: Counter[str],
    rule_effects: dict[str, RuleEffect],
    holdout_rule_effects: dict[str, RuleEffect],
    target_train: PairStats,
    target_holdout: PairStats,
    target_by_gap: dict[str, PairStats],
    target_fires: Counter[str],
) -> str:
    lines: list[str] = []
    lines.append("# Public-Anchored Guard Reranker Evaluation")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.base_model}`")
    lines.append(f"- Guard rules: `{args.guards}`")
    lines.append(f"- Target CSV: `{args.targets}`")
    lines.append(f"- Rules loaded: {len(rules)}")
    lines.append(f"- Rows loaded: {row_count}")
    lines.append(f"- Guard mode: {'opponent-specific only' if args.only_opponent_specific else 'all rules'}")
    lines.append(f"- Overlay behavior: first rule whose avoid side is the base top-1 action; bonus={args.guard_bonus:g}")
    lines.append(f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append("")
    lines.append("## Replay-Action Agreement")
    lines.append("")
    lines.append("| Split | N | Base Top-1 | Guard Top-1 | Base Top-3 | Guard Top-3 | Fires | Top-1 Changes | Fixes | Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(stats_row("all valid rows", all_stats))
    lines.append(stats_row("held-out teams", holdout_stats))
    lines.append("")
    lines.append("## Public-Anchor Pair Agreement")
    lines.append("")
    lines.append("| Split/Gap | N | Base Public > Competitor | Guard Public > Competitor | Base Top-1 | Guard Top-1 | Fires | Top-1 Changes |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    lines.append(pair_row("target train teams", target_train))
    lines.append(pair_row("target held-out teams", target_holdout))
    for gap, stats in sorted(target_by_gap.items(), key=lambda item: item[1].total, reverse=True)[: args.limit]:
        lines.append(pair_row(gap, stats))
    lines.append("")
    lines.append("## Top Rule Fires")
    lines.append("")
    for name, count in rule_fires.most_common(args.limit):
        lines.append(f"- {count}: `{name}`")
    if not rule_fires:
        lines.append("- 0: no rule fired")
    lines.append("")
    lines.append("## Per-Rule Safety")
    lines.append("")
    lines.append("| Rule | All Fires | All Fixes | All Regressions | Holdout Fires | Holdout Fixes | Holdout Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, effect in sorted(rule_effects.items(), key=lambda item: (item[1].fixes - item[1].regressions, item[1].fires), reverse=True)[: args.limit]:
        holdout_effect = holdout_rule_effects.get(name, RuleEffect())
        lines.append(
            f"| `{name}` | {effect.fires} | {effect.fixes} | {effect.regressions} | "
            f"{holdout_effect.fires} | {holdout_effect.fixes} | {holdout_effect.regressions} |"
        )
    if not rule_effects:
        lines.append("| - | 0 | 0 | 0 | 0 | 0 | 0 |")
    lines.append("")
    lines.append("## Target Rule Fires")
    lines.append("")
    for name, count in target_fires.most_common(args.limit):
        lines.append(f"- {count}: `{name}`")
    if not target_fires:
        lines.append("- 0: no target rule fired")
    lines.append("")
    lines.append("## Group Deltas")
    lines.append("")
    lines.append("| Group | N | Base Top-1 | Guard Top-1 | Fires | Fixes | Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    eligible = [(name, stats) for name, stats in group_stats.items() if stats.total >= args.min_group_n and stats.fired]
    eligible.sort(key=lambda item: (item[1].guard_top1 - item[1].base_top1, item[1].fired), reverse=True)
    for name, stats in eligible[: args.limit]:
        lines.append(
            f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | {pct(stats.guard_top1, stats.total)} | "
            f"{stats.fired} | {stats.fixes} | {stats.regressions} |"
        )
    if not eligible:
        lines.append("| - | 0 | 0.000 | 0.000 | 0 | 0 | 0 |")
    lines.append("")
    lines.append("## Largest Top-1 Changes")
    lines.append("")
    for text, count in changes.most_common(args.limit):
        lines.append(f"- {count}: {text}")
    if not changes:
        lines.append("- No top-1 changes.")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if target_holdout.total and target_holdout.fired == 0:
        lines.append("- The selected rules did not fire on held-out public-anchor pair examples; use broad replay-action deltas rather than target-pair deltas for this subset.")
    elif target_holdout.total and target_holdout.guard_pair >= target_holdout.base_pair:
        lines.append("- The guard overlay improves or preserves public-vs-competitor ordering on held-out public-anchor examples.")
    else:
        lines.append("- The guard overlay does not improve held-out public-anchor pair ordering; keep it as analysis only.")
    if holdout_stats.regressions:
        lines.append("- Regressions exist on held-out replay rows; any runtime patch must be narrower or gated by motif before packaging.")
    else:
        lines.append("- No held-out top-1 regressions were observed under this overlay, but this is still not a public-score predictor.")
    lines.append("- This report is a strategy/ML signal only. The public-anchor and backtest submit gates still decide promotion.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--guards", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_guard_eval.md"))
    parser.add_argument("--only-opponent-specific", action="store_true")
    parser.add_argument("--rule-name", action="append", default=[])
    parser.add_argument("--guard-bonus", type=float, default=1000.0)
    parser.add_argument("--top-targets", type=int, default=8)
    parser.add_argument("--target-rank", type=int, action="append")
    parser.add_argument("--gap", action="append")
    parser.add_argument("--archetype")
    parser.add_argument("--deck-hash")
    parser.add_argument("--anchor-tier", action="append", default=["exact-public-replay-supported"])
    parser.add_argument("--min-source-count", type=int, default=25)
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source", "target"], default="team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-group-n", type=int, default=50)
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_base_model(args.base_model)
    rules = load_rules(args.guards, args.only_opponent_specific, set(args.rule_name))
    targets = load_targets(args.targets, args)
    examples = collect_examples(rows, weights, targets)
    train_examples = [example for example in examples if not is_holdout(example, args)]
    holdout_examples = [example for example in examples if is_holdout(example, args)]
    holdout_rows = [row for row in rows if row_group(row, args.holdout_key) and is_row_holdout(row, args)]

    all_stats, group_stats, rule_fires, changes, rule_effects = eval_rows(rows, weights, rules, args)
    holdout_stats, _holdout_groups, _holdout_fires, _holdout_changes, holdout_rule_effects = eval_rows(holdout_rows, weights, rules, args)
    target_train, _target_train_by_gap, _target_train_fires = eval_pair_examples(train_examples, weights, rules, args)
    target_holdout, target_by_gap, target_fires = eval_pair_examples(holdout_examples, weights, rules, args)

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(
            args,
            len(rows),
            rules,
            all_stats,
            holdout_stats,
            group_stats,
            rule_fires,
            changes,
            rule_effects,
            holdout_rule_effects,
            target_train,
            target_holdout,
            target_by_gap,
            target_fires,
        ),
        encoding="utf-8",
    )
    print(
        "rows={rows} rules={rules} all_base_top1={base} all_guard_top1={guard} "
        "target_holdout_pair={pair} report={report}".format(
            rows=len(rows),
            rules=len(rules),
            base=pct(all_stats.base_top1, all_stats.total),
            guard=pct(all_stats.guard_top1, all_stats.total),
            pair=pct(target_holdout.guard_pair, target_holdout.total),
            report=args.report_out,
        )
    )
    return 0


def is_row_holdout(row: dict[str, Any], args: argparse.Namespace) -> bool:
    from train_action_ranker import stable_bucket

    if args.holdout_key == "target":
        value = f"{row_group(row, 'archetype')}:{row_group(row, 'deck_hash')}"
    else:
        value = row_group(row, args.holdout_key)
    return stable_bucket(value, args.holdout_mod) == args.holdout_bucket


if __name__ == "__main__":
    raise SystemExit(main())
