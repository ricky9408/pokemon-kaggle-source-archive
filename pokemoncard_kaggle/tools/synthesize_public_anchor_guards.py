#!/usr/bin/env python3
"""Synthesize transparent policy guards from public-anchored target examples.

The target model can learn public-vs-model corrections, but runtime policy
patches need to be small and inspectable. This tool converts those corrections
into simple guard rules such as "in MAIN, prefer ATTACK over extra PLAY" and
tests them on a held-out split before any agent code is touched.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import sys
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy_gap_miner import motif, row_group  # noqa: E402
from train_action_ranker import option_parts, pct  # noqa: E402
from train_public_anchor_target_model import (  # noqa: E402
    PairExample,
    collect_examples,
    holdout_value,
    is_holdout,
    load_base_model,
    load_rows,
    load_targets,
)


SCOPE_PRIORITY = {
    "context_opponent_motif": 6,
    "context_motif": 5,
    "opponent_motif": 4,
    "global_motif": 3,
    "context_type": 2,
    "global_type": 1,
}


@dataclass(frozen=True)
class Rule:
    name: str
    scope: str
    prefer_motif: str
    avoid_motif: str
    context: str = ""
    opponent_archetype: str = ""
    prefer_type: str = ""
    avoid_type: str = ""
    train_support: int = 0
    train_accuracy: float = 0.0

    def key(self) -> tuple[str, str, str, str, str, str]:
        return (
            self.scope,
            self.context,
            self.opponent_archetype,
            self.prefer_motif,
            self.avoid_motif,
            self.prefer_type + ">" + self.avoid_type,
        )


@dataclass
class RuleStats:
    total: int = 0
    correct: int = 0
    wins: int = 0
    losses: int = 0
    mistakes: Counter[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.mistakes is None:
            self.mistakes = Counter()

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def option_motif(text: str) -> str:
    return motif(text)


def option_type(text: str) -> str:
    return option_parts(text)["type"] or "UNKNOWN"


def example_context(example: PairExample) -> str:
    return row_group(example.row, "context")


def example_opponent(example: PairExample) -> str:
    return row_group(example.row, "opponent_archetype")


def make_candidate_rules(examples: list[PairExample]) -> list[Rule]:
    candidates: dict[tuple[str, str, str, str, str, str], Rule] = {}
    for example in examples:
        public_motif = option_motif(example.public_text)
        competitor_motif = option_motif(example.competitor_text)
        public_type = option_type(example.public_text)
        competitor_type = option_type(example.competitor_text)
        context = example_context(example)
        opponent = example_opponent(example)
        specs = []
        if public_motif != competitor_motif:
            specs.extend(
                [
                    ("global_motif", "", "", public_motif, competitor_motif, "", ""),
                    ("context_motif", context, "", public_motif, competitor_motif, "", ""),
                    ("opponent_motif", "", opponent, public_motif, competitor_motif, "", ""),
                    ("context_opponent_motif", context, opponent, public_motif, competitor_motif, "", ""),
                ]
            )
        if public_type != competitor_type:
            specs.extend(
                [
                    ("global_type", "", "", public_motif, competitor_motif, public_type, competitor_type),
                    ("context_type", context, "", public_motif, competitor_motif, public_type, competitor_type),
                ]
            )
        for scope, ctx, opp, prefer_motif, avoid_motif, prefer_type, avoid_type in specs:
            rule = Rule(
                name=f"{scope}:{ctx or '*'}:{opp or '*'}:{prefer_motif}>{avoid_motif}",
                scope=scope,
                context=ctx,
                opponent_archetype=opp,
                prefer_motif=prefer_motif,
                avoid_motif=avoid_motif,
                prefer_type=prefer_type,
                avoid_type=avoid_type,
            )
            candidates.setdefault(rule.key(), rule)
    return list(candidates.values())


def rule_direction(rule: Rule, example: PairExample) -> int:
    """Return 1 if rule prefers public, -1 if it prefers competitor, 0 if no match."""
    if rule.context and example_context(example) != rule.context:
        return 0
    if rule.opponent_archetype and example_opponent(example) != rule.opponent_archetype:
        return 0
    public_motif = option_motif(example.public_text)
    competitor_motif = option_motif(example.competitor_text)
    public_type = option_type(example.public_text)
    competitor_type = option_type(example.competitor_text)
    if rule.prefer_type:
        forward = public_type == rule.prefer_type and competitor_type == rule.avoid_type
        reverse = public_type == rule.avoid_type and competitor_type == rule.prefer_type
    else:
        forward = public_motif == rule.prefer_motif and competitor_motif == rule.avoid_motif
        reverse = public_motif == rule.avoid_motif and competitor_motif == rule.prefer_motif
    if forward:
        return 1
    if reverse:
        return -1
    return 0


def evaluate_rule(rule: Rule, examples: list[PairExample]) -> RuleStats:
    stats = RuleStats()
    for example in examples:
        direction = rule_direction(rule, example)
        if direction == 0:
            continue
        stats.total += 1
        correct = direction == 1
        stats.correct += int(correct)
        stats.wins += int(example.reward == "win")
        stats.losses += int(example.reward == "loss")
        if not correct:
            stats.mistakes[
                f"{example_context(example)} vs {example_opponent(example)}: public={example.public_text} competitor={example.competitor_text}"
            ] += 1
    return stats


def fit_rules(train_examples: list[PairExample], args: argparse.Namespace) -> list[Rule]:
    fitted: list[Rule] = []
    for rule in make_candidate_rules(train_examples):
        stats = evaluate_rule(rule, train_examples)
        if stats.total < args.min_rule_support:
            continue
        if stats.accuracy < args.min_rule_accuracy:
            continue
        fitted.append(
            Rule(
                name=rule.name,
                scope=rule.scope,
                context=rule.context,
                opponent_archetype=rule.opponent_archetype,
                prefer_motif=rule.prefer_motif,
                avoid_motif=rule.avoid_motif,
                prefer_type=rule.prefer_type,
                avoid_type=rule.avoid_type,
                train_support=stats.total,
                train_accuracy=stats.accuracy,
            )
        )
    fitted.sort(
        key=lambda item: (
            item.train_accuracy,
            SCOPE_PRIORITY.get(item.scope, 0),
            item.train_support,
            item.name,
        ),
        reverse=True,
    )
    selected: list[Rule] = []
    covered: set[int] = set()
    for rule in fitted:
        fires = {index for index, example in enumerate(train_examples) if rule_direction(rule, example)}
        incremental = len(fires - covered)
        if selected and incremental < args.min_incremental_support:
            continue
        selected.append(rule)
        covered.update(fires)
        if len(selected) >= args.max_rules:
            break
    return selected


def apply_rule_set(rules: list[Rule], examples: list[PairExample]) -> tuple[RuleStats, Counter[str]]:
    stats = RuleStats()
    fired: Counter[str] = Counter()
    for example in examples:
        decision = 0
        rule_name = ""
        for rule in rules:
            decision = rule_direction(rule, example)
            if decision:
                rule_name = rule.name
                break
        if not decision:
            continue
        fired[rule_name] += 1
        stats.total += 1
        correct = decision == 1
        stats.correct += int(correct)
        stats.wins += int(example.reward == "win")
        stats.losses += int(example.reward == "loss")
        if not correct:
            stats.mistakes[
                f"{rule_name}: public={example.public_text} competitor={example.competitor_text}"
            ] += 1
    return stats, fired


def render_stats(stats: RuleStats, denominator: int) -> str:
    coverage = stats.total / denominator if denominator else 0.0
    return f"{stats.total} | {coverage:.3f} | {stats.accuracy:.3f} | {stats.wins} | {stats.losses}"


def write_json(path: Path, rules: list[Rule], args: argparse.Namespace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": "public_anchor_policy_guard_rules",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "decisions": str(args.decisions),
        "targets": str(args.targets),
        "base_model": str(args.base_model),
        "holdout_key": args.holdout_key,
        "holdout_mod": args.holdout_mod,
        "holdout_bucket": args.holdout_bucket,
        "rules": [asdict(rule) for rule in rules],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def render_report(
    args: argparse.Namespace,
    examples: list[PairExample],
    train_examples: list[PairExample],
    holdout_examples: list[PairExample],
    rules: list[Rule],
    train_set_stats: RuleStats,
    holdout_set_stats: RuleStats,
    fired: Counter[str],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Public-Anchored Policy Guard Synthesis")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: synthesize tiny public-supported timing guards before deck architecture changes.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.base_model}`")
    lines.append(f"- Target CSV: `{args.targets}`")
    lines.append(f"- Guard JSON: `{args.guard_out}`")
    lines.append(f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append("- Guard filter: only discriminative motif/type rules are emitted; same-motif card-choice gaps stay evaluator-only.")
    lines.append("")
    lines.append("## Example Set")
    lines.append("")
    lines.append(f"- Pair examples: {len(examples)}")
    lines.append(f"- Train examples: {len(train_examples)}")
    lines.append(f"- Holdout examples: {len(holdout_examples)}")
    lines.append(f"- Rules selected from train only: {len(rules)}")
    lines.append("")
    lines.append("## Rule-Set Metrics")
    lines.append("")
    lines.append("| Split | Decided | Coverage | Accuracy | Wins | Losses |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    lines.append(f"| Train | {render_stats(train_set_stats, len(train_examples))} |")
    lines.append(f"| Holdout | {render_stats(holdout_set_stats, len(holdout_examples))} |")
    lines.append("")
    lines.append("## Selected Rules")
    lines.append("")
    lines.append("| Rank | Rule | Scope | Prefer | Avoid | Context | Opponent | Train Support | Train Acc | Holdout N | Holdout Acc |")
    lines.append("| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |")
    for index, rule in enumerate(rules, start=1):
        hstats = evaluate_rule(rule, holdout_examples)
        prefer = rule.prefer_type or rule.prefer_motif
        avoid = rule.avoid_type or rule.avoid_motif
        lines.append(
            f"| {index} | `{rule.name}` | `{rule.scope}` | `{prefer}` | `{avoid}` | "
            f"`{rule.context or '*'}` | `{rule.opponent_archetype or '*'}` | {rule.train_support} | "
            f"{rule.train_accuracy:.3f} | {hstats.total} | {hstats.accuracy:.3f} |"
        )
    if not rules:
        lines.append("| 0 | - | - | - | - | - | - | 0 | 0.000 | 0 | 0.000 |")
    lines.append("")
    lines.append("## Holdout Rule Fires")
    lines.append("")
    for rule_name, count in fired.most_common(args.fire_limit):
        lines.append(f"- {count}: `{rule_name}`")
    if not fired:
        lines.append("- 0: no rule fired")
    lines.append("")
    lines.append("## Top Holdout Mistakes")
    lines.append("")
    for mistake, count in holdout_set_stats.mistakes.most_common(args.fire_limit):
        lines.append(f"- {count}: {mistake}")
    if not holdout_set_stats.mistakes:
        lines.append("- No holdout mistakes among fired rules.")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if holdout_set_stats.total == 0:
        lines.append("- The selected guards did not fire on holdout; lower the support threshold or widen target ranks.")
    elif holdout_set_stats.accuracy >= args.good_accuracy:
        lines.append(
            f"- Holdout fired-rule accuracy {holdout_set_stats.accuracy:.3f} clears the {args.good_accuracy:.3f} threshold. These rules are suitable as research-only runtime guard candidates."
        )
    else:
        lines.append(
            f"- Holdout fired-rule accuracy {holdout_set_stats.accuracy:.3f} is below the {args.good_accuracy:.3f} threshold. Keep the learned target model as an evaluator rather than a runtime guard."
        )
    lines.append("- Do not submit based on this report. Wire only behind motif/action-holdout and public-anchor gates.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_guard_synthesis.md"))
    parser.add_argument("--guard-out", type=Path, default=Path("strategy/public_anchor_guard_rules.json"))
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
    parser.add_argument("--min-rule-support", type=int, default=25)
    parser.add_argument("--min-incremental-support", type=int, default=10)
    parser.add_argument("--min-rule-accuracy", type=float, default=0.90)
    parser.add_argument("--max-rules", type=int, default=16)
    parser.add_argument("--good-accuracy", type=float, default=0.85)
    parser.add_argument("--fire-limit", type=int, default=12)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    base_weights = load_base_model(args.base_model)
    targets = load_targets(args.targets, args)
    examples = collect_examples(rows, base_weights, targets)
    train_examples = [example for example in examples if not is_holdout(example, args)]
    holdout_examples = [example for example in examples if is_holdout(example, args)]
    rules = fit_rules(train_examples, args)
    train_set_stats, _train_fired = apply_rule_set(rules, train_examples)
    holdout_set_stats, holdout_fired = apply_rule_set(rules, holdout_examples)
    write_json(args.guard_out, rules, args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, examples, train_examples, holdout_examples, rules, train_set_stats, holdout_set_stats, holdout_fired),
        encoding="utf-8",
    )
    print(
        "examples={examples} rules={rules} holdout_fired={fired} holdout_acc={acc:.3f} report={report}".format(
            examples=len(examples),
            rules=len(rules),
            fired=holdout_set_stats.total,
            acc=holdout_set_stats.accuracy,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
