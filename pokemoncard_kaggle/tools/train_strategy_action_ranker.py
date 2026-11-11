#!/usr/bin/env python3
"""Train/evaluate a strategy-feature action ranker against the baseline.

This keeps the repo's dependency-free perceptron setup, but adds explicit
strategy features for public-anchored timing motifs. The first feature family is
Dudunsparce ability-vs-attack competition, because public replay mining shows it
is a stable strategy signal while hard-coded attack overrides overcorrect.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from train_action_ranker import (
    option_features as baseline_option_features,
    bucket_count,
    load_rows,
    option_parts,
    pct,
    stable_bucket,
    state_value,
    valid_single_label,
)


FeatureFn = Callable[[dict[str, Any], int], list[str]]


@dataclass
class EvalStats:
    total: int = 0
    top1: int = 0
    top3: int = 0
    skipped: int = 0


@dataclass
class CompareStats:
    total: int = 0
    baseline_top1: int = 0
    strategy_top1: int = 0
    baseline_top3: int = 0
    strategy_top3: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0
    changed_top1: int = 0
    skipped: int = 0


@dataclass
class TrainStats:
    rows: int = 0
    updates: int = 0
    skipped_multi: int = 0
    skipped_trivial: int = 0
    contexts: Counter[str] = field(default_factory=Counter)


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def holdout_value(row: dict[str, Any], key: str) -> str:
    if key == "source":
        return row_value(row, "source")
    if key == "team":
        return row_value(row, "team")
    if key == "opponent_team":
        return row_value(row, "opponent_team")
    if key == "episode_id":
        return row_value(row, "episode_id")
    if key == "target":
        return f"{row_value(row, 'archetype')}:{row_value(row, 'deck_hash')}"
    return row_value(row, key)


def is_holdout(row: dict[str, Any], args: argparse.Namespace) -> bool:
    return stable_bucket(holdout_value(row, args.holdout_key), args.holdout_mod) == args.holdout_bucket


def option_type(text: str) -> str:
    return option_parts(text)["type"]


def option_card(text: str) -> str:
    return option_parts(text)["card"]


def option_attack(text: str) -> str:
    return option_parts(text)["attack"]


def bucket_bool(name: str, value: bool) -> str:
    return f"{name}={'yes' if value else 'no'}"


def int_bucket(value: Any, cuts: tuple[int, ...]) -> str:
    if not isinstance(value, int):
        return "?"
    for cut in cuts:
        if value <= cut:
            return f"<={cut}"
    return f">{cuts[-1]}"


def has_dudunsparce_ability(options: list[str]) -> bool:
    return any(option_type(text) == "ABILITY" and option_card(text) == "66" for text in options)


def has_attack(options: list[str]) -> bool:
    return any(option_type(text) == "ATTACK" for text in options)


def has_option(options: list[str], needle: str) -> bool:
    return any(needle in text for text in options)


def strategy_option_features(row: dict[str, Any], option_index: int) -> list[str]:
    feats = list(baseline_option_features(row, option_index))
    options = [str(option) for option in (row.get("options") or [])]
    if not 0 <= option_index < len(options):
        return feats
    text = options[option_index]
    parts = option_parts(text)
    has_dudun = has_dudunsparce_ability(options)
    attacks_available = has_attack(options)
    if not (has_dudun and attacks_available and row_value(row, "context") == "MAIN"):
        return feats

    archetype = row_value(row, "archetype")
    opponent = row_value(row, "opponent_archetype")
    own_active = state_value(row, "me", "active")
    opp_active = state_value(row, "opponent", "active")
    own_bench_raw = state_value(row, "me", "bench_count")
    own_hand_raw = state_value(row, "me", "hand_count")
    opp_bench_raw = state_value(row, "opponent", "bench_count")
    opp_hand_raw = state_value(row, "opponent", "hand_count")
    turn_raw = (row.get("state") or {}).get("turn")
    turn_action_raw = (row.get("state") or {}).get("turn_action_count")
    own_bench = int_bucket(own_bench_raw, (1, 2, 3, 4))
    own_hand = int_bucket(own_hand_raw, (4, 7, 10, 13, 16))
    opp_bench = int_bucket(opp_bench_raw, (1, 2, 3, 4))
    opp_hand = int_bucket(opp_hand_raw, (4, 7, 10, 13, 16))
    turn = int_bucket(turn_raw, (2, 4, 6, 8, 12))
    turn_action = int_bucket(turn_action_raw, (2, 5, 9, 14, 20))
    option_role = "dudun_ability" if parts["type"] == "ABILITY" and parts["card"] == "66" else parts["type"].lower()

    shared = [
        "strategy=dudun_attack_competition",
        f"strategy_arch={archetype}",
        f"strategy_opp={opponent}",
        f"strategy_active={own_active}",
        f"strategy_opp_active={opp_active}",
        f"strategy_bench={own_bench}",
        f"strategy_hand={own_hand}",
        f"strategy_opp_bench={opp_bench}",
        f"strategy_opp_hand={opp_hand}",
        f"strategy_turn={turn}",
        f"strategy_turn_action={turn_action}",
        bucket_bool("strategy_has_boss", has_option(options, "Boss")),
        bucket_bool("strategy_has_recovery", any(has_option(options, needle) for needle in ("Night Stretcher", "Sacred Ash", "Lana"))),
        bucket_bool("strategy_has_hammer", has_option(options, "Enhanced Hammer")),
        bucket_bool("strategy_has_stadium", any(has_option(options, needle) for needle in ("Battle Cage", "Nighttime Mine"))),
    ]
    feats.extend(f"{feature}:role={option_role}" for feature in shared)
    feats.append(f"strategy_role={option_role}")

    if parts["type"] == "ABILITY" and parts["card"] == "66":
        feats.extend(
            [
                "strategy_prefer=dudun_ability_competes_attack",
                f"strategy_dudun_arch={archetype}",
                f"strategy_dudun_arch_bench={archetype}:{own_bench}",
                f"strategy_dudun_bench_hand={own_bench}:{own_hand}",
                f"strategy_dudun_active_bench={own_active}:{own_bench}",
                f"strategy_dudun_turn_action={turn_action}",
            ]
        )
        if archetype == "hops-trevenant":
            feats.append("strategy_dudun_hops")
            if own_bench == ">4":
                feats.append("strategy_dudun_hops_full_bench")
            if turn_action in {"<=2", "<=5", "<=9"}:
                feats.append("strategy_dudun_hops_early_action")
        if own_bench == ">4" and own_hand in {"<=4", "<=7"}:
            feats.append("strategy_dudun_full_bench_low_hand")
        if str(own_active) == "879" and own_bench == ">4":
            feats.append("strategy_dudun_hops_trevenant_full_bench")
    elif parts["type"] == "ATTACK":
        attack = parts["attack"] or "unknown"
        feats.extend(
            [
                "strategy_avoid=attack_over_dudun_ability",
                f"strategy_attack_id={attack}",
                f"strategy_attack_arch={archetype}:{attack}",
                f"strategy_attack_active={own_active}:{attack}",
                f"strategy_attack_bench_hand={own_bench}:{own_hand}",
            ]
        )
    return feats


def rank_options(weights: dict[str, float], row: dict[str, Any], feature_fn: FeatureFn) -> list[int]:
    option_count = int(row.get("option_count") or 0)
    scored = [
        (sum(weights.get(feature, 0.0) for feature in feature_fn(row, index)), -index, index)
        for index in range(option_count)
    ]
    scored.sort(reverse=True)
    return [index for _score, _neg_index, index in scored]


def train_model(rows: list[dict[str, Any]], args: argparse.Namespace, feature_fn: FeatureFn) -> tuple[dict[str, float], TrainStats]:
    train_rows = [row for row in rows if not is_holdout(row, args)]
    weights: dict[str, float] = {}
    stats = TrainStats()
    for _epoch in range(args.epochs):
        for row in train_rows:
            label = valid_single_label(row)
            if label is None:
                if len(row.get("action") or []) != 1:
                    stats.skipped_multi += 1
                else:
                    stats.skipped_trivial += 1
                continue
            stats.rows += 1
            stats.contexts[str(row.get("context"))] += 1
            prediction = rank_options(weights, row, feature_fn)[0]
            if prediction == label:
                continue
            stats.updates += 1
            for feature in feature_fn(row, label):
                weights[feature] = weights.get(feature, 0.0) + args.learning_rate
            for feature in feature_fn(row, prediction):
                weights[feature] = weights.get(feature, 0.0) - args.learning_rate
    return weights, stats


def compare_models(
    rows: list[dict[str, Any]],
    args: argparse.Namespace,
    baseline_weights: dict[str, float],
    strategy_weights: dict[str, float],
) -> tuple[CompareStats, dict[str, CompareStats], Counter[str]]:
    stats = CompareStats()
    groups: dict[str, CompareStats] = defaultdict(CompareStats)
    changes: Counter[str] = Counter()
    holdout_rows = [row for row in rows if is_holdout(row, args)]
    for row in holdout_rows:
        label = valid_single_label(row)
        if label is None:
            stats.skipped += 1
            continue
        base_rank = rank_options(baseline_weights, row, baseline_option_features)
        strat_rank = rank_options(strategy_weights, row, strategy_option_features)
        selected = (row.get("options") or [""])[label]
        group_key = f"{row_value(row, 'archetype')} vs {row_value(row, 'opponent_archetype')}"
        for bucket in (stats, groups[group_key]):
            bucket.total += 1
            bucket.baseline_top1 += int(base_rank and base_rank[0] == label)
            bucket.strategy_top1 += int(strat_rank and strat_rank[0] == label)
            bucket.baseline_top3 += int(label in base_rank[:3])
            bucket.strategy_top3 += int(label in strat_rank[:3])
            changed = bool(base_rank and strat_rank and base_rank[0] != strat_rank[0])
            bucket.changed_top1 += int(changed)
            base_hit = bool(base_rank and base_rank[0] == label)
            strat_hit = bool(strat_rank and strat_rank[0] == label)
            bucket.fixes += int(changed and not base_hit and strat_hit)
            bucket.regressions += int(changed and base_hit and not strat_hit)
            bucket.neutral_changes += int(changed and base_hit == strat_hit)
        if base_rank and strat_rank and base_rank[0] != strat_rank[0]:
            options = row.get("options") or []
            before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
            after = options[strat_rank[0]] if strat_rank[0] < len(options) else str(strat_rank[0])
            outcome = "fix" if strat_rank[0] == label and base_rank[0] != label else "regress" if base_rank[0] == label else "neutral"
            changes[f"{outcome}: public={selected} | baseline={before} | strategy={after}"] += 1
    return stats, dict(groups), changes


def write_model(path: Path, args: argparse.Namespace, weights: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "decisions": str(args.decisions),
        "feature_set": "strategy_dudunsparce_ability_attack_v1",
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "holdout_key": args.holdout_key,
        "holdout_mod": args.holdout_mod,
        "holdout_bucket": args.holdout_bucket,
        "weights": weights,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def stats_row(name: str, stats: CompareStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.baseline_top1, stats.total)} | {pct(stats.strategy_top1, stats.total)} | "
        f"{pct(stats.baseline_top3, stats.total)} | {pct(stats.strategy_top3, stats.total)} | "
        f"{stats.changed_top1} | {stats.fixes} | {stats.regressions} |"
    )


def render_report(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    baseline_train: TrainStats,
    strategy_train: TrainStats,
    overall: CompareStats,
    groups: dict[str, CompareStats],
    changes: Counter[str],
    baseline_weights: dict[str, float],
    strategy_weights: dict[str, float],
) -> str:
    lines: list[str] = [
        "# Strategy Action Ranker",
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
        f"- Epochs: {args.epochs}",
        f"- Learning rate: {args.learning_rate}",
        f"- Holdout rule: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}",
        f"- Strategy model: `{args.model_out}`",
        "- Feature set: baseline option features plus Dudunsparce ability-vs-attack competition features.",
        "",
        "## Training",
        "",
        f"- Baseline train single rows: {baseline_train.rows}; updates: {baseline_train.updates}; weights: {len(baseline_weights)}",
        f"- Strategy train single rows: {strategy_train.rows}; updates: {strategy_train.updates}; weights: {len(strategy_weights)}",
        "",
        "## Holdout Comparison",
        "",
        "| Split/Group | N | Baseline Top-1 | Strategy Top-1 | Baseline Top-3 | Strategy Top-3 | Top-1 Changes | Fixes | Regressions |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        stats_row("holdout all", overall),
    ]
    eligible_groups = [(name, stats) for name, stats in groups.items() if stats.total >= args.min_group_n]
    eligible_groups.sort(key=lambda item: (item[1].strategy_top1 - item[1].baseline_top1, item[1].total), reverse=True)
    for name, stats in eligible_groups[: args.limit]:
        lines.append(stats_row(name, stats))
    lines.extend(["", "## Largest Top-1 Changes", ""])
    for text, count in changes.most_common(args.limit):
        lines.append(f"- {count}: {text}")
    if not changes:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Strategy features are useful only if they improve heldout top-1/top-3 without creating a large regression count.",
            "- This is an offline behavior-cloning/ranker signal, not a public-score predictor; public-anchor and backtest gates remain authoritative.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.25)
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source", "target"], default="team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--model-out", type=Path, default=Path("strategy/strategy_action_ranker_model.json"))
    parser.add_argument("--report-out", type=Path, default=Path("strategy/strategy_action_ranker_report.md"))
    parser.add_argument("--min-group-n", type=int, default=50)
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()

    if args.holdout_mod <= 1:
        raise SystemExit("--holdout-mod must be greater than 1")
    if not 0 <= args.holdout_bucket < args.holdout_mod:
        raise SystemExit("--holdout-bucket must be in [0, holdout_mod)")

    rows = load_rows(args.decisions)
    baseline_weights, baseline_train = train_model(rows, args, baseline_option_features)
    strategy_weights, strategy_train = train_model(rows, args, strategy_option_features)
    overall, groups, changes = compare_models(rows, args, baseline_weights, strategy_weights)
    write_model(args.model_out, args, strategy_weights)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, rows, baseline_train, strategy_train, overall, groups, changes, baseline_weights, strategy_weights),
        encoding="utf-8",
    )
    print(
        "holdout={key} baseline_top1={base} strategy_top1={strategy} baseline_top3={base3} strategy_top3={strategy3} n={n} model={model} report={report}".format(
            key=args.holdout_key,
            base=pct(overall.baseline_top1, overall.total),
            strategy=pct(overall.strategy_top1, overall.total),
            base3=pct(overall.baseline_top3, overall.total),
            strategy3=pct(overall.strategy_top3, overall.total),
            n=overall.total,
            model=args.model_out,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
