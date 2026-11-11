#!/usr/bin/env python3
"""Train a frozen-baseline residual for Dudunsparce ability/attack timing.

Unlike ``train_strategy_action_ranker.py``, this does not retrain the full
action model. It loads a fixed baseline action ranker and learns only a small
residual feature set on MAIN states where Dudunsparce ability and at least one
attack are both legal. This is a conservative offline-RL/behavior-cloning step:
improve a public-anchored timing motif without perturbing unrelated choices.
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
from typing import Any

from train_action_ranker import (
    load_rows,
    option_features,
    option_parts,
    pct,
    score,
    stable_bucket,
    state_value,
    valid_single_label,
)


@dataclass
class TrainStats:
    rows: int = 0
    eligible: int = 0
    updates: int = 0
    skipped: int = 0
    contexts: Counter[str] = field(default_factory=Counter)


@dataclass
class EvalStats:
    total: int = 0
    eligible: int = 0
    base_top1: int = 0
    residual_top1: int = 0
    base_top3: int = 0
    residual_top3: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral: int = 0
    skipped: int = 0


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain weights")
    return {str(key): float(value) for key, value in weights.items()}


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def holdout_value(row: dict[str, Any], key: str) -> str:
    if key == "target":
        return f"{row_value(row, 'archetype')}:{row_value(row, 'deck_hash')}"
    return row_value(row, key)


def is_holdout(row: dict[str, Any], args: argparse.Namespace) -> bool:
    return stable_bucket(holdout_value(row, args.holdout_key), args.holdout_mod) == args.holdout_bucket


def int_bucket(value: Any, cuts: tuple[int, ...]) -> str:
    if not isinstance(value, int):
        return "?"
    for cut in cuts:
        if value <= cut:
            return f"<={cut}"
    return f">{cuts[-1]}"


def options(row: dict[str, Any]) -> list[str]:
    return [str(option) for option in (row.get("options") or [])]


def is_dudun_ability(text: str) -> bool:
    parts = option_parts(text)
    return parts["type"] == "ABILITY" and parts["card"] == "66"


def is_attack(text: str) -> bool:
    return option_parts(text)["type"] == "ATTACK"


def eligible_row(row: dict[str, Any]) -> bool:
    opts = options(row)
    return row_value(row, "context") == "MAIN" and any(is_dudun_ability(text) for text in opts) and any(is_attack(text) for text in opts)


def residual_features(row: dict[str, Any], option_index: int) -> list[str]:
    opts = options(row)
    if not 0 <= option_index < len(opts) or not eligible_row(row):
        return []
    text = opts[option_index]
    parts = option_parts(text)
    if not (is_dudun_ability(text) or is_attack(text)):
        return []
    role = "dudun_ability" if is_dudun_ability(text) else "attack"
    archetype = row_value(row, "archetype")
    opponent = row_value(row, "opponent_archetype")
    own_active = state_value(row, "me", "active")
    opp_active = state_value(row, "opponent", "active")
    bench = int_bucket(state_value(row, "me", "bench_count"), (1, 2, 3, 4))
    hand = int_bucket(state_value(row, "me", "hand_count"), (4, 7, 10, 13, 16))
    opp_bench = int_bucket(state_value(row, "opponent", "bench_count"), (1, 2, 3, 4))
    opp_hand = int_bucket(state_value(row, "opponent", "hand_count"), (4, 7, 10, 13, 16))
    turn = int_bucket((row.get("state") or {}).get("turn"), (2, 4, 6, 8, 12))
    turn_action = int_bucket((row.get("state") or {}).get("turn_action_count"), (2, 5, 9, 14, 20))
    attack = parts["attack"] if role == "attack" else next((option_parts(item)["attack"] for item in opts if is_attack(item)), "")
    feats = [
        f"res_role={role}",
        f"res_role_arch={role}:{archetype}",
        f"res_role_opp={role}:{opponent}",
        f"res_role_active={role}:{own_active}",
        f"res_role_opp_active={role}:{opp_active}",
        f"res_role_attack={role}:{attack or 'none'}",
        f"res_role_bench={role}:{bench}",
        f"res_role_hand={role}:{hand}",
        f"res_role_opp_bench={role}:{opp_bench}",
        f"res_role_opp_hand={role}:{opp_hand}",
        f"res_role_turn={role}:{turn}",
        f"res_role_turn_action={role}:{turn_action}",
        f"res_role_arch_bench={role}:{archetype}:{bench}",
        f"res_role_bench_hand={role}:{bench}:{hand}",
        f"res_role_active_bench={role}:{own_active}:{bench}",
    ]
    if role == "dudun_ability":
        if archetype == "hops-trevenant":
            feats.append("res_dudun_hops")
        if archetype == "hops-trevenant" and bench == ">4":
            feats.append("res_dudun_hops_full_bench")
        if bench == ">4" and hand in {"<=4", "<=7"}:
            feats.append("res_dudun_full_bench_low_hand")
        if str(own_active) == "879" and bench == ">4":
            feats.append("res_dudun_hops_trevenant_full_bench")
        if turn_action in {"<=2", "<=5", "<=9"}:
            feats.append("res_dudun_early_action")
    else:
        if archetype == "hops-trevenant":
            feats.append("res_attack_hops")
        if bench == ">4":
            feats.append("res_attack_full_bench")
        if hand in {"<=4", "<=7"}:
            feats.append("res_attack_low_hand")
    return feats


def base_rank(base_weights: dict[str, float], row: dict[str, Any]) -> list[int]:
    option_count = int(row.get("option_count") or 0)
    scored = [
        (score(base_weights, option_features(row, index)), -index, index)
        for index in range(option_count)
    ]
    scored.sort(reverse=True)
    return [index for _score, _neg_index, index in scored]


def residual_rank(base_weights: dict[str, float], residual_weights: dict[str, float], row: dict[str, Any]) -> list[int]:
    option_count = int(row.get("option_count") or 0)
    scored = []
    for index in range(option_count):
        base = score(base_weights, option_features(row, index))
        residual = sum(residual_weights.get(feature, 0.0) for feature in residual_features(row, index))
        scored.append((base + residual, -index, index))
    scored.sort(reverse=True)
    return [index for _score, _neg_index, index in scored]


def train(rows: list[dict[str, Any]], base_weights: dict[str, float], args: argparse.Namespace) -> tuple[dict[str, float], TrainStats]:
    weights: dict[str, float] = {}
    stats = TrainStats()
    train_rows = [row for row in rows if not is_holdout(row, args)]
    for _epoch in range(args.epochs):
        for row in train_rows:
            label = valid_single_label(row)
            if label is None:
                stats.skipped += 1
                continue
            stats.rows += 1
            stats.contexts[row_value(row, "context")] += 1
            if not eligible_row(row):
                continue
            stats.eligible += 1
            prediction = residual_rank(base_weights, weights, row)[0]
            if prediction == label:
                continue
            label_features = residual_features(row, label)
            pred_features = residual_features(row, prediction)
            if not label_features and not pred_features:
                continue
            stats.updates += 1
            for feature in label_features:
                weights[feature] = weights.get(feature, 0.0) + args.learning_rate
            for feature in pred_features:
                weights[feature] = weights.get(feature, 0.0) - args.learning_rate
    return weights, stats


def update_stats(stats: EvalStats, label: int | None, base: list[int], residual: list[int], row: dict[str, Any]) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.eligible += int(eligible_row(row))
    stats.base_top1 += int(bool(base) and base[0] == label)
    stats.residual_top1 += int(bool(residual) and residual[0] == label)
    stats.base_top3 += int(label in base[:3])
    stats.residual_top3 += int(label in residual[:3])
    changed = bool(base and residual and base[0] != residual[0])
    stats.changed += int(changed)
    base_hit = bool(base and base[0] == label)
    residual_hit = bool(residual and residual[0] == label)
    stats.fixes += int(changed and not base_hit and residual_hit)
    stats.regressions += int(changed and base_hit and not residual_hit)
    stats.neutral += int(changed and base_hit == residual_hit)


def evaluate(rows: list[dict[str, Any]], base_weights: dict[str, float], residual_weights: dict[str, float], args: argparse.Namespace) -> tuple[EvalStats, dict[str, EvalStats], Counter[str]]:
    overall = EvalStats()
    groups: dict[str, EvalStats] = defaultdict(EvalStats)
    changes: Counter[str] = Counter()
    for row in rows:
        if not is_holdout(row, args):
            continue
        label = valid_single_label(row)
        base = [] if label is None else base_rank(base_weights, row)
        residual = [] if label is None else residual_rank(base_weights, residual_weights, row)
        update_stats(overall, label, base, residual, row)
        group = f"{row_value(row, 'archetype')} vs {row_value(row, 'opponent_archetype')}"
        update_stats(groups[group], label, base, residual, row)
        if label is not None and base and residual and base[0] != residual[0]:
            opts = options(row)
            selected = opts[label] if label < len(opts) else str(label)
            before = opts[base[0]] if base[0] < len(opts) else str(base[0])
            after = opts[residual[0]] if residual[0] < len(opts) else str(residual[0])
            outcome = "fix" if residual[0] == label and base[0] != label else "regress" if base[0] == label else "neutral"
            changes[f"{outcome}: public={selected} | base={before} | residual={after}"] += 1
    return overall, dict(groups), changes


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | {pct(stats.residual_top1, stats.total)} | "
        f"{pct(stats.base_top3, stats.total)} | {pct(stats.residual_top3, stats.total)} | "
        f"{stats.eligible} | {stats.changed} | {stats.fixes} | {stats.regressions} |"
    )


def write_model(path: Path, args: argparse.Namespace, weights: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "decisions": str(args.decisions),
        "base_model": str(args.base_model),
        "feature_set": "dudunsparce_ability_attack_residual_v1",
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "holdout_key": args.holdout_key,
        "holdout_mod": args.holdout_mod,
        "holdout_bucket": args.holdout_bucket,
        "weights": weights,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def render(args: argparse.Namespace, train_stats: TrainStats, weights: dict[str, float], overall: EvalStats, groups: dict[str, EvalStats], changes: Counter[str]) -> str:
    lines: list[str] = [
        "# Dudunsparce Residual Ranker",
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
        f"- Frozen base model: `{args.base_model}`",
        f"- Residual model: `{args.model_out}`",
        f"- Holdout rule: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}",
        f"- Epochs: {args.epochs}",
        f"- Learning rate: {args.learning_rate}",
        "",
        "## Training",
        "",
        f"- Train single rows seen: {train_stats.rows}",
        f"- Eligible Dudunsparce/attack rows seen: {train_stats.eligible}",
        f"- Updates: {train_stats.updates}",
        f"- Residual weights: {len(weights)}",
        "",
        "## Holdout Comparison",
        "",
        "| Split/Group | N | Base Top-1 | Residual Top-1 | Base Top-3 | Residual Top-3 | Eligible | Changes | Fixes | Regressions |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        stats_row("holdout all", overall),
    ]
    eligible = [(name, stats) for name, stats in groups.items() if stats.total >= args.min_group_n]
    eligible.sort(key=lambda item: (item[1].residual_top1 - item[1].base_top1, item[1].total), reverse=True)
    for name, stats in eligible[: args.limit]:
        lines.append(stats_row(name, stats))
    lines.extend(["", "## Largest Changes", ""])
    for text, count in changes.most_common(args.limit):
        lines.append(f"- {count}: {text}")
    if not changes:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- This residual can be considered for policy distillation only if it improves multiple holdout keys without broad regressions.",
            "- It is still a public-action imitation signal, not a public-score predictor.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.2)
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source", "target"], default="team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--model-out", type=Path, default=Path("strategy/dudunsparce_residual_model.json"))
    parser.add_argument("--report-out", type=Path, default=Path("strategy/dudunsparce_residual_report.md"))
    parser.add_argument("--min-group-n", type=int, default=50)
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    base_weights = load_model(args.base_model)
    residual_weights, train_stats = train(rows, base_weights, args)
    overall, groups, changes = evaluate(rows, base_weights, residual_weights, args)
    write_model(args.model_out, args, residual_weights)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, train_stats, residual_weights, overall, groups, changes), encoding="utf-8")
    print(
        "holdout={key} base_top1={base} residual_top1={res} base_top3={base3} residual_top3={res3} n={n} changes={changes} fixes={fixes} regressions={regs} report={report}".format(
            key=args.holdout_key,
            base=pct(overall.base_top1, overall.total),
            res=pct(overall.residual_top1, overall.total),
            base3=pct(overall.base_top3, overall.total),
            res3=pct(overall.residual_top3, overall.total),
            n=overall.total,
            changes=overall.changed,
            fixes=overall.fixes,
            regs=overall.regressions,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
