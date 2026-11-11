#!/usr/bin/env python3
"""Train a lightweight behavior-cloning action ranker from replay decisions.

This is a dependency-free baseline. It uses an online perceptron over legal
options and learns to rank the public replay's selected action above the other
legal options. The goal is not to ship this model directly; it creates a
measurable public-action holdout signal for policy patches and future RL work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CARD_RE = re.compile(r"\((\d+)\)")
ATTACK_RE = re.compile(r"attack=(\d+)")
TO_RE = re.compile(r"to=([A-Z_]+):(\d+)")


@dataclass
class EvalStats:
    total: int = 0
    top1: int = 0
    top3: int = 0
    skipped: int = 0


@dataclass
class TrainStats:
    rows: int = 0
    updates: int = 0
    skipped_multi: int = 0
    skipped_trivial: int = 0
    contexts: Counter[str] = field(default_factory=Counter)


def stable_bucket(value: str, modulo: int) -> int:
    digest = hashlib.sha1(value.encode()).hexdigest()
    return int(digest[:10], 16) % modulo


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def option_parts(description: str) -> dict[str, str]:
    head = description.split(" ", 1)[0]
    option_type = head.split(":", 1)[1] if ":" in head else head
    card_match = CARD_RE.search(description)
    attack_match = ATTACK_RE.search(description)
    to_match = TO_RE.search(description)
    return {
        "type": option_type,
        "card": card_match.group(1) if card_match else "",
        "attack": attack_match.group(1) if attack_match else "",
        "to_area": to_match.group(1) if to_match else "",
        "to_index": to_match.group(2) if to_match else "",
    }


def bucket_count(value: Any, bucket_size: int = 3) -> str:
    if not isinstance(value, int):
        return "?"
    return str(min(6, value // bucket_size))


def row_state_value(row: dict[str, Any], field: str) -> Any:
    state = row.get("state") or {}
    return state.get(field)


def state_value(row: dict[str, Any], side: str, field: str) -> Any:
    state = row.get("state") or {}
    side_state = state.get(side) or {}
    return side_state.get(field)


def option_features(row: dict[str, Any], option_index: int) -> list[str]:
    options = row.get("options") or []
    description = options[option_index] if option_index < len(options) else ""
    parts = option_parts(description)
    context = str(row.get("context"))
    archetype = str(row.get("archetype"))
    opponent = str(row.get("opponent_archetype"))
    own_active = state_value(row, "me", "active")
    opp_active = state_value(row, "opponent", "active")
    own_bench = bucket_count(state_value(row, "me", "bench_count"))
    opp_bench = bucket_count(state_value(row, "opponent", "bench_count"))
    own_hand = bucket_count(state_value(row, "me", "hand_count"), 2)
    opp_hand = bucket_count(state_value(row, "opponent", "hand_count"), 2)
    turn = row.get("state", {}).get("turn")
    turn_bucket = bucket_count(turn, 2)
    turn_action_bucket = bucket_count(row_state_value(row, "turn_action_count"), 3)
    option_count_bucket = bucket_count(row.get("option_count"), 4)
    board_key = str(row.get("board_key") or "")
    energy_attached = str(row_state_value(row, "energy_attached"))
    supporter_played = str(row_state_value(row, "supporter_played"))
    stadium_played = str(row_state_value(row, "stadium_played"))

    feats = [
        "bias",
        f"ctx={context}",
        f"arch={archetype}",
        f"opp={opponent}",
        f"ctx_type={context}:{parts['type']}",
        f"type={parts['type']}",
        f"option_count={option_count_bucket}",
        f"turn={turn_bucket}",
        f"turn_action={turn_action_bucket}",
        f"energy_attached={energy_attached}",
        f"supporter_played={supporter_played}",
        f"stadium_played={stadium_played}",
        f"own_active={own_active}",
        f"opp_active={opp_active}",
        f"own_bench={own_bench}",
        f"opp_bench={opp_bench}",
        f"own_hand={own_hand}",
        f"opp_hand={opp_hand}",
        f"turn_type={turn_bucket}:{parts['type']}",
        f"energy_type={energy_attached}:{parts['type']}",
    ]
    if board_key:
        feats.extend(
            [
                f"board={board_key}",
                f"board_type={board_key}:{parts['type']}",
            ]
        )
    if parts["card"]:
        feats.extend(
            [
                f"card={parts['card']}",
                f"ctx_card={context}:{parts['card']}",
                f"arch_card={archetype}:{parts['card']}",
                f"opp_card={opponent}:{parts['card']}",
                f"energy_card={energy_attached}:{parts['card']}",
            ]
        )
        if board_key:
            feats.append(f"board_card={board_key}:{parts['card']}")
    if parts["attack"]:
        feats.extend([f"attack={parts['attack']}", f"ctx_attack={context}:{parts['attack']}"])
        if board_key:
            feats.append(f"board_attack={board_key}:{parts['attack']}")
    if parts["to_area"]:
        feats.extend([f"to_area={parts['to_area']}", f"ctx_to={context}:{parts['to_area']}"])
        if board_key:
            feats.append(f"board_to={board_key}:{parts['to_area']}")
    return feats


def valid_single_label(row: dict[str, Any]) -> int | None:
    action = row.get("action")
    option_count = row.get("option_count")
    if not isinstance(action, list) or len(action) != 1:
        return None
    selected = action[0]
    if not isinstance(option_count, int) or option_count <= 1:
        return None
    if not isinstance(selected, int) or not 0 <= selected < option_count:
        return None
    return selected


def score(weights: dict[str, float], features: list[str]) -> float:
    return sum(weights.get(feature, 0.0) for feature in features)


def ranked_options(weights: dict[str, float], row: dict[str, Any]) -> list[int]:
    option_count = int(row.get("option_count") or 0)
    scored = [
        (score(weights, option_features(row, index)), -index, index)
        for index in range(option_count)
    ]
    scored.sort(reverse=True)
    return [index for _, _, index in scored]


def train(
    rows: list[dict[str, Any]],
    epochs: int,
    learning_rate: float,
    holdout_mod: int,
    holdout_bucket: int,
) -> tuple[dict[str, float], TrainStats]:
    train_rows = [
        row
        for row in rows
        if stable_bucket(str(row.get("episode_id")), holdout_mod) != holdout_bucket
    ]
    weights: dict[str, float] = {}
    stats = TrainStats()
    for _ in range(epochs):
        for row in train_rows:
            label = valid_single_label(row)
            if label is None:
                if len(row.get("action") or []) != 1:
                    stats.skipped_multi += 1
                else:
                    stats.skipped_trivial += 1
                continue
            stats.rows += 1
            context = str(row.get("context"))
            stats.contexts[context] += 1
            prediction = ranked_options(weights, row)[0]
            if prediction == label:
                continue
            stats.updates += 1
            for feature in option_features(row, label):
                weights[feature] = weights.get(feature, 0.0) + learning_rate
            for feature in option_features(row, prediction):
                weights[feature] = weights.get(feature, 0.0) - learning_rate
    return weights, stats


def evaluate(
    rows: list[dict[str, Any]],
    weights: dict[str, float],
    holdout_mod: int,
    holdout_bucket: int,
) -> tuple[EvalStats, dict[str, EvalStats]]:
    holdout_rows = [
        row
        for row in rows
        if stable_bucket(str(row.get("episode_id")), holdout_mod) == holdout_bucket
    ]
    overall = EvalStats()
    by_context: defaultdict[str, EvalStats] = defaultdict(EvalStats)
    for row in holdout_rows:
        label = valid_single_label(row)
        context = str(row.get("context"))
        if label is None:
            overall.skipped += 1
            by_context[context].skipped += 1
            continue
        ranking = ranked_options(weights, row)
        overall.total += 1
        by_context[context].total += 1
        if ranking and ranking[0] == label:
            overall.top1 += 1
            by_context[context].top1 += 1
        if label in ranking[:3]:
            overall.top3 += 1
            by_context[context].top3 += 1
    return overall, dict(by_context)


def pct(num: int, den: int) -> str:
    if den == 0:
        return "0.000"
    return f"{num / den:.3f}"


def render_report(
    args: argparse.Namespace,
    weights: dict[str, float],
    train_stats: TrainStats,
    overall: EvalStats,
    by_context: dict[str, EvalStats],
) -> str:
    lines: list[str] = []
    lines.append("# Action Ranker Baseline")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Configuration")
    lines.append("")
    lines.append(f"- Dataset: `{args.decisions}`")
    lines.append(f"- Epochs: {args.epochs}")
    lines.append(f"- Learning rate: {args.learning_rate}")
    lines.append(f"- Holdout rule: sha1(episode_id) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append(f"- Model: `{args.model_out}`")
    lines.append("")
    lines.append("## Training")
    lines.append("")
    lines.append(f"- Effective single-action train decisions: {train_stats.rows}")
    lines.append(f"- Updates: {train_stats.updates}")
    lines.append(f"- Skipped multi-action decisions: {train_stats.skipped_multi}")
    lines.append(f"- Skipped trivial/invalid decisions: {train_stats.skipped_trivial}")
    lines.append(f"- Learned weights: {len(weights)}")
    lines.append("")
    lines.append("## Holdout")
    lines.append("")
    lines.append(
        f"- Overall top-1: {overall.top1}/{overall.total} = {pct(overall.top1, overall.total)}"
    )
    lines.append(
        f"- Overall top-3: {overall.top3}/{overall.total} = {pct(overall.top3, overall.total)}"
    )
    lines.append(f"- Skipped holdout rows: {overall.skipped}")
    lines.append("")
    lines.append("| Context | N | Top-1 | Top-3 | Skipped |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for context, stats in sorted(by_context.items(), key=lambda item: item[1].total, reverse=True):
        lines.append(
            f"| `{context}` | {stats.total} | {pct(stats.top1, stats.total)} | "
            f"{pct(stats.top3, stats.total)} | {stats.skipped} |"
        )
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "This is a behavior-cloning signal, not a submission agent. Use it to find "
        "where local policy disagrees with fresh public behavior, then verify any "
        "policy patch through public-failure holdouts and gauntlets."
    )
    return "\n".join(lines) + "\n"


def write_model(path: Path, args: argparse.Namespace, weights: dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "decisions": str(args.decisions),
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "holdout_mod": args.holdout_mod,
        "holdout_bucket": args.holdout_bucket,
        "weights": weights,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--learning-rate", type=float, default=0.25)
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--model-out", type=Path, default=Path("strategy/action_ranker_model.json"))
    parser.add_argument("--report-out", type=Path, default=Path("strategy/action_ranker_report.md"))
    args = parser.parse_args()

    if args.holdout_mod <= 1:
        raise SystemExit("--holdout-mod must be greater than 1")
    if not 0 <= args.holdout_bucket < args.holdout_mod:
        raise SystemExit("--holdout-bucket must be in [0, holdout_mod)")

    rows = load_rows(args.decisions)
    weights, train_stats = train(
        rows,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        holdout_mod=args.holdout_mod,
        holdout_bucket=args.holdout_bucket,
    )
    overall, by_context = evaluate(
        rows,
        weights=weights,
        holdout_mod=args.holdout_mod,
        holdout_bucket=args.holdout_bucket,
    )
    write_model(args.model_out, args, weights)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, weights, train_stats, overall, by_context),
        encoding="utf-8",
    )
    print(f"rows={len(rows)} train_single={train_stats.rows} weights={len(weights)}")
    print(f"holdout_top1={pct(overall.top1, overall.total)} holdout_top3={pct(overall.top3, overall.total)} n={overall.total}")
    print(f"model={args.model_out}")
    print(f"report={args.report_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
