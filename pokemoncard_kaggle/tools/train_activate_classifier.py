#!/usr/bin/env python3
"""Train a dependency-free ACTIVATE yes/no classifier from replay decisions.

This is an audit model, not a submission policy. It learns where public replay
players accept or decline optional activation prompts so policy probes can be
gated by feature-level evidence instead of hand-written global thresholds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Stats:
    total: int = 0
    correct: int = 0
    yes: int = 0
    no: int = 0
    pred_yes: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    by_hand: defaultdict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    by_arch: defaultdict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))


def stable_bucket(value: str, modulo: int) -> int:
    digest = hashlib.sha1(value.encode()).hexdigest()
    return int(digest[:10], 16) % modulo


def load_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return rows


def hand_bucket(value: Any) -> str:
    if not isinstance(value, int):
        return "?"
    if value <= 2:
        return "0-2"
    if value <= 4:
        return "3-4"
    if value <= 6:
        return "5-6"
    if value <= 8:
        return "7-8"
    if value <= 10:
        return "9-10"
    if value <= 12:
        return "11-12"
    return "13+"


def small_bucket(value: Any, size: int, cap: int) -> str:
    if not isinstance(value, int):
        return "?"
    return str(min(cap, value // size))


def selected_is_yes(row: dict[str, Any]) -> bool | None:
    if row.get("context") != "ACTIVATE":
        return None
    action = row.get("action")
    options = row.get("options") or []
    if not isinstance(action, list) or len(action) != 1:
        return None
    index = action[0]
    if not isinstance(index, int) or not 0 <= index < len(options):
        return None
    selected = options[index]
    if selected.endswith(":YES"):
        return True
    if selected.endswith(":NO"):
        return False
    return None


def card_features(prefix: str, cards: list[Any], limit: int = 5) -> list[str]:
    feats: list[str] = []
    for card in cards[:limit]:
        if isinstance(card, int):
            feats.append(f"{prefix}_has={card}")
    return feats


def features(row: dict[str, Any]) -> list[str]:
    state = row.get("state") or {}
    me = state.get("me") or {}
    opponent = state.get("opponent") or {}
    me_hand = me.get("hand_count")
    opp_hand = opponent.get("hand_count")
    me_bench = me.get("bench") or []
    opp_bench = opponent.get("bench") or []
    archetype = str(row.get("archetype"))
    opponent_archetype = str(row.get("opponent_archetype"))

    feats = [
        "bias",
        f"arch={archetype}",
        f"opp_arch={opponent_archetype}",
        f"pair={archetype}|{opponent_archetype}",
        f"deck={row.get('deck_hash')}",
        f"opp_deck={row.get('opponent_deck_hash')}",
        f"me_active={me.get('active')}",
        f"opp_active={opponent.get('active')}",
        f"me_hand={hand_bucket(me_hand)}",
        f"opp_hand={hand_bucket(opp_hand)}",
        f"hand_pair={hand_bucket(me_hand)}|{hand_bucket(opp_hand)}",
        f"me_bench_count={me.get('bench_count')}",
        f"opp_bench_count={opponent.get('bench_count')}",
        f"me_prizes={me.get('prize_count')}",
        f"opp_prizes={opponent.get('prize_count')}",
        f"turn={small_bucket(state.get('turn'), 3, 8)}",
        f"turn_action={small_bucket(state.get('turn_action_count'), 2, 8)}",
        f"energy_attached={state.get('energy_attached')}",
        f"supporter_played={state.get('supporter_played')}",
        f"stadium_played={state.get('stadium_played')}",
    ]
    feats.extend(card_features("me_bench", me_bench))
    feats.extend(card_features("opp_bench", opp_bench))
    if isinstance(me_hand, int):
        feats.append(f"active_hand={me.get('active')}|{hand_bucket(me_hand)}")
        feats.append(f"arch_hand={archetype}|{hand_bucket(me_hand)}")
    return feats


def score(weights: dict[str, float], feats: list[str]) -> float:
    return sum(weights.get(feature, 0.0) for feature in feats)


def train(rows: list[dict[str, Any]], epochs: int, learning_rate: float, holdout_mod: int, holdout_bucket: int) -> dict[str, float]:
    train_rows = [
        row
        for row in rows
        if selected_is_yes(row) is not None
        and stable_bucket(str(row.get("episode_id")), holdout_mod) != holdout_bucket
    ]
    weights: dict[str, float] = {}
    for _ in range(epochs):
        for row in train_rows:
            label = selected_is_yes(row)
            if label is None:
                continue
            y = 1.0 if label else -1.0
            feats = features(row)
            if y * score(weights, feats) > 0:
                continue
            for feature in feats:
                weights[feature] = weights.get(feature, 0.0) + learning_rate * y
    return weights


def evaluate(rows: list[dict[str, Any]], weights: dict[str, float], holdout_mod: int, holdout_bucket: int) -> Stats:
    stats = Stats()
    for row in rows:
        label = selected_is_yes(row)
        if label is None:
            continue
        if stable_bucket(str(row.get("episode_id")), holdout_mod) != holdout_bucket:
            continue
        pred = score(weights, features(row)) >= 0
        state = row.get("state") or {}
        me = state.get("me") or {}
        hand = hand_bucket(me.get("hand_count"))
        arch = str(row.get("archetype"))
        stats.total += 1
        stats.yes += int(label)
        stats.no += int(not label)
        stats.pred_yes += int(pred)
        stats.correct += int(pred == label)
        stats.tp += int(pred and label)
        stats.fp += int(pred and not label)
        stats.fn += int((not pred) and label)
        stats.by_hand[hand]["total"] += 1
        stats.by_hand[hand]["yes"] += int(label)
        stats.by_hand[hand]["correct"] += int(pred == label)
        stats.by_arch[arch]["total"] += 1
        stats.by_arch[arch]["yes"] += int(label)
        stats.by_arch[arch]["correct"] += int(pred == label)
    return stats


def pct(num: int, den: int) -> str:
    return "0.000" if den == 0 else f"{num / den:.3f}"


def top_weights(weights: dict[str, float], reverse: bool) -> list[tuple[str, float]]:
    return sorted(weights.items(), key=lambda item: item[1], reverse=reverse)[:20]


def render_report(args: argparse.Namespace, rows: list[dict[str, Any]], weights: dict[str, float], stats: Stats) -> str:
    activate_rows = [row for row in rows if selected_is_yes(row) is not None]
    precision = pct(stats.tp, stats.tp + stats.fp)
    recall = pct(stats.tp, stats.tp + stats.fn)
    lines: list[str] = []
    lines.append("# ACTIVATE Classifier Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: optional activation policy should be learned as a feature-conditioned audit, not a global hand-size rule.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    for path in args.decisions:
        lines.append(f"- Decision JSONL: `{path}`")
    lines.append(f"- ACTIVATE rows: {len(activate_rows)}")
    lines.append(f"- Holdout split: sha1(episode_id) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append(f"- Epochs: {args.epochs}")
    lines.append(f"- Learning rate: {args.learning_rate}")
    lines.append("")
    lines.append("## Holdout Metrics")
    lines.append("")
    lines.append(f"- Holdout rows: {stats.total}")
    lines.append(f"- Accuracy: {pct(stats.correct, stats.total)}")
    lines.append(f"- YES rate: {pct(stats.yes, stats.total)}")
    lines.append(f"- Predicted YES rate: {pct(stats.pred_yes, stats.total)}")
    lines.append(f"- YES precision: {precision}")
    lines.append(f"- YES recall: {recall}")
    lines.append(f"- Majority baseline: {pct(max(stats.yes, stats.no), stats.total)}")
    lines.append("")
    lines.append("## Hand Buckets")
    lines.append("")
    lines.append("| Hand | Rows | Public YES | Accuracy |")
    lines.append("| --- | ---: | ---: | ---: |")
    for hand, counter in sorted(stats.by_hand.items()):
        total = counter["total"]
        lines.append(f"| `{hand}` | {total} | {pct(counter['yes'], total)} | {pct(counter['correct'], total)} |")
    lines.append("")
    lines.append("## Archetypes")
    lines.append("")
    lines.append("| Archetype | Rows | Public YES | Accuracy |")
    lines.append("| --- | ---: | ---: | ---: |")
    for arch, counter in sorted(stats.by_arch.items(), key=lambda item: item[1]["total"], reverse=True)[:20]:
        total = counter["total"]
        lines.append(f"| `{arch}` | {total} | {pct(counter['yes'], total)} | {pct(counter['correct'], total)} |")
    lines.append("")
    lines.append("## YES-Weighted Features")
    lines.append("")
    for feature, value in top_weights(weights, True):
        lines.append(f"- `{feature}`: {value:.3f}")
    lines.append("")
    lines.append("## NO-Weighted Features")
    lines.append("")
    for feature, value in top_weights(weights, False):
        lines.append(f"- `{feature}`: {value:.3f}")
    lines.append("")
    lines.append("## Strategy Translation")
    lines.append("")
    lines.append("- Use this model as an audit gate: only probe activation changes when a feature subgroup has stable holdout behavior and replay examples.")
    lines.append("- Do not convert the global classifier directly into the agent; ACTIVATE prompts are sparse and matchup-dependent.")
    lines.append("- Rebuild this report after each fresh top-window scout and compare feature stability before any submit-facing activation patch.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", nargs="+", type=Path)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=0.25)
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = train(rows, args.epochs, args.learning_rate, args.holdout_mod, args.holdout_bucket)
    stats = evaluate(rows, weights, args.holdout_mod, args.holdout_bucket)
    report = render_report(args, rows, weights, stats)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    if args.model:
        args.model.parent.mkdir(parents=True, exist_ok=True)
        args.model.write_text(
            json.dumps(
                {
                    "created_utc": datetime.now(timezone.utc).isoformat(),
                    "decisions": [str(path) for path in args.decisions],
                    "epochs": args.epochs,
                    "learning_rate": args.learning_rate,
                    "holdout_mod": args.holdout_mod,
                    "holdout_bucket": args.holdout_bucket,
                    "weights": weights,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
