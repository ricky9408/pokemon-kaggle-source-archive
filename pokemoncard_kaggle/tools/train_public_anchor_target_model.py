#!/usr/bin/env python3
"""Train a narrow pairwise policy model on public-anchored target motifs.

The generic action ranker is useful for finding disagreements, but it is too
broad to become a policy patch directly. This tool uses the public-anchored
target CSV to pick a small curriculum, then learns to rank the public replay
action above the generic model's competing action on those specific motifs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from policy_gap_miner import classify_gap, motif, reward_bucket, row_group  # noqa: E402
from train_action_ranker import load_rows, option_features, pct, ranked_options, valid_single_label  # noqa: E402


@dataclass(frozen=True)
class Target:
    rank: int
    gap: str
    archetype: str
    deck_hash: str
    anchor_tier: str
    source_count: int
    source_score: float

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.archetype, self.deck_hash, self.gap)


@dataclass
class PairExample:
    row: dict[str, Any]
    target: Target
    public_index: int
    competitor_index: int
    public_text: str
    competitor_text: str
    reward: str


@dataclass
class EvalStats:
    total: int = 0
    correct: int = 0
    wins: int = 0
    losses: int = 0
    ties: int = 0
    mistakes: Counter[str] = field(default_factory=Counter)

    def add(self, correct: bool, reward: str, mistake: str | None = None) -> None:
        self.total += 1
        self.correct += int(correct)
        self.wins += int(reward == "win")
        self.losses += int(reward == "loss")
        self.ties += int(reward == "draw")
        if mistake:
            self.mistakes[mistake] += 1

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0


def stable_bucket(value: str, modulo: int) -> int:
    digest = hashlib.sha1(value.encode()).hexdigest()
    return int(digest[:10], 16) % modulo


def load_base_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def load_targets(path: Path, args: argparse.Namespace) -> list[Target]:
    requested_ranks = set(args.target_rank or [])
    requested_gaps = set(args.gap or [])
    requested_tiers = set(args.anchor_tier or [])
    targets: list[Target] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                rank = int(row.get("rank") or 0)
                source_count = int(row.get("count") or 0)
                source_score = float(row.get("score") or 0.0)
            except ValueError:
                continue
            archetype = str(row.get("archetype") or "")
            deck_hash = str(row.get("deck_hash") or "")
            gap = str(row.get("gap") or "")
            anchor_tier = str(row.get("anchor_tier") or "")
            if requested_ranks and rank not in requested_ranks:
                continue
            if not requested_ranks and rank > args.top_targets:
                continue
            if requested_gaps and gap not in requested_gaps:
                continue
            if args.archetype and archetype != args.archetype:
                continue
            if args.deck_hash and deck_hash != args.deck_hash:
                continue
            if requested_tiers and anchor_tier not in requested_tiers:
                continue
            if source_count < args.min_source_count:
                continue
            targets.append(
                Target(
                    rank=rank,
                    gap=gap,
                    archetype=archetype,
                    deck_hash=deck_hash,
                    anchor_tier=anchor_tier,
                    source_count=source_count,
                    source_score=source_score,
                )
            )
    return targets


def pair_features(row: dict[str, Any], option_index: int, target: Target) -> list[str]:
    feats = option_features(row, option_index)
    options = row.get("options") or []
    option_text = str(options[option_index]) if option_index < len(options) else ""
    option_motif = motif(option_text)
    state = row.get("state") or {}
    me = state.get("me") or {}
    opponent = state.get("opponent") or {}
    extra = [
        f"target_gap={target.gap}",
        f"target_lane={target.archetype}:{target.deck_hash}",
        f"target_rank={target.rank}",
        f"target_gap_motif={target.gap}:{option_motif}",
        f"lane_motif={target.archetype}:{option_motif}",
        f"opp_lane_motif={row_group(row, 'opponent_archetype')}:{option_motif}",
        f"prize_pair={me.get('prize_count')}|{opponent.get('prize_count')}",
        f"active_pair={me.get('active')}|{opponent.get('active')}",
        f"bench_pair={me.get('bench_count')}|{opponent.get('bench_count')}",
    ]
    # Conjoined sparse features are deliberately simple and inspectable.
    for feature in list(feats):
        extra.append(f"gap={target.gap}|{feature}")
        extra.append(f"lane={target.archetype}:{target.deck_hash}|{feature}")
    return feats + extra


def score(weights: dict[str, float], feats: list[str]) -> float:
    return sum(weights.get(feature, 0.0) for feature in feats)


def collect_examples(rows: list[dict[str, Any]], base_weights: dict[str, float], targets: list[Target]) -> list[PairExample]:
    target_by_key = {target.key: target for target in targets}
    examples: list[PairExample] = []
    for row in rows:
        label = valid_single_label(row)
        if label is None:
            continue
        ranking = ranked_options(base_weights, row)
        options = row.get("options") or []
        if not ranking or not (0 <= label < len(options) and 0 <= ranking[0] < len(options)):
            continue
        competitor = ranking[0]
        if competitor == label:
            continue
        selected = str(options[label])
        predicted = str(options[competitor])
        gap = classify_gap(row, selected, predicted)
        if gap is None:
            continue
        key = (row_group(row, "archetype"), row_group(row, "deck_hash"), gap)
        target = target_by_key.get(key)
        if target is None:
            continue
        examples.append(
            PairExample(
                row=row,
                target=target,
                public_index=label,
                competitor_index=competitor,
                public_text=selected,
                competitor_text=predicted,
                reward=reward_bucket(row.get("terminal_reward")),
            )
        )
    return examples


def holdout_value(example: PairExample, key: str) -> str:
    if key == "target":
        return f"{example.target.archetype}:{example.target.deck_hash}:{example.target.gap}"
    if key == "team":
        return row_group(example.row, "team")
    if key == "opponent_team":
        return row_group(example.row, "opponent_team")
    if key == "source":
        return row_group(example.row, "source")
    return str(example.row.get("episode_id"))


def is_holdout(example: PairExample, args: argparse.Namespace) -> bool:
    return stable_bucket(holdout_value(example, args.holdout_key), args.holdout_mod) == args.holdout_bucket


def train(examples: list[PairExample], args: argparse.Namespace) -> tuple[dict[str, float], int]:
    weights: dict[str, float] = {}
    updates = 0
    train_examples = [
        example
        for example in examples
        if not is_holdout(example, args)
    ]
    for _epoch in range(args.epochs):
        for example in train_examples:
            pos = pair_features(example.row, example.public_index, example.target)
            neg = pair_features(example.row, example.competitor_index, example.target)
            margin = score(weights, pos) - score(weights, neg)
            if margin > args.margin:
                continue
            updates += 1
            for feature in pos:
                weights[feature] = weights.get(feature, 0.0) + args.learning_rate
            for feature in neg:
                weights[feature] = weights.get(feature, 0.0) - args.learning_rate
    return weights, updates


def evaluate_examples(examples: list[PairExample], weights: dict[str, float]) -> tuple[EvalStats, dict[str, EvalStats]]:
    overall = EvalStats()
    by_target: dict[str, EvalStats] = defaultdict(EvalStats)
    for example in examples:
        public_score = score(weights, pair_features(example.row, example.public_index, example.target))
        competitor_score = score(weights, pair_features(example.row, example.competitor_index, example.target))
        correct = public_score > competitor_score
        mistake = None
        if not correct:
            mistake = (
                f"{row_group(example.row, 'context')} {example.target.gap}: "
                f"public={example.public_text} model={example.competitor_text} reward={example.reward}"
            )
        key = f"{example.target.rank}:{example.target.archetype}:{example.target.deck_hash}:{example.target.gap}"
        overall.add(correct, example.reward, mistake)
        by_target[key].add(correct, example.reward, mistake)
    return overall, dict(by_target)


def top_weights(weights: dict[str, float], reverse: bool, limit: int) -> list[tuple[str, float]]:
    return sorted(weights.items(), key=lambda item: item[1], reverse=reverse)[:limit]


def render_report(
    args: argparse.Namespace,
    targets: list[Target],
    examples: list[PairExample],
    updates: int,
    weights: dict[str, float],
    train_stats: EvalStats,
    holdout_stats: EvalStats,
    by_target: dict[str, EvalStats],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    holdout_examples = [example for example in examples if is_holdout(example, args)]
    train_examples = [example for example in examples if not is_holdout(example, args)]
    lines: list[str] = []
    lines.append("# Public-Anchored Target Policy Model")
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
    lines.append("- Strategy premise: learn a narrow public-supported policy correction before touching deck architecture.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.base_model}`")
    lines.append(f"- Target CSV: `{args.targets}`")
    lines.append(f"- Model out: `{args.model_out}`")
    lines.append(f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append(f"- Epochs: {args.epochs}")
    lines.append(f"- Learning rate: {args.learning_rate}")
    lines.append("")
    lines.append("## Selected Targets")
    lines.append("")
    lines.append("| Rank | Gap | Archetype | Hash | Anchor Tier | Source Count | Source Score |")
    lines.append("| ---: | --- | --- | --- | --- | ---: | ---: |")
    for target in targets:
        lines.append(
            f"| {target.rank} | `{target.gap}` | `{target.archetype}` | `{target.deck_hash}` | "
            f"`{target.anchor_tier}` | {target.source_count} | {target.source_score:.1f} |"
        )
    if not targets:
        lines.append("| 0 | - | - | - | - | 0 | 0.0 |")
    lines.append("")
    lines.append("## Pairwise Public-vs-Model Examples")
    lines.append("")
    lines.append(f"- Examples collected: {len(examples)}")
    lines.append(f"- Train examples: {len(train_examples)}")
    lines.append(f"- Holdout examples: {len(holdout_examples)}")
    lines.append(f"- Perceptron updates: {updates}")
    lines.append("")
    lines.append("## Metrics")
    lines.append("")
    lines.append("| Split | N | Accuracy | Wins | Losses | Draws |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    lines.append(f"| Train | {train_stats.total} | {train_stats.accuracy:.3f} | {train_stats.wins} | {train_stats.losses} | {train_stats.ties} |")
    lines.append(f"| Holdout | {holdout_stats.total} | {holdout_stats.accuracy:.3f} | {holdout_stats.wins} | {holdout_stats.losses} | {holdout_stats.ties} |")
    lines.append("")
    lines.append("## Holdout By Target")
    lines.append("")
    lines.append("| Target | N | Accuracy | Wins | Losses | Top Mistake |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
    for key, stats in sorted(by_target.items(), key=lambda item: (-item[1].total, item[0])):
        mistake = stats.mistakes.most_common(1)[0][0] if stats.mistakes else "-"
        lines.append(f"| `{key}` | {stats.total} | {stats.accuracy:.3f} | {stats.wins} | {stats.losses} | {mistake} |")
    if not by_target:
        lines.append("| - | 0 | 0.000 | 0 | 0 | - |")
    lines.append("")
    lines.append("## Strongest Learned Features")
    lines.append("")
    lines.append("### Toward Public Action")
    lines.append("")
    for feature, value in top_weights(weights, True, args.weight_limit):
        lines.append(f"- `{feature}`: {value:.3f}")
    lines.append("")
    lines.append("### Toward Generic Model Competitor")
    lines.append("")
    for feature, value in top_weights(weights, False, args.weight_limit):
        lines.append(f"- `{feature}`: {value:.3f}")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if holdout_stats.total == 0:
        lines.append("- No holdout examples were available; widen the target set before using this model.")
    elif holdout_stats.accuracy >= args.good_accuracy:
        lines.append(
            f"- Holdout pairwise accuracy {holdout_stats.accuracy:.3f} clears the {args.good_accuracy:.3f} probe threshold. This motif is learnable enough for a tiny research policy patch or offline value target."
        )
    else:
        lines.append(
            f"- Holdout pairwise accuracy {holdout_stats.accuracy:.3f} is below the {args.good_accuracy:.3f} probe threshold. Keep this as analysis and gather more public anchors before patching runtime policy."
        )
    lines.append("- This model is not a submit selector; it is a curriculum/evaluator for public-supported strategy corrections.")
    return "\n".join(lines)


def write_model(path: Path, weights: dict[str, float], targets: list[Target], args: argparse.Namespace, updates: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": "public_anchor_pairwise_target_model",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "decisions": str(args.decisions),
        "base_model": str(args.base_model),
        "targets": [target.__dict__ for target in targets],
        "holdout_mod": args.holdout_mod,
        "holdout_bucket": args.holdout_bucket,
        "holdout_key": args.holdout_key,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "updates": updates,
        "weights": weights,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--model-out", type=Path, default=Path("strategy/public_anchor_target_model.json"))
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_target_model.md"))
    parser.add_argument("--top-targets", type=int, default=8)
    parser.add_argument("--target-rank", type=int, action="append")
    parser.add_argument("--gap", action="append")
    parser.add_argument("--archetype")
    parser.add_argument("--deck-hash")
    parser.add_argument("--anchor-tier", action="append", default=["exact-public-replay-supported"])
    parser.add_argument("--min-source-count", type=int, default=25)
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--learning-rate", type=float, default=0.08)
    parser.add_argument("--margin", type=float, default=0.0)
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source", "target"], default="episode_id")
    parser.add_argument("--good-accuracy", type=float, default=0.70)
    parser.add_argument("--weight-limit", type=int, default=24)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    base_weights = load_base_model(args.base_model)
    targets = load_targets(args.targets, args)
    examples = collect_examples(rows, base_weights, targets)
    weights, updates = train(examples, args)
    train_examples = [example for example in examples if not is_holdout(example, args)]
    holdout_examples = [example for example in examples if is_holdout(example, args)]
    train_stats, _train_by_target = evaluate_examples(train_examples, weights)
    holdout_stats, holdout_by_target = evaluate_examples(holdout_examples, weights)
    write_model(args.model_out, weights, targets, args, updates)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, targets, examples, updates, weights, train_stats, holdout_stats, holdout_by_target),
        encoding="utf-8",
    )
    print(
        "targets={targets} examples={examples} holdout={holdout} acc={acc:.3f} report={report}".format(
            targets=len(targets),
            examples=len(examples),
            holdout=holdout_stats.total,
            acc=holdout_stats.accuracy,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
