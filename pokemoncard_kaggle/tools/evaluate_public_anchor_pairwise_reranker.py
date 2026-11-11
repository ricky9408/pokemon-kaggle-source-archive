#!/usr/bin/env python3
"""Evaluate a public-anchor pairwise model as a constrained reranker.

The pairwise target model can look excellent when it is judged only on
public-vs-model target pairs. This diagnostic asks the harder runtime-shaped
question: if the pairwise model is allowed to override the base top-1 only when
the current legal action motifs match a public-anchor target, does broad replay
action agreement improve without collateral regressions?
"""

from __future__ import annotations

import argparse
import csv
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
from policy_gap_miner import motif, row_group  # noqa: E402
from train_action_ranker import (  # noqa: E402
    load_rows,
    option_features,
    pct,
    ranked_options,
    score as base_score,
    stable_bucket,
    valid_single_label,
)
from train_public_anchor_target_model import (  # noqa: E402
    collect_examples,
    is_holdout,
    load_base_model,
    pair_features,
    score as pair_score,
)


@dataclass(frozen=True)
class TargetSpec:
    rank: int
    gap: str
    archetype: str
    deck_hash: str
    anchor_tier: str
    source_count: int
    source_score: float
    public_motif: str
    model_motif: str
    context: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.archetype, self.deck_hash, self.gap)

    @property
    def name(self) -> str:
        return f"{self.rank}:{self.archetype}:{self.deck_hash}:{self.gap}"


@dataclass
class EvalStats:
    total: int = 0
    skipped: int = 0
    base_top1: int = 0
    rerank_top1: int = 0
    base_top3: int = 0
    rerank_top3: int = 0
    fires: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0


@dataclass
class PairStats:
    total: int = 0
    base_pair: int = 0
    rerank_pair: int = 0
    base_top1: int = 0
    rerank_top1: int = 0
    fires: int = 0
    changed: int = 0


@dataclass
class TargetEffect:
    fires: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0
    margins: list[float] = field(default_factory=list)


@dataclass(frozen=True)
class RerankDecision:
    order: list[int]
    target: TargetSpec | None = None
    margin: float = 0.0
    promoted_index: int | None = None


def load_pair_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def load_targets(path: Path, args: argparse.Namespace) -> list[TargetSpec]:
    requested_ranks = set(args.target_rank or [])
    requested_gaps = set(args.gap or [])
    requested_tiers = set(args.anchor_tier or [])
    targets: list[TargetSpec] = []
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
            public_motif = str(row.get("public_motif") or "")
            model_motif = str(row.get("model_motif") or "")
            context = str(row.get("example_context") or "")
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
            if not args.include_same_motif and public_motif == model_motif:
                continue
            if not public_motif or not model_motif:
                continue
            targets.append(
                TargetSpec(
                    rank=rank,
                    gap=gap,
                    archetype=archetype,
                    deck_hash=deck_hash,
                    anchor_tier=anchor_tier,
                    source_count=source_count,
                    source_score=source_score,
                    public_motif=public_motif,
                    model_motif=model_motif,
                    context=context,
                )
            )
    return targets


def row_targets(row: dict[str, Any], targets: list[TargetSpec], args: argparse.Namespace) -> list[TargetSpec]:
    archetype = row_group(row, "archetype")
    deck_hash = row_group(row, "deck_hash")
    context = row_group(row, "context")
    matches: list[TargetSpec] = []
    for target in targets:
        if target.archetype != archetype or target.deck_hash != deck_hash:
            continue
        if not args.ignore_target_context and target.context and target.context != context:
            continue
        matches.append(target)
    return matches


def option_motifs(row: dict[str, Any]) -> list[str]:
    options = row.get("options") or []
    option_count = int(row.get("option_count") or 0)
    return [motif(str(options[index])) if index < len(options) else "" for index in range(option_count)]


def rank_with_pairwise(
    row: dict[str, Any],
    base_weights: dict[str, float],
    pair_weights: dict[str, float],
    targets: list[TargetSpec],
    threshold: float,
    args: argparse.Namespace,
) -> RerankDecision:
    base_order = ranked_options(base_weights, row)
    if not base_order:
        return RerankDecision([])
    options = row.get("options") or []
    option_count = int(row.get("option_count") or 0)
    if option_count <= 0:
        return RerankDecision(base_order)
    base_top = base_order[0]
    motifs = option_motifs(row)
    if base_top >= len(motifs):
        return RerankDecision(base_order)

    best: tuple[float, float, int, TargetSpec] | None = None
    for target in row_targets(row, targets, args):
        if motifs[base_top] != target.model_motif:
            continue
        preferred = [
            index
            for index in range(min(option_count, len(options)))
            if motifs[index] == target.public_motif and index != base_top
        ]
        if not preferred:
            continue
        base_pair_value = pair_score(pair_weights, pair_features(row, base_top, target))
        base_values = [
            base_score(base_weights, option_features(row, index))
            for index in range(option_count)
        ]
        candidate = max(
            preferred,
            key=lambda index: (
                pair_score(pair_weights, pair_features(row, index, target)),
                base_values[index],
                -index,
            ),
        )
        candidate_pair_value = pair_score(pair_weights, pair_features(row, candidate, target))
        margin = candidate_pair_value - base_pair_value
        if margin < threshold:
            continue
        record = (margin, target.source_score, -candidate, target)
        if best is None or record > best:
            best = record

    if best is None:
        return RerankDecision(base_order)
    margin, _source_score, neg_candidate, target = best
    promoted = -neg_candidate
    new_order = [promoted] + [index for index in base_order if index != promoted]
    return RerankDecision(new_order, target=target, margin=margin, promoted_index=promoted)


def update_stats(stats: EvalStats, label: int | None, base_order: list[int], rerank: RerankDecision) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    base_hit = bool(base_order and base_order[0] == label)
    rerank_hit = bool(rerank.order and rerank.order[0] == label)
    stats.base_top1 += int(base_hit)
    stats.rerank_top1 += int(rerank_hit)
    stats.base_top3 += int(label in base_order[:3])
    stats.rerank_top3 += int(label in rerank.order[:3])
    stats.fires += int(rerank.target is not None)
    changed = bool(base_order and rerank.order and base_order[0] != rerank.order[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and rerank_hit)
    stats.regressions += int(changed and base_hit and not rerank_hit)
    stats.neutral_changes += int(changed and base_hit == rerank_hit)


def eval_rows(
    rows: list[dict[str, Any]],
    base_weights: dict[str, float],
    pair_weights: dict[str, float],
    targets: list[TargetSpec],
    threshold: float,
    args: argparse.Namespace,
) -> tuple[EvalStats, dict[str, EvalStats], dict[str, TargetEffect], Counter[str]]:
    overall = EvalStats()
    by_group: dict[str, EvalStats] = defaultdict(EvalStats)
    by_target: dict[str, TargetEffect] = defaultdict(TargetEffect)
    changes: Counter[str] = Counter()
    for row in rows:
        label = valid_single_label(row)
        base_order = [] if label is None else ranked_options(base_weights, row)
        rerank = (
            RerankDecision([])
            if label is None
            else rank_with_pairwise(row, base_weights, pair_weights, targets, threshold, args)
        )
        update_stats(overall, label, base_order, rerank)
        group_key = f"{row_group(row, 'archetype')} vs {row_group(row, 'opponent_archetype')}"
        update_stats(by_group[group_key], label, base_order, rerank)
        if label is None or not base_order or not rerank.order or rerank.target is None:
            continue
        target_effect = by_target[rerank.target.name]
        target_effect.fires += 1
        target_effect.margins.append(rerank.margin)
        changed = base_order[0] != rerank.order[0]
        target_effect.changed += int(changed)
        base_hit = base_order[0] == label
        rerank_hit = rerank.order[0] == label
        target_effect.fixes += int(changed and not base_hit and rerank_hit)
        target_effect.regressions += int(changed and base_hit and not rerank_hit)
        target_effect.neutral_changes += int(changed and base_hit == rerank_hit)
        if changed:
            options = row.get("options") or []
            public = options[label] if label < len(options) else str(label)
            before = options[base_order[0]] if base_order[0] < len(options) else str(base_order[0])
            after = options[rerank.order[0]] if rerank.order[0] < len(options) else str(rerank.order[0])
            outcome = "fix" if rerank_hit and not base_hit else "regress" if base_hit and not rerank_hit else "neutral"
            changes[f"{outcome}: {rerank.target.name}: public={public} | base={before} | rerank={after}"] += 1
    return overall, dict(by_group), dict(by_target), changes


def eval_pair_examples(
    examples: list[Any],
    base_weights: dict[str, float],
    pair_weights: dict[str, float],
    targets: list[TargetSpec],
    threshold: float,
    args: argparse.Namespace,
) -> tuple[PairStats, dict[str, PairStats]]:
    overall = PairStats()
    by_gap: dict[str, PairStats] = defaultdict(PairStats)
    for example in examples:
        base_order = ranked_options(base_weights, example.row)
        rerank = rank_with_pairwise(example.row, base_weights, pair_weights, targets, threshold, args)
        base_pos = base_order.index(example.public_index) if example.public_index in base_order else 9999
        base_neg = base_order.index(example.competitor_index) if example.competitor_index in base_order else 9999
        rerank_pos = rerank.order.index(example.public_index) if example.public_index in rerank.order else 9999
        rerank_neg = rerank.order.index(example.competitor_index) if example.competitor_index in rerank.order else 9999
        for stats in (overall, by_gap[example.target.gap]):
            stats.total += 1
            stats.base_pair += int(base_pos < base_neg)
            stats.rerank_pair += int(rerank_pos < rerank_neg)
            stats.base_top1 += int(bool(base_order) and base_order[0] == example.public_index)
            stats.rerank_top1 += int(bool(rerank.order) and rerank.order[0] == example.public_index)
            stats.fires += int(rerank.target is not None)
            stats.changed += int(bool(base_order and rerank.order and base_order[0] != rerank.order[0]))
    return overall, dict(by_gap)


def row_is_holdout(row: dict[str, Any], args: argparse.Namespace) -> bool:
    if args.holdout_key == "target":
        value = f"{row_group(row, 'archetype')}:{row_group(row, 'deck_hash')}"
    else:
        value = row_group(row, args.holdout_key)
    return stable_bucket(value, args.holdout_mod) == args.holdout_bucket


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | "
        f"{pct(stats.rerank_top1, stats.total)} | {pct(stats.base_top3, stats.total)} | "
        f"{pct(stats.rerank_top3, stats.total)} | {stats.fires} | {stats.changed} | "
        f"{stats.fixes} | {stats.regressions} | {stats.neutral_changes} |"
    )


def pair_row(name: str, stats: PairStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_pair, stats.total)} | "
        f"{pct(stats.rerank_pair, stats.total)} | {pct(stats.base_top1, stats.total)} | "
        f"{pct(stats.rerank_top1, stats.total)} | {stats.fires} | {stats.changed} |"
    )


def render_target_effects(title: str, effects: dict[str, TargetEffect], args: argparse.Namespace) -> list[str]:
    lines = [f"## {title}", ""]
    lines.append("| Target | Fires | Fixes | Regressions | Neutral | Median Margin |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
    ordered = sorted(
        effects.items(),
        key=lambda item: (item[1].fixes - item[1].regressions, item[1].fires),
        reverse=True,
    )
    for name, effect in ordered[: args.limit]:
        margins = sorted(effect.margins)
        median = margins[len(margins) // 2] if margins else 0.0
        lines.append(
            f"| `{name}` | {effect.fires} | {effect.fixes} | {effect.regressions} | "
            f"{effect.neutral_changes} | {median:.3f} |"
        )
    if not ordered:
        lines.append("| - | 0 | 0 | 0 | 0 | 0.000 |")
    lines.append("")
    return lines


def render_report(
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    targets: list[TargetSpec],
    threshold_results: list[dict[str, Any]],
    train_examples: list[Any],
    holdout_examples: list[Any],
) -> str:
    lines: list[str] = []
    lines.append("# Public-Anchor Pairwise Reranker Evaluation")
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
    lines.append("- Strategy premise: public-anchor pairwise accuracy is insufficient unless a runtime-shaped reranker avoids broad regressions.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.base_model}`")
    lines.append(f"- Pairwise model: `{args.pairwise_model}`")
    lines.append(f"- Target CSV: `{args.targets}`")
    lines.append(f"- Rows loaded: {len(rows)}")
    lines.append(f"- Targets loaded: {len(targets)}")
    lines.append(f"- Public-anchor pair train/holdout examples: {len(train_examples)} / {len(holdout_examples)}")
    lines.append(f"- Holdout split: sha1({args.holdout_key}) % {args.holdout_mod} == {args.holdout_bucket}")
    lines.append(f"- Same-motif runtime targets: {'included' if args.include_same_motif else 'excluded'}")
    lines.append("")
    lines.append("## Selected Runtime Targets")
    lines.append("")
    lines.append("| Rank | Gap | Lane | Public Motif | Model Motif | Count | Score |")
    lines.append("| ---: | --- | --- | --- | --- | ---: | ---: |")
    for target in targets:
        lines.append(
            f"| {target.rank} | `{target.gap}` | `{target.archetype}:{target.deck_hash}` | "
            f"`{target.public_motif}` | `{target.model_motif}` | {target.source_count} | {target.source_score:.1f} |"
        )
    if not targets:
        lines.append("| 0 | - | - | - | - | 0 | 0.0 |")
    lines.append("")
    lines.append("## Threshold Summary")
    lines.append("")
    lines.append("| Split | N | Base Top-1 | Rerank Top-1 | Base Top-3 | Rerank Top-3 | Fires | Changes | Fixes | Regressions | Neutral |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in threshold_results:
        threshold = result["threshold"]
        lines.append(stats_row(f"{threshold:.3f} all rows", result["all_stats"]))
        lines.append(stats_row(f"{threshold:.3f} held-out rows", result["holdout_stats"]))
    lines.append("")
    lines.append("## Public-Anchor Pair Agreement")
    lines.append("")
    lines.append("| Split/Gap | N | Base Public > Competitor | Rerank Public > Competitor | Base Top-1 | Rerank Top-1 | Fires | Changes |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in threshold_results:
        threshold = result["threshold"]
        lines.append(pair_row(f"{threshold:.3f} target train", result["target_train"]))
        lines.append(pair_row(f"{threshold:.3f} target holdout", result["target_holdout"]))
    lines.append("")
    best = max(
        threshold_results,
        key=lambda result: (
            result["holdout_stats"].rerank_top1 - result["holdout_stats"].base_top1,
            result["all_stats"].rerank_top1 - result["all_stats"].base_top1,
            -result["holdout_stats"].regressions,
        ),
    ) if threshold_results else None
    if best is not None:
        lines.append(f"## Detail For Best Threshold `{best['threshold']:.3f}`")
        lines.append("")
        lines.extend(render_target_effects("Per-Target Safety", best["target_effects"], args))
        lines.append("## Group Deltas")
        lines.append("")
        lines.append("| Group | N | Base Top-1 | Rerank Top-1 | Fires | Fixes | Regressions |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        eligible = [
            (name, stats)
            for name, stats in best["groups"].items()
            if stats.total >= args.min_group_n and stats.fires
        ]
        eligible.sort(key=lambda item: (item[1].rerank_top1 - item[1].base_top1, item[1].fires), reverse=True)
        for name, stats in eligible[: args.limit]:
            lines.append(
                f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | "
                f"{pct(stats.rerank_top1, stats.total)} | {stats.fires} | {stats.fixes} | {stats.regressions} |"
            )
        if not eligible:
            lines.append("| - | 0 | 0.000 | 0.000 | 0 | 0 | 0 |")
        lines.append("")
        lines.append("## Largest Top-1 Changes")
        lines.append("")
        for text, count in best["changes"].most_common(args.limit):
            lines.append(f"- {count}: {text}")
        if not best["changes"]:
            lines.append("- No top-1 changes.")
        lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if best is None:
        lines.append("- No thresholds were evaluated.")
    else:
        all_delta = best["all_stats"].rerank_top1 - best["all_stats"].base_top1
        holdout_delta = best["holdout_stats"].rerank_top1 - best["holdout_stats"].base_top1
        if all_delta > 0 and holdout_delta >= 0 and best["holdout_stats"].regressions <= args.max_holdout_regressions:
            lines.append(
                "- The constrained pairwise reranker is a candidate offline feature: it improves broad top-1 without a negative held-out top-1 delta under the configured regression cap."
            )
        else:
            lines.append(
                "- The constrained pairwise reranker is not safe for direct policy distillation under this run: pairwise target accuracy does not translate cleanly into broad no-regression behavior."
            )
        lines.append("- Treat positive thresholds as curriculum/value-model evidence only until public-anchor and backtest gates clear.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--base-model", type=Path, required=True)
    parser.add_argument("--pairwise-model", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_pairwise_reranker.md"))
    parser.add_argument("--top-targets", type=int, default=8)
    parser.add_argument("--target-rank", type=int, action="append")
    parser.add_argument("--gap", action="append")
    parser.add_argument("--archetype")
    parser.add_argument("--deck-hash")
    parser.add_argument("--anchor-tier", action="append", default=["exact-public-replay-supported"])
    parser.add_argument("--min-source-count", type=int, default=25)
    parser.add_argument("--threshold", type=float, action="append", default=[])
    parser.add_argument("--include-same-motif", action="store_true")
    parser.add_argument("--ignore-target-context", action="store_true")
    parser.add_argument("--holdout-key", choices=["episode_id", "team", "opponent_team", "source", "target"], default="team")
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--max-holdout-regressions", type=int, default=0)
    parser.add_argument("--min-group-n", type=int, default=50)
    parser.add_argument("--limit", type=int, default=18)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    base_weights = load_base_model(args.base_model)
    pair_weights = load_pair_model(args.pairwise_model)
    targets = load_targets(args.targets, args)
    all_target_examples = collect_examples(rows, base_weights, targets)
    train_examples = [example for example in all_target_examples if not is_holdout(example, args)]
    holdout_examples = [example for example in all_target_examples if is_holdout(example, args)]
    holdout_rows = [row for row in rows if row_is_holdout(row, args)]
    thresholds = args.threshold or [0.0]

    threshold_results: list[dict[str, Any]] = []
    for threshold in thresholds:
        all_stats, groups, target_effects, changes = eval_rows(
            rows, base_weights, pair_weights, targets, threshold, args
        )
        holdout_stats, _holdout_groups, _holdout_target_effects, _holdout_changes = eval_rows(
            holdout_rows, base_weights, pair_weights, targets, threshold, args
        )
        target_train, _target_train_by_gap = eval_pair_examples(
            train_examples, base_weights, pair_weights, targets, threshold, args
        )
        target_holdout, target_holdout_by_gap = eval_pair_examples(
            holdout_examples, base_weights, pair_weights, targets, threshold, args
        )
        threshold_results.append(
            {
                "threshold": threshold,
                "all_stats": all_stats,
                "holdout_stats": holdout_stats,
                "groups": groups,
                "target_effects": target_effects,
                "changes": changes,
                "target_train": target_train,
                "target_holdout": target_holdout,
                "target_holdout_by_gap": target_holdout_by_gap,
            }
        )

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, rows, targets, threshold_results, train_examples, holdout_examples),
        encoding="utf-8",
    )
    best = max(
        threshold_results,
        key=lambda result: (
            result["holdout_stats"].rerank_top1 - result["holdout_stats"].base_top1,
            result["all_stats"].rerank_top1 - result["all_stats"].base_top1,
            -result["holdout_stats"].regressions,
        ),
    )
    print(
        "rows={rows} targets={targets} thresholds={thresholds} best={best:.3f} "
        "all_base={all_base} all_rerank={all_rerank} holdout_base={hold_base} "
        "holdout_rerank={hold_rerank} report={report}".format(
            rows=len(rows),
            targets=len(targets),
            thresholds=",".join(f"{value:.3f}" for value in thresholds),
            best=best["threshold"],
            all_base=pct(best["all_stats"].base_top1, best["all_stats"].total),
            all_rerank=pct(best["all_stats"].rerank_top1, best["all_stats"].total),
            hold_base=pct(best["holdout_stats"].base_top1, best["holdout_stats"].total),
            hold_rerank=pct(best["holdout_stats"].rerank_top1, best["holdout_stats"].total),
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
