#!/usr/bin/env python3
"""Evaluate composed offline strategy features.

The current ML/RL workflow has several small public-anchor-positive strategy
features. This tool answers a different question: do those features compose, or
does a new timing feature interfere with the stronger accepted Dudunsparce timing
signal?

It is a deterministic offline public-action imitation check. It does not use the
local full-game simulator as a promotion signal and it never submits.
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
from evaluate_ability_attack_predicates import parse_predicate as parse_ability_predicate  # noqa: E402
from evaluate_attachment_timing_overlay import feature_map as attachment_feature_map  # noqa: E402
from evaluate_attachment_timing_overlay import parse_predicate as parse_attachment_predicate  # noqa: E402
from mine_ability_attack_guard import Case, card_id  # noqa: E402
from public_anchor_policy_targets import anchor_tier, build_lanes, load_anchor_status  # noqa: E402
from train_action_ranker import load_rows, option_parts, pct, ranked_options, stable_bucket, valid_single_label  # noqa: E402


DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]
DEFAULT_ABILITY_EXCEPTIONS = [
    "opp_active=878 & opp_bench=<=4",
    "archetype=alakazam-hammer & prizes=6|5",
]
DEFAULT_ATTACHMENT_PREDICATES = [
    "turn_bucket=4",
    "active=879",
    "active=879 & stadium_played=False",
    "energy_attached=False & opp_hand_bucket=1",
    "opp_hand_bucket=1 & stadium_played=False",
    "bench=5 & stadium_played=False",
]
DEFAULT_ACTIVE_ATTACHMENT_PREDICATES = [
    "stadium_played=False",
    "energy_attached=False",
    "base_card=5",
    "base_card=11",
    "base_card=19",
    "base_card=1171",
    "archetype=hops-trevenant",
    "deck_hash=88c7104a02",
    "base_target=BENCH",
]
DEFAULT_TEMPO_PREDICATES = [
    "stadium_played=False & supporter_played=True",
]
PUBLIC_SUPPORTED_TIERS = {
    "submit-eligible-candidate",
    "exact-public-replay-supported",
    "single-team-public-replay-supported",
}


@dataclass(frozen=True)
class StepSpec:
    kind: str
    name: str
    predicates: tuple[Any, ...] = ()


@dataclass(frozen=True)
class StackSpec:
    name: str
    steps: tuple[StepSpec, ...]


@dataclass
class EvalStats:
    total: int = 0
    skipped: int = 0
    base_top1: int = 0
    stack_top1: int = 0
    base_top3: int = 0
    stack_top3: int = 0
    fired: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0

    @property
    def top1_delta(self) -> int:
        return self.stack_top1 - self.base_top1

    @property
    def top3_delta(self) -> int:
        return self.stack_top3 - self.base_top3

    @property
    def net_fixes(self) -> int:
        return self.fixes - self.regressions


@dataclass
class StackResult:
    spec: StackSpec
    overall: EvalStats = field(default_factory=EvalStats)
    holdouts: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    tiers: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    lanes: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    step_fires: Counter[str] = field(default_factory=Counter)
    step_changes: Counter[str] = field(default_factory=Counter)
    changes: Counter[str] = field(default_factory=Counter)


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def holdout_hit(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def lane_key(row: dict[str, Any]) -> tuple[str, str]:
    return row_value(row, "archetype"), row_value(row, "deck_hash")


def code(text: str) -> str:
    return f"`{text.replace('|', '&#124;')}`"


def fmt_ratio(numerator: int, denominator: int) -> str:
    return pct(numerator, denominator)


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def ability_case(row: dict[str, Any], label: int, rank: list[int]) -> Case | None:
    if row_value(row, "context") != "MAIN" or not rank:
        return None
    options = [str(option) for option in (row.get("options") or [])]
    ability_indices = [
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ABILITY" and card_id(text) == "66"
    ]
    attack_indices = [index for index, text in enumerate(options) if option_parts(text)["type"] == "ATTACK"]
    if not ability_indices or rank[0] not in attack_indices:
        return None
    ability_index = ability_indices[0]
    public_text = options[label] if label < len(options) else str(label)
    if label == ability_index:
        outcome = "fix"
    elif label in attack_indices:
        outcome = "regression"
    else:
        outcome = "neutral"
    return Case(
        row=row,
        label=label,
        base_top=rank[0],
        ability_index=ability_index,
        attack_index=rank[0],
        outcome=outcome,
        public_text=public_text,
        base_text=options[rank[0]],
        ability_text=options[ability_index],
        attack_text=options[rank[0]],
    )


def apply_ability_step(
    row: dict[str, Any],
    label: int,
    rank: list[int],
    base_predicate: Any,
    exceptions: tuple[Any, ...],
) -> tuple[list[int], bool, bool]:
    case = ability_case(row, label, rank)
    if case is None or not base_predicate.fn(case):
        return rank, False, False
    if any(predicate.fn(case) for predicate in exceptions):
        return rank, False, True
    ability = case.ability_index
    return [ability] + [index for index in rank if index != ability], True, False


def active_attach_indices(options: list[str]) -> set[int]:
    return {
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ATTACH" and option_parts(text)["to_area"] == "ACTIVE"
    }


def bench_attach_indices(options: list[str]) -> set[int]:
    return {
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ATTACH" and option_parts(text)["to_area"] == "BENCH"
    }


def play_indices(options: list[str]) -> set[int]:
    return {index for index, text in enumerate(options) if option_parts(text)["type"] == "PLAY"}


def attack_indices(options: list[str]) -> set[int]:
    return {index for index, text in enumerate(options) if option_parts(text)["type"] == "ATTACK"}


def bucket_num(value: Any, size: int, cap: int) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, number // size))


def legal_type_count(options: list[str], type_name: str) -> int:
    return sum(1 for option in options if option_parts(option)["type"] == type_name)


def tempo_feature_map(row: dict[str, Any], options: list[str], base_top: int, overlay_top: int) -> dict[str, str]:
    features = attachment_feature_map(row, options, base_top, overlay_top)
    features["legal_attack_count_bucket"] = bucket_num(legal_type_count(options, "ATTACK"), 1, 5)
    features["base_attack"] = option_parts(options[base_top]).get("attack") if 0 <= base_top < len(options) else "none"
    features["overlay_attack"] = option_parts(options[overlay_top]).get("attack") if 0 <= overlay_top < len(options) else "none"
    return features


def apply_attachment_step(row: dict[str, Any], rank: list[int], predicates: tuple[Any, ...]) -> tuple[list[int], bool]:
    if row_value(row, "context") != "MAIN" or not rank:
        return rank, False
    options = [str(option) for option in (row.get("options") or [])]
    attach_active = active_attach_indices(options)
    plays = play_indices(options)
    if rank[0] not in attach_active or not plays:
        return rank, False
    best_play = next((index for index in rank if index in plays), None)
    if best_play is None:
        return rank, False
    features = attachment_feature_map(row, options, rank[0], best_play)
    if not any(predicate.fn(features) for predicate in predicates):
        return rank, False
    return [best_play] + [index for index in rank if index != best_play], True


def apply_active_attachment_step(row: dict[str, Any], rank: list[int], predicates: tuple[Any, ...]) -> tuple[list[int], bool]:
    if row_value(row, "context") != "MAIN" or not rank:
        return rank, False
    options = [str(option) for option in (row.get("options") or [])]
    bench_attaches = bench_attach_indices(options)
    active_attaches = active_attach_indices(options)
    if rank[0] not in bench_attaches or not active_attaches:
        return rank, False
    base_card = option_parts(options[rank[0]]).get("card")
    same_card_active = {
        index for index in active_attaches if option_parts(options[index]).get("card") == base_card
    }
    candidate_pool = same_card_active or active_attaches
    best_active = next((index for index in rank if index in candidate_pool), None)
    if best_active is None:
        return rank, False
    features = attachment_feature_map(row, options, rank[0], best_active)
    if not any(predicate.fn(features) for predicate in predicates):
        return rank, False
    return [best_active] + [index for index in rank if index != best_active], True


def apply_tempo_play_over_attack_step(row: dict[str, Any], rank: list[int], predicates: tuple[Any, ...]) -> tuple[list[int], bool]:
    if row_value(row, "context") != "MAIN" or not rank:
        return rank, False
    options = [str(option) for option in (row.get("options") or [])]
    attacks = attack_indices(options)
    plays = play_indices(options)
    if rank[0] not in attacks or not plays:
        return rank, False
    best_play = next((index for index in rank if index in plays), None)
    if best_play is None:
        return rank, False
    features = tempo_feature_map(row, options, rank[0], best_play)
    if not any(predicate.fn(features) for predicate in predicates):
        return rank, False
    return [best_play] + [index for index in rank if index != best_play], True


def apply_stack(
    row: dict[str, Any],
    label: int,
    base_rank: list[int],
    spec: StackSpec,
    ability_predicate: Any,
    ability_exceptions: tuple[Any, ...],
) -> tuple[list[int], Counter[str], Counter[str], bool]:
    rank = list(base_rank)
    fires: Counter[str] = Counter()
    changes: Counter[str] = Counter()
    suppressed = False
    for step in spec.steps:
        before = list(rank)
        if step.kind == "ability":
            rank, fired, was_suppressed = apply_ability_step(row, label, rank, ability_predicate, ability_exceptions)
            suppressed = suppressed or was_suppressed
        elif step.kind == "attachment":
            rank, fired = apply_attachment_step(row, rank, step.predicates)
        elif step.kind == "active_attachment":
            rank, fired = apply_active_attachment_step(row, rank, step.predicates)
        elif step.kind == "tempo_play_over_attack":
            rank, fired = apply_tempo_play_over_attack_step(row, rank, step.predicates)
        else:
            raise ValueError(f"Unknown step kind: {step.kind}")
        if fired:
            fires[step.name] += 1
        if before != rank:
            changes[step.name] += 1
    return rank, fires, changes, suppressed


def update_stats(stats: EvalStats, label: int | None, base_rank: list[int], stack_rank: list[int], fired: bool) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.fired += int(fired)
    base_hit = bool(base_rank and base_rank[0] == label)
    stack_hit = bool(stack_rank and stack_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.stack_top1 += int(stack_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.stack_top3 += int(label in stack_rank[:3])
    changed = bool(base_rank and stack_rank and base_rank[0] != stack_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and stack_hit)
    stats.regressions += int(changed and base_hit and not stack_hit)
    stats.neutral_changes += int(changed and base_hit == stack_hit)


def stack_specs(
    attachment_predicates: tuple[Any, ...],
    active_attachment_all: tuple[Any, ...],
    active_attachment_predicates: tuple[Any, ...],
    tempo_predicates: tuple[Any, ...],
) -> list[StackSpec]:
    first_attachment = (attachment_predicates[0],)
    active_attachment = tuple(
        predicate for predicate in attachment_predicates if predicate.name in {"active=879", "active=879 & stadium_played=False"}
    )
    if not active_attachment:
        active_attachment = first_attachment
    any_attachment = attachment_predicates
    ability = StepSpec("ability", "dudunsparce_stable")
    attach_turn = StepSpec("attachment", "attach_play_turn_bucket4", first_attachment)
    attach_active = StepSpec("attachment", "attach_play_active879", active_attachment)
    attach_any = StepSpec("attachment", "attach_play_mined_any", any_attachment)
    active_attach_all = StepSpec("active_attachment", "active_attach_over_bench_all", active_attachment_all)
    active_attach_any = StepSpec("active_attachment", "active_attach_over_bench_mined_any", active_attachment_predicates)
    tempo = StepSpec("tempo_play_over_attack", "tempo_play_over_attack_supporter_no_stadium", tempo_predicates)
    core_stack = (ability, attach_any)
    active_attach_core = (ability, active_attach_any)
    return [
        StackSpec("base_ranker", ()),
        StackSpec("ability_stable", (ability,)),
        StackSpec("attachment_turn_bucket4", (attach_turn,)),
        StackSpec("attachment_active879", (attach_active,)),
        StackSpec("attachment_mined_any", (attach_any,)),
        StackSpec("active_attach_over_bench_all", (active_attach_all,)),
        StackSpec("active_attach_over_bench_mined_any", (active_attach_any,)),
        StackSpec("tempo_play_over_attack", (tempo,)),
        StackSpec("ability_then_attachment_turn_bucket4", (ability, attach_turn)),
        StackSpec("ability_then_attachment_active879", (ability, attach_active)),
        StackSpec("ability_then_attachment_mined_any", (ability, attach_any)),
        StackSpec("attachment_then_ability_mined_any", (attach_any, ability)),
        StackSpec("ability_then_active_attach_over_bench_all", (ability, active_attach_all)),
        StackSpec("ability_then_active_attach_over_bench_mined_any", active_attach_core),
        StackSpec("active_attach_then_ability_mined_any", (active_attach_any, ability)),
        StackSpec("ability_attachment_then_tempo", core_stack + (tempo,)),
        StackSpec("tempo_then_ability_attachment", (tempo,) + core_stack),
        StackSpec("ability_active_attach_then_tempo", active_attach_core + (tempo,)),
        StackSpec("tempo_then_ability_active_attach", (tempo,) + active_attach_core),
    ]


def evaluate(args: argparse.Namespace) -> tuple[list[StackResult], dict[str, Any]]:
    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    ability_predicate = parse_ability_predicate(args.ability_predicate)
    ability_exceptions = tuple(parse_ability_predicate(raw) for raw in args.ability_exception)
    attachment_predicates = tuple(parse_attachment_predicate(raw) for raw in args.attachment_predicate)
    active_attachment_all = (parse_attachment_predicate("all"),)
    active_attachment_predicates = tuple(parse_attachment_predicate(raw) for raw in args.active_attachment_predicate)
    tempo_predicates = tuple(parse_attachment_predicate(raw) for raw in args.tempo_predicate)
    specs = stack_specs(attachment_predicates, active_attachment_all, active_attachment_predicates, tempo_predicates)
    results = [StackResult(spec=spec) for spec in specs]

    for row in rows:
        label = valid_single_label(row)
        lane = lanes[lane_key(row)]
        tier, _candidates = anchor_tier(lane, anchors, args.min_public_episodes, args.min_public_teams)
        lane_name = f"{lane.archetype}:{lane.deck_hash}"
        base_rank = ranked_options(weights, row) if label is not None else []
        for result in results:
            if label is None:
                update_stats(result.overall, None, [], [], False)
                continue
            stack_rank, fires, changes, _suppressed = apply_stack(
                row,
                label,
                base_rank,
                result.spec,
                ability_predicate,
                ability_exceptions,
            )
            fired = bool(fires)
            update_stats(result.overall, label, base_rank, stack_rank, fired)
            update_stats(result.tiers[tier], label, base_rank, stack_rank, fired)
            update_stats(result.lanes[lane_name], label, base_rank, stack_rank, fired)
            for key in args.holdout_key:
                if holdout_hit(row, key, args.holdout_mod, args.holdout_bucket):
                    update_stats(result.holdouts[key], label, base_rank, stack_rank, fired)
            result.step_fires.update(fires)
            result.step_changes.update(changes)
            if base_rank and stack_rank and base_rank[0] != stack_rank[0]:
                options = row.get("options") or []
                public = options[label] if label < len(options) else str(label)
                before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
                after = options[stack_rank[0]] if stack_rank[0] < len(options) else str(stack_rank[0])
                if stack_rank[0] == label and base_rank[0] != label:
                    outcome = "fix"
                elif base_rank[0] == label and stack_rank[0] != label:
                    outcome = "regress"
                else:
                    outcome = "neutral"
                result.changes[f"{outcome}: public={public} | base={before} | stack={after}"] += 1

    meta = {
        "rows": len(rows),
        "ability_predicate": ability_predicate.name,
        "ability_exceptions": [predicate.name for predicate in ability_exceptions],
        "attachment_predicates": [predicate.name for predicate in attachment_predicates],
        "active_attachment_predicates": [predicate.name for predicate in active_attachment_predicates],
        "tempo_predicates": [predicate.name for predicate in tempo_predicates],
    }
    return results, meta


def stats_row(name: str, stats: EvalStats, ref: EvalStats | None = None) -> str:
    ref_delta = "-"
    if ref is not None and stats.total and ref.total:
        ref_delta = f"{stats.stack_top1 - ref.stack_top1:+d}"
    return (
        f"| {code(name)} | {stats.total} | {fmt_ratio(stats.base_top1, stats.total)} | "
        f"{fmt_ratio(stats.stack_top1, stats.total)} | {stats.top1_delta:+d} | {ref_delta} | "
        f"{fmt_ratio(stats.base_top3, stats.total)} | {fmt_ratio(stats.stack_top3, stats.total)} | "
        f"{stats.fired} | {stats.changed} | {stats.fixes} | {stats.regressions} |"
    )


def sort_stats(items: dict[str, EvalStats]) -> list[tuple[str, EvalStats]]:
    return sorted(items.items(), key=lambda item: (-item[1].fired, item[1].top1_delta, item[0]))


def result_by_name(results: list[StackResult]) -> dict[str, StackResult]:
    return {result.spec.name: result for result in results}


def decision(
    result: StackResult,
    reference: StackResult | None,
    core_reference: StackResult | None,
    args: argparse.Namespace,
) -> tuple[str, list[str]]:
    if result.spec.name == "base_ranker":
        return "baseline", ["Base action ranker only."]
    notes: list[str] = []
    if result.overall.fired < args.min_fires:
        notes.append("too few fires")
    if result.overall.top1_delta < 0:
        notes.append("overall top-1 delta negative")
    if result.overall.net_fixes < 0:
        notes.append("overall fixes-regressions negative")
    if reference is not None and result.spec.name.startswith("ability_then") and result.overall.stack_top1 < reference.overall.stack_top1:
        notes.append("stack underperforms ability-only reference")
    if "tempo" in result.spec.name and core_reference is not None and result.spec.name != "tempo_play_over_attack":
        if result.overall.stack_top1 < core_reference.overall.stack_top1:
            notes.append("tempo stack underperforms accepted ability+attachment reference")
    for key, stats in result.holdouts.items():
        if stats.fired >= args.min_gated_fires and stats.top1_delta < 0:
            notes.append(f"holdout {key} negative")
    for tier, stats in result.tiers.items():
        if tier in PUBLIC_SUPPORTED_TIERS and stats.fired >= args.min_gated_fires and stats.top1_delta < 0:
            notes.append(f"public tier {tier} negative")
    if notes:
        return "research-only", notes
    return "offline-stack-accepted", [
        "non-negative overall, deterministic holdouts, and supported public tiers",
        "still blocked from package promotion by public-score backtest gates",
    ]


def render(args: argparse.Namespace, results: list[StackResult], meta: dict[str, Any]) -> str:
    by_name = result_by_name(results)
    ability_reference = by_name.get("ability_stable")
    core_reference = by_name.get("ability_then_attachment_mined_any")
    lines: list[str] = [
        "# Strategy Feature Stack Evaluation",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Process metadata: pid={os.getpid()} user={os.getenv('USER', 'unknown')}",
        "- Runtime premise: deterministic offline public-action imitation only; no local full-game promotion and no live submission.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Anchor status: `{args.anchor_status}`",
        f"- Rows loaded: {meta['rows']}",
        f"- Ability predicate: `{meta['ability_predicate']}`",
        "- Ability exceptions:",
    ]
    for item in meta["ability_exceptions"]:
        lines.append(f"  - `{item}`")
    lines.append("- Attachment predicates:")
    for item in meta["attachment_predicates"]:
        lines.append(f"  - `{item}`")
    lines.append("- Active-attachment-over-bench predicates:")
    for item in meta["active_attachment_predicates"]:
        lines.append(f"  - `{item}`")
    lines.append("- Tempo predicates:")
    for item in meta["tempo_predicates"]:
        lines.append(f"  - `{item}`")
    lines.extend(
        [
            "",
            "## Summary",
            "",
            "| Stack | N | Base Top-1 | Stack Top-1 | Delta | Vs Ability-Only | Base Top-3 | Stack Top-3 | Fires | Changes | Fixes | Regressions |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in results:
        reference = (
            ability_reference.overall
            if ability_reference is not None and result.spec.name not in {"base_ranker", "ability_stable"}
            else None
        )
        lines.append(stats_row(result.spec.name, result.overall, reference))

    lines.extend(
        [
            "",
            "## Holdout Minimums",
            "",
            "| Stack | Worst Holdout Delta | Holdout Deltas |",
            "| --- | ---: | --- |",
        ]
    )
    for result in results:
        deltas = {key: stats.top1_delta for key, stats in result.holdouts.items()}
        worst = min(deltas.values()) if deltas else 0
        detail = ", ".join(f"{key}={value:+d}" for key, value in sorted(deltas.items()))
        lines.append(f"| {code(result.spec.name)} | {worst:+d} | {detail} |")

    lines.extend(
        [
            "",
            "## Public-Anchor Tier Deltas",
            "",
            "| Stack / Tier | N | Base Top-1 | Stack Top-1 | Delta | Vs Ability-Only | Base Top-3 | Stack Top-3 | Fires | Changes | Fixes | Regressions |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in results:
        reference_result = (
            ability_reference
            if ability_reference is not None and result.spec.name not in {"base_ranker", "ability_stable"}
            else None
        )
        for tier, stats in sort_stats(result.tiers):
            reference_stats = reference_result.tiers.get(tier) if reference_result is not None else None
            lines.append(stats_row(f"{result.spec.name} / {tier}", stats, reference_stats))

    for result in results:
        verdict, notes = decision(result, ability_reference, core_reference, args)
        lines.extend(["", f"## Stack Detail: `{result.spec.name}`", "", f"- Decision: `{verdict}`"])
        for note in notes:
            lines.append(f"- {note}")
        if result.step_fires:
            lines.append("- Step fires:")
            for name, count in result.step_fires.most_common():
                lines.append(f"  - `{name}`: {count}")
        if result.step_changes:
            lines.append("- Step changes:")
            for name, count in result.step_changes.most_common():
                lines.append(f"  - `{name}`: {count}")
        lines.append("- Top fired lanes:")
        lane_count = 0
        for lane, stats in sort_stats(result.lanes):
            if not stats.fired:
                continue
            lane_count += 1
            lines.append(
                f"  - `{lane}` N={stats.total} fires={stats.fired} top1 "
                f"{fmt_ratio(stats.base_top1, stats.total)} -> {fmt_ratio(stats.stack_top1, stats.total)} "
                f"delta={stats.top1_delta:+d} fixes={stats.fixes} regressions={stats.regressions}"
            )
            if lane_count >= args.limit:
                break
        if lane_count == 0:
            lines.append("  - none")
        lines.append("- Largest changes:")
        for text, count in result.changes.most_common(args.limit):
            lines.append(f"  - {count}: {text}")
        if not result.changes:
            lines.append("  - none")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `offline-stack-accepted` means the feature stack may remain in behavior-cloning, value-model, or RL curriculum experiments.",
            "- It does not make an agent package submit-safe.",
            "- Any runtime implementation still needs public-anchor eligibility and a trusted public-score backtest metric.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: list[StackResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "stack",
        "scope",
        "name",
        "total",
        "base_top1",
        "stack_top1",
        "top1_delta",
        "base_top3",
        "stack_top3",
        "top3_delta",
        "fires",
        "changes",
        "fixes",
        "regressions",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            buckets: list[tuple[str, str, EvalStats]] = [("overall", "all", result.overall)]
            buckets.extend(("holdout", key, stats) for key, stats in result.holdouts.items())
            buckets.extend(("tier", key, stats) for key, stats in result.tiers.items())
            buckets.extend(("lane", key, stats) for key, stats in result.lanes.items() if stats.fired)
            for scope, name, stats in buckets:
                writer.writerow(
                    {
                        "stack": result.spec.name,
                        "scope": scope,
                        "name": name,
                        "total": stats.total,
                        "base_top1": f"{stats.base_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        "stack_top1": f"{stats.stack_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        "top1_delta": stats.top1_delta,
                        "base_top3": f"{stats.base_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        "stack_top3": f"{stats.stack_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        "top3_delta": stats.top3_delta,
                        "fires": stats.fired,
                        "changes": stats.changed,
                        "fixes": stats.fixes,
                        "regressions": stats.regressions,
                    }
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor-status", type=Path, required=True)
    parser.add_argument("--ability-predicate", default="all")
    parser.add_argument("--ability-exception", action="append", default=[])
    parser.add_argument("--attachment-predicate", action="append", default=[])
    parser.add_argument("--active-attachment-predicate", action="append", default=[])
    parser.add_argument("--tempo-predicate", action="append", default=[])
    parser.add_argument("--holdout-key", action="append", default=[])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-fires", type=int, default=25)
    parser.add_argument("--min-gated-fires", type=int, default=10)
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/strategy_feature_stack.md"))
    parser.add_argument("--csv-out", type=Path, default=Path("strategy/strategy_feature_stack.csv"))
    args = parser.parse_args()

    if not args.ability_exception:
        args.ability_exception = list(DEFAULT_ABILITY_EXCEPTIONS)
    if not args.attachment_predicate:
        args.attachment_predicate = list(DEFAULT_ATTACHMENT_PREDICATES)
    if not args.active_attachment_predicate:
        args.active_attachment_predicate = list(DEFAULT_ACTIVE_ATTACHMENT_PREDICATES)
    if not args.tempo_predicate:
        args.tempo_predicate = list(DEFAULT_TEMPO_PREDICATES)
    if not args.holdout_key:
        args.holdout_key = list(DEFAULT_HOLDOUT_KEYS)

    results, meta = evaluate(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, results, meta), encoding="utf-8")
    write_csv(args.csv_out, results)
    print(f"rows={meta['rows']} stacks={len(results)} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
