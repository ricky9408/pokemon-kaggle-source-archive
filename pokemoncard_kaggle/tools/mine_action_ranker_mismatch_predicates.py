#!/usr/bin/env python3
"""Mine public-action mismatch overlays from an action-ranker baseline.

This is an offline public-anchor analysis tool.  It looks for cases where the
behavior-cloning action ranker puts the wrong legal option first, then tests
tiny pattern overlays such as "rank public RETREAT above model END" under
simple state predicates.  The output is evidence for future policy work, not a
submit selector.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_action_ranker import load_rows, option_parts, pct, ranked_options, stable_bucket, valid_single_label  # noqa: E402


CARD_RE = re.compile(r"\((\d+)\)")


@dataclass(frozen=True)
class Pattern:
    mode: str
    type_name: str
    card: str = "*"
    attack: str = "*"
    to_area: str = "*"

    @property
    def key(self) -> str:
        return f"{self.mode}:{self.type_name}:card={self.card}:attack={self.attack}:to={self.to_area}"


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[dict[str, str]], bool]


@dataclass
class Stats:
    total: int = 0
    skipped: int = 0
    base_top1: int = 0
    overlay_top1: int = 0
    base_top3: int = 0
    overlay_top3: int = 0
    eligible: int = 0
    fired: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0

    @property
    def top1_delta(self) -> int:
        return self.overlay_top1 - self.base_top1

    @property
    def net(self) -> int:
        return self.fixes - self.regressions


@dataclass
class Result:
    boundary: str
    public_pattern: Pattern
    model_pattern: Pattern
    predicate: str
    stats: Stats
    holdout_min_delta: int
    holdout_negative_groups: int
    examples: Counter[str]


@dataclass
class PreparedRow:
    row: dict[str, Any]
    label: int
    options: list[str]
    base_rank: list[int]
    features: dict[str, str]
    holdout: dict[str, bool]


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def state(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("state")
    return value if isinstance(value, dict) else {}


def side(row: dict[str, Any], name: str) -> dict[str, Any]:
    value = state(row).get(name)
    return value if isinstance(value, dict) else {}


def bucket(value: Any, size: int, cap: int) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, number // size))


def card_id(text: str) -> str:
    match = CARD_RE.search(text)
    return match.group(1) if match else "*"


def pattern_for(option: str, mode: str) -> Pattern:
    parts = option_parts(option)
    type_name = parts["type"] or "UNKNOWN"
    if mode == "type":
        return Pattern(mode, type_name)
    if mode == "target" and type_name == "ATTACH":
        return Pattern(mode, type_name, to_area=parts["to_area"] or "*")
    if mode == "card":
        if type_name in {"PLAY", "ABILITY", "ATTACH"}:
            return Pattern(mode, type_name, card=parts["card"] or card_id(option))
        if type_name == "ATTACK":
            return Pattern(mode, type_name, attack=parts["attack"] or "*")
        return Pattern(mode, type_name)
    if type_name == "ATTACH":
        return Pattern(mode, type_name, card=parts["card"] or card_id(option), to_area=parts["to_area"] or "*")
    if type_name in {"PLAY", "ABILITY"}:
        return Pattern(mode, type_name, card=parts["card"] or card_id(option))
    if type_name == "ATTACK":
        return Pattern(mode, type_name, attack=parts["attack"] or "*")
    return Pattern(mode, type_name)


def pattern_matches(pattern: Pattern, option: str) -> bool:
    observed = pattern_for(option, pattern.mode)
    return (
        observed.type_name == pattern.type_name
        and (pattern.card == "*" or observed.card == pattern.card)
        and (pattern.attack == "*" or observed.attack == pattern.attack)
        and (pattern.to_area == "*" or observed.to_area == pattern.to_area)
    )


def feature_map(row: dict[str, Any], options: list[str], base_top: int | None, public_index: int | None) -> dict[str, str]:
    me = side(row, "me")
    opp = side(row, "opponent")
    row_state = state(row)
    base_text = options[base_top] if base_top is not None and 0 <= base_top < len(options) else ""
    public_text = options[public_index] if public_index is not None and 0 <= public_index < len(options) else ""
    return {
        "context": row_value(row, "context"),
        "archetype": row_value(row, "archetype"),
        "deck_hash": row_value(row, "deck_hash"),
        "opponent": row_value(row, "opponent_archetype"),
        "opponent_deck_hash": row_value(row, "opponent_deck_hash"),
        "team": row_value(row, "team"),
        "opponent_team": row_value(row, "opponent_team"),
        "active": str(me.get("active", "unknown")),
        "opp_active": str(opp.get("active", "unknown")),
        "bench": str(me.get("bench_count", "unknown")),
        "opp_bench": str(opp.get("bench_count", "unknown")),
        "hand": str(me.get("hand_count", "unknown")),
        "opp_hand": str(opp.get("hand_count", "unknown")),
        "bench_bucket": bucket(me.get("bench_count"), 2, 3),
        "opp_bench_bucket": bucket(opp.get("bench_count"), 2, 3),
        "hand_bucket": bucket(me.get("hand_count"), 3, 6),
        "opp_hand_bucket": bucket(opp.get("hand_count"), 3, 6),
        "turn": str(row_state.get("turn", "unknown")),
        "turn_bucket": bucket(row_state.get("turn"), 3, 6),
        "turn_action": str(row_state.get("turn_action_count", "unknown")),
        "turn_action_bucket": bucket(row_state.get("turn_action_count"), 3, 6),
        "energy_attached": str(row_state.get("energy_attached", "unknown")),
        "supporter_played": str(row_state.get("supporter_played", "unknown")),
        "stadium_played": str(row_state.get("stadium_played", "unknown")),
        "base_type": pattern_for(base_text, "type").type_name if base_text else "none",
        "public_type": pattern_for(public_text, "type").type_name if public_text else "none",
        "base_card": card_id(base_text) if base_text else "none",
        "public_card": card_id(public_text) if public_text else "none",
        "base_target": option_parts(base_text).get("to_area") or "none" if base_text else "none",
        "public_target": option_parts(public_text).get("to_area") or "none" if public_text else "none",
        "legal_play_count": str(sum(1 for option in options if option_parts(option)["type"] == "PLAY")),
        "legal_attach_count": str(sum(1 for option in options if option_parts(option)["type"] == "ATTACH")),
        "legal_attack_count": str(sum(1 for option in options if option_parts(option)["type"] == "ATTACK")),
        "option_count_bucket": bucket(len(options), 4, 6),
    }


def predicate_candidates(rows: list[dict[str, Any]], weights: dict[str, float], sample_limit: int) -> list[Predicate]:
    values: dict[str, Counter[str]] = defaultdict(Counter)
    sampled = 0
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            continue
        ranking = ranked_options(weights, row)
        if not ranking:
            continue
        options = [str(option) for option in row.get("options") or []]
        feats = feature_map(row, options, ranking[0], label)
        for key, value in feats.items():
            if key in {"team", "opponent_team"}:
                continue
            values[key][value] += 1
        sampled += 1
        if sampled >= sample_limit:
            break

    predicates = [Predicate("all", lambda _features: True)]
    useful_keys = [
        "archetype",
        "deck_hash",
        "opponent",
        "opponent_deck_hash",
        "active",
        "opp_active",
        "bench_bucket",
        "opp_bench_bucket",
        "hand_bucket",
        "opp_hand_bucket",
        "turn_bucket",
        "turn_action_bucket",
        "energy_attached",
        "supporter_played",
        "stadium_played",
        "base_type",
        "base_card",
        "base_target",
        "option_count_bucket",
    ]
    for key in useful_keys:
        for value, count in values[key].most_common(12):
            if value in {"unknown", "none", ""} or count < 5:
                continue
            name = f"{key}={value}"
            predicates.append(Predicate(name, lambda features, k=key, v=value: features.get(k) == v))

    combo_specs = [
        ("archetype", "deck_hash"),
        ("archetype", "opponent"),
        ("active", "turn_bucket"),
        ("archetype", "turn_bucket"),
        ("energy_attached", "turn_action_bucket"),
    ]
    combo_counts: Counter[tuple[str, str, str, str]] = Counter()
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            continue
        ranking = ranked_options(weights, row)
        if not ranking:
            continue
        options = [str(option) for option in row.get("options") or []]
        feats = feature_map(row, options, ranking[0], label)
        for left, right in combo_specs:
            combo_counts[(left, feats.get(left, ""), right, feats.get(right, ""))] += 1
    for (left, left_value, right, right_value), count in combo_counts.most_common(80):
        if count < 8 or left_value in {"unknown", "none", ""} or right_value in {"unknown", "none", ""}:
            continue
        name = f"{left}={left_value} & {right}={right_value}"
        predicates.append(
            Predicate(
                name,
                lambda features, l=left, lv=left_value, r=right, rv=right_value: features.get(l) == lv and features.get(r) == rv,
            )
        )
    return predicates


def prepare_rows(rows: list[dict[str, Any]], weights: dict[str, float], args: argparse.Namespace) -> list[PreparedRow]:
    prepared: list[PreparedRow] = []
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            continue
        base_rank = ranked_options(weights, row)
        options = [str(option) for option in row.get("options") or []]
        if not base_rank or label >= len(options):
            continue
        features = feature_map(row, options, base_rank[0], label)
        holdout = {
            key: stable_bucket(row_value(row, key), args.holdout_mod) == args.holdout_bucket
            for key in args.holdout_key
        }
        prepared.append(PreparedRow(row=row, label=label, options=options, base_rank=base_rank, features=features, holdout=holdout))
    return prepared


def predicate_candidates_from_prepared(prepared: list[PreparedRow]) -> list[Predicate]:
    values: dict[str, Counter[str]] = defaultdict(Counter)
    for item in prepared:
        for key, value in item.features.items():
            if key in {"team", "opponent_team"}:
                continue
            values[key][value] += 1

    predicates = [Predicate("all", lambda _features: True)]
    useful_keys = [
        "archetype",
        "deck_hash",
        "opponent",
        "opponent_deck_hash",
        "active",
        "opp_active",
        "bench_bucket",
        "opp_bench_bucket",
        "hand_bucket",
        "opp_hand_bucket",
        "turn_bucket",
        "turn_action_bucket",
        "energy_attached",
        "supporter_played",
        "stadium_played",
        "base_type",
        "base_card",
        "base_target",
        "option_count_bucket",
    ]
    for key in useful_keys:
        for value, count in values[key].most_common(12):
            if value in {"unknown", "none", ""} or count < 5:
                continue
            name = f"{key}={value}"
            predicates.append(Predicate(name, lambda features, k=key, v=value: features.get(k) == v))

    combo_specs = [
        ("archetype", "deck_hash"),
        ("archetype", "opponent"),
        ("active", "turn_bucket"),
        ("archetype", "turn_bucket"),
        ("energy_attached", "turn_action_bucket"),
    ]
    combo_counts: Counter[tuple[str, str, str, str]] = Counter()
    for item in prepared:
        feats = item.features
        for left, right in combo_specs:
            combo_counts[(left, feats.get(left, ""), right, feats.get(right, ""))] += 1
    for (left, left_value, right, right_value), count in combo_counts.most_common(80):
        if count < 8 or left_value in {"unknown", "none", ""} or right_value in {"unknown", "none", ""}:
            continue
        name = f"{left}={left_value} & {right}={right_value}"
        predicates.append(
            Predicate(
                name,
                lambda features, l=left, lv=left_value, r=right, rv=right_value: features.get(l) == lv and features.get(r) == rv,
            )
        )
    return predicates


def boundary_key(public_pattern: Pattern, model_pattern: Pattern) -> str:
    return f"public={public_pattern.key} | model={model_pattern.key}"


def discover_boundaries_from_prepared(prepared: list[PreparedRow], args: argparse.Namespace) -> list[tuple[Pattern, Pattern, int]]:
    counts: Counter[tuple[Pattern, Pattern]] = Counter()
    for item in prepared:
        if item.base_rank[0] == item.label:
            continue
        for mode in args.pattern_mode:
            public_pattern = pattern_for(item.options[item.label], mode)
            model_pattern = pattern_for(item.options[item.base_rank[0]], mode)
            if public_pattern == model_pattern:
                continue
            counts[(public_pattern, model_pattern)] += 1
    return [(public, model, count) for (public, model), count in counts.most_common(args.boundary_limit)]


def discover_boundaries(rows: list[dict[str, Any]], weights: dict[str, float], args: argparse.Namespace) -> list[tuple[Pattern, Pattern, int]]:
    counts: Counter[tuple[Pattern, Pattern]] = Counter()
    modes = args.pattern_mode
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            continue
        ranking = ranked_options(weights, row)
        if not ranking or ranking[0] == label:
            continue
        options = [str(option) for option in row.get("options") or []]
        if label >= len(options) or ranking[0] >= len(options):
            continue
        for mode in modes:
            public_pattern = pattern_for(options[label], mode)
            model_pattern = pattern_for(options[ranking[0]], mode)
            if public_pattern == model_pattern:
                continue
            counts[(public_pattern, model_pattern)] += 1
    return [(public, model, count) for (public, model), count in counts.most_common(args.boundary_limit)]


def promoted_rank(base_rank: list[int], options: list[str], public_pattern: Pattern, model_pattern: Pattern) -> tuple[list[int], bool]:
    if not base_rank or not pattern_matches(model_pattern, options[base_rank[0]]):
        return base_rank, False
    promotable = [index for index in base_rank if pattern_matches(public_pattern, options[index])]
    if not promotable:
        return base_rank, False
    promoted = promotable[0]
    if promoted == base_rank[0]:
        return base_rank, False
    return [promoted] + [index for index in base_rank if index != promoted], True


def update(stats: Stats, label: int | None, base_rank: list[int], overlay_rank: list[int], eligible: bool, fired: bool) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.eligible += int(eligible)
    stats.fired += int(fired)
    base_hit = bool(base_rank and base_rank[0] == label)
    overlay_hit = bool(overlay_rank and overlay_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.overlay_top1 += int(overlay_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.overlay_top3 += int(label in overlay_rank[:3])
    changed = bool(base_rank and overlay_rank and base_rank[0] != overlay_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and overlay_hit)
    stats.regressions += int(changed and base_hit and not overlay_hit)
    stats.neutral_changes += int(changed and base_hit == overlay_hit)


def base_stats(prepared: list[PreparedRow]) -> Stats:
    stats = Stats()
    for item in prepared:
        stats.total += 1
        stats.base_top1 += int(item.base_rank[0] == item.label)
        stats.overlay_top1 += int(item.base_rank[0] == item.label)
        stats.base_top3 += int(item.label in item.base_rank[:3])
        stats.overlay_top3 += int(item.label in item.base_rank[:3])
    return stats


def eligible_for_boundary(prepared: list[PreparedRow], public_pattern: Pattern, model_pattern: Pattern) -> list[PreparedRow]:
    return [
        item
        for item in prepared
        if pattern_matches(model_pattern, item.options[item.base_rank[0]])
        and any(pattern_matches(public_pattern, option) for option in item.options)
    ]


def evaluate_overlay(
    rows: list[dict[str, Any]],
    weights: dict[str, float],
    public_pattern: Pattern,
    model_pattern: Pattern,
    predicate: Predicate,
    args: argparse.Namespace,
) -> Result:
    stats = Stats()
    holdouts: dict[str, Stats] = defaultdict(Stats)
    examples: Counter[str] = Counter()
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            update(stats, None, [], [], False, False)
            continue
        base_rank = ranked_options(weights, row)
        options = [str(option) for option in row.get("options") or []]
        eligible = bool(base_rank and pattern_matches(model_pattern, options[base_rank[0]]) and any(pattern_matches(public_pattern, option) for option in options))
        fired = False
        overlay_rank = base_rank
        if eligible:
            feats = feature_map(row, options, base_rank[0], label)
            fired = predicate.fn(feats)
            if fired:
                overlay_rank, _changed = promoted_rank(base_rank, options, public_pattern, model_pattern)
        update(stats, label, base_rank, overlay_rank, eligible, fired)
        for key in args.holdout_key:
            if stable_bucket(row_value(row, key), args.holdout_mod) == args.holdout_bucket:
                update(holdouts[key], label, base_rank, overlay_rank, eligible, fired)
        if fired and base_rank and overlay_rank and base_rank[0] != overlay_rank[0]:
            selected = options[label] if label < len(options) else str(label)
            before = options[base_rank[0]]
            after = options[overlay_rank[0]]
            if overlay_rank[0] == label and base_rank[0] != label:
                outcome = "fix"
            elif base_rank[0] == label and overlay_rank[0] != label:
                outcome = "regress"
            else:
                outcome = "neutral"
            examples[f"{outcome}: public={selected} | base={before} | overlay={after}"] += 1
    holdout_deltas = [bucket.top1_delta for bucket in holdouts.values()]
    return Result(
        boundary=boundary_key(public_pattern, model_pattern),
        public_pattern=public_pattern,
        model_pattern=model_pattern,
        predicate=predicate.name,
        stats=stats,
        holdout_min_delta=min(holdout_deltas) if holdout_deltas else 0,
        holdout_negative_groups=sum(1 for value in holdout_deltas if value < 0),
        examples=examples,
    )


def evaluate_overlay_prepared(
    eligible_items: list[PreparedRow],
    baseline: Stats,
    public_pattern: Pattern,
    model_pattern: Pattern,
    predicate: Predicate,
) -> Result:
    stats = Stats(
        total=baseline.total,
        skipped=baseline.skipped,
        base_top1=baseline.base_top1,
        overlay_top1=baseline.overlay_top1,
        base_top3=baseline.base_top3,
        overlay_top3=baseline.overlay_top3,
    )
    holdout_deltas: Counter[str] = Counter()
    examples: Counter[str] = Counter()
    for item in eligible_items:
        stats.eligible += 1
        if not predicate.fn(item.features):
            continue
        stats.fired += 1
        overlay_rank = item.base_rank
        overlay_rank, _changed = promoted_rank(item.base_rank, item.options, public_pattern, model_pattern)
        changed = bool(item.base_rank and overlay_rank and item.base_rank[0] != overlay_rank[0])
        if not changed:
            continue
        stats.changed += 1
        base_hit = item.base_rank[0] == item.label
        overlay_hit = overlay_rank[0] == item.label
        base_top3 = item.label in item.base_rank[:3]
        overlay_top3 = item.label in overlay_rank[:3]
        stats.overlay_top1 += int(overlay_hit) - int(base_hit)
        stats.overlay_top3 += int(overlay_top3) - int(base_top3)
        stats.fixes += int(not base_hit and overlay_hit)
        stats.regressions += int(base_hit and not overlay_hit)
        stats.neutral_changes += int(base_hit == overlay_hit)
        delta = int(overlay_hit) - int(base_hit)
        for key, is_holdout in item.holdout.items():
            if is_holdout:
                holdout_deltas[key] += delta
        if changed:
            selected = item.options[item.label] if item.label < len(item.options) else str(item.label)
            before = item.options[item.base_rank[0]]
            after = item.options[overlay_rank[0]]
            if overlay_rank[0] == item.label and item.base_rank[0] != item.label:
                outcome = "fix"
            elif item.base_rank[0] == item.label and overlay_rank[0] != item.label:
                outcome = "regress"
            else:
                outcome = "neutral"
            examples[f"{outcome}: public={selected} | base={before} | overlay={after}"] += 1
    return Result(
        boundary=boundary_key(public_pattern, model_pattern),
        public_pattern=public_pattern,
        model_pattern=model_pattern,
        predicate=predicate.name,
        stats=stats,
        holdout_min_delta=min(holdout_deltas.values()) if holdout_deltas else 0,
        holdout_negative_groups=sum(1 for value in holdout_deltas.values() if value < 0),
        examples=examples,
    )


def result_sort_key(result: Result) -> tuple[int, int, int, int, int]:
    return (
        result.stats.net,
        result.stats.top1_delta,
        -result.holdout_negative_groups,
        result.holdout_min_delta,
        result.stats.fixes,
    )


def stats_row(result: Result) -> list[Any]:
    stats = result.stats
    return [
        result.boundary,
        result.predicate,
        stats.total,
        pct(stats.base_top1, stats.total),
        pct(stats.overlay_top1, stats.total),
        stats.top1_delta,
        stats.eligible,
        stats.fired,
        stats.changed,
        stats.fixes,
        stats.regressions,
        stats.neutral_changes,
        stats.net,
        result.holdout_min_delta,
        result.holdout_negative_groups,
    ]


def write_csv(path: Path, results: list[Result]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "boundary",
                "predicate",
                "n",
                "base_top1",
                "overlay_top1",
                "top1_delta",
                "eligible",
                "fired",
                "changed",
                "fixes",
                "regressions",
                "neutral_changes",
                "net",
                "holdout_min_delta",
                "holdout_negative_groups",
            ]
        )
        for result in results:
            writer.writerow(stats_row(result))


def render_report(args: argparse.Namespace, boundaries: list[tuple[Pattern, Pattern, int]], results: list[Result]) -> str:
    lines = [
        "# Action-Ranker Mismatch Predicate Mining",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Model: `{args.model}`",
        f"- Pattern modes: `{', '.join(args.pattern_mode)}`",
        f"- Holdout keys: `{', '.join(args.holdout_key)}`",
        "",
        "## Top Discovered Boundaries",
        "",
        "| Count | Boundary |",
        "| ---: | --- |",
    ]
    for public_pattern, model_pattern, count in boundaries[: args.report_limit]:
        lines.append(f"| {count} | `{boundary_key(public_pattern, model_pattern)}` |")
    lines.extend(
        [
            "",
            "## Best Overlay Predicates",
            "",
            "| Boundary | Predicate | N | Base Top-1 | Overlay Top-1 | ΔTop1 | Eligible | Fired | Changed | Fixes | Regressions | Neutral | Net | Holdout Min Δ | Negative Holdouts |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in results[: args.report_limit]:
        row = stats_row(result)
        lines.append(
            "| "
            + " | ".join(f"`{cell}`" if i < 2 else str(cell) for i, cell in enumerate(row))
            + " |"
        )
    lines.extend(["", "## Example Changes", ""])
    for result in results[: min(8, args.report_limit)]:
        lines.append(f"### `{result.boundary}` / `{result.predicate}`")
        lines.append("")
        for text, count in result.examples.most_common(8):
            lines.append(f"- {count}: {text}")
        lines.append("")
    lines.extend(
        [
            "## Interpretation",
            "",
            "- A positive row here is a public-action imitation hypothesis, not package evidence.",
            "- Prefer predicates with positive net fixes, non-negative holdout deltas, and broad enough fired counts to survive the next current-window refresh.",
            "- Team-specific predicates are intentionally excluded from the mined set to reduce opponent memorization risk.",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--csv-out", type=Path, required=True)
    parser.add_argument("--pattern-mode", action="append", default=["exact", "card", "target", "type"])
    parser.add_argument("--boundary-limit", type=int, default=60)
    parser.add_argument("--predicate-sample-limit", type=int, default=5000)
    parser.add_argument("--min-fired", type=int, default=5)
    parser.add_argument("--holdout-key", action="append", default=["team", "opponent_team", "episode_id", "source"])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--report-limit", type=int, default=24)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    prepared = prepare_rows(rows, weights, args)
    baseline = base_stats(prepared)
    boundaries = discover_boundaries_from_prepared(prepared, args)
    predicates = predicate_candidates_from_prepared(prepared[: args.predicate_sample_limit])
    results: list[Result] = []
    for public_pattern, model_pattern, _count in boundaries:
        eligible_items = eligible_for_boundary(prepared, public_pattern, model_pattern)
        if not eligible_items:
            continue
        for predicate in predicates:
            result = evaluate_overlay_prepared(eligible_items, baseline, public_pattern, model_pattern, predicate)
            if result.stats.fired >= args.min_fired and result.stats.changed:
                results.append(result)
    results.sort(key=result_sort_key, reverse=True)

    write_csv(args.csv_out, results)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, boundaries, results), encoding="utf-8")
    best = results[0] if results else None
    if best is None:
        print(f"boundaries={len(boundaries)} predicates={len(predicates)} results=0 report={args.report_out}")
    else:
        print(
            "boundaries={b} predicates={p} results={r} best_net={net} best_delta={delta} "
            "best='{boundary}' predicate='{predicate}' report={report}".format(
                b=len(boundaries),
                p=len(predicates),
                r=len(results),
                net=best.stats.net,
                delta=best.stats.top1_delta,
                boundary=best.boundary,
                predicate=best.predicate,
                report=args.report_out,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
