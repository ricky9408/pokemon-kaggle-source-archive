#!/usr/bin/env python3
"""Evaluate attach-now vs play/search-first timing overlays.

This is an offline public-action imitation probe for the top curriculum item in
``public_anchor_curriculum``. It tests a tiny runtime-shaped overlay:

* when the base action ranker prefers an active attachment,
* and a PLAY action is legal,
* optionally under a row predicate,
* rank the best base-ranked PLAY action above that active attachment.

It does not submit and it does not use the local full-game simulator as a
promotion signal.
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
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_anchor_policy_targets import anchor_tier, build_lanes, load_anchor_status  # noqa: E402
from train_action_ranker import load_rows, option_parts, pct, ranked_options, stable_bucket, valid_single_label  # noqa: E402


DEFAULT_PREDICATES = [
    "all",
    "archetype=hops-trevenant & deck_hash=88c7104a02",
    "archetype=hops-trevenant",
]

DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]


@dataclass
class EvalStats:
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
    def net_fixes(self) -> int:
        return self.fixes - self.regressions


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[dict[str, str]], bool]


@dataclass
class PredicateResult:
    predicate: Predicate
    overall: EvalStats = field(default_factory=EvalStats)
    holdouts: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    tiers: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    lanes: dict[str, EvalStats] = field(default_factory=lambda: defaultdict(EvalStats))
    changes: Counter[str] = field(default_factory=Counter)


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def state(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("state")
    return value if isinstance(value, dict) else {}


def state_side(row: dict[str, Any], side: str) -> dict[str, Any]:
    value = state(row).get(side)
    return value if isinstance(value, dict) else {}


def bucket_num(value: Any, size: int, cap: int) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, number // size))


def option_card(options: list[str], index: int | None) -> str:
    if index is None or not 0 <= index < len(options):
        return "none"
    return option_parts(options[index]).get("card") or "none"


def option_type(options: list[str], index: int | None) -> str:
    if index is None or not 0 <= index < len(options):
        return "none"
    return option_parts(options[index]).get("type") or "none"


def legal_type_count(options: list[str], type_name: str) -> int:
    return sum(1 for option in options if option_parts(option)["type"] == type_name)


def feature_map(
    row: dict[str, Any],
    options: list[str],
    base_top: int | None = None,
    overlay_top: int | None = None,
) -> dict[str, str]:
    me = state_side(row, "me")
    opponent = state_side(row, "opponent")
    row_state = state(row)
    return {
        "archetype": row_value(row, "archetype"),
        "deck_hash": row_value(row, "deck_hash"),
        "opponent": row_value(row, "opponent_archetype"),
        "opponent_deck_hash": row_value(row, "opponent_deck_hash"),
        "context": row_value(row, "context"),
        "active": str(me.get("active", "unknown")),
        "opp_active": str(opponent.get("active", "unknown")),
        "bench": str(me.get("bench_count", "unknown")),
        "opp_bench": str(opponent.get("bench_count", "unknown")),
        "hand": str(me.get("hand_count", "unknown")),
        "opp_hand": str(opponent.get("hand_count", "unknown")),
        "bench_bucket": bucket_num(me.get("bench_count"), 2, 3),
        "opp_bench_bucket": bucket_num(opponent.get("bench_count"), 2, 3),
        "hand_bucket": bucket_num(me.get("hand_count"), 3, 6),
        "opp_hand_bucket": bucket_num(opponent.get("hand_count"), 3, 6),
        "prizes": str(me.get("prize_count", "unknown")),
        "opp_prizes": str(opponent.get("prize_count", "unknown")),
        "turn": str(row_state.get("turn", "unknown")),
        "turn_action": str(row_state.get("turn_action_count", "unknown")),
        "turn_bucket": bucket_num(row_state.get("turn"), 3, 6),
        "turn_action_bucket": bucket_num(row_state.get("turn_action_count"), 3, 6),
        "energy_attached": str(row_state.get("energy_attached", "unknown")),
        "supporter_played": str(row_state.get("supporter_played", "unknown")),
        "stadium_played": str(row_state.get("stadium_played", "unknown")),
        "base_type": option_type(options, base_top),
        "overlay_type": option_type(options, overlay_top),
        "base_card": option_card(options, base_top),
        "overlay_card": option_card(options, overlay_top),
        "legal_play_count_bucket": bucket_num(legal_type_count(options, "PLAY"), 2, 5),
        "legal_attach_count_bucket": bucket_num(legal_type_count(options, "ATTACH"), 2, 5),
        "option_count_bucket": bucket_num(len(options), 4, 6),
    }


def compare_atom(actual: str, expected: str) -> bool:
    if "|" in expected:
        return any(compare_atom(actual, part.strip()) for part in expected.split("|"))
    if expected.startswith(">="):
        return to_float(actual) >= to_float(expected[2:].strip())
    if expected.startswith("<="):
        return to_float(actual) <= to_float(expected[2:].strip())
    if expected.startswith(">"):
        return to_float(actual) > to_float(expected[1:].strip())
    if expected.startswith("<"):
        return to_float(actual) < to_float(expected[1:].strip())
    return actual == expected


def to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("nan")


def parse_predicate(raw: str) -> Predicate:
    text = raw.strip()
    if not text or text == "all":
        return Predicate("all", lambda _features: True)
    parsed: list[tuple[str, str]] = []
    for atom in text.split("&"):
        atom = atom.strip()
        if not atom:
            continue
        if "=" not in atom:
            raise ValueError(f"Predicate atom must be key=value: {atom!r}")
        key, value = atom.split("=", 1)
        parsed.append((key.strip(), value.strip()))
    return Predicate(text, lambda features, parts=tuple(parsed): all(compare_atom(features.get(key, ""), value) for key, value in parts))


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def active_attach_indices(options: list[str]) -> list[int]:
    return [
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ATTACH" and option_parts(text)["to_area"] == "ACTIVE"
    ]


def play_indices(options: list[str]) -> list[int]:
    return [index for index, text in enumerate(options) if option_parts(text)["type"] == "PLAY"]


def overlay_rank(row: dict[str, Any], weights: dict[str, float], predicate: Predicate) -> tuple[list[int], list[int], bool, bool]:
    base_rank = ranked_options(weights, row)
    if row_value(row, "context") != "MAIN" or not base_rank:
        return base_rank, base_rank, False, False
    options = [str(option) for option in (row.get("options") or [])]
    attach_active = set(active_attach_indices(options))
    plays = set(play_indices(options))
    if base_rank[0] not in attach_active or not plays:
        return base_rank, base_rank, False, False
    eligible = True
    best_play = next((index for index in base_rank if index in plays), None)
    if best_play is None:
        return base_rank, base_rank, eligible, False
    if not predicate.fn(feature_map(row, options, base_rank[0], best_play)):
        return base_rank, base_rank, eligible, False
    return base_rank, [best_play] + [index for index in base_rank if index != best_play], eligible, True


def update_stats(stats: EvalStats, label: int | None, base_rank: list[int], new_rank: list[int], eligible: bool, fired: bool) -> None:
    if label is None:
        stats.skipped += 1
        return
    stats.total += 1
    stats.eligible += int(eligible)
    stats.fired += int(fired)
    base_hit = bool(base_rank and base_rank[0] == label)
    new_hit = bool(new_rank and new_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.overlay_top1 += int(new_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.overlay_top3 += int(label in new_rank[:3])
    changed = bool(base_rank and new_rank and base_rank[0] != new_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and new_hit)
    stats.regressions += int(changed and base_hit and not new_hit)
    stats.neutral_changes += int(changed and base_hit == new_hit)


def holdout_hit(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def lane_key(row: dict[str, Any]) -> tuple[str, str]:
    return row_value(row, "archetype"), row_value(row, "deck_hash")


def evaluate(args: argparse.Namespace) -> tuple[list[PredicateResult], dict[str, Any]]:
    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    predicates = [parse_predicate(raw) for raw in args.predicate]
    results = [PredicateResult(predicate=predicate) for predicate in predicates]

    for row in rows:
        label = valid_single_label(row)
        lane = lanes[lane_key(row)]
        tier, _candidates = anchor_tier(lane, anchors, args.min_public_episodes, args.min_public_teams)
        lane_name = f"{lane.archetype}:{lane.deck_hash}"
        for result in results:
            if label is None:
                update_stats(result.overall, None, [], [], False, False)
                continue
            base_rank, new_rank, eligible, fired = overlay_rank(row, weights, result.predicate)
            update_stats(result.overall, label, base_rank, new_rank, eligible, fired)
            update_stats(result.tiers[tier], label, base_rank, new_rank, eligible, fired)
            update_stats(result.lanes[lane_name], label, base_rank, new_rank, eligible, fired)
            for key in args.holdout_key:
                if holdout_hit(row, key, args.holdout_mod, args.holdout_bucket):
                    update_stats(result.holdouts[key], label, base_rank, new_rank, eligible, fired)
            if fired and base_rank and new_rank and base_rank[0] != new_rank[0]:
                options = row.get("options") or []
                public = options[label] if label < len(options) else str(label)
                before = options[base_rank[0]] if base_rank[0] < len(options) else str(base_rank[0])
                after = options[new_rank[0]] if new_rank[0] < len(options) else str(new_rank[0])
                if new_rank[0] == label and base_rank[0] != label:
                    outcome = "fix"
                elif base_rank[0] == label and new_rank[0] != label:
                    outcome = "regress"
                else:
                    outcome = "neutral"
                result.changes[f"{outcome}: public={public} | base={before} | overlay={after}"] += 1

    meta = {
        "rows": len(rows),
        "predicates": [predicate.name for predicate in predicates],
    }
    return results, meta


def stats_row(name: str, stats: EvalStats) -> str:
    return (
        f"| `{name}` | {stats.total} | {pct(stats.base_top1, stats.total)} | {pct(stats.overlay_top1, stats.total)} | "
        f"{stats.top1_delta:+d} | {pct(stats.base_top3, stats.total)} | {pct(stats.overlay_top3, stats.total)} | "
        f"{stats.eligible} | {stats.fired} | {stats.changed} | {stats.fixes} | {stats.regressions} |"
    )


def sort_stats(items: dict[str, EvalStats]) -> list[tuple[str, EvalStats]]:
    return sorted(items.items(), key=lambda item: (-item[1].fired, item[1].top1_delta, item[0]))


def decision(result: PredicateResult, args: argparse.Namespace) -> tuple[str, list[str]]:
    notes: list[str] = []
    if result.overall.top1_delta < 0:
        notes.append("overall top-1 delta negative")
    if result.overall.net_fixes < 0:
        notes.append("overall fixes-regressions negative")
    for name, stats in result.holdouts.items():
        if stats.fired >= args.min_gated_fires and stats.top1_delta < 0:
            notes.append(f"holdout {name} negative")
    for name, stats in result.tiers.items():
        if name in PUBLIC_SUPPORTED_TIERS and stats.fired >= args.min_gated_fires and stats.top1_delta < 0:
            notes.append(f"public tier {name} negative")
    if result.overall.fired < args.min_fires:
        notes.append("too few fires")
    return ("offline-feature-accepted" if not notes else "research-only", notes)


PUBLIC_SUPPORTED_TIERS = {
    "submit-eligible-candidate",
    "exact-public-replay-supported",
    "single-team-public-replay-supported",
}


def render(args: argparse.Namespace, results: list[PredicateResult], meta: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Attachment Timing Overlay Evaluation")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.getenv('USER', 'unknown')}")
    lines.append("- Runtime premise: public-action imitation feature only; no local full-game promotion and no live submission.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.model}`")
    lines.append(f"- Anchor status: `{args.anchor_status}`")
    lines.append(f"- Rows loaded: {meta['rows']}")
    lines.append("- Overlay: when base top-1 is active ATTACH and a PLAY is legal, rank the best base-ranked PLAY first.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Predicate | N | Base Top-1 | Overlay Top-1 | Delta | Base Top-3 | Overlay Top-3 | Eligible | Fires | Changes | Fixes | Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        lines.append(stats_row(result.predicate.name, result.overall))
    lines.append("")
    lines.append("## Holdouts")
    lines.append("")
    lines.append("| Predicate / Holdout | N | Base Top-1 | Overlay Top-1 | Delta | Base Top-3 | Overlay Top-3 | Eligible | Fires | Changes | Fixes | Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        for key in args.holdout_key:
            lines.append(stats_row(f"{result.predicate.name} / {key}", result.holdouts.get(key, EvalStats())))
    lines.append("")
    lines.append("## Public-Anchor Tiers")
    lines.append("")
    lines.append("| Predicate / Tier | N | Base Top-1 | Overlay Top-1 | Delta | Base Top-3 | Overlay Top-3 | Eligible | Fires | Changes | Fixes | Regressions |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for result in results:
        for tier, stats in sort_stats(result.tiers):
            lines.append(stats_row(f"{result.predicate.name} / {tier}", stats))
    for result in results:
        verdict, notes = decision(result, args)
        lines.append("")
        lines.append(f"## Predicate Detail: `{result.predicate.name}`")
        lines.append("")
        lines.append(f"- Decision: `{verdict}`")
        if notes:
            lines.append(f"- Blockers: {', '.join(notes)}")
        lines.append(f"- Overall fixes/regressions: {result.overall.fixes}/{result.overall.regressions}")
        lines.append("")
        lines.append("Top lanes by fires:")
        for lane, stats in sort_stats(result.lanes)[: args.limit]:
            if not stats.fired:
                continue
            lines.append(
                f"- `{lane}` N={stats.total} fires={stats.fired} top1 {pct(stats.base_top1, stats.total)} -> "
                f"{pct(stats.overlay_top1, stats.total)} delta={stats.top1_delta:+d} fixes={stats.fixes} regressions={stats.regressions}"
            )
        lines.append("")
        lines.append("Largest changes:")
        for text, count in result.changes.most_common(args.limit):
            lines.append(f"- {count}: {text}")
        if not result.changes:
            lines.append("- none")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- A positive result is an offline value/ranker feature only; it must still pass public-anchor and public-score gates before packaging.")
    lines.append("- If broad `all` loses but the Hop's Trevenant exact-hash predicate wins, keep the feature lane-scoped and use broader lanes only as negative controls.")
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: list[PredicateResult], args: argparse.Namespace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "predicate",
        "scope",
        "name",
        "total",
        "base_top1",
        "overlay_top1",
        "top1_delta",
        "base_top3",
        "overlay_top3",
        "eligible",
        "fires",
        "changes",
        "fixes",
        "regressions",
        "decision",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            verdict, _notes = decision(result, args)
            buckets: list[tuple[str, str, EvalStats]] = [("overall", "all", result.overall)]
            buckets.extend(("holdout", key, stats) for key, stats in result.holdouts.items())
            buckets.extend(("tier", key, stats) for key, stats in result.tiers.items())
            buckets.extend(("lane", key, stats) for key, stats in result.lanes.items() if stats.fired)
            for scope, name, stats in buckets:
                writer.writerow(
                    {
                        "predicate": result.predicate.name,
                        "scope": scope,
                        "name": name,
                        "total": stats.total,
                        "base_top1": f"{stats.base_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        "overlay_top1": f"{stats.overlay_top1 / stats.total:.6f}" if stats.total else "0.000000",
                        "top1_delta": stats.top1_delta,
                        "base_top3": f"{stats.base_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        "overlay_top3": f"{stats.overlay_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        "eligible": stats.eligible,
                        "fires": stats.fired,
                        "changes": stats.changed,
                        "fixes": stats.fixes,
                        "regressions": stats.regressions,
                        "decision": verdict if scope == "overall" else "",
                    }
                )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor-status", type=Path)
    parser.add_argument("--predicate", action="append", default=[])
    parser.add_argument("--report-out", type=Path, default=Path("strategy/attachment_timing_overlay.md"))
    parser.add_argument("--csv-out", type=Path, default=Path("strategy/attachment_timing_overlay.csv"))
    parser.add_argument("--holdout-key", action="append", default=DEFAULT_HOLDOUT_KEYS)
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-fires", type=int, default=25)
    parser.add_argument("--min-gated-fires", type=int, default=10)
    parser.add_argument("--limit", type=int, default=12)
    args = parser.parse_args()

    if not args.predicate:
        args.predicate = DEFAULT_PREDICATES
    results, meta = evaluate(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, results, meta), encoding="utf-8")
    write_csv(args.csv_out, results, args)
    print(f"rows={meta['rows']} predicates={len(results)} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
