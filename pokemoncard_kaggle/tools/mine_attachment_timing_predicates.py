#!/usr/bin/env python3
"""Mine predicates for split-direction attachment timing.

The broad attachment overlay was too blunt: "rank PLAY above active ATTACH"
helped aggregate public-action imitation but failed public-anchor gates. This
miner splits the timing problem into two runtime-shaped directions and searches
small predicates that may survive holdouts:

* play_over_active_attach: base top-1 is active ATTACH, promote best legal PLAY.
* active_attach_over_play: base top-1 is PLAY, promote best legal active ATTACH.

Outputs are curriculum/feature evidence only. They are not package or submit
signals.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_anchor_policy_targets import anchor_tier, build_lanes, load_anchor_status  # noqa: E402
from train_action_ranker import load_rows, option_parts, ranked_options, stable_bucket, valid_single_label  # noqa: E402


PUBLIC_SUPPORTED_TIERS = {
    "submit-eligible-candidate",
    "exact-public-replay-supported",
    "single-team-public-replay-supported",
}

DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]
DEFAULT_DIRECTIONS = ["play_over_active_attach", "active_attach_over_play"]


@dataclass
class Stats:
    total: int = 0
    base_top1: int = 0
    overlay_top1: int = 0
    base_top3: int = 0
    overlay_top3: int = 0
    eligible: int = 0
    fires: int = 0
    changes: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral: int = 0

    @property
    def top1_delta(self) -> int:
        return self.overlay_top1 - self.base_top1

    @property
    def net_fixes(self) -> int:
        return self.fixes - self.regressions


@dataclass
class RowCase:
    row: dict[str, Any]
    label: int
    base_rank: list[int]
    overlay_rank: list[int]
    eligible: bool
    features: dict[str, str]
    lane_name: str
    tier: str
    holdouts: dict[str, bool]
    change_text: str


@dataclass
class PredicateResult:
    direction: str
    predicate: str
    atoms: tuple[str, ...]
    stats: Stats
    holdouts: dict[str, Stats] = field(default_factory=dict)
    tiers: dict[str, Stats] = field(default_factory=dict)
    lanes: dict[str, Stats] = field(default_factory=dict)
    changes: Counter[str] = field(default_factory=Counter)

    @property
    def status(self) -> str:
        if self.stats.fires < 1:
            return "empty"
        if self.stats.top1_delta <= 0 or self.stats.net_fixes <= 0:
            return "reject"
        for stats in self.holdouts.values():
            if stats.fires >= 10 and stats.top1_delta < 0:
                return "reject"
        for tier, stats in self.tiers.items():
            if tier in PUBLIC_SUPPORTED_TIERS and stats.fires >= 10 and stats.top1_delta < 0:
                return "reject"
        return "candidate-feature"

    @property
    def priority(self) -> float:
        score = 0.0
        score += 2.0 * self.stats.top1_delta
        score += 1.5 * self.stats.net_fixes
        score += 0.02 * self.stats.fires
        score += 0.5 * sum(stats.top1_delta for stats in self.holdouts.values())
        score += 0.5 * sum(
            stats.top1_delta for tier, stats in self.tiers.items() if tier in PUBLIC_SUPPORTED_TIERS
        )
        if self.status == "reject":
            score -= 1000.0
        return score


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


def side(row: dict[str, Any], key: str) -> dict[str, Any]:
    value = state(row).get(key)
    return value if isinstance(value, dict) else {}


def bucket_num(value: Any, size: int, cap: int) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, number // size))


def option_card(options: list[str], index: int) -> str:
    if not 0 <= index < len(options):
        return "none"
    return option_parts(options[index]).get("card") or "none"


def option_type(options: list[str], index: int) -> str:
    if not 0 <= index < len(options):
        return "none"
    return option_parts(options[index]).get("type") or "none"


def active_attach_indices(options: list[str]) -> list[int]:
    return [
        index
        for index, text in enumerate(options)
        if option_parts(text)["type"] == "ATTACH" and option_parts(text)["to_area"] == "ACTIVE"
    ]


def play_indices(options: list[str]) -> list[int]:
    return [index for index, text in enumerate(options) if option_parts(text)["type"] == "PLAY"]


def legal_type_count(options: list[str], type_name: str) -> int:
    return sum(1 for option in options if option_parts(option)["type"] == type_name)


def base_features(row: dict[str, Any], options: list[str], base_top: int, overlay_top: int) -> dict[str, str]:
    me = side(row, "me")
    opponent = side(row, "opponent")
    features = {
        "archetype": row_value(row, "archetype"),
        "deck_hash": row_value(row, "deck_hash"),
        "opponent": row_value(row, "opponent_archetype"),
        "opponent_deck_hash": row_value(row, "opponent_deck_hash"),
        "active": str(me.get("active", "unknown")),
        "opp_active": str(opponent.get("active", "unknown")),
        "bench": str(me.get("bench_count", "unknown")),
        "opp_bench": str(opponent.get("bench_count", "unknown")),
        "bench_bucket": bucket_num(me.get("bench_count"), 2, 3),
        "opp_bench_bucket": bucket_num(opponent.get("bench_count"), 2, 3),
        "hand_bucket": bucket_num(me.get("hand_count"), 3, 6),
        "opp_hand_bucket": bucket_num(opponent.get("hand_count"), 3, 6),
        "prizes": str(me.get("prize_count", "unknown")),
        "opp_prizes": str(opponent.get("prize_count", "unknown")),
        "turn_bucket": bucket_num(state(row).get("turn"), 3, 6),
        "turn_action_bucket": bucket_num(state(row).get("turn_action_count"), 3, 6),
        "energy_attached": str(state(row).get("energy_attached", "unknown")),
        "supporter_played": str(state(row).get("supporter_played", "unknown")),
        "stadium_played": str(state(row).get("stadium_played", "unknown")),
        "base_type": option_type(options, base_top),
        "overlay_type": option_type(options, overlay_top),
        "base_card": option_card(options, base_top),
        "overlay_card": option_card(options, overlay_top),
        "legal_play_count_bucket": bucket_num(legal_type_count(options, "PLAY"), 2, 5),
        "legal_attach_count_bucket": bucket_num(legal_type_count(options, "ATTACH"), 2, 5),
        "option_count_bucket": bucket_num(len(options), 4, 6),
    }
    return features


def holdout_hit(row: dict[str, Any], key: str, modulo: int, bucket: int) -> bool:
    return stable_bucket(row_value(row, key), modulo) == bucket


def lane_key(row: dict[str, Any]) -> tuple[str, str]:
    return row_value(row, "archetype"), row_value(row, "deck_hash")


def direction_overlay_rank(row: dict[str, Any], base_rank: list[int], direction: str) -> tuple[list[int], bool, str]:
    options = [str(option) for option in (row.get("options") or [])]
    if row_value(row, "context") != "MAIN" or not base_rank:
        return base_rank, False, ""
    attach_active = set(active_attach_indices(options))
    plays = set(play_indices(options))
    if not attach_active or not plays:
        return base_rank, False, ""
    if direction == "play_over_active_attach":
        if base_rank[0] not in attach_active:
            return base_rank, False, ""
        target = next((index for index in base_rank if index in plays), None)
    elif direction == "active_attach_over_play":
        if base_rank[0] not in plays:
            return base_rank, False, ""
        target = next((index for index in base_rank if index in attach_active), None)
    else:
        raise ValueError(f"Unknown direction: {direction}")
    if target is None:
        return base_rank, False, ""
    text = f"base={options[base_rank[0]]} -> overlay={options[target]}"
    return [target] + [index for index in base_rank if index != target], True, text


def update_stats(stats: Stats, case: RowCase, fired: bool) -> None:
    stats.total += 1
    stats.eligible += int(case.eligible)
    stats.fires += int(fired)
    rank = case.overlay_rank if fired else case.base_rank
    base_hit = bool(case.base_rank and case.base_rank[0] == case.label)
    overlay_hit = bool(rank and rank[0] == case.label)
    stats.base_top1 += int(base_hit)
    stats.overlay_top1 += int(overlay_hit)
    stats.base_top3 += int(case.label in case.base_rank[:3])
    stats.overlay_top3 += int(case.label in rank[:3])
    changed = bool(fired and case.base_rank and rank and case.base_rank[0] != rank[0])
    stats.changes += int(changed)
    stats.fixes += int(changed and not base_hit and overlay_hit)
    stats.regressions += int(changed and base_hit and not overlay_hit)
    stats.neutral += int(changed and base_hit == overlay_hit)


def make_cases(
    rows: list[dict[str, Any]],
    weights: dict[str, float],
    direction: str,
    lanes: dict[tuple[str, str], Any],
    anchors: dict[str, Any],
    args: argparse.Namespace,
) -> list[RowCase]:
    cases: list[RowCase] = []
    for row in rows:
        label = valid_single_label(row)
        if label is None:
            continue
        base_rank = ranked_options(weights, row)
        if not base_rank:
            continue
        overlay_rank, eligible, change_text = direction_overlay_rank(row, base_rank, direction)
        options = [str(option) for option in (row.get("options") or [])]
        lane = lanes[lane_key(row)]
        tier, _candidates = anchor_tier(lane, anchors, args.min_public_episodes, args.min_public_teams)
        features = base_features(row, options, base_rank[0], overlay_rank[0] if overlay_rank else base_rank[0])
        cases.append(
            RowCase(
                row=row,
                label=label,
                base_rank=base_rank,
                overlay_rank=overlay_rank,
                eligible=eligible,
                features=features,
                lane_name=f"{lane.archetype}:{lane.deck_hash}",
                tier=tier,
                holdouts={key: holdout_hit(row, key, args.holdout_mod, args.holdout_bucket) for key in args.holdout_key},
                change_text=change_text,
            )
        )
    return cases


def atom_candidates(cases: list[RowCase], args: argparse.Namespace) -> list[tuple[str, ...]]:
    counts: Counter[str] = Counter()
    allowed_keys = set(args.feature_key)
    for case in cases:
        if not case.eligible:
            continue
        for key, value in case.features.items():
            if key not in allowed_keys or value in {"", "unknown", "none"}:
                continue
            counts[f"{key}={value}"] += 1
    singles = [
        (atom,)
        for atom, count in counts.most_common()
        if count >= args.min_fires
    ][: args.max_single_atoms]

    # Mine pairs only from useful, reasonably common single atoms.
    pair_seed = [atom[0] for atom in singles[: args.max_pair_seed]]
    pair_counts: Counter[tuple[str, str]] = Counter()
    for case in cases:
        if not case.eligible:
            continue
        present = {
            f"{key}={value}"
            for key, value in case.features.items()
            if f"{key}={value}" in pair_seed
        }
        present_list = sorted(present)
        for i, left in enumerate(present_list):
            for right in present_list[i + 1 :]:
                if left.split("=", 1)[0] == right.split("=", 1)[0]:
                    continue
                pair_counts[(left, right)] += 1
    pairs = [
        tuple(pair)
        for pair, count in pair_counts.most_common(args.max_pairs)
        if count >= args.min_fires
    ]
    return singles + pairs


def atom_matches(case: RowCase, atoms: tuple[str, ...]) -> bool:
    for atom in atoms:
        key, expected = atom.split("=", 1)
        if case.features.get(key) != expected:
            return False
    return True


def evaluate_atoms(direction: str, cases: list[RowCase], atoms: tuple[str, ...]) -> PredicateResult:
    result = PredicateResult(
        direction=direction,
        predicate=" & ".join(atoms) if atoms else "all",
        atoms=atoms,
        stats=Stats(),
        holdouts=defaultdict(Stats),
        tiers=defaultdict(Stats),
        lanes=defaultdict(Stats),
    )
    for case in cases:
        fired = bool(case.eligible and atom_matches(case, atoms))
        update_stats(result.stats, case, fired)
        for key, hit in case.holdouts.items():
            if hit:
                update_stats(result.holdouts[key], case, fired)
        update_stats(result.tiers[case.tier], case, fired)
        if fired:
            update_stats(result.lanes[case.lane_name], case, fired)
            if case.change_text:
                options = case.row.get("options") or []
                public = options[case.label] if case.label < len(options) else str(case.label)
                base_hit = bool(case.base_rank and case.base_rank[0] == case.label)
                overlay_hit = bool(case.overlay_rank and case.overlay_rank[0] == case.label)
                if overlay_hit and not base_hit:
                    outcome = "fix"
                elif base_hit and not overlay_hit:
                    outcome = "regress"
                else:
                    outcome = "neutral"
                result.changes[f"{outcome}: public={public} | {case.change_text}"] += 1
    return result


def pct(num: int, den: int) -> str:
    if den <= 0:
        return "0.000"
    return f"{num / den:.3f}"


def stats_summary(stats: Stats) -> str:
    return (
        f"N={stats.total} top1 {pct(stats.base_top1, stats.total)}->{pct(stats.overlay_top1, stats.total)} "
        f"delta={stats.top1_delta:+d} fires={stats.fires} fixes={stats.fixes} regressions={stats.regressions}"
    )


def run(args: argparse.Namespace) -> tuple[list[PredicateResult], dict[str, int]]:
    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    results: list[PredicateResult] = []
    meta: dict[str, int] = {"rows": len(rows)}
    for direction in args.direction:
        cases = make_cases(rows, weights, direction, lanes, anchors, args)
        meta[f"{direction}_cases"] = len(cases)
        meta[f"{direction}_eligible"] = sum(case.eligible for case in cases)
        atoms_list = atom_candidates(cases, args)
        meta[f"{direction}_predicates"] = len(atoms_list)
        for atoms in atoms_list:
            result = evaluate_atoms(direction, cases, atoms)
            if result.stats.fires >= args.min_fires:
                results.append(result)
    results.sort(key=lambda result: (result.status != "candidate-feature", -result.priority, -result.stats.fires, result.predicate))
    return results, meta


def render(args: argparse.Namespace, results: list[PredicateResult], meta: dict[str, int]) -> str:
    lines: list[str] = []
    lines.append("# Attachment Timing Predicate Miner")
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
    lines.append("- Runtime premise: predicate mining for offline ML/RL strategy features only; no local full-game promotion and no live submission.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.model}`")
    lines.append(f"- Anchor status: `{args.anchor_status}`")
    lines.append(f"- Directions: {', '.join(args.direction)}")
    lines.append(f"- Rows loaded: {meta['rows']}")
    for direction in args.direction:
        lines.append(
            f"- {direction}: cases={meta.get(direction + '_cases', 0)}, "
            f"eligible={meta.get(direction + '_eligible', 0)}, predicates={meta.get(direction + '_predicates', 0)}"
        )
    lines.append("")
    lines.append("## Top Predicates")
    lines.append("")
    lines.append("| Rank | Status | Direction | Predicate | Priority | N | Delta | Fires | Fixes / Regressions | Worst Holdout Delta | Exact Tier Delta |")
    lines.append("| ---: | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for rank, result in enumerate(results[: args.limit], start=1):
        worst_holdout = min((stats.top1_delta for stats in result.holdouts.values() if stats.fires >= args.min_gated_fires), default=0)
        exact_delta = result.tiers.get("exact-public-replay-supported", Stats()).top1_delta
        lines.append(
            f"| {rank} | `{result.status}` | `{result.direction}` | `{result.predicate}` | {result.priority:.1f} | "
            f"{result.stats.total} | {result.stats.top1_delta:+d} | {result.stats.fires} | "
            f"{result.stats.fixes} / {result.stats.regressions} | {worst_holdout:+d} | {exact_delta:+d} |"
        )
    if not results:
        lines.append("| 0 | - | - | - | 0.0 | 0 | 0 | 0 | 0 / 0 | 0 | 0 |")
    lines.append("")
    for result in results[: args.detail_limit]:
        lines.append(f"## Detail: `{result.direction}` / `{result.predicate}`")
        lines.append("")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Overall: {stats_summary(result.stats)}")
        lines.append("- Holdouts:")
        for key, stats in sorted(result.holdouts.items()):
            if stats.fires:
                lines.append(f"  - `{key}`: {stats_summary(stats)}")
        lines.append("- Public-anchor tiers:")
        for tier, stats in sorted(result.tiers.items(), key=lambda item: (-item[1].fires, item[0])):
            if stats.fires:
                lines.append(f"  - `{tier}`: {stats_summary(stats)}")
        lines.append("- Top lanes:")
        for lane, stats in sorted(result.lanes.items(), key=lambda item: (-item[1].fires, item[0]))[:8]:
            lines.append(f"  - `{lane}`: {stats_summary(stats)}")
        lines.append("- Largest changes:")
        for change, count in result.changes.most_common(8):
            lines.append(f"  - {count}: {change}")
        lines.append("")
    lines.append("## Decision")
    lines.append("")
    accepted = [result for result in results if result.status == "candidate-feature"]
    if accepted:
        best = accepted[0]
        lines.append(
            f"- Best candidate feature: `{best.direction}` / `{best.predicate}`. "
            "Evaluate it with `tools/evaluate_attachment_timing_overlay.py` or a dedicated public-anchor feature gate before any policy implementation."
        )
    else:
        lines.append("- No attachment predicate cleared the candidate-feature gate; keep attachment timing research-only and collect/mine richer state features.")
    lines.append("- Use rejected broad and exact-hash overlays as negative controls.")
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: list[PredicateResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "status",
        "direction",
        "predicate",
        "priority",
        "total",
        "base_top1",
        "overlay_top1",
        "top1_delta",
        "base_top3",
        "overlay_top3",
        "fires",
        "fixes",
        "regressions",
        "worst_holdout_delta",
        "exact_public_delta",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rank, result in enumerate(results, start=1):
            worst_holdout = min((stats.top1_delta for stats in result.holdouts.values() if stats.fires >= 10), default=0)
            exact_delta = result.tiers.get("exact-public-replay-supported", Stats()).top1_delta
            writer.writerow(
                {
                    "rank": rank,
                    "status": result.status,
                    "direction": result.direction,
                    "predicate": result.predicate,
                    "priority": f"{result.priority:.6f}",
                    "total": result.stats.total,
                    "base_top1": pct(result.stats.base_top1, result.stats.total),
                    "overlay_top1": pct(result.stats.overlay_top1, result.stats.total),
                    "top1_delta": result.stats.top1_delta,
                    "base_top3": pct(result.stats.base_top3, result.stats.total),
                    "overlay_top3": pct(result.stats.overlay_top3, result.stats.total),
                    "fires": result.stats.fires,
                    "fixes": result.stats.fixes,
                    "regressions": result.stats.regressions,
                    "worst_holdout_delta": worst_holdout,
                    "exact_public_delta": exact_delta,
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor-status", type=Path)
    parser.add_argument("--direction", action="append", default=DEFAULT_DIRECTIONS)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/attachment_timing_predicates.md"))
    parser.add_argument("--csv-out", type=Path, default=Path("strategy/attachment_timing_predicates.csv"))
    parser.add_argument("--holdout-key", action="append", default=DEFAULT_HOLDOUT_KEYS)
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-fires", type=int, default=25)
    parser.add_argument("--min-gated-fires", type=int, default=10)
    parser.add_argument("--max-single-atoms", type=int, default=160)
    parser.add_argument("--max-pair-seed", type=int, default=50)
    parser.add_argument("--max-pairs", type=int, default=500)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--detail-limit", type=int, default=8)
    parser.add_argument(
        "--feature-key",
        action="append",
        default=[
            "archetype",
            "deck_hash",
            "opponent",
            "opponent_deck_hash",
            "active",
            "opp_active",
            "bench",
            "opp_bench",
            "bench_bucket",
            "opp_bench_bucket",
            "hand_bucket",
            "opp_hand_bucket",
            "prizes",
            "opp_prizes",
            "turn_bucket",
            "turn_action_bucket",
            "energy_attached",
            "supporter_played",
            "stadium_played",
            "base_card",
            "overlay_card",
            "legal_play_count_bucket",
            "legal_attach_count_bucket",
            "option_count_bucket",
        ],
    )
    args = parser.parse_args()

    results, meta = run(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render(args, results, meta), encoding="utf-8")
    write_csv(args.csv_out, results)
    print(f"rows={meta['rows']} results={len(results)} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
