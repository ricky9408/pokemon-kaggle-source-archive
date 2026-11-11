#!/usr/bin/env python3
"""Rank ML/RL policy targets by public replay and anchor support.

This report sits between the action-ranker/policy-gap miner and candidate
creation. It does not choose submissions. Instead, it answers: "which policy
motifs are worth improving next if public anchors, not the biased local gauntlet,
are our steering signal?"
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
from policy_gap_miner import classify_gap, motif, reward_bucket, row_group  # noqa: E402
from train_action_ranker import load_rows, pct, ranked_options, valid_single_label  # noqa: E402


@dataclass
class CandidateAnchor:
    candidate: str
    family: str
    deck_hash: str
    archetype: str
    anchor_state: str
    submit_eligible: bool
    reasons: str


@dataclass
class LaneSupport:
    archetype: str
    deck_hash: str
    episodes: set[str] = field(default_factory=set)
    wins: set[str] = field(default_factory=set)
    losses: set[str] = field(default_factory=set)
    draws: set[str] = field(default_factory=set)
    teams: Counter[str] = field(default_factory=Counter)
    decisions: int = 0

    @property
    def key(self) -> str:
        return f"{self.archetype}:{self.deck_hash}"

    @property
    def episode_count(self) -> int:
        return len(self.episodes)

    @property
    def win_rate(self) -> float:
        return len(self.wins) / len(self.episodes) if self.episodes else 0.0

    @property
    def team_count(self) -> int:
        return len(self.teams)

    def public_weight(self) -> float:
        # Public replay support, team diversity, and winning evidence all matter,
        # but keep this bounded so a single giant replay cluster does not dominate.
        episode_term = min(2.5, math.log1p(self.episode_count))
        team_term = min(1.0, 0.25 * self.team_count)
        result_term = 0.75 + self.win_rate
        return max(0.25, episode_term + team_term) * result_term


@dataclass
class TargetStat:
    gap: str
    archetype: str
    deck_hash: str
    count: int = 0
    win_rows: int = 0
    loss_rows: int = 0
    draw_rows: int = 0
    selected_motifs: Counter[str] = field(default_factory=Counter)
    predicted_motifs: Counter[str] = field(default_factory=Counter)
    teams: Counter[str] = field(default_factory=Counter)
    examples: Counter[tuple[str, str, str, str, str]] = field(default_factory=Counter)

    @property
    def key(self) -> str:
        return f"{self.archetype}:{self.deck_hash}:{self.gap}"

    @property
    def win_share(self) -> float:
        return self.win_rows / self.count if self.count else 0.0


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def load_anchor_status(path: Path | None) -> dict[str, list[CandidateAnchor]]:
    if path is None:
        return {}
    anchors: dict[str, list[CandidateAnchor]] = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            deck_hash = str(row.get("deck_hash") or "")
            if not deck_hash:
                continue
            anchors[deck_hash].append(
                CandidateAnchor(
                    candidate=str(row.get("candidate") or ""),
                    family=str(row.get("family") or ""),
                    deck_hash=deck_hash,
                    archetype=str(row.get("inferred_archetype") or ""),
                    anchor_state=str(row.get("anchor_state") or ""),
                    submit_eligible=str(row.get("submit_eligible") or "0") == "1",
                    reasons=str(row.get("reasons") or ""),
                )
            )
    return anchors


def lane_key(row: dict[str, Any]) -> tuple[str, str]:
    return row_group(row, "archetype"), row_group(row, "deck_hash")


def update_lane(lane: LaneSupport, row: dict[str, Any]) -> None:
    episode = str(row.get("episode_id") or f"row-{lane.decisions}")
    team = row_group(row, "team")
    lane.episodes.add(episode)
    lane.teams[team] += 1
    lane.decisions += 1
    reward = reward_bucket(row.get("terminal_reward"))
    if reward == "win":
        lane.wins.add(episode)
    elif reward == "loss":
        lane.losses.add(episode)
    elif reward == "draw":
        lane.draws.add(episode)


def build_lanes(rows: list[dict[str, Any]]) -> dict[tuple[str, str], LaneSupport]:
    lanes: dict[tuple[str, str], LaneSupport] = {}
    for row in rows:
        archetype, deck_hash = lane_key(row)
        lane = lanes.setdefault((archetype, deck_hash), LaneSupport(archetype=archetype, deck_hash=deck_hash))
        update_lane(lane, row)
    return lanes


def anchor_tier(
    lane: LaneSupport,
    candidates_by_hash: dict[str, list[CandidateAnchor]],
    min_public_episodes: int,
    min_public_teams: int,
) -> tuple[str, list[CandidateAnchor]]:
    candidates = candidates_by_hash.get(lane.deck_hash, [])
    if any(candidate.submit_eligible for candidate in candidates):
        return "submit-eligible-candidate", candidates
    if candidates and any("contradictory low public anchor" in candidate.reasons for candidate in candidates):
        return "candidate-public-contradicted", candidates
    if lane.episode_count >= min_public_episodes and lane.team_count >= min_public_teams:
        return "exact-public-replay-supported", candidates
    if lane.episode_count >= min_public_episodes:
        return "single-team-public-replay-supported", candidates
    if candidates:
        return "candidate-observed-thin", candidates
    return "thin-public-replay", candidates


def tier_multiplier(tier: str) -> float:
    return {
        "submit-eligible-candidate": 1.35,
        "exact-public-replay-supported": 1.25,
        "single-team-public-replay-supported": 1.05,
        "candidate-public-contradicted": 0.65,
        "candidate-observed-thin": 0.75,
        "thin-public-replay": 0.50,
    }.get(tier, 0.75)


def mine_targets(
    rows: list[dict[str, Any]],
    weights: dict[str, float],
    lanes: dict[tuple[str, str], LaneSupport],
    candidates_by_hash: dict[str, list[CandidateAnchor]],
    args: argparse.Namespace,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    stats: dict[tuple[str, str, str], TargetStat] = {}
    scored = 0
    skipped = 0
    mismatches = 0
    targeted = 0

    for row in rows:
        label = valid_single_label(row)
        if label is None:
            skipped += 1
            continue
        ranking = ranked_options(weights, row)
        options = row.get("options") or []
        if not ranking or not (0 <= label < len(options) and 0 <= ranking[0] < len(options)):
            skipped += 1
            continue
        selected = str(options[label])
        predicted = str(options[ranking[0]])
        scored += 1
        if selected == predicted:
            continue
        mismatches += 1
        gap = classify_gap(row, selected, predicted)
        if gap is None:
            continue
        targeted += 1
        archetype, deck_hash = lane_key(row)
        key = (archetype, deck_hash, gap)
        stat = stats.setdefault(key, TargetStat(gap=gap, archetype=archetype, deck_hash=deck_hash))
        stat.count += 1
        reward = reward_bucket(row.get("terminal_reward"))
        if reward == "win":
            stat.win_rows += 1
        elif reward == "loss":
            stat.loss_rows += 1
        elif reward == "draw":
            stat.draw_rows += 1
        stat.selected_motifs[motif(selected)] += 1
        stat.predicted_motifs[motif(predicted)] += 1
        stat.teams[row_group(row, "team")] += 1
        stat.examples[
            (
                row_group(row, "context"),
                row_group(row, "opponent_archetype"),
                selected,
                predicted,
                reward,
            )
        ] += 1

    rows_out: list[dict[str, Any]] = []
    for stat in stats.values():
        if stat.count < args.min_gap_count:
            continue
        lane = lanes[(stat.archetype, stat.deck_hash)]
        tier, candidates = anchor_tier(lane, candidates_by_hash, args.min_public_episodes, args.min_public_teams)
        score = stat.count * lane.public_weight() * tier_multiplier(tier) * (0.65 + stat.win_share)
        example = stat.examples.most_common(1)[0][0] if stat.examples else ("-", "-", "-", "-", "-")
        candidate_names = ", ".join(candidate.candidate for candidate in candidates[:4]) or "-"
        candidate_families = ", ".join(sorted({candidate.family for candidate in candidates if candidate.family})) or "-"
        candidate_states = ", ".join(sorted({candidate.anchor_state for candidate in candidates if candidate.anchor_state})) or "-"
        submit_eligible = any(candidate.submit_eligible for candidate in candidates)
        rows_out.append(
            {
                "score": score,
                "gap": stat.gap,
                "archetype": stat.archetype,
                "deck_hash": stat.deck_hash,
                "anchor_tier": tier,
                "count": stat.count,
                "win_rows": stat.win_rows,
                "loss_rows": stat.loss_rows,
                "draw_rows": stat.draw_rows,
                "win_share": stat.win_share,
                "lane_episodes": lane.episode_count,
                "lane_win_rate": lane.win_rate,
                "lane_teams": lane.team_count,
                "team_examples": ", ".join(team for team, _count in lane.teams.most_common(4)),
                "candidate_names": candidate_names,
                "candidate_families": candidate_families,
                "candidate_anchor_states": candidate_states,
                "candidate_submit_eligible": submit_eligible,
                "public_motif": stat.selected_motifs.most_common(1)[0][0] if stat.selected_motifs else "-",
                "model_motif": stat.predicted_motifs.most_common(1)[0][0] if stat.predicted_motifs else "-",
                "example_context": example[0],
                "example_opponent": example[1],
                "example_public": example[2],
                "example_model": example[3],
                "example_result": example[4],
            }
        )
    rows_out.sort(key=lambda item: item["score"], reverse=True)
    meta = {
        "loaded": len(rows),
        "scored": scored,
        "skipped": skipped,
        "mismatches": mismatches,
        "targeted": targeted,
        "target_rows": len(rows_out),
    }
    return rows_out, meta


def format_float(value: Any, digits: int = 3) -> str:
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def aggregate_by_gap(rows: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for row in rows:
        counter[row["gap"]] += int(row["count"])
    return counter


def strategic_directives(rows: list[dict[str, Any]]) -> list[str]:
    directives: list[str] = []
    top = rows[:8]
    top_gaps = {str(row["gap"]) for row in top}
    top_arches = Counter(str(row["archetype"]) for row in top)
    if any(gap.startswith("public_attack_model_play") or gap.startswith("public_end_model_play") for gap in top_gaps):
        directives.append(
            "First ML/RL probe: attack/end discipline under public-supported states, with a small behavior-cloned value prior instead of local win-rate promotion."
        )
    if any("attach" in gap for gap in top_gaps):
        directives.append(
            "Second probe: attachment target policy, especially bench-vs-active timing, evaluated as motif reduction before any gauntlet result is trusted."
        )
    if top_arches:
        archetype, count = top_arches.most_common(1)[0]
        directives.append(
            f"Use `{archetype}` as the first pressure-lane curriculum because it dominates the public-anchored target list ({count}/8 top rows)."
        )
    if any(row["anchor_tier"] == "candidate-public-contradicted" for row in top):
        directives.append(
            "Do not promote these variants directly: at least one high-scoring motif is tied to a candidate family with contradictory low public submissions."
        )
    if not directives:
        directives.append("No robust public-supported policy target emerged; collect more public replay anchors before patching strategy.")
    return directives


def render_report(args: argparse.Namespace, rows: list[dict[str, Any]], meta: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Public-Anchored Policy Targets")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.getenv('USER', 'unknown')}")
    lines.append("- Strategic premise: improve Pokemon TCG strategy/policy under type-balanced, non-transitive pressure lanes; do not chase one local deck.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Model: `{args.model}`")
    lines.append(f"- Anchor status: `{args.anchor_status}`")
    lines.append(f"- Minimum public episodes for exact-replay support: {args.min_public_episodes}")
    lines.append(f"- Minimum public teams for exact-replay support: {args.min_public_teams}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Rows loaded: {meta['loaded']}")
    lines.append(f"- Scored single-action nontrivial rows: {meta['scored']}")
    lines.append(f"- Model/public top-choice mismatches: {meta['mismatches']}/{meta['scored']} = {pct(meta['mismatches'], meta['scored'])}")
    lines.append(f"- Targeted strategic gaps: {meta['targeted']}/{meta['scored']} = {pct(meta['targeted'], meta['scored'])}")
    lines.append(f"- Public-anchored target rows emitted: {meta['target_rows']}")
    lines.append("")
    lines.append("## Top Public-Anchored Targets")
    lines.append("")
    lines.append(
        "| Rank | Score | Gap | Archetype | Hash | Anchor Tier | Count | Win Share | Episodes | Teams | Public Motif | Model Motif | Example |"
    )
    lines.append("| ---: | ---: | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |")
    for index, row in enumerate(rows[: args.limit], start=1):
        example = f"{row['example_context']} vs {row['example_opponent']}: {row['example_public']} -> {row['example_model']}"
        lines.append(
            f"| {index} | {float(row['score']):.1f} | `{row['gap']}` | `{row['archetype']}` | `{row['deck_hash']}` | "
            f"`{row['anchor_tier']}` | {row['count']} | {float(row['win_share']):.3f} | "
            f"{row['lane_episodes']} | {row['lane_teams']} | `{row['public_motif']}` | `{row['model_motif']}` | {example} |"
        )
    if not rows:
        lines.append("| 0 | 0.0 | - | - | - | - | 0 | 0.000 | 0 | 0 | - | - | - |")
    lines.append("")
    lines.append("## Gap Totals")
    lines.append("")
    lines.append("| Gap | Count |")
    lines.append("| --- | ---: |")
    for gap, count in aggregate_by_gap(rows).most_common(args.limit):
        lines.append(f"| `{gap}` | {count} |")
    if not rows:
        lines.append("| - | 0 |")
    lines.append("")
    lines.append("## Strategy Directives")
    lines.append("")
    for directive in strategic_directives(rows):
        lines.append(f"- {directive}")
    lines.append("")
    lines.append("## Workflow Use")
    lines.append("")
    lines.append("1. Pick a top target whose anchor tier is `exact-public-replay-supported` or stronger.")
    lines.append("2. Build a tiny policy probe or offline imitation/RL label for that motif only.")
    lines.append("3. Re-run action holdout, this target report, motif holdout, and public-anchor gates.")
    lines.append("4. Treat local gauntlets as stress tests only until backtest validity clears.")
    return "\n".join(lines)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "score",
        "gap",
        "archetype",
        "deck_hash",
        "anchor_tier",
        "count",
        "win_rows",
        "loss_rows",
        "draw_rows",
        "win_share",
        "lane_episodes",
        "lane_win_rate",
        "lane_teams",
        "team_examples",
        "candidate_names",
        "candidate_families",
        "candidate_anchor_states",
        "candidate_submit_eligible",
        "public_motif",
        "model_motif",
        "example_context",
        "example_opponent",
        "example_public",
        "example_model",
        "example_result",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rank, row in enumerate(rows, start=1):
            payload = {key: row.get(key, "") for key in fieldnames}
            payload["rank"] = rank
            payload["score"] = format_float(row.get("score"))
            payload["win_share"] = format_float(row.get("win_share"))
            payload["lane_win_rate"] = format_float(row.get("lane_win_rate"))
            writer.writerow(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--anchor-status", type=Path)
    parser.add_argument("--output", type=Path, default=Path("strategy/public_anchor_policy_targets.md"))
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-gap-count", type=int, default=10)
    parser.add_argument("--limit", type=int, default=24)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    target_rows, meta = mine_targets(rows, weights, lanes, anchors, args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(args, target_rows, meta), encoding="utf-8")
    if args.csv_output:
        write_csv(args.csv_output, target_rows)
    print(
        "rows={rows} scored={scored} targeted={targeted} targets={targets} report={report}".format(
            rows=len(rows),
            scored=meta["scored"],
            targeted=meta["targeted"],
            targets=len(target_rows),
            report=args.output,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
