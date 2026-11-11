#!/usr/bin/env python3
"""Summarize strategy and local gauntlet evidence into a matchup matrix."""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from strategy_research import (
    dominant,
    group_observations,
    load_cards,
    load_replay_observations,
    matchup_notes,
    profile_deck,
    read_agent_deck,
)


@dataclass
class OpponentResult:
    opponent: str
    weight: float
    wins: int
    losses: int
    draws: int
    unfinished: int
    win_rate: float
    teams: str


@dataclass
class CandidateResults:
    label: str
    path: str
    opponents: dict[str, OpponentResult]
    weighted_win_rate: float | None


def normalize_key(key: str) -> str:
    if ":" not in key:
        return key.replace("_", "-")
    archetype, deck_hash = key.split(":", 1)
    return f"{archetype.replace('_', '-')}:{deck_hash}"


def parse_gauntlet(path: Path) -> dict[str, CandidateResults]:
    candidates: dict[str, CandidateResults] = {}
    current: CandidateResults | None = None
    opponent_line = re.compile(r"^[a-z_]+:[0-9a-f]{10},")

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            candidate_path = line.removeprefix("Candidate ").strip()
            label = Path(candidate_path).name
            current = CandidateResults(label=label, path=candidate_path, opponents={}, weighted_win_rate=None)
            candidates[label] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            try:
                current.weighted_win_rate = float(line.split(",", 1)[1])
            except ValueError:
                pass
            continue
        if not opponent_line.match(line):
            continue
        row = next(csv.reader([line]))
        if len(row) < 8:
            continue
        opponent = normalize_key(row[0])
        try:
            result = OpponentResult(
                opponent=opponent,
                weight=float(row[1]),
                wins=int(row[2]),
                losses=int(row[3]),
                draws=int(row[4]),
                unfinished=int(row[5]),
                win_rate=float(row[6]),
                teams=row[7],
            )
        except ValueError:
            continue
        current.opponents[opponent] = result
    return candidates


def weighted_average(values: list[tuple[float, float]]) -> float:
    total_weight = sum(weight for weight, _ in values)
    if not total_weight:
        return 0.0
    return sum(weight * value for weight, value in values) / total_weight


def pair_rows(
    candidates: dict[str, CandidateResults],
    opponent_order: list[str],
    agent_profiles: dict[str, object],
) -> list[tuple[str, str, float, float, float, int, list[str]]]:
    labels = sorted(candidates)
    rows: list[tuple[str, str, float, float, float, int, list[str]]] = []
    for i, left in enumerate(labels):
        for right in labels[i + 1 :]:
            values: list[tuple[float, float]] = []
            blindspots: list[str] = []
            for opponent in opponent_order:
                left_result = candidates[left].opponents.get(opponent)
                right_result = candidates[right].opponents.get(opponent)
                result = left_result or right_result
                if result is None:
                    continue
                left_rate = left_result.win_rate if left_result else 0.0
                right_rate = right_result.win_rate if right_result else 0.0
                best = max(left_rate, right_rate)
                values.append((result.weight, best))
                if left_rate < 0.50 and right_rate < 0.50:
                    blindspots.append(opponent)
            raw_score = weighted_average(values)
            left_profile = agent_profiles.get(left)
            right_profile = agent_profiles.get(right)
            penalty = 0.0
            if left_profile is not None and right_profile is not None:
                if left_profile.deck_hash == right_profile.deck_hash:
                    penalty += 0.04
                elif left_profile.archetype == right_profile.archetype:
                    penalty += 0.015
            strategy_score = max(0.0, raw_score - penalty)
            rows.append((left, right, strategy_score, raw_score, penalty, len(blindspots), blindspots[:4]))
    return sorted(rows, key=lambda row: (-row[2], row[5], row[0], row[1]))


def render_matrix(args: argparse.Namespace) -> str:
    cards = load_cards(args.cards)
    replay_paths = sorted(args.replays)
    observations, duplicates = load_replay_observations(replay_paths, not args.no_dedupe, args.rank_weighting)
    replay_groups = group_observations(observations, args.winners_only)
    top_groups = replay_groups[: args.top_groups]
    group_profiles = {
        normalize_key(group.key): profile_deck(normalize_key(group.key), group.deck, cards)
        for group in top_groups
    }
    opponent_order = [normalize_key(group.key) for group in top_groups]
    opponent_weights = {normalize_key(group.key): group.weighted_wins for group in top_groups}
    opponent_teams = {
        normalize_key(group.key): ", ".join(team for team, _ in group.teams.most_common(3))
        for group in top_groups
    }

    candidates = parse_gauntlet(args.gauntlet_output)
    agent_profiles = {}
    for agent_path in args.agent:
        deck = read_agent_deck(agent_path)
        agent_profiles[agent_path.name] = profile_deck(agent_path.name, deck, cards)
    if agent_profiles:
        candidates = {label: result for label, result in candidates.items() if label in agent_profiles}
    if args.only_with_results:
        result_keys = {opponent for result in candidates.values() for opponent in result.opponents}
        opponent_order = [key for key in opponent_order if key in result_keys]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Strategy Matchup Matrix")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append(f"- Card metadata source: `{args.cards}`")
    lines.append(f"- Replay files requested: {len(replay_paths)}; duplicate episode files ignored: {duplicates}")
    lines.append(f"- Local gauntlet source: `{args.gauntlet_output}`")
    lines.append("")

    lines.append("## Top Opponent Clusters")
    lines.append("")
    lines.append("| Opponent | Weight | Teams | Type | Weak To | Strategic Tags |")
    lines.append("| --- | ---: | --- | --- | --- | --- |")
    for key in opponent_order:
        profile = group_profiles[key]
        tags = "; ".join(f"{tag}:{count}" for tag, count in profile.tag_counts.most_common(5))
        lines.append(
            f"| `{key}` | {opponent_weights[key]:.2f} | {opponent_teams[key]} | "
            f"{', '.join(f'{k}:{v}' for k, v in profile.type_counts.most_common(2)) or '-'} | "
            f"{', '.join(f'{k}:{v}' for k, v in profile.weakness_counts.most_common(2)) or '-'} | {tags or '-'} |"
        )
    lines.append("")

    lines.append("## Candidate Win-Rate Matrix")
    lines.append("")
    header = "| Candidate | Weighted | " + " | ".join(f"`{key}`" for key in opponent_order) + " |"
    divider = "| --- | ---: | " + " | ".join("---:" for _ in opponent_order) + " |"
    lines.append(header)
    lines.append(divider)
    for label, result in sorted(candidates.items(), key=lambda item: (-(item[1].weighted_win_rate or 0.0), item[0])):
        values = []
        for opponent in opponent_order:
            cell = result.opponents.get(opponent)
            values.append(f"{cell.win_rate:.3f}" if cell else "-")
        weighted = result.weighted_win_rate
        lines.append(f"| {label} | {weighted:.4f} | " + " | ".join(values) + " |")
    lines.append("")

    lines.append("## Pair Complementarity")
    lines.append("")
    lines.append("| Pair | Strategy Score | Raw Coverage | Diversity Penalty | Shared Blindspots | Examples |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
    for left, right, score, raw_score, penalty, blind_count, blindspots in pair_rows(candidates, opponent_order, agent_profiles)[:10]:
        examples = ", ".join(f"`{key}`" for key in blindspots) if blindspots else "-"
        lines.append(f"| {left} + {right} | {score:.4f} | {raw_score:.4f} | {penalty:.3f} | {blind_count} | {examples} |")
    lines.append("")

    lines.append("## Metadata Edges For Current Shortlist")
    lines.append("")
    for label in sorted(agent_profiles):
        if label not in candidates:
            continue
        candidate_profile = agent_profiles[label]
        candidate_types = ", ".join(sorted(dominant(candidate_profile.type_counts))) or "-"
        lines.append(f"### {label}")
        lines.append("")
        lines.append(
            f"- Architecture: {candidate_profile.archetype}, hash `{candidate_profile.deck_hash}`, "
            f"type plan {candidate_types}, special Energy {candidate_profile.special_energy_count}, "
            f"max printed damage {candidate_profile.max_damage}."
        )
        weak_rows = sorted(
            candidates[label].opponents.values(),
            key=lambda item: (item.win_rate, -item.weight, item.opponent),
        )[:4]
        for row in weak_rows:
            opponent_profile = group_profiles.get(row.opponent)
            if opponent_profile is None:
                continue
            notes = "; ".join(matchup_notes(candidate_profile, opponent_profile))
            lines.append(
                f"- Weak/important check vs `{row.opponent}` ({row.win_rate:.3f}, weight {row.weight:.2f}): {notes}."
            )
        lines.append("")

    archetype_counts = Counter(key.split(":", 1)[0] for key in opponent_order)
    lines.append("## Strategic Takeaways")
    lines.append("")
    if archetype_counts["mega-lucario"] >= 3:
        lines.append("- Mega Lucario is not one deck; it is a family of Fighting pressure shells. Keep Psychic pressure, but test against multiple Lucario hashes because policy/deck differences move the matchup.")
    if any(key.startswith("alakazam") for key in opponent_order):
        lines.append("- The Alakazam branch is internally diverse. Hammer, plain consistency, Nighttime Mine, and Battle Cage change the matchup more than the archetype name suggests.")
    lines.append("- Prefer a latest-two pair that wins by different mechanisms. A same-shell pair needs a much larger local edge than a diverse pair because public scoring can punish shared blind spots.")
    lines.append("- Treat local win rates as tactical signals. Public v39/v48 misses prove that strategy, policy timing, and leaderboard drift matter as much as deck-list mimicry.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--gauntlet-output", required=True, type=Path)
    parser.add_argument("--agent", action="append", type=Path, default=[])
    parser.add_argument("--top-groups", type=int, default=10)
    parser.add_argument("--winners-only", action="store_true")
    parser.add_argument("--rank-weighting", action="store_true")
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--only-with-results", action="store_true", help="show only opponent clusters present in the gauntlet output")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render_matrix(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
