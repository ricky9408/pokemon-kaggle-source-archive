#!/usr/bin/env python3
"""Report live type pressure and weakness targets from replay-observed decks.

Pokemon TCG strategy is not one best deck; it is a pressure/counterpressure
cycle. This tool keeps that layer explicit by combining card-pool metadata,
public replay deck shells, and local candidate decks before we spend
submissions.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strategy_research import (  # noqa: E402
    Card,
    DeckGroup,
    DeckProfile,
    card_tags,
    cost_size,
    dominant,
    group_observations,
    load_cards,
    load_replay_observations,
    parse_damage,
    profile_deck,
    read_agent_deck,
    top_cards,
    top_items,
)


TYPE_ORDER = ["{G}", "{R}", "{W}", "{L}", "{P}", "{F}", "{D}", "{M}", "{C}", "竜"]


@dataclass(frozen=True)
class TypePressure:
    attacker_types: Counter[str]
    exposed_weaknesses: Counter[str]
    tag_counts: Counter[str]


def sort_counter(counter: Counter[str]) -> list[tuple[str, float]]:
    return sorted(counter.items(), key=lambda item: (-item[1], TYPE_ORDER.index(item[0]) if item[0] in TYPE_ORDER else 99, item[0]))


def is_pokemon(card: Card) -> bool:
    return "Pokémon" in card.stage or "Pokemon" in card.stage


def is_attacker(card: Card) -> bool:
    if not is_pokemon(card):
        return False
    text = f"{card.move} {card.damage} {card.effect}".strip()
    return bool(text) and (parse_damage(card.damage) > 0 or "damage counter" in card.effect.lower())


def deck_type_pressure(deck: tuple[int, ...], cards: dict[int, Card]) -> TypePressure:
    attacker_types: Counter[str] = Counter()
    exposed_weaknesses: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    counts = Counter(deck)
    for card_id, count in counts.items():
        card = cards.get(card_id)
        if card is None:
            continue
        if is_pokemon(card):
            if card.weakness and card.weakness != "n/a":
                exposed_weaknesses[card.weakness] += count
            if is_attacker(card) and card.type_ and card.type_ not in {"", "n/a"}:
                attacker_types[card.type_] += count
        for tag in card_tags(card):
            tag_counts[tag] += count
    return TypePressure(attacker_types=attacker_types, exposed_weaknesses=exposed_weaknesses, tag_counts=tag_counts)


def weighted_type_pressure(groups: list[DeckGroup], cards: dict[int, Card]) -> TypePressure:
    attacker_types: Counter[str] = Counter()
    exposed_weaknesses: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    for group in groups:
        pressure = deck_type_pressure(group.deck, cards)
        weight = group.weighted_wins
        for key, value in pressure.attacker_types.items():
            attacker_types[key] += value * weight
        for key, value in pressure.exposed_weaknesses.items():
            exposed_weaknesses[key] += value * weight
        for key, value in pressure.tag_counts.items():
            tag_counts[key] += value * weight
    return TypePressure(attacker_types=attacker_types, exposed_weaknesses=exposed_weaknesses, tag_counts=tag_counts)


def type_list(counter: Counter[str], limit: int = 6) -> str:
    if not counter:
        return "-"
    return ", ".join(f"{key}:{value:.1f}" for key, value in sort_counter(counter)[:limit])


def pressure_score(candidate: TypePressure, opponent: TypePressure) -> tuple[float, float, set[str], set[str]]:
    candidate_hits = set(candidate.attacker_types) & set(opponent.exposed_weaknesses)
    opponent_hits = set(opponent.attacker_types) & set(candidate.exposed_weaknesses)
    hit_score = sum(candidate.attacker_types[type_] * opponent.exposed_weaknesses[type_] for type_ in candidate_hits)
    risk_score = sum(opponent.attacker_types[type_] * candidate.exposed_weaknesses[type_] for type_ in opponent_hits)
    return hit_score, risk_score, candidate_hits, opponent_hits


def normalize_score(value: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return value / denominator


def card_pool_counters(cards: dict[int, Card], weakness_types: list[str], limit_per_type: int = 5) -> dict[str, list[Card]]:
    result: dict[str, list[Card]] = {}
    for type_ in weakness_types:
        candidates: list[tuple[int, int, int, str, Card]] = []
        for card in cards.values():
            if not is_attacker(card) or card.type_ != type_:
                continue
            damage = parse_damage(card.damage)
            tags = card_tags(card)
            score = damage + 35 * ("energy_denial" in tags) + 30 * ("bench_damage" in tags)
            score += 25 * ("tempo_lock" in tags) + 20 * ("draw_consistency" in tags)
            score -= 8 * cost_size(card.cost)
            candidates.append((score, damage, -cost_size(card.cost), card.name, card))
        ordered = sorted(candidates, key=lambda item: (-item[0], -item[1], item[2], item[3], item[4].card_id))
        result[type_] = [card for *_prefix, card in ordered[:limit_per_type]]
    return result


def render(args: argparse.Namespace) -> str:
    cards = load_cards(args.cards)
    replay_paths = sorted(args.replays)
    observations, duplicates = load_replay_observations(replay_paths, not args.no_dedupe, args.rank_weighting)
    groups = group_observations(observations, args.winners_only)[: args.top_groups]
    live_pressure = weighted_type_pressure(groups, cards)
    live_denominator = max(1.0, sum(live_pressure.attacker_types.values()) + sum(live_pressure.exposed_weaknesses.values()))

    agent_profiles: list[tuple[Path, DeckProfile, TypePressure]] = []
    for agent_path in args.agent:
        deck = read_agent_deck(agent_path)
        agent_profiles.append((agent_path, profile_deck(agent_path.name, deck, cards), deck_type_pressure(deck, cards)))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Type Pressure Strategy Report")
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
    lines.append("- Strategic premise: type pressure and weakness exposure are treated separately from raw deck win rate.")
    lines.append("")

    lines.append("## Live Type Pressure")
    lines.append("")
    lines.append(f"- Weighted attacker types: {type_list(live_pressure.attacker_types)}")
    lines.append(f"- Weighted exposed weaknesses: {type_list(live_pressure.exposed_weaknesses)}")
    lines.append(f"- Weighted tactical tags: {type_list(live_pressure.tag_counts, 8)}")
    lines.append("")
    lines.append("| Rank | Opponent Cluster | Weight | Attacker Types | Weaknesses | Tactics |")
    lines.append("| ---: | --- | ---: | --- | --- | --- |")
    group_pressures: dict[str, TypePressure] = {}
    for index, group in enumerate(groups, 1):
        pressure = deck_type_pressure(group.deck, cards)
        group_pressures[group.key] = pressure
        teams = ", ".join(team for team, _ in group.teams.most_common(2))
        lines.append(
            f"| {index} | `{group.key}` ({teams}) | {group.weighted_wins:.2f} | "
            f"{type_list(pressure.attacker_types, 3)} | {type_list(pressure.exposed_weaknesses, 3)} | "
            f"{type_list(pressure.tag_counts, 4)} |"
        )
    lines.append("")

    lines.append("## Candidate Type Posture")
    lines.append("")
    lines.append("| Candidate | Archetype | Hash | Attack Types | Weaknesses | Live Type Edge | Live Type Risk | Tags |")
    lines.append("| --- | --- | --- | --- | --- | ---: | ---: | --- |")
    candidate_edges: list[tuple[float, str]] = []
    for _path, profile, pressure in agent_profiles:
        hit_score, risk_score, hits, risks = pressure_score(pressure, live_pressure)
        edge = normalize_score(hit_score - risk_score, live_denominator)
        candidate_edges.append((edge, profile.label))
        hit_text = ",".join(sorted(hits)) or "-"
        risk_text = ",".join(sorted(risks)) or "-"
        lines.append(
            f"| {profile.label} | {profile.archetype} | `{profile.deck_hash}` | "
            f"{type_list(pressure.attacker_types, 3)} | {type_list(pressure.exposed_weaknesses, 3)} | "
            f"{edge:.4f} ({hit_text}) | {normalize_score(risk_score, live_denominator):.4f} ({risk_text}) | "
            f"{type_list(pressure.tag_counts, 5)} |"
        )
    lines.append("")

    lines.append("## Candidate Stress Points")
    lines.append("")
    for _path, profile, pressure in sorted(agent_profiles, key=lambda item: item[1].label):
        lines.append(f"### {profile.label}")
        lines.append("")
        cluster_rows: list[tuple[float, DeckGroup, TypePressure, float, float, set[str], set[str]]] = []
        for group in groups:
            opponent_pressure = group_pressures[group.key]
            hit_score, risk_score, hits, risks = pressure_score(pressure, opponent_pressure)
            local_edge = hit_score - risk_score
            cluster_rows.append((local_edge, group, opponent_pressure, hit_score, risk_score, hits, risks))
        for local_edge, group, opponent_pressure, hit_score, risk_score, hits, risks in sorted(cluster_rows, key=lambda row: (row[0], -row[1].weighted_wins))[:5]:
            teams = ", ".join(team for team, _ in group.teams.most_common(2))
            lines.append(
                f"- `{group.key}` ({teams}, weight {group.weighted_wins:.2f}): "
                f"type_edge={local_edge:.1f}; hits={','.join(sorted(hits)) or '-'}; "
                f"risks={','.join(sorted(risks)) or '-'}; opponent tags={type_list(opponent_pressure.tag_counts, 4)}."
            )
        lines.append("")

    weakness_targets = [type_ for type_, _value in sort_counter(live_pressure.exposed_weaknesses)[:4]]
    counters = card_pool_counters(cards, weakness_targets, args.counter_cards)
    lines.append("## Card-Pool Counter Leads")
    lines.append("")
    lines.append("These are not automatic deck picks; they are card-pool leads for the pressure types currently rewarded by public replays.")
    lines.append("")
    for type_ in weakness_targets:
        lines.append(f"### Attack Type {type_}")
        lines.append("")
        for card in counters.get(type_, []):
            tags = ", ".join(sorted(card_tags(card))) or "-"
            lines.append(
                f"- {card.name} [{card.stage}] damage={card.damage or '-'} cost={card.cost or '-'} "
                f"weak={card.weakness or '-'} tags={tags}"
            )
        lines.append("")

    lines.append("## Strategy Implications")
    lines.append("")
    lines.append("- Submit pairs should not only maximize local win rate; they should cover different type-risk surfaces in the live ladder.")
    lines.append("- Psychic pressure remains justified while Mega Lucario dominates, but Psychic decks are exposed to Dark-type counterpressure and Enhanced Hammer mirrors.")
    lines.append("- Battle Cage Alakazam is a strategic branch, not merely a deck hash. It reduces bench-counter plans and changes whether Alakazam mirrors are won by damage placement, Energy denial, or consistency.")
    lines.append("- Plain Alakazam is less flashy but matters because it converts the mirror into setup consistency; this is why v77 remains strategically valuable even when v68 has stronger local raw coverage.")
    lines.append("")
    if candidate_edges:
        best = sorted(candidate_edges, reverse=True)[:3]
        lines.append(f"- Current type-edge shortlist: {', '.join(f'{label} {score:.4f}' for score, label in best)}.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--agent", action="append", type=Path, default=[])
    parser.add_argument("--top-groups", type=int, default=12)
    parser.add_argument("--counter-cards", type=int, default=5)
    parser.add_argument("--winners-only", action="store_true")
    parser.add_argument("--rank-weighting", action="store_true")
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
