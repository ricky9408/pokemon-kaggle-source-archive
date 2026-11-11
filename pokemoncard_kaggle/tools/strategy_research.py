#!/usr/bin/env python3
"""Build strategy reports from card metadata, decks, and public replays.

This is intentionally simulator-light: it explains strategic texture from the
current card pool and replay-observed decks before we spend submissions on a
specific architecture.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


TYPE_ORDER = ["{G}", "{R}", "{W}", "{L}", "{P}", "{F}", "{D}", "{M}", "{C}", "竜"]


@dataclass(frozen=True)
class Card:
    card_id: int
    name: str
    stage: str
    rule: str
    category: str
    hp: str
    type_: str
    weakness: str
    retreat: str
    move: str
    cost: str
    damage: str
    effect: str


@dataclass
class DeckObservation:
    deck: tuple[int, ...]
    archetype: str
    deck_hash: str
    team: str
    reward: int | None
    rank: int | None
    path: Path | None


@dataclass
class DeckGroup:
    key: str
    deck: tuple[int, ...]
    archetype: str
    deck_hash: str
    teams: Counter[str]
    seen: int
    wins: int
    losses: int
    weighted_seen: float
    weighted_wins: float


@dataclass
class DeckProfile:
    label: str
    deck: tuple[int, ...]
    archetype: str
    deck_hash: str
    card_counts: Counter[int]
    stage_counts: Counter[str]
    type_counts: Counter[str]
    weakness_counts: Counter[str]
    trainer_counts: Counter[str]
    tag_counts: Counter[str]
    tag_examples: dict[str, list[str]]
    max_damage: int
    average_attack_cost: float
    pokemon_count: int
    trainer_count: int
    energy_count: int
    special_energy_count: int
    basic_energy_count: int


@dataclass
class SimulationResult:
    candidate: str
    source: str
    weighted: float | None
    opponent_rates: dict[str, float]
    opponent_weights: dict[str, float]
    opponent_teams: dict[str, str]


def load_cards(path: Path) -> dict[int, Card]:
    cards: dict[int, Card] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            card_id = int(row["Card ID"])
            cards[card_id] = Card(
                card_id=card_id,
                name=row["Card Name"],
                stage=row["Stage (Pokémon)/Type (Energy and Trainer)"],
                rule=row["Rule"],
                category=row["Category"],
                hp=row["HP"],
                type_=row["Type"],
                weakness=row["Weakness"],
                retreat=row["Retreat"],
                move=row["Move Name"],
                cost=row["Cost"],
                damage=row["Damage"],
                effect=row["Effect Explanation"],
            )
    return cards


def deck_hash(deck: tuple[int, ...] | list[int]) -> str:
    packed = ",".join(str(card) for card in sorted(deck))
    return hashlib.sha1(packed.encode()).hexdigest()[:10]


def archetype(deck: tuple[int, ...] | list[int]) -> str:
    counts = Counter(deck)
    cards = set(counts)
    if {265, 268, 269, 270, 271} & cards:
        return "iono-lightning"
    if {646, 648} <= cards:
        if {103, 104} <= cards:
            return "grimmsnarl-froslass"
        return "grimmsnarl"
    if {878, 879} <= cards:
        return "hops-trevenant"
    if {379, 380, 381} <= cards:
        return "cynthias-garchomp"
    if 687 in cards:
        return "mega-absol-box"
    if 63 in cards:
        return "raging-bolt"
    if 272 in cards and 756 in cards:
        return "lillie-clefairy"
    if {741, 742, 743} <= cards:
        if 1266 in cards:
            if counts[1081] >= 4:
                return "alakazam-nighttime-hammer"
            return "alakazam-nighttime-mine"
        if counts[1081] >= 4:
            return "alakazam-hammer"
        if counts[1264] >= 4 and counts[1081] >= 3:
            return "alakazam-battle-cage"
        return "alakazam"
    if {89, 90, 92, 93} <= cards:
        return "festival-lead"
    if {292, 293} <= cards:
        return "n-zoroark"
    if {162, 163} <= cards:
        return "slowking"
    if {344, 345} <= cards and {1212, 1235, 1147} <= cards and counts[1] >= 16:
        return "pure-crustle-heal"
    if {344, 345, 1198, 1219} <= cards:
        return "crustle-petrel-crispin"
    if {344, 345} <= cards and 1120 in cards:
        return "hammer-crustle"
    if {344, 345} <= cards and ({1264, 1224} & cards):
        return "battle-cage-crustle"
    if {352, 353, 354, 344, 345} <= cards:
        return "ethan-crustle"
    if {352, 353, 354} <= cards:
        return "ethan-typhlosion"
    if {119, 120, 121} <= cards:
        if {131, 132, 133} & cards:
            return "dragapult-dusknoir"
        if {172, 173, 174} & cards:
            return "dragapult-noctowl"
        return "dragapult"
    if 678 in cards:
        return "mega-lucario"
    if {722, 723} & cards:
        return "mega-abomasnow"
    if 756 in cards and {344, 345} <= cards:
        return "mega-kangaskhan-crustle"
    if 756 in cards:
        return "mega-kangaskhan"
    if {400, 401, 431} <= cards:
        return "rocket-mewtwo"
    if {463, 891} & cards:
        return "rocket-honchkrow"
    if 150 in cards:
        return "hydrapple"
    if ({96, 108, 117} & cards) and (1090 in cards or 1250 in cards):
        return "ogerpon-box"
    if ({96, 150, 710} & cards) and ({1094, 1261} & cards):
        return "grass-toolbox"
    if ({676, 1142} <= cards) or ({116, 676} <= cards) or ({1051, 1052, 676} <= cards):
        return "fighting-toolbox"
    if {344, 345} <= cards:
        return "pure-crustle"
    return "other"


def replay_id(path: Path) -> str:
    match = re.search(r"episode-(\d+)-replay\.json$", path.name)
    return match.group(1) if match else str(path)


def scouting_root(path: Path) -> Path | None:
    for parent in path.parents:
        if (parent / "download_summary.csv").exists():
            return parent
    return None


def load_team_ranks(paths: list[Path]) -> dict[str, int]:
    ranks: dict[str, int] = {}
    roots = {root for path in paths if (root := scouting_root(path)) is not None}
    for root in roots:
        with (root / "download_summary.csv").open(encoding="utf-8-sig", newline="") as file:
            for row in csv.DictReader(file):
                team = row.get("team")
                rank_text = row.get("rank")
                if not team or not rank_text:
                    continue
                try:
                    rank = int(rank_text)
                except ValueError:
                    continue
                ranks[team] = min(rank, ranks.get(team, rank))
    return ranks


def rank_factor(rank: int | None) -> float:
    if rank is None or rank <= 0:
        return 1.0
    return 1.0 + 0.75 / math.sqrt(rank)


def load_replay_observations(paths: list[Path], dedupe: bool, rank_weighting: bool) -> tuple[list[DeckObservation], int]:
    observations: list[DeckObservation] = []
    seen_replays: set[str] = set()
    duplicates = 0
    ranks = load_team_ranks(paths) if rank_weighting else {}
    for path in sorted(paths):
        rid = replay_id(path)
        if dedupe and rid in seen_replays:
            duplicates += 1
            continue
        seen_replays.add(rid)
        data = json.loads(path.read_text())
        teams = data.get("info", {}).get("TeamNames", [])
        rewards = data.get("rewards") or [None] * len(teams)
        try:
            decks = data["steps"][0][0]["visualize"][0]["action"]
        except Exception:
            continue
        for slot, deck_list in enumerate(decks):
            if slot >= len(teams):
                continue
            deck = tuple(int(card) for card in deck_list)
            observations.append(
                DeckObservation(
                    deck=deck,
                    archetype=archetype(deck),
                    deck_hash=deck_hash(deck),
                    team=teams[slot],
                    reward=rewards[slot] if slot < len(rewards) else None,
                    rank=ranks.get(teams[slot]),
                    path=path,
                )
            )
    return observations, duplicates


def group_observations(observations: list[DeckObservation], winners_only: bool) -> list[DeckGroup]:
    grouped: dict[str, DeckGroup] = {}
    for obs in observations:
        if winners_only and obs.reward != 1:
            continue
        key = f"{obs.archetype}:{obs.deck_hash}"
        group = grouped.get(key)
        if group is None:
            group = DeckGroup(
                key=key,
                deck=obs.deck,
                archetype=obs.archetype,
                deck_hash=obs.deck_hash,
                teams=Counter(),
                seen=0,
                wins=0,
                losses=0,
                weighted_seen=0.0,
                weighted_wins=0.0,
            )
            grouped[key] = group
        factor = rank_factor(obs.rank)
        group.teams[obs.team] += 1
        group.seen += 1
        group.weighted_seen += factor
        if obs.reward == 1:
            group.wins += 1
            group.weighted_wins += factor
        elif obs.reward == -1:
            group.losses += 1
    return sorted(
        grouped.values(),
        key=lambda group: (-(group.weighted_wins + 0.35 * max(0.0, group.weighted_seen - group.weighted_wins)), group.key),
    )


def read_agent_deck(path: Path) -> tuple[int, ...]:
    deck_path = path / "deck.csv"
    deck = tuple(int(line) for line in deck_path.read_text().splitlines() if line.strip())
    if len(deck) != 60:
        raise ValueError(f"{deck_path} must contain 60 cards, got {len(deck)}")
    return deck


def parse_damage(value: str) -> int:
    if not value or value == "n/a":
        return 0
    match = re.search(r"\d+", value)
    return int(match.group(0)) if match else 0


def cost_size(value: str) -> int:
    if not value or value == "n/a":
        return 0
    typed = len(re.findall(r"\{[^}]+\}", value))
    colorless = value.count("●")
    return typed + colorless


def card_tags(card: Card) -> set[str]:
    name = card.name.lower()
    effect = card.effect.lower().replace("’", "'").replace("é", "e")
    text = f"{name} {card.stage} {card.category} {card.rule} {card.cost} {card.damage} {effect}".lower()
    tags: set[str] = set()
    opponentish = "opponent" in effect or "their active" in effect or "their benched" in effect
    energy_discard_from_opponent = (
        "discard" in effect
        and "energy" in effect
        and opponentish
        and "discard pile" not in effect
    )
    special_energy_targeting = "special energy" in effect and opponentish
    pokemon_card = "Pokémon" in card.stage or "Pokemon" in card.stage
    opponent_bench = (
        "opponent's benched" in effect
        or "opponent's bench" in effect
        or "opponent's pokemon on their bench" in effect
        or "opponent's pokémon on their bench" in effect
        or "their benched" in effect
    )

    if "search your deck" in effect or "buddy-buddy poffin" in name or "dusk ball" in name or "ultra ball" in name:
        tags.add("setup_search")
    if "onto your bench" in effect or "onto your bench." in effect:
        tags.add("bench_setup")
    if "rare candy" in name or "evolves from this" in effect or "evolve" in effect:
        tags.add("evolution_accel")
    if "draw" in effect or ("put" in effect and "into your hand" in effect) or "poke pad" in name:
        tags.add("draw_consistency")
    if ("attach" in effect and "energy" in effect) or "energy switch" in name or "glass trumpet" in name:
        tags.add("energy_accel")
    if energy_discard_from_opponent or "enhanced hammer" in name or "crushing hammer" in name:
        tags.add("energy_denial")
    if (special_energy_targeting and ("discard" in effect or "prevent" in effect)) or "enhanced hammer" in name:
        tags.add("special_energy_hate")
    if "heal" in effect or "remove damage" in effect or ("prevent all damage" in effect and "damage counter" not in effect):
        tags.add("stall_heal")
    if "damage counter" in effect and ("place" in effect or "put" in effect) and opponentish and "prevent" not in effect:
        tags.add("damage_counter_attack")
    if opponent_bench and "prevent" not in effect and ("damage" in effect or ("damage counter" in effect and ("place" in effect or "put" in effect))):
        tags.add("bench_damage")
    if "prevent all damage counters" in effect or "battle cage" in name:
        tags.add("bench_protection")
    if "can't retreat" in effect or "can't retreat" in effect or "cost {c} more" in effect or "nighttime mine" in name:
        tags.add("tempo_lock")
    if (
        "boss's orders" in name
        or "counter catcher" in name
        or "switch in 1 of your opponent's benched" in effect
        or "switch your active" in effect
        or "switch your opponent's active" in effect
    ):
        tags.add("gust_switch")
    if "random card from your opponent" in effect or "opponent reveals" in effect or "shuffles it into their deck" in effect:
        tags.add("hand_disruption")
    if parse_damage(card.damage) >= 220:
        tags.add("one_shot_pressure")
    if pokemon_card and ("mega " in name or "tera" in card.rule.lower()):
        tags.add("tera_or_mega_attacker")
    return tags


def profile_deck(label: str, deck: tuple[int, ...], cards: dict[int, Card]) -> DeckProfile:
    counts = Counter(deck)
    stage_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    weakness_counts: Counter[str] = Counter()
    trainer_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    tag_examples: dict[str, list[str]] = defaultdict(list)
    max_damage = 0
    costs: list[int] = []
    pokemon_count = trainer_count = energy_count = 0
    special_energy_count = basic_energy_count = 0

    for card_id, count in counts.items():
        card = cards.get(card_id)
        if card is None:
            continue
        stage_counts[card.stage] += count
        max_damage = max(max_damage, parse_damage(card.damage))
        cost = cost_size(card.cost)
        if cost:
            costs.extend([cost] * count)
        if "Pokémon" in card.stage or "Pokemon" in card.stage:
            pokemon_count += count
            if card.type_ and card.type_ not in {"n/a", ""}:
                type_counts[card.type_] += count
            if card.weakness and card.weakness != "n/a":
                weakness_counts[card.weakness] += count
        elif "Energy" in card.stage:
            energy_count += count
            if "Basic Energy" in card.stage:
                basic_energy_count += count
            else:
                special_energy_count += count
            if card.type_ and card.type_ not in {"n/a", ""}:
                type_counts[card.type_] += count
        else:
            trainer_count += count
            trainer_counts[card.stage] += count

        for tag in card_tags(card):
            tag_counts[tag] += count
            examples = tag_examples[tag]
            if len(examples) < 4 and card.name not in examples:
                examples.append(card.name)

    return DeckProfile(
        label=label,
        deck=deck,
        archetype=archetype(deck),
        deck_hash=deck_hash(deck),
        card_counts=counts,
        stage_counts=stage_counts,
        type_counts=type_counts,
        weakness_counts=weakness_counts,
        trainer_counts=trainer_counts,
        tag_counts=tag_counts,
        tag_examples=dict(tag_examples),
        max_damage=max_damage,
        average_attack_cost=sum(costs) / len(costs) if costs else 0.0,
        pokemon_count=pokemon_count,
        trainer_count=trainer_count,
        energy_count=energy_count,
        special_energy_count=special_energy_count,
        basic_energy_count=basic_energy_count,
    )


def top_items(counter: Counter[str], n: int = 3) -> str:
    if not counter:
        return "-"
    ordered = sorted(counter.items(), key=lambda item: (-item[1], TYPE_ORDER.index(item[0]) if item[0] in TYPE_ORDER else 99, item[0]))
    return ", ".join(f"{key}:{value}" for key, value in ordered[:n])


def top_cards(profile: DeckProfile, cards: dict[int, Card], n: int = 8) -> str:
    parts = []
    for card_id, count in profile.card_counts.most_common(n):
        name = cards.get(card_id).name if card_id in cards else str(card_id)
        parts.append(f"{name}x{count}")
    return ", ".join(parts)


def pressure_lane(archetype_name: str) -> str:
    normalized = archetype_name.replace("_", "-")
    if "mega-lucario" in normalized or "fighting-toolbox" in normalized:
        return "Fighting pressure"
    if "alakazam-battle-cage" in normalized:
        return "Battle Cage Alakazam control"
    if "alakazam-nighttime" in normalized:
        return "Nighttime Alakazam control"
    if "alakazam-hammer" in normalized:
        return "Hammer Alakazam control"
    if normalized == "alakazam":
        return "Plain Alakazam consistency"
    if "iono" in normalized or "lightning" in normalized:
        return "Lightning energy-ramp tail"
    if "dragapult" in normalized:
        return "Dragapult bench-pressure tail"
    if "crustle" in normalized:
        return "Crustle stall/heal tail"
    return "Other live tail"


def lane_requirement(lane: str) -> str:
    if lane == "Fighting pressure":
        return "Psychic pressure must convert setup into prizes before Mega Lucario one-shots stabilize."
    if lane == "Battle Cage Alakazam control":
        return "Win without depending on bench-damage shortcuts; value damage placement, Hammer timing, and setup tempo."
    if lane == "Nighttime Alakazam control":
        return "Respect Enhanced Hammer plus tempo-lock turns; avoid fragile special-Energy sequencing."
    if lane == "Hammer Alakazam control":
        return "Mirror sequencing matters: search, evolve, attach, and disrupt before the opponent's Hammer turns."
    if lane == "Plain Alakazam consistency":
        return "Beat raw setup consistency; denial alone is insufficient if it misses early turns."
    if lane == "Lightning energy-ramp tail":
        return "Do not lose the basic-Fighting weakness/energy-ramp race to Iono shells."
    if lane == "Dragapult bench-pressure tail":
        return "Protect bench development and avoid letting spread damage set up prize chains."
    if lane == "Crustle stall/heal tail":
        return "Carry enough inevitability, gust, or denial to avoid healing loops."
    return "Keep a flexible policy; this lane is too small for a deck rebuild unless it grows."


def lane_summary(groups: list[DeckGroup]) -> list[tuple[str, float, str, str]]:
    weights: Counter[str] = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    for group in groups:
        lane = pressure_lane(group.archetype)
        weights[lane] += group.weighted_wins
        example = f"{group.archetype}:{group.deck_hash}"
        if len(examples[lane]) < 3 and example not in examples[lane]:
            examples[lane].append(example)
    return [
        (lane, weight, ", ".join(examples[lane]), lane_requirement(lane))
        for lane, weight in sorted(weights.items(), key=lambda item: (-item[1], item[0]))
    ]


def dominant(counter: Counter[str], n: int = 2) -> set[str]:
    return {key for key, _ in counter.most_common(n) if key and key != "n/a"}


def matchup_notes(left: DeckProfile, right: DeckProfile) -> list[str]:
    notes: list[str] = []
    left_types = dominant(left.type_counts)
    right_types = dominant(right.type_counts)
    left_hits = left_types & set(right.weakness_counts)
    right_hits = right_types & set(left.weakness_counts)
    if left_hits and not right_hits:
        notes.append(f"{left.label} type edge via {', '.join(sorted(left_hits))}")
    elif right_hits and not left_hits:
        notes.append(f"{right.label} type edge via {', '.join(sorted(right_hits))}")
    elif left_hits and right_hits:
        notes.append(f"mutual weakness pressure ({left.label}: {', '.join(sorted(left_hits))}; {right.label}: {', '.join(sorted(right_hits))})")
    if left.tag_counts["energy_denial"] and right.special_energy_count:
        notes.append(f"{left.label} can attack {right.label}'s {right.special_energy_count} special Energy")
    if right.tag_counts["energy_denial"] and left.special_energy_count:
        notes.append(f"{right.label} can attack {left.label}'s {left.special_energy_count} special Energy")
    if left.tag_counts["bench_protection"] and right.tag_counts["bench_damage"]:
        notes.append(f"{left.label} can blunt {right.label}'s bench-damage plan")
    if right.tag_counts["bench_protection"] and left.tag_counts["bench_damage"]:
        notes.append(f"{right.label} can blunt {left.label}'s bench-damage plan")
    if left.tag_counts["tempo_lock"] and right.tag_counts["tera_or_mega_attacker"]:
        notes.append(f"{left.label} taxes/locks {right.label}'s Mega/Tera tempo")
    if right.tag_counts["tempo_lock"] and left.tag_counts["tera_or_mega_attacker"]:
        notes.append(f"{right.label} taxes/locks {left.label}'s Mega/Tera tempo")
    if left.max_damage >= 240 and right.tag_counts["stall_heal"]:
        notes.append(f"{left.label} can bypass some healing with one-shot pressure")
    if right.max_damage >= 240 and left.tag_counts["stall_heal"]:
        notes.append(f"{right.label} can bypass some healing with one-shot pressure")
    return notes or ["no obvious metadata edge; sequencing and policy likely decide"]


def format_tag_examples(profile: DeckProfile, limit: int = 5) -> str:
    parts = []
    for tag, count in profile.tag_counts.most_common(limit):
        examples = "/".join(profile.tag_examples.get(tag, [])[:2])
        parts.append(f"{tag}:{count}" + (f" ({examples})" if examples else ""))
    return "; ".join(parts) if parts else "-"


def parse_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_simulation_results(path: Path | None) -> dict[str, SimulationResult]:
    if path is None or not path.exists():
        return {}
    results: dict[str, SimulationResult] = {}
    current: SimulationResult | None = None
    in_opponent_table = False
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Candidate "):
                candidate = Path(line.removeprefix("Candidate ").strip()).name
                current = SimulationResult(
                    candidate=candidate,
                    source=str(path),
                    weighted=None,
                    opponent_rates={},
                    opponent_weights={},
                    opponent_teams={},
                )
                results[candidate] = current
                in_opponent_table = False
                continue
            if current is None:
                continue
            if line.startswith("opponent,"):
                in_opponent_table = True
                continue
            if line.startswith("weighted_win_rate,"):
                current.weighted = parse_float(line.split(",", 1)[1])
                in_opponent_table = False
                continue
            if not in_opponent_table:
                continue
            cells = next(csv.reader([line]))
            if len(cells) < 8:
                continue
            opponent = cells[0]
            weight = parse_float(cells[1]) or 0.0
            rate = parse_float(cells[6])
            if rate is None:
                continue
            current.opponent_weights[opponent] = weight
            current.opponent_rates[opponent] = rate
            current.opponent_teams[opponent] = ",".join(cells[7:])
    return results


def fmt_rate(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def sim_examples(result: SimulationResult | None, high: bool) -> str:
    if result is None:
        return "-"
    rows = [
        (opponent, rate, result.opponent_weights.get(opponent, 0.0))
        for opponent, rate in result.opponent_rates.items()
        if result.opponent_weights.get(opponent, 0.0) >= 1.0
    ]
    rows.sort(key=lambda item: ((-item[1] if high else item[1]), -item[2], item[0]))
    picked = rows[:3]
    return "; ".join(f"{opponent} {rate:.3f} (w {weight:.1f})" for opponent, rate, weight in picked) or "-"


def simulation_read(candidate: str, broad: SimulationResult | None, focus: SimulationResult | None) -> str:
    broad_rate = broad.weighted if broad else None
    focus_rate = focus.weighted if focus else None
    if broad_rate is None and focus_rate is None:
        return "no simulator evidence"
    if broad_rate is not None and focus_rate is not None:
        if broad_rate >= 0.80 and focus_rate < 0.55:
            return "broad anti-Lucario spike with control-mirror risk"
        if broad_rate >= 0.75 and focus_rate >= 0.58:
            return "balanced current-window candidate"
        if focus_rate >= 0.60:
            return "control-lane hedge"
        if focus_rate < 0.50:
            return "avoid when Alakazam control rises"
    if broad_rate is not None and broad_rate >= 0.80:
        return "strong broad lane; needs mirror check"
    if focus_rate is not None and focus_rate >= 0.60:
        return "promising control-lane specialist"
    return "conditional / fallback"


def render_simulation_section(
    agent_profiles: list[DeckProfile],
    broad_results: dict[str, SimulationResult],
    focus_results: dict[str, SimulationResult],
) -> list[str]:
    if not broad_results and not focus_results:
        return []
    labels = [profile.label for profile in agent_profiles]
    for candidate in sorted(set(broad_results) | set(focus_results)):
        if candidate not in labels:
            labels.append(candidate)
    lines = ["## Local Simulator Validation", ""]
    if broad_results:
        sample = next(iter(broad_results.values()))
        lines.append(f"- Broad source: `{sample.source}`")
    if focus_results:
        sample = next(iter(focus_results.values()))
        lines.append(f"- Focus source: `{sample.source}`")
    lines.append("- Read this as tactical validation of the card-pool thesis, not as a replacement for public-score priors.")
    lines.append("")
    lines.append("| Candidate | Broad | Control Focus | Delta | Local Read | Strong Examples | Blind Spots |")
    lines.append("| --- | ---: | ---: | ---: | --- | --- | --- |")
    for label in labels:
        broad = broad_results.get(label)
        focus = focus_results.get(label)
        broad_rate = broad.weighted if broad else None
        focus_rate = focus.weighted if focus else None
        delta = "-"
        if broad_rate is not None and focus_rate is not None:
            delta = f"{broad_rate - focus_rate:+.4f}"
        lines.append(
            f"| `{label}` | {fmt_rate(broad_rate)} | {fmt_rate(focus_rate)} | {delta} | "
            f"{simulation_read(label, broad, focus)} | {sim_examples(broad or focus, True)} | "
            f"{sim_examples(focus or broad, False)} |"
        )
    lines.append("")
    lines.append("### Strategy Interpretation")
    lines.append("")
    lines.append("- A candidate that is broad-strong but focus-weak should be treated as an anti-Fighting lane, not as proof it solves the whole metagame.")
    lines.append("- A candidate that is focus-strong but broad-mid is a latest-two partner candidate when Alakazam control weight rises.")
    lines.append("- If broad and focus disagree, prefer a pair that covers both axes instead of submitting two policies with the same failure mode.")
    lines.append("")
    return lines


def render_report(
    cards: dict[int, Card],
    replay_groups: list[DeckGroup],
    agent_profiles: list[DeckProfile],
    top_groups: int,
    replay_paths: list[Path],
    duplicate_count: int,
    args: argparse.Namespace,
    broad_results: dict[str, SimulationResult],
    focus_results: dict[str, SimulationResult],
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Card-Pool Strategy Research")
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
    lines.append(f"- Replay files requested: {len(replay_paths)}; duplicate episode files ignored: {duplicate_count}")
    lines.append("- Strategic scope: card-pool metadata plus public replay deck shells; simulator win rates should be read alongside this, not as a replacement.")
    lines.append("")

    lines.append("## Strategic Thesis")
    lines.append("")
    lines.append("- The current top window is not a single-deck problem. It is a triangle of Psychic Alakazam control, Fighting Mega Lucario pressure, and Alakazam mirror tech such as Battle Cage, Nighttime Mine, Enhanced Hammer, and plain high-consistency lists.")
    lines.append("- Type balance matters: Psychic Alakazam naturally pressures Mega Lucario's Psychic weakness, Mega Lucario pressures Lightning-type Iono shells through Fighting damage, and Dark/Grass/Fire weakness pockets create tail risk for Psychic, Fighting, and Crustle families.")
    lines.append("- The strongest submission pair should cover different strategic failure modes. Two exact hiroingk-style Hammer Alakazam policies share the same blind spots; pairing one with plain Alakazam or Nighttime/Battle-Cage diversity is more robust for the latest-two window.")
    lines.append("")

    top_replay_groups = replay_groups[:top_groups]
    lines.append("## Strategic Pressure Lanes")
    lines.append("")
    lines.append("| Rank | Lane | Weighted Wins | Representative Clusters | Strategic Requirement |")
    lines.append("| ---: | --- | ---: | --- | --- |")
    for index, (lane, weight, examples, requirement) in enumerate(lane_summary(top_replay_groups), 1):
        lines.append(f"| {index} | {lane} | {weight:.2f} | {examples} | {requirement} |")
    lines.append("")

    lines.append("## Replay-Derived Top Strategy Clusters")
    lines.append("")
    lines.append("| Rank | Archetype | Hash | Weighted Wins | Seen/Wins | Teams | Type | Weak To | Core Tags |")
    lines.append("| ---: | --- | --- | ---: | --- | --- | --- | --- | --- |")
    profiles_by_key: dict[str, DeckProfile] = {}
    for index, group in enumerate(top_replay_groups, 1):
        profile = profile_deck(group.key, group.deck, cards)
        profiles_by_key[group.key] = profile
        teams = ", ".join(team for team, _ in group.teams.most_common(3))
        lines.append(
            f"| {index} | {group.archetype} | `{group.deck_hash}` | {group.weighted_wins:.2f} | "
            f"{group.seen}/{group.wins} | {teams} | {top_items(profile.type_counts, 2)} | "
            f"{top_items(profile.weakness_counts, 2)} | {format_tag_examples(profile, 5)} |"
        )
    lines.append("")

    lines.append("## Candidate Strategy Profiles")
    lines.append("")
    lines.append("| Candidate | Archetype | Hash | P/T/E | Type | Weak To | Max Dmg | Avg Cost | Special E | Core Tags | Top Cards |")
    lines.append("| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |")
    for profile in agent_profiles:
        lines.append(
            f"| {profile.label} | {profile.archetype} | `{profile.deck_hash}` | "
            f"{profile.pokemon_count}/{profile.trainer_count}/{profile.energy_count} | "
            f"{top_items(profile.type_counts, 2)} | {top_items(profile.weakness_counts, 2)} | "
            f"{profile.max_damage} | {profile.average_attack_cost:.2f} | {profile.special_energy_count} | "
            f"{format_tag_examples(profile, 6)} | {top_cards(profile, cards, 5)} |"
        )
    lines.append("")

    lines.append("## Candidate vs Top-Cluster Metadata Edges")
    lines.append("")
    for candidate in agent_profiles:
        lines.append(f"### {candidate.label}")
        lines.append("")
        for group in top_replay_groups[:8]:
            opponent = profiles_by_key[group.key]
            notes = "; ".join(matchup_notes(candidate, opponent))
            lines.append(f"- vs {group.archetype} `{group.deck_hash}` ({', '.join(team for team, _ in group.teams.most_common(2))}): {notes}.")
        lines.append("")

    lines.extend(render_simulation_section(agent_profiles, broad_results, focus_results))

    lines.append("## Strategic Build Rules From Current Card Pool")
    lines.append("")
    lines.append("1. **Preserve a Psychic plan into Fighting.** Mega Lucario is still a dominant public pressure source, and Psychic Alakazam-style attackers have the cleanest metadata edge into its weakness.")
    lines.append("2. **Do not treat all Alakazam as equivalent.** Hammer Alakazam pressures Special Energy, plain Alakazam trades denial for consistency, Battle Cage Alakazam shields bench-counter plans, and Nighttime Mine/Hammer taxes Tera/Mega tempo.")
    lines.append("3. **Respect Special Energy exposure.** Telepath Psychic Energy and other Special Energy packages are powerful but make Enhanced Hammer mirrors more decisive.")
    lines.append("4. **Protect the latest-two window through strategic diversity.** The second submission should cover a different axis than the first unless fresh evidence shows a huge same-shell edge.")
    lines.append("5. **Use simulator screens as tactical checks, not the source of truth.** Public v39/v48 showed that high local win rates can be misleading when policy mismatch or public-meta drift changes live scoring.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="*", type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--agent", action="append", type=Path, default=[])
    parser.add_argument("--top-groups", type=int, default=12)
    parser.add_argument("--winners-only", action="store_true")
    parser.add_argument("--rank-weighting", action="store_true")
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--broad-gauntlet", type=Path)
    parser.add_argument("--focus-gauntlet", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    cards = load_cards(args.cards)
    replay_paths = sorted(args.replays)
    observations, duplicate_count = load_replay_observations(replay_paths, not args.no_dedupe, args.rank_weighting)
    replay_groups = group_observations(observations, args.winners_only)

    agent_profiles: list[DeckProfile] = []
    for agent_path in args.agent:
        deck = read_agent_deck(agent_path)
        agent_profiles.append(profile_deck(agent_path.name, deck, cards))

    broad_results = parse_simulation_results(args.broad_gauntlet)
    focus_results = parse_simulation_results(args.focus_gauntlet)
    report = render_report(
        cards,
        replay_groups,
        agent_profiles,
        args.top_groups,
        replay_paths,
        duplicate_count,
        args,
        broad_results,
        focus_results,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
