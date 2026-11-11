#!/usr/bin/env python3
"""Compare candidate policies against public replay decisions.

This is a critic signal, not a submission selector.  It answers a narrow
question: when a candidate is shown the same public decision states as a trusted
anchor, does it preserve or degrade agreement with observed public actions?

The script intentionally supports a worker mode so each agent is loaded in a
fresh Python process.  That avoids module-cache leakage between bundles that
ship their own ``cg`` package.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_ml_replay_dataset import AREA_NAMES, CONTEXT_NAMES, OPTION_NAMES  # noqa: E402
from run_local_battle import load_agent  # noqa: E402

DUNSPARCE_IDS = {65, 305}
DUDUNSPARCE_ID = 66
PSYCHIC_ENERGY_IDS = {5, 19}
ABRA_ID = 741
KADABRA_ID = 742
ALAKAZAM_ID = 743
PSYCHIC_LINE_IDS = {ABRA_ID, KADABRA_ID, ALAKAZAM_ID}
HIGH_VALUE_SETUP_PLAY_IDS = {1079, 1086, 1152, 1225, 1231}


@dataclass
class ContextStats:
    total: int = 0
    same: int = 0
    diff: int = 0
    invalid: int = 0

    @property
    def same_rate(self) -> float:
        return self.same / self.total if self.total else 0.0

    @property
    def usable_total(self) -> int:
        return self.total - self.invalid


def now_human() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def enum_name(mapping: dict[int, str], value: Any) -> str:
    try:
        return mapping.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def replay_id(path: Path) -> str:
    match = re.search(r"episode-(\d+)-replay\.json$", path.name)
    return match.group(1) if match else path.stem


def unique_replay_paths(paths: list[Path]) -> tuple[list[Path], int]:
    seen: set[str] = set()
    unique: list[Path] = []
    duplicates = 0
    for path in sorted(paths):
        key = replay_id(path)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(path)
    return unique, duplicates


def public_action_for_observation(steps: list[Any], step_index: int, slot: int) -> Any:
    """Return the public action responding to steps[step_index][slot].

    Kaggle replay rows pair a selectable observation at step t with the action
    chosen for that observation on step t + 1 for the same seat.
    """
    next_index = step_index + 1
    if next_index >= len(steps):
        return None
    try:
        return steps[next_index][slot].get("action")
    except (AttributeError, IndexError, TypeError):
        return None


def decision_state_key(obs: dict[str, Any]) -> str:
    current = dict(obs.get("current") or {})
    current.pop("result", None)
    return json.dumps(
        {"current": current, "select": obs.get("select") or {}},
        sort_keys=True,
        separators=(",", ":"),
    )


def valid_action(action: object, option_count: int, minimum: int, maximum: int) -> bool:
    if not isinstance(action, list):
        return False
    if not minimum <= len(action) <= maximum:
        return False
    return all(isinstance(item, int) and 0 <= item < option_count for item in action)


def load_names(path: Path) -> dict[int, str]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {int(row["Card ID"]): row["Card Name"] for row in csv.DictReader(handle)}


def card_id(card: Any) -> int | None:
    if isinstance(card, dict) and "id" in card:
        try:
            return int(card["id"])
        except (TypeError, ValueError):
            return None
    return None


def raw_card_id(card: Any) -> int | None:
    if isinstance(card, dict):
        return card_id(card)
    try:
        return int(getattr(card, "id"))
    except (TypeError, ValueError, AttributeError):
        return None


def observed_player_card_ids(obs: dict[str, Any]) -> set[int]:
    current = obs.get("current") or {}
    your_index = current.get("yourIndex")
    players = current.get("players") or []
    if not isinstance(your_index, int) or your_index < 0 or your_index >= len(players):
        return set()
    player = players[your_index] or {}
    ids: set[int] = set()
    for zone in ("hand", "discard", "active", "bench"):
        for card in player.get(zone) or []:
            cid = raw_card_id(card)
            if cid is not None:
                ids.add(cid)
    return ids


def get_option_card_id(obs: dict[str, Any], option: dict[str, Any]) -> int | None:
    area = option.get("area")
    index = option.get("index")
    current = obs.get("current") or {}
    player_index = option.get("playerIndex", current.get("yourIndex"))
    try:
        if area == 1:
            card = (obs.get("select") or {}).get("deck", [])[index]
        elif area == 2:
            card = current["players"][player_index]["hand"][index]
        elif area == 3:
            card = current["players"][player_index]["discard"][index]
        elif area == 4:
            card = current["players"][player_index]["active"][index]
        elif area == 5:
            card = current["players"][player_index]["bench"][index]
        elif area == 12:
            card = current.get("looking", [])[index]
        else:
            card = None
    except Exception:
        return None
    return card_id(card)


def get_card_from_area(obs: dict[str, Any], area: Any, index: Any, player_index: Any) -> Any:
    current = obs.get("current") or {}
    try:
        area_int = int(area)
        index_int = int(index)
        player_int = int(player_index)
    except (TypeError, ValueError):
        return None
    try:
        if area_int == 1:
            return (obs.get("select") or {}).get("deck", [])[index_int]
        if area_int == 2:
            return current["players"][player_int]["hand"][index_int]
        if area_int == 3:
            return current["players"][player_int]["discard"][index_int]
        if area_int == 4:
            return current["players"][player_int]["active"][index_int]
        if area_int == 5:
            return current["players"][player_int]["bench"][index_int]
        if area_int == 12:
            return current.get("looking", [])[index_int]
    except Exception:
        return None
    return None


def get_option_target_card(obs: dict[str, Any], option: dict[str, Any]) -> Any:
    current = obs.get("current") or {}
    player_index = option.get("playerIndex", current.get("yourIndex"))
    return get_card_from_area(obs, option.get("inPlayArea"), option.get("inPlayIndex"), player_index)


def option_description(obs: dict[str, Any], option_index: int, names: dict[int, str]) -> str:
    options = (obs.get("select") or {}).get("option") or []
    if not 0 <= option_index < len(options):
        return f"{option_index}:out"
    option = options[option_index]
    parts = [f"{option_index}:{enum_name(OPTION_NAMES, option.get('type'))}"]
    cid = get_option_card_id(obs, option)
    if cid is not None:
        parts.append(f"{names.get(cid, cid)}({cid})")
    if "attackId" in option:
        parts.append(f"attack={option.get('attackId')}")
    if "inPlayArea" in option:
        parts.append(f"to={enum_name(AREA_NAMES, option.get('inPlayArea'))}:{option.get('inPlayIndex')}")
    return " ".join(parts)


def action_descriptions(obs: dict[str, Any], action: list[int] | None, names: dict[int, str]) -> list[str]:
    return [option_description(obs, index, names) for index in (action or [])]


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def remaining_prizes(obs: dict[str, Any]) -> int | None:
    current = obs.get("current") or {}
    your_index = current.get("yourIndex")
    players = current.get("players") or []
    if not isinstance(your_index, int) or your_index < 0 or your_index >= len(players):
        return None
    prizes = (players[your_index] or {}).get("prize")
    return len(prizes) if isinstance(prizes, list) else None


def current_player(obs: dict[str, Any]) -> dict[str, Any]:
    current = obs.get("current") or {}
    your_index = current.get("yourIndex")
    players = current.get("players") or []
    if not isinstance(your_index, int) or your_index < 0 or your_index >= len(players):
        return {}
    player = players[your_index] or {}
    return player if isinstance(player, dict) else {}


def zone_card_ids(player: dict[str, Any], zone: str) -> list[int]:
    ids: list[int] = []
    for card in player.get(zone) or []:
        cid = raw_card_id(card)
        if cid is not None:
            ids.append(cid)
    return ids


def nonempty_zone_cards(player: dict[str, Any], zone: str) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for card in player.get(zone) or []:
        if isinstance(card, dict) and raw_card_id(card) is not None:
            cards.append(card)
    return cards


def card_int(card: dict[str, Any], key: str) -> int | None:
    try:
        value = card.get(key)
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def min_hp(cards: list[dict[str, Any]]) -> int | str:
    values = [hp for card in cards if (hp := card_int(card, "hp")) is not None]
    return min(values) if values else ""


def max_damage(cards: list[dict[str, Any]]) -> int | str:
    damages: list[int] = []
    for card in cards:
        hp = card_int(card, "hp")
        max_hp = card_int(card, "maxHp")
        if hp is not None and max_hp is not None:
            damages.append(max(0, max_hp - hp))
    return max(damages) if damages else ""


def attached_energy_count(cards: list[dict[str, Any]]) -> int:
    total = 0
    for card in cards:
        energies = card.get("energies")
        energy_cards = card.get("energyCards")
        if isinstance(energies, list):
            total += len(energies)
        elif isinstance(energy_cards, list):
            total += len(energy_cards)
    return total


def other_player(obs: dict[str, Any]) -> dict[str, Any]:
    current = obs.get("current") or {}
    your_index = current.get("yourIndex")
    players = current.get("players") or []
    if not isinstance(your_index, int):
        return {}
    for index, player in enumerate(players):
        if index != your_index and isinstance(player, dict):
            return player
    return {}


def available_option_facts(obs: dict[str, Any]) -> dict[str, Any]:
    options = (obs.get("select") or {}).get("option") or []
    counts: Counter[str] = Counter()
    attack_ids: set[int] = set()
    active_psychic_attach_target_ids: set[int] = set()
    has_dudunsparce_ability_option = False
    has_active_psychic_attach_option = False
    high_value_setup_play_count = 0
    psychic_line_evolve_count = 0
    dudunsparce_evolve_count = 0
    active_psychic_attach_to_psychic_line_count = 0
    active_psychic_attach_to_zero_energy_psychic_line_count = 0
    for option in options:
        option_type = enum_name(OPTION_NAMES, option.get("type"))
        counts[option_type] += 1
        if option_type == "ATTACK" and "attackId" in option:
            try:
                attack_ids.add(int(option.get("attackId")))
            except (TypeError, ValueError):
                pass
        cid = get_option_card_id(obs, option)
        if option_type == "PLAY" and cid in HIGH_VALUE_SETUP_PLAY_IDS:
            high_value_setup_play_count += 1
        if option_type == "EVOLVE":
            if cid in {KADABRA_ID, ALAKAZAM_ID}:
                psychic_line_evolve_count += 1
            if cid == DUDUNSPARCE_ID:
                dudunsparce_evolve_count += 1
        if option_type == "ABILITY" and cid == DUDUNSPARCE_ID:
            has_dudunsparce_ability_option = True
        target_area = enum_name(AREA_NAMES, option.get("inPlayArea"))
        if option_type == "ATTACH" and cid in PSYCHIC_ENERGY_IDS and target_area == "ACTIVE":
            has_active_psychic_attach_option = True
            target = get_option_target_card(obs, option)
            target_id = raw_card_id(target)
            if target_id is not None:
                active_psychic_attach_target_ids.add(target_id)
            if target_id in PSYCHIC_LINE_IDS:
                active_psychic_attach_to_psychic_line_count += 1
                if isinstance(target, dict) and attached_energy_count([target]) == 0:
                    active_psychic_attach_to_zero_energy_psychic_line_count += 1
    material_psychic_setup_option_count = high_value_setup_play_count + psychic_line_evolve_count
    material_setup_or_play_option_count = (
        material_psychic_setup_option_count
        + dudunsparce_evolve_count
        + (1 if has_dudunsparce_ability_option else 0)
    )
    return {
        "option_count": len(options),
        "available_attack_count": counts["ATTACK"],
        "available_ability_count": counts["ABILITY"],
        "available_attach_count": counts["ATTACH"],
        "available_play_count": counts["PLAY"],
        "available_evolve_count": counts["EVOLVE"],
        "available_end_count": counts["END"] + counts["PASS"],
        "available_attack_ids": ",".join(str(attack_id) for attack_id in sorted(attack_ids)),
        "has_dudunsparce_ability_option": has_dudunsparce_ability_option,
        "has_active_psychic_attach_option": has_active_psychic_attach_option,
        "available_high_value_setup_play_count": high_value_setup_play_count,
        "available_psychic_line_evolve_count": psychic_line_evolve_count,
        "available_dudunsparce_evolve_count": dudunsparce_evolve_count,
        "material_psychic_setup_option_count": material_psychic_setup_option_count,
        "material_setup_or_play_option_count": material_setup_or_play_option_count,
        "has_material_psychic_setup_option": material_psychic_setup_option_count > 0,
        "has_material_setup_or_play_option": material_setup_or_play_option_count > 0,
        "active_psychic_attach_target_ids": ",".join(
            str(cid) for cid in sorted(active_psychic_attach_target_ids)
        ),
        "active_psychic_attach_to_psychic_line_count": active_psychic_attach_to_psychic_line_count,
        "active_psychic_attach_to_zero_energy_psychic_line_count": (
            active_psychic_attach_to_zero_energy_psychic_line_count
        ),
        "has_active_psychic_attach_to_psychic_line_option": active_psychic_attach_to_psychic_line_count > 0,
        "has_active_psychic_attach_to_zero_energy_psychic_line_option": (
            active_psychic_attach_to_zero_energy_psychic_line_count > 0
        ),
    }


def action_type_names(obs: dict[str, Any], action: list[int] | None) -> set[str]:
    options = (obs.get("select") or {}).get("option") or []
    names: set[str] = set()
    for index in action or []:
        if not isinstance(index, int) or not 0 <= index < len(options):
            continue
        names.add(enum_name(OPTION_NAMES, options[index].get("type")))
    return names


def action_option_facts(obs: dict[str, Any], action: list[int] | None) -> dict[str, Any]:
    options = (obs.get("select") or {}).get("option") or []
    types: set[str] = set()
    card_ids: set[int] = set()
    has_dudunsparce_ability = False
    has_active_psychic_attach = False
    has_attack = False
    has_end = False
    for index in action or []:
        if not isinstance(index, int) or not 0 <= index < len(options):
            continue
        option = options[index]
        option_type = enum_name(OPTION_NAMES, option.get("type"))
        types.add(option_type)
        cid = get_option_card_id(obs, option)
        if cid is not None:
            card_ids.add(cid)
        if option_type == "ABILITY" and cid == DUDUNSPARCE_ID:
            has_dudunsparce_ability = True
        if option_type == "ATTACK":
            has_attack = True
        if option_type in {"END", "PASS"}:
            has_end = True
        target_area = enum_name(AREA_NAMES, option.get("inPlayArea"))
        if option_type == "ATTACH" and cid in PSYCHIC_ENERGY_IDS and target_area == "ACTIVE":
            has_active_psychic_attach = True
    return {
        "types": types,
        "card_ids": card_ids,
        "has_dudunsparce_ability": has_dudunsparce_ability,
        "has_active_psychic_attach": has_active_psychic_attach,
        "has_attack": has_attack,
        "has_end": has_end,
    }


def flatten_descriptions(descriptions: list[str]) -> str:
    return " | ".join(descriptions)


def decision_features(
    obs: dict[str, Any],
    public_action: list[int],
    agent_action: list[int] | None,
    names: dict[int, str],
) -> dict[str, Any]:
    current = obs.get("current") or {}
    turn = int_value(current.get("turn"), 0)
    turn_action_count = int_value(current.get("turnActionCount"), 0)
    prizes_left = remaining_prizes(obs)
    player = current_player(obs)
    opponent = other_player(obs)
    active_ids = zone_card_ids(player, "active")
    bench_ids = zone_card_ids(player, "bench")
    active_cards = nonempty_zone_cards(player, "active")
    bench_cards = nonempty_zone_cards(player, "bench")
    opponent_active_cards = nonempty_zone_cards(opponent, "active")
    opponent_bench_cards = nonempty_zone_cards(opponent, "bench")
    active_count = len(active_ids)
    bench_count = len(bench_ids)
    active_dudunsparce = DUDUNSPARCE_ID in active_ids
    bench_dudunsparce = DUDUNSPARCE_ID in bench_ids
    active_dunsparce = any(cid in DUNSPARCE_IDS for cid in active_ids)
    bench_dunsparce = any(cid in DUNSPARCE_IDS for cid in bench_ids)
    public_facts = action_option_facts(obs, public_action)
    agent_facts = action_option_facts(obs, agent_action)
    public_desc = action_descriptions(obs, public_action, names)
    agent_desc = action_descriptions(obs, agent_action, names)
    available_facts = available_option_facts(obs)
    active_psychic_line = any(cid in PSYCHIC_LINE_IDS for cid in active_ids)
    active_zero_energy_psychic_line = active_psychic_line and attached_energy_count(active_cards) == 0
    active_attach_to_zero_energy_line = bool(
        available_facts["has_active_psychic_attach_to_zero_energy_psychic_line_option"]
    )
    setup_clear_active_attach_window = (
        active_zero_energy_psychic_line
        and active_attach_to_zero_energy_line
        and not bool(available_facts["has_material_setup_or_play_option"])
    )
    setup_contested_active_attach_window = (
        active_zero_energy_psychic_line
        and active_attach_to_zero_energy_line
        and bool(available_facts["has_material_setup_or_play_option"])
    )

    low_prize = prizes_left is not None and prizes_left <= 2
    critical_prize = prizes_left is not None and prizes_left <= 1
    has_dudun_board = active_dudunsparce or bench_dudunsparce
    dudun_action_side = (
        "both"
        if public_facts["has_dudunsparce_ability"] and agent_facts["has_dudunsparce_ability"]
        else "public"
        if public_facts["has_dudunsparce_ability"]
        else "agent"
        if agent_facts["has_dudunsparce_ability"]
        else "none"
    )
    psychic_attach_side = (
        "both"
        if public_facts["has_active_psychic_attach"] and agent_facts["has_active_psychic_attach"]
        else "public"
        if public_facts["has_active_psychic_attach"]
        else "agent"
        if agent_facts["has_active_psychic_attach"]
        else "none"
    )
    attack_side = (
        "both"
        if public_facts["has_attack"] and agent_facts["has_attack"]
        else "public"
        if public_facts["has_attack"]
        else "agent"
        if agent_facts["has_attack"]
        else "none"
    )

    return {
        "turn": turn,
        "turn_action_count": turn_action_count,
        "prizes_left": "" if prizes_left is None else prizes_left,
        "low_prize": low_prize,
        "critical_prize": critical_prize,
        "late_turn": turn >= 8,
        "very_late_turn": turn >= 12,
        "active_count": active_count,
        "bench_count": bench_count,
        "hand_count": int_value(player.get("handCount"), len(player.get("hand") or [])),
        "deck_count": int_value(player.get("deckCount"), 0),
        "discard_count": len(player.get("discard") or []),
        "active_ids": ",".join(str(cid) for cid in active_ids),
        "bench_ids": ",".join(str(cid) for cid in bench_ids),
        "own_active_min_hp": min_hp(active_cards),
        "own_active_max_damage": max_damage(active_cards),
        "own_active_energy_count": attached_energy_count(active_cards),
        "own_bench_min_hp": min_hp(bench_cards),
        "own_bench_max_damage": max_damage(bench_cards),
        "own_bench_energy_count": attached_energy_count(bench_cards),
        "opponent_active_count": len(opponent_active_cards),
        "opponent_bench_count": len(opponent_bench_cards),
        "opponent_active_ids": ",".join(str(cid) for cid in zone_card_ids(opponent, "active")),
        "opponent_active_min_hp": min_hp(opponent_active_cards),
        "opponent_active_max_damage": max_damage(opponent_active_cards),
        "opponent_active_energy_count": attached_energy_count(opponent_active_cards),
        "active_dudunsparce": active_dudunsparce,
        "bench_dudunsparce": bench_dudunsparce,
        "active_dunsparce": active_dunsparce,
        "bench_dunsparce": bench_dunsparce,
        "active_psychic_line": active_psychic_line,
        "active_zero_energy_psychic_line": active_zero_energy_psychic_line,
        "setup_clear_active_attach_window": setup_clear_active_attach_window,
        "setup_contested_active_attach_window": setup_contested_active_attach_window,
        "public_setup_clear_active_psychic_attach": (
            setup_clear_active_attach_window and public_facts["has_active_psychic_attach"]
        ),
        "agent_setup_clear_active_psychic_attach": (
            setup_clear_active_attach_window and agent_facts["has_active_psychic_attach"]
        ),
        "public_setup_contested_active_psychic_attach": (
            setup_contested_active_attach_window and public_facts["has_active_psychic_attach"]
        ),
        "agent_setup_contested_active_psychic_attach": (
            setup_contested_active_attach_window and agent_facts["has_active_psychic_attach"]
        ),
        "has_dudunsparce_board": has_dudun_board,
        "dudunsparce_solo_active": active_dudunsparce and bench_count == 0,
        "dudunsparce_active_with_bench": active_dudunsparce and bench_count > 0,
        "dudunsparce_bench_with_active": bench_dudunsparce and active_count > 0,
        "public_has_dudunsparce_ability": public_facts["has_dudunsparce_ability"],
        "agent_has_dudunsparce_ability": agent_facts["has_dudunsparce_ability"],
        "dudunsparce_ability_side": dudun_action_side,
        "public_active_psychic_attach": public_facts["has_active_psychic_attach"],
        "agent_active_psychic_attach": agent_facts["has_active_psychic_attach"],
        "active_psychic_attach_side": psychic_attach_side,
        "public_attack": public_facts["has_attack"],
        "agent_attack": agent_facts["has_attack"],
        "attack_side": attack_side,
        "public_end": public_facts["has_end"],
        "agent_end": agent_facts["has_end"],
        "public_action_types": "|".join(sorted(public_facts["types"])),
        "agent_action_types": "|".join(sorted(agent_facts["types"])),
        "public_action_card_ids": ",".join(str(cid) for cid in sorted(public_facts["card_ids"])),
        "agent_action_card_ids": ",".join(str(cid) for cid in sorted(agent_facts["card_ids"])),
        "public_desc_flat": flatten_descriptions(public_desc),
        "agent_desc_flat": flatten_descriptions(agent_desc),
        **available_facts,
    }


def decision_weight(obs: dict[str, Any], public_action: list[int]) -> float:
    """Small, explainable importance weight for changed public-action decisions.

    Late-game and low-prize decisions have a larger public-score impact than
    setup turns, and ATTACK choices are often irreversible. This is deliberately
    coarse: it is a critic weight, not a learned value model.
    """
    current = obs.get("current") or {}
    turn = int_value(current.get("turn"), 0)
    weight = 1.0
    if turn >= 8:
        weight += 0.5
    if turn >= 12:
        weight += 0.5

    prizes_left = remaining_prizes(obs)
    if prizes_left is not None:
        if prizes_left <= 2:
            weight += 0.75
        if prizes_left <= 1:
            weight += 0.75

    action_types = action_type_names(obs, public_action)
    if "ATTACK" in action_types:
        weight += 0.5
    return weight


def decision_record(
    *,
    replay_path: Path,
    step_index: int,
    slot: int,
    team: str,
    context: str,
    public_action: list[int],
    agent_action: list[int] | None,
    obs: dict[str, Any],
    names: dict[int, str],
    same: bool,
    valid: bool,
) -> dict[str, Any]:
    public_desc = action_descriptions(obs, public_action, names)
    agent_desc = action_descriptions(obs, agent_action, names)
    return {
        "key": f"{replay_id(replay_path)}:{step_index}:{slot}:{context}",
        "replay": replay_path.name,
        "step": step_index,
        "public_action_step": step_index + 1,
        "slot": slot,
        "team": team,
        "context": context,
        "public_action": public_action,
        "agent_action": agent_action,
        "same": same,
        "valid": valid,
        "public_desc": public_desc,
        "agent_desc": agent_desc,
        "weight": decision_weight(obs, public_action),
        **decision_features(obs, public_action, agent_action, names),
    }


def sample_example(
    examples: list[dict[str, Any]],
    *,
    replay_path: Path,
    step_index: int,
    team: str,
    context: str,
    public_action: list[int],
    agent_action: list[int] | None,
    obs: dict[str, Any],
    names: dict[int, str],
    limit: int,
) -> None:
    if len(examples) >= limit:
        return
    options = (obs.get("select") or {}).get("option") or []
    examples.append(
        {
            "replay": replay_path.name,
            "step": step_index,
            "public_action_step": step_index + 1,
            "team": team,
            "context": context,
            "public_action": public_action,
            "agent_action": agent_action,
            "public_desc": action_descriptions(obs, public_action, names),
            "agent_desc": action_descriptions(obs, agent_action, names),
            "option_count": len(options),
        }
    )


def worker_compare(args: argparse.Namespace) -> int:
    names = load_names(args.cards)
    agent, deck = load_agent(args.worker_agent, args.worker_label)
    deck_ids = {int(cid) for cid in deck}
    target_teams = set(args.team or [])
    target_contexts = set(args.context or [])
    replay_paths, duplicates = unique_replay_paths(args.replays)
    if args.max_replays > 0:
        replay_paths = replay_paths[: args.max_replays]

    stats: dict[str, ContextStats] = defaultdict(ContextStats)
    examples: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    loaded = 0
    skipped_errors = 0
    skipped_deck_overlap = 0
    for replay_path in replay_paths:
        try:
            data = json.loads(replay_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            skipped_errors += 1
            continue
        loaded += 1
        teams = data.get("info", {}).get("TeamNames", [])
        steps = data.get("steps") or []
        seen_decision_states: set[tuple[int, str]] = set()
        for step_index, step in enumerate(steps):
            for slot, record in enumerate(step):
                team = teams[slot] if slot < len(teams) else str(slot)
                if target_teams and team not in target_teams:
                    continue
                obs = record.get("observation") or {}
                select = obs.get("select") or {}
                if not select:
                    continue
                state_key = (slot, decision_state_key(obs))
                if state_key in seen_decision_states:
                    continue
                seen_decision_states.add(state_key)
                options = select.get("option") or []
                action = public_action_for_observation(steps, step_index, slot)
                minimum = int(select.get("minCount", 0) or 0)
                maximum = int(select.get("maxCount", len(options)) or len(options))
                if not options or not valid_action(action, len(options), minimum, maximum):
                    continue
                if isinstance(action, list) and len(action) == 60:
                    continue
                context = enum_name(CONTEXT_NAMES, select.get("context"))
                if target_contexts and context not in target_contexts:
                    continue
                deck_overlap = len(observed_player_card_ids(obs) & deck_ids)
                if args.min_agent_deck_overlap > 0 and deck_overlap < args.min_agent_deck_overlap:
                    skipped_deck_overlap += 1
                    continue
                for key in ("ALL", context):
                    stats[key].total += 1
                try:
                    ours = agent(obs)
                except Exception:
                    ours = None
                if not valid_action(ours, len(options), minimum, maximum):
                    decisions.append(
                        decision_record(
                            replay_path=replay_path,
                            step_index=step_index,
                            slot=slot,
                            team=team,
                            context=context,
                            public_action=action,
                            agent_action=None,
                            obs=obs,
                            names=names,
                            same=False,
                            valid=False,
                        )
                    )
                    for key in ("ALL", context):
                        stats[key].invalid += 1
                        stats[key].diff += 1
                    sample_example(
                        examples,
                        replay_path=replay_path,
                        step_index=step_index,
                        team=team,
                        context=context,
                        public_action=action,
                        agent_action=None,
                        obs=obs,
                        names=names,
                        limit=args.examples,
                    )
                    continue
                same = action == ours
                decisions.append(
                    decision_record(
                        replay_path=replay_path,
                        step_index=step_index,
                        slot=slot,
                        team=team,
                        context=context,
                        public_action=action,
                        agent_action=ours,
                        obs=obs,
                        names=names,
                        same=same,
                        valid=True,
                    )
                )
                for key in ("ALL", context):
                    if same:
                        stats[key].same += 1
                    else:
                        stats[key].diff += 1
                if not same:
                    sample_example(
                        examples,
                        replay_path=replay_path,
                        step_index=step_index,
                        team=team,
                        context=context,
                        public_action=action,
                        agent_action=ours,
                        obs=obs,
                        names=names,
                        limit=args.examples,
                    )

    payload = {
        "label": args.worker_label,
        "agent": str(args.worker_agent),
        "loaded_replays": loaded,
        "duplicate_replays": duplicates,
        "skipped_replay_errors": skipped_errors,
        "skipped_deck_overlap": skipped_deck_overlap,
        "min_agent_deck_overlap": args.min_agent_deck_overlap,
        "action_alignment": "observation_step_t_to_action_step_t_plus_1",
        "stats": {
            key: {
                "total": value.total,
                "same": value.same,
                "diff": value.diff,
                "invalid": value.invalid,
                "same_rate": value.same_rate,
                "usable_total": value.usable_total,
            }
            for key, value in sorted(stats.items())
        },
        "examples": examples,
        "decisions": decisions,
    }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def parse_agent_spec(spec: str) -> tuple[str, Path]:
    if "=" in spec:
        label, path_text = spec.split("=", 1)
    else:
        path = Path(spec)
        label, path_text = path.name, spec
    path = Path(path_text)
    if not path.is_absolute():
        path = REPO / path
    return label, path


def run_worker(args: argparse.Namespace, label: str, path: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--worker",
        "--worker-label",
        label,
        "--worker-agent",
        str(path),
        "--cards",
        str(args.cards),
        "--examples",
        str(args.examples),
        "--max-replays",
        str(args.max_replays),
        "--min-agent-deck-overlap",
        str(args.min_agent_deck_overlap),
    ]
    for context in args.context or []:
        command.extend(["--context", context])
    for team in args.team or []:
        command.extend(["--team", team])
    command.extend(str(path) for path in args.replays)
    result = subprocess.run(command, cwd=REPO, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return {
            "label": label,
            "agent": str(path),
            "error": result.stderr.strip() or result.stdout.strip() or f"worker exited {result.returncode}",
            "stats": {},
            "examples": [],
            "skipped_deck_overlap": 0,
        }
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "label": label,
            "agent": str(path),
            "error": "worker did not emit JSON",
            "stats": {},
            "examples": [],
            "skipped_deck_overlap": 0,
        }


def context_stat(payload: dict[str, Any], context: str) -> dict[str, Any]:
    stats = payload.get("stats") or {}
    return stats.get(context) or {"total": 0, "same": 0, "diff": 0, "invalid": 0, "same_rate": 0.0, "usable_total": 0}


def decision_map(payload: dict[str, Any], context: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for decision in payload.get("decisions") or []:
        if context != "ALL" and decision.get("context") != context:
            continue
        key = str(decision.get("key") or "")
        if key:
            out[key] = decision
    return out


def action_tuple(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, list):
        return None
    try:
        return tuple(int(item) for item in value)
    except (TypeError, ValueError):
        return None


def baseline_delta_rows(
    payloads: list[dict[str, Any]],
    *,
    baseline_label: str,
    gate_labels: set[str],
    context: str,
) -> dict[str, dict[str, int]]:
    baseline = next((payload for payload in payloads if payload.get("label") == baseline_label), None)
    baseline_by_key = decision_map(baseline or {}, context)
    rows: dict[str, dict[str, int]] = {}
    for payload in payloads:
        label = str(payload.get("label") or "")
        if label not in gate_labels:
            continue
        changed = fixes = regressions = neutral = shared = 0
        weighted_changed = weighted_fixes = weighted_regressions = weighted_neutral = 0.0
        for key, candidate_decision in decision_map(payload, context).items():
            baseline_decision = baseline_by_key.get(key)
            if baseline_decision is None:
                continue
            shared += 1
            candidate_action = action_tuple(candidate_decision.get("agent_action"))
            baseline_action = action_tuple(baseline_decision.get("agent_action"))
            if candidate_action == baseline_action:
                continue
            changed += 1
            weight = float(candidate_decision.get("weight") or baseline_decision.get("weight") or 1.0)
            weighted_changed += weight
            baseline_same = bool(baseline_decision.get("same"))
            candidate_same = bool(candidate_decision.get("same"))
            if candidate_same and not baseline_same:
                fixes += 1
                weighted_fixes += weight
            elif baseline_same and not candidate_same:
                regressions += 1
                weighted_regressions += weight
            else:
                neutral += 1
                weighted_neutral += weight
        rows[label] = {
            "shared": shared,
            "changed": changed,
            "fixes": fixes,
            "regressions": regressions,
            "neutral": neutral,
            "net": fixes - regressions,
            "weighted_changed": weighted_changed,
            "weighted_fixes": weighted_fixes,
            "weighted_regressions": weighted_regressions,
            "weighted_neutral": weighted_neutral,
            "weighted_net": weighted_fixes - weighted_regressions,
        }
    return rows


def baseline_delta_examples(
    payloads: list[dict[str, Any]],
    *,
    baseline_label: str,
    gate_labels: set[str],
    context: str,
    limit: int,
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    baseline = next((payload for payload in payloads if payload.get("label") == baseline_label), None)
    baseline_by_key = decision_map(baseline or {}, context)
    out: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for payload in payloads:
        label = str(payload.get("label") or "")
        if label not in gate_labels:
            continue
        buckets: dict[str, list[dict[str, Any]]] = {"fixes": [], "regressions": [], "neutral": []}
        for key, candidate_decision in decision_map(payload, context).items():
            baseline_decision = baseline_by_key.get(key)
            if baseline_decision is None:
                continue
            candidate_action = action_tuple(candidate_decision.get("agent_action"))
            baseline_action = action_tuple(baseline_decision.get("agent_action"))
            if candidate_action == baseline_action:
                continue
            baseline_same = bool(baseline_decision.get("same"))
            candidate_same = bool(candidate_decision.get("same"))
            if candidate_same and not baseline_same:
                bucket = "fixes"
            elif baseline_same and not candidate_same:
                bucket = "regressions"
            else:
                bucket = "neutral"
            if len(buckets[bucket]) >= limit:
                continue
            buckets[bucket].append(
                {
                    "replay": candidate_decision.get("replay", ""),
                    "step": candidate_decision.get("step", ""),
                    "team": candidate_decision.get("team", ""),
                    "context": candidate_decision.get("context", ""),
                    "public_desc": candidate_decision.get("public_desc") or baseline_decision.get("public_desc") or [],
                    "baseline_desc": baseline_decision.get("agent_desc") or [],
                    "candidate_desc": candidate_decision.get("agent_desc") or [],
                    "baseline_same": baseline_same,
                    "candidate_same": candidate_same,
                    "weight": float(candidate_decision.get("weight") or baseline_decision.get("weight") or 1.0),
                }
            )
        out[label] = buckets
    return out


def write_csv(path: Path, payloads: list[dict[str, Any]], contexts: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["label", "agent", "context", "total", "same", "diff", "invalid", "usable_total", "same_rate", "error"])
        for payload in payloads:
            for context in contexts:
                stats = context_stat(payload, context)
                writer.writerow(
                    [
                        payload.get("label", ""),
                        payload.get("agent", ""),
                        context,
                        stats.get("total", 0),
                        stats.get("same", 0),
                        stats.get("diff", 0),
                        stats.get("invalid", 0),
                        stats.get("usable_total", 0),
                        f"{float(stats.get('same_rate') or 0.0):.6f}",
                        payload.get("error", ""),
                    ]
                )


def csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def write_decisions_csv(path: Path, payloads: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    decision_keys = sorted(
        {
            key
            for payload in payloads
            for decision in payload.get("decisions") or []
            for key in decision
        }
    )
    fieldnames = ["label", "agent", "worker_error", *decision_keys]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for payload in payloads:
            for decision in payload.get("decisions") or []:
                row = {
                    "label": payload.get("label", ""),
                    "agent": payload.get("agent", ""),
                    "worker_error": payload.get("error", ""),
                }
                row.update({key: csv_value(value) for key, value in decision.items()})
                writer.writerow(row)


def render_report(args: argparse.Namespace, payloads: list[dict[str, Any]], contexts: list[str]) -> tuple[str, bool]:
    baseline = next((payload for payload in payloads if payload.get("label") == args.baseline_label), None)
    baseline_stats = context_stat(baseline or {}, args.gate_context) if baseline else None
    gate_labels = set(args.gate_label or [])
    if not gate_labels:
        gate_labels = {payload.get("label", "") for payload in payloads if payload.get("label") != args.baseline_label}
    delta_rows = baseline_delta_rows(
        payloads,
        baseline_label=args.baseline_label,
        gate_labels=gate_labels,
        context=args.gate_context,
    )
    delta_examples = baseline_delta_examples(
        payloads,
        baseline_label=args.baseline_label,
        gate_labels=gate_labels,
        context=args.gate_context,
        limit=args.delta_examples,
    )

    failures: list[str] = []
    if args.baseline_label and baseline is None:
        failures.append(f"baseline label `{args.baseline_label}` was not present")
    elif baseline_stats and int(baseline_stats.get("total") or 0) < args.min_compared:
        failures.append(
            f"baseline `{args.baseline_label}` has only {baseline_stats.get('total', 0)} "
            f"{args.gate_context} decisions; need >= {args.min_compared}"
        )

    for payload in payloads:
        label = str(payload.get("label") or "")
        if label not in gate_labels:
            continue
        stats = context_stat(payload, args.gate_context)
        total = int(stats.get("total") or 0)
        rate = float(stats.get("same_rate") or 0.0)
        if payload.get("error"):
            failures.append(f"`{label}` worker failed: {payload.get('error')}")
            continue
        if total < args.min_compared:
            failures.append(f"`{label}` has only {total} {args.gate_context} decisions; need >= {args.min_compared}")
            continue
        if rate < args.min_same_rate:
            failures.append(f"`{label}` same-rate {rate:.3f} < required {args.min_same_rate:.3f}")
        if baseline_stats and int(baseline_stats.get("total") or 0) >= args.min_compared:
            baseline_rate = float(baseline_stats.get("same_rate") or 0.0)
            if rate < baseline_rate - args.max_regression:
                failures.append(
                    f"`{label}` same-rate {rate:.3f} trails baseline `{args.baseline_label}` "
                    f"{baseline_rate:.3f} by more than {args.max_regression:.3f}"
                )
        delta = delta_rows.get(label)
        if delta and delta["net"] < -args.max_net_regressions:
            threshold = -args.max_net_regressions
            failures.append(
                f"`{label}` has negative public-action delta vs `{args.baseline_label}`: "
                f"fixes={delta['fixes']} regressions={delta['regressions']} "
                f"net={delta['net']} < {threshold}"
            )
        if delta and delta["weighted_net"] < -args.max_net_weighted_regression:
            threshold = -args.max_net_weighted_regression
            failures.append(
                f"`{label}` has negative weighted public-action delta vs `{args.baseline_label}`: "
                f"weighted_fixes={delta['weighted_fixes']:.2f} "
                f"weighted_regressions={delta['weighted_regressions']:.2f} "
                f"weighted_net={delta['weighted_net']:.2f} < {threshold:.2f}"
            )

    trusted = not failures
    lines = [
        "# Public Action Mismatch Gate",
        "",
        f"Generated: {now_human()}",
        "",
        "## Decision",
        "",
        f"- Trust decision: **{'PUBLIC ACTION GATE PASSED' if trusted else 'PUBLIC ACTION GATE FAILED'}**",
        f"- Gate context: `{args.gate_context}`",
        f"- Baseline label: `{args.baseline_label or '-'}`",
        f"- Minimum compared decisions: {args.min_compared}",
        f"- Minimum same-rate: {args.min_same_rate:.3f}",
        f"- Maximum regression vs baseline: {args.max_regression:.3f}",
        f"- Maximum net regressions vs baseline: {args.max_net_regressions}",
        f"- Maximum net weighted regression vs baseline: {args.max_net_weighted_regression:.2f}",
    ]
    for failure in failures:
        lines.append(f"- Blocker: {failure}")
    lines.extend(
        [
            "",
            "## Inputs",
            "",
            f"- Replays requested: {len(args.replays)}",
            f"- Max replays: {args.max_replays or 'all'}",
            f"- Context filters: {', '.join(args.context or []) or 'all'}",
            f"- Team filters: {', '.join(args.team or []) or 'all'}",
            f"- Minimum agent deck overlap: {args.min_agent_deck_overlap}",
            "",
            "## Worker Coverage",
            "",
            "| Label | Loaded replays | Duplicate replays | Skipped replay errors | Skipped low-overlap decisions |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for payload in payloads:
        lines.append(
            f"| `{payload.get('label', '')}` | {payload.get('loaded_replays', 0)} | "
            f"{payload.get('duplicate_replays', 0)} | {payload.get('skipped_replay_errors', 0)} | "
            f"{payload.get('skipped_deck_overlap', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Summary",
            "",
            "| Label | Context | Decisions | Same | Diff | Invalid | Same rate | Error |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for payload in payloads:
        for context in contexts:
            stats = context_stat(payload, context)
            lines.append(
                f"| `{payload.get('label', '')}` | {context} | {stats.get('total', 0)} | "
                f"{stats.get('same', 0)} | {stats.get('diff', 0)} | {stats.get('invalid', 0)} | "
                f"{float(stats.get('same_rate') or 0.0):.3f} | {payload.get('error', '-') or '-'} |"
            )
    lines.extend(
        [
            "",
            "## Baseline Delta",
            "",
            "| Label | Shared decisions | Changed from baseline | Fixes | Regressions | Neutral changes | Net | Weighted fixes | Weighted regressions | Weighted neutral | Weighted net |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for label, delta in sorted(delta_rows.items()):
        lines.append(
            f"| `{label}` | {delta['shared']} | {delta['changed']} | {delta['fixes']} | "
            f"{delta['regressions']} | {delta['neutral']} | {delta['net']} | "
            f"{delta['weighted_fixes']:.2f} | {delta['weighted_regressions']:.2f} | "
            f"{delta['weighted_neutral']:.2f} | {delta['weighted_net']:.2f} |"
        )
    lines.extend(["", "## Baseline Delta Examples", ""])
    lines.append(
        "These examples explain changed decisions relative to the baseline. A regression means the baseline matched the public action but the candidate did not; a fix means the candidate matched where the baseline did not."
    )
    lines.append("")
    for label, buckets in sorted(delta_examples.items()):
        if not any(buckets.values()):
            continue
        lines.append(f"### {label}")
        lines.append("")
        for bucket_name in ("regressions", "fixes", "neutral"):
            examples = buckets.get(bucket_name) or []
            if not examples:
                continue
            lines.append(f"#### {bucket_name.title()}")
            lines.append("")
            for example in examples:
                lines.append(
                    f"- `{example.get('replay')}` step={example.get('step')} team={example.get('team')} "
                    f"ctx={example.get('context')} public={example.get('public_desc')} "
                    f"baseline={example.get('baseline_desc')} candidate={example.get('candidate_desc')} "
                    f"weight={float(example.get('weight') or 1.0):.2f}"
                )
            lines.append("")
    lines.extend(["", "## Examples", ""])
    for payload in payloads:
        examples = payload.get("examples") or []
        if not examples:
            continue
        lines.append(f"### {payload.get('label', '')}")
        lines.append("")
        for example in examples[: args.examples]:
            lines.append(
                f"- `{example.get('replay')}` step={example.get('step')} team={example.get('team')} "
                f"ctx={example.get('context')} public={example.get('public_desc')} "
                f"agent={example.get('agent_desc')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n", trusted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--candidate", action="append", default=[], help="LABEL=AGENT_DIR")
    parser.add_argument("--cards", type=Path, default=REPO / "data" / "EN_Card_Data.csv")
    parser.add_argument("--team", action="append", default=[])
    parser.add_argument("--context", action="append", default=[])
    parser.add_argument("--max-replays", type=int, default=40)
    parser.add_argument("--examples", type=int, default=6)
    parser.add_argument("--delta-examples", type=int, default=4)
    parser.add_argument(
        "--min-agent-deck-overlap",
        type=int,
        default=0,
        help="Skip public states whose revealed controlled-player cards overlap the candidate deck by fewer unique IDs.",
    )
    parser.add_argument("--baseline-label", default="")
    parser.add_argument("--gate-label", action="append", default=[])
    parser.add_argument("--gate-context", default="MAIN")
    parser.add_argument("--min-compared", type=int, default=100)
    parser.add_argument("--min-same-rate", type=float, default=0.0)
    parser.add_argument("--max-regression", type=float, default=0.03)
    parser.add_argument("--max-net-regressions", type=int, default=0)
    parser.add_argument(
        "--max-net-weighted-regression",
        type=float,
        default=0.0,
        help="Block when weighted fixes minus weighted regressions is below the negative of this value.",
    )
    parser.add_argument("--csv-output", type=Path, default=None)
    parser.add_argument(
        "--decisions-output",
        type=Path,
        default=None,
        help="Write one row per compared public decision with board/risk feature flags.",
    )
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--worker-label", default="")
    parser.add_argument("--worker-agent", type=Path, default=None)
    args = parser.parse_args()

    args.replays = [path if path.is_absolute() else REPO / path for path in args.replays]
    args.cards = args.cards if args.cards.is_absolute() else REPO / args.cards
    if not args.context:
        args.context = [args.gate_context]

    if args.worker:
        if args.worker_agent is None:
            raise SystemExit("--worker requires --worker-agent")
        args.worker_agent = args.worker_agent if args.worker_agent.is_absolute() else REPO / args.worker_agent
        return worker_compare(args)

    if not args.candidate:
        raise SystemExit("at least one --candidate LABEL=AGENT_DIR is required")

    payloads = []
    for spec in args.candidate:
        label, path = parse_agent_spec(spec)
        payloads.append(run_worker(args, label, path))

    contexts = ["ALL"]
    for context in args.context or []:
        if context not in contexts:
            contexts.append(context)
    if args.gate_context not in contexts:
        contexts.append(args.gate_context)

    report, trusted = render_report(args, payloads, contexts)
    if args.csv_output:
        write_csv(args.csv_output, payloads, contexts)
    if args.decisions_output:
        write_decisions_csv(args.decisions_output, payloads)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0 if trusted else 2


if __name__ == "__main__":
    raise SystemExit(main())
