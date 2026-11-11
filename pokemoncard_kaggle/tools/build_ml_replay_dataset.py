#!/usr/bin/env python3
"""Build replay manifests and decision JSONL for ML/RL experiments.

The output is intentionally model-agnostic. It turns public replay JSON files
into two artifacts:

* a replay-level manifest with teams, archetypes, rewards, and deck hashes
* a decision-level JSONL stream with legal-option metadata and chosen actions

This gives supervised imitation, offline value learning, and self-play audit
code the same deterministic input format.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from analyze_replays import archetype, deck_hash


AREA_NAMES = {
    1: "DECK",
    2: "HAND",
    3: "DISCARD",
    4: "ACTIVE",
    5: "BENCH",
    6: "PRIZE",
    7: "STADIUM",
    8: "ENERGY",
    9: "TOOL",
    10: "PRE_EVOLUTION",
    11: "PLAYER",
    12: "LOOKING",
}

OPTION_NAMES = {
    0: "NUMBER",
    1: "YES",
    2: "NO",
    3: "CARD",
    4: "TOOL_CARD",
    5: "ENERGY_CARD",
    6: "ENERGY",
    7: "PLAY",
    8: "ATTACH",
    9: "EVOLVE",
    10: "ABILITY",
    11: "DISCARD",
    12: "RETREAT",
    13: "ATTACK",
    14: "END",
    15: "SKILL",
    16: "SPECIAL_CONDITION",
}

CONTEXT_NAMES = {
    0: "MAIN",
    1: "SETUP_ACTIVE_POKEMON",
    2: "SETUP_BENCH_POKEMON",
    3: "SWITCH",
    4: "TO_ACTIVE",
    5: "TO_BENCH",
    6: "TO_FIELD",
    7: "TO_HAND",
    8: "DISCARD",
    9: "TO_DECK",
    10: "TO_DECK_BOTTOM",
    11: "TO_PRIZE",
    12: "NOT_MOVE",
    13: "DAMAGE_COUNTER",
    14: "DAMAGE_COUNTER_ANY",
    15: "DAMAGE",
    16: "REMOVE_DAMAGE_COUNTER",
    17: "HEAL",
    18: "EVOLVES_FROM",
    19: "EVOLVES_TO",
    20: "DEVOLVE",
    21: "ATTACH_FROM",
    22: "ATTACH_TO",
    23: "DETACH_FROM",
    24: "LOOK",
    25: "EFFECT_TARGET",
    26: "DISCARD_ENERGY_CARD",
    27: "DISCARD_TOOL_CARD",
    28: "SWITCH_ENERGY_CARD",
    29: "DISCARD_CARD_OR_ATTACHED_CARD",
    30: "DISCARD_ENERGY",
    31: "TO_HAND_ENERGY",
    32: "TO_DECK_ENERGY",
    33: "SWITCH_ENERGY",
    34: "SKILL_ORDER",
    35: "ATTACK",
    36: "DISABLE_ATTACK",
    37: "EVOLVE",
    38: "DRAW_COUNT",
    39: "DAMAGE_COUNTER_COUNT",
    40: "REMOVE_DAMAGE_COUNTER_COUNT",
    41: "IS_FIRST",
    42: "MULLIGAN",
    43: "ACTIVATE",
    44: "FIRST_EFFECT",
    45: "MORE_DEVOLVE",
    46: "COIN_HEAD",
    47: "AFFECT_SPECIAL_CONDITION",
    48: "RECOVER_SPECIAL_CONDITION",
}


def enum_name(mapping: dict[int, str], value: Any) -> str:
    try:
        return mapping.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def infer_date_from_path(path: Path) -> str:
    text = str(path)
    match = re.search(r"(20\d\d-\d\d-\d\d)", text)
    if match:
        return match.group(1)
    match = re.search(r"(20\d\d)[_-](\d\d)[_-](\d\d)", text)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
    match = re.search(r"(20\d\d)(\d\d)(\d\d)T", text)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
    return ""


def outcome_label(rewards: list[Any], statuses: list[Any]) -> str:
    try:
        r0 = float(rewards[0])
        r1 = float(rewards[1])
    except (IndexError, TypeError, ValueError):
        r0 = r1 = float("nan")
    status_text = " ".join(str(status) for status in statuses)
    if sorted([r0, r1]) == [-1.0, 1.0]:
        return "normal"
    if r0 == 0.0 and r1 == 0.0:
        return "draw"
    if "TIMEOUT" in status_text:
        return "timeout"
    if "ERROR" in status_text or "INVALID" in status_text:
        return "error_or_invalid"
    return "other"


def numeric_gap(left: Any, right: Any) -> str:
    try:
        return f"{abs(float(left) - float(right)):.3f}"
    except (TypeError, ValueError):
        return ""


def turn_bin(turn: Any) -> str:
    try:
        value = int(turn)
    except (TypeError, ValueError):
        return "unknown"
    if value <= 1:
        return "0-1"
    if value <= 3:
        return "2-3"
    if value <= 6:
        return "4-6"
    if value <= 10:
        return "7-10"
    if value <= 20:
        return "11-20"
    return "21+"


def count_bucket(value: Any, size: int = 2, cap: int = 4) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, number // size))


def load_names(path: Path) -> dict[int, str]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        return {int(row["Card ID"]): row["Card Name"] for row in csv.DictReader(file)}


def valid_action(action: object, option_count: int, minimum: int, maximum: int) -> bool:
    if not isinstance(action, list):
        return False
    if not minimum <= len(action) <= maximum:
        return False
    return all(isinstance(item, int) and 0 <= item < option_count for item in action)


def unique_replay_paths(paths: list[Path]) -> tuple[list[Path], int]:
    seen: set[str] = set()
    unique: list[Path] = []
    duplicates = 0
    for path in sorted(paths):
        key = path.stem
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(path)
    return unique, duplicates


def public_action_for_observation(steps: list[Any], step_index: int, player_index: int) -> Any:
    """Return the public action responding to an observation at step t.

    Kaggle replay JSON records the action selected for
    steps[t][player]["observation"] on steps[t + 1][player]["action"].
    """
    next_index = step_index + 1
    if next_index >= len(steps):
        return None
    try:
        return steps[next_index][player_index].get("action")
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


def card_id(card: Any) -> int | None:
    if isinstance(card, dict) and "id" in card:
        try:
            return int(card["id"])
        except (TypeError, ValueError):
            return None
    return None


def card_ids(cards: Any, limit: int | None = None) -> list[int]:
    if not isinstance(cards, list):
        return []
    ids = [cid for cid in (card_id(card) for card in cards) if cid is not None]
    return ids if limit is None else ids[:limit]


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


def option_type_name(option: dict[str, Any]) -> str:
    return enum_name(OPTION_NAMES, option.get("type"))


def option_attack_id(option: dict[str, Any]) -> int | None:
    attack = option.get("attackId")
    try:
        return int(attack)
    except (TypeError, ValueError):
        return None


def legal_type_counts(options: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter(option_type_name(option) for option in options if isinstance(option, dict))
    return dict(sorted(counts.items()))


def option_description(obs: dict[str, Any], option_index: int, names: dict[int, str]) -> str:
    options = (obs.get("select") or {}).get("option") or []
    if not 0 <= option_index < len(options):
        return f"{option_index}:out"
    option = options[option_index]
    parts = [f"{option_index}:{enum_name(OPTION_NAMES, option.get('type'))}"]
    cid = get_option_card_id(obs, option)
    if cid is None and option.get("type") == 7:
        cid = get_option_card_id(
            obs,
            {
                "area": 2,
                "index": option.get("index"),
                "playerIndex": (obs.get("current") or {}).get("yourIndex"),
            },
        )
    if cid is not None:
        parts.append(f"{names.get(cid, cid)}({cid})")
    if "number" in option:
        parts.append(f"num={option.get('number')}")
    if "attackId" in option:
        parts.append(f"attack={option.get('attackId')}")
    if "inPlayArea" in option:
        parts.append(f"to={enum_name(AREA_NAMES, option.get('inPlayArea'))}:{option.get('inPlayIndex')}")
    return " ".join(parts)


def player_features(player: dict[str, Any]) -> dict[str, Any]:
    active_ids = card_ids(player.get("active"), limit=1)
    bench_ids = card_ids(player.get("bench"))
    discard_ids = card_ids(player.get("discard"))
    return {
        "active": active_ids[0] if active_ids else None,
        "bench": bench_ids,
        "bench_count": len(bench_ids),
        "bench_max": player.get("benchMax"),
        "deck_count": player.get("deckCount"),
        "discard_count": len(discard_ids),
        "hand_count": player.get("handCount"),
        "prize_count": len(player.get("prize") or []),
        "status": {
            "asleep": bool(player.get("asleep")),
            "burned": bool(player.get("burned")),
            "confused": bool(player.get("confused")),
            "paralyzed": bool(player.get("paralyzed")),
            "poisoned": bool(player.get("poisoned")),
        },
    }


def compact_state_features(obs: dict[str, Any]) -> dict[str, Any]:
    current = obs.get("current") or {}
    players = current.get("players") or []
    your_index = current.get("yourIndex", 0)
    if not isinstance(your_index, int) or len(players) < 2:
        return {}
    opponent_index = 1 - your_index
    return {
        "turn": current.get("turn"),
        "turn_action_count": current.get("turnActionCount"),
        "your_index": your_index,
        "first_player": current.get("firstPlayer"),
        "supporter_played": current.get("supporterPlayed"),
        "stadium_played": current.get("stadiumPlayed"),
        "energy_attached": current.get("energyAttached"),
        "stadium": card_id(current.get("stadium")),
        "me": player_features(players[your_index]),
        "opponent": player_features(players[opponent_index]),
    }


def board_key_from_state(state: dict[str, Any]) -> str:
    me = state.get("me") or {}
    opponent = state.get("opponent") or {}
    return "|".join(
        [
            f"turn={turn_bin(state.get('turn'))}",
            f"active={me.get('active')}",
            f"opp_active={opponent.get('active')}",
            f"bench={count_bucket(me.get('bench_count'))}",
            f"opp_bench={count_bucket(opponent.get('bench_count'))}",
            f"energy={state.get('energy_attached')}",
        ]
    )


def replay_id(path: Path, data: dict[str, Any]) -> str:
    episode_id = (data.get("info") or {}).get("EpisodeId") or data.get("id")
    return str(episode_id) if episode_id is not None else path.stem


def source_label(path: Path) -> str:
    parts = path.parts
    for marker in ("scouting", "diagnostics", "leaderboard"):
        if marker in parts:
            index = parts.index(marker)
            return "/".join(parts[index : min(len(parts), index + 3)])
    return str(path.parent)


def load_initial_decks(data: dict[str, Any]) -> list[list[int]]:
    try:
        decks = data["steps"][0][0]["visualize"][0]["action"]
    except Exception:
        return [[], []]
    if isinstance(decks, list) and len(decks) == 2:
        return [[int(card) for card in deck] for deck in decks]
    return [[], []]


def replay_manifest_row(path: Path, data: dict[str, Any]) -> dict[str, Any]:
    teams = (data.get("info") or {}).get("TeamNames") or ["", ""]
    rewards = data.get("rewards") or [None, None]
    statuses = data.get("statuses") or ["", ""]
    decks = load_initial_decks(data)
    winner_index = None
    if (
        len(rewards) >= 2
        and rewards[0] is not None
        and rewards[1] is not None
        and rewards[0] != rewards[1]
    ):
        winner_index = 0 if rewards[0] > rewards[1] else 1
    return {
        "episode_id": replay_id(path, data),
        "date": infer_date_from_path(path),
        "path": str(path),
        "source": source_label(path),
        "team0": teams[0] if len(teams) > 0 else "",
        "team1": teams[1] if len(teams) > 1 else "",
        "reward0": rewards[0] if len(rewards) > 0 else "",
        "reward1": rewards[1] if len(rewards) > 1 else "",
        "winner_index": "" if winner_index is None else winner_index,
        "winner_team": "" if winner_index is None else teams[winner_index],
        "status0": statuses[0] if len(statuses) > 0 else "",
        "status1": statuses[1] if len(statuses) > 1 else "",
        "outcome_label": outcome_label(rewards, statuses),
        "abs_reward_gap": numeric_gap(rewards[0] if len(rewards) > 0 else "", rewards[1] if len(rewards) > 1 else ""),
        "steps": len(data.get("steps") or []),
        "deck0_hash": deck_hash(decks[0]) if decks and decks[0] else "",
        "deck1_hash": deck_hash(decks[1]) if len(decks) > 1 and decks[1] else "",
        "deck0_archetype": archetype(decks[0]) if decks and decks[0] else "unknown",
        "deck1_archetype": archetype(decks[1]) if len(decks) > 1 and decks[1] else "unknown",
    }


def selected_descriptions(obs: dict[str, Any], action: list[int], names: dict[int, str]) -> list[str]:
    return [option_description(obs, index, names) for index in action]


def selected_option_metadata(obs: dict[str, Any], action: list[int]) -> tuple[list[str], list[int], list[int]]:
    options = (obs.get("select") or {}).get("option") or []
    selected_types: list[str] = []
    selected_cards: list[int] = []
    selected_attacks: list[int] = []
    for index in action:
        if not 0 <= index < len(options):
            continue
        option = options[index]
        selected_types.append(option_type_name(option))
        card = get_option_card_id(obs, option)
        if card is None and option.get("type") == 7:
            card = get_option_card_id(
                obs,
                {
                    "area": 2,
                    "index": option.get("index"),
                    "playerIndex": (obs.get("current") or {}).get("yourIndex"),
                },
            )
        if card is not None:
            selected_cards.append(card)
        attack = option_attack_id(option)
        if attack is not None:
            selected_attacks.append(attack)
    return selected_types, selected_cards, selected_attacks


def iter_decisions(
    path: Path,
    data: dict[str, Any],
    names: dict[int, str],
    include_deck_choices: bool,
) -> tuple[list[dict[str, Any]], Counter[str]]:
    manifest = replay_manifest_row(path, data)
    teams = [manifest["team0"], manifest["team1"]]
    rewards = [manifest["reward0"], manifest["reward1"]]
    archetypes = [manifest["deck0_archetype"], manifest["deck1_archetype"]]
    deck_hashes = [manifest["deck0_hash"], manifest["deck1_hash"]]
    rows: list[dict[str, Any]] = []
    context_counts: Counter[str] = Counter()
    steps = data.get("steps") or []
    seen_decision_states: set[tuple[int, str]] = set()
    for step_index, step in enumerate(steps):
        if not isinstance(step, list):
            continue
        for player_index, record in enumerate(step):
            if not isinstance(record, dict):
                continue
            obs = record.get("observation") or {}
            select = obs.get("select")
            if not select:
                continue
            state_key = (player_index, decision_state_key(obs))
            if state_key in seen_decision_states:
                continue
            seen_decision_states.add(state_key)
            action = public_action_for_observation(steps, step_index, player_index)
            options = select.get("option") or []
            minimum = select.get("minCount", 0)
            maximum = select.get("maxCount", len(options))
            if not options or not valid_action(action, len(options), minimum, maximum):
                continue
            if len(action) == 60 and not include_deck_choices:
                continue
            context = enum_name(CONTEXT_NAMES, select.get("context"))
            context_counts[context] += 1
            opponent_index = 1 - player_index
            selected_types, selected_cards, selected_attacks = selected_option_metadata(obs, action)
            state = compact_state_features(obs)
            terminal_reward = rewards[player_index] if player_index < len(rewards) else ""
            opponent_reward = rewards[opponent_index] if opponent_index < len(rewards) else ""
            is_winner_player = (
                isinstance(terminal_reward, (int, float))
                and isinstance(opponent_reward, (int, float))
                and terminal_reward > opponent_reward
            )
            rows.append(
                {
                    "episode_id": manifest["episode_id"],
                    "date": manifest["date"],
                    "path": str(path),
                    "source": manifest["source"],
                    "step_index": step_index,
                    "player_index": player_index,
                    "team": teams[player_index] if player_index < len(teams) else "",
                    "opponent_team": teams[opponent_index] if opponent_index < len(teams) else "",
                    "terminal_reward": terminal_reward,
                    "opponent_terminal_reward": opponent_reward,
                    "is_winner_player": is_winner_player,
                    "winner_team": manifest["winner_team"],
                    "episode_steps": manifest["steps"],
                    "outcome_label": manifest["outcome_label"],
                    "archetype": archetypes[player_index] if player_index < len(archetypes) else "unknown",
                    "opponent_archetype": archetypes[opponent_index] if opponent_index < len(archetypes) else "unknown",
                    "deck_hash": deck_hashes[player_index] if player_index < len(deck_hashes) else "",
                    "opponent_deck_hash": deck_hashes[opponent_index] if opponent_index < len(deck_hashes) else "",
                    "context": context,
                    "select_type": select.get("type"),
                    "min_count": minimum,
                    "max_count": maximum,
                    "option_count": len(options),
                    "action": action,
                    "selected": selected_descriptions(obs, action, names),
                    "selected_types": selected_types,
                    "selected_card_ids": selected_cards,
                    "selected_attack_ids": selected_attacks,
                    "legal_type_counts": legal_type_counts(options),
                    "turn_bin": turn_bin(state.get("turn")),
                    "board_key": board_key_from_state(state),
                    "options": [option_description(obs, index, names) for index in range(len(options))],
                    "state": state,
                }
            )
    return rows, context_counts


def write_manifest(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "episode_id",
        "date",
        "path",
        "source",
        "team0",
        "team1",
        "reward0",
        "reward1",
        "winner_index",
        "winner_team",
        "status0",
        "status1",
        "outcome_label",
        "abs_reward_gap",
        "steps",
        "deck0_hash",
        "deck1_hash",
        "deck0_archetype",
        "deck1_archetype",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--manifest-out", type=Path, default=Path("strategy/ml_replay_manifest.csv"))
    parser.add_argument("--decisions-out", type=Path, default=Path("strategy/ml_decisions.jsonl"))
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--include-deck-choices", action="store_true")
    args = parser.parse_args()

    names = load_names(args.cards)
    replay_paths = sorted(args.replays)
    duplicates = 0
    if not args.no_dedupe:
        replay_paths, duplicates = unique_replay_paths(replay_paths)

    manifest_rows: list[dict[str, Any]] = []
    decision_rows: list[dict[str, Any]] = []
    context_counts: Counter[str] = Counter()
    failed = 0
    for replay_path in replay_paths:
        try:
            data = json.loads(replay_path.read_text())
            manifest_rows.append(replay_manifest_row(replay_path, data))
            rows, counts = iter_decisions(replay_path, data, names, args.include_deck_choices)
            decision_rows.extend(rows)
            context_counts.update(counts)
        except Exception as exc:
            failed += 1
            print(f"warning: failed to parse {replay_path}: {exc}")

    write_manifest(args.manifest_out, manifest_rows)
    write_jsonl(args.decisions_out, decision_rows)
    print(f"replays={len(manifest_rows)} decisions={len(decision_rows)} duplicates={duplicates} failed={failed}")
    print(f"manifest={args.manifest_out}")
    print(f"decisions={args.decisions_out}")
    for context, count in context_counts.most_common(20):
        print(f"context {context}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
