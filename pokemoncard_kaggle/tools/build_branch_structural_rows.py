#!/usr/bin/env python3
"""Build outcome-free branch_bridge_v2 structural rows."""

from __future__ import annotations

import argparse
from collections import defaultdict
import copy
import hashlib
import json
from math import comb
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.branch_outcome import canonical_json, sha256_file  # noqa: E402
from evaluation_v2.catalog_semantics import (  # noqa: E402
    ACTIVE_CLASSES,
    CardCatalog,
    POKEMON_STAGES,
    SUPERTYPES,
    SUPPORT_FAMILIES,
    actor_visible_representation,
    support_family,
)


SCHEMA = "branch_bridge_structural_rows_v2"
NATIVE_SCHEMA = "branch_bridge_native_root_capsule_v2"
AUDIT_SCHEMA = "branch_bridge_schema_audit_v2"
SCHEDULE_SCHEMA = "branch_bridge_root_schedule_v2"
ROOT_NAMESPACE = "branch-bridge-v2-root"
FORBIDDEN_KEYS = frozenset(
    {
        "target_reward",
        "teacher_reward",
        "terminal_reward",
        "opponent_terminal_reward",
        "winner_team",
        "is_winner_player",
        "outcome",
        "outcome_label",
        "reward",
        "rewards",
        "result",
        "logs",
        "remainingOverageTime",
        "search_begin_input",
        "path",
        "date",
        "episode_steps",
    }
)

STRUCTURAL_KEYS = frozenset(
    {
        "schema",
        "episode_id",
        "game_id",
        "player_index",
        "side_id",
        "pilot",
        "submission_id",
        "replay_sha256",
        "module_version",
        "target_deck_sha256",
        "step_index",
        "native_root_id",
        "observation",
        "legal_actions",
        "semantic_collision_groups",
        "semantic_collision",
        "selected_action",
        "selected_action_key",
        "selected_family",
        "representation",
        "representation_sha256",
        "root_priority_sha256",
        "scheduled_root",
    }
)
ACTION_KEYS = frozenset({"selection", "payload", "payload_key", "action_key", "family"})
ACTION_PAYLOAD_KEYS = frozenset(
    {
        "type",
        "actions",
        "card_id",
        "energy_id",
        "target_area",
        "target_index",
        "target_card_id",
        "source_card_id",
        "effect_id",
        "attack_id",
    }
)
CLEAN_CURRENT_KEYS = frozenset(
    {
        "energyAttached",
        "firstPlayer",
        "retreated",
        "stadiumPlayed",
        "supporterPlayed",
        "turn",
        "turnActionCount",
        "yourIndex",
        "players",
        "stadium",
    }
)
CLEAN_PLAYER_KEYS = frozenset(
    {
        "active",
        "bench",
        "benchMax",
        "deckCount",
        "discard",
        "hand",
        "handCount",
        "prize",
        "asleep",
        "burned",
        "confused",
        "paralyzed",
        "poisoned",
    }
)
CLEAN_CARD_KEYS = frozenset(
    {"id", "hp", "maxHp", "damage", "energyCards", "toolCards", "tools", "asleep", "burned", "confused", "paralyzed", "poisoned"}
)
NATIVE_CURRENT_KEYS = frozenset(
    {
        "energyAttached",
        "firstPlayer",
        "looking",
        "players",
        "result",
        "retreated",
        "stadium",
        "stadiumPlayed",
        "supporterPlayed",
        "turn",
        "turnActionCount",
        "yourIndex",
    }
)
NATIVE_PLAYER_KEYS = CLEAN_PLAYER_KEYS
NATIVE_CARD_KEYS = frozenset(
    {"appearThisTurn", "energies", "energyCards", "hp", "id", "maxHp", "playerIndex", "preEvolution", "serial", "tools"}
)
NATIVE_SELECT_KEYS = frozenset(
    {"context", "contextCard", "deck", "effect", "maxCount", "minCount", "option", "remainDamageCounter", "remainEnergyCost", "type"}
)
NATIVE_OPTION_KEYS = frozenset({"area", "attackId", "inPlayArea", "inPlayIndex", "index", "playerIndex", "type"})
NATIVE_CAPSULE_KEYS = frozenset(
    {
        "schema",
        "native_root_id",
        "episode_id",
        "game_id",
        "player_index",
        "side_id",
        "pilot",
        "replay_sha256",
        "module_version",
        "step_index",
        "recorded_selection",
        "observation",
    }
)
SCHEDULE_KEYS = frozenset(
    {"schema", "side_id", "slot_index", "native_root_id", "root_priority_sha256", "status"}
)
NUMERIC_REPRESENTATION_KEYS = frozenset(
    {
        "turn",
        "turn_action_count",
        "own_prize_count",
        "opp_prize_count",
        "own_hand_count",
        "opp_hand_count",
        "own_deck_count",
        "opp_deck_count",
        "own_bench_count",
        "opp_bench_count",
        "own_discard_count",
        "opp_discard_count",
        "own_active_hp_fraction",
        "opp_active_hp_fraction",
        "own_active_energy_count",
        "opp_active_energy_count",
        "own_active_retreat",
        "opp_active_retreat",
        "own_bench_hp_fraction",
        "opp_bench_hp_fraction",
        "own_bench_energy_count",
        "opp_bench_energy_count",
        "is_first_player",
        "energy_attached",
        "supporter_played",
        "stadium_played",
        "retreated",
        *(f"legal_{family.lower()}_{suffix}" for family in SUPPORT_FAMILIES for suffix in ("available", "count")),
    }
)
CATEGORICAL_REPRESENTATION_KEYS = frozenset(
    {
        "own_active_class",
        "opp_active_class",
        "own_active_type",
        "opp_active_type",
        "own_active_stage",
        "opp_active_stage",
        "own_active_rulebox",
        "opp_active_rulebox",
        "own_active_status",
        "opp_active_status",
        "own_to_opp_matchup",
        "opp_to_own_matchup",
        "own_bench_ontology_counts",
        "opp_bench_ontology_counts",
        "own_hand_supertype_counts",
        "own_hand_stage_counts",
    }
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _allowed_records(base_path: Path, augmentation_path: Path) -> dict[tuple[str, int, str], dict[str, Any]]:
    base = _load(base_path)
    augmentation = _load(augmentation_path)
    holdout_ids = {
        str(record["episode_id"])
        for record in base.get("episodes") or ()
        if record.get("role") == "holdout"
    }
    frozen_ids = {str(value) for value in augmentation.get("frozen_episode_ids") or ()}
    if not holdout_ids or not holdout_ids <= frozen_ids:
        raise ValueError("augmentation does not exclude every sealed episode")
    records = [
        record
        for record in base.get("episodes") or ()
        if record.get("role") == "development"
    ]
    for record in augmentation.get("records") or ():
        if record.get("role") != "development":
            raise ValueError("augmentation contains non-development evidence")
        if str(record.get("episode_id")) in holdout_ids:
            raise ValueError("augmentation contains a sealed episode")
        records.append(record)
    allowed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for record in records:
        key = (str(record["episode_id"]), int(record["target_slot"]), str(record["target_team"]))
        if key in allowed:
            raise ValueError(f"duplicate target-side record: {key}")
        allowed[key] = {
            "episode_id": key[0],
            "target_slot": key[1],
            "target_team": key[2],
            "replay_sha256": str(record["replay_sha256"]),
            "module_version": str(record["module_version"]),
            "submission_id": str(record.get("submission_id") or ""),
            "target_deck_sha256": str(record["target_deck_sha256"]),
        }
    return allowed


def _clean_card(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    allowed = {
        "id",
        "hp",
        "maxHp",
        "damage",
        "energyCards",
        "toolCards",
        "tools",
        "asleep",
        "burned",
        "confused",
        "paralyzed",
        "poisoned",
    }
    result: dict[str, Any] = {}
    for key in allowed:
        if key not in value:
            continue
        item = value[key]
        if key in {"energyCards", "toolCards", "tools"}:
            result[key] = [
                {"id": card.get("id")}
                for card in item
                if isinstance(card, Mapping) and card.get("id") is not None
            ] if isinstance(item, Sequence) and not isinstance(item, (str, bytes)) else []
        else:
            result[key] = item
    return result


def _clean_player(player: Mapping[str, Any], *, include_hand: bool) -> dict[str, Any]:
    active = [_clean_card(card) for card in player.get("active") or ()]
    bench = [_clean_card(card) for card in player.get("bench") or ()]
    discard = [_clean_card(card) for card in player.get("discard") or ()]
    hand = [_clean_card(card) for card in player.get("hand") or ()] if include_hand else None
    return {
        "active": [card for card in active if card is not None],
        "bench": [card for card in bench if card is not None],
        "benchMax": int(player.get("benchMax") or 0),
        "deckCount": int(player.get("deckCount") or 0),
        "discard": [card for card in discard if card is not None],
        "hand": [card for card in hand if card is not None] if hand is not None else None,
        "handCount": int(player.get("handCount") or 0),
        "prize": [None] * len(player.get("prize") or ()),
        "asleep": bool(player.get("asleep")),
        "burned": bool(player.get("burned")),
        "confused": bool(player.get("confused")),
        "paralyzed": bool(player.get("paralyzed")),
        "poisoned": bool(player.get("poisoned")),
    }


def sanitize_current(observation: Mapping[str, Any]) -> dict[str, Any]:
    current = observation.get("current") or {}
    your_index = int(current.get("yourIndex", -1))
    players = current.get("players") or ()
    if your_index not in (0, 1) or len(players) != 2:
        raise ValueError("observation has no valid actor-visible two-player state")
    scalars = {
        key: copy.deepcopy(current[key])
        for key in (
            "energyAttached",
            "firstPlayer",
            "retreated",
            "stadiumPlayed",
            "supporterPlayed",
            "turn",
            "turnActionCount",
            "yourIndex",
        )
        if key in current
    }
    stadium = [_clean_card(card) for card in current.get("stadium") or ()]
    return {
        **scalars,
        "players": [
            _clean_player(player, include_hand=index == your_index)
            for index, player in enumerate(players)
        ],
        "stadium": [card for card in stadium if card is not None],
    }


def _card_at(current: Mapping[str, Any], player: int, area: int, index: int) -> int | None:
    if area == 7:
        try:
            card = current["stadium"][index]
            return int(card["id"]) if isinstance(card, Mapping) else None
        except (IndexError, KeyError, TypeError, ValueError):
            return None
    zone = {2: "hand", 3: "discard", 4: "active", 5: "bench"}.get(area)
    if zone is None:
        return None
    try:
        card = current["players"][player][zone][index]
        return int(card["id"]) if isinstance(card, Mapping) else None
    except (IndexError, KeyError, TypeError, ValueError):
        return None


def _resolved_action(observation: Mapping[str, Any], selection: Sequence[int]) -> dict[str, Any]:
    select = observation.get("select") or {}
    options = select.get("option") or ()
    if len(selection) != 1:
        return {
            "type": "MULTI",
            "actions": [_resolved_action(observation, (index,)) for index in selection],
        }
    index = int(selection[0])
    option = options[index]
    raw_type = int(option.get("type", -1))
    current = observation.get("current") or {}
    actor = int(current.get("yourIndex", -1))
    payload: dict[str, Any] = {"type": raw_type}
    card_id = None
    area = option.get("area")
    option_index = option.get("index")
    if area is not None and option_index is not None:
        card_id = _card_at(current, int(option.get("playerIndex", actor)), int(area), int(option_index))
    if card_id is None and raw_type in {7, 9} and option_index is not None:
        card_id = _card_at(current, actor, 2, int(option_index))
    if card_id is not None:
        payload["card_id"] = card_id
    if raw_type == 13 and option.get("attackId") is not None:
        payload["attack_id"] = int(option["attackId"])
    if raw_type == 10:
        source_area = int(option.get("inPlayArea", option.get("area", 0)) or 0)
        source_index = int(option.get("inPlayIndex", option.get("index", 0)) or 0)
        source = _card_at(current, actor, source_area, source_index)
        if source is not None:
            payload["source_card_id"] = source
        if option.get("effect") is not None:
            payload["effect_id"] = option["effect"]
    if raw_type == 8:
        if card_id is not None:
            payload["energy_id"] = card_id
        target_area = int(option.get("inPlayArea", 0) or 0)
        target_index = int(option.get("inPlayIndex", 0) or 0)
        payload["target_area"] = target_area
        payload["target_index"] = target_index
        target = _card_at(current, actor, target_area, target_index)
        if target is not None:
            payload["target_card_id"] = target
    if raw_type == 9:
        target_area = int(option.get("inPlayArea", 0) or 0)
        target_index = int(option.get("inPlayIndex", 0) or 0)
        payload["target_area"] = target_area
        payload["target_index"] = target_index
        target = _card_at(current, actor, target_area, target_index)
        if target is not None:
            payload["target_card_id"] = target
    return payload


def _legal_selections(select: Mapping[str, Any]) -> list[tuple[int, ...]]:
    options = select.get("option") or ()
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", 0))
    if not 0 <= minimum <= maximum <= len(options):
        return []
    count = sum(comb(len(options), size) for size in range(minimum, maximum + 1))
    if not 2 <= count <= 128:
        return []
    from itertools import combinations

    return [
        tuple(selection)
        for size in range(minimum, maximum + 1)
        for selection in combinations(range(len(options)), size)
    ]


def _action_record(
    observation: Mapping[str, Any], selection: Sequence[int], catalog: CardCatalog
) -> dict[str, Any]:
    normalized_selection = [int(index) for index in selection]
    payload = _resolved_action(observation, selection)
    payload_key = canonical_json(payload)
    action_key = canonical_json({"selection": normalized_selection, "payload": payload})
    return {
        "selection": normalized_selection,
        "payload": payload,
        "payload_key": payload_key,
        "action_key": action_key,
        "family": support_family(payload, catalog),
    }


def _native_root_id(record: Mapping[str, Any], step_index: int, search_begin_input: str) -> str:
    return hashlib.sha256(
        (
            f"{NATIVE_SCHEMA}\0{record['replay_sha256']}\0{record['target_slot']}\0"
            f"{step_index}\0{search_begin_input}"
        ).encode("utf-8")
    ).hexdigest()


def native_root_capsule(
    row: Mapping[str, Any], record: Mapping[str, Any], native_root_id: str
) -> dict[str, Any]:
    observation = row.get("observation")
    if not isinstance(observation, Mapping):
        raise ValueError("native root observation must be a mapping")
    current = observation.get("current")
    select = observation.get("select")
    search_begin_input = observation.get("search_begin_input")
    if not isinstance(current, Mapping) or not isinstance(select, Mapping) or not isinstance(search_begin_input, str):
        raise ValueError("native root is missing current/select/search_begin_input")
    capsule = {
        "schema": NATIVE_SCHEMA,
        "native_root_id": native_root_id,
        "episode_id": str(record["episode_id"]),
        "game_id": str(record["episode_id"]),
        "player_index": int(record["target_slot"]),
        "side_id": f"{record['episode_id']}:{record['target_slot']}:{record['target_team']}",
        "pilot": str(record["target_team"]),
        "replay_sha256": str(record["replay_sha256"]),
        "module_version": str(record["module_version"]),
        "step_index": int(row["step_index"]),
        "recorded_selection": [int(index) for index in row["action"]],
        "observation": {
            "current": copy.deepcopy(current),
            "select": copy.deepcopy(select),
            "search_begin_input": search_begin_input,
        },
    }
    validate_native_capsule(capsule)
    return capsule


def structural_row(
    row: Mapping[str, Any],
    record: Mapping[str, Any],
    catalog: CardCatalog,
) -> dict[str, Any] | None:
    if row.get("cohort_role") != "development" or row.get("context") != "MAIN":
        return None
    observation = row.get("observation") or {}
    select = observation.get("select") or {}
    if select.get("context") != 0 or not observation.get("search_begin_input"):
        return None
    selections = _legal_selections(select)
    action = row.get("action")
    if not selections or not isinstance(action, list) or tuple(action) not in set(selections):
        return None
    legal_actions = sorted(
        (_action_record(observation, selection, catalog) for selection in selections),
        key=lambda value: value["action_key"],
    )
    selected_action = _action_record(observation, tuple(action), catalog)
    selected_key = selected_action["action_key"]
    legal_families = [value["family"] for value in legal_actions]
    selected_family = selected_action["family"]
    collision_members: dict[str, list[str]] = defaultdict(list)
    for value in legal_actions:
        collision_members[value["payload_key"]].append(value["action_key"])
    collision_groups = [
        {"payload_key": payload_key, "action_keys": sorted(action_keys)}
        for payload_key, action_keys in sorted(collision_members.items())
        if len(action_keys) > 1
    ]
    cleaned_observation = {
        "module_version": record["module_version"],
        "current": sanitize_current(observation),
    }
    representation = actor_visible_representation(
        cleaned_observation,
        legal_families=legal_families,
        catalog=catalog,
    )
    representation_sha256 = hashlib.sha256(canonical_json(representation).encode("ascii")).hexdigest()
    side_id = f"{record['episode_id']}:{record['target_slot']}:{record['target_team']}"
    root_priority_sha256 = hashlib.sha256(
        (
            f"{ROOT_NAMESPACE}\0{side_id}\0{int(row['step_index'])}\0"
            f"{representation_sha256}"
        ).encode("utf-8")
    ).hexdigest()
    native_id = _native_root_id(record, int(row["step_index"]), str(observation["search_begin_input"]))
    result = {
        "schema": SCHEMA,
        "episode_id": str(record["episode_id"]),
        "game_id": str(record["episode_id"]),
        "player_index": int(record["target_slot"]),
        "side_id": side_id,
        "pilot": str(record["target_team"]),
        "submission_id": str(record["submission_id"]),
        "replay_sha256": str(record["replay_sha256"]),
        "module_version": str(record["module_version"]),
        "target_deck_sha256": str(record["target_deck_sha256"]),
        "step_index": int(row["step_index"]),
        "native_root_id": native_id,
        "observation": cleaned_observation,
        "legal_actions": legal_actions,
        "semantic_collision_groups": collision_groups,
        "semantic_collision": bool(collision_groups),
        "selected_action": selected_action,
        "selected_action_key": selected_key,
        "selected_family": selected_family,
        "representation": representation,
        "representation_sha256": representation_sha256,
        "root_priority_sha256": root_priority_sha256,
        "scheduled_root": False,
    }
    validate_structural_row(result)
    return result


def _assert_outcome_free(value: Any, *, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden outcome/future field in structural row: {'.'.join((*path, str(key)))}")
            _assert_outcome_free(item, path=(*path, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_outcome_free(item, path=(*path, str(index)))


def _forbidden_paths(value: Any, *, path: tuple[str, ...] = ()) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = (*path, str(key))
            if str(key) in FORBIDDEN_KEYS:
                found.append(".".join(child))
            found.extend(_forbidden_paths(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_forbidden_paths(item, path=(*path, str(index))))
    return found


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(str(key) for key in value)
    if actual != expected:
        raise ValueError(f"{label} schema mismatch: missing={sorted(expected - actual)} extra={sorted(actual - expected)}")


def _validate_clean_card(card: Mapping[str, Any], label: str) -> None:
    extra = frozenset(str(key) for key in card) - CLEAN_CARD_KEYS
    if extra:
        raise ValueError(f"{label} has unsupported fields: {sorted(extra)}")
    if not isinstance(card.get("id"), int) or isinstance(card.get("id"), bool):
        raise ValueError(f"{label}.id must be an integer")
    for key in ("energyCards", "toolCards", "tools"):
        if key in card:
            values = card[key]
            if not isinstance(values, list) or not all(isinstance(value, Mapping) for value in values):
                raise ValueError(f"{label}.{key} must be a list of card mappings")
            for index, value in enumerate(values):
                _validate_clean_card(value, f"{label}.{key}[{index}]")


def _validate_payload(payload: Mapping[str, Any], label: str) -> None:
    extra = frozenset(str(key) for key in payload) - ACTION_PAYLOAD_KEYS
    if extra:
        raise ValueError(f"{label} has unsupported fields: {sorted(extra)}")
    if payload.get("type") == "MULTI":
        actions = payload.get("actions")
        if not isinstance(actions, list):
            raise ValueError(f"{label}.actions must be a list")
        for index, action in enumerate(actions):
            if not isinstance(action, Mapping):
                raise ValueError(f"{label}.actions[{index}] must be a mapping")
            _validate_payload(action, f"{label}.actions[{index}]")
    elif not isinstance(payload.get("type"), int) or isinstance(payload.get("type"), bool):
        raise ValueError(f"{label}.type must be an integer or MULTI")


def validate_structural_row(value: Mapping[str, Any]) -> None:
    _require_exact_keys(value, STRUCTURAL_KEYS, "structural row")
    if value.get("schema") != SCHEMA:
        raise ValueError("unsupported structural row schema")
    observation = value.get("observation")
    if not isinstance(observation, Mapping):
        raise ValueError("structural observation must be a mapping")
    _require_exact_keys(observation, frozenset({"module_version", "current"}), "structural observation")
    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("structural current must be a mapping")
    _require_exact_keys(current, CLEAN_CURRENT_KEYS, "structural current")
    players = current.get("players")
    if not isinstance(players, list) or len(players) != 2:
        raise ValueError("structural current must contain two players")
    for player_index, player in enumerate(players):
        if not isinstance(player, Mapping):
            raise ValueError("structural player must be a mapping")
        _require_exact_keys(player, CLEAN_PLAYER_KEYS, f"structural player {player_index}")
        for zone in ("active", "bench", "discard"):
            cards = player[zone]
            if not isinstance(cards, list):
                raise ValueError(f"structural player {zone} must be a list")
            for index, card in enumerate(cards):
                if not isinstance(card, Mapping):
                    raise ValueError(f"structural player {zone}[{index}] must be a mapping")
                _validate_clean_card(card, f"structural player {zone}[{index}]")
        hand = player["hand"]
        if hand is not None:
            if not isinstance(hand, list):
                raise ValueError("structural hand must be a list or null")
            for index, card in enumerate(hand):
                if not isinstance(card, Mapping):
                    raise ValueError("structural hand cards must be mappings")
                _validate_clean_card(card, f"structural hand[{index}]")
    stadium = current.get("stadium")
    if not isinstance(stadium, list):
        raise ValueError("structural stadium must be a list")
    for index, card in enumerate(stadium):
        if not isinstance(card, Mapping):
            raise ValueError("structural stadium cards must be mappings")
        _validate_clean_card(card, f"structural stadium[{index}]")
    actions = value.get("legal_actions")
    if not isinstance(actions, list) or len(actions) < 2:
        raise ValueError("structural legal_actions must contain at least two actions")
    action_keys: set[str] = set()
    for index, action in enumerate(actions):
        if not isinstance(action, Mapping):
            raise ValueError("structural action must be a mapping")
        _require_exact_keys(action, ACTION_KEYS, f"legal action {index}")
        payload = action.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("structural action payload must be a mapping")
        _validate_payload(payload, f"legal action {index} payload")
        expected_payload_key = canonical_json(payload)
        expected_action_key = canonical_json({"selection": action["selection"], "payload": payload})
        if action.get("payload_key") != expected_payload_key or action.get("action_key") != expected_action_key:
            raise ValueError("structural action identity mismatch")
        if expected_action_key in action_keys:
            raise ValueError("duplicate exact action identity")
        action_keys.add(expected_action_key)
    selected = value.get("selected_action")
    if not isinstance(selected, Mapping):
        raise ValueError("selected_action must be a mapping")
    _require_exact_keys(selected, ACTION_KEYS, "selected action")
    if value.get("selected_action_key") != selected.get("action_key") or selected.get("action_key") not in action_keys:
        raise ValueError("selected action is absent from legal actions")
    representation = value.get("representation")
    if not isinstance(representation, Mapping):
        raise ValueError("representation must be a mapping")
    _require_exact_keys(representation, frozenset({"numeric", "categorical"}), "representation")
    numeric = representation.get("numeric")
    categorical = representation.get("categorical")
    if not isinstance(numeric, Mapping) or not isinstance(categorical, Mapping):
        raise ValueError("representation components must be mappings")
    _require_exact_keys(numeric, NUMERIC_REPRESENTATION_KEYS, "numeric representation")
    _require_exact_keys(categorical, CATEGORICAL_REPRESENTATION_KEYS, "categorical representation")
    count_contracts = {
        "own_bench_ontology_counts": frozenset(ACTIVE_CLASSES) - {"EMPTY"},
        "opp_bench_ontology_counts": frozenset(ACTIVE_CLASSES) - {"EMPTY"},
        "own_hand_supertype_counts": frozenset(SUPERTYPES),
        "own_hand_stage_counts": frozenset(POKEMON_STAGES),
    }
    for key, expected in count_contracts.items():
        counts = categorical.get(key)
        if not isinstance(counts, Mapping):
            raise ValueError(f"categorical {key} must be a mapping")
        _require_exact_keys(counts, expected, f"categorical {key}")
    _assert_outcome_free(value)


def _validate_native_card(card: Mapping[str, Any], label: str) -> None:
    extra = frozenset(str(key) for key in card) - NATIVE_CARD_KEYS
    if extra:
        raise ValueError(f"{label} has unsupported native fields: {sorted(extra)}")
    if not isinstance(card.get("id"), int) or isinstance(card.get("id"), bool):
        raise ValueError(f"{label}.id must be an integer")
    if "energies" in card:
        energies = card["energies"]
        if not isinstance(energies, list) or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in energies
        ):
            raise ValueError(f"{label}.energies must be a list of nonnegative integers")
    for key in ("energyCards", "preEvolution", "tools"):
        if key in card:
            values = card[key]
            if not isinstance(values, list) or not all(isinstance(value, Mapping) for value in values):
                raise ValueError(f"{label}.{key} must be a list of mappings")
            for index, value in enumerate(values):
                _validate_native_card(value, f"{label}.{key}[{index}]")


def validate_native_capsule(value: Mapping[str, Any]) -> None:
    _require_exact_keys(value, NATIVE_CAPSULE_KEYS, "native capsule")
    if value.get("schema") != NATIVE_SCHEMA:
        raise ValueError("unsupported native capsule schema")
    observation = value.get("observation")
    if not isinstance(observation, Mapping):
        raise ValueError("native capsule observation must be a mapping")
    _require_exact_keys(observation, frozenset({"current", "select", "search_begin_input"}), "native observation")
    if not isinstance(observation.get("search_begin_input"), str) or not observation["search_begin_input"]:
        raise ValueError("native search_begin_input must be a nonempty string")
    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("native current must be a mapping")
    _require_exact_keys(current, NATIVE_CURRENT_KEYS, "native current")
    if current.get("result") != -1:
        raise ValueError("native development roots must be nonterminal")
    players = current.get("players")
    actor = current.get("yourIndex")
    if actor not in (0, 1) or not isinstance(players, list) or len(players) != 2:
        raise ValueError("native current must contain two players and a valid actor")
    for player_index, player in enumerate(players):
        if not isinstance(player, Mapping):
            raise ValueError("native player must be a mapping")
        _require_exact_keys(player, NATIVE_PLAYER_KEYS, f"native player {player_index}")
        if player_index != actor and player.get("hand") is not None:
            raise ValueError("native capsule exposes opponent hand identity")
        for prize in player.get("prize") or ():
            if isinstance(prize, Mapping) and prize.get("id") is not None:
                raise ValueError("native capsule exposes prize identity")
        for zone in ("active", "bench", "discard", "hand"):
            cards = player.get(zone)
            if cards is None:
                continue
            if not isinstance(cards, list):
                raise ValueError(f"native player {zone} must be a list or null")
            for index, card in enumerate(cards):
                if not isinstance(card, Mapping):
                    raise ValueError("native card must be a mapping")
                _validate_native_card(card, f"native player {zone}[{index}]")
    stadium = current.get("stadium")
    if not isinstance(stadium, list):
        raise ValueError("native stadium must be a list")
    for index, card in enumerate(stadium):
        if not isinstance(card, Mapping):
            raise ValueError("native stadium card must be a mapping")
        _validate_native_card(card, f"native stadium[{index}]")
    select = observation.get("select")
    if not isinstance(select, Mapping):
        raise ValueError("native select must be a mapping")
    _require_exact_keys(select, NATIVE_SELECT_KEYS, "native select")
    if select.get("context") != 0:
        raise ValueError("native capsule must be a MAIN root")
    options = select.get("option")
    if not isinstance(options, list):
        raise ValueError("native select.option must be a list")
    for index, option in enumerate(options):
        if not isinstance(option, Mapping):
            raise ValueError("native option must be a mapping")
        extra = frozenset(str(key) for key in option) - NATIVE_OPTION_KEYS
        if extra:
            raise ValueError(f"native option {index} has unsupported fields: {sorted(extra)}")


def schema_contract() -> dict[str, list[str]]:
    return {
        "structural": sorted(STRUCTURAL_KEYS),
        "action": sorted(ACTION_KEYS),
        "action_payload": sorted(ACTION_PAYLOAD_KEYS),
        "clean_current": sorted(CLEAN_CURRENT_KEYS),
        "clean_player": sorted(CLEAN_PLAYER_KEYS),
        "clean_card": sorted(CLEAN_CARD_KEYS),
        "native_capsule": sorted(NATIVE_CAPSULE_KEYS),
        "native_current": sorted(NATIVE_CURRENT_KEYS),
        "native_player": sorted(NATIVE_PLAYER_KEYS),
        "native_card": sorted(NATIVE_CARD_KEYS),
        "native_select": sorted(NATIVE_SELECT_KEYS),
        "native_option": sorted(NATIVE_OPTION_KEYS),
        "root_schedule": sorted(SCHEDULE_KEYS),
        "numeric_representation": sorted(NUMERIC_REPRESENTATION_KEYS),
        "categorical_representation": sorted(CATEGORICAL_REPRESENTATION_KEYS),
    }


def freeze_root_schedule(values: Sequence[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    by_side: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for value in values:
        by_side[value["side_id"]].append(value)
    schedule: list[dict[str, Any]] = []
    scheduled_ids: set[str] = set()
    for side_id, members in sorted(by_side.items()):
        selected = sorted(members, key=lambda item: (item["root_priority_sha256"], item["step_index"]))[:4]
        for slot_index in range(4):
            if slot_index < len(selected):
                value = selected[slot_index]
                value["scheduled_root"] = True
                scheduled_ids.add(value["native_root_id"])
                row = {
                    "schema": SCHEDULE_SCHEMA,
                    "side_id": side_id,
                    "slot_index": slot_index,
                    "native_root_id": value["native_root_id"],
                    "root_priority_sha256": value["root_priority_sha256"],
                    "status": "scheduled",
                }
            else:
                row = {
                    "schema": SCHEDULE_SCHEMA,
                    "side_id": side_id,
                    "slot_index": slot_index,
                    "native_root_id": None,
                    "root_priority_sha256": None,
                    "status": "missing_eligible_root",
                }
            _require_exact_keys(row, SCHEDULE_KEYS, "root schedule row")
            schedule.append(row)
    return schedule, scheduled_ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-manifest", type=Path, required=True)
    parser.add_argument("--augmentation-manifest", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, action="append", required=True)
    parser.add_argument("--card-data", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-roots-out", type=Path, required=True)
    parser.add_argument("--root-schedule-out", type=Path, required=True)
    parser.add_argument("--audit-out", type=Path, required=True)
    parser.add_argument("--manifest-out", type=Path, required=True)
    args = parser.parse_args()

    allowed = _allowed_records(args.cohort_manifest, args.augmentation_manifest)
    catalog = CardCatalog.load(args.card_data)
    seen: dict[tuple[str, int, int], str] = {}
    values: list[dict[str, Any]] = []
    capsules: dict[str, dict[str, Any]] = {}
    for source in args.decisions:
        for line in source.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            episode_id = str(row.get("episode_id"))
            slot = int(row.get("player_index", -1))
            pilot = str(row.get("teacher_team") or row.get("team") or "")
            record = allowed.get((episode_id, slot, pilot))
            if record is None:
                if row.get("cohort_role") == "development":
                    raise ValueError(f"development row is not an allowed target side: {(episode_id, slot, pilot)}")
                continue
            if row.get("frozen_replay_sha256") != record["replay_sha256"]:
                raise ValueError("decision replay hash mismatch")
            key = (episode_id, slot, int(row.get("step_index", -1)))
            decision_identity = canonical_json(
                {
                    "cohort_role": row.get("cohort_role"),
                    "context": row.get("context"),
                    "episode_id": episode_id,
                    "player_index": slot,
                    "teacher_team": pilot,
                    "step_index": row.get("step_index"),
                    "action": row.get("action"),
                    "frozen_replay_sha256": row.get("frozen_replay_sha256"),
                    "observation": row.get("observation"),
                }
            )
            if key in seen:
                if seen[key] != decision_identity:
                    raise ValueError(f"conflicting duplicate decision row: {key}")
                continue
            seen[key] = decision_identity
            value = structural_row(row, record, catalog)
            if value is not None:
                values.append(value)
                capsule = native_root_capsule(row, record, value["native_root_id"])
                previous = capsules.get(value["native_root_id"])
                if previous is not None and canonical_json(previous) != canonical_json(capsule):
                    raise ValueError("conflicting native-root capsule identity")
                capsules[value["native_root_id"]] = capsule
    values.sort(key=lambda value: (value["game_id"], value["player_index"], value["step_index"]))
    root_schedule, scheduled_ids = freeze_root_schedule(values)
    for value in values:
        validate_structural_row(value)
    scheduled_capsules = [capsules[root_id] for root_id in sorted(scheduled_ids)]
    for capsule in scheduled_capsules:
        validate_native_capsule(capsule)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(canonical_json(value) + "\n")
    args.native_roots_out.parent.mkdir(parents=True, exist_ok=True)
    with args.native_roots_out.open("w", encoding="utf-8", newline="\n") as handle:
        for capsule in scheduled_capsules:
            handle.write(canonical_json(capsule) + "\n")
    args.root_schedule_out.parent.mkdir(parents=True, exist_ok=True)
    with args.root_schedule_out.open("w", encoding="utf-8", newline="\n") as handle:
        for row in root_schedule:
            handle.write(canonical_json(row) + "\n")
    contract = schema_contract()
    forbidden_paths = [path for value in values for path in _forbidden_paths(value)]
    base_manifest = _load(args.cohort_manifest)
    sealed_ids = {
        str(record["episode_id"])
        for record in base_manifest.get("episodes") or ()
        if record.get("role") == "holdout"
    }
    sealed_rows = sum(value["game_id"] in sealed_ids for value in values)
    audit = {
        "schema": AUDIT_SCHEMA,
        "schema_contract_sha256": hashlib.sha256(canonical_json(contract).encode("ascii")).hexdigest(),
        "validated_structural_rows": len(values),
        "validated_native_roots": len(scheduled_capsules),
        "validated_schedule_slots": len(root_schedule),
        "unknown_fields": 0,
        "forbidden_fields": len(forbidden_paths),
        "outcome_labels_present": bool(forbidden_paths),
        "sealed_holdout_rows": sealed_rows,
        "passed": not forbidden_paths and sealed_rows == 0,
    }
    if not audit["passed"]:
        raise ValueError("structural schema audit failed")
    args.audit_out.parent.mkdir(parents=True, exist_ok=True)
    args.audit_out.write_text(canonical_json(audit) + "\n", encoding="utf-8", newline="\n")
    manifest = {
        "schema": "branch_bridge_structural_manifest_v2",
        "rows": len(values),
        "scheduled_slots": len(root_schedule),
        "scheduled_native_roots": len(scheduled_capsules),
        "missing_root_slots": sum(row["status"] != "scheduled" for row in root_schedule),
        "independent_games": len({value["game_id"] for value in values}),
        "target_sides": len({value["side_id"] for value in values}),
        "pilots": sorted({value["pilot"] for value in values}),
        "module_versions": sorted({value["module_version"] for value in values}),
        "schema_audit_sha256": sha256_file(args.audit_out),
        "cohort_manifest_sha256": sha256_file(args.cohort_manifest),
        "augmentation_manifest_sha256": sha256_file(args.augmentation_manifest),
        "decision_source_sha256": [sha256_file(path) for path in args.decisions],
        "card_data_sha256": sha256_file(args.card_data),
        "catalog_sha256": catalog.canonical_hash,
        "catalog_module_sha256": sha256_file(ROOT / "evaluation_v2" / "catalog_semantics.py"),
        "builder_sha256": sha256_file(Path(__file__)),
        "structural_rows_sha256": sha256_file(args.output),
        "native_roots_sha256": sha256_file(args.native_roots_out),
        "root_schedule_sha256": sha256_file(args.root_schedule_out),
        "root_namespace": ROOT_NAMESPACE,
        "roots_per_target_side": 4,
    }
    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.write_text(canonical_json(manifest) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
