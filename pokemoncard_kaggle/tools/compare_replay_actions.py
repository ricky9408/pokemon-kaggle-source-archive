#!/usr/bin/env python3
"""Compare an agent's choices with public replay actions.

Run this inside the linux/amd64 simulator environment, for example:

docker run -i --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work python:3.11-slim \
  python tools/compare_replay_actions.py --agent agents/v21_ethan_crustle \
  --team PyJa --team sbite0138 scouting/current_top/*.json
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


sys.path.insert(0, "submission")
from cg.api import AreaType, OptionType, SelectContext  # noqa: E402


def enum_name(enum_class, value) -> str:
    for name in dir(enum_class):
        if name.isupper() and getattr(enum_class, name) == value:
            return name
    return str(value)


def load_names(path: Path) -> dict[int, str]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        return {
            int(row["Card ID"]): row["Card Name"]
            for row in csv.DictReader(file)
        }


def load_agent(agent_dir: Path):
    agent_dir = agent_dir.resolve()
    sys.path.insert(0, str(agent_dir))
    old_cwd = os.getcwd()
    os.chdir(agent_dir)
    try:
        spec = importlib.util.spec_from_file_location("compared_agent", agent_dir / "main.py")
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load {agent_dir / 'main.py'}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.agent
    finally:
        os.chdir(old_cwd)


def get_card_id(obs: dict, option: dict) -> int | None:
    area = option.get("area")
    index = option.get("index")
    player_index = option.get("playerIndex", (obs.get("current") or {}).get("yourIndex"))
    current = obs.get("current") or {}
    try:
        if area == AreaType.DECK:
            card = (obs.get("select") or {}).get("deck", [])[index]
        elif area == AreaType.HAND:
            card = current["players"][player_index]["hand"][index]
        elif area == AreaType.DISCARD:
            card = current["players"][player_index]["discard"][index]
        elif area == AreaType.ACTIVE:
            card = current["players"][player_index]["active"][index]
        elif area == AreaType.BENCH:
            card = current["players"][player_index]["bench"][index]
        elif area == AreaType.LOOKING:
            card = current.get("looking", [])[index]
        else:
            card = None
    except Exception:
        return None
    return card.get("id") if isinstance(card, dict) else None


def option_description(obs: dict, option_index: int, names: dict[int, str]) -> str:
    options = (obs.get("select") or {}).get("option") or []
    if not 0 <= option_index < len(options):
        return f"{option_index}:out"
    option = options[option_index]
    parts = [f"{option_index}:{enum_name(OptionType, option.get('type'))}"]
    card_id = get_card_id(obs, option)
    if card_id is None and option.get("type") == OptionType.PLAY:
        card_id = get_card_id(
            obs,
            {
                "area": AreaType.HAND,
                "index": option.get("index"),
                "playerIndex": (obs.get("current") or {}).get("yourIndex"),
            },
        )
    if card_id is not None:
        parts.append(f"{names.get(card_id, card_id)}({card_id})")
    if "number" in option:
        parts.append(f"num={option.get('number')}")
    if "attackId" in option:
        parts.append(f"attack={option.get('attackId')}")
    if "inPlayArea" in option:
        parts.append(f"to={enum_name(AreaType, option.get('inPlayArea'))}:{option.get('inPlayIndex')}")
    return " ".join(parts)


def valid_action(action: object, option_count: int, minimum: int, maximum: int) -> bool:
    if not isinstance(action, list):
        return False
    if not minimum <= len(action) <= maximum:
        return False
    return all(isinstance(item, int) and 0 <= item < option_count for item in action)


def replay_id(path: Path) -> str:
    match = re.search(r"episode-(\d+)-replay\.json$", path.name)
    return match.group(1) if match else str(path)


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


def public_action_for_observation(steps: list, step_index: int, slot: int) -> object:
    """Replay action chosen for observation at step_index.

    Public Kaggle replay JSON stores the action responding to
    steps[t][slot]["observation"] on steps[t + 1][slot]["action"].
    """
    next_index = step_index + 1
    if next_index >= len(steps):
        return None
    try:
        return steps[next_index][slot].get("action")
    except (AttributeError, IndexError, TypeError):
        return None


def decision_state_key(obs: dict) -> str:
    """Stable key for a selectable public observation.

    Replay rows can repeat the same selectable observation while another player
    advances the game. The action for the first row is real; later identical
    state/select rows are stale and should not become extra supervised labels.
    """

    current = dict(obs.get("current") or {})
    current.pop("result", None)
    return json.dumps(
        {"current": current, "select": obs.get("select") or {}},
        sort_keys=True,
        separators=(",", ":"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--agent", type=Path, default=Path("submission"))
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--team", action="append", default=[])
    parser.add_argument("--examples", type=int, default=8)
    parser.add_argument("--no-dedupe", action="store_true")
    args = parser.parse_args()

    names = load_names(args.cards)
    agent = load_agent(args.agent)
    target_teams = set(args.team)

    counts: Counter[tuple[str, bool]] = Counter()
    examples = defaultdict(list)
    compared = 0
    replay_paths = sorted(args.replays)
    duplicates = 0
    if not args.no_dedupe:
        replay_paths, duplicates = unique_replay_paths(replay_paths)
        if duplicates:
            print(f"Deduped duplicate replay files: {duplicates}")

    for replay_path in replay_paths:
        data = json.loads(replay_path.read_text())
        teams = data["info"]["TeamNames"]
        steps = data["steps"]
        seen_decision_states: set[tuple[int, str]] = set()
        for step_index, step in enumerate(steps):
            for slot, record in enumerate(step):
                if target_teams and teams[slot] not in target_teams:
                    continue
                obs = record.get("observation") or {}
                select = obs.get("select")
                if not select:
                    continue
                state_key = (slot, decision_state_key(obs))
                if state_key in seen_decision_states:
                    continue
                seen_decision_states.add(state_key)
                action = public_action_for_observation(steps, step_index, slot)
                options = select.get("option") or []
                minimum = select.get("minCount", 0)
                maximum = select.get("maxCount", len(options))
                if not options or not valid_action(action, len(options), minimum, maximum):
                    continue
                if len(action) == 60:
                    continue

                ours = agent(obs)
                if not valid_action(ours, len(options), minimum, maximum):
                    continue

                context = enum_name(SelectContext, select.get("context"))
                same = action == ours
                counts[(context, same)] += 1
                compared += 1
                if not same and len(examples[context]) < args.examples:
                    examples[context].append(
                        (
                            replay_path.name,
                            step_index,
                            teams[slot],
                            action,
                            ours,
                            [option_description(obs, index, names) for index in action],
                            [option_description(obs, index, names) for index in ours],
                        )
                    )

    print(f"valid compared decisions: {compared}")
    for (context, same), count in counts.most_common():
        label = "same" if same else "diff"
        print(f"{context} {label} {count}")

    for context, rows in examples.items():
        print(f"\nCTX {context}")
        for replay_name, step_index, team, their_action, our_action, their_desc, our_desc in rows:
            print(
                f"{replay_name} step={step_index} team={team} "
                f"their={their_action} {their_desc} ours={our_action} {our_desc}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
