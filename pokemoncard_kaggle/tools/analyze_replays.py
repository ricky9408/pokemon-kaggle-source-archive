#!/usr/bin/env python3
"""Summarize Kaggle Pokemon TCG AI Battle replay JSON files.

This intentionally works from public replay files only. It is useful on macOS
where the supplied x86-64 Linux simulator library cannot be imported directly.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def load_names(card_csv: Path) -> dict[int, str]:
    with card_csv.open(encoding="utf-8-sig", newline="") as file:
        return {int(row["Card ID"]): row["Card Name"] for row in csv.DictReader(file)}


def archetype(deck: list[int]) -> str:
    counts = Counter(deck)
    ids = set(counts)
    if {265, 268, 269, 270, 271} & ids:
        return "iono-lightning"
    if {646, 648}.issubset(ids):
        if {103, 104}.issubset(ids):
            return "grimmsnarl-froslass"
        return "grimmsnarl"
    if {878, 879}.issubset(ids):
        return "hops-trevenant"
    if {379, 380, 381}.issubset(ids):
        return "cynthias-garchomp"
    if 687 in ids:
        return "mega-absol-box"
    if 63 in ids:
        return "raging-bolt"
    if 272 in ids and 756 in ids:
        return "lillie-clefairy"
    if {741, 742, 743}.issubset(ids):
        if 1266 in ids:
            if counts[1081] >= 4:
                return "alakazam-nighttime-hammer"
            return "alakazam-nighttime-mine"
        if counts[1081] >= 4:
            return "alakazam-hammer"
        if counts[1264] >= 4 and counts[1081] >= 3:
            return "alakazam-battle-cage"
        return "alakazam"
    if {89, 90, 92, 93}.issubset(ids):
        return "festival-lead"
    if {292, 293}.issubset(ids):
        return "n-zoroark"
    if {162, 163}.issubset(ids):
        return "slowking"
    if {344, 345}.issubset(ids) and {1212, 1235, 1147}.issubset(ids) and counts[1] >= 16:
        return "pure-crustle-heal"
    if {344, 345, 1198, 1219}.issubset(ids):
        return "crustle-petrel-crispin"
    if {344, 345}.issubset(ids) and 1120 in ids:
        return "hammer-crustle"
    if {344, 345}.issubset(ids) and ({1264, 1224} & ids):
        return "battle-cage-crustle"
    if {352, 353, 354, 344, 345}.issubset(ids):
        return "ethan-crustle"
    if {352, 353, 354}.issubset(ids):
        return "ethan-typhlosion"
    if ({96, 710}.issubset(ids)) and ({402, 403, 404} & ids):
        return "ogerpon-meganium"
    if {119, 120, 121}.issubset(ids):
        if {131, 132, 133} & ids:
            return "dragapult-dusknoir"
        if {172, 173, 174} & ids:
            return "dragapult-noctowl"
        return "dragapult"
    if 678 in ids:
        return "mega-lucario"
    if {722, 723} & ids:
        return "mega-abomasnow"
    if 756 in ids and {344, 345}.issubset(ids):
        return "mega-kangaskhan-crustle"
    if 756 in ids:
        return "mega-kangaskhan"
    if {400, 401, 431}.issubset(ids):
        return "rocket-mewtwo"
    if {463, 891} & ids:
        return "rocket-honchkrow"
    if 150 in ids:
        return "hydrapple"
    if ({96, 108, 117} & ids) and (1090 in ids or 1250 in ids):
        return "ogerpon-box"
    if ({96, 150, 710} & ids) and ({1094, 1261} & ids):
        return "grass-toolbox"
    if ({676, 1142}.issubset(ids)) or ({116, 676}.issubset(ids)):
        return "fighting-toolbox"
    if {408, 409}.issubset(ids):
        return "houndoom-crustle"
    if {344, 345}.issubset(ids):
        return "pure-crustle"
    return "other"


def deck_hash(deck: list[int]) -> str:
    return hashlib.sha1(",".join(map(str, sorted(deck))).encode()).hexdigest()[:10]


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


def summarize_deck(deck: list[int], names: dict[int, str], limit: int) -> str:
    pieces = []
    for card_id, count in Counter(deck).most_common(limit):
        pieces.append(f"{names.get(card_id, card_id)}x{count}")
    return ", ".join(pieces)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--no-dedupe", action="store_true")
    args = parser.parse_args()

    names = load_names(args.cards)
    archetypes: Counter[str] = Counter()
    wins: Counter[str] = Counter()
    replay_paths = sorted(args.replays)
    duplicates = 0
    if not args.no_dedupe:
        replay_paths, duplicates = unique_replay_paths(replay_paths)
        if duplicates:
            print(f"Deduped duplicate replay files: {duplicates}")

    for replay_path in replay_paths:
        data = json.loads(replay_path.read_text())
        teams = data["info"]["TeamNames"]
        rewards = data["rewards"]
        decks = data["steps"][0][0]["visualize"][0]["action"]
        print(f"\n{replay_path.name}: {teams} rewards={rewards} steps={len(data['steps'])}")
        for player_index, deck in enumerate(decks):
            kind = archetype(deck)
            archetypes[kind] += 1
            if rewards[player_index] == 1:
                wins[kind] += 1
            print(
                f"  p{player_index} {teams[player_index]} "
                f"reward={rewards[player_index]} {kind} {deck_hash(deck)} "
                f"{summarize_deck(deck, names, args.top)}"
            )

    print("\nArchetype frequency:")
    for kind, count in archetypes.most_common():
        print(f"  {kind}: {count} decks, {wins[kind]} wins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
