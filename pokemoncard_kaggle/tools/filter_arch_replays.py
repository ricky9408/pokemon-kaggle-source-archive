#!/usr/bin/env python3
"""Filter public replay lists to target-side Archaludon/Cinderace states.

The top-window scout intentionally downloads many decks. Shared trainers such as
Pokegear and opponent-side cards can make a replay look Archaludon-like when the
target team is actually on another shell. This tool keeps only replays where the
leaderboard target team's own observed cards include core Archaludon/Cinderace
cards, and optionally writes a pressure-matchup subset.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


CORE_ARCH_CARDS = {
    57: "Relicanth",
    169: "Duraludon",
    190: "Archaludon ex",
    666: "Cinderace",
}

PRESSURE_MATCHUP_CARDS = {
    121: "Dragapult ex",
    245: "Alakazam",
    304: "Hop Snorlax",
    345: "Crustle",
    533: "Crustle",
    677: "Riolu/Lucario line",
    678: "Riolu/Lucario line",
    741: "Alakazam line",
    742: "Alakazam line",
    743: "Alakazam line",
    756: "Mega Kangaskhan ex",
}


def collect_ids(value: Any, out: set[int]) -> None:
    if isinstance(value, dict):
        for key in ("id", "cardId"):
            try:
                if key in value and value[key] is not None:
                    out.add(int(value[key]))
            except (TypeError, ValueError):
                pass
        for child in value.values():
            collect_ids(child, out)
    elif isinstance(value, list):
        for child in value:
            collect_ids(child, out)


def path_target_map(summary_path: Path) -> dict[str, str]:
    if not summary_path.exists():
        return {}
    with summary_path.open(encoding="utf-8", newline="") as handle:
        return {row["path"]: row.get("team", "") for row in csv.DictReader(handle)}


def own_and_opponent_ids(replay_path: Path, target_team: str) -> tuple[set[int], set[int]]:
    data = json.loads(replay_path.read_text(encoding="utf-8"))
    teams = data.get("info", {}).get("TeamNames") or []
    own: set[int] = set()
    opponent: set[int] = set()
    for step in data.get("steps") or []:
        for slot, record in enumerate(step):
            if slot >= len(teams) or teams[slot] != target_team:
                continue
            obs = (record or {}).get("observation") or {}
            current = obs.get("current") or {}
            players = current.get("players") or []
            your_index = current.get("yourIndex", slot)
            if isinstance(your_index, int) and len(players) >= 2:
                collect_ids(players[your_index], own)
                collect_ids(players[1 - your_index], opponent)
            select = obs.get("select") or {}
            for key in ("deck", "hand", "discard", "looking"):
                collect_ids(select.get(key), own)
    return own, opponent


def write_list(path: Path, replay_paths: list[Path]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(str(replay_path) for replay_path in replay_paths) + ("\n" if replay_paths else ""), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scout-dir", required=True, type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--pressure-output", type=Path)
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--min-core-cards", type=int, default=1)
    args = parser.parse_args()

    summary_path = args.summary or args.scout_dir / "download_summary.csv"
    target_by_path = path_target_map(summary_path)
    rows: list[dict[str, str]] = []
    core_replays: list[Path] = []
    pressure_replays: list[Path] = []

    for replay_path in sorted(args.scout_dir.glob("**/*replay.json")):
        target_team = target_by_path.get(str(replay_path), "")
        if not target_team:
            continue
        own_ids, opponent_ids = own_and_opponent_ids(replay_path, target_team)
        core_ids = sorted(own_ids & set(CORE_ARCH_CARDS))
        pressure_ids = sorted(opponent_ids & set(PRESSURE_MATCHUP_CARDS))
        if len(core_ids) < args.min_core_cards:
            continue
        core_replays.append(replay_path)
        if pressure_ids:
            pressure_replays.append(replay_path)
        rows.append(
            {
                "team": target_team,
                "path": str(replay_path),
                "core_cards": ";".join(CORE_ARCH_CARDS[cid] for cid in core_ids),
                "pressure_cards": ";".join(PRESSURE_MATCHUP_CARDS[cid] for cid in pressure_ids),
                "core_count": str(len(core_ids)),
                "pressure_count": str(len(pressure_ids)),
            }
        )

    write_list(args.output, core_replays)
    if args.pressure_output:
        write_list(args.pressure_output, pressure_replays)
    if args.metadata_output:
        args.metadata_output.parent.mkdir(parents=True, exist_ok=True)
        with args.metadata_output.open("w", encoding="utf-8", newline="") as handle:
            fieldnames = ["team", "path", "core_cards", "pressure_cards", "core_count", "pressure_count"]
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    team_counts = Counter(row["team"] for row in rows)
    pressure_counts = Counter(
        card
        for row in rows
        for card in row["pressure_cards"].split(";")
        if card
    )
    print(f"core_replays={len(core_replays)}")
    print(f"pressure_replays={len(pressure_replays)}")
    print("teams=" + ",".join(f"{team}:{count}" for team, count in team_counts.most_common()))
    print("pressure_cards=" + ",".join(f"{card}:{count}" for card, count in pressure_counts.most_common()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
