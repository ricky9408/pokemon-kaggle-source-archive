#!/usr/bin/env python3
"""Freeze target-side exact deck lists from a scored replay download summary."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from analyze_replays import archetype, deck_hash  # noqa: E402
from build_ml_replay_dataset import load_initial_decks  # noqa: E402


def collect(
    summary: Path,
    *,
    include_opponents: bool = False,
    excluded_episode_ids: set[int] | None = None,
) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, int]] = set()
    excluded = excluded_episode_ids or set()
    with summary.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            replay_path = Path(row["path"])
            if not replay_path.is_absolute():
                replay_path = REPO / replay_path
            if not replay_path.exists():
                continue
            replay = json.loads(replay_path.read_text())
            teams = (replay.get("info") or {}).get("TeamNames") or []
            decks = load_initial_decks(replay)
            episode_id = int(row["episode_id"])
            if episode_id in excluded:
                continue
            for slot, team in enumerate(teams):
                is_target = team == row.get("team")
                if (not is_target and not include_opponents) or slot >= len(decks) or len(decks[slot]) != 60:
                    continue
                if (team, episode_id) in seen:
                    continue
                seen.add((team, episode_id))
                cards = decks[slot]
                identifier = deck_hash(cards)
                entry = grouped.setdefault(
                    identifier,
                    {
                        "deck_hash": identifier,
                        "archetype": archetype(cards),
                        "cards": sorted(cards),
                        "teams": set(),
                        "submission_ids": set(),
                        "episode_ids": set(),
                        "best_rank": int(row["rank"]) if is_target else 999999,
                        "best_score": float(row["score"]) if is_target else 0.0,
                    },
                )
                entry["teams"].add(team)
                if is_target:
                    entry["submission_ids"].add(int(row["submission_id"]))
                entry["episode_ids"].add(episode_id)
                if is_target:
                    entry["best_rank"] = min(entry["best_rank"], int(row["rank"]))
                    entry["best_score"] = max(entry["best_score"], float(row["score"]))
    records = []
    for entry in grouped.values():
        records.append(
            {
                **entry,
                "teams": sorted(entry["teams"]),
                "submission_ids": sorted(entry["submission_ids"]),
                "episode_ids": sorted(entry["episode_ids"]),
            }
        )
    return sorted(records, key=lambda item: (item["best_rank"], item["deck_hash"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-opponents", action="store_true")
    parser.add_argument("--exclude-manifest", type=Path, default=None)
    parser.add_argument("--exclude-role", choices=("development", "holdout"), default="holdout")
    args = parser.parse_args()
    excluded: set[int] = set()
    if args.exclude_manifest is not None:
        sys.path.insert(0, str(REPO))
        from evaluation_v2.cohort import load_manifest

        manifest = load_manifest(args.exclude_manifest)
        excluded = {episode.episode_id for episode in manifest.episodes if episode.role == args.exclude_role}
    entries = collect(
        args.summary,
        include_opponents=args.include_opponents,
        excluded_episode_ids=excluded,
    )
    payload = {
        "schema_version": 1,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(args.summary),
        "source_sha256": hashlib.sha256(args.summary.read_bytes()).hexdigest(),
        "include_opponents": args.include_opponents,
        "excluded_episode_ids": sorted(excluded),
        "entries": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    print(f"decks={len(entries)} teams={len({team for entry in entries for team in entry['teams']})} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
