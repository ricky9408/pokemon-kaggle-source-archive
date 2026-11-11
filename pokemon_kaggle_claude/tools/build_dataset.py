#!/usr/bin/env python3
"""Extract per-decision training rows from scouted Kaggle replays.

For every replay, identify each player's deck (from step0 visualize), then for
every observation with a select, record (obs_dict, action, player meta).
Only keeps decisions of players whose deck matches --deck (multiset), unless
--all-decks is set.

Output: JSONL, one row per decision:
  {episode_id, team, player_index, won, turn, deck_hash, obs, action}

Usage:
  python3 tools/build_dataset.py --scouting-root scouting --deck agent/deck.csv \
      --out analysis/grimm_decisions.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


def deck_hash(cards: list[int]) -> str:
    return hashlib.sha1(",".join(map(str, sorted(cards))).encode()).hexdigest()[:10]


def initial_decks(data: dict) -> list[list[int]] | None:
    try:
        vis = data["steps"][0][0].get("visualize")
        for v in vis or []:
            act = v.get("action")
            if (isinstance(act, list) and len(act) == 2
                    and all(isinstance(d, list) and len(d) == 60 for d in act)):
                return act
    except Exception:
        pass
    return None


def iter_decisions(path: Path, want_hash: str | None):
    try:
        data = json.loads(path.read_text())
    except Exception:
        return
    decks = initial_decks(data)
    if decks is None:
        return
    hashes = [deck_hash(d) for d in decks]
    rewards = data.get("rewards") or [None, None]
    teams = (data.get("info") or {}).get("TeamNames") or ["?", "?"]
    steps = data.get("steps") or []
    eid = str(data.get("id") or path.stem)
    for p in (0, 1):
        if want_hash is not None and hashes[p] != want_hash:
            continue
        for t in range(len(steps) - 1):
            try:
                entry = steps[t][p]
                obs = entry.get("observation") or {}
                sel = obs.get("select")
                cur = obs.get("current")
                if sel is None or cur is None:
                    continue
                if cur.get("yourIndex") != p:
                    continue
                action = steps[t + 1][p].get("action")
                n = len(sel.get("option") or [])
                if not isinstance(action, list) or not action:
                    continue
                if not all(isinstance(i, int) and 0 <= i < n for i in action):
                    continue
                yield {
                    "episode_id": eid,
                    "team": teams[p],
                    "player_index": p,
                    "won": rewards[p] == 1,
                    "turn": cur.get("turn"),
                    "deck_hash": hashes[p],
                    "opp_deck_hash": hashes[1 - p],
                    "obs": obs,
                    "action": action,
                }
            except Exception:
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scouting-root", type=Path, default=Path("scouting"))
    ap.add_argument("--deck", type=Path, default=None,
                    help="deck.csv whose multiset filters which players to learn from")
    ap.add_argument("--all-decks", action="store_true")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    want = None
    if args.deck and not args.all_decks:
        cards = [int(x) for x in args.deck.read_text().split() if x.strip()][:60]
        want = deck_hash(cards)
        print(f"filtering to deck_hash={want}")

    paths = sorted(set(args.scouting_root.glob("**/episode-*-replay.json")))
    seen_eids: set[str] = set()
    n_rows = 0
    counts = Counter()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as out:
        for path in paths:
            eid = path.name.split("-")[1]
            if eid in seen_eids:
                continue
            seen_eids.add(eid)
            for row in iter_decisions(path, want):
                out.write(json.dumps(row) + "\n")
                n_rows += 1
                counts[(row["team"], row["deck_hash"])] += 1
    print(f"replays={len(seen_eids)} decisions={n_rows}")
    for (team, dh), c in counts.most_common(20):
        print(f"  {team:30s} {dh} {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
