#!/usr/bin/env python3
"""Search-distillation data generation: our FULL agent (BC+guards+search) plays
vs the all-deck policy piloting meta decks; every decision our agent makes is
recorded as a training row (search-improved actions included).

Output rows are compatible with tools/train_policy.py (obs + action).

Usage:
  python3 tools/distill.py --games 300 --out analysis/distill_1.jsonl --seed 5
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "agent"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--games", type=int, default=300)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=5)
    args = ap.parse_args()

    os.chdir(ROOT / "agent")
    import main as ag
    from features import option_features  # noqa: F401
    os.chdir(ROOT)
    from cg.game import battle_start, battle_select, battle_finish

    meta = json.load(open(ROOT / "agent" / "meta_decks.json"))
    w_all = json.load(open(ROOT / "agent" / "policy_all.json"))["weights"]

    def opp_pick(obs, rng):
        sel = obs["select"]
        n = len(sel.get("option") or [])
        mn = max(0, min(sel.get("minCount", 1), n))
        mx = max(mn, min(sel.get("maxCount", 1), n))
        scores = []
        for i in range(n):
            try:
                scores.append(sum(w_all.get(f, 0.0) for f in option_features(obs, i)))
            except Exception:
                scores.append(-1e9)
        order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
        if mn == 1 and mx == 1 and n > 1 and rng.random() < 0.2:
            return [order[rng.randrange(min(2, n))]]
        picked = order[:max(mn, min(1, mx))]
        return picked if picked else list(range(mn))

    rng = random.Random(args.seed)
    deck_items = list(meta.items())
    my_deck = ag.MY_DECK
    n_rows = 0
    wins = 0
    played = 0
    with args.out.open("w") as out:
        for g in range(args.games):
            dh, opp_deck = deck_items[g % len(deck_items)]
            order = g % 2
            d0, d1 = (my_deck, opp_deck) if order == 0 else (opp_deck, my_deck)
            us = 0 if order == 0 else 1
            obs, sd = battle_start(list(d0), list(d1))
            if obs is None:
                continue
            rows = []
            steps = 0
            result = -1
            while steps < 4000:
                cur = obs.get("current")
                if cur is not None and cur.get("result", -1) != -1:
                    result = cur["result"]
                    break
                sel = obs.get("select")
                if sel is None:
                    break
                p = cur.get("yourIndex") if cur else 0
                if p == us:
                    os.chdir(ROOT / "agent")
                    try:
                        act = ag.agent(obs)
                    finally:
                        os.chdir(ROOT)
                    if (sel.get("minCount") == 1 and sel.get("maxCount") == 1
                            and len(sel.get("option") or []) > 1):
                        rows.append({"episode_id": f"ds_{args.seed}_{g}",
                                     "team": "distill", "player_index": p,
                                     "turn": cur.get("turn"),
                                     "deck_hash": "ours", "opp_deck_hash": dh,
                                     "obs": obs, "action": list(act)})
                else:
                    act = opp_pick(obs, rng)
                n = len(sel["option"])
                ok = (isinstance(act, list) and act
                      and all(isinstance(i, int) and 0 <= i < n for i in act)
                      and len(set(act)) == len(act)
                      and sel["minCount"] <= len(act) <= sel["maxCount"])
                if not ok:
                    act = list(range(max(1, sel["minCount"])))
                obs = battle_select(act)
                steps += 1
            battle_finish()
            played += 1
            won = result == us
            if won:
                wins += 1
            # keep only WINNING games' decisions (search-improved + successful)
            if won:
                for row in rows:
                    row["won"] = True
                    out.write(json.dumps(row) + "\n")
                    n_rows += 1
            if played % 20 == 0:
                print(f"progress: {played} games, winrate {wins/played:.2f}, rows {n_rows}", flush=True)
    print(f"DONE games={played} winrate={wins/max(1,played):.3f} rows={n_rows}")


if __name__ == "__main__":
    sys.exit(main())
