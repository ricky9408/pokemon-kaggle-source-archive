#!/usr/bin/env python3
"""Distill round 2: our FULL agent vs STRONG opponents (prev-repo agent dirs).
Records our single-pick decisions with an `override` tag (search overrode BC).

Usage:
  python3 tools/distill2.py --opponent DIR --games 100 --seed 7 --out FILE.jsonl
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "agent"))


def load_agent(agent_dir: Path, name: str):
    sys.path.insert(0, str(agent_dir))
    old = os.getcwd()
    os.chdir(agent_dir)
    try:
        spec = importlib.util.spec_from_file_location(name, agent_dir / "main.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    finally:
        os.chdir(old)
    deck = [int(x) for x in (agent_dir / "deck.csv").read_text().split() if x.strip()][:60]
    return mod, deck


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--opponent", type=Path, required=True)
    ap.add_argument("--games", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    os.chdir(ROOT / "agent")
    import main as ag
    os.chdir(ROOT)
    opp_mod, opp_deck = load_agent(args.opponent.resolve(), f"opp_{args.seed}")
    from cg.game import battle_start, battle_select, battle_finish

    random.seed(args.seed)
    my_deck = ag.MY_DECK
    n_rows = 0
    wins = 0
    played = 0
    opp_dir = str(args.opponent.resolve())
    with args.out.open("w") as out:
        for g in range(args.games):
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
                        # detect override: BC's greedy pick vs final action
                        bc_pick = None
                        if (sel.get("minCount") == 1 and sel.get("maxCount") == 1
                                and len(sel.get("option") or []) > 1):
                            scores = ag.guard_scores(obs, ag.policy_scores(obs))
                            bc_pick = max(range(len(scores)), key=lambda i: (scores[i], -i))
                    finally:
                        os.chdir(ROOT)
                    if bc_pick is not None and isinstance(act, list) and len(act) == 1:
                        rows.append({"episode_id": f"d2_{args.seed}_{g}",
                                     "team": "distill2", "player_index": p,
                                     "turn": cur.get("turn"),
                                     "deck_hash": "ours", "opp_deck_hash": "strong",
                                     "override": act[0] != bc_pick,
                                     "obs": obs, "action": list(act)})
                else:
                    old = os.getcwd()
                    os.chdir(opp_dir)
                    try:
                        act = opp_mod.agent(obs)
                    except Exception:
                        act = list(range(max(1, sel.get("minCount", 1))))
                    finally:
                        os.chdir(old)
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
                for row in rows:
                    row["won"] = True
                    out.write(json.dumps(row) + "\n")
                    n_rows += 1
            if played % 10 == 0:
                print(f"progress: {played} games, winrate {wins/played:.2f}, rows {n_rows}", flush=True)
    print(f"DONE games={played} winrate={wins/max(1,played):.3f} rows={n_rows}")


if __name__ == "__main__":
    sys.exit(main())
