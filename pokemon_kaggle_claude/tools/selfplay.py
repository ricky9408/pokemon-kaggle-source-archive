#!/usr/bin/env python3
"""Fast BC-level self-play data generation: our agent (policy.json, no search)
vs the all-deck policy (policy_all.json) piloting scouted meta decks.

Dumps decision states + outcomes as JSONL compatible with train_value.py.

Usage:
  python3 tools/selfplay.py --games-per-deck 60 --out analysis/selfplay_states.jsonl
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "engine"))
sys.path.insert(0, str(ROOT / "agent"))

from features import option_features  # noqa: E402


def scorer(weights):
    def score(obs):
        opts = obs["select"]["option"]
        out = []
        for i in range(len(opts)):
            try:
                out.append(sum(weights.get(f, 0.0) for f in option_features(obs, i)))
            except Exception:
                out.append(-1e9)
        return out
    return score


def pick(obs, score_fn, rng, temp_top=1):
    sel = obs["select"]
    n = len(sel.get("option") or [])
    mn = max(0, min(sel.get("minCount", 1), n))
    mx = max(mn, min(sel.get("maxCount", 1), n))
    scores = score_fn(obs)
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    if temp_top > 1 and mn == 1 and mx == 1 and n > 1:
        k = min(temp_top, n)
        return [order[rng.randrange(k)] if rng.random() < 0.25 else order[0]]
    picked = order[:max(mn, min(1, mx))]
    return picked if picked else list(range(mn))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--games-per-deck", type=int, default=60)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=99)
    ap.add_argument("--sample-every", type=int, default=3,
                    help="record every Nth decision state")
    args = ap.parse_args()

    from cg.game import battle_start, battle_select, battle_finish

    my_deck = [int(x) for x in (ROOT / "agent" / "deck.csv").read_text().split() if x.strip()][:60]
    meta = json.load(open(ROOT / "agent" / "meta_decks.json"))
    w_me = json.load(open(ROOT / "agent" / "policy.json"))["weights"]
    w_all = json.load(open(ROOT / "agent" / "policy_all.json"))["weights"]
    s_me, s_all = scorer(w_me), scorer(w_all)

    rng = random.Random(args.seed)
    n_states = 0
    n_games = 0
    wins = 0
    with args.out.open("w") as out:
        for dh, opp_deck in meta.items():
            for g in range(args.games_per_deck):
                order = g % 2
                d0, d1 = (my_deck, opp_deck) if order == 0 else (opp_deck, my_deck)
                us = 0 if order == 0 else 1
                obs, sd = battle_start(list(d0), list(d1))
                if obs is None:
                    continue
                states = []
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
                    fn = s_me if p == us else s_all
                    act = pick(obs, fn, rng, temp_top=2)
                    if steps % args.sample_every == 0 and cur is not None and cur.get("turn", 0) > 0:
                        states.append({"obs_current_only": True, "obs": {"current": cur},
                                       "player": p})
                    n = len(sel["option"])
                    ok = (act and all(0 <= i < n for i in act)
                          and sel["minCount"] <= len(act) <= sel["maxCount"]
                          and len(set(act)) == len(act))
                    if not ok:
                        act = list(range(max(1, sel["minCount"])))[:max(1, sel["minCount"])]
                    obs = battle_select(act)
                    steps += 1
                battle_finish()
                n_games += 1
                if result == us:
                    wins += 1
                if result in (0, 1):
                    eid = f"sp_{dh}_{g}"
                    for st in states:
                        row = {"episode_id": eid, "player_index": st["player"],
                               "won": result == st["player"], "obs": st["obs"]}
                        out.write(json.dumps(row) + "\n")
                        n_states += 1
    print(f"games={n_games} our_winrate={wins/max(1,n_games):.3f} states={n_states}")


if __name__ == "__main__":
    sys.exit(main())
