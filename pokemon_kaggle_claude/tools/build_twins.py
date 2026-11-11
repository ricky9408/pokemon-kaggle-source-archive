#!/usr/bin/env python3
"""Build behavior twins: per-(team,deck) BC pilots cloned from public replays,
each tagged with the team's known public rating (Issue #1).

Selection: known leaderboard score, >=min-rows decisions, dedupe by team
(highest-row deck), spread across the rating range.

Usage:
  python3 tools/build_twins.py --out baselines/twins --min-rows 400 --max-twins 20
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PILOT_MAIN = '''import json, os, sys
_D = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else "/kaggle_simulations/agent"
sys.path.insert(0, _D)
from features import option_features
W = json.load(open(os.path.join(_D, 'policy.json')))['weights']
DECK = [int(x) for x in open(os.path.join(_D, 'deck.csv')).read().split() if x.strip()]
def agent(obs):
    if obs.get('select') is None:
        return list(DECK)
    sel = obs['select']
    opts = sel.get('option') or []
    n = len(opts)
    mn = max(0, min(sel.get('minCount', 1), n))
    mx = max(mn, min(sel.get('maxCount', 1), n))
    scores = []
    for i in range(n):
        try: scores.append(sum(W.get(f, 0.0) for f in option_features(obs, i)))
        except Exception: scores.append(-1e9)
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    if mn == 1 and mx == 1:
        return [order[0]]
    picked = order[:mn]
    for i in order[mn:mx]:
        if scores[i] > 0:
            picked.append(i)
    return picked if picked else list(range(mn))
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "baselines" / "twins")
    ap.add_argument("--min-rows", type=int, default=400)
    ap.add_argument("--max-twins", type=int, default=20)
    ap.add_argument("--decisions", type=Path, default=ROOT / "analysis" / "all_decisions.jsonl")
    args = ap.parse_args()

    lb = sorted(glob.glob(str(ROOT / "leaderboard" / "*publicleaderboard*.csv")))[-1]
    scores = {}
    for r in csv.DictReader(open(lb, encoding="utf-8-sig")):
        scores[r["TeamName"]] = float(r["Score"])

    counts = Counter()
    for line in open(args.decisions):
        row = json.loads(line)
        counts[(row["team"], row["deck_hash"])] += 1

    # best deck per team, then spread across rating range
    best = {}
    for (team, dh), n in counts.items():
        if n < args.min_rows or team not in scores or team == "GarlicToday":
            continue
        if team not in best or counts[(team, best[team])] < n:
            best[team] = dh
    cands = sorted(((scores[t], t, dh, counts[(t, dh)]) for t, dh in best.items()),
                   key=lambda x: x[0])
    # stratified pick: bucket by 50 rating points, take highest-row per bucket first
    buckets = defaultdict(list)
    for c in cands:
        buckets[int(c[0] // 50)].append(c)
    picked = []
    for b in sorted(buckets):
        buckets[b].sort(key=lambda x: -x[3])
        picked.extend(buckets[b][:2])
    picked = sorted(picked, key=lambda x: x[0])[:args.max_twins]

    args.out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for score, team, dh, nrows in picked:
        slug = "".join(ch if ch.isalnum() else "_" for ch in team)[:24]
        tdir = args.out / f"{int(score)}_{slug}"
        tdir.mkdir(exist_ok=True)
        # extract this team+deck's rows
        rows_path = tdir / "rows.jsonl"
        deck = None
        with rows_path.open("w") as out:
            for line in open(args.decisions):
                row = json.loads(line)
                if row["team"] == team and row["deck_hash"] == dh:
                    out.write(line)
                    if deck is None:
                        # recover deck list from obs? store from meta libs instead
                        pass
        # deck list from any meta library
        for lib in (ROOT / "baselines/agent_kanga/meta_decks.json",
                    ROOT / "agent/meta_decks.json",
                    ROOT / "analysis/midband_decks.json"):
            if lib.exists():
                d = json.load(open(lib))
                if dh in d:
                    deck = d[dh]
                    break
        if deck is None:
            print(f"SKIP {team}: deck {dh} not in libraries")
            continue
        (tdir / "deck.csv").write_text("\n".join(map(str, deck)))
        (tdir / "main.py").write_text(PILOT_MAIN)
        subprocess.run([sys.executable, str(ROOT / "tools/train_policy.py"),
                        str(rows_path), "--out", str(tdir / "policy.json"),
                        "--epochs", "10"], check=True, capture_output=True, text=True)
        for f in ("features.py",):
            (tdir / f).write_bytes((ROOT / "agent" / f).read_bytes())
        hold = json.load(open(tdir / "policy.json")).get("holdout", {})
        meta = {"team": team, "deck_hash": dh, "public_score": score,
                "rows": nrows, "bc_top1": hold.get("top1")}
        (tdir / "twin.json").write_text(json.dumps(meta, indent=1))
        rows_path.unlink()  # keep dirs lean
        manifest.append(meta)
        print(f"twin {tdir.name}: score={score} rows={nrows} bc_top1={hold.get('top1'):.3f}"
              if hold.get("top1") else f"twin {tdir.name}: score={score}")
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print(f"built {len(manifest)} twins -> {args.out}")


if __name__ == "__main__":
    sys.exit(main())
