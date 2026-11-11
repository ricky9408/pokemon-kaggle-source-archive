#!/usr/bin/env python3
"""Run a candidate agent through the twin gauntlet (Issue #1).

Plays n games vs every twin in baselines/twins/, records winrates keyed by the
twin's public rating. Output JSON: {candidate, results: [{twin, rating, wins,
games}], mean_wr}.

Usage:
  python3 tools/twin_gauntlet.py CANDIDATE_DIR --games 8 --procs 8 --out runs/tg_x.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate")
    ap.add_argument("--games", type=int, default=8)
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--twins", type=Path, default=ROOT / "baselines" / "twins")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    manifest = json.load(open(args.twins / "manifest.json"))
    results = []
    for meta in manifest:
        slug = "".join(ch if ch.isalnum() else "_" for ch in meta["team"])[:24]
        tdir = args.twins / f"{int(meta['public_score'])}_{slug}"
        if not tdir.exists():
            continue
        tmp_json = ROOT / "runs" / f"tg_tmp_{slug}.json"
        res = subprocess.run(
            [sys.executable, str(ROOT / "tools/league.py"), str(args.candidate),
             str(tdir), "--games", str(args.games), "--procs", str(args.procs),
             "--quiet", "--json", str(tmp_json)],
            capture_output=True, text=True, cwd=str(ROOT))
        if not tmp_json.exists():
            print(f"twin {tdir.name}: league failed: {res.stderr[-200:]}", file=sys.stderr)
            continue
        data = json.loads(tmp_json.read_text())
        s = data["summary"]
        wins, losses = s["A"], s["B"]
        results.append({"twin": tdir.name, "rating": meta["public_score"],
                        "wins": wins, "games": wins + losses})
        print(f"{tdir.name}: {wins}-{losses}", flush=True)
        tmp_json.unlink()
    tot_w = sum(r["wins"] for r in results)
    tot_g = sum(r["games"] for r in results)
    out = {"candidate": str(args.candidate), "results": results,
           "mean_wr": tot_w / max(1, tot_g)}
    args.out.parent.mkdir(exist_ok=True)
    args.out.write_text(json.dumps(out, indent=1))
    print(f"GAUNTLET {args.candidate}: overall {tot_w}/{tot_g} = {tot_w/max(1,tot_g):.3f}")


if __name__ == "__main__":
    sys.exit(main())
