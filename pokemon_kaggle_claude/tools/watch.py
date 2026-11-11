#!/usr/bin/env python3
"""Poll our submission scores + leaderboard position; append to runs/score_ticks.csv.

Usage: python3 tools/watch.py [--once]
"""
from __future__ import annotations

import argparse
import csv
import io
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

COMP = "pokemon-tcg-ai-battle"
ROOT = Path(__file__).resolve().parent.parent
TICKS = ROOT / "runs" / "score_ticks.csv"


def poll() -> list[str]:
    res = subprocess.run(["kaggle", "competitions", "submissions", COMP, "-v"],
                         check=True, text=True, capture_output=True)
    rows = list(csv.DictReader(io.StringIO(res.stdout)))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = []
    TICKS.parent.mkdir(exist_ok=True)
    new_file = not TICKS.exists()
    with TICKS.open("a", newline="") as fh:
        w = csv.writer(fh)
        if new_file:
            w.writerow(["ts", "date", "description", "status", "publicScore"])
        for r in rows[:6]:
            w.writerow([now, r.get("date"), r.get("description"),
                        r.get("status"), r.get("publicScore")])
            out.append(f"{r.get('description','')[:44]:44s} {r.get('status','')[-9:]:9s} {r.get('publicScore') or '-'}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=int, default=900)
    args = ap.parse_args()
    while True:
        try:
            for line in poll():
                print(f"[{datetime.now(timezone.utc).strftime('%H:%M')}] {line}", flush=True)
        except Exception as e:
            print(f"poll error: {e}", file=sys.stderr, flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
