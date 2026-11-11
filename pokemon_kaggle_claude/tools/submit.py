#!/usr/bin/env python3
"""Submit a packaged agent and record it in the submission ledger.

Usage:
  python3 tools/submit.py submissions/name.tar.gz -m "message"
  python3 tools/submit.py --status          # show our recent submissions + scores
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

COMP = "pokemon-tcg-ai-battle"
ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "runs" / "submissions_ledger.jsonl"


def kaggle_submissions() -> list[dict]:
    res = subprocess.run(["kaggle", "competitions", "submissions", COMP, "-v"],
                         check=True, text=True, capture_output=True)
    return list(csv.DictReader(io.StringIO(res.stdout)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("archive", nargs="?", type=Path)
    ap.add_argument("-m", "--message", default="")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()

    if args.status or not args.archive:
        rows = kaggle_submissions()
        print(f"{'date':26s} {'status':10s} {'public':8s} description")
        for r in rows[:12]:
            print(f"{r.get('date',''):26s} {r.get('status','')[-9:]:10s} "
                  f"{r.get('publicScore','') or '-':8s} {r.get('description','')[:60]}")
        return 0

    msg = args.message or args.archive.stem
    res = subprocess.run(["kaggle", "competitions", "submit", COMP,
                          "-f", str(args.archive), "-m", msg],
                         text=True, capture_output=True)
    print(res.stdout, res.stderr)
    ok = res.returncode == 0
    LEDGER.parent.mkdir(exist_ok=True)
    with LEDGER.open("a") as fh:
        fh.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "archive": str(args.archive), "message": msg, "ok": ok,
        }) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
