#!/usr/bin/env python3
"""Scout top teams: download their recent public replays via kaggle CLI.

Usage:
  python3 tools/scout.py --team-limit 9 --episodes-per-submission 12 \
      --min-end-time 2026-07-01

Output: scouting/live_<stamp>/<rank>_<team>/submission_<id>/episode-<id>-replay.json
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

COMP = "pokemon-tcg-ai-battle"
ROOT = Path(__file__).resolve().parent.parent


def run_csv(args: list[str]) -> list[dict[str, str]]:
    result = subprocess.run(["kaggle"] + args, check=True, text=True, capture_output=True)
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    if not lines:
        return []
    return list(csv.DictReader(io.StringIO("\n".join(lines))))


def latest_leaderboard() -> Path:
    files = list((ROOT / "leaderboard").glob("*publicleaderboard*.csv"))
    if not files:
        raise FileNotFoundError("run: kaggle competitions leaderboard %s --download -p leaderboard/" % COMP)
    return max(files, key=lambda p: p.stat().st_mtime)


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "team"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--team-limit", type=int, default=9)
    ap.add_argument("--offset", type=int, default=0, help="skip top N teams")
    ap.add_argument("--submissions-per-team", type=int, default=2)
    ap.add_argument("--episodes-per-submission", type=int, default=12)
    ap.add_argument("--min-end-time", default="2026-07-01")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    lb = latest_leaderboard()
    rows = sorted(csv.DictReader(open(lb, encoding="utf-8-sig")), key=lambda r: float(r["Score"]), reverse=True)
    teams = rows[args.offset:args.offset + args.team_limit]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or ROOT / "scouting" / f"live_top_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    print(f"leaderboard={lb.name} out={out}")

    for rank, row in enumerate(teams, start=args.offset + 1):
        team_id, team_name, score = row["TeamId"], row["TeamName"], row["Score"]
        tdir = out / slug(f"{rank:02d}_{team_name}_{team_id}")
        tdir.mkdir(exist_ok=True)
        try:
            subs = run_csv(["competitions", "team-submissions", "-v", team_id])
        except subprocess.CalledProcessError as e:
            print(f"  {rank} {team_name}: team-submissions FAILED: {e.stderr[:200]}", file=sys.stderr)
            continue
        (tdir / "team_submissions.csv").write_text(
            "\n".join([",".join(subs[0].keys())] + [",".join(s.values()) for s in subs]) if subs else "")
        for sub in subs[:args.submissions_per_team]:
            sid = sub["id"]
            sdir = tdir / f"submission_{sid}"
            sdir.mkdir(exist_ok=True)
            try:
                eps = run_csv(["competitions", "episodes", "-v", sid])
            except subprocess.CalledProcessError as e:
                print(f"  sub {sid}: episodes FAILED: {e.stderr[:200]}", file=sys.stderr)
                continue
            done = [e for e in eps
                    if e.get("state") == "EpisodeState.COMPLETED"
                    and e.get("type") == "EpisodeType.EPISODE_TYPE_PUBLIC"
                    and e.get("endTime", "") >= args.min_end_time]
            done.sort(key=lambda e: e.get("endTime", ""), reverse=True)
            with (sdir / "episodes.csv").open("w", newline="") as fh:
                if eps:
                    w = csv.DictWriter(fh, fieldnames=list(eps[0].keys()))
                    w.writeheader()
                    w.writerows(eps)
            got = 0
            for ep in done[:args.episodes_per_submission]:
                eid = ep["id"]
                target = sdir / f"episode-{eid}-replay.json"
                if target.exists():
                    got += 1
                    continue
                try:
                    subprocess.run(["kaggle", "competitions", "replay", "-q", "-p", str(sdir), eid],
                                   check=True, capture_output=True, text=True)
                    got += 1
                except subprocess.CalledProcessError as e:
                    print(f"    replay {eid} FAILED: {e.stderr[:150]}", file=sys.stderr)
            print(f"{rank},{team_name},{score},sub={sid},episodes={got}/{len(done)}")
    print("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
