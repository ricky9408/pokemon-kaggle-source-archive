#!/usr/bin/env python3
"""Feed the predictive-validity gate a REAL local metric.

CRITICISM.md #3: the LOOCV gate has validated an EMPTY metrics file since
inception — no workflow ever produced a non-leaky local metric for the archives
that have public scores. This tool closes that hole:

  For every historical archive with a mature public score (from the outcome
  ledger / submissions CSV), play G seat-balanced games against a FIXED anchor
  pack of scouted meta decks piloted by a fixed reference policy. The resulting
  `anchor_winrate` column is a non-leaky, reproducible local metric keyed by
  archive — exactly what `tools/backtest_loocv.py --metrics-csv` needs to
  compute an honest local-vs-public correlation, which is what
  `pre_submit_gate.py` has been waiting for since June 22.

The anchor pack is FROZEN by listing exact (deck_hash, replay, slot) tuples in
this file. Do not casually change it: correlations are only comparable across
runs with the same pack.

Run where libcg loads (native arm64 works with the 20260701 engine; else Docker
linux/amd64).

Example:
  uv run python tools/anchor_gauntlet_metric.py \
      --submissions outcomes/our_submissions.csv \
      --games-per-seat 4 \
      --output outcomes/anchor_gauntlet_metrics.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tarfile
import tempfile
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from run_local_battle import load_agent, run_one  # noqa: E402

# ---------------------------------------------------------------------------
# FROZEN anchor pack: current-meta decks piloted by the generic replay policy.
# (team, replay path glob under the scout dir, pilot agent dir)
# ---------------------------------------------------------------------------
DEFAULT_SCOUT = "scouting/live_top_20260702T1335_top30_e4"
PILOT = "agents/v50_replay_meta_policy"
ANCHORS = [
    ("grimmsnarl_rank2", "02_tonakaiiii_16420537", "tonakaiiii"),
    ("alakazam_rank10", "10_aidy_16379469", "aidy"),
    ("archaludon_rank5", "05_ShumpeiNomura_16393745", "ShumpeiNomura"),
]


def load_anchor_deck(scout: Path, teamdir: str, team: str) -> list[int]:
    tdir = scout / teamdir
    for rp in sorted(tdir.glob("**/*replay.json")):
        data = json.loads(rp.read_text())
        teams = data.get("info", {}).get("TeamNames", [])
        if team in teams:
            return list(data["steps"][0][0]["visualize"][0]["action"][teams.index(team)])
    raise FileNotFoundError(f"no replay for {team} under {tdir}")


def extract_archive(archive: Path, dest: Path) -> Path:
    out = dest / archive.stem.replace(".tar", "")
    out.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as tf:
        tf.extractall(out)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Anchor-gauntlet local metric for scored archives")
    ap.add_argument("--submissions", type=Path, default=Path("outcomes/our_submissions.csv"))
    ap.add_argument("--scout-dir", type=Path, default=Path(DEFAULT_SCOUT))
    ap.add_argument("--pilot", type=Path, default=Path(PILOT))
    ap.add_argument("--games-per-seat", type=int, default=4)
    ap.add_argument("--max-steps", type=int, default=2000)
    ap.add_argument("--max-archives", type=int, default=0, help="0 = all scored archives")
    ap.add_argument("--only-archive", action="append", default=[],
                    help="restrict to these archive filenames (repeatable)")
    ap.add_argument("--output", type=Path, default=Path("outcomes/anchor_gauntlet_metrics.csv"))
    args = ap.parse_args()

    # scored archives (median public per archive for reference only — NOT a metric col)
    by_archive: dict[str, list[float]] = {}
    for row in csv.DictReader(args.submissions.open(encoding="utf-8-sig")):
        fn = (row.get("fileName") or "").strip()
        raw = (row.get("publicScore") or "").strip()
        if not fn or "COMPLETE" not in (row.get("status") or "").upper() or not raw:
            continue
        by_archive.setdefault(fn, []).append(float(raw))
    archives = sorted(by_archive)
    if args.only_archive:
        archives = [a for a in archives if a in set(args.only_archive)]
    if args.max_archives:
        archives = archives[: args.max_archives]

    pilot_fn, _ = load_agent(args.pilot, "pilot")
    anchor_decks = {}
    for label, teamdir, team in ANCHORS:
        anchor_decks[label] = load_anchor_deck(args.scout_dir, teamdir, team)
        print(f"anchor {label}: deck loaded ({team})")

    rows_out = []
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        for fn in archives:
            arch = REPO / fn
            if not arch.exists():
                print(f"skip {fn}: archive missing")
                continue
            try:
                adir = extract_archive(arch, tdp)
                agent_fn, agent_deck = load_agent(adir, f"cand_{arch.stem[:24]}")
            except Exception as exc:
                print(f"skip {fn}: load failed {type(exc).__name__}: {exc}")
                continue
            wins = games = errs = 0
            for label, deck in anchor_decks.items():
                for seat in (0, 1):
                    for _ in range(args.games_per_seat):
                        if seat == 0:
                            res = run_one(agent_fn, agent_deck, pilot_fn, deck, args.max_steps)
                            win_code = 0
                        else:
                            res = run_one(pilot_fn, deck, agent_fn, agent_deck, args.max_steps)
                            win_code = 1
                        # [fix 7] an errored game is a harness artifact, not
                        # a game result — exclude it from the winrate sample.
                        if res.get("error"):
                            errs += 1
                            continue
                        games += 1
                        if res.get("result") == win_code:
                            wins += 1
            wr = wins / games if games else 0.0
            rows_out.append({
                "fileName": fn,
                "anchor_winrate": f"{wr:.4f}",
                "anchor_games": games,
                "anchor_errors": errs,
            })
            print(f"{fn}: anchor_winrate={wr:.3f} ({wins}/{games}, err {errs}) "
                  f"[public median {sorted(by_archive[fn])[len(by_archive[fn])//2]:.1f}]")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["fileName", "anchor_winrate", "anchor_games", "anchor_errors"])
        w.writeheader()
        w.writerows(rows_out)
    print(f"wrote {args.output} ({len(rows_out)} archives)")
    print("next: uv run python tools/backtest_loocv.py --metrics-csv", args.output,
          "--submissions", args.submissions, "--summary-csv outcomes/loocv_summary.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
