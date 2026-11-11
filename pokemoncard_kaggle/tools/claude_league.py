#!/usr/bin/env python3
"""Round-robin local league over a set of agent directories.

Runs every unordered pair with seat balancing (G games with A as player 0, then G
games with A as player 1), so first-player advantage cannot bias the table. Uses
the real `cg` simulator via `run_local_battle.run_one`, so it MUST run where
`libcg.so` loads (linux/amd64 — i.e. inside the project Docker image on a Mac).

Outputs a standings table (win rate, W-L-D), a head-to-head win matrix, a CSV, and
a markdown report.

Example (from repo root, on an arm64 Mac):
  docker run -i --rm --platform linux/amd64 -v "$PWD":/work -w /work python:3.11-slim \
    python tools/claude_league.py \
      --agent agents/v101_claude_alakazam_control_v1 \
      --agent agents/v75_hiroingk_hammer_v57policy \
      --agent agents/v39_alakazam_denpa \
      --games-per-seat 6 --output strategy/claude_league
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local_battle import load_agent, run_one  # noqa: E402


def label_for(path: Path) -> str:
    return path.name


def main() -> int:
    parser = argparse.ArgumentParser(description="Round-robin local league")
    parser.add_argument("--agent", action="append", required=True, type=Path,
                        help="agent directory (repeatable)")
    parser.add_argument("--games-per-seat", type=int, default=6,
                        help="games per seat per pair (total per pair = 2x this)")
    parser.add_argument("--max-steps", type=int, default=2000)
    parser.add_argument("--output", type=Path, default=Path("strategy/claude_league"),
                        help="output prefix (writes .md and .csv)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    # load each agent once
    agents = {}
    for d in args.agent:
        label = label_for(d)
        fn, deck = load_agent(d, label)
        agents[label] = {"fn": fn, "deck": deck, "dir": str(d)}
    labels = list(agents)
    if len(labels) < 2:
        sys.stderr.write("Need >= 2 agents.\n")
        return 2

    # tallies
    wins = defaultdict(int)
    losses = defaultdict(int)
    draws = defaultdict(int)
    unfinished = defaultdict(int)
    errors = defaultdict(int)
    h2h_win = defaultdict(lambda: defaultdict(int))   # h2h_win[a][b] = games a beat b
    h2h_games = defaultdict(lambda: defaultdict(int))

    def play(a: str, b: str, a_seat: int) -> None:
        """Run one game; a_seat is which player slot agent a occupies (0 or 1)."""
        if a_seat == 0:
            res = run_one(agents[a]["fn"], agents[a]["deck"],
                          agents[b]["fn"], agents[b]["deck"], args.max_steps)
            a_result_code = 0
        else:
            res = run_one(agents[b]["fn"], agents[b]["deck"],
                          agents[a]["fn"], agents[a]["deck"], args.max_steps)
            a_result_code = 1
        if res.get("error"):
            errors[a] += 0  # errors are recorded as the game outcome below
        r = res["result"]
        h2h_games[a][b] += 1
        h2h_games[b][a] += 1
        if r == 2:
            draws[a] += 1; draws[b] += 1
        elif r == -1:
            unfinished[a] += 1; unfinished[b] += 1
        elif r == a_result_code:
            wins[a] += 1; losses[b] += 1; h2h_win[a][b] += 1
        elif r in (0, 1):
            wins[b] += 1; losses[a] += 1; h2h_win[b][a] += 1

    total_pairs = len(list(itertools.combinations(labels, 2)))
    for i, (a, b) in enumerate(itertools.combinations(labels, 2), 1):
        if not args.quiet:
            print(f"[pair {i}/{total_pairs}] {a} vs {b}", flush=True)
        for _ in range(args.games_per_seat):
            play(a, b, a_seat=0)
        for _ in range(args.games_per_seat):
            play(a, b, a_seat=1)
        if not args.quiet:
            print(f"    {a} {h2h_win[a][b]}-{h2h_win[b][a]} {b} "
                  f"(draw/unf excluded)", flush=True)

    # standings
    def winrate(lbl: str) -> float:
        w, l = wins[lbl], losses[lbl]
        return w / (w + l) if (w + l) else 0.0

    standings = sorted(labels, key=lambda l: (winrate(l), wins[l]), reverse=True)

    # ----- report -----
    lines = ["# Claude Local League", "",
             f"- Agents: {len(labels)} | games/seat: {args.games_per_seat} "
             f"(={2*args.games_per_seat}/pair) | max_steps: {args.max_steps}", "",
             "## Trust Status", "",
             "**Diagnostic only. Do not use this league by itself as a submit signal.**", "",
             "This league uses the local simulator and the listed local agents only. "
             "A local winner is submit-eligible only after mature public anchors, "
             "predictive-validity backtests, and the pre-submit gate agree.", "",
             "Before promoting a local winner, run `tools/audit_local_league_public_gap.py` "
             "against mature public submissions and check that public anchors do not contradict the league.", "",
             "## Standings (by decisive win rate)", "",
             "| # | Agent | Win% | W | L | Draw | Unfin |",
             "| ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
    for rank, lbl in enumerate(standings, 1):
        lines.append(f"| {rank} | {lbl} | {winrate(lbl)*100:.1f} | "
                     f"{wins[lbl]} | {losses[lbl]} | {draws[lbl]} | {unfinished[lbl]} |")

    lines += ["", "## Head-to-head win matrix (row beat column, decisive games)", "",
              "| vs | " + " | ".join(f"{l[:14]}" for l in standings) + " |",
              "| --- |" + " --- |" * len(standings)]
    for a in standings:
        row = [f"**{a[:18]}**"]
        for b in standings:
            if a == b:
                row.append("—")
            else:
                row.append(f"{h2h_win[a][b]}-{h2h_win[b][a]}")
        lines.append("| " + " | ".join(row) + " |")

    report = "\n".join(lines) + "\n"
    print("\n" + report)

    out_md = args.output.with_suffix(".md")
    out_csv = args.output.with_suffix(".csv")
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(report, encoding="utf-8")
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["rank", "agent", "win_pct", "wins", "losses", "draws", "unfinished"])
        for rank, lbl in enumerate(standings, 1):
            w.writerow([rank, lbl, f"{winrate(lbl)*100:.2f}", wins[lbl], losses[lbl],
                        draws[lbl], unfinished[lbl]])
    print(f"Wrote {out_md} and {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
