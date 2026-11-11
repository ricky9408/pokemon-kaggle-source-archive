#!/usr/bin/env python3
"""Panel rating: place a candidate on the PUBLIC rating scale before submitting.

Codex's criticism (2026-07-03): local ablations are small, the neural metric is
imitation accuracy not win value, and local-public correlation has been awful.
This tool attacks the correlation problem head-on with the one asset we own that
no scouted proxy has: OUR OWN SUBMITTED ARCHIVES, real runnable agents whose
converged public ratings are KNOWN (outcome ledger).

Method
------
Panel = archives with converged public labels (current environment). A candidate
plays seat-balanced games against every panel member. Bradley-Terry:

    P(candidate beats member_i) = 1 / (1 + exp(-(R_c - R_i) / s))

with member ratings R_i FIXED at their known public labels. The scale s is
fitted from panel-vs-panel games; the candidate's R_c is a 1-parameter MLE.
Output: predicted public rating + a likelihood-interval, i.e. a number directly
comparable to the leaderboard BEFORE spending a submission slot.

Self-validation (the honesty check)
-----------------------------------
--validate runs leave-one-out over the panel itself: each member is re-rated
from its games against the others and compared to its actual public label.
The resulting Spearman/MAE is the method's measured predictive accuracy — the
number the trust gate has been missing. If LOOCV can't predict the panel's own
labels, the method must not qualify candidates (and says so).

Games are APPENDED to a persistent CSV (outcomes/panel_games.csv), so evidence
accumulates across runs and re-fitting is free.

Run inside linux/amd64 Docker (old archives bundle x86 libcg):
  docker run -i --rm --platform linux/amd64 -v "$PWD":/work -w /work python:3.11-slim \
    python tools/panel_rating.py --play-panel --games-per-seat 3 --validate
  ... --candidate agents/v151_xxx --games-per-seat 4
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sqlite3
import sys
import tarfile
import tempfile
import time
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tools"))

from run_local_battle import load_agent, run_one  # noqa: E402

GAMES_CSV = REPO / "outcomes" / "panel_games.csv"
GAME_FIELDS = ["ts", "a", "b", "a_seat0", "result", "steps", "error"]


# --------------------------------------------------------------------------- #
# Panel definition: converged labels from the ledger, current environment.
# --------------------------------------------------------------------------- #
def load_panel(db: Path, since: str, max_members: int = 0) -> dict[str, float]:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT s.kaggle_filename fn, o.realized_public_median med, o.verdict,
                  MAX(s.submit_ts) ts
           FROM outcomes o JOIN submissions s ON o.ref = s.ref
           WHERE o.verdict = 'measured' AND s.submit_ts >= ?
           GROUP BY s.kaggle_filename""",
        (since,),
    ).fetchall()
    conn.close()
    # one label per archive: median of measured outcomes
    by_fn: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        by_fn[r["fn"]].append(float(r["med"]))
    panel = {}
    for fn, meds in by_fn.items():
        if (REPO / fn).exists():
            meds.sort()
            panel[fn] = meds[len(meds) // 2]
    items = sorted(panel.items(), key=lambda kv: -kv[1])
    if max_members:
        items = items[:max_members]
    return dict(items)


def extract_archive(archive: Path, dest: Path) -> Path:
    out = dest / archive.stem.replace(".tar", "")
    if not out.exists():
        out.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as tf:
            tf.extractall(out)
    return out


# --------------------------------------------------------------------------- #
# Game store
# --------------------------------------------------------------------------- #
def load_games() -> list[dict]:
    if not GAMES_CSV.exists():
        return []
    return list(csv.DictReader(GAMES_CSV.open(encoding="utf-8")))


def append_games(rows: list[dict]) -> None:
    GAMES_CSV.parent.mkdir(parents=True, exist_ok=True)
    new_file = not GAMES_CSV.exists()
    with GAMES_CSV.open("a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=GAME_FIELDS)
        if new_file:
            w.writeheader()
        w.writerows(rows)


def decisive_record(games: list[dict], a: str, b: str) -> tuple[int, int]:
    """(a_wins, b_wins) across stored games between a and b (errors excluded)."""
    aw = bw = 0
    for g in games:
        if g.get("error"):
            continue
        r = int(g["result"])
        if r not in (0, 1):
            continue
        if g["a"] == a and g["b"] == b:
            winner_is_a = (r == 0) == (g["a_seat0"] == "1")
        elif g["a"] == b and g["b"] == a:
            winner_is_a = (r == 0) != (g["a_seat0"] == "1")
        else:
            continue
        if winner_is_a:
            aw += 1
        else:
            bw += 1
    return aw, bw


def play_pair(agents: dict, a: str, b: str, games_per_seat: int, max_steps: int) -> list[dict]:
    out = []
    fa, da = agents[a]
    fb, db = agents[b]
    for seat in (0, 1):
        for _ in range(games_per_seat):
            if seat == 0:
                res = run_one(fa, da, fb, db, max_steps)
                a_seat0 = "1"
            else:
                res = run_one(fb, db, fa, da, max_steps)
                a_seat0 = "0"
            out.append({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "a": a, "b": b, "a_seat0": a_seat0,
                "result": res.get("result", -1),
                "steps": res.get("steps", -1),
                "error": (res.get("error") or "")[:80],
            })
    return out


# --------------------------------------------------------------------------- #
# Bradley-Terry with fixed opponent ratings
# --------------------------------------------------------------------------- #
def fit_scale(games: list[dict], labels: dict[str, float]) -> float:
    """MLE of the logistic scale s from panel-vs-panel games (labels fixed)."""
    pairs = []
    names = set(labels)
    for a in names:
        for b in names:
            if a >= b:
                continue
            aw, bw = decisive_record(games, a, b)
            if aw + bw:
                pairs.append((labels[a] - labels[b], aw, bw))
    if not pairs:
        return 120.0

    def nll(s):
        total = 0.0
        for d, aw, bw in pairs:
            p = 1.0 / (1.0 + math.exp(-d / s))
            p = min(max(p, 1e-6), 1 - 1e-6)
            total -= aw * math.log(p) + bw * math.log(1 - p)
        return total

    best_s, best_v = 120.0, float("inf")
    for s in [40, 60, 80, 100, 120, 150, 200, 260, 340, 450, 600]:
        v = nll(s)
        if v < best_v:
            best_s, best_v = s, v
    # local refine
    for step in (0.5, 0.25, 0.1):
        for s in (best_s * (1 - step), best_s * (1 + step)):
            v = nll(s)
            if v < best_v:
                best_s, best_v = s, v
    return best_s


def rate_candidate(games: list[dict], cand: str, labels: dict[str, float], s: float):
    """1-param MLE for R_cand given games vs labeled panel members."""
    records = []
    for opp, r_opp in labels.items():
        aw, bw = decisive_record(games, cand, opp)
        if aw + bw:
            records.append((r_opp, aw, bw))
    if not records:
        return None, None, 0

    def nll(rc):
        total = 0.0
        for r_opp, aw, bw in records:
            p = 1.0 / (1.0 + math.exp(-(rc - r_opp) / s))
            p = min(max(p, 1e-6), 1 - 1e-6)
            total -= aw * math.log(p) + bw * math.log(1 - p)
        return total

    lo, hi = 300.0, 1500.0
    for _ in range(60):  # golden-ish ternary search
        m1 = lo + (hi - lo) / 3
        m2 = hi - (hi - lo) / 3
        if nll(m1) < nll(m2):
            hi = m2
        else:
            lo = m1
    rc = (lo + hi) / 2
    # likelihood interval: +/- where nll rises by 1.92 (~95%)
    base = nll(rc)
    lo_ci = rc
    while lo_ci > 300 and nll(lo_ci) - base < 1.92:
        lo_ci -= 5
    hi_ci = rc
    while hi_ci < 1500 and nll(hi_ci) - base < 1.92:
        hi_ci += 5
    n = sum(aw + bw for _, aw, bw in records)
    return rc, (lo_ci, hi_ci), n


def spearman(xs: list[float], ys: list[float]) -> float:
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        rk = [0.0] * len(v)
        for pos, i in enumerate(order):
            rk[i] = pos
        return rk
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    if n < 3:
        return float("nan")
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else float("nan")


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Bradley-Terry panel rating vs known public labels")
    ap.add_argument("--ledger", type=Path, default=REPO / "outcomes" / "ledger.sqlite")
    ap.add_argument("--since", default="2026-06-28", help="panel label env cutoff")
    ap.add_argument("--max-members", type=int, default=0)
    ap.add_argument("--play-panel", action="store_true",
                    help="play missing panel-vs-panel games (evidence accumulates)")
    ap.add_argument("--candidate", action="append", type=Path, default=[],
                    help="agent dir to qualify (repeatable)")
    ap.add_argument("--games-per-seat", type=int, default=3)
    ap.add_argument("--min-pair-games", type=int, default=6,
                    help="target decisive games per pair before skipping")
    ap.add_argument("--max-steps", type=int, default=2000)
    ap.add_argument("--validate", action="store_true", help="LOOCV over the panel")
    ap.add_argument("--report", type=Path, default=None)
    args = ap.parse_args()

    labels = load_panel(args.ledger, args.since, args.max_members)
    print(f"panel: {len(labels)} archives with converged labels since {args.since}")
    for fn, r in sorted(labels.items(), key=lambda kv: -kv[1]):
        print(f"  {r:7.1f}  {fn}")
    if len(labels) < 4:
        print("panel too small (<4); accumulate more converged labels first")
        return 2

    games = load_games()
    lines = [f"# Panel Rating — {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}", ""]

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        agents: dict[str, tuple] = {}

        def ensure_agent(key: str, source: Path):
            if key not in agents:
                agents[key] = load_agent(source, f"p_{abs(hash(key)) % 99999}")

        # panel-vs-panel evidence
        if args.play_panel:
            for fn in labels:
                ensure_agent(fn, extract_archive(REPO / fn, tdp))
            names = list(labels)
            for i, a in enumerate(names):
                for b in names[i + 1:]:
                    aw, bw = decisive_record(games, a, b)
                    if aw + bw >= args.min_pair_games:
                        continue
                    new = play_pair(agents, a, b, args.games_per_seat, args.max_steps)
                    append_games(new)
                    games.extend(new)
                    naw, nbw = decisive_record(games, a, b)
                    print(f"  {a.split('-')[-1][:14]} vs {b.split('-')[-1][:14]}: {naw}-{nbw}", flush=True)

        s = fit_scale(games, labels)
        print(f"fitted logistic scale s = {s:.0f} rating pts")
        lines.append(f"- panel n={len(labels)}, fitted scale s={s:.0f}")

        # LOOCV self-validation
        if args.validate:
            preds, actual = [], []
            lines += ["", "## LOOCV self-validation", "",
                      "| archive | actual | predicted | CI | games |", "| --- | ---: | ---: | --- | ---: |"]
            for held in labels:
                rest = {k: v for k, v in labels.items() if k != held}
                s_l = fit_scale(games, rest)
                rc, ci, n = rate_candidate(games, held, rest, s_l)
                if rc is None:
                    continue
                preds.append(rc)
                actual.append(labels[held])
                lines.append(f"| {held.split('submission-')[-1][:36]} | {labels[held]:.0f} | "
                             f"{rc:.0f} | [{ci[0]:.0f},{ci[1]:.0f}] | {n} |")
            if len(preds) >= 3:
                mae = sum(abs(p - a) for p, a in zip(preds, actual)) / len(preds)
                rho = spearman(preds, actual)
                lines += ["", f"**LOOCV: Spearman {rho:.3f}, MAE {mae:.0f} pts (n={len(preds)})**"]
                print(f"LOOCV: Spearman {rho:.3f}  MAE {mae:.0f}  n={len(preds)}")

        # candidate qualification
        for cand_dir in args.candidate:
            key = f"CAND:{cand_dir.name}"
            ensure_agent(key, cand_dir)
            for fn in labels:
                ensure_agent(fn, extract_archive(REPO / fn, tdp))
                aw, bw = decisive_record(games, key, fn)
                if aw + bw >= args.min_pair_games:
                    continue
                new = play_pair(agents, key, fn, args.games_per_seat, args.max_steps)
                append_games(new)
                games.extend(new)
            rc, ci, n = rate_candidate(games, key, labels, s)
            verdict = ("QUALIFIES (predicted above best live anchor)"
                       if rc is not None and rc >= max(labels.values()) else "does not qualify")
            print(f"CANDIDATE {cand_dir.name}: predicted public rating {rc:.0f} "
                  f"CI [{ci[0]:.0f},{ci[1]:.0f}] over {n} games -> {verdict}")
            lines += ["", f"## Candidate {cand_dir.name}",
                      f"- predicted public rating **{rc:.0f}** CI [{ci[0]:.0f},{ci[1]:.0f}] "
                      f"({n} decisive games) — {verdict}"]

    if args.report:
        args.report.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
