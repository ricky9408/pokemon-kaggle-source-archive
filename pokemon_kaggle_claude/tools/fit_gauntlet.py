#!/usr/bin/env python3
"""Fit the twin-gauntlet rating model and validate against known anchor scores.

Model: P(candidate beats twin) = sigmoid(a + b*R_cand_public? ) — we do NOT
know R for new candidates, so the usable direction is the reverse: predict
public score from the winrate profile. Approach: leave-one-out ridge
regression from per-twin winrates (features) to public score, plus a simple
1-D approach (logistic strength fit). Reports LOO predictions and Spearman.

Usage: python3 tools/fit_gauntlet.py
"""
from __future__ import annotations

import glob
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def spearman(xs, ys):
    def rank(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        for pos, i in enumerate(order):
            r[i] = pos
        return r
    rx, ry = rank(xs), rank(ys)
    n = len(xs)
    mx = sum(rx) / n
    my = sum(ry) / n
    num = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    den = math.sqrt(sum((rx[i] - mx) ** 2 for i in range(n))
                    * sum((ry[i] - my) ** 2 for i in range(n)))
    return num / den if den else 0.0


def mle_strength(results, twin_scale=1.0, s=120.0):
    """1-D logistic MLE: find R s.t. sum residuals of wins vs sigmoid((R-r)/s)."""
    lo, hi = 300.0, 1800.0
    for _ in range(60):
        mid = (lo + hi) / 2
        grad = 0.0
        for r in results:
            p = 1.0 / (1.0 + math.exp(-(mid - r["rating"] * twin_scale) / s))
            grad += r["wins"] - r["games"] * p
        if grad > 0:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def main():
    scores = json.load(open(ROOT / "runs/anchor_scores.json"))
    anchors = []
    for f in sorted(glob.glob(str(ROOT / "runs/tg_*.json"))):
        d = json.loads(Path(f).read_text())
        name = Path(d["candidate"]).name
        if name not in scores:
            continue
        anchors.append((name, scores[name], d["results"]))
    if len(anchors) < 4:
        print(f"only {len(anchors)} anchors ready; need more")
        return 1

    # approach 1: raw MLE strength (uncalibrated scale)
    print("anchor                        public  meanWR  mle_R")
    feats = []
    for name, sc, results in anchors:
        wr = sum(r["wins"] for r in results) / max(1, sum(r["games"] for r in results))
        R = mle_strength(results)
        feats.append((name, sc, wr, R, results))
        print(f"{name:28s} {sc:6.0f}  {wr:.3f}  {R:6.0f}")

    pub = [f[1] for f in feats]
    print(f"\nSpearman(meanWR, public) = {spearman([f[2] for f in feats], pub):.3f}")
    print(f"Spearman(mle_R,  public) = {spearman([f[3] for f in feats], pub):.3f}")

    # approach 2: per-twin-band winrates as features, LOO linear fit
    # bands: twins <950, 950-1100, >1100
    def band_profile(results):
        bands = {"lo": [0, 0], "mid": [0, 0], "hi": [0, 0]}
        for r in results:
            k = "lo" if r["rating"] < 950 else ("mid" if r["rating"] <= 1100 else "hi")
            bands[k][0] += r["wins"]
            bands[k][1] += r["games"]
        return [bands[k][0] / max(1, bands[k][1]) for k in ("lo", "mid", "hi")]

    X = [band_profile(f[4]) for f in feats]
    preds = []
    for i in range(len(feats)):
        # LOO ordinary least squares on 3 features + intercept (tiny n -> ridge)
        train = [(X[j], pub[j]) for j in range(len(feats)) if j != i]
        lam = 1e-3
        import itertools
        # normal equations 4x4
        def phi(x):
            return [1.0] + x
        A = [[lam * (1 if a == b else 0) for b in range(4)] for a in range(4)]
        bvec = [0.0] * 4
        for x, y in train:
            p = phi(x)
            for a in range(4):
                bvec[a] += p[a] * y
                for b in range(4):
                    A[a][b] += p[a] * p[b]
        # gaussian elim
        M = [row[:] + [bvec[r]] for r, row in enumerate(A)]
        for c in range(4):
            piv = max(range(c, 4), key=lambda r: abs(M[r][c]))
            M[c], M[piv] = M[piv], M[c]
            for r in range(4):
                if r != c and abs(M[c][c]) > 1e-12:
                    f2 = M[r][c] / M[c][c]
                    for k in range(5):
                        M[r][k] -= f2 * M[c][k]
        w = [M[r][4] / M[r][r] if abs(M[r][r]) > 1e-12 else 0.0 for r in range(4)]
        pred = w[0] + sum(w[k + 1] * X[i][k] for k in range(3))
        preds.append(pred)
    print("\nLOO band-profile predictions:")
    for (name, sc, _, _, _), p in zip(feats, preds):
        print(f"  {name:28s} public={sc:6.0f} predicted={p:6.0f} err={p - sc:+6.0f}")
    print(f"Spearman(LOO pred, public) = {spearman(preds, pub):.3f}")
    mae = sum(abs(p - s) for p, s in zip(preds, pub)) / len(pub)
    print(f"LOO MAE = {mae:.0f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
