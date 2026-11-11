#!/usr/bin/env python3
"""Train a logistic value model P(win | board state) from decision rows.

Usage: python3 tools/train_value.py analysis/all_decisions.jsonl --out staging/value.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))
from values import value_features  # noqa: E402


def ep_bucket(eid, mod=6):
    return int(hashlib.sha1(str(eid).encode()).hexdigest()[:8], 16) % mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--lr", type=float, default=0.08)
    ap.add_argument("--l2", type=float, default=1e-6)
    args = ap.parse_args()

    train, hold = [], []
    seen = set()
    for p in args.data:
        for line in p.open():
            row = json.loads(line)
            obs = row.get("obs") or {}
            cur = obs.get("current") or {}
            if cur.get("turn") is None:
                continue
            # dedupe near-identical successive states within an episode+turn
            key = (row["episode_id"], row["player_index"], cur.get("turn"),
                   cur.get("turnActionCount"))
            if key in seen:
                continue
            seen.add(key)
            item = (value_features(obs), 1 if row.get("won") else 0)
            (hold if ep_bucket(row["episode_id"]) == 0 else train).append(item)
    print(f"train={len(train)} hold={len(hold)}")

    w = defaultdict(float)
    rng = random.Random(7)
    for ep in range(args.epochs):
        rng.shuffle(train)
        loss = 0.0
        for feats, y in train:
            z = sum(w[f] for f in feats)
            pz = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
            g = pz - y
            loss += -(y * math.log(max(pz, 1e-9)) + (1 - y) * math.log(max(1 - pz, 1e-9)))
            for f in feats:
                w[f] -= args.lr * (g + args.l2 * w[f])
        print(f"epoch {ep}: logloss={loss/len(train):.4f}")

    # holdout AUC-ish: accuracy + calibration
    correct = 0
    for feats, y in hold:
        z = sum(w.get(f, 0.0) for f in feats)
        correct += 1 if (z > 0) == (y == 1) else 0
    print(f"HOLDOUT acc={correct/max(1,len(hold)):.3f} n={len(hold)}")
    out = {f: round(v, 4) for f, v in w.items() if abs(v) >= 0.005}
    json.dump({"weights": out}, args.out.open("w"))
    print(f"saved {len(out)} weights -> {args.out}")


if __name__ == "__main__":
    sys.exit(main())
