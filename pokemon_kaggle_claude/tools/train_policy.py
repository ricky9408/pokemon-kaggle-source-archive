#!/usr/bin/env python3
"""Train a behavior-cloning action ranker (averaged perceptron) on decision rows.

Input rows: JSONL from tools/build_dataset.py (full obs preserved).
Uses agent/features.py so play-time parity is exact.

Usage:
  python3 tools/train_policy.py analysis/grimm_family.jsonl \
      --out agent/policy.json --epochs 8
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
import importlib.util as _ilu
import os as _os
_feat_path = _os.environ.get("FEATURES_PATH", str(ROOT / "agent" / "features.py"))
_spec = _ilu.spec_from_file_location("features_mod", _feat_path)
_fm = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_fm)
option_features = _fm.option_features


def ep_bucket(eid: str, mod: int = 6) -> int:
    return int(hashlib.sha1(str(eid).encode()).hexdigest()[:8], 16) % mod


def usable(row) -> bool:
    sel = (row.get("obs") or {}).get("select") or {}
    opts = sel.get("option") or []
    act = row.get("action") or []
    return (sel.get("minCount") == 1 and sel.get("maxCount") == 1
            and len(opts) > 1 and len(act) == 1 and 0 <= act[0] < len(opts))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("data", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--epochs", type=int, default=8)
    ap.add_argument("--lr", type=float, default=1.0)
    ap.add_argument("--holdout-bucket", type=int, default=0)
    ap.add_argument("--min-weight", type=float, default=0.01)
    ap.add_argument("--winners-only", action="store_true")
    args = ap.parse_args()

    train, hold = [], []
    for p in args.data:
        for line in p.open():
            row = json.loads(line)
            if not usable(row):
                continue
            if args.winners_only and not row.get("won"):
                continue
            feats = [option_features(row["obs"], i)
                     for i in range(len(row["obs"]["select"]["option"]))]
            item = (feats, row["action"][0], row["obs"]["select"].get("context"))
            if ep_bucket(row["episode_id"]) == args.holdout_bucket:
                hold.append(item)
            else:
                train.append(item)
    print(f"train={len(train)} holdout={len(hold)}")

    w: dict[str, float] = defaultdict(float)
    acc: dict[str, float] = defaultdict(float)  # for averaging
    t = 1
    rng = random.Random(13)
    for epoch in range(args.epochs):
        rng.shuffle(train)
        correct = 0
        for feats, label, _ctx in train:
            scores = [sum(w[f] for f in fs) for fs in feats]
            pred = max(range(len(scores)), key=lambda i: (scores[i], -i))
            if pred == label:
                correct += 1
            else:
                for f in feats[label]:
                    w[f] += args.lr
                    acc[f] += args.lr * t
                for f in feats[pred]:
                    w[f] -= args.lr
                    acc[f] -= args.lr * t
            t += 1
        print(f"epoch {epoch}: train_top1={correct/max(1,len(train)):.3f}")

    # averaged weights
    avg = {f: w[f] - acc[f] / t for f in w}
    avg = {f: round(v, 4) for f, v in avg.items() if abs(v - 0.0) >= args.min_weight}

    # holdout eval (overall + per-context)
    per_ctx = defaultdict(lambda: [0, 0, 0])  # top1, top3(hits), total
    for feats, label, ctx in hold:
        scores = [sum(avg.get(f, 0.0) for f in fs) for fs in feats]
        order = sorted(range(len(scores)), key=lambda i: (scores[i], -i), reverse=True)
        s = per_ctx[ctx]
        s[2] += 1
        if order[0] == label:
            s[0] += 1
        if label in order[:3]:
            s[1] += 1
    tot = sum(s[2] for s in per_ctx.values())
    top1 = sum(s[0] for s in per_ctx.values())
    top3 = sum(s[1] for s in per_ctx.values())
    print(f"HOLDOUT top1={top1/max(1,tot):.3f} top3={top3/max(1,tot):.3f} n={tot}")
    ctx_report = {}
    for ctx, (c1, c3, n) in sorted(per_ctx.items(), key=lambda kv: -kv[1][2]):
        ctx_report[str(ctx)] = {"top1": round(c1 / n, 3), "top3": round(c3 / n, 3), "n": n}
        if n >= 20:
            print(f"  ctx={ctx}: top1={c1/n:.3f} top3={c3/n:.3f} n={n}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"weights": avg, "ctx_report": ctx_report,
               "holdout": {"top1": top1 / max(1, tot), "top3": top3 / max(1, tot), "n": tot}},
              args.out.open("w"))
    print(f"saved {len(avg)} weights -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
