#!/usr/bin/env python3
"""Neural policy network for the agents — outcome-weighted behavior cloning.

Upgrades the 531-weight perceptron (holdout top-1 0.34) to a real network:

  feature strings (parity featurizer from train_ml_policy.option_features_v2)
    -> stable sha1 hash buckets (default 32768)
    -> EmbeddingBag(sum) -> ReLU MLP -> scalar score per legal option
    -> listwise softmax over the decision's options, cross-entropy on the
       option the (winning) public pilot chose.

Key choices:
  * OUTCOME WEIGHTING: decisions from game winners weigh 1.0, losers 0.35 —
    imitation without outcome weighting can't exceed its teachers (repo lesson).
  * PARITY: the featurizer is imported from train_ml_policy (byte-identical to
    the agents' play-time copy, 0/655 mismatch verified in June).
  * EXPORT: weights land in a single .npz (embedding + 2-layer MLP) that a
    dependency-light agent evaluates with numpy (or pure python fallback):
        score(option) = W2 @ relu(W1 @ (sum of emb[bucket(f)] for f) + b1) + b2
  * Stable episode holdout (sha1(episode_id) % 5 == 0), per-context metrics.

Train (Apple MPS):
  uv run python tools/train_policy_net.py strategy/ml_decisions_top30_20260702.jsonl \
      --epochs 6 --model-out strategy/policy_net_top30.npz
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from train_ml_policy import option_features_v2, valid_label  # noqa: E402  (parity!)


def stable_bucket(value: str, modulo: int) -> int:
    return int(hashlib.sha1(value.encode()).hexdigest()[:10], 16) % modulo


def load_rows(paths: list[Path], max_options: int) -> list[dict]:
    rows = []
    seen = set()
    for p in paths:
        for line in p.open(encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            label = valid_label(r)
            if label is None or label >= max_options:
                continue
            key = (r.get("episode_id"), r.get("context"), r.get("option_count"),
                   tuple(r.get("action") or []), str(r.get("options"))[:120])
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
    return rows


def featurize_rows(rows: list[dict], buckets: int, max_options: int):
    """Precompute hashed feature indices for every (decision, option)."""
    feats = []       # list per row: list per option: np.array of bucket idxs
    labels = []
    weights = []
    hold = []
    outcomes = []    # 1.0 if this side won the game, else 0.0 (value head target)
    for r in rows:
        n = min(int(r.get("option_count") or 0), max_options)
        per_opt = []
        for i in range(n):
            idxs = np.array(
                [stable_bucket(f, buckets) for f in option_features_v2(r, i)],
                dtype=np.int64,
            )
            per_opt.append(idxs)
        feats.append(per_opt)
        labels.append(int(r["action"][0]))
        is_winner = bool(r.get("is_winner_player"))
        weights.append(1.0 if is_winner else 0.35)
        outcomes.append(1.0 if is_winner else 0.0)
        hold.append(stable_bucket(str(r.get("episode_id")), 5) == 0)
    return (feats, np.array(labels), np.array(weights, dtype=np.float32),
            np.array(hold), np.array(outcomes, dtype=np.float32))


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the neural policy net")
    ap.add_argument("decisions", nargs="+", type=Path)
    ap.add_argument("--buckets", type=int, default=32768)
    ap.add_argument("--dim", type=int, default=48)
    ap.add_argument("--hidden", type=int, default=48)
    ap.add_argument("--max-options", type=int, default=24)
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--loser-weight", type=float, default=0.35)
    ap.add_argument("--model-out", type=Path, required=True)
    ap.add_argument("--report-out", type=Path, default=None)
    args = ap.parse_args()

    import torch
    import torch.nn as nn

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    rows = load_rows(args.decisions, args.max_options)
    print(f"rows={len(rows)} (device={device})")
    feats, labels, weights, hold, outcomes = featurize_rows(rows, args.buckets, args.max_options)
    weights = np.where(weights >= 1.0, 1.0, args.loser_weight).astype(np.float32)
    train_idx = np.where(~hold)[0]
    hold_idx = np.where(hold)[0]
    print(f"train={len(train_idx)} holdout={len(hold_idx)}")

    emb = nn.EmbeddingBag(args.buckets, args.dim, mode="sum").to(device)
    mlp = nn.Sequential(
        nn.ReLU(), nn.Linear(args.dim, args.hidden), nn.ReLU(), nn.Linear(args.hidden, 1),
    ).to(device)
    # VALUE HEAD (Codex criticism: imitation accuracy is not win value): from the
    # mean option-embedding of a decision, predict whether this side WON the game.
    value_head = nn.Sequential(
        nn.ReLU(), nn.Linear(args.dim, args.hidden), nn.ReLU(), nn.Linear(args.hidden, 1),
    ).to(device)
    params = list(emb.parameters()) + list(mlp.parameters()) + list(value_head.parameters())
    opt = torch.optim.Adam(params, lr=args.lr)

    def batch_logits(idx_batch):
        """Compute per-decision option logits (padded)."""
        flat, offsets, meta = [], [], []
        for ridx in idx_batch:
            for opt_feats in feats[ridx]:
                offsets.append(len(flat))
                flat.extend(opt_feats.tolist())
            meta.append(len(feats[ridx]))
        flat_t = torch.tensor(flat, dtype=torch.long, device=device)
        off_t = torch.tensor(offsets, dtype=torch.long, device=device)
        vecs = emb(flat_t, off_t)                 # (total_options, dim)
        scores = mlp(vecs).squeeze(-1)            # (total_options,)
        return scores, meta

    def batch_vecs(idx_batch):
        flat, offsets, meta = [], [], []
        for ridx in idx_batch:
            for opt_feats in feats[ridx]:
                offsets.append(len(flat))
                flat.extend(opt_feats.tolist())
            meta.append(len(feats[ridx]))
        flat_t = torch.tensor(flat, dtype=torch.long, device=device)
        off_t = torch.tensor(offsets, dtype=torch.long, device=device)
        return emb(flat_t, off_t), meta

    def batch_loss(idx_batch):
        vecs, meta = batch_vecs(idx_batch)
        scores = mlp(vecs).squeeze(-1)
        loss = torch.zeros((), device=device)
        pos = 0
        total_w = 0.0
        dec_vecs = []
        outc = []
        for k, ridx in enumerate(idx_batch):
            n = meta[k]
            logits = scores[pos:pos + n]
            dec_vecs.append(vecs[pos:pos + n].mean(dim=0))
            outc.append(outcomes[ridx])
            pos += n
            target = torch.tensor(labels[ridx], device=device)
            w = float(weights[ridx])
            loss = loss + w * torch.nn.functional.cross_entropy(
                logits.unsqueeze(0), target.unsqueeze(0))
            total_w += w
        policy_loss = loss / max(total_w, 1e-6)
        v_logit = value_head(torch.stack(dec_vecs)).squeeze(-1)
        v_tgt = torch.tensor(outc, dtype=torch.float32, device=device)
        value_loss = torch.nn.functional.binary_cross_entropy_with_logits(v_logit, v_tgt)
        return policy_loss + 0.5 * value_loss

    rng = np.random.default_rng(20260703)
    for epoch in range(args.epochs):
        order = rng.permutation(train_idx)
        total = 0.0
        nb = 0
        for s in range(0, len(order), args.batch):
            batch = order[s:s + args.batch]
            opt.zero_grad()
            loss = batch_loss(batch)
            loss.backward()
            opt.step()
            total += float(loss)
            nb += 1
        print(f"epoch {epoch + 1}/{args.epochs} loss={total / max(nb, 1):.4f}")

    # ---- holdout metrics (numpy inference == exported path) --------------- #
    W_emb = emb.weight.detach().cpu().numpy().astype(np.float32)
    v1 = value_head[1]
    v2 = value_head[3]
    V1 = v1.weight.detach().cpu().numpy().astype(np.float32)
    vb1 = v1.bias.detach().cpu().numpy().astype(np.float32)
    V2 = v2.weight.detach().cpu().numpy().astype(np.float32).reshape(-1)
    vb2 = float(v2.bias.detach().cpu().numpy()[0])
    lin1 = mlp[1]
    lin2 = mlp[3]
    W1 = lin1.weight.detach().cpu().numpy().astype(np.float32)
    b1 = lin1.bias.detach().cpu().numpy().astype(np.float32)
    W2 = lin2.weight.detach().cpu().numpy().astype(np.float32).reshape(-1)
    b2 = float(lin2.bias.detach().cpu().numpy()[0])

    def np_score(opt_feats: np.ndarray) -> float:
        v = W_emb[opt_feats].sum(axis=0)
        h = np.maximum(v, 0.0)
        h = np.maximum(W1 @ h + b1, 0.0)
        return float(W2 @ h + b2)

    by_ctx = defaultdict(lambda: [0, 0, 0])
    top1 = top3 = total_n = 0
    for ridx in hold_idx:
        scores = [np_score(f) for f in feats[ridx]]
        order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        lab = labels[ridx]
        ctx = str(rows[ridx].get("context"))
        total_n += 1
        by_ctx[ctx][2] += 1
        if order and order[0] == lab:
            top1 += 1
            by_ctx[ctx][0] += 1
        if lab in order[:3]:
            top3 += 1
            by_ctx[ctx][1] += 1

    def pct(a, b):
        return f"{a / b:.3f}" if b else "0.000"

    lines = ["# Neural Policy Net (outcome-weighted BC)", "",
             f"- rows={len(rows)} train={len(train_idx)} holdout={len(hold_idx)}",
             f"- buckets={args.buckets} dim={args.dim} hidden={args.hidden} "
             f"epochs={args.epochs} loser_weight={args.loser_weight}",
             f"- HOLDOUT top-1 {pct(top1, total_n)}  top-3 {pct(top3, total_n)}  (n={total_n})",
             "  (perceptron baseline was top-1 0.343 / top-3 0.622)", "",
             "| Context | N | Top-1 | Top-3 |", "| --- | ---: | ---: | ---: |"]
    for ctx, (a, b, n) in sorted(by_ctx.items(), key=lambda x: -x[1][2])[:14]:
        lines.append(f"| `{ctx}` | {n} | {pct(a, n)} | {pct(b, n)} |")
    report = "\n".join(lines) + "\n"
    print(report)
    if args.report_out:
        args.report_out.write_text(report, encoding="utf-8")

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    # holdout value AUC
    def np_value(row_feats):
        vs = np.stack([np.maximum(W_emb[f].sum(axis=0), 0.0) * 0 + W_emb[f].sum(axis=0) for f in row_feats])
        v = vs.mean(axis=0)
        h = np.maximum(V1 @ np.maximum(v, 0.0) + vb1, 0.0)
        return float(V2 @ h + vb2)
    vals, tgts = [], []
    for ridx in hold_idx:
        vals.append(np_value(feats[ridx]))
        tgts.append(outcomes[ridx])
    order = np.argsort(vals)
    ranks = np.empty(len(vals)); ranks[order] = np.arange(len(vals))
    pos = np.array(tgts) > 0.5
    n_pos, n_neg = pos.sum(), (~pos).sum()
    auc = ((ranks[pos].sum() - n_pos * (n_pos - 1) / 2) / max(n_pos * n_neg, 1)) if n_pos and n_neg else float("nan")
    print(f"VALUE HEAD holdout AUC = {auc:.3f} (n={len(vals)}, pos_rate={pos.mean():.2f})")

    np.savez_compressed(
        args.model_out, emb=W_emb, W1=W1, b1=b1, W2=W2,
        b2=np.array([b2], dtype=np.float32),
        V1=V1, vb1=vb1, V2=V2, vb2=np.array([vb2], dtype=np.float32),
        buckets=np.array([args.buckets]), dim=np.array([args.dim]),
    )
    print(f"model={args.model_out} ({args.model_out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
