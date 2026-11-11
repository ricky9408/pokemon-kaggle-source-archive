#!/usr/bin/env python3
"""Train a behavior-cloning action ranker for the Claude ML agent.

Unlike the mimic agents (hand-tuned copies of a public deck list), this learns a
policy from how STRONG PUBLIC PLAYERS actually decide, then the agent USES the
model at play time. It is a deliberately ML-style approach to the over-fit
problem: a heuristic tuned on local self-play over-fits the local pool (Codex
audit: local-league vs public Spearman ~0.12), whereas a policy cloned from a
diverse public population should generalize to the public evaluator.

Key design choice — FEATURE PARITY. The agent must compute the exact same feature
strings at play time as we use here in training. We achieve this by:
  * featurizing from a "decision row" whose fields all exist in the live obs dict
    (build_ml_replay_dataset produces these rows; the agent reconstructs an
    identical row from the live obs with the same option_description /
    compact_state_features / board_key functions), and
  * dropping only fields that are HIDDEN at play time: the opponent's archetype
    and hand contents. Opponent active/bench/hand-COUNT stay (they are visible).
  * normalizing every Alakazam-family archetype label to "alakazam" so the
    `arch=` feature is the same value the agent uses at play.

`option_features_v2` below is replicated VERBATIM in the agent's main.py; a parity
test (tools/test_ml_parity.py style) compares the two on shared rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

CARD_RE = re.compile(r"\((\d+)\)")
ATTACK_RE = re.compile(r"attack=(\d+)")
TO_RE = re.compile(r"to=([A-Z_]+):(\d+)")

ALAKAZAM_PREFIX = "alakazam"


def normalize_archetype(arch: str) -> str:
    """Collapse all Alakazam-family variants to one stable label the agent can use."""
    a = (arch or "").lower()
    if a.startswith(ALAKAZAM_PREFIX):
        return "alakazam"
    return a


def stable_bucket(value: str, modulo: int) -> int:
    return int(hashlib.sha1(value.encode()).hexdigest()[:10], 16) % modulo


def option_parts(description: str) -> dict[str, str]:
    head = description.split(" ", 1)[0]
    option_type = head.split(":", 1)[1] if ":" in head else head
    card = CARD_RE.search(description)
    attack = ATTACK_RE.search(description)
    to = TO_RE.search(description)
    return {
        "type": option_type,
        "card": card.group(1) if card else "",
        "attack": attack.group(1) if attack else "",
        "to_area": to.group(1) if to else "",
    }


def bucket_count(value: Any, bucket_size: int = 3) -> str:
    if not isinstance(value, int):
        return "?"
    return str(min(6, value // bucket_size))


def _state(row: dict[str, Any], side: str, field: str) -> Any:
    return ((row.get("state") or {}).get(side) or {}).get(field)


def _root(row: dict[str, Any], field: str) -> Any:
    return (row.get("state") or {}).get(field)


# ---------------------------------------------------------------------------
# THE PARITY-CRITICAL FEATURIZER. Keep byte-identical with the agent copy.
# Inputs: a decision row (offline) or an obs-reconstructed row (online).
# Hidden-at-play fields (opponent archetype/hand contents) are NOT used.
# ---------------------------------------------------------------------------
def option_features_v2(row: dict[str, Any], option_index: int) -> list[str]:
    options = row.get("options") or []
    description = options[option_index] if option_index < len(options) else ""
    parts = option_parts(description)
    context = str(row.get("context"))
    archetype = normalize_archetype(str(row.get("archetype")))
    own_active = _state(row, "me", "active")
    opp_active = _state(row, "opponent", "active")
    own_bench = bucket_count(_state(row, "me", "bench_count"))
    opp_bench = bucket_count(_state(row, "opponent", "bench_count"))
    own_hand = bucket_count(_state(row, "me", "hand_count"), 2)
    opp_hand = bucket_count(_state(row, "opponent", "hand_count"), 2)
    turn_bucket = bucket_count(_root(row, "turn"), 2)
    turn_action_bucket = bucket_count(_root(row, "turn_action_count"), 3)
    option_count_bucket = bucket_count(row.get("option_count"), 4)
    board_key = str(row.get("board_key") or "")
    energy_attached = str(_root(row, "energy_attached"))
    supporter_played = str(_root(row, "supporter_played"))
    stadium_played = str(_root(row, "stadium_played"))

    feats = [
        "bias",
        f"ctx={context}",
        f"arch={archetype}",
        f"ctx_type={context}:{parts['type']}",
        f"type={parts['type']}",
        f"option_count={option_count_bucket}",
        f"turn={turn_bucket}",
        f"turn_action={turn_action_bucket}",
        f"energy_attached={energy_attached}",
        f"supporter_played={supporter_played}",
        f"stadium_played={stadium_played}",
        f"own_active={own_active}",
        f"opp_active={opp_active}",
        f"own_bench={own_bench}",
        f"opp_bench={opp_bench}",
        f"own_hand={own_hand}",
        f"opp_hand={opp_hand}",
        f"turn_type={turn_bucket}:{parts['type']}",
        f"energy_type={energy_attached}:{parts['type']}",
    ]
    if board_key:
        feats += [f"board={board_key}", f"board_type={board_key}:{parts['type']}"]
    if parts["card"]:
        feats += [
            f"card={parts['card']}",
            f"ctx_card={context}:{parts['card']}",
            f"arch_card={archetype}:{parts['card']}",
            f"energy_card={energy_attached}:{parts['card']}",
        ]
        if board_key:
            feats.append(f"board_card={board_key}:{parts['card']}")
    if parts["attack"]:
        feats += [f"attack={parts['attack']}", f"ctx_attack={context}:{parts['attack']}"]
    if parts["to_area"]:
        feats += [f"to_area={parts['to_area']}", f"ctx_to={context}:{parts['to_area']}"]
    return feats


def score(weights: dict[str, float], features: list[str]) -> float:
    return sum(weights.get(f, 0.0) for f in features)


def ranked(weights: dict[str, float], row: dict[str, Any]) -> list[int]:
    n = int(row.get("option_count") or 0)
    scored = [(score(weights, option_features_v2(row, i)), -i, i) for i in range(n)]
    scored.sort(reverse=True)
    return [i for _, _, i in scored]


def valid_label(row: dict[str, Any]) -> int | None:
    action = row.get("action")
    oc = row.get("option_count")
    if not isinstance(action, list) or len(action) != 1:
        return None
    sel = action[0]
    if not isinstance(oc, int) or oc <= 1 or not isinstance(sel, int) or not 0 <= sel < oc:
        return None
    return sel


def load_rows(paths: list[Path], archetype_prefix: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for p in paths:
        for line in p.open(encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if not str(r.get("archetype", "")).lower().startswith(archetype_prefix):
                continue
            key = (r.get("episode_id"), r.get("context"), tuple(r.get("action") or []),
                   r.get("option_count"), str(r.get("options")))
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Train BC action ranker for the Claude ML agent")
    ap.add_argument("decisions", nargs="+", type=Path)
    ap.add_argument("--archetype-prefix", default="alakazam")
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--learning-rate", type=float, default=0.25)
    ap.add_argument("--holdout-mod", type=int, default=5)
    ap.add_argument("--holdout-bucket", type=int, default=0)
    ap.add_argument("--model-out", type=Path, required=True)
    ap.add_argument("--report-out", type=Path, default=None)
    args = ap.parse_args()

    rows = load_rows(args.decisions, args.archetype_prefix.lower())
    train_rows = [r for r in rows if stable_bucket(str(r.get("episode_id")), args.holdout_mod) != args.holdout_bucket]
    hold_rows = [r for r in rows if stable_bucket(str(r.get("episode_id")), args.holdout_mod) == args.holdout_bucket]

    weights: dict[str, float] = {}
    updates = 0
    trained = 0
    for _ in range(args.epochs):
        for r in train_rows:
            label = valid_label(r)
            if label is None:
                continue
            trained += 1
            pred = ranked(weights, r)[0]
            if pred == label:
                continue
            updates += 1
            for f in option_features_v2(r, label):
                weights[f] = weights.get(f, 0.0) + args.learning_rate
            for f in option_features_v2(r, pred):
                weights[f] = weights.get(f, 0.0) - args.learning_rate

    # holdout eval + ML score range (for blend calibration in the agent)
    top1 = top3 = total = 0
    by_ctx: defaultdict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    score_min = score_max = 0.0
    for r in hold_rows:
        label = valid_label(r)
        if label is None:
            continue
        total += 1
        rk = ranked(weights, r)
        ctx = str(r.get("context"))
        by_ctx[ctx][2] += 1
        if rk and rk[0] == label:
            top1 += 1; by_ctx[ctx][0] += 1
        if label in rk[:3]:
            top3 += 1; by_ctx[ctx][1] += 1
        for i in range(int(r.get("option_count") or 0)):
            s = score(weights, option_features_v2(r, i))
            score_min = min(score_min, s); score_max = max(score_max, s)

    payload = {
        "schema": "claude_ml_policy_v2",
        "archetype_prefix": args.archetype_prefix,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "n_rows": len(rows),
        "score_min": score_min,
        "score_max": score_max,
        "weights": weights,
    }
    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    args.model_out.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    def pct(a, b):
        return f"{a/b:.3f}" if b else "0.000"
    lines = ["# Claude ML Policy (behavior cloning)", "",
             f"- Inputs: {', '.join(str(p) for p in args.decisions)}",
             f"- Archetype filter: `{args.archetype_prefix}*` -> {len(rows)} rows "
             f"({len(train_rows)} train / {len(hold_rows)} holdout)",
             f"- Weights: {len(weights)} | updates: {updates} | trained decisions: {trained}",
             f"- ML score range (for blend calibration): [{score_min:.2f}, {score_max:.2f}]", "",
             f"- Holdout top-1: {pct(top1,total)}  top-3: {pct(top3,total)}  (n={total})", "",
             "| Context | N | Top-1 | Top-3 |", "| --- | ---: | ---: | ---: |"]
    for ctx, (a, b, n) in sorted(by_ctx.items(), key=lambda x: -x[1][2]):
        lines.append(f"| `{ctx}` | {n} | {pct(a,n)} | {pct(b,n)} |")
    report = "\n".join(lines) + "\n"
    if args.report_out:
        args.report_out.write_text(report, encoding="utf-8")
    print(report)
    print(f"model={args.model_out} weights={len(weights)} "
          f"holdout_top1={pct(top1,total)} top3={pct(top3,total)} n={total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
