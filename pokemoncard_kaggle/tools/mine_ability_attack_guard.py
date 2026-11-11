#!/usr/bin/env python3
"""Mine safe predicates for Dudunsparce ability-before-attack timing.

The public-anchor guard evaluator found that a broad "ABILITY before ATTACK"
overlay improves replay-action imitation, but still has regressions. This tool
looks at the exact rows where Dudunsparce ability and attack compete, then ranks
simple runtime predicates by fix/regression tradeoff.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from train_action_ranker import load_rows, option_parts, pct, ranked_options, valid_single_label


CARD_RE = re.compile(r"\((\d+)\)")


@dataclass(frozen=True)
class Case:
    row: dict[str, Any]
    label: int
    base_top: int
    ability_index: int
    attack_index: int
    outcome: str
    public_text: str
    base_text: str
    ability_text: str
    attack_text: str


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[Case], bool]


@dataclass
class PredStats:
    total: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral: int = 0
    wins: int = 0
    losses: int = 0

    @property
    def precision(self) -> float:
        den = self.fixes + self.regressions
        return self.fixes / den if den else 0.0

    @property
    def net(self) -> int:
        return self.fixes - self.regressions


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def card_id(text: str) -> str:
    match = CARD_RE.search(text)
    return match.group(1) if match else ""


def reward_bucket(value: Any) -> str:
    if value == 1:
        return "win"
    if value == -1:
        return "loss"
    if value == 0:
        return "draw"
    return "unknown"


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def state_value(row: dict[str, Any], side: str, key: str) -> Any:
    state = row.get("state") or {}
    side_state = state.get(side) or {}
    return side_state.get(key)


def bucket_int(value: Any, cuts: tuple[int, ...]) -> str:
    if not isinstance(value, int):
        return "?"
    for cut in cuts:
        if value <= cut:
            return f"<={cut}"
    return f">{cuts[-1]}"


def collect_cases(rows: list[dict[str, Any]], weights: dict[str, float]) -> list[Case]:
    cases: list[Case] = []
    for row in rows:
        if row_value(row, "context") != "MAIN":
            continue
        label = valid_single_label(row)
        if label is None:
            continue
        ranking = ranked_options(weights, row)
        if not ranking:
            continue
        options = [str(option) for option in (row.get("options") or [])]
        ability_indices = [
            index
            for index, text in enumerate(options)
            if option_parts(text)["type"] == "ABILITY" and card_id(text) == "66"
        ]
        attack_indices = [
            index
            for index, text in enumerate(options)
            if option_parts(text)["type"] == "ATTACK"
        ]
        if not ability_indices or not attack_indices:
            continue
        base_top = ranking[0]
        if base_top not in attack_indices:
            continue
        ability_index = ability_indices[0]
        attack_index = base_top
        public_text = options[label] if label < len(options) else str(label)
        if label == ability_index:
            outcome = "fix"
        elif label in attack_indices:
            outcome = "regression"
        else:
            outcome = "neutral"
        cases.append(
            Case(
                row=row,
                label=label,
                base_top=base_top,
                ability_index=ability_index,
                attack_index=attack_index,
                outcome=outcome,
                public_text=public_text,
                base_text=options[base_top],
                ability_text=options[ability_index],
                attack_text=options[attack_index],
            )
        )
    return cases


def feature_map(case: Case) -> dict[str, str]:
    row = case.row
    me_hand = state_value(row, "me", "hand_count")
    opp_hand = state_value(row, "opponent", "hand_count")
    me_bench = state_value(row, "me", "bench_count")
    opp_bench = state_value(row, "opponent", "bench_count")
    me_prize = state_value(row, "me", "prize_count")
    opp_prize = state_value(row, "opponent", "prize_count")
    turn = (row.get("state") or {}).get("turn")
    action_count = (row.get("state") or {}).get("turn_action_count")
    return {
        "archetype": row_value(row, "archetype"),
        "opponent": row_value(row, "opponent_archetype"),
        "active": str(state_value(row, "me", "active")),
        "opp_active": str(state_value(row, "opponent", "active")),
        "hand": bucket_int(me_hand, (4, 7, 10, 13, 16)),
        "opp_hand": bucket_int(opp_hand, (4, 7, 10, 13, 16)),
        "bench": bucket_int(me_bench, (1, 2, 3, 4)),
        "opp_bench": bucket_int(opp_bench, (1, 2, 3, 4)),
        "prizes": f"{me_prize}|{opp_prize}",
        "turn": bucket_int(turn, (2, 4, 6, 8, 12)),
        "turn_action": bucket_int(action_count, (2, 5, 9, 14, 20)),
        "attack": option_parts(case.attack_text)["attack"] or "?",
        "reward": reward_bucket(row.get("terminal_reward")),
    }


def make_predicates(cases: list[Case]) -> list[Predicate]:
    values: dict[str, Counter[str]] = {}
    for case in cases:
        for key, value in feature_map(case).items():
            if key == "reward":
                continue
            values.setdefault(key, Counter())[value] += 1

    predicates: list[Predicate] = [Predicate("all", lambda _case: True)]
    atoms: list[Predicate] = []
    for key, counter in sorted(values.items()):
        for value, count in counter.items():
            if count < 8:
                continue
            atoms.append(Predicate(f"{key}={value}", lambda case, k=key, v=value: feature_map(case).get(k) == v))
    predicates.extend(atoms)
    for left_index, left in enumerate(atoms):
        for right in atoms[left_index + 1 :]:
            left_key = left.name.split("=", 1)[0]
            right_key = right.name.split("=", 1)[0]
            if left_key == right_key:
                continue
            predicates.append(
                Predicate(
                    f"{left.name} & {right.name}",
                    lambda case, l=left.fn, r=right.fn: l(case) and r(case),
                )
            )
    return predicates


def evaluate_predicate(predicate: Predicate, cases: list[Case]) -> PredStats:
    stats = PredStats()
    for case in cases:
        if not predicate.fn(case):
            continue
        stats.total += 1
        stats.fixes += int(case.outcome == "fix")
        stats.regressions += int(case.outcome == "regression")
        stats.neutral += int(case.outcome == "neutral")
        reward = reward_bucket(case.row.get("terminal_reward"))
        stats.wins += int(reward == "win")
        stats.losses += int(reward == "loss")
    return stats


def render_report(args: argparse.Namespace, cases: list[Case], ranked: list[tuple[Predicate, PredStats]]) -> str:
    lines: list[str] = []
    lines.append("# Ability-Before-Attack Guard Miner")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Base model: `{args.model}`")
    lines.append("- Case definition: MAIN rows with Dudunsparce ability available, at least one attack available, and the base model top-1 is ATTACK.")
    lines.append("")
    total = PredStats()
    for case in cases:
        total.total += 1
        total.fixes += int(case.outcome == "fix")
        total.regressions += int(case.outcome == "regression")
        total.neutral += int(case.outcome == "neutral")
    lines.append("## Case Summary")
    lines.append("")
    lines.append(f"- Cases: {total.total}")
    lines.append(f"- Public chose Dudunsparce ability: {total.fixes}")
    lines.append(f"- Public kept attacking: {total.regressions}")
    lines.append(f"- Public chose another action: {total.neutral}")
    lines.append(f"- Broad precision if always ability-before-attack: {total.precision:.3f}")
    lines.append("")
    lines.append("## Candidate Runtime Predicates")
    lines.append("")
    lines.append("| Predicate | N | Fixes | Regressions | Neutral | Precision | Net | Wins | Losses |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    emitted = 0
    for pred, stats in ranked:
        if stats.total < args.min_support:
            continue
        if stats.precision < args.min_precision:
            continue
        lines.append(
            f"| `{pred.name}` | {stats.total} | {stats.fixes} | {stats.regressions} | {stats.neutral} | "
            f"{stats.precision:.3f} | {stats.net} | {stats.wins} | {stats.losses} |"
        )
        emitted += 1
        if emitted >= args.limit:
            break
    if emitted == 0:
        lines.append("| - | 0 | 0 | 0 | 0 | 0.000 | 0 | 0 | 0 |")
    lines.append("")
    lines.append("## Top Outcome Examples")
    lines.append("")
    for outcome in ("fix", "regression", "neutral"):
        lines.append(f"### {outcome}")
        lines.append("")
        shown = 0
        for case in cases:
            if case.outcome != outcome:
                continue
            features = feature_map(case)
            lines.append(
                "- `{team}` {arch} vs {opp} hand={hand} turn={turn} attack={attack}: public=`{public}` base=`{base}` ability=`{ability}`".format(
                    team=row_value(case.row, "team"),
                    arch=features["archetype"],
                    opp=features["opponent"],
                    hand=features["hand"],
                    turn=features["turn"],
                    attack=features["attack"],
                    public=case.public_text,
                    base=case.base_text,
                    ability=case.ability_text,
                )
            )
            shown += 1
            if shown >= args.examples:
                break
        if shown == 0:
            lines.append("- none")
        lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    if ranked:
        best, stats = ranked[0]
        lines.append(f"- Best raw predicate by net is `{best.name}` with net {stats.net}, precision {stats.precision:.3f}, support {stats.total}.")
    lines.append("- Prefer predicates with positive net and high precision; do not hard-apply broad ability-before-attack when public often attacks.")
    lines.append("- This is a strategy feature-mining artifact. Any policy patch still needs action/motif holdout and public-anchor gates.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/ability_attack_guard_miner.md"))
    parser.add_argument("--min-support", type=int, default=8)
    parser.add_argument("--min-precision", type=float, default=0.55)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--examples", type=int, default=8)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    cases = collect_cases(rows, weights)
    predicates = make_predicates(cases)
    ranked = [(predicate, evaluate_predicate(predicate, cases)) for predicate in predicates]
    ranked.sort(key=lambda item: (item[1].net, item[1].precision, item[1].total), reverse=True)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, cases, ranked), encoding="utf-8")
    all_stats = evaluate_predicate(Predicate("all", lambda _case: True), cases)
    print(
        "cases={cases} fixes={fixes} regressions={regs} precision={prec:.3f} report={report}".format(
            cases=all_stats.total,
            fixes=all_stats.fixes,
            regs=all_stats.regressions,
            prec=all_stats.precision,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
