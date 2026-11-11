#!/usr/bin/env python3
"""Mine public-replay predicates for a policy boundary between two agents.

The old local gauntlet is fenced because it does not predict public score. This
tool uses public replay observations instead: compare a baseline agent and a
candidate agent on the exact same public decision states, then rank simple
state predicates by whether the candidate's changed choice fixes or regresses
public-action imitation.

Run inside linux/amd64 when agents import the bundled simulator:

docker run -i --rm --platform linux/amd64 -v "$PWD:/work" -w /work python:3.11-slim \
  bash -lc "python tools/mine_agent_boundary.py \$(find scouting/... -name '*replay.json') \
    --baseline-agent agents/v75_hiroingk_hammer_v57policy \
    --candidate-agent agents/v100_hiroingk_hammer_dudun_lethal_attack"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare_replay_actions import (  # noqa: E402
    SelectContext,
    decision_state_key,
    enum_name,
    load_agent,
    load_names,
    option_description,
    public_action_for_observation,
    unique_replay_paths,
    valid_action,
)


CARD_RE = re.compile(r"\((\d+)\)")
TYPE_RE = re.compile(r"^\d+:([A-Z_]+)")
ATTACK_RE = re.compile(r"attack=(\d+)")


@dataclass(frozen=True)
class BoundaryCase:
    replay_name: str
    step_index: int
    team: str
    context: str
    public_action: tuple[int, ...]
    baseline_action: tuple[int, ...]
    candidate_action: tuple[int, ...]
    public_text: str
    baseline_text: str
    candidate_text: str
    outcome: str
    obs: dict
    option_texts: tuple[str, ...]


@dataclass(frozen=True)
class Predicate:
    name: str
    fn: Callable[[BoundaryCase], bool]


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
    def regression_rate(self) -> float:
        den = self.fixes + self.regressions
        return self.regressions / den if den else 0.0

    @property
    def net(self) -> int:
        return self.fixes - self.regressions


def selected_text(action: tuple[int, ...], option_texts: tuple[str, ...]) -> str:
    if not action:
        return "pass/no-pick"
    return "; ".join(option_texts[index] if 0 <= index < len(option_texts) else f"{index}:out" for index in action)


def option_type(text: str) -> str:
    match = TYPE_RE.search(text)
    return match.group(1) if match else "UNKNOWN"


def attack_id(text: str) -> str:
    match = ATTACK_RE.search(text)
    return match.group(1) if match else ""


def contains_card(text: str, card_id: int) -> bool:
    return f"({card_id})" in text


def card_id(card: object) -> str:
    if isinstance(card, dict) and card.get("id") is not None:
        return str(card["id"])
    return "none"


def bucket_int(value: object, cuts: tuple[int, ...]) -> str:
    if not isinstance(value, int):
        return "?"
    for cut in cuts:
        if value <= cut:
            return f"<={cut}"
    return f">{cuts[-1]}"


def player_states(obs: dict) -> tuple[dict, dict, int]:
    current = obs.get("current") or {}
    players = current.get("players") or []
    your_index = current.get("yourIndex", 0)
    if not isinstance(your_index, int) or len(players) < 2:
        return {}, {}, 0
    return players[your_index], players[1 - your_index], your_index


def list_count(state: dict, key: str, alt: str = "") -> int | None:
    value = state.get(key)
    if isinstance(value, list):
        return len(value)
    if alt and isinstance(state.get(alt), int):
        return int(state[alt])
    return None


def first_card_id(state: dict, key: str) -> str:
    value = state.get(key)
    if isinstance(value, list) and value:
        return card_id(value[0])
    return "none"


def has_option(case: BoundaryCase, needle: str) -> bool:
    return any(needle in text for text in case.option_texts)


def has_option_type(case: BoundaryCase, type_name: str) -> bool:
    return any(option_type(text) == type_name for text in case.option_texts)


def action_type(text: str) -> str:
    if ";" in text:
        return "MULTI"
    if text == "pass/no-pick":
        return "PASS"
    return option_type(text)


def feature_map(case: BoundaryCase) -> dict[str, str]:
    my_state, op_state, _your_index = player_states(case.obs)
    my_hand = list_count(my_state, "hand", "handCount")
    op_hand = list_count(op_state, "hand", "handCount")
    my_bench = list_count(my_state, "bench")
    op_bench = list_count(op_state, "bench")
    current = case.obs.get("current") or {}
    state_flags = case.obs.get("state") or {}
    turn = current.get("turn")
    if turn is None:
        turn = state_flags.get("turn")
    return {
        "context": case.context,
        "public_type": action_type(case.public_text),
        "baseline_type": action_type(case.baseline_text),
        "candidate_type": action_type(case.candidate_text),
        "candidate_attack": attack_id(case.candidate_text) or "?",
        "public_attack": attack_id(case.public_text) or "?",
        "active": first_card_id(my_state, "active"),
        "opp_active": first_card_id(op_state, "active"),
        "hand": bucket_int(my_hand, (4, 7, 10, 13, 16)),
        "opp_hand": bucket_int(op_hand, (4, 7, 10, 13, 16)),
        "bench": bucket_int(my_bench, (1, 2, 3, 4)),
        "opp_bench": bucket_int(op_bench, (1, 2, 3, 4)),
        "my_prizes": bucket_int(list_count(my_state, "prizes", "prizeCount"), (1, 2, 3, 4, 5)),
        "opp_prizes": bucket_int(list_count(op_state, "prizes", "prizeCount"), (1, 2, 3, 4, 5)),
        "turn": bucket_int(turn, (2, 4, 6, 8, 12)),
        "has_boss": str(has_option(case, "Boss")),
        "has_hilda": str(has_option(case, "Hilda")),
        "has_pokepad": str(has_option(case, "Poké Pad")),
        "has_recovery": str(any(has_option(case, text) for text in ("Night Stretcher", "Sacred Ash", "Lana"))),
        "has_hammer": str(has_option(case, "Enhanced Hammer")),
        "has_stadium": str(any(has_option(case, text) for text in ("Battle Cage", "Nighttime Mine"))),
        "has_attach": str(has_option_type(case, "ATTACH")),
        "has_dudun_ability": str(any(option_type(text) == "ABILITY" and contains_card(text, 66) for text in case.option_texts)),
    }


def collect_cases(args: argparse.Namespace) -> tuple[list[BoundaryCase], int, int]:
    names = load_names(args.cards)
    baseline = load_agent(args.baseline_agent)
    candidate = load_agent(args.candidate_agent)
    replay_paths = sorted(args.replays)
    duplicates = 0
    if not args.no_dedupe:
        replay_paths, duplicates = unique_replay_paths(replay_paths)

    cases: list[BoundaryCase] = []
    compared = 0
    target_teams = set(args.team)
    for replay_path in replay_paths:
        data = json.loads(replay_path.read_text(encoding="utf-8"))
        teams = data["info"]["TeamNames"]
        steps = data["steps"]
        seen_decision_states: set[tuple[int, str]] = set()
        for step_index, step in enumerate(steps):
            for slot, record in enumerate(step):
                team = teams[slot]
                if target_teams and team not in target_teams:
                    continue
                obs = record.get("observation") or {}
                select = obs.get("select")
                if not select:
                    continue
                state_key = (slot, decision_state_key(obs))
                if state_key in seen_decision_states:
                    continue
                seen_decision_states.add(state_key)
                public_action = public_action_for_observation(steps, step_index, slot)
                options = select.get("option") or []
                minimum = select.get("minCount", 0)
                maximum = select.get("maxCount", len(options))
                if not options or not valid_action(public_action, len(options), minimum, maximum):
                    continue
                if len(public_action) == 60:
                    continue

                baseline_action = baseline(obs)
                candidate_action = candidate(obs)
                if not valid_action(baseline_action, len(options), minimum, maximum):
                    continue
                if not valid_action(candidate_action, len(options), minimum, maximum):
                    continue
                compared += 1
                if baseline_action == candidate_action:
                    continue
                context = enum_name(SelectContext, select.get("context"))
                if args.context and context != args.context:
                    continue
                public_tuple = tuple(public_action)
                baseline_tuple = tuple(baseline_action)
                candidate_tuple = tuple(candidate_action)
                if candidate_tuple == public_tuple and baseline_tuple != public_tuple:
                    outcome = "fix"
                elif baseline_tuple == public_tuple and candidate_tuple != public_tuple:
                    outcome = "regression"
                else:
                    outcome = "neutral"
                option_texts = tuple(option_description(obs, index, names) for index in range(len(options)))
                public_text = selected_text(public_tuple, option_texts)
                baseline_text = selected_text(baseline_tuple, option_texts)
                candidate_text = selected_text(candidate_tuple, option_texts)
                if args.candidate_type and action_type(candidate_text) != args.candidate_type:
                    continue
                if args.baseline_type and action_type(baseline_text) != args.baseline_type:
                    continue
                cases.append(
                    BoundaryCase(
                        replay_name=replay_path.name,
                        step_index=step_index,
                        team=team,
                        context=context,
                        public_action=public_tuple,
                        baseline_action=baseline_tuple,
                        candidate_action=candidate_tuple,
                        public_text=public_text,
                        baseline_text=baseline_text,
                        candidate_text=candidate_text,
                        outcome=outcome,
                        obs=obs,
                        option_texts=option_texts,
                    )
                )
    return cases, compared, duplicates


def make_predicates(cases: list[BoundaryCase], min_support: int) -> list[Predicate]:
    values: dict[str, Counter[str]] = {}
    for case in cases:
        for key, value in feature_map(case).items():
            if key.startswith("public_"):
                continue
            values.setdefault(key, Counter())[value] += 1
    predicates = [Predicate("all", lambda _case: True)]
    atoms: list[Predicate] = []
    for key, counter in sorted(values.items()):
        for value, count in sorted(counter.items()):
            if count < min_support or value in {"?", "none"}:
                continue
            atoms.append(Predicate(f"{key}={value}", lambda case, k=key, v=value: feature_map(case).get(k) == v))
    predicates.extend(atoms)
    for left_index, left in enumerate(atoms):
        left_key = left.name.split("=", 1)[0]
        for right in atoms[left_index + 1 :]:
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


def evaluate(predicate: Predicate, cases: list[BoundaryCase]) -> PredStats:
    stats = PredStats()
    for case in cases:
        if not predicate.fn(case):
            continue
        stats.total += 1
        stats.fixes += int(case.outcome == "fix")
        stats.regressions += int(case.outcome == "regression")
        stats.neutral += int(case.outcome == "neutral")
    return stats


def examples(cases: list[BoundaryCase], outcome: str, limit: int) -> list[str]:
    rows: list[str] = []
    for case in cases:
        if case.outcome != outcome:
            continue
        features = feature_map(case)
        rows.append(
            "- `{team}` {replay} step={step} {ctx} active={active} opp={opp} hand={hand} "
            "public=`{public}` baseline=`{baseline}` candidate=`{candidate}`".format(
                team=case.team,
                replay=case.replay_name,
                step=case.step_index,
                ctx=case.context,
                active=features["active"],
                opp=features["opp_active"],
                hand=features["hand"],
                public=case.public_text,
                baseline=case.baseline_text,
                candidate=case.candidate_text,
            )
        )
        if len(rows) >= limit:
            break
    return rows


def render(args: argparse.Namespace, cases: list[BoundaryCase], compared: int, duplicates: int) -> str:
    all_stats = evaluate(Predicate("all", lambda _case: True), cases)
    predicates = make_predicates(cases, args.min_support)
    ranked_safe = [(pred, evaluate(pred, cases)) for pred in predicates]
    ranked_safe.sort(key=lambda item: (item[1].net, item[1].precision, item[1].total), reverse=True)
    ranked_unsafe = list(ranked_safe)
    ranked_unsafe.sort(key=lambda item: (item[1].regressions - item[1].fixes, item[1].regression_rate, item[1].total), reverse=True)

    lines: list[str] = [
        "# Agent Boundary Miner",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "",
        "## Inputs",
        "",
        f"- Baseline agent: `{args.baseline_agent}`",
        f"- Candidate agent: `{args.candidate_agent}`",
        f"- Replay files requested: {len(args.replays)}",
        f"- Deduped duplicate replay files: {duplicates}",
        f"- Compared valid decisions: {compared}",
        f"- Changed decisions after filters: {all_stats.total}",
        f"- Filters: context={args.context or 'any'}, baseline_type={args.baseline_type or 'any'}, candidate_type={args.candidate_type or 'any'}",
        "",
        "## Outcome Summary",
        "",
        f"- Fixes: {all_stats.fixes}",
        f"- Regressions: {all_stats.regressions}",
        f"- Neutral changes: {all_stats.neutral}",
        f"- Precision on changed fix/regression rows: {all_stats.precision:.3f}",
        f"- Net: {all_stats.net}",
        "",
        "## Safe Predicate Candidates",
        "",
        "| Predicate | N | Fixes | Regressions | Neutral | Precision | Net |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    emitted = 0
    for pred, stats in ranked_safe:
        if stats.total < args.min_support or stats.precision < args.min_precision:
            continue
        lines.append(f"| `{pred.name}` | {stats.total} | {stats.fixes} | {stats.regressions} | {stats.neutral} | {stats.precision:.3f} | {stats.net} |")
        emitted += 1
        if emitted >= args.limit:
            break
    if emitted == 0:
        lines.append("| - | 0 | 0 | 0 | 0 | 0.000 | 0 |")

    lines.extend(["", "## Unsafe Predicate Warnings", "", "| Predicate | N | Fixes | Regressions | Neutral | Regression Rate | Net |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    emitted = 0
    for pred, stats in ranked_unsafe:
        if stats.total < args.min_support or stats.regressions <= stats.fixes:
            continue
        lines.append(f"| `{pred.name}` | {stats.total} | {stats.fixes} | {stats.regressions} | {stats.neutral} | {stats.regression_rate:.3f} | {stats.net} |")
        emitted += 1
        if emitted >= args.limit:
            break
    if emitted == 0:
        lines.append("| - | 0 | 0 | 0 | 0 | 0.000 | 0 |")

    lines.extend(["", "## Examples", ""])
    for outcome in ("fix", "regression", "neutral"):
        lines.extend([f"### {outcome}", ""])
        rows = examples(cases, outcome, args.examples)
        lines.extend(rows or ["- none"])
        lines.append("")

    lines.extend(
        [
            "## Interpretation",
            "",
            "- Safe predicates are candidates for a narrow runtime policy probe only when they also avoid the unsafe warning predicates.",
            "- If `all` has negative net, the candidate is broadly unsafe even if it improves one motif.",
            "- This report is public-action imitation evidence, not public-score predictiveness; submit gates remain authoritative.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--baseline-agent", required=True, type=Path)
    parser.add_argument("--candidate-agent", required=True, type=Path)
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--team", action="append", default=[])
    parser.add_argument("--context", default="MAIN")
    parser.add_argument("--baseline-type", default="")
    parser.add_argument("--candidate-type", default="")
    parser.add_argument("--min-support", type=int, default=8)
    parser.add_argument("--min-precision", type=float, default=0.55)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--examples", type=int, default=8)
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--report-out", type=Path, default=Path("strategy/agent_boundary_miner.md"))
    args = parser.parse_args()

    cases, compared, duplicates = collect_cases(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    report = render(args, cases, compared, duplicates)
    args.report_out.write_text(report, encoding="utf-8")
    all_stats = evaluate(Predicate("all", lambda _case: True), cases)
    print(
        "changed={changed} fixes={fixes} regressions={regressions} precision={precision:.3f} net={net} report={report}".format(
            changed=all_stats.total,
            fixes=all_stats.fixes,
            regressions=all_stats.regressions,
            precision=all_stats.precision,
            net=all_stats.net,
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
