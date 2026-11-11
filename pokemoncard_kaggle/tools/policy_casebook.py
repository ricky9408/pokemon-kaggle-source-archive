#!/usr/bin/env python3
"""Mine public replay action gaps into concrete policy casebooks.

``compare_replay_actions.py`` is intentionally compact. This companion tool
keeps all repeated mismatches, groups them by normalized public-vs-local
choices, and renders the policy cases that are most worth testing.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


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


@dataclass
class PolicyCase:
    context: str
    their: tuple[str, ...]
    ours: tuple[str, ...]
    count: int = 0
    teams: Counter[str] = field(default_factory=Counter)
    motifs: Counter[str] = field(default_factory=Counter)
    examples: list[str] = field(default_factory=list)


def normalize_description(description: str) -> str:
    text = re.sub(r"^\d+:", "", description)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def descriptions_for_action(obs: dict, action: list[int], names: dict[int, str]) -> tuple[str, ...]:
    return tuple(normalize_description(option_description(obs, index, names)) for index in action)


def selected_text(items: tuple[str, ...]) -> str:
    return "; ".join(items) if items else "pass/no-pick"


def card_name(card: object, names: dict[int, str]) -> str:
    if not isinstance(card, dict):
        return "-"
    cid = card.get("id")
    if cid is None:
        return "-"
    return names.get(int(cid), str(cid))


def bench_names(cards: list[object], names: dict[int, str]) -> str:
    counts: Counter[str] = Counter(card_name(card, names) for card in cards if card)
    counts.pop("-", None)
    return ", ".join(f"{name}x{count}" for name, count in counts.most_common(4)) or "-"


def state_summary(obs: dict, names: dict[int, str]) -> str:
    current = obs.get("current") or {}
    players = current.get("players") or []
    my_index = current.get("yourIndex", 0)
    if not players or not isinstance(my_index, int) or my_index >= len(players):
        return "state unavailable"
    my_state = players[my_index]
    op_state = players[1 - my_index] if len(players) > 1 else {}
    active = (my_state.get("active") or [None])[0]
    op_active = (op_state.get("active") or [None])[0]
    return (
        f"hand={my_state.get('handCount', '?')} active={card_name(active, names)} "
        f"bench={bench_names(my_state.get('bench') or [], names)} "
        f"op_active={card_name(op_active, names)} "
        f"op_bench={bench_names(op_state.get('bench') or [], names)}"
    )


def motif_labels(context: str, their: tuple[str, ...], ours: tuple[str, ...]) -> list[str]:
    their_text = " ".join(their)
    ours_text = " ".join(ours)
    motifs: list[str] = []
    local_dudunsparce_ability = "ABILITY Dudunsparce" in ours_text
    if "Dunsparce" in their_text and "Abra" in ours_text:
        motifs.append("public_utility_basic_over_extra_abra")
    if "Kadabra" in their_text and "Alakazam" in ours_text:
        motifs.append("public_stage1_before_stage2")
    if "Basic {P} Energy" in their_text and ("Alakazam" in ours_text or "Abra" in ours_text):
        motifs.append("public_energy_before_extra_evolution_search")
    if "Night Stretcher" in their_text and any(card in ours_text for card in ("Hilda", "Buddy-Buddy Poffin", "Rare Candy", "Dawn")):
        motifs.append("public_recovery_before_engine_draw")
    if "Boss" in their_text and "Hilda" in ours_text:
        motifs.append("public_gust_before_draw")
    if local_dudunsparce_ability:
        if "Boss" in their_text:
            motifs.append("public_gust_before_engine_ability")
        if any(card in their_text for card in ("Night Stretcher", "Sacred Ash", "Lana")):
            motifs.append("public_recovery_before_engine_ability")
        if any(card in their_text for card in ("Hilda", "Dawn", "Colress", "Pokégear", "Poké Pad")):
            motifs.append("public_engine_before_engine_ability")
        if "ATTACH" in their_text:
            motifs.append("public_attach_before_engine_ability")
        if "ATTACK" in their_text:
            motifs.append("public_attack_before_engine_ability")
        if any(card in their_text for card in ("Battle Cage", "Nighttime Mine")):
            motifs.append("public_stadium_before_engine_ability")
        if "Enhanced Hammer" in their_text:
            motifs.append("public_disruption_before_engine_ability")
        if "END" in their_text:
            motifs.append("public_turn_discipline_over_engine_ability")
    if context == "MAIN" and "END" in their_text and any(action in ours_text for action in ("PLAY", "ATTACH", "ABILITY", "ATTACK")):
        motifs.append("public_turn_discipline")
    if context in {"TO_BENCH", "SETUP_BENCH_POKEMON", "TO_FIELD"}:
        if not their and ours:
            motifs.append("local_over_benches_optional_setup")
        if len(ours) > len(their):
            motifs.append("local_wider_bench_than_public")
    if context == "ACTIVATE" and "YES" in ours_text and "NO" in their_text:
        motifs.append("local_optional_activation_too_early")
    if context == "SWITCH" and their_text != ours_text:
        motifs.append("switch_target_priority_gap")
    if context == "TO_DECK" and their_text != ours_text:
        motifs.append("deck_return_priority_gap")
    return motifs or ["unclassified_policy_gap"]


def collect_cases(args: argparse.Namespace) -> tuple[dict[tuple[str, tuple[str, ...], tuple[str, ...]], PolicyCase], int, int]:
    names = load_names(args.cards)
    agent = load_agent(args.agent)
    target_teams = set(args.team)
    replay_paths = sorted(args.replays)
    duplicates = 0
    if not args.no_dedupe:
        replay_paths, duplicates = unique_replay_paths(replay_paths)

    cases: dict[tuple[str, tuple[str, ...], tuple[str, ...]], PolicyCase] = {}
    compared = 0
    for replay_path in replay_paths:
        data = json.loads(replay_path.read_text())
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
                action = public_action_for_observation(steps, step_index, slot)
                options = select.get("option") or []
                minimum = select.get("minCount", 0)
                maximum = select.get("maxCount", len(options))
                if not options or not valid_action(action, len(options), minimum, maximum):
                    continue
                if len(action) == 60:
                    continue
                ours = agent(obs)
                if not valid_action(ours, len(options), minimum, maximum):
                    continue
                compared += 1
                if action == ours:
                    continue

                context = enum_name(SelectContext, select.get("context"))
                their_desc = descriptions_for_action(obs, action, names)
                our_desc = descriptions_for_action(obs, ours, names)
                key = (context, their_desc, our_desc)
                case = cases.get(key)
                if case is None:
                    case = PolicyCase(context=context, their=their_desc, ours=our_desc)
                    cases[key] = case
                case.count += 1
                case.teams[team] += 1
                case.motifs.update(motif_labels(context, their_desc, our_desc))
                if len(case.examples) < args.examples:
                    case.examples.append(
                        f"{replay_path.name} step={step_index} team={team}; "
                        f"{state_summary(obs, names)}"
                    )
    return cases, compared, duplicates


def write_csv(path: Path, cases: list[PolicyCase]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["rank", "count", "context", "public_choice", "local_choice", "motifs", "teams"])
        for rank, case in enumerate(cases, start=1):
            writer.writerow(
                [
                    rank,
                    case.count,
                    case.context,
                    selected_text(case.their),
                    selected_text(case.ours),
                    ";".join(label for label, _ in case.motifs.most_common()),
                    ";".join(f"{team}:{count}" for team, count in case.teams.most_common()),
                ]
            )


def render(args: argparse.Namespace, cases: dict[tuple[str, tuple[str, ...], tuple[str, ...]], PolicyCase], compared: int, duplicates: int) -> str:
    ordered = sorted(cases.values(), key=lambda case: (case.count, sum(case.motifs.values())), reverse=True)
    top_cases = ordered[: args.top]
    motif_counts: Counter[str] = Counter()
    context_counts: Counter[str] = Counter()
    for case in cases.values():
        motif_counts.update({label: case.count for label in case.motifs})
        context_counts[case.context] += case.count

    lines: list[str] = []
    lines.append("# Policy Casebook")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: Pokemon TCG has no single strongest deck; repeated decision cases expose strategy timing inside a deck shell.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Agent: `{args.agent}`")
    lines.append(f"- Target teams: {', '.join(args.team) if args.team else 'all teams'}")
    lines.append(f"- Replay files requested: {len(args.replays)}")
    lines.append(f"- Deduped duplicate replay files: {duplicates}")
    lines.append(f"- Compared valid decisions: {compared}")
    lines.append(f"- Unique mismatch cases: {len(cases)}")
    lines.append("")
    lines.append("## Mismatch Contexts")
    lines.append("")
    for context, count in context_counts.most_common(12):
        lines.append(f"- `{context}`: {count} mismatches")
    lines.append("")
    lines.append("## Motif Totals")
    lines.append("")
    for motif, count in motif_counts.most_common(12):
        lines.append(f"- `{motif}`: {count}")
    lines.append("")
    lines.append("## Top Repeated Cases")
    lines.append("")
    lines.append("| Rank | Count | Context | Public Choice | Local Choice | Motifs | Teams |")
    lines.append("| ---: | ---: | --- | --- | --- | --- | --- |")
    for rank, case in enumerate(top_cases, start=1):
        motifs = ", ".join(label for label, _ in case.motifs.most_common(3))
        teams = ", ".join(f"{team} x{count}" for team, count in case.teams.most_common(3))
        lines.append(
            f"| {rank} | {case.count} | `{case.context}` | {selected_text(case.their)} | "
            f"{selected_text(case.ours)} | {motifs} | {teams} |"
        )
    lines.append("")
    lines.append("## Case Examples")
    lines.append("")
    for rank, case in enumerate(top_cases[: args.example_cases], start=1):
        lines.append(f"### Case {rank}: `{case.context}` x{case.count}")
        lines.append("")
        lines.append(f"- Public: {selected_text(case.their)}")
        lines.append(f"- Local: {selected_text(case.ours)}")
        lines.append(f"- Motifs: {', '.join(label for label, _ in case.motifs.most_common())}")
        for example in case.examples:
            lines.append(f"- {example}")
        lines.append("")
    lines.append("## Strategy Translation")
    lines.append("")
    lines.append("- Promote cases only when the same public-vs-local choice repeats across real replay states; single examples are scouting clues, not policy rules.")
    lines.append("- Prefer narrow policy probes that target one top motif, then require broad and Alakazam-focus gauntlet evidence before packaging.")
    lines.append("- If a probe improves action imitation but loses local broad/focus coverage, keep it as evaluator knowledge rather than a submit candidate.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--agent", type=Path, default=Path("submission"))
    parser.add_argument("--cards", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--team", action="append", default=[])
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--examples", type=int, default=3)
    parser.add_argument("--example-cases", type=int, default=8)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-dedupe", action="store_true")
    args = parser.parse_args()

    cases, compared, duplicates = collect_cases(args)
    report = render(args, cases, compared, duplicates)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    if args.csv_output:
        ordered = sorted(cases.values(), key=lambda case: (case.count, sum(case.motifs.values())), reverse=True)
        write_csv(args.csv_output, ordered)
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
