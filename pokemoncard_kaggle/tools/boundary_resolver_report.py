#!/usr/bin/env python3
"""Summarize high-sample boundary gauntlets between two candidate strategies.

The reset packet can wobble when broad and focus windows are nearly tied. This
tool turns the follow-up resolver gauntlets into a compact decision artifact so
the submit runbook can distinguish a real strategy flip from low-sample noise.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class OpponentRate:
    opponent: str
    weight: float
    win_rate: float
    teams: str


@dataclass
class CandidateRates:
    raw_name: str
    weighted_win_rate: float | None = None
    opponents: list[OpponentRate] = field(default_factory=list)


def alias(text: str) -> str:
    match = re.search(r"\bv(\d+)\b|v(\d+)_|-(v\d+)\b", text)
    if match:
        for group in match.groups():
            if group:
                return group if group.startswith("v") else f"v{group}"
    return Path(text).name


def parse_gauntlet(path: Path) -> dict[str, CandidateRates]:
    rates: dict[str, CandidateRates] = {}
    current: CandidateRates | None = None
    in_candidate = False
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Candidate "):
                raw_name = line.removeprefix("Candidate ").strip()
                current = CandidateRates(raw_name=raw_name)
                rates[alias(raw_name)] = current
                in_candidate = True
                continue
            if not in_candidate or current is None:
                continue
            if line.startswith("weighted_win_rate,"):
                current.weighted_win_rate = float(line.split(",", 1)[1])
                continue
            if line.startswith("opponent,") or line.startswith("opponent_pool") or line.startswith("archetype,"):
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue
            try:
                current.opponents.append(
                    OpponentRate(
                        opponent=parts[0],
                        weight=float(parts[1]),
                        win_rate=float(parts[6]),
                        teams=",".join(parts[7:]),
                    )
                )
            except ValueError:
                continue
    return rates


def get_candidate(rates: dict[str, CandidateRates], candidate: str) -> CandidateRates:
    key = alias(candidate)
    if key not in rates:
        available = ", ".join(sorted(rates))
        raise KeyError(f"Candidate {candidate!r} not found; available aliases: {available}")
    return rates[key]


def fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def verdict(a: str, b: str, broad_a: float, broad_b: float, focus_a: float, focus_b: float, epsilon: float) -> tuple[str, str]:
    broad_delta = broad_a - broad_b
    focus_delta = focus_a - focus_b
    broad_winner = a if broad_delta > epsilon else b if broad_delta < -epsilon else "tie"
    focus_winner = a if focus_delta > epsilon else b if focus_delta < -epsilon else "tie"
    if broad_winner == focus_winner and broad_winner != "tie":
        return broad_winner, f"{broad_winner} wins both broad and focus resolver windows."
    if broad_winner == "tie" and focus_winner != "tie":
        return focus_winner, f"Broad is within epsilon; {focus_winner} wins focus."
    if focus_winner == "tie" and broad_winner != "tie":
        return broad_winner, f"Focus is within epsilon; {broad_winner} wins broad."
    combined_a = 0.55 * broad_a + 0.45 * focus_a
    combined_b = 0.55 * broad_b + 0.45 * focus_b
    if abs(combined_a - combined_b) <= epsilon:
        return "rerun", "Resolver remains inside epsilon; rerun at reset rather than promoting a flip."
    winner = a if combined_a > combined_b else b
    return winner, f"Resolver is split; combined broad/focus score favors {winner}."


def opponent_delta_table(a_rates: CandidateRates, b_rates: CandidateRates, a: str, b: str, top: int) -> list[str]:
    by_b = {row.opponent: row for row in b_rates.opponents}
    rows: list[tuple[float, OpponentRate, OpponentRate]] = []
    for a_row in a_rates.opponents:
        b_row = by_b.get(a_row.opponent)
        if b_row is not None:
            rows.append((abs(a_row.win_rate - b_row.win_rate) * a_row.weight, a_row, b_row))
    rows.sort(key=lambda item: item[0], reverse=True)
    lines = ["| Opponent | Weight | " + a + " | " + b + " | Delta | Teams |", "| --- | ---: | ---: | ---: | ---: | --- |"]
    for _, a_row, b_row in rows[:top]:
        lines.append(
            f"| `{a_row.opponent}` | {a_row.weight:.2f} | {a_row.win_rate:.4f} | "
            f"{b_row.win_rate:.4f} | {a_row.win_rate - b_row.win_rate:+.4f} | {a_row.teams or b_row.teams} |"
        )
    return lines


def render(args: argparse.Namespace) -> str:
    broad = parse_gauntlet(args.broad)
    focus = parse_gauntlet(args.focus)
    broad_a = get_candidate(broad, args.candidate_a)
    broad_b = get_candidate(broad, args.candidate_b)
    focus_a = get_candidate(focus, args.candidate_a)
    focus_b = get_candidate(focus, args.candidate_b)

    if broad_a.weighted_win_rate is None or broad_b.weighted_win_rate is None:
        raise ValueError("Broad gauntlet is missing weighted_win_rate")
    if focus_a.weighted_win_rate is None or focus_b.weighted_win_rate is None:
        raise ValueError("Focus gauntlet is missing weighted_win_rate")

    a = args.label_a or alias(args.candidate_a)
    b = args.label_b or alias(args.candidate_b)
    winner, reason = verdict(
        a,
        b,
        broad_a.weighted_win_rate,
        broad_b.weighted_win_rate,
        focus_a.weighted_win_rate,
        focus_b.weighted_win_rate,
        args.epsilon,
    )

    lines: list[str] = []
    lines.append("# Boundary Resolver Report")
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
    lines.append("- Strategy premise: no single deck is permanently strongest; resolver tests decide which policy fits the current pressure lanes.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Broad resolver: `{args.broad}`")
    lines.append(f"- Focus resolver: `{args.focus}`")
    if args.packet:
        lines.append(f"- Decision packet being checked: `{args.packet}`")
    lines.append(f"- Candidates: `{a}` vs `{b}`")
    lines.append(f"- Epsilon: {args.epsilon:.4f}")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append(f"- Resolver winner: **{winner}**")
    lines.append(f"- Reason: {reason}")
    lines.append("")
    lines.append("## Weighted Rates")
    lines.append("")
    lines.append("| Window | " + a + " | " + b + " | Delta |")
    lines.append("| --- | ---: | ---: | ---: |")
    lines.append(f"| Broad | {fmt(broad_a.weighted_win_rate)} | {fmt(broad_b.weighted_win_rate)} | {broad_a.weighted_win_rate - broad_b.weighted_win_rate:+.4f} |")
    lines.append(f"| Focus | {fmt(focus_a.weighted_win_rate)} | {fmt(focus_b.weighted_win_rate)} | {focus_a.weighted_win_rate - focus_b.weighted_win_rate:+.4f} |")
    lines.append("")
    lines.append("## Broad Opponent Deltas")
    lines.append("")
    lines.extend(opponent_delta_table(broad_a, broad_b, a, b, args.top))
    lines.append("")
    lines.append("## Focus Opponent Deltas")
    lines.append("")
    lines.extend(opponent_delta_table(focus_a, focus_b, a, b, args.top))
    lines.append("")
    lines.append("## Reset Guidance")
    lines.append("")
    lines.append("- Use this report only as a tie-breaker after the fresh reset packet is generated.")
    lines.append("- If the reset packet conflicts with this pre-reset report, rerun the resolver on the reset scout before submitting.")
    lines.append("- Prefer a candidate that wins both broad and focus; otherwise preserve latest-two diversity unless the split margin is large.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broad", required=True, type=Path)
    parser.add_argument("--focus", required=True, type=Path)
    parser.add_argument("--candidate-a", required=True)
    parser.add_argument("--candidate-b", required=True)
    parser.add_argument("--label-a")
    parser.add_argument("--label-b")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--epsilon", type=float, default=0.01)
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
