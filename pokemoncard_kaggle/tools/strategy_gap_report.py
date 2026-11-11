#!/usr/bin/env python3
"""Explain candidate matchup gaps from replay-pool gauntlet logs."""

from __future__ import annotations

import argparse
import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Matchup:
    opponent: str
    weight: float
    wins: int
    losses: int
    draws: int
    unfinished: int
    win_rate: float
    teams: str

    @property
    def weighted_loss(self) -> float:
        return self.weight * (1.0 - self.win_rate)


@dataclass
class Candidate:
    name: str
    matchups: dict[str, Matchup] = field(default_factory=dict)
    weighted_win_rate: float | None = None


def short_candidate(text: str) -> str:
    return Path(text.strip()).name


def parse_gauntlet(path: Path) -> dict[str, Candidate]:
    candidates: dict[str, Candidate] = {}
    current: Candidate | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            name = short_candidate(line.removeprefix("Candidate "))
            current = Candidate(name=name)
            candidates[name] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            current.weighted_win_rate = float(line.split(",", 1)[1])
            continue
        if line.startswith(("opponent,", "forward ", "swapped ", "skipped,")):
            continue
        parts = line.split(",")
        if len(parts) < 8:
            continue
        try:
            matchup = Matchup(
                opponent=parts[0],
                weight=float(parts[1]),
                wins=int(parts[2]),
                losses=int(parts[3]),
                draws=int(parts[4]),
                unfinished=int(parts[5]),
                win_rate=float(parts[6]),
                teams=",".join(parts[7:]),
            )
        except ValueError:
            continue
        current.matchups[matchup.opponent] = matchup
    return candidates


def pick_baseline(candidates: dict[str, Candidate], requested: str | None) -> Candidate | None:
    if requested:
        return candidates.get(requested)
    ranked = [candidate for candidate in candidates.values() if candidate.weighted_win_rate is not None]
    if not ranked:
        return None
    return max(ranked, key=lambda candidate: candidate.weighted_win_rate or -1.0)


def format_rate(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def build_report(path: Path, baseline_name: str | None, output: Path | None) -> str:
    candidates = parse_gauntlet(path)
    baseline = pick_baseline(candidates, baseline_name)
    ranked = sorted(
        candidates.values(),
        key=lambda candidate: (candidate.weighted_win_rate is not None, candidate.weighted_win_rate or -1.0),
        reverse=True,
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Strategy Gap Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: matchup gaps identify policy/deck architecture priorities after type pressure has selected candidate branches.")
    lines.append("")
    lines.append("## Source")
    lines.append("")
    lines.append(f"- Gauntlet log: `{path}`")
    if baseline:
        lines.append(f"- Baseline for deltas: `{baseline.name}`")
    lines.append("")
    lines.append("## Candidate Ranking")
    lines.append("")
    lines.append("| Rank | Candidate | Weighted Win Rate | Worst Weighted Loss | Worst Matchup |")
    lines.append("| ---: | --- | ---: | ---: | --- |")
    for index, candidate in enumerate(ranked, start=1):
        worst = max(candidate.matchups.values(), key=lambda item: item.weighted_loss, default=None)
        worst_loss = "-" if worst is None else f"{worst.weighted_loss:.2f}"
        worst_opponent = "-" if worst is None else worst.opponent
        lines.append(
            f"| {index} | `{candidate.name}` | {format_rate(candidate.weighted_win_rate)} | "
            f"{worst_loss} | `{worst_opponent}` |"
        )
    lines.append("")

    if baseline:
        lines.append("## Delta Versus Baseline")
        lines.append("")
        lines.append("| Candidate | Weighted Delta | Largest Matchup Deficit | Largest Matchup Advantage |")
        lines.append("| --- | ---: | --- | --- |")
        for candidate in ranked:
            if candidate.name == baseline.name or candidate.weighted_win_rate is None or baseline.weighted_win_rate is None:
                continue
            common = set(candidate.matchups) & set(baseline.matchups)
            deficits: list[tuple[float, str]] = []
            advantages: list[tuple[float, str]] = []
            for key in common:
                delta = candidate.matchups[key].win_rate - baseline.matchups[key].win_rate
                weighted = delta * candidate.matchups[key].weight
                if weighted < 0:
                    deficits.append((weighted, key))
                elif weighted > 0:
                    advantages.append((weighted, key))
            worst = min(deficits, default=(0.0, "-"))
            best = max(advantages, default=(0.0, "-"))
            weighted_delta = candidate.weighted_win_rate - baseline.weighted_win_rate
            lines.append(
                f"| `{candidate.name}` | {weighted_delta:+.4f} | "
                f"`{worst[1]}` ({worst[0]:+.2f}) | `{best[1]}` ({best[0]:+.2f}) |"
            )
        lines.append("")

    lines.append("## Candidate Stress Points")
    lines.append("")
    for candidate in ranked:
        lines.append(f"### `{candidate.name}`")
        lines.append("")
        lines.append(f"- Weighted win rate: {format_rate(candidate.weighted_win_rate)}")
        lines.append("- Worst weighted-loss matchups:")
        for matchup in sorted(candidate.matchups.values(), key=lambda item: item.weighted_loss, reverse=True)[:5]:
            lines.append(
                f"  - `{matchup.opponent}`: win_rate={matchup.win_rate:.4f}, "
                f"weight={matchup.weight:.2f}, weighted_loss={matchup.weighted_loss:.2f}, teams={matchup.teams}"
            )
        lines.append("- Strongest high-weight matchups:")
        for matchup in sorted(candidate.matchups.values(), key=lambda item: (item.win_rate, item.weight), reverse=True)[:5]:
            lines.append(
                f"  - `{matchup.opponent}`: win_rate={matchup.win_rate:.4f}, weight={matchup.weight:.2f}, teams={matchup.teams}"
            )
        lines.append("")

    lines.append("## Strategic Interpretation")
    lines.append("")
    lines.append("- Treat a high weighted win rate as submit evidence only when the stress points are acceptable in the live public window.")
    lines.append("- If a candidate beats Lucario but collapses in Alakazam mirrors, use it as a same-shell or focused fallback rather than a diversity second slot.")
    lines.append("- If a candidate is weaker on raw rate but covers a different family with acceptable stress points, keep it in latest-two consideration.")
    report = "\n".join(lines) + "\n"
    if output:
        output.write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("gauntlet", type=Path)
    parser.add_argument("--baseline")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    print(build_report(args.gauntlet, args.baseline, args.output), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
