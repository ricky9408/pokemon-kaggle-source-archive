#!/usr/bin/env python3
"""Prioritize strategy experiments from current gauntlet blind spots.

This sits between raw matchup reports and agent edits. It asks: given the
current intended latest-two pair, which opponent families still create the most
weighted loss, and which candidate or strategy branch is the best lead for
closing that gap?
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class CandidateMeta:
    alias: str
    candidate: str
    path: str
    family: str
    kind: str
    notes: str


@dataclass(frozen=True)
class Matchup:
    opponent: str
    family: str
    weight: float
    win_rate: float
    teams: str

    @property
    def weighted_loss(self) -> float:
        return self.weight * (1.0 - self.win_rate)


@dataclass
class CandidateResult:
    alias: str
    label: str
    weighted: float | None = None
    matchups: dict[str, Matchup] = field(default_factory=dict)


@dataclass(frozen=True)
class Window:
    label: str
    path: Path
    candidates: dict[str, CandidateResult]


def alias_from_text(text: str) -> str:
    name = Path(text.strip()).name
    match = re.search(r"(?:^|[_-])v(\d+)(?:$|[_-])", name.lower())
    if match:
        return f"v{match.group(1)}"
    return name


def alias_from_candidate(candidate: str) -> str:
    match = re.search(r"(?:^|-)v(\d+)(?:$|-)", candidate.lower())
    if match:
        return f"v{match.group(1)}"
    return candidate


def parse_optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_candidate_meta(path: Path) -> dict[str, CandidateMeta]:
    metas: dict[str, CandidateMeta] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            candidate = row.get("candidate", "")
            if not candidate:
                continue
            alias = alias_from_candidate(candidate)
            metas[alias] = CandidateMeta(
                alias=alias,
                candidate=candidate,
                path=row.get("path", ""),
                family=row.get("family", ""),
                kind=row.get("kind", ""),
                notes=row.get("notes", ""),
            )
    return metas


def parse_gauntlet(path: Path, label: str) -> Window:
    candidates: dict[str, CandidateResult] = {}
    current: CandidateResult | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            candidate_label = Path(line.removeprefix("Candidate ").strip()).name
            alias = alias_from_text(candidate_label)
            current = CandidateResult(alias=alias, label=candidate_label)
            candidates[alias] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            current.weighted = parse_optional_float(line.split(",", 1)[1])
            continue
        if line.startswith(("opponent,", "opponent_pool", "archetype,", "skipped,")):
            continue
        fields = next(csv.reader([line]))
        if len(fields) < 8 or ":" not in fields[0]:
            continue
        try:
            opponent = fields[0]
            current.matchups[opponent] = Matchup(
                opponent=opponent,
                family=opponent.split(":", 1)[0],
                weight=float(fields[1]),
                win_rate=float(fields[6]),
                teams=",".join(fields[7:]),
            )
        except ValueError:
            continue
    return Window(label=label, path=path, candidates=candidates)


def parse_window_arg(value: str) -> tuple[str, Path]:
    if ":" not in value:
        path = Path(value)
        return path.stem, path
    label, path = value.split(":", 1)
    return label, Path(path)


def public_risk(meta: CandidateMeta | None) -> tuple[int, str]:
    if meta is None:
        return 1, "unknown metadata"
    reasons: list[str] = []
    risk = 0
    if meta.kind == "local-variant":
        risk += 2
        reasons.append("local variant")
    if meta.family == "alakazam_battle_cage":
        risk += 2
        reasons.append("Battle Cage public-miss family")
    if meta.kind == "submitted":
        risk += 1
        reasons.append("already submitted public test")
    if "public" in meta.kind and "recovery" in meta.kind:
        risk -= 1
        reasons.append("public recovery reference")
    if not reasons:
        reasons.append("public risk acceptable")
    return max(0, risk), "; ".join(reasons)


def format_rate(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def pair_matchup(window: Window, left: str, right: str, opponent: str) -> tuple[float, float, float, str]:
    left_result = window.candidates.get(left)
    right_result = window.candidates.get(right)
    left_rate = left_result.matchups[opponent].win_rate if left_result and opponent in left_result.matchups else 0.0
    right_rate = right_result.matchups[opponent].win_rate if right_result and opponent in right_result.matchups else 0.0
    matchup = None
    if left_result and opponent in left_result.matchups:
        matchup = left_result.matchups[opponent]
    elif right_result and opponent in right_result.matchups:
        matchup = right_result.matchups[opponent]
    weight = matchup.weight if matchup else 0.0
    teams = matchup.teams if matchup else ""
    return left_rate, right_rate, weight, teams


def best_alternative(window: Window, opponent: str, excluded: set[str]) -> tuple[str, float] | None:
    best: tuple[str, float] | None = None
    for alias, candidate in window.candidates.items():
        if alias in excluded or opponent not in candidate.matchups:
            continue
        rate = candidate.matchups[opponent].win_rate
        if best is None or rate > best[1]:
            best = (alias, rate)
    return best


def render(args: argparse.Namespace) -> str:
    metas = load_candidate_meta(args.candidates)
    windows = [parse_gauntlet(path, label) for label, path in (parse_window_arg(item) for item in args.window)]
    pair = (args.pair[0], args.pair[1])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows: list[tuple[float, str, str, float, float, float, str, tuple[str, float] | None]] = []
    family_loss: dict[str, float] = {}
    for window in windows:
        opponents = set()
        for alias in pair:
            if alias in window.candidates:
                opponents.update(window.candidates[alias].matchups)
        for opponent in sorted(opponents):
            left_rate, right_rate, weight, teams = pair_matchup(window, pair[0], pair[1], opponent)
            pair_rate = max(left_rate, right_rate)
            weighted_loss = weight * (1.0 - pair_rate)
            if weighted_loss <= 0:
                continue
            family = opponent.split(":", 1)[0]
            family_loss[family] = family_loss.get(family, 0.0) + weighted_loss
            alternative = best_alternative(window, opponent, set(pair))
            rows.append((weighted_loss, window.label, opponent, left_rate, right_rate, weight, teams, alternative))
    rows.sort(key=lambda item: (-item[0], item[1], item[2]))

    lines: list[str] = []
    lines.append("# Strategy Blindspot Backlog")
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
    lines.append("- Strategy premise: Pokemon TCG has no single strongest deck; prioritize experiments that close shared type/family blind spots without losing broad meta coverage.")
    lines.append("")

    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Intended pair: `{pair[0]}` + `{pair[1]}`")
    for window in windows:
        lines.append(f"- `{window.label}`: `{window.path}`")
    lines.append(f"- Candidate metadata: `{args.candidates}`")
    lines.append("")

    lines.append("## Pair Blindspots")
    lines.append("")
    lines.append("| Rank | Window | Opponent | Weight | Pair Rates | Weighted Loss | Best Non-Pair Lead | Teams |")
    lines.append("| ---: | --- | --- | ---: | --- | ---: | --- | --- |")
    for index, (weighted_loss, label, opponent, left_rate, right_rate, weight, teams, alternative) in enumerate(rows[: args.limit], 1):
        pair_rate = max(left_rate, right_rate)
        alt_text = "-"
        if alternative is not None:
            alias, rate = alternative
            meta = metas.get(alias)
            risk, risk_text = public_risk(meta)
            if rate > pair_rate + args.lead_margin:
                alt_text = f"`{alias}` {rate:.3f} ({risk_text}, risk {risk})"
            else:
                alt_text = f"no better current lead; best non-pair `{alias}` {rate:.3f}"
        lines.append(
            f"| {index} | {label} | `{opponent}` | {weight:.2f} | "
            f"`{pair[0]}` {left_rate:.3f}; `{pair[1]}` {right_rate:.3f} | "
            f"{weighted_loss:.2f} | {alt_text} | {teams} |"
        )
    lines.append("")

    lines.append("## Family Priorities")
    lines.append("")
    lines.append("| Rank | Family | Accumulated Pair Weighted Loss | Strategic Direction |")
    lines.append("| ---: | --- | ---: | --- |")
    for index, (family, loss) in enumerate(sorted(family_loss.items(), key=lambda item: (-item[1], item[0]))[:8], 1):
        direction = "policy timing/search priority"
        if family == "alakazam_battle_cage":
            direction = "Battle Cage mirror plan; bench protection and damage-counter routing"
        elif family == "alakazam_hammer":
            direction = "Hammer mirror discipline; disruption timing and recovery sequencing"
        elif family == "mega_lucario":
            direction = "preserve Psychic pressure while avoiding over-teching"
        elif family == "alakazam_nighttime_hammer":
            direction = "Nighttime/energy-denial mirror sequencing"
        lines.append(f"| {index} | `{family}` | {loss:.2f} | {direction} |")
    lines.append("")

    lines.append("## Experiment Backlog")
    lines.append("")
    sorted_families = sorted(family_loss.items(), key=lambda item: (-item[1], item[0]))
    if sorted_families:
        top_family = sorted_families[0][0]
        lines.append(
            f"1. First experiment: improve `{pair[0]}` against `{top_family}` without changing deck family; "
            "this is a policy/search-priority experiment, not a new-deck experiment yet."
        )
    lines.append(
        "2. Keep the second slot diverse unless a same-family alternative beats the intended pair across broad, control, and boundary windows."
    )
    lines.append(
        "3. Treat local Battle Cage variants as probes until public-family evidence improves; v39/v48 public misses remain a real prior."
    )
    lines.append(
        "4. Re-run this backlog after any fresh scout or immediate pre-reset gauntlet so the next edit targets the current ladder, not stale pressure."
    )
    lines.append("")

    lines.append("## Candidate Risk Notes")
    lines.append("")
    for alias in sorted(metas):
        risk, risk_text = public_risk(metas[alias])
        lines.append(f"- `{alias}` `{metas[alias].candidate}`: {risk_text} (risk {risk}).")

    report = "\n".join(lines) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--window", action="append", required=True, help="label:path gauntlet log")
    parser.add_argument("--pair", action="append", required=True, help="Candidate alias, e.g. v75. Provide exactly two.")
    parser.add_argument("--candidates", type=Path, default=Path("strategy/reset_candidates_20260620.csv"))
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--lead-margin", type=float, default=0.02)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if len(args.pair) != 2:
        parser.error("--pair must be supplied exactly twice")
    print(render(args), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
