#!/usr/bin/env python3
"""Generate an operational strategy playbook for the reset submission window.

This tool sits above the individual research reports. It turns the current
leaderboard, calibrated candidate ranking, and selected simulation files into a
single decision artifact that says what must be true before each candidate is
submitted.
"""

from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


TEAM_NAME = "GarlicToday"


@dataclass(frozen=True)
class LeaderboardRow:
    rank: int
    team: str
    score: float


@dataclass(frozen=True)
class CandidateEvidence:
    candidate: str
    path: str
    family: str
    kind: str
    replay_win_rate: str
    fixed_win_rate: str
    public_current: str
    public_best: str
    notes: str


@dataclass(frozen=True)
class CalibratedSingle:
    rank: int
    candidate: str
    score: float
    path: str
    family: str
    kind: str
    reasons: str


@dataclass(frozen=True)
class CalibratedPair:
    rank: int
    first_candidate: str
    second_candidate: str
    score: float
    first_path: str
    second_path: str
    reasons: str


def latest_leaderboard() -> Path:
    paths = glob.glob("leaderboard/current/pokemon-tcg-ai-battle-publicleaderboard-*.csv")
    if not paths:
        raise FileNotFoundError("No leaderboard CSV files found under leaderboard/current")
    return max((Path(path) for path in paths), key=leaderboard_timestamp)


def leaderboard_timestamp(path: Path) -> datetime:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)\.csv$", path.name)
    if match:
        date_part, time_part = match.group(1).split("T", 1)
        time_part = time_part.replace("-", ":")
        return datetime.fromisoformat(f"{date_part}T{time_part}").replace(tzinfo=timezone.utc)
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def load_leaderboard(path: Path) -> list[LeaderboardRow]:
    rows: list[LeaderboardRow] = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        for index, row in enumerate(csv.DictReader(file), start=1):
            team = row.get("teamName") or row.get("TeamName") or row.get("team_name") or ""
            raw_score = row.get("score") or row.get("Score") or row.get("publicScore") or "0"
            try:
                score = float(raw_score)
            except ValueError:
                score = 0.0
            rows.append(LeaderboardRow(rank=index, team=team, score=score))
    return rows


def load_candidates(path: Path) -> dict[str, CandidateEvidence]:
    candidates: dict[str, CandidateEvidence] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            evidence = CandidateEvidence(
                candidate=row["candidate"],
                path=row["path"],
                family=row["family"],
                kind=row["kind"],
                replay_win_rate=row.get("replay_win_rate", ""),
                fixed_win_rate=row.get("fixed_win_rate", ""),
                public_current=row.get("public_current", ""),
                public_best=row.get("public_best", ""),
                notes=row.get("notes", ""),
            )
            candidates[evidence.candidate] = evidence
    return candidates


def parse_calibration(path: Path) -> tuple[list[CalibratedSingle], list[CalibratedPair]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    singles: list[CalibratedSingle] = []
    pairs: list[CalibratedPair] = []
    mode: str | None = None
    single_fields: list[str] | None = None
    pair_fields: list[str] | None = None
    for line in lines:
        if line.startswith("rank,candidate,"):
            mode = "single"
            single_fields = line.split(",")
            continue
        if line.startswith("pair_rank,"):
            mode = "pair"
            pair_fields = line.split(",")
            continue
        if line.startswith("recommended_"):
            mode = None
            continue
        if mode == "single" and single_fields:
            row = dict(zip(single_fields, next(csv.reader([line]))))
            singles.append(
                CalibratedSingle(
                    rank=int(row["rank"]),
                    candidate=row["candidate"],
                    score=float(row["calibrated_score"]),
                    path=row["path"],
                    family=row["family"],
                    kind=row["kind"],
                    reasons=row["reasons"],
                )
            )
        elif mode == "pair" and pair_fields:
            row = dict(zip(pair_fields, next(csv.reader([line]))))
            pairs.append(
                CalibratedPair(
                    rank=int(row["pair_rank"]),
                    first_candidate=row["first_candidate"],
                    second_candidate=row["second_candidate"],
                    score=float(row["pair_score"]),
                    first_path=row["first_path"],
                    second_path=row["second_path"],
                    reasons=row["reasons"],
                )
            )
    return singles, pairs


def parse_weighted_rates(path: Path | None) -> dict[str, float]:
    if path is None or not path.exists():
        return {}
    rates: dict[str, float] = {}
    current: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("Candidate "):
            current = Path(line.removeprefix("Candidate ").strip()).name
            continue
        if current and line.startswith("weighted_win_rate,"):
            _, value = line.split(",", 1)
            rates[current] = float(value)
            current = None
    return rates


def fmt_score(value: str) -> str:
    return value if value else "-"


def top_table(rows: list[LeaderboardRow], count: int = 12) -> str:
    lines = ["| Rank | Team | Score |", "| ---: | --- | ---: |"]
    for row in rows[:count]:
        lines.append(f"| {row.rank} | {row.team} | {row.score:.1f} |")
    return "\n".join(lines)


def candidate_gate(candidate: CandidateEvidence, single: CalibratedSingle | None) -> list[str]:
    name = candidate.candidate
    gate = {
        "hiroingk-hammer-v57policy-v75": [
            "Role: first-slot anchor or challenger.",
            "Promote when the decision packet prefers its Alakazam-control focus enough to offset same-shell broad challengers.",
        ],
        "hiroingk-hammer-dunsparcefix-v82": [
            "Role: first-slot anchor or challenger.",
            "Promote when fresh broad confirmation and pair-aware calibration beat v75 by enough to offset weaker Alakazam-control focus.",
        ],
        "tubotu-plain-alakazam-v77": [
            "Role: second-slot diversity hedge.",
            "Promote when tubotu/plain Alakazam remains near the top window or pair-aware calibration keeps it as the best diversity partner.",
        ],
        "kadoraba-nighttime-hammer-v61": [
            "Role: second-slot fallback.",
            "Promote over v77 only if Kadoraba/Nighttime value recovers or tubotu/plain-Alakazam pressure fades.",
        ],
        "hiroingk-hammer-v72": [
            "Role: first-slot challenger with exact same hiroingk shell correlation.",
            "Promote over v75/v82 only if fresh evidence shows its same-shell edge survives both broad and control focus gates.",
        ],
        "aitoai-hammer-v73": [
            "Role: same-family fallback.",
            "Promote only if the fresh live edge is large enough to overcome correlation with v75.",
        ],
        "alakazam-hammer-mid-drawsoft-v68": [
            "Role: Battle Cage local-variant fallback.",
            "Promote only if fresh high-volume evidence and public-family prior both improve.",
        ],
        "alakazam-hammer-target-v53": [
            "Role: Battle Cage target-policy fallback.",
            "Promote only for a sharply Battle Cage-heavy window with confirmed public-family recovery.",
        ],
    }.get(
        name,
        [
            "Role: research or recovery reference.",
            "Do not submit unless fresh evidence explicitly promotes it through the calibrated gates.",
        ],
    )
    evidence = (
        f"Evidence: family={candidate.family}; kind={candidate.kind}; "
        f"replay={fmt_score(candidate.replay_win_rate)}; fixed={fmt_score(candidate.fixed_win_rate)}; "
        f"public_current={fmt_score(candidate.public_current)}; public_best={fmt_score(candidate.public_best)}."
    )
    if single is not None:
        evidence += f" Calibrated single rank {single.rank}, score {single.score:.4f}."
    return [*gate, evidence]


def build_report(args: argparse.Namespace) -> str:
    leaderboard_path = args.leaderboard or latest_leaderboard()
    leaderboard = load_leaderboard(leaderboard_path)
    team_row = next((row for row in leaderboard if row.team == TEAM_NAME), None)
    top10 = leaderboard[9] if len(leaderboard) >= 10 else None
    candidates = load_candidates(args.candidates)
    singles, pairs = parse_calibration(args.calibration)
    singles_by_name = {single.candidate: single for single in singles}
    rates = parse_weighted_rates(args.top_weight_confirmation)
    best_pair = pairs[0] if pairs else None
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# Current Strategy Playbook")
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
    lines.append("- Strategy premise: Pokemon TCG rewards type balance, but type edge must pass setup, timing, broad-meta, and public-prior gates.")
    lines.append("")
    lines.append("## Public Snapshot")
    lines.append("")
    lines.append(f"- Leaderboard source: `{leaderboard_path}`")
    if team_row:
        lines.append(f"- {TEAM_NAME}: rank {team_row.rank}, score {team_row.score:.1f}")
    if top10:
        lines.append(f"- Current top-10 cutoff: rank 10 {top10.team} at {top10.score:.1f}")
    lines.append("")
    lines.append(top_table(leaderboard))
    lines.append("")
    lines.append("## Current Strategic Read")
    lines.append("")
    lines.append("- The live ladder is still a three-axis game: Mega Lucario Fighting pressure, Alakazam control mirrors, and smaller tail decks.")
    lines.append("- Psychic Alakazam remains justified because Fighting pressure is large, but mirror tech and Dark weaknesses keep raw type advantage from being enough.")
    lines.append("- Battle Cage local variants are dangerous to over-trust because v39/v48 publicly missed after strong local screens.")
    lines.append("- Latest-two submissions should preserve family diversity unless a same-shell candidate has an overwhelming fresh edge.")
    lines.append("")
    lines.append("## Calibration")
    lines.append("")
    lines.append(f"- Calibration source: `{args.calibration}`")
    if best_pair:
        lines.append(
            f"- Recommended pair: `{best_pair.first_path}` then `{best_pair.second_path}` "
            f"(pair score {best_pair.score:.4f})."
        )
        lines.append(f"- Pair rationale: {best_pair.reasons}.")
    lines.append("")
    lines.append("| Rank | Candidate | Score | Family | Kind | Path |")
    lines.append("| ---: | --- | ---: | --- | --- | --- |")
    for single in singles[:8]:
        lines.append(
            f"| {single.rank} | `{single.candidate}` | {single.score:.4f} | "
            f"{single.family} | {single.kind} | `{single.path}` |"
        )
    lines.append("")
    if rates:
        lines.append("## Latest Top-Weight Simulation")
        lines.append("")
        lines.append(f"- Source: `{args.top_weight_confirmation}`")
        lines.append("")
        lines.append("| Candidate Agent | Weighted Win Rate |")
        lines.append("| --- | ---: |")
        for candidate, rate in sorted(rates.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| `{candidate}` | {rate:.4f} |")
        lines.append("")
    lines.append("## Candidate Gates")
    lines.append("")
    gate_order = [
        "hiroingk-hammer-dunsparcefix-v82",
        "hiroingk-hammer-v57policy-v75",
        "tubotu-plain-alakazam-v77",
        "kadoraba-nighttime-hammer-v61",
        "hiroingk-hammer-v72",
        "aitoai-hammer-v73",
        "alakazam-hammer-mid-drawsoft-v68",
        "alakazam-hammer-target-v53",
    ]
    for name in gate_order:
        candidate = candidates.get(name)
        if not candidate:
            continue
        lines.append(f"### `{name}`")
        lines.append("")
        for item in candidate_gate(candidate, singles_by_name.get(name)):
            lines.append(f"- {item}")
        lines.append("")
    lines.append("## Research-Only Branches")
    lines.append("")
    lines.append("- v78 Dark/Grimmsnarl theory failed broad execution and should stay rejected.")
    lines.append("- v79 Mega Absol Box failed the current pool and should stay rejected.")
    lines.append("- v80 Rocket Mewtwo/Spidops is a narrow Alakazam note, but too weak into Mega Lucario for the reset pair.")
    lines.append("")
    lines.append("## Pre-Reset Protocol")
    lines.append("")
    lines.append("1. Run `date -u` and confirm the UTC quota reset.")
    lines.append("2. Refresh submissions and leaderboard with `uv run kaggle ...` commands.")
    lines.append("3. Re-scout the current top window.")
    lines.append("4. Run broad quick and top-weight confirmation gauntlets.")
    lines.append("5. Rerun `tools/calibrated_candidate_rank.py` with the fresh cutoff.")
    lines.append("6. Submit only after quota is open and the candidate gates still agree.")
    lines.append("")
    lines.append("## Strategic Rule")
    lines.append("")
    lines.append("Beat the current public shape, not yesterday's local favorite. Type pressure starts the search; simulation, public priors, and latest-two diversity choose the submission pair.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path)
    parser.add_argument("--candidates", type=Path, default=Path("strategy/reset_candidates_20260620.csv"))
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--top-weight-confirmation", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report(args)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
