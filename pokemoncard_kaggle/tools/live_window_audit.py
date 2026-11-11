#!/usr/bin/env python3
"""Audit whether a fresh leaderboard needs a new replay scout.

The reset-window bottleneck is usually not simulation itself; it is deciding
whether a leaderboard twitch invalidates the current public-replay pool. This
tool compares a leaderboard snapshot with an existing ``scout_top_replays.py``
output directory and classifies the next action as:

* ``reuse-existing``: no material top-window change.
* ``reweight-existing``: same teams/submissions are covered, but ranks/scores
  moved enough that reports and decision packets should be regenerated.
* ``rescout``: a top-window team or active submission is missing from the scout.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class LeaderboardTeam:
    rank: int
    team_id: str
    team: str
    score: float
    last_submission: str


@dataclass
class ScoutTeam:
    team_id: str
    team: str
    rank: int
    score: float
    submissions: set[str]


def leaderboard_timestamp(path: Path) -> datetime:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)\.csv$", path.name)
    if match:
        date_part, time_part = match.group(1).split("T", 1)
        return datetime.fromisoformat(f"{date_part}T{time_part.replace('-', ':')}").replace(tzinfo=timezone.utc)
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def latest_leaderboard(root: Path = Path("leaderboard/current")) -> Path:
    files = list(root.glob("*publicleaderboard*.csv"))
    if not files:
        raise FileNotFoundError(f"No leaderboard CSVs found under {root}")
    return max(files, key=leaderboard_timestamp)


def latest_scout(root: Path = Path("scouting")) -> Path:
    candidates = [path for path in root.glob("live_top_*") if (path / "download_summary.csv").exists()]
    if not candidates:
        raise FileNotFoundError(f"No scout directories with download_summary.csv found under {root}")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def norm_date(value: str) -> str:
    value = value.strip().strip('"')
    if not value:
        return ""
    # Leaderboard CSVs omit microseconds while team-submissions include them.
    return value.split(".")[0]


def read_leaderboard(path: Path) -> list[LeaderboardTeam]:
    teams: list[LeaderboardTeam] = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            try:
                teams.append(
                    LeaderboardTeam(
                        rank=int(row["Rank"]),
                        team_id=row["TeamId"],
                        team=row["TeamName"],
                        score=float(row["Score"]),
                        last_submission=norm_date(row.get("LastSubmissionDate", "")),
                    )
                )
            except (KeyError, ValueError):
                continue
    return sorted(teams, key=lambda team: team.rank)


def read_scout(path: Path) -> dict[str, ScoutTeam]:
    summary = path / "download_summary.csv"
    teams: dict[str, ScoutTeam] = {}
    with summary.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            team_id = row.get("team_id", "")
            if not team_id:
                continue
            try:
                rank = int(row["rank"])
                score = float(row["score"])
            except (KeyError, ValueError):
                continue
            current = teams.get(team_id)
            if current is None:
                teams[team_id] = ScoutTeam(
                    team_id=team_id,
                    team=row.get("team", ""),
                    rank=rank,
                    score=score,
                    submissions=set(),
                )
            else:
                current.rank = min(current.rank, rank)
                current.score = max(current.score, score)

    for team_dir in path.iterdir():
        if not team_dir.is_dir():
            continue
        match = re.search(r"_(\d+)$", team_dir.name)
        if not match:
            continue
        team_id = match.group(1)
        team = teams.get(team_id)
        if team is None:
            continue
        submission_csv = team_dir / "team_submissions.csv"
        if not submission_csv.exists():
            continue
        with submission_csv.open(encoding="utf-8-sig", newline="") as file:
            for row in csv.DictReader(file):
                date = norm_date(row.get("dateSubmitted", ""))
                if date:
                    team.submissions.add(date)
    return teams


def score_delta(current: float, previous: float) -> float:
    return round(current - previous, 4)


def format_delta(value: float) -> str:
    if value > 0:
        return f"+{value:.1f}"
    return f"{value:.1f}"


def render(args: argparse.Namespace) -> str:
    leaderboard = args.leaderboard or latest_leaderboard()
    scout_dir = args.scout_dir or latest_scout()
    leaderboard_rows = read_leaderboard(leaderboard)
    scout_rows = read_scout(scout_dir)

    selected = leaderboard_rows[: args.team_limit]
    critical = leaderboard_rows[: args.critical_team_limit]
    current_ids = {row.team_id for row in selected}
    critical_ids = {row.team_id for row in critical}
    scout_ids = set(scout_rows)

    missing = [row for row in selected if row.team_id not in scout_ids]
    missing_critical = [row for row in critical if row.team_id not in scout_ids]
    submission_misses = [
        row
        for row in selected
        if row.team_id in scout_rows
        and row.last_submission
        and row.last_submission not in scout_rows[row.team_id].submissions
    ]
    crossed_into_critical = [
        row
        for row in critical
        if row.team_id in scout_rows and scout_rows[row.team_id].rank > args.critical_team_limit
    ]
    rank_shifts = [
        (row, scout_rows[row.team_id].rank, row.rank - scout_rows[row.team_id].rank)
        for row in selected
        if row.team_id in scout_rows and abs(row.rank - scout_rows[row.team_id].rank) >= args.rank_delta_threshold
    ]
    score_shifts = [
        (row, scout_rows[row.team_id].score, score_delta(row.score, scout_rows[row.team_id].score))
        for row in selected
        if row.team_id in scout_rows and abs(score_delta(row.score, scout_rows[row.team_id].score)) >= args.score_delta_threshold
    ]

    if missing_critical or submission_misses:
        action = "rescout"
        reason = "a critical top-window team or active submission is missing from the scout"
    elif missing:
        action = "rescout"
        reason = "a selected top-window team is missing from the scout"
    elif crossed_into_critical or rank_shifts or score_shifts:
        action = "reweight-existing"
        reason = "the existing episodes cover the teams, but ranks/scores changed enough to refresh weighting and reports"
    else:
        action = "reuse-existing"
        reason = "the existing scout still covers the live top-window without material rank or score drift"

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Live Top-Window Scout Audit")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategic premise: type balance identifies pressure axes; this audit decides whether public replay evidence is still fresh enough to support strategic simulation.")
    lines.append("")
    lines.append("## Decision")
    lines.append("")
    lines.append(f"- Recommended action: **{action}**")
    lines.append(f"- Reason: {reason}.")
    lines.append(f"- Leaderboard source: `{leaderboard}`")
    lines.append(f"- Scout source: `{scout_dir}`")
    lines.append(f"- Current top-{args.critical_team_limit} cutoff: rank {critical[-1].rank} {critical[-1].team} at {critical[-1].score:.1f}")
    lines.append("")

    lines.append("## Material Changes")
    lines.append("")
    if missing:
        lines.append("- Missing selected teams: " + ", ".join(f"{row.rank} {row.team}" for row in missing))
    else:
        lines.append("- Missing selected teams: none")
    if submission_misses:
        lines.append(
            "- Missing active submission timestamps: "
            + ", ".join(f"{row.rank} {row.team} ({row.last_submission})" for row in submission_misses)
        )
    else:
        lines.append("- Missing active submission timestamps: none")
    if crossed_into_critical:
        lines.append(
            f"- Teams crossing into top {args.critical_team_limit} from outside prior scout-critical window: "
            + ", ".join(
                f"{row.team} scout-rank {scout_rows[row.team_id].rank} -> current-rank {row.rank}"
                for row in crossed_into_critical
            )
        )
    else:
        lines.append(f"- Teams crossing into top {args.critical_team_limit}: none")
    if rank_shifts:
        lines.append(
            "- Rank shifts above threshold: "
            + ", ".join(f"{row.team} {old_rank}->{row.rank}" for row, old_rank, _ in rank_shifts)
        )
    else:
        lines.append("- Rank shifts above threshold: none")
    if score_shifts:
        lines.append(
            "- Score shifts above threshold: "
            + ", ".join(f"{row.team} {old_score:.1f}->{row.score:.1f} ({format_delta(delta)})" for row, old_score, delta in score_shifts)
        )
    else:
        lines.append("- Score shifts above threshold: none")
    lines.append("")

    lines.append("## Current Window Coverage")
    lines.append("")
    lines.append("| Current Rank | Team | Score | Last Submission | Scout Rank | Scout Score | Scout Has Submission | Coverage |")
    lines.append("| ---: | --- | ---: | --- | ---: | ---: | --- | --- |")
    for row in selected:
        scout = scout_rows.get(row.team_id)
        if scout is None:
            lines.append(
                f"| {row.rank} | {row.team} | {row.score:.1f} | {row.last_submission or '-'} | - | - | no | missing |"
            )
            continue
        has_submission = "yes" if not row.last_submission or row.last_submission in scout.submissions else "no"
        coverage = "critical" if row.team_id in critical_ids else "selected"
        lines.append(
            f"| {row.rank} | {row.team} | {row.score:.1f} | {row.last_submission or '-'} | "
            f"{scout.rank} | {scout.score:.1f} | {has_submission} | {coverage} |"
        )
    lines.append("")

    lines.append("## Next-Step Policy")
    lines.append("")
    lines.append("- `reuse-existing`: keep the current scout and current simulations unless the submit window opens.")
    lines.append("- `reweight-existing`: regenerate reports/decision packets against the latest leaderboard; re-scout only if the pre-reset window is close enough that rank-crossing teams need more public episodes.")
    lines.append("- `rescout`: run `tools/scout_top_replays.py` before trusting local gauntlets or submitting.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path)
    parser.add_argument("--scout-dir", type=Path)
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--critical-team-limit", type=int, default=10)
    parser.add_argument("--rank-delta-threshold", type=int, default=2)
    parser.add_argument("--score-delta-threshold", type=float, default=8.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
