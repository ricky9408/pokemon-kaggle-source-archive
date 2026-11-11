#!/usr/bin/env python3
"""Report whether current leaderboard pressure is covered by ML replay data.

The replay-action models are only useful when their decision corpus represents
the live public board. This tool joins a leaderboard snapshot, a
``scout_top_replays.py`` download summary, a replay manifest, and a decision
JSONL file, then emits a coverage report for the current top window.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LeaderboardRow:
    rank: int
    team_id: str
    team: str
    score: float
    last_submission: str


@dataclass
class TeamCoverage:
    row: LeaderboardRow
    summary_rows: int = 0
    summary_submissions: set[str] = field(default_factory=set)
    summary_episodes: set[str] = field(default_factory=set)
    actions: Counter[str] = field(default_factory=Counter)
    existing_replay_files: int = 0
    manifest_episodes: set[str] = field(default_factory=set)
    decision_rows: int = 0
    main_decisions: int = 0
    decks: Counter[str] = field(default_factory=Counter)
    deck_examples: dict[str, str] = field(default_factory=dict)
    unmatched_manifest_episodes: int = 0

    @property
    def submission_count(self) -> int:
        return len(self.summary_submissions)

    @property
    def episode_count(self) -> int:
        return len(self.summary_episodes)

    @property
    def manifest_count(self) -> int:
        return len(self.manifest_episodes)

    @property
    def coverage_state(self) -> str:
        if self.summary_rows == 0:
            return "missing-scout"
        if self.existing_replay_files == 0:
            return "missing-replay-files"
        if self.manifest_count == 0:
            return "missing-manifest"
        if self.decision_rows == 0:
            return "missing-decisions"
        return "covered"


def norm_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def name_matches(left: str, right: str) -> bool:
    left_norm = norm_text(left)
    right_norm = norm_text(right)
    if not left_norm or not right_norm:
        return False
    return left_norm == right_norm or left_norm in right_norm or right_norm in left_norm


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_leaderboard(path: Path, limit: int) -> list[LeaderboardRow]:
    rows: list[LeaderboardRow] = []
    for raw in read_csv(path):
        try:
            rows.append(
                LeaderboardRow(
                    rank=int(raw.get("Rank", raw.get("PublicRank", "0"))),
                    team_id=raw.get("TeamId", ""),
                    team=raw.get("TeamName", ""),
                    score=float(raw.get("Score", "0") or 0),
                    last_submission=(raw.get("LastSubmissionDate", "") or "").split(".")[0],
                )
            )
        except ValueError:
            continue
    return sorted(rows, key=lambda row: row.rank)[:limit]


def read_manifest(path: Path) -> dict[str, dict[str, str]]:
    manifest: dict[str, dict[str, str]] = {}
    for row in read_csv(path):
        episode_id = row.get("episode_id", "")
        if episode_id:
            manifest[episode_id] = row
    return manifest


def iter_decisions(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def deck_for_team(row: LeaderboardRow, summary_team: str, manifest_row: dict[str, str]) -> tuple[str, bool]:
    candidates = [
        (manifest_row.get("team0", ""), manifest_row.get("deck0_archetype", ""), manifest_row.get("deck0_hash", "")),
        (manifest_row.get("team1", ""), manifest_row.get("deck1_archetype", ""), manifest_row.get("deck1_hash", "")),
    ]
    for team_name, archetype, deck_hash in candidates:
        if name_matches(team_name, row.team) or name_matches(team_name, summary_team):
            return f"{archetype}:{deck_hash}", True
    non_empty = [f"{archetype}:{deck_hash}" for _team, archetype, deck_hash in candidates if deck_hash]
    return " / ".join(non_empty) if non_empty else "unknown", False


def build_coverage(args: argparse.Namespace) -> list[TeamCoverage]:
    leaderboard = read_leaderboard(args.leaderboard, args.team_limit)
    coverages = {row.team_id: TeamCoverage(row=row) for row in leaderboard}

    summary_rows = read_csv(args.scout_summary)
    episode_to_team_ids: dict[str, set[str]] = defaultdict(set)
    episode_to_summary_team: dict[tuple[str, str], str] = {}
    for raw in summary_rows:
        team_id = raw.get("team_id", "")
        coverage = coverages.get(team_id)
        if coverage is None:
            continue
        episode_id = raw.get("episode_id", "")
        submission_id = raw.get("submission_id", "")
        coverage.summary_rows += 1
        if submission_id:
            coverage.summary_submissions.add(submission_id)
        if episode_id:
            coverage.summary_episodes.add(episode_id)
            episode_to_team_ids[episode_id].add(team_id)
            episode_to_summary_team[(episode_id, team_id)] = raw.get("team", "")
        coverage.actions[raw.get("action", "") or "unknown"] += 1
        path = Path(raw.get("path", ""))
        if path.exists() and path.is_file():
            coverage.existing_replay_files += 1

    manifest = read_manifest(args.manifest)
    decisions = iter_decisions(args.decisions)
    decisions_by_episode: dict[str, Counter[str]] = defaultdict(Counter)
    for row in decisions:
        episode_id = str(row.get("episode_id", ""))
        if not episode_id:
            continue
        decisions_by_episode[episode_id]["all"] += 1
        if row.get("context") == "MAIN":
            decisions_by_episode[episode_id]["MAIN"] += 1

    for team_id, coverage in coverages.items():
        for episode_id in coverage.summary_episodes:
            manifest_row = manifest.get(episode_id)
            if manifest_row is None:
                continue
            coverage.manifest_episodes.add(episode_id)
            summary_team = episode_to_summary_team.get((episode_id, team_id), "")
            deck, matched = deck_for_team(coverage.row, summary_team, manifest_row)
            coverage.decks[deck] += 1
            if deck not in coverage.deck_examples:
                coverage.deck_examples[deck] = episode_id
            if not matched:
                coverage.unmatched_manifest_episodes += 1
            counts = decisions_by_episode.get(episode_id, Counter())
            coverage.decision_rows += counts["all"]
            coverage.main_decisions += counts["MAIN"]

    return [coverages[row.team_id] for row in leaderboard]


def fmt_actions(actions: Counter[str]) -> str:
    return ", ".join(f"{key}:{value}" for key, value in actions.most_common()) or "-"


def fmt_decks(decks: Counter[str], examples: dict[str, str], limit: int) -> str:
    parts: list[str] = []
    for deck, count in decks.most_common(limit):
        example = examples.get(deck, "-")
        parts.append(f"{deck} x{count} e{example}")
    return "; ".join(parts) or "-"


def write_csv_report(path: Path, coverages: list[TeamCoverage], deck_limit: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "rank",
        "team_id",
        "team",
        "score",
        "last_submission",
        "coverage_state",
        "summary_rows",
        "submissions",
        "episodes",
        "existing_replay_files",
        "manifest_episodes",
        "decision_rows",
        "main_decisions",
        "actions",
        "unmatched_manifest_episodes",
        "top_decks",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for coverage in coverages:
            writer.writerow(
                {
                    "rank": coverage.row.rank,
                    "team_id": coverage.row.team_id,
                    "team": coverage.row.team,
                    "score": f"{coverage.row.score:.1f}",
                    "last_submission": coverage.row.last_submission,
                    "coverage_state": coverage.coverage_state,
                    "summary_rows": coverage.summary_rows,
                    "submissions": coverage.submission_count,
                    "episodes": coverage.episode_count,
                    "existing_replay_files": coverage.existing_replay_files,
                    "manifest_episodes": coverage.manifest_count,
                    "decision_rows": coverage.decision_rows,
                    "main_decisions": coverage.main_decisions,
                    "actions": fmt_actions(coverage.actions),
                    "unmatched_manifest_episodes": coverage.unmatched_manifest_episodes,
                    "top_decks": fmt_decks(coverage.decks, coverage.deck_examples, deck_limit),
                }
            )


def render_markdown(args: argparse.Namespace, coverages: list[TeamCoverage]) -> str:
    covered = sum(1 for item in coverages if item.coverage_state == "covered")
    missing = [item for item in coverages if item.coverage_state != "covered"]
    critical_missing = [item for item in missing if item.row.rank <= args.critical_team_limit]
    total_decisions = sum(item.decision_rows for item in coverages)
    total_main = sum(item.main_decisions for item in coverages)

    lines: list[str] = []
    lines.append("# ML Replay Coverage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', '')}")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Leaderboard: `{args.leaderboard}`")
    lines.append(f"- Scout summary: `{args.scout_summary}`")
    lines.append(f"- Manifest: `{args.manifest}`")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    if critical_missing:
        status = "stale-or-incomplete"
        action = "do not train or trust submit-facing selectors from this corpus until missing critical rows are scouted and rebuilt"
    elif missing:
        status = "usable-with-tail-gaps"
        action = "usable for strategy research, but rescout tail teams before reset-sensitive pair selection"
    else:
        status = "current-top-covered"
        action = "usable for public-action ML/RL research; still not a public-score submit selector"
    lines.append(f"- Coverage status: **{status}**")
    lines.append(f"- Covered current top-window teams: {covered}/{len(coverages)}")
    lines.append(f"- Current-window decision rows represented: {total_decisions} total / {total_main} MAIN")
    lines.append(f"- Required action: {action}.")
    lines.append("- Submit status: no submit-safe pair is implied by this report; public-score backtest/pre-submit gates still decide eligibility.")
    lines.append("")
    lines.append("## Team Coverage")
    lines.append("")
    lines.append(
        "| Rank | Team | Score | Last Submission | State | Episodes | Files | Manifest | MAIN Decisions | Actions | Top Decks |"
    )
    lines.append("| ---: | --- | ---: | --- | --- | ---: | ---: | ---: | ---: | --- | --- |")
    for item in coverages:
        lines.append(
            f"| {item.row.rank} | {item.row.team} | {item.row.score:.1f} | {item.row.last_submission or '-'} | "
            f"`{item.coverage_state}` | {item.episode_count} | {item.existing_replay_files} | "
            f"{item.manifest_count} | {item.main_decisions} | {fmt_actions(item.actions)} | "
            f"{fmt_decks(item.decks, item.deck_examples, args.deck_limit)} |"
        )
    lines.append("")
    if missing:
        lines.append("## Gaps")
        lines.append("")
        for item in missing:
            lines.append(
                f"- Rank {item.row.rank} `{item.row.team}`: {item.coverage_state}; "
                f"episodes={item.episode_count}, manifest={item.manifest_count}, decisions={item.decision_rows}."
            )
        lines.append("")
    lines.append("## Next Commands")
    lines.append("")
    lines.append("```bash")
    lines.append(
        "uv run python tools/scout_top_replays.py "
        f"--leaderboard {args.leaderboard} --output-dir scouting/live_top_<UTC>_ml_ingest "
        f"--team-limit {args.team_limit} --submissions-per-team 2 --episodes-per-submission 4"
    )
    lines.append(
        "uv run python tools/build_ml_replay_dataset.py scouting/live_top_<UTC>_ml_ingest/**/episode-*-replay.json "
        "--manifest-out strategy/ml_replay_manifest_<UTC>_ml_ingest.csv "
        "--decisions-out strategy/ml_decisions_<UTC>_ml_ingest.jsonl"
    )
    lines.append(
        "uv run python tools/ml_replay_coverage_report.py "
        f"--leaderboard {args.leaderboard} --scout-summary scouting/live_top_<UTC>_ml_ingest/download_summary.csv "
        "--manifest strategy/ml_replay_manifest_<UTC>_ml_ingest.csv "
        "--decisions strategy/ml_decisions_<UTC>_ml_ingest.jsonl "
        "--report-out strategy/ml_replay_coverage_<UTC>.md"
    )
    lines.append("```")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("- This is an intake and training-data freshness gate, not a win-rate metric.")
    lines.append("- It protects behavior cloning, conservative offline RL, and PSRO reports from silently training on stale top-window pressure.")
    lines.append("- Full-game local evaluator results remain fenced because replay-fidelity audits could not inject Kaggle public replay seeds.")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--scout-summary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/ml_replay_coverage.md"))
    parser.add_argument("--csv-out", type=Path, default=None)
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--critical-team-limit", type=int, default=10)
    parser.add_argument("--deck-limit", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    csv_out = args.csv_out or args.report_out.with_suffix(".csv")
    coverages = build_coverage(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_markdown(args, coverages), encoding="utf-8")
    write_csv_report(csv_out, coverages, args.deck_limit)
    covered = sum(1 for item in coverages if item.coverage_state == "covered")
    main_decisions = sum(item.main_decisions for item in coverages)
    print(f"covered={covered}/{len(coverages)} main_decisions={main_decisions} report={args.report_out} csv={csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
