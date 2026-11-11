#!/usr/bin/env python3
"""Download public replays for the current top Kaggle teams.

This wraps the Kaggle CLI simulation helpers so top-ranker scouting is
repeatable instead of a pile of one-off shell snippets. It expects Kaggle CLI
auth to be available in the environment, for example via KAGGLE_API_TOKEN.

Typical use:

  uv run python tools/scout_top_replays.py \
    --leaderboard leaderboard/current/latest.csv \
    --team-limit 12 --episodes-per-submission 8
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_COMPETITION = "pokemon-tcg-ai-battle"


def leaderboard_timestamp(path: Path) -> datetime:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)\.csv$", path.name)
    if not match:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    stamp = match.group(1)
    date_part, time_part = stamp.split("T", 1)
    # Kaggle and local scripts have produced both HH:MM:SS and HH-MM-SS.
    time_part = time_part.replace("-", ":")
    return datetime.fromisoformat(f"{date_part}T{time_part}").replace(tzinfo=timezone.utc)


def latest_leaderboard() -> Path:
    files = list(Path("leaderboard/current").glob("*publicleaderboard*.csv"))
    if not files:
        raise FileNotFoundError("No leaderboard/current/*publicleaderboard*.csv files found")
    return max(files, key=leaderboard_timestamp)


def read_leaderboard(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise ValueError(f"{path} has no leaderboard rows")
    return rows


def rank_key(row: dict[str, str]) -> str:
    for key in row:
        if key.endswith("Rank") or key == "Rank":
            return key
    raise KeyError("Could not find Rank column")


def slug(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")
    return cleaned or "team"


def kaggle_command() -> list[str]:
    if shutil.which("uv"):
        return ["uv", "run", "kaggle"]
    return ["kaggle"]


def run_csv(args: list[str]) -> list[dict[str, str]]:
    command = kaggle_command() + args
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return []
    return list(csv.DictReader(lines))


def run_download(args: list[str]) -> None:
    subprocess.run(kaggle_command() + args, check=True)


def build_existing_replay_index(root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in root.glob("**/episode-*-replay.json"):
        parts = path.name.split("-")
        if len(parts) >= 3:
            index.setdefault(parts[1], path)
    return index


def public_completed_episodes(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row
        for row in rows
        if row.get("state") == "EpisodeState.COMPLETED"
        and row.get("type") == "EpisodeType.EPISODE_TYPE_PUBLIC"
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--leaderboard", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--episodes-per-submission", type=int, default=8)
    parser.add_argument("--submissions-per-team", type=int, default=2)
    parser.add_argument("--scouting-root", type=Path, default=Path("scouting"))
    parser.add_argument("--no-copy-known", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    leaderboard = args.leaderboard or latest_leaderboard()
    rows = read_leaderboard(leaderboard)
    rkey = rank_key(rows[0])
    rows.sort(key=lambda row: int(row[rkey]))
    selected = rows[: args.team_limit]

    if args.output_dir is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_dir = args.scouting_root / f"live_top_{stamp}"
    else:
        output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    existing = build_existing_replay_index(args.scouting_root)
    summary_rows: list[dict[str, str]] = []
    print(f"leaderboard,{leaderboard}")
    print(f"output_dir,{output_dir}")
    print("rank,team_id,team,score,submission_id,episode_id,action,path")

    for row in selected:
        team_rank = row[rkey]
        team_id = row["TeamId"]
        team_name = row["TeamName"]
        team_slug = slug(f"{int(team_rank):02d}_{team_name}_{team_id}")
        team_dir = output_dir / team_slug
        team_dir.mkdir(parents=True, exist_ok=True)

        submissions = run_csv(["competitions", "team-submissions", "-v", team_id])
        submissions = submissions[: args.submissions_per_team]
        submission_csv = team_dir / "team_submissions.csv"
        if submissions:
            with submission_csv.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=list(submissions[0].keys()))
                writer.writeheader()
                writer.writerows(submissions)
        else:
            submission_csv.write_text("id,dateSubmitted,publicScore\n")

        for submission in submissions:
            submission_id = submission["id"]
            submission_dir = team_dir / f"submission_{submission_id}"
            submission_dir.mkdir(parents=True, exist_ok=True)
            episode_rows = run_csv(["competitions", "episodes", "-v", submission_id])
            public_rows = public_completed_episodes(episode_rows)
            episode_csv = submission_dir / "episodes.csv"
            if episode_rows:
                with episode_csv.open("w", newline="") as file:
                    writer = csv.DictWriter(file, fieldnames=list(episode_rows[0].keys()))
                    writer.writeheader()
                    writer.writerows(episode_rows)
            else:
                episode_csv.write_text("id,createTime,endTime,state,type\n")

            for episode in public_rows[: args.episodes_per_submission]:
                episode_id = episode["id"]
                target = submission_dir / f"episode-{episode_id}-replay.json"
                action = "have"
                if target.exists():
                    pass
                elif not args.no_copy_known and episode_id in existing:
                    action = "copy"
                    if not args.dry_run:
                        shutil.copy2(existing[episode_id], target)
                else:
                    action = "download"
                    if not args.dry_run:
                        run_download(
                            [
                                "competitions",
                                "replay",
                                "-q",
                                "-p",
                                str(submission_dir),
                                episode_id,
                            ]
                        )
                path_text = str(target if target.exists() else submission_dir)
                print(
                    f"{team_rank},{team_id},{team_name},{row['Score']},"
                    f"{submission_id},{episode_id},{action},{path_text}"
                )
                summary_rows.append(
                    {
                        "rank": team_rank,
                        "team_id": team_id,
                        "team": team_name,
                        "score": row["Score"],
                        "submission_id": submission_id,
                        "episode_id": episode_id,
                        "action": action,
                        "path": path_text,
                    }
                )

    summary_path = output_dir / "download_summary.csv"
    with summary_path.open("w", newline="") as file:
        fieldnames = ["rank", "team_id", "team", "score", "submission_id", "episode_id", "action", "path"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)
    print(f"summary,{summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
