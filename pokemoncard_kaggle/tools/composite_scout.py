#!/usr/bin/env python3
"""Build a current-leaderboard scout from multiple cached scout directories.

Leaderboard ranks near the top-window edge can oscillate faster than fresh
episode scouting is useful. This tool unions recent scout directories, selects
current leaderboard teams from cached evidence, rewrites rank/score/path
metadata, and emits a normal scout directory for downstream strategy tools.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
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
class SourceTeam:
    source: Path
    directory: Path
    summary_rows: list[dict[str, str]]


def norm_date(value: str) -> str:
    value = value.strip().strip('"')
    return value.split(".")[0] if value else ""


def read_leaderboard(path: Path) -> list[LeaderboardTeam]:
    rows: list[LeaderboardTeam] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for raw in csv.DictReader(handle):
            team_id = raw.get("TeamId", "")
            if not team_id:
                continue
            try:
                rows.append(
                    LeaderboardTeam(
                        rank=int(raw["Rank"]),
                        team_id=team_id,
                        team=raw.get("TeamName", ""),
                        score=float(raw.get("Score", "0")),
                        last_submission=norm_date(raw.get("LastSubmissionDate", "")),
                    )
                )
            except ValueError:
                continue
    return sorted(rows, key=lambda row: row.rank)


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return value or "team"


def team_dirs(source: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for child in source.iterdir():
        if not child.is_dir():
            continue
        match = re.search(r"_(\d+)$", child.name)
        if match:
            result[match.group(1)] = child
    return result


def read_summary(source: Path) -> tuple[list[str], dict[str, list[dict[str, str]]]]:
    path = source / "download_summary.csv"
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    by_team: dict[str, list[dict[str, str]]] = {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        for row in reader:
            team_id = row.get("team_id", "")
            if team_id:
                by_team.setdefault(team_id, []).append(dict(row))
    return fieldnames, by_team


def collect_sources(sources: list[Path]) -> tuple[list[str], dict[str, list[SourceTeam]]]:
    fieldnames: list[str] = []
    result: dict[str, list[SourceTeam]] = {}
    for source in sources:
        current_fieldnames, rows_by_team = read_summary(source)
        if not fieldnames:
            fieldnames = current_fieldnames
        directories = team_dirs(source)
        for team_id, rows in rows_by_team.items():
            directory = directories.get(team_id)
            if directory is None:
                continue
            result.setdefault(team_id, []).append(SourceTeam(source=source, directory=directory, summary_rows=rows))
    if not fieldnames:
        raise ValueError("No download_summary.csv fields found")
    return fieldnames, result


def link_or_copy_file(source: Path, output: Path, mode: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if mode == "copy":
        shutil.copy2(source, output)
        return
    if mode == "symlink":
        output.symlink_to(os.path.relpath(source, output.parent))
        return
    if mode == "hardlink":
        try:
            os.link(source, output)
        except OSError:
            shutil.copy2(source, output)
        return
    raise ValueError(f"Unknown mode: {mode}")


def clone_team_dir(source_dir: Path, output_dir: Path, mode: str) -> None:
    for source in sorted(source_dir.rglob("*")):
        rel = source.relative_to(source_dir)
        dest = output_dir / rel
        if source.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        else:
            link_or_copy_file(source, dest, mode)


def remap_path(row: dict[str, str], source_team: SourceTeam, output_team_dir: Path) -> str:
    path_value = row.get("path", "")
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        rel = path.relative_to(source_team.directory)
        return str(output_team_dir / rel)
    except ValueError:
        pass
    try:
        rel = path.relative_to(source_team.source)
        team_rel = Path(*rel.parts[1:]) if len(rel.parts) > 1 else Path(path.name)
        return str(output_team_dir / team_rel)
    except ValueError:
        return str(output_team_dir / path.name)


def choose_source(candidates: list[SourceTeam]) -> SourceTeam:
    def key(item: SourceTeam) -> tuple[int, float]:
        replay_count = sum(1 for _ in item.directory.glob("**/episode-*-replay.json"))
        return replay_count, item.source.stat().st_mtime

    return max(candidates, key=key)


def write_summary(
    output: Path,
    fieldnames: list[str],
    selected: list[LeaderboardTeam],
    source_by_team: dict[str, SourceTeam],
    output_dir_by_team: dict[str, Path],
) -> tuple[int, int]:
    rows: list[dict[str, str]] = []
    covered = 0
    missing = 0
    seen: set[tuple[str, str, str]] = set()
    for team in selected:
        source_team = source_by_team.get(team.team_id)
        output_dir = output_dir_by_team.get(team.team_id)
        if source_team is None or output_dir is None:
            missing += 1
            continue
        covered += 1
        for row in source_team.summary_rows:
            key = (row.get("team_id", ""), row.get("submission_id", ""), row.get("episode_id", ""))
            if key in seen:
                continue
            seen.add(key)
            new_row = dict(row)
            new_row["rank"] = str(team.rank)
            new_row["team"] = team.team
            new_row["score"] = f"{team.score:.1f}"
            new_row["path"] = remap_path(row, source_team, output_dir)
            if "action" in new_row:
                new_row["action"] = f"composite:{source_team.source.name}"
            rows.append(new_row)

    with (output / "download_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return covered, missing


def render_manifest(
    args: argparse.Namespace,
    selected: list[LeaderboardTeam],
    source_by_team: dict[str, SourceTeam],
    output_dir_by_team: dict[str, Path],
    covered: int,
    missing: int,
) -> str:
    lines: list[str] = []
    lines.append("# Composite Scout Manifest")
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
    lines.append("- Strategy premise: type balance changes the useful pressure lanes; cached scout evidence should be unioned before re-downloading edge-rank teams.")
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append(f"- Leaderboard: `{args.leaderboard}`")
    lines.append(f"- Output scout: `{args.output}`")
    for source in args.source:
        lines.append(f"- Source scout: `{source}`")
    lines.append(f"- File mode: `{args.mode}`")
    lines.append(f"- Team limit: {args.team_limit}")
    lines.append(f"- Covered teams: {covered}")
    lines.append(f"- Missing teams: {missing}")
    lines.append("")
    lines.append("## Current Window Coverage")
    lines.append("")
    lines.append("| Rank | Team | Score | Last Submission | Source | Output Directory |")
    lines.append("| ---: | --- | ---: | --- | --- | --- |")
    for team in selected:
        source_team = source_by_team.get(team.team_id)
        output_dir = output_dir_by_team.get(team.team_id)
        source_text = f"`{source_team.source}`" if source_team else "missing"
        output_text = f"`{output_dir.relative_to(args.output)}`" if output_dir else "missing"
        lines.append(
            f"| {team.rank} | {team.team} | {team.score:.1f} | {team.last_submission or '-'} | {source_text} | {output_text} |"
        )
    lines.append("")
    lines.append("## Usage")
    lines.append("")
    lines.append("- Run `tools/live_window_audit.py` against this composite scout before deciding whether a fresh Kaggle replay scout is still necessary.")
    lines.append("- This is not new episode evidence; it is a current-rank view over cached replay evidence from multiple recent scouts.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source", required=True, action="append", type=Path)
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--mode", choices=["hardlink", "copy", "symlink"], default="hardlink")
    args = parser.parse_args()

    if args.output.exists():
        raise FileExistsError(f"{args.output} already exists; choose a new output path")
    args.output.mkdir(parents=True)

    selected = read_leaderboard(args.leaderboard)[: args.team_limit]
    fieldnames, source_candidates = collect_sources(args.source)
    source_by_team: dict[str, SourceTeam] = {}
    output_dir_by_team: dict[str, Path] = {}

    for team in selected:
        candidates = source_candidates.get(team.team_id, [])
        if not candidates:
            continue
        source_team = choose_source(candidates)
        output_dir = args.output / f"{team.rank:02d}_{safe_name(team.team)}_{team.team_id}"
        clone_team_dir(source_team.directory, output_dir, args.mode)
        source_by_team[team.team_id] = source_team
        output_dir_by_team[team.team_id] = output_dir

    covered, missing = write_summary(args.output, fieldnames, selected, source_by_team, output_dir_by_team)
    manifest = render_manifest(args, selected, source_by_team, output_dir_by_team, covered, missing)
    (args.output / "composite_manifest.md").write_text(manifest, encoding="utf-8")
    print(manifest, end="")
    if missing:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
