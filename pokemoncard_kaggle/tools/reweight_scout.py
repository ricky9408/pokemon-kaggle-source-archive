#!/usr/bin/env python3
"""Create a current-rank-weighted view of an existing replay scout.

When ``live_window_audit.py`` says ``reweight-existing``, the replay files are
still fresh but the rank/score weights in ``download_summary.csv`` are stale.
This tool copies or links the scout into a new directory and rewrites only the
summary rank/score fields from a newer leaderboard snapshot. Downstream tools
that already understand scout directories can then use the reweighted path
without knowing about the override.
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
class LeaderboardRow:
    rank: str
    team_id: str
    team: str
    score: str
    last_submission: str


def norm_date(value: str) -> str:
    value = value.strip().strip('"')
    return value.split(".")[0] if value else ""


def read_leaderboard(path: Path) -> dict[str, LeaderboardRow]:
    rows: dict[str, LeaderboardRow] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            team_id = row.get("TeamId", "")
            if not team_id:
                continue
            rows[team_id] = LeaderboardRow(
                rank=row.get("Rank", ""),
                team_id=team_id,
                team=row.get("TeamName", ""),
                score=row.get("Score", ""),
                last_submission=norm_date(row.get("LastSubmissionDate", "")),
            )
    if not rows:
        raise ValueError(f"No leaderboard rows parsed from {path}")
    return rows


def link_or_copy(src: Path, dst: Path, mode: str) -> None:
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.name == "download_summary.csv":
        # This file is rewritten after cloning. Never hardlink mutable metadata,
        # or the historical source scout will be rewritten too.
        shutil.copy2(src, dst)
        return
    if mode == "copy":
        shutil.copy2(src, dst)
    elif mode == "symlink":
        rel = os.path.relpath(src, dst.parent)
        dst.symlink_to(rel)
    elif mode == "hardlink":
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst)
    else:
        raise ValueError(f"Unknown copy mode: {mode}")


def clone_tree(source: Path, output: Path, mode: str) -> None:
    if output.exists():
        raise FileExistsError(f"{output} already exists; choose a new output path")
    for src in sorted(source.rglob("*")):
        rel = src.relative_to(source)
        dst = output / rel
        link_or_copy(src, dst, mode)


def rewrite_summary(
    source: Path,
    output: Path,
    source_summary: Path,
    output_summary: Path,
    leaderboard: dict[str, LeaderboardRow],
) -> tuple[int, int]:
    changed = 0
    missing = 0
    with source_summary.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))
        fieldnames = list(file and rows[0].keys()) if rows else []
    if not rows:
        raise ValueError(f"No rows in {source_summary}")
    if not fieldnames:
        fieldnames = list(rows[0].keys())

    rewritten: list[dict[str, str]] = []
    for row in rows:
        team_id = row.get("team_id", "")
        current = leaderboard.get(team_id)
        new_row = dict(row)
        if current is None:
            missing += 1
        else:
            before = (new_row.get("rank", ""), new_row.get("score", ""))
            new_row["rank"] = current.rank
            new_row["team"] = current.team or new_row.get("team", "")
            new_row["score"] = current.score
            after = (new_row.get("rank", ""), new_row.get("score", ""))
            if before != after:
                changed += 1
        path_value = new_row.get("path", "")
        if path_value:
            try:
                rel_path = Path(path_value).relative_to(source)
                new_row["path"] = str(output / rel_path)
            except ValueError:
                source_text = str(source)
                if path_value.startswith(source_text + os.sep):
                    new_row["path"] = str(output / path_value[len(source_text) + 1 :])
        rewritten.append(new_row)

    with output_summary.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rewritten)
    return changed, missing


def team_dirs(path: Path) -> dict[str, Path]:
    result = {}
    for child in path.iterdir():
        if not child.is_dir():
            continue
        match = re.search(r"_(\d+)$", child.name)
        if match:
            result[match.group(1)] = child
    return result


def render_manifest(
    source: Path,
    output: Path,
    leaderboard_path: Path,
    leaderboard: dict[str, LeaderboardRow],
    changed_rows: int,
    missing_rows: int,
    mode: str,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    output_team_dirs = team_dirs(output)
    current_top = sorted(leaderboard.values(), key=lambda row: int(row.rank or "999999"))[:12]

    lines: list[str] = []
    lines.append("# Reweighted Scout Manifest")
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
    lines.append("- Strategic premise: type balance and deck architecture are interpreted through current rank pressure; this file preserves replay evidence while updating that rank pressure.")
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append(f"- Source scout: `{source}`")
    lines.append(f"- Output scout: `{output}`")
    lines.append(f"- Leaderboard: `{leaderboard_path}`")
    lines.append(f"- File mode: `{mode}`")
    lines.append(f"- Summary rows with updated rank/score: {changed_rows}")
    lines.append(f"- Summary rows missing from leaderboard: {missing_rows}")
    lines.append("")
    lines.append("## Current Top-12 Coverage")
    lines.append("")
    lines.append("| Rank | Team | Score | Last Submission | Covered Directory |")
    lines.append("| ---: | --- | ---: | --- | --- |")
    for row in current_top:
        directory = output_team_dirs.get(row.team_id)
        directory_text = f"`{directory.relative_to(output)}`" if directory else "missing"
        lines.append(
            f"| {row.rank} | {row.team} | {float(row.score):.1f} | {row.last_submission or '-'} | {directory_text} |"
        )
    lines.append("")
    lines.append("## Usage")
    lines.append("")
    lines.append("- Point `tools/strategy_research.py`, `tools/type_pressure_report.py`, `tools/strategy_matrix.py`, and `tools/replay_pool_gauntlet.py` at replay files under this output directory when `live_window_audit.py` recommends `reweight-existing`.")
    lines.append("- Do not treat this as fresh episode scouting; it only updates rank/score weights.")
    return "\n".join(lines)


def default_output_path(source: Path, leaderboard: Path) -> Path:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)\.csv$", leaderboard.name)
    if match:
        stamp = match.group(1).replace("-", "").replace(":", "").replace("T", "T")
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return source.parent / f"{source.name}_reweighted_{stamp}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--mode", choices=["hardlink", "copy", "symlink"], default="hardlink")
    args = parser.parse_args()

    source = args.source
    output = args.output or default_output_path(source, args.leaderboard)
    summary = source / "download_summary.csv"
    if not summary.exists():
        raise FileNotFoundError(f"{summary} does not exist")

    leaderboard = read_leaderboard(args.leaderboard)
    clone_tree(source, output, args.mode)
    changed_rows, missing_rows = rewrite_summary(source, output, summary, output / "download_summary.csv", leaderboard)
    manifest = render_manifest(source, output, args.leaderboard, leaderboard, changed_rows, missing_rows, args.mode)
    manifest_path = output / "reweight_manifest.md"
    manifest_path.write_text(manifest + "\n", encoding="utf-8")
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
