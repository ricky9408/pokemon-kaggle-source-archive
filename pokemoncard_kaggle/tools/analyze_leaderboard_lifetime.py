#!/usr/bin/env python3
"""Analyze leaderboard churn and score lifetime from saved Kaggle snapshots.

This tool uses only local leaderboard CSV snapshots. It is useful when the
Kaggle API is flaky and for answering whether a score plateau is likely to drift
into top-10 range or whether the field is moving too quickly to wait.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


SNAPSHOT_RE = re.compile(r"publicleaderboard-(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.csv$")


@dataclass(frozen=True)
class SnapshotRow:
    timestamp: datetime
    rank: int
    team_id: str
    team_name: str
    last_submission: datetime | None
    score: float
    submission_count: int | None
    source: Path


@dataclass(frozen=True)
class Snapshot:
    timestamp: datetime
    source: Path
    rows: list[SnapshotRow]


def parse_snapshot_timestamp(path: Path) -> datetime | None:
    match = SNAPSHOT_RE.search(path.name)
    if not match:
        return None
    return datetime.fromisoformat(match.group("stamp")).replace(tzinfo=UTC)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().strip('"')
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def discover_files(patterns: list[str]) -> list[Path]:
    paths: set[Path] = set()
    for pattern in patterns:
        paths.update(Path().glob(pattern))
    return sorted(paths, key=lambda path: (parse_snapshot_timestamp(path) or datetime.min.replace(tzinfo=UTC), str(path)))


def load_snapshot(path: Path) -> Snapshot | None:
    timestamp = parse_snapshot_timestamp(path)
    if timestamp is None:
        return None
    rows: list[SnapshotRow] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            rank = parse_int(row.get("Rank"))
            score = parse_float(row.get("Score"))
            team_id = (row.get("TeamId") or "").strip()
            team_name = (row.get("TeamName") or "").strip()
            if rank is None or score is None or not team_name:
                continue
            rows.append(
                SnapshotRow(
                    timestamp=timestamp,
                    rank=rank,
                    team_id=team_id,
                    team_name=team_name,
                    last_submission=parse_datetime(row.get("LastSubmissionDate")),
                    score=score,
                    submission_count=parse_int(row.get("SubmissionCount")),
                    source=path,
                )
            )
    rows.sort(key=lambda item: item.rank)
    return Snapshot(timestamp=timestamp, source=path, rows=rows)


def fmt_time(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_float(value: float | None, digits: int = 1) -> str:
    if value is None or math.isnan(value):
        return "-"
    return f"{value:.{digits}f}"


def team_key(row: SnapshotRow) -> str:
    return row.team_id or row.team_name


def slope_per_hour(points: list[tuple[datetime, float]]) -> float | None:
    if len(points) < 2:
        return None
    start = points[0][0]
    xs = [(time - start).total_seconds() / 3600.0 for time, _ in points]
    ys = [score for _, score in points]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    denom = sum((x - x_mean) ** 2 for x in xs)
    if denom == 0:
        return None
    return sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)) / denom


def filter_window(snapshots: list[Snapshot], hours: float | None) -> list[Snapshot]:
    if not snapshots or hours is None or hours <= 0:
        return snapshots
    latest = snapshots[-1].timestamp
    cutoff = latest.timestamp() - hours * 3600.0
    return [snapshot for snapshot in snapshots if snapshot.timestamp.timestamp() >= cutoff]


def jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    return len(left & right) / len(left | right)


def render_report(args: argparse.Namespace, snapshots: list[Snapshot]) -> str:
    latest = snapshots[-1]
    top_k = args.top_k
    latest_top = latest.rows[:top_k]
    top_sets = [{team_key(row) for row in snapshot.rows[:top_k]} for snapshot in snapshots]

    churn_rows: list[tuple[Snapshot, int, int, float]] = []
    for index, snapshot in enumerate(snapshots[1:], 1):
        previous = top_sets[index - 1]
        current = top_sets[index]
        churn_rows.append((snapshot, len(current - previous), len(previous - current), jaccard(previous, current)))

    teams: dict[str, list[SnapshotRow]] = defaultdict(list)
    for snapshot in snapshots:
        for row in snapshot.rows:
            teams[team_key(row)].append(row)

    top_seen = set().union(*top_sets) if top_sets else set()
    lifetime_rows = []
    for key in top_seen:
        rows = sorted(teams[key], key=lambda row: row.timestamp)
        top_rows = [row for row in rows if row.rank <= top_k]
        if not top_rows:
            continue
        latest_row = rows[-1]
        first_row = rows[0]
        lifetime_rows.append(
            {
                "key": key,
                "name": latest_row.team_name,
                "top_snapshots": len(top_rows),
                "snapshot_share": len(top_rows) / len(snapshots),
                "first_top": top_rows[0].timestamp,
                "last_top": top_rows[-1].timestamp,
                "best_rank": min(row.rank for row in rows),
                "latest_rank": latest_row.rank,
                "latest_score": latest_row.score,
                "score_delta": latest_row.score - first_row.score,
                "last_submission": latest_row.last_submission,
            }
        )
    lifetime_rows.sort(key=lambda item: (-item["top_snapshots"], item["best_rank"], -item["latest_score"]))

    latest_cutoff = latest.rows[top_k - 1].score if len(latest.rows) >= top_k else None
    cutoff_points = [(snapshot.timestamp, snapshot.rows[top_k - 1].score) for snapshot in snapshots if len(snapshot.rows) >= top_k]
    cutoff_slope = slope_per_hour(cutoff_points)
    cutoff_delta = cutoff_points[-1][1] - cutoff_points[0][1] if len(cutoff_points) >= 2 else None

    target_points: list[tuple[datetime, float]] = []
    target_rows: list[SnapshotRow] = []
    target_lower = args.team.lower()
    for snapshot in snapshots:
        for row in snapshot.rows:
            if row.team_name.lower() == target_lower or row.team_id == args.team:
                target_rows.append(row)
                target_points.append((snapshot.timestamp, row.score))
                break
    target_latest = target_rows[-1] if target_rows else None
    target_slope = slope_per_hour(target_points)
    target_delta = target_points[-1][1] - target_points[0][1] if len(target_points) >= 2 else None
    target_gap = (latest_cutoff - target_latest.score) if latest_cutoff is not None and target_latest is not None else None

    recent_cutoff_time = latest.timestamp.timestamp() - args.recent_hours * 3600.0
    recent_cutoff_points = [point for point in cutoff_points if point[0].timestamp() >= recent_cutoff_time]
    recent_target_points = [point for point in target_points if point[0].timestamp() >= recent_cutoff_time]
    recent_cutoff_slope = slope_per_hour(recent_cutoff_points)
    recent_target_slope = slope_per_hour(recent_target_points)
    recent_cutoff_delta = (
        recent_cutoff_points[-1][1] - recent_cutoff_points[0][1] if len(recent_cutoff_points) >= 2 else None
    )
    recent_target_delta = (
        recent_target_points[-1][1] - recent_target_points[0][1] if len(recent_target_points) >= 2 else None
    )

    avg_jaccard = sum(row[3] for row in churn_rows) / len(churn_rows) if churn_rows else 1.0
    avg_entries = sum(row[1] for row in churn_rows) / len(churn_rows) if churn_rows else 0.0

    latest_top_ages: list[float] = []
    for row in latest_top:
        if row.last_submission is not None:
            latest_top_ages.append((latest.timestamp - row.last_submission).total_seconds() / 3600.0)
    median_age = None
    if latest_top_ages:
        ordered = sorted(latest_top_ages)
        middle = len(ordered) // 2
        median_age = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2.0

    lines = [
        "# Leaderboard Lifetime Analysis",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Inputs",
        "",
        f"- Snapshot files: {len(snapshots)}",
        f"- Window: {fmt_time(snapshots[0].timestamp)} -> {fmt_time(latest.timestamp)}",
        f"- Top-K: {top_k}",
        f"- Target team: `{args.team}`",
        "",
        "## Current Snapshot",
        "",
        f"- Source: `{latest.source}`",
        f"- Latest top-{top_k} cutoff: {fmt_float(latest_cutoff)}",
        f"- Top-{top_k} cutoff delta over this window: {fmt_float(cutoff_delta)}",
        f"- Top-{top_k} cutoff slope: {fmt_float(cutoff_slope, 2)} points/hour",
        f"- Recent {args.recent_hours:.0f}h top-{top_k} cutoff delta / slope: {fmt_float(recent_cutoff_delta)} / {fmt_float(recent_cutoff_slope, 2)} points/hour",
        f"- Average top-{top_k} entries per snapshot transition: {avg_entries:.2f}",
        f"- Average top-{top_k} Jaccard stability: {avg_jaccard:.3f}",
        f"- Median latest top-{top_k} submission age: {fmt_float(median_age, 2)} hours",
        "",
        f"## `{args.team}` Trajectory",
        "",
    ]
    if target_latest is None:
        lines.extend(["- Target team not found in the selected snapshots.", ""])
    else:
        lines.extend(
            [
                f"- Latest rank / score: {target_latest.rank} / {target_latest.score:.1f}",
                f"- Gap to current top-{top_k}: {fmt_float(target_gap)}",
                f"- Score delta over this window: {fmt_float(target_delta)}",
                f"- Score slope: {fmt_float(target_slope, 2)} points/hour",
                f"- Recent {args.recent_hours:.0f}h score delta / slope: {fmt_float(recent_target_delta)} / {fmt_float(recent_target_slope, 2)} points/hour",
                f"- Best rank in window: {min(row.rank for row in target_rows)}",
                f"- Best score in window: {max(row.score for row in target_rows):.1f}",
                f"- Last submission timestamp in latest row: {fmt_time(target_latest.last_submission)}",
                "",
            ]
        )

    lines.extend(
        [
            f"## Latest Top {top_k}",
            "",
            "| Rank | Team | Score | Last submission age (h) | Last submission |",
            "| ---: | --- | ---: | ---: | --- |",
        ]
    )
    for row in latest_top:
        age = None
        if row.last_submission is not None:
            age = (latest.timestamp - row.last_submission).total_seconds() / 3600.0
        lines.append(
            f"| {row.rank} | `{row.team_name}` | {row.score:.1f} | {fmt_float(age, 2)} | {fmt_time(row.last_submission)} |"
        )

    lines.extend(
        [
            "",
            f"## Top-{top_k} Lifetime Table",
            "",
            "| Team | Top snapshots | Share | Best rank | Latest rank | Latest score | Score delta | First top | Last top |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in lifetime_rows[: args.max_rows]:
        lines.append(
            "| {name} | {top_snapshots} | {share:.2f} | {best_rank} | {latest_rank} | {latest_score:.1f} | {delta:.1f} | {first} | {last} |".format(
                name=f"`{item['name']}`",
                top_snapshots=item["top_snapshots"],
                share=item["snapshot_share"],
                best_rank=item["best_rank"],
                latest_rank=item["latest_rank"],
                latest_score=item["latest_score"],
                delta=item["score_delta"],
                first=fmt_time(item["first_top"]),
                last=fmt_time(item["last_top"]),
            )
        )

    lines.extend(
        [
            "",
            "## Churn Tail",
            "",
            "| Snapshot | Entries | Exits | Jaccard |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for snapshot, entries, exits, score in churn_rows[-args.churn_rows :]:
        lines.append(f"| {fmt_time(snapshot.timestamp)} | {entries} | {exits} | {score:.3f} |")

    lines.extend(["", "## Decision Notes", ""])
    decision_target_slope = recent_target_slope if recent_target_slope is not None else target_slope
    decision_cutoff_slope = recent_cutoff_slope if recent_cutoff_slope is not None else cutoff_slope
    if target_gap is not None and decision_target_slope is not None and decision_cutoff_slope is not None:
        relative_slope = decision_target_slope - decision_cutoff_slope
        if target_gap > 100 and relative_slope <= 1.0:
            lines.append(
                "- Current target trajectory does not support waiting for passive drift into top-10; improvement needs a new validated candidate or a substantially better public-anchor signal."
            )
        elif relative_slope > 0:
            lines.append(
                "- Target score is improving faster than the cutoff in this window, but the gap should still be judged against mature submission anchors."
            )
        else:
            lines.append(
                "- Target score is not gaining on the cutoff in this window; local-only league wins should remain diagnostic."
            )
    lines.append("- This report is descriptive only and must not override the pre-submit gate.")
    lines.append("")
    return "\n".join(lines)


def write_lifetime_csv(path: Path, snapshots: list[Snapshot], top_k: int) -> None:
    teams: dict[str, list[SnapshotRow]] = defaultdict(list)
    top_sets = [{team_key(row) for row in snapshot.rows[:top_k]} for snapshot in snapshots]
    top_seen = set().union(*top_sets) if top_sets else set()
    for snapshot in snapshots:
        for row in snapshot.rows:
            teams[team_key(row)].append(row)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "team_key",
                "team_name",
                "top_snapshots",
                "snapshot_share",
                "best_rank",
                "latest_rank",
                "latest_score",
                "first_seen",
                "last_seen",
                "last_submission",
            ],
            lineterminator="\n",
        )
        writer.writeheader()
        for key in sorted(top_seen):
            rows = sorted(teams[key], key=lambda row: row.timestamp)
            top_rows = [row for row in rows if row.rank <= top_k]
            latest = rows[-1]
            writer.writerow(
                {
                    "team_key": key,
                    "team_name": latest.team_name,
                    "top_snapshots": len(top_rows),
                    "snapshot_share": f"{len(top_rows) / len(snapshots):.6f}",
                    "best_rank": min(row.rank for row in rows),
                    "latest_rank": latest.rank,
                    "latest_score": f"{latest.score:.6f}",
                    "first_seen": rows[0].timestamp.isoformat(),
                    "last_seen": rows[-1].timestamp.isoformat(),
                    "last_submission": latest.last_submission.isoformat() if latest.last_submission else "",
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--leaderboard-glob",
        action="append",
        default=["leaderboard/current/pokemon-tcg-ai-battle-publicleaderboard-*.csv"],
        help="Glob for local leaderboard CSV snapshots. Can be repeated.",
    )
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--window-hours", type=float, default=72.0, help="Only use snapshots within this many hours of latest. <=0 means all.")
    parser.add_argument("--recent-hours", type=float, default=24.0, help="Recent window for short-term drift analysis.")
    parser.add_argument("--max-rows", type=int, default=30)
    parser.add_argument("--churn-rows", type=int, default=12)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path)
    args = parser.parse_args()

    files = discover_files(args.leaderboard_glob)
    snapshots = [snapshot for path in files if (snapshot := load_snapshot(path)) is not None]
    snapshots = filter_window(snapshots, args.window_hours)
    if not snapshots:
        raise SystemExit("no leaderboard snapshots found")
    snapshots.sort(key=lambda snapshot: snapshot.timestamp)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render_report(args, snapshots), encoding="utf-8")
    if args.csv_output:
        args.csv_output.parent.mkdir(parents=True, exist_ok=True)
        write_lifetime_csv(args.csv_output, snapshots, args.top_k)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
