#!/usr/bin/env python3
"""Audit whether a local league is supported by mature public anchors.

Local leagues are stress tests, not public-score predictors. This script makes
that rule mechanical by joining a league CSV to saved Kaggle submissions and
highlighting either:

* local winners that underperformed publicly, which contradicts the league; or
* local winners with no mature public anchor yet, which is an evidence gap.
* mature anchors whose rank correlation is too weak to trust the league.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
import io
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class Submission:
    archive: str
    description: str
    submitted_at: datetime
    status: str
    public_score: float


@dataclass(frozen=True)
class LeagueRow:
    rank: int
    entry: str
    local_strength: float
    raw: dict[str, str]


def parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def parse_submissions(path: Path) -> list[Submission]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    csv_start = None
    for index, line in enumerate(lines):
        if line.startswith("ref,fileName") or (line.startswith("ref,") and "fileName" in line):
            csv_start = index
            break
    if csv_start is not None:
        rows: list[Submission] = []
        for row in csv.DictReader(io.StringIO("\n".join(lines[csv_start:]))):
            score = parse_float(row.get("publicScore"))
            if score is None:
                continue
            rows.append(
                Submission(
                    archive=(row.get("fileName") or "").strip(),
                    description=(row.get("description") or "").strip(),
                    submitted_at=parse_datetime(row.get("date") or ""),
                    status=(row.get("status") or "").strip(),
                    public_score=score,
                )
            )
        return rows

    rows = []
    pattern = re.compile(
        r"^\s*(?P<ref>\d+)\s+"
        r"(?P<archive>\S+)\s+"
        r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"(?P<description>.+?)\s+"
        r"(?P<status>SubmissionStatus\.\w+)\s+"
        r"(?P<score>-?[\d.]+)?\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        score = parse_float(match.group("score"))
        if score is None:
            continue
        rows.append(
            Submission(
                archive=match.group("archive"),
                description=match.group("description").strip(),
                submitted_at=parse_datetime(match.group("date")),
                status=match.group("status"),
                public_score=score,
            )
        )
    return rows


def parse_league(path: Path) -> list[LeagueRow]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    parsed: list[LeagueRow] = []
    for index, row in enumerate(rows, 1):
        rank = parse_int(row.get("rank")) or index
        entry = row.get("entry") or row.get("agent") or row.get("Agent") or ""
        if not entry:
            continue
        explicit_strength = parse_float(row.get("local_strength"))
        win_pct = parse_float(row.get("win_pct") or row.get("Win%"))
        points = parse_float(row.get("points"))
        game_diff = parse_float(row.get("game_diff"))
        wins = parse_float(row.get("wins") or row.get("game_wins") or row.get("match_wins"))
        if explicit_strength is not None:
            local_strength = explicit_strength
        elif win_pct is not None:
            local_strength = win_pct
        elif points is not None:
            local_strength = points * 1000 + (game_diff or 0.0) * 10 + (wins or 0.0)
        else:
            local_strength = -float(rank)
        parsed.append(LeagueRow(rank=rank, entry=entry, local_strength=local_strength, raw=row))
    return parsed


def version_alias(text: str) -> str | None:
    match = re.search(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", text.lower())
    return f"v{match.group(1)}" if match else None


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def parse_entry_maps(values: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--map must be ENTRY=ARCHIVE")
        entry, archive = value.split("=", 1)
        out[entry] = archive
    return out


def auto_archive_for(entry: str, submissions: list[Submission]) -> str | None:
    entry_norm = normalize(entry)
    alias = version_alias(entry)
    candidates = sorted(submissions, key=lambda item: item.submitted_at, reverse=True)
    if alias:
        for submission in candidates:
            haystack = f"{submission.archive} {submission.description}".lower()
            if alias in haystack:
                return submission.archive
        return None
    for marker in ("claude", "grok"):
        if marker in entry_norm:
            for submission in candidates:
                if marker in normalize(f"{submission.archive} {submission.description}"):
                    return submission.archive
    for submission in candidates:
        if entry_norm and entry_norm in normalize(f"{submission.archive} {submission.description}"):
            return submission.archive
    return None


def mature_latest_for(
    archive: str,
    submissions: list[Submission],
    now: datetime,
    maturity_minutes: int,
) -> Submission | None:
    cutoff = now - timedelta(minutes=maturity_minutes)
    eligible = [
        row
        for row in submissions
        if row.archive == archive
        and row.status == "SubmissionStatus.COMPLETE"
        and row.submitted_at <= cutoff
    ]
    if not eligible:
        return None
    return max(eligible, key=lambda row: row.submitted_at)


def rank_values(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    pos = 0
    while pos < len(order):
        end = pos + 1
        while end < len(order) and values[order[end]] == values[order[pos]]:
            end += 1
        rank = (pos + end + 1) / 2.0
        for cursor in range(pos, end):
            ranks[order[cursor]] = rank
        pos = end
    return ranks


def pearson(left: list[float], right: list[float]) -> float:
    if len(left) < 2:
        return math.nan
    mean_left = sum(left) / len(left)
    mean_right = sum(right) / len(right)
    cov = sum((a - mean_left) * (b - mean_right) for a, b in zip(left, right))
    var_left = sum((a - mean_left) ** 2 for a in left)
    var_right = sum((b - mean_right) ** 2 for b in right)
    if var_left == 0 or var_right == 0:
        return math.nan
    return cov / math.sqrt(var_left * var_right)


def spearman(left: list[float], right: list[float]) -> float:
    return pearson(rank_values(left), rank_values(right))


def kendall(left: list[float], right: list[float]) -> float:
    concordant = 0
    discordant = 0
    for i in range(len(left)):
        for j in range(i + 1, len(left)):
            da = left[i] - left[j]
            db = right[i] - right[j]
            if da == 0 or db == 0:
                continue
            if da * db > 0:
                concordant += 1
            else:
                discordant += 1
    total = concordant + discordant
    if total == 0:
        return math.nan
    return (concordant - discordant) / total


def fmt(value: float) -> str:
    return "nan" if math.isnan(value) else f"{value:.3f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--league-csv", type=Path, required=True)
    parser.add_argument("--submissions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--now", default=None)
    parser.add_argument("--maturity-minutes", type=int, default=60)
    parser.add_argument("--min-public-score", type=float, default=1000.0)
    parser.add_argument("--top-local-rank", type=int, default=3)
    parser.add_argument(
        "--min-correlated-anchors",
        type=int,
        default=2,
        help="minimum mature mapped anchors required before a no-contradiction result can be trusted",
    )
    parser.add_argument(
        "--min-public-spearman",
        type=float,
        default=0.55,
        help="minimum Spearman rank correlation required between local strength and mature public scores",
    )
    parser.add_argument("--map", action="append", default=[], help="ENTRY=ARCHIVE override, repeatable")
    args = parser.parse_args()

    now = parse_datetime(args.now) if args.now else datetime.now(UTC)
    submissions = parse_submissions(args.submissions)
    league = parse_league(args.league_csv)
    mapping = parse_entry_maps(args.map)

    joined: list[dict[str, object]] = []
    for row in league:
        archive = mapping.get(row.entry) or auto_archive_for(row.entry, submissions)
        public = mature_latest_for(archive, submissions, now, args.maturity_minutes) if archive else None
        kind = (row.raw.get("kind") or "").lower()
        is_local_candidate = kind in ("", "ours")
        if public is None and not is_local_candidate:
            status = "reference_opponent_no_anchor"
        elif public is None:
            status = "missing_public_anchor" if archive is None else "missing_mature_public_score"
        elif row.rank <= args.top_local_rank and public.public_score < args.min_public_score:
            status = "local_top_public_weak"
        else:
            status = "ok"
        joined.append(
            {
                "rank": row.rank,
                "entry": row.entry,
                "local_strength": row.local_strength,
                "archive": archive or "",
                "public_score": "" if public is None else public.public_score,
                "public_date": "" if public is None else public.submitted_at.strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
            }
        )

    correlated = [row for row in joined if isinstance(row["public_score"], float)]
    local_values = [float(row["local_strength"]) for row in correlated]
    public_values = [float(row["public_score"]) for row in correlated]
    rho = spearman(local_values, public_values)
    tau = kendall(local_values, public_values)

    weak_public_blockers = [
        row
        for row in joined
        if row["status"] == "local_top_public_weak"
        and int(row["rank"]) <= args.top_local_rank
    ]
    missing_anchor_gaps = [
        row
        for row in joined
        if row["status"] in ("missing_public_anchor", "missing_mature_public_score")
        and int(row["rank"]) <= args.top_local_rank
    ]
    evidence_gaps: list[str] = []
    if len(correlated) < args.min_correlated_anchors:
        evidence_gaps.append(
            f"only {len(correlated)} mapped mature public anchors; "
            f"require >= {args.min_correlated_anchors}"
        )
    for row in missing_anchor_gaps:
        evidence_gaps.append(
            f"local rank {row['rank']} `{row['entry']}` -> {row['status']} "
            f"(archive `{row['archive'] or '-'}`)"
        )
    correlation_failures: list[str] = []
    if len(correlated) >= args.min_correlated_anchors:
        if math.isnan(rho):
            correlation_failures.append(
                f"Spearman is nan with {len(correlated)} mature anchors"
            )
        elif rho < args.min_public_spearman:
            correlation_failures.append(
                f"Spearman {rho:.3f} < required {args.min_public_spearman:.3f} "
                f"with {len(correlated)} mature anchors"
            )

    lines = [
        "# Local League Public Gap Audit",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Inputs",
        "",
        f"- League CSV: `{args.league_csv}`",
        f"- Submissions: `{args.submissions}`",
        f"- Anchor maturity: {args.maturity_minutes} minutes before {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"- Local top-rank watch window: <= {args.top_local_rank}",
        f"- Weak-public threshold: < {args.min_public_score:.1f}",
        f"- Minimum correlated anchors: {args.min_correlated_anchors}",
        f"- Minimum public Spearman: {args.min_public_spearman:.3f}",
        "",
        "## Correlation",
        "",
        f"- Mapped mature public anchors: {len(correlated)} / {len(joined)}",
        f"- Spearman(local strength, mature public score): {fmt(rho)}",
        f"- Kendall(local strength, mature public score): {fmt(tau)}",
        "",
        "## Decision",
        "",
    ]
    if weak_public_blockers:
        lines.append("- Trust decision: **LOCAL LEAGUE CONTRADICTED BY PUBLIC ANCHORS**")
        for row in weak_public_blockers:
            public_text = row["public_score"] if row["public_score"] != "" else "missing"
            lines.append(
                f"- Blocker: local rank {row['rank']} `{row['entry']}` -> "
                f"{row['status']} (archive `{row['archive'] or '-'}`, public {public_text})."
            )
        if evidence_gaps:
            for gap in evidence_gaps:
                lines.append(f"- Evidence gap: {gap}.")
        if correlation_failures:
            for failure in correlation_failures:
                lines.append(f"- Correlation failure: {failure}.")
    elif correlation_failures:
        lines.append("- Trust decision: **LOCAL LEAGUE FAILS PUBLIC CORRELATION**")
        for failure in correlation_failures:
            lines.append(f"- Correlation failure: {failure}.")
        if evidence_gaps:
            for gap in evidence_gaps:
                lines.append(f"- Evidence gap: {gap}.")
    elif evidence_gaps:
        lines.append("- Trust decision: **LOCAL LEAGUE HAS INSUFFICIENT PUBLIC ANCHORS**")
        for gap in evidence_gaps:
            lines.append(f"- Evidence gap: {gap}.")
    else:
        lines.append("- Trust decision: **LOCAL LEAGUE NOT CONTRADICTED BY PUBLIC ANCHORS**")
        lines.append("- Legacy decision: no top-local public contradiction found in mapped mature anchors.")
    lines.extend(
        [
            "",
            "## Joined Rows",
            "",
            "| Local rank | Entry | Local strength | Archive | Mature public | Public date | Status |",
            "| ---: | --- | ---: | --- | ---: | --- | --- |",
        ]
    )
    for row in joined:
        public_text = "" if row["public_score"] == "" else f"{float(row['public_score']):.1f}"
        lines.append(
            f"| {row['rank']} | `{row['entry']}` | {float(row['local_strength']):.3f} | "
            f"`{row['archive'] or '-'}` | {public_text} | {row['public_date']} | `{row['status']}` |"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    print("\n".join(lines))
    if weak_public_blockers:
        return 2
    if correlation_failures:
        return 4
    if evidence_gaps:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
