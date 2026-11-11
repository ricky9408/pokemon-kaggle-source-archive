#!/usr/bin/env python3
"""Summarize motif-level policy holdouts from policy casebook CSV files."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class CaseRow:
    path: Path
    count: int
    context: str
    public_choice: str
    local_choice: str
    motifs: tuple[str, ...]
    teams: str


def parse_teams(raw: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in raw.split(";"):
        item = item.strip()
        if not item or ":" not in item:
            continue
        team, count = item.rsplit(":", 1)
        try:
            counts[team] += int(count)
        except ValueError:
            continue
    return counts


def load_rows(path: Path) -> list[CaseRow]:
    rows: list[CaseRow] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            try:
                count = int(raw["count"])
            except (KeyError, ValueError):
                continue
            rows.append(
                CaseRow(
                    path=path,
                    count=count,
                    context=raw.get("context", ""),
                    public_choice=raw.get("public_choice", ""),
                    local_choice=raw.get("local_choice", ""),
                    motifs=tuple(label for label in raw.get("motifs", "").split(";") if label),
                    teams=raw.get("teams", ""),
                )
            )
    return rows


def motif_matches(motif: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(motif, pattern) for pattern in patterns)


def source_label(path: Path) -> str:
    name = path.stem
    for prefix in ("policy_casebook_", "casebook_"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name


def summarize(rows: list[CaseRow], patterns: list[str]) -> dict[str, object]:
    motif_counts: Counter[str] = Counter()
    team_counts: Counter[str] = Counter()
    case_counts: Counter[tuple[str, str, str, tuple[str, ...]]] = Counter()
    total_mismatch = sum(row.count for row in rows)
    target_rows = 0
    target_mass = 0

    for row in rows:
        matched = tuple(motif for motif in row.motifs if motif_matches(motif, patterns))
        if not matched:
            continue
        target_rows += 1
        target_mass += row.count
        for motif in matched:
            motif_counts[motif] += row.count
        team_counts.update(parse_teams(row.teams))
        case_counts[(row.context, row.public_choice, row.local_choice, matched)] += row.count

    return {
        "total_mismatch": total_mismatch,
        "target_rows": target_rows,
        "target_mass": target_mass,
        "motif_counts": motif_counts,
        "team_counts": team_counts,
        "case_counts": case_counts,
    }


def render(args: argparse.Namespace, loaded: dict[Path, list[CaseRow]]) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    patterns = args.motif_glob
    summaries = {path: summarize(rows, patterns) for path, rows in loaded.items()}
    baseline_path = next(iter(summaries))
    baseline = summaries[baseline_path]

    lines: list[str] = [
        "# Motif Holdout Report",
        "",
        f"Generated: {generated}",
        "",
        "## Research Agent Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        "- Strategic premise: motif holdouts are policy-patch gates, not direct ladder-score estimates.",
        "",
        "## Inputs",
        "",
        f"- Motif glob(s): {', '.join(f'`{pattern}`' for pattern in patterns)}",
    ]
    for path in loaded:
        lines.append(f"- Casebook: `{path}`")

    lines.extend(["", "## Summary", "", "| Source | Total Mismatch | Target Rows | Target Mass | Delta vs First | Target Share |", "| --- | ---: | ---: | ---: | ---: | ---: |"])
    base_mass = int(baseline["target_mass"])
    for path, summary in summaries.items():
        total = int(summary["total_mismatch"])
        target = int(summary["target_mass"])
        share = target / total if total else 0.0
        lines.append(
            f"| `{source_label(path)}` | {total} | {summary['target_rows']} | {target} | {target - base_mass:+d} | {share:.3f} |"
        )

    all_motifs = sorted({motif for summary in summaries.values() for motif in summary["motif_counts"]})
    if all_motifs:
        lines.extend(["", "## Motif Counts", ""])
        header = "| Motif | " + " | ".join(f"`{source_label(path)}`" for path in summaries) + " |"
        lines.append(header)
        lines.append("| --- |" + " ---: |" * len(summaries))
        for motif in all_motifs:
            cells = [str(summaries[path]["motif_counts"].get(motif, 0)) for path in summaries]
            lines.append(f"| `{motif}` | " + " | ".join(cells) + " |")

    for path, summary in summaries.items():
        lines.extend(["", f"## Top Cases: `{source_label(path)}`", "", "| Count | Context | Public Choice | Local Choice | Motifs |", "| ---: | --- | --- | --- | --- |"])
        top_cases = summary["case_counts"].most_common(args.top_cases)
        if not top_cases:
            lines.append("| 0 | - | - | - | - |")
            continue
        for (context, public_choice, local_choice, motifs), count in top_cases:
            motif_text = ", ".join(f"`{motif}`" for motif in motifs)
            lines.append(f"| {count} | `{context}` | {public_choice} | {local_choice} | {motif_text} |")

        team_counts = summary["team_counts"].most_common(args.top_teams)
        if team_counts:
            lines.extend(["", "Top teams in target motifs:", ""])
            for team, count in team_counts:
                lines.append(f"- {team}: {count}")

    lines.extend(
        [
            "",
            "## Use",
            "",
            "- A candidate improves this holdout when target mass falls without creating larger broad-casebook or payoff regressions.",
            "- This report should be combined with action-ranker evaluation and process-recycled PSRO before any package is promoted.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("casebook_csv", type=Path, nargs="+")
    parser.add_argument("--motif-glob", action="append")
    parser.add_argument("--top-cases", type=int, default=12)
    parser.add_argument("--top-teams", type=int, default=8)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.motif_glob:
        args.motif_glob = ["public_*_before_engine_ability"]

    loaded = {path: load_rows(path) for path in args.casebook_csv}
    text = render(args, loaded)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
