#!/usr/bin/env python3
"""Build a non-leaky metrics panel from critic league outputs.

`heartbeat_loop.py` already produces local league and robustness CSVs, but the
predictive-validity gate needs one row per submitted archive with numeric,
non-public local metrics. This tool aggregates those critic CSVs into such a
panel so `tools/backtest_loocv.py` can test whether the local signals are
actually public-anchor consistent.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


def parse_float(value: object) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def normalize(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def parse_maps(values: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    exact: dict[str, str] = {}
    normalized: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--map must be ENTRY=ARCHIVE, got: {value}")
        entry, archive = value.split("=", 1)
        entry = entry.strip()
        archive = Path(archive.strip()).name
        exact[entry] = archive
        normalized[normalize(entry)] = archive
    return exact, normalized


@dataclass
class PanelRow:
    candidate: str
    archive: str
    metrics: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def add(self, metric: str, value: float | None) -> None:
        if value is not None:
            self.metrics[metric].append(value)


def mapped_archive(entry: str, exact: dict[str, str], normalized: dict[str, str]) -> str | None:
    return exact.get(entry) or normalized.get(normalize(entry))


def candidate_for_archive(archive: str) -> str:
    name = Path(archive).name
    stem = name.removeprefix("submission-").removesuffix(".tar.gz")
    return stem.replace("-", "_")


def add_league_rows(path: Path, rows: dict[str, PanelRow], exact: dict[str, str], normalized: dict[str, str]) -> int:
    added = 0
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            entry = (row.get("entry") or row.get("agent") or "").strip()
            archive = mapped_archive(entry, exact, normalized)
            if not archive:
                continue
            panel = rows.setdefault(archive, PanelRow(candidate_for_archive(archive), archive))
            added += 1
            rank = parse_float(row.get("rank"))
            panel.add("critic_league_inverse_rank", -rank if rank is not None else None)
            for column in (
                "win_pct",
                "points",
                "game_diff",
                "match_wins",
                "match_losses",
                "match_draws",
                "game_wins",
                "game_losses",
                "game_draws",
                "unfinished",
            ):
                panel.add(f"critic_league_{column}", parse_float(row.get(column)))
    return added


def add_robustness_rows(path: Path, rows: dict[str, PanelRow], exact: dict[str, str], normalized: dict[str, str]) -> int:
    added = 0
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            entry = (row.get("entry") or row.get("agent") or "").strip()
            archive = mapped_archive(entry, exact, normalized)
            if not archive:
                continue
            panel = rows.setdefault(archive, PanelRow(candidate_for_archive(archive), archive))
            added += 1
            rank = parse_float(row.get("rank"))
            panel.add("critic_robustness_inverse_rank", -rank if rank is not None else None)
            for column in (
                "top_games",
                "top_win_pct",
                "maximin_archetype_win_pct",
                "robustness_score",
                "local_strength",
                "mean_rank",
                "best_rank",
                "worst_rank",
                "rank_span",
                "robustness_best_count",
            ):
                panel.add(f"critic_robustness_{column}", parse_float(row.get(column)))
            max_regret = parse_float(row.get("max_regret"))
            avg_regret = parse_float(row.get("avg_regret"))
            panel.add("critic_robustness_negative_max_regret", -max_regret if max_regret is not None else None)
            panel.add("critic_robustness_negative_avg_regret", -avg_regret if avg_regret is not None else None)
    return added


def summarize(values: list[float]) -> tuple[str, str]:
    if not values:
        return "", ""
    return f"{statistics.fmean(values):.6f}", f"{values[-1]:.6f}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate critic league metrics into a LOOCV metrics CSV")
    parser.add_argument("--league-csv", action="append", default=[], type=Path)
    parser.add_argument("--robustness-csv", action="append", default=[], type=Path)
    parser.add_argument("--map", action="append", default=[], help="ENTRY=ARCHIVE mapping; repeatable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()

    if not args.map:
        raise SystemExit("at least one --map ENTRY=ARCHIVE is required")

    exact, normalized = parse_maps(args.map)
    rows: dict[str, PanelRow] = {}
    league_rows = 0
    robustness_rows = 0
    for path in args.league_csv:
        league_rows += add_league_rows(path, rows, exact, normalized)
    for path in args.robustness_csv:
        robustness_rows += add_robustness_rows(path, rows, exact, normalized)

    metric_names = sorted({metric for row in rows.values() for metric in row.metrics})
    fieldnames = ["candidate", "archive"]
    for metric in metric_names:
        fieldnames.extend([f"{metric}_mean", f"{metric}_latest"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for archive in sorted(rows):
            panel = rows[archive]
            out: dict[str, str] = {"candidate": panel.candidate, "archive": panel.archive}
            for metric in metric_names:
                mean, latest = summarize(panel.metrics.get(metric, []))
                out[f"{metric}_mean"] = mean
                out[f"{metric}_latest"] = latest
            writer.writerow(out)

    lines = [
        "# Critic Metric Panel",
        "",
        f"- Output: `{args.output}`",
        f"- League CSVs: {len(args.league_csv)}",
        f"- Robustness CSVs: {len(args.robustness_csv)}",
        f"- Mapped league rows: {league_rows}",
        f"- Mapped robustness rows: {robustness_rows}",
        f"- Archive rows: {len(rows)}",
        "",
        "## Archives",
        "",
    ]
    for archive in sorted(rows):
        metric_count = sum(len(values) for values in rows[archive].metrics.values())
        lines.append(f"- `{archive}`: {metric_count} metric observations")

    report = "\n".join(lines) + "\n"
    print(report, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
