#!/usr/bin/env python3
"""Build a non-leaky metrics panel from public-action mismatch reports.

The public-action gate is useful as a regression guard, but recent anchors show
that a pass is not necessarily a public-score predictor. This tool converts the
summary CSVs and markdown baseline-delta tables into an archive-keyed metrics
panel for `tools/backtest_loocv.py`.
"""

from __future__ import annotations

import argparse
import csv
import re
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
            raise SystemExit(f"--map must be LABEL=ARCHIVE, got: {value}")
        label, archive = value.split("=", 1)
        label = label.strip()
        archive = Path(archive.strip()).name
        exact[label] = archive
        normalized[normalize(label)] = archive
    return exact, normalized


@dataclass
class PanelRow:
    candidate: str
    archive: str
    metrics: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def add(self, metric: str, value: float | None) -> None:
        if value is not None:
            self.metrics[metric].append(value)


def candidate_for_archive(archive: str) -> str:
    return Path(archive).name.removeprefix("submission-").removesuffix(".tar.gz").replace("-", "_")


def mapped_archive(label: str, exact: dict[str, str], normalized: dict[str, str]) -> str | None:
    return exact.get(label) or normalized.get(normalize(label))


def add_summary_csv(path: Path, rows: dict[str, PanelRow], exact: dict[str, str], normalized: dict[str, str]) -> int:
    added = 0
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if (row.get("context") or "").strip() != "MAIN":
                continue
            total = parse_float(row.get("total"))
            if total is None or total <= 0:
                continue
            label = (row.get("label") or "").strip()
            archive = mapped_archive(label, exact, normalized)
            if not archive:
                continue
            panel = rows.setdefault(archive, PanelRow(candidate_for_archive(archive), archive))
            added += 1
            for column in ("total", "same", "diff", "invalid", "usable_total", "same_rate"):
                panel.add(f"action_{column}", parse_float(row.get(column)))
    return added


def parse_markdown_tables(path: Path) -> list[list[str]]:
    rows: list[list[str]] = []
    in_delta = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line == "## Baseline Delta":
            in_delta = True
            continue
        if in_delta and line.startswith("## ") and line != "## Baseline Delta":
            break
        if not in_delta or not line.startswith("|"):
            continue
        if "---" in line or "Label" in line:
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells:
            rows.append(cells)
    return rows


def add_markdown_delta(path: Path, rows: dict[str, PanelRow], exact: dict[str, str], normalized: dict[str, str]) -> int:
    added = 0
    headers = [
        "shared_decisions",
        "changed_from_baseline",
        "fixes",
        "regressions",
        "neutral_changes",
        "net",
        "weighted_fixes",
        "weighted_regressions",
        "weighted_neutral",
        "weighted_net",
    ]
    text = path.read_text(encoding="utf-8", errors="replace")
    baseline_match = re.search(r"Baseline label:\s+`([^`]+)`", text)
    baseline_label = baseline_match.group(1) if baseline_match else ""
    for cells in parse_markdown_tables(path):
        if len(cells) < 11:
            continue
        label = cells[0]
        archive = mapped_archive(label, exact, normalized)
        if not archive:
            continue
        panel = rows.setdefault(archive, PanelRow(candidate_for_archive(archive), archive))
        added += 1
        for column, raw_value in zip(headers, cells[1:11]):
            panel.add(f"action_delta_{column}", parse_float(raw_value))
        if baseline_label:
            # Numeric flag keeps reports that use the same baseline comparable.
            panel.add(f"action_delta_vs_{normalize(baseline_label)}", 1.0)
    return added


def summarize(values: list[float]) -> tuple[str, str]:
    if not values:
        return "", ""
    return f"{statistics.fmean(values):.6f}", f"{values[-1]:.6f}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate public-action mismatch metrics for LOOCV")
    parser.add_argument("--summary-csv", action="append", default=[], type=Path)
    parser.add_argument("--markdown", action="append", default=[], type=Path)
    parser.add_argument("--map", action="append", default=[], help="LABEL=ARCHIVE mapping; repeatable")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    if not args.map:
        raise SystemExit("at least one --map LABEL=ARCHIVE is required")
    exact, normalized = parse_maps(args.map)
    rows: dict[str, PanelRow] = {}
    summary_rows = 0
    delta_rows = 0
    for path in args.summary_csv:
        summary_rows += add_summary_csv(path, rows, exact, normalized)
    for path in args.markdown:
        delta_rows += add_markdown_delta(path, rows, exact, normalized)

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
        "# Public-Action Metric Panel",
        "",
        f"- Output: `{args.output}`",
        f"- Summary CSVs: {len(args.summary_csv)}",
        f"- Markdown reports: {len(args.markdown)}",
        f"- Mapped summary rows: {summary_rows}",
        f"- Mapped delta rows: {delta_rows}",
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
