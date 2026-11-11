#!/usr/bin/env python3
"""Evaluate a saved action-ranker model on replay decision JSONL files."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from train_action_ranker import load_rows, pct, ranked_options, valid_single_label


@dataclass
class Stats:
    total: int = 0
    top1: int = 0
    top3: int = 0
    skipped: int = 0

    def add(self, label: int | None, ranking: list[int]) -> None:
        if label is None:
            self.skipped += 1
            return
        self.total += 1
        if ranking and ranking[0] == label:
            self.top1 += 1
        if label in ranking[:3]:
            self.top3 += 1


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def row_value(row: dict[str, Any], group: str) -> str:
    value = row.get(group)
    if value is None:
        return "unknown"
    return str(value)


def source_date(row: dict[str, Any]) -> str:
    match = re.search(r"(20\d{6})", str(row.get("source", "")))
    return match.group(1) if match else "unknown"


def group_key(row: dict[str, Any], group: str) -> str:
    if group == "source_date":
        return source_date(row)
    return row_value(row, group)


def filter_rows(rows: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    filtered = rows
    if args.path_contains:
        filtered = [row for row in filtered if args.path_contains in str(row.get("path", ""))]
    if args.context:
        contexts = set(args.context)
        filtered = [row for row in filtered if str(row.get("context")) in contexts]
    if args.team:
        teams = set(args.team)
        filtered = [row for row in filtered if str(row.get("team")) in teams]
    if args.opponent_archetype:
        opponents = set(args.opponent_archetype)
        filtered = [row for row in filtered if str(row.get("opponent_archetype")) in opponents]
    return filtered


def evaluate(rows: list[dict[str, Any]], weights: dict[str, float], groups: list[str]) -> tuple[Stats, dict[str, Counter[str]], dict[str, dict[str, Stats]]]:
    overall = Stats()
    confusion: dict[str, Counter[str]] = defaultdict(Counter)
    grouped: dict[str, dict[str, Stats]] = {group: defaultdict(Stats) for group in groups}
    for row in rows:
        label = valid_single_label(row)
        ranking = [] if label is None else ranked_options(weights, row)
        overall.add(label, ranking)
        for group in groups:
            grouped[group][group_key(row, group)].add(label, ranking)
        if label is not None and ranking:
            context = str(row.get("context"))
            if ranking[0] != label:
                selected = "; ".join(row.get("selected") or [str(label)])
                predicted = (row.get("options") or [""])[ranking[0]]
                confusion[context][f"public={selected} | model={predicted}"] += 1
    return overall, confusion, {group: dict(stats) for group, stats in grouped.items()}


def render_table(title: str, stats_by_key: dict[str, Stats], min_n: int, limit: int) -> list[str]:
    rows = [
        (key, stats)
        for key, stats in stats_by_key.items()
        if stats.total >= min_n
    ]
    rows.sort(key=lambda item: (item[1].top1 / item[1].total if item[1].total else -1, item[1].total))
    lines = [f"## {title}", "", "| Group | N | Top-1 | Top-3 | Skipped |", "| --- | ---: | ---: | ---: | ---: |"]
    for key, stats in rows[:limit]:
        lines.append(
            f"| `{key}` | {stats.total} | {pct(stats.top1, stats.total)} | "
            f"{pct(stats.top3, stats.total)} | {stats.skipped} |"
        )
    if not rows:
        lines.append("| - | 0 | 0.000 | 0.000 | 0 |")
    lines.append("")
    return lines


def render_report(
    args: argparse.Namespace,
    row_count: int,
    filtered_count: int,
    overall: Stats,
    grouped: dict[str, dict[str, Stats]],
    confusion: dict[str, Counter[str]],
) -> str:
    lines: list[str] = []
    lines.append("# Action Ranker Evaluation")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Model: `{args.model}`")
    lines.append(f"- Rows loaded: {row_count}")
    lines.append(f"- Rows after filters: {filtered_count}")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append(f"- Top-1: {overall.top1}/{overall.total} = {pct(overall.top1, overall.total)}")
    lines.append(f"- Top-3: {overall.top3}/{overall.total} = {pct(overall.top3, overall.total)}")
    lines.append(f"- Skipped: {overall.skipped}")
    lines.append("")
    for group, stats in grouped.items():
        title = group.replace("_", " ").title()
        lines.extend(render_table(title, stats, args.min_group_n, args.limit))

    lines.append("## Largest Mismatches")
    lines.append("")
    for context, counter in sorted(confusion.items(), key=lambda item: sum(item[1].values()), reverse=True)[: args.limit]:
        lines.append(f"### {context}")
        lines.append("")
        for text, count in counter.most_common(8):
            lines.append(f"- {count}: {text}")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/action_ranker_eval.md"))
    parser.add_argument("--group", action="append", default=["context", "archetype", "opponent_archetype", "team", "source_date"])
    parser.add_argument("--context", action="append", default=[])
    parser.add_argument("--team", action="append", default=[])
    parser.add_argument("--opponent-archetype", action="append", default=[])
    parser.add_argument("--path-contains", default="")
    parser.add_argument("--min-group-n", type=int, default=20)
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    filtered = filter_rows(rows, args)
    weights = load_model(args.model)
    overall, confusion, grouped = evaluate(filtered, weights, args.group)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        render_report(args, len(rows), len(filtered), overall, grouped, confusion),
        encoding="utf-8",
    )
    print(f"rows={len(rows)} filtered={len(filtered)} top1={pct(overall.top1, overall.total)} top3={pct(overall.top3, overall.total)} n={overall.total}")
    print(f"report={args.report_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
