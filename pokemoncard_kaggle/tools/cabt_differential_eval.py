#!/usr/bin/env python3
"""Run only candidate/baseline cabt games against shared controls."""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cabt_local_league import cabt_engine_lines, candidate_entry, entry_from_participant  # noqa: E402
from local_top_league import load_top_team_participants  # noqa: E402
from run_engine_parity_league import run_pair  # noqa: E402


def render(rows: list[dict], args: argparse.Namespace, labels: list[str]) -> str:
    lines = [
        "# cabt Differential Evaluation",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        f"- Candidate: `{args.candidate_label}`",
        f"- Baseline: `{args.baseline_label}`",
        f"- Shared controls: {len(labels) - 2}",
        f"- Games per pair: {args.games_per_pair}",
        f"- Total scheduled pairs: {2 * (len(labels) - 2) + 1}",
        "",
        "## Engine Provenance",
        "",
        *cabt_engine_lines(),
        "",
        "## Trust Status",
        "",
        "Diagnostic noninferiority evidence only; this does not forecast public rating.",
        "",
        "## Pair Results",
        "",
        "| Pair | Anchor W-L-D-U | Average steps | Errors |",
        "| --- | --- | ---: | ---: |",
    ]
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["pair"], []).append(row)
    for pair, group in sorted(grouped.items()):
        counts = Counter(row["anchor_result"] for row in group)
        steps = [int(row["steps"]) for row in group if str(row["steps"]).isdigit()]
        errors = sum(bool(row["error"]) for row in group)
        lines.append(
            f"| `{pair}` | {counts['win']}-{counts['loss']}-{counts['draw']}-{counts['unfinished']} | "
            f"{statistics.mean(steps) if steps else 0:.1f} | {errors} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scout-dir", type=Path, required=True)
    parser.add_argument("--top-limit", type=int, default=3)
    parser.add_argument("--selection-mode", choices=("rank", "diverse"), default="diverse")
    parser.add_argument("--scan-limit", type=int, default=20)
    parser.add_argument("--min-archetypes", type=int, default=3)
    parser.add_argument("--min-decks", type=int, default=3)
    parser.add_argument("--allow-partial-top", action="store_true")
    parser.add_argument("--candidate", action="append", default=[])
    parser.add_argument("--candidate-label", required=True)
    parser.add_argument("--baseline-label", required=True)
    parser.add_argument("--games-per-pair", type=int, default=2)
    parser.add_argument("--max-steps", type=int, default=600)
    parser.add_argument("--output-prefix", type=Path, required=True)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    participants = load_top_team_participants(
        args.scout_dir,
        args.top_limit,
        args.allow_partial_top,
        args.selection_mode,
        args.scan_limit,
        args.min_archetypes,
        args.min_decks,
    )
    entries = [entry_from_participant(participant) for participant in participants]
    entries.extend(candidate_entry(spec) for spec in args.candidate)
    by_label = {entry.label: entry for entry in entries}
    if len(by_label) != len(entries):
        raise ValueError("entry labels must be unique")
    if args.candidate_label not in by_label or args.baseline_label not in by_label:
        raise ValueError("candidate-label and baseline-label must identify loaded --candidate entries")
    targets = {args.candidate_label, args.baseline_label}
    controls = [entry for entry in entries if entry.label not in targets]
    rows: list[dict] = []
    for target_label in (args.candidate_label, args.baseline_label):
        target = by_label[target_label]
        for control in controls:
            rows.extend(run_pair("cabt", target, control, args.games_per_pair, args.max_steps, args.verbose))
    rows.extend(
        run_pair(
            "cabt",
            by_label[args.candidate_label],
            by_label[args.baseline_label],
            args.games_per_pair,
            args.max_steps,
            args.verbose,
        )
    )
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_prefix.with_suffix(".csv")
    md_path = args.output_prefix.with_suffix(".md")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["engine"])
        writer.writeheader()
        writer.writerows(rows)
    md_path.write_text(render(rows, args, list(by_label)), encoding="utf-8")
    print(md_path.read_text())
    return 0 if all(not row["error"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
