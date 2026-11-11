#!/usr/bin/env python3
"""Compare two policy casebook CSVs and surface overcorrections.

The casebook miner shows repeated public-vs-local decision gaps. This comparer
answers the next question: did a probe remove important gaps, or merely create
new ones somewhere else?
"""

from __future__ import annotations

import argparse
import csv
import os
import socket
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class CaseKey:
    context: str
    public_choice: str
    local_choice: str


@dataclass
class CaseRow:
    key: CaseKey
    count: int
    motifs: tuple[str, ...]
    teams: str


def load_casebook(path: Path) -> dict[CaseKey, CaseRow]:
    rows: dict[CaseKey, CaseRow] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            key = CaseKey(
                raw["context"].strip(),
                raw["public_choice"].strip(),
                raw["local_choice"].strip(),
            )
            rows[key] = CaseRow(
                key=key,
                count=int(raw["count"]),
                motifs=tuple(motif for motif in raw["motifs"].split(";") if motif),
                teams=raw.get("teams", ""),
            )
    return rows


def motif_counts(rows: dict[CaseKey, CaseRow]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows.values():
        for motif in row.motifs:
            counts[motif] += row.count
    return counts


def context_counts(rows: dict[CaseKey, CaseRow]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for row in rows.values():
        counts[row.key.context] += row.count
    return counts


def format_case(row: CaseRow, transition: tuple[int, int] | None = None) -> str:
    motifs = ", ".join(row.motifs) or "-"
    delta = "" if transition is None else f" ({transition[0]} -> {transition[1]})"
    return (
        f"`{row.key.context}` {row.key.public_choice} => {row.key.local_choice}"
        f"{delta}; count {row.count}; motifs {motifs}; teams {row.teams or '-'}"
    )


def rank_deltas(
    base: dict[CaseKey, CaseRow],
    candidate: dict[CaseKey, CaseRow],
) -> tuple[list[tuple[int, CaseRow, int]], list[tuple[int, CaseRow, int]], list[CaseRow], list[CaseRow]]:
    improved: list[tuple[int, CaseRow, int]] = []
    worsened: list[tuple[int, CaseRow, int]] = []
    for key, base_row in base.items():
        cand_count = candidate.get(key).count if key in candidate else 0
        if cand_count < base_row.count:
            improved.append((base_row.count - cand_count, base_row, cand_count))
        elif cand_count > base_row.count:
            worsened.append((cand_count - base_row.count, candidate[key], base_row.count))
    new_cases = [row for key, row in candidate.items() if key not in base]
    removed_cases = [row for key, row in base.items() if key not in candidate]
    improved.sort(key=lambda item: item[0], reverse=True)
    worsened.sort(key=lambda item: item[0], reverse=True)
    new_cases.sort(key=lambda row: row.count, reverse=True)
    removed_cases.sort(key=lambda row: row.count, reverse=True)
    return improved, worsened, new_cases, removed_cases


def render(args: argparse.Namespace, base: dict[CaseKey, CaseRow], candidate: dict[CaseKey, CaseRow]) -> str:
    improved, worsened, new_cases, removed_cases = rank_deltas(base, candidate)
    base_motifs = motif_counts(base)
    cand_motifs = motif_counts(candidate)
    base_contexts = context_counts(base)
    cand_contexts = context_counts(candidate)
    base_total = sum(row.count for row in base.values())
    cand_total = sum(row.count for row in candidate.values())
    delta_total = cand_total - base_total

    lines: list[str] = []
    lines.append("# Policy Casebook Compare")
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
    lines.append("- Strategy premise: a strategy probe is useful only if it removes repeated public-policy gaps without creating larger counter-gaps.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Baseline: `{args.baseline}` ({args.baseline_label})")
    lines.append(f"- Candidate: `{args.candidate}` ({args.candidate_label})")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Baseline mismatch-count mass: {base_total}")
    lines.append(f"- Candidate mismatch-count mass: {cand_total}")
    lines.append(f"- Delta: {delta_total:+d}")
    lines.append(f"- Shared cases: {len(set(base) & set(candidate))}")
    lines.append(f"- New candidate cases: {len(new_cases)}")
    lines.append(f"- Removed baseline cases: {len(removed_cases)}")
    if delta_total > 0 and new_cases:
        lines.append("- Verdict hint: candidate likely overcorrects; require game-win evidence before promotion.")
    elif delta_total < 0 and not new_cases:
        lines.append("- Verdict hint: candidate improves imitation cleanly; still require broad/focus gauntlets before promotion.")
    else:
        lines.append("- Verdict hint: mixed imitation change; inspect new and improved cases before drawing conclusions.")
    lines.append("")

    lines.append("## Motif Deltas")
    lines.append("")
    lines.append("| Motif | Baseline | Candidate | Delta |")
    lines.append("| --- | ---: | ---: | ---: |")
    for motif in sorted(set(base_motifs) | set(cand_motifs), key=lambda label: (cand_motifs[label] - base_motifs[label], cand_motifs[label]), reverse=True):
        lines.append(f"| `{motif}` | {base_motifs[motif]} | {cand_motifs[motif]} | {cand_motifs[motif] - base_motifs[motif]:+d} |")
    lines.append("")

    lines.append("## Context Deltas")
    lines.append("")
    lines.append("| Context | Baseline | Candidate | Delta |")
    lines.append("| --- | ---: | ---: | ---: |")
    for context in sorted(set(base_contexts) | set(cand_contexts), key=lambda label: (cand_contexts[label] - base_contexts[label], cand_contexts[label]), reverse=True):
        lines.append(f"| `{context}` | {base_contexts[context]} | {cand_contexts[context]} | {cand_contexts[context] - base_contexts[context]:+d} |")
    lines.append("")

    lines.append("## Biggest Improvements")
    lines.append("")
    for delta, row, cand_count in improved[: args.top]:
        lines.append(f"- -{delta}: {format_case(row, transition=(row.count, cand_count))}")
    if not improved:
        lines.append("- None")
    lines.append("")

    lines.append("## Biggest Worsenings")
    lines.append("")
    for delta, row, before in worsened[: args.top]:
        lines.append(f"- +{delta}: {format_case(row, transition=(before, row.count))}")
    if not worsened:
        lines.append("- None")
    lines.append("")

    lines.append("## New Candidate Cases")
    lines.append("")
    for row in new_cases[: args.top]:
        lines.append(f"- {format_case(row)}")
    if not new_cases:
        lines.append("- None")
    lines.append("")

    lines.append("## Removed Baseline Cases")
    lines.append("")
    for row in removed_cases[: args.top]:
        lines.append(f"- {format_case(row)}")
    if not removed_cases:
        lines.append("- None")
    lines.append("")

    lines.append("## Strategy Translation")
    lines.append("")
    lines.append("- Treat motif improvement as hypothesis quality, not ladder quality; public replay imitation must still survive local broad and focus simulation.")
    lines.append("- New high-count candidate cases are overcorrection warnings, especially when they reverse the same card pair the probe targeted.")
    lines.append("- Prefer probes that reduce a motif while keeping Battle Cage, Nighttime, and broad Fighting lanes stable.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--baseline-label", default="baseline")
    parser.add_argument("--candidate-label", default="candidate")
    parser.add_argument("--top", type=int, default=12)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args, load_casebook(args.baseline), load_casebook(args.candidate))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
