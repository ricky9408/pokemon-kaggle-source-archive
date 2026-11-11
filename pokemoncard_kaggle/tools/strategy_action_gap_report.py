#!/usr/bin/env python3
"""Convert action-comparison logs into a tactical strategy report."""

from __future__ import annotations

import argparse
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class CompareLog:
    path: Path
    label: str
    compared: int = 0
    counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    examples: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))


def label_from_path(path: Path) -> str:
    name = path.stem
    match = re.search(r"action_compare_\d{8}T\d+_(.+)$", name)
    return match.group(1) if match else name


def parse_log(path: Path) -> CompareLog:
    log = CompareLog(path=path, label=label_from_path(path))
    current_context: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip()
        if line.startswith("valid compared decisions:"):
            log.compared = int(line.rsplit(":", 1)[1].strip())
            continue
        match = re.match(r"^([A-Z_]+) (same|diff) (\d+)$", line)
        if match:
            context, same, count = match.groups()
            log.counts[(context, same)] += int(count)
            continue
        if line.startswith("CTX "):
            current_context = line.removeprefix("CTX ").strip()
            continue
        if current_context and line.strip():
            log.examples[current_context].append(line.strip())
    return log


def diff_rate(log: CompareLog, context: str) -> float:
    diff = log.counts[(context, "diff")]
    same = log.counts[(context, "same")]
    total = diff + same
    return diff / total if total else 0.0


def option_names(text: str) -> list[str]:
    return re.findall(r"([A-Za-z0-9’s{}é .-]+)\(\d+\)", text)


def count_cards(rows: list[str], side: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    marker = f"{side}="
    for row in rows:
        if marker not in row:
            continue
        segment = row.split(marker, 1)[1]
        if side == "their" and " ours=" in segment:
            segment = segment.split(" ours=", 1)[0]
        for name in option_names(segment):
            cleaned = " ".join(name.split())
            if cleaned:
                counts[cleaned] += 1
    return counts


def theme_counts(log: CompareLog) -> Counter[str]:
    themes: Counter[str] = Counter()
    all_examples = "\n".join(line for rows in log.examples.values() for line in rows)
    if re.search(r"their=\[[^\]]*\] \[\] ours=\[[^\]]+\]", all_examples):
        themes["over-benching optional setup"] += 1
    if "their=[1] ['1:NO'] ours=[0] ['0:YES']" in all_examples:
        themes["over-activating optional abilities"] += 1
    if "Boss’s Orders" in all_examples or "Enhanced Hammer" in all_examples:
        themes["disruption timing mismatch"] += 1
    if "Dudunsparce" in all_examples and ("Kadabra" in all_examples or "Alakazam" in all_examples):
        themes["engine draw versus evolution search tension"] += 1
    if "Spectrier" in all_examples or "Fan Rotom" in all_examples or "Fezandipiti" in all_examples:
        themes["utility-pokemon priority mismatch"] += 1
    if "TO_DECK" in log.examples:
        themes["deck-return cardinality mismatch"] += 1
    return themes


def render(logs: list[CompareLog], output: Path | None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Strategy Action Gap Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: deck-list mimicry is incomplete; policy timing, optional actions, and search priorities decide games inside the same type shell.")
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    for log in logs:
        lines.append(f"- `{log.path}`")
    lines.append("")

    lines.append("## Decision Agreement")
    lines.append("")
    lines.append("| Log | Compared | Main Diff | To-Hand Diff | Setup Bench Diff | Activate Diff | Highest Gap |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for log in logs:
        contexts = sorted({context for context, _ in log.counts})
        highest = max(contexts, key=lambda context: diff_rate(log, context), default="-")
        highest_text = "-" if highest == "-" else f"{highest} {diff_rate(log, highest):.1%}"
        lines.append(
            f"| `{log.label}` | {log.compared} | {diff_rate(log, 'MAIN'):.1%} | "
            f"{diff_rate(log, 'TO_HAND'):.1%} | {diff_rate(log, 'SETUP_BENCH_POKEMON'):.1%} | "
            f"{diff_rate(log, 'ACTIVATE'):.1%} | {highest_text} |"
        )
    lines.append("")

    lines.append("## Repeated Tactical Themes")
    lines.append("")
    combined_themes: Counter[str] = Counter()
    for log in logs:
        combined_themes.update(theme_counts(log))
    for theme, count in combined_themes.most_common():
        lines.append(f"- {theme}: seen in {count} comparison log(s).")
    lines.append("")

    lines.append("## Search And Action Priority Signals")
    lines.append("")
    for log in logs:
        lines.append(f"### `{log.label}`")
        lines.append("")
        for context in ("TO_HAND", "MAIN", "TO_BENCH", "SETUP_BENCH_POKEMON", "ACTIVATE", "TO_DECK", "SWITCH", "EVOLVE"):
            rows = log.examples.get(context, [])
            if not rows:
                continue
            their_cards = count_cards(rows, "their")
            our_cards = count_cards(rows, "ours")
            their_top = ", ".join(f"{name} x{count}" for name, count in their_cards.most_common(5)) or "-"
            our_top = ", ".join(f"{name} x{count}" for name, count in our_cards.most_common(5)) or "-"
            lines.append(
                f"- `{context}` diff examples: ranker leans {their_top}; local policy leans {our_top}."
            )
        lines.append("")

    lines.append("## Strategic Translation")
    lines.append("")
    lines.append("- Exact ranker deck-list mimicry is not enough when MAIN, TO_HAND, setup, and optional-action gaps remain large; the public pilots' timing and search priorities are part of the strategy.")
    lines.append("- Utility-pokemon sequencing, disruption timing, and recovery windows should be tested as narrow policy changes before changing deck family.")
    lines.append("- Candidate-specific submit priority belongs in the current decision packet and pair selector; this action-gap report should only identify tactical differences that may explain local/public drift.")
    lines.append("- Policy edits should target one observed disagreement pattern at a time, then earn their place through broad and focus gauntlets before packaging.")
    report = "\n".join(lines) + "\n"
    if output:
        output.write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    logs = [parse_log(path) for path in args.logs]
    print(render(logs, args.output), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
