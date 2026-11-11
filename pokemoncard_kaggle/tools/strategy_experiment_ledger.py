#!/usr/bin/env python3
"""Summarize strategy experiments from replay-pool gauntlet outputs.

This is intentionally a lightweight evidence ledger. It turns several focused
and broad gauntlet text files into one markdown table so speculative type or
deck ideas can be promoted, rejected, or kept as conditional branches without
re-reading every raw simulation file.
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class CandidateResult:
    candidate: str
    weighted: float | None = None
    matchup_rates: dict[str, float] = field(default_factory=dict)


@dataclass
class Experiment:
    label: str
    path: Path
    results: dict[str, CandidateResult]


def short_candidate(path_text: str) -> str:
    parts = Path(path_text).parts
    if parts and parts[-1]:
        return parts[-1]
    return path_text


def parse_gauntlet(path: Path, label: str) -> Experiment:
    results: dict[str, CandidateResult] = {}
    current: CandidateResult | None = None
    in_candidate = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            candidate = short_candidate(line.removeprefix("Candidate ").strip())
            current = CandidateResult(candidate=candidate)
            results[candidate] = current
            in_candidate = True
            continue
        if line.startswith("skipped,"):
            in_candidate = False
            current = None
            continue
        if not in_candidate or current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            _, value = line.split(",", 1)
            current.weighted = float(value)
            continue
        if line.startswith("opponent,") or line.startswith("opponent_pool"):
            continue
        fields = line.split(",")
        if len(fields) >= 7:
            opponent = fields[0]
            try:
                win_rate = float(fields[6])
            except ValueError:
                continue
            current.matchup_rates[opponent] = win_rate
    return Experiment(label=label, path=path, results=results)


def parse_experiment(value: str) -> tuple[str, Path]:
    if ":" not in value:
        path = Path(value)
        return path.stem, path
    label, path_text = value.split(":", 1)
    return label, Path(path_text)


def parse_decision_override(value: str) -> tuple[str, tuple[str, str]]:
    parts = value.split(":", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("Decision override must be candidate:decision:reason")
    candidate, decision, reason = parts
    if not candidate or not decision or not reason:
        raise argparse.ArgumentTypeError("Decision override must include candidate, decision, and reason")
    return candidate, (decision, reason)


def classify_candidate(candidate: str, scores: dict[str, float | None]) -> tuple[str, str]:
    numeric = {label: score for label, score in scores.items() if score is not None}
    if not numeric:
        return "missing", "No weighted evidence parsed."
    broad_scores = [
        score
        for label, score in numeric.items()
        if any(token in label.lower() for token in ("broad", "current", "top", "live"))
    ]
    current = max(broad_scores) if broad_scores else max(numeric.values())
    alakazam = max((score for label, score in numeric.items() if "alakazam" in label.lower()), default=None)
    lucario = max((score for label, score in numeric.items() if "lucario" in label.lower()), default=None)

    if current >= 0.72:
        return "local confirm", "Broad current-pool result is strong enough to keep in calibrated consideration."
    if current >= 0.62:
        return "conditional local", "Broad result is usable only if fresh public pressure and public-family prior agree."
    if alakazam is not None and alakazam >= 0.57 and (lucario is None or lucario < 0.62):
        return "narrow counter", "Shows a focused Alakazam angle but lacks enough Lucario coverage for current meta."
    if current < 0.45:
        return "reject", "Broad current-pool result is too weak for further submission work."
    return "research only", "Keep as strategy evidence, not as a reset candidate."


def format_float(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def build_report(
    experiments: list[Experiment],
    output: Path | None,
    decision_overrides: dict[str, tuple[str, str]] | None = None,
) -> str:
    decision_overrides = decision_overrides or {}
    labels = [experiment.label for experiment in experiments]
    candidates = sorted({candidate for experiment in experiments for candidate in experiment.results})
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("# Strategy Experiment Ledger")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {getattr(os.uname(), 'nodename', 'unknown')}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: broad public-shape coverage beats isolated type advantage unless the focused edge is overwhelming.")
    lines.append("- Scope note: this ledger summarizes local experiments; it does not replace `tools/calibrated_candidate_rank.py` for final submit order.")
    lines.append("")
    lines.append("## Experiments")
    lines.append("")
    for experiment in experiments:
        lines.append(f"- `{experiment.label}`: `{experiment.path}`")
    lines.append("")
    lines.append("## Weighted Results")
    lines.append("")
    header = ["Candidate", *labels, "Decision", "Reason"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join(["---", *("---:" for _ in labels), "---", "---"]) + " |")
    for candidate in candidates:
        scores = {
            experiment.label: experiment.results.get(candidate).weighted if candidate in experiment.results else None
            for experiment in experiments
        }
        decision, reason = decision_overrides.get(candidate, classify_candidate(candidate, scores))
        score_cells = [format_float(scores[label]) for label in labels]
        lines.append(f"| `{candidate}` | " + " | ".join(score_cells + [decision, reason]) + " |")

    lines.append("")
    lines.append("## Strategic Rules")
    lines.append("")
    lines.append("- Reject a branch when type theory is strong but broad current-pool execution is weak; policy timing and setup consistency are part of the strategy.")
    lines.append("- A narrow Alakazam counter is not enough while Mega Lucario remains the largest winner cluster.")
    lines.append("- Promote a local variant only when broad current-pool evidence, focused branch evidence, and public-family prior all agree.")
    lines.append("- Preserve latest-two diversity unless a same-shell candidate has a very large broad edge.")
    report = "\n".join(lines) + "\n"
    if output:
        output.write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--experiment",
        action="append",
        required=True,
        help="Experiment in label:path form. The label is used as a table column.",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--decision",
        action="append",
        default=[],
        type=parse_decision_override,
        help="Override a candidate decision as candidate:decision:reason.",
    )
    args = parser.parse_args()

    experiments = []
    for item in args.experiment:
        label, path = parse_experiment(item)
        experiments.append(parse_gauntlet(path, label))
    print(build_report(experiments, args.output, dict(args.decision)), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
