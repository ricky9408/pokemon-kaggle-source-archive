#!/usr/bin/env python3
"""Aggregate live gauntlet windows into a strategy drift dashboard.

Single replay-pool screens are noisy. This report compares candidate strength
across several live windows, highlights volatile spikes, and keeps the Pokemon
TCG strategy premise explicit: type pressure and deck family matter, but the
submission pair should be stable across the moving public ladder.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev


@dataclass(frozen=True)
class OpponentResult:
    key: str
    family: str
    weight: float
    win_rate: float
    teams: str

    @property
    def weighted_loss(self) -> float:
        return self.weight * (1.0 - self.win_rate)


@dataclass
class CandidateWindow:
    name: str
    weighted_win_rate: float | None = None
    opponents: dict[str, OpponentResult] = field(default_factory=dict)


@dataclass
class Window:
    path: Path
    label: str
    candidates: dict[str, CandidateWindow] = field(default_factory=dict)


@dataclass(frozen=True)
class CandidateEvidence:
    alias: str
    candidate: str
    family: str
    kind: str
    public_current: float | None
    public_best: float | None
    notes: str


def short_name(raw: str) -> str:
    name = Path(raw.strip()).name
    name = name.removeprefix("v")
    aliases = {
        "75_hiroingk_hammer_v57policy": "v75",
        "72_hiroingk_hammer": "v72",
        "77_tubotu_plain_alakazam_v75policy": "v77",
        "61_kadoraba_nighttime_hammer": "v61",
        "73_aitoai_hammer": "v73",
        "68_alakazam_hammer_mid_drawsoft": "v68",
        "53_alakazam_hammer_target": "v53",
        "39_alakazam_denpa": "v39",
        "48_alakazam_hammer_mid": "v48",
    }
    return aliases.get(name, f"v{name.split('_', 1)[0]}" if name[:2].isdigit() else name)


def alias_from_candidate(candidate: str) -> str | None:
    match = re.search(r"(?:^|-)v(\d+)(?:$|-)", candidate)
    if not match:
        return None
    return f"v{match.group(1)}"


def parse_optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    return float(value)


def load_evidence(path: Path | None) -> dict[str, CandidateEvidence]:
    if path is None:
        return {}
    evidence: dict[str, CandidateEvidence] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            alias = alias_from_candidate(row["candidate"])
            if alias is None:
                continue
            evidence[alias] = CandidateEvidence(
                alias=alias,
                candidate=row["candidate"],
                family=row["family"],
                kind=row["kind"],
                public_current=parse_optional_float(row.get("public_current")),
                public_best=parse_optional_float(row.get("public_best")),
                notes=row.get("notes", ""),
            )
    return evidence


def window_label(path: Path) -> str:
    match = re.search(r"replay_pool_(\d{8}T\d{4})_(.+)\.txt$", path.name)
    if not match:
        return path.stem
    stamp, suffix = match.groups()
    suffix = suffix.replace("_top10_confirm", "").replace("_", " ")
    return f"{stamp} {suffix}"


def parse_window(path: Path) -> Window:
    window = Window(path=path, label=window_label(path))
    current: CandidateWindow | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            current = CandidateWindow(name=short_name(line.removeprefix("Candidate ")))
            window.candidates[current.name] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            try:
                current.weighted_win_rate = float(line.split(",", 1)[1])
            except ValueError:
                pass
            continue
        if line.startswith(("opponent,", "forward ", "swapped ", "skipped,")):
            continue
        parts = line.split(",")
        if len(parts) < 8 or ":" not in parts[0]:
            continue
        try:
            key = parts[0]
            family = key.split(":", 1)[0]
            current.opponents[key] = OpponentResult(
                key=key,
                family=family,
                weight=float(parts[1]),
                win_rate=float(parts[6]),
                teams=",".join(parts[7:]),
            )
        except ValueError:
            continue
    return window


def format_rate(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def stability_score(values: list[float]) -> float:
    if not values:
        return 0.0
    avg = mean(values)
    spread = pstdev(values) if len(values) > 1 else 0.0
    floor = min(values)
    return 0.70 * avg + 0.30 * floor - 0.35 * spread


def public_risk_penalty(alias: str, evidence: dict[str, CandidateEvidence]) -> tuple[float, list[str]]:
    item = evidence.get(alias)
    if item is None:
        return 0.0, []
    penalty = 0.0
    reasons: list[str] = []
    if item.kind == "local-variant":
        penalty += 0.055
        reasons.append("local_variant")
    if item.family == "alakazam_battle_cage":
        penalty += 0.045
        reasons.append("battle_cage_public_miss_family")
    if item.kind == "submitted" and item.public_current is not None and item.public_current < 900:
        penalty += 0.120
        reasons.append("submitted_below_900")
    return penalty, reasons


def shell_key(alias: str, evidence: dict[str, CandidateEvidence]) -> str:
    item = evidence.get(alias)
    if item is None:
        return alias
    if item.candidate.startswith("hiroingk-hammer-"):
        return "hiroingk_hammer_b9bcfb3e10"
    if item.family == "alakazam_battle_cage":
        return "battle_cage_alakazam_family"
    return item.family


def family_coverage(candidate_windows: list[CandidateWindow]) -> dict[str, tuple[float, float, float]]:
    grouped: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for candidate in candidate_windows:
        for result in candidate.opponents.values():
            grouped[result.family].append((result.weight, result.win_rate))
    coverage: dict[str, tuple[float, float, float]] = {}
    for family, rows in grouped.items():
        total_weight = sum(weight for weight, _ in rows)
        if not total_weight:
            continue
        weighted_rate = sum(weight * rate for weight, rate in rows) / total_weight
        worst_weighted_loss = max(weight * (1.0 - rate) for weight, rate in rows)
        coverage[family] = (weighted_rate, total_weight, worst_weighted_loss)
    return coverage


def pair_family_score(
    left: str,
    right: str,
    windows: list[Window],
    candidate_scores: dict[str, float],
    evidence: dict[str, CandidateEvidence],
) -> tuple[float, int, list[str]]:
    values: list[float] = []
    blindspots: set[str] = set()
    for window in windows:
        left_result = window.candidates.get(left)
        right_result = window.candidates.get(right)
        opponent_keys = set()
        if left_result:
            opponent_keys.update(left_result.opponents)
        if right_result:
            opponent_keys.update(right_result.opponents)
        for key in opponent_keys:
            family = key.split(":", 1)[0]
            left_rate = left_result.opponents[key].win_rate if left_result and key in left_result.opponents else 0.0
            right_rate = right_result.opponents[key].win_rate if right_result and key in right_result.opponents else 0.0
            best = max(left_rate, right_rate)
            values.append(best)
            if best < 0.50:
                blindspots.add(family)
    avg_cover = mean(values) if values else 0.0
    base = max(candidate_scores[left], candidate_scores[right]) + 0.35 * min(candidate_scores[left], candidate_scores[right])
    left_shell = shell_key(left, evidence)
    right_shell = shell_key(right, evidence)
    same_family_penalty = 0.070 if left_shell == right_shell else 0.0
    left_public_penalty, _ = public_risk_penalty(left, evidence)
    right_public_penalty, _ = public_risk_penalty(right, evidence)
    score = (
        base
        + 0.08 * avg_cover
        - same_family_penalty
        - 0.015 * len(blindspots)
        - 0.50 * (left_public_penalty + right_public_penalty)
    )
    return score, len(blindspots), sorted(blindspots)[:5]


def render_report(paths: list[Path], evidence_path: Path | None, output: Path | None) -> str:
    windows = [parse_window(path) for path in paths]
    evidence = load_evidence(evidence_path)
    candidates = sorted({name for window in windows for name in window.candidates})
    by_candidate = {
        name: [window.candidates[name] for window in windows if name in window.candidates]
        for name in candidates
    }
    score_by_candidate: dict[str, float] = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# Strategy Drift Dashboard")
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
    lines.append("- Strategy premise: Pokemon TCG has no single strongest deck; stable pair coverage across type/family pressure beats one-window spikes.")
    lines.append("")
    lines.append("## Source Windows")
    lines.append("")
    for window in windows:
        lines.append(f"- `{window.path}`")
    if evidence_path:
        lines.append(f"- Candidate evidence: `{evidence_path}`")
    lines.append("")

    lines.append("## Candidate Drift")
    lines.append("")
    lines.append("| Candidate | Windows | Mean | Min | Max | Std Dev | Local Stability | Public Risk | Reset Fit | Risk Flags |")
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |")
    drift_rows = []
    for name in candidates:
        values = [item.weighted_win_rate for item in by_candidate[name] if item.weighted_win_rate is not None]
        if not values:
            continue
        score = stability_score(values)
        public_penalty, risk_flags = public_risk_penalty(name, evidence)
        reset_fit = score - public_penalty
        score_by_candidate[name] = reset_fit
        spread = pstdev(values) if len(values) > 1 else 0.0
        drift_rows.append((reset_fit, score, name, values, spread, public_penalty, risk_flags))
    for reset_fit, score, name, values, spread, public_penalty, risk_flags in sorted(drift_rows, reverse=True):
        flags = "; ".join(risk_flags) if risk_flags else "-"
        lines.append(
            f"| `{name}` | {len(values)} | {mean(values):.4f} | {min(values):.4f} | "
            f"{max(values):.4f} | {spread:.4f} | {score:.4f} | {public_penalty:.3f} | {reset_fit:.4f} | {flags} |"
        )
    lines.append("")

    lines.append("## Family Stress")
    lines.append("")
    for _, _, name, _, _, _, _ in sorted(drift_rows, reverse=True)[:8]:
        coverage = family_coverage(by_candidate[name])
        lines.append(f"### `{name}`")
        lines.append("")
        lines.append("| Opponent Family | Weighted Rate | Total Weight Seen | Worst Weighted Loss |")
        lines.append("| --- | ---: | ---: | ---: |")
        for family, (rate, total_weight, worst_loss) in sorted(
            coverage.items(),
            key=lambda item: (-item[1][2], item[0]),
        )[:8]:
            lines.append(f"| `{family}` | {rate:.4f} | {total_weight:.2f} | {worst_loss:.2f} |")
        lines.append("")

    lines.append("## Pair Stability")
    lines.append("")
    lines.append("| Pair | Pair Score | Shared Blindspot Families | Examples |")
    lines.append("| --- | ---: | ---: | --- |")
    pair_rows = []
    for index, left in enumerate(score_by_candidate):
        for right in list(score_by_candidate)[index + 1 :]:
            score, blind_count, blindspots = pair_family_score(left, right, windows, score_by_candidate, evidence)
            pair_rows.append((score, left, right, blind_count, blindspots))
    for score, left, right, blind_count, blindspots in sorted(pair_rows, reverse=True)[:12]:
        examples = ", ".join(f"`{family}`" for family in blindspots) if blindspots else "-"
        lines.append(f"| `{left}` + `{right}` | {score:.4f} | {blind_count} | {examples} |")
    lines.append("")

    lines.append("## Strategic Interpretation")
    lines.append("")
    if drift_rows:
        best = max(drift_rows)[2]
        lines.append(f"- Most stable single across these windows: `{best}`.")
    if pair_rows:
        best_pair = max(pair_rows)
        lines.append(f"- Most stable pair across these windows: `{best_pair[1]}` plus `{best_pair[2]}`.")
    lines.append("- Treat candidates with high max but low minimum as strategy probes, not reset anchors.")
    if evidence:
        lines.append("- Public-risk-adjusted reset fit penalizes submitted/public-miss families even when local drift is strong.")
    lines.append("- If the pre-reset top window changes sharply, rerun this report with the newest quick and confirmation logs before spending submissions.")
    report = "\n".join(lines) + "\n"
    if output:
        output.write_text(report, encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("gauntlets", nargs="+", type=Path)
    parser.add_argument("--candidate-evidence", type=Path, default=Path("strategy/reset_candidates_20260620.csv"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    print(render_report(args.gauntlets, args.candidate_evidence, args.output), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
