#!/usr/bin/env python3
"""Route Pokemon TCG strategy work from pressure evidence.

This report sits above raw win-rate tables. It combines current type pressure,
public leaderboard state, local gauntlet performance, and candidate metadata to
decide which strategy lanes deserve submission, fallback, or research time.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import platform
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


WEAK_RATE = 0.55
STRONG_RATE = 0.75


@dataclass
class CandidateMeta:
    name: str
    path: str
    family: str
    kind: str
    public_current: str = ""
    public_best: str = ""
    public_floor: str = ""
    notes: str = ""


@dataclass
class CandidateResult:
    label: str
    source: str
    weighted: float | None = None
    opponents: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)
    teams: dict[str, str] = field(default_factory=dict)


def now_utc() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    value = str(value).strip()
    if not value or value == "-":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def read_leaderboard(path: Path, team: str) -> tuple[list[dict[str, str]], dict[str, str] | None, dict[str, str] | None]:
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            normalized = {key.lstrip("\ufeff"): value for key, value in row.items()}
            rows.append(normalized)
    target = None
    cutoff = None
    for row in rows:
        if row.get("TeamName") == team:
            target = row
        if row.get("Rank") == "10":
            cutoff = row
    return rows, target, cutoff


def candidate_alias(text: str) -> str:
    match = re.search(r"\bv(\d+)\b|v(\d+)_|-(v\d+)\b", text)
    if match:
        for group in match.groups():
            if group:
                if group.startswith("v"):
                    return group
                return f"v{group}"
    # Fall back to a readable stem.
    stem = Path(text).stem
    stem = stem.replace("submission-", "")
    return stem[:32]


def load_candidates(path: Path) -> dict[str, CandidateMeta]:
    metas: dict[str, CandidateMeta] = {}
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            alias = candidate_alias(f"{row.get('candidate','')} {row.get('path','')}")
            metas[alias] = CandidateMeta(
                name=row.get("candidate", alias),
                path=row.get("path", ""),
                family=row.get("family", ""),
                kind=row.get("kind", ""),
                public_current=row.get("public_current", ""),
                public_best=row.get("public_best", ""),
                public_floor=row.get("public_floor", ""),
                notes=row.get("notes", ""),
            )
    return metas


def parse_gauntlet(path: Path) -> dict[str, CandidateResult]:
    results: dict[str, CandidateResult] = {}
    current: CandidateResult | None = None
    in_candidate_table = False
    with path.open() as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("Candidate "):
                label = candidate_alias(line.removeprefix("Candidate ").strip())
                current = CandidateResult(label=label, source=str(path))
                results[label] = current
                in_candidate_table = False
                continue
            if current is None:
                continue
            if line.startswith("opponent,"):
                in_candidate_table = True
                continue
            if line.startswith("weighted_win_rate,"):
                current.weighted = parse_float(line.split(",", 1)[1])
                in_candidate_table = False
                continue
            if not in_candidate_table:
                continue
            parts = line.split(",")
            if len(parts) < 8:
                continue
            opponent = parts[0]
            weight = parse_float(parts[1]) or 0.0
            rate = parse_float(parts[6])
            teams = ",".join(parts[7:])
            if rate is None:
                continue
            current.opponents[opponent] = rate
            current.weights[opponent] = weight
            current.teams[opponent] = teams
    return results


def parse_type_report(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    summary: dict[str, str] = {}
    clusters: list[dict[str, str]] = []
    in_clusters = False
    with path.open() as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if line.startswith("- Weighted attacker types:"):
                summary["attacker_types"] = line.split(":", 1)[1].strip()
            elif line.startswith("- Weighted exposed weaknesses:"):
                summary["weaknesses"] = line.split(":", 1)[1].strip()
            elif line.startswith("- Weighted tactical tags:"):
                summary["tactics"] = line.split(":", 1)[1].strip()
            elif line.startswith("| Rank | Opponent Cluster |"):
                in_clusters = True
                continue
            elif in_clusters and line.startswith("## "):
                in_clusters = False
            elif in_clusters and line.startswith("|") and not line.startswith("| ---"):
                cells = [cell.strip() for cell in line.strip("|").split("|")]
                if len(cells) >= 6 and cells[0].isdigit():
                    clusters.append(
                        {
                            "rank": cells[0],
                            "cluster": cells[1],
                            "weight": cells[2],
                            "attacker_types": cells[3],
                            "weaknesses": cells[4],
                            "tactics": cells[5],
                        }
                    )
    return summary, clusters


def lane_for_opponent(opponent: str) -> str:
    archetype = opponent.split(":", 1)[0].replace("_", "-")
    if "mega-lucario" in archetype or "fighting" in archetype:
        return "Fighting pressure / Psychic answer"
    if "battle-cage" in archetype:
        return "Battle Cage Alakazam control"
    if "nighttime" in archetype:
        return "Nighttime Alakazam control"
    if "alakazam-hammer" in archetype:
        return "Hammer Alakazam control"
    if archetype == "alakazam":
        return "Plain Alakazam consistency"
    if "iono" in archetype or "lightning" in archetype:
        return "Lightning energy-ramp tail"
    if "dragapult" in archetype:
        return "Dragapult bench-pressure tail"
    if "crustle" in archetype:
        return "Crustle stall/heal tail"
    return "Other live tail"


def combine_results(broad: dict[str, CandidateResult], focus: dict[str, CandidateResult]) -> dict[str, dict[str, float | int | str]]:
    labels = sorted(set(broad) | set(focus))
    combined: dict[str, dict[str, float | int | str]] = {}
    for label in labels:
        broad_rate = broad.get(label).weighted if label in broad else None
        focus_rate = focus.get(label).weighted if label in focus else None
        all_rates: list[float] = []
        weak_spots: list[str] = []
        strong_spots: list[str] = []
        for source in (broad.get(label), focus.get(label)):
            if not source:
                continue
            for opponent, rate in source.opponents.items():
                weight = source.weights.get(opponent, 0.0)
                if weight < 1.0:
                    continue
                all_rates.append(rate)
                if rate < WEAK_RATE:
                    weak_spots.append(f"{opponent} {rate:.3f} (w {weight:.2f})")
                elif rate >= STRONG_RATE:
                    strong_spots.append(f"{opponent} {rate:.3f} (w {weight:.2f})")
        combined[label] = {
            "broad": broad_rate if broad_rate is not None else float("nan"),
            "focus": focus_rate if focus_rate is not None else float("nan"),
            "weak_count": len(weak_spots),
            "strong_count": len(strong_spots),
            "weak_examples": "; ".join(weak_spots[:3]) or "-",
            "strong_examples": "; ".join(strong_spots[:3]) or "-",
        }
    return combined


def axis_summary(results: dict[str, CandidateResult]) -> list[tuple[str, float, str, str]]:
    lanes: dict[str, float] = defaultdict(float)
    opponents: dict[str, list[str]] = defaultdict(list)
    bests: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for candidate, result in results.items():
        for opponent, rate in result.opponents.items():
            lane = lane_for_opponent(opponent)
            weight = result.weights.get(opponent, 0.0)
            lanes[lane] = max(lanes[lane], lanes[lane] + 0.0)
            if opponent not in opponents[lane]:
                opponents[lane].append(opponent)
                lanes[lane] += weight
            bests[lane].append((candidate, rate))
    rows = []
    for lane, weight in sorted(lanes.items(), key=lambda item: item[1], reverse=True):
        candidate_scores: dict[str, list[float]] = defaultdict(list)
        for candidate, rate in bests[lane]:
            candidate_scores[candidate].append(rate)
        ranked = sorted(
            ((cand, sum(vals) / len(vals)) for cand, vals in candidate_scores.items()),
            key=lambda item: item[1],
            reverse=True,
        )
        best = ", ".join(f"{cand} {score:.3f}" for cand, score in ranked[:3])
        rows.append((lane, weight, ", ".join(opponents[lane][:4]), best))
    return rows


def role_for(label: str, meta: CandidateMeta | None, broad: float | None, focus: float | None, weak_count: int) -> str:
    family = meta.family if meta else ""
    kind = meta.kind if meta else ""
    if kind == "submitted" or "battle_cage" in family and kind == "local-variant":
        return "fallback-only public-prior risk"
    if broad is not None and broad >= 0.80 and (focus is None or focus >= 0.55) and weak_count <= 3:
        return "first-slot anchor"
    if family not in {"alakazam_hammer", ""} and broad is not None and broad >= 0.70:
        return "second-slot diversity hedge"
    if broad is not None and broad >= 0.78:
        return "same-shell challenger"
    return "research or emergency fallback"


def fmt_float(value: float | str | int | None) -> str:
    if isinstance(value, float):
        if value != value:
            return "-"
        return f"{value:.4f}"
    if value is None:
        return "-"
    return str(value)


def build_report(args: argparse.Namespace) -> str:
    rows, target, cutoff = read_leaderboard(args.leaderboard, args.team)
    candidates = load_candidates(args.candidates)
    broad = parse_gauntlet(args.broad)
    focus = parse_gauntlet(args.focus) if args.focus else {}
    type_summary, type_clusters = parse_type_report(args.type_report)
    combined = combine_results(broad, focus)
    axes = axis_summary(broad)

    lines: list[str] = []
    lines.append("# Strategy Pressure Router")
    lines.append("")
    lines.append(f"Generated: {now_utc()}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {platform.node()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: type advantage chooses lanes; execution timing, public priors, and latest-two diversity choose submissions.")
    lines.append("")
    lines.append("## Public Snapshot")
    lines.append("")
    lines.append(f"- Leaderboard source: `{args.leaderboard}`")
    if target:
        lines.append(f"- {args.team}: rank {target.get('Rank')}, score {target.get('Score')}, last submission {target.get('LastSubmissionDate')}")
    if cutoff:
        lines.append(f"- Current top-10 cutoff: rank 10 {cutoff.get('TeamName')} at {cutoff.get('Score')}")
    lines.append("")
    lines.append("| Rank | Team | Score | Last Submission |")
    lines.append("| ---: | --- | ---: | --- |")
    for row in rows[:12]:
        lines.append(f"| {row.get('Rank')} | {row.get('TeamName')} | {row.get('Score')} | {row.get('LastSubmissionDate')} |")
    lines.append("")
    lines.append("## Type And Tactic Pressure")
    lines.append("")
    lines.append(f"- Weighted attacker types: {type_summary.get('attacker_types', '-')}")
    lines.append(f"- Weighted exposed weaknesses: {type_summary.get('weaknesses', '-')}")
    lines.append(f"- Weighted tactical tags: {type_summary.get('tactics', '-')}")
    lines.append("")
    lines.append("| Rank | Cluster | Weight | Pressure Read |")
    lines.append("| ---: | --- | ---: | --- |")
    for cluster in type_clusters[:10]:
        lines.append(
            f"| {cluster['rank']} | {cluster['cluster']} | {cluster['weight']} | "
            f"{cluster['attacker_types']} into weaknesses {cluster['weaknesses']}; {cluster['tactics']} |"
        )
    lines.append("")
    lines.append("## Strategic Lanes")
    lines.append("")
    lines.append("| Lane | Weight | Example Opponents | Current Best Local Routes |")
    lines.append("| --- | ---: | --- | --- |")
    for lane, weight, opponents, best in axes:
        lines.append(f"| {lane} | {weight:.2f} | `{opponents}` | {best} |")
    lines.append("")
    lines.append("## Candidate Routing")
    lines.append("")
    lines.append("| Candidate | Role | Family | Kind | Broad | Focus | Weak Spots | Strong Spots | Public Prior |")
    lines.append("| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |")
    for label, data in sorted(combined.items(), key=lambda item: (-(item[1]["broad"] if isinstance(item[1]["broad"], float) and item[1]["broad"] == item[1]["broad"] else -1), item[0])):
        meta = candidates.get(label)
        broad_rate = data["broad"] if isinstance(data["broad"], float) and data["broad"] == data["broad"] else None
        focus_rate = data["focus"] if isinstance(data["focus"], float) and data["focus"] == data["focus"] else None
        weak_count = int(data["weak_count"])
        role = role_for(label, meta, broad_rate, focus_rate, weak_count)
        prior = "-"
        if meta:
            public_bits = []
            if meta.public_current:
                public_bits.append(f"current {meta.public_current}")
            if meta.public_best:
                public_bits.append(f"best {meta.public_best}")
            if meta.public_floor:
                public_bits.append(f"floor {meta.public_floor}")
            prior = ", ".join(public_bits) or "-"
        lines.append(
            f"| `{label}` | {role} | {meta.family if meta else '-'} | {meta.kind if meta else '-'} | "
            f"{fmt_float(data['broad'])} | {fmt_float(data['focus'])} | {data['weak_count']} | {data['strong_count']} | {prior} |"
        )
    lines.append("")
    lines.append("## Route Decisions")
    lines.append("")
    broad_ranked = sorted(
        (
            (label, data["broad"])
            for label, data in combined.items()
            if isinstance(data["broad"], float) and data["broad"] == data["broad"]
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    focus_ranked = sorted(
        (
            (label, data["focus"])
            for label, data in combined.items()
            if isinstance(data["focus"], float) and data["focus"] == data["focus"]
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    if broad_ranked:
        broad_label, broad_value = broad_ranked[0]
        if focus_ranked:
            focus_label, focus_value = focus_ranked[0]
            if broad_label == focus_label:
                lines.append(
                    f"- Anchor lane: `{broad_label}` currently leads both broad coverage ({broad_value:.4f}) "
                    f"and Alakazam-control focus ({focus_value:.4f}); keep it first unless the reset scout moves."
                )
            else:
                lines.append(
                    f"- Anchor lane: `{broad_label}` leads broad coverage ({broad_value:.4f}), while "
                    f"`{focus_label}` leads Alakazam-control focus ({focus_value:.4f}); use the pair selector "
                    "and decision packet to arbitrate this split."
                )
        else:
            lines.append(f"- Anchor lane: `{broad_label}` currently leads broad coverage ({broad_value:.4f}).")
    else:
        lines.append("- Anchor lane: no broad gauntlet leader was available; rerun the broad screen before submitting.")
    lines.append("- Diversity lane: prefer v77 over same-shell v72/v82 when the pair objective needs a second pressure surface rather than another hiroingk Hammer clone.")
    lines.append("- Kadoraba lane: use v61 only if Nighttime/Kadoraba pressure rises enough to offset its current Hammer and Battle Cage blind spots.")
    lines.append("- Type-theory lane: Dark/Grass/Fighting counter decks need simulation proof before promotion; type weakness alone is not enough in this card pool.")
    lines.append("- Public-prior lane: keep Battle Cage local variants fallback-only until public-family evidence recovers from v39/v48 misses.")
    lines.append("")
    lines.append("## Next Efficient Tests")
    lines.append("")
    lines.append("1. At reset, refresh leaderboard/submissions and run `tools/live_window_audit.py` against the latest scout.")
    lines.append("2. If action is `reweight-existing`, regenerate this router plus broad and Alakazam-focus gauntlets before submitting.")
    lines.append("3. If action is `rescout`, scout top 12 first, then run broad top-weight and control-focus screens.")
    lines.append("4. Promote a new deck architecture only when it improves a named strategic lane and survives public-prior checks.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--type-report", type=Path, required=True)
    parser.add_argument("--broad", type=Path, required=True)
    parser.add_argument("--focus", type=Path)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report(args)
    if args.output:
        args.output.write_text(report)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
