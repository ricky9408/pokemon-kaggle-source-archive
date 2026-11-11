#!/usr/bin/env python3
"""Build one pre-reset strategy decision packet from existing research artifacts.

The other strategy tools answer narrower questions: type pressure, local
gauntlets, calibration, drift, and playbook. This tool fuses the latest outputs
into a compact gate audit so the submission decision is not scattered across
several files during the UTC reset window.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class LeaderboardRow:
    rank: int
    team: str
    score: float


@dataclass(frozen=True)
class CandidateRow:
    rank: int
    candidate: str
    score: float
    path: str
    family: str
    kind: str
    reasons: str


@dataclass(frozen=True)
class PairRow:
    rank: int
    first: str
    second: str
    score: float
    first_path: str
    second_path: str
    reasons: str


@dataclass
class GauntletCandidate:
    label: str
    weighted: float | None
    rates: dict[str, float]
    weights: dict[str, float]
    unfinished: int


def read_leaderboard(path: Path) -> list[LeaderboardRow]:
    rows: list[LeaderboardRow] = []
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            try:
                rows.append(
                    LeaderboardRow(
                        rank=int(row["Rank"]),
                        team=row["TeamName"],
                        score=float(row["Score"]),
                    )
                )
            except (KeyError, ValueError):
                continue
    return sorted(rows, key=lambda row: row.rank)


def parse_calibration(path: Path) -> tuple[list[CandidateRow], list[PairRow], dict[str, str]]:
    singles: list[CandidateRow] = []
    pairs: list[PairRow] = []
    recommendations: dict[str, str] = {}
    mode = "single"
    single_fields: list[str] | None = None
    pair_fields: list[str] | None = None

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("recommended_"):
            key, value = line.split("=", 1)
            recommendations[key] = value
            continue
        if line.startswith("rank,"):
            mode = "single"
            single_fields = next(csv.reader([line]))
            continue
        if line.startswith("pair_rank,"):
            mode = "pair"
            pair_fields = next(csv.reader([line]))
            continue
        if mode == "single" and single_fields and re.match(r"^\d+,", line):
            row = dict(zip(single_fields, next(csv.reader([line]))))
            try:
                singles.append(
                    CandidateRow(
                        rank=int(row["rank"]),
                        candidate=row["candidate"],
                        score=float(row["calibrated_score"]),
                        path=row["path"],
                        family=row["family"],
                        kind=row["kind"],
                        reasons=row["reasons"],
                    )
                )
            except (KeyError, ValueError):
                continue
        elif mode == "pair" and pair_fields and re.match(r"^\d+,", line):
            row = dict(zip(pair_fields, next(csv.reader([line]))))
            try:
                pairs.append(
                    PairRow(
                        rank=int(row["pair_rank"]),
                        first=row["first_candidate"],
                        second=row["second_candidate"],
                        score=float(row["pair_score"]),
                        first_path=row["first_path"],
                        second_path=row["second_path"],
                        reasons=row["reasons"],
                    )
                )
            except (KeyError, ValueError):
                continue
    return singles, pairs, recommendations


def parse_candidates(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        return {row["candidate"]: row for row in csv.DictReader(file) if row.get("candidate")}


def parse_gauntlet(path: Path) -> tuple[list[tuple[str, float, str]], list[GauntletCandidate]]:
    opponents: list[tuple[str, float, str]] = []
    candidates: list[GauntletCandidate] = []
    current: GauntletCandidate | None = None
    in_pool = False

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "opponent_pool":
            in_pool = True
            continue
        if line.startswith("Candidate "):
            in_pool = False
            label = Path(line.removeprefix("Candidate ").strip()).name
            current = GauntletCandidate(label=label, weighted=None, rates={}, weights={}, unfinished=0)
            candidates.append(current)
            continue
        if in_pool and re.match(r"^[a-z_]+,[0-9a-f]{10},", line):
            row = next(csv.reader([line]))
            if len(row) >= 8:
                opponents.append((f"{row[0]}:{row[1]}", float(row[6]), row[7]))
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            try:
                current.weighted = float(line.split(",", 1)[1])
            except ValueError:
                pass
            continue
        if re.match(r"^[a-z_]+:[0-9a-f]{10},", line):
            row = next(csv.reader([line]))
            if len(row) >= 7:
                key = row[0].replace("_", "-")
                try:
                    current.weights[key] = float(row[1])
                    current.rates[key] = float(row[6])
                    current.unfinished += int(row[5])
                except ValueError:
                    continue
    return opponents, sorted(candidates, key=lambda item: (-(item.weighted or 0.0), item.label))


def extract_type_lines(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    keep_prefixes = (
        "- Weighted attacker types:",
        "- Weighted exposed weaknesses:",
        "- Weighted tactical tags:",
        "- Current type-edge shortlist:",
    )
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(keep_prefixes):
            lines.append(line)
    return lines


def version_token(text: str) -> str | None:
    matches = re.findall(r"(?<![a-z0-9])v\d+(?![a-z0-9])", text.lower())
    return matches[-1] if matches else None


def compact_token(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def token_match(left: str, right: str) -> bool:
    left_version = version_token(left)
    right_version = version_token(right)
    if left_version or right_version:
        return left_version == right_version

    left_compact = compact_token(left)
    right_compact = compact_token(right)
    return bool(left_compact and right_compact and (left_compact in right_compact or right_compact in left_compact))


def gauntlet_for_candidate(candidate: str, gauntlet_rows: list[GauntletCandidate]) -> GauntletCandidate | None:
    matches = [row for row in gauntlet_rows if token_match(candidate, row.label)]
    if not matches:
        return None
    return max(matches, key=lambda row: row.weighted or 0.0)


def format_float(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def read_optional_float(row: dict[str, str], key: str) -> float | None:
    value = row.get(key, "")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def top_blindspots(row: GauntletCandidate, threshold: float = 0.5, limit: int = 4) -> list[str]:
    blind = [
        (key, row.weights.get(key, 0.0), rate)
        for key, rate in row.rates.items()
        if rate < threshold
    ]
    blind.sort(key=lambda item: (-item[1], item[0]))
    return [f"`{key}` {rate:.3f} (w {weight:.2f})" for key, weight, rate in blind[:limit]]


def best_focus_for_candidate(candidate: str, focus_rows: list[GauntletCandidate]) -> GauntletCandidate | None:
    return gauntlet_for_candidate(candidate, focus_rows)


def select_strategic_pair(
    pairs: list[PairRow],
    primary_gauntlets: list[GauntletCandidate],
    focus_gauntlets: list[GauntletCandidate],
    margin: float,
) -> tuple[PairRow | None, str]:
    if not pairs:
        return None, "no calibrated pair available"

    raw = pairs[0]
    raw_primary = gauntlet_for_candidate(raw.first, primary_gauntlets)
    raw_focus = best_focus_for_candidate(raw.first, focus_gauntlets)
    raw_primary_rate = raw_primary.weighted if raw_primary else None
    raw_focus_rate = raw_focus.weighted if raw_focus else None

    for candidate in pairs[1:]:
        if candidate.second != raw.second:
            continue
        if raw.score - candidate.score > margin:
            continue
        cand_primary = gauntlet_for_candidate(candidate.first, primary_gauntlets)
        cand_focus = best_focus_for_candidate(candidate.first, focus_gauntlets)
        cand_primary_rate = cand_primary.weighted if cand_primary else None
        cand_focus_rate = cand_focus.weighted if cand_focus else None
        if (
            cand_primary_rate is not None
            and raw_primary_rate is not None
            and cand_focus_rate is not None
            and raw_focus_rate is not None
            and cand_primary_rate >= raw_primary_rate - 0.002
            and cand_focus_rate >= raw_focus_rate + 0.050
        ):
            reason = (
                f"strategic gate selected `{candidate.first}` over calibrated `{raw.first}`: "
                f"pair score gap {raw.score - candidate.score:.4f}, "
                f"primary {cand_primary_rate:.4f} vs {raw_primary_rate:.4f}, "
                f"focus {cand_focus_rate:.4f} vs {raw_focus_rate:.4f}"
            )
            return candidate, reason
        if (
            cand_primary_rate is not None
            and raw_primary_rate is not None
            and cand_focus_rate is not None
            and raw_focus_rate is not None
            and cand_primary_rate >= raw_primary_rate - 0.015
            and cand_focus_rate >= raw_focus_rate + 0.100
        ):
            reason = (
                f"focus-dominant gate selected `{candidate.first}` over calibrated `{raw.first}`: "
                f"pair score gap {raw.score - candidate.score:.4f}, "
                f"primary {cand_primary_rate:.4f} vs {raw_primary_rate:.4f}, "
                f"focus {cand_focus_rate:.4f} vs {raw_focus_rate:.4f}"
            )
            return candidate, reason

    return raw, "calibrated pair passes strategic gates"


def render(args: argparse.Namespace) -> str:
    leaderboard = read_leaderboard(args.leaderboard)
    singles, pairs, recommendations = parse_calibration(args.calibration)
    candidate_meta = parse_candidates(args.candidates)
    opponents, gauntlets = parse_gauntlet(args.gauntlet_output)
    focus_outputs = [path for path in args.focus_output if path.exists()]
    focus_sections = [(path, *parse_gauntlet(path)) for path in focus_outputs]
    all_focus_gauntlets = [row for _, _, rows in focus_sections for row in rows]
    type_lines = extract_type_lines(args.type_report)

    team = next((row for row in leaderboard if row.team == args.team), None)
    top10 = leaderboard[9] if len(leaderboard) >= 10 else None
    raw_pair = pairs[0] if pairs else None
    best_pair, strategic_pair_reason = select_strategic_pair(
        pairs,
        gauntlets,
        all_focus_gauntlets,
        args.strategic_margin,
    )
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# Strategy Decision Packet")
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
    lines.append("- Decision premise: type advantage starts the search; strategy timing, public-family priors, local coverage, and latest-two diversity decide submissions.")
    lines.append("")

    lines.append("## Public State")
    lines.append("")
    lines.append(f"- Leaderboard source: `{args.leaderboard}`")
    if team:
        lines.append(f"- {args.team}: rank {team.rank}, score {team.score:.1f}")
    if top10:
        lines.append(f"- Top-10 cutoff: rank {top10.rank} {top10.team} at {top10.score:.1f}")
        if team:
            lines.append(f"- Gap to top 10: {top10.score - team.score:.1f}")
    if args.quota_note:
        lines.append(f"- Quota gate: {args.quota_note}")
    lines.append("")

    lines.append("## Decision")
    lines.append("")
    if best_pair:
        lines.append(
            f"- Strategic latest-two pair: `{best_pair.first_path}` then `{best_pair.second_path}` "
            f"(pair score {best_pair.score:.4f})."
        )
        lines.append(f"- Strategic gate: {strategic_pair_reason}.")
        lines.append(f"- Pair rationale: {best_pair.reasons}.")
        if raw_pair and raw_pair != best_pair:
            lines.append(
                f"- Raw calibrated pair was `{raw_pair.first_path}` then `{raw_pair.second_path}` "
                f"(pair score {raw_pair.score:.4f})."
            )
    if recommendations:
        lines.append(
            f"- Raw single recommendation from calibration: `{recommendations.get('recommended_first', '-')}` "
            f"then `{recommendations.get('recommended_second', '-')}`."
        )
    lines.append("- Submit only after the UTC quota reset and after rerunning this packet on the immediate pre-reset scout.")
    lines.append("")

    lines.append("## Strategic Pressure")
    lines.append("")
    if type_lines:
        lines.extend(type_lines)
    else:
        lines.append("- No type-pressure report supplied.")
    lines.append("")

    lines.append("## Candidate Gates")
    lines.append("")
    lines.append("| Rank | Candidate | Calibrated | Local Confirm | Family | Kind | Gate Notes |")
    lines.append("| ---: | --- | ---: | ---: | --- | --- | --- |")
    for row in singles[:8]:
        meta = candidate_meta.get(row.candidate, {})
        gauntlet = gauntlet_for_candidate(row.candidate, gauntlets)
        local_confirm = gauntlet.weighted if gauntlet else read_optional_float(meta, "replay_win_rate")
        notes = []
        if "weak_family_public_prior" in row.reasons or "family_floor_penalty" in row.reasons:
            notes.append("public-family risk")
        if meta.get("kind") == "local-variant":
            notes.append("local-only variant")
        if gauntlet is None and local_confirm is not None:
            notes.append("ledger local value, not in supplied confirmation")
        if gauntlet and gauntlet.unfinished:
            notes.append(f"{gauntlet.unfinished} unfinished games")
        blindspots = top_blindspots(gauntlet) if gauntlet else []
        if blindspots:
            notes.append("blindspots " + "; ".join(blindspots))
        if not notes:
            notes.append("passes current gates")
        lines.append(
            f"| {row.rank} | `{row.candidate}` | {row.score:.4f} | {format_float(local_confirm)} | "
            f"{row.family} | {row.kind} | {'; '.join(notes)} |"
        )
    lines.append("")

    if focus_outputs:
        lines.append("## Focus Gauntlets")
        lines.append("")
        for path, focus_opponents, focus_gauntlets in focus_sections:
            lines.append(f"### `{path}`")
            lines.append("")
            lines.append("| Candidate | Weighted Win Rate | Notes |")
            lines.append("| --- | ---: | --- |")
            for focus in focus_gauntlets:
                blindspots = top_blindspots(focus)
                note = "passes focus gates" if not blindspots else "blindspots " + "; ".join(blindspots)
                lines.append(f"| `{focus.label}` | {format_float(focus.weighted)} | {note} |")
            if focus_opponents:
                top_focus = ", ".join(f"`{key}` {weight:.2f}" for key, weight, _ in focus_opponents[:5])
                lines.append("")
                lines.append(f"- Focus opponent weights: {top_focus}.")
            lines.append("")

    lines.append("## Top Opponent Weights")
    lines.append("")
    lines.append("| Opponent | Weight | Teams |")
    lines.append("| --- | ---: | --- |")
    for key, weight, teams in opponents[:12]:
        lines.append(f"| `{key}` | {weight:.2f} | {teams} |")
    lines.append("")

    lines.append("## Pair Alternatives")
    lines.append("")
    lines.append("| Rank | Pair | Score | Reason |")
    lines.append("| ---: | --- | ---: | --- |")
    for row in pairs[:8]:
        lines.append(f"| {row.rank} | `{row.first}` + `{row.second}` | {row.score:.4f} | {row.reasons} |")
    lines.append("")

    lines.append("## Reset Runbook")
    lines.append("")
    lines.append("1. Run `date -u` and verify the UTC date has reached the reset window.")
    lines.append("2. Refresh Kaggle submissions and leaderboard with `uv run kaggle ...`.")
    lines.append("3. Re-scout top replays and rerun the quick plus confirmation gauntlets.")
    lines.append("4. Rerun calibration and this decision packet.")
    lines.append("5. Submit only if quota is open and the latest packet still recommends the pair.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", required=True, type=Path)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--calibration", required=True, type=Path)
    parser.add_argument("--gauntlet-output", required=True, type=Path)
    parser.add_argument("--focus-output", action="append", type=Path, default=[])
    parser.add_argument("--type-report", type=Path)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--quota-note", default="")
    parser.add_argument("--strategic-margin", type=float, default=0.002)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
