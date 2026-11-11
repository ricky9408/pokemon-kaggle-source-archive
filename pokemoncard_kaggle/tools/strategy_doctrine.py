#!/usr/bin/env python3
"""Generate a compact Pokemon TCG strategy doctrine from live evidence.

This report is intentionally above deck architecture. Pokemon TCG has no
permanent single-best deck because weakness, tempo, disruption, and pair
coverage rotate with the field. The doctrine turns current type pressure,
local broad/focus gauntlets, public priors, and blind spots into submit gates
and next research questions.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from strategy_pressure_router import (  # noqa: E402
    CandidateMeta,
    CandidateResult,
    candidate_alias,
    load_candidates,
    parse_gauntlet,
    parse_type_report,
    read_leaderboard,
)


BROAD_ANCHOR = 0.77
SOLID_FOCUS = 0.55
FOCUS_RISK = 0.50


@dataclass(frozen=True)
class CandidateDoctrine:
    alias: str
    meta: CandidateMeta | None
    broad: float | None
    focus: float | None
    role: str
    gate: str
    reason: str


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt(value: float | None) -> str:
    return "-" if value is None else f"{value:.4f}"


def read_weighted(result: CandidateResult | None) -> float | None:
    return None if result is None else result.weighted


def public_prior_risk(meta: CandidateMeta | None) -> str:
    if meta is None:
        return "unknown public prior"
    risks: list[str] = []
    family = meta.family.replace("-", "_")
    if meta.kind == "local-variant":
        risks.append("local variant")
    if family == "alakazam_battle_cage":
        risks.append("Battle Cage public-miss family")
    if meta.kind == "submitted":
        risks.append("already public-tested")
    if meta.public_current:
        risks.append(f"public current {meta.public_current}")
    if meta.public_best:
        risks.append(f"public best {meta.public_best}")
    return "; ".join(risks) or "acceptable public prior"


def classify_candidate(alias: str, meta: CandidateMeta | None, broad: float | None, focus: float | None) -> tuple[str, str, str]:
    family = meta.family.replace("-", "_") if meta else ""
    kind = meta.kind if meta else ""
    prior = public_prior_risk(meta)

    if kind == "submitted" and broad is not None and broad < BROAD_ANCHOR:
        return (
            "public-miss reference",
            "do not submit without new public-shape evidence",
            f"{prior}; local signal is not enough to overcome submitted miss.",
        )
    if kind == "local-variant" and family == "alakazam_battle_cage":
        return (
            "fallback-only",
            "require high-volume broad plus focus plus public-family recovery",
            f"{prior}; v39/v48 showed Battle Cage local strength can miss publicly.",
        )
    if broad is not None and broad >= BROAD_ANCHOR and focus is not None and focus >= SOLID_FOCUS:
        return (
            "first-slot anchor",
            "eligible if latest packet and pair selector agree",
            "covers the broad field while staying playable into Alakazam control.",
        )
    if focus is not None and focus < FOCUS_RISK:
        return (
            "research-only",
            "do not submit into Alakazam-heavy windows",
            "focus confirmation exposes a strategic blind spot.",
        )
    if broad is not None and broad >= BROAD_ANCHOR and (focus is None or focus < SOLID_FOCUS):
        return (
            "anti-Fighting spike",
            "eligible only if Fighting pressure dominates and pair covers control",
            "broad strength likely comes from Mega Lucario coverage; control focus is the gate.",
        )
    if focus is not None and focus >= SOLID_FOCUS and broad is not None and broad >= 0.70:
        return (
            "control hedge",
            "second-slot eligible when Alakazam lanes rise",
            "focus strength matters only if the pair still covers Fighting pressure.",
        )
    if family not in {"", "alakazam_hammer"} and broad is not None and broad >= 0.70:
        return (
            "diversity hedge",
            "second-slot eligible when pair correlation is the main risk",
            f"{prior}; useful when it covers a different failure mode than the first slot.",
        )
    return (
        "research or emergency fallback",
        "submit only with fresh packet promotion",
        f"{prior}; current evidence is not decisive.",
    )


def candidate_doctrines(
    broad: dict[str, CandidateResult],
    focus: dict[str, CandidateResult],
    metas: dict[str, CandidateMeta],
) -> list[CandidateDoctrine]:
    aliases = sorted(set(broad) | set(focus) | set(metas))
    doctrines: list[CandidateDoctrine] = []
    for alias in aliases:
        meta = metas.get(alias)
        broad_rate = read_weighted(broad.get(alias))
        focus_rate = read_weighted(focus.get(alias))
        role, gate, reason = classify_candidate(alias, meta, broad_rate, focus_rate)
        doctrines.append(CandidateDoctrine(alias, meta, broad_rate, focus_rate, role, gate, reason))
    return sorted(
        doctrines,
        key=lambda item: (
            -(item.broad if item.broad is not None else -1.0),
            -(item.focus if item.focus is not None else -1.0),
            item.alias,
        ),
    )


def top_lanes(clusters: list[dict[str, str]], limit: int = 8) -> list[str]:
    lines: list[str] = []
    for cluster in clusters[:limit]:
        lines.append(
            f"| {cluster['rank']} | {cluster['cluster']} | {cluster['weight']} | "
            f"{cluster['attacker_types']} | {cluster['weaknesses']} | {cluster['tactics']} |"
        )
    return lines


def parse_blindspot(path: Path | None) -> tuple[list[str], list[str]]:
    if path is None or not path.exists():
        return [], []
    family_rows: list[str] = []
    blindspot_rows: list[str] = []
    mode: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("## Family Loss Summary") or line.startswith("## Family Priorities"):
            mode = "family"
            continue
        if line.startswith("## Top Blindspots") or line.startswith("## Pair Blindspots"):
            mode = "blindspot"
            continue
        if line.startswith("## ") and mode:
            mode = None
            continue
        if not line.startswith("|") or line.startswith("| ---") or "Family" in line or "Window" in line:
            continue
        if mode == "family" and len(family_rows) < 6:
            family_rows.append(line)
        elif mode == "blindspot" and len(blindspot_rows) < 8:
            blindspot_rows.append(line)
    return family_rows, blindspot_rows


def strongest_pair_hint(doctrines: list[CandidateDoctrine]) -> str:
    scored: list[tuple[float, CandidateDoctrine]] = []
    for item in doctrines:
        if item.broad is None:
            continue
        focus = item.focus if item.focus is not None else 0.0
        role_bonus = 0.03 if item.role == "first-slot anchor" else 0.015 if item.role in {"anti-Fighting spike", "control hedge"} else 0.0
        scored.append((item.broad * 0.65 + focus * 0.35 + role_bonus, item))
    if not scored:
        return "No pair hint available; run broad/focus gauntlets and pair selector first."
    first = sorted(scored, key=lambda pair: pair[0], reverse=True)[0][1]
    first_family = first.meta.family if first.meta else ""
    hedges = [
        item
        for _score, item in sorted(scored, key=lambda pair: pair[0], reverse=True)
        if item.alias != first.alias and (not item.meta or item.meta.family != first_family or item.role == "diversity hedge")
    ]
    second = hedges[0] if hedges else next((item for _score, item in sorted(scored, key=lambda pair: pair[0], reverse=True) if item.alias != first.alias), None)
    if second is None:
        return f"Current single anchor is `{first.alias}`; pair diversity is unresolved."
    return (
        f"Current doctrine hint: `{first.alias}` first only if the decision packet agrees; "
        f"pair with `{second.alias}` when latest-two diversity is more valuable than a same-shell clone."
    )


def build_report(args: argparse.Namespace) -> str:
    rows, target, cutoff = read_leaderboard(args.leaderboard, args.team)
    type_summary, clusters = parse_type_report(args.type_report)
    broad = parse_gauntlet(args.broad)
    focus = parse_gauntlet(args.focus) if args.focus else {}
    metas = load_candidates(args.candidates)
    doctrines = candidate_doctrines(broad, focus, metas)
    family_rows, blindspot_rows = parse_blindspot(args.blindspot)

    lines: list[str] = []
    lines.append("# Pokemon TCG Strategy Doctrine")
    lines.append("")
    lines.append(f"Generated: {now_utc()}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()} / {platform.platform()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Doctrine premise: type balance prevents a permanent single strongest Pokemon TCG deck; current strategy must route around pressure lanes, weakness exposure, and latest-two diversity.")
    lines.append("")
    lines.append("## Current Public State")
    lines.append("")
    lines.append(f"- Leaderboard: `{args.leaderboard}`")
    if target:
        lines.append(f"- {args.team}: rank {target.get('Rank')}, score {target.get('Score')}, last submission {target.get('LastSubmissionDate')}")
    if cutoff:
        lines.append(f"- Top-10 cutoff: rank 10 {cutoff.get('TeamName')} at {cutoff.get('Score')}")
    lines.append(f"- Weighted attacker types: {type_summary.get('attacker_types', '-')}")
    lines.append(f"- Weighted exposed weaknesses: {type_summary.get('weaknesses', '-')}")
    lines.append(f"- Weighted tactics: {type_summary.get('tactics', '-')}")
    lines.append("")
    lines.append("## Live Strategy Lanes")
    lines.append("")
    lines.append("| Rank | Cluster | Weight | Attack Types | Weaknesses | Tactics |")
    lines.append("| ---: | --- | ---: | --- | --- | --- |")
    lines.extend(top_lanes(clusters))
    lines.append("")
    lines.append("## Doctrine Rules")
    lines.append("")
    lines.append("1. Treat type advantage as a lane selector, not a submission decision. A Psychic plan is attractive while Fighting/Mega Lucario dominates, but the same plan can lose to Dark exposure or Enhanced Hammer mirrors.")
    lines.append("2. Separate broad public-shape coverage from control-focus coverage. Broad strength without Alakazam focus is an anti-Fighting spike, not proof of a complete strategy.")
    lines.append("3. Protect the latest-two window through non-identical failure modes. Two same-shell Hammer policies need a large edge to beat one anchor plus one diversity hedge.")
    lines.append("4. Promote deck architecture only after the strategy lane is named. New cards should answer a specific lane such as Battle Cage, Nighttime Hammer, Lightning ramp, or Dragapult bench pressure.")
    lines.append("5. Reject local variants when public-family priors contradict them unless a fresh high-volume reset scout repairs that prior.")
    lines.append("")
    lines.append("## Candidate Gates")
    lines.append("")
    lines.append("| Candidate | Family | Kind | Broad | Focus | Role | Submit Gate |")
    lines.append("| --- | --- | --- | ---: | ---: | --- | --- |")
    for item in doctrines:
        meta = item.meta
        lines.append(
            f"| `{item.alias}` | {meta.family if meta else '-'} | {meta.kind if meta else '-'} | "
            f"{fmt(item.broad)} | {fmt(item.focus)} | {item.role} | {item.gate} |"
        )
    lines.append("")
    lines.append("## Pair Doctrine")
    lines.append("")
    lines.append(f"- {strongest_pair_hint(doctrines)}")
    lines.append("- Final submit order still belongs to the fresh reset decision packet; this doctrine explains which strategic gates that packet must satisfy.")
    lines.append("- If Fighting pressure remains dominant and control focus is tolerable, an anti-Fighting Hammer anchor can lead. If Alakazam control rises, the first slot must favor the control-stable policy even if broad is slightly lower.")
    lines.append("- The second slot should cover a different lane unless same-shell evidence is overwhelming after re-scout/reweight.")
    lines.append("")
    lines.append("## Blindspot Backlog")
    lines.append("")
    if family_rows:
        lines.append("| Rank | Family | Accumulated Pair Weighted Loss | Strategic Direction |")
        lines.append("| ---: | --- | ---: | --- |")
        lines.extend(family_rows)
        lines.append("")
    if blindspot_rows:
        lines.append("| Rank | Window | Opponent | Weight | Pair Rates | Weighted Loss | Best Non-Pair Lead | Teams |")
        lines.append("| ---: | --- | --- | ---: | --- | ---: | --- | --- |")
        lines.extend(blindspot_rows)
        lines.append("")
    if not family_rows and not blindspot_rows:
        lines.append("- No blindspot backlog supplied; run `tools/strategy_blindspot_backlog.py` after the pair selector.")
        lines.append("")
    lines.append("## Next Efficient Research")
    lines.append("")
    lines.append("1. At UTC reset, run the full reset refresh before any submit.")
    lines.append("2. If the packet splits broad and focus leaders, run one focused resolver instead of inventing a new deck.")
    lines.append("3. If a blindspot remains after pair selection, start with policy timing/action-priority experiments before deck architecture.")
    lines.append("4. Only move to a new architecture when the report names a lane and the local simulator proves it against current top-tier replays.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--type-report", type=Path, required=True)
    parser.add_argument("--broad", type=Path, required=True)
    parser.add_argument("--focus", type=Path)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--blindspot", type=Path)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
