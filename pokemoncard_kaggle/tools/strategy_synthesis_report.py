#!/usr/bin/env python3
"""Synthesize current Pokemon TCG strategy evidence into one agenda.

This report is intentionally strategy-first. It combines current leaderboard
state, type pressure, ML action-ranker behavior, motif holdouts, PSRO/payoff
signals, and public-failure metadata so candidate work is driven by matchup
coverage and policy quality before deck architecture.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


TEAM_NAME = "GarlicToday"


@dataclass(frozen=True)
class LeaderboardState:
    path: Path
    team_rank: int | None
    team_score: float | None
    cutoff_team: str
    cutoff_score: float | None
    top_rows: list[tuple[int, str, float, str]]


@dataclass(frozen=True)
class PressureLane:
    rank: int
    key: str
    teams: str
    weight: float
    attacker_types: str
    weaknesses: str
    tactics: str


@dataclass(frozen=True)
class RankerScore:
    source: Path
    top1: float | None
    top3: float | None
    rows: int | None


@dataclass(frozen=True)
class MotifScore:
    source: str
    total: int
    target_mass: int
    delta: int
    share: float


@dataclass(frozen=True)
class CandidateFailure:
    candidate: str
    family: str
    public_current: float
    notes: str


@dataclass(frozen=True)
class BacktestStatus:
    path: Path
    best_metric: str
    spearman: float | None
    kendall: float | None
    n: int | None
    required_missing: str
    trusted_count: int
    row_count: int


@dataclass(frozen=True)
class PimcStatus:
    path: Path
    lc: float | None
    lc_ci: str
    bias: float | None
    bias_ci: str
    df: float | None
    df_ci: str
    decision: str


@dataclass(frozen=True)
class PairGateStatus:
    path: Path
    submit_safe: bool
    blocker: str
    backtest_gate: str


@dataclass(frozen=True)
class PublicPolicyTarget:
    rank: int
    score: float
    gap: str
    archetype: str
    deck_hash: str
    anchor_tier: str
    count: int
    win_share: float
    episodes: int
    teams: int
    public_motif: str
    model_motif: str


def read_text(path: Path | None) -> str:
    if path is None:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def fmt_float(value: float | None, digits: int = 1) -> str:
    return "-" if value is None else f"{value:.{digits}f}"


def leaderboard_state(path: Path) -> LeaderboardState:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    top_rows: list[tuple[int, str, float, str]] = []
    team_rank: int | None = None
    team_score: float | None = None
    for idx, row in enumerate(rows, 1):
        rank = int(row.get("Rank") or idx)
        team = row.get("TeamName", "")
        score = float(row.get("Score") or 0.0)
        last = row.get("LastSubmissionDate", "")
        if idx <= 12:
            top_rows.append((rank, team, score, last))
        if team == TEAM_NAME:
            team_rank = rank
            team_score = score
    cutoff_team = rows[9].get("TeamName", "") if len(rows) >= 10 else ""
    cutoff_score = float(rows[9].get("Score") or 0.0) if len(rows) >= 10 else None
    return LeaderboardState(path=path, team_rank=team_rank, team_score=team_score, cutoff_team=cutoff_team, cutoff_score=cutoff_score, top_rows=top_rows)


def parse_pressure_lanes(path: Path | None, limit: int) -> tuple[str, str, list[PressureLane]]:
    text = read_text(path)
    attacker = "-"
    weaknesses = "-"
    for line in text.splitlines():
        if line.startswith("- Weighted attacker types:"):
            attacker = line.split(":", 1)[1].strip()
        elif line.startswith("- Weighted exposed weaknesses:"):
            weaknesses = line.split(":", 1)[1].strip()
    lanes: list[PressureLane] = []
    row_re = re.compile(r"^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\(([^)]*)\)\s*\|\s*([0-9.]+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|")
    for line in text.splitlines():
        match = row_re.match(line)
        if not match:
            continue
        lanes.append(
            PressureLane(
                rank=int(match.group(1)),
                key=match.group(2),
                teams=match.group(3).strip(),
                weight=float(match.group(4)),
                attacker_types=match.group(5).strip(),
                weaknesses=match.group(6).strip(),
                tactics=match.group(7).strip(),
            )
        )
        if len(lanes) >= limit:
            break
    return attacker, weaknesses, lanes


def parse_ranker(path: Path | None) -> RankerScore | None:
    if path is None:
        return None
    text = read_text(path)
    top1 = top3 = None
    rows = None
    overall = re.search(r"Top-1:\s+\d+/\d+\s+=\s+([0-9.]+).*?Top-3:\s+\d+/\d+\s+=\s+([0-9.]+)", text, re.S)
    if overall:
        top1 = float(overall.group(1))
        top3 = float(overall.group(2))
    holdout = re.search(r"Overall top-1:\s+\d+/\d+\s+=\s+([0-9.]+).*?Overall top-3:\s+\d+/\d+\s+=\s+([0-9.]+)", text, re.S)
    if holdout:
        top1 = float(holdout.group(1))
        top3 = float(holdout.group(2))
    row_match = re.search(r"Rows loaded:\s+(\d+)|rows=(\d+)", text)
    if row_match:
        rows = int(next(value for value in row_match.groups() if value))
    return RankerScore(source=path, top1=top1, top3=top3, rows=rows)


def parse_motif_scores(path: Path | None) -> list[MotifScore]:
    text = read_text(path)
    scores: list[MotifScore] = []
    row_re = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*([+-]?\d+)\s*\|\s*([0-9.]+)\s*\|")
    for line in text.splitlines():
        match = row_re.match(line)
        if not match:
            continue
        scores.append(
            MotifScore(
                source=match.group(1),
                total=int(match.group(2)),
                target_mass=int(match.group(4)),
                delta=int(match.group(5)),
                share=float(match.group(6)),
            )
        )
    return scores


def parse_psro(path: Path | None) -> tuple[str, str, list[str]]:
    text = read_text(path)
    pair = "-"
    metrics = "-"
    reasons: list[str] = []
    for line in text.splitlines():
        if line.startswith("- Pair aliases:"):
            pair = line.split(":", 1)[1].strip()
        elif line.startswith("- Weighted coverage:"):
            metrics = line.removeprefix("- ").strip()
        elif line.startswith("- Reasons:"):
            reasons.append(line.split(":", 1)[1].strip())
    return pair, metrics, reasons


def parse_failures(path: Path | None, floor: float) -> list[CandidateFailure]:
    if path is None:
        return []
    failures: list[CandidateFailure] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            public_current = parse_float(row.get("public_current"))
            if public_current is None or public_current >= floor:
                continue
            failures.append(
                CandidateFailure(
                    candidate=row.get("candidate", ""),
                    family=row.get("family", ""),
                    public_current=public_current,
                    notes=row.get("notes", ""),
                )
            )
    return sorted(failures, key=lambda item: item.public_current)


def parse_backtest_summary(path: Path | None) -> BacktestStatus | None:
    if path is None or not path.exists():
        return None
    rows: list[dict[str, str]] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    latest = [row for row in rows if row.get("public_target") == "latest_public"]
    scored = [
        row
        for row in latest
        if parse_float(row.get("spearman")) is not None
    ]
    if scored:
        best = max(scored, key=lambda row: parse_float(row.get("spearman")) or float("-inf"))
    elif rows:
        best = rows[0]
    else:
        best = {}
    trusted_count = sum(1 for row in rows if row.get("trusted") == "1")
    return BacktestStatus(
        path=path,
        best_metric=best.get("metric", "-"),
        spearman=parse_float(best.get("spearman")),
        kendall=parse_float(best.get("kendall")),
        n=int(best["n"]) if best.get("n", "").isdigit() else None,
        required_missing=best.get("required_missing", ""),
        trusted_count=trusted_count,
        row_count=len(rows),
    )


def parse_fidelity_report(path: Path | None) -> tuple[str, str, list[str]]:
    text = read_text(path)
    if not text:
        return "-", "-", []
    verdict = "-"
    cause = "-"
    bullets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("The local full-game engine does"):
            verdict = stripped
        elif stripped.startswith("Dominant cause:"):
            cause = stripped.removeprefix("Dominant cause:").strip()
        elif stripped.startswith("- ") and any(key in stripped for key in ("No trusted metric", "Gate remains", "Use public-anchor", "Do not use ordinary")):
            bullets.append(stripped)
    return verdict, cause, bullets[:5]


def parse_pimc(path: Path | None) -> PimcStatus | None:
    text = read_text(path)
    if not text or path is None:
        return None

    def line_value(label: str) -> str:
        pattern = re.compile(rf"^- {re.escape(label)}:\s*(.*)$", re.M)
        match = pattern.search(text)
        return match.group(1).strip() if match else ""

    return PimcStatus(
        path=path,
        lc=parse_float(line_value("Leaf correlation lc")),
        lc_ci=line_value("Leaf correlation 95% bootstrap CI") or "-",
        bias=parse_float(line_value("Bias b")),
        bias_ci=line_value("Bias 95% bootstrap CI") or "-",
        df=parse_float(line_value("Disambiguation factor df")),
        df_ci=line_value("Disambiguation factor 95% bootstrap CI") or "-",
        decision=line_value("Decision").replace("**", "") or "-",
    )


def parse_pair_gate(path: Path | None) -> PairGateStatus | None:
    text = read_text(path)
    if not text or path is None:
        return None
    submit_safe = "NO SUBMIT-SAFE PAIR" not in text
    blocker = "-"
    backtest_gate = "-"
    for line in text.splitlines():
        if line.startswith("- Blocker:"):
            blocker = line.split(":", 1)[1].strip()
        elif line.startswith("- Backtest gate:"):
            backtest_gate = line.split(":", 1)[1].strip()
    return PairGateStatus(path=path, submit_safe=submit_safe, blocker=blocker, backtest_gate=backtest_gate)


def parse_policy_gaps(path: Path | None, limit: int = 8) -> tuple[str, list[tuple[str, int, float]]]:
    text = read_text(path)
    if not text:
        return "-", []
    summary = "-"
    rows: list[tuple[str, int, float]] = []
    for line in text.splitlines():
        if line.startswith("- Targeted strategic gaps:"):
            summary = line.removeprefix("- ").strip()
            continue
        match = re.match(r"^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|\s*([0-9.]+)\s*\|", line)
        if match:
            rows.append((match.group(1), int(match.group(2)), float(match.group(3))))
            if len(rows) >= limit:
                break
    return summary, rows


def parse_public_policy_targets(path: Path | None, limit: int = 10) -> list[PublicPolicyTarget]:
    if path is None or not path.exists():
        return []
    targets: list[PublicPolicyTarget] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                target = PublicPolicyTarget(
                    rank=int(row.get("rank") or len(targets) + 1),
                    score=float(row.get("score") or 0.0),
                    gap=row.get("gap", ""),
                    archetype=row.get("archetype", ""),
                    deck_hash=row.get("deck_hash", ""),
                    anchor_tier=row.get("anchor_tier", ""),
                    count=int(row.get("count") or 0),
                    win_share=float(row.get("win_share") or 0.0),
                    episodes=int(row.get("lane_episodes") or 0),
                    teams=int(row.get("lane_teams") or 0),
                    public_motif=row.get("public_motif", ""),
                    model_motif=row.get("model_motif", ""),
                )
            except ValueError:
                continue
            targets.append(target)
            if len(targets) >= limit:
                break
    return targets


def lane_category(lane: PressureLane) -> str:
    key = lane.key
    if key.startswith("hops-trevenant"):
        return "Hop's Trevenant pressure"
    if "alakazam" in key:
        return "Alakazam control/mirror"
    if key.startswith("mega-lucario"):
        return "Fighting one-shot pressure"
    if key.startswith("festival"):
        return "Festival grass tempo"
    return "Other public pressure"


def strategy_priorities(lanes: list[PressureLane], motif_scores: list[MotifScore]) -> list[str]:
    by_category: dict[str, float] = {}
    examples: dict[str, list[str]] = {}
    for lane in lanes:
        category = lane_category(lane)
        by_category[category] = by_category.get(category, 0.0) + lane.weight
        examples.setdefault(category, []).append(f"`{lane.key}` {lane.weight:.2f}")
    motif_note = ""
    if motif_scores:
        best = min(motif_scores, key=lambda item: item.target_mass)
        base = motif_scores[0]
        motif_note = f" Engine-ability motif gate currently favors `{best.source}` ({best.target_mass} target mass vs {base.target_mass} baseline)."
    lines: list[str] = []
    for category, weight in sorted(by_category.items(), key=lambda item: -item[1])[:5]:
        example_text = ", ".join(examples[category][:3])
        if category == "Hop's Trevenant pressure":
            advice = "Prioritize pivot/energy/ability timing and avoid over-churning before attacks or recovery."
        elif category == "Alakazam control/mirror":
            advice = "Prioritize Hammer, Boss, Battle Cage/Nighttime, and search-order decisions before changing the deck shell."
        elif category == "Fighting one-shot pressure":
            advice = "Keep Psychic coverage available but verify it does not overfit away from the current Hop/Alakazam majority."
        elif category == "Festival grass tempo":
            advice = "Treat as a tail lane unless it rises into the top-10 pressure set."
        else:
            advice = "Scout before specializing."
        extra_note = motif_note if category in {"Hop's Trevenant pressure", "Alakazam control/mirror"} else ""
        lines.append(f"- **{category}** weight {weight:.2f}: {example_text}. {advice}{extra_note}")
    return lines


def evidence_hierarchy(backtest: BacktestStatus | None, pair_gate: PairGateStatus | None) -> list[str]:
    trusted = bool(backtest and backtest.trusted_count > 0)
    pair_safe = bool(pair_gate and pair_gate.submit_safe)
    lines = [
        "1. **Public anchors / exact public replays** are primary evidence. Candidate families need real GarlicToday public scores or fresh exact-hash top-window public replays before submit-safe promotion.",
        "2. **ML/RL imitation and motif reports** are policy-discovery evidence. They can propose code probes, but they do not prove ladder strength.",
        "3. **Local gauntlets, PSRO, and payoff matrices** are research-only until their metrics rank-correlate with public scores.",
        "4. **Replay-pool win rate is fenced** because the local full-game API cannot inject Kaggle replay seeds and therefore cannot reproduce public episodes move-for-move.",
    ]
    if not trusted or not pair_safe:
        lines.append("5. **Submit-facing status: closed.** No candidate pair should be uploaded until a backtest summary has `trusted=1` and the pair selector reports an actual submit-safe pair.")
    return lines


def render(args: argparse.Namespace) -> str:
    leaderboard = leaderboard_state(args.leaderboard)
    attacker_types, weaknesses, lanes = parse_pressure_lanes(args.type_report, args.lane_limit)
    rankers = [score for score in (parse_ranker(path) for path in args.ranker_report) if score]
    motif_scores = parse_motif_scores(args.motif_holdout)
    psro_pair, psro_metrics, psro_reasons = parse_psro(args.psro_report)
    failures = parse_failures(args.candidates, args.public_failure_floor)
    backtest = parse_backtest_summary(args.backtest_summary)
    fidelity_verdict, fidelity_cause, fidelity_bullets = parse_fidelity_report(args.fidelity_report)
    pimc = parse_pimc(args.pimc_report)
    pair_gate = parse_pair_gate(args.pair_selector)
    gap_summary, gap_rows = parse_policy_gaps(args.policy_gap_report)
    public_policy_targets = parse_public_policy_targets(args.public_anchor_policy_targets)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        "# Strategy Synthesis Report",
        "",
        f"Generated: {now}",
        "",
        "## Research Agent Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "- Strategic premise: Pokemon TCG is a type-balanced, non-transitive game; optimize strategy and policy population before deck architecture.",
        "- Game-theory lens: pressure lanes, best-response gaps, maximin/regret, diversity, and public-failure risk.",
        "",
        "## Source Evidence",
        "",
        f"- Leaderboard: `{leaderboard.path}`",
        f"- Type pressure: `{args.type_report}`",
        f"- Motif holdout: `{args.motif_holdout}`",
        f"- PSRO/payoff report: `{args.psro_report}`",
        f"- Candidate evidence: `{args.candidates}`",
    ]
    for ranker in rankers:
        lines.append(f"- Action-ranker report: `{ranker.source}`")
    if args.policy_gap_report:
        lines.append(f"- Policy-gap report: `{args.policy_gap_report}`")
    if args.public_anchor_policy_targets:
        lines.append(f"- Public-anchored policy targets: `{args.public_anchor_policy_targets}`")
    if args.fidelity_report:
        lines.append(f"- Replay-fidelity report: `{args.fidelity_report}`")
    if args.backtest_summary:
        lines.append(f"- Backtest summary: `{args.backtest_summary}`")
    if args.pimc_report:
        lines.append(f"- PIMC suitability report: `{args.pimc_report}`")
    if args.pair_selector:
        lines.append(f"- Pair selector: `{args.pair_selector}`")

    lines.extend(
        [
            "",
            "## Live Competitive State",
            "",
            f"- {TEAM_NAME}: rank {leaderboard.team_rank or '-'}, score {fmt_float(leaderboard.team_score)}",
            f"- Top-10 cutoff: `{leaderboard.cutoff_team}` at {fmt_float(leaderboard.cutoff_score)}",
            "",
            "| Rank | Team | Score | Last Submission |",
            "| ---: | --- | ---: | --- |",
        ]
    )
    for rank, team, score, last in leaderboard.top_rows:
        lines.append(f"| {rank} | {team} | {score:.1f} | {last} |")

    lines.extend(
        [
            "",
            "## Current Pressure Lanes",
            "",
            f"- Weighted attacker types: {attacker_types}",
            f"- Weighted exposed weaknesses: {weaknesses}",
            "",
            "| Rank | Lane | Weight | Teams | Types | Weaknesses | Tactics |",
            "| ---: | --- | ---: | --- | --- | --- | --- |",
        ]
    )
    for lane in lanes:
        lines.append(f"| {lane.rank} | `{lane.key}` | {lane.weight:.2f} | {lane.teams} | {lane.attacker_types} | {lane.weaknesses} | {lane.tactics} |")

    lines.extend(["", "## ML/RL Signals", ""])
    if rankers:
        lines.extend(["| Report | Top-1 | Top-3 | Rows |", "| --- | ---: | ---: | ---: |"])
        for ranker in rankers:
            lines.append(f"| `{ranker.source.name}` | {fmt_float(ranker.top1, 3)} | {fmt_float(ranker.top3, 3)} | {ranker.rows or '-'} |")
    else:
        lines.append("- No action-ranker reports supplied.")
    if motif_scores:
        lines.extend(["", "| Motif Source | Total Mismatch | Target Mass | Delta | Share |", "| --- | ---: | ---: | ---: | ---: |"])
        for score in motif_scores:
            lines.append(f"| `{score.source}` | {score.total} | {score.target_mass} | {score.delta:+d} | {score.share:.3f} |")
    if gap_rows:
        lines.extend(["", f"- Policy-gap summary: {gap_summary}", "", "| Gap Class | Count | Share |", "| --- | ---: | ---: |"])
        for gap, count, share in gap_rows:
            lines.append(f"| `{gap}` | {count} | {share:.3f} |")
    if public_policy_targets:
        lines.extend(
            [
                "",
                "### Public-Anchored Policy Targets",
                "",
                "| Rank | Score | Gap | Archetype | Hash | Anchor Tier | Count | Win Share | Episodes | Teams | Motif Shift |",
                "| ---: | ---: | --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for target in public_policy_targets:
            motif_shift = f"{target.public_motif} -> {target.model_motif}"
            lines.append(
                f"| {target.rank} | {target.score:.1f} | `{target.gap}` | `{target.archetype}` | `{target.deck_hash}` | "
                f"`{target.anchor_tier}` | {target.count} | {target.win_share:.3f} | {target.episodes} | {target.teams} | `{motif_shift}` |"
            )

    lines.extend(["", "## PSRO / Public-Failure Risk", ""])
    lines.append(f"- PSRO pair signal: {psro_pair}")
    lines.append(f"- PSRO metrics: {psro_metrics}")
    if psro_reasons:
        lines.append(f"- PSRO risk notes: {'; '.join(psro_reasons)}")
    if failures:
        lines.append("")
        lines.append("| Public-Failed Candidate | Family | Public Current | Notes |")
        lines.append("| --- | --- | ---: | --- |")
        for failure in failures[:12]:
            lines.append(f"| {failure.candidate} | {failure.family} | {failure.public_current:.1f} | {failure.notes or '-'} |")

    lines.extend(["", "## Fidelity And Gate Status", ""])
    lines.append(f"- Replay fidelity verdict: {fidelity_verdict}")
    lines.append(f"- Dominant divergence cause: {fidelity_cause}")
    if fidelity_bullets:
        for bullet in fidelity_bullets:
            lines.append(bullet)
    if backtest:
        lines.append(
            f"- Backtest best latest-public metric: `{backtest.best_metric}` Spearman {fmt_float(backtest.spearman, 3)}, "
            f"Kendall {fmt_float(backtest.kendall, 3)}, n={backtest.n or '-'}, trusted rows={backtest.trusted_count}/{backtest.row_count}, "
            f"missing anchors={backtest.required_missing or '-'}."
        )
    if pair_gate:
        status = "open" if pair_gate.submit_safe else "closed"
        lines.append(f"- Pair selector submit status: **{status}** from `{pair_gate.path}`.")
        if pair_gate.backtest_gate != "-":
            lines.append(f"- Pair selector backtest gate: {pair_gate.backtest_gate}")
        if pair_gate.blocker != "-":
            lines.append(f"- Pair selector blocker: {pair_gate.blocker}")
    if pimc:
        lines.append(
            f"- PIMC probe: lc={fmt_float(pimc.lc, 3)} CI {pimc.lc_ci}; "
            f"bias={fmt_float(pimc.bias, 3)} CI {pimc.bias_ci}; df={fmt_float(pimc.df, 3)} CI {pimc.df_ci}; decision={pimc.decision}."
        )

    lines.extend(["", "## Evidence Hierarchy", ""])
    lines.extend(evidence_hierarchy(backtest, pair_gate))

    lines.extend(["", "## Strategy Priorities", ""])
    lines.extend(strategy_priorities(lanes, motif_scores))
    lines.extend(
        [
            "",
            "## Promotion Gates",
            "",
            "1. Fresh public scout covers the current top window and top-10 crossing teams.",
            "2. Replay-fidelity fence is acknowledged: ordinary local full-game win rate is not used as a submit-facing metric.",
            "3. Candidate family has enough public anchors: two GarlicToday public submissions, or one GarlicToday public submission plus at least five fresh exact-hash top-window public replays with no contradictory low-score anchor.",
            "4. Backtest summary has `trusted=1`, Spearman >= 0.55, Kendall > 0, n >= 5, and required anchors covered.",
            "5. Behavior-cloning/action-ranker evidence agrees with or explicitly explains a policy patch.",
            "6. Motif holdout improves the targeted policy family without creating a larger broad casebook regression.",
            "7. Process-recycled payoff chunks cover pressure lanes only as secondary evidence.",
            "8. Pair selector reports an actual pair, and pre-submit gate verifies UTC quota, archive sanity, current packet, public-anchor backtest, and any resolver before upload.",
            "",
            "## Next Best Work",
            "",
            "- Do not submit from local gauntlet confidence alone; the current pair selector is closed until public-anchor correlation recovers.",
            "- Mine public exact-hash replays for candidate families before implementing deck-shell changes; prioritize public anchors for v39/pure-Crustle/v36/v4-style recovery families over unanchored local variants.",
            "- Use ML/RL reports to make narrow policy probes around attack/end discipline, bench-vs-active attachment, optional activation throttles, and Dudunsparce timing.",
            "- For search/RL, favor offline ISMCTS/CFR/PSRO-style population training with fast deterministic inference; cheap random-playout PIMC remains biased and should not drive submit selection.",
            "- Re-run this synthesis after each fresh scout and after each public anchor update so code work stays strategy-first and gate-aware.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--type-report", type=Path, required=True)
    parser.add_argument("--ranker-report", type=Path, action="append", default=[])
    parser.add_argument("--motif-holdout", type=Path)
    parser.add_argument("--psro-report", type=Path)
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--policy-gap-report", type=Path)
    parser.add_argument("--public-anchor-policy-targets", type=Path)
    parser.add_argument("--fidelity-report", type=Path)
    parser.add_argument("--backtest-summary", type=Path)
    parser.add_argument("--pimc-report", type=Path)
    parser.add_argument("--pair-selector", type=Path)
    parser.add_argument("--public-failure-floor", type=float, default=800.0)
    parser.add_argument("--lane-limit", type=int, default=12)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    text = render(args)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
