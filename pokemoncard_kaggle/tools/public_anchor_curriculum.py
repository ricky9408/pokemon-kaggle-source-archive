#!/usr/bin/env python3
"""Compile public-anchor policy gaps into an ML/RL curriculum.

The public replay action-ranker is useful only if it creates transferable
strategy work, not another local-gauntlet shortcut. This tool aggregates
public-anchor target rows into strategic families, attaches pressure-lane
weights and known negative controls, and emits the next offline experiments to
run before any package work.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PUBLIC_SUPPORTED_TIERS = {
    "submit-eligible-candidate",
    "exact-public-replay-supported",
    "single-team-public-replay-supported",
}


@dataclass
class SignalEvidence:
    accepted: list[dict[str, str]] = field(default_factory=list)
    rejected: list[dict[str, str]] = field(default_factory=list)


@dataclass
class CurriculumItem:
    family: str
    archetype: str
    deck_hash: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    raw_score: float = 0.0
    adjusted_score: float = 0.0
    count: int = 0
    win_rows: int = 0
    loss_rows: int = 0
    tiers: Counter[str] = field(default_factory=Counter)
    gaps: Counter[str] = field(default_factory=Counter)
    public_motifs: Counter[str] = field(default_factory=Counter)
    model_motifs: Counter[str] = field(default_factory=Counter)
    examples: Counter[str] = field(default_factory=Counter)
    teams: set[str] = field(default_factory=set)
    max_lane_episodes: int = 0
    max_lane_teams: int = 0
    pressure_weight: float = 0.0

    @property
    def key(self) -> str:
        return f"{self.family}:{self.archetype}:{self.deck_hash}"

    @property
    def lane(self) -> str:
        return f"{self.archetype}:{self.deck_hash}"

    @property
    def win_share(self) -> float:
        return self.win_rows / self.count if self.count else 0.0

    @property
    def dominant_tier(self) -> str:
        return self.tiers.most_common(1)[0][0] if self.tiers else "unknown"

    @property
    def top_gap(self) -> str:
        return self.gaps.most_common(1)[0][0] if self.gaps else "-"

    @property
    def top_public_motif(self) -> str:
        return self.public_motifs.most_common(1)[0][0] if self.public_motifs else "-"

    @property
    def top_model_motif(self) -> str:
        return self.model_motifs.most_common(1)[0][0] if self.model_motifs else "-"


def to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_type_pressure(path: Path | None) -> dict[str, float]:
    if path is None or not path.exists():
        return {}
    weights: dict[str, float] = {}
    row_re = re.compile(r"^\|\s*\d+\s*\|\s*`([^`]+)`[^|]*\|\s*([0-9.]+)\s*\|")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = row_re.match(line.strip())
        if match:
            weights[match.group(1)] = float(match.group(2))
    return weights


def family_for_gap(gap: str) -> str:
    if "public_ability_before_model_attack" in gap:
        return "engine_ability_before_attack"
    if "public_ability_before_model_play" in gap:
        return "engine_ability_before_play"
    if "declines_activation" in gap:
        return "optional_activation_throttle"
    if "attach" in gap:
        if "bench_model_active" in gap or "model_active" in gap:
            return "attachment_target_timing"
        return "attachment_vs_play_timing"
    if "public_attack_model_play" in gap or "model_attack_public_play" in gap:
        return "attack_vs_play_tempo"
    if "public_end_model" in gap or "model_attach_active_public_end" in gap:
        return "turn_end_discipline"
    if "retreat" in gap:
        return "retreat_timing"
    if "evolve" in gap:
        return "evolution_vs_energy_timing"
    return "misc_policy_gap"


def family_weight(family: str) -> float:
    return {
        "attachment_target_timing": 1.35,
        "attack_vs_play_tempo": 1.25,
        "turn_end_discipline": 1.10,
        "attachment_vs_play_timing": 1.05,
        "engine_ability_before_play": 0.95,
        "optional_activation_throttle": 0.85,
        "retreat_timing": 0.80,
        "evolution_vs_energy_timing": 0.75,
        # Already accepted as an offline feature; keep in the curriculum as a
        # regression guard, but do not let it crowd out the next learning target.
        "engine_ability_before_attack": 0.25,
    }.get(family, 0.70)


def tier_multiplier(tier: str) -> float:
    return {
        "submit-eligible-candidate": 1.25,
        "exact-public-replay-supported": 1.20,
        "single-team-public-replay-supported": 0.95,
        "candidate-public-contradicted": 0.42,
        "candidate-observed-thin": 0.50,
        "thin-public-replay": 0.35,
    }.get(tier, 0.60)


def action_template(family: str) -> str:
    return {
        "attachment_target_timing": "Train/evaluate bench-vs-active attachment target preference; start as soft value feature, not hard branch.",
        "attachment_vs_play_timing": "Learn the attach-now vs play/search-first boundary; require same-card and target-area negative controls.",
        "attack_vs_play_tempo": "Learn attack/end readiness threshold after setup; compare prize, KO, hand, and turn-action features.",
        "turn_end_discipline": "Learn stop-playing threshold; reward ending once setup risk exceeds marginal card value.",
        "engine_ability_before_play": "Probe Dudunsparce/engine ability before optional plays separately from the accepted attack boundary.",
        "engine_ability_before_attack": "Keep accepted timing feature as regression guard; do not broaden without public-anchor gate.",
        "optional_activation_throttle": "Improve ACTIVATE yes/no classifier before any runtime branch; current activation model was below majority baseline.",
        "retreat_timing": "Mine retreat predicates and validate with public-anchor feature gate before local stress tests.",
        "evolution_vs_energy_timing": "Treat evolve-before-attach as curriculum labels; require lane-specific holdout because this is board-shape sensitive.",
    }.get(family, "Mine public-vs-model context predicates, then gate as an offline feature.")


def validation_template(family: str) -> str:
    base = "Required: team/opponent/episode/source holdouts non-negative, public-anchor tier non-negative, no package promotion."
    if family == "attachment_target_timing":
        return base + " Add same-card target-area and active-KO-risk negative controls."
    if family == "attachment_vs_play_timing":
        return base + " Split public-play/model-attach and public-attach/model-play directions before any runtime probe."
    if family == "attack_vs_play_tempo":
        return base + " Must beat v100 attack-override negative control and avoid public-ability/local-attack reversals."
    if family == "engine_ability_before_play":
        return base + " Must not reintroduce rejected broad ranks-5+6 pairwise behavior."
    if family == "optional_activation_throttle":
        return base + " Must beat majority baseline on ACTIVATE rows before policy probing."
    return base


def negative_controls(family: str, signals: SignalEvidence) -> str:
    controls: list[str] = []
    if family in {"engine_ability_before_play", "engine_ability_before_attack"}:
        controls.extend(
            row["name"]
            for row in signals.rejected
            if "Ranks 5+6 ability targets" in row.get("name", "") or "Top-8 Hop" in row.get("name", "")
        )
    if family == "attack_vs_play_tempo":
        controls.append("v100 broad lethal-attack override: improved narrow motif but worsened total mismatch mass")
    if family == "optional_activation_throttle":
        controls.append("activation classifier below majority baseline; do not branch until classifier improves")
    if family.startswith("attachment"):
        controls.append("June 20 public failures: local replay-pool confidence is not a promotion signal")
    if not controls:
        controls.extend(row["name"] for row in signals.rejected[:2])
    deduped = []
    for control in controls:
        if control and control not in deduped:
            deduped.append(control)
    return "; ".join(deduped[:3]) or "-"


def status_for_item(item: CurriculumItem) -> str:
    if item.family == "engine_ability_before_attack":
        return "accepted-regression-guard"
    if item.dominant_tier == "candidate-public-contradicted":
        return "probe-only-contradicted-anchor"
    if item.dominant_tier not in PUBLIC_SUPPORTED_TIERS:
        return "needs-more-public-anchors"
    if item.count < 50 or item.max_lane_episodes < 5:
        return "probe-only-thin-sample"
    return "next-feature-probe"


def read_signal_evidence(path: Path | None) -> SignalEvidence:
    evidence = SignalEvidence()
    if path is None or not path.exists():
        return evidence
    for row in read_csv(path):
        status = row.get("status", "")
        if status == "offline-feature":
            evidence.accepted.append(row)
        elif status == "reject":
            evidence.rejected.append(row)
    evidence.accepted.sort(key=lambda row: to_float(row.get("priority")), reverse=True)
    evidence.rejected.sort(key=lambda row: to_float(row.get("priority")))
    return evidence


def team_examples(raw: str) -> set[str]:
    if not raw or raw == "-":
        return set()
    return {part.strip() for part in raw.split(",") if part.strip()}


def build_curriculum(
    target_rows: list[dict[str, str]],
    pressure_weights: dict[str, float],
) -> list[CurriculumItem]:
    items: dict[tuple[str, str, str], CurriculumItem] = {}
    for row in target_rows:
        gap = row.get("gap", "")
        family = family_for_gap(gap)
        archetype = row.get("archetype", "unknown")
        deck_hash = row.get("deck_hash", "unknown")
        key = (family, archetype, deck_hash)
        item = items.setdefault(key, CurriculumItem(family=family, archetype=archetype, deck_hash=deck_hash))
        lane = item.lane
        item.rows.append(dict(row))
        item.gaps[gap] += to_int(row.get("count"))
        item.public_motifs[row.get("public_motif", "-")] += to_int(row.get("count"))
        item.model_motifs[row.get("model_motif", "-")] += to_int(row.get("count"))
        item.tiers[row.get("anchor_tier", "unknown")] += to_int(row.get("count"))
        item.count += to_int(row.get("count"))
        item.win_rows += to_int(row.get("win_rows"))
        item.loss_rows += to_int(row.get("loss_rows"))
        item.raw_score += to_float(row.get("score"))
        item.max_lane_episodes = max(item.max_lane_episodes, to_int(row.get("lane_episodes")))
        item.max_lane_teams = max(item.max_lane_teams, to_int(row.get("lane_teams")))
        item.teams.update(team_examples(row.get("team_examples", "")))
        example = (
            f"{row.get('example_context', '-')}/{row.get('example_opponent', '-')}: "
            f"{row.get('example_public', '-')} => {row.get('example_model', '-')}"
        )
        item.examples[example] += 1
        item.pressure_weight = max(item.pressure_weight, pressure_weights.get(lane, 0.0))

    for item in items.values():
        pressure_bonus = 1.0 + min(0.35, math.log1p(item.pressure_weight) / 12.0)
        support_bonus = 1.0 + min(0.20, 0.03 * item.max_lane_teams)
        item.adjusted_score = (
            item.raw_score
            * family_weight(item.family)
            * tier_multiplier(item.dominant_tier)
            * pressure_bonus
            * support_bonus
        )
    return sorted(items.values(), key=lambda item: (-item.adjusted_score, -item.count, item.key))


def code(value: Any) -> str:
    return f"`{str(value).replace('|', '&#124;')}`"


def render_report(
    args: argparse.Namespace,
    items: list[CurriculumItem],
    signals: SignalEvidence,
    target_count: int,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Public-Anchor ML/RL Curriculum")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.getenv('USER', 'unknown')}")
    lines.append("- Runtime premise: no network/LLM at play time; local full-game gauntlets remain fenced until public-score backtests clear.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Public-anchor targets: `{args.targets}` ({target_count} rows)")
    lines.append(f"- Signal registry: `{args.signal_registry}` ({len(signals.accepted)} accepted, {len(signals.rejected)} rejected)")
    lines.append(f"- Type pressure report: `{args.type_pressure}`")
    lines.append(f"- CSV out: `{args.csv_out}`")
    lines.append("")
    lines.append("## Top Curriculum Items")
    lines.append("")
    lines.append(
        "| Rank | Status | Family | Lane | Adj Score | Rows | Win Share | Tier | Episodes / Teams | Public -> Model | Action Template |"
    )
    lines.append("| ---: | --- | --- | --- | ---: | ---: | ---: | --- | ---: | --- | --- |")
    for rank, item in enumerate(items[: args.limit], start=1):
        lines.append(
            f"| {rank} | {code(status_for_item(item))} | {code(item.family)} | {code(item.lane)} | "
            f"{item.adjusted_score:.1f} | {item.count} | {item.win_share:.3f} | {code(item.dominant_tier)} | "
            f"{item.max_lane_episodes} / {item.max_lane_teams} | "
            f"{code(item.top_public_motif + ' -> ' + item.top_model_motif)} | {action_template(item.family)} |"
        )
    if not items:
        lines.append("| 0 | - | - | - | 0.0 | 0 | 0.000 | - | 0 / 0 | - | - |")
    lines.append("")
    lines.append("## Validation Contracts")
    lines.append("")
    lines.append(
        "| Rank | Family | Lane | Top Gap | Example | Required Validation | Negative Controls |"
    )
    lines.append("| ---: | --- | --- | --- | --- | --- | --- |")
    for rank, item in enumerate(items[: args.limit], start=1):
        example = item.examples.most_common(1)[0][0] if item.examples else "-"
        lines.append(
            f"| {rank} | {code(item.family)} | {code(item.lane)} | {code(item.top_gap)} | "
            f"{example} | {validation_template(item.family)} | {negative_controls(item.family, signals)} |"
        )
    if not items:
        lines.append("| 0 | - | - | - | - | - | - |")
    lines.append("")
    lines.append("## Family Totals")
    lines.append("")
    family_counts: Counter[str] = Counter()
    family_scores: defaultdict[str, float] = defaultdict(float)
    for item in items:
        family_counts[item.family] += item.count
        family_scores[item.family] += item.adjusted_score
    lines.append("| Family | Rows | Adjusted Score |")
    lines.append("| --- | ---: | ---: |")
    for family, count in family_counts.most_common():
        lines.append(f"| {code(family)} | {count} | {family_scores[family]:.1f} |")
    if not family_counts:
        lines.append("| - | 0 | 0.0 |")
    lines.append("")
    lines.append("## Decision")
    lines.append("")
    next_probe = next((item for item in items if status_for_item(item) == "next-feature-probe"), None)
    if next_probe:
        lines.append(
            f"- Next offline probe: {code(next_probe.family)} on {code(next_probe.lane)}. "
            "Implement as a soft ranker/value feature or BC/RL curriculum label, then run the public-anchor feature gate."
        )
    else:
        lines.append("- No new public-supported feature is ready; collect more public anchors or improve the accepted regression guard.")
    lines.append("- Do not package or submit from this curriculum report. It is a strategy-work queue only.")
    lines.append("- Preserve accepted Dudunsparce timing as a regression guard while exploring the higher-priority attachment and tempo targets.")
    return "\n".join(lines)


def write_csv(path: Path, items: list[CurriculumItem], signals: SignalEvidence) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "status",
        "family",
        "archetype",
        "deck_hash",
        "adjusted_score",
        "raw_score",
        "count",
        "win_share",
        "dominant_tier",
        "lane_episodes",
        "lane_teams",
        "pressure_weight",
        "top_gap",
        "top_public_motif",
        "top_model_motif",
        "action_template",
        "validation_template",
        "negative_controls",
        "example",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rank, item in enumerate(items, start=1):
            writer.writerow(
                {
                    "rank": rank,
                    "status": status_for_item(item),
                    "family": item.family,
                    "archetype": item.archetype,
                    "deck_hash": item.deck_hash,
                    "adjusted_score": f"{item.adjusted_score:.6f}",
                    "raw_score": f"{item.raw_score:.6f}",
                    "count": item.count,
                    "win_share": f"{item.win_share:.6f}",
                    "dominant_tier": item.dominant_tier,
                    "lane_episodes": item.max_lane_episodes,
                    "lane_teams": item.max_lane_teams,
                    "pressure_weight": f"{item.pressure_weight:.6f}",
                    "top_gap": item.top_gap,
                    "top_public_motif": item.top_public_motif,
                    "top_model_motif": item.top_model_motif,
                    "action_template": action_template(item.family),
                    "validation_template": validation_template(item.family),
                    "negative_controls": negative_controls(item.family, signals),
                    "example": item.examples.most_common(1)[0][0] if item.examples else "",
                }
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("targets", type=Path)
    parser.add_argument("--signal-registry", type=Path, required=True)
    parser.add_argument("--type-pressure", type=Path)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/public_anchor_curriculum.md"))
    parser.add_argument("--csv-out", type=Path, default=Path("strategy/public_anchor_curriculum.csv"))
    parser.add_argument("--limit", type=int, default=16)
    args = parser.parse_args()

    targets = read_csv(args.targets)
    signals = read_signal_evidence(args.signal_registry)
    pressure_weights = parse_type_pressure(args.type_pressure)
    items = build_curriculum(targets, pressure_weights)

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, items, signals, len(targets)) + "\n", encoding="utf-8")
    write_csv(args.csv_out, items, signals)
    print(f"targets={len(targets)} items={len(items)} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
