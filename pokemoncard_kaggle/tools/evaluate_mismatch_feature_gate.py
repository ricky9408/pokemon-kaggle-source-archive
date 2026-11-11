#!/usr/bin/env python3
"""Gate generic action-ranker mismatch overlays against public-anchor lanes.

This extends ``public_anchor_feature_gate.py`` beyond the Dudunsparce timing
motif.  It consumes mined public-vs-model action boundaries such as
"public PLAY over model ATTACH when energy_attached=False", applies the overlay
as a tiny top-1 reranker, and reports whether the signal survives:

* overall public-action imitation,
* deterministic holdouts,
* public-anchor tiers, and
* hashes with contradictory GarlicToday public failures.

It is an offline ML/RL curriculum gate only.  It never submits and never treats
local full-game win rate as a trusted public-score predictor.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mine_action_ranker_mismatch_predicates import (  # noqa: E402
    Pattern,
    boundary_key,
    feature_map,
    pattern_matches,
    promoted_rank,
)
from public_anchor_policy_targets import anchor_tier, build_lanes, load_anchor_status  # noqa: E402
from train_action_ranker import load_rows, pct, ranked_options, stable_bucket, valid_single_label  # noqa: E402


DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]
DISALLOWED_PREDICATE_KEYS = {"public_type", "public_card", "public_target"}


@dataclass(frozen=True)
class Clause:
    key: str
    op: str
    values: tuple[str, ...]

    @property
    def text(self) -> str:
        return f"{self.key}{self.op}{'|'.join(self.values)}"


@dataclass(frozen=True)
class Predicate:
    name: str
    clauses: tuple[Clause, ...] = ()

    def matches(self, features: dict[str, str]) -> bool:
        if not self.clauses:
            return True
        for clause in self.clauses:
            observed = features.get(clause.key, "unknown")
            if clause.op == "=":
                if observed not in clause.values:
                    return False
            elif clause.op in {"<=", ">="}:
                try:
                    left = int(observed)
                    right_values = [int(value) for value in clause.values]
                except ValueError:
                    return False
                if clause.op == "<=" and not any(left <= right for right in right_values):
                    return False
                if clause.op == ">=" and not any(left >= right for right in right_values):
                    return False
            else:
                raise ValueError(f"Unsupported predicate op: {clause.op}")
        return True


@dataclass(frozen=True)
class OverlaySpec:
    name: str
    public_pattern: Pattern
    model_pattern: Pattern
    predicate: Predicate

    @property
    def boundary(self) -> str:
        return boundary_key(self.public_pattern, self.model_pattern)


@dataclass
class GateStats:
    total: int = 0
    base_top1: int = 0
    feature_top1: int = 0
    base_top3: int = 0
    feature_top3: int = 0
    eligible: int = 0
    fired: int = 0
    changed: int = 0
    fixes: int = 0
    regressions: int = 0
    neutral_changes: int = 0

    @property
    def top1_delta(self) -> int:
        return self.feature_top1 - self.base_top1

    @property
    def net(self) -> int:
        return self.fixes - self.regressions

    @property
    def base_top1_rate(self) -> float:
        return self.base_top1 / self.total if self.total else 0.0

    @property
    def feature_top1_rate(self) -> float:
        return self.feature_top1 / self.total if self.total else 0.0


@dataclass
class GateResult:
    spec: OverlaySpec
    overall: GateStats = field(default_factory=GateStats)
    holdouts: dict[str, GateStats] = field(default_factory=lambda: defaultdict(GateStats))
    tiers: dict[str, GateStats] = field(default_factory=lambda: defaultdict(GateStats))
    lanes: dict[str, GateStats] = field(default_factory=lambda: defaultdict(GateStats))
    failure_hashes: dict[str, GateStats] = field(default_factory=lambda: defaultdict(GateStats))
    examples: dict[str, int] = field(default_factory=lambda: defaultdict(int))


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def row_value(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return str(value) if value is not None else "unknown"


def parse_pattern(raw: str) -> Pattern:
    parts = raw.strip().split(":")
    if len(parts) < 2:
        raise ValueError(f"Bad pattern: {raw}")
    mode = parts[0]
    type_name = parts[1]
    fields = {"card": "*", "attack": "*", "to": "*"}
    for token in parts[2:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return Pattern(mode=mode, type_name=type_name, card=fields["card"], attack=fields["attack"], to_area=fields["to"])


def parse_boundary(raw: str) -> tuple[Pattern, Pattern]:
    left, right = raw.split("|", 1)
    left = left.strip()
    right = right.strip()
    if not left.startswith("public=") or not right.startswith("model="):
        raise ValueError(f"Boundary must look like 'public=... | model=...': {raw}")
    return parse_pattern(left.removeprefix("public=")), parse_pattern(right.removeprefix("model="))


def parse_predicate(raw: str) -> Predicate:
    raw = raw.strip()
    if raw in {"", "all"}:
        return Predicate("all")
    clauses: list[Clause] = []
    for chunk in raw.split("&"):
        text = chunk.strip()
        match = re.fullmatch(r"([A-Za-z0-9_]+)(<=|>=|=)([^&]+)", text)
        if not match:
            raise ValueError(f"Unsupported predicate clause: {text}")
        key, op, values = match.groups()
        if key in DISALLOWED_PREDICATE_KEYS or key.startswith("public_"):
            raise ValueError(f"Predicate uses label-derived key {key}; refusing label leakage")
        value_tuple = tuple(value.strip() for value in values.split("|") if value.strip())
        clauses.append(Clause(key=key, op=op, values=value_tuple))
    return Predicate(raw, tuple(clauses))


def spec_from_row(row: dict[str, str], index: int) -> OverlaySpec:
    public_pattern, model_pattern = parse_boundary(row["boundary"])
    predicate = parse_predicate(row["predicate"])
    return OverlaySpec(
        name=f"csv{index}:{row['boundary']} / {row['predicate']}",
        public_pattern=public_pattern,
        model_pattern=model_pattern,
        predicate=predicate,
    )


def load_specs(args: argparse.Namespace) -> list[OverlaySpec]:
    specs: list[OverlaySpec] = []
    if args.from_csv:
        with args.from_csv.open(encoding="utf-8", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle), start=1):
                if index > args.top:
                    break
                specs.append(spec_from_row(row, index))
    for raw in args.spec:
        boundary, predicate = raw.split("::", 1)
        public_pattern, model_pattern = parse_boundary(boundary)
        specs.append(
            OverlaySpec(
                name=f"manual:{boundary} / {predicate}",
                public_pattern=public_pattern,
                model_pattern=model_pattern,
                predicate=parse_predicate(predicate),
            )
        )
    if not specs:
        raise ValueError("Provide --from-csv or at least one --spec")
    return specs


def contradictory_hashes(anchor_status: Path | None) -> set[str]:
    if anchor_status is None:
        return set()
    failures: set[str] = set()
    with anchor_status.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            reasons = str(row.get("reasons") or "")
            deck_hash = str(row.get("deck_hash") or "")
            if deck_hash and "contradictory low public anchor" in reasons:
                failures.add(deck_hash)
    return failures


def update_stats(stats: GateStats, label: int, base_rank: list[int], feature_rank: list[int], eligible: bool, fired: bool) -> None:
    stats.total += 1
    stats.eligible += int(eligible)
    stats.fired += int(fired)
    base_hit = bool(base_rank and base_rank[0] == label)
    feature_hit = bool(feature_rank and feature_rank[0] == label)
    stats.base_top1 += int(base_hit)
    stats.feature_top1 += int(feature_hit)
    stats.base_top3 += int(label in base_rank[:3])
    stats.feature_top3 += int(label in feature_rank[:3])
    changed = bool(base_rank and feature_rank and base_rank[0] != feature_rank[0])
    stats.changed += int(changed)
    stats.fixes += int(changed and not base_hit and feature_hit)
    stats.regressions += int(changed and base_hit and not feature_hit)
    stats.neutral_changes += int(changed and base_hit == feature_hit)


def apply_spec(spec: OverlaySpec, row: dict[str, Any], weights: dict[str, float]) -> tuple[list[int], list[int], bool, bool]:
    label = valid_single_label(row)
    if label is None or row_value(row, "context") != "MAIN":
        return [], [], False, False
    base_rank = ranked_options(weights, row)
    options = [str(option) for option in row.get("options") or []]
    if not base_rank or base_rank[0] >= len(options):
        return base_rank, base_rank, False, False
    eligible = pattern_matches(spec.model_pattern, options[base_rank[0]]) and any(
        pattern_matches(spec.public_pattern, option) for option in options
    )
    if not eligible:
        return base_rank, base_rank, False, False
    features = feature_map(row, options, base_rank[0], label)
    if not spec.predicate.matches(features):
        return base_rank, base_rank, True, False
    feature_rank, changed = promoted_rank(base_rank, options, spec.public_pattern, spec.model_pattern)
    return base_rank, feature_rank, True, changed


def evaluate(args: argparse.Namespace, specs: list[OverlaySpec]) -> list[GateResult]:
    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    lanes = build_lanes(rows)
    anchors = load_anchor_status(args.anchor_status)
    failure_hash_set = contradictory_hashes(args.anchor_status)

    results = [GateResult(spec=spec) for spec in specs]
    for row in rows:
        label = valid_single_label(row)
        if label is None or row_value(row, "context") != "MAIN":
            continue
        lane = lanes[(row_value(row, "archetype"), row_value(row, "deck_hash"))]
        tier, _candidates = anchor_tier(lane, anchors, args.min_public_episodes, args.min_public_teams)
        lane_name = f"{lane.archetype}:{lane.deck_hash}"
        for result in results:
            base_rank, feature_rank, eligible, fired = apply_spec(result.spec, row, weights)
            update_stats(result.overall, label, base_rank, feature_rank, eligible, fired)
            update_stats(result.tiers[tier], label, base_rank, feature_rank, eligible, fired)
            update_stats(result.lanes[lane_name], label, base_rank, feature_rank, eligible, fired)
            if lane.deck_hash in failure_hash_set:
                update_stats(result.failure_hashes[lane_name], label, base_rank, feature_rank, eligible, fired)
            for key in args.holdout_key:
                if stable_bucket(row_value(row, key), args.holdout_mod) == args.holdout_bucket:
                    update_stats(result.holdouts[key], label, base_rank, feature_rank, eligible, fired)
            if fired and base_rank and feature_rank and base_rank[0] != feature_rank[0]:
                options = [str(option) for option in row.get("options") or []]
                if feature_rank[0] == label and base_rank[0] != label:
                    outcome = "fix"
                elif base_rank[0] == label and feature_rank[0] != label:
                    outcome = "regress"
                else:
                    outcome = "neutral"
                selected = options[label] if label < len(options) else str(label)
                before = options[base_rank[0]]
                after = options[feature_rank[0]]
                result.examples[f"{outcome}: public={selected} | base={before} | overlay={after}"] += 1
    return results


def stats_row(name: str, stats: GateStats) -> str:
    return (
        f"| `{name.replace('|', '&#124;')}` | {stats.total} | "
        f"{stats.base_top1_rate:.3f} | {stats.feature_top1_rate:.3f} | {stats.top1_delta:+d} | "
        f"{pct(stats.base_top3, stats.total)} | {pct(stats.feature_top3, stats.total)} | "
        f"{stats.eligible} | {stats.fired} | {stats.changed} | {stats.fixes} | "
        f"{stats.regressions} | {stats.neutral_changes} | {stats.net:+d} |"
    )


def sort_stats(items: dict[str, GateStats]) -> list[tuple[str, GateStats]]:
    return sorted(items.items(), key=lambda item: (-item[1].fired, item[1].top1_delta, item[0]))


def decision_for(result: GateResult, args: argparse.Namespace) -> tuple[str, list[str]]:
    notes: list[str] = []
    if result.overall.top1_delta < 0:
        notes.append(f"Overall top-1 delta is negative ({result.overall.top1_delta}).")
    if result.overall.net < 0:
        notes.append(f"Overall fixes-regressions net is negative ({result.overall.net}).")
    for key, stats in result.holdouts.items():
        if stats.top1_delta < 0:
            notes.append(f"Holdout `{key}` has negative top-1 delta ({stats.top1_delta}).")

    public_supported = {
        "submit-eligible-candidate",
        "exact-public-replay-supported",
        "single-team-public-replay-supported",
    }
    supported_with_fires = [
        (name, stats)
        for name, stats in result.tiers.items()
        if name in public_supported and stats.fired >= args.min_group_fires
    ]
    if not supported_with_fires:
        notes.append("No public-supported anchor tier has enough overlay fires.")
    for name, stats in supported_with_fires:
        if stats.top1_delta < 0:
            notes.append(f"Anchor tier `{name}` has negative top-1 delta ({stats.top1_delta}).")
        if stats.net < 0:
            notes.append(f"Anchor tier `{name}` has negative fixes-regressions net ({stats.net}).")

    for name, stats in result.tiers.items():
        if name == "candidate-public-contradicted" and stats.fired >= args.min_group_fires:
            if stats.top1_delta < 0:
                notes.append(f"Contradicted public-anchor tier has negative top-1 delta ({stats.top1_delta}).")
            if stats.net < 0:
                notes.append(f"Contradicted public-anchor tier has negative fixes-regressions net ({stats.net}).")

    for name, stats in result.failure_hashes.items():
        if stats.fired >= args.min_group_fires and stats.top1_delta < 0:
            notes.append(f"Public-failure hash `{name}` has negative top-1 delta ({stats.top1_delta}).")
        if stats.fired >= args.min_group_fires and stats.net < 0:
            notes.append(f"Public-failure hash `{name}` has negative fixes-regressions net ({stats.net}).")

    for name, stats in result.lanes.items():
        if stats.fired >= args.min_group_fires and stats.top1_delta <= -args.max_lane_regression:
            notes.append(f"Lane `{name}` exceeds allowed regression with top-1 delta {stats.top1_delta}.")

    if notes:
        return "research-only", notes + ["Do not package or submit from this feature."]
    return "offline-feature-accepted", [
        "The overlay is non-negative overall, on deterministic holdouts, and in public-anchor/failure lanes with enough fires.",
        "This is still ML/RL curriculum evidence only; submit-facing public-score gates remain separate.",
    ]


def render_report(args: argparse.Namespace, results: list[GateResult]) -> str:
    lines: list[str] = [
        "# Generic Public-Anchor Mismatch Feature Gate",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "- Runtime premise: deterministic offline analysis; no network or LLM at play time.",
        "- Submission status: no submission made.",
        "",
        "## Inputs",
        "",
        f"- Decisions: `{args.decisions}`",
        f"- Base model: `{args.model}`",
        f"- Anchor status: `{args.anchor_status}`",
        f"- Specs evaluated: {len(results)}",
        f"- Public replay support thresholds: episodes >= {args.min_public_episodes}, teams >= {args.min_public_teams}",
        "",
        "## Summary",
        "",
        "| Status | Boundary | Predicate | N | Base Top-1 | Feature Top-1 | Delta | Fires | Fixes | Regressions | Net |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    decisions: dict[str, tuple[str, list[str]]] = {}
    for result in results:
        status, notes = decision_for(result, args)
        decisions[result.spec.name] = (status, notes)
        stats = result.overall
        lines.append(
            f"| **{status}** | `{result.spec.boundary.replace('|', '&#124;')}` | "
            f"`{result.spec.predicate.name}` | {stats.total} | {stats.base_top1_rate:.3f} | "
            f"{stats.feature_top1_rate:.3f} | {stats.top1_delta:+d} | {stats.fired} | "
            f"{stats.fixes} | {stats.regressions} | {stats.net:+d} |"
        )

    for result in results:
        status, notes = decisions[result.spec.name]
        lines.extend(
            [
                "",
                f"## `{result.spec.predicate.name}`",
                "",
                f"- Boundary: `{result.spec.boundary}`",
                f"- Status: **{status}**",
            ]
        )
        for note in notes:
            lines.append(f"- {note}")
        lines.extend(
            [
                "",
                "### Overall And Holdouts",
                "",
                "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Neutral | Net |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                stats_row("all rows", result.overall),
            ]
        )
        for name, stats in result.holdouts.items():
            lines.append(stats_row(f"holdout:{name}", stats))
        lines.extend(
            [
                "",
                "### Public-Anchor Tiers",
                "",
                "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Neutral | Net |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for name, stats in sort_stats(result.tiers):
            lines.append(stats_row(name, stats))
        lines.extend(
            [
                "",
                "### Public-Failure Hashes",
                "",
                "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Neutral | Net |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for name, stats in sort_stats(result.failure_hashes):
            lines.append(stats_row(name, stats))
        lines.extend(
            [
                "",
                "### Top Fired Lanes",
                "",
                "| Group | N | Base Top-1 | Feature Top-1 | Delta | Base Top-3 | Feature Top-3 | Eligible | Fires | Changes | Fixes | Regressions | Neutral | Net |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for name, stats in sort_stats(result.lanes)[: args.lane_limit]:
            if stats.fired == 0 and stats.eligible == 0:
                continue
            lines.append(stats_row(name, stats))
        lines.extend(["", "### Example Changes", ""])
        for text, count in sorted(result.examples.items(), key=lambda item: (-item[1], item[0]))[:8]:
            lines.append(f"- {count}: {text}")

    lines.extend(
        [
            "",
            "## Use In Workflow",
            "",
            "- `offline-feature-accepted` means the feature may stay in behavior-cloning, value-model, or offline-RL experiments.",
            "- `research-only` means the feature failed at least one public-anchor or holdout guard.",
            "- Neither status makes an agent package submit-safe; public-score backtest and pre-submit gates still decide eligibility.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(path: Path, results: list[GateResult], args: argparse.Namespace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "spec",
                "status",
                "group_type",
                "group",
                "boundary",
                "predicate",
                "n",
                "base_top1",
                "feature_top1",
                "delta_top1_count",
                "base_top3",
                "feature_top3",
                "eligible",
                "fires",
                "changes",
                "fixes",
                "regressions",
                "neutral",
                "net",
            ]
        )
        for result in results:
            status, _notes = decision_for(result, args)
            groups: list[tuple[str, str, GateStats]] = [("overall", "all rows", result.overall)]
            groups += [("holdout", name, stats) for name, stats in result.holdouts.items()]
            groups += [("anchor_tier", name, stats) for name, stats in sort_stats(result.tiers)]
            groups += [("public_failure_hash", name, stats) for name, stats in sort_stats(result.failure_hashes)]
            groups += [("lane", name, stats) for name, stats in sort_stats(result.lanes)]
            for group_type, group, stats in groups:
                writer.writerow(
                    [
                        result.spec.name,
                        status,
                        group_type,
                        group,
                        result.spec.boundary,
                        result.spec.predicate.name,
                        stats.total,
                        f"{stats.base_top1_rate:.6f}",
                        f"{stats.feature_top1_rate:.6f}",
                        stats.top1_delta,
                        f"{stats.base_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        f"{stats.feature_top3 / stats.total:.6f}" if stats.total else "0.000000",
                        stats.eligible,
                        stats.fired,
                        stats.changed,
                        stats.fixes,
                        stats.regressions,
                        stats.neutral_changes,
                        stats.net,
                    ]
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--anchor-status", required=True, type=Path)
    parser.add_argument("--from-csv", type=Path)
    parser.add_argument(
        "--spec",
        action="append",
        default=[],
        help="Manual spec in the form 'public=... | model=...::predicate'.",
    )
    parser.add_argument("--top", type=int, default=8)
    parser.add_argument("--holdout-key", action="append", choices=DEFAULT_HOLDOUT_KEYS, default=[])
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-group-fires", type=int, default=10)
    parser.add_argument("--max-lane-regression", type=int, default=5)
    parser.add_argument("--lane-limit", type=int, default=20)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/mismatch_feature_gate.md"))
    parser.add_argument("--csv-out", type=Path)
    args = parser.parse_args()
    if not args.holdout_key:
        args.holdout_key = list(DEFAULT_HOLDOUT_KEYS)
    if args.csv_out is None:
        args.csv_out = args.report_out.with_suffix(".csv")
    return args


def main() -> int:
    args = parse_args()
    specs = load_specs(args)
    results = evaluate(args, specs)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, results), encoding="utf-8")
    write_csv(args.csv_out, results, args)
    status_counts: dict[str, int] = defaultdict(int)
    for result in results:
        status, _notes = decision_for(result, args)
        status_counts[status] += 1
    summary = " ".join(f"{key}={value}" for key, value in sorted(status_counts.items()))
    print(f"specs={len(results)} {summary} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
