#!/usr/bin/env python3
"""Compile the current public-anchor strategy evidence into a blueprint.

The blueprint is deliberately not a submit selector.  It is a coordination
artifact for behavior cloning, value features, conservative offline RL, and
future agent edits while the full-game local simulator remains fenced.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SIGNAL_REGISTRY = Path("strategy/strategy_signal_registry_20260620T2008.csv")
DEFAULT_FEATURE_STACK = Path("strategy/strategy_feature_stack_20260620T2008_tempo.csv")
DEFAULT_CURRICULUM = Path("strategy/public_anchor_curriculum_20260620T1930.csv")
DEFAULT_FIDELITY = Path("strategy/replay_fidelity_hardened_closure_20260620T2014.md")
DEFAULT_BACKTEST = Path("strategy/backtest_local_vs_public_20260620T2010_hardened_fidelity.summary.csv")


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        return [dict(row) for row in csv.DictReader(file)]


def fnum(value: str | None, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def inum(value: str | None, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        return int(float(value))
    except ValueError:
        return default


def fmt_float(value: str | float | None, digits: int = 3) -> str:
    if value is None or value == "":
        return "-"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def metadata(workspace: Path) -> dict[str, str]:
    return {
        "generated_utc": now_utc(),
        "implementation_agent": "Codex coding agent",
        "model_family": "GPT-5",
        "workspace": str(workspace.resolve()),
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "user": os.environ.get("USER", ""),
        "play_time_runtime": "deterministic offline; no network or LLM at play time",
    }


def top_rows(rows: list[dict[str, str]], *, status: str | None = None, limit: int = 10) -> list[dict[str, str]]:
    selected = [row for row in rows if status is None or row.get("status") == status]
    return sorted(selected, key=lambda row: fnum(row.get("priority")), reverse=True)[:limit]


def rejected_rows(rows: list[dict[str, str]], limit: int = 12) -> list[dict[str, str]]:
    rejected = [
        row
        for row in rows
        if row.get("status") == "reject"
        or "reject" in row.get("decision", "").lower()
        or fnum(row.get("priority")) < 0
    ]
    return sorted(rejected, key=lambda row: fnum(row.get("priority")))[:limit]


def find_feature_rows(rows: list[dict[str, str]], stack: str, scope: str | None = None, name: str | None = None) -> list[dict[str, str]]:
    found = [row for row in rows if row.get("stack") == stack]
    if scope is not None:
        found = [row for row in found if row.get("scope") == scope]
    if name is not None:
        found = [row for row in found if row.get("name") == name]
    return found


def summarize_stack(rows: list[dict[str, str]], stack: str) -> dict[str, Any]:
    overall = next(iter(find_feature_rows(rows, stack, "overall", "all")), {})
    holdouts = find_feature_rows(rows, stack, "holdout")[:8]
    tiers = find_feature_rows(rows, stack, "tier")[:8]
    lanes = sorted(
        find_feature_rows(rows, stack, "lane"),
        key=lambda row: inum(row.get("top1_delta")),
        reverse=True,
    )[:8]
    return {
        "stack": stack,
        "overall": overall,
        "holdouts": holdouts,
        "tiers": tiers,
        "top_lanes": lanes,
    }


def accepted_attachment_predicates(signal_rows: list[dict[str, str]]) -> list[str]:
    predicates: list[str] = []
    for row in signal_rows:
        name = row.get("name", "")
        if not name.startswith("attachment_timing_overlay:"):
            continue
        if row.get("decision") != "offline-feature-accepted":
            continue
        predicate = html.unescape(name.split(":", 1)[1].strip())
        if predicate != "all":
            predicates.append(predicate)
    return predicates


def accepted_timing_exceptions(signal_rows: list[dict[str, str]]) -> list[str]:
    exceptions: list[str] = []
    for row in signal_rows:
        name = row.get("name", "")
        if not name.startswith("timing_exception_overlay:exception only:"):
            continue
        if row.get("status") != "offline-feature":
            continue
        exceptions.append(html.unescape(name.split("exception only:", 1)[1].strip()))
    return exceptions


def best_backtest_rows(rows: list[dict[str, str]], limit: int = 8) -> list[dict[str, str]]:
    return sorted(rows, key=lambda row: fnum(row.get("spearman")), reverse=True)[:limit]


def gate_summary(backtest_rows: list[dict[str, str]]) -> dict[str, Any]:
    trusted = [row for row in backtest_rows if row.get("trusted") == "1"]
    required_covering = [row for row in backtest_rows if not row.get("required_missing")]
    best_required = max(required_covering, key=lambda row: fnum(row.get("spearman")), default={})
    best_any = max(backtest_rows, key=lambda row: fnum(row.get("spearman")), default={})
    return {
        "trusted_metric_count": len(trusted),
        "best_any_metric": best_any,
        "best_required_anchor_metric": best_required,
        "gate": "closed" if not trusted else "open",
        "minimum": {
            "spearman": ">= 0.55",
            "kendall": "> 0",
            "n": ">= 5",
            "trusted": "1",
            "required_anchors": "covered",
        },
    }


def compact_signal(row: dict[str, str]) -> dict[str, Any]:
    return {
        "name": row.get("name", ""),
        "kind": row.get("kind", ""),
        "status": row.get("status", ""),
        "priority": fnum(row.get("priority")),
        "all_delta": fnum(row.get("all_delta")),
        "worst_holdout_delta": fnum(row.get("worst_holdout_delta")),
        "fires": inum(row.get("fires")),
        "fixes": inum(row.get("fixes")),
        "regressions": inum(row.get("regressions")),
        "decision": row.get("decision", ""),
        "source": row.get("source", ""),
        "notes": row.get("notes", ""),
    }


def compact_curriculum(row: dict[str, str]) -> dict[str, Any]:
    return {
        "rank": inum(row.get("rank")),
        "status": row.get("status", ""),
        "family": row.get("family", ""),
        "archetype": row.get("archetype", ""),
        "deck_hash": row.get("deck_hash", ""),
        "adjusted_score": fnum(row.get("adjusted_score")),
        "count": inum(row.get("count")),
        "dominant_tier": row.get("dominant_tier", ""),
        "top_public_motif": row.get("top_public_motif", ""),
        "top_model_motif": row.get("top_model_motif", ""),
        "action_template": row.get("action_template", ""),
        "validation_template": row.get("validation_template", ""),
        "negative_controls": row.get("negative_controls", ""),
        "example": row.get("example", ""),
    }


def compact_stack_row(row: dict[str, str]) -> dict[str, Any]:
    return {
        "scope": row.get("scope", ""),
        "name": row.get("name", ""),
        "total": inum(row.get("total")),
        "base_top1": fnum(row.get("base_top1")),
        "stack_top1": fnum(row.get("stack_top1")),
        "top1_delta": inum(row.get("top1_delta")),
        "base_top3": fnum(row.get("base_top3")),
        "stack_top3": fnum(row.get("stack_top3")),
        "top3_delta": inum(row.get("top3_delta")),
        "fires": inum(row.get("fires")),
        "fixes": inum(row.get("fixes")),
        "regressions": inum(row.get("regressions")),
    }


def build_blueprint(args: argparse.Namespace) -> dict[str, Any]:
    signal_rows = read_csv(args.signal_registry)
    feature_rows = read_csv(args.feature_stack)
    curriculum_rows = read_csv(args.curriculum)
    backtest_rows = read_csv(args.backtest)

    accepted = top_rows(signal_rows, limit=args.signal_limit)
    rejected = rejected_rows(signal_rows, limit=args.reject_limit)
    curriculum = curriculum_rows[: args.curriculum_limit]

    ability_stack = summarize_stack(feature_rows, "ability_stable")
    attachment_stack = summarize_stack(feature_rows, "attachment_mined_any")
    tempo_stack = summarize_stack(feature_rows, "tempo_play_over_attack")
    composition_a = summarize_stack(feature_rows, "tempo_then_ability_attachment")
    composition_b = summarize_stack(feature_rows, "ability_attachment_then_tempo")

    return {
        "metadata": metadata(Path.cwd()),
        "sources": {
            "signal_registry": str(args.signal_registry),
            "feature_stack": str(args.feature_stack),
            "curriculum": str(args.curriculum),
            "fidelity_closure": str(args.fidelity),
            "backtest_summary": str(args.backtest),
        },
        "premise": {
            "strategy_priority": "strategy and decision timing over deck architecture",
            "non_transitive_game_theory": "Pokemon TCG is type-balanced and non-transitive; pair/value gates must avoid single-deck overfit.",
            "local_full_game_status": "fenced: replay-pool gauntlets and ordinary local win rates are research-only",
            "primary_signal": "public replay action imitation plus completed GarlicToday public scores",
        },
        "evidence_hierarchy": [
            "Completed GarlicToday public submissions and exact public replays",
            "Exact-deck-hash public-action anchors with public replay support",
            "Public-score backtest metrics that cover required anchors",
            "Public-action imitation feature gates with non-negative holdouts",
            "Local heldout, PSRO, PIMC, replay-pool, and RL metrics as research-only signals",
        ],
        "strategy_core": {
            "recommended_stack": {
                "name": "tempo_then_ability_attachment",
                "reason": "best all-row top-1 lift in the current feature stack; treat as soft value/ranker features",
                "overall": compact_stack_row(composition_a["overall"]),
            },
            "close_variant": {
                "name": "ability_attachment_then_tempo",
                "reason": "slightly stronger exact-public tier in some rows; keep as ablation/check",
                "overall": compact_stack_row(composition_b["overall"]),
            },
            "ability_before_attack": {
                "policy": "prefer Dudunsparce/engine ability timing before attack when feature fires",
                "exceptions": accepted_timing_exceptions(signal_rows),
                "overall": compact_stack_row(ability_stack["overall"]),
            },
            "attachment_vs_play": {
                "policy": "prefer play/search-first over attach-now only under accepted mined predicates",
                "predicates": accepted_attachment_predicates(signal_rows),
                "overall": compact_stack_row(attachment_stack["overall"]),
            },
            "play_over_attack_tempo": {
                "policy": "prefer continuing play/search over attack for the stable predicate, not a broad attack override",
                "stable_predicate": "stadium_played=False & supporter_played=True",
                "overall": compact_stack_row(tempo_stack["overall"]),
            },
        },
        "feature_stack_details": {
            "tempo_then_ability_attachment": {
                "overall": compact_stack_row(composition_a["overall"]),
                "tiers": [compact_stack_row(row) for row in composition_a["tiers"]],
                "holdouts": [compact_stack_row(row) for row in composition_a["holdouts"]],
                "top_lanes": [compact_stack_row(row) for row in composition_a["top_lanes"]],
            },
            "ability_attachment_then_tempo": {
                "overall": compact_stack_row(composition_b["overall"]),
                "tiers": [compact_stack_row(row) for row in composition_b["tiers"]],
                "holdouts": [compact_stack_row(row) for row in composition_b["holdouts"]],
            },
        },
        "accepted_signals": [compact_signal(row) for row in accepted],
        "negative_controls": [compact_signal(row) for row in rejected],
        "curriculum_targets": [compact_curriculum(row) for row in curriculum],
        "backtest_gate": gate_summary(backtest_rows),
        "best_backtest_rows": best_backtest_rows(backtest_rows),
        "pimc_status": {
            "source": "strategy/pimc_suitability_probe_20260620T1724_100games.md",
            "lc": 0.7145,
            "lc_95ci": [0.1762, 0.9425],
            "bias": -0.2080,
            "bias_95ci": [-0.2756, -0.1334],
            "df": 0.8552,
            "df_95ci": [0.4937, 0.9301],
            "decision": "PIMC/cheap determinization is research-only because rollout bias is large and negative",
        },
        "gates": {
            "no_live_submission": True,
            "candidate_promotion": "requires public-anchor support plus trusted public-score backtest",
            "metric_gate": "Spearman >= 0.55, Kendall > 0, n >= 5, trusted=1, required anchors covered",
            "package_status": "no submit-safe pair validated",
        },
    }


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def render_signal_table(signals: list[dict[str, Any]], limit: int = 10) -> str:
    rows: list[list[str]] = []
    for row in signals[:limit]:
        rows.append(
            [
                row["name"],
                row["status"],
                f"{row['priority']:.3f}",
                f"{row['all_delta']:.3f}",
                f"{row['worst_holdout_delta']:.3f}",
                str(row["fixes"]),
                str(row["regressions"]),
                row["decision"],
            ]
        )
    return markdown_table(
        ["Signal", "Status", "Priority", "All Delta", "Worst Holdout", "Fixes", "Regressions", "Decision"],
        rows,
    )


def render_curriculum_table(targets: list[dict[str, Any]], limit: int = 8) -> str:
    rows: list[list[str]] = []
    for row in targets[:limit]:
        rows.append(
            [
                str(row["rank"]),
                row["family"],
                row["archetype"],
                row["deck_hash"],
                row["dominant_tier"],
                str(row["count"]),
                row["top_public_motif"],
                row["top_model_motif"],
                row["action_template"],
            ]
        )
    return markdown_table(
        ["Rank", "Gap Family", "Archetype", "Hash", "Tier", "Rows", "Public Motif", "Model Motif", "Training Target"],
        rows,
    )


def render_backtest_table(rows: list[dict[str, str]], limit: int = 8) -> str:
    rendered: list[list[str]] = []
    for row in rows[:limit]:
        rendered.append(
            [
                row.get("public_target", ""),
                row.get("metric", ""),
                row.get("n", ""),
                fmt_float(row.get("spearman")),
                fmt_float(row.get("kendall")),
                row.get("required_missing") or "-",
                row.get("trusted", ""),
            ]
        )
    return markdown_table(
        ["Target", "Metric", "n", "Spearman", "Kendall", "Missing Anchors", "Trusted"],
        rendered,
    )


def render_stack_summary(stack: dict[str, Any]) -> str:
    overall = stack["overall"]
    return (
        f"`{stack['stack']}`: top1 {fmt_float(overall.get('base_top1'))} -> "
        f"{fmt_float(overall.get('stack_top1'))}, delta {overall.get('top1_delta', 0)}, "
        f"fires {overall.get('fires', 0)}, fixes {overall.get('fixes', 0)}, "
        f"regressions {overall.get('regressions', 0)}"
    )


def render_markdown(blueprint: dict[str, Any]) -> str:
    meta = blueprint["metadata"]
    core = blueprint["strategy_core"]
    gate = blueprint["backtest_gate"]
    best_required = gate.get("best_required_anchor_metric") or {}
    lines: list[str] = [
        "# Public-Anchor Strategy Blueprint",
        "",
        f"Generated: {meta['generated_utc']}",
        "",
        "## Metadata",
        "",
        f"- Implementation agent: {meta['implementation_agent']}",
        f"- Model family exposed to this thread: {meta['model_family']}",
        f"- Workspace: `{meta['workspace']}`",
        f"- Host: `{meta['host']}`",
        f"- Runtime premise: {meta['play_time_runtime']}",
        "- Live submission action: none",
        "",
        "## Premise",
        "",
        "This blueprint is strategy-first.  The current public evidence says the transferable edge is not a new deck shell; it is timing policy: ability sequencing, attachment timing, and play-vs-attack tempo.  Because the hardened replay-fidelity audit fenced the local full-game simulator, these signals are for behavior cloning, value features, conservative offline RL, and regression guards only.",
        "",
        "Evidence hierarchy:",
    ]
    lines.extend(f"- {item}" for item in blueprint["evidence_hierarchy"])
    lines.extend(
        [
            "",
            "## Current Strategy Core",
            "",
            f"- Recommended stack: `{core['recommended_stack']['name']}`. {core['recommended_stack']['reason']}.",
            f"- Close ablation: `{core['close_variant']['name']}`. {core['close_variant']['reason']}.",
            f"- Ability timing: {core['ability_before_attack']['policy']}. Exceptions: {', '.join(core['ability_before_attack']['exceptions']) or 'none'}.",
            f"- Attachment timing: {core['attachment_vs_play']['policy']}. Predicates: {', '.join(core['attachment_vs_play']['predicates']) or 'none'}.",
            f"- Tempo: {core['play_over_attack_tempo']['policy']}. Stable predicate: `{core['play_over_attack_tempo']['stable_predicate']}`.",
            "",
            "Stack summaries:",
            "",
            f"- {render_stack_summary({'stack': core['recommended_stack']['name'], 'overall': core['recommended_stack']['overall']})}",
            f"- {render_stack_summary({'stack': core['close_variant']['name'], 'overall': core['close_variant']['overall']})}",
            f"- {render_stack_summary({'stack': 'ability_stable', 'overall': core['ability_before_attack']['overall']})}",
            f"- {render_stack_summary({'stack': 'attachment_mined_any', 'overall': core['attachment_vs_play']['overall']})}",
            f"- {render_stack_summary({'stack': 'tempo_play_over_attack', 'overall': core['play_over_attack_tempo']['overall']})}",
            "",
            "## Accepted Signals",
            "",
            render_signal_table(blueprint["accepted_signals"], limit=12),
            "",
            "## ML/RL Curriculum Targets",
            "",
            "Train on the highest public-anchor gaps first.  Each target must keep its validation template and negative controls; do not turn these into hard runtime branches without public-score backtest support.",
            "",
            render_curriculum_table(blueprint["curriculum_targets"], limit=10),
            "",
            "## Negative Controls",
            "",
            "These are the paths that looked locally appealing but failed a holdout, public-anchor tier, or broadness test. Keep them as regression guards.",
            "",
            render_signal_table(blueprint["negative_controls"], limit=12),
            "",
            "## Gate Status",
            "",
            f"- Gate: **{gate['gate'].upper()}**",
            f"- Trusted public-score metric count: {gate['trusted_metric_count']}",
            f"- Best required-anchor metric: `{best_required.get('metric', '-')}` Spearman {fmt_float(best_required.get('spearman'))}, Kendall {fmt_float(best_required.get('kendall'))}, trusted={best_required.get('trusted', '-')}.",
            "- No submit-safe pair is validated.",
            "- Minimum submit-facing metric: Spearman >= 0.55, Kendall > 0, n >= 5, trusted=1, required anchors covered.",
            "",
            render_backtest_table(blueprint["best_backtest_rows"], limit=8),
            "",
            "## PIMC / Game-Theory Note",
            "",
            "The 100-game suitability probe is stabilized but not submit-facing: lc=0.7145, bias=-0.2080, df=0.8552. Cheap determinization has large negative rollout bias here; use ISMCTS/CFR/PSRO-style work as offline research unless public-anchor and public-score gates clear.",
            "",
            "## Operational Next Step",
            "",
            "Implement the strategy core as soft features in the action ranker or behavior-cloning target, then evaluate only through public-anchor holdouts and the public-score backtest gate. The first concrete target remains Hop's Trevenant attachment-vs-play timing, followed by attack-vs-play tempo, attachment target timing, and turn-end discipline.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signal-registry", type=Path, default=DEFAULT_SIGNAL_REGISTRY)
    parser.add_argument("--feature-stack", type=Path, default=DEFAULT_FEATURE_STACK)
    parser.add_argument("--curriculum", type=Path, default=DEFAULT_CURRICULUM)
    parser.add_argument("--fidelity", type=Path, default=DEFAULT_FIDELITY)
    parser.add_argument("--backtest", type=Path, default=DEFAULT_BACKTEST)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--signal-limit", type=int, default=16)
    parser.add_argument("--reject-limit", type=int, default=16)
    parser.add_argument("--curriculum-limit", type=int, default=16)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    blueprint = build_blueprint(args)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_markdown(blueprint), encoding="utf-8")
    args.json_out.write_text(json.dumps(blueprint, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {args.report_out}")
    print(f"Wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
