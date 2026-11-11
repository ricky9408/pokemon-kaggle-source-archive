#!/usr/bin/env python3
"""Compile the strategy blueprint into a deterministic adapter config.

This tool is the bridge between strategy research and future agent work.  It
reads the public-anchor strategy blueprint, emits a declarative runtime adapter
spec, and evaluates that spec through the same offline public-action imitation
harness used by the feature-stack reports.

It deliberately does not package or submit an agent.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluate_strategy_feature_stack import evaluate, result_by_name, stats_row  # noqa: E402


DEFAULT_BLUEPRINT = Path("strategy/strategy_blueprint_20260620T2018.json")
DEFAULT_DECISIONS = Path("strategy/ml_decisions_20260620T1611_strategy.jsonl")
DEFAULT_MODEL = Path("strategy/action_ranker_model_20260620T0038_plus_failures.json")
DEFAULT_ANCHOR_STATUS = Path("strategy/public_anchor_report_20260620T1736.csv")
DEFAULT_HOLDOUT_KEYS = ["team", "opponent_team", "episode_id", "source"]


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def read_blueprint(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def adapter_from_blueprint(blueprint: dict[str, Any]) -> dict[str, Any]:
    core = blueprint["strategy_core"]
    return {
        "metadata": {
            "generated_utc": now_utc(),
            "implementation_agent": "Codex coding agent",
            "model_family": "GPT-5",
            "workspace": str(Path.cwd()),
            "host": socket.gethostname(),
            "pid": os.getpid(),
            "user": os.environ.get("USER", ""),
            "runtime_policy": "deterministic offline; no network or LLM at play time",
        },
        "status": {
            "submit_selector": False,
            "package_promotion": "blocked until public-anchor and public-score backtest gates clear",
            "local_full_game_metric": "fenced",
        },
        "adapter": {
            "name": core["recommended_stack"]["name"],
            "style": "soft_action_rerank",
            "description": "Apply public-anchor timing motifs as ordered soft reranking steps.",
            "steps": [
                {
                    "kind": "tempo_play_over_attack",
                    "name": "tempo_play_over_attack_supporter_no_stadium",
                    "predicate": core["play_over_attack_tempo"]["stable_predicate"],
                    "intent": core["play_over_attack_tempo"]["policy"],
                },
                {
                    "kind": "ability_before_attack",
                    "name": "dudunsparce_stable",
                    "predicate": "all",
                    "exceptions": core["ability_before_attack"]["exceptions"],
                    "intent": core["ability_before_attack"]["policy"],
                },
                {
                    "kind": "attachment_vs_play",
                    "name": "attach_play_mined_any",
                    "predicates": core["attachment_vs_play"]["predicates"],
                    "intent": core["attachment_vs_play"]["policy"],
                },
            ],
        },
        "ablation": {
            "name": core["close_variant"]["name"],
            "reason": core["close_variant"]["reason"],
        },
        "gates": blueprint["gates"],
        "backtest_gate": blueprint["backtest_gate"],
        "negative_controls": blueprint["negative_controls"],
        "curriculum_targets": blueprint["curriculum_targets"][:8],
    }


def parse_eval_args(args: argparse.Namespace, adapter: dict[str, Any]) -> argparse.Namespace:
    step_map = {step["kind"]: step for step in adapter["adapter"]["steps"]}
    ability_step = step_map["ability_before_attack"]
    attachment_step = step_map["attachment_vs_play"]
    tempo_step = step_map["tempo_play_over_attack"]
    return argparse.Namespace(
        decisions=args.decisions,
        model=args.model,
        anchor_status=args.anchor_status,
        ability_predicate=ability_step["predicate"],
        ability_exception=list(ability_step["exceptions"]),
        attachment_predicate=list(attachment_step["predicates"]),
        tempo_predicate=[tempo_step["predicate"]],
        holdout_key=list(args.holdout_key),
        holdout_mod=args.holdout_mod,
        holdout_bucket=args.holdout_bucket,
        min_public_episodes=args.min_public_episodes,
        min_public_teams=args.min_public_teams,
        min_fires=args.min_fires,
        min_gated_fires=args.min_gated_fires,
        limit=args.limit,
        report_out=args.report_out,
        csv_out=args.csv_out,
    )


def ratio(numerator: int, denominator: int) -> str:
    return f"{numerator / denominator:.3f}" if denominator else "0.000"


def result_summary(result: Any) -> dict[str, Any]:
    stats = result.overall
    holdout_deltas = {key: value.top1_delta for key, value in result.holdouts.items()}
    tier_deltas = {key: value.top1_delta for key, value in result.tiers.items()}
    return {
        "stack": result.spec.name,
        "total": stats.total,
        "base_top1": ratio(stats.base_top1, stats.total),
        "stack_top1": ratio(stats.stack_top1, stats.total),
        "top1_delta": stats.top1_delta,
        "base_top3": ratio(stats.base_top3, stats.total),
        "stack_top3": ratio(stats.stack_top3, stats.total),
        "top3_delta": stats.top3_delta,
        "fires": stats.fired,
        "changes": stats.changed,
        "fixes": stats.fixes,
        "regressions": stats.regressions,
        "net_fixes": stats.net_fixes,
        "worst_holdout_delta": min(holdout_deltas.values()) if holdout_deltas else 0,
        "holdout_deltas": holdout_deltas,
        "public_tier_deltas": tier_deltas,
        "step_fires": dict(result.step_fires),
        "step_changes": dict(result.step_changes),
    }


def write_csv(path: Path, selected: list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "stack",
        "total",
        "base_top1",
        "stack_top1",
        "top1_delta",
        "base_top3",
        "stack_top3",
        "top3_delta",
        "fires",
        "changes",
        "fixes",
        "regressions",
        "net_fixes",
        "worst_holdout_delta",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in selected:
            summary = result_summary(result)
            writer.writerow({key: summary[key] for key in fieldnames})


def gate_verdict(summary: dict[str, Any], backtest_gate: dict[str, Any]) -> tuple[str, list[str]]:
    notes: list[str] = []
    if summary["top1_delta"] <= 0:
        notes.append("adapter does not improve public-action top-1")
    if summary["net_fixes"] <= 0:
        notes.append("fixes do not exceed regressions")
    if summary["worst_holdout_delta"] < 0:
        notes.append("a deterministic holdout is negative")
    for tier, delta in summary["public_tier_deltas"].items():
        if tier in {"exact-public-replay-supported", "single-team-public-replay-supported", "candidate-public-contradicted"} and delta < 0:
            notes.append(f"public-anchor tier {tier} is negative")
    if backtest_gate.get("gate") != "open":
        notes.append("public-score backtest gate is closed, so this cannot promote a package")
    if notes:
        return "research-only", notes
    return "adapter-ready-for-human-review", ["all offline adapter checks are positive"]


def render_report(
    args: argparse.Namespace,
    adapter: dict[str, Any],
    results: list[Any],
    eval_meta: dict[str, Any],
) -> str:
    by_name = result_by_name(results)
    target_name = adapter["adapter"]["name"]
    ablation_name = adapter["ablation"]["name"]
    target = by_name[target_name]
    ablation = by_name.get(ablation_name)
    target_summary = result_summary(target)
    verdict, notes = gate_verdict(target_summary, adapter["backtest_gate"])
    lines = [
        "# Strategy Adapter Compilation",
        "",
        f"Generated: {adapter['metadata']['generated_utc']}",
        "",
        "## Metadata",
        "",
        f"- Implementation agent: {adapter['metadata']['implementation_agent']}",
        f"- Model family exposed to this thread: {adapter['metadata']['model_family']}",
        f"- Workspace: `{adapter['metadata']['workspace']}`",
        f"- Host: `{adapter['metadata']['host']}`",
        f"- Process metadata: pid={adapter['metadata']['pid']} user={adapter['metadata']['user']}",
        f"- Runtime policy: {adapter['metadata']['runtime_policy']}",
        "- Live submission action: none",
        "",
        "## Inputs",
        "",
        f"- Blueprint: `{args.blueprint}`",
        f"- Decisions: `{args.decisions}`",
        f"- Action-ranker model: `{args.model}`",
        f"- Anchor status: `{args.anchor_status}`",
        f"- Rows loaded: {eval_meta['rows']}",
        "",
        "## Adapter",
        "",
        f"- Name: `{target_name}`",
        f"- Style: `{adapter['adapter']['style']}`",
        f"- Verdict: `{verdict}`",
        "- Steps:",
    ]
    for step in adapter["adapter"]["steps"]:
        if step["kind"] == "ability_before_attack":
            lines.append(f"  - `{step['kind']}` predicate=`{step['predicate']}` exceptions={step['exceptions']}")
        elif step["kind"] == "attachment_vs_play":
            lines.append(f"  - `{step['kind']}` predicates={step['predicates']}")
        else:
            lines.append(f"  - `{step['kind']}` predicate=`{step['predicate']}`")
    lines.extend(["", "## Offline Validation", ""])
    lines.extend(notes_to_lines(notes))
    lines.extend(
        [
            "",
            "| Stack | N | Base Top-1 | Stack Top-1 | Delta | Vs Reference | Base Top-3 | Stack Top-3 | Fires | Changes | Fixes | Regressions |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            stats_row(target.spec.name, target.overall),
        ]
    )
    if ablation is not None:
        lines.append(stats_row(ablation.spec.name, ablation.overall))
    lines.extend(
        [
            "",
            "### Holdout Deltas",
            "",
            "| Stack | Worst Holdout | Deltas |",
            "| --- | ---: | --- |",
        ]
    )
    for result in [target] + ([ablation] if ablation is not None else []):
        deltas = {key: stats.top1_delta for key, stats in result.holdouts.items()}
        detail = ", ".join(f"{key}={value:+d}" for key, value in sorted(deltas.items()))
        worst = min(deltas.values()) if deltas else 0
        lines.append(f"| `{result.spec.name}` | {worst:+d} | {detail} |")
    lines.extend(
        [
            "",
            "### Public-Anchor Tier Deltas",
            "",
            "| Stack | Tier | N | Delta | Fixes | Regressions |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for result in [target] + ([ablation] if ablation is not None else []):
        for tier, stats in sorted(result.tiers.items()):
            lines.append(
                f"| `{result.spec.name}` | `{tier}` | {stats.total} | {stats.top1_delta:+d} | "
                f"{stats.fixes} | {stats.regressions} |"
            )
    lines.extend(
        [
            "",
            "## Gate Status",
            "",
            f"- Public-score backtest gate: `{adapter['backtest_gate'].get('gate')}`",
            f"- Trusted metric count: {adapter['backtest_gate'].get('trusted_metric_count')}",
            f"- Package promotion: {adapter['status']['package_promotion']}",
            "- This adapter is suitable for future behavior-cloning/value/RL implementation experiments only.",
            "",
            "## Next Implementation Contract",
            "",
            "- Implement the adapter as additive action-value features, not hard legal-action overrides.",
            "- Preserve these exact predicates and exceptions in any agent branch.",
            "- Re-run public-action holdouts, public-anchor report, and public-score backtest before packaging.",
            "- Do not submit from this artifact directly.",
            "",
        ]
    )
    return "\n".join(lines)


def notes_to_lines(notes: list[str]) -> list[str]:
    return [f"- {note}" for note in notes]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", type=Path, default=DEFAULT_BLUEPRINT)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--anchor-status", type=Path, default=DEFAULT_ANCHOR_STATUS)
    parser.add_argument("--holdout-key", action="append", default=list(DEFAULT_HOLDOUT_KEYS))
    parser.add_argument("--holdout-mod", type=int, default=5)
    parser.add_argument("--holdout-bucket", type=int, default=0)
    parser.add_argument("--min-public-episodes", type=int, default=5)
    parser.add_argument("--min-public-teams", type=int, default=2)
    parser.add_argument("--min-fires", type=int, default=25)
    parser.add_argument("--min-gated-fires", type=int, default=10)
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--adapter-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--csv-out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    blueprint = read_blueprint(args.blueprint)
    adapter = adapter_from_blueprint(blueprint)
    eval_args = parse_eval_args(args, adapter)
    results, eval_meta = evaluate(eval_args)
    by_name = result_by_name(results)
    selected = [by_name[adapter["adapter"]["name"]]]
    if adapter["ablation"]["name"] in by_name:
        selected.append(by_name[adapter["ablation"]["name"]])
    adapter["offline_validation"] = {
        result.spec.name: result_summary(result) for result in selected
    }
    adapter["evaluation_inputs"] = {
        "decisions": str(args.decisions),
        "model": str(args.model),
        "anchor_status": str(args.anchor_status),
        "rows": eval_meta["rows"],
        "holdout_keys": list(args.holdout_key),
    }
    args.adapter_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.csv_out.parent.mkdir(parents=True, exist_ok=True)
    args.adapter_out.write_text(json.dumps(adapter, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    args.report_out.write_text(render_report(args, adapter, results, eval_meta), encoding="utf-8")
    write_csv(args.csv_out, selected)
    print(f"Wrote {args.adapter_out}")
    print(f"Wrote {args.report_out}")
    print(f"Wrote {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
