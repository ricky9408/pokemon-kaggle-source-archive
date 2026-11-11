#!/usr/bin/env python3
"""Mine interpretable policy gaps from replay decisions and an action ranker.

The action ranker is intentionally weak as a direct policy, but its errors are
useful: they show where public play in the current replay window disagrees with
the learned prior. This report turns those errors into strategy motifs for the
next hand-written policy or RL/self-play experiment.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from train_action_ranker import load_rows, option_parts, pct, ranked_options, valid_single_label


TARGET_TYPES = {"ABILITY", "ATTACH", "ATTACK", "END", "PLAY", "RETREAT"}


@dataclass
class GapCase:
    count: int
    gap: str
    context: str
    archetype: str
    opponent: str
    selected: str
    predicted: str
    reward: str


def load_model(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    weights = payload.get("weights")
    if not isinstance(weights, dict):
        raise ValueError(f"{path} does not contain a weights object")
    return {str(key): float(value) for key, value in weights.items()}


def card_name(description: str) -> str:
    body = description.split(" ", 1)[1] if " " in description else description
    if "(" in body:
        return body.rsplit("(", 1)[0].strip()
    return body.strip()


def motif(description: str) -> str:
    parts = option_parts(description)
    option_type = parts["type"]
    if option_type == "ATTACH":
        target = parts["to_area"] or "UNKNOWN"
        return f"attach_{target.lower()}"
    if option_type in {"YES", "NO"}:
        return f"activate_{option_type.lower()}"
    if option_type in TARGET_TYPES:
        return option_type.lower()
    return f"other_{option_type.lower()}"


def normalize_type(description: str) -> str:
    return option_parts(description)["type"] or "UNKNOWN"


def classify_gap(row: dict[str, Any], selected: str, predicted: str) -> str | None:
    if selected == predicted:
        return None

    context = str(row.get("context") or "")
    selected_parts = option_parts(selected)
    predicted_parts = option_parts(predicted)
    selected_type = selected_parts["type"]
    predicted_type = predicted_parts["type"]

    if context == "ACTIVATE":
        if selected_type == "NO" and predicted_type == "YES":
            return "public_declines_activation_model_uses"
        if selected_type == "YES" and predicted_type == "NO":
            return "public_uses_activation_model_declines"
        if selected_type in {"YES", "NO"} or predicted_type in {"YES", "NO"}:
            return "activation_choice_mismatch"

    if selected_type == "ATTACH" and predicted_type == "ATTACH":
        selected_area = selected_parts["to_area"] or "UNKNOWN"
        predicted_area = predicted_parts["to_area"] or "UNKNOWN"
        same_card = selected_parts["card"] == predicted_parts["card"]
        card_suffix = "same_card" if same_card else "different_card"
        if selected_area != predicted_area:
            return f"public_attach_{selected_area.lower()}_model_{predicted_area.lower()}_{card_suffix}"
        if not same_card:
            return "attach_card_mismatch_same_target"
        return None

    if selected_type == "ATTACH" and predicted_type != "ATTACH":
        selected_area = selected_parts["to_area"] or "UNKNOWN"
        return f"public_attach_{selected_area.lower()}_model_{predicted_type.lower()}"

    if predicted_type == "ATTACH" and selected_type != "ATTACH":
        predicted_area = predicted_parts["to_area"] or "UNKNOWN"
        return f"model_attach_{predicted_area.lower()}_public_{selected_type.lower()}"

    if predicted_type == "ABILITY" and selected_type != "ABILITY":
        return f"public_{selected_type.lower()}_before_model_ability"

    if selected_type == "ABILITY" and predicted_type != "ABILITY":
        return f"public_ability_before_model_{predicted_type.lower()}"

    if selected_type in {"ATTACK", "END", "RETREAT"} and predicted_type in TARGET_TYPES:
        return f"public_{selected_type.lower()}_model_{predicted_type.lower()}"

    if predicted_type in {"ATTACK", "END", "RETREAT"} and selected_type in TARGET_TYPES:
        return f"model_{predicted_type.lower()}_public_{selected_type.lower()}"

    return None


def reward_bucket(value: Any) -> str:
    if value == 1:
        return "win"
    if value == -1:
        return "loss"
    if value == 0:
        return "draw"
    return "unknown"


def row_group(row: dict[str, Any], field: str) -> str:
    value = row.get(field)
    if value is None:
        return "unknown"
    return str(value)


def format_counter(counter: Counter[str], limit: int) -> list[str]:
    lines = ["| Item | Count |", "| --- | ---: |"]
    for item, count in counter.most_common(limit):
        lines.append(f"| `{item}` | {count} |")
    if not counter:
        lines.append("| - | 0 |")
    return lines


def render_gap_table(title: str, counter: Counter[str], total: int, limit: int) -> list[str]:
    lines = [f"## {title}", "", "| Gap | Count | Share |", "| --- | ---: | ---: |"]
    for gap, count in counter.most_common(limit):
        lines.append(f"| `{gap}` | {count} | {pct(count, total)} |")
    if not counter:
        lines.append("| - | 0 | 0.000 |")
    lines.append("")
    return lines


def render_nested_counter(
    title: str,
    nested: dict[str, Counter[str]],
    gap_counts: Counter[str],
    limit: int,
    inner_limit: int,
) -> list[str]:
    lines = [f"## {title}", ""]
    for gap, _ in gap_counts.most_common(limit):
        lines.append(f"### `{gap}`")
        lines.append("")
        lines.extend(format_counter(nested.get(gap, Counter()), inner_limit))
        lines.append("")
    return lines


def strategic_directives(
    gap_counts: Counter[str],
    selected_motifs: Counter[str],
    predicted_motifs: Counter[str],
) -> list[str]:
    directives: list[str] = []
    active_to_bench = sum(
        count
        for gap, count in gap_counts.items()
        if gap.startswith("public_attach_active_model_bench")
    )
    bench_to_active = sum(
        count
        for gap, count in gap_counts.items()
        if gap.startswith("public_attach_bench_model_active")
    )
    model_ability_after_public = sum(
        count
        for gap, count in gap_counts.items()
        if gap.endswith("_before_model_ability")
    )
    decline_activation = gap_counts.get("public_declines_activation_model_uses", 0)
    use_activation = gap_counts.get("public_uses_activation_model_declines", 0)

    if active_to_bench > bench_to_active and active_to_bench >= 20:
        directives.append(
            "Test attach-to-active restraint/priority first: public replays often keep energy on active attackers while the model wants bench targets."
        )
    elif bench_to_active >= 20:
        directives.append(
            "Test bench-development attachment priority: public replays often attach to bench while the model overweights active targets."
        )

    if decline_activation >= max(10, use_activation * 2):
        directives.append(
            "Add an optional-activation throttle before more deck changes: public play often declines activations that the model wants to fire."
        )
    elif use_activation >= 10:
        directives.append(
            "Find missed must-use activations: public play uses some activations that the model declines."
        )

    if model_ability_after_public >= 50:
        directives.append(
            "Keep mining ability timing: public play repeatedly performs urgent attach/play/attack/end choices before the model's preferred ability."
        )

    if predicted_motifs.get("ability", 0) > selected_motifs.get("ability", 0) * 1.25:
        directives.append(
            "The learned prior is ability-heavy relative to public selections; every ability patch needs a motif holdout and broad payoff check."
        )

    if not directives:
        directives.append(
            "No single targeted motif dominates; keep using PSRO/payoff and public-failure penalties before promoting policy patches."
        )
    return directives


def mine(rows: list[dict[str, Any]], weights: dict[str, float], min_gap_count: int) -> dict[str, Any]:
    gap_counts: Counter[str] = Counter()
    context_counts: Counter[str] = Counter()
    selected_motifs: Counter[str] = Counter()
    predicted_motifs: Counter[str] = Counter()
    by_archetype: dict[str, Counter[str]] = defaultdict(Counter)
    by_opponent: dict[str, Counter[str]] = defaultdict(Counter)
    by_team: dict[str, Counter[str]] = defaultdict(Counter)
    by_reward: dict[str, Counter[str]] = defaultdict(Counter)
    examples: Counter[tuple[str, str, str, str, str, str, str]] = Counter()

    scored = 0
    mismatches = 0
    skipped = 0
    targeted = 0

    for row in rows:
        label = valid_single_label(row)
        if label is None:
            skipped += 1
            continue
        ranking = ranked_options(weights, row)
        if not ranking:
            skipped += 1
            continue
        options = row.get("options") or []
        if not (0 <= label < len(options) and 0 <= ranking[0] < len(options)):
            skipped += 1
            continue
        selected = str(options[label])
        predicted = str(options[ranking[0]])
        scored += 1
        context = row_group(row, "context")
        context_counts[context] += 1
        selected_motifs[motif(selected)] += 1
        predicted_motifs[motif(predicted)] += 1
        if selected == predicted:
            continue
        mismatches += 1
        gap = classify_gap(row, selected, predicted)
        if gap is None:
            continue
        targeted += 1
        gap_counts[gap] += 1
        by_archetype[gap][row_group(row, "archetype")] += 1
        by_opponent[gap][row_group(row, "opponent_archetype")] += 1
        by_team[gap][row_group(row, "team")] += 1
        by_reward[gap][reward_bucket(row.get("terminal_reward"))] += 1
        examples[
            (
                gap,
                context,
                row_group(row, "archetype"),
                row_group(row, "opponent_archetype"),
                selected,
                predicted,
                reward_bucket(row.get("terminal_reward")),
            )
        ] += 1

    filtered_examples = [
        GapCase(count, *key)
        for key, count in examples.items()
        if count >= min_gap_count
    ]
    filtered_examples.sort(key=lambda item: item.count, reverse=True)

    return {
        "scored": scored,
        "skipped": skipped,
        "mismatches": mismatches,
        "targeted": targeted,
        "context_counts": context_counts,
        "gap_counts": gap_counts,
        "selected_motifs": selected_motifs,
        "predicted_motifs": predicted_motifs,
        "by_archetype": by_archetype,
        "by_opponent": by_opponent,
        "by_team": by_team,
        "by_reward": by_reward,
        "examples": filtered_examples,
    }


def render_report(args: argparse.Namespace, row_count: int, mined: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scored = mined["scored"]
    mismatches = mined["mismatches"]
    targeted = mined["targeted"]
    gap_counts: Counter[str] = mined["gap_counts"]

    lines: list[str] = []
    lines.append("# Policy Gap Miner")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.getenv('USER', 'unknown')}")
    lines.append("- Strategic premise: use ML/RL to discover policy motifs, not to blindly chase one local deck.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Decisions: `{args.decisions}`")
    lines.append(f"- Model: `{args.model}`")
    lines.append(f"- Rows loaded: {row_count}")
    lines.append(f"- Scored single-action nontrivial rows: {scored}")
    lines.append(f"- Skipped rows: {mined['skipped']}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Model/public top-choice mismatches: {mismatches}/{scored} = {pct(mismatches, scored)}")
    lines.append(f"- Targeted strategic gaps: {targeted}/{scored} = {pct(targeted, scored)}")
    lines.append(f"- Targeted gap share of mismatches: {pct(targeted, mismatches)}")
    lines.append("")

    lines.extend(render_gap_table("Targeted Gap Classes", gap_counts, max(1, targeted), args.limit))

    lines.append("## Public Selection Motifs")
    lines.append("")
    lines.extend(format_counter(mined["selected_motifs"], args.limit))
    lines.append("")
    lines.append("## Model Top-Choice Motifs")
    lines.append("")
    lines.extend(format_counter(mined["predicted_motifs"], args.limit))
    lines.append("")

    lines.extend(
        render_nested_counter(
            "Gaps By Our Archetype",
            mined["by_archetype"],
            gap_counts,
            args.limit,
            args.inner_limit,
        )
    )
    lines.extend(
        render_nested_counter(
            "Gaps By Opponent Archetype",
            mined["by_opponent"],
            gap_counts,
            args.limit,
            args.inner_limit,
        )
    )
    lines.extend(
        render_nested_counter(
            "Gaps By Terminal Result",
            mined["by_reward"],
            gap_counts,
            min(args.limit, 10),
            4,
        )
    )

    lines.append("## Repeated Concrete Cases")
    lines.append("")
    lines.append("| Count | Gap | Context | Our Archetype | Opponent | Public | Model | Result |")
    lines.append("| ---: | --- | --- | --- | --- | --- | --- | --- |")
    for case in mined["examples"][: args.case_limit]:
        lines.append(
            f"| {case.count} | `{case.gap}` | `{case.context}` | `{case.archetype}` | "
            f"`{case.opponent}` | `{case.selected}` | `{case.predicted}` | `{case.reward}` |"
        )
    if not mined["examples"]:
        lines.append("| 0 | - | - | - | - | - | - | - |")
    lines.append("")

    lines.append("## Strategy Directives")
    lines.append("")
    for directive in strategic_directives(
        gap_counts,
        mined["selected_motifs"],
        mined["predicted_motifs"],
    ):
        lines.append(f"- {directive}")
    lines.append("")
    lines.append("## Workflow Use")
    lines.append("")
    lines.append("1. Convert dominant gaps into a tiny policy patch or candidate population member.")
    lines.append("2. Re-run action holdout and motif holdout before local gauntlets.")
    lines.append("3. Validate with process-recycled payoff chunks against current pressure lanes.")
    lines.append("4. Let PSRO/pair selection apply diversity and public-failure penalties before any submit gate.")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, default=Path("strategy/policy_gap_miner.md"))
    parser.add_argument("--limit", type=int, default=16)
    parser.add_argument("--inner-limit", type=int, default=8)
    parser.add_argument("--case-limit", type=int, default=30)
    parser.add_argument("--min-gap-count", type=int, default=2)
    args = parser.parse_args()

    rows = load_rows(args.decisions)
    weights = load_model(args.model)
    mined = mine(rows, weights, args.min_gap_count)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, len(rows), mined), encoding="utf-8")
    print(
        "rows={rows} scored={scored} mismatches={mismatches} targeted={targeted} report={report}".format(
            rows=len(rows),
            scored=mined["scored"],
            mismatches=mined["mismatches"],
            targeted=mined["targeted"],
            report=args.report_out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
