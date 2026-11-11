#!/usr/bin/env python3
"""Build archive-keyed replay-action feature metrics from decision rows.

`public_action_mismatch_gate.py` compares candidates against public replay
decisions. Its aggregate same-rate is too blunt: recent public anchors show that
raw agreement can improve while public score falls. This tool keeps the same
non-leaky shape as the other metric-panel builders, but splits decision
agreement by risk context such as Dudunsparce ability use, active Psychic
attachments, attacks, late turns, and low-prize states.
"""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


def normalize(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def parse_maps(values: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    exact: dict[str, str] = {}
    normalized: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--map must be LABEL=ARCHIVE, got: {value}")
        label, archive = value.split("=", 1)
        label = label.strip()
        archive = Path(archive.strip()).name
        exact[label] = archive
        normalized[normalize(label)] = archive
    return exact, normalized


def candidate_for_archive(archive: str) -> str:
    return Path(archive).name.removeprefix("submission-").removesuffix(".tar.gz").replace("-", "_")


def mapped_archive(label: str, exact: dict[str, str], normalized: dict[str, str]) -> str | None:
    return exact.get(label) or normalized.get(normalize(label))


def truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def parse_float(value: object, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def has_type(row: dict[str, str], column: str, value: str) -> bool:
    return value in {part.strip() for part in (row.get(column) or "").split("|") if part.strip()}


def has_card_id(row: dict[str, str], column: str, card_ids: set[int]) -> bool:
    raw = row.get(column) or ""
    for part in raw.split(","):
        try:
            if int(part.strip()) in card_ids:
                return True
        except ValueError:
            continue
    return False


PSYCHIC_LINE_IDS = {741, 742, 743}


def active_zero_energy_psychic_line_proxy(row: dict[str, str]) -> bool:
    return has_card_id(row, "active_ids", PSYCHIC_LINE_IDS) and parse_float(row.get("own_active_energy_count")) == 0


def no_play_evolve_active_attach_proxy(row: dict[str, str]) -> bool:
    return (
        active_zero_energy_psychic_line_proxy(row)
        and truthy(row.get("has_active_psychic_attach_option"))
        and parse_float(row.get("available_play_count")) == 0
        and parse_float(row.get("available_evolve_count")) == 0
    )


def play_evolve_contested_active_attach_proxy(row: dict[str, str]) -> bool:
    return (
        active_zero_energy_psychic_line_proxy(row)
        and truthy(row.get("has_active_psychic_attach_option"))
        and (
            parse_float(row.get("available_play_count")) > 0
            or parse_float(row.get("available_evolve_count")) > 0
        )
    )


@dataclass
class PanelRow:
    candidate: str
    archive: str
    metrics: dict[str, float] = field(default_factory=dict)


BucketPredicate = Callable[[dict[str, str]], bool]


BUCKETS: list[tuple[str, BucketPredicate]] = [
    ("all_main", lambda r: True),
    ("public_dudunsparce_ability", lambda r: truthy(r.get("public_has_dudunsparce_ability"))),
    ("agent_dudunsparce_ability", lambda r: truthy(r.get("agent_has_dudunsparce_ability"))),
    (
        "any_dudunsparce_ability",
        lambda r: truthy(r.get("public_has_dudunsparce_ability")) or truthy(r.get("agent_has_dudunsparce_ability")),
    ),
    (
        "agent_only_dudunsparce_ability",
        lambda r: (r.get("dudunsparce_ability_side") or "") == "agent",
    ),
    (
        "public_only_dudunsparce_ability",
        lambda r: (r.get("dudunsparce_ability_side") or "") == "public",
    ),
    (
        "both_dudunsparce_ability",
        lambda r: (r.get("dudunsparce_ability_side") or "") == "both",
    ),
    ("solo_active_dudunsparce_board", lambda r: truthy(r.get("dudunsparce_solo_active"))),
    (
        "solo_active_agent_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_solo_active")) and truthy(r.get("agent_has_dudunsparce_ability")),
    ),
    (
        "solo_active_public_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_solo_active")) and truthy(r.get("public_has_dudunsparce_ability")),
    ),
    (
        "active_with_bench_public_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_active_with_bench")) and truthy(r.get("public_has_dudunsparce_ability")),
    ),
    (
        "active_with_bench_agent_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_active_with_bench")) and truthy(r.get("agent_has_dudunsparce_ability")),
    ),
    (
        "bench_with_active_public_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_bench_with_active")) and truthy(r.get("public_has_dudunsparce_ability")),
    ),
    (
        "bench_with_active_agent_dudunsparce_ability",
        lambda r: truthy(r.get("dudunsparce_bench_with_active")) and truthy(r.get("agent_has_dudunsparce_ability")),
    ),
    ("public_active_psychic_attach", lambda r: truthy(r.get("public_active_psychic_attach"))),
    ("agent_active_psychic_attach", lambda r: truthy(r.get("agent_active_psychic_attach"))),
    (
        "any_active_psychic_attach",
        lambda r: truthy(r.get("public_active_psychic_attach")) or truthy(r.get("agent_active_psychic_attach")),
    ),
    (
        "agent_only_active_psychic_attach",
        lambda r: (r.get("active_psychic_attach_side") or "") == "agent",
    ),
    (
        "public_only_active_psychic_attach",
        lambda r: (r.get("active_psychic_attach_side") or "") == "public",
    ),
    ("public_attack", lambda r: truthy(r.get("public_attack"))),
    ("agent_attack", lambda r: truthy(r.get("agent_attack"))),
    ("any_attack", lambda r: truthy(r.get("public_attack")) or truthy(r.get("agent_attack"))),
    ("agent_only_attack", lambda r: (r.get("attack_side") or "") == "agent"),
    ("public_only_attack", lambda r: (r.get("attack_side") or "") == "public"),
    ("late_turn", lambda r: truthy(r.get("late_turn"))),
    ("very_late_turn", lambda r: truthy(r.get("very_late_turn"))),
    ("low_prize", lambda r: truthy(r.get("low_prize"))),
    ("critical_prize", lambda r: truthy(r.get("critical_prize"))),
    ("late_public_attack", lambda r: truthy(r.get("late_turn")) and truthy(r.get("public_attack"))),
    ("late_agent_attack", lambda r: truthy(r.get("late_turn")) and truthy(r.get("agent_attack"))),
    ("low_prize_public_attack", lambda r: truthy(r.get("low_prize")) and truthy(r.get("public_attack"))),
    ("low_prize_agent_attack", lambda r: truthy(r.get("low_prize")) and truthy(r.get("agent_attack"))),
    ("available_attack_option", lambda r: parse_float(r.get("available_attack_count")) > 0),
    ("available_dudunsparce_ability_option", lambda r: truthy(r.get("has_dudunsparce_ability_option"))),
    (
        "available_attack_and_dudunsparce_ability",
        lambda r: parse_float(r.get("available_attack_count")) > 0 and truthy(r.get("has_dudunsparce_ability_option")),
    ),
    (
        "public_attack_agent_dudunsparce_ability",
        lambda r: truthy(r.get("public_attack")) and truthy(r.get("agent_has_dudunsparce_ability")),
    ),
    (
        "public_dudunsparce_agent_attack",
        lambda r: truthy(r.get("public_has_dudunsparce_ability")) and truthy(r.get("agent_attack")),
    ),
    (
        "low_prize_attack_dudunsparce_choice",
        lambda r: truthy(r.get("low_prize"))
        and parse_float(r.get("available_attack_count")) > 0
        and truthy(r.get("has_dudunsparce_ability_option")),
    ),
    (
        "critical_attack_dudunsparce_choice",
        lambda r: truthy(r.get("critical_prize"))
        and parse_float(r.get("available_attack_count")) > 0
        and truthy(r.get("has_dudunsparce_ability_option")),
    ),
    (
        "low_deck_dudunsparce_choice",
        lambda r: parse_float(r.get("deck_count"), 99.0) <= 8
        and truthy(r.get("has_dudunsparce_ability_option")),
    ),
    (
        "high_hand_dudunsparce_choice",
        lambda r: parse_float(r.get("hand_count")) >= 10
        and truthy(r.get("has_dudunsparce_ability_option")),
    ),
    (
        "public_attack_low_opp_hp",
        lambda r: truthy(r.get("public_attack")) and parse_float(r.get("opponent_active_min_hp"), 999.0) <= 80,
    ),
    (
        "agent_dudunsparce_low_opp_hp_attack_available",
        lambda r: truthy(r.get("agent_has_dudunsparce_ability"))
        and parse_float(r.get("available_attack_count")) > 0
        and parse_float(r.get("opponent_active_min_hp"), 999.0) <= 80,
    ),
    (
        "early_active_psychic_attach_choice",
        lambda r: parse_float(r.get("turn")) <= 2
        and (
            truthy(r.get("public_active_psychic_attach"))
            or truthy(r.get("agent_active_psychic_attach"))
            or truthy(r.get("has_active_psychic_attach_option"))
        ),
    ),
    ("active_psychic_line", lambda r: truthy(r.get("active_psychic_line"))),
    ("active_zero_energy_psychic_line", lambda r: truthy(r.get("active_zero_energy_psychic_line"))),
    (
        "material_setup_or_play_available",
        lambda r: truthy(r.get("has_material_setup_or_play_option")),
    ),
    (
        "material_psychic_setup_available",
        lambda r: truthy(r.get("has_material_psychic_setup_option")),
    ),
    (
        "active_psychic_attach_to_line_available",
        lambda r: truthy(r.get("has_active_psychic_attach_to_psychic_line_option")),
    ),
    (
        "active_psychic_attach_to_zero_line_available",
        lambda r: truthy(r.get("has_active_psychic_attach_to_zero_energy_psychic_line_option")),
    ),
    (
        "setup_clear_active_attach_window",
        lambda r: truthy(r.get("setup_clear_active_attach_window")),
    ),
    (
        "setup_contested_active_attach_window",
        lambda r: truthy(r.get("setup_contested_active_attach_window")),
    ),
    (
        "proxy_no_play_evolve_active_attach_window",
        no_play_evolve_active_attach_proxy,
    ),
    (
        "proxy_play_evolve_contested_active_attach_window",
        play_evolve_contested_active_attach_proxy,
    ),
    (
        "proxy_public_no_play_evolve_active_psychic_attach",
        lambda r: no_play_evolve_active_attach_proxy(r) and truthy(r.get("public_active_psychic_attach")),
    ),
    (
        "proxy_agent_no_play_evolve_active_psychic_attach",
        lambda r: no_play_evolve_active_attach_proxy(r) and truthy(r.get("agent_active_psychic_attach")),
    ),
    (
        "proxy_public_contested_active_psychic_attach",
        lambda r: play_evolve_contested_active_attach_proxy(r) and truthy(r.get("public_active_psychic_attach")),
    ),
    (
        "proxy_agent_contested_active_psychic_attach",
        lambda r: play_evolve_contested_active_attach_proxy(r) and truthy(r.get("agent_active_psychic_attach")),
    ),
    (
        "proxy_no_play_evolve_attach_agreement",
        lambda r: no_play_evolve_active_attach_proxy(r)
        and (
            truthy(r.get("public_active_psychic_attach"))
            or truthy(r.get("agent_active_psychic_attach"))
            or truthy(r.get("has_active_psychic_attach_option"))
        ),
    ),
    (
        "proxy_contested_attach_agreement",
        lambda r: play_evolve_contested_active_attach_proxy(r)
        and (
            truthy(r.get("public_active_psychic_attach"))
            or truthy(r.get("agent_active_psychic_attach"))
            or truthy(r.get("has_active_psychic_attach_option"))
        ),
    ),
    (
        "public_setup_clear_active_psychic_attach",
        lambda r: truthy(r.get("public_setup_clear_active_psychic_attach")),
    ),
    (
        "agent_setup_clear_active_psychic_attach",
        lambda r: truthy(r.get("agent_setup_clear_active_psychic_attach")),
    ),
    (
        "public_setup_contested_active_psychic_attach",
        lambda r: truthy(r.get("public_setup_contested_active_psychic_attach")),
    ),
    (
        "agent_setup_contested_active_psychic_attach",
        lambda r: truthy(r.get("agent_setup_contested_active_psychic_attach")),
    ),
    (
        "setup_clear_attach_agreement",
        lambda r: truthy(r.get("setup_clear_active_attach_window"))
        and (
            truthy(r.get("public_active_psychic_attach"))
            or truthy(r.get("agent_active_psychic_attach"))
            or truthy(r.get("has_active_psychic_attach_option"))
        ),
    ),
    (
        "setup_contested_attach_agreement",
        lambda r: truthy(r.get("setup_contested_active_attach_window"))
        and (
            truthy(r.get("public_active_psychic_attach"))
            or truthy(r.get("agent_active_psychic_attach"))
            or truthy(r.get("has_active_psychic_attach_option"))
        ),
    ),
    (
        "low_prize_active_psychic_attach",
        lambda r: truthy(r.get("low_prize"))
        and (truthy(r.get("public_active_psychic_attach")) or truthy(r.get("agent_active_psychic_attach"))),
    ),
    ("public_play", lambda r: has_type(r, "public_action_types", "PLAY")),
    ("agent_play", lambda r: has_type(r, "agent_action_types", "PLAY")),
    ("public_end_or_pass", lambda r: truthy(r.get("public_end"))),
    ("agent_end_or_pass", lambda r: truthy(r.get("agent_end"))),
]


def summarize_bucket(prefix: str, rows: list[dict[str, str]], total_rows: int) -> dict[str, float]:
    if not rows:
        return {
            f"feat_{prefix}_n": 0.0,
            f"feat_{prefix}_rate": 0.0,
        }
    weights = [parse_float(row.get("weight"), 1.0) for row in rows]
    same = [1.0 if truthy(row.get("same")) else 0.0 for row in rows]
    valid = [1.0 if truthy(row.get("valid")) else 0.0 for row in rows]
    weight_sum = sum(weights)
    return {
        f"feat_{prefix}_n": float(len(rows)),
        f"feat_{prefix}_rate": float(len(rows) / total_rows) if total_rows else 0.0,
        f"feat_{prefix}_same_rate": statistics.fmean(same),
        f"feat_{prefix}_diff_rate": 1.0 - statistics.fmean(same),
        f"feat_{prefix}_valid_rate": statistics.fmean(valid),
        f"feat_{prefix}_avg_weight": statistics.fmean(weights),
        f"feat_{prefix}_weighted_same_rate": (
            sum(w * s for w, s in zip(weights, same)) / weight_sum if weight_sum else 0.0
        ),
    }


def build_rows(
    decision_paths: list[Path],
    exact: dict[str, str],
    normalized: dict[str, str],
    context: str,
) -> tuple[dict[str, PanelRow], dict[str, int]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    stats = {"read_rows": 0, "mapped_rows": 0, "unmapped_rows": 0}
    for path in decision_paths:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                stats["read_rows"] += 1
                if context != "ALL" and (row.get("context") or "") != context:
                    continue
                archive = mapped_archive(row.get("label") or "", exact, normalized)
                if not archive:
                    stats["unmapped_rows"] += 1
                    continue
                stats["mapped_rows"] += 1
                grouped[archive].append(row)

    panels: dict[str, PanelRow] = {}
    for archive, rows in grouped.items():
        panel = PanelRow(candidate_for_archive(archive), archive)
        total_rows = len(rows)
        for bucket_name, predicate in BUCKETS:
            bucket_rows = [row for row in rows if predicate(row)]
            panel.metrics.update(summarize_bucket(bucket_name, bucket_rows, total_rows))
        panels[archive] = panel
    return panels, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate public-action decision features for LOOCV")
    parser.add_argument("--decisions-csv", action="append", default=[], type=Path)
    parser.add_argument("--map", action="append", default=[], help="LABEL=ARCHIVE mapping; repeatable")
    parser.add_argument("--context", default="MAIN")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    if not args.decisions_csv:
        raise SystemExit("at least one --decisions-csv is required")
    if not args.map:
        raise SystemExit("at least one --map LABEL=ARCHIVE is required")
    exact, normalized = parse_maps(args.map)
    rows, stats = build_rows(args.decisions_csv, exact, normalized, args.context)

    metric_names = sorted({metric for row in rows.values() for metric in row.metrics})
    fieldnames = ["candidate", "archive", *metric_names]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for archive in sorted(rows):
            panel = rows[archive]
            out: dict[str, object] = {"candidate": panel.candidate, "archive": panel.archive}
            out.update({metric: f"{panel.metrics.get(metric, 0.0):.6f}" for metric in metric_names})
            writer.writerow(out)

    lines = [
        "# Public-Action Feature Panel",
        "",
        f"- Output: `{args.output}`",
        f"- Decision CSVs: {len(args.decisions_csv)}",
        f"- Context: `{args.context}`",
        f"- Read rows: {stats['read_rows']}",
        f"- Mapped rows: {stats['mapped_rows']}",
        f"- Unmapped rows: {stats['unmapped_rows']}",
        f"- Archive rows: {len(rows)}",
        "",
        "## Archives",
        "",
    ]
    for archive in sorted(rows):
        total = rows[archive].metrics.get("feat_all_main_n", 0.0)
        non_empty = sum(1 for metric, value in rows[archive].metrics.items() if metric.endswith("_n") and value > 0)
        lines.append(f"- `{archive}`: {total:.0f} decisions, {non_empty} non-empty feature buckets")
    report = "\n".join(lines) + "\n"
    print(report, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
