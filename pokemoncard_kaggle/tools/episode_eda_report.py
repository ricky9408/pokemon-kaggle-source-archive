#!/usr/bin/env python3
"""Generate compact EDA tables from replay manifest and decision JSONL files.

This adapts the useful parts of the public "top episodes" notebook into a
deterministic repo-native tool.  It intentionally avoids plotting and keeps
winner-based columns out of runtime policy features; those columns are for
hypothesis discovery and leakage checks only.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CARD_RE = re.compile(r"\((\d+)\)")
ATTACK_RE = re.compile(r"attack=(\d+)")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def pct(num: float, den: float) -> str:
    if den == 0:
        return "0.000"
    return f"{num / den:.3f}"


def selected_label(row: dict[str, Any]) -> str:
    selected = row.get("selected")
    if isinstance(selected, list) and selected:
        return " ; ".join(str(item) for item in selected)
    return ""


def selected_type(row: dict[str, Any]) -> str:
    selected = row.get("selected_types")
    if isinstance(selected, list) and selected:
        return "+".join(str(item) for item in selected)
    label = selected_label(row)
    head = label.split(" ", 1)[0]
    return head.split(":", 1)[1] if ":" in head else "unknown"


def selected_card_ids(row: dict[str, Any]) -> list[str]:
    explicit = row.get("selected_card_ids")
    if isinstance(explicit, list):
        return [str(value) for value in explicit]
    return CARD_RE.findall(selected_label(row))


def selected_attack_ids(row: dict[str, Any]) -> list[str]:
    explicit = row.get("selected_attack_ids")
    if isinstance(explicit, list):
        return [str(value) for value in explicit]
    return ATTACK_RE.findall(selected_label(row))


def state_side(row: dict[str, Any], side: str) -> dict[str, Any]:
    state = row.get("state")
    if not isinstance(state, dict):
        return {}
    value = state.get(side)
    return value if isinstance(value, dict) else {}


def card_observations(row: dict[str, Any]) -> list[tuple[str, str]]:
    observations: list[tuple[str, str]] = []
    for side in ("me", "opponent"):
        data = state_side(row, side)
        active = data.get("active")
        if active is not None:
            observations.append((side, str(active)))
        bench = data.get("bench")
        if isinstance(bench, list):
            observations.extend((side, str(card)) for card in bench)
    return observations


def quantile(values: list[int], q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[index]


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def build_board_action_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
    board_totals: Counter[str] = Counter()
    episodes: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        if row.get("context") != "MAIN":
            continue
        label = selected_label(row)
        if not label:
            continue
        key = (
            str(row.get("board_key") or "unknown"),
            str(row.get("context") or "unknown"),
            selected_type(row),
            label,
        )
        counts[key]["count"] += 1
        counts[key]["winner_count"] += int(bool(row.get("is_winner_player")))
        episodes[key].add(str(row.get("episode_id", "")))
        board_totals[key[0]] += 1
    out: list[dict[str, Any]] = []
    for key, counter in counts.items():
        board_key, context, action_type, label = key
        count = counter["count"]
        out.append(
            {
                "board_key": board_key,
                "context": context,
                "action_type": action_type,
                "selected_action": label,
                "count": count,
                "selected_share": pct(count, board_totals[board_key]),
                "winner_count": counter["winner_count"],
                "winner_share": pct(counter["winner_count"], count),
                "episodes": len(episodes[key]),
            }
        )
    out.sort(key=lambda row: (int(row["count"]), float(row["selected_share"]), float(row["winner_share"])), reverse=True)
    return out


def build_action_correlation(rows: list[dict[str, Any]], min_count: int) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    main_rows = [row for row in rows if row.get("context") == "MAIN" and selected_label(row)]
    baseline = sum(1 for row in main_rows if row.get("is_winner_player")) / len(main_rows) if main_rows else 0.0
    for row in main_rows:
        groups[selected_label(row)].append(row)
    out: list[dict[str, Any]] = []
    for label, group in groups.items():
        if len(group) < min_count:
            continue
        turns = [as_float((row.get("state") or {}).get("turn")) for row in group]
        bench = [as_float(state_side(row, "me").get("bench_count")) for row in group]
        turns = [value for value in turns if value is not None]
        bench = [value for value in bench if value is not None]
        winner_share = sum(1 for row in group if row.get("is_winner_player")) / len(group)
        out.append(
            {
                "selected_action": label,
                "action_type": selected_type(group[0]),
                "count": len(group),
                "winner_share": f"{winner_share:.3f}",
                "winrate_lift_vs_all_actions": f"{winner_share - baseline:.3f}",
                "mean_turn": f"{sum(turns) / len(turns):.2f}" if turns else "",
                "mean_own_bench": f"{sum(bench) / len(bench):.2f}" if bench else "",
                "selected_card_ids": ";".join(sorted(set().union(*(selected_card_ids(row) for row in group)))),
                "selected_attack_ids": ";".join(sorted(set().union(*(selected_attack_ids(row) for row in group)))),
            }
        )
    out.sort(key=lambda row: (float(row["winrate_lift_vs_all_actions"]), int(row["count"])), reverse=True)
    return out


def build_visible_card_counts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    episodes: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        episode_id = str(row.get("episode_id", ""))
        for side, card in card_observations(row):
            key = (side, card)
            observations[key]["observations"] += 1
            observations[key]["winner_observations"] += int(bool(row.get("is_winner_player")))
            episodes[key].add(episode_id)
    out: list[dict[str, Any]] = []
    for (side, card_id), counter in observations.items():
        count = counter["observations"]
        out.append(
            {
                "side": side,
                "card_id": card_id,
                "observations": count,
                "episodes": len(episodes[(side, card_id)]),
                "winner_observations": counter["winner_observations"],
                "winner_obs_share": pct(counter["winner_observations"], count),
            }
        )
    out.sort(key=lambda row: (int(row["episodes"]), int(row["observations"])), reverse=True)
    return out


def build_review_queue(manifest: list[dict[str, str]]) -> list[dict[str, Any]]:
    steps = [value for value in (as_int(row.get("steps")) for row in manifest) if value is not None]
    q10 = quantile(steps, 0.10)
    q90 = quantile(steps, 0.90)
    out: list[dict[str, Any]] = []
    for row in manifest:
        step_count = as_int(row.get("steps")) or 0
        if step_count <= q10:
            reason = "short_game_opening_plan"
        elif step_count >= q90:
            reason = "long_game_resource_loop"
        else:
            reason = "normal_top_episode"
        out.append(
            {
                "episode_id": row.get("episode_id", ""),
                "date": row.get("date", ""),
                "reason": reason,
                "steps": step_count,
                "team0": row.get("team0", ""),
                "team1": row.get("team1", ""),
                "reward0": row.get("reward0", ""),
                "reward1": row.get("reward1", ""),
                "winner_team": row.get("winner_team", ""),
                "outcome_label": row.get("outcome_label", ""),
                "path": row.get("path", ""),
            }
        )
    out.sort(key=lambda row: (row["reason"], row["steps"]))
    return out


def render_report(args: argparse.Namespace, manifest: list[dict[str, str]], decisions: list[dict[str, Any]], outputs: dict[str, Path]) -> str:
    main = [row for row in decisions if row.get("context") == "MAIN"]
    winners = sum(1 for row in main if row.get("is_winner_player"))
    lines = [
        "# Episode EDA Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Inputs",
        "",
        f"- Manifest: `{args.manifest}`",
        f"- Decisions: `{args.decisions}`",
        f"- Episodes: {len(manifest)}",
        f"- Decision rows: {len(decisions)}",
        f"- MAIN decision rows: {len(main)}",
        f"- MAIN winner-row share: {pct(winners, len(main))}",
        "",
        "## Outputs",
        "",
    ]
    for label, path in outputs.items():
        lines.append(f"- {label}: `{path}`")
    lines.extend(
        [
            "",
            "## Interpretation Guardrails",
            "",
            "- `winner_share` and `winrate_lift_vs_all_actions` are hypothesis signals only; they are not legal runtime policy features.",
            "- `board_action_counts.csv` is useful for behavior-cloning targets and local-vs-public gap inspection because it keys actions by runtime-visible board shape.",
            "- `review_queue.csv` highlights short opening failures and long resource-loop games for manual replay review.",
            "- Visible-card counts come from repeated decision states, not full deck extraction; use them as archetype clues, not exact deck lists.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("analysis/episode_eda"))
    parser.add_argument("--min-action-count", type=int, default=5)
    parser.add_argument("--report-out", type=Path, default=Path("analysis/episode_eda_report.md"))
    args = parser.parse_args()

    manifest = read_csv(args.manifest)
    decisions = read_jsonl(args.decisions)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    board_actions = build_board_action_counts(decisions)
    action_corr = build_action_correlation(decisions, args.min_action_count)
    visible_cards = build_visible_card_counts(decisions)
    review_queue = build_review_queue(manifest)

    outputs = {
        "board_action_counts": args.out_dir / "board_action_counts.csv",
        "action_correlation": args.out_dir / "action_correlation.csv",
        "visible_card_counts": args.out_dir / "visible_card_counts.csv",
        "review_queue": args.out_dir / "review_queue.csv",
    }
    write_csv(
        outputs["board_action_counts"],
        board_actions,
        ["board_key", "context", "action_type", "selected_action", "count", "selected_share", "winner_count", "winner_share", "episodes"],
    )
    write_csv(
        outputs["action_correlation"],
        action_corr,
        [
            "selected_action",
            "action_type",
            "count",
            "winner_share",
            "winrate_lift_vs_all_actions",
            "mean_turn",
            "mean_own_bench",
            "selected_card_ids",
            "selected_attack_ids",
        ],
    )
    write_csv(
        outputs["visible_card_counts"],
        visible_cards,
        ["side", "card_id", "observations", "episodes", "winner_observations", "winner_obs_share"],
    )
    write_csv(
        outputs["review_queue"],
        review_queue,
        ["episode_id", "date", "reason", "steps", "team0", "team1", "reward0", "reward1", "winner_team", "outcome_label", "path"],
    )
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(render_report(args, manifest, decisions, outputs), encoding="utf-8")
    print(f"episodes={len(manifest)} decisions={len(decisions)} main={sum(1 for row in decisions if row.get('context') == 'MAIN')}")
    print(f"report={args.report_out}")
    for label, path in outputs.items():
        print(f"{label}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
