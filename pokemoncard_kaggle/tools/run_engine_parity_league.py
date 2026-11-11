#!/usr/bin/env python3
"""Compare local cg battles with Kaggle cabt wrapper battles.

Run this in Linux/amd64. The competition libraries are Linux shared objects,
and macOS cannot load them directly.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from run_local_battle import load_agent, run_one


@dataclass(frozen=True)
class Entry:
    label: str
    path: Path
    agent: object
    deck: list[int]
    public_score: float | None


def now_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%MZ")


def parse_entry(text: str) -> tuple[str, Path, float | None]:
    parts = text.split("=")
    if len(parts) not in (2, 3):
        raise ValueError("entry specs must be LABEL=PATH or LABEL=PATH=PUBLIC_SCORE")
    label = parts[0].strip()
    path = Path(parts[1].strip())
    public_score = float(parts[2]) if len(parts) == 3 and parts[2].strip() else None
    if not label:
        raise ValueError(f"empty label in {text!r}")
    return label, path, public_score


def load_entry(spec: str) -> Entry:
    label, path, public_score = parse_entry(spec)
    agent, deck = load_agent(path, label)
    return Entry(label=label, path=path, agent=agent, deck=deck, public_score=public_score)


def winner_from_rewards(rewards: list[float | int | None]) -> int:
    if len(rewards) < 2:
        return -1
    if rewards[0] == rewards[1]:
        return 2
    if rewards[0] is None or rewards[1] is None:
        return -1
    return 0 if rewards[0] > rewards[1] else 1


def cabt_agent(entry: Entry):
    def wrapped(obs, config=None):
        if isinstance(obs, dict):
            select = obs.get("select")
        else:
            select = getattr(obs, "select", None)
        if select is None:
            return entry.deck
        return entry.agent(obs)

    return wrapped


def run_cabt_game(left: Entry, right: Entry, max_steps: int) -> dict:
    from kaggle_environments import make

    env = make(
        "cabt",
        debug=True,
        configuration={
            "episodeSteps": max_steps,
            "runTimeout": 2000,
            "actTimeout": 0,
        },
    )
    try:
        env.run([cabt_agent(left), cabt_agent(right)])
        last = env.steps[-1] if env.steps else []
        rewards = [state.reward for state in last] if last else [None, None]
        statuses = [state.status for state in last] if last else ["UNKNOWN", "UNKNOWN"]
        winner = winner_from_rewards(rewards)
        error = ""
        if hasattr(env, "steps") and env.steps:
            first = env.steps[0][0]
            error = getattr(first, "error", "") or ""
        return {
            "result": winner,
            "steps": max(0, len(env.steps) - 1),
            "error": error,
            "left_reward": rewards[0],
            "right_reward": rewards[1],
            "left_status": statuses[0],
            "right_status": statuses[1],
        }
    except Exception as exc:
        return {
            "result": -1,
            "steps": -1,
            "error": f"{type(exc).__name__}: {exc}",
            "left_reward": "",
            "right_reward": "",
            "left_status": "ERROR",
            "right_status": "ERROR",
        }


def run_cg_game(left: Entry, right: Entry, max_steps: int) -> dict:
    result = run_one(left.agent, left.deck, right.agent, right.deck, max_steps)
    winner = result["result"]
    if winner not in (0, 1, 2):
        winner = -1
    return {
        "result": winner,
        "steps": result["steps"],
        "error": result["error"],
        "left_reward": "",
        "right_reward": "",
        "left_status": "DONE" if winner in (0, 1, 2) else "UNKNOWN",
        "right_status": "DONE" if winner in (0, 1, 2) else "UNKNOWN",
    }


def run_pair(
    engine: str,
    anchor: Entry,
    opponent: Entry,
    games: int,
    max_steps: int,
    verbose: bool,
) -> list[dict]:
    rows: list[dict] = []
    for index in range(games):
        anchor_left = index % 2 == 0
        left = anchor if anchor_left else opponent
        right = opponent if anchor_left else anchor
        if engine == "cabt":
            result = run_cabt_game(left, right, max_steps)
        else:
            result = run_cg_game(left, right, max_steps)
        local_winner = result["result"]
        if local_winner == 2:
            winner_label = "draw"
            anchor_result = "draw"
        elif local_winner == -1:
            winner_label = "unfinished"
            anchor_result = "unfinished"
        else:
            winner = left if local_winner == 0 else right
            winner_label = winner.label
            anchor_result = "win" if winner.label == anchor.label else "loss"
        rows.append(
            {
                "engine": engine,
                "pair": f"{anchor.label}_vs_{opponent.label}",
                "game": index + 1,
                "anchor": anchor.label,
                "opponent": opponent.label,
                "anchor_left": int(anchor_left),
                "left": left.label,
                "right": right.label,
                "winner": winner_label,
                "anchor_result": anchor_result,
                "steps": result["steps"],
                "error": result["error"],
                "left_reward": result["left_reward"],
                "right_reward": result["right_reward"],
                "left_status": result["left_status"],
                "right_status": result["right_status"],
            }
        )
        if verbose:
            print(
                f"{engine} {anchor.label} vs {opponent.label} "
                f"game={index + 1}/{games} anchor_result={anchor_result} "
                f"steps={result['steps']} error={result['error']}",
                flush=True,
            )
    return rows


def summarize(rows: list[dict], entries: dict[str, Entry]) -> str:
    lines: list[str] = []
    lines.append("# cg/cabt Engine Parity League")
    lines.append("")
    lines.append(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Pair Summary")
    lines.append("")
    lines.append("| Engine | Pair | Anchor W-L-D-U | Avg steps | Errors | Public ordering matched |")
    lines.append("| --- | --- | --- | ---: | ---: | --- |")
    for (engine, pair), group in sorted(groupby(rows, ("engine", "pair")).items()):
        counts = Counter(row["anchor_result"] for row in group)
        steps = [int(row["steps"]) for row in group if str(row["steps"]).lstrip("-").isdigit() and int(row["steps"]) >= 0]
        errors = sum(1 for row in group if row["error"])
        anchor_label = group[0]["anchor"]
        opponent_label = group[0]["opponent"]
        anchor_score = entries[anchor_label].public_score
        opponent_score = entries[opponent_label].public_score
        if anchor_score is None or opponent_score is None:
            public_match = "n/a"
        else:
            expected_anchor_better = anchor_score > opponent_score
            observed_anchor_better = counts["win"] > counts["loss"]
            public_match = "yes" if expected_anchor_better == observed_anchor_better else "no"
        lines.append(
            f"| {engine} | `{pair}` | {counts['win']}-{counts['loss']}-{counts['draw']}-{counts['unfinished']} | "
            f"{(statistics.mean(steps) if steps else 0):.1f} | {errors} | {public_match} |"
        )

    lines.append("")
    lines.append("## Entry Public Scores")
    lines.append("")
    lines.append("| Entry | Public score hint | Path |")
    lines.append("| --- | ---: | --- |")
    for label, entry in sorted(entries.items()):
        score = "-" if entry.public_score is None else f"{entry.public_score:.1f}"
        lines.append(f"| `{label}` | {score} | `{entry.path}` |")
    return "\n".join(lines) + "\n"


def groupby(rows: list[dict], keys: tuple[str, ...]) -> dict[tuple[str, ...], list[dict]]:
    grouped: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for row in rows:
        grouped[tuple(row[key] for key in keys)].append(row)
    return grouped


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", choices=["cg", "cabt"], required=True)
    parser.add_argument("--anchor", required=True, help="LABEL=PATH or LABEL=PATH=PUBLIC_SCORE")
    parser.add_argument("--opponent", action="append", required=True, help="LABEL=PATH or LABEL=PATH=PUBLIC_SCORE")
    parser.add_argument("--games", type=int, default=10, help="Total games per opponent, alternating seats")
    parser.add_argument("--max-steps", type=int, default=10000)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    anchor = load_entry(args.anchor)
    opponents = [load_entry(spec) for spec in args.opponent]
    entries = {anchor.label: anchor, **{opponent.label: opponent for opponent in opponents}}

    rows: list[dict] = []
    for opponent in opponents:
        rows.extend(run_pair(args.engine, anchor, opponent, args.games, args.max_steps, args.verbose))

    args.output_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.output_csv.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()) if rows else ["engine"])
        writer.writeheader()
        writer.writerows(rows)

    report = summarize(rows, entries)
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(report, encoding="utf-8")
    print(report)
    return 0 if all(not row["error"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
