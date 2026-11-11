#!/usr/bin/env python3
"""Run a round-robin league through Kaggle's cabt wrapper."""

from __future__ import annotations

import argparse
import csv
import hashlib
import statistics
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from local_top_league import (  # noqa: E402
    Participant,
    load_top_team_participants,
    read_deck,
    safe_label,
)
from run_engine_parity_league import Entry, run_pair  # noqa: E402
from run_local_battle import load_agent  # noqa: E402


@dataclass
class Standing:
    label: str
    kind: str
    public_score: float | None
    match_wins: int = 0
    match_losses: int = 0
    match_draws: int = 0
    game_wins: int = 0
    game_losses: int = 0
    game_draws: int = 0
    unfinished: int = 0

    @property
    def points(self) -> int:
        return self.match_wins * 3 + self.match_draws

    @property
    def game_diff(self) -> int:
        return self.game_wins - self.game_losses

    @property
    def total_games(self) -> int:
        return self.game_wins + self.game_losses + self.game_draws

    @property
    def win_pct(self) -> float:
        if self.total_games == 0:
            return 0.0
        return (self.game_wins + 0.5 * self.game_draws) / self.total_games


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_candidate(spec: str) -> tuple[str, Path, float | None]:
    parts = spec.split("=")
    if len(parts) not in (2, 3):
        raise ValueError("--candidate must be LABEL=AGENT_DIR or LABEL=AGENT_DIR=PUBLIC_SCORE")
    label = safe_label(parts[0])
    path = Path(parts[1])
    score = float(parts[2]) if len(parts) == 3 and parts[2].strip() else None
    return label, path, score


def entry_from_participant(participant: Participant) -> Entry:
    agent, _deck_from_agent = load_agent(participant.policy, participant.label)
    return Entry(
        label=participant.label,
        path=participant.policy,
        agent=agent,
        deck=list(participant.deck),
        public_score=participant.public_score,
    )


def candidate_entry(spec: str) -> Entry:
    label, path, score = parse_candidate(spec)
    agent, deck = load_agent(path, label)
    return Entry(label=label, path=path, agent=agent, deck=deck, public_score=score)


def cabt_engine_lines() -> list[str]:
    lines = []
    try:
        from kaggle_environments.envs.cabt.cg import sim as cabt_sim

        lib_path = Path(cabt_sim.lib_path)
        lines.append(f"- cabt `libcg` path: `{lib_path}`")
        if lib_path.exists():
            lines.append(f"- cabt `libcg` sha256: `{sha256_file(lib_path)}`")
    except Exception as exc:
        lines.append(f"- cabt engine provenance unavailable: {type(exc).__name__}: {exc}")
    sample = Path("references/sample_submission_20260701/libcg.so")
    if sample.exists():
        lines.append(f"- fresh Kaggle sample `libcg.so` sha256: `{sha256_file(sample)}`")
    return lines


def summarize(rows: list[dict], entries: list[Entry], standings: dict[str, Standing], args: argparse.Namespace) -> str:
    ordered = sorted(
        standings.values(),
        key=lambda item: (-item.points, -item.match_wins, -item.game_diff, -item.game_wins, item.label),
    )
    lines: list[str] = [
        "# cabt New-Engine Local League",
        "",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Configuration",
        "",
        f"- Scout: `{args.scout_dir}`",
        f"- Top replay-deck policies: {args.top_limit}",
        f"- Games per pair: {args.games_per_pair}",
        f"- Max steps: {args.max_steps}",
        f"- Entries: {len(entries)}",
        "",
        "## Engine Provenance",
        "",
        *cabt_engine_lines(),
        "",
        "## Trust Status",
        "",
        "**Diagnostic only.** This uses Kaggle's `cabt` wrapper and local policies, but top teams are still represented by replay-observed decks plus local archetype policy templates, not their private agents.",
        "",
        "## Standings",
        "",
        "| Rank | Entry | Kind | Public score hint | Match record | Points | Game record | Win % | Game diff | Unfinished |",
        "| ---: | --- | --- | ---: | --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for rank, standing in enumerate(ordered, 1):
        score = "-" if standing.public_score is None else f"{standing.public_score:.1f}"
        lines.append(
            f"| {rank} | `{standing.label}` | {standing.kind} | {score} | "
            f"{standing.match_wins}-{standing.match_losses}-{standing.match_draws} | "
            f"{standing.points} | {standing.game_wins}-{standing.game_losses}-{standing.game_draws} | "
            f"{standing.win_pct:.3f} | {standing.game_diff} | {standing.unfinished} |"
        )

    pair_groups: dict[str, list[dict]] = {}
    for row in rows:
        pair_groups.setdefault(row["pair"], []).append(row)
    lines.extend(
        [
            "",
            "## Pair Results",
            "",
            "| Pair | Left-anchor W-L-D-U | Avg steps | Errors |",
            "| --- | --- | ---: | ---: |",
        ]
    )
    for pair, group in sorted(pair_groups.items()):
        counts = Counter(row["anchor_result"] for row in group)
        steps = [int(row["steps"]) for row in group if str(row["steps"]).lstrip("-").isdigit() and int(row["steps"]) >= 0]
        errors = sum(1 for row in group if row["error"])
        lines.append(
            f"| `{pair}` | {counts['win']}-{counts['loss']}-{counts['draw']}-{counts['unfinished']} | "
            f"{(statistics.mean(steps) if steps else 0):.1f} | {errors} |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scout-dir", type=Path, required=True)
    parser.add_argument("--top-limit", type=int, default=4)
    parser.add_argument("--selection-mode", choices=("rank", "diverse"), default="diverse")
    parser.add_argument("--scan-limit", type=int, default=12)
    parser.add_argument("--min-archetypes", type=int, default=3)
    parser.add_argument("--min-decks", type=int, default=3)
    parser.add_argument("--allow-partial-top", action="store_true")
    parser.add_argument("--candidate", action="append", default=[])
    parser.add_argument("--games-per-pair", type=int, default=2)
    parser.add_argument("--max-steps", type=int, default=1200)
    parser.add_argument("--output-prefix", type=Path, required=True)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    participants = load_top_team_participants(
        args.scout_dir,
        args.top_limit,
        args.allow_partial_top,
        args.selection_mode,
        args.scan_limit,
        args.min_archetypes,
        args.min_decks,
    )
    entries = [entry_from_participant(participant) for participant in participants]
    entries.extend(candidate_entry(spec) for spec in args.candidate)

    rows: list[dict] = []
    standings = {
        entry.label: Standing(
            label=entry.label,
            kind="candidate" if any(entry.label == parse_candidate(spec)[0] for spec in args.candidate) else "top_replay_policy",
            public_score=entry.public_score,
        )
        for entry in entries
    }

    for left_index, left in enumerate(entries):
        for right in entries[left_index + 1 :]:
            pair_rows = run_pair("cabt", left, right, args.games_per_pair, args.max_steps, args.verbose)
            rows.extend(pair_rows)
            left_counts = Counter(row["anchor_result"] for row in pair_rows)
            left_wins = left_counts["win"]
            right_wins = left_counts["loss"]
            draws = left_counts["draw"]
            unfinished = left_counts["unfinished"]
            left_standing = standings[left.label]
            right_standing = standings[right.label]
            left_standing.game_wins += left_wins
            left_standing.game_losses += right_wins
            left_standing.game_draws += draws
            left_standing.unfinished += unfinished
            right_standing.game_wins += right_wins
            right_standing.game_losses += left_wins
            right_standing.game_draws += draws
            right_standing.unfinished += unfinished
            if left_wins > right_wins:
                left_standing.match_wins += 1
                right_standing.match_losses += 1
            elif right_wins > left_wins:
                right_standing.match_wins += 1
                left_standing.match_losses += 1
            else:
                left_standing.match_draws += 1
                right_standing.match_draws += 1

    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    csv_path = args.output_prefix.with_suffix(".csv")
    md_path = args.output_prefix.with_suffix(".md")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["engine"])
        writer.writeheader()
        writer.writerows(rows)
    md_path.write_text(summarize(rows, entries, standings, args), encoding="utf-8")
    print(md_path.read_text(encoding="utf-8"))
    return 0 if all(not row["error"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
