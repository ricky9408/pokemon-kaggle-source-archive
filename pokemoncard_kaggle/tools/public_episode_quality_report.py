#!/usr/bin/env python3
"""Opponent-score-weighted public replay summary.

Raw public W/L can be misleading in this competition because a 20-5 record
against weak opponents may rate below a 12-13 record against stronger opponents.
This report joins downloaded replay outcomes to a fresh leaderboard snapshot.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median


def deck_hash(deck: list[int]) -> str:
    return hashlib.sha1(",".join(map(str, sorted(deck))).encode()).hexdigest()[:10]


def archetype(deck: list[int]) -> str:
    counts = Counter(deck)
    ids = set(counts)
    if {741, 742, 743}.issubset(ids):
        if 1266 in ids:
            if counts[1081] >= 4:
                return "alakazam-nighttime-hammer"
            return "alakazam-nighttime-mine"
        if counts[1081] >= 4:
            return "alakazam-hammer"
        if counts[1264] >= 4 and counts[1081] >= 3:
            return "alakazam-battle-cage"
        return "alakazam"
    if {119, 120, 121}.issubset(ids):
        if {131, 132, 133} & ids:
            return "dragapult-dusknoir"
        if {172, 173, 174} & ids:
            return "dragapult-noctowl"
        return "dragapult"
    if {878, 879}.issubset(ids):
        return "hops-trevenant"
    if 678 in ids:
        return "mega-lucario"
    if {722, 723} & ids:
        return "mega-abomasnow"
    if 756 in ids and {344, 345}.issubset(ids):
        return "mega-kangaskhan-crustle"
    if 756 in ids:
        return "mega-kangaskhan"
    if {344, 345}.issubset(ids) and 1120 in ids:
        return "hammer-crustle"
    if {344, 345}.issubset(ids):
        return "pure-crustle"
    if {400, 401, 431}.issubset(ids):
        return "rocket-mewtwo"
    if {463, 891} & ids:
        return "rocket-honchkrow"
    if {408, 409}.issubset(ids):
        return "houndoom-crustle"
    if ({190, 191, 192} & ids) or 190 in ids:
        return "archaludon-ish"
    return "other"


def rank_key(row: dict[str, str]) -> str:
    for key in row:
        if "Rank" in key:
            return key
    raise KeyError("leaderboard rank column not found")


def load_leaderboard(path: Path) -> dict[str, tuple[int, float]]:
    rows = list(csv.DictReader(path.open(newline="")))
    if not rows:
        return {}
    rk = rank_key(rows[0])
    out: dict[str, tuple[int, float]] = {}
    for row in rows:
        try:
            out[row["TeamName"]] = (int(row[rk]), float(row["Score"]))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def replay_id(path: Path) -> str:
    match = re.search(r"episode-(\d+)-replay\.json$", path.name)
    return match.group(1) if match else path.stem


def load_replay_rows(label: str, replay_dir: Path, team: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(replay_dir.glob("episode-*-replay.json")):
        data = json.loads(path.read_text())
        teams = data["info"]["TeamNames"]
        rewards = data["rewards"]
        decks = data["steps"][0][0]["visualize"][0]["action"]
        if team not in teams:
            continue
        our_idx = teams.index(team)
        opp_idx = 1 - our_idx
        reward = rewards[our_idx]
        result = "W" if reward == 1 else "L" if reward == -1 else "D"
        rows.append(
            {
                "label": label,
                "episode": replay_id(path),
                "result": result,
                "our_reward": str(reward),
                "our_idx": str(our_idx),
                "our_hash": deck_hash(decks[our_idx]),
                "opp_team": teams[opp_idx],
                "opp_arch": archetype(decks[opp_idx]),
                "opp_hash": deck_hash(decks[opp_idx]),
                "steps": str(len(data["steps"])),
            }
        )
    return rows


def add_leaderboard(rows: list[dict[str, str]], leaderboard: dict[str, tuple[int, float]]) -> None:
    for row in rows:
        rank, score = leaderboard.get(row["opp_team"], ("", ""))
        row["opp_rank"] = str(rank)
        row["opp_score"] = str(score)
        row["opp_layer"] = public_layer(rank, score)


def public_layer(rank: int | str, score: float | str) -> str:
    """Coarse public matchmaking layer for opponent-quality analysis."""
    try:
        rank_i = int(rank)
    except (TypeError, ValueError):
        rank_i = 0
    try:
        score_f = float(score)
    except (TypeError, ValueError):
        score_f = -1.0

    if rank_i and rank_i <= 100:
        return "top100"
    if score_f >= 1100:
        return "score1100_plus"
    if score_f >= 1000:
        return "score1000_1099"
    if score_f >= 850:
        return "score850_999"
    if score_f >= 0:
        return "score_below850"
    return "unranked"


def fmedian(values: list[float]) -> str:
    return f"{median(values):.1f}" if values else "-"


def fmean(values: list[float]) -> str:
    return f"{mean(values):.1f}" if values else "-"


def summarize(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for label in sorted({row["label"] for row in rows}):
        sub = [row for row in rows if row["label"] == label]
        counts = Counter(row["result"] for row in sub)
        wins = counts["W"]
        losses = counts["L"]
        draws = counts["D"]
        win_scores = [float(row["opp_score"]) for row in sub if row["result"] == "W" and row["opp_score"]]
        loss_scores = [float(row["opp_score"]) for row in sub if row["result"] == "L" and row["opp_score"]]
        win_ranks = [int(row["opp_rank"]) for row in sub if row["result"] == "W" and row["opp_rank"]]
        loss_ranks = [int(row["opp_rank"]) for row in sub if row["result"] == "L" and row["opp_rank"]]
        topish = [
            row
            for row in sub
            if row["opp_layer"] in {"top100", "score1100_plus", "score1000_1099"}
        ]
        low = [row for row in sub if row["opp_layer"] == "score_below850"]
        topish_counts = Counter(row["result"] for row in topish)
        low_counts = Counter(row["result"] for row in low)
        out.append(
            {
                "label": label,
                "games": str(len(sub)),
                "wins": str(wins),
                "losses": str(losses),
                "draws": str(draws),
                "win_rate": f"{wins / len(sub):.3f}" if sub else "0.000",
                "win_opp_score_mean": fmean(win_scores),
                "loss_opp_score_mean": fmean(loss_scores),
                "win_opp_score_median": fmedian(win_scores),
                "loss_opp_score_median": fmedian(loss_scores),
                "win_opp_rank_median": f"{median(win_ranks):.1f}" if win_ranks else "-",
                "loss_opp_rank_median": f"{median(loss_ranks):.1f}" if loss_ranks else "-",
                "topish_games": str(len(topish)),
                "topish_wld": f"{topish_counts['W']}-{topish_counts['L']}-{topish_counts['D']}",
                "low_games": str(len(low)),
                "low_wld": f"{low_counts['W']}-{low_counts['L']}-{low_counts['D']}",
            }
        )
    return out


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_md(path: Path, game_rows: list[dict[str, str]], summary_rows: list[dict[str, str]]) -> None:
    lines = ["# Public Episode Quality Report", ""]
    lines.append("## Summary")
    lines.append("")
    lines.append(
        "| label | games | W-L-D | win rate | topish W-L-D | low W-L-D | win opp score mean | loss opp score mean | win rank median | loss rank median |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in summary_rows:
        lines.append(
            f"| `{row['label']}` | {row['games']} | {row['wins']}-{row['losses']}-{row['draws']} | "
            f"{row['win_rate']} | {row['topish_wld']} | {row['low_wld']} | "
            f"{row['win_opp_score_mean']} | {row['loss_opp_score_mean']} | "
            f"{row['win_opp_rank_median']} | {row['loss_opp_rank_median']} |"
        )
    lines.append("")
    lines.append(
        "`topish` means top-100, score >= 1100, or score 1000-1099 opponents in the current leaderboard snapshot."
    )
    lines.append("")
    lines.append("## Public-Layer Breakdown")
    lines.append("")
    lines.append("| label | layer | games | W-L-D | win rate |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    by_label_layer: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    layer_games: Counter[tuple[str, str]] = Counter()
    for row in game_rows:
        key = (row["label"], row["opp_layer"])
        by_label_layer[key][row["result"]] += 1
        layer_games[key] += 1
    layer_order = {
        "top100": 0,
        "score1100_plus": 1,
        "score1000_1099": 2,
        "score850_999": 3,
        "score_below850": 4,
        "unranked": 5,
    }
    for (label, layer), counts in sorted(
        by_label_layer.items(), key=lambda item: (item[0][0], layer_order.get(item[0][1], 99))
    ):
        games = layer_games[(label, layer)]
        win_rate = counts["W"] / games if games else 0.0
        lines.append(
            f"| `{label}` | {layer} | {games} | {counts['W']}-{counts['L']}-{counts['D']} | {win_rate:.3f} |"
        )
    lines.append("")
    lines.append("## High-Score Losses")
    lines.append("")
    lines.append("| label | episode | opponent | layer | rank | score | archetype | steps |")
    lines.append("| --- | ---: | --- | --- | ---: | ---: | --- | ---: |")
    losses = [row for row in game_rows if row["result"] == "L" and row["opp_score"]]
    losses.sort(key=lambda row: float(row["opp_score"]), reverse=True)
    for row in losses[:20]:
        lines.append(
            f"| `{row['label']}` | {row['episode']} | {row['opp_team']} | {row['opp_layer']} | {row['opp_rank']} | "
            f"{float(row['opp_score']):.1f} | {row['opp_arch']} | {row['steps']} |"
        )
    lines.append("")
    lines.append("## Archetype Breakdown")
    lines.append("")
    lines.append("| label | archetype | W-L-D |")
    lines.append("| --- | --- | ---: |")
    by_label_arch: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in game_rows:
        by_label_arch[(row["label"], row["opp_arch"])][row["result"]] += 1
    for (label, arch), counts in sorted(by_label_arch.items()):
        lines.append(f"| `{label}` | {arch} | {counts['W']}-{counts['L']}-{counts['D']} |")
    lines.append("")
    lines.append("## Archetype By Public Layer")
    lines.append("")
    lines.append("| label | layer | archetype | W-L-D |")
    lines.append("| --- | --- | --- | ---: |")
    by_label_layer_arch: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    for row in game_rows:
        by_label_layer_arch[(row["label"], row["opp_layer"], row["opp_arch"])][row["result"]] += 1
    for (label, layer, arch), counts in sorted(
        by_label_layer_arch.items(), key=lambda item: (item[0][0], layer_order.get(item[0][1], 99), item[0][2])
    ):
        lines.append(f"| `{label}` | {layer} | {arch} | {counts['W']}-{counts['L']}-{counts['D']} |")
    path.write_text("\n".join(lines) + "\n")


def parse_label_dir(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected LABEL=REPLAY_DIR")
    label, path = value.split("=", 1)
    return label, Path(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path, required=True)
    parser.add_argument("--team", default="GarlicToday")
    parser.add_argument("--label-dir", action="append", type=parse_label_dir, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    parser.add_argument("--md-output", type=Path, required=True)
    args = parser.parse_args()

    leaderboard = load_leaderboard(args.leaderboard)
    game_rows: list[dict[str, str]] = []
    for label, replay_dir in args.label_dir:
        game_rows.extend(load_replay_rows(label, replay_dir, args.team))
    add_leaderboard(game_rows, leaderboard)
    summary_rows = summarize(game_rows)
    write_csv(args.csv_output, game_rows)
    write_csv(args.summary_output, summary_rows)
    write_md(args.md_output, game_rows, summary_rows)
    print(f"wrote {args.csv_output}")
    print(f"wrote {args.summary_output}")
    print(f"wrote {args.md_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
