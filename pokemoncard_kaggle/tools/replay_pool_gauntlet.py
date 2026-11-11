#!/usr/bin/env python3
"""Evaluate candidates against a pool of replay-observed deck shells.

`meta_gauntlet.py` is intentionally curated. This tool is broader: point it at
fresh public replay files and it builds an opponent pool from the decks seen in
those replays, assigning each known deck family to a local policy template.

Run inside the linux/amd64 simulator environment, for example:

docker run -i --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work python:3.11-slim \
  python tools/replay_pool_gauntlet.py --candidate agents/v39_alakazam_denpa \
  --games 6 scouting/top_visible_*/*replay.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local_battle import load_agent, run_games  # noqa: E402


@dataclass(frozen=True)
class DeckRecord:
    key: str
    deck_hash: str
    archetype: str
    policy: Path
    deck: tuple[int, ...]
    teams: tuple[str, ...]
    wins: int
    losses: int
    seen: int
    weight: float


def deck_hash(deck: list[int]) -> str:
    packed = ",".join(str(card) for card in sorted(deck))
    return hashlib.sha1(packed.encode()).hexdigest()[:10]


def replay_id(path: Path) -> str:
    match = re.search(r"episode-(\d+)-replay\.json$", path.name)
    return match.group(1) if match else str(path)


def scouting_root(path: Path) -> Path | None:
    for parent in path.parents:
        if (parent / "download_summary.csv").exists():
            return parent
    return None


def load_team_ranks(paths: list[Path]) -> dict[str, int]:
    ranks: dict[str, int] = {}
    roots = {root for path in paths if (root := scouting_root(path)) is not None}
    for root in roots:
        summary = root / "download_summary.csv"
        with summary.open(encoding="utf-8-sig", newline="") as file:
            for row in csv.DictReader(file):
                team = row.get("team")
                rank_text = row.get("rank")
                if not team or not rank_text:
                    continue
                try:
                    rank = int(rank_text)
                except ValueError:
                    continue
                if team not in ranks or rank < ranks[team]:
                    ranks[team] = rank
    return ranks


def rank_factor(rank: int | None) -> float:
    if rank is None or rank <= 0:
        return 1.0
    # Nudge top-ranked teams up without letting a single rank dominate.
    return 1.0 + 0.75 / math.sqrt(rank)


def archetype(deck: list[int]) -> str:
    counts = Counter(deck)
    cards = set(counts)
    if {265, 268, 269, 270, 271} & cards:
        return "iono_lightning"
    if {646, 648} <= cards:
        if {103, 104} <= cards:
            return "grimmsnarl_froslass"
        return "grimmsnarl"
    if {878, 879} <= cards:
        return "hops_trevenant"
    if {379, 380, 381} <= cards:
        return "cynthias_garchomp"
    if 687 in cards:
        return "mega_absol_box"
    if 63 in cards:
        return "raging_bolt"
    if 272 in cards and 756 in cards:
        return "lillie_clefairy"
    if {741, 742, 743} <= cards:
        if 1266 in cards:
            if counts[1081] >= 4:
                return "alakazam_nighttime_hammer"
            return "alakazam_nighttime_mine"
        if counts[1081] >= 4:
            return "alakazam_hammer"
        if counts[1264] >= 4 and counts[1081] >= 3:
            return "alakazam_battle_cage"
        return "alakazam"
    if {89, 90, 92, 93} <= cards:
        return "festival_lead"
    if {292, 293} <= cards:
        return "n_zoroark"
    if {162, 163} <= cards:
        return "slowking"
    if {119, 120, 121} <= cards:
        if {131, 132, 133} & cards:
            return "dragapult_dusknoir"
        if {172, 173, 174} & cards:
            return "dragapult_noctowl"
        return "dragapult"
    if {344, 345} <= cards and {1212, 1235, 1147} <= cards and counts[1] >= 16:
        return "pure_crustle_heal"
    if {344, 345, 1198, 1219} <= cards:
        return "crustle_petrel_crispin"
    if {344, 345} <= cards and {352, 353, 354} & cards:
        return "ethan_crustle"
    if {352, 353, 354} <= cards:
        return "ethan_typhlosion"
    if ({96, 710} <= cards) and ({402, 403, 404} & cards):
        return "ogerpon_meganium"
    if 756 in cards:
        if {344, 345} <= cards:
            return "mega_kangaskhan_crustle"
        return "mega_kangaskhan"
    if {344, 345} <= cards:
        if 1120 in cards:
            return "hammer_crustle"
        if 1264 in cards or 1224 in cards:
            return "battle_cage_crustle"
        return "pure_crustle"
    if 678 in cards:
        return "mega_lucario"
    if ({676, 1142} <= cards) or ({116, 676} <= cards) or ({1051, 1052, 676} <= cards):
        return "fighting_toolbox"
    if {722, 723} & cards:
        return "mega_abomasnow"
    if {400, 401, 431} <= cards:
        return "rocket_mewtwo"
    if {463, 891} & cards:
        return "rocket_honchkrow"
    if 150 in cards:
        return "hydrapple"
    if ({96, 108, 117} & cards) and (1090 in cards or 1250 in cards):
        return "ogerpon_box"
    if ({96, 150, 710} & cards) and ({1094, 1261} & cards):
        return "grass_toolbox"
    return "unknown"


def policy_for(archetype_name: str, deck: list[int]) -> Path | None:
    if archetype_name == "iono_lightning":
        return Path("agents/v63_iono_lightning_patient")
    if archetype_name == "alakazam_nighttime_hammer":
        return Path("agents/v61_kadoraba_nighttime_hammer")
    if archetype_name == "alakazam_nighttime_mine":
        return Path("agents/v58_donguk_nighttime")
    if archetype_name == "alakazam_battle_cage":
        return Path("agents/v48_alakazam_hammer_mid")
    if archetype_name.startswith("alakazam"):
        if archetype_name == "alakazam_hammer":
            return Path("agents/v45_alakazam_hammer")
        if 305 in deck:
            return Path("agents/v43_daitou_alakazam")
        return Path("agents/v39_alakazam_denpa")
    if archetype_name == "festival_lead":
        return Path("agents/v42_hibi_festival")
    if archetype_name == "hammer_crustle":
        return Path("agents/v20_hammer_target")
    if archetype_name in {"battle_cage_crustle", "crustle_petrel_crispin", "pure_crustle", "pure_crustle_heal"}:
        return Path("agents/v4")
    if archetype_name == "ethan_crustle":
        if deck.count(2) >= 9 or 1079 in deck or 1086 in deck:
            return Path("agents/v27_poffin5")
        return Path("agents/v21_ethan_crustle")
    if archetype_name == "ethan_typhlosion":
        return Path("agents/v50_replay_meta_policy")
    if archetype_name in {
        "dragapult",
        "dragapult_dusknoir",
        "dragapult_noctowl",
        "lillie_clefairy",
        "mega_lucario",
        "mega_abomasnow",
        "n_zoroark",
        "slowking",
        "raging_bolt",
        "hydrapple",
        "ogerpon_box",
        "mega_absol_box",
        "ogerpon_meganium",
        "rocket_mewtwo",
        "rocket_honchkrow",
        "grass_toolbox",
        "grimmsnarl_froslass",
        "grimmsnarl",
        "hops_trevenant",
        "cynthias_garchomp",
    }:
        return Path("agents/v50_replay_meta_policy")
    if archetype_name == "fighting_toolbox":
        return Path("agents/v64_noikaret_fighting_toolbox")
    if archetype_name == "mega_kangaskhan_crustle":
        return Path("agents/v62_karacoro_mega_kangaskhan")
    if archetype_name == "mega_kangaskhan":
        return Path("agents/v50_replay_meta_policy")
    return None


def load_pool(
    paths: list[Path],
    winners_only: bool,
    dedupe: bool,
    rank_weighting: bool,
) -> tuple[list[DeckRecord], Counter[str]]:
    grouped: dict[str, dict] = {}
    skipped: Counter[str] = Counter()
    seen_replays: set[str] = set()
    team_ranks = load_team_ranks(paths) if rank_weighting else {}
    for path in sorted(paths):
        if dedupe:
            rid = replay_id(path)
            if rid in seen_replays:
                skipped["duplicate_replay"] += 1
                continue
            seen_replays.add(rid)
        data = json.loads(path.read_text())
        teams = data.get("info", {}).get("TeamNames", [])
        rewards = data.get("rewards") or [None] * len(teams)
        try:
            decks = data["steps"][0][0]["visualize"][0]["action"]
        except Exception:
            skipped["missing_start_deck"] += 1
            continue
        for slot, deck in enumerate(decks):
            if slot >= len(teams):
                continue
            reward = rewards[slot] if slot < len(rewards) else None
            if winners_only and reward != 1:
                continue
            arch = archetype(deck)
            policy = policy_for(arch, deck)
            if policy is None:
                skipped[arch] += 1
                continue
            h = deck_hash(deck)
            key = f"{h}:{policy}"
            entry = grouped.setdefault(
                key,
                {
                    "deck_hash": h,
                    "archetype": arch,
                    "policy": policy,
                    "deck": tuple(deck),
                    "teams": Counter(),
                    "wins": 0,
                    "losses": 0,
                    "seen": 0,
                },
            )
            entry["teams"][teams[slot]] += 1
            entry["seen"] += 1
            factor = rank_factor(team_ranks.get(teams[slot]))
            entry.setdefault("weighted_seen", 0.0)
            entry.setdefault("weighted_wins", 0.0)
            entry.setdefault("weighted_losses", 0.0)
            entry["weighted_seen"] += factor
            if reward == 1:
                entry["wins"] += 1
                entry["weighted_wins"] += factor
            elif reward == -1:
                entry["losses"] += 1
                entry["weighted_losses"] += factor

    records = []
    for key, entry in grouped.items():
        top_teams = tuple(team for team, _ in entry["teams"].most_common(5))
        # Reward decks that are both frequent and winning in the observed top pool.
        weighted_seen = entry.get("weighted_seen", float(entry["seen"]))
        weighted_wins = entry.get("weighted_wins", float(entry["wins"]))
        weight = max(1.0, weighted_wins + 0.35 * max(0.0, weighted_seen - weighted_wins))
        records.append(
            DeckRecord(
                key=key,
                deck_hash=entry["deck_hash"],
                archetype=entry["archetype"],
                policy=entry["policy"],
                deck=entry["deck"],
                teams=top_teams,
                wins=entry["wins"],
                losses=entry["losses"],
                seen=entry["seen"],
                weight=weight,
            )
        )
    records.sort(key=lambda item: (-item.weight, item.archetype, item.deck_hash))
    return records, skipped


def summarize_counts(results: list[dict], candidate_is_p0: bool) -> tuple[int, int, int, int]:
    counts = Counter(result["result"] for result in results)
    wins = counts[0] if candidate_is_p0 else counts[1]
    losses = counts[1] if candidate_is_p0 else counts[0]
    return wins, losses, counts[2], counts[-1]


def evaluate_pair(
    candidate_agent,
    candidate_deck: list[int],
    opponent_agent,
    opponent_deck: list[int],
    games: int,
    max_steps: int,
    quiet: bool,
) -> tuple[int, int, int, int]:
    forward = run_games(
        candidate_agent,
        candidate_deck,
        opponent_agent,
        opponent_deck,
        games,
        max_steps,
        False,
        quiet,
        "forward",
    )
    f_wins, f_losses, f_draws, f_unfinished = summarize_counts(forward, candidate_is_p0=True)
    swapped = run_games(
        opponent_agent,
        opponent_deck,
        candidate_agent,
        candidate_deck,
        games,
        max_steps,
        False,
        quiet,
        "swapped",
    )
    s_wins, s_losses, s_draws, s_unfinished = summarize_counts(swapped, candidate_is_p0=False)
    return (
        f_wins + s_wins,
        f_losses + s_losses,
        f_draws + s_draws,
        f_unfinished + s_unfinished,
    )


def normalized_key(record: DeckRecord) -> str:
    return f"{record.archetype.replace('_', '-')}:{record.deck_hash}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--candidate", action="append", type=Path, default=[])
    parser.add_argument("--games", type=int, default=6, help="games per seat per opponent")
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--winners-only", action="store_true")
    parser.add_argument("--max-opponents", type=int, default=0, help="0 means no cap")
    parser.add_argument("--only-archetype", action="append", default=[], help="limit opponents to archetypes; accepts hyphen or underscore names")
    parser.add_argument("--only-key", action="append", default=[], help="limit opponents to archetype:hash keys; archetype may use hyphens or underscores")
    parser.add_argument("--no-dedupe", action="store_true", help="count duplicate episode JSON files separately")
    parser.add_argument("--rank-weighting", action="store_true", help="boost decks piloted by higher-ranked teams when scouting metadata is available")
    args = parser.parse_args()

    pool, skipped = load_pool(args.replays, args.winners_only, not args.no_dedupe, args.rank_weighting)
    if args.only_archetype:
        wanted = {name.replace("-", "_") for name in args.only_archetype}
        pool = [record for record in pool if record.archetype in wanted]
    if args.only_key:
        wanted_keys = {key.replace("_", "-") for key in args.only_key}
        pool = [record for record in pool if normalized_key(record) in wanted_keys]
    if args.max_opponents > 0:
        pool = pool[: args.max_opponents]
    print("opponent_pool")
    print("archetype,hash,policy,seen,wins,losses,weight,teams")
    for record in pool:
        print(
            f"{record.archetype},{record.deck_hash},{record.policy},"
            f"{record.seen},{record.wins},{record.losses},{record.weight:.2f},"
            f"{'|'.join(record.teams)}"
        )
    if skipped:
        print("skipped," + ",".join(f"{name}:{count}" for name, count in skipped.most_common()))

    candidates = args.candidate or [Path("submission")]
    total_exit = 0
    for candidate_path in candidates:
        candidate_agent, candidate_deck = load_agent(candidate_path, f"cand_{candidate_path.name}")
        weighted_wins = 0.0
        weighted_games = 0.0
        print(f"\nCandidate {candidate_path}")
        print("opponent,weight,wins,losses,draws,unfinished,win_rate,teams")
        for record in pool:
            opponent_agent, _ = load_agent(record.policy, f"opp_{record.archetype}_{record.deck_hash}")
            wins, losses, draws, unfinished = evaluate_pair(
                candidate_agent,
                candidate_deck,
                opponent_agent,
                list(record.deck),
                args.games,
                args.max_steps,
                args.quiet,
            )
            played = wins + losses + draws
            win_rate = wins / played if played else 0.0
            weighted_wins += record.weight * wins
            weighted_games += record.weight * played
            if unfinished:
                total_exit = 1
            print(
                f"{record.archetype}:{record.deck_hash},{record.weight:.2f},"
                f"{wins},{losses},{draws},{unfinished},{win_rate:.4f},"
                f"{'|'.join(record.teams)}"
            )
        score = weighted_wins / weighted_games if weighted_games else 0.0
        print(f"weighted_win_rate,{score:.4f}")
    return total_exit


if __name__ == "__main__":
    raise SystemExit(main())
