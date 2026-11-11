"""Current-public deck evidence derived from target-side replay decks."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .cohort import _initial_decks, deck_sha256


@dataclass(frozen=True)
class DeckMetaEvidence:
    deck_sha256: str
    exact_teams: int
    exact_submissions: int
    observed_episodes: int
    best_rank: int
    best_score: float
    rank10_score: float
    margin_over_rank10: float
    teams: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def evaluate_deck_meta(*, deck_cards: list[int], download_summary: Path, leaderboard: Path) -> DeckMetaEvidence:
    target_hash = deck_sha256(deck_cards)
    leaderboard_rows = list(csv.DictReader(leaderboard.open(encoding="utf-8-sig")))
    rank10_rows = [row for row in leaderboard_rows if int(row["Rank"]) == 10]
    if not rank10_rows:
        raise ValueError("leaderboard has no rank 10 row")
    rank10_score = float(rank10_rows[0]["Score"])
    observed: set[tuple[str, int, int]] = set()
    submissions: set[tuple[str, int]] = set()
    teams: dict[str, tuple[int, float]] = {}
    with download_summary.open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("action") != "download":
                continue
            path = Path(row["path"])
            replay = json.loads(path.read_text())
            team = row["team"]
            replay_teams = replay["info"]["TeamNames"]
            if team not in replay_teams:
                continue
            slot = replay_teams.index(team)
            if deck_sha256(_initial_decks(replay)[slot]) != target_hash:
                continue
            submission_id = int(row["submission_id"])
            episode_id = int(row["episode_id"])
            observed.add((team, submission_id, episode_id))
            submissions.add((team, submission_id))
            rank_score = (int(row["rank"]), float(row["score"]))
            if team not in teams or rank_score[0] < teams[team][0]:
                teams[team] = rank_score
    if not observed:
        raise ValueError("target deck did not appear on the target side of the scout")
    best_rank, best_score = min(teams.values(), key=lambda item: item[0])
    return DeckMetaEvidence(
        deck_sha256=target_hash,
        exact_teams=len(teams),
        exact_submissions=len(submissions),
        observed_episodes=len(observed),
        best_rank=best_rank,
        best_score=best_score,
        rank10_score=rank10_score,
        margin_over_rank10=best_score - rank10_score,
        teams=tuple(sorted(teams)),
    )
