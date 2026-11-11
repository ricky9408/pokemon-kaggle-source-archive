"""Versioned data contracts used by the trusted evaluator."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


SCHEMA_VERSION = 2
SplitRole = Literal["development", "holdout"]


@dataclass(frozen=True)
class CandidateIdentity:
    label: str
    archive_path: str
    archive_sha256: str
    agent_sha256: str
    deck_sha256: str
    cohort_id: str
    data_cutoff_utc: str
    change_axes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["change_axes"] = list(self.change_axes)
        return value


@dataclass(frozen=True)
class EpisodeRecord:
    episode_id: int
    replay_path: str
    replay_sha256: str
    target_team: str
    opponent_team: str
    target_slot: int
    target_reward: float
    target_deck_sha256: str
    submission_id: int | None
    module_version: str
    public_seed: int | None
    role: SplitRole

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CohortManifest:
    cohort_id: str
    created_at_utc: str
    cohort_name: str
    source_root: str
    source_root_sha256: str
    target_team: str
    target_deck_sha256: str
    target_deck_cards: tuple[int, ...]
    split_seed: int
    holdout_fraction: float
    preinspected_episode_ids: tuple[int, ...]
    leaderboard_path: str | None
    leaderboard_sha256: str | None
    episodes: tuple[EpisodeRecord, ...] = field(default_factory=tuple)
    target_teams: tuple[str, ...] = field(default_factory=tuple)
    source_digest_version: int = 1
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["target_deck_cards"] = list(self.target_deck_cards)
        value["preinspected_episode_ids"] = list(self.preinspected_episode_ids)
        value["target_teams"] = list(self.target_teams or (self.target_team,))
        value["episodes"] = [episode.to_dict() for episode in self.episodes]
        return value

    def resolve_replay(self, repo_root: Path, episode: EpisodeRecord) -> Path:
        path = Path(episode.replay_path)
        return path if path.is_absolute() else repo_root / path
