"""Chronology and identity guards for prospective public-game shadows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping


PUBLIC_TYPE = "EpisodeType.EPISODE_TYPE_PUBLIC"
COMPLETED_STATE = "EpisodeState.COMPLETED"


def utc_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("episode timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class PublicEpisode:
    episode_id: str
    submission_id: str
    created_at_utc: str
    ended_at_utc: str | None
    state: str
    episode_type: str

    @property
    def created(self) -> datetime:
        return utc_time(self.created_at_utc)

    @property
    def ended(self) -> datetime | None:
        return utc_time(self.ended_at_utc) if self.ended_at_utc else None

    @property
    def completed_public(self) -> bool:
        return self.state == COMPLETED_STATE and self.episode_type == PUBLIC_TYPE


def episode_from_row(row: Mapping[str, Any], *, submission_id: str) -> PublicEpisode:
    episode_id = str(row.get("id") or "")
    created = str(row.get("createTime") or row.get("createdAt") or "")
    ended_value = row.get("endTime") or row.get("endedAt")
    if not episode_id or not created:
        raise ValueError("episode id and create time are required")
    return PublicEpisode(
        episode_id=episode_id,
        submission_id=str(submission_id),
        created_at_utc=created,
        ended_at_utc=str(ended_value) if ended_value else None,
        state=str(row.get("state") or ""),
        episode_type=str(row.get("type") or ""),
    )


def ordered_public_episodes(episodes: Iterable[PublicEpisode]) -> tuple[PublicEpisode, ...]:
    values = list(episodes)
    if len({episode.episode_id for episode in values}) != len(values):
        raise ValueError("prospective episode list contains duplicate ids")
    submissions = {episode.submission_id for episode in values}
    if len(submissions) != 1:
        raise ValueError("prospective episode list mixes submission ids")
    public = [episode for episode in values if episode.episode_type == PUBLIC_TYPE]
    return tuple(sorted(public, key=lambda episode: (episode.created, episode.episode_id)))


def fixed_block_id(
    evaluator_frozen_at_utc: str,
    registered_at_utc: str,
    *,
    block_hours: int = 72,
) -> str:
    frozen = utc_time(evaluator_frozen_at_utc)
    registered = utc_time(registered_at_utc)
    if registered < frozen:
        raise ValueError("shadow registration predates evaluator freeze")
    if block_hours <= 0:
        raise ValueError("block_hours must be positive")
    index = int((registered - frozen).total_seconds() // (block_hours * 3600))
    start = frozen + timedelta(hours=index * block_hours)
    return f"{block_hours}h-{index:04d}-{start.strftime('%Y%m%dT%H%M%SZ')}"


def freeze_setup_games(
    episodes: Iterable[PublicEpisode],
    *,
    evaluator_frozen_at_utc: str,
    registered_at_utc: str,
) -> tuple[PublicEpisode, ...]:
    """Return exactly eight games when registration precedes game nine.

    Every public episode which *started* after evaluator freeze and no later
    than registration is counted. Pending or failed episodes are not silently
    skipped because that would make the horizon outcome-selective.
    """

    frozen = utc_time(evaluator_frozen_at_utc)
    registered = utc_time(registered_at_utc)
    ordered = ordered_public_episodes(episodes)
    started = [episode for episode in ordered if frozen <= episode.created <= registered]
    if len(started) != 8:
        raise ValueError(f"registration requires exactly eight started setup games; found {len(started)}")
    for episode in started:
        if not episode.completed_public or episode.ended is None:
            raise ValueError("all eight setup games must be completed public games")
        if episode.ended > registered:
            raise ValueError("setup game ended after registration")
    return tuple(started)


def close_followup_games(
    episodes: Iterable[PublicEpisode],
    *,
    evaluator_frozen_at_utc: str,
    registered_at_utc: str,
    setup_episode_ids: Iterable[str],
    module_versions: Mapping[str, str],
    expected_module_version: str,
) -> tuple[PublicEpisode, ...]:
    """Select the literal next 24 games and reject gaps or engine drift."""

    frozen = utc_time(evaluator_frozen_at_utc)
    registered = utc_time(registered_at_utc)
    ordered = tuple(episode for episode in ordered_public_episodes(episodes) if episode.created >= frozen)
    setup_ids = tuple(str(value) for value in setup_episode_ids)
    if len(setup_ids) != 8 or len(set(setup_ids)) != 8:
        raise ValueError("setup evidence must contain eight unique ordered episode ids")
    if tuple(episode.episode_id for episode in ordered[:8]) != setup_ids:
        raise ValueError("setup episode order no longer matches the submission chronology")
    if len(ordered) < 32:
        raise ValueError("fewer than 24 follow-up games are available")
    followup = ordered[8:32]
    if followup[0].created <= registered:
        raise ValueError("game nine started before shadow registration")
    for episode in (*ordered[:8], *followup):
        if not episode.completed_public or episode.ended is None:
            raise ValueError("the fixed 32-game horizon contains a non-completed public game")
        if module_versions.get(episode.episode_id) != expected_module_version:
            raise ValueError("engine module version changed inside the fixed horizon")
    return tuple(followup)


def policy_unit_identity(
    *,
    team_id: str,
    submission_id: str,
    deck_sha256: str,
    policy_content_sha256: str,
) -> str:
    if not all((team_id, submission_id, deck_sha256, policy_content_sha256)):
        raise ValueError("complete immutable policy identity is required")
    payload = {
        "deck_sha256": deck_sha256,
        "policy_content_sha256": policy_content_sha256,
        "submission_id": str(submission_id),
        "team_id": str(team_id),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "COMPLETED_STATE",
    "PUBLIC_TYPE",
    "PublicEpisode",
    "close_followup_games",
    "episode_from_row",
    "fixed_block_id",
    "freeze_setup_games",
    "ordered_public_episodes",
    "policy_unit_identity",
    "utc_time",
]
