from __future__ import annotations

import pytest

from tools.matchup_bleed_report import parse_replay, public_completed_episodes


def episode(episode_id: str, state: str, episode_type: str) -> dict[str, str]:
    return {"id": episode_id, "state": state, "type": episode_type}


def replay(*, reward: int, episode_id: str = "123") -> dict:
    return {
        "info": {
            "EpisodeId": int(episode_id),
            "TeamNames": ["GarlicToday", "Opponent"],
        },
        "rewards": [reward, -reward],
        "steps": [
            [
                {
                    "visualize": [
                        {
                            "action": [list(range(60)), list(range(100, 160))],
                        }
                    ]
                }
            ]
        ],
    }


def test_validation_episode_is_excluded() -> None:
    rows = [
        episode("validation", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_VALIDATION"),
        episode("public", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
    ]

    assert [row["id"] for row in public_completed_episodes(rows)] == ["public"]


def test_incomplete_public_episode_is_excluded() -> None:
    rows = [
        episode("pending", "EpisodeState.PENDING", "EpisodeType.EPISODE_TYPE_PUBLIC"),
        episode("running", "EpisodeState.RUNNING", "EpisodeType.EPISODE_TYPE_PUBLIC"),
    ]

    assert public_completed_episodes(rows) == []


def test_completed_public_episodes_are_included_in_hosted_order() -> None:
    rows = [
        episode("newest", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
        episode("older", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
    ]

    assert [row["id"] for row in public_completed_episodes(rows)] == ["newest", "older"]


def test_duplicate_public_episode_is_rejected() -> None:
    rows = [
        episode("duplicate", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
        episode("duplicate", "EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
    ]

    with pytest.raises(ValueError, match="duplicate public episode id"):
        public_completed_episodes(rows)


@pytest.mark.parametrize(("reward", "expected"), [(1, "W"), (-1, "L"), (0, "D")])
def test_terminal_rewards_are_not_omitted_or_collapsed(reward: int, expected: str) -> None:
    result = parse_replay(replay(reward=reward), episode_id="123")

    assert result is not None
    assert result.result == expected


def test_malformed_replay_is_rejected_conservatively() -> None:
    malformed = replay(reward=0)
    malformed["steps"] = []

    assert parse_replay(malformed, episode_id="123") is None
