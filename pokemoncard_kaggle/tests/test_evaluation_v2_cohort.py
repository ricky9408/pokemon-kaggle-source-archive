from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation_v2.cohort import deck_sha256, freeze_cohort, verify_manifest, write_manifest


def _replay(
    path: Path,
    episode: int,
    target_cards: list[int],
    opponent_cards: list[int],
    target_team: str = "target",
) -> None:
    payload = {
        "configuration": {"seed": episode},
        "info": {"EpisodeId": episode, "TeamNames": ["other", target_team]},
        "module_version": "1.32.0",
        "rewards": [1, -1],
        "steps": [[
            {"visualize": [{"action": [opponent_cards, target_cards]}]},
            {"visualize": []},
        ]],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


def test_freeze_filters_exact_deck_and_keeps_inspected_in_development(tmp_path: Path) -> None:
    target = list(range(60))
    opponent = list(range(100, 160))
    root = tmp_path / "submission_42"
    for episode in range(1, 14):
        _replay(root / f"episode-{episode}-replay.json", episode, target, opponent)
    _replay(root / "episode-999-replay.json", 999, opponent, target)

    manifest = freeze_cohort(
        repo_root=tmp_path,
        replay_root=root,
        target_team="target",
        target_deck=tuple(target),
        cohort_name="test",
        split_seed=7,
        holdout_fraction=0.5,
        preinspected_episode_ids={1, 2},
        leaderboard_path=None,
    )

    assert len(manifest.episodes) == 13
    assert manifest.target_deck_sha256 == deck_sha256(target)
    roles = {episode.episode_id: episode.role for episode in manifest.episodes}
    assert roles[1] == roles[2] == "development"
    assert {episode.role for episode in manifest.episodes} == {"development", "holdout"}
    assert all(episode.target_slot == 1 for episode in manifest.episodes)


def test_manifest_verification_detects_mutation(tmp_path: Path) -> None:
    target = list(range(60))
    opponent = list(range(100, 160))
    root = tmp_path / "submission_42"
    for episode in range(1, 13):
        _replay(root / f"episode-{episode}-replay.json", episode, target, opponent)
    manifest = freeze_cohort(
        repo_root=tmp_path,
        replay_root=root,
        target_team="target",
        target_deck=tuple(target),
        cohort_name="test",
        split_seed=3,
        holdout_fraction=0.5,
        preinspected_episode_ids=set(),
        leaderboard_path=None,
    )
    output = tmp_path / "manifest.json"
    write_manifest(manifest, output)
    assert verify_manifest(manifest, tmp_path) == []
    (root / "episode-1-replay.json").write_text("{}")
    assert "replay changed" in verify_manifest(manifest, tmp_path)[0]


def test_freeze_rejects_missing_preinspected_episode(tmp_path: Path) -> None:
    target = list(range(60))
    opponent = list(range(100, 160))
    root = tmp_path / "submission_42"
    for episode in range(1, 13):
        _replay(root / f"episode-{episode}-replay.json", episode, target, opponent)
    with pytest.raises(ValueError, match="preinspected"):
        freeze_cohort(
            repo_root=tmp_path,
            replay_root=root,
            target_team="target",
            target_deck=tuple(target),
            cohort_name="test",
            split_seed=3,
            holdout_fraction=0.5,
            preinspected_episode_ids={999},
            leaderboard_path=None,
        )


def test_freeze_supports_multiple_exact_deck_teacher_teams(tmp_path: Path) -> None:
    target = list(range(60))
    opponent = list(range(100, 160))
    root = tmp_path / "submission_42"
    for episode in range(1, 13):
        team = "target-a" if episode <= 6 else "target-b"
        _replay(root / f"episode-{episode}-replay.json", episode, target, opponent, team)
    manifest = freeze_cohort(
        repo_root=tmp_path,
        replay_root=root,
        target_team=None,
        target_teams={"target-a", "target-b"},
        target_deck=tuple(target),
        cohort_name="multi",
        split_seed=8,
        holdout_fraction=0.5,
        preinspected_episode_ids=set(),
        leaderboard_path=None,
    )
    assert manifest.target_teams == ("target-a", "target-b")
    assert {episode.target_team for episode in manifest.episodes} == {"target-a", "target-b"}
