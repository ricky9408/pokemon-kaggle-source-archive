import json
from pathlib import Path

from evaluation_v2.augmentation import build_augmentation, eligible_replay_paths
from evaluation_v2.cohort import deck_sha256
from evaluation_v2.schemas import CohortManifest, EpisodeRecord


def _manifest(deck: tuple[int, ...]) -> CohortManifest:
    record = EpisodeRecord(
        episode_id=42,
        replay_path="sealed.json",
        replay_sha256="abc",
        target_team="sealed",
        opponent_team="opponent",
        target_slot=0,
        target_reward=1.0,
        target_deck_sha256=deck_sha256(deck),
        submission_id=1,
        module_version="1",
        public_seed=1,
        role="holdout",
    )
    return CohortManifest(
        cohort_id="parent",
        created_at_utc="now",
        cohort_name="test",
        source_root="old",
        source_root_sha256="source",
        target_team="sealed",
        target_deck_sha256=deck_sha256(deck),
        target_deck_cards=deck,
        split_seed=1,
        holdout_fraction=0.5,
        preinspected_episode_ids=(),
        leaderboard_path=None,
        leaderboard_sha256=None,
        episodes=(record,),
    )


def _replay(episode_id: int, deck: tuple[int, ...]) -> dict:
    other = tuple(range(101, 161))
    return {
        "id": episode_id,
        "info": {"EpisodeId": episode_id, "TeamNames": ["fresh", "other"]},
        "configuration": {"seed": 9},
        "module_version": "1.32.0",
        "rewards": [1, -1],
        "steps": [[{"visualize": [{"action": [list(deck), list(other)]}]}]],
    }


def test_eligible_paths_skip_frozen_before_open(tmp_path: Path) -> None:
    sealed = tmp_path / "episode-42-replay.json"
    sealed.write_text("not valid json")
    fresh = tmp_path / "episode-43-replay.json"
    fresh.write_text("{}")

    paths, skipped = eligible_replay_paths(tmp_path, frozen_episode_ids={42})

    assert paths == [fresh]
    assert skipped == 1


def test_build_augmentation_collects_only_fresh_exact_deck(tmp_path: Path) -> None:
    deck = tuple(range(1, 61))
    (tmp_path / "episode-42-replay.json").write_text("sealed and unreadable")
    fresh = tmp_path / "submission_9" / "episode-43-replay.json"
    fresh.parent.mkdir()
    fresh.write_text(json.dumps(_replay(43, deck)))

    augmentation = build_augmentation(
        repo_root=tmp_path,
        replay_root=tmp_path,
        base_manifest=_manifest(deck),
    )

    assert augmentation.skipped_frozen_files == 1
    assert len(augmentation.records) == 1
    assert augmentation.records[0].episode_id == 43
    assert augmentation.records[0].target_team == "fresh"
    assert augmentation.records[0].submission_id == 9
    assert set(augmentation.frozen_episode_ids) == {42}
