from evaluation_v2.schemas import EpisodeRecord
from tools.build_cohort_ml_dataset import target_rows


def test_target_rows_respects_frozen_player_slot() -> None:
    episode = EpisodeRecord(
        episode_id=42,
        replay_path="episode.json",
        replay_sha256="abc",
        submission_id=7,
        target_team="teacher-b",
        opponent_team="teacher-a",
        target_slot=1,
        target_reward=1.0,
        public_seed=9,
        module_version="1.0",
        target_deck_sha256="deck",
        role="development",
    )
    rows = [
        {"episode_id": 42, "player_index": 0, "context": "MAIN"},
        {"episode_id": 42, "player_index": 1, "context": "MAIN"},
        {"episode_id": 43, "player_index": 1, "context": "MAIN"},
    ]

    selected = target_rows(rows, episode, "cohort-1")

    assert len(selected) == 1
    assert selected[0]["player_index"] == 1
    assert selected[0]["teacher_team"] == "teacher-b"
    assert selected[0]["cohort_role"] == "development"
    assert selected[0]["cohort_id"] == "cohort-1"
