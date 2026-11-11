from tools.public_calibration_horizon import (
    completed_public_episodes,
    enforce_append_only,
    horizon_summary,
)


def test_completed_public_episodes_filters_validation_and_sorts_oldest_first():
    rows = [
        {
            "id": "3",
            "createTime": "2026-07-13 05:00:00",
            "endTime": "2026-07-13 05:02:00",
            "state": "EpisodeState.COMPLETED",
            "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
        },
        {
            "id": "1",
            "createTime": "2026-07-13 04:00:00",
            "endTime": "2026-07-13 04:02:00",
            "state": "EpisodeState.COMPLETED",
            "type": "EpisodeType.EPISODE_TYPE_VALIDATION",
        },
        {
            "id": "2",
            "createTime": "2026-07-13 04:30:00",
            "endTime": "2026-07-13 04:32:00",
            "state": "EpisodeState.COMPLETED",
            "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
        },
    ]

    assert [row["id"] for row in completed_public_episodes(rows)] == ["2", "3"]


def test_append_only_rejects_reordered_prefix():
    old = [{"id": "1", "createTime": "a", "endTime": "b", "state": "s", "type": "t"}]
    current = [{"id": "2", "createTime": "a", "endTime": "b", "state": "s", "type": "t"}]

    try:
        enforce_append_only(old, current)
    except RuntimeError as exc:
        assert "chronology changed" in str(exc)
    else:
        raise AssertionError("reordered chronology was accepted")


def test_horizon_summary_uses_literal_prefix():
    rows = [
        {
            "episode_id": str(index),
            "analysis_status": "ok",
            "result": "W" if index % 2 else "L",
            "opponent_layer": "score850_999",
            "opponent_archetype": "other",
            "our_seat": "p0" if index % 2 else "p1",
            "short_loss": index == 2,
            "runtime_or_package_failure": False,
        }
        for index in range(1, 25)
    ]

    summary = horizon_summary(rows, 24)

    assert summary["complete"] is True
    assert summary["episode_ids"] == [str(index) for index in range(1, 25)]
    assert summary["wld"] == "12-12-0"
    assert summary["short_losses"] == 1
