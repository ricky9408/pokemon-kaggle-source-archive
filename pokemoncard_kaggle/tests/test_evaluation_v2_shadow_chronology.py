from datetime import datetime, timedelta, timezone

import pytest

from evaluation_v2.shadow_chronology import (
    COMPLETED_STATE,
    PUBLIC_TYPE,
    PublicEpisode,
    close_followup_games,
    fixed_block_id,
    freeze_setup_games,
    policy_unit_identity,
)


ZERO = datetime(2026, 7, 10, tzinfo=timezone.utc)


def _episodes(count: int, *, ninth_early: bool = False) -> list[PublicEpisode]:
    rows = []
    for index in range(count):
        created = ZERO + timedelta(hours=index + 1)
        if ninth_early and index == 8:
            created = ZERO + timedelta(hours=8, minutes=30)
        rows.append(
            PublicEpisode(
                episode_id=f"e{index:02d}",
                submission_id="s1",
                created_at_utc=created.isoformat(),
                ended_at_utc=(created + timedelta(minutes=10)).isoformat(),
                state=COMPLETED_STATE,
                episode_type=PUBLIC_TYPE,
            )
        )
    return rows


def test_freeze_setup_requires_registration_before_game_nine() -> None:
    rows = _episodes(9)
    registered = ZERO + timedelta(hours=8, minutes=30)
    setup = freeze_setup_games(
        rows,
        evaluator_frozen_at_utc=ZERO.isoformat(),
        registered_at_utc=registered.isoformat(),
    )
    assert [episode.episode_id for episode in setup] == [f"e{index:02d}" for index in range(8)]

    with pytest.raises(ValueError, match="exactly eight"):
        freeze_setup_games(
            _episodes(9, ninth_early=True),
            evaluator_frozen_at_utc=ZERO.isoformat(),
            registered_at_utc=registered.isoformat(),
        )


def test_close_selects_literal_next_24_and_rejects_engine_drift() -> None:
    rows = _episodes(35)
    registered = ZERO + timedelta(hours=8, minutes=30)
    versions = {episode.episode_id: "1.32.0" for episode in rows}
    followup = close_followup_games(
        rows,
        evaluator_frozen_at_utc=ZERO.isoformat(),
        registered_at_utc=registered.isoformat(),
        setup_episode_ids=[f"e{index:02d}" for index in range(8)],
        module_versions=versions,
        expected_module_version="1.32.0",
    )
    assert len(followup) == 24
    assert followup[0].episode_id == "e08"
    assert followup[-1].episode_id == "e31"

    versions["e17"] = "1.33.0"
    with pytest.raises(ValueError, match="module version"):
        close_followup_games(
            rows,
            evaluator_frozen_at_utc=ZERO.isoformat(),
            registered_at_utc=registered.isoformat(),
            setup_episode_ids=[f"e{index:02d}" for index in range(8)],
            module_versions=versions,
            expected_module_version="1.32.0",
        )


def test_close_rejects_changed_setup_order_and_early_game_nine() -> None:
    rows = _episodes(32)
    versions = {episode.episode_id: "1.32.0" for episode in rows}
    registered = ZERO + timedelta(hours=8, minutes=30)
    with pytest.raises(ValueError, match="order"):
        close_followup_games(
            rows,
            evaluator_frozen_at_utc=ZERO.isoformat(),
            registered_at_utc=registered.isoformat(),
            setup_episode_ids=["e01", "e00", *[f"e{index:02d}" for index in range(2, 8)]],
            module_versions=versions,
            expected_module_version="1.32.0",
        )
    with pytest.raises(ValueError, match="game nine"):
        close_followup_games(
            _episodes(32, ninth_early=True),
            evaluator_frozen_at_utc=ZERO.isoformat(),
            registered_at_utc=registered.isoformat(),
            setup_episode_ids=[f"e{index:02d}" for index in range(8)],
            module_versions=versions,
            expected_module_version="1.32.0",
        )


def test_block_and_policy_identity_are_deterministic() -> None:
    assert fixed_block_id(
        ZERO.isoformat(),
        (ZERO + timedelta(hours=80)).isoformat(),
    ).startswith("72h-0001-")
    first = policy_unit_identity(
        team_id="t",
        submission_id="s",
        deck_sha256="d",
        policy_content_sha256="p",
    )
    second = policy_unit_identity(
        team_id="t",
        submission_id="s",
        deck_sha256="d",
        policy_content_sha256="p",
    )
    assert first == second
