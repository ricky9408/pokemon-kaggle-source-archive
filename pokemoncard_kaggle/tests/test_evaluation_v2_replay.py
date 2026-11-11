from __future__ import annotations

from evaluation_v2.replay_eval import EpisodeAgreement, summarize


def _row(**updates: int) -> EpisodeAgreement:
    values = dict(
        episode_id=1,
        teacher_team="teacher",
        opponent_team="op",
        public_reward=1.0,
        compared=10,
        main_compared=5,
        candidate_correct=6,
        baseline_correct=4,
        candidate_main_correct=3,
        baseline_main_correct=2,
        changes=3,
        fixes=2,
        regressions=0,
        main_changes=2,
        main_fixes=1,
        main_regressions=0,
        candidate_illegal=0,
        baseline_illegal=0,
    )
    values.update(updates)
    return EpisodeAgreement(**values)


def test_summarize_aggregates_by_decision() -> None:
    result = summarize([_row(), _row(episode_id=2)])
    assert result["episodes"] == 2
    assert result["teacher_teams"] == 1
    assert result["compared"] == 20
    assert result["candidate_agreement"] == 0.6
    assert result["baseline_agreement"] == 0.4
    assert result["agreement_delta"] == 0.2
    assert result["main_agreement_delta"] == 0.2
