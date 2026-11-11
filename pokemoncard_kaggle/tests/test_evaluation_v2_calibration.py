from pathlib import Path

import pytest

from evaluation_v2.calibration import (
    OutcomeRecord,
    PredictionRecord,
    joined_surrogate_records,
    record_outcome,
    register_prediction,
)


def prediction() -> PredictionRecord:
    return PredictionRecord(
        created_at_utc="2026-07-10T08:31:00+00:00",
        candidate_label="codex-v1",
        archive_sha256="a" * 64,
        pipeline_sha256="b" * 64,
        deck_family="nightmine",
        meta_snapshot_id="meta-1",
        baseline_label="baseline",
        metrics={"agreement": 0.5, "arena_q10": 0.1},
    )


def outcome(prediction_id: str, observed: str = "2026-07-11T08:36:00+00:00") -> OutcomeRecord:
    return OutcomeRecord(
        prediction_id=prediction_id,
        submission_ref=123,
        submitted_at_utc="2026-07-10T08:33:00+00:00",
        first_complete_at_utc="2026-07-10T08:35:00+00:00",
        observed_at_utc=observed,
        candidate_score=900.0,
        baseline_score=850.0,
        evidence_path="leaderboard.csv",
    )


def test_prediction_and_mature_outcome_are_append_only(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    outcomes = tmp_path / "outcomes.jsonl"
    registered = register_prediction(predictions, prediction())
    record_outcome(predictions, outcomes, outcome(registered.prediction_id))

    rows = joined_surrogate_records(predictions, outcomes, ("agreement", "arena_q10"))

    assert len(rows) == 1
    assert rows[0].outcome_delta == 50.0
    with pytest.raises(ValueError, match="already registered"):
        register_prediction(predictions, prediction())
    with pytest.raises(ValueError, match="already recorded"):
        record_outcome(predictions, outcomes, outcome(registered.prediction_id))


def test_immature_outcome_is_rejected(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    outcomes = tmp_path / "outcomes.jsonl"
    registered = register_prediction(predictions, prediction())

    with pytest.raises(ValueError, match="maturity horizon"):
        record_outcome(
            predictions,
            outcomes,
            outcome(registered.prediction_id, observed="2026-07-11T08:34:59+00:00"),
        )


def test_outcome_requires_preexisting_prediction(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="no registered prediction"):
        record_outcome(tmp_path / "missing.jsonl", tmp_path / "outcomes.jsonl", outcome("missing"))
