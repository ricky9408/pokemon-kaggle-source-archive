from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v2.prospective_shadow import (
    ShadowOutcome,
    ShadowPrediction,
    record_outcome,
    register_prediction,
)


def _write_first_episode_evidence(
    path: Path,
    *,
    registered_at_utc: str,
    candidate_label: str = "codex-v999",
    archive_sha256: str = "a",
    evaluator_sha256: str = "e",
    transfer_panel_id: str = "p",
    nuisance_probability: float = 0.4,
    augmented_probability: float = 0.6,
    episode_ids: list[str] | None = None,
    generated_at_utc: str | None = None,
) -> None:
    payload = {
        "schema": "branch_outcome_shadow_evidence_v1",
        "candidate_label": candidate_label,
        "archive_sha256": archive_sha256,
        "evaluator_sha256": evaluator_sha256,
        "transfer_panel_id": transfer_panel_id,
        "nuisance_probability": nuisance_probability,
        "augmented_probability": augmented_probability,
        "episode_ids": episode_ids or [f"episode-{index}" for index in range(8)],
        "generated_at_utc": generated_at_utc or registered_at_utc,
    }
    path.write_text(json.dumps(payload, sort_keys=True))


def _prediction(evidence: Path, registered_at_utc: str) -> ShadowPrediction:
    return ShadowPrediction(
        registered_at_utc=registered_at_utc,
        candidate_label="codex-v999",
        archive_sha256="a",
        evaluator_sha256="e",
        transfer_panel_id="p",
        shadow_block="b1",
        first_episode_count=8,
        first_episode_evidence_path=str(evidence),
        first_episode_evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
        nuisance_probability=0.4,
        augmented_probability=0.6,
    )


def _write_outcome_evidence(
    path: Path,
    *,
    unit_id: str,
    outcomes: list[float],
    generated_at_utc: str,
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "branch_outcome_shadow_outcomes_v1",
                "unit_id": unit_id,
                "outcomes": outcomes,
                "generated_at_utc": generated_at_utc,
            },
            sort_keys=True,
        )
    )


def test_shadow_registration_and_fixed_horizon_close(tmp_path: Path) -> None:
    evidence = tmp_path / "first.json"
    predictions = tmp_path / "predictions.jsonl"
    outcomes = tmp_path / "outcomes.jsonl"
    now = datetime.now(timezone.utc)
    _write_first_episode_evidence(
        evidence,
        registered_at_utc=now.isoformat(),
        generated_at_utc=(now - timedelta(seconds=1)).isoformat(),
    )
    prediction = register_prediction(
        predictions,
        _prediction(evidence, now.isoformat()),
    )
    outcome_evidence = tmp_path / "outcome.json"
    outcomes_values = [1.0] * 24
    closed_at = now + timedelta(hours=1)
    _write_outcome_evidence(
        outcome_evidence,
        unit_id=prediction.unit_id,
        outcomes=outcomes_values,
        generated_at_utc=(now + timedelta(seconds=1)).isoformat(),
    )
    record_outcome(
        predictions,
        outcomes,
        ShadowOutcome(
            unit_id=prediction.unit_id,
            closed_at_utc=closed_at.isoformat(),
            outcomes=tuple(outcomes_values),
            evidence_path=str(outcome_evidence),
            evidence_sha256=hashlib.sha256(outcome_evidence.read_bytes()).hexdigest(),
        ),
    )
    assert outcomes.read_text().strip()


def test_shadow_rejects_short_outcome_horizon(tmp_path: Path) -> None:
    evidence = tmp_path / "first.json"
    predictions = tmp_path / "predictions.jsonl"
    now = datetime.now(timezone.utc)
    _write_first_episode_evidence(evidence, registered_at_utc=now.isoformat())
    prediction = register_prediction(
        predictions,
        _prediction(evidence, now.isoformat()),
    )
    outcome_evidence = tmp_path / "outcome.json"
    outcome_evidence.write_text("[]")
    with pytest.raises(ValueError, match="horizon"):
        record_outcome(
            predictions,
            tmp_path / "outcomes.jsonl",
            ShadowOutcome(
                unit_id=prediction.unit_id,
                closed_at_utc=(now + timedelta(hours=1)).isoformat(),
                outcomes=(1.0,) * 23,
                evidence_path=str(outcome_evidence),
                evidence_sha256=hashlib.sha256(b"[]").hexdigest(),
            ),
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("evaluator_sha256", "wrong", "evaluator_sha256 mismatch"),
        ("nuisance_probability", 0.5, "nuisance_probability mismatch"),
        ("augmented_probability", 0.5, "augmented_probability mismatch"),
    ],
)
def test_shadow_rejects_mismatched_semantic_fields(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    registered_at = datetime.now(timezone.utc)
    evidence = tmp_path / "first.json"
    _write_first_episode_evidence(
        evidence,
        registered_at_utc=registered_at.isoformat(),
        **{field: value},
    )
    with pytest.raises(ValueError, match=message):
        register_prediction(tmp_path / "predictions.jsonl", _prediction(evidence, registered_at.isoformat()))


@pytest.mark.parametrize(
    "episode_ids",
    [
        [f"episode-{index}" for index in range(7)],
        ["episode-0"] * 8,
    ],
)
def test_shadow_rejects_non_eight_or_duplicate_episodes(tmp_path: Path, episode_ids: list[str]) -> None:
    registered_at = datetime.now(timezone.utc)
    evidence = tmp_path / "first.json"
    _write_first_episode_evidence(
        evidence,
        registered_at_utc=registered_at.isoformat(),
        episode_ids=episode_ids,
    )
    with pytest.raises(ValueError, match="eight unique episode_ids"):
        register_prediction(tmp_path / "predictions.jsonl", _prediction(evidence, registered_at.isoformat()))


def test_shadow_rejects_evidence_generated_after_registration(tmp_path: Path) -> None:
    registered_at = datetime.now(timezone.utc)
    evidence = tmp_path / "first.json"
    _write_first_episode_evidence(
        evidence,
        registered_at_utc=registered_at.isoformat(),
        generated_at_utc=(registered_at + timedelta(seconds=1)).isoformat(),
    )
    with pytest.raises(ValueError, match="generated after registration"):
        register_prediction(tmp_path / "predictions.jsonl", _prediction(evidence, registered_at.isoformat()))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("unit_id", "wrong-unit", "unit_id mismatch"),
        ("outcomes", [0.0] * 24, "outcomes mismatch"),
    ],
)
def test_shadow_rejects_mismatched_outcome_evidence(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    now = datetime.now(timezone.utc)
    first_evidence = tmp_path / "first.json"
    _write_first_episode_evidence(first_evidence, registered_at_utc=now.isoformat())
    prediction = register_prediction(
        tmp_path / "predictions.jsonl",
        _prediction(first_evidence, now.isoformat()),
    )
    closed_at = now + timedelta(hours=1)
    outcome_evidence = tmp_path / "outcome.json"
    payload_unit_id = prediction.unit_id
    payload_outcomes = [1.0] * 24
    if field == "unit_id":
        payload_unit_id = value  # type: ignore[assignment]
    else:
        payload_outcomes = value  # type: ignore[assignment]
    _write_outcome_evidence(
        outcome_evidence,
        unit_id=payload_unit_id,
        outcomes=payload_outcomes,
        generated_at_utc=(now + timedelta(seconds=1)).isoformat(),
    )
    outcome = ShadowOutcome(
        unit_id=prediction.unit_id,
        closed_at_utc=closed_at.isoformat(),
        outcomes=(1.0,) * 24,
        evidence_path=str(outcome_evidence),
        evidence_sha256=hashlib.sha256(outcome_evidence.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match=message):
        record_outcome(tmp_path / "predictions.jsonl", tmp_path / "outcomes.jsonl", outcome)


@pytest.mark.parametrize(
    ("generated_at", "closed_at", "message"),
    [
        ("registered", "closed", "at or before registration"),
        ("after_closed", "closed", "after closure"),
    ],
)
def test_shadow_rejects_impossible_outcome_evidence_timestamps(
    tmp_path: Path, generated_at: str, closed_at: str, message: str
) -> None:
    now = datetime.now(timezone.utc)
    first_evidence = tmp_path / "first.json"
    _write_first_episode_evidence(first_evidence, registered_at_utc=now.isoformat())
    prediction = register_prediction(
        tmp_path / "predictions.jsonl",
        _prediction(first_evidence, now.isoformat()),
    )
    closure = now + timedelta(hours=1)
    generated = now if generated_at == "registered" else closure + timedelta(seconds=1)
    outcome_evidence = tmp_path / "outcome.json"
    _write_outcome_evidence(
        outcome_evidence,
        unit_id=prediction.unit_id,
        outcomes=[1.0] * 24,
        generated_at_utc=generated.isoformat(),
    )
    outcome = ShadowOutcome(
        unit_id=prediction.unit_id,
        closed_at_utc=closure.isoformat(),
        outcomes=(1.0,) * 24,
        evidence_path=str(outcome_evidence),
        evidence_sha256=hashlib.sha256(outcome_evidence.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match=message):
        record_outcome(tmp_path / "predictions.jsonl", tmp_path / "outcomes.jsonl", outcome)
