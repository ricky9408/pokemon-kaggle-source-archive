"""Append-only prospective prediction and fixed-horizon outcome records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .surrogate import SurrogateRecord, SurrogateResult, evaluate


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class PredictionRecord:
    created_at_utc: str
    candidate_label: str
    archive_sha256: str
    pipeline_sha256: str
    deck_family: str
    meta_snapshot_id: str
    baseline_label: str
    metrics: dict[str, float]
    horizon_hours: float = 24.0
    prediction_id: str = ""

    def normalized(self) -> "PredictionRecord":
        payload = asdict(self)
        payload.pop("prediction_id", None)
        identifier = hashlib.sha256(_canonical(payload)).hexdigest()[:20]
        return PredictionRecord(**{**payload, "prediction_id": identifier})

    def validate(self) -> None:
        _time(self.created_at_utc)
        if not self.candidate_label or not self.archive_sha256 or not self.pipeline_sha256:
            raise ValueError("candidate label and archive/pipeline hashes are required")
        if not self.deck_family or not self.meta_snapshot_id or not self.baseline_label:
            raise ValueError("deck family, meta snapshot, and baseline are required")
        if self.horizon_hours < 1.0:
            raise ValueError("public outcome horizon must be at least one hour")
        if not self.metrics or any(not isinstance(value, (int, float)) for value in self.metrics.values()):
            raise ValueError("metrics must be a nonempty numeric mapping")


@dataclass(frozen=True)
class OutcomeRecord:
    prediction_id: str
    submission_ref: int
    submitted_at_utc: str
    first_complete_at_utc: str
    observed_at_utc: str
    candidate_score: float
    baseline_score: float
    evidence_path: str

    @property
    def outcome_delta(self) -> float:
        return self.candidate_score - self.baseline_score


def _read(path: Path, cls: type[PredictionRecord] | type[OutcomeRecord]) -> list[Any]:
    if not path.exists():
        return []
    return [cls(**json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def register_prediction(path: Path, record: PredictionRecord) -> PredictionRecord:
    normalized = record.normalized()
    normalized.validate()
    existing = _read(path, PredictionRecord)
    if any(item.prediction_id == normalized.prediction_id for item in existing):
        raise ValueError("prediction already registered")
    if any(item.archive_sha256 == normalized.archive_sha256 for item in existing):
        raise ValueError("archive hash already registered")
    _append(path, asdict(normalized))
    return normalized


def record_outcome(predictions_path: Path, outcomes_path: Path, outcome: OutcomeRecord) -> None:
    predictions = {item.prediction_id: item for item in _read(predictions_path, PredictionRecord)}
    prediction = predictions.get(outcome.prediction_id)
    if prediction is None:
        raise ValueError("outcome has no registered prediction")
    if any(item.prediction_id == outcome.prediction_id for item in _read(outcomes_path, OutcomeRecord)):
        raise ValueError("outcome already recorded")
    created = _time(prediction.created_at_utc)
    submitted = _time(outcome.submitted_at_utc)
    completed = _time(outcome.first_complete_at_utc)
    observed = _time(outcome.observed_at_utc)
    if submitted < created:
        raise ValueError("submission predates prediction")
    if completed < submitted:
        raise ValueError("completion predates submission")
    if observed < completed + timedelta(hours=prediction.horizon_hours):
        raise ValueError("outcome is earlier than the preregistered maturity horizon")
    if not outcome.evidence_path:
        raise ValueError("outcome evidence path is required")
    _append(outcomes_path, asdict(outcome))


def joined_surrogate_records(predictions_path: Path, outcomes_path: Path, metric_names: Iterable[str]) -> list[SurrogateRecord]:
    names = tuple(metric_names)
    predictions = {item.prediction_id: item for item in _read(predictions_path, PredictionRecord)}
    outcomes = _read(outcomes_path, OutcomeRecord)
    records: list[SurrogateRecord] = []
    for outcome in outcomes:
        prediction = predictions[outcome.prediction_id]
        if set(prediction.metrics) != set(names):
            raise ValueError("prediction metric schema differs from preregistered audit schema")
        records.append(
            SurrogateRecord(
                observed_at=prediction.created_at_utc,
                archive_hash=prediction.archive_sha256,
                deck_family=prediction.deck_family,
                meta_snapshot_id=prediction.meta_snapshot_id,
                metrics=prediction.metrics,
                outcome_delta=outcome.outcome_delta,
            )
        )
    return sorted(records, key=lambda record: _time(str(record.observed_at)))


def audit(predictions_path: Path, outcomes_path: Path, metric_names: Iterable[str]) -> SurrogateResult:
    names = tuple(metric_names)
    records = joined_surrogate_records(predictions_path, outcomes_path, names)
    if not records:
        raise ValueError("no matured prospective outcomes")
    return evaluate(records, names)


__all__ = [
    "OutcomeRecord",
    "PredictionRecord",
    "audit",
    "joined_surrogate_records",
    "record_outcome",
    "register_prediction",
]
