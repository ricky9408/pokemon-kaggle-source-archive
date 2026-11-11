"""Append-only prospective shadow predictions and fixed-game outcomes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import random
from typing import Any, Iterable

from scipy.stats import spearmanr


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _validate_first_episode_evidence(path: Path, prediction: "ShadowPrediction") -> None:
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("first-episode evidence must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("first-episode evidence must be a JSON object")
    if payload.get("schema") != "branch_outcome_shadow_evidence_v1":
        raise ValueError("first-episode evidence schema mismatch")
    for field in (
        "candidate_label",
        "archive_sha256",
        "evaluator_sha256",
        "transfer_panel_id",
        "nuisance_probability",
        "augmented_probability",
    ):
        if field not in payload or payload[field] != getattr(prediction, field):
            raise ValueError(f"first-episode evidence {field} mismatch")

    episode_ids = payload.get("episode_ids")
    if (
        not isinstance(episode_ids, list)
        or len(episode_ids) != 8
        or any(not isinstance(episode_id, str) or not episode_id for episode_id in episode_ids)
        or len(set(episode_ids)) != 8
    ):
        raise ValueError("first-episode evidence requires eight unique episode_ids")

    generated_at = payload.get("generated_at_utc")
    if not isinstance(generated_at, str):
        raise ValueError("first-episode evidence generated_at_utc is required")
    try:
        generated_time = _time(generated_at)
    except ValueError as exc:
        raise ValueError("first-episode evidence generated_at_utc must include a timezone") from exc
    if generated_time > _time(prediction.registered_at_utc):
        raise ValueError("first-episode evidence was generated after registration")


def _validate_outcome_evidence(
    path: Path,
    prediction: "ShadowPrediction",
    outcome: "ShadowOutcome",
) -> None:
    try:
        payload = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("shadow outcome evidence must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("shadow outcome evidence must be a JSON object")
    if payload.get("schema") != "branch_outcome_shadow_outcomes_v1":
        raise ValueError("shadow outcome evidence schema mismatch")
    if payload.get("unit_id") != outcome.unit_id:
        raise ValueError("shadow outcome evidence unit_id mismatch")
    recorded_outcomes = payload.get("outcomes")
    if (
        not isinstance(recorded_outcomes, list)
        or len(recorded_outcomes) != prediction.horizon_games
        or recorded_outcomes != list(outcome.outcomes)
    ):
        raise ValueError("shadow outcome evidence outcomes mismatch")

    generated_at = payload.get("generated_at_utc")
    if not isinstance(generated_at, str):
        raise ValueError("shadow outcome evidence generated_at_utc is required")
    try:
        generated_time = _time(generated_at)
    except ValueError as exc:
        raise ValueError("shadow outcome evidence generated_at_utc must include a timezone") from exc
    registered_time = _time(prediction.registered_at_utc)
    closed_time = _time(outcome.closed_at_utc)
    if generated_time <= registered_time:
        raise ValueError("shadow outcome evidence was generated at or before registration")
    if generated_time > closed_time:
        raise ValueError("shadow outcome evidence was generated after closure")


@dataclass(frozen=True)
class ShadowPrediction:
    registered_at_utc: str
    candidate_label: str
    archive_sha256: str
    evaluator_sha256: str
    transfer_panel_id: str
    shadow_block: str
    first_episode_count: int
    first_episode_evidence_path: str
    first_episode_evidence_sha256: str
    nuisance_probability: float
    augmented_probability: float
    horizon_games: int = 24
    unit_id: str = ""

    def normalized(self) -> "ShadowPrediction":
        payload = asdict(self)
        payload.pop("unit_id", None)
        identifier = hashlib.sha256(_canonical(payload)).hexdigest()[:20]
        return ShadowPrediction(**{**payload, "unit_id": identifier})

    def validate(self) -> None:
        _time(self.registered_at_utc)
        if not all((self.candidate_label, self.archive_sha256, self.evaluator_sha256, self.transfer_panel_id, self.shadow_block)):
            raise ValueError("prediction identity fields are required")
        if self.first_episode_count != 8:
            raise ValueError("shadow prediction requires exactly eight setup episodes")
        if not self.first_episode_evidence_path or not self.first_episode_evidence_sha256:
            raise ValueError("first-episode evidence path and hash are required")
        if self.horizon_games != 24:
            raise ValueError("shadow horizon must be exactly 24 follow-up games")
        if not 0.0 < self.nuisance_probability < 1.0:
            raise ValueError("nuisance probability must be inside (0, 1)")
        if not 0.0 < self.augmented_probability < 1.0:
            raise ValueError("augmented probability must be inside (0, 1)")


@dataclass(frozen=True)
class ShadowOutcome:
    unit_id: str
    closed_at_utc: str
    outcomes: tuple[float, ...]
    evidence_path: str
    evidence_sha256: str

    def validate(self, prediction: ShadowPrediction) -> None:
        if _time(self.closed_at_utc) <= _time(prediction.registered_at_utc):
            raise ValueError("shadow outcome must be observed after registration")
        if len(self.outcomes) != prediction.horizon_games:
            raise ValueError("shadow outcome does not match the preregistered game horizon")
        if any(value not in (0.0, 0.5, 1.0) for value in self.outcomes):
            raise ValueError("outcomes must be 0, 0.5, or 1")
        if not self.evidence_path or not self.evidence_sha256:
            raise ValueError("outcome evidence path and hash are required")


def _append(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(asdict(value), sort_keys=True) + "\n")


def _read_predictions(path: Path) -> list[ShadowPrediction]:
    if not path.exists():
        return []
    return [ShadowPrediction(**json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


def _read_outcomes(path: Path) -> list[ShadowOutcome]:
    if not path.exists():
        return []
    values = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        row["outcomes"] = tuple(float(value) for value in row["outcomes"])
        values.append(ShadowOutcome(**row))
    return values


def register_prediction(path: Path, prediction: ShadowPrediction) -> ShadowPrediction:
    value = prediction.normalized()
    value.validate()
    evidence = Path(value.first_episode_evidence_path)
    if not evidence.is_file() or _sha256(evidence) != value.first_episode_evidence_sha256:
        raise ValueError("first-episode evidence hash mismatch")
    _validate_first_episode_evidence(evidence, value)
    existing = _read_predictions(path)
    if any(row.unit_id == value.unit_id for row in existing):
        raise ValueError("shadow unit already registered")
    if any(row.archive_sha256 == value.archive_sha256 for row in existing):
        raise ValueError("archive already has a shadow prediction")
    _append(path, value)
    return value


def record_outcome(
    predictions_path: Path,
    outcomes_path: Path,
    outcome: ShadowOutcome,
) -> None:
    predictions = {row.unit_id: row for row in _read_predictions(predictions_path)}
    prediction = predictions.get(outcome.unit_id)
    if prediction is None:
        raise ValueError("outcome has no preregistered shadow unit")
    if any(row.unit_id == outcome.unit_id for row in _read_outcomes(outcomes_path)):
        raise ValueError("shadow unit already closed")
    outcome.validate(prediction)
    evidence = Path(outcome.evidence_path)
    if not evidence.is_file() or _sha256(evidence) != outcome.evidence_sha256:
        raise ValueError("shadow outcome evidence hash mismatch")
    _validate_outcome_evidence(evidence, prediction, outcome)
    _append(outcomes_path, outcome)


def _loss(outcome: float, probability: float) -> float:
    probability = min(max(probability, 1e-6), 1.0 - 1e-6)
    return -(outcome * math.log(probability) + (1.0 - outcome) * math.log(1.0 - probability))


def _pairwise(predicted: list[float], observed: list[float]) -> float:
    scores: list[float] = []
    for left in range(len(predicted)):
        for right in range(left + 1, len(predicted)):
            truth = observed[left] - observed[right]
            guess = predicted[left] - predicted[right]
            if truth == 0:
                continue
            scores.append(0.5 if guess == 0 else float(truth * guess > 0))
    return sum(scores) / len(scores) if scores else float("nan")


def audit_shadow(
    predictions_path: Path,
    outcomes_path: Path,
    *,
    bootstrap_samples: int = 5000,
    seed: int = 20260710,
) -> dict[str, Any]:
    predictions = {row.unit_id: row for row in _read_predictions(predictions_path)}
    outcomes = {row.unit_id: row for row in _read_outcomes(outcomes_path)}
    joined = [(predictions[key], outcomes[key]) for key in sorted(predictions.keys() & outcomes.keys())]
    unit_rows: list[dict[str, Any]] = []
    for prediction, outcome in joined:
        nuisance_loss = sum(_loss(value, prediction.nuisance_probability) for value in outcome.outcomes) / len(outcome.outcomes)
        augmented_loss = sum(_loss(value, prediction.augmented_probability) for value in outcome.outcomes) / len(outcome.outcomes)
        observed = sum(outcome.outcomes) / len(outcome.outcomes)
        unit_rows.append(
            {
                "unit_id": prediction.unit_id,
                "shadow_block": prediction.shadow_block,
                "observed": observed,
                "observed_residual": observed - prediction.nuisance_probability,
                "predicted_uplift": prediction.augmented_probability - prediction.nuisance_probability,
                "logloss_improvement": nuisance_loss - augmented_loss,
            }
        )
    improvements = [row["logloss_improvement"] for row in unit_rows]
    rng = random.Random(seed)
    positive = 0
    if improvements:
        for _ in range(bootstrap_samples):
            draw = [improvements[rng.randrange(len(improvements))] for _ in improvements]
            positive += sum(draw) / len(draw) > 0
    predicted = [row["predicted_uplift"] for row in unit_rows]
    observed = [row["observed_residual"] for row in unit_rows]
    spearman = (
        float(spearmanr(predicted, observed).statistic)
        if len(unit_rows) >= 3 and len(set(predicted)) > 1 and len(set(observed)) > 1
        else float("nan")
    )
    metrics = {
        "units": len(unit_rows),
        "blocks": len({row["shadow_block"] for row in unit_rows}),
        "macro_logloss_improvement": sum(improvements) / len(improvements) if improvements else float("nan"),
        "pairwise_ordering_auc": _pairwise(predicted, observed),
        "agent_residual_spearman": spearman,
        "bootstrap_probability_improvement_gt_zero": positive / bootstrap_samples if improvements else 0.0,
        "positive_unit_fraction": sum(value > 0 for value in improvements) / len(improvements) if improvements else 0.0,
    }
    checks = [
        ("units", metrics["units"] >= 8, metrics["units"], ">=8"),
        ("blocks", metrics["blocks"] >= 2, metrics["blocks"], ">=2"),
        ("macro_logloss_improvement", metrics["macro_logloss_improvement"] >= 0.015, metrics["macro_logloss_improvement"], ">=0.015"),
        ("pairwise_ordering_auc", metrics["pairwise_ordering_auc"] >= 0.64, metrics["pairwise_ordering_auc"], ">=0.64"),
        ("agent_residual_spearman", metrics["agent_residual_spearman"] >= 0.30, metrics["agent_residual_spearman"], ">=0.30"),
        ("bootstrap_probability", metrics["bootstrap_probability_improvement_gt_zero"] >= 0.90, metrics["bootstrap_probability_improvement_gt_zero"], ">=0.90"),
        ("positive_unit_fraction", metrics["positive_unit_fraction"] >= 0.80, metrics["positive_unit_fraction"], ">=0.80"),
    ]
    return {
        "schema": "prospective_shadow_validation_v1",
        "certified": all(passed for _, passed, _, _ in checks),
        "checks": [
            {"name": name, "passed": passed, "value": value, "threshold": threshold}
            for name, passed, value, threshold in checks
        ],
        "metrics": metrics,
        "units": unit_rows,
    }


__all__ = [
    "ShadowOutcome",
    "ShadowPrediction",
    "audit_shadow",
    "record_outcome",
    "register_prediction",
]
