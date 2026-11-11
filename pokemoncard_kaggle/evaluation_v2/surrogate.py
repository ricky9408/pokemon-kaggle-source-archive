"""Prospective, walk-forward calibration for a public-score surrogate.

The records in this module are deliberately outcome-bearing, but outcomes are
used only to score predictions made for later records.  A caller must pass the
same fixed public-outcome horizon for every record and freeze ``metrics``
before collecting outcomes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import isfinite, sqrt
from numbers import Real
from typing import Mapping, Sequence


MIN_PREDICTIONS = 12
MIN_DECK_FAMILIES = 3
MIN_META_SNAPSHOTS = 2
MIN_SPEARMAN = 0.35
MIN_PAIRWISE_ACCURACY = 0.65


@dataclass(frozen=True)
class SurrogateRecord:
    """One pre-registered candidate and its fixed-horizon public outcome."""

    observed_at: str | datetime
    archive_hash: str
    deck_family: str
    meta_snapshot_id: str
    metrics: Mapping[str, float]
    outcome_delta: float

    @property
    def public_outcome_delta(self) -> float:
        """Descriptive alias for the fixed-horizon outcome field."""
        return self.outcome_delta


PublicSurrogateRecord = SurrogateRecord


@dataclass(frozen=True)
class SurrogateResult:
    """Walk-forward predictions and the prospective trust decision."""

    n_predictions: int
    spearman: float
    pairwise_accuracy: float
    mae: float
    trusted: bool
    reasons: tuple[str, ...]
    predictions: tuple[float, ...]


def evaluate(
    records: Sequence[SurrogateRecord],
    metrics: Sequence[str],
    *,
    ridge_alpha: float = 1.0,
) -> SurrogateResult:
    """Run a chronological ridge audit using only prior records per prediction.

    ``metrics`` is the frozen feature list.  It is intentionally required
    rather than inferred from record mappings, preventing a later-added metric
    from silently changing the historical feature space.
    """
    names = _validate_records(records, metrics, ridge_alpha)
    predictions: list[float] = []
    outcomes: list[float] = []

    for index in range(1, len(records)):
        training = records[:index]
        means, scales = _fit_scaler(training, names)
        design = [_standardize(record, names, means, scales) for record in training]
        target = [record.outcome_delta for record in training]
        coefficients = _ridge_fit(design, target, ridge_alpha)
        current = _standardize(records[index], names, means, scales)
        predictions.append(_predict(coefficients, current))
        outcomes.append(float(records[index].outcome_delta))

    count = len(predictions)
    spearman = _spearman(predictions, outcomes) if count >= 2 else 0.0
    pairwise = _pairwise_accuracy(predictions, outcomes) if count >= 2 else 0.0
    mae = sum(abs(prediction - outcome) for prediction, outcome in zip(predictions, outcomes)) / count if count else 0.0

    reasons: list[str] = []
    if count < MIN_PREDICTIONS:
        reasons.append(f"need at least {MIN_PREDICTIONS} predictions; got {count}")
    families = {record.deck_family for record in records}
    if len(families) < MIN_DECK_FAMILIES:
        reasons.append(f"need at least {MIN_DECK_FAMILIES} deck families; got {len(families)}")
    snapshots = {record.meta_snapshot_id for record in records}
    if len(snapshots) < MIN_META_SNAPSHOTS:
        reasons.append(f"need at least {MIN_META_SNAPSHOTS} meta snapshots; got {len(snapshots)}")
    if spearman < MIN_SPEARMAN:
        reasons.append(f"Spearman {spearman:.3f} is below {MIN_SPEARMAN:.2f}")
    if pairwise < MIN_PAIRWISE_ACCURACY:
        reasons.append(f"pairwise accuracy {pairwise:.3f} is below {MIN_PAIRWISE_ACCURACY:.2f}")

    return SurrogateResult(
        n_predictions=count,
        spearman=spearman,
        pairwise_accuracy=pairwise,
        mae=mae,
        trusted=not reasons,
        reasons=tuple(reasons),
        predictions=tuple(predictions),
    )


def _validate_records(
    records: Sequence[SurrogateRecord], metrics: Sequence[str], ridge_alpha: float
) -> tuple[str, ...]:
    if not records:
        raise ValueError("records must be nonempty")
    if isinstance(metrics, str) or not metrics:
        raise ValueError("metrics must be a nonempty sequence of names")
    names = tuple(metrics)
    if any(not isinstance(name, str) or not name for name in names):
        raise ValueError("metric names must be nonempty strings")
    if len(set(names)) != len(names):
        raise ValueError("metric names must be unique")
    if not isinstance(ridge_alpha, Real) or isinstance(ridge_alpha, bool):
        raise ValueError("ridge_alpha must be numeric")
    ridge_alpha = float(ridge_alpha)
    if not isfinite(ridge_alpha) or ridge_alpha <= 0.0:
        raise ValueError("ridge_alpha must be finite and positive")

    previous_time: float | None = None
    seen_hashes: set[str] = set()
    for record in records:
        if not isinstance(record, SurrogateRecord):
            raise TypeError("records must contain SurrogateRecord values")
        timestamp = _timestamp(record.observed_at)
        if previous_time is not None and timestamp <= previous_time:
            raise ValueError("observed_at timestamps must be strictly increasing")
        previous_time = timestamp
        if not isinstance(record.archive_hash, str) or not record.archive_hash:
            raise ValueError("archive_hash must be a nonempty string")
        if record.archive_hash in seen_hashes:
            raise ValueError("archive_hash values must be unique")
        seen_hashes.add(record.archive_hash)
        if not isinstance(record.deck_family, str) or not record.deck_family:
            raise ValueError("deck_family must be a nonempty string")
        if not isinstance(record.meta_snapshot_id, str) or not record.meta_snapshot_id:
            raise ValueError("meta_snapshot_id must be a nonempty string")
        if set(record.metrics) != set(names):
            raise ValueError("record metrics must exactly match the preregistered metrics")
        for name in names:
            value = record.metrics[name]
            if isinstance(value, bool) or not isinstance(value, Real) or not isfinite(float(value)):
                raise ValueError(f"metric {name!r} must be a finite numeric value")
        if isinstance(record.outcome_delta, bool) or not isinstance(record.outcome_delta, Real) or not isfinite(float(record.outcome_delta)):
            raise ValueError("outcome_delta must be a finite numeric value")
    return names


def _timestamp(value: str | datetime) -> float:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("observed_at must be an ISO-8601 timestamp") from exc
    else:
        raise TypeError("observed_at must be an ISO-8601 string or datetime")
    if parsed.tzinfo is None:
        return parsed.timestamp()
    return parsed.astimezone(timezone.utc).timestamp()


def _fit_scaler(records: Sequence[SurrogateRecord], names: Sequence[str]) -> tuple[list[float], list[float]]:
    means = [sum(float(record.metrics[name]) for record in records) / len(records) for name in names]
    scales: list[float] = []
    for name, mean in zip(names, means):
        variance = sum((float(record.metrics[name]) - mean) ** 2 for record in records) / len(records)
        scale = sqrt(variance)
        scales.append(scale if scale > 1e-12 else 1.0)
    return means, scales


def _standardize(record: SurrogateRecord, names: Sequence[str], means: Sequence[float], scales: Sequence[float]) -> list[float]:
    return [(float(record.metrics[name]) - mean) / scale for name, mean, scale in zip(names, means, scales)]


def _ridge_fit(design: Sequence[Sequence[float]], target: Sequence[float], alpha: float) -> list[float]:
    width = len(design[0]) + 1
    matrix = [[0.0] * width for _ in range(width)]
    vector = [0.0] * width
    for row, value in zip(design, target):
        augmented = [1.0, *row]
        for left in range(width):
            vector[left] += augmented[left] * value
            for right in range(width):
                matrix[left][right] += augmented[left] * augmented[right]
    for index in range(1, width):
        matrix[index][index] += alpha
    return _solve(matrix, vector)


def _solve(matrix: list[list[float]], vector: list[float]) -> list[float]:
    size = len(vector)
    augmented = [row[:] + [value] for row, value in zip(matrix, vector)]
    for column in range(size):
        pivot = max(range(column, size), key=lambda row: abs(augmented[row][column]))
        if abs(augmented[pivot][column]) <= 1e-12:
            raise ValueError("ridge system is singular")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        divisor = augmented[column][column]
        augmented[column] = [value / divisor for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            if factor:
                augmented[row] = [left - factor * right for left, right in zip(augmented[row], augmented[column])]
    return [augmented[index][-1] for index in range(size)]


def _predict(coefficients: Sequence[float], features: Sequence[float]) -> float:
    return coefficients[0] + sum(coefficient * feature for coefficient, feature in zip(coefficients[1:], features))


def _average_ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position + 1
        while end < len(order) and values[order[end]] == values[order[position]]:
            end += 1
        rank = (position + 1 + end) / 2.0
        for index in order[position:end]:
            ranks[index] = rank
        position = end
    return ranks


def _spearman(predictions: Sequence[float], outcomes: Sequence[float]) -> float:
    predicted_ranks = _average_ranks(predictions)
    outcome_ranks = _average_ranks(outcomes)
    return _correlation(predicted_ranks, outcome_ranks)


def _correlation(left: Sequence[float], right: Sequence[float]) -> float:
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    covariance = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_norm = sqrt(sum((value - left_mean) ** 2 for value in left))
    right_norm = sqrt(sum((value - right_mean) ** 2 for value in right))
    return covariance / (left_norm * right_norm) if left_norm and right_norm else 0.0


def _pairwise_accuracy(predictions: Sequence[float], outcomes: Sequence[float]) -> float:
    score = 0.0
    comparisons = 0
    for left in range(len(outcomes)):
        for right in range(left + 1, len(outcomes)):
            actual = outcomes[left] - outcomes[right]
            predicted = predictions[left] - predictions[right]
            comparisons += 1
            if actual == 0.0:
                score += 1.0 if predicted == 0.0 else 0.5
            elif predicted == 0.0:
                score += 0.5
            elif actual * predicted > 0.0:
                score += 1.0
    return score / comparisons if comparisons else 0.0


# Descriptive aliases keep the public entry point readable at call sites.
walk_forward_audit = evaluate
audit_public_surrogate = evaluate


__all__ = [
    "PublicSurrogateRecord",
    "SurrogateRecord",
    "SurrogateResult",
    "audit_public_surrogate",
    "evaluate",
    "walk_forward_audit",
]
