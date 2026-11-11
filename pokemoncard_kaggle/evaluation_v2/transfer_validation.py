"""Leakage-resistant validation of local features against public outcomes.

The public nuisance model explains matchup and environment variation.  The
augmented model may add only candidate-neutral local features.  Every reported
prediction is produced while holding out the complete policy lineage being
scored.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import json
import math
from pathlib import Path
import random
from typing import Any, Iterable, Sequence

import numpy as np
from scipy.stats import spearmanr
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


NUISANCE_COLUMNS = (
    "player_slot",
    "opponent_axis",
    "module_version",
    "time_block",
    "window_stage",
)
LOCAL_COLUMNS = ("paired_mean_delta", "paired_cvar20_delta")


@dataclass(frozen=True)
class TransferLimits:
    min_lineages: int = 8
    min_games: int = 200
    min_time_blocks: int = 3
    min_opponent_axes: int = 4
    min_matched_cells: int = 20
    min_macro_logloss_improvement: float = 0.015
    min_pairwise_ordering_auc: float = 0.64
    min_agent_residual_spearman: float = 0.30
    min_bootstrap_probability: float = 0.90
    min_positive_fold_fraction: float = 0.80


@dataclass(frozen=True)
class TransferCheck:
    name: str
    passed: bool
    value: float | int | bool
    threshold: str


def _window_stage(index: int) -> str:
    if index < 8:
        return "00_07"
    if index < 16:
        return "08_15"
    if index < 32:
        return "16_31"
    return "32_plus"


def load_transfer_inputs(
    panel_path: Path,
    local_features_path: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    panel = json.loads(panel_path.read_text())
    if panel.get("schema") != "public_transfer_panel_v1":
        raise ValueError("unsupported public transfer panel schema")
    local = json.loads(local_features_path.read_text())
    if local.get("schema") != "seeded_transfer_feature_panel_v1":
        raise ValueError("unsupported local feature panel schema")
    baseline = str(local["baseline_label"])
    features = dict(local.get("features") or {})
    rows: list[dict[str, Any]] = []
    labels = {str(game["agent_label"]) for game in panel.get("games") or []}
    if baseline not in labels:
        raise ValueError("local baseline is absent from public panel")
    coverage: dict[str, dict[str, Any]] = {}
    for label in sorted(labels):
        if label == baseline:
            feature = {
                "matched_cells": min(
                    (int(row.get("matched_cells", 0)) for row in features.values()),
                    default=0,
                ),
                "paired_mean_delta": 0.0,
                "paired_cvar20_delta": 0.0,
            }
        else:
            feature = features.get(label)
        if feature is None:
            coverage[label] = {"covered": False, "matched_cells": 0}
            continue
        matched_cells = int(feature.get("matched_cells", 0))
        mean_delta = feature.get("paired_mean_delta")
        tail_delta = feature.get("paired_cvar20_delta")
        covered = mean_delta is not None and tail_delta is not None
        coverage[label] = {"covered": covered, "matched_cells": matched_cells}
        if not covered:
            continue
        for game in panel.get("games") or []:
            if str(game["agent_label"]) != label:
                continue
            rows.append(
                {
                    **game,
                    "lineage": str(game["policy_lineage_id"]),
                    "window_stage": _window_stage(int(game["source_window_index"])),
                    "paired_mean_delta": float(mean_delta),
                    "paired_cvar20_delta": float(tail_delta),
                    "outcome": float(game["outcome"]),
                }
            )
    metadata = {
        "panel_id": panel.get("panel_id"),
        "baseline_label": baseline,
        "coverage": coverage,
        "local_feature_errors": sum(
            bool(row.get("error")) and str(row.get("anchor")) in labels
            for row in local.get("rows") or []
        ),
        "local_seeds": list(local.get("seeds") or []),
        "local_controls": list(local.get("controls") or []),
    }
    return rows, metadata


def _soft_label_fit_rows(
    rows: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], np.ndarray, np.ndarray]:
    expanded: list[dict[str, Any]] = []
    labels: list[int] = []
    weights: list[float] = []
    for row in rows:
        outcome = float(row["outcome"])
        if outcome == 0.5:
            expanded.extend((row, row))
            labels.extend((0, 1))
            weights.extend((0.5, 0.5))
        elif outcome in (0.0, 1.0):
            expanded.append(row)
            labels.append(int(outcome))
            weights.append(1.0)
        else:
            raise ValueError(f"outcome must be 0, 0.5, or 1; got {outcome}")
    return expanded, np.asarray(labels), np.asarray(weights)


def _model_row(row: dict[str, Any], *, include_local: bool) -> dict[str, float]:
    value = {
        f"nuisance:{column}={row[column]}": 1.0
        for column in NUISANCE_COLUMNS
    }
    if include_local:
        value.update({f"local:{column}": float(row[column]) for column in LOCAL_COLUMNS})
    return value


def _pipeline() -> Pipeline:
    return Pipeline(
        [
            ("features", DictVectorizer(sparse=True)),
            ("model", LogisticRegression(C=1.0, solver="lbfgs", max_iter=2000)),
        ]
    )


def _fit_predict(
    train: Sequence[dict[str, Any]],
    test: Sequence[dict[str, Any]],
    *,
    include_local: bool,
) -> np.ndarray:
    fit_rows, labels, weights = _soft_label_fit_rows(train)
    if len(set(labels.tolist())) < 2:
        raise ValueError("training fold has fewer than two outcome classes")
    model = _pipeline()
    model.fit(
        [_model_row(row, include_local=include_local) for row in fit_rows],
        labels,
        model__sample_weight=weights,
    )
    return model.predict_proba(
        [_model_row(row, include_local=include_local) for row in test]
    )[:, 1]


def leave_lineage_out_predictions(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    predictions: list[dict[str, Any]] = []
    lineages = sorted({str(row["lineage"]) for row in rows})
    for lineage in lineages:
        train = [row for row in rows if str(row["lineage"]) != lineage]
        test = [row for row in rows if str(row["lineage"]) == lineage]
        nuisance = _fit_predict(train, test, include_local=False)
        augmented = _fit_predict(train, test, include_local=True)
        for row, base_probability, local_probability in zip(test, nuisance, augmented):
            predictions.append(
                {
                    "agent_label": row["agent_label"],
                    "lineage": lineage,
                    "episode_id": row["episode_id"],
                    "time_block": row["time_block"],
                    "outcome": float(row["outcome"]),
                    "nuisance_probability": float(base_probability),
                    "augmented_probability": float(local_probability),
                }
            )
    return predictions


def historical_forward_predictions(
    rows: Sequence[dict[str, Any]],
    *,
    min_train_lineages: int = 4,
    min_train_games: int = 120,
) -> list[dict[str, Any]]:
    """Diagnostic forward-block predictions for lineages unseen in the past.

    This is retrospective and therefore cannot satisfy the prospective-shadow
    gate. It catches obvious time leakage before a metric is preregistered.
    """

    predictions: list[dict[str, Any]] = []
    for block in sorted({str(row["time_block"]) for row in rows}):
        train = [row for row in rows if str(row["time_block"]) < block]
        train_lineages = {str(row["lineage"]) for row in train}
        test = [
            row
            for row in rows
            if str(row["time_block"]) == block and str(row["lineage"]) not in train_lineages
        ]
        if len(train) < min_train_games or len(train_lineages) < min_train_lineages or not test:
            continue
        nuisance = _fit_predict(train, test, include_local=False)
        augmented = _fit_predict(train, test, include_local=True)
        for row, base_probability, local_probability in zip(test, nuisance, augmented):
            predictions.append(
                {
                    "agent_label": row["agent_label"],
                    "lineage": row["lineage"],
                    "episode_id": row["episode_id"],
                    "time_block": block,
                    "outcome": float(row["outcome"]),
                    "nuisance_probability": float(base_probability),
                    "augmented_probability": float(local_probability),
                }
            )
    return predictions


def _loss(outcome: float, probability: float) -> float:
    probability = min(max(float(probability), 1e-6), 1.0 - 1e-6)
    return -(outcome * math.log(probability) + (1.0 - outcome) * math.log(1.0 - probability))


def _mean(values: Iterable[float]) -> float:
    values = list(values)
    return sum(values) / len(values) if values else float("nan")


def _pairwise_concordance(predicted: dict[str, float], observed: dict[str, float]) -> float:
    labels = sorted(set(predicted) & set(observed))
    scores: list[float] = []
    for left_index, left in enumerate(labels):
        for right in labels[left_index + 1 :]:
            truth = observed[left] - observed[right]
            guess = predicted[left] - predicted[right]
            if truth == 0:
                continue
            if guess == 0:
                scores.append(0.5)
            else:
                scores.append(1.0 if truth * guess > 0 else 0.0)
    return _mean(scores)


def _safe_spearman(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) < 3 or len(set(left)) < 2 or len(set(right)) < 2:
        return float("nan")
    statistic = spearmanr(left, right).statistic
    return float(statistic) if statistic is not None else float("nan")


def score_predictions(
    predictions: Sequence[dict[str, Any]],
    *,
    bootstrap_samples: int = 5000,
    seed: int = 20260710,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        grouped[str(row["lineage"])].append(row)
    lineage_rows: dict[str, dict[str, float | str]] = {}
    for lineage, values in grouped.items():
        label = str(values[0]["agent_label"])
        outcome = _mean(float(row["outcome"]) for row in values)
        nuisance_probability = _mean(float(row["nuisance_probability"]) for row in values)
        augmented_probability = _mean(float(row["augmented_probability"]) for row in values)
        nuisance_loss = _mean(
            _loss(float(row["outcome"]), float(row["nuisance_probability"])) for row in values
        )
        augmented_loss = _mean(
            _loss(float(row["outcome"]), float(row["augmented_probability"])) for row in values
        )
        lineage_rows[lineage] = {
            "agent_label": label,
            "games": len(values),
            "outcome": outcome,
            "nuisance_probability": nuisance_probability,
            "augmented_probability": augmented_probability,
            "observed_residual": outcome - nuisance_probability,
            "predicted_uplift": augmented_probability - nuisance_probability,
            "nuisance_logloss": nuisance_loss,
            "augmented_logloss": augmented_loss,
            "logloss_improvement": nuisance_loss - augmented_loss,
        }
    macro_nuisance = _mean(float(row["nuisance_logloss"]) for row in lineage_rows.values())
    macro_augmented = _mean(float(row["augmented_logloss"]) for row in lineage_rows.values())
    observed_residual = {
        lineage: float(row["observed_residual"]) for lineage, row in lineage_rows.items()
    }
    predicted_uplift = {
        lineage: float(row["predicted_uplift"]) for lineage, row in lineage_rows.items()
    }
    ordered = sorted(lineage_rows)
    residual_spearman = _safe_spearman(
        [predicted_uplift[lineage] for lineage in ordered],
        [observed_residual[lineage] for lineage in ordered],
    )
    raw_spearman = _safe_spearman(
        [float(lineage_rows[lineage]["augmented_probability"]) for lineage in ordered],
        [float(lineage_rows[lineage]["outcome"]) for lineage in ordered],
    )
    improvements = [float(lineage_rows[lineage]["logloss_improvement"]) for lineage in ordered]
    rng = random.Random(seed)
    positive = 0
    for _ in range(bootstrap_samples):
        draw = [improvements[rng.randrange(len(improvements))] for _ in improvements]
        positive += _mean(draw) > 0.0
    return {
        "games": len(predictions),
        "lineages": len(lineage_rows),
        "macro_nuisance_logloss": macro_nuisance,
        "macro_augmented_logloss": macro_augmented,
        "macro_logloss_improvement": macro_nuisance - macro_augmented,
        "pairwise_ordering_auc": _pairwise_concordance(predicted_uplift, observed_residual),
        "agent_residual_spearman": residual_spearman,
        "agent_raw_spearman": raw_spearman,
        "positive_fold_fraction": sum(value > 0 for value in improvements) / len(improvements),
        "bootstrap_probability_improvement_gt_zero": positive / bootstrap_samples,
        "bootstrap_samples": bootstrap_samples,
        "lineage_results": lineage_rows,
    }


def evaluate_transfer(
    rows: Sequence[dict[str, Any]],
    metadata: dict[str, Any],
    *,
    limits: TransferLimits = TransferLimits(),
    bootstrap_samples: int = 5000,
) -> dict[str, Any]:
    labels = {str(row["agent_label"]) for row in rows}
    lineages = {str(row["lineage"]) for row in rows}
    blocks = {str(row["time_block"]) for row in rows}
    axes = {str(row["opponent_axis"]) for row in rows}
    coverage = metadata["coverage"]
    covered_labels = {label for label, value in coverage.items() if value["covered"]}
    minimum_cells = min(
        (int(value["matched_cells"]) for value in coverage.values() if value["covered"]),
        default=0,
    )
    inventory_checks = [
        TransferCheck("lineages", len(lineages) >= limits.min_lineages, len(lineages), f">={limits.min_lineages}"),
        TransferCheck("games", len(rows) >= limits.min_games, len(rows), f">={limits.min_games}"),
        TransferCheck("time_blocks", len(blocks) >= limits.min_time_blocks, len(blocks), f">={limits.min_time_blocks}"),
        TransferCheck("opponent_axes", len(axes) >= limits.min_opponent_axes, len(axes), f">={limits.min_opponent_axes}"),
        TransferCheck("feature_coverage", labels == covered_labels, len(covered_labels), f"all {len(labels)} labels"),
        TransferCheck("local_feature_errors", metadata["local_feature_errors"] == 0, metadata["local_feature_errors"], "==0"),
        TransferCheck("matched_cells", minimum_cells >= limits.min_matched_cells, minimum_cells, f">={limits.min_matched_cells}"),
    ]
    predictions: list[dict[str, Any]] = []
    metrics: dict[str, Any] | None = None
    predictive_checks: list[TransferCheck] = []
    if all(check.passed for check in inventory_checks):
        predictions = leave_lineage_out_predictions(rows)
        metrics = score_predictions(predictions, bootstrap_samples=bootstrap_samples)
        predictive_checks = [
            TransferCheck(
                "macro_logloss_improvement",
                metrics["macro_logloss_improvement"] >= limits.min_macro_logloss_improvement,
                metrics["macro_logloss_improvement"],
                f">={limits.min_macro_logloss_improvement:.3f}",
            ),
            TransferCheck(
                "pairwise_ordering_auc",
                metrics["pairwise_ordering_auc"] >= limits.min_pairwise_ordering_auc,
                metrics["pairwise_ordering_auc"],
                f">={limits.min_pairwise_ordering_auc:.2f}",
            ),
            TransferCheck(
                "agent_residual_spearman",
                metrics["agent_residual_spearman"] >= limits.min_agent_residual_spearman,
                metrics["agent_residual_spearman"],
                f">={limits.min_agent_residual_spearman:.2f}",
            ),
            TransferCheck(
                "bootstrap_probability",
                metrics["bootstrap_probability_improvement_gt_zero"] >= limits.min_bootstrap_probability,
                metrics["bootstrap_probability_improvement_gt_zero"],
                f">={limits.min_bootstrap_probability:.2f}",
            ),
            TransferCheck(
                "positive_fold_fraction",
                metrics["positive_fold_fraction"] >= limits.min_positive_fold_fraction,
                metrics["positive_fold_fraction"],
                f">={limits.min_positive_fold_fraction:.2f}",
            ),
        ]
    checks = inventory_checks + predictive_checks
    forward_predictions = (
        historical_forward_predictions(rows)
        if all(check.passed for check in inventory_checks)
        else []
    )
    forward_metrics = (
        score_predictions(forward_predictions, bootstrap_samples=bootstrap_samples)
        if forward_predictions
        else None
    )
    return {
        "schema": "public_transfer_validation_v1",
        "panel_id": metadata["panel_id"],
        "baseline_label": metadata["baseline_label"],
        "limits": asdict(limits),
        "checks": [asdict(check) for check in checks],
        "transfer_certified": bool(checks) and all(check.passed for check in checks),
        "metrics": metrics,
        "historical_forward_metrics": forward_metrics,
        "historical_forward_predictions": forward_predictions,
        "predictions": predictions,
        "metadata": metadata,
    }


__all__ = [
    "LOCAL_COLUMNS",
    "NUISANCE_COLUMNS",
    "TransferCheck",
    "TransferLimits",
    "evaluate_transfer",
    "historical_forward_predictions",
    "leave_lineage_out_predictions",
    "load_transfer_inputs",
    "score_predictions",
]
