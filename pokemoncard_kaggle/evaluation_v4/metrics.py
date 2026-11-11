"""Pure prospective metrics for the v4 whole-policy selector.

This module scores already-materialized 24-game unit rows.  It deliberately
does not read outcome files, register predictions, establish clock authority,
or authorize a submission.  ``simulator_delta`` is resampled only as an
ensemble/cell summary diagnostic; it is not treated as a candidate outcome or
as public certification.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import math
from numbers import Real
import random
from typing import Any


SCHEMA = "whole_policy_selector_metrics_v1"
UNIT_FIELDS = frozenset(
    {
        "unit_id",
        "lineage_id",
        "ancestry_id",
        "family_id",
        "block_id",
        "outcomes",
        "nuisance_probability",
        "selector_probability",
        "simulator_delta",
        "ood_mass",
        "engine_variant_means",
    }
)
OUTCOME_VALUES = frozenset({0.0, 0.5, 1.0})
DEFAULT_BOOTSTRAP_SAMPLES = 5000

# These are checks from the v4 architecture, not a composite score.  They are
# kept here as defaults so a caller can request the preregistered checks while
# still passing different explicit thresholds for a diagnostic experiment.
ARCHITECTURE_THRESHOLDS: dict[str, float] = {
    "macro_lineage_logloss_lift": 0.015,
    "lineage_bootstrap_probability_positive": 0.95,
    "lineage_bootstrap_q10": 0.0,
    "pairwise_residual_concordance": 0.65,
    "positive_unit_fraction": 0.80,
    "family_logloss_lift_min": -0.01,
    "calibration_slope_90_lower_bound": 0.0,
    "ood_mass_max": 0.10,
    "candidate_posterior_mean": 0.03,
    "candidate_posterior_probability_positive": 0.95,
    "candidate_posterior_q10": 0.0,
    "candidate_posterior_worst_family_q10": -0.02,
    "minimum_engine_variant_mean": 0.0,
}
ARCHITECTURE_MINIMUMS: dict[str, int] = {
    "lineages": 16,
    "families": 4,
    "blocks": 3,
}

# Selector-transfer validation and candidate promotion are different claims.
# The former asks whether frozen prospective probabilities improve public
# prediction.  Raw simulator summaries belong to the latter and must never be
# allowed to decide whether the selector itself transferred.
SELECTOR_CHECK_NAMES = frozenset(
    {
        "minimum_lineages",
        "minimum_families",
        "minimum_blocks",
        "macro_lineage_logloss_lift",
        "lineage_bootstrap_probability_positive",
        "lineage_bootstrap_q10_strictly_positive",
        "pairwise_residual_concordance",
        "positive_unit_fraction",
        "family_logloss_lifts",
        "calibration_slope_90_lower_bound_strictly_positive",
        "candidate_ood_mass_within_limit",
    }
)


def score_whole_policy(
    unit_rows: Iterable[Mapping[str, Any]],
    *,
    seed: int = 0,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
) -> dict[str, Any]:
    """Score prospective whole-policy units with deterministic resampling.

    Each row must contain exactly the fields in :data:`UNIT_FIELDS` and exactly
    24 ternary game outcomes.  Lineages are required to be unique, so a
    lineage bootstrap is a bootstrap over independent policy units rather than
    over individual games or decisions.
    """
    samples = _validate_bootstrap_samples(bootstrap_samples)
    seed = _validate_seed(seed)
    normalized = _validate_rows(unit_rows)
    normalized.sort(key=lambda row: (row["lineage_id"], row["unit_id"]))

    per_unit = [_unit_metrics(row) for row in normalized]
    unit_lifts = [unit["logloss_lift"] for unit in per_unit]
    simulator_deltas = [row["simulator_delta"] for row in normalized]
    residuals = [unit["residual"] for unit in per_unit]
    predicted_uplifts = [unit["predicted_uplift"] for unit in per_unit]

    family_rows: dict[str, list[dict[str, Any]]] = {}
    family_simulator_deltas: dict[str, list[float]] = {}
    variant_values: dict[str, list[float]] = {}
    for row, unit in zip(normalized, per_unit):
        family = row["family_id"]
        family_rows.setdefault(family, []).append(unit)
        family_simulator_deltas.setdefault(family, []).append(row["simulator_delta"])
        for variant, value in row["engine_variant_means"].items():
            variant_values.setdefault(variant, []).append(value)

    family_logloss_lifts = {
        family: _mean(unit["logloss_lift"] for unit in units)
        for family, units in sorted(family_rows.items())
    }
    per_family = {
        family: _family_metrics(units, family_simulator_deltas[family])
        for family, units in sorted(family_rows.items())
    }
    engine_variant_means = {
        variant: _mean(values) for variant, values in sorted(variant_values.items())
    }

    rng = random.Random(seed)
    lineage_lift_bootstrap: list[float] = []
    candidate_bootstrap: list[float] = []
    slope_bootstrap: list[float] = []
    family_candidate_bootstrap: dict[str, list[float]] = {
        family: [] for family in sorted(family_simulator_deltas)
    }
    for _ in range(samples):
        indices = _resampled_indices(rng, len(normalized))
        lineage_lift_bootstrap.append(_mean(unit_lifts[index] for index in indices))
        # This is intentionally a resampled simulator-cell summary, not a
        # posterior over unobserved candidate game outcomes.
        candidate_bootstrap.append(_mean(simulator_deltas[index] for index in indices))
        slope_bootstrap.append(
            _ols_slope(
                [simulator_deltas[index] for index in indices],
                [residuals[index] for index in indices],
            )
        )
        for family, values in family_simulator_deltas.items():
            family_indices = _resampled_indices(rng, len(values))
            family_candidate_bootstrap[family].append(
                _mean(values[index] for index in family_indices)
            )

    valid_slope_bootstrap = [value for value in slope_bootstrap if math.isfinite(value)]
    calibration_slope = _ols_slope(simulator_deltas, residuals)
    family_candidate_q10 = {
        family: _quantile(values, 0.10)
        for family, values in sorted(family_candidate_bootstrap.items())
    }
    for family, q10 in family_candidate_q10.items():
        per_family[family]["simulator_delta_bootstrap_q10"] = q10
    metrics: dict[str, Any] = {
        "unit_count": len(normalized),
        "lineages": len({row["lineage_id"] for row in normalized}),
        "families": len(family_rows),
        "blocks": len({row["block_id"] for row in normalized}),
        "macro_lineage_logloss_lift": _mean(unit_lifts),
        "lineage_bootstrap_probability_positive": _positive_fraction(lineage_lift_bootstrap),
        "lineage_bootstrap_q10": _quantile(lineage_lift_bootstrap, 0.10),
        "positive_unit_fraction": _positive_fraction(unit_lifts),
        "positive_residual_unit_fraction": _positive_fraction(residuals),
        "family_logloss_lifts": family_logloss_lifts,
        "pairwise_residual_concordance": _pairwise_concordance(
            predicted_uplifts, residuals
        ),
        "ood_mass_max": max(row["ood_mass"] for row in normalized),
        "engine_variant_means": engine_variant_means,
        "minimum_engine_variant_mean": min(engine_variant_means.values()),
        "candidate_posterior_mean": _mean(simulator_deltas),
        "candidate_posterior_probability_positive": _positive_fraction(candidate_bootstrap),
        "candidate_posterior_q10": _quantile(candidate_bootstrap, 0.10),
        "candidate_posterior_worst_family_q10": min(family_candidate_q10.values()),
        "candidate_posterior_family_q10": family_candidate_q10,
        "calibration_slope": calibration_slope,
        "calibration_slope_90_lower_bound": (
            _quantile(valid_slope_bootstrap, 0.10) if valid_slope_bootstrap else float("nan")
        ),
        "calibration_slope_bootstrap_valid_draws": len(valid_slope_bootstrap),
    }
    # Readable aliases make the artifact easier to consume without introducing
    # a second calculation or a weighted aggregate.
    metrics.update(
        {
            "macro_logloss_lift": metrics["macro_lineage_logloss_lift"],
            "lineage_logloss_lift_probability_positive": metrics[
                "lineage_bootstrap_probability_positive"
            ],
            "lineage_logloss_lift_q10": metrics["lineage_bootstrap_q10"],
            "candidate_simulator_delta_mean": metrics["candidate_posterior_mean"],
            "candidate_simulator_delta_probability_positive": metrics[
                "candidate_posterior_probability_positive"
            ],
            "candidate_simulator_delta_q10": metrics["candidate_posterior_q10"],
            "worst_family_simulator_delta_q10": metrics[
                "candidate_posterior_worst_family_q10"
            ],
        }
    )

    return {
        "schema": SCHEMA,
        "bootstrap": {
            "method": "lineage_resampling_with_replacement",
            "samples": samples,
            "seed": seed,
            "quantile": "type7_linear",
        },
        "metrics": metrics,
        "per_unit": per_unit,
        "per_family": per_family,
        "notes": [
            "simulator_delta posterior metrics resample unit simulator deltas as an ensemble/cell summary diagnostic; they are not candidate outcomes or public certification",
            "positive_unit_fraction counts units with positive logloss lift; positive_residual_unit_fraction is reported separately",
        ],
    }


def evaluate_checks(
    metrics: Mapping[str, Any],
    thresholds: Mapping[str, Any] | None = None,
    minimums: Mapping[str, Any] | None = None,
) -> dict[str, bool]:
    """Return named conjunctive checks without an authorization decision.

    ``metrics`` may be either the ``metrics`` member of a score artifact or the
    complete artifact.  The returned mapping intentionally has no aggregate
    ``certified``/``authorized`` field; callers can inspect each gate by name.
    """
    values = _metrics_mapping(metrics)
    threshold_values = _merge_numeric_settings(
        ARCHITECTURE_THRESHOLDS,
        thresholds,
        setting_name="thresholds",
    )
    minimum_values = _merge_integer_settings(
        ARCHITECTURE_MINIMUMS,
        minimums,
        setting_name="minimums",
    )

    family_lifts = values.get("family_logloss_lifts")
    variant_means = values.get("engine_variant_means")
    family_check = (
        isinstance(family_lifts, Mapping)
        and bool(family_lifts)
        and all(
            _finite_number(value, label="family logloss lift")
            >= threshold_values["family_logloss_lift_min"]
            for value in family_lifts.values()
        )
    )
    variant_check = (
        isinstance(variant_means, Mapping)
        and bool(variant_means)
        and all(
            _finite_number(value, label="engine variant mean")
            >= threshold_values["minimum_engine_variant_mean"]
            for value in variant_means.values()
        )
    )

    return {
        "minimum_lineages": _at_least(
            values.get("lineages"), minimum_values["lineages"]
        ),
        "minimum_families": _at_least(
            values.get("families"), minimum_values["families"]
        ),
        "minimum_blocks": _at_least(values.get("blocks"), minimum_values["blocks"]),
        "macro_lineage_logloss_lift": _at_least(
            values.get("macro_lineage_logloss_lift"),
            threshold_values["macro_lineage_logloss_lift"],
        ),
        "lineage_bootstrap_probability_positive": _at_least(
            values.get("lineage_bootstrap_probability_positive"),
            threshold_values["lineage_bootstrap_probability_positive"],
        ),
        "lineage_bootstrap_q10_strictly_positive": _strictly_above(
            values.get("lineage_bootstrap_q10"),
            threshold_values["lineage_bootstrap_q10"],
        ),
        "pairwise_residual_concordance": _at_least(
            values.get("pairwise_residual_concordance"),
            threshold_values["pairwise_residual_concordance"],
        ),
        "positive_unit_fraction": _at_least(
            values.get("positive_unit_fraction"),
            threshold_values["positive_unit_fraction"],
        ),
        "family_logloss_lifts": family_check,
        "calibration_slope_90_lower_bound_strictly_positive": _strictly_above(
            values.get("calibration_slope_90_lower_bound"),
            threshold_values["calibration_slope_90_lower_bound"],
        ),
        "candidate_ood_mass_within_limit": _at_most(
            values.get("ood_mass_max"), threshold_values["ood_mass_max"]
        ),
        "candidate_posterior_mean": _at_least(
            values.get("candidate_posterior_mean"),
            threshold_values["candidate_posterior_mean"],
        ),
        "candidate_posterior_probability_positive": _at_least(
            values.get("candidate_posterior_probability_positive"),
            threshold_values["candidate_posterior_probability_positive"],
        ),
        "candidate_posterior_q10": _at_least(
            values.get("candidate_posterior_q10"),
            threshold_values["candidate_posterior_q10"],
        ),
        "candidate_posterior_worst_family_q10": _at_least(
            values.get("candidate_posterior_worst_family_q10"),
            threshold_values["candidate_posterior_worst_family_q10"],
        ),
        "engine_variant_means": variant_check,
    }


def evaluate_selector_checks(
    metrics: Mapping[str, Any],
    thresholds: Mapping[str, Any] | None = None,
    minimums: Mapping[str, Any] | None = None,
) -> dict[str, bool]:
    """Return only prospective public-transfer checks.

    Candidate simulator-delta checks are intentionally excluded.  A caller may
    inspect them through :func:`evaluate_checks`, but they cannot validate the
    selector that is supposed to calibrate those diagnostics.
    """

    checks = evaluate_checks(metrics, thresholds=thresholds, minimums=minimums)
    return {name: checks[name] for name in sorted(SELECTOR_CHECK_NAMES)}


# Descriptive aliases keep the public call site flexible without adding a
# second implementation or a separate registration path.
evaluate = score_whole_policy
evaluate_whole_policy = score_whole_policy


def _validate_rows(unit_rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(unit_rows, (str, bytes, bytearray, Mapping)):
        raise TypeError("unit_rows must be an iterable of strict unit mappings")
    try:
        rows = list(unit_rows)
    except TypeError as exc:
        raise TypeError("unit_rows must be an iterable of strict unit mappings") from exc
    if not rows:
        raise ValueError("unit_rows must be nonempty")

    seen_units: set[str] = set()
    seen_lineages: set[str] = set()
    seen_ancestries: set[str] = set()
    expected_variant_ids: frozenset[str] | None = None
    normalized: list[dict[str, Any]] = []
    for position, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise TypeError(f"unit row {position} must be a mapping")
        fields = set(row)
        if fields != UNIT_FIELDS:
            missing = sorted(UNIT_FIELDS - fields, key=repr)
            unknown = sorted(fields - UNIT_FIELDS, key=repr)
            raise ValueError(
                f"unit row {position} fields must be exact; missing={missing}, unknown={unknown}"
            )

        identifiers = {
            field: _identifier(row[field], label=f"{field} in unit row {position}")
            for field in (
                "unit_id",
                "lineage_id",
                "ancestry_id",
                "family_id",
                "block_id",
            )
        }
        if identifiers["unit_id"] in seen_units:
            raise ValueError(f"duplicate unit_id {identifiers['unit_id']!r}")
        if identifiers["lineage_id"] in seen_lineages:
            raise ValueError(f"reused lineage_id {identifiers['lineage_id']!r}")
        if identifiers["ancestry_id"] in seen_ancestries:
            raise ValueError(f"reused ancestry_id {identifiers['ancestry_id']!r}")
        seen_units.add(identifiers["unit_id"])
        seen_lineages.add(identifiers["lineage_id"])
        seen_ancestries.add(identifiers["ancestry_id"])

        try:
            outcomes = tuple(row["outcomes"])
        except TypeError as exc:
            raise TypeError(f"outcomes in unit row {position} must be iterable") from exc
        if isinstance(row["outcomes"], (str, bytes, bytearray, Mapping)):
            raise TypeError(f"outcomes in unit row {position} must be a numeric sequence")
        if len(outcomes) != 24:
            raise ValueError(f"unit row {position} must contain exactly 24 outcomes")
        checked_outcomes = tuple(
            _outcome(value, label=f"outcomes[{index}] in unit row {position}")
            for index, value in enumerate(outcomes)
        )

        p0 = _finite_number(row["nuisance_probability"], label="nuisance_probability")
        p1 = _finite_number(row["selector_probability"], label="selector_probability")
        if not 0.0 < p0 < 1.0:
            raise ValueError("nuisance_probability must be strictly between 0 and 1")
        if not 0.0 < p1 < 1.0:
            raise ValueError("selector_probability must be strictly between 0 and 1")
        simulator_delta = _finite_number(row["simulator_delta"], label="simulator_delta")
        ood_mass = _finite_number(row["ood_mass"], label="ood_mass")
        if not 0.0 <= ood_mass <= 1.0:
            raise ValueError("ood_mass must be in [0, 1]")

        raw_variants = row["engine_variant_means"]
        if not isinstance(raw_variants, Mapping):
            raise TypeError("engine_variant_means must be a mapping")
        if not raw_variants:
            raise ValueError("engine_variant_means must be nonempty")
        variants: dict[str, float] = {}
        for variant, value in raw_variants.items():
            variant_id = _identifier(variant, label="engine variant id")
            variants[variant_id] = _finite_number(
                value, label=f"engine_variant_means[{variant_id!r}]"
            )
        variant_ids = frozenset(variants)
        if expected_variant_ids is None:
            expected_variant_ids = variant_ids
        elif variant_ids != expected_variant_ids:
            raise ValueError("all units must bind the same frozen engine variant set")

        normalized.append(
            {
                **identifiers,
                "outcomes": checked_outcomes,
                "nuisance_probability": p0,
                "selector_probability": p1,
                "simulator_delta": simulator_delta,
                "ood_mass": ood_mass,
                "engine_variant_means": variants,
            }
        )
    return normalized


def _unit_metrics(row: Mapping[str, Any]) -> dict[str, Any]:
    outcomes = row["outcomes"]
    observed_rate = _mean(outcomes)
    p0 = row["nuisance_probability"]
    p1 = row["selector_probability"]
    nuisance_logloss = _mean(_logloss(outcome, p0) for outcome in outcomes)
    selector_logloss = _mean(_logloss(outcome, p1) for outcome in outcomes)
    return {
        "unit_id": row["unit_id"],
        "lineage_id": row["lineage_id"],
        "ancestry_id": row["ancestry_id"],
        "family_id": row["family_id"],
        "block_id": row["block_id"],
        "outcome_count": len(outcomes),
        "observed_rate": observed_rate,
        "residual": observed_rate - p0,
        "nuisance_logloss": nuisance_logloss,
        "selector_logloss": selector_logloss,
        "logloss_lift": nuisance_logloss - selector_logloss,
        "predicted_uplift": p1 - p0,
        "simulator_delta": row["simulator_delta"],
        "ood_mass": row["ood_mass"],
        "engine_variant_means": dict(row["engine_variant_means"]),
    }


def _family_metrics(units: Sequence[Mapping[str, Any]], simulator_deltas: Sequence[float]) -> dict[str, Any]:
    return {
        "unit_count": len(units),
        "lineage_count": len({unit["lineage_id"] for unit in units}),
        "block_count": len({unit["block_id"] for unit in units}),
        "logloss_lift": _mean(unit["logloss_lift"] for unit in units),
        "positive_unit_fraction": _positive_fraction(
            unit["logloss_lift"] for unit in units
        ),
        "simulator_delta_mean": _mean(simulator_deltas),
    }


def _logloss(outcome: float, probability: float) -> float:
    return -(outcome * math.log(probability) + (1.0 - outcome) * math.log1p(-probability))


def _ols_slope(x_values: Sequence[float], y_values: Sequence[float]) -> float:
    if len(x_values) != len(y_values) or len(x_values) < 2:
        return float("nan")
    x_mean = _mean(x_values)
    y_mean = _mean(y_values)
    denominator = math.fsum((value - x_mean) ** 2 for value in x_values)
    if denominator == 0.0:
        return float("nan")
    return math.fsum(
        (x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values)
    ) / denominator


def _pairwise_concordance(predicted: Sequence[float], observed: Sequence[float]) -> float:
    scores: list[float] = []
    for left in range(len(observed)):
        for right in range(left + 1, len(observed)):
            observed_difference = observed[left] - observed[right]
            if observed_difference == 0.0:
                continue
            predicted_difference = predicted[left] - predicted[right]
            if predicted_difference == 0.0:
                scores.append(0.5)
            else:
                scores.append(
                    1.0 if observed_difference * predicted_difference > 0.0 else 0.0
                )
    return _mean(scores) if scores else 0.0


def _resampled_indices(rng: random.Random, size: int) -> list[int]:
    return [rng.randrange(size) for _ in range(size)]


def _quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _mean(values: Iterable[float]) -> float:
    materialized = list(values)
    if not materialized:
        return float("nan")
    return math.fsum(materialized) / len(materialized)


def _positive_fraction(values: Iterable[float]) -> float:
    materialized = list(values)
    return sum(value > 0.0 for value in materialized) / len(materialized)


def _finite_number(value: Any, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise TypeError(f"{label} must be a finite number")
    converted = float(value)
    if not math.isfinite(converted):
        raise ValueError(f"{label} must be finite")
    return converted


def _outcome(value: Any, *, label: str) -> float:
    converted = _finite_number(value, label=label)
    if converted not in OUTCOME_VALUES:
        raise ValueError(f"{label} must be one of 0, 0.5, or 1")
    return converted


def _identifier(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise TypeError(f"{label} must be a nonempty trimmed string")
    return value


def _validate_bootstrap_samples(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("bootstrap_samples must be a positive integer")
    return value


def _validate_seed(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("seed must be an integer")
    return value


def _metrics_mapping(metrics: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(metrics, Mapping):
        raise TypeError("metrics must be a mapping or a score artifact mapping")
    nested = metrics.get("metrics")
    if isinstance(nested, Mapping):
        return nested
    return metrics


def _merge_numeric_settings(
    defaults: Mapping[str, float],
    supplied: Mapping[str, Any] | None,
    *,
    setting_name: str,
) -> dict[str, float]:
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, Mapping):
        raise TypeError(f"{setting_name} must be a mapping")
    aliases = {
        "macro_logloss_lift": "macro_lineage_logloss_lift",
        "macro_lineage_logloss_lift_min": "macro_lineage_logloss_lift",
        "bootstrap_probability_positive": "lineage_bootstrap_probability_positive",
        "lineage_bootstrap_positive_probability_min": "lineage_bootstrap_probability_positive",
        "bootstrap_q10": "lineage_bootstrap_q10",
        "lineage_bootstrap_q10_lift_min": "lineage_bootstrap_q10",
        "pairwise_concordance": "pairwise_residual_concordance",
        "residual_pairwise_concordance_min": "pairwise_residual_concordance",
        "positive_unit_fraction_min": "positive_unit_fraction",
        "family_logloss_lift": "family_logloss_lift_min",
        "family_lift_floor": "family_logloss_lift_min",
        "calibration_slope_lower_bound": "calibration_slope_90_lower_bound",
        "calibration_slope_lower_bound_min": "calibration_slope_90_lower_bound",
        "ood_max": "ood_mass_max",
        "max_candidate_visited_ood_mass": "ood_mass_max",
        "candidate_mean_lift": "candidate_posterior_mean",
        "candidate_posterior_mean_lift_min": "candidate_posterior_mean",
        "candidate_probability_positive": "candidate_posterior_probability_positive",
        "candidate_posterior_positive_probability_min": "candidate_posterior_probability_positive",
        "candidate_q10": "candidate_posterior_q10",
        "candidate_posterior_q10_lift_min": "candidate_posterior_q10",
        "worst_family_q10": "candidate_posterior_worst_family_q10",
        "worst_family_q10_lift_min": "candidate_posterior_worst_family_q10",
        "engine_variant_minimum_mean": "minimum_engine_variant_mean",
        "engine_variant_mean_lift_min": "minimum_engine_variant_mean",
    }
    result = dict(defaults)
    for key, value in supplied.items():
        canonical = aliases.get(key, key)
        if canonical not in defaults:
            raise ValueError(f"unknown {setting_name} field {key!r}")
        result[canonical] = _finite_number(value, label=f"{setting_name}[{key!r}]")
    return result


def _merge_integer_settings(
    defaults: Mapping[str, int],
    supplied: Mapping[str, Any] | None,
    *,
    setting_name: str,
) -> dict[str, int]:
    if supplied is None:
        supplied = {}
    if not isinstance(supplied, Mapping):
        raise TypeError(f"{setting_name} must be a mapping")
    aliases = {"min_lineages": "lineages", "min_families": "families", "min_blocks": "blocks"}
    result = dict(defaults)
    for key, value in supplied.items():
        canonical = aliases.get(key, key)
        if canonical not in defaults:
            raise ValueError(f"unknown {setting_name} field {key!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{setting_name}[{key!r}] must be a nonnegative integer")
        result[canonical] = value
    return result


def _at_least(value: Any, threshold: float | int) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(float(value)) and float(value) >= threshold


def _strictly_above(value: Any, threshold: float) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(float(value)) and float(value) > threshold


def _at_most(value: Any, threshold: float) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool) and math.isfinite(float(value)) and float(value) <= threshold


__all__ = [
    "ARCHITECTURE_MINIMUMS",
    "ARCHITECTURE_THRESHOLDS",
    "DEFAULT_BOOTSTRAP_SAMPLES",
    "SCHEMA",
    "SELECTOR_CHECK_NAMES",
    "UNIT_FIELDS",
    "evaluate",
    "evaluate_checks",
    "evaluate_selector_checks",
    "evaluate_whole_policy",
    "score_whole_policy",
]
