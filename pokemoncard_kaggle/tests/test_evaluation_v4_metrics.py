from __future__ import annotations

from copy import deepcopy
import math

import pytest

from evaluation_v4.metrics import evaluate_checks, evaluate_selector_checks, score_whole_policy


def _row(
    index: int,
    *,
    outcomes: list[float] | None = None,
    p0: float = 0.20,
    p1: float = 0.80,
    simulator_delta: float | None = None,
    ood_mass: float = 0.02,
    family: str | None = None,
    block: str | None = None,
    variants: dict[str, float] | None = None,
) -> dict[str, object]:
    return {
        "unit_id": f"unit-{index}",
        "lineage_id": f"lineage-{index}",
        "ancestry_id": f"ancestry-{index // 2}",
        "family_id": family or f"family-{index % 4}",
        "block_id": block or f"block-{index % 3}",
        "outcomes": list(outcomes if outcomes is not None else [1.0] * 24),
        "nuisance_probability": p0,
        "selector_probability": p1,
        "simulator_delta": index + 1 if simulator_delta is None else simulator_delta,
        "ood_mass": ood_mass,
        "engine_variant_means": variants or {"engine-a": 0.10, "engine-b": 0.20},
    }


def _positive_rows() -> list[dict[str, object]]:
    rows = []
    for index in range(16):
        # The observed residual and simulator delta rise together.  The
        # selector is also more confident on every unit than the nuisance.
        p0 = 0.48 - index * 0.015
        row = _row(
            index,
            p0=p0,
            p1=p0 + 0.04 + index * 0.003,
            simulator_delta=0.05 + index * 0.01,
        )
        row["ancestry_id"] = f"ancestry-{index}"
        rows.append(row)
    return rows


def test_perfect_signal_has_the_expected_directions_and_passes_checks() -> None:
    result = score_whole_policy(_positive_rows(), seed=7, bootstrap_samples=300)
    metrics = result["metrics"]

    assert result["schema"] == "whole_policy_selector_metrics_v1"
    assert metrics["macro_lineage_logloss_lift"] > 0.015
    assert metrics["lineage_bootstrap_probability_positive"] == 1.0
    assert metrics["lineage_bootstrap_q10"] > 0.0
    assert metrics["pairwise_residual_concordance"] == 1.0
    assert metrics["positive_unit_fraction"] == 1.0
    assert metrics["calibration_slope_90_lower_bound"] > 0.0
    checks = evaluate_checks(result["metrics"])
    assert all(checks.values()), checks


def test_reversed_signal_fails_pairwise_concordance_and_slope() -> None:
    rows = []
    for index in range(16):
        p0 = 0.30 - index * 0.004
        row = _row(
            index,
            p0=p0,
            p1=p0 + 0.20 - index * 0.008,
            simulator_delta=1.0 - index * 0.03,
        )
        row["ancestry_id"] = f"ancestry-{index}"
        rows.append(row)
    metrics = score_whole_policy(rows, seed=11, bootstrap_samples=300)["metrics"]

    assert metrics["pairwise_residual_concordance"] == 0.0
    assert metrics["calibration_slope"] < 0.0
    assert metrics["calibration_slope_90_lower_bound"] < 0.0


def test_family_regression_is_visible_without_averaging_it_away() -> None:
    rows = _positive_rows()
    for index in range(4):
        rows[index]["outcomes"] = [0.0] * 24
        rows[index]["nuisance_probability"] = 0.20
        rows[index]["selector_probability"] = 0.80
    result = score_whole_policy(rows, seed=3, bootstrap_samples=200)
    metrics = result["metrics"]

    assert metrics["family_logloss_lifts"]["family-0"] < 0.0
    assert result["per_family"]["family-0"]["logloss_lift"] < 0.0
    assert evaluate_checks(metrics)["family_logloss_lifts"] is False


def test_high_ood_mass_is_visible_and_fails_ood_check() -> None:
    rows = _positive_rows()
    rows[9]["ood_mass"] = 0.75
    result = score_whole_policy(rows, seed=4, bootstrap_samples=100)

    assert result["metrics"]["ood_mass_max"] == 0.75
    assert evaluate_checks(result["metrics"])["candidate_ood_mass_within_limit"] is False


def test_bootstrap_is_deterministic_for_a_seed() -> None:
    rows = _positive_rows()
    first = score_whole_policy(rows, seed=123, bootstrap_samples=250)
    second = score_whole_policy(rows, seed=123, bootstrap_samples=250)

    assert first == second


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda row: row.pop("block_id"), "missing"),
        (lambda row: row.__setitem__("unknown", 1), "unknown"),
        (lambda row: row.__setitem__("outcomes", [1.0] * 23), "exactly 24"),
        (lambda row: row.__setitem__("outcomes", [1.0] * 25), "exactly 24"),
        (lambda row: row.__setitem__("outcomes", [0.25] * 24), "one of"),
        (lambda row: row.__setitem__("nuisance_probability", 0.0), "strictly"),
        (lambda row: row.__setitem__("selector_probability", float("nan")), "finite"),
        (lambda row: row.__setitem__("ood_mass", 1.01), "[0, 1]"),
        (lambda row: row.__setitem__("engine_variant_means", {}), "nonempty"),
    ],
)
def test_malformed_unit_rows_are_rejected(mutate, message: str) -> None:
    row = _row(0)
    mutate(row)
    with pytest.raises((TypeError, ValueError), match=message):
        score_whole_policy([row], bootstrap_samples=20)


def test_duplicate_units_and_reused_lineages_are_rejected() -> None:
    duplicate_unit = [_row(0), _row(0)]
    with pytest.raises(ValueError, match="duplicate unit_id"):
        score_whole_policy(duplicate_unit, bootstrap_samples=20)

    reused_lineage = [_row(0), _row(1)]
    reused_lineage[1]["lineage_id"] = reused_lineage[0]["lineage_id"]
    with pytest.raises(ValueError, match="reused lineage_id"):
        score_whole_policy(reused_lineage, bootstrap_samples=20)

    reused_ancestry = [_row(0), _row(2)]
    reused_ancestry[1]["ancestry_id"] = reused_ancestry[0]["ancestry_id"]
    with pytest.raises(ValueError, match="reused ancestry_id"):
        score_whole_policy(reused_ancestry, bootstrap_samples=20)


def test_every_unit_must_bind_the_same_engine_uncertainty_set() -> None:
    rows = [_row(0), _row(1)]
    rows[1]["ancestry_id"] = "ancestry-1"
    rows[1]["engine_variant_means"] = {"engine-a": 0.1, "engine-c": 0.2}

    with pytest.raises(ValueError, match="same frozen engine variant set"):
        score_whole_policy(rows, bootstrap_samples=20)


def test_candidate_and_engine_constraints_are_separate_checks() -> None:
    rows = _positive_rows()
    for row in rows:
        row["simulator_delta"] = -0.05
        row["engine_variant_means"] = {"engine-a": -0.01, "engine-b": 0.02}
    result = score_whole_policy(rows, seed=8, bootstrap_samples=200)
    checks = evaluate_checks(result["metrics"])

    assert result["metrics"]["candidate_posterior_mean"] == -0.05
    assert result["metrics"]["minimum_engine_variant_mean"] == -0.01
    assert checks["candidate_posterior_mean"] is False
    assert checks["candidate_posterior_probability_positive"] is False
    assert checks["candidate_posterior_q10"] is False
    assert checks["candidate_posterior_worst_family_q10"] is False
    assert checks["engine_variant_means"] is False

    selector_checks = evaluate_selector_checks(result["metrics"])
    assert not any(name.startswith("candidate_posterior") for name in selector_checks)
    assert "engine_variant_means" not in selector_checks
    assert selector_checks["macro_lineage_logloss_lift"] is True


def test_insufficient_calibration_variation_returns_nan_and_fails_check() -> None:
    rows = _positive_rows()
    for row in rows:
        row["simulator_delta"] = 0.2
    result = score_whole_policy(rows, seed=5, bootstrap_samples=100)

    assert math.isnan(result["metrics"]["calibration_slope"])
    assert math.isnan(result["metrics"]["calibration_slope_90_lower_bound"])
    assert evaluate_checks(result["metrics"])[
        "calibration_slope_90_lower_bound_strictly_positive"
    ] is False


def test_artifact_has_details_but_no_weighted_composite_or_certification() -> None:
    result = score_whole_policy(_positive_rows(), seed=9, bootstrap_samples=50)
    checks = evaluate_checks(result)

    assert len(result["per_unit"]) == 16
    assert set(result["per_family"]) == {"family-0", "family-1", "family-2", "family-3"}
    assert "certified" not in result
    assert "authorized" not in result
    assert not any("composite" in key for key in result)
    assert set(checks)  # named individual gates, with no authorization result
    assert "certified" not in checks


def test_input_rows_are_not_mutated() -> None:
    rows = _positive_rows()
    before = deepcopy(rows)
    score_whole_policy(rows, seed=10, bootstrap_samples=20)
    assert rows == before
