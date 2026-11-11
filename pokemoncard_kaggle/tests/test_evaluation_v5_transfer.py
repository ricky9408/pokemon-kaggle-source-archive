from __future__ import annotations

from copy import deepcopy
import math

import pytest

from evaluation_v5.transfer import (
    GAMES_PER_ARCHIVE,
    MIN_RESAMPLES,
    TransferValidationError,
    evaluate_transfer,
    validate_prediction_rows,
)


EPSILON = 0.001


def _rows(
    *,
    archives: int = 30,
    families: int = 15,
    baseline: float = 0.55,
    mci: float = 0.85,
    outcome: float = 1.0,
) -> list[dict[str, object]]:
    assert archives >= families
    rows: list[dict[str, object]] = []
    for archive_index in range(archives):
        family = f"family-{archive_index % families:02d}"
        package_hash = f"{archive_index + 1:064x}"
        for game_index in range(GAMES_PER_ARCHIVE):
            rows.append(
                {
                    "schema": "mci_transfer_prediction_row_v1",
                    "archive_id": f"archive-{archive_index:02d}",
                    "family_id": family,
                    "independent_family": True,
                    "registered_package_hash": package_hash,
                    "hosted_package_hash": package_hash,
                    "registration_at_utc": "2026-07-13T00:00:00Z",
                    "hosted_at_utc": f"2026-07-13T01:{game_index:02d}:00Z",
                    "game_id": f"game-{archive_index:02d}-{game_index:02d}",
                    "outcome": outcome,
                    "baseline_probability": baseline,
                    "mci_probability": mci,
                    "literal_valid_hosted_game": True,
                    "runtime_substituted": False,
                    "validation_substituted": False,
                }
            )
    return rows


def _evaluate(rows: list[dict[str, object]]) -> dict[str, object]:
    return evaluate_transfer(rows, epsilon=EPSILON, seed=17, resamples=MIN_RESAMPLES)


def test_positive_transfer_passes_with_archive_balanced_lift() -> None:
    result = _evaluate(_rows())

    assert result["fit_performed"] is False
    assert result["integrity_pass"] is True
    assert result["passed"] is True
    assert result["decision"] == "PASS"
    assert result["counts"] == {
        "archives": 30,
        "families": 15,
        "games": 30 * 48,
        "games_per_archive": 48,
    }
    assert result["metrics"]["archive_balanced_log_loss_lift"] > 0.010  # type: ignore[index]
    assert result["bootstrap"]["lower_bound_2_5_percent"] > 0.0  # type: ignore[index]
    assert result["bootstrap"]["one_sided_p_value"] == 1 / (MIN_RESAMPLES + 1)  # type: ignore[index]


def test_negative_and_null_predictions_fail_closed() -> None:
    negative = _evaluate(_rows(baseline=0.85, mci=0.55))
    null = _evaluate(_rows(baseline=0.70, mci=0.70))

    assert negative["passed"] is False
    assert "archive_balanced_log_loss_lift_below_0.010" in negative["reasons"]  # type: ignore[operator]
    assert null["passed"] is False
    assert "bootstrap_2.5_percent_lower_bound_not_strictly_positive" in null["reasons"]  # type: ignore[operator]
    assert null["bootstrap"]["one_sided_p_value"] == 1.0  # type: ignore[index]


def test_family_cluster_bootstrap_preserves_correlated_archive_groups() -> None:
    rows = _rows()
    # All archives in a family share the same direction.  A family bootstrap
    # must retain those pairs rather than pretending the 30 archives are IID.
    for row in rows:
        if row["family_id"] in {"family-00", "family-01", "family-02", "family-03", "family-04", "family-05", "family-06"}:
            row["baseline_probability"] = 0.85
            row["mci_probability"] = 0.55
    result = _evaluate(rows)

    assert result["metrics"]["archive_balanced_log_loss_lift"] > 0.010  # type: ignore[index]
    assert result["bootstrap"]["lower_bound_2_5_percent"] < 0.0  # type: ignore[index]
    assert result["passed"] is False


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda rows: rows.pop(), "exactly 48 valid literal games"),
        (lambda rows: rows[1].__setitem__("game_id", rows[0]["game_id"]), "duplicate game_id"),
        (lambda rows: rows[0].__setitem__("registered_package_hash", "f" * 64), "package hash differs"),
        (lambda rows: rows[0].__setitem__("hosted_at_utc", "2026-07-13T00:00:00Z"), "registration must be before"),
        (lambda rows: rows[0].__setitem__("runtime_substituted", True), "runtime substitution"),
        (lambda rows: rows[0].__setitem__("validation_substituted", True), "validation substitution"),
        (lambda rows: rows[0].__setitem__("literal_valid_hosted_game", False), "literal valid hosted game"),
    ],
)
def test_integrity_vetoes_fail_closed(mutate: object, message: str) -> None:
    rows = _rows()
    mutate(rows)  # type: ignore[operator]
    result = _evaluate(rows)

    assert result["integrity_pass"] is False
    assert result["passed"] is False
    assert any(message in reason for reason in result["reasons"])  # type: ignore[union-attr]


def test_population_minimums_are_explicit_integrity_vetoes() -> None:
    result = _evaluate(_rows(archives=29, families=14))

    assert result["integrity_pass"] is False
    assert set(result["reasons"]) >= {  # type: ignore[arg-type]
        "eligible_archive_count_below_30",
        "independent_family_count_below_15",
    }
    assert result["metrics"]["archive_balanced_log_loss_lift"] is None  # type: ignore[index]
    assert result["per_archive"] == []


def test_one_family_cannot_dominate_the_archive_balanced_panel() -> None:
    rows = _rows()
    for row in rows:
        if row["archive_id"] == "archive-29":
            row["family_id"] = "family-00"
    result = _evaluate(rows)

    assert result["integrity_pass"] is False
    assert "family_archive_count_above_2" in result["reasons"]  # type: ignore[operator]
    assert result["metrics"]["archive_balanced_log_loss_lift"] is None  # type: ignore[index]


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("baseline_probability", 0.001, "probabilities are not clipped"),
        ("mci_probability", 0.999, "probabilities are not clipped"),
        ("baseline_probability", math.nan, "must be finite"),
    ],
)
def test_probabilities_are_strictly_checked_not_clipped(
    field: str, value: float, message: str
) -> None:
    rows = _rows()
    rows[0][field] = value
    result = _evaluate(rows)

    assert result["passed"] is False
    assert message in result["reasons"][0]  # type: ignore[index]


def test_determinism_input_order_invariance_and_no_input_mutation() -> None:
    rows = _rows()
    before = deepcopy(rows)
    first = _evaluate(rows)
    second = _evaluate(list(reversed(rows)))

    assert rows == before
    assert first == second


def test_direct_validation_rejects_bad_epsilon_and_is_order_independent() -> None:
    rows = _rows()
    assert validate_prediction_rows(rows, epsilon=EPSILON) == validate_prediction_rows(
        list(reversed(rows)), epsilon=EPSILON
    )
    with pytest.raises(TransferValidationError, match="epsilon"):
        validate_prediction_rows(rows, epsilon=0.0)


def test_too_few_resamples_are_rejected_at_argument_validation() -> None:
    with pytest.raises(TransferValidationError, match="at least"):
        evaluate_transfer(
            _rows(), epsilon=EPSILON, seed=17, resamples=MIN_RESAMPLES - 1
        )
