"""Deterministic evaluator for the frozen MCI v5 transfer claim.

This module consumes already-materialized, pre-registered per-game predictions.
It intentionally has no fitting, recalibration, file access, or outcome
selection path: malformed or incomplete evidence is a closed gate.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
import math
from numbers import Integral, Real
import random
from typing import Any


INPUT_SCHEMA = "mci_transfer_prediction_row_v1"
RESULT_SCHEMA = "mci_transfer_validation_result_v1"
MIN_ARCHIVES = 30
MIN_FAMILIES = 15
MAX_ARCHIVES_PER_FAMILY = 2
GAMES_PER_ARCHIVE = 48
LIFT_THRESHOLD = 0.010
P_VALUE_THRESHOLD = 0.025
MIN_RESAMPLES = 999

ROW_FIELDS = frozenset(
    {
        "schema",
        "archive_id",
        "family_id",
        "independent_family",
        "registered_package_hash",
        "hosted_package_hash",
        "registration_at_utc",
        "hosted_at_utc",
        "game_id",
        "outcome",
        "baseline_probability",
        "mci_probability",
        "literal_valid_hosted_game",
        "runtime_substituted",
        "validation_substituted",
    }
)


class TransferValidationError(ValueError):
    """The supplied frozen confirmatory rows violate the v5 contract."""


def validate_prediction_rows(
    rows: Iterable[Mapping[str, Any]], *, epsilon: float
) -> list[dict[str, Any]]:
    """Validate frozen prediction rows and return a canonical copy.

    The function deliberately does not estimate any parameter.  ``epsilon`` is
    a required caller-controlled part of the frozen input contract; values are
    checked rather than clipped.
    """
    epsilon = _epsilon(epsilon)
    if isinstance(rows, (str, bytes)):
        raise TransferValidationError("rows must be an iterable of mappings")
    try:
        source_rows = list(rows)
    except TypeError as exc:
        raise TransferValidationError("rows must be an iterable of mappings") from exc
    if not source_rows:
        raise TransferValidationError("rows must not be empty")

    normalized: list[dict[str, Any]] = []
    seen_game_ids: set[str] = set()
    archives: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(source_rows):
        row = _normalize_row(raw, index=index, epsilon=epsilon)
        game_id = row["game_id"]
        if game_id in seen_game_ids:
            raise TransferValidationError(f"duplicate game_id {game_id!r}")
        seen_game_ids.add(game_id)
        normalized.append(row)
        archives.setdefault(row["archive_id"], []).append(row)

    for archive_id, archive_rows in archives.items():
        if len(archive_rows) != GAMES_PER_ARCHIVE:
            raise TransferValidationError(
                f"archive {archive_id!r} must contain exactly {GAMES_PER_ARCHIVE} valid literal games"
            )
        _check_archive_binding(archive_id, archive_rows)

    return sorted(normalized, key=lambda row: (row["family_id"], row["archive_id"], row["game_id"]))


def evaluate_transfer(
    rows: Iterable[Mapping[str, Any]], *, epsilon: float, seed: int, resamples: int
) -> dict[str, Any]:
    """Evaluate the preregistered v5 transfer rule and fail closed on vetoes.

    Families are resampled with replacement.  Each selected family contributes
    every one of its archives and every archive contributes its 48 literal
    games through its already-computed archive mean.  Zero-valued bootstrap
    draws count as non-positive for the one-sided p-value.
    """
    epsilon = _epsilon(epsilon)
    seed = _seed(seed)
    resamples = _resamples(resamples)
    try:
        normalized = validate_prediction_rows(rows, epsilon=epsilon)
    except TransferValidationError as exc:
        return _closed_integrity_result(
            reasons=[str(exc)], epsilon=epsilon, seed=seed, resamples=resamples
        )

    by_archive: dict[str, list[dict[str, Any]]] = {}
    for row in normalized:
        by_archive.setdefault(row["archive_id"], []).append(row)
    family_archive_counts: dict[str, int] = {}
    for archive_rows in by_archive.values():
        family = archive_rows[0]["family_id"]
        family_archive_counts[family] = family_archive_counts.get(family, 0) + 1
    integrity_reasons: list[str] = []
    if len(by_archive) < MIN_ARCHIVES:
        integrity_reasons.append("eligible_archive_count_below_30")
    if len(family_archive_counts) < MIN_FAMILIES:
        integrity_reasons.append("independent_family_count_below_15")
    if max(family_archive_counts.values(), default=0) > MAX_ARCHIVES_PER_FAMILY:
        integrity_reasons.append("family_archive_count_above_2")
    if integrity_reasons:
        return _closed_integrity_result(
            reasons=integrity_reasons,
            epsilon=epsilon,
            seed=seed,
            resamples=resamples,
            counts={
                "archives": len(by_archive),
                "families": len(family_archive_counts),
                "games": len(normalized),
                "games_per_archive": GAMES_PER_ARCHIVE,
            },
        )
    archive_metrics = [_archive_metrics(archive_id, archive_rows) for archive_id, archive_rows in sorted(by_archive.items())]
    by_family: dict[str, list[dict[str, float | str]]] = {}
    for archive in archive_metrics:
        by_family.setdefault(str(archive["family_id"]), []).append(archive)

    point_lift = _mean(float(item["log_loss_lift"]) for item in archive_metrics)
    baseline_loss = _mean(float(item["baseline_log_loss"]) for item in archive_metrics)
    mci_loss = _mean(float(item["mci_log_loss"]) for item in archive_metrics)
    bootstrap_draws = _family_cluster_bootstrap(by_family, seed=seed, resamples=resamples)
    lower_bound = _quantile(bootstrap_draws, 0.025)
    nonpositive_draws = sum(draw <= 0.0 for draw in bootstrap_draws)
    # The plus-one correction makes the empirical tail conservative and keeps
    # a finite bootstrap p-value strictly above zero.
    one_sided_p_value = (nonpositive_draws + 1) / (resamples + 1)

    reasons: list[str] = []
    integrity_reasons = _population_integrity_reasons(by_family, archive_metrics)
    reasons.extend(integrity_reasons)
    if point_lift < LIFT_THRESHOLD:
        reasons.append("archive_balanced_log_loss_lift_below_0.010")
    if lower_bound <= 0.0:
        reasons.append("bootstrap_2.5_percent_lower_bound_not_strictly_positive")
    if one_sided_p_value > P_VALUE_THRESHOLD:
        reasons.append("one_sided_family_cluster_bootstrap_p_value_above_0.025")

    integrity_pass = not integrity_reasons
    passed = not reasons
    return {
        "schema": RESULT_SCHEMA,
        "authority": False,
        "submission_authorized": False,
        "sealed_holdout_access": False,
        "fit_performed": False,
        "integrity_pass": integrity_pass,
        "passed": passed,
        "decision": "PASS" if passed else "FAIL_CLOSED",
        "reasons": reasons,
        "counts": {
            "archives": len(archive_metrics),
            "families": len(by_family),
            "games": len(normalized),
            "games_per_archive": GAMES_PER_ARCHIVE,
        },
        "metrics": {
            "archive_balanced_baseline_log_loss": baseline_loss,
            "archive_balanced_mci_log_loss": mci_loss,
            "archive_balanced_log_loss_lift": point_lift,
        },
        "bootstrap": {
            "method": "one_sided_family_cluster_resampling_with_replacement",
            "seed": seed,
            "resamples": resamples,
            "lower_bound_quantile": 0.025,
            "lower_bound_2_5_percent": lower_bound,
            "one_sided_p_value": one_sided_p_value,
            "nonpositive_draws": nonpositive_draws,
            "tie_behavior": "draws_equal_to_zero_count_as_nonpositive",
        },
        "input_contract": {
            "schema": INPUT_SCHEMA,
            "epsilon": epsilon,
            "probability_rule": "epsilon < probability < 1-epsilon; values are never clipped",
        },
        "per_archive": archive_metrics,
    }


# A descriptive alias keeps integrations readable without creating a second
# implementation or a differently behaving validation route.
evaluate_transfer_validation = evaluate_transfer


def _normalize_row(raw: object, *, index: int, epsilon: float) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != ROW_FIELDS:
        actual = sorted(raw) if isinstance(raw, Mapping) else type(raw).__name__
        raise TransferValidationError(
            f"row {index} fields must exactly be {sorted(ROW_FIELDS)}; got {actual}"
        )
    if raw["schema"] != INPUT_SCHEMA:
        raise TransferValidationError(f"row {index} schema must be {INPUT_SCHEMA!r}")
    row = {
        "archive_id": _identifier(raw["archive_id"], label=f"row {index} archive_id"),
        "family_id": _identifier(raw["family_id"], label=f"row {index} family_id"),
        "registered_package_hash": _hash(raw["registered_package_hash"], label=f"row {index} registered_package_hash"),
        "hosted_package_hash": _hash(raw["hosted_package_hash"], label=f"row {index} hosted_package_hash"),
        "registration_at": _timestamp(raw["registration_at_utc"], label=f"row {index} registration_at_utc"),
        "hosted_at": _timestamp(raw["hosted_at_utc"], label=f"row {index} hosted_at_utc"),
        "game_id": _identifier(raw["game_id"], label=f"row {index} game_id"),
        "outcome": _outcome(raw["outcome"], label=f"row {index} outcome"),
        "baseline_probability": _probability(raw["baseline_probability"], label=f"row {index} baseline_probability", epsilon=epsilon),
        "mci_probability": _probability(raw["mci_probability"], label=f"row {index} mci_probability", epsilon=epsilon),
    }
    if raw["independent_family"] is not True:
        raise TransferValidationError(f"row {index} independent_family must be true")
    if raw["literal_valid_hosted_game"] is not True:
        raise TransferValidationError(f"row {index} must be a literal valid hosted game")
    if raw["runtime_substituted"] is not False:
        raise TransferValidationError(f"row {index} has a runtime substitution")
    if raw["validation_substituted"] is not False:
        raise TransferValidationError(f"row {index} has a validation substitution")
    if row["registered_package_hash"] != row["hosted_package_hash"]:
        raise TransferValidationError(f"row {index} package hash differs from its registration")
    return row


def _check_archive_binding(archive_id: str, rows: list[dict[str, Any]]) -> None:
    fields = ("family_id", "registered_package_hash", "hosted_package_hash", "registration_at")
    for field in fields:
        values = {row[field] for row in rows}
        if len(values) != 1:
            raise TransferValidationError(f"archive {archive_id!r} has mixed {field}")
    registration_at = rows[0]["registration_at"]
    first_hosted_game = min(row["hosted_at"] for row in rows)
    if registration_at >= first_hosted_game:
        raise TransferValidationError(
            f"archive {archive_id!r} registration must be before its first hosted game"
        )


def _archive_metrics(archive_id: str, rows: list[dict[str, Any]]) -> dict[str, float | str]:
    baseline_loss = _mean(
        _log_loss(row["baseline_probability"], row["outcome"]) for row in rows
    )
    mci_loss = _mean(_log_loss(row["mci_probability"], row["outcome"]) for row in rows)
    return {
        "archive_id": archive_id,
        "family_id": rows[0]["family_id"],
        "baseline_log_loss": baseline_loss,
        "mci_log_loss": mci_loss,
        "log_loss_lift": baseline_loss - mci_loss,
    }


def _family_cluster_bootstrap(
    by_family: Mapping[str, list[dict[str, float | str]]], *, seed: int, resamples: int
) -> list[float]:
    families = sorted(by_family)
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(resamples):
        sampled_archives: list[dict[str, float | str]] = []
        for _ in families:
            sampled_archives.extend(by_family[families[rng.randrange(len(families))]])
        draws.append(_mean(float(archive["log_loss_lift"]) for archive in sampled_archives))
    return draws


def _population_integrity_reasons(
    by_family: Mapping[str, list[dict[str, float | str]]], archive_metrics: list[dict[str, float | str]]
) -> list[str]:
    reasons: list[str] = []
    if len(archive_metrics) < MIN_ARCHIVES:
        reasons.append("eligible_archive_count_below_30")
    if len(by_family) < MIN_FAMILIES:
        reasons.append("independent_family_count_below_15")
    return reasons


def _closed_integrity_result(
    *,
    reasons: list[str],
    epsilon: float,
    seed: int,
    resamples: int,
    counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "authority": False,
        "submission_authorized": False,
        "sealed_holdout_access": False,
        "fit_performed": False,
        "integrity_pass": False,
        "passed": False,
        "decision": "FAIL_CLOSED",
        "reasons": reasons,
        "counts": counts
        or {"archives": 0, "families": 0, "games": 0, "games_per_archive": GAMES_PER_ARCHIVE},
        "metrics": {
            "archive_balanced_baseline_log_loss": None,
            "archive_balanced_mci_log_loss": None,
            "archive_balanced_log_loss_lift": None,
        },
        "bootstrap": {
            "method": "one_sided_family_cluster_resampling_with_replacement",
            "seed": seed,
            "resamples": resamples,
            "lower_bound_quantile": 0.025,
            "lower_bound_2_5_percent": None,
            "one_sided_p_value": None,
            "nonpositive_draws": None,
            "tie_behavior": "draws_equal_to_zero_count_as_nonpositive",
        },
        "input_contract": {
            "schema": INPUT_SCHEMA,
            "epsilon": epsilon,
            "probability_rule": "epsilon < probability < 1-epsilon; values are never clipped",
        },
        "per_archive": [],
    }


def _epsilon(value: object) -> float:
    epsilon = _finite_real(value, label="epsilon")
    if not 0.0 < epsilon < 0.5:
        raise TransferValidationError("epsilon must be strictly between 0 and 0.5")
    return epsilon


def _seed(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise TransferValidationError("seed must be an integer")
    return int(value)


def _resamples(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral) or value < MIN_RESAMPLES:
        raise TransferValidationError(
            f"resamples must be an integer of at least {MIN_RESAMPLES}"
        )
    return int(value)


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise TransferValidationError(f"{label} must be a non-empty trimmed string")
    return value


def _hash(value: object, *, label: str) -> str:
    text = _identifier(value, label=label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise TransferValidationError(f"{label} must be a lowercase SHA-256")
    return text


def _timestamp(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TransferValidationError(f"{label} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransferValidationError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise TransferValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _finite_real(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise TransferValidationError(f"{label} must be finite")
    return float(value)


def _probability(value: object, *, label: str, epsilon: float) -> float:
    probability = _finite_real(value, label=label)
    if not epsilon < probability < 1.0 - epsilon:
        raise TransferValidationError(
            f"{label} must be strictly between epsilon and 1-epsilon; probabilities are not clipped"
        )
    return probability


def _outcome(value: object, *, label: str) -> float:
    outcome = _finite_real(value, label=label)
    if outcome not in (0.0, 1.0):
        raise TransferValidationError(f"{label} must be 0 or 1")
    return outcome


def _log_loss(probability: float, outcome: float) -> float:
    return -(outcome * math.log(probability) + (1.0 - outcome) * math.log1p(-probability))


def _mean(values: Iterable[float]) -> float:
    materialized = list(values)
    if not materialized:
        raise TransferValidationError("cannot average an empty population")
    return math.fsum(materialized) / len(materialized)


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
