"""Retired abstract-lift statistic retained for research reproducibility.

This module is not the load-bearing G11 selector.  The prospective hosted
time-split claim is implemented by :mod:`evaluation_v5_1.prospective_transfer`.
This legacy module has no keys, holdout access, candidate API, or submission
authority and must never be added to the production exact-verifier allowlist.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation, localcontext
import math
import re
from typing import Any

from .canonical import canonical_sha256


INPUT_SCHEMA = "evaluation_v5_1_family_outcome_v2"
RESULT_SCHEMA = "evaluation_v5_1_statistics_result_v2"
FAMILY_COUNT = 20
ARCHIVES_PER_FAMILY = 1
ACTIVATION_BLOCK_COUNT = 4
FAMILIES_PER_BLOCK = 5
REQUIRED_SUCCESS_COUNT = 15
MINIMUM_FAMILY_LIFT = Decimal("0.010000000000")
MINIMUM_MEAN_LIFT = Decimal("0.010000000000")
CATASTROPHIC_FAMILY_LIFT = Decimal("-0.050000000000")
MAX_CATASTROPHIC_FAMILIES = 1
P_VALUE_ALPHA = Decimal("0.025000000000")
NULL_SUCCESS_PROBABILITY = Decimal("0.500000000000")

_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{12}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ROW_FIELDS = frozenset(
    {"archive_sha256", "family_id", "activation_block", "lift", "unresolved_rows"}
)


class StatisticsValidationError(ValueError):
    """The supplied family panel violates the frozen v5.1 design."""


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise StatisticsValidationError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise StatisticsValidationError(f"{label} must be lowercase SHA-256 hex")
    return value


def _decimal12(value: object, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise StatisticsValidationError(f"{label} must be a canonical 12-decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise StatisticsValidationError(f"{label} is not a finite decimal") from exc
    if not parsed.is_finite() or format(parsed, ".12f") != value:
        raise StatisticsValidationError(f"{label} must be a canonical finite 12-decimal string")
    return parsed


def validate_family_results(value: object) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        if set(value) != {"schema", "families"} or value.get("schema") != INPUT_SCHEMA:
            raise StatisticsValidationError("input must use the frozen family outcome schema")
        value = value["families"]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise StatisticsValidationError("families must be an ordered list")

    rows: list[dict[str, Any]] = []
    archive_ids: set[str] = set()
    family_ids: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, Mapping) or set(raw) != _ROW_FIELDS:
            raise StatisticsValidationError(
                f"family row {index} fields must exactly be {sorted(_ROW_FIELDS)}"
            )
        archive_id = _sha256(raw["archive_sha256"], f"family row {index} archive_sha256")
        family_id = _identifier(raw["family_id"], f"family row {index} family_id")
        if archive_id in archive_ids:
            raise StatisticsValidationError(f"duplicate archive_sha256 {archive_id!r}")
        if family_id in family_ids:
            raise StatisticsValidationError(f"family {family_id!r} has more than one archive")
        block = raw["activation_block"]
        if type(block) is not int or not 0 <= block < ACTIVATION_BLOCK_COUNT:
            raise StatisticsValidationError(
                f"family row {index} activation_block must be an integer in [0, 3]"
            )
        unresolved = raw["unresolved_rows"]
        if type(unresolved) is not int or unresolved < 0:
            raise StatisticsValidationError(
                f"family row {index} unresolved_rows must be a non-negative integer"
            )
        rows.append(
            {
                "archive_sha256": archive_id,
                "family_id": family_id,
                "activation_block": block,
                "lift": format(_decimal12(raw["lift"], f"family row {index} lift"), ".12f"),
                "unresolved_rows": unresolved,
            }
        )
        archive_ids.add(archive_id)
        family_ids.add(family_id)
    return sorted(rows, key=lambda row: row["family_id"])


def exact_binomial_upper_tail_numerator(trials: int, successes: int) -> int:
    if type(trials) is not int or type(successes) is not int:
        raise ValueError("trials and successes must be integers")
    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("successes must be in [0, trials] and trials must be positive")
    return sum(math.comb(trials, k) for k in range(successes, trials + 1))


def _failed(reason: str, rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    result = {
        "schema": RESULT_SCHEMA,
        "input_schema": INPUT_SCHEMA,
        "authority": False,
        "authority_level": 0,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "legacy_selector_retired": True,
        "holdout_accessed": False,
        "integrity_pass": False,
        "primary_exact_pass": False,
        "conjunctive_pass": False,
        "passed": False,
        "decision": "FAIL_CLOSED",
        "reasons": [reason],
        "counts": {
            "families": len(rows or []),
            "successes": None,
            "catastrophic_families": None,
            "unresolved_rows": None,
        },
        "metrics": {
            "family_weighted_mean_lift": None,
            "activation_block_means": None,
            "exact_p_value": None,
        },
        "families": rows or [],
    }
    result["content_sha256"] = canonical_sha256(result)
    return result


def evaluate_primary_gate(family_results: object) -> dict[str, Any]:
    """Evaluate the frozen 20-family claim with permanent zero authority."""

    try:
        rows = validate_family_results(family_results)
    except StatisticsValidationError as exc:
        return _failed(str(exc))

    reasons: list[str] = []
    if len(rows) != FAMILY_COUNT:
        reasons.append("family_count_must_equal_20")

    block_counts = Counter(row["activation_block"] for row in rows)
    if any(block_counts.get(block, 0) != FAMILIES_PER_BLOCK for block in range(ACTIVATION_BLOCK_COUNT)):
        reasons.append("activation_blocks_must_each_contain_5_families")

    decimals = [Decimal(row["lift"]) for row in rows]
    success_count = sum(value >= MINIMUM_FAMILY_LIFT for value in decimals)
    catastrophic_count = sum(value < CATASTROPHIC_FAMILY_LIFT for value in decimals)
    unresolved_count = sum(row["unresolved_rows"] for row in rows)

    numerator = exact_binomial_upper_tail_numerator(len(rows), success_count) if rows else 0
    denominator = 1 << len(rows) if rows else 1
    with localcontext() as context:
        context.prec = 50
        p_value = Decimal(numerator) / Decimal(denominator)
        mean_lift = sum(decimals, Decimal(0)) / Decimal(len(decimals)) if decimals else Decimal(0)
        block_means = []
        for block in range(ACTIVATION_BLOCK_COUNT):
            values = [Decimal(row["lift"]) for row in rows if row["activation_block"] == block]
            block_means.append(sum(values, Decimal(0)) / Decimal(len(values)) if values else Decimal(0))

    primary_exact_pass = (
        len(rows) == FAMILY_COUNT
        and success_count >= REQUIRED_SUCCESS_COUNT
        and p_value <= P_VALUE_ALPHA
    )
    if not primary_exact_pass:
        reasons.append("minimum_lift_exact_binomial_claim_failed")
    if mean_lift < MINIMUM_MEAN_LIFT:
        reasons.append("family_weighted_mean_lift_below_0.010")
    if any(value < 0 for value in block_means):
        reasons.append("activation_block_mean_negative")
    if catastrophic_count > MAX_CATASTROPHIC_FAMILIES:
        reasons.append("more_than_one_catastrophic_family")
    if unresolved_count != 0:
        reasons.append("unresolved_outcome_rows_nonzero")

    integrity_reasons = {
        "family_count_must_equal_20",
        "activation_blocks_must_each_contain_5_families",
    }
    integrity_pass = not any(reason in integrity_reasons for reason in reasons)
    conjunctive_pass = (
        mean_lift >= MINIMUM_MEAN_LIFT
        and all(value >= 0 for value in block_means)
        and catastrophic_count <= MAX_CATASTROPHIC_FAMILIES
        and unresolved_count == 0
    )
    passed = integrity_pass and primary_exact_pass and conjunctive_pass

    normalized_rows = []
    for row in rows:
        value = Decimal(row["lift"])
        normalized_rows.append(
            {
                **row,
                "success": value >= MINIMUM_FAMILY_LIFT,
                "catastrophic": value < CATASTROPHIC_FAMILY_LIFT,
            }
        )
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "input_schema": INPUT_SCHEMA,
        "authority": False,
        "authority_level": 0,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "legacy_selector_retired": True,
        "holdout_accessed": False,
        "integrity_pass": integrity_pass,
        "primary_exact_pass": primary_exact_pass,
        "conjunctive_pass": conjunctive_pass,
        "passed": passed,
        "decision": "PASS_LEGACY_RESEARCH_ONLY" if passed else "FAIL_CLOSED",
        "reasons": reasons,
        "counts": {
            "families": len(rows),
            "successes": success_count,
            "catastrophic_families": catastrophic_count,
            "unresolved_rows": unresolved_count,
        },
        "metrics": {
            "family_weighted_mean_lift": format(mean_lift, ".12f"),
            "activation_block_means": [format(value, ".12f") for value in block_means],
            "exact_p_value": format(p_value, ".12f"),
        },
        "exact_test": {
            "method": "exact_one_sided_binomial",
            "null": "P(D_f >= 0.010000000000) <= 0.5",
            "required_successes": REQUIRED_SUCCESS_COUNT,
            "p_value_numerator": numerator,
            "p_value_denominator": denominator,
            "alpha": format(P_VALUE_ALPHA, ".12f"),
        },
        "protocol": {
            "family_count": FAMILY_COUNT,
            "archives_per_family": ARCHIVES_PER_FAMILY,
            "activation_blocks": ACTIVATION_BLOCK_COUNT,
            "families_per_block": FAMILIES_PER_BLOCK,
            "minimum_family_lift": format(MINIMUM_FAMILY_LIFT, ".12f"),
            "minimum_mean_lift": format(MINIMUM_MEAN_LIFT, ".12f"),
            "catastrophic_family_lift": format(CATASTROPHIC_FAMILY_LIFT, ".12f"),
            "max_catastrophic_families": MAX_CATASTROPHIC_FAMILIES,
            "bootstrap": False,
            "submission_authority": False,
        },
        "families": normalized_rows,
    }
    result["content_sha256"] = canonical_sha256(result)
    return result


evaluate_exact_statistical_primary_gate = evaluate_primary_gate
evaluate_v5_1_statistics = evaluate_primary_gate
evaluate_statistics = evaluate_primary_gate


__all__ = [
    "ACTIVATION_BLOCK_COUNT",
    "ARCHIVES_PER_FAMILY",
    "CATASTROPHIC_FAMILY_LIFT",
    "FAMILIES_PER_BLOCK",
    "FAMILY_COUNT",
    "INPUT_SCHEMA",
    "MAX_CATASTROPHIC_FAMILIES",
    "MINIMUM_FAMILY_LIFT",
    "MINIMUM_MEAN_LIFT",
    "P_VALUE_ALPHA",
    "REQUIRED_SUCCESS_COUNT",
    "RESULT_SCHEMA",
    "StatisticsValidationError",
    "evaluate_exact_statistical_primary_gate",
    "evaluate_primary_gate",
    "evaluate_statistics",
    "evaluate_v5_1_statistics",
    "exact_binomial_upper_tail_numerator",
    "validate_family_results",
]
