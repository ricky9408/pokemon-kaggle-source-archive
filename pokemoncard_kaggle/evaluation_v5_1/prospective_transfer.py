"""Frozen prospective selector validation for evaluator v5.1.

This module encodes the load-bearing scientific claim from the Sol review. Its
local calculator is explicitly synthetic and authority-free. The production-
shaped entry point cannot validate a selector until independently pinned
registry, collector, and disclosure services exist; neither path can authorize
candidate development, holdout access, or a Kaggle submission.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
import re
from typing import Any

from .canonical import canonical_sha256


INPUT_SCHEMA = "evaluation_v5_1_prospective_transfer_input_v1"
RESULT_SCHEMA = "evaluation_v5_1_prospective_transfer_result_v1"
DISCLOSURE_SCHEMA = "evaluation_v5_1_prospective_transfer_disclosure_v1"

FAMILY_COUNT = 20
LOCAL_EPISODES_PER_ARCHIVE = 10_000
OPPONENT_BIN_COUNT = 4
SEAT_COUNT = 2
STRATUM_COUNT = OPPONENT_BIN_COUNT * SEAT_COUNT
GAMES_PER_STRATUM = 25
GAMES_PER_FAMILY = STRATUM_COUNT * GAMES_PER_STRATUM
MIN_DISTINCT_OPPONENTS = 10
MAX_GAMES_PER_OPPONENT = 20
REQUIRED_ERROR_IMPROVEMENTS = 15
MAX_MEAN_ERROR_RATIO = Decimal("0.800000000000")
MIN_SPEARMAN = Decimal("0.500000000000")
MAX_TOP_ARCHIVE_HOSTED_RANK = 5

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(?:0|1)\.[0-9]{12}$")
_INPUT_FIELDS = frozenset(
    {
        "schema",
        "campaign_id",
        "freeze",
        "lineages",
        "games",
        "collection_closed_at_ns",
    }
)
_FREEZE_FIELDS = frozenset(
    {
        "campaign_root_sha256",
        "selector_sha256",
        "baseline_sha256",
        "ancestry_graph_sha256",
        "cohort_sha256",
        "source_engine_sha256",
        "local_schedule_sha256",
        "feature_extractor_sha256",
        "eligibility_spec_sha256",
        "statistics_spec_sha256",
        "collector_pair_sha256",
        "disclosure_recipient_key_sha256",
        "t0_ns",
        "t1_ns",
        "opponent_score_quartiles_milli",
    }
)
_LINEAGE_FIELDS = frozenset(
    {
        "family_id",
        "ancestry_component_id",
        "archive_sha256",
        "runnable_receipt_sha256",
        "selector_prediction",
        "baseline_prediction",
        "local_episode_count",
    }
)
_GAME_FIELDS = frozenset(
    {
        "game_id",
        "archive_sha256",
        "opponent_archive_sha256",
        "opponent_component_id",
        "seat",
        "outcome",
        "pre_game_opponent_score_milli",
        "server_start_time_ns",
        "server_end_time_ns",
        "source_row_sha256",
        "collector_agreement",
    }
)

# Production verification may use only independently pinned, hermetic services.
# Caller-provided callbacks or identities are never accepted. The registry is
# intentionally empty until G00/G05/G10 custody exists outside this process.
PINNED_PROSPECTIVE_SERVICE_IDENTITIES: Mapping[str, str] = {}


class ProspectiveTransferValidationError(ValueError):
    """The supplied evidence violates the frozen prospective protocol."""


def _exact_mapping(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProspectiveTransferValidationError(f"{label} fields are not exact")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise ProspectiveTransferValidationError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ProspectiveTransferValidationError(f"{label} must be lowercase SHA-256 hex")
    return value


def _probability(value: object, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise ProspectiveTransferValidationError(
            f"{label} must be a canonical probability with 12 decimals"
        )
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ProspectiveTransferValidationError(f"{label} is not finite") from exc
    if not parsed.is_finite() or parsed < 0 or parsed > 1:
        raise ProspectiveTransferValidationError(f"{label} must be in [0, 1]")
    return parsed


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ProspectiveTransferValidationError(f"{label} must be an integer >= {minimum}")
    return value


def _format_decimal(value: Decimal) -> str:
    return format(value, ".12f")


def _average_ranks(values: Sequence[Decimal]) -> list[Fraction]:
    order = sorted(range(len(values)), key=lambda index: (values[index], index))
    ranks: list[Fraction] = [Fraction(0)] * len(values)
    start = 0
    while start < len(order):
        end = start + 1
        while end < len(order) and values[order[end]] == values[order[start]]:
            end += 1
        average = Fraction((start + 1) + end, 2)
        for position in range(start, end):
            ranks[order[position]] = average
        start = end
    return ranks


def _spearman(values_a: Sequence[Decimal], values_b: Sequence[Decimal]) -> Decimal | None:
    ranks_a = _average_ranks(values_a)
    ranks_b = _average_ranks(values_b)
    mean = Fraction(len(values_a) + 1, 2)
    numerator = sum((a - mean) * (b - mean) for a, b in zip(ranks_a, ranks_b))
    sum_sq_a = sum((value - mean) ** 2 for value in ranks_a)
    sum_sq_b = sum((value - mean) ** 2 for value in ranks_b)
    if sum_sq_a == 0 or sum_sq_b == 0:
        return None
    with localcontext() as context:
        context.prec = 60
        numerator_decimal = Decimal(numerator.numerator) / Decimal(numerator.denominator)
        denominator_squared = (
            Decimal(sum_sq_a.numerator)
            / Decimal(sum_sq_a.denominator)
            * Decimal(sum_sq_b.numerator)
            / Decimal(sum_sq_b.denominator)
        )
        return numerator_decimal / denominator_squared.sqrt()


def _failed(reason: str, *, evidence_sha256: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "authority": False,
        "authority_level": 0,
        "candidate_development_authorized": False,
        "holdout_accessed": False,
        "holdout_access_authorized": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "passed": False,
        "synthetic_conformance_passed": False,
        "decision": "FAIL_CLOSED",
        "reasons": [reason],
        "evidence_sha256": evidence_sha256,
        "counts": {
            "families": None,
            "selected_games": None,
            "error_improvements": None,
        },
        "metrics": {
            "selector_mean_absolute_error": None,
            "baseline_mean_absolute_error": None,
            "mean_absolute_error_ratio": None,
            "selector_hosted_spearman": None,
            "selector_top_archive_hosted_rank": None,
            "mean_hosted_conditional_binomial_se": None,
            "worst_case_hosted_conditional_binomial_se": "0.035355339059",
        },
    }
    result["content_sha256"] = canonical_sha256(result)
    return result


def _normalize_input(value: object) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    root = _exact_mapping(value, _INPUT_FIELDS, "prospective input")
    if root["schema"] != INPUT_SCHEMA:
        raise ProspectiveTransferValidationError("prospective input schema mismatch")
    campaign_id = _identifier(root["campaign_id"], "campaign_id")
    freeze = _exact_mapping(root["freeze"], _FREEZE_FIELDS, "freeze")
    normalized_freeze: dict[str, Any] = {}
    for field in sorted(_FREEZE_FIELDS - {"t0_ns", "t1_ns", "opponent_score_quartiles_milli"}):
        normalized_freeze[field] = _sha256(freeze[field], f"freeze.{field}")
    t0_ns = _integer(freeze["t0_ns"], "freeze.t0_ns", minimum=1)
    t1_ns = _integer(freeze["t1_ns"], "freeze.t1_ns", minimum=1)
    if t1_ns <= t0_ns:
        raise ProspectiveTransferValidationError("freeze.t1_ns must be after freeze.t0_ns")
    quartiles = freeze["opponent_score_quartiles_milli"]
    if (
        type(quartiles) is not list
        or len(quartiles) != 3
        or any(type(value) is not int or value < 0 for value in quartiles)
        or not quartiles[0] < quartiles[1] < quartiles[2]
    ):
        raise ProspectiveTransferValidationError(
            "freeze.opponent_score_quartiles_milli must be three increasing integers"
        )
    normalized_freeze.update(
        {
            "t0_ns": t0_ns,
            "t1_ns": t1_ns,
            "opponent_score_quartiles_milli": list(quartiles),
        }
    )
    collection_closed_at_ns = _integer(
        root["collection_closed_at_ns"], "collection_closed_at_ns", minimum=1
    )
    if collection_closed_at_ns < t1_ns:
        raise ProspectiveTransferValidationError("collection closed before frozen T1")

    raw_lineages = root["lineages"]
    if type(raw_lineages) is not list:
        raise ProspectiveTransferValidationError("lineages must be a list")
    lineages: list[dict[str, Any]] = []
    family_ids: set[str] = set()
    ancestry_ids: set[str] = set()
    archives: set[str] = set()
    for index, raw in enumerate(raw_lineages):
        row = _exact_mapping(raw, _LINEAGE_FIELDS, f"lineage[{index}]")
        family_id = _identifier(row["family_id"], f"lineage[{index}].family_id")
        ancestry_id = _identifier(
            row["ancestry_component_id"], f"lineage[{index}].ancestry_component_id"
        )
        archive = _sha256(row["archive_sha256"], f"lineage[{index}].archive_sha256")
        if family_id in family_ids:
            raise ProspectiveTransferValidationError("family IDs must be unique")
        if ancestry_id in ancestry_ids:
            raise ProspectiveTransferValidationError(
                "exactly one archive is allowed per ancestry-connected component"
            )
        if archive in archives:
            raise ProspectiveTransferValidationError("archive SHA-256 values must be unique")
        local_count = _integer(
            row["local_episode_count"], f"lineage[{index}].local_episode_count"
        )
        if local_count != LOCAL_EPISODES_PER_ARCHIVE:
            raise ProspectiveTransferValidationError(
                f"each archive must have exactly {LOCAL_EPISODES_PER_ARCHIVE} local episodes"
            )
        lineages.append(
            {
                "family_id": family_id,
                "ancestry_component_id": ancestry_id,
                "archive_sha256": archive,
                "runnable_receipt_sha256": _sha256(
                    row["runnable_receipt_sha256"],
                    f"lineage[{index}].runnable_receipt_sha256",
                ),
                "selector_prediction": _format_decimal(
                    _probability(
                        row["selector_prediction"],
                        f"lineage[{index}].selector_prediction",
                    )
                ),
                "baseline_prediction": _format_decimal(
                    _probability(
                        row["baseline_prediction"],
                        f"lineage[{index}].baseline_prediction",
                    )
                ),
                "local_episode_count": local_count,
            }
        )
        family_ids.add(family_id)
        ancestry_ids.add(ancestry_id)
        archives.add(archive)

    raw_games = root["games"]
    if type(raw_games) is not list:
        raise ProspectiveTransferValidationError("games must be a list")
    games: list[dict[str, Any]] = []
    game_ids: set[str] = set()
    source_row_hashes: set[str] = set()
    for index, raw in enumerate(raw_games):
        row = _exact_mapping(raw, _GAME_FIELDS, f"game[{index}]")
        game_id = _identifier(row["game_id"], f"game[{index}].game_id")
        if game_id in game_ids:
            raise ProspectiveTransferValidationError("game IDs must be globally unique")
        archive = _sha256(row["archive_sha256"], f"game[{index}].archive_sha256")
        opponent = _sha256(
            row["opponent_archive_sha256"], f"game[{index}].opponent_archive_sha256"
        )
        opponent_component = _identifier(
            row["opponent_component_id"], f"game[{index}].opponent_component_id"
        )
        if archive not in archives:
            raise ProspectiveTransferValidationError("game references an archive outside the cohort")
        if opponent in archives:
            raise ProspectiveTransferValidationError(
                "validation cohort archives may not oppose one another"
            )
        if opponent_component in ancestry_ids:
            raise ProspectiveTransferValidationError(
                "validation ancestry components may not oppose one another"
            )
        seat = row["seat"]
        outcome = row["outcome"]
        if type(seat) is not int or seat not in (0, 1):
            raise ProspectiveTransferValidationError("game seat must be 0 or 1")
        if type(outcome) is not int or outcome not in (0, 1):
            raise ProspectiveTransferValidationError("game outcome must be 0 or 1")
        score = _integer(
            row["pre_game_opponent_score_milli"],
            f"game[{index}].pre_game_opponent_score_milli",
        )
        start_ns = _integer(row["server_start_time_ns"], f"game[{index}].server_start_time_ns")
        end_ns = _integer(row["server_end_time_ns"], f"game[{index}].server_end_time_ns")
        if not t0_ns <= start_ns <= end_ns < t1_ns:
            raise ProspectiveTransferValidationError("game is outside the frozen [T0,T1) window")
        if row["collector_agreement"] is not True:
            raise ProspectiveTransferValidationError("dual collectors do not agree on a game")
        opponent_bin = sum(score >= boundary for boundary in quartiles)
        source_row_sha256 = _sha256(
            row["source_row_sha256"], f"game[{index}].source_row_sha256"
        )
        if source_row_sha256 in source_row_hashes:
            raise ProspectiveTransferValidationError(
                "source-row SHA-256 values must be globally unique"
            )
        games.append(
            {
                "game_id": game_id,
                "archive_sha256": archive,
                "opponent_archive_sha256": opponent,
                "opponent_component_id": opponent_component,
                "seat": seat,
                "outcome": outcome,
                "pre_game_opponent_score_milli": score,
                "opponent_bin": opponent_bin,
                "server_start_time_ns": start_ns,
                "server_end_time_ns": end_ns,
                "source_row_sha256": source_row_sha256,
                "collector_agreement": True,
            }
        )
        game_ids.add(game_id)
        source_row_hashes.add(source_row_sha256)

    normalized_root = {
        "schema": INPUT_SCHEMA,
        "campaign_id": campaign_id,
        "freeze": normalized_freeze,
        "lineages": sorted(lineages, key=lambda row: row["archive_sha256"]),
        "games": sorted(
            games,
            key=lambda row: (
                row["archive_sha256"],
                row["server_end_time_ns"],
                row["game_id"],
            ),
        ),
        "collection_closed_at_ns": collection_closed_at_ns,
    }
    return normalized_root, normalized_root["lineages"], normalized_root["games"]


def evaluate_synthetic_prospective_conformance(evidence: object) -> dict[str, Any]:
    """Exercise the frozen mathematics with explicitly synthetic evidence.

    This function can never emit a production validation decision. It exists
    solely for deterministic conformance and adversarial tests.
    """

    try:
        normalized, lineages, games = _normalize_input(evidence)
    except ProspectiveTransferValidationError as exc:
        return _failed(str(exc))

    evidence_sha256 = canonical_sha256(normalized)
    reasons: list[str] = []
    if len(lineages) != FAMILY_COUNT:
        reasons.append("family_count_must_equal_20")

    grouped: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for game in games:
        grouped[(game["archive_sha256"], game["opponent_bin"], game["seat"])].append(game)
    selected: list[dict[str, Any]] = []
    for lineage in lineages:
        archive = lineage["archive_sha256"]
        for opponent_bin in range(OPPONENT_BIN_COUNT):
            for seat in range(SEAT_COUNT):
                rows = sorted(
                    grouped[(archive, opponent_bin, seat)],
                    key=lambda row: (row["server_end_time_ns"], row["game_id"]),
                )
                if len(rows) < GAMES_PER_STRATUM:
                    reasons.append(
                        f"missing_25_games:{archive}:bin{opponent_bin}:seat{seat}"
                    )
                    continue
                selected.extend(rows[:GAMES_PER_STRATUM])

    selected_by_archive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for game in selected:
        selected_by_archive[game["archive_sha256"]].append(game)
    for lineage in lineages:
        archive = lineage["archive_sha256"]
        rows = selected_by_archive[archive]
        opponent_counts = Counter(row["opponent_component_id"] for row in rows)
        if len(opponent_counts) < MIN_DISTINCT_OPPONENTS:
            reasons.append(f"fewer_than_10_distinct_opponent_components:{archive}")
        if opponent_counts and max(opponent_counts.values()) > MAX_GAMES_PER_OPPONENT:
            reasons.append(f"opponent_component_contributes_more_than_20_games:{archive}")

    complete = len(lineages) == FAMILY_COUNT and all(
        len(selected_by_archive[row["archive_sha256"]]) == GAMES_PER_FAMILY
        for row in lineages
    )
    if not complete:
        reasons.append("prospective_panel_incomplete")

    selector_errors: list[Decimal] = []
    baseline_errors: list[Decimal] = []
    selector_predictions: list[Decimal] = []
    hosted_targets: list[Decimal] = []
    hosted_standard_errors: list[Decimal] = []
    archive_metrics: list[dict[str, Any]] = []
    if complete:
        for lineage in lineages:
            archive = lineage["archive_sha256"]
            rows = selected_by_archive[archive]
            stratum_means: list[Decimal] = []
            stratum_variances: list[Decimal] = []
            for opponent_bin in range(OPPONENT_BIN_COUNT):
                for seat in range(SEAT_COUNT):
                    stratum = [
                        row
                        for row in rows
                        if row["opponent_bin"] == opponent_bin and row["seat"] == seat
                    ]
                    wins = sum(row["outcome"] for row in stratum)
                    mean = Decimal(wins) / Decimal(GAMES_PER_STRATUM)
                    stratum_means.append(mean)
                    stratum_variances.append(
                        mean * (Decimal(1) - mean) / Decimal(GAMES_PER_STRATUM)
                    )
            with localcontext() as context:
                context.prec = 60
                hosted = sum(stratum_means, Decimal(0)) / Decimal(STRATUM_COUNT)
                hosted_variance = sum(stratum_variances, Decimal(0)) / Decimal(
                    STRATUM_COUNT**2
                )
                hosted_se = hosted_variance.sqrt()
            selector = Decimal(lineage["selector_prediction"])
            baseline = Decimal(lineage["baseline_prediction"])
            selector_error = abs(hosted - selector)
            baseline_error = abs(hosted - baseline)
            selector_predictions.append(selector)
            hosted_targets.append(hosted)
            selector_errors.append(selector_error)
            baseline_errors.append(baseline_error)
            hosted_standard_errors.append(hosted_se)
            archive_metrics.append(
                {
                    "archive_sha256": archive,
                    "hosted": hosted,
                    "selector": selector,
                    "baseline": baseline,
                }
            )

    with localcontext() as context:
        context.prec = 60
        selector_mae = (
            sum(selector_errors, Decimal(0)) / Decimal(FAMILY_COUNT) if complete else None
        )
        baseline_mae = (
            sum(baseline_errors, Decimal(0)) / Decimal(FAMILY_COUNT) if complete else None
        )
        error_ratio = (
            selector_mae / baseline_mae
            if selector_mae is not None and baseline_mae is not None and baseline_mae > 0
            else None
        )
        mean_hosted_se = (
            sum(hosted_standard_errors, Decimal(0)) / Decimal(FAMILY_COUNT)
            if complete
            else None
        )
    improvement_count = (
        sum(selector < baseline for selector, baseline in zip(selector_errors, baseline_errors))
        if complete
        else None
    )
    spearman = _spearman(selector_predictions, hosted_targets) if complete else None

    selector_top_archive: str | None = None
    selector_top_hosted_rank: int | None = None
    if complete:
        selector_top_archive = sorted(
            archive_metrics,
            key=lambda row: (-row["selector"], row["archive_sha256"]),
        )[0]["archive_sha256"]
        hosted_order = sorted(
            archive_metrics,
            key=lambda row: (-row["hosted"], row["archive_sha256"]),
        )
        selector_top_hosted_rank = 1 + next(
            index
            for index, row in enumerate(hosted_order)
            if row["archive_sha256"] == selector_top_archive
        )

        if improvement_count is not None and improvement_count < REQUIRED_ERROR_IMPROVEMENTS:
            reasons.append("selector_improves_fewer_than_15_lineages")
        if baseline_mae == 0:
            reasons.append("baseline_mean_absolute_error_is_zero")
        elif error_ratio is None or error_ratio > MAX_MEAN_ERROR_RATIO:
            reasons.append("mean_absolute_error_ratio_exceeds_0.80")
        if spearman is None or spearman < MIN_SPEARMAN:
            reasons.append("selector_hosted_spearman_below_0.50")
        if (
            selector_top_hosted_rank is None
            or selector_top_hosted_rank > MAX_TOP_ARCHIVE_HOSTED_RANK
        ):
            reasons.append("selector_top_archive_hosted_rank_exceeds_5")

    claim_passed = complete and not reasons
    selected_projection = [
        {
            "archive_sha256": row["archive_sha256"],
            "game_id": row["game_id"],
            "source_row_sha256": row["source_row_sha256"],
        }
        for row in sorted(
            selected,
            key=lambda row: (
                row["archive_sha256"],
                row["server_end_time_ns"],
                row["game_id"],
            ),
        )
    ]
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "authority": False,
        "authority_level": 0,
        "candidate_development_authorized": False,
        "holdout_accessed": False,
        "holdout_access_authorized": False,
        "submission_authorized": False,
        "production_submission_authorized": False,
        "passed": False,
        "synthetic_conformance_passed": claim_passed,
        "decision": "SYNTHETIC_PROSPECTIVE_CONFORMANCE_ONLY" if claim_passed else "FAIL_CLOSED",
        "reasons": reasons,
        "evidence_sha256": evidence_sha256,
        "selected_games_sha256": canonical_sha256(selected_projection),
        "counts": {
            "families": len(lineages),
            "selected_games": len(selected),
            "error_improvements": improvement_count,
        },
        "metrics": {
            "selector_mean_absolute_error": (
                _format_decimal(selector_mae) if selector_mae is not None else None
            ),
            "baseline_mean_absolute_error": (
                _format_decimal(baseline_mae) if baseline_mae is not None else None
            ),
            "mean_absolute_error_ratio": (
                _format_decimal(error_ratio) if error_ratio is not None else None
            ),
            "selector_hosted_spearman": (
                _format_decimal(spearman) if spearman is not None else None
            ),
            "selector_top_archive_sha256": selector_top_archive,
            "selector_top_archive_hosted_rank": selector_top_hosted_rank,
            "mean_hosted_conditional_binomial_se": (
                _format_decimal(mean_hosted_se) if mean_hosted_se is not None else None
            ),
            "worst_case_hosted_conditional_binomial_se": "0.035355339059",
        },
        "protocol": {
            "families": FAMILY_COUNT,
            "local_episodes_per_archive": LOCAL_EPISODES_PER_ARCHIVE,
            "opponent_bins": OPPONENT_BIN_COUNT,
            "seats": SEAT_COUNT,
            "games_per_stratum": GAMES_PER_STRATUM,
            "games_per_family": GAMES_PER_FAMILY,
            "opponent_independence_unit": "ancestry_component",
            "minimum_distinct_opponent_components": MIN_DISTINCT_OPPONENTS,
            "maximum_games_per_opponent_component": MAX_GAMES_PER_OPPONENT,
            "required_error_improvements": REQUIRED_ERROR_IMPROVEMENTS,
            "maximum_mean_error_ratio": _format_decimal(MAX_MEAN_ERROR_RATIO),
            "minimum_spearman": _format_decimal(MIN_SPEARMAN),
            "maximum_top_archive_hosted_rank": MAX_TOP_ARCHIVE_HOSTED_RANK,
            "ties_count_for_baseline": True,
            "historical_data_allowed": False,
            "extension_allowed": False,
            "substitution_allowed": False,
            "uncertainty_interpretation": "conditional_binomial_non_inferential",
        },
    }
    result["content_sha256"] = canonical_sha256(result)
    return result


def evaluate_prospective_transfer(evidence: object) -> dict[str, Any]:
    """Production-shaped G11 entry point; hard-close without trusted services.

    The evidence argument fixes the future exact-gate call shape. It is
    intentionally not inspected while independently pinned campaign-registry,
    exhaustive-collector, and disclosure services are unavailable.
    """

    del evidence
    if not PINNED_PROSPECTIVE_SERVICE_IDENTITIES:
        return _failed(
            "trusted_prospective_freeze_collector_and_disclosure_services_unavailable"
        )
    return _failed("prospective_production_verifier_not_implemented")


def blinded_disclosure(result: object) -> dict[str, Any]:
    """Expose only the binary selector verdict, never lineage diagnostics."""

    if not isinstance(result, Mapping) or result.get("schema") != RESULT_SCHEMA:
        raise ProspectiveTransferValidationError("result schema mismatch")
    expected_hash = result.get("content_sha256")
    if type(expected_hash) is not str:
        raise ProspectiveTransferValidationError("result content hash is missing")
    unsigned = dict(result)
    unsigned.pop("content_sha256", None)
    if canonical_sha256(unsigned) != expected_hash:
        raise ProspectiveTransferValidationError("result content hash mismatch")
    if result.get("decision") not in {"FAIL_CLOSED", "SYNTHETIC_PROSPECTIVE_CONFORMANCE_ONLY"}:
        raise ProspectiveTransferValidationError(
            "trusted signed disclosure service is unavailable"
        )
    return {
        "schema": DISCLOSURE_SCHEMA,
        "decision": "TERMINAL_FAILURE",
        "result_sha256": expected_hash,
        "authority": False,
        "candidate_development_authorized": False,
        "holdout_access_authorized": False,
        "submission_authorized": False,
    }


__all__ = [
    "DISCLOSURE_SCHEMA",
    "FAMILY_COUNT",
    "GAMES_PER_FAMILY",
    "GAMES_PER_STRATUM",
    "INPUT_SCHEMA",
    "LOCAL_EPISODES_PER_ARCHIVE",
    "PINNED_PROSPECTIVE_SERVICE_IDENTITIES",
    "ProspectiveTransferValidationError",
    "RESULT_SCHEMA",
    "blinded_disclosure",
    "evaluate_prospective_transfer",
    "evaluate_synthetic_prospective_conformance",
]
