"""Binding, fail-closed Evaluation v6.3.1 statistics correction.

This module is deliberately only the numerical/verifier boundary.  It has no
authenticated composer, credential handling, permit issuer, holdout reader, or
upload path.  The explicit TEST_ONLY/OFFLINE fixture builders are useful for
conformance tests, but their outputs are diagnostics with zero authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import combinations
import math
import re
from typing import Any, TypeVar

import gmpy2

from .common import canonical_json_bytes, canonical_sha256, freeze, zero_authority


FEATURE_NAMES = (
    "early_prize_tempo",
    "attack_readiness",
    "damage_efficiency",
    "viable_attacker_recovery",
    "resource_viability",
    "seat_robustness",
)
SLOTS = ("D01", "D02", "D03", "D04", "D05", "D06", "DR01", "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "CR01")
DEV_PRIMARY_SLOTS = SLOTS[:6]
DEV_RESERVE_SLOT = "DR01"
CONFIRM_PRIMARY_SLOTS = SLOTS[7:15]
CONFIRM_RESERVE_SLOT = "CR01"

MPFR_PRECISION_BITS = 256
MPFR_ROUNDING = "round_to_nearest_even"
V0_DIAGONAL = ("9", "9")
A0 = "2"
B0 = "8"
Y_SCALE = "100"
SCORE_SERIAL_PLACES = 6
PROBABILITY_SERIAL_PLACES = 12
RATIO_SERIAL_PLACES = 12
MIN_FIT_OBSERVATIONS = 4
MAX_CONDITION_NUMBER = "1000000000000"
WIN_MARGIN_POINTS = "0.1"
CONCORDANCE_MARGIN_POINTS = "0.1"
DEV_UNIT_WINS_MINIMUM = 4
DEV_RATIO_MAXIMUM = "0.90"
DEV_BETA_PROBABILITY_MINIMUM = "0.90"
CONFIRM_WINS_MINIMUM = 7
CONFIRM_RATIO_MAXIMUM = "0.80"
CONFIRM_CONSTANT_RATIO_MAXIMUM = "0.95"
CONFIRM_CONCORDANCE_MINIMUM = 20
SIGN_TEST_THRESHOLD_NUMERATOR = 9
SIGN_TEST_DENOMINATOR = 256

_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MPFR_HEX_RE = re.compile(r"^-?0x[0-9a-f]+(?:\.[0-9a-f]+)?p[+-]?[0-9]+$")
_ARTIFACT_SENTINEL = object()
_FIXTURE_SENTINEL = object()
_FAILURE_SENTINEL = object()
_RESULT_SENTINEL = object()
_CONFIRM_OUTCOME_SENTINEL = object()
_ISSUED_ARTIFACTS: dict[int, _IssuedRecord] = {}
_ISSUED_PRECONFIRM_FIXTURES: dict[int, _IssuedRecord] = {}
_ISSUED_CONFIRM_OUTCOMES: dict[int, _IssuedRecord] = {}
_ISSUED_FIXTURES: dict[int, _IssuedRecord] = {}
_ISSUED_FAILURES: dict[int, _IssuedRecord] = {}
_ISSUED_RESULTS: dict[int, _IssuedRecord] = {}

FROZEN_NUMERIC_GOLDEN_VECTOR = freeze({
    "x": ["-1", "0", "0.5", "1"],
    "y": ["-0.5", "0", "0.25", "0.5"],
    "prediction_x": "0.25",
    "intercept": "0.002937336815",
    "beta": "0.475848563969",
    "prediction_points": "12.189947780679",
})
FROZEN_MODEL = {
    "schema": "eval.v6.3.1.closed-form-nig-statistics",
    "outcome": {"polls": 4, "gap": "score-rank10", "endpoint": "mean_of_sorted_middle_two", "model_scale": "Yobs/100", "score_domain": ["0", "10000"], "no_winsorization_clipping_imputation_trimming": True},
    "mechanics": {"feature_names": list(FEATURE_NAMES), "equal_weights": ["0.1666666666666666666666666666666666666666666666666666666666666666666666666667"] * 6, "range": ["-1", "1"], "raw_game_point_rate_forbidden_as_feature": True},
    "raw_comparator": {
        "source": "raw_paired_local_game_point_rate",
        "source_range": ["0", "1"],
        "regressor": "R",
        "transform": "R=2*raw_paired_local_game_point_rate-1",
        "regressor_range": ["-1", "1"],
        "mechanics_feature_use_forbidden": True,
    },
    "regression": {"family": "normal_inverse_gamma", "V0": [["9", "0"], ["0", "9"]], "a0": A0, "b0": B0, "coefficients": ["alpha", "beta"], "closed_form_only": True},
    "procedure": {"dev": "leave_one_source_component_out", "unit_win_margin_points": WIN_MARGIN_POINTS, "family_win_margin_points": WIN_MARGIN_POINTS, "concordance_margin_points": CONCORDANCE_MARGIN_POINTS, "ties_incorrect": True, "no_confirm_refit": True, "pre_confirm_freeze_must_not_receive_confirm_endpoints": True},
    "thresholds": {"dev_unit_wins_minimum": DEV_UNIT_WINS_MINIMUM, "dev_family_wins": "ceil(2F/3)", "dev_ratio_maximum": DEV_RATIO_MAXIMUM, "dev_beta_positive_probability_minimum": DEV_BETA_PROBABILITY_MINIMUM, "confirm_wins_minimum": CONFIRM_WINS_MINIMUM, "confirm_raw_ratio_maximum": CONFIRM_RATIO_MAXIMUM, "confirm_constant_ratio_maximum": CONFIRM_CONSTANT_RATIO_MAXIMUM, "confirm_concordant_pairs_minimum": CONFIRM_CONCORDANCE_MINIMUM, "sign_test_threshold": "9/256", "ratio_zero_over_zero": "1", "ratio_positive_over_zero": "Infinity"},
    "support": {
        "binding_spec": "V631_ASSIGNMENT_SUPPORT_CORRECTION",
        "binding_document_sha256": "be0f6531689b94ef3b45344178da2a12da2272994cc83995cdfb18e3c113a1a8",
        "implementation_owner": "separate_authenticated_assignment_module",
        "assignment_support_authenticated": False,
        "criterion_available": False,
        "implemented_in_statistics_module": False,
        "metrics": {
            "F": "joint_Chebyshev_max_abs_distance_over_F1_through_F6",
            "x": "separate_absolute_distance_on_equal_weight_mechanics_composite",
            "R": "separate_absolute_distance_on_raw_comparator",
        },
        "support_rule": "target_second_neighbor_distance_at_most_worst_DEV_second_neighbor_radius_plus_epsilon_for_F_x_and_R",
        "epsilon": "0.000000000001",
        "active_dev_scenarios_required": 7,
        "confirm_pool_targets_per_dev_scenario": 9,
        "dev_reserve_target_against_base_dev": True,
        "required_target_scenario_relations": "7x9_CONFIRM_plus_DR_against_DEV_0",
        "required_target_scenario_relation_count": 64,
        "point_estimate_pass_required": True,
        "bootstrap": {
            "replicates_required": 10000,
            "pass_count_required_per_relation": 9500,
            "common_seed_resampling_across_all_units": True,
            "atomic_block": "control_id_seed_id_with_both_seats",
            "strata": 4,
            "blocks_per_stratum": 300,
            "prng": "SHAKE256_common_index_matrix_with_unbiased_uint32_rejection_sampling",
        },
    },
    "authority_boundary": {
        "feature_spec_complete": False,
        "assignment_support_authenticated": False,
        "offline_independent_ab_numeric_agreement_verified": False,
        "offline_bootstrap_10000_verified": False,
        "timestamp_evidence_verified": False,
        "predictive_validity_established": False,
        "offline_outputs_test_only": True,
    },
    "numeric": {"library": "gmpy2", "required_version": "2.3.1", "mpfr_precision_bits": MPFR_PRECISION_BITS, "rounding": MPFR_ROUNDING, "student_t_cdf": "regularized_incomplete_beta_continued_fraction_v1", "beta_cf_max_iterations": 10000, "beta_cf_epsilon": "2^-220", "beta_cf_floor": "2^-240", "condition_number_max": MAX_CONDITION_NUMBER},
    "serialization": {
        "internal_mpfr": "C99_hexadecimal_with_64_fractional_hex_digits",
        "internal_mpfr_parse": "gmpy2_mpfr_under_frozen_256_bit_round_to_nearest_even_context",
        "rounded_prediction_fields_are_report_only": True,
        "offline_artifact_phase_binding": ["PRE_CONFIRM", "POST_FREEZE_CONFIRM_ENDPOINTS"],
        "predictions_score_points_decimal_places": SCORE_SERIAL_PLACES,
        "probabilities_decimal_places": PROBABILITY_SERIAL_PLACES,
        "ratios_decimal_places": RATIO_SERIAL_PLACES,
        "infinity": "Infinity",
    },
    "golden_vector": FROZEN_NUMERIC_GOLDEN_VECTOR,
}
FROZEN_MODEL = freeze(FROZEN_MODEL)
FROZEN_MODEL_ROOT_SHA256 = "8c2ea348904e9914c946eedc263ee68ae5dfacd24d87a36d703d19e72ab22e98"
if canonical_sha256(FROZEN_MODEL) != FROZEN_MODEL_ROOT_SHA256:
    raise RuntimeError("Evaluation v6.3.1 frozen model root mismatch")

_OFFLINE_DEV_THRESHOLDS_MET = "TEST_ONLY_OFFLINE_DEV_THRESHOLDS_MET"
_OFFLINE_DEV_THRESHOLDS_NOT_MET = "TEST_ONLY_OFFLINE_DEV_THRESHOLDS_NOT_MET"
_OFFLINE_PREDICTIONS_FROZEN = "TEST_ONLY_OFFLINE_PREDICTIONS_FROZEN"
_OFFLINE_CONFIRM_THRESHOLDS_MET = "TEST_ONLY_OFFLINE_CONFIRM_THRESHOLDS_MET"
_OFFLINE_CONFIRM_THRESHOLDS_NOT_MET = "TEST_ONLY_OFFLINE_CONFIRM_THRESHOLDS_NOT_MET"
_OFFLINE_INPUT_INVALID = "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"
_OFFLINE_NUMERIC_DIVERGENCE = "TEST_ONLY_OFFLINE_STATISTICS_NUMERIC_DIVERGENCE"
_OFFLINE_SIGN_TEST_NOT_EVALUABLE = "TEST_ONLY_OFFLINE_SIGN_TEST_NOT_EVALUABLE"
_OFFLINE_ARTIFACT_STATUS = {
    "test_only": True,
    "offline_conformance_only": True,
    "authenticated": False,
    "feature_spec_complete": False,
    "assignment_support_authenticated": False,
    "independent_ab_numeric_agreement_verified": False,
    "bootstrap_support_10000_verified": False,
    "timestamp_evidence_verified": False,
    "predictive_validity_established": False,
}
_SCHEMA_ASSIGNMENT = "eval.v6.3.1.test-only-offline.population-assignment"
_SCHEMA_LOCAL_FEATURES = "eval.v6.3.1.test-only-offline.local-features"
_SCHEMA_CONFIRM_POOL = "eval.v6.3.1.test-only-offline.confirm-pool"
_SCHEMA_FEATURE_SUPPORT = "eval.v6.3.1.test-only-offline.feature-support-pending"
_SCHEMA_CAMPAIGN_PREREG = "eval.v6.3.1.test-only-offline.campaign-prereg"
_SCHEMA_DEV_ENDPOINTS = "eval.v6.3.1.test-only-offline.dev-endpoints"
_SCHEMA_CAMPAIGN_INTEGRITY = "eval.v6.3.1.test-only-offline.synthetic-integrity"
_SCHEMA_ACTIVE_SET = "eval.v6.3.1.test-only-offline.active-set"
_SCHEMA_DEV_FIT = "eval.v6.3.1.test-only-offline.dev-fit"
_SCHEMA_PREDICTIONS = "eval.v6.3.1.test-only-offline.confirm-predictions"
_SCHEMA_CONFIRM_ENDPOINTS = "eval.v6.3.1.test-only-offline.confirm-endpoints"
_SCHEMA_DEV_RESULT = "eval.v6.3.1.test-only-offline.statistics.dev-result"
_SCHEMA_PREDICTION_RESULT = "eval.v6.3.1.test-only-offline.statistics.confirm-predictions"
_SCHEMA_CONFIRM_RESULT = "eval.v6.3.1.test-only-offline.statistics.confirm-result"


class StatisticsValidationError(ValueError):
    """A statistics input is malformed, unauthenticated, or numerically unsafe."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> StatisticsValidationError:
    return StatisticsValidationError(code, message)


@dataclass(frozen=True)
class _IssuedRecord:
    object_reference: object
    canonical_bytes: bytes
    fingerprint_sha256: str
    immutable_snapshot: Any


def _issuance_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, _VerifiedArtifact):
        return {
            "kind": type(value).__name__,
            "schema": value.schema,
            "parent_root_sha256": value.parent_root_sha256,
            "content_sha256": value.content_sha256,
            "offline_fixture_binding_sha256": value.offline_fixture_binding_sha256,
            "offline_fixture_only": value.offline_fixture_only,
            "payload": value.payload,
            "construction_token_valid": value._construction_token is _ARTIFACT_SENTINEL,
        }
    if type(value) is OfflinePreConfirmFixture:
        return {
            "kind": "OfflinePreConfirmFixture",
            "prereg": _issuance_payload(value.prereg),
            "assignment": _issuance_payload(value.assignment),
            "local_features": _issuance_payload(value.local_features),
            "confirm_pool": _issuance_payload(value.confirm_pool),
            "feature_support": _issuance_payload(value.feature_support),
            "dev_endpoints": _issuance_payload(value.dev_endpoints),
            "integrity": _issuance_payload(value.integrity),
            "test_only": value.test_only,
            "offline_conformance_only": value.offline_conformance_only,
            "construction_token_valid": value._construction_token is _FIXTURE_SENTINEL,
        }
    if type(value) is OfflineConfirmOutcomeFixture:
        return {
            "kind": "OfflineConfirmOutcomeFixture",
            "campaign_root_sha256": value.campaign_root_sha256,
            "confirm_pool_root_sha256": value.confirm_pool_root_sha256,
            "endpoints": value.endpoints,
            "test_only": value.test_only,
            "authenticated_endpoint_evidence": value.authenticated_endpoint_evidence,
            "leakage_marked": value.leakage_marked,
            "construction_token_valid": value._construction_token is _CONFIRM_OUTCOME_SENTINEL,
        }
    if type(value) is OfflineStatisticsFixture:
        return {
            "kind": "OfflineStatisticsFixture",
            "pre_confirm": _issuance_payload(value.pre_confirm),
            "confirm_outcomes": _issuance_payload(value.confirm_outcomes),
            "default_active_set": _issuance_payload(value.default_active_set),
            "test_only": value.test_only,
            "offline_conformance_only": value.offline_conformance_only,
            "construction_token_valid": value._construction_token is _FIXTURE_SENTINEL,
        }
    if type(value) is TestOnlyOfflineReserveFailureFixture:
        return {
            "kind": "TestOnlyOfflineReserveFailureFixture",
            "campaign_root_sha256": value.campaign_root_sha256,
            "slot_id": value.slot_id,
            "reason": value.reason,
            "before_mature_poll": value.before_mature_poll,
            "test_only": value.test_only,
            "authenticated_failure_evidence": value.authenticated_failure_evidence,
            "construction_token_valid": value._construction_token is _FAILURE_SENTINEL,
        }
    if type(value) is DevNumericAnalysis:
        return {
            "kind": "DevNumericAnalysis",
            "verdict": value.verdict,
            "report": value.report,
            "verified_fit": None if value.verified_fit is None else _issuance_payload(value.verified_fit),
            "construction_token_valid": value._construction_token is _RESULT_SENTINEL,
        }
    if type(value) is ConfirmPredictionFreeze:
        return {
            "kind": "ConfirmPredictionFreeze",
            "verdict": value.verdict,
            "report": value.report,
            "verified_predictions": None if value.verified_predictions is None else _issuance_payload(value.verified_predictions),
            "construction_token_valid": value._construction_token is _RESULT_SENTINEL,
        }
    if type(value) is ConfirmNumericAnalysis:
        return {
            "kind": "ConfirmNumericAnalysis",
            "verdict": value.verdict,
            "report": value.report,
            "construction_token_valid": value._construction_token is _RESULT_SENTINEL,
        }
    raise TypeError(f"unsupported issuance type {type(value).__name__}")


def _issue(value: Any, registry: dict[int, _IssuedRecord]) -> Any:
    payload = _issuance_payload(value)
    canonical = canonical_json_bytes(payload)
    registry[id(value)] = _IssuedRecord(
        object_reference=value,
        canonical_bytes=canonical,
        fingerprint_sha256=canonical_sha256(payload),
        immutable_snapshot=freeze(payload),
    )
    return value


def _require_issued(value: Any, registry: Mapping[int, _IssuedRecord], label: str) -> None:
    record = registry.get(id(value))
    if record is None or record.object_reference is not value:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} was not issued by this module")
    try:
        current_payload = _issuance_payload(value)
        current_bytes = canonical_json_bytes(current_payload)
        current_fingerprint = canonical_sha256(current_payload)
        snapshot_bytes = canonical_json_bytes(record.immutable_snapshot)
    except Exception as exc:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} issued content is no longer canonical") from exc
    if (
        current_bytes != record.canonical_bytes
        or current_fingerprint != record.fingerprint_sha256
        or snapshot_bytes != record.canonical_bytes
    ):
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} differs from its retained issuance snapshot")


def _ctx() -> gmpy2.context:
    context = gmpy2.get_context().copy()
    context.precision = MPFR_PRECISION_BITS
    context.round = gmpy2.RoundToNearest
    return context


def _require_runtime() -> None:
    expected_root = "8c2ea348904e9914c946eedc263ee68ae5dfacd24d87a36d703d19e72ab22e98"
    try:
        model_root = canonical_sha256(FROZEN_MODEL)
    except Exception as exc:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "FROZEN_MODEL is not canonically serializable") from exc
    if FROZEN_MODEL_ROOT_SHA256 != expected_root or model_root != expected_root:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "FROZEN_MODEL content does not match its literal root")
    if (
        tuple(FROZEN_MODEL["mechanics"]["feature_names"]) != FEATURE_NAMES
        or tuple(FROZEN_MODEL["mechanics"]["range"]) != ("-1", "1")
        or tuple(FROZEN_MODEL["regression"]["V0"][index][index] for index in range(2)) != V0_DIAGONAL
        or FROZEN_MODEL["regression"]["a0"] != A0
        or FROZEN_MODEL["regression"]["b0"] != B0
        or Y_SCALE != "100"
        or MIN_FIT_OBSERVATIONS != 4
        or MAX_CONDITION_NUMBER != FROZEN_MODEL["numeric"]["condition_number_max"]
        or MPFR_PRECISION_BITS != FROZEN_MODEL["numeric"]["mpfr_precision_bits"]
        or MPFR_ROUNDING != FROZEN_MODEL["numeric"]["rounding"]
        or FROZEN_MODEL["outcome"]["model_scale"] != "Yobs/100"
        or FROZEN_MODEL["procedure"]["unit_win_margin_points"] != WIN_MARGIN_POINTS
        or FROZEN_MODEL["procedure"]["family_win_margin_points"] != WIN_MARGIN_POINTS
        or FROZEN_MODEL["procedure"]["concordance_margin_points"] != CONCORDANCE_MARGIN_POINTS
        or FROZEN_MODEL["thresholds"]["dev_unit_wins_minimum"] != DEV_UNIT_WINS_MINIMUM
        or FROZEN_MODEL["thresholds"]["dev_ratio_maximum"] != DEV_RATIO_MAXIMUM
        or FROZEN_MODEL["thresholds"]["dev_beta_positive_probability_minimum"] != DEV_BETA_PROBABILITY_MINIMUM
        or FROZEN_MODEL["thresholds"]["confirm_wins_minimum"] != CONFIRM_WINS_MINIMUM
        or FROZEN_MODEL["thresholds"]["confirm_raw_ratio_maximum"] != CONFIRM_RATIO_MAXIMUM
        or FROZEN_MODEL["thresholds"]["confirm_constant_ratio_maximum"] != CONFIRM_CONSTANT_RATIO_MAXIMUM
        or FROZEN_MODEL["thresholds"]["confirm_concordant_pairs_minimum"] != CONFIRM_CONCORDANCE_MINIMUM
        or FROZEN_MODEL["thresholds"]["sign_test_threshold"] != f"{SIGN_TEST_THRESHOLD_NUMERATOR}/{SIGN_TEST_DENOMINATOR}"
        or FROZEN_MODEL["serialization"]["predictions_score_points_decimal_places"] != SCORE_SERIAL_PLACES
        or FROZEN_MODEL["serialization"]["probabilities_decimal_places"] != PROBABILITY_SERIAL_PLACES
        or FROZEN_MODEL["serialization"]["ratios_decimal_places"] != RATIO_SERIAL_PLACES
    ):
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "runtime statistics constants diverge from FROZEN_MODEL")
    if gmpy2.version() != FROZEN_MODEL["numeric"]["required_version"]:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "gmpy2 runtime version does not match FROZEN_MODEL_ROOT")
    context = _ctx()
    if context.precision != MPFR_PRECISION_BITS or context.round != gmpy2.RoundToNearest:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "MPFR context is not 256-bit round-to-nearest-even")


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} must be lowercase SHA-256")
    return value


def _decimal(value: Any, label: str, *, minimum: Decimal | None = None, maximum: Decimal | None = None) -> Decimal:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} must be a canonical finite decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} is not a decimal") from exc
    if not result.is_finite() or minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} is outside its frozen domain")
    return result


def _decimal_text(value: Decimal) -> str:
    value = value.normalize()
    text = format(value, "f")
    return "0" if text in {"-0", ""} else text


def _mp(value: str | Decimal | int) -> gmpy2.mpfr:
    return gmpy2.mpfr(str(value))


def _mpfr_exact_text(value: gmpy2.mpfr) -> str:
    """Serialize one finite MPFR value without decimal quantization."""

    if not gmpy2.is_finite(value):
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "internal MPFR values must be finite")
    return format(value, ".64a")


def _mpfr_exact(value: Any, label: str) -> gmpy2.mpfr:
    if type(value) is not str or _MPFR_HEX_RE.fullmatch(value) is None:
        raise _fail("VERIFIED_INPUT_INVALID", f"{label} must be the frozen full-precision MPFR hex encoding")
    with gmpy2.context(_ctx()):
        parsed = gmpy2.mpfr(value)
        if not gmpy2.is_finite(parsed) or _mpfr_exact_text(parsed) != value:
            raise _fail("VERIFIED_INPUT_INVALID", f"{label} is not a canonical frozen MPFR value")
        return parsed


def _text(value: gmpy2.mpfr, places: int) -> str:
    if not gmpy2.is_finite(value):
        return "Infinity" if value > 0 else "-Infinity"
    return format(value, f".{places}f")


def _ratio(numerator: gmpy2.mpfr, denominator: gmpy2.mpfr) -> gmpy2.mpfr | None:
    if denominator == 0:
        return _mp(1) if numerator == 0 else None
    return numerator / denominator


def frozen_ratio(numerator: str, denominator: str) -> str:
    """Implement Sol's explicit comparator-ratio zero semantics."""

    with gmpy2.context(_ctx()):
        top = _mp(_decimal(numerator, "ratio numerator", minimum=Decimal(0)))
        bottom = _mp(_decimal(denominator, "ratio denominator", minimum=Decimal(0)))
        result = _ratio(top, bottom)
        return "Infinity" if result is None else _text(result, RATIO_SERIAL_PLACES)


def _regularized_beta(a: gmpy2.mpfr, b: gmpy2.mpfr, x: gmpy2.mpfr) -> gmpy2.mpfr:
    if x <= 0:
        return _mp(0)
    if x >= 1:
        return _mp(1)
    epsilon = gmpy2.exp2(-220)
    floor = gmpy2.exp2(-240)

    def fraction(left: gmpy2.mpfr, right: gmpy2.mpfr, value: gmpy2.mpfr) -> gmpy2.mpfr:
        qab, qap, qam = left + right, left + 1, left - 1
        c = _mp(1)
        d = 1 - qab * value / qap
        d = floor if abs(d) < floor else d
        d = 1 / d
        h = d
        for iteration in range(1, 10001):
            twice = _mp(2 * iteration)
            aa = iteration * (right - iteration) * value / ((qam + twice) * (left + twice))
            d = 1 + aa * d
            d = floor if abs(d) < floor else d
            c = 1 + aa / c
            c = floor if abs(c) < floor else c
            d = 1 / d
            h *= d * c
            aa = -(left + iteration) * (qab + iteration) * value / ((left + twice) * (qap + twice))
            d = 1 + aa * d
            d = floor if abs(d) < floor else d
            c = 1 + aa / c
            c = floor if abs(c) < floor else c
            d = 1 / d
            delta = d * c
            h *= delta
            if abs(delta - 1) < epsilon:
                return h
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "regularized beta continued fraction did not converge")

    log_beta_term = gmpy2.exp(gmpy2.lngamma(a + b) - gmpy2.lngamma(a) - gmpy2.lngamma(b) + a * gmpy2.log(x) + b * gmpy2.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return log_beta_term * fraction(a, b, x) / a
    return 1 - log_beta_term * fraction(b, a, 1 - x) / b


def _student_t_cdf(value: gmpy2.mpfr, degrees_of_freedom: gmpy2.mpfr) -> gmpy2.mpfr:
    if degrees_of_freedom <= 0:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "Student-t degrees of freedom must be positive")
    x = degrees_of_freedom / (degrees_of_freedom + value * value)
    beta = _regularized_beta(degrees_of_freedom / 2, _mp("0.5"), x)
    return _mp("0.5") * beta if value < 0 else 1 - _mp("0.5") * beta


def _strict_concordant_mpfr(
    outcome_left: gmpy2.mpfr,
    outcome_right: gmpy2.mpfr,
    prediction_left: gmpy2.mpfr,
    prediction_right: gmpy2.mpfr,
) -> bool:
    observed = outcome_left - outcome_right
    predicted = prediction_left - prediction_right
    threshold = _mp(CONCORDANCE_MARGIN_POINTS)
    return abs(observed) >= threshold and abs(predicted) >= threshold and (observed > 0) == (predicted > 0)


def strict_concordant(outcome_left: str, outcome_right: str, prediction_left: str, prediction_right: str) -> bool:
    """Evaluate strict concordance from unquantized decimal inputs."""

    with gmpy2.context(_ctx()):
        return _strict_concordant_mpfr(
            _mp(_decimal(outcome_left, "outcome_left")),
            _mp(_decimal(outcome_right, "outcome_right")),
            _mp(_decimal(prediction_left, "prediction_left")),
            _mp(_decimal(prediction_right, "prediction_right")),
        )


def sign_test_values(wins: int) -> dict[str, str | int]:
    if type(wins) is not int or not 0 <= wins <= 8:
        raise ValueError("wins must be an integer in [0, 8]")
    observed = sum(math.comb(8, index) for index in range(wins, 9))
    with gmpy2.context(_ctx()):
        return {
            "wins": wins,
            "threshold_numerator": SIGN_TEST_THRESHOLD_NUMERATOR,
            "observed_numerator": observed,
            "denominator": SIGN_TEST_DENOMINATOR,
            "threshold_p_value": _text(_mp(SIGN_TEST_THRESHOLD_NUMERATOR) / _mp(SIGN_TEST_DENOMINATOR), PROBABILITY_SERIAL_PLACES),
            "observed_p_value": _text(_mp(observed) / _mp(SIGN_TEST_DENOMINATOR), PROBABILITY_SERIAL_PLACES),
        }


@dataclass(frozen=True)
class _VerifiedArtifact:
    schema: str
    parent_root_sha256: str
    content_sha256: str
    offline_fixture_binding_sha256: str
    offline_fixture_only: bool
    payload: Mapping[str, Any]
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _ARTIFACT_SENTINEL:
            raise ValueError("verified statistics artifacts require a module sentinel")


class VerifiedCampaignPrereg(_VerifiedArtifact):
    pass


class VerifiedPopulationAssignment(_VerifiedArtifact):
    pass


class VerifiedLocalFeatures(_VerifiedArtifact):
    pass


class VerifiedConfirmPool(_VerifiedArtifact):
    pass


class VerifiedFeatureSupport(_VerifiedArtifact):
    pass


class VerifiedDevEndpoints(_VerifiedArtifact):
    pass


class VerifiedDevFit(_VerifiedArtifact):
    pass


class VerifiedConfirmPredictions(_VerifiedArtifact):
    pass


class VerifiedConfirmEndpoints(_VerifiedArtifact):
    pass


class VerifiedActiveSet(_VerifiedArtifact):
    pass


class VerifiedCampaignIntegrity(_VerifiedArtifact):
    pass


@dataclass(frozen=True)
class SignedAuditorNumericResult:
    """Future authenticated A/B input; no local constructor is provided."""

    auditor_id: str
    campaign_root_sha256: str
    model_root_sha256: str
    input_root_sha256: str
    result_root_sha256: str
    signature_envelope_root_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("signed auditor numeric results require the future authenticated composer")


@dataclass(frozen=True)
class VerifiedABNumericAgreement:
    """Future authenticated cross-implementation agreement; never made offline."""

    auditor_a: SignedAuditorNumericResult
    auditor_b: SignedAuditorNumericResult
    agreement_receipt_root_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("A/B numeric agreement requires the future authenticated composer")


@dataclass(frozen=True)
class VerifiedAssignmentBootstrapSupport:
    """Future authenticated assignment-support input; never made offline."""

    campaign_root_sha256: str
    assignment_root_sha256: str
    local_features_root_sha256: str
    support_receipt_root_sha256: str
    bootstrap_replicates: int
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("bootstrap support requires the future authenticated composer")


@dataclass(frozen=True)
class ExternallySignedTimeBoundPreConfirmArtifact:
    """Future pre-CONFIRM receipt; no local constructor or verifier exists."""

    campaign_root_sha256: str
    preregistration_root_sha256: str
    assignment_support_root_sha256: str
    auditor_signature_quorum_root_sha256: str
    timestamp_quorum_root_sha256: str
    valid_before_confirm_not_before: str
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("time-bound pre-CONFIRM evidence requires the future authenticated composer")


@dataclass(frozen=True)
class SeparatelyReceivedConfirmEndpointArtifact:
    """Future post-freeze endpoint receipt; no local constructor exists."""

    campaign_root_sha256: str
    prediction_root_sha256: str
    endpoint_receipt_root_sha256: str
    auditor_signature_quorum_root_sha256: str
    received_at_evidence_root_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("separately received CONFIRM endpoints require the future authenticated composer")


@dataclass(frozen=True)
class LedgerDerivedReserveFailureArtifact:
    """Future reserve evidence derived from an authenticated campaign ledger."""

    campaign_root_sha256: str
    ledger_root_sha256: str
    failed_slot_id: str
    failure_event_root_sha256: str
    pre_maturity_evidence_root_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        raise ValueError("reserve failure evidence requires the future authenticated composer")


@dataclass(frozen=True)
class OfflineUnitFixture:
    slot_id: str
    archive_sha256: str
    mechanics: Mapping[str, str]
    raw_paired_local_game_point_rate: str
    polls: tuple[tuple[str, str], ...]
    test_only: bool = True


@dataclass(frozen=True)
class TestOnlyOfflineReserveFailureFixture:
    campaign_root_sha256: str
    slot_id: str
    reason: str
    before_mature_poll: bool
    test_only: bool
    authenticated_failure_evidence: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _FAILURE_SENTINEL:
            raise ValueError("TEST_ONLY/OFFLINE reserve-failure fixtures require a module sentinel")


@dataclass(frozen=True)
class OfflinePreConfirmFixture:
    prereg: VerifiedCampaignPrereg
    assignment: VerifiedPopulationAssignment
    local_features: VerifiedLocalFeatures
    confirm_pool: VerifiedConfirmPool
    feature_support: VerifiedFeatureSupport
    dev_endpoints: VerifiedDevEndpoints
    integrity: VerifiedCampaignIntegrity
    test_only: bool
    offline_conformance_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _FIXTURE_SENTINEL:
            raise ValueError("offline pre-CONFIRM fixtures require a module sentinel")


@dataclass(frozen=True)
class OfflineConfirmOutcomeFixture:
    campaign_root_sha256: str
    confirm_pool_root_sha256: str
    endpoints: Mapping[str, Mapping[str, str]]
    test_only: bool
    authenticated_endpoint_evidence: bool
    leakage_marked: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _CONFIRM_OUTCOME_SENTINEL:
            raise ValueError("offline CONFIRM outcomes require a module sentinel")


@dataclass(frozen=True)
class OfflineStatisticsFixture:
    pre_confirm: OfflinePreConfirmFixture
    confirm_outcomes: OfflineConfirmOutcomeFixture
    default_active_set: VerifiedActiveSet
    test_only: bool
    offline_conformance_only: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _FIXTURE_SENTINEL:
            raise ValueError("offline statistics fixtures require a module sentinel")


@dataclass(frozen=True)
class DevNumericAnalysis:
    verdict: str
    report: Mapping[str, Any]
    verified_fit: VerifiedDevFit | None
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _RESULT_SENTINEL:
            raise ValueError("statistics results require a module sentinel")


@dataclass(frozen=True)
class ConfirmPredictionFreeze:
    verdict: str
    report: Mapping[str, Any]
    verified_predictions: VerifiedConfirmPredictions | None
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _RESULT_SENTINEL:
            raise ValueError("statistics results require a module sentinel")


@dataclass(frozen=True)
class ConfirmNumericAnalysis:
    verdict: str
    report: Mapping[str, Any]
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _RESULT_SENTINEL:
            raise ValueError("statistics results require a module sentinel")


def validate_issued_statistics_result(value: Any) -> DevNumericAnalysis | ConfirmPredictionFreeze | ConfirmNumericAnalysis:
    """Revalidate a result against its retained immutable issuance snapshot."""

    if type(value) not in {DevNumericAnalysis, ConfirmPredictionFreeze, ConfirmNumericAnalysis}:
        raise _fail("VERIFIED_INPUT_INVALID", "statistics result must be a typed module-issued result")
    _require_issued(value, _ISSUED_RESULTS, "statistics result")
    return value


ArtifactType = TypeVar("ArtifactType", bound=_VerifiedArtifact)


def _artifact(cls: type[ArtifactType], schema: str, parent_root: str, payload: Mapping[str, Any], *, pre_confirm_phase: bool) -> ArtifactType:
    _sha(parent_root, "artifact parent root")
    reserved = set(_OFFLINE_ARTIFACT_STATUS)
    if reserved.intersection(payload):
        raise ValueError("offline artifact status fields are module-controlled")
    frozen_payload = freeze({**_OFFLINE_ARTIFACT_STATUS, **dict(payload)})
    content_core = {"schema": schema, "parent_root_sha256": parent_root, "payload": frozen_payload, "offline_fixture_only": True}
    content = canonical_sha256(content_core)
    phase = "PRE_CONFIRM" if pre_confirm_phase else "POST_FREEZE_CONFIRM_ENDPOINTS"
    fixture_binding = canonical_sha256({"offline_fixture_only": True, "content_sha256": content, "phase": phase})
    return _issue(cls(schema, parent_root, content, fixture_binding, True, frozen_payload, _ARTIFACT_SENTINEL), _ISSUED_ARTIFACTS)


def _verify_artifact(value: Any, cls: type[ArtifactType], schema: str, *, parent_root: str | None = None, pre_confirm_phase: bool) -> ArtifactType:
    if type(value) is not cls:
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} must be a typed verifier artifact, never a mapping or raw array")
    _require_issued(value, _ISSUED_ARTIFACTS, schema)
    item = value
    if item.schema != schema or item.offline_fixture_only is not True:
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} is not an admissible offline verifier artifact")
    if any(item.payload.get(name) is not expected for name, expected in _OFFLINE_ARTIFACT_STATUS.items()):
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} does not retain TEST_ONLY/OFFLINE status")
    if parent_root is not None and item.parent_root_sha256 != parent_root:
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} parent root is stale or mismatched")
    for field, raw in (("content", item.content_sha256), ("offline fixture binding", item.offline_fixture_binding_sha256)):
        _sha(raw, field)
    core = {"schema": schema, "parent_root_sha256": item.parent_root_sha256, "payload": item.payload, "offline_fixture_only": True}
    if canonical_sha256(core) != item.content_sha256:
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} content hash does not bind its payload")
    phase = "PRE_CONFIRM" if pre_confirm_phase else "POST_FREEZE_CONFIRM_ENDPOINTS"
    expected_binding = canonical_sha256({"offline_fixture_only": True, "content_sha256": item.content_sha256, "phase": phase})
    if item.offline_fixture_binding_sha256 != expected_binding:
        raise _fail("VERIFIED_INPUT_INVALID", f"{schema} offline fixture binding does not bind its content and phase")
    return item


def _component_id(kind: str, graph_root: str, archive_hashes: Sequence[str]) -> str:
    return canonical_sha256({"kind": kind, "graph_root_sha256": graph_root, "archive_sha256s": sorted(archive_hashes)})


def _endpoint_from_polls(polls: Sequence[tuple[str, str]], slot: str) -> str:
    if len(polls) != 4:
        raise _fail("VERIFIED_INPUT_INVALID", f"{slot} must bind exactly four dual-collected polls")
    gaps = []
    for index, pair in enumerate(polls):
        if type(pair) is not tuple or len(pair) != 2:
            raise _fail("VERIFIED_INPUT_INVALID", f"{slot} poll {index} is malformed")
        score = _decimal(pair[0], f"{slot} poll score", minimum=Decimal(0), maximum=Decimal(10000))
        cutoff = _decimal(pair[1], f"{slot} poll rank10 cutoff", minimum=Decimal(0), maximum=Decimal(10000))
        gaps.append(score - cutoff)
    gaps.sort()
    return _decimal_text((gaps[1] + gaps[2]) / Decimal(2))


def _fixture_record(value: OfflineUnitFixture) -> dict[str, Any]:
    if type(value) is not OfflineUnitFixture or value.test_only is not True or value.slot_id not in SLOTS:
        raise _fail("VERIFIED_INPUT_INVALID", "offline fixture units must use canonical slots")
    archive = _sha(value.archive_sha256, f"{value.slot_id}.archive_sha256")
    if not isinstance(value.mechanics, Mapping) or set(value.mechanics) != set(FEATURE_NAMES):
        raise _fail("VERIFIED_INPUT_INVALID", f"{value.slot_id} mechanics must be the exact six-feature object")
    mechanics = {name: _decimal_text(_decimal(value.mechanics[name], f"{value.slot_id}.{name}", minimum=Decimal(-1), maximum=Decimal(1))) for name in FEATURE_NAMES}
    raw_rate = _decimal(value.raw_paired_local_game_point_rate, f"{value.slot_id}.raw paired local game-point rate", minimum=Decimal(0), maximum=Decimal(1))
    comparator_r = _decimal_text(Decimal(2) * raw_rate - Decimal(1))
    return {"archive_sha256": archive, "mechanics": mechanics, "raw_comparator_R": comparator_r, "yobs_score_points": _endpoint_from_polls(value.polls, value.slot_id), "poll_receipt_root_sha256": canonical_sha256({"slot_id": value.slot_id, "polls": list(value.polls)})}


def _graph_identities(records: Mapping[str, Mapping[str, Any]], groups: Mapping[str, Sequence[Sequence[str]]]) -> dict[str, dict[str, str]]:
    expected_kinds = ("source", "lineage_time", "development_control", "intervention")
    if not isinstance(groups, Mapping) or set(groups) != set(expected_kinds):
        raise _fail("VERIFIED_INPUT_INVALID", "component graphs must contain exactly source, lineage_time, development_control, and intervention")
    identities = {slot: {} for slot in SLOTS}
    for kind in expected_kinds:
        raw_groups = groups[kind]
        if type(raw_groups) not in (list, tuple):
            raise _fail("VERIFIED_INPUT_INVALID", f"{kind} graph groups must be ordered sequences")
        canonical_groups = []
        seen: set[str] = set()
        for members in raw_groups:
            if type(members) not in (list, tuple) or not members:
                raise _fail("VERIFIED_INPUT_INVALID", f"{kind} graph has an empty component")
            member_tuple = tuple(sorted(members))
            if any(type(slot) is not str or slot not in SLOTS for slot in member_tuple) or len(set(member_tuple)) != len(member_tuple) or seen.intersection(member_tuple):
                raise _fail("VERIFIED_INPUT_INVALID", f"{kind} graph membership is invalid")
            seen.update(member_tuple)
            canonical_groups.append(member_tuple)
        if seen != set(SLOTS):
            raise _fail("VERIFIED_INPUT_INVALID", f"{kind} graph must cover every canonical population slot exactly once")
        graph_root = canonical_sha256({"kind": kind, "components": sorted([list(group) for group in canonical_groups])})
        field = f"{kind}_component_id"
        for members in canonical_groups:
            component = _component_id(kind, graph_root, [records[slot]["archive_sha256"] for slot in members])
            for slot in members:
                identities[slot][field] = component
    return identities


def _support_payload(records: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if set(records) != set(SLOTS):
        raise _fail("VERIFIED_INPUT_INVALID", "TEST_ONLY/OFFLINE support declaration requires all sixteen local-feature rows")
    return {
        "binding_spec": "V631_ASSIGNMENT_SUPPORT_CORRECTION",
        "status": "TEST_ONLY_OFFLINE_ASSIGNMENT_SUPPORT_UNAVAILABLE",
        "criterion_available": False,
        "implemented_in_statistics_module": False,
        "required_metrics": ["joint_Chebyshev_F", "separate_x", "separate_R"],
        "required_active_dev_scenarios": 7,
        "required_confirm_targets_per_dev_scenario": 9,
        "dev_reserve_against_base_dev_required": True,
        "required_target_scenario_relations": "7x9_CONFIRM_plus_DR_against_DEV_0",
        "required_target_scenario_relation_count": 64,
        "point_estimate_pass_verified": False,
        "bootstrap_replicates_required": 10000,
        "bootstrap_pass_count_required_per_relation": 9500,
        "bootstrap_replicates_completed": 0,
        "common_seed_bootstrap_verified": False,
    }


def _active_payload(pre_confirm: OfflinePreConfirmFixture, confirm_slots: tuple[str, ...], failure: TestOnlyOfflineReserveFailureFixture | None) -> VerifiedActiveSet:
    return _artifact(
        VerifiedActiveSet,
        _SCHEMA_ACTIVE_SET,
        pre_confirm.confirm_pool.content_sha256,
        {
            "campaign_root_sha256": pre_confirm.prereg.parent_root_sha256,
            "confirm_pool_root_sha256": pre_confirm.confirm_pool.content_sha256,
            "active_dev_slots": list(DEV_PRIMARY_SLOTS),
            "active_confirm_slots": list(confirm_slots),
            "failure_slot_id": None if failure is None else failure.slot_id,
            "reserve_activation_test_only": failure is not None,
            "authenticated_failure_evidence": False,
        },
        pre_confirm_phase=True,
    )


def make_test_only_offline_statistics_fixture(units: Sequence[OfflineUnitFixture], component_groups: Mapping[str, Sequence[Sequence[str]]]) -> OfflineStatisticsFixture:
    """Build a TEST_ONLY/OFFLINE conformance bundle with zero authority."""

    if type(units) not in (list, tuple) or len(units) != len(SLOTS):
        raise _fail("VERIFIED_INPUT_INVALID", "offline fixture requires exactly the canonical 16-unit population")
    records = {unit.slot_id: _fixture_record(unit) for unit in units}
    if set(records) != set(SLOTS) or len(records) != len(units):
        raise _fail("VERIFIED_INPUT_INVALID", "offline fixture slots must be unique and complete")
    if len({record["archive_sha256"] for record in records.values()}) != len(SLOTS):
        raise _fail("VERIFIED_INPUT_INVALID", "offline fixture archive identities must be unique")
    identities = _graph_identities(records, component_groups)
    assignment_payload = {
        "identities": identities,
        "archive_sha256s": {slot: records[slot]["archive_sha256"] for slot in SLOTS},
        "binding_spec": "V631_ASSIGNMENT_SUPPORT_CORRECTION",
    }
    feature_payload = {"features": {slot: {"mechanics": records[slot]["mechanics"], "raw_comparator_R": records[slot]["raw_comparator_R"]} for slot in SLOTS}}
    pool_slots = CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)
    campaign_root = canonical_sha256({"model_root_sha256": FROZEN_MODEL_ROOT_SHA256, "assignment": assignment_payload, "local_features": feature_payload, "confirm_pool_slots": list(pool_slots), "offline_fixture_only": True})
    assignment = _artifact(VerifiedPopulationAssignment, _SCHEMA_ASSIGNMENT, campaign_root, assignment_payload, pre_confirm_phase=True)
    features = _artifact(VerifiedLocalFeatures, _SCHEMA_LOCAL_FEATURES, assignment.content_sha256, feature_payload, pre_confirm_phase=True)
    confirm_pool = _artifact(
        VerifiedConfirmPool,
        _SCHEMA_CONFIRM_POOL,
        features.content_sha256,
        {
            "campaign_root_sha256": campaign_root,
            "assignment_root_sha256": assignment.content_sha256,
            "local_features_root_sha256": features.content_sha256,
            "slots": list(pool_slots),
            "archive_sha256s": {slot: records[slot]["archive_sha256"] for slot in pool_slots},
        },
        pre_confirm_phase=True,
    )
    feature_support = _artifact(VerifiedFeatureSupport, _SCHEMA_FEATURE_SUPPORT, confirm_pool.content_sha256, _support_payload(records), pre_confirm_phase=True)
    prereg = _artifact(
        VerifiedCampaignPrereg,
        _SCHEMA_CAMPAIGN_PREREG,
        campaign_root,
        {
            "model_root_sha256": FROZEN_MODEL_ROOT_SHA256,
            "assignment_root_sha256": assignment.content_sha256,
            "local_features_root_sha256": features.content_sha256,
            "confirm_pool_root_sha256": confirm_pool.content_sha256,
            "feature_support_root_sha256": feature_support.content_sha256,
        },
        pre_confirm_phase=True,
    )
    dev_slots = DEV_PRIMARY_SLOTS + (DEV_RESERVE_SLOT,)
    dev_endpoint_payload = {slot: {"yobs_score_points": records[slot]["yobs_score_points"], "poll_receipt_root_sha256": records[slot]["poll_receipt_root_sha256"]} for slot in dev_slots}
    dev_endpoints = _artifact(VerifiedDevEndpoints, _SCHEMA_DEV_ENDPOINTS, prereg.content_sha256, {"campaign_root_sha256": campaign_root, "prereg_root_sha256": prereg.content_sha256, "endpoints": dev_endpoint_payload}, pre_confirm_phase=True)
    integrity = _artifact(
        VerifiedCampaignIntegrity,
        _SCHEMA_CAMPAIGN_INTEGRITY,
        prereg.content_sha256,
        {
            "synthetic_custody_conformance": True,
            "synthetic_regime_conformance": True,
            "synthetic_preregistration_conformance": True,
            "external_evidence_authenticated": False,
        },
        pre_confirm_phase=True,
    )
    pre_confirm = _issue(
        OfflinePreConfirmFixture(
            prereg,
            assignment,
            features,
            confirm_pool,
            feature_support,
            dev_endpoints,
            integrity,
            True,
            True,
            _FIXTURE_SENTINEL,
        ),
        _ISSUED_PRECONFIRM_FIXTURES,
    )
    confirm_outcomes = _issue(OfflineConfirmOutcomeFixture(
        campaign_root,
        confirm_pool.content_sha256,
        freeze({slot: {"yobs_score_points": records[slot]["yobs_score_points"], "poll_receipt_root_sha256": records[slot]["poll_receipt_root_sha256"]} for slot in pool_slots}),
        True,
        False,
        False,
        _CONFIRM_OUTCOME_SENTINEL,
    ), _ISSUED_CONFIRM_OUTCOMES)
    default_active = _active_payload(pre_confirm, CONFIRM_PRIMARY_SLOTS, None)
    return _issue(OfflineStatisticsFixture(pre_confirm, confirm_outcomes, default_active, True, True, _FIXTURE_SENTINEL), _ISSUED_FIXTURES)


def make_test_only_offline_reserve_failure_fixture(fixture: OfflineStatisticsFixture, slot_id: str) -> TestOnlyOfflineReserveFailureFixture:
    """Create simulated reserve-failure input; it is not ledger evidence."""

    fixture = _verify_offline_fixture(fixture)
    if type(slot_id) is not str or slot_id not in CONFIRM_PRIMARY_SLOTS:
        raise _fail("VERIFIED_INPUT_INVALID", "only a CONFIRM primary can have a reserve-eligible fixture failure")
    return _issue(
        TestOnlyOfflineReserveFailureFixture(
            fixture.pre_confirm.prereg.parent_root_sha256,
            slot_id,
            "TEST_ONLY_OFFLINE_PRE_MATURITY_FAILURE_SIMULATION",
            True,
            True,
            False,
            _FAILURE_SENTINEL,
        ),
        _ISSUED_FAILURES,
    )


def make_test_only_offline_active_set(fixture: OfflineStatisticsFixture, failure: TestOnlyOfflineReserveFailureFixture | None = None) -> VerifiedActiveSet:
    """Create one TEST_ONLY/OFFLINE active set with no reserve authority."""

    fixture = _verify_offline_fixture(fixture)
    pre_confirm = fixture.pre_confirm
    campaign_root = pre_confirm.prereg.parent_root_sha256
    if failure is None:
        return fixture.default_active_set
    if type(failure) is not TestOnlyOfflineReserveFailureFixture:
        raise _fail("VERIFIED_INPUT_INVALID", "reserve simulation requires one typed TEST_ONLY/OFFLINE failure fixture")
    _require_issued(failure, _ISSUED_FAILURES, "TEST_ONLY/OFFLINE reserve-failure fixture")
    if (
        failure.campaign_root_sha256 != campaign_root
        or failure.before_mature_poll is not True
        or failure.reason != "TEST_ONLY_OFFLINE_PRE_MATURITY_FAILURE_SIMULATION"
        or failure.test_only is not True
        or failure.authenticated_failure_evidence is not False
    ):
        raise _fail("VERIFIED_INPUT_INVALID", "reserve simulation requires one intact TEST_ONLY/OFFLINE failure fixture")
    active = tuple(slot for slot in CONFIRM_PRIMARY_SLOTS if slot != failure.slot_id) + (CONFIRM_RESERVE_SLOT,)
    return _active_payload(pre_confirm, active, failure)


def _verify_pre_confirm(value: Any) -> OfflinePreConfirmFixture:
    if type(value) is not OfflinePreConfirmFixture:
        raise _fail("VERIFIED_INPUT_INVALID", "pre-CONFIRM statistics functions reject aggregate fixtures, CONFIRM outcomes, raw arrays, and plain dictionaries")
    _require_issued(value, _ISSUED_PRECONFIRM_FIXTURES, "pre-CONFIRM fixture")
    fixture = value
    if fixture.test_only is not True or fixture.offline_conformance_only is not True:
        raise _fail("VERIFIED_INPUT_INVALID", "pre-CONFIRM fixture must remain TEST_ONLY/OFFLINE")
    prereg = _verify_artifact(fixture.prereg, VerifiedCampaignPrereg, _SCHEMA_CAMPAIGN_PREREG, pre_confirm_phase=True)
    assignment = _verify_artifact(fixture.assignment, VerifiedPopulationAssignment, _SCHEMA_ASSIGNMENT, parent_root=prereg.parent_root_sha256, pre_confirm_phase=True)
    features = _verify_artifact(fixture.local_features, VerifiedLocalFeatures, _SCHEMA_LOCAL_FEATURES, parent_root=assignment.content_sha256, pre_confirm_phase=True)
    pool = _verify_artifact(fixture.confirm_pool, VerifiedConfirmPool, _SCHEMA_CONFIRM_POOL, parent_root=features.content_sha256, pre_confirm_phase=True)
    support = _verify_artifact(fixture.feature_support, VerifiedFeatureSupport, _SCHEMA_FEATURE_SUPPORT, parent_root=pool.content_sha256, pre_confirm_phase=True)
    expected_prereg = {
        **_OFFLINE_ARTIFACT_STATUS,
        "model_root_sha256": FROZEN_MODEL_ROOT_SHA256,
        "assignment_root_sha256": assignment.content_sha256,
        "local_features_root_sha256": features.content_sha256,
        "confirm_pool_root_sha256": pool.content_sha256,
        "feature_support_root_sha256": support.content_sha256,
    }
    if dict(prereg.payload) != expected_prereg:
        raise _fail("VERIFIED_INPUT_INVALID", "preregistration does not bind the exact model, assignment, local features, CONFIRM pool, and support roots")
    if pool.payload["campaign_root_sha256"] != prereg.parent_root_sha256 or pool.payload["assignment_root_sha256"] != assignment.content_sha256 or pool.payload["local_features_root_sha256"] != features.content_sha256 or tuple(pool.payload["slots"]) != CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,):
        raise _fail("VERIFIED_INPUT_INVALID", "active nine-unit CONFIRM pool is stale or cross-campaign")
    dev_endpoints = _verify_artifact(fixture.dev_endpoints, VerifiedDevEndpoints, _SCHEMA_DEV_ENDPOINTS, parent_root=prereg.content_sha256, pre_confirm_phase=True)
    if dev_endpoints.payload["campaign_root_sha256"] != prereg.parent_root_sha256 or dev_endpoints.payload["prereg_root_sha256"] != prereg.content_sha256 or set(dev_endpoints.payload["endpoints"]) != set(DEV_PRIMARY_SLOTS + (DEV_RESERVE_SLOT,)):
        raise _fail("VERIFIED_INPUT_INVALID", "DEV endpoints are not exactly bound to this campaign and preregistration")
    expected_support = {**_OFFLINE_ARTIFACT_STATUS, **_support_payload(fixture.local_features.payload["features"])}
    if canonical_sha256(support.payload) != canonical_sha256(expected_support):
        raise _fail("VERIFIED_INPUT_INVALID", "offline support artifact must retain the pending assignment-module declaration")
    integrity = _verify_artifact(fixture.integrity, VerifiedCampaignIntegrity, _SCHEMA_CAMPAIGN_INTEGRITY, parent_root=prereg.content_sha256, pre_confirm_phase=True)
    expected_integrity = {
        **_OFFLINE_ARTIFACT_STATUS,
        "synthetic_custody_conformance": True,
        "synthetic_regime_conformance": True,
        "synthetic_preregistration_conformance": True,
        "external_evidence_authenticated": False,
    }
    if dict(integrity.payload) != expected_integrity:
        raise _fail("VERIFIED_INPUT_INVALID", "TEST_ONLY/OFFLINE integrity conformance cannot claim external evidence")
    return fixture


def _verify_offline_fixture(value: Any) -> OfflineStatisticsFixture:
    if type(value) is not OfflineStatisticsFixture:
        raise _fail("VERIFIED_INPUT_INVALID", "offline fixture bundle is required")
    _require_issued(value, _ISSUED_FIXTURES, "offline fixture bundle")
    if value.test_only is not True or value.offline_conformance_only is not True:
        raise _fail("VERIFIED_INPUT_INVALID", "fixture bundle must remain TEST_ONLY/OFFLINE")
    pre_confirm = _verify_pre_confirm(value.pre_confirm)
    outcomes = value.confirm_outcomes
    if type(outcomes) is not OfflineConfirmOutcomeFixture:
        raise _fail("VERIFIED_INPUT_INVALID", "offline CONFIRM outcomes are not a typed issued fixture")
    _require_issued(outcomes, _ISSUED_CONFIRM_OUTCOMES, "offline CONFIRM outcomes")
    if outcomes.test_only is not True or outcomes.authenticated_endpoint_evidence is not False or outcomes.leakage_marked is not False:
        raise _fail("VERIFIED_INPUT_INVALID", "offline CONFIRM outcomes cannot claim authentication or carry a leakage mark")
    if outcomes.campaign_root_sha256 != pre_confirm.prereg.parent_root_sha256 or outcomes.confirm_pool_root_sha256 != pre_confirm.confirm_pool.content_sha256 or set(outcomes.endpoints) != set(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)):
        raise _fail("VERIFIED_INPUT_INVALID", "offline CONFIRM outcomes are stale or cross-campaign")
    _verify_active(value.default_active_set, pre_confirm)
    return value


def _verify_active(value: Any, pre_confirm: OfflinePreConfirmFixture) -> VerifiedActiveSet:
    active = _verify_artifact(value, VerifiedActiveSet, _SCHEMA_ACTIVE_SET, parent_root=pre_confirm.confirm_pool.content_sha256, pre_confirm_phase=True)
    if active.payload["campaign_root_sha256"] != pre_confirm.prereg.parent_root_sha256 or active.payload["confirm_pool_root_sha256"] != pre_confirm.confirm_pool.content_sha256:
        raise _fail("VERIFIED_INPUT_INVALID", "active set is stale or cross-campaign")
    if tuple(active.payload["active_dev_slots"]) != DEV_PRIMARY_SLOTS:
        raise _fail("VERIFIED_INPUT_INVALID", "active DEV set must be exactly D01-D06")
    confirm = tuple(active.payload["active_confirm_slots"])
    failure_slot = active.payload["failure_slot_id"]
    expected = CONFIRM_PRIMARY_SLOTS if failure_slot is None else tuple(slot for slot in CONFIRM_PRIMARY_SLOTS if slot != failure_slot) + (CONFIRM_RESERVE_SLOT,)
    if confirm != expected or len(confirm) != 8 or len(set(confirm)) != 8:
        raise _fail("VERIFIED_INPUT_INVALID", "active CONFIRM set is not the default eight or the sole typed reserve substitution")
    if active.payload["reserve_activation_test_only"] is not (failure_slot is not None) or active.payload["authenticated_failure_evidence"] is not False:
        raise _fail("VERIFIED_INPUT_INVALID", "offline active set cannot represent authenticated reserve evidence")
    return active


def _identity(fixture: OfflinePreConfirmFixture, slot: str) -> Mapping[str, str]:
    return fixture.assignment.payload["identities"][slot]


def _feature_vector(fixture: OfflinePreConfirmFixture, slot: str) -> tuple[tuple[gmpy2.mpfr, ...], gmpy2.mpfr, gmpy2.mpfr]:
    row = fixture.local_features.payload["features"][slot]
    mechanics = row["mechanics"]
    if set(mechanics) != set(FEATURE_NAMES):
        raise _fail("VERIFIED_INPUT_INVALID", "raw arrays and non-exact mechanics objects are forbidden")
    values = tuple(_mp(_decimal(mechanics[name], f"{slot}.{name}", minimum=Decimal(-1), maximum=Decimal(1))) for name in FEATURE_NAMES)
    if set(row) != {"mechanics", "raw_comparator_R"}:
        raise _fail("VERIFIED_INPUT_INVALID", "local feature rows must contain only the mechanics object and transformed comparator R")
    raw = _mp(_decimal(row["raw_comparator_R"], f"{slot}.R", minimum=Decimal(-1), maximum=Decimal(1)))
    return values, sum(values, _mp(0)) / 6, raw


def _feature(fixture: OfflinePreConfirmFixture, slot: str) -> tuple[gmpy2.mpfr, gmpy2.mpfr]:
    _, composite, raw = _feature_vector(fixture, slot)
    return composite, raw


def _outcome(fixture: OfflinePreConfirmFixture, slot: str) -> gmpy2.mpfr:
    row = fixture.dev_endpoints.payload["endpoints"][slot]
    return _mp(_decimal(row["yobs_score_points"], f"{slot}.Yobs"))


def _fit_nig(rows: Sequence[tuple[gmpy2.mpfr, gmpy2.mpfr]]) -> dict[str, gmpy2.mpfr]:
    if len(rows) < MIN_FIT_OBSERVATIONS:
        raise _fail("INVALID_DEV_FOLD", "each NIG fit requires at least four observations")
    one, nine = _mp(1), _mp(9)
    a00 = one / nine + len(rows)
    a01 = sum((x for x, _ in rows), _mp(0))
    a11 = one / nine + sum((x * x for x, _ in rows), _mp(0))
    determinant = a00 * a11 - a01 * a01
    if determinant <= 0:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "NIG posterior precision is singular")
    trace = a00 + a11
    discriminant = gmpy2.sqrt((a00 - a11) * (a00 - a11) + 4 * a01 * a01)
    smallest = (trace - discriminant) / 2
    largest = (trace + discriminant) / 2
    if smallest <= 0 or largest / smallest > _mp(MAX_CONDITION_NUMBER):
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "NIG posterior precision condition number exceeds 1e12")
    v00, v01, v11 = a11 / determinant, -a01 / determinant, a00 / determinant
    rhs0 = sum((y for _, y in rows), _mp(0))
    rhs1 = sum((x * y for x, y in rows), _mp(0))
    m0, m1 = v00 * rhs0 + v01 * rhs1, v01 * rhs0 + v11 * rhs1
    yty = sum((y * y for _, y in rows), _mp(0))
    quadratic = m0 * (a00 * m0 + a01 * m1) + m1 * (a01 * m0 + a11 * m1)
    an = _mp(A0) + _mp(len(rows)) / 2
    bn = _mp(B0) + (yty - quadratic) / 2
    if not gmpy2.is_finite(bn) or bn <= 0:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "NIG posterior bn must be finite and positive")
    scale = gmpy2.sqrt((bn / an) * v11)
    if scale <= 0 or not gmpy2.is_finite(scale):
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "NIG beta marginal scale is invalid")
    probability = 1 - _student_t_cdf((-m1) / scale, 2 * an)
    if not gmpy2.is_finite(probability) or probability < 0 or probability > 1:
        raise _fail("STATISTICS_NUMERIC_DIVERGENCE", "NIG beta posterior probability is invalid")
    return {"alpha": m0, "beta": m1, "an": an, "bn": bn, "v_beta_beta": v11, "beta_positive_probability": probability}


def _prediction(fit: Mapping[str, gmpy2.mpfr], x: gmpy2.mpfr) -> gmpy2.mpfr:
    return _mp(Y_SCALE) * (fit["alpha"] + fit["beta"] * x)


def _frozen_fit_coefficients(payload: Mapping[str, Any], prefix: str) -> dict[str, gmpy2.mpfr]:
    rounded = payload.get(f"{prefix}_fit")
    exact = payload.get(f"{prefix}_fit_mpfr_hex")
    expected = {"alpha", "beta", "an", "bn", "v_beta_beta", "beta_positive_probability"}
    if not isinstance(rounded, Mapping) or not isinstance(exact, Mapping) or set(rounded) != expected or set(exact) != expected:
        raise _fail("VERIFIED_INPUT_INVALID", f"{prefix} DEV fit lacks the complete frozen representation")
    parsed = {key: _mpfr_exact(exact[key], f"{prefix} fit {key}") for key in expected}
    if any(rounded[key] != _text(parsed[key], PROBABILITY_SERIAL_PLACES) for key in expected):
        raise _fail("VERIFIED_INPUT_INVALID", f"{prefix} DEV fit rounded fields do not match the frozen MPFR values")
    return {key: parsed[key] for key in ("alpha", "beta")}


def _population_checks(fixture: OfflinePreConfirmFixture, active: VerifiedActiveSet | None = None) -> None:
    dev = DEV_PRIMARY_SLOTS
    confirm_pool = CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)
    dev_all = DEV_PRIMARY_SLOTS + (DEV_RESERVE_SLOT,)
    for key in ("source_component_id", "lineage_time_component_id", "development_control_component_id"):
        if len({_identity(fixture, slot)[key] for slot in dev}) < 4:
            raise _fail("VERIFIED_INPUT_INVALID", f"active DEV requires at least four {key} values")
        if len({_identity(fixture, slot)[key] for slot in confirm_pool}) != len(confirm_pool):
            raise _fail("VERIFIED_INPUT_INVALID", f"the nine-unit CONFIRM pool must be pairwise distinct by {key}")
        if {_identity(fixture, slot)[key] for slot in confirm_pool}.intersection({_identity(fixture, slot)[key] for slot in dev_all}):
            raise _fail("VERIFIED_INPUT_INVALID", f"CONFIRM {key} values must be unseen in every DEV reserve scenario")
    source_counts = {}
    for slot in dev:
        source = _identity(fixture, slot)["source_component_id"]
        source_counts[source] = source_counts.get(source, 0) + 1
    if max(source_counts.values()) > 2 or len({_identity(fixture, slot)["intervention_component_id"] for slot in dev}) < 3:
        raise _fail("VERIFIED_INPUT_INVALID", "active DEV family balance/intervention requirements fail")
    allowed_confirm_sets = (CONFIRM_PRIMARY_SLOTS,) + tuple(tuple(slot for slot in CONFIRM_PRIMARY_SLOTS if slot != failed) + (CONFIRM_RESERVE_SLOT,) for failed in CONFIRM_PRIMARY_SLOTS)
    if any(len({_identity(fixture, slot)["intervention_component_id"] for slot in scenario}) < 4 for scenario in allowed_confirm_sets) or len({_identity(fixture, slot)["intervention_component_id"] for slot in SLOTS}) < 5:
        raise _fail("VERIFIED_INPUT_INVALID", "CONFIRM/full-population intervention requirements fail")
    if active is not None and len({_identity(fixture, slot)["intervention_component_id"] for slot in active.payload["active_confirm_slots"]}) < 4:
        raise _fail("VERIFIED_INPUT_INVALID", "active CONFIRM intervention support fails")

    feature_rows = {slot: fixture.local_features.payload["features"][slot] for slot in SLOTS}
    expected_support = {**_OFFLINE_ARTIFACT_STATUS, **_support_payload(feature_rows)}
    if canonical_sha256(fixture.feature_support.payload) != canonical_sha256(expected_support):
        raise _fail("VERIFIED_INPUT_INVALID", "pending assignment-support declaration does not match the frozen model")
    for slot in SLOTS:
        _feature_vector(fixture, slot)


def _report(schema: str, state: str, detail: str, extra: Mapping[str, Any]) -> Mapping[str, Any]:
    protected = {
        "feature_spec_complete",
        "assignment_support_authenticated",
        "independent_ab_numeric_agreement_verified",
        "bootstrap_support_10000_verified",
        "timestamp_evidence_verified",
        "predictive_validity_established",
        "authenticated_statistics_composer_present",
        "test_only",
        "offline_conformance_only",
    }
    if protected.intersection(extra):
        raise ValueError("callers cannot override authenticated numeric/support status")
    report = zero_authority(
        state,
        detail=detail,
        extra={
            "research_only": True,
            "test_only": True,
            "offline_conformance_only": True,
            "verdict": state,
            "feature_spec_complete": False,
            "assignment_support_authenticated": False,
            "independent_ab_numeric_agreement_verified": False,
            "bootstrap_support_10000_verified": False,
            "timestamp_evidence_verified": False,
            "predictive_validity_established": False,
            "authenticated_statistics_composer_present": False,
            **dict(extra),
        },
    )
    report["schema"] = schema
    report["content_sha256"] = canonical_sha256(report)
    return freeze(report)


def statistics_readiness_gate() -> Mapping[str, Any]:
    """Return the only public v6.3.1 statistics readiness state currently possible."""

    state = "FEATURE_ASSIGNMENT_AUTHENTICATION_INCOMPLETE"
    report = zero_authority(
        state,
        detail="exact feature assignment/support and authenticated phase-separated evidence are unavailable",
        extra={
            "verdict": state,
            "research_only": True,
            "binding_spec": "V631_ASSIGNMENT_SUPPORT_CORRECTION",
            "model_root_sha256": FROZEN_MODEL_ROOT_SHA256,
            "feature_spec_complete": False,
            "assignment_support_authenticated": False,
            "assignment_support_criterion_available": False,
            "independent_ab_numeric_agreement_verified": False,
            "bootstrap_support_10000_verified": False,
            "timestamp_evidence_verified": False,
            "predictive_validity_established": False,
            "externally_signed_time_bound_preconfirm_received": False,
            "separately_received_confirm_endpoints_received": False,
            "authenticated_statistics_composer_present": False,
        },
    )
    report["schema"] = "eval.v6.3.1.statistics.public-readiness"
    report["content_sha256"] = canonical_sha256(report)
    return freeze(report)


def _invalid_dev(code: str, message: str) -> DevNumericAnalysis:
    state = _OFFLINE_NUMERIC_DIVERGENCE if code == "STATISTICS_NUMERIC_DIVERGENCE" else _OFFLINE_INPUT_INVALID
    return _issue(DevNumericAnalysis(state, _report(_SCHEMA_DEV_RESULT, state, message, {"reason_code": code}), None, _RESULT_SENTINEL), _ISSUED_RESULTS)


def _evaluate_dev(value: Any) -> DevNumericAnalysis:
    """Run typed TEST_ONLY/OFFLINE NIG DEV threshold diagnostics."""

    try:
        _require_runtime()
        fixture = _verify_pre_confirm(value)
        _population_checks(fixture)
        dev = DEV_PRIMARY_SLOTS
        source_groups: dict[str, tuple[str, ...]] = {}
        for slot in dev:
            component = _identity(fixture, slot)["source_component_id"]
            source_groups[component] = tuple(item for item in dev if _identity(fixture, item)["source_component_id"] == component)
        folds = []
        mechanics_total = raw_total = _mp(0)
        unit_wins = family_wins = 0
        for component, held in sorted(source_groups.items()):
            training = tuple(slot for slot in dev if slot not in held)
            if len(training) < 4 or len({_identity(fixture, slot)["source_component_id"] for slot in training}) < 3:
                raise _fail("INVALID_DEV_FOLD", "LOSO fold needs four training units from three source components")
            mechanics_fit = _fit_nig([(_feature(fixture, slot)[0], _outcome(fixture, slot) / _mp(Y_SCALE)) for slot in training])
            raw_fit = _fit_nig([(_feature(fixture, slot)[1], _outcome(fixture, slot) / _mp(Y_SCALE)) for slot in training])
            family_mechanics = family_raw = _mp(0)
            members = []
            for slot in held:
                outcome = _outcome(fixture, slot)
                mechanics_error = abs(outcome - _prediction(mechanics_fit, _feature(fixture, slot)[0]))
                raw_error = abs(outcome - _prediction(raw_fit, _feature(fixture, slot)[1]))
                mechanics_total += mechanics_error
                raw_total += raw_error
                family_mechanics += mechanics_error
                family_raw += raw_error
                win = raw_error - mechanics_error >= _mp(WIN_MARGIN_POINTS)
                unit_wins += int(win)
                members.append({"slot_id": slot, "mechanics_absolute_error": _text(mechanics_error, SCORE_SERIAL_PLACES), "raw_absolute_error": _text(raw_error, SCORE_SERIAL_PLACES), "mechanics_win": win})
            family_win = family_raw / len(held) - family_mechanics / len(held) >= _mp(WIN_MARGIN_POINTS)
            family_wins += int(family_win)
            folds.append({"source_component_id": component, "held_out_slots": list(held), "members": members, "family_mechanics_win": family_win})
        full_mechanics = _fit_nig([(_feature(fixture, slot)[0], _outcome(fixture, slot) / _mp(Y_SCALE)) for slot in dev])
        full_raw = _fit_nig([(_feature(fixture, slot)[1], _outcome(fixture, slot) / _mp(Y_SCALE)) for slot in dev])
        ratio = _ratio(mechanics_total, raw_total)
        families_required = math.ceil(2 * len(source_groups) / 3)
        passes = unit_wins >= DEV_UNIT_WINS_MINIMUM and family_wins >= families_required and (ratio is not None and ratio <= _mp(DEV_RATIO_MAXIMUM)) and full_mechanics["beta_positive_probability"] >= _mp(DEV_BETA_PROBABILITY_MINIMUM)
        constant = sum((_outcome(fixture, slot) for slot in dev), _mp(0)) / len(dev)
        fit_payload = {
            "model_root_sha256": FROZEN_MODEL_ROOT_SHA256,
            "campaign_root_sha256": fixture.prereg.parent_root_sha256,
            "prereg_root_sha256": fixture.prereg.content_sha256,
            "assignment_root_sha256": fixture.assignment.content_sha256,
            "local_features_root_sha256": fixture.local_features.content_sha256,
            "dev_endpoints_root_sha256": fixture.dev_endpoints.content_sha256,
            "confirm_pool_root_sha256": fixture.confirm_pool.content_sha256,
            "feature_support_root_sha256": fixture.feature_support.content_sha256,
            "active_dev_slots": list(dev),
            "folds": folds,
            "mechanics_fit": {key: _text(item, PROBABILITY_SERIAL_PLACES) for key, item in full_mechanics.items()},
            "raw_fit": {key: _text(item, PROBABILITY_SERIAL_PLACES) for key, item in full_raw.items()},
            "mechanics_fit_mpfr_hex": {key: _mpfr_exact_text(item) for key, item in full_mechanics.items()},
            "raw_fit_mpfr_hex": {key: _mpfr_exact_text(item) for key, item in full_raw.items()},
            "dev_constant_prediction_points": _text(constant, SCORE_SERIAL_PLACES),
            "dev_constant_prediction_mpfr_hex": _mpfr_exact_text(constant),
            "metrics": {"unit_wins": unit_wins, "family_wins": family_wins, "family_wins_required": families_required, "source_component_count": len(source_groups), "oof_mechanics_total_absolute_error": _text(mechanics_total, SCORE_SERIAL_PLACES), "oof_raw_total_absolute_error": _text(raw_total, SCORE_SERIAL_PLACES), "oof_ratio": "Infinity" if ratio is None else _text(ratio, RATIO_SERIAL_PLACES), "posterior_beta_positive_probability": _text(full_mechanics["beta_positive_probability"], PROBABILITY_SERIAL_PLACES)},
        }
        verified_fit = _artifact(VerifiedDevFit, _SCHEMA_DEV_FIT, fixture.dev_endpoints.content_sha256, fit_payload, pre_confirm_phase=True)
        state = _OFFLINE_DEV_THRESHOLDS_MET if passes else _OFFLINE_DEV_THRESHOLDS_NOT_MET
        hidden_exact_fields = {"mechanics_fit_mpfr_hex", "raw_fit_mpfr_hex", "dev_constant_prediction_mpfr_hex"}
        report_payload = {
            key: item
            for key, item in fit_payload.items()
            if key not in {"independent_ab_numeric_agreement_verified", "bootstrap_support_10000_verified", *hidden_exact_fields}
        }
        report = _report(_SCHEMA_DEV_RESULT, state, "closed-form NIG TEST_ONLY/OFFLINE DEV threshold diagnostics", {"model_root_sha256": FROZEN_MODEL_ROOT_SHA256, "dev_fit_root_sha256": verified_fit.content_sha256, **report_payload})
        return _issue(DevNumericAnalysis(state, report, verified_fit, _RESULT_SENTINEL), _ISSUED_RESULTS)
    except StatisticsValidationError as exc:
        return _invalid_dev(exc.code, str(exc))


def evaluate_dev(value: Any) -> DevNumericAnalysis:
    """Run the complete DEV numerical core under frozen MPFR context."""

    with gmpy2.context(_ctx()):
        return _evaluate_dev(value)


def _preconfirm_bindings(fixture: OfflinePreConfirmFixture) -> dict[str, str]:
    return {
        "model_root_sha256": FROZEN_MODEL_ROOT_SHA256,
        "campaign_root_sha256": fixture.prereg.parent_root_sha256,
        "prereg_root_sha256": fixture.prereg.content_sha256,
        "assignment_root_sha256": fixture.assignment.content_sha256,
        "local_features_root_sha256": fixture.local_features.content_sha256,
        "dev_endpoints_root_sha256": fixture.dev_endpoints.content_sha256,
        "confirm_pool_root_sha256": fixture.confirm_pool.content_sha256,
        "feature_support_root_sha256": fixture.feature_support.content_sha256,
    }


def _freeze_confirm_predictions(dev: Any, fixture_value: Any) -> ConfirmPredictionFreeze:
    """Freeze all nine CONFIRM predictions from a typed numeric DEV fit only."""

    try:
        _require_runtime()
        if type(dev) is not DevNumericAnalysis:
            raise _fail("VERIFIED_INPUT_INVALID", "prediction freezing requires a typed favorable TEST_ONLY/OFFLINE DEV diagnostic")
        _require_issued(dev, _ISSUED_RESULTS, "DEV numeric result")
        if dev.verdict != _OFFLINE_DEV_THRESHOLDS_MET or dev.verified_fit is None:
            raise _fail("VERIFIED_INPUT_INVALID", "prediction freezing requires a typed favorable TEST_ONLY/OFFLINE DEV diagnostic")
        fixture = _verify_pre_confirm(fixture_value)
        fit = _verify_artifact(dev.verified_fit, VerifiedDevFit, _SCHEMA_DEV_FIT, parent_root=fixture.dev_endpoints.content_sha256, pre_confirm_phase=True)
        bindings = _preconfirm_bindings(fixture)
        if any(fit.payload.get(name) != root for name, root in bindings.items()):
            raise _fail("VERIFIED_INPUT_INVALID", "DEV fit is stale or substituted across campaign/preregistration roots")
        if fit.payload.get("independent_ab_numeric_agreement_verified") is not False or fit.payload.get("bootstrap_support_10000_verified") is not False:
            raise _fail("VERIFIED_INPUT_INVALID", "offline DEV fit cannot claim A/B numeric agreement or 10,000-bootstrap support")
        _population_checks(fixture)
        mechanics = _frozen_fit_coefficients(fit.payload, "mechanics")
        raw = _frozen_fit_coefficients(fit.payload, "raw")
        constant_value = _mpfr_exact(fit.payload.get("dev_constant_prediction_mpfr_hex"), "DEV constant prediction")
        if _text(constant_value, SCORE_SERIAL_PLACES) != fit.payload.get("dev_constant_prediction_points"):
            raise _fail("VERIFIED_INPUT_INVALID", "rounded DEV constant is inconsistent with its full-precision value")
        predictions = {}
        reported_predictions = {}
        for slot in CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,):
            mechanics_value = _prediction(mechanics, _feature(fixture, slot)[0])
            raw_value = _prediction(raw, _feature(fixture, slot)[1])
            rounded = {
                "mechanics_prediction_points": _text(mechanics_value, SCORE_SERIAL_PLACES),
                "raw_prediction_points": _text(raw_value, SCORE_SERIAL_PLACES),
                "dev_constant_prediction_points": _text(constant_value, SCORE_SERIAL_PLACES),
            }
            predictions[slot] = {
                **rounded,
                "mechanics_prediction_mpfr_hex": _mpfr_exact_text(mechanics_value),
                "raw_prediction_mpfr_hex": _mpfr_exact_text(raw_value),
                "dev_constant_prediction_mpfr_hex": _mpfr_exact_text(constant_value),
            }
            reported_predictions[slot] = rounded
        freeze_input_root = canonical_sha256({"schema": "eval.v6.3.1.prediction-freeze-inputs", **bindings, "dev_fit_root_sha256": fit.content_sha256, "all_nine_confirm_slots": list(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,))})
        payload = {
            **bindings,
            "dev_fit_root_sha256": fit.content_sha256,
            "freeze_input_root_sha256": freeze_input_root,
            "predictions": predictions,
            "all_nine_confirm_slots": list(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)),
        }
        verified = _artifact(VerifiedConfirmPredictions, _SCHEMA_PREDICTIONS, freeze_input_root, payload, pre_confirm_phase=True)
        state = _OFFLINE_PREDICTIONS_FROZEN
        report_payload = {
            key: item
            for key, item in payload.items()
            if key not in {"independent_ab_numeric_agreement_verified", "bootstrap_support_10000_verified", "predictions"}
        }
        report = _report(
            _SCHEMA_PREDICTION_RESULT,
            state,
            "nine TEST_ONLY/OFFLINE prediction diagnostics frozen without access to CONFIRM outcomes",
            {"prediction_root_sha256": verified.content_sha256, **report_payload, "predictions": reported_predictions},
        )
        return _issue(ConfirmPredictionFreeze(state, report, verified, _RESULT_SENTINEL), _ISSUED_RESULTS)
    except StatisticsValidationError as exc:
        state = _OFFLINE_NUMERIC_DIVERGENCE if exc.code == "STATISTICS_NUMERIC_DIVERGENCE" else _OFFLINE_INPUT_INVALID
        return _issue(ConfirmPredictionFreeze(state, _report(_SCHEMA_PREDICTION_RESULT, state, str(exc), {"reason_code": exc.code}), None, _RESULT_SENTINEL), _ISSUED_RESULTS)


def freeze_confirm_predictions(dev: Any, fixture_value: Any) -> ConfirmPredictionFreeze:
    """Freeze predictions under the frozen MPFR context."""

    with gmpy2.context(_ctx()):
        return _freeze_confirm_predictions(dev, fixture_value)


def _verify_predictions(value: Any, fixture: OfflinePreConfirmFixture) -> VerifiedConfirmPredictions:
    if type(value) is not ConfirmPredictionFreeze:
        raise _fail("VERIFIED_INPUT_INVALID", "CONFIRM analysis requires typed frozen predictions")
    _require_issued(value, _ISSUED_RESULTS, "prediction-freeze result")
    if value.verified_predictions is None or value.verdict != _OFFLINE_PREDICTIONS_FROZEN:
        raise _fail("VERIFIED_INPUT_INVALID", "CONFIRM analysis requires typed frozen predictions")
    predictions = _verify_artifact(value.verified_predictions, VerifiedConfirmPredictions, _SCHEMA_PREDICTIONS, pre_confirm_phase=True)
    bindings = _preconfirm_bindings(fixture)
    expected_freeze_root = canonical_sha256({"schema": "eval.v6.3.1.prediction-freeze-inputs", **bindings, "dev_fit_root_sha256": predictions.payload["dev_fit_root_sha256"], "all_nine_confirm_slots": list(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,))})
    if predictions.parent_root_sha256 != expected_freeze_root or predictions.payload["freeze_input_root_sha256"] != expected_freeze_root:
        raise _fail("VERIFIED_INPUT_INVALID", "prediction freeze input root is stale or cross-campaign")
    if any(predictions.payload.get(name) != root for name, root in bindings.items()) or tuple(predictions.payload["all_nine_confirm_slots"]) != CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,) or set(predictions.payload["predictions"]) != set(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)):
        raise _fail("VERIFIED_INPUT_INVALID", "prediction table does not bind the exact campaign/preregistration inputs and active nine-unit pool")
    if predictions.payload.get("independent_ab_numeric_agreement_verified") is not False or predictions.payload.get("bootstrap_support_10000_verified") is not False:
        raise _fail("VERIFIED_INPUT_INVALID", "offline prediction freeze cannot claim A/B numeric agreement or 10,000-bootstrap support")
    for slot, row in predictions.payload["predictions"].items():
        expected_fields = {
            "mechanics_prediction_points": "mechanics_prediction_mpfr_hex",
            "raw_prediction_points": "raw_prediction_mpfr_hex",
            "dev_constant_prediction_points": "dev_constant_prediction_mpfr_hex",
        }
        if not isinstance(row, Mapping) or set(row) != set(expected_fields).union(expected_fields.values()):
            raise _fail("VERIFIED_INPUT_INVALID", f"{slot} prediction row has an invalid frozen representation")
        for rounded_field, exact_field in expected_fields.items():
            exact = _mpfr_exact(row[exact_field], f"{slot}.{exact_field}")
            if row[rounded_field] != _text(exact, SCORE_SERIAL_PLACES):
                raise _fail("VERIFIED_INPUT_INVALID", f"{slot}.{rounded_field} is not report-only rounding of the frozen MPFR value")
    return predictions


def make_test_only_offline_confirm_endpoints(fixture_value: Any, prediction_value: Any) -> VerifiedConfirmEndpoints:
    """Create TEST_ONLY/OFFLINE later outcomes after the exact prediction freeze."""

    fixture = _verify_offline_fixture(fixture_value)
    pre_confirm = fixture.pre_confirm
    predictions = _verify_predictions(prediction_value, pre_confirm)
    payload = {
        "campaign_root_sha256": pre_confirm.prereg.parent_root_sha256,
        "prereg_root_sha256": pre_confirm.prereg.content_sha256,
        "confirm_pool_root_sha256": pre_confirm.confirm_pool.content_sha256,
        "prediction_root_sha256": predictions.content_sha256,
        "received_after_prediction_freeze": True,
        "leakage_marked": False,
        "authenticated_endpoint_evidence": False,
        "endpoints": fixture.confirm_outcomes.endpoints,
    }
    return _artifact(VerifiedConfirmEndpoints, _SCHEMA_CONFIRM_ENDPOINTS, predictions.content_sha256, payload, pre_confirm_phase=False)


def _verify_confirm_endpoints(value: Any, predictions: VerifiedConfirmPredictions, fixture: OfflinePreConfirmFixture) -> VerifiedConfirmEndpoints:
    endpoints = _verify_artifact(value, VerifiedConfirmEndpoints, _SCHEMA_CONFIRM_ENDPOINTS, parent_root=predictions.content_sha256, pre_confirm_phase=False)
    if endpoints.payload["campaign_root_sha256"] != fixture.prereg.parent_root_sha256 or endpoints.payload["prereg_root_sha256"] != fixture.prereg.content_sha256 or endpoints.payload["confirm_pool_root_sha256"] != fixture.confirm_pool.content_sha256 or endpoints.payload["prediction_root_sha256"] != predictions.content_sha256 or set(endpoints.payload["endpoints"]) != set(CONFIRM_PRIMARY_SLOTS + (CONFIRM_RESERVE_SLOT,)):
        raise _fail("VERIFIED_INPUT_INVALID", "CONFIRM endpoints are stale, pre-freeze, incomplete, or cross-campaign")
    if endpoints.payload["received_after_prediction_freeze"] is not True or endpoints.payload["leakage_marked"] is not False or endpoints.payload["authenticated_endpoint_evidence"] is not False:
        raise _fail("VERIFIED_INPUT_INVALID", "TEST_ONLY/OFFLINE CONFIRM endpoints are phase-invalid, leakage-marked, or falsely authenticated")
    return endpoints


def _evaluate_confirm(prediction_value: Any, fixture_value: Any, endpoint_value: Any, active_value: Any) -> ConfirmNumericAnalysis:
    """Evaluate the sole typed active set as TEST_ONLY/OFFLINE diagnostics."""

    try:
        _require_runtime()
        fixture = _verify_pre_confirm(fixture_value)
        active = _verify_active(active_value, fixture)
        _population_checks(fixture, active)
        predictions = _verify_predictions(prediction_value, fixture)
        endpoints = _verify_confirm_endpoints(endpoint_value, predictions, fixture)
        slots = tuple(active.payload["active_confirm_slots"])
        if len(slots) != 8:
            return _issue(ConfirmNumericAnalysis(_OFFLINE_SIGN_TEST_NOT_EVALUABLE, _report(_SCHEMA_CONFIRM_RESULT, _OFFLINE_SIGN_TEST_NOT_EVALUABLE, "fewer than eight valid active CONFIRM units", {}), _RESULT_SENTINEL), _ISSUED_RESULTS)
        rows = []
        concordance_values = []
        mechanics_total = raw_total = constant_total = _mp(0)
        wins = 0
        for slot in slots:
            endpoint = endpoints.payload["endpoints"][slot]
            outcome = _mp(_decimal(endpoint["yobs_score_points"], f"{slot}.Yobs"))
            prediction = predictions.payload["predictions"].get(slot)
            if prediction is None:
                raise _fail("VERIFIED_INPUT_INVALID", "active CONFIRM slot is absent from frozen nine-unit predictions")
            mechanics_prediction = _mpfr_exact(prediction["mechanics_prediction_mpfr_hex"], f"{slot}.mechanics prediction")
            raw_prediction = _mpfr_exact(prediction["raw_prediction_mpfr_hex"], f"{slot}.raw prediction")
            constant_prediction = _mpfr_exact(prediction["dev_constant_prediction_mpfr_hex"], f"{slot}.constant prediction")
            mechanics_error = abs(outcome - mechanics_prediction)
            raw_error = abs(outcome - raw_prediction)
            constant_error = abs(outcome - constant_prediction)
            mechanics_total += mechanics_error
            raw_total += raw_error
            constant_total += constant_error
            win = raw_error - mechanics_error >= _mp(WIN_MARGIN_POINTS)
            wins += int(win)
            concordance_values.append((outcome, mechanics_prediction))
            rows.append(
                {
                    "slot_id": slot,
                    "yobs_score_points": _text(outcome, SCORE_SERIAL_PLACES),
                    "mechanics_prediction_points": prediction["mechanics_prediction_points"],
                    "raw_prediction_points": prediction["raw_prediction_points"],
                    "dev_constant_prediction_points": prediction["dev_constant_prediction_points"],
                    "mechanics_absolute_error": _text(mechanics_error, SCORE_SERIAL_PLACES),
                    "raw_absolute_error": _text(raw_error, SCORE_SERIAL_PLACES),
                    "constant_absolute_error": _text(constant_error, SCORE_SERIAL_PLACES),
                    "mechanics_win": win,
                }
            )
        concordance = sum(
            _strict_concordant_mpfr(left[0], right[0], left[1], right[1])
            for left, right in combinations(concordance_values, 2)
        )
        raw_ratio = _ratio(mechanics_total, raw_total)
        constant_ratio = _ratio(mechanics_total, constant_total)
        sign = sign_test_values(wins)
        passes = wins >= CONFIRM_WINS_MINIMUM and raw_ratio is not None and raw_ratio <= _mp(CONFIRM_RATIO_MAXIMUM) and concordance >= CONFIRM_CONCORDANCE_MINIMUM and constant_ratio is not None and constant_ratio <= _mp(CONFIRM_CONSTANT_RATIO_MAXIMUM)
        state = _OFFLINE_CONFIRM_THRESHOLDS_MET if passes else _OFFLINE_CONFIRM_THRESHOLDS_NOT_MET
        metrics = {"mechanics_wins": wins, "mechanics_total_absolute_error": _text(mechanics_total, SCORE_SERIAL_PLACES), "raw_total_absolute_error": _text(raw_total, SCORE_SERIAL_PLACES), "constant_total_absolute_error": _text(constant_total, SCORE_SERIAL_PLACES), "mechanics_raw_ratio": "Infinity" if raw_ratio is None else _text(raw_ratio, RATIO_SERIAL_PLACES), "mechanics_constant_ratio": "Infinity" if constant_ratio is None else _text(constant_ratio, RATIO_SERIAL_PLACES), "concordant_pairs": concordance, "total_pairs": 28, "sign_test": sign}
        report = _report(_SCHEMA_CONFIRM_RESULT, state, "typed TEST_ONLY/OFFLINE CONFIRM threshold diagnostics", {"prediction_root_sha256": predictions.content_sha256, "confirm_endpoints_root_sha256": endpoints.content_sha256, "active_confirm_slots": list(slots), "units": rows, "metrics": metrics})
        return _issue(ConfirmNumericAnalysis(state, report, _RESULT_SENTINEL), _ISSUED_RESULTS)
    except StatisticsValidationError as exc:
        state = _OFFLINE_NUMERIC_DIVERGENCE if exc.code == "STATISTICS_NUMERIC_DIVERGENCE" else _OFFLINE_INPUT_INVALID
        return _issue(ConfirmNumericAnalysis(state, _report(_SCHEMA_CONFIRM_RESULT, state, str(exc), {"reason_code": exc.code}), _RESULT_SENTINEL), _ISSUED_RESULTS)


def evaluate_confirm(prediction_value: Any, fixture_value: Any, endpoint_value: Any, active_value: Any) -> ConfirmNumericAnalysis:
    """Run the complete CONFIRM numerical core under frozen MPFR context."""

    with gmpy2.context(_ctx()):
        return _evaluate_confirm(prediction_value, fixture_value, endpoint_value, active_value)


def nig_golden_vector() -> Mapping[str, str]:
    """Calculate the root-bound fixed golden vector using the MPFR NIG core."""

    _require_runtime()
    with gmpy2.context(_ctx()):
        fit = _fit_nig([(_mp(x), _mp(y)) for x, y in zip(FROZEN_NUMERIC_GOLDEN_VECTOR["x"], FROZEN_NUMERIC_GOLDEN_VECTOR["y"])])
        return freeze({"intercept": _text(fit["alpha"], PROBABILITY_SERIAL_PLACES), "beta": _text(fit["beta"], PROBABILITY_SERIAL_PLACES), "prediction_points": _text(_prediction(fit, _mp(FROZEN_NUMERIC_GOLDEN_VECTOR["prediction_x"])), PROBABILITY_SERIAL_PLACES)})


__all__ = [
    "CONFIRM_PRIMARY_SLOTS",
    "CONFIRM_RESERVE_SLOT",
    "DEV_PRIMARY_SLOTS",
    "FEATURE_NAMES",
    "FROZEN_MODEL",
    "FROZEN_MODEL_ROOT_SHA256",
    "FROZEN_NUMERIC_GOLDEN_VECTOR",
    "ConfirmNumericAnalysis",
    "ConfirmPredictionFreeze",
    "DevNumericAnalysis",
    "ExternallySignedTimeBoundPreConfirmArtifact",
    "LedgerDerivedReserveFailureArtifact",
    "OfflineConfirmOutcomeFixture",
    "OfflinePreConfirmFixture",
    "OfflineStatisticsFixture",
    "OfflineUnitFixture",
    "SeparatelyReceivedConfirmEndpointArtifact",
    "SignedAuditorNumericResult",
    "StatisticsValidationError",
    "TestOnlyOfflineReserveFailureFixture",
    "VerifiedABNumericAgreement",
    "VerifiedActiveSet",
    "VerifiedAssignmentBootstrapSupport",
    "VerifiedCampaignIntegrity",
    "VerifiedCampaignPrereg",
    "VerifiedConfirmEndpoints",
    "VerifiedConfirmPool",
    "VerifiedConfirmPredictions",
    "VerifiedDevEndpoints",
    "VerifiedDevFit",
    "VerifiedFeatureSupport",
    "VerifiedLocalFeatures",
    "VerifiedPopulationAssignment",
    "evaluate_confirm",
    "evaluate_dev",
    "freeze_confirm_predictions",
    "frozen_ratio",
    "make_test_only_offline_active_set",
    "make_test_only_offline_confirm_endpoints",
    "make_test_only_offline_reserve_failure_fixture",
    "make_test_only_offline_statistics_fixture",
    "nig_golden_vector",
    "sign_test_values",
    "statistics_readiness_gate",
    "strict_concordant",
    "validate_issued_statistics_result",
]
