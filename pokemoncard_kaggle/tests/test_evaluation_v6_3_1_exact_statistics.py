from __future__ import annotations

from dataclasses import replace
from decimal import Decimal, localcontext
from fractions import Fraction
import json
from pathlib import Path
import re

import gmpy2
import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.exact_statistics import (
    CANDIDATE_EXACT_MODEL_MANIFEST,
    CANDIDATE_EXACT_MODEL_ROOT_SHA256,
    CONFIRM_PRIMARY_SLOTS,
    CONFIRM_RESERVE_SLOT,
    CONFIRM_SLOTS,
    DEV_PRIMARY_SLOTS,
    DEV_RESERVE_SLOT,
    FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256,
    GOLDEN_MANIFEST_ROOT_SHA256,
    LARGE_RATIONAL_GOLDEN_INPUT,
    LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX,
    RETIRED_LEGACY_MODEL_ROOT_SHA256,
    THRESHOLDS,
    ExactRational,
    ExactStatisticsError,
    FeaturePoint,
    HostedPollReceipt,
    ExactHostedEndpoint,
    ExactLocalUnit,
    compare_exact_threshold,
    evaluate_dev_continue,
    evaluate_post_freeze,
    exact_statistics_readiness,
    fit_nig,
    freeze_pre_confirm_predictions,
    full_precision_golden_vector,
    make_post_freeze_confirm_endpoints,
    make_test_only_ledger_active_set,
    make_test_only_pre_confirm_input,
    mpfr_c99_hex,
    predict,
    project_exact,
    validate_model_root,
)


_C99 = re.compile(r"^-?0x[0-9a-f]+\.[0-9a-f]{64}p[+-][0-9]+$")


def _hash(index: int) -> str:
    return f"{index + 1:064x}"


def _r(numerator: int, denominator: int = 1) -> ExactRational:
    return ExactRational.from_integers(numerator, denominator)


def _endpoint(slot: str, offset: int, gap: ExactRational) -> ExactHostedEndpoint:
    cutoff = _r(1000)
    score = ExactRational.from_fraction(cutoff.as_fraction() + gap.as_fraction())
    polls = tuple(
        HostedPollReceipt(
            f"{slot}-poll-{index}",
            score,
            cutoff,
            _hash(offset * 20 + index * 2),
            _hash(offset * 20 + index * 2 + 1),
        )
        for index in range(4)
    )
    return ExactHostedEndpoint(slot, polls)  # type: ignore[arg-type]


def _unit(
    slot: str,
    index: int,
    x: ExactRational,
    *,
    endpoint: ExactHostedEndpoint | None,
    comparator_r: ExactRational | None = None,
) -> ExactLocalUnit:
    comparator_r = _r(0) if comparator_r is None else comparator_r
    regular_feature = ExactRational.from_fraction(x.as_fraction() * Fraction(6, 5))
    point = FeaturePoint.make([regular_feature] * 5 + [_r(0)], comparator_r)
    return ExactLocalUnit(
        slot,
        _hash(1000 + index),
        f"source-{index}",
        f"lineage-{index}",
        f"control-{index}",
        f"intervention-{index % 5}",
        point,
        ExactRational.from_fraction((comparator_r.as_fraction() + 1) / 2),
        _hash(2000 + index * 5),
        _hash(2001 + index * 5),
        _hash(2002 + index * 5),
        _hash(2003 + index * 5),
        CANDIDATE_EXACT_MODEL_ROOT_SHA256,
        endpoint,
    )


def _pre_confirm(*, dev_failure_slot: str | None = None, dev_outcome_scale: int = 200):
    assignment_root = _hash(3002)
    dev_active_set = make_test_only_ledger_active_set(
        tranche="DEV",
        assignment_root_sha256=assignment_root,
        execution_ledger_root_sha256=_hash(3010),
        failed_primary_slot_id=dev_failure_slot,
        failure_event_root_sha256=None if dev_failure_slot is None else _hash(3011),
        failure_before_mature_poll=dev_failure_slot is not None,
    )
    dev_x = (_r(-3, 4), _r(-1, 2), _r(-1, 4), _r(1, 4), _r(1, 2), _r(3, 4))
    dev = tuple(
        _unit(slot, index, x, endpoint=_endpoint(slot, index, ExactRational.from_fraction(x.as_fraction() * dev_outcome_scale)))
        for index, (slot, x) in enumerate(zip(dev_active_set.active_slots, dev_x, strict=True))
    )
    confirm_x = (_r(-2, 3), _r(-1, 2), _r(-1, 3), _r(-1, 6), _r(1, 6), _r(1, 3), _r(1, 2), _r(2, 3), _r(3, 4))
    confirm = tuple(_unit(slot, index + 10, x, endpoint=None) for index, (slot, x) in enumerate(zip(CONFIRM_SLOTS, confirm_x, strict=True)))
    return make_test_only_pre_confirm_input(
        campaign_nonce_root_sha256=_hash(3000),
        population_root_sha256=_hash(3001),
        assignment_root_sha256=assignment_root,
        preregistration_root_sha256=_hash(3003),
        dev_active_set=dev_active_set,
        dev_units=dev,
        confirm_units=confirm,
    )


_CONFIRM_X = dict(
    zip(
        CONFIRM_SLOTS,
        (_r(-2, 3), _r(-1, 2), _r(-1, 3), _r(-1, 6), _r(1, 6), _r(1, 3), _r(1, 2), _r(2, 3), _r(3, 4)),
        strict=True,
    )
)


def _confirm_active_set(pre, *, failed_primary_slot: str | None = None):
    return make_test_only_ledger_active_set(
        tranche="CONFIRM",
        assignment_root_sha256=pre.assignment_root_sha256,
        execution_ledger_root_sha256=_hash(3020),
        failed_primary_slot_id=failed_primary_slot,
        failure_event_root_sha256=None if failed_primary_slot is None else _hash(3021),
        failure_before_mature_poll=failed_primary_slot is not None,
    )


def _post_endpoints(slots=CONFIRM_PRIMARY_SLOTS):
    return tuple(
        _endpoint(slot, index + 100, ExactRational.from_fraction(_CONFIRM_X[slot].as_fraction() * 200))
        for index, slot in enumerate(slots)
    )


def _freeze(pre):
    decision = evaluate_dev_continue(pre)
    return decision, freeze_pre_confirm_predictions(pre, decision)


def _assert_code(code: str, fn) -> None:
    with pytest.raises(ExactStatisticsError) as raised:
        fn()
    assert raised.value.code == code


def test_canonical_scalars_reject_every_nonexact_input_boundary() -> None:
    assert ExactRational.make({"numerator": "-3", "denominator": "4"}) == _r(-3, 4)
    for value in ("0.5", 0.5, Decimal("0.5"), gmpy2.mpfr("0.5")):
        _assert_code("STATISTICS_ROUNDED_INPUT_USED", lambda value=value: ExactRational.make(value))
    _assert_code("STATISTICS_RATIONAL_NONCANONICAL", lambda: ExactRational("02", "1"))
    _assert_code("STATISTICS_RATIONAL_NONCANONICAL", lambda: ExactRational("0", "2"))


def test_f6_is_penalty_only() -> None:
    _assert_code(
        "STATISTICS_ENDPOINT_DERIVATION_MISMATCH",
        lambda: FeaturePoint.make([_r(0)] * 5 + [_r(1, 10)], _r(0)),
    )
    point = FeaturePoint.make([_r(0)] * 5 + [_r(-1, 10)], _r(0))
    assert point.features[5] == _r(-1, 10)


def test_display_poisoning_and_subdisplay_collision_are_rejected() -> None:
    _assert_code(
        "STATISTICS_ROUNDED_INPUT_USED",
        lambda: ExactRational.make({"numerator": "1", "denominator": "2", "display_12": "0.500000000000"}),
    )
    point = FeaturePoint.make([_r(1, 6)] * 5 + [_r(0)], _r(0))
    exact = point.exact_canonical()
    exact["sub_display"] = {"x": "0.166666666667"}
    _assert_code("STATISTICS_ROUNDED_INPUT_USED", lambda: FeaturePoint.from_exact_mapping(exact))


def test_projection_is_decimal_context_independent_and_direct_for_large_operands() -> None:
    vector = ExactRational.from_fraction(Fraction(2**401 + 2**199 + 1, 2**400 + 2**127 + 3))
    with localcontext() as context:
        context.prec = 2
        first = mpfr_c99_hex(project_exact(vector))
        fit_first = fit_nig([(_r(-3, 4), _r(-3, 4)), (_r(-1, 4), _r(-1, 4)), (_r(1, 4), _r(1, 4)), (_r(3, 4), _r(3, 4))])
    with localcontext() as context:
        context.prec = 80
        second = mpfr_c99_hex(project_exact(vector))
        fit_second = fit_nig([(_r(-3, 4), _r(-3, 4)), (_r(-1, 4), _r(-1, 4)), (_r(1, 4), _r(1, 4)), (_r(3, 4), _r(3, 4))])
    frozen_context = gmpy2.get_context().copy()
    frozen_context.precision = 256
    frozen_context.round = gmpy2.RoundToNearest
    with gmpy2.context(frozen_context):
        direct = gmpy2.mpfr(gmpy2.mpq(int(vector.numerator), int(vector.denominator)))
    assert first == second == mpfr_c99_hex(direct)
    assert first == LARGE_RATIONAL_GOLDEN_PROJECTION_C99_HEX
    assert fit_first.root_sha256 == fit_second.root_sha256


def test_full_precision_golden_vector_is_literal_complete_and_manifest_bound() -> None:
    vector = full_precision_golden_vector()
    checked_in = json.loads((Path(__file__).resolve().parents[1] / "evaluation_v6_3_1" / "golden_exact_statistics_v1.json").read_text(encoding="ascii"))
    assert canonical_sha256(checked_in) == GOLDEN_MANIFEST_ROOT_SHA256
    assert checked_in["large_rational_projection"]["input"] == dict(LARGE_RATIONAL_GOLDEN_INPUT)
    assert canonical_sha256(vector) == FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256
    assert CANDIDATE_EXACT_MODEL_MANIFEST.payload["full_precision_golden_vector"]["expected_artifact_root_sha256"] == FULL_PRECISION_GOLDEN_VECTOR_ROOT_SHA256
    assert CANDIDATE_EXACT_MODEL_MANIFEST.payload["full_precision_golden_vector"]["checked_in_manifest_root_sha256"] == GOLDEN_MANIFEST_ROOT_SHA256
    assert CANDIDATE_EXACT_MODEL_MANIFEST.payload["full_precision_golden_vector"]["large_rational_input"] == LARGE_RATIONAL_GOLDEN_INPUT
    assert set(vector["outputs"]) == {
        "fit",
        "prediction_minus",
        "prediction_plus",
        "error_minus",
        "error_plus",
        "mechanics_total",
        "constant_total",
        "ratio",
        "concordance",
    }
    assert vector["outputs"]["fit"]["coefficients_c99_hex"]
    assert vector["outputs"]["fit"]["posterior_c99_hex"]
    assert vector["outputs"]["fit"]["condition_c99_hex"]


def test_exact_threshold_boundaries_are_not_display_boundaries() -> None:
    assert compare_exact_threshold(_r(9, 10), THRESHOLDS["dev_ratio_maximum"]).passed is True
    assert compare_exact_threshold(_r(900000000001, 1000000000000), THRESHOLDS["dev_ratio_maximum"]).passed is False
    assert compare_exact_threshold(_r(1, 10), THRESHOLDS["unit_win_margin_points"], ">=").passed is True
    assert compare_exact_threshold(_r(99999999999, 1000000000000), THRESHOLDS["unit_win_margin_points"], ">=").passed is False


def test_exact_four_poll_endpoint_derives_sorted_middle_two_without_decimal_parsing() -> None:
    gaps = (_r(20), _r(-9), _r(3), _r(-1))
    endpoint = ExactHostedEndpoint(
        "D01",
        tuple(
            HostedPollReceipt(f"p-{index}", ExactRational.from_fraction(_r(1000).as_fraction() + gap.as_fraction()), _r(1000), _hash(4000 + index * 2), _hash(4001 + index * 2))
            for index, gap in enumerate(gaps)
        ),
    )
    assert endpoint.sorted_gaps == (_r(-9), _r(-1), _r(3), _r(20))
    assert endpoint.middle_gaps == (_r(-1), _r(3))
    assert endpoint.yobs == _r(1)
    assert endpoint.model_y == _r(1, 100)
    assert endpoint.canonical()["gaps"] == [gap.canonical() for gap in gaps]


def test_preconfirm_freeze_and_postfreeze_artifacts_reject_phase_substitution() -> None:
    pre = _pre_confirm()
    decision, frozen = _freeze(pre)
    active_set = _confirm_active_set(pre)
    post = make_post_freeze_confirm_endpoints(frozen, active_set, _post_endpoints(active_set.active_slots))
    assert frozen.phase == "PRE_CONFIRM"
    assert post.phase == "POST_FREEZE_CONFIRM_ENDPOINTS"
    _assert_code("STATISTICS_PHASE_ARTIFACT_INVALID", lambda: freeze_pre_confirm_predictions(post, decision))
    _assert_code("STATISTICS_PHASE_ARTIFACT_INVALID", lambda: evaluate_post_freeze(pre, post))
    object.__setattr__(post, "prediction_root_sha256", _hash(9999))
    _assert_code("STATISTICS_PHASE_ARTIFACT_INVALID", lambda: evaluate_post_freeze(frozen, post))


@pytest.mark.parametrize(
    "field_name",
    ("source_component_id", "lineage_time_component_id", "development_control_component_id"),
)
def test_dev_confirm_components_must_be_disjoint(field_name: str) -> None:
    pre = _pre_confirm()
    confirm = list(pre.confirm_units)
    confirm[0] = replace(confirm[0], **{field_name: getattr(pre.dev_units[0], field_name)})
    _assert_code(
        "STATISTICS_PHASE_ARTIFACT_INVALID",
        lambda: make_test_only_pre_confirm_input(
            campaign_nonce_root_sha256=pre.campaign_nonce_root_sha256,
            population_root_sha256=pre.population_root_sha256,
            assignment_root_sha256=pre.assignment_root_sha256,
            preregistration_root_sha256=pre.preregistration_root_sha256,
            dev_active_set=pre.dev_active_set,
            dev_units=pre.dev_units,
            confirm_units=confirm,
        ),
    )


def test_active_sets_support_reserves_and_forbid_post_outcome_best_eight() -> None:
    pre = _pre_confirm()
    _, frozen = _freeze(pre)
    default_active = _confirm_active_set(pre)
    cherry_picked = tuple(slot for slot in CONFIRM_SLOTS if slot != "C01")
    _assert_code(
        "STATISTICS_PHASE_ARTIFACT_INVALID",
        lambda: make_post_freeze_confirm_endpoints(frozen, default_active, _post_endpoints(cherry_picked)),
    )
    reserve_active = _confirm_active_set(pre, failed_primary_slot="C03")
    post = make_post_freeze_confirm_endpoints(frozen, reserve_active, _post_endpoints(reserve_active.active_slots))
    assert post.active_confirm_slots == ("C01", "C02", "C04", "C05", "C06", "C07", "C08", CONFIRM_RESERVE_SLOT)
    assert evaluate_post_freeze(frozen, post).active_confirm_slots == post.active_confirm_slots


def test_dev_reserve_realizes_six_units_and_failed_dev_cannot_freeze_confirm() -> None:
    reserve_pre = _pre_confirm(dev_failure_slot="D03")
    assert tuple(unit.slot_id for unit in reserve_pre.dev_units) == ("D01", "D02", "D04", "D05", "D06", DEV_RESERVE_SLOT)
    reserve_decision, reserve_freeze = _freeze(reserve_pre)
    assert reserve_decision.passes is True
    assert reserve_freeze.dev_active_set_root_sha256 == reserve_pre.dev_active_set.artifact_root_sha256

    failed_pre = _pre_confirm(dev_outcome_scale=0)
    failed_decision = evaluate_dev_continue(failed_pre)
    assert failed_decision.passes is False
    _assert_code(
        "STATISTICS_PHASE_ARTIFACT_INVALID",
        lambda: freeze_pre_confirm_predictions(failed_pre, failed_decision),
    )


def test_retired_root_and_wrapped_retired_root_are_rejected() -> None:
    _assert_code("STATISTICS_MODEL_ROOT_RETIRED", lambda: validate_model_root(RETIRED_LEGACY_MODEL_ROOT_SHA256))
    pre = _pre_confirm()
    _assert_code(
        "STATISTICS_MODEL_ROOT_RETIRED",
        lambda: make_test_only_pre_confirm_input(
            campaign_nonce_root_sha256=RETIRED_LEGACY_MODEL_ROOT_SHA256,
            population_root_sha256=pre.population_root_sha256,
            assignment_root_sha256=pre.assignment_root_sha256,
            preregistration_root_sha256=pre.preregistration_root_sha256,
            dev_active_set=pre.dev_active_set,
            dev_units=pre.dev_units,
            confirm_units=pre.confirm_units,
        ),
    )
    _assert_code(
        "STATISTICS_MODEL_ROOT_RETIRED",
        lambda: replace(_unit("D01", 55, _r(0), endpoint=_endpoint("D01", 55, _r(0))), model_root_sha256=RETIRED_LEGACY_MODEL_ROOT_SHA256),
    )


def test_full_c99_hex_is_retained_for_fit_prediction_errors_totals_ratios_and_concordance() -> None:
    pre = _pre_confirm()
    _, frozen = _freeze(pre)
    active_set = _confirm_active_set(pre)
    post = make_post_freeze_confirm_endpoints(frozen, active_set, _post_endpoints(active_set.active_slots))
    result = evaluate_post_freeze(frozen, post)
    fit = frozen.dev_analysis.full_mechanics_fit
    for values in (fit.coefficients_c99_hex, fit.posterior_c99_hex, fit.condition_c99_hex):
        assert values
        assert all(_C99.fullmatch(value) for value in values.values())
    for prediction_row in frozen.predictions.values():
        assert all(_C99.fullmatch(prediction.score_prediction_c99_hex) for prediction in prediction_row.values())
    for row in result.unit_rows.values():
        assert _C99.fullmatch(row["mechanics_error"]["absolute_error_c99_hex"])
        assert _C99.fullmatch(row["comparator_error"]["absolute_error_c99_hex"])
        assert _C99.fullmatch(row["constant_error"]["absolute_error_c99_hex"])
        assert _C99.fullmatch(row["unit_win_difference_c99_hex"])
    for total in (result.mechanics_total, result.comparator_total, result.constant_total):
        assert _C99.fullmatch(total.total_c99_hex)
    assert _C99.fullmatch(result.mechanics_comparator_ratio.ratio_c99_hex or "")
    assert _C99.fullmatch(result.mechanics_constant_ratio.ratio_c99_hex or "")
    assert len(result.concordances) == 28
    assert all(_C99.fullmatch(item.outcome_difference_c99_hex) and _C99.fullmatch(item.prediction_difference_c99_hex) for item in result.concordances)
    canonical = frozen.canonical()
    assert "coefficients_c99_hex" in canonical["dev_analysis"]["full_mechanics_fit"]
    assert "posterior_c99_hex" in canonical["dev_analysis"]["full_mechanics_fit"]
    assert "condition_c99_hex" in canonical["dev_analysis"]["full_mechanics_fit"]
    assert "coefficients_c99_hex" in canonical["dev_analysis"]["folds"][0]["mechanics_fit"]


def test_candidate_artifacts_are_deterministic_and_irrevocably_zero_authority() -> None:
    first, second = _pre_confirm(), _pre_confirm()
    first_decision, frozen_first = _freeze(first)
    second_decision, frozen_second = _freeze(second)
    assert first_decision.artifact_root_sha256 == second_decision.artifact_root_sha256
    assert frozen_first.artifact_root_sha256 == frozen_second.artifact_root_sha256
    active_set = _confirm_active_set(first)
    post = make_post_freeze_confirm_endpoints(frozen_first, active_set, _post_endpoints(active_set.active_slots))
    result = evaluate_post_freeze(frozen_first, post)
    for report in (exact_statistics_readiness(), frozen_first.authority, post.authority, result.authority):
        assert report["calibration_upload_authorized"] is False
        assert report["production_upload_authorized"] is False
        assert report["sealed_holdout_access_authorized"] is False
        assert report["agent_modification_authorized"] is False
        assert not report["permits"]
        assert report["calibration_slots_remaining"] == 16
        assert report["production_slots_remaining"] == 1
    assert CANDIDATE_EXACT_MODEL_MANIFEST.payload["feature_spec_complete"] is False
    assert CANDIDATE_EXACT_MODEL_MANIFEST.payload["independent_review_pinned"] is False


def test_predict_rejects_rounded_feature_inputs() -> None:
    fit = fit_nig([(_r(-3, 4), _r(-3, 4)), (_r(-1, 4), _r(-1, 4)), (_r(1, 4), _r(1, 4)), (_r(3, 4), _r(3, 4))])
    _assert_code("STATISTICS_EXACT_VALUE_MISSING", lambda: predict(fit, "0.25"))
