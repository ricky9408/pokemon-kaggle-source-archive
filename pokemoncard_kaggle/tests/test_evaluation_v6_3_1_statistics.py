from __future__ import annotations

from dataclasses import fields, replace
import inspect

import pytest

import evaluation_v6_3_1.statistics as statistics
from evaluation_v6_3_1.statistics import (
    CONFIRM_PRIMARY_SLOTS,
    DEV_PRIMARY_SLOTS,
    FEATURE_NAMES,
    FROZEN_MODEL,
    FROZEN_MODEL_ROOT_SHA256,
    FROZEN_NUMERIC_GOLDEN_VECTOR,
    ExternallySignedTimeBoundPreConfirmArtifact,
    LedgerDerivedReserveFailureArtifact,
    OfflineUnitFixture,
    SeparatelyReceivedConfirmEndpointArtifact,
    SignedAuditorNumericResult,
    VerifiedActiveSet,
    VerifiedAssignmentBootstrapSupport,
    evaluate_confirm,
    evaluate_dev,
    freeze_confirm_predictions,
    frozen_ratio,
    make_test_only_offline_active_set,
    make_test_only_offline_confirm_endpoints,
    make_test_only_offline_reserve_failure_fixture,
    make_test_only_offline_statistics_fixture,
    nig_golden_vector,
    sign_test_values,
    statistics_readiness_gate,
    strict_concordant,
    validate_issued_statistics_result,
)
from evaluation_v6_3_1.common import canonical_sha256


def _hash(index: int) -> str:
    return f"{index + 1:064x}"


def _polls(gap: str) -> tuple[tuple[str, str], ...]:
    return tuple((str(1000 + int(float(gap))), "1000") for _ in range(4))


def _unit(slot: str, index: int, *, x: str, raw: str, gap: str | None = None, archive_offset: int = 0) -> OfflineUnitFixture:
    endpoint = gap if gap is not None else str(float(x) * 100)
    return OfflineUnitFixture(slot, _hash(index + archive_offset), {name: x for name in FEATURE_NAMES}, raw, _polls(endpoint))


def _groups(*, paired_dev_source: bool = False, overlap_kind: str | None = None) -> dict[str, list[list[str]]]:
    slots = ["D01", "D02", "D03", "D04", "D05", "D06", "DR01", *CONFIRM_PRIMARY_SLOTS, "CR01"]
    source = [[slot] for slot in slots]
    if paired_dev_source:
        source = [["D01", "D02"], *[[slot] for slot in slots if slot not in {"D01", "D02"}]]
    result = {
        "source": source,
        "lineage_time": [[slot] for slot in slots],
        "development_control": [[slot] for slot in slots],
        "intervention": [["D01", "D02"], ["D03", "D04"], ["D05", "D06", "DR01"], ["C01", "C02"], ["C03", "C04"], ["C05", "C06"], ["C07", "C08", "CR01"]],
    }
    if overlap_kind is not None:
        result[overlap_kind] = [["D01", "C01"], *[[slot] for slot in slots if slot not in {"D01", "C01"}]]
    return result


def _fixture(*, paired_dev_source: bool = False, overlap_kind: str | None = None, feature_outlier: bool = False, archive_offset: int = 0):
    dev_x = ("-0.9", "-0.6", "-0.3", "0.2", "0.5", "0.8", "0.1")
    raw = ("0.9", "0.4", "0.75", "0.05", "0.55", "0.25", "0.65")
    units = [_unit(slot, index, x=dev_x[index], raw=raw[index], gap=str(float(dev_x[index]) * 1000), archive_offset=archive_offset) for index, slot in enumerate(("D01", "D02", "D03", "D04", "D05", "D06", "DR01"))]
    for offset, slot in enumerate((*CONFIRM_PRIMARY_SLOTS, "CR01"), 7):
        x = str(-0.7 + 0.15 * (offset - 7))
        units.append(_unit(slot, offset, x=x, raw="0.5", gap=str(float(x) * 1000), archive_offset=archive_offset))
    if feature_outlier:
        original = units[7]
        mechanics = dict(original.mechanics)
        mechanics[FEATURE_NAMES[0]] = "1"
        mechanics[FEATURE_NAMES[1]] = "-1"
        units[7] = replace(original, mechanics=mechanics)
    return make_test_only_offline_statistics_fixture(units, _groups(paired_dev_source=paired_dev_source, overlap_kind=overlap_kind))


def _frozen_path(fixture):
    dev = evaluate_dev(fixture.pre_confirm)
    frozen = freeze_confirm_predictions(dev, fixture.pre_confirm)
    endpoints = make_test_only_offline_confirm_endpoints(fixture, frozen)
    return dev, frozen, endpoints


def _mutate_and_rehash_artifact(artifact, *, payload=None, parent_root: str | None = None) -> None:
    if payload is not None:
        object.__setattr__(artifact, "payload", payload)
    if parent_root is not None:
        object.__setattr__(artifact, "parent_root_sha256", parent_root)
    core = {"schema": artifact.schema, "parent_root_sha256": artifact.parent_root_sha256, "payload": artifact.payload, "offline_fixture_only": True}
    content = canonical_sha256(core)
    object.__setattr__(artifact, "content_sha256", content)
    phase = "POST_FREEZE_CONFIRM_ENDPOINTS" if artifact.schema.endswith(".confirm-endpoints") else "PRE_CONFIRM"
    object.__setattr__(artifact, "offline_fixture_binding_sha256", canonical_sha256({"offline_fixture_only": True, "content_sha256": content, "phase": phase}))


def test_preconfirm_freeze_cannot_receive_or_inspect_confirm_outcomes() -> None:
    fixture = _fixture()
    pre = fixture.pre_confirm
    assert not hasattr(pre, "confirm_endpoints")
    assert set(pre.dev_endpoints.payload["endpoints"]) == set(DEV_PRIMARY_SLOTS + ("DR01",))
    assert "endpoint" not in inspect.signature(freeze_confirm_predictions).parameters

    dev = evaluate_dev(pre)
    assert freeze_confirm_predictions(dev, fixture).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"
    frozen = freeze_confirm_predictions(dev, pre)
    assert frozen.verdict == "TEST_ONLY_OFFLINE_PREDICTIONS_FROZEN"
    assert "yobs_score_points" not in repr(frozen.verified_predictions.payload)


def test_prediction_freeze_binds_every_preconfirm_root_and_rejects_cross_campaign_substitution() -> None:
    first = _fixture()
    second = _fixture(archive_offset=100)
    dev = evaluate_dev(first.pre_confirm)
    frozen = freeze_confirm_predictions(dev, first.pre_confirm)
    payload = frozen.verified_predictions.payload
    assert payload["campaign_root_sha256"] == first.pre_confirm.prereg.parent_root_sha256
    assert payload["prereg_root_sha256"] == first.pre_confirm.prereg.content_sha256
    assert payload["assignment_root_sha256"] == first.pre_confirm.assignment.content_sha256
    assert payload["local_features_root_sha256"] == first.pre_confirm.local_features.content_sha256
    assert payload["dev_endpoints_root_sha256"] == first.pre_confirm.dev_endpoints.content_sha256
    assert payload["dev_fit_root_sha256"] == dev.verified_fit.content_sha256
    assert payload["confirm_pool_root_sha256"] == first.pre_confirm.confirm_pool.content_sha256
    assert tuple(payload["all_nine_confirm_slots"]) == CONFIRM_PRIMARY_SLOTS + ("CR01",)
    assert freeze_confirm_predictions(dev, second.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_confirm_endpoints_are_later_typed_artifacts_bound_to_exact_freeze() -> None:
    first = _fixture()
    second = _fixture(archive_offset=100)
    _, frozen, endpoints = _frozen_path(first)
    assert endpoints.payload["received_after_prediction_freeze"] is True
    assert endpoints.payload["leakage_marked"] is False
    assert endpoints.payload["authenticated_endpoint_evidence"] is False
    result = evaluate_confirm(frozen, first.pre_confirm, endpoints, first.default_active_set)
    assert result.verdict == "TEST_ONLY_OFFLINE_CONFIRM_THRESHOLDS_MET"
    with pytest.raises(ValueError, match="cross-campaign"):
        make_test_only_offline_confirm_endpoints(second, frozen)
    assert evaluate_confirm(frozen, first.pre_confirm, {}, first.default_active_set).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_offline_results_and_artifacts_retain_every_incomplete_authentication_flag() -> None:
    fixture = _fixture()
    dev, frozen, endpoints = _frozen_path(fixture)
    result = evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set)
    for report in (dev.report, frozen.report, result.report):
        assert report["test_only"] is True
        assert report["offline_conformance_only"] is True
        assert report["feature_spec_complete"] is False
        assert report["assignment_support_authenticated"] is False
        assert report["independent_ab_numeric_agreement_verified"] is False
        assert report["bootstrap_support_10000_verified"] is False
        assert report["timestamp_evidence_verified"] is False
        assert report["predictive_validity_established"] is False
        assert report["calibration_upload_authorized"] is False
        assert report["production_upload_authorized"] is False
        assert report["permits"] == ()
    for artifact in (
        fixture.pre_confirm.prereg,
        fixture.pre_confirm.assignment,
        fixture.pre_confirm.local_features,
        fixture.pre_confirm.feature_support,
        dev.verified_fit,
        frozen.verified_predictions,
        endpoints,
    ):
        assert artifact.payload["test_only"] is True
        assert artifact.payload["feature_spec_complete"] is False
        assert artifact.payload["assignment_support_authenticated"] is False
        assert artifact.payload["independent_ab_numeric_agreement_verified"] is False
        assert artifact.payload["timestamp_evidence_verified"] is False
        assert artifact.payload["predictive_validity_established"] is False
    assert not hasattr(dev.verified_fit, "a_signature_sha256")
    assert not hasattr(frozen.verified_predictions, "b_signature_sha256")
    assert "numeric_fault" not in {field.name for field in fields(OfflineUnitFixture)}
    with pytest.raises(ValueError, match="future authenticated composer"):
        SignedAuditorNumericResult("A", "0" * 64, "0" * 64, "0" * 64, "0" * 64, "0" * 64, object())
    with pytest.raises(ValueError, match="future authenticated composer"):
        VerifiedAssignmentBootstrapSupport("0" * 64, "0" * 64, "0" * 64, "0" * 64, 10000, object())
    with pytest.raises(ValueError, match="future authenticated composer"):
        ExternallySignedTimeBoundPreConfirmArtifact("0" * 64, "0" * 64, "0" * 64, "0" * 64, "0" * 64, "2026-01-01T00:00:00Z", object())
    with pytest.raises(ValueError, match="future authenticated composer"):
        SeparatelyReceivedConfirmEndpointArtifact("0" * 64, "0" * 64, "0" * 64, "0" * 64, "0" * 64, object())
    with pytest.raises(ValueError, match="future authenticated composer"):
        LedgerDerivedReserveFailureArtifact("0" * 64, "0" * 64, "C01", "0" * 64, "0" * 64, object())
    assert not hasattr(statistics, "_AUTHENTICATED_NUMERIC_SENTINEL")


def test_public_readiness_and_pending_assignment_support_correction_fail_closed() -> None:
    readiness = statistics_readiness_gate()
    assert readiness["state"] == "FEATURE_ASSIGNMENT_AUTHENTICATION_INCOMPLETE"
    assert readiness["feature_spec_complete"] is False
    assert readiness["assignment_support_authenticated"] is False
    assert readiness["assignment_support_criterion_available"] is False
    assert readiness["independent_ab_numeric_agreement_verified"] is False
    assert readiness["timestamp_evidence_verified"] is False
    assert readiness["predictive_validity_established"] is False
    assert readiness["calibration_upload_authorized"] is False
    assert readiness["production_upload_authorized"] is False
    assert readiness["permits"] == ()
    with pytest.raises(TypeError):
        readiness["assignment_support_authenticated"] = True  # type: ignore[index]
    exported_builders = [name for name in statistics.__all__ if name.startswith("make_")]
    assert exported_builders
    assert all(name.startswith("make_test_only_offline_") for name in exported_builders)

    fixture = _fixture(feature_outlier=True)
    result = evaluate_dev(fixture.pre_confirm)
    assert result.verdict.startswith("TEST_ONLY_OFFLINE_")
    assert result.report["assignment_support_authenticated"] is False
    support = fixture.pre_confirm.feature_support.payload
    assert support["binding_spec"] == "V631_ASSIGNMENT_SUPPORT_CORRECTION"
    assert support["status"] == "TEST_ONLY_OFFLINE_ASSIGNMENT_SUPPORT_UNAVAILABLE"
    assert support["required_metrics"] == ("joint_Chebyshev_F", "separate_x", "separate_R")
    assert support["required_active_dev_scenarios"] == 7
    assert support["required_confirm_targets_per_dev_scenario"] == 9
    assert support["dev_reserve_against_base_dev_required"] is True
    assert support["required_target_scenario_relation_count"] == 64
    assert support["point_estimate_pass_verified"] is False
    assert support["bootstrap_replicates_required"] == 10000
    assert support["bootstrap_pass_count_required_per_relation"] == 9500
    assert support["bootstrap_replicates_completed"] == 0
    assert support["common_seed_bootstrap_verified"] is False
    assert "feature_ranges" not in support
    assert "composite_range" not in support
    assert "raw_comparator_range" not in support

    frozen_support = FROZEN_MODEL["support"]
    assert frozen_support["binding_spec"] == "V631_ASSIGNMENT_SUPPORT_CORRECTION"
    assert frozen_support["assignment_support_authenticated"] is False
    assert frozen_support["criterion_available"] is False
    assert frozen_support["implemented_in_statistics_module"] is False
    assert frozen_support["metrics"]["F"].startswith("joint_Chebyshev")
    assert frozen_support["active_dev_scenarios_required"] == 7
    assert frozen_support["confirm_pool_targets_per_dev_scenario"] == 9
    assert frozen_support["dev_reserve_target_against_base_dev"] is True
    assert frozen_support["required_target_scenario_relation_count"] == 64
    assert frozen_support["point_estimate_pass_required"] is True
    assert frozen_support["bootstrap"]["replicates_required"] == 10000
    assert frozen_support["bootstrap"]["pass_count_required_per_relation"] == 9500
    assert frozen_support["bootstrap"]["common_seed_resampling_across_all_units"] is True


def test_plain_arrays_and_rehashed_maps_cannot_produce_authority() -> None:
    invalid = evaluate_dev([])
    assert invalid.verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"
    fixture = _fixture()
    forged = {"root": FROZEN_MODEL_ROOT_SHA256, "content_sha256": fixture.pre_confirm.prereg.content_sha256}
    assert evaluate_dev(forged).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"
    unit = _unit("D01", 0, x="0", raw="0")
    with pytest.raises(ValueError, match="canonical slots"):
        make_test_only_offline_statistics_fixture([replace(unit, test_only=False)] * 16, _groups())
    mechanics = dict(unit.mechanics)
    mechanics["raw_paired_local_game_point_rate"] = "0.5"
    with pytest.raises(ValueError, match="exact six-feature"):
        make_test_only_offline_statistics_fixture([replace(unit, mechanics=mechanics)] * 16, _groups())
    slots = ["D01", "D02", "D03", "D04", "D05", "D06", "DR01", *CONFIRM_PRIMARY_SLOTS, "CR01"]
    units = [_unit(slot, index, x="0", raw="0.5") for index, slot in enumerate(slots)]
    units[1] = replace(units[1], archive_sha256=units[0].archive_sha256)
    with pytest.raises(ValueError, match="archive identities must be unique"):
        make_test_only_offline_statistics_fixture(units, _groups())


def test_raw_comparator_is_exactly_transformed_to_R_and_never_stored_as_a_feature() -> None:
    fixture = _fixture()
    row = fixture.pre_confirm.local_features.payload["features"]["D01"]
    assert row["raw_comparator_R"] == "0.8"
    assert "raw_paired_local_game_point_rate" not in row
    assert set(row["mechanics"]) == set(FEATURE_NAMES)
    assert FROZEN_MODEL["raw_comparator"]["transform"] == "R=2*raw_paired_local_game_point_rate-1"


def test_true_leave_one_source_component_out_holds_two_units_together() -> None:
    fixture = _fixture(paired_dev_source=True)
    result = evaluate_dev(fixture.pre_confirm)
    assert result.verdict == "TEST_ONLY_OFFLINE_DEV_THRESHOLDS_MET"
    paired = [fold for fold in result.report["folds"] if fold["held_out_slots"] == ("D01", "D02")]
    assert len(paired) == 1
    assert result.report["metrics"]["source_component_count"] == 5


@pytest.mark.parametrize("kind", ["source", "lineage_time", "development_control"])
def test_dev_confirm_component_disjointness_is_required(kind: str) -> None:
    assert evaluate_dev(_fixture(overlap_kind=kind).pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_ties_ratios_and_sign_test_remain_frozen() -> None:
    assert strict_concordant("10", "10", "5", "5") is False
    assert strict_concordant("10.05", "10", "5.2", "5") is False
    assert strict_concordant("0.1000005", "0", "0.1000005", "0") is True
    assert strict_concordant("0.0999995", "0", "0.1000005", "0") is False
    assert strict_concordant("0.1000005", "0", "0.0999995", "0") is False
    assert frozen_ratio("0", "0") == "1.000000000000"
    assert frozen_ratio("1", "0") == "Infinity"
    sign = sign_test_values(8)
    assert sign["observed_numerator"] == 1
    assert sign["observed_p_value"] == "0.003906250000"
    assert sign["threshold_numerator"] == 9
    assert sign["threshold_p_value"] == "0.035156250000"


def test_confirm_uses_frozen_full_precision_predictions_but_reports_only_rounded_values() -> None:
    fixture = _fixture()
    dev, frozen, endpoints = _frozen_path(fixture)
    assert dev.verified_fit.payload["mechanics_fit_mpfr_hex"]["beta"].startswith(("0x", "-0x"))
    assert "mechanics_fit_mpfr_hex" not in dev.report
    assert "dev_constant_prediction_mpfr_hex" not in dev.report
    exact_rows = frozen.verified_predictions.payload["predictions"]
    report_rows = frozen.report["predictions"]
    for slot in CONFIRM_PRIMARY_SLOTS + ("CR01",):
        assert exact_rows[slot]["mechanics_prediction_mpfr_hex"].startswith(("0x", "-0x"))
        assert exact_rows[slot]["raw_prediction_mpfr_hex"].startswith(("0x", "-0x"))
        assert exact_rows[slot]["dev_constant_prediction_mpfr_hex"].startswith(("0x", "-0x"))
        assert all("mpfr_hex" not in key for key in report_rows[slot])

    result = evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set)
    assert result.verdict == "TEST_ONLY_OFFLINE_CONFIRM_THRESHOLDS_MET"
    assert all(all("mpfr_hex" not in key for key in row) for row in result.report["units"])

    repeated = _fixture()
    _, repeated_frozen, _ = _frozen_path(repeated)
    assert repeated_frozen.verified_predictions.content_sha256 == frozen.verified_predictions.content_sha256
    assert repeated_frozen.verified_predictions.payload["predictions"] == exact_rows


def test_reserve_set_requires_typed_pre_maturity_failure_and_rejects_best_eight() -> None:
    fixture = _fixture()
    with pytest.raises(ValueError, match="typed"):
        make_test_only_offline_active_set(fixture, "C01")  # type: ignore[arg-type]
    failure = make_test_only_offline_reserve_failure_fixture(fixture, "C03")
    assert failure.test_only is True
    assert failure.authenticated_failure_evidence is False
    assert failure.reason == "TEST_ONLY_OFFLINE_PRE_MATURITY_FAILURE_SIMULATION"
    reserve = make_test_only_offline_active_set(fixture, failure)
    assert reserve.payload["active_confirm_slots"] == ("C01", "C02", "C04", "C05", "C06", "C07", "C08", "CR01")
    assert reserve.payload["reserve_activation_test_only"] is True
    assert reserve.payload["authenticated_failure_evidence"] is False
    with pytest.raises(ValueError, match="module sentinel"):
        VerifiedActiveSet("eval.v6.3.1.test-only-offline.active-set", fixture.pre_confirm.confirm_pool.content_sha256, "0" * 64, "0" * 64, True, {}, object())
    _, frozen, endpoints = _frozen_path(fixture)
    alternate = replace(fixture.default_active_set, payload={"campaign_root_sha256": fixture.pre_confirm.prereg.parent_root_sha256, "confirm_pool_root_sha256": fixture.pre_confirm.confirm_pool.content_sha256, "active_dev_slots": list(DEV_PRIMARY_SLOTS), "active_confirm_slots": ["C01", "C02", "C03", "C04", "C05", "C06", "C07", "CR01"], "failure_slot_id": None})
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, alternate).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_stale_content_hash_and_numeric_runtime_failure_remain_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture()
    forged_prereg = replace(fixture.pre_confirm.prereg, content_sha256="f" * 64)
    forged_pre = replace(fixture.pre_confirm, prereg=forged_prereg)
    assert evaluate_dev(forged_pre).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"
    monkeypatch.setattr(statistics.gmpy2, "version", lambda: "unexpected")
    assert evaluate_dev(fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_STATISTICS_NUMERIC_DIVERGENCE"


def test_runtime_model_replacement_cannot_reuse_the_literal_root(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture()
    monkeypatch.setattr(statistics, "FROZEN_MODEL", {"numeric": {"required_version": statistics.gmpy2.version()}})
    assert evaluate_dev(fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_STATISTICS_NUMERIC_DIVERGENCE"


def test_in_place_root_and_payload_mutations_fail_even_when_hashes_are_recomputed() -> None:
    fixture = _fixture()
    prereg = fixture.pre_confirm.prereg
    _mutate_and_rehash_artifact(prereg, parent_root="e" * 64)
    assert evaluate_dev(fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    features = fixture.pre_confirm.local_features
    forged_payload = {"features": {slot: dict(row) for slot, row in features.payload["features"].items()}}
    forged_payload["features"]["D01"] = {"mechanics": dict(features.payload["features"]["D01"]["mechanics"]), "raw_comparator_R": "0"}
    _mutate_and_rehash_artifact(features, payload=forged_payload)
    assert evaluate_dev(fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_dev_fit_and_dev_result_mutations_cannot_reach_prediction_freeze() -> None:
    fixture = _fixture()
    dev = evaluate_dev(fixture.pre_confirm)
    fit = dev.verified_fit
    payload = dict(fit.payload)
    mechanics_fit = dict(payload["mechanics_fit"])
    mechanics_fit["beta"] = "999.000000000000"
    payload["mechanics_fit"] = mechanics_fit
    _mutate_and_rehash_artifact(fit, payload=payload)
    assert freeze_confirm_predictions(dev, fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    dev = evaluate_dev(fixture.pre_confirm)
    forged_report = dict(dev.report)
    forged_report["calibration_upload_authorized"] = True
    object.__setattr__(dev, "report", forged_report)
    assert freeze_confirm_predictions(dev, fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    dev = evaluate_dev(fixture.pre_confirm)
    assert freeze_confirm_predictions(replace(dev), fixture.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"


def test_prediction_payload_report_and_verdict_mutations_are_rejected() -> None:
    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    predictions = frozen.verified_predictions
    payload = dict(predictions.payload)
    table = {slot: dict(row) for slot, row in payload["predictions"].items()}
    table["C01"]["mechanics_prediction_points"] = "999.000000"
    payload["predictions"] = table
    _mutate_and_rehash_artifact(predictions, payload=payload)
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    predictions = frozen.verified_predictions
    payload = dict(predictions.payload)
    table = {slot: dict(row) for slot, row in payload["predictions"].items()}
    table["C01"]["mechanics_prediction_mpfr_hex"] = table["C02"]["mechanics_prediction_mpfr_hex"]
    table["C01"]["mechanics_prediction_points"] = table["C02"]["mechanics_prediction_points"]
    payload["predictions"] = table
    _mutate_and_rehash_artifact(predictions, payload=payload)
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    _, frozen, _ = _frozen_path(fixture)
    object.__setattr__(frozen, "verdict", "FORGED_OFFLINE_PREDICTION_STATE")
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_confirm_endpoints(fixture, frozen)

    fixture = _fixture()
    _, frozen, _ = _frozen_path(fixture)
    report = dict(frozen.report)
    report["production_upload_authorized"] = True
    object.__setattr__(frozen, "report", report)
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_confirm_endpoints(fixture, frozen)


def test_active_set_endpoint_outcome_failure_and_fixture_mutations_are_rejected() -> None:
    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    active = fixture.default_active_set
    active_payload = dict(active.payload)
    active_payload["active_confirm_slots"] = ["C01", "C02", "C03", "C04", "C05", "C06", "C07", "CR01"]
    _mutate_and_rehash_artifact(active, payload=active_payload)
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, active).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    endpoint_payload = dict(endpoints.payload)
    endpoint_rows = {slot: dict(row) for slot, row in endpoint_payload["endpoints"].items()}
    endpoint_rows["C01"]["yobs_score_points"] = "9999"
    endpoint_payload["endpoints"] = endpoint_rows
    _mutate_and_rehash_artifact(endpoints, payload=endpoint_payload)
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    endpoint_payload = dict(endpoints.payload)
    endpoint_payload["leakage_marked"] = True
    _mutate_and_rehash_artifact(endpoints, payload=endpoint_payload)
    assert evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    fixture = _fixture()
    dev = evaluate_dev(fixture.pre_confirm)
    frozen = freeze_confirm_predictions(dev, fixture.pre_confirm)
    outcomes = fixture.confirm_outcomes
    rows = {slot: dict(row) for slot, row in outcomes.endpoints.items()}
    rows["C01"]["yobs_score_points"] = "9999"
    object.__setattr__(outcomes, "endpoints", rows)
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_confirm_endpoints(fixture, frozen)

    fixture = _fixture()
    failure = make_test_only_offline_reserve_failure_fixture(fixture, "C03")
    object.__setattr__(failure, "slot_id", "C04")
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_active_set(fixture, failure)

    fixture = _fixture()
    failure = make_test_only_offline_reserve_failure_fixture(fixture, "C03")
    object.__setattr__(failure, "authenticated_failure_evidence", True)
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_active_set(fixture, failure)

    fixture = _fixture()
    failure = make_test_only_offline_reserve_failure_fixture(fixture, "C03")
    with pytest.raises(ValueError, match="not issued"):
        make_test_only_offline_active_set(fixture, replace(failure, slot_id="C04"))

    first = _fixture()
    second = _fixture(archive_offset=100)
    object.__setattr__(first.pre_confirm, "local_features", second.pre_confirm.local_features)
    assert evaluate_dev(first.pre_confirm).verdict == "TEST_ONLY_OFFLINE_VERIFIED_INPUT_INVALID"

    first = _fixture()
    second = _fixture(archive_offset=100)
    object.__setattr__(first, "confirm_outcomes", second.confirm_outcomes)
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_active_set(first)

    fixture = _fixture()
    object.__setattr__(fixture, "test_only", False)
    with pytest.raises(ValueError, match="issuance snapshot"):
        make_test_only_offline_active_set(fixture)


def test_confirm_result_verdict_report_and_authority_mutations_fail_validation() -> None:
    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    result = evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set)
    assert validate_issued_statistics_result(result) is result
    forged_report = dict(result.report)
    forged_report["calibration_upload_authorized"] = True
    forged_report["production_upload_authorized"] = True
    forged_report["independent_ab_numeric_agreement_verified"] = True
    forged_report["bootstrap_support_10000_verified"] = True
    forged_report["feature_spec_complete"] = True
    forged_report["assignment_support_authenticated"] = True
    forged_report["timestamp_evidence_verified"] = True
    forged_report["predictive_validity_established"] = True
    object.__setattr__(result, "report", forged_report)
    object.__setattr__(result, "verdict", "FORGED_AUTHORITY_STATE")
    with pytest.raises(ValueError, match="issuance snapshot"):
        validate_issued_statistics_result(result)

    fixture = _fixture()
    _, frozen, endpoints = _frozen_path(fixture)
    result = evaluate_confirm(frozen, fixture.pre_confirm, endpoints, fixture.default_active_set)
    with pytest.raises(ValueError, match="not issued"):
        validate_issued_statistics_result(replace(result))


def test_deterministic_golden_vector() -> None:
    assert canonical_sha256(FROZEN_MODEL) == FROZEN_MODEL_ROOT_SHA256
    with pytest.raises(TypeError):
        FROZEN_MODEL["support"]["criterion_available"] = True  # type: ignore[index]
    with pytest.raises(TypeError):
        FROZEN_NUMERIC_GOLDEN_VECTOR["x"][0] = "999"  # type: ignore[index]
    golden = nig_golden_vector()
    assert golden["intercept"] == FROZEN_NUMERIC_GOLDEN_VECTOR["intercept"]
    assert golden["beta"] == FROZEN_NUMERIC_GOLDEN_VECTOR["beta"]
    assert golden["prediction_points"] == FROZEN_NUMERIC_GOLDEN_VECTOR["prediction_points"]
