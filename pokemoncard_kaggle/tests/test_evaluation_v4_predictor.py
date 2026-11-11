from __future__ import annotations

from copy import deepcopy
import json
import math

import pytest

from evaluation_v4.predictor import (
    FEATURE_NAMES,
    PREDICTION_RECEIPT_SCHEMA,
    PredictorError,
    build_predictor_model,
    build_simulation_feature,
    canonical_sha256,
    recompute_prediction,
    validate_predictor_model,
    write_predictor_model_once,
)


def _model_content() -> dict[str, object]:
    return {
        "schema": "whole_policy_predictor_model_v1",
        "protocol_sha256": "1" * 64,
        "lineage_manifest_sha256": "2" * 64,
        "training_manifest_sha256": "3" * 64,
        "training_code_sha256": "4" * 64,
        "simulation_design_schema": "whole_policy_simulation_design_v1",
        "feature_schema": "whole_policy_simulation_feature_v1",
        "training_ancestry_ids": ["ancestry-a", "ancestry-c"],
        "probability_clip": 0.01,
        "nuisance_logit_intercept": -0.25,
        "selector_coefficients": {
            "intercept": 0.10,
            "simulator_delta": 1.25,
            "candidate_visited_ood_mass": -0.50,
            "minimum_engine_variant_mean": 0.75,
            "minimum_opponent_family_mean": 0.60,
            "minimum_rating_layer_mean": 0.40,
        },
        "state": "FROZEN",
    }


def _feature_content(**changes: object) -> dict[str, object]:
    content: dict[str, object] = {
        "schema": "whole_policy_simulation_feature_v1",
        "feature_schema": "whole_policy_simulation_feature_v1",
        "candidate_archive_sha256": "a" * 64,
        "design_manifest_sha256": "b" * 64,
        "ancestry_id": "ancestry-z",
        "features": {
            "intercept": 1.0,
            "simulator_delta": 0.20,
            "candidate_visited_ood_mass": 0.08,
            "minimum_engine_variant_mean": 0.10,
            "minimum_opponent_family_mean": 0.05,
            "minimum_rating_layer_mean": -0.02,
        },
    }
    content.update(changes)
    return content


def _model() -> dict[str, object]:
    return build_predictor_model(_model_content())


def _feature() -> dict[str, object]:
    return build_simulation_feature(_feature_content())


def test_model_is_canonical_hash_bound_and_frozen() -> None:
    model = _model()
    assert model["state"] == "FROZEN"
    assert model["content_sha256"] == canonical_sha256(
        {key: value for key, value in model.items() if key != "content_sha256"}
    )
    reordered = {key: model[key] for key in reversed(list(model))}
    assert validate_predictor_model(reordered) == model


def test_recomputation_ignores_injected_cached_probabilities() -> None:
    model = _model()
    feature = _feature()
    receipt = recompute_prediction(model, feature, expected_archive_sha256="a" * 64)
    poisoned = deepcopy(feature)
    poisoned["cached_p0"] = 0.999999
    poisoned["cached_p1"] = 0.000001
    with pytest.raises(PredictorError, match="fields must exactly"):
        recompute_prediction(model, poisoned, expected_archive_sha256="a" * 64)
    assert receipt["schema"] == PREDICTION_RECEIPT_SCHEMA
    assert set(receipt) == {
        "schema",
        "predictor_model_sha256",
        "simulation_feature_content_sha256",
        "p0",
        "p1",
        "raw_logit_adjustment",
    }
    assert not {"outcome", "certification", "authorization"}.intersection(receipt)


def test_ancestry_overlap_and_archive_mismatch_are_rejected() -> None:
    model = _model()
    feature = _feature()
    overlapping = _feature_content(ancestry_id="ancestry-a")
    with pytest.raises(PredictorError, match="overlaps training ancestry"):
        recompute_prediction(model, build_simulation_feature(overlapping), expected_archive_sha256="a" * 64)
    with pytest.raises(PredictorError, match="does not match expected"):
        recompute_prediction(model, feature, expected_archive_sha256="c" * 64)
    with pytest.raises(PredictorError, match="required"):
        recompute_prediction(model, feature)


def test_model_and_feature_mutation_cannot_survive_content_hash_validation() -> None:
    model = _model()
    mutated_model = deepcopy(model)
    mutated_model["nuisance_logit_intercept"] = 4.0
    with pytest.raises(PredictorError, match="content_sha256 mismatch"):
        validate_predictor_model(mutated_model)

    feature = _feature()
    mutated_feature = deepcopy(feature)
    mutated_feature["features"]["simulator_delta"] = 9.0  # type: ignore[index]
    with pytest.raises(PredictorError, match="content_sha256 mismatch"):
        recompute_prediction(model, mutated_feature, expected_archive_sha256="a" * 64)


def test_ood_mass_must_be_in_unit_interval() -> None:
    feature = _feature_content()
    feature["features"]["candidate_visited_ood_mass"] = 1.000001  # type: ignore[index]
    with pytest.raises(PredictorError, match=r"in \[0, 1\]"):
        build_simulation_feature(feature)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["selector_coefficients"].pop("intercept"),
        lambda value: value["selector_coefficients"].__setitem__("unexpected", 0.0),
        lambda value: value["selector_coefficients"].__setitem__("simulator_delta", float("nan")),
    ],
)
def test_coefficients_must_exactly_cover_finite_feature_schema(mutate: object) -> None:
    content = _model_content()
    mutate(content)  # type: ignore[operator]
    with pytest.raises(PredictorError):
        build_predictor_model(content)
    assert set(FEATURE_NAMES) == set(_model_content()["selector_coefficients"])  # type: ignore[arg-type]


def test_extreme_finite_values_are_clipped() -> None:
    model_content = _model_content()
    model_content["nuisance_logit_intercept"] = 1_000_000.0
    model_content["selector_coefficients"] = {name: 1_000_000.0 for name in FEATURE_NAMES}
    model = build_predictor_model(model_content)
    receipt = recompute_prediction(model, _feature(), expected_archive_sha256="a" * 64)
    assert receipt["p0"] == 0.99
    assert receipt["p1"] == 0.99
    assert math.isfinite(receipt["raw_logit_adjustment"])

    model_content["nuisance_logit_intercept"] = -1_000_000.0
    model_content["selector_coefficients"] = {name: -1_000_000.0 for name in FEATURE_NAMES}
    model = build_predictor_model(model_content)
    receipt = recompute_prediction(model, _feature(), expected_archive_sha256="a" * 64)
    assert receipt["p0"] == 0.01
    assert receipt["p1"] == 0.01


def test_deterministic_and_input_order_invariant() -> None:
    model = _model()
    feature = _feature()
    first = recompute_prediction(model, feature, expected_archive_sha256="a" * 64)
    reordered = {
        "content_sha256": feature["content_sha256"],
        "features": {key: feature["features"][key] for key in reversed(FEATURE_NAMES)},  # type: ignore[index]
        "ancestry_id": feature["ancestry_id"],
        "design_manifest_sha256": feature["design_manifest_sha256"],
        "candidate_archive_sha256": feature["candidate_archive_sha256"],
        "feature_schema": feature["feature_schema"],
        "schema": feature["schema"],
    }
    assert recompute_prediction(model, reordered, expected_archive_sha256="a" * 64) == first


def test_write_once_is_durable_canonical_and_rejects_second_write(tmp_path: object) -> None:
    path = tmp_path / "nested" / "predictor.json"  # type: ignore[operator]
    model = _model()
    assert write_predictor_model_once(path, model) == path
    assert json.loads(path.read_text(encoding="ascii")) == model
    with pytest.raises(FileExistsError):
        write_predictor_model_once(path, model)
