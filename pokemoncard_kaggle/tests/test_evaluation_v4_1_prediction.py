from __future__ import annotations

import copy
import uuid

import pytest

from evaluation_v4.predictor import build_predictor_model, build_simulation_feature
from evaluation_v4_1.prediction import (
    PredictionBundleError,
    build_prediction_bundle,
    predictor_context_sha256,
    validate_prediction_bundle,
    write_prediction_bundle_once,
)
from evaluation_v4_1.protocol import build_pair_assignment, build_population_manifest


def _base_protocol() -> dict[str, object]:
    return {
        "schema": "voi_p5_protocol_v1",
        "protocol_id": "voi-p5-prediction-test",
        "retired_v4_manifest_sha256": "a" * 64,
        "evidence_budget_allocation_event_sha256": "b" * 64,
        "candidate_grammar_sha256": "c" * 64,
        "eligibility_code_sha256": "d" * 64,
        "family_ontology_sha256": "e" * 64,
        "runtime_manifest_sha256": "f" * 64,
        "selector_model_sha256": "0" * 64,
        "external_beacon_source": "https://beacon.nist.gov/beacon/2.0",
        "external_beacon_selection_rule": "first_signed_pulse_strictly_after_population_rfc3161_grant_plus_fixed_delay",
        "external_beacon_delay_seconds": 120,
        "clipping": 0.05,
        "endpoint": "first24_hosted_mean_win_plus_half_draw",
        "setup_games": 0,
        "horizon_games": 24,
        "pairs": 5,
        "selected_lineages": 10,
        "source_population_lineages": 16,
        "family_ids": ["family-a", "family-b", "family-c", "family-d"],
        "waves": ["wave-1", "wave-2", "wave-3"],
        "pair_allocation": {"wave-1": 2, "wave-2": 2, "wave-3": 1},
        "no_replacement": True,
        "interim_efficacy_looks": 0,
        "primary_rule": "all_five_strict_positive",
        "proper_score_lift_floor": 0.015,
        "confirmatory_alpha": 0.03125,
        "research_only": True,
        "sealed_holdout_id": "sealed-50-game-holdout",
        "frozen_at_utc": "2026-07-11T08:00:00.000000Z",
        "state": "FROZEN",
    }


def _model(*, tied: bool = False) -> dict[str, object]:
    base = _base_protocol()
    coefficients = {
        "intercept": 0.0,
        "simulator_delta": 0.0 if tied else 1.0,
        "candidate_visited_ood_mass": 0.0,
        "minimum_engine_variant_mean": 0.0,
        "minimum_opponent_family_mean": 0.0,
        "minimum_rating_layer_mean": 0.0,
    }
    return build_predictor_model(
        {
            "schema": "whole_policy_predictor_model_v1",
            "protocol_sha256": predictor_context_sha256(base),
            "lineage_manifest_sha256": "1" * 64,
            "training_manifest_sha256": "2" * 64,
            "training_code_sha256": "3" * 64,
            "simulation_design_schema": "whole_policy_simulation_design_v1",
            "feature_schema": "whole_policy_simulation_feature_v1",
            "training_ancestry_ids": ["training-ancestry"],
            "probability_clip": 0.05,
            "nuisance_logit_intercept": 0.0,
            "selector_coefficients": coefficients,
            "state": "FROZEN",
        }
    )


def _protocol(model: dict[str, object]) -> dict[str, object]:
    protocol = _base_protocol()
    protocol["selector_model_sha256"] = model["content_sha256"]
    return protocol


def _records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for family_index, family in enumerate(_base_protocol()["family_ids"]):
        for member_index in range(4):
            index = family_index * 4 + member_index
            records.append(
                {
                    "lineage_uuid": str(uuid.UUID(int=index + 1)),
                    "archive_sha256": f"{index + 1:064x}",
                    "policy_content_sha256": f"{index + 101:064x}",
                    "deck_sha256": f"{index + 201:064x}",
                    "lineage_id": f"lineage-{index:02d}",
                    "ancestry_id": f"ancestry-{index:02d}",
                    "family_id": family,
                    "compute_budget_id": "budget-fixed",
                }
            )
    return records


def _artifacts(*, tied: bool = False) -> tuple[dict[str, object], ...]:
    model = _model(tied=tied)
    protocol = _protocol(model)
    population = build_population_manifest(protocol, _records())
    assignment = build_pair_assignment(protocol, population, "4" * 64, "nist-chain-2-pulse-1")
    by_uuid = {record["lineage_uuid"]: record for record in population["records"]}
    features = {}
    for lineage_uuid in assignment["selected_lineage_uuids"]:
        record = by_uuid[lineage_uuid]
        index = uuid.UUID(lineage_uuid).int
        features[lineage_uuid] = build_simulation_feature(
            {
                "schema": "whole_policy_simulation_feature_v1",
                "feature_schema": "whole_policy_simulation_feature_v1",
                "candidate_archive_sha256": record["archive_sha256"],
                "design_manifest_sha256": protocol["runtime_manifest_sha256"],
                "ancestry_id": record["ancestry_id"],
                "features": {
                    "intercept": 1.0,
                    "simulator_delta": index / 100.0,
                    "candidate_visited_ood_mass": 0.05,
                    "minimum_engine_variant_mean": 0.0,
                    "minimum_opponent_family_mean": 0.0,
                    "minimum_rating_layer_mean": 0.0,
                },
            }
        )
    return protocol, population, assignment, model, features


def _bundle() -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    artifacts = _artifacts()
    protocol, population, assignment, model, features = artifacts
    bundle = build_prediction_bundle(
        protocol=protocol,
        population_manifest=population,
        pair_assignment=assignment,
        predictor_model=model,
        features_by_lineage_uuid=features,
        created_at_utc="2026-07-11T09:00:00.000000Z",
    )
    return bundle, artifacts


def test_bundle_recomputes_all_ten_predictions_and_five_preferences() -> None:
    bundle, artifacts = _bundle()
    assert len(bundle["records"]) == 10
    assert len(bundle["pair_preferences"]) == 5
    assert bundle["research_only"] is True
    assert bundle["production_submission_authorized"] is False
    assert validate_prediction_bundle(
        bundle,
        protocol=artifacts[0],
        population_manifest=artifacts[1],
        pair_assignment=artifacts[2],
        predictor_model=artifacts[3],
    ) == bundle


def test_cached_probability_or_preference_mutation_is_rejected() -> None:
    bundle, artifacts = _bundle()
    poisoned = copy.deepcopy(bundle)
    poisoned["records"][0]["prediction"]["p1"] = 0.95
    with pytest.raises(PredictionBundleError, match="exact recomputed"):
        validate_prediction_bundle(
            poisoned,
            protocol=artifacts[0],
            population_manifest=artifacts[1],
            pair_assignment=artifacts[2],
            predictor_model=artifacts[3],
        )

    poisoned = copy.deepcopy(bundle)
    poisoned["pair_preferences"][0]["selected_member"] = (
        "B" if poisoned["pair_preferences"][0]["selected_member"] == "A" else "A"
    )
    with pytest.raises(PredictionBundleError, match="exact recomputed"):
        validate_prediction_bundle(
            poisoned,
            protocol=artifacts[0],
            population_manifest=artifacts[1],
            pair_assignment=artifacts[2],
            predictor_model=artifacts[3],
        )


def test_feature_roster_archive_ancestry_and_design_are_exact() -> None:
    protocol, population, assignment, model, features = _artifacts()
    missing = dict(features)
    missing.pop(next(iter(missing)))
    with pytest.raises(PredictionBundleError, match="exactly cover"):
        build_prediction_bundle(
            protocol=protocol,
            population_manifest=population,
            pair_assignment=assignment,
            predictor_model=model,
            features_by_lineage_uuid=missing,
            created_at_utc="2026-07-11T09:00:00.000000Z",
        )

    lineage_uuid = next(iter(features))
    changed = copy.deepcopy(features)
    feature = dict(changed[lineage_uuid])
    feature["ancestry_id"] = "wrong-ancestry"
    feature.pop("content_sha256")
    changed[lineage_uuid] = build_simulation_feature(feature)
    with pytest.raises(PredictionBundleError, match="ancestry"):
        build_prediction_bundle(
            protocol=protocol,
            population_manifest=population,
            pair_assignment=assignment,
            predictor_model=model,
            features_by_lineage_uuid=changed,
            created_at_utc="2026-07-11T09:00:00.000000Z",
        )


def test_selector_tie_is_protocol_failure() -> None:
    protocol, population, assignment, model, features = _artifacts(tied=True)
    with pytest.raises(PredictionBundleError, match="p1 tie"):
        build_prediction_bundle(
            protocol=protocol,
            population_manifest=population,
            pair_assignment=assignment,
            predictor_model=model,
            features_by_lineage_uuid=features,
            created_at_utc="2026-07-11T09:00:00.000000Z",
        )


def test_model_hash_clip_and_context_are_protocol_bound() -> None:
    protocol, population, assignment, model, features = _artifacts()
    wrong = copy.deepcopy(protocol)
    wrong["selector_model_sha256"] = "9" * 64
    with pytest.raises(PredictionBundleError, match="selector_model_sha256"):
        build_prediction_bundle(
            protocol=wrong,
            population_manifest=build_population_manifest(wrong, _records()),
            pair_assignment=build_pair_assignment(
                wrong,
                build_population_manifest(wrong, _records()),
                "4" * 64,
                "nist-chain-2-pulse-1",
            ),
            predictor_model=model,
            features_by_lineage_uuid=features,
            created_at_utc="2026-07-11T09:00:00.000000Z",
        )


def test_create_once_writer_refuses_overwrite(tmp_path: object) -> None:
    bundle, artifacts = _bundle()
    path = tmp_path / "prediction.json"  # type: ignore[operator]
    kwargs = {
        "protocol": artifacts[0],
        "population_manifest": artifacts[1],
        "pair_assignment": artifacts[2],
        "predictor_model": artifacts[3],
    }
    assert write_prediction_bundle_once(path, bundle, **kwargs) == path
    with pytest.raises(FileExistsError):
        write_prediction_bundle_once(path, bundle, **kwargs)
