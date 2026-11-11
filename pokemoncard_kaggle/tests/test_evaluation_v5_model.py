from __future__ import annotations

from copy import deepcopy
import math

import pytest

from evaluation_v5.charter import FEATURE_NAMES
from evaluation_v5.model import (
    COMPARATOR_IDENTITIES,
    COMPARATOR_INPUT_KEYS,
    MODEL_SCHEMA,
    PredictionManifestError,
    build_prediction_manifest,
    build_prediction_rows,
    predict_game_probability,
    predict_probability,
    prediction_manifest_sha256,
    validate_prediction_manifest,
)


STAMP = "2026-07-13T00:00:00.000000Z"
REGISTRATION = "2026-07-14T00:00:00.000000Z"
PACKAGE = "a" * 64


def _wire(*, kind: str = "MCI") -> dict[str, object]:
    values = {name: 0.25 for name in FEATURE_NAMES}
    return {
        "schema": MODEL_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "feature_names": list(FEATURE_NAMES),
        "standardization_means": values.copy(),
        "standardization_scales": {name: 0.5 for name in FEATURE_NAMES},
        "feature_weights": {name: (1.0 if kind == "MCI" else 0.0) for name in FEATURE_NAMES},
        "intercept": 0.0,
        "mci_slope": 0.2 if kind == "MCI" else 0.0,
        "era_effects": {"2026Q3": 0.1},
        "seat_effects": {"0": 0.05, "1": -0.05},
        "opponent_rating_knots": [1000.0, 1500.0, 2000.0],
        "opponent_rating_values": [-0.2, 0.0, 0.2],
        "rating_interpolation": "piecewise_linear_clamp",
        "probability_epsilon": 0.001,
        "model_kind": kind,
        "comparator_identity": None if kind == "MCI" else "raw local win-rate model",
        "comparator_input_key": None if kind == "MCI" else "raw_local_win_rate",
        "comparator_input_mean": None if kind == "MCI" else 0.5,
        "comparator_input_scale": None if kind == "MCI" else 0.5,
        "comparator_slope": None if kind == "MCI" else 0.2,
        "comparator_null_value": None if kind == "MCI" else 0.5,
        "comparator_missing_behavior": "NOT_APPLICABLE" if kind == "MCI" else "USE_FROZEN_NULL_VALUE",
        "development_evidence_sha256": "b" * 64,
        "executable_sha256": "c" * 64,
        "created_at_utc": STAMP,
    }


def _game(index: int, *, outcome: object = 1.0) -> dict[str, object]:
    return {
        "game_id": f"game-{index:02d}",
        "hosted_at_utc": f"2026-07-15T00:0{index}:00.000000Z",
        "outcome": outcome,
        "features": {name: (index % 3) / 2.0 for name in reversed(FEATURE_NAMES)},
        "era": "2026Q3",
        "seat": index % 2,
        "opponent_rating": 1500 + index,
    }


def test_deterministic_predictions_and_canonical_hash() -> None:
    manifest = build_prediction_manifest(_wire())
    features = {name: 0.25 for name in reversed(FEATURE_NAMES)}
    first = predict_probability(manifest, features, era="2026Q3", seat=0, opponent_rating=1500)
    second = manifest.predict_probability(dict(reversed(list(features.items()))), era="2026Q3", seat=0, opponent_rating=1500)
    assert first == second
    assert prediction_manifest_sha256(manifest) == prediction_manifest_sha256(manifest.as_dict())
    assert prediction_manifest_sha256(manifest) == manifest.manifest_sha256


def test_manifest_is_immutable_and_tamper_is_rejected() -> None:
    manifest = build_prediction_manifest(_wire())
    with pytest.raises(TypeError):
        manifest.feature_weights[FEATURE_NAMES[0]] = 9.0  # type: ignore[index]
    tampered = deepcopy(manifest.as_dict())
    tampered["intercept"] = 1.0
    validate_prediction_manifest(tampered)
    assert prediction_manifest_sha256(manifest) != prediction_manifest_sha256(tampered)


@pytest.mark.parametrize(
    "change,match",
    [
        (lambda value: value.update({"unknown": 1}), "fields must exactly"),
        (lambda value: value["feature_weights"].pop(FEATURE_NAMES[0]), "exactly the six"),
        (lambda value: value.update({"intercept": math.nan}), "finite"),
        (lambda value: value.update({"standardization_scales": {name: 0.5 for name in FEATURE_NAMES} | {FEATURE_NAMES[0]: 0.0}}), "positive"),
        (lambda value: value.update({"opponent_rating_knots": [1000.0, 1000.0], "opponent_rating_values": [0.0, 0.1]}), "ordered and unique"),
        (lambda value: value.update({"mci_slope": -0.1}), "non-negative"),
    ],
)
def test_malformed_manifest_is_rejected(change, match: str) -> None:
    value = _wire()
    change(value)
    with pytest.raises(PredictionManifestError, match=match):
        build_prediction_manifest(value)


def test_probability_epsilon_is_strict_and_never_clipped() -> None:
    value = _wire()
    value["intercept"] = 1000.0
    manifest = build_prediction_manifest(value)
    with pytest.raises(PredictionManifestError, match="not clipped"):
        manifest.predict_probability(
            {name: 0.25 for name in FEATURE_NAMES}, era="2026Q3", seat=0, opponent_rating=1500
        )


def test_mci_cannot_bind_or_consume_old_comparator_metrics() -> None:
    value = _wire()
    value["comparator_identity"] = COMPARATOR_IDENTITIES[1]
    with pytest.raises(PredictionManifestError, match="cannot bind comparator"):
        build_prediction_manifest(value)

    manifest = build_prediction_manifest(_wire())
    game = _game(0)
    baseline = manifest.predict_probability(
        game["features"], era="2026Q3", seat=0, opponent_rating=1500
    )
    game["comparator_inputs"] = {"raw_local_win_rate": 0.99}
    assert manifest.predict_probability(
        game["features"], era="2026Q3", seat=0, opponent_rating=1500
    ) == baseline


def test_comparator_uses_frozen_scalar_and_missing_maps_to_frozen_null() -> None:
    comparator = build_prediction_manifest(_wire(kind="FROZEN_COMPARATOR"))
    game = _game(0)
    game["raw_local_win_rate"] = 0.99
    missing = comparator.predict_probability(
        None, era="2026Q3", seat=0, opponent_rating=1500,
        comparator_input=None,
    )
    explicit_null = comparator.predict_probability(
        None, era="2026Q3", seat=0, opponent_rating=1500,
        comparator_input=0.5,
    )
    assert missing == explicit_null
    assert predict_probability(
        comparator, None, era="2026Q3", seat=0, opponent_rating=1500,
        comparator_input=0.99,
    ) != missing
    assert predict_game_probability(comparator, game) == missing
    game["comparator_inputs"] = {"unrelated_alias": 0.99}
    assert predict_game_probability(comparator, game) == missing
    without_mci_features = dict(game)
    without_mci_features.pop("features")
    assert predict_game_probability(comparator, without_mci_features) == missing


@pytest.mark.parametrize(
    ("identity", "key"),
    [(identity, key) for identity, key in COMPARATOR_INPUT_KEYS.items() if key is not None],
)
def test_comparator_key_is_identity_bound_and_rejects_aliases(identity: str, key: str) -> None:
    value = _wire(kind="FROZEN_COMPARATOR")
    value["comparator_identity"] = identity
    value["comparator_input_key"] = key
    build_prediction_manifest(value)

    alias = deepcopy(value)
    alias["comparator_input_key"] = "public_outcome"
    with pytest.raises(PredictionManifestError, match="frozen key"):
        build_prediction_manifest(alias)


def test_missing_comparator_value_must_be_the_centered_null() -> None:
    value = _wire(kind="FROZEN_COMPARATOR")
    value["comparator_null_value"] = 0.6
    with pytest.raises(PredictionManifestError, match="must equal comparator_input_mean"):
        build_prediction_manifest(value)


def test_nuisance_only_comparator_is_explicit_and_hash_binds_comparator_contract() -> None:
    value = _wire(kind="FROZEN_COMPARATOR")
    for field in (
        "comparator_input_key",
        "comparator_input_mean",
        "comparator_input_scale",
        "comparator_slope",
        "comparator_null_value",
    ):
        value[field] = None
    value["comparator_identity"] = "nuisance-only null model"
    value["comparator_missing_behavior"] = "NUISANCE_ONLY"
    nuisance = build_prediction_manifest(value)
    game_features = {name: 0.0 for name in FEATURE_NAMES}
    assert nuisance.predict_probability(
        game_features, era="2026Q3", seat=0, opponent_rating=1500
    ) == nuisance.predict_probability(
        None, era="2026Q3", seat=0, opponent_rating=1500, comparator_input=0.99
    )

    changed = deepcopy(nuisance.as_dict())
    changed["comparator_missing_behavior"] = "NUISANCE_ONLY"
    changed["comparator_identity"] = "L/T mean model"
    changed["comparator_input_key"] = "lt_mean"
    changed["comparator_input_mean"] = 0.0
    changed["comparator_input_scale"] = 1.0
    changed["comparator_slope"] = 0.1
    changed["comparator_null_value"] = 0.0
    changed["comparator_missing_behavior"] = "USE_FROZEN_NULL_VALUE"
    assert prediction_manifest_sha256(changed) != nuisance.manifest_sha256


def test_build_rows_binds_identity_and_is_input_order_invariant() -> None:
    mci = build_prediction_manifest(_wire(kind="MCI"))
    comparator = build_prediction_manifest(_wire(kind="FROZEN_COMPARATOR"))
    games = [_game(1), _game(0)]
    rows = build_prediction_rows(
        mci,
        comparator,
        games,
        archive_id="archive-1",
        family_id="family-1",
        registered_package_hash=PACKAGE,
        registration_at_utc=REGISTRATION,
    )
    reversed_rows = build_prediction_rows(
        mci,
        comparator,
        list(reversed(games)),
        archive_id="archive-1",
        family_id="family-1",
        registered_package_hash=PACKAGE,
        registration_at_utc=REGISTRATION,
    )
    assert rows == reversed_rows
    assert [row["game_id"] for row in rows] == ["game-00", "game-01"]
    assert set(rows[0]) == {
        "schema", "archive_id", "family_id", "independent_family",
        "registered_package_hash", "hosted_package_hash", "registration_at_utc",
        "hosted_at_utc", "game_id", "outcome", "baseline_probability",
        "mci_probability", "literal_valid_hosted_game", "runtime_substituted",
        "validation_substituted",
    }


def test_timestamp_and_identity_mismatch_are_rejected() -> None:
    manifest = build_prediction_manifest(_wire())
    comparator = build_prediction_manifest(_wire(kind="FROZEN_COMPARATOR"))
    with pytest.raises(PredictionManifestError, match="before confirmatory"):
        build_prediction_rows(
            manifest, comparator, [_game(0)], archive_id="a", family_id="f",
            registered_package_hash=PACKAGE, registration_at_utc=STAMP,
        )
    game = _game(0)
    game["archive_id"] = "other"
    with pytest.raises(PredictionManifestError, match="does not match"):
        build_prediction_rows(
            manifest, comparator, [game], archive_id="a", family_id="f",
            registered_package_hash=PACKAGE, registration_at_utc=REGISTRATION,
        )


def test_prediction_input_rejects_unknown_feature() -> None:
    manifest = build_prediction_manifest(_wire())
    features = {name: 0.25 for name in FEATURE_NAMES}
    features["outcome"] = 1.0
    with pytest.raises(PredictionManifestError, match="exactly the six"):
        manifest.predict_probability(features, era="2026Q3", seat=0, opponent_rating=1500)
