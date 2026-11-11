"""Development-only fitter for the frozen v5 prediction representation.

This module consumes only explicit ``DEV_BURNED`` rows supplied by its caller.
It neither discovers files nor reaches into any outcome store.  Its output is
research metadata with permanently false authority flags.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
import math
import os
from pathlib import Path
import re
from typing import Any
import warnings

import numpy as np
from sklearn import __version__ as sklearn_version
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from .canonical import canonical_json_bytes, canonical_sha256
from .charter import FEATURE_NAMES, PROTOCOL_ID
from .engine_capabilities import (
    EngineCapabilityError,
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)
from .firewall import DEV_BURNED
from .model import (
    COMPARATOR_IDENTITIES,
    COMPARATOR_INPUT_KEYS,
    MODEL_SCHEMA,
    PredictionManifest,
    build_prediction_manifest,
)


DEVELOPMENT_ROW_SCHEMA = "evaluation_v5_development_burned_row_v1"
DEVELOPMENT_FIT_RESULT_SCHEMA = "evaluation_v5_development_fit_result_v1"
RATING_KNOTS = (0.0, 600.0, 900.0, 1200.0, 1500.0, 1800.0, 2400.0)
RATING_INTERPOLATION = "piecewise_linear_clamp"
PROBABILITY_EPSILON = 1e-12
RUNTIME_VERSIONS = {
    "numpy": str(np.__version__),
    "sklearn": str(sklearn_version),
}
FIT_CONFIG = {
    "estimator": "sklearn.linear_model.LogisticRegression",
    "penalty": "l2",
    "solver": "lbfgs",
    "C": 1.0,
    "max_iter": 2000,
    "random_state": 0,
    "rating_knots": list(RATING_KNOTS),
    "rating_interpolation": RATING_INTERPOLATION,
    "sample_weighting": "archive_balanced_mean_weight_one",
    "numpy_version": RUNTIME_VERSIONS["numpy"],
    "sklearn_version": RUNTIME_VERSIONS["sklearn"],
}
REPRODUCTION_TOLERANCE = 1e-12

_ROW_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "partition",
        "engine_manifest_sha256",
        "archive_id",
        "lineage_id",
        "family_id",
        "game_id",
        "features",
        "comparator_inputs",
        "era",
        "seat",
        "opponent_rating",
        "outcome",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMPARATOR_KEYS = tuple(
    key for key in COMPARATOR_INPUT_KEYS.values() if key is not None
)


class DevelopmentFitError(ValueError):
    """Development rows or fixed fitting inputs violate the frozen contract."""


class DevelopmentFitConvergenceError(DevelopmentFitError):
    """A fixed sklearn fit did not demonstrably converge."""


def fit_development_models(
    rows: Iterable[Mapping[str, Any]],
    *,
    engine_capability_manifest: object,
    development_evidence_sha256: str,
    executable_sha256: str,
    created_at_utc: str,
) -> dict[str, Any]:
    """Fit the development-only MCI and deterministically selected comparator.

    Capability validation deliberately precedes all row handling and all model
    calls.  A non-feasible engine audit returns a closed result instead of
    producing partial model material.
    """

    try:
        checked_engine = validate_engine_capability_manifest(engine_capability_manifest)
        capability_audit = audit_engine_capabilities(checked_engine)
    except EngineCapabilityError:
        return _closed_result(None)
    if (
        capability_audit["decision"] != "LOCAL_FEATURE_EXTRACTION_FEASIBLE"
        or capability_audit["missing_features"]
        or not all(
            capability_audit["feature_feasibility"][feature]["feasible"]
            for feature in FEATURE_NAMES
        )
    ):
        return _closed_result(capability_audit)

    checked_rows = validate_development_rows(
        rows, engine_manifest_sha256=checked_engine.manifest_sha256
    )
    _sha256(development_evidence_sha256, "development_evidence_sha256")
    _sha256(executable_sha256, "executable_sha256")
    _canonical_timestamp(created_at_utc)

    weights = _archive_balanced_weights(checked_rows)
    standardization = _feature_standardization(checked_rows)
    lineage_cv = _comparator_cv(checked_rows, weights, group_key="lineage_id")
    ranked = sorted(
        (
            (float(summary["archive_balanced_log_loss"]), identity)
            for identity, summary in lineage_cv.items()
        ),
        key=lambda item: (item[0], item[1]),
    )
    selected_identity = ranked[0][1]
    family_cv = _descriptive_family_cv(checked_rows, weights)

    mci_fit = _fit_model(
        checked_rows,
        weights,
        standardization=standardization,
        comparator_identity=None,
    )
    comparator_fit = _fit_model(
        checked_rows,
        weights,
        standardization=standardization,
        comparator_identity=selected_identity,
    )
    mci_manifest = _mci_manifest(
        mci_fit,
        standardization,
        development_evidence_sha256,
        executable_sha256,
        created_at_utc,
    )
    comparator_manifest = _comparator_manifest(
        comparator_fit,
        standardization,
        selected_identity,
        development_evidence_sha256,
        executable_sha256,
        created_at_utc,
    )
    mci_error = _manifest_reproduction_error(mci_manifest, checked_rows, mci_fit)
    comparator_error = _manifest_reproduction_error(
        comparator_manifest, checked_rows, comparator_fit
    )
    if max(mci_error, comparator_error) > REPRODUCTION_TOLERANCE:
        raise DevelopmentFitError("manifest representation does not reproduce fitted probabilities")

    core: dict[str, Any] = {
        "schema": DEVELOPMENT_FIT_RESULT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "decision": "DEVELOPMENT_ONLY",
        "fit_performed": True,
        "engine_capability_audit": capability_audit,
        "fit_config": dict(FIT_CONFIG),
        "runtime_versions": dict(RUNTIME_VERSIONS),
        "counts": {
            "rows": len(checked_rows),
            "archives": len({row["archive_id"] for row in checked_rows}),
            "lineages": len({row["lineage_id"] for row in checked_rows}),
            "families": len({row["family_id"] for row in checked_rows}),
        },
        "selected_comparator_identity": selected_identity,
        "cv_report": {
            "selection_basis": "leave_one_lineage_out_archive_balanced_log_loss",
            "lineage_out": lineage_cv,
            "family_out": family_cv,
            "family_out_role": "DESCRIPTIVE_ONLY_NOT_A_SELECTOR",
        },
        "mci_manifest": mci_manifest.as_dict(),
        "comparator_manifest": comparator_manifest.as_dict(),
        "canonical_hashes": {
            "engine_manifest_sha256": checked_engine.manifest_sha256,
            "mci_manifest_sha256": mci_manifest.manifest_sha256,
            "comparator_manifest_sha256": comparator_manifest.manifest_sha256,
            "development_rows_sha256": canonical_sha256(checked_rows),
        },
        "reproduction": {
            "tolerance": REPRODUCTION_TOLERANCE,
            "mci_max_absolute_error": mci_error,
            "comparator_max_absolute_error": comparator_error,
        },
    }
    result = dict(core)
    result["result_sha256"] = canonical_sha256(core)
    return result


def validate_development_rows(
    rows: Iterable[Mapping[str, Any]], *, engine_manifest_sha256: str
) -> list[dict[str, Any]]:
    """Validate and canonically order exact outcome-bearing burned rows."""

    _sha256(engine_manifest_sha256, "engine_manifest_sha256")
    if isinstance(rows, (str, bytes)):
        raise DevelopmentFitError("rows must be an iterable of mappings")
    try:
        source = list(rows)
    except TypeError as exc:
        raise DevelopmentFitError("rows must be an iterable of mappings") from exc
    if not source:
        raise DevelopmentFitError("rows must not be empty")

    checked: list[dict[str, Any]] = []
    game_ids: set[str] = set()
    archive_bindings: dict[str, tuple[str, str]] = {}
    for index, row in enumerate(source):
        if not isinstance(row, Mapping) or set(row) != _ROW_FIELDS:
            actual = sorted(row) if isinstance(row, Mapping) else type(row).__name__
            raise DevelopmentFitError(
                f"row {index} fields must exactly be {sorted(_ROW_FIELDS)}; got {actual}"
            )
        if row["schema"] != DEVELOPMENT_ROW_SCHEMA or row["protocol_id"] != PROTOCOL_ID:
            raise DevelopmentFitError(f"row {index} has the wrong development schema or protocol")
        if row["partition"] != DEV_BURNED:
            raise DevelopmentFitError(f"row {index} must be in {DEV_BURNED}")
        if row["engine_manifest_sha256"] != engine_manifest_sha256:
            raise DevelopmentFitError(f"row {index} engine_manifest_sha256 does not bind the audit")
        archive_id = _text(row["archive_id"], f"row {index} archive_id")
        lineage_id = _text(row["lineage_id"], f"row {index} lineage_id")
        family_id = _text(row["family_id"], f"row {index} family_id")
        game_id = _text(row["game_id"], f"row {index} game_id")
        if game_id in game_ids:
            raise DevelopmentFitError(f"duplicate game_id {game_id!r}")
        game_ids.add(game_id)
        prior = archive_bindings.setdefault(archive_id, (lineage_id, family_id))
        if prior != (lineage_id, family_id):
            raise DevelopmentFitError("each archive_id must bind one lineage_id and family_id")
        features = _features(row["features"], index)
        comparator_inputs = _comparator_inputs(row["comparator_inputs"], index)
        era = _text(row["era"], f"row {index} era")
        seat = row["seat"]
        if type(seat) is not int or seat not in (0, 1):
            raise DevelopmentFitError(f"row {index} seat must be exactly 0 or 1")
        rating = _finite(row["opponent_rating"], f"row {index} opponent_rating")
        if rating < 0.0:
            raise DevelopmentFitError(f"row {index} opponent_rating must be non-negative")
        outcome = _finite(row["outcome"], f"row {index} outcome")
        if outcome not in (0.0, 1.0):
            raise DevelopmentFitError(f"row {index} outcome must be exactly 0 or 1")
        checked.append(
            {
                "schema": DEVELOPMENT_ROW_SCHEMA,
                "protocol_id": PROTOCOL_ID,
                "partition": DEV_BURNED,
                "engine_manifest_sha256": engine_manifest_sha256,
                "archive_id": archive_id,
                "lineage_id": lineage_id,
                "family_id": family_id,
                "game_id": game_id,
                "features": features,
                "comparator_inputs": comparator_inputs,
                "era": era,
                "seat": seat,
                "opponent_rating": rating,
                "outcome": outcome,
            }
        )
    if len({row["lineage_id"] for row in checked}) < 2:
        raise DevelopmentFitError("at least two lineages are required")
    if {row["outcome"] for row in checked} != {0.0, 1.0}:
        raise DevelopmentFitError("at least two outcome classes are required")
    for identity in COMPARATOR_IDENTITIES:
        key = COMPARATOR_INPUT_KEYS[identity]
        if key is not None and not any(row["comparator_inputs"][key] is not None for row in checked):
            raise DevelopmentFitError(f"comparator {identity!r} has no non-null development value")
    return sorted(checked, key=lambda row: row["game_id"])


def write_manifest_once(path: str | Path, manifest: PredictionManifest | Mapping[str, Any]) -> str:
    """Create one canonical manifest file, refusing overwrite without reading it."""

    checked = build_prediction_manifest(manifest.as_dict() if isinstance(manifest, PredictionManifest) else manifest)
    destination = Path(path)
    payload = canonical_json_bytes(checked.as_dict())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(f"manifest destination already exists: {destination}") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_parent(destination)
    return checked.manifest_sha256


def _closed_result(capability_audit: Mapping[str, Any] | None) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": DEVELOPMENT_FIT_RESULT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "decision": "FAIL_CLOSED",
        "reason": "NO_LOCAL_FEATURE_EXTRACTION",
        "fit_performed": False,
        "engine_capability_audit": dict(capability_audit) if capability_audit is not None else None,
        "runtime_versions": dict(RUNTIME_VERSIONS),
    }
    result = dict(core)
    result["result_sha256"] = canonical_sha256(core)
    return result


def _comparator_cv(
    rows: list[dict[str, Any]], weights: np.ndarray, *, group_key: str
) -> dict[str, dict[str, Any]]:
    report: dict[str, dict[str, Any]] = {}
    for identity in COMPARATOR_IDENTITIES:
        try:
            probabilities = _group_out_predictions(rows, weights, group_key, identity)
            report[identity] = {
                "archive_balanced_log_loss": _archive_balanced_log_loss(rows, probabilities),
                "folds": len({row[group_key] for row in rows}),
            }
        except DevelopmentFitConvergenceError:
            raise
        except DevelopmentFitError as exc:
            raise DevelopmentFitError(f"{group_key} CV failed for {identity!r}: {exc}") from exc
    return report


def _descriptive_family_cv(rows: list[dict[str, Any]], weights: np.ndarray) -> dict[str, Any]:
    try:
        return {
            "available": True,
            "scores": _comparator_cv(rows, weights, group_key="family_id"),
        }
    except DevelopmentFitConvergenceError:
        raise
    except DevelopmentFitError as exc:
        return {"available": False, "reason": str(exc)}


def _group_out_predictions(
    rows: list[dict[str, Any]], weights: np.ndarray, group_key: str, identity: str
) -> np.ndarray:
    predictions = np.empty(len(rows), dtype=float)
    for group in sorted({str(row[group_key]) for row in rows}):
        test_indexes = np.array([index for index, row in enumerate(rows) if row[group_key] == group])
        train_indexes = np.array([index for index, row in enumerate(rows) if row[group_key] != group])
        if len(train_indexes) == 0 or set(float(rows[index]["outcome"]) for index in train_indexes) != {0.0, 1.0}:
            raise DevelopmentFitError(f"fold {group!r} does not retain both outcome classes")
        train_rows = [rows[index] for index in train_indexes]
        fit = _fit_model(
            train_rows,
            _archive_balanced_weights(train_rows),
            standardization=_feature_standardization(train_rows),
            comparator_identity=identity,
        )
        predictions[test_indexes] = _predict_estimator(fit, [rows[index] for index in test_indexes])
    return predictions


def _fit_model(
    rows: list[dict[str, Any]],
    weights: np.ndarray,
    *,
    standardization: dict[str, dict[str, float]],
    comparator_identity: str | None,
) -> dict[str, Any]:
    if len(rows) != len(weights):
        raise DevelopmentFitError("row and sample-weight counts differ")
    if set(row["outcome"] for row in rows) != {0.0, 1.0}:
        raise DevelopmentFitError("model fit requires both outcome classes")
    eras = tuple(sorted({str(row["era"]) for row in rows}))
    comparator = _comparator_standardization(rows, comparator_identity)
    matrix = _design_matrix(rows, standardization, eras, comparator_identity, comparator)
    outcomes = np.asarray([row["outcome"] for row in rows], dtype=float)
    estimator = LogisticRegression(
        penalty="l2", solver="lbfgs", C=1.0, max_iter=2000, random_state=0, fit_intercept=True
    )
    with warnings.catch_warnings(record=True) as caught_warnings:
        warnings.simplefilter("always", ConvergenceWarning)
        estimator.fit(matrix, outcomes, sample_weight=np.asarray(weights, dtype=float))
    if any(issubclass(item.category, ConvergenceWarning) for item in caught_warnings):
        raise DevelopmentFitConvergenceError(
            "LogisticRegression emitted ConvergenceWarning; no prediction manifest was created"
        )
    iterations = np.asarray(estimator.n_iter_, dtype=int)
    if np.any(iterations >= estimator.max_iter):
        raise DevelopmentFitConvergenceError(
            "LogisticRegression reached or exceeded max_iter; no prediction manifest was created"
        )
    return {
        "estimator": estimator,
        "eras": eras,
        "standardization": standardization,
        "comparator_identity": comparator_identity,
        "comparator": comparator,
    }


def _predict_estimator(fit: Mapping[str, Any], rows: list[dict[str, Any]]) -> np.ndarray:
    matrix = _design_matrix(
        rows,
        fit["standardization"],
        fit["eras"],
        fit["comparator_identity"],
        fit["comparator"],
    )
    estimator: LogisticRegression = fit["estimator"]
    positive_index = int(np.flatnonzero(estimator.classes_ == 1.0)[0])
    return estimator.predict_proba(matrix)[:, positive_index]


def _design_matrix(
    rows: list[dict[str, Any]],
    standardization: Mapping[str, Mapping[str, float]],
    eras: tuple[str, ...],
    comparator_identity: str | None,
    comparator: Mapping[str, float] | None,
) -> np.ndarray:
    if not eras:
        raise DevelopmentFitError("design requires at least one era")
    columns: list[list[float]] = []
    reference_era = eras[0]
    for row in rows:
        vector = (
            [
                (float(row["features"][name]) - standardization["means"][name])
                / standardization["scales"][name]
                for name in FEATURE_NAMES
            ]
            if comparator_identity is None
            else []
        )
        vector.extend(1.0 if row["era"] == era else 0.0 for era in eras if era != reference_era)
        vector.append(float(row["seat"]))
        vector.extend(_rating_basis(float(row["opponent_rating"])))
        if comparator_identity is not None and comparator_identity != "nuisance-only null model":
            assert comparator is not None
            key = COMPARATOR_INPUT_KEYS[comparator_identity]
            assert key is not None
            value = row["comparator_inputs"][key]
            centered = comparator["mean"] if value is None else float(value)
            vector.append((centered - comparator["mean"]) / comparator["scale"])
        columns.append(vector)
    return np.asarray(columns, dtype=float)


def _mci_manifest(
    fit: Mapping[str, Any], standardization: Mapping[str, Mapping[str, float]], evidence: str, executable: str, created_at: str
) -> PredictionManifest:
    estimator: LogisticRegression = fit["estimator"]
    coefficients = estimator.coef_[0]
    feature_coefficients = coefficients[: len(FEATURE_NAMES)]
    slope = float(np.linalg.norm(feature_coefficients))
    if slope == 0.0:
        feature_weights = {name: 0.0 for name in FEATURE_NAMES}
    else:
        feature_weights = {
            name: float(feature_coefficients[index] / slope)
            for index, name in enumerate(FEATURE_NAMES)
        }
    nuisance = _nuisance_fields(coefficients, fit["eras"], feature_column_count=len(FEATURE_NAMES))
    return build_prediction_manifest(
        schema=MODEL_SCHEMA,
        protocol_id=PROTOCOL_ID,
        feature_names=FEATURE_NAMES,
        standardization_means=standardization["means"],
        standardization_scales=standardization["scales"],
        feature_weights=feature_weights,
        intercept=float(estimator.intercept_[0]),
        mci_slope=slope,
        **nuisance,
        probability_epsilon=PROBABILITY_EPSILON,
        model_kind="MCI",
        comparator_identity=None,
        comparator_input_key=None,
        comparator_input_mean=None,
        comparator_input_scale=None,
        comparator_slope=None,
        comparator_null_value=None,
        comparator_missing_behavior="NOT_APPLICABLE",
        development_evidence_sha256=evidence,
        executable_sha256=executable,
        created_at_utc=created_at,
    )


def _comparator_manifest(
    fit: Mapping[str, Any], standardization: Mapping[str, Mapping[str, float]], identity: str, evidence: str, executable: str, created_at: str
) -> PredictionManifest:
    estimator: LogisticRegression = fit["estimator"]
    coefficients = estimator.coef_[0]
    nuisance = _nuisance_fields(coefficients, fit["eras"], feature_column_count=0)
    scalar_position = (len(fit["eras"]) - 1) + 1 + len(RATING_KNOTS)
    scalar = fit["comparator"]
    if identity == "nuisance-only null model":
        scalar_fields: dict[str, Any] = {
            "comparator_input_key": None,
            "comparator_input_mean": None,
            "comparator_input_scale": None,
            "comparator_slope": None,
            "comparator_null_value": None,
            "comparator_missing_behavior": "NUISANCE_ONLY",
        }
    else:
        assert scalar is not None
        scalar_fields = {
            "comparator_input_key": COMPARATOR_INPUT_KEYS[identity],
            "comparator_input_mean": scalar["mean"],
            "comparator_input_scale": scalar["scale"],
            "comparator_slope": float(coefficients[scalar_position]),
            "comparator_null_value": scalar["mean"],
            "comparator_missing_behavior": "USE_FROZEN_NULL_VALUE",
        }
    return build_prediction_manifest(
        schema=MODEL_SCHEMA,
        protocol_id=PROTOCOL_ID,
        feature_names=FEATURE_NAMES,
        standardization_means=standardization["means"],
        standardization_scales=standardization["scales"],
        feature_weights={name: 0.0 for name in FEATURE_NAMES},
        intercept=float(estimator.intercept_[0]),
        mci_slope=0.0,
        **nuisance,
        probability_epsilon=PROBABILITY_EPSILON,
        model_kind="FROZEN_COMPARATOR",
        comparator_identity=identity,
        **scalar_fields,
        development_evidence_sha256=evidence,
        executable_sha256=executable,
        created_at_utc=created_at,
    )


def _nuisance_fields(
    coefficients: np.ndarray, eras: tuple[str, ...], *, feature_column_count: int
) -> dict[str, Any]:
    offset = feature_column_count
    era_effects = {eras[0]: 0.0}
    for era in eras[1:]:
        era_effects[era] = float(coefficients[offset])
        offset += 1
    seat_effect = float(coefficients[offset])
    offset += 1
    rating_values = tuple(float(value) for value in coefficients[offset : offset + len(RATING_KNOTS)])
    return {
        "era_effects": era_effects,
        "seat_effects": {"0": 0.0, "1": seat_effect},
        "opponent_rating_knots": RATING_KNOTS,
        "opponent_rating_values": rating_values,
        "rating_interpolation": RATING_INTERPOLATION,
    }


def _manifest_reproduction_error(manifest: PredictionManifest, rows: list[dict[str, Any]], fit: Mapping[str, Any]) -> float:
    expected = _predict_estimator(fit, rows)
    actual = np.asarray(
        [
            manifest.predict_probability(
                row["features"] if manifest.model_kind == "MCI" else None,
                era=row["era"],
                seat=row["seat"],
                opponent_rating=row["opponent_rating"],
                comparator_input=(
                    None
                    if manifest.model_kind == "MCI" or manifest.comparator_identity == "nuisance-only null model"
                    else row["comparator_inputs"][manifest.comparator_input_key]  # type: ignore[index]
                ),
            )
            for row in rows
        ],
        dtype=float,
    )
    return float(np.max(np.abs(expected - actual)))


def _feature_standardization(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    means: dict[str, float] = {}
    scales: dict[str, float] = {}
    for name in FEATURE_NAMES:
        values = np.asarray([row["features"][name] for row in rows], dtype=float)
        means[name] = float(np.mean(values))
        deviation = float(np.sqrt(np.mean((values - means[name]) ** 2)))
        scales[name] = 1.0 if deviation == 0.0 else deviation
    return {"means": means, "scales": scales}


def _comparator_standardization(rows: list[dict[str, Any]], identity: str | None) -> dict[str, float] | None:
    if identity is None or identity == "nuisance-only null model":
        return None
    key = COMPARATOR_INPUT_KEYS[identity]
    assert key is not None
    observed = [row["comparator_inputs"][key] for row in rows if row["comparator_inputs"][key] is not None]
    if not observed:
        raise DevelopmentFitError(f"comparator {identity!r} has no training values")
    values = np.asarray(observed, dtype=float)
    mean = float(np.mean(values))
    deviation = float(np.sqrt(np.mean((values - mean) ** 2)))
    return {"mean": mean, "scale": 1.0 if deviation == 0.0 else deviation}


def _archive_balanced_weights(rows: list[dict[str, Any]]) -> np.ndarray:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["archive_id"]] = counts.get(row["archive_id"], 0) + 1
    archive_count = len(counts)
    return np.asarray(
        [len(rows) / (archive_count * counts[row["archive_id"]]) for row in rows], dtype=float
    )


def _archive_balanced_log_loss(rows: list[dict[str, Any]], probabilities: np.ndarray) -> float:
    by_archive: dict[str, list[float]] = {}
    for row, probability in zip(rows, probabilities, strict=True):
        if not 0.0 < probability < 1.0:
            raise DevelopmentFitError("fitted probability is not strictly between zero and one")
        outcome = float(row["outcome"])
        loss = -(outcome * math.log(float(probability)) + (1.0 - outcome) * math.log1p(-float(probability)))
        by_archive.setdefault(str(row["archive_id"]), []).append(loss)
    return float(np.mean([np.mean(by_archive[archive]) for archive in sorted(by_archive)]))


def _rating_basis(rating: float) -> list[float]:
    basis = [0.0] * len(RATING_KNOTS)
    if rating <= RATING_KNOTS[0]:
        basis[0] = 1.0
        return basis
    if rating >= RATING_KNOTS[-1]:
        basis[-1] = 1.0
        return basis
    index = next(position - 1 for position, knot in enumerate(RATING_KNOTS) if rating < knot)
    left, right = RATING_KNOTS[index], RATING_KNOTS[index + 1]
    fraction = (rating - left) / (right - left)
    basis[index] = 1.0 - fraction
    basis[index + 1] = fraction
    return basis


def _features(value: object, index: int) -> dict[str, float]:
    if not isinstance(value, Mapping) or set(value) != set(FEATURE_NAMES):
        raise DevelopmentFitError(f"row {index} features must contain exactly the six charter features")
    result: dict[str, float] = {}
    for name in FEATURE_NAMES:
        number = _finite(value[name], f"row {index} features.{name}")
        if not 0.0 <= number <= 1.0:
            raise DevelopmentFitError(f"row {index} features.{name} must be in [0, 1]")
        result[name] = number
    return result


def _comparator_inputs(value: object, index: int) -> dict[str, float | None]:
    if not isinstance(value, Mapping) or set(value) != set(_COMPARATOR_KEYS):
        raise DevelopmentFitError(f"row {index} comparator_inputs must contain exactly six frozen comparator keys")
    return {
        key: None if value[key] is None else _finite(value[key], f"row {index} comparator_inputs.{key}")
        for key in _COMPARATOR_KEYS
    }


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise DevelopmentFitError(f"{label} must be a non-empty trimmed string")
    return value


def _finite(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise DevelopmentFitError(f"{label} must be finite")
    return float(value)


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DevelopmentFitError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_timestamp(value: object) -> None:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value):
        raise DevelopmentFitError("created_at_utc must be canonical UTC with six fractional digits")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise DevelopmentFitError("created_at_utc must be a valid calendar datetime") from exc


def _fsync_parent(destination: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(destination.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


fit_development = fit_development_models
run_development_fit = fit_development_models


__all__ = [
    "DEVELOPMENT_FIT_RESULT_SCHEMA",
    "DEVELOPMENT_ROW_SCHEMA",
    "DevelopmentFitConvergenceError",
    "DevelopmentFitError",
    "FIT_CONFIG",
    "PROBABILITY_EPSILON",
    "RATING_INTERPOLATION",
    "RATING_KNOTS",
    "REPRODUCTION_TOLERANCE",
    "RUNTIME_VERSIONS",
    "fit_development",
    "fit_development_models",
    "run_development_fit",
    "validate_development_rows",
    "write_manifest_once",
]
