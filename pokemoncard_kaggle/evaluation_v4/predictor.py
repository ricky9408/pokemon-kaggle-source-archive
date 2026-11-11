"""Strict, deterministic frozen predictor artifact for selector v4.

This module intentionally contains no training or calibration logic.  A model is
an immutable, hash-bound set of coefficients, and every prediction is
recomputed from a hash-bound simulation feature artifact.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from numbers import Real
from typing import Any, Mapping


PREDICTOR_MODEL_SCHEMA = "whole_policy_predictor_model_v1"
SIMULATION_FEATURE_SCHEMA = "whole_policy_simulation_feature_v1"
PREDICTION_RECEIPT_SCHEMA = "whole_policy_prediction_recomputation_receipt_v1"
SIMULATION_DESIGN_SCHEMA = "whole_policy_simulation_design_v1"
STATE_FROZEN = "FROZEN"
MODEL_SCHEMA = PREDICTOR_MODEL_SCHEMA
FEATURE_SCHEMA = SIMULATION_FEATURE_SCHEMA
RECEIPT_SCHEMA = PREDICTION_RECEIPT_SCHEMA

FEATURE_NAMES = (
    "intercept",
    "simulator_delta",
    "candidate_visited_ood_mass",
    "minimum_engine_variant_mean",
    "minimum_opponent_family_mean",
    "minimum_rating_layer_mean",
)
_FEATURE_NAME_SET = frozenset(FEATURE_NAMES)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_MODEL_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "lineage_manifest_sha256",
        "training_manifest_sha256",
        "training_code_sha256",
        "simulation_design_schema",
        "feature_schema",
        "training_ancestry_ids",
        "probability_clip",
        "nuisance_logit_intercept",
        "selector_coefficients",
        "state",
    }
)
_MODEL_FIELDS = _MODEL_CONTENT_FIELDS | {"content_sha256"}
_FEATURE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "feature_schema",
        "candidate_archive_sha256",
        "design_manifest_sha256",
        "ancestry_id",
        "features",
    }
)
_FEATURE_FIELDS = _FEATURE_CONTENT_FIELDS | {"content_sha256"}
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "predictor_model_sha256",
        "simulation_feature_content_sha256",
        "p0",
        "p1",
        "raw_logit_adjustment",
    }
)


class PredictorError(ValueError):
    """A predictor model, feature artifact, or recomputation is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the single canonical JSON encoding used for all content hashes."""
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PredictorError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PredictorError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise PredictorError(f"{label} must be a lowercase SHA-256")
    return value


def _finite(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise PredictorError(f"{label} must be finite")
    return float(value)


def _sorted_unique_identifiers(value: object, *, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise PredictorError(f"{label} must be a non-empty list")
    result = [_identifier(item, label=f"{label} item") for item in value]
    if result != sorted(set(result)):
        raise PredictorError(f"{label} must be sorted and unique")
    return result


def _model_content(model: object) -> Mapping[str, Any]:
    return _exact_fields(model, _MODEL_CONTENT_FIELDS, label="predictor model")


def _normalize_model_content(model: object) -> dict[str, Any]:
    value = _model_content(model)
    if value["schema"] != PREDICTOR_MODEL_SCHEMA:
        raise PredictorError(f"model schema must be {PREDICTOR_MODEL_SCHEMA!r}")
    if value["simulation_design_schema"] != SIMULATION_DESIGN_SCHEMA:
        raise PredictorError(f"simulation_design_schema must be {SIMULATION_DESIGN_SCHEMA!r}")
    if value["feature_schema"] != SIMULATION_FEATURE_SCHEMA:
        raise PredictorError(f"feature_schema must be {SIMULATION_FEATURE_SCHEMA!r}")
    if value["state"] != STATE_FROZEN:
        raise PredictorError("predictor model state must be FROZEN")

    raw_coefficients = _exact_fields(
        value["selector_coefficients"], _FEATURE_NAME_SET, label="selector_coefficients"
    )
    coefficients = {
        name: _finite(raw_coefficients[name], label=f"selector_coefficients.{name}")
        for name in FEATURE_NAMES
    }
    clip = _finite(value["probability_clip"], label="probability_clip")
    if not 0.0 < clip < 0.5:
        raise PredictorError("probability_clip must be strictly between 0 and 0.5")

    return {
        "schema": PREDICTOR_MODEL_SCHEMA,
        "protocol_sha256": _sha256(value["protocol_sha256"], label="protocol_sha256"),
        "lineage_manifest_sha256": _sha256(
            value["lineage_manifest_sha256"], label="lineage_manifest_sha256"
        ),
        "training_manifest_sha256": _sha256(
            value["training_manifest_sha256"], label="training_manifest_sha256"
        ),
        "training_code_sha256": _sha256(value["training_code_sha256"], label="training_code_sha256"),
        "simulation_design_schema": SIMULATION_DESIGN_SCHEMA,
        "feature_schema": SIMULATION_FEATURE_SCHEMA,
        "training_ancestry_ids": _sorted_unique_identifiers(
            value["training_ancestry_ids"], label="training_ancestry_ids"
        ),
        "probability_clip": clip,
        "nuisance_logit_intercept": _finite(
            value["nuisance_logit_intercept"], label="nuisance_logit_intercept"
        ),
        "selector_coefficients": coefficients,
        "state": STATE_FROZEN,
    }


def build_predictor_model(model: Mapping[str, Any]) -> dict[str, Any]:
    """Build a frozen model and compute its canonical content SHA-256."""
    if not isinstance(model, Mapping):
        raise PredictorError("predictor model must be a mapping")
    if "content_sha256" in model:
        raise PredictorError("build_predictor_model accepts hash-free model content")
    content = _normalize_model_content(model)
    result = {**content, "content_sha256": canonical_sha256(content)}
    validate_predictor_model(result)
    return result


def validate_predictor_model(model: object) -> dict[str, Any]:
    """Validate a complete frozen model and recompute its content hash."""
    value = _exact_fields(model, _MODEL_FIELDS, label="predictor model")
    content = _normalize_model_content({field: value[field] for field in _MODEL_CONTENT_FIELDS})
    content_sha256 = _sha256(value["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise PredictorError("predictor model content_sha256 mismatch")
    return {**content, "content_sha256": content_sha256}


def _normalize_simulation_feature_content(feature: object) -> dict[str, Any]:
    value = _exact_fields(feature, _FEATURE_CONTENT_FIELDS, label="simulation feature content")
    if value["schema"] != SIMULATION_FEATURE_SCHEMA:
        raise PredictorError(f"simulation feature schema must be {SIMULATION_FEATURE_SCHEMA!r}")
    if value["feature_schema"] != SIMULATION_FEATURE_SCHEMA:
        raise PredictorError(f"simulation feature feature_schema must be {SIMULATION_FEATURE_SCHEMA!r}")
    raw_features = _exact_fields(value["features"], _FEATURE_NAME_SET, label="simulation feature features")
    features = {
        name: _finite(raw_features[name], label=f"features.{name}") for name in FEATURE_NAMES
    }
    if features["intercept"] != 1.0:
        raise PredictorError("features.intercept must equal 1.0")
    if not 0.0 <= features["candidate_visited_ood_mass"] <= 1.0:
        raise PredictorError("features.candidate_visited_ood_mass must be in [0, 1]")
    content = {
        "schema": SIMULATION_FEATURE_SCHEMA,
        "feature_schema": SIMULATION_FEATURE_SCHEMA,
        "candidate_archive_sha256": _sha256(
            value["candidate_archive_sha256"], label="candidate_archive_sha256"
        ),
        "design_manifest_sha256": _sha256(
            value["design_manifest_sha256"], label="design_manifest_sha256"
        ),
        "ancestry_id": _identifier(value["ancestry_id"], label="ancestry_id"),
        "features": features,
    }
    return content


def _normalize_simulation_feature(feature: object) -> dict[str, Any]:
    value = _exact_fields(feature, _FEATURE_FIELDS, label="simulation feature")
    content = _normalize_simulation_feature_content(
        {field: value[field] for field in _FEATURE_CONTENT_FIELDS}
    )
    content_sha256 = _sha256(value["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise PredictorError("simulation feature content_sha256 mismatch")
    return {**content, "content_sha256": content_sha256}


def build_simulation_feature(feature: Mapping[str, Any]) -> dict[str, Any]:
    """Build a hash-bound feature envelope; no probabilities are accepted."""
    if not isinstance(feature, Mapping):
        raise PredictorError("simulation feature must be a mapping")
    if "content_sha256" in feature:
        raise PredictorError("build_simulation_feature accepts hash-free feature content")
    content = _normalize_simulation_feature_content(feature)
    result = {**content, "content_sha256": canonical_sha256(content)}
    return _normalize_simulation_feature(result)


def validate_simulation_feature(feature: object) -> dict[str, Any]:
    return _normalize_simulation_feature(feature)


def _sigmoid(logit: float) -> float:
    # Branching avoids overflow while retaining deterministic math for finite inputs.
    if logit >= 0.0:
        return 1.0 / (1.0 + math.exp(-logit))
    exp_logit = math.exp(logit)
    return exp_logit / (1.0 + exp_logit)


def _clip_probability(value: float, clip: float) -> float:
    return min(1.0 - clip, max(clip, value))


def _probability(value: object, *, label: str) -> float:
    result = _finite(value, label=label)
    if not 0.0 <= result <= 1.0:
        raise PredictorError(f"{label} must be in [0, 1]")
    return result


def recompute_prediction(
    model: object,
    simulation_feature: object,
    expected_archive_sha256: str | None = None,
    *,
    expected_candidate_archive_sha256: str | None = None,
    expected_design_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Recompute p0/p1 from the frozen model and feature artifact.

    The expected candidate archive is explicit because accepting the archive
    hash supplied by the feature artifact alone would not bind the prediction
    to the archive the caller intended to evaluate.
    """
    normalized_model = validate_predictor_model(model)
    normalized_feature = validate_simulation_feature(simulation_feature)

    expected_archive = expected_candidate_archive_sha256 or expected_archive_sha256
    if expected_candidate_archive_sha256 is not None and expected_archive_sha256 is not None:
        if expected_candidate_archive_sha256 != expected_archive_sha256:
            raise PredictorError("expected archive SHA-256 arguments disagree")
    if expected_archive is None:
        raise PredictorError("expected candidate archive SHA-256 is required")
    expected_archive = _sha256(expected_archive, label="expected_candidate_archive_sha256")
    if normalized_feature["candidate_archive_sha256"] != expected_archive:
        raise PredictorError("candidate archive SHA-256 does not match expected archive")
    if expected_design_manifest_sha256 is not None:
        expected_design = _sha256(expected_design_manifest_sha256, label="expected_design_manifest_sha256")
        if normalized_feature["design_manifest_sha256"] != expected_design:
            raise PredictorError("design manifest SHA-256 does not match expected design")
    if normalized_feature["ancestry_id"] in normalized_model["training_ancestry_ids"]:
        raise PredictorError("simulation feature ancestry_id overlaps training ancestry")

    coefficients = normalized_model["selector_coefficients"]
    raw_adjustment = math.fsum(
        coefficients[name] * normalized_feature["features"][name] for name in FEATURE_NAMES
    )
    nuisance_logit = normalized_model["nuisance_logit_intercept"]
    clip = normalized_model["probability_clip"]
    p0 = _clip_probability(_sigmoid(nuisance_logit), clip)
    p1 = _clip_probability(_sigmoid(nuisance_logit + raw_adjustment), clip)
    return {
        "schema": PREDICTION_RECEIPT_SCHEMA,
        "predictor_model_sha256": normalized_model["content_sha256"],
        "simulation_feature_content_sha256": normalized_feature["content_sha256"],
        "p0": p0,
        "p1": p1,
        "raw_logit_adjustment": raw_adjustment,
    }


def validate_prediction_receipt(receipt: object) -> dict[str, Any]:
    """Validate the intentionally outcome-free recomputation receipt."""
    value = _exact_fields(receipt, _RECEIPT_FIELDS, label="prediction receipt")
    if value["schema"] != PREDICTION_RECEIPT_SCHEMA:
        raise PredictorError(f"prediction receipt schema must be {PREDICTION_RECEIPT_SCHEMA!r}")
    return {
        "schema": PREDICTION_RECEIPT_SCHEMA,
        "predictor_model_sha256": _sha256(
            value["predictor_model_sha256"], label="predictor_model_sha256"
        ),
        "simulation_feature_content_sha256": _sha256(
            value["simulation_feature_content_sha256"], label="simulation_feature_content_sha256"
        ),
        "p0": _probability(value["p0"], label="p0"),
        "p1": _probability(value["p1"], label="p1"),
        "raw_logit_adjustment": _finite(
            value["raw_logit_adjustment"], label="raw_logit_adjustment"
        ),
    }


def write_predictor_model_once(path: str | Path, model: object) -> Path:
    """Durably create one canonical frozen predictor model, never overwrite it."""
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"predictor model already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(validate_predictor_model(model)) + b"\n"
    try:
        with target.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"predictor model already exists: {target}") from None
    directory_fd = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target


def load_predictor_model(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PredictorError(f"cannot read predictor model: {exc}") from exc
    return validate_predictor_model(value)


# Short aliases make the primitive convenient without adding alternate schemas.
build_model = build_predictor_model
validate_model = validate_predictor_model
recompute = recompute_prediction


__all__ = [
    "FEATURE_SCHEMA",
    "FEATURE_NAMES",
    "MODEL_SCHEMA",
    "PREDICTION_RECEIPT_SCHEMA",
    "PREDICTOR_MODEL_SCHEMA",
    "PredictorError",
    "RECEIPT_SCHEMA",
    "SIMULATION_DESIGN_SCHEMA",
    "SIMULATION_FEATURE_SCHEMA",
    "build_model",
    "build_predictor_model",
    "build_simulation_feature",
    "canonical_json_bytes",
    "canonical_sha256",
    "load_predictor_model",
    "recompute",
    "recompute_prediction",
    "validate_model",
    "validate_prediction_receipt",
    "validate_predictor_model",
    "validate_simulation_feature",
    "write_predictor_model_once",
]
