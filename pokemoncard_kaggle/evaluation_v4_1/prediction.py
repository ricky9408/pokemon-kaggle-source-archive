"""Frozen, recomputable prediction bundle for the research-only VOI-P5 pilot.

The bundle is deliberately outcome-free.  It binds the exact protocol,
population, beacon assignment, predictor model, and one simulation feature per
selected lineage.  Cached probabilities and caller-selected pair preferences
are never accepted: both are recomputed here from the frozen artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from evaluation_v4.predictor import (
    recompute_prediction,
    validate_predictor_model,
    validate_simulation_feature,
)

from .protocol import (
    canonical_json_bytes,
    canonical_sha256,
    protocol_core_sha256,
    validate_pair_assignment,
    validate_population_manifest,
    validate_protocol,
)


BUNDLE_SCHEMA = "voi_p5_prediction_bundle_v1"
STATE_FROZEN = "FROZEN"
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "population_content_sha256",
        "pair_assignment_content_sha256",
        "predictor_model_content_sha256",
        "design_manifest_sha256",
        "records",
        "pair_preferences",
        "created_at_utc",
        "state",
        "research_only",
        "production_submission_authorized",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_RECORD_FIELDS = frozenset(
    {
        "lineage_uuid",
        "lineage_id",
        "archive_sha256",
        "ancestry_id",
        "family_id",
        "pair_id",
        "wave_id",
        "member",
        "simulation_feature",
        "prediction",
    }
)
_PREFERENCE_FIELDS = frozenset(
    {
        "pair_id",
        "family_id",
        "wave_id",
        "selected_member",
        "selected_lineage_uuid",
        "other_lineage_uuid",
        "p1_by_member",
    }
)


class PredictionBundleError(ValueError):
    """A VOI-P5 prediction bundle is malformed or cannot be recomputed."""


def predictor_context_sha256(protocol: object) -> str:
    """Hash the protocol context without creating a model/protocol hash cycle.

    The model is built against this context first.  Its resulting content hash
    is then inserted into ``selector_model_sha256`` in the final protocol.
    """

    return protocol_core_sha256(protocol)


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PredictionBundleError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise PredictionBundleError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise PredictionBundleError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PredictionBundleError(f"{label} is invalid") from exc
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical != value:
        raise PredictionBundleError(f"{label} must be canonical UTC")
    return value


def _feature_mapping(value: object, selected: set[str]) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PredictionBundleError("features_by_lineage_uuid must be a mapping")
    if set(value) != selected:
        missing = sorted(selected - set(value))
        extra = sorted(set(value) - selected)
        raise PredictionBundleError(
            f"simulation features must exactly cover selected lineages; missing={missing}, extra={extra}"
        )
    return dict(value)


def _build_content(
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    predictor_model: object,
    features_by_lineage_uuid: object,
    created_at_utc: str,
) -> dict[str, Any]:
    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    assignment = validate_pair_assignment(pair_assignment, frozen, population)
    model = validate_predictor_model(predictor_model)
    protocol_sha = canonical_sha256(frozen)
    if model["content_sha256"] != frozen["selector_model_sha256"]:
        raise PredictionBundleError("predictor model does not match protocol selector_model_sha256")
    if model["protocol_sha256"] != predictor_context_sha256(frozen):
        raise PredictionBundleError("predictor model protocol context mismatch")
    if model["probability_clip"] != frozen["clipping"]:
        raise PredictionBundleError("predictor probability clip does not match protocol clipping")

    selected = set(assignment["selected_lineage_uuids"])
    feature_map = _feature_mapping(features_by_lineage_uuid, selected)
    population_by_uuid = {record["lineage_uuid"]: record for record in population["records"]}
    records: list[dict[str, Any]] = []
    preferences: list[dict[str, Any]] = []
    design_sha = frozen["runtime_manifest_sha256"]

    for pair in assignment["pairs"]:
        by_member: dict[str, dict[str, Any]] = {}
        for member, lineage_uuid in zip(("A", "B"), pair["slot_order"]):
            population_record = population_by_uuid[lineage_uuid]
            feature = validate_simulation_feature(feature_map[lineage_uuid])
            if feature["candidate_archive_sha256"] != population_record["archive_sha256"]:
                raise PredictionBundleError("simulation feature archive does not match population")
            if feature["ancestry_id"] != population_record["ancestry_id"]:
                raise PredictionBundleError("simulation feature ancestry does not match population")
            if feature["design_manifest_sha256"] != design_sha:
                raise PredictionBundleError("simulation feature design does not match frozen runtime manifest")
            prediction = recompute_prediction(
                model,
                feature,
                expected_candidate_archive_sha256=population_record["archive_sha256"],
                expected_design_manifest_sha256=design_sha,
            )
            record = {
                "lineage_uuid": lineage_uuid,
                "lineage_id": population_record["lineage_id"],
                "archive_sha256": population_record["archive_sha256"],
                "ancestry_id": population_record["ancestry_id"],
                "family_id": pair["family_id"],
                "pair_id": pair["pair_id"],
                "wave_id": pair["wave_id"],
                "member": member,
                "simulation_feature": feature,
                "prediction": prediction,
            }
            records.append(record)
            by_member[member] = record

        p1_a = by_member["A"]["prediction"]["p1"]
        p1_b = by_member["B"]["prediction"]["p1"]
        if p1_a == p1_b:
            raise PredictionBundleError(f"pair {pair['pair_id']} has a selector p1 tie")
        selected_member = "A" if p1_a > p1_b else "B"
        other_member = "B" if selected_member == "A" else "A"
        preferences.append(
            {
                "pair_id": pair["pair_id"],
                "family_id": pair["family_id"],
                "wave_id": pair["wave_id"],
                "selected_member": selected_member,
                "selected_lineage_uuid": by_member[selected_member]["lineage_uuid"],
                "other_lineage_uuid": by_member[other_member]["lineage_uuid"],
                "p1_by_member": {"A": p1_a, "B": p1_b},
            }
        )

    return {
        "schema": BUNDLE_SCHEMA,
        "protocol_sha256": protocol_sha,
        "population_content_sha256": population["content_sha256"],
        "pair_assignment_content_sha256": assignment["content_sha256"],
        "predictor_model_content_sha256": model["content_sha256"],
        "design_manifest_sha256": design_sha,
        "records": sorted(records, key=lambda row: row["lineage_uuid"]),
        "pair_preferences": sorted(preferences, key=lambda row: row["pair_id"]),
        "created_at_utc": _utc(created_at_utc, label="created_at_utc"),
        "state": STATE_FROZEN,
        "research_only": True,
        "production_submission_authorized": False,
    }


def build_prediction_bundle(
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    predictor_model: object,
    features_by_lineage_uuid: object,
    created_at_utc: str,
) -> dict[str, Any]:
    """Build a frozen outcome-free bundle from recomputed predictions."""

    content = _build_content(
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        predictor_model=predictor_model,
        features_by_lineage_uuid=features_by_lineage_uuid,
        created_at_utc=created_at_utc,
    )
    result = {**content, "content_sha256": canonical_sha256(content)}
    return validate_prediction_bundle(
        result,
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        predictor_model=predictor_model,
    )


def validate_prediction_bundle(
    value: object,
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    predictor_model: object,
) -> dict[str, Any]:
    """Recompute every receipt and preference before accepting a bundle."""

    raw = _exact_fields(value, _FIELDS, label="prediction bundle")
    if raw["schema"] != BUNDLE_SCHEMA:
        raise PredictionBundleError(f"prediction bundle schema must be {BUNDLE_SCHEMA!r}")
    records = raw["records"]
    preferences = raw["pair_preferences"]
    if not isinstance(records, list) or len(records) != 10:
        raise PredictionBundleError("prediction bundle must contain exactly ten records")
    if not isinstance(preferences, list) or len(preferences) != 5:
        raise PredictionBundleError("prediction bundle must contain exactly five pair preferences")
    for record in records:
        _exact_fields(record, _RECORD_FIELDS, label="prediction record")
    for preference in preferences:
        _exact_fields(preference, _PREFERENCE_FIELDS, label="pair preference")
    features = {record["lineage_uuid"]: record["simulation_feature"] for record in records}
    if len(features) != 10:
        raise PredictionBundleError("prediction record lineage_uuid values must be unique")
    expected = _build_content(
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        predictor_model=predictor_model,
        features_by_lineage_uuid=features,
        created_at_utc=raw["created_at_utc"],
    )
    if {field: raw[field] for field in _CONTENT_FIELDS} != expected:
        raise PredictionBundleError("prediction bundle is not the exact recomputed bundle")
    content_sha = _sha(raw["content_sha256"], label="content_sha256")
    if content_sha != canonical_sha256(expected):
        raise PredictionBundleError("prediction bundle content_sha256 mismatch")
    return {**expected, "content_sha256": content_sha}


def write_prediction_bundle_once(
    path: str | Path,
    bundle: object,
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    predictor_model: object,
) -> Path:
    """Durably write one recomputed prediction bundle and refuse overwrite."""

    validated = validate_prediction_bundle(
        bundle,
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        predictor_model=predictor_model,
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(validated) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"prediction bundle already exists: {target}") from None
    return target


__all__ = [
    "BUNDLE_SCHEMA",
    "PredictionBundleError",
    "build_prediction_bundle",
    "predictor_context_sha256",
    "validate_prediction_bundle",
    "write_prediction_bundle_once",
]
