"""Standalone, authority-free v5.1 DEV fit evidence verifier.

The verifier owns the v5.1 data boundary and fitter.  It deliberately has no
dependency on retired modules, external numerical backends, or any
authority-producing module.  Three signed v5.1 envelopes bind an ordered
DEV_BURNED source, a frozen fit specification, and a byte-reproducible result.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Context, Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from typing import Any

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope
from . import hosted_dev_custody
from .scenario_evidence import (
    SOURCE_TRACE_RECEIPT_SCHEMA,
    ScenarioEvidenceError,
    derive_source_trace_receipt,
)


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
AUTHORITY = False
DEV_BURNED = "DEV_BURNED"
DEV_DATASET_MANIFEST_SCHEMA = "evaluation_v5_1_dev_dataset_manifest_v1"
DEV_FIT_SPEC_SCHEMA = "evaluation_v5_1_dev_fit_spec_v1"
DEV_FIT_RESULT_SCHEMA = "evaluation_v5_1_dev_fit_result_v1"
DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA = "evaluation_v5_1_development_evidence_audit_v1"
ENGINE_CAPABILITY_SCHEMA = "evaluation_v5_1_engine_capability_manifest_v1"
DEV_ROW_SCHEMA = "evaluation_v5_1_dev_burned_row_v1"
RAW_COMPARATOR_SCHEMA = "evaluation_v5_1_retired_comparator_raw_v1"
MODEL_MANIFEST_SCHEMA = "evaluation_v5_1_dev_model_manifest_v1"
SCENARIO_RECEIPT_SCHEMA = SOURCE_TRACE_RECEIPT_SCHEMA

FEATURE_REGISTRY = ("A2", "P4", "E2", "K1", "S1", "R4")
MODEL_FEATURES = ("A2", "P4", "E2", "K1", "S1")
SAFETY_FEATURES = ("R4",)
MCI_MODEL_ID = "MCI_V2"
COMPARATOR_IDENTITIES = (
    "B_NULL_V2",
    "B_RAW_LOCAL_WIN_RATE_V2",
    "B_LT_MEAN_V2",
    "B_LOCAL_CVAR_V2",
    "B_ACTION_IMITATION_V2",
    "B_SEARCH_RANK_V2",
    "B_ACCEPTED_EXPLORATION_V2",
)

# These are protocol constants, not caller supplied hashes.  The raw source
# receipt for every retired comparator must name the matching extractor.
_EXTRACTOR_HASHES = {name: hashlib.sha256(f"v5.1-extractor:{name}:raw-v2".encode()).hexdigest() for name in COMPARATOR_IDENTITIES}
_D = Decimal
_DECIMAL_CONTEXT = Context(prec=50, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999)
_Q12 = _D("0.000000000001")
_P_MIN = _D("0.020000000000")
_P_MAX = _D("0.980000000000")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")

_DATASET_FIELDS = frozenset({
    "schema", "protocol_id", "source_files", "comparator_source_files",
    "provenance_files", "scenario_receipt_files",
    "row_count", "archive_count", "lineage_count", "partitions", "provenance",
    "feature_registry", "time_derivation", "scenario_receipt_root_sha256", "engine_manifest_sha256",
    "scenario_sha256", "runtime_sha256", "container_sha256", "executable_sha256",
    "rows_sha256", "g05_result_sha256", "g05_row_merkle_root_sha256",
    "g05_trace_binding_root_sha256",
})
_SOURCE_FIELDS = frozenset({"path", "sha256", "row_count"})
_COMPARATOR_SOURCE_FIELDS = frozenset({"model_id", "path", "sha256", "row_count", "extractor_sha256"})
_PROVENANCE_FILE_FIELDS = frozenset({"category", "path", "sha256", "byte_count"})
_SCENARIO_RECEIPT_FILE_FIELDS = frozenset({"game_id", "path", "sha256"})
_PROVENANCE_FIELDS = frozenset({"source_kind", "root_sha256"})
_TIME_FIELDS = frozenset({"anchor_utc", "game_day_origin", "era_calendar"})
_ERA_FIELDS = frozenset({"era", "starts_at_utc", "ends_at_utc"})
_ROW_FIELDS = frozenset({
    "schema", "protocol_id", "partition", "competition_id", "game_id", "canary_archive_id",
    "canary_lineage_id", "scenario_receipt_sha256", "features", "canary_seat",
    "server_started_at_ns", "game_day", "era", "opponent_score_decimal",
    "model_target_decimal",
})
_RAW_RECORD_FIELDS = frozenset({"schema", "protocol_id", "model_id", "game_id", "raw_score"})
_ENGINE_FIELDS = frozenset({
    "schema", "protocol_id", "decision", "local_feature_extraction", "feature_registry",
    "engine_sha256", "scenario_sha256", "runtime_sha256", "container_sha256", "executable_sha256",
})
_SPEC_FIELDS = frozenset({
    "schema", "protocol_id", "dataset_manifest_sha256", "engine_manifest_sha256", "scenario_sha256",
    "runtime_sha256", "container_sha256", "executable_sha256", "feature_registry", "standardization",
    "optimizer", "regularization", "seed", "lolo", "model_registry", "comparator_registry", "missing_rules",
    "tie_break", "fit_created_at_utc",
})
_MODEL_FIELDS = frozenset({
    "schema", "protocol_id", "model_id", "model_kind", "feature_registry", "design_columns",
    "standardization", "coefficients", "coefficient_quantization_decimals", "safety_feature_registry",
    "probability_quantization_decimals", "probability_clip", "dataset_manifest_sha256",
    "fit_spec_sha256", "executable_sha256",
})
_RESULT_FIELDS = frozenset({
    "schema", "protocol_id", "authority", "candidate_development_authorized",
    "sealed_holdout_access_authorized", "submission_authorized", "fit_status",
    "dataset_manifest_sha256", "fit_spec_sha256", "engine_manifest_sha256", "scenario_sha256",
    "runtime_sha256", "container_sha256", "executable_sha256", "fit_created_at_utc", "fold_hash",
    "candidate_score_table", "candidate_score_table_sha256", "selected_comparator_identity",
    "mci_manifest", "comparator_manifest", "prediction_transcript_sha256", "model_output_sha256",
    "result_core_sha256", "rebuild_receipts",
})
_REBUILD_FIELDS = frozenset({"rebuild_id", "os", "arch", "clean", "runtime_sha256", "executable_sha256", "result_core_sha256", "model_output_sha256"})
_HOSTED_CUSTODY_INPUT_FIELDS = frozenset({
    "role_keys", "frozen_spec_envelope", "spec_countersignature_envelope",
    "collector_c1_envelope", "collector_c2_envelope", "evidence_bundle_envelope",
    "trace_envelopes", "raw_blobs", "final_audit_authority_envelope",
    "final_audit_countersignature_envelope",
})
_G05_TRACE_FIELDS = frozenset({
    "schema", "protocol_id", "spec_sha256", "binding_id", "evidence_bundle_sha256",
    "competition_id", "game_id", "canary_archive_id", "opponent_archive_id",
    "canary_seat", "canary_package_sha256", "opponent_package_sha256",
    "source_engine_sha256", "source_container_sha256", "deterministic_seed_sha256",
    "trace_root_sha256", "relation", "hosted_replay_or_rng_fidelity_claim",
    "hosted_fields", "source_trace_receipt",
})

_STANDARDIZATION = {
    "training_fold_only": True,
    "method": "population_mean_rms",
    "zero_variance_scale": "1.000000000000",
    "quantization_decimals": 12,
}
_OPTIMIZER = {
    "arithmetic": "Decimal",
    "precision": 50,
    "rounding": "ROUND_HALF_EVEN",
    "method": "projected_coordinate_newton",
    "sweep_count": 24,
    "coordinate_order": "design_columns_lexical",
    "nonnegative_mci_projection": True,
    "coefficient_quantization_decimals": 12,
    "probability_quantization_decimals": 12,
    "probability_clip": ["0.020000000000", "0.980000000000"],
}
_REGULARIZATION = {"penalty": "L2", "lambda": "0.010000000000", "intercept_penalty": False}
_MISSING_RULES = {
    "feature": "REJECT",
    "opponent_score": "REJECT",
    "comparator": "RAW_SOURCE_AND_EXTRACTOR_RECEIPT_REQUIRED",
}
_TIE_BREAK = {
    "keys": ["log_loss", "model_id"],
    "directions": ["ascending", "ascending"],
    "name": "decimal_quantized_log_loss_then_lexical_model_id",
}


class DevelopmentEvidenceError(ValueError):
    """A v5.1 development artifact is malformed or cannot be reproduced."""


class _DuplicateJSONKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise DevelopmentEvidenceError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise DevelopmentEvidenceError(f"{label} fields are not exact")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise DevelopmentEvidenceError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise DevelopmentEvidenceError(f"{label} must be a non-empty trimmed string")
    return value


def _count(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise DevelopmentEvidenceError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise DevelopmentEvidenceError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise DevelopmentEvidenceError(f"{label} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise DevelopmentEvidenceError(f"{label} is not canonical UTC")
    return parsed


def _utc_ns(value: object, label: str) -> int:
    instant = _timestamp(value, label)
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + instant.microsecond * 1_000


def _epoch_ns(value: object, label: str) -> int:
    if type(value) is not int:
        raise DevelopmentEvidenceError(f"{label} must be a signed epoch-nanosecond integer")
    return value


def _decimal(value: object, label: str, *, nonnegative: bool = False) -> Decimal:
    if type(value) is not str or not value or value.strip() != value:
        raise DevelopmentEvidenceError(f"{label} must be a decimal string")
    try:
        number = _D(value)
    except InvalidOperation as exc:
        raise DevelopmentEvidenceError(f"{label} is not a Decimal") from exc
    if not number.is_finite() or (nonnegative and number < 0):
        raise DevelopmentEvidenceError(f"{label} is outside its finite domain")
    return number


def _canonical_decimal(value: object, label: str, *, nonnegative: bool = False) -> str:
    if type(value) is not str or _CANONICAL_DECIMAL_RE.fullmatch(value) is None:
        raise DevelopmentEvidenceError(f"{label} must be a canonical decimal string")
    _decimal(value, label, nonnegative=nonnegative)
    return value


def _q12(value: Decimal) -> str:
    with localcontext(_DECIMAL_CONTEXT):
        return format(value.quantize(_Q12, rounding=ROUND_HALF_EVEN), "f")


def _relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise DevelopmentEvidenceError(f"{label} must be a repo-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise DevelopmentEvidenceError(f"{label} must be a normalized repo-relative POSIX path")
    return value


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return all(getattr(a, f) == getattr(b, f) for f in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def _secure_read(root_fd: int, relative_path: str) -> tuple[bytes, str]:
    current = os.dup(root_fd)
    try:
        parts = relative_path.split("/")
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
            os.close(current)
            current = nxt
        fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise DevelopmentEvidenceError(f"{relative_path!r} is not a regular file")
            data = bytearray()
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                data.extend(block)
                digest.update(block)
            after = os.fstat(fd)
            if not _same_file(before, after):
                raise DevelopmentEvidenceError(f"{relative_path!r} changed while being read")
            return bytes(data), digest.hexdigest()
        finally:
            os.close(fd)
    except OSError as exc:
        raise DevelopmentEvidenceError(f"unable to securely read {relative_path!r}") from exc
    finally:
        os.close(current)


def _engine(value: object, *, scenario: str, runtime: str, container: str, executable: str) -> tuple[dict[str, Any], str, bool]:
    raw = _exact(value, _ENGINE_FIELDS, "v5.1 engine capability manifest")
    if raw["schema"] != ENGINE_CAPABILITY_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise DevelopmentEvidenceError("retired engine capability manifest or protocol")
    if raw["feature_registry"] != list(FEATURE_REGISTRY):
        raise DevelopmentEvidenceError("engine feature registry is not the frozen v5.1 registry")
    for name in ("engine_sha256", "scenario_sha256", "runtime_sha256", "container_sha256", "executable_sha256"):
        _sha(raw[name], f"engine.{name}")
    if raw["scenario_sha256"] != scenario or raw["runtime_sha256"] != runtime or raw["container_sha256"] != container or raw["executable_sha256"] != executable:
        raise DevelopmentEvidenceError("engine capability hash binding mismatch")
    if type(raw["local_feature_extraction"]) is not bool:
        raise DevelopmentEvidenceError("engine local_feature_extraction must be boolean")
    expected = "LOCAL_FEATURE_EXTRACTION_FEASIBLE" if raw["local_feature_extraction"] else "NO_LOCAL_FEATURE_EXTRACTION"
    if raw["decision"] != expected:
        raise DevelopmentEvidenceError("engine capability decision is inconsistent")
    normalized = dict(raw)
    return normalized, canonical_sha256(normalized), raw["local_feature_extraction"]


def _validate_time(value: object) -> dict[str, Any]:
    raw = _exact(value, _TIME_FIELDS, "time derivation")
    anchor = _timestamp(raw["anchor_utc"], "time_derivation.anchor_utc")
    if type(raw["game_day_origin"]) is not int or raw["game_day_origin"] < 0:
        raise DevelopmentEvidenceError("game_day_origin must be non-negative")
    calendar = raw["era_calendar"]
    if type(calendar) is not list or not calendar:
        raise DevelopmentEvidenceError("era_calendar must be non-empty")
    checked: list[dict[str, str]] = []
    previous = anchor
    names: set[str] = set()
    for index, item in enumerate(calendar):
        era = _exact(item, _ERA_FIELDS, f"era_calendar[{index}]")
        name = _text(era["era"], "era")
        start = _timestamp(era["starts_at_utc"], "era start")
        end = _timestamp(era["ends_at_utc"], "era end")
        if name in names or start != previous or end <= start:
            raise DevelopmentEvidenceError("era calendar must be ordered and gap-free from the anchor")
        names.add(name)
        previous = end
        checked.append({"era": name, "starts_at_utc": era["starts_at_utc"], "ends_at_utc": era["ends_at_utc"]})
    return {"anchor_utc": raw["anchor_utc"], "game_day_origin": raw["game_day_origin"], "era_calendar": checked}


def _derive_day_era(row: Mapping[str, Any], time: Mapping[str, Any]) -> tuple[int, str]:
    start_ns = _epoch_ns(row["server_started_at_ns"], "server_started_at_ns")
    anchor = _timestamp(time["anchor_utc"], "anchor_utc")
    anchor_ns = _utc_ns(time["anchor_utc"], "anchor_utc")
    if start_ns < anchor_ns:
        raise DevelopmentEvidenceError("server start precedes the frozen time anchor")
    seconds, nanos = divmod(start_ns, 1_000_000_000)
    start = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=nanos // 1_000)
    day = (start.date() - anchor.date()).days + time["game_day_origin"]
    era_name = None
    for era in time["era_calendar"]:
        if _utc_ns(era["starts_at_utc"], "era start") <= start_ns < _utc_ns(era["ends_at_utc"], "era end"):
            era_name = era["era"]
            break
    if era_name is None:
        raise DevelopmentEvidenceError("server start is outside the frozen era calendar")
    return day, era_name


def _validate_row(value: object, time: Mapping[str, Any]) -> dict[str, Any]:
    raw = _exact(value, _ROW_FIELDS, "DEV_BURNED row")
    if raw["schema"] != DEV_ROW_SCHEMA or raw["protocol_id"] != PROTOCOL_ID or raw["partition"] != DEV_BURNED:
        raise DevelopmentEvidenceError("row is not a v5.1 DEV_BURNED row")
    for field in ("competition_id", "game_id", "canary_archive_id", "canary_lineage_id"):
        _text(raw[field], f"row.{field}")
    _sha(raw["scenario_receipt_sha256"], "row.scenario_receipt_sha256")
    features = raw["features"]
    if type(features) is not dict or set(features) != set(FEATURE_REGISTRY):
        raise DevelopmentEvidenceError("row features must be exactly A2/P4/E2/K1/S1/R4")
    checked_features: dict[str, str] = {}
    for name in FEATURE_REGISTRY:
        number = _decimal(features[name], f"row.features.{name}")
        if not _D("0") <= number <= _D("1"):
            raise DevelopmentEvidenceError(f"row.features.{name} must be in [0,1]")
        checked_features[name] = _q12(number)
    if checked_features["R4"] != _q12(_D(1)):
        raise DevelopmentEvidenceError("R4 safety feature must be exactly 1.000000000000")
    if type(raw["canary_seat"]) is not int or raw["canary_seat"] not in (0, 1):
        raise DevelopmentEvidenceError("row.canary_seat must be 0 or 1")
    _epoch_ns(raw["server_started_at_ns"], "row.server_started_at_ns")
    day, era = _derive_day_era(raw, time)
    if raw["game_day"] != day or raw["era"] != era:
        raise DevelopmentEvidenceError("game_day/era is not derived from server_started_at_ns")
    score = _canonical_decimal(raw["opponent_score_decimal"], "row.opponent_score_decimal", nonnegative=True)
    outcome = _canonical_decimal(raw["model_target_decimal"], "row.model_target_decimal")
    if outcome not in {"0", "0.5", "1"}:
        raise DevelopmentEvidenceError("row.model_target_decimal must be one of 0, 0.5, or 1")
    return {
        "schema": DEV_ROW_SCHEMA, "protocol_id": PROTOCOL_ID, "partition": DEV_BURNED,
        "competition_id": raw["competition_id"], "game_id": raw["game_id"],
        "canary_archive_id": raw["canary_archive_id"], "canary_lineage_id": raw["canary_lineage_id"],
        "scenario_receipt_sha256": raw["scenario_receipt_sha256"], "features": checked_features,
        "canary_seat": raw["canary_seat"], "server_started_at_ns": raw["server_started_at_ns"],
        "game_day": day, "era": era, "opponent_score_decimal": score,
        "model_target_decimal": outcome,
    }


def _validate_dataset(value: object, *, engine_hash: str, scenario: str, runtime: str, container: str, executable: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = _exact(value, _DATASET_FIELDS, "development dataset manifest")
    if raw["schema"] != DEV_DATASET_MANIFEST_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise DevelopmentEvidenceError("dataset is not the v5.1 dataset schema")
    if raw["partitions"] != [DEV_BURNED] or raw["feature_registry"] != list(FEATURE_REGISTRY):
        raise DevelopmentEvidenceError("dataset partition or feature registry is not frozen")
    bindings = {"engine_manifest_sha256": engine_hash, "scenario_sha256": scenario, "runtime_sha256": runtime, "container_sha256": container, "executable_sha256": executable}
    for key, expected in bindings.items():
        if _sha(raw[key], f"dataset.{key}") != expected:
            raise DevelopmentEvidenceError(f"dataset {key} mismatch")
    for key in ("g05_result_sha256", "g05_row_merkle_root_sha256", "g05_trace_binding_root_sha256"):
        _sha(raw[key], f"dataset.{key}")
    time = _validate_time(raw["time_derivation"])
    provenance = _exact(raw["provenance"], _PROVENANCE_FIELDS, "dataset provenance")
    if provenance["source_kind"] != DEV_BURNED:
        raise DevelopmentEvidenceError("dataset provenance source_kind must be DEV_BURNED")
    sources: list[dict[str, Any]] = []
    paths: list[str] = []
    for index, item in enumerate(raw["source_files"]):
        source = _exact(item, _SOURCE_FIELDS, f"source_files[{index}]")
        path = _relative_path(source["path"], "source path")
        if path in paths:
            raise DevelopmentEvidenceError("duplicate DEV source path")
        paths.append(path)
        sources.append({"path": path, "sha256": _sha(source["sha256"], "source sha256"), "row_count": _count(source["row_count"], "source row_count")})
    if paths != sorted(paths) or not sources:
        raise DevelopmentEvidenceError("source_files must be nonempty and path ordered")
    comp_sources: list[dict[str, Any]] = []
    comp_ids: list[str] = []
    for index, item in enumerate(raw["comparator_source_files"]):
        source = _exact(item, _COMPARATOR_SOURCE_FIELDS, f"comparator_source_files[{index}]")
        model_id = source["model_id"]
        if model_id not in COMPARATOR_IDENTITIES or model_id in comp_ids:
            raise DevelopmentEvidenceError("comparator registry is incomplete or duplicated")
        comp_ids.append(model_id)
        if source["extractor_sha256"] != _EXTRACTOR_HASHES[model_id]:
            raise DevelopmentEvidenceError("retired comparator extractor receipt mismatch")
        comp_sources.append({"model_id": model_id, "path": _relative_path(source["path"], "comparator source path"), "sha256": _sha(source["sha256"], "comparator source sha256"), "row_count": _count(source["row_count"], "comparator source row_count"), "extractor_sha256": source["extractor_sha256"]})
    if comp_ids != list(COMPARATOR_IDENTITIES):
        raise DevelopmentEvidenceError("every frozen comparator requires a raw source receipt")
    provenance_files: list[dict[str, Any]] = []
    provenance_categories: list[str] = []
    for index, item in enumerate(raw["provenance_files"]):
        entry = _exact(item, _PROVENANCE_FILE_FIELDS, f"provenance_files[{index}]")
        category = entry["category"]
        if category not in {"raw_source", "replay", "exclusion", "parser"} or category in provenance_categories:
            raise DevelopmentEvidenceError("G05 requires one unique raw_source/replay/exclusion/parser receipt")
        provenance_categories.append(category)
        path = _relative_path(entry["path"], "provenance path")
        provenance_files.append({"category": category, "path": path, "sha256": _sha(entry["sha256"], "provenance sha256"), "byte_count": _count(entry["byte_count"], "provenance byte_count")})
    if provenance_categories != ["raw_source", "replay", "exclusion", "parser"]:
        raise DevelopmentEvidenceError("G05 provenance categories are incomplete or out of order")
    scenario_receipts: list[dict[str, Any]] = []
    receipt_ids: list[str] = []
    for index, item in enumerate(raw["scenario_receipt_files"]):
        entry = _exact(item, _SCENARIO_RECEIPT_FILE_FIELDS, f"scenario_receipt_files[{index}]")
        game_id = _text(entry["game_id"], "scenario receipt game_id")
        if game_id in receipt_ids:
            raise DevelopmentEvidenceError("duplicate scenario receipt game_id")
        receipt_ids.append(game_id)
        scenario_receipts.append({"game_id": game_id, "path": _relative_path(entry["path"], "scenario receipt path"), "sha256": _sha(entry["sha256"], "scenario receipt sha256")})
    if receipt_ids != sorted(receipt_ids) or not scenario_receipts:
        raise DevelopmentEvidenceError("scenario receipt files must be nonempty and game ordered")
    scenario_root = canonical_sha256(scenario_receipts)
    if raw["scenario_receipt_root_sha256"] != scenario_root:
        raise DevelopmentEvidenceError("scenario receipt root mismatch")
    all_paths = [item["path"] for item in sources] + [item["path"] for item in comp_sources] + [item["path"] for item in provenance_files] + [item["path"] for item in scenario_receipts]
    if len(all_paths) != len(set(all_paths)):
        raise DevelopmentEvidenceError("source, comparator, provenance, and scenario receipt paths must be distinct")
    source_root = canonical_sha256({
        "source_files": sources, "comparator_source_files": comp_sources,
        "provenance_files": provenance_files, "scenario_receipt_files": scenario_receipts,
        "g05_result_sha256": raw["g05_result_sha256"],
        "g05_row_merkle_root_sha256": raw["g05_row_merkle_root_sha256"],
        "g05_trace_binding_root_sha256": raw["g05_trace_binding_root_sha256"],
    })
    if _sha(provenance["root_sha256"], "provenance.root_sha256") != source_root:
        raise DevelopmentEvidenceError("G05 provenance root does not bind every source category")
    normalized = dict(raw)
    normalized["source_files"] = sources
    normalized["comparator_source_files"] = comp_sources
    normalized["provenance_files"] = provenance_files
    normalized["scenario_receipt_files"] = scenario_receipts
    normalized["scenario_receipt_root_sha256"] = scenario_root
    normalized["time_derivation"] = time
    return normalized, time


def _read_rows(root_fd: int, dataset: Mapping[str, Any], time: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in dataset["source_files"]:
        raw, digest = _secure_read(root_fd, source["path"])
        if digest != source["sha256"]:
            raise DevelopmentEvidenceError(f"DEV source digest mismatch for {source['path']!r}")
        parsed = _parse_json(raw, f"DEV source {source['path']!r}")
        if type(parsed) is not list or len(parsed) != source["row_count"] or canonical_json_bytes(parsed) != raw:
            raise DevelopmentEvidenceError(f"DEV source {source['path']!r} must be a canonical ordered JSON list")
        checked = [_validate_row(item, time) for item in parsed]
        if canonical_json_bytes(checked) != raw:
            raise DevelopmentEvidenceError(f"DEV source {source['path']!r} is not the exact normalized v5.1 row list")
        rows.extend(checked)
    if len(rows) != dataset["row_count"]:
        raise DevelopmentEvidenceError("dataset row_count mismatch")
    if len({row["game_id"] for row in rows}) != len(rows):
        raise DevelopmentEvidenceError("duplicate game_id in ordered DEV rows")
    if len({row["canary_lineage_id"] for row in rows}) < 15:
        raise DevelopmentEvidenceError("at least 15 DEV lineages are required")
    if dataset["archive_count"] != len({row["canary_archive_id"] for row in rows}) or dataset["lineage_count"] != len({row["canary_lineage_id"] for row in rows}):
        raise DevelopmentEvidenceError("dataset archive/lineage count mismatch")
    if dataset["rows_sha256"] != canonical_sha256(rows):
        raise DevelopmentEvidenceError("dataset rows_sha256 mismatch")
    return rows


def _validate_hosted_custody_inputs(value: object, development_public_key: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    """Recompute the complete G05 receipt with the DEV signer excluded by key."""
    inputs = _exact(value, _HOSTED_CUSTODY_INPUT_FIELDS, "hosted_custody_inputs")
    custody = hosted_dev_custody.validate_hosted_dev_custody_result_receipt(
        **inputs,
        development_public_key=development_public_key,
    )
    if type(custody) is not dict:
        raise DevelopmentEvidenceError("G05 custody validator did not return a receipt object")
    if custody.get("decision") != hosted_dev_custody.G05_DECISION:
        raise DevelopmentEvidenceError("G05 custody receipt is not the complete research-only decision")
    if custody.get("schema") != hosted_dev_custody.G05_AUDIT_SCHEMA or custody.get("protocol_id") != hosted_dev_custody.G05_PROTOCOL:
        raise DevelopmentEvidenceError("G05 custody receipt schema or protocol mismatch")
    for field in ("authority", "submission_authorized", "sealed_holdout_access", "candidate_development_authorized"):
        if custody.get(field) is not False:
            raise DevelopmentEvidenceError(f"G05 custody receipt illegally sets {field}")
    receipt_hash = _sha(custody.get("result_sha256"), "G05 result_sha256")
    if canonical_sha256({key: item for key, item in custody.items() if key != "result_sha256"}) != receipt_hash:
        raise DevelopmentEvidenceError("G05 custody result_sha256 mismatch")
    role_keys = _exact(inputs["role_keys"], frozenset(hosted_dev_custody.ROLES), "G05 role_keys")
    trace_attestor = _exact(role_keys["trace_attestor"], frozenset({"identity", "public_key"}), "G05 trace_attestor role")
    trace_public_key = trace_attestor["public_key"]
    if type(trace_public_key) is not bytes or len(trace_public_key) != 32:
        raise DevelopmentEvidenceError("G05 trace-attestor public key is invalid")
    return inputs, custody, trace_public_key


def _bind_dataset_to_g05(dataset: Mapping[str, Any], custody: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], dict[str, str]]:
    bindings = {
        "g05_result_sha256": custody.get("result_sha256"),
        "g05_row_merkle_root_sha256": custody.get("row_merkle_root_sha256"),
        "g05_trace_binding_root_sha256": custody.get("trace_binding_root_sha256"),
    }
    for field, expected in bindings.items():
        if dataset[field] != _sha(expected, f"G05 {field}"):
            raise DevelopmentEvidenceError(f"dataset {field} does not bind the validator-signed G05 receipt")
    g05_rows = custody.get("rows")
    trace_hashes = custody.get("game_trace_envelope_sha256")
    if type(g05_rows) is not list or not g05_rows or type(trace_hashes) is not dict:
        raise DevelopmentEvidenceError("G05 custody receipt lacks its derived rows or trace bindings")
    rows: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(g05_rows):
        if type(row) is not dict or set(row) != set(hosted_dev_custody.HOSTED_COLUMNS):
            raise DevelopmentEvidenceError(f"G05 row {index} is not the exact published HOSTED_COLUMNS projection")
        game_id = _text(row.get("game_id"), "G05 row game_id")
        if game_id in rows:
            raise DevelopmentEvidenceError("G05 custody receipt has duplicate game IDs")
        for field in (
            "competition_id", "canary_archive_id", "canary_lineage_id", "canary_seat",
            "server_started_at_ns", "opponent_score_decimal", "outcome_code",
        ):
            if field not in row:
                raise DevelopmentEvidenceError(f"G05 row lacks {field}")
        if type(row["canary_seat"]) is not int or row["canary_seat"] not in (0, 1):
            raise DevelopmentEvidenceError("G05 row canary seat is invalid")
        _epoch_ns(row["server_started_at_ns"], "G05 row server_started_at_ns")
        _canonical_decimal(row["opponent_score_decimal"], "G05 row opponent_score_decimal", nonnegative=True)
        if type(row["outcome_code"]) is not int or row["outcome_code"] not in (-1, 0, 1):
            raise DevelopmentEvidenceError("G05 row outcome_code is invalid")
        rows[game_id] = row
    checked_trace_hashes: dict[str, str] = {}
    for game_id, digest in trace_hashes.items():
        checked_trace_hashes[_text(game_id, "G05 trace game_id")] = _sha(digest, "G05 game trace envelope sha256")
    if set(rows) != set(checked_trace_hashes):
        raise DevelopmentEvidenceError("G05 rows and trace bindings do not cover the exact same games")
    if len({row["canary_lineage_id"] for row in rows.values()}) < 15:
        raise DevelopmentEvidenceError("G05 custody evidence has fewer than 15 DEV lineages")
    return rows, checked_trace_hashes


def _bind_rows_to_g05(rows: Sequence[Mapping[str, Any]], g05_rows: Mapping[str, Mapping[str, Any]]) -> None:
    by_game = {row["game_id"]: row for row in rows}
    if set(by_game) != set(g05_rows):
        raise DevelopmentEvidenceError("caller DEV rows and G05 custody rows do not have the exact same game set")
    for game_id, row in by_game.items():
        hosted = g05_rows[game_id]
        for field in (
            "competition_id", "game_id", "canary_archive_id", "canary_lineage_id",
            "canary_seat", "server_started_at_ns", "opponent_score_decimal",
        ):
            if row[field] != hosted[field]:
                raise DevelopmentEvidenceError(f"caller DEV row {field} disagrees with G05 custody evidence")
        target = {-1: "0", 0: "0.5", 1: "1"}[hosted["outcome_code"]]
        if row["model_target_decimal"] != target:
            raise DevelopmentEvidenceError("caller DEV row model_target_decimal disagrees with G05 outcome_code")


def _read_g05_provenance(
    root_fd: int,
    dataset: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
    *,
    engine: Mapping[str, Any],
    g05_rows: Mapping[str, Mapping[str, Any]],
    g05_trace_hashes: Mapping[str, str],
    trace_attestor_public_key: bytes,
) -> None:
    """Use G05 trace envelopes only for local feature derivation.

    Hosted labels and covariates are accepted only from the validator-signed
    G05 rows.  The nested source trace receipt is a local rollout, never a
    source of hosted time, score, or outcome information.
    """
    for entry in dataset["provenance_files"]:
        raw, digest = _secure_read(root_fd, entry["path"])
        if digest != entry["sha256"] or len(raw) != entry["byte_count"]:
            raise DevelopmentEvidenceError(f"G05 provenance receipt mismatch for {entry['category']}")
        parsed = _parse_json(raw, f"G05 {entry['category']} receipt")
        if canonical_json_bytes(parsed) != raw:
            raise DevelopmentEvidenceError(f"G05 {entry['category']} receipt is not canonical")
    by_game = {row["game_id"]: row for row in rows}
    if [entry["game_id"] for entry in dataset["scenario_receipt_files"]] != sorted(by_game):
        raise DevelopmentEvidenceError("scenario receipt manifest does not cover the ordered DEV game set")
    support = {name: {"n": 0, "lineages": set()} for name in MODEL_FEATURES}
    for entry in dataset["scenario_receipt_files"]:
        raw, digest = _secure_read(root_fd, entry["path"])
        row = by_game[entry["game_id"]]
        if digest != entry["sha256"] or digest != row["scenario_receipt_sha256"]:
            raise DevelopmentEvidenceError(f"scenario receipt hash mismatch for {entry['game_id']}")
        envelope = _parse_json(raw, f"scenario receipt {entry['game_id']}")
        if canonical_json_bytes(envelope) != raw:
            raise DevelopmentEvidenceError("scenario receipt is not canonical")
        envelope_hash = canonical_sha256(envelope)
        if digest != envelope_hash or envelope_hash != g05_trace_hashes[entry["game_id"]]:
            raise DevelopmentEvidenceError("scenario receipt raw canonical hash is not the G05 trace-envelope binding")
        payload = _exact(
            verify_envelope(
                envelope,
                expected_artifact_schema=hosted_dev_custody.G05_TRACE_SCHEMA,
                pinned_public_key_bytes=trace_attestor_public_key,
            ),
            _G05_TRACE_FIELDS,
            "G05 trace envelope payload",
        )
        hosted = g05_rows[entry["game_id"]]
        for field in ("competition_id", "game_id", "canary_archive_id", "opponent_archive_id", "canary_seat"):
            if payload[field] != hosted[field]:
                raise DevelopmentEvidenceError(f"G05 trace {field} disagrees with its G05 row binding")
        if payload["source_engine_sha256"] != engine["engine_sha256"] or payload["source_container_sha256"] != dataset["container_sha256"]:
            raise DevelopmentEvidenceError("G05 trace engine/container binding mismatch")
        if payload["relation"] != "archive-conditioned-local-rollout" or payload["hosted_replay_or_rng_fidelity_claim"] is not False or payload["hosted_fields"] != []:
            raise DevelopmentEvidenceError("G05 trace makes an invalid hosted-fidelity claim")
        try:
            derived = derive_source_trace_receipt(payload["source_trace_receipt"])
        except ScenarioEvidenceError as exc:
            raise DevelopmentEvidenceError(f"source trace receipt is incomplete or invalid: {exc}") from exc
        if derived["scenario_sha256"] != dataset["scenario_sha256"]:
            raise DevelopmentEvidenceError("source trace receipt scenario hash mismatch")
        if derived["source_engine_sha256"] != payload["source_engine_sha256"] or derived["source_container_sha256"] != payload["source_container_sha256"]:
            raise DevelopmentEvidenceError("source trace receipt engine/container binding mismatch")
        if derived["trace_root_sha256"] != payload["trace_root_sha256"]:
            raise DevelopmentEvidenceError("source trace receipt trace root disagrees with its G05 envelope")
        plan = payload["source_trace_receipt"].get("scenario_plan") if type(payload["source_trace_receipt"]) is dict else None
        if type(plan) is not dict or plan.get("candidate_archive_sha256") != payload["canary_package_sha256"]:
            raise DevelopmentEvidenceError("G05 trace does not bind the nested canary package")
        opponents = plan.get("opponent_packages")
        if type(opponents) is not dict or payload["opponent_package_sha256"] not in {
            item.get("package_sha256") for item in opponents.values() if type(item) is dict
        }:
            raise DevelopmentEvidenceError("G05 trace does not bind the nested opponent package")
        source_bindings = {
            "game_id": hosted["game_id"], "archive_id": hosted["canary_archive_id"],
            "lineage_id": hosted["canary_lineage_id"], "seat": hosted["canary_seat"],
        }
        for field, expected in source_bindings.items():
            if derived[field] != expected:
                raise DevelopmentEvidenceError(f"source trace receipt {field} is not bound to its G05 trace row")
        if derived["features"] != row["features"]:
            raise DevelopmentEvidenceError("caller-supplied row features differ from signed source trace evidence")
        if derived["features"]["R4"] != "1.000000000000":
            raise DevelopmentEvidenceError("source trace receipt has unsafe R4")
        for name in MODEL_FEATURES:
            support[name]["n"] += derived["support"][name]["n"]
            if derived["support"][name]["n"] > 0:
                support[name]["lineages"].add(row["canary_lineage_id"])
    qualified = 0
    for name, item in support.items():
        if name in {"A2", "P4"}:
            qualified += int(item["n"] > 0)
        else:
            qualified += int(item["n"] >= 500 and len(item["lineages"]) >= 10)
    if qualified < 3:
        raise DevelopmentEvidenceError("trace-derived DEV support has fewer than three qualifying model features")


def _read_comparators(root_fd: int, dataset: Mapping[str, Any], game_ids: Sequence[str]) -> dict[str, dict[str, Decimal]]:
    expected_games = set(game_ids)
    result: dict[str, dict[str, Decimal]] = {}
    for source in dataset["comparator_source_files"]:
        raw, digest = _secure_read(root_fd, source["path"])
        if digest != source["sha256"]:
            raise DevelopmentEvidenceError(f"comparator source digest mismatch for {source['path']!r}")
        parsed = _parse_json(raw, f"comparator source {source['path']!r}")
        if type(parsed) is not list or len(parsed) != source["row_count"] or canonical_json_bytes(parsed) != raw:
            raise DevelopmentEvidenceError("comparator raw source must be canonical and ordered")
        values: dict[str, Decimal] = {}
        for index, item in enumerate(parsed):
            rec = _exact(item, _RAW_RECORD_FIELDS, f"raw comparator record {index}")
            if rec["schema"] != RAW_COMPARATOR_SCHEMA or rec["protocol_id"] != PROTOCOL_ID or rec["model_id"] != source["model_id"]:
                raise DevelopmentEvidenceError("raw comparator record is not bound to its registry entry")
            game_id = _text(rec["game_id"], "raw comparator game_id")
            if game_id in values or game_id not in expected_games:
                raise DevelopmentEvidenceError("raw comparator game set is duplicated or incomplete")
            value = _decimal(rec["raw_score"], "raw comparator score")
            if not _D("0") <= value <= _D("1"):
                raise DevelopmentEvidenceError("raw comparator score must be in [0,1]")
            values[game_id] = value
        if set(values) != expected_games:
            raise DevelopmentEvidenceError("every comparator raw source must cover every DEV game")
        result[source["model_id"]] = values
    return result


def _registry() -> list[dict[str, Any]]:
    return [{"model_id": name, "model_kind": "RETIRED_COMPARATOR", "extractor_sha256": _EXTRACTOR_HASHES[name], "raw_schema": RAW_COMPARATOR_SCHEMA, "raw_source_required": True} for name in COMPARATOR_IDENTITIES]


def _model_registry() -> list[dict[str, Any]]:
    return [{"model_id": MCI_MODEL_ID, "model_kind": "MCI", "feature_registry": list(MODEL_FEATURES), "safety_feature_registry": list(SAFETY_FEATURES), "raw_source_required": False}] + _registry()


def _validate_spec(value: object, *, dataset_hash: str, engine_hash: str, scenario: str, runtime: str, container: str, executable: str, folds: list[str]) -> dict[str, Any]:
    raw = _exact(value, _SPEC_FIELDS, "development fit spec")
    expected = {
        "schema": DEV_FIT_SPEC_SCHEMA, "protocol_id": PROTOCOL_ID, "dataset_manifest_sha256": dataset_hash,
        "engine_manifest_sha256": engine_hash, "scenario_sha256": scenario, "runtime_sha256": runtime,
        "container_sha256": container, "executable_sha256": executable, "feature_registry": list(FEATURE_REGISTRY),
        "standardization": _STANDARDIZATION, "optimizer": _OPTIMIZER, "regularization": _REGULARIZATION,
        "seed": 0, "lolo": {"unit": "lineage_id", "equal_lineage": True, "outer": True, "folds": folds, "fold_order": "lexical_lineage_id"},
        "model_registry": _model_registry(), "comparator_registry": _registry(), "missing_rules": _MISSING_RULES, "tie_break": _TIE_BREAK,
    }
    for key, expected_value in expected.items():
        if raw[key] != expected_value:
            raise DevelopmentEvidenceError(f"fit spec {key} mismatch")
    _timestamp(raw["fit_created_at_utc"], "fit_created_at_utc")
    if canonical_json_bytes(raw) != canonical_json_bytes({**expected, "fit_created_at_utc": raw["fit_created_at_utc"]}):
        raise DevelopmentEvidenceError("fit spec is not the exact frozen v5.1 spec")
    return dict(raw)


def _design(rows: Sequence[Mapping[str, Any]], comparator: Mapping[str, Decimal] | None, *, means: Mapping[str, Decimal] | None = None, scales: Mapping[str, Decimal] | None = None) -> tuple[list[str], list[list[Decimal]], dict[str, Decimal], dict[str, Decimal]]:
    eras = sorted({str(row["era"]) for row in rows})
    columns = ["intercept"] + [f"era:{era}" for era in eras[1:]] + ["seat", "game_day", "opponent_score"]
    if comparator is None:
        columns += [f"feature:{name}" for name in MODEL_FEATURES]
    else:
        columns += ["comparator_score"]
    standardize = [column for column in columns if column not in {"intercept", "seat"}]
    matrix: list[list[Decimal]] = []
    raw_by_column: dict[str, list[Decimal]] = {column: [] for column in columns}
    for row in rows:
        values = {"intercept": _D(1), "seat": _D(row["canary_seat"]), "game_day": _D(row["game_day"]), "opponent_score": _D(row["opponent_score_decimal"]), **{f"era:{era}": _D(1 if row["era"] == era else 0) for era in eras[1:]}}
        if comparator is None:
            values.update({f"feature:{name}": _D(row["features"][name]) for name in MODEL_FEATURES})
        else:
            values["comparator_score"] = comparator[row["game_id"]]
        for column in columns:
            raw_by_column[column].append(values.get(column, _D(0)))
    fitted_means = dict(means or {})
    fitted_scales = dict(scales or {})
    for column in standardize:
        if column not in fitted_means:
            values = raw_by_column[column]
            mean = sum(values, _D(0)) / _D(len(values))
            variance = sum((value - mean) ** 2 for value in values) / _D(len(values))
            scale = variance.sqrt() if variance > 0 else _D(1)
            fitted_means[column] = mean
            fitted_scales[column] = scale
        if fitted_scales[column] == 0:
            fitted_scales[column] = _D(1)
    for index in range(len(rows)):
        matrix.append([(raw_by_column[column][index] - fitted_means[column]) / fitted_scales[column] if column in standardize else raw_by_column[column][index] for column in columns])
    return columns, matrix, fitted_means, fitted_scales


def _sigmoid(z: Decimal) -> Decimal:
    with localcontext(_DECIMAL_CONTEXT):
        if z >= 0:
            return _D(1) / (_D(1) + (-z).exp())
        ez = z.exp()
        return ez / (_D(1) + ez)


def _fit(rows: Sequence[Mapping[str, Any]], comparator: Mapping[str, Decimal] | None, *, l2: Decimal) -> tuple[dict[str, Any], list[list[Decimal]]]:
    columns, matrix, means, scales = _design(rows, comparator)
    coefficients = [_D(0) for _ in columns]
    projected = {index for index, column in enumerate(columns) if comparator is None and column.startswith("feature:")}
    labels = [_D(row["model_target_decimal"]) for row in rows]
    with localcontext(_DECIMAL_CONTEXT):
        for _sweep in range(_OPTIMIZER["sweep_count"]):
            for coordinate in range(len(columns)):
                gradient = _D(0)
                hessian = l2 if coordinate != 0 else _D(0)
                for values, label in zip(matrix, labels):
                    probability = _sigmoid(sum(coefficient * value for coefficient, value in zip(coefficients, values)))
                    weight = probability * (_D(1) - probability)
                    gradient += values[coordinate] * (probability - label)
                    hessian += weight * values[coordinate] * values[coordinate]
                if hessian == 0:
                    continue
                updated = coefficients[coordinate] - gradient / hessian
                coefficients[coordinate] = max(_D(0), updated) if coordinate in projected else updated
    model = {
        "columns": columns,
        "means": {key: _q12(value) for key, value in sorted(means.items())},
        "scales": {key: _q12(value) for key, value in sorted(scales.items())},
        "coefficients": {column: _q12(coefficient) for column, coefficient in zip(columns, coefficients)},
    }
    return model, matrix


def _predict(model: Mapping[str, Any], row: Mapping[str, Any], comparator_value: Decimal | None) -> Decimal:
    columns = model["columns"]
    means = {key: _D(value) for key, value in model["means"].items()}
    scales = {key: _D(value) for key, value in model["scales"].items()}
    coefficients = {key: _D(value) for key, value in model["coefficients"].items()}
    values: dict[str, Decimal] = {"intercept": _D(1), "seat": _D(row["canary_seat"]), "game_day": _D(row["game_day"]), "opponent_score": _D(row["opponent_score_decimal"])}
    for column in columns:
        if column.startswith("era:"):
            values[column] = _D(1 if row["era"] == column[4:] else 0)
        if column.startswith("feature:"):
            values[column] = _D(row["features"][column[8:]])
    if "comparator_score" in columns:
        if comparator_value is None:
            raise DevelopmentEvidenceError("comparator prediction is missing its raw receipt")
        values["comparator_score"] = comparator_value
    vector = [(values[column] - means[column]) / scales[column] if column in means else values[column] for column in columns]
    with localcontext(_DECIMAL_CONTEXT):
        probability = _sigmoid(sum(coefficients[column] * value for column, value in zip(columns, vector)))
        return max(_P_MIN, min(_P_MAX, probability))


def _loss(probability: Decimal, outcome: Decimal) -> Decimal:
    with localcontext(_DECIMAL_CONTEXT):
        probability = max(_P_MIN, min(_P_MAX, probability))
        return -(outcome * probability.ln() + (_D(1) - outcome) * (_D(1) - probability).ln())


def _score_candidates(rows: list[dict[str, Any]], raw_values: Mapping[str, Mapping[str, Decimal]], folds: list[str]) -> list[dict[str, Any]]:
    table: list[dict[str, Any]] = []
    for model_id in COMPARATOR_IDENTITIES:
        fold_scores: list[dict[str, Any]] = []
        for lineage in folds:
            training = [row for row in rows if row["canary_lineage_id"] != lineage]
            testing = [row for row in rows if row["canary_lineage_id"] == lineage]
            model, _ = _fit(training, raw_values[model_id], l2=_D(_REGULARIZATION["lambda"]))
            score = sum((_loss(_predict(model, row, raw_values[model_id][row["game_id"]]), _D(row["model_target_decimal"])) for row in testing), _D(0)) / _D(len(testing))
            fold_scores.append({"lineage_id": lineage, "log_loss": _q12(score), "row_count": len(testing)})
        total = sum((_D(item["log_loss"]) for item in fold_scores), _D(0)) / _D(len(fold_scores))
        table.append({"model_id": model_id, "folds": fold_scores, "log_loss": _q12(total)})
    return table


def _fit_complete(rows: list[dict[str, Any]], raw_values: Mapping[str, Mapping[str, Decimal]], spec_hash: str, dataset_hash: str, executable: str, folds: list[str]) -> tuple[list[dict[str, Any]], str, dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    table = _score_candidates(rows, raw_values, folds)
    selected = min(table, key=lambda item: (_D(item["log_loss"]), item["model_id"]))
    mci, _ = _fit(rows, None, l2=_D(_REGULARIZATION["lambda"]))
    comparator, _ = _fit(rows, raw_values[selected["model_id"]], l2=_D(_REGULARIZATION["lambda"]))
    def manifest(model_id: str, kind: str, fitted: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": MODEL_MANIFEST_SCHEMA, "protocol_id": PROTOCOL_ID, "model_id": model_id, "model_kind": kind,
            "feature_registry": list(MODEL_FEATURES), "design_columns": fitted["columns"],
            "safety_feature_registry": list(SAFETY_FEATURES),
            "standardization": {"means": fitted["means"], "scales": fitted["scales"]}, "coefficients": fitted["coefficients"],
            "coefficient_quantization_decimals": 12, "probability_quantization_decimals": 12,
            "probability_clip": [_q12(_P_MIN), _q12(_P_MAX)], "dataset_manifest_sha256": dataset_hash,
            "fit_spec_sha256": spec_hash, "executable_sha256": executable,
        }
    mci_manifest = manifest(MCI_MODEL_ID, "MCI", mci)
    comparator_manifest = manifest(selected["model_id"], "RETIRED_COMPARATOR", comparator)
    transcript = [{"game_id": row["game_id"], "mci_probability": _q12(_predict(mci_manifest_to_model(mci_manifest), row, None)), "comparator_probability": _q12(_predict(mci_manifest_to_model(comparator_manifest), row, raw_values[selected["model_id"]][row["game_id"]]))} for row in rows]
    return table, selected["model_id"], mci_manifest, comparator_manifest, transcript


def fit_development_models(
    rows: Sequence[Mapping[str, Any]],
    comparator_values: Mapping[str, Mapping[str, Decimal | str]],
    *,
    dataset_manifest_sha256: str,
    fit_spec_sha256: str,
    executable_sha256: str,
    folds: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run the pinned v5.1 fitter without an external numerical backend.

    The audit function never accepts ``comparator_values`` from an evidence
    caller; it derives them from verified raw-source/extractor receipts first.
    """
    checked_rows = [dict(row) for row in rows]
    lineage_folds = list(folds) if folds is not None else sorted({row["canary_lineage_id"] for row in checked_rows})
    if lineage_folds != sorted(set(lineage_folds)) or len(lineage_folds) < 15:
        raise DevelopmentEvidenceError("fit requires at least 15 ordered DEV lineages")
    if set(lineage_folds) != {row["canary_lineage_id"] for row in checked_rows}:
        raise DevelopmentEvidenceError("fit folds do not cover exactly the DEV lineages")
    values: dict[str, dict[str, Decimal]] = {}
    for model_id in COMPARATOR_IDENTITIES:
        if model_id not in comparator_values:
            raise DevelopmentEvidenceError("fit comparator registry is incomplete")
        values[model_id] = {}
        for game_id, value in comparator_values[model_id].items():
            values[model_id][game_id] = value if isinstance(value, Decimal) else _decimal(value, f"{model_id}.{game_id}")
    table, selected, mci, comparator, transcript = _fit_complete(
        checked_rows, values, _sha(fit_spec_sha256, "fit_spec_sha256"),
        _sha(dataset_manifest_sha256, "dataset_manifest_sha256"),
        _sha(executable_sha256, "executable_sha256"), lineage_folds,
    )
    return {"candidate_score_table": table, "selected_model_id": selected, "mci_manifest": mci, "comparator_manifest": comparator, "prediction_transcript": transcript}


def mci_manifest_to_model(manifest: Mapping[str, Any]) -> dict[str, Any]:
    standardization = manifest["standardization"]
    return {"columns": manifest["design_columns"], "means": standardization["means"], "scales": standardization["scales"], "coefficients": manifest["coefficients"]}


def _core(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: result[key] for key in _RESULT_FIELDS if key not in {"result_core_sha256", "rebuild_receipts"}}


def _validate_result_shape(value: object) -> dict[str, Any]:
    result = _exact(value, _RESULT_FIELDS, "development fit result")
    for field in ("authority", "candidate_development_authorized", "sealed_holdout_access_authorized", "submission_authorized"):
        if result[field] is not False:
            raise DevelopmentEvidenceError(f"fit result illegally sets {field}")
    if result["fit_status"] not in {"FIT_COMPLETE", "NO_LOCAL_FEATURE_EXTRACTION"}:
        raise DevelopmentEvidenceError("unknown fit status")
    return result


def _validate_rebuilds(value: object, *, result_core_hash: str, model_output_hash: str, runtime: str, executable: str) -> None:
    if type(value) is not list or len(value) != 2:
        raise DevelopmentEvidenceError("exactly two clean Linux/amd64 rebuild receipts are required")
    ids: list[str] = []
    for index, item in enumerate(value):
        receipt = _exact(item, _REBUILD_FIELDS, f"rebuild receipt {index}")
        if receipt["rebuild_id"] in ids or receipt["os"] != "linux" or receipt["arch"] != "amd64" or receipt["clean"] is not True:
            raise DevelopmentEvidenceError("rebuild receipts must be distinct clean Linux/amd64 identities")
        ids.append(receipt["rebuild_id"])
        if receipt["runtime_sha256"] != runtime or receipt["executable_sha256"] != executable or receipt["result_core_sha256"] != result_core_hash or receipt["model_output_sha256"] != model_output_hash:
            raise DevelopmentEvidenceError("rebuild receipt does not bind the byte-identical fit root")
    if ids != sorted(ids):
        raise DevelopmentEvidenceError("rebuild receipts must be ordered by rebuild_id")


def _closed(reason: str, engine_hash: str | None = None) -> dict[str, Any]:
    return {"schema": DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA, "protocol_id": PROTOCOL_ID, "authority": False, "candidate_development_authorized": False, "sealed_holdout_access_authorized": False, "submission_authorized": False, "evidence_complete": False, "decision": "NO_LOCAL_FEATURE_EXTRACTION" if reason == "NO_LOCAL_FEATURE_EXTRACTION" else "DEVELOPMENT_EVIDENCE_INCOMPLETE", "local_feature_extraction": False, "engine_manifest_sha256": engine_hash, "failure_reason": reason}


def audit_development_fit_evidence(dataset_envelope: object, fit_spec_envelope: object, fit_result_envelope: object, repo_root: str | os.PathLike[str], *, engine_capability_manifest: object, scenario_sha256: str, runtime_sha256: str, container_sha256: str, executable_sha256: str, pinned_public_key_bytes: bytes, hosted_custody_inputs: object) -> dict[str, Any]:
    """Verify G_DEV and return a non-authoritative audit receipt."""
    try:
        scenario = _sha(scenario_sha256, "scenario_sha256")
        runtime = _sha(runtime_sha256, "runtime_sha256")
        container = _sha(container_sha256, "container_sha256")
        executable = _sha(executable_sha256, "executable_sha256")
        engine, engine_hash, feasible = _engine(engine_capability_manifest, scenario=scenario, runtime=runtime, container=container, executable=executable)
        dataset_payload = verify_envelope(dataset_envelope, expected_artifact_schema=DEV_DATASET_MANIFEST_SCHEMA, pinned_public_key_bytes=pinned_public_key_bytes)
        dataset, time = _validate_dataset(dataset_payload, engine_hash=engine_hash, scenario=scenario, runtime=runtime, container=container, executable=executable)
        dataset_hash = canonical_sha256(dataset_payload)
        _, custody, trace_attestor_public_key = _validate_hosted_custody_inputs(hosted_custody_inputs, pinned_public_key_bytes)
        g05_rows, g05_trace_hashes = _bind_dataset_to_g05(dataset, custody)
        root = os.open(os.fspath(repo_root), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            rows = _read_rows(root, dataset, time)
            _bind_rows_to_g05(rows, g05_rows)
            _read_g05_provenance(
                root,
                dataset,
                rows,
                engine=engine,
                g05_rows=g05_rows,
                g05_trace_hashes=g05_trace_hashes,
                trace_attestor_public_key=trace_attestor_public_key,
            )
            raw_values = _read_comparators(root, dataset, [row["game_id"] for row in rows])
        finally:
            os.close(root)
        folds = sorted({row["canary_lineage_id"] for row in rows})
        spec_payload = verify_envelope(fit_spec_envelope, expected_artifact_schema=DEV_FIT_SPEC_SCHEMA, pinned_public_key_bytes=pinned_public_key_bytes)
        spec = _validate_spec(spec_payload, dataset_hash=dataset_hash, engine_hash=engine_hash, scenario=scenario, runtime=runtime, container=container, executable=executable, folds=folds)
        spec_hash = canonical_sha256(spec_payload)
        result_payload = verify_envelope(fit_result_envelope, expected_artifact_schema=DEV_FIT_RESULT_SCHEMA, pinned_public_key_bytes=pinned_public_key_bytes)
        result = _validate_result_shape(result_payload)
        bindings = {"dataset_manifest_sha256": dataset_hash, "fit_spec_sha256": spec_hash, "engine_manifest_sha256": engine_hash, "scenario_sha256": scenario, "runtime_sha256": runtime, "container_sha256": container, "executable_sha256": executable, "fit_created_at_utc": spec["fit_created_at_utc"]}
        for field, expected in bindings.items():
            if result[field] != expected:
                raise DevelopmentEvidenceError(f"fit result {field} mismatch")
        if result["fold_hash"] != canonical_sha256(folds):
            raise DevelopmentEvidenceError("fit result fold_hash mismatch")
        if not feasible:
            if result["fit_status"] != "NO_LOCAL_FEATURE_EXTRACTION" or result["candidate_score_table"] or result["selected_comparator_identity"] is not None or result["mci_manifest"] is not None or result["comparator_manifest"] is not None:
                raise DevelopmentEvidenceError("NO_LOCAL_FEATURE_EXTRACTION result must be empty and closed")
            model_output_hash = canonical_sha256({"mci_manifest": None, "comparator_manifest": None, "prediction_transcript_sha256": result["prediction_transcript_sha256"]})
            core_hash = canonical_sha256(_core(result))
            _validate_rebuilds(result["rebuild_receipts"], result_core_hash=core_hash, model_output_hash=model_output_hash, runtime=runtime, executable=executable)
            if result["result_core_sha256"] != core_hash or result["model_output_sha256"] != model_output_hash:
                raise DevelopmentEvidenceError("closed result root hash mismatch")
            return _closed("NO_LOCAL_FEATURE_EXTRACTION", engine_hash)
        table, selected, mci, comparator, transcript = _fit_complete(rows, raw_values, spec_hash, dataset_hash, executable, folds)
        expected_table_hash = canonical_sha256(table)
        if result["fit_status"] != "FIT_COMPLETE" or result["candidate_score_table"] != table or result["candidate_score_table_sha256"] != expected_table_hash:
            raise DevelopmentEvidenceError("complete candidate score table mismatch")
        ranked = min(table, key=lambda item: (_D(item["log_loss"]), item["model_id"]))
        if selected != ranked["model_id"] or result["selected_comparator_identity"] != selected:
            raise DevelopmentEvidenceError("deterministic (log_loss, model_id) tie-break selection mismatch")
        expected_transcript_hash = canonical_sha256(transcript)
        model_output_hash = canonical_sha256({"mci_manifest": mci, "comparator_manifest": comparator, "prediction_transcript_sha256": expected_transcript_hash})
        if result["mci_manifest"] != mci or result["comparator_manifest"] != comparator or result["prediction_transcript_sha256"] != expected_transcript_hash or result["model_output_sha256"] != model_output_hash:
            raise DevelopmentEvidenceError("MCI/comparator/prediction output is not byte-identical")
        core_hash = canonical_sha256(_core(result))
        if result["result_core_sha256"] != core_hash:
            raise DevelopmentEvidenceError("fit result core hash mismatch")
        _validate_rebuilds(result["rebuild_receipts"], result_core_hash=core_hash, model_output_hash=model_output_hash, runtime=runtime, executable=executable)
        return {"schema": DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA, "protocol_id": PROTOCOL_ID, "authority": False, "candidate_development_authorized": False, "sealed_holdout_access_authorized": False, "submission_authorized": False, "evidence_complete": True, "decision": "DEVELOPMENT_ONLY", "local_feature_extraction": True, "engine_manifest_sha256": engine_hash, "failure_reason": None, "selected_comparator_identity": selected, "candidate_score_table_sha256": expected_table_hash}
    except (DevelopmentEvidenceError, EnvelopeError, CanonicalJSONError, TypeError, ValueError, OSError) as exc:
        return _closed(str(exc))


audit = audit_development_fit_evidence
audit_development_evidence = audit_development_fit_evidence
audit_dev_fit_evidence = audit_development_fit_evidence
verify_development_fit_evidence = audit_development_fit_evidence


__all__ = [
    "AUTHORITY", "COMPARATOR_IDENTITIES", "DEV_BURNED", "DEV_DATASET_MANIFEST_SCHEMA", "DEV_FIT_RESULT_SCHEMA", "DEV_FIT_SPEC_SCHEMA", "DEV_ROW_SCHEMA", "DEVELOPMENT_EVIDENCE_AUDIT_SCHEMA", "FEATURE_REGISTRY", "MODEL_FEATURES", "SAFETY_FEATURES", "DevelopmentEvidenceError", "audit", "audit_development_evidence", "audit_dev_fit_evidence", "audit_development_fit_evidence", "fit_development_models", "mci_manifest_to_model", "verify_development_fit_evidence",
]
