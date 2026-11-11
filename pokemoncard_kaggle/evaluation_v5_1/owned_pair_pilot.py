"""Development-only rehearsal for two exact archive outcome pairs.

This module is intentionally separate from G11.  It verifies the shape and
ordering of a local ``L(A)`` receipt followed by a prospective ``H+(A)``
receipt, but it has no trust roots, no production allowlist, and no authority.
In particular, a structurally complete rehearsal is never a submission gate.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any

from .canonical import canonical_json_bytes, canonical_sha256


PROTOCOL_ID = "EVALUATION_V5_1_OWNED_PAIR_PILOT_V1"
DESIGN_SCHEMA = "evaluation_v5_1_owned_pair_design_freeze_v1"
LOCAL_SCHEMA = "evaluation_v5_1_owned_pair_local_result_v1"
ACTIVATION_SCHEMA = "evaluation_v5_1_owned_pair_activation_freeze_v1"
HOSTED_SCHEMA = "evaluation_v5_1_owned_pair_hosted_result_v1"
REHEARSAL_SCHEMA = "evaluation_v5_1_owned_pair_rehearsal_receipt_v1"
MODE = "DEVELOPMENT_ONLY_ZERO_AUTHORITY"
COMPLETE = "DEVELOPMENT_COLLECTION_COMPLETE_NO_TRANSFER_CLAIM"
INCOMPLETE = "DEVELOPMENT_PAIR_REHEARSAL_INCOMPLETE"
SCIENTIFIC_DISPOSITION = "OBSERVATIONAL_DEV_ONLY_SCIENTIFICALLY_UNDERSPECIFIED"
SCIENTIFIC_BLOCKERS = (
    "NO_FROZEN_TRANSFER_ESTIMAND",
    "NO_FROZEN_T1_OR_CENSORING_RULE",
    "UNMATCHED_HOSTED_SCHEDULER_EXPOSURE",
    "NO_EPISODE_LEVEL_OPPONENT_ARCHIVE_BINDING",
    "NO_FROZEN_UNCERTAINTY_OR_DECISION_RULE",
    "NO_PRE_T0_ANALYSIS_LOCK",
)

_SHA = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_FORBIDDEN_PUBLIC_FIELDS = frozenset(
    {
        "public_score",
        "public_rank",
        "leaderboard_score",
        "leaderboard_rank",
        "kaggle_score",
        "kaggle_rank",
        "hosted_score",
        "hosted_rank",
        "public_outcome",
        "hosted_outcome",
    }
)
_SEALED_TOKENS = ("sealed", "holdout")
_AUTHORITY_STRING = "SUBMIT_AUTHORIZED"
_REQUIRED_CONTROL_ROLES = frozenset({"claude", "grok", "top_tier"})
_PRODUCTION_BLOCKERS = (
    "common_ancestry",
    "external_collector_unavailable",
    "only_two_units",
    "prior_hosted_history",
)
_SEATS = (0, 1)
_TERMINAL_OUTCOMES = ("DRAW", "LOSS", "WIN")
_ALLOWED_AGENT_STATUSES = frozenset(
    {"CRASHED", "DONE", "ERROR", "FAILED", "INVALID", "PACKAGE_ERROR", "RUNTIME_ERROR", "TIMEOUT"}
)
_AUTHORITY_FLAGS = (
    "authority",
    "candidate_development_authorized",
    "sealed_holdout_access",
    "holdout_access_authorized",
    "submission_authorized",
)
_FORBIDDEN_HOSTED_FIELDS = tuple(sorted(_FORBIDDEN_PUBLIC_FIELDS))


class OwnedPairPilotError(ValueError):
    """Raised when a rehearsal artifact is malformed or out of phase."""


class _DuplicateKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _reject_floats(value: object, path: str = "$") -> None:
    """Protocol values use integers or canonical decimal strings, never JSON floats."""

    if type(value) is float:
        raise OwnedPairPilotError(f"{path} contains a float")
    if type(value) is list:
        for index, child in enumerate(value):
            _reject_floats(child, f"{path}[{index}]")
    elif type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise OwnedPairPilotError(f"{path} has a non-string key")
            _reject_floats(child, f"{path}.{key}")


def _reject_authority_text(value: object, path: str = "$") -> None:
    if type(value) is str and _AUTHORITY_STRING in value:
        raise OwnedPairPilotError(f"{path} contains forbidden authority text")
    if type(value) is list:
        for index, child in enumerate(value):
            _reject_authority_text(child, f"{path}[{index}]")
    elif type(value) is dict:
        for key, child in value.items():
            _reject_authority_text(key, f"{path}.<key>")
            _reject_authority_text(child, f"{path}.{key}")


def _reject_hosted_forbidden(value: object, path: str = "$") -> None:
    if type(value) is str:
        lowered = value.lower().replace("-", "_")
        if any(token in lowered for token in _SEALED_TOKENS):
            raise OwnedPairPilotError(f"{path} contains a sealed/holdout reference")
    if type(value) is list:
        for index, child in enumerate(value):
            _reject_hosted_forbidden(child, f"{path}[{index}]")
    elif type(value) is dict:
        for key, child in value.items():
            normalized = key.lower().replace("-", "_") if type(key) is str else ""
            if normalized in _FORBIDDEN_PUBLIC_FIELDS:
                raise OwnedPairPilotError(f"{path}.{key} is a forbidden public/hosted field")
            _reject_hosted_forbidden(child, f"{path}.{key}")


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise OwnedPairPilotError(f"{label} fields are not exact")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise OwnedPairPilotError(f"{label} must be a nonempty trimmed string")
    if _AUTHORITY_STRING in value:
        raise OwnedPairPilotError(f"{label} contains forbidden authority text")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OwnedPairPilotError(f"{label} must be lowercase SHA-256")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise OwnedPairPilotError(f"{label} must be canonical microsecond UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise OwnedPairPilotError(f"{label} is not a real UTC timestamp") from exc


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise OwnedPairPilotError(f"{label} must be boolean")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise OwnedPairPilotError(f"{label} must be a positive integer")
    return value


def _sorted_unique_texts(value: object, label: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise OwnedPairPilotError(f"{label} must be a list of strings")
    if value != sorted(set(value)):
        raise OwnedPairPilotError(f"{label} must be sorted and duplicate-free")
    return value


def _root(value: Mapping[str, Any], field: str) -> str:
    unsigned = {key: item for key, item in value.items() if key != field}
    return canonical_sha256(unsigned)


def _assert_root(value: Mapping[str, Any], field: str, label: str) -> str:
    actual = _sha(value.get(field), f"{label}.{field}")
    expected = _root(value, field)
    if actual != expected:
        raise OwnedPairPilotError(f"{label} root does not match canonical content")
    return actual


def add_canonical_root(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    """Return a copy with a canonical content root in ``field``."""

    result = dict(value)
    result[field] = _root(result, field)
    return result


def _common_header(value: object, schema: str, fields: frozenset[str], label: str) -> dict[str, Any]:
    raw = _exact(value, fields, label)
    _reject_floats(raw)
    _reject_authority_text(raw)
    if raw["schema"] != schema or raw["protocol_id"] != PROTOCOL_ID or raw["mode"] != MODE:
        raise OwnedPairPilotError(f"{label} schema, protocol, or mode is invalid")
    return raw


def _validate_pair(value: object, label: str) -> dict[str, Any]:
    pair = _exact(
        value,
        frozenset({"pair_id", "archive_identity", "submission_ref", "submission_id", "archive_sha256", "active"}),
        label,
    )
    pair_id = _text(pair["pair_id"], f"{label}.pair_id")
    identity = _exact(pair["archive_identity"], frozenset({"archive_id", "archive_label"}), f"{label}.archive_identity")
    _text(identity["archive_id"], f"{label}.archive_identity.archive_id")
    _text(identity["archive_label"], f"{label}.archive_identity.archive_label")
    _text(pair["submission_ref"], f"{label}.submission_ref")
    _text(pair["submission_id"], f"{label}.submission_id")
    _sha(pair["archive_sha256"], f"{label}.archive_sha256")
    if pair["active"] is not True:
        raise OwnedPairPilotError(f"{label}.active must be true for an owned active pair")
    return {**pair, "pair_id": pair_id}


def validate_design_freeze(value: object) -> dict[str, Any]:
    """Validate the immutable pre-run design and return it unchanged."""

    fields = frozenset(
        {
            "schema", "protocol_id", "mode", "design_frozen_at_utc", "pairs", "controls",
            "deterministic_engine", "evaluator_runner_sha256", "schedule", "metrics", "quotas",
            "pre_registration_sha256", "forbidden_hosted_fields", "production_blockers",
            "design_root_sha256",
        }
    )
    design = _common_header(value, DESIGN_SCHEMA, fields, "design")
    frozen = _timestamp(design["design_frozen_at_utc"], "design.design_frozen_at_utc")
    _sha(design["pre_registration_sha256"], "design.pre_registration_sha256")
    pairs = design["pairs"]
    if type(pairs) is not list or len(pairs) != 2:
        raise OwnedPairPilotError("design must contain exactly two owned archive pairs")
    checked_pairs = [_validate_pair(item, f"design.pairs[{index}]") for index, item in enumerate(pairs)]
    if [item["pair_id"] for item in checked_pairs] != sorted({item["pair_id"] for item in checked_pairs}):
        raise OwnedPairPilotError("design pair IDs must be sorted and unique")

    pair_archive_hashes = [item["archive_sha256"] for item in checked_pairs]
    pair_submission_refs = [item["submission_ref"] for item in checked_pairs]
    pair_submission_ids = [item["submission_id"] for item in checked_pairs]
    if (
        len(set(pair_archive_hashes)) != len(checked_pairs)
        or len(set(pair_submission_refs)) != len(checked_pairs)
        or len(set(pair_submission_ids)) != len(checked_pairs)
    ):
        raise OwnedPairPilotError("design pair archive and submission identities must be unique")

    controls = design["controls"]
    if type(controls) is not list or not controls:
        raise OwnedPairPilotError("design.controls must be a nonempty list")
    checked_controls: list[dict[str, Any]] = []
    for index, value in enumerate(controls):
        control = _exact(
            value,
            frozenset({"control_label", "role", "archive_id", "archive_sha256"}),
            f"design.controls[{index}]",
        )
        _text(control["control_label"], f"design.controls[{index}].control_label")
        _text(control["archive_id"], f"design.controls[{index}].archive_id")
        if control["role"] not in _REQUIRED_CONTROL_ROLES:
            raise OwnedPairPilotError("design control has an unsupported role")
        _sha(control["archive_sha256"], f"design.controls[{index}].archive_sha256")
        checked_controls.append(control)
    control_labels = [item["control_label"] for item in checked_controls]
    control_hashes = [item["archive_sha256"] for item in checked_controls]
    if control_labels != sorted(set(control_labels)):
        raise OwnedPairPilotError("design control labels must be sorted and unique")
    if len(set(control_hashes)) != len(control_hashes):
        raise OwnedPairPilotError("design control archive hashes must be unique")
    if set(control_hashes) & set(pair_archive_hashes):
        raise OwnedPairPilotError("design control archive reuses an owned pair archive")
    if {item["role"] for item in checked_controls} != _REQUIRED_CONTROL_ROLES:
        raise OwnedPairPilotError("design must include Claude, Grok, and top-tier controls")
    controls_by_label = {item["control_label"]: item for item in checked_controls}

    engine = _exact(design["deterministic_engine"], frozenset({"manifest_id", "manifest_sha256"}), "design.deterministic_engine")
    _text(engine["manifest_id"], "design.deterministic_engine.manifest_id")
    _sha(engine["manifest_sha256"], "design.deterministic_engine.manifest_sha256")
    _sha(design["evaluator_runner_sha256"], "design.evaluator_runner_sha256")

    schedule = _exact(
        design["schedule"],
        frozenset({"seed_root_sha256", "seats", "control_labels", "cells"}),
        "design.schedule",
    )
    _sha(schedule["seed_root_sha256"], "design.schedule.seed_root_sha256")
    if schedule["seats"] != list(_SEATS) or schedule["control_labels"] != control_labels:
        raise OwnedPairPilotError("design schedule seat/control order is not frozen")
    quotas = _exact(design["quotas"], frozenset({"local_cells_per_pair", "hosted_future_episodes_per_pair"}), "design.quotas")
    local_quota = _positive_int(quotas["local_cells_per_pair"], "design.quotas.local_cells_per_pair")
    hosted_quota = _positive_int(quotas["hosted_future_episodes_per_pair"], "design.quotas.hosted_future_episodes_per_pair")
    _sorted_unique_texts(design["metrics"], "design.metrics")
    if design["forbidden_hosted_fields"] != list(_FORBIDDEN_HOSTED_FIELDS):
        raise OwnedPairPilotError("design forbidden hosted field registry is not exact")

    blockers = _exact(
        design["production_blockers"],
        frozenset(_PRODUCTION_BLOCKERS),
        "design.production_blockers",
    )
    for key in blockers:
        blocker = _exact(blockers[key], frozenset({"terminal", "reason"}), f"design.production_blockers.{key}")
        if blocker["terminal"] is not True or not _text(blocker["reason"], f"{key}.reason"):
            raise OwnedPairPilotError(f"{key} must be an explicit terminal production blocker")

    cells = schedule["cells"]
    expected_count = len(checked_pairs) * local_quota
    if type(cells) is not list or len(cells) != expected_count:
        raise OwnedPairPilotError("design schedule does not match local quota")
    expected_pairs = {item["pair_id"]: item for item in checked_pairs}
    seen_cells: set[str] = set()
    seen_schedule_keys: set[tuple[str, str, int, int]] = set()
    pair_cell_counts = {pair_id: 0 for pair_id in expected_pairs}
    pair_roles = {pair_id: set() for pair_id in expected_pairs}
    pair_seats = {pair_id: set() for pair_id in expected_pairs}
    observed_seeds: set[int] = set()
    for index, cell_value in enumerate(cells):
        cell = _exact(
            cell_value,
            frozenset({"cell_id", "pair_id", "control_label", "control_role", "control_archive_sha256", "seed", "seat"}),
            f"design.schedule.cells[{index}]",
        )
        cell_id = _text(cell["cell_id"], f"schedule.cells[{index}].cell_id")
        if cell_id in seen_cells:
            raise OwnedPairPilotError("design schedule contains duplicate cells")
        seen_cells.add(cell_id)
        pair_id = _text(cell["pair_id"], f"schedule.cells[{index}].pair_id")
        if pair_id not in expected_pairs:
            raise OwnedPairPilotError("schedule cell refers to an unknown pair")
        label = _text(cell["control_label"], f"schedule.cells[{index}].control_label")
        control = controls_by_label.get(label)
        if (
            control is None
            or cell["control_role"] != control["role"]
            or cell["control_archive_sha256"] != control["archive_sha256"]
        ):
            raise OwnedPairPilotError("schedule cell control archive mismatch")
        seed = _positive_int(cell["seed"], f"schedule.cells[{index}].seed")
        if cell["seat"] not in _SEATS:
            raise OwnedPairPilotError("schedule cell seat is invalid")
        schedule_key = (pair_id, label, seed, cell["seat"])
        if schedule_key in seen_schedule_keys:
            raise OwnedPairPilotError("design schedule contains a duplicate matchup cell")
        seen_schedule_keys.add(schedule_key)
        pair_cell_counts[pair_id] += 1
        pair_roles[pair_id].add(control["role"])
        pair_seats[pair_id].add(cell["seat"])
        observed_seeds.add(seed)
    if len(seen_cells) != expected_count:
        raise OwnedPairPilotError("design schedule cells are not unique")
    if any(count != local_quota for count in pair_cell_counts.values()):
        raise OwnedPairPilotError("design schedule has the wrong per-pair cell count")
    if any(roles != _REQUIRED_CONTROL_ROLES for roles in pair_roles.values()):
        raise OwnedPairPilotError("every pair must cover all required control roles")
    if any(seats != set(_SEATS) for seats in pair_seats.values()):
        raise OwnedPairPilotError("every pair must cover both seats")
    expected_schedule_keys = {
        (pair_id, control_label, seed, seat)
        for pair_id in expected_pairs
        for control_label in controls_by_label
        for seed in observed_seeds
        for seat in _SEATS
    }
    if seen_schedule_keys != expected_schedule_keys:
        raise OwnedPairPilotError("design schedule is not the exact pair/control/seed/seat Cartesian product")
    if local_quota != len(controls_by_label) * len(observed_seeds) * len(_SEATS):
        raise OwnedPairPilotError("design local quota does not match the exact Cartesian schedule")
    if schedule["seed_root_sha256"] != canonical_sha256(sorted(observed_seeds)):
        raise OwnedPairPilotError("design schedule seed root is not derived from its cells")
    if _assert_root(design, "design_root_sha256", "design") != design["design_root_sha256"]:
        raise OwnedPairPilotError("design root mismatch")
    if frozen.tzinfo is None:  # defensive; _timestamp always returns aware values
        raise OwnedPairPilotError("design timestamp is not UTC")
    return design


def _design_indexes(design: Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    pairs = {item["pair_id"]: item for item in design["pairs"]}
    cells = {item["cell_id"]: item for item in design["schedule"]["cells"]}
    return pairs, cells


def validate_local_results(value: object, design_value: object, activation_value: object | None = None) -> dict[str, Any]:
    """Validate complete, error-free local ``L(A)`` output for the frozen schedule."""

    design = validate_design_freeze(design_value)
    fields = frozenset(
        {
            "schema", "protocol_id", "mode", "design_root_sha256", "local_started_at_utc",
            "local_completed_at_utc", "reproducibility", "rows", "local_result_root_sha256",
        }
    )
    local = _common_header(value, LOCAL_SCHEMA, fields, "local result")
    if local["design_root_sha256"] != design["design_root_sha256"]:
        raise OwnedPairPilotError("local result does not bind design root")
    design_time = _timestamp(design["design_frozen_at_utc"], "design.design_frozen_at_utc")
    local_start = _timestamp(local["local_started_at_utc"], "local.local_started_at_utc")
    local_end = _timestamp(local["local_completed_at_utc"], "local.local_completed_at_utc")
    if local_start <= design_time or local_end < local_start:
        raise OwnedPairPilotError("local execution is not after design freeze or is out of order")

    reproducibility = _exact(
        local["reproducibility"],
        frozenset(
            {
                "primary_panel_sha256", "repeat_panel_sha256",
                "semantic_rows_sha256", "semantic_reproduction_equal",
            }
        ),
        "local.reproducibility",
    )
    _sha(reproducibility["primary_panel_sha256"], "local.reproducibility.primary_panel_sha256")
    _sha(reproducibility["repeat_panel_sha256"], "local.reproducibility.repeat_panel_sha256")
    _sha(reproducibility["semantic_rows_sha256"], "local.reproducibility.semantic_rows_sha256")
    if reproducibility["semantic_reproduction_equal"] is not True:
        raise OwnedPairPilotError("local result requires exact semantic reproduction")

    pairs, cells = _design_indexes(design)
    rows = local["rows"]
    expected = len(cells)
    if type(rows) is not list or len(rows) != expected:
        raise OwnedPairPilotError("local result does not close the exact schedule")
    row_fields = frozenset(
        {
            "cell_id", "pair_id", "submission_ref", "submission_id", "archive_sha256",
            "control_label", "control_role", "control_archive_sha256", "seed", "seat", "started_at_utc",
            "completed_at_utc", "transcript_sha256", "terminal_outcome", "error", "metrics",
        }
    )
    seen: set[str] = set()
    metric_names = design["metrics"]
    for index, row_value in enumerate(rows):
        row = _exact(row_value, row_fields, f"local.rows[{index}]")
        cell_id = _text(row["cell_id"], f"local.rows[{index}].cell_id")
        if cell_id in seen:
            raise OwnedPairPilotError("local result contains duplicate cells")
        seen.add(cell_id)
        if cell_id not in cells:
            raise OwnedPairPilotError("local result contains an unscheduled cell")
        cell = cells[cell_id]
        pair = pairs[cell["pair_id"]]
        if (
            row["pair_id"] != pair["pair_id"]
            or row["submission_ref"] != pair["submission_ref"]
            or row["submission_id"] != pair["submission_id"]
            or row["archive_sha256"] != pair["archive_sha256"]
            or row["control_label"] != cell["control_label"]
            or row["control_role"] != cell["control_role"]
            or row["control_archive_sha256"] != cell["control_archive_sha256"]
            or row["seed"] != cell["seed"]
            or row["seat"] != cell["seat"]
        ):
            raise OwnedPairPilotError("local row does not bind its exact schedule identity")
        started = _timestamp(row["started_at_utc"], f"local.rows[{index}].started_at_utc")
        completed = _timestamp(row["completed_at_utc"], f"local.rows[{index}].completed_at_utc")
        if started < local_start or completed < started or completed > local_end or started <= design_time:
            raise OwnedPairPilotError("local row timestamp is outside the frozen local phase")
        _sha(row["transcript_sha256"], f"local.rows[{index}].transcript_sha256")
        if row["terminal_outcome"] not in _TERMINAL_OUTCOMES or row["error"] is not None:
            raise OwnedPairPilotError("local row does not have a clean terminal outcome")
        metrics = _exact(row["metrics"], frozenset(metric_names), f"local.rows[{index}].metrics")
        for metric, metric_value in metrics.items():
            if type(metric_value) not in {int, str, bool} or type(metric_value) is float:
                raise OwnedPairPilotError(f"local metric {metric} must not be a float")
    if seen != set(cells):
        raise OwnedPairPilotError("local result omits one or more scheduled cells")
    _assert_root(local, "local_result_root_sha256", "local result")
    if activation_value is not None:
        activation = validate_activation_freeze(activation_value, design, local)
        if local_end >= _timestamp(activation["activation_frozen_at_utc"], "activation.activation_frozen_at_utc"):
            raise OwnedPairPilotError("local result is not complete before activation freeze")
    return local


def validate_activation_freeze(value: object, design_value: object, local_value: object) -> dict[str, Any]:
    """Validate the second freeze, which binds completed local output and ``T0``."""

    design = validate_design_freeze(design_value)
    local = validate_local_results(local_value, design)
    fields = frozenset(
        {
            "schema", "protocol_id", "mode", "design_root_sha256", "local_result_root_sha256",
            "activation_frozen_at_utc", "t0_utc", "activation_root_sha256",
        }
    )
    activation = _common_header(value, ACTIVATION_SCHEMA, fields, "activation")
    if activation["design_root_sha256"] != design["design_root_sha256"] or activation["local_result_root_sha256"] != local["local_result_root_sha256"]:
        raise OwnedPairPilotError("activation does not bind exact design and local roots")
    local_end = _timestamp(local["local_completed_at_utc"], "local.local_completed_at_utc")
    frozen = _timestamp(activation["activation_frozen_at_utc"], "activation.activation_frozen_at_utc")
    t0 = _timestamp(activation["t0_utc"], "activation.t0_utc")
    if local_end >= frozen or frozen >= t0:
        raise OwnedPairPilotError("activation freeze must follow local completion and precede T0")
    _assert_root(activation, "activation_root_sha256", "activation")
    return activation


def _hosted_row(value: object, label: str) -> dict[str, Any]:
    row = _exact(
        value,
        frozenset(
            {
                "pair_id", "submission_ref", "submission_id", "archive_sha256", "episode_id",
                "created_at_utc", "started_at_utc", "ended_at_utc", "outcome", "seat",
                "agent_status", "runtime_or_package_failure", "source_sha256",
            }
        ),
        label,
    )
    _text(row["pair_id"], f"{label}.pair_id")
    _text(row["submission_ref"], f"{label}.submission_ref")
    _text(row["submission_id"], f"{label}.submission_id")
    _sha(row["archive_sha256"], f"{label}.archive_sha256")
    _text(row["episode_id"], f"{label}.episode_id")
    created = _timestamp(row["created_at_utc"], f"{label}.created_at_utc")
    started = _timestamp(row["started_at_utc"], f"{label}.started_at_utc")
    ended = _timestamp(row["ended_at_utc"], f"{label}.ended_at_utc")
    if not created <= started < ended:
        raise OwnedPairPilotError(f"{label} timestamps are not ordered")
    if row["outcome"] not in _TERMINAL_OUTCOMES:
        raise OwnedPairPilotError(f"{label}.outcome must be WIN, LOSS, or DRAW")
    if row["seat"] not in _SEATS:
        raise OwnedPairPilotError(f"{label}.seat is invalid")
    status = _text(row["agent_status"], f"{label}.agent_status")
    if status not in _ALLOWED_AGENT_STATUSES:
        raise OwnedPairPilotError(f"{label}.agent_status is not a supported canonical status")
    failure = _bool(row["runtime_or_package_failure"], f"{label}.runtime_or_package_failure")
    if failure != (status != "DONE"):
        raise OwnedPairPilotError(f"{label} runtime/package failure flag disagrees with agent status")
    if failure and row["outcome"] == "WIN":
        raise OwnedPairPilotError(f"{label} cannot record a runtime/package failure as a win")
    _sha(row["source_sha256"], f"{label}.source_sha256")
    return row


def _hosted_sort_key(row: Mapping[str, Any]) -> tuple[datetime, str]:
    return (
        _timestamp(row["ended_at_utc"], "hosted.ended_at_utc"),
        row["episode_id"],
    )


def validate_hosted_results(value: object, design_value: object, activation_value: object, local_value: object) -> dict[str, Any]:
    """Validate only the literal earliest post-``T0`` hosted inventory prefix."""

    design = validate_design_freeze(design_value)
    local = validate_local_results(local_value, design)
    activation = validate_activation_freeze(activation_value, design, local)
    _reject_hosted_forbidden(value)
    fields = frozenset(
        {
            "schema", "protocol_id", "mode", "design_root_sha256", "activation_root_sha256",
            "exhaustive_inventory", "exhaustive_inventory_root_sha256", "rows", "hosted_result_root_sha256",
        }
    )
    hosted = _common_header(value, HOSTED_SCHEMA, fields, "hosted result")
    if hosted["design_root_sha256"] != design["design_root_sha256"] or hosted["activation_root_sha256"] != activation["activation_root_sha256"]:
        raise OwnedPairPilotError("hosted result does not bind exact design and activation roots")
    inventory_raw = hosted["exhaustive_inventory"]
    rows_raw = hosted["rows"]
    if type(inventory_raw) is not list or type(rows_raw) is not list:
        raise OwnedPairPilotError("hosted inventory and rows must be lists")
    inventory = [_hosted_row(item, f"hosted.exhaustive_inventory[{index}]") for index, item in enumerate(inventory_raw)]
    rows = [_hosted_row(item, f"hosted.rows[{index}]") for index, item in enumerate(rows_raw)]
    _sha(hosted["exhaustive_inventory_root_sha256"], "hosted.exhaustive_inventory_root_sha256")
    if hosted["exhaustive_inventory_root_sha256"] != canonical_sha256(inventory):
        raise OwnedPairPilotError("exhaustive inventory root mismatch")
    _assert_root(hosted, "hosted_result_root_sha256", "hosted result")

    pairs, _ = _design_indexes(design)
    quota = design["quotas"]["hosted_future_episodes_per_pair"]
    inventory_ids: set[str] = set()
    for index, row in enumerate(inventory):
        if row["episode_id"] in inventory_ids:
            raise OwnedPairPilotError("hosted inventory contains duplicate episode IDs")
        inventory_ids.add(row["episode_id"])
        if row["pair_id"] not in pairs:
            raise OwnedPairPilotError("hosted inventory refers to an unknown pair")
        pair = pairs[row["pair_id"]]
        if row["submission_ref"] != pair["submission_ref"] or row["submission_id"] != pair["submission_id"] or row["archive_sha256"] != pair["archive_sha256"]:
            raise OwnedPairPilotError("hosted inventory row does not bind exact archive identity")
        t0 = _timestamp(activation["t0_utc"], "activation.t0_utc")
        if any(
            timestamp <= t0
            for timestamp in (
                _timestamp(row["created_at_utc"], "hosted.created_at_utc"),
                _timestamp(row["started_at_utc"], "hosted.started_at_utc"),
                _timestamp(row["ended_at_utc"], "hosted.ended_at_utc"),
            )
        ):
            raise OwnedPairPilotError("hosted inventory contains a pre-T0 row")
        if index and _hosted_sort_key(inventory[index - 1]) > _hosted_sort_key(row):
            raise OwnedPairPilotError("exhaustive inventory is not chronological")

    expected_rows: list[dict[str, Any]] = []
    for pair_id in sorted(pairs):
        candidates = sorted((row for row in inventory if row["pair_id"] == pair_id), key=_hosted_sort_key)
        if len(candidates) < quota:
            raise OwnedPairPilotError("exhaustive inventory does not contain the hosted quota")
        expected_rows.extend(candidates[:quota])
    expected_rows.sort(key=lambda row: (row["pair_id"], _hosted_sort_key(row)))
    actual_rows = sorted(rows, key=lambda row: (row["pair_id"], _hosted_sort_key(row)))
    if actual_rows != expected_rows:
        raise OwnedPairPilotError("hosted rows are not the exact earliest chronological prefix")
    if len(rows) != len(pairs) * quota:
        raise OwnedPairPilotError("hosted result does not close the future quota")
    return hosted


def validate_rehearsal(design: object, local: object, activation: object, hosted: object) -> dict[str, Any]:
    """Validate every phase and return a canonical, permanently zero-authority receipt."""

    checked_design = validate_design_freeze(design)
    checked_local = validate_local_results(local, checked_design)
    checked_activation = validate_activation_freeze(activation, checked_design, checked_local)
    checked_hosted = validate_hosted_results(hosted, checked_design, checked_activation, checked_local)
    receipt: dict[str, Any] = {
        "schema": REHEARSAL_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "mode": MODE,
        "decision": COMPLETE,
        "scientific_disposition": SCIENTIFIC_DISPOSITION,
        "scientific_blockers": list(SCIENTIFIC_BLOCKERS),
        "design_root_sha256": checked_design["design_root_sha256"],
        "local_result_root_sha256": checked_local["local_result_root_sha256"],
        "activation_root_sha256": checked_activation["activation_root_sha256"],
        "hosted_result_root_sha256": checked_hosted["hosted_result_root_sha256"],
        "production_blockers": list(_PRODUCTION_BLOCKERS),
        "authority": False,
        "candidate_development_authorized": False,
        "predictive_validity_authorized": False,
        "sealed_holdout_access": False,
        "holdout_access_authorized": False,
        "submission_authorized": False,
    }
    receipt["receipt_root_sha256"] = canonical_sha256(receipt)
    return receipt


def validate_json_file(path: str | Path, *, kind: str = "rehearsal", design: str | Path | None = None, local: str | Path | None = None, activation: str | Path | None = None, hosted: str | Path | None = None) -> dict[str, Any]:
    """Validate JSON files for the CLI and return the canonical result."""

    def load(source: str | Path, label: str) -> object:
        try:
            raw = Path(source).read_bytes()
            return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey) as exc:
            raise OwnedPairPilotError(f"{label} is not valid JSON: {exc}") from exc

    if kind == "design":
        return validate_design_freeze(load(path, "design"))
    if kind == "local":
        if design is None:
            raise OwnedPairPilotError("--design is required for local validation")
        return validate_local_results(load(path, "local"), load(design, "design"))
    if kind == "activation":
        if design is None or local is None:
            raise OwnedPairPilotError("--design and --local are required for activation validation")
        return validate_activation_freeze(load(path, "activation"), load(design, "design"), load(local, "local"))
    if kind == "hosted":
        if design is None or local is None or activation is None:
            raise OwnedPairPilotError("--design, --local, and --activation are required for hosted validation")
        return validate_hosted_results(load(path, "hosted"), load(design, "design"), load(activation, "activation"), load(local, "local"))
    if kind == "rehearsal":
        design_source = design if design is not None else path
        if local is None or activation is None or hosted is None:
            raise OwnedPairPilotError("all four phase files are required for rehearsal validation")
        return validate_rehearsal(load(design_source, "design"), load(local, "local"), load(activation, "activation"), load(hosted, "hosted"))
    raise OwnedPairPilotError(f"unknown validation kind: {kind}")


def canonical_json(value: object) -> str:
    """Serialize a protocol value using the repository's canonical JSON helper."""

    _reject_floats(value)
    _reject_authority_text(value)
    return canonical_json_bytes(value).decode("ascii")


# Short aliases make the phase boundaries pleasant to use from small scripts.
validate_design = validate_design_freeze
validate_local = validate_local_results
validate_activation = validate_activation_freeze
validate_hosted = validate_hosted_results
validate_protocol = validate_rehearsal


def main(argv: Sequence[str] | None = None) -> int:
    if argv is not None:
        argv = [str(item) for item in argv]
    parser = argparse.ArgumentParser(description="Validate a zero-authority owned-pair rehearsal")
    parser.add_argument("kind", choices=("design", "local", "activation", "hosted", "rehearsal"))
    parser.add_argument("path", type=Path, help="JSON artifact to validate; rehearsal uses --design as its design file")
    parser.add_argument("--design", type=Path)
    parser.add_argument("--local", type=Path)
    parser.add_argument("--activation", type=Path)
    parser.add_argument("--hosted", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_json_file(args.path, kind=args.kind, design=args.design, local=args.local, activation=args.activation, hosted=args.hosted)
    except OwnedPairPilotError as exc:
        print(json.dumps({"decision": INCOMPLETE, "error": str(exc)}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through subprocesses
    raise SystemExit(main())


__all__ = [
    "ACTIVATION_SCHEMA", "COMPLETE", "DESIGN_SCHEMA", "HOSTED_SCHEMA", "INCOMPLETE", "LOCAL_SCHEMA",
    "MODE", "OwnedPairPilotError", "PROTOCOL_ID", "REHEARSAL_SCHEMA", "add_canonical_root",
    "canonical_json", "main", "validate_activation", "validate_activation_freeze", "validate_design",
    "validate_design_freeze", "validate_hosted", "validate_hosted_results", "validate_json_file",
    "validate_local", "validate_local_results", "validate_protocol", "validate_rehearsal",
]
