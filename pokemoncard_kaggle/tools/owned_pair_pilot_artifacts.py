#!/usr/bin/env python3
"""Compose canonical artifacts for the zero-authority owned-pair pilot.

The composer is deliberately narrower than a production gate.  It expands an
already-frozen preregistration, verifies two deterministic local panels agree
after removing wall-clock timing, and creates phase-bound receipts accepted by
``evaluation_v5_1.owned_pair_pilot``.  Every emitted artifact remains
development-only and can never authorize candidate work, holdout access, or a
submission.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256  # noqa: E402
from evaluation_v5_1.owned_pair_pilot import (  # noqa: E402
    ACTIVATION_SCHEMA,
    DESIGN_SCHEMA,
    HOSTED_SCHEMA,
    LOCAL_SCHEMA,
    MODE,
    PROTOCOL_ID,
    OwnedPairPilotError,
    add_canonical_root,
    validate_activation_freeze,
    validate_design_freeze,
    validate_hosted_results,
    validate_local_results,
)


FORBIDDEN_HOSTED_FIELDS = [
    "hosted_outcome",
    "hosted_rank",
    "hosted_score",
    "kaggle_rank",
    "kaggle_score",
    "leaderboard_rank",
    "leaderboard_score",
    "public_outcome",
    "public_rank",
    "public_score",
]
BLOCKER_REASONS = {
    "common_ancestry": "the two owned archives share development ancestry",
    "external_collector_unavailable": "no independent authenticated external collector is available",
    "only_two_units": "two owned archive units cannot establish production transfer validity",
    "prior_hosted_history": "both owned archives had hosted exposure before this pilot",
}
BASELINE_SCHEMA = "evaluation_v5_1_owned_pair_baseline_inventory_v1"
FUTURE_INVENTORY_SCHEMA = "evaluation_v5_1_owned_pair_future_inventory_v1"
BASELINE_FIELDS = frozenset(
    {
        "schema", "protocol_id", "mode", "design_root_sha256", "activation_root_sha256",
        "t0_utc", "collected_at_utc", "collector", "inventories", "authority",
        "candidate_development_authorized", "sealed_holdout_access",
        "holdout_access_authorized", "submission_authorized", "baseline_root_sha256",
    }
)
BASELINE_INVENTORY_FIELDS = frozenset(
    {
        "pair_id", "submission_ref", "submission_id", "archive_sha256", "query_inventory",
        "query_inventory_root_sha256", "completed_public_count", "pre_t0_public_episode_ids",
        "future_metadata_episode_ids",
    }
)
FUTURE_ARTIFACT_FIELDS = frozenset(
    {
        "schema", "protocol_id", "mode", "design_root_sha256", "activation_root_sha256",
        "baseline_root_sha256", "inventory_observation_root_sha256", "collected_at_utc",
        "start_time_derivation", "rows", "authority", "candidate_development_authorized",
        "sealed_holdout_access", "holdout_access_authorized", "submission_authorized",
        "future_inventory_root_sha256",
    }
)
FUTURE_ROW_FIELDS = frozenset(
    {
        "pair_id", "submission_ref", "submission_id", "archive_sha256", "episode_id",
        "created_at_utc", "started_at_utc", "ended_at_utc", "outcome", "seat",
        "agent_status", "runtime_or_package_failure", "source_sha256",
    }
)
ALLOWED_AGENT_STATUSES = frozenset(
    {"CRASHED", "DONE", "ERROR", "FAILED", "INVALID", "PACKAGE_ERROR", "RUNTIME_ERROR", "TIMEOUT"}
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArtifactComposerError(ValueError):
    """Raised when source material cannot support a canonical pilot artifact."""


class _DuplicateKey(ValueError):
    pass


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey) as exc:
        raise ArtifactComposerError(f"invalid JSON in {path}: {exc}") from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_file_sha(path: Path, expected: str, label: str) -> None:
    actual = _file_sha256(path)
    if actual != expected:
        raise ArtifactComposerError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _utc_from_ns(value: Any) -> str:
    if type(value) is not int or value <= 0 or value % 1000:
        raise ArtifactComposerError("frozen nanosecond timestamp must be a positive whole microsecond")
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    return (
        datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{nanoseconds // 1000:06d}Z"
    )


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json_bytes(value) + b"\n")
    temporary.replace(path)


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _parse_timestamp(value: str) -> datetime:
    if type(value) is not str or not value:
        raise ArtifactComposerError(f"invalid episode timestamp: {value!r}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ArtifactComposerError(f"invalid episode timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _enum_tail(value: str) -> str:
    return value.rsplit(".", 1)[-1].upper()


def _is_completed_public(row: dict[str, str]) -> bool:
    return _enum_tail(row["state"]) == "COMPLETED" and _enum_tail(row["type"]) in {
        "EPISODE_TYPE_PUBLIC",
        "PUBLIC",
    }


def _validate_episode_rows(
    rows: Any,
    *,
    label: str,
    collected_at: datetime | None = None,
) -> list[dict[str, str]]:
    required = {"id", "createTime", "endTime", "state", "type"}
    if type(rows) is not list:
        raise ArtifactComposerError(f"{label} must be a list")
    ids: list[str] = []
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != required:
            raise ArtifactComposerError(f"{label} row {index} has an unexpected schema")
        if any(type(row[field]) is not str or not row[field] for field in required):
            raise ArtifactComposerError(f"{label} row {index} has an empty or non-string field")
        created = _parse_timestamp(row["createTime"])
        ended = _parse_timestamp(row["endTime"])
        if created >= ended:
            raise ArtifactComposerError(f"{label} row {index} timestamps are not ordered")
        if collected_at is not None and ended > collected_at:
            raise ArtifactComposerError(f"{label} row {index} ends after collected_at_utc")
        ids.append(row["id"])
    if len(ids) != len(set(ids)):
        raise ArtifactComposerError(f"{label} has duplicate episode IDs")
    ordered = sorted(rows, key=lambda row: (_parse_timestamp(row["endTime"]), row["id"]))
    if rows != ordered:
        raise ArtifactComposerError(f"{label} is not ordered by end time and episode ID")
    return rows


def _canonical_agent_status(value: Any, *, episode_id: str) -> str:
    if type(value) is not str or not value.strip():
        raise ArtifactComposerError(f"replay agent status is invalid for episode {episode_id}")
    status = _enum_tail(value.strip())
    if status not in ALLOWED_AGENT_STATUSES:
        raise ArtifactComposerError(f"replay agent status is unsupported for episode {episode_id}")
    return status


def _episode_csv(output: str) -> list[dict[str, str]]:
    lines = output.splitlines()
    header = next((index for index, line in enumerate(lines) if line.startswith("id,")), None)
    if header is None:
        raise ArtifactComposerError("Kaggle episodes output has no CSV header")
    csv_lines = [lines[header]]
    for line in lines[header + 1 :]:
        if not line.strip():
            break
        csv_lines.append(line)
    rows = list(csv.DictReader(io.StringIO("\n".join(csv_lines))))
    required = {"id", "createTime", "endTime", "state", "type"}
    if not rows or any(set(row) != required for row in rows):
        raise ArtifactComposerError("Kaggle episodes output has an unexpected schema")
    normalized = [
        {key: (row.get(key) or "").strip() for key in ("id", "createTime", "endTime", "state", "type")}
        for row in rows
    ]
    ordered = sorted(normalized, key=lambda row: (_parse_timestamp(row["endTime"]), row["id"]))
    return _validate_episode_rows(ordered, label="Kaggle episodes inventory")


def _fetch_episode_csv(submission_ref: str) -> str:
    result = subprocess.run(
        ["uv", "run", "kaggle", "competitions", "episodes", "-v", submission_ref],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ArtifactComposerError(result.stderr.strip() or result.stdout.strip() or "Kaggle episodes query failed")
    return result.stdout


def build_design(
    preregistration_path: Path,
    sources_path: Path,
    *,
    repository_root: Path = ROOT,
) -> dict[str, Any]:
    """Expand the frozen preliminary design without inspecting local outcomes."""

    preregistration_path = preregistration_path.resolve()
    sources_path = sources_path.resolve()
    prereg = _load(preregistration_path)
    sources_payload = _load(sources_path)
    if prereg.get("schema") != "owned_pair_development_design_v1":
        raise ArtifactComposerError("unsupported preliminary preregistration schema")
    if sources_payload.get("schema") != "public_transfer_sources_v1":
        raise ArtifactComposerError("unsupported source configuration schema")
    for field in ("authority", "candidate_development_authorized", "sealed_holdout_access_authorized", "submission_authorized"):
        if prereg.get(field) is not False:
            raise ArtifactComposerError(f"preliminary preregistration must set {field}=false")

    evaluator = prereg.get("local_evaluator")
    if type(evaluator) is not dict:
        raise ArtifactComposerError("preliminary preregistration has no local evaluator")
    expected_sources_sha = evaluator.get("source_config_sha256")
    if type(expected_sources_sha) is not str:
        raise ArtifactComposerError("source configuration hash is missing")
    _require_file_sha(sources_path, expected_sources_sha, "source configuration")

    source_rows = sources_payload.get("sources")
    if type(source_rows) is not list:
        raise ArtifactComposerError("source configuration must contain a source list")
    sources_by_archive = {str(row.get("archive_path")): row for row in source_rows if type(row) is dict}
    units = prereg.get("units")
    if type(units) is not list or len(units) != 2:
        raise ArtifactComposerError("preliminary preregistration must contain exactly two units")
    pairs: list[dict[str, Any]] = []
    for unit in units:
        if type(unit) is not dict:
            raise ArtifactComposerError("unit is not an object")
        archive_path = str(unit.get("archive_path"))
        source = sources_by_archive.get(archive_path)
        if source is None:
            raise ArtifactComposerError(f"unit archive {archive_path} is not in the source configuration")
        label = str(source.get("label"))
        archive_sha = str(unit.get("archive_sha256"))
        _require_file_sha(_resolve(repository_root, archive_path), archive_sha, f"pair archive {label}")
        submission_ref = str(source.get("submission_ref"))
        if submission_ref != str(unit.get("submission_id")):
            raise ArtifactComposerError(f"submission reference mismatch for {label}")
        pairs.append(
            {
                "pair_id": label,
                "archive_identity": {"archive_id": archive_path, "archive_label": label},
                "submission_ref": submission_ref,
                "submission_id": submission_ref,
                "archive_sha256": archive_sha,
                "active": True,
            }
        )
    pairs.sort(key=lambda row: row["pair_id"])

    controls_raw = prereg.get("controls")
    if type(controls_raw) is not list:
        raise ArtifactComposerError("preliminary preregistration must contain controls")
    controls: list[dict[str, Any]] = []
    for control in controls_raw:
        if type(control) is not dict:
            raise ArtifactComposerError("control is not an object")
        archive_path = str(control.get("archive_path"))
        archive_sha = str(control.get("archive_sha256"))
        _require_file_sha(_resolve(repository_root, archive_path), archive_sha, f"control archive {archive_path}")
        controls.append(
            {
                "control_label": str(control.get("label")),
                "role": str(control.get("role")),
                "archive_id": archive_path,
                "archive_sha256": archive_sha,
            }
        )
    controls.sort(key=lambda row: row["control_label"])

    seeds = evaluator.get("seeds")
    seats = evaluator.get("seats")
    if type(seeds) is not list or any(type(seed) is not int or seed <= 0 for seed in seeds):
        raise ArtifactComposerError("frozen seeds are invalid")
    if seats != [0, 1]:
        raise ArtifactComposerError("frozen seats must be [0, 1]")
    cells: list[dict[str, Any]] = []
    for pair in pairs:
        for control in controls:
            for seed in seeds:
                for seat in seats:
                    cells.append(
                        {
                            "cell_id": f"{pair['pair_id']}:{control['control_label']}:{seed}:{seat}",
                            "pair_id": pair["pair_id"],
                            "control_label": control["control_label"],
                            "control_role": control["role"],
                            "control_archive_sha256": control["archive_sha256"],
                            "seed": seed,
                            "seat": seat,
                        }
                    )
    local_cells_per_pair = len(controls) * len(seeds) * len(seats)
    if evaluator.get("required_cells_per_unit") != local_cells_per_pair:
        raise ArtifactComposerError("expanded schedule does not match preregistered local cell quota")

    manifest_id = str(evaluator.get("engine_manifest_path"))
    manifest_path = _resolve(repository_root, manifest_id)
    runner_path = _resolve(repository_root, str(evaluator.get("runner_path")))
    _require_file_sha(manifest_path, str(evaluator.get("engine_manifest_sha256")), "engine manifest")
    _require_file_sha(runner_path, str(evaluator.get("runner_sha256")), "evaluator runner")
    engine_manifest = _load(manifest_path)
    engine_library = manifest_path.parent / "cg" / "libcg.so"
    _require_file_sha(engine_library, str(evaluator.get("engine_library_sha256")), "engine library")

    future = prereg.get("future_hosted_protocol")
    if type(future) is not dict:
        raise ArtifactComposerError("future hosted protocol is missing")
    design = add_canonical_root(
        {
            "schema": DESIGN_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_frozen_at_utc": _utc_from_ns(prereg.get("design_frozen_at_ns")),
            "pre_registration_sha256": _file_sha256(preregistration_path),
            "pairs": pairs,
            "controls": controls,
            "deterministic_engine": {
                "manifest_id": manifest_id,
                "manifest_sha256": _file_sha256(manifest_path),
            },
            "evaluator_runner_sha256": _file_sha256(runner_path),
            "schedule": {
                "seed_root_sha256": canonical_sha256(sorted(set(seeds))),
                "seats": seats,
                "control_labels": [row["control_label"] for row in controls],
                "cells": cells,
            },
            "metrics": ["steps"],
            "quotas": {
                "local_cells_per_pair": local_cells_per_pair,
                "hosted_future_episodes_per_pair": int(future.get("required_games_per_unit")),
            },
            "forbidden_hosted_fields": FORBIDDEN_HOSTED_FIELDS,
            "production_blockers": {
                key: {"terminal": True, "reason": reason}
                for key, reason in BLOCKER_REASONS.items()
            },
        },
        "design_root_sha256",
    )
    if engine_manifest.get("libcg_sha256") != evaluator.get("engine_library_sha256"):
        raise ArtifactComposerError("engine manifest does not bind the preregistered library")
    return validate_design_freeze(design)


def _panel_semantics(panel: Any) -> dict[str, Any]:
    if type(panel) is not dict or panel.get("schema") != "seeded_transfer_feature_panel_v1":
        raise ArtifactComposerError("unsupported deterministic panel schema")
    if panel.get("complete") is not True or panel.get("errors") != 0:
        raise ArtifactComposerError("deterministic panel is incomplete or has errors")
    rows_raw = panel.get("rows")
    if type(rows_raw) is not list:
        raise ArtifactComposerError("deterministic panel has no rows")
    fields = (
        "anchor", "control", "seed", "anchor_left", "left", "right",
        "winner", "steps", "error", "transcript_sha256",
    )
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(rows_raw):
        if type(row) is not dict or any(field not in row for field in fields):
            raise ArtifactComposerError(f"panel row {index} lacks a semantic field")
        rows.append({field: row[field] for field in fields})
    rows.sort(key=lambda row: (row["anchor"], row["control"], row["seed"], row["anchor_left"]))
    return {
        "schema": panel["schema"],
        "engine_manifest": panel.get("engine_manifest"),
        "baseline_label": panel.get("baseline_label"),
        "seeds": panel.get("seeds"),
        "controls": panel.get("controls"),
        "source_identities": panel.get("source_identities"),
        "rows": rows,
    }


def build_local(
    design_path: Path,
    primary_panel_path: Path,
    repeat_panel_path: Path,
    *,
    started_at_utc: str,
    completed_at_utc: str,
    repository_root: Path = ROOT,
) -> dict[str, Any]:
    """Bind two semantically identical deterministic panels into a local receipt."""

    design = validate_design_freeze(_load(design_path))
    primary = _load(primary_panel_path)
    repeat = _load(repeat_panel_path)
    primary_semantics = _panel_semantics(primary)
    repeat_semantics = _panel_semantics(repeat)
    if primary_semantics != repeat_semantics:
        raise ArtifactComposerError("primary and repeat panels are not semantically identical")

    manifest_path = _resolve(repository_root, design["deterministic_engine"]["manifest_id"])
    if primary_semantics["engine_manifest"] != _load(manifest_path):
        raise ArtifactComposerError("panel engine manifest does not match frozen design")
    if primary_semantics["controls"] != design["schedule"]["control_labels"]:
        raise ArtifactComposerError("panel control labels do not match frozen design")
    observed_seeds = sorted({cell["seed"] for cell in design["schedule"]["cells"]})
    if primary_semantics["seeds"] != observed_seeds:
        raise ArtifactComposerError("panel seeds do not match frozen design")

    pairs = {pair["pair_id"]: pair for pair in design["pairs"]}
    source_identities = primary_semantics["source_identities"]
    if type(source_identities) is not dict:
        raise ArtifactComposerError("panel source identities are missing")
    for pair_id, pair in pairs.items():
        identity = source_identities.get(pair_id)
        if type(identity) is not dict or identity.get("archive_sha256") != pair["archive_sha256"]:
            raise ArtifactComposerError(f"panel source identity does not bind {pair_id}")

    panel_by_key: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    for row in primary_semantics["rows"]:
        if row["anchor_left"] not in (0, 1):
            raise ArtifactComposerError("panel anchor_left must be 0 or 1")
        seat = 0 if row["anchor_left"] == 1 else 1
        key = (str(row["anchor"]), str(row["control"]), int(row["seed"]), seat)
        if key in panel_by_key:
            raise ArtifactComposerError("panel contains a duplicate schedule row")
        panel_by_key[key] = row

    local_rows: list[dict[str, Any]] = []
    for cell in design["schedule"]["cells"]:
        key = (cell["pair_id"], cell["control_label"], cell["seed"], cell["seat"])
        row = panel_by_key.get(key)
        if row is None:
            raise ArtifactComposerError(f"panel omits schedule cell {cell['cell_id']}")
        pair = pairs[cell["pair_id"]]
        anchor_left = cell["seat"] == 0
        expected_left = cell["pair_id"] if anchor_left else cell["control_label"]
        expected_right = cell["control_label"] if anchor_left else cell["pair_id"]
        if row["left"] != expected_left or row["right"] != expected_right:
            raise ArtifactComposerError(f"panel seat mapping is inconsistent for {cell['cell_id']}")
        if row["error"] is not None or row["winner"] not in (0, 1, 2):
            raise ArtifactComposerError(f"panel row is not a clean terminal game for {cell['cell_id']}")
        if type(row["steps"]) is not int or row["steps"] <= 0:
            raise ArtifactComposerError(f"panel steps are invalid for {cell['cell_id']}")
        winner_label = None if row["winner"] == 2 else (row["left"] if row["winner"] == 0 else row["right"])
        terminal_outcome = "DRAW" if winner_label is None else ("WIN" if winner_label == cell["pair_id"] else "LOSS")
        local_rows.append(
            {
                "cell_id": cell["cell_id"],
                "pair_id": pair["pair_id"],
                "submission_ref": pair["submission_ref"],
                "submission_id": pair["submission_id"],
                "archive_sha256": pair["archive_sha256"],
                "control_label": cell["control_label"],
                "control_role": cell["control_role"],
                "control_archive_sha256": cell["control_archive_sha256"],
                "seed": cell["seed"],
                "seat": cell["seat"],
                "started_at_utc": started_at_utc,
                "completed_at_utc": completed_at_utc,
                "transcript_sha256": row["transcript_sha256"],
                "terminal_outcome": terminal_outcome,
                "error": None,
                "metrics": {"steps": row["steps"]},
            }
        )
    if len(panel_by_key) != len(local_rows):
        raise ArtifactComposerError("panel contains rows outside the frozen schedule")

    local = add_canonical_root(
        {
            "schema": LOCAL_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_root_sha256": design["design_root_sha256"],
            "local_started_at_utc": started_at_utc,
            "local_completed_at_utc": completed_at_utc,
            "reproducibility": {
                "primary_panel_sha256": _file_sha256(primary_panel_path),
                "repeat_panel_sha256": _file_sha256(repeat_panel_path),
                "semantic_rows_sha256": canonical_sha256(primary_semantics),
                "semantic_reproduction_equal": True,
            },
            "rows": local_rows,
        },
        "local_result_root_sha256",
    )
    return validate_local_results(local, design)


def build_activation(
    design_path: Path,
    local_path: Path,
    *,
    activation_frozen_at_utc: str,
    t0_utc: str,
) -> dict[str, Any]:
    design = validate_design_freeze(_load(design_path))
    local = validate_local_results(_load(local_path), design)
    activation = add_canonical_root(
        {
            "schema": ACTIVATION_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_root_sha256": design["design_root_sha256"],
            "local_result_root_sha256": local["local_result_root_sha256"],
            "activation_frozen_at_utc": activation_frozen_at_utc,
            "t0_utc": t0_utc,
        },
        "activation_root_sha256",
    )
    return validate_activation_freeze(activation, design, local)


def collect_baseline_inventory(
    design_path: Path,
    local_path: Path,
    activation_path: Path,
    *,
    collected_at_utc: str,
    episode_fetcher: Any = _fetch_episode_csv,
) -> dict[str, Any]:
    """Bind the authenticated episode inventory observed immediately after T0."""

    design = validate_design_freeze(_load(design_path))
    local = validate_local_results(_load(local_path), design)
    activation = validate_activation_freeze(_load(activation_path), design, local)
    collected = _parse_timestamp(collected_at_utc)
    t0 = _parse_timestamp(activation["t0_utc"])
    if collected <= t0:
        raise ArtifactComposerError("baseline inventory must be collected after T0")
    inventories: list[dict[str, Any]] = []
    for pair in design["pairs"]:
        rows = _episode_csv(episode_fetcher(pair["submission_ref"]))
        _validate_episode_rows(rows, label=f"inventory for {pair['pair_id']}", collected_at=collected)
        public = [row for row in rows if _is_completed_public(row)]
        pre_t0 = [
            row
            for row in public
            if _parse_timestamp(row["createTime"]) <= t0 or _parse_timestamp(row["endTime"]) <= t0
        ]
        future_metadata = [row for row in public if row not in pre_t0]
        inventories.append(
            {
                "pair_id": pair["pair_id"],
                "submission_ref": pair["submission_ref"],
                "submission_id": pair["submission_id"],
                "archive_sha256": pair["archive_sha256"],
                "query_inventory": rows,
                "query_inventory_root_sha256": canonical_sha256(rows),
                "completed_public_count": len(public),
                "pre_t0_public_episode_ids": [row["id"] for row in pre_t0],
                "future_metadata_episode_ids": [row["id"] for row in future_metadata],
            }
        )
    baseline = add_canonical_root(
        {
            "schema": BASELINE_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_root_sha256": design["design_root_sha256"],
            "activation_root_sha256": activation["activation_root_sha256"],
            "t0_utc": activation["t0_utc"],
            "collected_at_utc": collected_at_utc,
            "collector": "authenticated_kaggle_cli_single_collector",
            "inventories": inventories,
            "authority": False,
            "candidate_development_authorized": False,
            "sealed_holdout_access": False,
            "holdout_access_authorized": False,
            "submission_authorized": False,
        },
        "baseline_root_sha256",
    )
    return baseline


def _assert_content_root(value: dict[str, Any], field: str, label: str) -> None:
    actual = value.get(field)
    expected = canonical_sha256({key: item for key, item in value.items() if key != field})
    if actual != expected:
        raise ArtifactComposerError(f"{label} canonical root mismatch")


def _snapshot_by_pair(
    value: Any,
    design: dict[str, Any],
    activation: dict[str, Any],
    *,
    label: str,
) -> dict[str, dict[str, Any]]:
    if type(value) is not dict or set(value) != BASELINE_FIELDS or value.get("schema") != BASELINE_SCHEMA:
        raise ArtifactComposerError(f"{label} has an unsupported inventory schema")
    _assert_content_root(value, "baseline_root_sha256", label)
    if (
        value.get("protocol_id") != PROTOCOL_ID
        or value.get("mode") != MODE
        or value.get("design_root_sha256") != design["design_root_sha256"]
        or value.get("activation_root_sha256") != activation["activation_root_sha256"]
        or value.get("t0_utc") != activation["t0_utc"]
    ):
        raise ArtifactComposerError(f"{label} does not bind the frozen design and activation")
    for field in (
        "authority", "candidate_development_authorized", "sealed_holdout_access",
        "holdout_access_authorized", "submission_authorized",
    ):
        if value.get(field) is not False:
            raise ArtifactComposerError(f"{label} must set {field}=false")
    inventories = value.get("inventories")
    if type(inventories) is not list or len(inventories) != len(design["pairs"]):
        raise ArtifactComposerError(f"{label} has the wrong inventory count")
    result: dict[str, dict[str, Any]] = {}
    pairs = {pair["pair_id"]: pair for pair in design["pairs"]}
    t0 = _parse_timestamp(activation["t0_utc"])
    collected_value = value.get("collected_at_utc")
    if type(collected_value) is not str:
        raise ArtifactComposerError(f"{label} collected_at_utc is missing")
    collected = _parse_timestamp(collected_value)
    if collected <= t0:
        raise ArtifactComposerError(f"{label} must be collected after T0")
    if value.get("collector") != "authenticated_kaggle_cli_single_collector":
        raise ArtifactComposerError(f"{label} collector identity is invalid")
    for inventory in inventories:
        if type(inventory) is not dict or set(inventory) != BASELINE_INVENTORY_FIELDS:
            raise ArtifactComposerError(f"{label} inventory has an unexpected schema")
        pair_id = inventory.get("pair_id")
        if pair_id not in pairs or pair_id in result:
            raise ArtifactComposerError(f"{label} has an unknown or duplicate pair")
        pair = pairs[pair_id]
        if (
            inventory.get("submission_ref") != pair["submission_ref"]
            or inventory.get("submission_id") != pair["submission_id"]
            or inventory.get("archive_sha256") != pair["archive_sha256"]
        ):
            raise ArtifactComposerError(f"{label} inventory does not bind exact pair {pair_id}")
        rows = inventory.get("query_inventory")
        if type(rows) is not list or inventory.get("query_inventory_root_sha256") != canonical_sha256(rows):
            raise ArtifactComposerError(f"{label} query inventory root mismatch for {pair_id}")
        _validate_episode_rows(rows, label=f"{label} query inventory for {pair_id}", collected_at=collected)
        completed_public = [row for row in rows if _is_completed_public(row)]
        pre_t0 = [
            row
            for row in completed_public
            if _parse_timestamp(row["createTime"]) <= t0 or _parse_timestamp(row["endTime"]) <= t0
        ]
        future = [row for row in completed_public if row not in pre_t0]
        if inventory.get("completed_public_count") != len(completed_public):
            raise ArtifactComposerError(f"{label} completed count mismatch for {pair_id}")
        if inventory.get("pre_t0_public_episode_ids") != [row["id"] for row in pre_t0]:
            raise ArtifactComposerError(f"{label} pre-T0 identity mismatch for {pair_id}")
        if inventory.get("future_metadata_episode_ids") != [row["id"] for row in future]:
            raise ArtifactComposerError(f"{label} future identity mismatch for {pair_id}")
        result[pair_id] = inventory
    return result


def _canonical_utc(value: str) -> str:
    return _parse_timestamp(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _download_replay(episode_id: str, replay_dir: Path) -> Path:
    target = replay_dir / f"episode-{episode_id}-replay.json"
    if target.exists():
        return target
    replay_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["uv", "run", "kaggle", "competitions", "replay", "-q", "-p", str(replay_dir), episode_id],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode or not target.exists():
        detail = result.stderr.strip() or result.stdout.strip() or "replay file missing"
        raise ArtifactComposerError(f"could not download replay {episode_id}: {detail}")
    return target


def _replay_row(
    metadata: dict[str, str],
    pair: dict[str, Any],
    replay_path: Path,
    *,
    team: str,
) -> dict[str, Any]:
    replay = _load(replay_path)
    info = replay.get("info")
    if type(info) is not dict or str(info.get("EpisodeId")) != metadata["id"]:
        raise ArtifactComposerError(f"replay identity mismatch for episode {metadata['id']}")
    teams = info.get("TeamNames")
    if (
        type(teams) is not list
        or len(teams) != 2
        or any(type(item) is not str or not item for item in teams)
        or len(set(teams)) != 2
        or teams.count(team) != 1
    ):
        raise ArtifactComposerError(f"replay team identity mismatch for episode {metadata['id']}")
    seat = teams.index(team)
    rewards = replay.get("rewards")
    if (
        type(rewards) is not list
        or len(rewards) != 2
        or any(type(reward) is not int or reward not in (-1, 0, 1) for reward in rewards)
    ):
        raise ArtifactComposerError(f"replay reward is invalid for episode {metadata['id']}")
    outcome = {-1: "LOSS", 0: "DRAW", 1: "WIN"}[rewards[seat]]
    statuses = replay.get("statuses")
    if type(statuses) is not list or len(statuses) != 2:
        raise ArtifactComposerError(f"replay terminal statuses are invalid for episode {metadata['id']}")
    canonical_statuses = [
        _canonical_agent_status(value, episode_id=metadata["id"])
        for value in statuses
    ]
    status = canonical_statuses[seat]
    runtime_or_package_failure = status != "DONE"
    if runtime_or_package_failure and outcome == "WIN":
        raise ArtifactComposerError(f"runtime/package failure cannot be a win for episode {metadata['id']}")
    created = _canonical_utc(metadata["createTime"])
    ended = _canonical_utc(metadata["endTime"])
    return {
        "pair_id": pair["pair_id"],
        "submission_ref": pair["submission_ref"],
        "submission_id": pair["submission_id"],
        "archive_sha256": pair["archive_sha256"],
        "episode_id": metadata["id"],
        "created_at_utc": created,
        "started_at_utc": created,
        "ended_at_utc": ended,
        "outcome": outcome,
        "seat": seat,
        "agent_status": status,
        "runtime_or_package_failure": runtime_or_package_failure,
        "source_sha256": _file_sha256(replay_path),
    }


def _validate_future_artifact(
    value: Any,
    design: dict[str, Any],
    activation: dict[str, Any],
    baseline: dict[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != FUTURE_ARTIFACT_FIELDS or value.get("schema") != FUTURE_INVENTORY_SCHEMA:
        raise ArtifactComposerError(f"{label} has an unsupported schema")
    _assert_content_root(value, "future_inventory_root_sha256", label)
    if (
        value.get("protocol_id") != PROTOCOL_ID
        or value.get("mode") != MODE
        or value.get("design_root_sha256") != design["design_root_sha256"]
        or value.get("activation_root_sha256") != activation["activation_root_sha256"]
        or value.get("baseline_root_sha256") != baseline["baseline_root_sha256"]
        or value.get("start_time_derivation") != "started_at_utc_equals_authenticated_createTime"
    ):
        raise ArtifactComposerError(f"{label} does not bind the frozen pilot")
    observation_root = value.get("inventory_observation_root_sha256")
    if type(observation_root) is not str or SHA256_RE.fullmatch(observation_root) is None:
        raise ArtifactComposerError(f"{label} observation root is invalid")
    for field in (
        "authority", "candidate_development_authorized", "sealed_holdout_access",
        "holdout_access_authorized", "submission_authorized",
    ):
        if value.get(field) is not False:
            raise ArtifactComposerError(f"{label} must set {field}=false")
    collected_value = value.get("collected_at_utc")
    if type(collected_value) is not str:
        raise ArtifactComposerError(f"{label} collected_at_utc is missing")
    collected = _parse_timestamp(collected_value)
    t0 = _parse_timestamp(activation["t0_utc"])
    pairs = {pair["pair_id"]: pair for pair in design["pairs"]}
    rows = value.get("rows")
    if type(rows) is not list:
        raise ArtifactComposerError(f"{label} rows must be a list")
    seen_ids: set[str] = set()
    previous_key: tuple[datetime, str] | None = None
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != FUTURE_ROW_FIELDS:
            raise ArtifactComposerError(f"{label} row {index} has an unexpected schema")
        pair = pairs.get(row.get("pair_id"))
        if pair is None or any(
            row.get(field) != pair[field]
            for field in ("submission_ref", "submission_id", "archive_sha256")
        ):
            raise ArtifactComposerError(f"{label} row {index} does not bind an exact pair")
        episode_id = row.get("episode_id")
        if type(episode_id) is not str or not episode_id or episode_id in seen_ids:
            raise ArtifactComposerError(f"{label} has a missing or duplicate episode ID")
        seen_ids.add(episode_id)
        created = _parse_timestamp(row.get("created_at_utc"))
        started = _parse_timestamp(row.get("started_at_utc"))
        ended = _parse_timestamp(row.get("ended_at_utc"))
        if created != started or not t0 < created < ended <= collected:
            raise ArtifactComposerError(f"{label} row {index} timestamps are invalid")
        if row.get("outcome") not in {"DRAW", "LOSS", "WIN"} or row.get("seat") not in {0, 1}:
            raise ArtifactComposerError(f"{label} row {index} outcome or seat is invalid")
        status = row.get("agent_status")
        failure = row.get("runtime_or_package_failure")
        if status not in ALLOWED_AGENT_STATUSES or type(failure) is not bool or failure != (status != "DONE"):
            raise ArtifactComposerError(f"{label} row {index} status/failure semantics are invalid")
        if failure and row["outcome"] == "WIN":
            raise ArtifactComposerError(f"{label} row {index} cannot record a failed win")
        if type(row.get("source_sha256")) is not str or SHA256_RE.fullmatch(row["source_sha256"]) is None:
            raise ArtifactComposerError(f"{label} row {index} source hash is invalid")
        key = (ended, episode_id)
        if previous_key is not None and previous_key > key:
            raise ArtifactComposerError(f"{label} rows are not chronological")
        previous_key = key
    return value


def build_future_inventory(
    design_path: Path,
    local_path: Path,
    activation_path: Path,
    baseline_path: Path,
    observation_path: Path,
    *,
    replay_dirs: dict[str, Path],
    team: str = "GarlicToday",
    previous_path: Path | None = None,
) -> dict[str, Any]:
    """Normalize every literal post-T0 replay without inspecting a favorable subset."""

    design = validate_design_freeze(_load(design_path))
    local = validate_local_results(_load(local_path), design)
    activation = validate_activation_freeze(_load(activation_path), design, local)
    baseline = _load(baseline_path)
    observation = _load(observation_path)
    baseline_by_pair = _snapshot_by_pair(baseline, design, activation, label="baseline")
    observation_by_pair = _snapshot_by_pair(observation, design, activation, label="observation")
    if _parse_timestamp(observation["collected_at_utc"]) <= _parse_timestamp(baseline["collected_at_utc"]):
        raise ArtifactComposerError("inventory observation must follow the baseline collection")
    t0 = _parse_timestamp(activation["t0_utc"])
    rows: list[dict[str, Any]] = []
    for pair in design["pairs"]:
        pair_id = pair["pair_id"]
        if pair_id not in replay_dirs:
            raise ArtifactComposerError(f"missing replay directory for {pair_id}")
        baseline_inventory = baseline_by_pair[pair_id]
        current_inventory = observation_by_pair[pair_id]
        if current_inventory["pre_t0_public_episode_ids"] != baseline_inventory["pre_t0_public_episode_ids"]:
            raise ArtifactComposerError(f"pre-T0 inventory changed for {pair_id}")
        future_ids = set(current_inventory["future_metadata_episode_ids"])
        metadata_rows = [
            row
            for row in current_inventory["query_inventory"]
            if row["id"] in future_ids
        ]
        metadata_rows.sort(key=lambda row: (_parse_timestamp(row["endTime"]), row["id"]))
        if [row["id"] for row in metadata_rows] != current_inventory["future_metadata_episode_ids"]:
            raise ArtifactComposerError(f"future metadata order changed for {pair_id}")
        for metadata in metadata_rows:
            if _parse_timestamp(metadata["createTime"]) <= t0 or _parse_timestamp(metadata["endTime"]) <= t0:
                raise ArtifactComposerError(f"future metadata is not strictly post-T0 for {pair_id}")
            replay_path = _download_replay(metadata["id"], replay_dirs[pair_id])
            rows.append(_replay_row(metadata, pair, replay_path, team=team))
    rows.sort(key=lambda row: (row["ended_at_utc"], row["episode_id"]))

    if previous_path is not None:
        previous = _validate_future_artifact(
            _load(previous_path),
            design,
            activation,
            baseline,
            label="previous future inventory",
        )
        previous_rows = previous.get("rows")
        if type(previous_rows) is not list or rows[: len(previous_rows)] != previous_rows:
            raise ArtifactComposerError("future inventory is not append-only")

    artifact = add_canonical_root(
        {
            "schema": FUTURE_INVENTORY_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_root_sha256": design["design_root_sha256"],
            "activation_root_sha256": activation["activation_root_sha256"],
            "baseline_root_sha256": baseline["baseline_root_sha256"],
            "inventory_observation_root_sha256": observation["baseline_root_sha256"],
            "collected_at_utc": observation["collected_at_utc"],
            "start_time_derivation": "started_at_utc_equals_authenticated_createTime",
            "rows": rows,
            "authority": False,
            "candidate_development_authorized": False,
            "sealed_holdout_access": False,
            "holdout_access_authorized": False,
            "submission_authorized": False,
        },
        "future_inventory_root_sha256",
    )
    return _validate_future_artifact(
        artifact,
        design,
        activation,
        baseline,
        label="future inventory",
    )


def build_hosted(
    design_path: Path,
    local_path: Path,
    activation_path: Path,
    inventory_path: Path,
) -> dict[str, Any]:
    """Freeze the literal earliest complete post-T0 quota from an exhaustive inventory."""

    design = validate_design_freeze(_load(design_path))
    local = validate_local_results(_load(local_path), design)
    activation = validate_activation_freeze(_load(activation_path), design, local)
    payload = _load(inventory_path)
    inventory = payload.get("rows") if type(payload) is dict else payload
    if type(inventory) is not list:
        raise ArtifactComposerError("hosted inventory must be a list or an object with rows")
    inventory = sorted(inventory, key=lambda row: (row["ended_at_utc"], row["episode_id"]))
    quota = design["quotas"]["hosted_future_episodes_per_pair"]
    selected: list[dict[str, Any]] = []
    for pair in design["pairs"]:
        rows = [row for row in inventory if row.get("pair_id") == pair["pair_id"]]
        if len(rows) < quota:
            raise ArtifactComposerError(f"hosted quota is incomplete for {pair['pair_id']}: {len(rows)}/{quota}")
        selected.extend(rows[:quota])
    hosted = add_canonical_root(
        {
            "schema": HOSTED_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "mode": MODE,
            "design_root_sha256": design["design_root_sha256"],
            "activation_root_sha256": activation["activation_root_sha256"],
            "exhaustive_inventory": inventory,
            "exhaustive_inventory_root_sha256": canonical_sha256(inventory),
            "rows": selected,
        },
        "hosted_result_root_sha256",
    )
    return validate_hosted_results(hosted, design, activation, local)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    design_parser = subparsers.add_parser("design")
    design_parser.add_argument("--pre-registration", type=Path, required=True)
    design_parser.add_argument("--sources", type=Path, required=True)
    design_parser.add_argument("--output", type=Path, required=True)

    local_parser = subparsers.add_parser("local")
    local_parser.add_argument("--design", type=Path, required=True)
    local_parser.add_argument("--primary", type=Path, required=True)
    local_parser.add_argument("--repeat", type=Path, required=True)
    local_parser.add_argument("--started-at", required=True)
    local_parser.add_argument("--completed-at", required=True)
    local_parser.add_argument("--output", type=Path, required=True)

    activation_parser = subparsers.add_parser("activation")
    activation_parser.add_argument("--design", type=Path, required=True)
    activation_parser.add_argument("--local", type=Path, required=True)
    activation_parser.add_argument("--activation-frozen-at", required=True)
    activation_parser.add_argument("--t0", required=True)
    activation_parser.add_argument("--output", type=Path, required=True)

    baseline_parser = subparsers.add_parser("baseline")
    baseline_parser.add_argument("--design", type=Path, required=True)
    baseline_parser.add_argument("--local", type=Path, required=True)
    baseline_parser.add_argument("--activation", type=Path, required=True)
    baseline_parser.add_argument("--collected-at", required=True)
    baseline_parser.add_argument("--output", type=Path, required=True)

    future_parser = subparsers.add_parser("future")
    future_parser.add_argument("--design", type=Path, required=True)
    future_parser.add_argument("--local", type=Path, required=True)
    future_parser.add_argument("--activation", type=Path, required=True)
    future_parser.add_argument("--baseline", type=Path, required=True)
    future_parser.add_argument("--observation", type=Path, required=True)
    future_parser.add_argument("--replay-dir", action="append", required=True)
    future_parser.add_argument("--team", default="GarlicToday")
    future_parser.add_argument("--previous", type=Path)
    future_parser.add_argument("--output", type=Path, required=True)

    hosted_parser = subparsers.add_parser("hosted")
    hosted_parser.add_argument("--design", type=Path, required=True)
    hosted_parser.add_argument("--local", type=Path, required=True)
    hosted_parser.add_argument("--activation", type=Path, required=True)
    hosted_parser.add_argument("--inventory", type=Path, required=True)
    hosted_parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "design":
            artifact = build_design(args.pre_registration, args.sources)
        elif args.command == "local":
            artifact = build_local(
                args.design,
                args.primary,
                args.repeat,
                started_at_utc=args.started_at,
                completed_at_utc=args.completed_at,
            )
        elif args.command == "activation":
            artifact = build_activation(
                args.design,
                args.local,
                activation_frozen_at_utc=args.activation_frozen_at,
                t0_utc=args.t0,
            )
        elif args.command == "baseline":
            artifact = collect_baseline_inventory(
                args.design,
                args.local,
                args.activation,
                collected_at_utc=args.collected_at,
            )
        elif args.command == "future":
            replay_dirs: dict[str, Path] = {}
            for item in args.replay_dir:
                if "=" not in item:
                    raise ArtifactComposerError("--replay-dir must be PAIR_ID=PATH")
                pair_id, raw_path = item.split("=", 1)
                if not pair_id or pair_id in replay_dirs:
                    raise ArtifactComposerError("--replay-dir pair IDs must be nonempty and unique")
                replay_dirs[pair_id] = Path(raw_path)
            artifact = build_future_inventory(
                args.design,
                args.local,
                args.activation,
                args.baseline,
                args.observation,
                replay_dirs=replay_dirs,
                team=args.team,
                previous_path=args.previous,
            )
        else:
            artifact = build_hosted(args.design, args.local, args.activation, args.inventory)
        _write(args.output, artifact)
    except (ArtifactComposerError, OwnedPairPilotError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output), "sha256": _file_sha256(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
