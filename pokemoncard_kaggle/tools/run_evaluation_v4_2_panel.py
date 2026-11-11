#!/usr/bin/env python3
"""Run the process-isolated evaluation v4.2 simulation panel.

The checkpoint written by this tool is deliberately a raw-row receipt.  It is
not a panel and never contains derived features.  A validated panel and its
features are written only after the complete engine/opponent/seed/seat grid
has finished without an execution error.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.package import sha256_file  # noqa: E402
from evaluation_v2.cohort import deck_sha256  # noqa: E402
from evaluation_v2.public_transfer import (  # noqa: E402
    ArchivePolicyIdentity,
    archive_policy_identity,
    materialize_historical_archive,
)
from evaluation_v2.seeded_arena import (  # noqa: E402
    ArenaEntry,
    load_entry_isolated,
    load_seeded_game,
    run_seeded_game,
)
from evaluation_v4_2.simulation_design import (  # noqa: E402
    SEATS,
    build_candidate_panel,
    canonical_sha256,
    compile_candidate_features,
    validate_simulation_template,
)
from evaluation_v4_2.runtime_binding import (  # noqa: E402
    RuntimeBindingError,
    validate_runtime_binding_file,
)
from evaluation_v4_2.contrast_protocol import (  # noqa: E402
    ContrastProtocolError,
    load_contrast_protocol,
)
from evaluation_v4_2.candidate_binding import (  # noqa: E402
    CandidateBindingError,
    load_candidate_binding_file,
)
from evaluation_v4_2.opponent_roster import (  # noqa: E402
    OpponentRosterError,
    audit_opponent_roster,
)


RAW_CHECKPOINT_SCHEMA = "evaluation_v4_2_raw_panel_checkpoint_v1"
WORKER_SCHEMA = "evaluation_v4_2_cell_result_v1"
ARM_WORKER_SCHEMA = "evaluation_v4_2_arm_result_v1"
EXECUTION_SOURCE_SCHEMA = "evaluation_v4_2_execution_sources_v1"
DEFAULT_MAX_STEPS = 600
DEFAULT_TIMEOUT_SECONDS = 900.0
EXECUTION_SOURCE_FIELDS = frozenset(
    {
        "schema",
        "protocol_path",
        "scientific_plan_path",
        "dependency_lock_path",
        "runtime_binding_path",
    }
)
OPPONENT_SOURCE_SCHEMA = "evaluation_v4_2_opponent_execution_sources_v1"
OPPONENT_SOURCE_FIELDS = frozenset(
    {
        "schema",
        "sources",
        "roster_receipt_path",
        "ontology_path",
        "leaderboard_snapshot_path",
        "identities_path",
    }
)
RAW_ROW_FIELDS = frozenset(
    {
        "engine_id",
        "opponent_id",
        "seed",
        "seat",
        "candidate_outcome",
        "baseline_outcome",
        "candidate_runtime_seconds",
        "baseline_runtime_seconds",
        "candidate_error",
        "baseline_error",
    }
)


class RunnerError(RuntimeError):
    """The runner cannot produce a complete, identity-bound panel."""


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RunnerError(f"could not read JSON {path}: {exc}") from exc


def _resolve_manifest_path(value: object, *, manifest: Path, label: str) -> Path:
    if not isinstance(value, str) or not value.strip() or value.strip() != value:
        raise RunnerError(f"{label} must be a non-empty path string")
    path = Path(value).expanduser()
    return (manifest.parent / path).resolve() if not path.is_absolute() else path.resolve()


def _unwrap_mapping(payload: object, *, keys: tuple[str, ...], label: str) -> Mapping[str, Any]:
    if isinstance(payload, Mapping):
        for key in keys:
            if key in payload:
                value = payload[key]
                if not isinstance(value, Mapping):
                    raise RunnerError(f"{label}.{key} must be an object")
                return value
        return payload
    raise RunnerError(f"{label} must be an object")


def _identity_dict(identity: ArchivePolicyIdentity) -> dict[str, str]:
    return asdict(identity)


def _archive_identity(path: Path, *, label: str) -> ArchivePolicyIdentity:
    if not path.is_file():
        raise RunnerError(f"{label} archive does not exist: {path}")
    try:
        return archive_policy_identity(path)
    except Exception as exc:
        raise RunnerError(f"invalid {label} archive {path}: {exc}") from exc


def _materialized_policy_identity(path: Path, *, label: str) -> dict[str, str]:
    digest = hashlib.sha256()
    main_bytes: bytes | None = None
    deck_bytes: bytes | None = None
    members: list[tuple[str, Path]] = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise RunnerError(f"{label} contains a symlink: {item}")
        if not item.is_file():
            continue
        relative = item.relative_to(path).as_posix()
        parts = Path(relative).parts
        if not parts or parts[0] == "cg" or "__pycache__" in parts or relative.endswith((".pyc", ".pyo")):
            continue
        members.append((relative, item))
    for relative, item in sorted(members):
        data = item.read_bytes()
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        if relative == "main.py":
            main_bytes = data
        elif relative == "deck.csv":
            deck_bytes = data
    if main_bytes is None or deck_bytes is None:
        raise RunnerError(f"{label} lacks main.py or deck.csv")
    try:
        cards = tuple(
            int(line.strip())
            for line in deck_bytes.decode("utf-8-sig").splitlines()
            if line.strip()
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RunnerError(f"{label} deck.csv is invalid: {exc}") from exc
    if len(cards) != 60:
        raise RunnerError(f"{label} deck has {len(cards)} cards")
    return {
        "policy_content_sha256": digest.hexdigest(),
        "main_sha256": hashlib.sha256(main_bytes).hexdigest(),
        "deck_sha256": deck_sha256(cards),
    }


def _verify_materialized_archive(
    snapshot: Path,
    destination: Path,
    expected: Mapping[str, str],
    *,
    label: str,
) -> None:
    if sha256_file(snapshot) != expected["archive_sha256"]:
        raise RunnerError(f"{label} archive identity mismatch after materialization")
    actual = _materialized_policy_identity(destination, label=label)
    semantic_expected = {key: expected[key] for key in actual}
    if actual != semantic_expected:
        raise RunnerError(
            f"{label} materialized policy/deck identity mismatch: "
            f"expected={semantic_expected} actual={actual}"
        )


def directory_tree_sha256(path: Path) -> str:
    """Hash every regular file in one engine runtime tree, including its path."""

    root = path.resolve()
    if not root.is_dir():
        raise RunnerError(f"runtime tree does not exist: {root}")
    records: list[dict[str, str]] = []
    for item in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        if item.is_symlink():
            raise RunnerError(f"runtime tree contains a symlink: {item}")
        if item.is_file():
            records.append(
                {
                    "path": item.relative_to(root).as_posix(),
                    "sha256": sha256_file(item),
                }
            )
    if not records:
        raise RunnerError(f"runtime tree contains no files: {root}")
    return hashlib.sha256(
        json.dumps(records, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _write_exclusive_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise RunnerError(f"snapshot destination already exists: {path}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _snapshot_file(source: Path, destination: Path, *, label: str) -> Path:
    if source.is_symlink() or not source.is_file():
        raise RunnerError(f"{label} source must be a regular file: {source}")
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise RunnerError(f"could not read {label} source {source}: {exc}") from exc
    _write_exclusive_bytes(destination, data)
    return destination


def _snapshot_tree(source: Path, destination: Path, *, label: str) -> Path:
    if source.is_symlink() or not source.is_dir():
        raise RunnerError(f"{label} source must be a regular directory: {source}")
    destination.mkdir(parents=True, exist_ok=False)
    copied = 0
    for item in sorted(source.rglob("*"), key=lambda value: value.relative_to(source).as_posix()):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise RunnerError(f"{label} source contains a symlink: {item}")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            _snapshot_file(item, target, label=label)
            copied += 1
        else:
            raise RunnerError(f"{label} source contains a non-regular entry: {item}")
    if copied == 0:
        raise RunnerError(f"{label} source contains no files: {source}")
    return destination


def load_execution_sources(
    manifest_path: Path, template: Mapping[str, Any]
) -> tuple[dict[str, str], dict[str, Any]]:
    """Verify every non-roster execution artifact bound by the template."""

    payload = _json(manifest_path)
    if not isinstance(payload, Mapping) or set(payload) != EXECUTION_SOURCE_FIELDS:
        raise RunnerError(
            f"execution source manifest fields must exactly be {sorted(EXECUTION_SOURCE_FIELDS)}"
        )
    if payload.get("schema") != EXECUTION_SOURCE_SCHEMA:
        raise RunnerError(f"execution source manifest schema must be {EXECUTION_SOURCE_SCHEMA!r}")
    source_fields = {
        "protocol_sha256": "protocol_path",
        "scientific_plan_sha256": "scientific_plan_path",
        "dependency_lock_sha256": "dependency_lock_path",
        "runtime_binding_sha256": "runtime_binding_path",
    }
    verified: dict[str, str] = {}
    contrast_protocol: dict[str, Any] | None = None
    for digest_field, path_field in source_fields.items():
        path = _resolve_manifest_path(
            payload[path_field], manifest=manifest_path, label=f"execution source {path_field}"
        )
        if not path.is_file():
            raise RunnerError(f"execution source does not exist: {path}")
        actual = sha256_file(path)
        expected = str(template[digest_field])
        if actual != expected:
            raise RunnerError(
                f"execution source hash mismatch for {digest_field}: expected={expected} actual={actual}"
            )
        verified[digest_field] = actual
        if digest_field == "protocol_sha256":
            try:
                contrast_protocol = load_contrast_protocol(path)
            except ContrastProtocolError as exc:
                raise RunnerError(f"contrast protocol validation failed: {exc}") from exc
        if digest_field == "runtime_binding_sha256":
            try:
                validate_runtime_binding_file(path)
            except RuntimeBindingError as exc:
                raise RunnerError(f"runtime binding validation failed: {exc}") from exc
    runner_actual = sha256_file(Path(__file__).resolve())
    runner_expected = str(template["runner_code_sha256"])
    if runner_actual != runner_expected:
        raise RunnerError(
            f"runner code hash mismatch: expected={runner_expected} actual={runner_actual}"
        )
    verified["runner_code_sha256"] = runner_actual
    if contrast_protocol is None:
        raise RunnerError("execution sources omitted the contrast protocol")
    verified["contrast_protocol_content_sha256"] = str(
        contrast_protocol["content_sha256"]
    )
    return verified, contrast_protocol


def load_opponent_sources(
    manifest_path: Path, template: Mapping[str, Any]
) -> tuple[dict[str, Path], dict[str, dict[str, str]], str]:
    """Resolve and identity-check the exact archive for every template opponent."""

    payload = _json(manifest_path)
    if not isinstance(payload, Mapping) or set(payload) != OPPONENT_SOURCE_FIELDS:
        raise RunnerError(
            f"opponent execution manifest fields must exactly be {sorted(OPPONENT_SOURCE_FIELDS)}"
        )
    if payload.get("schema") != OPPONENT_SOURCE_SCHEMA:
        raise RunnerError(f"opponent execution manifest schema must be {OPPONENT_SOURCE_SCHEMA!r}")
    mapping = payload["sources"]
    if not isinstance(mapping, Mapping):
        raise RunnerError("opponent execution manifest sources must be an object")
    evidence_paths = {
        key: _resolve_manifest_path(payload[key], manifest=manifest_path, label=key)
        for key in (
            "roster_receipt_path",
            "ontology_path",
            "leaderboard_snapshot_path",
            "identities_path",
        )
    }
    try:
        roster = audit_opponent_roster(
            _json(evidence_paths["roster_receipt_path"]),
            _json(evidence_paths["ontology_path"]),
            _json(evidence_paths["leaderboard_snapshot_path"]),
            _json(evidence_paths["identities_path"]),
        )
    except OpponentRosterError as exc:
        raise RunnerError(f"opponent roster evidence failed: {exc}") from exc
    roster_projection = [
        {key: value for key, value in row.items() if key != "main_sha256"}
        for row in roster["opponent_roster"]
    ]
    if roster_projection != template["opponent_roster"]:
        raise RunnerError("template opponent roster differs from exact source derivation")
    expected = {
        str(row["opponent_id"]): {
            "archive_sha256": str(row["archive_sha256"]),
            "policy_content_sha256": str(row["policy_content_sha256"]),
            "deck_sha256": str(row["deck_sha256"]),
        }
        for row in template["opponent_roster"]
    }
    if set(mapping) != set(expected):
        raise RunnerError(
            "opponent manifest ids must exactly match template: "
            f"missing={sorted(set(expected) - set(mapping))} "
            f"extra={sorted(set(mapping) - set(expected))}"
        )
    paths: dict[str, Path] = {}
    identities: dict[str, dict[str, str]] = {}
    for opponent_id in sorted(expected):
        raw = mapping[opponent_id]
        if isinstance(raw, Mapping):
            raw = raw.get("archive_path", raw.get("path"))
        path = _resolve_manifest_path(raw, manifest=manifest_path, label=f"opponent {opponent_id}")
        identity = _archive_identity(path, label=f"opponent {opponent_id}")
        identity_fields = _identity_dict(identity)
        actual_identity = {key: identity_fields[key] for key in expected[opponent_id]}
        if actual_identity != expected[opponent_id]:
            raise RunnerError(
                f"opponent {opponent_id} archive/policy/deck identity mismatch: "
                f"expected={expected[opponent_id]} actual={actual_identity}"
            )
        paths[opponent_id] = path
        identities[opponent_id] = actual_identity
    return paths, identities, str(roster["content_sha256"])


def load_engine_sources(
    manifest_path: Path, template: Mapping[str, Any]
) -> tuple[dict[str, Path], dict[str, dict[str, str]]]:
    """Resolve and hash-check each complete engine runtime tree."""

    mapping = _unwrap_mapping(_json(manifest_path), keys=("engines", "engine_dirs"), label="engine manifest")
    expected = {
        str(row["engine_id"]): {
            "binary_sha256": str(row["binary_sha256"]),
            "runtime_tree_sha256": str(row["runtime_tree_sha256"]),
        }
        for row in template["engine_roster"]
    }
    if set(mapping) != set(expected):
        raise RunnerError(
            "engine manifest ids must exactly match template: "
            f"missing={sorted(set(expected) - set(mapping))} "
            f"extra={sorted(set(mapping) - set(expected))}"
        )
    paths: dict[str, Path] = {}
    identities: dict[str, dict[str, str]] = {}
    for engine_id in sorted(expected):
        raw = mapping[engine_id]
        if isinstance(raw, Mapping):
            raw = raw.get("engine_dir", raw.get("path"))
        path = _resolve_manifest_path(raw, manifest=manifest_path, label=f"engine {engine_id}")
        binary = path / "cg" / "libcg.so"
        if not path.is_dir() or not binary.is_file():
            raise RunnerError(f"engine {engine_id} is missing directory or cg/libcg.so: {path}")
        actual_binary = sha256_file(binary)
        actual_tree = directory_tree_sha256(path)
        actual = {
            "binary_sha256": actual_binary,
            "runtime_tree_sha256": actual_tree,
        }
        if actual != expected[engine_id]:
            raise RunnerError(
                f"engine {engine_id} runtime identity mismatch: "
                f"expected={expected[engine_id]} actual={actual}"
            )
        paths[engine_id] = path
        identities[engine_id] = actual
    return paths, identities


def _task_key(task: Mapping[str, Any]) -> tuple[str, str, int, str]:
    return (str(task["engine_id"]), str(task["opponent_id"]), int(task["seed"]), str(task["seat"]))


def _row_key(row: Mapping[str, Any]) -> tuple[str, str, int, str]:
    return (str(row["engine_id"]), str(row["opponent_id"]), int(row["seed"]), str(row["seat"]))


def build_tasks(
    template: Mapping[str, Any],
    *,
    engine_dirs: Mapping[str, Path],
    opponent_dirs: Mapping[str, Path],
    candidate_dir: Path,
    baseline_dir: Path,
    completed: set[tuple[str, str, int, str]] | None = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    max_action_seconds: float = 9.0,
) -> list[dict[str, Any]]:
    """Build one process-isolated task for each missing terminal cell."""

    completed = completed or set()
    tasks: list[dict[str, Any]] = []
    for engine in template["engine_roster"]:
        engine_id = str(engine["engine_id"])
        for opponent in template["opponent_roster"]:
            opponent_id = str(opponent["opponent_id"])
            for seed in template["seeds"]:
                for seat in SEATS:
                    task = {
                        "engine_id": engine_id,
                        "engine_dir": str(engine_dirs[engine_id]),
                        "opponent_id": opponent_id,
                        "opponent_dir": str(opponent_dirs[opponent_id]),
                        "candidate_dir": str(candidate_dir),
                        "baseline_dir": str(baseline_dir),
                        "seed": int(seed),
                        "seat": seat,
                        "max_steps": int(max_steps),
                        "max_action_seconds": float(max_action_seconds),
                    }
                    if _task_key(task) not in completed:
                        tasks.append(task)
    return tasks


def _outcome(result: Mapping[str, Any], *, policy_label: str) -> tuple[float | None, str | None]:
    error = result.get("error")
    if error is not None:
        return None, str(error)
    winner = result.get("winner")
    if winner == 2:
        return 0.5, None
    if winner not in (0, 1):
        return None, f"invalid worker winner: {winner!r}"
    labels = (result.get("left"), result.get("right"))
    if labels[0] is None or labels[1] is None:
        return None, "worker result omitted player labels"
    return (1.0 if labels[int(winner)] == policy_label else 0.0), None


def _make_row(
    task: Mapping[str, Any],
    candidate_result: Mapping[str, Any] | None,
    baseline_result: Mapping[str, Any] | None,
    *,
    error: str | None = None,
) -> dict[str, Any]:
    def policy_runtime(result: Mapping[str, Any] | None, policy_label: str) -> float:
        if result is None:
            return 0.0
        values = result.get("max_action_seconds_by_label")
        if not isinstance(values, Mapping) or policy_label not in values:
            raise RunnerError(f"worker result omitted per-policy runtime for {policy_label}")
        runtime = values[policy_label]
        if isinstance(runtime, bool) or not isinstance(runtime, (int, float)):
            raise RunnerError(f"worker runtime for {policy_label} must be numeric")
        return float(runtime)

    candidate_runtime = policy_runtime(candidate_result, "candidate")
    baseline_runtime = policy_runtime(baseline_result, "baseline")
    candidate_outcome, candidate_error = (
        (None, error) if error else _outcome(candidate_result or {}, policy_label="candidate")
    )
    baseline_outcome, baseline_error = (
        (None, error) if error else _outcome(baseline_result or {}, policy_label="baseline")
    )
    return {
        "engine_id": str(task["engine_id"]),
        "opponent_id": str(task["opponent_id"]),
        "seed": int(task["seed"]),
        "seat": str(task["seat"]),
        "candidate_outcome": candidate_outcome,
        "baseline_outcome": baseline_outcome,
        "candidate_runtime_seconds": candidate_runtime,
        "baseline_runtime_seconds": baseline_runtime,
        "candidate_error": candidate_error,
        "baseline_error": baseline_error,
    }


def _validate_raw_row(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != RAW_ROW_FIELDS:
        raise RunnerError(f"{label} fields must exactly match the raw row schema")
    row = dict(value)
    try:
        _row_key(row)
    except (KeyError, TypeError, ValueError) as exc:
        raise RunnerError(f"{label} has no valid cell key: {exc}") from exc
    for prefix in ("candidate", "baseline"):
        outcome = row[f"{prefix}_outcome"]
        error = row[f"{prefix}_error"]
        runtime = row[f"{prefix}_runtime_seconds"]
        if isinstance(runtime, bool) or not isinstance(runtime, (int, float)):
            raise RunnerError(f"{label} {prefix} runtime must be numeric")
        if not math.isfinite(float(runtime)) or float(runtime) < 0.0:
            raise RunnerError(f"{label} {prefix} runtime must be finite and non-negative")
        if error is None:
            if isinstance(outcome, bool) or outcome not in (0.0, 0.5, 1.0):
                raise RunnerError(f"{label} {prefix} outcome must be terminal when error is null")
        else:
            if not isinstance(error, str) or not error:
                raise RunnerError(f"{label} {prefix} error must be a non-empty string")
            if outcome is not None:
                raise RunnerError(f"{label} {prefix} outcome must be null when execution failed")
    return row


def _validate_worker_result(value: object, *, task: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"schema", "row"}:
        raise RunnerError("cell runner result fields must exactly be schema and row")
    if value.get("schema") != WORKER_SCHEMA:
        raise RunnerError("cell runner returned the wrong schema")
    row = _validate_raw_row(value.get("row"), label="cell runner row")
    if _row_key(row) != _task_key(task):
        raise RunnerError(
            f"cell runner returned the wrong cell: expected={_task_key(task)} actual={_row_key(row)}"
        )
    return row


def _arm_task(task: Mapping[str, Any], policy_label: str) -> dict[str, Any]:
    if policy_label not in {"candidate", "baseline"}:
        raise RunnerError(f"unsupported arm policy label: {policy_label}")
    return {
        "engine_id": str(task["engine_id"]),
        "engine_dir": str(task["engine_dir"]),
        "opponent_id": str(task["opponent_id"]),
        "opponent_dir": str(task["opponent_dir"]),
        "policy_label": policy_label,
        "policy_dir": str(task[f"{policy_label}_dir"]),
        "seed": int(task["seed"]),
        "seat": str(task["seat"]),
        "max_steps": int(task["max_steps"]),
        "max_action_seconds": float(task["max_action_seconds"]),
    }


def _deadline_entry(entry: ArenaEntry, *, seconds: float) -> ArenaEntry:
    def agent(observation: dict[str, Any]) -> list[int]:
        previous_handler = signal.getsignal(signal.SIGALRM)

        def timeout_handler(signum: int, frame: object) -> None:
            del signum, frame
            raise TimeoutError("per_action_deadline_exceeded")

        signal.signal(signal.SIGALRM, timeout_handler)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            return entry.agent(observation)
        finally:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            signal.signal(signal.SIGALRM, previous_handler)

    return ArenaEntry(entry.label, entry.path, entry.deck, agent)


def run_arm(task: Mapping[str, Any]) -> dict[str, Any]:
    """Run exactly one policy-vs-opponent arm in the current fresh process."""

    policy_label = str(task["policy_label"])
    deadline = float(task["max_action_seconds"])
    policy = _deadline_entry(
        load_entry_isolated(policy_label, Path(str(task["policy_dir"]))),
        seconds=deadline,
    )
    opponent = _deadline_entry(
        load_entry_isolated(str(task["opponent_id"]), Path(str(task["opponent_dir"]))),
        seconds=deadline,
    )
    game = load_seeded_game(Path(str(task["engine_dir"])))
    policy_left = str(task["seat"]) == "policy_first"
    result = run_seeded_game(
        game,
        policy if policy_left else opponent,
        opponent if policy_left else policy,
        seed=int(task["seed"]),
        max_steps=int(task["max_steps"]),
    )
    return {"schema": ARM_WORKER_SCHEMA, "policy_label": policy_label, "result": result}


def run_cell(task: Mapping[str, Any]) -> dict[str, Any]:
    """Diagnostic in-process pairing; production uses separate arm workers."""

    candidate_result = run_arm(_arm_task(task, "candidate"))["result"]
    baseline_result = run_arm(_arm_task(task, "baseline"))["result"]
    return {"schema": WORKER_SCHEMA, "row": _make_row(task, candidate_result, baseline_result)}


def _failed_row(task: Mapping[str, Any], error: str) -> dict[str, Any]:
    return {"schema": WORKER_SCHEMA, "row": _make_row(task, None, None, error=error)}


def _run_arm_subprocess(
    task: Mapping[str, Any], policy_label: str, *, timeout_seconds: float
) -> Mapping[str, Any]:
    arm_task = _arm_task(task, policy_label)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "worker-arm",
        "--task-json",
        json.dumps(arm_task, sort_keys=True, separators=(",", ":")),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=float(timeout_seconds),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "left": policy_label,
            "right": str(task["opponent_id"]),
            "winner": None,
            "error": "worker_timeout",
            "max_action_seconds_by_label": {policy_label: 0.0},
        }
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "worker failed").strip()[-1000:]
        return {
            "left": policy_label,
            "right": str(task["opponent_id"]),
            "winner": None,
            "error": f"worker_exit_{completed.returncode}: {detail}",
            "max_action_seconds_by_label": {policy_label: 0.0},
        }
    try:
        payload = json.loads(completed.stdout)
        if (
            not isinstance(payload, Mapping)
            or set(payload) != {"schema", "policy_label", "result"}
            or payload.get("schema") != ARM_WORKER_SCHEMA
            or payload.get("policy_label") != policy_label
            or not isinstance(payload.get("result"), Mapping)
        ):
            raise RunnerError("invalid arm worker payload")
        return dict(payload["result"])
    except (RunnerError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "left": policy_label,
            "right": str(task["opponent_id"]),
            "winner": None,
            "error": f"worker_protocol_error: {exc}",
            "max_action_seconds_by_label": {policy_label: 0.0},
        }


def run_cell_subprocess(task: Mapping[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    """Run candidate and baseline arms in separate fresh interpreter processes."""

    with ThreadPoolExecutor(max_workers=2) as executor:
        candidate_future = executor.submit(
            _run_arm_subprocess, task, "candidate", timeout_seconds=timeout_seconds
        )
        baseline_future = executor.submit(
            _run_arm_subprocess, task, "baseline", timeout_seconds=timeout_seconds
        )
        candidate_result = candidate_future.result()
        baseline_result = baseline_future.result()
    return {
        "schema": WORKER_SCHEMA,
        "row": _make_row(task, candidate_result, baseline_result),
    }


def _raw_binding(
    *,
    template: Mapping[str, Any],
    candidate_sha256: str,
    baseline_sha256: str,
    ancestry_id: str,
    candidate_binding: Mapping[str, str],
    execution_identities: Mapping[str, str],
    opponent_roster_receipt_sha256: str,
    opponent_identities: Mapping[str, Mapping[str, str]],
    engine_identities: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    return {
        "schema": RAW_CHECKPOINT_SCHEMA,
        "template_content_sha256": str(template["content_sha256"]),
        "candidate_archive_sha256": candidate_sha256,
        "baseline_archive_sha256": baseline_sha256,
        "ancestry_id": ancestry_id,
        "candidate_binding": dict(sorted(candidate_binding.items())),
        "execution_identities": dict(sorted(execution_identities.items())),
        "opponent_roster_receipt_sha256": opponent_roster_receipt_sha256,
        "opponent_identities": {key: dict(opponent_identities[key]) for key in sorted(opponent_identities)},
        "engine_identities": {key: dict(engine_identities[key]) for key in sorted(engine_identities)},
    }


def _write_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _checkpoint_payload(binding: Mapping[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    content = {**dict(binding), "rows": sorted(rows, key=_row_key)}
    return {**content, "content_sha256": canonical_sha256(content)}


def _encoded_json(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def _preflight_create_once_or_identical(path: Path, payload: object) -> None:
    if path.exists() and (not path.is_file() or path.read_bytes() != _encoded_json(payload)):
        raise RunnerError(f"final output already exists with different bytes: {path}")


def _write_create_once_or_identical(path: Path, payload: object) -> None:
    data = _encoded_json(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.is_file() and path.read_bytes() == data:
            return
        raise RunnerError(f"final output already exists with different bytes: {path}")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.is_file() and path.read_bytes() == data:
            return
        raise RunnerError(f"final output raced with different bytes: {path}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _validate_checkpoint(
    payload: object, binding: Mapping[str, Any], template: Mapping[str, Any]
) -> list[dict[str, Any]]:
    if not isinstance(payload, Mapping) or payload.get("schema") != RAW_CHECKPOINT_SCHEMA:
        raise RunnerError("checkpoint schema is incompatible")
    expected_fields = set(binding) | {"rows", "content_sha256"}
    if set(payload) != expected_fields:
        raise RunnerError("checkpoint fields are incompatible")
    content = {key: payload[key] for key in payload if key != "content_sha256"}
    if payload.get("content_sha256") != canonical_sha256(content):
        raise RunnerError("checkpoint content_sha256 mismatch")
    for key, value in binding.items():
        if payload.get(key) != value:
            raise RunnerError(f"checkpoint identity mismatch for {key}")
    rows = payload.get("rows")
    if not isinstance(rows, list):
        raise RunnerError("checkpoint rows must be a list")
    expected = {
        (str(engine["engine_id"]), str(opponent["opponent_id"]), int(seed), seat)
        for engine in template["engine_roster"]
        for opponent in template["opponent_roster"]
        for seed in template["seeds"]
        for seat in SEATS
    }
    seen: set[tuple[str, str, int, str]] = set()
    checked: list[dict[str, Any]] = []
    for row in rows:
        checked_row = _validate_raw_row(row, label="checkpoint row")
        key = _row_key(checked_row)
        if key not in expected:
            raise RunnerError(f"checkpoint contains an undeclared cell {key}")
        if key in seen:
            raise RunnerError(f"checkpoint contains duplicate cell {key}")
        seen.add(key)
        checked.append(checked_row)
    if any(row.get("candidate_error") or row.get("baseline_error") for row in checked):
        raise RunnerError("checkpoint contains a failed attempt; frozen panel is permanently vetoed")
    return sorted(checked, key=_row_key)


def _completed_keys(rows: list[Mapping[str, Any]]) -> set[tuple[str, str, int, str]]:
    completed: set[tuple[str, str, int, str]] = set()
    for row in rows:
        if (
            set(row) == RAW_ROW_FIELDS
            and row.get("candidate_error") is None
            and row.get("baseline_error") is None
            and not isinstance(row.get("candidate_outcome"), bool)
            and not isinstance(row.get("baseline_outcome"), bool)
            and row.get("candidate_outcome") in (0.0, 0.5, 1.0)
            and row.get("baseline_outcome") in (0.0, 0.5, 1.0)
            and not isinstance(row.get("candidate_runtime_seconds"), bool)
            and not isinstance(row.get("baseline_runtime_seconds"), bool)
            and isinstance(row.get("candidate_runtime_seconds"), (int, float))
            and isinstance(row.get("baseline_runtime_seconds"), (int, float))
            and math.isfinite(float(row["candidate_runtime_seconds"]))
            and math.isfinite(float(row["baseline_runtime_seconds"]))
            and float(row["candidate_runtime_seconds"]) >= 0.0
            and float(row["baseline_runtime_seconds"]) >= 0.0
        ):
            completed.add(_row_key(row))
    return completed


def _materialize(
    archive: Path, destination: Path, *, label: str
) -> None:
    try:
        materialize_historical_archive(archive, destination)
    except Exception as exc:
        raise RunnerError(f"could not safely materialize {label}: {exc}") from exc


def _finalize(
    *,
    template: Mapping[str, Any],
    rows: list[dict[str, Any]],
    candidate_sha256: str,
    baseline_sha256: str,
    ancestry_id: str,
    panel_output: Path,
    feature_output: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if any(row.get("candidate_error") or row.get("baseline_error") for row in rows):
        raise RunnerError("cannot finalize a panel containing execution errors")
    try:
        panel = build_candidate_panel(
            template,
            candidate_archive_sha256=candidate_sha256,
            baseline_archive_sha256=baseline_sha256,
            ancestry_id=ancestry_id,
            rows=rows,
        )
        features = compile_candidate_features(panel, template)
    except ValueError as exc:
        raise RunnerError(f"final panel validation failed: {exc}") from exc
    _preflight_create_once_or_identical(panel_output, panel)
    _preflight_create_once_or_identical(feature_output, features)
    _write_create_once_or_identical(panel_output, panel)
    _write_create_once_or_identical(feature_output, features)
    return panel, features


def run_evaluation(
    *,
    template_path: Path,
    candidate_archive: Path,
    baseline_archive: Path,
    population_readiness: Path,
    execution_source_manifest: Path,
    opponent_manifest: Path,
    engine_manifest: Path,
    panel_output: Path,
    feature_output: Path,
    checkpoint_path: Path,
    workers: int | None = None,
    resume: bool = False,
    timeout_seconds: float | None = None,
    max_steps: int | None = None,
    cell_runner: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Execute and finalize one candidate-bound panel.

    ``cell_runner`` is an intentionally small test seam.  Production uses the
    subprocess runner; tests can supply a deterministic fake without making
    external or native calls.
    """

    template = validate_simulation_template(_json(template_path))
    execution_identities, contrast_protocol = load_execution_sources(
        execution_source_manifest.resolve(), template
    )
    protocol_workers = int(contrast_protocol["workers"])
    protocol_timeout = float(contrast_protocol["worker_timeout_seconds"])
    protocol_max_steps = int(contrast_protocol["max_steps"])
    protocol_max_action = float(contrast_protocol["max_action_seconds"])
    if workers is not None and workers != protocol_workers:
        raise RunnerError("workers override differs from the frozen contrast protocol")
    if timeout_seconds is not None and float(timeout_seconds) != protocol_timeout:
        raise RunnerError("timeout override differs from the frozen contrast protocol")
    if max_steps is not None and max_steps != protocol_max_steps:
        raise RunnerError("max_steps override differs from the frozen contrast protocol")
    workers = protocol_workers
    timeout_seconds = protocol_timeout
    max_steps = protocol_max_steps
    if len(template["engine_roster"]) != int(contrast_protocol["engine_count"]):
        raise RunnerError("template engine count differs from the frozen contrast protocol")
    if len(template["opponent_roster"]) != int(contrast_protocol["opponent_count"]):
        raise RunnerError("template opponent count differs from the frozen contrast protocol")
    if len(template["seeds"]) != int(contrast_protocol["seed_count"]):
        raise RunnerError("template seed count differs from the frozen contrast protocol")
    if list(SEATS) != list(contrast_protocol["seats"]):
        raise RunnerError("template seats differ from the frozen contrast protocol")
    if cell_runner is None and (
        platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}
    ):
        raise RunnerError("native v4.2 execution requires Linux/amd64 isolation")
    candidate_identity = _archive_identity(candidate_archive.resolve(), label="candidate")
    baseline_identity = _archive_identity(baseline_archive.resolve(), label="baseline")
    if candidate_identity.archive_sha256 == baseline_identity.archive_sha256:
        raise RunnerError("candidate and baseline archives must differ")
    expected_baseline = {
        "archive_sha256": str(contrast_protocol["baseline_archive_sha256"]),
        "policy_content_sha256": str(contrast_protocol["baseline_policy_content_sha256"]),
        "main_sha256": str(contrast_protocol["baseline_main_sha256"]),
        "deck_sha256": str(contrast_protocol["baseline_deck_sha256"]),
    }
    if _identity_dict(baseline_identity) != expected_baseline:
        raise RunnerError(
            "baseline identity differs from the frozen contrast protocol: "
            f"expected={expected_baseline} actual={_identity_dict(baseline_identity)}"
        )
    try:
        candidate_binding = load_candidate_binding_file(
            population_readiness.resolve(), candidate_identity.archive_sha256
        )
    except CandidateBindingError as exc:
        raise RunnerError(f"candidate population binding failed: {exc}") from exc
    if candidate_binding["readiness_content_sha256"] != contrast_protocol["population_readiness_sha256"]:
        raise RunnerError("candidate readiness hash differs from the frozen contrast protocol")
    candidate_semantic_identity = {
        "archive_sha256": candidate_identity.archive_sha256,
        "policy_content_sha256": candidate_identity.policy_content_sha256,
        "deck_sha256": candidate_identity.deck_sha256,
    }
    expected_candidate_identity = {
        key: str(candidate_binding[key]) for key in candidate_semantic_identity
    }
    if candidate_semantic_identity != expected_candidate_identity:
        raise RunnerError(
            "candidate archive identity differs from the readiness receipt: "
            f"expected={expected_candidate_identity} actual={candidate_semantic_identity}"
        )
    opponent_paths, opponent_identities, opponent_roster_receipt_sha256 = load_opponent_sources(
        opponent_manifest.resolve(), template
    )
    engine_paths, engine_identities = load_engine_sources(engine_manifest.resolve(), template)
    ancestry = str(candidate_binding["ancestry_id"])
    binding = _raw_binding(
        template=template,
        candidate_sha256=candidate_identity.archive_sha256,
        baseline_sha256=baseline_identity.archive_sha256,
        ancestry_id=ancestry,
        candidate_binding=candidate_binding,
        execution_identities=execution_identities,
        opponent_roster_receipt_sha256=opponent_roster_receipt_sha256,
        opponent_identities=opponent_identities,
        engine_identities=engine_identities,
    )

    rows: list[dict[str, Any]] = []
    if resume:
        if not checkpoint_path.is_file():
            raise RunnerError(f"resume checkpoint does not exist: {checkpoint_path}")
        rows = _validate_checkpoint(_json(checkpoint_path), binding, template)
        if any(
            float(row["candidate_runtime_seconds"]) > protocol_max_action
            or float(row["baseline_runtime_seconds"]) > protocol_max_action
            for row in rows
        ):
            raise RunnerError("checkpoint exceeds the frozen per-action deadline")
    elif checkpoint_path.exists():
        raise RunnerError(
            "checkpoint already exists; use --resume for an incomplete clean attempt"
        )

    with tempfile.TemporaryDirectory(prefix="evaluation-v4-2-") as temporary:
        materialized = Path(temporary)
        snapshot_root = materialized / "snapshots"
        snapshot_root.mkdir()
        candidate_snapshot = _snapshot_file(
            candidate_archive.resolve(), snapshot_root / "candidate.tar.gz", label="candidate archive"
        )
        baseline_snapshot = _snapshot_file(
            baseline_archive.resolve(), snapshot_root / "baseline.tar.gz", label="baseline archive"
        )
        if _archive_identity(candidate_snapshot, label="candidate snapshot") != candidate_identity:
            raise RunnerError("candidate archive changed after identity verification")
        if _archive_identity(baseline_snapshot, label="baseline snapshot") != baseline_identity:
            raise RunnerError("baseline archive changed after identity verification")

        opponent_snapshots: dict[str, Path] = {}
        for opponent_id in sorted(opponent_paths):
            snapshot = _snapshot_file(
                opponent_paths[opponent_id],
                snapshot_root / "opponents" / f"{opponent_id}.tar.gz",
                label=f"opponent {opponent_id} archive",
            )
            snapshot_identity = _archive_identity(snapshot, label=f"opponent {opponent_id} snapshot")
            snapshot_fields = _identity_dict(snapshot_identity)
            projected = {key: snapshot_fields[key] for key in opponent_identities[opponent_id]}
            if projected != opponent_identities[opponent_id]:
                raise RunnerError(f"opponent {opponent_id} archive changed after identity verification")
            opponent_snapshots[opponent_id] = snapshot

        engine_snapshots: dict[str, Path] = {}
        for engine_id in sorted(engine_paths):
            snapshot = _snapshot_tree(
                engine_paths[engine_id],
                snapshot_root / "engines" / engine_id,
                label=f"engine {engine_id}",
            )
            snapshot_identity = {
                "binary_sha256": sha256_file(snapshot / "cg" / "libcg.so"),
                "runtime_tree_sha256": directory_tree_sha256(snapshot),
            }
            if snapshot_identity != engine_identities[engine_id]:
                raise RunnerError(f"engine {engine_id} changed after identity verification")
            engine_snapshots[engine_id] = snapshot

        candidate_dir = materialized / "candidate"
        baseline_dir = materialized / "baseline"
        _materialize(candidate_snapshot, candidate_dir, label="candidate")
        _materialize(baseline_snapshot, baseline_dir, label="baseline")
        _verify_materialized_archive(
            candidate_snapshot,
            candidate_dir,
            _identity_dict(candidate_identity),
            label="candidate",
        )
        _verify_materialized_archive(
            baseline_snapshot,
            baseline_dir,
            _identity_dict(baseline_identity),
            label="baseline",
        )
        opponent_dirs: dict[str, Path] = {}
        for opponent_id in sorted(opponent_snapshots):
            directory = materialized / "opponents" / opponent_id
            _materialize(opponent_snapshots[opponent_id], directory, label=f"opponent {opponent_id}")
            opponent_expected = {
                **opponent_identities[opponent_id],
                "main_sha256": _materialized_policy_identity(
                    directory, label=f"opponent {opponent_id}"
                )["main_sha256"],
            }
            _verify_materialized_archive(
                opponent_snapshots[opponent_id],
                directory,
                opponent_expected,
                label=f"opponent {opponent_id}",
            )
            opponent_dirs[opponent_id] = directory
        tasks = build_tasks(
            template,
            engine_dirs=engine_snapshots,
            opponent_dirs=opponent_dirs,
            candidate_dir=candidate_dir,
            baseline_dir=baseline_dir,
            completed=_completed_keys(rows),
            max_steps=max_steps,
            max_action_seconds=protocol_max_action,
        )
        _write_atomic(checkpoint_path, _checkpoint_payload(binding, rows))
        runner = cell_runner or (lambda task: run_cell_subprocess(task, timeout_seconds=timeout_seconds))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(runner, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    result = future.result()
                    row = _validate_worker_result(result, task=task)
                except BaseException as exc:
                    row = _make_row(task, None, None, error=f"cell_runner_error: {type(exc).__name__}: {exc}")
                row = _validate_raw_row(row, label="checkpoint candidate row")
                if (
                    float(row["candidate_runtime_seconds"]) > protocol_max_action
                    or float(row["baseline_runtime_seconds"]) > protocol_max_action
                ):
                    row = _make_row(
                        task,
                        None,
                        None,
                        error="per_action_deadline_exceeded",
                    )
                existing = {_row_key(value): value for value in rows}
                existing[_row_key(row)] = row
                rows = sorted(existing.values(), key=_row_key)
                _write_atomic(checkpoint_path, _checkpoint_payload(binding, rows))

    expected_count = len(template["engine_roster"]) * len(template["opponent_roster"]) * len(template["seeds"]) * len(SEATS)
    if len(rows) != expected_count:
        raise RunnerError(f"cannot finalize incomplete panel: expected={expected_count} actual={len(rows)}")
    return _finalize(
        template=template,
        rows=rows,
        candidate_sha256=candidate_identity.archive_sha256,
        baseline_sha256=baseline_identity.archive_sha256,
        ancestry_id=ancestry,
        panel_output=panel_output,
        feature_output=feature_output,
    )


def _worker_arm_main(raw_task: str) -> int:
    task = json.loads(raw_task)
    result = run_arm(task)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", "--template-json", dest="template_path", type=Path, required=True)
    parser.add_argument("--candidate-archive", type=Path, required=True)
    parser.add_argument("--baseline-archive", type=Path, required=True)
    parser.add_argument("--population-readiness", type=Path, required=True)
    parser.add_argument("--execution-source-manifest", type=Path, required=True)
    parser.add_argument("--opponent-manifest", "--opponents", dest="opponent_manifest", type=Path, required=True)
    parser.add_argument("--engine-manifest", "--engines", dest="engine_manifest", type=Path, required=True)
    parser.add_argument("--panel-output", "--panel", dest="panel_output", type=Path, required=True)
    parser.add_argument("--feature-output", "--features", dest="feature_output", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--timeout-seconds", "--worker-timeout-seconds", dest="timeout_seconds", type=float)
    parser.add_argument("--max-steps", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    checkpoint = args.checkpoint or args.panel_output.with_suffix(args.panel_output.suffix + ".raw.json")
    try:
        panel, features = run_evaluation(
            template_path=args.template_path,
            candidate_archive=args.candidate_archive,
            baseline_archive=args.baseline_archive,
            population_readiness=args.population_readiness,
            execution_source_manifest=args.execution_source_manifest,
            opponent_manifest=args.opponent_manifest,
            engine_manifest=args.engine_manifest,
            panel_output=args.panel_output,
            feature_output=args.feature_output,
            checkpoint_path=checkpoint,
            workers=args.workers,
            resume=args.resume,
            timeout_seconds=args.timeout_seconds,
            max_steps=args.max_steps,
        )
    except (RunnerError, OSError, ValueError) as exc:
        parser.exit(1, f"evaluation v4.2 failed: {exc}\n")
    print(json.dumps({"panel_content_sha256": panel["content_sha256"], "feature_content_sha256": features["content_sha256"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker-arm":
        worker_parser = argparse.ArgumentParser()
        worker_parser.add_argument("--task-json", required=True)
        raise SystemExit(_worker_arm_main(worker_parser.parse_args(sys.argv[2:]).task_json))
    raise SystemExit(main())
