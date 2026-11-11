#!/usr/bin/env python3
"""Run one development-only v4.2 arm in three isolated Docker sandboxes.

The referee is the only container which imports the engine.  The two policy
containers only import their own policy and communicate with the referee
through the host broker's framed stdin/stdout channels.  Parent-bound execution
consumes campaign chronology and runtime evidence; standalone execution remains
an explicitly unparented diagnostic.  Neither mode creates panel authority.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Mapping
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import selectors
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.sandbox_protocol import (
    ACTION_REQUEST_SCHEMA,
    ACTION_RESPONSE_SCHEMA,
    FRAME_HEADER,
    FRAME_HEADER_SIZE,
    MAX_AGGREGATE_OUTPUT_BYTES,
    MAX_FRAME_SIZE,
    MAX_PAYLOAD_SIZE,
    MAX_STDERR_BYTES,
    PROTOCOL_SCHEMA,
    Frame,
    ProtocolState,
    SandboxProtocolError,
    TranscriptAccumulator,
    canonical_json_bytes,
    canonical_sha256,
    decode_frame,
    read_next_frame,
    validate_action_request,
    validate_action_response,
    validate_hello,
    validate_ready,
    validate_sandbox_execution_spec,
    validate_terminal,
    write_frame,
)
from evaluation_v4_2.sandbox_binding import (
    ARM_CAMPAIGN_SCHEMA,
    FALSE_AUTHORITY_FLAGS,
    PARENT_GATE_STATEMENT,
    SandboxBindingError,
    arm_campaign_sha256 as _binding_arm_campaign_sha256,
    build_arm_campaign as _binding_build_arm_campaign,
    build_arm_claim as _binding_build_arm_claim,
    policy_identity_sha256 as _binding_policy_identity_sha256,
)
from evaluation_v4_2.witness_journal import CLAIMED, STARTED, TERMINAL, WitnessJournal

# The same exact source is copied into the three containers.  Worker modes need
# only the framed protocol/binding surface; importing host campaign modules in a
# worker both expands the sandbox TCB and requires files that are intentionally
# not mounted.  Host execution imports the parent surface normally.
_CONTAINER_WORKER_MODE = len(sys.argv) > 1 and sys.argv[1] in {
    "policy-worker",
    "referee-worker",
}
if not _CONTAINER_WORKER_MODE:
    from evaluation_v4_2 import campaign_runtime
    from evaluation_v4_2.campaign_journal import (
        BURN as CAMPAIGN_BURN,
        FAILURE as CAMPAIGN_FAILURE,
        POPEN_OBSERVED,
        START_DURABLE_POPEN_UNCERTAIN,
        SUCCESS as CAMPAIGN_SUCCESS,
        CampaignJournal,
    )
    from evaluation_v4_2.campaign_preparation import validate_campaign_prepared_manifest
    from evaluation_v4_2.parent_arm_claim import (
        ParentArmClaimError,
        build_parent_bound_child_claim,
        deterministic_parent_container_names,
        parent_bound_child_claim_sha256,
        parent_child_campaign_sha256,
        validate_child_claim_template,
        validate_parent_bound_child_claim,
    )


DEFAULT_IMAGE = (
    "docker.io/library/python@sha256:"
    "a7bce671c71744cd4dcef2bc9cd9c5eff3d7cfa6b55eca30759765047184bcdb"
)
DEFAULT_CPU_MILLICORES = 1000
DEFAULT_MEMORY_BYTES = 512 * 1024 * 1024
DEFAULT_PIDS_LIMIT = 64
DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
DEFAULT_ARM_DEADLINE_SECONDS = 900.0
DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS = 15.0
MAX_OUTPUT_BYTES = MAX_AGGREGATE_OUTPUT_BYTES
CONTAINER_USER = "65534:65534"
GAME_ID = "game-1"

ARM_RESULT_SCHEMA = "evaluation_v4_2_development_single_arm_result_v1"
ARTIFACT_MANIFEST_SCHEMA = "evaluation_v4_2_development_sandbox_artifacts_v1"
WITNESSED_ARM_SCHEMA = "evaluation_v4_2_witness_reopened_sandbox_arm_v4"
PARENT_BOUND_ARM_RESULT_SCHEMA = "evaluation_v4_2_parent_bound_sandbox_arm_result_v1"
AUTHORITY_STATEMENT = (
    "DEVELOPMENT_ONLY in-process HMAC witness; separate-principal deployment "
    "is still required before any panel or production authority is considered."
)
_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


class SandboxArmError(RuntimeError):
    """The arm could not be prepared or its evidence could not be sealed."""


class SandboxArmFault(SandboxArmError):
    """A launched arm reached a host-observed terminal fault."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SandboxArmError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _json_bytes(value: object) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SandboxArmError(f"could not read JSON {path}: {exc}") from exc


def _write_bytes(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: object, *, mode: int = 0o444) -> None:
    _write_bytes(path, _json_bytes(value), mode=mode)


def _reject_symlinks(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise SandboxArmError(f"expected a regular directory: {root}")
    for item in root.rglob("*"):
        if item.is_symlink():
            raise SandboxArmError(f"tree contains a symlink: {item}")


def _copy_tree(source: Path, destination: Path) -> None:
    _reject_symlinks(source)
    source = source.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    for item in sorted(source.rglob("*"), key=lambda value: value.relative_to(source).as_posix()):
        relative = item.relative_to(source)
        if _is_snapshot_copy_excluded(relative):
            continue
        target = destination / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
        else:
            raise SandboxArmError(f"tree contains a non-file entry: {item}")


def _freeze_tree(root: Path) -> None:
    for item in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if item.is_file():
            item.chmod(0o444)
        elif item.is_dir():
            item.chmod(0o555)
    root.chmod(0o555)


def _tree_records(root: Path) -> list[dict[str, str]]:
    root = root.resolve()
    _reject_symlinks(root)
    records: list[dict[str, str]] = []
    for item in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        if item.is_file():
            records.append(
                {
                    "path": item.relative_to(root).as_posix(),
                    "sha256": _sha256_file(item),
                }
            )
    if not records:
        raise SandboxArmError(f"tree contains no files: {root}")
    return records


def _tree_sha256(root: Path) -> str:
    return canonical_sha256(_tree_records(root))


_SNAPSHOT_TREE_SOURCES = (
    ("policy", "policy"),
    ("opponent", "opponent"),
    ("engine", "engine"),
    ("runtime", "runtime"),
)


def _is_snapshot_copy_excluded(relative: Path) -> bool:
    return "__pycache__" in relative.parts or relative.name.endswith((".pyc", ".pyo"))


def _require_regular_snapshot_file(path: Path) -> Path:
    if path.is_symlink():
        raise SandboxArmError(f"snapshot source is a symlink: {path}")
    if not path.is_file():
        raise SandboxArmError(f"snapshot source is not a regular file: {path}")
    return path.resolve()


def _snapshot_tree_files(source: Path, destination_prefix: str) -> list[tuple[str, Path]]:
    """List the regular files that ``_copy_tree`` would place under one prefix."""

    _reject_symlinks(source)
    resolved_source = source.resolve()
    files: list[tuple[str, Path]] = []
    for item in sorted(
        resolved_source.rglob("*"), key=lambda value: value.relative_to(resolved_source).as_posix()
    ):
        relative = item.relative_to(resolved_source)
        if _is_snapshot_copy_excluded(relative):
            continue
        if item.is_dir():
            continue
        if not item.is_file():
            raise SandboxArmError(f"tree contains a non-file entry: {item}")
        files.append((f"{destination_prefix}/{relative.as_posix()}", item))
    return files


def _register_snapshot_source(
    entries: dict[str, Path | bytes],
    path: str,
    source: Path | bytes,
    *,
    overwrite: bool = False,
) -> None:
    """Add one virtual snapshot file while rejecting file/directory ambiguity."""

    relative = PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts or str(relative) in {"", "."}:
        raise SandboxArmError(f"snapshot output path is unsafe: {path!r}")
    normalized = relative.as_posix()
    if normalized in entries:
        if not overwrite:
            raise SandboxArmError(f"snapshot output collision: {normalized}")
        entries[normalized] = source
        return
    for parent in relative.parents:
        parent_name = parent.as_posix()
        if parent_name == ".":
            break
        if parent_name in entries:
            raise SandboxArmError(f"snapshot output collision: {parent_name} is a file")
    prefix = normalized + "/"
    if any(existing.startswith(prefix) for existing in entries):
        raise SandboxArmError(f"snapshot output collision: {normalized} would replace a directory")
    entries[normalized] = source


def _snapshot_virtual_sources(bundle_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Path | bytes]:
    """Build the complete virtual snapshot file map without creating a snapshot."""

    bundle = bundle_dir.resolve()
    entries: dict[str, Path | bytes] = {}
    for source_name, destination_prefix in _SNAPSHOT_TREE_SOURCES:
        for destination, source in _snapshot_tree_files(bundle / source_name, destination_prefix):
            _register_snapshot_source(entries, destination, source)

    _register_snapshot_source(
        entries,
        "decks/candidate/deck.csv",
        _require_regular_snapshot_file(bundle / "policy" / "deck.csv"),
    )
    _register_snapshot_source(
        entries,
        "decks/opponent/deck.csv",
        _require_regular_snapshot_file(bundle / "opponent" / "deck.csv"),
    )
    _register_snapshot_source(entries, "task.json", _json_bytes(manifest["task"]))

    # These are intentional replacements for stale bundle runtime copies.
    for destination, source in _snapshot_runtime_overwrites():
        _register_snapshot_source(
            entries,
            destination,
            _require_regular_snapshot_file(source),
            overwrite=True,
        )
    return entries


def _snapshot_runtime_overwrites() -> tuple[tuple[str, Path], ...]:
    """Resolve the runtime sources at prediction/materialization time."""

    runtime = ROOT / "evaluation_v4_2"
    return (
        ("runtime/evaluation_v4_2/sandbox_protocol.py", runtime / "sandbox_protocol.py"),
        ("runtime/evaluation_v4_2/sandbox_binding.py", runtime / "sandbox_binding.py"),
        ("runtime/evaluation_v4_2/witness_journal.py", runtime / "witness_journal.py"),
        ("runtime/sandbox_arm.py", Path(__file__).resolve()),
    )


def predict_snapshot_manifest(bundle_dir: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Predict ``_snapshot_bundle``'s manifest without copying bundle files.

    This is deliberately preparation-safe: it only validates and hashes the
    source files, generated deck aliases, canonical task payload, and the live
    runtime overlays that the materializer injects.
    """

    sources = _snapshot_virtual_sources(bundle_dir, manifest)
    records = [
        {
            "path": path,
            "sha256": _sha256_bytes(source) if isinstance(source, bytes) else _sha256_file(source),
        }
        for path, source in sorted(sources.items())
    ]
    if not records:
        raise SandboxArmError("snapshot contains no files")
    return {
        "schema": "evaluation_v4_2_development_private_snapshot_v1",
        "bundle_manifest_sha256": manifest["content_sha256"],
        "files": records,
        "tree_sha256": canonical_sha256(records),
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }


def _load_bundle_validator() -> Any:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.run_evaluation_v4_2_container_arm import validate_input_bundle

    return validate_input_bundle


def _binding_error(exc: SandboxBindingError) -> SandboxArmError:
    return SandboxArmError(str(exc))


def _compatibility_task(task: Mapping[str, Any]) -> Mapping[str, Any]:
    """Preserve the historical runner identity API's label-independent input."""

    label = task.get("policy_label") if isinstance(task, Mapping) else None
    if isinstance(label, str) and label and label == label.strip() and label not in {
        "candidate",
        "baseline",
    }:
        return {**task, "policy_label": "candidate"}
    return task


def policy_identity_sha256(task: Mapping[str, Any], prefix: str = "policy") -> str:
    try:
        return _binding_policy_identity_sha256(_compatibility_task(task), prefix)
    except SandboxBindingError as exc:
        raise _binding_error(exc) from exc


def build_arm_campaign(task: Mapping[str, Any], bundle_manifest_sha256: str) -> dict[str, Any]:
    """Build the identity of this one arm, never a candidate-level campaign."""

    try:
        return _binding_build_arm_campaign(_compatibility_task(task), bundle_manifest_sha256)
    except SandboxBindingError as exc:
        raise _binding_error(exc) from exc


def arm_campaign_sha256(task: Mapping[str, Any], bundle_manifest_sha256: str) -> str:
    try:
        return _binding_arm_campaign_sha256(_compatibility_task(task), bundle_manifest_sha256)
    except SandboxBindingError as exc:
        raise _binding_error(exc) from exc


def build_arm_claim(task: Mapping[str, Any], bundle_manifest_sha256: str) -> dict[str, Any]:
    """Return a journal claim document suitable for one arm's CLAIM event."""

    try:
        return _binding_build_arm_claim(_compatibility_task(task), bundle_manifest_sha256)
    except SandboxBindingError as exc:
        raise _binding_error(exc) from exc


def claim_arm(
    journal: WitnessJournal,
    attempt_id: str,
    task: Mapping[str, Any],
    bundle_manifest_sha256: str,
) -> dict[str, Any]:
    """Reserve one arm in an injected development witness journal.

    This helper intentionally does not call ``claim_plan``: that API is for a
    broader campaign identity and is not a substitute for a parent panel gate.
    """

    document = build_arm_claim(task, bundle_manifest_sha256)
    campaign_sha256 = document["campaign_sha256"]
    one_shot_key = journal.one_shot_key(
        campaign_sha256,
        policy_identity_sha256(task),
    )
    return journal.claim(
        attempt_id,
        claim=document,
        one_shot_key_sha256=one_shot_key,
        metadata={
            "scope": "single_arm",
            "campaign_sha256": campaign_sha256,
            "panel_parent_claim_verified": False,
            "parent_campaign_gate_required": True,
        },
    )


def execute_standalone_unparented_arm(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Run the retained diagnostic-only standalone path.

    Parent campaign composition must use :func:`execute_parent_bound_arm`.
    This alias is intentionally explicit at call sites without changing the
    legacy ``execute_arm`` API used by development diagnostics.
    """

    return execute_arm(*args, **kwargs)


def _snapshot_bundle(
    bundle_dir: Path,
    artifact_root: Path,
    manifest: Mapping[str, Any],
) -> tuple[Path, dict[str, Any]]:
    bundle = bundle_dir.resolve()
    _snapshot_virtual_sources(bundle, manifest)
    snapshot = artifact_root / "snapshot"
    snapshot.mkdir(parents=False, mode=0o755)
    _copy_tree(bundle / "policy", snapshot / "policy")
    _copy_tree(bundle / "opponent", snapshot / "opponent")
    _copy_tree(bundle / "engine", snapshot / "engine")
    _copy_tree(bundle / "runtime", snapshot / "runtime")
    (snapshot / "decks" / "candidate").mkdir(parents=True)
    (snapshot / "decks" / "opponent").mkdir(parents=True)
    shutil.copyfile(bundle / "policy" / "deck.csv", snapshot / "decks" / "candidate" / "deck.csv")
    shutil.copyfile(bundle / "opponent" / "deck.csv", snapshot / "decks" / "opponent" / "deck.csv")
    _write_bytes(snapshot / "task.json", _json_bytes(manifest["task"]))

    runtime_protocol = snapshot / "runtime" / "evaluation_v4_2" / "sandbox_protocol.py"
    runtime_protocol.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "evaluation_v4_2" / "sandbox_protocol.py", runtime_protocol)
    shutil.copyfile(ROOT / "evaluation_v4_2" / "sandbox_binding.py", runtime_protocol.parent / "sandbox_binding.py")
    shutil.copyfile(
        ROOT / "evaluation_v4_2" / "witness_journal.py",
        runtime_protocol.parent / "witness_journal.py",
    )
    shutil.copyfile(Path(__file__).resolve(), snapshot / "runtime" / "sandbox_arm.py")

    _freeze_tree(snapshot)
    records = _tree_records(snapshot)
    snapshot_manifest = {
        "schema": "evaluation_v4_2_development_private_snapshot_v1",
        "bundle_manifest_sha256": manifest["content_sha256"],
        "files": records,
        "tree_sha256": canonical_sha256(records),
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    return snapshot, snapshot_manifest


def _verify_snapshot(snapshot: Path, manifest: Mapping[str, Any]) -> None:
    expected = _require_digest(manifest.get("tree_sha256"), "snapshot tree_sha256")
    if _tree_sha256(snapshot) != expected:
        raise SandboxArmFault("private input snapshot changed during execution")


def deterministic_container_names(attempt_id: str) -> dict[str, str]:
    token = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:32]
    return {
        "referee": f"ev42-sbx-{token}-referee",
        "candidate_policy": f"ev42-sbx-{token}-candidate",
        "opponent_policy": f"ev42-sbx-{token}-opponent",
    }


def _image_digest(image: str) -> str:
    if "@sha256:" not in image:
        raise SandboxArmError("image must be digest-pinned with @sha256:<digest>")
    digest = image.rsplit("@sha256:", 1)[1]
    return _require_digest(digest, "image digest")


def _mount(source: Path, target: str) -> str:
    return f"type=bind,source={source.resolve()},target={target},readonly,bind-propagation=rprivate"


def build_docker_command(
    role: str,
    snapshot: Path,
    *,
    image: str,
    name: str,
    session_id: str,
    arm_claim_sha256: str,
    task: Mapping[str, Any],
    cpu_millicores: int = DEFAULT_CPU_MILLICORES,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    tmpfs_bytes: int = DEFAULT_TMPFS_BYTES,
    arm_bound_event_sha256: str | None = None,
    child_start_event_sha256: str | None = None,
) -> list[str]:
    """Build one exact, read-only, networkless container command."""

    if role not in {"referee", "candidate_policy", "opponent_policy"}:
        raise SandboxArmError(f"unknown sandbox role: {role}")
    image_digest = _image_digest(image)
    del image_digest
    if cpu_millicores <= 0 or memory_bytes <= 0 or pids_limit <= 0 or tmpfs_bytes <= 0:
        raise SandboxArmError("container resource limits must be positive")
    if (arm_bound_event_sha256 is None) != (child_start_event_sha256 is None):
        raise SandboxArmError("parent event hashes must be supplied together")
    if arm_bound_event_sha256 is not None:
        _require_digest(arm_bound_event_sha256, "ARM_BOUND event sha256")
        _require_digest(child_start_event_sha256, "child START event sha256")
    names = {
        "referee": "referee",
        "candidate_policy": "candidate_policy",
        "opponent_policy": "opponent_policy",
    }
    sandbox_id = names[role]
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--interactive",
        "--name",
        name,
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--user",
        CONTAINER_USER,
        "--ipc",
        "private",
        "--pids-limit",
        str(pids_limit),
        "--memory",
        str(memory_bytes),
        "--memory-swap",
        str(memory_bytes),
        "--cpus",
        f"{cpu_millicores / 1000.0:.3f}",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        f"nproc={pids_limit}:{pids_limit}",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs_bytes},mode=700,uid=65534,gid=65534",
        "--workdir",
        "/tmp",
        "--env",
        "HOME=/tmp",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONHASHSEED=0",
        "--env",
        "PYTHONPATH=/input/runtime",
        "--label",
        f"evaluation_v4_2.role={role}",
        "--label",
        f"evaluation_v4_2.session_id={session_id}",
        "--label",
        f"evaluation_v4_2.claim_sha256={arm_claim_sha256}",
    ]
    if arm_bound_event_sha256 is not None:
        command.extend(
            [
                "--label",
                f"evaluation_v4_2.arm_bound_event_sha256={arm_bound_event_sha256}",
                "--label",
                f"evaluation_v4_2.child_start_event_sha256={child_start_event_sha256}",
            ]
        )
    if role == "referee":
        if task["seat"] == "policy_first":
            left_deck = "/input/decks/candidate/deck.csv"
            right_deck = "/input/decks/opponent/deck.csv"
        elif task["seat"] == "policy_second":
            left_deck = "/input/decks/opponent/deck.csv"
            right_deck = "/input/decks/candidate/deck.csv"
        else:
            raise SandboxArmError("task seat is invalid")
        mounts = [
            _mount(snapshot / "engine", "/input/engine"),
            _mount(snapshot / "decks", "/input/decks"),
            _mount(snapshot / "task.json", "/input/task.json"),
            _mount(snapshot / "runtime", "/input/runtime"),
        ]
        worker_args = [
            "referee-worker",
            "--session-id",
            session_id,
            "--arm-claim-sha256",
            arm_claim_sha256,
            "--task",
            "/input/task.json",
            "--left-deck",
            left_deck,
            "--right-deck",
            right_deck,
            "--engine",
            "/input/engine",
        ]
    elif role == "candidate_policy":
        mounts = [
            _mount(snapshot / "policy", "/input/policy"),
            _mount(snapshot / "runtime", "/input/runtime"),
        ]
        worker_args = [
            "policy-worker",
            "--role",
            role,
            "--session-id",
            session_id,
            "--arm-claim-sha256",
            arm_claim_sha256,
            "--policy-dir",
            "/input/policy",
        ]
    else:
        mounts = [
            _mount(snapshot / "opponent", "/input/opponent"),
            _mount(snapshot / "runtime", "/input/runtime"),
        ]
        worker_args = [
            "policy-worker",
            "--role",
            role,
            "--session-id",
            session_id,
            "--arm-claim-sha256",
            arm_claim_sha256,
            "--policy-dir",
            "/input/opponent",
        ]
    for mount in mounts:
        command.extend(["--mount", mount])
    command.extend([image, "python", "/input/runtime/sandbox_arm.py", *worker_args])
    return command


def _docker_call(
    command: list[str],
    *,
    timeout: float = DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxArmFault(f"docker call timed out: {' '.join(command[:4])}") from exc
    except OSError as exc:
        raise SandboxArmFault(f"docker call failed: {exc}") from exc


def _docker_json(
    command: list[str],
    *,
    timeout: float = DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
) -> tuple[subprocess.CompletedProcess[bytes], Any]:
    result = _docker_call(command, timeout=timeout)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or b"")[-2000:].decode("utf-8", errors="replace")
        raise SandboxArmFault(f"docker command failed ({result.returncode}): {detail}")
    try:
        return result, json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise SandboxArmFault(f"docker command did not return JSON: {' '.join(command)}") from exc


def _verify_image(image: str, *, timeout: float) -> dict[str, Any]:
    digest = _image_digest(image)
    _, payload = _docker_json(["docker", "image", "inspect", image], timeout=timeout)
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
        raise SandboxArmFault("docker image inspect returned an invalid payload")
    row = payload[0]
    if row.get("Architecture") != "amd64" or row.get("Os") != "linux":
        raise SandboxArmFault("resolved image is not linux/amd64")
    repo_digests = row.get("RepoDigests") or []
    if not any(isinstance(item, str) and item.endswith(f"@sha256:{digest}") for item in repo_digests):
        raise SandboxArmFault("resolved image does not retain the exact pinned digest")
    return dict(row)


def _validate_observed_container(
    inspect: Mapping[str, Any],
    role: str,
    snapshot: Path,
    *,
    image: str,
    expected_command: list[str],
    session_id: str,
    arm_claim_sha256: str,
    cpu_millicores: int,
    memory_bytes: int,
    pids_limit: int,
    tmpfs_bytes: int,
) -> dict[str, Any]:
    config = inspect.get("Config")
    host = inspect.get("HostConfig")
    mounts = inspect.get("Mounts")
    if not isinstance(config, Mapping) or not isinstance(host, Mapping) or not isinstance(mounts, list):
        raise SandboxArmFault(f"container inspect for {role} lacks Config/HostConfig/Mounts")
    if config.get("User") != CONTAINER_USER:
        raise SandboxArmFault(f"{role} is not running as the required nonroot user")
    if config.get("Image") != image or config.get("Cmd") != expected_command:
        raise SandboxArmFault(f"{role} image or command differs from the frozen launch")
    if config.get("OpenStdin") is not True or config.get("Tty") is not False:
        raise SandboxArmFault(f"{role} does not expose the required framed stdin pipe")
    labels = config.get("Labels") or {}
    expected_labels = {
        "evaluation_v4_2.role": role,
        "evaluation_v4_2.session_id": session_id,
        "evaluation_v4_2.claim_sha256": arm_claim_sha256,
    }
    if not isinstance(labels, Mapping) or any(labels.get(key) != value for key, value in expected_labels.items()):
        raise SandboxArmFault(f"{role} labels do not bind the session and claim")
    if host.get("NetworkMode") != "none":
        raise SandboxArmFault(f"{role} has container networking enabled")
    if host.get("ReadonlyRootfs") is not True:
        raise SandboxArmFault(f"{role} root filesystem is writable")
    if host.get("Privileged") is not False:
        raise SandboxArmFault(f"{role} is privileged")
    if sorted(host.get("CapDrop") or []) != ["ALL"]:
        raise SandboxArmFault(f"{role} does not drop all capabilities")
    if not any(
        value in {"no-new-privileges", "no-new-privileges=true"}
        for value in (host.get("SecurityOpt") or [])
    ):
        raise SandboxArmFault(f"{role} does not set no-new-privileges")
    if host.get("PidMode") not in {"private", ""}:
        raise SandboxArmFault(f"{role} does not use a private PID namespace")
    if host.get("IpcMode") not in {"private", ""}:
        raise SandboxArmFault(f"{role} does not use a private IPC namespace")
    if host.get("PidsLimit") != pids_limit:
        raise SandboxArmFault(f"{role} pids limit differs from the frozen limit")
    if host.get("Memory") != memory_bytes or host.get("MemorySwap") != memory_bytes:
        raise SandboxArmFault(f"{role} memory limits differ from the frozen limit")
    if int(host.get("NanoCpus") or 0) != cpu_millicores * 1_000_000:
        raise SandboxArmFault(f"{role} CPU limit differs from the frozen limit")
    tmpfs = host.get("Tmpfs") or {}
    tmpfs_value = tmpfs.get("/tmp") if isinstance(tmpfs, Mapping) else None
    if not isinstance(tmpfs_value, str) or f"size={tmpfs_bytes}" not in tmpfs_value:
        raise SandboxArmFault(f"{role} tmpfs limit is missing")
    expected_sources = {
        "referee": {
            "/input/engine": snapshot / "engine",
            "/input/decks": snapshot / "decks",
            "/input/task.json": snapshot / "task.json",
            "/input/runtime": snapshot / "runtime",
        },
        "candidate_policy": {
            "/input/policy": snapshot / "policy",
            "/input/runtime": snapshot / "runtime",
        },
        "opponent_policy": {
            "/input/opponent": snapshot / "opponent",
            "/input/runtime": snapshot / "runtime",
        },
    }[role]
    observed: list[dict[str, Any]] = []
    for mount in mounts:
        if not isinstance(mount, Mapping):
            raise SandboxArmFault(f"{role} has a malformed mount")
        destination = mount.get("Destination")
        source = mount.get("Source")
        if destination not in expected_sources:
            raise SandboxArmFault(f"{role} has an unexpected mount: {destination}")
        if Path(str(source)).resolve() != expected_sources[destination].resolve():
            raise SandboxArmFault(f"{role} mount source mismatch for {destination}")
        if mount.get("RW") is not False or mount.get("Propagation") != "rprivate":
            raise SandboxArmFault(f"{role} has a writable or non-private mount")
        observed.append(
            {
                "source": str(source),
                "destination": destination,
                "type": mount.get("Type"),
                "read_only": not bool(mount.get("RW")),
                "propagation": mount.get("Propagation"),
            }
        )
    if {item["destination"] for item in observed} != set(expected_sources):
        raise SandboxArmFault(f"{role} mount set is incomplete")
    return {
        "role": role,
        "id": inspect.get("Id"),
        "image": inspect.get("Image"),
        "config": dict(config),
        "host_config": dict(host),
        "mounts": sorted(observed, key=lambda item: item["destination"]),
        "state": dict(inspect.get("State") or {}),
    }


@dataclass
class _Child:
    role: str
    name: str
    command: list[str]
    process: Any
    stdin_bytes: bytearray = field(default_factory=bytearray)
    stdout_bytes: bytearray = field(default_factory=bytearray)
    stderr_bytes: bytearray = field(default_factory=bytearray)
    stdout_buffer: bytearray = field(default_factory=bytearray)
    stdout_eof: bool = False
    stderr_eof: bool = False


@dataclass
class _OutputBudget:
    """One broker-owned ceiling for every child stdout/stderr byte."""

    limit: int = field(default_factory=lambda: MAX_AGGREGATE_OUTPUT_BYTES)
    consumed: int = 0

    def consume(self, child: _Child, kind: str, size: int) -> None:
        self.consumed += size
        if self.consumed > self.limit:
            raise SandboxArmFault(
                "aggregate child stdout/stderr output limit exceeded "
                f"after {child.role} {kind}"
            )


def _fileno(stream: Any) -> int | None:
    try:
        value = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None
    return value if isinstance(value, int) and value >= 0 else None


def _nonblocking(stream: Any) -> int | None:
    fd = _fileno(stream)
    if fd is not None:
        try:
            os.set_blocking(fd, False)
        except OSError as exc:
            raise SandboxArmFault(f"could not make IPC channel nonblocking: {exc}") from exc
    return fd


def _capture_fd(
    child: _Child,
    kind: str,
    limit: int,
    *,
    output_budget: _OutputBudget | None = None,
) -> bytes:
    stream = getattr(child.process, kind)
    fd = _fileno(stream)
    if fd is None:
        return b""
    try:
        data = os.read(fd, 65536)
    except BlockingIOError:
        return b""
    except OSError as exc:
        raise SandboxArmFault(f"could not read {kind} from {child.role}: {exc}") from exc
    if not data:
        if kind == "stdout":
            child.stdout_eof = True
        else:
            child.stderr_eof = True
        return b""
    target = child.stdout_bytes if kind == "stdout" else child.stderr_bytes
    target.extend(data)
    if len(target) > limit:
        raise SandboxArmFault(f"{child.role} {kind} output limit exceeded")
    if output_budget is not None:
        output_budget.consume(child, kind, len(data))
    if len(child.stdout_bytes) + len(child.stderr_bytes) > MAX_OUTPUT_BYTES:
        raise SandboxArmFault(f"{child.role} combined output limit exceeded")
    if kind == "stdout":
        child.stdout_buffer.extend(data)
    return data


def _poll(child: _Child) -> int | None:
    try:
        return child.process.poll()
    except (AttributeError, OSError) as exc:
        raise SandboxArmFault(f"could not poll {child.role}: {exc}") from exc


def _write_ipc(child: _Child, payload: bytes, deadline: float) -> None:
    stream = getattr(child.process, "stdin", None)
    if stream is None:
        raise SandboxArmFault(f"{child.role} stdin is unavailable")
    fd = _nonblocking(stream)
    written = 0
    while written < len(payload):
        if _poll(child) is not None:
            raise SandboxArmFault(f"{child.role} exited while receiving a frame")
        if time.monotonic() >= deadline:
            raise SandboxArmFault(f"write deadline exceeded for {child.role}")
        if fd is None:
            try:
                count = stream.write(payload[written:])
                if hasattr(stream, "flush"):
                    stream.flush()
            except (BrokenPipeError, OSError) as exc:
                raise SandboxArmFault(f"could not write to {child.role}: {exc}") from exc
            if not isinstance(count, int) or count <= 0:
                raise SandboxArmFault(f"{child.role} stdin made no progress")
        else:
            try:
                count = os.write(fd, payload[written:])
            except BlockingIOError:
                selector = selectors.DefaultSelector()
                try:
                    selector.register(fd, selectors.EVENT_WRITE)
                    selector.select(max(0.0, min(0.05, deadline - time.monotonic())))
                finally:
                    selector.close()
                continue
            except (BrokenPipeError, OSError) as exc:
                raise SandboxArmFault(f"could not write to {child.role}: {exc}") from exc
            if count <= 0:
                raise SandboxArmFault(f"{child.role} stdin made no progress")
        child.stdin_bytes.extend(payload[written : written + count])
        written += count


def _read_frame_from_child(
    target: _Child,
    children: list[_Child],
    deadline: float,
    *,
    monitor_other_stdout: bool,
    output_budget: _OutputBudget | None = None,
) -> Frame:
    target_stdout = getattr(target.process, "stdout", None)
    if target_stdout is None:
        raise SandboxArmFault(f"{target.role} stdout is unavailable")
    target_fd = _nonblocking(target_stdout)
    if target_fd is None:
        # This fallback keeps unit-test fakes usable.  Real Popen pipes always
        # take the nonblocking selector path above.
        while True:
            if target.stdout_buffer:
                frame = _pop_frame(target)
                if frame is not None:
                    return frame
            if time.monotonic() >= deadline:
                raise SandboxArmFault(f"read deadline exceeded for {target.role}")
            chunk = target_stdout.read(65536)
            if chunk:
                target.stdout_bytes.extend(chunk)
                target.stdout_buffer.extend(chunk)
                if len(target.stdout_bytes) > MAX_OUTPUT_BYTES:
                    raise SandboxArmFault(f"{target.role} stdout output limit exceeded")
                if output_budget is not None:
                    output_budget.consume(target, "stdout", len(chunk))
            else:
                if _poll(target) is not None:
                    raise SandboxArmFault(f"{target.role} exited before a complete frame")
                time.sleep(0.001)

    selector = selectors.DefaultSelector()
    registered: dict[int, tuple[_Child, str]] = {}
    try:
        selector.register(target_fd, selectors.EVENT_READ)
        registered[target_fd] = (target, "stdout")
        for child in children:
            stderr_fd = _nonblocking(getattr(child.process, "stderr", None)) if getattr(child.process, "stderr", None) is not None else None
            if stderr_fd is not None and stderr_fd not in registered:
                selector.register(stderr_fd, selectors.EVENT_READ)
                registered[stderr_fd] = (child, "stderr")
            if monitor_other_stdout and child is not target:
                other_fd = _nonblocking(getattr(child.process, "stdout", None)) if getattr(child.process, "stdout", None) is not None else None
                if other_fd is not None and other_fd not in registered:
                    selector.register(other_fd, selectors.EVENT_READ)
                    registered[other_fd] = (child, "stdout")
        while True:
            frame = _pop_frame(target)
            if frame is not None:
                if target.stdout_buffer:
                    raise SandboxArmFault(f"{target.role} emitted more than one frame at once")
                return frame
            if time.monotonic() >= deadline:
                raise SandboxArmFault(f"read deadline exceeded for {target.role}")
            events = selector.select(max(0.0, min(0.05, deadline - time.monotonic())))
            if not events:
                for child in children:
                    return_code = _poll(child)
                    if return_code is not None and child is not target:
                        raise SandboxArmFault(f"{child.role} exited before the arm was terminal")
                    if return_code is not None and child is target and child.stdout_eof:
                        raise SandboxArmFault(f"{target.role} exited before a complete frame")
                continue
            for key, _ in events:
                child, kind = registered[key.fd]
                data = _capture_fd(
                    child,
                    kind,
                    MAX_STDERR_BYTES if kind == "stderr" else MAX_OUTPUT_BYTES,
                    output_budget=output_budget,
                )
                if kind == "stdout" and not data and child.stdout_eof:
                    raise SandboxArmFault(f"{child.role} closed stdout before a complete frame")
                if kind == "stdout" and child is not target and data:
                    raise SandboxArmFault(f"unexpected stdout from idle {child.role}")
    finally:
        selector.close()


def _pop_frame(child: _Child) -> Frame | None:
    if len(child.stdout_buffer) < FRAME_HEADER_SIZE:
        return None
    try:
        _, _, _, _, _, payload_length, _ = FRAME_HEADER.unpack(
            bytes(child.stdout_buffer[:FRAME_HEADER_SIZE])
        )
    except struct.error as exc:  # pragma: no cover - FRAME_HEADER is fixed.
        raise SandboxArmFault(f"malformed frame header from {child.role}: {exc}") from exc
    if payload_length > MAX_PAYLOAD_SIZE:
        raise SandboxArmFault(f"oversize frame from {child.role}")
    frame_length = FRAME_HEADER_SIZE + payload_length
    if frame_length > MAX_FRAME_SIZE:
        raise SandboxArmFault(f"oversize frame from {child.role}")
    if len(child.stdout_buffer) < frame_length:
        return None
    raw = bytes(child.stdout_buffer[:frame_length])
    del child.stdout_buffer[:frame_length]
    try:
        return decode_frame(raw, max_frame_size=MAX_FRAME_SIZE)
    except SandboxProtocolError as exc:
        raise SandboxArmFault(f"malformed frame from {child.role}: {exc}") from exc

def _close_stdin(children: list[_Child]) -> None:
    for child in children:
        stream = getattr(child.process, "stdin", None)
        if stream is None:
            continue
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _wait_clean(
    children: list[_Child],
    deadline: float,
    *,
    output_budget: _OutputBudget | None = None,
) -> None:
    while True:
        all_done = True
        for child in children:
            for kind, limit in (("stderr", MAX_STDERR_BYTES), ("stdout", MAX_OUTPUT_BYTES)):
                new_data = _capture_fd(child, kind, limit, output_budget=output_budget)
                if kind == "stdout" and new_data:
                    # The terminal frame was already consumed.  Any later
                    # stdout is an output-spam or result-substitution attempt.
                    raise SandboxArmFault(f"{child.role} emitted stdout after terminal")
            return_code = _poll(child)
            if return_code is None:
                all_done = False
            elif return_code != 0:
                raise SandboxArmFault(f"{child.role} exited with status {return_code}")
        if all_done:
            return
        if time.monotonic() >= deadline:
            raise SandboxArmFault("child exit deadline exceeded after terminal")
        time.sleep(0.005)


def _launch_children(
    commands: Mapping[str, list[str]],
    names: Mapping[str, str],
) -> list[_Child]:
    children: list[_Child] = []
    for role in ("referee", "candidate_policy", "opponent_policy"):
        command = commands[role]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxArmFault(f"could not launch {role}: {exc}") from exc
        children.append(_Child(role, names[role], command, process))
    return children


def _kill_and_remove(
    children: list[_Child],
    names: Mapping[str, str],
    *,
    docker_timeout: float,
) -> None:
    # Issue all deterministic kills even when one Docker CLI call fails.
    for role in ("referee", "candidate_policy", "opponent_policy"):
        try:
            _docker_call(
                ["docker", "kill", "--signal", "KILL", names[role]],
                timeout=docker_timeout,
            )
        except BaseException:
            pass
    for child in children:
        try:
            if _poll(child) is None:
                child.process.kill()
        except BaseException:
            pass
    for child in children:
        try:
            child.process.wait(timeout=min(5.0, docker_timeout))
        except BaseException:
            pass
    for role in ("referee", "candidate_policy", "opponent_policy"):
        try:
            _docker_call(
                ["docker", "container", "rm", "--force", names[role]],
                timeout=docker_timeout,
            )
        except BaseException:
            pass


def _remove_exited(
    names: Mapping[str, str],
    *,
    docker_timeout: float,
) -> None:
    for role in ("referee", "candidate_policy", "opponent_policy"):
        try:
            _docker_call(
                ["docker", "container", "rm", "--force", names[role]],
                timeout=docker_timeout,
            )
        except BaseException:
            pass


class _Broker:
    def __init__(
        self,
        children: list[_Child],
        task: Mapping[str, Any],
        *,
        session_id: str,
        arm_claim_sha256: str,
        arm_deadline_seconds: float,
    ) -> None:
        self.children = children
        self.by_role = {child.role: child for child in children}
        self.task = task
        self.session_id = session_id
        self.arm_claim_sha256 = arm_claim_sha256
        self.action_deadline_seconds = float(task["max_action_seconds"])
        self.arm_deadline_seconds = arm_deadline_seconds
        self.state = ProtocolState()
        self.transcript = TranscriptAccumulator()
        self.transcript_records: list[dict[str, Any]] = []
        self.terminal_frame: Frame | None = None
        self.host_outcome: float | None = None
        self.winner_role: str | None = None
        self.winner_index: int | None = None
        self.output_budget = _OutputBudget()

    def _record(self, direction: str, frame: Frame) -> None:
        raw = frame.to_bytes()
        digest = self.transcript.add(direction, raw)
        self.transcript_records.append(
            {
                "direction": direction,
                "role": frame.role,
                "message_type": frame.message_type,
                "sequence": frame.sequence,
                "frame_sha256": _sha256_bytes(raw),
                "transcript_sha256": digest,
                "frame_base64": base64.b64encode(raw).decode("ascii"),
            }
        )

    def _accept(self, frame: Frame) -> None:
        try:
            self.state.accept(frame)
        except SandboxProtocolError as exc:
            raise SandboxArmFault(f"protocol state rejected {frame.message_type}: {exc}") from exc

    def _check_binding(self, payload: Mapping[str, Any]) -> None:
        if payload.get("session_id") != self.session_id:
            raise SandboxArmFault("frame session_id does not match the arm")
        if payload.get("arm_claim_sha256") != self.arm_claim_sha256:
            raise SandboxArmFault("frame claim does not match the arm")
        if payload.get("game_id") != GAME_ID:
            raise SandboxArmFault("frame game_id does not match the arm")

    def _handshake(self, deadline: float) -> None:
        for role in ("referee", "candidate_policy", "opponent_policy"):
            child = self.by_role[role]
            frame = _read_frame_from_child(
                child,
                self.children,
                deadline,
                monitor_other_stdout=False,
            )
            if frame.role != role or frame.message_type != "HELLO" or frame.sequence != 1:
                raise SandboxArmFault(f"unexpected handshake frame from {role}")
            try:
                hello = validate_hello(frame.payload, frame_role=role)
            except SandboxProtocolError as exc:
                raise SandboxArmFault(f"invalid HELLO from {role}: {exc}") from exc
            if (
                hello["session_id"] != self.session_id
                or hello["arm_claim_sha256"] != self.arm_claim_sha256
                or hello["sandbox_id"] != role
            ):
                raise SandboxArmFault(f"HELLO from {role} is not bound to this arm")
            self._accept(frame)
        for role in ("referee", "candidate_policy", "opponent_policy"):
            payload = {
                "schema": PROTOCOL_SCHEMA + "_ready_v1",
                "session_id": self.session_id,
                "arm_claim_sha256": self.arm_claim_sha256,
                "role": role,
                "sandbox_id": role,
                "protocol": PROTOCOL_SCHEMA,
                "hello_sequence": 1,
            }
            try:
                validate_ready(payload, frame_role=role)
                ready = Frame(role, "READY", 1, payload)
                raw = ready.to_bytes()
            except SandboxProtocolError as exc:
                raise SandboxArmFault(f"could not build READY for {role}: {exc}") from exc
            _write_ipc(self.by_role[role], raw, deadline)

    def _host_outcome(self, winner_role: str | None) -> tuple[float, int | None]:
        policy_left = self.task["seat"] == "policy_first"
        left_role = "candidate_policy" if policy_left else "opponent_policy"
        right_role = "opponent_policy" if policy_left else "candidate_policy"
        if winner_role is None:
            return 0.5, None
        if winner_role not in {left_role, right_role}:
            raise SandboxArmFault("terminal winner is not a policy role")
        winner_index = 0 if winner_role == left_role else 1
        policy_won = (winner_index == 0) is policy_left
        return (1.0 if policy_won else 0.0), winner_index

    def run(self) -> dict[str, Any]:
        started = time.monotonic()
        deadline = started + self.arm_deadline_seconds
        self._handshake(deadline)
        referee = self.by_role["referee"]
        while True:
            frame = _read_frame_from_child(
                referee,
                self.children,
                deadline,
                monitor_other_stdout=True,
                output_budget=self.output_budget,
            )
            if frame.role != "referee":
                raise SandboxArmFault("non-referee frame arrived on the referee channel")
            if frame.message_type == "ACTION_REQUEST":
                try:
                    request = validate_action_request(frame.payload)
                except SandboxProtocolError as exc:
                    raise SandboxArmFault(f"invalid ACTION_REQUEST: {exc}") from exc
                self._check_binding(request)
                if len(self.state.pending_request_ids) != 0:
                    raise SandboxArmFault("referee issued an action while another was pending")
                self._accept(frame)
                self._record("referee_to_policy", frame)
                target = self.by_role[request["actor_role"]]
                request_bytes = frame.to_bytes()
                _write_ipc(target, request_bytes, deadline)
                # The action clock begins only after the complete request is
                # in the policy pipe, as required by the external deadline.
                action_deadline = min(
                    deadline,
                    time.monotonic() + self.action_deadline_seconds,
                )
                response_frame = _read_frame_from_child(
                    target,
                    self.children,
                    action_deadline,
                    monitor_other_stdout=True,
                    output_budget=self.output_budget,
                )
                if response_frame.role != target.role or response_frame.message_type != "ACTION_RESPONSE":
                    raise SandboxArmFault("policy did not return its own ACTION_RESPONSE")
                try:
                    response = validate_action_response(
                        response_frame.payload,
                        legal_option_count=request["legal_option_count"],
                        expected_request=request,
                    )
                except SandboxProtocolError as exc:
                    raise SandboxArmFault(f"illegal, stale, or malformed policy action: {exc}") from exc
                self._check_binding(response)
                self._accept(response_frame)
                if time.monotonic() > action_deadline:
                    raise SandboxArmFault("external action deadline exceeded")
                self._record("policy_to_referee", response_frame)
                _write_ipc(referee, response_frame.to_bytes(), action_deadline)
                if time.monotonic() > action_deadline:
                    raise SandboxArmFault("external action deadline exceeded while relaying response")
                continue
            if frame.message_type == "TERMINAL":
                try:
                    terminal = validate_terminal(frame.payload)
                except SandboxProtocolError as exc:
                    raise SandboxArmFault(f"invalid referee TERMINAL: {exc}") from exc
                self._check_binding(terminal)
                self._accept(frame)
                if self.state.pending_request_ids:
                    raise SandboxArmFault("referee sent TERMINAL with a pending action")
                if terminal["outcome"] != "game_complete":
                    raise SandboxArmFault("referee reported a non-game terminal condition")
                self._record("referee_to_policy", frame)
                self.terminal_frame = frame
                self.winner_role = terminal["winner_role"]
                self.host_outcome, self.winner_index = self._host_outcome(self.winner_role)
                terminal_bytes = frame.to_bytes()
                for role in ("candidate_policy", "opponent_policy"):
                    _write_ipc(self.by_role[role], terminal_bytes, deadline)
                _close_stdin(self.children)
                _wait_clean(self.children, deadline, output_budget=self.output_budget)
                return {
                    "status": "SUCCESS",
                    "outcome": self.host_outcome,
                    "winner_role": self.winner_role,
                    "winner_index": self.winner_index,
                    "terminal_frame_sha256": _sha256_bytes(terminal_bytes),
                    "transcript_sha256": self.transcript.hexdigest,
                    "transcript_records": list(self.transcript_records),
                    "arm_duration_seconds": time.monotonic() - started,
                }
            raise SandboxArmFault(f"unexpected referee frame type: {frame.message_type}")


def _inspect_containers(
    children: list[_Child],
    snapshot: Path,
    *,
    image: str,
    session_id: str,
    arm_claim_sha256: str,
    cpu_millicores: int,
    memory_bytes: int,
    pids_limit: int,
    tmpfs_bytes: int,
    docker_timeout: float,
    strict: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for child in children:
        try:
            _, payload = _docker_json(
                ["docker", "container", "inspect", child.name],
                timeout=docker_timeout,
            )
            if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
                raise SandboxArmFault(f"invalid inspect payload for {child.role}")
            row = dict(payload[0])
            try:
                image_position = child.command.index(image)
            except ValueError as exc:
                raise SandboxArmFault(f"frozen command for {child.role} lacks the pinned image") from exc
            result[child.role] = _validate_observed_container(
                row,
                child.role,
                snapshot,
                image=image,
                expected_command=child.command[image_position + 1 :],
                session_id=session_id,
                arm_claim_sha256=arm_claim_sha256,
                cpu_millicores=cpu_millicores,
                memory_bytes=memory_bytes,
                pids_limit=pids_limit,
                tmpfs_bytes=tmpfs_bytes,
            )
        except BaseException as exc:
            if strict:
                if isinstance(exc, SandboxArmFault):
                    raise
                raise SandboxArmFault(f"container evidence failed for {child.role}: {exc}") from exc
            result[child.role] = {
                "role": child.role,
                "inspect_error": f"{type(exc).__name__}: {exc}",
            }
    return result


def _artifact_files(root: Path, *, exclude: set[str]) -> dict[str, dict[str, Any]]:
    files: dict[str, dict[str, Any]] = {}
    for item in sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix()):
        if not item.is_file():
            continue
        relative = item.relative_to(root).as_posix()
        if relative in exclude:
            continue
        data = item.read_bytes()
        files[relative] = {"sha256": _sha256_bytes(data), "size_bytes": len(data)}
    return files


def _write_artifacts(
    artifact_root: Path,
    children: list[_Child],
    commands: Mapping[str, list[str]],
    inspect_records: Mapping[str, Any],
    broker_result: Mapping[str, Any] | None,
    *,
    fault: str | None,
    campaign_sha256: str,
    arm_claim_sha256: str,
    snapshot_manifest: Mapping[str, Any],
    parent_binding: Mapping[str, Any] | None = None,
    terminal_status: str | None = None,
    launch_state: str | None = None,
) -> dict[str, Any]:
    if parent_binding is None and (terminal_status is not None or launch_state is not None):
        raise SandboxArmError("standalone artifacts may not carry parent launch disposition")
    if parent_binding is not None and (
        terminal_status not in {CAMPAIGN_SUCCESS, CAMPAIGN_FAILURE, CAMPAIGN_BURN}
        or launch_state not in {START_DURABLE_POPEN_UNCERTAIN, POPEN_OBSERVED}
    ):
        raise SandboxArmError("parent artifacts require an exact terminal and launch disposition")
    raw_root = artifact_root / "raw"
    for child in children:
        role_root = raw_root / child.role
        _write_bytes(role_root / "stdin.bin", bytes(child.stdin_bytes))
        _write_bytes(role_root / "stdout.bin", bytes(child.stdout_bytes))
        _write_bytes(role_root / "stderr.bin", bytes(child.stderr_bytes))
        _write_json(
            artifact_root / "containers" / f"{child.role}.command.json",
            {"role": child.role, "command": commands[child.role]},
        )
        _write_json(
            artifact_root / "containers" / f"{child.role}.inspect.json",
            inspect_records.get(child.role, {"role": child.role, "inspect_error": "absent"}),
        )
    transcript = {
        "schema": "evaluation_v4_2_deterministic_sandbox_transcript_v1",
        "frames": list((broker_result or {}).get("transcript_records", [])),
        "transcript_sha256": (broker_result or {}).get("transcript_sha256"),
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    _write_json(artifact_root / "transcript.json", transcript)
    files = _artifact_files(artifact_root, exclude={"artifact_manifest.json", "terminal_evidence.json"})
    scope = "parent_bound_campaign_arm" if parent_binding is not None else "single_arm"
    artifact_manifest = {
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "scope": scope,
        "files": files,
        "tree_sha256": canonical_sha256(files),
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    _write_json(artifact_root / "artifact_manifest.json", artifact_manifest)
    terminal_evidence: dict[str, Any] = {
        "schema": (
            PARENT_BOUND_ARM_RESULT_SCHEMA + "_evidence_v1"
            if parent_binding is not None
            else ARM_RESULT_SCHEMA + "_evidence_v1"
        ),
        "scope": scope,
        "arm_claim_sha256": arm_claim_sha256,
        "campaign_sha256": campaign_sha256,
        "snapshot_tree_sha256": snapshot_manifest["tree_sha256"],
        "artifact_manifest_sha256": canonical_sha256(artifact_manifest),
        "artifact_files": files,
        "status": (
            terminal_status
            if parent_binding is not None
            else "FAILURE" if fault is not None else "SUCCESS"
        ),
        "fault": fault,
        "host_outcome": (broker_result or {}).get("outcome"),
        "winner_role": (broker_result or {}).get("winner_role"),
        "winner_index": (broker_result or {}).get("winner_index"),
        "transcript_sha256": (broker_result or {}).get("transcript_sha256"),
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": PARENT_GATE_STATEMENT,
        "authority_statement": AUTHORITY_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    if parent_binding is not None:
        terminal_evidence["parent_binding"] = dict(parent_binding)
        terminal_evidence["terminal_status"] = terminal_status
        terminal_evidence["launch_state"] = launch_state
    _write_json(artifact_root / "terminal_evidence.json", terminal_evidence)
    return terminal_evidence


def _install_witness_cas(
    journal: WitnessJournal,
    artifact_root: Path,
    terminal_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Copy every raw artifact referenced by the terminal packet into CAS."""

    raw_files = terminal_evidence.get("artifact_files")
    if not isinstance(raw_files, Mapping):
        raise SandboxArmError("terminal evidence lacks an artifact file manifest")
    witness_refs: dict[str, dict[str, Any]] = {}
    resolved_root = artifact_root.resolve()
    for relative, metadata in sorted(raw_files.items()):
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith("/")
            or ".." in Path(relative).parts
            or not isinstance(metadata, Mapping)
        ):
            raise SandboxArmError("terminal artifact manifest contains an unsafe entry")
        expected_sha256 = _require_digest(
            metadata.get("sha256"),
            f"artifact {relative} sha256",
        )
        expected_size = metadata.get("size_bytes")
        if isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0:
            raise SandboxArmError(f"artifact {relative} size is invalid")
        path = resolved_root.joinpath(*Path(relative).parts)
        if not path.is_file() or path.is_symlink():
            raise SandboxArmError(f"artifact {relative} is not a regular file")
        payload = path.read_bytes()
        if len(payload) != expected_size or _sha256_bytes(payload) != expected_sha256:
            raise SandboxArmError(f"artifact {relative} changed before witness custody")
        installed = journal.evidence.put(payload, digest=expected_sha256)
        witness_refs[relative] = {
            "sha256": installed,
            "size_bytes": expected_size,
        }
    return {
        **dict(terminal_evidence),
        "witness_cas_complete": True,
        "witness_cas_file_count": len(witness_refs),
        "witness_cas_files": witness_refs,
    }


def _read_reopened_json(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    relative: str,
) -> Mapping[str, Any]:
    reference = reopened.get(relative)
    if not isinstance(reference, Mapping):
        raise SandboxArmError(f"witness CAS is missing {relative}")
    payload = journal.evidence.read(_require_digest(reference.get("sha256"), relative))
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxArmError(f"witness CAS {relative} is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise SandboxArmError(f"witness CAS {relative} must be an object")
    if payload != canonical_json_bytes(dict(value)) + b"\n":
        raise SandboxArmError(f"witness CAS {relative} is not canonical JSON")
    return value


def _read_reopened_bytes(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    relative: str,
) -> bytes:
    reference = reopened.get(relative)
    if not isinstance(reference, Mapping):
        raise SandboxArmError(f"witness CAS is missing {relative}")
    payload = journal.evidence.read(_require_digest(reference.get("sha256"), relative))
    if len(payload) != reference.get("size_bytes"):
        raise SandboxArmError(f"witness CAS size differs for {relative}")
    return payload


_SANDBOX_ROLES = ("referee", "candidate_policy", "opponent_policy")
_SNAPSHOT_MARKER = Path("/__evaluation_v4_2_reopened_snapshot__")


def _verify_reopened_artifact_manifest(
    evidence: Mapping[str, Any],
    artifact_files: Mapping[str, Any],
    *,
    scope: str = "single_arm",
) -> None:
    files = dict(artifact_files)
    manifest = {
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "scope": scope,
        "files": files,
        "tree_sha256": canonical_sha256(files),
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    if evidence.get("artifact_manifest_sha256") != canonical_sha256(manifest):
        raise SandboxArmError("terminal evidence artifact manifest differs from reopened artifacts")


def _verify_reopened_snapshot(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    snapshot_manifest: Mapping[str, Any],
) -> None:
    expected_fields = {
        "schema",
        "bundle_manifest_sha256",
        "files",
        "tree_sha256",
        "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
    if set(snapshot_manifest) != expected_fields:
        raise SandboxArmError("prepared snapshot manifest fields differ")
    if snapshot_manifest.get("schema") != "evaluation_v4_2_development_private_snapshot_v1":
        raise SandboxArmError("prepared snapshot manifest schema differs")
    if snapshot_manifest.get("authority") != "DEVELOPMENT_ONLY":
        raise SandboxArmError("prepared snapshot manifest authority differs")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if snapshot_manifest.get(field) is not expected:
            raise SandboxArmError(f"prepared snapshot authority field changed: {field}")
    records = snapshot_manifest.get("files")
    if not isinstance(records, list) or not records:
        raise SandboxArmError("prepared snapshot manifest has no file records")
    previous = ""
    expected_paths: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != {"path", "sha256"}:
            raise SandboxArmError("prepared snapshot file record is malformed")
        path = record.get("path")
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or ".." in PurePosixPath(path).parts
            or path <= previous
            or path in expected_paths
        ):
            raise SandboxArmError("prepared snapshot file paths are not a canonical tree")
        previous = path
        expected_paths.add(path)
        digest = _require_digest(record.get("sha256"), f"prepared snapshot {path}")
        payload = _read_reopened_bytes(journal, reopened, f"snapshot/{path}")
        if _sha256_bytes(payload) != digest:
            raise SandboxArmError(f"reopened snapshot file differs: {path}")
    reopened_snapshot_paths = {
        relative.removeprefix("snapshot/")
        for relative in reopened
        if relative.startswith("snapshot/")
    }
    if reopened_snapshot_paths != expected_paths:
        raise SandboxArmError("witness CAS snapshot does not exactly match the prepared manifest")
    if snapshot_manifest.get("tree_sha256") != canonical_sha256(records):
        raise SandboxArmError("prepared snapshot tree digest differs")


def _single_command_option(command: list[str], option: str) -> str:
    positions = [index for index, value in enumerate(command) if value == option]
    if len(positions) != 1 or positions[0] + 1 >= len(command):
        raise SandboxArmError(f"sealed container command lacks one {option} option")
    return command[positions[0] + 1]


def _command_resources(command: list[str]) -> tuple[int, int, int, int]:
    def positive_integer(option: str) -> int:
        value = _single_command_option(command, option)
        if not value.isdecimal() or int(value) <= 0:
            raise SandboxArmError(f"sealed container {option} is not a positive integer")
        return int(value)

    pids_limit = positive_integer("--pids-limit")
    memory_bytes = positive_integer("--memory")
    if _single_command_option(command, "--memory-swap") != str(memory_bytes):
        raise SandboxArmError("sealed container memory-swap differs from memory")
    cpu_text = _single_command_option(command, "--cpus")
    try:
        cpu_millicores = int(round(float(cpu_text) * 1000))
    except ValueError as exc:
        raise SandboxArmError("sealed container CPU limit is malformed") from exc
    if cpu_millicores <= 0 or cpu_text != f"{cpu_millicores / 1000.0:.3f}":
        raise SandboxArmError("sealed container CPU limit is not canonical")
    tmpfs = _single_command_option(command, "--tmpfs")
    prefix = "/tmp:rw,noexec,nosuid,nodev,size="
    suffix = ",mode=700,uid=65534,gid=65534"
    if not tmpfs.startswith(prefix) or not tmpfs.endswith(suffix):
        raise SandboxArmError("sealed container tmpfs binding differs")
    tmpfs_size = tmpfs[len(prefix) : -len(suffix)]
    if not tmpfs_size.isdecimal() or int(tmpfs_size) <= 0:
        raise SandboxArmError("sealed container tmpfs size is malformed")
    return cpu_millicores, memory_bytes, pids_limit, int(tmpfs_size)


def _command_mounts(command: list[str]) -> list[dict[str, str]]:
    mounts: list[dict[str, str]] = []
    for index, token in enumerate(command):
        if token != "--mount":
            continue
        if index + 1 >= len(command):
            raise SandboxArmError("sealed container command ends with --mount")
        parts = command[index + 1].split(",")
        values: dict[str, str] = {}
        flags: set[str] = set()
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                if key in values:
                    raise SandboxArmError("sealed container mount repeats a field")
                values[key] = value
            else:
                flags.add(part)
        if values.get("type") != "bind" or flags != {"readonly"} or set(values) != {
            "type", "source", "target", "bind-propagation"
        } or values["bind-propagation"] != "rprivate":
            raise SandboxArmError("sealed container mount is not the required read-only bind")
        mounts.append({"source": values["source"], "destination": values["target"]})
    if not mounts:
        raise SandboxArmError("sealed container command has no mounts")
    return mounts


def _snapshot_root_from_command(role: str, command: list[str]) -> Path:
    expected_suffixes = {
        "referee": {
            "/input/engine": "engine",
            "/input/decks": "decks",
            "/input/task.json": "task.json",
            "/input/runtime": "runtime",
        },
        "candidate_policy": {"/input/policy": "policy", "/input/runtime": "runtime"},
        "opponent_policy": {"/input/opponent": "opponent", "/input/runtime": "runtime"},
    }[role]
    mounts = _command_mounts(command)
    if {mount["destination"] for mount in mounts} != set(expected_suffixes):
        raise SandboxArmError(f"sealed {role} command mount topology differs")
    roots: set[Path] = set()
    for mount in mounts:
        source = PurePosixPath(mount["source"])
        suffix = PurePosixPath(expected_suffixes[mount["destination"]])
        if not source.is_absolute() or source.parts[-len(suffix.parts) :] != suffix.parts:
            raise SandboxArmError(f"sealed {role} command mount source differs")
        roots.add(Path(*source.parts[: -len(suffix.parts)]))
    if len(roots) != 1:
        raise SandboxArmError(f"sealed {role} command mounts do not share one snapshot")
    return roots.pop()


def _normalize_snapshot_command(command: list[str], snapshot_root: Path) -> list[str]:
    root = str(snapshot_root)
    if not root.startswith("/") or any("$SNAPSHOT" in token for token in command):
        raise SandboxArmError("sealed container command has an unsafe snapshot reference")
    return [token.replace(root, "$SNAPSHOT") for token in command]


def _verify_reopened_launch_evidence(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    prepared: Mapping[str, Any],
    started: Mapping[str, Any],
    packet: Mapping[str, Any],
    task: Mapping[str, Any],
    *,
    expected_campaign_sha256: str,
    expected_claim_sha256: str,
) -> bool:
    required_prepared = {
        "schema", "scope", "campaign_sha256", "arm_claim_sha256", "snapshot_manifest",
        "container_names", "reserved_child_arm_identities", "container_commands",
        "panel_parent_claim_verified", "parent_campaign_gate_required",
        "parent_campaign_gate_statement", "authority", *FALSE_AUTHORITY_FLAGS,
    }
    required_started = {
        "schema", "scope", "campaign_sha256", "arm_claim_sha256", "prepared_evidence_sha256",
        "reserved_child_arm_identities", "panel_parent_claim_verified",
        "parent_campaign_gate_required", "parent_campaign_gate_statement", "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
    if set(prepared) != required_prepared or prepared.get("schema") != ARM_RESULT_SCHEMA + "_prepared_v1":
        raise SandboxArmError("prepared evidence is not the exact launch record")
    if set(started) != required_started or started.get("schema") != ARM_RESULT_SCHEMA + "_started_v1":
        raise SandboxArmError("started evidence is not the exact launch record")
    if started.get("prepared_evidence_sha256") != packet.get("prepared_evidence_sha256"):
        raise SandboxArmError("started evidence does not bind the prepared evidence")
    for label, record in (("prepared", prepared), ("started", started)):
        if (
            record.get("scope") != "single_arm"
            or record.get("campaign_sha256") != expected_campaign_sha256
            or record.get("arm_claim_sha256") != expected_claim_sha256
            or record.get("panel_parent_claim_verified") is not False
            or record.get("parent_campaign_gate_required") is not True
            or record.get("parent_campaign_gate_statement") != PARENT_GATE_STATEMENT
            or record.get("authority") != "DEVELOPMENT_ONLY"
        ):
            raise SandboxArmError(f"{label} evidence does not bind the claimed arm")
        for field, expected in FALSE_AUTHORITY_FLAGS.items():
            if record.get(field) is not expected:
                raise SandboxArmError(f"{label} authority field changed: {field}")
    names = deterministic_container_names(str(packet.get("attempt_id")))
    if prepared.get("container_names") != names:
        raise SandboxArmError("prepared container names are not deterministic")
    sealed_commands: dict[str, list[str]] = {}
    snapshot_roots: set[Path] = set()
    images: set[str] = set()
    command_templates: dict[str, list[str]] = {}
    for role in _SANDBOX_ROLES:
        command_record = _read_reopened_json(journal, reopened, f"containers/{role}.command.json")
        command = command_record.get("command")
        if set(command_record) != {"role", "command"} or command_record.get("role") != role:
            raise SandboxArmError(f"sealed {role} command record is malformed")
        if not isinstance(command, list) or not all(isinstance(token, str) for token in command):
            raise SandboxArmError(f"sealed {role} command is not a token list")
        if command.count("python") != 1:
            raise SandboxArmError(f"sealed {role} command lacks the worker interpreter")
        image_index = command.index("python") - 1
        if image_index < 0:
            raise SandboxArmError(f"sealed {role} command lacks the image")
        image = command[image_index]
        _image_digest(image)
        images.add(image)
        resources = _command_resources(command)
        snapshot_root = _snapshot_root_from_command(role, command)
        snapshot_roots.add(snapshot_root)
        expected = build_docker_command(
            role,
            _SNAPSHOT_MARKER,
            image=image,
            name=names[role],
            session_id=f"sbx-{expected_campaign_sha256[:32]}",
            arm_claim_sha256=expected_claim_sha256,
            task=task,
            cpu_millicores=resources[0],
            memory_bytes=resources[1],
            pids_limit=resources[2],
            tmpfs_bytes=resources[3],
        )
        normalized = _normalize_snapshot_command(command, snapshot_root)
        expected_template = _normalize_snapshot_command(expected, _SNAPSHOT_MARKER)
        if normalized != expected_template:
            raise SandboxArmError(f"sealed {role} command differs from the exact launch template")
        sealed_commands[role] = command
        command_templates[role] = normalized
    if len(images) != 1 or len(snapshot_roots) != 1:
        raise SandboxArmError("sealed containers do not share one image and snapshot")
    if prepared.get("container_commands") != command_templates:
        raise SandboxArmError("prepared container commands differ from sealed launch commands")
    identities = [
        {
            "role": role,
            "container_name": names[role],
            "command_sha256": canonical_sha256(sealed_commands[role]),
        }
        for role in _SANDBOX_ROLES
    ]
    if prepared.get("reserved_child_arm_identities") != identities:
        raise SandboxArmError("prepared child identities differ from sealed launch commands")
    if started.get("reserved_child_arm_identities") != identities:
        raise SandboxArmError("started child identities differ from prepared evidence")

    policy_sources: dict[str, str] = {}
    for role in _SANDBOX_ROLES:
        inspect = _read_reopened_json(journal, reopened, f"containers/{role}.inspect.json")
        config = inspect.get("config")
        host = inspect.get("host_config")
        mounts = inspect.get("mounts")
        if inspect.get("role") != role or "inspect_error" in inspect:
            raise SandboxArmError(f"sealed {role} inspect record is unavailable")
        if not isinstance(config, Mapping) or not isinstance(host, Mapping) or not isinstance(mounts, list):
            raise SandboxArmError(f"sealed {role} inspect record is malformed")
        command = sealed_commands[role]
        image_index = command.index("python") - 1
        image = command[image_index]
        resources = _command_resources(command)
        expected_labels = {
            "evaluation_v4_2.role": role,
            "evaluation_v4_2.session_id": f"sbx-{expected_campaign_sha256[:32]}",
            "evaluation_v4_2.claim_sha256": expected_claim_sha256,
        }
        if (
            config.get("User") != CONTAINER_USER
            or config.get("Image") != image
            or config.get("Cmd") != command[image_index + 1 :]
            or config.get("OpenStdin") is not True
            or config.get("Tty") is not False
            or not isinstance(config.get("Labels"), Mapping)
            or dict(config["Labels"]) != expected_labels
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or sorted(host.get("CapDrop") or []) != ["ALL"]
            or not any(value in {"no-new-privileges", "no-new-privileges=true"} for value in (host.get("SecurityOpt") or []))
            or host.get("PidMode") not in {"", "private"}
            or host.get("IpcMode") not in {"", "private"}
            or host.get("PidsLimit") != resources[2]
            or host.get("Memory") != resources[1]
            or host.get("MemorySwap") != resources[1]
            or int(host.get("NanoCpus") or 0) != resources[0] * 1_000_000
        ):
            raise SandboxArmError(f"sealed {role} inspect bindings differ from the exact command")
        tmpfs = host.get("Tmpfs")
        if not isinstance(tmpfs, Mapping) or f"size={resources[3]}" not in str(tmpfs.get("/tmp")):
            raise SandboxArmError(f"sealed {role} inspect tmpfs differs from the exact command")
        expected_mounts = _command_mounts(command)
        observed_mounts: dict[str, Mapping[str, Any]] = {}
        for mount in mounts:
            if not isinstance(mount, Mapping) or not isinstance(mount.get("destination"), str):
                raise SandboxArmError(f"sealed {role} inspect mount is malformed")
            destination = mount["destination"]
            if destination in observed_mounts:
                raise SandboxArmError(f"sealed {role} inspect repeats a mount")
            observed_mounts[destination] = mount
        if set(observed_mounts) != {mount["destination"] for mount in expected_mounts}:
            raise SandboxArmError(f"sealed {role} inspect mount set differs from command")
        for expected_mount in expected_mounts:
            observed = observed_mounts[expected_mount["destination"]]
            if (
                observed.get("type") != "bind"
                or observed.get("source") != expected_mount["source"]
                or observed.get("read_only") is not True
                or observed.get("propagation") != "rprivate"
            ):
                raise SandboxArmError(f"sealed {role} inspect mount differs from command")
            if expected_mount["destination"] in {"/input/policy", "/input/opponent"}:
                policy_sources[role] = str(observed["source"])
    return (
        set(policy_sources) == {"candidate_policy", "opponent_policy"}
        and policy_sources["candidate_policy"] != policy_sources["opponent_policy"]
    )


def _parse_frame_stream(payload: bytes, label: str) -> list[tuple[bytes, Frame]]:
    stream = io.BytesIO(payload)
    frames: list[tuple[bytes, Frame]] = []
    while stream.tell() < len(payload):
        start = stream.tell()
        try:
            frame = read_next_frame(stream)
        except SandboxProtocolError as exc:
            raise SandboxArmError(f"sealed raw channel {label} is not a complete frame stream") from exc
        frames.append((payload[start : stream.tell()], frame))
    return frames


def _verify_raw_channel_binding(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    records: list[tuple[str, bytes, Frame]],
    *,
    expected_session_id: str,
    expected_claim_sha256: str,
) -> None:
    channels: dict[tuple[str, str], list[tuple[bytes, Frame]]] = {}
    for role in ("referee", "candidate_policy", "opponent_policy"):
        for stream in ("stdin", "stdout"):
            relative = f"raw/{role}/{stream}.bin"
            channels[(role, stream)] = _parse_frame_stream(
                _read_reopened_bytes(journal, reopened, relative),
                relative,
            )

    hellos: dict[str, Frame] = {}
    for role in ("referee", "candidate_policy", "opponent_policy"):
        stdout = channels[(role, "stdout")]
        stdin = channels[(role, "stdin")]
        if not stdout or stdout[0][1].message_type != "HELLO" or stdout[0][1].role != role:
            raise SandboxArmError(f"sealed {role} stdout lacks its initial HELLO")
        if not stdin or stdin[0][1].message_type != "READY" or stdin[0][1].role != role:
            raise SandboxArmError(f"sealed {role} stdin lacks its initial READY")
        hello = validate_hello(stdout[0][1].payload, frame_role=role)
        ready = validate_ready(stdin[0][1].payload, frame_role=role)
        if (
            hello["session_id"] != expected_session_id
            or hello["arm_claim_sha256"] != expected_claim_sha256
            or ready["session_id"] != expected_session_id
            or ready["arm_claim_sha256"] != expected_claim_sha256
        ):
            raise SandboxArmError(f"sealed {role} handshake does not bind the claimed arm")
        hellos[role] = stdout[0][1]

    state = ProtocolState()
    for role in ("referee", "candidate_policy", "opponent_policy"):
        try:
            state.accept(hellos[role])
        except SandboxProtocolError as exc:
            raise SandboxArmError(f"sealed {role} HELLO violates protocol state") from exc
    for index, (direction, _raw, frame) in enumerate(records):
        if frame.payload.get("game_id") != GAME_ID:
            raise SandboxArmError(f"transcript record {index} does not bind {GAME_ID}")
        if direction == "referee_to_policy":
            if frame.role != "referee" or frame.message_type not in {"ACTION_REQUEST", "TERMINAL"}:
                raise SandboxArmError(f"transcript record {index} has an invalid referee direction")
        elif direction == "policy_to_referee":
            if frame.role not in {"candidate_policy", "opponent_policy"} or frame.message_type != "ACTION_RESPONSE":
                raise SandboxArmError(f"transcript record {index} has an invalid policy direction")
        else:
            raise SandboxArmError(f"transcript record {index} has an invalid direction")
        try:
            state.accept(frame)
        except SandboxProtocolError as exc:
            raise SandboxArmError(f"transcript record {index} violates protocol state") from exc
    if state.pending_request_ids:
        raise SandboxArmError("sealed transcript leaves pending action requests")

    referee_to_policy = [raw for direction, raw, _frame in records if direction == "referee_to_policy"]
    policy_to_referee = [raw for direction, raw, _frame in records if direction == "policy_to_referee"]
    if [raw for raw, _frame in channels[("referee", "stdout")][1:]] != referee_to_policy:
        raise SandboxArmError("transcript differs from sealed referee stdout")
    if [raw for raw, _frame in channels[("referee", "stdin")][1:]] != policy_to_referee:
        raise SandboxArmError("transcript differs from sealed referee stdin")

    for role in ("candidate_policy", "opponent_policy"):
        expected_stdout = [
            raw
            for direction, raw, frame in records
            if direction == "policy_to_referee" and frame.role == role
        ]
        expected_stdin: list[bytes] = []
        for direction, raw, frame in records:
            if direction != "referee_to_policy":
                continue
            if frame.message_type == "TERMINAL":
                expected_stdin.append(raw)
            elif frame.payload.get("actor_role") == role:
                expected_stdin.append(raw)
        if [raw for raw, _frame in channels[(role, "stdout")][1:]] != expected_stdout:
            raise SandboxArmError(f"transcript differs from sealed {role} stdout")
        if [raw for raw, _frame in channels[(role, "stdin")][1:]] != expected_stdin:
            raise SandboxArmError(f"transcript differs from sealed {role} stdin")


def _verify_reopened_transcript(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Any],
    *,
    expected_session_id: str,
    expected_claim_sha256: str,
) -> tuple[str | None, str | None, float | None]:
    transcript = _read_reopened_json(journal, reopened, "transcript.json")
    if transcript.get("schema") != "evaluation_v4_2_deterministic_sandbox_transcript_v1":
        raise SandboxArmError("witness transcript schema differs")
    if transcript.get("authority") != "DEVELOPMENT_ONLY":
        raise SandboxArmError("witness transcript authority differs")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if transcript.get(field) is not expected:
            raise SandboxArmError(f"witness transcript authority field changed: {field}")
    records = transcript.get("frames")
    if not isinstance(records, list):
        raise SandboxArmError("witness transcript frames must be a list")
    declared_digest = transcript.get("transcript_sha256")
    if declared_digest != evidence.get("transcript_sha256"):
        raise SandboxArmError("witness transcript digest differs from terminal evidence")
    if not records:
        if declared_digest is not None:
            raise SandboxArmError("empty witness transcript declares a digest")
        return None, None, None

    accumulator = TranscriptAccumulator()
    final_frame: Frame | None = None
    verified_records: list[tuple[str, bytes, Frame]] = []
    expected_fields = {
        "direction",
        "role",
        "message_type",
        "sequence",
        "frame_sha256",
        "transcript_sha256",
        "frame_base64",
    }
    for index, record in enumerate(records):
        if not isinstance(record, Mapping) or set(record) != expected_fields:
            raise SandboxArmError(f"witness transcript record {index} is malformed")
        encoded = record.get("frame_base64")
        if not isinstance(encoded, str):
            raise SandboxArmError(f"witness transcript record {index} lacks frame bytes")
        try:
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
            frame = decode_frame(raw)
        except (UnicodeEncodeError, ValueError, SandboxProtocolError) as exc:
            raise SandboxArmError(f"witness transcript record {index} has an invalid frame") from exc
        if (
            record.get("direction") not in {"referee_to_policy", "policy_to_referee"}
            or record.get("role") != frame.role
            or record.get("message_type") != frame.message_type
            or record.get("sequence") != frame.sequence
            or record.get("frame_sha256") != _sha256_bytes(raw)
        ):
            raise SandboxArmError(f"witness transcript record {index} metadata differs")
        chained = accumulator.add(str(record["direction"]), raw)
        if record.get("transcript_sha256") != chained:
            raise SandboxArmError(f"witness transcript record {index} chain differs")
        verified_records.append((str(record["direction"]), raw, frame))
        final_frame = frame

    if declared_digest != accumulator.hexdigest:
        raise SandboxArmError("witness transcript final chain differs")
    if final_frame is None or final_frame.role != "referee" or final_frame.message_type != "TERMINAL":
        raise SandboxArmError("witness transcript does not end in a referee terminal frame")
    _verify_raw_channel_binding(
        journal,
        reopened,
        verified_records,
        expected_session_id=expected_session_id,
        expected_claim_sha256=expected_claim_sha256,
    )
    try:
        terminal = validate_terminal(final_frame.payload)
    except SandboxProtocolError as exc:
        raise SandboxArmError("witness transcript terminal frame is invalid") from exc
    requests = [
        validate_action_request(frame.payload)
        for _direction, _raw, frame in verified_records
        if frame.message_type == "ACTION_REQUEST"
    ]
    expected_request_id = requests[-1]["request_id"] if requests else "start-0"
    expected_turn_id = requests[-1]["turn_id"] if requests else 0
    if (
        terminal["game_id"] != GAME_ID
        or terminal["request_id"] != expected_request_id
        or terminal["turn_id"] != expected_turn_id
    ):
        raise SandboxArmError("witness terminal does not close the final sealed request")
    winner_role = terminal["winner_role"]
    host_outcome = 0.5 if winner_role is None else (1.0 if winner_role == "candidate_policy" else 0.0)
    if evidence.get("winner_role") != winner_role or evidence.get("host_outcome") != host_outcome:
        raise SandboxArmError("witness terminal outcome differs from the sealed transcript")
    return accumulator.hexdigest, winner_role, host_outcome


def _verify_reopened_isolation(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
) -> bool:
    expected_mounts = {
        "referee": {"/input/engine", "/input/decks", "/input/task.json", "/input/runtime"},
        "candidate_policy": {"/input/policy", "/input/runtime"},
        "opponent_policy": {"/input/opponent", "/input/runtime"},
    }
    policy_sources: dict[str, str] = {}
    for role, destinations in expected_mounts.items():
        inspect = _read_reopened_json(
            journal,
            reopened,
            f"containers/{role}.inspect.json",
        )
        if inspect.get("role") != role or "inspect_error" in inspect:
            return False
        config = inspect.get("config")
        host = inspect.get("host_config")
        mounts = inspect.get("mounts")
        if not isinstance(config, Mapping) or not isinstance(host, Mapping) or not isinstance(mounts, list):
            return False
        if (
            config.get("User") != CONTAINER_USER
            or config.get("OpenStdin") is not True
            or config.get("Tty") is not False
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or sorted(host.get("CapDrop") or []) != ["ALL"]
            or not any(
                option in {"no-new-privileges", "no-new-privileges=true"}
                for option in (host.get("SecurityOpt") or [])
            )
            or host.get("PidMode") not in {"", "private"}
            or host.get("IpcMode") not in {"", "private"}
        ):
            return False
        observed: set[str] = set()
        for mount in mounts:
            if not isinstance(mount, Mapping):
                return False
            destination = mount.get("destination")
            source = mount.get("source")
            if (
                destination not in destinations
                or not isinstance(source, str)
                or mount.get("type") != "bind"
                or mount.get("read_only") is not True
                or mount.get("propagation") != "rprivate"
                or "docker.sock" in source
            ):
                return False
            observed.add(str(destination))
            if destination in {"/input/policy", "/input/opponent"}:
                policy_sources[role] = source
        if observed != destinations:
            return False
    return (
        set(policy_sources) == {"candidate_policy", "opponent_policy"}
        and Path(policy_sources["candidate_policy"]).resolve()
        != Path(policy_sources["opponent_policy"]).resolve()
    )


def _read_journal_json_evidence(
    journal: WitnessJournal,
    digest: object,
    label: str,
) -> Mapping[str, Any]:
    payload = journal.evidence.read(_require_digest(digest, label))
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxArmError(f"{label} is not valid JSON") from exc
    if not isinstance(value, Mapping) or payload != canonical_json_bytes(dict(value)):
        raise SandboxArmError(f"{label} is not canonical JSON")
    return value


def _reopen_witness_file_set(
    journal: WitnessJournal,
    evidence: Mapping[str, Any],
) -> tuple[Mapping[str, Any], dict[str, dict[str, Any]]]:
    artifact_files = evidence.get("artifact_files")
    witness_files = evidence.get("witness_cas_files")
    if not isinstance(artifact_files, Mapping) or not isinstance(witness_files, Mapping):
        raise SandboxArmError("witness terminal evidence lacks CAS file references")
    if set(artifact_files) != set(witness_files):
        raise SandboxArmError("witness CAS references do not exactly cover raw artifacts")
    reopened: dict[str, dict[str, Any]] = {}
    for relative in sorted(witness_files):
        artifact = artifact_files[relative]
        reference = witness_files[relative]
        if not isinstance(artifact, Mapping) or not isinstance(reference, Mapping):
            raise SandboxArmError("witness CAS file reference is malformed")
        if dict(artifact) != dict(reference):
            raise SandboxArmError(f"witness CAS reference differs for {relative}")
        digest = _require_digest(reference.get("sha256"), f"witness CAS {relative}")
        size = reference.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SandboxArmError(f"witness CAS size is invalid for {relative}")
        payload = journal.evidence.read(digest)
        if len(payload) != size:
            raise SandboxArmError(f"witness CAS size differs for {relative}")
        reopened[relative] = {"sha256": digest, "size_bytes": size}
    if evidence.get("witness_cas_file_count") != len(reopened):
        raise SandboxArmError("witness CAS file count differs from reopened artifacts")
    return artifact_files, reopened


def _parent_claim_state(claim: Mapping[str, Any]) -> dict[str, Any]:
    wave = claim.get("wave")
    if isinstance(wave, bool) or not isinstance(wave, int) or wave < 0:
        raise SandboxArmError("parent-bound child claim wave is invalid")
    return {
        "campaign_id": claim.get("campaign_id"),
        "authority_id": claim.get("campaign_authority_id"),
        "root_id": claim.get("campaign_root_id"),
        "claim_event_sha256": claim.get("parent_claim_event_sha256"),
        "arm_witness_authority_id": claim.get("arm_witness_authority_id"),
        "arm_witness_root_id": claim.get("arm_witness_root_id"),
        "prepared_manifest_sha256": claim.get("prepared_manifest_sha256"),
        "prepare_event_sha256": claim.get("parent_prepare_event_sha256"),
        "start_evidence_sha256": claim.get("parent_start_evidence_sha256"),
        "start_event_sha256": claim.get("parent_start_event_sha256"),
        "wave_start_event_sha256s": {
            str(wave): claim.get("parent_wave_start_event_sha256")
        },
        "wave_runtime_verification_sha256s": {
            str(wave): claim.get("wave_runtime_verification_sha256")
        },
    }


def _verify_parent_reopened_launch(
    journal: WitnessJournal,
    reopened: Mapping[str, Mapping[str, Any]],
    template: Mapping[str, Any],
    *,
    names: Mapping[str, str],
    child_claim_sha256: str,
    arm_bound_event_sha256: str,
    child_start_event_sha256: str,
    session_id: str,
) -> bool:
    commands: dict[str, list[str]] = {}
    roots: set[Path] = set()
    for role in _SANDBOX_ROLES:
        record = _read_reopened_json(journal, reopened, f"containers/{role}.command.json")
        command = record.get("command")
        if set(record) != {"role", "command"} or record.get("role") != role:
            raise SandboxArmError(f"sealed parent {role} command record is malformed")
        if not isinstance(command, list) or not all(isinstance(token, str) for token in command):
            raise SandboxArmError(f"sealed parent {role} command is not a token list")
        if _single_command_option(command, "--name") != names[role]:
            raise SandboxArmError(f"sealed parent {role} container name differs")
        roots.add(_snapshot_root_from_command(role, command))
        commands[role] = command
    if len(roots) != 1:
        raise SandboxArmError("sealed parent commands do not share one snapshot")
    snapshot_root = roots.pop()
    expected_commands = _materialize_parent_commands(
        template,
        snapshot=snapshot_root,
        child_claim_sha256=child_claim_sha256,
        arm_bound_event_sha256=arm_bound_event_sha256,
        child_start_event_sha256=child_start_event_sha256,
        session_id=session_id,
    )
    if commands != expected_commands:
        raise SandboxArmError("sealed parent commands differ from the prepared template")

    policy_sources: dict[str, str] = {}
    expected_labels_base = {
        "evaluation_v4_2.session_id": session_id,
        "evaluation_v4_2.claim_sha256": child_claim_sha256,
        "evaluation_v4_2.arm_bound_event_sha256": arm_bound_event_sha256,
        "evaluation_v4_2.child_start_event_sha256": child_start_event_sha256,
    }
    for role in _SANDBOX_ROLES:
        command = commands[role]
        if command.count("python") != 1:
            raise SandboxArmError(f"sealed parent {role} command lacks its worker interpreter")
        image_index = command.index("python") - 1
        if image_index < 0:
            raise SandboxArmError(f"sealed parent {role} command lacks its pinned image")
        image = command[image_index]
        _image_digest(image)
        resources = _command_resources(command)
        inspect = _read_reopened_json(journal, reopened, f"containers/{role}.inspect.json")
        config = inspect.get("config")
        host = inspect.get("host_config")
        mounts = inspect.get("mounts")
        if (
            inspect.get("role") != role
            or "inspect_error" in inspect
            or not isinstance(config, Mapping)
            or not isinstance(host, Mapping)
            or not isinstance(mounts, list)
        ):
            raise SandboxArmError(f"sealed parent {role} inspect record is malformed")
        expected_labels = {"evaluation_v4_2.role": role, **expected_labels_base}
        if (
            config.get("User") != CONTAINER_USER
            or config.get("Image") != image
            or config.get("Cmd") != command[image_index + 1 :]
            or config.get("OpenStdin") is not True
            or config.get("Tty") is not False
            or not isinstance(config.get("Labels"), Mapping)
            or dict(config["Labels"]) != expected_labels
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or sorted(host.get("CapDrop") or []) != ["ALL"]
            or not any(
                value in {"no-new-privileges", "no-new-privileges=true"}
                for value in (host.get("SecurityOpt") or [])
            )
            or host.get("PidMode") not in {"", "private"}
            or host.get("IpcMode") not in {"", "private"}
            or host.get("PidsLimit") != resources[2]
            or host.get("Memory") != resources[1]
            or host.get("MemorySwap") != resources[1]
            or int(host.get("NanoCpus") or 0) != resources[0] * 1_000_000
        ):
            raise SandboxArmError(f"sealed parent {role} inspect bindings differ")
        tmpfs_map = host.get("Tmpfs")
        if not isinstance(tmpfs_map, Mapping) or f"size={resources[3]}" not in str(tmpfs_map.get("/tmp")):
            raise SandboxArmError(f"sealed parent {role} inspect tmpfs differs")
        expected_mounts = _command_mounts(command)
        observed = {
            item.get("destination"): item
            for item in mounts
            if isinstance(item, Mapping) and isinstance(item.get("destination"), str)
        }
        if len(observed) != len(mounts) or set(observed) != {
            item["destination"] for item in expected_mounts
        }:
            raise SandboxArmError(f"sealed parent {role} inspect mount set differs")
        for expected in expected_mounts:
            actual = observed[expected["destination"]]
            if (
                actual.get("type") != "bind"
                or actual.get("source") != expected["source"]
                or actual.get("read_only") is not True
                or actual.get("propagation") != "rprivate"
            ):
                raise SandboxArmError(f"sealed parent {role} inspect mount differs")
            if expected["destination"] in {"/input/policy", "/input/opponent"}:
                policy_sources[role] = str(actual["source"])
    return (
        set(policy_sources) == {"candidate_policy", "opponent_policy"}
        and policy_sources["candidate_policy"] != policy_sources["opponent_policy"]
    )


def _compose_parent_bound_witnessed_arm(
    journal: WitnessJournal,
    attempt_id: str,
    packet: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    required_terminal_fields = {
        "schema", "scope", "arm_claim_sha256", "campaign_sha256", "snapshot_tree_sha256",
        "artifact_manifest_sha256", "artifact_files", "status", "fault", "host_outcome",
        "winner_role", "winner_index", "transcript_sha256", "panel_parent_claim_verified",
        "parent_campaign_gate_required", "parent_campaign_gate_statement", "authority_statement",
        "authority", "parent_binding", "terminal_status", "launch_state",
        "witness_cas_complete", "witness_cas_file_count", "witness_cas_files",
        *FALSE_AUTHORITY_FLAGS,
    }
    if (
        set(evidence) != required_terminal_fields
        or evidence.get("schema") != PARENT_BOUND_ARM_RESULT_SCHEMA + "_evidence_v1"
        or evidence.get("scope") != "parent_bound_campaign_arm"
        or evidence.get("witness_cas_complete") is not True
    ):
        raise SandboxArmError("parent-bound terminal evidence is not the exact artifact envelope")
    if (
        evidence.get("status") != CAMPAIGN_SUCCESS
        or evidence.get("terminal_status") != CAMPAIGN_SUCCESS
        or evidence.get("launch_state") != POPEN_OBSERVED
        or packet.get("terminal_status") != CAMPAIGN_SUCCESS
    ):
        raise SandboxArmError("parent-bound recomposition requires a successful POPEN_OBSERVED child")
    if (
        evidence.get("panel_parent_claim_verified") is not False
        or evidence.get("parent_campaign_gate_required") is not True
        or evidence.get("parent_campaign_gate_statement") != PARENT_GATE_STATEMENT
        or evidence.get("authority_statement") != AUTHORITY_STATEMENT
        or evidence.get("authority") != "DEVELOPMENT_ONLY"
    ):
        raise SandboxArmError("parent-bound terminal authority posture changed")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if evidence.get(field) is not expected:
            raise SandboxArmError(f"parent-bound terminal authority field changed: {field}")

    artifact_files, reopened = _reopen_witness_file_set(journal, evidence)
    required_paths = {
        "transcript.json",
        "snapshot/task.json",
        *{
            f"containers/{role}.{suffix}.json"
            for role in _SANDBOX_ROLES
            for suffix in ("command", "inspect")
        },
        *{
            f"raw/{role}/{stream}.bin"
            for role in _SANDBOX_ROLES
            for stream in ("stdin", "stdout", "stderr")
        },
    }
    if not required_paths <= reopened.keys():
        raise SandboxArmError("parent-bound witness CAS lacks complete launch evidence")
    prepared = _read_journal_json_evidence(
        journal, packet.get("prepared_evidence_sha256"), "parent prepared evidence"
    )
    started = _read_journal_json_evidence(
        journal, packet.get("started_evidence_sha256"), "parent started evidence"
    )
    required_prepared = {
        "schema", "scope", "parent_binding", "snapshot_manifest", "child_claim_template",
        "runner_binding", "pre_arm_runtime_verification_sha256", "container_names",
        "normalized_command_templates", "command_template_sha256s", "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
    required_started = {
        "schema", "scope", "parent_binding", "prepared_evidence_sha256",
        "pre_arm_runtime_verification_sha256", "authority", *FALSE_AUTHORITY_FLAGS,
    }
    if (
        set(prepared) != required_prepared
        or prepared.get("schema") != PARENT_BOUND_ARM_RESULT_SCHEMA + "_prepared_v1"
        or set(started) != required_started
        or started.get("schema") != PARENT_BOUND_ARM_RESULT_SCHEMA + "_started_v1"
    ):
        raise SandboxArmError("parent child PREPARE/START evidence fields are not exact")
    if started.get("prepared_evidence_sha256") != packet.get("prepared_evidence_sha256"):
        raise SandboxArmError("parent child START does not bind PREPARE")
    for label, record in (("PREPARE", prepared), ("START", started)):
        if record.get("scope") != "parent_bound_campaign_arm" or record.get("authority") != "DEVELOPMENT_ONLY":
            raise SandboxArmError(f"parent child {label} posture changed")
        for field, expected in FALSE_AUTHORITY_FLAGS.items():
            if record.get(field) is not expected:
                raise SandboxArmError(f"parent child {label} authority field changed: {field}")

    claim_sha256 = _require_digest(packet.get("claim_sha256"), "parent child claim sha256")
    claim = _read_journal_json_evidence(journal, claim_sha256, "parent child claim")
    if parent_bound_child_claim_sha256(claim) != claim_sha256:
        raise SandboxArmError("parent child claim CAS content differs from CLAIM")
    metadata = _journal_claim_metadata(journal, attempt_id)
    expected_metadata = {
        "scope": "parent_bound_campaign_arm",
        "campaign_id": claim["campaign_id"],
        "allocation_id": claim["allocation_id"],
        "child_claim_template_sha256": claim["child_claim_template_sha256"],
        "child_claim_evidence_sha256": claim_sha256,
    }
    if metadata != expected_metadata:
        raise SandboxArmError("parent child CLAIM metadata differs from claim CAS")
    claim_event = next(
        (
            event
            for event in journal.events()
            if event.get("event_type") == "CLAIM"
            and event.get("payload", {}).get("attempt_id") == attempt_id
        ),
        None,
    )
    if (
        not isinstance(claim_event, Mapping)
        or claim_event.get("payload", {}).get("claim_sha256") != claim_sha256
        or claim_event.get("payload", {}).get("metadata") != expected_metadata
    ):
        raise SandboxArmError("parent child CLAIM event differs from claim CAS")
    child_claim_event_sha256 = _require_digest(
        claim_event.get("event_sha256"), "parent child CLAIM event sha256"
    )

    template = prepared.get("child_claim_template")
    if not isinstance(template, Mapping) or not isinstance(template.get("content_sha256"), str):
        raise SandboxArmError("parent PREPARE lacks its child claim template")
    template_content = {key: value for key, value in template.items() if key != "content_sha256"}
    if (
        canonical_sha256(template_content) != template.get("content_sha256")
        or template.get("content_sha256") != claim.get("child_claim_template_sha256")
    ):
        raise SandboxArmError("parent child claim template hash differs")
    try:
        validate_parent_bound_child_claim(claim, template, _parent_claim_state(claim))
    except ParentArmClaimError as exc:
        raise SandboxArmError(f"parent child claim/template chronology is invalid: {exc}") from exc
    if claim.get("child_attempt_id") != attempt_id:
        raise SandboxArmError("parent child attempt differs from the campaign-derived claim")
    expected_one_shot_key = journal.one_shot_key(
        parent_child_campaign_sha256(claim["campaign_id"], claim["allocation_id"]),
        claim["normalized_policy_identity_sha256"],
    )
    if packet.get("one_shot_key_sha256") != expected_one_shot_key:
        raise SandboxArmError("parent child CLAIM does not use its campaign one-shot key")

    prepared_binding = prepared.get("parent_binding")
    started_binding = started.get("parent_binding")
    terminal_binding = evidence.get("parent_binding")
    if not all(isinstance(item, Mapping) for item in (prepared_binding, started_binding, terminal_binding)):
        raise SandboxArmError("parent binding evidence is malformed")
    runtime_digest = _require_digest(
        prepared.get("pre_arm_runtime_verification_sha256"),
        "pre-arm runtime verification sha256",
    )
    base_binding = {
        "campaign_id": claim["campaign_id"],
        "allocation_id": claim["allocation_id"],
        "parent_bound_child_claim_sha256": claim_sha256,
        "child_claim_event_sha256": child_claim_event_sha256,
        "arm_bound_event_sha256": _require_digest(
            prepared_binding.get("arm_bound_event_sha256"), "ARM_BOUND event sha256"
        ),
        "parent_prepare_event_sha256": claim["parent_prepare_event_sha256"],
        "parent_start_evidence_sha256": claim["parent_start_evidence_sha256"],
        "parent_start_event_sha256": claim["parent_start_event_sha256"],
        "parent_wave_start_event_sha256": claim["parent_wave_start_event_sha256"],
        "wave_runtime_verification_sha256": claim["wave_runtime_verification_sha256"],
        "prepared_allocation_content_sha256": claim["prepared_allocation_content_sha256"],
        "prepared_manifest_sha256": claim["prepared_manifest_sha256"],
        "pre_arm_runtime_verification_sha256": runtime_digest,
    }
    if dict(prepared_binding) != base_binding or dict(started_binding) != base_binding:
        raise SandboxArmError("parent child PREPARE/START chronology binding differs")
    if started.get("pre_arm_runtime_verification_sha256") != runtime_digest:
        raise SandboxArmError("parent child START runtime receipt differs from PREPARE")
    runtime_receipt = _read_journal_json_evidence(
        journal, runtime_digest, "pre-arm runtime verification"
    )
    try:
        campaign_runtime.validate_campaign_runtime_verification(
            runtime_receipt,
            runner_binding=prepared.get("runner_binding"),
            phase="pre_arm_start",
            campaign_id=claim["campaign_id"],
            plan_sha256=claim["plan_sha256"],
            wave=claim["wave"],
            allocation_id=claim["allocation_id"],
        )
    except Exception as exc:
        raise SandboxArmError(f"parent pre-arm runtime receipt is invalid: {exc}") from exc

    child_start_event_sha256 = _child_event_sha256(journal, attempt_id, "START")
    session_id = _parent_session_id(
        claim_sha256, base_binding["arm_bound_event_sha256"], child_start_event_sha256
    )
    expected_terminal_binding = {
        **base_binding,
        "child_start_event_sha256": child_start_event_sha256,
        "session_id": session_id,
    }
    if dict(terminal_binding) != expected_terminal_binding:
        raise SandboxArmError("parent terminal binding differs from durable child chronology")

    snapshot_manifest = prepared.get("snapshot_manifest")
    if not isinstance(snapshot_manifest, Mapping):
        raise SandboxArmError("parent PREPARE lacks its snapshot manifest")
    if (
        canonical_sha256(snapshot_manifest) != template.get("snapshot_manifest_sha256")
        or snapshot_manifest.get("tree_sha256") != template.get("snapshot_tree_sha256")
        or evidence.get("snapshot_tree_sha256") != snapshot_manifest.get("tree_sha256")
    ):
        raise SandboxArmError("parent snapshot differs from the prepared template")
    _verify_reopened_artifact_manifest(
        evidence, artifact_files, scope="parent_bound_campaign_arm"
    )
    _verify_reopened_snapshot(journal, reopened, snapshot_manifest)
    task = _read_reopened_json(journal, reopened, "snapshot/task.json")
    bundle_manifest_sha256 = _require_digest(
        snapshot_manifest.get("bundle_manifest_sha256"), "parent bundle manifest sha256"
    )
    if canonical_sha256(build_arm_claim(task, bundle_manifest_sha256)) != claim.get(
        "base_sandbox_arm_claim_sha256"
    ):
        raise SandboxArmError("parent claim does not bind the reopened bundle task")
    expected_campaign_sha256 = parent_child_campaign_sha256(
        claim["campaign_id"], claim["allocation_id"]
    )
    if (
        evidence.get("arm_claim_sha256") != claim_sha256
        or evidence.get("campaign_sha256") != expected_campaign_sha256
    ):
        raise SandboxArmError("parent terminal evidence differs from child claim identity")
    names = deterministic_parent_container_names(claim["campaign_id"], claim["allocation_id"])
    if prepared.get("container_names") != names or template.get("container_names") != names:
        raise SandboxArmError("parent PREPARE container names are not campaign-derived")
    if (
        prepared.get("normalized_command_templates") != template.get("normalized_command_templates")
        or prepared.get("command_template_sha256s") != template.get("command_template_sha256s")
    ):
        raise SandboxArmError("parent PREPARE command templates differ from the child template")
    isolation_verified = _verify_parent_reopened_launch(
        journal,
        reopened,
        template,
        names=names,
        child_claim_sha256=claim_sha256,
        arm_bound_event_sha256=base_binding["arm_bound_event_sha256"],
        child_start_event_sha256=child_start_event_sha256,
        session_id=session_id,
    )
    transcript_sha256, winner_role, host_outcome = _verify_reopened_transcript(
        journal,
        reopened,
        evidence,
        expected_session_id=session_id,
        expected_claim_sha256=claim_sha256,
    )
    if winner_role is None:
        winner_index = None
    elif task.get("seat") == "policy_first":
        winner_index = 0 if winner_role == "candidate_policy" else 1
    elif task.get("seat") == "policy_second":
        winner_index = 1 if winner_role == "candidate_policy" else 0
    else:
        raise SandboxArmError("parent reopened task seat is invalid")
    if evidence.get("winner_index") != winner_index:
        raise SandboxArmError("parent terminal winner index differs from transcript")
    if transcript_sha256 is None or not isolation_verified:
        raise SandboxArmError("successful parent child lacks transcript or isolation evidence")

    content = {
        "schema": WITNESSED_ARM_SCHEMA,
        "attempt_id": attempt_id,
        "authority_id": journal.authority_id,
        "arm_witness_root_id": journal.root_id,
        "one_shot_key_sha256": packet["one_shot_key_sha256"],
        "terminal_event_sha256": packet["terminal_event_sha256"],
        "terminal_status": packet["terminal_status"],
        "terminal_evidence_sha256": packet["evidence_sha256"],
        "prepared_evidence_sha256": packet["prepared_evidence_sha256"],
        "started_evidence_sha256": packet["started_evidence_sha256"],
        "reopened_file_count": len(reopened),
        "reopened_manifest_sha256": canonical_sha256(reopened),
        "transcript_sha256": transcript_sha256,
        "status": evidence["status"],
        "fault": evidence["fault"],
        "host_outcome": host_outcome,
        "winner_role": winner_role,
        "witness_chain_verified": True,
        "global_one_shot_within_authority": False,
        "root_local_one_shot_enforced": True,
        "canonical_external_journal_required": True,
        "receipt_artifacts_reopened": True,
        "transcript_chain_recomputed": True,
        "terminal_outcome_recomputed": True,
        "cross_policy_isolation_configuration_verified": True,
        "cross_policy_isolation_verified": False,
        "cross_policy_noninterference_proven": False,
        "sandbox_escape_absence_proven": False,
        "referee_rules_correctness_verified": False,
        "policy_execution_successful": True,
        "outcome_usable": False,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY",
        "external_witness_verified": False,
        "scientific_selector_admissible": False,
        **FALSE_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def compose_witnessed_arm(
    journal: WitnessJournal,
    attempt_id: str,
    caller_receipt: object | None = None,
) -> dict[str, Any]:
    """Rebuild one development arm solely from journal and CAS digests."""

    if caller_receipt is not None:
        raise SandboxArmError("caller receipt objects are not admissible")
    journal.verify()
    packet = journal.compose_attempt(attempt_id)
    evidence = packet.get("evidence")
    if not isinstance(evidence, Mapping):
        raise SandboxArmError("witness terminal evidence must be an object")
    if evidence.get("scope") == "parent_bound_campaign_arm":
        return _compose_parent_bound_witnessed_arm(
            journal,
            attempt_id,
            packet,
            evidence,
        )
    if evidence.get("scope") != "single_arm" or evidence.get("witness_cas_complete") is not True:
        raise SandboxArmError("witness terminal evidence is not a complete single arm")
    required_terminal_fields = {
        "schema", "scope", "arm_claim_sha256", "campaign_sha256", "snapshot_tree_sha256",
        "artifact_manifest_sha256", "artifact_files", "status", "fault", "host_outcome",
        "winner_role", "winner_index", "transcript_sha256", "panel_parent_claim_verified",
        "parent_campaign_gate_required", "parent_campaign_gate_statement", "authority_statement",
        "authority", "witness_cas_complete", "witness_cas_file_count", "witness_cas_files",
        *FALSE_AUTHORITY_FLAGS,
    }
    if set(evidence) != required_terminal_fields or evidence.get("schema") != ARM_RESULT_SCHEMA + "_evidence_v1":
        raise SandboxArmError("witness terminal evidence is not the exact artifact envelope")
    if (
        evidence.get("panel_parent_claim_verified") is not False
        or evidence.get("parent_campaign_gate_required") is not True
        or evidence.get("parent_campaign_gate_statement") != PARENT_GATE_STATEMENT
        or evidence.get("authority_statement") != AUTHORITY_STATEMENT
        or evidence.get("authority") != "DEVELOPMENT_ONLY"
    ):
        raise SandboxArmError("single-arm evidence may not claim a verified panel parent")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if evidence.get(field) is not expected:
            raise SandboxArmError(f"witness terminal authority field changed: {field}")
    artifact_files = evidence.get("artifact_files")
    witness_files = evidence.get("witness_cas_files")
    if not isinstance(artifact_files, Mapping) or not isinstance(witness_files, Mapping):
        raise SandboxArmError("witness terminal evidence lacks CAS file references")
    if set(artifact_files) != set(witness_files):
        raise SandboxArmError("witness CAS references do not exactly cover raw artifacts")
    reopened: dict[str, dict[str, Any]] = {}
    for relative in sorted(witness_files):
        artifact = artifact_files[relative]
        reference = witness_files[relative]
        if not isinstance(artifact, Mapping) or not isinstance(reference, Mapping):
            raise SandboxArmError("witness CAS file reference is malformed")
        if dict(artifact) != dict(reference):
            raise SandboxArmError(f"witness CAS reference differs for {relative}")
        digest = _require_digest(reference.get("sha256"), f"witness CAS {relative}")
        size = reference.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise SandboxArmError(f"witness CAS size is invalid for {relative}")
        payload = journal.evidence.read(digest)
        if len(payload) != size:
            raise SandboxArmError(f"witness CAS size differs for {relative}")
        reopened[relative] = {"sha256": digest, "size_bytes": size}
    if evidence.get("witness_cas_file_count") != len(reopened):
        raise SandboxArmError("witness CAS file count differs from reopened artifacts")
    required_paths = {
        "transcript.json",
        "snapshot/task.json",
        *{
            f"containers/{role}.{suffix}.json"
            for role in ("referee", "candidate_policy", "opponent_policy")
            for suffix in ("command", "inspect")
        },
        *{
            f"raw/{role}/{stream}.bin"
            for role in ("referee", "candidate_policy", "opponent_policy")
            for stream in ("stdin", "stdout", "stderr")
        },
    }
    if not required_paths <= reopened.keys():
        raise SandboxArmError("witness CAS is missing required referee/policy evidence")
    prepared = _read_journal_json_evidence(
        journal,
        packet.get("prepared_evidence_sha256"),
        "prepared evidence",
    )
    started = _read_journal_json_evidence(
        journal,
        packet.get("started_evidence_sha256"),
        "started evidence",
    )
    snapshot_manifest = prepared.get("snapshot_manifest")
    if not isinstance(snapshot_manifest, Mapping):
        raise SandboxArmError("prepared evidence lacks its snapshot manifest")
    _verify_reopened_artifact_manifest(evidence, artifact_files)
    _verify_reopened_snapshot(journal, reopened, snapshot_manifest)
    if evidence.get("snapshot_tree_sha256") != snapshot_manifest.get("tree_sha256"):
        raise SandboxArmError("terminal evidence snapshot digest differs from prepared snapshot")
    task = _read_reopened_json(journal, reopened, "snapshot/task.json")
    bundle_manifest_sha256 = _require_digest(
        snapshot_manifest.get("bundle_manifest_sha256"),
        "prepared bundle_manifest_sha256",
    )
    expected_claim = build_arm_claim(task, bundle_manifest_sha256)
    expected_claim_sha256 = canonical_sha256(expected_claim)
    expected_campaign_sha256 = arm_campaign_sha256(task, bundle_manifest_sha256)
    expected_one_shot_key = journal.one_shot_key(
        expected_campaign_sha256,
        policy_identity_sha256(task),
    )
    if packet.get("claim_sha256") != expected_claim_sha256:
        raise SandboxArmError("witness claim is not the canonical single-arm claim")
    if packet.get("one_shot_key_sha256") != expected_one_shot_key:
        raise SandboxArmError("witness claim does not use the derived one-shot key")
    if (
        evidence.get("arm_claim_sha256") != expected_claim_sha256
        or evidence.get("campaign_sha256") != expected_campaign_sha256
    ):
        raise SandboxArmError("terminal evidence does not bind the canonical arm claim")
    success = evidence.get("status") == "SUCCESS"
    isolation_verified = False
    if success:
        isolation_verified = _verify_reopened_launch_evidence(
            journal,
            reopened,
            prepared,
            started,
            packet,
            task,
            expected_campaign_sha256=expected_campaign_sha256,
            expected_claim_sha256=expected_claim_sha256,
        )
    elif started.get("prepared_evidence_sha256") != packet.get("prepared_evidence_sha256"):
        raise SandboxArmError("started evidence does not bind the prepared evidence")
    transcript_sha256, winner_role, host_outcome = _verify_reopened_transcript(
        journal,
        reopened,
        evidence,
        expected_session_id=f"sbx-{expected_campaign_sha256[:32]}",
        expected_claim_sha256=expected_claim_sha256,
    )
    if winner_role is None:
        winner_index = None
    elif task.get("seat") == "policy_first":
        winner_index = 0 if winner_role == "candidate_policy" else 1
    elif task.get("seat") == "policy_second":
        winner_index = 1 if winner_role == "candidate_policy" else 0
    else:
        raise SandboxArmError("reopened task seat is invalid")
    if evidence.get("winner_index") != winner_index:
        raise SandboxArmError("witness terminal winner index differs from the sealed transcript")
    if success != (packet.get("terminal_status") == "SUCCESS"):
        raise SandboxArmError("witness terminal status differs from terminal evidence")
    if success and (transcript_sha256 is None or not isolation_verified):
        raise SandboxArmError("successful arm lacks verified transcript or isolation evidence")
    reopened_manifest_sha256 = canonical_sha256(reopened)
    content = {
        "schema": WITNESSED_ARM_SCHEMA,
        "attempt_id": attempt_id,
        "authority_id": journal.authority_id,
        "arm_witness_root_id": journal.root_id,
        "one_shot_key_sha256": packet["one_shot_key_sha256"],
        "terminal_event_sha256": packet["terminal_event_sha256"],
        "terminal_status": packet["terminal_status"],
        "terminal_evidence_sha256": packet["evidence_sha256"],
        "prepared_evidence_sha256": packet["prepared_evidence_sha256"],
        "started_evidence_sha256": packet["started_evidence_sha256"],
        "reopened_file_count": len(reopened),
        "reopened_manifest_sha256": reopened_manifest_sha256,
        "transcript_sha256": transcript_sha256,
        "status": evidence.get("status"),
        "fault": evidence.get("fault"),
        "host_outcome": host_outcome if success else None,
        "winner_role": winner_role if success else None,
        "witness_chain_verified": True,
        "global_one_shot_within_authority": False,
        "root_local_one_shot_enforced": True,
        "canonical_external_journal_required": True,
        "receipt_artifacts_reopened": True,
        "transcript_chain_recomputed": transcript_sha256 is not None,
        "terminal_outcome_recomputed": success,
        "cross_policy_isolation_configuration_verified": isolation_verified,
        "cross_policy_isolation_verified": False,
        "cross_policy_noninterference_proven": False,
        "sandbox_escape_absence_proven": False,
        "referee_rules_correctness_verified": False,
        "policy_execution_successful": success,
        "outcome_usable": False,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY",
        "external_witness_verified": False,
        "scientific_selector_admissible": False,
        **FALSE_AUTHORITY_FLAGS,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def _existing_name_check(names: Mapping[str, str], *, docker_timeout: float) -> None:
    for role in ("referee", "candidate_policy", "opponent_policy"):
        result = _docker_call(
            ["docker", "container", "inspect", names[role]],
            timeout=docker_timeout,
        )
        if result.returncode == 0:
            raise SandboxArmFault(f"deterministic container name already exists: {names[role]}")


def _journal_claim_metadata(journal: WitnessJournal, attempt_id: str) -> dict[str, Any]:
    for event in reversed(journal.events()):
        if event.get("event_type") == "CLAIM" and event.get("payload", {}).get("attempt_id") == attempt_id:
            metadata = event["payload"].get("metadata")
            return dict(metadata) if isinstance(metadata, Mapping) else {}
    return {}


def burn_started_attempt(
    journal: WitnessJournal,
    attempt_id: str,
    fault: BaseException | str,
) -> dict[str, Any]:
    """Seal an unrecoverable post-START failure without permitting a rerun."""

    journal.recover()
    state = journal.state(attempt_id)
    if state["state"] == TERMINAL:
        return state
    if state["state"] != STARTED:
        raise SandboxArmError(f"burn requires STARTED, got {state['state']}")
    evidence = {
        "schema": ARM_RESULT_SCHEMA + "_infrastructure_burn_v1",
        "scope": "single_arm",
        "status": "BURN",
        "fault": str(fault),
        "outcome_usable": False,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    journal.terminal(attempt_id, "BURN", evidence=evidence)
    return journal.state(attempt_id)


def _campaign_evidence_json(
    campaign_journal: CampaignJournal,
    digest: object,
    label: str,
) -> Mapping[str, Any]:
    payload = campaign_journal.read_evidence(_require_digest(digest, label))
    try:
        value = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SandboxArmError(f"{label} is not canonical JSON") from exc
    if not isinstance(value, Mapping) or canonical_json_bytes(dict(value)) != payload:
        raise SandboxArmError(f"{label} is not canonical JSON")
    return value


def _parent_session_id(
    child_claim_sha256: str,
    arm_bound_event_sha256: str,
    child_start_event_sha256: str,
) -> str:
    """Make the protocol's session token carry all parent execution anchors."""

    return "pb-" + "-".join(
        (
            _require_digest(child_claim_sha256, "child claim sha256"),
            _require_digest(arm_bound_event_sha256, "ARM_BOUND event sha256"),
            _require_digest(child_start_event_sha256, "child START event sha256"),
        )
    )


def _child_event_sha256(journal: WitnessJournal, attempt_id: str, event_type: str) -> str:
    for event in reversed(journal.events()):
        if (
            event.get("event_type") == event_type
            and event.get("payload", {}).get("attempt_id") == attempt_id
        ):
            return _require_digest(event.get("event_sha256"), f"child {event_type} event sha256")
    raise SandboxArmError(f"child {event_type} event is absent")


def _materialize_parent_commands(
    template: Mapping[str, Any],
    *,
    snapshot: Path,
    child_claim_sha256: str,
    arm_bound_event_sha256: str,
    child_start_event_sha256: str,
    session_id: str,
) -> dict[str, list[str]]:
    """Expand only a previously validated frozen parent command template."""

    raw = template.get("normalized_command_templates")
    expected_hashes = template.get("command_template_sha256s")
    if not isinstance(raw, Mapping) or not isinstance(expected_hashes, Mapping):
        raise SandboxArmError("prepared template lacks frozen command templates")
    replacements = {
        "$SNAPSHOT": str(snapshot.resolve()),
        "$CHILD_CLAIM_SHA256": _require_digest(child_claim_sha256, "child claim sha256"),
        "$ARM_BOUND_EVENT_SHA256": _require_digest(
            arm_bound_event_sha256, "ARM_BOUND event sha256"
        ),
        "$CHILD_START_EVENT_SHA256": _require_digest(
            child_start_event_sha256, "child START event sha256"
        ),
        "$SESSION_ID": session_id,
    }
    commands: dict[str, list[str]] = {}
    for role in ("referee", "candidate_policy", "opponent_policy"):
        command = raw.get(role)
        if not isinstance(command, list) or not all(isinstance(token, str) and token for token in command):
            raise SandboxArmError(f"prepared command template for {role} is invalid")
        if canonical_sha256(command) != _require_digest(
            expected_hashes.get(role), f"prepared command template hash for {role}"
        ):
            raise SandboxArmError(f"prepared command template hash drifted for {role}")
        materialized = list(command)
        for placeholder, replacement in replacements.items():
            materialized = [token.replace(placeholder, replacement) for token in materialized]
        if any("$" in token for token in materialized):
            raise SandboxArmError(f"prepared command template for {role} has an unresolved placeholder")
        commands[role] = materialized
    return commands


def build_parent_docker_command_templates(
    snapshot: Path,
    task: Mapping[str, Any],
    *,
    image: str,
    names: Mapping[str, str],
    cpu_millicores: int,
    memory_bytes: int,
    pids_limit: int,
    tmpfs_bytes: int,
) -> dict[str, list[str]]:
    """Normalize real Docker commands into post-START parent templates.

    The resulting mount and label tokens necessarily contain embedded
    placeholders, matching the parent claim template grammar.
    """

    markers = {
        "$CHILD_CLAIM_SHA256": "1" * 64,
        "$ARM_BOUND_EVENT_SHA256": "2" * 64,
        "$CHILD_START_EVENT_SHA256": "3" * 64,
    }
    session_marker = _parent_session_id(
        markers["$CHILD_CLAIM_SHA256"],
        markers["$ARM_BOUND_EVENT_SHA256"],
        markers["$CHILD_START_EVENT_SHA256"],
    )
    replacements = {
        str(snapshot.resolve()): "$SNAPSHOT",
        session_marker: "$SESSION_ID",
        markers["$CHILD_CLAIM_SHA256"]: "$CHILD_CLAIM_SHA256",
        markers["$ARM_BOUND_EVENT_SHA256"]: "$ARM_BOUND_EVENT_SHA256",
        markers["$CHILD_START_EVENT_SHA256"]: "$CHILD_START_EVENT_SHA256",
    }
    templates: dict[str, list[str]] = {}
    for role in _SANDBOX_ROLES:
        if role not in names:
            raise SandboxArmError(f"parent container name is absent for {role}")
        command = build_docker_command(
            role,
            snapshot,
            image=image,
            name=names[role],
            session_id=session_marker,
            arm_claim_sha256=markers["$CHILD_CLAIM_SHA256"],
            task=task,
            cpu_millicores=cpu_millicores,
            memory_bytes=memory_bytes,
            pids_limit=pids_limit,
            tmpfs_bytes=tmpfs_bytes,
            arm_bound_event_sha256=markers["$ARM_BOUND_EVENT_SHA256"],
            child_start_event_sha256=markers["$CHILD_START_EVENT_SHA256"],
        )
        normalized = list(command)
        for value, placeholder in replacements.items():
            normalized = [token.replace(value, placeholder) for token in normalized]
        for placeholder in replacements.values():
            if not any(placeholder in token for token in normalized):
                raise SandboxArmError(f"functional parent template lacks {placeholder}")
        templates[role] = normalized
    return templates


def _parent_runner_values(plan: Mapping[str, Any]) -> tuple[str, float, float, int, int, int, int]:
    binding = plan.get("runner_binding")
    if not isinstance(binding, Mapping):
        raise SandboxArmError("campaign plan lacks a runner binding")
    image = binding.get("oci_image")
    deadlines = binding.get("deadline_caps")
    resources = binding.get("resource_caps")
    if not isinstance(image, str) or not isinstance(deadlines, Mapping) or not isinstance(resources, Mapping):
        raise SandboxArmError("campaign runner binding is incomplete")
    try:
        arm_deadline = float(deadlines["arm_deadline_seconds"])
        docker_timeout = float(deadlines["docker_call_timeout_seconds"])
        cpu = int(resources["cpu_limit_millicores"])
        memory = int(resources["memory_limit_bytes"])
        pids = int(resources["pids_limit"])
        tmpfs = int(resources["tmpfs_size_bytes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SandboxArmError("campaign runner binding has invalid runtime values") from exc
    if arm_deadline <= 0 or docker_timeout <= 0 or min(cpu, memory, pids, tmpfs) <= 0:
        raise SandboxArmError("campaign runner binding has non-positive runtime values")
    return image, arm_deadline, docker_timeout, cpu, memory, pids, tmpfs


def _parent_execution_context(
    campaign_journal: CampaignJournal,
    campaign_id: str,
    allocation_id: str,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Reopen and validate the sole parent-selected allocation and template."""

    if not isinstance(campaign_journal, CampaignJournal):
        raise SandboxArmError("parent mode requires a CampaignJournal")
    campaign = _require_digest(campaign_id, "campaign_id")
    if not isinstance(allocation_id, str) or not allocation_id or allocation_id != allocation_id.strip():
        raise SandboxArmError("allocation_id must be a non-empty trimmed token")
    try:
        campaign_journal.verify()
        state = campaign_journal.state(campaign)
        plan = campaign_journal.read_campaign_plan(campaign)
    except Exception as exc:
        raise SandboxArmError(f"could not reopen parent campaign: {exc}") from exc
    if state.get("state") != "STARTED" or state.get("current_wave") is None:
        raise SandboxArmError("parent campaign must have a durable active wave")
    allocations = plan.get("allocations")
    if not isinstance(allocations, list):
        raise SandboxArmError("parent campaign plan lacks allocations")
    allocation = next(
        (item for item in allocations if isinstance(item, Mapping) and item.get("allocation_id") == allocation_id),
        None,
    )
    if not isinstance(allocation, Mapping):
        raise SandboxArmError("allocation_id is absent from the parent campaign")
    if allocation.get("wave") != state.get("current_wave"):
        raise SandboxArmError("allocation is not in the active parent wave")
    if allocation_id in state.get("bound_arms", {}) or allocation_id in state.get("dispositions", {}):
        raise SandboxArmError("parent allocation is already bound or terminal")
    if manifest.get("content_sha256") != allocation.get("bundle_manifest_sha256"):
        raise SandboxArmError("input bundle manifest differs from the parent allocation")
    if manifest.get("task") != allocation.get("task"):
        raise SandboxArmError("input bundle task differs from the parent allocation")
    prepared = _campaign_evidence_json(
        campaign_journal, state.get("prepared_manifest_sha256"), "prepared parent manifest"
    )
    try:
        prepared = validate_campaign_prepared_manifest(prepared, plan, state)
    except Exception as exc:
        raise SandboxArmError(f"prepared parent manifest is invalid: {exc}") from exc
    templates = prepared.get("allocations")
    if not isinstance(templates, list):
        raise SandboxArmError("prepared parent manifest lacks allocation templates")
    template = next(
        (item for item in templates if isinstance(item, Mapping) and item.get("allocation_id") == allocation_id),
        None,
    )
    if not isinstance(template, Mapping):
        raise SandboxArmError("prepared parent manifest lacks this allocation template")
    try:
        template = validate_child_claim_template(template, plan, state, allocation)
    except ParentArmClaimError as exc:
        raise SandboxArmError(f"prepared child template is invalid: {exc}") from exc
    return dict(state), dict(plan), dict(allocation), dict(template)


def execute_parent_bound_arm(
    bundle_dir: Path,
    *,
    output_dir: Path,
    campaign_journal: CampaignJournal,
    campaign_id: str,
    allocation_id: str,
) -> dict[str, Any]:
    """Execute one campaign-owned child arm with no caller-selected runtime knobs.

    The parent journal is the sole source of the child attempt, containers,
    OCI/runtime values, and command templates.  A standalone witness claim or
    packet cannot enter this path because the durable ARM_BOUND transition is
    created from the parent-derived child claim before child PREPARE/START.
    """

    try:
        validate_sandbox_execution_spec(
            __import__("evaluation_v4_2.sandbox_protocol", fromlist=["sandbox_execution_spec"])
            .sandbox_execution_spec()
        )
    except SandboxProtocolError as exc:
        raise SandboxArmError(f"frozen sandbox execution spec is invalid: {exc}") from exc
    manifest = _load_bundle_validator()(bundle_dir.resolve())
    state, plan, allocation, template = _parent_execution_context(
        campaign_journal, campaign_id, allocation_id, manifest
    )
    image, arm_deadline, docker_timeout, cpu, memory, pids, tmpfs = _parent_runner_values(plan)
    task = allocation["task"]
    if not isinstance(task, Mapping):
        raise SandboxArmError("parent allocation task is invalid")

    artifact_root = output_dir.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifact_root.chmod(0o700)
    snapshot, snapshot_manifest = _snapshot_bundle(bundle_dir, artifact_root, manifest)
    if (
        snapshot_manifest.get("tree_sha256") != template.get("snapshot_tree_sha256")
        or canonical_sha256(snapshot_manifest) != template.get("snapshot_manifest_sha256")
    ):
        raise SandboxArmError("materialized snapshot differs from the prepared parent template")

    try:
        child_claim = build_parent_bound_child_claim(template, state)
        child_claim = validate_parent_bound_child_claim(child_claim, template, state)
    except ParentArmClaimError as exc:
        raise SandboxArmError(f"parent-bound child claim is invalid: {exc}") from exc
    child_claim_sha256 = parent_bound_child_claim_sha256(child_claim)
    child_attempt_id = _require_digest(template.get("child_attempt_id"), "child_attempt_id")
    child_journal = getattr(campaign_journal, "_arm_journal", None)
    if not isinstance(child_journal, WitnessJournal):
        raise SandboxArmError("campaign-owned child witness is unavailable")
    one_shot_key = child_journal.one_shot_key(
        parent_child_campaign_sha256(campaign_id, allocation_id),
        _require_digest(template.get("normalized_policy_identity_sha256"), "policy identity"),
    )
    child_claim_evidence_sha256 = child_journal.evidence.put(child_claim)
    if child_claim_evidence_sha256 != child_claim_sha256:
        raise SandboxArmError("child claim CAS digest differs from its canonical claim hash")
    claim_event = child_journal.claim(
        child_attempt_id,
        claim=child_claim,
        one_shot_key_sha256=one_shot_key,
        metadata={
            "scope": "parent_bound_campaign_arm",
            "campaign_id": campaign_id,
            "allocation_id": allocation_id,
            "child_claim_template_sha256": template["content_sha256"],
            "child_claim_evidence_sha256": child_claim_evidence_sha256,
        },
    )
    arm_bound = campaign_journal.bind_arm(
        campaign_id,
        allocation_id,
        child_attempt_id,
        child_claim_sha256,
        claim_event["event_sha256"],
    )
    arm_bound_event_sha256 = _require_digest(arm_bound.get("event_sha256"), "ARM_BOUND event sha256")
    runtime_receipt = campaign_runtime.verify_campaign_runtime(
        plan["runner_binding"],
        repository_root=ROOT,
        phase="pre_arm_start",
        campaign_id=campaign_id,
        plan_sha256=_require_digest(plan.get("content_sha256"), "campaign plan sha256"),
        wave=int(allocation["wave"]),
        allocation_id=allocation_id,
    )
    campaign_runtime_receipt_sha256 = campaign_journal.evidence.put(runtime_receipt)
    child_runtime_receipt_sha256 = child_journal.evidence.put(runtime_receipt)
    if campaign_runtime_receipt_sha256 != child_runtime_receipt_sha256:
        raise SandboxArmError("campaign and child runtime receipt CAS digests differ")
    pre_arm_runtime_verification_sha256 = child_runtime_receipt_sha256
    bound_state = campaign_journal.state(campaign_id)
    try:
        validate_parent_bound_child_claim(child_claim, template, bound_state)
    except ParentArmClaimError as exc:
        raise SandboxArmError(f"parent-bound claim changed after ARM_BOUND: {exc}") from exc

    parent_binding = {
        "campaign_id": campaign_id,
        "allocation_id": allocation_id,
        "parent_bound_child_claim_sha256": child_claim_sha256,
        "child_claim_event_sha256": _require_digest(claim_event.get("event_sha256"), "child CLAIM event sha256"),
        "arm_bound_event_sha256": arm_bound_event_sha256,
        "parent_prepare_event_sha256": child_claim["parent_prepare_event_sha256"],
        "parent_start_evidence_sha256": child_claim["parent_start_evidence_sha256"],
        "parent_start_event_sha256": child_claim["parent_start_event_sha256"],
        "parent_wave_start_event_sha256": child_claim["parent_wave_start_event_sha256"],
        "wave_runtime_verification_sha256": child_claim["wave_runtime_verification_sha256"],
        "prepared_allocation_content_sha256": child_claim["prepared_allocation_content_sha256"],
        "prepared_manifest_sha256": child_claim["prepared_manifest_sha256"],
        "pre_arm_runtime_verification_sha256": pre_arm_runtime_verification_sha256,
    }
    prepared_evidence = {
        "schema": PARENT_BOUND_ARM_RESULT_SCHEMA + "_prepared_v1",
        "scope": "parent_bound_campaign_arm",
        "parent_binding": parent_binding,
        "snapshot_manifest": snapshot_manifest,
        "child_claim_template": template,
        "runner_binding": plan["runner_binding"],
        "pre_arm_runtime_verification_sha256": pre_arm_runtime_verification_sha256,
        "container_names": template["container_names"],
        "normalized_command_templates": template["normalized_command_templates"],
        "command_template_sha256s": template["command_template_sha256s"],
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    child_journal.prepare(child_attempt_id, evidence=prepared_evidence)
    started_evidence = {
        "schema": PARENT_BOUND_ARM_RESULT_SCHEMA + "_started_v1",
        "scope": "parent_bound_campaign_arm",
        "parent_binding": parent_binding,
        "prepared_evidence_sha256": child_journal.state(child_attempt_id)["prepared_evidence_sha256"],
        "pre_arm_runtime_verification_sha256": pre_arm_runtime_verification_sha256,
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    child_journal.start(child_attempt_id, evidence=started_evidence)
    launch_state = START_DURABLE_POPEN_UNCERTAIN
    child_start_event_sha256 = _child_event_sha256(child_journal, child_attempt_id, "START")
    session_id = _parent_session_id(child_claim_sha256, arm_bound_event_sha256, child_start_event_sha256)
    commands = _materialize_parent_commands(
        template,
        snapshot=snapshot,
        child_claim_sha256=child_claim_sha256,
        arm_bound_event_sha256=arm_bound_event_sha256,
        child_start_event_sha256=child_start_event_sha256,
        session_id=session_id,
    )
    names = template["container_names"]
    if not isinstance(names, Mapping) or set(names) != {"referee", "candidate_policy", "opponent_policy"}:
        raise SandboxArmError("prepared template has invalid campaign-derived container names")
    parent_binding = {**parent_binding, "child_start_event_sha256": child_start_event_sha256, "session_id": session_id}

    children: list[_Child] = []
    broker_result: dict[str, Any] | None = None
    inspect_records: dict[str, Any] = {}
    fault: str | None = None
    try:
        _verify_image(image, timeout=docker_timeout)
        _existing_name_check(names, docker_timeout=docker_timeout)
        children = _launch_children(commands, names)
        if (
            len(children) != len(_SANDBOX_ROLES)
            or [child.role for child in children] != list(_SANDBOX_ROLES)
        ):
            raise SandboxArmFault("child launch did not return all three canonical sandboxes")
        launch_state = POPEN_OBSERVED
        broker_result = _Broker(
            children,
            task,
            session_id=session_id,
            arm_claim_sha256=child_claim_sha256,
            arm_deadline_seconds=arm_deadline,
        ).run()
        inspect_records = _inspect_containers(
            children, snapshot, image=image, session_id=session_id,
            arm_claim_sha256=child_claim_sha256, cpu_millicores=cpu,
            memory_bytes=memory, pids_limit=pids, tmpfs_bytes=tmpfs,
            docker_timeout=docker_timeout, strict=True,
        )
    except BaseException as exc:
        fault = f"{type(exc).__name__}: {exc}"
        if children:
            inspect_records = _inspect_containers(
                children, snapshot, image=image, session_id=session_id,
                arm_claim_sha256=child_claim_sha256, cpu_millicores=cpu,
                memory_bytes=memory, pids_limit=pids, tmpfs_bytes=tmpfs,
                docker_timeout=docker_timeout, strict=False,
            )
        _kill_and_remove(children, names, docker_timeout=docker_timeout)
    else:
        _remove_exited(names, docker_timeout=docker_timeout)
    try:
        _verify_snapshot(snapshot, snapshot_manifest)
    except BaseException as exc:
        snapshot_fault = f"{type(exc).__name__}: {exc}"
        fault = snapshot_fault if fault is None else f"{fault}; {snapshot_fault}"
    if fault is None and broker_result is None:
        fault = "host broker returned no terminal result"
    terminal_status = (
        CAMPAIGN_SUCCESS
        if fault is None
        else CAMPAIGN_FAILURE
        if launch_state == POPEN_OBSERVED
        else CAMPAIGN_BURN
    )
    try:
        terminal = _write_artifacts(
            artifact_root, children, commands, inspect_records, broker_result,
            fault=fault, campaign_sha256=parent_child_campaign_sha256(campaign_id, allocation_id),
            arm_claim_sha256=child_claim_sha256, snapshot_manifest=snapshot_manifest,
            parent_binding=parent_binding,
            terminal_status=terminal_status,
            launch_state=launch_state,
        )
        child_journal.terminal(
            child_attempt_id,
            terminal_status,
            evidence=_install_witness_cas(child_journal, artifact_root, terminal),
        )
    except BaseException as exc:
        try:
            burn_started_attempt(child_journal, child_attempt_id, exc)
        except BaseException as burn_exc:
            raise SandboxArmError(f"post-START sealing failed and burn could not be sealed: {burn_exc}") from exc
        raise SandboxArmError("post-START sealing failed; parent-bound child is BURN") from exc
    return {
        "schema": PARENT_BOUND_ARM_RESULT_SCHEMA,
        "execution_mode": "parent_bound",
        "scope": "parent_bound_campaign_arm",
        "status": "SUCCESS" if fault is None else "FAULT",
        "terminal_status": terminal_status,
        "launch_state": launch_state,
        "fault": fault,
        "campaign_id": campaign_id,
        "allocation_id": allocation_id,
        "child_attempt_id": child_attempt_id,
        "parent_binding": parent_binding,
        "artifact_root": str(artifact_root),
        "snapshot_tree_sha256": snapshot_manifest["tree_sha256"],
        "transcript_sha256": (broker_result or {}).get("transcript_sha256"),
        "outcome": (broker_result or {}).get("outcome"),
        "winner_role": (broker_result or {}).get("winner_role"),
        "winner_index": (broker_result or {}).get("winner_index"),
        "authority": "DEVELOPMENT_ONLY",
        "policy_result_accepted": False,
        **FALSE_AUTHORITY_FLAGS,
    }


def execute_arm(
    bundle_dir: Path,
    *,
    output_dir: Path,
    journal: WitnessJournal,
    attempt_id: str,
    claim_sha256: str | None = None,
    campaign_sha256: str | None = None,
    image: str = DEFAULT_IMAGE,
    arm_deadline_seconds: float = DEFAULT_ARM_DEADLINE_SECONDS,
    docker_timeout: float = DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS,
    cpu_millicores: int = DEFAULT_CPU_MILLICORES,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    tmpfs_bytes: int = DEFAULT_TMPFS_BYTES,
) -> dict[str, Any]:
    """Execute one already-claimed arm and return host-authored evidence."""

    if arm_deadline_seconds <= 0 or docker_timeout <= 0:
        raise SandboxArmError("deadlines and Docker call timeout must be positive")
    try:
        validate_sandbox_execution_spec(
            __import__("evaluation_v4_2.sandbox_protocol", fromlist=["sandbox_execution_spec"]).sandbox_execution_spec()
        )
    except SandboxProtocolError as exc:
        raise SandboxArmError(f"frozen sandbox execution spec is invalid: {exc}") from exc
    validate_input_bundle = _load_bundle_validator()
    manifest = validate_input_bundle(bundle_dir.resolve())
    task = manifest["task"]
    arm_campaign = build_arm_campaign(task, manifest["content_sha256"])
    derived_campaign_sha256 = canonical_sha256(arm_campaign)
    if campaign_sha256 is not None and campaign_sha256 != derived_campaign_sha256:
        raise SandboxArmError("campaign_sha256 is not the deterministic single-arm campaign digest")
    campaign_sha256 = derived_campaign_sha256
    state = journal.state(attempt_id)
    if state["state"] != CLAIMED:
        raise SandboxArmError(f"attempt must be CLAIMED before execute, got {state['state']}")
    journal_claim_sha256 = _require_digest(state["claim_sha256"], "journal claim_sha256")
    expected_claim = build_arm_claim(task, manifest["content_sha256"])
    expected_claim_sha256 = canonical_sha256(expected_claim)
    expected_one_shot_key = journal.one_shot_key(
        campaign_sha256,
        policy_identity_sha256(task),
    )
    if journal_claim_sha256 != expected_claim_sha256:
        raise SandboxArmError("journal claim is not the canonical single-arm claim")
    if state.get("one_shot_key_sha256") != expected_one_shot_key:
        raise SandboxArmError("journal claim does not use the derived one-shot key")
    if claim_sha256 is not None and claim_sha256 != journal_claim_sha256:
        raise SandboxArmError("claim_sha256 does not match the injected witness claim")
    claim_sha256 = journal_claim_sha256
    metadata = _journal_claim_metadata(journal, attempt_id)
    if metadata.get("scope") != "single_arm":
        raise SandboxArmError("injected witness claim must be explicitly single_arm scoped")
    if metadata.get("panel_parent_claim_verified") is not False:
        raise SandboxArmError("a single arm may not assert a verified panel parent claim")
    if metadata.get("campaign_sha256") != campaign_sha256:
        raise SandboxArmError("witness claim metadata is not the single-arm campaign")

    artifact_root = output_dir.resolve()
    artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifact_root.chmod(0o700)
    snapshot, snapshot_manifest = _snapshot_bundle(bundle_dir, artifact_root, manifest)
    names = deterministic_container_names(attempt_id)
    session_id = f"sbx-{campaign_sha256[:32]}"
    commands = {
        role: build_docker_command(
            role,
            snapshot,
            image=image,
            name=names[role],
            session_id=session_id,
            arm_claim_sha256=claim_sha256,
            task=task,
            cpu_millicores=cpu_millicores,
            memory_bytes=memory_bytes,
            pids_limit=pids_limit,
            tmpfs_bytes=tmpfs_bytes,
        )
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    # Image/name checks happen before the witness is STARTED, so a launch can
    # never occur unless the preflight evidence is itself durably prepared.
    _verify_image(image, timeout=docker_timeout)
    _existing_name_check(names, docker_timeout=docker_timeout)
    prepared_evidence = {
        "schema": ARM_RESULT_SCHEMA + "_prepared_v1",
        "scope": "single_arm",
        "campaign_sha256": campaign_sha256,
        "arm_claim_sha256": claim_sha256,
        "snapshot_manifest": snapshot_manifest,
        "container_names": names,
        "reserved_child_arm_identities": [
            {
                "role": role,
                "container_name": names[role],
                "command_sha256": canonical_sha256(commands[role]),
            }
            for role in ("referee", "candidate_policy", "opponent_policy")
        ],
        "container_commands": {
            role: [token.replace(str(snapshot), "$SNAPSHOT") for token in command]
            for role, command in commands.items()
        },
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": PARENT_GATE_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    journal.prepare(attempt_id, evidence=prepared_evidence)
    started_evidence = {
        "schema": ARM_RESULT_SCHEMA + "_started_v1",
        "scope": "single_arm",
        "campaign_sha256": campaign_sha256,
        "arm_claim_sha256": claim_sha256,
        "prepared_evidence_sha256": journal.state(attempt_id)["prepared_evidence_sha256"],
        "reserved_child_arm_identities": [
            {"role": role, "container_name": names[role], "command_sha256": canonical_sha256(commands[role])}
            for role in ("referee", "candidate_policy", "opponent_policy")
        ],
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": PARENT_GATE_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        **FALSE_AUTHORITY_FLAGS,
    }
    # This call is intentionally before the first Popen.  WitnessJournal writes
    # and fsyncs START before any child can be unblocked or launched.
    journal.start(attempt_id, evidence=started_evidence)

    children: list[_Child] = []
    broker: _Broker | None = None
    inspect_records: dict[str, Any] = {}
    broker_result: dict[str, Any] | None = None
    fault: str | None = None
    try:
        children = _launch_children(commands, names)
        broker = _Broker(
            children,
            task,
            session_id=session_id,
            arm_claim_sha256=claim_sha256,
            arm_deadline_seconds=arm_deadline_seconds,
        )
        broker_result = broker.run()
        inspect_records = _inspect_containers(
            children,
            snapshot,
            image=image,
            session_id=session_id,
            arm_claim_sha256=claim_sha256,
            cpu_millicores=cpu_millicores,
            memory_bytes=memory_bytes,
            pids_limit=pids_limit,
            tmpfs_bytes=tmpfs_bytes,
            docker_timeout=docker_timeout,
            strict=True,
        )
    except BaseException as exc:
        fault = f"{type(exc).__name__}: {exc}"
        if children:
            inspect_records = _inspect_containers(
                children,
                snapshot,
                image=image,
                session_id=session_id,
                arm_claim_sha256=claim_sha256,
                cpu_millicores=cpu_millicores,
                memory_bytes=memory_bytes,
                pids_limit=pids_limit,
                tmpfs_bytes=tmpfs_bytes,
                docker_timeout=docker_timeout,
                strict=False,
            )
        _kill_and_remove(children, names, docker_timeout=docker_timeout)
    else:
        _remove_exited(names, docker_timeout=docker_timeout)

    try:
        _verify_snapshot(snapshot, snapshot_manifest)
    except BaseException as exc:
        snapshot_fault = f"{type(exc).__name__}: {exc}"
        fault = snapshot_fault if fault is None else f"{fault}; {snapshot_fault}"

    if fault is None and broker_result is None:
        fault = "host broker returned no terminal result"
    try:
        terminal_evidence = _write_artifacts(
            artifact_root,
            children,
            commands,
            inspect_records,
            broker_result,
            fault=fault,
            campaign_sha256=campaign_sha256,
            arm_claim_sha256=claim_sha256,
            snapshot_manifest=snapshot_manifest,
        )
        witnessed_terminal_evidence = _install_witness_cas(
            journal,
            artifact_root,
            terminal_evidence,
        )
        terminal_status = "SUCCESS" if fault is None else "FAILURE"
        journal.terminal(
            attempt_id,
            terminal_status,
            evidence=witnessed_terminal_evidence,
        )
    except BaseException as exc:
        try:
            burned = burn_started_attempt(journal, attempt_id, exc)
        except BaseException as burn_exc:
            raise SandboxArmError(
                f"post-START sealing failed and burn could not be sealed: {burn_exc}"
            ) from exc
        raise SandboxArmError(
            f"post-START sealing failed; attempt is {burned['terminal_status']}"
        ) from exc
    witness = compose_witnessed_arm(journal, attempt_id)
    result = {
        "schema": ARM_RESULT_SCHEMA,
        "execution_mode": "standalone_unparented",
        "scope": "single_arm",
        "status": "SUCCESS" if fault is None else "FAULT",
        "terminal_status": terminal_status,
        "fault": fault,
        "arm_claim_sha256": claim_sha256,
        "campaign_sha256": campaign_sha256,
        "attempt_id": attempt_id,
        "artifact_root": str(artifact_root),
        "snapshot_tree_sha256": snapshot_manifest["tree_sha256"],
        "transcript_sha256": (broker_result or {}).get("transcript_sha256"),
        "outcome": (broker_result or {}).get("outcome"),
        "winner_role": (broker_result or {}).get("winner_role"),
        "winner_index": (broker_result or {}).get("winner_index"),
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": PARENT_GATE_STATEMENT,
        "authority_statement": AUTHORITY_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        "witness": witness,
        "policy_result_accepted": False,
        **FALSE_AUTHORITY_FLAGS,
    }
    return result


run_host_execute = execute_arm


def _load_policy(policy_dir: Path, role: str) -> Any:
    main_path = policy_dir.resolve() / "main.py"
    if not main_path.is_file():
        raise SandboxArmError(f"policy is missing main.py: {main_path}")
    sys.path.insert(0, str(policy_dir.resolve()))
    old_cwd = Path.cwd()
    os.chdir(policy_dir.resolve())
    try:
        module_name = f"sandbox_policy_{role}_{hashlib.sha256(str(main_path).encode()).hexdigest()[:16]}"
        spec = importlib.util.spec_from_file_location(module_name, main_path)
        if spec is None or spec.loader is None:
            raise SandboxArmError(f"could not load policy module: {main_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        agent = getattr(module, "agent", None)
        if not callable(agent):
            raise SandboxArmError("policy main.py does not define callable agent")
        return agent
    finally:
        os.chdir(old_cwd)
        try:
            sys.path.remove(str(policy_dir.resolve()))
        except ValueError:
            pass


def _worker_hello(role: str, session_id: str, arm_claim_sha256: str) -> None:
    payload = {
        "schema": PROTOCOL_SCHEMA + "_hello_v1",
        "session_id": session_id,
        "arm_claim_sha256": arm_claim_sha256,
        "role": role,
        "sandbox_id": role,
        "protocol": PROTOCOL_SCHEMA,
    }
    frame = Frame(role, "HELLO", 1, payload)
    write_frame(sys.stdout.buffer, frame)
    sys.stdout.buffer.flush()


def _worker_ready(role: str, session_id: str, arm_claim_sha256: str) -> None:
    frame = read_next_frame(sys.stdin.buffer)
    try:
        payload = validate_ready(frame.payload, frame_role=role)
    except SandboxProtocolError as exc:
        raise SandboxArmError(f"invalid READY: {exc}") from exc
    if (
        frame.role != role
        or frame.message_type != "READY"
        or frame.sequence != 1
        or payload["session_id"] != session_id
        or payload["arm_claim_sha256"] != arm_claim_sha256
    ):
        raise SandboxArmError("READY is not bound to this worker")


def _policy_worker(role: str, session_id: str, arm_claim_sha256: str, policy_dir: Path) -> int:
    if role not in {"candidate_policy", "opponent_policy"}:
        raise SandboxArmError("policy worker role must be candidate_policy or opponent_policy")
    agent = _load_policy(policy_dir, role)
    _worker_hello(role, session_id, arm_claim_sha256)
    _worker_ready(role, session_id, arm_claim_sha256)
    next_sequence = 2
    last_referee_sequence = 1
    last_turn_id = -1
    seen_requests: set[str] = set()
    behavior = os.environ.get("SANDBOX_TEST_BEHAVIOR", "")
    while True:
        frame = read_next_frame(sys.stdin.buffer)
        if frame.message_type == "TERMINAL":
            validate_terminal(frame.payload)
            return 0
        if frame.role != "referee" or frame.message_type != "ACTION_REQUEST":
            raise SandboxArmError("policy worker received a non-request frame")
        request = validate_action_request(frame.payload)
        if frame.sequence <= last_referee_sequence:
            raise SandboxArmError("policy worker received a stale referee sequence")
        if (
            request["session_id"] != session_id
            or request["arm_claim_sha256"] != arm_claim_sha256
            or request["actor_role"] != role
        ):
            raise SandboxArmError("policy worker request binding mismatch")
        if request["request_id"] in seen_requests or request["turn_id"] <= last_turn_id:
            raise SandboxArmError("policy worker received a replayed or stale request")
        last_referee_sequence = frame.sequence
        last_turn_id = request["turn_id"]
        seen_requests.add(request["request_id"])
        if behavior == "os_exit":
            os._exit(97)
        if behavior == "stdout_garbage":
            sys.stdout.buffer.write(b"policy-garbage")
            sys.stdout.buffer.flush()
        if behavior == "hang":
            time.sleep(3600.0)
        action = agent(request["observation"])
        if behavior == "illegal":
            action = [request["legal_option_count"]]
        response_binding = dict(request)
        response_binding.pop("observation", None)
        response_binding.pop("legal_option_count", None)
        response_binding.pop("legal_min_count", None)
        response_binding.pop("legal_max_count", None)
        response_binding["schema"] = ACTION_RESPONSE_SCHEMA
        response_binding["action"] = action
        if behavior == "stale":
            response_binding["request_id"] = "stale-request"
        response = Frame(role, "ACTION_RESPONSE", next_sequence, response_binding)
        raw = response.to_bytes()
        write_frame(sys.stdout.buffer, raw)
        sys.stdout.buffer.flush()
        next_sequence += 1
        # A deliberately malicious out-of-range/stale frame is still sent to
        # the host boundary.  A normal frame must satisfy the local contract.
        try:
            validate_action_response(
                response.payload,
                legal_option_count=request["legal_option_count"],
                expected_request=request,
            )
        except SandboxProtocolError:
            return 2


def _read_deck(path: Path) -> list[int]:
    try:
        values = [int(line.strip()) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    except (OSError, UnicodeError, ValueError) as exc:
        raise SandboxArmError(f"invalid deck {path}: {exc}") from exc
    if len(values) != 60:
        raise SandboxArmError(f"deck {path} must contain 60 cards")
    return values


def _referee_terminal(
    sequence: int,
    session_id: str,
    arm_claim_sha256: str,
    observation: Mapping[str, Any],
    request_id: str,
    turn_id: int,
    outcome: str,
    winner_role: str | None,
) -> Frame:
    payload = {
        "schema": PROTOCOL_SCHEMA + "_terminal_v1",
        "session_id": session_id,
        "arm_claim_sha256": arm_claim_sha256,
        "game_id": GAME_ID,
        "turn_id": turn_id,
        "actor_role": "referee",
        "observation_sha256": canonical_sha256(observation),
        "request_id": request_id,
        "outcome": outcome,
        "winner_role": winner_role,
    }
    return Frame("referee", "TERMINAL", sequence, payload)


def _referee_worker(
    session_id: str,
    arm_claim_sha256: str,
    task_path: Path,
    left_deck_path: Path,
    right_deck_path: Path,
    engine_dir: Path,
) -> int:
    task = _read_json(task_path)
    if not isinstance(task, Mapping) or task.get("schema") != "evaluation_v4_2_container_arm_task_v1":
        raise SandboxArmError("referee task is not a validated v4.2 task")
    left_deck = _read_deck(left_deck_path)
    right_deck = _read_deck(right_deck_path)
    from evaluation_v2.seeded_arena import load_seeded_game

    game = load_seeded_game(engine_dir)
    state = ProtocolState()
    hello_payload = {
        "schema": PROTOCOL_SCHEMA + "_hello_v1",
        "session_id": session_id,
        "arm_claim_sha256": arm_claim_sha256,
        "role": "referee",
        "sandbox_id": "referee",
        "protocol": PROTOCOL_SCHEMA,
    }
    hello = Frame("referee", "HELLO", 1, hello_payload)
    _worker_hello("referee", session_id, arm_claim_sha256)
    _worker_ready("referee", session_id, arm_claim_sha256)
    state.accept(hello)
    # Policy HELLO frames are broker-local and are not forwarded to the
    # referee, but their sequence-1 anchors are needed for relayed responses.
    for role in ("candidate_policy", "opponent_policy"):
        state.accept(
            Frame(
                role,
                "HELLO",
                1,
                {
                    "schema": PROTOCOL_SCHEMA + "_hello_v1",
                    "session_id": session_id,
                    "arm_claim_sha256": arm_claim_sha256,
                    "role": role,
                    "sandbox_id": role,
                    "protocol": PROTOCOL_SCHEMA,
                },
            )
        )
    sequence = 2
    last_observation: Mapping[str, Any] = {
        "current": {"yourIndex": 0},
        "select": {"option": [{"index": 0}], "minCount": 0, "maxCount": 1},
    }
    last_request_id = "start-0"
    policy_left = task["seat"] == "policy_first"
    try:
        observation, start = game.battle_start_seeded(left_deck, right_deck, task["seed"])
        if observation is None:
            raise SandboxArmError(f"engine start failed: player={start.errorPlayer} type={start.errorType}")
        max_steps = int(task["max_steps"])
        for step in range(1, max_steps + 2):
            current = observation.get("current") or {}
            result = current.get("result")
            last_observation = observation
            if result is not None and int(result) != -1:
                winner_index = int(result)
                if winner_index == 2:
                    winner_role = None
                elif winner_index in (0, 1):
                    left_role = "candidate_policy" if policy_left else "opponent_policy"
                    right_role = "opponent_policy" if policy_left else "candidate_policy"
                    winner_role = left_role if winner_index == 0 else right_role
                else:
                    raise SandboxArmError("engine returned an invalid winner")
                terminal = _referee_terminal(
                    sequence,
                    session_id,
                    arm_claim_sha256,
                    observation,
                    last_request_id,
                    step - 1,
                    "game_complete",
                    winner_role,
                )
                state.accept(terminal)
                write_frame(sys.stdout.buffer, terminal)
                sys.stdout.buffer.flush()
                return 0
            if step > max_steps:
                break
            select = observation.get("select")
            if not isinstance(select, Mapping) or not isinstance(select.get("option"), list):
                raise SandboxArmError("engine returned an invalid selection")
            options = select["option"]
            minimum = select.get("minCount", 0)
            maximum = select.get("maxCount", len(options))
            actor_index = int(current.get("yourIndex"))
            if actor_index not in (0, 1):
                raise SandboxArmError("engine returned an invalid actor")
            left_role = "candidate_policy" if policy_left else "opponent_policy"
            right_role = "opponent_policy" if policy_left else "candidate_policy"
            actor_role = left_role if actor_index == 0 else right_role
            last_request_id = f"action-{step}"
            request_payload = {
                "schema": ACTION_REQUEST_SCHEMA,
                "session_id": session_id,
                "arm_claim_sha256": arm_claim_sha256,
                "game_id": GAME_ID,
                "turn_id": step,
                "actor_role": actor_role,
                "observation_sha256": canonical_sha256(observation),
                "request_id": last_request_id,
                "observation": json.loads(canonical_json_bytes(dict(observation)).decode("ascii")),
                "legal_options_sha256": canonical_sha256(select),
                "legal_option_count": len(options),
                "legal_min_count": int(minimum),
                "legal_max_count": int(maximum),
            }
            if not options:
                raise SandboxArmError("engine returned no legal options")
            request = Frame("referee", "ACTION_REQUEST", sequence, request_payload)
            state.accept(request)
            write_frame(sys.stdout.buffer, request)
            sys.stdout.buffer.flush()
            sequence += 1
            response = read_next_frame(sys.stdin.buffer)
            if response.role != actor_role or response.message_type != "ACTION_RESPONSE":
                raise SandboxArmError("referee received the wrong policy response")
            checked = validate_action_response(
                response.payload,
                legal_option_count=len(options),
                expected_request=request_payload,
            )
            state.accept(response)
            observation = game.battle_select(checked["action"])
        raise SandboxArmError("engine reached max_steps without a terminal result")
    finally:
        try:
            game.battle_finish()
        except BaseException:
            pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    policy = subparsers.add_parser("policy-worker")
    policy.add_argument("--role", choices=("candidate_policy", "opponent_policy"), required=True)
    policy.add_argument("--session-id", required=True)
    policy.add_argument("--arm-claim-sha256", required=True)
    policy.add_argument("--policy-dir", type=Path, required=True)
    referee = subparsers.add_parser("referee-worker")
    referee.add_argument("--session-id", required=True)
    referee.add_argument("--arm-claim-sha256", required=True)
    referee.add_argument("--task", type=Path, required=True)
    referee.add_argument("--left-deck", type=Path, required=True)
    referee.add_argument("--right-deck", type=Path, required=True)
    referee.add_argument("--engine", type=Path, required=True)
    execute = subparsers.add_parser("execute")
    execute.add_argument("--bundle-dir", type=Path, required=True)
    execute.add_argument("--output-dir", type=Path, required=True)
    execute.add_argument("--journal-root", type=Path, required=True)
    execute.add_argument("--hmac-key", required=True)
    execute.add_argument("--attempt-id", required=True)
    execute.add_argument("--claim-sha256")
    execute.add_argument("--campaign-sha256")
    execute.add_argument("--image", default=DEFAULT_IMAGE)
    execute.add_argument("--arm-deadline-seconds", type=float, default=DEFAULT_ARM_DEADLINE_SECONDS)
    execute.add_argument("--docker-timeout", type=float, default=DEFAULT_DOCKER_CALL_TIMEOUT_SECONDS)
    execute.add_argument("--cpu-millicores", type=int, default=DEFAULT_CPU_MILLICORES)
    execute.add_argument("--memory-bytes", type=int, default=DEFAULT_MEMORY_BYTES)
    execute.add_argument("--pids-limit", type=int, default=DEFAULT_PIDS_LIMIT)
    execute.add_argument("--tmpfs-bytes", type=int, default=DEFAULT_TMPFS_BYTES)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.mode == "policy-worker":
            return _policy_worker(args.role, args.session_id, _require_digest(args.arm_claim_sha256, "arm claim"), args.policy_dir)
        if args.mode == "referee-worker":
            return _referee_worker(
                args.session_id,
                _require_digest(args.arm_claim_sha256, "arm claim"),
                args.task,
                args.left_deck,
                args.right_deck,
                args.engine,
            )
        journal = WitnessJournal(journal_root=args.journal_root, hmac_key=args.hmac_key)
        result = execute_arm(
            args.bundle_dir,
            output_dir=args.output_dir,
            journal=journal,
            attempt_id=args.attempt_id,
            claim_sha256=args.claim_sha256,
            campaign_sha256=args.campaign_sha256,
            image=args.image,
            arm_deadline_seconds=args.arm_deadline_seconds,
            docker_timeout=args.docker_timeout,
            cpu_millicores=args.cpu_millicores,
            memory_bytes=args.memory_bytes,
            pids_limit=args.pids_limit,
            tmpfs_bytes=args.tmpfs_bytes,
        )
        print(canonical_json_bytes(result).decode("ascii"))
        return 0 if result["status"] == "SUCCESS" else 3
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
