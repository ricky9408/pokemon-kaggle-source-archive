#!/usr/bin/env python3
"""Prepare and execute one v4.2 arm in a locked-down Linux/amd64 container.

The host side creates a deterministic read-only input bundle, claims one
attempt with ``O_EXCL``, runs one container under an external watchdog, checks
Docker's observed configuration, and writes one terminal receipt.  This is
local trusted-host verification, not remote attestation and not submission
authority.
"""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SCHEMA = "evaluation_v4_2_container_input_bundle_v1"
TASK_SCHEMA = "evaluation_v4_2_container_arm_task_v1"
SECURITY_SPEC_SCHEMA = "evaluation_v4_2_docker_security_spec_v1"
ATTEMPT_FAILURE_SCHEMA = "evaluation_v4_2_local_attempt_failure_v1"
DEFAULT_IMAGE = (
    "docker.io/library/python@sha256:"
    "a7bce671c71744cd4dcef2bc9cd9c5eff3d7cfa6b55eca30759765047184bcdb"
)
DEFAULT_CPU_MILLICORES = 1000
DEFAULT_MEMORY_BYTES = 512 * 1024 * 1024
DEFAULT_PIDS_LIMIT = 64
DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
DEFAULT_ARM_DEADLINE_SECONDS = 900.0
DEFAULT_ACTION_DEADLINE_SECONDS = 1.0
DEFAULT_OUTPUT_LIMIT_BYTES = 1024 * 1024
CONTAINER_USER = "65534:65534"

_SHA256_RE = __import__("re").compile(r"^[0-9a-f]{64}$")
_TASK_FIELDS = frozenset(
    {
        "schema",
        "policy_label",
        "policy_archive_sha256",
        "policy_policy_content_sha256",
        "policy_main_sha256",
        "policy_deck_sha256",
        "opponent_id",
        "opponent_archive_sha256",
        "opponent_policy_content_sha256",
        "opponent_main_sha256",
        "opponent_deck_sha256",
        "engine_id",
        "engine_binary_sha256",
        "engine_runtime_tree_sha256",
        "seed",
        "seat",
        "max_steps",
        "max_action_seconds",
    }
)


class ContainerArmError(RuntimeError):
    """The one-shot container arm could not be prepared or verified."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContainerArmError(f"could not read JSON {path}: {exc}") from exc


def _write_json_exclusive(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True).encode("ascii") + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    except FileExistsError as exc:
        raise ContainerArmError(f"one-shot artifact already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _record_claimed_failure(
    *, claim_path: Path, attempts_root: Path, error: BaseException
) -> None:
    """Best-effort terminal marker for an exception after a claim was burned."""

    try:
        claim = _json(claim_path.resolve())
        attempt_id = claim.get("attempt_id") if isinstance(claim, Mapping) else None
        claim_sha256 = claim.get("content_sha256") if isinstance(claim, Mapping) else None
        if (
            not isinstance(attempt_id, str)
            or _SHA256_RE.fullmatch(attempt_id) is None
            or not isinstance(claim_sha256, str)
            or _SHA256_RE.fullmatch(claim_sha256) is None
        ):
            return
        attempt_dir = attempts_root.resolve() / attempt_id
        if not (attempt_dir / "claim.json").is_file() or (attempt_dir / "receipt.json").exists():
            return
        content = {
            "schema": ATTEMPT_FAILURE_SCHEMA,
            "attempt_id": attempt_id,
            "claim_content_sha256": claim_sha256,
            "recorded_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "error_type": type(error).__name__,
            "error": str(error)[:4000],
            "disposition": "ARM_BURNED_PANEL_VETO",
            "authority": "LOCAL_DOCKER_EXECUTION_EVIDENCE_ONLY",
            "remote_attestation_verified": False,
            "anchor_allowed": False,
            "production_submission_authorized": False,
            "submit_authorized": False,
        }
        payload = {**content, "content_sha256": _canonical_sha256(content)}
        _write_json_exclusive(attempt_dir / "failure.json", payload)
    except BaseException:
        # The existing claim directory is already a permanent veto.  Failure
        # reporting must never hide the original exception.
        return


def _cleanup_claim_container(claim_path: Path) -> None:
    """Best-effort cleanup after evidence has been persisted."""

    try:
        claim = _json(claim_path.resolve())
        attempt_id = claim.get("attempt_id") if isinstance(claim, Mapping) else None
        if isinstance(attempt_id, str) and _SHA256_RE.fullmatch(attempt_id):
            subprocess.run(
                ["docker", "container", "rm", "--force", f"ev42-{attempt_id[:40]}"],
                capture_output=True,
            )
    except BaseException:
        return


def _tree_records(root: Path, *, excluded: frozenset[str] = frozenset()) -> list[dict[str, str]]:
    resolved = root.resolve()
    if resolved.is_symlink() or not resolved.is_dir():
        raise ContainerArmError(f"tree is not a regular directory: {resolved}")
    records: list[dict[str, str]] = []
    for item in sorted(resolved.rglob("*"), key=lambda value: value.relative_to(resolved).as_posix()):
        relative = item.relative_to(resolved).as_posix()
        if relative in excluded:
            continue
        if item.is_symlink():
            raise ContainerArmError(f"tree contains a symlink: {item}")
        if item.is_file():
            records.append({"path": relative, "sha256": _sha256_file(item)})
    if not records:
        raise ContainerArmError(f"tree contains no files: {resolved}")
    return records


def _tree_sha256(root: Path, *, excluded: frozenset[str] = frozenset()) -> str:
    return _canonical_sha256(_tree_records(root, excluded=excluded))


def _copy_tree_readable(source: Path, destination: Path) -> None:
    source = source.resolve()
    if source.is_symlink() or not source.is_dir():
        raise ContainerArmError(f"source tree is invalid: {source}")
    destination.mkdir(parents=True, exist_ok=False)
    for item in sorted(source.rglob("*"), key=lambda value: value.relative_to(source).as_posix()):
        relative = item.relative_to(source)
        if "__pycache__" in relative.parts or item.name.endswith((".pyc", ".pyo")):
            continue
        if item.is_symlink():
            raise ContainerArmError(f"source tree contains a symlink: {item}")
        target = destination / relative
        if item.is_dir():
            target.mkdir(exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
        else:
            raise ContainerArmError(f"source tree contains a non-file entry: {item}")


def _freeze_tree_permissions(root: Path) -> None:
    for item in sorted(root.rglob("*"), reverse=True):
        if item.is_file():
            item.chmod(0o444)
        elif item.is_dir():
            item.chmod(0o555)
    root.chmod(0o555)


def _identity(path: Path) -> dict[str, str]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from dataclasses import asdict
    from evaluation_v2.public_transfer import archive_policy_identity

    return asdict(archive_policy_identity(path))


def _materialized_policy_identity(path: Path) -> dict[str, str]:
    """Recompute the archive policy identity from staged extracted bytes."""

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from evaluation_v2.cohort import deck_sha256

    digest = hashlib.sha256()
    main_bytes: bytes | None = None
    deck_bytes: bytes | None = None
    members: list[tuple[str, Path]] = []
    for item in path.rglob("*"):
        if item.is_symlink():
            raise ContainerArmError(f"materialized policy contains a symlink: {item}")
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
        raise ContainerArmError("materialized policy lacks main.py or deck.csv")
    try:
        cards = tuple(
            int(line.strip())
            for line in deck_bytes.decode("utf-8-sig").splitlines()
            if line.strip()
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise ContainerArmError(f"materialized policy deck is invalid: {exc}") from exc
    if len(cards) != 60:
        raise ContainerArmError(f"materialized policy deck has {len(cards)} cards")
    return {
        "policy_content_sha256": digest.hexdigest(),
        "main_sha256": hashlib.sha256(main_bytes).hexdigest(),
        "deck_sha256": deck_sha256(cards),
    }


def _materialize(path: Path, destination: Path, custody_archive: Path) -> dict[str, str]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from evaluation_v2.public_transfer import materialize_historical_archive

    archive_bytes = path.read_bytes()
    custody_archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(custody_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    except FileExistsError as exc:
        raise ContainerArmError(f"custody archive already exists: {custody_archive}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(archive_bytes)
        handle.flush()
        os.fsync(handle.fileno())
    identity = _identity(custody_archive)
    if identity["archive_sha256"] != _sha256_bytes(archive_bytes):
        raise ContainerArmError("custody archive identity changed while staging")
    materialize_historical_archive(custody_archive, destination)
    if not (destination / "main.py").is_file() or not (destination / "deck.csv").is_file():
        raise ContainerArmError(f"archive did not materialize a policy: {path}")
    materialized = _materialized_policy_identity(destination)
    expected = {key: identity[key] for key in materialized}
    if materialized != expected:
        raise ContainerArmError(
            f"materialized policy identity mismatch: expected={expected} actual={materialized}"
        )
    return identity


def _engine_identity(engine_dir: Path) -> dict[str, str]:
    engine = engine_dir.resolve()
    binary = engine / "cg" / "libcg.so"
    if not binary.is_file():
        binary = engine / "libcg.so"
    if not binary.is_file():
        raise ContainerArmError(f"engine lacks libcg.so: {engine}")
    return {
        "binary_sha256": _sha256_file(binary),
        "runtime_tree_sha256": _tree_sha256(engine),
    }


def _validate_task(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _TASK_FIELDS:
        raise ContainerArmError(f"task fields must exactly be {sorted(_TASK_FIELDS)}")
    task = dict(value)
    if task["schema"] != TASK_SCHEMA:
        raise ContainerArmError(f"task schema must be {TASK_SCHEMA!r}")
    if task["policy_label"] not in ("candidate", "baseline"):
        raise ContainerArmError("task policy_label must be candidate or baseline")
    if task["seat"] not in ("policy_first", "policy_second"):
        raise ContainerArmError("task seat is invalid")
    for field in (
        "policy_archive_sha256",
        "policy_policy_content_sha256",
        "policy_main_sha256",
        "policy_deck_sha256",
        "opponent_archive_sha256",
        "opponent_policy_content_sha256",
        "opponent_main_sha256",
        "opponent_deck_sha256",
        "engine_binary_sha256",
        "engine_runtime_tree_sha256",
    ):
        if not isinstance(task[field], str) or _SHA256_RE.fullmatch(task[field]) is None:
            raise ContainerArmError(f"task {field} is not a SHA-256 digest")
    for field in ("opponent_id", "engine_id"):
        if not isinstance(task[field], str) or not task[field].strip() or task[field] != task[field].strip():
            raise ContainerArmError(f"task {field} is invalid")
    if isinstance(task["seed"], bool) or not isinstance(task["seed"], int) or not 0 <= task["seed"] < 2**63:
        raise ContainerArmError("task seed is invalid")
    if isinstance(task["max_steps"], bool) or not isinstance(task["max_steps"], int) or task["max_steps"] <= 0:
        raise ContainerArmError("task max_steps is invalid")
    if not isinstance(task["max_action_seconds"], float) or not math.isfinite(task["max_action_seconds"]) or task["max_action_seconds"] <= 0:
        raise ContainerArmError("task max_action_seconds must be a positive canonical float")
    return task


def prepare_input_bundle(
    *,
    policy_archive: Path,
    opponent_archive: Path,
    engine_dir: Path,
    output_dir: Path,
    policy_label: str,
    opponent_id: str,
    engine_id: str,
    seed: int,
    seat: str,
    max_steps: int,
    max_action_seconds: float,
) -> dict[str, Any]:
    """Create one immutable, arm-private input bundle before protocol freeze."""

    output = output_dir.resolve()
    if output.exists():
        raise ContainerArmError(f"bundle destination already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent)))
    try:
        policy_identity = _materialize(
            policy_archive.resolve(), temporary / "policy", temporary / "custody" / "policy.tar.gz"
        )
        opponent_identity = _materialize(
            opponent_archive.resolve(),
            temporary / "opponent",
            temporary / "custody" / "opponent.tar.gz",
        )
        _copy_tree_readable(engine_dir.resolve(), temporary / "engine")
        engine_identity = _engine_identity(temporary / "engine")
        runtime = temporary / "runtime"
        runtime.mkdir()
        _copy_tree_readable(ROOT / "evaluation_v2", runtime / "evaluation_v2")
        shutil.copyfile(Path(__file__).resolve(), runtime / "container_arm.py")

        task = _validate_task(
            {
                "schema": TASK_SCHEMA,
                "policy_label": policy_label,
                "policy_archive_sha256": policy_identity["archive_sha256"],
                "policy_policy_content_sha256": policy_identity["policy_content_sha256"],
                "policy_main_sha256": policy_identity["main_sha256"],
                "policy_deck_sha256": policy_identity["deck_sha256"],
                "opponent_id": opponent_id,
                "opponent_archive_sha256": opponent_identity["archive_sha256"],
                "opponent_policy_content_sha256": opponent_identity["policy_content_sha256"],
                "opponent_main_sha256": opponent_identity["main_sha256"],
                "opponent_deck_sha256": opponent_identity["deck_sha256"],
                "engine_id": engine_id,
                "engine_binary_sha256": engine_identity["binary_sha256"],
                "engine_runtime_tree_sha256": engine_identity["runtime_tree_sha256"],
                "seed": seed,
                "seat": seat,
                "max_steps": max_steps,
                "max_action_seconds": float(max_action_seconds),
            }
        )
        (temporary / "task.json").write_bytes(_canonical_bytes(task) + b"\n")
        runtime_sha256 = _tree_sha256(runtime)
        source_sha256 = _sha256_file(runtime / "container_arm.py")
        bundle_tree_sha256 = _tree_sha256(temporary)
        content = {
            "schema": BUNDLE_SCHEMA,
            "task": task,
            "task_spec_sha256": _canonical_sha256(task),
            "bundle_tree_sha256": bundle_tree_sha256,
            "runtime_bundle_sha256": runtime_sha256,
            "worker_source_sha256": source_sha256,
            "authority": "DEVELOPMENT_ONLY",
            "anchor_allowed": False,
            "production_submission_authorized": False,
        }
        manifest = {**content, "content_sha256": _canonical_sha256(content)}
        (temporary / "bundle_manifest.json").write_bytes(_canonical_bytes(manifest) + b"\n")
        os.replace(temporary, output)
        _freeze_tree_permissions(output)
        return manifest
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def validate_input_bundle(path: Path) -> dict[str, Any]:
    bundle = path.resolve()
    manifest = _json(bundle / "bundle_manifest.json")
    expected_fields = {
        "schema",
        "task",
        "task_spec_sha256",
        "bundle_tree_sha256",
        "runtime_bundle_sha256",
        "worker_source_sha256",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
        "content_sha256",
    }
    if not isinstance(manifest, Mapping) or set(manifest) != expected_fields:
        raise ContainerArmError("bundle manifest fields are invalid")
    if manifest["schema"] != BUNDLE_SCHEMA:
        raise ContainerArmError("bundle manifest schema is invalid")
    task = _validate_task(manifest["task"])
    if manifest["task_spec_sha256"] != _canonical_sha256(task):
        raise ContainerArmError("bundle task_spec_sha256 mismatch")
    if manifest["bundle_tree_sha256"] != _tree_sha256(
        bundle, excluded=frozenset({"bundle_manifest.json"})
    ):
        raise ContainerArmError("bundle tree changed after freeze")
    if manifest["runtime_bundle_sha256"] != _tree_sha256(bundle / "runtime"):
        raise ContainerArmError("runtime bundle changed after freeze")
    if manifest["worker_source_sha256"] != _sha256_file(bundle / "runtime" / "container_arm.py"):
        raise ContainerArmError("worker source changed after freeze")
    if (
        manifest["authority"] != "DEVELOPMENT_ONLY"
        or manifest["anchor_allowed"] is not False
        or manifest["production_submission_authorized"] is not False
    ):
        raise ContainerArmError("bundle authority fields are invalid")
    content = {key: manifest[key] for key in expected_fields if key != "content_sha256"}
    if manifest["content_sha256"] != _canonical_sha256(content):
        raise ContainerArmError("bundle manifest content_sha256 mismatch")
    return dict(manifest)


def docker_security_spec(protocol: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact host-enforced Docker security specification."""

    return {
        "schema": SECURITY_SPEC_SCHEMA,
        "platform": protocol["platform"],
        "network_mode": protocol["network_mode"],
        "read_only_rootfs": protocol["read_only_rootfs"],
        "cap_drop": protocol["cap_drop"],
        "no_new_privileges": protocol["no_new_privileges"],
        "user": CONTAINER_USER,
        "ipc_mode": "none",
        "pid_mode": "private",
        "pids_limit": protocol["pids_limit"],
        "memory_limit_bytes": protocol["memory_limit_bytes"],
        "memory_swap_limit_bytes": protocol["memory_limit_bytes"],
        "cpu_limit_millicores": protocol["cpu_limit_millicores"],
        "tmpfs": {
            "target": protocol["scratch_tmpfs"]["target"],
            "size_bytes": protocol["scratch_tmpfs"]["size_bytes"],
            "options": sorted(
                ["rw", "noexec", "nosuid", "nodev", "mode=700", "uid=65534", "gid=65534"]
            ),
        },
        "ulimits": {
            "core": "0:0",
            "nofile": "256:256",
            "nproc": f"{protocol['pids_limit']}:{protocol['pids_limit']}",
        },
        "environment": [
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONHASHSEED=0",
            "PYTHONPATH=/input/runtime",
        ],
        "mount_targets": [mount["target"] for mount in protocol["input_mounts"]],
        "command": protocol["command"],
    }


def build_protocol_for_bundle(
    bundle_dir: Path,
    *,
    arm_id: str | None = None,
    image: str = DEFAULT_IMAGE,
    cpu_millicores: int = DEFAULT_CPU_MILLICORES,
    memory_bytes: int = DEFAULT_MEMORY_BYTES,
    pids_limit: int = DEFAULT_PIDS_LIMIT,
    tmpfs_bytes: int = DEFAULT_TMPFS_BYTES,
    arm_deadline_seconds: float = DEFAULT_ARM_DEADLINE_SECONDS,
) -> dict[str, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from evaluation_v4_2.container_protocol import (
        CONTAINER_PROTOCOL_SCHEMA,
        compile_container_protocol,
    )

    manifest = validate_input_bundle(bundle_dir)
    task = manifest["task"]
    if arm_id is None:
        from evaluation_v4_2.execution_plan import arm_protocol_id

        arm_id = arm_protocol_id(
            task["policy_label"],
            task["engine_id"],
            task["opponent_id"],
            task["seed"],
            task["seat"],
        )
    image_digest = image.rsplit("@sha256:", 1)[-1]
    image_manifest = _image_manifest_observation(image)
    command = ["python", "/input/runtime/container_arm.py", "worker", "--task", "/input/task.json"]
    preliminary = {
        "schema": CONTAINER_PROTOCOL_SCHEMA,
        "arm_id": arm_id,
        "arm_kind": task["policy_label"],
        "bundle_manifest_sha256": manifest["content_sha256"],
        "task_spec_sha256": manifest["task_spec_sha256"],
        "oci_image": image,
        "image_digest_sha256": image_digest,
        "image_manifest_media_type": image_manifest["media_type"],
        "image_manifest_raw_sha256": image_manifest["raw_sha256"],
        "image_config_sha256": image_manifest["config_sha256"],
        "image_layer_sha256s": image_manifest["layer_sha256s"],
        "platform": "linux/amd64",
        "network_mode": "none",
        "read_only_rootfs": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "input_mounts": [
            {
                "source_id": "arm-private-input-bundle",
                "source_sha256": manifest["bundle_tree_sha256"],
                "target": "/input",
                "read_only": True,
                "private": True,
            }
        ],
        "scratch_tmpfs": {
            "target": "/tmp",
            "size_bytes": tmpfs_bytes,
            "read_only": False,
            "private": True,
        },
        "cpu_limit_millicores": cpu_millicores,
        "memory_limit_bytes": memory_bytes,
        "pids_limit": pids_limit,
        "max_steps": task["max_steps"],
        "output_limit_bytes": DEFAULT_OUTPUT_LIMIT_BYTES,
        "arm_deadline_seconds": float(arm_deadline_seconds),
        "arm_deadline_enforcement": "external_watchdog",
        "action_deadline_seconds": task["max_action_seconds"],
        "action_deadline_enforcement": "exact_per_action",
        "retry_policy": "none",
        "container_scope": "one_arm_per_container",
        "runtime_sha256": manifest["runtime_bundle_sha256"],
        "security_sha256": "0" * 64,
        "source_sha256": _sha256_file(Path(__file__).resolve()),
        "command": command,
        "authority": "DEVELOPMENT_ONLY",
        "research_only": True,
        "external_authority": False,
        "submission_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
        "state": "FROZEN",
    }
    preliminary["security_sha256"] = _canonical_sha256(docker_security_spec(preliminary))
    return compile_container_protocol(preliminary)


def _run_json(command: list[str]) -> Any:
    completed = subprocess.run(command, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", errors="replace")[-2000:]
        raise ContainerArmError(f"command failed ({completed.returncode}): {' '.join(command)}: {detail}")
    try:
        return json.loads(completed.stdout)
    except ValueError as exc:
        raise ContainerArmError(f"command did not return JSON: {' '.join(command)}") from exc


def _image_manifest_observation(image: str) -> dict[str, Any]:
    completed = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", image],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode("utf-8", errors="replace")[-2000:]
        raise ContainerArmError(f"could not inspect raw OCI manifest: {detail}")
    raw_bytes = completed.stdout
    try:
        payload = json.loads(raw_bytes)
    except ValueError as exc:
        raise ContainerArmError("raw OCI manifest is not JSON") from exc
    if not isinstance(payload, Mapping):
        raise ContainerArmError("raw OCI manifest is not an object")
    if payload.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ContainerArmError("pinned OCI digest is not a single-platform image manifest")
    config = payload.get("config")
    layers = payload.get("layers")
    if not isinstance(config, Mapping) or not isinstance(layers, list) or not layers:
        raise ContainerArmError("OCI manifest lacks config or layers")
    config_digest = config.get("digest")
    layer_digests = [row.get("digest") if isinstance(row, Mapping) else None for row in layers]
    if (
        not isinstance(config_digest, str)
        or not config_digest.startswith("sha256:")
        or _SHA256_RE.fullmatch(config_digest[7:]) is None
        or any(
            not isinstance(value, str)
            or not value.startswith("sha256:")
            or _SHA256_RE.fullmatch(value[7:]) is None
            for value in layer_digests
        )
    ):
        raise ContainerArmError("OCI manifest config or layer digest is invalid")
    return {
        "media_type": payload["mediaType"],
        "raw_sha256": _sha256_bytes(raw_bytes),
        "config_sha256": config_digest[7:],
        "layer_sha256s": [value[7:] for value in layer_digests],
    }


def _image_observation(protocol: Mapping[str, Any]) -> dict[str, Any]:
    image = protocol["oci_image"]
    manifest = _image_manifest_observation(image)
    expected_manifest = {
        "media_type": protocol["image_manifest_media_type"],
        "raw_sha256": protocol["image_manifest_raw_sha256"],
        "config_sha256": protocol["image_config_sha256"],
        "layer_sha256s": protocol["image_layer_sha256s"],
    }
    if manifest != expected_manifest:
        raise ContainerArmError("resolved OCI manifest/config/layers differ from protocol")
    payload = _run_json(["docker", "image", "inspect", image])
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
        raise ContainerArmError("docker image inspect returned an invalid payload")
    row = payload[0]
    image_id = row.get("Id")
    if not isinstance(image_id, str) or not image_id.startswith("sha256:") or _SHA256_RE.fullmatch(image_id[7:]) is None:
        raise ContainerArmError("image config ID is invalid")
    if row.get("Architecture") != "amd64" or row.get("Os") != "linux":
        raise ContainerArmError("resolved image is not linux/amd64")
    expected_repo_digest = f"@sha256:{protocol['image_digest_sha256']}"
    if not any(
        isinstance(value, str) and value.endswith(expected_repo_digest)
        for value in (row.get("RepoDigests") or [])
    ):
        raise ContainerArmError("local image does not retain the exact pinned RepoDigest")
    return {
        "runtime_image_id_sha256": image_id[7:],
        "image_config_sha256": manifest["config_sha256"],
        "image_layer_sha256s": manifest["layer_sha256s"],
        "architecture": row["Architecture"],
        "os": row["Os"],
        "raw_sha256": _canonical_sha256(payload),
    }


def _daemon_evidence() -> tuple[str, dict[str, Any]]:
    version = _run_json(["docker", "version", "--format", "{{json .}}"])
    raw_info = _run_json(["docker", "info", "--format", "{{json .}}"])
    if not isinstance(raw_info, Mapping):
        raise ContainerArmError("docker info returned an invalid payload")
    info = {
        "security_options": raw_info.get("SecurityOptions"),
        "driver": raw_info.get("Driver"),
        "architecture": raw_info.get("Architecture"),
        "os_type": raw_info.get("OSType"),
        "kernel_version": raw_info.get("KernelVersion"),
        "cgroup_driver": raw_info.get("CgroupDriver"),
        "cgroup_version": raw_info.get("CgroupVersion"),
    }
    evidence = {"version": version, "info": info}
    return _canonical_sha256(evidence), evidence


def _expected_observed_spec(
    protocol: Mapping[str, Any],
    image: Mapping[str, Any],
    *,
    mount_source: Path,
    claim: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "evaluation_v4_2_observed_container_spec_v1",
        "runtime_image_id_sha256": image["runtime_image_id_sha256"],
        "image_architecture": image["architecture"],
        "image_os": image["os"],
        "security": docker_security_spec(protocol),
        "mounts": [
            {
                "source": str(mount_source.resolve()),
                "destination": mount["target"],
                "type": "bind",
                "read_only": True,
                "propagation": "rprivate",
            }
            for mount in protocol["input_mounts"]
        ],
        "labels": {
            "evaluation_v4_2.attempt_id": claim["attempt_id"],
            "evaluation_v4_2.claim_sha256": claim["content_sha256"],
            "evaluation_v4_2.protocol_sha256": protocol["content_sha256"],
        },
    }


def _observed_spec(inspect: Mapping[str, Any], protocol: Mapping[str, Any], image: Mapping[str, Any]) -> dict[str, Any]:
    config = inspect.get("Config") or {}
    host = inspect.get("HostConfig") or {}
    mounts = inspect.get("Mounts") or []
    environment = sorted(
        item for item in (config.get("Env") or []) if item.split("=", 1)[0] in {"HOME", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONHASHSEED", "PYTHONPATH"}
    )
    tmpfs_raw = (host.get("Tmpfs") or {}).get("/tmp")
    tmpfs_tokens = str(tmpfs_raw).split(",") if isinstance(tmpfs_raw, str) else []
    size_tokens = [token for token in tmpfs_tokens if token.startswith("size=")]
    try:
        observed_tmpfs_size = int(size_tokens[0].split("=", 1)[1]) if len(size_tokens) == 1 else None
    except ValueError:
        observed_tmpfs_size = None
    tmpfs_options = sorted(token for token in tmpfs_tokens if not token.startswith("size="))
    ulimits = {
        str(row.get("Name")): f"{row.get('Soft')}:{row.get('Hard')}"
        for row in (host.get("Ulimits") or [])
        if isinstance(row, Mapping)
    }
    observed_security = {
        "schema": SECURITY_SPEC_SCHEMA,
        "platform": protocol["platform"],
        "network_mode": host.get("NetworkMode"),
        "read_only_rootfs": host.get("ReadonlyRootfs"),
        "cap_drop": host.get("CapDrop") or [],
        "no_new_privileges": any(
            option in {"no-new-privileges", "no-new-privileges=true"}
            for option in (host.get("SecurityOpt") or [])
        ),
        "user": config.get("User"),
        "ipc_mode": host.get("IpcMode"),
        "pid_mode": "private" if not host.get("PidMode") else host.get("PidMode"),
        "pids_limit": host.get("PidsLimit"),
        "memory_limit_bytes": host.get("Memory"),
        "memory_swap_limit_bytes": host.get("MemorySwap"),
        "cpu_limit_millicores": int((host.get("NanoCpus") or 0) // 1_000_000),
        "tmpfs": {
            "target": "/tmp",
            "size_bytes": observed_tmpfs_size,
            "options": tmpfs_options,
        },
        "ulimits": ulimits,
        "environment": environment,
        "mount_targets": [mount["target"] for mount in protocol["input_mounts"]],
        "command": config.get("Cmd") or [],
    }
    return {
        "schema": "evaluation_v4_2_observed_container_spec_v1",
        "runtime_image_id_sha256": str(inspect.get("Image", ""))[7:],
        "image_architecture": image["architecture"],
        "image_os": image["os"],
        "security": observed_security,
        "mounts": sorted(
            [
                {
                    "source": mount.get("Source"),
                    "destination": mount.get("Destination"),
                    "type": mount.get("Type"),
                    "read_only": not bool(mount.get("RW")),
                    "propagation": mount.get("Propagation"),
                }
                for mount in mounts
            ],
            key=lambda row: str(row["destination"]),
        ),
        "labels": {
            key: value
            for key, value in (config.get("Labels") or {}).items()
            if str(key).startswith("evaluation_v4_2.")
        },
    }


def _docker_command(
    protocol: Mapping[str, Any], bundle_dir: Path, name: str, claim: Mapping[str, Any]
) -> list[str]:
    tmpfs = protocol["scratch_tmpfs"]
    cpu = protocol["cpu_limit_millicores"] / 1000.0
    return [
        "docker",
        "run",
        "--pull",
        "never",
        "--name",
        name,
        "--platform",
        protocol["platform"],
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
        "none",
        "--pids-limit",
        str(protocol["pids_limit"]),
        "--memory",
        str(protocol["memory_limit_bytes"]),
        "--memory-swap",
        str(protocol["memory_limit_bytes"]),
        "--cpus",
        f"{cpu:.3f}",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        f"nproc={protocol['pids_limit']}:{protocol['pids_limit']}",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={tmpfs['size_bytes']},mode=700,uid=65534,gid=65534",
        "--mount",
        f"type=bind,source={bundle_dir.resolve()},target=/input,readonly,bind-propagation=rprivate",
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
        f"evaluation_v4_2.attempt_id={claim['attempt_id']}",
        "--label",
        f"evaluation_v4_2.claim_sha256={claim['content_sha256']}",
        "--label",
        f"evaluation_v4_2.protocol_sha256={protocol['content_sha256']}",
        protocol["oci_image"],
        *protocol["command"],
    ]


def execute_claimed_arm(
    *,
    claim_path: Path,
    protocol_path: Path,
    bundle_dir: Path,
    attempts_root: Path,
    output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
) -> dict[str, Any]:
    """Execute exactly one previously unclaimed arm and seal its terminal receipt."""

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from evaluation_v4_2.arm_receipt import (
        ARM_RECEIPT_SCHEMA,
        CONTAINER_AUTHORITY,
        WORKER_RESULT_SCHEMA,
        build_arm_receipt,
        validate_attempt_claim,
    )
    from evaluation_v4_2.container_protocol import validate_container_protocol

    claim = validate_attempt_claim(_json(claim_path.resolve()))
    protocol = validate_container_protocol(_json(protocol_path.resolve()))
    manifest = validate_input_bundle(bundle_dir)
    task = manifest["task"]
    if claim["container_protocol_sha256"] != protocol["content_sha256"]:
        raise ContainerArmError("claim does not bind the supplied container protocol")
    if (
        claim["bundle_manifest_sha256"] != manifest["content_sha256"]
        or protocol["bundle_manifest_sha256"] != manifest["content_sha256"]
        or claim["task_spec_sha256"] != manifest["task_spec_sha256"]
        or protocol["task_spec_sha256"] != manifest["task_spec_sha256"]
    ):
        raise ContainerArmError("claim/protocol does not bind the bundle manifest and task")
    from evaluation_v4_2.execution_plan import arm_protocol_id

    expected_arm_id = arm_protocol_id(
        claim["policy_label"],
        claim["engine_id"],
        claim["opponent_id"],
        claim["seed"],
        claim["seat"],
    )
    if protocol["arm_id"] != expected_arm_id or protocol["arm_kind"] != task["policy_label"]:
        raise ContainerArmError("container protocol does not bind the input task")
    if protocol["input_mounts"] != [
        {
            "source_id": "arm-private-input-bundle",
            "source_sha256": manifest["bundle_tree_sha256"],
            "target": "/input",
            "read_only": True,
            "private": True,
        }
    ]:
        raise ContainerArmError("container protocol does not bind the input bundle")
    if protocol["runtime_sha256"] != manifest["runtime_bundle_sha256"]:
        raise ContainerArmError("container protocol runtime binding mismatch")
    if protocol["source_sha256"] != _sha256_file(Path(__file__).resolve()):
        raise ContainerArmError("container protocol host-launcher binding mismatch")
    if protocol["security_sha256"] != _canonical_sha256(docker_security_spec(protocol)):
        raise ContainerArmError("container protocol security hash mismatch")
    if protocol["action_deadline_seconds"] != task["max_action_seconds"]:
        raise ContainerArmError("container action deadline differs from task")
    if protocol["max_steps"] != task["max_steps"] or claim["max_steps"] != task["max_steps"]:
        raise ContainerArmError("claim/protocol max_steps differs from task")
    if output_limit_bytes != protocol["output_limit_bytes"]:
        raise ContainerArmError("caller output limit differs from frozen container protocol")
    if claim["policy_label"] != task["policy_label"] or claim["policy_archive_sha256"] != task["policy_archive_sha256"]:
        raise ContainerArmError("claim policy identity differs from bundle")
    for claim_field, task_field in (
        ("opponent_id", "opponent_id"),
        ("opponent_archive_sha256", "opponent_archive_sha256"),
        ("opponent_policy_content_sha256", "opponent_policy_content_sha256"),
        ("opponent_main_sha256", "opponent_main_sha256"),
        ("opponent_deck_sha256", "opponent_deck_sha256"),
        ("engine_id", "engine_id"),
        ("engine_binary_sha256", "engine_binary_sha256"),
        ("engine_runtime_tree_sha256", "engine_runtime_tree_sha256"),
        ("seed", "seed"),
        ("seat", "seat"),
    ):
        if claim[claim_field] != task[task_field]:
            raise ContainerArmError(f"claim {claim_field} differs from bundle")

    attempt_dir = attempts_root.resolve() / claim["attempt_id"]
    attempt_dir.mkdir(parents=True, exist_ok=False)
    _write_json_exclusive(attempt_dir / "claim.json", claim)
    input_snapshot = attempt_dir / "input_snapshot"
    _copy_tree_readable(bundle_dir.resolve(), input_snapshot)
    snapshot_manifest = validate_input_bundle(input_snapshot)
    if snapshot_manifest != manifest:
        raise ContainerArmError("private input snapshot differs from the pre-claim bundle")
    _freeze_tree_permissions(input_snapshot)
    stdout_path = attempt_dir / "stdout.bin"
    stderr_path = attempt_dir / "stderr.bin"

    image = _image_observation(protocol)
    daemon_sha256, daemon_evidence = _daemon_evidence()
    name = f"ev42-{claim['attempt_id'][:40]}"
    existing = subprocess.run(["docker", "container", "inspect", name], capture_output=True)
    if existing.returncode == 0:
        raise ContainerArmError(f"deterministic container name already exists: {name}")
    command = _docker_command(protocol, input_snapshot, name, claim)
    command_sha256 = _canonical_sha256(command)
    launcher_sha256 = _sha256_file(Path(__file__).resolve())

    started_wall = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    deadline_exceeded = False
    output_exceeded = False
    with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
        process = subprocess.Popen(command, stdout=stdout_handle, stderr=stderr_handle)
        while process.poll() is None:
            elapsed = time.monotonic() - started_monotonic
            size = stdout_path.stat().st_size + stderr_path.stat().st_size
            if size > output_limit_bytes:
                output_exceeded = True
                subprocess.run(["docker", "kill", "--signal", "KILL", name], capture_output=True)
                break
            if elapsed > protocol["arm_deadline_seconds"]:
                deadline_exceeded = True
                subprocess.run(["docker", "kill", "--signal", "KILL", name], capture_output=True)
                break
            time.sleep(0.02)
        try:
            process.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            deadline_exceeded = True
    finished_monotonic = time.monotonic()
    finished_wall = datetime.now(timezone.utc)
    if finished_monotonic - started_monotonic > protocol["arm_deadline_seconds"]:
        deadline_exceeded = True
    final_stdout_size = stdout_path.stat().st_size
    final_stderr_size = stderr_path.stat().st_size
    if final_stdout_size + final_stderr_size > output_limit_bytes:
        output_exceeded = True

    inspect_payload = _run_json(["docker", "container", "inspect", name])
    if not isinstance(inspect_payload, list) or len(inspect_payload) != 1 or not isinstance(inspect_payload[0], Mapping):
        raise ContainerArmError("docker container inspect returned an invalid payload")
    inspect = inspect_payload[0]
    observed = _observed_spec(inspect, protocol, image)
    expected = _expected_observed_spec(
        protocol,
        image,
        mount_source=input_snapshot,
        claim=claim,
    )
    if observed != expected:
        raise ContainerArmError(f"Docker observed spec differs from protocol: expected={expected} observed={observed}")
    if validate_input_bundle(input_snapshot) != manifest:
        raise ContainerArmError("private input snapshot changed during execution")

    stdout_sha256 = _sha256_file(stdout_path)
    stderr_sha256 = _sha256_file(stderr_path)
    stdout_bytes = stdout_path.read_bytes() if not output_exceeded else b""
    stderr_bytes = stderr_path.read_bytes() if not output_exceeded else b""
    state = inspect.get("State") or {}
    exit_code = state.get("ExitCode")
    oom_killed = bool(state.get("OOMKilled"))
    still_running = bool(state.get("Running"))
    worker_result: dict[str, Any] | None = None
    launcher_error: str | None = None
    terminal_status = "FAILURE"
    if still_running:
        launcher_error = "container_still_running_after_watchdog"
    elif oom_killed:
        terminal_status = "OOM_KILLED"
        launcher_error = "container_oom_killed"
    elif output_exceeded:
        terminal_status = "OUTPUT_LIMIT"
        launcher_error = "combined_output_limit_exceeded"
    elif deadline_exceeded:
        terminal_status = "TIMEOUT"
        launcher_error = "external_watchdog_timeout"
    elif exit_code == 0:
        try:
            parsed = json.loads(stdout_bytes)
            if not isinstance(parsed, Mapping) or parsed.get("schema") != WORKER_RESULT_SCHEMA:
                raise ValueError("worker schema mismatch")
            worker_result = dict(parsed)
            terminal_status = "SUCCESS"
        except (ValueError, json.JSONDecodeError) as exc:
            launcher_error = f"worker_output_invalid: {exc}"
    else:
        launcher_error = f"container_exit_{exit_code}"

    content = {
        "schema": ARM_RECEIPT_SCHEMA,
        "claim_content_sha256": claim["content_sha256"],
        "attempt_id": claim["attempt_id"],
        "container_protocol_sha256": protocol["content_sha256"],
        "image_manifest_sha256": protocol["image_digest_sha256"],
        "image_config_sha256": protocol["image_config_sha256"],
        "container_id": inspect.get("Id"),
        "observed_container_spec_sha256": _canonical_sha256(observed),
        "docker_daemon_fingerprint_sha256": daemon_sha256,
        "docker_inspect_sha256": _canonical_sha256(inspect_payload),
        "input_bundle_sha256": manifest["bundle_tree_sha256"],
        "runtime_bundle_sha256": manifest["runtime_bundle_sha256"],
        "launcher_source_sha256": launcher_sha256,
        "command_sha256": command_sha256,
        "started_at_utc": started_wall.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "finished_at_utc": finished_wall.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "duration_seconds": finished_monotonic - started_monotonic,
        "external_deadline_seconds": protocol["arm_deadline_seconds"],
        "output_limit_bytes": output_limit_bytes,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "stdout_size_bytes": final_stdout_size,
        "stderr_size_bytes": final_stderr_size,
        "exit_code": exit_code,
        "oom_killed": oom_killed,
        "deadline_exceeded": deadline_exceeded,
        "output_limit_exceeded": output_exceeded,
        "terminal_status": terminal_status,
        "worker_result": worker_result,
        "launcher_error": launcher_error,
        "authority": CONTAINER_AUTHORITY,
        "remote_attestation_verified": False,
        "docker_daemon_reports_amd64": daemon_evidence["info"]["architecture"] in {
            "amd64",
            "x86_64",
        },
        "native_platform_verified": False,
        "latency_parity_allowed": False,
        "randomization_allowed": False,
        "submit_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }
    receipt = build_arm_receipt(content, claim)
    _write_json_exclusive(attempt_dir / "receipt.json", receipt)
    subprocess.run(["docker", "container", "rm", name], capture_output=True)
    return receipt


def _deadline_entry(entry: Any, *, seconds: float) -> Any:
    from evaluation_v2.seeded_arena import ArenaEntry

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


def run_worker(task_path: Path) -> dict[str, Any]:
    """Run inside the locked container and return one strict terminal result."""

    task = _validate_task(_json(task_path))
    manifest = validate_input_bundle(Path("/input"))
    if manifest["task"] != task:
        raise ContainerArmError("worker task differs from frozen bundle manifest")
    from evaluation_v2.seeded_arena import load_entry_isolated, load_seeded_game, run_seeded_game

    policy_label = task["policy_label"]
    policy = _deadline_entry(
        load_entry_isolated(policy_label, Path("/input/policy")),
        seconds=task["max_action_seconds"],
    )
    opponent = _deadline_entry(
        load_entry_isolated(task["opponent_id"], Path("/input/opponent")),
        seconds=task["max_action_seconds"],
    )
    game = load_seeded_game(Path("/input/engine"))
    policy_left = task["seat"] == "policy_first"
    result = run_seeded_game(
        game,
        policy if policy_left else opponent,
        opponent if policy_left else policy,
        seed=task["seed"],
        max_steps=task["max_steps"],
    )
    if result.get("error") is not None or result.get("winner") not in (0, 1, 2):
        raise ContainerArmError(f"engine arm failed: {result.get('error')}")
    winner = int(result["winner"])
    if winner == 2:
        outcome = 0.5
    else:
        outcome = 1.0 if ((winner == 0) is policy_left) else 0.0
    timings = result.get("max_action_seconds_by_label") or {}
    return {
        "schema": "evaluation_v4_2_container_worker_result_v1",
        "policy_label": policy_label,
        "opponent_id": task["opponent_id"],
        "seed": task["seed"],
        "seat": task["seat"],
        "policy_left": policy_left,
        "outcome": outcome,
        "winner": winner,
        "steps": int(result["steps"]),
        "max_policy_action_seconds": float(timings.get(policy_label, 0.0)),
        "max_opponent_action_seconds": float(timings.get(task["opponent_id"], 0.0)),
        "transcript_sha256": result["transcript_sha256"],
        "error": None,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command_name", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--policy-archive", type=Path, required=True)
    prepare.add_argument("--opponent-archive", type=Path, required=True)
    prepare.add_argument("--engine-dir", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--policy-label", choices=("candidate", "baseline"), required=True)
    prepare.add_argument("--opponent-id", required=True)
    prepare.add_argument("--engine-id", required=True)
    prepare.add_argument("--seed", type=int, required=True)
    prepare.add_argument("--seat", choices=("policy_first", "policy_second"), required=True)
    prepare.add_argument("--max-steps", type=int, default=600)
    prepare.add_argument("--max-action-seconds", type=float, default=DEFAULT_ACTION_DEADLINE_SECONDS)

    freeze = subparsers.add_parser("freeze-protocol")
    freeze.add_argument("--bundle-dir", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--arm-id")
    freeze.add_argument("--image", default=DEFAULT_IMAGE)
    freeze.add_argument("--arm-deadline-seconds", type=float, default=DEFAULT_ARM_DEADLINE_SECONDS)

    execute = subparsers.add_parser("execute")
    execute.add_argument("--claim", type=Path, required=True)
    execute.add_argument("--protocol", type=Path, required=True)
    execute.add_argument("--bundle-dir", type=Path, required=True)
    execute.add_argument("--attempts-root", type=Path, required=True)
    execute.add_argument("--output-limit-bytes", type=int, default=DEFAULT_OUTPUT_LIMIT_BYTES)

    worker = subparsers.add_parser("worker")
    worker.add_argument("--task", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command_name == "prepare":
            payload = prepare_input_bundle(
                policy_archive=args.policy_archive,
                opponent_archive=args.opponent_archive,
                engine_dir=args.engine_dir,
                output_dir=args.output_dir,
                policy_label=args.policy_label,
                opponent_id=args.opponent_id,
                engine_id=args.engine_id,
                seed=args.seed,
                seat=args.seat,
                max_steps=args.max_steps,
                max_action_seconds=float(args.max_action_seconds),
            )
        elif args.command_name == "freeze-protocol":
            payload = build_protocol_for_bundle(
                args.bundle_dir,
                arm_id=args.arm_id,
                image=args.image,
                arm_deadline_seconds=float(args.arm_deadline_seconds),
            )
            _write_json_exclusive(args.output.resolve(), payload)
        elif args.command_name == "execute":
            payload = execute_claimed_arm(
                claim_path=args.claim,
                protocol_path=args.protocol,
                bundle_dir=args.bundle_dir,
                attempts_root=args.attempts_root,
                output_limit_bytes=args.output_limit_bytes,
            )
        elif args.command_name == "worker":
            original_stdout = sys.stdout
            with redirect_stdout(sys.stderr):
                payload = run_worker(args.task)
            original_stdout.write(_canonical_bytes(payload).decode("ascii") + "\n")
            original_stdout.flush()
            return 0
        else:  # pragma: no cover
            raise AssertionError("unreachable command")
        print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:
        if args.command_name == "execute":
            _record_claimed_failure(
                claim_path=args.claim,
                attempts_root=args.attempts_root,
                error=exc,
            )
            _cleanup_claim_container(args.claim)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
