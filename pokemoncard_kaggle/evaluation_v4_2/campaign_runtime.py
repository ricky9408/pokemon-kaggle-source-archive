"""Exact host/runtime verification for the exclusive v4.2 campaign runner.

The frozen runner binding is only useful when the process that launches a wave
re-measures the same executable, source, Docker client/daemon, and pinned image.
This module performs that measurement and emits a self-hashed, authority-closed
receipt suitable for the campaign and child witness CAS stores.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any

from .campaign_protocol import (
    CODE_MANIFEST_KEYS,
    build_runner_binding,
    validate_runner_binding,
)
from .sandbox_binding import FALSE_AUTHORITY_FLAGS, canonical_sha256


RUNTIME_VERIFICATION_SCHEMA = "evaluation_v4_2_campaign_runtime_verification_v1"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
PHASES = frozenset({"campaign_start", "wave_start", "pre_arm_start"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "phase",
        "campaign_id",
        "wave",
        "allocation_id",
        "plan_sha256",
        "runner_binding_content_sha256",
        "code_manifest",
        "python_executable_sha256",
        "python_executable_path_sha256",
        "python_version_sha256",
        "python_platform_sha256",
        "docker_cli_sha256",
        "docker_cli_path_sha256",
        "docker_version_sha256",
        "oci_image",
        "image_digest_sha256",
        "image_config_sha256",
        "image_layer_sha256s",
        "runtime_static_verified",
        "image_present_and_exact",
        "authority",
        *FALSE_AUTHORITY_FLAGS,
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}


class CampaignRuntimeError(ValueError):
    """The executing host differs from the frozen campaign runner binding."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise CampaignRuntimeError(f"runtime source is not a regular non-symlink file: {path}")
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def code_paths(repository_root: Path) -> dict[str, Path]:
    root = repository_root.resolve(strict=True)
    paths = {
        "parent_executor": root / "tools" / "run_evaluation_v4_2_campaign.py",
        "arm_runner": root / "tools" / "run_evaluation_v4_2_sandbox_arm.py",
        "analysis_contract": root / "evaluation_v4_2" / "analysis_contract.py",
        "campaign_protocol": root / "evaluation_v4_2" / "campaign_protocol.py",
        "campaign_journal": root / "evaluation_v4_2" / "campaign_journal.py",
        "campaign_preparation": root / "evaluation_v4_2" / "campaign_preparation.py",
        "campaign_runtime": root / "evaluation_v4_2" / "campaign_runtime.py",
        "campaign_composer": root / "evaluation_v4_2" / "campaign_composer.py",
        "parent_arm_claim": root / "evaluation_v4_2" / "parent_arm_claim.py",
        "witness_journal": root / "evaluation_v4_2" / "witness_journal.py",
        "sandbox_protocol": root / "evaluation_v4_2" / "sandbox_protocol.py",
        "sandbox_binding": root / "evaluation_v4_2" / "sandbox_binding.py",
        # The arm runner copies its own exact bytes into each frozen snapshot.
        "sandbox_worker_source": root / "tools" / "run_evaluation_v4_2_sandbox_arm.py",
    }
    if set(paths) != CODE_MANIFEST_KEYS:
        raise CampaignRuntimeError("runtime code path set differs from CODE_MANIFEST_KEYS")
    return paths


def measure_code_manifest(repository_root: Path) -> dict[str, str]:
    return {name: sha256_file(path) for name, path in sorted(code_paths(repository_root).items())}


def _run_json(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> object:
    try:
        result = runner(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CampaignRuntimeError(f"runtime command failed to execute: {command[0]}: {exc}") from exc
    if result.returncode != 0:
        stderr = bytes(result.stderr or b"")[:4096].decode("utf-8", errors="replace")
        raise CampaignRuntimeError(
            f"runtime command failed with exit {result.returncode}: {' '.join(command)}: {stderr}"
        )
    try:
        return json.loads(bytes(result.stdout).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CampaignRuntimeError(f"runtime command did not return JSON: {' '.join(command)}") from exc


def _docker_facts(
    binding: Mapping[str, Any],
    *,
    timeout_seconds: float,
    which: Callable[[str], str | None],
    runner: Callable[..., subprocess.CompletedProcess[bytes]],
) -> dict[str, Any]:
    cli_name = binding["container_runtime_contract"]["docker_cli"]
    selected = which(cli_name)
    if not selected:
        raise CampaignRuntimeError(f"required Docker CLI is absent: {cli_name}")
    docker = Path(selected).resolve(strict=True)
    if not docker.is_file():
        raise CampaignRuntimeError("resolved Docker CLI is not a regular file")
    version = _run_json(
        [str(docker), "version", "--format", "{{json .}}"],
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    inspected = _run_json(
        [str(docker), "image", "inspect", binding["oci_image"]],
        timeout_seconds=timeout_seconds,
        runner=runner,
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], Mapping):
        raise CampaignRuntimeError("Docker image inspect did not return one exact image")
    image = inspected[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise CampaignRuntimeError("local OCI image is not the required linux/amd64 platform")
    repo_digests = image.get("RepoDigests")
    pinned_suffix = f"@sha256:{binding['image_digest_sha256']}"
    if not isinstance(repo_digests, list) or not any(
        isinstance(item, str) and item.endswith(pinned_suffix) for item in repo_digests
    ):
        raise CampaignRuntimeError("pinned OCI image digest is not present locally")
    config_id = image.get("Id")
    expected_config = f"sha256:{binding['image_config_sha256']}"
    if config_id != expected_config:
        raise CampaignRuntimeError("local OCI image config digest differs from the runner binding")
    rootfs = image.get("RootFS")
    layers = rootfs.get("Layers") if isinstance(rootfs, Mapping) else None
    expected_layers = [f"sha256:{item}" for item in binding["image_layer_sha256s"]]
    if layers != expected_layers:
        raise CampaignRuntimeError("local OCI image layer list differs from the runner binding")
    return {
        "docker_cli_sha256": sha256_file(docker),
        "docker_cli_path_sha256": _sha256_text(str(docker)),
        "docker_version_sha256": canonical_sha256(version),
        "image_config_sha256": binding["image_config_sha256"],
        "image_layer_sha256s": list(binding["image_layer_sha256s"]),
    }


def build_current_runner_binding(
    *,
    repository_root: Path,
    oci_image: str,
    arm_deadline_seconds: float,
    action_deadline_seconds: float,
    docker_call_timeout_seconds: float,
    scheduler_width: int,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    """Freeze the current exact host and pinned local image into a runner binding."""

    match = re.fullmatch(r"[^\s@]+@sha256:([0-9a-f]{64})", oci_image)
    if match is None:
        raise CampaignRuntimeError("oci_image must be digest-pinned")
    docker_name = "docker"
    selected = which(docker_name)
    if not selected:
        raise CampaignRuntimeError("required Docker CLI is absent")
    docker = Path(selected).resolve(strict=True)
    version = _run_json(
        [str(docker), "version", "--format", "{{json .}}"],
        timeout_seconds=docker_call_timeout_seconds,
        runner=runner,
    )
    inspected = _run_json(
        [str(docker), "image", "inspect", oci_image],
        timeout_seconds=docker_call_timeout_seconds,
        runner=runner,
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], Mapping):
        raise CampaignRuntimeError("Docker image inspect did not return one exact image")
    image = inspected[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise CampaignRuntimeError("local OCI image is not the required linux/amd64 platform")
    pinned = match.group(1)
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or not any(
        isinstance(item, str) and item.endswith(f"@sha256:{pinned}")
        for item in repo_digests
    ):
        raise CampaignRuntimeError("pinned OCI image digest is not present locally")
    config_id = image.get("Id")
    if not isinstance(config_id, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", config_id) is None:
        raise CampaignRuntimeError("Docker image config digest is invalid")
    rootfs = image.get("RootFS")
    raw_layers = rootfs.get("Layers") if isinstance(rootfs, Mapping) else None
    if not isinstance(raw_layers, list) or not raw_layers:
        raise CampaignRuntimeError("Docker image layer list is absent")
    layers: list[str] = []
    for item in raw_layers:
        if not isinstance(item, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None:
            raise CampaignRuntimeError("Docker image layer digest is invalid")
        layers.append(item.removeprefix("sha256:"))
    executable = Path(sys.executable).resolve(strict=True)
    code_manifest = measure_code_manifest(repository_root)
    return build_runner_binding(
        {
            "parent_runner_sha256": code_manifest["parent_executor"],
            "arm_runner_sha256": code_manifest["arm_runner"],
            "journal_sha256": code_manifest["campaign_journal"],
            "sandbox_protocol_sha256": code_manifest["sandbox_protocol"],
            "composer_sha256": code_manifest["campaign_composer"],
            "code_manifest": code_manifest,
            "python_executable_sha256": sha256_file(executable),
            "python_executable_path_sha256": _sha256_text(str(executable)),
            "python_version_sha256": _sha256_text(sys.version),
            "python_platform_sha256": canonical_sha256(
                {
                    "implementation": platform.python_implementation(),
                    "machine": platform.machine(),
                    "platform": platform.platform(),
                    "system": platform.system(),
                }
            ),
            "docker_cli_sha256": sha256_file(docker),
            "docker_cli_path_sha256": _sha256_text(str(docker)),
            "docker_version_sha256": canonical_sha256(version),
            "oci_image": oci_image,
            "image_digest_sha256": pinned,
            "image_manifest_raw_sha256": pinned,
            "image_config_sha256": config_id.removeprefix("sha256:"),
            "image_layer_sha256s": layers,
            "arm_deadline_seconds": arm_deadline_seconds,
            "action_deadline_seconds": action_deadline_seconds,
            "docker_call_timeout_seconds": docker_call_timeout_seconds,
            "scheduler_width": scheduler_width,
        }
    )


def verify_campaign_runtime(
    runner_binding: object,
    *,
    repository_root: Path,
    phase: str,
    campaign_id: str,
    plan_sha256: str,
    wave: int | None = None,
    allocation_id: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> dict[str, Any]:
    """Measure and compare the exact runtime immediately before a launch boundary."""

    try:
        binding = validate_runner_binding(runner_binding)
    except Exception as exc:
        raise CampaignRuntimeError(f"runner binding is invalid: {exc}") from exc
    if phase not in PHASES:
        raise CampaignRuntimeError(f"phase must be one of {sorted(PHASES)}")
    if not isinstance(campaign_id, str) or _SHA256_RE.fullmatch(campaign_id) is None:
        raise CampaignRuntimeError("campaign_id must be a lowercase SHA-256 digest")
    if not isinstance(plan_sha256, str) or _SHA256_RE.fullmatch(plan_sha256) is None:
        raise CampaignRuntimeError("plan_sha256 must be a lowercase SHA-256 digest")
    if phase == "campaign_start":
        if wave is not None or allocation_id is not None:
            raise CampaignRuntimeError("campaign_start must not name a wave or allocation")
    elif phase == "wave_start":
        if isinstance(wave, bool) or not isinstance(wave, int) or wave < 0 or allocation_id is not None:
            raise CampaignRuntimeError("wave_start requires one non-negative wave and no allocation")
    else:
        if (
            isinstance(wave, bool)
            or not isinstance(wave, int)
            or wave < 0
            or not isinstance(allocation_id, str)
            or not allocation_id
        ):
            raise CampaignRuntimeError("pre_arm_start requires a wave and allocation_id")

    measured_code = measure_code_manifest(repository_root)
    if measured_code != binding["code_manifest"]:
        differing = sorted(
            name for name in CODE_MANIFEST_KEYS if measured_code.get(name) != binding["code_manifest"].get(name)
        )
        raise CampaignRuntimeError(f"executing source differs from code_manifest: {differing}")
    executable = Path(sys.executable).resolve(strict=True)
    python_facts = {
        "python_executable_sha256": sha256_file(executable),
        "python_executable_path_sha256": _sha256_text(str(executable)),
        "python_version_sha256": _sha256_text(sys.version),
        "python_platform_sha256": canonical_sha256(
            {
                "implementation": platform.python_implementation(),
                "machine": platform.machine(),
                "platform": platform.platform(),
                "system": platform.system(),
            }
        ),
    }
    timeout = float(binding["deadline_caps"]["docker_call_timeout_seconds"])
    docker_facts = _docker_facts(binding, timeout_seconds=timeout, which=which, runner=runner)
    measured = {**python_facts, **docker_facts}
    expected = {key: binding[key] for key in measured}
    if measured != expected:
        differing = sorted(key for key in measured if measured[key] != expected[key])
        raise CampaignRuntimeError(f"executing runtime differs from runner binding: {differing}")
    content = {
        "schema": RUNTIME_VERIFICATION_SCHEMA,
        "phase": phase,
        "campaign_id": campaign_id,
        "wave": wave,
        "allocation_id": allocation_id,
        "plan_sha256": plan_sha256,
        "runner_binding_content_sha256": binding["content_sha256"],
        "code_manifest": measured_code,
        **measured,
        "oci_image": binding["oci_image"],
        "image_digest_sha256": binding["image_digest_sha256"],
        "runtime_static_verified": True,
        "image_present_and_exact": True,
        "authority": DEVELOPMENT_AUTHORITY,
        **dict(FALSE_AUTHORITY_FLAGS),
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_campaign_runtime_verification(
    value: object,
    *,
    runner_binding: object,
    phase: str,
    campaign_id: str,
    plan_sha256: str,
    wave: int | None = None,
    allocation_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise CampaignRuntimeError("runtime verification fields are not exact")
    content = {field: value[field] for field in _CONTENT_FIELDS}
    if value.get("schema") != RUNTIME_VERIFICATION_SCHEMA:
        raise CampaignRuntimeError("runtime verification schema mismatch")
    if value.get("content_sha256") != canonical_sha256(content):
        raise CampaignRuntimeError("runtime verification content hash mismatch")
    binding = validate_runner_binding(runner_binding)
    expected_identity = {
        "phase": phase,
        "campaign_id": campaign_id,
        "wave": wave,
        "allocation_id": allocation_id,
        "plan_sha256": plan_sha256,
        "runner_binding_content_sha256": binding["content_sha256"],
        "code_manifest": binding["code_manifest"],
        "python_executable_sha256": binding["python_executable_sha256"],
        "python_executable_path_sha256": binding["python_executable_path_sha256"],
        "python_version_sha256": binding["python_version_sha256"],
        "python_platform_sha256": binding["python_platform_sha256"],
        "docker_cli_sha256": binding["docker_cli_sha256"],
        "docker_cli_path_sha256": binding["docker_cli_path_sha256"],
        "docker_version_sha256": binding["docker_version_sha256"],
        "oci_image": binding["oci_image"],
        "image_digest_sha256": binding["image_digest_sha256"],
        "image_config_sha256": binding["image_config_sha256"],
        "image_layer_sha256s": binding["image_layer_sha256s"],
    }
    for field, expected in expected_identity.items():
        if value.get(field) != expected:
            raise CampaignRuntimeError(f"runtime verification {field} differs from binding")
    if value.get("runtime_static_verified") is not True or value.get("image_present_and_exact") is not True:
        raise CampaignRuntimeError("runtime verification success flags must be true")
    if value.get("authority") != DEVELOPMENT_AUTHORITY:
        raise CampaignRuntimeError("runtime verification authority must remain DEVELOPMENT_ONLY")
    for field, expected in FALSE_AUTHORITY_FLAGS.items():
        if value.get(field) is not expected:
            raise CampaignRuntimeError(f"runtime verification {field} must remain false")
    return dict(value)


__all__ = [
    "build_current_runner_binding",
    "CampaignRuntimeError",
    "RUNTIME_VERIFICATION_SCHEMA",
    "code_paths",
    "measure_code_manifest",
    "sha256_file",
    "validate_campaign_runtime_verification",
    "verify_campaign_runtime",
]
