from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import pytest

from evaluation_v4_2.campaign_protocol import build_runner_binding
from evaluation_v4_2.campaign_runtime import (
    CampaignRuntimeError,
    build_current_runner_binding,
    code_paths,
    measure_code_manifest,
    sha256_file,
    validate_campaign_runtime_verification,
    verify_campaign_runtime,
)
from evaluation_v4_2.sandbox_binding import canonical_sha256


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fake_repository(root: Path) -> None:
    root.mkdir(parents=True)
    for name, path in code_paths(root).items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(f"# {name}\n", encoding="ascii")


def _binding(root: Path, docker: Path) -> tuple[dict[str, object], object]:
    code_manifest = measure_code_manifest(root)
    image_digest = _sha("image")
    config = _sha("config")
    layers = [_sha("layer-1"), _sha("layer-2")]
    version = {"Client": {"Version": "test"}, "Server": {"Version": "test"}}
    facts = {
        "python_executable_sha256": sha256_file(Path(sys.executable).resolve()),
        "python_executable_path_sha256": _sha(str(Path(sys.executable).resolve())),
        "python_version_sha256": _sha(sys.version),
        "python_platform_sha256": canonical_sha256(
            {
                "implementation": platform.python_implementation(),
                "machine": platform.machine(),
                "platform": platform.platform(),
                "system": platform.system(),
            }
        ),
        "docker_cli_sha256": sha256_file(docker),
        "docker_cli_path_sha256": _sha(str(docker.resolve())),
        "docker_version_sha256": canonical_sha256(version),
    }
    binding = build_runner_binding(
        {
            "parent_runner_sha256": code_manifest["parent_executor"],
            "arm_runner_sha256": code_manifest["arm_runner"],
            "journal_sha256": code_manifest["campaign_journal"],
            "sandbox_protocol_sha256": code_manifest["sandbox_protocol"],
            "composer_sha256": code_manifest["campaign_composer"],
            "code_manifest": code_manifest,
            **facts,
            "oci_image": f"registry.example/evaluator@sha256:{image_digest}",
            "image_digest_sha256": image_digest,
            "image_manifest_raw_sha256": image_digest,
            "image_config_sha256": config,
            "image_layer_sha256s": layers,
            "arm_deadline_seconds": 900.0,
            "action_deadline_seconds": 1.0,
            "docker_call_timeout_seconds": 15.0,
            "scheduler_width": 16,
        }
    )
    return binding, version


def _runner(binding: dict[str, object], version: object):
    def run(command, **_kwargs):
        if command[1] == "version":
            payload = version
        else:
            payload = [
                {
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoDigests": [binding["oci_image"]],
                    "Id": f"sha256:{binding['image_config_sha256']}",
                    "RootFS": {
                        "Layers": [
                            f"sha256:{item}" for item in binding["image_layer_sha256s"]
                        ]
                    },
                }
            ]
        return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode(), b"")

    return run


def _raw_runner(oci_image: str, config: str, layers: list[str], version: object):
    def run(command, **_kwargs):
        payload = (
            version
            if command[1] == "version"
            else [
                {
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoDigests": [oci_image],
                    "Id": f"sha256:{config}",
                    "RootFS": {"Layers": [f"sha256:{item}" for item in layers]},
                }
            ]
        )
        return subprocess.CompletedProcess(command, 0, json.dumps(payload).encode(), b"")

    return run


def test_freeze_builds_a_binding_from_the_same_live_measurement_contract(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _fake_repository(root)
    docker = tmp_path / "docker"
    docker.write_bytes(b"fake-docker-cli")
    image_digest = _sha("image")
    oci_image = f"registry.example/evaluator@sha256:{image_digest}"
    config = _sha("config")
    layers = [_sha("layer-1"), _sha("layer-2")]
    version = {"Client": {"Version": "test"}, "Server": {"Version": "test"}}

    binding = build_current_runner_binding(
        repository_root=root,
        oci_image=oci_image,
        scheduler_width=4,
        arm_deadline_seconds=900.0,
        action_deadline_seconds=1.0,
        docker_call_timeout_seconds=15.0,
        which=lambda _name: str(docker),
        runner=_raw_runner(oci_image, config, layers, version),
    )
    receipt = verify_campaign_runtime(
        binding,
        repository_root=root,
        phase="campaign_start",
        campaign_id="c" * 64,
        plan_sha256="a" * 64,
        which=lambda _name: str(docker),
        runner=_raw_runner(oci_image, config, layers, version),
    )
    assert binding["scheduler_width"] == 4
    assert receipt["runner_binding_content_sha256"] == binding["content_sha256"]


def test_runtime_receipt_remeasures_exact_source_python_docker_and_image(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _fake_repository(root)
    docker = tmp_path / "docker"
    docker.write_bytes(b"fake-docker-cli")
    binding, version = _binding(root, docker)

    receipt = verify_campaign_runtime(
        binding,
        repository_root=root,
        phase="wave_start",
        campaign_id="c" * 64,
        plan_sha256="a" * 64,
        wave=3,
        which=lambda _name: str(docker),
        runner=_runner(binding, version),
    )

    assert receipt["runtime_static_verified"] is True
    assert receipt["image_present_and_exact"] is True
    assert receipt["submit_authorized"] is False
    assert validate_campaign_runtime_verification(
        receipt,
        runner_binding=binding,
        phase="wave_start",
        campaign_id="c" * 64,
        plan_sha256="a" * 64,
        wave=3,
    ) == receipt


def test_runtime_source_or_docker_drift_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _fake_repository(root)
    docker = tmp_path / "docker"
    docker.write_bytes(b"fake-docker-cli")
    binding, version = _binding(root, docker)

    code_paths(root)["campaign_preparation"].write_text("# changed\n", encoding="ascii")
    with pytest.raises(CampaignRuntimeError, match="source differs"):
        verify_campaign_runtime(
            binding,
            repository_root=root,
            phase="campaign_start",
            campaign_id="c" * 64,
            plan_sha256="a" * 64,
            which=lambda _name: str(docker),
            runner=_runner(binding, version),
        )

    code_paths(root)["campaign_preparation"].write_text(
        "# campaign_preparation\n", encoding="ascii"
    )
    bad_version = {"Client": {"Version": "other"}, "Server": {"Version": "test"}}
    with pytest.raises(CampaignRuntimeError, match="docker_version_sha256"):
        verify_campaign_runtime(
            binding,
            repository_root=root,
            phase="campaign_start",
            campaign_id="c" * 64,
            plan_sha256="a" * 64,
            which=lambda _name: str(docker),
            runner=_runner(binding, bad_version),
        )


def test_runtime_phase_and_receipt_identity_are_exact(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _fake_repository(root)
    docker = tmp_path / "docker"
    docker.write_bytes(b"fake-docker-cli")
    binding, version = _binding(root, docker)
    with pytest.raises(CampaignRuntimeError, match="campaign_start"):
        verify_campaign_runtime(
            binding,
            repository_root=root,
            phase="campaign_start",
            campaign_id="c" * 64,
            plan_sha256="a" * 64,
            wave=0,
            which=lambda _name: str(docker),
            runner=_runner(binding, version),
        )

    receipt = verify_campaign_runtime(
        binding,
        repository_root=root,
        phase="pre_arm_start",
        campaign_id="c" * 64,
        plan_sha256="a" * 64,
        wave=0,
        allocation_id="allocation-0",
        which=lambda _name: str(docker),
        runner=_runner(binding, version),
    )
    altered = deepcopy(receipt)
    altered["allocation_id"] = "allocation-1"
    content = {key: value for key, value in altered.items() if key != "content_sha256"}
    altered["content_sha256"] = canonical_sha256(content)
    with pytest.raises(CampaignRuntimeError, match="allocation_id differs"):
        validate_campaign_runtime_verification(
            altered,
            runner_binding=binding,
            phase="pre_arm_start",
            campaign_id="c" * 64,
            plan_sha256="a" * 64,
            wave=0,
            allocation_id="allocation-0",
        )
