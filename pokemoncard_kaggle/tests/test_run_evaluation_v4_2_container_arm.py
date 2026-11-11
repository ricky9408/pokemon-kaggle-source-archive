from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile

import pytest

import tools.run_evaluation_v4_2_container_arm as container_arm
from evaluation_v4_2.execution_plan import arm_protocol_id
from tools.run_evaluation_v4_2_container_arm import (
    CONTAINER_USER,
    ContainerArmError,
    _record_claimed_failure,
    _write_json_exclusive,
    build_protocol_for_bundle,
    docker_security_spec,
    prepare_input_bundle,
    validate_input_bundle,
)


def _archive(path: Path, marker: str) -> Path:
    main = f"def agent(observation):\n    return []\n# {marker}\n".encode("ascii")
    deck = ("1\n" * 60).encode("ascii")
    with tarfile.open(path, "w:gz") as archive:
        for name, data in (("main.py", main), ("deck.csv", deck)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return path


def _engine(path: Path) -> Path:
    cg = path / "cg"
    cg.mkdir(parents=True)
    (cg / "libcg.so").write_bytes(b"test-engine-binary")
    (cg / "game.py").write_text("# test engine\n", encoding="ascii")
    return path


def _bundle(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    output = tmp_path / "bundle"
    manifest = prepare_input_bundle(
        policy_archive=_archive(tmp_path / "candidate.tar.gz", "candidate"),
        opponent_archive=_archive(tmp_path / "opponent.tar.gz", "opponent"),
        engine_dir=_engine(tmp_path / "engine"),
        output_dir=output,
        policy_label="candidate",
        opponent_id="opponent-control",
        engine_id="engine-a",
        seed=123,
        seat="policy_second",
        max_steps=600,
        max_action_seconds=1.0,
    )
    return output, manifest


def test_prepared_bundle_is_content_addressed_and_read_only(tmp_path: Path) -> None:
    bundle, manifest = _bundle(tmp_path)

    assert validate_input_bundle(bundle) == manifest
    assert (bundle.stat().st_mode & 0o222) == 0
    assert (bundle / "task.json").stat().st_mode & 0o222 == 0
    assert manifest["authority"] == "DEVELOPMENT_ONLY"
    assert manifest["anchor_allowed"] is False


def test_bundle_mutation_is_detected(tmp_path: Path) -> None:
    bundle, _ = _bundle(tmp_path)
    task = bundle / "task.json"
    task.chmod(0o644)
    task.write_text("{}\n", encoding="ascii")

    with pytest.raises(ContainerArmError, match="bundle tree changed"):
        validate_input_bundle(bundle)


def test_protocol_derives_full_arm_id_and_frozen_security(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, manifest = _bundle(tmp_path)
    task = manifest["task"]
    image_digest = container_arm.DEFAULT_IMAGE.rsplit("@sha256:", 1)[1]
    monkeypatch.setattr(
        container_arm,
        "_image_manifest_observation",
        lambda image: {
            "media_type": "application/vnd.oci.image.manifest.v1+json",
            "raw_sha256": image_digest,
            "config_sha256": "c" * 64,
            "layer_sha256s": ["d" * 64],
        },
    )
    protocol = build_protocol_for_bundle(bundle, arm_deadline_seconds=30.0)

    assert protocol["arm_id"] == arm_protocol_id(
        "candidate", "engine-a", "opponent-control", 123, "policy_second"
    )
    assert protocol["platform"] == "linux/amd64"
    assert protocol["network_mode"] == "none"
    assert protocol["pids_limit"] == 64
    assert protocol["input_mounts"][0]["source_sha256"] == manifest["bundle_tree_sha256"]
    security = docker_security_spec(protocol)
    assert security["user"] == CONTAINER_USER
    assert security["read_only_rootfs"] is True
    assert security["ulimits"]["nproc"] == "64:64"
    assert task["max_action_seconds"] == protocol["action_deadline_seconds"]


def test_one_shot_artifact_writer_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "claim.json"
    _write_json_exclusive(path, {"claim": 1})
    with pytest.raises(ContainerArmError, match="already exists"):
        _write_json_exclusive(path, {"claim": 2})
    assert json.loads(path.read_text()) == {"claim": 1}


def test_claimed_exception_writes_a_terminal_veto_marker(tmp_path: Path) -> None:
    attempt_id = "a" * 64
    claim_sha256 = "b" * 64
    claim_path = tmp_path / "source-claim.json"
    claim_path.write_text(
        json.dumps({"attempt_id": attempt_id, "content_sha256": claim_sha256}),
        encoding="ascii",
    )
    attempt_dir = tmp_path / "attempts" / attempt_id
    attempt_dir.mkdir(parents=True)
    _write_json_exclusive(
        attempt_dir / "claim.json",
        {"attempt_id": attempt_id, "content_sha256": claim_sha256},
    )

    _record_claimed_failure(
        claim_path=claim_path,
        attempts_root=tmp_path / "attempts",
        error=RuntimeError("preflight failed"),
    )

    failure = json.loads((attempt_dir / "failure.json").read_text())
    assert failure["disposition"] == "ARM_BURNED_PANEL_VETO"
    assert failure["error_type"] == "RuntimeError"
    assert failure["submit_authorized"] is False
