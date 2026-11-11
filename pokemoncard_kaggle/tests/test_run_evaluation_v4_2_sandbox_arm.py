import base64
import inspect
import io
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

import evaluation_v4_2.campaign_journal as campaign_module
from evaluation_v4_2.campaign_journal import (
    BURN,
    POPEN_OBSERVED,
    START_DURABLE_POPEN_UNCERTAIN,
    CampaignJournal,
)
from evaluation_v4_2.campaign_preparation import (
    build_campaign_prepared_manifest,
    build_prepared_allocation,
)
from evaluation_v4_2.sandbox_protocol import (
    ACTION_REQUEST_SCHEMA,
    PROTOCOL_SCHEMA,
    Frame,
    TranscriptAccumulator,
    canonical_json_bytes,
    canonical_sha256,
    read_next_frame,
    write_frame,
)
from evaluation_v4_2.witness_journal import WitnessJournal
import tools.run_evaluation_v4_2_sandbox_arm as runner


DIGEST = "a" * 64
IMAGE = "registry.example/python@sha256:" + "b" * 64


def pytest_configure(config):
    config.addinivalue_line("markers", "docker_smoke: opt-in three-container Docker smoke test")


def _task() -> dict[str, object]:
    return {
        "schema": "evaluation_v4_2_container_arm_task_v1",
        "policy_label": "candidate",
        "policy_archive_sha256": "1" * 64,
        "policy_policy_content_sha256": "2" * 64,
        "policy_main_sha256": "3" * 64,
        "policy_deck_sha256": "4" * 64,
        "opponent_id": "opponent-1",
        "opponent_archive_sha256": "5" * 64,
        "opponent_policy_content_sha256": "6" * 64,
        "opponent_main_sha256": "7" * 64,
        "opponent_deck_sha256": "8" * 64,
        "engine_id": "engine-1",
        "engine_binary_sha256": "9" * 64,
        "engine_runtime_tree_sha256": "a" * 64,
        "seed": 4,
        "seat": "policy_first",
        "max_steps": 20,
        "max_action_seconds": 0.25,
    }


def _snapshot_fixture(monkeypatch, tmp_path):
    """Build a compact bundle and isolate the runner's live runtime sources."""

    bundle = tmp_path / "bundle"
    files = {
        "policy/deck.csv": b"candidate-deck\n",
        "policy/policy.py": b"candidate-policy-v1\n",
        "opponent/deck.csv": b"opponent-deck\n",
        "opponent/policy.py": b"opponent-policy-v1\n",
        "engine/engine.py": b"engine-v1\n",
        "runtime/support.py": b"runtime-support\n",
        "runtime/sandbox_arm.py": b"stale-bundle-arm\n",
        "runtime/evaluation_v4_2/sandbox_protocol.py": b"stale-bundle-protocol\n",
        "runtime/evaluation_v4_2/sandbox_binding.py": b"stale-bundle-binding\n",
        "runtime/evaluation_v4_2/witness_journal.py": b"stale-bundle-journal\n",
        "runtime/__pycache__/hidden.py": b"ignored-cache\n",
        "runtime/ignored.pyc": b"ignored-bytecode\n",
    }
    for relative, payload in files.items():
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    live_root = tmp_path / "live-root"
    live_files = {
        "evaluation_v4_2/sandbox_protocol.py": b"live-protocol-v1\n",
        "evaluation_v4_2/sandbox_binding.py": b"live-binding-v1\n",
        "evaluation_v4_2/witness_journal.py": b"live-journal-v1\n",
        "sandbox-arm-source.py": b"live-sandbox-arm-v1\n",
    }
    for relative, payload in live_files.items():
        path = live_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    monkeypatch.setattr(runner, "ROOT", live_root)
    monkeypatch.setattr(runner, "__file__", str(live_root / "sandbox-arm-source.py"))
    return bundle, live_root, {
        "content_sha256": "c" * 64,
        "task": {"schema": "snapshot-test-task-v1", "seed": 7, "nested": {"b": 2, "a": 1}},
    }


def test_predict_snapshot_manifest_matches_materialization_and_runtime_overwrites(monkeypatch, tmp_path):
    bundle, live_root, manifest = _snapshot_fixture(monkeypatch, tmp_path)

    predicted = runner.predict_snapshot_manifest(bundle, manifest)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    snapshot, materialized = runner._snapshot_bundle(bundle, artifact_root, manifest)

    assert materialized == predicted
    assert runner._tree_records(snapshot) == predicted["files"]
    records = {record["path"]: record["sha256"] for record in predicted["files"]}
    assert "runtime/__pycache__/hidden.py" not in records
    assert "runtime/ignored.pyc" not in records
    assert snapshot.joinpath("decks", "candidate", "deck.csv").read_bytes() == b"candidate-deck\n"
    assert snapshot.joinpath("task.json").read_bytes() == canonical_json_bytes(manifest["task"]) + b"\n"
    assert snapshot.joinpath("runtime", "evaluation_v4_2", "sandbox_protocol.py").read_bytes() == (
        live_root / "evaluation_v4_2" / "sandbox_protocol.py"
    ).read_bytes()
    assert snapshot.joinpath("runtime", "sandbox_arm.py").read_bytes() == (
        live_root / "sandbox-arm-source.py"
    ).read_bytes()


def test_predict_snapshot_manifest_changes_for_bundle_and_live_runtime_mutations(monkeypatch, tmp_path):
    bundle, live_root, manifest = _snapshot_fixture(monkeypatch, tmp_path)

    original = runner.predict_snapshot_manifest(bundle, manifest)
    (bundle / "policy" / "policy.py").write_bytes(b"candidate-policy-v2\n")
    bundle_mutated = runner.predict_snapshot_manifest(bundle, manifest)
    (live_root / "evaluation_v4_2" / "sandbox_binding.py").write_bytes(b"live-binding-v2\n")
    runtime_mutated = runner.predict_snapshot_manifest(bundle, manifest)

    assert bundle_mutated != original
    assert runtime_mutated != bundle_mutated
    assert original["tree_sha256"] != bundle_mutated["tree_sha256"]
    assert bundle_mutated["tree_sha256"] != runtime_mutated["tree_sha256"]


def test_snapshot_predictor_rejects_symlinks_nonfiles_and_runtime_path_collisions(monkeypatch, tmp_path):
    bundle, _, manifest = _snapshot_fixture(monkeypatch, tmp_path)
    (bundle / "policy" / "linked.py").symlink_to(bundle / "policy" / "policy.py")
    with pytest.raises(runner.SandboxArmError, match="symlink"):
        runner.predict_snapshot_manifest(bundle, manifest)

    (bundle / "policy" / "linked.py").unlink()
    os.mkfifo(bundle / "engine" / "stream")
    with pytest.raises(runner.SandboxArmError, match="non-file"):
        runner.predict_snapshot_manifest(bundle, manifest)

    (bundle / "engine" / "stream").unlink()
    protocol_parent = bundle / "runtime" / "evaluation_v4_2"
    for child in protocol_parent.iterdir():
        child.unlink()
    protocol_parent.rmdir()
    protocol_parent.write_bytes(b"not-a-directory\n")
    with pytest.raises(runner.SandboxArmError, match="snapshot output collision"):
        runner.predict_snapshot_manifest(bundle, manifest)
    artifact_root = tmp_path / "collision-artifacts"
    artifact_root.mkdir()
    with pytest.raises(runner.SandboxArmError, match="snapshot output collision"):
        runner._snapshot_bundle(bundle, artifact_root, manifest)
    assert not (artifact_root / "snapshot").exists()


def _parent_campaign_fixture(monkeypatch, tmp_path):
    task = _task()
    bundle_manifest_sha256 = "c" * 64
    allocation = {
        "allocation_id": "allocation-0",
        "ordinal": 0,
        "wave": 0,
        "slot": 0,
        "logical_attempt_id": "logical-attempt-0",
        "logical_claim_content_sha256": "d" * 64,
        "sandbox_arm_claim_sha256": canonical_sha256(
            runner.build_arm_claim(task, bundle_manifest_sha256)
        ),
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "bundle_tree_sha256": "e" * 64,
        "bundle_task_spec_sha256": "f" * 64,
        "runtime_bundle_sha256": "1" * 64,
        "worker_source_sha256": "2" * 64,
        "normalized_policy_identity_sha256": runner.policy_identity_sha256(task),
        "task": task,
    }
    runner_binding = {
        "scheduler_width": 1,
        "oci_image": IMAGE,
        "deadline_caps": {
            "arm_deadline_seconds": 10.0,
            "docker_call_timeout_seconds": 1.0,
        },
        "resource_caps": {
            "cpu_limit_millicores": 1000,
            "memory_limit_bytes": 512 * 1024 * 1024,
            "pids_limit": 64,
            "tmpfs_size_bytes": 64 * 1024 * 1024,
        },
    }
    plan = {
        "content_sha256": "3" * 64,
        "candidate_normalized_identity_sha256": runner.policy_identity_sha256(task),
        "runner_binding_content_sha256": "4" * 64,
        "allocations": [allocation],
        "runner_binding": runner_binding,
    }
    monkeypatch.setattr(campaign_module, "validate_campaign_plan", lambda value: value)
    monkeypatch.setattr(
        campaign_module._campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda value, **kwargs: value,
    )
    journal = CampaignJournal(
        tmp_path / "campaign-journal",
        b"parent-runner-test-key",
        key_id="parent-runner-test",
        domain="tests.parent-runner",
    )
    campaign_id = journal.claim_campaign(plan, "5" * 64)["payload"]["campaign_id"]
    state = journal.state(campaign_id)
    snapshot_manifest = {
        "schema": "evaluation_v4_2_development_private_snapshot_v1",
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "files": [],
        "tree_sha256": "6" * 64,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    snapshot_manifest_sha256 = journal.evidence.put(snapshot_manifest)
    names = runner.deterministic_parent_container_names(campaign_id, allocation["allocation_id"])
    command_templates = runner.build_parent_docker_command_templates(
        tmp_path / "parent-artifacts" / "snapshot",
        task,
        image=IMAGE,
        names=names,
        cpu_millicores=1000,
        memory_bytes=512 * 1024 * 1024,
        pids_limit=64,
        tmpfs_bytes=64 * 1024 * 1024,
    )
    template = build_prepared_allocation(
        plan,
        state,
        allocation,
        snapshot_manifest_sha256=snapshot_manifest_sha256,
        snapshot_tree_sha256=snapshot_manifest["tree_sha256"],
        normalized_command_templates=command_templates,
    )
    prepared_manifest = build_campaign_prepared_manifest(plan, state, [template])
    journal.prepare_campaign(campaign_id, prepared_manifest)
    journal.start_campaign(campaign_id, {"phase": "campaign-start"})
    journal.start_wave(
        campaign_id,
        0,
        runtime_verification={"phase": "wave-start", "wave": 0},
    )
    manifest = {"content_sha256": bundle_manifest_sha256, "task": task}
    return {
        "journal": journal,
        "campaign_id": campaign_id,
        "allocation": allocation,
        "plan": plan,
        "template": template,
        "manifest": manifest,
        "snapshot_manifest": snapshot_manifest,
    }


def _fake_parent_execution_edges(monkeypatch, fixture, tmp_path, *, pre_popen_fault=False):
    journal = fixture["journal"]
    campaign_id = fixture["campaign_id"]
    allocation = fixture["allocation"]
    template = fixture["template"]
    snapshot_manifest = fixture["snapshot_manifest"]
    child_attempt_id = template["child_attempt_id"]
    runtime_calls = []
    launch_calls = []
    artifact_calls = []

    def verify_runtime(binding, **kwargs):
        runtime_calls.append((binding, kwargs))
        assert journal.state(campaign_id)["bound_arms"][allocation["allocation_id"]]
        assert journal._arm_journal.state(child_attempt_id)["state"] == "CLAIMED"
        return {
            "schema": "test-pre-arm-runtime-receipt-v1",
            "phase": kwargs["phase"],
            "campaign_id": kwargs["campaign_id"],
            "wave": kwargs["wave"],
            "allocation_id": kwargs["allocation_id"],
            "plan_sha256": kwargs["plan_sha256"],
        }

    def launch(commands, names):
        launch_calls.append((commands, names))
        assert journal._arm_journal.state(child_attempt_id)["state"] == "STARTED"
        return [
            runner._Child(role, names[role], commands[role], SimpleNamespace())
            for role in ("referee", "candidate_policy", "opponent_policy")
        ]

    def write_artifacts(*args, **kwargs):
        artifact_calls.append(kwargs)
        return {
            "schema": "test-parent-terminal",
            "scope": "parent_bound_campaign_arm",
            "status": kwargs["terminal_status"],
            "launch_state": kwargs["launch_state"],
            "parent_binding": kwargs["parent_binding"],
        }

    monkeypatch.setattr(runner, "_load_bundle_validator", lambda: lambda path: fixture["manifest"])
    monkeypatch.setattr(
        runner,
        "_snapshot_bundle",
        lambda bundle, root, manifest: (root / "snapshot", snapshot_manifest),
    )
    monkeypatch.setattr(runner.campaign_runtime, "verify_campaign_runtime", verify_runtime)
    if pre_popen_fault:
        monkeypatch.setattr(
            runner,
            "_verify_image",
            lambda image, timeout: (_ for _ in ()).throw(runner.SandboxArmFault("image missing")),
        )
    else:
        monkeypatch.setattr(runner, "_verify_image", lambda image, timeout: {})
    monkeypatch.setattr(runner, "_existing_name_check", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_launch_children", launch)
    monkeypatch.setattr(
        runner,
        "_Broker",
        lambda *args, **kwargs: type(
            "Broker", (), {"run": lambda self: {"status": "SUCCESS", "outcome": 1.0}}
        )(),
    )
    monkeypatch.setattr(runner, "_inspect_containers", lambda *args, **kwargs: {})
    monkeypatch.setattr(runner, "_remove_exited", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_kill_and_remove", lambda children, names, docker_timeout: None)
    monkeypatch.setattr(runner, "_verify_snapshot", lambda snapshot, manifest: None)
    monkeypatch.setattr(runner, "_write_artifacts", write_artifacts)
    monkeypatch.setattr(runner, "_install_witness_cas", lambda journal, root, terminal: terminal)
    result = runner.execute_parent_bound_arm(
        tmp_path / "bundle",
        output_dir=tmp_path / "parent-artifacts",
        campaign_journal=journal,
        campaign_id=campaign_id,
        allocation_id=allocation["allocation_id"],
    )
    return result, runtime_calls, launch_calls, artifact_calls


def _observation() -> dict[str, object]:
    return {
        "current": {"yourIndex": 0},
        "select": {
            "option": [{"index": 0}],
            "minCount": 0,
            "maxCount": 1,
        },
    }


def _request(session: str, claim: str) -> dict[str, object]:
    observation = _observation()
    return {
        "schema": ACTION_REQUEST_SCHEMA,
        "session_id": session,
        "arm_claim_sha256": claim,
        "game_id": "game-1",
        "turn_id": 1,
        "actor_role": "candidate_policy",
        "observation_sha256": canonical_sha256(observation),
        "request_id": "action-1",
        "observation": observation,
        "legal_options_sha256": canonical_sha256(observation["select"]),
        "legal_option_count": 1,
        "legal_min_count": 0,
        "legal_max_count": 1,
    }


def _hello(role: str, session: str, claim: str) -> Frame:
    return Frame(
        role,
        "HELLO",
        1,
        {
            "schema": PROTOCOL_SCHEMA + "_hello_v1",
            "session_id": session,
            "arm_claim_sha256": claim,
            "role": role,
            "sandbox_id": role,
            "protocol": PROTOCOL_SCHEMA,
        },
    )


def _ready(role: str, session: str, claim: str) -> Frame:
    return Frame(
        role,
        "READY",
        1,
        {
            "schema": PROTOCOL_SCHEMA + "_ready_v1",
            "session_id": session,
            "arm_claim_sha256": claim,
            "role": role,
            "sandbox_id": role,
            "protocol": PROTOCOL_SCHEMA,
            "hello_sequence": 1,
        },
    )


def _terminal(
    session: str,
    claim: str,
    *,
    sequence: int = 3,
    request_id: str = "action-1",
    turn_id: int = 1,
    winner_role: str | None = "candidate_policy",
) -> Frame:
    return Frame(
        "referee",
        "TERMINAL",
        sequence,
        {
            "schema": PROTOCOL_SCHEMA + "_terminal_v1",
            "session_id": session,
            "arm_claim_sha256": claim,
            "game_id": "game-1",
            "turn_id": turn_id,
            "actor_role": "referee",
            "observation_sha256": canonical_sha256(_observation()),
            "request_id": request_id,
            "outcome": "game_complete",
            "winner_role": winner_role,
        },
    )


def _sealed_arm_journal(
    tmp_path,
    *,
    status="SUCCESS",
    invalid_isolation=False,
    invalid_transcript=False,
    missing_reference=False,
    raw_mismatch=False,
    omit_snapshot_file=False,
    tamper_snapshot_file=False,
    command_mutator=None,
    sealed_command_mutator=None,
    inspect_mutator=None,
    started_prepared_digest=None,
    draw=False,
):
    journal = WitnessJournal(tmp_path / "journal", b"sealed-arm-test-key")
    attempt_id = "attempt"
    task = _task()
    bundle_manifest_sha256 = "c" * 64
    campaign_sha256 = runner.arm_campaign_sha256(task, bundle_manifest_sha256)
    claim_document = runner.build_arm_claim(task, bundle_manifest_sha256)
    claim_sha256 = canonical_sha256(claim_document)
    one_shot_key = journal.one_shot_key(
        campaign_sha256,
        runner.policy_identity_sha256(task),
    )
    journal.claim(
        attempt_id,
        claim=claim_document,
        one_shot_key_sha256=one_shot_key,
        metadata={
            "scope": "single_arm",
            "campaign_sha256": campaign_sha256,
            "panel_parent_claim_verified": False,
        },
    )
    session_id = f"sbx-{campaign_sha256[:32]}"
    snapshot = tmp_path / "snapshot"
    snapshot_payloads = {
        "task.json": canonical_json_bytes(task) + b"\n",
        "policy/deck.csv": b"candidate-deck\n",
        "opponent/deck.csv": b"opponent-deck\n",
        "engine/engine.py": b"engine\n",
        "runtime/sandbox_arm.py": b"runtime\n",
        "decks/candidate/deck.csv": b"candidate-deck\n",
        "decks/opponent/deck.csv": b"opponent-deck\n",
    }
    for relative, payload in snapshot_payloads.items():
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    snapshot_records = [
        {"path": relative, "sha256": runner._sha256_bytes(payload)}
        for relative, payload in sorted(snapshot_payloads.items())
    ]
    snapshot_manifest = {
        "schema": "evaluation_v4_2_development_private_snapshot_v1",
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "files": snapshot_records,
        "tree_sha256": canonical_sha256(snapshot_records),
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    names = runner.deterministic_container_names(attempt_id)
    commands = {
        role: runner.build_docker_command(
            role,
            snapshot,
            image=IMAGE,
            name=names[role],
            session_id=session_id,
            arm_claim_sha256=claim_sha256,
            task=task,
        )
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    if command_mutator is not None:
        command_mutator(commands)
    identities = [
        {
            "role": role,
            "container_name": names[role],
            "command_sha256": canonical_sha256(commands[role]),
        }
        for role in ("referee", "candidate_policy", "opponent_policy")
    ]
    prepared_evidence = {
        "schema": runner.ARM_RESULT_SCHEMA + "_prepared_v1",
        "scope": "single_arm",
        "campaign_sha256": campaign_sha256,
        "arm_claim_sha256": claim_sha256,
        "snapshot_manifest": snapshot_manifest,
        "container_names": names,
        "reserved_child_arm_identities": identities,
        "container_commands": {
            role: [token.replace(str(snapshot), "$SNAPSHOT") for token in command]
            for role, command in commands.items()
        },
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": runner.PARENT_GATE_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    journal.prepare(attempt_id, evidence=prepared_evidence)
    prepared_digest = journal.state(attempt_id)["prepared_evidence_sha256"]
    journal.start(
        attempt_id,
        evidence={
            "schema": runner.ARM_RESULT_SCHEMA + "_started_v1",
            "scope": "single_arm",
            "campaign_sha256": campaign_sha256,
            "arm_claim_sha256": claim_sha256,
            "prepared_evidence_sha256": started_prepared_digest or prepared_digest,
            "reserved_child_arm_identities": identities,
            "panel_parent_claim_verified": False,
            "parent_campaign_gate_required": True,
            "parent_campaign_gate_statement": runner.PARENT_GATE_STATEMENT,
            "authority": "DEVELOPMENT_ONLY",
            **runner.FALSE_AUTHORITY_FLAGS,
        },
    )
    if sealed_command_mutator is not None:
        sealed_command_mutator(commands)

    terminal_frame = _terminal(
        session_id,
        claim_sha256,
        sequence=2,
        request_id="start-0",
        turn_id=0,
        winner_role=None if draw else "candidate_policy",
    )
    raw_terminal = terminal_frame.to_bytes()
    accumulator = TranscriptAccumulator()
    chained = accumulator.add("referee_to_policy", raw_terminal)
    record = {
        "direction": "referee_to_policy",
        "role": terminal_frame.role,
        "message_type": terminal_frame.message_type,
        "sequence": terminal_frame.sequence,
        "frame_sha256": runner._sha256_bytes(raw_terminal),
        "transcript_sha256": "f" * 64 if invalid_transcript else chained,
        "frame_base64": base64.b64encode(raw_terminal).decode("ascii"),
    }
    success = status == "SUCCESS"
    transcript_sha256 = chained if success else None
    transcript = {
        "schema": "evaluation_v4_2_deterministic_sandbox_transcript_v1",
        "frames": [record] if success else [],
        "transcript_sha256": transcript_sha256,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }

    def inspect_record(role):
        if not success:
            return {"role": role, "inspect_error": "policy fault before strict inspect"}
        command = commands[role]
        image_index = command.index("python") - 1
        cpu, memory, pids, tmpfs_size = runner._command_resources(command)
        mounts = [
            {
                "source": mount["source"],
                "destination": mount["destination"],
                "type": "bind",
                "read_only": True,
                "propagation": "rprivate",
            }
            for mount in runner._command_mounts(command)
        ]
        if invalid_isolation and role == "candidate_policy":
            mounts.append(
                {
                    "source": "/var/run/docker.sock",
                    "destination": "/var/run/docker.sock",
                    "type": "bind",
                    "read_only": True,
                    "propagation": "rprivate",
                }
            )
        return {
            "role": role,
            "config": {
                "User": runner.CONTAINER_USER,
                "Image": command[image_index],
                "Cmd": command[image_index + 1 :],
                "OpenStdin": True,
                "Tty": False,
                "Labels": {
                    "evaluation_v4_2.role": role,
                    "evaluation_v4_2.session_id": session_id,
                    "evaluation_v4_2.claim_sha256": claim_sha256,
                },
            },
            "host_config": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges=true"],
                "PidMode": "",
                "IpcMode": "private",
                "PidsLimit": pids,
                "Memory": memory,
                "MemorySwap": memory,
                "NanoCpus": cpu * 1_000_000,
                "Tmpfs": {
                    "/tmp": f"rw,noexec,nosuid,nodev,size={tmpfs_size},mode=700,uid=65534,gid=65534"
                },
            },
            "mounts": mounts,
        }

    files = {
        "transcript.json": canonical_json_bytes(transcript) + b"\n",
    }
    for relative, payload in snapshot_payloads.items():
        files[f"snapshot/{relative}"] = payload
    if tamper_snapshot_file:
        files["snapshot/policy/deck.csv"] = b"tampered-candidate-deck\n"
    for role in ("referee", "candidate_policy", "opponent_policy"):
        command = {"role": role, "command": commands[role]}
        inspect = inspect_record(role)
        if inspect_mutator is not None:
            inspect_mutator(role, inspect)
        files[f"containers/{role}.command.json"] = canonical_json_bytes(command) + b"\n"
        files[f"containers/{role}.inspect.json"] = canonical_json_bytes(inspect) + b"\n"
        if success:
            hello = _hello(role, session_id, claim_sha256).to_bytes()
            ready = _ready(role, session_id, claim_sha256).to_bytes()
            files[f"raw/{role}/stdout.bin"] = hello
            files[f"raw/{role}/stdin.bin"] = ready + (
                raw_terminal if role in {"candidate_policy", "opponent_policy"} else b""
            )
            if role == "referee":
                files[f"raw/{role}/stdout.bin"] += b"" if raw_mismatch else raw_terminal
        else:
            files[f"raw/{role}/stdin.bin"] = b""
            files[f"raw/{role}/stdout.bin"] = b""
        files[f"raw/{role}/stderr.bin"] = b""

    if omit_snapshot_file:
        files.pop("snapshot/policy/deck.csv")
    references = {}
    for relative, payload in files.items():
        digest = journal.evidence.put(payload)
        references[relative] = {"sha256": digest, "size_bytes": len(payload)}
    witness_references = dict(references)
    if missing_reference:
        witness_references.pop("raw/opponent_policy/stderr.bin")
    evidence = {
        "schema": runner.ARM_RESULT_SCHEMA + "_evidence_v1",
        "scope": "single_arm",
        "arm_claim_sha256": claim_sha256,
        "campaign_sha256": campaign_sha256,
        "snapshot_tree_sha256": snapshot_manifest["tree_sha256"],
        "artifact_manifest_sha256": canonical_sha256({
            "schema": runner.ARTIFACT_MANIFEST_SCHEMA,
            "scope": "single_arm",
            "files": references,
            "tree_sha256": canonical_sha256(references),
            "authority": "DEVELOPMENT_ONLY",
            **runner.FALSE_AUTHORITY_FLAGS,
        }),
        "artifact_files": references,
        "witness_cas_complete": True,
        "witness_cas_file_count": len(witness_references),
        "witness_cas_files": witness_references,
        "status": status,
        "fault": None if success else "policy fault",
        "host_outcome": (0.5 if draw else 1.0) if success else None,
        "winner_role": None if draw else ("candidate_policy" if success else None),
        "winner_index": None if draw or not success else 0,
        "transcript_sha256": transcript_sha256,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": runner.PARENT_GATE_STATEMENT,
        "authority_statement": runner.AUTHORITY_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    journal.terminal(attempt_id, status, evidence=evidence)
    return journal, attempt_id, references


def _sealed_parent_arm_journal(tmp_path):
    task = _task()
    bundle_manifest_sha256 = "c" * 64
    campaign_id = "7" * 64
    allocation_id = "allocation-0"
    snapshot = tmp_path / "snapshot"
    snapshot_payloads = {
        "task.json": canonical_json_bytes(task) + b"\n",
        "policy/deck.csv": b"candidate-deck\n",
        "opponent/deck.csv": b"opponent-deck\n",
        "engine/engine.py": b"engine\n",
        "runtime/sandbox_arm.py": b"runtime\n",
        "decks/candidate/deck.csv": b"candidate-deck\n",
        "decks/opponent/deck.csv": b"opponent-deck\n",
    }
    records = [
        {"path": relative, "sha256": runner._sha256_bytes(payload)}
        for relative, payload in sorted(snapshot_payloads.items())
    ]
    snapshot_manifest = {
        "schema": "evaluation_v4_2_development_private_snapshot_v1",
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "files": records,
        "tree_sha256": canonical_sha256(records),
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    plan = {"content_sha256": "8" * 64, "runner_binding_content_sha256": "9" * 64}
    state = {
        "campaign_id": campaign_id,
        "authority_id": "a" * 64,
        "root_id": "b" * 64,
        "claim_event_sha256": "d" * 64,
        "arm_witness_authority_id": "e" * 64,
        "arm_witness_root_id": "f" * 64,
        "prepared_manifest_sha256": "1" * 64,
        "prepare_event_sha256": "2" * 64,
        "start_evidence_sha256": "3" * 64,
        "start_event_sha256": "4" * 64,
        "wave_start_event_sha256s": {"0": "5" * 64},
        "wave_runtime_verification_sha256s": {"0": "6" * 64},
    }
    allocation = {
        "allocation_id": allocation_id,
        "ordinal": 0,
        "wave": 0,
        "slot": 0,
        "logical_attempt_id": "logical-attempt-0",
        "logical_claim_content_sha256": "a" * 64,
        "sandbox_arm_claim_sha256": canonical_sha256(
            runner.build_arm_claim(task, bundle_manifest_sha256)
        ),
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "bundle_tree_sha256": "b" * 64,
        "bundle_task_spec_sha256": "d" * 64,
        "runtime_bundle_sha256": "e" * 64,
        "worker_source_sha256": "f" * 64,
        "normalized_policy_identity_sha256": runner.policy_identity_sha256(task),
    }
    placeholder_commands = {
        role: [
            "docker", "$SNAPSHOT", "$CHILD_CLAIM_SHA256",
            "$ARM_BOUND_EVENT_SHA256", "$CHILD_START_EVENT_SHA256", "$SESSION_ID",
        ]
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    template = build_prepared_allocation(
        plan,
        state,
        allocation,
        snapshot_manifest_sha256=canonical_sha256(snapshot_manifest),
        snapshot_tree_sha256=snapshot_manifest["tree_sha256"],
        normalized_command_templates=placeholder_commands,
    )
    names = template["container_names"]
    functional_templates = runner.build_parent_docker_command_templates(
        snapshot,
        task,
        image=IMAGE,
        names=names,
        cpu_millicores=runner.DEFAULT_CPU_MILLICORES,
        memory_bytes=runner.DEFAULT_MEMORY_BYTES,
        pids_limit=runner.DEFAULT_PIDS_LIMIT,
        tmpfs_bytes=runner.DEFAULT_TMPFS_BYTES,
    )
    template_content = {
        **{key: value for key, value in template.items() if key != "content_sha256"},
        "normalized_command_templates": functional_templates,
        "command_template_sha256s": {
            role: canonical_sha256(command)
            for role, command in functional_templates.items()
        },
    }
    template = {**template_content, "content_sha256": canonical_sha256(template_content)}
    claim = runner.build_parent_bound_child_claim(template, state)
    claim_sha256 = runner.parent_bound_child_claim_sha256(claim)
    attempt_id = claim["child_attempt_id"]
    journal = WitnessJournal(tmp_path / "parent-journal", b"sealed-parent-key")
    assert journal.evidence.put(claim) == claim_sha256
    one_shot = journal.one_shot_key(
        runner.parent_child_campaign_sha256(campaign_id, allocation_id),
        allocation["normalized_policy_identity_sha256"],
    )
    claim_event = journal.claim(
        attempt_id,
        claim=claim,
        one_shot_key_sha256=one_shot,
        metadata={
            "scope": "parent_bound_campaign_arm",
            "campaign_id": campaign_id,
            "allocation_id": allocation_id,
            "child_claim_template_sha256": template["content_sha256"],
            "child_claim_evidence_sha256": claim_sha256,
        },
    )
    runtime_receipt = {"schema": "test-runtime-receipt", "phase": "pre_arm_start"}
    runtime_digest = journal.evidence.put(runtime_receipt)
    arm_bound_event_sha256 = "0" * 64
    base_binding = {
        "campaign_id": campaign_id,
        "allocation_id": allocation_id,
        "parent_bound_child_claim_sha256": claim_sha256,
        "child_claim_event_sha256": claim_event["event_sha256"],
        "arm_bound_event_sha256": arm_bound_event_sha256,
        "parent_prepare_event_sha256": claim["parent_prepare_event_sha256"],
        "parent_start_evidence_sha256": claim["parent_start_evidence_sha256"],
        "parent_start_event_sha256": claim["parent_start_event_sha256"],
        "parent_wave_start_event_sha256": claim["parent_wave_start_event_sha256"],
        "wave_runtime_verification_sha256": claim["wave_runtime_verification_sha256"],
        "prepared_allocation_content_sha256": claim["prepared_allocation_content_sha256"],
        "prepared_manifest_sha256": claim["prepared_manifest_sha256"],
        "pre_arm_runtime_verification_sha256": runtime_digest,
    }
    runner_binding = {"schema": "test-runner-binding"}
    prepared = {
        "schema": runner.PARENT_BOUND_ARM_RESULT_SCHEMA + "_prepared_v1",
        "scope": "parent_bound_campaign_arm",
        "parent_binding": base_binding,
        "snapshot_manifest": snapshot_manifest,
        "child_claim_template": template,
        "runner_binding": runner_binding,
        "pre_arm_runtime_verification_sha256": runtime_digest,
        "container_names": names,
        "normalized_command_templates": template["normalized_command_templates"],
        "command_template_sha256s": template["command_template_sha256s"],
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    journal.prepare(attempt_id, evidence=prepared)
    prepared_digest = journal.state(attempt_id)["prepared_evidence_sha256"]
    started = {
        "schema": runner.PARENT_BOUND_ARM_RESULT_SCHEMA + "_started_v1",
        "scope": "parent_bound_campaign_arm",
        "parent_binding": base_binding,
        "prepared_evidence_sha256": prepared_digest,
        "pre_arm_runtime_verification_sha256": runtime_digest,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    journal.start(attempt_id, evidence=started)
    start_event_sha256 = runner._child_event_sha256(journal, attempt_id, "START")
    session_id = runner._parent_session_id(
        claim_sha256, arm_bound_event_sha256, start_event_sha256
    )
    commands = runner._materialize_parent_commands(
        template,
        snapshot=snapshot,
        child_claim_sha256=claim_sha256,
        arm_bound_event_sha256=arm_bound_event_sha256,
        child_start_event_sha256=start_event_sha256,
        session_id=session_id,
    )
    terminal_binding = {
        **base_binding,
        "child_start_event_sha256": start_event_sha256,
        "session_id": session_id,
    }
    terminal_frame = _terminal(
        session_id,
        claim_sha256,
        sequence=2,
        request_id="start-0",
        turn_id=0,
    )
    raw_terminal = terminal_frame.to_bytes()
    accumulator = TranscriptAccumulator()
    transcript_sha256 = accumulator.add("referee_to_policy", raw_terminal)
    transcript = {
        "schema": "evaluation_v4_2_deterministic_sandbox_transcript_v1",
        "frames": [{
            "direction": "referee_to_policy",
            "role": "referee",
            "message_type": "TERMINAL",
            "sequence": 2,
            "frame_sha256": runner._sha256_bytes(raw_terminal),
            "transcript_sha256": transcript_sha256,
            "frame_base64": base64.b64encode(raw_terminal).decode("ascii"),
        }],
        "transcript_sha256": transcript_sha256,
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }

    def inspect_record(role):
        command = commands[role]
        image_index = command.index("python") - 1
        cpu, memory, pids, tmpfs_size = runner._command_resources(command)
        return {
            "role": role,
            "config": {
                "User": runner.CONTAINER_USER,
                "Image": command[image_index],
                "Cmd": command[image_index + 1 :],
                "OpenStdin": True,
                "Tty": False,
                "Labels": {
                    "evaluation_v4_2.role": role,
                    "evaluation_v4_2.session_id": session_id,
                    "evaluation_v4_2.claim_sha256": claim_sha256,
                    "evaluation_v4_2.arm_bound_event_sha256": arm_bound_event_sha256,
                    "evaluation_v4_2.child_start_event_sha256": start_event_sha256,
                },
            },
            "host_config": {
                "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
                "PidMode": "", "IpcMode": "private", "PidsLimit": pids,
                "Memory": memory, "MemorySwap": memory, "NanoCpus": cpu * 1_000_000,
                "Tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={tmpfs_size}"},
            },
            "mounts": [
                {
                    "source": item["source"], "destination": item["destination"],
                    "type": "bind", "read_only": True, "propagation": "rprivate",
                }
                for item in runner._command_mounts(command)
            ],
        }

    files = {"transcript.json": canonical_json_bytes(transcript) + b"\n"}
    for relative, payload in snapshot_payloads.items():
        files[f"snapshot/{relative}"] = payload
    for role in ("referee", "candidate_policy", "opponent_policy"):
        files[f"containers/{role}.command.json"] = canonical_json_bytes(
            {"role": role, "command": commands[role]}
        ) + b"\n"
        files[f"containers/{role}.inspect.json"] = canonical_json_bytes(
            inspect_record(role)
        ) + b"\n"
        hello = _hello(role, session_id, claim_sha256).to_bytes()
        ready = _ready(role, session_id, claim_sha256).to_bytes()
        files[f"raw/{role}/stdout.bin"] = hello + (raw_terminal if role == "referee" else b"")
        files[f"raw/{role}/stdin.bin"] = ready + (
            raw_terminal if role in {"candidate_policy", "opponent_policy"} else b""
        )
        files[f"raw/{role}/stderr.bin"] = b""
    references = {
        relative: {"sha256": journal.evidence.put(payload), "size_bytes": len(payload)}
        for relative, payload in files.items()
    }
    artifact_manifest = {
        "schema": runner.ARTIFACT_MANIFEST_SCHEMA,
        "scope": "parent_bound_campaign_arm",
        "files": references,
        "tree_sha256": canonical_sha256(references),
        "authority": "DEVELOPMENT_ONLY",
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    evidence = {
        "schema": runner.PARENT_BOUND_ARM_RESULT_SCHEMA + "_evidence_v1",
        "scope": "parent_bound_campaign_arm",
        "arm_claim_sha256": claim_sha256,
        "campaign_sha256": runner.parent_child_campaign_sha256(campaign_id, allocation_id),
        "snapshot_tree_sha256": snapshot_manifest["tree_sha256"],
        "artifact_manifest_sha256": canonical_sha256(artifact_manifest),
        "artifact_files": references,
        "status": "SUCCESS",
        "fault": None,
        "host_outcome": 1.0,
        "winner_role": "candidate_policy",
        "winner_index": 0,
        "transcript_sha256": transcript_sha256,
        "panel_parent_claim_verified": False,
        "parent_campaign_gate_required": True,
        "parent_campaign_gate_statement": runner.PARENT_GATE_STATEMENT,
        "authority_statement": runner.AUTHORITY_STATEMENT,
        "authority": "DEVELOPMENT_ONLY",
        "parent_binding": terminal_binding,
        "terminal_status": "SUCCESS",
        "launch_state": POPEN_OBSERVED,
        "witness_cas_complete": True,
        "witness_cas_file_count": len(references),
        "witness_cas_files": references,
        **runner.FALSE_AUTHORITY_FLAGS,
    }
    journal.terminal(attempt_id, "SUCCESS", evidence=evidence)
    return journal, attempt_id


class _FakeProcess:
    def __init__(self, stdin, stdout, stderr):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = None
        self._lock = threading.Lock()

    def poll(self):
        with self._lock:
            return self.returncode

    def finish(self, code=0):
        with self._lock:
            self.returncode = code

    def kill(self):
        self.finish(-9)

    def wait(self, timeout=None):
        del timeout
        self.finish(0 if self.returncode is None else self.returncode)
        return self.returncode


def _pipe_process(worker, role, session=DIGEST, claim=DIGEST):
    worker_in, host_in = os.pipe()
    host_out, worker_out = os.pipe()
    host_err, worker_err = os.pipe()
    process = _FakeProcess(
        os.fdopen(host_in, "wb", buffering=0),
        os.fdopen(host_out, "rb", buffering=0),
        os.fdopen(host_err, "rb", buffering=0),
    )

    def run():
        worker_in_stream = os.fdopen(worker_in, "rb", buffering=0)
        worker_out_stream = os.fdopen(worker_out, "wb", buffering=0)
        worker_err_stream = os.fdopen(worker_err, "wb", buffering=0)
        try:
            write_frame(worker_out_stream, _hello(role, session, claim))
            ready = read_next_frame(worker_in_stream)
            assert ready == _ready(role, session, claim)
            worker(role, worker_in_stream, worker_out_stream, worker_err_stream)
        except BaseException:
            process.finish(1)
        else:
            process.finish(0)
        finally:
            for stream in (worker_in_stream, worker_out_stream, worker_err_stream):
                try:
                    stream.close()
                except OSError:
                    pass

    threading.Thread(target=run, daemon=True).start()
    return process


def _good_worker(role, worker_in, worker_out, worker_err):
    del worker_err
    if role == "referee":
        write_frame(worker_out, Frame("referee", "ACTION_REQUEST", 2, _request(DIGEST, DIGEST)))
        response = read_next_frame(worker_in)
        assert response.message_type == "ACTION_RESPONSE"
        write_frame(worker_out, _terminal(DIGEST, DIGEST))
        return
    if role == "candidate_policy":
        request = read_next_frame(worker_in)
        payload = dict(request.payload)
        payload.pop("observation", None)
        payload.pop("legal_option_count", None)
        payload.pop("legal_min_count", None)
        payload.pop("legal_max_count", None)
        payload.update({"schema": PROTOCOL_SCHEMA + "_action_response_v1", "action": []})
        write_frame(worker_out, Frame(role, "ACTION_RESPONSE", 2, payload))
        read_next_frame(worker_in)
        return
    read_next_frame(worker_in)


def _malicious_worker(behavior):
    def worker(role, worker_in, worker_out, worker_err):
        del worker_err
        if role == "referee":
            write_frame(worker_out, Frame("referee", "ACTION_REQUEST", 2, _request(DIGEST, DIGEST)))
            read_next_frame(worker_in)
            return
        if role == "candidate_policy":
            request = read_next_frame(worker_in)
            if behavior == "hang":
                time.sleep(0.2)
                return
            if behavior == "os_exit":
                return
            if behavior == "stdout_garbage":
                worker_out.write(b"garbage")
                worker_out.flush()
                return
            payload = dict(request.payload)
            payload.pop("observation", None)
            payload.pop("legal_option_count", None)
            payload.pop("legal_min_count", None)
            payload.pop("legal_max_count", None)
            payload.update({"schema": PROTOCOL_SCHEMA + "_action_response_v1"})
            if behavior == "illegal":
                payload["action"] = [1]
            else:
                payload["action"] = []
                payload["request_id"] = "stale-request"
            write_frame(worker_out, Frame(role, "ACTION_RESPONSE", 2, payload))
            return
        read_next_frame(worker_in)

    return worker


def _broker(children, task=None, deadline=1.0):
    return runner._Broker(
        children,
        task or _task(),
        session_id=DIGEST,
        arm_claim_sha256=DIGEST,
        arm_deadline_seconds=deadline,
    )


def test_build_commands_enforce_three_mount_topologies(tmp_path):
    snapshot = tmp_path / "snapshot"
    for path in ("engine", "decks", "task.json", "runtime", "policy", "opponent"):
        target = snapshot / path
        target.mkdir(parents=True, exist_ok=True) if "." not in path else target.write_bytes(b"{}")
    task = _task()
    common = {
        "image": IMAGE,
        "name": "ev42-test",
        "session_id": DIGEST,
        "arm_claim_sha256": DIGEST,
        "task": task,
    }
    commands = {
        role: runner.build_docker_command(role, snapshot, **common)
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    assert len(commands) == 3
    for command in commands.values():
        assert "--interactive" in command
        assert "--platform" in command and command[command.index("--platform") + 1] == "linux/amd64"
        assert "--network" in command and command[command.index("--network") + 1] == "none"
        assert "--read-only" in command
        assert command.count("--cap-drop") == 1
        assert command.count("--label") == 3
        assert "ALL" in command
        assert "no-new-privileges=true" in command
        assert "--pid" not in command  # Docker's default is a private PID namespace.
        assert "--ipc" in command and command[command.index("--ipc") + 1] == "private"
        assert "docker.sock" not in " ".join(command)
        mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
        assert mounts and all("readonly" in mount and "bind-propagation=rprivate" in mount for mount in mounts)
    referee_mounts = [commands["referee"][index + 1] for index, item in enumerate(commands["referee"]) if item == "--mount"]
    candidate_mounts = [commands["candidate_policy"][index + 1] for index, item in enumerate(commands["candidate_policy"]) if item == "--mount"]
    opponent_mounts = [commands["opponent_policy"][index + 1] for index, item in enumerate(commands["opponent_policy"]) if item == "--mount"]
    assert {mount.split(",target=", 1)[1].split(",", 1)[0] for mount in referee_mounts} == {
        "/input/engine", "/input/decks", "/input/task.json", "/input/runtime"
    }
    assert {mount.split(",target=", 1)[1].split(",", 1)[0] for mount in candidate_mounts} == {
        "/input/policy", "/input/runtime"
    }
    assert {mount.split(",target=", 1)[1].split(",", 1)[0] for mount in opponent_mounts} == {
        "/input/opponent", "/input/runtime"
    }
    referee = commands["referee"]
    assert referee[referee.index("--left-deck") + 1] == "/input/decks/candidate/deck.csv"
    assert referee[referee.index("--right-deck") + 1] == "/input/decks/opponent/deck.csv"

    second_task = {**task, "seat": "policy_second"}
    second = runner.build_docker_command("referee", snapshot, **{**common, "task": second_task})
    assert second[second.index("--left-deck") + 1] == "/input/decks/opponent/deck.csv"
    assert second[second.index("--right-deck") + 1] == "/input/decks/candidate/deck.csv"


def test_broker_recomputes_outcome_and_transcript_from_referee_only():
    children = [
        runner._Child("referee", "referee", [], None),
        runner._Child("candidate_policy", "candidate", [], None),
        runner._Child("opponent_policy", "opponent", [], None),
    ]
    children[0].process = _pipe_process(_good_worker, "referee")
    children[1].process = _pipe_process(_good_worker, "candidate_policy")
    children[2].process = _pipe_process(_good_worker, "opponent_policy")
    result = _broker(children).run()
    assert result["status"] == "SUCCESS"
    assert result["outcome"] == 1.0
    assert result["winner_role"] == "candidate_policy"
    assert result["winner_index"] == 0
    assert result["transcript_sha256"]
    assert len(result["transcript_records"]) == 3


@pytest.mark.parametrize("behavior", ["hang", "stdout_garbage", "illegal", "stale", "os_exit"])
def test_malicious_policy_boundary_is_a_terminal_fault(behavior):
    children = [
        runner._Child("referee", "referee", [], None),
        runner._Child("candidate_policy", "candidate", [], None),
        runner._Child("opponent_policy", "opponent", [], None),
    ]
    children[0].process = _pipe_process(_malicious_worker(behavior), "referee")
    children[1].process = _pipe_process(_malicious_worker(behavior), "candidate_policy")
    children[2].process = _pipe_process(_malicious_worker(behavior), "opponent_policy")
    with pytest.raises(runner.SandboxArmFault):
        _broker(children, deadline=0.05).run()
    for child in children:
        child.process.kill()
        child.process.wait(timeout=1)


def test_broker_output_budget_is_shared_across_all_child_streams(monkeypatch):
    monkeypatch.setattr(runner, "MAX_AGGREGATE_OUTPUT_BYTES", 8)
    broker = _broker([])
    streams = []
    children = []
    try:
        for index in range(3):
            read_fd, write_fd = os.pipe()
            os.write(write_fd, b"abc")
            os.close(write_fd)
            stream = os.fdopen(read_fd, "rb", buffering=0)
            streams.append(stream)
            children.append(
                runner._Child(
                    f"child-{index}",
                    f"child-{index}",
                    [],
                    SimpleNamespace(stdout=stream, stderr=stream),
                )
            )
        assert runner._capture_fd(
            children[0], "stdout", runner.MAX_OUTPUT_BYTES, output_budget=broker.output_budget
        ) == b"abc"
        assert runner._capture_fd(
            children[1], "stderr", runner.MAX_STDERR_BYTES, output_budget=broker.output_budget
        ) == b"abc"
        with pytest.raises(runner.SandboxArmFault, match="aggregate child stdout/stderr"):
            runner._capture_fd(
                children[2], "stdout", runner.MAX_OUTPUT_BYTES, output_budget=broker.output_budget
            )
    finally:
        for stream in streams:
            stream.close()


def test_docker_calls_have_bounded_timeouts(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return type("Completed", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner._docker_call(["docker", "version"], timeout=0.125)
    assert seen["kwargs"]["timeout"] == 0.125
    assert seen["kwargs"]["capture_output"] is True
    assert seen["kwargs"]["check"] is False


def test_launch_uses_exactly_three_attached_popen_channels(monkeypatch):
    calls = []

    class FakeProcess:
        stdin = object()
        stdout = object()
        stderr = object()

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeProcess()

    monkeypatch.setattr(runner.subprocess, "Popen", fake_popen)
    commands = {
        role: ["docker", "run", role]
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    names = runner.deterministic_container_names("attempt-1")
    children = runner._launch_children(commands, names)
    assert [child.role for child in children] == ["referee", "candidate_policy", "opponent_policy"]
    assert len(calls) == 3
    assert all(call[1]["stdin"] is runner.subprocess.PIPE for call in calls)
    assert all(call[1]["stdout"] is runner.subprocess.PIPE for call in calls)
    assert all(call[1]["stderr"] is runner.subprocess.PIPE for call in calls)
    assert all(call[1]["close_fds"] is True for call in calls)


def test_fault_cleanup_kills_all_three_deterministic_names(monkeypatch):
    calls = []

    def fake_call(command, **kwargs):
        calls.append((command, kwargs))
        return type("Completed", (), {"returncode": 1, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(runner, "_docker_call", fake_call)
    names = runner.deterministic_container_names("attempt-1")
    runner._kill_and_remove([], names, docker_timeout=0.5)
    kill_names = [command[-1] for command, _ in calls if command[1] == "kill"]
    remove_names = [command[-1] for command, _ in calls if command[1] == "container"]
    assert kill_names == [names[role] for role in ("referee", "candidate_policy", "opponent_policy")]
    assert remove_names == [names[role] for role in ("referee", "candidate_policy", "opponent_policy")]


def test_start_is_durable_before_first_child_launch(monkeypatch, tmp_path):
    task = _task()
    manifest = {"content_sha256": "c" * 64, "task": task}
    snapshot_manifest = {"tree_sha256": "d" * 64, "files": []}
    events = []
    expected_claim_sha256 = canonical_sha256(
        runner.build_arm_claim(task, manifest["content_sha256"])
    )
    expected_one_shot_key = "e" * 64

    class FakeJournal:
        def state(self, attempt_id):
            return {
                "state": "CLAIMED",
                "claim_sha256": expected_claim_sha256,
                "one_shot_key_sha256": expected_one_shot_key,
                "prepared_evidence_sha256": DIGEST,
            }

        def one_shot_key(self, campaign_sha256, candidate_identity_sha256):
            return expected_one_shot_key

        def events(self):
            return [{
                "event_type": "CLAIM",
                "payload": {
                    "attempt_id": "attempt",
                    "metadata": {
                        "scope": "single_arm",
                        "campaign_sha256": runner.arm_campaign_sha256(task, manifest["content_sha256"]),
                        "panel_parent_claim_verified": False,
                    },
                },
            }]

        def prepare(self, attempt_id, evidence=None):
            events.append("PREPARED")
            return {}

        def start(self, attempt_id, evidence=None):
            events.append("STARTED")
            return {}

        def terminal(self, attempt_id, status, evidence=None):
            events.append("TERMINAL")
            return {}

        def compose_attempt(self, attempt_id):
            return {"authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY", "terminal_status": "SUCCESS"}

    def fake_launch(commands, names):
        assert events == ["PREPARED", "STARTED"]
        return []

    monkeypatch.setattr(runner, "_load_bundle_validator", lambda: lambda path: manifest)
    monkeypatch.setattr(runner, "_snapshot_bundle", lambda bundle, root, value: (root / "snapshot", snapshot_manifest))
    monkeypatch.setattr(runner, "_verify_image", lambda image, timeout: {})
    monkeypatch.setattr(runner, "_existing_name_check", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_launch_children", fake_launch)
    monkeypatch.setattr(runner, "_remove_exited", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_verify_snapshot", lambda snapshot, manifest: None)
    monkeypatch.setattr(runner, "_write_artifacts", lambda *args, **kwargs: {"schema": "evidence"})
    monkeypatch.setattr(
        runner,
        "_install_witness_cas",
        lambda journal, artifact_root, evidence: {
            **evidence,
            "witness_cas_complete": True,
            "witness_cas_files": {},
        },
    )
    monkeypatch.setattr(runner, "_Broker", lambda *args, **kwargs: type("Broker", (), {"run": lambda self: {"status": "SUCCESS", "outcome": 1.0}})())
    monkeypatch.setattr(
        runner,
        "compose_witnessed_arm",
        lambda journal, attempt_id: {
            "authority": "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY",
            "attempt_id": attempt_id,
            "submit_authorized": False,
        },
    )
    result = runner.execute_arm(
        tmp_path / "bundle",
        output_dir=tmp_path / "artifacts",
        journal=FakeJournal(),
        attempt_id="attempt",
        claim_sha256=expected_claim_sha256,
        campaign_sha256=runner.arm_campaign_sha256(task, manifest["content_sha256"]),
    )
    assert result["status"] == "SUCCESS"
    assert result["panel_parent_claim_verified"] is False
    assert events == ["PREPARED", "STARTED", "TERMINAL"]


def test_raw_artifacts_are_reopened_and_installed_in_witness_cas(tmp_path):
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    raw = artifact_root / "raw" / "candidate_policy" / "stdout.bin"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b"framed-policy-output")
    digest = runner._sha256_file(raw)
    journal = WitnessJournal(tmp_path / "journal", b"cas-test-key")
    terminal = {
        "schema": "terminal",
        "artifact_files": {
            "raw/candidate_policy/stdout.bin": {
                "sha256": digest,
                "size_bytes": raw.stat().st_size,
            }
        },
    }
    witnessed = runner._install_witness_cas(journal, artifact_root, terminal)
    assert witnessed["witness_cas_complete"] is True
    assert witnessed["witness_cas_file_count"] == 1
    assert journal.evidence.read(digest) == b"framed-policy-output"

    raw.chmod(0o600)
    raw.write_bytes(b"tampered")
    with pytest.raises(runner.SandboxArmError, match="changed"):
        runner._install_witness_cas(journal, artifact_root, terminal)


def test_witnessed_arm_reopens_cas_recomputes_transcript_and_isolation(tmp_path):
    journal, attempt_id, references = _sealed_arm_journal(tmp_path)
    result = runner.compose_witnessed_arm(journal, attempt_id)
    assert result["status"] == "SUCCESS"
    assert result["host_outcome"] == 1.0
    assert result["winner_role"] == "candidate_policy"
    assert result["reopened_file_count"] == len(references)
    assert result["transcript_chain_recomputed"] is True
    assert result["terminal_outcome_recomputed"] is True
    assert result["cross_policy_isolation_configuration_verified"] is True
    assert result["cross_policy_isolation_verified"] is False
    assert result["cross_policy_noninterference_proven"] is False
    assert result["sandbox_escape_absence_proven"] is False
    assert result["referee_rules_correctness_verified"] is False
    assert result["policy_execution_successful"] is True
    assert result["outcome_usable"] is False
    assert result["global_one_shot_within_authority"] is False
    assert result["root_local_one_shot_enforced"] is True
    assert result["canonical_external_journal_required"] is True
    assert result["submit_authorized"] is False
    assert result["panel_parent_claim_verified"] is False


def test_witnessed_arm_rejects_caller_receipts_and_incomplete_cas(tmp_path):
    journal, attempt_id, _ = _sealed_arm_journal(tmp_path / "caller")
    with pytest.raises(runner.SandboxArmError, match="caller receipt"):
        runner.compose_witnessed_arm(journal, attempt_id, caller_receipt={"status": "SUCCESS"})

    incomplete, incomplete_attempt, _ = _sealed_arm_journal(
        tmp_path / "incomplete",
        missing_reference=True,
    )
    with pytest.raises(runner.SandboxArmError, match="exactly cover"):
        runner.compose_witnessed_arm(incomplete, incomplete_attempt)


def test_witnessed_arm_rejects_tampered_cas_and_transcript_chain(tmp_path):
    journal, attempt_id, references = _sealed_arm_journal(tmp_path / "cas")
    transcript_digest = references["transcript.json"]["sha256"]
    transcript_path = journal.evidence.root / transcript_digest
    transcript_path.chmod(0o600)
    transcript_path.write_bytes(b"tampered")
    with pytest.raises(Exception, match="rehash"):
        runner.compose_witnessed_arm(journal, attempt_id)

    bad_chain, bad_attempt, _ = _sealed_arm_journal(
        tmp_path / "chain",
        invalid_transcript=True,
    )
    with pytest.raises(runner.SandboxArmError, match="chain differs"):
        runner.compose_witnessed_arm(bad_chain, bad_attempt)

    raw_mismatch, raw_attempt, _ = _sealed_arm_journal(
        tmp_path / "raw-mismatch",
        raw_mismatch=True,
    )
    with pytest.raises(runner.SandboxArmError, match="referee stdout"):
        runner.compose_witnessed_arm(raw_mismatch, raw_attempt)


def test_witnessed_arm_rejects_success_without_observed_isolation(tmp_path):
    journal, attempt_id, _ = _sealed_arm_journal(tmp_path, invalid_isolation=True)
    with pytest.raises(runner.SandboxArmError, match="inspect mount set"):
        runner.compose_witnessed_arm(journal, attempt_id)


def test_witnessed_arm_reopens_the_complete_snapshot(tmp_path):
    omitted, omitted_attempt, _ = _sealed_arm_journal(
        tmp_path / "omitted",
        omit_snapshot_file=True,
    )
    with pytest.raises(runner.SandboxArmError, match="snapshot/policy/deck.csv"):
        runner.compose_witnessed_arm(omitted, omitted_attempt)

    tampered, tampered_attempt, _ = _sealed_arm_journal(
        tmp_path / "tampered",
        tamper_snapshot_file=True,
    )
    with pytest.raises(runner.SandboxArmError, match="reopened snapshot file differs"):
        runner.compose_witnessed_arm(tampered, tampered_attempt)


def test_witnessed_arm_rejects_command_resource_mount_and_image_drift(tmp_path):
    def change_command(commands):
        commands["referee"][0] = "podman"

    def change_resource(commands):
        command = commands["referee"]
        command[command.index("--memory") + 1] = "123456789"
        command[command.index("--memory-swap") + 1] = "123456789"

    def change_mount(commands):
        command = commands["candidate_policy"]
        mount_index = command.index("--mount") + 1
        command[mount_index] = command[mount_index].replace("/policy", "/policy-drift", 1)

    def change_image(commands):
        command = commands["opponent_policy"]
        command[command.index("python") - 1] = "registry.example/python@sha256:" + "c" * 64

    for label, mutator in {
        "command": change_command,
        "resource": change_resource,
        "mount": change_mount,
        "image": change_image,
    }.items():
        journal, attempt_id, _ = _sealed_arm_journal(
            tmp_path / label,
            sealed_command_mutator=mutator,
        )
        with pytest.raises(runner.SandboxArmError):
            runner.compose_witnessed_arm(journal, attempt_id)


def test_witnessed_arm_rejects_a_synthetic_minimal_inspect_record(tmp_path):
    def strip_candidate_inspect(role, inspect):
        if role == "candidate_policy":
            inspect["config"] = {"User": runner.CONTAINER_USER}

    journal, attempt_id, _ = _sealed_arm_journal(
        tmp_path,
        inspect_mutator=strip_candidate_inspect,
    )
    with pytest.raises(runner.SandboxArmError, match="inspect bindings differ"):
        runner.compose_witnessed_arm(journal, attempt_id)


def test_witnessed_arm_rejects_started_evidence_mismatch(tmp_path):
    journal, attempt_id, _ = _sealed_arm_journal(
        tmp_path,
        started_prepared_digest="f" * 64,
    )
    with pytest.raises(runner.SandboxArmError, match="started evidence does not bind"):
        runner.compose_witnessed_arm(journal, attempt_id)


def test_witnessed_arm_preserves_a_valid_draw_outcome(tmp_path):
    journal, attempt_id, _ = _sealed_arm_journal(tmp_path, draw=True)
    result = runner.compose_witnessed_arm(journal, attempt_id)
    assert result["status"] == "SUCCESS"
    assert result["winner_role"] is None
    assert result["host_outcome"] == 0.5


def test_witnessed_failed_arm_has_no_selectable_outcome(tmp_path):
    journal, attempt_id, _ = _sealed_arm_journal(tmp_path, status="FAILURE")
    result = runner.compose_witnessed_arm(journal, attempt_id)
    assert result["status"] == "FAILURE"
    assert result["host_outcome"] is None
    assert result["winner_role"] is None
    assert result["transcript_chain_recomputed"] is False
    assert result["terminal_outcome_recomputed"] is False
    assert result["cross_policy_isolation_configuration_verified"] is False
    assert result["cross_policy_isolation_verified"] is False
    assert result["policy_execution_successful"] is False
    assert result["outcome_usable"] is False
    assert result["submit_authorized"] is False


def test_single_arm_claim_document_cannot_claim_panel_authority():
    document = runner.build_arm_claim(_task(), "c" * 64)
    assert document["scope"] == "single_arm"
    assert document["panel_parent_claim_verified"] is False
    assert document["production_submission_authorized"] is False
    assert document["submit_authorized"] is False
    assert "parent campaign claim" in document["arm_campaign"]["parent_campaign_gate_statement"]


def test_parent_mode_rejects_standalone_witness_adoption(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "_load_bundle_validator", lambda: lambda path: {"task": _task()})
    standalone = WitnessJournal(tmp_path / "standalone", b"standalone-key")
    with pytest.raises(runner.SandboxArmError, match="CampaignJournal"):
        runner.execute_parent_bound_arm(
            tmp_path / "bundle",
            output_dir=tmp_path / "artifacts",
            campaign_journal=standalone,  # type: ignore[arg-type]
            campaign_id=DIGEST,
            allocation_id="allocation-0",
        )


def test_parent_mode_accepts_no_caller_selectable_runner_defaults():
    parameters = inspect.signature(runner.execute_parent_bound_arm).parameters
    assert set(parameters) == {
        "bundle_dir",
        "output_dir",
        "campaign_journal",
        "campaign_id",
        "allocation_id",
    }
    for forbidden in (
        "image",
        "arm_deadline_seconds",
        "docker_timeout",
        "cpu_millicores",
        "memory_bytes",
        "pids_limit",
        "tmpfs_bytes",
    ):
        assert forbidden not in parameters


def test_parent_bound_execution_has_no_standalone_cli_surface():
    parser = runner._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["execute-parent-bound"])


def test_parent_template_materialization_binds_all_durable_hashes_and_rejects_drift(tmp_path):
    snapshot = tmp_path / "snapshot"
    template = {
        "normalized_command_templates": {
            role: [
                "docker",
                "run",
                "$SNAPSHOT",
                "$CHILD_CLAIM_SHA256",
                "$ARM_BOUND_EVENT_SHA256",
                "$CHILD_START_EVENT_SHA256",
                "$SESSION_ID",
            ]
            for role in ("referee", "candidate_policy", "opponent_policy")
        },
    }
    template["command_template_sha256s"] = {
        role: canonical_sha256(command)
        for role, command in template["normalized_command_templates"].items()
    }
    child_claim = "1" * 64
    arm_bound = "2" * 64
    child_start = "3" * 64
    session = runner._parent_session_id(child_claim, arm_bound, child_start)
    commands = runner._materialize_parent_commands(
        template,
        snapshot=snapshot,
        child_claim_sha256=child_claim,
        arm_bound_event_sha256=arm_bound,
        child_start_event_sha256=child_start,
        session_id=session,
    )
    assert all(command[-1] == session for command in commands.values())
    assert all(child_claim in command and arm_bound in command and child_start in command for command in commands.values())
    assert child_claim in session and arm_bound in session and child_start in session

    template["normalized_command_templates"]["referee"][1] = "run-drift"
    with pytest.raises(runner.SandboxArmError, match="hash drifted"):
        runner._materialize_parent_commands(
            template,
            snapshot=snapshot,
            child_claim_sha256=child_claim,
            arm_bound_event_sha256=arm_bound,
            child_start_event_sha256=child_start,
            session_id=session,
        )


def test_parent_execution_binds_instantiated_claim_and_runtime_receipt(monkeypatch, tmp_path):
    fixture = _parent_campaign_fixture(monkeypatch, tmp_path)
    result, runtime_calls, launch_calls, artifact_calls = _fake_parent_execution_edges(
        monkeypatch, fixture, tmp_path
    )
    journal = fixture["journal"]
    child_journal = journal._arm_journal
    child_state = child_journal.state(result["child_attempt_id"])
    claim = json.loads(child_journal.evidence.read(child_state["claim_sha256"]))
    prepared = json.loads(
        child_journal.evidence.read(child_state["prepared_evidence_sha256"])
    )
    started = json.loads(
        child_journal.evidence.read(child_state["started_evidence_sha256"])
    )

    assert len(runtime_calls) == 1
    assert runtime_calls[0][1] == {
        "repository_root": runner.ROOT,
        "phase": "pre_arm_start",
        "campaign_id": fixture["campaign_id"],
        "plan_sha256": fixture["plan"]["content_sha256"],
        "wave": 0,
        "allocation_id": fixture["allocation"]["allocation_id"],
    }
    assert len(launch_calls) == 1
    assert result["terminal_status"] == "SUCCESS"
    assert result["launch_state"] == POPEN_OBSERVED
    for field in (
        "parent_prepare_event_sha256",
        "parent_start_evidence_sha256",
        "parent_start_event_sha256",
        "parent_wave_start_event_sha256",
        "wave_runtime_verification_sha256",
    ):
        assert field not in fixture["template"]
        assert prepared["parent_binding"][field] == claim[field]
        assert started["parent_binding"][field] == claim[field]
    runtime_digest = prepared["pre_arm_runtime_verification_sha256"]
    assert started["pre_arm_runtime_verification_sha256"] == runtime_digest
    assert child_journal.evidence.contains(runtime_digest)
    assert journal.evidence.contains(runtime_digest)
    assert artifact_calls[0]["terminal_status"] == "SUCCESS"
    assert artifact_calls[0]["launch_state"] == POPEN_OBSERVED


def test_parent_execution_burns_a_fault_before_complete_popen(monkeypatch, tmp_path):
    fixture = _parent_campaign_fixture(monkeypatch, tmp_path)
    result, runtime_calls, launch_calls, artifact_calls = _fake_parent_execution_edges(
        monkeypatch,
        fixture,
        tmp_path,
        pre_popen_fault=True,
    )
    child_state = fixture["journal"]._arm_journal.state(result["child_attempt_id"])
    assert len(runtime_calls) == 1
    assert launch_calls == []
    assert result["status"] == "FAULT"
    assert result["terminal_status"] == BURN
    assert result["launch_state"] == START_DURABLE_POPEN_UNCERTAIN
    assert child_state["terminal_status"] == BURN
    assert artifact_calls[0]["terminal_status"] == BURN
    assert artifact_calls[0]["launch_state"] == START_DURABLE_POPEN_UNCERTAIN


def test_parent_bound_success_recomposes_from_claim_runtime_and_launch_evidence(
    monkeypatch, tmp_path
):
    journal, attempt_id = _sealed_parent_arm_journal(tmp_path)
    monkeypatch.setattr(
        runner.campaign_runtime,
        "validate_campaign_runtime_verification",
        lambda value, **kwargs: value,
    )
    packet = runner.compose_witnessed_arm(journal, attempt_id)
    assert packet["schema"] == runner.WITNESSED_ARM_SCHEMA
    assert packet["attempt_id"] == attempt_id
    assert packet["status"] == "SUCCESS"
    assert packet["host_outcome"] == 1.0
    assert packet["witness_chain_verified"] is True
    assert packet["cross_policy_isolation_configuration_verified"] is True
    assert packet["outcome_usable"] is False


def test_functional_parent_templates_round_trip_real_docker_commands(tmp_path):
    snapshot = tmp_path / "snapshot"
    names = runner.deterministic_container_names("template-round-trip")
    templates = runner.build_parent_docker_command_templates(
        snapshot,
        _task(),
        image=IMAGE,
        names=names,
        cpu_millicores=1000,
        memory_bytes=512 * 1024 * 1024,
        pids_limit=64,
        tmpfs_bytes=64 * 1024 * 1024,
    )
    child_claim = "1" * 64
    arm_bound = "2" * 64
    child_start = "3" * 64
    session = runner._parent_session_id(child_claim, arm_bound, child_start)
    template = {
        "normalized_command_templates": templates,
        "command_template_sha256s": {
            role: canonical_sha256(command) for role, command in templates.items()
        },
    }
    materialized = runner._materialize_parent_commands(
        template,
        snapshot=snapshot,
        child_claim_sha256=child_claim,
        arm_bound_event_sha256=arm_bound,
        child_start_event_sha256=child_start,
        session_id=session,
    )
    expected = {
        role: runner.build_docker_command(
            role,
            snapshot,
            image=IMAGE,
            name=names[role],
            session_id=session,
            arm_claim_sha256=child_claim,
            task=_task(),
            arm_bound_event_sha256=arm_bound,
            child_start_event_sha256=child_start,
        )
        for role in ("referee", "candidate_policy", "opponent_policy")
    }
    assert materialized == expected
    assert any("$SNAPSHOT" in token and token != "$SNAPSHOT" for token in templates["referee"])


def test_campaign_and_one_shot_identity_ignore_labels_and_archive_repackaging():
    task = _task()
    aliased = {
        **task,
        "policy_label": "renamed-candidate",
        "policy_archive_sha256": "b" * 64,
        "opponent_id": "renamed-opponent",
        "opponent_archive_sha256": "c" * 64,
        "engine_id": "renamed-engine",
    }
    assert runner.build_arm_campaign(task, "d" * 64) == runner.build_arm_campaign(
        aliased,
        "e" * 64,
    )
    assert runner.policy_identity_sha256(task) == runner.policy_identity_sha256(aliased)

    changed_policy = {**aliased, "policy_main_sha256": "f" * 64}
    assert runner.build_arm_campaign(task, "d" * 64) != runner.build_arm_campaign(
        changed_policy,
        "e" * 64,
    )


def test_execute_rejects_noncanonical_claim_and_arbitrary_one_shot_key(monkeypatch, tmp_path):
    task = _task()
    manifest = {"content_sha256": "c" * 64, "task": task}
    campaign_sha256 = runner.arm_campaign_sha256(task, manifest["content_sha256"])
    candidate_identity = runner.policy_identity_sha256(task)
    monkeypatch.setattr(runner, "_load_bundle_validator", lambda: lambda path: manifest)

    forged_claim = WitnessJournal(tmp_path / "forged-journal", b"forged-key")
    forged_claim.claim(
        "attempt",
        claim={"forged": True},
        one_shot_key_sha256=forged_claim.one_shot_key(campaign_sha256, candidate_identity),
        metadata={
            "scope": "single_arm",
            "campaign_sha256": campaign_sha256,
            "panel_parent_claim_verified": False,
        },
    )
    with pytest.raises(runner.SandboxArmError, match="canonical single-arm claim"):
        runner.execute_arm(
            tmp_path / "bundle",
            output_dir=tmp_path / "forged-output",
            journal=forged_claim,
            attempt_id="attempt",
        )

    wrong_key = WitnessJournal(tmp_path / "wrong-key-journal", b"wrong-key")
    wrong_key.claim(
        "attempt",
        claim=runner.build_arm_claim(task, manifest["content_sha256"]),
        one_shot_key_sha256="f" * 64,
        metadata={
            "scope": "single_arm",
            "campaign_sha256": campaign_sha256,
            "panel_parent_claim_verified": False,
        },
    )
    with pytest.raises(runner.SandboxArmError, match="derived one-shot key"):
        runner.execute_arm(
            tmp_path / "bundle",
            output_dir=tmp_path / "wrong-key-output",
            journal=wrong_key,
            attempt_id="attempt",
        )


def test_post_start_sealing_failure_burns_attempt_without_rerun(monkeypatch, tmp_path):
    task = _task()
    manifest = {"content_sha256": "c" * 64, "task": task}
    snapshot_manifest = {
        "bundle_manifest_sha256": manifest["content_sha256"],
        "tree_sha256": "d" * 64,
        "files": [],
    }
    journal = WitnessJournal(tmp_path / "journal", b"burn-test-key")
    runner.claim_arm(journal, "attempt", task, manifest["content_sha256"])

    monkeypatch.setattr(runner, "_load_bundle_validator", lambda: lambda path: manifest)
    monkeypatch.setattr(
        runner,
        "_snapshot_bundle",
        lambda bundle, root, value: (root / "snapshot", snapshot_manifest),
    )
    monkeypatch.setattr(runner, "_verify_image", lambda image, timeout: {})
    monkeypatch.setattr(runner, "_existing_name_check", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_launch_children", lambda commands, names: [])
    monkeypatch.setattr(runner, "_remove_exited", lambda names, docker_timeout: None)
    monkeypatch.setattr(runner, "_verify_snapshot", lambda snapshot, value: None)
    monkeypatch.setattr(
        runner,
        "_Broker",
        lambda *args, **kwargs: type(
            "Broker",
            (),
            {"run": lambda self: {"status": "SUCCESS", "outcome": 1.0}},
        )(),
    )
    monkeypatch.setattr(
        runner,
        "_write_artifacts",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(runner.SandboxArmError, match="attempt is BURN"):
        runner.execute_arm(
            tmp_path / "bundle",
            output_dir=tmp_path / "artifacts",
            journal=journal,
            attempt_id="attempt",
        )
    assert journal.state("attempt")["terminal_status"] == "BURN"
    assert journal.compose_attempt("attempt")["evidence"]["outcome_usable"] is False
    with pytest.raises(runner.SandboxArmError, match="must be CLAIMED"):
        runner.execute_arm(
            tmp_path / "bundle",
            output_dir=tmp_path / "second-artifacts",
            journal=journal,
            attempt_id="attempt",
        )


def test_referee_accepts_terminal_result_created_by_last_permitted_action(monkeypatch, tmp_path):
    session_id = "session-final-action"
    claim_sha256 = DIGEST
    task = {**_task(), "max_steps": 1}
    task_path = tmp_path / "task.json"
    task_path.write_bytes(canonical_json_bytes(task))
    deck_bytes = ("1\n" * 60).encode("ascii")
    left_deck = tmp_path / "left.csv"
    right_deck = tmp_path / "right.csv"
    left_deck.write_bytes(deck_bytes)
    right_deck.write_bytes(deck_bytes)

    initial = _observation()
    terminal_observation = {
        "current": {"yourIndex": 0, "result": 0},
        "select": {"option": [], "minCount": 0, "maxCount": 0},
    }

    class FakeGame:
        def battle_start_seeded(self, left, right, seed):
            return initial, SimpleNamespace(errorPlayer=None, errorType=None)

        def battle_select(self, action):
            assert action == [0]
            return terminal_observation

        def battle_finish(self):
            return None

    request_payload = _request(session_id, claim_sha256)
    response_payload = dict(request_payload)
    for key in ("observation", "legal_option_count", "legal_min_count", "legal_max_count"):
        response_payload.pop(key)
    response_payload.update({"schema": PROTOCOL_SCHEMA + "_action_response_v1", "action": [0]})
    input_bytes = _ready("referee", session_id, claim_sha256).to_bytes() + Frame(
        "candidate_policy",
        "ACTION_RESPONSE",
        2,
        response_payload,
    ).to_bytes()
    stdin = io.BytesIO(input_bytes)
    stdout = io.BytesIO()
    monkeypatch.setattr(runner, "sys", SimpleNamespace(stdin=SimpleNamespace(buffer=stdin), stdout=SimpleNamespace(buffer=stdout)))
    monkeypatch.setattr(
        "evaluation_v2.seeded_arena.load_seeded_game",
        lambda engine_dir: FakeGame(),
    )

    assert runner._referee_worker(
        session_id,
        claim_sha256,
        task_path,
        left_deck,
        right_deck,
        tmp_path / "engine",
    ) == 0
    stream = io.BytesIO(stdout.getvalue())
    frames = []
    while stream.tell() < len(stdout.getvalue()):
        frames.append(read_next_frame(stream))
    assert [frame.message_type for frame in frames] == ["HELLO", "ACTION_REQUEST", "TERMINAL"]
    assert frames[-1].payload["winner_role"] == "candidate_policy"


@pytest.mark.docker_smoke
@pytest.mark.skipif(os.environ.get("EVALUATION_V4_2_DOCKER_SMOKE") != "1", reason="opt-in Docker smoke")
def test_docker_smoke_is_opt_in_only():
    assert os.environ.get("EVALUATION_V4_2_DOCKER_SMOKE") == "1"
