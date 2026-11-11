from __future__ import annotations

import json
import hashlib
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation_v6_2.integration_v622 import canonical_json_bytes
from evaluation_v6_2 import provisioning_v626
from tools import evaluation_v6_2_6_provisioning as cli
from tests.test_evaluation_v6_2_provisioning_v626 import (
    _build_provisioning_fixture,
)


CLI = Path(__file__).parents[1] / "tools" / "evaluation_v6_2_6_provisioning.py"


def _run(*args: str) -> tuple[int, dict[str, object]]:
    result = subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, check=False)
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def _no_authority(report: dict[str, object]) -> None:
    assert report["candidate_policy_pinned"] is False
    assert report["recruitment_intake_authorized"] is False
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["permits"] == []
    assert report["sealed_holdout_accessed"] is False


def _invocation(tmp_path: Path, *, manifest: bytes | None = None, extra_payload: bool = False) -> Path:
    policy = tmp_path / "policy.json"
    packet = tmp_path / "packet.json"
    nodes = tmp_path / "nodes.jsonl"
    edges = tmp_path / "edges.jsonl"
    manifest_path = tmp_path / "manifest.jsonl"
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    policy.write_bytes(canonical_json_bytes({"candidate": True}))
    packet.write_bytes(canonical_json_bytes({"packet": True}))
    nodes.write_bytes(b"{}\n")
    edges.write_bytes(b"{}\n")
    payload = b"payload"
    digest = hashlib.sha256(payload).hexdigest()
    if manifest is None:
        manifest = canonical_json_bytes({"payload_sha256": digest}) + b"\n"
    manifest_path.write_bytes(manifest)
    (payload_dir / f"{digest}.payload").write_bytes(payload)
    if extra_payload:
        (payload_dir / "extra.payload").write_bytes(b"extra")
    value = {
        "schema": cli.INVOCATION_SCHEMA,
        "candidate_trust_policy_path": "policy.json",
        "candidate_trust_policy_sha256": "0" * 64,
        "provisioning_packet_path": "packet.json",
        "evidence_nodes_jsonl_path": "nodes.jsonl",
        "evidence_edges_jsonl_path": "edges.jsonl",
        "evidence_payload_manifest_jsonl_path": "manifest.jsonl",
        "evidence_payload_directory": "payloads",
    }
    path = tmp_path / "invocation.json"
    path.write_bytes(canonical_json_bytes(value))
    return path


def _complete_invocation(tmp_path: Path) -> Path:
    fixture = _build_provisioning_fixture()
    policy_path = tmp_path / "candidate-policy.json"
    packet_path = tmp_path / "provisioning-packet.json"
    nodes_path = tmp_path / "nodes.jsonl"
    edges_path = tmp_path / "edges.jsonl"
    manifest_path = tmp_path / "payload-manifest.jsonl"
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    policy_path.write_bytes(canonical_json_bytes(fixture.kwargs["candidate_trust_policy"]))
    packet_path.write_bytes(canonical_json_bytes(fixture.kwargs["provisioning_packet"]))
    nodes_path.write_bytes(fixture.kwargs["nodes_jsonl"])
    edges_path.write_bytes(fixture.kwargs["edges_jsonl"])
    manifest_path.write_bytes(fixture.kwargs["payload_manifest_jsonl"])
    for digest, payload in fixture.kwargs["payloads"].items():
        (payload_dir / f"{digest}.payload").write_bytes(payload)
    invocation = {
        "schema": cli.INVOCATION_SCHEMA,
        "candidate_trust_policy_path": policy_path.name,
        "candidate_trust_policy_sha256": fixture.kwargs[
            "candidate_trust_policy_sha256"
        ],
        "provisioning_packet_path": packet_path.name,
        "evidence_nodes_jsonl_path": nodes_path.name,
        "evidence_edges_jsonl_path": edges_path.name,
        "evidence_payload_manifest_jsonl_path": manifest_path.name,
        "evidence_payload_directory": payload_dir.name,
    }
    invocation_path = tmp_path / "complete-invocation.json"
    invocation_path.write_bytes(canonical_json_bytes(invocation))
    return invocation_path


def test_status_is_evidence_absent_and_zero_authority() -> None:
    exit_code, report = _run("status")
    assert exit_code == 2
    assert report["schema"] == cli.CLI_SCHEMA
    assert report["state"] == "EXTERNAL_PROVISIONING_EVIDENCE_ABSENT"
    _no_authority(report)


def test_complete_packet_crosses_cli_boundary_but_gains_no_authority(
    tmp_path: Path,
) -> None:
    exit_code, report = _run("assess", str(_complete_invocation(tmp_path)))
    assert exit_code == 0
    assert (
        report["state"]
        == "CANDIDATE_EXTERNAL_SERVICES_PACKET_STRUCTURALLY_COMPLETE_REQUIRES_LIVE_CHALLENGE_AND_POLICY_PIN_REVIEW"
    )
    assert report["provisioning_evidence_complete"] is False
    assert report["offline_packet_structurally_complete"] is True
    _no_authority(report)


def test_assess_loads_exact_inputs_and_calls_provisioning(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    invocation = _invocation(tmp_path)
    captured: dict[str, object] = {}

    def fake(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return provisioning_v626.fail_closed_provisioning_verdict("EXTERNAL_PROVISIONING_EVIDENCE_ABSENT", "test")

    monkeypatch.setattr(provisioning_v626, "assess_external_provisioning_readiness", fake)
    loaded = cli.load_invocation(invocation)
    assert set(loaded) == {"candidate_trust_policy", "candidate_trust_policy_sha256", "provisioning_packet", "nodes_jsonl", "edges_jsonl", "payload_manifest_jsonl", "payloads"}
    cli.main(["assess", str(invocation)])
    assert captured["candidate_trust_policy"] == {"candidate": True}
    assert captured["nodes_jsonl"] == b"{}\n"


@pytest.mark.parametrize("kind", ["policy", "packet", "nodes", "manifest"])
def test_loader_rejects_noncanonical_json_or_jsonl(tmp_path: Path, kind: str) -> None:
    invocation = _invocation(tmp_path)
    path = {"policy": "policy.json", "packet": "packet.json", "nodes": "nodes.jsonl", "manifest": "manifest.jsonl"}[kind]
    (tmp_path / path).write_bytes(b'{ "x": true }' if kind in {"policy", "packet"} else b'{ "x": true }\n')
    with pytest.raises(cli.ProvisioningCliError, match="canonical"):
        cli.load_invocation(invocation)


def test_loader_rejects_symlink(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path)
    real = tmp_path / "real-policy.json"
    real.write_bytes((tmp_path / "policy.json").read_bytes())
    (tmp_path / "policy.json").unlink()
    (tmp_path / "policy.json").symlink_to(real)
    with pytest.raises(cli.ProvisioningCliError, match="non-symlink"):
        cli.load_invocation(invocation)


def test_loader_rejects_unexpected_payload(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path, extra_payload=True)
    with pytest.raises(cli.ProvisioningCliError, match="exactly match"):
        cli.load_invocation(invocation)


def test_loader_rejects_unexpected_payload_subdirectory(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path)
    (tmp_path / "payloads" / "unexpected-directory").mkdir()
    with pytest.raises(cli.ProvisioningCliError, match="exactly match"):
        cli.load_invocation(invocation)


def test_loader_rejects_forbidden_holdout_path(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path)
    value = json.loads(invocation.read_text())
    value["candidate_trust_policy_path"] = "sealed/policy.json"
    invocation.write_bytes(canonical_json_bytes(value))
    with pytest.raises(cli.ProvisioningCliError, match="sealed or holdout"):
        cli.load_invocation(invocation)


def test_loader_rejects_embedded_holdout_path_label(tmp_path: Path) -> None:
    invocation = _invocation(tmp_path)
    value = json.loads(invocation.read_text())
    value["candidate_trust_policy_path"] = "candidate-holdout-material/policy.json"
    invocation.write_bytes(canonical_json_bytes(value))
    with pytest.raises(cli.ProvisioningCliError, match="sealed or holdout"):
        cli.load_invocation(invocation)


def test_parser_failure_is_zero_authority() -> None:
    exit_code, report = _run()
    assert exit_code == 2
    _no_authority(report)
