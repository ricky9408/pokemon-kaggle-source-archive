from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from evaluation_v6_2.integration_v622 import canonical_json_bytes
from evaluation_v6_2 import release_v626
from tests.test_evaluation_v6_2_release_v626 import Fixture, _build_fixture
from tools import evaluation_v6_2_6_release as cli


CLI = Path(__file__).parents[1] / "tools" / "evaluation_v6_2_6_release.py"


def _run_cli(*args: str) -> tuple[int, dict[str, object]]:
    result = subprocess.run(
        [sys.executable, str(CLI), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def _assert_no_authority(report: dict[str, object]) -> None:
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["permits"] == []
    assert report["sealed_holdout_accessed"] is False


def _write_pack(tmp_path: Path, fixture: Fixture) -> Path:
    kwargs = fixture.kwargs
    files = {
        "witness.json": kwargs["witness_transition"],
        "opening-head.json": kwargs["opening_witness_head"],
        "closing-head.json": kwargs["closing_witness_head"],
        "open-time.json": kwargs["opening_time_receipts"],
        "close-time.json": kwargs["closing_time_receipts"],
        "receipts.json": kwargs["verification_receipts"],
        "observed-witness.json": [],
    }
    for name, value in files.items():
        (tmp_path / name).write_bytes(canonical_json_bytes(value))
    (tmp_path / "nodes.jsonl").write_bytes(kwargs["nodes_jsonl"])
    (tmp_path / "edges.jsonl").write_bytes(kwargs["edges_jsonl"])
    (tmp_path / "payload-manifest.jsonl").write_bytes(kwargs["payload_manifest_jsonl"])
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    for digest, data in kwargs["payloads"].items():
        (payload_dir / f"{digest}.payload").write_bytes(data)
    invocation = {
        "schema": cli.INVOCATION_SCHEMA,
        "witness_transition_path": "witness.json",
        "opening_witness_head_path": "opening-head.json",
        "closing_witness_head_path": "closing-head.json",
        "opening_time_receipts_path": "open-time.json",
        "closing_time_receipts_path": "close-time.json",
        "evidence_nodes_jsonl_path": "nodes.jsonl",
        "evidence_edges_jsonl_path": "edges.jsonl",
        "evidence_payload_manifest_jsonl_path": "payload-manifest.jsonl",
        "evidence_payload_directory": "payloads",
        "evidence_graph_root_sha256": kwargs["evidence_graph_root_sha256"],
        "campaign_bundle_root_sha256": kwargs["campaign_bundle_root_sha256"],
        "verification_packet_root_sha256": kwargs["verification_packet_root_sha256"],
        "invocation_challenge_sha256": kwargs["invocation_challenge_sha256"],
        "population_analysis_root_sha256": kwargs["population_analysis_root_sha256"],
        "evidence_input_graph_root_sha256": kwargs["evidence_input_graph_root_sha256"],
        "pair_classification_graph_root_sha256": kwargs["pair_classification_graph_root_sha256"],
        "component_assignment_root_sha256": kwargs["component_assignment_root_sha256"],
        "pair_analysis_root_sha256s": kwargs["pair_analysis_root_sha256s"],
        "principal_assignment_root_sha256s": kwargs["principal_assignment_root_sha256s"],
        "verification_receipts_path": "receipts.json",
        "observed_witness_transitions_path": "observed-witness.json",
    }
    path = tmp_path / "invocation.json"
    path.write_bytes(canonical_json_bytes(invocation))
    return path


def test_status_is_bootstrap_absent_and_no_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release_v626, "PINNED_EXTERNAL_TRUST_POLICY", None)
    monkeypatch.setattr(release_v626, "PINNED_EXTERNAL_TRUST_POLICY_SHA256", None)
    exit_code, report = _run_cli("status")
    assert exit_code == 2
    assert report["state"] == "BOOTSTRAP_CONFIG_ABSENT"
    _assert_no_authority(report)


def test_assess_fails_before_reading_campaign_inputs_when_policy_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release_v626, "PINNED_EXTERNAL_TRUST_POLICY", None)
    monkeypatch.setattr(release_v626, "PINNED_EXTERNAL_TRUST_POLICY_SHA256", None)
    exit_code, report = _run_cli("assess", "/definitely/not/present.json")
    assert exit_code == 2
    assert report["state"] == "BOOTSTRAP_CONFIG_ABSENT"
    _assert_no_authority(report)


def test_canonical_artifact_pack_cannot_replace_live_witness_acquisition(tmp_path: Path) -> None:
    fixture = _build_fixture()
    invocation = _write_pack(tmp_path, fixture)
    loaded = cli.load_invocation(invocation)
    offline = release_v626.assess_population_trust(
        trust_policy=fixture.policy,
        trust_policy_sha256=fixture.kwargs["trust_policy_sha256"],
        **loaded,
    )
    assert offline["state"] == "LIVE_EXTERNAL_STATE_NOT_ACQUIRED"
    _assert_no_authority(offline)

    verdict = release_v626.verify_population_trust(
        trust_policy=fixture.policy,
        trust_policy_sha256=fixture.kwargs["trust_policy_sha256"],
        live_witness_acquisition=fixture.kwargs["live_witness_acquisition"],
        live_time_acquisition=fixture.kwargs["live_time_acquisition"],
        **loaded,
    )
    assert verdict["state"] == "POPULATION_TRUST_GATE_PASSED_LOCAL_EVIDENCE_PENDING"
    _assert_no_authority(verdict)


def test_loader_rejects_symlinked_evidence(tmp_path: Path) -> None:
    fixture = _build_fixture()
    invocation = _write_pack(tmp_path, fixture)
    nodes = tmp_path / "nodes.jsonl"
    real = tmp_path / "nodes-real.jsonl"
    nodes.rename(real)
    nodes.symlink_to(real)
    with pytest.raises(cli.ReleaseCliV626Error, match="non-symlink|escapes"):
        cli.load_invocation(invocation)


def test_parser_failure_is_no_authority() -> None:
    exit_code, report = _run_cli()
    assert exit_code == 2
    assert report["state"] == "POPULATION_INFEASIBLE"
    _assert_no_authority(report)
