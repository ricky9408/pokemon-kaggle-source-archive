from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

import pytest

from evaluation_v2.public_transfer import archive_policy_identity
from evaluation_v4_2.contrast_protocol import (
    ARM_EXECUTION_MODE,
    CONTRAST_PROTOCOL_SCHEMA,
    FAILURE_POLICY,
    REQUIRED_PLATFORM,
    SEATS as CONTRAST_SEATS,
    build_contrast_protocol,
)
from evaluation_v4_2.runtime_binding import build_runtime_binding
from evaluation_v4_2.simulation_design import (
    SEED_DERIVATION_ALGORITHM,
    build_simulation_template,
    canonical_sha256,
)
from tools import run_evaluation_v4_2_panel as runner
from tests.v4_2_fixtures import ready_population_for_candidate, write_opponent_evidence


def _archive(path: Path, marker: str, *, deck_shift: int = 0) -> None:
    deck = "".join(f"{card}\n" for card in [*range(1, 60), 1000 + deck_shift])
    files = {
        "./main.py": f"def agent(observation):\n    return [0]  # {marker}\n".encode(),
        "./deck.csv": deck.encode(),
        "./model.bin": marker.encode(),
        "./cg/libcg.so": b"archive-engine",
    }
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))


def _digest(value: int) -> str:
    return f"{value:064x}"


def _fixture(tmp_path: Path, *, runner_code_sha256: str | None = None) -> dict[str, object]:
    archives = tmp_path / "archives"
    archives.mkdir(parents=True)
    candidate = archives / "candidate.tar.gz"
    baseline = archives / "baseline.tar.gz"
    _archive(candidate, "candidate")
    _archive(baseline, "baseline")
    candidate_identity = archive_policy_identity(candidate)
    readiness = ready_population_for_candidate(candidate_identity)
    readiness_path = tmp_path / "population-readiness.json"
    readiness_path.write_text(json.dumps(readiness, sort_keys=True), encoding="utf-8")

    opponents: dict[str, str] = {}
    for index in range(12):
        opponent_id = f"opponent-{index:02d}"
        path = archives / f"{opponent_id}.tar.gz"
        _archive(path, opponent_id, deck_shift=index + 1)
        opponents[opponent_id] = str(path)
    opponent_manifest, template_opponents = write_opponent_evidence(tmp_path, opponents)

    engines: dict[str, str] = {}
    engine_roster: list[dict[str, str]] = []
    for index in range(2):
        directory = tmp_path / f"engine-{index}"
        binary = directory / "cg" / "libcg.so"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(f"engine-{index}".encode())
        engines[f"engine-{index}"] = str(directory)
        engine_roster.append(
            {
                "engine_id": f"engine-{index}",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "runtime_tree_sha256": runner.directory_tree_sha256(directory),
            }
        )

    execution_sources = {
        "protocol": tmp_path / "protocol.txt",
        "scientific_plan": tmp_path / "scientific-plan.txt",
        "dependency_lock": tmp_path / "dependency-lock.txt",
        "runtime_binding": tmp_path / "runtime-binding.txt",
    }
    for name, path in execution_sources.items():
        path.write_text(name, encoding="ascii")
    repo_root = Path(runner.__file__).resolve().parents[1]
    execution_sources["runtime_binding"].write_text(
        json.dumps(
            build_runtime_binding(
                {
                    "evaluation_v2": repo_root / "evaluation_v2",
                    "evaluation_v4_2": repo_root / "evaluation_v4_2",
                }
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )
    baseline_identity = archive_policy_identity(baseline)
    execution_sources["protocol"].write_text(
        json.dumps(
            build_contrast_protocol(
                {
                    "schema": CONTRAST_PROTOCOL_SCHEMA,
                    "baseline_archive_sha256": baseline_identity.archive_sha256,
                    "baseline_policy_content_sha256": baseline_identity.policy_content_sha256,
                    "baseline_main_sha256": baseline_identity.main_sha256,
                    "baseline_deck_sha256": baseline_identity.deck_sha256,
                    "max_steps": 600,
                    "worker_timeout_seconds": 900.0,
                    "max_action_seconds": 9.0,
                    "workers": 1,
                    "platform": REQUIRED_PLATFORM,
                    "arm_execution_mode": ARM_EXECUTION_MODE,
                    "failure_policy": FAILURE_POLICY,
                    "engine_count": 2,
                    "opponent_count": 12,
                    "seed_count": 16,
                    "seats": list(CONTRAST_SEATS),
                    "population_readiness_sha256": readiness["content_sha256"],
                }
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )

    content = {
        "schema": "evaluation_v4_2_simulation_template_v1",
        "protocol_sha256": hashlib.sha256(execution_sources["protocol"].read_bytes()).hexdigest(),
        "scientific_plan_sha256": hashlib.sha256(execution_sources["scientific_plan"].read_bytes()).hexdigest(),
        "runner_code_sha256": runner_code_sha256 or hashlib.sha256(Path(runner.__file__).read_bytes()).hexdigest(),
        "dependency_lock_sha256": hashlib.sha256(execution_sources["dependency_lock"].read_bytes()).hexdigest(),
        "runtime_binding_sha256": hashlib.sha256(execution_sources["runtime_binding"].read_bytes()).hexdigest(),
        "engine_roster": engine_roster,
        "opponent_roster": template_opponents,
        "seed_beacon_sha256": _digest(6),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "state": "FROZEN",
    }
    template = build_simulation_template(content)
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(template, sort_keys=True), encoding="utf-8")
    engine_manifest = tmp_path / "engines.json"
    engine_manifest.write_text(json.dumps(engines, sort_keys=True), encoding="utf-8")
    execution_manifest = tmp_path / "execution-sources.json"
    execution_manifest.write_text(
        json.dumps(
            {
                "schema": runner.EXECUTION_SOURCE_SCHEMA,
                "protocol_path": str(execution_sources["protocol"]),
                "scientific_plan_path": str(execution_sources["scientific_plan"]),
                "dependency_lock_path": str(execution_sources["dependency_lock"]),
                "runtime_binding_path": str(execution_sources["runtime_binding"]),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "template": template,
        "template_path": template_path,
        "candidate": candidate,
        "baseline": baseline,
        "population_readiness": readiness_path,
        "opponent_manifest": opponent_manifest,
        "engine_manifest": engine_manifest,
        "execution_manifest": execution_manifest,
        "opponents": opponents,
    }


def _fake_runner(task: dict[str, object], *, schema: str = runner.WORKER_SCHEMA) -> dict[str, object]:
    candidate_left = task["seat"] == "policy_first"
    candidate = {
        "left": "candidate" if candidate_left else task["opponent_id"],
        "right": task["opponent_id"] if candidate_left else "candidate",
        "winner": 0 if candidate_left else 1,
        "error": None,
        "max_action_seconds": 0.01,
        "max_action_seconds_by_label": {"candidate": 0.01, task["opponent_id"]: 0.9},
    }
    baseline = {
        "left": "baseline" if candidate_left else task["opponent_id"],
        "right": task["opponent_id"] if candidate_left else "baseline",
        "winner": 1 if candidate_left else 0,
        "error": None,
        "max_action_seconds": 0.02,
        "max_action_seconds_by_label": {"baseline": 0.02, task["opponent_id"]: 0.8},
    }
    return {"schema": schema, "row": runner._make_row(task, candidate, baseline)}


def _run(tmp_path: Path, fixture: dict[str, object], cell_runner) -> tuple[dict[str, object], dict[str, object]]:
    return runner.run_evaluation(
        template_path=fixture["template_path"],
        candidate_archive=fixture["candidate"],
        baseline_archive=fixture["baseline"],
        population_readiness=fixture["population_readiness"],
        execution_source_manifest=fixture["execution_manifest"],
        opponent_manifest=fixture["opponent_manifest"],
        engine_manifest=fixture["engine_manifest"],
        panel_output=tmp_path / "panel.json",
        feature_output=tmp_path / "features.json",
        checkpoint_path=tmp_path / "panel.raw.json",
        workers=1,
        cell_runner=cell_runner,
    )


def test_frozen_runner_artifact_hash_is_verified_before_cells(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path, runner_code_sha256=_digest(999))
    calls: list[dict[str, object]] = []

    def cell(task: dict[str, object]) -> dict[str, object]:
        calls.append(task)
        return _fake_runner(task)

    with pytest.raises(runner.RunnerError, match="runner.*hash|execution artifact"):
        _run(tmp_path, fixture, cell)
    assert calls == []


def test_frozen_baseline_and_worker_count_are_enforced_before_cells(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    calls: list[dict[str, object]] = []
    _archive(Path(fixture["baseline"]), "replacement-baseline")

    with pytest.raises(runner.RunnerError, match="baseline identity differs"):
        _run(tmp_path, fixture, lambda task: calls.append(task) or _fake_runner(task))
    assert calls == []

    fixture = _fixture(tmp_path / "worker-count")
    with pytest.raises(runner.RunnerError, match="workers override differs"):
        runner.run_evaluation(
            template_path=fixture["template_path"],
            candidate_archive=fixture["candidate"],
            baseline_archive=fixture["baseline"],
            population_readiness=fixture["population_readiness"],
            execution_source_manifest=fixture["execution_manifest"],
            opponent_manifest=fixture["opponent_manifest"],
            engine_manifest=fixture["engine_manifest"],
            panel_output=tmp_path / "worker-count" / "panel.json",
            feature_output=tmp_path / "worker-count" / "features.json",
            checkpoint_path=tmp_path / "worker-count" / "raw.json",
            workers=2,
            cell_runner=lambda task: _fake_runner(task),
        )


def test_checkpoint_has_canonical_hash_and_rejects_tampering() -> None:
    binding = {
        "schema": runner.RAW_CHECKPOINT_SCHEMA,
        "template_content_sha256": _digest(1),
        "candidate_archive_sha256": _digest(2),
        "baseline_archive_sha256": _digest(3),
        "ancestry_id": "ancestry-test",
        "opponent_identities": {},
        "engine_identities": {},
    }
    payload = runner._checkpoint_payload(binding, [])
    content = {key: value for key, value in payload.items() if key != "content_sha256"}
    assert payload["content_sha256"] == canonical_sha256(content)

    tampered = dict(payload)
    tampered["ancestry_id"] = "tampered"
    with pytest.raises(runner.RunnerError, match="checkpoint.*hash|content_sha256"):
        runner._validate_checkpoint(tampered, binding, {"engine_roster": [], "opponent_roster": [], "seeds": []})


def test_final_outputs_are_create_once_or_byte_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "build_candidate_panel", lambda *args, **kwargs: {"panel": 1})
    monkeypatch.setattr(runner, "compile_candidate_features", lambda *args, **kwargs: {"features": 1})
    panel_path = tmp_path / "panel.json"
    feature_path = tmp_path / "features.json"
    kwargs = {
        "template": {},
        "rows": [],
        "candidate_sha256": _digest(1),
        "baseline_sha256": _digest(2),
        "ancestry_id": "ancestry-test",
        "panel_output": panel_path,
        "feature_output": feature_path,
    }

    runner._finalize(**kwargs)
    panel_bytes = panel_path.read_bytes()
    runner._finalize(**kwargs)
    assert panel_path.read_bytes() == panel_bytes

    panel_path.write_bytes(b"tampered output")
    with pytest.raises(runner.RunnerError, match="create-once|byte-identical|already exists"):
        runner._finalize(**kwargs)
    assert panel_path.read_bytes() == b"tampered output"


def test_wrong_worker_schema_is_rejected_by_the_panel_runner(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    with pytest.raises(runner.RunnerError, match="execution errors|schema"):
        _run(tmp_path, fixture, lambda task: _fake_runner(task, schema="wrong-worker-schema"))


def test_frozen_per_action_deadline_vetoes_the_panel(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    def slow_candidate(task: dict[str, object]) -> dict[str, object]:
        result = _fake_runner(task)
        result["row"]["candidate_runtime_seconds"] = 9.01
        return result

    with pytest.raises(runner.RunnerError, match="execution errors"):
        _run(tmp_path, fixture, slow_candidate)
    checkpoint = json.loads((tmp_path / "panel.raw.json").read_text(encoding="utf-8"))
    assert any(
        row["candidate_error"] == "per_action_deadline_exceeded"
        for row in checkpoint["rows"]
    )


def test_worker_extra_row_fields_are_rejected_at_the_worker_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = {
        "engine_id": "engine-a",
        "engine_dir": "/engine",
        "opponent_id": "opponent-a",
        "opponent_dir": "/opponent",
        "candidate_dir": "/candidate",
        "baseline_dir": "/baseline",
        "seed": 1,
        "seat": "policy_first",
        "max_steps": 10,
        "max_action_seconds": 9.0,
    }
    row = runner._make_row(task, None, None, error="synthetic")
    payload = {"schema": runner.WORKER_SCHEMA, "row": {**row, "unexpected": True}}
    completed = subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: completed)

    result = runner.run_cell_subprocess(task, timeout_seconds=1.0)
    assert set(result["row"]) == runner.RAW_ROW_FIELDS
    assert str(result["row"]["candidate_error"]).startswith("worker_protocol_error")


@pytest.mark.parametrize("mutation", ["archive", "policy", "deck"])
def test_opponent_archive_policy_or_deck_mutation_after_resolution_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    fixture = _fixture(tmp_path)
    original_materialize = runner._materialize
    changed = False

    def materialize(archive: Path, destination: Path, *, label: str) -> None:
        nonlocal changed
        if label != "opponent opponent-00" or changed:
            original_materialize(archive, destination, label=label)
            return
        changed = True
        if mutation == "archive":
            _archive(archive, "mutated-archive")
            original_materialize(archive, destination, label=label)
        else:
            original_materialize(archive, destination, label=label)
        if mutation == "policy":
            (destination / "main.py").write_text("def agent(observation):\n    return [1]\n", encoding="utf-8")
        elif mutation == "deck":
            (destination / "deck.csv").write_text("\n".join(str(card) for card in range(2, 62)) + "\n", encoding="utf-8")

    monkeypatch.setattr(runner, "_materialize", materialize)
    with pytest.raises(runner.RunnerError, match="opponent.*identity|archive.*mismatch|deck"):
        _run(tmp_path, fixture, lambda task: _fake_runner(task))
