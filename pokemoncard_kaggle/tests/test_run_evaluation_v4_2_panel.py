from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import time

import pytest

from evaluation_v2.public_transfer import archive_policy_identity
from evaluation_v2.seeded_arena import ArenaEntry
from evaluation_v4_2.contrast_protocol import (
    ARM_EXECUTION_MODE,
    CONTRAST_PROTOCOL_SCHEMA,
    FAILURE_POLICY,
    REQUIRED_PLATFORM,
    SEATS as CONTRAST_SEATS,
    build_contrast_protocol,
)
from evaluation_v4_2.runtime_binding import build_runtime_binding
from evaluation_v4_2.simulation_design import SEED_DERIVATION_ALGORITHM, build_simulation_template
from tools import run_evaluation_v4_2_panel as runner
from tests.v4_2_fixtures import ready_population_for_candidate, write_opponent_evidence


def _archive(path: Path, marker: str, *, deck_shift: int = 0) -> None:
    deck = [*range(1, 60), 1000 + deck_shift]
    files = {
        "./main.py": f"def agent(observation):\n    return [0]  # {marker}\n".encode(),
        "./deck.csv": "".join(f"{card}\n" for card in deck).encode(),
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


def _fixture(tmp_path: Path) -> dict[str, object]:
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
        path = archives / f"opponent-{index:02d}.tar.gz"
        _archive(path, f"opponent-{index:02d}", deck_shift=index + 1)
        opponent_id = f"opponent-{index:02d}"
        opponents[opponent_id] = str(path)
    opponent_manifest, template_opponents = write_opponent_evidence(tmp_path, opponents)

    engines: dict[str, str] = {}
    engine_hashes: list[str] = []
    engine_tree_hashes: list[str] = []
    for index in range(2):
        directory = tmp_path / f"engine-{index}"
        (directory / "cg").mkdir(parents=True)
        binary = directory / "cg" / "libcg.so"
        binary.write_bytes(f"engine-{index}".encode())
        engine_id = f"engine-{index}"
        engines[engine_id] = str(directory)
        engine_hashes.append(hashlib.sha256(binary.read_bytes()).hexdigest())
        engine_tree_hashes.append(runner.directory_tree_sha256(directory))

    execution_files: dict[str, Path] = {}
    for name in ("protocol", "scientific_plan", "dependency_lock", "runtime_binding"):
        path = tmp_path / f"{name}.txt"
        path.write_text(f"{name}-fixture\n", encoding="utf-8")
        execution_files[name] = path
    repo_root = Path(runner.__file__).resolve().parents[1]
    execution_files["runtime_binding"].write_text(
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
    execution_files["protocol"].write_text(
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
                    "workers": 4,
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
    execution_manifest = tmp_path / "execution-sources.json"
    execution_manifest.write_text(
        json.dumps(
            {
                "schema": runner.EXECUTION_SOURCE_SCHEMA,
                "protocol_path": str(execution_files["protocol"]),
                "scientific_plan_path": str(execution_files["scientific_plan"]),
                "dependency_lock_path": str(execution_files["dependency_lock"]),
                "runtime_binding_path": str(execution_files["runtime_binding"]),
            },
            sort_keys=True,
        )
    )

    content = {
        "schema": "evaluation_v4_2_simulation_template_v1",
        "protocol_sha256": hashlib.sha256(execution_files["protocol"].read_bytes()).hexdigest(),
        "scientific_plan_sha256": hashlib.sha256(execution_files["scientific_plan"].read_bytes()).hexdigest(),
        "runner_code_sha256": hashlib.sha256(Path(runner.__file__).read_bytes()).hexdigest(),
        "dependency_lock_sha256": hashlib.sha256(execution_files["dependency_lock"].read_bytes()).hexdigest(),
        "runtime_binding_sha256": hashlib.sha256(execution_files["runtime_binding"].read_bytes()).hexdigest(),
        "engine_roster": [
            {
                "engine_id": f"engine-{index}",
                "binary_sha256": engine_hashes[index],
                "runtime_tree_sha256": engine_tree_hashes[index],
            }
            for index in range(2)
        ],
        "opponent_roster": template_opponents,
        "seed_beacon_sha256": _digest(6),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "state": "FROZEN",
    }
    template = build_simulation_template(content)
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(template, sort_keys=True))
    engine_manifest = tmp_path / "engines.json"
    engine_manifest.write_text(json.dumps(engines, sort_keys=True))
    return {
        "template": template,
        "template_path": template_path,
        "candidate": candidate,
        "baseline": baseline,
        "execution_source_manifest": execution_manifest,
        "population_readiness": readiness_path,
        "opponent_manifest": opponent_manifest,
        "engine_manifest": engine_manifest,
        "engines": engines,
        "opponents": opponents,
    }


def _fake_runner(calls: list[dict[str, object]]):
    def run(task: dict[str, object]) -> dict[str, object]:
        calls.append(dict(task))
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
        return {"schema": runner.WORKER_SCHEMA, "row": runner._make_row(task, candidate, baseline)}

    return run


def _run(tmp_path: Path, fixture: dict[str, object], calls: list[dict[str, object]], **kwargs: object):
    return runner.run_evaluation(
        template_path=fixture["template_path"],
        candidate_archive=fixture["candidate"],
        baseline_archive=fixture["baseline"],
        population_readiness=fixture["population_readiness"],
        execution_source_manifest=fixture["execution_source_manifest"],
        opponent_manifest=fixture["opponent_manifest"],
        engine_manifest=fixture["engine_manifest"],
        panel_output=tmp_path / "panel.json",
        feature_output=tmp_path / "features.json",
        checkpoint_path=tmp_path / "panel.raw.json",
        workers=4,
        cell_runner=_fake_runner(calls),
        **kwargs,
    )


def test_full_grid_cardinality_common_seed_and_same_seat_pairing(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    calls: list[dict[str, object]] = []
    panel, features = _run(tmp_path, fixture, calls)

    assert len(calls) == 2 * 12 * 16 * 2
    assert len(panel["rows"]) == len(calls)
    assert features["panel_content_sha256"] == panel["content_sha256"]
    assert {call["seat"] for call in calls} == {"policy_first", "policy_second"}
    assert len({(call["seed"], call["seat"]) for call in calls}) == 32
    for call in calls:
        assert call["seed"] in fixture["template"]["seeds"]
        if call["seat"] == "policy_first":
            assert Path(call["candidate_dir"]).name == "candidate"
        else:
            assert Path(call["baseline_dir"]).name == "baseline"


def test_run_cell_pairs_candidate_and_baseline_with_identical_seed_and_seat(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, str, int]] = []

    class Entry:
        def __init__(self, label: str) -> None:
            self.label = label
            self.path = f"/{label}"
            self.deck = tuple(range(60))
            self.agent = lambda observation: [0]

    monkeypatch.setattr(runner, "load_entry_isolated", lambda label, path: Entry(label))
    monkeypatch.setattr(runner, "load_seeded_game", lambda path: object())

    def fake_game(game: object, left: Entry, right: Entry, *, seed: int, max_steps: int) -> dict[str, object]:
        captured.append((left.label, right.label, seed))
        return {
            "left": left.label,
            "right": right.label,
            "winner": 0,
            "error": None,
            "max_action_seconds": 0.03,
            "max_action_seconds_by_label": {left.label: 0.01, right.label: 0.03},
        }

    monkeypatch.setattr(runner, "run_seeded_game", fake_game)
    task = {
        "engine_id": "engine-a",
        "engine_dir": "/engine",
        "opponent_id": "opponent-a",
        "opponent_dir": "/opponent",
        "candidate_dir": "/candidate",
        "baseline_dir": "/baseline",
        "seed": 123,
        "seat": "policy_second",
        "max_steps": 10,
        "max_action_seconds": 9.0,
    }
    result = runner.run_cell(task)

    assert captured == [("opponent-a", "candidate", 123), ("opponent-a", "baseline", 123)]
    assert result["row"]["candidate_outcome"] == 0.0
    assert result["row"]["baseline_outcome"] == 0.0


def test_per_action_deadline_interrupts_policy_call() -> None:
    def slow_agent(observation: dict[str, object]) -> list[int]:
        del observation
        time.sleep(0.2)
        return [0]

    entry = ArenaEntry("slow", "/slow", tuple(range(60)), slow_agent)
    wrapped = runner._deadline_entry(entry, seconds=0.02)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="per_action_deadline_exceeded"):
        wrapped.agent({})
    assert time.monotonic() - started < 0.15


def test_identity_mismatch_is_rejected_before_any_cell_runs(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    manifest = json.loads(Path(fixture["engine_manifest"]).read_text())
    (Path(manifest["engine-0"]) / "cg" / "libcg.so").write_bytes(b"changed")
    calls: list[dict[str, object]] = []
    with pytest.raises(runner.RunnerError, match="runtime identity mismatch"):
        _run(tmp_path, fixture, calls)
    assert calls == []


def test_resume_is_hash_bound_and_failed_attempt_is_permanent_veto(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    calls: list[dict[str, object]] = []

    def one_failure(task: dict[str, object]) -> dict[str, object]:
        if not calls:
            calls.append(dict(task))
            return runner._failed_row(task, "synthetic failure")
        return _fake_runner(calls)(task)

    with pytest.raises(runner.RunnerError, match="execution errors"):
        runner.run_evaluation(
            template_path=fixture["template_path"], candidate_archive=fixture["candidate"], baseline_archive=fixture["baseline"],
            population_readiness=fixture["population_readiness"],
            execution_source_manifest=fixture["execution_source_manifest"],
            opponent_manifest=fixture["opponent_manifest"], engine_manifest=fixture["engine_manifest"],
            panel_output=tmp_path / "panel.json", feature_output=tmp_path / "features.json",
            checkpoint_path=tmp_path / "panel.raw.json", workers=4, cell_runner=one_failure,
        )
    assert not (tmp_path / "panel.json").exists()

    retry_calls: list[dict[str, object]] = []
    with pytest.raises(runner.RunnerError, match="failed attempt|permanently vetoed"):
        runner.run_evaluation(
            template_path=fixture["template_path"], candidate_archive=fixture["candidate"], baseline_archive=fixture["baseline"],
            population_readiness=fixture["population_readiness"],
            execution_source_manifest=fixture["execution_source_manifest"],
            opponent_manifest=fixture["opponent_manifest"], engine_manifest=fixture["engine_manifest"],
            panel_output=tmp_path / "panel.json", feature_output=tmp_path / "features.json",
            checkpoint_path=tmp_path / "panel.raw.json", resume=True, cell_runner=_fake_runner(retry_calls),
        )
    assert retry_calls == []

def test_deterministic_final_outputs_with_fake_runner(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path / "first")
    calls: list[dict[str, object]] = []
    panel_one, features_one = _run(tmp_path / "first", fixture, calls)
    fixture_two = _fixture(tmp_path / "second")
    panel_two, features_two = _run(tmp_path / "second", fixture_two, [])

    assert panel_one == panel_two
    assert features_one == features_two
