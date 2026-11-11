from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from evaluation_v3.evidence_log import append_event
from evaluation_v3.episode_inventory import COMPLETED_STATE, PUBLIC_TYPE, sha256_file
from evaluation_v3.promotion import CLOSURE_EVENT, REGISTRATION_EVENT, compose_promotion_verdict
from tools.outcome_transfer_gate import main


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def _timestamp(index: int, *, half: bool = False) -> str:
    fraction = "500000" if half else "000000"
    return f"2026-07-01T00:00:{index:02d}.{fraction}Z"


def _game(index: int, *, outcome: float = 1.0) -> dict[str, object]:
    return {
        "game_id": str(90000000 + index),
        "submission_id": "submission-001",
        "created_at_utc": _timestamp(index),
        "ended_at_utc": _timestamp(index, half=True),
        "state": COMPLETED_STATE,
        "type": PUBLIC_TYPE,
        "module_version": "module-v3",
        "outcome": outcome,
    }


def _write_raw(path: Path, games: list[dict[str, object]]) -> None:
    fields = [
        "id",
        "createTime",
        "endTime",
        "state",
        "type",
        "submission_id",
        "module_version",
        "outcome",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for game in reversed(games):
            writer.writerow(
                {
                    "id": game["game_id"],
                    "createTime": str(game["created_at_utc"]).replace("T", " ").removesuffix("Z"),
                    "endTime": str(game["ended_at_utc"]).replace("T", " ").removesuffix("Z"),
                    "state": game["state"],
                    "type": game["type"],
                    "submission_id": game["submission_id"],
                    "module_version": game["module_version"],
                    "outcome": game["outcome"],
                }
            )


def _result(paths: dict[str, Path]) -> dict:
    return compose_promotion_verdict(
        protocol_path=paths["protocol"],
        archive_path=paths["archive"],
        transfer_path=paths["transfer"],
        candidate_path=paths["candidate"],
        safety_path=paths["safety"],
        identification_path=paths["identification"],
        holdout_path=paths["holdout"],
    )


def _check(result: dict, name: str) -> dict:
    return next(check for check in result["checks"] if check["name"] == name)


def _refresh_identification_hash(paths: dict[str, Path], field: str, target: str) -> None:
    identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
    identification[field] = sha256_file(paths[target])
    _write(paths["identification"], identification)


def _rebuild_log(
    paths: dict[str, Path],
    *,
    registration_time: str = "2026-07-01T00:00:08.500000Z",
    closure_time: str = "2026-07-01T00:00:33.000000Z",
) -> None:
    registration = json.loads(paths["registration"].read_text(encoding="utf-8"))
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    registration_hash = sha256_file(paths["registration"])
    chronology_hash = sha256_file(paths["chronology"])
    paths["log"].unlink(missing_ok=True)
    append_event(
        paths["log"],
        log_id="v3-evidence-log",
        event_id="register-unit-v3-001",
        event_type=REGISTRATION_EVENT,
        created_at_utc=registration_time,
        payload={
            "unit_id": registration["unit_id"],
            "registration_manifest_sha256": registration_hash,
            "setup_game_ids": registration["setup_game_ids"],
        },
    )
    closed = append_event(
        paths["log"],
        log_id="v3-evidence-log",
        event_id="close-unit-v3-001",
        event_type=CLOSURE_EVENT,
        created_at_utc=closure_time,
        payload={
            "unit_id": chronology["unit_id"],
            "chronology_sha256": chronology_hash,
            "followup_game_ids": [game["game_id"] for game in chronology["followup_games"]],
        },
    )
    identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
    identification.update(
        {
            "registration_manifest_sha256": registration_hash,
            "chronology_manifest_sha256": chronology_hash,
            "prospective_evidence_log_sha256": sha256_file(paths["log"]),
            "expected_head_event_sha256": closed["event_sha256"],
            "expected_event_count": 2,
        }
    )
    _write(paths["identification"], identification)


def _artifacts(tmp_path: Path) -> dict[str, Path]:
    archive = tmp_path / "submission-codex-v999.tar.gz"
    archive.write_bytes(b"candidate archive")
    archive_hash = sha256_file(archive)
    protocol = _write(
        tmp_path / "protocol.json",
        {
            "schema": "outcome_transfer_protocol_v3",
            "protocol_id": "outcome-v3-unit",
            "evaluator_sha256": "e" * 64,
            "candidate_archive_sha256": archive_hash,
            "sealed_holdout_id": "sealed-v3-50",
            "retirement_cutoff_utc": "2026-06-30T23:59:00.000000Z",
            "frozen_at_utc": "2026-07-01T00:00:00.000000Z",
            "identification_thresholds": {
                "residual_min": 0.5,
                "logloss_lift_min": 0.5,
                "bootstrap_q10_min": 0.5,
                "bootstrap_probability_min": 0.95,
                "bootstrap_samples": 200,
                "seed": 20260711,
            },
            "state": "FROZEN",
        },
    )
    protocol_hash = sha256_file(protocol)
    common = {"protocol_sha256": protocol_hash, "evaluator_sha256": "e" * 64}
    transfer = _write(
        tmp_path / "transfer.json",
        {
            "schema": "public_transfer_validation_v2",
            **common,
            "panel_id": "future-outcomes-v3",
            "certified": True,
        },
    )
    candidate = _write(
        tmp_path / "candidate.json",
        {
            "schema": "candidate_matched_outcome_v2",
            **common,
            "archive_sha256": archive_hash,
            "candidate_label": "codex-v999-intervention",
            "passed": True,
        },
    )
    safety = _write(
        tmp_path / "safety.json",
        {
            "schema": "candidate_safety_burnin_v2",
            **common,
            "archive_sha256": archive_hash,
            "passed": True,
        },
    )
    holdout = _write(
        tmp_path / "holdout.json",
        {
            "schema": "sealed_holdout_verdict_v2",
            **common,
            "archive_sha256": archive_hash,
            "sealed_holdout_id": "sealed-v3-50",
            "episodes": 50,
            "passed": True,
        },
    )
    games = [_game(index) for index in range(1, 33)]
    raw = tmp_path / "episodes.csv"
    _write_raw(raw, games)
    registration = _write(
        tmp_path / "registration.json",
        {
            "schema": "candidate_public_intervention_registration_v1",
            "unit_id": "unit-v3-001",
            **common,
            "archive_sha256": archive_hash,
            "submission_id": "submission-001",
            "setup_game_ids": [game["game_id"] for game in games[:8]],
            "registered_at_utc": "2026-07-01T00:00:08.500000Z",
            "nuisance_probability": 0.4,
            "candidate_probability": 0.8,
        },
    )
    chronology = _write(
        tmp_path / "chronology.json",
        {
            "schema": "candidate_public_intervention_chronology_v1",
            "unit_id": "unit-v3-001",
            **common,
            "archive_sha256": archive_hash,
            "registration_manifest_sha256": sha256_file(registration),
            "submission_id": "submission-001",
            "source_episodes_path": raw.name,
            "source_episodes_sha256": sha256_file(raw),
            "setup_games": games[:8],
            "followup_games": games[8:],
        },
    )
    identification = _write(
        tmp_path / "identification.json",
        {
            "schema": "candidate_identifiability_validation_v1",
            **common,
            "archive_sha256": archive_hash,
            "route": "candidate_public_intervention",
            "passed": True,
            "checks": [{"name": "candidate_public_residual", "passed": True}],
            "registration_manifest_path": registration.name,
            "registration_manifest_sha256": sha256_file(registration),
            "chronology_manifest_path": chronology.name,
            "chronology_manifest_sha256": sha256_file(chronology),
            "prospective_evidence_log_path": "evidence.jsonl",
            "prospective_evidence_log_sha256": "0" * 64,
            "log_id": "v3-evidence-log",
            "expected_head_event_sha256": "0" * 64,
            "expected_event_count": 2,
        },
    )
    paths = {
        "archive": archive,
        "protocol": protocol,
        "transfer": transfer,
        "candidate": candidate,
        "safety": safety,
        "identification": identification,
        "holdout": holdout,
        "registration": registration,
        "chronology": chronology,
        "raw": raw,
        "log": tmp_path / "evidence.jsonl",
    }
    _rebuild_log(paths)
    return paths


def test_local_only_intervention_evidence_is_permanently_closed(tmp_path: Path) -> None:
    result = _result(_artifacts(tmp_path))

    assert result["decision"] == "CLOSED"
    assert result["identification_metrics"] is None
    assert result["identification_route_status"] == "PERMANENTLY_CLOSED"
    assert result["intervention_already_exists"] is False
    assert result["externally_verified_submission_id"] is None
    assert not _check(result, "identification_route")["passed"]
    assert not _check(result, "external_registration_anchor")["passed"]
    assert not _check(result, "frozen_prediction_recomputation")["passed"]
    assert not _check(result, "intervention_already_exists")["passed"]


def test_gate_receipt_is_create_once(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    output = tmp_path / "verdict.json"
    arguments = [
        "--protocol", str(paths["protocol"]), "--archive", str(paths["archive"]),
        "--transfer", str(paths["transfer"]), "--candidate", str(paths["candidate"]),
        "--safety", str(paths["safety"]), "--identification", str(paths["identification"]),
        "--holdout", str(paths["holdout"]), "--output", str(output),
    ]

    assert main(arguments) == 1
    original = output.read_bytes()
    assert main(arguments) == 2
    assert output.read_bytes() == original


@pytest.mark.parametrize(
    ("artifact", "legacy_schema"),
    [
        ("transfer", "public_transfer_validation_v1"),
        ("candidate", "candidate_matched_outcome_v1"),
        ("safety", "candidate_safety_burnin_v1"),
        ("holdout", "sealed_holdout_verdict_v1"),
    ],
)
def test_legacy_v1_promotion_artifacts_close(tmp_path: Path, artifact: str, legacy_schema: str) -> None:
    paths = _artifacts(tmp_path)
    value = json.loads(paths[artifact].read_text(encoding="utf-8"))
    value["schema"] = legacy_schema
    _write(paths[artifact], value)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert not _check(result, f"{artifact}_schema")["passed"]


def test_old_forged_shadow_cannot_open_or_be_supplied(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    _write(paths["identification"], {"schema": "prospective_shadow_validation_v1", "certified": True})
    assert _result(paths)["decision"] == "CLOSED"

    with pytest.raises(SystemExit) as error:
        main(
            [
                "--protocol", str(paths["protocol"]), "--archive", str(paths["archive"]),
                "--transfer", str(paths["transfer"]), "--candidate", str(paths["candidate"]),
                "--safety", str(paths["safety"]), "--identification", str(paths["identification"]),
                "--holdout", str(paths["holdout"]), "--output", str(tmp_path / "verdict.json"),
                "--prospective-shadow", str(tmp_path / "forged.json"),
            ]
        )
    assert error.value.code == 2


def test_future_ids_in_registration_close_even_when_reference_hash_is_updated(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    registration = json.loads(paths["registration"].read_text(encoding="utf-8"))
    registration["followup_game_ids"] = [str(90000000 + index) for index in range(9, 33)]
    _write(paths["registration"], registration)
    _refresh_identification_hash(paths, "registration_manifest_sha256", "registration")

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert not _check(result, "registration_manifest")["passed"]
    assert "fields must exactly" in _check(result, "registration_manifest")["detail"]


def test_skipped_raw_episode_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    games = [_game(index) for index in range(1, 34) if index != 10]
    _write_raw(paths["raw"], games)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    chronology["source_episodes_sha256"] = sha256_file(paths["raw"])
    _write(paths["chronology"], chronology)
    _rebuild_log(paths)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert not _check(result, "raw_episode_chronology")["passed"]
    assert "first 32" in _check(result, "raw_episode_chronology")["detail"]


def test_pending_or_failed_raw_episode_in_horizon_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    games = [_game(index) for index in range(1, 33)]
    games[9]["state"] = "EpisodeState.PENDING"
    games[9]["ended_at_utc"] = ""
    _write_raw(paths["raw"], games)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    chronology["source_episodes_sha256"] = sha256_file(paths["raw"])
    _write(paths["chronology"], chronology)
    _rebuild_log(paths)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert "pending/failed" in _check(result, "raw_episode_chronology")["detail"]


def test_self_reported_passed_with_failing_raw_outcomes_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    for game in chronology["followup_games"]:
        game["outcome"] = 0.0
    all_games = chronology["setup_games"] + chronology["followup_games"]
    _write_raw(paths["raw"], all_games)
    chronology["source_episodes_sha256"] = sha256_file(paths["raw"])
    _write(paths["chronology"], chronology)
    identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
    identification["passed"] = True
    identification["checks"] = [{"name": "candidate_public_residual", "passed": True}]
    _write(paths["identification"], identification)
    _rebuild_log(paths)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert result["identification_metrics"] is None
    assert not _check(result, "frozen_prediction_recomputation")["passed"]


def test_injected_extreme_probabilities_cannot_open_route(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    registration = json.loads(paths["registration"].read_text(encoding="utf-8"))
    registration["nuisance_probability"] = 0.01
    registration["candidate_probability"] = 0.99
    _write(paths["registration"], registration)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    chronology["registration_manifest_sha256"] = sha256_file(paths["registration"])
    _write(paths["chronology"], chronology)
    _rebuild_log(paths)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert result["submit_open"] is False
    assert result["identification_metrics"] is None
    assert not _check(result, "frozen_prediction_recomputation")["passed"]


def test_handwritten_external_anchor_and_existing_submission_claims_cannot_open(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
    identification.update(
        {
            "external_anchor_verified": True,
            "external_anchor_timestamp_utc": "2026-07-01T00:00:08.500000Z",
            "intervention_already_exists": True,
            "externally_verified_submission_id": "submission-001",
            "predictor_recomputed": True,
        }
    )
    _write(paths["identification"], identification)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert result["intervention_already_exists"] is False
    assert result["externally_verified_submission_id"] is None
    assert not _check(result, "external_registration_anchor")["passed"]


@pytest.mark.parametrize(
    ("registration_time", "closure_time", "message"),
    [
        ("2026-07-01T00:00:08.400000Z", "2026-07-01T00:00:33.000000Z", "must equal"),
        ("2026-07-01T00:00:08.500000Z", "2026-07-01T00:00:20.000000Z", "last follow-up"),
    ],
)
def test_wrong_event_times_close(
    tmp_path: Path,
    registration_time: str,
    closure_time: str,
    message: str,
) -> None:
    paths = _artifacts(tmp_path)
    _rebuild_log(paths, registration_time=registration_time, closure_time=closure_time)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert message in _check(result, "intervention_log_events")["detail"]


def test_extra_or_other_unit_event_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
    appended = append_event(
        paths["log"],
        log_id="v3-evidence-log",
        event_id="orphan-unit",
        event_type="unrelated",
        created_at_utc="2026-07-01T00:00:34.000000Z",
        payload={"unit_id": "other-unit"},
    )
    identification.update(
        {
            "prospective_evidence_log_sha256": sha256_file(paths["log"]),
            "expected_head_event_sha256": appended["event_sha256"],
            "expected_event_count": 3,
        }
    )
    _write(paths["identification"], identification)

    result = _result(paths)

    assert result["decision"] == "CLOSED"
    assert not _check(result, "prospective_evidence_log")["passed"]


def test_log_mutation_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    paths["log"].write_text(
        paths["log"].read_text(encoding="ascii").replace("90000001", "tampered", 1),
        encoding="ascii",
    )
    assert _result(paths)["decision"] == "CLOSED"


def test_cross_artifact_hash_mismatch_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    candidate = json.loads(paths["candidate"].read_text(encoding="utf-8"))
    candidate["protocol_sha256"] = "0" * 64
    _write(paths["candidate"], candidate)
    result = _result(paths)
    assert result["decision"] == "CLOSED"
    assert not _check(result, "candidate_binding")["passed"]


def test_chronology_gap_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    chronology["followup_games"].pop()
    _write(paths["chronology"], chronology)
    _rebuild_log(paths)
    result = _result(paths)
    assert result["decision"] == "CLOSED"
    assert not _check(result, "intervention_chronology")["passed"]


def test_backdated_registration_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    registration = json.loads(paths["registration"].read_text(encoding="utf-8"))
    registration["registered_at_utc"] = "2026-07-01T00:00:02.000000Z"
    _write(paths["registration"], registration)
    chronology = json.loads(paths["chronology"].read_text(encoding="utf-8"))
    chronology["registration_manifest_sha256"] = sha256_file(paths["registration"])
    _write(paths["chronology"], chronology)
    _rebuild_log(paths, registration_time="2026-07-01T00:00:02.000000Z")
    result = _result(paths)
    assert result["decision"] == "CLOSED"
    assert not _check(result, "intervention_chronology")["passed"]


def test_wrong_archive_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    paths["archive"].write_bytes(b"different archive")
    result = _result(paths)
    assert result["decision"] == "CLOSED"
    assert not _check(result, "protocol_archive_identity")["passed"]


def test_unsupported_or_unknown_identification_route_closes(tmp_path: Path) -> None:
    for route in ("public_equivalent_counterfactual_oracle", "invented_route"):
        route_dir = tmp_path / route
        route_dir.mkdir()
        paths = _artifacts(route_dir)
        identification = json.loads(paths["identification"].read_text(encoding="utf-8"))
        identification["route"] = route
        _write(paths["identification"], identification)
        result = _result(paths)
        assert result["decision"] == "CLOSED"
        assert not _check(result, "identification_route")["passed"]


def test_final_name_closes(tmp_path: Path) -> None:
    paths = _artifacts(tmp_path)
    final_archive = tmp_path / "submission-codex-final-v999.tar.gz"
    final_archive.write_bytes(paths["archive"].read_bytes())
    paths["archive"] = final_archive
    result = _result(paths)
    assert result["decision"] == "CLOSED"
    assert not _check(result, "naming")["passed"]
