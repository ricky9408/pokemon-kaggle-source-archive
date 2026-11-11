from __future__ import annotations

import copy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v4.predictor import build_simulation_feature
from evaluation_v4_1.authorization import (
    AuthorizationError,
    build_authorization,
    guard_research_submission,
)
from evaluation_v4_1.chronology import (
    ChronologyError,
    build_literal_first24_horizon,
    build_pair_completion_barrier,
    build_submission_receipt,
    validate_literal_first24_horizon,
    validate_pair_completion_barrier,
    validate_submission_receipt,
)
from evaluation_v4_1.prediction import build_prediction_bundle
from evaluation_v4_1.protocol import build_pair_assignment, build_population_manifest
from evaluation_v4_1.runtime import build_kaggle_runtime_binding
from tests.test_evaluation_v4_1_prediction import _artifacts, _records


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fixture(tmp_path: Path) -> dict[str, object]:
    protocol, initial_population, initial_assignment, model, initial_features = _artifacts()
    pair_uuids = list(initial_assignment["pairs"][0]["slot_order"])
    archive_bytes_by_uuid = {
        pair_uuids[0]: b"exact research archive bytes slot one\n",
        pair_uuids[1]: b"exact research archive bytes slot two\n",
    }
    records = _records()
    for lineage_uuid, archive_bytes in archive_bytes_by_uuid.items():
        next(record for record in records if record["lineage_uuid"] == lineage_uuid)[
            "archive_sha256"
        ] = hashlib.sha256(archive_bytes).hexdigest()
    population = build_population_manifest(protocol, records)
    assignment = build_pair_assignment(protocol, population, "4" * 64, "nist-chain-2-pulse-1")
    assert assignment["pairs"][0]["slot_order"] == pair_uuids
    population_by_uuid = {record["lineage_uuid"]: record for record in population["records"]}
    features = {}
    for lineage_uuid in assignment["selected_lineage_uuids"]:
        original = copy.deepcopy(initial_features[lineage_uuid])
        original.pop("content_sha256")
        original["candidate_archive_sha256"] = population_by_uuid[lineage_uuid]["archive_sha256"]
        features[lineage_uuid] = build_simulation_feature(original)
    bundle = build_prediction_bundle(
        protocol=protocol,
        population_manifest=population,
        pair_assignment=assignment,
        predictor_model=model,
        features_by_lineage_uuid=features,
        created_at_utc="2026-07-11T09:00:00.000000Z",
    )
    artifacts = {
        "protocol": protocol,
        "population_manifest": population,
        "pair_assignment": assignment,
        "prediction_bundle": bundle,
        "predictor_model": model,
        "kaggle_runtime_binding": build_kaggle_runtime_binding(
            Path(__file__).resolve().parents[1]
        ),
    }
    names = {
        lineage_uuid: f"submission-codex-voi-{index:02d}.tar.gz"
        for index, lineage_uuid in enumerate(assignment["selected_lineage_uuids"], start=1)
    }
    ledger = tmp_path / "usage.jsonl"
    authorization = build_authorization(
        **artifacts,
        usage_ledger_path=ledger,
        archive_names_by_lineage_uuid=names,
        authorization_id="voi-p5-chronology-test",
        explicit_user_override_text_sha256=hashlib.sha256(b"override").hexdigest(),
        created_at_utc="2026-07-11T09:01:00.000000Z",
        expires_at_utc="2026-07-12T09:01:00.000000Z",
    )
    archives: dict[str, Path] = {}
    permits: dict[str, dict[str, object]] = {}
    for index, lineage_uuid in enumerate(pair_uuids):
        row = next(
            item
            for item in authorization["archive_assignments"]
            if item["lineage_uuid"] == lineage_uuid
        )
        archive = tmp_path / row["archive_name"]
        archive.write_bytes(archive_bytes_by_uuid[lineage_uuid])
        archives[lineage_uuid] = archive
        permits[lineage_uuid] = guard_research_submission(
            authorization,
            ledger,
            artifacts=artifacts,
            **row,
            now=f"2026-07-11T09:02:{index:02d}.000000Z",
        )
    submissions = tmp_path / "submissions.csv"
    rows_by_uuid: dict[str, dict[str, str]] = {}
    with submissions.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ref", "fileName", "date", "description", "status", "publicScore", "privateScore"],
        )
        writer.writeheader()
        for index, lineage_uuid in enumerate(pair_uuids):
            row = {
                "ref": str(12345 + index),
                "fileName": archives[lineage_uuid].name,
                "date": f"2026-07-11 09:03:{index * 10:02d}.000000",
                "description": f"codex-voi-research-{index + 1:02d}",
                "status": "SubmissionStatus.COMPLETE",
                "publicScore": "600.0",
                "privateScore": "",
            }
            writer.writerow(row)
            rows_by_uuid[lineage_uuid] = row

    receipts: dict[str, dict[str, object]] = {}
    directories: dict[str, Path] = {}
    start = datetime(2026, 7, 11, 9, 4, tzinfo=timezone.utc)
    pair_evidence: dict[str, dict[str, object]] = {}
    for member_index, lineage_uuid in enumerate(pair_uuids):
        row = rows_by_uuid[lineage_uuid]
        receipt = build_submission_receipt(
            authorization=authorization,
            permit=permits[lineage_uuid],
            usage_ledger_path=ledger,
            artifacts=artifacts,
            authenticated_submissions_csv=submissions,
            local_archive=archives[lineage_uuid],
            submission_ref=row["ref"],
            expected_description=row["description"],
            first_observed_complete_at_utc="2026-07-11T09:30:00.000000Z",
        )
        receipts[lineage_uuid] = receipt
        directory = tmp_path / f"submission_{row['ref']}"
        directory.mkdir()
        directories[lineage_uuid] = directory
        with (directory / "episodes.csv").open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["id", "createTime", "endTime", "state", "type"])
            writer.writeheader()
            for index in reversed(range(25)):
                created = start + timedelta(minutes=index)
                ended = created + timedelta(seconds=30)
                game_id = str((1000 + member_index * 1000) + index)
                writer.writerow(
                    {
                        "id": game_id,
                        "createTime": created.strftime("%Y-%m-%d %H:%M:%S.%f"),
                        "endTime": ended.strftime("%Y-%m-%d %H:%M:%S.%f"),
                        "state": "EpisodeState.COMPLETED",
                        "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
                    }
                )
                replay = {
                    "id": f"replay-{game_id}",
                    "module_version": "1.32.0",
                    "info": {
                        "EpisodeId": int(game_id),
                        "TeamNames": ["GarlicToday", f"Opponent-{index}"],
                    },
                    "steps": [
                        [{}, {}],
                        [
                            {"reward": 1 if index % 3 else 0, "status": "DONE"},
                            {"reward": -1 if index % 3 else 0, "status": "DONE"},
                        ],
                    ],
                }
                (directory / f"episode-{game_id}-replay.json").write_text(
                    json.dumps(replay), encoding="utf-8"
                )
        pair_evidence[lineage_uuid] = {
            "permit": permits[lineage_uuid],
            "submission_receipt": receipt,
            "authenticated_submissions_csv": submissions,
            "local_archive": archives[lineage_uuid],
            "submission_directory": directory,
            "team_name": "GarlicToday",
        }

    first_uuid = pair_uuids[0]
    return {
        "authorization": authorization,
        "artifacts": artifacts,
        "ledger": ledger,
        "permit": permits[first_uuid],
        "submissions": submissions,
        "archive": archives[first_uuid],
        "submission_receipt": receipts[first_uuid],
        "directory": directories[first_uuid],
        "pair_id": assignment["pairs"][0]["pair_id"],
        "pair_evidence": pair_evidence,
    }


def _horizon_kwargs(fixture: dict[str, object]) -> dict[str, object]:
    return {
        "authorization": fixture["authorization"],
        "permit": fixture["permit"],
        "usage_ledger_path": fixture["ledger"],
        "artifacts": fixture["artifacts"],
        "submission_receipt": fixture["submission_receipt"],
        "authenticated_submissions_csv": fixture["submissions"],
        "local_archive": fixture["archive"],
        "submission_directory": fixture["directory"],
        "team_name": "GarlicToday",
    }


def _barrier_kwargs(fixture: dict[str, object]) -> dict[str, object]:
    return {
        "authorization": fixture["authorization"],
        "pair_id": fixture["pair_id"],
        "usage_ledger_path": fixture["ledger"],
        "artifacts": fixture["artifacts"],
        "member_evidence_by_lineage_uuid": fixture["pair_evidence"],
    }


def test_submission_receipt_rebuilds_authenticated_row_and_archive(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    assert validate_submission_receipt(
        fixture["submission_receipt"],
        authorization=fixture["authorization"],
        permit=fixture["permit"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
        authenticated_submissions_csv=fixture["submissions"],
        local_archive=fixture["archive"],
    ) == fixture["submission_receipt"]
    changed = copy.deepcopy(fixture["submission_receipt"])
    changed["submission_ref"] = "99999"
    with pytest.raises(ChronologyError):
        validate_submission_receipt(
            changed,
            authorization=fixture["authorization"],
            permit=fixture["permit"],
            usage_ledger_path=fixture["ledger"],
            artifacts=fixture["artifacts"],
            authenticated_submissions_csv=fixture["submissions"],
            local_archive=fixture["archive"],
        )


def test_literal_horizon_uses_first_24_and_excludes_no_setup_games(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    horizon = build_literal_first24_horizon(**_horizon_kwargs(fixture))
    assert horizon["horizon_games"] == 24
    assert horizon["setup_games_excluded"] == 0
    assert [game["game_id"] for game in horizon["games"]] == [str(1000 + index) for index in range(24)]
    assert "1024" not in [game["game_id"] for game in horizon["games"]]
    assert len(horizon["outcomes"]) == 24
    assert horizon["production_submission_authorized"] is False


def test_outcome_summary_mutation_cannot_survive_raw_rebuild(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    kwargs = _horizon_kwargs(fixture)
    horizon = build_literal_first24_horizon(**kwargs)
    changed = copy.deepcopy(horizon)
    changed["outcomes"][0] = 0.0 if changed["outcomes"][0] != 0.0 else 1.0
    with pytest.raises(ChronologyError, match="raw-data rebuild"):
        validate_literal_first24_horizon(changed, **kwargs)


@pytest.mark.parametrize("mutation", ["pending", "own-v-own", "mixed-module", "missing-replay"])
def test_pending_interference_module_drift_and_missing_replays_fail_closed(
    tmp_path: Path, mutation: str
) -> None:
    fixture = _fixture(tmp_path)
    directory = fixture["directory"]
    if mutation == "pending":
        rows = list(csv.DictReader((directory / "episodes.csv").open()))
        rows[-1]["state"] = "EpisodeState.PENDING"
        with (directory / "episodes.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    elif mutation == "own-v-own":
        path = directory / "episode-1000-replay.json"
        replay = json.loads(path.read_text())
        replay["info"]["TeamNames"] = ["GarlicToday", "GarlicToday"]
        path.write_text(json.dumps(replay))
    elif mutation == "mixed-module":
        path = directory / "episode-1000-replay.json"
        replay = json.loads(path.read_text())
        replay["module_version"] = "1.33.0"
        path.write_text(json.dumps(replay))
    else:
        (directory / "episode-1000-replay.json").unlink()
    with pytest.raises(ChronologyError):
        build_literal_first24_horizon(**_horizon_kwargs(fixture))


def test_local_archive_byte_mutation_fails_before_horizon(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    fixture["archive"].write_bytes(b"mutated")
    with pytest.raises(ChronologyError, match="archive SHA-256"):
        build_literal_first24_horizon(**_horizon_kwargs(fixture))


def test_pair_completion_barrier_rebuilds_both_exact_horizons(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    barrier = build_pair_completion_barrier(**_barrier_kwargs(fixture))
    assert barrier["horizon_games_per_member"] == 24
    assert len(barrier["members"]) == 2
    assert barrier["prior_pair_barrier_content_sha256"] is None
    assert barrier["latest_two_exposure_complete_at_utc"] == "2026-07-11T09:03:10.000000Z"
    assert barrier["horizon_started_at_utc"] == "2026-07-11T09:04:00.000000Z"
    assert validate_pair_completion_barrier(
        barrier,
        **_barrier_kwargs(fixture),
    ) == barrier


def test_pair_barrier_rejects_games_before_second_member_exposure(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first_evidence = next(iter(fixture["pair_evidence"].values()))
    episodes = first_evidence["submission_directory"] / "episodes.csv"
    rows = list(csv.DictReader(episodes.open()))
    rows[-1]["createTime"] = "2026-07-11 09:03:05.000000"
    rows[-1]["endTime"] = "2026-07-11 09:03:35.000000"
    with episodes.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ChronologyError, match="before both members"):
        build_pair_completion_barrier(**_barrier_kwargs(fixture))


def test_pair_barrier_rejects_submission_that_displaces_latest_two_mid_horizon(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    submissions = fixture["submissions"]
    rows = list(csv.DictReader(submissions.open()))
    rows.append(
        {
            "ref": "99999",
            "fileName": "submission-codex-unrelated-v999.tar.gz",
            "date": "2026-07-11 09:10:00.000000",
            "description": "codex-unrelated-v999",
            "status": "SubmissionStatus.COMPLETE",
            "publicScore": "600.0",
            "privateScore": "",
        }
    )
    with submissions.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    for evidence in fixture["pair_evidence"].values():
        old = evidence["submission_receipt"]
        evidence["submission_receipt"] = build_submission_receipt(
            authorization=fixture["authorization"],
            permit=evidence["permit"],
            usage_ledger_path=fixture["ledger"],
            artifacts=fixture["artifacts"],
            authenticated_submissions_csv=submissions,
            local_archive=evidence["local_archive"],
            submission_ref=old["submission_ref"],
            expected_description=old["submission_description"],
            first_observed_complete_at_utc=old["first_observed_complete_at_utc"],
        )
    with pytest.raises(ChronologyError, match="displaced the pair"):
        build_pair_completion_barrier(**_barrier_kwargs(fixture))


def test_later_pair_permit_requires_validated_completed_prior_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    barrier = build_pair_completion_barrier(**_barrier_kwargs(fixture))
    next_row = fixture["authorization"]["archive_assignments"][2]
    with pytest.raises(AuthorizationError, match="authenticated prior pair capture"):
        guard_research_submission(
            fixture["authorization"],
            fixture["ledger"],
            artifacts=fixture["artifacts"],
            **next_row,
            now="2026-07-11T09:28:00.000000Z",
        )
    def validate_capture(value: object, **_: object) -> object:
        validate_pair_completion_barrier(
            value["pair_completion_barrier"],
            **_barrier_kwargs(fixture),
        )
        return value

    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.reverify_authenticated_pair_capture_online",
        validate_capture,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    with pytest.raises(AuthorizationError, match="precedes prior pair"):
        guard_research_submission(
            fixture["authorization"],
            fixture["ledger"],
            artifacts=fixture["artifacts"],
            **next_row,
            now=barrier["horizon_completed_at_utc"],
            prior_pair_capture={"pair_id": fixture["pair_id"], "pair_completion_barrier": barrier},
        )
    permit = guard_research_submission(
        fixture["authorization"],
        fixture["ledger"],
        artifacts=fixture["artifacts"],
        **next_row,
        now="2026-07-11T09:28:00.000000Z",
        prior_pair_capture={"pair_id": fixture["pair_id"], "pair_completion_barrier": barrier},
    )
    assert permit["prior_pair_barrier_content_sha256"] == barrier["content_sha256"]


def test_pair_barrier_tamper_cannot_authorize_next_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    barrier = build_pair_completion_barrier(**_barrier_kwargs(fixture))
    changed = copy.deepcopy(barrier)
    changed["horizon_completed_at_utc"] = "2026-07-11T09:04:00.000000Z"
    def validate_capture(value: object, **_: object) -> object:
        validate_pair_completion_barrier(
            value["pair_completion_barrier"],
            **_barrier_kwargs(fixture),
        )
        return value

    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.reverify_authenticated_pair_capture_online",
        validate_capture,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    with pytest.raises(AuthorizationError, match="capture is invalid"):
        guard_research_submission(
            fixture["authorization"],
            fixture["ledger"],
            artifacts=fixture["artifacts"],
            **fixture["authorization"]["archive_assignments"][2],
            now="2026-07-11T09:28:00.000000Z",
            prior_pair_capture={"pair_id": fixture["pair_id"], "pair_completion_barrier": changed},
        )
