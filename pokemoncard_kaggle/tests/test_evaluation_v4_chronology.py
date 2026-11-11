from __future__ import annotations

import csv
from dataclasses import asdict
import json
from pathlib import Path

import pytest

from evaluation_v4.chronology import build_literal_horizon, write_horizon_create_once
from evaluation_v4.evidence import PredictionRegistration


def _registration() -> PredictionRegistration:
    return PredictionRegistration.from_mapping(
        {
            "schema": "whole_policy_prediction_registration_v1",
            "unit_id": "unit-001",
            "protocol_sha256": "a" * 64,
            "lineage_manifest_sha256": "d" * 64,
            "selector_code_sha256": "b" * 64,
            "archive_sha256": "c" * 64,
            "archive_name": "submission-codex-selector-v999.tar.gz",
            "team_name": "GarlicToday",
            "lineage_id": "lineage-001",
            "ancestry_id": "ancestry-001",
            "family_id": "family-a",
            "block_id": "block-1",
            "frozen_at_utc": "2026-07-11T00:00:00.000000Z",
            "nuisance_probability": 0.4,
            "selector_probability": 0.6,
            "simulator_delta": 0.12,
            "ood_mass": 0.04,
            "engine_variant_means": {"sample": 0.1, "source": 0.08},
        }
    )


def _anchor() -> dict:
    return {
        "schema": "kaggle_prediction_anchor_receipt_v1",
        "anchor_verified": True,
        "registration_sha256": "d" * 64,
        "submission_ref": "12345",
        "submission_date_utc": "2026-07-11T00:01:00.000000Z",
    }


def _fixture(tmp_path: Path, *, count: int = 32) -> Path:
    directory = tmp_path / "submission_12345"
    directory.mkdir()
    with (directory / "episodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "createTime", "endTime", "state", "type"])
        writer.writeheader()
        for index in reversed(range(count)):
            game_id = str(1000 + index)
            minute = index + 2
            writer.writerow(
                {
                    "id": game_id,
                    "createTime": f"2026-07-11 00:{minute:02d}:00.000000",
                    "endTime": f"2026-07-11 00:{minute:02d}:30.000000",
                    "state": "EpisodeState.COMPLETED",
                    "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
                }
            )
            slot = index % 2
            rewards = [1, -1] if slot == 0 else [-1, 1]
            replay = {
                "id": int(game_id),
                "module_version": "1.32.0",
                "info": {"TeamNames": ["GarlicToday", "Other"] if slot == 0 else ["Other", "GarlicToday"]},
                "steps": [[{}, {}], [{"reward": rewards[0], "status": "DONE"}, {"reward": rewards[1], "status": "DONE"}]],
            }
            (directory / f"episode-{game_id}-replay.json").write_text(json.dumps(replay), encoding="utf-8")
    return directory


def test_builds_literal_first_eight_plus_next_twenty_four(tmp_path: Path) -> None:
    directory = _fixture(tmp_path)

    result = build_literal_horizon(_registration(), _anchor(), directory)

    assert result["setup_game_ids"] == [str(1000 + index) for index in range(8)]
    assert [game["game_id"] for game in result["followup_games"]] == [str(1000 + index) for index in range(8, 32)]
    assert result["outcomes"] == [1.0] * 24
    assert result["first_submission_authorized"] is False


def test_missing_or_skipped_game_fails_closed(tmp_path: Path) -> None:
    directory = _fixture(tmp_path, count=31)
    with pytest.raises(ValueError, match="32 required"):
        build_literal_horizon(_registration(), _anchor(), directory)


def test_pending_game_inside_horizon_fails_closed(tmp_path: Path) -> None:
    directory = _fixture(tmp_path)
    rows = list(csv.DictReader((directory / "episodes.csv").open()))
    rows[-10]["state"] = "EpisodeState.PENDING"
    with (directory / "episodes.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(ValueError, match="non-completed"):
        build_literal_horizon(_registration(), _anchor(), directory)


def test_wrong_team_or_submission_directory_fails_closed(tmp_path: Path) -> None:
    directory = _fixture(tmp_path)
    replay = directory / "episode-1000-replay.json"
    value = json.loads(replay.read_text())
    value["info"]["TeamNames"] = ["Other", "Someone"]
    replay.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="does not contain team"):
        build_literal_horizon(_registration(), _anchor(), directory)

    wrong = tmp_path / "submission_99999"
    directory.rename(wrong)
    with pytest.raises(ValueError, match="submission_ref"):
        build_literal_horizon(_registration(), _anchor(), wrong)


def test_mixed_module_versions_fail_closed(tmp_path: Path) -> None:
    directory = _fixture(tmp_path)
    replay = directory / "episode-1031-replay.json"
    value = json.loads(replay.read_text())
    value["module_version"] = "1.33.0"
    replay.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="crosses module"):
        build_literal_horizon(_registration(), _anchor(), directory)


def test_horizon_receipt_is_create_once(tmp_path: Path) -> None:
    horizon = build_literal_horizon(_registration(), _anchor(), _fixture(tmp_path))
    output = tmp_path / "horizon.json"
    write_horizon_create_once(output, horizon)
    with pytest.raises(FileExistsError):
        write_horizon_create_once(output, horizon)
