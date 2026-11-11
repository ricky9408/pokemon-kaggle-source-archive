from __future__ import annotations

from dataclasses import asdict, replace
import csv
import json
from pathlib import Path

import pytest

from evaluation_v4.evidence import (
    PredictionRegistration,
    load_registration,
    sha256_file,
    verify_kaggle_submission_anchor,
    write_registration_create_once,
)


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


def _write_csv(path: Path, registration: PredictionRegistration, registration_sha256: str, *, status: str = "SubmissionStatus.COMPLETE", description: str | None = None) -> None:
    fields = ["ref", "fileName", "date", "description", "status", "publicScore"]
    value = description or (
        f"codex-v999 reg-sha256={registration_sha256} "
        f"archive-sha256={registration.archive_sha256}"
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "ref": "12345",
                "fileName": registration.archive_name,
                "date": "2026-07-11 00:01:00.000000",
                "description": value,
                "status": status,
                "publicScore": "600.0",
            }
        )


def test_external_anchor_commits_registration_but_not_server_archive_bytes(tmp_path: Path) -> None:
    registration_path = tmp_path / "registration.json"
    write_registration_create_once(registration_path, _registration())
    submissions = tmp_path / "submissions.csv"
    _write_csv(submissions, _registration(), sha256_file(registration_path))

    receipt = verify_kaggle_submission_anchor(registration_path, submissions)

    assert receipt["anchor_verified"] is True
    assert receipt["scope"] == "post_submission_calibration_only"
    assert receipt["archive_bytes_server_verified"] is False
    assert receipt["first_submission_authorized"] is False
    assert receipt["submission_ref"] == "12345"


def test_registration_is_create_once_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "registration.json"
    registration = _registration()
    write_registration_create_once(path, registration)

    assert load_registration(path) == registration
    with pytest.raises(FileExistsError):
        write_registration_create_once(path, registration)


@pytest.mark.parametrize("field", ["outcomes", "followup_game_ids", "submission_ref"])
def test_registration_rejects_future_or_postsubmission_fields(field: str) -> None:
    value = asdict(_registration())
    value[field] = [] if field != "submission_ref" else "12345"

    with pytest.raises(ValueError, match="fields must exactly"):
        PredictionRegistration.from_mapping(value)


def test_anchor_rejects_missing_archive_commitment(tmp_path: Path) -> None:
    path = tmp_path / "registration.json"
    registration = _registration()
    write_registration_create_once(path, registration)
    submissions = tmp_path / "submissions.csv"
    _write_csv(
        submissions,
        registration,
        sha256_file(path),
        description=f"reg-sha256={sha256_file(path)}",
    )

    with pytest.raises(ValueError, match="does not bind archive"):
        verify_kaggle_submission_anchor(path, submissions)


def test_anchor_rejects_backdated_external_receipt(tmp_path: Path) -> None:
    path = tmp_path / "registration.json"
    registration = replace(_registration(), frozen_at_utc="2026-07-11T00:02:00.000000Z")
    write_registration_create_once(path, registration)
    submissions = tmp_path / "submissions.csv"
    _write_csv(submissions, registration, sha256_file(path))

    with pytest.raises(ValueError, match="after the external"):
        verify_kaggle_submission_anchor(path, submissions)


def test_local_registration_without_external_row_cannot_anchor(tmp_path: Path) -> None:
    path = tmp_path / "registration.json"
    write_registration_create_once(path, _registration())
    submissions = tmp_path / "submissions.csv"
    _write_csv(submissions, _registration(), "0" * 64)

    with pytest.raises(ValueError, match="found 0"):
        verify_kaggle_submission_anchor(path, submissions)


def test_bad_probability_and_noncanonical_time_rejected() -> None:
    value = asdict(_registration())
    value["selector_probability"] = 1.0
    with pytest.raises(ValueError, match="probabilities"):
        PredictionRegistration.from_mapping(value)
    value = asdict(_registration())
    value["frozen_at_utc"] = "2026-07-11T00:00:00Z"
    with pytest.raises(ValueError, match="canonical UTC"):
        PredictionRegistration.from_mapping(value)
