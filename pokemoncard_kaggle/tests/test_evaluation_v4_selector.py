from __future__ import annotations

import csv
from dataclasses import asdict
import json
from pathlib import Path

from evaluation_v4.evidence import PredictionRegistration, sha256_file, write_registration_create_once
from evaluation_v4.protocol import assign_ancestry_split, build_manifest, canonical_sha256, validate_protocol, write_manifest_once
from evaluation_v4.selector import evaluate_selector_packet, write_selector_receipt_once


def _protocol() -> dict:
    return {
        "schema": "whole_policy_selector_protocol_v1",
        "protocol_id": "selector-v4-test",
        "frozen_at_utc": "2026-07-11T07:03:00.000000Z",
        "selector_code_sha256": "a" * 64,
        "split_salt_sha256": "b" * 64,
        "burned_panel_ids": ["f4414154ee58038ac1da"],
        "sealed_holdout_id": "sealed-v4-50",
        "estimand": "next24_win_plus_half_draw",
        "setup_games": 8,
        "horizon_games": 24,
        "minimums": {"min_lineages": 16, "min_families": 4, "min_blocks": 3},
        "thresholds": {
            "macro_lineage_logloss_lift_min": 0.015,
            "lineage_bootstrap_positive_probability_min": 0.95,
            "lineage_bootstrap_q10_lift_min": 0,
            "residual_pairwise_concordance_min": 0.65,
            "positive_unit_fraction_min": 0.8,
            "family_lift_floor": -0.01,
            "calibration_slope_lower_bound_min": 0,
            "max_candidate_visited_ood_mass": 0.10,
            "candidate_posterior_mean_lift_min": 0.03,
            "candidate_posterior_positive_probability_min": 0.95,
            "candidate_posterior_q10_lift_min": 0,
            "worst_family_q10_lift_min": -0.02,
            "engine_variant_mean_lift_min": 0,
        },
        "bootstrap_samples": 200,
        "seed": 20260711,
        "state": "FROZEN",
    }


def _local_test_ancestries(count: int) -> list[str]:
    result: list[str] = []
    index = 0
    while len(result) < count:
        candidate = f"ancestry-{index}"
        if assign_ancestry_split("b" * 64, candidate) == "local_test":
            result.append(candidate)
        index += 1
    return result


def _write_submission_games(directory: Path, *, base_id: int, wins: int) -> None:
    directory.mkdir(parents=True)
    with (directory / "episodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "createTime", "endTime", "state", "type"])
        writer.writeheader()
        for index in reversed(range(32)):
            game_id = str(base_id + index)
            minute = index + 1
            writer.writerow(
                {
                    "id": game_id,
                    "createTime": f"2026-07-11 08:{minute:02d}:00.000000",
                    "endTime": f"2026-07-11 08:{minute:02d}:30.000000",
                    "state": "EpisodeState.COMPLETED",
                    "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
                }
            )
            followup_index = index - 8
            won = index < 8 or followup_index < wins
            rewards = [1, -1] if won else [-1, 1]
            replay = {
                "id": int(game_id),
                "module_version": "1.32.0",
                "info": {"TeamNames": ["GarlicToday", "Other"]},
                "steps": [[{}, {}], [{"reward": rewards[0], "status": "DONE"}, {"reward": rewards[1], "status": "DONE"}]],
            }
            (directory / f"episode-{game_id}-replay.json").write_text(json.dumps(replay), encoding="utf-8")


def _packet(tmp_path: Path) -> dict[str, Path]:
    protocol = _protocol()
    protocol_path = tmp_path / "protocol.json"
    protocol_path.write_text(json.dumps(protocol), encoding="utf-8")
    protocol_sha = canonical_sha256(validate_protocol(protocol))
    ancestries = _local_test_ancestries(16)
    records = []
    unit_specs = []
    submission_rows = []
    pending_registrations = []
    for index, ancestry in enumerate(ancestries):
        archive = tmp_path / f"submission-codex-calibration-v{900 + index}.tar.gz"
        archive.write_bytes(f"archive-{index}".encode())
        archive_sha = sha256_file(archive)
        lineage = f"lineage-{index}"
        family = f"family-{index % 4}"
        records.append(
            {
                "archive_sha256": archive_sha,
                "policy_content_sha256": f"{index + 1:064x}",
                "deck_sha256": f"{index + 101:064x}",
                "lineage_id": lineage,
                "ancestry_id": ancestry,
                "family_id": family,
                "first_seen_utc": f"2026-07-10T00:00:{index:02d}.000000Z",
            }
        )
        wins = 9 + index
        rate = wins / 24
        pending_registrations.append(
            {
                "schema": "whole_policy_prediction_registration_v1",
                "unit_id": f"unit-{index}",
                "protocol_sha256": protocol_sha,
                "lineage_manifest_sha256": "0" * 64,
                "selector_code_sha256": "a" * 64,
                "archive_sha256": archive_sha,
                "archive_name": archive.name,
                "team_name": "GarlicToday",
                "lineage_id": lineage,
                "ancestry_id": ancestry,
                "family_id": family,
                "block_id": f"block-{index % 3}",
                "frozen_at_utc": "2026-07-11T07:10:00.000000Z",
                "nuisance_probability": 0.2,
                "selector_probability": min(rate, 0.95),
                "simulator_delta": rate - 0.2,
                "ood_mass": 0.02,
                "engine_variant_means": {"sample": rate - 0.25, "source": rate - 0.27},
            }
        )
    manifest = build_manifest(protocol, records)
    manifest_path = tmp_path / "lineages.json"
    write_manifest_once(manifest_path, manifest, protocol)
    manifest_file_sha = sha256_file(manifest_path)
    for index, registration_value in enumerate(pending_registrations):
        registration_value["lineage_manifest_sha256"] = manifest_file_sha
        registration = PredictionRegistration.from_mapping(registration_value)
        registration_path = tmp_path / f"registration-{index}.json"
        write_registration_create_once(registration_path, registration)
        ref = str(50000 + index)
        submission_dir = tmp_path / f"submission_{ref}"
        wins = 9 + index
        _write_submission_games(submission_dir, base_id=100000 + index * 100, wins=wins)
        registration_sha = sha256_file(registration_path)
        submission_rows.append(
            {
                "ref": ref,
                "fileName": registration.archive_name,
                "date": "2026-07-11 08:00:00.000000",
                "description": f"reg-sha256={registration_sha} archive-sha256={registration.archive_sha256}",
                "status": "SubmissionStatus.COMPLETE",
            }
        )
        unit_specs.append(
            {
                "registration_path": registration_path.name,
                "registration_sha256": registration_sha,
                "archive_path": registration.archive_name,
                "archive_sha256": registration.archive_sha256,
                "submission_dir": submission_dir.name,
            }
        )
    submissions = tmp_path / "submissions.csv"
    with submissions.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ref", "fileName", "date", "description", "status"])
        writer.writeheader()
        writer.writerows(submission_rows)
    sources = {
        "schema": "whole_policy_calibration_sources_v1",
        "protocol_sha256": protocol_sha,
        "lineage_manifest_sha256": manifest_file_sha,
        "submissions_csv_path": submissions.name,
        "submissions_csv_sha256": sha256_file(submissions),
        "units": unit_specs,
    }
    sources_path = tmp_path / "sources.json"
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    return {"protocol": protocol_path, "manifest": manifest_path, "sources": sources_path, "archive": tmp_path / unit_specs[0]["archive_path"]}


def test_perfect_raw_packet_stays_closed_without_frozen_prediction_recomputation(tmp_path: Path) -> None:
    paths = _packet(tmp_path)

    result = evaluate_selector_packet(protocol_path=paths["protocol"], lineage_manifest_path=paths["manifest"], sources_path=paths["sources"])

    assert result["selector_validated"] is False
    assert result["decision"] == "CLOSED"
    assert result["prediction_recomputation_complete"] is False
    recomputation = next(
        check for check in result["checks"] if check["name"] == "frozen_prediction_recomputation"
    )
    assert recomputation["passed"] is False
    assert result["submission_authority"] == "NONE"
    assert result["first_submission_authorized"] is False
    assert result["sealed_holdout_accessed"] is False
    assert len(result["unit_receipts"]) == 16


def test_archive_mutation_closes_raw_packet(tmp_path: Path) -> None:
    paths = _packet(tmp_path)
    paths["archive"].write_bytes(b"mutated")

    result = evaluate_selector_packet(protocol_path=paths["protocol"], lineage_manifest_path=paths["manifest"], sources_path=paths["sources"])

    assert result["selector_validated"] is False
    assert result["decision"] == "CLOSED"
    assert any(not check["passed"] and "archive" in check["detail"] for check in result["checks"])


def test_selector_receipt_is_create_once(tmp_path: Path) -> None:
    paths = _packet(tmp_path)
    result = evaluate_selector_packet(protocol_path=paths["protocol"], lineage_manifest_path=paths["manifest"], sources_path=paths["sources"])
    output = tmp_path / "receipt.json"
    write_selector_receipt_once(output, result)
    try:
        write_selector_receipt_once(output, result)
    except FileExistsError:
        pass
    else:
        raise AssertionError("selector receipt overwrite was accepted")


def test_dropping_a_registered_local_test_lineage_closes_packet(tmp_path: Path) -> None:
    paths = _packet(tmp_path)
    sources = json.loads(paths["sources"].read_text())
    sources["units"].pop()
    paths["sources"].write_text(json.dumps(sources))

    result = evaluate_selector_packet(protocol_path=paths["protocol"], lineage_manifest_path=paths["manifest"], sources_path=paths["sources"])

    roster = next(check for check in result["checks"] if check["name"] == "complete_local_test_roster")
    assert roster["passed"] is False
    assert result["selector_validated"] is False
