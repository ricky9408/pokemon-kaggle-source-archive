from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

import evaluation_v4_1.composer as composer_module
from evaluation_v4.predictor import build_simulation_feature
from evaluation_v4_1.authorization import build_authorization, guard_research_submission
from evaluation_v4_1.beacon import build_beacon_receipt
from evaluation_v4_1.chronology import (
    build_literal_first24_horizon,
    build_pair_completion_barrier,
    build_submission_receipt,
)
from evaluation_v4_1.composer import CompositionError, compose_research_result
from evaluation_v4_1.evidence_budget import append_allocation, create_genesis
from evaluation_v4_1.prediction import build_prediction_bundle
from evaluation_v4_1.protocol import (
    build_pair_assignment,
    build_population_manifest,
    canonical_json_bytes,
    protocol_core_sha256,
)
from evaluation_v4_1.runtime import build_kaggle_runtime_binding
from tests.test_evaluation_v4_1_beacon import _certificate, _pulse
from tests.test_evaluation_v4_1_prediction import _model, _protocol, _records


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_artifact(path: Path, value: object) -> None:
    path.write_bytes(canonical_json_bytes(value) + b"\n")


def _packet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    monkeypatch.setattr(
        "evaluation_v4_1.authorization._wall_now",
        lambda: datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc),
    )
    def fake_reverify(value: object, **kwargs: object) -> dict[str, object]:
        capture = value
        evidence = capture["member_evidence_manifest"]
        horizons = {
            lineage_uuid: build_literal_first24_horizon(
                authorization=kwargs["authorization"],
                permit=item["permit"],
                usage_ledger_path=kwargs["usage_ledger_path"],
                artifacts=kwargs["artifacts"],
                submission_receipt=item["submission_receipt"],
                authenticated_submissions_csv=item["authenticated_submissions_csv"],
                local_archive=item["local_archive"],
                submission_directory=item["submission_directory"],
                team_name=item["team_name"],
            )
            for lineage_uuid, item in evidence.items()
        }
        barrier = build_pair_completion_barrier(
            authorization=kwargs["authorization"],
            pair_id=capture["pair_id"],
            usage_ledger_path=kwargs["usage_ledger_path"],
            artifacts=kwargs["artifacts"],
            member_evidence_by_lineage_uuid=evidence,
        )
        return {
            "pair_id": capture["pair_id"],
            "capture_content_sha256": capture["content_sha256"],
            "content_sha256": capture["content_sha256"],
            "permits_by_lineage_uuid": {
                lineage_uuid: item["permit"] for lineage_uuid, item in evidence.items()
            },
            "submission_receipts_by_lineage_uuid": {
                lineage_uuid: item["submission_receipt"]
                for lineage_uuid, item in evidence.items()
            },
            "horizons_by_lineage_uuid": horizons,
            "pair_completion_barrier": barrier,
        }

    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.reverify_authenticated_pair_capture_online",
        fake_reverify,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.composer.reverify_authenticated_pair_capture_online",
        fake_reverify,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.kaggle_evidence.validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    monkeypatch.setattr(
        "evaluation_v4_1.composer.validate_authenticated_live_pair_snapshot",
        lambda value, **_: value,
    )
    model = _model()
    provisional_protocol = _protocol(model)
    budget_path = tmp_path / "evidence-budget.jsonl"
    create_genesis(
        budget_path,
        program_id="pokemon-selector-program",
        created_at_utc="2026-07-11T08:00:00.000000Z",
    )
    budget_state = append_allocation(
        budget_path,
        protocol_context_sha256=protocol_core_sha256(provisional_protocol),
        alpha_amount=0.03125,
        created_at_utc="2026-07-11T08:01:00.000000Z",
    )
    allocation = budget_state["events"][-1]
    protocol = dict(provisional_protocol)
    protocol["evidence_budget_allocation_event_sha256"] = allocation["event_sha256"]

    archive_bytes_by_uuid: dict[str, bytes] = {}
    records = _records()
    for record in records:
        payload = f"archive bytes for {record['lineage_uuid']}\n".encode("ascii")
        archive_bytes_by_uuid[record["lineage_uuid"]] = payload
        record["archive_sha256"] = hashlib.sha256(payload).hexdigest()
    population = build_population_manifest(protocol, records)
    population_grant = datetime(2026, 7, 11, 9, 0, tzinfo=timezone.utc)

    key, certificate, certificate_id = _certificate(tmp_path)
    previous_time = datetime(2026, 7, 11, 9, 2, tzinfo=timezone.utc)
    current_time = datetime(2026, 7, 11, 9, 3, tzinfo=timezone.utc)
    previous_pulse = _pulse(
        key=key,
        certificate_id=certificate_id,
        index=20,
        timestamp=previous_time,
        previous_output="0" * 128,
    )
    current_pulse = _pulse(
        key=key,
        certificate_id=certificate_id,
        index=21,
        timestamp=current_time,
        previous_output=previous_pulse["outputValue"],  # type: ignore[arg-type]
    )
    beacon = build_beacon_receipt(
        protocol=protocol,
        anchor_granted_at_utc=_iso(population_grant),
        current_pulse=current_pulse,
        previous_pulse=previous_pulse,
        current_certificate_pem=certificate,
        previous_certificate_pem=certificate,
        fetched_at_utc="2026-07-11T09:04:00.000000Z",
        openssl_bin="openssl",
    )
    assignment = build_pair_assignment(
        protocol,
        population,
        beacon["external_beacon_sha256"],
        beacon["external_beacon_round"],
    )
    population_by_uuid = {record["lineage_uuid"]: record for record in population["records"]}
    features = {}
    for pair in assignment["pairs"]:
        for member, lineage_uuid in zip(("A", "B"), pair["slot_order"]):
            record = population_by_uuid[lineage_uuid]
            features[lineage_uuid] = build_simulation_feature(
                {
                    "schema": "whole_policy_simulation_feature_v1",
                    "feature_schema": "whole_policy_simulation_feature_v1",
                    "candidate_archive_sha256": record["archive_sha256"],
                    "design_manifest_sha256": protocol["runtime_manifest_sha256"],
                    "ancestry_id": record["ancestry_id"],
                    "features": {
                        "intercept": 1.0,
                        "simulator_delta": 1.0 if member == "A" else -1.0,
                        "candidate_visited_ood_mass": 0.05,
                        "minimum_engine_variant_mean": 0.0,
                        "minimum_opponent_family_mean": 0.0,
                        "minimum_rating_layer_mean": 0.0,
                    },
                }
            )
    predictions = build_prediction_bundle(
        protocol=protocol,
        population_manifest=population,
        pair_assignment=assignment,
        predictor_model=model,
        features_by_lineage_uuid=features,
        created_at_utc="2026-07-11T09:04:00.000000Z",
    )
    names = {
        lineage_uuid: f"submission-codex-voi-{index:02d}.tar.gz"
        for index, lineage_uuid in enumerate(assignment["selected_lineage_uuids"], start=1)
    }
    artifacts = {
        "protocol": protocol,
        "population_manifest": population,
        "pair_assignment": assignment,
        "prediction_bundle": predictions,
        "predictor_model": model,
        "kaggle_runtime_binding": build_kaggle_runtime_binding(
            Path(__file__).resolve().parents[1]
        ),
    }
    usage_path = tmp_path / "usage.jsonl"
    authorization = build_authorization(
        **artifacts,
        usage_ledger_path=usage_path,
        archive_names_by_lineage_uuid=names,
        authorization_id="voi-p5-composer-test",
        explicit_user_override_text_sha256=hashlib.sha256(b"explicit override").hexdigest(),
        created_at_utc="2026-07-11T09:06:00.000000Z",
        expires_at_utc="2026-07-12T12:00:00.000000Z",
    )

    archive_paths: dict[str, Path] = {}
    for row in authorization["archive_assignments"]:
        path = tmp_path / row["archive_name"]
        path.write_bytes(archive_bytes_by_uuid[row["lineage_uuid"]])
        archive_paths[row["lineage_uuid"]] = path

    base_submission = datetime(2026, 7, 11, 9, 10, tzinfo=timezone.utc)
    accumulated_submission_rows: list[dict[str, object]] = []
    previous_barrier: dict[str, object] | None = None
    previous_capture: dict[str, object] | None = None
    pair_capture_packages: dict[str, dict[str, object]] = {}
    columns = ["ref", "fileName", "date", "description", "status", "publicScore", "privateScore"]
    for pair_index, pair in enumerate(assignment["pairs"]):
        pair_start = base_submission + timedelta(hours=pair_index)
        pair_rows: list[dict[str, object]] = []
        pair_permits: dict[str, dict[str, object]] = {}
        for slot, lineage_uuid in enumerate(pair["slot_order"], start=1):
            submitted = pair_start + timedelta(seconds=(slot - 1) * 10)
            first_game = pair_start + timedelta(seconds=20)
            assignment_row = next(
                item
                for item in authorization["archive_assignments"]
                if item["lineage_uuid"] == lineage_uuid
            )
            guard_kwargs: dict[str, object] = {}
            if previous_capture is not None:
                guard_kwargs = {"prior_pair_capture": previous_capture}
            pair_permits[lineage_uuid] = guard_research_submission(
                authorization,
                usage_path,
                artifacts=artifacts,
                **assignment_row,
                **guard_kwargs,
                now=_iso(submitted - timedelta(seconds=2)),
            )
            ref = str(90000 + pair_index * 2 + slot)
            pair_rows.append(
                {
                    "ref": ref,
                    "fileName": assignment_row["archive_name"],
                    "date": submitted.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "description": f"codex-voi-pair-{pair_index + 1:02d}-slot-{slot}",
                    "status": "SubmissionStatus.COMPLETE",
                    "publicScore": "600.0",
                    "privateScore": "",
                    "lineage_uuid": lineage_uuid,
                    "first_game": first_game,
                    "selected": member_for_uuid(pair, lineage_uuid) == "A",
                }
            )

        accumulated_submission_rows.extend(pair_rows)
        submissions_csv = tmp_path / f"submissions-pair-{pair_index + 1:02d}.csv"
        with submissions_csv.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(
                [
                    {column: row[column] for column in columns}
                    for row in accumulated_submission_rows
                ]
            )

        pair_evidence: dict[str, dict[str, object]] = {}
        for row in pair_rows:
            lineage_uuid = str(row["lineage_uuid"])
            permit = pair_permits[lineage_uuid]
            submission_receipt = build_submission_receipt(
                authorization=authorization,
                permit=permit,
                usage_ledger_path=usage_path,
                artifacts=artifacts,
                authenticated_submissions_csv=submissions_csv,
                local_archive=archive_paths[lineage_uuid],
                submission_ref=str(row["ref"]),
                expected_description=str(row["description"]),
                first_observed_complete_at_utc=_iso(row["first_game"] + timedelta(minutes=25)),
            )
            directory = tmp_path / f"submission_{row['ref']}"
            directory.mkdir()
            with (directory / "episodes.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["id", "createTime", "endTime", "state", "type"])
                writer.writeheader()
                for game_index in reversed(range(24)):
                    created = row["first_game"] + timedelta(minutes=game_index)
                    game_id = str(int(row["ref"]) * 100 + game_index)
                    writer.writerow(
                        {
                            "id": game_id,
                            "createTime": created.strftime("%Y-%m-%d %H:%M:%S.%f"),
                            "endTime": (created + timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S.%f"),
                            "state": "EpisodeState.COMPLETED",
                            "type": "EpisodeType.EPISODE_TYPE_PUBLIC",
                        }
                    )
                    win = bool(row["selected"])
                    replay = {
                        "id": f"replay-{game_id}",
                        "module_version": "1.32.0",
                        "info": {
                            "EpisodeId": int(game_id),
                            "TeamNames": ["GarlicToday", f"Opponent-{game_index}"],
                        },
                        "steps": [
                            [{}, {}],
                            [
                                {"reward": 1 if win else -1, "status": "DONE"},
                                {"reward": -1 if win else 1, "status": "DONE"},
                            ],
                        ],
                    }
                    (directory / f"episode-{game_id}-replay.json").write_text(
                        json.dumps(replay), encoding="utf-8"
                    )
            evidence_row = {
                "permit": permit,
                "submission_receipt": submission_receipt,
                "authenticated_submissions_csv": submissions_csv,
                "local_archive": archive_paths[lineage_uuid],
                "submission_directory": directory,
                "team_name": "GarlicToday",
            }
            pair_evidence[lineage_uuid] = evidence_row
        previous_barrier = build_pair_completion_barrier(
            authorization=authorization,
            pair_id=pair["pair_id"],
            usage_ledger_path=usage_path,
            artifacts=artifacts,
            member_evidence_by_lineage_uuid=pair_evidence,
        )
        previous_capture = {
            "pair_id": pair["pair_id"],
            "pair_completion_barrier": previous_barrier,
            "member_evidence_manifest": pair_evidence,
            "content_sha256": hashlib.sha256(pair["pair_id"].encode("ascii")).hexdigest(),
        }
        pair_capture_packages[pair["pair_id"]] = previous_capture

    anchors = {}
    for name, artifact in (
        ("population", population),
        ("prediction", predictions),
        ("authorization", authorization),
    ):
        data = tmp_path / f"{name}.json"
        token = tmp_path / f"{name}.tsr"
        ca = tmp_path / f"{name}.ca"
        _write_artifact(data, artifact)
        token.write_bytes(name.encode("ascii"))
        ca.write_bytes(b"ca")
        anchors[name] = {"data_path": data, "token_path": token, "ca_file": ca}
    return {
        "protocol": protocol,
        "population_manifest": population,
        "pair_assignment": assignment,
        "beacon_receipt": beacon,
        "predictor_model": model,
        "kaggle_runtime_binding": artifacts["kaggle_runtime_binding"],
        "prediction_bundle": predictions,
        "authorization": authorization,
        "population_timestamp_material": anchors["population"],
        "prediction_timestamp_material": anchors["prediction"],
        "authorization_timestamp_material": anchors["authorization"],
        "evidence_budget_ledger_path": budget_path,
        "usage_ledger_path": usage_path,
        "pair_capture_packages_by_pair_id": pair_capture_packages,
    }


def member_for_uuid(pair: dict[str, object], lineage_uuid: str) -> str:
    return "A" if pair["slot_order"][0] == lineage_uuid else "B"  # type: ignore[index]


def _fake_timestamp_verifier(*, data_path: object, token_path: object, ca_file: object) -> dict[str, object]:
    name = Path(data_path).stem
    times = {
        "population": "2026-07-11T09:00:00.000000Z",
        "prediction": "2026-07-11T09:05:00.000000Z",
        "authorization": "2026-07-11T09:07:00.000000Z",
    }
    return {
        "schema": "rfc3161_registration_anchor_v1",
        "verified": True,
        "data_sha256": hashlib.sha256(Path(data_path).read_bytes()).hexdigest(),
        "token_sha256": hashlib.sha256(Path(token_path).read_bytes()).hexdigest(),
        "granted_at_utc": times[name],
        "performance_evidence": False,
        "production_submission_authorized": False,
    }


def test_complete_raw_packet_can_only_emit_research_signal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    packet = _packet(tmp_path, monkeypatch)
    monkeypatch.setattr(composer_module, "verify_rfc3161_token", _fake_timestamp_verifier)
    result = compose_research_result(**packet)
    assert result["integrity_pass"] is True
    assert result["decision"] == "VOI_SIGNAL_RESEARCH_ONLY"
    assert result["statistics_result"]["positive_delta_count"] == 5
    assert result["statistics_result"]["sign_test_probability"] == 0.03125
    assert result["production_submission_authorized"] is False
    assert result["sealed_holdout_accessed"] is False


def test_games_before_both_pair_members_are_submitted_fail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    packet = _packet(tmp_path, monkeypatch)
    monkeypatch.setattr(composer_module, "verify_rfc3161_token", _fake_timestamp_verifier)
    first_uuid = packet["pair_assignment"]["pairs"][0]["slot_order"][0]
    pair_id = packet["pair_assignment"]["pairs"][0]["pair_id"]
    unit = packet["pair_capture_packages_by_pair_id"][pair_id][
        "member_evidence_manifest"
    ][first_uuid]
    episodes = unit["submission_directory"] / "episodes.csv"
    rows = list(csv.DictReader(episodes.open()))
    # Rows were written in reverse order; the last row is literal game zero.
    rows[-1]["createTime"] = "2026-07-11 09:10:05.000000"
    rows[-1]["endTime"] = "2026-07-11 09:10:35.000000"
    with episodes.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    with pytest.raises(CompositionError, match="before both members"):
        compose_research_result(**packet)


def test_timestamped_artifact_mutation_fails_before_timestamp_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet = _packet(tmp_path, monkeypatch)
    monkeypatch.setattr(composer_module, "verify_rfc3161_token", _fake_timestamp_verifier)
    data = packet["prediction_timestamp_material"]["data_path"]
    data.write_bytes(data.read_bytes() + b"mutation")
    with pytest.raises(CompositionError, match="exact canonical artifact"):
        compose_research_result(**packet)
