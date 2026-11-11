from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from evaluation_v5_1.paired_evidence_preflight import (
    HARD_CLOSE,
    PROTOCOL_SCHEMA,
    RESEARCH_ONLY,
    STRUCTURAL_PAIRING_READY,
    STRUCTURAL_PROSPECTIVE,
    evaluate_paired_evidence_preflight,
    evaluate_structural_pairing_conformance,
    preflight_from_files,
    render_json,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _fixture() -> dict[str, object]:
    global_hashes = {
        "evaluator_sha256": _hash("evaluator"),
        "local_schedule_sha256": _hash("local-schedule"),
        "local_config_sha256": _hash("local-config"),
        "local_runtime_sha256": _hash("local-runtime"),
    }
    protocol = {
        "schema": PROTOCOL_SCHEMA,
        "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "required_unit_count": 2,
        "freeze_time_ns": 100,
        "t1_ns": 200,
        "natural_start_local_quota": 2,
        "required_strata": [
            {"seat": 0, "opponent_score_stratum": "low", "required_games": 1},
            {"seat": 1, "opponent_score_stratum": "high", "required_games": 1},
        ],
        "frozen_hashes": global_hashes,
        "selector_feature_allowlist": ["a2", "setup_rate"],
    }
    archives: list[dict[str, object]] = []
    local: list[dict[str, object]] = []
    hosted: list[dict[str, object]] = []
    for index in range(2):
        archive = _hash(f"archive-{index}")
        unit: dict[str, object] = {
            "unit_id": f"unit-{index}",
            "team_id": f"team-{index}",
            "family_id": f"family-{index}",
            "ancestry_id": f"ancestry-{index}",
            "submission_id": f"submission-{index}",
            "archive_sha256": archive,
            "archive_frozen_at_ns": 50,
            "runnable": True,
            "evaluator_compatible": True,
            "evidence_role": STRUCTURAL_PROSPECTIVE,
            "evaluator_sha256": global_hashes["evaluator_sha256"],
            "code_sha256": _hash(f"code-{index}"),
            "deck_sha256": _hash(f"deck-{index}"),
            "model_sha256": _hash(f"model-{index}"),
            "agent_config_sha256": _hash(f"agent-config-{index}"),
            "archive_custody_receipt_sha256": _hash(f"custody-{index}"),
            "runnable_receipt_sha256": _hash(f"runnable-{index}"),
            "ancestry_attestation_receipt_sha256": _hash(f"ancestry-receipt-{index}"),
            "hosted_linkage_receipt_sha256": _hash(f"hosted-link-{index}"),
            "local_output_receipt_sha256": _hash(f"local-output-{index}"),
            "selector_prediction": f"0.{600_000_000_000 + index:012d}",
            "baseline_prediction": f"0.{500_000_000_000 + index:012d}",
            "selector_features": {"a2": 0.5 + index / 10, "setup_rate": 0.75},
        }
        archives.append(unit)
        identity = {
            name: unit[name]
            for name in (
                "unit_id",
                "team_id",
                "family_id",
                "ancestry_id",
                "submission_id",
                "archive_sha256",
            )
        }
        archive_hashes = {
            name: unit[name]
            for name in (
                "code_sha256",
                "deck_sha256",
                "model_sha256",
                "agent_config_sha256",
            )
        }
        for run_index in range(2):
            local.append(
                {
                    **identity,
                    "episode_id": f"local-{index}-{run_index}",
                    "started_at_ns": 10 + run_index,
                    "ended_at_ns": 20 + run_index,
                    "seed_sha256": _hash(f"seed-{index}-{run_index}"),
                    "schedule_slot_id": f"slot-{index}-{run_index}",
                    "trace_receipt_sha256": _hash(f"trace-{index}-{run_index}"),
                    "natural_start": True,
                    "evidence_role": STRUCTURAL_PROSPECTIVE,
                    **global_hashes,
                    **archive_hashes,
                }
            )
        for game_index, (seat, stratum) in enumerate(((0, "low"), (1, "high"))):
            hosted.append(
                {
                    **identity,
                    "episode_id": f"hosted-{index}-{game_index}",
                    "created_at_ns": 110 + game_index,
                    "started_at_ns": 111 + game_index,
                    "ended_at_ns": 120 + game_index,
                    "seat": seat,
                    "opponent_score_stratum": stratum,
                    "opponent_archive_sha256": _hash(f"opponent-{index}-{game_index}"),
                    "opponent_component_id": f"opponent-component-{index}-{game_index}",
                    "pre_game_opponent_score_milli": 750_000 + game_index,
                    "outcome": 1 if game_index == 0 else 0,
                    "source_row_sha256": _hash(f"source-row-{index}-{game_index}"),
                    "collector_agreement": True,
                    "episode_level": True,
                    "aggregate_only": False,
                    "evidence_role": STRUCTURAL_PROSPECTIVE,
                }
            )
    candidate = [
        {
            "candidate_id": "candidate-0",
            "archive_sha256": _hash("unsubmitted-candidate"),
            "team_id": "candidate-team",
            "family_id": "candidate-family",
            "ancestry_id": "candidate-ancestry",
            "submitted": False,
            "evidence_role": RESEARCH_ONLY,
            "parent_archive_sha256": archives[0]["archive_sha256"],
            "hosted_evidence_inherited": False,
            "forbidden_evidence_roots": [],
            "candidate_provenance_receipt_sha256": _hash("candidate-provenance"),
            "local_output_receipt_sha256": _hash("candidate-local-output"),
            "selector_prediction": "0.650000000000",
        }
    ]
    return {
        "protocol": protocol,
        "archives": archives,
        "local": local,
        "hosted": hosted,
        "candidates": candidate,
    }


def _structural(data: dict[str, object]) -> dict[str, object]:
    return evaluate_structural_pairing_conformance(
        data["protocol"],
        data["archives"],
        data["local"],
        data["hosted"],
        data["candidates"],
    )


def _run(data: dict[str, object]) -> dict[str, object]:
    return evaluate_paired_evidence_preflight(
        data["protocol"],
        data["archives"],
        data["local"],
        data["hosted"],
        data["candidates"],
    )


def test_complete_fixture_can_only_pass_structural_conformance() -> None:
    result = _structural(_fixture())
    assert result["preflight_status"] == STRUCTURAL_PAIRING_READY
    assert result["production_gate_status"] == HARD_CLOSE
    assert result["structural_eligible_unit_count"] == 2
    assert result["eligible_paired_unit_count"] == 0
    assert result["terminal_blockers"] == []
    assert result["external_authentication_verified"] is False
    assert result["g11_selector_validated"] is False
    assert result["candidate_development_authorized"] is False
    assert result["sealed_holdout_access_authorized"] is False
    assert result["submission_authorized"] is False
    assert "SUBMIT_AUTHORIZED" not in render_json(result)
    unsigned = dict(result)
    content_hash = unsigned.pop("content_sha256")
    assert _hash(render_json(unsigned)) == content_hash


def test_production_entry_point_is_non_bypassably_hard_closed() -> None:
    data = _fixture()
    data["protocol"]["external_verifier_id"] = "caller-asserted-verifier"
    data["archives"][0]["authenticated"] = True
    result = _run(data)
    assert result["preflight_status"] == STRUCTURAL_PAIRING_READY
    assert result["production_gate_status"] == HARD_CLOSE
    assert result["eligible_paired_unit_count"] == 0
    assert result["external_authentication_verified"] is False
    assert "pinned_paired_evidence_verifier_unavailable" in result["terminal_blockers"]
    assert result["authority"] is False
    assert result["candidate_development_authorized"] is False
    assert result["sealed_holdout_access_authorized"] is False
    assert result["submission_authorized"] is False
    assert "SUBMIT_AUTHORIZED" not in render_json(result)


def test_required_unit_count_is_mandatory_and_exact() -> None:
    data = _fixture()
    data["protocol"]["required_unit_count"] = 3
    result = _structural(data)
    assert result["preflight_status"] == HARD_CLOSE
    assert "archive_unit_count_mismatch" in result["terminal_blockers"]

    data = _fixture()
    del data["protocol"]["required_unit_count"]
    result = _structural(data)
    assert result["preflight_status"] == HARD_CLOSE
    assert "missing:required_unit_count" in result["terminal_blockers"]


def test_research_only_or_caller_asserted_archive_evidence_is_excluded() -> None:
    for role in (RESEARCH_ONLY, "AUTHENTICATED_PROSPECTIVE"):
        data = _fixture()
        data["archives"][0]["evidence_role"] = role
        result = _structural(data)
        assert result["preflight_status"] == HARD_CLOSE
        assert result["structural_eligible_unit_count"] == 1

    data = _fixture()
    data["hosted"][0]["evidence_role"] = RESEARCH_ONLY
    result = _structural(data)
    assert result["preflight_status"] == HARD_CLOSE
    assert "research_only_evidence_excluded" in result["per_unit_flags"][0]["reasons"]


def test_rows_bind_exact_unit_team_family_ancestry_submission_and_archive() -> None:
    data = _fixture()
    data["hosted"][0]["family_id"] = data["archives"][1]["family_id"]
    data["hosted"][0]["ancestry_id"] = data["archives"][1]["ancestry_id"]
    result = _structural(data)
    reasons = result["per_unit_flags"][0]["reasons"]
    assert "hosted_identity_mismatch:family_id" in reasons
    assert "hosted_identity_mismatch:ancestry_id" in reasons

    data = _fixture()
    data["local"][0]["submission_id"] = "wrong-submission"
    result = _structural(data)
    assert "local_identity_mismatch:submission_id" in result["per_unit_flags"][0]["reasons"]


def test_local_rows_bind_archive_components_and_global_runtime_hashes() -> None:
    data = _fixture()
    data["local"][0]["model_sha256"] = _hash("mutated-model")
    result = _structural(data)
    assert "local_hash_mismatch:model_sha256" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["local"][0]["local_runtime_sha256"] = _hash("mutated-runtime")
    result = _structural(data)
    assert "local_hash_mismatch:local_runtime_sha256" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["archives"][0]["deck_sha256"] = _hash("mutated-deck")
    result = _structural(data)
    assert "local_hash_mismatch:deck_sha256" in result["per_unit_flags"][0]["reasons"]


def test_hosted_rows_do_not_claim_or_require_local_model_hashes() -> None:
    data = _fixture()
    data["hosted"][0]["model_sha256"] = _hash("host-only-model-observation")
    result = _structural(data)
    assert result["preflight_status"] == STRUCTURAL_PAIRING_READY


def test_local_and_hosted_quotas_are_exact() -> None:
    data = _fixture()
    extra = deepcopy(data["local"][0])
    extra["episode_id"] = "extra-local"
    extra["seed_sha256"] = _hash("extra-local-seed")
    extra["schedule_slot_id"] = "extra-local-slot"
    data["local"].append(extra)
    result = _structural(data)
    assert "local_quota_exact_mismatch" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    extra = deepcopy(data["hosted"][0])
    extra["episode_id"] = "extra-hosted"
    extra["source_row_sha256"] = _hash("extra-hosted-row")
    data["hosted"].append(extra)
    result = _structural(data)
    assert "stratum_count_mismatch:seat0:low" in result["per_unit_flags"][0]["reasons"]


def test_future_episode_ids_are_not_prefrozen_or_retrospectively_selected() -> None:
    first_data = _fixture()
    first = _structural(first_data)
    assert "expected_episode_ids" not in first_data["protocol"]
    assert first["preflight_status"] == STRUCTURAL_PAIRING_READY

    renamed = _fixture()
    renamed["hosted"][0]["episode_id"] = "future-hosted-id-assigned-after-t0"
    second = _structural(renamed)
    assert second["preflight_status"] == STRUCTURAL_PAIRING_READY
    assert first["input_roots"]["hosted_observations"] != second["input_roots"]["hosted_observations"]


def test_protocol_set_order_and_input_row_order_are_invariant() -> None:
    first = _run(_fixture())
    data = _fixture()
    data["protocol"]["required_strata"] = list(reversed(data["protocol"]["required_strata"]))
    data["protocol"]["selector_feature_allowlist"] = list(
        reversed(data["protocol"]["selector_feature_allowlist"])
    )
    for name in ("archives", "local", "hosted", "candidates"):
        data[name] = list(reversed(data[name]))
    assert first == _run(data)


def test_duplicate_archive_team_family_and_ancestry_fail_closed() -> None:
    for field in ("archive_sha256", "team_id", "family_id", "ancestry_id"):
        data = _fixture()
        data["archives"][1][field] = data["archives"][0][field]
        result = _structural(data)
        assert result["preflight_status"] == HARD_CLOSE
        assert f"duplicate_{field}" in result["terminal_blockers"]
        assert result["structural_eligible_unit_count"] == 0


def test_benign_candidate_ancestry_is_allowed_but_hosted_dependency_is_not() -> None:
    result = _structural(_fixture())
    assert result["preflight_status"] == STRUCTURAL_PAIRING_READY

    data = _fixture()
    data["candidates"][0]["hosted_evidence_inherited"] = True
    result = _structural(data)
    assert "candidate_hosted_evidence_dependency_present" in result["terminal_blockers"]

    data = _fixture()
    data["candidates"][0]["forbidden_evidence_roots"] = [_hash("public-root")]
    result = _structural(data)
    assert "candidate_forbidden_evidence_roots_present" in result["terminal_blockers"]

    data = _fixture()
    data["candidates"][0]["archive_sha256"] = data["archives"][0]["archive_sha256"]
    result = _structural(data)
    assert "candidate_reuses_paired_archive" in result["terminal_blockers"]

    data = _fixture()
    data["candidates"][0]["public_score"] = 123
    result = _structural(data)
    assert "forbidden_candidate_public_or_hosted_field" in result["terminal_blockers"]


def test_public_fields_and_sealed_holdout_references_are_rejected() -> None:
    data = _fixture()
    data["archives"][0]["selector_features"]["public_score"] = 999
    result = _structural(data)
    assert "forbidden_public_selector_field" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["hosted"][0]["public_score"] = 999
    result = _structural(data)
    assert "forbidden_public_hosted_field" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["protocol"]["sealed_holdout_path"] = "/evidence/sealed_50/holdout.json"
    result = _structural(data)
    assert "sealed_holdout_reference_present" in result["terminal_blockers"]


def test_time_outcome_collector_and_episode_integrity_are_fail_closed() -> None:
    data = _fixture()
    data["hosted"][0]["created_at_ns"] = 99
    result = _structural(data)
    assert "hosted_game_not_strictly_prospective" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["hosted"][0]["started_at_ns"] = 200
    result = _structural(data)
    assert "hosted_game_not_strictly_prospective" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["hosted"][0]["outcome"] = "win"
    data["hosted"][0]["collector_agreement"] = False
    result = _structural(data)
    reasons = result["per_unit_flags"][0]["reasons"]
    assert "invalid_hosted_outcome" in reasons
    assert "hosted_collector_agreement_missing" in reasons

    data = _fixture()
    data["local"][0]["ended_at_ns"] = 100
    result = _structural(data)
    assert "local_run_not_pre_freeze" in result["per_unit_flags"][0]["reasons"]

    data = _fixture()
    data["hosted"][1]["episode_id"] = data["hosted"][0]["episode_id"]
    result = _structural(data)
    assert "duplicate_episode_id" in result["terminal_blockers"]


def test_local_seed_and_schedule_slot_commitments_must_be_unique() -> None:
    data = _fixture()
    data["local"][1]["seed_sha256"] = data["local"][0]["seed_sha256"]
    result = _structural(data)
    assert "duplicate_local_seed_commitment" in result["terminal_blockers"]

    data = _fixture()
    data["local"][1]["schedule_slot_id"] = data["local"][0]["schedule_slot_id"]
    result = _structural(data)
    assert "duplicate_local_schedule_slot" in result["terminal_blockers"]


def test_json_and_jsonl_files_use_production_hard_close(tmp_path: Path) -> None:
    data = _fixture()
    paths: dict[str, Path] = {}
    for key, suffix in (
        ("protocol", ".json"),
        ("archives", ".jsonl"),
        ("local", ".jsonl"),
        ("hosted", ".jsonl"),
        ("candidates", ".json"),
    ):
        path = tmp_path / f"{key}{suffix}"
        value = data[key]
        if suffix == ".jsonl":
            path.write_text(
                "".join(json.dumps(row) + "\n" for row in value), encoding="utf-8"
            )
        else:
            path.write_text(json.dumps(value), encoding="utf-8")
        paths[key] = path

    result = preflight_from_files(
        paths["protocol"],
        paths["archives"],
        paths["local"],
        paths["hosted"],
        paths["candidates"],
    )
    assert result["preflight_status"] == STRUCTURAL_PAIRING_READY
    assert result["production_gate_status"] == HARD_CLOSE
    assert "pinned_paired_evidence_verifier_unavailable" in result["terminal_blockers"]
    assert json.loads(render_json(result)) == result
