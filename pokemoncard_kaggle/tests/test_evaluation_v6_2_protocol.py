from __future__ import annotations

import copy

import pytest

from evaluation_v6_2.protocol import (
    ProtocolError,
    _REQUIRED_ARTIFACTS,
    build_population_manifest,
    build_preregistration_root,
    canonical_json_loads,
    canonical_sha256,
    read_canonical_json_file,
    validate_feature_vectors,
    validate_population_manifest,
    validate_protocol,
    validate_submission_name,
    write_protocol_once,
)


def _protocol() -> dict[str, object]:
    return {
        "schema": "evaluation_v6_2_1_protocol_v1", "protocol_id": "v6-2-1-calibration",
        "N": 16, "population_size": 16, "dev_primary_count": 6, "confirm_primary_count": 8,
        "dev_reserve_count": 1, "confirm_reserve_count": 1, "production_slots": 1,
        "one_at_a_time": True, "latest_two_required": True, "daily_calibration_upload_max": 3,
        "poll_offsets_minutes": [60, 120, 240, 480], "poll_window_minutes": 10,
        "poll_retry_seconds": 60, "poll_sync_max_skew_seconds": 60, "precomplete_deadline_hours": 12,
        "naming_forbidden_substring": "final", "feature_names": [
            "early_prize_tempo_t2", "board_readiness_t2_t4", "damage_efficiency_t4", "recovery_rate", "resource_viability", "seat_robustness",
        ], "dev_min_wins": 4, "dev_oof_mae_ratio_max": 0.90, "dev_beta_posterior_min": 0.90,
        "dev_successful_folds_required": 6, "confirm_sign_wins_min": 7, "confirm_mae_ratio_max": 0.80,
        "confirm_const_mae_ratio_max": 0.95, "confirm_concordance_min": 20,
        "canonical_epsilon": 0.000001, "research_only": True, "upload_authorized": False,
        "production_authorized": False, "state": "PREREGISTRATION_LOCKED",
    }


def _records() -> list[dict[str, object]]:
    roles = ["DEV_PRIMARY"] * 6 + ["DEV_RESERVE"] + ["CONFIRM_PRIMARY"] * 8 + ["CONFIRM_RESERVE"]
    interventions = ["a", "b", "c", "d", "e", "f", "g", "a", "b", "c", "d", "e", "a", "b", "c", "d"]
    return [
        {
            "archive_hash": f"{index + 1:064x}", "role": roles[index], "upload_order": index + 1,
            "lineage_time_block_id": f"block-{index:02d}", "source_family_id": f"source-{index:02d}",
            "intervention_family_id": interventions[index], "production_eligibility_flag": False,
            "production_ineligibility_reason": "CALIBRATION_LEDGER_DISJOINT_FROM_PRODUCTION",
        }
        for index in range(16)
    ]


def _vectors() -> dict[str, dict[str, float]]:
    names = _protocol()["feature_names"]
    slots = ["D01", "D02", "D03", "D04", "D05", "D06", "DR01", "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "CR01"]
    return {slot: {name: 0.5 for name in names} for slot in slots}  # type: ignore[misc]


def _artifacts() -> dict[str, str]:
    return {name: canonical_sha256({"artifact": name}) for name in _REQUIRED_ARTIFACTS}


def test_protocol_freezes_counts_windows_thresholds_and_one_production_slot() -> None:
    assert validate_protocol(_protocol())["production_slots"] == 1
    for field, value in (("N", 15), ("population_size", 15), ("poll_offsets_minutes", [60, 120, 240]), ("confirm_sign_wins_min", 6), ("upload_authorized", True)):
        changed = _protocol()
        changed[field] = value
        with pytest.raises(ProtocolError):
            validate_protocol(changed)


def test_json_rejects_duplicate_keys_and_nan() -> None:
    with pytest.raises(ProtocolError, match="duplicate"):
        canonical_json_loads('{"a":1,"a":2}')
    with pytest.raises(ProtocolError, match="non-finite"):
        canonical_json_loads('{"a":NaN}')


def test_population_rejects_malformed_count_and_role_or_order_errors() -> None:
    with pytest.raises(ProtocolError, match="16"):
        build_population_manifest(_protocol(), _records()[:-1])
    records = _records()
    records[0]["role"] = "CONFIRM_PRIMARY"
    with pytest.raises(ProtocolError, match="role"):
        build_population_manifest(_protocol(), records)


def test_only_dev_primaries_can_be_production_eligible_metadata() -> None:
    records = _records()
    records[0]["production_eligibility_flag"] = True
    records[0]["production_ineligibility_reason"] = None
    assert build_population_manifest(_protocol(), records)["records"][0]["production_eligibility_flag"] is True
    records = _records()
    records[7]["production_eligibility_flag"] = True
    records[7]["production_ineligibility_reason"] = None
    with pytest.raises(ProtocolError, match="only DEV primaries"):
        build_population_manifest(_protocol(), records)
    records = _records()
    records[7]["upload_order"] = 3
    with pytest.raises(ProtocolError, match="upload_order"):
        build_population_manifest(_protocol(), records)


@pytest.mark.parametrize("field", ["archive_hash", "source_family_id", "lineage_time_block_id"])
def test_population_requires_all_identity_bindings_distinct(field: str) -> None:
    records = _records()
    records[1][field] = records[0][field]
    with pytest.raises(ProtocolError, match=field):
        build_population_manifest(_protocol(), records)


def test_population_rejects_reserve_intervention_scenarios() -> None:
    records = _records()
    for index, family in enumerate(["a", "a", "a", "b", "b", "c", "a"]):
        records[index]["intervention_family_id"] = family
    with pytest.raises(ProtocolError, match="DEV reserve"):
        build_population_manifest(_protocol(), records)
    records = _records()
    for index, family in enumerate(["a", "a", "a", "b", "b", "c", "c", "d", "a"]):
        records[7 + index]["intervention_family_id"] = family
    with pytest.raises(ProtocolError, match="CONFIRM reserve"):
        build_population_manifest(_protocol(), records)


def test_feature_support_contains_all_possible_active_dev_sets() -> None:
    manifest = build_population_manifest(_protocol(), _records())
    vectors = _vectors()
    vectors["D01"]["recovery_rate"] = 0.1
    vectors["DR01"]["recovery_rate"] = 0.9
    vectors["C01"]["recovery_rate"] = 0.5
    validate_feature_vectors(vectors, manifest, _protocol())
    vectors["C01"]["recovery_rate"] = 0.95
    with pytest.raises(ProtocolError, match="outside support"):
        validate_feature_vectors(vectors, manifest, _protocol())


def test_names_containing_final_and_sealed_holdout_paths_are_rejected(tmp_path: object) -> None:
    with pytest.raises(ProtocolError, match="final"):
        validate_submission_name("codex-final-v1")
    bad = _protocol()
    bad["protocol_id"] = "sealed-holdout-path"
    with pytest.raises(ProtocolError, match="sealed-holdout"):
        validate_protocol(bad)
    with pytest.raises(ProtocolError, match="traverse"):
        write_protocol_once(tmp_path / "x" / ".." / "protocol.json", _protocol())  # type: ignore[operator]
    with pytest.raises(ProtocolError, match="sealed-holdout"):
        write_protocol_once(tmp_path / "sealed" / "holdout" / "protocol.json", _protocol())  # type: ignore[operator]


def test_immutable_helpers_reject_symlinks_and_overwrites(tmp_path: object) -> None:
    target = tmp_path / "protocol.json"  # type: ignore[operator]
    write_protocol_once(target, _protocol())
    with pytest.raises(FileExistsError):
        write_protocol_once(target, _protocol())
    linked = tmp_path / "linked.json"  # type: ignore[operator]
    linked.symlink_to(target)
    with pytest.raises(ProtocolError, match="symlink"):
        read_canonical_json_file(linked)


def test_population_is_deterministic_and_tamper_evident() -> None:
    manifest = build_population_manifest(_protocol(), _records())
    assert manifest == build_population_manifest(_protocol(), _records())
    tampered = copy.deepcopy(manifest)
    tampered["records"][0]["intervention_family_id"] = "z"
    with pytest.raises(ProtocolError, match="content_sha256"):
        validate_population_manifest(tampered, _protocol())


def test_preregistration_roots_are_deterministic_and_never_authorize_uploads() -> None:
    protocol = _protocol()
    manifest = build_population_manifest(protocol, _records())
    first = build_preregistration_root(protocol, manifest, _vectors(), _artifacts())
    second = build_preregistration_root(protocol, manifest, _vectors(), _artifacts())
    assert first == second
    assert first["upload_authorized"] is False
    assert first["production_authorized"] is False
    assert "AUTHORIZED" not in first["state"]
