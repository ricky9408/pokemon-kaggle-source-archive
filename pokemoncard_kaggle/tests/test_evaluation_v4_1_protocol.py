from __future__ import annotations

import copy
import uuid

import pytest

from evaluation_v4_1.protocol import (
    ProtocolError,
    build_pair_assignment,
    build_population_manifest,
    canonical_sha256,
    protocol_core_sha256,
    validate_pair_assignment,
    validate_population_manifest,
    validate_protocol,
    write_pair_assignment_once,
    write_population_manifest_once,
    write_protocol_once,
)


def _protocol() -> dict[str, object]:
    return {
        "schema": "voi_p5_protocol_v1",
        "protocol_id": "voi-p5-001",
        "retired_v4_manifest_sha256": "a" * 64,
        "evidence_budget_allocation_event_sha256": "b" * 64,
        "candidate_grammar_sha256": "c" * 64,
        "eligibility_code_sha256": "d" * 64,
        "family_ontology_sha256": "e" * 64,
        "runtime_manifest_sha256": "f" * 64,
        "selector_model_sha256": "0" * 64,
        "external_beacon_source": "https://beacon.nist.gov/beacon/2.0",
        "external_beacon_selection_rule": "first_signed_pulse_strictly_after_population_rfc3161_grant_plus_fixed_delay",
        "external_beacon_delay_seconds": 120,
        "clipping": 0.05,
        "endpoint": "first24_hosted_mean_win_plus_half_draw",
        "setup_games": 0,
        "horizon_games": 24,
        "pairs": 5,
        "selected_lineages": 10,
        "source_population_lineages": 16,
        "family_ids": ["family-a", "family-b", "family-c", "family-d"],
        "waves": ["wave-1", "wave-2", "wave-3"],
        "pair_allocation": {"wave-1": 2, "wave-2": 2, "wave-3": 1},
        "no_replacement": True,
        "interim_efficacy_looks": 0,
        "primary_rule": "all_five_strict_positive",
        "proper_score_lift_floor": 0.015,
        "confirmatory_alpha": 0.03125,
        "research_only": True,
        "sealed_holdout_id": "sealed-50-game-holdout",
        "frozen_at_utc": "2026-07-11T08:00:00.000000Z",
        "state": "FROZEN",
    }


def _records() -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for family_index, family in enumerate(_protocol()["family_ids"]):
        for member_index in range(4):
            index = family_index * 4 + member_index
            records.append(
                {
                    "lineage_uuid": str(uuid.UUID(int=index + 1)),
                    "archive_sha256": f"{index + 1:064x}",
                    "policy_content_sha256": f"{index + 101:064x}",
                    "deck_sha256": f"{index + 201:064x}",
                    "lineage_id": f"lineage-{index:02d}",
                    "ancestry_id": f"ancestry-{index:02d}",
                    "family_id": family,
                    "compute_budget_id": "budget-fixed",
                }
            )
    return records


def _population() -> dict[str, object]:
    return build_population_manifest(_protocol(), _records())


def test_protocol_freezes_all_voi_p5_constants() -> None:
    assert validate_protocol(_protocol())["proper_score_lift_floor"] == 0.015
    for field, bad_value in (
        ("clipping", 0.049),
        ("setup_games", 1),
        ("horizon_games", 23),
        ("pairs", 4),
        ("research_only", False),
        ("state", "OPEN"),
    ):
        changed = _protocol()
        changed[field] = bad_value
        with pytest.raises(ProtocolError):
            validate_protocol(changed)


def test_protocol_core_zeros_both_derived_hash_slots() -> None:
    first = _protocol()
    second = _protocol()
    second["selector_model_sha256"] = "9" * 64
    second["evidence_budget_allocation_event_sha256"] = "8" * 64
    assert protocol_core_sha256(first) == protocol_core_sha256(second)
    assert canonical_sha256(validate_protocol(first)) != canonical_sha256(validate_protocol(second))


@pytest.mark.parametrize("field", ["unknown", "outcome", "prediction", "selector_preference"])
def test_protocol_rejects_field_injection(field: str) -> None:
    protocol = _protocol()
    protocol[field] = True
    with pytest.raises(ProtocolError, match="fields"):
        validate_protocol(protocol)


@pytest.mark.parametrize("field", ["outcome", "prediction", "proper_score", "name"])
def test_population_rejects_outcome_prediction_and_unknown_fields(field: str) -> None:
    records = _records()
    records[0][field] = "injected"
    with pytest.raises(ProtocolError, match="fields"):
        build_population_manifest(_protocol(), records)


@pytest.mark.parametrize("field", ["lineage_uuid", "archive_sha256", "policy_content_sha256", "lineage_id", "ancestry_id"])
def test_population_rejects_duplicate_identity_bindings(field: str) -> None:
    records = _records()
    records[1][field] = records[0][field]
    with pytest.raises(ProtocolError, match=field):
        build_population_manifest(_protocol(), records)


def test_population_requires_four_per_frozen_family() -> None:
    records = _records()
    records[0]["family_id"] = "family-b"
    with pytest.raises(ProtocolError, match="four records"):
        build_population_manifest(_protocol(), records)


def test_population_requires_one_frozen_compute_budget() -> None:
    records = _records()
    records[0]["compute_budget_id"] = "budget-other"
    with pytest.raises(ProtocolError, match="one frozen compute_budget_id"):
        build_population_manifest(_protocol(), records)


def test_population_is_input_order_invariant_and_hash_bound() -> None:
    protocol = _protocol()
    forward = build_population_manifest(protocol, _records())
    backward = build_population_manifest(protocol, list(reversed(_records())))
    assert forward == backward
    assert forward["content_sha256"] == canonical_sha256(
        {key: value for key, value in forward.items() if key != "content_sha256"}
    )


def test_assignment_is_beacon_determined_and_has_exact_wave_balance() -> None:
    protocol = _protocol()
    population = _population()
    assignment = build_pair_assignment(protocol, population, "1" * 64, "nist-2026-07-12")
    assert assignment == build_pair_assignment(protocol, population, "1" * 64, "nist-2026-07-12")
    assert len(assignment["selected_lineage_uuids"]) == 10
    assert len(assignment["pairs"]) == 5
    assert [pair["wave_id"] for pair in assignment["pairs"]] == [
        "wave-1",
        "wave-1",
        "wave-2",
        "wave-2",
        "wave-3",
    ]
    family_counts: dict[str, int] = {}
    for pair in assignment["pairs"]:
        assert set(pair["slot_order"]) == set(pair["member_uuids"])
        family_counts[pair["family_id"]] = family_counts.get(pair["family_id"], 0) + 1
    assert sorted(family_counts.values()) == [1, 1, 1, 2]


def test_beacon_change_changes_assignment() -> None:
    protocol = _protocol()
    population = _population()
    first = build_pair_assignment(protocol, population, "1" * 64, "round-a")
    second = build_pair_assignment(protocol, population, "2" * 64, "round-a")
    assert first["content_sha256"] != second["content_sha256"]


def test_archive_or_name_mutation_cannot_grind_selection_after_uuid_freeze() -> None:
    protocol = _protocol()
    original = _population()
    mutated_records = _records()
    mutated_records[0]["archive_sha256"] = "f" * 64
    mutated_records[0]["policy_content_sha256"] = "e" * 64
    mutated_records[0]["lineage_id"] = "a-completely-different-name"
    mutated = build_population_manifest(protocol, mutated_records)
    original_assignment = build_pair_assignment(protocol, original, "3" * 64, "round-a")
    mutated_assignment = build_pair_assignment(protocol, mutated, "3" * 64, "round-a")
    assert original_assignment["selected_lineage_uuids"] == mutated_assignment["selected_lineage_uuids"]
    assert [pair["member_uuids"] for pair in original_assignment["pairs"]] == [
        pair["member_uuids"] for pair in mutated_assignment["pairs"]
    ]


def test_assignment_rejects_mutation_and_prohibited_fields() -> None:
    protocol = _protocol()
    population = _population()
    assignment = build_pair_assignment(protocol, population, "4" * 64, "round-a")
    tampered = copy.deepcopy(assignment)
    tampered["pairs"][0]["wave_id"] = "wave-3"
    tampered["content_sha256"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "content_sha256"}
    )
    with pytest.raises(ProtocolError, match="deterministic"):
        validate_pair_assignment(tampered, protocol, population)
    assignment["authorization"] = True
    with pytest.raises(ProtocolError, match="fields"):
        validate_pair_assignment(assignment, protocol, population)


def test_create_once_writers_fsync_and_refuse_overwrite(tmp_path: object) -> None:
    protocol = _protocol()
    population = _population()
    assignment = build_pair_assignment(protocol, population, "5" * 64, "round-a")
    protocol_path = tmp_path / "nested" / "protocol.json"  # type: ignore[operator]
    population_path = tmp_path / "nested" / "population.json"  # type: ignore[operator]
    assignment_path = tmp_path / "nested" / "assignment.json"  # type: ignore[operator]
    assert write_protocol_once(protocol_path, protocol) == protocol_path
    assert write_population_manifest_once(population_path, population, protocol) == population_path
    assert write_pair_assignment_once(assignment_path, assignment, protocol, population) == assignment_path
    with pytest.raises(FileExistsError):
        write_protocol_once(protocol_path, protocol)
