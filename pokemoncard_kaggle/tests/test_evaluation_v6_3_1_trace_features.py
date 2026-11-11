from __future__ import annotations

import copy
import hashlib

import pytest

import evaluation_v6_3_1.trace_features as trace_features
from evaluation_v6_3_1.trace_features import (
    DIRECT_DAMAGE_KIND,
    ExactRational,
    RECEIPT_SCHEMA,
    TRACE_SCHEMA,
    TraceFeatureError,
    canonical_legal_action_set_sha256,
    derive_game_feature_counts,
    extract_offline_trace_features,
    make_replay_verified_game,
)


def _hash(value: object) -> str:
    return hashlib.sha256(repr(value).encode("ascii")).hexdigest()


def _receipt() -> dict[str, object]:
    return {
        "schema_id": RECEIPT_SCHEMA,
        "replay_verified": True,
        "state_hashes_verified": True,
        "rng_transcript_verified": True,
        "legal_actions_verified": True,
        "selected_actions_verified": True,
        "attack_costs_verified": True,
        "canonical_records_verified": True,
    }


def _action(action_class: str, actor: str, parameters: object | None = None) -> dict[str, object]:
    canonical_parameters = {} if parameters is None else parameters
    return {
        "action_class": action_class,
        "actor_player_id": actor,
        "canonical_parameters": canonical_parameters,
        "canonical_action_sha256": trace_features._action_digest(action_class, actor, canonical_parameters),
    }


def _record(
    game_id: str,
    sequence: int,
    record_type: str,
    payload: dict[str, object],
    *,
    actor: str | None = None,
    ordinal: int | None = None,
    action_id: str | None = None,
) -> dict[str, object]:
    return {
        "schema_id": TRACE_SCHEMA,
        "game_id": game_id,
        "sequence_number": sequence,
        "record_type": record_type,
        "engine_tick": sequence,
        "actor_player_id": actor,
        "turn_owner_player_id": actor,
        "regular_turn_ordinal": ordinal,
        "phase_id": "MAIN",
        "action_instance_id": action_id,
        "parent_action_instance_id": None,
        "state_before_sha256": _hash((game_id, "state", sequence)),
        "state_after_sha256": _hash((game_id, "state", sequence + 1)),
        "payload": payload,
    }


def _game(
    control: int = 0,
    seed: int = 0,
    orientation: int = 0,
    *,
    terminal: bool = False,
    control_wins: bool = False,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    game_id = f"c{control}-s{seed}-o{orientation}"
    candidate, control_player = "K", "B"
    records: list[dict[str, object]] = []

    def add(kind: str, payload: dict[str, object], **kwargs: object) -> None:
        records.append(_record(game_id, len(records), kind, payload, **kwargs))

    if not terminal:
        for ordinal in range(1, 5):
            for player in (candidate, control_player):
                add("TURN_START", {"player_id": player, "regular_turn_ordinal": ordinal, "turn_kind": "REGULAR"}, actor=player, ordinal=ordinal)
                add("MANDATORY_PROCESSING_COMPLETE", {"player_id": player, "regular_turn_ordinal": ordinal, "mandatory_draw_completed": True, "status_processing_completed": True}, actor=player, ordinal=ordinal)
                actions = [_action("DECLARE_ATTACK", player)] if player == candidate else [_action("END_TURN", player)]
                add(
                    "FIRST_DECISION_CHECKPOINT",
                    {
                        "player_id": player,
                        "regular_turn_ordinal": ordinal,
                        "state_sha256": _hash((game_id, "state", len(records) + 1)),
                        "canonical_legal_action_set_sha256": canonical_legal_action_set_sha256(actions),
                        "canonical_legal_actions": actions,
                        "attack_phase_permitted": True,
                    },
                    actor=player,
                    ordinal=ordinal,
                )
                if player == candidate:
                    action_id = f"attack-{ordinal}"
                    chosen = actions[0]
                    add(
                        "ACTION_CHOSEN",
                        {
                            "player_id": player,
                            "action_instance_id": action_id,
                            "action_class": "DECLARE_ATTACK",
                            "action_definition_id": "attack",
                            "canonical_parameters": chosen["canonical_parameters"],
                            "canonical_action_sha256": chosen["canonical_action_sha256"],
                            "legal_action_set_sha256": canonical_legal_action_set_sha256(actions),
                        },
                        actor=player,
                        ordinal=ordinal,
                        action_id=action_id,
                    )
                    add(
                        "ATTACK_DECLARE",
                        {
                            "player_id": player,
                            "action_instance_id": action_id,
                            "attack_definition_id": "attack",
                            "effective_attack_cost_definition_sha256": _hash("cost"),
                            "effective_required_attack_cost_units": 1,
                            "mandatory_additional_energy_units_consumed_to_declare": 0,
                        },
                        actor=player,
                        ordinal=ordinal,
                        action_id=action_id,
                    )
                    add(
                        "DAMAGE_APPLIED",
                        {
                            "source_action_instance_id": action_id,
                            "source_actor_player_id": player,
                            "damage_kind": DIRECT_DAMAGE_KIND,
                            "target_object_id": "target",
                            "target_owner_player_id": control_player,
                            "raw_damage_hp": 20,
                            "applied_damage_hp": 20,
                            "target_hp_before": 100,
                            "target_hp_after": 80,
                            "weakness_modifier": 0,
                            "resistance_modifier": 0,
                            "prevention_amount": 0,
                        },
                        actor=player,
                        ordinal=ordinal,
                    )
                    if ordinal == 2:
                        add(
                            "PRIZE_ZONE_CHANGE",
                            {"player_id": player, "prize_count_before": 6, "prize_count_after": 5, "reason_code": "KNOCKOUT", "source_action_instance_id": action_id},
                            actor=player,
                            ordinal=ordinal,
                        )
                add("TURN_END", {"player_id": player, "regular_turn_ordinal": ordinal, "end_reason": "NORMAL"}, actor=player, ordinal=ordinal)
    add(
        "GAME_END",
        {
            "winner_player_id": control_player if control_wins else candidate,
            "terminal_reason": "COMPLETE",
            "terminal_sequence_number": len(records),
            "terminal_state_sha256": _hash((game_id, "state", len(records) + 1)),
        },
    )
    header = {
        "schema_id": TRACE_SCHEMA,
        "game_id": game_id,
        "candidate_archive_sha256": _hash("candidate"),
        "control_archive_sha256": _hash(("control", control)),
        "candidate_source_tree_sha256": _hash("candidate-source"),
        "control_source_tree_sha256": _hash(("control-source", control)),
        "engine_sha256": _hash("engine"),
        "ruleset_sha256": _hash("rules"),
        "card_catalog_sha256": _hash("catalog"),
        "candidate_deck_manifest_root": _hash("candidate-deck"),
        "control_deck_manifest_root": _hash(("control-deck", control)),
        "common_seed_id": f"seed-{seed}",
        "common_seed_material_sha256": _hash(("seed", seed)),
        "orientation": orientation,
        "candidate_seat": orientation,
        "control_seat": 1 - orientation,
        "starting_player_id": candidate if orientation == 0 else control_player,
        "player_roles": {"candidate": candidate, "control": control_player},
        "initial_prize_count": 6,
        "damage_counter_unit_hp": 10,
        "initial_state_sha256": records[0]["state_before_sha256"],
        "final_state_sha256": records[-1]["state_after_sha256"],
    }
    return header, records


def _issued_game(**kwargs: object):
    header, records = _game(**kwargs)
    return make_replay_verified_game(header, records, _receipt())


@pytest.fixture(scope="module")
def full_panel():
    return [
        _issued_game(control=control, seed=seed, orientation=orientation)
        for control in range(4)
        for seed in range(300)
        for orientation in (0, 1)
    ]


def test_f1_to_f6_x_and_r_use_candidate_sign_and_fixed_serialization(full_panel) -> None:
    panel = full_panel
    result = extract_offline_trace_features(panel)
    assert result.features == {
        "F1": "0.166666666667",
        "F2": "1.000000000000",
        "F3": "0.666666666667",
        "F4": "0.500000000000",
        "F5": "1.000000000000",
        "F6": "0.000000000000",
    }
    assert result.x == "0.555555555556"
    assert result.r == "1.000000000000"
    assert result.exact_rationals["F1"] == ExactRational("1", "6")
    assert result.exact_rationals["F3"] == ExactRational("2", "3")
    assert result.exact_rationals["F6"] == ExactRational("0", "1")
    assert result.exact_rationals["x"] == ExactRational("5", "9")
    assert result.exact_rationals["R"] == ExactRational("1", "1")
    assert result.feature_point.x == result.exact_rationals["x"]
    assert result.feature_point.mpfr256_projection_sha256 == result.mpfr256_projection_sha256
    assert len(result.seed_pair_sufficient_statistics) == 4 * 300
    assert result.seed_pair_sufficient_statistics[0].orientation_zero.f3_damage == (8, 0)
    with pytest.raises(ValueError):
        ExactRational("2", "4")
    with pytest.raises(ValueError):
        ExactRational("0", "7")
    assert set(result.pre_serialization_mpfr256) == {"F1", "F2", "F3", "F4", "F5", "F6", "x", "R"}
    assert result.control_count == 4 and result.seeds_per_control == 300


def test_terminal_neutral_rules_and_missing_checkpoint_fail_closed() -> None:
    terminal = _issued_game(terminal=True)
    counts = derive_game_feature_counts(terminal)
    assert counts.f2_count == (0, 0)
    assert trace_features._pair_features(counts, counts)[1] == 0
    assert trace_features._pair_features(counts, counts)[3] == 0
    assert trace_features._pair_features(counts, counts)[4] == 0

    header, records = _game()
    records = [record for record in records if not (record["record_type"] == "FIRST_DECISION_CHECKPOINT" and record["actor_player_id"] == "B" and record["regular_turn_ordinal"] == 1)]
    for sequence, record in enumerate(records):
        record["sequence_number"] = sequence
        record["engine_tick"] = sequence
        record["state_before_sha256"] = _hash((header["game_id"], "state", sequence))
        record["state_after_sha256"] = _hash((header["game_id"], "state", sequence + 1))
        if record["record_type"] == "FIRST_DECISION_CHECKPOINT":
            record["payload"]["state_sha256"] = record["state_after_sha256"]
        if record["record_type"] == "GAME_END":
            record["payload"]["terminal_sequence_number"] = sequence
            record["payload"]["terminal_state_sha256"] = record["state_after_sha256"]
    header["final_state_sha256"] = records[-1]["state_after_sha256"]
    with pytest.raises(TraceFeatureError) as caught:
        derive_game_feature_counts(make_replay_verified_game(header, records, _receipt()))
    assert caught.value.code == "LOCAL_RESOURCE_CHECKPOINT_INVALID"


def test_action_whitelist_damage_cost_and_seat_pair_guards(full_panel) -> None:
    header, records = _game()
    unknown = records[2]["payload"]["canonical_legal_actions"][0]
    unknown["action_class"] = "MYSTERY"
    unknown["canonical_action_sha256"] = trace_features._action_digest("MYSTERY", "K", {})
    records[2]["payload"]["canonical_legal_action_set_sha256"] = canonical_legal_action_set_sha256(records[2]["payload"]["canonical_legal_actions"])
    with pytest.raises(TraceFeatureError) as caught:
        make_replay_verified_game(header, records, _receipt())
    assert caught.value.code == "LOCAL_ACTION_CLASS_UNRESOLVED"

    header, records = _game()
    next(record for record in records if record["record_type"] == "DAMAGE_APPLIED")["payload"]["damage_kind"] = "POISON"
    with pytest.raises(TraceFeatureError) as caught:
        derive_game_feature_counts(make_replay_verified_game(header, records, _receipt()))
    assert caught.value.code == "LOCAL_DAMAGE_EVENT_UNCLASSIFIED"

    header, records = _game()
    next(record for record in records if record["record_type"] == "ATTACK_DECLARE")["payload"]["effective_required_attack_cost_units"] = -1
    with pytest.raises(TraceFeatureError) as caught:
        make_replay_verified_game(header, records, _receipt())
    assert caught.value.code == "LOCAL_ATTACK_COST_UNRESOLVED"

    with pytest.raises(TraceFeatureError) as caught:
        extract_offline_trace_features(full_panel[:-1])
    assert caught.value.code == "LOCAL_SEAT_PAIR_INCOMPLETE"


def test_control_and_common_seed_bindings_cannot_drift_across_panel(full_panel) -> None:
    changed = list(full_panel)
    header, records = _game(control=1, seed=0, orientation=0)
    header["control_deck_manifest_root"] = _hash("substituted-control-deck")
    replacement = make_replay_verified_game(header, records, _receipt())
    index = next(
        i
        for i, game in enumerate(changed)
        if game.header["control_archive_sha256"] == replacement.header["control_archive_sha256"]
        and game.header["common_seed_id"] == replacement.header["common_seed_id"]
        and game.header["orientation"] == 0
    )
    changed[index] = replacement
    with pytest.raises(TraceFeatureError) as caught:
        extract_offline_trace_features(changed)
    assert caught.value.code == "LOCAL_DECK_MANIFEST_MISMATCH"

    changed = list(full_panel)
    for orientation in (0, 1):
        header, records = _game(control=1, seed=0, orientation=orientation)
        header["common_seed_material_sha256"] = _hash("substituted-common-seed")
        replacement = make_replay_verified_game(header, records, _receipt())
        index = next(
            i
            for i, game in enumerate(changed)
            if game.header["control_archive_sha256"] == replacement.header["control_archive_sha256"]
            and game.header["common_seed_id"] == replacement.header["common_seed_id"]
            and game.header["orientation"] == orientation
        )
        changed[index] = replacement
    with pytest.raises(TraceFeatureError) as caught:
        extract_offline_trace_features(changed)
    assert caught.value.code == "LOCAL_COMMON_SEED_MISMATCH"


def test_outputs_are_offline_conformance_and_never_authority(full_panel) -> None:
    assert trace_features.CALLER_RECEIPT_AUTHENTICITY_PATH_RETIRED is True
    result = extract_offline_trace_features(full_panel)
    assert result.offline_conformance_only is True
    assert result.trace_authenticity_verified is False
    assert result.official_wrapper_parity_verified is False
    assert result.authority is False
    assert result.calibration_upload_authorized is False
    assert result.production_upload_authorized is False
    assert result.sealed_holdout_access_authorized is False
    assert result.agent_modification_authorized is False
    assert result.permits == ()
    assert result.report["permits"] == ()
