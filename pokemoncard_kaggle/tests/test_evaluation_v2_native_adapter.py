from dataclasses import dataclass

import pytest

from evaluation_v2.native_adapter import (
    derive_world_seed,
    enumerate_legal_selections,
    information_set_hash,
    native_search_arguments,
    semantic_selection,
)
from evaluation_v2.world_bank import BeliefWorld, PlayerWorld


def _player(*, active=(1,)) -> PlayerWorld:
    return PlayerWorld(
        deck=tuple(range(10, 50)),
        prize=(50, 51, 52, 53, 54, 55),
        hand=(56, 57, 58, 59, 60, 61),
        active=active,
        bench=(2, 3),
        discard=(4, 5, 6, 7, 8),
    )


def _world() -> BeliefWorld:
    return BeliefWorld("world", "a" * 64, 1, "deck", _player(), _player(active=(99,)))


def test_enumerates_every_legal_multiselect_without_truncation() -> None:
    select = {"minCount": 1, "maxCount": 2, "option": [{"type": 1}, {"type": 2}, {"type": 3}]}

    actions = enumerate_legal_selections(select)

    assert actions == ((0,), (1,), (2,), (0, 1), (0, 2), (1, 2))


def test_action_cap_fails_closed() -> None:
    select = {"minCount": 0, "maxCount": 5, "option": [{}] * 10}

    with pytest.raises(ValueError, match="cap"):
        enumerate_legal_selections(select, max_actions=20)


def test_semantic_selection_is_option_order_independent() -> None:
    first = {"option": [{"type": 7, "cardId": 10}, {"type": 14}]}
    second = {"option": [{"type": 14}, {"cardId": 10, "type": 7}]}

    assert semantic_selection(first, (0,)) == semantic_selection(second, (1,))


def test_information_set_ignores_transport_fields_and_option_order() -> None:
    base = {
        "current": {"yourIndex": 0, "turn": 3, "players": [{"hand": []}, {"hand": None}]},
        "select": {"context": 0, "minCount": 1, "maxCount": 1, "option": [{"type": 7}, {"type": 14}]},
        "logs": [{"type": 99}],
        "remainingOverageTime": 5,
        "search_begin_input": "private transport",
    }
    reordered = {
        **base,
        "select": {**base["select"], "option": list(reversed(base["select"]["option"]))},
        "logs": [],
        "remainingOverageTime": 999,
        "search_begin_input": "different",
    }

    assert information_set_hash(base) == information_set_hash(reordered)


def test_information_set_and_actions_ignore_engine_serial_renumbering() -> None:
    first = {
        "current": {
            "yourIndex": 0,
            "turn": 3,
            "players": [{"hand": [{"id": 19, "serial": 100}]}, {"hand": None}],
        },
        "select": {
            "context": 0,
            "minCount": 1,
            "maxCount": 1,
            "option": [{"type": 7, "index": 0, "serial": 100}],
        },
    }
    second = {
        "current": {
            "yourIndex": 0,
            "turn": 3,
            "players": [{"hand": [{"id": 19, "serial": 999}]}, {"hand": None}],
        },
        "select": {
            "context": 0,
            "minCount": 1,
            "maxCount": 1,
            "option": [{"type": 7, "index": 0, "serial": 999}],
        },
    }

    assert information_set_hash(first) == information_set_hash(second)
    assert semantic_selection(first["select"], (0,)) == semantic_selection(second["select"], (0,))


def test_native_arguments_use_hidden_world_and_only_predict_facedown_active() -> None:
    observation = {
        "current": {
            "yourIndex": 0,
            "players": [{"active": [{"id": 1}]}, {"active": [None]}],
        }
    }

    arguments = native_search_arguments(observation, _world())

    assert arguments["opponent_active"] == [99]
    assert arguments["opponent_hand"] == [56, 57, 58, 59, 60, 61]
    assert len(arguments["your_deck"]) == 40


def test_world_seed_is_stable_uint32() -> None:
    seed = derive_world_seed(_world())
    assert seed == derive_world_seed(_world())
    assert 0 <= seed <= 0xFFFFFFFF
