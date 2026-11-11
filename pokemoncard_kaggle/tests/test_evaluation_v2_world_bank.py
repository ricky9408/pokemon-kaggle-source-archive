from __future__ import annotations

from collections import Counter
from copy import deepcopy

import pytest

from evaluation_v2.world_bank import build_world_bank


def _deck(*required: int) -> list[int]:
    cards = list(required)
    cards.extend(range(100, 100 + 60 - len(cards)))
    return cards


def _observation() -> dict:
    return {
        "current": {
            "yourIndex": 0,
            "turn": 4,
            "firstPlayer": 0,
            "energyAttached": True,
            "retreated": False,
            "stadiumPlayed": False,
            "supporterPlayed": True,
            "turnActionCount": 2,
            "stadium": [],
            "players": [
                {
                    "deckCount": 49,
                    "handCount": 2,
                    "hand": [{"id": 1, "playerIndex": 0}, {"id": 2, "playerIndex": 0}],
                    "active": [{"id": 3, "playerIndex": 0}],
                    "bench": [{"id": 4, "playerIndex": 0}],
                    "discard": [{"id": 5, "playerIndex": 0}],
                    "prize": [None] * 6,
                },
                {
                    "deckCount": 49,
                    "handCount": 2,
                    "hand": None,
                    "active": [None],
                    "bench": [{"id": 21, "playerIndex": 1}],
                    "discard": [{"id": 22, "playerIndex": 1}],
                    "prize": [None] * 6,
                },
            ],
        },
        "logs": [{"private_debug": "ignored"}],
        "remainingOverageTime": 123.45,
        "search_begin_input": "ignored",
    }


def _meta_entries() -> list[dict]:
    return [
        {"deck_hash": "compatible", "cards": _deck(21, 22)},
        {"deck_hash": "incompatible", "cards": _deck(21, 23)},
    ]


def test_world_bank_is_deterministic_and_snapshot_order_independent() -> None:
    observation = _observation()
    own_deck = _deck(1, 2, 3, 4, 5)
    first = build_world_bank(observation, own_deck, _meta_entries())
    second = build_world_bank(deepcopy(observation), list(own_deck), list(reversed(_meta_entries())))

    assert first == second
    assert len(first.worlds) == 1
    assert first.worlds[0].world_id == first.worlds[0].stable_hash[:20]


def test_every_world_preserves_exact_card_multiplicities() -> None:
    own_deck = _deck(1, 2, 3, 4, 5)
    compatible_deck = _meta_entries()[0]["cards"]
    bank = build_world_bank(_observation(), own_deck, _meta_entries())

    world = bank.worlds[0]
    assert Counter(world.own.all_cards()) == Counter(own_deck)
    assert Counter(world.opponent.all_cards()) == Counter(compatible_deck)
    assert 21 in world.opponent.bench
    assert 22 in world.opponent.discard
    assert len(world.own.prize) == len(world.opponent.prize) == 6
    assert len(world.opponent.active) == 1


def test_fixed_world_count_is_deterministic_and_conserving() -> None:
    own_deck = _deck(1, 2, 3, 4, 5)
    first = build_world_bank(_observation(), own_deck, _meta_entries(), world_count=8)
    second = build_world_bank(_observation(), own_deck, _meta_entries(), world_count=8)

    assert first == second
    assert len(first.worlds) == 8
    assert len({world.world_id for world in first.worlds}) == 8
    assert all(Counter(world.own.all_cards()) == Counter(own_deck) for world in first.worlds)


def test_world_count_cannot_drop_compatible_decks() -> None:
    observation = _observation()
    extra = {"cards": _deck(21, 22, 24), "episode_ids": [1]}
    with pytest.raises(ValueError, match="cover every compatible deck"):
        build_world_bank(observation, _deck(1, 2, 3, 4, 5), [_meta_entries()[0], extra], world_count=1)


def test_incompatible_opponent_decks_are_excluded_and_missing_coverage_fails_closed() -> None:
    bank = build_world_bank(_observation(), _deck(1, 2, 3, 4, 5), _meta_entries())
    assert len(bank.worlds) == 1
    assert Counter(bank.worlds[0].opponent.all_cards()) == Counter(_meta_entries()[0]["cards"])

    with pytest.raises(ValueError, match="no compatible opponent decks"):
        build_world_bank(_observation(), _deck(1, 2, 3, 4, 5), _meta_entries()[1:])


def test_seed_and_worlds_ignore_irrelevant_or_private_looking_metadata() -> None:
    baseline = build_world_bank(_observation(), _deck(1, 2, 3, 4, 5), _meta_entries())
    noisy = deepcopy(_observation())
    noisy["logs"] = [{"private_debug": "different"}]
    noisy["remainingOverageTime"] = 0.01
    noisy["search_begin_input"] = "different"
    noisy["private_note"] = {"serial": 999999}
    noisy["current"]["players"][0]["hand"][0]["serial"] = 123456

    assert build_world_bank(noisy, _deck(1, 2, 3, 4, 5), _meta_entries()) == baseline


def test_replay_rewards_and_private_opponent_hand_are_rejected() -> None:
    rewards = _observation()
    rewards["rewards"] = [1, -1]
    with pytest.raises(ValueError, match="forbidden non-public"):
        build_world_bank(rewards, _deck(1, 2, 3, 4, 5), _meta_entries())

    private_hand = _observation()
    private_hand["current"]["players"][1]["hand"] = [{"id": 22, "playerIndex": 1}]
    with pytest.raises(ValueError, match="opponent private hand"):
        build_world_bank(private_hand, _deck(1, 2, 3, 4, 5), _meta_entries())
