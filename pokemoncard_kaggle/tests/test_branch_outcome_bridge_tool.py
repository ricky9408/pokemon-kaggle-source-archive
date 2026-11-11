from tools.branch_outcome_bridge import (
    _legal_action_count,
    _selection_family,
    _selection_identity,
)


def _observation() -> dict:
    return {
        "current": {
            "yourIndex": 0,
            "players": [
                {
                    "hand": [{"id": 100}, {"id": 200}],
                },
                {"hand": None},
            ],
        },
        "select": {
            "context": 0,
            "minCount": 1,
            "maxCount": 1,
            "option": [
                {"index": 1, "type": 7},
                {"attackId": 55, "type": 13},
            ],
        },
    }


def test_play_family_resolves_card_from_actor_hand() -> None:
    observation = _observation()
    assert _selection_family(observation, (0,)) == "PLAY(200)"
    assert _selection_family(observation, (1,)) == "ATTACK(55)"


def test_selection_identity_matches_native_semantic_shape() -> None:
    observation = _observation()
    assert _selection_identity(observation["select"], (1,)) == '[{"attackId":55,"type":13}]'


def test_legal_action_count_respects_combination_bounds() -> None:
    select = {"option": [{}, {}, {}], "minCount": 1, "maxCount": 2}
    assert _legal_action_count(select) == 6
