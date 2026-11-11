from evaluation_v2.native_tree import public_leaf_value


def _observation(result: int = -1) -> dict:
    return {
        "current": {
            "result": result,
            "players": [
                {
                    "prize": [None] * 5,
                    "handCount": 5,
                    "active": [{"hp": 100, "energyCards": [{"id": 1}]}],
                    "bench": [{"hp": 50, "energyCards": []}],
                },
                {
                    "prize": [None] * 4,
                    "handCount": 3,
                    "active": [{"hp": 80, "energyCards": []}],
                    "bench": [],
                },
            ],
        }
    }


def test_public_leaf_value_is_antisymmetric_under_player_swap() -> None:
    observation = _observation()
    assert public_leaf_value(observation, 0) == -public_leaf_value(observation, 1)


def test_terminal_value_ignores_heuristic_material() -> None:
    observation = _observation(result=0)
    assert public_leaf_value(observation, 0) == 1.0
    assert public_leaf_value(observation, 1) == -1.0


def test_public_leaf_value_is_bounded() -> None:
    observation = _observation()
    observation["current"]["players"][0]["handCount"] = 1000
    assert public_leaf_value(observation, 0) == 0.95
