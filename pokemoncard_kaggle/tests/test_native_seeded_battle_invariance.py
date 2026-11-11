import pytest

from tools.native_seeded_battle_invariance import canonical_action, semantically_equal


def test_canonical_action_selects_minimum_prefix() -> None:
    observation = {
        "select": {
            "option": [{"type": 1}, {"type": 2}, {"type": 3}],
            "minCount": 2,
            "maxCount": 3,
        }
    }

    assert canonical_action(observation) == [0, 1]


def test_canonical_action_chooses_one_for_optional_nonempty_selection() -> None:
    observation = {"select": {"option": [{"type": 1}], "minCount": 0, "maxCount": 1}}

    assert canonical_action(observation) == [0]


def test_canonical_action_rejects_impossible_selection() -> None:
    with pytest.raises(ValueError, match="no options"):
        canonical_action({"select": {"option": [], "minCount": 1, "maxCount": 1}})


def test_semantic_equality_ignores_opaque_raw_serial_drift() -> None:
    first = {
        "seed": 7,
        "error": None,
        "steps": 10,
        "result": 0,
        "transcript_sha256": "semantic",
        "raw_transcript_sha256": "raw-a",
    }
    second = dict(first, raw_transcript_sha256="raw-b")

    assert semantically_equal(first, second)
