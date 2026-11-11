from pathlib import Path

import pytest

from tools.native_search_development_eval import _teacher_action, _validate_model_configuration


def test_teacher_action_reads_following_step() -> None:
    steps = [
        [{"observation": {}}, {"observation": {}}],
        [{"action": [2]}, {"action": [3]}],
    ]

    assert _teacher_action(steps, 0, 1) == [3]
    assert _teacher_action(steps, 1, 1) is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"policy_prior_weight": 1.0}, "requires a policy model"),
        ({"policy_prior_weight": -0.1}, "must be non-negative"),
        ({"value_weight": 0.5}, "requires a value model"),
        ({"value_weight": 1.1}, "between zero and one"),
    ],
)
def test_model_configuration_fails_closed(kwargs: dict, message: str) -> None:
    values = {
        "policy_model_path": None,
        "policy_fold_dir": None,
        "policy_prior_weight": 0.0,
        "value_model_path": None,
        "value_weight": 0.0,
    }
    values.update(kwargs)

    with pytest.raises(ValueError, match=message):
        _validate_model_configuration(**values)


def test_model_configuration_accepts_explicit_models() -> None:
    _validate_model_configuration(
        policy_model_path=Path("policy.json"),
        policy_fold_dir=None,
        policy_prior_weight=1.0,
        value_model_path=Path("value.bin"),
        value_weight=0.5,
    )
