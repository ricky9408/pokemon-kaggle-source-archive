import pytest

from evaluation_v2.option_forest import OptionForest


def _payload() -> dict:
    return {
        "schema": "cohort_option_forest_v1",
        "metadata": {"name": "test"},
        "feature_names": ["present"],
        "trees": [
            {
                "left": [1, -1, -1],
                "right": [2, -1, -1],
                "feature": [0, -2, -2],
                "threshold": [0.5, -2.0, -2.0],
                "probability": [0.0, 0.1, 0.9],
            }
        ],
    }


def test_forest_scores_sparse_features() -> None:
    model = OptionForest(_payload())
    assert model.score_features({}) == 0.1
    assert model.score_features({"present": 1.0}) == 0.9


def test_forest_rejects_unknown_schema() -> None:
    payload = _payload()
    payload["schema"] = "wrong"
    with pytest.raises(ValueError, match="schema"):
        OptionForest(payload)
