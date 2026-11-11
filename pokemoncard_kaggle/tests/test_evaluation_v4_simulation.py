from __future__ import annotations

from copy import deepcopy

import pytest

from evaluation_v4.simulation import compile_simulation_feature


def _panel() -> dict:
    engines = {"sample": "a" * 64, "source": "b" * 64}
    opponents = {
        "top-a": {"content_sha256": "c" * 64, "family_id": "control", "rating_layer": "top", "ood_mass": 0.04},
        "mid-b": {"content_sha256": "d" * 64, "family_id": "tempo", "rating_layer": "mid", "ood_mass": 0.08},
    }
    rows = []
    for engine in engines:
        for opponent in opponents:
            for seed in (11, 22):
                for left in (False, True):
                    rows.append(
                        {
                            "engine_variant": engine,
                            "opponent_model": opponent,
                            "seed": seed,
                            "candidate_left": left,
                            "candidate_outcome": 1.0,
                            "baseline_outcome": 0.0,
                            "candidate_error": None,
                            "baseline_error": None,
                            "candidate_max_action_seconds": 0.01,
                            "baseline_max_action_seconds": 0.01,
                        }
                    )
    return {
        "schema": "whole_policy_terminal_runs_v1",
        "candidate": {"label": "candidate", "archive_sha256": "e" * 64},
        "baseline": {"label": "baseline", "archive_sha256": "f" * 64},
        "engine_variants": engines,
        "opponent_models": opponents,
        "seeds": [11, 22],
        "rows": rows,
    }


def test_complete_positive_panel_compiles_without_authorization() -> None:
    result = compile_simulation_feature(_panel(), bootstrap_samples=100, seed=7)

    assert result["simulator_delta"] == 1.0
    assert result["minimum_engine_variant_mean"] == 1.0
    assert result["minimum_opponent_family_mean"] == 1.0
    assert result["minimum_rating_layer_mean"] == 1.0
    assert result["opponent_cluster_bootstrap_probability_positive"] == 1.0
    assert result["candidate_visited_ood_mass"] == 0.08
    assert "certified" not in result and "authorized" not in result


def test_missing_or_duplicate_cartesian_cell_is_rejected() -> None:
    missing = _panel()
    missing["rows"].pop()
    with pytest.raises(ValueError, match="exact Cartesian"):
        compile_simulation_feature(missing, bootstrap_samples=20)

    duplicate = _panel()
    duplicate["rows"].append(deepcopy(duplicate["rows"][0]))
    with pytest.raises(ValueError, match="duplicate matched cell"):
        compile_simulation_feature(duplicate, bootstrap_samples=20)


def test_any_execution_error_rejects_entire_panel() -> None:
    panel = _panel()
    panel["rows"][0]["candidate_error"] = "timeout"
    with pytest.raises(ValueError, match="execution error"):
        compile_simulation_feature(panel, bootstrap_samples=20)


def test_negative_engine_family_and_layer_remain_visible() -> None:
    panel = _panel()
    for row in panel["rows"]:
        if row["engine_variant"] == "source" and row["opponent_model"] == "mid-b":
            row["candidate_outcome"] = 0.0
            row["baseline_outcome"] = 1.0
    result = compile_simulation_feature(panel, bootstrap_samples=100, seed=3)

    assert result["engine_variant_means"]["source"] == 0.0
    assert result["opponent_family_means"]["tempo"] == 0.0
    assert result["rating_layer_means"]["mid"] == 0.0


def test_cluster_bootstrap_is_deterministic_and_input_is_not_mutated() -> None:
    panel = _panel()
    before = deepcopy(panel)
    first = compile_simulation_feature(panel, bootstrap_samples=80, seed=99)
    second = compile_simulation_feature(panel, bootstrap_samples=80, seed=99)
    assert first == second
    assert panel == before


def test_unknown_fields_and_same_archive_are_rejected() -> None:
    panel = _panel()
    panel["rows"][0]["unknown"] = True
    with pytest.raises(ValueError, match="fields must exactly"):
        compile_simulation_feature(panel, bootstrap_samples=20)
    panel = _panel()
    panel["baseline"]["archive_sha256"] = panel["candidate"]["archive_sha256"]
    with pytest.raises(ValueError, match="must differ"):
        compile_simulation_feature(panel, bootstrap_samples=20)
