from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from evaluation_v4_2.simulation_design import (
    FEATURE_SCHEMA,
    PANEL_SCHEMA,
    SEED_DERIVATION_ALGORITHM,
    TEMPLATE_SCHEMA,
    SimulationDesignError,
    build_candidate_panel,
    build_simulation_template,
    canonical_sha256,
    compile_candidate_features,
    derive_seeds,
    validate_candidate_features,
    validate_candidate_panel,
    validate_simulation_template,
)


def _digest(number: int) -> str:
    return f"{number:064x}"


def _template() -> dict[str, object]:
    layers = ("top", "mid", "low")
    families = ("control", "tempo", "spread", "toolbox", "lock")
    opponents = [
        {
            "opponent_id": f"opponent-{index:02d}",
            "archive_sha256": _digest(100 + index),
            "policy_content_sha256": _digest(200 + index),
            "deck_sha256": _digest(300 + index),
            "family_id": families[index % len(families)],
            "rating_layer": layers[index % len(layers)],
            "weight": 1.0 / 12.0,
            "ood_mass": 1.0 if layers[index % len(layers)] == "low" else 0.0,
        }
        for index in range(12)
    ]
    return {
        "schema": TEMPLATE_SCHEMA,
        "protocol_sha256": _digest(1),
        "scientific_plan_sha256": _digest(2),
        "runner_code_sha256": _digest(3),
        "dependency_lock_sha256": _digest(4),
        "runtime_binding_sha256": _digest(5),
        "engine_roster": [
            {
                "engine_id": "engine-a",
                "binary_sha256": _digest(10),
                "runtime_tree_sha256": _digest(12),
            },
            {
                "engine_id": "engine-b",
                "binary_sha256": _digest(11),
                "runtime_tree_sha256": _digest(13),
            },
        ],
        "opponent_roster": opponents,
        "seed_beacon_sha256": _digest(6),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "state": "FROZEN",
    }


def _rows(template: dict[str, object], *, positive: bool = True) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for engine in template["engine_roster"]:  # type: ignore[union-attr]
        for opponent in template["opponent_roster"]:  # type: ignore[union-attr]
            for seed in derive_seeds(template["seed_beacon_sha256"]):  # type: ignore[index]
                for seat in ("policy_first", "policy_second"):
                    rows.append(
                        {
                            "engine_id": engine["engine_id"],  # type: ignore[index]
                            "opponent_id": opponent["opponent_id"],  # type: ignore[index]
                            "seed": seed,
                            "seat": seat,
                            "candidate_outcome": 1.0 if positive else 0.0,
                            "baseline_outcome": 0.0 if positive else 1.0,
                            "candidate_runtime_seconds": 0.02,
                            "baseline_runtime_seconds": 0.03,
                            "candidate_error": None,
                            "baseline_error": None,
                        }
                    )
    return rows


def _panel(template: dict[str, object], candidate: str, *, positive: bool = True) -> dict[str, object]:
    return build_candidate_panel(
        template,
        candidate_archive_sha256=candidate,
        baseline_archive_sha256=_digest(90),
        ancestry_id="ancestry-1",
        rows=_rows(template, positive=positive),
    )


def test_template_is_candidate_neutral_and_has_exact_frozen_support() -> None:
    template = build_simulation_template(_template())

    assert template["schema"] == TEMPLATE_SCHEMA
    assert len(template["seeds"]) == 16
    assert len(set(template["seeds"])) == 16
    assert "candidate_archive_sha256" not in template
    assert "baseline_archive_sha256" not in template
    assert validate_simulation_template(template) == template


def test_same_template_reuses_cleanly_but_candidate_panels_and_features_differ() -> None:
    template = build_simulation_template(_template())
    first = _panel(template, _digest(91), positive=True)
    second = _panel(template, _digest(92), positive=False)

    first_features = compile_candidate_features(first, template)
    second_features = compile_candidate_features(second, template)

    assert first["template_content_sha256"] == second["template_content_sha256"] == template["content_sha256"]
    assert first["content_sha256"] != second["content_sha256"]
    assert first_features["schema"] == second_features["schema"] == FEATURE_SCHEMA
    assert first_features["content_sha256"] != second_features["content_sha256"]
    assert first_features["simulator_delta"] == 1.0
    assert second_features["simulator_delta"] == -1.0
    assert first_features["minimum_engine_mean"] == 1.0
    assert first_features["ood_mass"] == 4 / 12
    assert first["authority"] == first_features["authority"] == "DEVELOPMENT_ONLY"
    assert first["anchor_allowed"] is first_features["anchor_allowed"] is False
    assert (
        first["production_submission_authorized"]
        is first_features["production_submission_authorized"]
        is False
    )

    forged = deepcopy(first)
    forged["authority"] = "SUBMIT_AUTHORIZED"
    forged["anchor_allowed"] = True
    forged["production_submission_authorized"] = True
    forged_content = {key: value for key, value in forged.items() if key != "content_sha256"}
    forged["content_sha256"] = canonical_sha256(forged_content)
    with pytest.raises(SimulationDesignError, match="DEVELOPMENT_ONLY|external authority"):
        validate_candidate_panel(forged, template)


def test_panel_is_the_exact_engine_opponent_seed_seat_cartesian_grid() -> None:
    template = build_simulation_template(_template())
    panel = _panel(template, _digest(91))
    assert panel["schema"] == PANEL_SCHEMA
    assert len(panel["rows"]) == 2 * 12 * 16 * 2

    missing = deepcopy(panel)
    missing["rows"].pop()  # type: ignore[union-attr]
    with pytest.raises(SimulationDesignError, match="exact Cartesian"):
        validate_candidate_panel(missing, template)

    duplicate = deepcopy(panel)
    duplicate["rows"].append(deepcopy(duplicate["rows"][0]))  # type: ignore[union-attr]
    with pytest.raises(SimulationDesignError, match="duplicate terminal cell"):
        validate_candidate_panel(duplicate, template)


def test_template_candidate_field_and_raw_error_or_outcome_injection_is_rejected() -> None:
    content = _template()
    content["candidate_archive_sha256"] = _digest(91)
    with pytest.raises(SimulationDesignError, match="fields must exactly"):
        build_simulation_template(content)

    template = build_simulation_template(_template())
    panel = _panel(template, _digest(91))
    errored = deepcopy(panel)
    errored["rows"][0]["candidate_error"] = "timeout"  # type: ignore[index]
    with pytest.raises(SimulationDesignError, match="execution error"):
        validate_candidate_panel(errored, template)

    invalid_outcome = deepcopy(panel)
    invalid_outcome["rows"][0]["candidate_outcome"] = 0.25  # type: ignore[index]
    with pytest.raises(SimulationDesignError, match="exactly 0"):
        validate_candidate_panel(invalid_outcome, template)


def test_hash_tamper_and_caller_summary_injection_are_rejected() -> None:
    template = build_simulation_template(_template())
    panel = _panel(template, _digest(91))
    tampered_panel = deepcopy(panel)
    tampered_panel["candidate_archive_sha256"] = _digest(93)
    with pytest.raises(SimulationDesignError, match="content_sha256 mismatch"):
        validate_candidate_panel(tampered_panel, template)

    features = compile_candidate_features(panel, template)
    injected = deepcopy(features)
    injected["simulator_delta"] = 0.0
    injected_content = {key: value for key, value in injected.items() if key != "content_sha256"}
    injected["content_sha256"] = canonical_sha256(injected_content)
    with pytest.raises(SimulationDesignError, match="not derived from the raw panel"):
        validate_candidate_features(injected, panel, template)

    same_archive = deepcopy(panel)
    same_archive["baseline_archive_sha256"] = same_archive["candidate_archive_sha256"]
    with pytest.raises(SimulationDesignError, match="must differ"):
        validate_candidate_panel(same_archive, template)


def test_seed_derivation_and_feature_compilation_are_deterministic_without_side_effects(
    tmp_path: Path,
) -> None:
    template = build_simulation_template(_template())
    panel = _panel(template, _digest(91))
    before = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))

    first = compile_candidate_features(panel, template)
    second = compile_candidate_features(panel, template)
    after = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))

    assert first == second
    assert before == after == []
    assert derive_seeds(_digest(6)) == derive_seeds(_digest(6))
    expected = int.from_bytes(hashlib.sha256(f"{_digest(6)}:0".encode("ascii")).digest()[:8], "big") & ((1 << 63) - 1)
    assert derive_seeds(_digest(6))[0] == expected
