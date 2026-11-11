from __future__ import annotations

from copy import deepcopy
import random

import pytest

from evaluation_v5_1.canonical import canonical_sha256
from evaluation_v5_1.prospective_transfer import (
    GAMES_PER_FAMILY,
    INPUT_SCHEMA,
    ProspectiveTransferValidationError,
    blinded_disclosure,
    evaluate_prospective_transfer,
    evaluate_synthetic_prospective_conformance,
)


def _hash(value: int) -> str:
    return f"{value:064x}"


def _panel(*, family_count: int = 20) -> dict[str, object]:
    t0_ns = 1_000_000_000
    lineages: list[dict[str, object]] = []
    games: list[dict[str, object]] = []
    serial = 1
    for family in range(family_count):
        archive = _hash(family + 1)
        target_wins = 40 + family * 6
        target = target_wins / GAMES_PER_FAMILY
        selector = min(1.0, target + 0.005)
        baseline = min(1.0, target + 0.100)
        lineages.append(
            {
                "family_id": f"family-{family:02d}",
                "ancestry_component_id": f"component-{family:02d}",
                "archive_sha256": archive,
                "runnable_receipt_sha256": _hash(1_000 + family),
                "selector_prediction": f"{selector:.12f}",
                "baseline_prediction": f"{baseline:.12f}",
                "local_episode_count": 10_000,
            }
        )
        base_wins, remainder = divmod(target_wins, 8)
        for opponent_bin, score in enumerate((700_000, 850_000, 950_000, 1_100_000)):
            for seat in (0, 1):
                stratum = opponent_bin * 2 + seat
                wins = base_wins + (1 if stratum < remainder else 0)
                for position in range(25):
                    timestamp = t0_ns + serial * 10
                    games.append(
                        {
                            "game_id": f"game-{family:02d}-{opponent_bin}-{seat}-{position:02d}",
                            "archive_sha256": archive,
                            "opponent_archive_sha256": _hash(
                                10_000 + family * 10 + ((stratum * 25 + position) % 10)
                            ),
                            "opponent_component_id": (
                                f"external-{family:02d}-"
                                f"{((stratum * 25 + position) % 10):02d}"
                            ),
                            "seat": seat,
                            "outcome": 1 if position < wins else 0,
                            "pre_game_opponent_score_milli": score,
                            "server_start_time_ns": timestamp,
                            "server_end_time_ns": timestamp + 1,
                            "source_row_sha256": _hash(100_000 + serial),
                            "collector_agreement": True,
                        }
                    )
                    serial += 1
    return {
        "schema": INPUT_SCHEMA,
        "campaign_id": "prospective-selector-campaign-01",
        "freeze": {
            "campaign_root_sha256": _hash(200_001),
            "selector_sha256": _hash(200_002),
            "baseline_sha256": _hash(200_003),
            "ancestry_graph_sha256": _hash(200_004),
            "cohort_sha256": _hash(200_005),
            "source_engine_sha256": _hash(200_006),
            "local_schedule_sha256": _hash(200_007),
            "feature_extractor_sha256": _hash(200_008),
            "eligibility_spec_sha256": _hash(200_009),
            "statistics_spec_sha256": _hash(200_010),
            "collector_pair_sha256": _hash(200_011),
            "disclosure_recipient_key_sha256": _hash(200_012),
            "t0_ns": t0_ns,
            "t1_ns": t0_ns + 1_000_000_000,
            "opponent_score_quartiles_milli": [800_000, 900_000, 1_000_000],
        },
        "lineages": lineages,
        "games": games,
        "collection_closed_at_ns": t0_ns + 1_000_000_000,
    }


def test_exact_prospective_panel_passes_all_four_claims_without_authority() -> None:
    result = evaluate_synthetic_prospective_conformance(_panel())

    assert result["passed"] is False
    assert result["synthetic_conformance_passed"] is True
    assert result["decision"] == "SYNTHETIC_PROSPECTIVE_CONFORMANCE_ONLY"
    assert result["counts"] == {
        "families": 20,
        "selected_games": 4_000,
        "error_improvements": 20,
    }
    assert result["metrics"]["mean_absolute_error_ratio"] == "0.050000000000"
    assert result["metrics"]["selector_hosted_spearman"] == "1.000000000000"
    assert result["metrics"]["selector_top_archive_hosted_rank"] == 1
    assert result["authority"] is False
    assert result["candidate_development_authorized"] is False
    assert result["holdout_accessed"] is False
    assert result["submission_authorized"] is False


def test_exactly_20_ancestry_independent_families_are_required() -> None:
    result = evaluate_synthetic_prospective_conformance(_panel(family_count=12))
    assert result["passed"] is False
    assert "family_count_must_equal_20" in result["reasons"]

    panel = _panel()
    panel["lineages"][1]["ancestry_component_id"] = panel["lineages"][0][
        "ancestry_component_id"
    ]
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "ancestry-connected component" in result["reasons"][0]


def test_exact_25_games_per_eight_strata_and_window_are_enforced() -> None:
    panel = _panel()
    del panel["games"][0]
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert any(reason.startswith("missing_25_games:") for reason in result["reasons"])
    assert "prospective_panel_incomplete" in result["reasons"]

    panel = _panel()
    panel["games"][0]["server_end_time_ns"] = panel["freeze"]["t1_ns"]
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "outside the frozen" in result["reasons"][0]


def test_validation_archives_cannot_play_one_another() -> None:
    panel = _panel()
    panel["games"][0]["opponent_archive_sha256"] = panel["lineages"][1]["archive_sha256"]
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "may not oppose" in result["reasons"][0]


def test_opponent_diversity_and_max_contribution_are_mandatory() -> None:
    panel = _panel()
    archive = panel["lineages"][0]["archive_sha256"]
    rows = [row for row in panel["games"] if row["archive_sha256"] == archive]
    for row in rows:
        row["opponent_archive_sha256"] = _hash(900_000)
        row["opponent_component_id"] = "one-external-component"
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert any(
        reason.startswith("fewer_than_10_distinct_opponent_components")
        for reason in result["reasons"]
    )
    assert any(
        reason.startswith("opponent_component_contributes_more_than_20_games")
        for reason in result["reasons"]
    )


def test_ties_count_for_baseline_and_all_four_criteria_are_conjunctive() -> None:
    panel = _panel()
    for row in panel["lineages"]:
        row["selector_prediction"] = row["baseline_prediction"]
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert result["counts"]["error_improvements"] == 0
    assert "selector_improves_fewer_than_15_lineages" in result["reasons"]
    assert "mean_absolute_error_ratio_exceeds_0.80" in result["reasons"]

    panel = _panel()
    predictions = [row["selector_prediction"] for row in panel["lineages"]]
    for row, prediction in zip(panel["lineages"], reversed(predictions)):
        row["selector_prediction"] = prediction
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "selector_hosted_spearman_below_0.50" in result["reasons"]
    assert "selector_top_archive_hosted_rank_exceeds_5" in result["reasons"]


def test_earliest_25_selection_and_input_order_are_deterministic() -> None:
    panel = _panel()
    first = evaluate_synthetic_prospective_conformance(panel)
    random.Random(20260714).shuffle(panel["games"])
    random.Random(42).shuffle(panel["lineages"])
    second = evaluate_synthetic_prospective_conformance(panel)

    assert first == second


def test_blinded_disclosure_reveals_no_lineage_metrics_or_authority() -> None:
    result = evaluate_synthetic_prospective_conformance(_panel())
    disclosure = blinded_disclosure(result)

    assert disclosure == {
        "schema": "evaluation_v5_1_prospective_transfer_disclosure_v1",
        "decision": "TERMINAL_FAILURE",
        "result_sha256": result["content_sha256"],
        "authority": False,
        "candidate_development_authorized": False,
        "holdout_access_authorized": False,
        "submission_authorized": False,
    }


def test_malformed_probabilities_and_collector_disagreement_fail_closed() -> None:
    panel = _panel()
    panel["lineages"][0]["selector_prediction"] = "0.5"
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "12 decimals" in result["reasons"][0]

    panel = _panel()
    panel["games"][0]["collector_agreement"] = False
    result = evaluate_synthetic_prospective_conformance(panel)
    assert result["passed"] is False
    assert "collectors do not agree" in result["reasons"][0]


def test_no_threshold_override_or_alternative_input_path_exists() -> None:
    try:
        evaluate_synthetic_prospective_conformance(_panel(), minimum_spearman="0.1")
    except TypeError:
        pass
    else:
        raise AssertionError("threshold override was accepted")

    try:
        evaluate_synthetic_prospective_conformance(evidence=_panel(), games=[])
    except TypeError:
        pass
    else:
        raise AssertionError("alternative input path was accepted")


def test_input_is_not_mutated() -> None:
    panel = _panel()
    before = deepcopy(panel)
    evaluate_synthetic_prospective_conformance(panel)
    assert panel == before


def test_production_entry_and_disclosure_hard_close_without_trusted_services() -> None:
    result = evaluate_prospective_transfer(_panel())

    assert result["decision"] == "FAIL_CLOSED"
    assert result["passed"] is False
    assert result["submission_authorized"] is False
    assert result["reasons"] == [
        "trusted_prospective_freeze_collector_and_disclosure_services_unavailable"
    ]
    assert blinded_disclosure(result)["decision"] == "TERMINAL_FAILURE"


def test_duplicate_source_rows_fail_synthetic_conformance() -> None:
    panel = _panel()
    panel["games"][1]["source_row_sha256"] = panel["games"][0]["source_row_sha256"]

    result = evaluate_synthetic_prospective_conformance(panel)

    assert result["decision"] == "FAIL_CLOSED"
    assert "globally unique" in result["reasons"][0]


def test_validation_ancestry_component_cannot_reenter_as_opponent() -> None:
    panel = _panel()
    panel["games"][0]["opponent_component_id"] = panel["lineages"][1][
        "ancestry_component_id"
    ]

    result = evaluate_synthetic_prospective_conformance(panel)

    assert result["decision"] == "FAIL_CLOSED"
    assert "ancestry components may not oppose" in result["reasons"][0]


def test_self_hashed_success_disclosure_is_rejected() -> None:
    forged = evaluate_synthetic_prospective_conformance(_panel())
    forged["decision"] = "PROSPECTIVE_SELECTOR_VALIDATED_RESEARCH_ONLY"
    forged.pop("content_sha256")
    forged["content_sha256"] = canonical_sha256(forged)

    with pytest.raises(ProspectiveTransferValidationError, match="trusted signed disclosure"):
        blinded_disclosure(forged)
