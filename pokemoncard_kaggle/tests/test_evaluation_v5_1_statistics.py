from __future__ import annotations

from copy import deepcopy
import json

import pytest

from evaluation_v5_1.statistics import (
    INPUT_SCHEMA,
    evaluate_primary_gate,
    exact_binomial_upper_tail_numerator,
)


def _panel(
    *,
    successes: int = 15,
    positive_lift: str = "0.020000000000",
    negative_lift: str = "-0.001000000000",
) -> dict[str, object]:
    activation_round_robin = [block * 5 + position for position in range(5) for block in range(4)]
    success_indices = set(activation_round_robin[:successes])
    return {
        "schema": INPUT_SCHEMA,
        "families": [
            {
                "archive_sha256": f"{index + 1:064x}",
                "family_id": f"family-{index:02d}",
                "activation_block": index // 5,
                "lift": positive_lift if index in success_indices else negative_lift,
                "unresolved_rows": 0,
            }
            for index in range(20)
        ],
    }


def test_exact_20_family_boundary_15_passes_and_14_fails() -> None:
    passed = evaluate_primary_gate(_panel(successes=15))
    failed = evaluate_primary_gate(_panel(successes=14))

    assert passed["passed"] is True
    assert passed["counts"]["successes"] == 15
    assert passed["exact_test"]["p_value_numerator"] == 21700
    assert passed["exact_test"]["p_value_denominator"] == 2**20
    assert passed["metrics"]["exact_p_value"] == "0.020694732666"
    assert failed["passed"] is False
    assert "minimum_lift_exact_binomial_claim_failed" in failed["reasons"]


def test_success_requires_lift_at_least_0_010_not_merely_positive() -> None:
    result = evaluate_primary_gate(_panel(successes=20, positive_lift="0.009999999999"))
    assert result["counts"]["successes"] == 0
    assert result["primary_exact_pass"] is False


def test_mean_block_catastrophe_and_unresolved_are_conjunctive_vetoes() -> None:
    panel = _panel(successes=15)
    panel["families"][0]["lift"] = "-0.060000000000"
    panel["families"][1]["lift"] = "-0.060000000000"
    panel["families"][2]["unresolved_rows"] = 1
    result = evaluate_primary_gate(panel)

    assert result["passed"] is False
    assert "activation_block_mean_negative" in result["reasons"]
    assert "more_than_one_catastrophic_family" in result["reasons"]
    assert "unresolved_outcome_rows_nonzero" in result["reasons"]


@pytest.mark.parametrize("count", [19, 21])
def test_exact_family_count_is_mandatory(count: int) -> None:
    panel = _panel(successes=15)
    panel["families"] = panel["families"][:count]
    if count == 21:
        panel["families"].append(
            {
                "archive_sha256": f"{21:064x}",
                "family_id": "family-20",
                "activation_block": 3,
                "lift": "0.020000000000",
                "unresolved_rows": 0,
            }
        )
    result = evaluate_primary_gate(panel)
    assert result["passed"] is False
    assert "family_count_must_equal_20" in result["reasons"]


def test_exactly_one_archive_per_family_and_five_per_block() -> None:
    panel = _panel()
    panel["families"][1]["family_id"] = panel["families"][0]["family_id"]
    result = evaluate_primary_gate(panel)
    assert result["integrity_pass"] is False
    assert "more than one archive" in result["reasons"][0]

    panel = _panel()
    panel["families"][0]["activation_block"] = 1
    result = evaluate_primary_gate(panel)
    assert result["passed"] is False
    assert "activation_blocks_must_each_contain_5_families" in result["reasons"]


@pytest.mark.parametrize("lift", [0.02, "0.02", "nan", "0.0200000000000", "+0.020000000000"])
def test_lift_requires_canonical_12_decimal_string(lift: object) -> None:
    panel = _panel()
    panel["families"][0]["lift"] = lift
    result = evaluate_primary_gate(panel)
    assert result["integrity_pass"] is False
    assert "12-decimal" in result["reasons"][0]


def test_archive_identity_requires_real_sha256() -> None:
    panel = _panel()
    panel["families"][0]["archive_sha256"] = "archive-00"
    result = evaluate_primary_gate(panel)
    assert result["integrity_pass"] is False
    assert "SHA-256" in result["reasons"][0]


def test_result_is_order_invariant_hash_ready_and_never_authorizes() -> None:
    panel = _panel()
    before = deepcopy(panel)
    first = evaluate_primary_gate(panel)
    panel["families"] = list(reversed(panel["families"]))
    second = evaluate_primary_gate(panel)

    assert before["families"] == list(reversed(panel["families"]))
    assert first == second
    assert len(first["content_sha256"]) == 64
    assert first["authority"] is False
    assert first["submission_authorized"] is False
    assert first["production_submission_authorized"] is False
    assert first["holdout_accessed"] is False
    assert first["decision"] == "PASS_LEGACY_RESEARCH_ONLY"
    assert first["legacy_selector_retired"] is True
    assert first["protocol"]["bootstrap"] is False
    json.dumps(first, allow_nan=False, sort_keys=True)


def test_no_threshold_override_or_alternative_input_path_exists() -> None:
    with pytest.raises(TypeError):
        evaluate_primary_gate(_panel(), required_successes=14)
    with pytest.raises(TypeError):
        evaluate_primary_gate(archive_lifts=_panel())


def test_exact_tail_helper_matches_frozen_boundary() -> None:
    assert exact_binomial_upper_tail_numerator(20, 15) == 21700
