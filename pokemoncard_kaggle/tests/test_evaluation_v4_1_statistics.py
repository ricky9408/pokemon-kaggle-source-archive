from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from evaluation_v4_1.statistics import (
    DECISION_CLOSED,
    DECISION_RESEARCH_ONLY,
    evaluate_voi_p5,
    write_voi_p5_result_once,
)


def _outcomes(value: float) -> list[float]:
    return [value] * 24


def _batch(*, tie_pair: int | None = None, negative_pair: int | None = None) -> dict[str, object]:
    pairs: list[dict[str, object]] = []
    for pair_index in range(5):
        family = f"family-{pair_index % 4}"
        is_tie = pair_index == tie_pair
        is_negative = pair_index == negative_pair
        a_outcome = 0.5 if is_tie else 0.0 if is_negative else 1.0
        b_outcome = 0.5 if is_tie else 1.0 if is_negative else 0.0
        pairs.append(
            {
                "pair_id": f"pair-{pair_index}",
                "family_id": family,
                "wave_id": "wave-3" if pair_index == 4 else "wave-1" if pair_index < 2 else "wave-2",
                "selected_member": "A",
                "members": {
                    "A": {
                        "lineage_id": f"lineage-{pair_index}-A",
                        "family_id": family,
                        "p0": 0.5,
                        "p1": 0.8 if not is_tie else 0.5,
                        "outcomes": _outcomes(a_outcome),
                    },
                    "B": {
                        "lineage_id": f"lineage-{pair_index}-B",
                        "family_id": family,
                        "p0": 0.5,
                        "p1": 0.2 if not is_tie else 0.5,
                        "outcomes": _outcomes(b_outcome),
                    },
                },
            }
        )
    return {
        "schema": "voi_p5_outcomes_v1",
        "protocol_sha256": "a" * 64,
        "pair_assignment_sha256": "b" * 64,
        "waves": [
            {"wave_id": "wave-1", "pair_ids": ["pair-0", "pair-1"]},
            {"wave_id": "wave-2", "pair_ids": ["pair-2", "pair-3"]},
            {"wave_id": "wave-3", "pair_ids": ["pair-4"]},
        ],
        "pairs": pairs,
    }


def test_all_five_positive_passes_primary_and_research_signal() -> None:
    result = evaluate_voi_p5(_batch())

    assert result["schema"] == "voi_p5_research_result_v1"
    assert result["integrity_pass"] is True
    assert result["primary_pass"] is True
    assert result["forecast_diagnostic_pass"] is True
    assert result["research_only"] is True
    assert result["decision"] == DECISION_RESEARCH_ONLY
    assert result["production_submission_authorized"] is False
    assert result["sealed_holdout_accessed"] is False
    assert result["positive_delta_count"] == 5
    assert result["sign_test_probability"] == 1 / 32
    assert result["macro_proper_score_lift"] > 0.015
    assert all(item["selected_minus_other_delta"] > 0 for item in result["pair_metrics"])


def test_tie_fails_even_when_other_pairs_are_positive() -> None:
    result = evaluate_voi_p5(_batch(tie_pair=4))

    assert result["positive_delta_count"] == 4
    assert result["sign_test_probability"] == 6 / 32
    assert result["primary_pass"] is False
    assert result["decision"] == DECISION_CLOSED


def test_four_of_five_positive_reports_exact_tail_and_never_passes() -> None:
    result = evaluate_voi_p5(_batch(negative_pair=4))

    assert result["positive_delta_count"] == 4
    assert result["sign_test_probability"] == 6 / 32
    assert result["primary_pass"] is False
    assert result["decision"] == DECISION_CLOSED


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda value: value["pairs"][0]["members"]["A"].__setitem__("outcomes", [1.0] * 23), "exactly 24"),
        (lambda value: value["pairs"][0]["members"]["B"].__setitem__("outcomes", [0.25] * 24), "one of"),
        (lambda value: value["pairs"][0]["members"]["A"].__setitem__("p0", 0.049), "[0.05, 0.95]"),
        (lambda value: value["pairs"][1]["members"]["B"].__setitem__("p1", 0.951), "[0.05, 0.95]"),
    ],
)
def test_malformed_outcome_or_probability_fails_the_entire_batch(mutate: object, message: str) -> None:
    value = _batch()
    mutate(value)  # type: ignore[operator]
    with pytest.raises(ValueError, match=message):
        evaluate_voi_p5(value)


def test_duplicate_lineage_family_and_wave_mismatches_are_rejected() -> None:
    duplicate_lineage = _batch()
    duplicate_lineage["pairs"][1]["members"]["A"]["lineage_id"] = "lineage-0-A"  # type: ignore[index]
    with pytest.raises(ValueError, match="duplicate lineage_id"):
        evaluate_voi_p5(duplicate_lineage)

    family_mismatch = _batch()
    family_mismatch["pairs"][0]["members"]["B"]["family_id"] = "other-family"  # type: ignore[index]
    with pytest.raises(ValueError, match="pair family_id"):
        evaluate_voi_p5(family_mismatch)

    wave_mismatch = _batch()
    wave_mismatch["pairs"][0]["wave_id"] = "wave-3"  # type: ignore[index]
    with pytest.raises(ValueError, match="wave assignment mismatch"):
        evaluate_voi_p5(wave_mismatch)


@pytest.mark.parametrize("injected_field", ["missing", "error", "replacement", "duplicate", "self_match"])
def test_forbidden_field_injection_is_rejected(injected_field: str) -> None:
    value = _batch()
    value["pairs"][0]["members"]["A"][injected_field] = False  # type: ignore[index]

    with pytest.raises(ValueError, match="fields must exactly"):
        evaluate_voi_p5(value)


def test_input_order_does_not_change_metrics_or_hash() -> None:
    original = _batch()
    reordered = deepcopy(original)
    reordered["pairs"] = list(reversed(reordered["pairs"]))  # type: ignore[assignment]
    reordered["waves"] = [
        {"wave_id": "wave-3", "pair_ids": ["pair-4"]},
        {"wave_id": "wave-2", "pair_ids": ["pair-3", "pair-2"]},
        {"wave_id": "wave-1", "pair_ids": ["pair-1", "pair-0"]},
    ]

    assert evaluate_voi_p5(original) == evaluate_voi_p5(reordered)


def test_result_write_is_create_once_and_canonical(tmp_path: Path) -> None:
    result = evaluate_voi_p5(_batch())
    path = tmp_path / "nested" / "voi-p5-result.json"

    assert write_voi_p5_result_once(path, result) == path
    assert json.loads(path.read_text(encoding="utf-8")) == result
    with pytest.raises(FileExistsError):
        write_voi_p5_result_once(path, result)
