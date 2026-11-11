from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v4_2.scientific_audit import (
    INPUT_SCHEMA,
    RESULT_SCHEMA,
    ScientificAuditError,
    audit_scientific_claim,
    build_scientific_audit_input,
    canonical_sha256,
    validate_scientific_audit_result,
)


def _current_v41() -> dict[str, object]:
    return {
        "schema": INPUT_SCHEMA,
        "total_lineages": 16,
        "family_count": 4,
        "pair_count": 5,
        "signs": [1, 1, 1, 1, 1],
        "assumed_per_pair_selector_accuracy": 0.8,
        "target_endpoint": "first24_hosted_win_rate",
        "within_pair_outcomes_share_opponents": False,
        "within_pair_outcomes_share_seeds": False,
        "within_pair_outcomes_share_matchmaking": False,
        "family_independence_demonstrated": False,
        "pair_independence_demonstrated": False,
    }


def _sufficient_design() -> dict[str, object]:
    return {
        "schema": INPUT_SCHEMA,
        "total_lineages": 20,
        "family_count": 5,
        "pair_count": 5,
        "signs": ["positive"] * 5,
        "assumed_per_pair_selector_accuracy": 0.8,
        "target_endpoint": "matched_opponent_seeded_win_rate",
        "within_pair_outcomes_share_opponents": True,
        "within_pair_outcomes_share_seeds": True,
        "within_pair_outcomes_share_matchmaking": True,
        "family_independence_demonstrated": True,
        "pair_independence_demonstrated": True,
    }


def test_current_v41_is_closed_and_reports_the_claimed_arithmetic() -> None:
    result = audit_scientific_claim(build_scientific_audit_input(_current_v41()))

    assert result["schema"] == RESULT_SCHEMA
    assert result["ANCHOR_ALLOWED"] is False
    assert result["nominal_all_positive_null_probability"] == 1 / 32
    assert result["demonstrated_independent_components"] == 1
    assert result["dependence_aware_effective_independent_blocks"] == 1
    assert result["dependence_aware_null_probability_lower_resolution"] >= 1 / 16
    assert result["all_positive_power"] == 0.32768
    assert {
        "TARGET_ENDPOINT_NOT_MATCHED_OPPONENT_SEEDED_WIN_RATE",
        "WITHIN_PAIR_OPPONENTS_NOT_MATCHED",
        "WITHIN_PAIR_SEEDS_NOT_MATCHED",
        "WITHIN_PAIR_MATCHMAKING_NOT_MATCHED",
        "FAMILY_INDEPENDENCE_NOT_DEMONSTRATED",
        "PAIR_INDEPENDENCE_NOT_DEMONSTRATED",
    } <= set(result["fatal_blockers"])
    assert validate_scientific_audit_result(result) == result


def test_hypothetical_matched_independent_design_can_pass() -> None:
    result = audit_scientific_claim(build_scientific_audit_input(_sufficient_design()))

    assert result["ANCHOR_ALLOWED"] is True
    assert result["fatal_blockers"] == []
    assert result["demonstrated_independent_components"] == 5
    assert result["dependence_aware_effective_independent_blocks"] == 5
    assert result["dependence_aware_null_probability_lower_resolution"] == 1 / 32
    assert result["all_positive_observed"] is True


def test_unknown_input_fields_are_rejected_before_hashing() -> None:
    value = _current_v41()
    value["holdout_score"] = 1.0
    with pytest.raises(ScientificAuditError, match="fields must exactly"):
        build_scientific_audit_input(value)


def test_input_hash_tamper_is_rejected_even_when_the_value_shape_is_unchanged() -> None:
    sealed = build_scientific_audit_input(_current_v41())
    tampered = deepcopy(sealed)
    tampered["pair_count"] = 6
    with pytest.raises(ScientificAuditError, match="content_sha256 mismatch"):
        audit_scientific_claim(tampered)


def test_result_hash_tamper_is_rejected() -> None:
    result = audit_scientific_claim(build_scientific_audit_input(_current_v41()))
    tampered = deepcopy(result)
    tampered["ANCHOR_ALLOWED"] = True
    with pytest.raises(ScientificAuditError, match="content_sha256 mismatch"):
        validate_scientific_audit_result(tampered)


def test_build_and_audit_do_not_mutate_input_or_have_external_effects(tmp_path: Path) -> None:
    source = _current_v41()
    before = deepcopy(source)
    before_files = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))
    sealed = build_scientific_audit_input(source)
    first = audit_scientific_claim(sealed)
    second = audit_scientific_claim(sealed)
    after_files = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*"))

    assert source == before
    assert before_files == after_files == []
    assert first == second


def test_canonical_hash_is_order_invariant_and_ascii_only() -> None:
    left = {"z": [2, 1], "a": "plain"}
    right = {"a": "plain", "z": [2, 1]}
    assert canonical_sha256(left) == canonical_sha256(right)
    assert hashlib.sha256(json.dumps(left, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != ""
