from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest

from evaluation_v4_2.analysis_contract import (
    ANALYSIS_CONTRACT_SCHEMA,
    FIRST_GAMES_PER_ARCHIVE,
    HOLDOUT_OPENING_RULE,
    MECHANISM_FAMILIES,
    PUBLIC_ENDPOINT,
    SELECTOR_PROTOCOL,
    STOPPING_RULE,
    THRESHOLDS,
    TRAINING_ROOTS,
    VALIDATION_PAIRS,
    VALIDATION_ROOTS,
    AnalysisContractError,
    build_analysis_contract,
    canonical_sha256,
    validate_analysis_contract,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _content() -> dict[str, object]:
    return {
        "schema": ANALYSIS_CONTRACT_SCHEMA,
        "analysis_id": "external-natural-intervention-v1",
        "feature_extractor_sha256": _sha("feature-extractor"),
        "predictor_model_sha256": _sha("predictor-model"),
        "analysis_program_sha256": _sha("analysis-program"),
        "decision_rule_sha256": _sha("decision-rule"),
        "alpha_ledger_sha256": _sha("alpha-ledger"),
        "holdout_rule_sha256": _sha("holdout-rule"),
        "training_manifest_sha256": _sha("training-manifest"),
        "burn_denylist_sha256": _sha("burn-denylist"),
        "selector_protocol": SELECTOR_PROTOCOL,
        "public_endpoint": PUBLIC_ENDPOINT,
        "training_roots": TRAINING_ROOTS,
        "validation_roots": VALIDATION_ROOTS,
        "validation_pairs": VALIDATION_PAIRS,
        "mechanism_families": MECHANISM_FAMILIES,
        "first_games_per_archive": FIRST_GAMES_PER_ARCHIVE,
        "thresholds": THRESHOLDS,
        "stopping_rule": STOPPING_RULE,
        "holdout_opening_rule": HOLDOUT_OPENING_RULE,
        "authority": "DEVELOPMENT_ONLY",
        "scientific_authority": False,
        "external_authority": False,
        "holdout_authorized": False,
        "submission_authorized": False,
        "state": "FROZEN",
    }


def test_builds_canonical_authority_free_contract() -> None:
    contract = build_analysis_contract(_content())

    assert contract["content_sha256"] == canonical_sha256(_content())
    assert validate_analysis_contract(contract) == contract
    assert contract["scientific_authority"] is False
    assert contract["holdout_authorized"] is False
    assert contract["submission_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pair_wins_min", 11),
        ("sign_test_p_max", 0.05),
        ("macro_log_loss_lift_min", 0.0),
    ],
)
def test_threshold_drift_is_rejected(field: str, value: object) -> None:
    content = _content()
    content["thresholds"] = {**THRESHOLDS, field: value}

    with pytest.raises(AnalysisContractError, match="thresholds"):
        build_analysis_contract(content)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("selector_protocol", "retired-local-win-rate"),
        ("public_endpoint", "first_24"),
        ("stopping_rule", "peek_and_replace"),
        ("holdout_authorized", True),
        ("submission_authorized", True),
    ],
)
def test_protocol_or_authority_drift_is_rejected(field: str, value: object) -> None:
    content = _content()
    content[field] = value

    with pytest.raises(AnalysisContractError, match=field):
        build_analysis_contract(content)


def test_hash_and_unknown_field_mutations_are_rejected() -> None:
    contract = build_analysis_contract(_content())
    bad_hash = deepcopy(contract)
    bad_hash["analysis_id"] = "changed"
    with pytest.raises(AnalysisContractError, match="content_sha256"):
        validate_analysis_contract(bad_hash)

    extra = deepcopy(contract)
    extra["passed"] = True
    with pytest.raises(AnalysisContractError, match="fields"):
        validate_analysis_contract(extra)
