"""Frozen, authority-free analysis contract for one v4.2 campaign.

The contract prevents a complete local panel from being searched with an
analysis chosen after outcomes are visible.  It does not make the analysis
scientifically valid and cannot authorize a holdout or submission.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import re
from typing import Any


ANALYSIS_CONTRACT_SCHEMA = "evaluation_v4_2_analysis_contract_v1"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
SELECTOR_PROTOCOL = "prospective_external_natural_intervention_whole_policy_v1"
PUBLIC_ENDPOINT = "literal_first_96_completed_public_games_per_exact_archive"
STOPPING_RULE = "no_interim_looks_no_replacements_ties_fail"
HOLDOUT_OPENING_RULE = "open_once_only_after_prospective_selector_and_candidate_gates_pass"

TRAINING_ROOTS = 30
VALIDATION_ROOTS = 30
VALIDATION_PAIRS = 15
MECHANISM_FAMILIES = 5
FIRST_GAMES_PER_ARCHIVE = 96

THRESHOLDS = {
    "bootstrap_probability_lift_positive_min": 0.95,
    "candidate_lower_bound_min": 0.0,
    "candidate_predicted_mean_lift_min": 0.03,
    "macro_log_loss_lift_min": 0.015,
    "pair_wins_min": 12,
    "q10_lift_strictly_positive": True,
    "require_nonnegative_each_family": True,
    "sign_test_p_max": 0.017578125,
}

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "analysis_id",
        "feature_extractor_sha256",
        "predictor_model_sha256",
        "analysis_program_sha256",
        "decision_rule_sha256",
        "alpha_ledger_sha256",
        "holdout_rule_sha256",
        "training_manifest_sha256",
        "burn_denylist_sha256",
        "selector_protocol",
        "public_endpoint",
        "training_roots",
        "validation_roots",
        "validation_pairs",
        "mechanism_families",
        "first_games_per_archive",
        "thresholds",
        "stopping_rule",
        "holdout_opening_rule",
        "authority",
        "scientific_authority",
        "external_authority",
        "holdout_authorized",
        "submission_authorized",
        "state",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_ARTIFACT_FIELDS = (
    "feature_extractor_sha256",
    "predictor_model_sha256",
    "analysis_program_sha256",
    "decision_rule_sha256",
    "alpha_ledger_sha256",
    "holdout_rule_sha256",
    "training_manifest_sha256",
    "burn_denylist_sha256",
)


class AnalysisContractError(ValueError):
    """The preregistered analysis contract is malformed or authority-bearing."""


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AnalysisContractError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AnalysisContractError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise AnalysisContractError(f"{label} must be a lowercase SHA-256")
    return value


def _token(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(character.isspace() for character in value)
    ):
        raise AnalysisContractError(f"{label} must be a non-empty token")
    return value


def _normalize_content(value: object) -> dict[str, Any]:
    raw = _exact(value, _CONTENT_FIELDS, label="analysis contract content")
    if raw["schema"] != ANALYSIS_CONTRACT_SCHEMA:
        raise AnalysisContractError("analysis contract schema mismatch")
    artifacts = {field: _sha(raw[field], label=field) for field in _ARTIFACT_FIELDS}
    expected_literals = {
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
        "authority": DEVELOPMENT_AUTHORITY,
        "scientific_authority": False,
        "external_authority": False,
        "holdout_authorized": False,
        "submission_authorized": False,
        "state": "FROZEN",
    }
    for field, expected in expected_literals.items():
        if raw[field] != expected:
            raise AnalysisContractError(f"analysis contract {field} differs from the frozen protocol")
    return {
        "schema": ANALYSIS_CONTRACT_SCHEMA,
        "analysis_id": _token(raw["analysis_id"], label="analysis_id"),
        **artifacts,
        **expected_literals,
    }


def build_analysis_contract(content: Mapping[str, Any]) -> dict[str, Any]:
    if "content_sha256" in content:
        raise AnalysisContractError("analysis contract builder accepts hash-free content")
    normalized = _normalize_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def validate_analysis_contract(value: object) -> dict[str, Any]:
    raw = _exact(value, _FIELDS, label="analysis contract")
    normalized = _normalize_content({field: raw[field] for field in _CONTENT_FIELDS})
    digest = _sha(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(normalized):
        raise AnalysisContractError("analysis contract content_sha256 mismatch")
    expected = {**normalized, "content_sha256": digest}
    if dict(raw) != expected:
        raise AnalysisContractError("analysis contract is not canonical")
    return expected


__all__ = [
    "ANALYSIS_CONTRACT_SCHEMA",
    "AnalysisContractError",
    "DEVELOPMENT_AUTHORITY",
    "FIRST_GAMES_PER_ARCHIVE",
    "HOLDOUT_OPENING_RULE",
    "MECHANISM_FAMILIES",
    "PUBLIC_ENDPOINT",
    "SELECTOR_PROTOCOL",
    "STOPPING_RULE",
    "THRESHOLDS",
    "TRAINING_ROOTS",
    "VALIDATION_PAIRS",
    "VALIDATION_ROOTS",
    "build_analysis_contract",
    "canonical_json_bytes",
    "canonical_sha256",
    "validate_analysis_contract",
]
