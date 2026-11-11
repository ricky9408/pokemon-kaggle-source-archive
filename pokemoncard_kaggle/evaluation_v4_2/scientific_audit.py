"""Pure scientific audit for the retired VOI-P5 v4.1 claim.

The audit is deliberately an arithmetic and schema-boundary function.  It does
not read evidence, contact a service, inspect a holdout, or authorize a
submission.  In particular, an audit result with no blockers is still only a
scientific-design statement; the ``ANCHOR_ALLOWED`` field is false unless the
design meets this module's prospective matching and independence requirements.
"""

from __future__ import annotations

import hashlib
import json
import math
from numbers import Real
import re
from typing import Any, Mapping


INPUT_SCHEMA = "evaluation_v4_2_scientific_audit_input_v1"
RESULT_SCHEMA = "evaluation_v4_2_scientific_audit_result_v1"
ANCHOR_ALLOWED = "ANCHOR_ALLOWED"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INPUT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "total_lineages",
        "family_count",
        "pair_count",
        "signs",
        "assumed_per_pair_selector_accuracy",
        "target_endpoint",
        "within_pair_outcomes_share_opponents",
        "within_pair_outcomes_share_seeds",
        "within_pair_outcomes_share_matchmaking",
        "family_independence_demonstrated",
        "pair_independence_demonstrated",
    }
)
_INPUT_FIELDS = _INPUT_CONTENT_FIELDS | {"content_sha256"}
_RESULT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "input_content_sha256",
        "total_lineages",
        "family_count",
        "pair_count",
        "positive_sign_count",
        "all_positive_observed",
        "nominal_all_positive_null_probability",
        "demonstrated_independent_components",
        "dependence_aware_effective_independent_blocks",
        "dependence_aware_null_probability_lower_resolution",
        "all_positive_power",
        "fatal_blockers",
        ANCHOR_ALLOWED,
    }
)
_RESULT_FIELDS = _RESULT_CONTENT_FIELDS | {"content_sha256"}


class ScientificAuditError(ValueError):
    """A scientific-audit input or result is malformed or tampered."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the one JSON encoding used for all audit content hashes."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ScientificAuditError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash a JSON value after canonical serialization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ScientificAuditError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ScientificAuditError(f"{label} must be a lowercase SHA-256")
    return value


def _positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ScientificAuditError(f"{label} must be a positive integer")
    return value


def _probability(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ScientificAuditError(f"{label} must be a finite probability")
    result = float(value)
    if not math.isfinite(result) or not 0.0 <= result <= 1.0:
        raise ScientificAuditError(f"{label} must be a finite probability in [0, 1]")
    return result


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise ScientificAuditError(f"{label} must be boolean")
    return value


def _normalized_sign(value: object, *, label: str) -> int:
    # Accept common transport spellings, but seal one canonical integer form.
    if value in (1, "+", "positive", "POSITIVE"):
        return 1
    if value in (-1, "-", "negative", "NEGATIVE"):
        return -1
    raise ScientificAuditError(f"{label} must be a positive or negative sign")


def _endpoint_is_matched(value: str) -> bool:
    """Recognize an endpoint that explicitly binds opponent and seed matching."""

    return (
        value.startswith("matched_")
        and "opponent" in value
        and "seed" in value
        and "win_rate" in value
    )


def _normalize_input(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _INPUT_FIELDS, label="scientific audit input")
    content = {field: raw[field] for field in _INPUT_CONTENT_FIELDS}
    if raw["content_sha256"] != canonical_sha256(content):
        raise ScientificAuditError("scientific audit input content_sha256 mismatch")
    _sha256(raw["content_sha256"], label="content_sha256")

    if content["schema"] != INPUT_SCHEMA:
        raise ScientificAuditError(f"schema must be {INPUT_SCHEMA!r}")
    total_lineages = _positive_int(content["total_lineages"], label="total_lineages")
    family_count = _positive_int(content["family_count"], label="family_count")
    pair_count = _positive_int(content["pair_count"], label="pair_count")
    if total_lineages < 2 * pair_count:
        raise ScientificAuditError("total_lineages must cover two lineages per pair")

    signs = content["signs"]
    if not isinstance(signs, list) or len(signs) != pair_count:
        raise ScientificAuditError("signs must contain exactly pair_count entries")
    normalized_signs = [
        _normalized_sign(item, label=f"signs[{index}]") for index, item in enumerate(signs)
    ]
    accuracy = _probability(
        content["assumed_per_pair_selector_accuracy"],
        label="assumed_per_pair_selector_accuracy",
    )
    endpoint = content["target_endpoint"]
    if not isinstance(endpoint, str) or not endpoint or endpoint.strip() != endpoint:
        raise ScientificAuditError("target_endpoint must be a non-empty trimmed string")
    booleans = {
        field: _boolean(content[field], label=field)
        for field in (
            "within_pair_outcomes_share_opponents",
            "within_pair_outcomes_share_seeds",
            "within_pair_outcomes_share_matchmaking",
            "family_independence_demonstrated",
            "pair_independence_demonstrated",
        )
    }
    return {
        "schema": INPUT_SCHEMA,
        "total_lineages": total_lineages,
        "family_count": family_count,
        "pair_count": pair_count,
        "signs": normalized_signs,
        "assumed_per_pair_selector_accuracy": accuracy,
        "target_endpoint": endpoint,
        **booleans,
        "content_sha256": raw["content_sha256"],
    }


def build_scientific_audit_input(content: Mapping[str, Any]) -> dict[str, Any]:
    """Build and validate a hash-sealed audit input from hash-free content."""

    if not isinstance(content, Mapping) or "content_sha256" in content:
        raise ScientificAuditError("scientific audit input builder accepts hash-free content")
    # Reconstructing through the normalizer also canonicalizes sign spellings.
    candidate = dict(content)
    if set(candidate) != _INPUT_CONTENT_FIELDS:
        _exact_fields(candidate, _INPUT_CONTENT_FIELDS, label="scientific audit input content")
    normalized_without_hash = _normalize_input(
        {**candidate, "content_sha256": canonical_sha256(candidate)}
    )
    content_only = {field: normalized_without_hash[field] for field in _INPUT_CONTENT_FIELDS}
    return {**content_only, "content_sha256": canonical_sha256(content_only)}


def validate_scientific_audit_input(value: object) -> dict[str, Any]:
    """Validate an immutable, exactly shaped, hash-sealed audit input."""

    return _normalize_input(value)


def _fatal_blockers(spec: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not _endpoint_is_matched(spec["target_endpoint"]):
        blockers.append("TARGET_ENDPOINT_NOT_MATCHED_OPPONENT_SEEDED_WIN_RATE")
    if not spec["within_pair_outcomes_share_opponents"]:
        blockers.append("WITHIN_PAIR_OPPONENTS_NOT_MATCHED")
    if not spec["within_pair_outcomes_share_seeds"]:
        blockers.append("WITHIN_PAIR_SEEDS_NOT_MATCHED")
    if not spec["within_pair_outcomes_share_matchmaking"]:
        blockers.append("WITHIN_PAIR_MATCHMAKING_NOT_MATCHED")
    if not spec["family_independence_demonstrated"]:
        blockers.append("FAMILY_INDEPENDENCE_NOT_DEMONSTRATED")
    if not spec["pair_independence_demonstrated"]:
        blockers.append("PAIR_INDEPENDENCE_NOT_DEMONSTRATED")
    if spec["family_count"] < spec["pair_count"]:
        blockers.append("FAMILY_COUNT_BELOW_PAIR_COUNT")
    if any(sign != 1 for sign in spec["signs"]):
        blockers.append("NOT_ALL_SIGNS_POSITIVE")
    return blockers


def audit_scientific_claim(value: object) -> dict[str, Any]:
    """Compute the read-only v4.1 claim audit for a sealed input."""

    spec = validate_scientific_audit_input(value)
    pairs = spec["pair_count"]
    family_count = spec["family_count"]
    accuracy = spec["assumed_per_pair_selector_accuracy"]

    nominal = round(0.5**pairs, 12)
    # A block is credited only for a demonstrated decomposition.  Pair-level
    # proof is stronger than family-level proof; absent either, one block is
    # the only defensible resolution.  Family count remains a hard cap.
    if spec["pair_independence_demonstrated"]:
        demonstrated_components = pairs
    elif spec["family_independence_demonstrated"]:
        demonstrated_components = family_count
    else:
        demonstrated_components = 1
    effective_blocks = min(pairs, family_count, demonstrated_components)
    dependence_aware = round(0.5**effective_blocks, 12)
    power = round(accuracy**pairs, 12)
    blockers = _fatal_blockers(spec)
    content = {
        "schema": RESULT_SCHEMA,
        "input_content_sha256": spec["content_sha256"],
        "total_lineages": spec["total_lineages"],
        "family_count": family_count,
        "pair_count": pairs,
        "positive_sign_count": sum(sign == 1 for sign in spec["signs"]),
        "all_positive_observed": all(sign == 1 for sign in spec["signs"]),
        "nominal_all_positive_null_probability": nominal,
        "demonstrated_independent_components": demonstrated_components,
        "dependence_aware_effective_independent_blocks": effective_blocks,
        "dependence_aware_null_probability_lower_resolution": dependence_aware,
        "all_positive_power": power,
        "fatal_blockers": blockers,
        ANCHOR_ALLOWED: not blockers,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_scientific_audit_result(value: object) -> dict[str, Any]:
    """Validate a computed result and recompute its sealed content hash."""

    raw = _exact_fields(value, _RESULT_FIELDS, label="scientific audit result")
    content = {field: raw[field] for field in _RESULT_CONTENT_FIELDS}
    _sha256(raw["content_sha256"], label="content_sha256")
    if raw["content_sha256"] != canonical_sha256(content):
        raise ScientificAuditError("scientific audit result content_sha256 mismatch")
    if content["schema"] != RESULT_SCHEMA:
        raise ScientificAuditError(f"schema must be {RESULT_SCHEMA!r}")
    _sha256(content["input_content_sha256"], label="input_content_sha256")
    for field in ("total_lineages", "family_count", "pair_count"):
        _positive_int(content[field], label=field)
    if (
        isinstance(content["positive_sign_count"], bool)
        or not isinstance(content["positive_sign_count"], int)
        or not 0 <= content["positive_sign_count"] <= content["pair_count"]
    ):
        raise ScientificAuditError("positive_sign_count must be an integer in [0, pair_count]")
    if content["positive_sign_count"] > content["pair_count"]:
        raise ScientificAuditError("positive_sign_count cannot exceed pair_count")
    if not isinstance(content["all_positive_observed"], bool):
        raise ScientificAuditError("all_positive_observed must be boolean")
    if content["all_positive_observed"] != (
        content["positive_sign_count"] == content["pair_count"]
    ):
        raise ScientificAuditError("all_positive_observed does not match positive_sign_count")
    _probability(
        content["nominal_all_positive_null_probability"],
        label="nominal_all_positive_null_probability",
    )
    _positive_int(
        content["demonstrated_independent_components"],
        label="demonstrated_independent_components",
    )
    _positive_int(
        content["dependence_aware_effective_independent_blocks"],
        label="dependence_aware_effective_independent_blocks",
    )
    if content["dependence_aware_effective_independent_blocks"] > min(
        content["pair_count"],
        content["family_count"],
        content["demonstrated_independent_components"],
    ):
        raise ScientificAuditError("effective independent blocks exceed pair/family resolution")
    _probability(
        content["dependence_aware_null_probability_lower_resolution"],
        label="dependence_aware_null_probability_lower_resolution",
    )
    _probability(content["all_positive_power"], label="all_positive_power")
    if not isinstance(content["fatal_blockers"], list) or any(
        not isinstance(item, str) or not item for item in content["fatal_blockers"]
    ):
        raise ScientificAuditError("fatal_blockers must be a list of non-empty strings")
    if not isinstance(content[ANCHOR_ALLOWED], bool):
        raise ScientificAuditError(f"{ANCHOR_ALLOWED} must be boolean")
    if content[ANCHOR_ALLOWED] != (not content["fatal_blockers"]):
        raise ScientificAuditError(f"{ANCHOR_ALLOWED} must be false when blockers exist")
    return {**content, "content_sha256": raw["content_sha256"]}


# Short names are useful to callers while the explicit names remain the
# canonical API used in reports and tests.
build_audit_input = build_scientific_audit_input
validate_audit_input = validate_scientific_audit_input
evaluate_scientific_audit = audit_scientific_claim


__all__ = [
    "ANCHOR_ALLOWED",
    "INPUT_SCHEMA",
    "RESULT_SCHEMA",
    "ScientificAuditError",
    "audit_scientific_claim",
    "build_audit_input",
    "build_scientific_audit_input",
    "canonical_json_bytes",
    "canonical_sha256",
    "evaluate_scientific_audit",
    "validate_audit_input",
    "validate_scientific_audit_input",
    "validate_scientific_audit_result",
]
