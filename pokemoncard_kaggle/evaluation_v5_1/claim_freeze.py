"""Exact, zero-authority verifier for G07 primary-claim and validator freeze.

G07 is a freeze boundary, not a statistical result and not an authorization
boundary.  It validates the immutable scientific claim from raw canonical
bytes, then verifies that the evaluation authority signed that exact derived
payload and that an independent validator countersigned the exact authority
envelope bytes.  A signature only authenticates those bytes; it never replaces
the deterministic reconstruction below.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
from math import comb
import re
from typing import Any

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .envelope import EnvelopeError, verify_envelope


PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"
GATE_ID = "G07_PRIMARY_CLAIM_AND_VALIDATOR_FREEZE"
CLAIM_MANIFEST_SCHEMA = "evaluation_v5_1_g07_claim_manifest_v1"
ROLE_REGISTRY_SCHEMA = "evaluation_v5_1_g07_role_registry_v1"
FINAL_GATE_SCHEMA = "evaluation_v5_1_g07_final_gate_v1"
COUNTERSIGNATURE_SCHEMA = "evaluation_v5_1_g07_countersignature_v1"
CLOSED_AUDIT_SCHEMA = "evaluation_v5_1_g07_closed_audit_v1"
BYTE_WRAPPER_SCHEMA = "evaluation_v5_1_canonical_byte_wrapper_v1"
VALIDATOR_MEDIA_TYPE = "application/vnd.evaluation-v5-1.validator"
JCS_MEDIA_TYPE = "application/jcs+json"

AUTHORITY = False
DECISION = "G07_CLAIM_FREEZE_VERIFIED_ZERO_AUTHORITY"
FAIL_DECISION = "FAIL_CLOSED"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_DECIMAL12_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)\.[0-9]{12}$")

_ROOT_FIELDS = frozenset(
    {
        "campaign_root_sha256",
        "campaign_created_at_utc",
        "g00_root_sha256",
        "g00_frozen_at_utc",
        "g01_root_sha256",
        "g01_frozen_at_utc",
        "frozen_spec_sha256",
        "spec_frozen_at_utc",
        "campaign_registry_sha256",
        "validator_artifact_sha256",
    }
)
_ROLE_NAMES = ("evaluation_authority", "independent_validator")
_ROLE_FIELDS = frozenset(
    {
        "identity",
        "key_id",
        "algorithm",
        "public_key_ed25519_base64",
        "valid_from_utc",
        "valid_until_utc",
        "revoked",
    }
)
_BYTE_WRAPPER_FIELDS = frozenset(
    {"schema", "base64", "decoded_length", "sha256", "media_type"}
)

RAW_EVIDENCE_IDS = (
    "population",
    "metrics",
    "dependency_graph",
    "thresholds",
    "multiplicity_correction",
    "exclusions",
    "failure_rules",
    "evidence_requirements",
    "role_registry",
    "key_policy",
    "deadline_policy",
    "amendment_policy",
    "validator_artifact",
    "claim_manifest",
)
_MANIFEST_REFERENCE_IDS = RAW_EVIDENCE_IDS[:-1]

_DOCUMENT_SCHEMAS = {
    "population": "evaluation_v5_1_g07_population_v1",
    "metrics": "evaluation_v5_1_g07_metrics_v1",
    "dependency_graph": "evaluation_v5_1_g07_dependency_graph_v1",
    "thresholds": "evaluation_v5_1_g07_thresholds_v1",
    "multiplicity_correction": "evaluation_v5_1_g07_multiplicity_v1",
    "exclusions": "evaluation_v5_1_g07_exclusions_v1",
    "failure_rules": "evaluation_v5_1_g07_failure_rules_v1",
    "evidence_requirements": "evaluation_v5_1_g07_evidence_requirements_v1",
    "key_policy": "evaluation_v5_1_g07_key_policy_v1",
    "deadline_policy": "evaluation_v5_1_g07_deadline_policy_v1",
    "amendment_policy": "evaluation_v5_1_g07_amendment_policy_v1",
}

_CLAIM_DEFINITIONS = (
    {
        "claim_id": "C01_PRIMARY_TRANSFER_EFFECT",
        "kind": "primary_scientific_claim",
        "normative_text": (
            "For one archive from each frozen external family, MCI_V2 improves "
            "first-48 hosted per-game log loss over B_STAR_V2 by at least "
            "0.010000000000 nats/game in more than one half of families."
        ),
        "depends_on": [
            "C02_EXACT_BINOMIAL_TEST",
            "C03_CONJUNCTIVE_FAILURE_GUARDS",
            "C04_NO_INTERIM_SUBSTITUTION_OR_EXTENSION",
        ],
    },
    {
        "claim_id": "C02_EXACT_BINOMIAL_TEST",
        "kind": "primary_test",
        "normative_text": (
            "Use exactly one one-sided exact binomial test over 20 independent "
            "transitive families and reject only at 15 or more successes."
        ),
        "depends_on": ["C04_NO_INTERIM_SUBSTITUTION_OR_EXTENSION"],
    },
    {
        "claim_id": "C03_CONJUNCTIVE_FAILURE_GUARDS",
        "kind": "conjunctive_guard",
        "normative_text": (
            "Require the frozen mean, activation-block, catastrophic-family, and "
            "unresolved-row guards; descriptive analyses cannot rescue failure."
        ),
        "depends_on": ["C04_NO_INTERIM_SUBSTITUTION_OR_EXTENSION"],
    },
    {
        "claim_id": "C04_NO_INTERIM_SUBSTITUTION_OR_EXTENSION",
        "kind": "irreversibility_rule",
        "normative_text": (
            "There are no interim success looks, substitutions, extensions, "
            "replacement archives, alternate tests, or fallback thresholds."
        ),
        "depends_on": [],
    },
    {
        "claim_id": "C05_G07_ZERO_AUTHORITY",
        "kind": "authority_boundary",
        "normative_text": (
            "G07 verifies only a frozen claim and validator; it grants no candidate, "
            "holdout, release, or submission authority."
        ),
        "depends_on": [],
    },
)


class ClaimFreezeError(ValueError):
    """A G07 artifact is malformed, mutated, stale, or unbound."""


class _DuplicateJSONKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ClaimFreezeError(f"{label} fields are not exact")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ClaimFreezeError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise ClaimFreezeError(f"{label} must be a nonempty trimmed string")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise ClaimFreezeError(f"{label} must be canonical microsecond UTC")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ClaimFreezeError(f"{label} must be a real UTC timestamp") from exc
    if result.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ClaimFreezeError(f"{label} must be canonical microsecond UTC")
    return result


def _decimal12(value: object, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL12_RE.fullmatch(value) is None:
        raise ClaimFreezeError(f"{label} must be a canonical 12-decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ClaimFreezeError(f"{label} is not a Decimal") from exc
    if not result.is_finite() or format(result, ".12f") != value:
        raise ClaimFreezeError(f"{label} must be a finite canonical decimal")
    return result


def _base64(value: object, label: str, *, expected_length: int | None = None) -> bytes:
    if type(value) is not str:
        raise ClaimFreezeError(f"{label} must be a canonical base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ClaimFreezeError(f"{label} is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ClaimFreezeError(f"{label} is not canonical base64")
    if expected_length is not None and len(raw) != expected_length:
        raise ClaimFreezeError(f"{label} must decode to {expected_length} bytes")
    return raw


def wrap_canonical_bytes(raw: bytes, *, media_type: str) -> dict[str, Any]:
    """Return the only accepted raw-byte wrapper for G07 evidence."""

    if type(raw) is not bytes:
        raise ClaimFreezeError("raw evidence must be bytes")
    _text(media_type, "media_type")
    if not raw:
        raise ClaimFreezeError("raw evidence must be nonempty")
    return {
        "schema": BYTE_WRAPPER_SCHEMA,
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def decode_canonical_bytes(
    value: object, *, label: str, expected_media_type: str | None = None
) -> tuple[bytes, dict[str, Any]]:
    """Decode and revalidate a canonical base64 evidence wrapper."""

    wrapper = _exact(value, _BYTE_WRAPPER_FIELDS, label)
    if wrapper["schema"] != BYTE_WRAPPER_SCHEMA:
        raise ClaimFreezeError(f"{label} has the wrong byte-wrapper schema")
    raw = _base64(wrapper["base64"], f"{label}.base64")
    if type(wrapper["decoded_length"]) is not int or wrapper["decoded_length"] < 1:
        raise ClaimFreezeError(f"{label}.decoded_length must be a positive integer")
    if len(raw) != wrapper["decoded_length"]:
        raise ClaimFreezeError(f"{label}.decoded_length does not bind decoded bytes")
    if hashlib.sha256(raw).hexdigest() != _sha256(wrapper["sha256"], f"{label}.sha256"):
        raise ClaimFreezeError(f"{label}.sha256 does not bind decoded bytes")
    media_type = _text(wrapper["media_type"], f"{label}.media_type")
    if expected_media_type is not None and media_type != expected_media_type:
        raise ClaimFreezeError(f"{label}.media_type is not {expected_media_type!r}")
    return raw, dict(wrapper)


def _parse_jcs_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKey, ValueError) as exc:
        raise ClaimFreezeError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if type(parsed) is not dict:
        raise ClaimFreezeError(f"{label} must be a JSON object")
    try:
        if canonical_json_bytes(parsed) != raw:
            raise ClaimFreezeError(f"{label} is not exact canonical JCS bytes")
    except CanonicalJSONError as exc:
        raise ClaimFreezeError(f"{label} is not canonical JSON: {exc}") from exc
    return parsed


def _validate_roots(value: object) -> tuple[dict[str, Any], dict[str, datetime]]:
    roots = _exact(value, _ROOT_FIELDS, "dependency_roots")
    for field in (
        "campaign_root_sha256",
        "g00_root_sha256",
        "g01_root_sha256",
        "frozen_spec_sha256",
        "campaign_registry_sha256",
        "validator_artifact_sha256",
    ):
        _sha256(roots[field], field)
    times = {
        "campaign": _timestamp(roots["campaign_created_at_utc"], "campaign_created_at_utc"),
        "g00": _timestamp(roots["g00_frozen_at_utc"], "g00_frozen_at_utc"),
        "g01": _timestamp(roots["g01_frozen_at_utc"], "g01_frozen_at_utc"),
        "spec": _timestamp(roots["spec_frozen_at_utc"], "spec_frozen_at_utc"),
    }
    if not (times["campaign"] < times["g00"] < times["g01"] <= times["spec"]):
        raise ClaimFreezeError("campaign, G00, G01, and spec chronology is invalid")
    return dict(roots), times


def _validate_roles(value: object, *, at: datetime) -> dict[str, dict[str, Any]]:
    if type(value) is not dict or set(value) != set(_ROLE_NAMES):
        raise ClaimFreezeError("trusted role registry must declare authority and independent validator exactly")
    identities: set[str] = set()
    key_ids: set[str] = set()
    keys: set[bytes] = set()
    result: dict[str, dict[str, Any]] = {}
    for role in _ROLE_NAMES:
        item = _exact(value[role], _ROLE_FIELDS, f"{role} role")
        identity = _text(item["identity"], f"{role}.identity")
        key_id = _text(item["key_id"], f"{role}.key_id")
        if item["algorithm"] != "Ed25519":
            raise ClaimFreezeError(f"{role} must use Ed25519")
        key = _base64(item["public_key_ed25519_base64"], f"{role}.public_key_ed25519_base64", expected_length=32)
        start = _timestamp(item["valid_from_utc"], f"{role}.valid_from_utc")
        end = _timestamp(item["valid_until_utc"], f"{role}.valid_until_utc")
        if start >= end or not start <= at < end:
            raise ClaimFreezeError(f"{role} key is stale or outside its validity interval")
        if item["revoked"] is not False:
            raise ClaimFreezeError(f"{role} key is revoked")
        if identity in identities or key_id in key_ids or key in keys:
            raise ClaimFreezeError("G07 role identities, key IDs, and Ed25519 public keys must be distinct")
        identities.add(identity)
        key_ids.add(key_id)
        keys.add(key)
        result[role] = {**item, "public_key_bytes": key}
    return result


def _static_documents() -> dict[str, dict[str, Any]]:
    """The frozen normative terms.  Dynamic identities and roots live elsewhere."""

    return {
        "population": {
            "schema": _DOCUMENT_SCHEMAS["population"],
            "protocol_id": PROTOCOL_ID,
            "population_id": "EXTERNAL_CONFIRMATORY",
            "family_count": 20,
            "archives_per_family": 1,
            "family_definition": "full_undirected_transitive_ancestry_component",
            "archive_selection": "one_preregistered_archive_per_family",
            "outcome_partition": "EXTERNAL_CONFIRMATORY",
            "first48_definition": "first_48_hosted_episodes_ordered_by_server_started_at_then_episode_id_after_maturity_window",
        },
        "metrics": {
            "schema": _DOCUMENT_SCHEMAS["metrics"],
            "protocol_id": PROTOCOL_ID,
            "metric_id": "D_F_FIRST48_HOSTED_LOG_LOSS_LIFT",
            "formula": "mean_g_1_to_48(log_loss(B_STAR_V2,y_fg)-log_loss(MCI_V2,y_fg))",
            "success_indicator": "I_f=1[D_f>=0.010000000000]",
            "comparator": "single_deterministic_DEV_selected_B_STAR_V2",
            "outcome_source": "interface_observable_first48_hosted_per_game_log_loss",
        },
        "thresholds": {
            "schema": _DOCUMENT_SCHEMAS["thresholds"],
            "protocol_id": PROTOCOL_ID,
            "minimum_family_lift": "0.010000000000",
            "minimum_family_count": 20,
            "required_successes": 15,
            "one_sided_alpha": "0.025000000000",
            "exact_tail_numerator": 21700,
            "exact_tail_denominator": 1048576,
            "minimum_family_weighted_mean_lift": "0.010000000000",
            "activation_block_count": 4,
            "minimum_activation_block_mean": "0.000000000000",
            "catastrophic_family_lift": "-0.050000000000",
            "maximum_catastrophic_families": 1,
            "maximum_unresolved_outcome_rows": 0,
        },
        "multiplicity_correction": {
            "schema": _DOCUMENT_SCHEMAS["multiplicity_correction"],
            "protocol_id": PROTOCOL_ID,
            "familywise_alpha": "0.025000000000",
            "method": "single_primary_exact_binomial_no_recycling",
            "comparison_count": 1,
            "allocations": [
                {"test_id": "C02_EXACT_BINOMIAL_TEST", "alpha": "0.025000000000"}
            ],
            "hierarchy": False,
            "recycling": False,
            "post_hoc_metric_removal": False,
        },
        "exclusions": {
            "schema": _DOCUMENT_SCHEMAS["exclusions"],
            "protocol_id": PROTOCOL_ID,
            "permitted_partition": "EXTERNAL_CONFIRMATORY",
            "excluded_partitions": ["DEV_BURNED", "PROSPECTIVE_SHADOW", "SEALED_50"],
            "outcome_conditioned_inclusion": False,
            "feature_revision_after_outcome": False,
            "parser_revision_after_outcome": False,
            "family_splitting_after_outcome": False,
            "model_refit_after_outcome": False,
        },
        "failure_rules": {
            "schema": _DOCUMENT_SCHEMAS["failure_rules"],
            "protocol_id": PROTOCOL_ID,
            "insufficient_support_is_failure": True,
            "unresolved_rows_are_failure": True,
            "missing_or_duplicate_family_is_failure": True,
            "replacement_archive_is_failure": True,
            "alternate_test_is_failure": True,
            "fallback_threshold_is_failure": True,
            "descriptive_analysis_can_rescue_failure": False,
        },
        "evidence_requirements": {
            "schema": _DOCUMENT_SCHEMAS["evidence_requirements"],
            "protocol_id": PROTOCOL_ID,
            "raw_evidence_ids": list(_MANIFEST_REFERENCE_IDS),
            "byte_wrapper_schema": BYTE_WRAPPER_SCHEMA,
            "canonical_json_media_type": JCS_MEDIA_TYPE,
            "validator_media_type": VALIDATOR_MEDIA_TYPE,
            "producer_pass_flags_authoritative": False,
            "private_keys_permitted": False,
        },
        "key_policy": {
            "schema": _DOCUMENT_SCHEMAS["key_policy"],
            "protocol_id": PROTOCOL_ID,
            "required_roles": ["evaluation_authority", "independent_validator"],
            "algorithm": "Ed25519",
            "identities_must_be_distinct": True,
            "public_keys_must_be_distinct": True,
            "validity_must_cover_freeze_and_finalization": True,
            "revoked_keys_permitted": False,
            "private_keys_permitted": False,
            "authority_signature_binding": "exact_canonical_final_gate_payload",
            "validator_countersignature_binding": "exact_authority_envelope_jcs_bytes",
        },
        "deadline_policy": {
            "schema": _DOCUMENT_SCHEMAS["deadline_policy"],
            "protocol_id": PROTOCOL_ID,
            "freeze_before": "EXTERNAL_CONFIRMATORY_OUTCOMES_EXIST",
            "interim_success_looks": 0,
            "substitutions_permitted": False,
            "extensions_permitted": False,
            "finalization_must_not_precede_freeze": True,
            "finalization_must_be_within_key_validity": True,
        },
        "amendment_policy": {
            "schema": _DOCUMENT_SCHEMAS["amendment_policy"],
            "protocol_id": PROTOCOL_ID,
            "policy": "NO_POST_FREEZE_AMENDMENTS_FOR_CAMPAIGN_ROOT",
            "amendments": [],
            "post_freeze_mutation_result": "FAIL_CAMPAIGN",
            "new_campaign_root_required": True,
            "mutable_fields": [],
        },
    }


def _normative_graph() -> dict[str, Any]:
    return {
        "schema": _DOCUMENT_SCHEMAS["dependency_graph"],
        "protocol_id": PROTOCOL_ID,
        "claims": [
            {"claim_id": item["claim_id"], "depends_on": list(item["depends_on"])}
            for item in _CLAIM_DEFINITIONS
        ],
    }


def _topological_order(claims: object) -> list[str]:
    if type(claims) is not list or not claims:
        raise ClaimFreezeError("claim dependency graph must contain a nonempty ordered claims list")
    declared: dict[str, list[str]] = {}
    for index, raw in enumerate(claims):
        item = _exact(raw, frozenset({"claim_id", "depends_on"}), f"claim graph row {index}")
        claim_id = _text(item["claim_id"], f"claim graph row {index}.claim_id")
        dependencies = item["depends_on"]
        if type(dependencies) is not list or any(type(dep) is not str for dep in dependencies):
            raise ClaimFreezeError(f"claim graph row {index}.depends_on must be a string list")
        if len(dependencies) != len(set(dependencies)):
            raise ClaimFreezeError(f"claim graph row {index}.depends_on contains duplicates")
        if claim_id in declared:
            raise ClaimFreezeError("claim graph declares a duplicate claim")
        declared[claim_id] = list(dependencies)
    for claim_id, dependencies in declared.items():
        undeclared = sorted(set(dependencies) - set(declared))
        if undeclared:
            raise ClaimFreezeError(
                f"claim {claim_id} depends on undeclared claim {undeclared[0]}"
            )
    children = {claim_id: [] for claim_id in declared}
    indegree = {claim_id: len(dependencies) for claim_id, dependencies in declared.items()}
    for claim_id, dependencies in declared.items():
        for dependency in dependencies:
            children[dependency].append(claim_id)
    ready = sorted(claim_id for claim_id, degree in indegree.items() if degree == 0)
    result: list[str] = []
    while ready:
        current = ready.pop(0)
        result.append(current)
        for child in sorted(children[current]):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if len(result) != len(declared):
        raise ClaimFreezeError("claim dependency graph contains a cycle")
    return result


def _validate_normative_documents(documents: Mapping[str, dict[str, Any]]) -> list[str]:
    static = _static_documents()
    for evidence_id, expected in static.items():
        if documents[evidence_id] != expected:
            raise ClaimFreezeError(f"{evidence_id} does not equal the normative G07 document")
    graph = documents["dependency_graph"]
    order = _topological_order(graph["claims"])
    if graph != _normative_graph():
        raise ClaimFreezeError("claim dependency graph does not equal the normative G07 graph")
    return order


def _validate_thresholds(documents: Mapping[str, dict[str, Any]]) -> None:
    thresholds = documents["thresholds"]
    alpha = _decimal12(thresholds["one_sided_alpha"], "one_sided_alpha")
    _decimal12(thresholds["minimum_family_lift"], "minimum_family_lift")
    _decimal12(thresholds["minimum_family_weighted_mean_lift"], "minimum_family_weighted_mean_lift")
    _decimal12(thresholds["minimum_activation_block_mean"], "minimum_activation_block_mean")
    _decimal12(thresholds["catastrophic_family_lift"], "catastrophic_family_lift")
    if thresholds["minimum_family_count"] != 20 or thresholds["required_successes"] != 15:
        raise ClaimFreezeError("primary family count or success threshold is mutated")
    if type(thresholds["exact_tail_numerator"]) is not int or type(thresholds["exact_tail_denominator"]) is not int:
        raise ClaimFreezeError("exact tail representation must use integer numerator and denominator")
    expected_numerator = sum(comb(20, successes) for successes in range(15, 21))
    if (
        thresholds["exact_tail_numerator"] != expected_numerator
        or thresholds["exact_tail_denominator"] != 2**20
    ):
        raise ClaimFreezeError("exact binomial tail representation is mutated")
    if Decimal(expected_numerator) / Decimal(2**20) > alpha:
        raise ClaimFreezeError("primary success threshold exceeds the frozen alpha budget")
    if Decimal(sum(comb(20, successes) for successes in range(14, 21))) / Decimal(2**20) <= alpha:
        raise ClaimFreezeError("primary success threshold is not the minimum valid exact threshold")

    multiplicity = documents["multiplicity_correction"]
    familywise = _decimal12(multiplicity["familywise_alpha"], "familywise_alpha")
    allocations = multiplicity["allocations"]
    if type(allocations) is not list or multiplicity["comparison_count"] != len(allocations):
        raise ClaimFreezeError("multiplicity comparison count is inconsistent")
    spent = Decimal("0")
    seen: set[str] = set()
    for index, raw in enumerate(allocations):
        item = _exact(raw, frozenset({"test_id", "alpha"}), f"multiplicity allocation {index}")
        test_id = _text(item["test_id"], f"multiplicity allocation {index}.test_id")
        if test_id in seen:
            raise ClaimFreezeError("multiplicity allocation repeats a test")
        seen.add(test_id)
        amount = _decimal12(item["alpha"], f"multiplicity allocation {index}.alpha")
        if amount <= 0:
            raise ClaimFreezeError("multiplicity allocations must be positive")
        spent += amount
    if spent > familywise:
        raise ClaimFreezeError("multiplicity budget is overspent")
    if familywise != alpha or spent != familywise:
        raise ClaimFreezeError("multiplicity budget does not equal the frozen primary alpha")


def _validate_manifest(
    manifest: object,
    *,
    roots: Mapping[str, Any],
    wrappers: Mapping[str, Mapping[str, Any]],
    topological_order: list[str],
    freeze_time: datetime,
) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema",
            "protocol_id",
            "gate_id",
            "dependency_roots",
            "freeze_time_utc",
            "claims",
            "topological_order",
            "documents",
            "amendments",
        }
    )
    value = _exact(manifest, fields, "claim manifest")
    if value["schema"] != CLAIM_MANIFEST_SCHEMA or value["protocol_id"] != PROTOCOL_ID or value["gate_id"] != GATE_ID:
        raise ClaimFreezeError("claim manifest schema, protocol, or gate is invalid")
    manifest_roots, _ = _validate_roots(value["dependency_roots"])
    if manifest_roots != roots:
        raise ClaimFreezeError("claim manifest dependency roots do not equal pinned G00/G01/spec roots")
    if _timestamp(value["freeze_time_utc"], "claim manifest freeze_time_utc") != freeze_time:
        raise ClaimFreezeError("claim manifest freeze time is inconsistent")
    if freeze_time <= _timestamp(roots["spec_frozen_at_utc"], "spec_frozen_at_utc"):
        raise ClaimFreezeError("G07 freeze does not occur after the frozen specification")
    if value["claims"] != list(_CLAIM_DEFINITIONS):
        raise ClaimFreezeError("claim manifest declarations are hidden, missing, or non-normative")
    if value["topological_order"] != topological_order:
        raise ClaimFreezeError("claim manifest topological order is not the deterministic recomputation")
    if value["amendments"] != []:
        raise ClaimFreezeError("post-freeze amendments are forbidden for this campaign root")
    descriptors = value["documents"]
    if type(descriptors) is not list or len(descriptors) != len(_MANIFEST_REFERENCE_IDS):
        raise ClaimFreezeError("claim manifest document references are incomplete")
    expected_descriptors = [
        {
            "evidence_id": evidence_id,
            "sha256": wrappers[evidence_id]["sha256"],
            "decoded_length": wrappers[evidence_id]["decoded_length"],
            "media_type": wrappers[evidence_id]["media_type"],
        }
        for evidence_id in _MANIFEST_REFERENCE_IDS
    ]
    for index, descriptor in enumerate(descriptors):
        _exact(
            descriptor,
            frozenset({"evidence_id", "sha256", "decoded_length", "media_type"}),
            f"claim manifest document {index}",
        )
    if descriptors != expected_descriptors:
        raise ClaimFreezeError("claim manifest document references do not bind exact raw bytes")
    return value


def _scan_for_private_material(value: object, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            if key.lower() in {
                "private_key",
                "private_key_pem",
                "private_key_ed25519_base64",
                "secret_key",
                "secret_key_base64",
            }:
                raise ClaimFreezeError(f"private material is forbidden in artifact at {path}.{key}")
            _scan_for_private_material(child, path=f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _scan_for_private_material(child, path=f"{path}[{index}]")
    elif type(value) is str and "PRIVATE KEY" in value.upper():
        raise ClaimFreezeError(f"private material is forbidden in artifact at {path}")


def _closed(code: str, detail: str) -> dict[str, Any]:
    return {
        "schema": CLOSED_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": GATE_ID,
        "decision": FAIL_DECISION,
        "failure_codes": [{"code": code, "detail": detail}],
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "release_authorized": False,
        "submission_authorized": False,
    }


def _failure_code(error: Exception) -> str:
    text = str(error).lower()
    if "base64" in text or "decoded" in text or "byte-wrapper" in text:
        return "G07_MALFORMED_BYTE_EVIDENCE"
    if "cycle" in text:
        return "G07_CLAIM_DEPENDENCY_CYCLE"
    if "undeclared claim" in text:
        return "G07_UNDECLARED_CLAIM_REFERENCE"
    if "multiplicity" in text:
        return "G07_MULTIPLICITY_INVALID"
    if "threshold" in text or "binomial" in text or "tail" in text:
        return "G07_THRESHOLD_RECOMPUTATION_FAILED"
    if "exclusion" in text:
        return "G07_EXCLUSION_POLICY_MUTATED"
    if "amendment" in text or "mutation" in text:
        return "G07_AMENDMENT_POLICY_VIOLATION"
    if "chronology" in text or "freeze" in text or "stale" in text or "validity" in text:
        return "G07_CHRONOLOGY_OR_KEY_VALIDITY_FAILED"
    if "role" in text or "ed25519" in text or "revoked" in text or "private" in text:
        return "G07_ROLE_KEY_POLICY_FAILED"
    if "manifest" in text or "document" in text or "normative" in text:
        return "G07_MANIFEST_OR_REFERENCE_INVALID"
    if "hash" in text or "sha256" in text:
        return "G07_HASH_BINDING_FAILED"
    return "G07_EVIDENCE_INVALID"


def derive_claim_freeze_audit(
    *,
    dependency_roots: object,
    trusted_role_registry: object,
    evidence_blobs: object,
    finalized_at_utc: object,
) -> dict[str, Any]:
    """Recompute G07 from raw bytes without trusting a producer decision flag."""

    try:
        roots, _ = _validate_roots(dependency_roots)
        freeze_time = _timestamp(finalized_at_utc, "finalized_at_utc")
        if freeze_time <= _timestamp(roots["spec_frozen_at_utc"], "spec_frozen_at_utc"):
            raise ClaimFreezeError("G07 finalization precedes or equals the frozen specification")
        trusted_roles = _validate_roles(trusted_role_registry, at=freeze_time)
        if type(evidence_blobs) is not dict or set(evidence_blobs) != set(RAW_EVIDENCE_IDS):
            raise ClaimFreezeError("G07 evidence blobs must contain every raw artifact exactly once")

        wrappers: dict[str, dict[str, Any]] = {}
        documents: dict[str, dict[str, Any]] = {}
        for evidence_id in RAW_EVIDENCE_IDS:
            expected_media = VALIDATOR_MEDIA_TYPE if evidence_id == "validator_artifact" else JCS_MEDIA_TYPE
            raw, wrapper = decode_canonical_bytes(
                evidence_blobs[evidence_id], label=evidence_id, expected_media_type=expected_media
            )
            wrappers[evidence_id] = wrapper
            if evidence_id == "validator_artifact":
                if b"PRIVATE KEY" in raw.upper():
                    raise ClaimFreezeError("private material is forbidden in validator artifact")
                continue
            document = _parse_jcs_json(raw, evidence_id)
            _scan_for_private_material(document)
            documents[evidence_id] = document

        role_registry = _exact(
            documents["role_registry"],
            frozenset({"schema", "protocol_id", "campaign_root_sha256", "g00_root_sha256", "campaign_registry_sha256", "roles"}),
            "role registry evidence",
        )
        if (
            role_registry["schema"] != ROLE_REGISTRY_SCHEMA
            or role_registry["protocol_id"] != PROTOCOL_ID
            or role_registry["campaign_root_sha256"] != roots["campaign_root_sha256"]
            or role_registry["g00_root_sha256"] != roots["g00_root_sha256"]
            or role_registry["campaign_registry_sha256"] != roots["campaign_registry_sha256"]
        ):
            raise ClaimFreezeError("role registry does not bind the campaign and G00 trust root")
        evidence_roles = _validate_roles(role_registry["roles"], at=freeze_time)
        if {
            role: {key: value for key, value in trusted_roles[role].items() if key != "public_key_bytes"}
            for role in _ROLE_NAMES
        } != {
            role: {key: value for key, value in evidence_roles[role].items() if key != "public_key_bytes"}
            for role in _ROLE_NAMES
        }:
            raise ClaimFreezeError("raw role registry does not equal the G00-pinned trusted roles")

        topological_order = _validate_normative_documents(documents)
        _validate_thresholds(documents)
        if wrappers["validator_artifact"]["sha256"] != roots["validator_artifact_sha256"]:
            raise ClaimFreezeError(
                "validator artifact does not equal the G01-pinned validator digest"
            )
        manifest = _validate_manifest(
            documents["claim_manifest"],
            roots=roots,
            wrappers=wrappers,
            topological_order=topological_order,
            freeze_time=freeze_time,
        )

        audit = {
            "schema": FINAL_GATE_SCHEMA,
            "protocol_id": PROTOCOL_ID,
            "gate_id": GATE_ID,
            "campaign_root_sha256": roots["campaign_root_sha256"],
            "frozen_spec_sha256": roots["frozen_spec_sha256"],
            "g00_root_sha256": roots["g00_root_sha256"],
            "g01_root_sha256": roots["g01_root_sha256"],
            "campaign_registry_sha256": roots["campaign_registry_sha256"],
            "claim_manifest_sha256": wrappers["claim_manifest"]["sha256"],
            "validator_artifact_sha256": wrappers["validator_artifact"]["sha256"],
            "finalized_at_utc": finalized_at_utc,
            "recomputed_outputs": {
                "dependency_roots": roots,
                "claim_ids": [item["claim_id"] for item in _CLAIM_DEFINITIONS],
                "topological_order": topological_order,
                "raw_evidence_sha256": {
                    evidence_id: wrappers[evidence_id]["sha256"] for evidence_id in RAW_EVIDENCE_IDS
                },
                "threshold_representation": documents["thresholds"],
                "multiplicity_budget": documents["multiplicity_correction"],
                "exclusions": documents["exclusions"],
                "failure_rules": documents["failure_rules"],
                "claim_manifest_root_sha256": canonical_sha256(manifest),
                "validator_module_digest": wrappers["validator_artifact"]["sha256"],
                "producer_pass_flags_authoritative": False,
            },
            "decision": DECISION,
            "failure_codes": [],
            "authority": False,
            "candidate_development_authorized": False,
            "sealed_holdout_access_authorized": False,
            "release_authorized": False,
            "submission_authorized": False,
        }
        # Force canonical serialization now so an accidental non-JSON value cannot
        # survive into a supposedly signable final gate payload.
        canonical_json_bytes(audit)
        return audit
    except (CanonicalJSONError, ClaimFreezeError, KeyError, TypeError, ValueError) as exc:
        return _closed(_failure_code(exc), str(exc) or "invalid G07 evidence")


def _verify_final_signatures(
    *,
    audit: Mapping[str, Any],
    trusted_role_registry: object,
    final_authority_envelope: object,
    final_validator_countersignature_envelope: object,
) -> None:
    finalized = _timestamp(audit["finalized_at_utc"], "audit.finalized_at_utc")
    roles = _validate_roles(trusted_role_registry, at=finalized)
    try:
        authority_payload = verify_envelope(
            final_authority_envelope,
            expected_artifact_schema=FINAL_GATE_SCHEMA,
            pinned_public_key_bytes=roles["evaluation_authority"]["public_key_bytes"],
        )
    except EnvelopeError as exc:
        raise ClaimFreezeError(f"evaluation authority envelope rejected: {exc}") from exc
    if authority_payload != audit:
        raise ClaimFreezeError("evaluation authority did not sign the exact recomputed G07 final gate payload")
    try:
        authority_bytes = canonical_json_bytes(final_authority_envelope)
    except CanonicalJSONError as exc:
        raise ClaimFreezeError(f"authority envelope is not canonical JCS: {exc}") from exc
    authority_hash = hashlib.sha256(authority_bytes).hexdigest()
    try:
        countersignature = verify_envelope(
            final_validator_countersignature_envelope,
            expected_artifact_schema=COUNTERSIGNATURE_SCHEMA,
            pinned_public_key_bytes=roles["independent_validator"]["public_key_bytes"],
        )
    except EnvelopeError as exc:
        raise ClaimFreezeError(f"independent validator countersignature rejected: {exc}") from exc
    fields = frozenset(
        {
            "schema",
            "protocol_id",
            "gate_id",
            "campaign_root_sha256",
            "authority_envelope_sha256",
            "authority_envelope_jcs",
            "countersigned_at_utc",
        }
    )
    countersignature = _exact(countersignature, fields, "validator countersignature payload")
    if (
        countersignature["schema"] != COUNTERSIGNATURE_SCHEMA
        or countersignature["protocol_id"] != PROTOCOL_ID
        or countersignature["gate_id"] != GATE_ID
        or countersignature["campaign_root_sha256"] != audit["campaign_root_sha256"]
        or countersignature["authority_envelope_sha256"] != authority_hash
    ):
        raise ClaimFreezeError("validator countersignature does not bind this authority envelope")
    embedded_bytes, _ = decode_canonical_bytes(
        countersignature["authority_envelope_jcs"],
        label="authority_envelope_jcs",
        expected_media_type=JCS_MEDIA_TYPE,
    )
    if embedded_bytes != authority_bytes:
        raise ClaimFreezeError("validator did not countersign the exact authority envelope JCS bytes")
    countersigned = _timestamp(countersignature["countersigned_at_utc"], "countersigned_at_utc")
    if countersigned < finalized:
        raise ClaimFreezeError("validator countersignature predates the frozen final gate payload")
    _validate_roles(trusted_role_registry, at=countersigned)


def verify_claim_freeze(
    *,
    dependency_roots: object,
    trusted_role_registry: object,
    evidence_blobs: object,
    finalized_at_utc: object,
    final_authority_envelope: object,
    final_validator_countersignature_envelope: object,
) -> dict[str, Any]:
    """Verify raw G07 evidence plus the authority/validator dual signature chain."""

    audit = derive_claim_freeze_audit(
        dependency_roots=dependency_roots,
        trusted_role_registry=trusted_role_registry,
        evidence_blobs=evidence_blobs,
        finalized_at_utc=finalized_at_utc,
    )
    if audit["decision"] != DECISION:
        return audit
    try:
        _verify_final_signatures(
            audit=audit,
            trusted_role_registry=trusted_role_registry,
            final_authority_envelope=final_authority_envelope,
            final_validator_countersignature_envelope=final_validator_countersignature_envelope,
        )
        return audit
    except (CanonicalJSONError, ClaimFreezeError, EnvelopeError, KeyError, TypeError, ValueError) as exc:
        return _closed(_failure_code(exc), str(exc) or "invalid G07 final signatures")


def build_normative_claim_evidence(
    *,
    dependency_roots: object,
    trusted_role_registry: object,
    freeze_time_utc: object,
    validator_artifact: bytes,
) -> dict[str, dict[str, Any]]:
    """Build canonical *unsigned* test/producer evidence for the fixed G07 contract.

    This helper has no signing capability and cannot create authority.  It is
    useful for deterministic fixtures and for external producers that still
    need the verifier to reconstruct every supplied byte.
    """

    roots, _ = _validate_roots(dependency_roots)
    freeze_time = _timestamp(freeze_time_utc, "freeze_time_utc")
    if freeze_time <= _timestamp(roots["spec_frozen_at_utc"], "spec_frozen_at_utc"):
        raise ClaimFreezeError("G07 freeze must occur after the frozen specification")
    _validate_roles(trusted_role_registry, at=freeze_time)
    if type(validator_artifact) is not bytes or not validator_artifact or b"PRIVATE KEY" in validator_artifact.upper():
        raise ClaimFreezeError("validator_artifact must be nonempty bytes without private key material")

    documents = _static_documents()
    documents["dependency_graph"] = _normative_graph()
    documents["role_registry"] = {
        "schema": ROLE_REGISTRY_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root_sha256": roots["campaign_root_sha256"],
        "g00_root_sha256": roots["g00_root_sha256"],
        "campaign_registry_sha256": roots["campaign_registry_sha256"],
        "roles": trusted_role_registry,
    }
    blobs: dict[str, dict[str, Any]] = {
        evidence_id: wrap_canonical_bytes(canonical_json_bytes(documents[evidence_id]), media_type=JCS_MEDIA_TYPE)
        for evidence_id in _MANIFEST_REFERENCE_IDS
        if evidence_id != "validator_artifact"
    }
    blobs["validator_artifact"] = wrap_canonical_bytes(
        validator_artifact, media_type=VALIDATOR_MEDIA_TYPE
    )
    topological_order = _topological_order(documents["dependency_graph"]["claims"])
    manifest = {
        "schema": CLAIM_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "gate_id": GATE_ID,
        "dependency_roots": roots,
        "freeze_time_utc": freeze_time_utc,
        "claims": list(_CLAIM_DEFINITIONS),
        "topological_order": topological_order,
        "documents": [
            {
                "evidence_id": evidence_id,
                "sha256": blobs[evidence_id]["sha256"],
                "decoded_length": blobs[evidence_id]["decoded_length"],
                "media_type": blobs[evidence_id]["media_type"],
            }
            for evidence_id in _MANIFEST_REFERENCE_IDS
        ],
        "amendments": [],
    }
    blobs["claim_manifest"] = wrap_canonical_bytes(
        canonical_json_bytes(manifest), media_type=JCS_MEDIA_TYPE
    )
    if set(blobs) != set(RAW_EVIDENCE_IDS):
        raise AssertionError("internal G07 evidence builder closure failure")
    return blobs


# Explicit G07 names keep the API discoverable without adding any authority path.
derive_g07_claim_freeze = derive_claim_freeze_audit
verify_g07_claim_freeze = verify_claim_freeze
build_g07_claim_evidence = build_normative_claim_evidence
wrap_byte_evidence = wrap_canonical_bytes
decode_byte_evidence = decode_canonical_bytes


__all__ = [
    "AUTHORITY",
    "BYTE_WRAPPER_SCHEMA",
    "CLAIM_MANIFEST_SCHEMA",
    "COUNTERSIGNATURE_SCHEMA",
    "ClaimFreezeError",
    "CLOSED_AUDIT_SCHEMA",
    "DECISION",
    "FAIL_DECISION",
    "FINAL_GATE_SCHEMA",
    "GATE_ID",
    "JCS_MEDIA_TYPE",
    "PROTOCOL_ID",
    "RAW_EVIDENCE_IDS",
    "ROLE_REGISTRY_SCHEMA",
    "VALIDATOR_MEDIA_TYPE",
    "build_g07_claim_evidence",
    "build_normative_claim_evidence",
    "decode_byte_evidence",
    "decode_canonical_bytes",
    "derive_claim_freeze_audit",
    "derive_g07_claim_freeze",
    "verify_claim_freeze",
    "verify_g07_claim_freeze",
    "wrap_byte_evidence",
    "wrap_canonical_bytes",
]
