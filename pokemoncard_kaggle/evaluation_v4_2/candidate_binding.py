"""Fail-closed, read-only binding from a v4.2 readiness report to an archive.

``load_candidate_binding`` returns exactly these required keys:
``schema``, ``archive_sha256``, ``policy_content_sha256``, ``deck_sha256``,
``lineage_uuid``, ``lineage_id``, ``ancestry_id``, ``family_id``,
``dependency_component_id``, and ``readiness_content_sha256``.  It includes
``main_sha256`` only when a readiness candidate explicitly contains that known
optional field.  The current ``population_readiness`` producer does not emit
``main_sha256``; this loader deliberately does not infer one from an archive,
policy, or source tree.

This module reads reports only.  A readiness decision is not an authority to
create a population manifest, use a quota, submit to Kaggle, or access a
holdout.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
from typing import Any, Mapping
import uuid

from evaluation_v4.lineage import ancestry_id_for_roots, lineage_id_for_archive

from .population_readiness import READINESS_SCHEMA, canonical_sha256


CANDIDATE_BINDING_SCHEMA = "evaluation_v4_2_candidate_binding_v1"
REQUIRED_CANDIDATE_COUNT = 15
REQUIRED_FAMILY_COUNT = 5
REQUIRED_ROOTS_PER_FAMILY = 3

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FAMILY_RE = re.compile(r"^deck-family-[a-z0-9]+(?:-[a-z0-9]+)*$")
_REPORT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "roster_id",
        "candidate_grammar_sha256",
        "eligibility_sha256",
        "family_ontology_sha256",
        "checks",
        "candidates",
        "family_counts",
        "effective_ancestry_roots",
        "family_effective_roots",
        "shared_nonallowlisted_dependencies",
        "pairwise_policy_similarity",
        "decision",
        "population_manifest_created",
        "kaggle_quota_authorized",
        "production_submission_authorized",
        "sealed_holdout_accessed",
    }
)
_REPORT_FIELDS = _REPORT_CONTENT_FIELDS | {"content_sha256"}
_CHECK_FIELDS = frozenset({"name", "passed", "detail"})
_CANDIDATE_FIELDS = frozenset(
    {
        "position",
        "lineage_uuid",
        "origin_session_uuid",
        "model_request_id",
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "source_tree_sha256",
        "context_manifest_sha256",
        "root_receipt_sha256",
        "compute_receipt_sha256",
        "dependency_artifact_sha256s",
        "lineage_id",
        "ancestry_id",
        "family_id",
        "compute_budget_id",
        "dependency_component_id",
        "eligible",
        "blockers",
    }
)
_OPTIONAL_MAIN_CANDIDATE_FIELDS = _CANDIDATE_FIELDS | {"main_sha256"}
_PAIRWISE_FIELDS = frozenset({"left", "right", "jaccard"})
_REQUIRED_CHECK_NAMES = (
    "candidate_grammar",
    "family_ontology",
    "eligibility",
    "eligibility_bindings",
    "ontology_cardinality",
    "roster_bindings",
    "population_cardinality",
    "unique_lineage_uuid",
    "unique_origin_session_uuid",
    "unique_model_request_id",
    "unique_archive_sha256",
    "unique_policy_content_sha256",
    "unique_source_tree_sha256",
    "unique_ancestry_id",
    "unique_compute_receipt_sha256",
    "all_records_eligible",
    "family_balance",
    "dependency_independence",
    "family_effective_roots",
    "policy_near_clone_guard",
)


class CandidateBindingError(ValueError):
    """A readiness report cannot safely bind the requested candidate."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise CandidateBindingError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CandidateBindingError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CandidateBindingError(f"{label} must be a non-empty trimmed string")
    return value


def _uuid(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise CandidateBindingError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise CandidateBindingError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise CandidateBindingError(f"{label} must be a canonical UUID")
    return value


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateBindingError(f"{label} must be a non-negative integer")
    return value


def _validate_checks(value: object) -> None:
    if not isinstance(value, list) or len(value) != len(_REQUIRED_CHECK_NAMES):
        raise CandidateBindingError("readiness checks must contain the complete v1 check set")
    for index, raw in enumerate(value):
        check = _exact_fields(raw, _CHECK_FIELDS, label=f"readiness check {index}")
        name = _identifier(check["name"], label=f"readiness check {index}.name")
        if not isinstance(check["passed"], bool) or check["passed"] is not True:
            raise CandidateBindingError(f"readiness check {name!r} must have passed")
        if not isinstance(check["detail"], str):
            raise CandidateBindingError(f"readiness check {name!r}.detail must be a string")
        if name != _REQUIRED_CHECK_NAMES[index]:
            raise CandidateBindingError("readiness checks are not in the exact v1 producer order")


def _validate_candidate(raw: object, *, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) not in (_CANDIDATE_FIELDS, _OPTIONAL_MAIN_CANDIDATE_FIELDS):
        raise CandidateBindingError(f"candidate {index} has unknown or missing fields")
    candidate = dict(raw)
    if _nonnegative_int(candidate["position"], label=f"candidate {index}.position") != index:
        raise CandidateBindingError(f"candidate {index}.position must equal its list index")
    normalized = {
        "position": index,
        "lineage_uuid": _uuid(candidate["lineage_uuid"], label=f"candidate {index}.lineage_uuid"),
        "origin_session_uuid": _uuid(
            candidate["origin_session_uuid"], label=f"candidate {index}.origin_session_uuid"
        ),
        "model_request_id": _identifier(
            candidate["model_request_id"], label=f"candidate {index}.model_request_id"
        ),
        "archive_sha256": _sha256(candidate["archive_sha256"], label=f"candidate {index}.archive_sha256"),
        "policy_content_sha256": _sha256(
            candidate["policy_content_sha256"], label=f"candidate {index}.policy_content_sha256"
        ),
        "deck_sha256": _sha256(candidate["deck_sha256"], label=f"candidate {index}.deck_sha256"),
        "source_tree_sha256": _sha256(
            candidate["source_tree_sha256"], label=f"candidate {index}.source_tree_sha256"
        ),
        "context_manifest_sha256": _sha256(
            candidate["context_manifest_sha256"], label=f"candidate {index}.context_manifest_sha256"
        ),
        "root_receipt_sha256": _sha256(
            candidate["root_receipt_sha256"], label=f"candidate {index}.root_receipt_sha256"
        ),
        "compute_receipt_sha256": _sha256(
            candidate["compute_receipt_sha256"], label=f"candidate {index}.compute_receipt_sha256"
        ),
        "lineage_id": _identifier(candidate["lineage_id"], label=f"candidate {index}.lineage_id"),
        "ancestry_id": _identifier(candidate["ancestry_id"], label=f"candidate {index}.ancestry_id"),
        "family_id": _identifier(candidate["family_id"], label=f"candidate {index}.family_id"),
        "compute_budget_id": _identifier(
            candidate["compute_budget_id"], label=f"candidate {index}.compute_budget_id"
        ),
        "dependency_component_id": _uuid(
            candidate["dependency_component_id"], label=f"candidate {index}.dependency_component_id"
        ),
    }
    if _FAMILY_RE.fullmatch(normalized["family_id"]) is None:
        raise CandidateBindingError(f"candidate {index}.family_id is invalid")
    dependencies = candidate["dependency_artifact_sha256s"]
    if not isinstance(dependencies, list):
        raise CandidateBindingError(f"candidate {index}.dependency_artifact_sha256s must be a list")
    normalized_dependencies = [
        _sha256(item, label=f"candidate {index}.dependency_artifact_sha256s[{item_index}]")
        for item_index, item in enumerate(dependencies)
    ]
    if normalized_dependencies != sorted(set(normalized_dependencies)):
        raise CandidateBindingError(f"candidate {index}.dependency_artifact_sha256s must be sorted and unique")
    if candidate["eligible"] is not True or candidate["blockers"] != []:
        raise CandidateBindingError(f"candidate {index} must be eligible and blocker-free")
    if normalized["lineage_id"] != lineage_id_for_archive(normalized["archive_sha256"]):
        raise CandidateBindingError(f"candidate {index}.lineage_id is not derived from archive_sha256")
    if normalized["ancestry_id"] != ancestry_id_for_roots([normalized["archive_sha256"]]):
        raise CandidateBindingError(f"candidate {index}.ancestry_id is not derived from archive_sha256")
    if "main_sha256" in candidate:
        normalized["main_sha256"] = _sha256(candidate["main_sha256"], label=f"candidate {index}.main_sha256")
    return normalized


def _validate_candidate_set(candidates: list[dict[str, Any]]) -> None:
    if len(candidates) != REQUIRED_CANDIDATE_COUNT:
        raise CandidateBindingError(
            f"readiness candidates must contain exactly {REQUIRED_CANDIDATE_COUNT} roots"
        )
    for field in (
        "lineage_uuid",
        "origin_session_uuid",
        "model_request_id",
        "archive_sha256",
        "policy_content_sha256",
        "source_tree_sha256",
        "lineage_id",
        "ancestry_id",
        "compute_receipt_sha256",
    ):
        values = [candidate[field] for candidate in candidates]
        if len(values) != len(set(values)):
            raise CandidateBindingError(f"duplicate candidate {field}")
    lineages = {candidate["lineage_uuid"] for candidate in candidates}
    if any(candidate["dependency_component_id"] != candidate["lineage_uuid"] for candidate in candidates):
        raise CandidateBindingError("ready candidates must each have an independent dependency component")
    if any(candidate["dependency_component_id"] not in lineages for candidate in candidates):
        raise CandidateBindingError("candidate dependency component is not a known lineage")


def _validate_derived_report_fields(report: Mapping[str, Any], candidates: list[dict[str, Any]]) -> None:
    family_counts = report["family_counts"]
    family_roots = report["family_effective_roots"]
    if not isinstance(family_counts, Mapping) or not isinstance(family_roots, Mapping):
        raise CandidateBindingError("readiness family summaries must be mappings")
    expected_counts: dict[str, int] = {}
    for candidate in candidates:
        expected_counts[candidate["family_id"]] = expected_counts.get(candidate["family_id"], 0) + 1
    for label, summary in (("family_counts", family_counts), ("family_effective_roots", family_roots)):
        for family_id, count in summary.items():
            if not isinstance(family_id, str) or _FAMILY_RE.fullmatch(family_id) is None:
                raise CandidateBindingError(f"readiness {label} has an invalid family ID")
            _nonnegative_int(count, label=f"readiness {label}.{family_id}")
    if dict(family_counts) != expected_counts or dict(family_roots) != expected_counts:
        raise CandidateBindingError("readiness family summaries do not match candidates")
    if len(expected_counts) != REQUIRED_FAMILY_COUNT or any(
        count != REQUIRED_ROOTS_PER_FAMILY for count in expected_counts.values()
    ):
        raise CandidateBindingError(
            "readiness population must contain five families with three roots each"
        )
    if (
        _nonnegative_int(
            report["effective_ancestry_roots"], label="readiness effective_ancestry_roots"
        )
        != len(candidates)
    ):
        raise CandidateBindingError("readiness effective_ancestry_roots must equal candidate count")
    if report["shared_nonallowlisted_dependencies"] != {}:
        raise CandidateBindingError("readiness report has shared nonallowlisted dependencies")
    pairwise = report["pairwise_policy_similarity"]
    if not isinstance(pairwise, list):
        raise CandidateBindingError("readiness pairwise_policy_similarity must be a list")
    expected_pairs = {
        (left["lineage_uuid"], right["lineage_uuid"])
        for index, left in enumerate(sorted(candidates, key=lambda candidate: candidate["lineage_uuid"]))
        for right in sorted(candidates, key=lambda candidate: candidate["lineage_uuid"])[index + 1 :]
    }
    observed_pairs: set[tuple[str, str]] = set()
    for index, raw in enumerate(pairwise):
        pair = _exact_fields(raw, _PAIRWISE_FIELDS, label=f"pairwise similarity {index}")
        left = _uuid(pair["left"], label=f"pairwise similarity {index}.left")
        right = _uuid(pair["right"], label=f"pairwise similarity {index}.right")
        score = pair["jaccard"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(float(score)) or not 0.0 <= float(score) <= 1.0:
            raise CandidateBindingError(f"pairwise similarity {index}.jaccard must be in [0, 1]")
        if left >= right:
            raise CandidateBindingError(f"pairwise similarity {index} UUIDs must be sorted")
        observed_pairs.add((left, right))
    if observed_pairs != expected_pairs or len(observed_pairs) != len(pairwise):
        raise CandidateBindingError("readiness pairwise similarities do not cover candidates exactly")


def load_candidate_binding(readiness_report: object, archive_sha256: str) -> dict[str, str]:
    """Bind one exact archive SHA to a fully-ready, authority-free report.

    ``archive_sha256`` is the only caller-controlled candidate identity.  The
    returned ancestry is re-derived from that archive, never accepted from a
    caller or merely trusted from the report.
    """

    requested_archive = _sha256(archive_sha256, label="archive_sha256")
    report = _exact_fields(readiness_report, _REPORT_FIELDS, label="readiness report")
    content = {field: report[field] for field in _REPORT_CONTENT_FIELDS}
    readiness_sha = _sha256(report["content_sha256"], label="readiness report.content_sha256")
    if readiness_sha != canonical_sha256(content):
        raise CandidateBindingError("readiness report content_sha256 mismatch")
    if report["schema"] != READINESS_SCHEMA:
        raise CandidateBindingError(f"readiness report schema must be {READINESS_SCHEMA!r}")
    _identifier(report["roster_id"], label="readiness report.roster_id")
    for field in ("candidate_grammar_sha256", "eligibility_sha256", "family_ontology_sha256"):
        _sha256(report[field], label=f"readiness report.{field}")
    if report["decision"] != "READY_FOR_POPULATION_FREEZE":
        raise CandidateBindingError("readiness report decision is not READY_FOR_POPULATION_FREEZE")
    for field in (
        "population_manifest_created",
        "kaggle_quota_authorized",
        "production_submission_authorized",
        "sealed_holdout_accessed",
    ):
        if report[field] is not False:
            raise CandidateBindingError(f"readiness report {field} must be false")
    _validate_checks(report["checks"])
    raw_candidates = report["candidates"]
    if not isinstance(raw_candidates, list):
        raise CandidateBindingError("readiness candidates must be a list")
    candidates = [_validate_candidate(raw, index=index) for index, raw in enumerate(raw_candidates)]
    _validate_candidate_set(candidates)
    _validate_derived_report_fields(report, candidates)
    matches = [candidate for candidate in candidates if candidate["archive_sha256"] == requested_archive]
    if len(matches) != 1:
        raise CandidateBindingError("readiness report must contain exactly one eligible requested archive")
    candidate = matches[0]
    binding = {
        "schema": CANDIDATE_BINDING_SCHEMA,
        "archive_sha256": requested_archive,
        "policy_content_sha256": candidate["policy_content_sha256"],
        "deck_sha256": candidate["deck_sha256"],
        "lineage_uuid": candidate["lineage_uuid"],
        "lineage_id": lineage_id_for_archive(requested_archive),
        "ancestry_id": ancestry_id_for_roots([requested_archive]),
        "family_id": candidate["family_id"],
        "dependency_component_id": candidate["dependency_component_id"],
        "readiness_content_sha256": readiness_sha,
    }
    if "main_sha256" in candidate:
        binding["main_sha256"] = candidate["main_sha256"]
    return binding


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateBindingError(f"readiness report JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise CandidateBindingError(f"readiness report JSON contains invalid constant {value!r}")


def load_candidate_binding_file(path: str | Path, archive_sha256: str) -> dict[str, str]:
    """Read one JSON readiness report without modifying it, then bind an archive."""

    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except CandidateBindingError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateBindingError(f"could not read readiness report {path}: {exc}") from exc
    return load_candidate_binding(payload, archive_sha256)


__all__ = [
    "CANDIDATE_BINDING_SCHEMA",
    "CandidateBindingError",
    "load_candidate_binding",
    "load_candidate_binding_file",
]
