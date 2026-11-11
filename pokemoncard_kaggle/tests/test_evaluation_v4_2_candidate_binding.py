from __future__ import annotations

import copy
import json
from pathlib import Path
import uuid

import pytest

from evaluation_v4.lineage import ancestry_id_for_roots, lineage_id_for_archive
from evaluation_v4_2.candidate_binding import (
    CANDIDATE_BINDING_SCHEMA,
    CandidateBindingError,
    load_candidate_binding,
    load_candidate_binding_file,
)
from evaluation_v4_2.population_readiness import READINESS_SCHEMA, canonical_sha256


def _digest(number: int) -> str:
    return f"{number:064x}"


def _candidate(index: int) -> dict[str, object]:
    archive = _digest(index + 1)
    lineage_uuid = str(uuid.UUID(int=index + 1))
    return {
        "position": index,
        "lineage_uuid": lineage_uuid,
        "origin_session_uuid": str(uuid.UUID(int=index + 101)),
        "model_request_id": f"request-{index}",
        "archive_sha256": archive,
        "policy_content_sha256": _digest(index + 201),
        "deck_sha256": _digest(index + 301),
        "source_tree_sha256": _digest(index + 401),
        "context_manifest_sha256": _digest(index + 501),
        "root_receipt_sha256": _digest(index + 601),
        "compute_receipt_sha256": _digest(index + 701),
        "dependency_artifact_sha256s": [_digest(index + 801)],
        "lineage_id": lineage_id_for_archive(archive),
        "ancestry_id": ancestry_id_for_roots([archive]),
        "family_id": f"deck-family-axis-{(index % 5) + 1}",
        "compute_budget_id": "fixed-clean-room-budget",
        "dependency_component_id": lineage_uuid,
        "eligible": True,
        "blockers": [],
    }


def _report(*, include_main: bool = False) -> dict[str, object]:
    candidates = [_candidate(index) for index in range(15)]
    if include_main:
        candidates[0]["main_sha256"] = _digest(999)
    check_names = [
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
    ]
    sorted_uuids = sorted(str(candidate["lineage_uuid"]) for candidate in candidates)
    family_counts: dict[str, int] = {}
    for candidate in candidates:
        family = str(candidate["family_id"])
        family_counts[family] = family_counts.get(family, 0) + 1
    content: dict[str, object] = {
        "schema": READINESS_SCHEMA,
        "roster_id": "population-draft-v1",
        "candidate_grammar_sha256": _digest(901),
        "eligibility_sha256": _digest(902),
        "family_ontology_sha256": _digest(903),
        "checks": [{"name": name, "passed": True, "detail": "verified"} for name in check_names],
        "candidates": candidates,
        "family_counts": family_counts,
        "effective_ancestry_roots": len(candidates),
        "family_effective_roots": dict(family_counts),
        "shared_nonallowlisted_dependencies": {},
        "pairwise_policy_similarity": [
            {"left": left, "right": right, "jaccard": 0.25}
            for index, left in enumerate(sorted_uuids)
            for right in sorted_uuids[index + 1 :]
        ],
        "decision": "READY_FOR_POPULATION_FREEZE",
        "population_manifest_created": False,
        "kaggle_quota_authorized": False,
        "production_submission_authorized": False,
        "sealed_holdout_accessed": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def _reseal(report: dict[str, object]) -> dict[str, object]:
    content = {key: value for key, value in report.items() if key != "content_sha256"}
    return {**content, "content_sha256": canonical_sha256(content)}


def test_binds_exact_ready_candidate_without_inventing_main_sha256() -> None:
    report = _report()
    archive = report["candidates"][0]["archive_sha256"]

    binding = load_candidate_binding(report, archive)

    assert binding == {
        "schema": CANDIDATE_BINDING_SCHEMA,
        "archive_sha256": archive,
        "policy_content_sha256": report["candidates"][0]["policy_content_sha256"],
        "deck_sha256": report["candidates"][0]["deck_sha256"],
        "lineage_uuid": report["candidates"][0]["lineage_uuid"],
        "lineage_id": lineage_id_for_archive(archive),
        "ancestry_id": ancestry_id_for_roots([archive]),
        "family_id": report["candidates"][0]["family_id"],
        "dependency_component_id": report["candidates"][0]["dependency_component_id"],
        "readiness_content_sha256": report["content_sha256"],
    }
    assert "main_sha256" not in binding


def test_returns_explicit_main_sha256_only_when_present() -> None:
    report = _report(include_main=True)
    archive = report["candidates"][0]["archive_sha256"]

    binding = load_candidate_binding(report, archive)

    assert binding["main_sha256"] == _digest(999)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda report: report.__setitem__("decision", "CLOSED"), "decision"),
        (lambda report: report.__setitem__("kaggle_quota_authorized", True), "must be false"),
        (lambda report: report["checks"][0].__setitem__("passed", False), "must have passed"),
        (lambda report: report["candidates"][0].__setitem__("ancestry_id", "caller-value"), "ancestry_id"),
        (lambda report: report["candidates"][0].__setitem__("blockers", ["blocked"]), "blocker-free"),
    ],
)
def test_rejects_nonready_or_tampered_semantics(mutate, match: str) -> None:
    report = _report()
    archive = report["candidates"][0]["archive_sha256"]
    mutate(report)
    report = _reseal(report)

    with pytest.raises(CandidateBindingError, match=match):
        load_candidate_binding(report, archive)


def test_rejects_hash_tampering_unknown_fields_and_duplicate_archive() -> None:
    report = _report()
    archive = report["candidates"][0]["archive_sha256"]
    tampered = copy.deepcopy(report)
    tampered["decision"] = "CLOSED"
    with pytest.raises(CandidateBindingError, match="content_sha256 mismatch"):
        load_candidate_binding(tampered, archive)

    unknown = copy.deepcopy(report)
    unknown["unexpected"] = True
    with pytest.raises(CandidateBindingError, match="fields must exactly"):
        load_candidate_binding(_reseal(unknown), archive)

    duplicate = copy.deepcopy(report)
    duplicate["candidates"][1]["archive_sha256"] = archive
    duplicate["candidates"][1]["lineage_id"] = lineage_id_for_archive(archive)
    duplicate["candidates"][1]["ancestry_id"] = ancestry_id_for_roots([archive])
    with pytest.raises(CandidateBindingError, match="duplicate candidate archive_sha256"):
        load_candidate_binding(_reseal(duplicate), archive)


def test_rejects_self_sealed_underpowered_population() -> None:
    report = _report()
    archive = report["candidates"][0]["archive_sha256"]
    report["candidates"] = report["candidates"][:2]
    report["family_counts"] = {
        str(candidate["family_id"]): 1 for candidate in report["candidates"]
    }
    report["family_effective_roots"] = dict(report["family_counts"])
    report["effective_ancestry_roots"] = 2
    report["pairwise_policy_similarity"] = report["pairwise_policy_similarity"][:1]
    with pytest.raises(CandidateBindingError, match="exactly 15"):
        load_candidate_binding(_reseal(report), archive)


def test_file_loader_is_read_only_and_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    report = _report()
    archive = report["candidates"][0]["archive_sha256"]
    path = tmp_path / "readiness.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    before = path.read_bytes()

    assert load_candidate_binding_file(path, archive)["archive_sha256"] == archive
    assert path.read_bytes() == before

    duplicate_key_path = tmp_path / "duplicate.json"
    duplicate_key_path.write_text('{"schema":"a","schema":"b"}', encoding="ascii")
    with pytest.raises(CandidateBindingError, match="duplicate key"):
        load_candidate_binding_file(duplicate_key_path, archive)
