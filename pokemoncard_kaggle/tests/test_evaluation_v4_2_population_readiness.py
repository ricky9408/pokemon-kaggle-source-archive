from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import uuid

import pytest

from evaluation_v2.package import build_archive
from evaluation_v4_2.population_readiness import (
    CANDIDATE_GRAMMAR_SCHEMA,
    CONTEXT_MANIFEST_SCHEMA,
    ELIGIBILITY_SCHEMA,
    FAMILY_ONTOLOGY_SCHEMA,
    ROOT_RECEIPT_SCHEMA,
    ROSTER_SCHEMA,
    PopulationReadinessError,
    build_candidate_grammar,
    build_context_manifest,
    build_eligibility,
    build_family_ontology,
    build_root_receipt,
    compile_population_readiness,
    source_tree_sha256,
    write_readiness_once,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _policy_source(index: int) -> str:
    operators = ["+", "-", "*", "//", "%", "|", "&", "^", "<<", ">>"]
    operator = operators[index % len(operators)]
    branches = "\n".join(
        f"    value = (value {operator} {step + 2})\n    if value {['<', '>', '==', '!='][step % 4]} {step + 3}:\n        value = value {operators[(index + step + 1) % len(operators)]} {step + 4}"
        for step in range(index + 2)
    )
    return (
        "from __future__ import annotations\n\n"
        "def policy(observation):\n"
        f"    value = len(observation) {operator} {index + 1}\n"
        f"{branches}\n"
        "    return value\n"
    )


def _make_population(tmp_path: Path) -> tuple[dict[str, object], ...]:
    grammar = build_candidate_grammar(
        {
            "schema": CANDIDATE_GRAMMAR_SCHEMA,
            "grammar_id": "clean-room-policy-roots-v1",
            "required_root_files": ["deck.csv", "main.py"],
            "required_engine_files": ["cg/api.py", "cg/libcg.so"],
            "allowed_generation_modes": ["isolated_clean_room_v1"],
            "forbid_outcome_conditioning": True,
            "require_isolated_context": True,
            "state": "FROZEN",
        }
    )
    orchestrator_sha = "a" * 64
    packager_sha = "b" * 64
    uuid_allocation_sha = "c" * 64
    allowed_shared_sha = _sha(b"official-engine-card-data")
    burned_sha = "d" * 64
    records: list[dict[str, str]] = []
    deck_hashes: list[str] = []
    for family_index in range(5):
        deck_data = f"card_id,quantity\n{family_index + 1},60\n".encode("ascii")
        deck_hashes.append(_sha(deck_data))
        for member_index in range(3):
            index = family_index * 3 + member_index
            lineage_uuid = str(uuid.UUID(int=index + 1))
            session_uuid = str(uuid.UUID(int=index + 101))
            source_dir = tmp_path / "sources" / f"candidate-{index:02d}"
            (source_dir / "cg").mkdir(parents=True)
            (source_dir / "main.py").write_text(_policy_source(index), encoding="utf-8")
            (source_dir / "deck.csv").write_bytes(deck_data)
            (source_dir / "cg" / "api.py").write_text("API = 1\n", encoding="ascii")
            (source_dir / "cg" / "libcg.so").write_bytes(b"linux-amd64-placeholder")
            archive_path = tmp_path / "archives" / f"candidate-{index:02d}.tar.gz"
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            archive_sha = build_archive(source_dir, archive_path)

            evidence_dir = tmp_path / "evidence" / f"candidate-{index:02d}"
            prompt_path = evidence_dir / "context" / "prompt.txt"
            prompt_path.parent.mkdir(parents=True, exist_ok=True)
            prompt_path.write_text(f"Build isolated policy root {index}.\n", encoding="ascii")
            context = build_context_manifest(
                {
                    "schema": CONTEXT_MANIFEST_SCHEMA,
                    "origin_session_uuid": session_uuid,
                    "entries": [
                        {
                            "path": "context/prompt.txt",
                            "sha256": _sha(prompt_path.read_bytes()),
                            "role": "prompt",
                        }
                    ],
                    "state": "SEALED",
                }
            )
            context_path = evidence_dir / "context.json"
            _write_json(context_path, context)
            receipt = build_root_receipt(
                {
                    "schema": ROOT_RECEIPT_SCHEMA,
                    "lineage_uuid": lineage_uuid,
                    "origin_session_uuid": session_uuid,
                    "generation_mode": "isolated_clean_room_v1",
                    "model_provider": "openai",
                    "model_id": "gpt-worker",
                    "model_request_id": f"request-{index:02d}",
                    "orchestrator_sha256": orchestrator_sha,
                    "packager_sha256": packager_sha,
                    "uuid_allocation_sha256": uuid_allocation_sha,
                    "context_manifest_sha256": context["content_sha256"],
                    "source_tree_sha256": source_tree_sha256(source_dir),
                    "archive_sha256": archive_sha,
                    "input_artifact_sha256s": sorted(
                        [allowed_shared_sha, _sha(f"candidate-input-{index}".encode("ascii"))]
                    ),
                    "human_patch_sha256s": [],
                    "compute_receipt_sha256": _sha(f"compute-{index}".encode("ascii")),
                    "parent_archive_sha256s": [],
                    "prior_hosted_submission_refs": [],
                    "outcome_conditioned": False,
                    "predictor_output_seen": False,
                    "eligibility_result_seen": False,
                    "started_at_utc": "2026-07-11T10:00:00.000000Z",
                    "finished_at_utc": "2026-07-11T10:01:00.000000Z",
                    "state": "SEALED",
                }
            )
            receipt_path = evidence_dir / "receipt.json"
            _write_json(receipt_path, receipt)
            records.append(
                {
                    "lineage_uuid": lineage_uuid,
                    "archive_path": str(archive_path.relative_to(tmp_path)),
                    "source_dir": str(source_dir.relative_to(tmp_path)),
                    "context_manifest_path": str(context_path.relative_to(tmp_path)),
                    "root_receipt_path": str(receipt_path.relative_to(tmp_path)),
                }
            )

    ontology = build_family_ontology(
        {
            "schema": FAMILY_ONTOLOGY_SCHEMA,
            "ontology_id": "structural-deck-families-v1",
            "classification_basis": "deck_sha256_allowlist",
            "families": [
                {
                    "family_id": f"deck-family-axis-{index + 1}",
                    "deck_sha256s": [deck_hash],
                }
                for index, deck_hash in enumerate(deck_hashes)
            ],
            "state": "FROZEN",
        }
    )
    eligibility = build_eligibility(
        {
            "schema": ELIGIBILITY_SCHEMA,
            "eligibility_id": "voi-p5-clean-roots-v1",
            "candidate_grammar_sha256": grammar["content_sha256"],
            "family_ontology_sha256": ontology["content_sha256"],
            "trusted_orchestrator_sha256": orchestrator_sha,
            "trusted_packager_sha256": packager_sha,
            "uuid_allocation_sha256": uuid_allocation_sha,
            "allowed_shared_material_sha256s": [allowed_shared_sha],
            "burned_artifact_sha256s": [burned_sha],
            "required_population_size": 15,
            "required_families": 5,
            "required_per_family": 3,
            "require_zero_parents": True,
            "require_unique_origin_session": True,
            "require_archive_source_identity": True,
            "maximum_policy_shingle_jaccard": 0.90,
            "forbidden_context_namespaces": [
                "agents",
                "leaderboard",
                "outcomes",
                "strategy",
            ],
            "state": "FROZEN",
        }
    )
    roster = {
        "schema": ROSTER_SCHEMA,
        "roster_id": "population-draft-v1",
        "candidate_grammar_sha256": grammar["content_sha256"],
        "eligibility_sha256": eligibility["content_sha256"],
        "family_ontology_sha256": ontology["content_sha256"],
        "compute_budget_id": "worker-budget-fixed-v1",
        "records": records,
        "state": "DRAFT",
    }
    return grammar, eligibility, ontology, roster


def test_complete_isolated_population_is_ready_but_has_no_authority(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    assert report["decision"] == "READY_FOR_POPULATION_FREEZE"
    assert all(check["passed"] for check in report["checks"])
    assert len(report["candidates"]) == 15
    assert len({row["ancestry_id"] for row in report["candidates"]}) == 15
    assert report["population_manifest_created"] is False
    assert report["kaggle_quota_authorized"] is False
    assert report["production_submission_authorized"] is False
    assert report["sealed_holdout_accessed"] is False


def test_roster_cannot_inject_family_ancestry_or_outcomes(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    for field in ("family_id", "ancestry_id", "outcome"):
        changed = copy.deepcopy(roster)
        changed["records"][0][field] = "caller-controlled"
        report = compile_population_readiness(
            candidate_grammar=grammar,
            eligibility=eligibility,
            family_ontology=ontology,
            roster=changed,
            roster_base_dir=tmp_path,
        )
        assert report["decision"] == "CLOSED"
        assert report["candidates"][0]["eligible"] is False
        assert any("fields" in blocker for blocker in report["candidates"][0]["blockers"])


def test_receipt_with_parent_or_outcome_conditioning_is_rejected() -> None:
    base = {
        "schema": ROOT_RECEIPT_SCHEMA,
        "lineage_uuid": str(uuid.UUID(int=1)),
        "origin_session_uuid": str(uuid.UUID(int=2)),
        "generation_mode": "isolated_clean_room_v1",
        "model_provider": "openai",
        "model_id": "gpt-worker",
        "model_request_id": "request-1",
        "orchestrator_sha256": "a" * 64,
        "packager_sha256": "b" * 64,
        "uuid_allocation_sha256": "c" * 64,
        "context_manifest_sha256": "c" * 64,
        "source_tree_sha256": "d" * 64,
        "archive_sha256": "e" * 64,
        "input_artifact_sha256s": ["1" * 64],
        "human_patch_sha256s": [],
        "compute_receipt_sha256": "2" * 64,
        "parent_archive_sha256s": [],
        "prior_hosted_submission_refs": [],
        "outcome_conditioned": False,
        "predictor_output_seen": False,
        "eligibility_result_seen": False,
        "started_at_utc": "2026-07-11T10:00:00.000000Z",
        "finished_at_utc": "2026-07-11T10:01:00.000000Z",
        "state": "SEALED",
    }
    with pytest.raises(PopulationReadinessError, match="zero parent"):
        build_root_receipt({**base, "parent_archive_sha256s": ["f" * 64]})
    with pytest.raises(PopulationReadinessError, match="outcome-free"):
        build_root_receipt({**base, "outcome_conditioned": True})


def test_source_mutation_after_receipt_closes_readiness(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    source = tmp_path / roster["records"][0]["source_dir"] / "main.py"
    source.write_text(source.read_text(encoding="utf-8") + "\nMUTATED = True\n", encoding="utf-8")
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    assert report["decision"] == "CLOSED"
    assert report["candidates"][0]["eligible"] is False
    assert any("source" in blocker for blocker in report["candidates"][0]["blockers"])


def test_shared_nonallowlisted_input_merges_effective_roots(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    shared = "9" * 64
    for index in (0, 1):
        receipt_path = tmp_path / roster["records"][index]["root_receipt_path"]
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        content = {key: value for key, value in receipt.items() if key != "content_sha256"}
        content["input_artifact_sha256s"] = sorted(content["input_artifact_sha256s"] + [shared])
        _write_json(receipt_path, build_root_receipt(content))
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    assert report["decision"] == "CLOSED"
    assert report["effective_ancestry_roots"] == 14
    assert report["shared_nonallowlisted_dependencies"][shared] == [
        roster["records"][0]["lineage_uuid"],
        roster["records"][1]["lineage_uuid"],
    ]


def test_burned_input_or_prior_hosted_ancestry_is_fatal(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    receipt_path = tmp_path / roster["records"][0]["root_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    content = {key: value for key, value in receipt.items() if key != "content_sha256"}
    content["input_artifact_sha256s"] = sorted(
        content["input_artifact_sha256s"] + eligibility["burned_artifact_sha256s"]
    )
    content["prior_hosted_submission_refs"] = [123]
    _write_json(receipt_path, build_root_receipt(content))
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    assert report["decision"] == "CLOSED"
    blockers = report["candidates"][0]["blockers"]
    assert "root provenance includes a burned artifact" in blockers
    assert "root ancestry already has hosted public outcomes" in blockers


def test_partial_roster_stays_closed_without_external_effects(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    roster["records"] = roster["records"][:14]
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    assert report["decision"] == "CLOSED"
    cardinality = next(check for check in report["checks"] if check["name"] == "population_cardinality")
    assert cardinality["passed"] is False
    assert report["kaggle_quota_authorized"] is False


def test_family_ontology_rejects_provenance_labels() -> None:
    with pytest.raises(PopulationReadinessError, match="neutral"):
        build_family_ontology(
            {
                "schema": FAMILY_ONTOLOGY_SCHEMA,
                "ontology_id": "bad",
                "classification_basis": "deck_sha256_allowlist",
                "families": [
                    {"family_id": "claude-family", "deck_sha256s": [f"{index + 1:064x}"]}
                    for index in range(5)
                ],
                "state": "FROZEN",
            }
        )


def test_readiness_writer_is_create_once(tmp_path: Path) -> None:
    grammar, eligibility, ontology, roster = _make_population(tmp_path)
    report = compile_population_readiness(
        candidate_grammar=grammar,
        eligibility=eligibility,
        family_ontology=ontology,
        roster=roster,
        roster_base_dir=tmp_path,
    )
    output = tmp_path / "readiness.json"
    write_readiness_once(output, report)
    with pytest.raises(FileExistsError):
        write_readiness_once(output, report)
