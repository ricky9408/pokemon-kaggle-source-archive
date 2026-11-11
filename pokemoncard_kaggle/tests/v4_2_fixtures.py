from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import uuid

from evaluation_v2.public_transfer import ArchivePolicyIdentity, archive_policy_identity
from evaluation_v4.lineage import ancestry_id_for_roots, lineage_id_for_archive
from evaluation_v4_2.population_readiness import READINESS_SCHEMA, canonical_sha256
from evaluation_v4_2.opponent_roster import (
    build_deck_family_ontology,
    build_leaderboard_snapshot,
    compile_opponent_roster,
)


def _digest(number: int) -> str:
    return f"{number:064x}"


def ready_population_for_candidate(identity: ArchivePolicyIdentity) -> dict[str, object]:
    candidates: list[dict[str, object]] = []
    identities = asdict(identity)
    for index in range(15):
        archive = identities["archive_sha256"] if index == 0 else _digest(10_000 + index)
        lineage_uuid = str(uuid.UUID(int=index + 1))
        candidates.append(
            {
                "position": index,
                "lineage_uuid": lineage_uuid,
                "origin_session_uuid": str(uuid.UUID(int=index + 101)),
                "model_request_id": f"request-{index:02d}",
                "archive_sha256": archive,
                "policy_content_sha256": (
                    identities["policy_content_sha256"] if index == 0 else _digest(20_000 + index)
                ),
                "deck_sha256": identities["deck_sha256"] if index == 0 else _digest(30_000 + index),
                "source_tree_sha256": _digest(40_000 + index),
                "context_manifest_sha256": _digest(50_000 + index),
                "root_receipt_sha256": _digest(60_000 + index),
                "compute_receipt_sha256": _digest(70_000 + index),
                "dependency_artifact_sha256s": [_digest(80_000 + index)],
                "lineage_id": lineage_id_for_archive(archive),
                "ancestry_id": ancestry_id_for_roots([archive]),
                "family_id": f"deck-family-axis-{(index % 5) + 1}",
                "compute_budget_id": "fixed-clean-room-budget",
                "dependency_component_id": lineage_uuid,
                "eligible": True,
                "blockers": [],
            }
        )
    family_counts = {f"deck-family-axis-{index}": 3 for index in range(1, 6)}
    lineage_uuids = sorted(str(candidate["lineage_uuid"]) for candidate in candidates)
    check_names = (
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
    content: dict[str, object] = {
        "schema": READINESS_SCHEMA,
        "roster_id": "runner-fixture-population-v1",
        "candidate_grammar_sha256": _digest(90_001),
        "eligibility_sha256": _digest(90_002),
        "family_ontology_sha256": _digest(90_003),
        "checks": [
            {"name": name, "passed": True, "detail": "fixture-derived"}
            for name in check_names
        ],
        "candidates": candidates,
        "family_counts": family_counts,
        "effective_ancestry_roots": 15,
        "family_effective_roots": dict(family_counts),
        "shared_nonallowlisted_dependencies": {},
        "pairwise_policy_similarity": [
            {"left": left, "right": right, "jaccard": 0.0}
            for index, left in enumerate(lineage_uuids)
            for right in lineage_uuids[index + 1 :]
        ],
        "decision": "READY_FOR_POPULATION_FREEZE",
        "population_manifest_created": False,
        "kaggle_quota_authorized": False,
        "production_submission_authorized": False,
        "sealed_holdout_accessed": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def write_opponent_evidence(
    tmp_path: Path, opponents: dict[str, str]
) -> tuple[Path, list[dict[str, object]]]:
    identities: list[dict[str, object]] = []
    deck_to_family: dict[str, str] = {}
    source_classes = ["top_public"] * 9 + ["codex", "claude", "grok"]
    snapshot_rows: list[dict[str, object]] = []
    for index, opponent_id in enumerate(sorted(opponents)):
        identity = archive_policy_identity(Path(opponents[opponent_id]))
        family_id = f"mechanism-axis-{(index % 5) + 1}"
        deck_to_family[identity.deck_sha256] = family_id
        team_id = f"team-{index:02d}"
        rank = index + 1 if index < 4 else 100 + index if index < 8 else 600 + index
        snapshot_rows.append({"team_id": team_id, "rank": rank, "score": 1500.0 - index})
        identities.append(
            {
                "opponent_id": opponent_id,
                "archive_sha256": identity.archive_sha256,
                "policy_content_sha256": identity.policy_content_sha256,
                "main_sha256": identity.main_sha256,
                "deck_sha256": identity.deck_sha256,
                "source_class": source_classes[index],
                "leaderboard_team_id": team_id,
            }
        )
    ontology = build_deck_family_ontology(
        {
            "schema": "evaluation_v4_2_opponent_deck_family_ontology_v1",
            "ontology_id": "runner-fixture-ontology-v1",
            "classification_basis": "deck_sha256_only_v1",
            "deck_to_family": deck_to_family,
            "state": "FROZEN",
        }
    )
    snapshot = build_leaderboard_snapshot(
        {
            "schema": "evaluation_v4_2_leaderboard_snapshot_v1",
            "snapshot_id": "runner-fixture-leaderboard-v1",
            "cutoff_timestamp": "2026-07-12T00:00:00.000000Z",
            "rows": snapshot_rows,
            "state": "FROZEN",
        }
    )
    roster = compile_opponent_roster(ontology, snapshot, identities)
    evidence_dir = tmp_path / "opponent-evidence"
    evidence_dir.mkdir()
    paths = {
        "roster_receipt_path": evidence_dir / "roster.json",
        "ontology_path": evidence_dir / "ontology.json",
        "leaderboard_snapshot_path": evidence_dir / "leaderboard.json",
        "identities_path": evidence_dir / "identities.json",
    }
    values = {
        "roster_receipt_path": roster,
        "ontology_path": ontology,
        "leaderboard_snapshot_path": snapshot,
        "identities_path": identities,
    }
    for key, path in paths.items():
        path.write_text(json.dumps(values[key], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = evidence_dir / "execution-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "evaluation_v4_2_opponent_execution_sources_v1",
                "sources": opponents,
                **{key: str(path) for key, path in paths.items()},
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    template_rows = [
        {key: value for key, value in row.items() if key != "main_sha256"}
        for row in roster["opponent_roster"]
    ]
    return manifest, template_rows
