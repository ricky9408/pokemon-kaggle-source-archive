from __future__ import annotations

from copy import deepcopy

import pytest

from evaluation_v4_2.opponent_roster import (
    OpponentRosterError,
    build_deck_family_ontology,
    build_leaderboard_snapshot,
    canonical_sha256,
    compile_opponent_roster,
    validate_opponent_roster,
)


def _sha(number: int) -> str:
    return f"{number:064x}"


def _inputs() -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    deck_to_family = {_sha(100 + index): f"mechanism-{index + 1}" for index in range(6)}
    ontology = build_deck_family_ontology(
        {
            "schema": "evaluation_v4_2_opponent_deck_family_ontology_v1",
            "ontology_id": "ontology-20260712",
            "classification_basis": "deck_sha256_only_v1",
            "deck_to_family": deck_to_family,
            "state": "FROZEN",
        }
    )
    leaderboard_rows = []
    for index in range(12):
        leaderboard_rows.append(
            {
                "team_id": f"team-{index:02d}",
                "rank": (index + 1) if index < 3 else (100 + index if index < 6 else 600 + index),
                "score": 1500.0 - index,
            }
        )
    snapshot = build_leaderboard_snapshot(
        {
            "schema": "evaluation_v4_2_leaderboard_snapshot_v1",
            "snapshot_id": "snapshot-20260712",
            "cutoff_timestamp": "2026-07-12T00:00:00.000000Z",
            "rows": leaderboard_rows,
            "state": "FROZEN",
        }
    )
    identities = []
    source_classes = ["top_public"] * 8 + ["codex", "claude", "grok", "top_public"]
    for index in range(12):
        identities.append(
            {
                "opponent_id": f"opponent-{index:02d}",
                "archive_sha256": _sha(1000 + index),
                "policy_content_sha256": _sha(2000 + index),
                "main_sha256": _sha(3000 + index),
                "deck_sha256": _sha(100 + index % 6),
                "source_class": source_classes[index],
                "leaderboard_team_id": f"team-{index:02d}",
            }
        )
    return ontology, snapshot, identities


def test_compile_is_template_ready_derived_and_no_authority() -> None:
    ontology, snapshot, identities = _inputs()
    result = compile_opponent_roster(ontology, snapshot, identities)

    assert result["content_sha256"]
    assert result["ontology_sha256"] == ontology["content_sha256"]
    assert result["leaderboard_snapshot_sha256"] == snapshot["content_sha256"]
    assert all(result[key] is False for key in (
        "external_authority",
        "submission_authorized",
        "anchor_allowed",
        "production_submission_authorized",
    ))
    rows = result["opponent_roster"]
    assert {row["family_id"] for row in rows} == {f"mechanism-{index}" for index in range(1, 7)}
    assert {row["rating_layer"] for row in rows} == {"top", "mid", "low"}
    assert {row["ood_mass"] for row in rows} == {0.0, 1.0}
    assert {row["ood_mass"] for row in rows if row["rating_layer"] == "low"} == {1.0}
    assert {row["ood_mass"] for row in rows if row["rating_layer"] != "low"} == {0.0}
    assert {row["weight"] for row in rows} == {1.0 / 12}
    assert all("source_class" not in row and "leaderboard_team_id" not in row for row in rows)
    assert validate_opponent_roster(result) == result


@pytest.mark.parametrize(
    "mutator, message",
    [
        (lambda ontology, snapshot, identities: identities[0].update({"family_id": "forged"}), "fields must exactly"),
        (lambda ontology, snapshot, identities: identities[0].update({"rating_layer": "low"}), "fields must exactly"),
        (lambda ontology, snapshot, identities: identities[0].update({"weight": 1.0}), "fields must exactly"),
        (lambda ontology, snapshot, identities: identities[0].update({"ood_mass": 1.0}), "fields must exactly"),
        (lambda ontology, snapshot, identities: identities[0].update({"archive_sha256": identities[1]["archive_sha256"]}), "duplicate archive"),
        (lambda ontology, snapshot, identities: identities[0].update({"policy_content_sha256": identities[1]["policy_content_sha256"]}), "duplicate policy"),
        (lambda ontology, snapshot, identities: identities[0].update({"leaderboard_team_id": "missing-team"}), "matching leaderboard team"),
        (lambda ontology, snapshot, identities: identities[0].update({"deck_sha256": _sha(9999)}), "no ontology family"),
    ],
)
def test_rejects_identity_tampering_and_caller_derived_fields(mutator, message) -> None:
    ontology, snapshot, identities = _inputs()
    mutator(ontology, snapshot, identities)
    with pytest.raises(OpponentRosterError, match=message):
        compile_opponent_roster(ontology, snapshot, identities)


def test_rejects_missing_sources_counts_and_duplicate_identity() -> None:
    ontology, snapshot, identities = _inputs()
    for identity in identities:
        identity["source_class"] = "codex"
    with pytest.raises(OpponentRosterError, match="Claude|Grok|top_public"):
        compile_opponent_roster(ontology, snapshot, identities)

    ontology, snapshot, identities = _inputs()
    identities[11] = deepcopy(identities[10])
    with pytest.raises(OpponentRosterError, match="duplicate opponent_id"):
        compile_opponent_roster(ontology, snapshot, identities)


def test_rejects_snapshot_and_ontology_hash_tampering_or_invalid_leaderboard_values() -> None:
    ontology, snapshot, identities = _inputs()
    forged_ontology = deepcopy(ontology)
    forged_ontology["deck_to_family"][_sha(100)] = "forged"
    with pytest.raises(OpponentRosterError, match="content_sha256 mismatch"):
        compile_opponent_roster(forged_ontology, snapshot, identities)

    forged_snapshot = deepcopy(snapshot)
    forged_snapshot["rows"][0]["score"] = float("nan")
    with pytest.raises(OpponentRosterError, match="content_sha256 mismatch|finite"):
        compile_opponent_roster(ontology, forged_snapshot, identities)

    forged_snapshot = deepcopy(snapshot)
    forged_snapshot["rows"][0]["rank"] = 0
    with pytest.raises(OpponentRosterError, match="positive integer|content_sha256 mismatch"):
        compile_opponent_roster(ontology, forged_snapshot, identities)


def test_audit_catches_source_or_output_tampering() -> None:
    ontology, snapshot, identities = _inputs()
    roster = compile_opponent_roster(ontology, snapshot, identities)

    tampered = deepcopy(roster)
    tampered["opponent_roster"][0]["family_id"] = "wrong-family"
    with pytest.raises(OpponentRosterError, match="content_sha256 mismatch"):
        validate_opponent_roster(tampered)

    tampered = deepcopy(roster)
    tampered["opponent_roster"][0]["family_id"] = "mechanism-2"
    tampered["content_sha256"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "content_sha256"}
    )
    with pytest.raises(OpponentRosterError, match="source derivation"):
        from evaluation_v4_2.opponent_roster import audit_opponent_roster

        audit_opponent_roster(tampered, ontology, snapshot, identities)
