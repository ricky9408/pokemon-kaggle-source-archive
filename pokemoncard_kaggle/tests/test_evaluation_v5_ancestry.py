from __future__ import annotations

from copy import deepcopy
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.ancestry import (
    ANCESTRY_MANIFEST_SCHEMA,
    ANCESTRY_PROTOCOL_ID,
    AncestryAuditError,
    FAMILY_EVIDENCE_SCHEMA,
    audit_external_confirmatory_ancestry,
    canonical_unsigned_manifest_bytes,
)
from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.cohort import build_archive_registration


def _hash(character: str) -> str:
    return hashlib.sha256(character.encode("ascii")).hexdigest()


def _record(
    archive: str,
    policy: str,
    source: str,
    *,
    parents: list[str] | None = None,
    teachers: list[str] | None = None,
    provenance: list[str] | None = None,
    complete: bool = True,
    review_timestamp: str = "2026-07-14T03:04:05.000000Z",
) -> dict[str, object]:
    return {
        "archive_sha256": _hash(archive),
        "policy_sha256": _hash(policy),
        "source_tree_sha256": _hash(source),
        "direct_parent_policy_sha256s": parents or [],
        "teacher_checkpoint_sha256s": teachers or [],
        "declared_provenance_evidence_sha256s": (
            [_hash(f"provenance-{archive}")] if provenance is None else provenance
        ),
        "ancestry_complete": complete,
        "review_timestamp_utc": review_timestamp,
    }


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return private_key, public_key


def _manifest(private_key: Ed25519PrivateKey, records: list[dict[str, object]]) -> dict[str, object]:
    unsigned = {
        "schema": ANCESTRY_MANIFEST_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "records": records,
    }
    return {
        **unsigned,
        "auditor_signature_ed25519": private_key.sign(canonical_unsigned_manifest_bytes(unsigned)).hex(),
    }


def _audit(records: list[dict[str, object]]) -> dict[str, object]:
    private_key, public_key = _keypair()
    return audit_external_confirmatory_ancestry(_manifest(private_key, records), pinned_public_key_hex=public_key)


def test_shared_teacher_parent_and_source_evidence_merge_families() -> None:
    records = [
        _record("a", "b", "c", teachers=[_hash("1")]),
        _record("d", "e", "f", teachers=[_hash("1")]),
        _record("g", "h", "i", parents=[_hash("e")]),
        _record("j", "k", "i"),
        _record("l", "m", "n", provenance=[_hash("2")]),
        _record("o", "p", "q", provenance=[_hash("2")]),
    ]
    audit = _audit(records)
    families = audit["archive_to_family"]
    assert families[_hash("a")] == families[_hash("d")]
    assert families[_hash("d")] == families[_hash("g")]
    assert families[_hash("g")] == families[_hash("j")]
    assert families[_hash("l")] == families[_hash("o")]
    assert families[_hash("a")] != families[_hash("l")]
    assert audit["counts"] == {
        "archive_count": 6,
        "family_count": 2,
        "complete_archive_count": 6,
        "incomplete_archive_count": 0,
    }


def test_identical_policy_is_a_cosmetic_fork_not_an_independent_family() -> None:
    audit = _audit([_record("a", "b", "c"), _record("d", "b", "e")])
    families = audit["archive_to_family"]
    assert families[_hash("a")] == families[_hash("d")]
    assert len(families[_hash("a")]) == 64
    assert set(families[_hash("a")]) <= set("0123456789abcdef")
    assert audit["counts"]["family_count"] == 1


def test_incomplete_records_and_any_linked_complete_record_become_unknown_family() -> None:
    records = [
        _record("a", "b", "c", teachers=[_hash("1")], complete=False),
        _record("d", "e", "f", complete=False),
        _record("g", "h", "i", teachers=[_hash("1")]),
        _record("j", "k", "l"),
    ]
    audit = _audit(records)
    families = audit["archive_to_family"]
    assert families[_hash("a")] == families[_hash("d")] == families[_hash("g")]
    assert families[_hash("j")] != families[_hash("a")]
    assert audit["family_descriptors"][families[_hash("a")]] == {
        "schema": FAMILY_EVIDENCE_SCHEMA,
        "kind": "UNKNOWN_INCOMPLETE_ANCESTRY",
    }
    assert audit["counts"]["family_count"] == 2
    assert audit["counts"]["incomplete_archive_count"] == 2


def test_family_descriptor_hashes_equal_keys_and_bind_registration() -> None:
    audit = _audit(
        [
            _record("a", "b", "c"),
            _record("d", "e", "f", complete=False),
        ]
    )
    descriptors = audit["family_descriptors"]
    assert set(descriptors) == set(audit["archive_to_family"].values())
    for family_sha256, descriptor in descriptors.items():
        assert canonical_sha256(descriptor) == family_sha256

    family_sha256 = audit["archive_to_family"][_hash("a")]
    registration = build_archive_registration(
        archive_sha256=_hash("a"),
        deck_sha256=_hash("deck"),
        policy_sha256=_hash("b"),
        model_input_sha256=_hash("model"),
        team_pseudonym="team-a",
        submission_slot_id="slot-a",
        intended_window_start_utc="2026-07-15T00:00:00.000000Z",
        intended_window_end_utc="2026-07-15T01:00:00.000000Z",
        consent_sha256=_hash("consent"),
        registered_at_utc="2026-07-14T12:00:00.000000Z",
        family_provenance=descriptors[family_sha256],
    )
    assert registration["family_provenance_sha256"] == family_sha256


def test_signature_tamper_and_wrong_pinned_key_fail_closed() -> None:
    private_key, public_key = _keypair()
    manifest = _manifest(private_key, [_record("a", "b", "c")])
    tampered = deepcopy(manifest)
    tampered["records"][0]["source_tree_sha256"] = _hash("d")
    with pytest.raises(AncestryAuditError, match="signature"):
        audit_external_confirmatory_ancestry(tampered, pinned_public_key_hex=public_key)
    _, wrong_public_key = _keypair()
    with pytest.raises(AncestryAuditError, match="signature"):
        audit_external_confirmatory_ancestry(manifest, pinned_public_key_hex=wrong_public_key)


def test_signed_audit_identity_binds_signature_and_pinned_auditor_key() -> None:
    records = [_record("a", "b", "c")]
    first_private_key, first_public_key = _keypair()
    second_private_key, second_public_key = _keypair()
    first = audit_external_confirmatory_ancestry(
        _manifest(first_private_key, records), pinned_public_key_hex=first_public_key
    )
    second = audit_external_confirmatory_ancestry(
        _manifest(second_private_key, records), pinned_public_key_hex=second_public_key
    )
    assert first["manifest_sha256"] == second["manifest_sha256"]
    assert first["archive_to_family"] == second["archive_to_family"]
    assert first["signed_manifest_sha256"] != second["signed_manifest_sha256"]
    assert first["auditor_public_key_sha256"] != second["auditor_public_key_sha256"]
    assert first["evidence_sha256"] != second["evidence_sha256"]


@pytest.mark.parametrize("complete", [True, False])
def test_every_record_requires_declared_provenance_evidence(complete: bool) -> None:
    private_key, public_key = _keypair()
    record = _record("a", "b", "c", provenance=[], complete=complete)
    with pytest.raises(AncestryAuditError, match="at least one evidence hash"):
        audit_external_confirmatory_ancestry(
            _manifest(private_key, [record]), pinned_public_key_hex=public_key
        )


def test_audit_exposes_review_timestamp_bounds_and_binds_them_in_evidence() -> None:
    private_key, public_key = _keypair()
    records = [
        _record("a", "b", "c", review_timestamp="2026-07-14T05:00:00.000000Z"),
        _record("d", "e", "f", review_timestamp="2026-07-13T23:59:59.000000Z"),
        _record("g", "h", "i", review_timestamp="2026-07-14T03:00:00.000000Z"),
    ]
    first = audit_external_confirmatory_ancestry(
        _manifest(private_key, records), pinned_public_key_hex=public_key
    )
    reordered = audit_external_confirmatory_ancestry(
        _manifest(private_key, list(reversed(records))), pinned_public_key_hex=public_key
    )
    assert first == reordered
    assert first["earliest_review_timestamp_utc"] == "2026-07-13T23:59:59.000000Z"
    assert first["latest_review_timestamp_utc"] == "2026-07-14T05:00:00.000000Z"

    changed_records = deepcopy(records)
    changed_records[1]["review_timestamp_utc"] = "2026-07-13T23:59:58.000000Z"
    changed = audit_external_confirmatory_ancestry(
        _manifest(private_key, changed_records), pinned_public_key_hex=public_key
    )
    assert changed["earliest_review_timestamp_utc"] != first["earliest_review_timestamp_utc"]
    assert changed["evidence_sha256"] != first["evidence_sha256"]


def test_caller_supplied_family_fields_duplicates_and_noncanonical_values_are_rejected() -> None:
    private_key, public_key = _keypair()
    poisoned = _record("a", "b", "c")
    poisoned["family_id"] = "trust-me"
    with pytest.raises(AncestryAuditError, match="fields must exactly"):
        audit_external_confirmatory_ancestry(_manifest(private_key, [poisoned]), pinned_public_key_hex=public_key)

    duplicate_archives = [_record("a", "b", "c"), _record("a", "d", "e")]
    with pytest.raises(AncestryAuditError, match="duplicate archive"):
        audit_external_confirmatory_ancestry(_manifest(private_key, duplicate_archives), pinned_public_key_hex=public_key)

    duplicate_teacher = _record("a", "b", "c", teachers=[_hash("1"), _hash("1")])
    with pytest.raises(AncestryAuditError, match="must not contain duplicates"):
        audit_external_confirmatory_ancestry(_manifest(private_key, [duplicate_teacher]), pinned_public_key_hex=public_key)

    upper_hash = _record("a", "b", "c")
    upper_hash["policy_sha256"] = "B" * 64
    with pytest.raises(AncestryAuditError, match="lowercase"):
        audit_external_confirmatory_ancestry(_manifest(private_key, [upper_hash]), pinned_public_key_hex=public_key)

    bad_timestamp = _record("a", "b", "c")
    bad_timestamp["review_timestamp_utc"] = "2026-07-14T03:04:05Z"
    with pytest.raises(AncestryAuditError, match="canonical UTC"):
        audit_external_confirmatory_ancestry(_manifest(private_key, [bad_timestamp]), pinned_public_key_hex=public_key)


def test_record_order_does_not_change_signed_content_or_audit_and_never_grants_authority() -> None:
    private_key, public_key = _keypair()
    records = [_record("a", "b", "c"), _record("d", "e", "f", teachers=[_hash("1")])]
    first = _manifest(private_key, records)
    second = _manifest(private_key, list(reversed(records)))
    assert first["auditor_signature_ed25519"] == second["auditor_signature_ed25519"]
    first_audit = audit_external_confirmatory_ancestry(first, pinned_public_key_hex=public_key)
    second_audit = audit_external_confirmatory_ancestry(second, pinned_public_key_hex=public_key)
    assert first_audit == second_audit
    assert first_audit["authority"] is False
    assert first_audit["submission"] is False
    assert first_audit["holdout"] is False
    assert isinstance(first_audit["cryptography_version"], str)
    assert len(first_audit["evidence_sha256"]) == 64
