from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.ancestry import (
    ANCESTRY_MANIFEST_SCHEMA,
    ANCESTRY_PROTOCOL_ID,
    canonical_unsigned_manifest_bytes,
    validate_signed_population_manifest,
)
from evaluation_v5.provenance_evidence import (
    PROVENANCE_EVIDENCE_AUDIT_SCHEMA,
    audit_provenance_evidence,
    provenance_evidence_signing_payload,
    signed_ancestry_manifest_sha256,
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _ancestry(private_key: Ed25519PrivateKey, tokens: list[str]) -> dict[str, object]:
    record = {
        "archive_sha256": "1" * 64,
        "policy_sha256": "2" * 64,
        "source_tree_sha256": "3" * 64,
        "direct_parent_policy_sha256s": [],
        "teacher_checkpoint_sha256s": [],
        "declared_provenance_evidence_sha256s": tokens,
        "ancestry_complete": True,
        "review_timestamp_utc": "2026-07-14T00:00:00.000000Z",
    }
    unsigned = {
        "schema": ANCESTRY_MANIFEST_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "records": [record],
    }
    return {
        **unsigned,
        "auditor_signature_ed25519": private_key.sign(
            canonical_unsigned_manifest_bytes(unsigned)
        ).hex(),
    }


def _index(
    ancestry: dict[str, object],
    ancestry_signer: Ed25519PrivateKey,
    signer: Ed25519PrivateKey,
    files: list[dict[str, str]],
) -> dict[str, object]:
    validated = validate_signed_population_manifest(
        ancestry,
        pinned_public_key_hex=_public_key(ancestry_signer).hex(),
    )
    unsigned = {
        "schema": "evaluation_v5_provenance_evidence_index_manifest_v1",
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "signed_ancestry_manifest_sha256": signed_ancestry_manifest_sha256(validated),
        "signer_public_key_fingerprint_sha256": _sha256(_public_key(signer)),
        "evidence_files": sorted(files, key=lambda item: item["path"]),
    }
    return {
        **unsigned,
        "signature_ed25519_base64": base64.b64encode(
            signer.sign(
                provenance_evidence_signing_payload(
                    {
                        **unsigned,
                        "signature_ed25519_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
                    }
                )
            )
        ).decode("ascii"),
    }


def _fixture(tmp_path: Path, contents: list[tuple[str, bytes]]) -> tuple[
    dict[str, object], Ed25519PrivateKey, Ed25519PrivateKey, Path, list[dict[str, str]]
]:
    ancestry_signer = Ed25519PrivateKey.generate()
    evidence_signer = Ed25519PrivateKey.generate()
    entries: list[dict[str, str]] = []
    for path, content in contents:
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_bytes(content)
        entries.append({"path": path, "sha256": _sha256(content)})
    ancestry = _ancestry(ancestry_signer, [entry["sha256"] for entry in entries])
    return ancestry, ancestry_signer, evidence_signer, tmp_path, entries


def test_valid_index_resolves_exact_declared_tokens_and_returns_only_two_fields(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(
        tmp_path,
        [("evidence/a.txt", b"alpha"), ("evidence/b.txt", b"beta")],
    )
    index = _index(ancestry, ancestry_signer, signer, entries)

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result == {
        "schema": PROVENANCE_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": ANCESTRY_PROTOCOL_ID,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": True,
        "failure_reason": None,
        "signed_ancestry_manifest_sha256": signed_ancestry_manifest_sha256(
            validate_signed_population_manifest(
                ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()
            )
        ),
        "signed_evidence_index_payload_sha256": _sha256(
            provenance_evidence_signing_payload(index)
        ),
        "signer_public_key_fingerprint_sha256": _sha256(_public_key(signer)),
        "verified_files": entries,
    }


def test_missing_declared_token_fails_closed(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("a", b"a"), ("b", b"b")])
    index = _index(ancestry, ancestry_signer, signer, entries[:1])

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result["evidence_complete"] is False
    assert result["schema"] == PROVENANCE_EVIDENCE_AUDIT_SCHEMA
    assert result["protocol_id"] == ANCESTRY_PROTOCOL_ID
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    assert result["holdout_access_authorized"] is False
    assert result["failure_reason"]
    assert result["signed_ancestry_manifest_sha256"] is not None
    assert result["signed_evidence_index_payload_sha256"] is not None
    assert result["signer_public_key_fingerprint_sha256"] == _sha256(_public_key(signer))
    assert result["verified_files"] == []


def test_unique_invented_token_fails_closed(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("a", b"a")])
    invented = {"path": "invented", "sha256": _sha256(b"invented")}
    index = _index(ancestry, ancestry_signer, signer, entries + [invented])

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result["evidence_complete"] is False


def test_duplicate_digest_is_rejected_even_when_same_file_is_repeated(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("a", b"a")])
    index = _index(ancestry, ancestry_signer, signer, entries)
    index["evidence_files"] = list(index["evidence_files"]) + [dict(entries[0])]  # type: ignore[index]

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result["evidence_complete"] is False


def test_canonical_path_order_and_signature_are_required(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("a", b"a"), ("b", b"b")])
    index = _index(ancestry, ancestry_signer, signer, entries)
    index["evidence_files"] = list(reversed(index["evidence_files"]))  # type: ignore[index]
    index["signature_ed25519_base64"] = base64.b64encode(b"bad" * 21 + b"!").decode("ascii")

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result["evidence_complete"] is False


def test_symlink_and_traversal_are_not_evidence_files(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("evidence.txt", b"safe")])
    outside = tmp_path.parent / "outside-evidence.txt"
    outside.write_bytes(b"safe")
    (repo / "link.txt").symlink_to(outside)
    validated = validate_signed_population_manifest(
        ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()
    )

    symlink_index = _index(
        ancestry,
        ancestry_signer,
        signer,
        [{"path": "link.txt", "sha256": entries[0]["sha256"]}],
    )
    traversal_index = _index(ancestry, ancestry_signer, signer, entries)
    traversal_index["evidence_files"] = [{
        "path": "../outside-evidence.txt",
        "sha256": entries[0]["sha256"],
    }]

    assert not audit_provenance_evidence(
        validated,
        symlink_index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )["evidence_complete"]
    assert not audit_provenance_evidence(
        validated,
        traversal_index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )["evidence_complete"]


def test_tampered_bytes_fail_sha256_binding(tmp_path: Path) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(tmp_path, [("evidence.txt", b"original")])
    index = _index(ancestry, ancestry_signer, signer, entries)
    (repo / "evidence.txt").write_bytes(b"tampered")

    result = audit_provenance_evidence(
        validate_signed_population_manifest(ancestry, pinned_public_key_hex=_public_key(ancestry_signer).hex()),
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )

    assert result["evidence_complete"] is False


def test_invalid_ancestry_signature_cannot_produce_complete_evidence(
    tmp_path: Path,
) -> None:
    ancestry, ancestry_signer, signer, repo, entries = _fixture(
        tmp_path, [("evidence.txt", b"original")]
    )
    index = _index(ancestry, ancestry_signer, signer, entries)
    ancestry["auditor_signature_ed25519"] = "00" * 64
    result = audit_provenance_evidence(
        ancestry,
        index,
        repo,
        pinned_public_key=_public_key(signer),
        pinned_ancestry_public_key_hex=_public_key(ancestry_signer).hex(),
    )
    assert result["evidence_complete"] is False
