from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.engine_capabilities import (
    CAPABILITY_NAMES,
    ENGINE_CAPABILITY_MANIFEST_SCHEMA,
    HASH_NAMES,
    REQUIRED_BACKENDS,
    build_engine_capability_manifest,
)
from evaluation_v5.engine_evidence import audit_engine_evidence, engine_evidence_signing_payload


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sign(evidence: dict[str, object], private_key: Ed25519PrivateKey) -> None:
    payload = engine_evidence_signing_payload(evidence)  # type: ignore[arg-type]
    evidence["signature_ed25519_base64"] = base64.b64encode(private_key.sign(payload)).decode("ascii")


def _rebind_and_sign(
    manifest: dict[str, object], evidence: dict[str, object], private_key: Ed25519PrivateKey
) -> None:
    for receipt in evidence["receipts"]:  # type: ignore[union-attr]
        manifest["backends"][receipt["backend"]]["capability_evidence_sha256"][  # type: ignore[index]
            receipt["capability"]
        ] = canonical_sha256(receipt)
    evidence["engine_capability_manifest_sha256"] = build_engine_capability_manifest(  # type: ignore[arg-type]
        manifest
    ).manifest_sha256
    _sign(evidence, private_key)


def _fixture(tmp_path: Path) -> tuple[dict[str, object], dict[str, object], bytes, Ed25519PrivateKey]:
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    identities: dict[str, dict[str, str]] = {}
    receipts: list[dict[str, object]] = []
    reviewed_at = "2026-07-14T00:00:00Z"
    for backend_index, backend in enumerate(REQUIRED_BACKENDS):
        files: dict[str, tuple[str, str]] = {}
        for stem, content in (
            ("auditor.bin", f"{backend}:auditor".encode()),
            ("transcript.json", f"{backend}:transcript".encode()),
        ):
            relative = f"evidence/{backend}/{stem}"
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            files[stem] = (relative, _sha256(content))
        identity = {name: f"{backend_index * 100 + index + 1:064x}" for index, name in enumerate(HASH_NAMES)}
        identity["auditor_executable_sha256"] = files["auditor.bin"][1]
        identity["audit_transcript_sha256"] = files["transcript.json"][1]
        identities[backend] = identity
        for capability in CAPABILITY_NAMES:
            proof_relative = f"evidence/{backend}/proof-{capability}.txt"
            proof_bytes = f"{backend}:{capability}:proof".encode()
            (root / proof_relative).write_bytes(proof_bytes)
            evidence_files = [
                {"path": files["auditor.bin"][0], "sha256": files["auditor.bin"][1]},
                {"path": f"evidence/{backend}/proof-{capability}.txt", "sha256": _sha256(proof_bytes)},
                {"path": files["transcript.json"][0], "sha256": files["transcript.json"][1]},
            ]
            receipts.append(
                {
                    "backend": backend,
                    "capability": capability,
                    "reviewed_at": reviewed_at,
                    "backend_identity_sha256": identity,
                    "auditor_executable_sha256": identity["auditor_executable_sha256"],
                    "audit_transcript_sha256": identity["audit_transcript_sha256"],
                    "evidence_files": evidence_files,
                }
            )

    # Receipt hashes are hashes of receipts themselves, not of a surrounding envelope.
    receipt_hashes = {
        (receipt["backend"], receipt["capability"]): canonical_sha256(receipt)
        for receipt in receipts
    }
    manifest = {
        "schema": ENGINE_CAPABILITY_MANIFEST_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "backends": {
            backend: {
                **identities[backend],
                **{capability: True for capability in CAPABILITY_NAMES},
                "capability_evidence_sha256": {
                    capability: receipt_hashes[(backend, capability)] for capability in CAPABILITY_NAMES
                },
            }
            for backend in REQUIRED_BACKENDS
        },
    }
    checked = build_engine_capability_manifest(manifest)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    evidence: dict[str, object] = {
        "schema": "evaluation_v5_engine_evidence_manifest_v1",
        "protocol_id": "MCI_TRANSFER_V1",
        "reviewed_at": reviewed_at,
        "engine_capability_manifest_sha256": checked.manifest_sha256,
        "signer_public_key_fingerprint_sha256": _sha256(public_key),
        "receipts": receipts,
        "signature_ed25519_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
    }
    _sign(evidence, private_key)
    return manifest, evidence, public_key, private_key


def test_feasible_synthetic_full_evidence_is_complete_and_authority_free(tmp_path: Path) -> None:
    manifest, evidence, public_key, _ = _fixture(tmp_path)
    audit = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)

    assert audit["evidence_complete"] is True
    assert audit["local_feature_extraction"] is True
    assert audit["signed_manifest_sha256"] == _sha256(engine_evidence_signing_payload(evidence))
    assert len(audit["receipts"]) == len(REQUIRED_BACKENDS) * len(CAPABILITY_NAMES)
    assert audit["authority"] is False
    assert audit["submission_authorized"] is False
    assert audit["holdout_access_authorized"] is False


def test_complete_evidence_never_elevates_a_declared_infeasible_engine(tmp_path: Path) -> None:
    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    manifest["backends"]["official_wrapper"]["seeded_start"] = False  # type: ignore[index]
    del manifest["backends"]["official_wrapper"]["capability_evidence_sha256"]["seeded_start"]  # type: ignore[index]
    evidence["receipts"] = [  # type: ignore[index]
        receipt
        for receipt in evidence["receipts"]  # type: ignore[union-attr]
        if (receipt["backend"], receipt["capability"]) != ("official_wrapper", "seeded_start")
    ]
    _rebind_and_sign(manifest, evidence, private_key)

    audit = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert audit["evidence_complete"] is True
    assert audit["local_feature_extraction"] is False
    assert audit["engine_capability_audit"]["local_feature_extraction"] is False
    assert audit["authority"] is False


def test_random_hashes_without_evidence_files_fail_closed(tmp_path: Path) -> None:
    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    evidence["receipts"][0]["evidence_files"][0]["path"] = "evidence/opened_source/does-not-exist.bin"  # type: ignore[index]
    _rebind_and_sign(manifest, evidence, private_key)

    audit = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert audit["evidence_complete"] is False
    assert audit["local_feature_extraction"] is False


def test_missing_or_extra_receipt_fails_exact_coverage(tmp_path: Path) -> None:
    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    evidence["receipts"].pop()  # type: ignore[union-attr]
    _sign(evidence, private_key)
    missing = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert missing["evidence_complete"] is False
    assert "exactly cover" in missing["failure_reason"]

    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    evidence["receipts"].append(deepcopy(evidence["receipts"][-1]))  # type: ignore[index,union-attr]
    extra = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert extra["evidence_complete"] is False


def test_wrong_backend_identity_and_signature_or_key_tampering_fail(tmp_path: Path) -> None:
    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    evidence["receipts"][0]["backend_identity_sha256"]["binary_sha256"] = "f" * 64  # type: ignore[index]
    _sign(evidence, private_key)
    identity = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert identity["evidence_complete"] is False
    assert "identity" in identity["failure_reason"]

    manifest, evidence, public_key, _ = _fixture(tmp_path)
    evidence["signature_ed25519_base64"] = base64.b64encode(b"\0" * 64).decode("ascii")
    tampered_signature = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert tampered_signature["evidence_complete"] is False

    manifest, evidence, _, _ = _fixture(tmp_path)
    wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    tampered_key = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=wrong_key)
    assert tampered_key["evidence_complete"] is False
    assert "fingerprint" in tampered_key["failure_reason"]


def test_symlink_traversal_and_mutated_bytes_fail(tmp_path: Path) -> None:
    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    evidence["receipts"][0]["evidence_files"][0]["path"] = "../outside"  # type: ignore[index]
    traversal = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert traversal["evidence_complete"] is False

    manifest, evidence, public_key, _ = _fixture(tmp_path)
    proof = tmp_path / "repo" / "evidence/opened_source/proof-seeded_start.txt"
    proof.write_bytes(b"mutated after receipt")
    mutation = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert mutation["evidence_complete"] is False

    manifest, evidence, public_key, private_key = _fixture(tmp_path)
    link = tmp_path / "repo" / "evidence/opened_source/auditor-link.bin"
    link.symlink_to(tmp_path / "repo" / "evidence/opened_source/auditor.bin")
    evidence["receipts"][0]["evidence_files"][0]["path"] = "evidence/opened_source/auditor-link.bin"  # type: ignore[index]
    _rebind_and_sign(manifest, evidence, private_key)
    symlink = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    assert symlink["evidence_complete"] is False


def test_audit_is_deterministic_despite_mapping_order(tmp_path: Path) -> None:
    manifest, evidence, public_key, _ = _fixture(tmp_path)
    reordered_manifest = {key: manifest[key] for key in reversed(list(manifest))}
    reordered_evidence = {key: evidence[key] for key in reversed(list(evidence))}

    first = audit_engine_evidence(manifest, evidence, tmp_path / "repo", pinned_public_key=public_key)
    second = audit_engine_evidence(
        reordered_manifest, reordered_evidence, tmp_path / "repo", pinned_public_key=public_key
    )
    assert first == second
