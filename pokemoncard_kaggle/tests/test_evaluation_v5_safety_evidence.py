from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.canonical import canonical_json_bytes
from evaluation_v5.safety_evidence import (
    OPERATIONAL_SAFETY_MANIFEST_SCHEMA,
    PRODUCTION_MIN_TESTED_CALLS,
    _audit_operational_safety_evidence,
    audit_operational_safety_evidence,
    operational_safety_signing_payload,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(manifest: dict[str, object], private_key: Ed25519PrivateKey) -> None:
    signature = private_key.sign(operational_safety_signing_payload(manifest))
    manifest["signature_ed25519_base64"] = base64.b64encode(signature).decode("ascii")


def _fixture(tmp_path: Path) -> tuple[Path, dict[str, object], bytes, Ed25519PrivateKey]:
    root = tmp_path / "repo"
    root.mkdir()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    artifacts = {
        "runner.bin": b"runner bytes",
        "container.digest": b"container bytes",
        "runtime.json": b'{"python":"3.14"}\n',
    }
    for relative, content in artifacts.items():
        (root / relative).write_bytes(content)

    archives = ["a" * 64, "b" * 64]
    rows = [
        {"archive_sha256": archives[0], "call_index": 0, "outcome": "win"},
        {"archive_sha256": archives[0], "call_index": 1, "outcome": "loss"},
        {"archive_sha256": archives[1], "call_index": 0, "outcome": "draw"},
    ]
    log_bytes = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    (root / "calls.jsonl").write_bytes(log_bytes)
    manifest: dict[str, object] = {
        "schema": OPERATIONAL_SAFETY_MANIFEST_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "campaign_sha256": "c" * 64,
        "archive_sha256s": archives,
        "runner_executable": {"path": "runner.bin", "sha256": _sha256(artifacts["runner.bin"])},
        "container": {"path": "container.digest", "sha256": _sha256(artifacts["container.digest"])},
        "runtime": {"path": "runtime.json", "sha256": _sha256(artifacts["runtime.json"])},
        "call_log": {"path": "calls.jsonl", "sha256": _sha256(log_bytes)},
        "tested_calls": 3,
        "outcome_counts": {
            "win": 1,
            "loss": 1,
            "draw": 1,
            "crash": 0,
            "illegal": 0,
            "malformed": 0,
            "runtime": 0,
            "timeout": 0,
        },
        "signer_public_key_fingerprint_sha256": _sha256(public_key),
    }
    _sign(manifest, private_key)
    return root, manifest, public_key, private_key


def _replace_log_and_resign(
    root: Path,
    manifest: dict[str, object],
    private_key: Ed25519PrivateKey,
    rows: list[dict[str, object]],
) -> None:
    log_bytes = b"".join(canonical_json_bytes(row) + b"\n" for row in rows)
    (root / "calls.jsonl").write_bytes(log_bytes)
    manifest["call_log"] = {"path": "calls.jsonl", "sha256": _sha256(log_bytes)}
    manifest["tested_calls"] = len(rows)
    counts = {outcome: 0 for outcome in ("win", "loss", "draw", "crash", "illegal", "malformed", "runtime", "timeout")}
    for row in rows:
        counts[row["outcome"]] += 1  # type: ignore[index]
    manifest["outcome_counts"] = counts
    _sign(manifest, private_key)


def test_valid_evidence_recomputes_counts_and_remains_authority_free(tmp_path: Path) -> None:
    root, manifest, public_key, _ = _fixture(tmp_path)

    audit = _audit_operational_safety_evidence(
        manifest,
        root,
        pinned_public_key=public_key,
        minimum_tested_calls=3,
    )

    assert audit["evidence_complete"] is True
    assert audit["tested_calls"] == 3
    assert audit["outcome_counts"]["win"] == 1
    assert audit["authority"] is False
    assert audit["submission_authorized"] is False
    assert audit["holdout_access_authorized"] is False
    assert audit["signer_public_key_fingerprint_sha256"] == _sha256(public_key)


def test_public_verifier_keeps_the_production_50k_floor(tmp_path: Path) -> None:
    root, manifest, public_key, _ = _fixture(tmp_path)

    audit = audit_operational_safety_evidence(manifest, root, pinned_public_key=public_key)

    assert audit["evidence_complete"] is False
    assert "minimum" in audit["failure_reason"]
    assert PRODUCTION_MIN_TESTED_CALLS == 50_000


def test_signed_count_claim_cannot_replace_recomputed_count(tmp_path: Path) -> None:
    root, manifest, public_key, private_key = _fixture(tmp_path)
    manifest["outcome_counts"]["win"] = 2  # type: ignore[index]
    manifest["outcome_counts"]["loss"] = 0  # type: ignore[index]
    _sign(manifest, private_key)

    audit = _audit_operational_safety_evidence(
        manifest,
        root,
        pinned_public_key=public_key,
        minimum_tested_calls=3,
    )

    assert audit["evidence_complete"] is False
    assert "outcome_counts" in audit["failure_reason"]


def test_duplicate_per_archive_index_is_rejected_after_signature_verification(tmp_path: Path) -> None:
    root, manifest, public_key, private_key = _fixture(tmp_path)
    rows = [
        {"archive_sha256": "a" * 64, "call_index": 0, "outcome": "win"},
        {"archive_sha256": "a" * 64, "call_index": 0, "outcome": "loss"},
        {"archive_sha256": "b" * 64, "call_index": 0, "outcome": "draw"},
    ]
    _replace_log_and_resign(root, manifest, private_key, rows)

    audit = audit_operational_safety_evidence(manifest, root, pinned_public_key=public_key)

    assert audit["evidence_complete"] is False
    assert "signature" in audit["failure_reason"] or "duplicate" in audit["failure_reason"]


def test_archive_set_must_be_covered_exactly(tmp_path: Path) -> None:
    root, manifest, public_key, private_key = _fixture(tmp_path)
    rows = [{"archive_sha256": "a" * 64, "call_index": 0, "outcome": "win"}]
    _replace_log_and_resign(root, manifest, private_key, rows)

    audit = _audit_operational_safety_evidence(
        manifest,
        root,
        pinned_public_key=public_key,
        minimum_tested_calls=1,
    )

    assert audit["evidence_complete"] is False
    assert "coverage" in audit["failure_reason"]


def test_symlinked_bound_artifact_is_not_followed(tmp_path: Path) -> None:
    root, manifest, public_key, private_key = _fixture(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (root / "runtime.json").unlink()
    (root / "runtime.json").symlink_to(outside)
    manifest["runtime"] = {"path": "runtime.json", "sha256": _sha256(outside.read_bytes())}
    _sign(manifest, private_key)

    audit = audit_operational_safety_evidence(manifest, root, pinned_public_key=public_key)

    assert audit["evidence_complete"] is False
    assert "securely open" in audit["failure_reason"] or "signature" in audit["failure_reason"]


def test_fatal_outcome_is_counted_and_closes_the_audit(tmp_path: Path) -> None:
    root, manifest, public_key, _ = _fixture(tmp_path)
    # A changed signed log would require the original private key.  The
    # verifier must still fail closed even before it reaches outcome policy.
    raw = (root / "calls.jsonl").read_text()
    (root / "calls.jsonl").write_text(raw.replace('"win"', '"timeout"', 1))

    audit = audit_operational_safety_evidence(manifest, root, pinned_public_key=public_key)

    assert audit["evidence_complete"] is False
    assert "digest" in audit["failure_reason"] or "signature" in audit["failure_reason"]
