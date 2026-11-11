from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5.canonical import canonical_json_bytes
from evaluation_v5.charter import FEATURE_NAMES
from evaluation_v5.development_evidence import (
    DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA,
    audit_development_fit_evidence,
    development_evidence_signing_payload,
)
from evaluation_v5.development_fit import DEVELOPMENT_ROW_SCHEMA, fit_development_models, validate_development_rows
from evaluation_v5.engine_capabilities import CAPABILITY_NAMES, HASH_NAMES, engine_capability_manifest_sha256
from evaluation_v5.model import COMPARATOR_INPUT_KEYS


CREATED = "2026-07-14T03:00:00.000000Z"
REVIEWED = "2026-07-14T04:00:00.000000Z"
IMPLEMENTATION = "b" * 64


def _backend(*, enabled: bool = True) -> dict[str, object]:
    value: dict[str, object] = {name: f"{index + 1:064x}" for index, name in enumerate(HASH_NAMES)}
    value.update({name: enabled for name in CAPABILITY_NAMES})
    value["capability_evidence_sha256"] = {
        name: f"{index + 20:064x}" for index, name in enumerate(CAPABILITY_NAMES) if value[name]
    }
    return value


def _engine(*, feasible: bool = True) -> dict[str, object]:
    return {
        "schema": "evaluation_v5_engine_capability_manifest_v1",
        "protocol_id": "MCI_TRANSFER_V1",
        "backends": {
            "opened_source": _backend(),
            "official_wrapper": _backend() if feasible else _backend(enabled=False),
        },
    }


def _row(index: int) -> dict[str, object]:
    return {
        "schema": DEVELOPMENT_ROW_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "partition": "DEV_BURNED",
        "engine_manifest_sha256": "pending",
        "archive_id": f"archive-{index // 4:02d}",
        "lineage_id": f"lineage-{index // 4:02d}",
        "family_id": f"family-{index // 8:02d}",
        "game_id": f"game-{index:03d}",
        "features": {
            name: ((index + feature_index) % 5) / 4.0
            for feature_index, name in enumerate(FEATURE_NAMES)
        },
        "comparator_inputs": {
            key: (index % 5) / 4.0
            for key in COMPARATOR_INPUT_KEYS.values()
            if key is not None
        },
        "era": "2026Q3" if index % 2 else "2026Q2",
        "seat": index % 2,
        "opponent_rating": 700 + (index % 12) * 100,
        "outcome": float(index % 2),
    }


def _fixture(
    tmp_path: Path,
    *,
    engine: dict[str, object] | None = None,
    rows_bytes: bytes | None = None,
    fit_value: dict[str, object] | None = None,
    reviewed_at: str = REVIEWED,
) -> tuple[dict[str, object], Ed25519PrivateKey, dict[str, object]]:
    checked_engine = engine or _engine()
    engine_hash = engine_capability_manifest_sha256(checked_engine)
    rows = [_row(index) for index in range(16)]
    for row in rows:
        row["engine_manifest_sha256"] = engine_hash
    checked_rows = validate_development_rows(rows, engine_manifest_sha256=engine_hash)
    rows_bytes = rows_bytes or canonical_json_bytes(checked_rows)
    rows_hash = hashlib.sha256(rows_bytes).hexdigest()
    if fit_value is None:
        fit_value = fit_development_models(
            checked_rows,
            engine_capability_manifest=checked_engine,
            development_evidence_sha256=rows_hash,
            executable_sha256=IMPLEMENTATION,
            created_at_utc=CREATED,
        )
    rows_path = tmp_path / "dev_rows.json"
    fit_path = tmp_path / "fit_result.json"
    rows_path.write_bytes(rows_bytes)
    fit_bytes = canonical_json_bytes(fit_value)
    fit_path.write_bytes(fit_bytes)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    manifest: dict[str, object] = {
        "schema": DEVELOPMENT_EVIDENCE_MANIFEST_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "reviewed_at": reviewed_at,
        "created_at_utc": CREATED,
        "development_rows_path": rows_path.name,
        "development_rows_sha256": rows_hash,
        "fit_result_path": fit_path.name,
        "fit_result_sha256": hashlib.sha256(fit_bytes).hexdigest(),
        "engine_capability_manifest_sha256": engine_hash,
        "implementation_binding_manifest_sha256": IMPLEMENTATION,
        "signer_public_key_fingerprint_sha256": hashlib.sha256(public_key).hexdigest(),
    }
    manifest["signature_ed25519_base64"] = base64.b64encode(
        private_key.sign(development_evidence_signing_payload(manifest))
    ).decode("ascii")
    return manifest, private_key, checked_engine


def _audit(tmp_path: Path, manifest: dict[str, object], key: Ed25519PrivateKey, engine: object) -> dict[str, object]:
    return audit_development_fit_evidence(
        engine,
        manifest,
        tmp_path,
        pinned_public_key=key.public_key().public_bytes_raw(),
        implementation_binding_manifest_sha256=IMPLEMENTATION,
    )


def _resign(manifest: dict[str, object], key: Ed25519PrivateKey) -> None:
    manifest["signature_ed25519_base64"] = base64.b64encode(
        key.sign(development_evidence_signing_payload(manifest))
    ).decode("ascii")


def test_valid_signed_fit_is_recomputed_and_never_authoritative(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is True
    assert result["decision"] == "DEVELOPMENT_ONLY"
    assert result["authority"] is False
    assert result["submission_authorized"] is False
    assert result["holdout_access_authorized"] is False
    assert result["b_star_selection"]["rule"].startswith("minimum_lineage_out")  # type: ignore[index]


def test_current_no_local_feature_extraction_is_complete_closure_not_fit_evidence(tmp_path: Path) -> None:
    engine = _engine(feasible=False)
    manifest, key, checked_engine = _fixture(tmp_path, engine=engine)
    result = _audit(tmp_path, manifest, key, checked_engine)
    assert result["evidence_complete"] is False
    assert result["decision"] == "NO_LOCAL_FEATURE_EXTRACTION"
    assert result["failure_reason"] == "NO_LOCAL_FEATURE_EXTRACTION"
    assert result["authority"] is False


def test_duplicate_json_object_key_is_rejected_before_fit(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(
        tmp_path,
        rows_bytes=b'[{"schema":"x","schema":"y"}]',
    )
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "duplicate JSON object key" in result["failure_reason"]  # type: ignore[operator]


def test_noncanonical_fit_result_bytes_are_rejected(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    fit_path = tmp_path / "fit_result.json"
    fit_path.write_bytes(b" " + fit_path.read_bytes())
    manifest["fit_result_sha256"] = hashlib.sha256(fit_path.read_bytes()).hexdigest()
    _resign(manifest, key)
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "canonical JSON" in result["failure_reason"]  # type: ignore[operator]


def test_symlinked_evidence_file_is_not_followed(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    rows_path = tmp_path / "dev_rows.json"
    target = tmp_path / "real_rows.json"
    target.write_bytes(rows_path.read_bytes())
    rows_path.unlink()
    rows_path.symlink_to(target)
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "securely open" in result["failure_reason"]  # type: ignore[operator]


def test_manifest_cannot_alias_rows_and_fit_result_path(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    manifest["fit_result_path"] = manifest["development_rows_path"]
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "different files" in result["failure_reason"]  # type: ignore[operator]


def test_resigned_mci_mutation_is_rejected(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    fit_path = tmp_path / "fit_result.json"
    fit = json.loads(fit_path.read_text())
    fit["mci_manifest"]["intercept"] += 0.25  # type: ignore[index]
    fit_bytes = canonical_json_bytes(fit)
    fit_path.write_bytes(fit_bytes)
    manifest["fit_result_sha256"] = hashlib.sha256(fit_bytes).hexdigest()
    _resign(manifest, key)
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert result["failure_reason"] == "MCI manifest mismatch"


def test_resigned_b_star_selection_mutation_is_rejected(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    fit_path = tmp_path / "fit_result.json"
    fit = json.loads(fit_path.read_text())
    original_selection = fit["selected_comparator_identity"]
    fit["selected_comparator_identity"] = next(
        identity
        for identity in (
            "nuisance-only null model",
            "raw local win-rate model",
            "L/T mean model",
            "local CVaR model",
            "action-imitation model",
            "search-rank model",
        )
        if identity != original_selection
    )
    fit_bytes = canonical_json_bytes(fit)
    fit_path.write_bytes(fit_bytes)
    manifest["fit_result_sha256"] = hashlib.sha256(fit_bytes).hexdigest()
    _resign(manifest, key)
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert result["failure_reason"] == "B_STAR comparator selection mismatch"


def test_signature_and_chronology_fail_closed(tmp_path: Path) -> None:
    manifest, key, engine = _fixture(tmp_path)
    manifest["reviewed_at"] = "2026-07-14T02:00:00.000000Z"
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "reviewed_at cannot precede" in result["failure_reason"]  # type: ignore[operator]

    manifest, key, engine = _fixture(tmp_path)
    manifest["fit_result_sha256"] = "0" * 64
    result = _audit(tmp_path, manifest, key, engine)
    assert result["evidence_complete"] is False
    assert "signature" in result["failure_reason"]  # type: ignore[operator]
