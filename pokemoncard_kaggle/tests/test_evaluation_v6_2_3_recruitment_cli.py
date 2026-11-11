from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v6_2.integration_v622 import canonical_json_bytes
from evaluation_v6_2.attestation_v623 import DOMAIN_REGISTRY, signing_message
from tools import evaluation_v6_2_3_recruitment as cli


def _write(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    return path


def _run(capsys, *argv: str) -> tuple[int, dict]:
    code = cli.main(list(argv))
    output = capsys.readouterr()
    assert not output.err
    return code, json.loads(output.out)


def _admin_config(path: Path) -> tuple[Path, str]:
    records = []
    for index in range(3):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        records.append(
            {
                "entity_id": f"admin-{index}",
                "public_key_ed25519_base64": base64.b64encode(public_key).decode("ascii"),
                "external_identity_receipt_sha256": hashlib.sha256(f"receipt-{index}".encode()).hexdigest(),
            }
        )
    raw = canonical_json_bytes({"schema": cli.PINNED_ADMINS_SCHEMA, "admins": records})
    config_path = _write(path, raw)
    return config_path, hashlib.sha256(raw).hexdigest()


def test_key_id_accepts_raw_and_pem_public_keys(tmp_path: Path, capsys) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected = f"ed25519-sha256:{hashlib.sha256(raw).hexdigest()}"
    raw_path = _write(tmp_path / "public.key", raw)
    pem_path = _write(
        tmp_path / "public.pem",
        public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
    )

    assert _run(capsys, "key-id", str(raw_path)) == (0, {"schema": cli.CLI_SCHEMA, "key_id": expected})
    assert _run(capsys, "key-id", "--public-key", str(pem_path)) == (0, {"schema": cli.CLI_SCHEMA, "key_id": expected})


def test_key_id_rejects_symlink(tmp_path: Path, capsys) -> None:
    target = _write(tmp_path / "real.key", b"x" * 32)
    link = tmp_path / "link.key"
    link.symlink_to(target)

    code, report = _run(capsys, "key-id", str(link))
    assert code != 0
    assert report["schema"] == cli.CLI_SCHEMA
    assert "safe" in report["error"] or "symlink" in report["error"]


def test_signing_message_is_registered_and_exact(tmp_path: Path, capsys) -> None:
    payload = {"schema": "eval.v6.2.3.trust-registry", "value": "example"}
    raw = canonical_json_bytes(payload)
    payload_path = _write(tmp_path / "payload.json", raw)

    code, report = _run(capsys, "signing-message", "--kind", "registry", "--payload", str(payload_path))
    expected_message = signing_message(DOMAIN_REGISTRY, payload)
    assert code == 0
    assert report == {
        "schema": cli.CLI_SCHEMA,
        "artifact_kind": "registry",
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "signing_message_base64": base64.b64encode(expected_message).decode("ascii"),
    }


def test_assess_rejects_wrong_pinned_config_hash_before_verifier(tmp_path: Path, capsys, monkeypatch) -> None:
    config_path, _ = _admin_config(tmp_path / "admins.json")
    called = False

    def should_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("assessment must not run with an unbound config")

    monkeypatch.setattr(cli, "assess_population_trust_file", should_not_run)
    code, report = _run(
        capsys,
        "assess",
        "--trust-bundle",
        str(tmp_path / "bundle.json"),
        "--pinned-admins",
        str(config_path),
        "--pinned-admins-sha256",
        "0" * 64,
    )
    assert code != 0
    assert not called
    assert "exact config bytes" in report["error"]


def test_assess_success_is_structural_only_and_has_no_authority(tmp_path: Path, capsys, monkeypatch) -> None:
    config_path, config_hash = _admin_config(tmp_path / "admins.json")
    bundle_path = _write(tmp_path / "bundle.json", b"{}")
    expected = {
        "schema": "eval.v6.2.3.population-trust-verdict",
        "state": "STRUCTURAL_TRUST_BUNDLE_VALID_REQUIRES_EXTERNAL_VERIFIER",
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }
    observed = {}

    def structural(path, *, pinned_registry_admins, external_verifier):
        observed["path"] = path
        observed["admins"] = pinned_registry_admins
        observed["external_verifier"] = external_verifier
        return expected

    monkeypatch.setattr(cli, "assess_population_trust_file", structural)
    code, report = _run(
        capsys,
        "assess",
        str(bundle_path),
        str(config_path),
        "--pinned-admins-sha256",
        config_hash,
    )
    assert code == 0
    assert report == expected
    assert observed["path"] == str(bundle_path)
    assert len(observed["admins"]) == 3
    assert observed["external_verifier"] is None
