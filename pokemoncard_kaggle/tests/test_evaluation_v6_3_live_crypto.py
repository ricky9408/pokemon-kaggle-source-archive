from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from evaluation_v6_2.integration_v622 import canonical_json_bytes
from evaluation_v6_3.common import SIGNATURE_SCHEMA, V63Error, key_id_for_public_key, signing_message
from evaluation_v6_3 import live_crypto
from evaluation_v6_3.live_crypto import verify_live_drand_receipt
from evaluation_v6_3.live_crypto import verify_live_rfc3161_quorum
from evaluation_v6_3.hybrid_trust import validate_hybrid_trust_profile
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from tests.test_evaluation_v6_3_hybrid_trust import _profile_fixture


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _signed_precommit(value: dict[str, object], private: dict[str, object]) -> dict[str, object]:
    core = {key: value[key] for key in value if key != "signatures"}
    value["signatures"] = [
        {
            "schema": SIGNATURE_SCHEMA,
            "party_id": party,
            "key_id": key_id_for_public_key(private[party].public_key().public_bytes_raw()),  # type: ignore[attr-defined]
            "signature_base64": base64.b64encode(
                private[party].sign(signing_message(live_crypto.DOMAIN_LIVE_CRYPTO_PRECOMMIT, core))  # type: ignore[attr-defined]
            ).decode("ascii"),
        }
        for party in ("A", "B", "C")
    ]
    return value


def _live_profile() -> tuple[dict[str, object], object, dict[str, object]]:
    raw, _, private = _profile_fixture()
    raw["crypto_runtime_policy"]["drand_verifier_script_sha256"] = live_crypto.PINNED_DRAND_SCRIPT_SHA256  # type: ignore[index]
    profile = validate_hybrid_trust_profile(raw)
    return raw, profile, private


def _drand_precommit(profile: object, private: dict[str, object]) -> dict[str, object]:
    return _signed_precommit(
        {
            "schema": live_crypto.DRAND_PRECOMMIT_SCHEMA,
            "profile_sha256": profile["sha256"],  # type: ignore[index]
            "campaign_root_sha256": _digest("campaign"),
            "review_challenge_sha256": _digest("review-challenge"),
            "single_use_token_sha256": _digest("single-use"),
            "campaign_nonce_sha256": _digest("campaign-nonce"),
            "committed_round": "72785",
            "committed_at": "2020-08-16T00:00:00Z",
            "node_executable_sha256": live_crypto.PINNED_NODE_EXECUTABLE_SHA256,
            "node_version": live_crypto.PINNED_NODE_VERSION,
            "dependency_tree_sha256": live_crypto.PINNED_DRAND_DEPENDENCY_TREE_SHA256,
            "drand_verifier_script_sha256": live_crypto.PINNED_DRAND_SCRIPT_SHA256,
            "drand_verifier_package_sha256": live_crypto.PINNED_DRAND_PACKAGE_SHA256,
            "drand_verifier_lock_sha256": live_crypto.PINNED_DRAND_LOCK_SHA256,
            "drand_client_version": live_crypto.PINNED_DRAND_CLIENT_VERSION,
        },
        private,
    )


def _drand_evidence(profile: object, precommit: dict[str, object]) -> dict[str, object]:
    policy = profile["public_roots"]["drand"]  # type: ignore[index]
    return {
        "beacon": {
            "previous_signature": "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747",
            "randomness": "8b676484b5fb1f37f9ec5c413d7d29883504e5b669f604a1ce68b3388e9ae3d9",
            "round": 72785,
            "signature": "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42",
        },
        "chain_info": {
            "genesis_time": 1595431050,
            "groupHash": "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a",
            "hash": policy["network_chain_hash"],
            "metadata": {"beaconID": "default"},
            "period": 30,
            "public_key": policy["network_public_key_hex"],
            "schemeID": "pedersen-bls-chained",
        },
        "expected_chain_hash": policy["network_chain_hash"],
        "expected_public_key": policy["network_public_key_hex"],
        "expected_round": 72785,
        "profile_sha256": profile["sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "review_challenge_sha256": precommit["review_challenge_sha256"],
        "single_use_token_sha256": precommit["single_use_token_sha256"],
        "campaign_nonce_sha256": precommit["campaign_nonce_sha256"],
        "precommit_sha256": hashlib.sha256(canonical_json_bytes(precommit)).hexdigest(),
    }


def test_live_drand_verifier_accepts_known_beacon_without_network() -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    result = verify_live_drand_receipt(
        raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
        raw_precommit=canonical_json_bytes(precommit),
        profile=profile,
    )
    assert result.round == 72785
    assert result.randomness == "8b676484b5fb1f37f9ec5c413d7d29883504e5b669f604a1ce68b3388e9ae3d9"
    assert result.network_access_used is False
    assert result.verifier == "drand-client@1.4.2"
    assert result.campaign_root_sha256 == precommit["campaign_root_sha256"]
    assert result.single_use_token_sha256 == precommit["single_use_token_sha256"]


@pytest.mark.parametrize("mutation", ["round", "signature", "chain"])
def test_live_drand_verifier_rejects_tampering(mutation: str) -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    evidence = _drand_evidence(profile, precommit)
    if mutation == "round":
        evidence["beacon"]["round"] = 72784  # type: ignore[index]
    elif mutation == "signature":
        evidence["beacon"]["signature"] = "00" * 96  # type: ignore[index]
    else:
        evidence["expected_chain_hash"] = "00" * 32
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(evidence),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "DRAND_RECEIPT_INVALID"


def test_live_drand_verifier_rejects_noncanonical_input() -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=b'{ "beacon": {} }',
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "DRAND_RECEIPT_INVALID"


def test_live_drand_verifier_requires_immutable_validated_profile() -> None:
    raw, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=raw,  # type: ignore[arg-type]
        )
    assert caught.value.code == "DRAND_RECEIPT_INVALID"


@pytest.mark.parametrize("field", ["campaign_root_sha256", "review_challenge_sha256", "single_use_token_sha256"])
def test_live_drand_requires_exact_precommitted_bindings(field: str) -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    evidence = _drand_evidence(profile, precommit)
    evidence[field] = _digest(f"changed-{field}")
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(evidence),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "DRAND_RECEIPT_INVALID"


def test_live_drand_requires_precommit_before_round() -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    precommit["committed_at"] = "2020-08-17T00:00:00Z"
    _signed_precommit(precommit, private)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "DRAND_RECEIPT_INVALID"


def test_live_drand_runtime_mutation_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    monkeypatch.setattr(live_crypto, "_dependency_tree_sha256", lambda root: "0" * 64)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE"


def test_live_drand_node_version_mutation_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    monkeypatch.setattr(live_crypto, "_node_version", lambda node: "v0.0.0")
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE"


@pytest.mark.parametrize(
    "field,replacement",
    [
        ("node_executable_sha256", "0" * 64),
        ("node_version", "v0.0.0"),
        ("dependency_tree_sha256", "0" * 64),
    ],
)
def test_live_drand_precommit_runtime_pin_mutation_fails_closed(field: str, replacement: str) -> None:
    _, profile, private = _live_profile()
    precommit = _drand_precommit(profile, private)
    precommit[field] = replacement
    _signed_precommit(precommit, private)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE"


def test_live_drand_profile_runtime_pin_mutation_fails_closed() -> None:
    raw, _, private = _profile_fixture()
    raw["crypto_runtime_policy"]["node_version"] = "v0.0.0"  # type: ignore[index]
    profile = validate_hybrid_trust_profile(raw)
    precommit = _drand_precommit(profile, private)
    with pytest.raises(V63Error) as caught:
        verify_live_drand_receipt(
            raw_evidence=canonical_json_bytes(_drand_evidence(profile, precommit)),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,
        )
    assert caught.value.code == "LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE"


def _command(*args: str, cwd: Path | None = None) -> bytes:
    completed = subprocess.run(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    return completed.stdout


def _tsa_response(directory: Path, *, label: str, query: Path, policy_oid: str) -> tuple[bytes, bytes, bytes]:
    directory.mkdir()
    openssl = shutil.which("openssl")
    assert openssl is not None
    ca_key = directory / "ca.key"
    ca_pem = directory / "ca.pem"
    tsa_key = directory / "tsa.key"
    tsa_csr = directory / "tsa.csr"
    tsa_pem = directory / "tsa.pem"
    extension = directory / "tsa-ext.cnf"
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=critical,timeStamping\n",
        encoding="ascii",
    )
    _command(
        openssl,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "2",
        "-subj",
        f"/CN=V63 Test CA {label}",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_pem),
    )
    _command(
        openssl,
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        f"/CN=V63 Test TSA {label}",
        "-keyout",
        str(tsa_key),
        "-out",
        str(tsa_csr),
    )
    _command(
        openssl,
        "x509",
        "-req",
        "-in",
        str(tsa_csr),
        "-CA",
        str(ca_pem),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(extension),
        "-out",
        str(tsa_pem),
    )
    (directory / "index.txt").write_text("", encoding="ascii")
    (directory / "ca-serial").write_text("1000\n", encoding="ascii")
    (directory / "crlnumber").write_text("1000\n", encoding="ascii")
    (directory / "newcerts").mkdir()
    ca_config = directory / "ca.cnf"
    ca_config.write_text(
        "[ca]\n"
        "default_ca = CA_default\n"
        "[CA_default]\n"
        f"database = {directory / 'index.txt'}\n"
        f"new_certs_dir = {directory / 'newcerts'}\n"
        f"certificate = {ca_pem}\n"
        f"private_key = {ca_key}\n"
        f"serial = {directory / 'ca-serial'}\n"
        f"crlnumber = {directory / 'crlnumber'}\n"
        "default_md = sha256\n"
        "default_days = 2\n"
        "default_crl_days = 2\n"
        "policy = policy_any\n"
        "[policy_any]\n"
        "commonName = optional\n",
        encoding="ascii",
    )
    crl_pem = directory / "ca.crl.pem"
    _command(openssl, "ca", "-gencrl", "-batch", "-config", str(ca_config), "-out", str(crl_pem))
    serial = directory / "serial"
    serial.write_text("01\n", encoding="ascii")
    config = directory / "tsa.cnf"
    config.write_text(
        "[tsa]\n"
        "default_tsa = tsa_config\n"
        "[tsa_config]\n"
        f"serial = {serial}\n"
        "crypto_device = builtin\n"
        f"signer_cert = {tsa_pem}\n"
        f"certs = {ca_pem}\n"
        f"signer_key = {tsa_key}\n"
        "signer_digest = sha256\n"
        f"default_policy = {policy_oid}\n"
        "digests = sha256\n"
        "accuracy = secs:1\n"
        "ordering = yes\n"
        "tsa_name = yes\n"
        "ess_cert_id_chain = no\n",
        encoding="ascii",
    )
    response = directory / "response.tsr"
    _command(
        openssl,
        "ts",
        "-reply",
        "-config",
        str(config),
        "-section",
        "tsa_config",
        "-queryfile",
        str(query),
        "-out",
        str(response),
    )
    return response.read_bytes(), ca_pem.read_bytes(), crl_pem.read_bytes()


def _rfc3161_fixture(tmp_path: Path) -> tuple[
    bytes,
    tuple[bytes, bytes],
    tuple[bytes, bytes],
    tuple[bytes, bytes],
    object,
    dict[str, object],
    str,
]:
    openssl = shutil.which("openssl")
    assert openssl is not None
    data = tmp_path / "payload.bin"
    data.write_bytes(b"evaluation-v6.3-rfc3161-test")
    query = tmp_path / "request.tsq"
    _command(openssl, "ts", "-query", "-data", str(data), "-sha256", "-cert", "-out", str(query))
    response_d, root_d, crl_d = _tsa_response(tmp_path / "tsa-d", label="D", query=query, policy_oid="1.2.3.4.1")
    response_e, root_e, crl_e = _tsa_response(tmp_path / "tsa-e", label="E", query=query, policy_oid="1.2.3.4.2")
    raw_profile, _, private = _profile_fixture()
    for index, root in enumerate((root_d, root_e)):
        certificate = x509.load_pem_x509_certificate(root)
        raw_profile["time_authorities"][index]["certificate_root_sha256"] = hashlib.sha256(
            certificate.public_bytes(Encoding.DER)
        ).hexdigest()
        raw_profile["time_authorities"][index]["revocation_policy_root_sha256"] = hashlib.sha256(
            (crl_d, crl_e)[index]
        ).hexdigest()
    raw_profile["crypto_runtime_policy"]["rfc3161_openssl_binary_sha256"] = hashlib.sha256(
        Path(openssl).read_bytes()
    ).hexdigest()
    raw_profile["crypto_runtime_policy"]["rfc3161_openssl_version"] = _command(openssl, "version").decode("ascii").strip()
    raw_profile["crypto_runtime_policy"]["drand_verifier_script_sha256"] = live_crypto.PINNED_DRAND_SCRIPT_SHA256
    profile = validate_hybrid_trust_profile(raw_profile)
    query_bytes = query.read_bytes()
    query_text = _command(openssl, "ts", "-query", "-in", str(query), "-text").decode("utf-8")
    nonce_match = re.search(r"^Nonce:\s*(\S+)$", query_text, re.MULTILINE)
    assert nonce_match is not None
    return query_bytes, (response_d, response_e), (root_d, root_e), (crl_d, crl_e), profile, private, nonce_match.group(1)


def _rfc3161_precommit(
    profile: object,
    private: dict[str, object],
    query: bytes,
    nonce: str,
) -> dict[str, object]:
    runtime = profile["crypto_runtime_policy"]  # type: ignore[index]
    return _signed_precommit(
        {
            "schema": live_crypto.RFC3161_PRECOMMIT_SCHEMA,
            "profile_sha256": profile["sha256"],  # type: ignore[index]
            "campaign_root_sha256": _digest("campaign-rfc"),
            "review_challenge_sha256": _digest("review-challenge-rfc"),
            "single_use_token_sha256": _digest("single-use-rfc"),
            "campaign_nonce_sha256": _digest("campaign-nonce-rfc"),
            "payload_sha256": _digest("evaluation-v6.3-rfc3161-test"),
            "query_sha256": hashlib.sha256(query).hexdigest(),
            "rfc3161_nonce": nonce,
            "tsa_policy_oids": ["1.2.3.4.1", "1.2.3.4.2"],
            "openssl_binary_sha256": runtime["rfc3161_openssl_binary_sha256"],
            "openssl_version": runtime["rfc3161_openssl_version"],
            "node_executable_sha256": live_crypto.PINNED_NODE_EXECUTABLE_SHA256,
            "node_version": live_crypto.PINNED_NODE_VERSION,
            "dependency_tree_sha256": live_crypto.PINNED_DRAND_DEPENDENCY_TREE_SHA256,
            "drand_verifier_script_sha256": live_crypto.PINNED_DRAND_SCRIPT_SHA256,
            "drand_verifier_package_sha256": live_crypto.PINNED_DRAND_PACKAGE_SHA256,
            "drand_verifier_lock_sha256": live_crypto.PINNED_DRAND_LOCK_SHA256,
            "drand_client_version": live_crypto.PINNED_DRAND_CLIENT_VERSION,
            "committed_at": "2026-07-16T10:00:00Z",
        },
        private,
    )


def test_live_rfc3161_quorum_verifies_two_independent_tokens(tmp_path: Path) -> None:
    query, responses, roots, revocation, profile, private, nonce = _rfc3161_fixture(tmp_path)
    precommit = _rfc3161_precommit(profile, private, query, nonce)
    result = verify_live_rfc3161_quorum(
        raw_query=query,
        raw_responses=responses,
        root_certificates_pem=roots,
        revocation_material_pem=revocation,
        untrusted_certificates_pem=(None, None),
        raw_precommit=canonical_json_bytes(precommit),
        profile=profile,  # type: ignore[arg-type]
    )
    assert len(result.response_sha256s) == 2
    assert len(set(result.root_certificate_der_sha256s)) == 2
    assert result.nonce
    assert result.policy_oids == ("1.2.3.4.1", "1.2.3.4.2")
    assert result.query_sha256 == precommit["query_sha256"]
    assert result.campaign_root_sha256 == precommit["campaign_root_sha256"]


def test_live_rfc3161_quorum_rejects_tampered_response(tmp_path: Path) -> None:
    query, responses, roots, revocation, profile, private, nonce = _rfc3161_fixture(tmp_path)
    precommit = _rfc3161_precommit(profile, private, query, nonce)
    tampered = responses[0][:-1] + bytes([responses[0][-1] ^ 1])
    with pytest.raises(V63Error) as caught:
        verify_live_rfc3161_quorum(
            raw_query=query,
            raw_responses=(tampered, responses[1]),
            root_certificates_pem=roots,
            revocation_material_pem=revocation,
            untrusted_certificates_pem=(None, None),
            raw_precommit=canonical_json_bytes(precommit),
            profile=profile,  # type: ignore[arg-type]
        )
    assert caught.value.code == "RFC3161_RECEIPT_INVALID"


def test_live_rfc3161_requires_expected_query_payload_nonce_and_oids(tmp_path: Path) -> None:
    query, responses, roots, revocation, profile, private, nonce = _rfc3161_fixture(tmp_path)
    precommit = _rfc3161_precommit(profile, private, query, nonce)
    for field, replacement in (
        ("query_sha256", _digest("wrong-query")),
        ("payload_sha256", _digest("wrong-payload")),
        ("rfc3161_nonce", "0xdeadbeef"),
        ("tsa_policy_oids", ["1.2.3.4.9", "1.2.3.4.2"]),
    ):
        broken = deepcopy(precommit)
        broken[field] = replacement
        _signed_precommit(broken, private)
        with pytest.raises(V63Error) as caught:
            verify_live_rfc3161_quorum(
                raw_query=query,
                raw_responses=responses,
                root_certificates_pem=roots,
                revocation_material_pem=revocation,
                untrusted_certificates_pem=(None, None),
                raw_precommit=canonical_json_bytes(broken),
                profile=profile,  # type: ignore[arg-type]
            )
        assert caught.value.code == "RFC3161_RECEIPT_INVALID"
