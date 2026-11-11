"""Fail-closed external-cryptography checks for Evaluation v6.3.1.

The public functions return only zero-authority evidence reports. RFC3161 and
drand mechanics can be checked, but the repository has no externally pinned
revocation or organization-identity evidence and therefore cannot produce a
live-valid proof, permit, holdout authority, or upload authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads

from .common import canonical_integer, exact, fail, identifier, sha256, zero_authority
from .policy import ValidatedV631Policy, require_validated_policy


LIVE_PRECOMMIT_SCHEMA = "eval.v6.3.1.live-crypto-precommit"
SHA256_OID = "2.16.840.1.101.3.4.2.1"

QUICKNET_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_PUBLIC_KEY_HEX = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
    "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
    "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
QUICKNET_GENESIS_TIME = 1692803367
QUICKNET_PERIOD_SECONDS = 3
QUICKNET_GROUP_HASH = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e"
QUICKNET_SCHEME_ID = "bls-unchained-g1-rfc9380"
QUICKNET_BEACON_ID = "quicknet"

_ROOT = Path(__file__).resolve().parents[1]
_DRAND_RUNTIME = _ROOT / "evaluation_v6_3" / "drand_verifier"
_DRAND_SCRIPT = _DRAND_RUNTIME / "verify.mjs"
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_OID_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_QUERY_HEX_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]{4}\s+-\s+(.+)$")

_PRECOMMIT_FIELDS = frozenset(
    {
        "schema",
        "policy_sha256",
        "campaign_root_sha256",
        "preregistration_root_sha256",
        "assignment_root_sha256",
        "archive_sha256",
        "slot_id",
        "a_previous_journal_head_sha256",
        "b_previous_journal_head_sha256",
        "committed_drand_round",
    }
)


def _require_bytes(value: Any, label: str, *, code: str) -> bytes:
    if type(value) is not bytes or not value:
        raise fail(code, f"{label} must be nonempty bytes")
    return value


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", f"unable to read pinned artifact {path}") from exc


def _tree_sha256(root: Path) -> str:
    """Hash every path, type, mode, and file byte under a non-symlink tree."""
    try:
        if not root.is_absolute() or root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError("runtime root is not an absolute real directory")
        paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    except (OSError, ValueError) as exc:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", "drand verifier tree is unavailable or redirected") from exc
    digest = hashlib.sha256()
    for path in paths:
        if path.is_symlink():
            raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", "drand verifier tree contains a symlink")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        mode = stat.S_IMODE(path.stat().st_mode)
        if path.is_dir():
            kind = b"D"
            content = b""
        elif path.is_file():
            kind = b"F"
            content = path.read_bytes()
        else:
            raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", "drand verifier tree contains a special file")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(kind)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def drand_verifier_root_sha256() -> str:
    """Return the current complete verifier-tree digest for policy review."""
    return _tree_sha256(_DRAND_RUNTIME)


def _verified_executable(path_text: str, expected_sha256: str, *, label: str) -> str:
    path = Path(path_text)
    try:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or path.resolve(strict=True) != path
            or not path.is_file()
            or not os.access(path, os.X_OK)
        ):
            raise ValueError("not a pinned executable")
    except (OSError, ValueError) as exc:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", f"{label} path is missing, redirected, or non-executable") from exc
    if _file_sha256(path) != expected_sha256:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", f"{label} executable digest differs from policy")
    return str(path)


def _verify_runtime(policy: ValidatedV631Policy) -> tuple[str, str]:
    runtime = policy["crypto_runtime"]
    openssl = _verified_executable(
        runtime["openssl_executable_path"],
        runtime["openssl_executable_sha256"],
        label="OpenSSL",
    )
    node = _verified_executable(
        runtime["node_executable_path"],
        runtime["node_executable_sha256"],
        label="Node",
    )
    if runtime["rfc3161_imprint_oid"] != SHA256_OID:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", "policy does not pin the SHA-256 imprint OID")
    if _tree_sha256(_DRAND_RUNTIME) != policy["drand"]["live_verifier_root_sha256"]:
        raise fail("V631_CRYPTO_RUNTIME_UNAVAILABLE", "complete drand verifier tree differs from policy")
    return openssl, node


def _sanitized_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent-v631-crypto-home",
        "LANG": "C",
        "LC_ALL": "C",
        "NODE_NO_WARNINGS": "1",
        "NODE_OPTIONS": "",
        "NODE_PATH": "",
        "OPENSSL_CONF": os.devnull,
        "PATH": "/usr/bin:/bin",
        "SSL_CERT_DIR": "/nonexistent-v631-cert-dir",
        "SSL_CERT_FILE": os.devnull,
        "TZ": "UTC",
    }


def _run(command: list[str], *, input_bytes: bytes | None = None, code: str, label: str) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
            env=_sanitized_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail(code, f"{label} could not execute") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise fail(code, f"{label} failed: {detail or 'no detail'}")
    return completed


def _canonical_object(raw: bytes, *, label: str, code: str) -> dict[str, Any]:
    raw = _require_bytes(raw, label, code=code)
    if raw.startswith(b"\xef\xbb\xbf") or raw.endswith(b"\n") or b"\r" in raw:
        raise fail(code, f"{label} must be unframed canonical JSON")
    try:
        value = canonical_json_loads(raw)
    except Exception as exc:
        raise fail(code, f"{label} is not duplicate-free JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise fail(code, f"{label} must be a canonical JSON object")
    return value


def _parse_precommit(raw_precommit: bytes, *, policy: ValidatedV631Policy, code: str) -> dict[str, Any]:
    item = exact(
        _canonical_object(raw_precommit, label="live precommit", code=code),
        _PRECOMMIT_FIELDS,
        "live precommit",
        code=code,
    )
    if item["schema"] != LIVE_PRECOMMIT_SCHEMA or item["policy_sha256"] != policy["sha256"]:
        raise fail(code, "live precommit schema or exact policy digest is wrong")
    bindings = {
        field: sha256(item[field], field, code=code)
        for field in (
            "policy_sha256",
            "campaign_root_sha256",
            "preregistration_root_sha256",
            "assignment_root_sha256",
            "archive_sha256",
            "a_previous_journal_head_sha256",
            "b_previous_journal_head_sha256",
        )
    }
    slot_id = identifier(item["slot_id"], "slot id", code=code)
    committed_round = canonical_integer(
        item["committed_drand_round"], "committed drand round", code=code, minimum=1
    )
    return {
        **dict(item),
        **bindings,
        "slot_id": slot_id,
        "committed_drand_round_int": committed_round,
        "sha256": hashlib.sha256(raw_precommit).hexdigest(),
    }


def _root_der_sha256(pem: bytes, *, code: str) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise fail(code, "TSA root is not a PEM X.509 certificate") from exc
    return hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()


def _root_spki_sha256(pem: bytes, *, code: str) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise fail(code, "TSA root is not a PEM X.509 certificate") from exc
    return _spki_sha256(certificate)


def _message_imprint(text: str, *, code: str, label: str) -> tuple[str, str]:
    digest_bytes = bytearray()
    algorithms: list[str] = []
    in_message = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Hash Algorithm:"):
            algorithms.append(stripped.removeprefix("Hash Algorithm:").strip())
        if stripped == "Message data:":
            in_message = True
            continue
        if in_message:
            match = _QUERY_HEX_LINE_RE.match(line)
            if match:
                tokens = match.group(1).split("   ", 1)[0].replace("-", " ").split()
                if not tokens or any(re.fullmatch(r"[0-9a-fA-F]{2}", token) is None for token in tokens):
                    raise fail(code, f"{label} message imprint is malformed")
                digest_bytes.extend(bytes.fromhex("".join(tokens)))
                continue
            in_message = False
    if algorithms != ["sha256"] or len(digest_bytes) != 32:
        raise fail(code, f"{label} must use the exact SHA-256 imprint OID")
    return SHA256_OID, digest_bytes.hex()


def _query_details(text: str, *, code: str) -> dict[str, str]:
    algorithm_oid, imprint = _message_imprint(text, code=code, label="RFC3161 query")
    nonces = [
        line.strip().removeprefix("Nonce:").strip()
        for line in text.splitlines()
        if line.strip().startswith("Nonce:")
    ]
    if len(nonces) != 1 or not nonces[0]:
        raise fail(code, "RFC3161 query must contain exactly one nonce")
    return {"algorithm_oid": algorithm_oid, "imprint": imprint, "nonce": nonces[0]}


def _timestamp_details(text: str, *, code: str) -> dict[str, Any]:
    algorithm_oid, imprint = _message_imprint(text, code=code, label="RFC3161 response")
    values: dict[str, str] = {}
    labels = {
        "Policy OID:": "policy_oid",
        "Serial number:": "serial_number",
        "Time stamp:": "gen_time",
        "Nonce:": "nonce",
    }
    counts = {name: 0 for name in labels.values()}
    for line in text.splitlines():
        stripped = line.strip()
        for prefix, name in labels.items():
            if stripped.startswith(prefix):
                counts[name] += 1
                values[name] = stripped.removeprefix(prefix).strip()
    if any(count != 1 for count in counts.values()) or any(not values.get(name) for name in counts):
        raise fail(code, "RFC3161 response must contain one policy, serial, genTime, and nonce")
    if _OID_RE.fullmatch(values["policy_oid"]) is None:
        raise fail(code, "RFC3161 response policy OID is malformed")
    for format_string in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S.%f %Y GMT"):
        try:
            gen_time = datetime.strptime(values["gen_time"], format_string).replace(tzinfo=timezone.utc)
            return {**values, "algorithm_oid": algorithm_oid, "imprint": imprint, "gen_time": gen_time}
        except ValueError:
            pass
    raise fail(code, "RFC3161 response genTime is malformed")


def _spki_sha256(certificate: x509.Certificate) -> str:
    spki = certificate.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _timestamp_signer_spki(certificates_pem: bytes, *, code: str) -> str:
    try:
        certificates = x509.load_pem_x509_certificates(certificates_pem)
    except ValueError as exc:
        raise fail(code, "RFC3161 token certificate set is malformed") from exc
    signers: list[x509.Certificate] = []
    for certificate in certificates:
        try:
            basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
            eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if basic.ca is False and ExtendedKeyUsageOID.TIME_STAMPING in eku:
            signers.append(certificate)
    if len(signers) != 1:
        raise fail(code, "RFC3161 token must contain exactly one timestamp signer certificate")
    return _spki_sha256(signers[0])


def _verify_rfc3161_evidence(
    *,
    raw_precommit: bytes,
    raw_query: bytes,
    raw_responses: tuple[bytes, bytes],
    root_certificates_pem: tuple[bytes, bytes],
    policy: ValidatedV631Policy,
    openssl: str,
    code: str,
) -> dict[str, Any]:
    precommit = _parse_precommit(raw_precommit, policy=policy, code=code)
    raw_query = _require_bytes(raw_query, "RFC3161 query", code=code)
    if (
        type(raw_responses) is not tuple
        or len(raw_responses) != 2
        or type(root_certificates_pem) is not tuple
        or len(root_certificates_pem) != 2
    ):
        raise fail(code, "RFC3161 evidence must provide exactly D and E inputs")
    responses = tuple(
        _require_bytes(value, f"TSA response {index}", code=code)
        for index, value in enumerate(raw_responses)
    )
    roots = tuple(
        _require_bytes(value, f"TSA root {index}", code=code)
        for index, value in enumerate(root_certificates_pem)
    )
    root_hashes = tuple(_root_der_sha256(value, code=code) for value in roots)
    root_spki_hashes = tuple(_root_spki_sha256(value, code=code) for value in roots)
    authorities = policy["time_authorities"]
    expected_roots = tuple(authority["trust_root_sha256"] for authority in authorities)
    expected_oids = tuple(authority["tsa_policy_oid"] for authority in authorities)
    expected_signers = tuple(authority["tsa_signer_spki_sha256"] for authority in authorities)
    expected_revocation_issuers = tuple(
        authority["revocation_issuer_spki_sha256"] for authority in authorities
    )
    if root_hashes != expected_roots or len(set(root_hashes)) != 2:
        raise fail(code, "D/E trust roots are not independently policy-pinned")
    if root_spki_hashes != expected_revocation_issuers or len(set(root_spki_hashes)) != 2:
        raise fail(code, "D/E revocation issuer SPKIs are not independently policy-pinned")

    precommit_sha256 = hashlib.sha256(raw_precommit).hexdigest()
    parsed: list[dict[str, Any]] = []
    signer_hashes: list[str] = []
    with tempfile.TemporaryDirectory(prefix="eval-v631-rfc3161-") as temporary:
        directory = Path(temporary)
        query_path = directory / "request.tsq"
        query_path.write_bytes(raw_query)
        query_rendered = _run(
            [openssl, "ts", "-query", "-in", str(query_path), "-text"],
            code=code,
            label="RFC3161 query rendering",
        )
        query = _query_details(query_rendered.stdout.decode("utf-8", errors="strict"), code=code)
        if query["algorithm_oid"] != SHA256_OID or query["imprint"] != precommit_sha256:
            raise fail(code, "RFC3161 query does not SHA-256 imprint the exact precommit")
        for index, response in enumerate(responses):
            response_path = directory / f"response-{index}.tsr"
            root_path = directory / f"root-{index}.pem"
            token_path = directory / f"token-{index}.p7"
            response_path.write_bytes(response)
            root_path.write_bytes(roots[index])
            rendered = _run(
                [openssl, "ts", "-reply", "-in", str(response_path), "-text"],
                code=code,
                label=f"RFC3161 response {index} rendering",
            )
            token = _timestamp_details(rendered.stdout.decode("utf-8", errors="strict"), code=code)
            _run(
                [openssl, "ts", "-reply", "-in", str(response_path), "-token_out", "-out", str(token_path)],
                code=code,
                label=f"RFC3161 response {index} token extraction",
            )
            certificates = _run(
                [openssl, "pkcs7", "-inform", "DER", "-in", str(token_path), "-print_certs", "-quiet", "-outform", "PEM"],
                code=code,
                label=f"RFC3161 response {index} certificate extraction",
            )
            signer_hashes.append(_timestamp_signer_spki(certificates.stdout, code=code))
            verified = _run(
                [
                    openssl,
                    "ts",
                    "-verify",
                    "-queryfile",
                    str(query_path),
                    "-in",
                    str(response_path),
                    "-CAfile",
                    str(root_path),
                    "-attime",
                    str(int(token["gen_time"].timestamp())),
                    "-x509_strict",
                ],
                code=code,
                label=f"RFC3161 response {index} CMS verification",
            )
            if b"Verification: OK" not in verified.stdout:
                raise fail(code, f"RFC3161 response {index} did not verify")
            if token["algorithm_oid"] != SHA256_OID or token["imprint"] != precommit_sha256:
                raise fail(code, "RFC3161 response does not SHA-256 imprint the exact precommit")
            parsed.append(token)
    if tuple(signer_hashes) != expected_signers or len(set(signer_hashes)) != 2:
        raise fail(code, "D/E timestamp signer SPKIs are not independently policy-pinned")
    if tuple(token["nonce"] for token in parsed) != (query["nonce"], query["nonce"]):
        raise fail(code, "RFC3161 response nonce differs from the exact query nonce")
    if tuple(token["policy_oid"] for token in parsed) != expected_oids:
        raise fail(code, "RFC3161 response policy OIDs differ from D/E policy pins")
    gen_times = (parsed[0]["gen_time"], parsed[1]["gen_time"])
    if abs(gen_times[0] - gen_times[1]) > timedelta(seconds=120):
        raise fail(code, "D/E RFC3161 genTimes differ by more than 120 seconds")
    response_hashes = tuple(hashlib.sha256(response).hexdigest() for response in responses)
    if len(set(response_hashes)) != 2:
        raise fail(code, "D/E RFC3161 responses must be distinct")
    return {
        "precommit": precommit,
        "query_sha256": hashlib.sha256(raw_query).hexdigest(),
        "nonce": query["nonce"],
        "response_sha256s": response_hashes,
        "root_certificate_der_sha256s": root_hashes,
        "signer_spki_sha256s": tuple(signer_hashes),
        "policy_oids": expected_oids,
        "serial_numbers": (parsed[0]["serial_number"], parsed[1]["serial_number"]),
        "gen_times": gen_times,
    }


def _verify_quicknet_policy(policy: ValidatedV631Policy, *, code: str) -> None:
    drand = policy["drand"]
    expected = {
        "chain_hash": QUICKNET_CHAIN_HASH,
        "public_key_bytes": bytes.fromhex(QUICKNET_PUBLIC_KEY_HEX),
        "genesis_time_int": QUICKNET_GENESIS_TIME,
        "period_seconds_int": QUICKNET_PERIOD_SECONDS,
        "group_hash": QUICKNET_GROUP_HASH,
        "scheme_id": QUICKNET_SCHEME_ID,
        "beacon_id": QUICKNET_BEACON_ID,
    }
    if any(drand[field] != value for field, value in expected.items()):
        raise fail(code, "policy does not pin the exact Quicknet chain, key, schedule, scheme, group, and beacon")


def _parse_beacon(raw_beacon: bytes, *, code: str) -> dict[str, Any]:
    beacon = exact(
        _canonical_object(raw_beacon, label="Quicknet beacon", code=code),
        frozenset({"round", "randomness", "signature"}),
        "Quicknet beacon",
        code=code,
    )
    if type(beacon["round"]) is not int or not (1 <= beacon["round"] <= 2**53 - 1):
        raise fail(code, "Quicknet round must be a positive safe integer")
    if any(
        type(beacon[field]) is not str or _HEX_RE.fullmatch(beacon[field]) is None
        for field in ("randomness", "signature")
    ):
        raise fail(code, "Quicknet randomness or signature is not lowercase hexadecimal")
    if len(beacon["randomness"]) != 64 or len(beacon["signature"]) != 96:
        raise fail(code, "Quicknet beacon has an unexpected randomness or signature length")
    if hashlib.sha256(bytes.fromhex(beacon["signature"])).hexdigest() != beacon["randomness"]:
        raise fail(code, "Quicknet randomness is not SHA-256(signature)")
    return dict(beacon)


def _verify_quicknet_signature(
    *,
    raw_beacon: bytes,
    beacon: Mapping[str, Any],
    precommit: Mapping[str, Any],
    policy: ValidatedV631Policy,
    node: str,
    code: str,
) -> dict[str, Any]:
    evidence = {
        "beacon": dict(beacon),
        "campaign_nonce_sha256": precommit["assignment_root_sha256"],
        "campaign_root_sha256": precommit["campaign_root_sha256"],
        "chain_info": {
            "genesis_time": QUICKNET_GENESIS_TIME,
            "groupHash": QUICKNET_GROUP_HASH,
            "hash": QUICKNET_CHAIN_HASH,
            "metadata": {"beaconID": QUICKNET_BEACON_ID},
            "period": QUICKNET_PERIOD_SECONDS,
            "public_key": QUICKNET_PUBLIC_KEY_HEX,
            "schemeID": QUICKNET_SCHEME_ID,
        },
        "expected_chain_hash": QUICKNET_CHAIN_HASH,
        "expected_public_key": QUICKNET_PUBLIC_KEY_HEX,
        "expected_round": beacon["round"],
        "precommit_sha256": precommit["sha256"],
        "profile_sha256": policy["sha256"],
        "review_challenge_sha256": precommit["preregistration_root_sha256"],
        "single_use_token_sha256": precommit["archive_sha256"],
    }
    raw_evidence = canonical_json_bytes(evidence)
    completed = _run(
        [
            node,
            "--permission",
            f"--allow-fs-read={_DRAND_RUNTIME}",
            str(_DRAND_SCRIPT),
        ],
        input_bytes=raw_evidence,
        code=code,
        label="Quicknet signature verification",
    )
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail(code, "Quicknet verifier output is invalid JSON") from exc
    expected_fields = {
        "input_sha256",
        "network_access_used",
        "public_key",
        "randomness",
        "round",
        "scheme_id",
        "signature_verified",
        "verifier",
    }
    if type(report) is not dict or set(report) != expected_fields:
        raise fail(code, "Quicknet verifier output fields are not exact")
    if (
        report["input_sha256"] != hashlib.sha256(raw_evidence).hexdigest()
        or report["public_key"] != QUICKNET_PUBLIC_KEY_HEX
        or report["randomness"] != beacon["randomness"]
        or report["round"] != str(beacon["round"])
        or report["scheme_id"] != QUICKNET_SCHEME_ID
        or report["signature_verified"] is not True
    ):
        raise fail(code, "Quicknet verifier output is not bound to the exact beacon and policy")
    return {
        "beacon_sha256": hashlib.sha256(raw_beacon).hexdigest(),
        "randomness": beacon["randomness"],
        "signature_sha256": hashlib.sha256(bytes.fromhex(beacon["signature"])).hexdigest(),
    }


def _bindings(precommit: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: precommit[field]
        for field in (
            "policy_sha256",
            "campaign_root_sha256",
            "preregistration_root_sha256",
            "assignment_root_sha256",
            "archive_sha256",
            "slot_id",
            "a_previous_journal_head_sha256",
            "b_previous_journal_head_sha256",
            "committed_drand_round",
        )
    }


def _unavailable_report(*, stage: str, rfc: Mapping[str, Any], drand: Mapping[str, Any] | None = None) -> dict[str, Any]:
    extra: dict[str, Any] = {
        "authority": "NO_UPLOAD",
        "verified_stage": stage,
        "precommit_sha256": rfc["precommit"]["sha256"],
        "precommit_bindings": _bindings(rfc["precommit"]),
        "rfc3161_query_sha256": rfc["query_sha256"],
        "rfc3161_response_sha256s": list(rfc["response_sha256s"]),
        "rfc3161_mechanics_verified": True,
        "revocation_evidence_verified": False,
        "external_tsa_identity_verified": False,
    }
    if drand is not None:
        extra.update(
            {
                "drand_beacon_sha256": drand["beacon_sha256"],
                "drand_round": str(rfc["precommit"]["committed_drand_round_int"]),
                "drand_randomness": drand["randomness"],
                "drand_signature_mechanics_verified": True,
            }
        )
    return zero_authority(
        "REVOCATION_EVIDENCE_MISSING/IDENTITY_UNVERIFIED",
        detail=(
            "Cryptographic mechanics were checked against policy pins, but no externally acquired and "
            "policy-rooted CRL/OCSP or organization-identity evidence is present. AUTHORITY=NO_UPLOAD."
        ),
        extra=extra,
    )


def verify_live_rfc3161_quorum(
    *,
    raw_precommit: bytes,
    raw_query: bytes,
    raw_responses: tuple[bytes, bytes],
    root_certificates_pem: tuple[bytes, bytes],
    policy: ValidatedV631Policy,
) -> dict[str, Any]:
    """Reverify raw RFC3161 evidence and return only a zero-authority report."""
    policy = require_validated_policy(policy)
    openssl, _ = _verify_runtime(policy)
    rfc = _verify_rfc3161_evidence(
        raw_precommit=raw_precommit,
        raw_query=raw_query,
        raw_responses=raw_responses,
        root_certificates_pem=root_certificates_pem,
        policy=policy,
        openssl=openssl,
        code="V631_LIVE_RFC3161_INVALID",
    )
    return _unavailable_report(stage="RFC3161_MECHANICS_ONLY", rfc=rfc)


def verify_live_drand_receipt(
    *,
    raw_precommit: bytes,
    raw_query: bytes,
    raw_responses: tuple[bytes, bytes],
    root_certificates_pem: tuple[bytes, bytes],
    raw_beacon: bytes,
    policy: ValidatedV631Policy,
) -> dict[str, Any]:
    """Reverify raw RFC3161 and Quicknet bytes without accepting typed proofs."""
    policy = require_validated_policy(policy)
    openssl, node = _verify_runtime(policy)
    rfc = _verify_rfc3161_evidence(
        raw_precommit=raw_precommit,
        raw_query=raw_query,
        raw_responses=raw_responses,
        root_certificates_pem=root_certificates_pem,
        policy=policy,
        openssl=openssl,
        code="V631_LIVE_DRAND_INVALID",
    )
    _verify_quicknet_policy(policy, code="V631_LIVE_DRAND_INVALID")
    beacon = _parse_beacon(raw_beacon, code="V631_LIVE_DRAND_INVALID")
    committed_round = rfc["precommit"]["committed_drand_round_int"]
    if beacon["round"] != committed_round:
        raise fail("V631_LIVE_DRAND_INVALID", "Quicknet beacon round differs from the exact precommit")
    try:
        round_time = datetime.fromtimestamp(
            QUICKNET_GENESIS_TIME + (committed_round - 1) * QUICKNET_PERIOD_SECONDS,
            tz=timezone.utc,
        )
    except (OSError, OverflowError, ValueError) as exc:
        raise fail("V631_LIVE_DRAND_INVALID", "Quicknet round time is not representable") from exc
    if max(rfc["gen_times"]) >= round_time:
        raise fail("V631_LIVE_DRAND_INVALID", "committed Quicknet round was not future after both TSA times")
    drand = _verify_quicknet_signature(
        raw_beacon=raw_beacon,
        beacon=beacon,
        precommit=rfc["precommit"],
        policy=policy,
        node=node,
        code="V631_LIVE_DRAND_INVALID",
    )
    return _unavailable_report(stage="RFC3161_AND_DRAND_MECHANICS_ONLY", rfc=rfc, drand=drand)


__all__ = [
    "LIVE_PRECOMMIT_SCHEMA",
    "QUICKNET_BEACON_ID",
    "QUICKNET_CHAIN_HASH",
    "QUICKNET_GENESIS_TIME",
    "QUICKNET_GROUP_HASH",
    "QUICKNET_PERIOD_SECONDS",
    "QUICKNET_PUBLIC_KEY_HEX",
    "QUICKNET_SCHEME_ID",
    "SHA256_OID",
    "drand_verifier_root_sha256",
    "verify_live_drand_receipt",
    "verify_live_rfc3161_quorum",
]
