"""Pinned live cryptographic verifiers for evaluation v6.3.

Only drand is implemented here. Ethereum execution/finality proofs and RFC3161
CMS/path/revocation verification remain explicit blockers in hybrid_trust.py.
The drand verifier is network-denied by Node's permission model and uses the
official lockfile-pinned drand-client package.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from evaluation_v6_2.integration_v622 import canonical_json_bytes, canonical_json_loads

from .common import canonical_integer, fail, identifier, sha256, utc, verify_signature_set
from .hybrid_trust import ValidatedHybridProfile


ROOT = Path(__file__).resolve().parent
DRAND_RUNTIME = ROOT / "drand_verifier"
DRAND_SCRIPT = DRAND_RUNTIME / "verify.mjs"
DRAND_PACKAGE = DRAND_RUNTIME / "package.json"
DRAND_LOCK = DRAND_RUNTIME / "package-lock.json"
DRAND_MODULE = DRAND_RUNTIME / "node_modules" / "drand-client" / "package.json"

PINNED_DRAND_SCRIPT_SHA256 = "69a42cfd846a32a9403c5f5fc57a1efb63299373871ccf2d023aa21cf2486e12"
PINNED_DRAND_PACKAGE_SHA256 = "bf362e0016798f809eb333f0f9589419e8fe38f3c1cade01dfd48833dba77e82"
PINNED_DRAND_LOCK_SHA256 = "294fdefce98916f000a0c2ae21b27d988103c4bf0cd036a3543b4c89379a4a5a"
PINNED_DRAND_CLIENT_VERSION = "1.4.2"
PINNED_NODE_VERSION = "v26.5.0"
PINNED_NODE_EXECUTABLE_SHA256 = "19fa44ac565968cd4dbf38277854c829e441598f0872223881002efb471b40e9"
PINNED_DRAND_DEPENDENCY_TREE_SHA256 = "fbcaf38ddf92f05b063097e3b695cbc4e11d06bcc46fb5498965b7a8d9f03993"
PINNED_DRAND_GENESIS_TIME = 1595431050
PINNED_DRAND_PERIOD = 30
PINNED_DRAND_GROUP_HASH = "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
PINNED_DRAND_SCHEME_ID = "pedersen-bls-chained"
PINNED_DRAND_BEACON_ID = "default"

DRAND_PRECOMMIT_SCHEMA = "eval.v6.3.live-drand-precommit"
RFC3161_PRECOMMIT_SCHEMA = "eval.v6.3.live-rfc3161-precommit"
DOMAIN_LIVE_CRYPTO_PRECOMMIT = b"EVAL-V63/LIVE-CRYPTO-PRECOMMIT\0"
_OID_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+$")
_QUERY_HEX_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]{4}\s+-\s+(.+)$")

_DRAND_SENTINEL = object()


@dataclass(frozen=True)
class LiveDrandVerification:
    input_sha256: str
    profile_sha256: str
    precommit_sha256: str
    campaign_root_sha256: str
    review_challenge_sha256: str
    single_use_token_sha256: str
    campaign_nonce_sha256: str
    committed_at: datetime
    round: int
    randomness: str
    scheme_id: str
    public_key: str
    verifier: str
    verifier_script_sha256: str
    verifier_lock_sha256: str
    network_access_used: bool
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _DRAND_SENTINEL:
            raise ValueError("LiveDrandVerification can only be created by verify_live_drand_receipt")


_RFC3161_SENTINEL = object()


@dataclass(frozen=True)
class LiveRFC3161Quorum:
    query_sha256: str
    precommit_sha256: str
    profile_sha256: str
    campaign_root_sha256: str
    review_challenge_sha256: str
    single_use_token_sha256: str
    campaign_nonce_sha256: str
    payload_sha256: str
    rfc3161_nonce: str
    response_sha256s: tuple[str, str]
    root_certificate_der_sha256s: tuple[str, str]
    revocation_material_sha256s: tuple[str, str]
    policy_oids: tuple[str, str]
    serial_numbers: tuple[str, str]
    gen_times: tuple[datetime, datetime]
    nonce: str
    openssl_binary_sha256: str
    openssl_version: str
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _RFC3161_SENTINEL:
            raise ValueError("LiveRFC3161Quorum can only be created by verify_live_rfc3161_quorum")


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", f"unable to read pinned drand verifier file {path.name}") from exc


def _dependency_tree_sha256(root: Path) -> str:
    if not root.is_dir() or root.is_symlink():
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "drand dependency tree is unavailable or symlinked")
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "drand dependency tree contains a symlink")
    files = [path for path in paths if path.is_file()]
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _node_version(node: str) -> str:
    try:
        completed = subprocess.run(
            [node, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", ""), "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "Node version probe failed") from exc
    if completed.returncode != 0 or completed.stderr:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "Node version probe returned an error")
    return completed.stdout.decode("ascii", errors="strict").strip()


def _verify_runtime(profile: ValidatedHybridProfile, precommit: dict[str, Any]) -> str:
    expected = {
        DRAND_SCRIPT: PINNED_DRAND_SCRIPT_SHA256,
        DRAND_PACKAGE: PINNED_DRAND_PACKAGE_SHA256,
        DRAND_LOCK: PINNED_DRAND_LOCK_SHA256,
    }
    for path, digest in expected.items():
        if _file_sha256(path) != digest:
            raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", f"pinned drand verifier hash mismatch: {path.name}")
    policy = profile["crypto_runtime_policy"]
    if (
        policy["drand_verifier_script_sha256"] != PINNED_DRAND_SCRIPT_SHA256
        or policy["drand_verifier_package_sha256"] != PINNED_DRAND_PACKAGE_SHA256
        or policy["drand_verifier_lock_sha256"] != PINNED_DRAND_LOCK_SHA256
        or policy["drand_client_version"] != PINNED_DRAND_CLIENT_VERSION
        or policy["node_executable_sha256"] != PINNED_NODE_EXECUTABLE_SHA256
        or policy["node_version"] != PINNED_NODE_VERSION
        or policy["dependency_tree_sha256"] != PINNED_DRAND_DEPENDENCY_TREE_SHA256
    ):
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "profile drand runtime pin differs from the code-pinned runtime")
    if (
        precommit["node_version"] != PINNED_NODE_VERSION
        or precommit["node_executable_sha256"] != PINNED_NODE_EXECUTABLE_SHA256
        or precommit["dependency_tree_sha256"] != PINNED_DRAND_DEPENDENCY_TREE_SHA256
        or precommit["drand_verifier_script_sha256"] != PINNED_DRAND_SCRIPT_SHA256
        or precommit["drand_verifier_package_sha256"] != PINNED_DRAND_PACKAGE_SHA256
        or precommit["drand_verifier_lock_sha256"] != PINNED_DRAND_LOCK_SHA256
        or precommit["drand_client_version"] != PINNED_DRAND_CLIENT_VERSION
    ):
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "drand precommit runtime pin differs from the code-pinned runtime")
    node = shutil.which("node")
    if node is None or not DRAND_MODULE.is_file():
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "Node or npm-ci drand-client runtime is unavailable")
    node_path = Path(node).resolve()
    if _file_sha256(node_path) != PINNED_NODE_EXECUTABLE_SHA256 or _node_version(str(node_path)) != PINNED_NODE_VERSION:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "Node executable or version differs from the pinned runtime")
    if _dependency_tree_sha256(DRAND_RUNTIME / "node_modules") != PINNED_DRAND_DEPENDENCY_TREE_SHA256:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "installed drand dependency tree differs from the pinned runtime")
    try:
        package = json.loads(DRAND_MODULE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "installed drand-client package metadata is unreadable") from exc
    if package.get("name") != "drand-client" or package.get("version") != PINNED_DRAND_CLIENT_VERSION:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "installed drand-client version differs from the lock")
    return str(node_path)


def _canonical_object(raw: bytes, *, code: str, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or raw.startswith(b"\xef\xbb\xbf") or raw.endswith(b"\n") or b"\r" in raw:
        raise fail(code, f"{label} must be unframed canonical JSON bytes")
    try:
        value = canonical_json_loads(raw)
    except Exception as exc:
        raise fail(code, f"{label} is invalid JSON") from exc
    if type(value) is not dict or canonical_json_bytes(value) != raw:
        raise fail(code, f"{label} must be a canonical JSON object")
    return value


def _validate_hash_fields(item: dict[str, Any], fields: tuple[str, ...], *, code: str) -> None:
    for field in fields:
        sha256(item[field], field, code=code)


def _validate_signed_precommit(
    raw_precommit: bytes,
    *,
    profile: ValidatedHybridProfile,
    schema: str,
    fields: frozenset[str],
) -> tuple[dict[str, Any], str]:
    code = "LIVE_BINDING_INVALID"
    item = _canonical_object(raw_precommit, code=code, label="live precommit")
    if set(item) != fields or item["schema"] != schema or item["profile_sha256"] != profile["sha256"]:
        raise fail(code, "live precommit schema or profile binding is invalid")
    _validate_hash_fields(
        item,
        (
            "profile_sha256",
            "campaign_root_sha256",
            "review_challenge_sha256",
            "single_use_token_sha256",
            "campaign_nonce_sha256",
            "node_executable_sha256",
            "dependency_tree_sha256",
            "drand_verifier_script_sha256",
            "drand_verifier_package_sha256",
            "drand_verifier_lock_sha256",
        ),
        code=code,
    )
    identifier(item["node_version"], "node version", code=code)
    identifier(item["drand_client_version"], "drand client version", code=code)
    committed_at = utc(item["committed_at"], "precommit committed_at", code=code)
    core = {key: item[key] for key in item if key != "signatures"}
    verify_signature_set(
        item["signatures"],
        core=core,
        domain=DOMAIN_LIVE_CRYPTO_PRECOMMIT,
        identities=profile["identities"],
        required_party_ids=("A", "B", "C"),
        code=code,
    )
    return {**dict(item), "committed_at_dt": committed_at}, hashlib.sha256(raw_precommit).hexdigest()


_RUNTIME_PRECOMMIT_FIELDS = frozenset(
    {
        "profile_sha256",
        "campaign_root_sha256",
        "review_challenge_sha256",
        "single_use_token_sha256",
        "campaign_nonce_sha256",
        "node_executable_sha256",
        "node_version",
        "dependency_tree_sha256",
        "drand_verifier_script_sha256",
        "drand_verifier_package_sha256",
        "drand_verifier_lock_sha256",
        "drand_client_version",
        "committed_at",
        "signatures",
    }
)

_DRAND_PRECOMMIT_FIELDS = _RUNTIME_PRECOMMIT_FIELDS | frozenset({"schema", "committed_round"})
_RFC3161_PRECOMMIT_FIELDS = _RUNTIME_PRECOMMIT_FIELDS | frozenset(
    {"schema", "payload_sha256", "query_sha256", "rfc3161_nonce", "tsa_policy_oids", "openssl_binary_sha256", "openssl_version"}
)


def _validate_drand_precommit(raw_precommit: bytes, *, profile: ValidatedHybridProfile) -> tuple[dict[str, Any], str]:
    item, digest = _validate_signed_precommit(
        raw_precommit,
        profile=profile,
        schema=DRAND_PRECOMMIT_SCHEMA,
        fields=_DRAND_PRECOMMIT_FIELDS,
    )
    item["committed_round_int"] = canonical_integer(item["committed_round"], "committed round", code="LIVE_BINDING_INVALID", minimum=1)
    return item, digest


def _validate_rfc3161_precommit(raw_precommit: bytes, *, profile: ValidatedHybridProfile) -> tuple[dict[str, Any], str]:
    item, digest = _validate_signed_precommit(
        raw_precommit,
        profile=profile,
        schema=RFC3161_PRECOMMIT_SCHEMA,
        fields=_RFC3161_PRECOMMIT_FIELDS,
    )
    code = "LIVE_BINDING_INVALID"
    sha256(item["payload_sha256"], "payload digest", code=code)
    sha256(item["query_sha256"], "query digest", code=code)
    identifier(item["rfc3161_nonce"], "RFC3161 nonce", code=code)
    oids = item["tsa_policy_oids"]
    if type(oids) is not list or len(oids) != 2 or any(type(oid) is not str or _OID_RE.fullmatch(oid) is None for oid in oids) or len(set(oids)) != 2:
        raise fail(code, "RFC3161 precommit must pin two distinct TSA policy OIDs")
    sha256(item["openssl_binary_sha256"], "OpenSSL binary digest", code=code)
    identifier(item["openssl_version"], "OpenSSL version", code=code)
    return item, digest


def _parse_query_text(text: str) -> tuple[str, str]:
    digest_bytes = bytearray()
    in_message = False
    nonce: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "Message data:":
            in_message = True
            continue
        if in_message:
            match = _QUERY_HEX_LINE_RE.match(line)
            if match:
                try:
                    hex_text = match.group(1).split("   ", 1)[0].replace("-", " ")
                    tokens = hex_text.split()
                    if not tokens or any(re.fullmatch(r"[0-9a-fA-F]{2}", token) is None for token in tokens):
                        raise ValueError("invalid hex byte")
                    digest_bytes.extend(bytes.fromhex("".join(tokens)))
                except ValueError as exc:
                    raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 query contains malformed message data") from exc
                continue
            in_message = False
        if stripped.startswith("Nonce:"):
            nonce = stripped[len("Nonce:") :].strip()
    if not digest_bytes or nonce is None:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 query lacks a message imprint or nonce")
    return digest_bytes.hex(), nonce


def verify_live_drand_receipt(
    *,
    raw_evidence: bytes,
    raw_precommit: bytes,
    profile: ValidatedHybridProfile,
) -> LiveDrandVerification:
    if type(profile) is not ValidatedHybridProfile:
        raise fail("DRAND_RECEIPT_INVALID", "live drand verification requires an immutable validated profile")
    precommit, precommit_sha = _validate_drand_precommit(raw_precommit, profile=profile)
    value = _canonical_object(raw_evidence, code="DRAND_RECEIPT_INVALID", label="drand evidence")
    expected_fields = {
        "beacon",
        "chain_info",
        "expected_chain_hash",
        "expected_public_key",
        "expected_round",
        "profile_sha256",
        "campaign_root_sha256",
        "review_challenge_sha256",
        "single_use_token_sha256",
        "campaign_nonce_sha256",
        "precommit_sha256",
    }
    if set(value) != expected_fields:
        raise fail("DRAND_RECEIPT_INVALID", "drand evidence top-level fields are not exact")
    _validate_hash_fields(
        value,
        (
            "profile_sha256",
            "campaign_root_sha256",
            "review_challenge_sha256",
            "single_use_token_sha256",
            "campaign_nonce_sha256",
            "precommit_sha256",
            "expected_chain_hash",
        ),
        code="DRAND_RECEIPT_INVALID",
    )
    if (
        value["profile_sha256"] != profile["sha256"]
        or value["precommit_sha256"] != precommit_sha
        or any(value[field] != precommit[field] for field in (
            "campaign_root_sha256",
            "review_challenge_sha256",
            "single_use_token_sha256",
            "campaign_nonce_sha256",
        ))
    ):
        raise fail("DRAND_RECEIPT_INVALID", "drand evidence is not bound to the signed precommit")
    policy = profile["public_roots"]["drand"]
    if (
        value["expected_chain_hash"] != policy["network_chain_hash"]
        or value["expected_public_key"] != policy["network_public_key_hex"]
    ):
        raise fail("DRAND_RECEIPT_INVALID", "drand evidence differs from the profile-pinned chain or key")
    if type(value["expected_round"]) is not int or not (1 <= value["expected_round"] <= 2**53 - 1):
        raise fail("DRAND_RECEIPT_INVALID", "expected round must be a positive safe integer")
    expected_round = value["expected_round"]
    if expected_round != precommit["committed_round_int"]:
        raise fail("DRAND_RECEIPT_INVALID", "drand round differs from the signed precommit")
    chain_info = value["chain_info"]
    if (
        type(chain_info) is not dict
        or type(chain_info.get("genesis_time")) is not int
        or type(chain_info.get("period")) is not int
        or chain_info["genesis_time"] != PINNED_DRAND_GENESIS_TIME
        or chain_info["period"] != PINNED_DRAND_PERIOD
        or chain_info.get("groupHash") != PINNED_DRAND_GROUP_HASH
        or chain_info.get("schemeID") != PINNED_DRAND_SCHEME_ID
        or chain_info.get("metadata") != {"beaconID": PINNED_DRAND_BEACON_ID}
    ):
        raise fail("DRAND_RECEIPT_INVALID", "drand chain timing or scheme differs from the pinned default chain")
    try:
        round_time = datetime.fromtimestamp(chain_info["genesis_time"] + chain_info["period"] * expected_round, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise fail("DRAND_RECEIPT_INVALID", "drand round timestamp is invalid") from exc
    if precommit["committed_at_dt"] >= round_time:
        raise fail("DRAND_RECEIPT_INVALID", "drand round was not precommitted before its beacon time")
    node = _verify_runtime(profile, precommit)
    command = [
        node,
        "--permission",
        f"--allow-fs-read={DRAND_RUNTIME}",
        str(DRAND_SCRIPT),
    ]
    environment = {
        "HOME": "/nonexistent-v63-drand-home",
        "LANG": "C",
        "LC_ALL": "C",
        "NODE_NO_WARNINGS": "1",
        "PATH": os.environ.get("PATH", ""),
        "TZ": "UTC",
    }
    try:
        completed = subprocess.run(
            command,
            input=raw_evidence,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=DRAND_RUNTIME,
            env=environment,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "pinned drand verifier could not execute") from exc
    if completed.returncode != 0 or completed.stderr:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise fail("DRAND_RECEIPT_INVALID", f"drand signature verification failed: {detail or 'no detail'}")
    try:
        report = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("DRAND_RECEIPT_INVALID", "drand verifier output is invalid JSON") from exc
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
        raise fail("DRAND_RECEIPT_INVALID", "drand verifier output fields are not exact")
    input_sha = hashlib.sha256(raw_evidence).hexdigest()
    if (
        report["input_sha256"] != input_sha
        or report["network_access_used"] is not False
        or report["public_key"] != policy["network_public_key_hex"]
        or report["round"] != str(expected_round)
        or report["signature_verified"] is not True
        or report["verifier"] != f"drand-client@{PINNED_DRAND_CLIENT_VERSION}"
    ):
        raise fail("DRAND_RECEIPT_INVALID", "drand verifier output is not bound to the exact input and runtime")
    return LiveDrandVerification(
        input_sha256=input_sha,
        profile_sha256=profile["sha256"],
        precommit_sha256=precommit_sha,
        campaign_root_sha256=precommit["campaign_root_sha256"],
        review_challenge_sha256=precommit["review_challenge_sha256"],
        single_use_token_sha256=precommit["single_use_token_sha256"],
        campaign_nonce_sha256=precommit["campaign_nonce_sha256"],
        committed_at=precommit["committed_at_dt"],
        round=int(report["round"]),
        randomness=str(report["randomness"]),
        scheme_id=str(report["scheme_id"]),
        public_key=str(report["public_key"]),
        verifier=str(report["verifier"]),
        verifier_script_sha256=PINNED_DRAND_SCRIPT_SHA256,
        verifier_lock_sha256=PINNED_DRAND_LOCK_SHA256,
        network_access_used=False,
        _construction_token=_DRAND_SENTINEL,
    )


def _openssl_runtime(profile: ValidatedHybridProfile, precommit: dict[str, Any]) -> tuple[str, str, str]:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL executable is unavailable")
    binary_sha = _file_sha256(Path(openssl))
    try:
        completed = subprocess.run(
            [openssl, "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", ""), "TZ": "UTC"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL version probe failed") from exc
    if completed.returncode != 0 or completed.stderr:
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL version probe returned an error")
    version = completed.stdout.decode("ascii", errors="strict").strip()
    runtime_policy = profile["crypto_runtime_policy"]
    if (
        binary_sha != runtime_policy["rfc3161_openssl_binary_sha256"]
        or version != runtime_policy["rfc3161_openssl_version"]
        or binary_sha != precommit["openssl_binary_sha256"]
        or version != precommit["openssl_version"]
    ):
        raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL binary or version differs from the profile/precommit pin")
    return openssl, binary_sha, version


def _root_der_sha256(pem: bytes) -> str:
    try:
        certificate = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 root certificate is not valid PEM X.509") from exc
    return hashlib.sha256(certificate.public_bytes(Encoding.DER)).hexdigest()


def _parse_timestamp_text(text: str) -> dict[str, Any]:
    values: dict[str, str] = {}
    labels = {
        "Policy OID:": "policy_oid",
        "Serial number:": "serial_number",
        "Time stamp:": "gen_time",
        "Nonce:": "nonce",
    }
    for line in text.splitlines():
        stripped = line.strip()
        for prefix, name in labels.items():
            if stripped.startswith(prefix):
                values[name] = stripped[len(prefix) :].strip()
    if set(values) != set(labels.values()) or any(not value for value in values.values()):
        raise fail("RFC3161_RECEIPT_INVALID", "OpenSSL timestamp text lacks policy, serial, time, or nonce")
    raw_time = values["gen_time"]
    parsed_time = None
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S.%f %Y GMT"):
        try:
            parsed_time = datetime.strptime(raw_time, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    if parsed_time is None:
        raise fail("RFC3161_RECEIPT_INVALID", "OpenSSL timestamp genTime is not parseable")
    return {**values, "gen_time": parsed_time}


def verify_live_rfc3161_quorum(
    *,
    raw_query: bytes,
    raw_responses: tuple[bytes, bytes],
    root_certificates_pem: tuple[bytes, bytes],
    revocation_material_pem: tuple[bytes, bytes],
    untrusted_certificates_pem: tuple[bytes | None, bytes | None],
    raw_precommit: bytes,
    profile: ValidatedHybridProfile,
) -> LiveRFC3161Quorum:
    if type(profile) is not ValidatedHybridProfile:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 verification requires an immutable validated profile")
    precommit, precommit_sha = _validate_rfc3161_precommit(raw_precommit, profile=profile)
    if (
        type(raw_query) is not bytes
        or not raw_query
        or type(raw_responses) is not tuple
        or len(raw_responses) != 2
        or any(type(value) is not bytes or not value for value in raw_responses)
        or type(root_certificates_pem) is not tuple
        or len(root_certificates_pem) != 2
        or any(type(value) is not bytes or not value for value in root_certificates_pem)
        or type(revocation_material_pem) is not tuple
        or len(revocation_material_pem) != 2
        or any(type(value) is not bytes or not value for value in revocation_material_pem)
        or type(untrusted_certificates_pem) is not tuple
        or len(untrusted_certificates_pem) != 2
        or any(value is not None and type(value) is not bytes for value in untrusted_certificates_pem)
    ):
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 verifier inputs have invalid types or cardinality")
    query_sha = hashlib.sha256(raw_query).hexdigest()
    if query_sha != precommit["query_sha256"]:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 query differs from the signed precommit")
    openssl, binary_sha, version = _openssl_runtime(profile, precommit)
    root_hashes = tuple(_root_der_sha256(value) for value in root_certificates_pem)
    expected_roots = tuple(
        authority["certificate_root_sha256"] for authority in profile["time_authorities"]
    )
    if root_hashes != expected_roots or len(set(root_hashes)) != 2:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 root certificates differ from the two profile pins or are not independent")
    revocation_hashes = tuple(hashlib.sha256(value).hexdigest() for value in revocation_material_pem)
    expected_revocation = tuple(
        authority["revocation_policy_root_sha256"] for authority in profile["time_authorities"]
    )
    if revocation_hashes != expected_revocation:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 revocation material differs from the profile pins")
    parsed_tokens = []
    response_hashes = []
    with tempfile.TemporaryDirectory(prefix="eval-v63-rfc3161-") as temporary:
        directory = Path(temporary)
        query_path = directory / "request.tsq"
        query_path.write_bytes(raw_query)
        query_path.chmod(0o600)
        environment = {
            "HOME": "/nonexistent-v63-openssl-home",
            "LANG": "C",
            "LC_ALL": "C",
            "OPENSSL_CONF": os.devnull,
            "PATH": os.environ.get("PATH", ""),
            "TZ": "UTC",
        }
        try:
            query_text = subprocess.run(
                [openssl, "ts", "-query", "-in", str(query_path), "-text"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
                env=environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL RFC3161 query rendering could not execute") from exc
        if query_text.returncode != 0:
            raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 query could not be rendered")
        payload_sha, query_nonce = _parse_query_text(query_text.stdout.decode("utf-8", errors="strict"))
        if payload_sha != precommit["payload_sha256"] or query_nonce != precommit["rfc3161_nonce"]:
            raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 query payload or nonce differs from the signed precommit")
        for index in range(2):
            response_path = directory / f"response-{index}.tsr"
            root_path = directory / f"trust-store-{index}.pem"
            response_path.write_bytes(raw_responses[index])
            root_path.write_bytes(root_certificates_pem[index] + b"\n" + revocation_material_pem[index])
            response_path.chmod(0o600)
            root_path.chmod(0o600)
            try:
                rendered = subprocess.run(
                    [openssl, "ts", "-reply", "-in", str(response_path), "-text"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                    env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL RFC3161 token rendering could not execute") from exc
            if rendered.returncode != 0:
                raise fail("RFC3161_RECEIPT_INVALID", f"RFC3161 token {index} could not be rendered")
            parsed_token = _parse_timestamp_text(rendered.stdout.decode("utf-8", errors="strict"))
            command = [
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
                str(int(parsed_token["gen_time"].timestamp())),
                "-crl_check_all",
                "-x509_strict",
                "-check_ss_sig",
            ]
            if untrusted_certificates_pem[index] is not None:
                chain_path = directory / f"untrusted-{index}.pem"
                chain_path.write_bytes(untrusted_certificates_pem[index] or b"")
                chain_path.chmod(0o600)
                command.extend(["-untrusted", str(chain_path)])
            try:
                verified = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                    env=environment,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise fail("LIVE_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE", "OpenSSL RFC3161 verification could not execute") from exc
            if verified.returncode != 0 or b"Verification: OK" not in verified.stdout:
                detail = (verified.stderr or verified.stdout).decode("utf-8", errors="replace").strip()
                raise fail("RFC3161_RECEIPT_INVALID", f"RFC3161 token {index} failed verification: {detail}")
            parsed_tokens.append(parsed_token)
            response_hashes.append(hashlib.sha256(raw_responses[index]).hexdigest())
    if parsed_tokens[0]["nonce"] != parsed_tokens[1]["nonce"]:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 tokens do not bind the same query nonce")
    if parsed_tokens[0]["nonce"] != query_nonce:
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 response nonce differs from the query nonce")
    if tuple(parsed_token["policy_oid"] for parsed_token in parsed_tokens) != tuple(precommit["tsa_policy_oids"]):
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 policy OIDs differ from the signed precommit")
    if any(precommit["committed_at_dt"] >= parsed_token["gen_time"] for parsed_token in parsed_tokens):
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 token was issued before the signed precommit")
    if abs(parsed_tokens[0]["gen_time"] - parsed_tokens[1]["gen_time"]) > timedelta(seconds=120):
        raise fail("RFC3161_RECEIPT_INVALID", "RFC3161 token genTimes differ by more than 120 seconds")
    return LiveRFC3161Quorum(
        query_sha256=query_sha,
        precommit_sha256=precommit_sha,
        profile_sha256=profile["sha256"],
        campaign_root_sha256=precommit["campaign_root_sha256"],
        review_challenge_sha256=precommit["review_challenge_sha256"],
        single_use_token_sha256=precommit["single_use_token_sha256"],
        campaign_nonce_sha256=precommit["campaign_nonce_sha256"],
        payload_sha256=payload_sha,
        rfc3161_nonce=query_nonce,
        response_sha256s=(response_hashes[0], response_hashes[1]),
        root_certificate_der_sha256s=(root_hashes[0], root_hashes[1]),
        revocation_material_sha256s=(revocation_hashes[0], revocation_hashes[1]),
        policy_oids=(parsed_tokens[0]["policy_oid"], parsed_tokens[1]["policy_oid"]),
        serial_numbers=(parsed_tokens[0]["serial_number"], parsed_tokens[1]["serial_number"]),
        gen_times=(parsed_tokens[0]["gen_time"], parsed_tokens[1]["gen_time"]),
        nonce=parsed_tokens[0]["nonce"],
        openssl_binary_sha256=binary_sha,
        openssl_version=version,
        _construction_token=_RFC3161_SENTINEL,
    )


__all__ = [
    "DOMAIN_LIVE_CRYPTO_PRECOMMIT",
    "DRAND_PRECOMMIT_SCHEMA",
    "LiveDrandVerification",
    "LiveRFC3161Quorum",
    "PINNED_DRAND_DEPENDENCY_TREE_SHA256",
    "PINNED_DRAND_BEACON_ID",
    "PINNED_DRAND_CLIENT_VERSION",
    "PINNED_DRAND_GENESIS_TIME",
    "PINNED_DRAND_GROUP_HASH",
    "PINNED_DRAND_LOCK_SHA256",
    "PINNED_DRAND_PACKAGE_SHA256",
    "PINNED_DRAND_PERIOD",
    "PINNED_DRAND_SCHEME_ID",
    "PINNED_DRAND_SCRIPT_SHA256",
    "PINNED_NODE_EXECUTABLE_SHA256",
    "PINNED_NODE_VERSION",
    "RFC3161_PRECOMMIT_SCHEMA",
    "verify_live_drand_receipt",
    "verify_live_rfc3161_quorum",
]
