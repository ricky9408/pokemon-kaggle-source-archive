"""External trust primitives for the v6.2.6 population gate.

This module validates receipts produced by independently controlled services. It
does not create trusted time, redeem challenges, or mutate witness state. A
project-local process cannot manufacture those facts, so callers must supply an
externally signed compare-and-append transition and two trusted-time quorums.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .integration_v622 import canonical_json_bytes, canonical_sha256
from .release_v625 import verify_transparency_consistency, verify_transparency_inclusion


TRUST_POLICY_SCHEMA = "eval.v6.2.6.external-trust-policy"
AUTHORITY_SCHEMA = "eval.v6.2.6.authority"
MONOTONIC_STATE_SCHEMA = "eval.v6.2.6.monotonic-state"
REDEMPTION_REQUEST_SCHEMA = "eval.v6.2.6.redemption-request"
LOG_CHECKPOINT_SCHEMA = "eval.v6.2.6.log-checkpoint"
WITNESS_TRANSITION_SCHEMA = "eval.v6.2.6.witness-transition"
WITNESS_ENVELOPE_SCHEMA = "eval.v6.2.6.witness-envelope"
WITNESS_HEAD_SCHEMA = "eval.v6.2.6.witness-head"
WITNESS_HEAD_ENVELOPE_SCHEMA = "eval.v6.2.6.witness-head-envelope"
TIME_OPEN_SCHEMA = "eval.v6.2.6.time-open-receipt"
TIME_CLOSE_SCHEMA = "eval.v6.2.6.time-close-receipt"
TIME_ENVELOPE_SCHEMA = "eval.v6.2.6.time-envelope"

ROLE_LOG_AUTHORITY = "APPEND_ONLY_LOG_AUTHORITY"
ROLE_WITNESS_COSIGNER = "MONOTONIC_WITNESS_COSIGNER"
ROLE_TIME_AUTHORITY = "TRUSTED_TIME_AUTHORITY"
ROLE_EXTERNAL_VERIFIER = "EXTERNAL_VERIFIER"
ROLE_IDENTITY_ISSUER = "IDENTITY_ISSUER"

DOMAIN_WITNESS_STATE = b"EVAL-V626/MONOTONIC-STATE\0"
DOMAIN_WITNESS_TRANSITION = b"EVAL-V626/WITNESS-TRANSITION\0"
DOMAIN_WITNESS_HEAD = b"EVAL-V626/WITNESS-HEAD\0"
DOMAIN_TIME_OPEN = b"EVAL-V626/TIME-OPEN\0"
DOMAIN_TIME_CLOSE = b"EVAL-V626/TIME-CLOSE\0"
DOMAIN_LOG_LEAF = b"EVAL-V626/LOG-LEAF\0"

FAILURE_STATES = frozenset(
    {
        "BOOTSTRAP_CONFIG_ABSENT",
        "RELEASE_ROOT_UNAUTHORIZED",
        "MONOTONIC_WITNESS_UNAVAILABLE",
        "MONOTONIC_CAS_REJECTED",
        "LIVE_EXTERNAL_STATE_NOT_ACQUIRED",
        "OPENING_HEAD_TRANSITION_MISMATCH",
        "CLOSING_HEAD_TRANSITION_MISMATCH",
        "OPENING_CLOSING_CONSISTENCY_FAILURE",
        "MONOTONIC_FORK_DETECTED",
        "WITNESS_QUORUM_DISAGREEMENT",
        "CHALLENGE_ALREADY_REDEEMED",
        "TRANSPARENCY_CONSISTENCY_FAILURE",
        "TRUSTED_TIME_QUORUM_INVALID",
        "VERIFICATION_WINDOW_EXPIRED",
        "CHECKPOINT_STALE",
        "CHECKPOINT_FUTURE_SKEW",
        "REVOCATION_STATE_ADVANCED_REVERIFY_REQUIRED",
        "REVOCATION_INVALIDATES_SIGNER",
        "REVOCATION_SEMANTICS_INVALID",
        "INDEPENDENT_RUN_POLICY_NOT_SATISFIED",
        "EXTERNAL_VERIFIER_DISAGREEMENT",
    }
)

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^ed25519-sha256:[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32,256}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TrustV626Error(ValueError):
    """An external-trust artifact failed with a stable failure state."""

    def __init__(self, code: str, message: str) -> None:
        if code not in FAILURE_STATES:
            raise ValueError(f"unknown v6.2.6 trust failure state: {code}")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TrustedInterval:
    lower: datetime
    upper: datetime
    authority_key_ids: tuple[str, ...]


@dataclass(frozen=True)
class WitnessValidation:
    transition_sha256: str
    invocation_challenge_sha256: str
    previous_state_sha256: str
    previous_sequence: int
    previous_checkpoint_tree_size: int
    previous_checkpoint_root_sha256: str
    previous_registry_epoch: int
    previous_revocation_sequence: int
    previous_revocation_head_sha256: str
    new_state_sha256: str
    new_sequence: int
    checkpoint_sha256: str
    checkpoint_tree_size: int
    checkpoint_observed_at: datetime
    registry_epoch: int
    revocation_sequence: int
    revocation_head_sha256: str
    signer_key_ids: tuple[str, ...]


@dataclass(frozen=True)
class WitnessHeadValidation:
    state_sha256: str
    sequence: int
    checkpoint_tree_size: int
    checkpoint_root_sha256: str
    registry_epoch: int
    revocation_sequence: int
    revocation_head_sha256: str
    response_nonce: str
    signer_key_ids: tuple[str, ...]


def _fail(code: str, message: str) -> TrustV626Error:
    return TrustV626Error(code, message)


def _exact(value: Any, fields: frozenset[str], label: str, *, code: str) -> Mapping[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _fail(code, f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\0" in value:
        raise _fail(code, f"{label} must be a nonempty trimmed string without NUL")
    return value


def _sha(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _SHA_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _nonce(value: Any, label: str, *, code: str) -> str:
    if type(value) is not str or _NONCE_RE.fullmatch(value) is None or len(value) % 2:
        raise _fail(code, f"{label} must be 16 through 128 bytes of lowercase hex")
    return value


def _decimal(value: Any, label: str, *, code: str) -> int:
    if type(value) is not str or not value.isdigit() or (len(value) > 1 and value[0] == "0"):
        raise _fail(code, f"{label} must be a canonical nonnegative decimal string")
    return int(value)


def _utc(value: Any, label: str, *, code: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be canonical second-resolution UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise _fail(code, f"{label} is not a valid UTC timestamp") from exc


def _b64(value: Any, label: str, *, expected_length: int, code: str) -> bytes:
    if type(value) is not str:
        raise _fail(code, f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise _fail(code, f"{label} must be canonical base64") from exc
    if len(decoded) != expected_length or base64.b64encode(decoded).decode("ascii") != value:
        raise _fail(code, f"{label} has the wrong length or noncanonical encoding")
    return decoded


def _authority(value: Any, *, role: str, label: str, code: str) -> dict[str, Any]:
    item = _exact(
        value,
        frozenset(
            {
                "schema",
                "key_id",
                "public_key_base64",
                "subject_id",
                "role",
                "control_group_id",
                "organization_id",
            }
        ),
        label,
        code=code,
    )
    if item["schema"] != AUTHORITY_SCHEMA or item["role"] != role:
        raise _fail(code, f"{label} has the wrong schema or role")
    public_key = _b64(item["public_key_base64"], f"{label}.public_key_base64", expected_length=32, code=code)
    key_id = _identifier(item["key_id"], f"{label}.key_id", code=code)
    derived = "ed25519-sha256:" + hashlib.sha256(public_key).hexdigest()
    if _KEY_ID_RE.fullmatch(key_id) is None or key_id != derived:
        raise _fail(code, f"{label}.key_id does not match the public key")
    return {
        "key_id": key_id,
        "public_key": public_key,
        "subject_id": _identifier(item["subject_id"], f"{label}.subject_id", code=code),
        "role": role,
        "control_group_id": _identifier(item["control_group_id"], f"{label}.control_group_id", code=code),
        "organization_id": _identifier(item["organization_id"], f"{label}.organization_id", code=code),
    }


def _authority_set(
    values: Any,
    *,
    role: str,
    expected_count: int,
    label: str,
    code: str,
) -> dict[str, dict[str, Any]]:
    if type(values) is not list or len(values) != expected_count:
        raise _fail(code, f"{label} must contain exactly {expected_count} authorities")
    parsed = [_authority(value, role=role, label=f"{label}[{index}]", code=code) for index, value in enumerate(values)]
    for field in ("key_id", "subject_id", "control_group_id", "organization_id"):
        if len({item[field] for item in parsed}) != expected_count:
            raise _fail(code, f"{label} must have distinct {field} values")
    return {item["key_id"]: item for item in parsed}


def validate_trust_policy(value: Any, *, expected_sha256: str) -> dict[str, Any]:
    code = "RELEASE_ROOT_UNAUTHORIZED"
    policy = _exact(
        value,
        frozenset(
            {
                "schema",
                "namespace",
                "release_root_sha256",
                "release_sequence",
                "previous_release_root_sha256",
                "bootstrap_authorization_root_sha256",
                "witness_policy_sha256",
                "time_policy_sha256",
                "evidence_policy_sha256",
                "runtime_tcb_policy_sha256",
                "accepted_verifier_build_root_sha256",
                "project_control_group_ids",
                "log_authority",
                "witness_cosigner_authorities",
                "time_authorities",
                "verifier_authorities",
                "identity_issuer_authorities",
                "witness_cosigner_quorum",
                "time_authority_quorum",
                "verifier_quorum",
            }
        ),
        "external trust policy",
        code=code,
    )
    if policy["schema"] != TRUST_POLICY_SCHEMA:
        raise _fail(code, "external trust policy schema mismatch")
    expected = _sha(expected_sha256, "expected trust policy sha256", code=code)
    if canonical_sha256(policy) != expected:
        raise _fail(code, "external trust policy does not match the code-pinned digest")
    project_groups = policy["project_control_group_ids"]
    if type(project_groups) is not list or not project_groups:
        raise _fail(code, "project_control_group_ids must be a nonempty list")
    project_groups = tuple(_identifier(value, "project control group", code=code) for value in project_groups)
    if len(set(project_groups)) != len(project_groups):
        raise _fail(code, "project_control_group_ids contains duplicates")
    log = _authority(policy["log_authority"], role=ROLE_LOG_AUTHORITY, label="log authority", code=code)
    witnesses = _authority_set(
        policy["witness_cosigner_authorities"],
        role=ROLE_WITNESS_COSIGNER,
        expected_count=3,
        label="witness cosigner authorities",
        code=code,
    )
    times = _authority_set(
        policy["time_authorities"],
        role=ROLE_TIME_AUTHORITY,
        expected_count=3,
        label="time authorities",
        code=code,
    )
    verifiers = _authority_set(
        policy["verifier_authorities"],
        role=ROLE_EXTERNAL_VERIFIER,
        expected_count=3,
        label="verifier authorities",
        code=code,
    )
    identity_issuers = _authority_set(
        policy["identity_issuer_authorities"],
        role=ROLE_IDENTITY_ISSUER,
        expected_count=2,
        label="identity issuer authorities",
        code=code,
    )
    if policy["witness_cosigner_quorum"] != "2" or policy["time_authority_quorum"] != "2" or policy["verifier_quorum"] != "2":
        raise _fail(code, "v6.2.6 requires exact 2-of-3 witness, time, and verifier quorums")
    all_authorities = [
        log,
        *witnesses.values(),
        *times.values(),
        *verifiers.values(),
        *identity_issuers.values(),
    ]
    if len({item["key_id"] for item in all_authorities}) != len(all_authorities):
        raise _fail(code, "external trust authorities must use distinct keys")
    if len({item["subject_id"] for item in all_authorities}) != len(all_authorities):
        raise _fail(code, "external trust authorities must use distinct subjects")
    if len({item["control_group_id"] for item in all_authorities}) != len(all_authorities):
        raise _fail(code, "external trust authorities must use distinct control groups")
    if len({item["organization_id"] for item in all_authorities}) != len(all_authorities):
        raise _fail(code, "external trust authorities must use distinct organizations")
    if set(project_groups) & {item["control_group_id"] for item in all_authorities}:
        raise _fail(code, "external trust authorities must be disjoint from project control groups")
    return {
        "namespace": _identifier(policy["namespace"], "policy namespace", code=code),
        "release_root_sha256": _sha(policy["release_root_sha256"], "release root", code=code),
        "release_sequence": _decimal(policy["release_sequence"], "release sequence", code=code),
        "previous_release_root_sha256": _sha(policy["previous_release_root_sha256"], "previous release root", code=code),
        "bootstrap_authorization_root_sha256": _sha(policy["bootstrap_authorization_root_sha256"], "bootstrap authorization root", code=code),
        "witness_policy_sha256": _sha(policy["witness_policy_sha256"], "witness policy", code=code),
        "time_policy_sha256": _sha(policy["time_policy_sha256"], "time policy", code=code),
        "evidence_policy_sha256": _sha(policy["evidence_policy_sha256"], "evidence policy", code=code),
        "runtime_tcb_policy_sha256": _sha(policy["runtime_tcb_policy_sha256"], "runtime TCB policy", code=code),
        "accepted_verifier_build_root_sha256": _sha(policy["accepted_verifier_build_root_sha256"], "accepted verifier build root", code=code),
        "project_control_group_ids": project_groups,
        "log_authority": log,
        "witness_cosigners": witnesses,
        "time_authorities": times,
        "verifier_authorities": verifiers,
        "identity_issuers": identity_issuers,
    }


def _verify_signature(authority: Mapping[str, Any], domain: bytes, payload: Mapping[str, Any], signature: Any, *, code: str) -> None:
    encoded = _b64(signature, "signature", expected_length=64, code=code)
    message = domain + hashlib.sha256(canonical_json_bytes(payload)).digest()
    try:
        Ed25519PublicKey.from_public_bytes(authority["public_key"]).verify(encoded, message)
    except InvalidSignature as exc:
        raise _fail(code, f"signature from {authority['key_id']} is invalid") from exc


def verify_authority_signature(
    authority: Mapping[str, Any],
    domain: bytes,
    payload: Mapping[str, Any],
    signature: Any,
    *,
    code: str,
) -> None:
    """Verify one release-pinned authority signature with a stable failure code."""

    _verify_signature(authority, domain, payload, signature, code=code)


def _witness_quorum_signers(
    signatures: Any,
    *,
    payload: Mapping[str, Any],
    domain: bytes,
    policy: Mapping[str, Any],
    label: str,
) -> tuple[str, ...]:
    code = "WITNESS_QUORUM_DISAGREEMENT"
    if type(signatures) is not list:
        raise _fail(code, f"{label} signatures must be a list")
    seen: set[str] = set()
    log_seen = False
    witness_seen = 0
    for index, raw in enumerate(signatures):
        signed = _exact(raw, frozenset({"key_id", "signature_base64"}), f"{label} signature[{index}]", code=code)
        key_id = _identifier(signed["key_id"], f"{label} signer key id", code=code)
        if key_id in seen:
            raise _fail(code, f"duplicate {label} signer")
        seen.add(key_id)
        if key_id == policy["log_authority"]["key_id"]:
            authority = policy["log_authority"]
            log_seen = True
        elif key_id in policy["witness_cosigners"]:
            authority = policy["witness_cosigners"][key_id]
            witness_seen += 1
        else:
            raise _fail(code, f"unrecognized {label} signer")
        _verify_signature(authority, domain, payload, signed["signature_base64"], code=code)
    if not log_seen or witness_seen < 2:
        raise _fail(code, f"{label} requires the log authority and two cosigners")
    return tuple(sorted(seen))


def monotonic_state_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("state_sha256", None)
    return hashlib.sha256(DOMAIN_WITNESS_STATE + canonical_json_bytes(payload)).hexdigest()


def _monotonic_state(value: Any, label: str) -> dict[str, Any]:
    code = "MONOTONIC_CAS_REJECTED"
    item = _exact(
        value,
        frozenset(
            {
                "schema",
                "namespace",
                "release_root_sha256",
                "sequence",
                "state_sha256",
                "authorization_sequence",
                "authorization_root_sha256",
                "checkpoint_tree_size",
                "checkpoint_root_sha256",
                "registry_epoch",
                "revocation_sequence",
                "revocation_head_sha256",
                "last_redeemed_challenge_sha256",
                "previous_state_sha256",
            }
        ),
        label,
        code=code,
    )
    if item["schema"] != MONOTONIC_STATE_SCHEMA:
        raise _fail(code, f"{label} schema mismatch")
    parsed = {
        "schema": MONOTONIC_STATE_SCHEMA,
        "namespace": _identifier(item["namespace"], f"{label}.namespace", code=code),
        "release_root_sha256": _sha(item["release_root_sha256"], f"{label}.release_root_sha256", code=code),
        "sequence": _decimal(item["sequence"], f"{label}.sequence", code=code),
        "state_sha256": _sha(item["state_sha256"], f"{label}.state_sha256", code=code),
        "authorization_sequence": _decimal(item["authorization_sequence"], f"{label}.authorization_sequence", code=code),
        "authorization_root_sha256": _sha(item["authorization_root_sha256"], f"{label}.authorization_root_sha256", code=code),
        "checkpoint_tree_size": _decimal(item["checkpoint_tree_size"], f"{label}.checkpoint_tree_size", code=code),
        "checkpoint_root_sha256": _sha(item["checkpoint_root_sha256"], f"{label}.checkpoint_root_sha256", code=code),
        "registry_epoch": _decimal(item["registry_epoch"], f"{label}.registry_epoch", code=code),
        "revocation_sequence": _decimal(item["revocation_sequence"], f"{label}.revocation_sequence", code=code),
        "revocation_head_sha256": _sha(item["revocation_head_sha256"], f"{label}.revocation_head_sha256", code=code),
        "last_redeemed_challenge_sha256": None,
        "previous_state_sha256": None,
    }
    for field in ("last_redeemed_challenge_sha256", "previous_state_sha256"):
        raw = item[field]
        if raw is not None:
            parsed[field] = _sha(raw, f"{label}.{field}", code=code)
    serializable = dict(item)
    if monotonic_state_sha256(serializable) != parsed["state_sha256"]:
        raise _fail(code, f"{label}.state_sha256 is not content-derived")
    return parsed


def _redemption_request(value: Any) -> dict[str, Any]:
    code = "MONOTONIC_CAS_REJECTED"
    item = _exact(
        value,
        frozenset(
            {
                "schema",
                "namespace",
                "release_root_sha256",
                "expected_sequence",
                "expected_state_sha256",
                "invocation_challenge_sha256",
                "campaign_bundle_root_sha256",
                "evidence_graph_root_sha256",
                "verification_packet_root_sha256",
                "request_nonce",
            }
        ),
        "redemption request",
        code=code,
    )
    if item["schema"] != REDEMPTION_REQUEST_SCHEMA:
        raise _fail(code, "redemption request schema mismatch")
    return {
        "namespace": _identifier(item["namespace"], "redemption namespace", code=code),
        "release_root_sha256": _sha(item["release_root_sha256"], "redemption release root", code=code),
        "expected_sequence": _decimal(item["expected_sequence"], "redemption expected sequence", code=code),
        "expected_state_sha256": _sha(item["expected_state_sha256"], "redemption expected state", code=code),
        "invocation_challenge_sha256": _sha(item["invocation_challenge_sha256"], "invocation challenge", code=code),
        "campaign_bundle_root_sha256": _sha(item["campaign_bundle_root_sha256"], "campaign bundle root", code=code),
        "evidence_graph_root_sha256": _sha(item["evidence_graph_root_sha256"], "evidence graph root", code=code),
        "verification_packet_root_sha256": _sha(item["verification_packet_root_sha256"], "verification packet root", code=code),
        "request_nonce": _nonce(item["request_nonce"], "redemption request nonce", code=code),
    }


def _checkpoint(value: Any) -> dict[str, Any]:
    code = "TRANSPARENCY_CONSISTENCY_FAILURE"
    item = _exact(
        value,
        frozenset(
            {
                "schema",
                "log_id",
                "tree_size",
                "root_sha256",
                "previous_tree_size",
                "previous_root_sha256",
                "leaf_index",
                "leaf_sha256",
                "inclusion_proof",
                "consistency_proof",
                "observed_at",
            }
        ),
        "log checkpoint",
        code=code,
    )
    if item["schema"] != LOG_CHECKPOINT_SCHEMA:
        raise _fail(code, "log checkpoint schema mismatch")
    for field in ("inclusion_proof", "consistency_proof"):
        if type(item[field]) is not list:
            raise _fail(code, f"log checkpoint {field} must be a list")
    return {
        "log_id": _identifier(item["log_id"], "log id", code=code),
        "tree_size": _decimal(item["tree_size"], "tree size", code=code),
        "root_sha256": _sha(item["root_sha256"], "checkpoint root", code=code),
        "previous_tree_size": _decimal(item["previous_tree_size"], "previous tree size", code=code),
        "previous_root_sha256": _sha(item["previous_root_sha256"], "previous checkpoint root", code=code),
        "leaf_index": _decimal(item["leaf_index"], "leaf index", code=code),
        "leaf_sha256": _sha(item["leaf_sha256"], "leaf hash", code=code),
        "inclusion_proof": tuple(_sha(value, "inclusion proof hash", code=code) for value in item["inclusion_proof"]),
        "consistency_proof": tuple(_sha(value, "consistency proof hash", code=code) for value in item["consistency_proof"]),
        "observed_at": _utc(item["observed_at"], "checkpoint observed_at", code=code),
    }


def _log_leaf_hash(request: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(DOMAIN_LOG_LEAF + canonical_json_bytes(request)).digest()


def validate_witness_transition(value: Any, *, policy: Mapping[str, Any]) -> WitnessValidation:
    code = "MONOTONIC_WITNESS_UNAVAILABLE"
    envelope = _exact(
        value,
        frozenset({"schema", "payload", "signatures"}),
        "witness transition envelope",
        code=code,
    )
    if envelope["schema"] != WITNESS_ENVELOPE_SCHEMA or type(envelope["signatures"]) is not list:
        raise _fail(code, "witness transition envelope schema or signatures invalid")
    payload = _exact(
        envelope["payload"],
        frozenset({"schema", "previous_state", "request", "new_state", "checkpoint"}),
        "witness transition",
        code=code,
    )
    if payload["schema"] != WITNESS_TRANSITION_SCHEMA:
        raise _fail(code, "witness transition schema mismatch")
    previous_state = _monotonic_state(payload["previous_state"], "previous monotonic state")
    request = _redemption_request(payload["request"])
    new_state = _monotonic_state(payload["new_state"], "new monotonic state")
    checkpoint = _checkpoint(payload["checkpoint"])
    for actual, expected, label in (
        (request["namespace"], policy["namespace"], "request namespace"),
        (request["release_root_sha256"], policy["release_root_sha256"], "request release root"),
        (previous_state["namespace"], policy["namespace"], "previous namespace"),
        (new_state["namespace"], policy["namespace"], "new namespace"),
        (previous_state["release_root_sha256"], policy["release_root_sha256"], "previous release root"),
        (new_state["release_root_sha256"], policy["release_root_sha256"], "new release root"),
    ):
        if actual != expected:
            raise _fail("MONOTONIC_CAS_REJECTED", f"{label} does not match policy")
    if request["expected_sequence"] != previous_state["sequence"] or request["expected_state_sha256"] != previous_state["state_sha256"]:
        raise _fail("MONOTONIC_CAS_REJECTED", "redemption request does not bind the previous witness state")
    if new_state["sequence"] != previous_state["sequence"] + 1 or new_state["previous_state_sha256"] != previous_state["state_sha256"]:
        raise _fail("MONOTONIC_CAS_REJECTED", "witness state did not advance exactly once from the expected predecessor")
    if new_state["last_redeemed_challenge_sha256"] != request["invocation_challenge_sha256"]:
        raise _fail("CHALLENGE_ALREADY_REDEEMED", "new witness state does not bind the redeemed challenge")
    if new_state["authorization_sequence"] < previous_state["authorization_sequence"]:
        raise _fail("MONOTONIC_FORK_DETECTED", "authorization sequence rolled back")
    if new_state["registry_epoch"] < previous_state["registry_epoch"] or new_state["revocation_sequence"] < previous_state["revocation_sequence"]:
        raise _fail("MONOTONIC_FORK_DETECTED", "registry or revocation state rolled back")
    if checkpoint["previous_tree_size"] != previous_state["checkpoint_tree_size"] or checkpoint["previous_root_sha256"] != previous_state["checkpoint_root_sha256"]:
        raise _fail("TRANSPARENCY_CONSISTENCY_FAILURE", "checkpoint does not extend the witness predecessor")
    if checkpoint["tree_size"] <= checkpoint["previous_tree_size"] or checkpoint["leaf_index"] >= checkpoint["tree_size"]:
        raise _fail("TRANSPARENCY_CONSISTENCY_FAILURE", "checkpoint size or leaf index is invalid")
    leaf = _log_leaf_hash(payload["request"])
    if leaf.hex() != checkpoint["leaf_sha256"]:
        raise _fail("TRANSPARENCY_CONSISTENCY_FAILURE", "checkpoint leaf does not bind the redemption request")
    try:
        verify_transparency_inclusion(
            leaf_hash=leaf,
            leaf_index=checkpoint["leaf_index"],
            tree_size=checkpoint["tree_size"],
            expected_root_sha256=checkpoint["root_sha256"],
            audit_path_sha256s=checkpoint["inclusion_proof"],
        )
        verify_transparency_consistency(
            old_tree_size=checkpoint["previous_tree_size"],
            new_tree_size=checkpoint["tree_size"],
            old_root_sha256=checkpoint["previous_root_sha256"],
            new_root_sha256=checkpoint["root_sha256"],
            consistency_path_sha256s=checkpoint["consistency_proof"],
        )
    except Exception as exc:
        raise _fail("TRANSPARENCY_CONSISTENCY_FAILURE", "checkpoint proof encoding is invalid") from exc
    if new_state["checkpoint_tree_size"] != checkpoint["tree_size"] or new_state["checkpoint_root_sha256"] != checkpoint["root_sha256"]:
        raise _fail("TRANSPARENCY_CONSISTENCY_FAILURE", "new witness state does not bind the checkpoint")
    signatures = envelope["signatures"]
    seen: set[str] = set()
    log_seen = False
    witness_seen = 0
    for index, raw in enumerate(signatures):
        signed = _exact(raw, frozenset({"key_id", "signature_base64"}), f"witness signature[{index}]", code=code)
        key_id = _identifier(signed["key_id"], "witness signer key id", code=code)
        if key_id in seen:
            raise _fail("WITNESS_QUORUM_DISAGREEMENT", "duplicate witness signer")
        seen.add(key_id)
        if key_id == policy["log_authority"]["key_id"]:
            authority = policy["log_authority"]
            log_seen = True
        elif key_id in policy["witness_cosigners"]:
            authority = policy["witness_cosigners"][key_id]
            witness_seen += 1
        else:
            raise _fail("WITNESS_QUORUM_DISAGREEMENT", "unrecognized witness signer")
        _verify_signature(authority, DOMAIN_WITNESS_TRANSITION, payload, signed["signature_base64"], code="WITNESS_QUORUM_DISAGREEMENT")
    if not log_seen or witness_seen < 2:
        raise _fail("WITNESS_QUORUM_DISAGREEMENT", "witness transition requires the log authority and two cosigners")
    transition_sha = hashlib.sha256(DOMAIN_WITNESS_TRANSITION + canonical_json_bytes(payload)).hexdigest()
    checkpoint_sha = canonical_sha256(payload["checkpoint"])
    return WitnessValidation(
        transition_sha256=transition_sha,
        invocation_challenge_sha256=request["invocation_challenge_sha256"],
        previous_state_sha256=previous_state["state_sha256"],
        previous_sequence=previous_state["sequence"],
        previous_checkpoint_tree_size=previous_state["checkpoint_tree_size"],
        previous_checkpoint_root_sha256=previous_state["checkpoint_root_sha256"],
        previous_registry_epoch=previous_state["registry_epoch"],
        previous_revocation_sequence=previous_state["revocation_sequence"],
        previous_revocation_head_sha256=previous_state["revocation_head_sha256"],
        new_state_sha256=new_state["state_sha256"],
        new_sequence=new_state["sequence"],
        checkpoint_sha256=checkpoint_sha,
        checkpoint_tree_size=checkpoint["tree_size"],
        checkpoint_observed_at=checkpoint["observed_at"],
        registry_epoch=new_state["registry_epoch"],
        revocation_sequence=new_state["revocation_sequence"],
        revocation_head_sha256=new_state["revocation_head_sha256"],
        signer_key_ids=tuple(sorted(seen)),
    )


def validate_witness_head(
    value: Any,
    *,
    policy: Mapping[str, Any],
    expected_response_nonce: str,
) -> WitnessHeadValidation:
    code = "MONOTONIC_WITNESS_UNAVAILABLE"
    envelope = _exact(
        value,
        frozenset({"schema", "payload", "signatures"}),
        "witness head envelope",
        code=code,
    )
    if envelope["schema"] != WITNESS_HEAD_ENVELOPE_SCHEMA:
        raise _fail(code, "witness head envelope schema mismatch")
    payload = _exact(
        envelope["payload"],
        frozenset({"schema", "namespace", "release_root_sha256", "state", "response_nonce"}),
        "witness head",
        code=code,
    )
    if payload["schema"] != WITNESS_HEAD_SCHEMA:
        raise _fail(code, "witness head schema mismatch")
    if payload["namespace"] != policy["namespace"] or payload["release_root_sha256"] != policy["release_root_sha256"]:
        raise _fail("MONOTONIC_CAS_REJECTED", "witness head namespace or release root mismatch")
    response_nonce = _nonce(payload["response_nonce"], "witness head response nonce", code=code)
    if response_nonce != _nonce(expected_response_nonce, "expected witness head nonce", code=code):
        raise _fail("MONOTONIC_CAS_REJECTED", "witness head does not bind the caller nonce")
    state = _monotonic_state(payload["state"], "witness head state")
    signers = _witness_quorum_signers(
        envelope["signatures"],
        payload=payload,
        domain=DOMAIN_WITNESS_HEAD,
        policy=policy,
        label="witness head",
    )
    return WitnessHeadValidation(
        state_sha256=state["state_sha256"],
        sequence=state["sequence"],
        checkpoint_tree_size=state["checkpoint_tree_size"],
        checkpoint_root_sha256=state["checkpoint_root_sha256"],
        registry_epoch=state["registry_epoch"],
        revocation_sequence=state["revocation_sequence"],
        revocation_head_sha256=state["revocation_head_sha256"],
        response_nonce=response_nonce,
        signer_key_ids=signers,
    )


def detect_witness_forks(observations: Sequence[WitnessValidation]) -> None:
    """Reject every observed same-sequence or same-predecessor fork."""

    by_sequence: dict[int, str] = {}
    by_predecessor: dict[str, tuple[str, str]] = {}
    for item in observations:
        prior_state = by_sequence.setdefault(item.new_sequence, item.new_state_sha256)
        if prior_state != item.new_state_sha256:
            raise _fail("MONOTONIC_FORK_DETECTED", "same witness sequence has different state roots")
        successor = (item.new_state_sha256, item.invocation_challenge_sha256)
        prior_successor = by_predecessor.setdefault(item.previous_state_sha256, successor)
        if prior_successor != successor:
            raise _fail("MONOTONIC_FORK_DETECTED", "same witness predecessor has different successors")


_TIME_COMMON_FIELDS = frozenset(
    {
        "time_policy_sha256",
        "release_root_sha256",
        "campaign_bundle_root_sha256",
        "invocation_challenge_sha256",
        "checkpoint_sha256",
        "checkpoint_tree_size",
        "registry_epoch",
        "revocation_sequence",
        "revocation_head_sha256",
        "authority_key_id",
        "authority_subject_id",
        "authority_control_group_id",
        "authority_organization_id",
        "receipt_nonce",
        "time_lower_utc",
        "time_upper_utc",
    }
)
_TIME_OPEN_FIELDS = _TIME_COMMON_FIELDS | frozenset(
    {"schema", "expected_witness_state_sha256", "expected_witness_sequence"}
)
_TIME_CLOSE_FIELDS = _TIME_COMMON_FIELDS | frozenset(
    {
        "schema",
        "witness_transition_sha256",
        "new_witness_state_sha256",
        "comprehensive_verifier_receipt_sha256s",
        "transcript_root_sha256s",
        "runtime_manifest_root_sha256s",
        "evidence_graph_root_sha256",
    }
)


def _time_quorum(
    values: Any,
    *,
    schema: str,
    fields: frozenset[str],
    domain: bytes,
    policy: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> TrustedInterval:
    code = "TRUSTED_TIME_QUORUM_INVALID"
    if type(values) is not list or len(values) < 2 or len(values) > 3:
        raise _fail(code, "trusted-time quorum must contain two or three receipts")
    accepted: list[tuple[datetime, datetime, dict[str, Any]]] = []
    seen_keys: set[str] = set()
    seen_nonces: set[str] = set()
    for index, raw in enumerate(values):
        envelope = _exact(raw, frozenset({"schema", "payload", "signature_base64"}), f"time envelope[{index}]", code=code)
        if envelope["schema"] != TIME_ENVELOPE_SCHEMA:
            raise _fail(code, "trusted-time envelope schema mismatch")
        payload = _exact(envelope["payload"], fields, f"time receipt[{index}]", code=code)
        if payload["schema"] != schema:
            raise _fail(code, "trusted-time receipt schema mismatch")
        key_id = _identifier(payload["authority_key_id"], "time authority key id", code=code)
        if key_id in seen_keys or key_id not in policy["time_authorities"]:
            raise _fail(code, "duplicate or unrecognized time authority")
        authority = policy["time_authorities"][key_id]
        for field, authority_field in (
            ("authority_subject_id", "subject_id"),
            ("authority_control_group_id", "control_group_id"),
            ("authority_organization_id", "organization_id"),
        ):
            if payload[field] != authority[authority_field]:
                raise _fail(code, f"time receipt {field} does not match the pinned authority")
        for field, expected_value in expected.items():
            if payload.get(field) != expected_value:
                raise _fail(code, f"time receipt {field} does not match the verification binding")
        nonce = _nonce(payload["receipt_nonce"], "time receipt nonce", code=code)
        if nonce in seen_nonces:
            raise _fail(code, "trusted-time receipt nonce was reused")
        lower = _utc(payload["time_lower_utc"], "time lower bound", code=code)
        upper = _utc(payload["time_upper_utc"], "time upper bound", code=code)
        if upper < lower or upper - lower > timedelta(seconds=60):
            raise _fail(code, "trusted-time authority interval is invalid or wider than 60 seconds")
        _verify_signature(authority, domain, payload, envelope["signature_base64"], code=code)
        seen_keys.add(key_id)
        seen_nonces.add(nonce)
        accepted.append((lower, upper, authority))
    if len({item[2]["subject_id"] for item in accepted}) < 2 or len({item[2]["control_group_id"] for item in accepted}) < 2 or len({item[2]["organization_id"] for item in accepted}) < 2:
        raise _fail(code, "trusted-time quorum lacks independent subjects, control groups, or organizations")
    lower = max(item[0] for item in accepted)
    upper = min(item[1] for item in accepted)
    if lower > upper:
        raise _fail(code, "trusted-time authority intervals do not intersect")
    if max(item[1] for item in accepted) - min(item[0] for item in accepted) > timedelta(seconds=120):
        raise _fail(code, "trusted-time authority span exceeds 120 seconds")
    return TrustedInterval(lower=lower, upper=upper, authority_key_ids=tuple(sorted(seen_keys)))


def validate_open_time_quorum(values: Any, *, policy: Mapping[str, Any], expected: Mapping[str, Any]) -> TrustedInterval:
    required = {
        "time_policy_sha256": policy["time_policy_sha256"],
        "release_root_sha256": policy["release_root_sha256"],
        **expected,
    }
    return _time_quorum(values, schema=TIME_OPEN_SCHEMA, fields=_TIME_OPEN_FIELDS, domain=DOMAIN_TIME_OPEN, policy=policy, expected=required)


def validate_close_time_quorum(values: Any, *, policy: Mapping[str, Any], expected: Mapping[str, Any]) -> TrustedInterval:
    required = {
        "time_policy_sha256": policy["time_policy_sha256"],
        "release_root_sha256": policy["release_root_sha256"],
        **expected,
    }
    return _time_quorum(values, schema=TIME_CLOSE_SCHEMA, fields=_TIME_CLOSE_FIELDS, domain=DOMAIN_TIME_CLOSE, policy=policy, expected=required)


def validate_time_window(
    *,
    opening: TrustedInterval,
    closing: TrustedInterval,
    checkpoint_observed_at: datetime,
) -> None:
    if closing.lower < opening.lower or closing.upper < opening.upper:
        raise _fail("TRUSTED_TIME_QUORUM_INVALID", "closing trusted-time quorum precedes the opening quorum")
    if closing.upper - opening.lower > timedelta(seconds=3600):
        raise _fail("VERIFICATION_WINDOW_EXPIRED", "verification exceeded the one-hour trusted-time window")
    if closing.lower - checkpoint_observed_at > timedelta(seconds=86400):
        raise _fail("CHECKPOINT_STALE", "checkpoint is older than 24 hours at closing")
    if checkpoint_observed_at - closing.upper > timedelta(seconds=30):
        raise _fail("CHECKPOINT_FUTURE_SKEW", "checkpoint is more than 30 seconds in the trusted future")


def fail_closed_verdict(state: str, *, reason: str) -> dict[str, Any]:
    return {
        "schema": "eval.v6.2.6.external-trust-verdict",
        "state": state,
        "reason": reason,
        "external_authentication_verified": False,
        "population_feasible": False,
        "population_feasible_under_pinned_policy": False,
        "local_process_output_authoritative": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "permits": [],
        "sealed_holdout_accessed": False,
    }


__all__ = [
    "AUTHORITY_SCHEMA",
    "DOMAIN_TIME_CLOSE",
    "DOMAIN_TIME_OPEN",
    "DOMAIN_WITNESS_HEAD",
    "DOMAIN_WITNESS_STATE",
    "DOMAIN_WITNESS_TRANSITION",
    "FAILURE_STATES",
    "LOG_CHECKPOINT_SCHEMA",
    "MONOTONIC_STATE_SCHEMA",
    "REDEMPTION_REQUEST_SCHEMA",
    "ROLE_EXTERNAL_VERIFIER",
    "ROLE_IDENTITY_ISSUER",
    "ROLE_LOG_AUTHORITY",
    "ROLE_TIME_AUTHORITY",
    "ROLE_WITNESS_COSIGNER",
    "TIME_CLOSE_SCHEMA",
    "TIME_ENVELOPE_SCHEMA",
    "TIME_OPEN_SCHEMA",
    "TRUST_POLICY_SCHEMA",
    "TrustV626Error",
    "TrustedInterval",
    "WITNESS_ENVELOPE_SCHEMA",
    "WITNESS_HEAD_ENVELOPE_SCHEMA",
    "WITNESS_HEAD_SCHEMA",
    "WITNESS_TRANSITION_SCHEMA",
    "WitnessValidation",
    "WitnessHeadValidation",
    "fail_closed_verdict",
    "detect_witness_forks",
    "monotonic_state_sha256",
    "validate_close_time_quorum",
    "validate_open_time_quorum",
    "validate_time_window",
    "validate_trust_policy",
    "validate_witness_transition",
    "validate_witness_head",
    "verify_authority_signature",
]
