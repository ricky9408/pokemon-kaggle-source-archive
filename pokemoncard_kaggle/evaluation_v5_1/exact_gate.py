"""Retired v1 exact-gate wire helpers.

The v1 schema is retained only so historical diagnostic artifacts remain
readable.  Its verifier is permanently fail-closed: v1 accepted caller-selected
trust anchors, roots, module digests, dependencies, and recomputed outputs, so a
self-consistent signed fiction could pass.  New gates must use the v2 service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .canonical import canonical_sha256
from .envelope import verify_envelope


EXACT_GATE_PAYLOAD_SCHEMA = "evaluation_v5_1_exact_gate_payload_v1"
EXACT_GATE_COUNTERSIGNATURE_SCHEMA = (
    "evaluation_v5_1_exact_gate_countersignature_v1"
)
PASS_DECISION = "PASS_RESEARCH_ONLY"
FAIL_DECISION = "FAIL_UNVERIFIED_EVIDENCE"
EXACT_GATE_V1_RETIRED = True
V1_RETIRED_REASON = (
    "exact-gate v1 is retired: caller-controlled recomputation and trust anchors"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GATE_RE = re.compile(r"^G(?:0[0-9]|1[0-5])_[A-Z0-9_]+$")
_FAILURE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_MEDIA_TYPE_RE = re.compile(
    r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"
)
_BYTE_EVIDENCE_FIELDS = frozenset(
    {"base64", "decoded_length", "sha256", "media_type"}
)
_DEPENDENCY_FIELDS = frozenset({"gate_id", "result_root"})
_GATE_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_root",
        "evaluation_id",
        "gate_id",
        "frozen_spec_hash",
        "dependency_roots",
        "campaign_registry_hash",
        "evidence_manifest_root",
        "verifier_module_digest",
        "recomputed_outputs",
        "decision",
        "failure_codes",
    }
)
_COUNTERSIGNATURE_FIELDS = frozenset(
    {
        "schema_version",
        "campaign_root",
        "evaluation_id",
        "gate_id",
        "authority_envelope_sha256",
        "authority_payload_sha256",
        "decision",
    }
)
_CAPABILITY_KEYS = frozenset(
    {
        "authority",
        "candidate_development_authorized",
        "sealed_holdout_access",
        "sealed_holdout_access_authorized",
        "submission_authorized",
        "production_submission_authorized",
    }
)


class ExactGateError(ValueError):
    """Raw evidence, a recomputation, or a dual signature is not exact."""


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ExactGateError(f"{label} fields are not exact")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise ExactGateError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\x00" in value:
        raise ExactGateError(f"{label} must be a non-empty trimmed string without NUL")
    return value


def _gate_id(value: object, label: str) -> str:
    text = _text(value, label)
    if _GATE_RE.fullmatch(text) is None:
        raise ExactGateError(f"{label} is not a canonical G00-G15 gate id")
    return text


def _reject_private_or_capability_claims(value: object, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            lowered = key.lower()
            if (
                ("private" in lowered and "key" in lowered)
                or lowered in {"secret_key", "signing_seed", "private_seed"}
            ):
                raise ExactGateError(f"{path}.{key} contains forbidden private material")
            if key in _CAPABILITY_KEYS and child is not False:
                raise ExactGateError(f"{path}.{key} claims authority")
            _reject_private_or_capability_claims(child, path=f"{path}.{key}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _reject_private_or_capability_claims(child, path=f"{path}[{index}]")


def encode_byte_evidence(raw: bytes, *, media_type: str) -> dict[str, object]:
    """Encode bytes with canonical base64 and independently checked metadata."""

    if type(raw) is not bytes:
        raise ExactGateError("byte evidence must be bytes")
    if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
        raise ExactGateError("media_type is not canonical")
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "decoded_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "media_type": media_type,
    }


def decode_byte_evidence(
    value: object,
    *,
    expected_media_type: str | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    """Decode a strict byte wrapper and recompute all metadata."""

    record = _exact(value, _BYTE_EVIDENCE_FIELDS, "byte evidence")
    if type(record["base64"]) is not str:
        raise ExactGateError("byte evidence base64 must be a string")
    try:
        raw = base64.b64decode(record["base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ExactGateError("byte evidence is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != record["base64"]:
        raise ExactGateError("byte evidence is not canonical base64")
    if type(record["decoded_length"]) is not int or record["decoded_length"] < 0:
        raise ExactGateError("byte evidence decoded_length is invalid")
    if record["decoded_length"] != len(raw):
        raise ExactGateError("byte evidence decoded_length mismatch")
    digest = _sha256(record["sha256"], "byte evidence sha256")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ExactGateError("byte evidence sha256 mismatch")
    media_type = record["media_type"]
    if type(media_type) is not str or _MEDIA_TYPE_RE.fullmatch(media_type) is None:
        raise ExactGateError("byte evidence media_type is invalid")
    if expected_media_type is not None and media_type != expected_media_type:
        raise ExactGateError("byte evidence media_type mismatch")
    if expected_sha256 is not None and digest != _sha256(
        expected_sha256, "expected byte evidence sha256"
    ):
        raise ExactGateError("byte evidence expected sha256 mismatch")
    return raw


def _dependencies(value: object) -> list[dict[str, str]]:
    if type(value) is not list:
        raise ExactGateError("dependency_roots must be a list")
    result: list[dict[str, str]] = []
    prior_gate = ""
    for item in value:
        row = _exact(item, _DEPENDENCY_FIELDS, "dependency root")
        gate = _gate_id(row["gate_id"], "dependency gate_id")
        if gate <= prior_gate:
            raise ExactGateError("dependency roots must be unique and gate-id sorted")
        prior_gate = gate
        result.append(
            {"gate_id": gate, "result_root": _sha256(row["result_root"], "dependency root")}
        )
    return result


def _failure_codes(value: object, *, decision: str) -> list[str]:
    if type(value) is not list or any(
        type(item) is not str or _FAILURE_RE.fullmatch(item) is None for item in value
    ):
        raise ExactGateError("failure_codes are not canonical")
    if value != sorted(set(value)):
        raise ExactGateError("failure_codes must be unique and sorted")
    if decision == PASS_DECISION and value:
        raise ExactGateError("a passing exact gate cannot contain failure codes")
    if decision == FAIL_DECISION and not value:
        raise ExactGateError("a failed exact gate must contain a failure code")
    return list(value)


def derive_exact_gate_payload(
    *,
    campaign_root: str,
    evaluation_id: str,
    gate_id: str,
    frozen_spec_hash: str,
    dependency_roots: Sequence[Mapping[str, str]],
    campaign_registry_hash: str,
    evidence_manifest_root: str,
    verifier_module_digest: str,
    recomputed_outputs: Mapping[str, Any],
    decision: str,
    failure_codes: Sequence[str],
) -> dict[str, Any]:
    """Build the only final gate payload shape accepted by the shared verifier."""

    if type(recomputed_outputs) is not dict:
        raise ExactGateError("recomputed_outputs must be a plain mapping")
    if decision not in {PASS_DECISION, FAIL_DECISION}:
        raise ExactGateError("decision is not an exact-gate decision")
    payload = {
        "schema_version": EXACT_GATE_PAYLOAD_SCHEMA,
        "campaign_root": _sha256(campaign_root, "campaign_root"),
        "evaluation_id": _text(evaluation_id, "evaluation_id"),
        "gate_id": _gate_id(gate_id, "gate_id"),
        "frozen_spec_hash": _sha256(frozen_spec_hash, "frozen_spec_hash"),
        "dependency_roots": _dependencies(list(dependency_roots)),
        "campaign_registry_hash": _sha256(
            campaign_registry_hash, "campaign_registry_hash"
        ),
        "evidence_manifest_root": _sha256(
            evidence_manifest_root, "evidence_manifest_root"
        ),
        "verifier_module_digest": _sha256(
            verifier_module_digest, "verifier_module_digest"
        ),
        "recomputed_outputs": dict(recomputed_outputs),
        "decision": decision,
        "failure_codes": _failure_codes(list(failure_codes), decision=decision),
    }
    _reject_private_or_capability_claims(payload)
    canonical_sha256(payload)
    return payload


def derive_countersignature_payload(authority_envelope: object) -> dict[str, Any]:
    """Bind a validator countersignature to the exact authority envelope bytes."""

    if type(authority_envelope) is not dict:
        raise ExactGateError("authority envelope must be a plain mapping")
    payload = authority_envelope.get("payload")
    exact_payload = _exact(payload, _GATE_FIELDS, "authority exact-gate payload")
    if exact_payload["schema_version"] != EXACT_GATE_PAYLOAD_SCHEMA:
        raise ExactGateError("authority exact-gate payload schema mismatch")
    return {
        "schema_version": EXACT_GATE_COUNTERSIGNATURE_SCHEMA,
        "campaign_root": exact_payload["campaign_root"],
        "evaluation_id": exact_payload["evaluation_id"],
        "gate_id": exact_payload["gate_id"],
        "authority_envelope_sha256": canonical_sha256(authority_envelope),
        "authority_payload_sha256": canonical_sha256(exact_payload),
        "decision": exact_payload["decision"],
    }


def verify_exact_gate_dual_signature(
    *,
    authority_envelope: object,
    countersignature_envelope: object,
    authority_public_key: bytes,
    validator_public_key: bytes,
    expected_campaign_root: str,
    expected_evaluation_id: str,
    expected_gate_id: str,
    expected_frozen_spec_hash: str,
    expected_dependency_roots: Sequence[Mapping[str, str]],
    expected_campaign_registry_hash: str,
    expected_evidence_manifest_root: str,
    expected_verifier_module_digest: str,
    recomputed_outputs: Mapping[str, Any],
    expected_decision: str,
    expected_failure_codes: Sequence[str],
) -> dict[str, Any]:
    """Reject every v1 result, including otherwise valid dual signatures.

    The arguments remain in the signature to make stale callers fail at the
    verification boundary instead of silently importing a different helper.
    """

    raise ExactGateError(V1_RETIRED_REASON)

    # Historical implementation intentionally remains unreachable below.  It
    # documents why old fixtures once passed and keeps static comparison tools
    # useful while every G00-G15 module migrates to v2.

    if (
        type(authority_public_key) is not bytes
        or type(validator_public_key) is not bytes
        or len(authority_public_key) != 32
        or len(validator_public_key) != 32
    ):
        raise ExactGateError("authority and validator keys must be raw Ed25519 public keys")
    if authority_public_key == validator_public_key:
        raise ExactGateError("authority and validator keys must be distinct")

    authority_payload = verify_envelope(
        authority_envelope,
        expected_artifact_schema=EXACT_GATE_PAYLOAD_SCHEMA,
        pinned_public_key_bytes=authority_public_key,
    )
    authority_payload = _exact(
        authority_payload, _GATE_FIELDS, "authority exact-gate payload"
    )
    expected_payload = derive_exact_gate_payload(
        campaign_root=expected_campaign_root,
        evaluation_id=expected_evaluation_id,
        gate_id=expected_gate_id,
        frozen_spec_hash=expected_frozen_spec_hash,
        dependency_roots=expected_dependency_roots,
        campaign_registry_hash=expected_campaign_registry_hash,
        evidence_manifest_root=expected_evidence_manifest_root,
        verifier_module_digest=expected_verifier_module_digest,
        recomputed_outputs=recomputed_outputs,
        decision=expected_decision,
        failure_codes=expected_failure_codes,
    )
    if authority_payload != expected_payload:
        raise ExactGateError("authority payload is not the exact recomputed gate result")

    countersignature = verify_envelope(
        countersignature_envelope,
        expected_artifact_schema=EXACT_GATE_COUNTERSIGNATURE_SCHEMA,
        pinned_public_key_bytes=validator_public_key,
    )
    countersignature = _exact(
        countersignature,
        _COUNTERSIGNATURE_FIELDS,
        "exact-gate countersignature payload",
    )
    expected_countersignature = derive_countersignature_payload(authority_envelope)
    if countersignature != expected_countersignature:
        raise ExactGateError(
            "validator did not countersign the exact authority envelope"
        )
    return dict(authority_payload)


__all__ = [
    "EXACT_GATE_COUNTERSIGNATURE_SCHEMA",
    "EXACT_GATE_PAYLOAD_SCHEMA",
    "EXACT_GATE_V1_RETIRED",
    "ExactGateError",
    "FAIL_DECISION",
    "PASS_DECISION",
    "V1_RETIRED_REASON",
    "decode_byte_evidence",
    "derive_countersignature_payload",
    "derive_exact_gate_payload",
    "encode_byte_evidence",
    "verify_exact_gate_dual_signature",
]
