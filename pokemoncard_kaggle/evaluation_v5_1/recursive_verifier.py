"""Research-only recursive verifier for the frozen exact-gate v2 DAG.

This module is intentionally a compositor, not a gate dispatcher.  It accepts
raw signed wire bundles, rebuilds the reachable G00--G15 dependency closure
from the registered DAG, and asks injected *trusted* receipt interfaces to
attest to hermetic execution and valid-only replay handling.  It contains no
local replay database, no verifier allowlist, and no route to production
authority.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, Protocol

from . import exact_gate_v2, governance
from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256


RECURSIVE_AUDIT_SCHEMA = "ptcg.exact-gate.recursive-audit/v1"
HERMETIC_RECEIPT_SCHEMA = "ptcg.exact-gate.hermetic-execution-receipt/v1"
REPLAY_RECEIPT_SCHEMA = "ptcg.exact-gate.valid-only-replay-receipt/v1"
RESEARCH_AUDIT_DECISION = "SYNTHETIC_RECURSIVE_CONFORMANCE_ONLY"

# Production trust services must be installed by a separately reviewed change.
# Caller-supplied Protocol implementations are never production trust anchors.
PINNED_HERMETIC_SERVICE_IDENTITIES: Mapping[str, str] = MappingProxyType({})
PINNED_REPLAY_SERVICE_IDENTITIES: Mapping[str, str] = MappingProxyType({})

_BUNDLE_ROW_FIELDS = frozenset({"gate_id", "final_bundle"})
_GOVERNANCE_MATERIAL_FIELDS = frozenset(
    {
        "genesis_envelope",
        "registry_epoch_envelopes",
        "role_pop_envelopes",
        "evaluation_entry_envelope",
        "freeze_authority_envelope",
        "freeze_validator_envelope",
        "evidence_manifest_wrapper",
        "supplied_artifacts",
        "failure_code_registry_raw",
        "pinned_offline_root_public_key",
    }
)
_HERMETIC_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "receipt_kind",
        "executor_id",
        "gate_id",
        "bundle_sha256",
        "input_bundle_root",
        "verifier_bundle_digest",
        "verifier_runtime_digest",
        "recomputed_outputs",
        "failure_codes",
        "decision",
    }
)
_REPLAY_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "service_id",
        "campaign_root",
        "evaluation_id",
        "evaluation_nonce",
        "gate_id",
        "attempt",
        "bundle_sha256",
        "registry_epoch",
        "registry_hash",
        "status",
    }
)
_ZERO_AUTHORITY_FLAGS = {
    "authority": False,
    "submission_authorized": False,
    "holdout_access": False,
    "sealed_holdout_access": False,
    "candidate_authorized": False,
    "candidate_development_authorized": False,
}


class RecursiveExactVerificationError(ValueError):
    """The recursive research protocol could not verify exact evidence."""


class HermeticExecutionReceiptVerifier(Protocol):
    """Trusted boundary for signed, gate-specific hermetic execution receipts.

    An implementation must raise on an unauthenticated, non-hermetic, or
    non-content-addressed receipt.  It deliberately returns no caller-selected
    validity boolean.
    """

    def verify_hermetic_execution_receipt(
        self,
        *,
        receipt_raw: bytes,
        gate_id: str,
        bundle_sha256: str,
        verifier_bundle_digest: str,
        verifier_runtime_digest: str,
    ) -> None: ...


class TrustedValidOnlyReplayService(Protocol):
    """Trusted durable replay boundary; no local implementation is provided."""

    def verify_valid_only_replay_receipt(
        self,
        *,
        receipt_raw: bytes,
        campaign_root: str,
        evaluation_id: str,
        evaluation_nonce: str,
        gate_id: str,
        attempt: int,
        bundle_sha256: str,
        registry_epoch: int,
        registry_hash: str,
    ) -> None: ...


def _exact(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise RecursiveExactVerificationError(f"{label} fields are not exact")
    return dict(value)


def _raw(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise RecursiveExactVerificationError(f"{label} must be raw bytes")
    return value


def _gate_id(value: object, label: str) -> str:
    if type(value) is not str or value not in governance.GOVERNANCE_V2_GATE_IDS:
        raise RecursiveExactVerificationError(f"{label} is not a registered G00-G15 gate")
    return value


def _reachable_gate_ids(target_gate_id: str) -> tuple[str, ...]:
    target = _gate_id(target_gate_id, "target gate_id")
    if target not in governance.GOVERNANCE_V2_GATE_DEPENDENCIES:
        raise RecursiveExactVerificationError("target gate is absent from the frozen DAG")
    pending = [target]
    reached: set[str] = set()
    while pending:
        gate = pending.pop()
        if gate in reached:
            continue
        try:
            dependencies = governance.GOVERNANCE_V2_GATE_DEPENDENCIES[gate]
        except KeyError as exc:  # Defensive: the registered DAG itself is malformed.
            raise RecursiveExactVerificationError("frozen DAG references an unknown gate") from exc
        reached.add(gate)
        pending.extend(dependencies)
    return tuple(gate for gate in governance.GOVERNANCE_V2_GATE_IDS if gate in reached)


def _registered_edges(gate_ids: Sequence[str]) -> list[dict[str, str]]:
    reached = set(gate_ids)
    return [
        {"gate_id": gate, "dependency_gate_id": dependency}
        for gate in gate_ids
        for dependency in governance.GOVERNANCE_V2_GATE_DEPENDENCIES[gate]
        if dependency in reached
    ]


def _decode_payload_from_envelope(
    envelope_raw: bytes,
    *,
    expected_schema: str,
    expected_payload_media_type: str,
    label: str,
) -> tuple[bytes, dict[str, Any]]:
    """Decode the exact payload bytes after the governance verifier authenticates it."""

    try:
        envelope = exact_gate_v2.strict_canonical_json(envelope_raw, label=label)
        if type(envelope) is not dict:
            raise exact_gate_v2.ExactGateV2Error("envelope must be an object")
        if envelope.get("schema_version") != expected_schema:
            raise exact_gate_v2.ExactGateV2Error("envelope schema mismatch")
        payload_raw = exact_gate_v2.decode_byte_evidence(
            envelope.get("payload"), expected_media_type=expected_payload_media_type
        )
        payload = exact_gate_v2.strict_canonical_json(payload_raw, label=f"{label} payload")
        if type(payload) is not dict:
            raise exact_gate_v2.ExactGateV2Error("payload must be an object")
        return payload_raw, dict(payload)
    except exact_gate_v2.ExactGateV2Error as exc:
        raise RecursiveExactVerificationError(f"{label} is malformed: {exc}") from exc


def _raw_bundles(value: object, *, expected_gate_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) != len(expected_gate_ids):
        raise RecursiveExactVerificationError("raw bundle set must contain every reachable gate exactly once")
    bundles: dict[str, dict[str, Any]] = {}
    for row_value in value:
        row = _exact(row_value, _BUNDLE_ROW_FIELDS, "raw gate bundle")
        gate = _gate_id(row["gate_id"], "raw bundle gate_id")
        if gate in bundles:
            raise RecursiveExactVerificationError("raw bundle set contains a duplicate gate")
        final_bundle = _raw(row["final_bundle"], "raw final bundle")
        try:
            authority_raw, validator_raw, bundle_sha256 = exact_gate_v2.parse_final_bundle(final_bundle)
        except exact_gate_v2.ExactGateV2Error as exc:
            raise RecursiveExactVerificationError(f"raw {gate} bundle is invalid: {exc}") from exc
        authority_payload_raw, authority_payload = _decode_payload_from_envelope(
            authority_raw,
            expected_schema=exact_gate_v2.AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=exact_gate_v2.AUTHORITY_PAYLOAD_MEDIA_TYPE,
            label=f"raw {gate} authority envelope",
        )
        validator_payload_raw, validator_payload = _decode_payload_from_envelope(
            validator_raw,
            expected_schema=exact_gate_v2.VALIDATOR_ENVELOPE_SCHEMA,
            expected_payload_media_type=exact_gate_v2.VALIDATOR_PAYLOAD_MEDIA_TYPE,
            label=f"raw {gate} validator envelope",
        )
        if authority_payload.get("gate_id") != gate or validator_payload.get("gate_id") != gate:
            raise RecursiveExactVerificationError("raw bundle row gate does not match its signed payload")
        bundles[gate] = {
            "authority_raw": authority_raw,
            "validator_raw": validator_raw,
            "authority_payload_raw": authority_payload_raw,
            "validator_payload_raw": validator_payload_raw,
            "authority_payload": authority_payload,
            "validator_payload": validator_payload,
            "bundle_sha256": bundle_sha256,
        }
    if set(bundles) != set(expected_gate_ids):
        raise RecursiveExactVerificationError("raw bundle set has missing or extra reachable gates")
    return bundles


def _governance_materials(value: object, *, expected_gate_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    if type(value) is not dict or set(value) != set(expected_gate_ids):
        raise RecursiveExactVerificationError("governance material must cover every reachable gate exactly once")
    result: dict[str, dict[str, Any]] = {}
    for gate in expected_gate_ids:
        result[gate] = _exact(value[gate], _GOVERNANCE_MATERIAL_FIELDS, f"{gate} governance material")
    return result


def _dependency_records(
    *,
    gate_ids: Sequence[str],
    bundles: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Rebuild each gate's full ancestor records from exact raw bundle bytes."""

    records_by_gate: dict[str, list[dict[str, Any]]] = {}
    reached_by_gate = {gate: set(_reachable_gate_ids(gate)) - {gate} for gate in gate_ids}
    for gate in gate_ids:
        records_by_gate[gate] = [
            {
                "gate_id": ancestor,
                "bundle_sha256": bundles[ancestor]["bundle_sha256"],
                "authority_payload_sha256": hashlib.sha256(
                    bundles[ancestor]["authority_payload_raw"]
                ).hexdigest(),
                "decision": bundles[ancestor]["authority_payload"].get("decision"),
            }
            for ancestor in governance.GOVERNANCE_V2_GATE_IDS
            if ancestor in reached_by_gate[gate]
        ]
    return records_by_gate


def _validate_dependency_bindings(
    *,
    gate_ids: Sequence[str],
    bundles: Mapping[str, Mapping[str, Any]],
) -> None:
    """Reject wrong edges, substitutions, cycles, and ignored dependency failure."""

    for gate in gate_ids:
        payload = bundles[gate]["authority_payload"]
        expected = governance.GOVERNANCE_V2_GATE_DEPENDENCIES[gate]
        try:
            direct = exact_gate_v2.normalize_direct_dependencies(payload.get("direct_dependencies"))
        except exact_gate_v2.ExactGateV2Error as exc:
            raise RecursiveExactVerificationError(f"{gate} direct dependencies are invalid: {exc}") from exc
        if tuple(row["gate_id"] for row in direct) != expected:
            raise RecursiveExactVerificationError(f"{gate} direct edges differ from the frozen DAG")
        for row in direct:
            dependency = bundles.get(row["gate_id"])
            if dependency is None:
                raise RecursiveExactVerificationError(f"{gate} names a missing raw dependency")
            if row["bundle_sha256"] != dependency["bundle_sha256"]:
                raise RecursiveExactVerificationError(f"{gate} dependency bundle hash substitution")
            if row["authority_payload_sha256"] != hashlib.sha256(
                dependency["authority_payload_raw"]
            ).hexdigest():
                raise RecursiveExactVerificationError(f"{gate} dependency authority payload substitution")
            if row["decision"] != dependency["authority_payload"].get("decision"):
                raise RecursiveExactVerificationError(f"{gate} dependency decision substitution")
        failed = sorted(row["gate_id"] for row in direct if row["decision"] == exact_gate_v2.FAIL_DECISION)
        if failed:
            outputs = payload.get("recomputed_outputs")
            if (
                payload.get("decision") != exact_gate_v2.FAIL_DECISION
                or type(outputs) is not dict
                or outputs.get("failed_dependency_gate_ids") != failed
                or exact_gate_v2.DEPENDENCY_FAILURE_CODE not in payload.get("failure_codes", [])
            ):
                raise RecursiveExactVerificationError(
                    f"{gate} does not force dependency failure before gate-specific pass"
                )


def _validate_shared_identity(
    *,
    target_gate: str,
    gate_ids: Sequence[str],
    bundles: Mapping[str, Mapping[str, Any]],
    governance_results: Mapping[str, Mapping[str, Any]],
) -> None:
    """A raw ancestor cannot be borrowed from another campaign or registry tip."""

    target_payload = bundles[target_gate]["authority_payload"]
    target_governance = governance_results[target_gate]
    identity = {
        "campaign_root": target_payload.get("campaign_root"),
        "evaluation_id": target_payload.get("evaluation_id"),
        "evaluation_nonce": target_payload.get("evaluation_nonce"),
        "attempt": target_payload.get("attempt"),
    }
    registry = {
        "registry_epoch": target_governance.get("registry_epoch"),
        "registry_hash": target_governance.get("registry_hash"),
    }
    for gate in gate_ids:
        payload = bundles[gate]["authority_payload"]
        result = governance_results[gate]
        for field, expected in identity.items():
            if payload.get(field) != expected or result.get(field) != expected:
                raise RecursiveExactVerificationError(
                    f"{gate} raw bundle is from a different campaign/evaluation identity"
                )
        for field, expected in registry.items():
            if result.get(field) != expected:
                raise RecursiveExactVerificationError(
                    f"{gate} governance binding uses a different registry tip"
                )


def _receipt(
    raw: object,
    *,
    expected_kind: str,
    gate: str,
    bundle: Mapping[str, Any],
) -> dict[str, Any]:
    receipt_raw = _raw(raw, f"{gate} {expected_kind} execution receipt")
    try:
        value = exact_gate_v2.strict_canonical_json(receipt_raw, label=f"{gate} hermetic receipt")
    except exact_gate_v2.ExactGateV2Error as exc:
        raise RecursiveExactVerificationError(f"{gate} hermetic receipt is malformed: {exc}") from exc
    receipt = _exact(value, _HERMETIC_RECEIPT_FIELDS, f"{gate} hermetic receipt")
    if receipt["schema_version"] != HERMETIC_RECEIPT_SCHEMA or receipt["receipt_kind"] != expected_kind:
        raise RecursiveExactVerificationError(f"{gate} hermetic receipt kind/schema mismatch")
    if type(receipt["executor_id"]) is not str or not receipt["executor_id"]:
        raise RecursiveExactVerificationError(f"{gate} hermetic executor identity is invalid")
    expected = {
        "gate_id": gate,
        "bundle_sha256": bundle["bundle_sha256"],
        "input_bundle_root": bundle["authority_payload"].get("input_bundle_root"),
        "verifier_bundle_digest": bundle["authority_payload"].get("verifier_bundle_digest"),
        "verifier_runtime_digest": bundle["authority_payload"].get("verifier_runtime_digest"),
        "recomputed_outputs": bundle["authority_payload"].get("recomputed_outputs"),
        "failure_codes": bundle["authority_payload"].get("failure_codes"),
        "decision": bundle["authority_payload"].get("decision"),
    }
    for field, expected_value in expected.items():
        if receipt[field] != expected_value:
            raise RecursiveExactVerificationError(f"{gate} {expected_kind} receipt {field} differs from signed result")
    # Canonical byte equality, rather than Python object equality, is the
    # reproducibility contract for independently executed outputs/failures.
    for field in ("recomputed_outputs", "failure_codes"):
        if canonical_json_bytes(receipt[field]) != canonical_json_bytes(expected[field]):
            raise RecursiveExactVerificationError(f"{gate} {expected_kind} receipt {field} is not byte-identical")
    return receipt


def _verify_replay_receipt(
    *,
    replay_service: TrustedValidOnlyReplayService,
    receipt_raw: object,
    target_gate: str,
    bundle: Mapping[str, Any],
    governance_result: Mapping[str, Any],
) -> str:
    raw = _raw(receipt_raw, "trusted replay-service receipt")
    authority = bundle["authority_payload"]
    expected = {
        "campaign_root": authority.get("campaign_root"),
        "evaluation_id": authority.get("evaluation_id"),
        "evaluation_nonce": authority.get("evaluation_nonce"),
        "gate_id": target_gate,
        "attempt": authority.get("attempt"),
        "bundle_sha256": bundle["bundle_sha256"],
        "registry_epoch": governance_result.get("registry_epoch"),
        "registry_hash": governance_result.get("registry_hash"),
    }
    try:
        replay_service.verify_valid_only_replay_receipt(receipt_raw=raw, **expected)
        value = exact_gate_v2.strict_canonical_json(raw, label="trusted replay-service receipt")
    except (exact_gate_v2.ExactGateV2Error, ValueError, TypeError) as exc:
        raise RecursiveExactVerificationError(f"trusted replay service rejected receipt: {exc}") from exc
    receipt = _exact(value, _REPLAY_RECEIPT_FIELDS, "trusted replay-service receipt")
    if receipt["schema_version"] != REPLAY_RECEIPT_SCHEMA or receipt["status"] != "VALID_ONLY_REPLAY_ACCEPTED":
        raise RecursiveExactVerificationError("trusted replay receipt is not a valid-only acceptance")
    if type(receipt["service_id"]) is not str or not receipt["service_id"]:
        raise RecursiveExactVerificationError("trusted replay receipt service identity is invalid")
    for field, expected_value in expected.items():
        if receipt[field] != expected_value:
            raise RecursiveExactVerificationError(f"trusted replay receipt {field} is stale or conflicts")
    return hashlib.sha256(raw).hexdigest()


def _build_synthetic_recursive_audit(
    *,
    target_gate_id: str,
    raw_gate_bundles: object,
    governance_material_by_gate: object,
    authority_execution_receipts: Mapping[str, bytes],
    validator_execution_receipts: Mapping[str, bytes],
    hermetic_receipt_verifier: HermeticExecutionReceiptVerifier,
    replay_service: TrustedValidOnlyReplayService,
    replay_service_receipt: bytes,
) -> dict[str, Any]:
    """Build a synthetic, caller-service conformance audit with zero authority.

    All failures raise :class:`RecursiveExactVerificationError`; this function
    intentionally has no rejected/pass production result branch.  The caller
    cannot supply a pass boolean, a dependency checklist, an execution result,
    or a local replay index.
    """

    try:
        target = _gate_id(target_gate_id, "target gate_id")
        gate_ids = _reachable_gate_ids(target)
        bundles = _raw_bundles(raw_gate_bundles, expected_gate_ids=gate_ids)
        materials = _governance_materials(governance_material_by_gate, expected_gate_ids=gate_ids)
        if set(authority_execution_receipts) != set(gate_ids) or set(validator_execution_receipts) != set(gate_ids):
            raise RecursiveExactVerificationError("two execution receipts are required for every reachable gate")
        _validate_dependency_bindings(gate_ids=gate_ids, bundles=bundles)
        records = _dependency_records(gate_ids=gate_ids, bundles=bundles)

        governance_results: dict[str, dict[str, Any]] = {}
        for gate in gate_ids:
            bundle = bundles[gate]
            material = materials[gate]
            governance_result = governance.verify_exact_gate_v2_governance(
                **material,
                exact_gate_authority_envelope=bundle["authority_raw"],
                exact_gate_validator_envelope=bundle["validator_raw"],
                transitive_dependencies=records[gate],
                transitive_dependency_edges=_registered_edges(_reachable_gate_ids(gate)),
            )
            if governance_result.get("decision") != "EXACT_GATE_V2_GOVERNANCE_BOUND_RESEARCH_ONLY":
                raise RecursiveExactVerificationError(
                    f"{gate} governance binding failed: {governance_result.get('fail_code', 'unknown') }"
                )
            if governance_result.get("gate_id") != gate:
                raise RecursiveExactVerificationError(f"{gate} governance binding returned another gate")
            if any(governance_result.get(flag) is not False for flag in _ZERO_AUTHORITY_FLAGS):
                raise RecursiveExactVerificationError(f"{gate} governance binding asserted authority")
            governance_results[gate] = governance_result

            authority_receipt = _receipt(
                authority_execution_receipts[gate], expected_kind="AUTHORITY", gate=gate, bundle=bundle
            )
            validator_receipt = _receipt(
                validator_execution_receipts[gate], expected_kind="VALIDATOR", gate=gate, bundle=bundle
            )
            if authority_receipt["executor_id"] == validator_receipt["executor_id"]:
                raise RecursiveExactVerificationError(f"{gate} execution receipts are not independent")
            for receipt_raw in (authority_execution_receipts[gate], validator_execution_receipts[gate]):
                hermetic_receipt_verifier.verify_hermetic_execution_receipt(
                    receipt_raw=receipt_raw,
                    gate_id=gate,
                    bundle_sha256=bundle["bundle_sha256"],
                    verifier_bundle_digest=bundle["authority_payload"]["verifier_bundle_digest"],
                    verifier_runtime_digest=bundle["authority_payload"]["verifier_runtime_digest"],
                )

        _validate_shared_identity(
            target_gate=target,
            gate_ids=gate_ids,
            bundles=bundles,
            governance_results=governance_results,
        )
        replay_receipt_sha256 = _verify_replay_receipt(
            replay_service=replay_service,
            receipt_raw=replay_service_receipt,
            target_gate=target,
            bundle=bundles[target],
            governance_result=governance_results[target],
        )
        content = {
            "schema_version": RECURSIVE_AUDIT_SCHEMA,
            "decision": RESEARCH_AUDIT_DECISION,
            "target_gate_id": target,
            "reachable_gate_ids": list(gate_ids),
            "raw_bundle_sha256_by_gate": {gate: bundles[gate]["bundle_sha256"] for gate in gate_ids},
            "authority_execution_receipt_sha256_by_gate": {
                gate: hashlib.sha256(authority_execution_receipts[gate]).hexdigest()
                for gate in gate_ids
            },
            "validator_execution_receipt_sha256_by_gate": {
                gate: hashlib.sha256(validator_execution_receipts[gate]).hexdigest()
                for gate in gate_ids
            },
            "governance_result_sha256_by_gate": {
                gate: governance_results[gate].get("result_sha256") for gate in gate_ids
            },
            "replay_service_receipt_sha256": replay_receipt_sha256,
            **_ZERO_AUTHORITY_FLAGS,
        }
        return {**content, "audit_sha256": canonical_sha256(content)}
    except RecursiveExactVerificationError:
        raise
    except (
        exact_gate_v2.ExactGateV2Error,
        governance.GovernanceValidationError,
        CanonicalJSONError,
        KeyError,
        TypeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise RecursiveExactVerificationError(str(exc)) from exc


def verify_recursive_exact_v2(
    *,
    target_gate_id: str,
    raw_gate_bundles: object,
    governance_material_by_gate: object,
    authority_execution_receipts: Mapping[str, bytes],
    validator_execution_receipts: Mapping[str, bytes],
    hermetic_receipt_verifier: HermeticExecutionReceiptVerifier,
    replay_service: TrustedValidOnlyReplayService,
    replay_service_receipt: bytes,
) -> dict[str, Any]:
    """Production-shaped entry point, hard-closed until trust is independently pinned."""

    del (
        target_gate_id,
        raw_gate_bundles,
        governance_material_by_gate,
        authority_execution_receipts,
        validator_execution_receipts,
        hermetic_receipt_verifier,
        replay_service,
        replay_service_receipt,
    )
    if not PINNED_HERMETIC_SERVICE_IDENTITIES or not PINNED_REPLAY_SERVICE_IDENTITIES:
        raise RecursiveExactVerificationError(
            "independently pinned hermetic and replay trust services are unavailable"
        )
    raise RecursiveExactVerificationError(
        "production recursive verifier integration is not implemented"
    )


__all__ = [
    "HERMETIC_RECEIPT_SCHEMA",
    "RECURSIVE_AUDIT_SCHEMA",
    "REPLAY_RECEIPT_SCHEMA",
    "RESEARCH_AUDIT_DECISION",
    "PINNED_HERMETIC_SERVICE_IDENTITIES",
    "PINNED_REPLAY_SERVICE_IDENTITIES",
    "HermeticExecutionReceiptVerifier",
    "RecursiveExactVerificationError",
    "TrustedValidOnlyReplayService",
    "verify_recursive_exact_v2",
]
