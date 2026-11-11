"""Evidence-bound composer for the v5 prospective evaluator.

This is the only v5 entry point that may call a transfer result evaluator-valid.
It independently verifies the current implementation bytes, signed engine
capability receipts, and raw RFC 3161 registration anchors before delegating to
the statistical prevalidation gate.  It deliberately grants neither submission
nor sealed-holdout authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .binding import binding_sha256, verify_binding
from .campaign_anchor import CampaignAnchorError, verify_campaign_anchor
from .canonical import canonical_sha256
from .cohort import validate_observation_log, validate_registry
from .custody_anchor import CustodyAnchorError, verify_custody_anchor_batch
from .engine_evidence import audit_engine_evidence
from .gates import (
    build_operational_safety_evidence,
    prevalidation_gate,
    validate_campaign,
)
from .host_evidence import audit_host_evidence
from .implementation_binding import ImplementationBindingError, verify_manifest
from .openssl_runtime import OpenSSLRuntimeError, verify_pinned_openssl
from .provenance_evidence import audit_provenance_evidence
from .safety_evidence import audit_operational_safety_evidence
from . import trust_roots


SCHEMA = "evaluation_v5_evidence_bound_prevalidation_v1"

# A campaign implementation manifest must bind this exact ordered set.  Keeping
# the list static makes any source/test/protocol change a new implementation and
# therefore a new preregistered campaign.  The implementation manifest itself is
# deliberately absent because its self-hash would be recursive; the independent
# RFC 3161 campaign anchor binds that manifest instead.
AUTHORITATIVE_IMPLEMENTATION_PATHS = (
    "evaluation_v4_1/__init__.py",
    "evaluation_v4_1/protocol.py",
    "evaluation_v4_1/timestamping.py",
    "evaluation_v5/__init__.py",
    "evaluation_v5/README.md",
    "evaluation_v5/ancestry.py",
    "evaluation_v5/binding.py",
    "evaluation_v5/campaign_anchor.py",
    "evaluation_v5/canonical.py",
    "evaluation_v5/charter.py",
    "evaluation_v5/cohort.py",
    "evaluation_v5/custody_anchor.py",
    "evaluation_v5/development_fit.py",
    "evaluation_v5/engine_capabilities.py",
    "evaluation_v5/engine_evidence.py",
    "evaluation_v5/evidence_bound_gate.py",
    "evaluation_v5/firewall.py",
    "evaluation_v5/gates.py",
    "evaluation_v5/host_evidence.py",
    "evaluation_v5/implementation_binding.py",
    "evaluation_v5/model.py",
    "evaluation_v5/openssl_runtime.py",
    "evaluation_v5/provenance_evidence.py",
    "evaluation_v5/safety_evidence.py",
    "evaluation_v5/transfer.py",
    "evaluation_v5/trust_roots.py",
    "pytest.ini",
    "strategy/evaluation_v5_architecture_binding_20260713.json",
    "strategy/evaluation_v5_external_cohort_protocol_20260713.md",
    "strategy/evaluation_v5_integrity_closure_20260714.md",
    "strategy/evaluation_v5_preregistration_20260713.md",
    "strategy/evaluation_v5_scenario_contract_20260713.md",
    "strategy/evaluation_v5_sol_review_20260713.md",
    "tests/test_evaluation_v4_1_timestamping.py",
    "tests/test_evaluation_v5_ancestry.py",
    "tests/test_evaluation_v5_binding.py",
    "tests/test_evaluation_v5_campaign_anchor.py",
    "tests/test_evaluation_v5_charter.py",
    "tests/test_evaluation_v5_cohort.py",
    "tests/test_evaluation_v5_current_artifacts.py",
    "tests/test_evaluation_v5_custody_anchor.py",
    "tests/test_evaluation_v5_development_fit.py",
    "tests/test_evaluation_v5_engine_capabilities.py",
    "tests/test_evaluation_v5_engine_evidence.py",
    "tests/test_evaluation_v5_evidence_bound_gate.py",
    "tests/test_evaluation_v5_firewall.py",
    "tests/test_evaluation_v5_gates.py",
    "tests/test_evaluation_v5_host_evidence.py",
    "tests/test_evaluation_v5_implementation_binding.py",
    "tests/test_evaluation_v5_model.py",
    "tests/test_evaluation_v5_openssl_runtime.py",
    "tests/test_evaluation_v5_provenance_evidence.py",
    "tests/test_evaluation_v5_safety_evidence.py",
    "tests/test_evaluation_v5_status.py",
    "tests/test_evaluation_v5_transfer.py",
    "tests/test_evaluation_v5_trust_roots.py",
    "tools/evaluation_v5_status.py",
)


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError("timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _first_hosted_games(
    registry: Mapping[str, Any], observation_log: Mapping[str, Any]
) -> dict[str, str]:
    checked_registry = validate_registry(registry)
    checked_log = validate_observation_log(observation_log)
    expected = {record["archive_sha256"] for record in checked_registry["records"]}
    first: dict[str, str] = {}
    for record in checked_log["records"]:
        archive = record["archive_sha256"]
        if archive not in expected:
            continue
        timestamp = record["created_at_utc"]
        if archive not in first or _parse_utc(timestamp) < _parse_utc(first[archive]):
            first[archive] = timestamp
    if set(first) != expected:
        raise ValueError("every registered archive must have a literal hosted game")
    return first


def _closed(reason: str, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    content = {
        "authority": {"sealed_holdout_access": False, "submission_authorized": False},
        "decision": "NO_SUBMIT_INTEGRITY",
        "evidence": dict(evidence or {}),
        "reason": reason,
        "schema": SCHEMA,
        "sealed_holdout_access": False,
        "submission_authorized": False,
    }
    return {**content, "result_sha256": canonical_sha256(content)}


def evidence_bound_prevalidation_gate(
    *,
    repo_root: str | Path,
    binding: object,
    charter: object,
    implementation_manifest: object,
    firewall: object,
    ancestry_manifest: object,
    ancestry_auditor_public_key_hex: str,
    provenance_evidence_manifest: Mapping[str, Any],
    campaign: Mapping[str, Any],
    campaign_anchor: Mapping[str, str | Path],
    mci_manifest: object,
    comparator_manifest: object,
    model_inputs: Sequence[Mapping[str, Any]],
    engine_capability_manifest: object,
    engine_evidence_manifest: Mapping[str, Any],
    engine_evidence_public_key: bytes,
    host_evidence_public_key: bytes,
    host_evidence_manifest: Mapping[str, Any],
    safety_evidence_public_key: bytes,
    safety_evidence_manifest: Mapping[str, Any],
    provenance_evidence_public_key: bytes,
    registry: Mapping[str, Any],
    observation_log: Mapping[str, Any],
    custody_anchors: Sequence[Mapping[str, str | Path]],
    as_of_utc: str,
) -> dict[str, Any]:
    """Compose all evaluator-integrity checks without granting production authority."""

    evidence: dict[str, Any] = {}
    try:
        checked_campaign = validate_campaign(campaign)
        checked_architecture = verify_binding(repo_root, binding)
        checked_implementation = verify_manifest(
            repo_root,
            implementation_manifest,
            required_paths=AUTHORITATIVE_IMPLEMENTATION_PATHS,
        )
        if checked_implementation["architecture_binding_sha256"] != binding_sha256(
            checked_architecture
        ):
            raise ImplementationBindingError(
                "implementation does not bind the verified architecture"
            )
        if (
            checked_implementation["manifest_sha256"]
            != checked_campaign["implementation_binding_sha256"]
        ):
            raise ImplementationBindingError("campaign implementation binding mismatch")
        if _parse_utc(checked_implementation["created_at_utc"]) > _parse_utc(
            checked_campaign["registration_opened_at_utc"]
        ):
            raise ImplementationBindingError(
                "implementation must be frozen no later than campaign opening"
            )
        evidence["implementation_binding_sha256"] = checked_implementation[
            "manifest_sha256"
        ]
    except Exception:
        return _closed("implementation_or_campaign_binding_invalid")

    try:
        verified_roots = trust_roots.validate_campaign_trust_roots(
            checked_campaign,
            ancestry_public_key_hex=ancestry_auditor_public_key_hex,
            engine_evidence_public_key=engine_evidence_public_key,
            host_evidence_public_key=host_evidence_public_key,
            safety_evidence_public_key=safety_evidence_public_key,
            provenance_evidence_public_key=provenance_evidence_public_key,
        )
    except trust_roots.TrustRootError:
        return _closed("external_trust_roots_not_configured_or_mismatch", evidence)

    try:
        trusted_openssl = verify_pinned_openssl(
            verified_roots["openssl_executable_sha256"]
        )
        evidence["openssl_executable_sha256"] = verified_roots[
            "openssl_executable_sha256"
        ]
    except (KeyError, OpenSSLRuntimeError):
        return _closed("openssl_runtime_untrusted", evidence)

    try:
        if _parse_utc(as_of_utc) > _now_utc():
            raise ValueError("as_of_utc is in the future")
    except (TypeError, ValueError):
        return _closed("evaluation_cutoff_invalid", evidence)

    try:
        if set(campaign_anchor) != {"payload_path", "token_path", "ca_file"}:
            raise CampaignAnchorError("campaign anchor path fields are not exact")
        anchor_audit = verify_campaign_anchor(
            payload_path=campaign_anchor["payload_path"],
            token_path=campaign_anchor["token_path"],
            ca_file=campaign_anchor["ca_file"],
            expected_ca_file_sha256=checked_campaign["custody_ca_file_sha256"],
            expected_tsa_policy_oid=checked_campaign["custody_tsa_policy_oid"],
            openssl_bin=trusted_openssl,
        )
        if (
            anchor_audit["architecture_binding_sha256"]
            != binding_sha256(checked_architecture)
            or anchor_audit["implementation_binding_sha256"]
            != checked_implementation["manifest_sha256"]
            or anchor_audit["campaign_sha256"] != checked_campaign["campaign_sha256"]
            or anchor_audit["trust_roots_snapshot_sha256"]
            != checked_campaign["trust_roots_snapshot_sha256"]
            or anchor_audit["campaign_opened_at_utc"]
            != checked_campaign["registration_opened_at_utc"]
        ):
            raise CampaignAnchorError("campaign anchor binding mismatch")
        evidence["campaign_anchor_sha256"] = anchor_audit["evidence_sha256"]
        if verify_pinned_openssl(
            verified_roots["openssl_executable_sha256"]
        ) != trusted_openssl:
            raise CampaignAnchorError("OpenSSL path changed during campaign verification")
    except (CampaignAnchorError, KeyError, TypeError, ValueError):
        return _closed("campaign_preregistration_anchor_invalid", evidence)

    provenance_audit = audit_provenance_evidence(
        ancestry_manifest,
        provenance_evidence_manifest,
        repo_root,
        pinned_public_key=provenance_evidence_public_key,
        pinned_ancestry_public_key_hex=ancestry_auditor_public_key_hex,
    )
    if provenance_audit.get("evidence_complete") is not True:
        return _closed("ancestry_provenance_evidence_invalid", evidence)
    evidence["provenance_evidence_audit_sha256"] = canonical_sha256(
        provenance_audit
    )

    engine_audit = audit_engine_evidence(
        engine_capability_manifest,
        engine_evidence_manifest,
        repo_root,
        pinned_public_key=engine_evidence_public_key,
    )
    if (
        engine_audit.get("evidence_complete") is not True
        or engine_audit.get("local_feature_extraction") is not True
        or engine_audit.get("decision") != "LOCAL_FEATURE_EXTRACTION_FEASIBLE"
        or engine_audit.get("signed_manifest_sha256")
        != checked_campaign["engine_evidence_manifest_sha256"]
        or engine_audit.get("signer_public_key_fingerprint_sha256")
        != checked_campaign["engine_evidence_signer_public_key_sha256"]
    ):
        return _closed("engine_evidence_invalid_or_infeasible", evidence)
    try:
        reviewed_at = _parse_utc(str(engine_evidence_manifest["reviewed_at"]))
        if reviewed_at > _parse_utc(checked_campaign["registration_opened_at_utc"]):
            raise ValueError("engine evidence postdates campaign opening")
    except (KeyError, TypeError, ValueError):
        return _closed("engine_evidence_chronology_invalid", evidence)
    evidence["engine_evidence_audit_sha256"] = canonical_sha256(engine_audit)

    host_audit = audit_host_evidence(
        observation_log,
        host_evidence_manifest,
        repo_root,
        pinned_public_key=host_evidence_public_key,
        registry=registry,
    )
    if host_audit.get("evidence_complete") is not True:
        return _closed("hosted_observation_evidence_invalid", evidence)
    evidence["host_evidence_audit_sha256"] = canonical_sha256(host_audit)

    safety_audit = audit_operational_safety_evidence(
        safety_evidence_manifest,
        repo_root,
        pinned_public_key=safety_evidence_public_key,
    )
    checked_registry = validate_registry(registry)
    expected_archives = sorted(
        record["archive_sha256"] for record in checked_registry["records"]
    )
    if (
        safety_audit.get("evidence_complete") is not True
        or safety_audit.get("decision") != "OPERATIONAL_SAFETY_VERIFIED"
        or safety_audit.get("campaign_sha256") != checked_campaign["campaign_sha256"]
        or safety_audit.get("archive_sha256s") != expected_archives
    ):
        return _closed("operational_safety_evidence_invalid", evidence)
    evidence["safety_evidence_audit_sha256"] = canonical_sha256(safety_audit)
    safety_counts = safety_audit["outcome_counts"]
    verified_safety = build_operational_safety_evidence(
        campaign_sha256=checked_campaign["campaign_sha256"],
        archive_sha256s=expected_archives,
        tested_calls=safety_audit["tested_calls"],
        counts={
            "crashes": safety_counts["crash"],
            "illegal_actions": safety_counts["illegal"],
            "malformed_outputs": safety_counts["malformed"],
            "runtime_failures": safety_counts["runtime"],
            "timeouts": safety_counts["timeout"],
        },
    )

    try:
        first_games = _first_hosted_games(registry, observation_log)
        custody_audit = verify_custody_anchor_batch(
            registry=registry,
            anchors=custody_anchors,
            campaign_sha256=checked_campaign["campaign_sha256"],
            implementation_binding_sha256=checked_implementation["manifest_sha256"],
            signed_ancestry_manifest_sha256=checked_campaign["ancestry_manifest_sha256"],
            first_hosted_game_at_utc_by_archive=first_games,
            openssl_bin=trusted_openssl,
        )
        if any(
            anchor["ca_file_sha256"] != checked_campaign["custody_ca_file_sha256"]
            or anchor["tsa_policy_oid"] != checked_campaign["custody_tsa_policy_oid"]
            for anchor in custody_audit["anchors"]
        ):
            raise CustodyAnchorError("custody trust anchor or TSA policy mismatch")
        evidence["custody_audit_sha256"] = custody_audit["evidence_sha256"]
        if verify_pinned_openssl(
            verified_roots["openssl_executable_sha256"]
        ) != trusted_openssl:
            raise CustodyAnchorError("OpenSSL path changed during custody verification")
    except (CustodyAnchorError, KeyError, TypeError, ValueError):
        return _closed("rfc3161_custody_invalid", evidence)

    statistical = prevalidation_gate(
        repo_root=repo_root,
        binding=binding,
        charter=charter,
        firewall=firewall,
        ancestry_manifest=ancestry_manifest,
        ancestry_auditor_public_key_hex=ancestry_auditor_public_key_hex,
        campaign=campaign,
        mci_manifest=mci_manifest,
        comparator_manifest=comparator_manifest,
        model_inputs=model_inputs,
        engine_capability_manifest=engine_capability_manifest,
        safety_evidence=verified_safety,
        registry=registry,
        observation_log=observation_log,
        as_of_utc=as_of_utc,
    )
    evidence["statistical_prevalidation_sha256"] = statistical["result_sha256"]
    decision = statistical["decision"]
    if decision == "TRANSFER_VALIDATED_RESEARCH_ONLY":
        decision = "EVALUATOR_VALIDATED_RESEARCH_ONLY"
    content = {
        "authority": {"sealed_holdout_access": False, "submission_authorized": False},
        "decision": decision,
        "evidence": dict(sorted(evidence.items())),
        "schema": SCHEMA,
        "sealed_holdout_access": False,
        "statistical_prevalidation": statistical,
        "submission_authorized": False,
    }
    return {**content, "result_sha256": canonical_sha256(content)}


__all__ = [
    "AUTHORITATIVE_IMPLEMENTATION_PATHS",
    "SCHEMA",
    "evidence_bound_prevalidation_gate",
]
