from __future__ import annotations

from pathlib import Path

import evaluation_v5.evidence_bound_gate as module


def _arguments() -> dict[str, object]:
    return {
        "repo_root": Path("."),
        "binding": {},
        "charter": {},
        "implementation_manifest": {},
        "firewall": {},
        "ancestry_manifest": {},
        "ancestry_auditor_public_key_hex": "11" * 32,
        "provenance_evidence_manifest": {},
        "campaign": {},
        "campaign_anchor": {
            "payload_path": "payload.json",
            "token_path": "token.tsr",
            "ca_file": "ca.pem",
        },
        "mci_manifest": {},
        "comparator_manifest": {},
        "model_inputs": [],
        "engine_capability_manifest": {},
        "engine_evidence_manifest": {"reviewed_at": "2026-07-14T00:00:00Z"},
        "engine_evidence_public_key": b"x" * 32,
        "host_evidence_public_key": b"h" * 32,
        "host_evidence_manifest": {},
        "safety_evidence_public_key": b"s" * 32,
        "safety_evidence_manifest": {},
        "provenance_evidence_public_key": b"p" * 32,
        "registry": {},
        "observation_log": {},
        "custody_anchors": [],
        "as_of_utc": "2026-07-15T00:00:00.000000Z",
    }


def _install_valid_composition(monkeypatch) -> None:
    campaign = {
        "campaign_sha256": "1" * 64,
        "implementation_binding_sha256": "2" * 64,
        "engine_evidence_manifest_sha256": "3" * 64,
        "engine_evidence_signer_public_key_sha256": "4" * 64,
        "host_evidence_signer_public_key_sha256": "a" * 64,
        "safety_evidence_signer_public_key_sha256": "b" * 64,
        "provenance_evidence_signer_public_key_sha256": "c" * 64,
        "trust_roots_snapshot_sha256": "d" * 64,
        "ancestry_manifest_sha256": "5" * 64,
        "custody_ca_file_sha256": "6" * 64,
        "custody_tsa_policy_oid": "1.2.3.4",
        "registration_opened_at_utc": "2026-07-14T00:00:00.000000Z",
    }
    monkeypatch.setattr(module, "validate_campaign", lambda _value: campaign)
    monkeypatch.setattr(
        module.trust_roots,
        "validate_campaign_trust_roots",
        lambda *_args, **_kwargs: {"openssl_executable_sha256": "f" * 64},
    )
    monkeypatch.setattr(
        module,
        "verify_pinned_openssl",
        lambda _expected: "/trusted/openssl",
    )
    monkeypatch.setattr(
        module,
        "_now_utc",
        lambda: module._parse_utc("2026-07-16T00:00:00.000000Z"),
    )
    monkeypatch.setattr(module, "verify_binding", lambda *_args: {"binding": True})
    monkeypatch.setattr(module, "binding_sha256", lambda _value: "7" * 64)
    monkeypatch.setattr(
        module,
        "verify_manifest",
        lambda *_args, **_kwargs: {
            "manifest_sha256": "2" * 64,
            "architecture_binding_sha256": "7" * 64,
            "created_at_utc": "2026-07-13T23:59:59.000000Z",
        },
    )
    monkeypatch.setattr(
        module,
        "verify_campaign_anchor",
        lambda **_kwargs: {
            "architecture_binding_sha256": "7" * 64,
            "implementation_binding_sha256": "2" * 64,
            "campaign_sha256": "1" * 64,
            "trust_roots_snapshot_sha256": "d" * 64,
            "campaign_opened_at_utc": "2026-07-14T00:00:00.000000Z",
            "evidence_sha256": "e" * 64,
        },
    )
    monkeypatch.setattr(
        module,
        "audit_provenance_evidence",
        lambda *_args, **_kwargs: {"evidence_complete": True},
    )
    monkeypatch.setattr(
        module,
        "audit_engine_evidence",
        lambda *_args, **_kwargs: {
            "evidence_complete": True,
            "local_feature_extraction": True,
            "decision": "LOCAL_FEATURE_EXTRACTION_FEASIBLE",
            "signed_manifest_sha256": "3" * 64,
            "signer_public_key_fingerprint_sha256": "4" * 64,
        },
    )
    monkeypatch.setattr(
        module,
        "audit_host_evidence",
        lambda *_args, **_kwargs: {"evidence_complete": True},
    )
    monkeypatch.setattr(
        module,
        "audit_operational_safety_evidence",
        lambda *_args, **_kwargs: {
            "evidence_complete": True,
            "decision": "OPERATIONAL_SAFETY_VERIFIED",
            "campaign_sha256": "1" * 64,
            "archive_sha256s": ["a" * 64],
            "tested_calls": 50_000,
            "outcome_counts": {
                "crash": 0,
                "illegal": 0,
                "malformed": 0,
                "ok": 50_000,
                "runtime": 0,
                "timeout": 0,
            },
        },
    )
    monkeypatch.setattr(
        module,
        "validate_registry",
        lambda _value: {"records": [{"archive_sha256": "a" * 64}]},
    )
    monkeypatch.setattr(module, "_first_hosted_games", lambda *_args: {"a" * 64: "x"})
    monkeypatch.setattr(
        module,
        "verify_custody_anchor_batch",
        lambda **_kwargs: {
            "anchors": [
                {"ca_file_sha256": "6" * 64, "tsa_policy_oid": "1.2.3.4"}
            ],
            "evidence_sha256": "8" * 64,
        },
    )


def test_successful_evidence_composition_remains_research_only(monkeypatch) -> None:
    _install_valid_composition(monkeypatch)
    monkeypatch.setattr(
        module,
        "prevalidation_gate",
        lambda **_kwargs: {
            "decision": "TRANSFER_VALIDATED_RESEARCH_ONLY",
            "result_sha256": "9" * 64,
            "submission_authorized": False,
            "sealed_holdout_access": False,
        },
    )
    result = module.evidence_bound_prevalidation_gate(**_arguments())
    assert result["decision"] == "EVALUATOR_VALIDATED_RESEARCH_ONLY"
    assert result["submission_authorized"] is False
    assert result["sealed_holdout_access"] is False
    assert result["authority"] == {
        "sealed_holdout_access": False,
        "submission_authorized": False,
    }


def test_campaign_anchor_cannot_inject_a_runner(monkeypatch) -> None:
    _install_valid_composition(monkeypatch)
    arguments = _arguments()
    arguments["campaign_anchor"] = {
        "payload_path": "payload.json",
        "token_path": "token.tsr",
        "ca_file": "ca.pem",
        "runner": object(),
    }
    result = module.evidence_bound_prevalidation_gate(**arguments)
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert result["reason"] == "campaign_preregistration_anchor_invalid"


def test_implementation_manifest_must_bind_exact_authoritative_paths(monkeypatch) -> None:
    _install_valid_composition(monkeypatch)
    seen: dict[str, object] = {}

    def verify(_root, _manifest, *, required_paths):
        seen["required_paths"] = required_paths
        return {
            "manifest_sha256": "2" * 64,
            "architecture_binding_sha256": "7" * 64,
            "created_at_utc": "2026-07-13T23:59:59.000000Z",
        }

    monkeypatch.setattr(module, "verify_manifest", verify)
    monkeypatch.setattr(
        module,
        "prevalidation_gate",
        lambda **_kwargs: {
            "decision": "TRANSFER_VALIDATED_RESEARCH_ONLY",
            "result_sha256": "9" * 64,
        },
    )
    result = module.evidence_bound_prevalidation_gate(**_arguments())
    assert result["decision"] == "EVALUATOR_VALIDATED_RESEARCH_ONLY"
    assert seen["required_paths"] == module.AUTHORITATIVE_IMPLEMENTATION_PATHS


def test_missing_engine_receipts_suppresses_statistical_analysis(monkeypatch) -> None:
    _install_valid_composition(monkeypatch)
    called = False

    def statistical(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("statistical gate must not run")

    monkeypatch.setattr(module, "prevalidation_gate", statistical)
    monkeypatch.setattr(
        module,
        "audit_engine_evidence",
        lambda *_args, **_kwargs: {
            "evidence_complete": False,
            "local_feature_extraction": False,
        },
    )
    result = module.evidence_bound_prevalidation_gate(**_arguments())
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert result["reason"] == "engine_evidence_invalid_or_infeasible"
    assert called is False
    assert "statistical_prevalidation" not in result


def test_future_cutoff_is_rejected_before_hosted_analysis(monkeypatch) -> None:
    _install_valid_composition(monkeypatch)
    monkeypatch.setattr(
        module,
        "_now_utc",
        lambda: module._parse_utc("2026-07-14T00:00:00.000000Z"),
    )
    result = module.evidence_bound_prevalidation_gate(**_arguments())
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert result["reason"] == "evaluation_cutoff_invalid"


def test_malformed_implementation_fails_before_other_evidence() -> None:
    result = module.evidence_bound_prevalidation_gate(**_arguments())
    assert result["decision"] == "NO_SUBMIT_INTEGRITY"
    assert result["reason"] == "implementation_or_campaign_binding_invalid"
    assert result["submission_authorized"] is False
