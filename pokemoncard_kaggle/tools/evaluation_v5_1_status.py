#!/usr/bin/env python3
"""Read-only status for the authority-free v5.1 evidence pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
from typing import Any


SCHEMA = "evaluation_v5_1_status_v1"
PROTOCOL_ID = "MCI_FAMILY_TRANSFER_V2"

LOCAL_FILES = (
    "evaluation_v5_1/canonical.py",
    "evaluation_v5_1/envelope.py",
    "evaluation_v5_1/exact_gate.py",
    "evaluation_v5_1/exact_gate_v2.py",
    "evaluation_v5_1/governance.py",
    "evaluation_v5_1/engine_capability.py",
    "evaluation_v5_1/development_evidence.py",
    "evaluation_v5_1/rebuild_custody.py",
    "evaluation_v5_1/claim_freeze.py",
    "evaluation_v5_1/blind_activation.py",
    "evaluation_v5_1/scenario_evidence.py",
    "evaluation_v5_1/cross_engine.py",
    "evaluation_v5_1/hosted_dev_custody.py",
    "evaluation_v5_1/recruitment.py",
    "evaluation_v5_1/host_census.py",
    "evaluation_v5_1/statistics.py",
    "evaluation_v5_1/prospective_transfer.py",
    "evaluation_v5_1/paired_evidence_preflight.py",
    "evaluation_v5_1/owned_pair_pilot.py",
    "evaluation_v5_1/feasibility.py",
    "evaluation_v5_1/feasibility_constraints_current.json",
    "evaluation_v5_1/blind_release.py",
    "evaluation_v5_1/production_candidate.py",
    "evaluation_v5_1/production_release.py",
    "evaluation_v5_1/recursive_verifier.py",
    "evaluation_v5_1/gate_dag.py",
    "tools/evaluation_v5_1_population_readiness.py",
    "tools/owned_pair_pilot_artifacts.py",
    "tools/evaluation_v5_1_feasibility.py",
    "strategy/evaluation_v5_transfer_retirement_20260714.md",
    "strategy/evaluation_v5_1_remediation_contract_20260714.md",
    "strategy/evaluation_v5_1_sol_missing_gate_spec_20260714.md",
    "strategy/evaluation_v5_1_sol_exact_gate_v2_20260714.md",
    "strategy/evaluation_v5_1_sol_exact_gate_v2_foundation_audit_20260714.md",
    "strategy/evaluation_v5_1_sol_production_gates_g12_g15_20260714.md",
    "strategy/evaluation_v5_1_sol_scientific_feasibility_20260714.md",
    "strategy/evaluation_v5_1_sol_objective_compatibility_20260714.md",
    "strategy/evaluation_v5_1_g11_adversarial_closure_20260714.md",
    "strategy/evaluation_v5_1_gate_inventory_20260714.md",
    "strategy/evaluation_v5_1_population_readiness_20260714.md",
)

DEVELOPMENT_ARTIFACT_FILES = {
    "owned_pair_design": "evaluation_artifacts/prospective_pair_v160_v161/design_v1.json",
    "owned_pair_local_result": "evaluation_artifacts/prospective_pair_v160_v161/local_result_v1.json",
    "owned_pair_activation": "evaluation_artifacts/prospective_pair_v160_v161/activation_v1.json",
    "owned_pair_baseline_inventory": "evaluation_artifacts/prospective_pair_v160_v161/baseline_inventory_v1.json",
    "owned_pair_future_inventory_latest": "evaluation_artifacts/prospective_pair_v160_v161/future_inventory_latest.json",
    "owned_pair_hosted_result": "evaluation_artifacts/prospective_pair_v160_v161/hosted_result_v1.json",
}

EXTERNAL_FILES = {
    "trust_roots": "evaluation_artifacts/evaluation_v5_1/trust_roots.json",
    "v2_offline_root_genesis": "evaluation_artifacts/evaluation_v5_1/v2_campaign_genesis.envelope.json",
    "v2_registry_chain": "evaluation_artifacts/evaluation_v5_1/v2_registry_chain.json",
    "v2_evaluation_registration": "evaluation_artifacts/evaluation_v5_1/v2_evaluation_registration.envelope.json",
    "v2_registry_current_tip": "evaluation_artifacts/evaluation_v5_1/v2_registry_current_tip.envelope.json",
    "v2_replay_service_receipt": "evaluation_artifacts/evaluation_v5_1/v2_replay_service_receipt.envelope.json",
    "constitution_freeze": "evaluation_artifacts/evaluation_v5_1/constitution.envelope.json",
    "rfc3161_study_root": "evaluation_artifacts/evaluation_v5_1/study_root.tsr",
    "source_event_capability": "evaluation_artifacts/evaluation_v5_1/source_event_capability.envelope.json",
    "wrapper_event_capability": "evaluation_artifacts/evaluation_v5_1/wrapper_event_capability.envelope.json",
    "cross_engine_observational_contract": "evaluation_artifacts/evaluation_v5_1/cross_engine_contract.envelope.json",
    "cross_engine_measurement_receipt": "evaluation_artifacts/evaluation_v5_1/cross_engine_measurement.envelope.json",
    "verified_mpfr_256_rndu_receipt": "evaluation_artifacts/evaluation_v5_1/mpfr_256_rndu.envelope.json",
    "g05_dual_signed_query_spec": "evaluation_artifacts/evaluation_v5_1/g05_spec.dual_envelope.json",
    "g05_collector_a_manifest": "evaluation_artifacts/evaluation_v5_1/g05_collector_a.envelope.json",
    "g05_collector_b_manifest": "evaluation_artifacts/evaluation_v5_1/g05_collector_b.envelope.json",
    "g05_collector_a_universe": "evaluation_artifacts/evaluation_v5_1/g05_collector_a_universe.json",
    "g05_collector_b_universe": "evaluation_artifacts/evaluation_v5_1/g05_collector_b_universe.json",
    "g05_evidence_custodian_root": "evaluation_artifacts/evaluation_v5_1/g05_evidence_root.envelope.json",
    "g05_trace_attestor_root": "evaluation_artifacts/evaluation_v5_1/g05_trace_root.envelope.json",
    "g05_evaluation_authority_final": "evaluation_artifacts/evaluation_v5_1/g05_final_authority.envelope.json",
    "g05_validator_audit": "evaluation_artifacts/evaluation_v5_1/g05_validator_audit.envelope.json",
    "signed_dev_fit_host_a": "evaluation_artifacts/evaluation_v5_1/dev_fit_host_a.envelope.json",
    "signed_dev_fit_host_b": "evaluation_artifacts/evaluation_v5_1/dev_fit_host_b.envelope.json",
    "claim_validator_freeze": "evaluation_artifacts/evaluation_v5_1/claim_validator_freeze.envelope.json",
    "signed_recruitment_plan": "evaluation_artifacts/evaluation_v5_1/recruitment_plan.envelope.json",
    "closed_intake": "evaluation_artifacts/evaluation_v5_1/intake_closure.envelope.json",
    "commit_reveal_selection": "evaluation_artifacts/evaluation_v5_1/selection_receipt.envelope.json",
    "transitive_ancestry": "evaluation_artifacts/evaluation_v5_1/ancestry_dag.envelope.json",
    "blind_activation": "evaluation_artifacts/evaluation_v5_1/blind_activation.envelope.json",
    "collector_a_stable_close": "evaluation_artifacts/evaluation_v5_1/collector_a_close.envelope.json",
    "collector_b_stable_close": "evaluation_artifacts/evaluation_v5_1/collector_b_close.envelope.json",
    "collector_reconciliation": "evaluation_artifacts/evaluation_v5_1/collector_reconciliation.envelope.json",
    "release_quorum": "evaluation_artifacts/evaluation_v5_1/release_quorum.envelope.json",
    "published_validation": "evaluation_artifacts/evaluation_v5_1/published_validation.envelope.json",
    "g12_evaluator_unseal": "evaluation_artifacts/evaluation_v5_1/g12_evaluator_unseal.envelope.json",
    "g13_candidate_freeze": "evaluation_artifacts/evaluation_v5_1/g13_candidate_freeze.envelope.json",
    "g14_runtime_holdout": "evaluation_artifacts/evaluation_v5_1/g14_runtime_holdout.envelope.json",
    "g15_release_authorization": "evaluation_artifacts/evaluation_v5_1/g15_release_authorization.envelope.json",
    "g15_submission_history_baseline": "evaluation_artifacts/evaluation_v5_1/g15_submission_history_baseline.envelope.json",
    "prospective_selector_freeze": "evaluation_artifacts/evaluation_v5_1/prospective_selector_freeze.envelope.json",
    "prospective_ancestry_cohort": "evaluation_artifacts/evaluation_v5_1/prospective_ancestry_cohort.envelope.json",
    "prospective_future_public_panel": "evaluation_artifacts/evaluation_v5_1/prospective_future_public_panel.envelope.json",
    "prospective_transfer_result": "evaluation_artifacts/evaluation_v5_1/prospective_transfer_result.envelope.json",
}

_FORBIDDEN_PARTS = frozenset({"holdout", "sealed", "sealed_50", "sealed-holdout"})


def _digest_regular_file(root: Path, relative: str) -> str | None:
    path = root / relative
    if any(part.lower() in _FORBIDDEN_PARTS for part in path.parts):
        raise ValueError("status configuration references a forbidden sealed path")
    try:
        if path.is_symlink():
            return None
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
        info = resolved.stat()
    except (OSError, RuntimeError, ValueError):
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def build_status(root: Path) -> dict[str, Any]:
    """Report presence only; never treat file presence as verified evidence."""

    local = {
        relative: {
            "present": (digest := _digest_regular_file(root, relative)) is not None,
            "sha256": digest,
        }
        for relative in LOCAL_FILES
    }
    external = {
        name: {
            "path": relative,
            "present_unverified": (digest := _digest_regular_file(root, relative)) is not None,
            "sha256": digest,
            "verified": False,
        }
        for name, relative in EXTERNAL_FILES.items()
    }
    development_artifacts = {
        name: {
            "path": relative,
            "present_unverified": (digest := _digest_regular_file(root, relative)) is not None,
            "sha256": digest,
            "production_authority": False,
        }
        for name, relative in DEVELOPMENT_ARTIFACT_FILES.items()
    }
    missing_local = sorted(path for path, item in local.items() if not item["present"])
    missing_external = sorted(name for name, item in external.items() if not item["present_unverified"])
    return {
        "schema": SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "ready_to_freeze": False,
        "research_gate_open": False,
        "production_gate_exists": False,
        "prospective_required_family_count": 20,
        "prospective_required_games_per_family": 200,
        "prospective_required_strata": 8,
        "prospective_mathematical_conformance_implemented": local[
            "evaluation_v5_1/prospective_transfer.py"
        ]["present"],
        "prospective_production_verifier_available": False,
        "prospective_observed_account_cluster_lower_bound": 30,
        "prospective_authenticated_independent_family_count": 0,
        "prospective_missing_verified_family_count": 20,
        "prospective_population_feasible": False,
        "paired_evidence_structural_preflight_implemented": local[
            "evaluation_v5_1/paired_evidence_preflight.py"
        ]["present"],
        "paired_evidence_external_verifier_available": False,
        "paired_evidence_authenticated_unit_count": 0,
        "paired_evidence_production_ready": False,
        "submission_budget_feasibility_auditor_implemented": all(
            local[path]["present"]
            for path in (
                "evaluation_v5_1/feasibility.py",
                "evaluation_v5_1/feasibility_constraints_current.json",
                "tools/evaluation_v5_1_feasibility.py",
            )
        ),
        "submission_budget_feasibility_decision": (
            "INFEASIBLE_WITH_CURRENT_EVIDENCE_AND_AUTHORIZED_SUBMISSION_BUDGET"
        ),
        "submission_budget_feasible_before_reserved_final": False,
        "submission_budget_maximum_self_controlled_family_upper_bound": 1,
        "submission_budget_required_independent_family_count": 20,
        "submission_budget_minimum_external_exact_pairs_needed": 19,
        "submission_budget_authorized_nonfinal_research_submissions": 0,
        "submission_budget_feasibility_production_authority": False,
        "owned_pair_development_pilot_implemented": (
            local["evaluation_v5_1/owned_pair_pilot.py"]["present"]
            and local["tools/owned_pair_pilot_artifacts.py"]["present"]
        ),
        "owned_pair_development_artifacts": development_artifacts,
        "owned_pair_development_hosted_quota_complete": False,
        "owned_pair_development_authority": False,
        "owned_pair_predictive_validity_authorized": False,
        "owned_pair_scientific_transfer_retired": True,
        "legacy_statistics_selector_retired": True,
        "exact_gate_v1_retired": True,
        "exact_gate_v2_verifier_allowlist_count": 0,
        "decision": "NO_SUBMIT_IDENTIFIABILITY",
        "local_implementation": local,
        "external_evidence": external,
        "missing_local_components": missing_local,
        "missing_external_components": missing_external,
        "notes": [
            "file presence is not evidence verification",
            "external independence cannot be self-attested by this process",
            "the exact confirmatory design requires 20 families and one archive per family",
            "the host target is interface-observable first48, not backend-complete first48",
            "retrospective DEV can train or debug but can never validate transfer",
            "G04 cannot pass without a pinned verified MPFR-256 RNDU backend",
            "G05 cannot pass without a dual-signed query spec, two complete terminal-cursor TLS/API captures, exact universe agreement, zero-orphan custody, an evaluation-authority-signed final audit, and a validator countersignature over that exact authority envelope",
            "exact-gate v1 is permanently retired because caller-controlled roots and recomputed outputs could form a signed fiction",
            "exact-gate v2 has an empty hermetic verifier allowlist; no G00-G15 pass is currently possible",
            "the local SQLite replay helper is quarantined and cannot occupy an authoritative slot",
            "v2 still requires raw offline-root governance, prospective evaluation registration, recursive dependency verification, a trusted valid-only replay service, hermetic module execution, and independent validator execution",
            "G12-G15 local protocol code is research-only; authentic unseal, candidate, holdout, release, history-baseline, and capability-service receipts remain mandatory",
            "Sol's scientific review makes the 20-lineage future-time-split test load-bearing; exact-gate integrity and local episode count carry no predictive weight",
            "Sol's objective-compatibility correction requires exact archive-level pairs: frozen local output L(A) plus strictly prospective hosted outcome H+(A) for that same archive",
            "the paired-evidence preflight validates structural fixture shape only; caller-supplied roles and receipt hashes cannot authenticate evidence or open G11",
            "the submission-budget feasibility auditor is negative-authority only: under the one-final-submission reservation, the maximum self-controlled family upper bound is one versus twenty required, so nineteen independently authenticated external exact pairs or nineteen authorized nonfinal independent submissions are still needed",
            "the owned-pair pilot binds exact v160/v161 archives, deterministic repeated local cells, and a post-T0 authenticated metadata baseline, but remains a two-unit common-ancestry single-collector development rehearsal with zero production authority",
            "the owned-pair v1 scientific transfer claim is retired because it froze no operational estimand, T1/censoring rule, matched hosted exposure rule, uncertainty procedure, or pre-T0 analysis lock; append-only collection remains DEV observation only",
            "future hosted episode IDs are derived after T0 from authenticated exhaustive collectors and are never frozen from post-outcome observations",
            "prospective_transfer.py freezes the mathematics for 200 future hosted games per lineage as 25 games in each of four opponent-score bins crossed with two seats, then requires all four transfer criteria conjunctively",
            "the prospective production entry hard-closes until independently pinned freeze, exhaustive dual-collector, and signed disclosure services exist; caller-supplied hashes and booleans cannot validate G11",
            "statistics.py is retained only for legacy research reproducibility and is not the load-bearing G11 selector",
            "the complete current top-30 scout proves 30 observed account clusters and 60 active-submission rows, but no authenticated archive-level L(A)/H+(A) pair; account, deck, policy, archive, and semantic similarity cannot substitute",
            "the public recursive verifier hard-closes caller-supplied trust services; only an explicitly synthetic conformance path accepts test doubles",
            "the sealed 50-game holdout was not inspected by this command",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = build_status(args.repo_root.resolve())
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
