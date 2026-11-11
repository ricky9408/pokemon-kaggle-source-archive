from __future__ import annotations

from pathlib import Path

from tools.evaluation_v5_1_status import build_status


def test_status_is_presence_only_and_never_authorizes(tmp_path: Path) -> None:
    for relative in (
        "evaluation_v5_1/canonical.py",
        "strategy/evaluation_v5_transfer_retirement_20260714.md",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("evidence-shaped bytes", encoding="ascii")

    result = build_status(tmp_path)

    assert result["decision"] == "NO_SUBMIT_IDENTIFIABILITY"
    assert result["ready_to_freeze"] is False
    assert result["research_gate_open"] is False
    assert result["production_gate_exists"] is False
    assert result["prospective_required_family_count"] == 20
    assert result["prospective_required_games_per_family"] == 200
    assert result["prospective_required_strata"] == 8
    assert result["prospective_mathematical_conformance_implemented"] is False
    assert result["prospective_production_verifier_available"] is False
    assert result["prospective_observed_account_cluster_lower_bound"] == 30
    assert result["prospective_authenticated_independent_family_count"] == 0
    assert result["prospective_missing_verified_family_count"] == 20
    assert result["prospective_population_feasible"] is False
    assert result["paired_evidence_structural_preflight_implemented"] is False
    assert result["paired_evidence_external_verifier_available"] is False
    assert result["paired_evidence_authenticated_unit_count"] == 0
    assert result["paired_evidence_production_ready"] is False
    assert result["submission_budget_feasibility_auditor_implemented"] is False
    assert result["submission_budget_feasibility_decision"] == (
        "INFEASIBLE_WITH_CURRENT_EVIDENCE_AND_AUTHORIZED_SUBMISSION_BUDGET"
    )
    assert result["submission_budget_feasible_before_reserved_final"] is False
    assert result["submission_budget_maximum_self_controlled_family_upper_bound"] == 1
    assert result["submission_budget_required_independent_family_count"] == 20
    assert result["submission_budget_minimum_external_exact_pairs_needed"] == 19
    assert result["submission_budget_authorized_nonfinal_research_submissions"] == 0
    assert result["submission_budget_feasibility_production_authority"] is False
    assert result["owned_pair_development_pilot_implemented"] is False
    assert result["owned_pair_development_hosted_quota_complete"] is False
    assert result["owned_pair_development_authority"] is False
    assert result["owned_pair_predictive_validity_authorized"] is False
    assert result["owned_pair_scientific_transfer_retired"] is True
    assert all(
        item["production_authority"] is False
        for item in result["owned_pair_development_artifacts"].values()
    )
    assert result["legacy_statistics_selector_retired"] is True
    assert result["submission_authorized"] is False
    assert result["sealed_holdout_access_authorized"] is False
    assert all(item["verified"] is False for item in result["external_evidence"].values())


def test_status_does_not_discover_similarly_named_or_sealed_files(tmp_path: Path) -> None:
    decoy = tmp_path / "evaluation_artifacts/evaluation_v5_1/published_validation_extra.envelope.json"
    decoy.parent.mkdir(parents=True)
    decoy.write_text("{}", encoding="ascii")
    sealed = tmp_path / "sealed_50/holdout.json"
    sealed.parent.mkdir(parents=True)
    sealed.write_text("do not read", encoding="ascii")

    result = build_status(tmp_path)

    assert result["external_evidence"]["published_validation"]["present_unverified"] is False
    assert result["sealed_holdout_access_authorized"] is False
