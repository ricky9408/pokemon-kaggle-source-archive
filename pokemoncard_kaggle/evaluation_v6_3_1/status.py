"""Read-only, fail-closed status for Evaluation v6.3.1.

The v6.3.1 policy pin is a release-controlled constant.  While it is the
literal value ``None``, status is intentionally independent of all campaign,
population, and evidence inputs.  In particular, no caller input can turn
this module into an evidence loader or an authority source.
"""

from __future__ import annotations

from . import policy


STATUS_SCHEMA = "eval.v6.3.1.status"
CALIBRATION_BUDGET = 16
PRODUCTION_RESERVE = 1


def compose_status(
) -> dict[str, object]:
    """Compose the current status without any caller-controlled inputs."""
    if policy.PINNED_V631_POLICY is not None:  # pragma: no cover - release guard
        raise RuntimeError("v6.3.1 status cannot run with a locally activated policy")

    return {
        "schema": STATUS_SCHEMA,
        "state": "POPULATION_INFEASIBLE",
        "detail": "PINNED_V631_POLICY is None; campaign inputs are not read and no authority exists.",
        "candidate_policy_structurally_valid": False,
        "candidate_policy_pinned": False,
        "policy_pin_present": False,
        "policy_pin_sha256": None,
        "external_roster_authenticated": False,
        "population_semantically_closed": False,
        "local_evidence_frozen": False,
        "assignment_frozen": False,
        "preregistration_published": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
        "calibration_slots_remaining": CALIBRATION_BUDGET,
        "production_slots_remaining": PRODUCTION_RESERVE,
        "sealed_holdout_accessed": False,
    }


__all__ = ["CALIBRATION_BUDGET", "PRODUCTION_RESERVE", "STATUS_SCHEMA", "compose_status"]
