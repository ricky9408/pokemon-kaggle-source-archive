"""Retired v6.2.4 population-release route.

GPT-5.6 Sol rejected this version's release-root and transparency boundaries.
The module remains importable only so historical tools fail closed with a
stable result. It cannot validate a root, open recruitment, issue a permit,
access the sealed holdout, or authorize any upload.
"""

from __future__ import annotations

from typing import Any


RELEASE_ROOT_SCHEMA = "eval.v6.2.4.recruitment-release-root"
RELEASE_PACKET_SCHEMA = "eval.v6.2.4.population-release-packet"
VERDICT_SCHEMA = "eval.v6.2.4.population-trust-verdict"
RECRUITMENT_RELEASE_ROOT_ALLOWLIST: frozenset[str] = frozenset()


class ReleaseV624Error(ValueError):
    """The v6.2.4 route is retired and cannot grant authority."""


def _retired() -> ReleaseV624Error:
    return ReleaseV624Error(
        "evaluation v6.2.4 is retired after binding adversarial rejection; "
        "use the separately reviewed v6.2.5-or-later path"
    )


def validate_release_root(value: Any, **_: Any) -> dict[str, Any]:
    del value
    raise _retired()


def verify_population_release_files(**_: Any) -> dict[str, Any]:
    raise _retired()


def assess_population_release_files(**_: Any) -> dict[str, Any]:
    return {
        "schema": VERDICT_SCHEMA,
        "state": "POPULATION_INFEASIBLE",
        "failure": str(_retired()),
        "external_authentication_verified": False,
        "semantic_artifact_verification_complete": False,
        "independence_adjudicated_under_policy": False,
        "population_feasible": False,
        "independence_ground_truth_proven": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "unit_upload_permits": [],
        "sealed_holdout_accessed": False,
    }


__all__ = [
    "RECRUITMENT_RELEASE_ROOT_ALLOWLIST",
    "RELEASE_PACKET_SCHEMA",
    "RELEASE_ROOT_SCHEMA",
    "ReleaseV624Error",
    "VERDICT_SCHEMA",
    "assess_population_release_files",
    "validate_release_root",
    "verify_population_release_files",
]
