"""Shared fail-closed primitives for Evaluation v6.3.1."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from evaluation_v6_3.common import (  # re-export the reviewed canonical layer
    SIGNATURE_SCHEMA,
    V63Error,
    canonical_base64,
    canonical_integer,
    canonical_json_bytes,
    canonical_sha256,
    canonical_string_list,
    exact,
    fail,
    identifier,
    key_id_for_public_key,
    sha256,
    signing_message,
    utc,
    verify_signature_envelope,
    verify_signature_set,
)


CALIBRATION_BUDGET = 16
PRODUCTION_BUDGET = 1


def freeze(value: Any) -> Any:
    """Recursively freeze validated JSON values."""
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def zero_authority(
    state: str,
    *,
    detail: str,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the sole v6.3.1 result shape available before a live permit."""
    report: dict[str, Any] = {
        "schema": "eval.v6.3.1.zero-authority-verdict",
        "state": state,
        "detail": detail,
        "candidate_policy_structurally_valid": False,
        "candidate_policy_pinned": False,
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
        "production_slots_remaining": PRODUCTION_BUDGET,
        "sealed_holdout_accessed": False,
    }
    if extra:
        overlap = set(report).intersection(extra)
        if overlap:
            raise ValueError(f"zero-authority extension overlaps protected fields: {sorted(overlap)}")
        report.update(extra)
    return report


__all__ = [
    "CALIBRATION_BUDGET",
    "PRODUCTION_BUDGET",
    "SIGNATURE_SCHEMA",
    "V63Error",
    "canonical_base64",
    "canonical_integer",
    "canonical_json_bytes",
    "canonical_sha256",
    "canonical_string_list",
    "exact",
    "fail",
    "freeze",
    "identifier",
    "key_id_for_public_key",
    "sha256",
    "signing_message",
    "utc",
    "verify_signature_envelope",
    "verify_signature_set",
    "zero_authority",
]
