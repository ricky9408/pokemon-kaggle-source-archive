"""Zero-authority bridge from offline trace features to exact statistics.

The archive and component fields in :class:`OfflineExactLocalMetadata` are
caller claims.  This module does not authenticate them, derive a campaign
root, issue a permit, access a holdout, or authorize an upload.  Its only
output is the exact-statistics conformance type ``ExactLocalUnit``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from . import exact_statistics
from . import trace_bootstrap
from . import trace_features
from .assignment import FeaturePoint as AssignmentFeaturePoint
from .assignment import ExactRational as AssignmentExactRational
from .trace_features import FEATURE_KEYS, FEATURE_RESULT_SCHEMA, OfflineTraceFeatureResult


BRIDGE_SCHEMA = "eval.v6.3.1.offline-exact-bridge.v1"
OFFLINE_CONFORMANCE_ONLY = True
METADATA_AUTHENTICATED = False
AUTHORITY = False


class ExactBridgeError(ValueError):
    """A bridge input failed closed before an exact local unit was produced."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> ExactBridgeError:
    return ExactBridgeError(code, message)


@dataclass(frozen=True, slots=True)
class OfflineExactLocalMetadata:
    """Explicit, untrusted metadata required to label one local unit.

    ``phase`` is deliberately required so an endpoint cannot be attached to a
    unit unless the caller explicitly identifies it as DEV.  The two boolean
    fields make the trust boundary visible and are fixed to their only
    permitted values by ``__post_init__``.
    """

    slot_id: str
    archive_sha256: str
    source_component_id: str
    lineage_time_component_id: str
    development_control_component_id: str
    intervention_component_id: str
    transcript_root_sha256: str
    extractor_root_sha256: str
    local_feature_root_sha256: str
    local_panel_root_sha256: str
    model_root_sha256: str
    phase: Literal["DEV", "CONFIRM"]
    offline_conformance_only: bool = OFFLINE_CONFORMANCE_ONLY
    metadata_authenticated: bool = METADATA_AUTHENTICATED
    authority: bool = AUTHORITY

    def __post_init__(self) -> None:
        if self.phase not in ("DEV", "CONFIRM"):
            raise _fail("BRIDGE_PHASE_INVALID", "phase must be explicitly DEV or CONFIRM")
        if self.offline_conformance_only is not True:
            raise _fail("BRIDGE_AUTHORITY_METADATA_INVALID", "bridge metadata must be offline-conformance-only")
        if self.metadata_authenticated is not False or self.authority is not False:
            raise _fail("BRIDGE_AUTHORITY_METADATA_INVALID", "caller metadata cannot claim authentication or authority")


def _rethrow(code: str, message: str) -> ExactBridgeError:
    return ExactBridgeError(code, message)


def _validate_trace_result(result: Any) -> OfflineTraceFeatureResult:
    """Revalidate the full issued result and recompute its exact point.

    ``trace_bootstrap`` owns the detailed row/schema checks.  The private
    helpers are used here so a bridge caller cannot bypass the sufficient-
    statistics consistency check by constructing a dataclass with a copied or
    mutated point.
    """

    if type(result) is not OfflineTraceFeatureResult:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "an OfflineTraceFeatureResult is required")
    try:
        rows, controls = trace_bootstrap._validate_result(result)
        prepared = trace_bootstrap._prepare_controls(
            {control: tuple(row for row in rows if row.control_archive_sha256 == control) for control in controls}
        )
        expected = trace_bootstrap._endpoint_for_selection(
            prepared,
            {control: tuple(range(trace_bootstrap.SEEDS_PER_CONTROL)) for control in controls},
        )
    except Exception as exc:
        if isinstance(exc, ExactBridgeError):
            raise
        raise _rethrow("BRIDGE_TRACE_RESULT_INVALID", "trace feature result failed offline revalidation") from exc

    if result.schema_id != FEATURE_RESULT_SCHEMA or result.offline_conformance_only is not True:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "trace feature result is not the frozen offline schema")
    if expected != result.feature_point:
        raise _fail("BRIDGE_TRACE_POINT_MISMATCH", "trace feature point does not match exact sufficient statistics")

    assignment_point = result.feature_point
    if type(assignment_point) is not AssignmentFeaturePoint:
        raise _fail("BRIDGE_ASSIGNMENT_POINT_INVALID", "assignment.FeaturePoint is required")
    try:
        rebuilt_assignment = AssignmentFeaturePoint.make(assignment_point.features, assignment_point.r)
    except Exception as exc:
        raise _rethrow("BRIDGE_ASSIGNMENT_POINT_INVALID", "assignment.FeaturePoint failed exact revalidation") from exc
    if rebuilt_assignment != assignment_point:
        raise _fail("BRIDGE_ASSIGNMENT_POINT_INVALID", "assignment.FeaturePoint has a divergent exact x or F6")

    expected_mapping = assignment_point.exact_canonical()
    exact_values = result.exact_rationals
    if not isinstance(exact_values, Mapping) or set(exact_values) != set((*FEATURE_KEYS, "x", "R")):
        raise _fail("BRIDGE_EXACT_MAPPING_INVALID", "trace result exact mapping has the wrong keys")
    if any(type(exact_values[name]) is not AssignmentExactRational for name in (*FEATURE_KEYS, "x", "R")):
        raise _fail("BRIDGE_ROUNDED_INPUT_REJECTED", "trace result exact mapping must contain assignment exact rationals")
    actual_mapping = {name: exact_values[name].canonical() for name in (*FEATURE_KEYS, "x", "R")}
    if actual_mapping != expected_mapping:
        raise _fail("BRIDGE_EXACT_MAPPING_INVALID", "trace result exact mapping diverges from assignment.FeaturePoint")
    expected_displays = dict(zip(FEATURE_KEYS, assignment_point.display_features, strict=True))
    if dict(result.features) != expected_displays or result.x != assignment_point.display_x or result.r != assignment_point.display_r:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "trace result display fields are stale or mutated")
    expected_precursors = {
        name: trace_features._exact_mpfr_text(exact_values[name].as_fraction())  # type: ignore[attr-defined]
        for name in (*FEATURE_KEYS, "x", "R")
    }
    if dict(result.pre_serialization_mpfr256) != expected_precursors:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "trace result MPFR precursor fields are stale or mutated")
    if result.mpfr256_projection_sha256 != assignment_point.mpfr256_projection_sha256:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "trace result projection digest is stale or mutated")
    if result.report.get("offline_conformance_only") is not True or result.report.get("trace_authenticity_verified") is not False or result.report.get("official_wrapper_parity_verified") is not False:
        raise _fail("BRIDGE_TRACE_RESULT_INVALID", "trace result report is not explicitly offline-only")
    return result


def bridge_offline_trace_to_exact_local_unit(
    result: OfflineTraceFeatureResult,
    metadata: OfflineExactLocalMetadata,
    *,
    endpoint: exact_statistics.ExactHostedEndpoint | None = None,
) -> exact_statistics.ExactLocalUnit:
    """Convert one revalidated offline trace result into an exact local unit.

    The result contains the only accepted feature source.  Metadata is copied
    as caller-claimed labels, and ``local_game_point_rate`` is always derived
    from the exact ``R`` value; there is intentionally no rate parameter.
    """

    if type(metadata) is not OfflineExactLocalMetadata:
        raise _fail("BRIDGE_METADATA_INVALID", "OfflineExactLocalMetadata is required")
    _validate_trace_result(result)
    if metadata.model_root_sha256 == exact_statistics.RETIRED_LEGACY_MODEL_ROOT_SHA256:
        raise _fail("BRIDGE_MODEL_ROOT_RETIRED", "the retired statistics model root is forbidden")
    if metadata.model_root_sha256 != exact_statistics.CANDIDATE_EXACT_MODEL_ROOT_SHA256:
        raise _fail("BRIDGE_MODEL_ROOT_MISMATCH", "metadata model root is not the candidate exact-statistics root")
    if endpoint is not None:
        if metadata.phase != "DEV":
            raise _fail("BRIDGE_ENDPOINT_PHASE_INVALID", "hosted endpoints may be supplied only for explicit DEV metadata")
        if type(endpoint) is not exact_statistics.ExactHostedEndpoint:
            raise _fail("BRIDGE_ENDPOINT_INVALID", "endpoint must be an exact ExactHostedEndpoint")
        if endpoint.slot_id != metadata.slot_id:
            raise _fail("BRIDGE_ENDPOINT_INVALID", "hosted endpoint slot does not match metadata")
    assignment_point = result.feature_point
    exact_mapping = assignment_point.exact_canonical()
    try:
        point = exact_statistics.FeaturePoint.from_exact_mapping(exact_mapping)
        rate = exact_statistics.exact_divide(
            exact_statistics.exact_add(point.r, exact_statistics.ExactRational.from_integers(1)),
            exact_statistics.ExactRational.from_integers(2),
        )
        return exact_statistics.ExactLocalUnit(
            metadata.slot_id,
            metadata.archive_sha256,
            metadata.source_component_id,
            metadata.lineage_time_component_id,
            metadata.development_control_component_id,
            metadata.intervention_component_id,
            point,
            rate,
            metadata.transcript_root_sha256,
            metadata.extractor_root_sha256,
            metadata.local_feature_root_sha256,
            metadata.local_panel_root_sha256,
            metadata.model_root_sha256,
            endpoint,
        )
    except exact_statistics.ExactStatisticsError as exc:
        raise _rethrow("BRIDGE_EXACT_CONVERSION_INVALID", "exact-statistics conversion failed closed") from exc


__all__ = [
    "AUTHORITY",
    "BRIDGE_SCHEMA",
    "METADATA_AUTHENTICATED",
    "OFFLINE_CONFORMANCE_ONLY",
    "ExactBridgeError",
    "OfflineExactLocalMetadata",
    "bridge_offline_trace_to_exact_local_unit",
]
