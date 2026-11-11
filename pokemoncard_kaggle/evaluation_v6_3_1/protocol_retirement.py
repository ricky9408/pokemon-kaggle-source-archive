"""Fail-closed admission boundary for superseded Package 3A artifacts.

The module intentionally provides no converter, wrapper, rehasher, or
compatibility decoder.  It can admit an already-current 631302 record set past
the version/format boundary, or reject the entire set.  Downstream schema and
semantic verification remain mandatory.  Admission never grants a
permit, campaign authority, holdout access, agent-modification authority, or
upload authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Iterable, Mapping

from .unified_rng_protocol import (
    AUTHORITY,
    PROTOCOL_VERSION,
    RETIRED_PROTOCOL_VERSION,
    UnifiedRngProtocolError,
    canonical_cbor_decode,
)


CURRENT_TRACE_FORMAT: Final = "concatenated-canonical-cbor-v631302"
LEGACY_TRACE_FORMATS: Final = frozenset({"full-trace-v1", "branch-trace-v2"})
FORBIDDEN_MIGRATION_OPERATIONS: Final = frozenset(
    {"translate", "wrap", "rehash", "parent-root", "compatibility-parse"}
)


class ProtocolRetirementError(UnifiedRngProtocolError):
    """A superseded or mixed Package 3A artifact failed admission."""


def _fail(code: str, message: str) -> ProtocolRetirementError:
    return ProtocolRetirementError(code, message)


def _record_version(record: bytes | list[Any]) -> int:
    if type(record) is bytes:
        try:
            value = canonical_cbor_decode(record)
        except UnifiedRngProtocolError as exc:
            raise _fail(exc.code, str(exc)) from exc
    elif type(record) is list:
        value = record
    else:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "protocol records must be canonical CBOR bytes or arrays",
        )
    if not value or type(value[0]) is not int:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "protocol record has no unsigned version field",
        )
    return value[0]


@dataclass(frozen=True, slots=True)
class ProtocolAdmission:
    """Immutable zero-authority result for a wholly current record set."""

    protocol_version: int
    trace_format: str
    record_count: int
    state: str = "CURRENT_VERSION_ONLY_REQUIRES_SCHEMA_VERIFICATION"
    authority: str = AUTHORITY
    calibration_upload_authorized: bool = False
    production_upload_authorized: bool = False
    sealed_holdout_access_authorized: bool = False
    agent_modification_authorized: bool = False
    permits: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.protocol_version != PROTOCOL_VERSION
            or self.trace_format != CURRENT_TRACE_FORMAT
            or type(self.record_count) is not int
            or self.record_count < 1
            or self.state != "CURRENT_VERSION_ONLY_REQUIRES_SCHEMA_VERIFICATION"
            or self.authority != AUTHORITY
            or self.calibration_upload_authorized
            or self.production_upload_authorized
            or self.sealed_holdout_access_authorized
            or self.agent_modification_authorized
            or self.permits
        ):
            raise _fail(
                "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
                "protocol admission must remain current and zero-authority",
            )

    def as_dict(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "protocol_version": self.protocol_version,
                "trace_format": self.trace_format,
                "record_count": self.record_count,
                "state": self.state,
                "authority": self.authority,
                "calibration_upload_authorized": False,
                "production_upload_authorized": False,
                "sealed_holdout_access_authorized": False,
                "agent_modification_authorized": False,
                "permits": (),
            }
        )


def admit_current_protocol_records(
    records: Iterable[bytes | list[Any]],
    *,
    trace_format: str,
) -> ProtocolAdmission:
    """Admit only an unmigrated, single-version 631302 record collection."""

    if type(trace_format) is not str:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "trace format must be the literal current format name",
        )
    if trace_format in LEGACY_TRACE_FORMATS:
        raise _fail(
            "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
            f"legacy trace format {trace_format!r} cannot enter 631302",
        )
    if trace_format != CURRENT_TRACE_FORMAT:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "unknown trace format cannot enter 631302",
        )
    materialized = tuple(records)
    if not materialized:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "protocol record collection cannot be empty",
        )
    versions = {_record_version(record) for record in materialized}
    if len(versions) > 1:
        raise _fail(
            "RNG_MIXED_PROTOCOL_SESSION",
            "record collection mixes protocol versions",
        )
    version = next(iter(versions))
    if version == RETIRED_PROTOCOL_VERSION:
        raise _fail(
            "RNG_PROTOCOL_631301_RETIRED",
            "631301 artifacts are SUPERSEDED_NONAUTHORITATIVE",
        )
    if version != PROTOCOL_VERSION:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "record collection uses an unsupported protocol version",
        )
    return ProtocolAdmission(PROTOCOL_VERSION, CURRENT_TRACE_FORMAT, len(materialized))


def reject_legacy_migration(operation: str, source_trace_format: str) -> None:
    """Reject every prohibited attempt to migrate a legacy artifact."""

    if operation in FORBIDDEN_MIGRATION_OPERATIONS or source_trace_format in LEGACY_TRACE_FORMATS:
        raise _fail(
            "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
            "legacy Package 3A artifacts cannot be translated, wrapped, rehashed, parented, or compatibility-parsed",
        )
    raise _fail(
        "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
        "migration operation is not part of the current protocol",
    )


def require_current_parent_protocol(parent_protocol_version: int) -> None:
    """Prevent a superseded artifact from entering a 631302 parent root."""

    if parent_protocol_version == RETIRED_PROTOCOL_VERSION:
        raise _fail(
            "RNG_LEGACY_TRACE_TRANSLATION_ATTEMPTED",
            "631301 artifacts cannot be used as a parent root",
        )
    if parent_protocol_version != PROTOCOL_VERSION:
        raise _fail(
            "RNG_EVENT_ENVELOPE_VERSION_MISMATCH",
            "parent root uses an unsupported protocol version",
        )


__all__ = [
    "CURRENT_TRACE_FORMAT",
    "FORBIDDEN_MIGRATION_OPERATIONS",
    "LEGACY_TRACE_FORMATS",
    "ProtocolAdmission",
    "ProtocolRetirementError",
    "admit_current_protocol_records",
    "reject_legacy_migration",
    "require_current_parent_protocol",
]
