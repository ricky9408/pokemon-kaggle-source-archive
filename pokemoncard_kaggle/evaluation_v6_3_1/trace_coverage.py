"""Offline source coverage contract for the v6.3.1 trace derivative.

This module models the seven build-time coverage manifests required by the
canonical engine trace architecture.  It does not scan source, attest a
reviewer, build an executable, issue a permit, open the holdout, or authorize
any campaign action.  A valid result is therefore only a structural,
zero-authority offline contract.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256


TRACE_COVERAGE_SCHEMA = "eval.v6.3.1.trace-coverage-manifest.v1"
TRACE_COVERAGE_MODE = "TEST_ONLY/OFFLINE_STATIC_CONTRACT"

SEMANTIC_FIELD_MANIFEST = "semantic_field_manifest"
MUTATION_SITE_MANIFEST = "mutation_site_manifest"
RNG_SITE_MANIFEST = "rng_site_manifest"
SELECTION_SITE_MANIFEST = "selection_site_manifest"
IPC_SITE_MANIFEST = "ipc_site_manifest"
TERMINAL_SITE_MANIFEST = "terminal_site_manifest"
TRACE_HOOK_MANIFEST = "trace_hook_manifest"

REQUIRED_MANIFEST_FAMILIES = (
    SEMANTIC_FIELD_MANIFEST,
    MUTATION_SITE_MANIFEST,
    RNG_SITE_MANIFEST,
    SELECTION_SITE_MANIFEST,
    IPC_SITE_MANIFEST,
    TERMINAL_SITE_MANIFEST,
    TRACE_HOOK_MANIFEST,
)

SEMANTIC_FIELD_CLASSIFICATIONS = frozenset(
    {
        "SEMANTIC_SERIALIZED",
        "DERIVED_RECOMPUTED_AND_VERIFIED",
        "DIAGNOSTIC_NONEXECUTIONAL",
    }
)

FAMILY_CLASSIFICATIONS = {
    SEMANTIC_FIELD_MANIFEST: {
        "STATE_FIELD": SEMANTIC_FIELD_CLASSIFICATIONS,
        "DERIVED_FIELD": SEMANTIC_FIELD_CLASSIFICATIONS,
        "DIAGNOSTIC_FIELD": SEMANTIC_FIELD_CLASSIFICATIONS,
    },
    MUTATION_SITE_MANIFEST: {
        "HP": frozenset({"AUTHORITATIVE_MUTATION"}),
        "ZONE": frozenset({"AUTHORITATIVE_MUTATION"}),
        "CARD": frozenset({"AUTHORITATIVE_MUTATION"}),
        "STATUS": frozenset({"AUTHORITATIVE_MUTATION"}),
        "TURN": frozenset({"AUTHORITATIVE_MUTATION"}),
        "PRIZE": frozenset({"AUTHORITATIVE_MUTATION"}),
        "PROPERTY": frozenset({"AUTHORITATIVE_MUTATION"}),
        "RESULT": frozenset({"AUTHORITATIVE_MUTATION"}),
        "SELECTION": frozenset({"AUTHORITATIVE_MUTATION"}),
    },
    RNG_SITE_MANIFEST: {
        "RNG_CONSTRUCTION": frozenset({"SEEDED_DETERMINISTIC"}),
        "RNG_DRAW": frozenset({"RECORDED_DRAW"}),
        "RNG_PERMUTATION": frozenset({"RECORDED_PERMUTATION"}),
        "RNG_ENTROPY": frozenset({"REJECTED_ENTROPY", "VIRTUALIZED_ENTROPY"}),
    },
    SELECTION_SITE_MANIFEST: {
        "LEGAL_OPTIONS": frozenset({"LEGAL_OPTION_SET"}),
        "SELECTION_STACK": frozenset({"SELECTION_STACK"}),
        "SELECTION_CHOICE": frozenset({"SELECTION_CHOICE"}),
        "ORDERING": frozenset({"ORDERED_SELECTION"}),
    },
    IPC_SITE_MANIFEST: {
        "AGENT_REQUEST": frozenset({"AGENT_IPC"}),
        "AGENT_RESPONSE": frozenset({"AGENT_IPC"}),
        "TIMEOUT": frozenset({"AGENT_IPC"}),
        "INVALID_ACTION": frozenset({"AGENT_IPC"}),
    },
    TERMINAL_SITE_MANIFEST: {
        "TERMINAL_STATE": frozenset({"TERMINAL_TRANSITION"}),
        "TERMINAL_RESULT": frozenset({"TERMINAL_TRANSITION"}),
        "TRACE_CLOSE": frozenset({"TERMINAL_TRANSITION"}),
        "AGENT_FAILURE": frozenset({"TERMINAL_TRANSITION"}),
    },
    TRACE_HOOK_MANIFEST: {
        "MUTATION": frozenset({"MUTATION_HOOK"}),
        "RNG": frozenset({"RNG_HOOK"}),
        "SELECTION": frozenset({"SELECTION_HOOK"}),
        "IPC": frozenset({"IPC_HOOK"}),
        "TERMINAL": frozenset({"TERMINAL_HOOK"}),
        "CHECKPOINT": frozenset({"CHECKPOINT_HOOK"}),
        "TRANSACTION": frozenset({"TRANSACTION_HOOK"}),
    },
}

ENTRY_FIELDS = frozenset(
    {
        "source_root_sha256",
        "canonical_relative_path",
        "stable_site_id",
        "family",
        "classification",
        "authorized_primitive_id",
        "trace_hook_id",
        "classification_a",
        "classification_b",
        "reviewer_a_id",
        "reviewer_b_id",
    }
)

AUTHORITY_FIELDS = frozenset(
    {
        "authority",
        "upload_authorized",
        "calibration_upload_authorized",
        "production_upload_authorized",
        "holdout_access_authorized",
        "sealed_holdout_access_authorized",
        "campaign_authorized",
        "agent_modification_authorized",
        "permits",
    }
)

MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "source_root_sha256",
        "required_site_ids",
        "manifests",
        "coverage_manifest_root_sha256",
        "authority",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

# These are rejected wherever a classification or binding identifier could
# smuggle an inadmissible serialization mechanism into the static contract.
PROHIBITED_SERIALIZATION_TERMS = frozenset(
    {
        "RAW_MEMORY",
        "MEMCPY",
        "MEMMOVE",
        "STRUCT_PADDING",
        "VTABLE",
        "POINTER",
        "OBJECT_HASH",
        "NATIVE_HASH",
        "UNORDERED",
        "LOCALE",
        "LOCALIZED",
        "BINARY_FLOAT",
        "IMPLEMENTATION_DEFINED",
        "UNSTABLE_FILESYSTEM",
        "WALL_CLOCK",
    }
)
_AUTHORITY_KEYS = frozenset(
    {
        "authority",
        "upload_authorized",
        "calibration_upload_authorized",
        "production_upload_authorized",
        "holdout_access_authorized",
        "sealed_holdout_access_authorized",
        "campaign_authorized",
        "agent_modification_authorized",
        "permits",
    }
)


class TraceCoverageError(ValueError):
    """A source coverage contract failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> TraceCoverageError:
    return TraceCoverageError(code, message)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("TRACE_COVERAGE_ROOT_INVALID", f"{label} must be lowercase SHA-256 hex")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or _IDENTIFIER_RE.fullmatch(value) is None:
        raise _fail("TRACE_COVERAGE_ENTRY_INVALID", f"{label} must be a canonical identifier")
    return value


def _source_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\\" in value:
        raise _fail("TRACE_COVERAGE_ENTRY_INVALID", f"{label} must be a canonical relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or _PATH_SEGMENT_RE.fullmatch(part) is None for part in parts):
        raise _fail("TRACE_COVERAGE_ENTRY_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _reject_prohibited_mechanism(value: str, label: str) -> None:
    upper = value.upper().replace("-", "_").replace(" ", "_")
    if upper.startswith(("V631_NO_", "V631_REJECT_", "V631_CANONICAL_", "V631_VIRTUALIZED_")):
        return
    if any(term in upper for term in PROHIBITED_SERIALIZATION_TERMS):
        raise _fail("TRACE_COVERAGE_PROHIBITED_SERIALIZATION", f"{label} uses a prohibited serialization classification")


def _canonical_root(payload: Mapping[str, Any]) -> str:
    try:
        return canonical_sha256(payload)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _fail("TRACE_COVERAGE_CANONICAL_INVALID", "coverage payload is not canonical JSON") from exc


def _authority() -> dict[str, Any]:
    return {
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "campaign_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }


@dataclass(frozen=True, slots=True)
class CoverageEntry:
    """One rooted source site or semantic field classification."""

    source_root_sha256: str
    canonical_relative_path: str
    stable_site_id: str
    family: str
    classification: str
    authorized_primitive_id: str
    trace_hook_id: str
    classification_a: str
    classification_b: str
    reviewer_a_id: str
    reviewer_b_id: str

    def canonical(self) -> dict[str, str]:
        return {
            "source_root_sha256": self.source_root_sha256,
            "canonical_relative_path": self.canonical_relative_path,
            "stable_site_id": self.stable_site_id,
            "family": self.family,
            "classification": self.classification,
            "authorized_primitive_id": self.authorized_primitive_id,
            "trace_hook_id": self.trace_hook_id,
            "classification_a": self.classification_a,
            "classification_b": self.classification_b,
            "reviewer_a_id": self.reviewer_a_id,
            "reviewer_b_id": self.reviewer_b_id,
        }


@dataclass(frozen=True, slots=True)
class CoverageManifest:
    """Validated, immutable, offline-only source coverage."""

    source_root_sha256: str
    required_site_ids: Mapping[str, tuple[str, ...]]
    manifests: Mapping[str, tuple[CoverageEntry, ...]]
    coverage_manifest_root_sha256: str
    authority: Mapping[str, Any]
    schema: str = TRACE_COVERAGE_SCHEMA
    mode: str = TRACE_COVERAGE_MODE

    @property
    def root_sha256(self) -> str:
        return self.coverage_manifest_root_sha256

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "mode": self.mode,
            "source_root_sha256": self.source_root_sha256,
            "required_site_ids": {
                name: list(self.required_site_ids[name]) for name in REQUIRED_MANIFEST_FAMILIES
            },
            "manifests": {
                name: [entry.canonical() for entry in self.manifests[name]]
                for name in REQUIRED_MANIFEST_FAMILIES
            },
            "coverage_manifest_root_sha256": self.coverage_manifest_root_sha256,
            "authority": dict(self.authority),
        }

    def zero_authority_report(self) -> dict[str, Any]:
        """Return the only authority surface this offline tool can produce."""

        return {
            "schema": "eval.v6.3.1.trace-coverage-zero-authority.v1",
            "state": "OFFLINE_STATIC_CONTRACT_VALID",
            "coverage_manifest_root_sha256": self.coverage_manifest_root_sha256,
            "source_root_sha256": self.source_root_sha256,
            **dict(self.authority),
        }

    def as_dict(self) -> dict[str, Any]:
        return self.canonical()


def _entry(value: Any, family_name: str, source_root: str, index: int) -> CoverageEntry:
    if type(value) is not dict or set(value) != ENTRY_FIELDS:
        raise _fail("TRACE_COVERAGE_ENTRY_INVALID", f"{family_name}[{index}] fields are not exact")
    entry_source = _sha(value["source_root_sha256"], f"{family_name}[{index}].source_root_sha256")
    if entry_source != source_root:
        raise _fail("TRACE_COVERAGE_ROOT_STALE", f"{family_name}[{index}] is bound to a stale source root")
    path = _source_path(value["canonical_relative_path"], f"{family_name}[{index}].canonical_relative_path")
    stable_id = _identifier(value["stable_site_id"], f"{family_name}[{index}].stable_site_id")
    entry_family = _identifier(value["family"], f"{family_name}[{index}].family")
    classification = _identifier(value["classification"], f"{family_name}[{index}].classification")
    if any(text.upper() in {"UNKNOWN", "UNCLASSIFIED", "PROHIBITED_UNCLASSIFIED"} for text in (entry_family, classification)):
        raise _fail("TRACE_COVERAGE_UNCLASSIFIED", f"{family_name}[{index}] has an unknown or unclassified label")
    allowed_families = FAMILY_CLASSIFICATIONS[family_name]
    if entry_family not in allowed_families or classification not in allowed_families[entry_family]:
        raise _fail("TRACE_COVERAGE_UNCLASSIFIED", f"{family_name}[{index}] has an unknown or unclassified family")
    primitive = _identifier(value["authorized_primitive_id"], f"{family_name}[{index}].authorized_primitive_id")
    hook = _identifier(value["trace_hook_id"], f"{family_name}[{index}].trace_hook_id")
    if any(text.upper() in {"UNKNOWN", "UNCLASSIFIED", "NONE", "NULL"} for text in (primitive, hook)):
        raise _fail("TRACE_COVERAGE_UNCLASSIFIED", f"{family_name}[{index}] has an unknown primitive or trace hook")
    classification_a = _identifier(value["classification_a"], f"{family_name}[{index}].classification_a")
    classification_b = _identifier(value["classification_b"], f"{family_name}[{index}].classification_b")
    reviewer_a = _identifier(value["reviewer_a_id"], f"{family_name}[{index}].reviewer_a_id")
    reviewer_b = _identifier(value["reviewer_b_id"], f"{family_name}[{index}].reviewer_b_id")
    if classification_a != classification or classification_b != classification:
        raise _fail("TRACE_COVERAGE_REVIEW_DISAGREEMENT", f"{family_name}[{index}] A/B classifications do not match the entry")
    if reviewer_a == reviewer_b:
        raise _fail("TRACE_COVERAGE_REVIEW_NOT_INDEPENDENT", f"{family_name}[{index}] has one reviewer identity")
    for label, text in (
        ("classification", classification),
        ("authorized_primitive_id", primitive),
        ("classification_a", classification_a),
        ("classification_b", classification_b),
    ):
        _reject_prohibited_mechanism(text, f"{family_name}[{index}].{label}")
    return CoverageEntry(
        entry_source,
        path,
        stable_id,
        entry_family,
        classification,
        primitive,
        hook,
        classification_a,
        classification_b,
        reviewer_a,
        reviewer_b,
    )


def _payload_without_root(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value[key]
        for key in ("schema", "mode", "source_root_sha256", "required_site_ids", "manifests", "authority")
    }


def validate_coverage_manifest(
    value: Any,
    *,
    expected_source_root_sha256: str | None = None,
) -> CoverageManifest:
    """Validate a caller-provided manifest without granting authority."""

    if isinstance(value, CoverageManifest):
        return validate_coverage_manifest(value.as_dict(), expected_source_root_sha256=expected_source_root_sha256)
    if type(value) is not dict or set(value) != MANIFEST_FIELDS:
        raise _fail("TRACE_COVERAGE_MANIFEST_INVALID", "coverage manifest fields are not exact")
    if value["schema"] != TRACE_COVERAGE_SCHEMA or value["mode"] != TRACE_COVERAGE_MODE:
        raise _fail("TRACE_COVERAGE_MANIFEST_INVALID", "coverage manifest schema or mode is invalid")
    source_root = _sha(value["source_root_sha256"], "source_root_sha256")
    if expected_source_root_sha256 is not None and _sha(expected_source_root_sha256, "expected_source_root_sha256") != source_root:
        raise _fail("TRACE_COVERAGE_ROOT_STALE", "coverage manifest source root is stale")

    authority = value["authority"]
    if type(authority) is not dict or set(authority) != AUTHORITY_FIELDS:
        raise _fail("TRACE_COVERAGE_AUTHORITY_CLAIM", "authority declaration is not exact")
    expected_authority = _authority()
    if authority != expected_authority:
        raise _fail("TRACE_COVERAGE_AUTHORITY_CLAIM", "coverage manifest cannot claim upload, holdout, campaign, or agent authority")

    required = value["required_site_ids"]
    manifests = value["manifests"]
    if type(required) is not dict or set(required) != set(REQUIRED_MANIFEST_FAMILIES):
        raise _fail("TRACE_COVERAGE_MANIFEST_FAMILY_MISSING", "required site inventory must contain all seven families")
    if type(manifests) is not dict or set(manifests) != set(REQUIRED_MANIFEST_FAMILIES):
        raise _fail("TRACE_COVERAGE_MANIFEST_FAMILY_MISSING", "coverage must contain all seven manifests")

    parsed_required: dict[str, tuple[str, ...]] = {}
    parsed_manifests: dict[str, tuple[CoverageEntry, ...]] = {}
    global_ids: set[str] = set()
    hook_ids: set[str] = set()
    for family_name in REQUIRED_MANIFEST_FAMILIES:
        ids = required[family_name]
        if type(ids) is not list or not ids:
            raise _fail("TRACE_COVERAGE_MANIFEST_FAMILY_MISSING", f"{family_name} has no required site inventory")
        parsed_ids = tuple(_identifier(item, f"required_site_ids.{family_name}") for item in ids)
        if parsed_ids != tuple(sorted(parsed_ids)) or len(set(parsed_ids)) != len(parsed_ids):
            raise _fail("TRACE_COVERAGE_ORDER_INVALID", f"required_site_ids.{family_name} is not sorted and unique")
        rows = manifests[family_name]
        if type(rows) is not list or not rows:
            raise _fail("TRACE_COVERAGE_MANIFEST_FAMILY_MISSING", f"{family_name} is empty")
        parsed_rows = tuple(_entry(row, family_name, source_root, index) for index, row in enumerate(rows))
        row_keys = tuple((row.canonical_relative_path, row.stable_site_id) for row in parsed_rows)
        if row_keys != tuple(sorted(row_keys)):
            raise _fail("TRACE_COVERAGE_ORDER_INVALID", f"{family_name} is not in canonical path/site order")
        row_ids = tuple(row.stable_site_id for row in parsed_rows)
        if set(row_ids) != set(parsed_ids):
            missing = sorted(set(parsed_ids) - set(row_ids))
            extra = sorted(set(row_ids) - set(parsed_ids))
            raise _fail("TRACE_COVERAGE_UNCOVERED_SITE", f"{family_name} inventory mismatch; missing={missing}, extra={extra}")
        for row in parsed_rows:
            if row.stable_site_id in global_ids:
                raise _fail("TRACE_COVERAGE_DUPLICATE", f"duplicate stable site ID {row.stable_site_id}")
            global_ids.add(row.stable_site_id)
        if family_name == TRACE_HOOK_MANIFEST:
            hook_ids = {row.trace_hook_id for row in parsed_rows}
            if len(hook_ids) != len(parsed_rows):
                raise _fail("TRACE_COVERAGE_DUPLICATE", "trace hook IDs are not unique")
        parsed_required[family_name] = parsed_ids
        parsed_manifests[family_name] = parsed_rows

    for family_name, rows in parsed_manifests.items():
        if family_name == TRACE_HOOK_MANIFEST:
            continue
        for row in rows:
            if row.trace_hook_id not in hook_ids:
                raise _fail("TRACE_COVERAGE_UNHOOKED_SITE", f"{family_name}:{row.stable_site_id} references an unmanifested trace hook")

    declared_root = _sha(value["coverage_manifest_root_sha256"], "coverage_manifest_root_sha256")
    if declared_root != _canonical_root(_payload_without_root(value)):
        raise _fail("TRACE_COVERAGE_ROOT_STALE", "coverage manifest root does not match its canonical contents")
    return CoverageManifest(
        source_root,
        MappingProxyType(parsed_required),
        MappingProxyType(parsed_manifests),
        declared_root,
        MappingProxyType(dict(authority)),
    )


def build_coverage_manifest(
    source_root_sha256: str,
    manifests: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    required_site_ids: Mapping[str, Sequence[str]] | None = None,
) -> CoverageManifest:
    """Build and validate a manifest payload from offline fixture rows.

    The builder preserves caller ordering so noncanonical fixtures fail in the
    same validator used for loaded artifacts.  It never infers missing source
    sites and never creates authority.
    """

    source_root = _sha(source_root_sha256, "source_root_sha256")
    if required_site_ids is None:
        required_site_ids = {
            name: [str(row["stable_site_id"]) for row in manifests.get(name, ())]
            for name in REQUIRED_MANIFEST_FAMILIES
        }
    payload: dict[str, Any] = {
        "schema": TRACE_COVERAGE_SCHEMA,
        "mode": TRACE_COVERAGE_MODE,
        "source_root_sha256": source_root,
        "required_site_ids": {name: list(required_site_ids[name]) for name in REQUIRED_MANIFEST_FAMILIES},
        "manifests": {name: list(manifests[name]) for name in REQUIRED_MANIFEST_FAMILIES},
        "authority": _authority(),
    }
    payload["coverage_manifest_root_sha256"] = _canonical_root(payload)
    return validate_coverage_manifest(payload, expected_source_root_sha256=source_root)


def coverage_manifest_root(value: CoverageManifest | Mapping[str, Any]) -> str:
    """Return the validated canonical coverage root."""

    return validate_coverage_manifest(value).coverage_manifest_root_sha256


__all__ = [
    "AUTHORITY_FIELDS",
    "CoverageEntry",
    "CoverageManifest",
    "ENTRY_FIELDS",
    "FAMILY_CLASSIFICATIONS",
    "IPC_SITE_MANIFEST",
    "MANIFEST_FIELDS",
    "MUTATION_SITE_MANIFEST",
    "PROHIBITED_SERIALIZATION_TERMS",
    "REQUIRED_MANIFEST_FAMILIES",
    "RNG_SITE_MANIFEST",
    "SEMANTIC_FIELD_CLASSIFICATIONS",
    "SEMANTIC_FIELD_MANIFEST",
    "SELECTION_SITE_MANIFEST",
    "TERMINAL_SITE_MANIFEST",
    "TRACE_COVERAGE_MODE",
    "TRACE_COVERAGE_SCHEMA",
    "TRACE_HOOK_MANIFEST",
    "TraceCoverageError",
    "build_coverage_manifest",
    "coverage_manifest_root",
    "validate_coverage_manifest",
]
