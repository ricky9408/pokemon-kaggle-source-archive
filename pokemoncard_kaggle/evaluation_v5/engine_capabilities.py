"""Fail-closed engine capability bindings for evaluation v5.

This module records whether the two frozen execution backends can support the
mechanistic scenarios.  It is deliberately descriptive: a passing capability
audit is not evidence of hosted equivalence and has no submission or holdout
authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from types import MappingProxyType
from typing import Any

from .canonical import canonical_sha256
from .charter import FEATURE_NAMES, PROTOCOL_ID


ENGINE_CAPABILITY_MANIFEST_SCHEMA = "evaluation_v5_engine_capability_manifest_v1"
ENGINE_CAPABILITY_AUDIT_SCHEMA = "evaluation_v5_engine_capability_audit_v1"
REQUIRED_BACKENDS = ("opened_source", "official_wrapper")
CAPABILITY_NAMES = (
    "seeded_start",
    "snapshot_restore_rng",
    "legal_interventions",
    "search_world_interface",
    "repeatability_audited",
)
HASH_NAMES = (
    "binary_sha256",
    "source_sha256",
    "wrapper_sha256",
    "runtime_sha256",
    "container_sha256",
    "card_db_sha256",
    "auditor_executable_sha256",
    "audit_transcript_sha256",
)

SCENARIO_CAPABILITIES = {
    "natural_opening": ("seeded_start",),
    "active_ko": ("seeded_start", "snapshot_restore_rng", "legal_interventions"),
    "disruption": ("seeded_start", "snapshot_restore_rng", "legal_interventions"),
    "observation_invariance": ("search_world_interface", "repeatability_audited"),
    "crn": ("seeded_start", "snapshot_restore_rng"),
}
FEATURE_SCENARIOS = {
    "attack_availability_t2_t4": "natural_opening",
    "prize_progress_t4": "natural_opening",
    "post_active_ko_attack_recovery": "active_ko",
    "attachment_productivity_2t": "natural_opening",
    "post_disruption_attack_recovery": "disruption",
    "observation_invariance": "observation_invariance",
}

_MANIFEST_FIELDS = frozenset({"schema", "protocol_id", "backends"})
_BACKEND_FIELDS = frozenset((*HASH_NAMES, *CAPABILITY_NAMES, "capability_evidence_sha256"))
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EngineCapabilityError(ValueError):
    """The supplied engine capability manifest is malformed or has drifted."""


EngineCapabilityManifestError = EngineCapabilityError


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    """One exact, hash-bound backend and its audited capabilities."""

    binary_sha256: str
    source_sha256: str
    wrapper_sha256: str
    runtime_sha256: str
    container_sha256: str
    card_db_sha256: str
    auditor_executable_sha256: str
    audit_transcript_sha256: str
    seeded_start: bool
    snapshot_restore_rng: bool
    legal_interventions: bool
    search_world_interface: bool
    repeatability_audited: bool
    capability_evidence_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        for name in HASH_NAMES:
            value = getattr(self, name)
            if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
                raise EngineCapabilityError(f"{name} must be a lowercase SHA-256 hex string")
        for name in CAPABILITY_NAMES:
            if type(getattr(self, name)) is not bool:
                raise EngineCapabilityError(f"{name} must be a boolean")
        evidence = self.capability_evidence_sha256
        if not isinstance(evidence, Mapping):
            raise EngineCapabilityError("capability_evidence_sha256 must be a mapping")
        true_capabilities = {
            name for name in CAPABILITY_NAMES if getattr(self, name) is True
        }
        if set(evidence) != true_capabilities:
            raise EngineCapabilityError(
                "capability_evidence_sha256 must contain exactly the true capabilities"
            )
        for capability, evidence_hash in evidence.items():
            if type(capability) is not str or type(evidence_hash) is not str:
                raise EngineCapabilityError(
                    "capability_evidence_sha256 keys and values must be strings"
                )
            if _SHA256_RE.fullmatch(evidence_hash) is None:
                raise EngineCapabilityError(
                    f"capability evidence for {capability!r} must be a lowercase SHA-256 hex string"
                )
        object.__setattr__(self, "capability_evidence_sha256", MappingProxyType(dict(evidence)))

    def as_dict(self) -> dict[str, Any]:
        values = {name: getattr(self, name) for name in (*HASH_NAMES, *CAPABILITY_NAMES)}
        values["capability_evidence_sha256"] = dict(self.capability_evidence_sha256)
        return values


@dataclass(frozen=True, slots=True)
class EngineCapabilityManifest:
    """The canonical pair of execution backends required by v5."""

    schema: str
    protocol_id: str
    backends: Mapping[str, BackendCapabilities]
    _manifest_hash: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self.schema) is not str or self.schema != ENGINE_CAPABILITY_MANIFEST_SCHEMA:
            raise EngineCapabilityError(f"schema must be {ENGINE_CAPABILITY_MANIFEST_SCHEMA!r}")
        if type(self.protocol_id) is not str or self.protocol_id != PROTOCOL_ID:
            raise EngineCapabilityError(f"protocol_id must be {PROTOCOL_ID!r}")
        if not isinstance(self.backends, Mapping) or set(self.backends) != set(REQUIRED_BACKENDS):
            raise EngineCapabilityError(f"backends must contain exactly {list(REQUIRED_BACKENDS)}")
        normalized: dict[str, BackendCapabilities] = {}
        for backend_name in REQUIRED_BACKENDS:
            backend = self.backends[backend_name]
            if not isinstance(backend, BackendCapabilities):
                raise EngineCapabilityError(f"backend {backend_name!r} must be BackendCapabilities")
            normalized[backend_name] = backend
        object.__setattr__(self, "backends", MappingProxyType(normalized))
        object.__setattr__(self, "_manifest_hash", canonical_sha256(self.as_dict()))

    @property
    def manifest_sha256(self) -> str:
        """SHA-256 of this manifest's exact canonical JSON representation."""

        return self._manifest_hash

    @property
    def content_sha256(self) -> str:
        """Compatibility spelling for the canonical manifest hash."""

        return self.manifest_sha256

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "protocol_id": self.protocol_id,
            "backends": {
                backend_name: self.backends[backend_name].as_dict()
                for backend_name in REQUIRED_BACKENDS
            },
        }


def build_backend_capabilities(**fields: Any) -> BackendCapabilities:
    """Build one strictly typed backend binding."""

    if set(fields) != _BACKEND_FIELDS:
        raise EngineCapabilityError(f"backend fields must exactly be {sorted(_BACKEND_FIELDS)}")
    try:
        return BackendCapabilities(**fields)
    except TypeError as exc:
        raise EngineCapabilityError(f"malformed backend capability binding: {exc}") from exc


def build_engine_capability_manifest(
    value: Mapping[str, Any] | None = None, **fields: Any
) -> EngineCapabilityManifest:
    """Build the exact frozen manifest from JSON-native wire fields."""

    if value is not None and fields:
        raise EngineCapabilityError("provide a manifest mapping or keyword fields, not both")
    raw: Mapping[str, Any] = value if value is not None else fields
    if not isinstance(raw, Mapping) or set(raw) != _MANIFEST_FIELDS:
        actual = sorted(raw) if isinstance(raw, Mapping) else type(raw).__name__
        raise EngineCapabilityError(
            f"manifest fields must exactly be {sorted(_MANIFEST_FIELDS)}; got {actual}"
        )
    raw_backends = raw["backends"]
    if not isinstance(raw_backends, Mapping) or set(raw_backends) != set(REQUIRED_BACKENDS):
        raise EngineCapabilityError(f"backends must contain exactly {list(REQUIRED_BACKENDS)}")
    backends: dict[str, BackendCapabilities] = {}
    for backend_name in REQUIRED_BACKENDS:
        backend = raw_backends[backend_name]
        if isinstance(backend, BackendCapabilities):
            backends[backend_name] = backend
            continue
        if not isinstance(backend, Mapping):
            raise EngineCapabilityError(f"backend {backend_name!r} must be a mapping")
        if set(backend) != _BACKEND_FIELDS:
            raise EngineCapabilityError(
                f"backend {backend_name!r} fields must exactly be {sorted(_BACKEND_FIELDS)}"
            )
        try:
            backends[backend_name] = build_backend_capabilities(**dict(backend))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, EngineCapabilityError):
                raise
            raise EngineCapabilityError(f"malformed backend {backend_name!r}: {exc}") from exc
    try:
        return EngineCapabilityManifest(
            schema=raw["schema"], protocol_id=raw["protocol_id"], backends=backends
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, EngineCapabilityError):
            raise
        raise EngineCapabilityError(f"malformed engine capability manifest: {exc}") from exc


def validate_engine_capability_manifest(
    value: EngineCapabilityManifest | Mapping[str, Any],
) -> EngineCapabilityManifest:
    """Validate a typed manifest or its exact canonical wire representation."""

    if isinstance(value, EngineCapabilityManifest):
        return value
    return build_engine_capability_manifest(value)


def engine_capability_manifest_sha256(
    value: EngineCapabilityManifest | Mapping[str, Any],
) -> str:
    """Return the canonical hash after exact manifest validation."""

    return validate_engine_capability_manifest(value).manifest_sha256


def _scenario_audit(
    manifest: EngineCapabilityManifest, scenario: str
) -> dict[str, Any]:
    required = SCENARIO_CAPABILITIES[scenario]
    missing = {
        backend_name: [
            capability
            for capability in required
            if not getattr(manifest.backends[backend_name], capability)
        ]
        for backend_name in REQUIRED_BACKENDS
    }
    return {
        "required_capabilities": list(required),
        "feasible": all(not missing[backend_name] for backend_name in REQUIRED_BACKENDS),
        "missing_capabilities": missing,
    }


def audit_engine_capabilities(
    manifest: EngineCapabilityManifest | Mapping[str, Any],
) -> dict[str, Any]:
    """Return a deterministic, authority-free capability veto result.

    The result only describes local execution feasibility.  It never infers
    hosted equivalence and never grants submission or holdout authority.
    """

    checked = validate_engine_capability_manifest(manifest)
    scenarios = {
        scenario: _scenario_audit(checked, scenario)
        for scenario in (*SCENARIO_CAPABILITIES,)
    }
    features = {
        feature_name: {
            "scenario": scenario,
            "feasible": scenarios[scenario]["feasible"],
            "required_capabilities": scenarios[scenario]["required_capabilities"],
            "missing_capabilities": scenarios[scenario]["missing_capabilities"],
        }
        for feature_name, scenario in FEATURE_SCENARIOS.items()
    }
    missing_features = [
        feature_name for feature_name in FEATURE_NAMES if not features[feature_name]["feasible"]
    ]
    missing_capabilities = {
        feature_name: features[feature_name]["missing_capabilities"]
        for feature_name in missing_features
    }
    return {
        "schema": ENGINE_CAPABILITY_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "manifest_sha256": checked.manifest_sha256,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "decision": "NO_LOCAL_FEATURE_EXTRACTION" if missing_features else "LOCAL_FEATURE_EXTRACTION_FEASIBLE",
        "local_feature_extraction": not missing_features,
        "missing_features": missing_features,
        "missing_capabilities": missing_capabilities,
        "scenario_feasibility": scenarios,
        "feature_feasibility": features,
    }


# Short aliases keep callers readable without creating alternate semantics.
audit = audit_engine_capabilities
manifest_sha256 = engine_capability_manifest_sha256


__all__ = [
    "BackendCapabilities",
    "CAPABILITY_NAMES",
    "ENGINE_CAPABILITY_AUDIT_SCHEMA",
    "ENGINE_CAPABILITY_MANIFEST_SCHEMA",
    "EngineCapabilityError",
    "EngineCapabilityManifest",
    "EngineCapabilityManifestError",
    "FEATURE_SCENARIOS",
    "HASH_NAMES",
    "REQUIRED_BACKENDS",
    "SCENARIO_CAPABILITIES",
    "audit",
    "audit_engine_capabilities",
    "build_backend_capabilities",
    "build_engine_capability_manifest",
    "engine_capability_manifest_sha256",
    "manifest_sha256",
    "validate_engine_capability_manifest",
]
