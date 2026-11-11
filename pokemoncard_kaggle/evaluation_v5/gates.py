"""Fail-closed v5 prevalidation composition."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from collections import Counter
from datetime import datetime, timedelta
import hashlib
import math
from pathlib import Path
import re
from typing import Any

from .binding import BindingVerificationError, binding_sha256, verify_binding
from .canonical import canonical_sha256
from .charter import CharterError, charter_sha256, validate_charter
from .cohort import CohortCustodyError, compose_first48, validate_observation_log, validate_registry
from .ancestry import AncestryAuditError, audit_external_confirmatory_ancestry, validate_signed_population_manifest
from .engine_capabilities import (
    EngineCapabilityError,
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)
from .firewall import EXTERNAL_CONFIRMATORY, FirewallError, validate_firewall
from .model import (
    PredictionManifestError,
    build_prediction_rows,
    prediction_manifest_sha256,
    validate_prediction_manifest,
)
from .transfer import evaluate_transfer

GATE_SCHEMA = "evaluation_v5_prevalidation_gate_v1"
CAMPAIGN_SCHEMA = "evaluation_v5_prediction_campaign_v3"
MODEL_INPUT_SCHEMA = "evaluation_v5_preregistered_model_input_v2"
SAFETY_SCHEMA = "evaluation_v5_operational_safety_evidence_v2"
PREDECLARED_MIN_TESTED_CALLS = 50_000
PREDECLARED_BOOTSTRAP_SEED = 17
PREDECLARED_BOOTSTRAP_RESAMPLES = 999
PREDECLARED_LIFT_THRESHOLD_NATS = 0.010
PREDECLARED_ALPHA = 0.025
MAX_ARCHIVES_PER_FAMILY = 2
PROTOCOL_ID = "MCI_TRANSFER_V1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_CAMPAIGN_FIELDS = frozenset(
    {
        "alpha",
        "ancestry_auditor_public_key_sha256",
        "ancestry_manifest_sha256",
        "architecture_binding_sha256",
        "analysis_executable_sha256",
        "bootstrap_resamples",
        "bootstrap_seed",
        "campaign_id",
        "campaign_sha256",
        "charter_sha256",
        "comparator_manifest_sha256",
        "custody_ca_file_sha256",
        "custody_tsa_policy_oid",
        "deadline_at_utc",
        "engine_capability_manifest_sha256",
        "engine_evidence_manifest_sha256",
        "engine_evidence_signer_public_key_sha256",
        "host_evidence_signer_public_key_sha256",
        "implementation_binding_sha256",
        "provenance_evidence_signer_public_key_sha256",
        "safety_evidence_signer_public_key_sha256",
        "trust_roots_snapshot_sha256",
        "lift_threshold_nats",
        "mci_manifest_sha256",
        "protocol_id",
        "registration_opened_at_utc",
        "schema",
    }
)
_INPUT_FIELDS = frozenset(
    {
        "archive_sha256",
        "campaign_sha256",
        "comparator_inputs",
        "comparator_manifest_sha256",
        "created_at_utc",
        "engine_capability_manifest_sha256",
        "era",
        "features",
        "mci_manifest_sha256",
        "model_input_sha256",
        "protocol_id",
        "schema",
    }
)
_SAFETY_FIELDS = frozenset(
    {
        "archive_sha256s",
        "authority",
        "campaign_sha256",
        "counts",
        "protocol_id",
        "safety_sha256",
        "schema",
        "tested_calls",
    }
)
_SAFETY_COUNT_FIELDS = frozenset(
    {"crashes", "illegal_actions", "malformed_outputs", "runtime_failures", "timeouts"}
)
_SAFETY_KINDS = tuple(sorted(_SAFETY_COUNT_FIELDS))


class GateValidationError(ValueError):
    """A v5 gate artifact is malformed or not bound to the frozen protocol."""


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise GateValidationError(f"{label} fields are not exact")
    return value


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise GateValidationError(f"{label} must be a lowercase SHA-256")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise GateValidationError(f"{label} must be a non-empty trimmed string")
    return value


def _utc(value: object, label: str) -> tuple[datetime, str]:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise GateValidationError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise GateValidationError(f"{label} is invalid") from exc
    return parsed, value


def _real(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise GateValidationError(f"{label} must be finite")
    return float(value)


def _hash(value: object) -> str:
    return canonical_sha256(value)


def _analysis_executable_sha256() -> str:
    """Hash the exact gate program whose behavior is being evaluated."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def build_campaign(
    *,
    campaign_id: str,
    registration_opened_at_utc: str,
    charter_sha256: str,
    architecture_binding_sha256: str,
    analysis_executable_sha256: str,
    ancestry_auditor_public_key_sha256: str,
    ancestry_manifest_sha256: str,
    engine_capability_manifest_sha256: str,
    engine_evidence_manifest_sha256: str,
    engine_evidence_signer_public_key_sha256: str,
    host_evidence_signer_public_key_sha256: str,
    safety_evidence_signer_public_key_sha256: str,
    provenance_evidence_signer_public_key_sha256: str,
    trust_roots_snapshot_sha256: str,
    implementation_binding_sha256: str,
    custody_ca_file_sha256: str,
    custody_tsa_policy_oid: str,
    mci_manifest_sha256: str,
    comparator_manifest_sha256: str,
    bootstrap_seed: int = PREDECLARED_BOOTSTRAP_SEED,
    bootstrap_resamples: int = PREDECLARED_BOOTSTRAP_RESAMPLES,
    lift_threshold_nats: float = PREDECLARED_LIFT_THRESHOLD_NATS,
    alpha: float = PREDECLARED_ALPHA,
) -> dict[str, Any]:
    opened, opened_text = _utc(registration_opened_at_utc, "registration_opened_at_utc")
    content = {
        "alpha": _real(alpha, "alpha"),
        "ancestry_auditor_public_key_sha256": _sha(ancestry_auditor_public_key_sha256, "ancestry_auditor_public_key_sha256"),
        "ancestry_manifest_sha256": _sha(ancestry_manifest_sha256, "ancestry_manifest_sha256"),
        "architecture_binding_sha256": _sha(architecture_binding_sha256, "architecture_binding_sha256"),
        "analysis_executable_sha256": _sha(analysis_executable_sha256, "analysis_executable_sha256"),
        "bootstrap_resamples": bootstrap_resamples,
        "bootstrap_seed": bootstrap_seed,
        "campaign_id": _text(campaign_id, "campaign_id"),
        "charter_sha256": _sha(charter_sha256, "charter_sha256"),
        "comparator_manifest_sha256": _sha(comparator_manifest_sha256, "comparator_manifest_sha256"),
        "custody_ca_file_sha256": _sha(custody_ca_file_sha256, "custody_ca_file_sha256"),
        "custody_tsa_policy_oid": _text(custody_tsa_policy_oid, "custody_tsa_policy_oid"),
        "deadline_at_utc": (opened + timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "engine_capability_manifest_sha256": _sha(engine_capability_manifest_sha256, "engine_capability_manifest_sha256"),
        "engine_evidence_manifest_sha256": _sha(engine_evidence_manifest_sha256, "engine_evidence_manifest_sha256"),
        "engine_evidence_signer_public_key_sha256": _sha(
            engine_evidence_signer_public_key_sha256,
            "engine_evidence_signer_public_key_sha256",
        ),
        "implementation_binding_sha256": _sha(implementation_binding_sha256, "implementation_binding_sha256"),
        "host_evidence_signer_public_key_sha256": _sha(
            host_evidence_signer_public_key_sha256,
            "host_evidence_signer_public_key_sha256",
        ),
        "safety_evidence_signer_public_key_sha256": _sha(
            safety_evidence_signer_public_key_sha256,
            "safety_evidence_signer_public_key_sha256",
        ),
        "provenance_evidence_signer_public_key_sha256": _sha(
            provenance_evidence_signer_public_key_sha256,
            "provenance_evidence_signer_public_key_sha256",
        ),
        "trust_roots_snapshot_sha256": _sha(
            trust_roots_snapshot_sha256, "trust_roots_snapshot_sha256"
        ),
        "lift_threshold_nats": _real(lift_threshold_nats, "lift_threshold_nats"),
        "mci_manifest_sha256": _sha(mci_manifest_sha256, "mci_manifest_sha256"),
        "protocol_id": PROTOCOL_ID,
        "registration_opened_at_utc": opened_text,
        "schema": CAMPAIGN_SCHEMA,
    }
    return {**content, "campaign_sha256": _hash(content)}


def validate_campaign(value: object) -> dict[str, Any]:
    raw = _exact(value, _CAMPAIGN_FIELDS, "campaign")
    if raw["schema"] != CAMPAIGN_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise GateValidationError("campaign schema or protocol mismatch")
    opened, opened_text = _utc(raw["registration_opened_at_utc"], "registration_opened_at_utc")
    deadline, deadline_text = _utc(raw["deadline_at_utc"], "deadline_at_utc")
    if deadline != opened + timedelta(days=120):
        raise GateValidationError("campaign deadline is not exactly 120 days after opening")
    if raw["bootstrap_seed"] != PREDECLARED_BOOTSTRAP_SEED:
        raise GateValidationError("campaign bootstrap seed is not the frozen seed")
    if (
        isinstance(raw["bootstrap_resamples"], bool)
        or not isinstance(raw["bootstrap_resamples"], int)
        or raw["bootstrap_resamples"] < PREDECLARED_BOOTSTRAP_RESAMPLES
    ):
        raise GateValidationError("campaign bootstrap resamples are below the frozen minimum")
    if _real(raw["lift_threshold_nats"], "lift_threshold_nats") != PREDECLARED_LIFT_THRESHOLD_NATS:
        raise GateValidationError("campaign lift threshold is not frozen")
    if _real(raw["alpha"], "alpha") != PREDECLARED_ALPHA:
        raise GateValidationError("campaign alpha is not frozen")
    content = {
        "alpha": float(raw["alpha"]),
        "architecture_binding_sha256": _sha(raw["architecture_binding_sha256"], "architecture_binding_sha256"),
        "analysis_executable_sha256": _sha(raw["analysis_executable_sha256"], "analysis_executable_sha256"),
        "ancestry_auditor_public_key_sha256": _sha(raw["ancestry_auditor_public_key_sha256"], "ancestry_auditor_public_key_sha256"),
        "ancestry_manifest_sha256": _sha(raw["ancestry_manifest_sha256"], "ancestry_manifest_sha256"),
        "bootstrap_resamples": raw["bootstrap_resamples"],
        "bootstrap_seed": raw["bootstrap_seed"],
        "campaign_id": _text(raw["campaign_id"], "campaign_id"),
        "charter_sha256": _sha(raw["charter_sha256"], "charter_sha256"),
        "comparator_manifest_sha256": _sha(raw["comparator_manifest_sha256"], "comparator_manifest_sha256"),
        "custody_ca_file_sha256": _sha(raw["custody_ca_file_sha256"], "custody_ca_file_sha256"),
        "custody_tsa_policy_oid": _text(raw["custody_tsa_policy_oid"], "custody_tsa_policy_oid"),
        "deadline_at_utc": deadline_text,
        "engine_capability_manifest_sha256": _sha(raw["engine_capability_manifest_sha256"], "engine_capability_manifest_sha256"),
        "engine_evidence_manifest_sha256": _sha(raw["engine_evidence_manifest_sha256"], "engine_evidence_manifest_sha256"),
        "engine_evidence_signer_public_key_sha256": _sha(
            raw["engine_evidence_signer_public_key_sha256"],
            "engine_evidence_signer_public_key_sha256",
        ),
        "implementation_binding_sha256": _sha(raw["implementation_binding_sha256"], "implementation_binding_sha256"),
        "host_evidence_signer_public_key_sha256": _sha(
            raw["host_evidence_signer_public_key_sha256"],
            "host_evidence_signer_public_key_sha256",
        ),
        "safety_evidence_signer_public_key_sha256": _sha(
            raw["safety_evidence_signer_public_key_sha256"],
            "safety_evidence_signer_public_key_sha256",
        ),
        "provenance_evidence_signer_public_key_sha256": _sha(
            raw["provenance_evidence_signer_public_key_sha256"],
            "provenance_evidence_signer_public_key_sha256",
        ),
        "trust_roots_snapshot_sha256": _sha(
            raw["trust_roots_snapshot_sha256"], "trust_roots_snapshot_sha256"
        ),
        "lift_threshold_nats": float(raw["lift_threshold_nats"]),
        "mci_manifest_sha256": _sha(raw["mci_manifest_sha256"], "mci_manifest_sha256"),
        "protocol_id": raw["protocol_id"],
        "registration_opened_at_utc": opened_text,
        "schema": raw["schema"],
    }
    if raw["campaign_sha256"] != _hash(content):
        raise GateValidationError("campaign hash mismatch")
    return {**content, "campaign_sha256": _sha(raw["campaign_sha256"], "campaign_sha256")}


def build_model_input_record(
    *,
    archive_sha256: str,
    campaign_sha256: str,
    mci_manifest_sha256: str,
    comparator_manifest_sha256: str,
    engine_capability_manifest_sha256: str,
    features: Mapping[str, float],
    comparator_inputs: Mapping[str, float | None],
    era: str,
    created_at_utc: str,
) -> dict[str, Any]:
    content = {
        "archive_sha256": _sha(archive_sha256, "archive_sha256"),
        "campaign_sha256": _sha(campaign_sha256, "campaign_sha256"),
        "comparator_inputs": dict(comparator_inputs),
        "comparator_manifest_sha256": _sha(comparator_manifest_sha256, "comparator_manifest_sha256"),
        "created_at_utc": _utc(created_at_utc, "model input created_at_utc")[1],
        "engine_capability_manifest_sha256": _sha(engine_capability_manifest_sha256, "engine_capability_manifest_sha256"),
        "era": _text(era, "era"),
        "features": dict(features),
        "mci_manifest_sha256": _sha(mci_manifest_sha256, "mci_manifest_sha256"),
        "protocol_id": PROTOCOL_ID,
        "schema": MODEL_INPUT_SCHEMA,
    }
    return {**content, "model_input_sha256": _hash(content)}


def validate_model_input_record(
    value: object, *, mci_manifest: object, comparator_manifest: object
) -> dict[str, Any]:
    raw = _exact(value, _INPUT_FIELDS, "model input record")
    if raw["schema"] != MODEL_INPUT_SCHEMA or raw["protocol_id"] != PROTOCOL_ID:
        raise GateValidationError("model input schema or protocol mismatch")
    mci = validate_prediction_manifest(mci_manifest)
    comparator = validate_prediction_manifest(comparator_manifest)
    if raw["mci_manifest_sha256"] != mci.manifest_sha256 or raw["comparator_manifest_sha256"] != comparator.manifest_sha256:
        raise GateValidationError("model input does not bind the supplied real manifests")
    features = raw["features"]
    if not isinstance(features, Mapping) or set(features) != set(mci.feature_names):
        raise GateValidationError("model input does not contain all six MCI features")
    checked_features = {name: _real(features[name], f"feature {name}") for name in mci.feature_names}
    if any(not 0.0 <= value <= 1.0 for value in checked_features.values()):
        raise GateValidationError("MCI features must be in [0, 1]")
    comparator_inputs = raw["comparator_inputs"]
    if not isinstance(comparator_inputs, Mapping) or any(type(key) is not str for key in comparator_inputs):
        raise GateValidationError("comparator_inputs must be a string-keyed mapping")
    expected_key = comparator.comparator_input_key
    if expected_key is None:
        if dict(comparator_inputs):
            raise GateValidationError("nuisance-only comparator cannot bind comparator inputs")
        checked_comparator_inputs: dict[str, float | None] = {}
    else:
        if set(comparator_inputs) != {expected_key}:
            raise GateValidationError("comparator_inputs do not match the frozen comparator identity")
        value_for_key = comparator_inputs[expected_key]
        checked_comparator_inputs = {
            expected_key: None if value_for_key is None else _real(value_for_key, "comparator input")
        }
    era = _text(raw["era"], "era")
    if era not in mci.era_effects or era not in comparator.era_effects:
        raise GateValidationError("model input era is absent from a frozen manifest")
    content = {
        "archive_sha256": _sha(raw["archive_sha256"], "archive_sha256"),
        "campaign_sha256": _sha(raw["campaign_sha256"], "campaign_sha256"),
        "comparator_inputs": checked_comparator_inputs,
        "comparator_manifest_sha256": _sha(raw["comparator_manifest_sha256"], "comparator_manifest_sha256"),
        "created_at_utc": _utc(raw["created_at_utc"], "model input created_at_utc")[1],
        "engine_capability_manifest_sha256": _sha(raw["engine_capability_manifest_sha256"], "engine_capability_manifest_sha256"),
        "era": era,
        "features": checked_features,
        "mci_manifest_sha256": _sha(raw["mci_manifest_sha256"], "mci_manifest_sha256"),
        "protocol_id": raw["protocol_id"],
        "schema": raw["schema"],
    }
    if raw["model_input_sha256"] != _hash(content):
        raise GateValidationError("model input hash mismatch")
    return {**content, "model_input_sha256": _sha(raw["model_input_sha256"], "model_input_sha256")}


def build_operational_safety_evidence(
    *, campaign_sha256: str, archive_sha256s: Iterable[str], tested_calls: int,
    counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    content = {
        "archive_sha256s": sorted(archive_sha256s),
        "authority": False,
        "campaign_sha256": campaign_sha256,
        "counts": dict(counts) if counts is not None else {kind: 0 for kind in _SAFETY_KINDS},
        "protocol_id": PROTOCOL_ID,
        "schema": SAFETY_SCHEMA,
        "tested_calls": tested_calls,
    }
    return {**content, "safety_sha256": _hash(content)}


def validate_operational_safety(value: object) -> dict[str, Any]:
    raw = _exact(value, _SAFETY_FIELDS, "operational safety")
    if raw["schema"] != SAFETY_SCHEMA or raw["protocol_id"] != PROTOCOL_ID or raw["authority"] is not False:
        raise GateValidationError("operational safety schema, protocol, or authority mismatch")
    archives = raw["archive_sha256s"]
    if not isinstance(archives, list) or not archives or archives != sorted(archives) or len(set(archives)) != len(archives):
        raise GateValidationError("operational safety archive binding is not an ordered set")
    checked_archives = [_sha(item, "safety archive_sha256") for item in archives]
    checked_counts = _exact(raw["counts"], _SAFETY_COUNT_FIELDS, "operational safety counts")
    counts = {kind: checked_counts[kind] for kind in _SAFETY_KINDS}
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in counts.values()):
        raise GateValidationError("operational safety counts must be non-negative integers")
    if isinstance(raw["tested_calls"], bool) or not isinstance(raw["tested_calls"], int) or raw["tested_calls"] < PREDECLARED_MIN_TESTED_CALLS:
        raise GateValidationError("operational safety tested_calls is below the predeclared minimum")
    content = {
        "archive_sha256s": checked_archives,
        "authority": False,
        "campaign_sha256": _sha(raw["campaign_sha256"], "safety campaign_sha256"),
        "counts": counts,
        "protocol_id": raw["protocol_id"],
        "schema": raw["schema"],
        "tested_calls": raw["tested_calls"],
    }
    if raw["safety_sha256"] != _hash(content):
        raise GateValidationError("operational safety self-hash mismatch")
    return {**content, "safety_sha256": _sha(raw["safety_sha256"], "safety_sha256")}


def _gate(name: str, passed: bool, reasons: Iterable[str], evidence: object | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"name": name, "passed": bool(passed), "reasons": sorted(set(reasons))}
    if evidence is not None:
        result["evidence_sha256"] = _hash(evidence)
    return result


def _firewall_matches_registry(firewall: object, registry: Mapping[str, Any]) -> None:
    checked_firewall = validate_firewall(firewall)
    checked_registry = validate_registry(registry)
    expected = {item["archive_sha256"]: item for item in checked_registry["records"]}
    external = [item for item in checked_firewall.records if item.partition == EXTERNAL_CONFIRMATORY]
    if len(external) != len(expected) or {item.archive_sha256 for item in external} != set(expected):
        raise FirewallError("firewall external confirmatory set does not match registry cardinality")
    for record in external:
        registration = expected[record.archive_sha256]
        if any(
            actual != registration[field]
            for actual, field in (
                (record.deck_sha256, "deck_sha256"),
                (record.policy_sha256, "policy_sha256"),
                (record.family_provenance_sha256, "family_provenance_sha256"),
                (record.model_input_sha256, "model_input_sha256"),
                (record.registered_at_utc, "registered_at_utc"),
            )
        ):
            raise FirewallError("firewall external record does not bind registry identity")


def _audit_ancestry_matches_registry(
    ancestry_manifest: object, pinned_public_key_hex: str, registry: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify signed ancestry and reject every self-attested family label."""

    audit = audit_external_confirmatory_ancestry(
        ancestry_manifest, pinned_public_key_hex=pinned_public_key_hex
    )
    signed = validate_signed_population_manifest(
        ancestry_manifest, pinned_public_key_hex=pinned_public_key_hex
    )
    checked_registry = validate_registry(registry)
    registrations = {item["archive_sha256"]: item for item in checked_registry["records"]}
    signed_by_archive = {item["archive_sha256"]: item for item in signed["records"]}
    if set(signed_by_archive) != set(registrations):
        raise AncestryAuditError("ancestry audit archive set does not exactly match registry")
    for archive, registration in registrations.items():
        ancestry_record = signed_by_archive[archive]
        if ancestry_record["policy_sha256"] != registration["policy_sha256"]:
            raise AncestryAuditError("ancestry audit policy does not match registry")
        derived_family = audit["archive_to_family"].get(archive)
        if derived_family != registration["family_provenance_sha256"]:
            raise AncestryAuditError("registration family hash is not the audited family id")
        if _utc(audit["latest_review_timestamp_utc"], "ancestry review")[0] >= _utc(
            registration["registered_at_utc"], "registration"
        )[0]:
            raise AncestryAuditError("ancestry review is not before registration")
    return audit


def _select_eligible_archives(
    registry: Mapping[str, Any], observation_log: Mapping[str, Any], *, as_of_utc: str,
    deadline_at_utc: str, archive_to_family: Mapping[str, str]
) -> tuple[list[dict[str, Any]], list[str]]:
    checked_registry = validate_registry(registry)
    checked_log = validate_observation_log(observation_log)
    # Registration is closed at the protocol minimum.  Allowing a larger pool
    # and choosing whichever 30 complete first would make completion itself a
    # post-registration selection variable.
    if len(checked_registry["records"]) != 30:
        raise LookupError("analysis_not_open")
    _, deadline_text = _utc(deadline_at_utc, "campaign deadline")
    deadline, _ = _utc(deadline_text, "campaign deadline")
    eligible: list[dict[str, Any]] = []
    for registration in checked_registry["records"]:
        try:
            horizon = compose_first48(
                checked_registry,
                checked_log,
                archive_sha256=registration["archive_sha256"],
                as_of_utc=as_of_utc,
            )
            horizon_times = [_utc(game["created_at_utc"], "hosted game")[0] for game in horizon["games"]]
            maturity = _utc(horizon["mature_after_utc"], "mature_after_utc")[0]
            completion = _utc(horizon["completion_observed_at_utc"], "completion_observed_at_utc")[0]
            if any(item > deadline for item in horizon_times) or completion > deadline or maturity > deadline:
                raise LookupError("analysis_not_open")
        except CohortCustodyError as exc:
            # Every preregistered archive is part of the immutable population.
            # Silently skipping incomplete archives enables selective completion.
            raise LookupError("analysis_not_open") from exc
        eligible.append({"registration": registration, "horizon": horizon})
    if len(eligible) != 30:
        raise LookupError("analysis_not_open")
    selected = eligible
    selected_families = [
        archive_to_family[item["registration"]["archive_sha256"]] for item in selected
    ]
    family_ids = sorted(set(selected_families))
    if len(family_ids) < 15:
        raise LookupError("analysis_not_open")
    if max(Counter(selected_families).values(), default=0) > MAX_ARCHIVES_PER_FAMILY:
        raise LookupError("analysis_not_open")
    return selected, family_ids


def _reconstruct_rows(
    selected: list[dict[str, Any]], inputs: list[dict[str, Any]], mci: object, comparator: object,
    archive_to_family: Mapping[str, str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    inputs_by_archive = {item["archive_sha256"]: item for item in inputs}
    rows: list[dict[str, Any]] = []
    horizons: list[dict[str, Any]] = []
    for item in selected:
        registration = item["registration"]
        archive = registration["archive_sha256"]
        family_id = archive_to_family.get(archive)
        if family_id is None or registration["family_provenance_sha256"] != family_id:
            raise CohortCustodyError("registration family is not the audited ancestry family")
        model_input = inputs_by_archive.get(archive)
        if model_input is None or registration["model_input_sha256"] != model_input["model_input_sha256"]:
            raise CohortCustodyError("model input does not match archive registration")
        input_time = _utc(model_input["created_at_utc"], "model input")[0]
        registration_time = _utc(registration["registered_at_utc"], "registration")[0]
        if input_time >= registration_time:
            raise CohortCustodyError("model input must precede registration")
        games = []
        for observation in item["horizon"]["games"]:
            games.append(
                {
                    "archive_id": archive,
                    "family_id": family_id,
                    "game_id": observation["game_id"],
                    "hosted_at_utc": observation["created_at_utc"],
                    "outcome": 1.0 if observation["outcome"] == "win" else 0.0,
                    "era": model_input["era"],
                    "seat": observation["seat"],
                    "opponent_rating": observation["opponent_rating"],
                    "features": model_input["features"],
                    "comparator_inputs": model_input["comparator_inputs"],
                }
            )
        rows.extend(
            build_prediction_rows(
                mci,
                comparator,
                games,
                archive_id=archive,
                family_id=family_id,
                registered_package_hash=archive,
                registration_at_utc=registration["registered_at_utc"],
            )
        )
        horizons.append(item["horizon"])
    return rows, {"schema": "evaluation_v5_reconstructed_prediction_binding_v1", "first48": horizons, "model_inputs": inputs}


def prevalidation_gate(
    *, repo_root: str | Path, binding: object, charter: object, firewall: object,
    ancestry_manifest: object | None = None,
    ancestry_auditor_public_key_hex: str | None = None,
    campaign: Mapping[str, Any] | None = None, mci_manifest: object | None = None,
    comparator_manifest: object | None = None, model_inputs: Iterable[Mapping[str, Any]] | None = None,
    engine_capability_manifest: object | None = None, safety_evidence: object | None = None,
    registry: Mapping[str, Any] | None = None, observation_log: Mapping[str, Any] | None = None,
    as_of_utc: str | None = None,
) -> dict[str, Any]:
    gates: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    checked_charter = checked_binding = None
    try:
        checked_charter = validate_charter(charter)
        checked_binding = verify_binding(repo_root, binding)
        if checked_charter.protocol_id != checked_binding["protocol_id"]:
            raise CharterError("charter and binding protocols differ")
        g0_evidence = {"charter": checked_charter.as_dict(), "binding": checked_binding}
        gates.append(_gate("G0", True, (), g0_evidence))
        evidence["charter_sha256"] = charter_sha256(checked_charter)
        evidence["architecture_binding_sha256"] = binding_sha256(checked_binding)
    except (BindingVerificationError, CharterError, TypeError, ValueError):
        gates.append(_gate("G0", False, ("charter_or_binding_invalid",)))

    checked_registry = None
    checked_ancestry_audit = None
    cohort_missing = registry is None or observation_log is None or as_of_utc is None
    try:
        checked_registry = validate_registry(registry) if registry is not None else None
        if checked_registry is None:
            raise LookupError
        _firewall_matches_registry(firewall, checked_registry)
        if ancestry_manifest is None or ancestry_auditor_public_key_hex is None:
            raise AncestryAuditError("ancestry_audit_missing")
        checked_ancestry_audit = _audit_ancestry_matches_registry(
            ancestry_manifest, ancestry_auditor_public_key_hex, checked_registry
        )
        firewall_wire = sorted(
            (record.as_dict() for record in validate_firewall(firewall).records),
            key=lambda row: (row["partition"], row["archive_sha256"]),
        )
        gates.append(_gate("G1", True, (), firewall_wire))
        evidence["firewall_sha256"] = _hash(firewall_wire)
        evidence["ancestry_audit_sha256"] = checked_ancestry_audit["evidence_sha256"]
    except LookupError:
        gates.append(_gate("G1", False, ("firewall_binding_pending_cohort",)))
    except AncestryAuditError as exc:
        gates.append(_gate("G1", False, ("ancestry_audit_missing" if str(exc) == "ancestry_audit_missing" else "ancestry_audit_invalid",)))
    except (FirewallError, CohortCustodyError, TypeError, ValueError, AttributeError):
        gates.append(_gate("G1", False, ("firewall_registry_binding_invalid",)))

    checked_campaign = checked_mci = checked_comparator = None
    checked_inputs: list[dict[str, Any]] | None = None
    try:
        if campaign is None or mci_manifest is None or comparator_manifest is None or model_inputs is None:
            raise LookupError
        if checked_binding is None or checked_charter is None:
            raise GateValidationError("G0 must pass before campaign binding")
        checked_campaign = validate_campaign(campaign)
        checked_mci = validate_prediction_manifest(mci_manifest)
        checked_comparator = validate_prediction_manifest(comparator_manifest)
        if checked_mci.model_kind != "MCI" or checked_comparator.model_kind != "FROZEN_COMPARATOR":
            raise GateValidationError("campaign model roles are invalid")
        if prediction_manifest_sha256(checked_mci) != checked_campaign["mci_manifest_sha256"] or prediction_manifest_sha256(checked_comparator) != checked_campaign["comparator_manifest_sha256"]:
            raise GateValidationError("campaign does not bind the real model manifests")
        if checked_mci.probability_epsilon != checked_comparator.probability_epsilon:
            raise GateValidationError("MCI and comparator probability_epsilon differ")
        if checked_campaign["charter_sha256"] != charter_sha256(checked_charter) or checked_campaign["architecture_binding_sha256"] != binding_sha256(checked_binding):
            raise GateValidationError("campaign does not bind charter and architecture binding")
        if checked_ancestry_audit is None and checked_registry is not None:
            raise GateValidationError("ancestry_audit_missing")
        if checked_ancestry_audit is not None and (checked_campaign["ancestry_manifest_sha256"] != checked_ancestry_audit["manifest_sha256"] or checked_campaign["ancestry_auditor_public_key_sha256"] != checked_ancestry_audit["auditor_public_key_sha256"]):
            raise GateValidationError("campaign ancestry binding mismatch")
        if checked_campaign["analysis_executable_sha256"] != _analysis_executable_sha256():
            raise GateValidationError("campaign analysis executable hash differs from this gate")
        opened = _utc(checked_campaign["registration_opened_at_utc"], "campaign opening")[0]
        deadline = _utc(checked_campaign["deadline_at_utc"], "campaign deadline")[0]
        mci_created = _utc(checked_mci.created_at_utc, "MCI manifest")[0]
        comparator_created = _utc(checked_comparator.created_at_utc, "comparator manifest")[0]
        if mci_created >= opened or comparator_created >= opened:
            raise GateValidationError(
                "both model manifests must be frozen before campaign opening"
            )
        if not (0.0 < checked_campaign["alpha"] < 1.0):
            raise GateValidationError("campaign alpha is invalid")
        checked_inputs = [
            validate_model_input_record(item, mci_manifest=checked_mci, comparator_manifest=checked_comparator)
            for item in model_inputs
        ]
        archives = [item["archive_sha256"] for item in checked_inputs]
        if len(archives) != len(set(archives)):
            raise GateValidationError("duplicate model input archive")
        for item in checked_inputs:
            input_time = _utc(item["created_at_utc"], "model input")[0]
            if input_time <= mci_created or input_time <= comparator_created:
                raise GateValidationError("model input must follow both frozen manifests")
            if item["campaign_sha256"] != checked_campaign["campaign_sha256"] or item["engine_capability_manifest_sha256"] != checked_campaign["engine_capability_manifest_sha256"]:
                raise GateValidationError("model input campaign or engine binding mismatch")
        if checked_registry is not None:
            registration_by_archive = {item["archive_sha256"]: item for item in checked_registry["records"]}
            if set(archives) != set(registration_by_archive) or len(archives) != len(registration_by_archive):
                raise GateValidationError("model inputs do not cover exactly one record per registration")
            for item in checked_inputs:
                registration = registration_by_archive[item["archive_sha256"]]
                registered = _utc(registration["registered_at_utc"], "registration")[0]
                if not (opened <= registered <= deadline):
                    raise GateValidationError("registration is outside the campaign window")
                if _utc(item["created_at_utc"], "model input")[0] >= registered:
                    raise GateValidationError("model input must precede registration")
        checked_inputs.sort(key=lambda item: item["archive_sha256"])
        model_wire = {"campaign": checked_campaign, "mci_manifest_sha256": checked_mci.manifest_sha256, "comparator_manifest_sha256": checked_comparator.manifest_sha256, "model_inputs": checked_inputs}
        gates.append(_gate("G2", True, (), model_wire))
        evidence["model_binding_sha256"] = _hash(model_wire)
    except LookupError:
        gates.append(_gate("G2", False, ("campaign_or_model_binding_missing",)))
    except (GateValidationError, PredictionManifestError, TypeError, ValueError):
        gates.append(_gate("G2", False, ("campaign_or_model_binding_invalid",)))

    safety_pending = False
    try:
        checked_safety = validate_operational_safety(safety_evidence)
        safety_reasons = [kind for kind, count in checked_safety["counts"].items() if count]
        if checked_registry is None:
            safety_pending = True
            safety_reasons.append("safety_binding_pending_cohort")
        else:
            expected_archives = sorted(item["archive_sha256"] for item in checked_registry["records"])
            if checked_safety["archive_sha256s"] != expected_archives:
                safety_reasons.append("safety_archive_binding_mismatch")
            if checked_campaign is None or checked_safety["campaign_sha256"] != checked_campaign["campaign_sha256"]:
                safety_reasons.append("safety_campaign_binding_mismatch")
        gates.append(_gate("G3", not safety_reasons, safety_reasons, checked_safety))
        evidence["safety_sha256"] = checked_safety["safety_sha256"]
    except (GateValidationError, TypeError, ValueError):
        gates.append(_gate("G3", False, ("operational_safety_invalid",)))

    cohort_evidence = None
    cohort_reasons: list[str] = []
    reconstructed_rows = None
    g0_g3_pass = all(gate["passed"] for gate in gates[:4])
    if not g0_g3_pass:
        if gates[1]["reasons"] == ["ancestry_audit_missing"]:
            cohort_reasons.append("ancestry_audit_missing")
        else:
            cohort_reasons.append("prior_gate_failed" if not cohort_missing else "external_cohort_artifact_missing")
    elif checked_inputs is None or checked_mci is None or checked_comparator is None or checked_campaign is None:
        cohort_reasons.append("campaign_or_model_binding_missing")
    else:
        try:
            if registry is None or observation_log is None or as_of_utc is None:
                raise LookupError("analysis_not_open")
            _, as_of_text = _utc(as_of_utc, "as_of_utc")
            selected, families = _select_eligible_archives(
                checked_registry,
                observation_log,
                as_of_utc=as_of_text,
                deadline_at_utc=checked_campaign["deadline_at_utc"],
                archive_to_family=checked_ancestry_audit["archive_to_family"],
            )
            capability_manifest = validate_engine_capability_manifest(engine_capability_manifest)
            capability_audit = audit_engine_capabilities(capability_manifest)
            if capability_manifest.manifest_sha256 != checked_campaign["engine_capability_manifest_sha256"]:
                raise GateValidationError("engine capability manifest hash mismatch")
            if capability_audit["decision"] != "LOCAL_FEATURE_EXTRACTION_FEASIBLE" or capability_audit["missing_features"]:
                raise GateValidationError("local feature extraction is not feasible")
            reconstructed_rows, cohort_evidence = _reconstruct_rows(selected, checked_inputs, checked_mci, checked_comparator, checked_ancestry_audit["archive_to_family"])
            cohort_evidence.update({"analysis_archive_hashes": [item["registration"]["archive_sha256"] for item in selected], "family_hashes": families, "engine_capability_manifest_sha256": capability_manifest.manifest_sha256, "engine_capability_audit": capability_audit})
        except LookupError as exc:
            cohort_reasons.append(str(exc) or "analysis_not_open")
        except (CohortCustodyError, EngineCapabilityError, GateValidationError, PredictionManifestError, TypeError, ValueError):
            cohort_reasons.append("external_cohort_or_capability_artifact_invalid")
    g4_pass = not cohort_reasons and cohort_evidence is not None and reconstructed_rows is not None
    gates.append(_gate("G4", g4_pass, cohort_reasons, cohort_evidence))
    if cohort_evidence is not None:
        evidence["cohort_sha256"] = _hash(cohort_evidence)

    transfer_result = None
    transfer_reasons: list[str] = []
    if g4_pass and all(gate["passed"] for gate in gates[:5]):
        assert checked_mci is not None and checked_campaign is not None and reconstructed_rows is not None
        transfer_result = evaluate_transfer(
            reconstructed_rows,
            epsilon=checked_mci.probability_epsilon,
            seed=checked_campaign["bootstrap_seed"],
            resamples=checked_campaign["bootstrap_resamples"],
        )
        if transfer_result["integrity_pass"] is not True:
            transfer_reasons.append("transfer_integrity_failed")
        if transfer_result["passed"] is not True or transfer_result["decision"] != "PASS":
            transfer_reasons.extend(str(reason) for reason in transfer_result["reasons"])
    else:
        transfer_reasons.append("analysis_not_open")
    gates.append(_gate("G5", transfer_result is not None and not transfer_reasons, transfer_reasons, transfer_result))
    if transfer_result is not None:
        evidence["transfer_sha256"] = _hash(transfer_result)

    hard_integrity = (not gates[0]["passed"]) or (not gates[1]["passed"] and not cohort_missing) or (not gates[2]["passed"]) or (not gates[3]["passed"] and not safety_pending)
    if hard_integrity:
        decision = "NO_SUBMIT_INTEGRITY"
    elif not g4_pass:
        decision = "NO_SUBMIT_IDENTIFIABILITY"
    elif not gates[5]["passed"]:
        decision = "NO_SUBMIT_TRANSFER"
    else:
        decision = "TRANSFER_VALIDATED_RESEARCH_ONLY"
    content = {
        "authority": {"sealed_holdout_access": False, "submission_authorized": False},
        "decision": decision,
        "evidence": dict(sorted(evidence.items())),
        "gates": gates,
        "protocol_id": PROTOCOL_ID,
        "schema": GATE_SCHEMA,
        "sealed_holdout_access": False,
        "submission_authorized": False,
    }
    return {**content, "result_sha256": _hash(content)}


run_prevalidation_gate = prevalidation_gate


__all__ = [
    "CAMPAIGN_SCHEMA", "GateValidationError", "GATE_SCHEMA", "MODEL_INPUT_SCHEMA",
    "PREDECLARED_ALPHA", "PREDECLARED_BOOTSTRAP_RESAMPLES", "PREDECLARED_BOOTSTRAP_SEED",
    "PREDECLARED_LIFT_THRESHOLD_NATS", "PREDECLARED_MIN_TESTED_CALLS", "SAFETY_SCHEMA",
    "build_campaign", "build_model_input_record", "build_operational_safety_evidence",
    "prevalidation_gate", "run_prevalidation_gate", "validate_campaign",
    "validate_model_input_record", "validate_operational_safety",
]
