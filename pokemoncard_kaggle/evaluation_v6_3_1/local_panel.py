"""Retired caller-summary local-panel contract for Evaluation v6.3.1.

Only canonical transcript bytes are accepted. This module validates evidence
produced by an engine elsewhere; it never executes an engine, reads a holdout,
changes an agent, issues a permit, or uploads an archive.

The binding feature definitions now live in :mod:`trace_features`.  This older
schema cannot prove replayed legal actions, checkpoints, damage taxonomy, or
exact rational sufficient statistics, so it remains available only for legacy
negative conformance tests and can never emit an OfflineLocalFeatureCandidate.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import json
import re
import threading
from types import MappingProxyType
from typing import Any
import weakref


CONTROL_REGISTRY_SCHEMA = "eval.v6.3.1.local-control-registry"
CONTROL_ENTRY_SCHEMA = "eval.v6.3.1.local-control-entry"
PANEL_TRANSCRIPT_SCHEMA = "eval.v6.3.1.local-panel-transcript"
GAME_TRANSCRIPT_SCHEMA = "eval.v6.3.1.local-game-transcript"
PANEL_CANDIDATE_SCHEMA = "eval.v6.3.1.offline-local-panel-candidate"
FEATURE_CANDIDATE_SCHEMA = "eval.v6.3.1.offline-local-feature-candidate"
FEATURE_DERIVATION_SCHEMA = "eval.v6.3.1.local-feature-derivation"

CONTROL_LABELS = (
    "latest_runnable_claude",
    "latest_runnable_grok",
    "exact_codex_baseline",
    "frozen_top_deck",
)
SEATS = ("archive_first", "control_first")
SEED_INDEXES = tuple(range(300))
GAMES_PER_CONTROL = len(SEATS) * len(SEED_INDEXES)
EXPECTED_GAME_COUNT = len(CONTROL_LABELS) * GAMES_PER_CONTROL

FEATURE_NAMES = (
    "early_prize_tempo",
    "attack_readiness",
    "damage_efficiency",
    "viable_attacker_recovery",
    "resource_viability",
    "seat_robustness",
)
PRE_SEAT_FEATURE_NAMES = FEATURE_NAMES[:5]
FEATURE_SIGNS = (1, 1, 1, 1, 1, 1)
AGGREGATION_WEIGHTS = MappingProxyType(
    {
        "controls": "1/4",
        "seats_within_control": "1/2",
        "seeds_within_control_seat": "1/300",
        "features_in_x": "1/6",
    }
)

RAW_SUFFICIENT_STATISTIC_FIELDS = (
    "candidate_prizes_taken_through_turn_2",
    "control_prizes_taken_through_turn_2",
    "candidate_viable_attackers_turn_2",
    "control_viable_attackers_turn_2",
    "candidate_viable_attackers_turn_4",
    "control_viable_attackers_turn_4",
    "candidate_damage_delivered_through_turn_4",
    "control_damage_delivered_through_turn_4",
    "candidate_energy_attached_or_consumed_through_turn_4",
    "control_energy_attached_or_consumed_through_turn_4",
    "candidate_recovery_successes",
    "candidate_recovery_opportunities",
    "control_recovery_successes",
    "control_recovery_opportunities",
    "candidate_resource_viable_checkpoints",
    "candidate_resource_checkpoint_count",
    "control_resource_viable_checkpoints",
    "control_resource_checkpoint_count",
)

# F1-F5 preserve only what is currently known. The missing clauses are
# explicit so a future correction can close them without silently changing
# this contract. F6 is complete and is derived only after seat aggregates.
FEATURE_SPEC = MappingProxyType(
    {
        "early_prize_tempo": MappingProxyType(
            {
                "formula": "clip(signed candidate-control prize tempo through turn 2, -1, 1)",
                "raw_fields": RAW_SUFFICIENT_STATISTIC_FIELDS[0:2],
                "complete": False,
                "missing": "normalizing denominator and prize/checkpoint semantics",
            }
        ),
        "attack_readiness": MappingProxyType(
            {
                "formula": "clip(signed candidate-control attack readiness at turns 2 and 4, -1, 1)",
                "raw_fields": RAW_SUFFICIENT_STATISTIC_FIELDS[2:6],
                "complete": False,
                "missing": "turn-combination, viable-attacker definition, and normalizing denominator",
            }
        ),
        "damage_efficiency": MappingProxyType(
            {
                "formula": "clip(signed candidate-control damage per attached-or-consumed energy through turn 4, -1, 1)",
                "raw_fields": RAW_SUFFICIENT_STATISTIC_FIELDS[6:10],
                "complete": False,
                "missing": "zero-energy rule, damage scope, and normalization",
            }
        ),
        "viable_attacker_recovery": MappingProxyType(
            {
                "formula": "clip(signed candidate-control one-turn viable-attacker recovery rate, -1, 1)",
                "raw_fields": RAW_SUFFICIENT_STATISTIC_FIELDS[10:14],
                "complete": False,
                "missing": "opportunity/checkpoint definition and zero-opportunity rule",
            }
        ),
        "resource_viability": MappingProxyType(
            {
                "formula": "clip(signed candidate-control resource-viability rate, -1, 1)",
                "raw_fields": RAW_SUFFICIENT_STATISTIC_FIELDS[14:18],
                "complete": False,
                "missing": "checkpoint schedule, viability predicate, and zero-checkpoint rule",
            }
        ),
        "seat_robustness": MappingProxyType(
            {
                "formula": "-abs(Mpre1-Mpre2)/2",
                "raw_fields": (),
                "complete": True,
                "missing": None,
            }
        ),
    }
)
FEATURE_SPEC_STATE = "LEGACY_SUMMARY_PANEL_RETIRED"

GAME_POINT_FORMULA = MappingProxyType(
    {
        "candidate": "1",
        "draw": "1/2",
        "control": "0",
        "archive_R": "2*archive_point_rate-1",
    }
)

_CONTROL_ENTRY_FIELDS = frozenset(
    {
        "schema",
        "label",
        "archive_sha256",
        "source_root_sha256",
        "deck_sha256",
        "policy_sha256",
        "runtime_sha256",
    }
)
_CONTROL_REGISTRY_FIELDS = frozenset({"schema", "entries"})
_PANEL_TRANSCRIPT_FIELDS = frozenset({"schema", "games"})
_GAME_FIELDS = frozenset(
    {
        "schema",
        "candidate_archive_sha256",
        "candidate_source_root_sha256",
        "candidate_deck_sha256",
        "candidate_policy_sha256",
        "runtime_engine_root_sha256",
        "control_label",
        "control_entry_sha256",
        "seat",
        "seed_index",
        "rng_seed_sha256",
        "status",
        "error",
        "events",
        "raw_sufficient_statistics",
        "trace_root_sha256",
    }
)
_EVENT_FIELDS = frozenset({"sequence", "event_type", "actor", "facts"})
_GAME_END_FACT_FIELDS = frozenset({"terminal_category", "winner"})
_FORBIDDEN_CALLER_DERIVED_FIELDS = frozenset(
    {
        "archive_game_points",
        "derived_game_points",
        "feature_values",
        "normalized_feature_values",
        "mechanics_vector",
        "mechanics_x",
        "archive_point_rate",
        "archive_r",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_EVENT_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

_DOMAIN_CONTROL_ENTRY = b"EVAL-V631/LOCAL-CONTROL-ENTRY\0"
_DOMAIN_CONTROL_REGISTRY = b"EVAL-V631/LOCAL-CONTROL-REGISTRY\0"
_DOMAIN_RNG_SEED = b"EVAL-V631/LOCAL-RNG-SEED\0"
_DOMAIN_GAME_TRACE = b"EVAL-V631/LOCAL-GAME-TRACE\0"
_DOMAIN_PANEL_LEAF = b"EVAL-V631/LOCAL-PANEL-LEAF\0"
_DOMAIN_PANEL_NODE = b"EVAL-V631/LOCAL-PANEL-NODE\0"
_DOMAIN_PANEL_CANDIDATE = b"EVAL-V631/LOCAL-PANEL-CANDIDATE\0"
_DOMAIN_FEATURE_CANDIDATE = b"EVAL-V631/LOCAL-FEATURE-CANDIDATE\0"
_DOMAIN_FEATURE_DERIVATION = b"EVAL-V631/LOCAL-FEATURE-DERIVATION\0"

_REGISTRY_TOKEN = object()
_PANEL_TOKEN = object()
_FEATURE_TOKEN = object()
_DERIVATION_TOKEN = object()
_ISSUANCE_LOCK = threading.RLock()


@dataclass(frozen=True)
class _IssuanceRecord:
    object_ref: weakref.ReferenceType[Any]
    snapshot: tuple[Any, ...]


_ISSUED_OBJECTS: dict[type[Any], dict[int, _IssuanceRecord]] = {}


class LocalPanelError(ValueError):
    """A local-panel input or typed artifact failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> LocalPanelError:
    return LocalPanelError(code, message)


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _fail("CANONICAL_JSON_INVALID", "value is not canonical JSON") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _domain_hash(domain: bytes, value: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail("CANONICAL_JSON_INVALID", f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise _fail("CANONICAL_JSON_INVALID", f"floating-point literal is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise _fail("CANONICAL_JSON_INVALID", f"non-finite JSON value is forbidden: {value}")


def parse_canonical_transcript(payload: bytes) -> dict[str, Any]:
    """Parse byte-exact canonical JSON with duplicate-key/float rejection."""

    if type(payload) is not bytes:
        raise _fail("CANONICAL_JSON_INVALID", "input must be canonical transcript bytes")
    try:
        parsed = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except LocalPanelError:
        raise
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("CANONICAL_JSON_INVALID", "input is not valid JSON") from exc
    if type(parsed) is not dict:
        raise _fail("CANONICAL_JSON_INVALID", "canonical transcript root must be an object")
    if canonical_json_bytes(parsed) != payload:
        raise _fail("CANONICAL_JSON_INVALID", "input bytes are not canonical")
    return parsed


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _exact(value: Any, fields: frozenset[str], label: str, *, code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise _fail(code, f"{label} fields must be exact")
    return value


def _reject_caller_derived_fields(value: Any, label: str) -> None:
    if type(value) is dict:
        overlap = set(value).intersection(_FORBIDDEN_CALLER_DERIVED_FIELDS)
        if overlap:
            raise _fail(
                "CALLER_DERIVED_VALUE_FORBIDDEN",
                f"{label} contains caller-derived fields {sorted(overlap)}",
            )
        for key, item in value.items():
            _reject_caller_derived_fields(item, f"{label}.{key}")
    elif type(value) is list:
        for index, item in enumerate(value):
            _reject_caller_derived_fields(item, f"{label}[{index}]")


def _sha256(value: Any, label: str, *, code: str = "ROOT_BINDING_INVALID") -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail(code, f"{label} must be lowercase SHA-256 hex")
    return value


def _decimal(value: Any, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise _fail("FEATURE_INPUT_INVALID", f"{label} must be a canonical decimal")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise _fail("FEATURE_INPUT_INVALID", f"{label} is not decimal") from exc
    if not result.is_finite() or (value.startswith("-") and result == 0):
        raise _fail("FEATURE_INPUT_INVALID", f"{label} must be finite")
    return result


def _decimal_text(value: Decimal) -> str:
    text = format(value.normalize(), "f")
    return "0" if text in {"", "-0"} else text


def _fraction_text(value: Fraction) -> str:
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator}/{value.denominator}"


def _clip(value: Decimal) -> Decimal:
    return min(Decimal(1), max(Decimal(-1), value))


def control_entry_sha256(entry: Mapping[str, Any]) -> str:
    return _domain_hash(_DOMAIN_CONTROL_ENTRY, dict(entry))


def derive_rng_seed(
    candidate_archive_sha256: str,
    control_archive_sha256: str,
    seat: str,
    seed_index: int,
    runtime_engine_root_sha256: str,
) -> str:
    """Derive the sole RNG seed for one frozen panel cell."""

    candidate = _sha256(candidate_archive_sha256, "candidate archive")
    control = _sha256(control_archive_sha256, "control archive")
    runtime = _sha256(runtime_engine_root_sha256, "runtime/engine root")
    if seat not in SEATS or type(seat) is not str:
        raise _fail("RNG_SEED_INVALID", "seat is outside the frozen two-seat set")
    if type(seed_index) is not int or type(seed_index) is bool or seed_index not in SEED_INDEXES:
        raise _fail("RNG_SEED_INVALID", "seed_index is outside [0, 299]")
    return _domain_hash(
        _DOMAIN_RNG_SEED,
        {
            "candidate_archive_sha256": candidate,
            "control_archive_sha256": control,
            "seat": seat,
            "seed_index": seed_index,
            "runtime_engine_root_sha256": runtime,
        },
    )


def derive_game_trace_root(game_without_trace_root: Mapping[str, Any]) -> str:
    """Root every canonical game fact except its self-hash field."""

    if not isinstance(game_without_trace_root, Mapping):
        raise _fail("TRACE_ROOT_INVALID", "game trace core must be a mapping")
    core = dict(game_without_trace_root)
    if "trace_root_sha256" in core:
        raise _fail("TRACE_ROOT_INVALID", "game trace core must exclude trace_root_sha256")
    return _domain_hash(_DOMAIN_GAME_TRACE, core)


def canonical_panel_merkle_root(trace_roots: tuple[str, ...]) -> str:
    """Build the canonical ordered SHA-256 tree, duplicating an odd tail."""

    if not trace_roots:
        raise _fail("PANEL_MERKLE_INVALID", "panel Merkle tree must not be empty")
    level = [
        hashlib.sha256(
            _DOMAIN_PANEL_LEAF + index.to_bytes(8, "big") + bytes.fromhex(
                _sha256(root, f"trace root {index}", code="PANEL_MERKLE_INVALID")
            )
        ).digest()
        for index, root in enumerate(trace_roots)
    ]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(_DOMAIN_PANEL_NODE + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def derive_seat_robustness(mpre1: str, mpre2: str) -> str:
    """Apply the corrected penalty-only F6 for legacy conformance tests."""

    left = _decimal(mpre1, "Mpre1")
    right = _decimal(mpre2, "Mpre2")
    if not Decimal(-1) <= left <= Decimal(1) or not Decimal(-1) <= right <= Decimal(1):
        raise _fail("FEATURE_INPUT_INVALID", "Mpre seat aggregates must lie in [-1, 1]")
    value = -abs(left - right) / Decimal(2)
    return _decimal_text(_clip(value))


@dataclass(frozen=True)
class VerifiedControlRegistry:
    schema: str
    entries: tuple[Mapping[str, Any], ...]
    content_sha256: str
    canonical_bytes: bytes
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _REGISTRY_TOKEN:
            raise ValueError("control registries require the verifier construction token")


@dataclass(frozen=True)
class OfflineLocalPanelCandidate:
    schema: str
    candidate_archive_sha256: str
    candidate_source_root_sha256: str
    candidate_deck_sha256: str
    candidate_policy_sha256: str
    runtime_engine_root_sha256: str
    control_registry_root_sha256: str
    control_registry: VerifiedControlRegistry
    canonical_transcript_bytes: bytes
    transcript_payload_sha256: str
    panel_merkle_root_sha256: str
    diagnostics_root_sha256: str
    game_count: int
    games: tuple[Mapping[str, Any], ...]
    archive_point_rate: str
    archive_r: str
    feature_spec_state: str
    authority: bool
    calibration_upload_authorized: bool
    production_upload_authorized: bool
    sealed_holdout_access_authorized: bool
    agent_modification_authorized: bool
    permits: tuple[object, ...]
    content_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _PANEL_TOKEN:
            raise ValueError("offline panel candidates require the verifier construction token")
        _require_zero_authority_fields(self)


@dataclass(frozen=True)
class OfflineLocalFeatureCandidate:
    schema: str
    panel_candidate: OfflineLocalPanelCandidate
    panel_content_sha256: str
    mechanics_vector: tuple[str, str, str, str, str, str]
    mechanics_x: str
    archive_r: str
    canonical_feature_bytes: bytes
    authority: bool
    calibration_upload_authorized: bool
    production_upload_authorized: bool
    sealed_holdout_access_authorized: bool
    agent_modification_authorized: bool
    permits: tuple[object, ...]
    content_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _FEATURE_TOKEN:
            raise ValueError("offline feature candidates require the verifier construction token")
        _require_zero_authority_fields(self)


@dataclass(frozen=True)
class LocalFeatureDerivation:
    schema: str
    state: str
    panel_candidate: OfflineLocalPanelCandidate
    panel_content_sha256: str
    feature_candidate: OfflineLocalFeatureCandidate | None
    report: Mapping[str, Any]
    canonical_report_bytes: bytes
    authority: bool
    calibration_upload_authorized: bool
    production_upload_authorized: bool
    sealed_holdout_access_authorized: bool
    agent_modification_authorized: bool
    permits: tuple[object, ...]
    content_sha256: str
    _construction_token: object

    def __post_init__(self) -> None:
        if self._construction_token is not _DERIVATION_TOKEN:
            raise ValueError("feature derivations require the verifier construction token")
        _require_zero_authority_fields(self)


def _require_zero_authority_fields(value: Any) -> None:
    if (
        value.authority is not False
        or value.calibration_upload_authorized is not False
        or value.production_upload_authorized is not False
        or value.sealed_holdout_access_authorized is not False
        or value.agent_modification_authorized is not False
        or value.permits != ()
    ):
        raise ValueError("offline local artifacts must remain zero-authority")


def _issued_snapshot(value: Any) -> tuple[Any, ...]:
    if type(value) is VerifiedControlRegistry:
        return (
            "VerifiedControlRegistry",
            value.schema,
            canonical_sha256([_thaw(entry) for entry in value.entries]),
            value.content_sha256,
            hashlib.sha256(value.canonical_bytes).hexdigest(),
            id(value._construction_token),
        )
    if type(value) is OfflineLocalPanelCandidate:
        return (
            "OfflineLocalPanelCandidate",
            value.schema,
            value.candidate_archive_sha256,
            value.candidate_source_root_sha256,
            value.candidate_deck_sha256,
            value.candidate_policy_sha256,
            value.runtime_engine_root_sha256,
            value.control_registry_root_sha256,
            id(value.control_registry),
            hashlib.sha256(value.canonical_transcript_bytes).hexdigest(),
            value.transcript_payload_sha256,
            value.panel_merkle_root_sha256,
            value.diagnostics_root_sha256,
            value.game_count,
            canonical_sha256([_thaw(game) for game in value.games]),
            value.archive_point_rate,
            value.archive_r,
            value.feature_spec_state,
            value.authority,
            value.calibration_upload_authorized,
            value.production_upload_authorized,
            value.sealed_holdout_access_authorized,
            value.agent_modification_authorized,
            value.permits,
            value.content_sha256,
            id(value._construction_token),
        )
    if type(value) is OfflineLocalFeatureCandidate:
        return (
            "OfflineLocalFeatureCandidate",
            value.schema,
            id(value.panel_candidate),
            value.panel_content_sha256,
            value.mechanics_vector,
            value.mechanics_x,
            value.archive_r,
            hashlib.sha256(value.canonical_feature_bytes).hexdigest(),
            value.authority,
            value.calibration_upload_authorized,
            value.production_upload_authorized,
            value.sealed_holdout_access_authorized,
            value.agent_modification_authorized,
            value.permits,
            value.content_sha256,
            id(value._construction_token),
        )
    if type(value) is LocalFeatureDerivation:
        return (
            "LocalFeatureDerivation",
            value.schema,
            value.state,
            id(value.panel_candidate),
            value.panel_content_sha256,
            None if value.feature_candidate is None else id(value.feature_candidate),
            canonical_sha256(_thaw(value.report)),
            hashlib.sha256(value.canonical_report_bytes).hexdigest(),
            value.authority,
            value.calibration_upload_authorized,
            value.production_upload_authorized,
            value.sealed_holdout_access_authorized,
            value.agent_modification_authorized,
            value.permits,
            value.content_sha256,
            id(value._construction_token),
        )
    raise TypeError("unsupported issued local-panel object")


def _register_issued(value: Any) -> Any:
    object_type = type(value)
    object_id = id(value)
    snapshot = _issued_snapshot(value)

    def remove(reference: weakref.ReferenceType[Any]) -> None:
        with _ISSUANCE_LOCK:
            by_type = _ISSUED_OBJECTS.get(object_type)
            if by_type is None:
                return
            current = by_type.get(object_id)
            if current is not None and current.object_ref is reference:
                del by_type[object_id]
            if not by_type:
                _ISSUED_OBJECTS.pop(object_type, None)

    reference = weakref.ref(value, remove)
    with _ISSUANCE_LOCK:
        by_type = _ISSUED_OBJECTS.setdefault(object_type, {})
        existing = by_type.get(object_id)
        if existing is not None and existing.object_ref() is not None:
            raise RuntimeError("issued-object identity collision")
        by_type[object_id] = _IssuanceRecord(reference, snapshot)
    return value


def _require_issued(value: Any, expected_type: type[Any]) -> None:
    if type(value) is not expected_type:
        raise _fail(
            "VERIFIER_IDENTITY_INVALID",
            f"value must be the exact issued {expected_type.__name__}",
        )
    with _ISSUANCE_LOCK:
        record = _ISSUED_OBJECTS.get(expected_type, {}).get(id(value))
    if record is None or record.object_ref() is not value:
        raise _fail(
            "VERIFIER_IDENTITY_INVALID",
            f"{expected_type.__name__} identity was not issued by this verifier",
        )
    try:
        current_snapshot = _issued_snapshot(value)
    except Exception as exc:
        raise _fail(
            "VERIFIER_IDENTITY_INVALID",
            f"issued {expected_type.__name__} has malformed mutated fields",
        ) from exc
    if record.snapshot != current_snapshot:
        raise _fail(
            "VERIFIER_IDENTITY_INVALID",
            f"issued {expected_type.__name__} was mutated after issuance",
        )


def _registry_core(entries: tuple[Mapping[str, Any], ...]) -> dict[str, Any]:
    return {
        "schema": CONTROL_REGISTRY_SCHEMA,
        "entries": [_thaw(entry) for entry in entries],
    }


def _validate_control_registry_bytes(
    payload: bytes,
) -> tuple[tuple[Mapping[str, Any], ...], str]:
    raw = parse_canonical_transcript(payload)
    registry = _exact(
        raw,
        _CONTROL_REGISTRY_FIELDS,
        "control registry",
        code="CONTROL_REGISTRY_INVALID",
    )
    if registry["schema"] != CONTROL_REGISTRY_SCHEMA or type(registry["entries"]) is not list:
        raise _fail("CONTROL_REGISTRY_INVALID", "control registry schema or entries are invalid")
    if len(registry["entries"]) != len(CONTROL_LABELS):
        raise _fail("CONTROL_REGISTRY_INVALID", "control registry must contain exactly four entries")

    entries: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(registry["entries"]):
        entry = _exact(
            raw_entry,
            _CONTROL_ENTRY_FIELDS,
            f"control entry {index}",
            code="CONTROL_REGISTRY_INVALID",
        )
        expected_label = CONTROL_LABELS[index]
        if entry["schema"] != CONTROL_ENTRY_SCHEMA or entry["label"] != expected_label:
            raise _fail("CONTROL_REGISTRY_INVALID", "control labels must be exact and canonically ordered")
        normalized = {
            "schema": CONTROL_ENTRY_SCHEMA,
            "label": expected_label,
            "archive_sha256": _sha256(entry["archive_sha256"], f"{expected_label} archive"),
            "source_root_sha256": _sha256(entry["source_root_sha256"], f"{expected_label} source"),
            "deck_sha256": _sha256(entry["deck_sha256"], f"{expected_label} deck"),
            "policy_sha256": _sha256(entry["policy_sha256"], f"{expected_label} policy"),
            "runtime_sha256": _sha256(entry["runtime_sha256"], f"{expected_label} runtime"),
        }
        normalized["entry_sha256"] = control_entry_sha256(normalized)
        entries.append(normalized)
    frozen_entries = tuple(_freeze(entry) for entry in entries)
    content_root = _domain_hash(_DOMAIN_CONTROL_REGISTRY, _registry_core(frozen_entries))
    return frozen_entries, content_root


def verify_control_registry(payload: bytes) -> VerifiedControlRegistry:
    entries, content_root = _validate_control_registry_bytes(payload)
    issued = VerifiedControlRegistry(
        CONTROL_REGISTRY_SCHEMA,
        entries,
        content_root,
        payload,
        _REGISTRY_TOKEN,
    )
    return _register_issued(issued)


def revalidate_control_registry(value: Any) -> VerifiedControlRegistry:
    _require_issued(value, VerifiedControlRegistry)
    entries, content_root = _validate_control_registry_bytes(value.canonical_bytes)
    if [_thaw(entry) for entry in value.entries] != [_thaw(entry) for entry in entries]:
        raise _fail("VERIFIED_INPUT_INVALID", "typed control entries differ from retained canonical bytes")
    if value.content_sha256 != content_root:
        raise _fail("VERIFIED_INPUT_INVALID", "typed control registry root differs from retained bytes")
    return value


def _validate_raw_statistics(value: Any, label: str) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(RAW_SUFFICIENT_STATISTIC_FIELDS):
        raise _fail("RAW_STATISTICS_INVALID", f"{label} raw statistic fields are not exact")
    checked: dict[str, int] = {}
    for field in RAW_SUFFICIENT_STATISTIC_FIELDS:
        item = value[field]
        if type(item) is not int or type(item) is bool or not 0 <= item <= 1_000_000_000:
            raise _fail("RAW_STATISTICS_INVALID", f"{label}.{field} must be a bounded nonnegative integer")
        checked[field] = item
    if checked["candidate_recovery_successes"] > checked["candidate_recovery_opportunities"]:
        raise _fail("RAW_STATISTICS_INVALID", f"{label} candidate recovery successes exceed opportunities")
    if checked["control_recovery_successes"] > checked["control_recovery_opportunities"]:
        raise _fail("RAW_STATISTICS_INVALID", f"{label} control recovery successes exceed opportunities")
    if checked["candidate_resource_viable_checkpoints"] > checked["candidate_resource_checkpoint_count"]:
        raise _fail("RAW_STATISTICS_INVALID", f"{label} candidate viable checkpoints exceed checkpoints")
    if checked["control_resource_viable_checkpoints"] > checked["control_resource_checkpoint_count"]:
        raise _fail("RAW_STATISTICS_INVALID", f"{label} control viable checkpoints exceed checkpoints")
    return checked


def _validate_events(value: Any, label: str) -> tuple[list[dict[str, Any]], Fraction]:
    if type(value) is not list or not value:
        raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} events must be a nonempty list")
    events: list[dict[str, Any]] = []
    game_end_count = 0
    points: Fraction | None = None
    for index, raw in enumerate(value):
        event = _exact(raw, _EVENT_FIELDS, f"{label}.events[{index}]", code="GAME_TRANSCRIPT_INVALID")
        if event["sequence"] != index or type(event["sequence"]) is not int:
            raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} event sequence is not contiguous")
        if type(event["event_type"]) is not str or _EVENT_TYPE_RE.fullmatch(event["event_type"]) is None:
            raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} event type is invalid")
        if event["actor"] not in {"candidate", "control", "system"} or type(event["actor"]) is not str:
            raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} event actor is invalid")
        if type(event["facts"]) is not dict:
            raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} event facts must be an object")
        if event["event_type"] == "GAME_END":
            game_end_count += 1
            facts = _exact(
                event["facts"],
                _GAME_END_FACT_FIELDS,
                f"{label} GAME_END facts",
                code="GAME_TRANSCRIPT_INVALID",
            )
            if event["actor"] != "system" or facts["terminal_category"] != "completed":
                raise _fail("GAME_NOT_ERROR_FREE", f"{label} GAME_END is not a completed system event")
            if facts["winner"] == "candidate":
                points = Fraction(1)
            elif facts["winner"] == "draw":
                points = Fraction(1, 2)
            elif facts["winner"] == "control":
                points = Fraction(0)
            else:
                raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} winner is invalid")
        events.append(
            {
                "sequence": index,
                "event_type": event["event_type"],
                "actor": event["actor"],
                "facts": event["facts"],
            }
        )
    if game_end_count != 1 or events[-1]["event_type"] != "GAME_END" or points is None:
        raise _fail("GAME_NOT_ERROR_FREE", f"{label} requires one final completed GAME_END")
    return events, points


def _expected_keys() -> tuple[tuple[str, str, int], ...]:
    return tuple(
        (control, seat, seed_index)
        for control in CONTROL_LABELS
        for seat in SEATS
        for seed_index in SEED_INDEXES
    )


def _validate_game(
    raw_game: Any,
    *,
    index: int,
    candidate_bindings: Mapping[str, str],
    runtime_engine_root_sha256: str,
    control_by_label: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], Fraction]:
    label = f"games[{index}]"
    game = _exact(raw_game, _GAME_FIELDS, label, code="GAME_TRANSCRIPT_INVALID")
    if game["schema"] != GAME_TRANSCRIPT_SCHEMA:
        raise _fail("GAME_TRANSCRIPT_INVALID", f"{label} schema is invalid")
    for field, expected in candidate_bindings.items():
        if _sha256(game[field], f"{label}.{field}") != expected:
            raise _fail("ROOT_BINDING_INVALID", f"{label}.{field} does not bind the candidate")
    if _sha256(game["runtime_engine_root_sha256"], f"{label}.runtime") != runtime_engine_root_sha256:
        raise _fail("ROOT_BINDING_INVALID", f"{label} runtime/engine root does not bind the panel")
    control_label = game["control_label"]
    if type(control_label) is not str or control_label not in control_by_label:
        raise _fail("CONTROL_BINDING_INVALID", f"{label} control label is unknown")
    control = control_by_label[control_label]
    if game["control_entry_sha256"] != control["entry_sha256"]:
        raise _fail("CONTROL_BINDING_INVALID", f"{label} does not bind its selected control entry")
    if game["seat"] not in SEATS or type(game["seat"]) is not str:
        raise _fail("PANEL_COVERAGE_INVALID", f"{label} seat is invalid")
    if type(game["seed_index"]) is not int or type(game["seed_index"]) is bool or game["seed_index"] not in SEED_INDEXES:
        raise _fail("PANEL_COVERAGE_INVALID", f"{label} seed_index is invalid")
    expected_seed = derive_rng_seed(
        candidate_bindings["candidate_archive_sha256"],
        control["archive_sha256"],
        game["seat"],
        game["seed_index"],
        runtime_engine_root_sha256,
    )
    if game["rng_seed_sha256"] != expected_seed:
        raise _fail("RNG_SEED_INVALID", f"{label} RNG seed is substituted or stale")
    if game["status"] != "COMPLETE" or game["error"] is not None:
        raise _fail("GAME_NOT_ERROR_FREE", f"{label} is not completed error-free")
    events, points = _validate_events(game["events"], label)
    statistics = _validate_raw_statistics(game["raw_sufficient_statistics"], label)

    core = {
        "schema": GAME_TRANSCRIPT_SCHEMA,
        **candidate_bindings,
        "runtime_engine_root_sha256": runtime_engine_root_sha256,
        "control_label": control_label,
        "control_entry_sha256": control["entry_sha256"],
        "seat": game["seat"],
        "seed_index": game["seed_index"],
        "rng_seed_sha256": expected_seed,
        "status": "COMPLETE",
        "error": None,
        "events": events,
        "raw_sufficient_statistics": statistics,
    }
    expected_trace = derive_game_trace_root(core)
    if game["trace_root_sha256"] != expected_trace:
        raise _fail("TRACE_ROOT_INVALID", f"{label} trace root is stale or substituted")
    return {
        **core,
        "trace_root_sha256": expected_trace,
        "derived_game_points": _fraction_text(points),
    }, points


def _balanced_archive_point_rate(
    games: tuple[Mapping[str, Any], ...],
) -> tuple[Fraction, str]:
    diagnostics: list[dict[str, Any]] = []
    control_rates: list[Fraction] = []
    for control in CONTROL_LABELS:
        seat_rates: list[Fraction] = []
        for seat in SEATS:
            rows = [
                game
                for game in games
                if game["control_label"] == control and game["seat"] == seat
            ]
            if len(rows) != len(SEED_INDEXES):
                raise _fail("PANEL_COVERAGE_INVALID", "balanced aggregation lacks an exact seed stratum")
            rate = sum(
                (Fraction(game["derived_game_points"]) for game in rows),
                Fraction(0),
            ) / len(SEED_INDEXES)
            seat_rates.append(rate)
            diagnostics.append(
                {
                    "control_label": control,
                    "seat": seat,
                    "point_rate": _fraction_text(rate),
                }
            )
        control_rates.append(sum(seat_rates, Fraction(0)) / len(SEATS))
    archive_rate = sum(control_rates, Fraction(0)) / len(CONTROL_LABELS)
    diagnostics_root = canonical_sha256(
        {
            "schema": "eval.v6.3.1.local-nonselectable-diagnostics",
            "aggregation_order": ["control", "seat", "seed_index"],
            "strata": diagnostics,
        }
    )
    return archive_rate, diagnostics_root


def _replay_panel_transcript(
    transcript_payload: bytes,
    registry: VerifiedControlRegistry,
    candidate_bindings: Mapping[str, str],
    runtime_engine_root_sha256: str,
) -> tuple[tuple[Mapping[str, Any], ...], str, Fraction, str]:
    raw = parse_canonical_transcript(transcript_payload)
    _reject_caller_derived_fields(raw, "panel transcript")
    panel = _exact(
        raw,
        _PANEL_TRANSCRIPT_FIELDS,
        "panel transcript",
        code="PANEL_COVERAGE_INVALID",
    )
    if panel["schema"] != PANEL_TRANSCRIPT_SCHEMA or type(panel["games"]) is not list:
        raise _fail("PANEL_COVERAGE_INVALID", "panel transcript schema or games are invalid")
    if len(panel["games"]) != EXPECTED_GAME_COUNT:
        raise _fail("PANEL_COVERAGE_INVALID", f"panel must contain exactly {EXPECTED_GAME_COUNT} games")

    control_by_label = {entry["label"]: entry for entry in registry.entries}
    checked: list[dict[str, Any]] = []
    observed_keys: list[tuple[str, str, int]] = []
    for index, raw_game in enumerate(panel["games"]):
        game, _ = _validate_game(
            raw_game,
            index=index,
            candidate_bindings=candidate_bindings,
            runtime_engine_root_sha256=runtime_engine_root_sha256,
            control_by_label=control_by_label,
        )
        checked.append(game)
        observed_keys.append((game["control_label"], game["seat"], game["seed_index"]))
    if len(set(observed_keys)) != EXPECTED_GAME_COUNT:
        raise _fail("PANEL_DUPLICATE_GAME", "panel contains duplicate control/seat/seed-index cells")
    if tuple(observed_keys) != _expected_keys():
        raise _fail("PANEL_COVERAGE_INVALID", "panel order or exact control/seat/seed-index coverage is invalid")
    trace_roots = tuple(game["trace_root_sha256"] for game in checked)
    if len(set(trace_roots)) != EXPECTED_GAME_COUNT:
        raise _fail("TRACE_ROOT_INVALID", "game trace roots must be unique")
    panel_merkle = canonical_panel_merkle_root(trace_roots)
    frozen_games = tuple(_freeze(game) for game in checked)
    point_rate, diagnostics_root = _balanced_archive_point_rate(frozen_games)
    return frozen_games, panel_merkle, point_rate, diagnostics_root


def _panel_core(value: OfflineLocalPanelCandidate) -> dict[str, Any]:
    return {
        "schema": value.schema,
        "candidate_archive_sha256": value.candidate_archive_sha256,
        "candidate_source_root_sha256": value.candidate_source_root_sha256,
        "candidate_deck_sha256": value.candidate_deck_sha256,
        "candidate_policy_sha256": value.candidate_policy_sha256,
        "runtime_engine_root_sha256": value.runtime_engine_root_sha256,
        "control_registry_root_sha256": value.control_registry_root_sha256,
        "control_registry_bytes_sha256": hashlib.sha256(
            value.control_registry.canonical_bytes
        ).hexdigest(),
        "transcript_payload_sha256": value.transcript_payload_sha256,
        "panel_merkle_root_sha256": value.panel_merkle_root_sha256,
        "diagnostics_root_sha256": value.diagnostics_root_sha256,
        "game_count": value.game_count,
        "games": [_thaw(game) for game in value.games],
        "archive_point_rate": value.archive_point_rate,
        "archive_r": value.archive_r,
        "feature_spec_state": value.feature_spec_state,
        "authority": value.authority,
        "calibration_upload_authorized": value.calibration_upload_authorized,
        "production_upload_authorized": value.production_upload_authorized,
        "sealed_holdout_access_authorized": value.sealed_holdout_access_authorized,
        "agent_modification_authorized": value.agent_modification_authorized,
        "permits": list(value.permits),
    }


def verify_local_panel(
    transcript_payload: bytes,
    control_registry: VerifiedControlRegistry,
    *,
    candidate_archive_sha256: str,
    candidate_source_root_sha256: str,
    candidate_deck_sha256: str,
    candidate_policy_sha256: str,
    runtime_engine_root_sha256: str,
) -> OfflineLocalPanelCandidate:
    """Validate the exact transcript grid and derive one archive-level R."""

    registry = revalidate_control_registry(control_registry)
    candidate_bindings = {
        "candidate_archive_sha256": _sha256(candidate_archive_sha256, "candidate archive"),
        "candidate_source_root_sha256": _sha256(candidate_source_root_sha256, "candidate source"),
        "candidate_deck_sha256": _sha256(candidate_deck_sha256, "candidate deck"),
        "candidate_policy_sha256": _sha256(candidate_policy_sha256, "candidate policy"),
    }
    runtime_root = _sha256(runtime_engine_root_sha256, "runtime/engine root")
    frozen_games, panel_merkle, point_rate, diagnostics_root = _replay_panel_transcript(
        transcript_payload,
        registry,
        candidate_bindings,
        runtime_root,
    )
    archive_r = Fraction(2) * point_rate - Fraction(1)

    draft = OfflineLocalPanelCandidate(
        schema=PANEL_CANDIDATE_SCHEMA,
        **candidate_bindings,
        runtime_engine_root_sha256=runtime_root,
        control_registry_root_sha256=registry.content_sha256,
        control_registry=registry,
        canonical_transcript_bytes=transcript_payload,
        transcript_payload_sha256=hashlib.sha256(transcript_payload).hexdigest(),
        panel_merkle_root_sha256=panel_merkle,
        diagnostics_root_sha256=diagnostics_root,
        game_count=EXPECTED_GAME_COUNT,
        games=frozen_games,
        archive_point_rate=_fraction_text(point_rate),
        archive_r=_fraction_text(archive_r),
        feature_spec_state=FEATURE_SPEC_STATE,
        authority=False,
        calibration_upload_authorized=False,
        production_upload_authorized=False,
        sealed_holdout_access_authorized=False,
        agent_modification_authorized=False,
        permits=(),
        content_sha256="",
        _construction_token=_PANEL_TOKEN,
    )
    issued = OfflineLocalPanelCandidate(
        **{
            **draft.__dict__,
            "content_sha256": _domain_hash(_DOMAIN_PANEL_CANDIDATE, _panel_core(draft)),
        }
    )
    return _register_issued(issued)


def revalidate_offline_local_panel_candidate(value: Any) -> OfflineLocalPanelCandidate:
    _require_issued(value, OfflineLocalPanelCandidate)
    _require_zero_authority_fields(value)
    if value.schema != PANEL_CANDIDATE_SCHEMA or value.feature_spec_state != FEATURE_SPEC_STATE:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel schema or feature state is invalid")
    for field in (
        "candidate_archive_sha256",
        "candidate_source_root_sha256",
        "candidate_deck_sha256",
        "candidate_policy_sha256",
        "runtime_engine_root_sha256",
        "control_registry_root_sha256",
        "transcript_payload_sha256",
        "panel_merkle_root_sha256",
        "diagnostics_root_sha256",
        "content_sha256",
    ):
        _sha256(getattr(value, field), field, code="VERIFIED_INPUT_INVALID")
    registry = value.control_registry
    revalidate_control_registry(registry)
    if value.control_registry_root_sha256 != registry.content_sha256:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel registry binding is stale")
    if value.transcript_payload_sha256 != hashlib.sha256(
        value.canonical_transcript_bytes
    ).hexdigest():
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel retained transcript hash is stale")
    candidate_bindings = {
        "candidate_archive_sha256": value.candidate_archive_sha256,
        "candidate_source_root_sha256": value.candidate_source_root_sha256,
        "candidate_deck_sha256": value.candidate_deck_sha256,
        "candidate_policy_sha256": value.candidate_policy_sha256,
    }
    games, panel_merkle, point_rate, diagnostics_root = _replay_panel_transcript(
        value.canonical_transcript_bytes,
        registry,
        candidate_bindings,
        value.runtime_engine_root_sha256,
    )
    if [_thaw(game) for game in value.games] != [_thaw(game) for game in games]:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel games differ from retained transcript bytes")
    if value.game_count != EXPECTED_GAME_COUNT or len(value.games) != EXPECTED_GAME_COUNT:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel game count is stale")
    if value.panel_merkle_root_sha256 != panel_merkle:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel Merkle root differs from retained bytes")
    if value.archive_point_rate != _fraction_text(point_rate):
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel point rate differs from retained bytes")
    if value.archive_r != _fraction_text(Fraction(2) * point_rate - Fraction(1)):
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel R differs from retained bytes")
    if value.diagnostics_root_sha256 != diagnostics_root:
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel diagnostics differ from retained bytes")
    if value.content_sha256 != _domain_hash(_DOMAIN_PANEL_CANDIDATE, _panel_core(value)):
        raise _fail("VERIFIED_INPUT_INVALID", "offline panel content root is stale")
    return value


def _feature_candidate_core(value: OfflineLocalFeatureCandidate) -> dict[str, Any]:
    return {
        "schema": value.schema,
        "panel_content_sha256": value.panel_content_sha256,
        "mechanics_vector": list(value.mechanics_vector),
        "mechanics_x": value.mechanics_x,
        "archive_r": value.archive_r,
        "canonical_feature_bytes_sha256": hashlib.sha256(
            value.canonical_feature_bytes
        ).hexdigest(),
        "authority": value.authority,
        "calibration_upload_authorized": value.calibration_upload_authorized,
        "production_upload_authorized": value.production_upload_authorized,
        "sealed_holdout_access_authorized": value.sealed_holdout_access_authorized,
        "agent_modification_authorized": value.agent_modification_authorized,
        "permits": list(value.permits),
    }


def revalidate_offline_local_feature_candidate(value: Any) -> OfflineLocalFeatureCandidate:
    _require_issued(value, OfflineLocalFeatureCandidate)
    _require_zero_authority_fields(value)
    panel = revalidate_offline_local_panel_candidate(value.panel_candidate)
    if value.panel_content_sha256 != panel.content_sha256:
        raise _fail("VERIFIED_INPUT_INVALID", "offline feature panel identity is stale")
    if value.schema != FEATURE_CANDIDATE_SCHEMA or len(value.mechanics_vector) != len(FEATURE_NAMES):
        raise _fail("VERIFIED_INPUT_INVALID", "offline feature candidate shape is invalid")
    values = tuple(_decimal(item, f"mechanics_vector[{index}]") for index, item in enumerate(value.mechanics_vector))
    if any(not Decimal(-1) <= item <= Decimal(1) for item in values):
        raise _fail("VERIFIED_INPUT_INVALID", "offline mechanics vector is outside [-1, 1]")
    expected_x = _decimal_text(sum(values, Decimal(0)) / Decimal(len(values)))
    if value.mechanics_x != expected_x:
        raise _fail("VERIFIED_INPUT_INVALID", "offline mechanics x is not the equal feature mean")
    feature_bytes = parse_canonical_transcript(value.canonical_feature_bytes)
    expected_feature_bytes = {
        "schema": value.schema,
        "panel_content_sha256": value.panel_content_sha256,
        "mechanics_vector": list(value.mechanics_vector),
        "mechanics_x": value.mechanics_x,
        "archive_r": value.archive_r,
    }
    if feature_bytes != expected_feature_bytes:
        raise _fail("VERIFIED_INPUT_INVALID", "offline feature values differ from retained bytes")
    if value.content_sha256 != _domain_hash(_DOMAIN_FEATURE_CANDIDATE, _feature_candidate_core(value)):
        raise _fail("VERIFIED_INPUT_INVALID", "offline feature content root is stale")
    return value


def derive_local_feature_candidate(
    panel: OfflineLocalPanelCandidate,
) -> LocalFeatureDerivation:
    """Fail closed because caller-summary panels cannot satisfy trace v1."""

    verified = revalidate_offline_local_panel_candidate(panel)
    incomplete = tuple(
        name for name in PRE_SEAT_FEATURE_NAMES if FEATURE_SPEC[name]["complete"] is False
    )
    report = {
        "feature_spec_state": FEATURE_SPEC_STATE,
        "incomplete_features": list(incomplete),
        "required_raw_fields": list(RAW_SUFFICIENT_STATISTIC_FIELDS),
        "seat_robustness_formula": FEATURE_SPEC["seat_robustness"]["formula"],
        "aggregation_order": ["control", "seat", "seed_index"],
        "selectable_stratum_diagnostics": False,
        "reason": "legacy caller summaries cannot satisfy the replay-verified exact-rational trace feature contract",
        "successor_module": "evaluation_v6_3_1.trace_features",
    }
    report_bytes = canonical_json_bytes(report)
    draft = LocalFeatureDerivation(
        schema=FEATURE_DERIVATION_SCHEMA,
        state=FEATURE_SPEC_STATE,
        panel_candidate=verified,
        panel_content_sha256=verified.content_sha256,
        feature_candidate=None,
        report=_freeze(report),
        canonical_report_bytes=report_bytes,
        authority=False,
        calibration_upload_authorized=False,
        production_upload_authorized=False,
        sealed_holdout_access_authorized=False,
        agent_modification_authorized=False,
        permits=(),
        content_sha256="",
        _construction_token=_DERIVATION_TOKEN,
    )
    issued = LocalFeatureDerivation(
        **{
            **draft.__dict__,
            "content_sha256": _domain_hash(
                _DOMAIN_FEATURE_DERIVATION,
                _derivation_core(draft),
            ),
        }
    )
    return _register_issued(issued)


def _derivation_core(value: LocalFeatureDerivation) -> dict[str, Any]:
    return {
        "schema": value.schema,
        "state": value.state,
        "panel_content_sha256": value.panel_content_sha256,
        "feature_candidate": None,
        "report": _thaw(value.report),
        "canonical_report_bytes_sha256": hashlib.sha256(
            value.canonical_report_bytes
        ).hexdigest(),
        "authority": value.authority,
        "calibration_upload_authorized": value.calibration_upload_authorized,
        "production_upload_authorized": value.production_upload_authorized,
        "sealed_holdout_access_authorized": value.sealed_holdout_access_authorized,
        "agent_modification_authorized": value.agent_modification_authorized,
        "permits": list(value.permits),
    }


def revalidate_local_feature_derivation(value: Any) -> LocalFeatureDerivation:
    _require_issued(value, LocalFeatureDerivation)
    _require_zero_authority_fields(value)
    panel = revalidate_offline_local_panel_candidate(value.panel_candidate)
    if (
        value.schema != FEATURE_DERIVATION_SCHEMA
        or value.state != FEATURE_SPEC_STATE
        or value.feature_candidate is not None
        or value.panel_content_sha256 != panel.content_sha256
    ):
        raise _fail("VERIFIED_INPUT_INVALID", "legacy summary feature derivation must remain retired")
    retained_report = parse_canonical_transcript(value.canonical_report_bytes)
    if retained_report != _thaw(value.report):
        raise _fail("VERIFIED_INPUT_INVALID", "feature report differs from retained bytes")
    if value.content_sha256 != _domain_hash(
        _DOMAIN_FEATURE_DERIVATION,
        _derivation_core(value),
    ):
        raise _fail("VERIFIED_INPUT_INVALID", "feature derivation content root is stale")
    return value


def zero_authority_report() -> dict[str, Any]:
    return {
        "schema": "eval.v6.3.1.local-panel-zero-authority",
        "state": FEATURE_SPEC_STATE,
        "authority": False,
        "local_panel_execution_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }


__all__ = [
    "AGGREGATION_WEIGHTS",
    "CONTROL_ENTRY_SCHEMA",
    "CONTROL_LABELS",
    "CONTROL_REGISTRY_SCHEMA",
    "EXPECTED_GAME_COUNT",
    "FEATURE_CANDIDATE_SCHEMA",
    "FEATURE_DERIVATION_SCHEMA",
    "FEATURE_NAMES",
    "FEATURE_SPEC",
    "FEATURE_SPEC_STATE",
    "GAME_POINT_FORMULA",
    "GAME_TRANSCRIPT_SCHEMA",
    "GAMES_PER_CONTROL",
    "LocalFeatureDerivation",
    "LocalPanelError",
    "OfflineLocalFeatureCandidate",
    "OfflineLocalPanelCandidate",
    "PANEL_CANDIDATE_SCHEMA",
    "PANEL_TRANSCRIPT_SCHEMA",
    "RAW_SUFFICIENT_STATISTIC_FIELDS",
    "SEATS",
    "SEED_INDEXES",
    "VerifiedControlRegistry",
    "canonical_json_bytes",
    "canonical_panel_merkle_root",
    "canonical_sha256",
    "control_entry_sha256",
    "derive_game_trace_root",
    "derive_local_feature_candidate",
    "derive_rng_seed",
    "derive_seat_robustness",
    "parse_canonical_transcript",
    "revalidate_control_registry",
    "revalidate_local_feature_derivation",
    "revalidate_offline_local_feature_candidate",
    "revalidate_offline_local_panel_candidate",
    "verify_control_registry",
    "verify_local_panel",
    "zero_authority_report",
]
