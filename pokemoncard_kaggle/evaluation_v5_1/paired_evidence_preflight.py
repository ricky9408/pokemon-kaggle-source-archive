"""Bounded, fail-closed G11 paired-evidence preflight.

This module verifies structural pairing only.  It never authenticates external
evidence and never creates candidate, holdout, G11, or submission authority.
The production-shaped entry point remains hard closed until an independently
pinned verifier can authenticate archive custody, local executions, hosted
collection, and ancestry receipts.  The synthetic path exists only to test the
shape of a future evidence bridge.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from decimal import Decimal, InvalidOperation
import json
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .canonical import canonical_json_bytes, canonical_sha256


PROTOCOL_SCHEMA = "evaluation_v5_1_g11_paired_evidence_protocol_v1"
RESULT_SCHEMA = "evaluation_v5_1_g11_paired_evidence_preflight_result_v1"
GATE_ID = "G11_PAIRED_EVIDENCE_PREFLIGHT_V1"
HARD_CLOSE = "HARD_CLOSE"
STRUCTURAL_PAIRING_READY = "STRUCTURAL_PAIRING_READY"
RESEARCH_ONLY = "RESEARCH_ONLY"
STRUCTURAL_PROSPECTIVE = "STRUCTURAL_PROSPECTIVE"

# A production verifier must be independently pinned in code. Caller-provided
# role strings and receipt hashes can never populate this allowlist.
PINNED_PAIRED_EVIDENCE_VERIFIERS: Mapping[str, str] = MappingProxyType({})

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROBABILITY = re.compile(r"^(?:0|1)\.[0-9]{12}$")
_GLOBAL_HASHES = (
    "evaluator_sha256",
    "local_schedule_sha256",
    "local_config_sha256",
    "local_runtime_sha256",
)
_ARCHIVE_HASHES = (
    "code_sha256",
    "deck_sha256",
    "model_sha256",
    "agent_config_sha256",
)
_ARCHIVE_RECEIPT_HASHES = (
    "archive_custody_receipt_sha256",
    "runnable_receipt_sha256",
    "ancestry_attestation_receipt_sha256",
    "hosted_linkage_receipt_sha256",
    "local_output_receipt_sha256",
)
_PUBLIC_TOKENS = frozenset(
    {
        "public_score",
        "leaderboard_score",
        "kaggle_score",
        "hosted_score",
        "post_game_score",
        "public_outcome",
        "leaderboard_rank",
        "public_rank",
    }
)
_CANDIDATE_FORBIDDEN_KEYS = frozenset(
    {
        "episode_id",
        "game_id",
        "outcome",
        "result",
        "seat",
        "opponent_score",
        "opponent_score_stratum",
        "opponent_bin",
        "started_at_ns",
        "created_at_ns",
        "ended_at_ns",
        "server_start_time_ns",
        "server_end_time_ns",
        "server_started_at_ns",
        "server_ended_at_ns",
        "submission_id",
        "opponent_archive_sha256",
        "replay_content_sha256",
        "public_score",
        "hosted_observations",
    }
)
_SEALED_TOKENS = ("sealed", "holdout", "g14_holdout", "sealed_50", "sealed-50")


class PairedEvidencePreflightError(ValueError):
    """Raised by the direct source loader for an unusable input source."""


def _is_hash(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _identifier(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def _probability(value: object) -> bool:
    if type(value) is not str or _PROBABILITY.fullmatch(value) is None:
        return False
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return False
    return parsed.is_finite() and Decimal(0) <= parsed <= Decimal(1)


def _sorted_values(values: Sequence[object]) -> list[object]:
    return sorted(values, key=lambda value: canonical_json_bytes(value))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PairedEvidencePreflightError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_bytes(payload: bytes, *, path: str) -> object:
    try:
        text = payload.decode("utf-8")
        if path.lower().endswith(".jsonl"):
            return [
                json.loads(line, object_pairs_hook=_reject_duplicate_keys)
                for line in text.splitlines()
                if line.strip()
            ]
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, PairedEvidencePreflightError) as exc:
        raise PairedEvidencePreflightError(f"{path} is invalid JSON: {exc}") from exc


def load_json_or_jsonl(source: object, *, label: str = "input") -> object:
    """Load a JSON/JSONL path or an already decoded JSON value."""

    if isinstance(source, (str, Path)):
        try:
            return _parse_bytes(Path(source).read_bytes(), path=str(source))
        except OSError as exc:
            raise PairedEvidencePreflightError(f"{label} cannot be read: {exc}") from exc
    if isinstance(source, (Mapping, list)):
        return source
    raise PairedEvidencePreflightError(f"{label} must be a JSON value or path")


def _rows_source(source: object, *, label: str) -> tuple[list[dict[str, Any]], object]:
    raw = load_json_or_jsonl(source, label=label)
    if isinstance(raw, list):
        rows = raw
        semantic: object = _sorted_values(rows)
    elif isinstance(raw, Mapping):
        row_key = next(
            (key for key in ("rows", "records", "items", "archives", "runs", "games", "candidates") if key in raw),
            None,
        )
        if row_key is None or not isinstance(raw[row_key], list):
            raise PairedEvidencePreflightError(f"{label} has no valid row collection")
        rows = raw[row_key]
        semantic = {
            key: (_sorted_values(value) if isinstance(value, list) else value)
            for key, value in raw.items()
        }
    else:
        raise PairedEvidencePreflightError(f"{label} must be an object or list")
    if any(not isinstance(row, Mapping) for row in rows):
        raise PairedEvidencePreflightError(f"{label} rows must be objects")
    return [dict(row) for row in rows], semantic


def _protocol_root(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize protocol set-like fields before hashing them."""

    normalized = dict(raw)
    if isinstance(normalized.get("required_strata"), list):
        normalized["required_strata"] = _sorted_values(normalized["required_strata"])
    if isinstance(normalized.get("selector_feature_allowlist"), list):
        normalized["selector_feature_allowlist"] = sorted(
            normalized["selector_feature_allowlist"], key=lambda value: str(value)
        )
    if isinstance(normalized.get("forbidden_hosted_fields"), list):
        normalized["forbidden_hosted_fields"] = sorted(
            normalized["forbidden_hosted_fields"], key=lambda value: str(value)
        )
    return normalized


def canonical_input_root(source: object, *, label: str = "input", protocol: bool = False) -> str:
    """Return a deterministic content root, invariant to set-row ordering."""

    raw = load_json_or_jsonl(source, label=label)
    if protocol:
        if not isinstance(raw, Mapping):
            raise PairedEvidencePreflightError(f"{label} must be an object")
        return canonical_sha256(_protocol_root(raw))
    _, semantic = _rows_source(raw, label=label)
    return canonical_sha256(semantic)


def _field(row: Mapping[str, Any], name: str, *, label: str, issues: list[str]) -> Any:
    if name not in row:
        issues.append(f"missing:{label}")
        return None
    return row[name]


def _hash_field(row: Mapping[str, Any], name: str, *, label: str, issues: list[str]) -> str | None:
    value = _field(row, name, label=label, issues=issues)
    if not _is_hash(value):
        issues.append(f"invalid_hash:{label}")
        return None
    return value


def _int_field(row: Mapping[str, Any], name: str, *, label: str, issues: list[str]) -> int | None:
    value = _field(row, name, label=label, issues=issues)
    if type(value) is not int:
        issues.append(f"invalid_integer:{label}")
        return None
    return value


def _contains_token(value: object, tokens: Sequence[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            any(token in str(key).lower().replace("-", "_") for token in tokens)
            or _contains_token(item, tokens)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_token(item, tokens) for item in value)
    if isinstance(value, str):
        normalized = value.lower().replace("-", "_")
        return any(token in normalized for token in tokens)
    return False


def _has_forbidden_key(value: object, keys: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).lower().replace("-", "_") in keys
            or _has_forbidden_key(item, keys)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_has_forbidden_key(item, keys) for item in value)
    return False


def _result(
    *,
    protocol_hash: str | None,
    input_roots: Mapping[str, str | None],
    blockers: Sequence[str],
    units: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "gate_id": GATE_ID,
        "protocol_hash": protocol_hash,
        "input_roots": dict(sorted(input_roots.items())),
        "per_unit_flags": sorted(
            (dict(unit) for unit in units), key=lambda item: str(item.get("unit_id", ""))
        ),
        "structural_eligible_unit_count": sum(
            bool(unit.get("structurally_complete")) for unit in units
        ),
        "eligible_paired_unit_count": 0,
        "preflight_status": HARD_CLOSE,
        "production_gate_status": HARD_CLOSE,
        "external_authentication_verified": False,
        "g11_selector_validated": False,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "research_only_available_fields": [
            "paired_archive_identity",
            "local_natural_start_quota_status",
            "hosted_episode_identity_and_stratum_status",
            "prospective_chronology_status",
        ],
        "terminal_blockers": sorted(set(blockers)),
    }
    result["content_sha256"] = canonical_sha256(result)
    return result


def _normalize_protocol(raw: object) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not isinstance(raw, Mapping):
        return {}, ["protocol_not_object"]
    if raw.get("schema") != PROTOCOL_SCHEMA:
        issues.append("protocol_schema_mismatch")
    if raw.get("protocol_id") != "MCI_FAMILY_TRANSFER_V2":
        issues.append("protocol_id_mismatch")
    required_unit_count = _int_field(raw, "required_unit_count", label="required_unit_count", issues=issues)
    if required_unit_count is not None and required_unit_count < 1:
        issues.append("invalid_required_unit_count")
    freeze = _int_field(raw, "freeze_time_ns", label="freeze_time_ns", issues=issues)
    if freeze is not None and freeze <= 0:
        issues.append("freeze_time_ns_must_be_positive")
    t1 = _int_field(raw, "t1_ns", label="t1_ns", issues=issues)
    if t1 is not None and freeze is not None and t1 <= freeze:
        issues.append("t1_ns_must_follow_freeze")
    quota = _int_field(raw, "natural_start_local_quota", label="natural_start_local_quota", issues=issues)
    if quota is not None and quota < 1:
        issues.append("invalid_local_quota")

    raw_strata = raw.get("required_strata")
    if not isinstance(raw_strata, list) or not raw_strata:
        issues.append("missing_required_strata")
        raw_strata = []
    strata: list[dict[str, Any]] = []
    seen_strata: set[tuple[int, str]] = set()
    for index, item in enumerate(raw_strata):
        if not isinstance(item, Mapping):
            issues.append(f"invalid_stratum:{index}")
            continue
        seat = item.get("seat")
        name = item.get("opponent_score_stratum")
        amount = item.get("required_games")
        if type(seat) is not int or seat not in (0, 1) or not _identifier(name) or type(amount) is not int or amount < 1:
            issues.append(f"invalid_stratum:{index}")
            continue
        key = (seat, name)
        if key in seen_strata:
            issues.append(f"duplicate_stratum:{seat}:{name}")
        seen_strata.add(key)
        strata.append({"seat": seat, "opponent_score_stratum": name, "required_games": amount})

    frozen = raw.get("frozen_hashes")
    if not isinstance(frozen, Mapping) or set(frozen) != set(_GLOBAL_HASHES):
        issues.append("frozen_hashes_schema_mismatch")
        frozen = {}
    global_hashes: dict[str, str] = {}
    for name in _GLOBAL_HASHES:
        value = _hash_field(frozen, name, label=name, issues=issues)
        if value is not None:
            global_hashes[name] = value

    allowlist = raw.get("selector_feature_allowlist")
    if not isinstance(allowlist, list) or any(not _identifier(item) for item in allowlist) or len(set(allowlist)) != len(allowlist):
        issues.append("invalid_selector_feature_allowlist")
        allowlist = []

    forbidden_fields = raw.get("forbidden_hosted_fields", [])
    if not isinstance(forbidden_fields, list) or any(not _identifier(item) for item in forbidden_fields) or len(set(forbidden_fields)) != len(forbidden_fields):
        issues.append("invalid_forbidden_hosted_fields")
        forbidden_fields = []
    normalized = {
        "schema": PROTOCOL_SCHEMA,
        "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "required_unit_count": required_unit_count,
        "freeze_time_ns": freeze,
        "t1_ns": t1,
        "natural_start_local_quota": quota,
        "required_strata": sorted(strata, key=lambda item: (item["seat"], item["opponent_score_stratum"])),
        "frozen_hashes": global_hashes,
        "selector_feature_allowlist": sorted(allowlist),
        "forbidden_hosted_fields": sorted(forbidden_fields),
    }
    return normalized, issues


def _unit_base(row: Mapping[str, Any], index: int) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    values: dict[str, Any] = {}
    for name in ("unit_id", "team_id", "family_id", "ancestry_id", "submission_id"):
        value = _field(row, name, label=name, issues=issues)
        if not _identifier(value):
            issues.append(f"invalid_{name}")
        values[name] = value
    values["archive_sha256"] = _hash_field(row, "archive_sha256", label="archive_sha256", issues=issues)
    values["unit_id"] = values["unit_id"] if _identifier(values["unit_id"]) else f"invalid-{index}"
    return values, issues


def _bind_identity(row: Mapping[str, Any], unit: Mapping[str, Any], issues: list[str], *, prefix: str) -> None:
    for name in (
        "unit_id",
        "team_id",
        "submission_id",
        "family_id",
        "ancestry_id",
        "archive_sha256",
    ):
        value = _field(row, name, label=f"{prefix}.{name}", issues=issues)
        if value != unit.get(name):
            issues.append(f"{prefix}_identity_mismatch:{name}")


def _bind_hashes(row: Mapping[str, Any], names: Sequence[str], expected: Mapping[str, str], issues: list[str], *, prefix: str) -> None:
    for name in names:
        value = _hash_field(row, name, label=f"{prefix}.{name}", issues=issues)
        if value != expected.get(name):
            issues.append(f"{prefix}_hash_mismatch:{name}")


def evaluate_structural_pairing_conformance(
    protocol: object,
    archive_registry: object,
    local_runs: object,
    hosted_observations: object,
    candidate_registry: object,
) -> dict[str, Any]:
    """Check synthetic structure without authenticating any supplied receipt."""

    sources = {
        "protocol": protocol,
        "archive_registry": archive_registry,
        "local_runs": local_runs,
        "hosted_observations": hosted_observations,
        "candidate_registry": candidate_registry,
    }
    roots: dict[str, str | None] = {}
    parsed: dict[str, object] = {}
    blockers: list[str] = []
    for label, source in sources.items():
        try:
            if label == "protocol":
                raw = load_json_or_jsonl(source, label=label)
                if not isinstance(raw, Mapping):
                    raise PairedEvidencePreflightError("protocol must be an object")
                parsed[label] = raw
                roots[label] = canonical_input_root(raw, label=label, protocol=True)
            else:
                rows, semantic = _rows_source(source, label=label)
                parsed[label] = rows
                roots[label] = canonical_sha256(semantic)
        except (PairedEvidencePreflightError, TypeError, ValueError):
            roots[label] = None
            blockers.append(f"unverifiable_{label}")
    if blockers:
        return _result(protocol_hash=roots.get("protocol"), input_roots=roots, blockers=blockers)

    normalized_protocol, protocol_issues = _normalize_protocol(parsed["protocol"])
    if protocol_issues:
        return _result(protocol_hash=roots["protocol"], input_roots=roots, blockers=protocol_issues)

    freeze = normalized_protocol["freeze_time_ns"]
    t1 = normalized_protocol["t1_ns"]
    global_hashes = normalized_protocol["frozen_hashes"]
    allowlist = set(normalized_protocol["selector_feature_allowlist"])
    for raw_source in parsed.values():
        if _contains_token(raw_source, _SEALED_TOKENS):
            blockers.append("sealed_holdout_reference_present")

    archives: list[dict[str, Any]] = []
    for index, raw in enumerate(parsed["archive_registry"]):
        unit, issues = _unit_base(raw, index)
        _bind_hashes(raw, ("evaluator_sha256",), global_hashes, issues, prefix="archive")
        for name in _ARCHIVE_HASHES:
            unit[name] = _hash_field(raw, name, label=name, issues=issues)
        for name in _ARCHIVE_RECEIPT_HASHES:
            unit[name] = _hash_field(raw, name, label=name, issues=issues)
        for name in ("selector_prediction", "baseline_prediction"):
            value = _field(raw, name, label=name, issues=issues)
            if not _probability(value):
                issues.append(f"invalid_{name}")
            unit[name] = value
        frozen_at = _int_field(
            raw, "archive_frozen_at_ns", label="archive_frozen_at_ns", issues=issues
        )
        if frozen_at is None or frozen_at > freeze:
            issues.append("archive_not_frozen_before_t0")
        if raw.get("runnable") is not True:
            issues.append("archive_not_runnable")
        if raw.get("evaluator_compatible") is not True:
            issues.append("archive_not_evaluator_compatible")
        role = _field(raw, "evidence_role", label="evidence_role", issues=issues)
        if role == RESEARCH_ONLY:
            issues.append("research_only_evidence_excluded")
        elif role != STRUCTURAL_PROSPECTIVE:
            issues.append("invalid_evidence_role")
        features = raw.get("selector_features")
        if not isinstance(features, Mapping):
            issues.append("selector_features_outside_frozen_domain")
        elif _contains_token(features, _PUBLIC_TOKENS):
            issues.append("forbidden_public_selector_field")
        if isinstance(features, Mapping) and set(features) != allowlist:
            issues.append("selector_features_outside_frozen_domain")
        if raw.get("candidate") is True or raw.get("candidate_id") is not None:
            issues.append("candidate_archive_in_pair_registry")
        unit.update({"selector_features": dict(features) if isinstance(features, Mapping) else {}, "issues": sorted(set(issues))})
        archives.append(unit)

    identity_names = ("unit_id", "archive_sha256", "team_id", "family_id", "ancestry_id", "submission_id")
    for name in identity_names:
        groups: dict[object, list[dict[str, Any]]] = defaultdict(list)
        for unit in archives:
            if unit.get(name) is not None:
                groups[unit[name]].append(unit)
        for value, group in groups.items():
            if len(group) > 1:
                reason = f"duplicate_{name}"
                blockers.append(reason)
                for unit in group:
                    unit["issues"].append(reason)
                    unit["issues"] = sorted(set(unit["issues"]))

    archive_by_hash = {unit["archive_sha256"]: unit for unit in archives if _is_hash(unit.get("archive_sha256"))}
    archive_by_unit = {unit["unit_id"]: unit for unit in archives}
    local_by_archive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    hosted_by_archive: dict[str, list[dict[str, Any]]] = defaultdict(list)
    all_local_ids: dict[str, list[dict[str, Any]]] = defaultdict(list)
    all_hosted_ids: dict[str, list[dict[str, Any]]] = defaultdict(list)
    local_seed_keys: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    local_schedule_keys: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for raw in parsed["local_runs"]:
        issues: list[str] = []
        archive = _hash_field(raw, "archive_sha256", label="local.archive_sha256", issues=issues)
        episode = _field(raw, "episode_id", label="local.episode_id", issues=issues)
        started = _int_field(raw, "started_at_ns", label="local.started_at_ns", issues=issues)
        ended = _int_field(raw, "ended_at_ns", label="local.ended_at_ns", issues=issues)
        seed = _hash_field(raw, "seed_sha256", label="local.seed_sha256", issues=issues)
        schedule_slot = _field(
            raw, "schedule_slot_id", label="local.schedule_slot_id", issues=issues
        )
        _hash_field(
            raw,
            "trace_receipt_sha256",
            label="local.trace_receipt_sha256",
            issues=issues,
        )
        unit = archive_by_hash.get(archive)
        if unit is None:
            issues.append("archive_not_in_registry")
        else:
            _bind_identity(raw, unit, issues, prefix="local")
            _bind_hashes(raw, _ARCHIVE_HASHES, unit, issues, prefix="local")
        _bind_hashes(raw, _GLOBAL_HASHES, global_hashes, issues, prefix="local")
        if not _identifier(episode):
            issues.append("invalid_episode_id")
        if started is None or ended is None or ended < started or ended >= freeze:
            issues.append("local_run_not_pre_freeze")
        if not _identifier(schedule_slot):
            issues.append("invalid_schedule_slot_id")
        if raw.get("natural_start") is not True:
            issues.append("local_run_not_natural_start")
        role = _field(raw, "evidence_role", label="local.evidence_role", issues=issues)
        if role == RESEARCH_ONLY:
            issues.append("research_only_evidence_excluded")
        elif role != STRUCTURAL_PROSPECTIVE:
            issues.append("invalid_evidence_role")
        record = {"archive_sha256": archive, "episode_id": episode, "issues": sorted(set(issues))}
        if _is_hash(archive):
            local_by_archive[archive].append(record)
        if _identifier(episode):
            all_local_ids[episode].append(record)
        if _is_hash(archive) and _is_hash(seed):
            local_seed_keys[(archive, seed)].append(record)
        if _is_hash(archive) and _identifier(schedule_slot):
            local_schedule_keys[(archive, schedule_slot)].append(record)

    for raw in parsed["hosted_observations"]:
        issues = []
        archive = _hash_field(raw, "archive_sha256", label="hosted.archive_sha256", issues=issues)
        episode = _field(raw, "episode_id", label="hosted.episode_id", issues=issues)
        started = _int_field(raw, "started_at_ns", label="hosted.started_at_ns", issues=issues)
        created = _int_field(raw, "created_at_ns", label="hosted.created_at_ns", issues=issues)
        ended = _int_field(raw, "ended_at_ns", label="hosted.ended_at_ns", issues=issues)
        seat = _field(raw, "seat", label="hosted.seat", issues=issues)
        stratum = _field(raw, "opponent_score_stratum", label="hosted.opponent_score_stratum", issues=issues)
        opponent_archive = _hash_field(
            raw,
            "opponent_archive_sha256",
            label="hosted.opponent_archive_sha256",
            issues=issues,
        )
        opponent_component = _field(
            raw,
            "opponent_component_id",
            label="hosted.opponent_component_id",
            issues=issues,
        )
        opponent_score = _int_field(
            raw,
            "pre_game_opponent_score_milli",
            label="hosted.pre_game_opponent_score_milli",
            issues=issues,
        )
        outcome = _field(raw, "outcome", label="hosted.outcome", issues=issues)
        _hash_field(
            raw,
            "source_row_sha256",
            label="hosted.source_row_sha256",
            issues=issues,
        )
        unit = archive_by_hash.get(archive)
        if unit is None:
            issues.append("archive_not_in_registry")
        else:
            _bind_identity(raw, unit, issues, prefix="hosted")
        if not _identifier(episode):
            issues.append("invalid_episode_id")
        if type(seat) is not int or seat not in (0, 1) or not _identifier(stratum):
            issues.append("invalid_hosted_stratum")
        if not _is_hash(opponent_archive) or not _identifier(opponent_component):
            issues.append("invalid_hosted_opponent_identity")
        if opponent_score is None or opponent_score < 0:
            issues.append("invalid_pre_game_opponent_score")
        if type(outcome) is not int or outcome not in (0, 1):
            issues.append("invalid_hosted_outcome")
        if (
            started is None
            or created is None
            or ended is None
            or not (freeze <= created <= started < t1 and ended >= started)
        ):
            issues.append("hosted_game_not_strictly_prospective")
        if raw.get("collector_agreement") is not True:
            issues.append("hosted_collector_agreement_missing")
        if raw.get("episode_level") is not True or raw.get("aggregate_only") is not False:
            issues.append("aggregate_only_hosted_row")
        if _contains_token(raw, _PUBLIC_TOKENS):
            issues.append("forbidden_public_hosted_field")
        if _has_forbidden_key(raw, set(normalized_protocol["forbidden_hosted_fields"])):
            issues.append("forbidden_hosted_field")
        role = _field(raw, "evidence_role", label="hosted.evidence_role", issues=issues)
        if role == RESEARCH_ONLY:
            issues.append("research_only_evidence_excluded")
        elif role != STRUCTURAL_PROSPECTIVE:
            issues.append("invalid_evidence_role")
        record = {
            "archive_sha256": archive,
            "episode_id": episode,
            "seat": seat,
            "stratum": stratum,
            "issues": sorted(set(issues)),
        }
        if _is_hash(archive):
            hosted_by_archive[archive].append(record)
        if _identifier(episode):
            all_hosted_ids[episode].append(record)

    for episode, records in {**all_local_ids, **all_hosted_ids}.items():
        if len(records) > 1:
            for record in records:
                record["issues"].append("duplicate_episode_id")
                record["issues"] = sorted(set(record["issues"]))
            blockers.append("duplicate_episode_id")
    for episode in set(all_local_ids) & set(all_hosted_ids):
        for record in all_local_ids[episode] + all_hosted_ids[episode]:
            record["issues"].append("duplicate_episode_id")
            record["issues"] = sorted(set(record["issues"]))
        blockers.append("duplicate_episode_id")
    for groups, reason in (
        (local_seed_keys, "duplicate_local_seed_commitment"),
        (local_schedule_keys, "duplicate_local_schedule_slot"),
    ):
        for records in groups.values():
            if len(records) <= 1:
                continue
            blockers.append(reason)
            for record in records:
                record["issues"].append(reason)
                record["issues"] = sorted(set(record["issues"]))

    for raw in parsed["candidate_registry"]:
        issues: list[str] = []
        candidate_id = _field(raw, "candidate_id", label="candidate_id", issues=issues)
        archive = _hash_field(raw, "archive_sha256", label="candidate.archive_sha256", issues=issues)
        for name in ("team_id", "family_id", "ancestry_id"):
            if not _identifier(_field(raw, name, label=f"candidate.{name}", issues=issues)):
                issues.append(f"invalid_candidate_{name}")
        if not _identifier(candidate_id):
            issues.append("invalid_candidate_id")
        if raw.get("submitted") is not False:
            issues.append("candidate_already_submitted")
        if raw.get("evidence_role") != RESEARCH_ONLY:
            issues.append("candidate_must_be_research_only")
        parent = raw.get("parent_archive_sha256")
        if parent is not None and not _is_hash(parent):
            issues.append("invalid_candidate_parent_archive")
        if raw.get("hosted_evidence_inherited") is not False:
            issues.append("candidate_hosted_evidence_dependency_present")
        evidence_roots = raw.get("forbidden_evidence_roots")
        if not isinstance(evidence_roots, list) or evidence_roots:
            issues.append("candidate_forbidden_evidence_roots_present")
        for name in (
            "candidate_provenance_receipt_sha256",
            "local_output_receipt_sha256",
        ):
            _hash_field(raw, name, label=f"candidate.{name}", issues=issues)
        if not _probability(raw.get("selector_prediction")):
            issues.append("invalid_candidate_selector_prediction")
        if archive in archive_by_hash:
            issues.append("candidate_reuses_paired_archive")
        if _contains_token(raw, _PUBLIC_TOKENS) or _has_forbidden_key(raw, set(_CANDIDATE_FORBIDDEN_KEYS)):
            issues.append("forbidden_candidate_public_or_hosted_field")
        if issues:
            blockers.extend(issues)

    units: list[dict[str, Any]] = []
    required_quota = normalized_protocol["natural_start_local_quota"]
    for unit in archives:
        reasons = list(unit["issues"])
        archive = unit["archive_sha256"]
        local_rows = local_by_archive.get(archive, [])
        valid_local = [row for row in local_rows if not row["issues"]]
        if len(valid_local) != required_quota:
            reasons.append("local_quota_exact_mismatch")

        host_rows = hosted_by_archive.get(archive, [])
        valid_hosted = [row for row in host_rows if not row["issues"]]
        for stratum in normalized_protocol["required_strata"]:
            count = sum(
                row["seat"] == stratum["seat"]
                and row["stratum"] == stratum["opponent_score_stratum"]
                for row in valid_hosted
            )
            if count != stratum["required_games"]:
                reasons.append(
                    f"stratum_count_mismatch:seat{stratum['seat']}:{stratum['opponent_score_stratum']}"
                )
        reasons.extend(reason for row in local_rows + host_rows for reason in row["issues"])
        structurally_complete = not reasons
        units.append(
            {
                "unit_id": unit["unit_id"],
                "archive_sha256": archive,
                "team_id": unit["team_id"],
                "family_id": unit["family_id"],
                "ancestry_id": unit["ancestry_id"],
                "structurally_complete": structurally_complete,
                "production_eligible": False,
                "eligible": False,
                "flags": {
                    "exact_archive_linkage": structurally_complete
                    and bool(valid_local)
                    and bool(valid_hosted),
                    "runnable_evaluator_compatible": "archive_not_runnable" not in reasons and "archive_not_evaluator_compatible" not in reasons,
                    "frozen_hashes": not any("hash_mismatch" in reason for reason in reasons),
                    "natural_start_local_quota": "local_quota_exact_mismatch" not in reasons,
                    "prospective_hosted_games": "hosted_game_not_strictly_prospective" not in reasons,
                    "required_strata": not any(reason.startswith("stratum_count_mismatch:") for reason in reasons),
                    "ancestry_family_unique": not any(reason.startswith("duplicate_") for reason in reasons),
                    "selector_domain_safe": not any("selector" in reason or "public" in reason for reason in reasons),
                    "structural_receipts_present": not any(
                        reason.startswith("missing:")
                        or reason.startswith("invalid_hash:")
                        for reason in reasons
                    ),
                    "external_authentication_verified": False,
                    "no_sealed_holdout_reference": "sealed_holdout_reference_present" not in blockers,
                },
                "reasons": sorted(set(reasons)),
            }
        )

    archive_count = len(archives)
    required_count = normalized_protocol["required_unit_count"]
    if archive_count != required_count:
        blockers.append("archive_unit_count_mismatch")
    structurally_complete_count = sum(unit["structurally_complete"] for unit in units)
    if structurally_complete_count != required_count:
        blockers.append("structural_paired_unit_count_mismatch")
    blockers.extend(reason for unit in units for reason in unit["reasons"])
    ready = (
        not blockers
        and archive_count == required_count
        and structurally_complete_count == required_count
    )

    result = _result(
        protocol_hash=roots["protocol"],
        input_roots=roots,
        blockers=[] if ready else blockers,
        units=units,
    )
    result["preflight_status"] = STRUCTURAL_PAIRING_READY if ready else HARD_CLOSE
    result.pop("content_sha256", None)
    result["content_sha256"] = canonical_sha256(result)
    return result


def evaluate_paired_evidence_preflight(
    protocol: object,
    archive_registry: object,
    local_runs: object,
    hosted_observations: object,
    candidate_registry: object,
) -> dict[str, Any]:
    """Run diagnostics while retaining a non-bypassable production hard close."""

    result = evaluate_structural_pairing_conformance(
        protocol,
        archive_registry,
        local_runs,
        hosted_observations,
        candidate_registry,
    )
    blockers = set(result["terminal_blockers"])
    if not PINNED_PAIRED_EVIDENCE_VERIFIERS:
        blockers.add("pinned_paired_evidence_verifier_unavailable")
    else:
        blockers.add("production_paired_evidence_verification_not_implemented")
    result.update(
        {
            "eligible_paired_unit_count": 0,
            "production_gate_status": HARD_CLOSE,
            "external_authentication_verified": False,
            "g11_selector_validated": False,
            "authority": False,
            "candidate_development_authorized": False,
            "sealed_holdout_access_authorized": False,
            "submission_authorized": False,
            "terminal_blockers": sorted(blockers),
        }
    )
    result.pop("content_sha256", None)
    result["content_sha256"] = canonical_sha256(result)
    return result


def preflight_from_files(
    protocol_path: str | Path,
    archive_registry_path: str | Path,
    local_runs_path: str | Path,
    hosted_observations_path: str | Path,
    candidate_registry_path: str | Path,
) -> dict[str, Any]:
    return evaluate_paired_evidence_preflight(
        protocol_path, archive_registry_path, local_runs_path, hosted_observations_path, candidate_registry_path
    )


def render_json(result: Mapping[str, Any]) -> str:
    return canonical_json_bytes(result).decode("ascii")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=GATE_ID)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--archive-registry", required=True)
    parser.add_argument("--local-runs", required=True)
    parser.add_argument("--hosted-observations", required=True)
    parser.add_argument("--candidate-registry", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = preflight_from_files(args.protocol, args.archive_registry, args.local_runs, args.hosted_observations, args.candidate_registry)
    rendered = render_json(result) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="ascii")
    else:
        sys.stdout.write(rendered)
    return 0


evaluate_g11_paired_evidence_preflight = evaluate_paired_evidence_preflight

__all__ = [
    "GATE_ID",
    "HARD_CLOSE",
    "PINNED_PAIRED_EVIDENCE_VERIFIERS",
    "PROTOCOL_SCHEMA",
    "RESEARCH_ONLY",
    "RESULT_SCHEMA",
    "STRUCTURAL_PAIRING_READY",
    "STRUCTURAL_PROSPECTIVE",
    "PairedEvidencePreflightError",
    "canonical_input_root",
    "evaluate_g11_paired_evidence_preflight",
    "evaluate_paired_evidence_preflight",
    "evaluate_structural_pairing_conformance",
    "load_json_or_jsonl",
    "main",
    "preflight_from_files",
    "render_json",
]


if __name__ == "__main__":
    raise SystemExit(main())
