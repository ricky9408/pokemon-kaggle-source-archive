"""Strict outcome-free primitives for the retired-v4 replacement VOI-P5 pilot.

This module deliberately cannot rank policies, ingest outcomes, certify a
selector, or authorize a submission.  It only freezes a protocol, records an
already-complete population, and derives a beacon-bound assignment from the
population's preassigned UUIDs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
import uuid


PROTOCOL_SCHEMA = "voi_p5_protocol_v1"
POPULATION_MANIFEST_SCHEMA = "voi_population_manifest_v1"
PAIR_ASSIGNMENT_SCHEMA = "voi_pair_assignment_v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_PROTOCOL_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "retired_v4_manifest_sha256",
        "evidence_budget_allocation_event_sha256",
        "candidate_grammar_sha256",
        "eligibility_code_sha256",
        "family_ontology_sha256",
        "runtime_manifest_sha256",
        "selector_model_sha256",
        "external_beacon_source",
        "external_beacon_selection_rule",
        "external_beacon_delay_seconds",
        "clipping",
        "endpoint",
        "setup_games",
        "horizon_games",
        "pairs",
        "selected_lineages",
        "source_population_lineages",
        "family_ids",
        "waves",
        "pair_allocation",
        "no_replacement",
        "interim_efficacy_looks",
        "primary_rule",
        "proper_score_lift_floor",
        "confirmatory_alpha",
        "research_only",
        "sealed_holdout_id",
        "frozen_at_utc",
        "state",
    }
)
_POPULATION_FIELDS = frozenset(
    {"schema", "protocol_id", "protocol_sha256", "records", "counts", "content_sha256"}
)
_POPULATION_RECORD_FIELDS = frozenset(
    {
        "lineage_uuid",
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "lineage_id",
        "ancestry_id",
        "family_id",
        "compute_budget_id",
    }
)
_POPULATION_COUNT_FIELDS = frozenset({"lineages", "families", "per_family"})
_ASSIGNMENT_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "protocol_sha256",
        "population_content_sha256",
        "external_beacon_sha256",
        "external_beacon_round",
        "selected_lineage_uuids",
        "pairs",
        "content_sha256",
    }
)
_PAIR_FIELDS = frozenset({"pair_id", "family_id", "wave_id", "member_uuids", "slot_order"})

_ENDPOINT = "first24_hosted_mean_win_plus_half_draw"
_PRIMARY_RULE = "all_five_strict_positive"
_EXTERNAL_BEACON_SOURCE = "https://beacon.nist.gov/beacon/2.0"
_EXTERNAL_BEACON_RULE = (
    "first_signed_pulse_strictly_after_population_rfc3161_grant_plus_fixed_delay"
)


class ProtocolError(ValueError):
    """An outcome-free VOI-P5 artifact violates its frozen schema or binding."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical JSON representation used for all bindings."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 of canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def protocol_core_sha256(protocol: object) -> str:
    """Hash the acyclic core bound by the model and alpha allocation.

    Both derived artifact slots are zeroed so the two artifacts can be built
    before their hashes are inserted into the final protocol.
    """

    frozen = validate_protocol(protocol)
    return canonical_sha256(
        {
            **frozen,
            "selector_model_sha256": "0" * 64,
            "evidence_budget_allocation_event_sha256": "0" * 64,
        }
    )


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProtocolError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ProtocolError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _uuid(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{label} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ProtocolError(f"{label} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise ProtocolError(f"{label} must be a canonical UUID string")
    return value


def _canonical_utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ProtocolError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ProtocolError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value:
        raise ProtocolError(f"{label} must be canonical UTC")
    return value


def _integer(value: object, *, label: str, expected: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{label} must be an integer")
    if expected is not None and value != expected:
        raise ProtocolError(f"{label} must equal frozen value {expected}")
    return value


def _exact_number(value: object, *, label: str, expected: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ProtocolError(f"{label} must be a finite number")
    if float(value) != expected:
        raise ProtocolError(f"{label} must equal frozen value {expected}")
    return expected


def _sorted_identifiers(value: object, *, label: str, count: int) -> list[str]:
    if not isinstance(value, list) or len(value) != count:
        raise ProtocolError(f"{label} must contain exactly {count} identifiers")
    items = [_identifier(item, label=f"{label} item") for item in value]
    if items != sorted(set(items)):
        raise ProtocolError(f"{label} must be sorted and unique")
    return items


def validate_protocol(protocol: object) -> dict[str, Any]:
    """Validate the exact immutable VOI-P5 protocol schema."""

    value = _exact_fields(protocol, _PROTOCOL_FIELDS, label="protocol")
    if value["schema"] != PROTOCOL_SCHEMA:
        raise ProtocolError(f"protocol schema must be {PROTOCOL_SCHEMA!r}")
    family_ids = _sorted_identifiers(value["family_ids"], label="family_ids", count=4)
    waves = _sorted_identifiers(value["waves"], label="waves", count=3)
    pair_allocation = _exact_fields(value["pair_allocation"], frozenset(waves), label="pair_allocation")
    expected_allocation = {waves[0]: 2, waves[1]: 2, waves[2]: 1}
    if any(_integer(pair_allocation[wave], label=f"pair_allocation.{wave}") != count for wave, count in expected_allocation.items()):
        raise ProtocolError("pair_allocation must be exactly 2/2/1 in wave order")
    hash_fields = (
        "retired_v4_manifest_sha256",
        "evidence_budget_allocation_event_sha256",
        "candidate_grammar_sha256",
        "eligibility_code_sha256",
        "family_ontology_sha256",
        "runtime_manifest_sha256",
        "selector_model_sha256",
    )
    normalized = {
        "schema": PROTOCOL_SCHEMA,
        "protocol_id": _identifier(value["protocol_id"], label="protocol_id"),
        **{field: _sha256(value[field], label=field) for field in hash_fields},
        "external_beacon_source": _EXTERNAL_BEACON_SOURCE,
        "external_beacon_selection_rule": _EXTERNAL_BEACON_RULE,
        "external_beacon_delay_seconds": _integer(
            value["external_beacon_delay_seconds"],
            label="external_beacon_delay_seconds",
            expected=120,
        ),
        "clipping": _exact_number(value["clipping"], label="clipping", expected=0.05),
        "endpoint": _ENDPOINT,
        "setup_games": _integer(value["setup_games"], label="setup_games", expected=0),
        "horizon_games": _integer(value["horizon_games"], label="horizon_games", expected=24),
        "pairs": _integer(value["pairs"], label="pairs", expected=5),
        "selected_lineages": _integer(value["selected_lineages"], label="selected_lineages", expected=10),
        "source_population_lineages": _integer(
            value["source_population_lineages"], label="source_population_lineages", expected=16
        ),
        "family_ids": family_ids,
        "waves": waves,
        "pair_allocation": expected_allocation,
        "no_replacement": True,
        "interim_efficacy_looks": _integer(
            value["interim_efficacy_looks"], label="interim_efficacy_looks", expected=0
        ),
        "primary_rule": _PRIMARY_RULE,
        "proper_score_lift_floor": _exact_number(
            value["proper_score_lift_floor"], label="proper_score_lift_floor", expected=0.015
        ),
        "confirmatory_alpha": _exact_number(
            value["confirmatory_alpha"], label="confirmatory_alpha", expected=0.03125
        ),
        "research_only": True,
        "sealed_holdout_id": _identifier(value["sealed_holdout_id"], label="sealed_holdout_id"),
        "frozen_at_utc": _canonical_utc(value["frozen_at_utc"], label="frozen_at_utc"),
        "state": "FROZEN",
    }
    if value["endpoint"] != _ENDPOINT:
        raise ProtocolError(f"endpoint must be {_ENDPOINT!r}")
    if value["external_beacon_source"] != _EXTERNAL_BEACON_SOURCE:
        raise ProtocolError(f"external_beacon_source must be {_EXTERNAL_BEACON_SOURCE!r}")
    if value["external_beacon_selection_rule"] != _EXTERNAL_BEACON_RULE:
        raise ProtocolError(f"external_beacon_selection_rule must be {_EXTERNAL_BEACON_RULE!r}")
    if value["no_replacement"] is not True:
        raise ProtocolError("no_replacement must be true")
    if value["primary_rule"] != _PRIMARY_RULE:
        raise ProtocolError(f"primary_rule must be {_PRIMARY_RULE!r}")
    if value["research_only"] is not True:
        raise ProtocolError("research_only must be true")
    if value["state"] != "FROZEN":
        raise ProtocolError("state must be FROZEN")
    return normalized


def _validate_population_record(record: object, *, family_ids: set[str]) -> dict[str, str]:
    value = _exact_fields(record, _POPULATION_RECORD_FIELDS, label="population record")
    normalized = {
        "lineage_uuid": _uuid(value["lineage_uuid"], label="lineage_uuid"),
        "archive_sha256": _sha256(value["archive_sha256"], label="archive_sha256"),
        "policy_content_sha256": _sha256(value["policy_content_sha256"], label="policy_content_sha256"),
        "deck_sha256": _sha256(value["deck_sha256"], label="deck_sha256"),
        "lineage_id": _identifier(value["lineage_id"], label="lineage_id"),
        "ancestry_id": _identifier(value["ancestry_id"], label="ancestry_id"),
        "family_id": _identifier(value["family_id"], label="family_id"),
        "compute_budget_id": _identifier(value["compute_budget_id"], label="compute_budget_id"),
    }
    if normalized["family_id"] not in family_ids:
        raise ProtocolError("population record family_id is absent from protocol family_ids")
    # This cannot prove how UUIDs were minted, but makes their role explicit:
    # assignment consumes only this preassigned value, never archive/name bytes.
    if normalized["lineage_uuid"] in {normalized["archive_sha256"], normalized["lineage_id"]}:
        raise ProtocolError("lineage_uuid must not equal archive_sha256 or lineage_id")
    return normalized


def _validate_population_records(records: Iterable[object], *, protocol: Mapping[str, Any]) -> list[dict[str, str]]:
    try:
        raw_records = list(records)
    except TypeError as exc:
        raise ProtocolError("population records must be iterable") from exc
    if len(raw_records) != 16:
        raise ProtocolError("population must contain exactly 16 records")
    normalized = [
        _validate_population_record(record, family_ids=set(protocol["family_ids"])) for record in raw_records
    ]
    unique_fields = ("lineage_uuid", "archive_sha256", "policy_content_sha256", "lineage_id", "ancestry_id")
    for field in unique_fields:
        values = [record[field] for record in normalized]
        if len(values) != len(set(values)):
            raise ProtocolError(f"population {field} values must be unique")
    compute_budgets = {record["compute_budget_id"] for record in normalized}
    if len(compute_budgets) != 1:
        raise ProtocolError("all population records must share one frozen compute_budget_id")
    counts = {family: sum(record["family_id"] == family for record in normalized) for family in protocol["family_ids"]}
    if counts != {family: 4 for family in protocol["family_ids"]}:
        raise ProtocolError("population must contain exactly four records per protocol family")
    return sorted(normalized, key=lambda record: record["lineage_uuid"])


def _population_content(protocol: Mapping[str, Any], records: list[dict[str, str]]) -> dict[str, Any]:
    counts = {
        "lineages": 16,
        "families": 4,
        "per_family": {family: 4 for family in protocol["family_ids"]},
    }
    return {
        "schema": POPULATION_MANIFEST_SCHEMA,
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": canonical_sha256(protocol),
        "records": records,
        "counts": counts,
    }


def build_population_manifest(protocol: object, records: Iterable[object]) -> dict[str, Any]:
    """Build the complete 16-lineage, UUID-rooted outcome-free population."""

    frozen = validate_protocol(protocol)
    normalized_records = _validate_population_records(records, protocol=frozen)
    content = _population_content(frozen, normalized_records)
    manifest = {**content, "content_sha256": canonical_sha256(content)}
    validate_population_manifest(manifest, frozen)
    return manifest


def validate_population_manifest(manifest: object, protocol: object) -> dict[str, Any]:
    """Validate a population manifest against the exact frozen protocol."""

    frozen = validate_protocol(protocol)
    value = _exact_fields(manifest, _POPULATION_FIELDS, label="population manifest")
    if value["schema"] != POPULATION_MANIFEST_SCHEMA:
        raise ProtocolError(f"population manifest schema must be {POPULATION_MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != frozen["protocol_id"]:
        raise ProtocolError("population manifest protocol_id mismatch")
    if value["protocol_sha256"] != canonical_sha256(frozen):
        raise ProtocolError("population manifest protocol_sha256 mismatch")
    if not isinstance(value["records"], list):
        raise ProtocolError("population manifest records must be a list")
    records = _validate_population_records(value["records"], protocol=frozen)
    expected_content = _population_content(frozen, records)
    if value["counts"] != expected_content["counts"]:
        raise ProtocolError("population manifest counts do not match records")
    if value["content_sha256"] != canonical_sha256(expected_content):
        raise ProtocolError("population manifest content_sha256 mismatch")
    return {**expected_content, "content_sha256": value["content_sha256"]}


def _beacon_rank(beacon: str, domain: str, value: str) -> str:
    return hashlib.sha256(f"{beacon}:{domain}:{value}".encode("utf-8")).hexdigest()


def _doubled_family(beacon: str, family_ids: list[str]) -> str:
    digest = hashlib.sha256(f"{beacon}:doubled-family".encode("ascii")).digest()
    return family_ids[int.from_bytes(digest, "big") % len(family_ids)]


def _assignment_content(
    protocol: Mapping[str, Any], population: Mapping[str, Any], *, beacon: str, beacon_round: str
) -> dict[str, Any]:
    by_family: dict[str, list[dict[str, str]]] = {family: [] for family in protocol["family_ids"]}
    for record in population["records"]:
        by_family[record["family_id"]].append(record)
    doubled = _doubled_family(beacon, protocol["family_ids"])
    raw_pairs: list[tuple[str, tuple[str, str]]] = []
    selected_uuids: list[str] = []
    for family in protocol["family_ids"]:
        ranked = sorted(
            by_family[family],
            key=lambda record: (_beacon_rank(beacon, f"select:{family}", record["lineage_uuid"]), record["lineage_uuid"]),
        )
        selected = ranked if family == doubled else ranked[:2]
        selected_uuids.extend(record["lineage_uuid"] for record in selected)
        pairing_order = sorted(
            selected,
            key=lambda record: (_beacon_rank(beacon, f"pair:{family}", record["lineage_uuid"]), record["lineage_uuid"]),
        )
        for index in range(0, len(pairing_order), 2):
            members = tuple(sorted(record["lineage_uuid"] for record in pairing_order[index : index + 2]))
            raw_pairs.append((family, members))
    if len(raw_pairs) != 5 or len(selected_uuids) != 10:
        raise ProtocolError("internal assignment cardinality failure")
    ordered_pairs = sorted(
        raw_pairs,
        key=lambda item: (_beacon_rank(beacon, "wave-order", "|".join(item[1])), item[0], item[1]),
    )
    wave_sequence = [wave for wave in protocol["waves"] for _ in range(protocol["pair_allocation"][wave])]
    pairs: list[dict[str, Any]] = []
    for index, ((family, members), wave) in enumerate(zip(ordered_pairs, wave_sequence), start=1):
        pair_id = f"pair-{index:02d}"
        slot_order = list(members)
        if int(_beacon_rank(beacon, "slot-order", pair_id), 16) % 2:
            slot_order.reverse()
        pairs.append(
            {
                "pair_id": pair_id,
                "family_id": family,
                "wave_id": wave,
                "member_uuids": list(members),
                "slot_order": slot_order,
            }
        )
    return {
        "schema": PAIR_ASSIGNMENT_SCHEMA,
        "protocol_id": protocol["protocol_id"],
        "protocol_sha256": canonical_sha256(protocol),
        "population_content_sha256": population["content_sha256"],
        "external_beacon_sha256": beacon,
        "external_beacon_round": beacon_round,
        "selected_lineage_uuids": sorted(selected_uuids),
        "pairs": pairs,
    }


def build_pair_assignment(
    protocol: object,
    population_manifest: object,
    external_beacon_sha256: str,
    external_beacon_round: str,
) -> dict[str, Any]:
    """Derive the five pair/wave/slot assignments from an external beacon.

    There are intentionally no arguments for a caller-selected roster, pair,
    wave, or slot.  Archive hashes and lineage names are not assignment inputs.
    """

    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    beacon = _sha256(external_beacon_sha256, label="external_beacon_sha256")
    beacon_round = _identifier(external_beacon_round, label="external_beacon_round")
    content = _assignment_content(frozen, population, beacon=beacon, beacon_round=beacon_round)
    assignment = {**content, "content_sha256": canonical_sha256(content)}
    validate_pair_assignment(assignment, frozen, population)
    return assignment


def _normalize_assignment_shape(value: Mapping[str, Any], *, protocol: Mapping[str, Any]) -> None:
    if value["schema"] != PAIR_ASSIGNMENT_SCHEMA:
        raise ProtocolError(f"pair assignment schema must be {PAIR_ASSIGNMENT_SCHEMA!r}")
    if value["protocol_id"] != protocol["protocol_id"]:
        raise ProtocolError("pair assignment protocol_id mismatch")
    if value["protocol_sha256"] != canonical_sha256(protocol):
        raise ProtocolError("pair assignment protocol_sha256 mismatch")
    _sha256(value["population_content_sha256"], label="population_content_sha256")
    _sha256(value["external_beacon_sha256"], label="external_beacon_sha256")
    _identifier(value["external_beacon_round"], label="external_beacon_round")
    selected = value["selected_lineage_uuids"]
    if not isinstance(selected, list) or len(selected) != 10:
        raise ProtocolError("selected_lineage_uuids must contain exactly 10 UUIDs")
    selected_uuids = [_uuid(item, label="selected_lineage_uuids item") for item in selected]
    if selected_uuids != sorted(set(selected_uuids)):
        raise ProtocolError("selected_lineage_uuids must be sorted and unique")
    pairs = value["pairs"]
    if not isinstance(pairs, list) or len(pairs) != 5:
        raise ProtocolError("pairs must contain exactly five pair records")
    seen_members: list[str] = []
    for index, pair in enumerate(pairs, start=1):
        record = _exact_fields(pair, _PAIR_FIELDS, label="pair record")
        if record["pair_id"] != f"pair-{index:02d}":
            raise ProtocolError("pair records must use canonical pair ids in order")
        if record["family_id"] not in protocol["family_ids"]:
            raise ProtocolError("pair record family_id is absent from protocol")
        if record["wave_id"] not in protocol["waves"]:
            raise ProtocolError("pair record wave_id is absent from protocol")
        members = record["member_uuids"]
        slots = record["slot_order"]
        if not isinstance(members, list) or len(members) != 2:
            raise ProtocolError("pair member_uuids must contain two UUIDs")
        clean_members = [_uuid(item, label="pair member UUID") for item in members]
        if clean_members != sorted(set(clean_members)):
            raise ProtocolError("pair member_uuids must be sorted and unique")
        if not isinstance(slots, list) or len(slots) != 2:
            raise ProtocolError("pair slot_order must contain two UUIDs")
        clean_slots = [_uuid(item, label="pair slot UUID") for item in slots]
        if set(clean_slots) != set(clean_members) or len(set(clean_slots)) != 2:
            raise ProtocolError("pair slot_order must be a permutation of member_uuids")
        seen_members.extend(clean_members)
    if sorted(seen_members) != selected_uuids:
        raise ProtocolError("pair members must exactly equal selected_lineage_uuids")


def validate_pair_assignment(
    assignment: object, protocol: object, population_manifest: object
) -> dict[str, Any]:
    """Validate that an assignment is exactly the beacon-derived receipt."""

    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    value = _exact_fields(assignment, _ASSIGNMENT_FIELDS, label="pair assignment")
    _normalize_assignment_shape(value, protocol=frozen)
    if value["population_content_sha256"] != population["content_sha256"]:
        raise ProtocolError("pair assignment population_content_sha256 mismatch")
    expected = _assignment_content(
        frozen,
        population,
        beacon=value["external_beacon_sha256"],
        beacon_round=value["external_beacon_round"],
    )
    if {key: value[key] for key in expected} != expected:
        raise ProtocolError("pair assignment does not match deterministic beacon assignment")
    if value["content_sha256"] != canonical_sha256(expected):
        raise ProtocolError("pair assignment content_sha256 mismatch")
    return {**expected, "content_sha256": value["content_sha256"]}


def _write_once(path: str | Path, payload: Mapping[str, Any], *, label: str) -> Path:
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"{label} already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"{label} already exists: {target}") from None
    return target


def write_protocol_once(path: str | Path, protocol: object) -> Path:
    """Write a valid frozen protocol once, using exclusive creation and fsync."""

    return _write_once(path, validate_protocol(protocol), label="protocol")


def write_population_manifest_once(path: str | Path, manifest: object, protocol: object) -> Path:
    """Write a valid UUID-rooted population manifest once, using fsync."""

    return _write_once(path, validate_population_manifest(manifest, protocol), label="population manifest")


def write_pair_assignment_once(
    path: str | Path, assignment: object, protocol: object, population_manifest: object
) -> Path:
    """Write a valid beacon-bound pair assignment once, using fsync."""

    return _write_once(
        path,
        validate_pair_assignment(assignment, protocol, population_manifest),
        label="pair assignment",
    )
