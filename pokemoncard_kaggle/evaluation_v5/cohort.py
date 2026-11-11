"""Custody primitives for the v5 external confirmatory cohort.

This module is deliberately local and outcome-agnostic at registration time.
Registrations and hosted observations are authenticated by small hash chains;
the first-48 composer only accepts literal, public, mature observations.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from evaluation_v5.canonical import canonical_json_bytes, canonical_sha256


REGISTRY_SCHEMA = "evaluation_v5_external_confirmatory_registry_v3"
REGISTRATION_SCHEMA = "evaluation_v5_archive_registration_v3"
OBSERVATION_LOG_SCHEMA = "evaluation_v5_hosted_observation_log_v4"
OBSERVATION_SCHEMA = "evaluation_v5_hosted_outcome_observation_v4"
HORIZON_SCHEMA = "evaluation_v5_literal_first48_manifest_v6"
PROTOCOL_ID = "MCI_TRANSFER_V1"
HORIZON_GAMES = 48
_GENESIS = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_REGISTRATION_FIELDS = frozenset(
    {
        "schema",
        "archive_sha256",
        "deck_sha256",
        "policy_sha256",
        "model_input_sha256",
        "family_provenance_sha256",
        "team_pseudonym",
        "submission_slot_id",
        "intended_window_start_utc",
        "intended_window_end_utc",
        "consent_sha256",
        "registered_at_utc",
    }
)
_REGISTRY_FIELDS = frozenset({"schema", "protocol", "records", "chain_hashes"})
_OBSERVATION_FIELDS = frozenset(
    {
        "schema",
        "archive_sha256",
        "game_id",
        "created_at_utc",
        "completion_observed_at_utc",
        "completion_evidence_sha256",
        "seat",
        "opponent_rating",
        "outcome",
        "mature_after_utc",
        "hosted_scope",
        "replay_content_sha256",
    }
)
_OBSERVATION_LATER_FIELDS = _OBSERVATION_FIELDS | {"first_hosted_game_at_utc"}
_OBSERVATION_LOG_FIELDS = frozenset({"schema", "records", "chain_hashes"})
_MANIFEST_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "protocol",
        "archive_sha256",
        "registration_sha256",
        "registration_chain_head",
        "observation_chain_head",
        "observation_log_prefix_length",
        "as_of_utc",
        "completion_observed_at_utc",
        "completion_evidence_sha256",
        "mature_after_utc",
        "first_hosted_game_at_utc",
        "games",
    }
)
_MANIFEST_FIELDS = _MANIFEST_CONTENT_FIELDS | {"manifest_sha256"}


class CohortCustodyError(ValueError):
    """A v5 registration, observation, chain, or horizon is invalid."""


# Short aliases make callers which use the protocol's terminology readable.
EvaluationV5Error = CohortCustodyError
CustodyError = CohortCustodyError


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CohortCustodyError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CohortCustodyError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _parse_utc(value: object, *, label: str, require_canonical: bool) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise CohortCustodyError(f"{label} is required")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CohortCustodyError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CohortCustodyError(f"{label} must include a UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if require_canonical and value != normalized:
        raise CohortCustodyError(f"{label} must be canonical UTC")
    return parsed, normalized


def _utc_for_build(value: object, *, label: str) -> str:
    return _parse_utc(value, label=label, require_canonical=False)[1]


def _nonempty_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CohortCustodyError(f"{label} must be a non-empty trimmed string")
    return value


def derive_family_provenance_sha256(family_provenance: Mapping[str, Any]) -> str:
    """Derive the family/provenance identity from its canonical local record."""

    if not isinstance(family_provenance, Mapping) or not family_provenance:
        raise CohortCustodyError("family/provenance evidence is required")
    try:
        return canonical_sha256(dict(family_provenance))
    except (TypeError, ValueError) as exc:
        raise CohortCustodyError("family/provenance evidence is not canonical JSON") from exc


# Natural spelling used by some callers.
family_provenance_sha256 = derive_family_provenance_sha256


def build_archive_registration(
    *,
    archive_sha256: str,
    deck_sha256: str,
    policy_sha256: str,
    model_input_sha256: str,
    team_pseudonym: str,
    submission_slot_id: str,
    intended_window_start_utc: str,
    intended_window_end_utc: str,
    consent_sha256: str,
    registered_at_utc: str,
    family_provenance: Mapping[str, Any] | None = None,
    family_provenance_sha256: str | None = None,
) -> dict[str, Any]:
    """Build the exact outcome-free registration record.

    Supplying raw family/provenance evidence is preferred.  A pre-derived hash
    is accepted for detached custody imports, but it is still required and is
    validated as a SHA-256 digest.
    """

    if family_provenance is None and family_provenance_sha256 is None:
        raise CohortCustodyError("family/provenance evidence or its derived hash is required")
    derived = (
        derive_family_provenance_sha256(family_provenance)
        if family_provenance is not None
        else None
    )
    if family_provenance_sha256 is not None:
        _sha256(family_provenance_sha256, label="family_provenance_sha256")
        if derived is not None and derived != family_provenance_sha256:
            raise CohortCustodyError("family/provenance hash does not match its evidence")
    record = {
        "schema": REGISTRATION_SCHEMA,
        "archive_sha256": archive_sha256,
        "deck_sha256": deck_sha256,
        "policy_sha256": policy_sha256,
        "model_input_sha256": model_input_sha256,
        "family_provenance_sha256": family_provenance_sha256 or derived,
        "team_pseudonym": team_pseudonym,
        "submission_slot_id": submission_slot_id,
        "intended_window_start_utc": _utc_for_build(
            intended_window_start_utc, label="intended_window_start_utc"
        ),
        "intended_window_end_utc": _utc_for_build(
            intended_window_end_utc, label="intended_window_end_utc"
        ),
        "consent_sha256": consent_sha256,
        "registered_at_utc": _utc_for_build(registered_at_utc, label="registered_at_utc"),
    }
    return validate_registration(record)


def validate_registration(value: object) -> dict[str, Any]:
    """Validate and return an exact registration without adding any fields."""

    raw = _exact_fields(value, _REGISTRATION_FIELDS, label="registration")
    if raw["schema"] != REGISTRATION_SCHEMA:
        raise CohortCustodyError(f"registration schema must be {REGISTRATION_SCHEMA!r}")
    for field in (
        "archive_sha256",
        "deck_sha256",
        "policy_sha256",
        "model_input_sha256",
        "family_provenance_sha256",
        "consent_sha256",
    ):
        _sha256(raw[field], label=field)
    _nonempty_identifier(raw["team_pseudonym"], label="team_pseudonym")
    _nonempty_identifier(raw["submission_slot_id"], label="submission_slot_id")
    window_start, window_start_text = _parse_utc(
        raw["intended_window_start_utc"],
        label="intended_window_start_utc",
        require_canonical=True,
    )
    window_end, window_end_text = _parse_utc(
        raw["intended_window_end_utc"],
        label="intended_window_end_utc",
        require_canonical=True,
    )
    if window_end <= window_start:
        raise CohortCustodyError("intended_window_end_utc must be after intended_window_start_utc")
    _, timestamp = _parse_utc(raw["registered_at_utc"], label="registered_at_utc", require_canonical=True)
    normalized = dict(raw)
    normalized["intended_window_start_utc"] = window_start_text
    normalized["intended_window_end_utc"] = window_end_text
    normalized["registered_at_utc"] = timestamp
    return normalized


def _validate_first_hosted_window(
    registration: Mapping[str, Any], observations: Iterable[Mapping[str, Any]]
) -> str:
    records = list(observations)
    if not records:
        raise CohortCustodyError("at least one hosted observation is required")
    first = min(records, key=lambda item: (item["created_at_utc"], item["game_id"]))
    start, _ = _parse_utc(
        registration["intended_window_start_utc"],
        label="intended_window_start_utc",
        require_canonical=True,
    )
    end, _ = _parse_utc(
        registration["intended_window_end_utc"],
        label="intended_window_end_utc",
        require_canonical=True,
    )
    first_created, first_created_text = _parse_utc(
        first["created_at_utc"],
        label="first hosted created_at_utc",
        require_canonical=True,
    )
    if first_created < start or first_created > end:
        raise CohortCustodyError(
            "first hosted game is outside the registered intended timestamp window"
        )
    for item in records:
        if "first_hosted_game_at_utc" not in item:
            continue
        _, declared_text = _parse_utc(
            item["first_hosted_game_at_utc"],
            label="first_hosted_game_at_utc",
            require_canonical=True,
        )
        if declared_text != first_created_text:
            raise CohortCustodyError(
                "first_hosted_game_at_utc must equal the computed earliest hosted game timestamp"
            )
    return first_created_text


def _chain_link(previous: str, record: Mapping[str, Any]) -> str:
    return canonical_sha256({"previous_chain_hash": previous, "record": record})


def new_registry() -> dict[str, Any]:
    return {"schema": REGISTRY_SCHEMA, "protocol": PROTOCOL_ID, "records": [], "chain_hashes": []}


def _validate_registry(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _REGISTRY_FIELDS, label="registry")
    if raw["schema"] != REGISTRY_SCHEMA or raw["protocol"] != PROTOCOL_ID:
        raise CohortCustodyError("registry schema or protocol is not v5")
    records = raw["records"]
    chains = raw["chain_hashes"]
    if not isinstance(records, list) or not isinstance(chains, list) or len(records) != len(chains):
        raise CohortCustodyError("registry records and chain_hashes must be equal-length lists")
    seen: set[str] = set()
    previous = _GENESIS
    prior_registered: datetime | None = None
    normalized_records: list[dict[str, Any]] = []
    for index, (record, chain_hash) in enumerate(zip(records, chains)):
        normalized = validate_registration(record)
        archive = normalized["archive_sha256"]
        if archive in seen:
            raise CohortCustodyError(f"duplicate archive hash at registry record {index}")
        seen.add(archive)
        registered, _ = _parse_utc(
            normalized["registered_at_utc"], label="registered_at_utc", require_canonical=True
        )
        if prior_registered is not None and registered < prior_registered:
            raise CohortCustodyError("registry registration chronology is retroactive")
        _sha256(chain_hash, label=f"chain_hashes[{index}]")
        expected = _chain_link(previous, normalized)
        if chain_hash != expected:
            raise CohortCustodyError(f"registry chain hash mismatch at index {index}")
        normalized_records.append(normalized)
        previous = chain_hash
        prior_registered = registered
    return {
        "schema": REGISTRY_SCHEMA,
        "protocol": PROTOCOL_ID,
        "records": normalized_records,
        "chain_hashes": list(chains),
    }


def validate_registry(value: object) -> dict[str, Any]:
    return _validate_registry(value)


def append_registration(registry: Mapping[str, Any], registration: Mapping[str, Any]) -> dict[str, Any]:
    """Return a new registry with one append-only registration."""

    current = _validate_registry(registry)
    record = validate_registration(registration)
    if any(item["archive_sha256"] == record["archive_sha256"] for item in current["records"]):
        raise CohortCustodyError("duplicate archive hash cannot be registered")
    if current["records"]:
        previous, _ = _parse_utc(
            current["records"][-1]["registered_at_utc"],
            label="registered_at_utc",
            require_canonical=True,
        )
        registered, _ = _parse_utc(
            record["registered_at_utc"], label="registered_at_utc", require_canonical=True
        )
        if registered < previous:
            raise CohortCustodyError("retroactive registration is forbidden")
    result = deepcopy(current)
    result["records"].append(record)
    previous = result["chain_hashes"][-1] if result["chain_hashes"] else _GENESIS
    result["chain_hashes"].append(_chain_link(previous, record))
    return _validate_registry(result)


register_archive = append_registration
append_archive_registration = append_registration


def write_registry_create_once(path: str | Path, registry: Mapping[str, Any]) -> Path:
    """Write one canonical registry snapshot and refuse every overwrite."""

    checked = _validate_registry(registry)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json_bytes(checked).decode("ascii"))
            handle.write("\n")
    except FileExistsError as exc:
        raise CohortCustodyError("registry is create-once and already exists") from exc
    return destination


def load_registry(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CohortCustodyError(f"cannot read registry: {exc}") from exc
    return _validate_registry(value)


def append_registration_file(path: str | Path, registration: Mapping[str, Any]) -> Path:
    """Append semantically to a registry snapshot after validating its chain."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    current = load_registry(destination) if destination.exists() else new_registry()
    updated = append_registration(current, registration)
    temporary = destination.with_name(destination.name + ".append.tmp")
    try:
        if temporary.exists():
            temporary.unlink()
        write_registry_create_once(temporary, updated)
        temporary.replace(destination)
    except OSError as exc:
        if temporary.exists():
            temporary.unlink()
        raise CohortCustodyError(f"cannot append registry: {exc}") from exc
    return destination


def build_outcome_observation(
    *,
    archive_sha256: str,
    game_id: str | None = None,
    hosted_game_id: str | None = None,
    created_at_utc: str,
    completion_observed_at_utc: str,
    completion_evidence_sha256: str,
    seat: int,
    opponent_rating: int | float,
    outcome: str,
    hosted_scope: str = "public",
    first_hosted_game_at_utc: str | None = None,
    replay_content_sha256: str | None = None,
) -> dict[str, Any]:
    """Build one outcome observation; validation games cannot be represented."""

    chosen_game_id = game_id if game_id is not None else hosted_game_id
    if game_id is not None and hosted_game_id is not None and game_id != hosted_game_id:
        raise CohortCustodyError("game_id and hosted_game_id disagree")
    created = _utc_for_build(created_at_utc, label="created_at_utc")
    completion_observed = _utc_for_build(
        completion_observed_at_utc, label="completion_observed_at_utc"
    )
    created_dt, _ = _parse_utc(created, label="created_at_utc", require_canonical=True)
    completion_dt, _ = _parse_utc(
        completion_observed,
        label="completion_observed_at_utc",
        require_canonical=True,
    )
    if isinstance(seat, bool) or seat not in (0, 1):
        raise CohortCustodyError("seat must be 0 or 1")
    if isinstance(opponent_rating, bool) or not isinstance(opponent_rating, (int, float)):
        raise CohortCustodyError("opponent_rating must be numeric")
    if not math.isfinite(float(opponent_rating)) or float(opponent_rating) < 0:
        raise CohortCustodyError("opponent_rating must be a finite non-negative number")
    if outcome not in {"win", "loss", "runtime_failure"}:
        raise CohortCustodyError("outcome must be win, loss, or runtime_failure")
    record = {
        "schema": OBSERVATION_SCHEMA,
        "archive_sha256": archive_sha256,
        "game_id": _nonempty_identifier(chosen_game_id, label="game_id"),
        "created_at_utc": created,
        "completion_observed_at_utc": completion_observed,
        "completion_evidence_sha256": completion_evidence_sha256,
        "seat": seat,
        "opponent_rating": float(opponent_rating),
        "outcome": outcome,
        "mature_after_utc": (completion_dt + timedelta(hours=1)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
        "hosted_scope": hosted_scope,
        "replay_content_sha256": replay_content_sha256,
    }
    if first_hosted_game_at_utc is not None:
        first_hosted_dt, first_hosted_text = _parse_utc(
            first_hosted_game_at_utc,
            label="first_hosted_game_at_utc",
            require_canonical=False,
        )
        if first_hosted_dt > created_dt:
            raise CohortCustodyError("first_hosted_game_at_utc cannot follow the observed game")
        record["first_hosted_game_at_utc"] = first_hosted_text
    return validate_observation(record)


observe_game = build_outcome_observation


def validate_observation(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CohortCustodyError("outcome observation must be a mapping")
    fields = _OBSERVATION_LATER_FIELDS if "first_hosted_game_at_utc" in value else _OBSERVATION_FIELDS
    raw = _exact_fields(value, fields, label="outcome observation")
    if raw["schema"] != OBSERVATION_SCHEMA:
        raise CohortCustodyError(f"observation schema must be {OBSERVATION_SCHEMA!r}")
    _sha256(raw["archive_sha256"], label="archive_sha256")
    _sha256(raw["completion_evidence_sha256"], label="completion_evidence_sha256")
    if raw["replay_content_sha256"] is not None:
        _sha256(raw["replay_content_sha256"], label="replay_content_sha256")
    _nonempty_identifier(raw["game_id"], label="game_id")
    created, created_text = _parse_utc(raw["created_at_utc"], label="created_at_utc", require_canonical=True)
    completion, completion_text = _parse_utc(
        raw["completion_observed_at_utc"],
        label="completion_observed_at_utc",
        require_canonical=True,
    )
    mature, mature_text = _parse_utc(
        raw["mature_after_utc"], label="mature_after_utc", require_canonical=True
    )
    expected_mature = (completion + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if mature_text != expected_mature:
        raise CohortCustodyError(
            "mature_after_utc must equal completion_observed_at_utc plus exactly one hour"
        )
    if created < mature:
        raise CohortCustodyError("created_at_utc must be at or after mature_after_utc")
    if isinstance(raw["seat"], bool) or raw["seat"] not in (0, 1):
        raise CohortCustodyError("seat must be 0 or 1")
    rating = raw["opponent_rating"]
    if isinstance(rating, bool) or not isinstance(rating, (int, float)):
        raise CohortCustodyError("opponent_rating must be numeric")
    if not math.isfinite(float(rating)) or float(rating) < 0:
        raise CohortCustodyError("opponent_rating must be a finite non-negative number")
    if raw["outcome"] not in {"win", "loss", "runtime_failure"}:
        raise CohortCustodyError("invalid hosted outcome")
    if raw["hosted_scope"] != "public":
        raise CohortCustodyError("only literal public hosted games are eligible")
    normalized = {
        **dict(raw),
        "created_at_utc": created_text,
        "completion_observed_at_utc": completion_text,
        "mature_after_utc": mature_text,
        "opponent_rating": float(rating),
    }
    if "first_hosted_game_at_utc" in raw:
        first_hosted, first_hosted_text = _parse_utc(
            raw["first_hosted_game_at_utc"],
            label="first_hosted_game_at_utc",
            require_canonical=True,
        )
        if first_hosted > created:
            raise CohortCustodyError("first_hosted_game_at_utc cannot follow the observed game")
        normalized["first_hosted_game_at_utc"] = first_hosted_text
    return normalized


def new_observation_log() -> dict[str, Any]:
    return {"schema": OBSERVATION_LOG_SCHEMA, "records": [], "chain_hashes": []}


def validate_observation_log(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _OBSERVATION_LOG_FIELDS, label="observation log")
    if raw["schema"] != OBSERVATION_LOG_SCHEMA:
        raise CohortCustodyError("observation log schema mismatch")
    records = raw["records"]
    chains = raw["chain_hashes"]
    if not isinstance(records, list) or not isinstance(chains, list) or len(records) != len(chains):
        raise CohortCustodyError("observation log records and chain_hashes must align")
    previous = _GENESIS
    seen_ids: set[str] = set()
    last_created_by_archive: dict[str, datetime] = {}
    checked: list[dict[str, Any]] = []
    for index, (record, chain_hash) in enumerate(zip(records, chains)):
        checked_record = validate_observation(record)
        if checked_record["game_id"] in seen_ids:
            raise CohortCustodyError(f"duplicate hosted game id at observation {index}")
        seen_ids.add(checked_record["game_id"])
        created, _ = _parse_utc(
            checked_record["created_at_utc"],
            label="created_at_utc",
            require_canonical=True,
        )
        archive = checked_record["archive_sha256"]
        prior_created = last_created_by_archive.get(archive)
        if prior_created is not None and created <= prior_created:
            raise CohortCustodyError(
                "hosted observations must be appended in strictly increasing "
                "created_at_utc order per archive"
            )
        last_created_by_archive[archive] = created
        _sha256(chain_hash, label=f"chain_hashes[{index}]")
        expected = _chain_link(previous, checked_record)
        if chain_hash != expected:
            raise CohortCustodyError(f"observation chain hash mismatch at index {index}")
        checked.append(checked_record)
        previous = chain_hash
    return {"schema": OBSERVATION_LOG_SCHEMA, "records": checked, "chain_hashes": list(chains)}


def append_observations_batch(
    log: Mapping[str, Any],
    observations: Iterable[Mapping[str, Any]],
    *,
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Atomically append observations after one starting-state validation."""

    current = validate_observation_log(log)
    checked_registry = validate_registry(registry)
    registrations = {item["archive_sha256"]: item for item in checked_registry["records"]}
    result = deepcopy(current)
    seen_ids = {item["game_id"] for item in result["records"]}
    archive_records: dict[str, list[dict[str, Any]]] = {}
    for item in result["records"]:
        archive_records.setdefault(item["archive_sha256"], []).append(item)
    initialized_archives: set[str] = set()
    previous = result["chain_hashes"][-1] if result["chain_hashes"] else _GENESIS

    for observation in observations:
        record = validate_observation(observation)
        if record["game_id"] in seen_ids:
            raise CohortCustodyError("duplicate hosted game id cannot be observed")
        registration = registrations.get(record["archive_sha256"])
        if registration is None:
            raise CohortCustodyError("observation archive was not registered")
        records_for_archive = archive_records.setdefault(record["archive_sha256"], [])
        if record["archive_sha256"] not in initialized_archives:
            if records_for_archive:
                registered, _ = _parse_utc(
                    registration["registered_at_utc"],
                    label="registered_at_utc",
                    require_canonical=True,
                )
                if any(
                    _parse_utc(
                        item["created_at_utc"],
                        label="created_at_utc",
                        require_canonical=True,
                    )[0]
                    <= registered
                    for item in records_for_archive
                ):
                    raise CohortCustodyError(
                        "hosted game must be after archive registration"
                    )
                _validate_first_hosted_window(registration, records_for_archive)
            initialized_archives.add(record["archive_sha256"])

        registered, _ = _parse_utc(
            registration["registered_at_utc"],
            label="registered_at_utc",
            require_canonical=True,
        )
        record_created, _ = _parse_utc(
            record["created_at_utc"], label="created_at_utc", require_canonical=True
        )
        if record_created <= registered:
            raise CohortCustodyError("hosted game must be after archive registration")
        if records_for_archive:
            prior_created, _ = _parse_utc(
                records_for_archive[-1]["created_at_utc"],
                label="created_at_utc",
                require_canonical=True,
            )
            if record_created <= prior_created:
                raise CohortCustodyError(
                    "new hosted observation created_at_utc must be strictly later "
                    "than the last observation for its archive"
                )
            if "first_hosted_game_at_utc" in record:
                _, declared_first = _parse_utc(
                    record["first_hosted_game_at_utc"],
                    label="first_hosted_game_at_utc",
                    require_canonical=True,
                )
                if declared_first != records_for_archive[0]["created_at_utc"]:
                    raise CohortCustodyError(
                        "first_hosted_game_at_utc must equal the computed earliest "
                        "hosted game timestamp"
                    )
        else:
            _validate_first_hosted_window(registration, [record])

        records_for_archive.append(record)
        result["records"].append(record)
        previous = _chain_link(previous, record)
        result["chain_hashes"].append(previous)
        seen_ids.add(record["game_id"])

    return validate_observation_log(result)


def append_observation(
    log: Mapping[str, Any],
    observation: Mapping[str, Any],
    *,
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    """Append one observation through the atomic batch implementation."""

    return append_observations_batch(log, (observation,), registry=registry)


record_observation = append_observation


def _registration_for(
    registry: Mapping[str, Any], archive_sha256: str | None
) -> tuple[dict[str, Any], str, str]:
    checked_registry = validate_registry(registry)
    if not checked_registry["records"]:
        raise CohortCustodyError("registry has no archive registrations")
    chosen = archive_sha256
    if chosen is None:
        if len(checked_registry["records"]) != 1:
            raise CohortCustodyError("archive_sha256 is required for a multi-archive registry")
        chosen = checked_registry["records"][0]["archive_sha256"]
    _sha256(chosen, label="archive_sha256")
    matches = [
        item for item in checked_registry["records"] if item["archive_sha256"] == chosen
    ]
    if len(matches) != 1:
        raise CohortCustodyError("archive is absent from registry")
    index = checked_registry["records"].index(matches[0])
    return matches[0], canonical_sha256(matches[0]), checked_registry["chain_hashes"][index]


def compose_first48(
    registry: Mapping[str, Any],
    observation_log: Mapping[str, Any],
    *,
    archive_sha256: str | None = None,
    as_of_utc: str | None = None,
    now_utc: str | None = None,
) -> dict[str, Any]:
    """Compose the literal first 48 games from one validated global log."""

    if as_of_utc is not None and now_utc is not None:
        raise CohortCustodyError("provide only one of as_of_utc and now_utc")
    as_of = as_of_utc or now_utc
    if as_of is None:
        raise CohortCustodyError("as_of_utc is required for deterministic composition")
    as_of_dt, as_of_text = _parse_utc(as_of, label="as_of_utc", require_canonical=False)
    registration, registration_sha, registration_chain_head = _registration_for(
        registry, archive_sha256
    )
    checked_log = validate_observation_log(observation_log)
    target = registration["archive_sha256"]
    target_records = [
        item for item in checked_log["records"] if item["archive_sha256"] == target
    ]
    registered_dt, _ = _parse_utc(
        registration["registered_at_utc"], label="registered_at_utc", require_canonical=True
    )
    for item in target_records:
        created, _ = _parse_utc(item["created_at_utc"], label="created_at_utc", require_canonical=True)
        if created <= registered_dt:
            raise CohortCustodyError("game was created before or at archive registration")
    if len(target_records) < HORIZON_GAMES:
        raise CohortCustodyError(
            f"literal first48 requires at least {HORIZON_GAMES} games; "
            f"received {len(target_records)} for the target archive"
        )
    games = sorted(
        target_records, key=lambda item: (item["created_at_utc"], item["game_id"])
    )[:HORIZON_GAMES]
    first_hosted_game_at_utc = _validate_first_hosted_window(registration, games)
    maturity_boundaries = {item["mature_after_utc"] for item in games}
    if len(maturity_boundaries) != 1:
        raise CohortCustodyError("all first48 observations must share one mature_after_utc boundary")
    mature_after_text = next(iter(maturity_boundaries))
    completion_observed = {item["completion_observed_at_utc"] for item in games}
    if len(completion_observed) != 1:
        raise CohortCustodyError(
            "all first48 observations must share one completion_observed_at_utc"
        )
    completion_observed_text = next(iter(completion_observed))
    completion_evidence = {item["completion_evidence_sha256"] for item in games}
    if len(completion_evidence) != 1:
        raise CohortCustodyError(
            "all first48 observations must share one completion_evidence_sha256"
        )
    completion_evidence_sha256 = next(iter(completion_evidence))
    maturity_boundary, _ = _parse_utc(
        mature_after_text, label="mature_after_utc", require_canonical=True
    )
    if maturity_boundary > as_of_dt:
        raise CohortCustodyError("archive maturity boundary is not yet mature")
    for item in games:
        created, _ = _parse_utc(item["created_at_utc"], label="created_at_utc", require_canonical=True)
        if created < maturity_boundary:
            raise CohortCustodyError(f"observation {item['game_id']} is immature: precedes mature_after_utc")
        if created > as_of_dt:
            raise CohortCustodyError(
                f"observation {item['game_id']} was created after as_of_utc"
            )
    global_index_by_game_id = {
        item["game_id"]: index for index, item in enumerate(checked_log["records"])
    }
    boundary_index = global_index_by_game_id[games[-1]["game_id"]]
    content = {
        "schema": HORIZON_SCHEMA,
        "protocol": PROTOCOL_ID,
        "archive_sha256": target,
        "registration_sha256": registration_sha,
        "registration_chain_head": registration_chain_head,
        "observation_chain_head": checked_log["chain_hashes"][boundary_index],
        "observation_log_prefix_length": boundary_index + 1,
        "as_of_utc": as_of_text,
        "completion_observed_at_utc": completion_observed_text,
        "completion_evidence_sha256": completion_evidence_sha256,
        "mature_after_utc": mature_after_text,
        "first_hosted_game_at_utc": first_hosted_game_at_utc,
        "games": games,
    }
    return {**content, "manifest_sha256": canonical_sha256(content)}


compose_first48_horizon = compose_first48
build_first48_manifest = compose_first48


def validate_first48_manifest(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _MANIFEST_FIELDS, label="first48 manifest")
    content = {key: raw[key] for key in _MANIFEST_CONTENT_FIELDS}
    if raw["manifest_sha256"] != canonical_sha256(content):
        raise CohortCustodyError("first48 manifest hash mismatch")
    if content["schema"] != HORIZON_SCHEMA or content["protocol"] != PROTOCOL_ID:
        raise CohortCustodyError("first48 manifest schema or protocol mismatch")
    _sha256(content["archive_sha256"], label="archive_sha256")
    _sha256(content["registration_sha256"], label="registration_sha256")
    if content["registration_chain_head"] != _GENESIS:
        _sha256(content["registration_chain_head"], label="registration_chain_head")
    _sha256(content["observation_chain_head"], label="observation_chain_head")
    prefix_length = content["observation_log_prefix_length"]
    if (
        isinstance(prefix_length, bool)
        or not isinstance(prefix_length, int)
        or prefix_length < HORIZON_GAMES
    ):
        raise CohortCustodyError(
            "observation_log_prefix_length must be an integer of at least 48"
        )
    _parse_utc(content["as_of_utc"], label="as_of_utc", require_canonical=True)
    completion_observed, completion_observed_text = _parse_utc(
        content["completion_observed_at_utc"],
        label="completion_observed_at_utc",
        require_canonical=True,
    )
    _sha256(content["completion_evidence_sha256"], label="completion_evidence_sha256")
    maturity_boundary, _ = _parse_utc(
        content["mature_after_utc"], label="mature_after_utc", require_canonical=True
    )
    expected_mature = (completion_observed + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if content["mature_after_utc"] != expected_mature:
        raise CohortCustodyError(
            "manifest mature_after_utc must equal completion_observed_at_utc plus exactly one hour"
        )
    as_of, _ = _parse_utc(content["as_of_utc"], label="as_of_utc", require_canonical=True)
    if maturity_boundary > as_of:
        raise CohortCustodyError("manifest maturity boundary is not yet mature")
    _parse_utc(
        content["first_hosted_game_at_utc"], label="first_hosted_game_at_utc", require_canonical=True
    )
    games = content["games"]
    if not isinstance(games, list) or len(games) != HORIZON_GAMES:
        raise CohortCustodyError("first48 manifest must contain exactly 48 games")
    checked = [validate_observation(game) for game in games]
    game_ids = [game["game_id"] for game in checked]
    if len(set(game_ids)) != len(game_ids):
        raise CohortCustodyError("first48 manifest contains duplicate hosted game ids")
    if any(game["archive_sha256"] != content["archive_sha256"] for game in checked):
        raise CohortCustodyError("first48 manifest contains another archive")
    if {game["mature_after_utc"] for game in checked} != {content["mature_after_utc"]}:
        raise CohortCustodyError("manifest games do not share the common maturity boundary")
    if {game["completion_observed_at_utc"] for game in checked} != {
        completion_observed_text
    }:
        raise CohortCustodyError(
            "manifest games do not share the common completion observation timestamp"
        )
    if {game["completion_evidence_sha256"] for game in checked} != {
        content["completion_evidence_sha256"]
    }:
        raise CohortCustodyError("manifest games do not share the completion evidence hash")
    if any(
        _parse_utc(game["created_at_utc"], label="created_at_utc", require_canonical=True)[0]
        < maturity_boundary
        for game in checked
    ):
        raise CohortCustodyError("manifest contains a game before the maturity boundary")
    if any(
        _parse_utc(game["created_at_utc"], label="created_at_utc", require_canonical=True)[0]
        > as_of
        for game in checked
    ):
        raise CohortCustodyError("manifest contains a game created after as_of_utc")
    if checked != sorted(checked, key=lambda item: (item["created_at_utc"], item["game_id"])):
        raise CohortCustodyError("first48 games are not chronological")
    if checked[0]["created_at_utc"] != content["first_hosted_game_at_utc"]:
        raise CohortCustodyError("first_hosted_game_at_utc is not bound to the first game")
    return {**content, "games": checked, "manifest_sha256": raw["manifest_sha256"]}


__all__ = [
    "CohortCustodyError",
    "EvaluationV5Error",
    "CustodyError",
    "REGISTRY_SCHEMA",
    "REGISTRATION_SCHEMA",
    "OBSERVATION_LOG_SCHEMA",
    "OBSERVATION_SCHEMA",
    "HORIZON_SCHEMA",
    "PROTOCOL_ID",
    "HORIZON_GAMES",
    "canonical_json_bytes",
    "canonical_sha256",
    "derive_family_provenance_sha256",
    "family_provenance_sha256",
    "build_archive_registration",
    "validate_registration",
    "new_registry",
    "validate_registry",
    "append_registration",
    "register_archive",
    "append_archive_registration",
    "write_registry_create_once",
    "load_registry",
    "append_registration_file",
    "build_outcome_observation",
    "observe_game",
    "validate_observation",
    "new_observation_log",
    "validate_observation_log",
    "append_observations_batch",
    "append_observation",
    "record_observation",
    "compose_first48",
    "compose_first48_horizon",
    "build_first48_manifest",
    "validate_first48_manifest",
]
