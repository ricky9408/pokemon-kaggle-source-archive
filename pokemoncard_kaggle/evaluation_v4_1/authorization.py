"""Artifact-bound research firewall for the VOI-P5 calibration experiment.

This module never calls Kaggle and never grants production authority.  Every
research slot is derived from the beacon assignment and recomputed prediction
bundle; callers cannot invent pair, wave, lineage, or archive bindings.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .prediction import validate_prediction_bundle
from .protocol import (
    canonical_json_bytes,
    canonical_sha256,
    validate_pair_assignment,
    validate_population_manifest,
    validate_protocol,
)
from .runtime import validate_kaggle_runtime_binding


AUTHORIZATION_SCHEMA = "voi_p5_authorization_v4"
USAGE_LEDGER_SCHEMA = "voi_p5_usage_ledger_v4"
PERMIT_SCHEMA = "voi_p5_research_submission_permit_v4"
MAX_SUBMISSIONS = 10
PAIR_COUNT = 5
SLOTS_PER_PAIR = 2
HORIZON = "literal_first24"
SCOPE = "RESEARCH_ONLY_CALIBRATION"
GENESIS_EVENT_SHA256 = "0" * 64

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_id",
        "protocol_sha256",
        "population_content_sha256",
        "pair_assignment_content_sha256",
        "prediction_bundle_content_sha256",
        "kaggle_runtime_binding_content_sha256",
        "usage_ledger_path",
        "usage_ledger_path_sha256",
        "archive_assignments",
        "max_submissions",
        "horizon",
        "replacement_policy",
        "interim_efficacy_policy",
        "scope",
        "explicit_user_override_text_sha256",
        "created_at_utc",
        "expires_at_utc",
        "state",
        "research_only",
        "production_submission_authorized",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}
_ASSIGNMENT_FIELDS = frozenset(
    {
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
    }
)
_EVENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "sequence",
        "event_id",
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "prior_pair_barrier_content_sha256",
        "created_at_utc",
        "previous_event_sha256",
        "event_sha256",
    }
)
_PERMIT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "protocol_sha256",
        "population_content_sha256",
        "pair_assignment_content_sha256",
        "prediction_bundle_content_sha256",
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "prior_pair_barrier_content_sha256",
        "usage_sequence",
        "usage_event_sha256",
        "horizon",
        "scope",
        "remaining_cap",
        "research_only",
        "production_submission_authorized",
        "content_sha256",
    }
)


class AuthorizationError(ValueError):
    """The research authorization or usage ledger is invalid."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AuthorizationError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise AuthorizationError(f"{label} must be a strict identifier")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise AuthorizationError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: object, *, label: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise AuthorizationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AuthorizationError(f"{label} is invalid") from exc
    return parsed, value


def _now(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise AuthorizationError("now must be timezone-aware")
        return value.astimezone(timezone.utc)
    return _utc(value, label="now")[0]


def _wall_now() -> datetime:
    return datetime.now(timezone.utc)


def _archive_name(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise AuthorizationError(f"{label} must be a trimmed basename")
    if Path(value).name != value or value in {".", ".."} or "/" in value or "\\" in value:
        raise AuthorizationError(f"{label} must be a basename")
    if "final" in value.casefold():
        raise AuthorizationError(f"{label} must not contain 'final'")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AuthorizationError(f"{label} contains a control character")
    return value


def _archive_name_map(value: object, selected: set[str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != selected:
        raise AuthorizationError("archive_names_by_lineage_uuid must exactly cover selected lineages")
    names = {lineage_uuid: _archive_name(name, label="archive name") for lineage_uuid, name in value.items()}
    if len(set(names.values())) != MAX_SUBMISSIONS:
        raise AuthorizationError("archive names must be unique")
    return names


def _canonical_path(value: object, *, label: str) -> tuple[str, str]:
    if not isinstance(value, (str, os.PathLike)):
        raise AuthorizationError(f"{label} must be a filesystem path")
    path = Path(value).expanduser().resolve(strict=False)
    text = str(path)
    if not path.is_absolute() or not text:
        raise AuthorizationError(f"{label} must resolve to an absolute path")
    return text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def _derive_assignments(
    *,
    population: Mapping[str, Any],
    pair_assignment: Mapping[str, Any],
    archive_names_by_lineage_uuid: object,
) -> list[dict[str, Any]]:
    selected = set(pair_assignment["selected_lineage_uuids"])
    names = _archive_name_map(archive_names_by_lineage_uuid, selected)
    population_by_uuid = {record["lineage_uuid"]: record for record in population["records"]}
    assignments: list[dict[str, Any]] = []
    for pair in pair_assignment["pairs"]:
        for slot, lineage_uuid in enumerate(pair["slot_order"], start=1):
            assignments.append(
                {
                    "archive_sha256": population_by_uuid[lineage_uuid]["archive_sha256"],
                    "archive_name": names[lineage_uuid],
                    "lineage_uuid": lineage_uuid,
                    "pair_id": pair["pair_id"],
                    "wave_id": pair["wave_id"],
                    "slot": slot,
                }
            )
    return assignments


def _build_content(
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    prediction_bundle: object,
    predictor_model: object,
    kaggle_runtime_binding: object,
    usage_ledger_path: str | Path,
    archive_names_by_lineage_uuid: object,
    authorization_id: str,
    explicit_user_override_text_sha256: str,
    created_at_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    frozen = validate_protocol(protocol)
    population = validate_population_manifest(population_manifest, frozen)
    assignment = validate_pair_assignment(pair_assignment, frozen, population)
    predictions = validate_prediction_bundle(
        prediction_bundle,
        protocol=frozen,
        population_manifest=population,
        pair_assignment=assignment,
        predictor_model=predictor_model,
    )
    runtime = validate_kaggle_runtime_binding(kaggle_runtime_binding)
    created, created_text = _utc(created_at_utc, label="created_at_utc")
    expires, expires_text = _utc(expires_at_utc, label="expires_at_utc")
    if expires <= created:
        raise AuthorizationError("expires_at_utc must follow created_at_utc")
    assignments = _derive_assignments(
        population=population,
        pair_assignment=assignment,
        archive_names_by_lineage_uuid=archive_names_by_lineage_uuid,
    )
    ledger_path, ledger_path_sha = _canonical_path(
        usage_ledger_path,
        label="usage_ledger_path",
    )
    return {
        "schema": AUTHORIZATION_SCHEMA,
        "authorization_id": _identifier(authorization_id, label="authorization_id"),
        "protocol_sha256": canonical_sha256(frozen),
        "population_content_sha256": population["content_sha256"],
        "pair_assignment_content_sha256": assignment["content_sha256"],
        "prediction_bundle_content_sha256": predictions["content_sha256"],
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "usage_ledger_path": ledger_path,
        "usage_ledger_path_sha256": ledger_path_sha,
        "archive_assignments": assignments,
        "max_submissions": MAX_SUBMISSIONS,
        "horizon": HORIZON,
        "replacement_policy": "NONE",
        "interim_efficacy_policy": "FORBIDDEN",
        "scope": SCOPE,
        "explicit_user_override_text_sha256": _sha(
            explicit_user_override_text_sha256,
            label="explicit_user_override_text_sha256",
        ),
        "created_at_utc": created_text,
        "expires_at_utc": expires_text,
        "state": "FROZEN",
        "research_only": True,
        "production_submission_authorized": False,
    }


def build_authorization(
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    prediction_bundle: object,
    predictor_model: object,
    kaggle_runtime_binding: object,
    usage_ledger_path: str | Path,
    archive_names_by_lineage_uuid: object,
    authorization_id: str,
    explicit_user_override_text_sha256: str,
    created_at_utc: str,
    expires_at_utc: str,
) -> dict[str, Any]:
    """Derive a research authorization from exact upstream artifacts."""

    content = _build_content(
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        prediction_bundle=prediction_bundle,
        predictor_model=predictor_model,
        kaggle_runtime_binding=kaggle_runtime_binding,
        usage_ledger_path=usage_ledger_path,
        archive_names_by_lineage_uuid=archive_names_by_lineage_uuid,
        authorization_id=authorization_id,
        explicit_user_override_text_sha256=explicit_user_override_text_sha256,
        created_at_utc=created_at_utc,
        expires_at_utc=expires_at_utc,
    )
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_authorization(
    value: object,
    *,
    protocol: object,
    population_manifest: object,
    pair_assignment: object,
    prediction_bundle: object,
    predictor_model: object,
    kaggle_runtime_binding: object,
) -> dict[str, Any]:
    """Rebuild the authorization and reject every caller-selected binding."""

    raw = _exact_fields(value, _FIELDS, label="authorization")
    if raw["schema"] != AUTHORIZATION_SCHEMA:
        raise AuthorizationError("authorization schema mismatch")
    assignments = raw["archive_assignments"]
    if not isinstance(assignments, list) or len(assignments) != MAX_SUBMISSIONS:
        raise AuthorizationError("authorization must contain exactly ten archive assignments")
    for row in assignments:
        _exact_fields(row, _ASSIGNMENT_FIELDS, label="archive assignment")
    names = {row["lineage_uuid"]: row["archive_name"] for row in assignments}
    if len(names) != MAX_SUBMISSIONS:
        raise AuthorizationError("archive assignment lineage UUIDs must be unique")
    expected = _build_content(
        protocol=protocol,
        population_manifest=population_manifest,
        pair_assignment=pair_assignment,
        prediction_bundle=prediction_bundle,
        predictor_model=predictor_model,
        kaggle_runtime_binding=kaggle_runtime_binding,
        usage_ledger_path=raw["usage_ledger_path"],
        archive_names_by_lineage_uuid=names,
        authorization_id=raw["authorization_id"],
        explicit_user_override_text_sha256=raw["explicit_user_override_text_sha256"],
        created_at_utc=raw["created_at_utc"],
        expires_at_utc=raw["expires_at_utc"],
    )
    if {field: raw[field] for field in _CONTENT_FIELDS} != expected:
        raise AuthorizationError("authorization is not the exact artifact-derived authorization")
    content_sha = _sha(raw["content_sha256"], label="content_sha256")
    if content_sha != canonical_sha256(expected):
        raise AuthorizationError("authorization content_sha256 mismatch")
    return {**expected, "content_sha256": content_sha}


def _artifact_kwargs(artifacts: Mapping[str, object]) -> dict[str, object]:
    required = {
        "protocol",
        "population_manifest",
        "pair_assignment",
        "prediction_bundle",
        "predictor_model",
        "kaggle_runtime_binding",
    }
    if set(artifacts) != required:
        raise AuthorizationError(f"artifacts fields must exactly be {sorted(required)}")
    return dict(artifacts)


def write_authorization_create_once(
    path: str | Path,
    authorization: object,
    *,
    artifacts: Mapping[str, object],
) -> Path:
    validated = validate_authorization(authorization, **_artifact_kwargs(artifacts))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(validated) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"authorization already exists: {target}") from None
    return target


def _event_digest(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes({key: event[key] for key in event if key != "event_sha256"})
    ).hexdigest()


def _assignment_key(row: Mapping[str, Any]) -> tuple[str, int]:
    return str(row["pair_id"]), int(row["slot"])


def _pair_ids(authorization: Mapping[str, Any]) -> list[str]:
    return sorted({str(row["pair_id"]) for row in authorization["archive_assignments"]})


def _prior_pair_id(authorization: Mapping[str, Any], pair_id: str) -> str | None:
    pair_ids = _pair_ids(authorization)
    index = pair_ids.index(pair_id)
    return pair_ids[index - 1] if index else None


def _read_events(handle: Any, authorization: Mapping[str, Any]) -> list[dict[str, Any]]:
    handle.seek(0)
    payload = handle.read()
    if not payload:
        return []
    try:
        text = payload.decode("ascii")
        if not text.endswith("\n"):
            raise AuthorizationError("usage ledger must end with a newline")
        values = [json.loads(line) for line in text.splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("usage ledger is not canonical ASCII JSONL") from exc

    expected_rows = {
        _assignment_key(row): row for row in authorization["archive_assignments"]
    }
    expected_order = sorted(expected_rows)
    events: list[dict[str, Any]] = []
    previous = GENESIS_EVENT_SHA256
    previous_time: datetime | None = None
    for index, value in enumerate(values, start=1):
        item = _exact_fields(value, _EVENT_FIELDS, label="usage event")
        if item["schema"] != USAGE_LEDGER_SCHEMA:
            raise AuthorizationError("usage event schema mismatch")
        if item["authorization_sha256"] != authorization["content_sha256"] or item["sequence"] != index:
            raise AuthorizationError("usage event authorization or sequence mismatch")
        pair_id = _identifier(item["pair_id"], label="usage pair_id")
        slot = item["slot"]
        if isinstance(slot, bool) or not isinstance(slot, int):
            raise AuthorizationError("usage slot must be an integer")
        if index > len(expected_order) or (pair_id, slot) != expected_order[index - 1]:
            raise AuthorizationError("usage events must follow exact pair/slot order")
        expected = expected_rows[(pair_id, slot)]
        for field in ("archive_sha256", "archive_name", "lineage_uuid", "pair_id", "wave_id", "slot"):
            if item[field] != expected[field]:
                raise AuthorizationError("usage event does not match exact archive assignment")
        barrier_sha = item["prior_pair_barrier_content_sha256"]
        if _prior_pair_id(authorization, pair_id) is None:
            if barrier_sha is not None:
                raise AuthorizationError("first-pair usage events cannot claim a prior barrier")
        else:
            _sha(barrier_sha, label="prior_pair_barrier_content_sha256")
            if slot == 2 and events[-1]["prior_pair_barrier_content_sha256"] != barrier_sha:
                raise AuthorizationError("pair usage events do not share one prior barrier")
        created, created_text = _utc(item["created_at_utc"], label="usage created_at_utc")
        if previous_time is not None and created < previous_time:
            raise AuthorizationError("usage timestamps move backward")
        if item["previous_event_sha256"] != previous:
            raise AuthorizationError("usage hash chain is broken")
        event_sha = _sha(item["event_sha256"], label="event_sha256")
        if event_sha != _event_digest(item):
            raise AuthorizationError("usage event_sha256 mismatch")
        normalized = dict(item)
        normalized["created_at_utc"] = created_text
        events.append(normalized)
        previous = event_sha
        previous_time = created
    return events


def validate_usage_ledger(
    path: str | Path,
    authorization: object,
    *,
    artifacts: Mapping[str, object],
) -> list[dict[str, Any]]:
    normalized = validate_authorization(authorization, **_artifact_kwargs(artifacts))
    target = Path(path)
    target_text, target_sha = _canonical_path(target, label="usage ledger path")
    if (
        target_text != normalized["usage_ledger_path"]
        or target_sha != normalized["usage_ledger_path_sha256"]
    ):
        raise AuthorizationError("usage ledger path does not match frozen authorization")
    if not target.exists():
        return []
    with target.open("rb") as handle:
        return _read_events(handle, normalized)


def guard_research_submission(
    authorization: object,
    ledger_path: str | Path,
    *,
    artifacts: Mapping[str, object],
    archive_sha256: str,
    archive_name: str,
    lineage_uuid: str,
    pair_id: str,
    wave_id: str,
    slot: int,
    now: str | datetime,
    prior_pair_capture: object | None = None,
) -> dict[str, Any]:
    """Consume the next exact research slot and return a non-production permit."""

    normalized = validate_authorization(authorization, **_artifact_kwargs(artifacts))
    current = _now(now)
    wall = _wall_now()
    created = _utc(normalized["created_at_utc"], label="created_at_utc")[0]
    expires = _utc(normalized["expires_at_utc"], label="expires_at_utc")[0]
    if current < created or current >= expires or wall < created or wall >= expires:
        raise AuthorizationError("authorization is outside its validity window")
    if current > wall + timedelta(minutes=1):
        raise AuthorizationError("usage timestamp is ahead of the system UTC clock")
    target = Path(ledger_path)
    target_text, target_sha = _canonical_path(target, label="usage ledger path")
    if (
        target_text != normalized["usage_ledger_path"]
        or target_sha != normalized["usage_ledger_path_sha256"]
    ):
        raise AuthorizationError("usage ledger path does not match frozen authorization")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            prior = _read_events(handle, normalized)
            if len(prior) >= MAX_SUBMISSIONS:
                raise AuthorizationError("authorization submission cap is exhausted")
            expected = normalized["archive_assignments"][len(prior)]
            requested = {
                "archive_sha256": _sha(archive_sha256, label="archive_sha256"),
                "archive_name": _archive_name(archive_name, label="archive_name"),
                "lineage_uuid": lineage_uuid,
                "pair_id": pair_id,
                "wave_id": wave_id,
                "slot": slot,
            }
            if requested != expected:
                raise AuthorizationError("requested slot is not the next exact authorization assignment")
            prior_pair_id = _prior_pair_id(normalized, pair_id)
            if prior_pair_id is None:
                if prior_pair_capture is not None:
                    raise AuthorizationError("first pair must not provide a prior authenticated capture")
                barrier_sha = None
            else:
                if prior_pair_capture is None:
                    raise AuthorizationError("later pairs require an authenticated prior pair capture")
                # Lazy import avoids an authorization/evidence import cycle.
                from .kaggle_evidence import (
                    reverify_authenticated_pair_capture_online,
                    validate_authenticated_live_pair_snapshot,
                )

                try:
                    live_snapshot = reverify_authenticated_pair_capture_online(
                        prior_pair_capture,
                        authorization=normalized,
                        usage_ledger_path=target,
                        artifacts=artifacts,
                    )
                    capture = validate_authenticated_live_pair_snapshot(
                        live_snapshot,
                        authorization=normalized,
                        artifacts=artifacts,
                    )
                except Exception as exc:
                    raise AuthorizationError(f"prior authenticated pair capture is invalid: {exc}") from exc
                if capture["pair_id"] != prior_pair_id:
                    raise AuthorizationError("prior authenticated capture is for the wrong pair")
                barrier = capture["pair_completion_barrier"]
                barrier_completed = _utc(
                    barrier["horizon_completed_at_utc"],
                    label="prior barrier horizon_completed_at_utc",
                )[0]
                if current <= barrier_completed or wall <= barrier_completed:
                    raise AuthorizationError("next pair permit precedes prior pair horizon completion")
                barrier_sha = barrier["content_sha256"]
                if slot == 2 and prior[-1]["prior_pair_barrier_content_sha256"] != barrier_sha:
                    raise AuthorizationError("pair slots must bind the same prior completion barrier")
            sequence = len(prior) + 1
            created_text = current.isoformat(timespec="microseconds").replace("+00:00", "Z")
            event = {
                "schema": USAGE_LEDGER_SCHEMA,
                "authorization_sha256": normalized["content_sha256"],
                "sequence": sequence,
                "event_id": f"voi-p5-usage-{sequence:02d}",
                **requested,
                "prior_pair_barrier_content_sha256": barrier_sha,
                "created_at_utc": created_text,
                "previous_event_sha256": prior[-1]["event_sha256"] if prior else GENESIS_EVENT_SHA256,
                "event_sha256": "",
            }
            event["event_sha256"] = _event_digest(event)
            # Revalidate the prospective complete ledger before durable append.
            encoded_prior = b"".join(canonical_json_bytes(item) + b"\n" for item in prior)
            encoded_candidate = encoded_prior + canonical_json_bytes(event) + b"\n"
            handle.seek(0)
            original = handle.read()
            if original != encoded_prior:
                raise AuthorizationError("usage ledger changed while locked")
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json_bytes(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
            if handle.read() != encoded_candidate:
                raise AuthorizationError("usage ledger durable append verification failed")
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    permit_content = {
        "schema": PERMIT_SCHEMA,
        "authorization_sha256": normalized["content_sha256"],
        "protocol_sha256": normalized["protocol_sha256"],
        "population_content_sha256": normalized["population_content_sha256"],
        "pair_assignment_content_sha256": normalized["pair_assignment_content_sha256"],
        "prediction_bundle_content_sha256": normalized["prediction_bundle_content_sha256"],
        **requested,
        "prior_pair_barrier_content_sha256": barrier_sha,
        "usage_sequence": sequence,
        "usage_event_sha256": event["event_sha256"],
        "horizon": HORIZON,
        "scope": SCOPE,
        "remaining_cap": MAX_SUBMISSIONS - sequence,
        "research_only": True,
        "production_submission_authorized": False,
    }
    permit = {**permit_content, "content_sha256": canonical_sha256(permit_content)}
    validate_research_permit(
        permit,
        normalized,
        ledger_path=target,
        artifacts=artifacts,
    )
    return permit


def validate_research_permit(
    value: object,
    authorization: Mapping[str, Any],
    *,
    ledger_path: str | Path,
    artifacts: Mapping[str, object],
) -> dict[str, Any]:
    item = _exact_fields(value, _PERMIT_FIELDS, label="research permit")
    if item["schema"] != PERMIT_SCHEMA or item["authorization_sha256"] != authorization["content_sha256"]:
        raise AuthorizationError("research permit authorization binding mismatch")
    row = next(
        (
            candidate
            for candidate in authorization["archive_assignments"]
            if candidate["pair_id"] == item["pair_id"] and candidate["slot"] == item["slot"]
        ),
        None,
    )
    if row is None or any(item[field] != row[field] for field in _ASSIGNMENT_FIELDS):
        raise AuthorizationError("research permit archive assignment mismatch")
    prior_pair_id = _prior_pair_id(authorization, str(item["pair_id"]))
    barrier_sha = item["prior_pair_barrier_content_sha256"]
    if prior_pair_id is None:
        if barrier_sha is not None:
            raise AuthorizationError("first-pair research permit cannot claim a prior barrier")
    else:
        _sha(barrier_sha, label="research permit prior_pair_barrier_content_sha256")
    usage_sequence = item["usage_sequence"]
    expected_sequence = authorization["archive_assignments"].index(row) + 1
    if (
        isinstance(usage_sequence, bool)
        or not isinstance(usage_sequence, int)
        or usage_sequence != expected_sequence
    ):
        raise AuthorizationError("research permit usage_sequence mismatch")
    _sha(item["usage_event_sha256"], label="research permit usage_event_sha256")
    for field in (
        "protocol_sha256",
        "population_content_sha256",
        "pair_assignment_content_sha256",
        "prediction_bundle_content_sha256",
    ):
        if item[field] != authorization[field]:
            raise AuthorizationError(f"research permit {field} mismatch")
    remaining = item["remaining_cap"]
    if (
        isinstance(remaining, bool)
        or not isinstance(remaining, int)
        or remaining != MAX_SUBMISSIONS - usage_sequence
    ):
        raise AuthorizationError("research permit remaining_cap is invalid")
    if item["horizon"] != HORIZON or item["scope"] != SCOPE:
        raise AuthorizationError("research permit scope mismatch")
    if item["research_only"] is not True or item["production_submission_authorized"] is not False:
        raise AuthorizationError("research permit cannot authorize production")
    content_sha = _sha(item["content_sha256"], label="research permit content_sha256")
    expected_sha = canonical_sha256({key: item[key] for key in _PERMIT_FIELDS if key != "content_sha256"})
    if content_sha != expected_sha:
        raise AuthorizationError("research permit content_sha256 mismatch")
    usage_events = validate_usage_ledger(ledger_path, authorization, artifacts=artifacts)
    if len(usage_events) < usage_sequence:
        raise AuthorizationError("research permit usage event is absent from the bound ledger")
    usage_event = usage_events[usage_sequence - 1]
    if usage_event["event_sha256"] != item["usage_event_sha256"]:
        raise AuthorizationError("research permit usage event SHA-256 is not in the bound ledger")
    for field in (
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "prior_pair_barrier_content_sha256",
    ):
        if usage_event[field] != item[field]:
            raise AuthorizationError("research permit does not match its bound usage event")
    return dict(item)


__all__ = [
    "AUTHORIZATION_SCHEMA",
    "AuthorizationError",
    "GENESIS_EVENT_SHA256",
    "HORIZON",
    "MAX_SUBMISSIONS",
    "PAIR_COUNT",
    "PERMIT_SCHEMA",
    "SCOPE",
    "SLOTS_PER_PAIR",
    "USAGE_LEDGER_SCHEMA",
    "build_authorization",
    "guard_research_submission",
    "validate_authorization",
    "validate_research_permit",
    "validate_usage_ledger",
    "write_authorization_create_once",
]
