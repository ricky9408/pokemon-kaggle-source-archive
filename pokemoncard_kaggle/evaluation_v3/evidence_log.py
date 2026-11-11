"""Fail-closed, append-only evidence events for prospective governance.

The log stores exactly one canonical JSON event per line.  There is deliberately
no clock access here: callers must supply every event timestamp explicitly.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, TextIO

from .episode_inventory import canonical_json


EVIDENCE_LOG_SCHEMA = "prospective_evidence_log_v1"
GENESIS_EVENT_SHA256 = "0" * 64
EVENT_KEYS = frozenset(
    {
        "schema",
        "log_id",
        "sequence",
        "event_id",
        "event_type",
        "created_at_utc",
        "previous_event_sha256",
        "payload",
        "event_sha256",
    }
)
_HASH_KEYS = frozenset("0123456789abcdef")
_UNSET = object()


def _normalize_utc(value: str, *, label: str) -> str:
    """Return the one timestamp representation permitted in persisted events."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty, trimmed string")
    return value


def _require_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HASH_KEYS for char in value):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _canonical_payload(payload: object) -> dict[str, Any]:
    """Validate and snapshot a JSON-object payload through the shared encoder."""

    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a JSON object")
    try:
        encoded = canonical_json(dict(payload))
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("payload must be canonical-JSON serializable") from exc
    if not isinstance(normalized, dict):  # Defensive: the Mapping check above is intentional.
        raise ValueError("payload must be a JSON object")
    return normalized


def _event_digest(envelope: Mapping[str, Any]) -> str:
    """Hash the event envelope, excluding its self-referential digest field."""

    without_digest = {key: value for key, value in envelope.items() if key != "event_sha256"}
    return hashlib.sha256(canonical_json(without_digest).encode("ascii")).hexdigest()


def _verify_event(event: object, *, line_number: int, expected_log_id: str | None, expected_sequence: int,
                  previous_event_sha256: str, event_ids: set[str]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError(f"line {line_number}: event must be a JSON object")
    if set(event) != EVENT_KEYS:
        raise ValueError(f"line {line_number}: event keys must exactly match the evidence-log schema")

    if event["schema"] != EVIDENCE_LOG_SCHEMA:
        raise ValueError(f"line {line_number}: unexpected schema")
    log_id = _require_identifier(event["log_id"], label=f"line {line_number}: log_id")
    if expected_log_id is not None and log_id != expected_log_id:
        raise ValueError(f"line {line_number}: log_id does not match expected log_id")
    if not isinstance(event["sequence"], int) or isinstance(event["sequence"], bool):
        raise ValueError(f"line {line_number}: sequence must be an integer")
    if event["sequence"] != expected_sequence:
        raise ValueError(f"line {line_number}: sequence must be contiguous and zero-based")
    event_id = _require_identifier(event["event_id"], label=f"line {line_number}: event_id")
    _require_identifier(event["event_type"], label=f"line {line_number}: event_type")
    if event_id in event_ids:
        raise ValueError(f"line {line_number}: duplicate event_id {event_id!r}")
    event_ids.add(event_id)

    normalized_created_at = _normalize_utc(event["created_at_utc"], label=f"line {line_number}: created_at_utc")
    if event["created_at_utc"] != normalized_created_at:
        raise ValueError(f"line {line_number}: created_at_utc must be canonical UTC")
    if not isinstance(event["payload"], dict):
        raise ValueError(f"line {line_number}: payload must be a JSON object")
    try:
        if canonical_json(event["payload"]) != canonical_json(dict(event["payload"])):
            raise ValueError("payload is not a JSON object")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"line {line_number}: payload is not canonical-JSON serializable") from exc

    previous_hash = _require_sha256(event["previous_event_sha256"], label=f"line {line_number}: previous_event_sha256")
    if previous_hash != previous_event_sha256:
        raise ValueError(f"line {line_number}: previous_event_sha256 does not match the chain")
    event_hash = _require_sha256(event["event_sha256"], label=f"line {line_number}: event_sha256")
    if event_hash != _event_digest(event):
        raise ValueError(f"line {line_number}: event_sha256 does not match the event envelope")
    return event


def _verify_text(text: str, *, log_id: str | None) -> dict[str, Any]:
    if not text:
        return {"event_count": 0, "head_event_sha256": None, "head_created_at_utc": None}
    if "\r" in text:
        raise ValueError("event log must use LF line endings")
    if not text.endswith("\n"):
        raise ValueError("event log ends with a partial JSONL line")

    lines = text[:-1].split("\n")
    previous_hash = GENESIS_EVENT_SHA256
    event_ids: set[str] = set()
    expected_log_id = log_id
    previous_created_at: datetime | None = None
    for sequence, line in enumerate(lines):
        line_number = sequence + 1
        if not line.strip():
            raise ValueError(f"line {line_number}: blank lines are not permitted")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: malformed JSON") from exc
        if canonical_json(event) != line:
            raise ValueError(f"line {line_number}: event is not canonical JSON")
        verified = _verify_event(
            event,
            line_number=line_number,
            expected_log_id=expected_log_id,
            expected_sequence=sequence,
            previous_event_sha256=previous_hash,
            event_ids=event_ids,
        )
        created_at = datetime.fromisoformat(verified["created_at_utc"].replace("Z", "+00:00"))
        if previous_created_at is not None and created_at < previous_created_at:
            raise ValueError(f"line {line_number}: created_at_utc moves backward")
        previous_created_at = created_at
        expected_log_id = verified["log_id"]
        previous_hash = verified["event_sha256"]
    return {
        "event_count": len(lines),
        "head_event_sha256": previous_hash,
        "head_created_at_utc": lines and json.loads(lines[-1])["created_at_utc"],
    }


def _check_expected(summary: Mapping[str, Any], *, expected_head_sha256: object, expected_event_count: object) -> None:
    if expected_event_count is not _UNSET:
        if not isinstance(expected_event_count, int) or isinstance(expected_event_count, bool) or expected_event_count < 0:
            raise ValueError("expected_event_count must be a non-negative integer")
        if summary["event_count"] != expected_event_count:
            raise ValueError("event count does not match expected_event_count")
    if expected_head_sha256 is not _UNSET:
        if expected_head_sha256 is not None:
            _require_sha256(expected_head_sha256, label="expected_head_sha256")
        if summary["head_event_sha256"] != expected_head_sha256:
            raise ValueError("head hash does not match expected_head_sha256")


def verify_event_log(
    path: str | Path,
    *,
    log_id: str,
    expected_head_sha256: str | None | object = _UNSET,
    expected_event_count: int | object = _UNSET,
) -> dict[str, Any]:
    """Verify every byte of an evidence log and return its count and head hash.

    A missing log is the valid empty genesis log.  Supplying ``None`` explicitly
    as ``expected_head_sha256`` asserts that the log is still empty.
    """

    _require_identifier(log_id, label="log_id")
    event_path = Path(path)
    if not event_path.exists():
        summary = {
            "event_count": 0,
            "head_event_sha256": None,
            "head_created_at_utc": None,
        }
    else:
        try:
            text = event_path.read_text(encoding="ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("event log must be ASCII canonical JSONL") from exc
        summary = _verify_text(text, log_id=log_id)
    _check_expected(summary, expected_head_sha256=expected_head_sha256, expected_event_count=expected_event_count)
    return dict(summary)


def append_event(
    path: str | Path,
    *,
    log_id: str,
    event_id: str,
    event_type: str,
    created_at_utc: str,
    payload: Mapping[str, Any],
    expected_head_sha256: str | None | object = _UNSET,
    expected_event_count: int | object = _UNSET,
) -> dict[str, Any]:
    """Verify then durably append one event while holding a POSIX advisory lock."""

    log_id = _require_identifier(log_id, label="log_id")
    event_id = _require_identifier(event_id, label="event_id")
    event_type = _require_identifier(event_type, label="event_type")
    created_at_utc = _normalize_utc(created_at_utc, label="created_at_utc")
    normalized_payload = _canonical_payload(payload)
    event_path = Path(path)
    event_path.parent.mkdir(parents=True, exist_ok=True)

    # ``a+`` creates the initial empty log and O_APPEND prevents an unlocked seek/write race.
    with event_path.open("a+", encoding="ascii", newline="\n") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            handle.seek(0)
            summary = _verify_text(handle.read(), log_id=log_id)
            _check_expected(summary, expected_head_sha256=expected_head_sha256, expected_event_count=expected_event_count)
            if event_id in _event_ids_from_handle(handle):
                raise ValueError(f"duplicate event_id {event_id!r}")
            if summary["head_created_at_utc"] is not None and datetime.fromisoformat(
                created_at_utc.replace("Z", "+00:00")
            ) < datetime.fromisoformat(summary["head_created_at_utc"].replace("Z", "+00:00")):
                raise ValueError("created_at_utc moves backward")

            event: dict[str, Any] = {
                "schema": EVIDENCE_LOG_SCHEMA,
                "log_id": log_id,
                "sequence": summary["event_count"],
                "event_id": event_id,
                "event_type": event_type,
                "created_at_utc": created_at_utc,
                "previous_event_sha256": summary["head_event_sha256"] or GENESIS_EVENT_SHA256,
                "payload": normalized_payload,
            }
            event["event_sha256"] = _event_digest(event)
            handle.write(canonical_json(event) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            return json.loads(canonical_json(event))
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _event_ids_from_handle(handle: TextIO) -> set[str]:
    """Return ids only after the caller has already fully verified the log."""

    handle.seek(0)
    text = handle.read()
    if not text:
        return set()
    return {json.loads(line)["event_id"] for line in text[:-1].split("\n")}


__all__ = [
    "EVIDENCE_LOG_SCHEMA",
    "EVENT_KEYS",
    "GENESIS_EVENT_SHA256",
    "append_event",
    "verify_event_log",
]
