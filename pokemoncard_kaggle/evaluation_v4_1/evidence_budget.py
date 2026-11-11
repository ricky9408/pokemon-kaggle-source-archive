"""Program-wide alpha ledger for prospective selector versions.

Changing a protocol SHA does not reset the evidence budget.  Every confirmatory
version must consume an allocation from this single append-only hash chain
before any outcome is observed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping


EVENT_SCHEMA = "selector_evidence_budget_event_v1"
TOTAL_ALPHA = 0.05
GENESIS_HASH = "0" * 64
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_FIELDS = frozenset(
    {
        "schema",
        "event_type",
        "event_index",
        "program_id",
        "created_at_utc",
        "previous_event_sha256",
        "protocol_context_sha256",
        "alpha_amount",
        "disposition",
        "event_sha256",
    }
)
_CLOSE_DISPOSITIONS = frozenset({"PASSED", "FAILED", "PROTOCOL_FAIL", "RETIRED_NO_OUTCOME"})


class EvidenceBudgetError(ValueError):
    """The selector evidence ledger is malformed or over budget."""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _event_hash(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes({key: event[key] for key in event if key != "event_sha256"})
    ).hexdigest()


def _sha(value: object, *, label: str, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise EvidenceBudgetError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: object, *, label: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise EvidenceBudgetError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EvidenceBudgetError(f"{label} is invalid") from exc
    return parsed, value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise EvidenceBudgetError(f"{label} must be a non-empty trimmed string")
    return value


def _alpha(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise EvidenceBudgetError(f"{label} must be finite")
    result = float(value)
    if result < 0.0 or result > TOTAL_ALPHA:
        raise EvidenceBudgetError(f"{label} must be in [0, {TOTAL_ALPHA}]")
    return result


def validate_events(events: list[object]) -> dict[str, Any]:
    """Validate a complete hash chain and return its program state."""

    if not events:
        raise EvidenceBudgetError("evidence ledger requires a genesis event")
    normalized: list[dict[str, Any]] = []
    previous = GENESIS_HASH
    previous_time: datetime | None = None
    allocated: dict[str, float] = {}
    closed: dict[str, str] = {}
    program_id: str | None = None
    total_budget: float | None = None
    for index, raw in enumerate(events):
        if not isinstance(raw, Mapping) or set(raw) != _FIELDS:
            raise EvidenceBudgetError("evidence event fields are not exact")
        if raw["schema"] != EVENT_SCHEMA:
            raise EvidenceBudgetError("evidence event schema mismatch")
        if raw["event_index"] != index:
            raise EvidenceBudgetError("evidence event indices must be contiguous from zero")
        current_program = _identifier(raw["program_id"], label="program_id")
        if program_id is None:
            program_id = current_program
        elif current_program != program_id:
            raise EvidenceBudgetError("program_id changes inside evidence ledger")
        created, created_text = _utc(raw["created_at_utc"], label="created_at_utc")
        if previous_time is not None and created < previous_time:
            raise EvidenceBudgetError("evidence event timestamps move backward")
        if raw["previous_event_sha256"] != previous:
            raise EvidenceBudgetError("evidence hash chain is broken")
        event_type = raw["event_type"]
        alpha_amount = _alpha(raw["alpha_amount"], label="alpha_amount")
        protocol_sha = _sha(
            raw["protocol_context_sha256"],
            label="protocol_context_sha256",
            allow_none=True,
        )
        disposition = raw["disposition"]
        if index == 0:
            if event_type != "GENESIS" or protocol_sha is not None or disposition != "OPEN":
                raise EvidenceBudgetError("first event must be OPEN GENESIS")
            if alpha_amount != TOTAL_ALPHA:
                raise EvidenceBudgetError("genesis alpha_amount must equal total program budget")
            total_budget = alpha_amount
        elif event_type == "ALLOCATE":
            if protocol_sha is None or protocol_sha in allocated or protocol_sha in closed:
                raise EvidenceBudgetError("protocol allocation is missing or duplicated")
            if disposition != "ALLOCATED" or alpha_amount <= 0.0:
                raise EvidenceBudgetError("allocation must carry positive alpha and ALLOCATED disposition")
            allocated[protocol_sha] = alpha_amount
        elif event_type == "CLOSE":
            if protocol_sha is None or protocol_sha not in allocated or protocol_sha in closed:
                raise EvidenceBudgetError("close event must reference one open allocation")
            if disposition not in _CLOSE_DISPOSITIONS or alpha_amount != 0.0:
                raise EvidenceBudgetError("close event disposition or alpha_amount is invalid")
            closed[protocol_sha] = disposition
        else:
            raise EvidenceBudgetError("event_type must be GENESIS, ALLOCATE, or CLOSE")
        event_sha = _sha(raw["event_sha256"], label="event_sha256")
        clean = {
            "schema": EVENT_SCHEMA,
            "event_type": event_type,
            "event_index": index,
            "program_id": current_program,
            "created_at_utc": created_text,
            "previous_event_sha256": previous,
            "protocol_context_sha256": protocol_sha,
            "alpha_amount": alpha_amount,
            "disposition": disposition,
            "event_sha256": event_sha,
        }
        if event_sha != _event_hash(clean):
            raise EvidenceBudgetError("evidence event hash mismatch")
        normalized.append(clean)
        previous = event_sha
        previous_time = created
    assert total_budget is not None and program_id is not None
    spent = math.fsum(allocated.values())
    if spent > total_budget + 1e-15:
        raise EvidenceBudgetError("program-wide alpha budget is exceeded")
    return {
        "events": normalized,
        "program_id": program_id,
        "total_alpha": total_budget,
        "allocated_alpha": spent,
        "remaining_alpha": total_budget - spent,
        "open_protocols": sorted(set(allocated) - set(closed)),
        "closed_protocols": dict(sorted(closed.items())),
        "head_sha256": previous,
    }


def _read_locked(handle: Any) -> list[dict[str, Any]]:
    handle.seek(0)
    payload = handle.read()
    if not payload:
        return []
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise EvidenceBudgetError("evidence ledger must be ASCII JSONL") from exc
    if not text.endswith("\n"):
        raise EvidenceBudgetError("evidence ledger must end with a newline")
    try:
        return [json.loads(line) for line in text.splitlines()]
    except json.JSONDecodeError as exc:
        raise EvidenceBudgetError("evidence ledger contains malformed JSON") from exc


def _append_event(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            existing = _read_locked(handle)
            candidate = existing + [event]
            state = validate_events(candidate)
            handle.seek(0, os.SEEK_END)
            handle.write(canonical_json_bytes(state["events"][-1]) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    return state


def _new_event(
    *,
    existing: list[dict[str, Any]],
    event_type: str,
    program_id: str,
    created_at_utc: str,
    protocol_context_sha256: str | None,
    alpha_amount: float,
    disposition: str,
) -> dict[str, Any]:
    previous = existing[-1]["event_sha256"] if existing else GENESIS_HASH
    event = {
        "schema": EVENT_SCHEMA,
        "event_type": event_type,
        "event_index": len(existing),
        "program_id": program_id,
        "created_at_utc": created_at_utc,
        "previous_event_sha256": previous,
        "protocol_context_sha256": protocol_context_sha256,
        "alpha_amount": alpha_amount,
        "disposition": disposition,
        "event_sha256": "",
    }
    event["event_sha256"] = _event_hash(event)
    return event


def create_genesis(path: str | Path, *, program_id: str, created_at_utc: str) -> dict[str, Any]:
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"evidence ledger already exists: {target}")
    _identifier(program_id, label="program_id")
    _utc(created_at_utc, label="created_at_utc")
    return _append_event(
        target,
        _new_event(
            existing=[],
            event_type="GENESIS",
            program_id=program_id,
            created_at_utc=created_at_utc,
            protocol_context_sha256=None,
            alpha_amount=TOTAL_ALPHA,
            disposition="OPEN",
        ),
    )


def append_allocation(
    path: str | Path,
    *,
    protocol_context_sha256: str,
    alpha_amount: float,
    created_at_utc: str,
) -> dict[str, Any]:
    target = Path(path)
    with target.open("rb") as handle:
        existing = _read_locked(handle)
    state = validate_events(existing)
    _sha(protocol_context_sha256, label="protocol_context_sha256")
    _utc(created_at_utc, label="created_at_utc")
    return _append_event(
        target,
        _new_event(
            existing=existing,
            event_type="ALLOCATE",
            program_id=state["program_id"],
            created_at_utc=created_at_utc,
            protocol_context_sha256=protocol_context_sha256,
            alpha_amount=_alpha(alpha_amount, label="alpha_amount"),
            disposition="ALLOCATED",
        ),
    )


def append_close(
    path: str | Path,
    *,
    protocol_context_sha256: str,
    disposition: str,
    created_at_utc: str,
) -> dict[str, Any]:
    target = Path(path)
    with target.open("rb") as handle:
        existing = _read_locked(handle)
    state = validate_events(existing)
    _sha(protocol_context_sha256, label="protocol_context_sha256")
    _utc(created_at_utc, label="created_at_utc")
    return _append_event(
        target,
        _new_event(
            existing=existing,
            event_type="CLOSE",
            program_id=state["program_id"],
            created_at_utc=created_at_utc,
            protocol_context_sha256=protocol_context_sha256,
            alpha_amount=0.0,
            disposition=disposition,
        ),
    )


def load_ledger(path: str | Path) -> dict[str, Any]:
    with Path(path).open("rb") as handle:
        return validate_events(_read_locked(handle))


__all__ = [
    "EVENT_SCHEMA",
    "EvidenceBudgetError",
    "TOTAL_ALPHA",
    "append_allocation",
    "append_close",
    "create_genesis",
    "load_ledger",
    "validate_events",
]
