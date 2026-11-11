"""Crash-safe, research-only VOI-P5 permit executor.

The executor is deliberately a narrow state machine that owns the one-shot
Kaggle upload. Its journal is append-only canonical JSONL, protected by an
advisory exclusive lock and a SHA-256 hash chain.
"""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .authorization import (
    HORIZON,
    MAX_SUBMISSIONS,
    PERMIT_SCHEMA,
    SCOPE,
    AuthorizationError,
    guard_research_submission,
    validate_authorization,
    validate_research_permit,
    validate_usage_ledger,
)
from .chronology import (
    SUBMISSION_RECEIPT_SCHEMA,
)
from .kaggle_evidence import (
    authenticated_upload_preflight,
    build_live_completed_submission_receipt,
    capture_authenticated_pair,
    load_exact_archive_bytes,
    observe_hosted_submission,
    reverify_authenticated_pair_capture_online,
    submit_exact_archive_once,
    validate_authenticated_pair_capture,
    validate_authenticated_live_pair_snapshot,
    validate_authenticated_upload_preflight,
    validate_hosted_observation,
)
from .protocol import canonical_json_bytes, canonical_sha256


EXECUTOR_EVENT_SCHEMA = "voi_p5_executor_event_v3"
UPLOAD_CLAIM_SCHEMA = "voi_p5_single_upload_claim_v3"
GENESIS_EVENT_SHA256 = "0" * 64

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_EVENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "sequence",
        "event_id",
        "transition",
        "payload",
        "created_at_utc",
        "previous_event_sha256",
        "event_sha256",
    }
)
_REQUEST_FIELDS = frozenset(
    {
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "prior_pair_barrier_content_sha256",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "permit_content_sha256",
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "submission_ref",
        "submission_created_at_utc",
        "submission_description",
        "submission_status",
        "first_observed_complete_at_utc",
        "authenticated_submissions_csv_sha256",
        "local_archive_sha256",
        "research_only",
        "production_submission_authorized",
        "content_sha256",
    }
)
_UPLOAD_CLAIM_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "permit_content_sha256",
        "usage_event_sha256",
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "submission_description",
        "local_archive_path",
        "archive_content_length",
        "upload_transport",
        "authenticated_upload_preflight",
        "research_only",
        "production_submission_authorized",
    }
)
_UPLOAD_CLAIM_FIELDS = _UPLOAD_CLAIM_CONTENT_FIELDS | {"content_sha256"}


class ExecutorError(ValueError):
    """The executor journal or requested state transition is invalid."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ExecutorError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ExecutorError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: str | datetime, *, label: str) -> tuple[datetime, str]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ExecutorError(f"{label} must be timezone-aware")
        parsed = value.astimezone(timezone.utc)
    elif isinstance(value, str) and value.strip() == value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExecutorError(f"{label} is not ISO-8601") from exc
        if parsed.tzinfo is None:
            raise ExecutorError(f"{label} must include a timezone")
        parsed = parsed.astimezone(timezone.utc)
    else:
        raise ExecutorError(f"{label} is required")
    return parsed, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _event_digest(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json_bytes({key: event[key] for key in event if key != "event_sha256"})
    ).hexdigest()


def _wall_now() -> datetime:
    return datetime.now(timezone.utc)


class VOIP5CalibrationExecutor:
    """Append-only permit lifecycle for one frozen research authorization.

    ``prepare_pair`` selects both exact assignments. ``upload_exact_archive``
    durably claims and performs the sole external upload call itself. A restart
    that sees the claim may only query live history through
    ``recover_claimed_upload``; it can never retry the upload. No production
    authority is ever created by this class.
    """

    def __init__(
        self,
        *,
        state_path: str | Path,
        ledger_path: str | Path,
        authorization: object,
        artifacts: Mapping[str, object],
    ) -> None:
        self.state_path = Path(state_path)
        self.ledger_path = Path(ledger_path)
        self.authorization = validate_authorization(authorization, **self._artifacts(artifacts))
        self.artifacts = dict(artifacts)

    @staticmethod
    def _artifacts(artifacts: Mapping[str, object]) -> dict[str, object]:
        required = {
            "protocol",
            "population_manifest",
            "pair_assignment",
            "prediction_bundle",
            "predictor_model",
            "kaggle_runtime_binding",
        }
        if set(artifacts) != required:
            raise ExecutorError(f"artifacts fields must exactly be {sorted(required)}")
        return dict(artifacts)

    def _lock_path(self) -> Path:
        return self.state_path.with_name(f"{self.state_path.name}.lock")

    def _with_lock(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock = self._lock_path().open("a+b")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return lock

    def _assert_upload_window(self) -> datetime:
        wall = _wall_now()
        created, _ = _utc(self.authorization["created_at_utc"], label="authorization created_at_utc")
        expires, _ = _utc(self.authorization["expires_at_utc"], label="authorization expires_at_utc")
        if wall < created or wall >= expires:
            raise ExecutorError("authorization is outside its wall-clock upload window")
        return wall

    def _read_events(self) -> list[dict[str, Any]]:
        if not self.state_path.exists():
            return []
        try:
            payload = self.state_path.read_bytes()
            if not payload:
                return []
            text = payload.decode("ascii")
            if not text.endswith("\n"):
                raise ExecutorError("executor journal must end with a newline")
            lines = text.splitlines()
            raw_events = [json.loads(line) for line in lines]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorError(f"executor journal is not canonical ASCII JSONL: {exc}") from exc

        events: list[dict[str, Any]] = []
        previous = GENESIS_EVENT_SHA256
        previous_time: datetime | None = None
        for sequence, raw in enumerate(raw_events, start=1):
            event = _exact_fields(raw, _EVENT_FIELDS, label="executor event")
            if canonical_json_bytes(event) != lines[sequence - 1].encode("ascii"):
                raise ExecutorError("executor journal event is not canonical JSON")
            if event["schema"] != EXECUTOR_EVENT_SCHEMA:
                raise ExecutorError("executor event schema mismatch")
            if event["authorization_sha256"] != self.authorization["content_sha256"]:
                raise ExecutorError("executor event authorization mismatch")
            if event["sequence"] != sequence or event["event_id"] != f"voi-p5-executor-{sequence:02d}":
                raise ExecutorError("executor event sequence mismatch")
            if event["previous_event_sha256"] != previous:
                raise ExecutorError("executor hash chain is broken")
            if _event_digest(event) != _sha(event["event_sha256"], label="executor event_sha256"):
                raise ExecutorError("executor event_sha256 mismatch")
            created, created_text = _utc(event["created_at_utc"], label="executor created_at_utc")
            if previous_time is not None and created < previous_time:
                raise ExecutorError("executor event timestamps move backward")
            normalized = dict(event)
            normalized["created_at_utc"] = created_text
            events.append(normalized)
            previous = normalized["event_sha256"]
            previous_time = created
        self._validate_transitions(events)
        return events

    def _expected_request(self, prepare_count: int, barrier_sha: str | None) -> dict[str, Any]:
        try:
            assignment = self.authorization["archive_assignments"][prepare_count]
        except IndexError as exc:
            raise ExecutorError("authorization submission cap is exhausted") from exc
        return {
            "archive_sha256": assignment["archive_sha256"],
            "archive_name": assignment["archive_name"],
            "lineage_uuid": assignment["lineage_uuid"],
            "pair_id": assignment["pair_id"],
            "wave_id": assignment["wave_id"],
            "slot": assignment["slot"],
            "prior_pair_barrier_content_sha256": barrier_sha,
        }

    def _validate_request(self, request: object, *, prepare_count: int) -> dict[str, Any]:
        raw = _exact_fields(request, _REQUEST_FIELDS, label="submit intent")
        pair_ids = sorted({str(row["pair_id"]) for row in self.authorization["archive_assignments"]})
        pair_id = raw["pair_id"]
        if not isinstance(pair_id, str) or pair_id not in pair_ids:
            raise ExecutorError("submit intent pair_id is invalid")
        prior = pair_ids.index(pair_id) > 0
        barrier_sha = raw["prior_pair_barrier_content_sha256"]
        if prior:
            _sha(barrier_sha, label="prior_pair_barrier_content_sha256")
        elif barrier_sha is not None:
            raise ExecutorError("first pair submit intent cannot claim a prior barrier")
        expected = self._expected_request(prepare_count, barrier_sha)
        if dict(raw) != expected:
            raise ExecutorError("submit intent is not the exact next authorization assignment")
        return dict(raw)

    def _validate_receipt_shape(self, receipt: object, permit: Mapping[str, Any]) -> dict[str, Any]:
        raw = _exact_fields(receipt, _RECEIPT_FIELDS, label="submission receipt")
        if raw["schema"] != SUBMISSION_RECEIPT_SCHEMA:
            raise ExecutorError("submission receipt schema mismatch")
        if raw["authorization_sha256"] != self.authorization["content_sha256"]:
            raise ExecutorError("submission receipt authorization mismatch")
        if raw["permit_content_sha256"] != permit["content_sha256"]:
            raise ExecutorError("submission receipt permit mismatch")
        for field in ("archive_sha256", "archive_name", "lineage_uuid", "pair_id", "wave_id", "slot"):
            if raw[field] != permit[field]:
                raise ExecutorError("submission receipt assignment mismatch")
        if raw["research_only"] is not True or raw["production_submission_authorized"] is not False:
            raise ExecutorError("submission receipt cannot authorize production")
        content = {key: raw[key] for key in raw if key != "content_sha256"}
        if raw["content_sha256"] != canonical_sha256(content):
            raise ExecutorError("submission receipt content_sha256 mismatch")
        return dict(raw)

    def _validate_upload_claim(
        self,
        claim: object,
        permit: Mapping[str, Any],
    ) -> dict[str, Any]:
        raw = _exact_fields(claim, _UPLOAD_CLAIM_FIELDS, label="upload claim")
        if raw["schema"] != UPLOAD_CLAIM_SCHEMA:
            raise ExecutorError("upload claim schema mismatch")
        if raw["authorization_sha256"] != self.authorization["content_sha256"]:
            raise ExecutorError("upload claim authorization mismatch")
        if raw["permit_content_sha256"] != permit["content_sha256"]:
            raise ExecutorError("upload claim permit mismatch")
        if raw["usage_event_sha256"] != permit["usage_event_sha256"]:
            raise ExecutorError("upload claim usage event mismatch")
        for field in ("archive_sha256", "archive_name", "lineage_uuid", "pair_id", "wave_id", "slot"):
            if raw[field] != permit[field]:
                raise ExecutorError("upload claim assignment mismatch")
        description = raw["submission_description"]
        if (
            not isinstance(description, str)
            or not description
            or description.strip() != description
            or len(description) > 100
            or "codex" not in description.casefold()
            or "final" in description.casefold()
            or any(ord(character) < 32 or ord(character) > 126 for character in description)
        ):
            raise ExecutorError("upload claim submission description is invalid")
        if raw["research_only"] is not True or raw["production_submission_authorized"] is not False:
            raise ExecutorError("upload claim cannot authorize production")
        try:
            validate_authenticated_upload_preflight(
                raw["authenticated_upload_preflight"],
                archive_name=permit["archive_name"],
                submission_description=description,
                kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
            )
        except Exception as exc:
            raise ExecutorError(f"upload claim preflight is invalid: {exc}") from exc
        archive_path = Path(raw["local_archive_path"])
        if (
            not archive_path.is_absolute()
            or archive_path.name != permit["archive_name"]
            or isinstance(raw["archive_content_length"], bool)
            or not isinstance(raw["archive_content_length"], int)
            or raw["archive_content_length"] <= 0
            or raw["upload_transport"] != "pinned_sdk_anonymous_pipe_v1"
        ):
            raise ExecutorError("upload claim byte-custody metadata is invalid")
        content = {key: raw[key] for key in raw if key != "content_sha256"}
        if raw["content_sha256"] != canonical_sha256(content):
            raise ExecutorError("upload claim content_sha256 mismatch")
        return dict(raw)

    def _validate_transitions(self, events: list[dict[str, Any]]) -> None:
        states: list[dict[str, Any]] = []
        prepare_count = 0
        refs: set[str] = set()
        hosted_refs: set[str] = set()
        for event in events:
            transition = event["transition"]
            if transition == "PREPARE":
                request = self._validate_request(event["payload"], prepare_count=prepare_count)
                if prepare_count % 2 == 0:
                    if states and any(state["receipt"] is None for state in states[-2:]):
                        raise ExecutorError("a later pair was prepared before the preceding pair reconciled")
                else:
                    prior = states[-1]
                    if prior["permit"] is None or prior["request"]["pair_id"] != request["pair_id"]:
                        raise ExecutorError("second pair member was prepared before the first permit")
                states.append(
                    {
                        "request": request,
                        "permit": None,
                        "claim": None,
                        "hosted": None,
                        "receipt": None,
                    }
                )
                prepare_count += 1
            elif transition == "ISSUE":
                permit = validate_research_permit(
                    event["payload"],
                    self.authorization,
                    ledger_path=self.ledger_path,
                    artifacts=self.artifacts,
                )
                index = permit["usage_sequence"] - 1
                if index >= len(states) or states[index]["permit"] is not None:
                    raise ExecutorError("permit issue transition is out of order")
                if any(permit[field] != states[index]["request"][field] for field in _REQUEST_FIELDS):
                    raise ExecutorError("issued permit does not match submit intent")
                states[index]["permit"] = permit
            elif transition == "CLAIM_UPLOAD":
                raw_claim = _exact_fields(event["payload"], _UPLOAD_CLAIM_FIELDS, label="upload claim")
                permit_sha = raw_claim["permit_content_sha256"]
                matches = [
                    (index, state)
                    for index, state in enumerate(states)
                    if state["permit"] is not None
                    and state["permit"]["content_sha256"] == permit_sha
                ]
                if len(matches) != 1:
                    raise ExecutorError("upload claim does not identify one issued permit")
                index, state = matches[0]
                if state["claim"] is not None:
                    raise ExecutorError("upload claim transition is out of order or duplicated")
                if index % 2 == 1 and states[index - 1]["hosted"] is None:
                    raise ExecutorError("second pair upload was claimed before the first was hosted")
                state["claim"] = self._validate_upload_claim(event["payload"], state["permit"])
            elif transition == "HOSTED":
                raw_hosted = event["payload"]
                matches = [
                    state
                    for state in states
                    if state["claim"] is not None
                    and state["claim"]["archive_name"] == raw_hosted.get("archive_name")
                    and state["claim"]["submission_description"]
                    == raw_hosted.get("submission_description")
                ] if isinstance(raw_hosted, Mapping) else []
                if len(matches) != 1:
                    raise ExecutorError("hosted observation does not identify one upload claim")
                state = matches[0]
                if state["hosted"] is not None:
                    raise ExecutorError("hosted observation transition is duplicated")
                try:
                    hosted = validate_hosted_observation(
                        raw_hosted,
                        archive_name=state["permit"]["archive_name"],
                        archive_sha256=state["permit"]["archive_sha256"],
                        submission_description=state["claim"]["submission_description"],
                        kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
                        expires_at_utc=self.authorization["expires_at_utc"],
                    )
                except Exception as exc:
                    raise ExecutorError(f"hosted observation is invalid: {exc}") from exc
                if hosted["submission_ref"] in hosted_refs:
                    raise ExecutorError("hosted submission reference is duplicated")
                hosted_refs.add(hosted["submission_ref"])
                state["hosted"] = hosted
            elif transition == "RECONCILE":
                raw_receipt = _exact_fields(event["payload"], _RECEIPT_FIELDS, label="submission receipt")
                permit_sha = raw_receipt["permit_content_sha256"]
                matches = [
                    state
                    for state in states
                    if state["permit"] is not None
                    and state["permit"]["content_sha256"] == permit_sha
                ]
                if len(matches) != 1:
                    raise ExecutorError("submission reconciliation does not identify one permit")
                state = matches[0]
                if state["claim"] is None or state["hosted"] is None or state["receipt"] is not None:
                    raise ExecutorError("submission reconciliation lacks a hosted one-shot upload")
                receipt = self._validate_receipt_shape(event["payload"], state["permit"])
                if receipt["submission_description"] != state["claim"]["submission_description"]:
                    raise ExecutorError("submission receipt does not match the one-shot upload claim")
                if receipt["submission_ref"] != state["hosted"]["submission_ref"]:
                    raise ExecutorError("submission receipt does not match the hosted observation")
                if receipt["submission_ref"] in refs:
                    raise ExecutorError("submission reference is duplicated in executor journal")
                refs.add(receipt["submission_ref"])
                state["receipt"] = receipt
            elif transition == "CAPTURE_PAIR":
                try:
                    capture = validate_authenticated_pair_capture(
                        event["payload"],
                        authorization=self.authorization,
                        usage_ledger_path=self.ledger_path,
                        artifacts=self.artifacts,
                    )
                except Exception as exc:
                    raise ExecutorError(f"pair capture is invalid: {exc}") from exc
                pair_states = [
                    state
                    for state in states
                    if state["request"]["pair_id"] == capture["pair_id"]
                ]
                if len(pair_states) != 2 or any(state["receipt"] is None for state in pair_states):
                    raise ExecutorError("pair capture precedes both reconciled submissions")
                if any(
                    prior["transition"] == "CAPTURE_PAIR"
                    and prior["payload"]["pair_id"] == capture["pair_id"]
                    for prior in events[: event["sequence"] - 1]
                ):
                    raise ExecutorError("pair capture is duplicated")
            else:
                raise ExecutorError("unknown executor transition")

    def _append(self, events: list[dict[str, Any]], transition: str, payload: Mapping[str, Any], now: str | datetime) -> dict[str, Any]:
        _, created = _utc(now, label="transition time")
        event = {
            "schema": EXECUTOR_EVENT_SCHEMA,
            "authorization_sha256": self.authorization["content_sha256"],
            "sequence": len(events) + 1,
            "event_id": f"voi-p5-executor-{len(events) + 1:02d}",
            "transition": transition,
            "payload": dict(payload),
            "created_at_utc": created,
            "previous_event_sha256": events[-1]["event_sha256"] if events else GENESIS_EVENT_SHA256,
            "event_sha256": "",
        }
        event["event_sha256"] = _event_digest(event)
        encoded = canonical_json_bytes(event) + b"\n"
        with self.state_path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        # A read-after-fsync catches torn or externally altered writes before a
        # later transition can proceed.
        if self._read_events()[-1] != event:
            raise ExecutorError("executor durable append verification failed")
        events.append(event)
        return event

    def _states(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        states: list[dict[str, Any]] = []
        for event in events:
            if event["transition"] == "PREPARE":
                states.append(
                    {
                        "request": dict(event["payload"]),
                        "permit": None,
                        "claim": None,
                        "hosted": None,
                        "receipt": None,
                    }
                )
            elif event["transition"] == "ISSUE":
                permit = dict(event["payload"])
                states[permit["usage_sequence"] - 1]["permit"] = permit
            elif event["transition"] == "CLAIM_UPLOAD":
                claim = dict(event["payload"])
                next(
                    state
                    for state in states
                    if state["permit"]["content_sha256"] == claim["permit_content_sha256"]
                )["claim"] = claim
            elif event["transition"] == "HOSTED":
                hosted = dict(event["payload"])
                next(
                    state
                    for state in states
                    if state["claim"] is not None
                    and state["claim"]["archive_name"] == hosted["archive_name"]
                    and state["claim"]["submission_description"]
                    == hosted["submission_description"]
                )["hosted"] = hosted
            elif event["transition"] == "RECONCILE":
                receipt = dict(event["payload"])
                next(
                    state
                    for state in states
                    if state["permit"]["content_sha256"] == receipt["permit_content_sha256"]
                )["receipt"] = receipt
        return states

    @staticmethod
    def _captures(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        return {
            event["payload"]["pair_id"]: dict(event["payload"])
            for event in events
            if event["transition"] == "CAPTURE_PAIR"
        }

    def _prior_capture_material(
        self,
        events: list[dict[str, Any]],
        assignment_index: int,
    ) -> object | None:
        pair_ids = sorted({str(row["pair_id"]) for row in self.authorization["archive_assignments"]})
        pair_id = str(self.authorization["archive_assignments"][assignment_index]["pair_id"])
        pair_index = pair_ids.index(pair_id)
        if pair_index == 0:
            return None
        capture = self._captures(events).get(pair_ids[pair_index - 1])
        if capture is None:
            raise ExecutorError("preceding pair lacks a direct authenticated Kaggle capture")
        reverify_authenticated_pair_capture_online(
            capture,
            authorization=self.authorization,
            usage_ledger_path=self.ledger_path,
            artifacts=self.artifacts,
        )
        return capture

    def _barrier_hash(
        self,
        *,
        assignment: Mapping[str, Any],
        prior_pair_capture: object | None,
    ) -> str | None:
        pair_ids = sorted({str(row["pair_id"]) for row in self.authorization["archive_assignments"]})
        pair_id = str(assignment["pair_id"])
        index = pair_ids.index(pair_id)
        if index == 0:
            if prior_pair_capture is not None:
                raise ExecutorError("first pair must not provide a prior authenticated capture")
            return None
        if prior_pair_capture is None:
            raise ExecutorError("later pairs require an authenticated prior pair capture")
        try:
            online_snapshot = reverify_authenticated_pair_capture_online(
                prior_pair_capture,
                authorization=self.authorization,
                usage_ledger_path=self.ledger_path,
                artifacts=self.artifacts,
            )
            snapshot = validate_authenticated_live_pair_snapshot(
                online_snapshot,
                authorization=self.authorization,
                artifacts=self.artifacts,
            )
        except Exception as exc:
            raise ExecutorError(f"prior authenticated pair capture is invalid: {exc}") from exc
        if snapshot["pair_id"] != pair_ids[index - 1]:
            raise ExecutorError("prior authenticated capture is for the wrong pair")
        return str(snapshot["pair_completion_barrier"]["content_sha256"])

    def _permit_from_usage(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        events = validate_usage_ledger(self.ledger_path, self.authorization, artifacts=self.artifacts)
        sequence = self.authorization["archive_assignments"].index(
            next(
                row
                for row in self.authorization["archive_assignments"]
                if row["pair_id"] == request["pair_id"] and row["slot"] == request["slot"]
            )
        ) + 1
        if len(events) > sequence:
            raise ExecutorError("usage ledger is ahead of the executor recovery boundary")
        if len(events) < sequence:
            return None
        event = events[sequence - 1]
        if any(event[field] != request[field] for field in _REQUEST_FIELDS):
            raise ExecutorError("consumed usage event does not match submit intent")
        content = {
            "schema": PERMIT_SCHEMA,
            "authorization_sha256": self.authorization["content_sha256"],
            "protocol_sha256": self.authorization["protocol_sha256"],
            "population_content_sha256": self.authorization["population_content_sha256"],
            "pair_assignment_content_sha256": self.authorization["pair_assignment_content_sha256"],
            "prediction_bundle_content_sha256": self.authorization["prediction_bundle_content_sha256"],
            **request,
            "usage_sequence": sequence,
            "usage_event_sha256": event["event_sha256"],
            "horizon": HORIZON,
            "scope": SCOPE,
            "remaining_cap": MAX_SUBMISSIONS - sequence,
            "research_only": True,
            "production_submission_authorized": False,
        }
        permit = {**content, "content_sha256": canonical_sha256(content)}
        return validate_research_permit(
            permit,
            self.authorization,
            ledger_path=self.ledger_path,
            artifacts=self.artifacts,
        )

    def _issue_pending(
        self,
        events: list[dict[str, Any]],
        request: Mapping[str, Any],
        *,
        now: str | datetime,
        prior_pair_capture: object | None,
        allow_consume: bool,
    ) -> dict[str, Any]:
        permit = self._permit_from_usage(request)
        if permit is None:
            if not allow_consume:
                raise ExecutorError("prepared permit was not consumed; resume it before reconciling")
            assignment = next(
                row
                for row in self.authorization["archive_assignments"]
                if row["pair_id"] == request["pair_id"] and row["slot"] == request["slot"]
            )
            # Validate the raw predecessor again immediately before consumption.
            expected_hash = self._barrier_hash(
                assignment=assignment,
                prior_pair_capture=prior_pair_capture,
            )
            if expected_hash != request["prior_pair_barrier_content_sha256"]:
                raise ExecutorError("prior pair barrier does not match the prepared intent")
            try:
                permit = guard_research_submission(
                    self.authorization,
                    self.ledger_path,
                    artifacts=self.artifacts,
                    **{field: request[field] for field in _REQUEST_FIELDS if field != "prior_pair_barrier_content_sha256"},
                    now=now,
                    prior_pair_capture=prior_pair_capture,
                )
            except AuthorizationError as exc:
                raise ExecutorError(f"research permit was not issued: {exc}") from exc
        self._append(events, "ISSUE", permit, now)
        return permit

    def _prepare_one(
        self,
        events: list[dict[str, Any]],
        *,
        index: int,
        now: str | datetime,
        prior_pair_capture: object | None,
    ) -> dict[str, Any]:
        assignment = self.authorization["archive_assignments"][index]
        barrier_sha = self._barrier_hash(
            assignment=assignment,
            prior_pair_capture=prior_pair_capture,
        )
        request = self._expected_request(index, barrier_sha)
        self._append(events, "PREPARE", request, now)
        return self._issue_pending(
            events,
            request,
            now=now,
            prior_pair_capture=prior_pair_capture,
            allow_consume=True,
        )

    def prepare_pair(
        self,
        *,
        now: str | datetime,
    ) -> list[dict[str, Any]]:
        """Durably prepare both exact permits for the next randomized pair."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            prepare_count = len(states)
            if prepare_count % 2:
                raise ExecutorError("a pair preparation is incomplete; resume it instead")
            if states and any(state["receipt"] is None for state in states[-2:]):
                raise ExecutorError("preceding pair must fully reconcile before preparing another pair")
            if prepare_count >= MAX_SUBMISSIONS:
                raise ExecutorError("authorization submission cap is exhausted")
            prior_pair_capture = self._prior_capture_material(
                events,
                prepare_count,
            )
            return [
                self._prepare_one(
                    events,
                    index=index,
                    now=now,
                    prior_pair_capture=prior_pair_capture,
                )
                for index in (prepare_count, prepare_count + 1)
            ]
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def resume_pair(
        self,
        *,
        now: str | datetime,
    ) -> list[dict[str, Any]]:
        """Recover a pair interrupted between either prepare/issue transition."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            if not states or (len(states) % 2 == 0 and all(state["receipt"] is not None for state in states[-2:])):
                raise ExecutorError("there is no incomplete pair to resume")
            pair_start = len(states) - 1 if len(states) % 2 else len(states) - 2
            prior_pair_capture = self._prior_capture_material(
                events,
                pair_start,
            )
            if states[-1]["permit"] is None:
                states[-1]["permit"] = self._issue_pending(
                    events,
                    states[-1]["request"],
                    now=now,
                    prior_pair_capture=prior_pair_capture,
                    allow_consume=True,
                )
            if len(states) % 2:
                permit = self._prepare_one(
                    events,
                    index=len(states),
                    now=now,
                    prior_pair_capture=prior_pair_capture,
                )
                states.append(
                    {
                        "request": self._expected_request(
                            len(states), permit["prior_pair_barrier_content_sha256"]
                        ),
                        "permit": permit,
                        "claim": None,
                        "hosted": None,
                        "receipt": None,
                    }
                )
            return [states[pair_start]["permit"], states[pair_start + 1]["permit"]]
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def upload_exact_archive(
        self,
        *,
        usage_sequence: int,
        local_archive: str | Path,
        submission_description: str,
    ) -> dict[str, Any]:
        """Durably claim and perform the sole exact Kaggle upload call.

        Once ``CLAIM_UPLOAD`` is fsynced this method will never issue another
        upload for the permit, even if the process dies before or during the
        external call. Recovery is query-only and therefore fail-closed.
        """

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            if (
                isinstance(usage_sequence, bool)
                or not isinstance(usage_sequence, int)
                or not 1 <= usage_sequence <= len(states)
            ):
                raise ExecutorError("usage_sequence does not identify a prepared permit")
            state = states[usage_sequence - 1]
            permit = state["permit"]
            if permit is None:
                raise ExecutorError("the selected permit has not been issued")
            if state["claim"] is not None:
                raise ExecutorError("upload is already claimed; only query-based recovery is allowed")
            if usage_sequence % 2 == 0 and states[usage_sequence - 2]["hosted"] is None:
                raise ExecutorError("first pair upload must be hosted before the second upload")
            self._assert_upload_window()
            try:
                archive_path, archive_bytes = load_exact_archive_bytes(
                    local_archive,
                    archive_name=permit["archive_name"],
                    archive_sha256=permit["archive_sha256"],
                )
                preflight = authenticated_upload_preflight(
                    archive_name=permit["archive_name"],
                    submission_description=submission_description,
                    kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
                )
            except ExecutorError:
                raise
            except Exception as exc:
                raise ExecutorError(f"authenticated upload preflight failed: {exc}") from exc
            content = {
                "schema": UPLOAD_CLAIM_SCHEMA,
                "authorization_sha256": self.authorization["content_sha256"],
                "permit_content_sha256": permit["content_sha256"],
                "usage_event_sha256": permit["usage_event_sha256"],
                "archive_sha256": permit["archive_sha256"],
                "archive_name": permit["archive_name"],
                "lineage_uuid": permit["lineage_uuid"],
                "pair_id": permit["pair_id"],
                "wave_id": permit["wave_id"],
                "slot": permit["slot"],
                "submission_description": submission_description,
                "local_archive_path": str(archive_path),
                "archive_content_length": len(archive_bytes),
                "upload_transport": "pinned_sdk_anonymous_pipe_v1",
                "authenticated_upload_preflight": preflight,
                "research_only": True,
                "production_submission_authorized": False,
            }
            claim = self._validate_upload_claim(
                {**content, "content_sha256": canonical_sha256(content)},
                permit,
            )
            self._append(events, "CLAIM_UPLOAD", claim, preflight["checked_at_utc"])
            self._assert_upload_window()
            try:
                submit_exact_archive_once(
                    archive_bytes=archive_bytes,
                    archive_name=permit["archive_name"],
                    archive_sha256=permit["archive_sha256"],
                    submission_description=submission_description,
                    kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
                )
            except Exception as exc:
                raise ExecutorError(
                    "upload call failed after the durable claim; never retry automatically"
                ) from exc
            try:
                hosted = observe_hosted_submission(
                    archive_name=permit["archive_name"],
                    archive_sha256=permit["archive_sha256"],
                    submission_description=submission_description,
                    kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
                    not_before_utc=preflight["checked_at_utc"],
                    expires_at_utc=self.authorization["expires_at_utc"],
                )
            except Exception as exc:
                raise ExecutorError(
                    "upload was invoked but is not yet uniquely hosted; call recover_claimed_upload and never retry"
                ) from exc
            self._append(events, "HOSTED", hosted, hosted["observed_at_utc"])
            return hosted
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def recover_claimed_upload(self, *, usage_sequence: int) -> dict[str, Any]:
        """Recover a claimed upload by live-history query only; never resubmit."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            if (
                isinstance(usage_sequence, bool)
                or not isinstance(usage_sequence, int)
                or not 1 <= usage_sequence <= len(states)
            ):
                raise ExecutorError("usage_sequence does not identify a prepared permit")
            state = states[usage_sequence - 1]
            if state["claim"] is None:
                raise ExecutorError("upload has no durable claim to recover")
            if state["hosted"] is not None:
                return state["hosted"]
            claim = state["claim"]
            try:
                hosted = observe_hosted_submission(
                    archive_name=claim["archive_name"],
                    archive_sha256=claim["archive_sha256"],
                    submission_description=claim["submission_description"],
                    kaggle_runtime_binding=self.artifacts["kaggle_runtime_binding"],
                    not_before_utc=claim["authenticated_upload_preflight"]["checked_at_utc"],
                    expires_at_utc=self.authorization["expires_at_utc"],
                )
            except Exception as exc:
                raise ExecutorError(
                    "claimed upload is not uniquely visible; manual review is required and upload retry is forbidden"
                ) from exc
            self._append(events, "HOSTED", hosted, hosted["observed_at_utc"])
            return hosted
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def reconcile_completed_submission(self, *, usage_sequence: int) -> dict[str, Any]:
        """Poll one hosted ref and journal its first observed COMPLETE receipt."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            if (
                isinstance(usage_sequence, bool)
                or not isinstance(usage_sequence, int)
                or not 1 <= usage_sequence <= len(states)
            ):
                raise ExecutorError("usage_sequence does not identify a prepared permit")
            state = states[usage_sequence - 1]
            if state["receipt"] is not None:
                return state["receipt"]
            if state["claim"] is None or state["hosted"] is None:
                raise ExecutorError("submission must be durably claimed and hosted before reconciliation")
            try:
                receipt = build_live_completed_submission_receipt(
                    authorization=self.authorization,
                    permit=state["permit"],
                    hosted_observation=state["hosted"],
                    submission_description=state["claim"]["submission_description"],
                    usage_ledger_path=self.ledger_path,
                    artifacts=self.artifacts,
                    local_archive=state["claim"]["local_archive_path"],
                )
            except Exception as exc:
                raise ExecutorError(f"live hosted submission is not ready to reconcile: {exc}") from exc
            self._append(
                events,
                "RECONCILE",
                receipt,
                receipt["first_observed_complete_at_utc"],
            )
            return receipt
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def capture_completed_pair(
        self,
        *,
        team_name: str,
        capture_directory: str | Path,
    ) -> dict[str, Any]:
        """Capture both reconciled horizons through authenticated byte custody."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            if len(states) < 2 or len(states) % 2:
                raise ExecutorError("there is no fully prepared pair to capture")
            pair_states = states[-2:]
            if any(state["receipt"] is None for state in pair_states):
                raise ExecutorError("both pair submissions must reconcile before capture")
            pair_id = pair_states[0]["request"]["pair_id"]
            if pair_states[1]["request"]["pair_id"] != pair_id:
                raise ExecutorError("latest executor states do not form one pair")
            if pair_id in self._captures(events):
                raise ExecutorError("pair already has an authenticated Kaggle capture")
            permits = {
                state["permit"]["lineage_uuid"]: state["permit"] for state in pair_states
            }
            refs = {
                state["permit"]["lineage_uuid"]: state["receipt"]["submission_ref"]
                for state in pair_states
            }
            descriptions = {
                state["permit"]["lineage_uuid"]: state["claim"]["submission_description"]
                for state in pair_states
            }
            local_archives_by_lineage_uuid = {
                state["permit"]["lineage_uuid"]: state["claim"]["local_archive_path"]
                for state in pair_states
            }
            try:
                capture = capture_authenticated_pair(
                    authorization=self.authorization,
                    pair_id=pair_id,
                    usage_ledger_path=self.ledger_path,
                    artifacts=self.artifacts,
                    permits_by_lineage_uuid=permits,
                    submission_refs_by_lineage_uuid=refs,
                    descriptions_by_lineage_uuid=descriptions,
                    local_archives_by_lineage_uuid=local_archives_by_lineage_uuid,
                    team_name=team_name,
                    capture_directory=capture_directory,
                )
            except Exception as exc:
                raise ExecutorError(f"authenticated Kaggle pair capture failed: {exc}") from exc
            self._append(events, "CAPTURE_PAIR", capture, capture["captured_at_utc"])
            return capture
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()

    def status(self) -> dict[str, Any]:
        """Return the small runner-facing state without performing any transition."""

        lock = self._with_lock()
        try:
            events = self._read_events()
            states = self._states(events)
            prepared = len(states)
            current_pair = states[-2:] if states and prepared % 2 == 0 else states[-1:]
            pair_complete = bool(current_pair) and len(current_pair) == 2 and all(
                state["receipt"] is not None for state in current_pair
            )
            if not states or pair_complete:
                state_name = "READY"
            elif len(current_pair) < 2 or any(state["permit"] is None for state in current_pair):
                state_name = "PAIR_PREPARING"
            elif all(state["hosted"] is not None for state in current_pair):
                state_name = "PAIR_HOSTED"
            elif all(state["claim"] is not None for state in current_pair):
                state_name = "PAIR_UPLOADS_CLAIMED"
            elif any(state["hosted"] is not None for state in current_pair):
                state_name = "PAIR_HOSTED_PARTIAL"
            elif any(state["claim"] is not None for state in current_pair):
                state_name = "PAIR_UPLOAD_PARTIAL"
            else:
                state_name = "PAIR_ISSUED"
            return {
                "schema": "voi_p5_executor_status_v1",
                "authorization_sha256": self.authorization["content_sha256"],
                "state": state_name,
                "prepared_submissions": prepared,
                "remaining_cap": MAX_SUBMISSIONS - prepared,
                "current_pair": current_pair,
                "captured_pair_ids": sorted(self._captures(events)),
                "research_only": True,
                "production_submission_authorized": False,
            }
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()


__all__ = [
    "EXECUTOR_EVENT_SCHEMA",
    "UPLOAD_CLAIM_SCHEMA",
    "ExecutorError",
    "VOIP5CalibrationExecutor",
]
