"""Fail-closed local executor for the v6.2.1 calibration campaign.

This module intentionally has no Kaggle client and no upload operation.  A
caller may obtain a journaled ``UNIT_UPLOAD_PERMIT`` and reconcile externally
observed, mapping-shaped evidence.  The project lock and append-only journal
make an interrupted intent an ambiguity to resolve, never something to retry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
from statistics import median
from typing import Any, Mapping


EVENT_SCHEMA = "evaluation_v6_2_executor_event_v1"
GENESIS_SHA256 = "0" * 64
CALIBRATION_BUDGET = 16
PRODUCTION_BUDGET = 1
REQUIRED_VERIFIER_PASSES = frozenset(
    {
        "CUSTODY_PASS",
        "POPULATION_16_PASS",
        "INDEPENDENCE_PASS",
        "CONTROLS_PASS",
        "LOCAL_EVIDENCE_FROZEN",
        "ANALYSIS_LOCK_PASS",
        "EXECUTOR_FAIL_CLOSED_PASS",
        "UPLOAD_LOCK_EXCLUSIVE_PASS",
        "LEDGER_DISJOINT_PASS",
        "QUOTA_READY",
        "PREREG_ROOT_PUBLISHED",
        "SOL_PREUPLOAD_PASS",
    }
)
DEV_PRIMARY_IDS = tuple(f"D{index:02d}" for index in range(1, 7))
CONFIRM_PRIMARY_IDS = tuple(f"C{index:02d}" for index in range(1, 9))
DEV_RESERVE_ID = "DR01"
CONFIRM_RESERVE_ID = "CR01"
SLOT_IDS = DEV_PRIMARY_IDS + (DEV_RESERVE_ID,) + CONFIRM_PRIMARY_IDS + (CONFIRM_RESERVE_ID,)
_SHA = re.compile(r"^[0-9a-f]{64}$")


class ExecutorError(ValueError):
    """A requested transition or persisted campaign journal is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    """ASCII canonical JSON suitable for stable event hashing."""
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ExecutorError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _utc(value: object, *, label: str) -> tuple[datetime, str]:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip() == value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ExecutorError(f"{label} must be ISO-8601 UTC") from exc
    else:
        raise ExecutorError(f"{label} is required")
    if parsed.tzinfo is None:
        raise ExecutorError(f"{label} must be timezone-aware")
    parsed = parsed.astimezone(timezone.utc)
    return parsed, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ExecutorError(f"{label} must be a lowercase SHA-256")
    return value


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ExecutorError(f"{label} must be a finite number")
    return float(value)


def _event_digest(event: Mapping[str, Any]) -> str:
    return canonical_sha256({key: event[key] for key in event if key != "event_sha256"})


class CalibrationCampaignExecutor:
    """A crash-recoverable, sequential campaign state machine.

    All inputs deliberately use mappings.  External collectors own the live
    evidence and are expected to supply its hashes, timestamps, and status.
    This class only validates and journals those observations.
    """

    def __init__(
        self,
        *,
        state_path: str | Path,
        campaign_id: str,
        project_lock_path: str | Path | None = None,
    ) -> None:
        if not isinstance(campaign_id, str) or not campaign_id or campaign_id.strip() != campaign_id:
            raise ExecutorError("campaign_id must be a nonempty trimmed string")
        self.state_path = Path(state_path)
        self.campaign_id = campaign_id
        self.project_lock_path = (
            Path(project_lock_path)
            if project_lock_path is not None
            else self.state_path.parent / ".evaluation_v6_2_project_upload.lock.json"
        )

    def _journal_lock(self):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.state_path.with_name(f"{self.state_path.name}.lock").open("a+b")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _read_events(self) -> list[dict[str, Any]]:
        if not self.state_path.exists():
            return []
        raw = self.state_path.read_bytes()
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise ExecutorError("journal must end with a newline")
        try:
            lines = raw.decode("ascii").splitlines()
            events = [json.loads(line) for line in lines]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorError(f"journal is not canonical ASCII JSONL: {exc}") from exc
        previous = GENESIS_SHA256
        prior_time: datetime | None = None
        checked: list[dict[str, Any]] = []
        fields = {
            "schema", "campaign_id", "sequence", "transition", "payload",
            "created_at_utc", "previous_event_sha256", "event_sha256",
        }
        for index, event in enumerate(events, start=1):
            if not isinstance(event, dict) or set(event) != fields:
                raise ExecutorError("journal event has unexpected fields")
            if canonical_json_bytes(event) != lines[index - 1].encode("ascii"):
                raise ExecutorError("journal event is not canonical JSON")
            if event["schema"] != EVENT_SCHEMA or event["campaign_id"] != self.campaign_id:
                raise ExecutorError("journal event campaign binding mismatch")
            if event["sequence"] != index or event["previous_event_sha256"] != previous:
                raise ExecutorError("journal sequence or hash chain is broken")
            if _event_digest(event) != _sha(event["event_sha256"], label="event_sha256"):
                raise ExecutorError("journal event hash mismatch")
            when, normalized = _utc(event["created_at_utc"], label="created_at_utc")
            if prior_time is not None and when < prior_time:
                raise ExecutorError("journal timestamps move backward")
            event = dict(event)
            event["created_at_utc"] = normalized
            checked.append(event)
            previous, prior_time = event["event_sha256"], when
        return checked

    def _append(self, transition: str, payload: Mapping[str, object], now: object) -> dict[str, Any]:
        events = self._read_events()
        _, created = _utc(now, label="now")
        event: dict[str, Any] = {
            "schema": EVENT_SCHEMA,
            "campaign_id": self.campaign_id,
            "sequence": len(events) + 1,
            "transition": transition,
            "payload": dict(payload),
            "created_at_utc": created,
            "previous_event_sha256": events[-1]["event_sha256"] if events else GENESIS_SHA256,
        }
        event["event_sha256"] = _event_digest(event)
        data = canonical_json_bytes(event) + b"\n"
        fd = os.open(self.state_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        return event

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {
            "state": "NEW",
            "population": None,
            "prereg_receipt": None,
            "local_evidence_receipt": None,
            "dev_fit_receipt": None,
            "prediction_receipt": None,
            "confirm_progress": [],
            "units": {},
            "active_unit_id": None,
            "terminal_reason": None,
            "calibration_budget_remaining": CALIBRATION_BUDGET,
            "production_budget_remaining": PRODUCTION_BUDGET,
        }

    def _state(self) -> dict[str, Any]:
        state = self._empty_state()
        for event in self._read_events():
            payload = event["payload"]
            transition = event["transition"]
            if transition == "POPULATION_FROZEN":
                state["population"] = payload["population"]
                state["units"] = {row["slot_id"]: {"row": row, "state": "QUEUED", "polls": []} for row in payload["population"]}
                state["state"] = "POPULATION_FROZEN"
            elif transition == "PREREG_LOCKED":
                state["prereg_receipt"] = payload["receipt"]
                state["state"] = "PREREG_LOCKED"
            elif transition == "LOCAL_EVIDENCE_FROZEN":
                state["local_evidence_receipt"] = payload["receipt"]
                state["state"] = "LOCAL_EVIDENCE_FROZEN"
            elif transition == "DEV_QUEUE_READY":
                state["state"] = "DEV_QUEUE_READY"
            elif transition == "UPLOAD_INTENT_WRITTEN":
                unit = state["units"][payload["unit_id"]]
                unit.update({"state": "UPLOAD_INTENT", "permit": payload["permit"], "intent_at_utc": event["created_at_utc"]})
                state["active_unit_id"] = payload["unit_id"]
                state["calibration_budget_remaining"] -= 1
                state["state"] = "UPLOAD_INTENT"
            elif transition == "UPLOAD_BOUND":
                unit = state["units"][payload["unit_id"]]
                unit.update({"state": "WAIT_COMPLETE", "submission": payload["submission"]})
                state["state"] = "WAIT_COMPLETE"
            elif transition == "UPLOAD_AMBIGUOUS":
                state["units"][payload["unit_id"]]["state"] = "UPLOAD_AMBIGUOUS"
                state["state"] = "UPLOAD_AMBIGUOUS"
            elif transition == "COMPLETE_OBSERVED":
                unit = state["units"][payload["unit_id"]]
                unit["first_observed_complete_at_utc"] = payload["first_observed_complete_at_utc"]
                unit["state"] = "MATURITY_WAIT"
                state["state"] = "MATURITY_WAIT"
            elif transition == "POLL_RECORDED":
                unit = state["units"][payload["unit_id"]]
                unit["polls"].append(payload["poll"])
                unit["state"] = f"POLL_{len(unit['polls'])}"
                state["state"] = unit["state"]
            elif transition == "ENDPOINT_CLOSED":
                unit = state["units"][payload["unit_id"]]
                unit.update({"state": "ENDPOINT_CLOSED", "endpoint": payload["endpoint"]})
                state["active_unit_id"] = None
                state["state"] = "ENDPOINT_CLOSED"
            elif transition == "UNIT_PREMATURITY_FAILURE":
                unit = state["units"][payload["unit_id"]]
                unit.update({"state": "PREMATURITY_FAILURE", "failure": payload["failure"]})
                state["active_unit_id"] = None
                state["state"] = payload["next_state"]
            elif transition == "DEV_FIT_LOCKED":
                state["dev_fit_receipt"] = payload["receipt"]
                state["state"] = "DEV_FIT_LOCKED"
            elif transition == "CONFIRM_PREDICTIONS_FROZEN":
                state["prediction_receipt"] = payload["receipt"]
                state["state"] = "CONFIRM_QUEUE_READY"
            elif transition == "CONFIRM_PROGRESS_RECORDED":
                state["confirm_progress"].append(payload["comparison"])
            elif transition == "CAMPAIGN_CLOSED":
                if state["active_unit_id"] is not None:
                    state["units"][state["active_unit_id"]]["state"] = "TERMINATED"
                    state["active_unit_id"] = None
                state["state"] = payload["state"]
                state["terminal_reason"] = payload.get("reason")
            else:
                raise ExecutorError(f"unknown journal transition {transition!r}")
        if state["calibration_budget_remaining"] < 0:
            raise ExecutorError("calibration budget is negative")
        return state

    @staticmethod
    def _assert_receipt(receipt: object, *, label: str) -> dict[str, Any]:
        if not isinstance(receipt, Mapping):
            raise ExecutorError(f"{label} must be a mapping")
        result = dict(receipt)
        if result.get("status") != "PASS":
            raise ExecutorError(f"{label} must have status PASS")
        return result

    @staticmethod
    def _validate_population(population: object) -> list[dict[str, Any]]:
        if not isinstance(population, list) or len(population) != 16:
            raise ExecutorError("population must contain exactly 16 slots")
        required = {
            "slot_id", "archive_hash", "role", "upload_order", "lineage_time_block_id",
            "source_family_id", "intervention_family_id", "production_eligibility_flag",
            "production_ineligibility_reason", "submission_name", "unique_token",
        }
        rows: list[dict[str, Any]] = []
        for row in population:
            if not isinstance(row, Mapping) or set(row) != required:
                raise ExecutorError("population rows have unexpected fields")
            item = dict(row)
            if item["slot_id"] not in SLOT_IDS or item["role"] not in {"DEV", "CONFIRM"}:
                raise ExecutorError("population slot_id or role is invalid")
            expected_role = "DEV" if item["slot_id"].startswith("D") else "CONFIRM"
            if item["role"] != expected_role or item["upload_order"] != SLOT_IDS.index(item["slot_id"]) + 1:
                raise ExecutorError("population role or upload order is invalid")
            _sha(item["archive_hash"], label="archive_hash")
            for key in ("lineage_time_block_id", "source_family_id", "intervention_family_id", "submission_name", "unique_token"):
                if not isinstance(item[key], str) or not item[key] or item[key].strip() != item[key]:
                    raise ExecutorError(f"population {key} is invalid")
            if "final" in item["submission_name"].casefold():
                raise ExecutorError("submission names must not contain 'final'")
            if item["production_eligibility_flag"] is not False or not isinstance(item["production_ineligibility_reason"], str) or not item["production_ineligibility_reason"]:
                raise ExecutorError("calibration rows must be production-ineligible")
            rows.append(item)
        if {row["slot_id"] for row in rows} != set(SLOT_IDS):
            raise ExecutorError("population slot ids are not the exact v6.2.1 composition")
        for key in ("archive_hash", "source_family_id", "lineage_time_block_id", "unique_token"):
            if len({row[key] for row in rows}) != 16:
                raise ExecutorError(f"population {key} values must be pairwise distinct")
        return sorted(rows, key=lambda row: row["upload_order"])

    def freeze_population(self, population: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            if self._state()["state"] != "NEW":
                raise ExecutorError("population can only be frozen once")
            rows = self._validate_population(population)
            self._append("POPULATION_FROZEN", {"population": rows}, now)
            return self.status()

    def lock_preregistration(self, receipt: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            if self._state()["state"] != "POPULATION_FROZEN":
                raise ExecutorError("preregistration requires a frozen population")
            checked = self._assert_receipt(receipt, label="preregistration receipt")
            _sha(checked.get("prereg_root_sha256"), label="preregistration prereg_root_sha256")
            self._append("PREREG_LOCKED", {"receipt": checked}, now)
            return self.status()

    def lock_local_evidence(self, receipt: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            if self._state()["state"] != "PREREG_LOCKED":
                raise ExecutorError("local evidence requires preregistration lock")
            self._append("LOCAL_EVIDENCE_FROZEN", {"receipt": self._assert_receipt(receipt, label="local evidence receipt")}, now)
            return self.status()

    def open_dev_queue(self, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            if self._state()["state"] != "LOCAL_EVIDENCE_FROZEN":
                raise ExecutorError("DEV queue requires local evidence lock")
            self._append("DEV_QUEUE_READY", {}, now)
            return self.status()

    @staticmethod
    def _all_required_passes(receipt: Mapping[str, Any]) -> bool:
        outputs = receipt.get("verifier_outputs")
        if not isinstance(outputs, Mapping) or set(outputs) != REQUIRED_VERIFIER_PASSES:
            return False
        return receipt.get("frozen") is True and all(outputs[key] == "PASS" for key in REQUIRED_VERIFIER_PASSES)

    @staticmethod
    def _tranche_units(tranche: str) -> tuple[str, ...]:
        if tranche == "DEV":
            return DEV_PRIMARY_IDS + (DEV_RESERVE_ID,)
        if tranche == "CONFIRM":
            return CONFIRM_PRIMARY_IDS + (CONFIRM_RESERVE_ID,)
        raise ExecutorError("unknown campaign tranche")

    def _next_unit_id(self, state: Mapping[str, Any]) -> str | None:
        if state["state"] in {"DEV_QUEUE_READY", "ENDPOINT_CLOSED"} and state["dev_fit_receipt"] is None:
            tranche = "DEV"
        elif state["state"] in {"CONFIRM_QUEUE_READY", "ENDPOINT_CLOSED"} and state["prediction_receipt"] is not None:
            tranche = "CONFIRM"
        else:
            return None
        units = state["units"]
        primary = DEV_PRIMARY_IDS if tranche == "DEV" else CONFIRM_PRIMARY_IDS
        reserve = DEV_RESERVE_ID if tranche == "DEV" else CONFIRM_RESERVE_ID
        for unit_id in primary:
            if units[unit_id]["state"] == "QUEUED":
                return unit_id
        failed = sum(units[unit_id]["state"] == "PREMATURITY_FAILURE" for unit_id in primary)
        if failed == 1 and units[reserve]["state"] == "QUEUED":
            return reserve
        return None

    def _acquire_project_lock(self, unit_id: str) -> None:
        self.project_lock_path.parent.mkdir(parents=True, exist_ok=True)
        body = canonical_json_bytes({"campaign_id": self.campaign_id, "state_path": str(self.state_path.resolve()), "unit_id": unit_id}) + b"\n"
        try:
            fd = os.open(self.project_lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ExecutorError("durable project-wide upload lock is already held") from exc
        try:
            os.write(fd, body)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _release_project_lock(self, state: Mapping[str, Any]) -> None:
        if not self.project_lock_path.exists():
            raise ExecutorError("durable project-wide upload lock disappeared")
        try:
            locked = json.loads(self.project_lock_path.read_text(encoding="ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutorError(f"durable project-wide upload lock is unreadable: {exc}") from exc
        if locked.get("campaign_id") != self.campaign_id:
            raise ExecutorError("durable project-wide upload lock belongs to another campaign")
        self.project_lock_path.unlink()

    def issue_upload_permit(self, verifier_receipt: object, *, own_uploads_today: object, now: object) -> dict[str, Any]:
        """Reject the retired v6.2.1 synthetic-PASS authorization path.

        The v6.2.2 executor will accept only an Ed25519-signed, one-time permit
        bound to the rooted population, verification root, and runtime state.
        Keeping this public method closed prevents the otherwise-valid state
        machine from being reached with a caller-fabricated PASS mapping.
        """
        del verifier_receipt, own_uploads_today, now
        raise ExecutorError(
            "v6.2.1 permit issuance is retired; a signed v6.2.2 UNIT_UPLOAD_PERMIT is required"
        )

    def reconcile_upload_matches(self, matches: object, *, now: object, timeout_expired: bool = False) -> dict[str, Any]:
        """Bind exactly one external submission, or retain/terminate ambiguity."""
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["state"] not in {"UPLOAD_INTENT", "UPLOAD_AMBIGUOUS"}:
                raise ExecutorError("upload reconciliation requires an unresolved upload intent")
            unit_id = state["active_unit_id"]
            if not isinstance(matches, list):
                raise ExecutorError("upload matches must be a list")
            token = state["units"][unit_id]["row"]["unique_token"]
            normalized: list[dict[str, Any]] = []
            for match in matches:
                if not isinstance(match, Mapping):
                    raise ExecutorError("upload match must be a mapping")
                item = dict(match)
                if item.get("unique_token") != token or not isinstance(item.get("submission_ref"), str) or not item["submission_ref"]:
                    raise ExecutorError("upload match does not bind the active unique token")
                normalized.append(item)
            if len(normalized) == 1:
                self._append("UPLOAD_BOUND", {"unit_id": unit_id, "submission": normalized[0]}, now)
            elif len(normalized) == 0 and not timeout_expired:
                self._append("UPLOAD_AMBIGUOUS", {"unit_id": unit_id}, now)
            else:
                self._append("CAMPAIGN_CLOSED", {"state": "CAMPAIGN_INCONCLUSIVE_UPLOAD_AMBIGUOUS", "reason": "duplicate or unresolved upload intent"}, now)
                self._release_project_lock(state)
            return self.status()

    def observe_submission_status(self, observation: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["state"] != "WAIT_COMPLETE":
                raise ExecutorError("status observation requires WAIT_COMPLETE")
            if not isinstance(observation, Mapping):
                raise ExecutorError("status observation must be a mapping")
            unit_id = state["active_unit_id"]
            status = observation.get("status")
            observed, observed_text = _utc(observation.get("observed_at_utc"), label="observed_at_utc")
            if status == "COMPLETE":
                existing = state["units"][unit_id].get("first_observed_complete_at_utc")
                if existing is None:
                    self._append("COMPLETE_OBSERVED", {"unit_id": unit_id, "first_observed_complete_at_utc": observed_text}, now)
                return self.status()
            if status == "ERROR" and observation.get("verified_technical_failure") is True:
                self._pre_maturity_failure(state, unit_id, {"kind": "ERROR_BEFORE_COMPLETE", "observed_at_utc": observed_text}, now)
                return self.status()
            if observed >= _utc(state["units"][unit_id]["intent_at_utc"], label="intent_at_utc")[0] + timedelta(hours=12) and observation.get("verified_platform_outage") is True:
                self._pre_maturity_failure(state, unit_id, {"kind": "NO_COMPLETE_PLATFORM_OUTAGE", "observed_at_utc": observed_text}, now)
                return self.status()
            raise ExecutorError("only COMPLETE or a verified pre-COMPLETE technical failure is actionable")

    def _pre_maturity_failure(self, state: Mapping[str, Any], unit_id: str, failure: Mapping[str, object], now: object) -> None:
        unit = state["units"][unit_id]
        if unit["polls"]:
            self._terminal(state, "CAMPAIGN_INCONCLUSIVE", "failure after a mature poll", now)
            return
        tranche = unit["row"]["role"]
        primary = DEV_PRIMARY_IDS if tranche == "DEV" else CONFIRM_PRIMARY_IDS
        failures = sum(state["units"][item]["state"] == "PREMATURITY_FAILURE" for item in primary)
        next_state = "DEV_QUEUE_READY" if tranche == "DEV" else "CONFIRM_QUEUE_READY"
        self._append("UNIT_PREMATURITY_FAILURE", {"unit_id": unit_id, "failure": dict(failure), "next_state": next_state}, now)
        self._release_project_lock(state)
        if failures >= 1:
            self._terminal(self._state(), "CAMPAIGN_INCONCLUSIVE", f"second {tranche} pre-maturity failure", now)

    def record_pre_maturity_failure(self, failure: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["state"] not in {"WAIT_COMPLETE", "MATURITY_WAIT"}:
                raise ExecutorError("pre-maturity failure requires an active unresolved unit")
            if not isinstance(failure, Mapping) or failure.get("verified_technical_failure") is not True:
                raise ExecutorError("failure must be verified technical failure")
            unit_id = state["active_unit_id"]
            if state["units"][unit_id]["polls"]:
                self._terminal(state, "CAMPAIGN_INCONCLUSIVE", "failure after a mature poll", now)
            else:
                self._pre_maturity_failure(state, unit_id, dict(failure), now)
            return self.status()

    def _terminal(self, state: Mapping[str, Any], terminal_state: str, reason: str, now: object) -> None:
        self._append("CAMPAIGN_CLOSED", {"state": terminal_state, "reason": reason}, now)
        if state["active_unit_id"] is not None:
            self._release_project_lock(state)

    def record_poll(self, poll: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["state"] not in {"MATURITY_WAIT", "POLL_1", "POLL_2", "POLL_3"}:
                raise ExecutorError("poll is not currently expected")
            if not isinstance(poll, Mapping):
                raise ExecutorError("poll must be a mapping")
            unit_id = state["active_unit_id"]
            unit = state["units"][unit_id]
            ordinal = len(unit["polls"]) + 1
            complete, _ = _utc(unit["first_observed_complete_at_utc"], label="first_observed_complete_at_utc")
            expected = complete + timedelta(minutes=(60, 120, 240, 480)[ordinal - 1])
            observed, observed_text = _utc(poll.get("observed_at_utc", now), label="poll observed_at_utc")
            if observed < expected or observed > expected + timedelta(minutes=10):
                raise ExecutorError("poll is outside its mandatory 10-minute window")
            score_time, score_text = _utc(poll.get("score_observed_at_utc"), label="score_observed_at_utc")
            board_time, board_text = _utc(poll.get("leaderboard_observed_at_utc"), label="leaderboard_observed_at_utc")
            if abs((score_time - board_time).total_seconds()) > 60:
                raise ExecutorError("score and leaderboard evidence skew exceeds 60 seconds")
            score = _number(poll.get("score"), label="score")
            cutoff = _number(poll.get("top10_cutoff"), label="top10_cutoff")
            _sha(poll.get("score_body_sha256"), label="score_body_sha256")
            _sha(poll.get("leaderboard_body_sha256"), label="leaderboard_body_sha256")
            latest_two = poll.get("latest_two_submission_refs")
            ref = unit["submission"]["submission_ref"]
            if not isinstance(latest_two, list) or ref not in latest_two or len(latest_two) > 2 or poll.get("out_of_band_upload_detected") is True:
                self._terminal(state, "CAMPAIGN_INTEGRITY_FAIL", "latest-two displacement or out-of-band upload", now)
                return self.status()
            if poll.get("official_scoring_changed") is True or poll.get("leaderboard_format_changed") is True:
                self._terminal(state, "CAMPAIGN_INCONCLUSIVE_REGIME_BREAK", "official scoring/rules or leaderboard format changed", now)
                return self.status()
            if unit["polls"]:
                previous = unit["polls"][-1]
                previous_time, _ = _utc(previous["observed_at_utc"], label="previous poll observed_at_utc")
                if observed - previous_time <= timedelta(hours=2) and abs(cutoff - previous["top10_cutoff"]) >= 100:
                    self._terminal(state, "CAMPAIGN_INCONCLUSIVE_REGIME_BREAK", "top-10 cutoff regime break", now)
                    return self.status()
            normalized = {
                "ordinal": ordinal, "observed_at_utc": observed_text,
                "score_observed_at_utc": score_text, "leaderboard_observed_at_utc": board_text,
                "score": score, "top10_cutoff": cutoff,
                "score_body_sha256": poll["score_body_sha256"], "leaderboard_body_sha256": poll["leaderboard_body_sha256"],
                "latest_two_submission_refs": list(latest_two),
            }
            self._append("POLL_RECORDED", {"unit_id": unit_id, "poll": normalized}, now)
            if ordinal == 4:
                endpoint = {"gaps": [entry["score"] - entry["top10_cutoff"] for entry in unit["polls"] + [normalized]]}
                endpoint["median_gap"] = median(endpoint["gaps"])
                self._append("ENDPOINT_CLOSED", {"unit_id": unit_id, "endpoint": endpoint}, now)
                self._release_project_lock(state)
            return self.status()

    def close_missing_poll(self, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["active_unit_id"] is None or state["state"] not in {"MATURITY_WAIT", "POLL_1", "POLL_2", "POLL_3"}:
                raise ExecutorError("there is no open poll window to close")
            unit = state["units"][state["active_unit_id"]]
            ordinal = len(unit["polls"]) + 1
            complete, _ = _utc(unit["first_observed_complete_at_utc"], label="first_observed_complete_at_utc")
            deadline = complete + timedelta(minutes=(60, 120, 240, 480)[ordinal - 1] + 10)
            current, _ = _utc(now, label="now")
            if current <= deadline:
                raise ExecutorError("poll window has not yet expired")
            self._terminal(state, "CAMPAIGN_INCONCLUSIVE", "required synchronized poll is missing", now)
            return self.status()

    def lock_dev_fit(self, receipt: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["active_unit_id"] is not None or state["dev_fit_receipt"] is not None:
                raise ExecutorError("DEV fit cannot be locked while a unit is active or after a prior lock")
            dev_valid = sum(
                state["units"][item]["state"] == "ENDPOINT_CLOSED"
                for item in DEV_PRIMARY_IDS + (DEV_RESERVE_ID,)
            )
            if dev_valid != 6:
                raise ExecutorError("exactly six valid DEV endpoints are required before fitting")
            checked = self._assert_receipt(receipt, label="DEV fit receipt")
            if checked.get("verdict") != "DEV_CONTINUE" or checked.get("successful_folds") != 6:
                raise ExecutorError("DEV fit receipt must prove DEV_CONTINUE with 6/6 successful folds")
            self._append("DEV_FIT_LOCKED", {"receipt": checked}, now)
            return self.status()

    def freeze_confirm_predictions(self, receipt: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            if self._state()["state"] != "DEV_FIT_LOCKED":
                raise ExecutorError("CONFIRM prediction lock requires DEV_FIT_LOCKED")
            checked = self._assert_receipt(receipt, label="CONFIRM prediction receipt")
            if checked.get("prediction_lock") != "PASS":
                raise ExecutorError("CONFIRM predictions must be explicitly frozen")
            self._append("CONFIRM_PREDICTIONS_FROZEN", {"receipt": checked}, now)
            return self.status()

    def record_confirm_progress(self, comparison: object, *, now: object) -> dict[str, Any]:
        """Record a frozen-model CONFIRM comparison and apply futility only.

        The analysis layer supplies canonical absolute errors and pairwise
        concordance.  This executor never refits or selects from them; it only
        stops when the preregistered 7/8 or 20/28 target is unreachable.
        """
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if (
                state["state"] != "ENDPOINT_CLOSED"
                or state["active_unit_id"] is not None
                or state["prediction_receipt"] is None
            ):
                raise ExecutorError("CONFIRM progress requires a closed endpoint and frozen predictions")
            if not isinstance(comparison, Mapping):
                raise ExecutorError("CONFIRM comparison must be a mapping")
            raw = dict(comparison)
            required = {"slot_id", "v6_absolute_error", "raw_absolute_error", "new_concordant_pairs"}
            if set(raw) != required or raw["slot_id"] not in CONFIRM_PRIMARY_IDS + (CONFIRM_RESERVE_ID,):
                raise ExecutorError("CONFIRM comparison fields or slot_id are invalid")
            if state["units"][raw["slot_id"]]["state"] != "ENDPOINT_CLOSED":
                raise ExecutorError("CONFIRM comparison requires that unit's closed endpoint")
            if any(row["slot_id"] == raw["slot_id"] for row in state["confirm_progress"]):
                raise ExecutorError("CONFIRM comparison is already recorded")
            v6_error = _number(raw["v6_absolute_error"], label="v6_absolute_error")
            raw_error = _number(raw["raw_absolute_error"], label="raw_absolute_error")
            pairs = raw["new_concordant_pairs"]
            if (
                isinstance(pairs, bool)
                or not isinstance(pairs, int)
                or not 0 <= pairs <= len(state["confirm_progress"])
            ):
                raise ExecutorError("new_concordant_pairs exceeds available prior CONFIRM pairs")
            normalized = {
                "slot_id": raw["slot_id"], "v6_absolute_error": v6_error,
                "raw_absolute_error": raw_error,
                "new_concordant_pairs": pairs,
                "win": v6_error < raw_error - 1e-6,
            }
            self._append("CONFIRM_PROGRESS_RECORDED", {"comparison": normalized}, now)
            updated = self._state()
            comparisons = updated["confirm_progress"]
            non_wins = sum(not item["win"] for item in comparisons)
            # With n observed units, at most n * (n - 1) / 2 pairwise claims
            # are available now; the remaining pairs can contribute at most all.
            observed_pairs = sum(item["new_concordant_pairs"] for item in comparisons)
            remaining_units = 8 - len(comparisons)
            maximum_total_pairs = observed_pairs + (28 - len(comparisons) * (len(comparisons) - 1) // 2)
            if non_wins >= 2 or maximum_total_pairs < 20:
                self._terminal(updated, "CAMPAIGN_FUTILITY", "CONFIRM pass criteria are unreachable", now)
            return self.status()

    def close_campaign(self, result_receipt: object, *, now: object) -> dict[str, Any]:
        with self._journal_lock() as lock:
            del lock
            state = self._state()
            if state["state"] != "ENDPOINT_CLOSED" or state["active_unit_id"] is not None:
                raise ExecutorError("campaign cannot close with an active endpoint")
            confirm_valid = sum(
                state["units"][item]["state"] == "ENDPOINT_CLOSED"
                for item in CONFIRM_PRIMARY_IDS + (CONFIRM_RESERVE_ID,)
            )
            if confirm_valid != 8 or len(state["confirm_progress"]) != 8:
                raise ExecutorError("campaign close requires exactly eight assessed CONFIRM endpoints")
            checked = self._assert_receipt(result_receipt, label="campaign result receipt")
            verdict = checked.get("verdict")
            if verdict not in {"PASS", "FAIL", "INCONCLUSIVE", "DEV_FUTILITY"}:
                raise ExecutorError("campaign result verdict is invalid")
            self._append("CAMPAIGN_CLOSED", {"state": f"CAMPAIGN_{verdict}", "reason": "result receipt locked"}, now)
            return self.status()

    def status(self) -> dict[str, Any]:
        state = self._state()
        # Returning a JSON round-trip prevents callers mutating cached journal state.
        return json.loads(canonical_json_bytes(state))


__all__ = [
    "CALIBRATION_BUDGET", "CalibrationCampaignExecutor", "ExecutorError", "PRODUCTION_BUDGET",
    "REQUIRED_VERIFIER_PASSES", "canonical_json_bytes", "canonical_sha256",
]
