"""Authenticated, local-development-only batch campaign journal.

The campaign journal is a small filesystem witness for a complete batch.  It
does not grant scientific, outcome, anchor, or submission authority.  Its
one-shot rule is deliberately local to one fixed root: another root using the
same key can record the same candidate and epoch.  A campaign id still binds
the exact validated plan, so changing a plan cannot silently replace a batch
inside one root.

Only authenticated durable journal events are replayed.  A signed head may be
advanced over such events after a crash, but neither the journal nor the head
is ever rolled back or repaired from unauthenticated data.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Iterator, Mapping

try:
    import fcntl
except ImportError as exc:  # pragma: no cover - this is a Unix development journal.
    raise RuntimeError("CampaignJournal requires advisory flock support") from exc

from .witness_journal import (
    CompositionError,
    EvidenceError,
    EvidenceStore,
    JournalIntegrityError,
    TransitionError,
    WitnessJournalError,
    WitnessJournal,
    _write_atomic,
    canonical_json_bytes,
    canonical_sha256,
    sha256_bytes,
)
from .campaign_preparation import (
    CampaignPreparationError,
    validate_campaign_prepared_manifest,
)
from .parent_arm_claim import child_attempt_id as derive_child_attempt_id
from . import campaign_runtime as _campaign_runtime

try:
    from . import campaign_protocol as _campaign_protocol
except ModuleNotFoundError as exc:  # pragma: no cover - a parallel checkout may add it later.
    if exc.name != f"{__package__}.campaign_protocol":
        raise

    def validate_campaign_plan(value: object) -> Mapping[str, Any]:
        raise WitnessJournalError("evaluation_v4_2.campaign_protocol is not available")
else:

    def validate_campaign_plan(value: object) -> Mapping[str, Any]:
        # Resolve through the companion module so tests or a parallel worker
        # can replace its validator without replacing this module too.
        return _campaign_protocol.validate_campaign_plan(value)


CAMPAIGN_JOURNAL_SCHEMA = "evaluation_v4_2_campaign_journal_v2"
JOURNAL_SCHEMA = CAMPAIGN_JOURNAL_SCHEMA
HEAD_SCHEMA = "evaluation_v4_2_campaign_head_v2"
AUTHORITY = "DEVELOPMENT_ONLY"
LOCAL_DEVELOPMENT_ONLY = AUTHORITY

CLAIMED = "CLAIMED"
PREPARED = "PREPARED"
STARTED = "STARTED"
TERMINAL = "TERMINAL"
STATES = frozenset({CLAIMED, PREPARED, STARTED, TERMINAL})

SUCCESS = "SUCCESS"
FAILURE = "FAILURE"
BURN = "BURN"
VETO = "VETO"
ARM_TERMINAL_STATUSES = frozenset({SUCCESS, FAILURE, BURN})
CAMPAIGN_TERMINAL_STATUSES = frozenset({SUCCESS, VETO})
NEVER_STARTED = "NEVER_STARTED"
START_DURABLE_POPEN_UNCERTAIN = "START_DURABLE_POPEN_UNCERTAIN"
POPEN_OBSERVED = "POPEN_OBSERVED"
LAUNCH_STATES = frozenset(
    {NEVER_STARTED, START_DURABLE_POPEN_UNCERTAIN, POPEN_OBSERVED}
)
GENESIS_HASH = "0" * 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")

# These fields are intentionally closed.  The root-local one-shot marker is
# reported separately and is the only positive one-shot-related signal.
_FALSE_AUTHORITY_FIELDS: dict[str, bool] = {
    "external_authority": False,
    "remote_attestation_verified": False,
    "native_platform_verified": False,
    "latency_parity_allowed": False,
    "latency_metrics_admissible": False,
    "randomization_allowed": False,
    "global_one_shot_verified": False,
    "scientific_authority": False,
    "scientific_selector_admissible": False,
    "outcome_usable": False,
    "outcome_use_authorized": False,
    "anchor_allowed": False,
    "submission_authorized": False,
    "submit_authorized": False,
    "production_submission_authorized": False,
    "candidate_level_authority": False,
    "panel_authority": False,
}

_EVENT_FIELDS = frozenset(
    {
        "schema",
        "key_id",
        "domain",
        "root_id",
        "authority_id",
        "sequence",
        "previous_event_sha256",
        "event_type",
        "payload",
        "event_sha256",
        "hmac_sha256",
    }
)
_HEAD_FIELDS = frozenset(
    {
        "schema",
        "key_id",
        "domain",
        "root_id",
        "authority_id",
        "high_water_sequence",
        "head_event_sha256",
        "authority",
        "root_local_campaign_one_shot",
        *_FALSE_AUTHORITY_FIELDS.keys(),
        "hmac_sha256",
    }
)
_CLAIM_FIELDS = frozenset(
    {
        "campaign_id",
        "plan_sha256",
        "plan_evidence_sha256",
        "evaluation_epoch_sha256",
        "candidate_normalized_identity_sha256",
        "one_shot_key_sha256",
        "arm_witness_authority_id",
        "arm_witness_root_id",
        "allocation_ids",
        "allocation_refs",
        "scheduler_width",
        "metadata",
    }
)
_PREPARE_FIELDS = frozenset({"campaign_id", "prepared_manifest_sha256"})
_START_FIELDS = frozenset({"campaign_id", "start_evidence_sha256"})
_WAVE_FIELDS = frozenset(
    {"campaign_id", "wave", "allocation_ids", "runtime_verification_sha256"}
)
_ARM_BOUND_FIELDS = frozenset(
    {
        "campaign_id",
        "allocation_id",
        "wave",
        "child_attempt_id",
        "child_claim_sha256",
        "child_claim_event_sha256",
    }
)
ARM_BOUND_FIELDS = _ARM_BOUND_FIELDS
_ARM_FIELDS = frozenset(
    {
        "campaign_id",
        "allocation_id",
        "terminal_status",
        "launch_state",
        "terminal_evidence_sha256",
    }
)
_CAMPAIGN_TERMINAL_FIELDS = frozenset(
    {"campaign_id", "terminal_status", "terminal_evidence_sha256"}
)


# The existing witness exceptions are deliberately reused so callers can use
# one family of errors for the v4.2 local journals.
CampaignJournalError = WitnessJournalError


def _validate_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise CampaignJournalError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CampaignJournalError(f"{label} must be a non-empty trimmed string")
    if _ID_RE.fullmatch(value) is None:
        raise CampaignJournalError(f"{label} contains unsafe characters")
    return value


def _validate_int(value: object, *, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CampaignJournalError(f"{label} must be an integer >= {minimum}")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise JournalIntegrityError("JSON object contains duplicate keys")
        result[key] = value
    return result


def _parse_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n"):
        raise JournalIntegrityError(f"{label} must end with a newline")
    line = raw[:-1]
    try:
        value = json.loads(
            line.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalIntegrityError(f"{label} is not ASCII JSON: {exc}") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != line:
        raise JournalIntegrityError(f"{label} is not canonical JSON")
    return value


def _payload_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return canonical_json_bytes(value)


def _canonical_object_from_evidence(payload: bytes, *, label: str) -> object:
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalIntegrityError(f"{label} is not canonical ASCII JSON: {exc}") from exc
    if canonical_json_bytes(value) != payload:
        raise JournalIntegrityError(f"{label} is not canonical JSON")
    return value


def _deep_copy(value: object) -> Any:
    return json.loads(canonical_json_bytes(value).decode("ascii"))


class CampaignJournal:
    """A fixed-root, HMAC-authenticated batch campaign journal."""

    def __init__(
        self,
        root: str | os.PathLike[str] | None = None,
        key: bytes | bytearray | str | None = None,
        *,
        journal_root: str | os.PathLike[str] | None = None,
        hmac_key: bytes | bytearray | str | None = None,
        key_id: str = "local-development-key",
        domain: str = "evaluation_v4_2.campaign_journal",
    ):
        if root is not None and journal_root is not None:
            raise CampaignJournalError("specify root or journal_root, not both")
        if key is not None and hmac_key is not None:
            raise CampaignJournalError("specify key or hmac_key, not both")
        selected_root = journal_root if journal_root is not None else root
        selected_key = hmac_key if hmac_key is not None else key
        if selected_root is None or selected_key is None:
            raise CampaignJournalError("journal root and HMAC key are required")
        if isinstance(selected_key, str):
            selected_key = selected_key.encode("utf-8")
        if not isinstance(selected_key, (bytes, bytearray)) or not selected_key:
            raise CampaignJournalError("HMAC key must be non-empty bytes")

        self._root = Path(selected_root).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._key = bytes(selected_key)
        self._key_id = _validate_id(key_id, label="key_id")
        self._domain = _validate_id(domain, label="domain")
        self._journal_path = self._root / "journal.jsonl"
        self._head_path = self._root / "head.json"
        self._lock_path = self._root / "journal.lock"
        self._thread_lock = threading.RLock()
        self.evidence = EvidenceStore(self._root / "evidence")
        arm_key = hmac.new(
            self._key,
            b"evaluation-v4.2/campaign-owned-arm-witness-key/v1\0"
            + self._domain.encode("ascii")
            + b"\0"
            + self._key_id.encode("ascii"),
            hashlib.sha256,
        ).digest()
        self._arm_journal = WitnessJournal(
            self._root / "arm-witness",
            arm_key,
            key_id=f"{self._key_id}.arm",
            domain=f"{self._domain}.arm",
        )

    @property
    def root(self) -> Path:
        return self._root

    @property
    def authority(self) -> str:
        return AUTHORITY

    @property
    def authority_id(self) -> str:
        return self._authority_id()

    @property
    def root_id(self) -> str:
        return self._root_id()

    @property
    def arm_witness_authority_id(self) -> str:
        """Read-only identity of the campaign-owned child witness namespace."""

        return self._arm_journal.authority_id

    @property
    def arm_witness_root_id(self) -> str:
        """Read-only identity of the campaign-owned child witness namespace."""

        return self._arm_journal.root_id

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            with self._lock_path.open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _root_id(self) -> str:
        return sha256_bytes(
            b"evaluation-v4.2/campaign-root/v1\0"
            + str(self._root).encode("utf-8")
        )

    def _authority_id(self) -> str:
        return hmac.new(
            self._key,
            b"evaluation-v4.2/campaign-authority/v1\0"
            + self._domain.encode("ascii")
            + b"\0"
            + self._key_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _sign(self, kind: str, value: Mapping[str, Any]) -> str:
        message = (
            b"evaluation-v4.2/campaign-journal/v1\0"
            + self._domain.encode("ascii")
            + b"\0"
            + kind.encode("ascii")
            + b"\0"
            + canonical_json_bytes(value)
        )
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def one_shot_key(
        self,
        evaluation_epoch_sha256: str,
        candidate_normalized_identity_sha256: str,
    ) -> str:
        """Derive the root-local campaign reservation key.

        The plan hash is intentionally absent.  Therefore a changed plan for
        the same authority, epoch, and normalized candidate collides here.
        """

        epoch = _validate_sha(evaluation_epoch_sha256, label="evaluation_epoch_sha256")
        candidate = _validate_sha(
            candidate_normalized_identity_sha256,
            label="candidate_normalized_identity_sha256",
        )
        return hmac.new(
            self._key,
            b"evaluation-v4.2/campaign-one-shot/v1\0"
            + bytes.fromhex(self._authority_id())
            + bytes.fromhex(epoch)
            + bytes.fromhex(candidate),
            hashlib.sha256,
        ).hexdigest()

    campaign_one_shot_key = one_shot_key
    derive_one_shot_key = one_shot_key

    def derive_campaign_id(self, plan_sha256: str, one_shot_key_sha256: str) -> str:
        plan = _validate_sha(plan_sha256, label="plan_sha256")
        one_shot = _validate_sha(one_shot_key_sha256, label="one_shot_key_sha256")
        return hmac.new(
            self._key,
            b"evaluation-v4.2/campaign-id/v1\0"
            + bytes.fromhex(self._authority_id())
            + bytes.fromhex(one_shot)
            + bytes.fromhex(plan),
            hashlib.sha256,
        ).hexdigest()

    def _normalize_plan(self, value: object) -> dict[str, Any]:
        try:
            checked = validate_campaign_plan(value)
        except Exception as exc:
            if isinstance(exc, CampaignJournalError):
                raise
            raise CampaignJournalError(f"campaign plan is invalid: {exc}") from exc
        if not isinstance(checked, Mapping):
            raise CampaignJournalError("validated campaign plan must be an object")

        plan_sha256 = _validate_sha(checked.get("content_sha256"), label="plan content_sha256")
        candidate = checked.get("candidate_normalized_identity_sha256")
        if candidate is None:
            candidate = checked.get("candidate_normalized_policy_identity_sha256")
        candidate = _validate_sha(
            candidate,
            label="candidate_normalized_identity_sha256",
        )

        raw_allocations = checked.get("allocations")
        if not isinstance(raw_allocations, list) or not raw_allocations:
            raise CampaignJournalError("validated campaign plan allocations must be a non-empty list")
        binding = checked.get("runner_binding")
        if not isinstance(binding, Mapping):
            raise CampaignJournalError("validated campaign plan runner_binding must be an object")
        width = binding.get("scheduler_width")
        if width is None:
            width = checked.get("scheduler_width")
        width = _validate_int(width, label="runner_binding.scheduler_width", minimum=1)
        if "scheduler_width" in checked and checked["scheduler_width"] != width:
            raise CampaignJournalError("campaign scheduler_width differs from runner binding")

        refs: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_pairs: set[tuple[int, int]] = set()
        for index, raw in enumerate(raw_allocations):
            if not isinstance(raw, Mapping):
                raise CampaignJournalError(f"allocations[{index}] must be an object")
            allocation_id = _validate_id(raw.get("allocation_id"), label=f"allocations[{index}].allocation_id")
            wave = _validate_int(raw.get("wave"), label=f"allocations[{index}].wave")
            slot = _validate_int(raw.get("slot"), label=f"allocations[{index}].slot")
            if allocation_id in seen_ids:
                raise CampaignJournalError("campaign allocation ids must be unique")
            if (wave, slot) in seen_pairs:
                raise CampaignJournalError("campaign allocation wave/slot pairs must be unique")
            seen_ids.add(allocation_id)
            seen_pairs.add((wave, slot))
            refs.append({"allocation_id": allocation_id, "wave": wave, "slot": slot})

        ordered = sorted(refs, key=lambda item: (item["wave"], item["slot"]))
        if refs != ordered:
            raise CampaignJournalError("validated campaign allocations are not in canonical wave order")
        by_wave: dict[int, list[dict[str, Any]]] = {}
        for ref in refs:
            by_wave.setdefault(ref["wave"], []).append(ref)
        for wave, wave_refs in by_wave.items():
            if len(wave_refs) > width:
                raise CampaignJournalError(f"wave {wave} exceeds scheduler_width")
            if [item["slot"] for item in wave_refs] != list(range(len(wave_refs))):
                raise CampaignJournalError(f"wave {wave} slots are not canonical")

        return {
            "plan": _deep_copy(checked),
            "plan_sha256": plan_sha256,
            "candidate_normalized_identity_sha256": candidate,
            "allocation_ids": [item["allocation_id"] for item in refs],
            "allocation_refs": refs,
            "scheduler_width": width,
            "waves": {wave: [item["allocation_id"] for item in wave_refs] for wave, wave_refs in by_wave.items()},
        }

    def _epoch_from_argument(
        self,
        plan: object,
        evaluation_epoch_sha256: str | None,
        epoch_sha256: str | None,
    ) -> str:
        if evaluation_epoch_sha256 is not None and epoch_sha256 is not None:
            if evaluation_epoch_sha256 != epoch_sha256:
                raise CampaignJournalError("evaluation epoch arguments disagree")
        selected = evaluation_epoch_sha256 if evaluation_epoch_sha256 is not None else epoch_sha256
        if selected is None and isinstance(plan, Mapping):
            selected = plan.get("evaluation_epoch_sha256")
        if selected is None:
            raise CampaignJournalError("evaluation_epoch_sha256 is required")
        return _validate_sha(selected, label="evaluation_epoch_sha256")

    def _read_events(self) -> list[dict[str, Any]]:
        if not self._journal_path.exists():
            return []
        try:
            raw = self._journal_path.read_bytes()
        except OSError as exc:
            raise JournalIntegrityError(f"cannot read campaign journal: {exc}") from exc
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise JournalIntegrityError("campaign journal is truncated and has no final newline")

        events: list[dict[str, Any]] = []
        previous = GENESIS_HASH
        for sequence, line in enumerate(raw.splitlines(keepends=True)):
            event = _parse_canonical_json(line, label=f"campaign journal event {sequence}")
            if set(event) != _EVENT_FIELDS:
                raise JournalIntegrityError("campaign journal event fields are not exact")
            if event["schema"] != CAMPAIGN_JOURNAL_SCHEMA or event["key_id"] != self._key_id:
                raise JournalIntegrityError("campaign journal schema or key_id mismatch")
            if (
                event["domain"] != self._domain
                or event["root_id"] != self._root_id()
                or event["authority_id"] != self._authority_id()
                or event["sequence"] != sequence
            ):
                raise JournalIntegrityError("campaign journal root, authority, or sequence mismatch")
            _validate_sha(event["previous_event_sha256"], label="previous event hash")
            if event["previous_event_sha256"] != previous:
                raise JournalIntegrityError("campaign journal hash chain is broken")
            if not isinstance(event["event_type"], str) or not isinstance(event["payload"], dict):
                raise JournalIntegrityError("campaign journal event type or payload is invalid")
            content = {key: event[key] for key in _EVENT_FIELDS if key not in {"event_sha256", "hmac_sha256"}}
            expected_hash = sha256_bytes(canonical_json_bytes(content))
            _validate_sha(event["event_sha256"], label="event hash")
            if event["event_sha256"] != expected_hash:
                raise JournalIntegrityError("campaign journal event hash mismatch")
            signed = {key: event[key] for key in _EVENT_FIELDS if key != "hmac_sha256"}
            _validate_sha(event["hmac_sha256"], label="event HMAC")
            if not hmac.compare_digest(event["hmac_sha256"], self._sign("event", signed)):
                raise JournalIntegrityError("campaign journal event HMAC mismatch")
            previous = expected_hash
            events.append(event)
        return events

    def _head_record(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            raise JournalIntegrityError("cannot build a campaign head without events")
        content: dict[str, Any] = {
            "schema": HEAD_SCHEMA,
            "key_id": self._key_id,
            "domain": self._domain,
            "root_id": self._root_id(),
            "authority_id": self._authority_id(),
            "high_water_sequence": events[-1]["sequence"],
            "head_event_sha256": events[-1]["event_sha256"],
            "authority": AUTHORITY,
            "root_local_campaign_one_shot": True,
            **_FALSE_AUTHORITY_FIELDS,
        }
        return {**content, "hmac_sha256": self._sign("head", content)}

    def _read_head(
        self,
        events: list[dict[str, Any]],
        *,
        allow_authenticated_prefix: bool = False,
    ) -> bool:
        if not self._head_path.exists():
            if events and not allow_authenticated_prefix:
                raise JournalIntegrityError("campaign journal has events but no signed head")
            return not events
        try:
            record = _parse_canonical_json(self._head_path.read_bytes(), label="campaign head")
        except OSError as exc:
            raise JournalIntegrityError(f"cannot read campaign head: {exc}") from exc
        if set(record) != _HEAD_FIELDS:
            raise JournalIntegrityError("campaign head fields are not exact")
        if record["schema"] != HEAD_SCHEMA or record["key_id"] != self._key_id:
            raise JournalIntegrityError("campaign head schema or key_id mismatch")
        if (
            record["domain"] != self._domain
            or record["root_id"] != self._root_id()
            or record["authority_id"] != self._authority_id()
        ):
            raise JournalIntegrityError("campaign head root, domain, or authority mismatch")
        if record["authority"] != AUTHORITY or record["root_local_campaign_one_shot"] is not True:
            raise JournalIntegrityError("campaign head authority posture is not closed")
        if any(record[field] is not False for field in _FALSE_AUTHORITY_FIELDS):
            raise JournalIntegrityError("campaign head authority flags are not closed")
        content = {key: record[key] for key in _HEAD_FIELDS if key != "hmac_sha256"}
        _validate_sha(record["hmac_sha256"], label="head HMAC")
        if not hmac.compare_digest(record["hmac_sha256"], self._sign("head", content)):
            raise JournalIntegrityError("campaign head HMAC mismatch")
        if not events:
            raise JournalIntegrityError("campaign head exists without journal events")
        sequence = record["high_water_sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0 or sequence >= len(events):
            raise JournalIntegrityError("campaign head high-water sequence is invalid")
        _validate_sha(record["head_event_sha256"], label="head event hash")
        if record["head_event_sha256"] != events[sequence]["event_sha256"]:
            raise JournalIntegrityError("campaign head hash does not match the journal")
        if sequence != events[-1]["sequence"]:
            if allow_authenticated_prefix:
                return False
            raise JournalIntegrityError("campaign head high-water sequence does not match the journal")
        return True

    def _require_cas(self, digest: object, *, label: str) -> str:
        checked = _validate_sha(digest, label=label)
        try:
            self.evidence.read(checked)
        except Exception as exc:
            if isinstance(exc, JournalIntegrityError):
                raise
            raise JournalIntegrityError(f"{label} is absent or changed in the CAS") from exc
        return checked

    def _validate_allocation_refs(
        self,
        allocation_ids: object,
        allocation_refs: object,
        *,
        scheduler_width: object,
    ) -> tuple[list[str], list[dict[str, Any]], dict[int, list[str]]]:
        if not isinstance(allocation_ids, list) or not allocation_ids:
            raise JournalIntegrityError("campaign claim allocation_ids must be a non-empty list")
        if not isinstance(allocation_refs, list) or len(allocation_refs) != len(allocation_ids):
            raise JournalIntegrityError("campaign claim allocation_refs must cover allocation_ids exactly")
        width = _validate_int(scheduler_width, label="scheduler_width", minimum=1)
        ids: list[str] = []
        refs: list[dict[str, Any]] = []
        seen: set[str] = set()
        pairs: set[tuple[int, int]] = set()
        for index, raw_ref in enumerate(allocation_refs):
            if not isinstance(raw_ref, dict) or set(raw_ref) != {"allocation_id", "wave", "slot"}:
                raise JournalIntegrityError("campaign allocation reference fields are not exact")
            allocation_id = _validate_id(raw_ref["allocation_id"], label=f"allocation_refs[{index}].allocation_id")
            wave = _validate_int(raw_ref["wave"], label=f"allocation_refs[{index}].wave")
            slot = _validate_int(raw_ref["slot"], label=f"allocation_refs[{index}].slot")
            if allocation_ids[index] != allocation_id:
                raise JournalIntegrityError("campaign allocation ids and refs differ")
            if allocation_id in seen or (wave, slot) in pairs:
                raise JournalIntegrityError("campaign allocation references are duplicated")
            seen.add(allocation_id)
            pairs.add((wave, slot))
            ids.append(allocation_id)
            refs.append({"allocation_id": allocation_id, "wave": wave, "slot": slot})
        if refs != sorted(refs, key=lambda item: (item["wave"], item["slot"])):
            raise JournalIntegrityError("campaign allocation references are not in canonical order")
        by_wave: dict[int, list[str]] = {}
        for ref in refs:
            by_wave.setdefault(ref["wave"], []).append(ref["allocation_id"])
        for wave, wave_ids in by_wave.items():
            if len(wave_ids) > width:
                raise JournalIntegrityError(f"campaign wave {wave} exceeds scheduler_width")
            slots = [ref["slot"] for ref in refs if ref["wave"] == wave]
            if slots != list(range(len(wave_ids))):
                raise JournalIntegrityError(f"campaign wave {wave} slots are not canonical")
        return ids, refs, by_wave

    def _new_campaign_state(self, event: Mapping[str, Any]) -> dict[str, Any]:
        payload = event["payload"]
        if set(payload) != _CLAIM_FIELDS:
            raise JournalIntegrityError("CAMPAIGN_CLAIM payload fields are not exact")
        campaign_id = _validate_sha(payload["campaign_id"], label="campaign_id")
        plan_sha256 = _validate_sha(payload["plan_sha256"], label="plan_sha256")
        plan_evidence_sha256 = self._require_cas(
            payload["plan_evidence_sha256"], label="plan_evidence_sha256"
        )
        plan_payload = self.evidence.read(plan_evidence_sha256)
        plan_value = _canonical_object_from_evidence(plan_payload, label="campaign plan")
        normalized_plan = self._normalize_plan(plan_value)
        if normalized_plan["plan_sha256"] != plan_sha256:
            raise JournalIntegrityError("campaign plan CAS object does not match plan_sha256")
        epoch = _validate_sha(payload["evaluation_epoch_sha256"], label="evaluation_epoch_sha256")
        candidate = _validate_sha(
            payload["candidate_normalized_identity_sha256"],
            label="candidate_normalized_identity_sha256",
        )
        one_shot = _validate_sha(payload["one_shot_key_sha256"], label="one_shot_key_sha256")
        arm_authority = _validate_sha(
            payload["arm_witness_authority_id"], label="arm_witness_authority_id"
        )
        arm_root = _validate_sha(payload["arm_witness_root_id"], label="arm_witness_root_id")
        if (
            arm_authority != self._arm_journal.authority_id
            or arm_root != self._arm_journal.root_id
        ):
            raise JournalIntegrityError("campaign claim does not bind its owned arm witness namespace")
        if campaign_id != self.derive_campaign_id(plan_sha256, one_shot):
            raise JournalIntegrityError("campaign id does not bind the plan hash and one-shot key")
        expected_one_shot = self.one_shot_key(epoch, candidate)
        if one_shot != expected_one_shot:
            raise JournalIntegrityError("campaign one-shot key does not bind authority, epoch, and candidate")
        if not isinstance(payload["metadata"], dict):
            raise JournalIntegrityError("CAMPAIGN_CLAIM metadata must be an object")
        ids, refs, by_wave = self._validate_allocation_refs(
            payload["allocation_ids"],
            payload["allocation_refs"],
            scheduler_width=payload["scheduler_width"],
        )
        if (
            ids != normalized_plan["allocation_ids"]
            or refs != normalized_plan["allocation_refs"]
            or payload["scheduler_width"] != normalized_plan["scheduler_width"]
            or candidate != normalized_plan["candidate_normalized_identity_sha256"]
        ):
            raise JournalIntegrityError("CAMPAIGN_CLAIM differs from the reopened campaign plan")
        return {
            "campaign_id": campaign_id,
            "plan_sha256": plan_sha256,
            "plan_evidence_sha256": plan_evidence_sha256,
            "evaluation_epoch_sha256": epoch,
            "candidate_normalized_identity_sha256": candidate,
            "one_shot_key_sha256": one_shot,
            "arm_witness_authority_id": arm_authority,
            "arm_witness_root_id": arm_root,
            "allocation_ids": ids,
            "allocation_refs": refs,
            "scheduler_width": payload["scheduler_width"],
            "waves": by_wave,
            "child_attempt_ids": {
                allocation_id: derive_child_attempt_id(campaign_id, allocation_id)
                for allocation_id in ids
            },
            "started_waves": [],
            "current_wave": None,
            "dispositions": {},
            "state": CLAIMED,
            "prepared_manifest_sha256": None,
            "prepare_event_sha256": None,
            "start_evidence_sha256": None,
            "start_event_sha256": None,
            "wave_start_event_sha256s": {},
            "wave_runtime_verification_sha256s": {},
            "bound_arms": {},
            "arm_bound_event_sha256s": {},
            "terminal_status": None,
            "terminal_evidence_sha256": None,
            "metadata": dict(payload["metadata"]),
            "claim_event_sha256": event["event_sha256"],
        }

    @staticmethod
    def _campaign_state(campaigns: Mapping[str, dict[str, Any]], campaign_id: object) -> dict[str, Any]:
        checked = _validate_sha(campaign_id, label="campaign_id")
        state = campaigns.get(checked)
        if state is None:
            raise JournalIntegrityError("campaign event references an absent campaign")
        return state

    @staticmethod
    def _public_campaign_state(
        campaigns: Mapping[str, dict[str, Any]], campaign_id: object
    ) -> dict[str, Any]:
        try:
            return CampaignJournal._campaign_state(campaigns, campaign_id)
        except CampaignJournalError as exc:
            raise TransitionError("campaign_id is not claimed") from exc

    @staticmethod
    def _expect_state(state: Mapping[str, Any], expected: str, event_type: str) -> None:
        if state["state"] != expected:
            raise JournalIntegrityError(
                f"{event_type} requires {expected}; campaign is {state['state']}"
            )

    @staticmethod
    def _expect_public_state(state: Mapping[str, Any], expected: str, event_type: str) -> None:
        if state["state"] != expected:
            raise TransitionError(
                f"{event_type} requires {expected}; campaign is {state['state']}"
            )

    @staticmethod
    def _wave_complete(state: Mapping[str, Any], wave: int) -> bool:
        return all(item in state["dispositions"] for item in state["waves"].get(wave, []))

    @staticmethod
    def _wave_all_success(state: Mapping[str, Any], wave: int) -> bool:
        ids = state["waves"].get(wave, [])
        return bool(ids) and all(
            state["dispositions"].get(item, {}).get("terminal_status") == SUCCESS
            for item in ids
        )

    @staticmethod
    def _has_non_success(state: Mapping[str, Any]) -> bool:
        return any(
            item.get("terminal_status") != SUCCESS
            for item in state["dispositions"].values()
        )

    def _validate_prepared_manifest(
        self,
        digest: object,
        state: Mapping[str, Any],
    ) -> str:
        checked = self._require_cas(digest, label="prepared_manifest_sha256")
        payload = self.evidence.read(checked)
        value = _canonical_object_from_evidence(payload, label="prepared manifest")
        plan_payload = self.evidence.read(state["plan_evidence_sha256"])
        plan = _canonical_object_from_evidence(plan_payload, label="campaign plan")
        binding_state = {
            **state,
            "authority_id": self._authority_id(),
            "root_id": self._root_id(),
        }
        try:
            prepared = validate_campaign_prepared_manifest(value, plan, binding_state)
        except CampaignPreparationError as exc:
            raise JournalIntegrityError(f"prepared manifest is invalid: {exc}") from exc
        for index, allocation in enumerate(prepared["allocations"]):
            self._require_cas(
                allocation["snapshot_manifest_sha256"],
                label=f"prepared allocation[{index}] snapshot_manifest_sha256",
            )
        return checked

    def _validate_runtime_verification(
        self,
        digest: object,
        state: Mapping[str, Any],
        *,
        phase: str,
        wave: int | None = None,
    ) -> str:
        checked = self._require_cas(digest, label=f"{phase}_runtime_verification_sha256")
        payload = self.evidence.read(checked)
        value = _canonical_object_from_evidence(payload, label=f"{phase} runtime verification")
        plan_payload = self.evidence.read(state["plan_evidence_sha256"])
        plan = _canonical_object_from_evidence(plan_payload, label="campaign plan")
        if not isinstance(plan, Mapping) or "runner_binding" not in plan:
            raise JournalIntegrityError("campaign plan lacks a frozen runner binding")
        try:
            _campaign_runtime.validate_campaign_runtime_verification(
                value,
                runner_binding=plan["runner_binding"],
                phase=phase,
                campaign_id=state["campaign_id"],
                plan_sha256=state["plan_sha256"],
                wave=wave,
            )
        except Exception as exc:
            raise JournalIntegrityError(f"{phase} runtime verification is invalid: {exc}") from exc
        return checked

    def _validate_child_claim_event(
        self,
        *,
        child_attempt_id: object,
        child_claim_sha256: object,
        child_claim_event_sha256: object,
    ) -> tuple[str, str, str]:
        """Require a claim in the fixed private child witness namespace."""

        attempt_id = _validate_id(child_attempt_id, label="child_attempt_id")
        claim_sha256 = _validate_sha(child_claim_sha256, label="child_claim_sha256")
        event_sha256 = _validate_sha(
            child_claim_event_sha256, label="child_claim_event_sha256"
        )
        for event in self._arm_journal.events():
            if event["event_sha256"] != event_sha256:
                continue
            if event["event_type"] != "CLAIM":
                raise JournalIntegrityError("child claim event is not a child CLAIM")
            payload = event["payload"]
            if (
                payload.get("attempt_id") != attempt_id
                or payload.get("claim_sha256") != claim_sha256
            ):
                raise JournalIntegrityError("child claim event does not match ARM_BOUND")
            return attempt_id, claim_sha256, event_sha256
        raise JournalIntegrityError("child claim event is absent from the owned arm witness")

    def _replay(self, events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        campaigns: dict[str, dict[str, Any]] = {}
        one_shot_keys: set[str] = set()
        for event in events:
            event_type = event["event_type"]
            payload = event["payload"]
            if event_type == "CAMPAIGN_CLAIM":
                state = self._new_campaign_state(event)
                campaign_id = state["campaign_id"]
                if campaign_id in campaigns:
                    raise JournalIntegrityError("campaign is claimed more than once")
                if state["one_shot_key_sha256"] in one_shot_keys:
                    raise JournalIntegrityError("campaign one-shot key is duplicated in the root")
                campaigns[campaign_id] = state
                one_shot_keys.add(state["one_shot_key_sha256"])
                continue

            if not isinstance(payload, dict) or "campaign_id" not in payload:
                raise JournalIntegrityError(f"{event_type} lacks campaign_id")
            state = self._campaign_state(campaigns, payload["campaign_id"])
            campaign_id = state["campaign_id"]

            if event_type == "CAMPAIGN_PREPARE":
                if set(payload) != _PREPARE_FIELDS:
                    raise JournalIntegrityError("CAMPAIGN_PREPARE payload fields are not exact")
                self._expect_state(state, CLAIMED, event_type)
                digest = self._validate_prepared_manifest(payload["prepared_manifest_sha256"], state)
                state["prepared_manifest_sha256"] = digest
                state["prepare_event_sha256"] = event["event_sha256"]
                state["state"] = PREPARED
                continue

            if event_type == "CAMPAIGN_START":
                if set(payload) != _START_FIELDS:
                    raise JournalIntegrityError("CAMPAIGN_START payload fields are not exact")
                self._expect_state(state, PREPARED, event_type)
                digest = self._validate_runtime_verification(
                    payload["start_evidence_sha256"],
                    state,
                    phase="campaign_start",
                )
                state["start_evidence_sha256"] = digest
                state["start_event_sha256"] = event["event_sha256"]
                state["state"] = STARTED
                continue

            if event_type == "WAVE_START":
                if set(payload) != _WAVE_FIELDS:
                    raise JournalIntegrityError("WAVE_START payload fields are not exact")
                self._expect_state(state, STARTED, event_type)
                wave = _validate_int(payload["wave"], label="wave")
                expected_waves = sorted(state["waves"])
                next_index = len(state["started_waves"])
                if next_index >= len(expected_waves) or wave != expected_waves[next_index]:
                    raise JournalIntegrityError("WAVE_START is not the next canonical wave")
                if next_index:
                    previous_wave = expected_waves[next_index - 1]
                    if not self._wave_complete(state, previous_wave):
                        raise JournalIntegrityError("WAVE_START precedes terminal arms for the prior wave")
                    if not self._wave_all_success(state, previous_wave):
                        raise JournalIntegrityError("a non-successful wave prevents future waves")
                ids = state["waves"][wave]
                if payload["allocation_ids"] != ids:
                    raise JournalIntegrityError("WAVE_START allocation slice is not canonical")
                runtime_digest = self._validate_runtime_verification(
                    payload["runtime_verification_sha256"],
                    state,
                    phase="wave_start",
                    wave=wave,
                )
                state["started_waves"].append(wave)
                state["wave_start_event_sha256s"][wave] = event["event_sha256"]
                state["wave_runtime_verification_sha256s"][wave] = runtime_digest
                state["current_wave"] = wave
                continue

            if event_type == "ARM_BOUND":
                if set(payload) != _ARM_BOUND_FIELDS:
                    raise JournalIntegrityError("ARM_BOUND payload fields are not exact")
                self._expect_state(state, STARTED, event_type)
                allocation_id = _validate_id(payload["allocation_id"], label="allocation_id")
                if allocation_id not in state["allocation_ids"]:
                    raise JournalIntegrityError("ARM_BOUND references an unknown allocation")
                if allocation_id in state["bound_arms"]:
                    raise JournalIntegrityError("allocation has a duplicate ARM_BOUND")
                if allocation_id in state["dispositions"]:
                    raise JournalIntegrityError("ARM_BOUND follows a terminal disposition")
                current_wave = state["current_wave"]
                if current_wave is None:
                    raise JournalIntegrityError("ARM_BOUND precedes WAVE_START")
                ref = next(item for item in state["allocation_refs"] if item["allocation_id"] == allocation_id)
                wave = _validate_int(payload["wave"], label="wave")
                if ref["wave"] != current_wave or wave != current_wave:
                    raise JournalIntegrityError("ARM_BOUND is not in the active canonical wave")
                attempt_id, claim_sha256, claim_event_sha256 = self._validate_child_claim_event(
                    child_attempt_id=payload["child_attempt_id"],
                    child_claim_sha256=payload["child_claim_sha256"],
                    child_claim_event_sha256=payload["child_claim_event_sha256"],
                )
                if attempt_id != state["child_attempt_ids"][allocation_id]:
                    raise JournalIntegrityError("ARM_BOUND child attempt differs from the allocation")
                if any(
                    item["child_claim_event_sha256"] == claim_event_sha256
                    for item in state["bound_arms"].values()
                ):
                    raise JournalIntegrityError("ARM_BOUND reuses a child claim event")
                state["bound_arms"][allocation_id] = {
                    "campaign_id": campaign_id,
                    "allocation_id": allocation_id,
                    "wave": wave,
                    "child_attempt_id": attempt_id,
                    "child_claim_sha256": claim_sha256,
                    "child_claim_event_sha256": claim_event_sha256,
                    "event_sha256": event["event_sha256"],
                }
                state["arm_bound_event_sha256s"][allocation_id] = event["event_sha256"]
                continue

            if event_type == "ARM_TERMINAL":
                if set(payload) != _ARM_FIELDS:
                    raise JournalIntegrityError("ARM_TERMINAL payload fields are not exact")
                self._expect_state(state, STARTED, event_type)
                allocation_id = _validate_id(payload["allocation_id"], label="allocation_id")
                if allocation_id not in state["allocation_ids"]:
                    raise JournalIntegrityError("ARM_TERMINAL references an unknown allocation")
                if allocation_id in state["dispositions"]:
                    raise JournalIntegrityError("allocation has a duplicate or replacement terminal arm")
                status = payload["terminal_status"]
                if status not in ARM_TERMINAL_STATUSES:
                    raise JournalIntegrityError("ARM_TERMINAL status is invalid")
                launch_state = payload["launch_state"]
                if launch_state not in LAUNCH_STATES:
                    raise JournalIntegrityError("ARM_TERMINAL launch_state is invalid")
                digest = self._require_cas(
                    payload["terminal_evidence_sha256"],
                    label="terminal_evidence_sha256",
                )
                ref = next(item for item in state["allocation_refs"] if item["allocation_id"] == allocation_id)
                current_wave = state["current_wave"]
                if current_wave is None:
                    raise JournalIntegrityError("ARM_TERMINAL precedes WAVE_START")
                if ref["wave"] < current_wave:
                    raise JournalIntegrityError("ARM_TERMINAL arrives after a later wave started")
                if ref["wave"] > current_wave:
                    if not self._wave_complete(state, current_wave):
                        raise JournalIntegrityError("future burns require all started-wave allocations to be terminal")
                    if status != BURN or launch_state != NEVER_STARTED:
                        raise JournalIntegrityError("future allocations must be BURN with NEVER_STARTED")
                    if not self._has_non_success(state):
                        first_future = next(
                            (
                                item["allocation_id"]
                                for item in state["allocation_refs"]
                                if item["wave"] > current_wave
                                and item["allocation_id"] not in state["dispositions"]
                            ),
                            None,
                        )
                        if allocation_id != first_future:
                            raise JournalIntegrityError(
                                "recovery future burn must begin at the canonical next allocation"
                            )
                elif ref["wave"] == current_wave:
                    bound = allocation_id in state["bound_arms"]
                    if status in {SUCCESS, FAILURE}:
                        if not bound:
                            raise JournalIntegrityError("SUCCESS/FAILURE requires prior ARM_BOUND")
                        if launch_state != POPEN_OBSERVED:
                            raise JournalIntegrityError("SUCCESS/FAILURE requires POPEN_OBSERVED")
                    elif status == BURN:
                        if launch_state not in {
                            NEVER_STARTED,
                            START_DURABLE_POPEN_UNCERTAIN,
                        }:
                            raise JournalIntegrityError(
                                "active-wave BURN requires a non-observed launch state"
                            )
                        if launch_state == START_DURABLE_POPEN_UNCERTAIN and not bound:
                            raise JournalIntegrityError(
                                "START_DURABLE_POPEN_UNCERTAIN requires prior ARM_BOUND"
                            )
                else:
                    raise JournalIntegrityError("ARM_TERMINAL allocation is outside the active wave")
                state["dispositions"][allocation_id] = {
                    "allocation_id": allocation_id,
                    "wave": ref["wave"],
                    "slot": ref["slot"],
                    "terminal_status": status,
                    "launch_state": launch_state,
                    "arm_bound_event_sha256": state["arm_bound_event_sha256s"].get(allocation_id),
                    "terminal_evidence_sha256": digest,
                    "event_sha256": event["event_sha256"],
                }
                continue

            if event_type == "CAMPAIGN_TERMINAL":
                if set(payload) != _CAMPAIGN_TERMINAL_FIELDS:
                    raise JournalIntegrityError("CAMPAIGN_TERMINAL payload fields are not exact")
                status = payload["terminal_status"]
                if status not in CAMPAIGN_TERMINAL_STATUSES:
                    raise JournalIntegrityError("CAMPAIGN_TERMINAL status is invalid")
                digest = self._require_cas(
                    payload["terminal_evidence_sha256"],
                    label="campaign terminal evidence",
                )
                prelaunch = state["state"] in {CLAIMED, PREPARED} or (
                    state["state"] == STARTED and not state["started_waves"]
                )
                if prelaunch:
                    if status != VETO or state["dispositions"]:
                        raise JournalIntegrityError("prelaunch recovery must be a clean VETO")
                    for ref in state["allocation_refs"]:
                        state["dispositions"][ref["allocation_id"]] = {
                            "allocation_id": ref["allocation_id"],
                            "wave": ref["wave"],
                            "slot": ref["slot"],
                            "terminal_status": BURN,
                            "launch_state": NEVER_STARTED,
                            "terminal_evidence_sha256": digest,
                            "arm_bound_event_sha256": None,
                            "event_sha256": event["event_sha256"],
                        }
                    state["terminal_status"] = VETO
                    state["terminal_evidence_sha256"] = digest
                    state["state"] = TERMINAL
                    continue
                self._expect_state(state, STARTED, event_type)
                if len(state["dispositions"]) != len(state["allocation_ids"]):
                    raise JournalIntegrityError("CAMPAIGN_TERMINAL lacks a terminal disposition for every allocation")
                if not self._wave_complete(state, state["current_wave"]):
                    raise JournalIntegrityError("CAMPAIGN_TERMINAL lacks terminal arms for the started wave")
                for ref in state["allocation_refs"]:
                    disposition = state["dispositions"].get(ref["allocation_id"])
                    if disposition is None:
                        raise JournalIntegrityError("CAMPAIGN_TERMINAL has an incomplete allocation set")
                    if ref["wave"] > state["current_wave"] and (
                        disposition["terminal_status"] != BURN
                        or disposition["launch_state"] != NEVER_STARTED
                    ):
                        raise JournalIntegrityError("future allocations must be explicit NEVER_STARTED burns")
                all_success = all(
                    disposition["terminal_status"] == SUCCESS
                    for disposition in state["dispositions"].values()
                )
                if (status == SUCCESS) != all_success:
                    raise JournalIntegrityError("CAMPAIGN_TERMINAL SUCCESS requires complete allocation success")
                if status == VETO and all_success:
                    raise JournalIntegrityError("non-success campaign terminal requires a non-success allocation")
                state["terminal_status"] = status
                state["terminal_evidence_sha256"] = digest
                state["state"] = TERMINAL
                continue

            raise JournalIntegrityError(f"unknown campaign journal event type {event_type!r}")

        return campaigns

    def _verified_events(self) -> list[dict[str, Any]]:
        events = self._read_events()
        self._read_head(events)
        self._replay(events)
        return events

    def _summary(self, events: list[dict[str, Any]], campaigns: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": CAMPAIGN_JOURNAL_SCHEMA,
            "authority": AUTHORITY,
            "authority_id": self._authority_id(),
            "root": str(self._root),
            "sequence": events[-1]["sequence"] if events else -1,
            "head_event_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
            "events": len(events),
            "campaigns": len(campaigns),
            "root_local_campaign_one_shot": True,
            **_FALSE_AUTHORITY_FIELDS,
        }

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        events = self._verified_events()
        content: dict[str, Any] = {
            "schema": CAMPAIGN_JOURNAL_SCHEMA,
            "key_id": self._key_id,
            "domain": self._domain,
            "root_id": self._root_id(),
            "authority_id": self._authority_id(),
            "sequence": len(events),
            "previous_event_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
            "event_type": event_type,
            "payload": dict(payload),
        }
        event = {
            **content,
            "event_sha256": sha256_bytes(canonical_json_bytes(content)),
        }
        event["hmac_sha256"] = self._sign("event", event)
        with self._journal_path.open("ab") as handle:
            handle.write(canonical_json_bytes(event) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        # The event is durable before the signed high-water head advances.
        _write_atomic(self._head_path, canonical_json_bytes(self._head_record(events + [event])) + b"\n")
        return event

    def _materialize_evidence(
        self,
        value: object | None,
        *,
        digest: str | None = None,
        default: object | None = None,
    ) -> str:
        if value is None and digest is None and default is not None:
            value = default
        if digest is not None:
            _validate_sha(digest, label="evidence_sha256")
            if value is None:
                self.evidence.read(digest)
                return digest
            return self.evidence.put(value, digest=digest)
        if value is None:
            raise CampaignJournalError("evidence or evidence_sha256 is required")
        if isinstance(value, str) and _SHA256_RE.fullmatch(value):
            self.evidence.read(value)
            return value
        return self.evidence.put(value)

    @staticmethod
    def _campaign_id_argument(value: object) -> str:
        if isinstance(value, Mapping):
            payload = value.get("payload")
            if isinstance(payload, Mapping):
                value = payload.get("campaign_id")
            else:
                value = value.get("campaign_id")
        return _validate_sha(value, label="campaign_id")

    def claim_campaign(
        self,
        plan: object,
        evaluation_epoch_sha256: str | None = None,
        *,
        epoch_sha256: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically reserve a complete validated batch allocation list."""

        normalized = self._normalize_plan(plan)
        epoch = self._epoch_from_argument(plan, evaluation_epoch_sha256, epoch_sha256)
        one_shot = self.one_shot_key(epoch, normalized["candidate_normalized_identity_sha256"])
        campaign_id = self.derive_campaign_id(normalized["plan_sha256"], one_shot)
        plan_evidence_sha256 = self.evidence.put(normalized["plan"])
        if metadata is not None and not isinstance(metadata, Mapping):
            raise CampaignJournalError("metadata must be an object")
        frozen_metadata = dict(metadata or {})
        if {
            "campaign_id",
            "plan_sha256",
            "plan_evidence_sha256",
            "evaluation_epoch_sha256",
            "candidate_normalized_identity_sha256",
            "one_shot_key_sha256",
            "allocation_ids",
        } & frozen_metadata.keys():
            raise CampaignJournalError("metadata may not override campaign identity or allocation fields")
        if set(frozen_metadata) & (set(_FALSE_AUTHORITY_FIELDS) | {"root_local_campaign_one_shot"}):
            raise CampaignJournalError("metadata may not carry authority or one-shot posture fields")
        payload = {
            "campaign_id": campaign_id,
            "plan_sha256": normalized["plan_sha256"],
            "plan_evidence_sha256": plan_evidence_sha256,
            "evaluation_epoch_sha256": epoch,
            "candidate_normalized_identity_sha256": normalized["candidate_normalized_identity_sha256"],
            "one_shot_key_sha256": one_shot,
            "arm_witness_authority_id": self.arm_witness_authority_id,
            "arm_witness_root_id": self.arm_witness_root_id,
            "allocation_ids": normalized["allocation_ids"],
            "allocation_refs": normalized["allocation_refs"],
            "scheduler_width": normalized["scheduler_width"],
            "metadata": frozen_metadata,
        }
        with self._locked():
            events = self._verified_events()
            campaigns = self._replay(events)
            if one_shot in {item["one_shot_key_sha256"] for item in campaigns.values()}:
                raise TransitionError("one-shot key is already claimed in this witness root")
            if campaign_id in campaigns:
                raise TransitionError("campaign_id is already claimed; retries are forbidden")
            return self._append_event("CAMPAIGN_CLAIM", payload)

    def campaign_id_for_plan(
        self,
        plan: object,
        evaluation_epoch_sha256: str,
    ) -> str:
        normalized = self._normalize_plan(plan)
        epoch = _validate_sha(evaluation_epoch_sha256, label="evaluation_epoch_sha256")
        one_shot = self.one_shot_key(epoch, normalized["candidate_normalized_identity_sha256"])
        return self.derive_campaign_id(normalized["plan_sha256"], one_shot)

    def prepare_campaign(
        self,
        campaign_id: object,
        prepared_manifest: object | None = None,
        *,
        manifest: object | None = None,
        prepared_manifest_sha256: str | None = None,
        manifest_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Durably reference one exact complete prepared manifest in the CAS."""

        campaign = self._campaign_id_argument(campaign_id)
        if prepared_manifest is not None and manifest is not None:
            raise CampaignJournalError("specify prepared_manifest or manifest, not both")
        value = prepared_manifest if prepared_manifest is not None else manifest
        selected_digest = prepared_manifest_sha256 if prepared_manifest_sha256 is not None else manifest_sha256
        if prepared_manifest_sha256 is not None and manifest_sha256 is not None and prepared_manifest_sha256 != manifest_sha256:
            raise CampaignJournalError("prepared manifest digest arguments disagree")
        digest = self._materialize_evidence(value, digest=selected_digest)
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, CLAIMED, "CAMPAIGN_PREPARE")
            checked = self._validate_prepared_manifest(digest, state)
            return self._append_event(
                "CAMPAIGN_PREPARE",
                {"campaign_id": campaign, "prepared_manifest_sha256": checked},
            )

    def start_campaign(
        self,
        campaign_id: object,
        evidence: object | None = None,
        *,
        evidence_sha256: str | None = None,
        start_evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Make CAMPAIGN_START durable before any WAVE_START event is allowed."""

        campaign = self._campaign_id_argument(campaign_id)
        if evidence_sha256 is not None and start_evidence_sha256 is not None and evidence_sha256 != start_evidence_sha256:
            raise CampaignJournalError("start evidence digest arguments disagree")
        digest_arg = evidence_sha256 if evidence_sha256 is not None else start_evidence_sha256
        digest = self._materialize_evidence(evidence, digest=digest_arg)
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, PREPARED, "CAMPAIGN_START")
            checked_digest = self._validate_runtime_verification(
                digest,
                state,
                phase="campaign_start",
            )
            return self._append_event(
                "CAMPAIGN_START",
                {"campaign_id": campaign, "start_evidence_sha256": checked_digest},
            )

    def start_wave(
        self,
        campaign_id: object,
        wave: object,
        allocation_ids: object | None = None,
        *,
        allocations: object | None = None,
        allocation_slice: object | None = None,
        runtime_verification: object | None = None,
        runtime_verification_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Start the next complete canonical wave allocation slice."""

        campaign = self._campaign_id_argument(campaign_id)
        checked_wave = _validate_int(wave, label="wave")
        supplied = [item is not None for item in (allocation_ids, allocations, allocation_slice)]
        if sum(supplied) > 1:
            raise CampaignJournalError("specify one allocation slice argument")
        selected = next(
            (item for item in (allocation_ids, allocations, allocation_slice) if item is not None),
            None,
        )
        runtime_digest = self._materialize_evidence(
            runtime_verification,
            digest=runtime_verification_sha256,
        )
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, STARTED, "WAVE_START")
            expected_waves = sorted(state["waves"])
            next_index = len(state["started_waves"])
            if next_index >= len(expected_waves) or checked_wave != expected_waves[next_index]:
                raise TransitionError("WAVE_START must follow canonical wave order")
            if next_index:
                previous_wave = expected_waves[next_index - 1]
                if not self._wave_complete(state, previous_wave):
                    raise TransitionError("WAVE_START requires terminal arms for the prior wave")
                if not self._wave_all_success(state, previous_wave):
                    raise TransitionError("a non-successful wave prevents future waves")
            expected_ids = state["waves"][checked_wave]
            if selected is None:
                checked_ids = list(expected_ids)
            elif isinstance(selected, (list, tuple)):
                checked_ids = []
                for index, entry in enumerate(selected):
                    if isinstance(entry, Mapping):
                        entry = entry.get("allocation_id")
                    checked_ids.append(_validate_id(entry, label=f"allocation_ids[{index}]"))
            else:
                raise TransitionError("WAVE_START allocation_ids must be the complete canonical list")
            if checked_ids != expected_ids:
                raise TransitionError("WAVE_START allocation slice is not the exact canonical wave")
            checked_runtime_digest = self._validate_runtime_verification(
                runtime_digest,
                state,
                phase="wave_start",
                wave=checked_wave,
            )
            return self._append_event(
                "WAVE_START",
                {
                    "campaign_id": campaign,
                    "wave": checked_wave,
                    "allocation_ids": checked_ids,
                    "runtime_verification_sha256": checked_runtime_digest,
                },
            )

    def bind_arm(
        self,
        campaign_id: object,
        allocation_id: object,
        child_attempt_id: object,
        child_claim_sha256: object,
        child_claim_event_sha256: object,
        *,
        wave: object | None = None,
    ) -> dict[str, Any]:
        """Bind one active allocation to one immutable child witness claim."""

        campaign = self._campaign_id_argument(campaign_id)
        checked_allocation_id = _validate_id(allocation_id, label="allocation_id")
        checked_attempt_id = _validate_id(child_attempt_id, label="child_attempt_id")
        checked_claim_sha256 = _validate_sha(child_claim_sha256, label="child_claim_sha256")
        checked_event_sha256 = _validate_sha(
            child_claim_event_sha256, label="child_claim_event_sha256"
        )
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, STARTED, "ARM_BOUND")
            current_wave = state["current_wave"]
            if current_wave is None:
                raise TransitionError("ARM_BOUND requires a started wave")
            if checked_allocation_id not in state["allocation_ids"]:
                raise TransitionError("allocation_id is not in the claimed batch")
            ref = next(
                item for item in state["allocation_refs"] if item["allocation_id"] == checked_allocation_id
            )
            if ref["wave"] != current_wave:
                raise TransitionError("ARM_BOUND allocation is not in the active wave")
            checked_wave = current_wave if wave is None else _validate_int(wave, label="wave")
            if checked_wave != current_wave:
                raise TransitionError("ARM_BOUND wave must equal the active wave")
            if checked_allocation_id in state["bound_arms"]:
                raise TransitionError("allocation already has an ARM_BOUND event; retries are forbidden")
            if checked_allocation_id in state["dispositions"]:
                raise TransitionError("allocation already has a terminal disposition")
            if checked_attempt_id != state["child_attempt_ids"][checked_allocation_id]:
                raise TransitionError("child_attempt_id differs from the claimed allocation")
            try:
                self._validate_child_claim_event(
                    child_attempt_id=checked_attempt_id,
                    child_claim_sha256=checked_claim_sha256,
                    child_claim_event_sha256=checked_event_sha256,
                )
            except JournalIntegrityError as exc:
                raise TransitionError(str(exc)) from exc
            return self._append_event(
                "ARM_BOUND",
                {
                    "campaign_id": campaign,
                    "allocation_id": checked_allocation_id,
                    "wave": checked_wave,
                    "child_attempt_id": checked_attempt_id,
                    "child_claim_sha256": checked_claim_sha256,
                    "child_claim_event_sha256": checked_event_sha256,
                },
            )

    bind_child_arm = bind_arm

    def terminal_arm(
        self,
        campaign_id: object,
        allocation_id: object,
        terminal_status: str | None = None,
        launch_state: str | None = None,
        evidence: object | None = None,
        *,
        status: str | None = None,
        terminal_evidence: object | None = None,
        evidence_sha256: str | None = None,
        terminal_evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Record exactly one terminal disposition for one allocation."""

        campaign = self._campaign_id_argument(campaign_id)
        if terminal_status is not None and status is not None and terminal_status != status:
            raise CampaignJournalError("terminal status arguments disagree")
        checked_status = terminal_status if terminal_status is not None else status
        if checked_status not in ARM_TERMINAL_STATUSES:
            raise TransitionError("terminal_status must be SUCCESS, FAILURE, or BURN")
        if launch_state not in LAUNCH_STATES:
            raise TransitionError(f"launch_state must be one of {sorted(LAUNCH_STATES)}")
        if evidence is not None and terminal_evidence is not None:
            raise CampaignJournalError("specify evidence or terminal_evidence, not both")
        selected_evidence = evidence if evidence is not None else terminal_evidence
        if evidence_sha256 is not None and terminal_evidence_sha256 is not None and evidence_sha256 != terminal_evidence_sha256:
            raise CampaignJournalError("terminal evidence digest arguments disagree")
        digest_arg = evidence_sha256 if evidence_sha256 is not None else terminal_evidence_sha256
        checked_allocation_id = _validate_id(allocation_id, label="allocation_id")
        default_evidence = {
            "campaign_id": campaign,
            "allocation_id": checked_allocation_id,
            "terminal_status": checked_status,
            "launch_state": launch_state,
        }
        digest = self._materialize_evidence(selected_evidence, digest=digest_arg, default=default_evidence)
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, STARTED, "ARM_TERMINAL")
            if checked_allocation_id not in state["allocation_ids"]:
                raise TransitionError("allocation_id is not in the claimed batch")
            if checked_allocation_id in state["dispositions"]:
                raise TransitionError("allocation already has a terminal arm; replacement is forbidden")
            current_wave = state["current_wave"]
            if current_wave is None:
                raise TransitionError("ARM_TERMINAL requires a started wave")
            ref = next(item for item in state["allocation_refs"] if item["allocation_id"] == checked_allocation_id)
            if ref["wave"] < current_wave:
                raise TransitionError("allocation belongs to a previous terminal wave")
            if ref["wave"] > current_wave:
                if not self._wave_complete(state, current_wave):
                    raise TransitionError("future burns require every started-wave allocation to be terminal")
                if checked_status != BURN or launch_state != NEVER_STARTED:
                    raise TransitionError("future allocations must be BURN with NEVER_STARTED")
                if not self._has_non_success(state):
                    first_future = next(
                        (
                            item["allocation_id"]
                            for item in state["allocation_refs"]
                            if item["wave"] > current_wave
                            and item["allocation_id"] not in state["dispositions"]
                        ),
                        None,
                    )
                    if checked_allocation_id != first_future:
                        raise TransitionError(
                            "recovery future burn must begin at the canonical next allocation"
                        )
            elif ref["wave"] == current_wave:
                bound = checked_allocation_id in state["bound_arms"]
                if checked_status in {SUCCESS, FAILURE}:
                    if not bound:
                        raise TransitionError("SUCCESS/FAILURE requires prior ARM_BOUND")
                    if launch_state != POPEN_OBSERVED:
                        raise TransitionError("SUCCESS/FAILURE requires POPEN_OBSERVED")
                elif checked_status == BURN:
                    if launch_state not in {
                        NEVER_STARTED,
                        START_DURABLE_POPEN_UNCERTAIN,
                    }:
                        raise TransitionError(
                            "active-wave BURN requires a non-observed launch state"
                        )
                    if launch_state == START_DURABLE_POPEN_UNCERTAIN and not bound:
                        raise TransitionError(
                            "START_DURABLE_POPEN_UNCERTAIN requires prior ARM_BOUND"
                        )
            else:
                raise TransitionError("allocation belongs to a previous terminal wave")
            return self._append_event(
                "ARM_TERMINAL",
                {
                    "campaign_id": campaign,
                    "allocation_id": checked_allocation_id,
                    "terminal_status": checked_status,
                    "launch_state": launch_state,
                    "terminal_evidence_sha256": digest,
                },
            )

    def terminal_campaign(
        self,
        campaign_id: object,
        terminal_status: str | None = None,
        evidence: object | None = None,
        *,
        status: str | None = None,
        terminal_evidence: object | None = None,
        evidence_sha256: str | None = None,
        terminal_evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Close a wave-started campaign as SUCCESS or VETO."""

        campaign = self._campaign_id_argument(campaign_id)
        if terminal_status is not None and status is not None and terminal_status != status:
            raise CampaignJournalError("terminal status arguments disagree")
        checked_status = terminal_status if terminal_status is not None else status
        if checked_status not in CAMPAIGN_TERMINAL_STATUSES:
            raise TransitionError("campaign terminal status must be SUCCESS or VETO")
        if evidence is not None and terminal_evidence is not None:
            raise CampaignJournalError("specify evidence or terminal_evidence, not both")
        selected_evidence = evidence if evidence is not None else terminal_evidence
        if evidence_sha256 is not None and terminal_evidence_sha256 is not None and evidence_sha256 != terminal_evidence_sha256:
            raise CampaignJournalError("campaign terminal evidence digest arguments disagree")
        digest_arg = evidence_sha256 if evidence_sha256 is not None else terminal_evidence_sha256
        default_evidence = {"campaign_id": campaign, "terminal_status": checked_status}
        digest = self._materialize_evidence(selected_evidence, digest=digest_arg, default=default_evidence)
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            self._expect_public_state(state, STARTED, "CAMPAIGN_TERMINAL")
            if not state["started_waves"]:
                raise TransitionError("prelaunch VETO requires veto_prelaunch")
            if len(state["dispositions"]) != len(state["allocation_ids"]):
                raise TransitionError("CAMPAIGN_TERMINAL requires a disposition for every allocation")
            if not self._wave_complete(state, state["current_wave"]):
                raise TransitionError("CAMPAIGN_TERMINAL requires all started-wave allocations to be terminal")
            all_success = all(
                item["terminal_status"] == SUCCESS for item in state["dispositions"].values()
            )
            if (checked_status == SUCCESS) != all_success:
                raise TransitionError("SUCCESS is allowed only when every allocation is SUCCESS")
            if checked_status == VETO and all_success:
                raise TransitionError("VETO requires a non-success allocation")
            for ref in state["allocation_refs"]:
                disposition = state["dispositions"].get(ref["allocation_id"])
                if disposition is None:
                    raise TransitionError("CAMPAIGN_TERMINAL has an incomplete allocation set")
                if ref["wave"] > state["current_wave"] and (
                    disposition["terminal_status"] != BURN
                    or disposition["launch_state"] != NEVER_STARTED
                ):
                    raise TransitionError("future allocations must be explicit BURN with NEVER_STARTED")
            return self._append_event(
                "CAMPAIGN_TERMINAL",
                {
                    "campaign_id": campaign,
                    "terminal_status": checked_status,
                    "terminal_evidence_sha256": digest,
                },
            )

    def veto_prelaunch(
        self,
        campaign_id: object,
        evidence: object | None = None,
        *,
        terminal_evidence: object | None = None,
        evidence_sha256: str | None = None,
        terminal_evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Fail closed before a wave: consume the campaign as all-never-started burns."""

        campaign = self._campaign_id_argument(campaign_id)
        if evidence is not None and terminal_evidence is not None:
            raise CampaignJournalError("specify evidence or terminal_evidence, not both")
        if (
            evidence_sha256 is not None
            and terminal_evidence_sha256 is not None
            and evidence_sha256 != terminal_evidence_sha256
        ):
            raise CampaignJournalError("campaign terminal evidence digest arguments disagree")
        selected_evidence = evidence if evidence is not None else terminal_evidence
        digest_arg = (
            evidence_sha256 if evidence_sha256 is not None else terminal_evidence_sha256
        )
        digest = self._materialize_evidence(
            selected_evidence,
            digest=digest_arg,
            default={"campaign_id": campaign, "terminal_status": VETO, "prelaunch": True},
        )
        with self._locked():
            events = self._verified_events()
            state = self._public_campaign_state(self._replay(events), campaign)
            prelaunch = state["state"] in {CLAIMED, PREPARED} or (
                state["state"] == STARTED and not state["started_waves"]
            )
            if not prelaunch:
                raise TransitionError("veto_prelaunch requires CLAIMED, PREPARED, or STARTED-before-wave")
            return self._append_event(
                "CAMPAIGN_TERMINAL",
                {
                    "campaign_id": campaign,
                    "terminal_status": VETO,
                    "terminal_evidence_sha256": digest,
                },
            )

    recover_prelaunch_veto = veto_prelaunch
    recover_and_veto_prelaunch = veto_prelaunch

    def _public_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        allocation_states: list[dict[str, Any]] = []
        for ref in state["allocation_refs"]:
            disposition = state["dispositions"].get(ref["allocation_id"])
            allocation_states.append(
                {
                    **ref,
                    "terminal_status": disposition["terminal_status"] if disposition else None,
                    "launch_state": disposition["launch_state"] if disposition else None,
                    "terminal_evidence_sha256": disposition["terminal_evidence_sha256"] if disposition else None,
                    "arm_bound_event_sha256": disposition["arm_bound_event_sha256"] if disposition else None,
                }
            )
        waves = [
            {
                "wave": wave,
                "allocation_ids": list(state["waves"][wave]),
                "started": wave in state["started_waves"],
                "complete": self._wave_complete(state, wave),
                "all_success": self._wave_all_success(state, wave),
            }
            for wave in sorted(state["waves"])
        ]
        dispositions = {
            allocation_id: dict(value)
            for allocation_id, value in state["dispositions"].items()
        }
        return {
            "schema": CAMPAIGN_JOURNAL_SCHEMA,
            "authority": AUTHORITY,
            "authority_id": self._authority_id(),
            "root": str(self._root),
            "root_id": self._root_id(),
            "campaign_id": state["campaign_id"],
            "plan_sha256": state["plan_sha256"],
            "plan_evidence_sha256": state["plan_evidence_sha256"],
            "evaluation_epoch_sha256": state["evaluation_epoch_sha256"],
            "candidate_normalized_identity_sha256": state["candidate_normalized_identity_sha256"],
            "one_shot_key_sha256": state["one_shot_key_sha256"],
            "claim_event_sha256": state["claim_event_sha256"],
            "arm_witness_authority_id": state["arm_witness_authority_id"],
            "arm_witness_root_id": state["arm_witness_root_id"],
            "allocation_ids": list(state["allocation_ids"]),
            "allocation_refs": _deep_copy(state["allocation_refs"]),
            "allocation_states": allocation_states,
            "dispositions": dispositions,
            "scheduler_width": state["scheduler_width"],
            "waves": waves,
            "started_waves": list(state["started_waves"]),
            "current_wave": state["current_wave"],
            "state": state["state"],
            "prepared_manifest_sha256": state["prepared_manifest_sha256"],
            "prepare_event_sha256": state["prepare_event_sha256"],
            "start_evidence_sha256": state["start_evidence_sha256"],
            "start_event_sha256": state["start_event_sha256"],
            "wave_start_event_sha256s": {
                str(wave): digest
                for wave, digest in sorted(state["wave_start_event_sha256s"].items())
            },
            "wave_runtime_verification_sha256s": {
                str(wave): digest
                for wave, digest in sorted(state["wave_runtime_verification_sha256s"].items())
            },
            "arm_bound_event_sha256s": {
                allocation_id: digest
                for allocation_id, digest in sorted(state["arm_bound_event_sha256s"].items())
            },
            "bound_arms": _deep_copy(state["bound_arms"]),
            "terminal_status": state["terminal_status"],
            "terminal_evidence_sha256": state["terminal_evidence_sha256"],
            "metadata": _deep_copy(state["metadata"]),
            "root_local_campaign_one_shot": True,
            **_FALSE_AUTHORITY_FIELDS,
        }

    def state(self, campaign_id: object) -> dict[str, Any]:
        campaign = self._campaign_id_argument(campaign_id)
        with self._locked():
            events = self._verified_events()
            state = self._campaign_state(self._replay(events), campaign)
            return _deep_copy(self._public_state(state))

    def read_campaign_plan(self, campaign_id: object) -> dict[str, Any]:
        """Reopen and revalidate the exact plan referenced by CAMPAIGN_CLAIM."""

        state = self.state(campaign_id)
        payload = self.read_evidence(state["plan_evidence_sha256"])
        value = _canonical_object_from_evidence(payload, label="campaign plan")
        normalized = self._normalize_plan(value)
        if (
            normalized["plan_sha256"] != state["plan_sha256"]
            or normalized["candidate_normalized_identity_sha256"]
            != state["candidate_normalized_identity_sha256"]
            or normalized["allocation_ids"] != state["allocation_ids"]
            or normalized["allocation_refs"] != state["allocation_refs"]
        ):
            raise CompositionError("reopened campaign plan differs from CAMPAIGN_CLAIM")
        return _deep_copy(normalized["plan"])

    def read_evidence(self, evidence_sha256: str) -> bytes:
        """Read a CAS object after rehash verification."""

        return self.evidence.read(_validate_sha(evidence_sha256, label="evidence_sha256"))

    def read_terminal_evidence(self, campaign_id: object, allocation_id: object) -> bytes:
        campaign = self._campaign_id_argument(campaign_id)
        checked_allocation_id = _validate_id(allocation_id, label="allocation_id")
        state = self.state(campaign)
        disposition = state["dispositions"].get(checked_allocation_id)
        if disposition is None:
            raise CompositionError("allocation has no terminal evidence")
        return self.read_evidence(disposition["terminal_evidence_sha256"])

    def events(self) -> list[dict[str, Any]]:
        with self._locked():
            return _deep_copy(self._verified_events())

    def verify(self) -> dict[str, Any]:
        """Strictly verify the authenticated chain, head, CAS, and state machine."""

        with self._locked():
            events = self._verified_events()
            campaigns = self._replay(events)
            return self._summary(events, campaigns)

    def recover(self) -> dict[str, Any]:
        """Advance a valid signed head over authenticated durable events only."""

        with self._locked():
            events = self._read_events()
            exact = self._read_head(events, allow_authenticated_prefix=True)
            campaigns = self._replay(events)
            if events and not exact:
                _write_atomic(self._head_path, canonical_json_bytes(self._head_record(events)) + b"\n")
                self._read_head(events)
            return self._summary(events, campaigns)


__all__ = [
    "AUTHORITY",
    "ARM_BOUND_FIELDS",
    "ARM_TERMINAL_STATUSES",
    "BURN",
    "CAMPAIGN_JOURNAL_SCHEMA",
    "CAMPAIGN_TERMINAL_STATUSES",
    "CLAIMED",
    "CampaignJournal",
    "CampaignJournalError",
    "CompositionError",
    "EvidenceError",
    "EvidenceStore",
    "FAILURE",
    "GENESIS_HASH",
    "HEAD_SCHEMA",
    "JournalIntegrityError",
    "LAUNCH_STATES",
    "LOCAL_DEVELOPMENT_ONLY",
    "NEVER_STARTED",
    "POPEN_OBSERVED",
    "PREPARED",
    "STARTED",
    "STATES",
    "START_DURABLE_POPEN_UNCERTAIN",
    "SUCCESS",
    "TERMINAL",
    "TransitionError",
    "VETO",
    "canonical_json_bytes",
    "canonical_sha256",
    "sha256_bytes",
]
