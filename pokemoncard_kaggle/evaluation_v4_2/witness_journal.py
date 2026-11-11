"""A local, authenticated, one-shot attempt witness for evaluation v4.2.

This module is deliberately a development witness, not an attestation system.
It protects against accidental races, edits, truncation, and receipt
substitution while the journal and its high-water record remain available.
Malicious control of the host or storage, including rollback of both records,
is outside the TCB and is not prevented.

The caller's artifact directory is never a journal namespace.  The resolved
journal directory captured by :class:`WitnessJournal` is the only namespace;
therefore claim hashes are unique across every client using that root.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Iterator, Mapping

try:
    import fcntl
except ImportError as exc:  # pragma: no cover - this is a Unix development witness.
    raise RuntimeError("WitnessJournal requires advisory flock support") from exc


JOURNAL_SCHEMA = "evaluation_v4_2_witness_journal_v1"
HEAD_SCHEMA = "evaluation_v4_2_witness_head_v1"
EVIDENCE_SCHEMA = "evaluation_v4_2_witness_evidence_v1"
AUTHORITY = "LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY"
LOCAL_TRUSTED_WITNESS_DEVELOPMENT_ONLY = AUTHORITY

CLAIMED = "CLAIMED"
PREPARED = "PREPARED"
STARTED = "STARTED"
TERMINAL = "TERMINAL"
STATES = frozenset({CLAIMED, PREPARED, STARTED, TERMINAL})
TERMINAL_STATUSES = frozenset({"SUCCESS", "FAILURE", "BURN"})
GENESIS_HASH = "0" * 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GENERIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:/+-]+$")
_FALSE_AUTHORITY_FIELDS = {
    "external_authority": False,
    "remote_attestation_verified": False,
    "native_platform_verified": False,
    "latency_parity_allowed": False,
    "latency_metrics_admissible": False,
    "randomization_allowed": False,
    "submit_authorized": False,
    "anchor_allowed": False,
    "production_submission_authorized": False,
}


class WitnessJournalError(ValueError):
    """Base error for malformed, unauthenticated, or illegal journal data."""


class JournalIntegrityError(WitnessJournalError):
    """The append log or signed high-water record cannot be verified."""


class TransitionError(WitnessJournalError):
    """An attempt transition violates the retry-free state machine."""


class EvidenceError(WitnessJournalError):
    """Evidence is missing, changed, or cannot be immutably installed."""


class CompositionError(WitnessJournalError):
    """A terminal attempt cannot be composed from journaled evidence."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole canonical ASCII JSON encoding used by this module."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise WitnessJournalError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise WitnessJournalError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise WitnessJournalError(f"{label} must be a non-empty trimmed string")
    if _GENERIC_ID_RE.fullmatch(value) is None:
        raise WitnessJournalError(f"{label} contains unsafe characters")
    return value


def _payload_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return canonical_json_bytes(value)


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
        text = line.decode("ascii")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalIntegrityError(f"{label} is not ASCII JSON: {exc}") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != line:
        raise JournalIntegrityError(f"{label} is not canonical JSON")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_atomic(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class EvidenceStore:
    """Immutable SHA-256 content-addressed bytes below one journal root."""

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        _validate_sha(digest, label="evidence digest")
        return self.root / digest

    def put(self, content: object, *, digest: str | None = None) -> str:
        payload = _payload_bytes(content)
        actual = sha256_bytes(payload)
        if digest is not None and _validate_sha(digest, label="evidence digest") != actual:
            raise EvidenceError("evidence digest does not match bytes")
        path = self._path(actual)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{actual}.",
            suffix=".tmp",
            dir=self.root,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fchmod(handle.fileno(), 0o400)
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                try:
                    existing = path.read_bytes()
                except OSError as exc:
                    raise EvidenceError(f"cannot read existing evidence: {exc}") from exc
                if sha256_bytes(existing) != actual or existing != payload:
                    raise EvidenceError("content-addressed evidence was changed")
            else:
                _fsync_directory(self.root)
        finally:
            if descriptor != -1:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return actual

    def read(self, digest: str) -> bytes:
        path = self._path(digest)
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise EvidenceError(f"evidence {digest} is absent: {exc}") from exc
        if sha256_bytes(payload) != digest:
            raise EvidenceError(f"evidence {digest} failed rehash verification")
        return payload

    def contains(self, digest: str) -> bool:
        try:
            self.read(digest)
        except EvidenceError:
            return False
        return True


class WitnessJournal:
    """Authenticated append-only journal with a fixed root and fixed key domain."""

    def __init__(
        self,
        root: str | os.PathLike[str] | None = None,
        key: bytes | bytearray | str | None = None,
        *,
        journal_root: str | os.PathLike[str] | None = None,
        hmac_key: bytes | bytearray | str | None = None,
        key_id: str = "local-development-key",
        domain: str = "evaluation_v4_2.witness_journal",
    ):
        if root is not None and journal_root is not None:
            raise WitnessJournalError("specify root or journal_root, not both")
        if key is not None and hmac_key is not None:
            raise WitnessJournalError("specify key or hmac_key, not both")
        selected_root = journal_root if journal_root is not None else root
        selected_key = hmac_key if hmac_key is not None else key
        if selected_root is None or selected_key is None:
            raise WitnessJournalError("journal root and HMAC key are required")
        if isinstance(selected_key, str):
            selected_key = selected_key.encode("utf-8")
        if not isinstance(selected_key, (bytes, bytearray)) or not selected_key:
            raise WitnessJournalError("HMAC key must be non-empty bytes")
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

    @property
    def root(self) -> Path:
        """The immutable journal root captured at construction time."""

        return self._root

    @property
    def authority(self) -> str:
        return AUTHORITY

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._thread_lock:
            with self._lock_path.open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _sign(self, kind: str, value: Mapping[str, Any]) -> str:
        message = (
            b"evaluation-v4.2/witness-journal/v1\0"
            + self._domain.encode("utf-8")
            + b"\0"
            + kind.encode("ascii")
            + b"\0"
            + canonical_json_bytes(value)
        )
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def _root_id(self) -> str:
        return hashlib.sha256(
            b"evaluation-v4.2/witness-root/v1\0" + str(self._root).encode("utf-8")
        ).hexdigest()

    def _authority_id(self) -> str:
        return hmac.new(
            self._key,
            b"evaluation-v4.2/witness-authority/v1\0"
            + self._domain.encode("utf-8")
            + b"\0"
            + self._key_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @property
    def authority_id(self) -> str:
        """Pseudonymous identifier for this witness key and domain."""

        return self._authority_id()

    @property
    def root_id(self) -> str:
        """Path-bound identifier for this exact local witness root."""

        return self._root_id()

    def one_shot_key(self, campaign_sha256: str, candidate_identity_sha256: str) -> str:
        """Derive the path-independent scientific claim identity."""

        campaign = _validate_sha(campaign_sha256, label="campaign_sha256")
        candidate = _validate_sha(
            candidate_identity_sha256,
            label="candidate_identity_sha256",
        )
        return hashlib.sha256(
            b"evaluation-v4.2/one-shot-claim/v1\0"
            + bytes.fromhex(self._authority_id())
            + bytes.fromhex(campaign)
            + bytes.fromhex(candidate)
        ).hexdigest()

    def _read_events(self) -> list[dict[str, Any]]:
        if not self._journal_path.exists():
            return []
        try:
            raw = self._journal_path.read_bytes()
        except OSError as exc:
            raise JournalIntegrityError(f"cannot read journal: {exc}") from exc
        if not raw:
            return []
        if not raw.endswith(b"\n"):
            raise JournalIntegrityError("journal is truncated and has no final newline")
        events: list[dict[str, Any]] = []
        previous = GENESIS_HASH
        for sequence, line in enumerate(raw.splitlines(keepends=True)):
            event = _parse_canonical_json(line, label=f"journal event {sequence}")
            required = {
                "schema", "key_id", "domain", "root_id", "authority_id",
                "sequence", "previous_event_sha256",
                "event_type", "payload", "event_sha256", "hmac_sha256",
            }
            if set(event) != required:
                raise JournalIntegrityError("journal event fields are not exact")
            if event["schema"] != JOURNAL_SCHEMA or event["key_id"] != self._key_id:
                raise JournalIntegrityError("journal schema or key_id mismatch")
            if (
                event["domain"] != self._domain
                or event["root_id"] != self._root_id()
                or event["authority_id"] != self._authority_id()
                or event["sequence"] != sequence
            ):
                raise JournalIntegrityError("journal sequence or domain mismatch")
            _validate_sha(event["previous_event_sha256"], label="previous event hash")
            if event["previous_event_sha256"] != previous:
                raise JournalIntegrityError("journal hash chain is broken")
            if not isinstance(event["payload"], dict):
                raise JournalIntegrityError("journal payload must be an object")
            content = {key: event[key] for key in required if key not in {"event_sha256", "hmac_sha256"}}
            event_hash = sha256_bytes(canonical_json_bytes(content))
            _validate_sha(event["event_sha256"], label="event hash")
            if event["event_sha256"] != event_hash:
                raise JournalIntegrityError("journal event hash mismatch")
            signed = {key: event[key] for key in required if key != "hmac_sha256"}
            expected_hmac = self._sign("event", signed)
            _validate_sha(event["hmac_sha256"], label="event HMAC")
            if not hmac.compare_digest(str(event["hmac_sha256"]), expected_hmac):
                raise JournalIntegrityError("journal event HMAC mismatch")
            previous = event_hash
            events.append(event)
        return events

    def _head_record(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            raise JournalIntegrityError("cannot build a high-water record without events")
        content: dict[str, Any] = {
            "schema": HEAD_SCHEMA,
            "key_id": self._key_id,
            "domain": self._domain,
            "root_id": self._root_id(),
            "authority_id": self._authority_id(),
            "high_water_sequence": events[-1]["sequence"],
            "head_event_sha256": events[-1]["event_sha256"],
            "authority": AUTHORITY,
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
            if events:
                if allow_authenticated_prefix:
                    return False
                raise JournalIntegrityError("journal has events but no signed high-water record")
            return True
        try:
            record = _parse_canonical_json(self._head_path.read_bytes(), label="head record")
        except OSError as exc:
            raise JournalIntegrityError(f"cannot read head record: {exc}") from exc
        required = {
            "schema", "key_id", "domain", "root_id", "authority_id",
            "high_water_sequence",
            "head_event_sha256", "authority", * _FALSE_AUTHORITY_FIELDS.keys(), "hmac_sha256",
        }
        if set(record) != required:
            raise JournalIntegrityError("head record fields are not exact")
        if record["schema"] != HEAD_SCHEMA or record["key_id"] != self._key_id:
            raise JournalIntegrityError("head schema or key_id mismatch")
        if (
            record["domain"] != self._domain
            or record["root_id"] != self._root_id()
            or record["authority_id"] != self._authority_id()
        ):
            raise JournalIntegrityError("head domain or root mismatch")
        if record["authority"] != AUTHORITY or any(
            record[field] is not False for field in _FALSE_AUTHORITY_FIELDS
        ):
            raise JournalIntegrityError("head authority flags are not closed")
        content = {key: record[key] for key in required if key != "hmac_sha256"}
        _validate_sha(record["hmac_sha256"], label="head HMAC")
        if not hmac.compare_digest(str(record["hmac_sha256"]), self._sign("head", content)):
            raise JournalIntegrityError("head HMAC mismatch")
        sequence = record["high_water_sequence"]
        if (
            not events
            or isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            or sequence >= len(events)
        ):
            raise JournalIntegrityError("head high-water sequence does not match journal")
        _validate_sha(record["head_event_sha256"], label="head event hash")
        if record["head_event_sha256"] != events[sequence]["event_sha256"]:
            raise JournalIntegrityError("head hash does not match journal")
        if sequence != events[-1]["sequence"]:
            if allow_authenticated_prefix:
                return False
            raise JournalIntegrityError("head high-water sequence does not match journal")
        return True

    def _verified_events(self) -> list[dict[str, Any]]:
        events = self._read_events()
        self._read_head(events)
        self._attempts(events)
        return events

    def verify(self) -> dict[str, Any]:
        """Strictly verify the chain and head; never roll either one backward."""

        with self._locked():
            events = self._verified_events()
        return {
            "schema": JOURNAL_SCHEMA,
            "authority": AUTHORITY,
            "authority_id": self._authority_id(),
            "root_id": self._root_id(),
            "root": str(self._root),
            "sequence": events[-1]["sequence"] if events else -1,
            "head_event_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
            "events": len(events),
            **_FALSE_AUTHORITY_FIELDS,
        }

    def recover(self) -> dict[str, Any]:
        """Advance a valid signed head over authenticated durable journal events."""

        with self._locked():
            events = self._read_events()
            exact = self._read_head(events, allow_authenticated_prefix=True)
            self._attempts(events)
            if events and not exact:
                _write_atomic(
                    self._head_path,
                    canonical_json_bytes(self._head_record(events)) + b"\n",
                )
                self._read_head(events)
        return {
            "schema": JOURNAL_SCHEMA,
            "authority": AUTHORITY,
            "authority_id": self._authority_id(),
            "root_id": self._root_id(),
            "root": str(self._root),
            "sequence": events[-1]["sequence"] if events else -1,
            "head_event_sha256": events[-1]["event_sha256"] if events else GENESIS_HASH,
            "events": len(events),
            **_FALSE_AUTHORITY_FIELDS,
        }

    def _append_event(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        events = self._verified_events()
        sequence = len(events)
        content: dict[str, Any] = {
            "schema": JOURNAL_SCHEMA,
            "key_id": self._key_id,
            "domain": self._domain,
            "root_id": self._root_id(),
            "authority_id": self._authority_id(),
            "sequence": sequence,
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
        # The journal is durable before the signed high-water advances.
        _write_atomic(self._head_path, canonical_json_bytes(self._head_record(events + [event])) + b"\n")
        return event

    def _attempts(self, events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        attempts: dict[str, dict[str, Any]] = {}
        for event in events:
            payload = event["payload"]
            attempt_id = payload.get("attempt_id")
            if not isinstance(attempt_id, str):
                raise JournalIntegrityError("attempt event lacks attempt_id")
            state = attempts.get(attempt_id)
            if event["event_type"] == "CLAIM":
                if state is not None:
                    raise JournalIntegrityError("attempt is claimed more than once")
                if set(payload) != {
                    "attempt_id",
                    "claim_sha256",
                    "one_shot_key_sha256",
                    "metadata",
                }:
                    raise JournalIntegrityError("CLAIM payload fields are not exact")
                _validate_id(attempt_id, label="attempt_id")
                _validate_sha(payload.get("claim_sha256"), label="claim_sha256")
                _validate_sha(
                    payload.get("one_shot_key_sha256"),
                    label="one_shot_key_sha256",
                )
                if not isinstance(payload.get("metadata"), dict):
                    raise JournalIntegrityError("CLAIM metadata must be an object")
                attempts[attempt_id] = {
                    "attempt_id": attempt_id,
                    "claim_sha256": payload.get("claim_sha256"),
                    "one_shot_key_sha256": payload.get("one_shot_key_sha256"),
                    "state": CLAIMED,
                    "terminal_status": None,
                    "evidence_sha256": None,
                    "prepared_evidence_sha256": None,
                    "started_evidence_sha256": None,
                    "claim_event_sha256": event["event_sha256"],
                }
                continue
            if state is None:
                raise JournalIntegrityError("attempt transition precedes CLAIM")
            expected = {"PREPARE": (CLAIMED, PREPARED), "START": (PREPARED, STARTED), "TERMINAL": (STARTED, TERMINAL)}
            if event["event_type"] not in expected:
                raise JournalIntegrityError("unknown journal event type")
            expected_payload_fields = {"attempt_id", "evidence_sha256"}
            if event["event_type"] == "TERMINAL":
                expected_payload_fields |= {"terminal_status"}
            if set(payload) != expected_payload_fields:
                raise JournalIntegrityError("transition payload fields are not exact")
            before, after = expected[event["event_type"]]
            if state["state"] != before:
                raise JournalIntegrityError("journal contains an illegal state transition")
            digest = payload.get("evidence_sha256")
            if digest is not None:
                _validate_sha(digest, label="evidence_sha256")
            if event["event_type"] == "PREPARE":
                state["prepared_evidence_sha256"] = digest
            elif event["event_type"] == "START":
                state["started_evidence_sha256"] = digest
            elif event["event_type"] == "TERMINAL":
                if payload.get("terminal_status") not in TERMINAL_STATUSES:
                    raise JournalIntegrityError("terminal status is invalid")
                state["terminal_status"] = payload.get("terminal_status")
                state["evidence_sha256"] = digest
                state["terminal_event_sha256"] = event["event_sha256"]
            state["state"] = after
        one_shot_keys = [item["one_shot_key_sha256"] for item in attempts.values()]
        if len(one_shot_keys) != len(set(one_shot_keys)):
            raise JournalIntegrityError("one_shot_key_sha256 is duplicated in the witness root")
        return attempts

    def claim(
        self,
        attempt_id: str,
        claim_sha256: str | None = None,
        *,
        claim: object | None = None,
        one_shot_key_sha256: str | None = None,
        artifact_root: str | os.PathLike[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record a unique claim.  ``artifact_root`` is intentionally non-authoritative."""

        _validate_id(attempt_id, label="attempt_id")
        if claim_sha256 is None:
            if claim is None:
                raise WitnessJournalError("claim_sha256 or claim is required")
            claim_sha256 = sha256_bytes(_payload_bytes(claim)) if isinstance(claim, (bytes, bytearray)) else canonical_sha256(claim)
        _validate_sha(claim_sha256, label="claim_sha256")
        if one_shot_key_sha256 is None:
            one_shot_key_sha256 = claim_sha256
        _validate_sha(one_shot_key_sha256, label="one_shot_key_sha256")
        if metadata is not None and not isinstance(metadata, Mapping):
            raise WitnessJournalError("metadata must be an object")
        payload = {
            "attempt_id": attempt_id,
            "claim_sha256": claim_sha256,
            "one_shot_key_sha256": one_shot_key_sha256,
            "metadata": dict(metadata or {}),
        }
        with self._locked():
            events = self._verified_events()
            attempts = self._attempts(events)
            if attempt_id in attempts:
                raise TransitionError("attempt_id is already claimed; retries are forbidden")
            for item in attempts.values():
                if item["one_shot_key_sha256"] == one_shot_key_sha256:
                    raise TransitionError("one-shot key is already claimed in this witness root")
            return self._append_event("CLAIM", payload)

    def claim_plan(
        self,
        campaign_sha256: str,
        candidate_archive_sha256: str,
        *,
        claim: object,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Claim one authority/campaign/candidate tuple with a witness ID."""

        one_shot_key = self.one_shot_key(campaign_sha256, candidate_archive_sha256)
        attempt_id = hmac.new(
            self._key,
            b"evaluation-v4.2/attempt-id/v1\0" + bytes.fromhex(one_shot_key),
            hashlib.sha256,
        ).hexdigest()
        claim_sha256 = canonical_sha256(claim)
        caller_metadata = dict(metadata or {})
        if {"campaign_sha256", "candidate_archive_sha256"} & caller_metadata.keys():
            raise WitnessJournalError("metadata may not override one-shot identity fields")
        frozen_metadata = {
            **caller_metadata,
            "campaign_sha256": _validate_sha(campaign_sha256, label="campaign_sha256"),
            "candidate_archive_sha256": _validate_sha(
                candidate_archive_sha256,
                label="candidate_archive_sha256",
            ),
        }
        return self.claim(
            attempt_id,
            claim_sha256,
            one_shot_key_sha256=one_shot_key,
            metadata=frozen_metadata,
        )

    def _transition(
        self,
        attempt_id: str,
        event_type: str,
        expected: str,
        evidence: object | None = None,
        *,
        evidence_sha256: str | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_id(attempt_id, label="attempt_id")
        digest: str | None = None
        if evidence is not None:
            digest = self.evidence.put(evidence, digest=evidence_sha256)
        elif evidence_sha256 is not None:
            self.evidence.read(_validate_sha(evidence_sha256, label="evidence_sha256"))
            digest = evidence_sha256
        with self._locked():
            events = self._verified_events()
            state = self._attempts(events).get(attempt_id)
            if state is None:
                raise TransitionError("attempt_id is not claimed")
            if state["state"] != expected:
                raise TransitionError(f"{event_type} requires {expected}; attempt is {state['state']}")
            return self._append_event(
                event_type,
                {
                    "attempt_id": attempt_id,
                    "evidence_sha256": digest,
                    **dict(payload or {}),
                },
            )

    def prepare(
        self,
        attempt_id: str,
        evidence: object | None = None,
        *,
        evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._transition(
            attempt_id,
            "PREPARE",
            CLAIMED,
            evidence,
            evidence_sha256=evidence_sha256,
        )

    def start(
        self,
        attempt_id: str,
        evidence: object | None = None,
        *,
        evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._transition(
            attempt_id,
            "START",
            PREPARED,
            evidence,
            evidence_sha256=evidence_sha256,
        )

    def terminal(
        self,
        attempt_id: str,
        terminal_status: str,
        evidence: object | None = None,
        *,
        evidence_sha256: str | None = None,
    ) -> dict[str, Any]:
        if terminal_status not in TERMINAL_STATUSES:
            raise TransitionError(f"terminal_status must be one of {sorted(TERMINAL_STATUSES)}")
        _validate_id(attempt_id, label="attempt_id")
        # Evidence is installed before taking the journal lock/event path.  If
        # the process dies after this write, the digest is an unreachable orphan.
        digest: str | None = None
        if evidence is not None:
            digest = self.evidence.put(evidence, digest=evidence_sha256)
        elif evidence_sha256 is not None:
            _validate_sha(evidence_sha256, label="evidence_sha256")
            self.evidence.read(evidence_sha256)
            digest = evidence_sha256
        with self._locked():
            events = self._verified_events()
            state = self._attempts(events).get(attempt_id)
            if state is None:
                raise TransitionError("attempt_id is not claimed")
            if state["state"] != STARTED:
                raise TransitionError(f"TERMINAL requires STARTED; attempt is {state['state']}")
            return self._append_event(
                "TERMINAL",
                {"attempt_id": attempt_id, "terminal_status": terminal_status, "evidence_sha256": digest},
            )

    complete = terminal
    finish = terminal

    def state(self, attempt_id: str) -> dict[str, Any]:
        _validate_id(attempt_id, label="attempt_id")
        with self._locked():
            events = self._verified_events()
            state = self._attempts(events).get(attempt_id)
        if state is None:
            raise WitnessJournalError("attempt_id is absent")
        return dict(state)

    def events(self) -> list[dict[str, Any]]:
        with self._locked():
            return list(self._verified_events())

    def read_terminal_evidence(self, attempt_id: str) -> bytes:
        """Resolve evidence only through a terminal journal event and its digest."""

        state = self.state(attempt_id)
        if state["state"] != TERMINAL:
            raise CompositionError("attempt is not terminal")
        digest = state["evidence_sha256"]
        if not isinstance(digest, str):
            raise CompositionError("terminal attempt has no journaled evidence digest")
        return self.evidence.read(digest)

    def compose_attempt(self, attempt_id: str) -> dict[str, Any]:
        state = self.state(attempt_id)
        payload = self.read_terminal_evidence(attempt_id)
        try:
            evidence: object = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            evidence = payload
        return {
            "schema": EVIDENCE_SCHEMA,
            "authority": AUTHORITY,
            "authority_id": self._authority_id(),
            "root_id": self._root_id(),
            "attempt_id": state["attempt_id"],
            "claim_sha256": state["claim_sha256"],
            "one_shot_key_sha256": state["one_shot_key_sha256"],
            "prepared_evidence_sha256": state["prepared_evidence_sha256"],
            "started_evidence_sha256": state["started_evidence_sha256"],
            "terminal_status": state["terminal_status"],
            "terminal_event_sha256": state["terminal_event_sha256"],
            "evidence_sha256": state["evidence_sha256"],
            "evidence": evidence,
            **_FALSE_AUTHORITY_FIELDS,
        }

    compose = compose_attempt


def compose_terminal_evidence(journal: WitnessJournal, attempt_id: str, receipt: object | None = None) -> dict[str, Any]:
    """Compatibility function that explicitly refuses caller-supplied receipts."""

    if receipt is not None:
        raise CompositionError("caller receipt objects are not admissible")
    return journal.compose_attempt(attempt_id)


__all__ = [
    "AUTHORITY", "CLAIMED", "PREPARED", "STARTED", "TERMINAL", "STATES",
    "TERMINAL_STATUSES", "JOURNAL_SCHEMA", "HEAD_SCHEMA", "EVIDENCE_SCHEMA",
    "WitnessJournal", "EvidenceStore", "WitnessJournalError", "JournalIntegrityError",
    "TransitionError", "EvidenceError", "CompositionError", "canonical_json_bytes",
    "canonical_sha256", "sha256_bytes", "compose_terminal_evidence",
]
