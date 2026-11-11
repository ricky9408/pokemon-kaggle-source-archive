"""Offline Package 3A evaluator-secret custody conformance.

This module models the local commit/bind/open/close/reveal protocol only.  It
does not hold an external commitment, prove evaluator custody, authenticate a
process boundary, or grant campaign authority.  In particular, every report
from this module is permanently ``NO_UPLOAD``.

The public journal is a canonical-CBOR envelope whose events form a SHA-256
hash chain.  The evaluator secret is present only in the final reveal event;
the schedule is derived from the frozen context and secret, while the
candidate/control/seat values are confined to the public run binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Final

from .canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode
from .common import freeze
from .rng_seed_protocol import (
    RNG_RUN_COMMITMENT_DOMAIN,
    RNG_SEED_PROTOCOL_SCHEMA,
    RNG_STREAM_COMMITMENT_DOMAIN,
    RNG_STREAM_ID_DOMAIN,
    RNG_STREAM_SEED_DOMAIN,
    SeedMaterial,
    derive_evaluator_secret_commitment,
    derive_schedule_context_root,
    verify_reveal_receipt,
)


NO_UPLOAD: Final = "NO_UPLOAD"
RNG_SEED_CUSTODY_SCHEMA: Final = "eval.v6.3.1.rng-seed-custody.v1"
RNG_PUBLIC_JOURNAL_SCHEMA: Final = "eval.v6.3.1.rng-seed-custody-journal.v1"

COMMIT: Final = "COMMIT"
BIND_RUN: Final = "BIND_RUN"
PRIVATE_ENGINE_OPEN: Final = "PRIVATE_ENGINE_OPEN"
RUN_CLOSE: Final = "RUN_CLOSE"
REVEAL: Final = "REVEAL"
TRANSITIONS: Final = (COMMIT, BIND_RUN, PRIVATE_ENGINE_OPEN, RUN_CLOSE, REVEAL)

INITIAL: Final = "INITIAL"
COMMITTED: Final = "COMMITTED"
BOUND: Final = "BOUND"
ENGINE_OPEN: Final = "ENGINE_OPEN"
CLOSED: Final = "CLOSED"
REVEALED: Final = "REVEALED"

_ZERO_ROOT = bytes(32)
_JOURNAL_GENESIS_DOMAIN = b"V631/RNG/CUSTODY/JOURNAL/GENESIS/V1"
_JOURNAL_EVENT_DOMAIN = b"V631/RNG/CUSTODY/JOURNAL/EVENT/V1"
_RUN_CLOSE_DOMAIN = b"V631/RNG/CUSTODY/RUN-CLOSE/V1"


class RngSeedCustodyError(ValueError):
    """A local Package 3A custody operation failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> RngSeedCustodyError:
    return RngSeedCustodyError(code, message)


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail("RNG_CUSTODY_ROOT_INVALID", f"{label} must be exactly 32 bytes")
    return value


def _secret(value: Any) -> bytes:
    value = _root(value, "evaluator_secret")
    if value == _ZERO_ROOT:
        raise _fail("RNG_CUSTODY_SECRET_INVALID", "evaluator_secret must not be all zero")
    return value


def _seed_id(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise _fail("RNG_CUSTODY_TYPE_INVALID", "common_seed_id must be a non-boolean uint16")
    return value


def _seat(value: Any) -> int:
    if type(value) is not int or value not in (0, 1):
        raise _fail("RNG_CUSTODY_TYPE_INVALID", "candidate_seat must be a non-boolean 0 or 1")
    return value


def _stream_domain(value: Any) -> str:
    if type(value) is not str or not value or value.strip() != value or not value.isascii():
        raise _fail("RNG_CUSTODY_STREAM_INVALID", "stream_domain must be non-empty canonical ASCII")
    return value


def _digest(domain: bytes, value: Any) -> bytes:
    return sha256(domain + canonical_cbor_encode(value)).digest()


def _genesis_hash() -> bytes:
    return _digest(_JOURNAL_GENESIS_DOMAIN, [RNG_PUBLIC_JOURNAL_SCHEMA, RNG_SEED_CUSTODY_SCHEMA])


def _event_hash(sequence: int, event: str, payload: list[Any], previous: bytes) -> bytes:
    return _digest(_JOURNAL_EVENT_DOMAIN, [RNG_PUBLIC_JOURNAL_SCHEMA, sequence, event, payload, previous])


def _run_commitment(
    schedule_context_root: bytes,
    evaluator_secret_commitment: bytes,
    candidate_archive_sha256: bytes,
    control_archive_sha256: bytes,
    candidate_seat: int,
) -> bytes:
    return _digest(
        RNG_RUN_COMMITMENT_DOMAIN,
        [
            RNG_SEED_PROTOCOL_SCHEMA,
            schedule_context_root,
            evaluator_secret_commitment,
            candidate_archive_sha256,
            control_archive_sha256,
            candidate_seat,
        ],
    )


def _run_close_root(run_commitment: bytes, execution_root: bytes) -> bytes:
    return _digest(_RUN_CLOSE_DOMAIN, [RNG_SEED_CUSTODY_SCHEMA, run_commitment, execution_root])


@dataclass(frozen=True, slots=True)
class PublicRunBinding:
    """The public binding; it intentionally contains no private seed value."""

    schedule_context_root: bytes
    evaluator_secret_commitment: bytes
    candidate_archive_sha256: bytes
    control_archive_sha256: bytes
    candidate_seat: int
    run_commitment: bytes


@dataclass(frozen=True, slots=True)
class JournalVerification:
    """Immutable result of checking a canonical journal prefix."""

    state: str
    event_names: tuple[str, ...]
    head_hash: bytes
    run_binding: PublicRunBinding | None


class PrivateEngineCapability:
    """One local-use capability for the private deterministic engine schedule.

    The capability deliberately has no serialization or copying protocol.  It
    can reveal derived private values to the local engine, but its repr and
    public journal representation never include them.  Python object privacy
    is not evaluator-held secrecy; that limitation is part of this contract.
    """

    __slots__ = ("_master_seed", "_run_commitment", "_active")

    def __init__(self, master_seed: bytes, run_commitment: bytes) -> None:
        self._master_seed = _root(master_seed, "master_seed")
        self._run_commitment = _root(run_commitment, "run_commitment")
        self._active = True

    def __repr__(self) -> str:
        return "PrivateEngineCapability(active=True)" if self._active else "PrivateEngineCapability(active=False)"

    def __str__(self) -> str:
        return self.__repr__()

    def __bytes__(self) -> bytes:
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "private engine capability has no byte representation")

    def __reduce__(self) -> Any:
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "private engine capability cannot be serialized")

    def __reduce_ex__(self, protocol: int) -> Any:
        del protocol
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "private engine capability cannot be serialized")

    def __copy__(self) -> Any:
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "private engine capability cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> Any:
        del memo
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "private engine capability cannot be copied")

    def _require_active(self) -> None:
        if not self._active:
            raise _fail("RNG_CUSTODY_PRIVATE_REVOKED", "private engine capability is closed")

    def _revoke(self) -> None:
        self._active = False

    def master_seed(self) -> bytes:
        self._require_active()
        return self._master_seed

    def stream_seed(self, stream_domain: str) -> bytes:
        self._require_active()
        return _digest(RNG_STREAM_SEED_DOMAIN, [self._master_seed, _stream_domain(stream_domain)])

    def stream_id(self, stream_domain: str) -> bytes:
        self._require_active()
        return _digest(RNG_STREAM_ID_DOMAIN, [self._run_commitment, _stream_domain(stream_domain)])

    def stream_seed_commitment(self, stream_domain: str) -> bytes:
        self._require_active()
        domain = _stream_domain(stream_domain)
        return _digest(
            RNG_STREAM_COMMITMENT_DOMAIN,
            [self._run_commitment, domain, self.stream_seed(domain)],
        )


class RngSeedCustodyStateMachine:
    """Strict, deterministic, zero-authority local custody state machine."""

    __slots__ = (
        "_state",
        "_protocol_root",
        "_model_root",
        "_population_root",
        "_common_seed_id",
        "_evaluator_secret",
        "_schedule_context_root",
        "_evaluator_secret_commitment",
        "_binding",
        "_events",
        "_head_hash",
        "_capability",
        "_execution_root",
    )

    def __init__(self) -> None:
        self._state = INITIAL
        self._protocol_root: bytes | None = None
        self._model_root: bytes | None = None
        self._population_root: bytes | None = None
        self._common_seed_id: int | None = None
        self._evaluator_secret: bytes | None = None
        self._schedule_context_root: bytes | None = None
        self._evaluator_secret_commitment: bytes | None = None
        self._binding: PublicRunBinding | None = None
        self._events: list[list[Any]] = []
        self._head_hash = _genesis_hash()
        self._capability: PrivateEngineCapability | None = None
        self._execution_root: bytes | None = None

    def __repr__(self) -> str:
        return f"RngSeedCustodyStateMachine(state={self._state!r}, events={len(self._events)})"

    def __getstate__(self) -> Any:
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "custody state is not serializable")

    def __reduce__(self) -> Any:
        raise _fail("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", "custody state is not serializable")

    @property
    def state(self) -> str:
        return self._state

    @property
    def schedule_context_root(self) -> bytes:
        if self._schedule_context_root is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "schedule context is not committed")
        return self._schedule_context_root

    @property
    def evaluator_secret_commitment(self) -> bytes:
        if self._evaluator_secret_commitment is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "secret commitment is not committed")
        return self._evaluator_secret_commitment

    @property
    def run_binding(self) -> PublicRunBinding:
        if self._binding is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "run is not bound")
        return self._binding

    def _require(self, expected: str) -> None:
        if self._state != expected:
            raise _fail(
                "RNG_CUSTODY_TRANSITION_INVALID",
                f"expected {expected}, current state is {self._state}",
            )

    def _append(self, event: str, payload: list[Any]) -> None:
        if event not in TRANSITIONS:
            raise _fail("RNG_CUSTODY_EVENT_INVALID", "event is outside the frozen transition set")
        sequence = len(self._events)
        event_hash = _event_hash(sequence, event, payload, self._head_hash)
        record = [RNG_PUBLIC_JOURNAL_SCHEMA, sequence, event, payload, self._head_hash, event_hash]
        self._events.append(record)
        self._head_hash = event_hash

    def commit(
        self,
        protocol_root: bytes,
        model_root: bytes,
        population_root: bytes,
        common_seed_id: int,
        evaluator_secret: bytes,
    ) -> bytes:
        """Commit the evaluator secret without putting it in the journal."""

        self._require(INITIAL)
        protocol_root = _root(protocol_root, "protocol_root")
        model_root = _root(model_root, "model_root")
        population_root = _root(population_root, "population_root")
        common_seed_id = _seed_id(common_seed_id)
        evaluator_secret = _secret(evaluator_secret)
        context = derive_schedule_context_root(protocol_root, model_root, population_root, common_seed_id)
        commitment = derive_evaluator_secret_commitment(
            evaluator_secret, protocol_root, model_root, population_root, common_seed_id
        )
        payload = [
            RNG_SEED_PROTOCOL_SCHEMA,
            protocol_root,
            model_root,
            population_root,
            common_seed_id,
            context,
            commitment,
        ]
        self._append(COMMIT, payload)
        self._protocol_root = protocol_root
        self._model_root = model_root
        self._population_root = population_root
        self._common_seed_id = common_seed_id
        self._evaluator_secret = evaluator_secret
        self._schedule_context_root = context
        self._evaluator_secret_commitment = commitment
        self._state = COMMITTED
        return commitment

    def bind_run(
        self,
        candidate_archive_sha256: bytes,
        control_archive_sha256: bytes,
        candidate_seat: int,
    ) -> PublicRunBinding:
        self._require(COMMITTED)
        candidate_archive_sha256 = _root(candidate_archive_sha256, "candidate_archive_sha256")
        control_archive_sha256 = _root(control_archive_sha256, "control_archive_sha256")
        candidate_seat = _seat(candidate_seat)
        run_commitment = _run_commitment(
            self.schedule_context_root,
            self.evaluator_secret_commitment,
            candidate_archive_sha256,
            control_archive_sha256,
            candidate_seat,
        )
        binding = PublicRunBinding(
            self.schedule_context_root,
            self.evaluator_secret_commitment,
            candidate_archive_sha256,
            control_archive_sha256,
            candidate_seat,
            run_commitment,
        )
        self._append(
            BIND_RUN,
            [
                binding.schedule_context_root,
                binding.evaluator_secret_commitment,
                binding.candidate_archive_sha256,
                binding.control_archive_sha256,
                binding.candidate_seat,
                binding.run_commitment,
            ],
        )
        self._binding = binding
        self._state = BOUND
        return binding

    def open_private_engine(self) -> PrivateEngineCapability:
        self._require(BOUND)
        if self._capability is not None:
            raise _fail("RNG_CUSTODY_ENGINE_REOPEN", "private engine capability was already opened")
        if self._protocol_root is None or self._model_root is None or self._population_root is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "committed context is incomplete")
        if self._common_seed_id is None or self._evaluator_secret is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "private seed material is incomplete")
        material = SeedMaterial(
            self._protocol_root,
            self._model_root,
            self._population_root,
            self.run_binding.candidate_archive_sha256,
            self.run_binding.control_archive_sha256,
            self._common_seed_id,
            self.run_binding.candidate_seat,
            self._evaluator_secret,
            self.evaluator_secret_commitment,
        )
        master_seed = material.master_seed()
        capability = PrivateEngineCapability(master_seed, self.run_binding.run_commitment)
        self._append(PRIVATE_ENGINE_OPEN, [self.run_binding.run_commitment])
        self._capability = capability
        self._state = ENGINE_OPEN
        return capability

    def close_run(
        self,
        run_commitment: bytes,
        execution_root: bytes = _ZERO_ROOT,
        expected_close_root: bytes | None = None,
    ) -> bytes:
        self._require(ENGINE_OPEN)
        run_commitment = _root(run_commitment, "run_commitment")
        execution_root = _root(execution_root, "execution_root")
        if run_commitment != self.run_binding.run_commitment:
            raise _fail("RNG_CUSTODY_CLOSE_MISMATCH", "RUN_CLOSE does not match the bound run")
        close_root = _run_close_root(run_commitment, execution_root)
        if expected_close_root is not None and _root(expected_close_root, "expected_close_root") != close_root:
            raise _fail("RNG_CUSTODY_CLOSE_MISMATCH", "RUN_CLOSE root does not match its bound inputs")
        self._append(RUN_CLOSE, [run_commitment, execution_root, close_root])
        self._execution_root = execution_root
        if self._capability is not None:
            self._capability._revoke()
        self._capability = None
        self._state = CLOSED
        return close_root

    def reveal(self) -> list[Any]:
        """Open the commitment only after a successful RUN_CLOSE."""

        self._require(CLOSED)
        if self._evaluator_secret is None:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "secret is unavailable for reveal")
        receipt = [
            RNG_SEED_PROTOCOL_SCHEMA,
            self.schedule_context_root,
            self.evaluator_secret_commitment,
            self._evaluator_secret,
        ]
        try:
            verify_reveal_receipt(receipt)
        except Exception as exc:
            raise _fail("RNG_CUSTODY_REVEAL_MISMATCH", "reveal does not open the committed secret") from exc
        self._append(REVEAL, [receipt])
        self._state = REVEALED
        return receipt

    def reveal_bytes(self) -> bytes:
        """Return canonical reveal bytes after ``REVEAL`` has occurred."""

        self._require(REVEALED)
        if not self._events or self._events[-1][2] != REVEAL:
            raise _fail("RNG_CUSTODY_STATE_INVALID", "reveal event is missing")
        return canonical_cbor_encode(self._events[-1][3][0])

    def journal_bytes(self) -> bytes:
        """Return the exact canonical public journal, including a prefix."""

        return canonical_cbor_encode([RNG_PUBLIC_JOURNAL_SCHEMA, self._events])

    def public_journal(self) -> bytes:
        return self.journal_bytes()

    def write_public_journal(self, path: str | Path) -> None:
        """Create a journal file once, rejecting symlinks and output reuse."""

        target = _safe_output_path(path)
        raw = self.journal_bytes()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o600)
        except OSError as exc:
            raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output is reused or unsafe") from exc
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short journal write")
                view = view[written:]
            os.fsync(fd)
        except Exception as exc:
            try:
                os.unlink(target)
            except OSError:
                pass
            if isinstance(exc, RngSeedCustodyError):
                raise
            raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output could not be written") from exc
        finally:
            os.close(fd)

    def write_journal(self, path: str | Path) -> None:
        self.write_public_journal(path)

    def zero_authority_report(self) -> MappingProxyType:
        """Return an immutable report with no campaign capability whatsoever."""

        return freeze(
            {
                "schema": RNG_SEED_CUSTODY_SCHEMA,
                "custody_state": self._state,
                "authority": NO_UPLOAD,
                "state": NO_UPLOAD,
                "calibration_upload_authorized": False,
                "production_upload_authorized": False,
                "sealed_holdout_access_authorized": False,
                "agent_modification_authorized": False,
                "permits": [],
                "holdout_accessed": False,
                "external_custody_proven": False,
                "external_publication_verified": False,
                "limitations": [
                    "Python object encapsulation does not prove evaluator-held secrecy.",
                    "Local filesystem output does not prove external publication or process custody.",
                    "This offline conformance state machine has no permit, holdout, upload, or agent authority.",
                ],
            }
        )

    def report(self) -> MappingProxyType:
        return self.zero_authority_report()


def _safe_output_path(value: str | Path) -> Path:
    target = Path(value)
    if not target.is_absolute() or target.name in ("", ".", ".."):
        raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output must be an absolute file path")
    parent = target.parent
    if not parent.is_dir() or parent.is_symlink():
        raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output parent must be an existing non-symlink directory")
    current = parent
    while current != current.parent:
        if current.is_symlink():
            raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output path contains a symlink")
        current = current.parent
    if target.exists() or target.is_symlink():
        raise _fail("RNG_CUSTODY_OUTPUT_REJECTED", "journal output cannot be reused")
    return target


def verify_public_journal(raw: bytes) -> JournalVerification:
    """Verify canonical encoding, event hashes, and the strict transition prefix."""

    try:
        parsed = canonical_cbor_decode(raw)
        if canonical_cbor_encode(parsed) != raw:
            raise _fail("RNG_CUSTODY_JOURNAL_NONCANONICAL", "journal is not canonical CBOR")
    except RngSeedCustodyError:
        raise
    except Exception as exc:
        raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "journal is not canonical CBOR") from exc
    if type(parsed) is not list or len(parsed) != 2 or parsed[0] != RNG_PUBLIC_JOURNAL_SCHEMA:
        raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "journal envelope is malformed")
    events = parsed[1]
    if type(events) is not list or len(events) > len(TRANSITIONS):
        raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "journal must contain an ordered transition prefix")

    previous = _genesis_hash()
    names: list[str] = []
    binding: PublicRunBinding | None = None
    context: tuple[bytes, bytes, bytes, int, bytes, bytes] | None = None
    for sequence, record in enumerate(events):
        if type(record) is not list or len(record) != 6:
            raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "journal event record is malformed")
        schema, actual_sequence, event, payload, actual_previous, actual_hash = record
        if schema != RNG_PUBLIC_JOURNAL_SCHEMA or actual_sequence != sequence or event != TRANSITIONS[sequence]:
            raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "journal transitions are not strict and ordered")
        if type(payload) is not list or type(actual_previous) is not bytes or type(actual_hash) is not bytes:
            raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "journal event fields are malformed")
        if actual_previous != previous:
            raise _fail("RNG_CUSTODY_HASH_CHAIN_INVALID", "journal previous hash does not match")
        expected_hash = _event_hash(sequence, event, payload, previous)
        if actual_hash != expected_hash:
            raise _fail("RNG_CUSTODY_HASH_CHAIN_INVALID", "journal event hash does not match")
        _validate_public_event(sequence, event, payload, context, binding)
        if event == COMMIT:
            context = _parse_commit_payload(payload)
        elif event == BIND_RUN:
            binding = _parse_binding_payload(payload, context)
        elif event == RUN_CLOSE:
            if binding is None:
                raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "RUN_CLOSE requires BIND_RUN")
            _parse_close_payload(payload, binding)
        elif event == REVEAL:
            if binding is None or context is None:
                raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "REVEAL requires a bound run")
            _parse_reveal_payload(payload, context)
        names.append(event)
        previous = actual_hash
    return JournalVerification(
        state=(INITIAL, COMMITTED, BOUND, ENGINE_OPEN, CLOSED, REVEALED)[len(events)],
        event_names=tuple(names),
        head_hash=previous,
        run_binding=binding,
    )


def _validate_public_event(
    sequence: int,
    event: str,
    payload: list[Any],
    context: tuple[bytes, bytes, bytes, int, bytes, bytes] | None,
    binding: PublicRunBinding | None,
) -> None:
    if sequence == 0:
        if event != COMMIT or len(payload) != 7:
            raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "COMMIT payload is malformed")
        _parse_commit_payload(payload)
    elif sequence == 1:
        if event != BIND_RUN or context is None:
            raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "BIND_RUN lacks COMMIT")
        if len(payload) != 6:
            raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "BIND_RUN payload is malformed")
    elif sequence == 2:
        if event != PRIVATE_ENGINE_OPEN or binding is None or len(payload) != 1:
            raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "PRIVATE_ENGINE_OPEN lacks BIND_RUN")
        if _root(payload[0], "run_commitment") != binding.run_commitment:
            raise _fail("RNG_CUSTODY_COMMITMENT_MISMATCH", "PRIVATE_ENGINE_OPEN does not match the bound run")
    elif sequence == 3:
        if event != RUN_CLOSE or binding is None or len(payload) != 3:
            raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "RUN_CLOSE lacks PRIVATE_ENGINE_OPEN")
        _parse_close_payload(payload, binding)
    elif sequence == 4:
        if event != REVEAL or binding is None or len(payload) != 1:
            raise _fail("RNG_CUSTODY_TRANSITION_INVALID", "REVEAL lacks RUN_CLOSE")
        _parse_reveal_payload(payload, context if context is not None else ())


def _parse_commit_payload(payload: list[Any]) -> tuple[bytes, bytes, bytes, int, bytes, bytes]:
    if len(payload) != 7 or payload[0] != RNG_SEED_PROTOCOL_SCHEMA:
        raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "COMMIT payload is malformed")
    protocol, model, population = (_root(payload[index], label) for index, label in ((1, "protocol_root"), (2, "model_root"), (3, "population_root")))
    common_seed_id = _seed_id(payload[4])
    context = _root(payload[5], "schedule_context_root")
    commitment = _root(payload[6], "evaluator_secret_commitment")
    if derive_schedule_context_root(protocol, model, population, common_seed_id) != context:
        raise _fail("RNG_CUSTODY_COMMITMENT_MISMATCH", "COMMIT context root is inconsistent")
    return protocol, model, population, common_seed_id, context, commitment


def _parse_binding_payload(
    payload: list[Any],
    context: tuple[bytes, bytes, bytes, int, bytes, bytes] | None,
) -> PublicRunBinding:
    if len(payload) != 6 or context is None:
        raise _fail("RNG_CUSTODY_JOURNAL_MALFORMED", "BIND_RUN payload is malformed")
    context_root = _root(payload[0], "schedule_context_root")
    commitment = _root(payload[1], "evaluator_secret_commitment")
    candidate = _root(payload[2], "candidate_archive_sha256")
    control = _root(payload[3], "control_archive_sha256")
    seat = _seat(payload[4])
    run = _root(payload[5], "run_commitment")
    if context_root != context[4] or commitment != context[5]:
        raise _fail("RNG_CUSTODY_COMMITMENT_MISMATCH", "BIND_RUN does not match COMMIT")
    if run != _run_commitment(context_root, commitment, candidate, control, seat):
        raise _fail("RNG_CUSTODY_COMMITMENT_MISMATCH", "run commitment is inconsistent")
    return PublicRunBinding(context_root, commitment, candidate, control, seat, run)


def _parse_close_payload(payload: list[Any], binding: PublicRunBinding) -> bytes:
    run = _root(payload[0], "run_commitment")
    execution = _root(payload[1], "execution_root")
    close = _root(payload[2], "close_root")
    if run != binding.run_commitment or close != _run_close_root(run, execution):
        raise _fail("RNG_CUSTODY_CLOSE_MISMATCH", "RUN_CLOSE does not match the bound run")
    return close


def _parse_reveal_payload(payload: list[Any], context: tuple[Any, ...]) -> None:
    if len(payload) != 1 or type(payload[0]) is not list or len(payload[0]) != 4:
        raise _fail("RNG_CUSTODY_REVEAL_INVALID", "REVEAL payload is malformed")
    receipt = payload[0]
    if not context or receipt[1] != context[4] or receipt[2] != context[5]:
        raise _fail("RNG_CUSTODY_REVEAL_MISMATCH", "REVEAL does not match COMMIT")
    try:
        verify_reveal_receipt(receipt)
    except Exception as exc:
        raise _fail("RNG_CUSTODY_REVEAL_MISMATCH", "REVEAL does not open the commitment") from exc


# Friendly aliases for callers using the shorter contract names.
RngSeedCustody = RngSeedCustodyStateMachine
SeedCustodyStateMachine = RngSeedCustodyStateMachine
PrivateEngine = PrivateEngineCapability


__all__ = [
    "BIND_RUN",
    "CLOSED",
    "COMMIT",
    "COMMITTED",
    "ENGINE_OPEN",
    "INITIAL",
    "NO_UPLOAD",
    "PRIVATE_ENGINE_OPEN",
    "REVEAL",
    "REVEALED",
    "RNG_PUBLIC_JOURNAL_SCHEMA",
    "RNG_SEED_CUSTODY_SCHEMA",
    "RUN_CLOSE",
    "TRANSITIONS",
    "BOUND",
    "JournalVerification",
    "PrivateEngine",
    "PrivateEngineCapability",
    "PublicRunBinding",
    "RngSeedCustody",
    "RngSeedCustodyError",
    "RngSeedCustodyStateMachine",
    "SeedCustodyStateMachine",
    "verify_public_journal",
]
