"""Seat-neutral commit/reveal seed protocol for the Package 3A RNG gateway.

The random schedule is derived only from an evaluator-held secret and the
frozen evaluation context. Candidate/control archives and seat remain bound in
the public run commitment, but cannot perturb the schedule. This is required
for common-random-number comparisons across candidates and seat swaps.

This module is local conformance code. It does not prove secret custody,
independent commitment publication, or hosted parity, and grants no authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from .canonical_trace_codec import canonical_cbor_encode


RNG_SEED_PROTOCOL_SCHEMA = "eval.v6.3.1.rng-seed-protocol.v2"
RNG_SCHEDULE_CONTEXT_DOMAIN = b"V631/RNG/SCHEDULE-CONTEXT/V2"
RNG_SECRET_COMMITMENT_DOMAIN = b"V631/RNG/SECRET-COMMITMENT/V2"
RNG_MASTER_SEED_DOMAIN = b"V631/RNG/MASTER-SEED/V2"
RNG_RUN_COMMITMENT_DOMAIN = b"V631/RNG/RUN-COMMITMENT/V2"
RNG_STREAM_SEED_DOMAIN = b"V631/RNG/STREAM-SEED/V2"
RNG_STREAM_ID_DOMAIN = b"V631/RNG/STREAM-ID/V2"
RNG_STREAM_COMMITMENT_DOMAIN = b"V631/RNG/STREAM-COMMITMENT/V2"

UINT16_MAX = (1 << 16) - 1


class RngSeedProtocolError(ValueError):
    """A Package 3A seed-protocol input failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> RngSeedProtocolError:
    return RngSeedProtocolError(code, message)


def _root(value: Any, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise _fail("RNG_SEED_ROOT_INVALID", f"{label} must be exactly 32 bytes")
    return value


def _secret(value: Any) -> bytes:
    secret = _root(value, "evaluator_secret")
    if secret == bytes(32):
        raise _fail("RNG_SEED_SECRET_INVALID", "evaluator_secret must not be the all-zero test value")
    return secret


def _u16(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= UINT16_MAX:
        raise _fail("RNG_SEED_TYPE_INVALID", f"{label} must be a non-boolean uint16")
    return value


def _seat(value: Any) -> int:
    if type(value) is not int or value not in (0, 1):
        raise _fail("RNG_SEED_TYPE_INVALID", "candidate_seat must be a non-boolean 0 or 1")
    return value


def _stream_domain(value: Any) -> str:
    if type(value) is not str or not value or value.strip() != value or not value.isascii():
        raise _fail("RNG_SEED_STREAM_INVALID", "stream_domain must be non-empty canonical ASCII")
    return value


def _digest(domain: bytes, payload: Any) -> bytes:
    return sha256(domain + canonical_cbor_encode(payload)).digest()


def schedule_context_payload(
    protocol_root: bytes,
    model_root: bytes,
    population_root: bytes,
    common_seed_id: int,
) -> list[Any]:
    """Return the frozen, seat-neutral random-schedule transcript."""

    return [
        RNG_SEED_PROTOCOL_SCHEMA,
        _root(protocol_root, "protocol_root"),
        _root(model_root, "model_root"),
        _root(population_root, "population_root"),
        _u16(common_seed_id, "common_seed_id"),
    ]


def derive_schedule_context_root(
    protocol_root: bytes,
    model_root: bytes,
    population_root: bytes,
    common_seed_id: int,
) -> bytes:
    return _digest(
        RNG_SCHEDULE_CONTEXT_DOMAIN,
        schedule_context_payload(protocol_root, model_root, population_root, common_seed_id),
    )


def derive_evaluator_secret_commitment(
    evaluator_secret: bytes,
    protocol_root: bytes,
    model_root: bytes,
    population_root: bytes,
    common_seed_id: int,
) -> bytes:
    context = derive_schedule_context_root(protocol_root, model_root, population_root, common_seed_id)
    return _digest(RNG_SECRET_COMMITMENT_DOMAIN, [context, _secret(evaluator_secret)])


@dataclass(frozen=True, slots=True)
class SeedMaterial:
    """Complete private seed envelope plus its public run binding.

    ``evaluator_secret`` must remain evaluator-private until the run's
    preregistered reveal point. ``sanitized_receipt`` deliberately omits it.
    """

    protocol_root: bytes
    model_root: bytes
    population_root: bytes
    candidate_archive_sha256: bytes
    control_archive_sha256: bytes
    common_seed_id: int
    candidate_seat: int
    evaluator_secret: bytes
    evaluator_secret_commitment: bytes

    def __post_init__(self) -> None:
        for name in (
            "protocol_root",
            "model_root",
            "population_root",
            "candidate_archive_sha256",
            "control_archive_sha256",
        ):
            _root(getattr(self, name), name)
        _u16(self.common_seed_id, "common_seed_id")
        _seat(self.candidate_seat)
        _secret(self.evaluator_secret)
        supplied = _root(self.evaluator_secret_commitment, "evaluator_secret_commitment")
        if supplied != self.expected_evaluator_secret_commitment():
            raise _fail(
                "RNG_SEED_COMMITMENT_MISMATCH",
                "evaluator_secret does not open evaluator_secret_commitment",
            )

    def schedule_context_payload(self) -> list[Any]:
        return schedule_context_payload(
            self.protocol_root,
            self.model_root,
            self.population_root,
            self.common_seed_id,
        )

    def schedule_context_root(self) -> bytes:
        return _digest(RNG_SCHEDULE_CONTEXT_DOMAIN, self.schedule_context_payload())

    def expected_evaluator_secret_commitment(self) -> bytes:
        return _digest(
            RNG_SECRET_COMMITMENT_DOMAIN,
            [self.schedule_context_root(), self.evaluator_secret],
        )

    def master_seed(self) -> bytes:
        """Private, seat-neutral CRN schedule seed."""

        return _digest(
            RNG_MASTER_SEED_DOMAIN,
            [self.schedule_context_root(), self.evaluator_secret],
        )

    def run_commitment_payload(self) -> list[Any]:
        """Public artifact/seat binding that does not perturb ``master_seed``."""

        return [
            RNG_SEED_PROTOCOL_SCHEMA,
            self.schedule_context_root(),
            self.evaluator_secret_commitment,
            self.candidate_archive_sha256,
            self.control_archive_sha256,
            self.candidate_seat,
        ]

    def run_commitment(self) -> bytes:
        return _digest(RNG_RUN_COMMITMENT_DOMAIN, self.run_commitment_payload())

    def stream_seed(self, stream_domain: str) -> bytes:
        return _digest(
            RNG_STREAM_SEED_DOMAIN,
            [self.master_seed(), _stream_domain(stream_domain)],
        )

    def stream_id(self, stream_domain: str) -> bytes:
        return _digest(
            RNG_STREAM_ID_DOMAIN,
            [self.run_commitment(), _stream_domain(stream_domain)],
        )

    def stream_seed_commitment(self, stream_domain: str) -> bytes:
        return _digest(
            RNG_STREAM_COMMITMENT_DOMAIN,
            [
                self.run_commitment(),
                _stream_domain(stream_domain),
                self.stream_seed(stream_domain),
            ],
        )

    def seed_material_root(self) -> bytes:
        """Root the public seed receipt without exposing the secret."""

        return _digest(RNG_RUN_COMMITMENT_DOMAIN, self.sanitized_receipt())

    def sanitized_receipt(self) -> list[Any]:
        return [
            RNG_SEED_PROTOCOL_SCHEMA,
            self.schedule_context_payload(),
            self.schedule_context_root(),
            self.evaluator_secret_commitment,
            self.run_commitment_payload(),
            self.run_commitment(),
            "EVALUATOR_SECRET_WITHHELD_UNTIL_PREREGISTERED_REVEAL",
        ]

    def reveal_receipt(self) -> list[Any]:
        """Return the post-run opening; callers control release timing."""

        return [
            RNG_SEED_PROTOCOL_SCHEMA,
            self.schedule_context_root(),
            self.evaluator_secret_commitment,
            self.evaluator_secret,
        ]


def verify_reveal_receipt(value: Any) -> None:
    if type(value) is not list or len(value) != 4 or value[0] != RNG_SEED_PROTOCOL_SCHEMA:
        raise _fail("RNG_SEED_REVEAL_INVALID", "seed reveal receipt is malformed")
    context = _root(value[1], "schedule_context_root")
    commitment = _root(value[2], "evaluator_secret_commitment")
    secret = _secret(value[3])
    if commitment != _digest(RNG_SECRET_COMMITMENT_DOMAIN, [context, secret]):
        raise _fail("RNG_SEED_COMMITMENT_MISMATCH", "seed reveal does not open its commitment")


__all__ = [
    "RNG_MASTER_SEED_DOMAIN",
    "RNG_RUN_COMMITMENT_DOMAIN",
    "RNG_SCHEDULE_CONTEXT_DOMAIN",
    "RNG_SECRET_COMMITMENT_DOMAIN",
    "RNG_SEED_PROTOCOL_SCHEMA",
    "RNG_STREAM_COMMITMENT_DOMAIN",
    "RNG_STREAM_ID_DOMAIN",
    "RNG_STREAM_SEED_DOMAIN",
    "RngSeedProtocolError",
    "SeedMaterial",
    "derive_evaluator_secret_commitment",
    "derive_schedule_context_root",
    "schedule_context_payload",
    "verify_reveal_receipt",
]

