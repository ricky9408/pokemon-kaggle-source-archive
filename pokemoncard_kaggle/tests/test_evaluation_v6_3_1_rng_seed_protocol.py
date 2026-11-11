from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from evaluation_v6_3_1.rng_seed_protocol import (
    RngSeedProtocolError,
    SeedMaterial,
    derive_evaluator_secret_commitment,
    verify_reveal_receipt,
)


def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _material(
    *,
    candidate: str = "candidate-a",
    control: str = "control-a",
    seat: int = 0,
    secret: bytes | None = None,
) -> SeedMaterial:
    secret = _root("evaluator-secret") if secret is None else secret
    protocol = _root("protocol")
    model = _root("model")
    population = _root("population")
    commitment = derive_evaluator_secret_commitment(secret, protocol, model, population, 17)
    return SeedMaterial(
        protocol,
        model,
        population,
        _root(candidate),
        _root(control),
        17,
        seat,
        secret,
        commitment,
    )


def test_schedule_is_secret_and_seat_neutral_while_run_binding_changes() -> None:
    first = _material(candidate="candidate-a", control="control-a", seat=0)
    second = _material(candidate="candidate-b", control="control-b", seat=1)

    assert first.schedule_context_root() == second.schedule_context_root()
    assert first.master_seed() == second.master_seed()
    assert first.stream_seed("COIN") == second.stream_seed("COIN")
    assert first.run_commitment() != second.run_commitment()
    assert first.stream_id("COIN") != second.stream_id("COIN")
    assert first.stream_seed_commitment("COIN") != second.stream_seed_commitment("COIN")


def test_secret_changes_schedule_and_commitment_opens_only_after_reveal() -> None:
    first = _material(secret=_root("secret-a"))
    second = _material(secret=_root("secret-b"))
    assert first.master_seed() != second.master_seed()
    assert first.evaluator_secret_commitment != second.evaluator_secret_commitment
    assert first.evaluator_secret not in repr(first.sanitized_receipt()).encode("utf-8")
    verify_reveal_receipt(first.reveal_receipt())

    forged = first.reveal_receipt()
    forged[3] = _root("forged-secret")
    with pytest.raises(RngSeedProtocolError, match="does not open"):
        verify_reveal_receipt(forged)


def test_seed_protocol_rejects_weak_mismatched_and_type_confused_inputs() -> None:
    material = _material()
    with pytest.raises(RngSeedProtocolError) as mismatch:
        replace(material, evaluator_secret=_root("other-secret"))
    assert mismatch.value.code == "RNG_SEED_COMMITMENT_MISMATCH"

    with pytest.raises(RngSeedProtocolError) as zero:
        replace(material, evaluator_secret=bytes(32))
    assert zero.value.code == "RNG_SEED_SECRET_INVALID"

    with pytest.raises(RngSeedProtocolError) as boolean:
        replace(material, common_seed_id=True)
    assert boolean.value.code == "RNG_SEED_TYPE_INVALID"

    with pytest.raises(RngSeedProtocolError) as seat:
        replace(material, candidate_seat=False)
    assert seat.value.code == "RNG_SEED_TYPE_INVALID"

