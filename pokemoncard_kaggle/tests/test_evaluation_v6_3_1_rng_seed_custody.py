from __future__ import annotations

from copy import copy, deepcopy
from hashlib import sha256
import pickle

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode
from evaluation_v6_3_1.rng_seed_custody import (
    BIND_RUN,
    CLOSED,
    COMMIT,
    ENGINE_OPEN,
    NO_UPLOAD,
    PRIVATE_ENGINE_OPEN,
    REVEAL,
    REVEALED,
    RUN_CLOSE,
    RngSeedCustodyError,
    RngSeedCustodyStateMachine,
    verify_public_journal,
)
def _root(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


PROTOCOL, MODEL, POPULATION, SECRET = (_root(value) for value in ("protocol", "model", "population", "secret"))


def _machine() -> RngSeedCustodyStateMachine:
    machine = RngSeedCustodyStateMachine()
    machine.commit(PROTOCOL, MODEL, POPULATION, 37, SECRET)
    return machine


def _bound(
    candidate: str = "candidate-a",
    control: str = "control-a",
    seat: int = 0,
) -> RngSeedCustodyStateMachine:
    machine = _machine()
    machine.bind_run(_root(candidate), _root(control), seat)
    return machine


def _open() -> RngSeedCustodyStateMachine:
    machine = _bound()
    machine.open_private_engine()
    return machine


def _assert_code(code: str, func, *args, **kwargs) -> None:
    with pytest.raises(RngSeedCustodyError) as raised:
        func(*args, **kwargs)
    assert raised.value.code == code


def test_exact_canonical_journal_and_hash_chain_are_deterministic() -> None:
    left, right = _bound(), _bound()
    assert left.journal_bytes() == right.journal_bytes()
    checked = verify_public_journal(left.journal_bytes())
    assert checked.event_names == (COMMIT, BIND_RUN)
    assert checked.state == "BOUND"
    assert checked.head_hash == canonical_cbor_decode(left.journal_bytes())[1][-1][5]
    assert verify_public_journal(RngSeedCustodyStateMachine().journal_bytes()).state == "INITIAL"

    left.open_private_engine()
    right.open_private_engine()
    left.close_run(left.run_binding.run_commitment, _root("execution"))
    right.close_run(right.run_binding.run_commitment, _root("execution"))
    assert left.journal_bytes() == right.journal_bytes()
    reveal = left.reveal()
    assert reveal[3] == SECRET
    assert verify_public_journal(left.journal_bytes()).state == REVEALED


def test_public_prefix_never_contains_secret_master_or_stream_seed() -> None:
    machine = _bound()
    pre_reveal = machine.journal_bytes()
    assert SECRET not in pre_reveal
    assert SECRET.hex().encode("ascii") not in pre_reveal
    assert "secret" not in repr(machine).lower()

    capability = machine.open_private_engine()
    master = capability.master_seed()
    stream = capability.stream_seed("SHUFFLE")
    pre_close = machine.journal_bytes()
    assert SECRET not in pre_close
    assert master not in pre_close
    assert stream not in pre_close
    assert master.hex().encode("ascii") not in pre_close
    assert stream.hex().encode("ascii") not in pre_close
    assert "master" not in repr(capability).lower()
    assert "stream" not in repr(capability).lower()


def test_candidate_control_and_seat_bind_the_run_but_not_the_schedule() -> None:
    first, second = _bound("candidate-a", "control-a", 0), _bound("candidate-b", "control-b", 1)
    assert first.schedule_context_root == second.schedule_context_root
    first_cap, second_cap = first.open_private_engine(), second.open_private_engine()
    assert first_cap.master_seed() == second_cap.master_seed()
    assert first_cap.stream_seed("COIN") == second_cap.stream_seed("COIN")
    assert first.run_binding.run_commitment != second.run_binding.run_commitment
    assert first_cap.stream_id("COIN") != second_cap.stream_id("COIN")


def test_strict_lifecycle_rejects_early_duplicate_rebind_and_reopen() -> None:
    machine = RngSeedCustodyStateMachine()
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.bind_run, _root("c"), _root("d"), 0)
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.open_private_engine)
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.reveal)
    machine.commit(PROTOCOL, MODEL, POPULATION, 37, SECRET)
    machine.bind_run(_root("c"), _root("d"), 0)
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.bind_run, _root("e"), _root("f"), 1)
    machine.open_private_engine()
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.open_private_engine)
    machine.close_run(machine.run_binding.run_commitment)
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.close_run, machine.run_binding.run_commitment)
    machine.reveal()
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.reveal)
    _assert_code("RNG_CUSTODY_TRANSITION_INVALID", machine.open_private_engine)


def test_close_mismatch_and_private_capability_revocation_fail_closed() -> None:
    machine = _open()
    capability = machine._capability
    assert capability is not None
    _assert_code("RNG_CUSTODY_CLOSE_MISMATCH", machine.close_run, _root("wrong-run"))
    machine.close_run(machine.run_binding.run_commitment)
    assert machine.state == CLOSED
    _assert_code("RNG_CUSTODY_PRIVATE_REVOKED", capability.master_seed)


def test_private_engine_capability_cannot_be_serialized_or_copied() -> None:
    capability = _open()._capability
    assert capability is not None
    _assert_code("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", bytes, capability)
    _assert_code("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", pickle.dumps, capability)
    _assert_code("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", copy, capability)
    _assert_code("RNG_CUSTODY_PRIVATE_NOT_SERIALIZABLE", deepcopy, capability)


@pytest.mark.parametrize("mutation", ("truncate", "wrong_previous", "wrong_hash", "noncanonical"))
def test_malformed_or_tampered_journal_fails_closed(mutation: str) -> None:
    machine = _open()
    machine.close_run(machine.run_binding.run_commitment)
    raw = machine.journal_bytes()
    if mutation == "truncate":
        raw = raw[:-1]
    elif mutation == "wrong_previous":
        parsed = canonical_cbor_decode(raw)
        parsed[1][2][4] = _root("wrong-previous")
        raw = canonical_cbor_encode(parsed)
    elif mutation == "wrong_hash":
        parsed = canonical_cbor_decode(raw)
        parsed[1][3][5] = _root("wrong-hash")
        raw = canonical_cbor_encode(parsed)
    else:
        raw = b"\x81" + raw[1:]
    _assert_code("RNG_CUSTODY_JOURNAL_MALFORMED", verify_public_journal, raw) if mutation in {"truncate", "noncanonical"} else _assert_code("RNG_CUSTODY_HASH_CHAIN_INVALID", verify_public_journal, raw)


def test_reveal_verifies_commitment_and_reveal_tampering_fails_closed() -> None:
    machine = _open()
    machine.close_run(machine.run_binding.run_commitment)
    machine.reveal()
    raw = machine.journal_bytes()
    parsed = canonical_cbor_decode(raw)
    parsed[1][-1][3][0][3] = _root("forged")
    forged = canonical_cbor_encode(parsed)
    _assert_code("RNG_CUSTODY_HASH_CHAIN_INVALID", verify_public_journal, forged)


def test_symlink_and_output_reuse_fail_closed(tmp_path) -> None:
    machine = _machine()
    target = tmp_path / "journal.cbor"
    machine.write_public_journal(target)
    assert target.read_bytes() == machine.journal_bytes()
    _assert_code("RNG_CUSTODY_OUTPUT_REJECTED", machine.write_public_journal, target)
    link = tmp_path / "link.cbor"
    link.symlink_to(target)
    _assert_code("RNG_CUSTODY_OUTPUT_REJECTED", machine.write_public_journal, link)


def test_reports_are_immutable_and_permanently_no_upload() -> None:
    machine = _open()
    report = machine.report()
    assert report["authority"] == NO_UPLOAD
    assert report["state"] == NO_UPLOAD
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False
    assert report["sealed_holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == ()
    with pytest.raises(TypeError):
        report["authority"] = "UPLOAD"  # type: ignore[index]
    machine.close_run(machine.run_binding.run_commitment)
    machine.reveal()
    assert machine.report()["authority"] == NO_UPLOAD
