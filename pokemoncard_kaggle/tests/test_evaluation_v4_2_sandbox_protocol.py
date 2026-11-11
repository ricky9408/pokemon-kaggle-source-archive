import io
import struct

import pytest

from evaluation_v4_2.sandbox_protocol import (
    ACTION_REQUEST_SCHEMA,
    ACTION_RESPONSE_SCHEMA,
    ERROR_SCHEMA,
    FRAME_HEADER,
    FRAME_HEADER_SIZE,
    FRAME_MAGIC,
    FRAME_VERSION,
    PROTOCOL_SCHEMA,
    ProtocolState,
    SandboxProtocolError,
    TranscriptAccumulator,
    canonical_sha256,
    decode_frame,
    encode_frame,
    read_frame,
    read_next_frame,
    sandbox_execution_spec,
    validate_action_response,
    validate_error,
    validate_hello,
    validate_ready,
    validate_sandbox_execution_spec,
    validate_terminal,
    write_frame,
)


DIGEST = "a" * 64


def observation(count=3, minimum=0, maximum=1):
    return {
        "current": {"yourIndex": 0},
        "select": {
            "option": [{"index": index} for index in range(count)],
            "minCount": minimum,
            "maxCount": maximum,
        },
    }


def binding(actor_role="candidate_policy", request_id="request-1", turn_id=4, count=3):
    return {
        "session_id": "session-1",
        "arm_claim_sha256": DIGEST,
        "game_id": "game-1",
        "turn_id": turn_id,
        "actor_role": actor_role,
        "observation_sha256": canonical_sha256(observation(count)),
        "request_id": request_id,
    }


def exchange_binding(actor_role="candidate_policy", request_id="request-1", turn_id=4, count=3):
    observed = observation(count)
    return {
        **binding(actor_role, request_id, turn_id, count),
        "legal_options_sha256": canonical_sha256(observed["select"]),
    }


def request(
    actor_role="candidate_policy",
    request_id="request-1",
    turn_id=4,
    count=3,
    minimum=0,
    maximum=1,
):
    observed = observation(count, minimum, maximum)
    return {
        "schema": ACTION_REQUEST_SCHEMA,
        **exchange_binding(actor_role, request_id, turn_id, count),
        "observation_sha256": canonical_sha256(observed),
        "observation": observed,
        "legal_options_sha256": canonical_sha256(observed["select"]),
        "legal_option_count": count,
        "legal_min_count": minimum,
        "legal_max_count": maximum,
    }


def response(action=(1,), **kwargs):
    return {
        "schema": ACTION_RESPONSE_SCHEMA,
        **exchange_binding(**kwargs),
        "action": list(action),
    }


def framed(role, message_type, sequence, payload):
    return decode_frame(encode_frame(role, message_type, sequence, payload))


def test_partial_stream_reads_and_short_writes_are_exact():
    data = encode_frame("referee", "ACTION_REQUEST", 1, request())

    class ShortReader(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 2))

    class ShortWriter(io.BytesIO):
        def write(self, value):
            return super().write(value[:3])

    reader = ShortReader(data)
    assert read_frame(reader).to_bytes() == data
    writer = ShortWriter()
    assert write_frame(writer, data) == len(data)
    assert writer.getvalue() == data


def test_noncanonical_json_and_trailing_bytes_are_rejected():
    data = encode_frame("referee", "ACTION_REQUEST", 1, request())
    header = data[:FRAME_HEADER_SIZE]
    payload = data[FRAME_HEADER_SIZE:]
    noncanonical = b'{"schema":' + payload.split(b'"schema":', 1)[1]
    assert noncanonical != payload
    bad = header[: FRAME_HEADER.size - 32] + __import__("hashlib").sha256(noncanonical).digest()
    bad = bad + noncanonical
    with pytest.raises(SandboxProtocolError):
        decode_frame(bad)
    with pytest.raises(SandboxProtocolError, match="trailing"):
        read_frame(io.BytesIO(data + b"x"))


@pytest.mark.parametrize("mutation", ["magic", "version", "hash", "length", "role", "type"])
def test_corrupt_header_fields_are_rejected(mutation):
    data = bytearray(encode_frame("referee", "ACTION_REQUEST", 1, request()))
    if mutation == "magic":
        data[:4] = b"NOPE"
    elif mutation == "version":
        data[4] = FRAME_VERSION + 1
    elif mutation == "hash":
        data[-1] ^= 1
    elif mutation == "length":
        data[15:19] = struct.pack("!I", 999999)
    elif mutation == "role":
        data[5] = 99
    elif mutation == "type":
        data[6] = 99
    with pytest.raises(SandboxProtocolError):
        decode_frame(bytes(data))


def test_magic_and_header_are_fixed_binary_values():
    data = encode_frame("referee", "ACTION_REQUEST", 1, request())
    assert data[:4] == FRAME_MAGIC
    assert len(data) >= FRAME_HEADER_SIZE
    assert FRAME_HEADER.unpack(data[:FRAME_HEADER_SIZE])[0] == FRAME_MAGIC


def test_hello_ready_terminal_and_error_have_strict_schemas():
    hello = {
        "schema": PROTOCOL_SCHEMA + "_hello_v1",
        "session_id": "session-1",
        "arm_claim_sha256": DIGEST,
        "role": "candidate_policy",
        "sandbox_id": "candidate_policy",
        "protocol": PROTOCOL_SCHEMA,
    }
    assert validate_hello(hello, frame_role="candidate_policy")["role"] == "candidate_policy"
    ready = {**hello, "schema": PROTOCOL_SCHEMA + "_ready_v1", "hello_sequence": 1}
    assert validate_ready(ready, frame_role="candidate_policy")["hello_sequence"] == 1
    terminal = {
        "schema": PROTOCOL_SCHEMA + "_terminal_v1",
        **binding(actor_role="referee", request_id="terminal-1"),
        "outcome": "game_complete",
        "winner_role": "candidate_policy",
    }
    assert validate_terminal(terminal)["winner_role"] == "candidate_policy"
    error = {
        "schema": ERROR_SCHEMA,
        **binding(actor_role="candidate_policy", request_id="error-1"),
        "code": "ACTION_TIMEOUT",
        "message": "deadline exceeded",
    }
    assert validate_error(error, frame_role="candidate_policy")["code"] == "ACTION_TIMEOUT"
    with pytest.raises(SandboxProtocolError):
        validate_hello({**hello, "schema": "wrong"})
    with pytest.raises(SandboxProtocolError, match="game_complete"):
        validate_terminal({**terminal, "outcome": "candidate_win"})
    with pytest.raises(SandboxProtocolError, match="policy sandbox"):
        validate_terminal({**terminal, "winner_role": "referee"})


def test_duplicate_indexes_and_out_of_range_indexes_are_rejected():
    with pytest.raises(SandboxProtocolError, match="unique"):
        validate_action_response(response(action=(1, 1)))
    with pytest.raises(SandboxProtocolError, match="out-of-range"):
        validate_action_response(response(action=(3,)), legal_option_count=3)


def test_empty_action_is_valid_only_when_request_minimum_is_zero():
    zero = request(minimum=0, maximum=1)
    zero_response = response(action=())
    zero_response["observation_sha256"] = zero["observation_sha256"]
    zero_response["legal_options_sha256"] = zero["legal_options_sha256"]
    assert validate_action_response(
        zero_response,
        legal_option_count=3,
        expected_request=zero,
    )["action"] == []
    required = request(minimum=1, maximum=1)
    required_response = response(action=())
    required_response["observation_sha256"] = required["observation_sha256"]
    required_response["legal_options_sha256"] = required["legal_options_sha256"]
    with pytest.raises(SandboxProtocolError, match="count"):
        validate_action_response(
            required_response,
            legal_option_count=3,
            expected_request=required,
        )


def test_protocol_state_binds_request_response_and_rejects_stale_or_replayed_actions():
    state = ProtocolState()
    req = framed("referee", "ACTION_REQUEST", 1, request())
    state.accept(req)
    state.accept(framed("candidate_policy", "ACTION_RESPONSE", 1, response()))
    with pytest.raises(SandboxProtocolError, match="stale"):
        state.accept(framed("candidate_policy", "ACTION_RESPONSE", 2, response()))

    other = ProtocolState()
    other.accept(framed("referee", "ACTION_REQUEST", 1, request()))
    with pytest.raises(SandboxProtocolError, match="stale"):
        other.accept(framed("referee", "ACTION_REQUEST", 2, request(request_id="request-2", turn_id=3)))


def test_channel_sequences_must_be_strictly_contiguous():
    state = ProtocolState()
    state.accept(framed("referee", "ACTION_REQUEST", 1, request()))
    with pytest.raises(SandboxProtocolError, match="sequence"):
        state.accept(framed("candidate_policy", "ACTION_RESPONSE", 2, response()))
    state.accept(framed("candidate_policy", "ACTION_RESPONSE", 1, response()))


def test_terminal_requires_no_pending_action_and_policy_winner():
    terminal = {
        "schema": PROTOCOL_SCHEMA + "_terminal_v1",
        **binding(actor_role="referee", request_id="terminal-1"),
        "outcome": "game_complete",
        "winner_role": "candidate_policy",
    }
    pending = ProtocolState()
    pending.accept(framed("referee", "ACTION_REQUEST", 1, request()))
    with pytest.raises(SandboxProtocolError, match="pending"):
        pending.accept(framed("referee", "TERMINAL", 2, terminal))

    complete = ProtocolState()
    complete.accept(framed("referee", "ACTION_REQUEST", 1, request()))
    complete.accept(framed("candidate_policy", "ACTION_RESPONSE", 1, response()))
    complete.accept(framed("referee", "TERMINAL", 2, terminal))
    assert complete.pending_request_ids == frozenset()


def test_transcript_is_deterministic_and_excludes_wall_clock_timing():
    frame = framed("referee", "ACTION_REQUEST", 1, request())
    first = TranscriptAccumulator()
    second = TranscriptAccumulator()
    assert first.add("referee_to_policy", frame) == second.add("referee_to_policy", frame)
    assert first.hexdigest == second.hexdigest
    assert first.hexdigest != TranscriptAccumulator().hexdigest
    assert first.add("policy_to_referee", framed("candidate_policy", "ACTION_RESPONSE", 1, response()))


def test_execution_spec_is_frozen_and_all_authority_flags_are_hard_false():
    spec = sandbox_execution_spec()
    assert len(spec["containers"]) == 3
    assert {item["role"] for item in spec["containers"]} == {
        "referee",
        "candidate_policy",
        "opponent_policy",
    }
    assert spec["authority"] == "DEVELOPMENT_ONLY"
    assert spec["one_process_per_container"] is False
    for key in (
        "networking",
        "shared_writable_mounts",
        "external_authority",
        "remote_attestation_verified",
        "native_platform_verified",
        "latency_parity_allowed",
        "randomization_allowed",
        "anchor_allowed",
        "production_submission_authorized",
        "submit_authorized",
    ):
        assert spec[key] is False
    assert spec["action_deadline_enforcement"] == "external"
    validate_sandbox_execution_spec(spec)
    spec["submit_authorized"] = True
    with pytest.raises(SandboxProtocolError):
        validate_sandbox_execution_spec(spec)


def test_read_next_frame_allows_a_second_frame_on_a_channel():
    first = encode_frame("referee", "ACTION_REQUEST", 1, request())
    second = encode_frame("referee", "ACTION_REQUEST", 2, request(request_id="request-2"))
    stream = io.BytesIO(first + second)
    assert read_next_frame(stream).sequence == 1
    assert read_frame(stream).sequence == 2
