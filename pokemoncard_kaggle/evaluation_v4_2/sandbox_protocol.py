"""Pure framed protocol for the three isolated v4.2 sandboxes.

This module intentionally has no clock, filesystem, subprocess, Docker, or
network surface.  It defines bytes, schemas, and state transitions only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import struct
from typing import Any, BinaryIO


PROTOCOL_SCHEMA = "evaluation_v4_2_three_sandbox_framed_protocol_v1"
FRAME_MAGIC = b"SBX4"
FRAME_VERSION = 1
# magic, version, role, message type, sequence, payload length, full SHA-256.
FRAME_HEADER = struct.Struct("!4sBBBQI32s")
FRAME_HEADER_SIZE = FRAME_HEADER.size
MAX_FRAME_SIZE = 1024 * 1024
MAX_PAYLOAD_SIZE = MAX_FRAME_SIZE - FRAME_HEADER_SIZE
MAX_STDERR_BYTES = 64 * 1024
MAX_AGGREGATE_OUTPUT_BYTES = 128 * 1024 * 1024

ROLE_IDS = {
    "referee": 1,
    "candidate_policy": 2,
    "opponent_policy": 3,
}
ROLES = frozenset(ROLE_IDS)
ID_ROLES = {value: key for key, value in ROLE_IDS.items()}

MESSAGE_IDS = {
    "HELLO": 1,
    "READY": 2,
    "ACTION_REQUEST": 3,
    "ACTION_RESPONSE": 4,
    "TERMINAL": 5,
    "ERROR": 6,
}
MESSAGES = frozenset(MESSAGE_IDS)
ID_MESSAGES = {value: key for key, value in MESSAGE_IDS.items()}
POLICY_ROLES = frozenset({"candidate_policy", "opponent_policy"})

HELLO_SCHEMA = PROTOCOL_SCHEMA + "_hello_v1"
READY_SCHEMA = PROTOCOL_SCHEMA + "_ready_v1"
ACTION_REQUEST_SCHEMA = PROTOCOL_SCHEMA + "_action_request_v1"
ACTION_RESPONSE_SCHEMA = PROTOCOL_SCHEMA + "_action_response_v1"
TERMINAL_SCHEMA = PROTOCOL_SCHEMA + "_terminal_v1"
ERROR_SCHEMA = PROTOCOL_SCHEMA + "_error_v1"

DEVELOPMENT_ONLY = "DEVELOPMENT_ONLY"
AUTHORITY = DEVELOPMENT_ONLY

_SHA256_HEX = frozenset("0123456789abcdef")
_IDENTIFIER_FIELDS = frozenset({"session_id", "game_id", "request_id"})
_ACTION_BINDING_FIELDS = frozenset(
    {
        "session_id",
        "arm_claim_sha256",
        "game_id",
        "turn_id",
        "actor_role",
        "observation_sha256",
        "request_id",
    }
)
_ACTION_EXCHANGE_BINDING_FIELDS = _ACTION_BINDING_FIELDS | frozenset(
    {"legal_options_sha256"}
)
_HELLO_FIELDS = frozenset(
    {"schema", "session_id", "arm_claim_sha256", "role", "sandbox_id", "protocol"}
)
_READY_FIELDS = _HELLO_FIELDS | frozenset({"hello_sequence"})
_ACTION_REQUEST_FIELDS = _ACTION_EXCHANGE_BINDING_FIELDS | frozenset(
    {
        "schema",
        "observation",
        "legal_option_count",
        "legal_min_count",
        "legal_max_count",
    }
)
_ACTION_RESPONSE_FIELDS = _ACTION_EXCHANGE_BINDING_FIELDS | frozenset(
    {"schema", "action"}
)
_TERMINAL_FIELDS = frozenset(
    {
        "schema",
        "session_id",
        "arm_claim_sha256",
        "game_id",
        "turn_id",
        "actor_role",
        "observation_sha256",
        "request_id",
        "outcome",
        "winner_role",
    }
)
_ERROR_FIELDS = _ACTION_BINDING_FIELDS | frozenset({"schema", "code", "message"})


class SandboxProtocolError(ValueError):
    """A frame, message, execution spec, or protocol state is invalid."""


def canonical_json_bytes(value: object) -> bytes:
    """Serialize JSON using the one ASCII, sorted, whitespace-free encoding."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SandboxProtocolError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _duplicate_key_rejector(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SandboxProtocolError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _decode_canonical_json(payload: bytes) -> dict[str, Any]:
    if not payload or any(byte > 0x7F for byte in payload):
        raise SandboxProtocolError("payload must be non-empty ASCII JSON")
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_duplicate_key_rejector)
    except (UnicodeDecodeError, json.JSONDecodeError, SandboxProtocolError) as exc:
        raise SandboxProtocolError(f"invalid JSON payload: {exc}") from exc
    if not isinstance(value, dict):
        raise SandboxProtocolError("payload must be a JSON object")
    if canonical_json_bytes(value) != payload:
        raise SandboxProtocolError("payload is not canonical JSON")
    return value


def _exact_fields(value: object, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise SandboxProtocolError(f"{label} fields must exactly be {sorted(expected)}; got {actual}")
    return value


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(
        character.isspace() for character in value
    ):
        raise SandboxProtocolError(f"{label} must be a non-empty token without whitespace")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 4096:
        raise SandboxProtocolError(f"{label} must be non-empty trimmed text of at most 4096 characters")
    if any(ord(character) < 0x20 for character in value):
        raise SandboxProtocolError(f"{label} must not contain control characters")
    return value


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _SHA256_HEX for character in value)
    ):
        raise SandboxProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise SandboxProtocolError(f"{label} must be an integer >= {minimum}")
    return value


def _role(value: object, label: str) -> str:
    if not isinstance(value, str) or value not in ROLES:
        raise SandboxProtocolError(f"{label} must be one of {sorted(ROLES)}")
    return value  # type: ignore[return-value]


def _common_action(value: object, expected_fields: frozenset[str], label: str) -> dict[str, Any]:
    raw = _exact_fields(value, expected_fields, label)
    actor_role = _role(raw["actor_role"], f"{label}.actor_role")
    result = {
        "schema": raw["schema"],
        "session_id": _token(raw["session_id"], f"{label}.session_id"),
        "arm_claim_sha256": _digest(raw["arm_claim_sha256"], f"{label}.arm_claim_sha256"),
        "game_id": _token(raw["game_id"], f"{label}.game_id"),
        "turn_id": _integer(raw["turn_id"], f"{label}.turn_id"),
        "actor_role": actor_role,
        "observation_sha256": _digest(
            raw["observation_sha256"], f"{label}.observation_sha256"
        ),
        "request_id": _token(raw["request_id"], f"{label}.request_id"),
    }
    if "legal_options_sha256" in raw:
        result["legal_options_sha256"] = _digest(
            raw["legal_options_sha256"],
            f"{label}.legal_options_sha256",
        )
    return result


def validate_hello(payload: object, *, frame_role: str | None = None) -> dict[str, Any]:
    raw = _exact_fields(payload, _HELLO_FIELDS, "HELLO")
    if raw["schema"] != HELLO_SCHEMA:
        raise SandboxProtocolError(f"HELLO.schema must be {HELLO_SCHEMA!r}")
    role = _role(raw["role"], "HELLO.role")
    if frame_role is not None and role != frame_role:
        raise SandboxProtocolError("HELLO.role does not match frame role")
    if raw["protocol"] != PROTOCOL_SCHEMA:
        raise SandboxProtocolError("HELLO.protocol does not match this protocol")
    return {
        "schema": HELLO_SCHEMA,
        "session_id": _token(raw["session_id"], "HELLO.session_id"),
        "arm_claim_sha256": _digest(raw["arm_claim_sha256"], "HELLO.arm_claim_sha256"),
        "role": role,
        "sandbox_id": _token(raw["sandbox_id"], "HELLO.sandbox_id"),
        "protocol": PROTOCOL_SCHEMA,
    }


def validate_ready(payload: object, *, frame_role: str | None = None) -> dict[str, Any]:
    raw = _exact_fields(payload, _READY_FIELDS, "READY")
    if raw["schema"] != READY_SCHEMA:
        raise SandboxProtocolError(f"READY.schema must be {READY_SCHEMA!r}")
    hello_fields = {key: raw[key] for key in _HELLO_FIELDS}
    hello_fields["schema"] = HELLO_SCHEMA
    result = validate_hello(hello_fields, frame_role=frame_role)
    result["schema"] = READY_SCHEMA
    result["hello_sequence"] = _integer(raw["hello_sequence"], "READY.hello_sequence", 1)
    return result


def validate_action_request(payload: object) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or payload.get("schema") != ACTION_REQUEST_SCHEMA:
        raise SandboxProtocolError(f"ACTION_REQUEST.schema must be {ACTION_REQUEST_SCHEMA!r}")
    result = _common_action(payload, _ACTION_REQUEST_FIELDS, "ACTION_REQUEST")
    if result["actor_role"] not in POLICY_ROLES:
        raise SandboxProtocolError("ACTION_REQUEST.actor_role must identify a policy sandbox")
    observation = payload["observation"]  # type: ignore[index]
    if not isinstance(observation, Mapping):
        raise SandboxProtocolError("ACTION_REQUEST.observation must be an object")
    detached_observation = json.loads(canonical_json_bytes(dict(observation)).decode("ascii"))
    if canonical_sha256(detached_observation) != result["observation_sha256"]:
        raise SandboxProtocolError("ACTION_REQUEST.observation_sha256 does not match observation")
    selection = detached_observation.get("select")
    if not isinstance(selection, Mapping):
        raise SandboxProtocolError("ACTION_REQUEST.observation.select must be an object")
    options = selection.get("option")
    if not isinstance(options, list):
        raise SandboxProtocolError("ACTION_REQUEST.observation.select.option must be a list")
    option_count = _integer(
        payload["legal_option_count"], "ACTION_REQUEST.legal_option_count", 1  # type: ignore[index]
    )
    minimum = _integer(payload["legal_min_count"], "ACTION_REQUEST.legal_min_count")  # type: ignore[index]
    maximum = _integer(payload["legal_max_count"], "ACTION_REQUEST.legal_max_count")  # type: ignore[index]
    if option_count != len(options):
        raise SandboxProtocolError("ACTION_REQUEST.legal_option_count does not match observation")
    observed_minimum = _integer(
        selection.get("minCount", 0),
        "ACTION_REQUEST.observation.select.minCount",
    )
    observed_maximum = _integer(
        selection.get("maxCount", option_count),
        "ACTION_REQUEST.observation.select.maxCount",
    )
    if minimum != observed_minimum or maximum != observed_maximum:
        raise SandboxProtocolError("ACTION_REQUEST legal count bounds do not match observation")
    if minimum > maximum or maximum > option_count:
        raise SandboxProtocolError("ACTION_REQUEST legal count bounds are invalid")
    options_digest = result["legal_options_sha256"]
    if options_digest != canonical_sha256(selection):
        raise SandboxProtocolError("ACTION_REQUEST.legal_options_sha256 does not match selection")
    result.update(
        {
            "observation": detached_observation,
            "legal_options_sha256": options_digest,
            "legal_option_count": option_count,
            "legal_min_count": minimum,
            "legal_max_count": maximum,
        }
    )
    return result


def validate_action_response(
    payload: object,
    *,
    legal_option_count: int | None = None,
    expected_request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or payload.get("schema") != ACTION_RESPONSE_SCHEMA:
        raise SandboxProtocolError(f"ACTION_RESPONSE.schema must be {ACTION_RESPONSE_SCHEMA!r}")
    result = _common_action(payload, _ACTION_RESPONSE_FIELDS, "ACTION_RESPONSE")
    if result["actor_role"] not in POLICY_ROLES:
        raise SandboxProtocolError("ACTION_RESPONSE.actor_role must identify a policy sandbox")
    action = payload["action"]  # type: ignore[index]
    if not isinstance(action, list):
        raise SandboxProtocolError("ACTION_RESPONSE.action must be a list")
    if any(isinstance(index, bool) or not isinstance(index, int) for index in action):
        raise SandboxProtocolError("ACTION_RESPONSE.action indexes must be integers")
    if len(action) != len(set(action)):
        raise SandboxProtocolError("ACTION_RESPONSE.action indexes must be unique")
    if legal_option_count is not None:
        _integer(legal_option_count, "legal_option_count", 1)
        if any(index < 0 or index >= legal_option_count for index in action):
            raise SandboxProtocolError("ACTION_RESPONSE.action contains an out-of-range index")
    if expected_request is not None:
        for key in _ACTION_EXCHANGE_BINDING_FIELDS:
            if result[key] != expected_request[key]:
                raise SandboxProtocolError(f"ACTION_RESPONSE does not echo {key}")
        minimum = _integer(expected_request["legal_min_count"], "expected_request.legal_min_count")
        maximum = _integer(expected_request["legal_max_count"], "expected_request.legal_max_count")
        if not minimum <= len(action) <= maximum:
            raise SandboxProtocolError("ACTION_RESPONSE.action count violates request bounds")
    result["action"] = list(action)
    return result


def validate_terminal(payload: object) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or payload.get("schema") != TERMINAL_SCHEMA:
        raise SandboxProtocolError(f"TERMINAL.schema must be {TERMINAL_SCHEMA!r}")
    result = _common_action(payload, _TERMINAL_FIELDS, "TERMINAL")
    if result["actor_role"] != "referee":
        raise SandboxProtocolError("TERMINAL.actor_role must be referee")
    raw = payload  # type: ignore[assignment]
    outcome = _token(raw["outcome"], "TERMINAL.outcome")  # type: ignore[index]
    if outcome != "game_complete":
        raise SandboxProtocolError("TERMINAL.outcome must be game_complete")
    winner_role = raw["winner_role"]  # type: ignore[index]
    if winner_role is not None:
        _role(winner_role, "TERMINAL.winner_role")
        if winner_role not in POLICY_ROLES:
            raise SandboxProtocolError("TERMINAL.winner_role must identify a policy sandbox")
    result.update({"outcome": outcome, "winner_role": winner_role})
    return result


def validate_error(payload: object, *, frame_role: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or payload.get("schema") != ERROR_SCHEMA:
        raise SandboxProtocolError(f"ERROR.schema must be {ERROR_SCHEMA!r}")
    result = _common_action(payload, _ERROR_FIELDS, "ERROR")
    raw = payload  # type: ignore[assignment]
    if frame_role is not None and result["actor_role"] != frame_role:
        raise SandboxProtocolError("ERROR.actor_role does not match frame role")
    result.update(
        {
            "code": _token(raw["code"], "ERROR.code"),  # type: ignore[index]
            "message": _text(raw["message"], "ERROR.message"),  # type: ignore[index]
        }
    )
    return result


@dataclass(frozen=True)
class Frame:
    role: str
    message_type: str
    sequence: int
    payload: Mapping[str, Any]

    @property
    def payload_bytes(self) -> bytes:
        return canonical_json_bytes(dict(self.payload))

    def to_bytes(self) -> bytes:
        return encode_frame(self.role, self.message_type, self.sequence, self.payload)


def _validate_frame_header_fields(role: str, message_type: str, sequence: int) -> None:
    if role not in ROLES:
        raise SandboxProtocolError(f"unknown frame role: {role!r}")
    if message_type not in MESSAGES:
        raise SandboxProtocolError(f"unknown frame message type: {message_type!r}")
    _integer(sequence, "frame.sequence", 1)


def _validate_message_role(role: str, message_type: str, payload: Mapping[str, Any]) -> None:
    if message_type == "ACTION_REQUEST" and role != "referee":
        raise SandboxProtocolError("ACTION_REQUEST may only be sent by referee")
    if message_type == "ACTION_RESPONSE" and role not in POLICY_ROLES:
        raise SandboxProtocolError("ACTION_RESPONSE may only be sent by a policy")
    if message_type == "TERMINAL" and role != "referee":
        raise SandboxProtocolError("TERMINAL may only be sent by referee")
    if message_type == "HELLO":
        validate_hello(payload, frame_role=role)
    elif message_type == "READY":
        validate_ready(payload, frame_role=role)
    elif message_type == "ACTION_REQUEST":
        validate_action_request(payload)
    elif message_type == "ACTION_RESPONSE":
        validate_action_response(payload)
        if payload["actor_role"] != role:
            raise SandboxProtocolError("ACTION_RESPONSE.actor_role does not match frame role")
    elif message_type == "TERMINAL":
        validate_terminal(payload)
    elif message_type == "ERROR":
        validate_error(payload, frame_role=role)


def encode_frame(role: str, message_type: str, sequence: int, payload: Mapping[str, Any]) -> bytes:
    _validate_frame_header_fields(role, message_type, sequence)
    if not isinstance(payload, Mapping):
        raise SandboxProtocolError("frame payload must be a JSON object")
    canonical_payload = canonical_json_bytes(dict(payload))
    if len(canonical_payload) > MAX_PAYLOAD_SIZE:
        raise SandboxProtocolError("frame payload exceeds maximum frame size")
    decoded = _decode_canonical_json(canonical_payload)
    _validate_message_role(role, message_type, decoded)
    header = FRAME_HEADER.pack(
        FRAME_MAGIC,
        FRAME_VERSION,
        ROLE_IDS[role],
        MESSAGE_IDS[message_type],
        sequence,
        len(canonical_payload),
        hashlib.sha256(canonical_payload).digest(),
    )
    return header + canonical_payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise SandboxProtocolError("stream returned a non-bytes read result")
        if not chunk:
            raise SandboxProtocolError("truncated frame")
        data = bytes(chunk)
        if len(data) > remaining:
            raise SandboxProtocolError("stream returned more bytes than requested")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def decode_frame(data: bytes, *, max_frame_size: int = MAX_FRAME_SIZE) -> Frame:
    if not isinstance(data, bytes):
        raise SandboxProtocolError("frame must be bytes")
    if len(data) > max_frame_size:
        raise SandboxProtocolError("frame exceeds maximum frame size")
    if len(data) < FRAME_HEADER_SIZE:
        raise SandboxProtocolError("truncated frame header")
    header = data[:FRAME_HEADER_SIZE]
    magic, version, role_id, message_id, sequence, payload_length, digest = FRAME_HEADER.unpack(header)
    if magic != FRAME_MAGIC:
        raise SandboxProtocolError("bad frame magic")
    if version != FRAME_VERSION:
        raise SandboxProtocolError("unsupported frame version")
    role = ID_ROLES.get(role_id)
    message_type = ID_MESSAGES.get(message_id)
    if role is None:
        raise SandboxProtocolError("unknown frame role id")
    if message_type is None:
        raise SandboxProtocolError("unknown frame message type id")
    _validate_frame_header_fields(role, message_type, sequence)
    if payload_length > MAX_PAYLOAD_SIZE or FRAME_HEADER_SIZE + payload_length > max_frame_size:
        raise SandboxProtocolError("oversize frame payload")
    if len(data) != FRAME_HEADER_SIZE + payload_length:
        raise SandboxProtocolError("frame has trailing bytes or an invalid payload length")
    payload = data[FRAME_HEADER_SIZE:]
    if hashlib.sha256(payload).digest() != digest:
        raise SandboxProtocolError("frame payload SHA-256 mismatch")
    decoded = _decode_canonical_json(payload)
    _validate_message_role(role, message_type, decoded)
    return Frame(role, message_type, sequence, decoded)


def read_frame(
    stream: BinaryIO,
    *,
    max_frame_size: int = MAX_FRAME_SIZE,
    reject_trailing: bool = True,
) -> Frame:
    if max_frame_size < FRAME_HEADER_SIZE:
        raise SandboxProtocolError("max_frame_size is smaller than the frame header")
    header = _read_exact(stream, FRAME_HEADER_SIZE)
    magic, version, role_id, message_id, sequence, payload_length, digest = FRAME_HEADER.unpack(header)
    if magic != FRAME_MAGIC:
        raise SandboxProtocolError("bad frame magic")
    if version != FRAME_VERSION:
        raise SandboxProtocolError("unsupported frame version")
    if role_id not in ID_ROLES:
        raise SandboxProtocolError("unknown frame role id")
    if message_id not in ID_MESSAGES:
        raise SandboxProtocolError("unknown frame message type id")
    if payload_length > max_frame_size - FRAME_HEADER_SIZE or payload_length > MAX_PAYLOAD_SIZE:
        raise SandboxProtocolError("oversize frame payload")
    payload = _read_exact(stream, payload_length)
    frame = decode_frame(header + payload, max_frame_size=max_frame_size)
    if reject_trailing:
        trailing = stream.read(1)
        if trailing not in (b"", None):
            raise SandboxProtocolError("stream contains trailing bytes")
    return frame


def read_next_frame(stream: BinaryIO, *, max_frame_size: int = MAX_FRAME_SIZE) -> Frame:
    """Read exactly one frame while leaving the next frame on a channel."""

    return read_frame(stream, max_frame_size=max_frame_size, reject_trailing=False)


def write_frame(stream: BinaryIO, frame: Frame | bytes) -> int:
    data = frame.to_bytes() if isinstance(frame, Frame) else frame
    if not isinstance(data, bytes):
        raise SandboxProtocolError("frame must be a Frame or bytes")
    decode_frame(data)
    written = 0
    while written < len(data):
        count = stream.write(data[written:])
        if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
            raise SandboxProtocolError("stream failed to make progress while writing")
        if count > len(data) - written:
            raise SandboxProtocolError("stream reported an oversized write")
        written += count
    return written


class ProtocolState:
    """Validate channel sequence monotonicity and one-shot action exchanges."""

    def __init__(self) -> None:
        self._last_sequence: dict[str, int] = {}
        self._last_turn: dict[str, int] = {}
        self._pending: dict[tuple[str, str], dict[str, Any]] = {}
        self._completed: set[tuple[str, str]] = set()
        self._session_id: str | None = None
        self._arm_claim_sha256: str | None = None

    @property
    def pending_request_ids(self) -> frozenset[str]:
        return frozenset(request_id for _, request_id in self._pending)

    def accept(self, frame: Frame) -> None:
        encoded = frame.to_bytes()
        checked = decode_frame(encoded)
        if checked != frame:
            raise SandboxProtocolError("frame is not canonical")
        previous = self._last_sequence.get(frame.role, 0)
        if frame.sequence != previous + 1:
            raise SandboxProtocolError("frame sequence is stale, replayed, or not contiguous")
        payload = frame.payload
        if frame.message_type == "ACTION_REQUEST":
            request = validate_action_request(payload)
            self._bind_session(request)
            key = (request["actor_role"], request["request_id"])
            if key in self._pending or key in self._completed:
                raise SandboxProtocolError("duplicate or replayed action request")
            prior_turn = self._last_turn.get(request["actor_role"])
            if prior_turn is not None and request["turn_id"] <= prior_turn:
                raise SandboxProtocolError("stale action request turn")
            self._last_turn[request["actor_role"]] = request["turn_id"]
            self._pending[key] = dict(request)
        elif frame.message_type == "ACTION_RESPONSE":
            response = validate_action_response(payload)
            self._bind_session(response)
            if response["actor_role"] != frame.role:
                raise SandboxProtocolError("response actor role does not match channel role")
            key = (frame.role, response["request_id"])
            request = self._pending.get(key)
            if request is None:
                raise SandboxProtocolError("response is stale or has no pending request")
            validate_action_response(
                response,
                legal_option_count=request["legal_option_count"],
                expected_request=request,
            )
            del self._pending[key]
            self._completed.add(key)
        elif frame.message_type == "HELLO":
            hello = validate_hello(payload, frame_role=frame.role)
            self._bind_session(hello)
        elif frame.message_type == "TERMINAL":
            terminal = validate_terminal(payload)
            self._bind_session(terminal)
            if self._pending:
                raise SandboxProtocolError("terminal frame leaves a pending action request")
        elif frame.message_type == "ERROR":
            error = validate_error(payload, frame_role=frame.role)
            self._bind_session(error)

        self._last_sequence[frame.role] = frame.sequence

    def _bind_session(self, message: Mapping[str, Any]) -> None:
        if self._session_id is None:
            self._session_id = message["session_id"]
            self._arm_claim_sha256 = message["arm_claim_sha256"]
            return
        if message["session_id"] != self._session_id:
            raise SandboxProtocolError("message session_id does not match protocol state")
        if message["arm_claim_sha256"] != self._arm_claim_sha256:
            raise SandboxProtocolError("message arm claim does not match protocol state")


class TranscriptAccumulator:
    """Deterministic hash chain over direction, sender, sequence, and frame bytes."""

    _DOMAIN = b"evaluation_v4_2_sandbox_transcript_v1"

    def __init__(self) -> None:
        self._digest = hashlib.sha256(self._DOMAIN).digest()

    def add(self, direction: str, frame: Frame | bytes) -> str:
        if direction not in {"referee_to_policy", "policy_to_referee"}:
            raise SandboxProtocolError("invalid transcript direction")
        data = frame.to_bytes() if isinstance(frame, Frame) else frame
        checked = decode_frame(data)
        direction_bytes = direction.encode("ascii")
        role_bytes = checked.role.encode("ascii")
        record = b"".join(
            (
                struct.pack("!I", len(direction_bytes)),
                direction_bytes,
                struct.pack("!I", len(role_bytes)),
                role_bytes,
                struct.pack("!Q", checked.sequence),
                struct.pack("!I", len(data)),
                data,
            )
        )
        self._digest = hashlib.sha256(self._digest + record).digest()
        return self.hexdigest

    @property
    def digest(self) -> bytes:
        return self._digest

    @property
    def hexdigest(self) -> str:
        return self._digest.hex()


SANDBOX_EXECUTION_SPEC = {
    "schema": PROTOCOL_SCHEMA + "_execution_spec_v1",
    "authority": DEVELOPMENT_ONLY,
    "containers": [
        {"name": "trusted_referee", "role": "referee"},
        {"name": "candidate_policy", "role": "candidate_policy"},
        {"name": "opponent_policy", "role": "opponent_policy"},
    ],
    "networking": False,
    "shared_writable_mounts": False,
    "external_action_deadlines": True,
    "action_deadline_enforcement": "external",
    "stderr_limit_bytes": MAX_STDERR_BYTES,
    "output_limit_bytes": MAX_AGGREGATE_OUTPUT_BYTES,
    "one_process_per_container": False,
    "external_authority": False,
    "remote_attestation_verified": False,
    "native_platform_verified": False,
    "latency_parity_allowed": False,
    "randomization_allowed": False,
    "anchor_allowed": False,
    "production_submission_authorized": False,
    "submit_authorized": False,
}


def sandbox_execution_spec() -> dict[str, Any]:
    """Return a detached copy of the frozen three-sandbox execution spec."""

    return json.loads(canonical_json_bytes(SANDBOX_EXECUTION_SPEC).decode("ascii"))


def validate_sandbox_execution_spec(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SandboxProtocolError("execution spec must be an object")
    actual = json.loads(canonical_json_bytes(dict(value)).decode("ascii"))
    expected = sandbox_execution_spec()
    if actual != expected:
        raise SandboxProtocolError("execution spec does not match the frozen development-only spec")
    return expected


__all__ = [
    "ACTION_REQUEST_SCHEMA",
    "ACTION_RESPONSE_SCHEMA",
    "AUTHORITY",
    "DEVELOPMENT_ONLY",
    "ERROR_SCHEMA",
    "FRAME_HEADER_SIZE",
    "FRAME_MAGIC",
    "FRAME_VERSION",
    "Frame",
    "HELLO_SCHEMA",
    "MAX_FRAME_SIZE",
    "MAX_AGGREGATE_OUTPUT_BYTES",
    "MAX_PAYLOAD_SIZE",
    "MAX_STDERR_BYTES",
    "MESSAGE_IDS",
    "POLICY_ROLES",
    "PROTOCOL_SCHEMA",
    "ProtocolState",
    "READY_SCHEMA",
    "SandboxProtocolError",
    "SANDBOX_EXECUTION_SPEC",
    "TERMINAL_SCHEMA",
    "TranscriptAccumulator",
    "canonical_json_bytes",
    "canonical_sha256",
    "decode_frame",
    "encode_frame",
    "read_frame",
    "read_next_frame",
    "sandbox_execution_spec",
    "validate_action_request",
    "validate_action_response",
    "validate_error",
    "validate_hello",
    "validate_ready",
    "validate_sandbox_execution_spec",
    "validate_terminal",
    "write_frame",
]
