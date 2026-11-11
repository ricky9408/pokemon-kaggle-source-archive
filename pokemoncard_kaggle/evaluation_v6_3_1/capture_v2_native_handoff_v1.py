"""Zero-authority Python boundary for the Capture V2 native prelaunch handoff.

The raw request codec in this module is deliberately local to the handoff
wire.  The general EIR codec has a smaller string limit than Amendment 4's
public-file-rows limit, while this boundary must preserve the exact original
CBOR bytes.  No function here reads the host, starts a process, issues a
permit, or grants any campaign authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .capture_v2_assembler import (
    CaptureV2AssemblyError,
    _bridge_decode,
    assemble_capture_v2_production,
)
from .capture_v2_manifest_v1 import (
    CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256,
    CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1,
    PATH_PROFILE_V2_CBOR,
    validate_argv_grammar_pin,
    validate_path_profile_v2,
    validate_requested_driver_argv_v1,
)
from .capture_v2_prelaunch_expectations import (
    PrelaunchExpectationsError,
    ValidatedPrelaunchExpectationsV2,
    _validate_frozen_prelaunch_expectations_v2,
    freeze_validated_prelaunch_expectations_v2,
)
from .eir_prebinding import EIRPrebindingError, eir_canonical_cbor_decode, eir_canonical_cbor_encode
from .m0_diagnostic_census import M0DiagnosticCensusError, _collector_profile
from .m0_diagnostic_primitives import (
    M0PrimitiveError,
    canonical_cbor_decode as diagnostic_cbor_decode,
    canonical_cbor_encode as diagnostic_cbor_encode,
    text as primitive_text,
)


PROTOCOL_ID = 631302
NATIVE_PRELAUNCH_HANDOFF_V1 = 1
RAW_PRELAUNCH_REQUEST_V1 = 1
RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1 = 67_108_864
RAW_PRELAUNCH_REQUEST_V1_MAX_BYTES = RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1
# The outer item contains a CBOR header, the 32-byte root, and the bstr header
# in addition to the raw request.  It has no separate protocol size limit.
NATIVE_PRELAUNCH_HANDOFF_MAX_BYTES_V1 = RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1 + 128
RAW_PRELAUNCH_REQUEST_SCHEMA_FROZEN = True
NATIVE_PRELAUNCH_HANDOFF_INVALID = "NATIVE_PRELAUNCH_HANDOFF_INVALID"
RAW_PRELAUNCH_REQUEST_INVALID = "RAW_PRELAUNCH_REQUEST_INVALID"

MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1 = 1_048_576
MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1 = 65_535
MAXIMUM_COLLECTOR_PROFILE_CBOR_BYTES_V1 = 16_777_216
MAXIMUM_PATH_PROFILE_CBOR_BYTES_V1 = 4_096
MAXIMUM_PUBLIC_FILE_ROWS_CBOR_BYTES_V1 = 50_331_648
MAXIMUM_RELATIVE_PATH_BYTES_V1 = 4_096
MAXIMUM_ARGV_ITEMS_V1 = 4_096
MAXIMUM_ARGV_ARGUMENT_BYTES_V1 = 1_048_576
MAXIMUM_REQUESTED_ARGV_CBOR_BYTES_V1 = 16_777_216
MAXIMUM_HARNESS_COMPONENT_BYTES_V1 = 1_073_741_824
MAXIMUM_HARNESS_BUILD_ID_BYTES_V1 = 65_535

ZERO_AUTHORITY = True
AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False
SEALED_HOLDOUT_ACCESS_AUTHORITY = False


class NativePrelaunchHandoffError(EIRPrebindingError):
    def __init__(
        self,
        message: str,
        code: str = NATIVE_PRELAUNCH_HANDOFF_INVALID,
    ) -> None:
        super().__init__(code, message)


def _fail(message: str, code: str = NATIVE_PRELAUNCH_HANDOFF_INVALID) -> NativePrelaunchHandoffError:
    return NativePrelaunchHandoffError(message, code)


class _NativeCaptureV3Transport(Protocol):
    """The one native call: exact handoff bytes in, exact bridge bytes out."""

    def __call__(self, handoff_bytes: bytes, /) -> bytes:
        ...


# The raw-request wire permits only uints, byte strings, UTF-8 text, and
# definite arrays.  This codec is intentionally not a general CBOR parser.
_RAW_CBOR_MAX_DEPTH = 64
_RAW_CBOR_MAX_NODES = 1_000_000
_RAW_CBOR_UINT_MAX = (1 << 64) - 1


def _raw_cbor_head(major: int, value: int) -> bytes:
    if type(value) is not int or value < 0 or value > _RAW_CBOR_UINT_MAX:
        raise _fail("raw request CBOR argument is outside uint64", RAW_PRELAUNCH_REQUEST_INVALID)
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")


def _raw_cbor_encode(
    value: Any,
    *,
    depth: int = 0,
    active: set[int] | None = None,
    maximum: int = RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1,
) -> bytes:
    if depth > _RAW_CBOR_MAX_DEPTH:
        raise _fail("raw request CBOR nesting exceeds the frozen limit", RAW_PRELAUNCH_REQUEST_INVALID)
    if active is None:
        active = set()
    if type(value) is int:
        if value < 0 or value > _RAW_CBOR_UINT_MAX:
            raise _fail("raw request contains a non-uint integer", RAW_PRELAUNCH_REQUEST_INVALID)
        return _raw_cbor_head(0, value)
    if type(value) is bytes:
        return _raw_cbor_head(2, len(value)) + value
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise _fail("raw request contains invalid UTF-8 text", RAW_PRELAUNCH_REQUEST_INVALID) from exc
        return _raw_cbor_head(3, len(encoded)) + encoded
    if type(value) not in (list, tuple):
        raise _fail("raw request CBOR permits arrays, uints, bstrs, and text only", RAW_PRELAUNCH_REQUEST_INVALID)
    if len(value) > _RAW_CBOR_MAX_NODES:
        raise _fail("raw request array exceeds the frozen node limit", RAW_PRELAUNCH_REQUEST_INVALID)
    identity = id(value)
    if identity in active:
        raise _fail("cyclic raw request values are forbidden", RAW_PRELAUNCH_REQUEST_INVALID)
    active.add(identity)
    try:
        parts = [_raw_cbor_head(4, len(value))]
        total = len(parts[0])
        for item in value:
            encoded = _raw_cbor_encode(
                item, depth=depth + 1, active=active, maximum=maximum
            )
            total += len(encoded)
            if total > maximum:
                raise _fail(
                    "raw request CBOR exceeds its frozen total-byte limit",
                    RAW_PRELAUNCH_REQUEST_INVALID,
                )
            parts.append(encoded)
        return b"".join(parts)
    finally:
        active.remove(identity)


class _RawCborDecoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.nodes = 0

    def _take(self, count: int) -> bytes:
        if count < 0 or count > len(self.raw) - self.offset:
            raise _fail("raw request CBOR is truncated", RAW_PRELAUNCH_REQUEST_INVALID)
        start = self.offset
        self.offset += count
        return self.raw[start:self.offset]

    def _visit(self, depth: int) -> None:
        if depth > _RAW_CBOR_MAX_DEPTH:
            raise _fail("raw request CBOR nesting exceeds the frozen limit", RAW_PRELAUNCH_REQUEST_INVALID)
        self.nodes += 1
        if self.nodes > _RAW_CBOR_MAX_NODES:
            raise _fail("raw request CBOR exceeds the frozen node limit", RAW_PRELAUNCH_REQUEST_INVALID)

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None:
            raise _fail("raw request uses an indefinite or reserved CBOR form", RAW_PRELAUNCH_REQUEST_INVALID)
        encoded = self._take(width)
        value = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 1 << 32}[width]
        if value < minimum:
            raise _fail("raw request CBOR integer or length is not shortest-form", RAW_PRELAUNCH_REQUEST_INVALID)
        return value

    def decode(self, depth: int = 0) -> Any:
        self._visit(depth)
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 0x1F
        if major == 0:
            return self._argument(additional)
        if major not in (2, 3, 4):
            raise _fail("raw request contains a forbidden CBOR major type", RAW_PRELAUNCH_REQUEST_INVALID)
        length = self._argument(additional)
        if major in (2, 3):
            payload = self._take(length)
            if major == 2:
                return payload
            try:
                return payload.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise _fail("raw request contains invalid UTF-8 text", RAW_PRELAUNCH_REQUEST_INVALID) from exc
        if length > _RAW_CBOR_MAX_NODES - self.nodes:
            raise _fail("raw request array exceeds the frozen node limit", RAW_PRELAUNCH_REQUEST_INVALID)
        return [self.decode(depth + 1) for _ in range(length)]


def _raw_cbor_decode(raw: bytes, *, maximum: int = RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise _fail("raw request CBOR has an invalid byte length", RAW_PRELAUNCH_REQUEST_INVALID)
    decoder = _RawCborDecoder(raw)
    value = decoder.decode()
    if decoder.offset != len(raw):
        raise _fail("raw request CBOR has trailing bytes", RAW_PRELAUNCH_REQUEST_INVALID)
    try:
        canonical = _raw_cbor_encode(value, maximum=maximum)
    except NativePrelaunchHandoffError:
        raise
    if canonical != raw:
        raise _fail("raw request CBOR is not canonical", RAW_PRELAUNCH_REQUEST_INVALID)
    return value


def _text(value: Any, label: str, *, maximum: int, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value) or "\x00" in value:
        raise _fail(f"{label} is not valid NUL-free text", RAW_PRELAUNCH_REQUEST_INVALID)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(f"{label} is not valid UTF-8", RAW_PRELAUNCH_REQUEST_INVALID) from exc
    if len(encoded) > maximum or (not allow_empty and not encoded):
        raise _fail(f"{label} exceeds its frozen byte limit", RAW_PRELAUNCH_REQUEST_INVALID)
    return value


def _uint(value: Any, label: str, *, minimum: int = 0, maximum: int = _RAW_CBOR_UINT_MAX) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise _fail(f"{label} is outside its frozen unsigned range", RAW_PRELAUNCH_REQUEST_INVALID)
    return value


def _bytes(value: Any, label: str, *, minimum: int = 0, maximum: int | None = None, exact: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise _fail(f"{label} must be a CBOR byte string", RAW_PRELAUNCH_REQUEST_INVALID)
    if exact is not None and len(value) != exact:
        raise _fail(f"{label} must be exactly {exact} bytes", RAW_PRELAUNCH_REQUEST_INVALID)
    if len(value) < minimum or (maximum is not None and len(value) > maximum):
        raise _fail(f"{label} exceeds its frozen byte limit", RAW_PRELAUNCH_REQUEST_INVALID)
    return bytes(value)


def _relative_path(value: Any, label: str) -> str:
    path = _text(value, label, maximum=MAXIMUM_RELATIVE_PATH_BYTES_V1)
    if path.startswith("/") or path.endswith("/") or "\\" in path:
        raise _fail(f"{label} is not a canonical relative path", RAW_PRELAUNCH_REQUEST_INVALID)
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise _fail(f"{label} is not a canonical relative path", RAW_PRELAUNCH_REQUEST_INVALID)
    return path


def _decode_embedded(raw: bytes, label: str, maximum: int) -> Any:
    value = _raw_cbor_decode(_bytes(raw, label, minimum=1, maximum=maximum), maximum=maximum)
    if type(value) is not list:
        raise _fail(f"{label} must contain one arrays-only CBOR item", RAW_PRELAUNCH_REQUEST_INVALID)
    return value


def _validate_collector_profile(raw: bytes, expected_label: str) -> bytes:
    raw = _bytes(raw, "collector_profile_cbor_bytes", minimum=1, maximum=MAXIMUM_COLLECTOR_PROFILE_CBOR_BYTES_V1)
    try:
        decoded = diagnostic_cbor_decode(raw)
        normalized = _collector_profile(decoded, raw)
        embedded_label = primitive_text(normalized[1], "collector profile build label")
    except (M0DiagnosticCensusError, M0PrimitiveError, TypeError, ValueError) as exc:
        raise _fail("collector profile is not the frozen canonical profile", RAW_PRELAUNCH_REQUEST_INVALID) from exc
    encoded_label = embedded_label.encode("utf-8", "strict")
    if not 1 <= len(encoded_label) <= MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1 or any(
        byte < 0x20 or byte > 0x7E for byte in encoded_label
    ):
        raise _fail("collector profile label violates printable ASCII", RAW_PRELAUNCH_REQUEST_INVALID)
    if embedded_label != expected_label or diagnostic_cbor_encode(normalized) != raw:
        raise _fail("collector profile does not match the frozen label or bytes", RAW_PRELAUNCH_REQUEST_INVALID)
    return raw


def _validate_path_profile(raw: bytes, working: str) -> bytes:
    raw = _bytes(raw, "path_profile_cbor_bytes", minimum=1, maximum=MAXIMUM_PATH_PROFILE_CBOR_BYTES_V1)
    try:
        value = eir_canonical_cbor_decode(raw)
        if value != [2, "/src", "/work", "/bin"] or eir_canonical_cbor_encode(value) != raw:
            raise ValueError("PATH_PROFILE_V2 differs")
    except (EIRPrebindingError, TypeError, ValueError) as exc:
        raise _fail("path profile is not the exact canonical PATH_PROFILE_V2", RAW_PRELAUNCH_REQUEST_INVALID) from exc
    if working != "work":
        raise _fail("working directory does not match PATH_PROFILE_V2", RAW_PRELAUNCH_REQUEST_INVALID)
    return raw


def _validate_public_rows(
    raw: bytes,
    primary: str,
    collector_profile_cbor_bytes: bytes,
) -> bytes:
    raw = _bytes(raw, "public_file_rows_cbor_bytes", minimum=1, maximum=MAXIMUM_PUBLIC_FILE_ROWS_CBOR_BYTES_V1)
    rows = _decode_embedded(raw, "public_file_rows_cbor_bytes", MAXIMUM_PUBLIC_FILE_ROWS_CBOR_BYTES_V1)
    previous: bytes | None = None
    collector_paths: list[str] = []
    primary_paths: list[str] = []
    topology: list[tuple[str, tuple[int, ...], int]] = []
    row_digests: dict[str, bytes] = {}
    for index, row in enumerate(rows):
        if type(row) is not list or len(row) != 5:
            raise _fail(f"public file row {index} has the wrong width", RAW_PRELAUNCH_REQUEST_INVALID)
        path = _relative_path(row[0], f"public_file_rows[{index}].path")
        path_bytes = path.encode("utf-8")
        if previous is not None and path_bytes <= previous:
            raise _fail("public file rows are not strictly UTF-8-byte sorted", RAW_PRELAUNCH_REQUEST_INVALID)
        previous = path_bytes
        roles = row[1]
        if type(roles) is not list or not roles:
            raise _fail("public file row roles must be a nonempty array", RAW_PRELAUNCH_REQUEST_INVALID)
        prior = 0
        for role in roles:
            role = _uint(role, f"public_file_rows[{index}].role", minimum=1)
            if role <= prior:
                raise _fail("public file row roles are not strictly increasing", RAW_PRELAUNCH_REQUEST_INVALID)
            prior = role
        _uint(row[2], f"public_file_rows[{index}].normalized_mode")
        _uint(row[3], f"public_file_rows[{index}].byte_length")
        digest = _bytes(
            row[4], f"public_file_rows[{index}].sha256", exact=32
        )
        topology.append((path, tuple(roles), row[2]))
        row_digests[path] = digest
        if 1 in roles:
            collector_paths.append(path)
        if 2 in roles:
            primary_paths.append(path)
    if not rows or collector_paths != ["bin/collector"]:
        raise _fail("public file rows must contain exactly one bin/collector role", RAW_PRELAUNCH_REQUEST_INVALID)
    if primary_paths != [primary]:
        raise _fail("public file rows do not contain exactly the primary source role", RAW_PRELAUNCH_REQUEST_INVALID)
    expected_topology = [
        ("bin/collector", (1,), 0o555),
        ("lib/ld-linux-x86-64.so.2", (6,), 0o444),
        ("lib/libc.so.6", (8,), 0o444),
        ("lib/libclang-cpp.so.16", (7, 8), 0o444),
        (primary, (2, 3), 0o444),
    ]
    if topology != expected_topology:
        raise _fail(
            "public file rows differ from the exact five-object capture topology",
            RAW_PRELAUNCH_REQUEST_INVALID,
        )
    try:
        profile = _collector_profile(
            diagnostic_cbor_decode(collector_profile_cbor_bytes),
            collector_profile_cbor_bytes,
        )
    except (M0DiagnosticCensusError, M0PrimitiveError, TypeError, ValueError) as exc:
        raise _fail(
            "collector profile cannot bind public file rows",
            RAW_PRELAUNCH_REQUEST_INVALID,
        ) from exc
    if (
        profile[0] != row_digests["bin/collector"]
        or profile[2] != row_digests["lib/libclang-cpp.so.16"]
        or profile[3] != 16
    ):
        raise _fail(
            "collector profile identity fields differ from retained runtime rows",
            RAW_PRELAUNCH_REQUEST_INVALID,
        )
    if _raw_cbor_encode(rows) != raw:
        raise _fail("public file rows are not byte-canonical", RAW_PRELAUNCH_REQUEST_INVALID)
    return raw


def _validate_requested_argv(
    value: Any,
    argv_grammar_version: int,
    argv_grammar_sha256: bytes,
    path_profile_cbor_bytes: bytes,
    working_directory_relative_path: str,
    primary_source: str,
) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAXIMUM_ARGV_ITEMS_V1:
        raise _fail("requested_argv has an invalid argument count", RAW_PRELAUNCH_REQUEST_INVALID)
    result: list[str] = []
    for index, argument in enumerate(value):
        result.append(
            _text(
                argument,
                f"requested_argv[{index}]",
                maximum=MAXIMUM_ARGV_ARGUMENT_BYTES_V1,
                allow_empty=index != 0,
            )
        )
        if "\x00" in argument or argument.startswith("@"):
            raise _fail("requested_argv contains a forbidden argument", RAW_PRELAUNCH_REQUEST_INVALID)
    encoded = _raw_cbor_encode(result)
    if len(encoded) > MAXIMUM_REQUESTED_ARGV_CBOR_BYTES_V1:
        raise _fail("requested_argv exceeds its encoded byte limit", RAW_PRELAUNCH_REQUEST_INVALID)
    try:
        return validate_requested_driver_argv_v1(
            argv_grammar_version=argv_grammar_version,
            argv_grammar_sha256=argv_grammar_sha256,
            path_profile_cbor_bytes=path_profile_cbor_bytes,
            working_directory_relative_path=working_directory_relative_path,
            primary_source_relative_path=primary_source,
            requested_argv=result,
        )
    except EIRPrebindingError as exc:
        raise _fail(
            "requested_argv violates the frozen inner Clang driver grammar",
            RAW_PRELAUNCH_REQUEST_INVALID,
        ) from exc


def _validate_harness(value: Any) -> tuple[tuple[int, bytes, bytes], ...]:
    if type(value) is not list or len(value) != 3:
        raise _fail("harness_expectations must contain entry, interpreter, supervisor", RAW_PRELAUNCH_REQUEST_INVALID)
    result: list[tuple[int, bytes, bytes]] = []
    for index, item in enumerate(value):
        if type(item) is not list or len(item) != 3:
            raise _fail(f"harness expectation {index} has the wrong width", RAW_PRELAUNCH_REQUEST_INVALID)
        length = _uint(item[0], f"harness_expectations[{index}].byte_length", minimum=1, maximum=MAXIMUM_HARNESS_COMPONENT_BYTES_V1)
        digest = _bytes(item[1], f"harness_expectations[{index}].sha256", exact=32)
        build_id = _bytes(item[2], f"harness_expectations[{index}].build_id_bytes", maximum=MAXIMUM_HARNESS_BUILD_ID_BYTES_V1)
        result.append((length, digest, build_id))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class RawPrelaunchRequestV1:
    """Decoded semantic form of the exact root-free 13-field request."""

    collector_profile_build_label_text: str
    expected_collector_gnu_build_id_descriptor_bytes: bytes
    collector_profile_cbor_bytes: bytes
    argv_grammar_version: int
    argv_grammar_sha256: bytes
    path_profile_cbor_bytes: bytes
    working_directory_relative_path: str
    primary_source_relative_path: str
    public_file_rows_cbor_bytes: bytes
    requested_argv: tuple[str, ...]
    harness_expectations: tuple[tuple[int, bytes, bytes], ...]

    def as_value(self) -> list[Any]:
        return [
            PROTOCOL_ID,
            RAW_PRELAUNCH_REQUEST_V1,
            self.collector_profile_build_label_text,
            self.expected_collector_gnu_build_id_descriptor_bytes,
            self.collector_profile_cbor_bytes,
            self.argv_grammar_version,
            self.argv_grammar_sha256,
            self.path_profile_cbor_bytes,
            self.working_directory_relative_path,
            self.primary_source_relative_path,
            self.public_file_rows_cbor_bytes,
            list(self.requested_argv),
            [list(item) for item in self.harness_expectations],
        ]

    @property
    def canonical_cbor_bytes(self) -> bytes:
        return _raw_cbor_encode(self.as_value())


def _decode_request_value(value: Any) -> RawPrelaunchRequestV1:
    if type(value) is not list or len(value) != 13:
        raise _fail("RAW_PRELAUNCH_REQUEST_V1 must contain exactly 13 fields", RAW_PRELAUNCH_REQUEST_INVALID)
    if value[0] != PROTOCOL_ID or value[1] != RAW_PRELAUNCH_REQUEST_V1:
        raise _fail("raw request protocol or version is not frozen V1", RAW_PRELAUNCH_REQUEST_INVALID)
    label = _text(value[2], "collector_profile_build_label_text", maximum=MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1)
    label_bytes = label.encode("utf-8")
    if any(byte < 0x20 or byte > 0x7E for byte in label_bytes):
        raise _fail("collector profile build label is not printable ASCII", RAW_PRELAUNCH_REQUEST_INVALID)
    descriptor = _bytes(value[3], "expected_collector_gnu_build_id_descriptor_bytes", minimum=1, maximum=MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1)
    collector = _validate_collector_profile(value[4], label)
    grammar_version = _uint(value[5], "argv_grammar_version", minimum=1, maximum=0xFFFFFFFF)
    grammar_digest = _bytes(value[6], "argv_grammar_sha256", exact=32)
    try:
        validate_argv_grammar_pin(grammar_version, grammar_digest)
    except EIRPrebindingError as exc:
        raise _fail("raw request does not bind the frozen argv grammar", RAW_PRELAUNCH_REQUEST_INVALID) from exc
    working = _relative_path(value[8], "working_directory_relative_path")
    primary = _relative_path(value[9], "primary_source_relative_path")
    path_profile = _validate_path_profile(value[7], working)
    if primary != "src/Export.cpp":
        raise _fail("primary_source_relative_path is not the frozen Export.cpp path", RAW_PRELAUNCH_REQUEST_INVALID)
    rows = _validate_public_rows(value[10], primary, collector)
    argv = _validate_requested_argv(
        value[11], grammar_version, grammar_digest, path_profile, working, primary
    )
    harness = _validate_harness(value[12])
    request = RawPrelaunchRequestV1(
        label,
        descriptor,
        collector,
        grammar_version,
        grammar_digest,
        path_profile,
        working,
        primary,
        rows,
        argv,
        harness,
    )
    if request.as_value() != value:
        raise _fail("raw request fields failed canonical semantic normalization", RAW_PRELAUNCH_REQUEST_INVALID)
    return request


def decode_raw_prelaunch_request_v1(raw: bytes, /) -> RawPrelaunchRequestV1:
    value = _raw_cbor_decode(raw)
    return _decode_request_value(value)


def _validate_raw_prelaunch_request(raw: bytes) -> bytes:
    """Validate one request while retaining the caller's exact bytes."""

    request = decode_raw_prelaunch_request_v1(raw)
    if request.canonical_cbor_bytes != raw:
        raise _fail("raw request bytes were normalized", RAW_PRELAUNCH_REQUEST_INVALID)
    return raw


def _request_from_expectations(artifact: ValidatedPrelaunchExpectationsV2) -> RawPrelaunchRequestV1:
    """Derive the root-free V1 wire solely from the rooted V2 commitment."""

    if type(artifact) is not ValidatedPrelaunchExpectationsV2:
        raise _fail("raw request requires the rooted V2 prelaunch expectations artifact", RAW_PRELAUNCH_REQUEST_INVALID)
    try:
        _validate_frozen_prelaunch_expectations_v2(artifact)
        return _decode_request_value([
            PROTOCOL_ID,
            RAW_PRELAUNCH_REQUEST_V1,
            artifact.collector_profile_build_label_text,
            artifact.expected_collector_gnu_build_id_descriptor_bytes,
            artifact.collector_profile_cbor_bytes,
            artifact.argv_grammar_version,
            artifact.argv_grammar_sha256,
            artifact.path_profile_cbor_bytes,
            artifact.working_directory_relative_path,
            artifact.primary_source_relative_path,
            artifact.public_file_rows_cbor_bytes,
            list(artifact.requested_argv),
            [list(item) for item in artifact.harness_expectations],
        ])
    except (NativePrelaunchHandoffError, EIRPrebindingError) as exc:
        raise _fail("opaque expectations artifact contains invalid raw-request leaves", RAW_PRELAUNCH_REQUEST_INVALID) from exc


def to_raw_prelaunch_request_v1(
    artifact: ValidatedPrelaunchExpectationsV2,
    /,
) -> RawPrelaunchRequestV1:
    """The sole production derivation of RAW_PRELAUNCH_REQUEST_V1."""

    return _request_from_expectations(artifact)


def encode_raw_prelaunch_request_v1(
    artifact: ValidatedPrelaunchExpectationsV2,
    /,
) -> bytes:
    """Encode raw V1 only from an immutable rooted V2 artifact."""

    return to_raw_prelaunch_request_v1(artifact).canonical_cbor_bytes


def _cross_check_request(artifact: ValidatedPrelaunchExpectationsV2, raw: RawPrelaunchRequestV1) -> None:
    if type(artifact) is not ValidatedPrelaunchExpectationsV2:
        raise _fail(
            "raw request requires the rooted V2 prelaunch expectations artifact",
            RAW_PRELAUNCH_REQUEST_INVALID,
        )
    expected_value = [
        PROTOCOL_ID,
        RAW_PRELAUNCH_REQUEST_V1,
        artifact.collector_profile_build_label_text,
        artifact.expected_collector_gnu_build_id_descriptor_bytes,
        artifact.collector_profile_cbor_bytes,
        artifact.argv_grammar_version,
        artifact.argv_grammar_sha256,
        artifact.path_profile_cbor_bytes,
        artifact.working_directory_relative_path,
        artifact.primary_source_relative_path,
        artifact.public_file_rows_cbor_bytes,
        list(artifact.requested_argv),
        [list(item) for item in artifact.harness_expectations],
    ]
    if raw.as_value() != expected_value:
        fields = (
            "collector label", "collector build ID", "collector profile", "argv grammar version",
            "argv grammar digest", "path profile", "working directory", "primary source",
            "public file rows", "requested argv", "harness expectations",
        )
        for field, actual, frozen in zip(
            fields, raw.as_value()[2:], expected_value[2:]
        ):
            if actual != frozen:
                raise _fail(f"raw request {field} differs from opaque expectations", RAW_PRELAUNCH_REQUEST_INVALID)
        raise _fail("raw request differs from opaque expectations", RAW_PRELAUNCH_REQUEST_INVALID)


def _encode_native_prelaunch_handoff_v1(
    expectations_root: bytes,
    raw_prelaunch_request_cbor: bytes,
    /,
) -> bytes:
    """Encode exactly one outer root-bearing handoff item."""

    if type(expectations_root) is not bytes or len(expectations_root) != 32:
        raise _fail("handoff expectations root must be exactly 32 bytes")
    request = decode_raw_prelaunch_request_v1(raw_prelaunch_request_cbor)
    value = [PROTOCOL_ID, NATIVE_PRELAUNCH_HANDOFF_V1, bytes(expectations_root), request.canonical_cbor_bytes]
    encoded = _raw_cbor_encode(value, maximum=NATIVE_PRELAUNCH_HANDOFF_MAX_BYTES_V1)
    decoded = _decode_handoff(encoded)
    if decoded[2] != expectations_root or decoded[3] != request.canonical_cbor_bytes:
        raise _fail("handoff encoder round trip failed")
    return encoded


def to_native_prelaunch_handoff(
    artifact: ValidatedPrelaunchExpectationsV2,
    /,
) -> bytes:
    """Derive the exact outer handoff from one rooted V2 artifact."""

    raw = to_raw_prelaunch_request_v1(artifact)
    _cross_check_request(artifact, raw)
    return _encode_native_prelaunch_handoff_v1(
        artifact.validated_prelaunch_expectations_root,
        raw.canonical_cbor_bytes,
    )


@dataclass(frozen=True, slots=True)
class DirectInProcessClangCollectorLaunchContractV2:
    """The exact collector executable, context, and argv derived from V2."""

    executable_path: str
    absolute_primary: str
    capture_context_cbor_bytes: bytes
    capture_context_hex: str
    argv: tuple[str, ...]


def derive_direct_in_process_clang_collector_launch_contract_v2(
    artifact: ValidatedPrelaunchExpectationsV2,
    /,
) -> DirectInProcessClangCollectorLaunchContractV2:
    """Derive the sole in-process Clang collector launch contract."""

    raw = to_raw_prelaunch_request_v1(artifact)
    _cross_check_request(artifact, raw)
    return _derive_direct_in_process_clang_collector_launch_contract_from_raw(raw)


def _derive_direct_in_process_clang_collector_launch_contract_from_raw(
    raw: RawPrelaunchRequestV1,
    /,
) -> DirectInProcessClangCollectorLaunchContractV2:
    rows = _decode_embedded(
        raw.public_file_rows_cbor_bytes,
        "public_file_rows_cbor_bytes",
        MAXIMUM_PUBLIC_FILE_ROWS_CBOR_BYTES_V1,
    )
    collector = [row[0] for row in rows if 1 in row[1]]
    if collector != ["bin/collector"]:
        raise _fail("rooted public rows do not bind one collector executable")
    try:
        decoded_path_profile = eir_canonical_cbor_decode(
            raw.path_profile_cbor_bytes
        )
        profile = validate_path_profile_v2(
            decoded_path_profile,
            raw.working_directory_relative_path,
        )
    except EIRPrebindingError as exc:
        raise _fail("rooted path profile cannot derive the collector launch") from exc
    source_relative_prefix = profile.source_absolute_prefix.removeprefix("/")
    if not raw.primary_source_relative_path.startswith(
        source_relative_prefix + "/"
    ):
        raise _fail("rooted primary source is outside PATH_PROFILE_V2")
    absolute_primary = "/" + raw.primary_source_relative_path
    if not absolute_primary.startswith(profile.source_absolute_prefix + "/"):
        raise _fail("rooted primary source cannot derive its absolute path")
    context_bytes = eir_canonical_cbor_encode(
        [
            1,
            raw.primary_source_relative_path,
            decoded_path_profile,
        ]
    )
    context_hex = context_bytes.hex()
    executable_path = "/bin/collector"
    argv = (
        executable_path,
        "--protocol=631302",
        "--level=2",
        "--primary-source=" + absolute_primary,
        "--capture-context-v1-cbor-hex=" + context_hex,
        "--",
        *raw.requested_argv,
    )
    return DirectInProcessClangCollectorLaunchContractV2(
        executable_path=executable_path,
        absolute_primary=absolute_primary,
        capture_context_cbor_bytes=context_bytes,
        capture_context_hex=context_hex,
        argv=argv,
    )


def _decode_handoff(raw: bytes) -> list[Any]:
    if type(raw) is not bytes or not raw:
        raise _fail("handoff must be immutable nonempty bytes")
    try:
        value = _raw_cbor_decode(raw, maximum=NATIVE_PRELAUNCH_HANDOFF_MAX_BYTES_V1)
    except NativePrelaunchHandoffError:
        raise
    if type(value) is not list or len(value) != 4:
        raise _fail("handoff must contain exactly four fields")
    if value[0] != PROTOCOL_ID or value[1] != NATIVE_PRELAUNCH_HANDOFF_V1:
        raise _fail("handoff protocol or version is not frozen V1")
    if type(value[2]) is not bytes or len(value[2]) != 32:
        raise _fail("handoff root is not exactly 32 bytes")
    request = decode_raw_prelaunch_request_v1(value[3])
    if request.canonical_cbor_bytes != value[3]:
        raise _fail("handoff raw request bytes were normalized")
    if _raw_cbor_encode(value, maximum=NATIVE_PRELAUNCH_HANDOFF_MAX_BYTES_V1) != raw:
        raise _fail("handoff is not byte-canonical")
    return value


@dataclass(frozen=True, slots=True)
class RawPrelaunchInput:
    """One trusted semantic source for the opaque artifact and raw request."""

    collector_profile_build_label_text: str
    expected_collector_gnu_build_id_descriptor_bytes: bytes
    collector_profile_cbor_bytes: bytes
    path_profile_cbor_bytes: bytes
    working_directory_relative_path: str
    primary_source_relative_path: str
    raw_prelaunch_request_cbor: bytes | None = None
    argv_grammar_version: int = CLANG16_CAPTURE_PROFILE_GRAMMAR_VERSION_V1
    argv_grammar_sha256: bytes = CLANG16_CAPTURE_PROFILE_GRAMMAR_V1_SHA256
    public_file_rows_cbor_bytes: bytes | None = None
    requested_argv: tuple[str, ...] | None = None
    harness_expectations: tuple[tuple[int, bytes, bytes], ...] | None = None


@dataclass(frozen=True, slots=True)
class _NativeCapturePrelaunchSessionV1:
    expectations: ValidatedPrelaunchExpectationsV2
    expectations_root: bytes
    raw_request: RawPrelaunchRequestV1
    handoff_bytes: bytes


def _prepare_session(raw_input: RawPrelaunchInput) -> _NativeCapturePrelaunchSessionV1:
    if not isinstance(raw_input, RawPrelaunchInput):
        raise _fail("prelaunch session requires RawPrelaunchInput")
    if raw_input.public_file_rows_cbor_bytes is None or raw_input.requested_argv is None or raw_input.harness_expectations is None:
        raise _fail("prelaunch input is missing Amendment 4 raw-request leaves", RAW_PRELAUNCH_REQUEST_INVALID)
    # The opaque object is frozen first. No caller-controlled raw field is
    # reconstructed or modified after this point; the wire is derived only
    # from the artifact's immutable typed leaves.
    try:
        expectations = freeze_validated_prelaunch_expectations_v2(
            collector_profile_build_label_text=raw_input.collector_profile_build_label_text,
            expected_collector_gnu_build_id_descriptor_bytes=raw_input.expected_collector_gnu_build_id_descriptor_bytes,
            collector_profile_cbor_bytes=raw_input.collector_profile_cbor_bytes,
            argv_grammar_version=raw_input.argv_grammar_version,
            argv_grammar_sha256=raw_input.argv_grammar_sha256,
            path_profile_cbor_bytes=raw_input.path_profile_cbor_bytes,
            working_directory_relative_path=raw_input.working_directory_relative_path,
            primary_source_relative_path=raw_input.primary_source_relative_path,
            public_file_rows_cbor_bytes=raw_input.public_file_rows_cbor_bytes,
            requested_argv=raw_input.requested_argv,
            harness_expectations=raw_input.harness_expectations,
        )
    except PrelaunchExpectationsError as exc:
        raise _fail("V2 prelaunch expectations failed closed", RAW_PRELAUNCH_REQUEST_INVALID) from exc
    handoff = to_native_prelaunch_handoff(expectations)
    decoded = _decode_handoff(handoff)
    raw_request = decode_raw_prelaunch_request_v1(decoded[3])
    _cross_check_request(expectations, raw_request)
    raw_request_cbor = raw_request.canonical_cbor_bytes
    if _raw_cbor_decode(raw_request_cbor) != raw_request.as_value():
        raise _fail(
            "encoded raw request differs from the opaque artifact",
            RAW_PRELAUNCH_REQUEST_INVALID,
        )
    if raw_input.raw_prelaunch_request_cbor is not None:
        if (
            type(raw_input.raw_prelaunch_request_cbor) is not bytes
            or raw_input.raw_prelaunch_request_cbor != raw_request_cbor
        ):
            raise _fail(
                "caller raw request differs from the trusted semantic source",
                RAW_PRELAUNCH_REQUEST_INVALID,
            )
    root = expectations.validated_prelaunch_expectations_root
    if decoded[2] != root:
        raise _fail("handoff root differs from the retained artifact root")
    _derive_direct_in_process_clang_collector_launch_contract_from_raw(raw_request)
    return _NativeCapturePrelaunchSessionV1(expectations, root, raw_request, handoff)


def _produce_capture_v2_with_test_transport(
    raw_prelaunch_input: RawPrelaunchInput,
    native_transport: _NativeCaptureV3Transport,
    /,
) -> bytes:
    """Test-only orchestration seam for cross-language fixture transports."""

    if not isinstance(raw_prelaunch_input, RawPrelaunchInput):
        raise _fail("production orchestration requires RawPrelaunchInput")
    if not callable(native_transport):
        raise _fail("native transport must be a callable typed boundary")
    session = _prepare_session(raw_prelaunch_input)
    try:
        private_bridge = native_transport(session.handoff_bytes)
    except Exception as exc:
        raise _fail("native transport failed closed") from exc
    if type(private_bridge) is not bytes:
        raise _fail("native transport must return exactly one immutable bridge")
    try:
        bridge = _bridge_decode(private_bridge)
    except (CaptureV2AssemblyError, EIRPrebindingError) as exc:
        raise _fail("native transport returned an invalid private bridge") from exc
    if len(bridge) != 10 or bridge[4][1] != session.expectations_root:
        raise _fail("private bridge root differs from the retained artifact root")
    try:
        return assemble_capture_v2_production(private_bridge, session.expectations)
    except CaptureV2AssemblyError as exc:
        raise _fail("production Capture V2 assembly failed") from exc


def produce_capture_v2_via_native(
    raw_prelaunch_input: RawPrelaunchInput,
    /,
) -> bytes:
    """Fail closed until loaded native-image custody is actually implemented."""

    if not isinstance(raw_prelaunch_input, RawPrelaunchInput):
        raise _fail("production orchestration requires RawPrelaunchInput")
    raise _fail(
        "native production loaded-image custody is not implemented; "
        "the injectable bridge is test-only"
    )


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "CALIBRATION_UPLOAD_AUTHORITY",
    "HOLDOUT_ACCESS_AUTHORITY",
    "MAXIMUM_ARGV_ARGUMENT_BYTES_V1",
    "MAXIMUM_ARGV_ITEMS_V1",
    "MAXIMUM_COLLECTOR_PROFILE_CBOR_BYTES_V1",
    "MAXIMUM_GNU_BUILD_ID_DESCRIPTOR_BYTES_V1",
    "MAXIMUM_HARNESS_BUILD_ID_BYTES_V1",
    "MAXIMUM_HARNESS_COMPONENT_BYTES_V1",
    "MAXIMUM_PATH_PROFILE_CBOR_BYTES_V1",
    "MAXIMUM_PROFILE_BUILD_LABEL_BYTES_V1",
    "MAXIMUM_PUBLIC_FILE_ROWS_CBOR_BYTES_V1",
    "MAXIMUM_RELATIVE_PATH_BYTES_V1",
    "MAXIMUM_REQUESTED_ARGV_CBOR_BYTES_V1",
    "NATIVE_PRELAUNCH_HANDOFF_MAX_BYTES_V1",
    "NATIVE_PRELAUNCH_HANDOFF_INVALID",
    "NATIVE_PRELAUNCH_HANDOFF_V1",
    "NativePrelaunchHandoffError",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "RAW_PRELAUNCH_REQUEST_INVALID",
    "RAW_PRELAUNCH_REQUEST_MAX_BYTES_V1",
    "RAW_PRELAUNCH_REQUEST_SCHEMA_FROZEN",
    "RAW_PRELAUNCH_REQUEST_V1",
    "RAW_PRELAUNCH_REQUEST_V1_MAX_BYTES",
    "RawPrelaunchInput",
    "RawPrelaunchRequestV1",
    "SEALED_HOLDOUT_ACCESS_AUTHORITY",
    "UPLOAD_AUTHORITY",
    "ValidatedPrelaunchExpectationsV2",
    "_NativeCapturePrelaunchSessionV1",
    "_decode_handoff",
    "_prepare_session",
    "_validate_raw_prelaunch_request",
    "decode_raw_prelaunch_request_v1",
    "DirectInProcessClangCollectorLaunchContractV2",
    "derive_direct_in_process_clang_collector_launch_contract_v2",
    "encode_raw_prelaunch_request_v1",
    "produce_capture_v2_via_native",
    "to_native_prelaunch_handoff",
    "to_raw_prelaunch_request_v1",
]
