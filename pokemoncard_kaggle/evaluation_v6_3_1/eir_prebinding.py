"""Pure zero-authority compiler-prebinding v2 validation for EIR-631302.

The module accepts already-materialized values only.  It performs lexical
normalization, schema checks, canonical-CBOR hashing, and graph closure.  It
does not read host state, execute programs, access archives or sealed data,
or provide campaign, permit, upload, engine-wiring, or modification authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha256
import json
import posixpath
from typing import Any, Sequence


PROTOCOL_ID = 631302
WIRE_VERSION = 2
PREBINDING_SCHEMA = "V631302_COMPILER_PREBINDING_1"
FIXED_TARGET_ROOT = bytes.fromhex(
    "e7945c89633e0bf4e4f56ed2830d7126e78055ca280b6e19e69a817b9a48bdde"
)
ZERO32 = bytes(32)

ZERO_AUTHORITY = True
AUTHORITY = False
ENGINE_WIRING_AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
UNFROZEN_CANDIDATE_EIR_ROOT = "UNFROZEN_CANDIDATE_EIR_ROOT"

QUAL_TYPE_NON_ASCII = "QUAL_TYPE_NON_ASCII"
QUAL_TYPE_UNSUPPORTED_TOKEN = "QUAL_TYPE_UNSUPPORTED_TOKEN"
QUAL_TYPE_SPLIT_PUNCTUATOR = "QUAL_TYPE_SPLIT_PUNCTUATOR"
QUAL_TYPE_UNBALANCED_DELIMITER = "QUAL_TYPE_UNBALANCED_DELIMITER"
QUAL_TYPE_INVALID_COMMA = "QUAL_TYPE_INVALID_COMMA"
QUAL_TYPE_AMBIGUOUS_ANGLE = "QUAL_TYPE_AMBIGUOUS_ANGLE"
QUAL_TYPE_EMPTY = "QUAL_TYPE_EMPTY"
QUAL_TYPE_IDENTITY_MISMATCH = "QUAL_TYPE_IDENTITY_MISMATCH"

PREBINDING_INVALID_TYPE = "PREBINDING_INVALID_TYPE"
PREBINDING_INVALID_WIDTH = "PREBINDING_INVALID_WIDTH"
PREBINDING_INVALID_BSTR32 = "PREBINDING_INVALID_BSTR32"
PREBINDING_INVALID_TEXT = "PREBINDING_INVALID_TEXT"
PREBINDING_NONCANONICAL_TEXT = "PREBINDING_NONCANONICAL_TEXT"
PREBINDING_SCHEMA_INVALID = "PREBINDING_SCHEMA_INVALID"
PREBINDING_ORDER_INVALID = "PREBINDING_ORDER_INVALID"
PREBINDING_DENSE_ORDINAL_INVALID = "PREBINDING_DENSE_ORDINAL_INVALID"
PREBINDING_ROOT_MISMATCH = "PREBINDING_ROOT_MISMATCH"
PREBINDING_CANONICAL_ENCODING = "PREBINDING_CANONICAL_ENCODING"
TARGET_REGISTRY_MISMATCH = "TARGET_REGISTRY_MISMATCH"
HELPER_ID_MISMATCH = "HELPER_ID_MISMATCH"
HELPER_SCOPE_INVALID = "HELPER_SCOPE_INVALID"
HELPER_DECLARATION_INVALID = "HELPER_DECLARATION_INVALID"
FUNCTION_SCAN_INVALID = "FUNCTION_SCAN_INVALID"
TERMINAL_COHERENCE_INVALID = "TERMINAL_COHERENCE_INVALID"
BACKEND_REGISTRY_INVALID = "BACKEND_REGISTRY_INVALID"
GRAPH_CLOSURE_INVALID = "GRAPH_CLOSURE_INVALID"
UNRESOLVED_REACHABLE_CALL = "UNRESOLVED_REACHABLE_CALL"
NON_CONTIGUOUS_DEFINITION_BYTES = "NON_CONTIGUOUS_DEFINITION_BYTES"
UNLISTED_EXECUTABLE = "UNLISTED_EXECUTABLE"
RESPONSE_FILE_SYNTAX_FORBIDDEN = "RESPONSE_FILE_SYNTAX_FORBIDDEN"
COMPILER_CONFIG_FILE_FORBIDDEN = "COMPILER_CONFIG_FILE_FORBIDDEN"
STDIN_INPUT_FORBIDDEN = "STDIN_INPUT_FORBIDDEN"
VALIDATOR_STATE_NON_MONOTONIC = "VALIDATOR_STATE_NON_MONOTONIC"
VALIDATOR_EVIDENCE_UNAVAILABLE = "VALIDATOR_EVIDENCE_UNAVAILABLE"
CANDIDATE_EIR_SCHEMA_UNAVAILABLE = "CANDIDATE_EIR_SCHEMA_UNAVAILABLE"

STRUCTURAL_ONLY_EVIDENCE_SCOPE = "SCHEMA_AND_STRUCTURAL_CLOSURE_ONLY"
OPEN_EVIDENCE_REQUIREMENTS = (
    "ODR_DEFINITION_INSTANCE_EQUIVALENCE",
    "TU_SCOPE_HASH_DERIVATION",
    "ENTRYPOINT_NO_SHEBANG",
    "RUNTIME_MANIFEST_EXHAUSTIVENESS",
    "COMPILER_SCAN_COMPLETENESS",
    "EXTERNAL_TERMINAL_AUTHENTICATION",
)

DS_SITE_ID = b"V631302/SITE_ID\x00"
DS_HELPER_ID = b"V631302/HELPER_ID\x00"
DS_HELPER_SITE_ID = b"V631302/HELPER_SITE_ID\x00"
DS_FUNCTION_DEFINITION = b"V631302/FUNCTION_DEFINITION\x00"
DS_TOOLCHAIN_RUNTIME_ROOT = b"V631302/TOOLCHAIN_RUNTIME_ROOT\x00"
DS_COMPILER_SEMANTICS_ROOT = b"V631302/COMPILER_SEMANTICS_ROOT\x00"
DS_BACKEND_MATCHER_ROOT = b"V631302/BACKEND_MATCHER_ROOT\x00"
DS_EXTERNAL_TERMINAL_ROOT = b"V631302/EXTERNAL_TERMINAL_ROOT\x00"
DS_TARGET_SEED_ROOT = b"V631302/TARGET_SEED_ROOT\x00"
DS_HELPER_DECLARATION_ROOT = b"V631302/HELPER_DECLARATION_ROOT\x00"
DS_FUNCTION_SCAN_ROOT = b"V631302/FUNCTION_SCAN_ROOT\x00"
DS_HELPER_CLOSURE_ROOT = b"V631302/HELPER_CLOSURE_ROOT\x00"
DS_PREBINDING_ROOT = b"V631302/COMPILER_PREBINDING_ROOT\x00"
DS_EIR_ROOT = b"V631302/EIR_ROOT\x00"

LINKAGE_ODR_MERGEABLE = 1
LINKAGE_TRANSLATION_UNIT_LOCAL = 2
BACKEND_RANDOM_DEVICE = 1
BACKEND_GAME_RNG = 2
PRIMITIVE_RAW_SCALAR_WORD = 1
DRAW_ONE_RAW_SCALAR_PER_CALL = 1

TARGET_REF = 0
HELPER_REF = 1
TERMINAL_REF = 2
INVOCATION_KINDS = frozenset(range(1, 9))
RESOLUTION_EXACT_SINGLE = 1
RESOLUTION_EXACT_FINITE_SET = 2

ENVIRONMENT = [
    ["HOME", "/nonexistent"],
    ["LANG", "C"],
    ["LC_ALL", "C"],
    ["SOURCE_DATE_EPOCH", "0"],
    ["TMPDIR", "/v631302/work/tmp"],
    ["TZ", "UTC"],
]

_MULTI = ("->*", "...", "::", "&&", "->", ".*")
_SINGLE = frozenset("()[]<>,*&=+-/%!~?:.^|")
_ASCII_WHITESPACE = frozenset("\x09\x0a\x0b\x0c\x0d ")
_CV_QUALIFIERS = frozenset({"const", "volatile", "noexcept", "restrict"})
_CONFIG_FLAGS = ("--config", "--config-system-dir", "--config-user-dir")

_CBOR_MAX_DEPTH = 64
_CBOR_MAX_CONTAINER_ITEMS = 250_000
_CBOR_MAX_NODES = 1_000_000
_CBOR_MAX_STRING_BYTES = 16 * 1024 * 1024
_CBOR_MAX_ENCODED_BYTES = 64 * 1024 * 1024
_UINT64_MAX = (1 << 64) - 1


class EIRPrebindingError(ValueError):
    """A prebinding value failed closed with a stable error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ValidatorState(IntEnum):
    BYTE_VALID = 1
    STRUCTURAL_CLOSURE_VALID = 2
    COMPILER_RECOMPUTED = 3
    EXTERNAL_EVIDENCE_VALID = 4


@dataclass(frozen=True)
class PrebindingValidation:
    state: ValidatorState
    component_roots: tuple[bytes, ...]
    prebinding_root: bytes
    evidence_scope: str = STRUCTURAL_ONLY_EVIDENCE_SCOPE
    compiler_recomputed: bool = False
    external_evidence_valid: bool = False
    open_evidence_requirements: tuple[str, ...] = OPEN_EVIDENCE_REQUIREMENTS
    authority: bool = False
    engine_wiring_authority: bool = False
    upload_authority: bool = False
    permit_authority: bool = False
    holdout_access_authority: bool = False
    agent_modification_authority: bool = False


@dataclass(frozen=True)
class CandidateEIRHash:
    state: str
    digest: bytes
    authority: bool = False
    engine_wiring_authority: bool = False
    upload_authority: bool = False
    permit_authority: bool = False
    holdout_access_authority: bool = False
    agent_modification_authority: bool = False


def _fail(code: str, message: str) -> EIRPrebindingError:
    return EIRPrebindingError(code, message)


def _array(value: Any, label: str) -> Sequence[Any]:
    if type(value) not in (list, tuple):
        raise _fail(PREBINDING_INVALID_TYPE, f"{label} must be a CBOR array")
    return value


def _text(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str:
        raise _fail(PREBINDING_INVALID_TYPE, f"{label} must be text")
    if nonempty and not value:
        raise _fail(PREBINDING_INVALID_TEXT, f"{label} must not be empty")
    if "\x00" in value:
        raise _fail(PREBINDING_INVALID_TEXT, f"{label} must be NUL-free")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(PREBINDING_INVALID_TEXT, f"{label} is not valid UTF-8") from exc
    return value


def _uint(value: Any, bits: int, label: str) -> int:
    if type(value) is not int:
        raise _fail(PREBINDING_INVALID_TYPE, f"{label} must be an unsigned integer")
    if value < 0 or value >= 1 << bits:
        raise _fail(PREBINDING_INVALID_WIDTH, f"{label} does not fit uint{bits}")
    return value


def _bstr(value: Any, label: str) -> bytes:
    if type(value) is not bytes:
        raise _fail(PREBINDING_INVALID_TYPE, f"{label} must be a byte string")
    return value


def _bstr32(value: Any, label: str) -> bytes:
    value = _bstr(value, label)
    if len(value) != 32:
        raise _fail(PREBINDING_INVALID_BSTR32, f"{label} must be exactly 32 bytes")
    return value


def _canonical_path(value: Any, label: str) -> str:
    path = _text(value, label)
    if not path.startswith("/") or (path != "/" and path.endswith("/")):
        raise _fail(PREBINDING_INVALID_TEXT, f"{label} must be an absolute canonical POSIX path")
    if path == "/":
        return path
    components = path[1:].split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _fail(PREBINDING_INVALID_TEXT, f"{label} has an invalid path component")
    return path


def _canonical_encode(value: Any) -> bytes:
    return _PrebindingCBOREncoder().encode(value)


def eir_canonical_cbor_encode(value: Any) -> bytes:
    """Encode one arrays-only EIR value without Unicode normalization.

    Protocol 631302 commits to the exact valid UTF-8 bytes supplied by Clang
    and the manifests.  This intentionally differs from the trace codec,
    whose separate wire profile requires NFC-normalized text.
    """

    return _canonical_encode(value)


def eir_canonical_cbor_decode(raw: bytes) -> Any:
    """Decode one strict arrays-only EIR value without Unicode normalization.

    The private decoder rejects noncanonical or forbidden CBOR forms and
    trailing bytes.  Re-encoding the result keeps this public boundary bound
    to the same deterministic encoder used for EIR commitments.
    """

    value = _canonical_decode(raw)
    if type(value) is not list:
        raise _fail(PREBINDING_INVALID_TYPE, "top-level EIR value must be an array")
    if _canonical_encode(value) != raw:
        raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR bytes are not canonical")
    return value


def _cbor_head(major: int, value: int) -> bytes:
    if value < 0:
        raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR argument is negative")
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + value.to_bytes(4, "big")
    if value <= _UINT64_MAX:
        return bytes(((major << 5) | 27,)) + value.to_bytes(8, "big")
    raise _fail(PREBINDING_INVALID_WIDTH, "CBOR argument exceeds uint64")


class _PrebindingCBOREncoder:
    """Exact-UTF-8 deterministic CBOR for the prebinding arrays-only profile."""

    def __init__(self) -> None:
        self.nodes = 0
        self.active: set[int] = set()

    def _visit(self, depth: int) -> None:
        if depth > _CBOR_MAX_DEPTH:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR nesting exceeds the profile limit")
        self.nodes += 1
        if self.nodes > _CBOR_MAX_NODES:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR node count exceeds the profile limit")

    def encode(self, value: Any, depth: int = 0) -> bytes:
        self._visit(depth)
        if type(value) is int:
            if value < 0 or value > _UINT64_MAX:
                raise _fail(PREBINDING_INVALID_WIDTH, "wire integer is outside uint64")
            return _cbor_head(0, value)
        if type(value) is bytes:
            if len(value) > _CBOR_MAX_STRING_BYTES:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR byte string exceeds the profile limit")
            return _cbor_head(2, len(value)) + value
        if type(value) is str:
            try:
                encoded = value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise _fail(PREBINDING_INVALID_TEXT, "wire text is not valid UTF-8") from exc
            if len(encoded) > _CBOR_MAX_STRING_BYTES:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR text exceeds the profile limit")
            return _cbor_head(3, len(encoded)) + encoded
        if type(value) in (list, tuple):
            if len(value) > _CBOR_MAX_CONTAINER_ITEMS:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR array exceeds the profile limit")
            identity = id(value)
            if identity in self.active:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "cyclic values cannot be encoded")
            self.active.add(identity)
            try:
                parts = [_cbor_head(4, len(value))]
                size = len(parts[0])
                for item in value:
                    encoded_item = self.encode(item, depth + 1)
                    size += len(encoded_item)
                    if size > _CBOR_MAX_ENCODED_BYTES:
                        raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR value exceeds the profile limit")
                    parts.append(encoded_item)
                return b"".join(parts)
            finally:
                self.active.remove(identity)
        raise _fail(
            PREBINDING_INVALID_TYPE,
            "wire profile permits arrays, uints, bstrs, and exact UTF-8 tstrs only",
        )


class _PrebindingCBORDecoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.nodes = 0

    def _visit(self, depth: int) -> None:
        if depth > _CBOR_MAX_DEPTH:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR nesting exceeds the profile limit")
        self.nodes += 1
        if self.nodes > _CBOR_MAX_NODES:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR node count exceeds the profile limit")

    def _take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.raw):
            raise _fail(PREBINDING_CANONICAL_ENCODING, "truncated CBOR value")
        value = self.raw[self.offset:end]
        self.offset = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "indefinite or reserved CBOR argument")
        encoded = self._take(width)
        value = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 1 << 32}[width]
        if value < minimum:
            raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR integer or length is not shortest-form")
        return value

    def decode(self, depth: int = 0) -> Any:
        self._visit(depth)
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if major == 0:
            return self._argument(additional)
        if major in (2, 3):
            length = self._argument(additional)
            if length > _CBOR_MAX_STRING_BYTES:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR string exceeds the profile limit")
            payload = self._take(length)
            if major == 2:
                return payload
            try:
                return payload.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise _fail(PREBINDING_INVALID_TEXT, "wire text is not valid UTF-8") from exc
        if major == 4:
            length = self._argument(additional)
            if length > _CBOR_MAX_CONTAINER_ITEMS:
                raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR array exceeds the profile limit")
            return [self.decode(depth + 1) for _ in range(length)]
        raise _fail(
            PREBINDING_INVALID_TYPE,
            "wire profile forbids maps, negative integers, simple values, tags, floats, and indefinite items",
        )


def _canonical_decode(raw: bytes) -> Any:
    if type(raw) is not bytes:
        raise _fail(PREBINDING_INVALID_TYPE, "prebinding bytes must be a byte string")
    if not raw or len(raw) > _CBOR_MAX_ENCODED_BYTES:
        raise _fail(PREBINDING_CANONICAL_ENCODING, "CBOR input is empty or exceeds the profile limit")
    decoder = _PrebindingCBORDecoder(raw)
    value = decoder.decode()
    if decoder.offset != len(raw):
        raise _fail(PREBINDING_CANONICAL_ENCODING, "trailing bytes follow the CBOR value")
    return value


def _canonical_hash(domain: bytes, value: Any) -> bytes:
    return sha256(domain + _canonical_encode(value)).digest()


def _dense(values: Sequence[int], label: str) -> None:
    if list(values) != list(range(len(values))):
        raise _fail(PREBINDING_DENSE_ORDINAL_INVALID, f"{label} must be dense from zero")


def _strictly_increasing(values: Sequence[int], label: str) -> None:
    if list(values) != sorted(set(values)):
        raise _fail(PREBINDING_ORDER_INVALID, f"{label} must be strictly increasing")


def _split_punctuator(raw: str, start: int) -> bool:
    for punctuator in _MULTI:
        if raw[start] != punctuator[0]:
            continue
        cursor = start + 1
        for expected in punctuator[1:]:
            while cursor < len(raw) and raw[cursor] in _ASCII_WHITESPACE:
                cursor += 1
            if cursor >= len(raw) or raw[cursor] != expected:
                break
            cursor += 1
        else:
            if cursor != start + len(punctuator):
                return True
    return False


def _qtid_tokens(raw: str) -> list[tuple[str, str]]:
    if type(raw) is not str:
        raise _fail(PREBINDING_INVALID_TYPE, "raw_qual_type must be text")
    if not raw:
        raise _fail(QUAL_TYPE_EMPTY, "qualified type is empty")
    for char in raw:
        code = ord(char)
        if code > 0x7F:
            raise _fail(QUAL_TYPE_NON_ASCII, "qualified type is not ASCII")
        if (code < 0x20 and char not in _ASCII_WHITESPACE) or code == 0x7F:
            raise _fail(QUAL_TYPE_UNSUPPORTED_TOKEN, "qualified type contains unsupported ASCII")

    tokens: list[tuple[str, str]] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char in _ASCII_WHITESPACE:
            index += 1
            continue
        if _split_punctuator(raw, index):
            raise _fail(QUAL_TYPE_SPLIT_PUNCTUATOR, "whitespace splits a multi-byte punctuator")
        if char.isalpha() or char == "_":
            end = index + 1
            while end < len(raw) and (raw[end].isalnum() or raw[end] == "_"):
                end += 1
            tokens.append(("word", raw[index:end]))
            index = end
            continue
        if char.isdigit():
            end = index + 1
            while end < len(raw) and (raw[end].isalnum() or raw[end] in "_'"):
                end += 1
            tokens.append(("number", raw[index:end]))
            index = end
            continue
        matched = next((token for token in _MULTI if raw.startswith(token, index)), None)
        if matched is not None:
            tokens.append(("punct", matched))
            index += len(matched)
            continue
        if char in _SINGLE:
            tokens.append(("punct", char))
            index += 1
            continue
        raise _fail(QUAL_TYPE_UNSUPPORTED_TOKEN, f"unsupported token at offset {index}")
    if not tokens:
        raise _fail(QUAL_TYPE_EMPTY, "qualified type contains no tokens")
    return tokens


def qtid_ascii_v1(raw_qual_type: str) -> str:
    """Return the exact QTID_ASCII_V1 lexical identity spelling."""

    tokens = _qtid_tokens(raw_qual_type)
    stack: list[str] = []
    previous: tuple[str, str] | None = None
    for kind, spelling in tokens:
        if spelling in ("(", "["):
            stack.append(spelling)
        elif spelling == "<":
            if previous is None or (
                previous[0] != "word" and previous[1] not in (")", "]", ">")
            ):
                raise _fail(QUAL_TYPE_AMBIGUOUS_ANGLE, "angle opener is not a template delimiter")
            stack.append(spelling)
        elif spelling in (")", "]", ">"):
            expected = {")": "(", "]": "[", ">": "<"}[spelling]
            if not stack or stack[-1] != expected:
                raise _fail(QUAL_TYPE_UNBALANCED_DELIMITER, "delimiters are not properly nested")
            stack.pop()
        elif spelling == ",":
            if not stack or stack[-1] not in ("(", "<"):
                raise _fail(QUAL_TYPE_INVALID_COMMA, "comma is outside parentheses or angle brackets")
        if stack and stack[-1] == "<" and spelling in (
            "=", "+", "-", "/", "%", "!", "~", "?", ":", ".", "^", "|"
        ):
            raise _fail(QUAL_TYPE_AMBIGUOUS_ANGLE, "angle contents look like an expression")
        previous = (kind, spelling)
    if stack:
        raise _fail(QUAL_TYPE_UNBALANCED_DELIMITER, "qualified type delimiters are unbalanced")
    for left, right in zip(tokens, tokens[1:]):
        if left[1] == ">" and right[0] in ("word", "number") and right[1] not in _CV_QUALIFIERS:
            raise _fail(QUAL_TYPE_AMBIGUOUS_ANGLE, "angle spelling is ambiguous")

    output: list[str] = []
    for index, (kind, spelling) in enumerate(tokens):
        if index and kind in ("word", "number") and tokens[index - 1][0] in ("word", "number"):
            output.append(" ")
        output.append(spelling)
    return "".join(output)


QTID_ASCII_V1 = qtid_ascii_v1


def _identity_type(value: Any, label: str) -> str:
    identity = _text(value, label)
    if qtid_ascii_v1(identity) != identity:
        raise _fail(QUAL_TYPE_IDENTITY_MISMATCH, f"{label} is not canonical QTID_ASCII_V1")
    return identity


def _linkage(value: Any, scope: Any, label: str) -> tuple[int, bytes]:
    linkage = _uint(value, 8, f"{label} linkage_code")
    scope_id = _bstr32(scope, f"{label} linkage_scope_id")
    if linkage == LINKAGE_ODR_MERGEABLE:
        if scope_id != ZERO32:
            raise _fail(HELPER_SCOPE_INVALID, f"{label} ODR scope must be zero32")
    elif linkage == LINKAGE_TRANSLATION_UNIT_LOCAL:
        if scope_id == ZERO32:
            raise _fail(HELPER_SCOPE_INVALID, f"{label} TU-local scope must be nonzero")
    else:
        raise _fail(HELPER_SCOPE_INVALID, f"{label} linkage code is reserved")
    return linkage, scope_id


def target_site_id(
    target_root: bytes,
    index: int,
    name: str,
    identity_qual_type: str,
    entropy_ordinal: int,
) -> bytes:
    return _canonical_hash(
        DS_SITE_ID,
        [
            _bstr32(target_root, "target_root"),
            _uint(index, 32, "target index"),
            _text(name, "target name"),
            _identity_type(identity_qual_type, "identity_qual_type"),
            _uint(entropy_ordinal, 32, "entropy_ordinal"),
        ],
    )


def helper_id(
    source_root: bytes,
    linkage_code: int,
    linkage_scope_id: bytes,
    qualified_name: str,
    identity_qual_type: str,
) -> bytes:
    linkage, scope = _linkage(linkage_code, linkage_scope_id, "helper")
    return _canonical_hash(
        DS_HELPER_ID,
        [
            _bstr32(source_root, "source_root"),
            linkage,
            scope,
            _text(qualified_name, "qualified_name"),
            _identity_type(identity_qual_type, "identity_qual_type"),
        ],
    )


def helper_site_id(helper_identity: bytes, entropy_ordinal: int) -> bytes:
    """Derive a helper-owned entropy-site ID under the still-binding KDF."""

    return _canonical_hash(
        DS_HELPER_SITE_ID,
        [
            _bstr32(helper_identity, "helper_id"),
            _uint(entropy_ordinal, 32, "entropy_ordinal"),
        ],
    )


def function_definition_digest(definition_bytes: bytes, *, contiguous: bool = True) -> bytes:
    if type(contiguous) is not bool:
        raise _fail(PREBINDING_INVALID_TYPE, "contiguous must be boolean")
    if not contiguous:
        raise _fail(NON_CONTIGUOUS_DEFINITION_BYTES, "definition bytes are not contiguous source bytes")
    return _canonical_hash(
        DS_FUNCTION_DEFINITION,
        [_bstr(definition_bytes, "definition_bytes")],
    )


definition_digest = function_definition_digest


def _validate_runtime_platform(value: Any) -> list[Any]:
    row = _array(value, "runtime_platform")
    if len(row) != 5:
        raise _fail(PREBINDING_SCHEMA_INVALID, "runtime platform has the wrong width")
    os_abi = _text(row[0], "operating_system_abi")
    architecture = _text(row[1], "architecture")
    endianness = _uint(row[2], 8, "endianness")
    pointer_width = _uint(row[3], 16, "pointer_width_bits")
    char_width = _uint(row[4], 8, "char_width_bits")
    if endianness not in (1, 2):
        raise _fail(PREBINDING_INVALID_WIDTH, "endianness is reserved")
    if pointer_width == 0 or pointer_width % 8:
        raise _fail(PREBINDING_INVALID_WIDTH, "pointer width must be positive and byte-aligned")
    if char_width != 8:
        raise _fail(PREBINDING_INVALID_WIDTH, "char width must equal 8")
    return [os_abi, architecture, endianness, pointer_width, char_width]


def _validate_filesystem_entry(value: Any) -> list[Any]:
    row = _array(value, "filesystem_entry")
    if len(row) != 6:
        raise _fail(PREBINDING_SCHEMA_INVALID, "filesystem entry has the wrong width")
    path = _canonical_path(row[0], "virtual_path")
    kind = _uint(row[1], 8, "filesystem kind")
    permissions = _uint(row[2], 16, "permission_bits")
    byte_length = _uint(row[3], 64, "byte_length")
    digest = _bstr32(row[4], "payload_sha256")
    target = _text(row[5], "symlink_target", nonempty=False)
    if kind not in (1, 2, 3):
        raise _fail(PREBINDING_SCHEMA_INVALID, "unsupported inode kind")
    if permissions > 0x0FFF:
        raise _fail(PREBINDING_INVALID_WIDTH, "permission bits exceed st_mode & 0x0fff")
    if kind == 1:
        if target:
            raise _fail(PREBINDING_SCHEMA_INVALID, "regular file symlink target must be empty")
    elif kind == 2:
        if byte_length != 0 or digest != ZERO32 or target:
            raise _fail(PREBINDING_SCHEMA_INVALID, "directory payload fields must be empty")
    else:
        if not target:
            raise _fail(PREBINDING_SCHEMA_INVALID, "symlink target must not be empty")
        target_bytes = target.encode("utf-8")
        if byte_length != len(target_bytes) or digest != sha256(target_bytes).digest():
            raise _fail(PREBINDING_SCHEMA_INVALID, "symlink length or digest is inconsistent")
    return [path, kind, permissions, byte_length, digest, target]


def validate_toolchain_runtime_manifest(value: Any) -> list[Any]:
    row = _array(value, "toolchain_runtime_manifest")
    if len(row) != 5 or _uint(row[0], 8, "runtime manifest version") != 1:
        raise _fail(PREBINDING_SCHEMA_INVALID, "runtime manifest header is invalid")
    compiler_path = _canonical_path(row[1], "compiler_entry_path")
    extractor_path = _canonical_path(row[2], "extractor_entry_path")
    if compiler_path == extractor_path:
        raise _fail(PREBINDING_SCHEMA_INVALID, "compiler and extractor entry paths must differ")
    platform = _validate_runtime_platform(row[3])
    entries = [_validate_filesystem_entry(item) for item in _array(row[4], "filesystem_entries")]
    paths = [entry[0].encode("utf-8") for entry in entries]
    if paths != sorted(set(paths)):
        raise _fail(PREBINDING_ORDER_INVALID, "filesystem entries must be unique and raw-UTF-8 sorted")
    return [1, compiler_path, extractor_path, platform, entries]


def toolchain_runtime_root(manifest: Any) -> bytes:
    return _canonical_hash(
        DS_TOOLCHAIN_RUNTIME_ROOT,
        validate_toolchain_runtime_manifest(manifest),
    )


def _resolve_runtime_entry(entries: Sequence[Sequence[Any]], start_path: str) -> Sequence[Any]:
    by_path = {entry[0]: entry for entry in entries}
    current = start_path
    visited: set[str] = set()
    while True:
        if current in visited:
            raise _fail(UNLISTED_EXECUTABLE, "entrypoint symlink cycle is unresolvable")
        visited.add(current)
        entry = by_path.get(current)
        if entry is None:
            raise _fail(UNLISTED_EXECUTABLE, "entrypoint does not resolve inside runtime manifest")
        if entry[1] == 1:
            return entry
        if entry[1] != 3:
            raise _fail(UNLISTED_EXECUTABLE, "entrypoint does not resolve to a regular file")
        target = entry[5]
        if target.startswith("/"):
            resolved = posixpath.normpath(target)
        else:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(current), target))
        current = _canonical_path(resolved, "resolved entrypoint")


def _validate_argv(value: Any, expected_argv0: str, label: str) -> list[str]:
    command = _array(value, label)
    if not command:
        raise _fail(PREBINDING_SCHEMA_INVALID, f"{label} must not be empty")
    argv = [_text(item, f"{label} argument") for item in command]
    if argv[0] != expected_argv0:
        raise _fail(UNLISTED_EXECUTABLE, f"{label} argv[0] is not the bound entrypoint")
    for argument in argv:
        if "@" in argument:
            raise _fail(RESPONSE_FILE_SYNTAX_FORBIDDEN, "response-file syntax is forbidden")
        if any(argument.startswith(flag) for flag in _CONFIG_FLAGS):
            raise _fail(COMPILER_CONFIG_FILE_FORBIDDEN, "compiler config-file argument is forbidden")
        if argument == "-":
            raise _fail(STDIN_INPUT_FORBIDDEN, "stdin input is forbidden")
    return argv


def validate_compiler_semantics_manifest(
    value: Any,
    *,
    runtime_manifest: Any | None = None,
    expected_source_root: bytes | None = None,
) -> list[Any]:
    row = _array(value, "compiler_semantics_manifest")
    if len(row) != 9 or _uint(row[0], 8, "compiler semantics version") != 2:
        raise _fail(PREBINDING_SCHEMA_INVALID, "compiler semantics v2 header is invalid")
    runtime_root = _bstr32(row[1], "toolchain_runtime_root")
    source_root = _bstr32(row[2], "source_root")
    if list(row[3:6]) != ["/v631302/work", "/v631302/src", "/v631302/toolchain"]:
        raise _fail(PREBINDING_SCHEMA_INVALID, "compiler virtual mounts are not exact")
    environment = []
    for value_pair in _array(row[6], "environment"):
        pair = _array(value_pair, "environment pair")
        if len(pair) != 2:
            raise _fail(PREBINDING_SCHEMA_INVALID, "environment pair has the wrong width")
        environment.append([_text(pair[0], "environment key"), _text(pair[1], "environment value")])
    if environment != ENVIRONMENT:
        raise _fail(PREBINDING_SCHEMA_INVALID, "compiler environment is not exact")

    policy = _array(row[7], "execution_policy")
    if len(policy) != 6 or [_uint(item, 8, "execution policy flag") for item in policy[:5]] != [1, 0, 0, 0, 0]:
        raise _fail(PREBINDING_SCHEMA_INVALID, "execution policy is not the exact v2 policy")
    executable_rows = _array(policy[5], "execution policy executables")
    if len(executable_rows) != 2:
        raise _fail(PREBINDING_SCHEMA_INVALID, "execution policy must bind exactly two executables")
    checked_executables: list[list[Any]] = []
    for position, executable in enumerate(executable_rows, 1):
        executable = _array(executable, "execution policy executable")
        if len(executable) != 3 or _uint(executable[0], 8, "executable role") != position:
            raise _fail(PREBINDING_SCHEMA_INVALID, "execution roles must be exactly [1,2]")
        checked_executables.append(
            [position, _canonical_path(executable[1], "executable path"), _bstr32(executable[2], "executable sha256")]
        )

    if runtime_manifest is not None:
        runtime = validate_toolchain_runtime_manifest(runtime_manifest)
        if runtime_root != toolchain_runtime_root(runtime):
            raise _fail(PREBINDING_ROOT_MISMATCH, "compiler semantics runtime root is stale")
        expected_paths = runtime[1:3]
        if [item[1] for item in checked_executables] != expected_paths:
            raise _fail(UNLISTED_EXECUTABLE, "execution policy paths differ from runtime entrypoints")
        for executable in checked_executables:
            resolved = _resolve_runtime_entry(runtime[4], executable[1])
            if resolved[4] != executable[2]:
                raise _fail(PREBINDING_ROOT_MISMATCH, "entrypoint digest differs from final runtime bytes")
    if expected_source_root is not None and source_root != _bstr32(expected_source_root, "expected_source_root"):
        raise _fail(PREBINDING_ROOT_MISMATCH, "compiler semantics source root is stale")

    translation_units: list[list[Any]] = []
    for unit_value in _array(row[8], "translation_units"):
        unit = _array(unit_value, "translation_unit")
        if len(unit) != 4:
            raise _fail(PREBINDING_SCHEMA_INVALID, "translation unit has the wrong width")
        ordinal = _uint(unit[0], 32, "tu_ordinal")
        source_path = _canonical_path(unit[1], "primary_source_virtual_path")
        if source_path != "/v631302/src" and not source_path.startswith("/v631302/src/"):
            raise _fail(PREBINDING_INVALID_TEXT, "primary source lies outside the source mount")
        compiler_command = _validate_argv(unit[2], checked_executables[0][1], "compiler_command")
        extractor_command = _validate_argv(unit[3], checked_executables[1][1], "extractor_command")
        translation_units.append([ordinal, source_path, compiler_command, extractor_command])
    _dense([unit[0] for unit in translation_units], "translation unit ordinals")
    sort_keys = [_canonical_encode([unit[1], unit[2], unit[3]]) for unit in translation_units]
    if sort_keys != sorted(set(sort_keys)):
        raise _fail(PREBINDING_ORDER_INVALID, "translation units are not canonically sorted")
    if not translation_units:
        raise _fail(PREBINDING_SCHEMA_INVALID, "translation unit list must not be empty")
    return [
        2,
        runtime_root,
        source_root,
        row[3],
        row[4],
        row[5],
        [list(item) for item in ENVIRONMENT],
        [1, 0, 0, 0, 0, checked_executables],
        translation_units,
    ]


def compiler_semantics_root(manifest: Any) -> bytes:
    return _canonical_hash(
        DS_COMPILER_SEMANTICS_ROOT,
        validate_compiler_semantics_manifest(manifest),
    )


def validate_declaration_key(value: Any) -> list[Any]:
    row = _array(value, "declaration_key")
    if len(row) != 6:
        raise _fail(PREBINDING_SCHEMA_INVALID, "declaration key has the wrong width")
    ast_kind = _text(row[0], "ast_decl_kind")
    name = _text(row[1], "qualified_name")
    raw_type = _text(row[2], "raw_qual_type")
    identity = _identity_type(row[3], "identity_qual_type")
    if qtid_ascii_v1(raw_type) != identity:
        raise _fail(QUAL_TYPE_IDENTITY_MISMATCH, "declaration raw and identity types disagree")
    linkage, scope = _linkage(row[4], row[5], "declaration")
    return [ast_kind, name, raw_type, identity, linkage, scope]


def validate_backend_matcher_registry(
    value: Any,
    *,
    expected_compiler_semantics_root: bytes | None = None,
) -> list[Any]:
    row = _array(value, "backend_matcher_registry")
    if len(row) != 3 or _uint(row[0], 8, "backend registry version") != 1:
        raise _fail(BACKEND_REGISTRY_INVALID, "backend registry header is invalid")
    semantics_root = _bstr32(row[1], "compiler_semantics_root")
    if expected_compiler_semantics_root is not None and semantics_root != _bstr32(
        expected_compiler_semantics_root, "expected_compiler_semantics_root"
    ):
        raise _fail(PREBINDING_ROOT_MISMATCH, "backend registry compiler root is stale")
    entries_value = _array(row[2], "backend_entries")
    if len(entries_value) != 2:
        raise _fail(BACKEND_REGISTRY_INVALID, "backend registry must have exactly two entries")
    entries: list[list[Any]] = []
    keys: list[bytes] = []
    for expected_code, value_entry in enumerate(entries_value, 1):
        entry = _array(value_entry, "backend_entry")
        if len(entry) != 5:
            raise _fail(BACKEND_REGISTRY_INVALID, "backend entry has the wrong width")
        code = _uint(entry[0], 16, "backend_code")
        primitive = _uint(entry[1], 16, "primitive_code")
        draw_semantics = _uint(entry[2], 8, "draw_semantics_code")
        if code != expected_code or primitive != 1 or draw_semantics != 1:
            raise _fail(BACKEND_REGISTRY_INVALID, "backend codes and semantics must be exactly [1,2]/1/1")
        ast_call_kind = _text(entry[3], "ast_call_expr_kind")
        declaration = validate_declaration_key(entry[4])
        entries.append([code, primitive, draw_semantics, ast_call_kind, declaration])
        keys.append(_canonical_encode(declaration))
    if len(set(keys)) != 2:
        raise _fail(BACKEND_REGISTRY_INVALID, "backend declaration keys must be unique")
    return [1, semantics_root, entries]


def backend_matcher_root(registry: Any) -> bytes:
    return _canonical_hash(
        DS_BACKEND_MATCHER_ROOT,
        validate_backend_matcher_registry(registry),
    )


def validate_external_terminal_registry(
    value: Any,
    *,
    backend_registry: Any | None = None,
    expected_compiler_semantics_root: bytes | None = None,
    expected_backend_matcher_root: bytes | None = None,
    expected_toolchain_runtime_root: bytes | None = None,
) -> list[Any]:
    row = _array(value, "external_terminal_registry")
    if len(row) != 4 or _uint(row[0], 8, "terminal registry version") != 1:
        raise _fail(TERMINAL_COHERENCE_INVALID, "terminal registry header is invalid")
    semantics_root = _bstr32(row[1], "compiler_semantics_root")
    backend_root = _bstr32(row[2], "backend_matcher_root")
    if expected_compiler_semantics_root is not None and semantics_root != _bstr32(
        expected_compiler_semantics_root, "expected_compiler_semantics_root"
    ):
        raise _fail(PREBINDING_ROOT_MISMATCH, "terminal registry compiler root is stale")
    if expected_backend_matcher_root is not None and backend_root != _bstr32(
        expected_backend_matcher_root, "expected_backend_matcher_root"
    ):
        raise _fail(PREBINDING_ROOT_MISMATCH, "terminal registry backend root is stale")

    entries: list[list[Any]] = []
    declaration_bytes: list[bytes] = []
    for value_entry in _array(row[3], "terminal_entries"):
        entry = _array(value_entry, "terminal_entry")
        if len(entry) != 6:
            raise _fail(TERMINAL_COHERENCE_INVALID, "terminal entry has the wrong width")
        ordinal = _uint(entry[0], 32, "terminal_ordinal")
        terminal_class = _uint(entry[1], 8, "terminal_class")
        declaration = validate_declaration_key(entry[2])
        backend_code = _uint(entry[3], 16, "backend_code")
        evidence_kind = _uint(entry[4], 8, "evidence_kind")
        evidence_root = _bstr32(entry[5], "evidence_root")
        if terminal_class == 1:
            if backend_code not in (1, 2) or evidence_kind != 1 or evidence_root != backend_root:
                raise _fail(TERMINAL_COHERENCE_INVALID, "entropy backend terminal evidence is incoherent")
        elif terminal_class == 2:
            if backend_code != 0 or evidence_kind not in (2, 3):
                raise _fail(TERMINAL_COHERENCE_INVALID, "entropy-free terminal classification is incoherent")
            if evidence_kind == 3 and expected_toolchain_runtime_root is not None:
                if evidence_root != _bstr32(
                    expected_toolchain_runtime_root, "expected_toolchain_runtime_root"
                ):
                    raise _fail(TERMINAL_COHERENCE_INVALID, "compiler builtin evidence must bind the runtime root")
        else:
            raise _fail(TERMINAL_COHERENCE_INVALID, "terminal class is reserved")
        entries.append([ordinal, terminal_class, declaration, backend_code, evidence_kind, evidence_root])
        declaration_bytes.append(_canonical_encode(declaration))

    _dense([entry[0] for entry in entries], "terminal ordinals")
    if declaration_bytes != sorted(set(declaration_bytes)):
        raise _fail(PREBINDING_ORDER_INVALID, "terminals must be uniquely sorted by declaration key")
    entropy_entries = [entry for entry in entries if entry[1] == 1]
    if len(entropy_entries) != 2 or {entry[3] for entry in entropy_entries} != {1, 2}:
        raise _fail(TERMINAL_COHERENCE_INVALID, "there must be one entropy terminal for each backend")

    if backend_registry is not None:
        backends = validate_backend_matcher_registry(
            backend_registry,
            expected_compiler_semantics_root=semantics_root,
        )[2]
        backend_keys = {entry[0]: entry[4] for entry in backends}
        for entry in entropy_entries:
            if entry[2] != backend_keys[entry[3]]:
                raise _fail(TERMINAL_COHERENCE_INVALID, "entropy terminal declaration differs from backend")
        backend_key_bytes = {_canonical_encode(key) for key in backend_keys.values()}
        if any(_canonical_encode(entry[2]) in backend_key_bytes for entry in entries if entry[1] == 2):
            raise _fail(TERMINAL_COHERENCE_INVALID, "entropy-free terminal matches an entropy backend")
    return [1, semantics_root, backend_root, entries]


def external_terminal_root(registry: Any) -> bytes:
    return _canonical_hash(
        DS_EXTERNAL_TERMINAL_ROOT,
        validate_external_terminal_registry(registry),
    )


def _target_projection_root(rows: Sequence[Sequence[Any]]) -> bytes:
    entries = [
        {"index": row[0], "name": row[1], "qual_type": row[2]}
        for row in rows
    ]
    # The fixed target root predates prebinding v2 and remains the canonical
    # JSON commitment emitted by the source-bound static-closure analyzer.
    payload = {
        "schema": "eval.v6.3.1.compiler-derived-function-registry.v1",
        "entries": entries,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).digest()


def validate_target_seed_rows(value: Any, *, expected_target_root: bytes) -> list[list[Any]]:
    target_root = _bstr32(expected_target_root, "expected_target_root")
    rows_value = _array(value, "target_seed_rows")
    if len(rows_value) != 116:
        raise _fail(TARGET_REGISTRY_MISMATCH, "target seed registry must contain exactly 116 rows")
    rows: list[list[Any]] = []
    for value_row in rows_value:
        row = _array(value_row, "target_seed_row")
        if len(row) != 4:
            raise _fail(PREBINDING_SCHEMA_INVALID, "target seed row has the wrong width")
        index = _uint(row[0], 32, "target index")
        name = _text(row[1], "target name")
        raw_type = _text(row[2], "raw_qual_type")
        identity = _identity_type(row[3], "identity_qual_type")
        if qtid_ascii_v1(raw_type) != identity:
            raise _fail(QUAL_TYPE_IDENTITY_MISMATCH, "target raw and identity types disagree")
        rows.append([index, name, raw_type, identity])
    indexes = [row[0] for row in rows]
    if indexes != sorted(set(indexes)):
        raise _fail(PREBINDING_ORDER_INVALID, "target indexes must be unique and ascending")
    if target_root != FIXED_TARGET_ROOT or _target_projection_root(rows) != FIXED_TARGET_ROOT:
        raise _fail(TARGET_REGISTRY_MISMATCH, "target projection does not match the source-bound target root")
    return rows


def target_seed_root(source_root: bytes, target_root: bytes, target_seed_rows: Any) -> bytes:
    source = _bstr32(source_root, "source_root")
    target = _bstr32(target_root, "target_root")
    rows = validate_target_seed_rows(target_seed_rows, expected_target_root=target)
    return _canonical_hash(DS_TARGET_SEED_ROOT, [source, target, rows])


def _tu_ordinals(value: Any, valid_tu_ordinals: set[int], label: str) -> list[int]:
    ordinals = [_uint(item, 32, f"{label} TU ordinal") for item in _array(value, label)]
    if not ordinals:
        raise _fail(PREBINDING_SCHEMA_INVALID, f"{label} must not be empty")
    _strictly_increasing(ordinals, label)
    if any(ordinal not in valid_tu_ordinals for ordinal in ordinals):
        raise _fail(PREBINDING_SCHEMA_INVALID, f"{label} references an unknown translation unit")
    return ordinals


def validate_helper_declaration_rows(
    value: Any,
    *,
    source_root: bytes,
    target_seed_rows: Sequence[Sequence[Any]],
    valid_tu_ordinals: set[int],
) -> list[list[Any]]:
    source = _bstr32(source_root, "source_root")
    rows: list[list[Any]] = []
    ids: list[bytes] = []
    identity_tuples: set[bytes] = set()
    raw_by_normalized_identity: dict[bytes, str] = {}
    target_identities = {(row[1], row[3]) for row in target_seed_rows}
    for value_row in _array(value, "helper_declaration_rows"):
        row = _array(value_row, "helper_declaration_row")
        if len(row) != 9:
            raise _fail(PREBINDING_SCHEMA_INVALID, "helper declaration row has the wrong width")
        ordinal = _uint(row[0], 32, "helper_ordinal")
        declared_id = _bstr32(row[1], "helper_id")
        name = _text(row[2], "qualified_name")
        raw_type = _text(row[3], "raw_qual_type")
        identity = _identity_type(row[4], "identity_qual_type")
        if qtid_ascii_v1(raw_type) != identity:
            raise _fail(QUAL_TYPE_IDENTITY_MISMATCH, "helper raw and identity types disagree")
        linkage, scope = _linkage(row[5], row[6], "helper")
        digest = _bstr32(row[7], "definition_digest")
        definitions = _tu_ordinals(row[8], valid_tu_ordinals, "helper definition_tu_ordinals")
        if linkage == LINKAGE_TRANSLATION_UNIT_LOCAL and len(definitions) != 1:
            raise _fail(HELPER_DECLARATION_INVALID, "TU-local helper must have exactly one definition TU")
        expected_id = helper_id(source, linkage, scope, name, identity)
        if declared_id != expected_id:
            raise _fail(HELPER_ID_MISMATCH, "helper ID does not bind its preimage")
        identity_tuple = _canonical_encode([name, identity, linkage, scope])
        if identity_tuple in identity_tuples:
            raise _fail(HELPER_DECLARATION_INVALID, "duplicate helper identity tuple")
        identity_tuples.add(identity_tuple)
        normalized_identity = _canonical_encode([name, identity])
        prior_raw = raw_by_normalized_identity.setdefault(normalized_identity, raw_type)
        if prior_raw != raw_type:
            raise _fail(HELPER_DECLARATION_INVALID, "one normalized identity has differing raw types")
        if (name, identity) in target_identities:
            raise _fail(HELPER_DECLARATION_INVALID, "declaration aliases a target and helper")
        rows.append([ordinal, declared_id, name, raw_type, identity, linkage, scope, digest, definitions])
        ids.append(declared_id)
    _dense([row[0] for row in rows], "helper ordinals")
    if ids != sorted(set(ids)):
        raise _fail(PREBINDING_ORDER_INVALID, "helpers must be uniquely sorted by raw helper ID")
    return rows


def helper_declaration_root(
    source_root: bytes,
    target_root: bytes,
    helper_declaration_rows: Sequence[Sequence[Any]],
) -> bytes:
    return _canonical_hash(
        DS_HELPER_DECLARATION_ROOT,
        [
            _bstr32(source_root, "source_root"),
            _bstr32(target_root, "target_root"),
            [list(row) for row in helper_declaration_rows],
        ],
    )


def _validate_function_ref(value: Any, label: str) -> list[Any]:
    ref = _array(value, label)
    if len(ref) != 2:
        raise _fail(FUNCTION_SCAN_INVALID, f"{label} has the wrong width")
    kind = _uint(ref[0], 8, f"{label} kind")
    if kind == TARGET_REF:
        return [kind, _uint(ref[1], 32, f"{label} target index")]
    if kind == HELPER_REF:
        return [kind, _bstr32(ref[1], f"{label} helper ID")]
    if kind == TERMINAL_REF:
        return [kind, _uint(ref[1], 32, f"{label} terminal ordinal")]
    raise _fail(FUNCTION_SCAN_INVALID, f"{label} kind is reserved")


def _validate_invocation_rows(
    value: Any,
    *,
    target_indexes: set[int],
    helper_ids: set[bytes],
    terminal_ordinals: set[int],
) -> list[list[Any]]:
    rows: list[list[Any]] = []
    ordering: list[tuple[tuple[int, ...], bytes]] = []
    slots_by_path: dict[tuple[int, ...], list[int]] = {}
    for value_row in _array(value, "invocation_rows"):
        row = _array(value_row, "invocation_row")
        if len(row) != 7:
            raise _fail(FUNCTION_SCAN_INVALID, "invocation row has the wrong width")
        ordinal = _uint(row[0], 32, "invocation_ordinal")
        path = [_uint(item, 32, "anchor AST path component") for item in _array(row[1], "anchor_ast_path")]
        slot = _uint(row[2], 32, "semantic_slot")
        invocation_kind = _uint(row[3], 8, "invocation_kind")
        resolution_kind = _uint(row[4], 8, "resolution_kind")
        occurrence_count = _uint(row[5], 32, "occurrence_count")
        if invocation_kind not in INVOCATION_KINDS:
            raise _fail(FUNCTION_SCAN_INVALID, "invocation kind is reserved")
        if resolution_kind not in (RESOLUTION_EXACT_SINGLE, RESOLUTION_EXACT_FINITE_SET):
            raise _fail(UNRESOLVED_REACHABLE_CALL, "resolution is not exact and finite")
        if occurrence_count == 0:
            raise _fail(FUNCTION_SCAN_INVALID, "occurrence count must be positive")
        callees = [_validate_function_ref(item, "callee_ref") for item in _array(row[6], "callee_refs")]
        expected_count = 1 if resolution_kind == RESOLUTION_EXACT_SINGLE else 2
        if len(callees) < expected_count or (resolution_kind == RESOLUTION_EXACT_SINGLE and len(callees) != 1):
            raise _fail(UNRESOLVED_REACHABLE_CALL, "callee set does not match resolution kind")
        callee_keys = [_canonical_encode(ref) for ref in callees]
        if callee_keys != sorted(set(callee_keys)):
            raise _fail(PREBINDING_ORDER_INVALID, "callee refs must be unique and canonically sorted")
        for ref in callees:
            if ref[0] == TARGET_REF and ref[1] not in target_indexes:
                raise _fail(GRAPH_CLOSURE_INVALID, "callee target is absent from target seeds")
            if ref[0] == HELPER_REF and ref[1] not in helper_ids:
                raise _fail(GRAPH_CLOSURE_INVALID, "reachable helper is undeclared")
            if ref[0] == TERMINAL_REF and ref[1] not in terminal_ordinals:
                raise _fail(GRAPH_CLOSURE_INVALID, "callee terminal ordinal is absent")
        rows.append([ordinal, path, slot, invocation_kind, resolution_kind, occurrence_count, callees])
        path_tuple = tuple(path)
        slots_by_path.setdefault(path_tuple, []).append(slot)
        ordering.append((path_tuple, _canonical_encode([invocation_kind, resolution_kind, callees])))
    _dense([row[0] for row in rows], "invocation ordinals")
    if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
        raise _fail(PREBINDING_ORDER_INVALID, "invocation groups must be unique and canonically ordered")
    for path, slots in slots_by_path.items():
        _dense(slots, f"semantic slots at path {path}")
    return rows


def validate_function_scan_rows(
    value: Any,
    *,
    target_seed_rows: Sequence[Sequence[Any]],
    helper_declaration_rows: Sequence[Sequence[Any]],
    terminal_entries: Sequence[Sequence[Any]],
    valid_tu_ordinals: set[int],
) -> list[list[Any]]:
    target_indexes = {row[0] for row in target_seed_rows}
    helper_by_id = {row[1]: row for row in helper_declaration_rows}
    helper_ids = set(helper_by_id)
    terminal_ordinals = {row[0] for row in terminal_entries}
    rows: list[list[Any]] = []
    refs: list[bytes] = []
    for value_row in _array(value, "function_scan_rows"):
        row = _array(value_row, "function_scan_row")
        if len(row) != 6:
            raise _fail(FUNCTION_SCAN_INVALID, "function scan row has the wrong width")
        ordinal = _uint(row[0], 32, "scan_ordinal")
        function_ref = _validate_function_ref(row[1], "function_ref")
        if function_ref[0] == TERMINAL_REF:
            raise _fail(FUNCTION_SCAN_INVALID, "terminal refs cannot have function scans")
        digest = _bstr32(row[2], "definition_digest")
        definitions = _tu_ordinals(row[3], valid_tu_ordinals, "scan definition_tu_ordinals")
        reported_count = _uint(row[4], 32, "compiler_reported_invocation_count")
        invocations = _validate_invocation_rows(
            row[5],
            target_indexes=target_indexes,
            helper_ids=helper_ids,
            terminal_ordinals=terminal_ordinals,
        )
        if reported_count != sum(invocation[5] for invocation in invocations):
            raise _fail(FUNCTION_SCAN_INVALID, "reported invocation count does not equal grouped occurrences")
        if function_ref[0] == TARGET_REF:
            if function_ref[1] not in target_indexes:
                raise _fail(GRAPH_CLOSURE_INVALID, "scan target is absent from target seeds")
        else:
            helper = helper_by_id.get(function_ref[1])
            if helper is None:
                raise _fail(GRAPH_CLOSURE_INVALID, "helper scan has no declaration")
            if digest != helper[7] or definitions != helper[8]:
                raise _fail(FUNCTION_SCAN_INVALID, "helper scan definition fields differ from declaration")
        rows.append([ordinal, function_ref, digest, definitions, reported_count, invocations])
        refs.append(_canonical_encode(function_ref))
    expected_count = 116 + len(helper_declaration_rows)
    if len(rows) != expected_count:
        raise _fail(FUNCTION_SCAN_INVALID, "scan count must equal 116 plus helper count")
    _dense([row[0] for row in rows], "scan ordinals")
    if refs != sorted(set(refs)):
        raise _fail(PREBINDING_ORDER_INVALID, "function scans must be uniquely sorted by function ref")
    expected_refs = {
        _canonical_encode([TARGET_REF, index]) for index in target_indexes
    } | {
        _canonical_encode([HELPER_REF, helper_identity]) for helper_identity in helper_ids
    }
    if set(refs) != expected_refs:
        raise _fail(FUNCTION_SCAN_INVALID, "function scans do not cover every target and helper exactly once")
    return rows


def reachable_helper_closure(
    target_seed_rows: Sequence[Sequence[Any]],
    helper_declaration_rows: Sequence[Sequence[Any]],
    function_scan_rows: Sequence[Sequence[Any]],
) -> tuple[bytes, ...]:
    scan_by_ref = {_canonical_encode(row[1]): row for row in function_scan_rows}
    pending = [[TARGET_REF, row[0]] for row in target_seed_rows]
    visited: set[bytes] = set()
    reachable_helpers: set[bytes] = set()
    while pending:
        ref = pending.pop()
        key = _canonical_encode(ref)
        if key in visited:
            continue
        visited.add(key)
        scan = scan_by_ref.get(key)
        if scan is None:
            raise _fail(GRAPH_CLOSURE_INVALID, "reachable nonterminal function has no scan")
        if ref[0] == HELPER_REF:
            reachable_helpers.add(ref[1])
        for invocation in scan[5]:
            for callee in invocation[6]:
                if callee[0] != TERMINAL_REF:
                    pending.append(callee)
    declared_helpers = {row[1] for row in helper_declaration_rows}
    if reachable_helpers != declared_helpers:
        missing = declared_helpers - reachable_helpers
        extra = reachable_helpers - declared_helpers
        raise _fail(
            GRAPH_CLOSURE_INVALID,
            f"helper closure mismatch: unreachable={len(missing)} undeclared={len(extra)}",
        )
    return tuple(sorted(reachable_helpers))


def function_scan_root(
    source_root: bytes,
    target_root: bytes,
    compiler_semantics_root_value: bytes,
    target_seed_root_value: bytes,
    helper_declaration_root_value: bytes,
    external_terminal_root_value: bytes,
    function_scan_rows: Sequence[Sequence[Any]],
) -> bytes:
    return _canonical_hash(
        DS_FUNCTION_SCAN_ROOT,
        [
            _bstr32(source_root, "source_root"),
            _bstr32(target_root, "target_root"),
            _bstr32(compiler_semantics_root_value, "compiler_semantics_root"),
            _bstr32(target_seed_root_value, "target_seed_root"),
            _bstr32(helper_declaration_root_value, "helper_declaration_root"),
            _bstr32(external_terminal_root_value, "external_terminal_root"),
            [list(row) for row in function_scan_rows],
        ],
    )


def helper_closure_root(
    source_root: bytes,
    target_root: bytes,
    target_seed_root_value: bytes,
    helper_declaration_root_value: bytes,
    function_scan_root_value: bytes,
    backend_matcher_root_value: bytes,
    external_terminal_root_value: bytes,
) -> bytes:
    return _canonical_hash(
        DS_HELPER_CLOSURE_ROOT,
        [
            _bstr32(source_root, "source_root"),
            _bstr32(target_root, "target_root"),
            _bstr32(target_seed_root_value, "target_seed_root"),
            _bstr32(helper_declaration_root_value, "helper_declaration_root"),
            _bstr32(function_scan_root_value, "function_scan_root"),
            _bstr32(backend_matcher_root_value, "backend_matcher_root"),
            _bstr32(external_terminal_root_value, "external_terminal_root"),
        ],
    )


def prebinding_root(
    source_root: bytes,
    target_root: bytes,
    static_closure_artifact_sha256: bytes,
    component_roots: Sequence[bytes],
) -> bytes:
    components = _array(component_roots, "component_roots")
    if len(components) != 10:
        raise _fail(PREBINDING_SCHEMA_INVALID, "component_roots must contain exactly ten roots")
    checked = [_bstr32(root, f"component root {index}") for index, root in enumerate(components)]
    return _canonical_hash(
        DS_PREBINDING_ROOT,
        [
            PROTOCOL_ID,
            WIRE_VERSION,
            _bstr32(source_root, "source_root"),
            _bstr32(target_root, "target_root"),
            _bstr32(static_closure_artifact_sha256, "static_closure_artifact_sha256"),
            *checked,
        ],
    )


def _build_compiler_prebinding(
    source_root: bytes,
    target_root: bytes,
    static_closure_artifact_sha256: bytes,
    runtime_manifest: Any,
    semantics_manifest: Any,
    backend_registry: Any,
    terminal_registry: Any,
    target_rows_value: Any,
    helper_rows_value: Any,
    scan_rows_value: Any,
) -> list[Any]:
    source = _bstr32(source_root, "source_root")
    target = _bstr32(target_root, "target_root")
    static_closure = _bstr32(static_closure_artifact_sha256, "static_closure_artifact_sha256")
    runtime = validate_toolchain_runtime_manifest(runtime_manifest)
    runtime_root = toolchain_runtime_root(runtime)
    semantics = validate_compiler_semantics_manifest(
        semantics_manifest,
        runtime_manifest=runtime,
        expected_source_root=source,
    )
    semantics_root = compiler_semantics_root(semantics)
    executable_rows = semantics[7][5]
    compiler_binary = executable_rows[0][2]
    extractor_binary = executable_rows[1][2]
    backends = validate_backend_matcher_registry(
        backend_registry,
        expected_compiler_semantics_root=semantics_root,
    )
    backend_root = backend_matcher_root(backends)
    terminals = validate_external_terminal_registry(
        terminal_registry,
        backend_registry=backends,
        expected_compiler_semantics_root=semantics_root,
        expected_backend_matcher_root=backend_root,
        expected_toolchain_runtime_root=runtime_root,
    )
    terminal_root = external_terminal_root(terminals)
    target_rows = validate_target_seed_rows(target_rows_value, expected_target_root=target)
    target_root_value = target_seed_root(source, target, target_rows)
    valid_tus = {unit[0] for unit in semantics[8]}
    helper_rows = validate_helper_declaration_rows(
        helper_rows_value,
        source_root=source,
        target_seed_rows=target_rows,
        valid_tu_ordinals=valid_tus,
    )
    helper_root = helper_declaration_root(source, target, helper_rows)
    scan_rows = validate_function_scan_rows(
        scan_rows_value,
        target_seed_rows=target_rows,
        helper_declaration_rows=helper_rows,
        terminal_entries=terminals[3],
        valid_tu_ordinals=valid_tus,
    )
    reachable_helper_closure(target_rows, helper_rows, scan_rows)
    scan_root = function_scan_root(
        source,
        target,
        semantics_root,
        target_root_value,
        helper_root,
        terminal_root,
        scan_rows,
    )
    closure_root = helper_closure_root(
        source,
        target,
        target_root_value,
        helper_root,
        scan_root,
        backend_root,
        terminal_root,
    )
    components = [
        runtime_root,
        compiler_binary,
        extractor_binary,
        semantics_root,
        backend_root,
        terminal_root,
        target_root_value,
        helper_root,
        scan_root,
        closure_root,
    ]
    final_root = prebinding_root(source, target, static_closure, components)
    return [
        PROTOCOL_ID,
        WIRE_VERSION,
        source,
        target,
        static_closure,
        runtime,
        semantics,
        backends,
        terminals,
        target_rows,
        helper_rows,
        scan_rows,
        components,
        final_root,
    ]


def build_compiler_prebinding(
    source_root: bytes,
    target_root: bytes,
    static_closure_artifact_sha256: bytes,
    toolchain_runtime_manifest: Any,
    compiler_semantics_manifest: Any,
    backend_matcher_registry: Any,
    external_terminal_registry: Any,
    target_seed_rows: Any,
    helper_declaration_rows: Any,
    function_scan_rows: Any,
) -> list[Any]:
    """Construct the exact v2 artifact with all roots recomputed."""

    return _build_compiler_prebinding(
        source_root,
        target_root,
        static_closure_artifact_sha256,
        toolchain_runtime_manifest,
        compiler_semantics_manifest,
        backend_matcher_registry,
        external_terminal_registry,
        target_seed_rows,
        helper_declaration_rows,
        function_scan_rows,
    )


def compiler_prebinding_bytes(*args: Any, **kwargs: Any) -> bytes:
    return _canonical_encode(build_compiler_prebinding(*args, **kwargs))


def validate_compiler_prebinding(value: Any) -> PrebindingValidation:
    row = _array(value, "compiler prebinding v2")
    if len(row) != 14:
        raise _fail(PREBINDING_SCHEMA_INVALID, "prebinding v2 has the wrong width")
    if _uint(row[0], 32, "protocol ID") != PROTOCOL_ID or _uint(row[1], 8, "wire version") != 2:
        raise _fail(PREBINDING_SCHEMA_INVALID, "only prebinding wire version 2 is accepted")
    expected = _build_compiler_prebinding(
        row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11]
    )
    supplied_components = _array(row[12], "component_roots")
    if len(supplied_components) != 10:
        raise _fail(PREBINDING_SCHEMA_INVALID, "component_roots has the wrong width")
    for index, root in enumerate(supplied_components):
        _bstr32(root, f"component root {index}")
    supplied_final = _bstr32(row[13], "prebinding_root")
    if list(supplied_components) != expected[12]:
        raise _fail(PREBINDING_ROOT_MISMATCH, "one or more component roots are stale")
    if supplied_final != expected[13]:
        raise _fail(PREBINDING_ROOT_MISMATCH, "prebinding root is stale")
    return PrebindingValidation(
        ValidatorState.STRUCTURAL_CLOSURE_VALID,
        tuple(expected[12]),
        expected[13],
    )


def _validate_array_only_profile(value: Any) -> None:
    if type(value) is list or type(value) is tuple:
        for item in value:
            _validate_array_only_profile(item)
        return
    if type(value) is int:
        if value < 0 or value >= 1 << 64:
            raise _fail(PREBINDING_INVALID_WIDTH, "wire integer is outside uint64")
        return
    if type(value) is bytes:
        return
    if type(value) is str:
        _text(value, "wire text", nonempty=False)
        return
    raise _fail(PREBINDING_INVALID_TYPE, "wire profile permits arrays, uints, bstrs, and tstrs only")


def decode_compiler_prebinding(raw: bytes) -> list[Any]:
    value = _canonical_decode(raw)
    _validate_array_only_profile(value)
    row = _array(value, "compiler prebinding v2")
    if len(row) != 14 or row[0] != PROTOCOL_ID or row[1] != WIRE_VERSION:
        raise _fail(PREBINDING_SCHEMA_INVALID, "canonical bytes are not prebinding v2")
    return list(row)


def validate_compiler_prebinding_bytes(raw: bytes) -> PrebindingValidation:
    return validate_compiler_prebinding(decode_compiler_prebinding(raw))


def validator_state(
    *,
    byte_valid: bool,
    structural_closure_valid: bool,
    compiler_recomputed: bool,
    external_evidence_valid: bool,
) -> ValidatorState:
    """Describe only states this pure library can establish itself.

    Compiler recomputation and independently authenticated external evidence
    require separately reviewed evidence schemas that do not exist in this
    module.  Caller booleans therefore cannot elevate an offline structural
    result into either state.
    """

    flags = [byte_valid, structural_closure_valid, compiler_recomputed, external_evidence_valid]
    if any(type(flag) is not bool for flag in flags):
        raise _fail(PREBINDING_INVALID_TYPE, "validator state flags must be booleans")
    if any(flags[index] and not flags[index - 1] for index in range(1, len(flags))):
        raise _fail(VALIDATOR_STATE_NON_MONOTONIC, "validator state prerequisites are not monotonic")
    if structural_closure_valid or compiler_recomputed or external_evidence_valid:
        raise _fail(
            VALIDATOR_EVIDENCE_UNAVAILABLE,
            "structural, compiler, and external states must come from their evidence validators",
        )
    if byte_valid:
        return ValidatorState.BYTE_VALID
    raise _fail(VALIDATOR_STATE_NON_MONOTONIC, "BYTE_VALID is required for every validator state")


def candidate_eir_hash(eir_binding: Any) -> CandidateEIRHash:
    """Fail closed until an EIR schema binds every prebinding-v2 component.

    The retained 15-field EIR formula does not define how the v2 target-seed,
    helper-declaration, function-scan, and helper-closure roots map onto its
    final three roots.  Hashing caller-supplied roots would therefore create a
    digest disconnected from the artifact this module actually validated.
    """

    del eir_binding
    raise _fail(
        CANDIDATE_EIR_SCHEMA_UNAVAILABLE,
        "no reviewed EIR schema binds the compiler-prebinding v2 roots",
    )


def zero_authority_status() -> dict[str, Any]:
    return {
        "state": "ZERO_AUTHORITY",
        "authority": False,
        "engine_wiring_authority": False,
        "upload_authority": False,
        "permit_authority": False,
        "holdout_access_authority": False,
        "agent_modification_authority": False,
    }


__all__ = [
    "AGENT_MODIFICATION_AUTHORITY",
    "AUTHORITY",
    "BACKEND_GAME_RNG",
    "BACKEND_RANDOM_DEVICE",
    "CANDIDATE_EIR_SCHEMA_UNAVAILABLE",
    "CandidateEIRHash",
    "DS_HELPER_SITE_ID",
    "ENGINE_WIRING_AUTHORITY",
    "ENVIRONMENT",
    "EIRPrebindingError",
    "FIXED_TARGET_ROOT",
    "HOLDOUT_ACCESS_AUTHORITY",
    "LINKAGE_ODR_MERGEABLE",
    "LINKAGE_TRANSLATION_UNIT_LOCAL",
    "OPEN_EVIDENCE_REQUIREMENTS",
    "PERMIT_AUTHORITY",
    "PREBINDING_SCHEMA",
    "PROTOCOL_ID",
    "PrebindingValidation",
    "QTID_ASCII_V1",
    "STRUCTURAL_ONLY_EVIDENCE_SCOPE",
    "UNFROZEN_CANDIDATE_EIR_ROOT",
    "UPLOAD_AUTHORITY",
    "ValidatorState",
    "WIRE_VERSION",
    "ZERO32",
    "ZERO_AUTHORITY",
    "backend_matcher_root",
    "build_compiler_prebinding",
    "candidate_eir_hash",
    "compiler_prebinding_bytes",
    "compiler_semantics_root",
    "decode_compiler_prebinding",
    "definition_digest",
    "eir_canonical_cbor_decode",
    "eir_canonical_cbor_encode",
    "external_terminal_root",
    "function_definition_digest",
    "function_scan_root",
    "helper_closure_root",
    "helper_declaration_root",
    "helper_id",
    "helper_site_id",
    "prebinding_root",
    "qtid_ascii_v1",
    "reachable_helper_closure",
    "target_seed_root",
    "target_site_id",
    "toolchain_runtime_root",
    "validate_backend_matcher_registry",
    "validate_compiler_prebinding",
    "validate_compiler_prebinding_bytes",
    "validate_compiler_semantics_manifest",
    "validate_declaration_key",
    "validate_external_terminal_registry",
    "validate_function_scan_rows",
    "validate_helper_declaration_rows",
    "validate_target_seed_rows",
    "validate_toolchain_runtime_manifest",
    "validator_state",
    "zero_authority_status",
]
