"""Zero-authority validation for the Stage-1 compiler dependency manifest.

This module consumes only already-materialized dependency bytes and manifest
rows.  It never opens a path, walks a filesystem, resolves a link, hashes a
file, executes a compiler, or grants campaign, profile, permit, upload,
holdout, or agent-modification authority.

The raw dependency parser implements the deliberately small Make grammar
needed by the pinned Clang invocation.  Relative names are normalized against
the exact lexical working directory ``/work``.  That operation is lexical
only; it is not a claim about any filesystem object.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import posixpath
from typing import Any, Iterable, Sequence

from .eir_prebinding import EIRPrebindingError, eir_canonical_cbor_decode, eir_canonical_cbor_encode


PROTOCOL_ID = 631302
WIRE_VERSION = 1
TARGET_NAME_BYTES = b"launch_gate_llvm_mc_decoder_v1.o"
TARGET_NAME = TARGET_NAME_BYTES.decode("ascii")
LEXICAL_WORKING_DIRECTORY_BYTES = b"/work"
LEXICAL_WORKING_DIRECTORY = "/work"
LLVM_HEADER_ROOTS = (
    b"/opt/llvm-build/include",
    b"/opt/llvm-src/llvm/include",
)

# These are schema resource bounds, not observations about the host image.
MAX_RAW_DEPENDENCY_BYTES = 16 * 1024 * 1024
MAX_DEPENDENCY_ENTRIES = 100_000
MAX_PATH_BYTES = 4096
MAX_LINK_TARGET_BYTES = 4096
MAX_SYMLINK_CHAIN_ENTRIES = 4096
MAX_FILE_BYTES = (1 << 63) - 1

ZERO_AUTHORITY = True
AUTHORITY = False
ENGINE_WIRING_AUTHORITY = False
UPLOAD_AUTHORITY = False
PERMIT_AUTHORITY = False
HOLDOUT_ACCESS_AUTHORITY = False
AGENT_MODIFICATION_AUTHORITY = False
CALIBRATION_UPLOAD_AUTHORITY = False
PRODUCTION_UPLOAD_AUTHORITY = False

DEPENDENCY_INVALID_TYPE = "DEPENDENCY_INVALID_TYPE"
DEPENDENCY_RESOURCE_LIMIT = "DEPENDENCY_RESOURCE_LIMIT"
DEPENDENCY_ENCODING = "DEPENDENCY_ENCODING"
DEPENDENCY_SYNTAX = "DEPENDENCY_SYNTAX"
DEPENDENCY_TARGET = "DEPENDENCY_TARGET"
DEPENDENCY_TOKEN = "DEPENDENCY_TOKEN"
DEPENDENCY_EMPTY = "DEPENDENCY_EMPTY"
DEPENDENCY_DUPLICATE = "DEPENDENCY_DUPLICATE"
DEPENDENCY_PATH = "DEPENDENCY_PATH"
DEPENDENCY_SCHEMA = "DEPENDENCY_SCHEMA"
DEPENDENCY_ORDER = "DEPENDENCY_ORDER"
DEPENDENCY_HASH = "DEPENDENCY_HASH"
DEPENDENCY_CBOR = "DEPENDENCY_CBOR"

_TOKEN_SEPARATORS = frozenset(" \t\f\v")
_FORBIDDEN_TOKEN_CHARS = frozenset("#$:")


class LaunchGateDependencyManifestError(EIRPrebindingError):
    """A raw dependency or materialized manifest value failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)


# A shorter name is useful to callers that use the surrounding v6.3.1 error
# terminology.  Both names identify the same exception type.
DependencyManifestError = LaunchGateDependencyManifestError


def _fail(code: str, message: str) -> LaunchGateDependencyManifestError:
    return LaunchGateDependencyManifestError(code, message)


def _strict_utf8(raw: bytes, label: str) -> str:
    if type(raw) is not bytes:
        raise _fail(DEPENDENCY_INVALID_TYPE, f"{label} must be bytes")
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise _fail(DEPENDENCY_ENCODING, f"{label} is not valid UTF-8") from exc


def _strict_bytes(value: Any, label: str, maximum: int) -> bytes:
    if type(value) is not bytes:
        raise _fail(DEPENDENCY_INVALID_TYPE, f"{label} must be a byte string")
    if len(value) > maximum:
        raise _fail(DEPENDENCY_RESOURCE_LIMIT, f"{label} exceeds {maximum} bytes")
    return value


def _uint64(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        raise _fail(DEPENDENCY_SCHEMA, f"{label} must be a bounded nonnegative integer")
    return value


def _hash32(value: Any, label: str) -> bytes:
    result = _strict_bytes(value, label, 32)
    if len(result) != 32:
        raise _fail(DEPENDENCY_HASH, f"{label} must be exactly 32 bytes")
    return result


def _canonical_absolute_path_bytes(value: Any, label: str) -> bytes:
    raw = _strict_bytes(value, label, MAX_PATH_BYTES)
    if not raw:
        raise _fail(DEPENDENCY_PATH, f"{label} must not be empty")
    text = _strict_utf8(raw, label)
    if "\x00" in text or "\\" in text:
        raise _fail(DEPENDENCY_PATH, f"{label} contains a forbidden byte")
    if any(character.isspace() for character in text):
        raise _fail(DEPENDENCY_PATH, f"{label} contains whitespace")
    if any(character in _FORBIDDEN_TOKEN_CHARS for character in text):
        raise _fail(DEPENDENCY_PATH, f"{label} contains a forbidden path character")
    if not text.startswith("/"):
        raise _fail(DEPENDENCY_PATH, f"{label} must be absolute")
    if text != "/" and text.endswith("/"):
        raise _fail(DEPENDENCY_PATH, f"{label} must not have a trailing slash")
    components = [] if text == "/" else text[1:].split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _fail(DEPENDENCY_PATH, f"{label} is not a canonical lexical path")
    return raw


def _dependency_token_bytes(value: Any, label: str = "dependency") -> bytes:
    raw = _strict_bytes(value, label, MAX_PATH_BYTES)
    if not raw:
        raise _fail(DEPENDENCY_EMPTY, f"{label} is empty")
    text = _strict_utf8(raw, label)
    if "\x00" in text:
        raise _fail(DEPENDENCY_TOKEN, f"{label} contains NUL")
    if any(character.isspace() for character in text):
        raise _fail(DEPENDENCY_TOKEN, f"{label} contains whitespace")
    if any(character in _FORBIDDEN_TOKEN_CHARS for character in text):
        raise _fail(DEPENDENCY_TOKEN, f"{label} contains #, $, or colon")
    if "\\" in text:
        raise _fail(DEPENDENCY_TOKEN, f"{label} contains a non-continuation backslash")
    return raw


def lexical_absolute_dependency_path(token: bytes | str) -> bytes:
    """Derive one absolute POSIX path without consulting the filesystem.

    The input is a raw dependency token.  POSIX ``.``/``..`` components and
    repeated separators are normalized lexically.  Relative tokens are joined
    to the fixed working directory ``/work``.  No filesystem operation is
    performed and the returned bytes do not assert that the path exists.
    """

    if type(token) is str:
        try:
            token_bytes = token.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise _fail(DEPENDENCY_ENCODING, "dependency token is not valid UTF-8") from exc
    elif type(token) is bytes:
        token_bytes = token
    else:
        raise _fail(DEPENDENCY_INVALID_TYPE, "dependency token must be bytes or text")
    token_bytes = _dependency_token_bytes(token_bytes)
    token_text = _strict_utf8(token_bytes, "dependency token")

    joined = token_text if token_text.startswith("/") else posixpath.join(
        LEXICAL_WORKING_DIRECTORY, token_text
    )
    components: list[str] = []
    for component in joined.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if components:
                components.pop()
            continue
        components.append(component)
    normalized = "/" + "/".join(components)
    result = normalized.encode("utf-8", "strict")
    return _canonical_absolute_path_bytes(result, "lexical absolute dependency path")


def _strip_make_continuations(raw: bytes) -> bytes:
    if type(raw) is not bytes:
        raise _fail(DEPENDENCY_INVALID_TYPE, "raw dependency input must be bytes")
    if len(raw) > MAX_RAW_DEPENDENCY_BYTES:
        raise _fail(DEPENDENCY_RESOURCE_LIMIT, "raw dependency input exceeds its byte bound")
    if b"\x00" in raw:
        raise _fail(DEPENDENCY_ENCODING, "raw dependency input contains NUL")
    _strict_utf8(raw, "raw dependency input")

    # Clang's -MD output terminates its sole rule with one LF.  That terminal
    # record delimiter is not a second rule; every other bare CR/LF remains a
    # syntax error.  CRLF is deliberately outside the frozen grammar.
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raise _fail(DEPENDENCY_SYNTAX, "CRLF is not the frozen dependency delimiter")

    output = bytearray()
    index = 0
    while index < len(raw):
        byte = raw[index]
        if byte == 0x5C:  # backslash
            if index + 1 >= len(raw) or raw[index + 1] != 0x0A:
                raise _fail(
                    DEPENDENCY_SYNTAX,
                    "only backslash-newline continuation is permitted",
                )
            output.append(0x20)
            index += 2
            continue
        if byte in (0x0A, 0x0D):
            raise _fail(DEPENDENCY_SYNTAX, "bare line termination is not a dependency continuation")
        output.append(byte)
        index += 1
    return bytes(output)


def _split_dependency_tokens(raw: str) -> tuple[str, ...]:
    tokens: list[str] = []
    current: list[str] = []

    def append_current() -> None:
        if len(tokens) >= MAX_DEPENDENCY_ENTRIES:
            raise _fail(
                DEPENDENCY_RESOURCE_LIMIT,
                f"dependency list exceeds {MAX_DEPENDENCY_ENTRIES} entries",
            )
        tokens.append("".join(current))
        current.clear()

    for character in raw:
        if character in _TOKEN_SEPARATORS:
            if current:
                append_current()
            continue
        if character.isspace():
            raise _fail(DEPENDENCY_TOKEN, "non-ASCII whitespace is not a token separator")
        if character in _FORBIDDEN_TOKEN_CHARS:
            raise _fail(DEPENDENCY_TOKEN, "dependency tokens cannot contain #, $, or colon")
        if character == "\\":
            raise _fail(DEPENDENCY_SYNTAX, "non-continuation backslash remains")
        current.append(character)
    if current:
        append_current()
    if not tokens:
        raise _fail(DEPENDENCY_EMPTY, "dependency rule has an empty dependency list")
    return tuple(tokens)


@dataclass(frozen=True)
class ParsedMakeDependencyFileV1:
    """The parser's lexical result; it contains no filesystem evidence."""

    target: bytes
    dependency_tokens: tuple[bytes, ...]
    lexical_absolute_paths: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if self.target != TARGET_NAME_BYTES:
            raise _fail(DEPENDENCY_TARGET, "parsed target is not the exact decoder object target")
        if type(self.dependency_tokens) is not tuple:
            raise _fail(DEPENDENCY_INVALID_TYPE, "dependency_tokens must be an immutable tuple")
        if type(self.lexical_absolute_paths) is not tuple:
            raise _fail(DEPENDENCY_INVALID_TYPE, "lexical_absolute_paths must be an immutable tuple")
        if len(self.dependency_tokens) != len(self.lexical_absolute_paths):
            raise _fail(DEPENDENCY_SCHEMA, "token and lexical path counts differ")
        if len(self.dependency_tokens) == 0:
            raise _fail(DEPENDENCY_EMPTY, "dependency list is empty")
        if len(self.dependency_tokens) > MAX_DEPENDENCY_ENTRIES:
            raise _fail(
                DEPENDENCY_RESOURCE_LIMIT,
                f"dependency list exceeds {MAX_DEPENDENCY_ENTRIES} entries",
            )
        seen: set[bytes] = set()
        for index, (token, path) in enumerate(
            zip(self.dependency_tokens, self.lexical_absolute_paths)
        ):
            _dependency_token_bytes(token, f"dependency token {index}")
            _canonical_absolute_path_bytes(path, f"lexical path {index}")
            if path in seen:
                raise _fail(DEPENDENCY_DUPLICATE, "duplicate lexical dependency path")
            seen.add(path)

    def as_arrays(self) -> list[Any]:
        return [self.target, list(self.dependency_tokens), list(self.lexical_absolute_paths)]


def parse_make_dependency_file_v1(raw: bytes) -> ParsedMakeDependencyFileV1:
    """Parse exactly one pinned Make dependency rule from raw bytes."""

    flattened = _strip_make_continuations(raw)
    text = _strict_utf8(flattened, "flattened dependency input")
    if text.count(":") != 1:
        raise _fail(DEPENDENCY_SYNTAX, "exactly one Make target separator is required")
    target_text, dependency_text = text.split(":", 1)
    if target_text.strip(" \t\f\v") != TARGET_NAME:
        raise _fail(DEPENDENCY_TARGET, "dependency target is not the exact pinned object target")
    token_texts = _split_dependency_tokens(dependency_text)
    token_bytes = tuple(token.encode("utf-8", "strict") for token in token_texts)
    lexical_paths = tuple(lexical_absolute_dependency_path(token) for token in token_bytes)
    if len(set(lexical_paths)) != len(lexical_paths):
        raise _fail(DEPENDENCY_DUPLICATE, "duplicate lexical dependency path")
    return ParsedMakeDependencyFileV1(TARGET_NAME_BYTES, token_bytes, lexical_paths)


# Descriptive aliases for callers using the terminology from the ruling.
parse_raw_dependency_file_v1 = parse_make_dependency_file_v1
parse_raw_make_dependency_file_v1 = parse_make_dependency_file_v1
derive_lexical_absolute_path = lexical_absolute_dependency_path


@dataclass(frozen=True)
class SymlinkRowV1:
    """One materialized symlink observation; it is not collected here."""

    symlink_absolute_path_bytes: bytes
    exact_link_target_bytes: bytes
    sha256_of_exact_link_target_bytes: bytes

    def __post_init__(self) -> None:
        _canonical_absolute_path_bytes(
            self.symlink_absolute_path_bytes, "symlink_absolute_path_bytes"
        )
        target = _strict_bytes(
            self.exact_link_target_bytes,
            "exact_link_target_bytes",
            MAX_LINK_TARGET_BYTES,
        )
        if b"\x00" in target:
            raise _fail(DEPENDENCY_SCHEMA, "exact_link_target_bytes contains NUL")
        digest = _hash32(
            self.sha256_of_exact_link_target_bytes,
            "sha256_of_exact_link_target_bytes",
        )
        if digest != sha256(target).digest():
            raise _fail(DEPENDENCY_HASH, "symlink target hash does not match target bytes")

    def as_array(self) -> list[Any]:
        return [
            self.symlink_absolute_path_bytes,
            self.exact_link_target_bytes,
            self.sha256_of_exact_link_target_bytes,
        ]

    @classmethod
    def from_array(cls, value: Any) -> "SymlinkRowV1":
        if type(value) is not list or len(value) != 3:
            raise _fail(DEPENDENCY_SCHEMA, "symlink row must be an array of three fields")
        return cls(value[0], value[1], value[2])


SymlinkChainEntryV1 = SymlinkRowV1


@dataclass(frozen=True)
class DependencyRowV1:
    """One canonical dependency row made from caller-supplied evidence."""

    lexical_absolute_path_bytes: bytes
    canonical_real_path_bytes: bytes
    byte_length: int
    file_sha256: bytes
    symlink_chain: tuple[SymlinkRowV1, ...]

    def __post_init__(self) -> None:
        _canonical_absolute_path_bytes(
            self.lexical_absolute_path_bytes, "lexical_absolute_path_bytes"
        )
        _canonical_absolute_path_bytes(
            self.canonical_real_path_bytes, "canonical_real_path_bytes"
        )
        _uint64(self.byte_length, "byte_length", MAX_FILE_BYTES)
        _hash32(self.file_sha256, "file_sha256")
        if type(self.symlink_chain) is not tuple:
            raise _fail(DEPENDENCY_INVALID_TYPE, "symlink_chain must be an immutable tuple")
        if len(self.symlink_chain) > MAX_SYMLINK_CHAIN_ENTRIES:
            raise _fail(DEPENDENCY_RESOURCE_LIMIT, "symlink_chain exceeds its entry bound")
        seen: set[bytes] = set()
        for row in self.symlink_chain:
            if type(row) is not SymlinkRowV1:
                raise _fail(DEPENDENCY_INVALID_TYPE, "symlink_chain contains an invalid row type")
            path = row.symlink_absolute_path_bytes
            if path in seen:
                raise _fail(DEPENDENCY_DUPLICATE, "symlink_chain contains a duplicate path")
            seen.add(path)

    def as_array(self) -> list[Any]:
        return [
            self.lexical_absolute_path_bytes,
            self.canonical_real_path_bytes,
            self.byte_length,
            self.file_sha256,
            [row.as_array() for row in self.symlink_chain],
        ]

    @classmethod
    def from_array(cls, value: Any) -> "DependencyRowV1":
        if type(value) is not list or len(value) != 5:
            raise _fail(DEPENDENCY_SCHEMA, "dependency row must be an array of five fields")
        symlink_values = value[4]
        if type(symlink_values) is not list:
            raise _fail(DEPENDENCY_SCHEMA, "symlink_chain must be an array")
        return cls(
            value[0],
            value[1],
            value[2],
            value[3],
            tuple(SymlinkRowV1.from_array(item) for item in symlink_values),
        )


def _validate_sorted_unique_rows(rows: tuple[DependencyRowV1, ...]) -> None:
    if len(rows) > MAX_DEPENDENCY_ENTRIES:
        raise _fail(DEPENDENCY_RESOURCE_LIMIT, "dependency entry count exceeds its bound")
    if not rows:
        raise _fail(DEPENDENCY_EMPTY, "dependency manifest must contain at least one entry")
    previous: bytes | None = None
    for row in rows:
        if type(row) is not DependencyRowV1:
            raise _fail(DEPENDENCY_INVALID_TYPE, "dependency entries contain an invalid row type")
        current = row.lexical_absolute_path_bytes
        if previous is not None and current <= previous:
            raise _fail(DEPENDENCY_ORDER, "dependency entries are not strictly byte-sorted")
        previous = current


@dataclass(frozen=True)
class DependencyManifestV1:
    """The exact Section 10 manifest, permanently without authority."""

    entries: tuple[DependencyRowV1, ...]
    protocol_id: int = PROTOCOL_ID
    version: int = WIRE_VERSION
    header_roots: tuple[bytes, bytes] = LLVM_HEADER_ROOTS

    def __post_init__(self) -> None:
        if self.protocol_id != PROTOCOL_ID or type(self.protocol_id) is not int:
            raise _fail(DEPENDENCY_SCHEMA, "protocol_id is not the exact protocol identifier")
        if self.version != WIRE_VERSION or type(self.version) is not int:
            raise _fail(DEPENDENCY_SCHEMA, "manifest version is not the exact wire version")
        if type(self.header_roots) is not tuple or self.header_roots != LLVM_HEADER_ROOTS:
            raise _fail(DEPENDENCY_SCHEMA, "header roots are not the exact ordered roots")
        if type(self.entries) is not tuple:
            raise _fail(DEPENDENCY_INVALID_TYPE, "entries must be an immutable tuple")
        _validate_sorted_unique_rows(self.entries)

    @classmethod
    def from_entries(cls, entries: Iterable[DependencyRowV1]) -> "DependencyManifestV1":
        return cls(tuple(entries))

    def as_array(self) -> list[Any]:
        return [
            self.protocol_id,
            self.version,
            list(self.header_roots),
            [row.as_array() for row in self.entries],
        ]

    @classmethod
    def from_array(cls, value: Any) -> "DependencyManifestV1":
        if type(value) is not list or len(value) != 4:
            raise _fail(DEPENDENCY_SCHEMA, "dependency manifest must be an array of four fields")
        roots = value[2]
        entries = value[3]
        if type(roots) is not list or len(roots) != 2:
            raise _fail(DEPENDENCY_SCHEMA, "header roots must be an array of two fields")
        if type(entries) is not list:
            raise _fail(DEPENDENCY_SCHEMA, "dependency entries must be an array")
        return cls(
            tuple(DependencyRowV1.from_array(item) for item in entries),
            value[0],
            value[1],
            tuple(roots),
        )


def build_dependency_manifest_v1(
    entries: Sequence[DependencyRowV1],
) -> DependencyManifestV1:
    """Validate materialized rows into the exact manifest data type."""

    if type(entries) not in (list, tuple):
        raise _fail(DEPENDENCY_INVALID_TYPE, "entries must be a list or tuple")
    return DependencyManifestV1.from_entries(entries)


def encode_dependency_manifest_v1(
    manifest: DependencyManifestV1 | Sequence[DependencyRowV1],
) -> bytes:
    """Encode the exact arrays-only canonical CBOR manifest."""

    if isinstance(manifest, DependencyManifestV1):
        value = manifest
    elif type(manifest) in (list, tuple):
        value = build_dependency_manifest_v1(manifest)
    else:
        raise _fail(DEPENDENCY_INVALID_TYPE, "manifest must be a DependencyManifestV1")
    return eir_canonical_cbor_encode(value.as_array())


def decode_dependency_manifest_v1(raw: bytes) -> DependencyManifestV1:
    """Decode and semantically validate one exact canonical CBOR manifest."""

    if type(raw) is not bytes:
        raise _fail(DEPENDENCY_INVALID_TYPE, "dependency manifest CBOR must be bytes")
    try:
        value = eir_canonical_cbor_decode(raw)
    except EIRPrebindingError as exc:
        raise _fail(DEPENDENCY_CBOR, f"dependency manifest CBOR is invalid: {exc}") from exc
    manifest = DependencyManifestV1.from_array(value)
    if encode_dependency_manifest_v1(manifest) != raw:
        raise _fail(DEPENDENCY_CBOR, "dependency manifest is not byte-canonical")
    return manifest


validate_dependency_manifest_v1 = DependencyManifestV1.from_array
canonical_dependency_manifest_v1 = encode_dependency_manifest_v1


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
    "CALIBRATION_UPLOAD_AUTHORITY",
    "DependencyManifestError",
    "DependencyManifestV1",
    "DependencyRowV1",
    "DEPENDENCY_CBOR",
    "DEPENDENCY_DUPLICATE",
    "DEPENDENCY_EMPTY",
    "DEPENDENCY_INVALID_TYPE",
    "DEPENDENCY_ORDER",
    "DEPENDENCY_PATH",
    "DEPENDENCY_SCHEMA",
    "DEPENDENCY_SYNTAX",
    "DEPENDENCY_TARGET",
    "DEPENDENCY_TOKEN",
    "DEPENDENCY_ENCODING",
    "DEPENDENCY_HASH",
    "DEPENDENCY_RESOURCE_LIMIT",
    "ENGINE_WIRING_AUTHORITY",
    "HOLDOUT_ACCESS_AUTHORITY",
    "LEXICAL_WORKING_DIRECTORY",
    "LEXICAL_WORKING_DIRECTORY_BYTES",
    "LLVM_HEADER_ROOTS",
    "LaunchGateDependencyManifestError",
    "MAX_DEPENDENCY_ENTRIES",
    "MAX_FILE_BYTES",
    "MAX_LINK_TARGET_BYTES",
    "MAX_PATH_BYTES",
    "MAX_RAW_DEPENDENCY_BYTES",
    "MAX_SYMLINK_CHAIN_ENTRIES",
    "ParsedMakeDependencyFileV1",
    "PERMIT_AUTHORITY",
    "PRODUCTION_UPLOAD_AUTHORITY",
    "PROTOCOL_ID",
    "SymlinkChainEntryV1",
    "SymlinkRowV1",
    "TARGET_NAME",
    "TARGET_NAME_BYTES",
    "UPLOAD_AUTHORITY",
    "WIRE_VERSION",
    "ZERO_AUTHORITY",
    "build_dependency_manifest_v1",
    "canonical_dependency_manifest_v1",
    "decode_dependency_manifest_v1",
    "derive_lexical_absolute_path",
    "eir_canonical_cbor_decode",
    "eir_canonical_cbor_encode",
    "encode_dependency_manifest_v1",
    "lexical_absolute_dependency_path",
    "parse_make_dependency_file_v1",
    "parse_raw_dependency_file_v1",
    "parse_raw_make_dependency_file_v1",
    "validate_dependency_manifest_v1",
    "zero_authority_status",
]
