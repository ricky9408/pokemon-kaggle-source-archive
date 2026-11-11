"""Small, strict deterministic-CBOR codec for v6.3.1 trace values.

This module deliberately implements only the CBOR data model needed by the
trace architecture.  It has no authority, upload, permit, or holdout logic.
The wire profile follows deterministic CBOR ordering: map keys are ordered by
the length of their encoded key, then by the encoded key bytes.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Any


TRACE_NONCANONICAL_ENCODING = "TRACE_NONCANONICAL_ENCODING"
TRACE_UNSUPPORTED_TYPE = "TRACE_UNSUPPORTED_TYPE"
TRACE_RESOURCE_LIMIT = "TRACE_CODEC_RESOURCE_LIMIT"
TRACE_INTEGER_OUT_OF_RANGE = "TRACE_INTEGER_OUT_OF_RANGE"

# These bounds keep malformed input from turning the codec into an unbounded
# allocator or Python-recursion exercise.  They are part of this codec's wire
# profile, rather than caller-selectable knobs.
MAX_DEPTH = 64
MAX_CONTAINER_ITEMS = 100_000
MAX_NODES = 200_000
MAX_TEXT_BYTES = 1 * 1024 * 1024
MAX_BYTE_STRING_BYTES = 1 * 1024 * 1024
MAX_ENCODED_BYTES = 16 * 1024 * 1024

_UINT64_MAX = (1 << 64) - 1


class CanonicalTraceCodecError(ValueError):
    """A canonical trace value or byte string failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> CanonicalTraceCodecError:
    return CanonicalTraceCodecError(code, message)


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise _fail(TRACE_NONCANONICAL_ENCODING, "CBOR length or integer argument is negative")
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
    raise _fail(TRACE_INTEGER_OUT_OF_RANGE, "integer or length exceeds CBOR uint64")


def _check_text(value: str) -> bytes:
    if unicodedata.normalize("NFC", value) != value:
        raise _fail(TRACE_NONCANONICAL_ENCODING, "text is not NFC-normalized")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _fail(TRACE_NONCANONICAL_ENCODING, "text is not valid UTF-8") from exc
    if len(encoded) > MAX_TEXT_BYTES:
        raise _fail(TRACE_RESOURCE_LIMIT, "text exceeds the codec byte limit")
    return encoded


class _Encoder:
    def __init__(self) -> None:
        self.nodes = 0
        self.active: set[int] = set()

    def _visit(self, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise _fail(TRACE_RESOURCE_LIMIT, "CBOR nesting exceeds the codec depth limit")
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _fail(TRACE_RESOURCE_LIMIT, "CBOR node count exceeds the codec limit")

    def _container_start(self, value: Any, depth: int) -> int:
        self._visit(depth)
        if len(value) > MAX_CONTAINER_ITEMS:
            raise _fail(TRACE_RESOURCE_LIMIT, "CBOR container exceeds the item limit")
        identity = id(value)
        if identity in self.active:
            raise _fail(TRACE_NONCANONICAL_ENCODING, "cyclic Python value cannot be encoded")
        self.active.add(identity)
        return identity

    def _container_end(self, identity: int) -> None:
        self.active.remove(identity)

    def value(self, value: Any, depth: int = 0) -> bytes:
        if value is None:
            self._visit(depth)
            return b"\xf6"
        if type(value) is bool:
            self._visit(depth)
            return b"\xf5" if value else b"\xf4"
        if type(value) is int:
            self._visit(depth)
            if value >= 0:
                return _head(0, value)
            magnitude = -1 - value
            if magnitude > _UINT64_MAX:
                raise _fail(TRACE_INTEGER_OUT_OF_RANGE, "negative integer exceeds CBOR int64 profile")
            return _head(1, magnitude)
        if type(value) is bytes:
            self._visit(depth)
            if len(value) > MAX_BYTE_STRING_BYTES:
                raise _fail(TRACE_RESOURCE_LIMIT, "byte string exceeds the codec byte limit")
            return _head(2, len(value)) + value
        if type(value) is str:
            self._visit(depth)
            encoded = _check_text(value)
            return _head(3, len(encoded)) + encoded
        if type(value) is list or type(value) is tuple:
            identity = self._container_start(value, depth)
            try:
                encoded_items = []
                encoded_length = len(_head(4, len(value)))
                for item in value:
                    encoded_item = self.value(item, depth + 1)
                    encoded_length += len(encoded_item)
                    if encoded_length > MAX_ENCODED_BYTES:
                        raise _fail(TRACE_RESOURCE_LIMIT, "encoded value exceeds the byte limit")
                    encoded_items.append(encoded_item)
                result = _head(4, len(encoded_items)) + b"".join(encoded_items)
            finally:
                self._container_end(identity)
            if len(result) > MAX_ENCODED_BYTES:
                raise _fail(TRACE_RESOURCE_LIMIT, "encoded value exceeds the byte limit")
            return result
        if type(value) is dict:
            identity = self._container_start(value, depth)
            try:
                entries = []
                encoded_length = len(_head(5, len(value)))
                for key, item in value.items():
                    encoded_key = self.value(key, depth + 1)
                    encoded_item = self.value(item, depth + 1)
                    encoded_length += len(encoded_key) + len(encoded_item)
                    if encoded_length > MAX_ENCODED_BYTES:
                        raise _fail(TRACE_RESOURCE_LIMIT, "encoded value exceeds the byte limit")
                    entries.append((encoded_key, encoded_item))
                entries.sort(key=lambda pair: (len(pair[0]), pair[0]))
                for previous, current in zip(entries, entries[1:]):
                    if current[0] == previous[0]:
                        raise _fail(TRACE_NONCANONICAL_ENCODING, "map contains duplicate encoded keys")
                result = _head(5, len(entries)) + b"".join(
                    key + item for key, item in entries
                )
            finally:
                self._container_end(identity)
            if len(result) > MAX_ENCODED_BYTES:
                raise _fail(TRACE_RESOURCE_LIMIT, "encoded value exceeds the byte limit")
            return result
        raise _fail(TRACE_UNSUPPORTED_TYPE, f"unsupported Python type: {type(value).__name__}")


def canonical_cbor_encode(value: Any) -> bytes:
    """Encode a supported Python value as canonical, definite-length CBOR."""

    encoded = _Encoder().value(value)
    if len(encoded) > MAX_ENCODED_BYTES:
        raise _fail(TRACE_RESOURCE_LIMIT, "encoded value exceeds the byte limit")
    return encoded


class _Decoder:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0
        self.nodes = 0

    def _visit(self, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise _fail(TRACE_RESOURCE_LIMIT, "CBOR nesting exceeds the codec depth limit")
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise _fail(TRACE_RESOURCE_LIMIT, "CBOR node count exceeds the codec limit")

    def _take(self, count: int) -> bytes:
        end = self.offset + count
        if count < 0 or end > len(self.raw):
            raise _fail(TRACE_NONCANONICAL_ENCODING, "truncated CBOR value")
        value = self.raw[self.offset:end]
        self.offset = end
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise _fail(TRACE_NONCANONICAL_ENCODING, "indefinite or unsupported CBOR argument")
        encoded = self._take(width)
        value = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 256, 4: 65_536, 8: 1 << 32}[width]
        if value < minimum:
            raise _fail(TRACE_NONCANONICAL_ENCODING, "CBOR argument is not minimally encoded")
        return value

    def value(self, depth: int = 0, *, key_context: bool = False) -> Any:
        self._visit(depth)
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F

        if major in (0, 1):
            argument = self._argument(additional)
            return argument if major == 0 else -1 - argument
        if major == 2 or major == 3:
            length = self._argument(additional)
            limit = MAX_BYTE_STRING_BYTES if major == 2 else MAX_TEXT_BYTES
            if length > limit:
                raise _fail(TRACE_RESOURCE_LIMIT, "CBOR string exceeds the codec byte limit")
            payload = self._take(length)
            if major == 2:
                return payload
            try:
                text = payload.decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise _fail(TRACE_NONCANONICAL_ENCODING, "text is not valid UTF-8") from exc
            if unicodedata.normalize("NFC", text) != text:
                raise _fail(TRACE_NONCANONICAL_ENCODING, "text is not NFC-normalized")
            return text
        if major == 4:
            length = self._argument(additional)
            if length > MAX_CONTAINER_ITEMS:
                raise _fail(TRACE_RESOURCE_LIMIT, "CBOR array exceeds the item limit")
            items = [self.value(depth + 1, key_context=key_context) for _ in range(length)]
            return tuple(items) if key_context else items
        if major == 5:
            length = self._argument(additional)
            if length > MAX_CONTAINER_ITEMS:
                raise _fail(TRACE_RESOURCE_LIMIT, "CBOR map exceeds the item limit")
            result: dict[Any, Any] = {}
            previous_order: tuple[int, bytes] | None = None
            key_value_pairs: list[tuple[Any, Any]] = []
            for _ in range(length):
                key_start = self.offset
                key = self.value(depth + 1, key_context=True)
                encoded_key = self.raw[key_start:self.offset]
                order = (len(encoded_key), encoded_key)
                if previous_order is not None and order <= previous_order:
                    raise _fail(TRACE_NONCANONICAL_ENCODING, "map keys are not in canonical order")
                previous_order = order
                item = self.value(depth + 1, key_context=key_context)
                try:
                    duplicate = key in result
                except TypeError as exc:
                    raise _fail(TRACE_UNSUPPORTED_TYPE, "map key cannot be represented by Python") from exc
                if duplicate:
                    raise _fail(TRACE_NONCANONICAL_ENCODING, "map contains duplicate keys")
                result[key] = item
                key_value_pairs.append((key, item))
            if key_context:
                return tuple(key_value_pairs)
            return result
        if major == 7 and additional in (20, 21, 22):
            return {20: False, 21: True, 22: None}[additional]
        raise _fail(TRACE_NONCANONICAL_ENCODING, "unsupported CBOR type, tag, float, or indefinite length")


def canonical_cbor_decode(raw: bytes) -> Any:
    """Decode one complete canonical CBOR value and reject all trailing bytes."""

    if type(raw) is not bytes:
        raise _fail(TRACE_UNSUPPORTED_TYPE, "raw CBOR input must be bytes")
    if not raw:
        raise _fail(TRACE_NONCANONICAL_ENCODING, "CBOR input is empty")
    if len(raw) > MAX_ENCODED_BYTES:
        raise _fail(TRACE_RESOURCE_LIMIT, "CBOR input exceeds the byte limit")
    decoder = _Decoder(raw)
    value = decoder.value()
    if decoder.offset != len(raw):
        raise _fail(TRACE_NONCANONICAL_ENCODING, "trailing bytes after CBOR value")
    return value


def domain_sha256(domain: bytes, value: Any) -> str:
    """Return hex SHA-256 of ``domain || canonical_cbor_encode(value)``."""

    if type(domain) is not bytes or not domain:
        raise _fail(TRACE_UNSUPPORTED_TYPE, "hash domain must be non-empty bytes")
    payload = canonical_cbor_encode(value)
    return hashlib.sha256(domain + payload).hexdigest()


__all__ = [
    "CanonicalTraceCodecError",
    "canonical_cbor_encode",
    "canonical_cbor_decode",
    "domain_sha256",
]
