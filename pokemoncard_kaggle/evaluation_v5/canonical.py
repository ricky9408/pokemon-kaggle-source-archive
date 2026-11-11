"""The single deterministic JSON and hash representation used by v5."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class CanonicalJSONError(ValueError):
    """The value is not a finite, JSON-native value."""


def _check_json(value: object, *, path: str = "$", active: set[int] | None = None) -> None:
    """Reject Python conveniences that ``json.dumps`` would silently coerce."""

    if active is None:
        active = set()
    value_type = type(value)
    if value is None or value_type is bool or value_type is int or value_type is str:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise CanonicalJSONError(f"{path} contains NaN or infinity")
        return
    if value_type is list:
        object_id = id(value)
        if object_id in active:
            raise CanonicalJSONError(f"{path} contains a cyclic reference")
        active.add(object_id)
        try:
            for index, item in enumerate(value):
                _check_json(item, path=f"{path}[{index}]", active=active)
        finally:
            active.remove(object_id)
        return
    if value_type is dict:
        object_id = id(value)
        if object_id in active:
            raise CanonicalJSONError(f"{path} contains a cyclic reference")
        active.add(object_id)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise CanonicalJSONError(f"{path} has a non-string object key")
                _check_json(item, path=f"{path}.{key}", active=active)
        finally:
            active.remove(object_id)
        return
    raise CanonicalJSONError(f"{path} contains non-JSON type {value_type.__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return compact, sorted, ASCII JSON bytes or fail closed.

    Tuples, sets, bytes, custom scalar subclasses, non-string object keys, and
    non-finite floats are deliberately not accepted as JSON input.
    """

    _check_json(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CanonicalJSONError(f"value is not canonical JSON: {exc}") from exc
    return encoded


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 digest of :func:`canonical_json_bytes`."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = ["CanonicalJSONError", "canonical_json_bytes", "canonical_sha256"]
