"""Strict canonical JSON representation for v5.1 evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import math


class CanonicalJSONError(ValueError):
    """The value is not finite, JSON-native, and canonically representable."""


def _check_json(value: object, *, path: str = "$", active: set[int] | None = None) -> None:
    if active is None:
        active = set()
    value_type = type(value)
    if value is None or value_type in {bool, int, str}:
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
                    raise CanonicalJSONError(f"{path} has a non-string key")
                _check_json(item, path=f"{path}.{key}", active=active)
        finally:
            active.remove(object_id)
        return
    raise CanonicalJSONError(f"{path} contains non-JSON type {value_type.__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return sorted compact ASCII JSON or fail closed."""

    _check_json(value)
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CanonicalJSONError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = ["CanonicalJSONError", "canonical_json_bytes", "canonical_sha256"]
