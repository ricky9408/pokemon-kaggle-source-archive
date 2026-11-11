from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import math

import pytest

from evaluation_v5.canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from evaluation_v5.charter import (
    ALPHA,
    EFFECT_THRESHOLD_NATS,
    FEATURE_NAMES,
    FORBIDDEN_SELECTORS,
    Charter,
    CharterError,
    build_charter,
    validate_charter,
)


def test_canonical_json_is_order_independent_and_hash_changes_on_tamper() -> None:
    assert canonical_json_bytes({"b": 2, "a": [True, None]}) == b'{"a":[true,null],"b":2}'
    assert canonical_sha256({"a": 1}) != canonical_sha256({"a": 2})
    assert canonical_sha256({"a": 1}) == canonical_sha256({"a": 1})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), {1: "bad"}, (1, 2), {1, 2}, b"bytes"])
def test_canonical_json_rejects_non_json_values(value: object) -> None:
    with pytest.raises(CanonicalJSONError):
        canonical_json_bytes(value)


def test_charter_is_exact_and_authority_is_closed() -> None:
    charter = build_charter()
    assert charter.protocol_id == "MCI_TRANSFER_V1"
    assert charter.feature_names == FEATURE_NAMES
    assert charter.forbidden_selectors == FORBIDDEN_SELECTORS
    assert charter.min_archives == 30
    assert charter.min_families == 15
    assert charter.games_per_archive == 48
    assert charter.alpha == ALPHA
    assert charter.effect_threshold_nats == EFFECT_THRESHOLD_NATS
    assert charter.deadline_days == 120
    assert charter.authority is False
    with pytest.raises(FrozenInstanceError):
        charter.authority = True  # type: ignore[misc]


@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol_id", "OTHER"),
        ("feature_names", ("wrong",)),
        ("alpha", 0.05),
        ("effect_threshold_nats", 0.0),
        ("min_archives", True),
        ("authority", True),
    ],
)
def test_charter_drift_fails_closed(field: str, value: object) -> None:
    with pytest.raises(CharterError):
        replace(build_charter(), **{field: value})


def test_charter_wire_hash_rejects_tamper() -> None:
    charter = build_charter()
    wire = charter.as_dict()
    assert validate_charter(wire) == charter
    wire["effect_threshold_nats"] = math.nextafter(EFFECT_THRESHOLD_NATS, 1.0)
    with pytest.raises(CharterError):
        validate_charter(wire)


def test_charter_wire_schema_is_bound() -> None:
    wire = build_charter().as_dict()
    wire["schema"] = "other"
    with pytest.raises(CharterError, match="schema"):
        validate_charter(wire)
