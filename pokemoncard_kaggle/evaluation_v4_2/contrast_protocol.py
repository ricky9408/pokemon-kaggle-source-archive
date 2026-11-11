"""Frozen, outcome-free v4.2 contrast protocol receipts.

This module is intentionally a custody primitive only.  A receipt describes
the inputs and execution contract for a contrast; it cannot inspect outcomes,
rank policies, authorize a quota, or submit anything externally.
"""

from __future__ import annotations

import hashlib
import json
import math
from numbers import Real
from pathlib import Path
import re
from typing import Any, Mapping


CONTRAST_PROTOCOL_SCHEMA = "evaluation_v4_2_contrast_protocol_v1"
REQUIRED_PLATFORM = "Linux/x86_64"
ARM_EXECUTION_MODE = "separate_fresh_process_per_arm"
FAILURE_POLICY = "fail_panel_on_first_error_no_retry"
ENGINE_COUNT = 2
MIN_OPPONENT_COUNT = 12
SEED_COUNT = 16
SEATS = ["policy_first", "policy_second"]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "baseline_archive_sha256",
        "baseline_policy_content_sha256",
        "baseline_main_sha256",
        "baseline_deck_sha256",
        "max_steps",
        "worker_timeout_seconds",
        "max_action_seconds",
        "workers",
        "platform",
        "arm_execution_mode",
        "failure_policy",
        "engine_count",
        "opponent_count",
        "seed_count",
        "seats",
        "population_readiness_sha256",
    }
)
_FIELDS = _CONTENT_FIELDS | {"content_sha256"}


class ContrastProtocolError(ValueError):
    """A v4.2 contrast protocol receipt is malformed or not frozen."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the one canonical JSON encoding used by the receipt hash."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContrastProtocolError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash a value after canonical JSON serialization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise ContrastProtocolError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ContrastProtocolError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _integer(value: object, *, label: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContrastProtocolError(f"{label} must be an integer, not a boolean")
    if value < minimum:
        raise ContrastProtocolError(f"{label} must be at least {minimum}")
    return value


def _finite_float(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ContrastProtocolError(f"{label} must be a finite number, not a boolean")
    result = float(value)
    if not math.isfinite(result) or result <= 0.0:
        raise ContrastProtocolError(f"{label} must be finite and positive")
    return result


def _content(value: Mapping[str, Any]) -> dict[str, Any]:
    return {field: value[field] for field in _CONTENT_FIELDS}


def _validate_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _CONTENT_FIELDS, label="contrast protocol content")
    if raw["schema"] != CONTRAST_PROTOCOL_SCHEMA:
        raise ContrastProtocolError(
            f"contrast protocol schema must be {CONTRAST_PROTOCOL_SCHEMA!r}"
        )

    normalized = {
        "schema": CONTRAST_PROTOCOL_SCHEMA,
        "baseline_archive_sha256": _sha256(
            raw["baseline_archive_sha256"], label="baseline_archive_sha256"
        ),
        "baseline_policy_content_sha256": _sha256(
            raw["baseline_policy_content_sha256"],
            label="baseline_policy_content_sha256",
        ),
        "baseline_main_sha256": _sha256(
            raw["baseline_main_sha256"], label="baseline_main_sha256"
        ),
        "baseline_deck_sha256": _sha256(
            raw["baseline_deck_sha256"], label="baseline_deck_sha256"
        ),
        "max_steps": _integer(raw["max_steps"], label="max_steps"),
        "worker_timeout_seconds": _finite_float(
            raw["worker_timeout_seconds"], label="worker_timeout_seconds"
        ),
        "max_action_seconds": _finite_float(
            raw["max_action_seconds"], label="max_action_seconds"
        ),
        "workers": _integer(raw["workers"], label="workers"),
        "platform": raw["platform"],
        "arm_execution_mode": raw["arm_execution_mode"],
        "failure_policy": raw["failure_policy"],
        "engine_count": raw["engine_count"],
        "opponent_count": raw["opponent_count"],
        "seed_count": raw["seed_count"],
        "seats": raw["seats"],
        "population_readiness_sha256": _sha256(
            raw["population_readiness_sha256"], label="population_readiness_sha256"
        ),
    }
    if normalized["platform"] != REQUIRED_PLATFORM:
        raise ContrastProtocolError(f"platform must be {REQUIRED_PLATFORM!r}")
    if normalized["arm_execution_mode"] != ARM_EXECUTION_MODE:
        raise ContrastProtocolError(f"arm_execution_mode must be {ARM_EXECUTION_MODE!r}")
    if normalized["failure_policy"] != FAILURE_POLICY:
        raise ContrastProtocolError(f"failure_policy must be {FAILURE_POLICY!r}")
    if normalized["engine_count"] != ENGINE_COUNT:
        raise ContrastProtocolError(f"engine_count must equal {ENGINE_COUNT}")
    if normalized["opponent_count"] != raw["opponent_count"]:
        raise AssertionError("unreachable opponent count normalization")
    _integer(normalized["opponent_count"], label="opponent_count", minimum=MIN_OPPONENT_COUNT)
    if normalized["seed_count"] != SEED_COUNT:
        raise ContrastProtocolError(f"seed_count must equal {SEED_COUNT}")
    if normalized["seats"] != SEATS:
        raise ContrastProtocolError(f"seats must equal {SEATS!r}")

    # These fields are deliberately canonicalized to a JSON list and floats.
    # Reject alternate spellings/types instead of accepting a rehashed variant.
    if not isinstance(raw["platform"], str):
        raise ContrastProtocolError("platform must be a string")
    if not isinstance(raw["arm_execution_mode"], str):
        raise ContrastProtocolError("arm_execution_mode must be a string")
    if not isinstance(raw["failure_policy"], str):
        raise ContrastProtocolError("failure_policy must be a string")
    if not isinstance(raw["engine_count"], int) or isinstance(raw["engine_count"], bool):
        raise ContrastProtocolError("engine_count must be an integer, not a boolean")
    if not isinstance(raw["seed_count"], int) or isinstance(raw["seed_count"], bool):
        raise ContrastProtocolError("seed_count must be an integer, not a boolean")
    if not isinstance(raw["seats"], list):
        raise ContrastProtocolError("seats must be a list")
    if not all(isinstance(seat, str) for seat in raw["seats"]):
        raise ContrastProtocolError("seats must contain only strings")
    if not isinstance(raw["worker_timeout_seconds"], float):
        raise ContrastProtocolError("worker_timeout_seconds must use canonical float form")
    if not isinstance(raw["max_action_seconds"], float):
        raise ContrastProtocolError("max_action_seconds must use canonical float form")
    if raw["seats"] != list(SEATS):
        raise ContrastProtocolError("seats must be the canonical ordered list")
    return normalized


def validate_contrast_protocol(value: object) -> dict[str, Any]:
    """Validate and return an exact, self-hash-checked protocol receipt."""

    raw = _exact_fields(value, _FIELDS, label="contrast protocol")
    content = _validate_content({field: raw[field] for field in _CONTENT_FIELDS})
    digest = _sha256(raw["content_sha256"], label="content_sha256")
    if digest != canonical_sha256(content):
        raise ContrastProtocolError("contrast protocol content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise ContrastProtocolError("contrast protocol is not canonical")
    return expected


def build_contrast_protocol(content: Mapping[str, Any]) -> dict[str, Any]:
    """Build a sealed receipt from hash-free exact content.

    ``content`` is intentionally a mapping rather than a collection of
    convenience options: callers must state every bound choice explicitly.
    """

    if not isinstance(content, Mapping):
        raise ContrastProtocolError("contrast protocol content must be a mapping")
    if "content_sha256" in content:
        raise ContrastProtocolError("builder accepts hash-free contrast protocol content")
    normalized = _validate_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def load_contrast_protocol(path: Path) -> dict[str, Any]:
    """Load and validate one JSON receipt from ``path``."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContrastProtocolError(f"could not read contrast protocol {path}: {exc}") from exc
    return validate_contrast_protocol(payload)


# Descriptive aliases keep the API discoverable without creating an authority
# route or a second wire format.
build_contrast_receipt = build_contrast_protocol
validate_contrast_receipt = validate_contrast_protocol
load_contrast_receipt = load_contrast_protocol


__all__ = [
    "ARM_EXECUTION_MODE",
    "CONTRAST_PROTOCOL_SCHEMA",
    "ContrastProtocolError",
    "ENGINE_COUNT",
    "FAILURE_POLICY",
    "MIN_OPPONENT_COUNT",
    "REQUIRED_PLATFORM",
    "SEATS",
    "SEED_COUNT",
    "build_contrast_protocol",
    "build_contrast_receipt",
    "canonical_json_bytes",
    "canonical_sha256",
    "load_contrast_protocol",
    "load_contrast_receipt",
    "validate_contrast_protocol",
    "validate_contrast_receipt",
]
