"""Create-once, outcome-free simulation-design manifests for evaluation v4."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
from numbers import Real
from typing import Any, Mapping


DESIGN_SCHEMA = "whole_policy_simulation_design_v1"
SEED_COUNT = 16
SEED_DERIVATION_ALGORITHM = (
    "sha256_ascii_seed_beacon_sha256_colon_decimal_counter_0_through_15_"
    "first_8_bytes_big_endian_mask_63_bits_v1"
)
RATING_LAYERS = frozenset({"top", "mid", "low"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INPUT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "compiler_code_sha256",
        "runner_code_sha256",
        "dependency_lock_sha256",
        "candidate_archive_sha256",
        "baseline_archive_sha256",
        "seed_beacon_sha256",
        "seed_derivation_algorithm",
        "engine_roster",
        "opponent_roster",
        "state",
    }
)
_MANIFEST_FIELDS = _INPUT_FIELDS | frozenset({"seeds", "content_sha256"})
_ENGINE_FIELDS = frozenset({"engine_id", "binary_sha256"})
_OPPONENT_FIELDS = frozenset(
    {"opponent_id", "content_sha256", "family_id", "rating_layer", "weight"}
)


class DesignError(ValueError):
    """A whole-policy simulation design is malformed or not frozen."""


def canonical_json_bytes(value: object) -> bytes:
    """Return the unique JSON encoding used for manifest content bindings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sha256(value: object) -> str:
    """Return the SHA-256 digest of the canonical JSON encoding."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DesignError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise DesignError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise DesignError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _weight(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise DesignError(f"{label} must be a finite positive number")
    normalized = float(value)
    if normalized <= 0.0:
        raise DesignError(f"{label} must be a finite positive number")
    return normalized


def derive_seeds(seed_beacon_sha256: object) -> list[int]:
    """Derive the fixed 16 non-negative signed-63-bit seeds from the beacon."""
    beacon = _sha256(seed_beacon_sha256, label="seed_beacon_sha256")
    return [
        int.from_bytes(
            hashlib.sha256(f"{beacon}:{counter}".encode("ascii")).digest()[:8],
            "big",
        )
        & ((1 << 63) - 1)
        for counter in range(SEED_COUNT)
    ]


def _validate_engines(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) < 2:
        raise DesignError("engine_roster must contain at least two engine variants")
    engines: list[dict[str, str]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for index, raw in enumerate(value):
        engine = _exact_fields(raw, _ENGINE_FIELDS, label=f"engine_roster[{index}]")
        engine_id = _identifier(engine["engine_id"], label=f"engine_roster[{index}].engine_id")
        binary_sha256 = _sha256(engine["binary_sha256"], label=f"engine_roster[{index}].binary_sha256")
        if engine_id in ids:
            raise DesignError(f"duplicate engine_id {engine_id!r}")
        if binary_sha256 in hashes:
            raise DesignError(f"duplicate engine binary_sha256 {binary_sha256!r}")
        ids.add(engine_id)
        hashes.add(binary_sha256)
        engines.append({"engine_id": engine_id, "binary_sha256": binary_sha256})
    return sorted(engines, key=lambda item: item["engine_id"])


def _validate_opponents(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 12:
        raise DesignError("opponent_roster must contain at least twelve opponent models")
    opponents: list[dict[str, Any]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    family_mass: dict[str, float] = {}
    layer_mass: dict[str, float] = {layer: 0.0 for layer in RATING_LAYERS}
    layer_count: dict[str, int] = {layer: 0 for layer in RATING_LAYERS}
    for index, raw in enumerate(value):
        opponent = _exact_fields(raw, _OPPONENT_FIELDS, label=f"opponent_roster[{index}]")
        opponent_id = _identifier(opponent["opponent_id"], label=f"opponent_roster[{index}].opponent_id")
        content_sha256 = _sha256(opponent["content_sha256"], label=f"opponent_roster[{index}].content_sha256")
        family_id = _identifier(opponent["family_id"], label=f"opponent_roster[{index}].family_id")
        rating_layer = opponent["rating_layer"]
        if rating_layer not in RATING_LAYERS:
            raise DesignError("opponent rating_layer must be exactly one of top, mid, or low")
        weight = _weight(opponent["weight"], label=f"opponent_roster[{index}].weight")
        if opponent_id in ids:
            raise DesignError(f"duplicate opponent_id {opponent_id!r}")
        if content_sha256 in hashes:
            raise DesignError(f"duplicate opponent content_sha256 {content_sha256!r}")
        ids.add(opponent_id)
        hashes.add(content_sha256)
        family_mass[family_id] = family_mass.get(family_id, 0.0) + weight
        layer_mass[rating_layer] += weight
        layer_count[rating_layer] += 1
        opponents.append(
            {
                "opponent_id": opponent_id,
                "content_sha256": content_sha256,
                "family_id": family_id,
                "rating_layer": rating_layer,
                "weight": weight,
            }
        )
    if len(family_mass) < 4:
        raise DesignError("opponent_roster must cover at least four families")
    if set(layer_count) != RATING_LAYERS or any(layer_count[layer] < 3 for layer in RATING_LAYERS):
        raise DesignError("each rating layer top, mid, and low must contain at least three opponents")
    total_weight = math.fsum(opponent["weight"] for opponent in opponents)
    if abs(total_weight - 1.0) > 1e-12:
        raise DesignError("opponent weights must sum to one within 1e-12")
    if any(mass <= 0.0 for mass in family_mass.values()) or any(mass <= 0.0 for mass in layer_mass.values()):
        raise DesignError("every opponent family and rating layer must carry positive weight mass")
    return sorted(opponents, key=lambda item: item["opponent_id"])


def _validate_design_input(value: object) -> dict[str, Any]:
    design = _exact_fields(value, _INPUT_FIELDS, label="simulation design")
    if design["schema"] != DESIGN_SCHEMA:
        raise DesignError(f"simulation design schema must be {DESIGN_SCHEMA!r}")
    if design["seed_derivation_algorithm"] != SEED_DERIVATION_ALGORITHM:
        raise DesignError(f"seed_derivation_algorithm must be {SEED_DERIVATION_ALGORITHM!r}")
    if design["state"] != "FROZEN":
        raise DesignError("state must be FROZEN")
    candidate_archive_sha256 = _sha256(design["candidate_archive_sha256"], label="candidate_archive_sha256")
    baseline_archive_sha256 = _sha256(design["baseline_archive_sha256"], label="baseline_archive_sha256")
    if candidate_archive_sha256 == baseline_archive_sha256:
        raise DesignError("candidate and baseline archive SHA-256 values must differ")
    return {
        "schema": DESIGN_SCHEMA,
        "protocol_sha256": _sha256(design["protocol_sha256"], label="protocol_sha256"),
        "compiler_code_sha256": _sha256(design["compiler_code_sha256"], label="compiler_code_sha256"),
        "runner_code_sha256": _sha256(design["runner_code_sha256"], label="runner_code_sha256"),
        "dependency_lock_sha256": _sha256(design["dependency_lock_sha256"], label="dependency_lock_sha256"),
        "candidate_archive_sha256": candidate_archive_sha256,
        "baseline_archive_sha256": baseline_archive_sha256,
        "seed_beacon_sha256": _sha256(design["seed_beacon_sha256"], label="seed_beacon_sha256"),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "engine_roster": _validate_engines(design["engine_roster"]),
        "opponent_roster": _validate_opponents(design["opponent_roster"]),
        "state": "FROZEN",
    }


def build_design_manifest(design: object) -> dict[str, Any]:
    """Build a canonical frozen design; caller-provided seed values are impossible."""
    normalized = _validate_design_input(design)
    content = {**normalized, "seeds": derive_seeds(normalized["seed_beacon_sha256"])}
    manifest = {**content, "content_sha256": canonical_sha256(content)}
    validate_design_manifest(manifest)
    return manifest


def validate_design_manifest(manifest: object) -> dict[str, Any]:
    """Validate every binding and recompute its content SHA-256."""
    value = _exact_fields(manifest, _MANIFEST_FIELDS, label="simulation design manifest")
    input_value = {field: value[field] for field in _INPUT_FIELDS}
    normalized = _validate_design_input(input_value)
    seeds = value["seeds"]
    expected_seeds = derive_seeds(normalized["seed_beacon_sha256"])
    if not isinstance(seeds, list) or seeds != expected_seeds:
        raise DesignError("seeds must be the exact deterministic derivation from seed_beacon_sha256")
    # A frozen receipt has one byte-level representation, including sorted rosters.
    for field in ("engine_roster", "opponent_roster"):
        if canonical_json_bytes(value[field]) != canonical_json_bytes(normalized[field]):
            raise DesignError(f"{field} must be canonically sorted and normalized")
    content = {**normalized, "seeds": expected_seeds}
    content_sha256 = _sha256(value["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise DesignError("simulation design manifest content_sha256 mismatch")
    return {**content, "content_sha256": content_sha256}


def write_design_manifest_once(path: str | Path, manifest: object) -> Path:
    """Write one validated receipt with exclusive creation and durable fsyncs."""
    target = Path(path)
    if target.exists():
        raise FileExistsError(f"simulation design manifest already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json_bytes(validate_design_manifest(manifest)) + b"\n"
    try:
        with target.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"simulation design manifest already exists: {target}") from None
    directory_fd = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return target


__all__ = [
    "DESIGN_SCHEMA",
    "DesignError",
    "RATING_LAYERS",
    "SEED_COUNT",
    "SEED_DERIVATION_ALGORITHM",
    "build_design_manifest",
    "canonical_json_bytes",
    "canonical_sha256",
    "derive_seeds",
    "validate_design_manifest",
    "write_design_manifest_once",
]
