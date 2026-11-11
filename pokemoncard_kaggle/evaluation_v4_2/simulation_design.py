"""Pure candidate-neutral simulation design and raw-panel feature compiler.

This module intentionally has no filesystem, network, clock, subprocess, or
external-service surface.  A template is reusable for many candidates; only a
raw terminal panel binds candidate identity.  All derived summaries are
recomputed by :func:`compile_candidate_features`.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import math
from numbers import Real
import re
from typing import Any, Iterable, Mapping


TEMPLATE_SCHEMA = "evaluation_v4_2_simulation_template_v1"
PANEL_SCHEMA = "evaluation_v4_2_candidate_panel_v1"
FEATURE_SCHEMA = "evaluation_v4_2_candidate_features_v1"
STATE_FROZEN = "FROZEN"
DEVELOPMENT_AUTHORITY = "DEVELOPMENT_ONLY"
SEED_COUNT = 16
RATING_LAYERS = frozenset({"top", "mid", "low"})
SEATS = ("policy_first", "policy_second")
SEED_DERIVATION_ALGORITHM = (
    "sha256_ascii_seed_beacon_sha256_colon_decimal_counter_0_through_15_"
    "first_8_bytes_big_endian_mask_63_bits_v1"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TEMPLATE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "protocol_sha256",
        "scientific_plan_sha256",
        "runner_code_sha256",
        "dependency_lock_sha256",
        "runtime_binding_sha256",
        "engine_roster",
        "opponent_roster",
        "seed_beacon_sha256",
        "seed_derivation_algorithm",
        "state",
    }
)
_TEMPLATE_FIELDS = _TEMPLATE_CONTENT_FIELDS | frozenset({"seeds", "content_sha256"})
_ENGINE_FIELDS = frozenset({"engine_id", "binary_sha256", "runtime_tree_sha256"})
_OPPONENT_FIELDS = frozenset(
    {
        "opponent_id",
        "archive_sha256",
        "policy_content_sha256",
        "deck_sha256",
        "family_id",
        "rating_layer",
        "weight",
        "ood_mass",
    }
)
_PANEL_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "template_content_sha256",
        "candidate_archive_sha256",
        "baseline_archive_sha256",
        "ancestry_id",
        "rows",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_PANEL_FIELDS = _PANEL_CONTENT_FIELDS | frozenset({"content_sha256"})
_ROW_FIELDS = frozenset(
    {
        "engine_id",
        "opponent_id",
        "seed",
        "seat",
        "candidate_outcome",
        "baseline_outcome",
        "candidate_runtime_seconds",
        "baseline_runtime_seconds",
        "candidate_error",
        "baseline_error",
    }
)
_FEATURE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "template_content_sha256",
        "panel_content_sha256",
        "candidate_archive_sha256",
        "baseline_archive_sha256",
        "ancestry_id",
        "simulator_delta",
        "engine_means",
        "family_means",
        "layer_means",
        "minimum_engine_mean",
        "minimum_family_mean",
        "minimum_layer_mean",
        "ood_mass",
        "positive_cell_fraction",
        "worst_runtime_seconds",
        "authority",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_FEATURE_FIELDS = _FEATURE_CONTENT_FIELDS | frozenset({"content_sha256"})


class SimulationDesignError(ValueError):
    """A v4.2 template, raw panel, or feature receipt is invalid."""


# A shorter name is useful to callers while retaining the descriptive class.
DesignError = SimulationDesignError


def canonical_json_bytes(value: object) -> bytes:
    """Return the deterministic JSON bytes used for all content bindings."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SimulationDesignError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    """Hash a value after canonical JSON serialization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise SimulationDesignError(
            f"{label} fields must exactly be {sorted(fields)}; got {actual}"
        )
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise SimulationDesignError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise SimulationDesignError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _finite(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise SimulationDesignError(f"{label} must be finite")
    return float(value)


def _positive_weight(value: object, *, label: str) -> float:
    result = _finite(value, label=label)
    if result <= 0.0:
        raise SimulationDesignError(f"{label} must be positive")
    return result


def _outcome(value: object, *, label: str) -> float:
    result = _finite(value, label=label)
    if result not in (0.0, 0.5, 1.0):
        raise SimulationDesignError(f"{label} must be exactly 0, 0.5, or 1")
    return result


def _seed(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 2**63:
        raise SimulationDesignError(f"{label} must be a non-negative signed-63-bit integer")
    return value


def derive_seeds(seed_beacon_sha256: object) -> list[int]:
    """Derive exactly sixteen unique seeds from the frozen beacon digest."""

    beacon = _sha256(seed_beacon_sha256, label="seed_beacon_sha256")
    seeds = [
        int.from_bytes(
            hashlib.sha256(f"{beacon}:{counter}".encode("ascii")).digest()[:8],
            "big",
        )
        & ((1 << 63) - 1)
        for counter in range(SEED_COUNT)
    ]
    if len(set(seeds)) != SEED_COUNT:  # Defensive: the derivation is fixed, not probabilistic input.
        raise SimulationDesignError("beacon derivation did not produce unique seeds")
    return seeds


def _normalize_engines(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) < 2:
        raise SimulationDesignError("engine_roster must contain at least two engines")
    result: list[dict[str, str]] = []
    ids: set[str] = set()
    hashes: set[str] = set()
    for index, raw in enumerate(value):
        engine = _exact_fields(raw, _ENGINE_FIELDS, label=f"engine_roster[{index}]")
        engine_id = _identifier(engine["engine_id"], label=f"engine_roster[{index}].engine_id")
        binary_sha256 = _sha256(
            engine["binary_sha256"], label=f"engine_roster[{index}].binary_sha256"
        )
        runtime_tree_sha256 = _sha256(
            engine["runtime_tree_sha256"],
            label=f"engine_roster[{index}].runtime_tree_sha256",
        )
        if engine_id in ids:
            raise SimulationDesignError(f"duplicate engine_id {engine_id!r}")
        if binary_sha256 in hashes:
            raise SimulationDesignError(f"duplicate engine binary_sha256 {binary_sha256!r}")
        ids.add(engine_id)
        hashes.add(binary_sha256)
        result.append(
            {
                "engine_id": engine_id,
                "binary_sha256": binary_sha256,
                "runtime_tree_sha256": runtime_tree_sha256,
            }
        )
    return sorted(result, key=lambda item: item["engine_id"])


def _normalize_opponents(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < 12:
        raise SimulationDesignError("opponent_roster must contain at least twelve opponents")
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    archive_hashes: set[str] = set()
    families: set[str] = set()
    layers: set[str] = set()
    for index, raw in enumerate(value):
        opponent = _exact_fields(raw, _OPPONENT_FIELDS, label=f"opponent_roster[{index}]")
        opponent_id = _identifier(opponent["opponent_id"], label=f"opponent_roster[{index}].opponent_id")
        archive_sha256 = _sha256(
            opponent["archive_sha256"], label=f"opponent_roster[{index}].archive_sha256"
        )
        policy_content_sha256 = _sha256(
            opponent["policy_content_sha256"],
            label=f"opponent_roster[{index}].policy_content_sha256",
        )
        deck_sha256 = _sha256(
            opponent["deck_sha256"], label=f"opponent_roster[{index}].deck_sha256"
        )
        family_id = _identifier(opponent["family_id"], label=f"opponent_roster[{index}].family_id")
        rating_layer = opponent["rating_layer"]
        if rating_layer not in RATING_LAYERS:
            raise SimulationDesignError("opponent rating_layer must be top, mid, or low")
        weight = _positive_weight(opponent["weight"], label=f"opponent_roster[{index}].weight")
        ood_mass = _finite(opponent["ood_mass"], label=f"opponent_roster[{index}].ood_mass")
        if not 0.0 <= ood_mass <= 1.0:
            raise SimulationDesignError("opponent ood_mass must be in [0, 1]")
        if opponent_id in ids:
            raise SimulationDesignError(f"duplicate opponent_id {opponent_id!r}")
        if archive_sha256 in archive_hashes:
            raise SimulationDesignError(f"duplicate opponent archive_sha256 {archive_sha256!r}")
        ids.add(opponent_id)
        archive_hashes.add(archive_sha256)
        families.add(family_id)
        layers.add(rating_layer)
        result.append(
            {
                "opponent_id": opponent_id,
                "archive_sha256": archive_sha256,
                "policy_content_sha256": policy_content_sha256,
                "deck_sha256": deck_sha256,
                "family_id": family_id,
                "rating_layer": rating_layer,
                "weight": weight,
                "ood_mass": ood_mass,
            }
        )
    if len(archive_hashes) < 12:
        raise SimulationDesignError("opponent archive hashes must be distinct")
    if len(families) < 5:
        raise SimulationDesignError("opponent_roster must cover at least five mechanism families")
    if layers != RATING_LAYERS:
        raise SimulationDesignError("opponent_roster must span top, mid, and low rating layers")
    if abs(math.fsum(item["weight"] for item in result) - 1.0) > 1e-12:
        raise SimulationDesignError("opponent weights must be positive and sum to one")
    return sorted(result, key=lambda item: item["opponent_id"])


def _normalize_template_content(value: object) -> dict[str, Any]:
    raw = _exact_fields(value, _TEMPLATE_CONTENT_FIELDS, label="simulation template")
    if raw["schema"] != TEMPLATE_SCHEMA:
        raise SimulationDesignError(f"template schema must be {TEMPLATE_SCHEMA!r}")
    if raw["state"] != STATE_FROZEN:
        raise SimulationDesignError("template state must be FROZEN")
    if raw["seed_derivation_algorithm"] != SEED_DERIVATION_ALGORITHM:
        raise SimulationDesignError("template seed derivation algorithm is not supported")
    return {
        "schema": TEMPLATE_SCHEMA,
        "protocol_sha256": _sha256(raw["protocol_sha256"], label="protocol_sha256"),
        "scientific_plan_sha256": _sha256(
            raw["scientific_plan_sha256"], label="scientific_plan_sha256"
        ),
        "runner_code_sha256": _sha256(raw["runner_code_sha256"], label="runner_code_sha256"),
        "dependency_lock_sha256": _sha256(
            raw["dependency_lock_sha256"], label="dependency_lock_sha256"
        ),
        "runtime_binding_sha256": _sha256(
            raw["runtime_binding_sha256"], label="runtime_binding_sha256"
        ),
        "engine_roster": _normalize_engines(raw["engine_roster"]),
        "opponent_roster": _normalize_opponents(raw["opponent_roster"]),
        "seed_beacon_sha256": _sha256(raw["seed_beacon_sha256"], label="seed_beacon_sha256"),
        "seed_derivation_algorithm": SEED_DERIVATION_ALGORITHM,
        "state": STATE_FROZEN,
    }


def build_simulation_template(content: Mapping[str, Any]) -> dict[str, Any]:
    """Build a candidate-neutral, hash-sealed frozen template."""

    if not isinstance(content, Mapping) or "content_sha256" in content or "seeds" in content:
        raise SimulationDesignError("template builder accepts hash-free content without seeds")
    normalized = _normalize_template_content(content)
    sealed_content = {**normalized, "seeds": derive_seeds(normalized["seed_beacon_sha256"])}
    result = {**sealed_content, "content_sha256": canonical_sha256(sealed_content)}
    return validate_simulation_template(result)


def validate_simulation_template(template: object) -> dict[str, Any]:
    """Validate a template, recomputing its roster, seed, and content hashes."""

    raw = _exact_fields(template, _TEMPLATE_FIELDS, label="simulation template")
    normalized = _normalize_template_content(
        {field: raw[field] for field in _TEMPLATE_CONTENT_FIELDS}
    )
    expected_seeds = derive_seeds(normalized["seed_beacon_sha256"])
    if raw["seeds"] != expected_seeds:
        raise SimulationDesignError("template seeds must be the exact beacon derivation")
    if canonical_json_bytes(raw["engine_roster"]) != canonical_json_bytes(normalized["engine_roster"]):
        raise SimulationDesignError("engine_roster must be canonically sorted and normalized")
    if canonical_json_bytes(raw["opponent_roster"]) != canonical_json_bytes(normalized["opponent_roster"]):
        raise SimulationDesignError("opponent_roster must be canonically sorted and normalized")
    content = {**normalized, "seeds": expected_seeds}
    content_sha256 = _sha256(raw["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise SimulationDesignError("simulation template content_sha256 mismatch")
    return {**content, "content_sha256": content_sha256}


def _normalize_row(raw: object, *, index: int, template: Mapping[str, Any]) -> dict[str, Any]:
    row = _exact_fields(raw, _ROW_FIELDS, label=f"rows[{index}]")
    engine_id = _identifier(row["engine_id"], label=f"rows[{index}].engine_id")
    opponent_id = _identifier(row["opponent_id"], label=f"rows[{index}].opponent_id")
    engine_ids = {item["engine_id"] for item in template["engine_roster"]}
    opponent_ids = {item["opponent_id"] for item in template["opponent_roster"]}
    if engine_id not in engine_ids or opponent_id not in opponent_ids:
        raise SimulationDesignError(f"rows[{index}] references an undeclared engine or opponent")
    row_seed = _seed(row["seed"], label=f"rows[{index}].seed")
    if row_seed not in template["seeds"]:
        raise SimulationDesignError(f"rows[{index}] references an undeclared seed")
    seat = row["seat"]
    if seat not in SEATS:
        raise SimulationDesignError(f"rows[{index}].seat must be policy_first or policy_second")
    if row["candidate_error"] is not None or row["baseline_error"] is not None:
        raise SimulationDesignError(f"rows[{index}] contains an execution error")
    candidate_runtime = _finite(
        row["candidate_runtime_seconds"], label=f"rows[{index}].candidate_runtime_seconds"
    )
    baseline_runtime = _finite(
        row["baseline_runtime_seconds"], label=f"rows[{index}].baseline_runtime_seconds"
    )
    if candidate_runtime < 0.0 or baseline_runtime < 0.0:
        raise SimulationDesignError(f"rows[{index}] runtimes must be non-negative")
    return {
        "engine_id": engine_id,
        "opponent_id": opponent_id,
        "seed": row_seed,
        "seat": seat,
        "candidate_outcome": _outcome(row["candidate_outcome"], label=f"rows[{index}].candidate_outcome"),
        "baseline_outcome": _outcome(row["baseline_outcome"], label=f"rows[{index}].baseline_outcome"),
        "candidate_runtime_seconds": candidate_runtime,
        "baseline_runtime_seconds": baseline_runtime,
        "candidate_error": None,
        "baseline_error": None,
    }


def _validate_grid(rows: list[dict[str, Any]], template: Mapping[str, Any]) -> list[dict[str, Any]]:
    keys: set[tuple[str, str, int, str]] = set()
    for row in rows:
        key = (row["engine_id"], row["opponent_id"], row["seed"], row["seat"])
        if key in keys:
            raise SimulationDesignError(f"duplicate terminal cell {key}")
        keys.add(key)
    expected = {
        (engine["engine_id"], opponent["opponent_id"], seed, seat)
        for engine in template["engine_roster"]
        for opponent in template["opponent_roster"]
        for seed in template["seeds"]
        for seat in SEATS
    }
    missing = expected - keys
    extra = keys - expected
    if missing or extra:
        raise SimulationDesignError(
            f"rows must be the exact Cartesian grid: missing={len(missing)} extra={len(extra)}"
        )
    return sorted(rows, key=lambda row: (row["engine_id"], row["opponent_id"], row["seed"], row["seat"]))


def build_candidate_panel(
    template: Mapping[str, Any],
    *,
    candidate_archive_sha256: str,
    baseline_archive_sha256: str,
    ancestry_id: str,
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build a candidate-bound panel from raw terminal rows only."""

    checked_template = validate_simulation_template(template)
    candidate = _sha256(candidate_archive_sha256, label="candidate_archive_sha256")
    baseline = _sha256(baseline_archive_sha256, label="baseline_archive_sha256")
    if candidate == baseline:
        raise SimulationDesignError("candidate and baseline archive SHA-256 values must differ")
    ancestry = _identifier(ancestry_id, label="ancestry_id")
    if not isinstance(rows, list):
        rows = list(rows)
    normalized_rows = _validate_grid(
        [_normalize_row(row, index=index, template=checked_template) for index, row in enumerate(rows)],
        checked_template,
    )
    content = {
        "schema": PANEL_SCHEMA,
        "template_content_sha256": checked_template["content_sha256"],
        "candidate_archive_sha256": candidate,
        "baseline_archive_sha256": baseline,
        "ancestry_id": ancestry,
        "rows": normalized_rows,
        "authority": DEVELOPMENT_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }
    return validate_candidate_panel({**content, "content_sha256": canonical_sha256(content)}, checked_template)


def validate_candidate_panel(panel: object, template: object) -> dict[str, Any]:
    """Validate panel identity, hash integrity, error-free rows, and full grid."""

    checked_template = validate_simulation_template(template)
    raw = _exact_fields(panel, _PANEL_FIELDS, label="candidate panel")
    if raw["schema"] != PANEL_SCHEMA:
        raise SimulationDesignError(f"panel schema must be {PANEL_SCHEMA!r}")
    template_hash = _sha256(raw["template_content_sha256"], label="template_content_sha256")
    if template_hash != checked_template["content_sha256"]:
        raise SimulationDesignError("panel template_content_sha256 does not match the template")
    candidate = _sha256(raw["candidate_archive_sha256"], label="candidate_archive_sha256")
    baseline = _sha256(raw["baseline_archive_sha256"], label="baseline_archive_sha256")
    if candidate == baseline:
        raise SimulationDesignError("candidate and baseline archive SHA-256 values must differ")
    ancestry = _identifier(raw["ancestry_id"], label="ancestry_id")
    if raw["authority"] != DEVELOPMENT_AUTHORITY:
        raise SimulationDesignError("candidate panel authority must remain DEVELOPMENT_ONLY")
    if raw["anchor_allowed"] is not False or raw["production_submission_authorized"] is not False:
        raise SimulationDesignError("candidate panel cannot grant external authority")
    if not isinstance(raw["rows"], list):
        raise SimulationDesignError("panel rows must be a list")
    normalized_rows = _validate_grid(
        [_normalize_row(row, index=index, template=checked_template) for index, row in enumerate(raw["rows"])],
        checked_template,
    )
    if canonical_json_bytes(raw["rows"]) != canonical_json_bytes(normalized_rows):
        raise SimulationDesignError("panel rows must be canonically sorted and normalized")
    content = {
        "schema": PANEL_SCHEMA,
        "template_content_sha256": template_hash,
        "candidate_archive_sha256": candidate,
        "baseline_archive_sha256": baseline,
        "ancestry_id": ancestry,
        "rows": normalized_rows,
        "authority": DEVELOPMENT_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }
    content_sha256 = _sha256(raw["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(content):
        raise SimulationDesignError("candidate panel content_sha256 mismatch")
    return {**content, "content_sha256": content_sha256}


def _group_mean(rows: Iterable[tuple[float, float]]) -> float:
    numerator = math.fsum(value * weight for value, weight in rows)
    denominator = math.fsum(weight for _, weight in rows)
    if denominator <= 0.0:
        raise SimulationDesignError("cannot compute an empty feature group")
    return numerator / denominator


def _compile_feature_content(panel: Mapping[str, Any], template: Mapping[str, Any]) -> dict[str, Any]:
    opponents = {item["opponent_id"]: item for item in template["opponent_roster"]}
    engines = [item["engine_id"] for item in template["engine_roster"]]
    rows = panel["rows"]
    cell_weight = {row["opponent_id"]: opponents[row["opponent_id"]]["weight"] for row in rows}
    divisor = len(engines) * SEED_COUNT * len(SEATS)
    weighted_deltas = [
        (
            row["candidate_outcome"] - row["baseline_outcome"],
            cell_weight[row["opponent_id"]] / divisor,
        )
        for row in rows
    ]
    engine_groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    family_groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    layer_groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for row, weighted in zip(rows, weighted_deltas):
        opponent = opponents[row["opponent_id"]]
        engine_groups[row["engine_id"]].append(weighted)
        family_groups[opponent["family_id"]].append(weighted)
        layer_groups[opponent["rating_layer"]].append(weighted)
    engine_means = {key: _group_mean(engine_groups[key]) for key in sorted(engine_groups)}
    family_means = {key: _group_mean(family_groups[key]) for key in sorted(family_groups)}
    layer_means = {key: _group_mean(layer_groups[key]) for key in sorted(layer_groups)}
    positive_cell_fraction = sum(
        row["candidate_outcome"] > row["baseline_outcome"] for row in rows
    ) / len(rows)
    return {
        "schema": FEATURE_SCHEMA,
        "template_content_sha256": template["content_sha256"],
        "panel_content_sha256": panel["content_sha256"],
        "candidate_archive_sha256": panel["candidate_archive_sha256"],
        "baseline_archive_sha256": panel["baseline_archive_sha256"],
        "ancestry_id": panel["ancestry_id"],
        "simulator_delta": math.fsum(value * weight for value, weight in weighted_deltas),
        "engine_means": engine_means,
        "family_means": family_means,
        "layer_means": layer_means,
        "minimum_engine_mean": min(engine_means.values()),
        "minimum_family_mean": min(family_means.values()),
        "minimum_layer_mean": min(layer_means.values()),
        "ood_mass": math.fsum(
            item["weight"] * item["ood_mass"] for item in template["opponent_roster"]
        ),
        "positive_cell_fraction": positive_cell_fraction,
        "worst_runtime_seconds": max(
            max(row["candidate_runtime_seconds"] for row in rows),
            max(row["baseline_runtime_seconds"] for row in rows),
        ),
        "authority": DEVELOPMENT_AUTHORITY,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def compile_candidate_features(panel: Mapping[str, Any], template: Mapping[str, Any]) -> dict[str, Any]:
    """Compile hash-sealed features using only the validated raw panel."""

    checked_panel = validate_candidate_panel(panel, template)
    checked_template = validate_simulation_template(template)
    content = _compile_feature_content(checked_panel, checked_template)
    return validate_candidate_features(
        {**content, "content_sha256": canonical_sha256(content)}, checked_panel, checked_template
    )


def _validate_feature_values(raw: Mapping[str, Any]) -> dict[str, Any]:
    for name in ("simulator_delta", "minimum_engine_mean", "minimum_family_mean", "minimum_layer_mean", "ood_mass", "positive_cell_fraction", "worst_runtime_seconds"):
        _finite(raw[name], label=name)
    if not 0.0 <= float(raw["ood_mass"]) <= 1.0:
        raise SimulationDesignError("ood_mass must be in [0, 1]")
    if not 0.0 <= float(raw["positive_cell_fraction"]) <= 1.0:
        raise SimulationDesignError("positive_cell_fraction must be in [0, 1]")
    for name in ("engine_means", "family_means", "layer_means"):
        values = raw[name]
        if not isinstance(values, Mapping) or not values:
            raise SimulationDesignError(f"{name} must be a non-empty mapping")
        for key, value in values.items():
            _identifier(key, label=f"{name} key")
            _finite(value, label=f"{name}[{key!r}]")
        if dict(values) != dict(sorted(values.items())):
            raise SimulationDesignError(f"{name} must be sorted by key")
    return dict(raw)


def validate_candidate_features(
    features: object, panel: object, template: object
) -> dict[str, Any]:
    """Recompute and verify every feature and every hash binding."""

    checked_template = validate_simulation_template(template)
    checked_panel = validate_candidate_panel(panel, checked_template)
    raw = _exact_fields(features, _FEATURE_FIELDS, label="candidate features")
    if raw["schema"] != FEATURE_SCHEMA:
        raise SimulationDesignError(f"feature schema must be {FEATURE_SCHEMA!r}")
    if _sha256(raw["template_content_sha256"], label="template_content_sha256") != checked_template["content_sha256"]:
        raise SimulationDesignError("feature template binding mismatch")
    if _sha256(raw["panel_content_sha256"], label="panel_content_sha256") != checked_panel["content_sha256"]:
        raise SimulationDesignError("feature panel binding mismatch")
    if _sha256(raw["candidate_archive_sha256"], label="candidate_archive_sha256") != checked_panel["candidate_archive_sha256"]:
        raise SimulationDesignError("feature candidate archive binding mismatch")
    if _sha256(raw["baseline_archive_sha256"], label="baseline_archive_sha256") != checked_panel["baseline_archive_sha256"]:
        raise SimulationDesignError("feature baseline archive binding mismatch")
    if _identifier(raw["ancestry_id"], label="ancestry_id") != checked_panel["ancestry_id"]:
        raise SimulationDesignError("feature ancestry binding mismatch")
    expected = _compile_feature_content(checked_panel, checked_template)
    _validate_feature_values(raw)
    if canonical_json_bytes({field: raw[field] for field in _FEATURE_CONTENT_FIELDS}) != canonical_json_bytes(expected):
        raise SimulationDesignError("candidate features were not derived from the raw panel")
    content_sha256 = _sha256(raw["content_sha256"], label="content_sha256")
    if content_sha256 != canonical_sha256(expected):
        raise SimulationDesignError("candidate features content_sha256 mismatch")
    return {**expected, "content_sha256": content_sha256}


# Compatibility aliases use the same strict implementations; they do not add
# alternate schemas or a second code path.
build_template = build_simulation_template
validate_template = validate_simulation_template
build_panel = build_candidate_panel
validate_panel = validate_candidate_panel
compile_features = compile_candidate_features
validate_features = validate_candidate_features


__all__ = [
    "DesignError",
    "DEVELOPMENT_AUTHORITY",
    "FEATURE_SCHEMA",
    "PANEL_SCHEMA",
    "RATING_LAYERS",
    "SEATS",
    "SEED_COUNT",
    "SEED_DERIVATION_ALGORITHM",
    "STATE_FROZEN",
    "SimulationDesignError",
    "TEMPLATE_SCHEMA",
    "build_candidate_panel",
    "build_panel",
    "build_simulation_template",
    "build_template",
    "canonical_json_bytes",
    "canonical_sha256",
    "compile_candidate_features",
    "compile_features",
    "derive_seeds",
    "validate_candidate_features",
    "validate_candidate_panel",
    "validate_features",
    "validate_panel",
    "validate_simulation_template",
    "validate_template",
]
