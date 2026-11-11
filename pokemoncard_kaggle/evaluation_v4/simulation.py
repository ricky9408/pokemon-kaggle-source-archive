"""Strict whole-policy terminal simulation feature compiler for selector v4."""

from __future__ import annotations

from collections import defaultdict
import math
from numbers import Real
import random
from typing import Any, Iterable, Mapping


INPUT_SCHEMA = "whole_policy_terminal_runs_v1"
OUTPUT_SCHEMA = "whole_policy_simulation_feature_v1"
_TOP_FIELDS = {
    "schema",
    "candidate",
    "baseline",
    "engine_variants",
    "opponent_models",
    "seeds",
    "rows",
}
_POLICY_FIELDS = {"label", "archive_sha256"}
_OPPONENT_FIELDS = {"content_sha256", "family_id", "rating_layer", "ood_mass"}
_ROW_FIELDS = {
    "engine_variant",
    "opponent_model",
    "seed",
    "candidate_left",
    "candidate_outcome",
    "baseline_outcome",
    "candidate_error",
    "baseline_error",
    "candidate_max_action_seconds",
    "baseline_max_action_seconds",
}


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _sha(value: object, *, label: str) -> str:
    text = _identifier(value, label=label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return text


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(float(value)):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _outcome(value: object, *, label: str) -> float:
    result = _number(value, label=label)
    if result not in (0.0, 0.5, 1.0):
        raise ValueError(f"{label} must be 0, 0.5, or 1")
    return result


def _mean(values: Iterable[float]) -> float:
    materialized = list(values)
    if not materialized:
        return float("nan")
    return math.fsum(materialized) / len(materialized)


def _quantile(values: Iterable[float], probability: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _policy(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _POLICY_FIELDS:
        raise ValueError(f"{label} fields must exactly be {sorted(_POLICY_FIELDS)}")
    return {
        "label": _identifier(value["label"], label=f"{label}.label"),
        "archive_sha256": _sha(value["archive_sha256"], label=f"{label}.archive_sha256"),
    }


def compile_simulation_feature(
    payload: Mapping[str, Any],
    *,
    bootstrap_samples: int = 5000,
    seed: int = 20260711,
) -> dict[str, Any]:
    """Compile one candidate-vs-baseline feature from a complete matched panel."""

    if set(payload) != _TOP_FIELDS or payload.get("schema") != INPUT_SCHEMA:
        raise ValueError(f"terminal panel fields/schema must exactly match {sorted(_TOP_FIELDS)}")
    if isinstance(bootstrap_samples, bool) or not isinstance(bootstrap_samples, int) or bootstrap_samples <= 0:
        raise ValueError("bootstrap_samples must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    candidate = _policy(payload["candidate"], label="candidate")
    baseline = _policy(payload["baseline"], label="baseline")
    if candidate["archive_sha256"] == baseline["archive_sha256"]:
        raise ValueError("candidate and baseline archives must differ")

    raw_variants = payload["engine_variants"]
    if not isinstance(raw_variants, Mapping) or not raw_variants:
        raise ValueError("engine_variants must be a non-empty mapping")
    variants = {
        _identifier(name, label="engine variant"): _sha(digest, label=f"engine_variants[{name!r}]")
        for name, digest in raw_variants.items()
    }
    raw_opponents = payload["opponent_models"]
    if not isinstance(raw_opponents, Mapping) or not raw_opponents:
        raise ValueError("opponent_models must be a non-empty mapping")
    opponents: dict[str, dict[str, Any]] = {}
    for name, raw in raw_opponents.items():
        opponent = _identifier(name, label="opponent model")
        if not isinstance(raw, Mapping) or set(raw) != _OPPONENT_FIELDS:
            raise ValueError(f"opponent model fields must exactly be {sorted(_OPPONENT_FIELDS)}")
        ood_mass = _number(raw["ood_mass"], label=f"opponent_models[{opponent!r}].ood_mass")
        if not 0.0 <= ood_mass <= 1.0:
            raise ValueError("opponent model ood_mass must be in [0, 1]")
        opponents[opponent] = {
            "content_sha256": _sha(raw["content_sha256"], label=f"opponent_models[{opponent!r}].content_sha256"),
            "family_id": _identifier(raw["family_id"], label="opponent family_id"),
            "rating_layer": _identifier(raw["rating_layer"], label="opponent rating_layer"),
            "ood_mass": ood_mass,
        }
    raw_seeds = payload["seeds"]
    if not isinstance(raw_seeds, list) or not raw_seeds:
        raise ValueError("seeds must be a non-empty list")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in raw_seeds):
        raise ValueError("seeds must contain integers")
    seeds = list(raw_seeds)
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")

    raw_rows = payload["rows"]
    if not isinstance(raw_rows, list):
        raise ValueError("rows must be a list")
    rows: list[dict[str, Any]] = []
    keys: set[tuple[str, str, int, bool]] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping) or set(raw) != _ROW_FIELDS:
            raise ValueError(f"row {index} fields must exactly be {sorted(_ROW_FIELDS)}")
        variant = _identifier(raw["engine_variant"], label=f"row {index} engine_variant")
        opponent = _identifier(raw["opponent_model"], label=f"row {index} opponent_model")
        row_seed = raw["seed"]
        left = raw["candidate_left"]
        if variant not in variants or opponent not in opponents or row_seed not in seeds:
            raise ValueError(f"row {index} references an undeclared cell identity")
        if not isinstance(left, bool):
            raise ValueError(f"row {index} candidate_left must be boolean")
        key = (variant, opponent, int(row_seed), left)
        if key in keys:
            raise ValueError(f"duplicate matched cell {key}")
        keys.add(key)
        candidate_error = raw["candidate_error"]
        baseline_error = raw["baseline_error"]
        if candidate_error is not None or baseline_error is not None:
            raise ValueError(f"matched cell {key} contains an execution error")
        candidate_runtime = _number(raw["candidate_max_action_seconds"], label="candidate runtime")
        baseline_runtime = _number(raw["baseline_max_action_seconds"], label="baseline runtime")
        if candidate_runtime < 0.0 or baseline_runtime < 0.0:
            raise ValueError("runtime values must be nonnegative")
        candidate_outcome = _outcome(raw["candidate_outcome"], label="candidate_outcome")
        baseline_outcome = _outcome(raw["baseline_outcome"], label="baseline_outcome")
        rows.append(
            {
                "engine_variant": variant,
                "opponent_model": opponent,
                "seed": int(row_seed),
                "candidate_left": left,
                "candidate_outcome": candidate_outcome,
                "baseline_outcome": baseline_outcome,
                "paired_delta": candidate_outcome - baseline_outcome,
                "candidate_max_action_seconds": candidate_runtime,
                "baseline_max_action_seconds": baseline_runtime,
            }
        )
    expected = {
        (variant, opponent, value, left)
        for variant in variants
        for opponent in opponents
        for value in seeds
        for left in (False, True)
    }
    missing = expected - keys
    extra = keys - expected
    if missing or extra:
        raise ValueError(f"terminal panel is not the exact Cartesian matched grid: missing={len(missing)} extra={len(extra)}")
    rows.sort(key=lambda row: (row["engine_variant"], row["opponent_model"], row["seed"], row["candidate_left"]))

    by_engine: dict[str, list[float]] = defaultdict(list)
    by_opponent: dict[str, list[float]] = defaultdict(list)
    by_family: dict[str, list[float]] = defaultdict(list)
    by_layer: dict[str, list[float]] = defaultdict(list)
    runtimes: list[float] = []
    for row in rows:
        delta = row["paired_delta"]
        opponent = opponents[row["opponent_model"]]
        by_engine[row["engine_variant"]].append(delta)
        by_opponent[row["opponent_model"]].append(delta)
        by_family[opponent["family_id"]].append(delta)
        by_layer[opponent["rating_layer"]].append(delta)
        runtimes.append(row["candidate_max_action_seconds"])
    engine_means = {key: _mean(values) for key, values in sorted(by_engine.items())}
    opponent_means = {key: _mean(values) for key, values in sorted(by_opponent.items())}
    family_means = {key: _mean(values) for key, values in sorted(by_family.items())}
    layer_means = {key: _mean(values) for key, values in sorted(by_layer.items())}
    opponent_ids = sorted(by_opponent)
    rng = random.Random(seed)
    bootstrap = []
    for _ in range(bootstrap_samples):
        draw = [opponent_ids[rng.randrange(len(opponent_ids))] for _ in opponent_ids]
        bootstrap.append(_mean(opponent_means[opponent] for opponent in draw))
    deltas = [row["paired_delta"] for row in rows]
    return {
        "schema": OUTPUT_SCHEMA,
        "candidate": candidate,
        "baseline": baseline,
        "support": {
            "matched_cells": len(rows),
            "engine_variants": len(variants),
            "opponent_models": len(opponents),
            "opponent_families": len(by_family),
            "rating_layers": len(by_layer),
            "seeds": len(seeds),
            "both_seats": True,
        },
        "simulator_delta": _mean(deltas),
        "empirical_cell_q10": _quantile(deltas, 0.10),
        "opponent_cluster_bootstrap_probability_positive": sum(value > 0.0 for value in bootstrap) / len(bootstrap),
        "opponent_cluster_bootstrap_q10": _quantile(bootstrap, 0.10),
        "positive_cell_fraction": sum(value > 0.0 for value in deltas) / len(deltas),
        "engine_variant_means": engine_means,
        "opponent_model_means": opponent_means,
        "opponent_family_means": family_means,
        "rating_layer_means": layer_means,
        "minimum_engine_variant_mean": min(engine_means.values()),
        "minimum_opponent_family_mean": min(family_means.values()),
        "minimum_rating_layer_mean": min(layer_means.values()),
        "candidate_visited_ood_mass": max(value["ood_mass"] for value in opponents.values()),
        "candidate_runtime_p99_seconds": _quantile(runtimes, 0.99),
        "candidate_runtime_max_seconds": max(runtimes),
        "bootstrap": {"unit": "opponent_model", "samples": bootstrap_samples, "seed": seed},
        "notes": [
            "terminal outcomes are diagnostics until prospective public transfer validates this feature",
            "no weighted composite or submission authorization is emitted",
        ],
    }


__all__ = ["compile_simulation_feature", "INPUT_SCHEMA", "OUTPUT_SCHEMA"]
