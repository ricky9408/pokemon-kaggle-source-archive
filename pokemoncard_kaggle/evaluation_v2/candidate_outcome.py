"""Candidate qualification from matched-seed terminal outcomes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import random
import statistics
from typing import Any

from .seeded_arena import anchor_outcome


@dataclass(frozen=True)
class CandidateOutcomeLimits:
    min_matched_cells: int = 80
    min_support_fraction: float = 0.85
    min_mean_delta: float = 0.04
    min_bootstrap_q10: float = 0.01
    min_probability_positive: float = 0.90
    min_control_cvar20: float = -0.02
    min_control_delta: float = -0.10


def _quantile(values: list[float], probability: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    index = (len(ordered) - 1) * probability
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def matched_candidate_deltas(
    panel: dict[str, Any],
    *,
    candidate_label: str,
) -> tuple[list[dict[str, Any]], int]:
    baseline_label = str(panel["baseline_label"])
    cells: dict[tuple[str, str, int, int], float] = {}
    expected: set[tuple[str, int, int]] = set()
    for row in panel.get("rows") or []:
        anchor = str(row["anchor"])
        control = str(row["control"])
        seed = int(row["seed"])
        anchor_left = int(row["anchor_left"])
        if anchor in {candidate_label, baseline_label}:
            expected.add((control, seed, anchor_left))
        outcome = anchor_outcome(row, anchor)
        if outcome is not None and not row.get("error"):
            cells[(anchor, control, seed, anchor_left)] = outcome
    deltas: list[dict[str, Any]] = []
    for control, seed, anchor_left in sorted(expected):
        candidate = cells.get((candidate_label, control, seed, anchor_left))
        baseline = cells.get((baseline_label, control, seed, anchor_left))
        if candidate is None or baseline is None:
            continue
        deltas.append(
            {
                "control": control,
                "seed": seed,
                "anchor_left": anchor_left,
                "candidate_outcome": candidate,
                "baseline_outcome": baseline,
                "delta": candidate - baseline,
            }
        )
    return deltas, len(expected)


def evaluate_candidate_outcomes(
    panel: dict[str, Any],
    *,
    candidate_label: str,
    limits: CandidateOutcomeLimits = CandidateOutcomeLimits(),
    bootstrap_samples: int = 5000,
    seed: int = 20260710,
) -> dict[str, Any]:
    labels = {str(row["anchor"]) for row in panel.get("rows") or []}
    baseline_label = str(panel["baseline_label"])
    deltas, expected_cells = matched_candidate_deltas(panel, candidate_label=candidate_label)
    matched_cells = len(deltas)
    support = matched_cells / expected_cells if expected_cells else 0.0
    values = [float(row["delta"]) for row in deltas]
    clusters: dict[tuple[str, int], list[float]] = {}
    for row in deltas:
        clusters.setdefault((str(row["control"]), int(row["seed"])), []).append(float(row["delta"]))
    cluster_values = [statistics.fmean(value) for value in clusters.values()]
    control_values: dict[str, float] = {}
    for control in sorted({str(row["control"]) for row in deltas}):
        control_values[control] = statistics.fmean(
            float(row["delta"]) for row in deltas if str(row["control"]) == control
        )
    tail_count = max(1, (len(control_values) + 4) // 5) if control_values else 0
    control_cvar20 = (
        statistics.fmean(sorted(control_values.values())[:tail_count])
        if control_values
        else float("nan")
    )
    rng = random.Random(seed)
    bootstrap: list[float] = []
    if cluster_values:
        for _ in range(bootstrap_samples):
            draw = [cluster_values[rng.randrange(len(cluster_values))] for _ in cluster_values]
            bootstrap.append(statistics.fmean(draw))
    mean_delta = statistics.fmean(values) if values else float("nan")
    q10 = _quantile(bootstrap, 0.10)
    probability_positive = (
        sum(value > 0 for value in bootstrap) / len(bootstrap) if bootstrap else 0.0
    )
    worst_control = min(control_values.values()) if control_values else float("nan")
    checks = [
        {
            "name": "panel_complete",
            "passed": bool(panel.get("complete")),
            "value": bool(panel.get("complete")),
            "threshold": "true",
        },
        {
            "name": "panel_errors",
            "passed": int(panel.get("errors", 0)) == 0,
            "value": int(panel.get("errors", 0)),
            "threshold": "==0",
        },
        {
            "name": "candidate_present",
            "passed": candidate_label in labels and candidate_label != baseline_label,
            "value": candidate_label in labels,
            "threshold": "candidate and baseline present",
        },
        {
            "name": "matched_cells",
            "passed": matched_cells >= limits.min_matched_cells,
            "value": matched_cells,
            "threshold": f">={limits.min_matched_cells}",
        },
        {
            "name": "support_fraction",
            "passed": support >= limits.min_support_fraction,
            "value": support,
            "threshold": f">={limits.min_support_fraction:.2f}",
        },
        {
            "name": "mean_delta",
            "passed": mean_delta >= limits.min_mean_delta,
            "value": mean_delta,
            "threshold": f">={limits.min_mean_delta:.3f}",
        },
        {
            "name": "bootstrap_q10",
            "passed": q10 >= limits.min_bootstrap_q10,
            "value": q10,
            "threshold": f">={limits.min_bootstrap_q10:.3f}",
        },
        {
            "name": "probability_positive",
            "passed": probability_positive >= limits.min_probability_positive,
            "value": probability_positive,
            "threshold": f">={limits.min_probability_positive:.2f}",
        },
        {
            "name": "control_cvar20",
            "passed": control_cvar20 >= limits.min_control_cvar20,
            "value": control_cvar20,
            "threshold": f">={limits.min_control_cvar20:.3f}",
        },
        {
            "name": "worst_control",
            "passed": worst_control >= limits.min_control_delta,
            "value": worst_control,
            "threshold": f">={limits.min_control_delta:.3f}",
        },
    ]
    return {
        "schema": "candidate_matched_outcome_v1",
        "candidate_label": candidate_label,
        "baseline_label": baseline_label,
        "candidate_identity": (panel.get("source_identities") or {}).get(candidate_label),
        "baseline_identity": (panel.get("source_identities") or {}).get(baseline_label),
        "limits": asdict(limits),
        "checks": checks,
        "passed": all(bool(check["passed"]) for check in checks),
        "matched_cells": matched_cells,
        "expected_cells": expected_cells,
        "clusters": len(cluster_values),
        "mean_delta": mean_delta,
        "bootstrap_q10": q10,
        "probability_positive": probability_positive,
        "control_cvar20": control_cvar20,
        "control_deltas": control_values,
        "deltas": deltas,
    }


def load_and_evaluate(
    path: Path,
    *,
    candidate_label: str,
    bootstrap_samples: int = 5000,
) -> dict[str, Any]:
    panel = json.loads(path.read_text())
    if panel.get("schema") != "seeded_transfer_feature_panel_v1":
        raise ValueError("unsupported seeded outcome panel schema")
    return evaluate_candidate_outcomes(
        panel,
        candidate_label=candidate_label,
        bootstrap_samples=bootstrap_samples,
    )


__all__ = [
    "CandidateOutcomeLimits",
    "evaluate_candidate_outcomes",
    "load_and_evaluate",
    "matched_candidate_deltas",
]
