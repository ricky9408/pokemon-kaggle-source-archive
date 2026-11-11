#!/usr/bin/env python3
"""Test whether local evaluator features predict held-out public lineages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.transfer_validation import evaluate_transfer, load_transfer_inputs  # noqa: E402


def _markdown(result: dict) -> str:
    lines = [
        "# Public-transfer validation",
        "",
        f"- Panel: `{result['panel_id']}`",
        f"- Baseline: `{result['baseline_label']}`",
        f"- Verdict: **{'CERTIFIED' if result['transfer_certified'] else 'NOT CERTIFIED'}**",
        "",
        "## Checks",
        "",
        "| Check | Pass | Value | Threshold |",
        "|---|---:|---:|---:|",
    ]
    for check in result["checks"]:
        value = check["value"]
        rendered = f"{value:.6f}" if isinstance(value, float) else str(value)
        lines.append(
            f"| {check['name']} | {'yes' if check['passed'] else 'no'} | {rendered} | {check['threshold']} |"
        )
    metrics = result.get("metrics")
    if metrics:
        lines.extend(
            [
                "",
                "## Interpretation",
                "",
                "Predictions are leave-one-policy-lineage-out. The nuisance model uses only seat, "
                "opponent axis, engine version, time block, and source-window stage. The augmented "
                "model adds only matched-seed mean and CVaR20 deltas. A failed check means the local "
                "evaluator is not a submit selector.",
                "",
                "| Agent | Games | Outcome | Nuisance | Augmented | Loss lift |",
                "|---|---:|---:|---:|---:|---:|",
            ]
        )
        for value in sorted(metrics["lineage_results"].values(), key=lambda row: row["agent_label"]):
            lines.append(
                f"| {value['agent_label']} | {value['games']} | {value['outcome']:.3f} | "
                f"{value['nuisance_probability']:.3f} | {value['augmented_probability']:.3f} | "
                f"{value['logloss_improvement']:+.4f} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", type=Path, required=True)
    parser.add_argument("--local-features", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    args = parser.parse_args()
    rows, metadata = load_transfer_inputs(args.panel, args.local_features)
    result = evaluate_transfer(rows, metadata, bootstrap_samples=args.bootstrap_samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(_markdown(result))
    print(
        json.dumps(
            {
                key: value
                for key, value in result.items()
                if key not in {"predictions", "historical_forward_predictions", "metadata"}
            },
            indent=2,
        )
    )
    return 0 if result["transfer_certified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
