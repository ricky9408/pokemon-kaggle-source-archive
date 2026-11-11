#!/usr/bin/env python3
"""Register pre-submit metrics and close fixed-horizon public outcomes."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evaluation_v2.calibration import (  # noqa: E402
    OutcomeRecord,
    PredictionRecord,
    audit,
    record_outcome,
    register_prediction,
)

METRICS = (
    "candidate_main_agreement",
    "bootstrap_q10",
    "arena_robust_q10",
    "meta_margin_over_rank10",
)


def register(args: argparse.Namespace) -> int:
    verdict = json.loads(args.verdict.read_text())
    record = PredictionRecord(
        created_at_utc=verdict["generated_at_utc"],
        candidate_label=verdict["candidate"]["label"],
        archive_sha256=verdict["candidate"]["archive_sha256"],
        pipeline_sha256=verdict["pipeline_sha256"],
        deck_family=args.deck_family,
        meta_snapshot_id=args.meta_snapshot_id,
        baseline_label=args.baseline_label,
        metrics={
            "candidate_main_agreement": float(verdict["holdout"]["summary"]["candidate_main_agreement"]),
            "bootstrap_q10": float(verdict["holdout"]["bootstrap"]["q10"]),
            "arena_robust_q10": float(verdict["arena"]["robust"]["q10"]),
            "meta_margin_over_rank10": float(verdict["meta"]["margin_over_rank10"]),
        },
        horizon_hours=args.horizon_hours,
    )
    registered = register_prediction(args.predictions, record)
    print(json.dumps(asdict(registered), sort_keys=True))
    return 0


def close(args: argparse.Namespace) -> int:
    outcome = OutcomeRecord(
        prediction_id=args.prediction_id,
        submission_ref=args.submission_ref,
        submitted_at_utc=args.submitted_at,
        first_complete_at_utc=args.first_complete_at,
        observed_at_utc=args.observed_at,
        candidate_score=args.candidate_score,
        baseline_score=args.baseline_score,
        evidence_path=str(args.evidence),
    )
    record_outcome(args.predictions, args.outcomes, outcome)
    print(json.dumps({**asdict(outcome), "outcome_delta": outcome.outcome_delta}, sort_keys=True))
    return 0


def report(args: argparse.Namespace) -> int:
    result = audit(args.predictions, args.outcomes, METRICS)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.trusted else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=Path, default=REPO / "outcomes" / "prospective_predictions.jsonl")
    parser.add_argument("--outcomes", type=Path, default=REPO / "outcomes" / "prospective_outcomes.jsonl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("--verdict", type=Path, required=True)
    register_parser.add_argument("--deck-family", required=True)
    register_parser.add_argument("--meta-snapshot-id", required=True)
    register_parser.add_argument("--baseline-label", required=True)
    register_parser.add_argument("--horizon-hours", type=float, default=24.0)
    register_parser.set_defaults(handler=register)

    close_parser = subparsers.add_parser("close")
    close_parser.add_argument("--prediction-id", required=True)
    close_parser.add_argument("--submission-ref", type=int, required=True)
    close_parser.add_argument("--submitted-at", required=True)
    close_parser.add_argument("--first-complete-at", required=True)
    close_parser.add_argument("--observed-at", required=True)
    close_parser.add_argument("--candidate-score", type=float, required=True)
    close_parser.add_argument("--baseline-score", type=float, required=True)
    close_parser.add_argument("--evidence", type=Path, required=True)
    close_parser.set_defaults(handler=close)

    audit_parser = subparsers.add_parser("audit")
    audit_parser.set_defaults(handler=report)

    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
