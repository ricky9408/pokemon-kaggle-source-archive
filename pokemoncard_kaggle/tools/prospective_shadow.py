#!/usr/bin/env python3
"""Register, close, and audit fixed-game prospective evaluator shadows."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.prospective_shadow import (  # noqa: E402
    ShadowOutcome,
    ShadowPrediction,
    audit_shadow,
    record_outcome,
    register_prediction,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def register(args: argparse.Namespace) -> int:
    value = register_prediction(
        args.predictions,
        ShadowPrediction(
            registered_at_utc=datetime.now(timezone.utc).isoformat(),
            candidate_label=args.candidate_label,
            archive_sha256=args.archive_sha256,
            evaluator_sha256=args.evaluator_sha256,
            transfer_panel_id=args.transfer_panel_id,
            shadow_block=args.shadow_block,
            first_episode_count=8,
            first_episode_evidence_path=str(args.first_episode_evidence.resolve()),
            first_episode_evidence_sha256=_sha256(args.first_episode_evidence),
            nuisance_probability=args.nuisance_probability,
            augmented_probability=args.augmented_probability,
        ),
    )
    print(json.dumps(asdict(value), sort_keys=True))
    return 0


def close(args: argparse.Namespace) -> int:
    payload = json.loads(args.outcomes_json.read_text())
    outcomes = tuple(float(value) for value in payload["outcomes"])
    value = ShadowOutcome(
        unit_id=args.unit_id,
        closed_at_utc=datetime.now(timezone.utc).isoformat(),
        outcomes=outcomes,
        evidence_path=str(args.outcomes_json.resolve()),
        evidence_sha256=_sha256(args.outcomes_json),
    )
    record_outcome(args.predictions, args.outcomes, value)
    print(json.dumps(asdict(value), sort_keys=True))
    return 0


def audit(args: argparse.Namespace) -> int:
    result = audit_shadow(args.predictions, args.outcomes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "units"}, indent=2))
    return 0 if result["certified"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--predictions", type=Path, default=ROOT / "outcomes" / "prospective_shadow_predictions.jsonl")
    parser.add_argument("--outcomes", type=Path, default=ROOT / "outcomes" / "prospective_shadow_outcomes.jsonl")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_parser = subparsers.add_parser("register")
    register_parser.add_argument("--candidate-label", required=True)
    register_parser.add_argument("--archive-sha256", required=True)
    register_parser.add_argument("--evaluator-sha256", required=True)
    register_parser.add_argument("--transfer-panel-id", required=True)
    register_parser.add_argument("--shadow-block", required=True)
    register_parser.add_argument("--first-episode-evidence", type=Path, required=True)
    register_parser.add_argument("--nuisance-probability", type=float, required=True)
    register_parser.add_argument("--augmented-probability", type=float, required=True)
    register_parser.set_defaults(handler=register)
    close_parser = subparsers.add_parser("close")
    close_parser.add_argument("--unit-id", required=True)
    close_parser.add_argument("--outcomes-json", type=Path, required=True)
    close_parser.set_defaults(handler=close)
    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("--output", type=Path, required=True)
    audit_parser.set_defaults(handler=audit)
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
