#!/usr/bin/env python3
"""Compile a read-only evaluation-v4.2 population readiness report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.population_readiness import (
    compile_population_readiness,
    write_readiness_once,
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"artifact must contain a JSON object: {path}")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grammar", type=Path, required=True)
    parser.add_argument("--eligibility", type=Path, required=True)
    parser.add_argument("--ontology", type=Path, required=True)
    parser.add_argument("--roster", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="exit with status 2 when the report is closed",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = compile_population_readiness(
        candidate_grammar=_load(args.grammar),
        eligibility=_load(args.eligibility),
        family_ontology=_load(args.ontology),
        roster=_load(args.roster),
        roster_base_dir=args.roster.parent,
    )
    write_readiness_once(args.output, report)
    failed = [check for check in report["checks"] if not check["passed"]]
    print(f"decision={report['decision']}")
    print(f"eligible={sum(row['eligible'] for row in report['candidates'])}/{len(report['candidates'])}")
    for check in failed:
        print(f"FAILED {check['name']}: {check['detail']}")
    return 2 if args.require_ready and report["decision"] != "READY_FOR_POPULATION_FREEZE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
