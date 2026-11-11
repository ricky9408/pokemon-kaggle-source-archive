#!/usr/bin/env python3
"""Run the pure evaluation-v4.2 scientific-design audit."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.scientific_audit import (
    audit_scientific_claim,
    canonical_json_bytes,
    validate_scientific_audit_result,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-anchor-allowed", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    value = json.loads(args.input.read_text(encoding="utf-8"))
    result = validate_scientific_audit_result(audit_scientific_claim(value))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with args.output.open("xb") as handle:
            handle.write(canonical_json_bytes(result) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"scientific audit already exists: {args.output}") from None
    print(f"ANCHOR_ALLOWED={result['ANCHOR_ALLOWED']}")
    print(f"nominal_null={result['nominal_all_positive_null_probability']}")
    print(f"dependence_aware_null={result['dependence_aware_null_probability_lower_resolution']}")
    print(f"power={result['all_positive_power']}")
    for blocker in result["fatal_blockers"]:
        print(f"BLOCKER {blocker}")
    return 2 if args.require_anchor_allowed and not result["ANCHOR_ALLOWED"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
