#!/usr/bin/env python3
"""Run the authority-free v5.1 exact-pair feasibility auditor."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

# Direct ``python tools/...py`` execution puts only ``tools`` on sys.path.
# Add the repository root so the package import has the same behavior as
# ``python -m`` and pytest without changing any input or output discovery.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from evaluation_v5_1.feasibility import (
    FeasibilityError,
    audit_feasibility,
    render_json,
    write_report_atomic,
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--constraints",
        "--constraints-json",
        dest="constraints",
        required=True,
        type=Path,
        help="explicit constraints JSON path",
    )
    parser.add_argument(
        "--status",
        "--status-json",
        dest="status",
        required=True,
        type=Path,
        help="explicit v5.1 status JSON path",
    )
    parser.add_argument(
        "--output",
        "--output-json",
        dest="output",
        type=Path,
        help="optional output JSON path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = audit_feasibility(args.constraints, args.status)
        if args.output is not None:
            write_report_atomic(args.output, report)
    except FeasibilityError as exc:
        print(f"evaluation-v5.1-feasibility-error: {exc}", file=sys.stderr)
        return 2
    print(render_json(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
