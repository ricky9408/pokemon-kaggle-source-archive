#!/usr/bin/env python3
"""Recompute the v4 whole-policy selector receipt from raw anchored evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4.selector import evaluate_selector_packet, write_selector_receipt_once  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--lineage-manifest", type=Path, required=True)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        print(f"refusing to overwrite existing receipt: {args.output}", file=sys.stderr)
        return 2
    receipt = evaluate_selector_packet(
        protocol_path=args.protocol,
        lineage_manifest_path=args.lineage_manifest,
        sources_path=args.sources,
    )
    write_selector_receipt_once(args.output, receipt)
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["selector_validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
