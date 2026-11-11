#!/usr/bin/env python3
"""Create an auditable public panel child with explicit non-outcome exclusions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.public_transfer import filter_panel_by_label  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", type=Path, required=True)
    parser.add_argument("--exclude-label", action="append", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = filter_panel_by_label(
        json.loads(args.panel.read_text()),
        excluded_labels=args.exclude_label,
        exclusion_reason=args.reason,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "panel_id": result["panel_id"],
                "games": len(result["games"]),
                "excluded_labels": result["excluded_labels"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
