#!/usr/bin/env python3
"""Print the read-only fail-closed v6.3.1 status."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v6_3_1.status import compose_status


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments != ["status"]:
        print("usage: evaluation_v6_3_1_status.py status", file=sys.stderr)
        return 2
    report = compose_status()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
