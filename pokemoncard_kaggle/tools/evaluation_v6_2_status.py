#!/usr/bin/env python3
"""Print a deterministic, read-only v6.2.1 pre-upload verification verdict."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v6_2.verifier import verify_preupload_bundle_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="canonical JSON pre-upload bundle")
    parser.add_argument("--root", type=Path, help="artifact root (defaults to bundle directory)")
    args = parser.parse_args()
    verdict = verify_preupload_bundle_file(args.bundle, root=args.root)
    print(json.dumps(verdict, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
