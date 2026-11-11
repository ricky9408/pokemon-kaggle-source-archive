#!/usr/bin/env python3
"""Compose the single authoritative outcome-transfer submission verdict."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v3.promotion import compose_promotion_verdict  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--transfer", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--safety", type=Path, required=True)
    parser.add_argument("--identification", type=Path, required=True)
    parser.add_argument("--holdout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = compose_promotion_verdict(
        protocol_path=args.protocol,
        archive_path=args.archive,
        transfer_path=args.transfer,
        candidate_path=args.candidate,
        safety_path=args.safety,
        identification_path=args.identification,
        holdout_path=args.holdout,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    try:
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        print(f"refusing to overwrite existing verdict: {args.output}", file=sys.stderr)
        return 2
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps(result, indent=2))
    return 0 if result["submit_open"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
