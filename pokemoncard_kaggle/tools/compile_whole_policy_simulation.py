#!/usr/bin/env python3
"""Compile a strict v4 whole-policy terminal simulation feature."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4.simulation import compile_simulation_feature  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260711)
    args = parser.parse_args(argv)
    if args.output.exists():
        print(f"refusing to overwrite existing feature: {args.output}", file=sys.stderr)
        return 2
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        feature = compile_simulation_feature(payload, bootstrap_samples=args.bootstrap_samples, seed=args.seed)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"simulation panel rejected: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(feature, indent=2, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    print(json.dumps(feature, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
