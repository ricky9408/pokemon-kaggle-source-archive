#!/usr/bin/env python3
"""Disposable native branch worker for the engine-oracle parity probe."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v3.engine_oracle import ProbeFailure, run_branch, write_create_once_json  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        request = json.loads(args.input.read_text(encoding="utf-8"))
        if request.get("schema") != "engine_oracle_branch_request_v1":
            raise ProbeFailure("invalid branch request schema")
        result = run_branch(
            Path(request["library"]),
            request["observation"],
            request["zones"],
            request["first_action"],
            max_steps=int(request["max_steps"]),
        )
        write_create_once_json(args.output, result)
    except (KeyError, OSError, TypeError, ValueError, ProbeFailure) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
