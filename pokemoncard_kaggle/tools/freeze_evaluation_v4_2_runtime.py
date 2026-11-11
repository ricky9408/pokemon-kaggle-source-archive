#!/usr/bin/env python3
"""Create or verify the exact local runtime receipt for evaluation v4.2."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4_2.runtime_binding import (  # noqa: E402
    RuntimeBindingError,
    build_runtime_binding,
    validate_runtime_binding_file,
)


def _encoded(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def _write_create_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise RuntimeBindingError(f"runtime binding already exists: {path}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "freeze":
            receipt = build_runtime_binding(
                {
                    "evaluation_v2": ROOT / "evaluation_v2",
                    "evaluation_v4_2": ROOT / "evaluation_v4_2",
                }
            )
            _write_create_once(args.output, _encoded(receipt))
        else:
            receipt = validate_runtime_binding_file(args.output)
    except (RuntimeBindingError, OSError, ValueError) as exc:
        parser.exit(1, f"evaluation v4.2 runtime binding failed: {exc}\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
