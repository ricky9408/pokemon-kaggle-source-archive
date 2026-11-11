#!/usr/bin/env python3
"""Freeze or verify one branch-bridge stage execution manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.stage_guard import (  # noqa: E402
    canonical_json,
    load_preregistration,
    stage_execution_manifest,
    verify_execution_manifest,
)


def dependency_versions() -> dict[str, str]:
    import numpy
    import scipy
    import sklearn

    return {
        "numpy": numpy.__version__,
        "scipy": scipy.__version__,
        "scikit_learn": sklearn.__version__,
    }


def code_paths(values: list[Path]) -> list[Path]:
    paths = {Path(__file__).resolve(), (ROOT / "evaluation_v2" / "stage_guard.py").resolve()}
    paths.update(path.resolve() for path in values)
    return sorted(paths, key=lambda path: str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "verify"))
    parser.add_argument("--stage", choices=("stage_a", "stage_b", "stage_c"), required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--code", type=Path, action="append", default=[])
    parser.add_argument("--lock", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    load_preregistration(args.preregistration, root=ROOT)
    paths = code_paths(args.code)
    versions = dependency_versions()
    if args.mode == "freeze":
        if args.output.exists():
            raise ValueError("execution manifest already exists; use verify rather than overwriting it")
        payload = stage_execution_manifest(
            stage=args.stage,
            preregistration_path=args.preregistration,
            code_paths=paths,
            lock_paths=args.lock,
            dependency_versions=versions,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(canonical_json(payload) + "\n", encoding="utf-8", newline="\n")
    else:
        if not args.output.is_file():
            raise ValueError("execution manifest does not exist")
        payload = json.loads(args.output.read_text(encoding="utf-8"))
        verify_execution_manifest(
            payload,
            stage=args.stage,
            preregistration_path=args.preregistration,
            code_paths=paths,
            lock_paths=args.lock,
            dependency_versions=versions,
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
