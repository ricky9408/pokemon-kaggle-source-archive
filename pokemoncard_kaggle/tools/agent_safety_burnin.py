#!/usr/bin/env python3
"""Run the outcome-transfer hard safety burn-in on Linux/amd64."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.safety_burnin import load_observation_corpus, run_burnin  # noqa: E402


def _load_module(agent_dir: Path) -> ModuleType:
    main_path = agent_dir.resolve() / "main.py"
    name = "burnin_" + hashlib.sha256(str(main_path).encode()).hexdigest()[:16]
    old_cwd = Path.cwd()
    sys.path.insert(0, str(agent_dir.resolve()))
    os.chdir(agent_dir.resolve())
    try:
        spec = importlib.util.spec_from_file_location(name, main_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {main_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        os.chdir(old_cwd)
        sys.path.remove(str(agent_dir.resolve()))


def _fallback_counter(module: ModuleType):
    getter = getattr(module, "get_runtime_counters", None)
    if not callable(getter):
        return None

    def count() -> int:
        counters = getter()
        if not isinstance(counters, dict):
            raise TypeError("get_runtime_counters() must return a dict")
        return int(counters.get("fallbacks", counters.get("fallback_count", 0)))

    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-dir", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, action="append", required=True)
    parser.add_argument("--deck-hash")
    parser.add_argument("--calls", type=int, default=50_000)
    parser.add_argument("--repeat-checks", type=int, default=2_000)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    module = _load_module(args.agent_dir)
    observations = load_observation_corpus(args.dataset, deck_hash=args.deck_hash)
    result = run_burnin(
        module.agent,
        observations,
        calls=args.calls,
        repeat_checks=args.repeat_checks,
        fallback_count=_fallback_counter(module),
    )
    result.update(
        {
            "agent_dir": str(args.agent_dir),
            "archive_sha256": args.archive_sha256,
            "deck_hash_filter": args.deck_hash,
            "datasets": [str(path) for path in args.dataset],
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "checks"}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
