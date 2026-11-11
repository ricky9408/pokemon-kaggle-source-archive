#!/usr/bin/env python3
"""Find hidden-world leakage in patched SearchBegin root observations."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.cohort import load_manifest
from evaluation_v2.native_adapter import PatchedNativeSession, derive_world_seed, information_set_projection
from evaluation_v2.world_bank import build_world_bank


def _load_api(engine_dir: Path) -> Any:
    sys.path.insert(0, str(engine_dir.resolve()))
    try:
        return importlib.import_module("cg.api")
    finally:
        sys.path.remove(str(engine_dir.resolve()))


def _first_root(manifest: Any) -> dict[str, Any]:
    for episode in manifest.episodes:
        if episode.role != "development":
            continue
        replay = json.loads(manifest.resolve_replay(ROOT, episode).read_text())
        for step in replay.get("steps") or []:
            observation = step[episode.target_slot].get("observation") or {}
            select = observation.get("select")
            if isinstance(select, dict) and select.get("context") == 0 and observation.get("search_begin_input"):
                return observation
    raise ValueError("no development MAIN root")


def _differences(left: Any, right: Any, path: str = "") -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": path, "left": left, "right": right}]
    if isinstance(left, dict):
        result: list[dict[str, Any]] = []
        for key in sorted(set(left) | set(right)):
            result.extend(_differences(left.get(key), right.get(key), f"{path}.{key}" if path else key))
        return result
    if isinstance(left, list):
        result = []
        for index in range(max(len(left), len(right))):
            lvalue = left[index] if index < len(left) else "<missing>"
            rvalue = right[index] if index < len(right) else "<missing>"
            result.extend(_differences(lvalue, rvalue, f"{path}[{index}]"))
        return result
    return [] if left == right else [{"path": path, "left": left, "right": right}]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--meta-snapshot", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--worlds", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    observation = _first_root(manifest)
    entries = json.loads(args.meta_snapshot.read_text())["entries"]
    bank = build_world_bank(observation, manifest.target_deck_cards, entries, world_count=max(96, len(entries)))
    api = _load_api(args.engine_dir)
    projections: list[dict[str, Any]] = []
    for world in sorted(bank.worlds, key=lambda item: item.stable_hash)[: args.worlds]:
        with PatchedNativeSession(api, seed=derive_world_seed(world)) as session:
            state = session.begin(observation, world)
            projections.append(information_set_projection(asdict(state.observation)))
    baseline = projections[0]
    differences = [
        {"world_index": index, "differences": _differences(baseline, projection)}
        for index, projection in enumerate(projections[1:], start=1)
    ]
    result = {
        "worlds": len(projections),
        "identical": all(not item["differences"] for item in differences),
        "differences": differences,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
