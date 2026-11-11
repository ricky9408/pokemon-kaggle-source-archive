#!/usr/bin/env python3
"""Audit seeded native search for branch-order and process invariance."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import importlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.cohort import load_manifest, verify_manifest
from evaluation_v2.native_adapter import (
    PatchedNativeSession,
    derive_world_seed,
    enumerate_legal_selections,
    native_observation_hash,
    semantic_selection,
)
from evaluation_v2.world_bank import BeliefWorld, build_world_bank


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _load_api(engine_dir: Path) -> Any:
    engine_dir = engine_dir.resolve()
    if not (engine_dir / "cg" / "libcg.so").is_file():
        raise FileNotFoundError(f"patched engine missing: {engine_dir}")
    sys.path.insert(0, str(engine_dir))
    try:
        return importlib.import_module("cg.api")
    finally:
        sys.path.remove(str(engine_dir))


def _root_observations(replay: dict[str, Any], slot: int) -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []
    seen: set[str] = set()
    for step in replay.get("steps") or []:
        try:
            observation = step[slot].get("observation") or {}
        except (AttributeError, IndexError, TypeError):
            continue
        select = observation.get("select")
        if not isinstance(select, dict) or select.get("context") != 0:
            continue
        if not observation.get("search_begin_input") or not select.get("option"):
            continue
        key = _canonical({"current": observation.get("current"), "select": select})
        if key in seen:
            continue
        seen.add(key)
        roots.append(observation)
    return roots


def _choose_canonical(observation: Any, *, max_actions: int) -> tuple[int, ...] | None:
    if observation.select is None:
        return None
    select = asdict(observation.select)
    actions = enumerate_legal_selections(select, max_actions=max_actions)
    return min(actions, key=lambda action: _canonical(semantic_selection(select, action)))


def _trace_order(
    api: Any,
    observation: dict[str, Any],
    world: BeliefWorld,
    actions: list[tuple[int, ...]],
    *,
    depth: int,
    max_actions: int,
) -> dict[str, dict[str, Any]]:
    seed = derive_world_seed(world)
    traces: dict[str, dict[str, Any]] = {}
    with PatchedNativeSession(api, seed=seed) as session:
        root = session.begin(observation, world)
        root_id = root.searchId
        root_select = observation["select"]
        for root_action in actions:
            semantic = semantic_selection(root_select, root_action)
            key = _canonical(semantic)
            state = session.step(root_id, root_action)
            hashes = [native_observation_hash(state.observation)]
            path = [list(root_action)]
            for _ in range(max(0, depth - 1)):
                current = state.observation.current
                if current is None or current.result != -1 or state.observation.select is None:
                    break
                action = _choose_canonical(state.observation, max_actions=max_actions)
                if action is None:
                    break
                state = session.step(state.searchId, action)
                path.append(list(action))
                hashes.append(native_observation_hash(state.observation))
            current = state.observation.current
            traces[key] = {
                "path": path,
                "observation_hashes": hashes,
                "terminal_result": current.result if current is not None else None,
            }
    return traces


def audit(
    *,
    manifest_path: Path,
    meta_snapshot_path: Path,
    engine_dir: Path,
    role: str,
    root_limit: int,
    worlds_per_root: int,
    depth: int,
    max_actions: int,
) -> dict[str, Any]:
    if role != "development":
        raise ValueError("native invariance audit is development-only")
    manifest = load_manifest(manifest_path)
    errors = verify_manifest(manifest, ROOT)
    if errors:
        raise ValueError("manifest verification failed: " + "; ".join(errors))
    meta = json.loads(meta_snapshot_path.read_text())
    entries = meta.get("entries")
    if not isinstance(entries, list):
        raise ValueError("meta snapshot has no entries")
    api = _load_api(engine_dir)

    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    roots_seen = 0
    for episode in manifest.episodes:
        if episode.role != role or roots_seen >= root_limit:
            continue
        replay = json.loads(manifest.resolve_replay(ROOT, episode).read_text())
        for observation in _root_observations(replay, episode.target_slot):
            if roots_seen >= root_limit:
                break
            roots_seen += 1
            root_key = sha256(_canonical({"current": observation["current"], "select": observation["select"]}).encode()).hexdigest()
            try:
                actions = list(enumerate_legal_selections(observation["select"], max_actions=max_actions))
                bank = build_world_bank(
                    observation,
                    manifest.target_deck_cards,
                    entries,
                    world_count=max(len(entries), worlds_per_root),
                )
                selected_worlds = bank.worlds[:worlds_per_root]
                for world in selected_worlds:
                    forward = _trace_order(
                        api,
                        observation,
                        world,
                        actions,
                        depth=depth,
                        max_actions=max_actions,
                    )
                    reverse = _trace_order(
                        api,
                        observation,
                        world,
                        list(reversed(actions)),
                        depth=depth,
                        max_actions=max_actions,
                    )
                    if forward != reverse:
                        failures.append(
                            {
                                "episode_id": episode.episode_id,
                                "root_hash": root_key,
                                "world_id": world.world_id,
                                "reason": "branch_order_mismatch",
                            }
                        )
                    records.append(
                        {
                            "episode_id": episode.episode_id,
                            "root_hash": root_key,
                            "world_id": world.world_id,
                            "seed": derive_world_seed(world),
                            "action_count": len(actions),
                            "forward": forward,
                        }
                    )
            except Exception as exc:
                failures.append(
                    {
                        "episode_id": episode.episode_id,
                        "root_hash": root_key,
                        "reason": "adapter_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
    canonical_records = _canonical(records)
    return {
        "schema_version": 1,
        "manifest_id": manifest.cohort_id,
        "meta_snapshot": str(meta_snapshot_path),
        "engine_manifest": json.loads((engine_dir / "build_manifest.json").read_text()),
        "role": role,
        "root_limit": root_limit,
        "roots_seen": roots_seen,
        "worlds_per_root": worlds_per_root,
        "depth": depth,
        "records": records,
        "failures": failures,
        "transcript_sha256": sha256(canonical_records.encode()).hexdigest(),
        "passed": roots_seen == root_limit and bool(records) and not failures,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--meta-snapshot", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--role", default="development")
    parser.add_argument("--root-limit", type=int, default=10)
    parser.add_argument("--worlds-per-root", type=int, default=2)
    parser.add_argument("--depth", type=int, default=4)
    parser.add_argument("--max-actions", type=int, default=256)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = audit(
        manifest_path=args.manifest,
        meta_snapshot_path=args.meta_snapshot,
        engine_dir=args.engine_dir,
        role=args.role,
        root_limit=args.root_limit,
        worlds_per_root=args.worlds_per_root,
        depth=args.depth,
        max_actions=args.max_actions,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"records", "engine_manifest"}}, indent=2, sort_keys=True))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
