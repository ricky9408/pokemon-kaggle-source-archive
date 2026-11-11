#!/usr/bin/env python3
"""Verify deterministic full-battle transcripts in the evaluator-only engine."""

from __future__ import annotations

import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.cohort import read_deck  # noqa: E402
from evaluation_v2.native_adapter import information_set_hash, semantic_selection  # noqa: E402


def canonical_action(observation: dict[str, Any]) -> list[int]:
    select = observation.get("select") or {}
    options = select.get("option") or []
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", len(options)))
    if not options:
        if minimum == 0:
            return []
        raise ValueError("required selection has no options")
    count = max(1, minimum)
    count = min(count, maximum, len(options))
    return list(range(count))


def _load_game(engine_dir: Path) -> Any:
    sys.path.insert(0, str(engine_dir.resolve()))
    try:
        return importlib.import_module("cg.game")
    finally:
        sys.path.remove(str(engine_dir.resolve()))


def run_game(
    game: Any,
    deck0: tuple[int, ...],
    deck1: tuple[int, ...],
    *,
    seed: int,
    max_steps: int,
) -> dict[str, Any]:
    observation, start = game.battle_start_seeded(list(deck0), list(deck1), seed)
    if observation is None:
        return {
            "seed": seed,
            "error": f"battle start failed player={start.errorPlayer} type={start.errorType}",
            "steps": 0,
            "result": None,
            "transcript_sha256": None,
        }
    digest = sha256()
    raw_digest = sha256()
    result: int | None = None
    error: str | None = None
    steps = 0
    try:
        for steps in range(1, max_steps + 1):
            current = observation.get("current") or {}
            result = current.get("result")
            raw_digest.update(
                json.dumps(observation, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
            )
            digest.update(information_set_hash(observation).encode("ascii"))
            if result is not None and int(result) != -1:
                break
            action = canonical_action(observation)
            raw_digest.update(json.dumps(action, separators=(",", ":")).encode())
            digest.update(
                json.dumps(
                    semantic_selection(observation["select"], action),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            )
            observation = game.battle_select(action)
        else:
            error = "max_steps"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        game.battle_finish()
    return {
        "seed": seed,
        "error": error,
        "steps": steps,
        "result": result,
        "transcript_sha256": digest.hexdigest(),
        "raw_transcript_sha256": raw_digest.hexdigest(),
    }


def semantically_equal(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return all(
        first.get(key) == second.get(key)
        for key in ("seed", "error", "steps", "result", "transcript_sha256")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--deck0", type=Path, required=True)
    parser.add_argument("--deck1", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260710)
    parser.add_argument("--max-steps", type=int, default=600)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    game = _load_game(args.engine_dir)
    deck0 = read_deck(args.deck0)
    deck1 = read_deck(args.deck1)
    first = run_game(game, deck0, deck1, seed=args.seed, max_steps=args.max_steps)
    repeat = run_game(game, deck0, deck1, seed=args.seed, max_steps=args.max_steps)
    alternate = run_game(game, deck0, deck1, seed=args.seed + 1, max_steps=args.max_steps)
    same_seed_identical = semantically_equal(first, repeat)
    passed = (
        first["error"] is None
        and repeat["error"] is None
        and same_seed_identical
    )
    result = {
        "schema": "seeded_battle_invariance_v1",
        "engine_manifest": json.loads((args.engine_dir / "build_manifest.json").read_text()),
        "first": first,
        "repeat": repeat,
        "alternate_seed": alternate,
        "same_seed_identical": same_seed_identical,
        "same_seed_raw_identical": first["raw_transcript_sha256"] == repeat["raw_transcript_sha256"],
        "alternate_seed_differs": first["transcript_sha256"] != alternate["transcript_sha256"],
        "passed": passed,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "engine_manifest"}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
