#!/usr/bin/env python3
"""Annotate frozen cohort decision rows with one exact agent policy action."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evaluation_v2.replay_eval import _load_agent, _valid_action  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decisions", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--context", action="append", default=[])
    parser.add_argument("--max-decisions", type=int, default=0)
    parser.add_argument("--capture-debug", action="store_true")
    args = parser.parse_args()

    agent = _load_agent(args.agent, args.label)
    replay_cache: dict[str, dict[str, Any]] = {}
    annotated = 0
    invalid = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as target:
        for line in args.decisions.open(encoding="utf-8"):
            row = json.loads(line)
            if args.context and row.get("context") not in args.context:
                continue
            if args.max_decisions and annotated >= args.max_decisions:
                break
            replay_path = str(row["path"])
            replay = replay_cache.get(replay_path)
            if replay is None:
                source = Path(replay_path)
                if not source.exists():
                    parts = source.parts
                    if "pokemoncard_kaggle" in parts:
                        source = REPO.joinpath(*parts[parts.index("pokemoncard_kaggle") + 1 :])
                    elif not source.is_absolute():
                        source = REPO / source
                replay = json.loads(source.read_text())
                replay_cache[replay_path] = replay
            observation = replay["steps"][int(row["step_index"])][int(row["player_index"])]["observation"]
            action = agent(observation)
            valid = _valid_action(action, int(row["option_count"]), int(row["min_count"]), int(row["max_count"]))
            invalid += int(not valid)
            row[f"{args.label}_action"] = action
            row[f"{args.label}_valid"] = valid
            if args.capture_debug:
                row[f"{args.label}_debug"] = dict(agent.__globals__.get("LAST_SEARCH") or {})
            target.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            annotated += 1
    print(f"label={args.label} decisions={annotated} invalid={invalid} replays={len(replay_cache)} output={args.output}")
    return 0 if invalid == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
