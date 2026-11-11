"""Deterministic matched-seed arena for public-transfer feature extraction."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import importlib
import json
from pathlib import Path
import statistics
import sys
import time
from typing import Any, Callable, Iterable

from .cohort import read_deck
from .native_adapter import information_set_hash, semantic_selection
from .replay_eval import _load_agent


@dataclass(frozen=True)
class ArenaEntry:
    label: str
    path: str
    deck: tuple[int, ...]
    agent: Callable[[dict[str, Any]], list[int]]


def _cg_modules() -> dict[str, Any]:
    return {name: module for name, module in sys.modules.items() if name == "cg" or name.startswith("cg.")}


def _clear_cg_modules() -> None:
    for name in list(sys.modules):
        if name == "cg" or name.startswith("cg."):
            del sys.modules[name]


def load_entry_isolated(label: str, agent_dir: Path) -> ArenaEntry:
    """Load one policy while preventing bundled ``cg`` module collisions."""
    saved = _cg_modules()
    _clear_cg_modules()
    try:
        agent = _load_agent(agent_dir, f"seeded_{label}")
    finally:
        _clear_cg_modules()
        sys.modules.update(saved)
    return ArenaEntry(label, str(agent_dir), read_deck(agent_dir / "deck.csv"), agent)


def load_seeded_game(engine_dir: Path) -> Any:
    _clear_cg_modules()
    sys.path.insert(0, str(engine_dir.resolve()))
    try:
        return importlib.import_module("cg.game")
    finally:
        sys.path.remove(str(engine_dir.resolve()))


def _valid_action(action: Any, observation: dict[str, Any]) -> bool:
    select = observation.get("select") or {}
    options = select.get("option") or []
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", len(options)))
    return (
        isinstance(action, list)
        and minimum <= len(action) <= maximum
        and len(action) == len(set(action))
        and all(isinstance(index, int) and 0 <= index < len(options) for index in action)
    )


def run_seeded_game(
    game: Any,
    left: ArenaEntry,
    right: ArenaEntry,
    *,
    seed: int,
    max_steps: int,
) -> dict[str, Any]:
    observation, start = game.battle_start_seeded(list(left.deck), list(right.deck), seed)
    if observation is None:
        return {
            "seed": seed,
            "left": left.label,
            "right": right.label,
            "winner": None,
            "steps": 0,
            "error": f"start player={start.errorPlayer} type={start.errorType}",
            "max_action_seconds": 0.0,
            "max_action_seconds_by_label": {left.label: 0.0, right.label: 0.0},
            "transcript_sha256": None,
        }
    digest = sha256()
    result: int | None = None
    error: str | None = None
    max_action_seconds = 0.0
    max_action_seconds_by_label = {left.label: 0.0, right.label: 0.0}
    steps = 0
    try:
        for steps in range(1, max_steps + 1):
            current = observation.get("current") or {}
            result = current.get("result")
            digest.update(information_set_hash(observation).encode("ascii"))
            if result is not None and int(result) != -1:
                break
            actor = int(current.get("yourIndex"))
            entry = left if actor == 0 else right
            started = time.perf_counter()
            action = entry.agent(observation)
            action_seconds = time.perf_counter() - started
            max_action_seconds = max(max_action_seconds, action_seconds)
            max_action_seconds_by_label[entry.label] = max(
                max_action_seconds_by_label[entry.label], action_seconds
            )
            if not _valid_action(action, observation):
                error = f"illegal action by {entry.label}: {action}"
                break
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
    winner = int(result) if error is None and result is not None and int(result) in (0, 1, 2) else None
    return {
        "seed": seed,
        "left": left.label,
        "right": right.label,
        "winner": winner,
        "steps": steps,
        "error": error,
        "max_action_seconds": max_action_seconds,
        "max_action_seconds_by_label": max_action_seconds_by_label,
        "transcript_sha256": digest.hexdigest(),
    }


def anchor_outcome(row: dict[str, Any], anchor_label: str) -> float | None:
    winner = row.get("winner")
    if winner not in (0, 1, 2):
        return None
    if winner == 2:
        return 0.5
    winner_label = row["left"] if winner == 0 else row["right"]
    return 1.0 if winner_label == anchor_label else 0.0


def summarize_matched_deltas(
    rows: Iterable[dict[str, Any]],
    *,
    baseline_label: str,
) -> dict[str, dict[str, Any]]:
    rows = list(rows)
    cells: dict[tuple[str, str, int, int], float] = {}
    labels: set[str] = set()
    for row in rows:
        anchor = str(row["anchor"])
        labels.add(anchor)
        outcome = anchor_outcome(row, anchor)
        if outcome is None:
            continue
        cells[(anchor, str(row["control"]), int(row["seed"]), int(row["anchor_left"]))] = outcome
    features: dict[str, dict[str, Any]] = {}
    for label in sorted(labels):
        if label == baseline_label:
            continue
        deltas: list[float] = []
        for (anchor, control, seed, anchor_left), outcome in cells.items():
            if anchor != label:
                continue
            baseline = cells.get((baseline_label, control, seed, anchor_left))
            if baseline is not None:
                deltas.append(outcome - baseline)
        tail_count = max(1, (len(deltas) + 4) // 5) if deltas else 0
        ordered = sorted(deltas)
        features[label] = {
            "matched_cells": len(deltas),
            "paired_mean_delta": statistics.fmean(deltas) if deltas else None,
            "paired_cvar20_delta": statistics.fmean(ordered[:tail_count]) if deltas else None,
            "positive_cell_fraction": (
                sum(delta > 0 for delta in deltas) / len(deltas) if deltas else None
            ),
        }
    return features


__all__ = [
    "ArenaEntry",
    "anchor_outcome",
    "load_entry_isolated",
    "load_seeded_game",
    "run_seeded_game",
    "summarize_matched_deltas",
]
