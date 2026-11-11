"""Target-side public replay comparison for a frozen cohort.

Public actions are teacher observations, not optimal-action labels.  This module
therefore reports agreement and candidate-vs-baseline changes without assigning
counterfactual value to unchanged or unmatched actions.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable

from .cohort import verify_manifest
from .schemas import CohortManifest, EpisodeRecord


Agent = Callable[[dict], list[int]]


def _load_agent(agent_dir: Path, label: str) -> Agent:
    main_path = agent_dir.resolve() / "main.py"
    module_name = f"qualified_{label}_{hashlib.sha256(str(main_path).encode()).hexdigest()[:12]}"
    old_cwd = Path.cwd()
    sys.path.insert(0, str(agent_dir.resolve()))
    os.chdir(agent_dir.resolve())
    try:
        spec = importlib.util.spec_from_file_location(module_name, main_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {main_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.agent
    finally:
        os.chdir(old_cwd)
        try:
            sys.path.remove(str(agent_dir.resolve()))
        except ValueError:
            pass


def _engine_fingerprint(agent_dir: Path) -> tuple[str, str]:
    api = agent_dir / "cg" / "api.py"
    native = agent_dir / "cg" / "libcg.so"
    if not api.exists() or not native.exists():
        raise ValueError(f"agent is missing bundled engine files: {agent_dir}")
    return (
        hashlib.sha256(api.read_bytes()).hexdigest(),
        hashlib.sha256(native.read_bytes()).hexdigest(),
    )


def _valid_action(action: object, option_count: int, minimum: int, maximum: int) -> bool:
    return (
        isinstance(action, list)
        and minimum <= len(action) <= maximum
        and all(isinstance(index, int) and 0 <= index < option_count for index in action)
    )


def _state_key(obs: dict) -> str:
    current = dict(obs.get("current") or {})
    current.pop("result", None)
    return json.dumps(
        {"current": current, "select": obs.get("select") or {}},
        sort_keys=True,
        separators=(",", ":"),
    )


def _public_action(steps: list, step_index: int, slot: int) -> object:
    if step_index + 1 >= len(steps):
        return None
    try:
        return steps[step_index + 1][slot].get("action")
    except (AttributeError, IndexError, TypeError):
        return None


@dataclass(frozen=True)
class EpisodeAgreement:
    episode_id: int
    teacher_team: str
    opponent_team: str
    public_reward: float
    compared: int
    main_compared: int
    candidate_correct: int
    baseline_correct: int
    candidate_main_correct: int
    baseline_main_correct: int
    changes: int
    fixes: int
    regressions: int
    main_changes: int
    main_fixes: int
    main_regressions: int
    candidate_illegal: int
    baseline_illegal: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def compare_episode(path: Path, episode: EpisodeRecord, candidate: Agent, baseline: Agent) -> EpisodeAgreement:
    replay = json.loads(path.read_text())
    steps = replay["steps"]
    slot = episode.target_slot
    seen: set[str] = set()
    values: Counter[str] = Counter()
    for step_index, step in enumerate(steps):
        try:
            observation = (step[slot].get("observation") or {})
        except (AttributeError, IndexError, TypeError):
            continue
        select = observation.get("select")
        if not select:
            continue
        key = _state_key(observation)
        if key in seen:
            continue
        seen.add(key)
        options = select.get("option") or []
        minimum = int(select.get("minCount", 0))
        maximum = int(select.get("maxCount", len(options)))
        teacher = _public_action(steps, step_index, slot)
        if not options or not _valid_action(teacher, len(options), minimum, maximum):
            continue
        if len(teacher) == 60:
            continue
        # SelectContext.MAIN is stable at zero in every distributed engine API.
        # Keeping this reader independent of an agent's bundled cg package also
        # prevents import-order contamination when comparing two archives.
        is_main = select.get("context") == 0
        candidate_action = candidate(observation)
        baseline_action = baseline(observation)
        candidate_valid = _valid_action(candidate_action, len(options), minimum, maximum)
        baseline_valid = _valid_action(baseline_action, len(options), minimum, maximum)
        values["candidate_illegal"] += int(not candidate_valid)
        values["baseline_illegal"] += int(not baseline_valid)
        if not candidate_valid or not baseline_valid:
            continue
        candidate_same = candidate_action == teacher
        baseline_same = baseline_action == teacher
        changed = candidate_action != baseline_action
        fix = changed and candidate_same and not baseline_same
        regression = changed and baseline_same and not candidate_same
        values["compared"] += 1
        values["candidate_correct"] += int(candidate_same)
        values["baseline_correct"] += int(baseline_same)
        values["changes"] += int(changed)
        values["fixes"] += int(fix)
        values["regressions"] += int(regression)
        if is_main:
            values["main_compared"] += 1
            values["candidate_main_correct"] += int(candidate_same)
            values["baseline_main_correct"] += int(baseline_same)
            values["main_changes"] += int(changed)
            values["main_fixes"] += int(fix)
            values["main_regressions"] += int(regression)
    return EpisodeAgreement(
        episode_id=episode.episode_id,
        teacher_team=episode.target_team,
        opponent_team=episode.opponent_team,
        public_reward=episode.target_reward,
        **{field: values[field] for field in EpisodeAgreement.__dataclass_fields__ if field not in {"episode_id", "teacher_team", "opponent_team", "public_reward"}},
    )


def compare_manifest(
    *,
    manifest: CohortManifest,
    repo_root: Path,
    candidate_dir: Path,
    baseline_dir: Path,
    role: str,
) -> list[EpisodeAgreement]:
    if role not in {"development", "holdout"}:
        raise ValueError("role must be development or holdout")
    errors = verify_manifest(manifest, repo_root)
    if errors:
        raise ValueError("frozen cohort verification failed: " + "; ".join(errors))
    if _engine_fingerprint(candidate_dir) != _engine_fingerprint(baseline_dir):
        raise ValueError("candidate and baseline bundle different cg engines; compare in isolated workers")
    candidate = _load_agent(candidate_dir, "candidate")
    baseline = _load_agent(baseline_dir, "baseline")
    return [
        compare_episode(manifest.resolve_replay(repo_root, episode), episode, candidate, baseline)
        for episode in manifest.episodes
        if episode.role == role
    ]


def summarize(rows: Iterable[EpisodeAgreement]) -> dict[str, object]:
    records = list(rows)
    totals: Counter[str] = Counter()
    for row in records:
        for field in EpisodeAgreement.__dataclass_fields__:
            if field not in {"episode_id", "teacher_team", "opponent_team", "public_reward"}:
                totals[field] += int(getattr(row, field))
    compared = totals["compared"]
    main_compared = totals["main_compared"]
    return {
        "episodes": len(records),
        "teacher_teams": len({record.teacher_team for record in records}),
        **dict(totals),
        "candidate_agreement": totals["candidate_correct"] / compared if compared else 0.0,
        "baseline_agreement": totals["baseline_correct"] / compared if compared else 0.0,
        "agreement_delta": (totals["candidate_correct"] - totals["baseline_correct"]) / compared if compared else 0.0,
        "candidate_main_agreement": totals["candidate_main_correct"] / main_compared if main_compared else 0.0,
        "baseline_main_agreement": totals["baseline_main_correct"] / main_compared if main_compared else 0.0,
        "main_agreement_delta": (totals["candidate_main_correct"] - totals["baseline_main_correct"]) / main_compared if main_compared else 0.0,
    }
