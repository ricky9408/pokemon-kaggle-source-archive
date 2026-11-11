#!/usr/bin/env python3
"""Evaluate candidate-neutral native search on frozen development teachers."""

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
from evaluation_v2.native_tree import public_leaf_value, search_native_world_bank
from evaluation_v2.option_forest import ObservationForestPrior, OptionForest
from evaluation_v2.replay_eval import _load_agent
from evaluation_v2.value_head import ObservationValueHead
from evaluation_v2.world_bank import build_world_bank


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


def _valid(action: Any, select: dict[str, Any]) -> bool:
    options = select.get("option") or []
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", len(options)))
    return (
        isinstance(action, list)
        and minimum <= len(action) <= maximum
        and len(set(action)) == len(action)
        and all(isinstance(index, int) and 0 <= index < len(options) for index in action)
    )


def _teacher_action(steps: list[Any], index: int, slot: int) -> Any:
    if index + 1 >= len(steps):
        return None
    try:
        return steps[index + 1][slot].get("action")
    except (AttributeError, IndexError, TypeError):
        return None


def _validate_model_configuration(
    *,
    policy_model_path: Path | None,
    policy_fold_dir: Path | None,
    policy_prior_weight: float,
    value_model_path: Path | None,
    value_weight: float,
) -> None:
    if policy_model_path is not None and policy_fold_dir is not None:
        raise ValueError("use either policy_model_path or policy_fold_dir, not both")
    if policy_prior_weight < 0.0:
        raise ValueError("policy_prior_weight must be non-negative")
    if policy_prior_weight > 0.0 and policy_model_path is None and policy_fold_dir is None:
        raise ValueError("positive policy_prior_weight requires a policy model or fold directory")
    if not 0.0 <= value_weight <= 1.0:
        raise ValueError("value_weight must be between zero and one")
    if value_weight > 0.0 and value_model_path is None:
        raise ValueError("positive value_weight requires a value model")


def _development_roots(manifest: Any, *, limit: int, sampling: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for episode in manifest.episodes:
        if episode.role != "development":
            continue
        replay = json.loads(manifest.resolve_replay(ROOT, episode).read_text())
        steps = replay.get("steps") or []
        for step_index, step in enumerate(steps):
            try:
                observation = step[episode.target_slot].get("observation") or {}
            except (AttributeError, IndexError, TypeError):
                continue
            select = observation.get("select")
            if not isinstance(select, dict) or select.get("context") != 0 or not observation.get("search_begin_input"):
                continue
            teacher = _teacher_action(steps, step_index, episode.target_slot)
            if not _valid(teacher, select) or len(teacher) == 60:
                continue
            key = sha256(_canonical({"current": observation.get("current"), "select": select}).encode()).hexdigest()
            identity = (episode.target_team, key)
            if identity in seen:
                continue
            seen.add(identity)
            grouped.setdefault(episode.target_team, []).append(
                {
                    "episode": episode,
                    "step_index": step_index,
                    "observation": observation,
                    "select": select,
                    "teacher": teacher,
                    "root_hash": key,
                }
            )
    for records in grouped.values():
        # The root hash is a deterministic pseudo-random ordering over states;
        # using it first avoids selecting only each teacher's earliest game.
        records.sort(key=lambda item: (item["root_hash"], item["episode"].episode_id, item["step_index"]))
    if sampling == "sequential":
        return [item for team in sorted(grouped) for item in grouped[team]][:limit]
    if sampling != "balanced-teacher":
        raise ValueError("sampling must be sequential or balanced-teacher")
    selected: list[dict[str, Any]] = []
    index = 0
    while len(selected) < limit:
        added = False
        for team in sorted(grouped):
            if index < len(grouped[team]):
                selected.append(grouped[team][index])
                added = True
                if len(selected) >= limit:
                    break
        if not added:
            break
        index += 1
    return selected


def evaluate(
    *,
    manifest_path: Path,
    meta_snapshot_path: Path,
    engine_dir: Path,
    baseline_dir: Path,
    root_limit: int,
    world_count: int,
    world_limit: int,
    depth: int,
    max_native_nodes: int,
    max_actions: int,
    policy_model_path: Path | None,
    policy_fold_dir: Path | None,
    policy_prior_weight: float,
    archetype: str,
    card_data_path: Path,
    sampling: str,
    value_model_path: Path | None,
    value_weight: float,
) -> dict[str, Any]:
    _validate_model_configuration(
        policy_model_path=policy_model_path,
        policy_fold_dir=policy_fold_dir,
        policy_prior_weight=policy_prior_weight,
        value_model_path=value_model_path,
        value_weight=value_weight,
    )
    manifest = load_manifest(manifest_path)
    errors = verify_manifest(manifest, ROOT)
    if errors:
        raise ValueError("manifest verification failed: " + "; ".join(errors))
    meta = json.loads(meta_snapshot_path.read_text())
    entries = meta.get("entries")
    if not isinstance(entries, list):
        raise ValueError("meta snapshot has no entries")
    api = _load_api(engine_dir)
    baseline = _load_agent(baseline_dir, "native_search_development_baseline")
    policy_prior = (
        ObservationForestPrior.load(
            policy_model_path,
            archetype=archetype,
            card_data_path=card_data_path,
        )
        if policy_model_path is not None
        else None
    )
    fold_priors: dict[str, ObservationForestPrior] = {}
    if policy_fold_dir is not None:
        from tools.build_ml_replay_dataset import load_names

        fold_manifest = json.loads((policy_fold_dir / "folds.json").read_text())
        if fold_manifest.get("schema") != "leave_one_teacher_option_forest_v1":
            raise ValueError("unsupported policy fold manifest")
        card_names = load_names(card_data_path)
        fold_priors = {
            team: ObservationForestPrior(
                OptionForest.load(policy_fold_dir / filename),
                archetype=archetype,
                card_names=card_names,
            )
            for team, filename in fold_manifest["models"].items()
        }
    value_head = (
        ObservationValueHead.load(
            value_model_path,
            archetype=archetype,
            card_data_path=card_data_path,
        )
        if value_model_path is not None
        else None
    )

    def leaf_evaluator(observation: dict[str, Any], root_player: int) -> float:
        material = public_leaf_value(observation, root_player)
        if value_head is None or value_weight == 0.0:
            return material
        neural = value_head.root_utility(observation, root_player)
        return (1.0 - value_weight) * material + value_weight * neural

    rows: list[dict[str, Any]] = []
    roots = _development_roots(manifest, limit=root_limit, sampling=sampling)
    for root in roots:
        episode = root["episode"]
        episode_policy_prior = fold_priors.get(episode.target_team, policy_prior)
        observation = root["observation"]
        select = root["select"]
        teacher = root["teacher"]
        baseline_action = baseline(observation)
        policy_action = None
        if episode_policy_prior is not None and int(select.get("minCount", 0)) == 1 and int(select.get("maxCount", 0)) == 1:
            policy_scores = episode_policy_prior.option_scores(observation)
            if policy_scores:
                policy_action = [min(range(len(policy_scores)), key=lambda index: (-policy_scores[index], index))]
        bank_error: str | None = None
        try:
            bank = build_world_bank(
                observation,
                manifest.target_deck_cards,
                entries,
                world_count=max(world_count, len(entries)),
            )
            decision = search_native_world_bank(
                api,
                observation,
                bank,
                depth=depth,
                world_limit=world_limit,
                max_native_nodes=max_native_nodes,
                max_actions=max_actions,
                max_policy_prior=episode_policy_prior.option_scores if episode_policy_prior is not None else None,
                prior_weight=policy_prior_weight,
                leaf_evaluator=leaf_evaluator,
            )
        except Exception as exc:
            bank_error = f"{type(exc).__name__}: {exc}"
            decision = None
        search_action = list(decision.selection) if decision and decision.selection is not None else None
        coverage = asdict(decision.search.coverage) if decision and decision.search is not None else None
        unresolved = [asdict(item) for item in decision.search.unresolved] if decision and decision.search is not None else None
        root_transitions = (
            [asdict(item) for item in decision.search.transitions if item.actor == "max" and item.world_count == decision.worlds]
            if decision and decision.search is not None
            else None
        )
        rows.append(
            {
                "episode_id": episode.episode_id,
                "step_index": root["step_index"],
                "teacher_team": episode.target_team,
                "root_hash": root["root_hash"],
                "teacher_action": teacher,
                "baseline_action": baseline_action,
                "policy_action": policy_action,
                "search_action": search_action,
                "root_options": select.get("option"),
                "baseline_correct": baseline_action == teacher,
                "search_correct": search_action == teacher,
                "changed": search_action is not None and search_action != baseline_action,
                "fix": search_action == teacher and baseline_action != teacher,
                "regression": baseline_action == teacher and search_action != teacher,
                "resolved": bool(decision and decision.resolved),
                "value": decision.value if decision else None,
                "worlds": decision.worlds if decision else 0,
                "native_nodes_built": decision.native_nodes_built if decision else 0,
                "search_margin": decision.margin if decision else None,
                "root_action_values": decision.root_action_values if decision else None,
                "coverage": coverage,
                "unresolved": unresolved,
                "root_transitions": root_transitions,
                "error": bank_error or (decision.error if decision else None),
            }
        )

    resolved = [row for row in rows if row["resolved"]]
    result = {
        "schema_version": 1,
        "role": "development",
        "manifest_id": manifest.cohort_id,
        "meta_snapshot": str(meta_snapshot_path),
        "engine_manifest": json.loads((engine_dir / "build_manifest.json").read_text()),
        "baseline_dir": str(baseline_dir),
        "policy_model": str(policy_model_path) if policy_model_path is not None else None,
        "policy_fold_dir": str(policy_fold_dir) if policy_fold_dir is not None else None,
        "policy_prior_weight": policy_prior_weight,
        "value_model": str(value_model_path) if value_model_path is not None else None,
        "value_weight": value_weight,
        "root_limit": root_limit,
        "sampling": sampling,
        "roots": len(rows),
        "resolved": len(resolved),
        "coverage": len(resolved) / len(rows) if rows else 0.0,
        "baseline_teacher_agreement": sum(row["baseline_correct"] for row in rows) / len(rows) if rows else 0.0,
        "policy_teacher_agreement": (
            sum(row["policy_action"] == row["teacher_action"] for row in rows) / len(rows)
            if rows and (policy_prior is not None or fold_priors)
            else None
        ),
        "search_teacher_agreement_resolved": (
            sum(row["search_correct"] for row in resolved) / len(resolved) if resolved else 0.0
        ),
        "fixes": sum(row["fix"] for row in resolved),
        "regressions": sum(row["regression"] for row in resolved),
        "rows": rows,
    }
    result["transcript_sha256"] = sha256(_canonical(rows).encode()).hexdigest()
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--meta-snapshot", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--root-limit", type=int, default=20)
    parser.add_argument("--sampling", choices=("balanced-teacher", "sequential"), default="balanced-teacher")
    parser.add_argument("--world-count", type=int, default=96)
    parser.add_argument("--world-limit", type=int, default=8)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-native-nodes", type=int, default=20_000)
    parser.add_argument("--max-actions", type=int, default=128)
    parser.add_argument("--policy-model", type=Path, default=None)
    parser.add_argument("--policy-fold-dir", type=Path, default=None)
    parser.add_argument("--policy-prior-weight", type=float, default=0.0)
    parser.add_argument("--archetype", default="alakazam-nighttime-mine")
    parser.add_argument("--card-data", type=Path, default=Path("data/EN_Card_Data.csv"))
    parser.add_argument("--value-model", type=Path, default=None)
    parser.add_argument("--value-weight", type=float, default=0.0)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = evaluate(
        manifest_path=args.manifest,
        meta_snapshot_path=args.meta_snapshot,
        engine_dir=args.engine_dir,
        baseline_dir=args.baseline_dir,
        root_limit=args.root_limit,
        world_count=args.world_count,
        world_limit=args.world_limit,
        depth=args.depth,
        max_native_nodes=args.max_native_nodes,
        max_actions=args.max_actions,
        policy_model_path=args.policy_model,
        policy_fold_dir=args.policy_fold_dir,
        policy_prior_weight=args.policy_prior_weight,
        archetype=args.archetype,
        card_data_path=args.card_data,
        sampling=args.sampling,
        value_model_path=args.value_model,
        value_weight=args.value_weight,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"rows", "engine_manifest"}}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
