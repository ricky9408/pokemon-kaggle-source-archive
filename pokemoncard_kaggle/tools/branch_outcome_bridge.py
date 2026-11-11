#!/usr/bin/env python3
"""Fit and trace the preregistered branch_bridge_v1 evaluator."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import importlib
import json
from math import comb
from pathlib import Path
import sys
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.branch_outcome import (  # noqa: E402
    BranchRoot,
    FrozenHashedLogistic,
    actor_visible_state_features,
    build_support_table,
    canonical_json,
    canonical_sha256,
    fixed_overlap_cluster_key,
    reject_burned_artifact,
    semantic_action_family,
    sha256_file,
)
from evaluation_v2.native_adapter import (  # noqa: E402
    enumerate_legal_selections,
    information_set_hash,
    semantic_selection,
)
from evaluation_v2.native_tree import search_native_world_bank  # noqa: E402
from evaluation_v2.world_bank import build_world_bank  # noqa: E402


PREREG_SCHEMA = "branch_bridge_preregistration_v1"
STATE_SCHEMA = "branch_bridge_state_models_v1"
TRACE_SCHEMA = "branch_bridge_native_trace_v1"
ROOT_NAMESPACE = "branch-bridge-v1-root-sample"


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _verify_file(path: Path, expected: str) -> None:
    reject_burned_artifact(path)
    actual = sha256_file(path)
    if actual != expected:
        raise ValueError(f"source hash mismatch for {path}: {actual} != {expected}")


def load_preregistration(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if payload.get("schema") != PREREG_SCHEMA or payload.get("experiment_id") != "branch_bridge_v1":
        raise ValueError("unsupported branch bridge preregistration")
    if payload.get("status") != "frozen_before_development_metrics":
        raise ValueError("branch bridge preregistration is not frozen")
    for name in (
        "cohort_manifest",
        "cohort_development_decisions",
        "augmentation_manifest",
        "augmentation_decisions",
        "engine_library",
        "card_data",
    ):
        record = payload["data"][name]
        _verify_file(ROOT / record["path"], str(record["sha256"]))
    return payload


def _allowed_records(prereg: Mapping[str, Any]) -> tuple[dict[tuple[str, int, str], dict[str, Any]], tuple[int, ...]]:
    cohort = _load_json(ROOT / prereg["data"]["cohort_manifest"]["path"])
    augmentation = _load_json(ROOT / prereg["data"]["augmentation_manifest"]["path"])
    if cohort.get("cohort_id") != prereg["data"]["cohort_manifest"]["id"]:
        raise ValueError("cohort id mismatch")
    if augmentation.get("augmentation_id") != prereg["data"]["augmentation_manifest"]["id"]:
        raise ValueError("augmentation id mismatch")
    frozen_ids = {str(value) for value in augmentation.get("frozen_episode_ids") or ()}
    holdout_ids = {
        str(record["episode_id"])
        for record in cohort.get("episodes") or ()
        if record.get("role") == "holdout"
    }
    if not holdout_ids or not holdout_ids <= frozen_ids:
        raise ValueError("augmentation does not denylist every sealed holdout episode")
    records = []
    for record in cohort.get("episodes") or ():
        if record.get("role") == "development":
            records.append(record)
    for record in augmentation.get("records") or ():
        if record.get("role") != "development":
            raise ValueError("augmentation contains a non-development record")
        if str(record.get("episode_id")) in holdout_ids:
            raise ValueError("augmentation contains a sealed holdout episode")
        records.append(record)
    allowed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for record in records:
        if record.get("module_version") != prereg["data"]["module_version"]:
            raise ValueError("development record uses an unexpected engine module")
        if record.get("target_deck_sha256") != prereg["data"]["target_deck_sha256"]:
            raise ValueError("development record uses an unexpected target deck")
        key = (str(record["episode_id"]), int(record["target_slot"]), str(record["target_team"]))
        if key in allowed:
            raise ValueError(f"duplicate development side record: {key}")
        allowed[key] = record
    return allowed, tuple(int(card) for card in cohort["target_deck_cards"])


def _legal_action_count(select: Mapping[str, Any]) -> int:
    options = select.get("option") or ()
    minimum = int(select.get("minCount", 0))
    maximum = int(select.get("maxCount", 0))
    if not 0 <= minimum <= maximum <= len(options):
        return 0
    return sum(comb(len(options), count) for count in range(minimum, maximum + 1))


def _row_outcome(value: Any) -> float:
    reward = float(value)
    return 1.0 if reward > 0 else 0.0 if reward < 0 else 0.5


def _read_decision_sources(prereg: Mapping[str, Any]) -> list[dict[str, Any]]:
    allowed, _ = _allowed_records(prereg)
    paths = (
        ROOT / prereg["data"]["cohort_development_decisions"]["path"],
        ROOT / prereg["data"]["augmentation_decisions"]["path"],
    )
    seen: set[tuple[str, int, int]] = set()
    rows: list[dict[str, Any]] = []
    for path in paths:
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("cohort_role") != "development":
                raise ValueError(f"non-development row found in {path}")
            episode_id = str(row.get("episode_id"))
            slot = int(row.get("player_index", -1))
            pilot = str(row.get("teacher_team") or row.get("team") or "")
            record = allowed.get((episode_id, slot, pilot))
            if record is None:
                raise ValueError(f"decision row is not an allowed target side: {(episode_id, slot, pilot)}")
            if row.get("frozen_replay_sha256") != record.get("replay_sha256"):
                raise ValueError("decision replay hash does not match its frozen record")
            key = (episode_id, slot, int(row.get("step_index", -1)))
            if key in seen:
                continue
            seen.add(key)
            observation = row.get("observation") or {}
            select = observation.get("select") or {}
            options = select.get("option") or ()
            action = row.get("action")
            count = _legal_action_count(select)
            if (
                row.get("context") != "MAIN"
                or select.get("context") != 0
                or not observation.get("search_begin_input")
                or not 2 <= count <= 128
                or not isinstance(action, list)
                or not int(select.get("minCount", 0)) <= len(action) <= int(select.get("maxCount", 0))
                or len(set(action)) != len(action)
                or any(not isinstance(index, int) or not 0 <= index < len(options) for index in action)
            ):
                continue
            enriched = dict(observation)
            enriched["module_version"] = record["module_version"]
            rows.append(
                {
                    **row,
                    "observation": enriched,
                    "_pilot": pilot,
                    "_episode_id": episode_id,
                    "_slot": slot,
                    "_side_id": f"{episode_id}:{slot}:{pilot}",
                    "_game_id": episode_id,
                    "_replay_cluster": str(record["replay_sha256"]),
                    "_outcome": _row_outcome(record["target_reward"]),
                    "_module_version": str(record["module_version"]),
                }
            )
    return rows


def _fit_model(rows: list[dict[str, Any]], *, c_value: float) -> FrozenHashedLogistic:
    import numpy as np
    from scipy.sparse import csr_matrix
    from sklearn.linear_model import LogisticRegression

    if not rows:
        raise ValueError("state model training set is empty")
    sides_per_game = Counter(row["_game_id"] for row in {row["_side_id"]: row for row in rows}.values())
    decisions_per_side = Counter(row["_side_id"] for row in rows)
    labels: list[int] = []
    weights: list[float] = []
    indptr = [0]
    indices: list[int] = []
    values: list[float] = []
    expanded_rows: list[tuple[dict[str, Any], int, float]] = []
    for row in rows:
        base_weight = 1.0 / sides_per_game[row["_game_id"]] / decisions_per_side[row["_side_id"]]
        outcome = float(row["_outcome"])
        if outcome == 0.5:
            expanded_rows.extend(((row, 0, base_weight * 0.5), (row, 1, base_weight * 0.5)))
        else:
            expanded_rows.append((row, int(outcome), base_weight))
    for row, label, weight in expanded_rows:
        counts = Counter(actor_visible_state_features(row["observation"]))
        for bucket, count in sorted(counts.items()):
            indices.append(int(bucket))
            values.append(float(count))
        indptr.append(len(indices))
        labels.append(label)
        weights.append(weight)
    matrix = csr_matrix((values, indices, indptr), shape=(len(expanded_rows), 32768), dtype=np.float64)
    if len(set(labels)) < 2:
        raise ValueError("state model training fold has fewer than two outcome classes")
    model = LogisticRegression(C=c_value, solver="lbfgs", max_iter=2000, class_weight=None)
    model.fit(matrix, np.asarray(labels), sample_weight=np.asarray(weights))
    return FrozenHashedLogistic(
        intercept=float(model.intercept_[0]),
        weights=model.coef_[0].tolist(),
    )


def _resolved_option(observation: Mapping[str, Any], index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    select = observation["select"]
    option = dict(select["option"][index])
    resolved: dict[str, Any] = {}
    card_id = _get_option_card_id(observation, option)
    if card_id is None and int(option.get("type", -1)) in {7, 9}:
        card_id = _get_option_card_id(
            observation,
            {
                "area": 2,
                "index": option.get("index"),
                "playerIndex": (observation.get("current") or {}).get("yourIndex"),
            },
        )
    if card_id is not None:
        resolved["cardId"] = card_id
        raw_type = int(option.get("type", -1))
        if raw_type == 8:
            resolved["energyId"] = card_id
        elif raw_type == 10:
            resolved["sourceCardId"] = card_id
        elif raw_type == 12:
            resolved["targetCardId"] = card_id
    if "attackId" in option:
        resolved["attackId"] = option["attackId"]
    if "inPlayArea" in option:
        resolved["targetArea"] = option["inPlayArea"]
    if "effect" in option:
        resolved["effectId"] = option["effect"]
    return option, resolved


def _get_option_card_id(observation: Mapping[str, Any], option: Mapping[str, Any]) -> int | None:
    area = option.get("area")
    index = option.get("index")
    current = observation.get("current") or {}
    player_index = option.get("playerIndex", current.get("yourIndex"))
    try:
        if area == 1:
            card = (observation.get("select") or {}).get("deck", [])[index]
        elif area == 2:
            card = current["players"][player_index]["hand"][index]
        elif area == 3:
            card = current["players"][player_index]["discard"][index]
        elif area == 4:
            card = current["players"][player_index]["active"][index]
        elif area == 5:
            card = current["players"][player_index]["bench"][index]
        elif area == 12:
            card = current.get("looking", [])[index]
        else:
            return None
        return int(card["id"]) if isinstance(card, Mapping) and "id" in card else None
    except (IndexError, KeyError, TypeError, ValueError):
        return None


def _selection_identity(select: Mapping[str, Any], selection: Iterable[int]) -> str:
    return json.dumps(
        semantic_selection(select, tuple(selection)),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _selection_family(observation: Mapping[str, Any], selection: list[int] | tuple[int, ...]) -> str:
    if len(selection) != 1:
        families = [semantic_action_family(*_resolved_option(observation, index)) for index in selection]
        return "OTHER(MULTI:" + "+".join(sorted(families)) + ")"
    option, resolved = _resolved_option(observation, selection[0])
    return semantic_action_family(option, resolved)


def _support_row(row: Mapping[str, Any]) -> dict[str, Any]:
    observation = row["observation"]
    select = observation["select"]
    selections = enumerate_legal_selections(select, max_actions=128)
    family_by_action = {
        _selection_identity(select, selection): _selection_family(observation, selection)
        for selection in selections
    }
    selected_action = _selection_identity(select, row["action"])
    selected_family = family_by_action[selected_action]
    cluster = fixed_overlap_cluster_key(observation, family_by_action.values())
    return {
        "pilot": row["_pilot"],
        "episode_id": row["_side_id"],
        "game_id": row["_game_id"],
        "replay_cluster": row["_replay_cluster"],
        "fold": row["_pilot"],
        "cluster_key": cluster.as_dict(),
        "selected_action": selected_action,
        "selected_family": selected_family,
        "action_families": family_by_action,
        "outcome": row["_outcome"],
        "chronological_index": int(row["step_index"]),
    }


def fit_state_models(args: argparse.Namespace) -> int:
    prereg = load_preregistration(args.preregistration)
    rows = _read_decision_sources(prereg)
    pilots = sorted({row["_pilot"] for row in rows})
    support_rows = [_support_row(row) for row in rows]
    folds: dict[str, Any] = {}
    for pilot in pilots:
        held_games = {row["_game_id"] for row in rows if row["_pilot"] == pilot}
        training = [row for row in rows if row["_game_id"] not in held_games]
        model = _fit_model(training, c_value=float(prereg["state_model"]["model_c"]))
        folds[pilot] = {
            "excluded_game_ids": sorted(held_games),
            "training_games": len({row["_game_id"] for row in training}),
            "training_sides": len({row["_side_id"] for row in training}),
            "model": model.export_dict(),
        }
    final_model = _fit_model(rows, c_value=float(prereg["state_model"]["model_c"]))
    payload = {
        "schema": STATE_SCHEMA,
        "experiment_id": "branch_bridge_v1",
        "preregistration_path": str(args.preregistration),
        "preregistration_sha256": sha256_file(args.preregistration),
        "source_rows": len(rows),
        "independent_games": len({row["_game_id"] for row in rows}),
        "target_sides": len({row["_side_id"] for row in rows}),
        "pilots": pilots,
        "folds": folds,
        "final_model": final_model.export_dict(),
        "support_rows": support_rows,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in payload.items() if key not in {"folds", "final_model", "support_rows"}}, indent=2))
    return 0


def audit_support(args: argparse.Namespace) -> int:
    prereg = load_preregistration(args.preregistration)
    state_models = _load_json(args.state_models)
    if state_models.get("schema") != STATE_SCHEMA:
        raise ValueError("unsupported branch state-model artifact")
    if state_models.get("preregistration_sha256") != sha256_file(args.preregistration):
        raise ValueError("state model was fit under another preregistration")
    rows = [BranchRoot.from_dict(row) for row in state_models.get("support_rows") or ()]
    pilots = sorted({row.pilot for row in rows})
    audited: list[dict[str, Any]] = []
    for held_pilot in pilots:
        held_games = {row.game_id for row in rows if row.pilot == held_pilot}
        training = [row for row in rows if row.pilot != held_pilot and row.game_id not in held_games]
        training_pilots = sorted({row.pilot for row in training})
        table = build_support_table(training, training_folds=training_pilots)
        for row in rows:
            if row.pilot != held_pilot:
                continue
            support = table.evaluate(row.cluster_key, row.selected_family)
            audited.append(
                {
                    "pilot": row.pilot,
                    "episode_id": row.episode_id,
                    "game_id": row.game_id,
                    "cluster_key": row.as_dict()["cluster_key"],
                    "selected_family": row.selected_family,
                    **support,
                }
            )
    by_pilot: dict[str, list[bool]] = defaultdict(list)
    games_by_pilot: dict[str, set[str]] = defaultdict(set)
    supported_clusters: set[str] = set()
    for row in audited:
        by_pilot[row["pilot"]].append(bool(row["supported"]))
        games_by_pilot[row["pilot"]].add(row["game_id"])
        if row["supported"]:
            supported_clusters.add(canonical_json(row["cluster_key"]))
    per_pilot = {
        pilot: sum(values) / len(values)
        for pilot, values in sorted(by_pilot.items())
    }
    eligible_pilots = [
        per_pilot[pilot]
        for pilot, games in games_by_pilot.items()
        if len(games) >= 8
    ]
    overall = sum(bool(row["supported"]) for row in audited) / len(audited) if audited else 0.0
    minimum_pilot = min(eligible_pilots) if eligible_pilots else 0.0
    checks = [
        {
            "name": "overall_supported_mass",
            "passed": overall >= float(prereg["activation"]["min_overall_supported_mass"]),
            "value": overall,
            "threshold": prereg["activation"]["min_overall_supported_mass"],
        },
        {
            "name": "eligible_pilot_supported_mass",
            "passed": minimum_pilot >= float(prereg["activation"]["min_pilot_supported_mass"]),
            "value": minimum_pilot,
            "threshold": prereg["activation"]["min_pilot_supported_mass"],
        },
        {
            "name": "eligible_overlap_clusters",
            "passed": len(supported_clusters) >= 20,
            "value": len(supported_clusters),
            "threshold": 20,
        },
    ]
    payload = {
        "schema": "branch_bridge_support_audit_v1",
        "experiment_id": "branch_bridge_v1",
        "preregistration_sha256": sha256_file(args.preregistration),
        "state_models_sha256": sha256_file(args.state_models),
        "decisions": len(audited),
        "independent_games": len({row["game_id"] for row in audited}),
        "overall_supported_mass": overall,
        "per_pilot_supported_mass": per_pilot,
        "per_pilot_games": {pilot: len(games) for pilot, games in sorted(games_by_pilot.items())},
        "minimum_eligible_pilot_supported_mass": minimum_pilot,
        "eligible_overlap_clusters": len(supported_clusters),
        "checks": checks,
        "passed": all(check["passed"] for check in checks),
        "rows": audited,
    }
    payload["content_sha256"] = canonical_sha256(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in payload.items() if key != "rows"}, indent=2))
    return 0 if payload["passed"] else 1


def _load_api(engine_dir: Path) -> Any:
    sys.path.insert(0, str(engine_dir.resolve()))
    try:
        return importlib.import_module("cg.api")
    finally:
        sys.path.remove(str(engine_dir.resolve()))


def _sample_roots(rows: list[dict[str, Any]], roots_per_episode: int) -> list[dict[str, Any]]:
    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for row in rows:
        identity = information_set_hash(row["observation"])
        key = hashlib.sha256(
            f"{ROOT_NAMESPACE}\0{row['_side_id']}\0{row['step_index']}\0{identity}".encode()
        ).hexdigest()
        grouped[row["_side_id"]].append((key, row))
    selected = []
    for side_id in sorted(grouped):
        selected.extend(row for _, row in sorted(grouped[side_id])[:roots_per_episode])
    return sorted(selected, key=lambda row: (row["_side_id"], int(row["step_index"])))


def trace_development(args: argparse.Namespace) -> int:
    prereg = load_preregistration(args.preregistration)
    state_models = _load_json(args.state_models)
    if state_models.get("schema") != STATE_SCHEMA:
        raise ValueError("unsupported branch state-model artifact")
    if state_models.get("preregistration_sha256") != sha256_file(args.preregistration):
        raise ValueError("state model was fit under another preregistration")
    rows = _read_decision_sources(prereg)
    roots = _sample_roots(rows, int(prereg["branch_feature"]["roots_per_episode"]))
    roots = [row for index, row in enumerate(roots) if index % args.shard_count == args.shard_index]
    folds = {
        pilot: FrozenHashedLogistic.import_dict(record["model"])
        for pilot, record in state_models["folds"].items()
    }
    _, own_deck = _allowed_records(prereg)
    meta = _load_json(args.meta_snapshot)
    entries = meta.get("entries") or ()
    if not entries:
        raise ValueError("meta snapshot has no entries")
    api = _load_api(args.engine_dir)
    traced: list[dict[str, Any]] = []
    for row in roots:
        observation = row["observation"]
        select = observation["select"]
        selections = enumerate_legal_selections(select, max_actions=128)
        family_by_action = {
            _selection_identity(select, selection): _selection_family(observation, selection)
            for selection in selections
        }
        selected_action = _selection_identity(select, row["action"])
        selected_family = family_by_action[selected_action]
        cluster = fixed_overlap_cluster_key(observation, family_by_action.values())
        model = folds[row["_pilot"]]

        def leaf_value(leaf: dict[str, Any], root_player: int) -> float:
            probability = model.probability(leaf)
            actor = int((leaf.get("current") or {}).get("yourIndex", -1))
            actor_utility = 2.0 * probability - 1.0
            return actor_utility if actor == root_player else -actor_utility

        try:
            bank = build_world_bank(
                observation,
                own_deck,
                entries,
                world_count=max(int(prereg["branch_feature"]["world_limit"]), len(entries)),
            )
            decision = search_native_world_bank(
                api,
                observation,
                bank,
                depth=int(prereg["branch_feature"]["depth_main_decisions"]),
                world_limit=int(prereg["branch_feature"]["world_limit"]),
                max_native_nodes=int(prereg["branch_feature"]["max_native_nodes"]),
                max_actions=int(prereg["branch_feature"]["max_actions"]),
                prior_weight=0.0,
                leaf_evaluator=leaf_value,
            )
            if not decision.resolved:
                raise RuntimeError(decision.error or "native branch search unresolved")
            q_values = {
                action: min(max((float(value) + 1.0) / 2.0, 0.0), 1.0)
                for action, value in decision.root_action_values
            }
            if selected_action not in q_values:
                raise RuntimeError("recorded public action is absent from native branch values")
            root = BranchRoot(
                pilot=row["_pilot"],
                episode_id=row["_side_id"],
                replay_cluster=row["_replay_cluster"],
                cluster_key=cluster,
                selected_action=selected_action,
                selected_family=selected_family,
                action_families=family_by_action,
                outcome=row["_outcome"],
                q_values=q_values,
                supported=False,
                error=None,
                game_id=row["_game_id"],
                fold=row["_pilot"],
                chronological_index=int(row["step_index"]),
            )
        except Exception as exc:
            root = BranchRoot(
                pilot=row["_pilot"],
                episode_id=row["_side_id"],
                replay_cluster=row["_replay_cluster"],
                cluster_key=cluster,
                selected_action=selected_action,
                selected_family=selected_family,
                action_families=family_by_action,
                outcome=row["_outcome"],
                q_values={},
                supported=False,
                error=f"{type(exc).__name__}: {exc}",
                game_id=row["_game_id"],
                fold=row["_pilot"],
                chronological_index=int(row["step_index"]),
            )
        traced.append(root.as_dict())
    transcript = canonical_sha256(traced)
    payload = {
        "schema": TRACE_SCHEMA,
        "experiment_id": "branch_bridge_v1",
        "preregistration_sha256": sha256_file(args.preregistration),
        "state_models_sha256": sha256_file(args.state_models),
        "engine_manifest_sha256": sha256_file(args.engine_dir / "build_manifest.json"),
        "meta_snapshot_sha256": sha256_file(args.meta_snapshot),
        "shard_count": args.shard_count,
        "shard_index": args.shard_index,
        "roots": len(traced),
        "resolved": sum(not row["error"] for row in traced),
        "transcript_sha256": transcript,
        "rows": traced,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: value for key, value in payload.items() if key != "rows"}, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fit = subparsers.add_parser("fit-state")
    fit.add_argument("--preregistration", type=Path, required=True)
    fit.add_argument("--output", type=Path, required=True)
    fit.set_defaults(handler=fit_state_models)
    support = subparsers.add_parser("audit-support")
    support.add_argument("--preregistration", type=Path, required=True)
    support.add_argument("--state-models", type=Path, required=True)
    support.add_argument("--output", type=Path, required=True)
    support.set_defaults(handler=audit_support)
    trace = subparsers.add_parser("trace-development")
    trace.add_argument("--preregistration", type=Path, required=True)
    trace.add_argument("--state-models", type=Path, required=True)
    trace.add_argument("--engine-dir", type=Path, required=True)
    trace.add_argument("--meta-snapshot", type=Path, required=True)
    trace.add_argument("--shard-count", type=int, default=1)
    trace.add_argument("--shard-index", type=int, default=0)
    trace.add_argument("--output", type=Path, required=True)
    trace.set_defaults(handler=trace_development)
    args = parser.parse_args()
    if getattr(args, "shard_count", 1) <= 0:
        parser.error("shard-count must be positive")
    if not 0 <= getattr(args, "shard_index", 0) < getattr(args, "shard_count", 1):
        parser.error("shard-index must be in [0, shard-count)")
    return args


def main() -> int:
    args = parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
