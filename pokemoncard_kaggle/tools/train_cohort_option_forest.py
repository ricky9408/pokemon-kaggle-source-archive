#!/usr/bin/env python3
"""Train a pure-Python-exportable option forest on frozen development rows."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from tools.train_ml_policy import option_features_v2, valid_label  # noqa: E402

TARGET_RE = re.compile(r"to=(ACTIVE|BENCH):(\d+)")


def _bucket(value: Any, size: int, cap: int = 10) -> int:
    try:
        return min(cap, max(0, int(value)) // size)
    except (TypeError, ValueError):
        return -1


def _option_signature(description: str) -> str:
    body = description.split(":", 1)[1] if ":" in description else description
    return TARGET_RE.sub(lambda match: f"to={match.group(1)}", body)


def option_features_v3(row: dict[str, Any], option_index: int) -> list[str]:
    """Richer runtime-observable features for exact-deck multi-pilot learning."""
    features = option_features_v2(row, option_index)
    state = row.get("state") or {}
    me = state.get("me") or {}
    opponent = state.get("opponent") or {}
    options = row.get("options") or []
    description = options[option_index] if option_index < len(options) else ""
    signature = _option_signature(description)
    own_active = me.get("active")
    opponent_active = opponent.get("active")
    own_bench = tuple(sorted(int(card) for card in (me.get("bench") or []) if card is not None))
    opponent_bench = tuple(sorted(int(card) for card in (opponent.get("bench") or []) if card is not None))
    turn_bucket = _bucket(state.get("turn"), 2)
    action_bucket = _bucket(state.get("turn_action_count"), 2)
    hand_bucket = _bucket(me.get("hand_count"), 2)
    opponent_hand_bucket = _bucket(opponent.get("hand_count"), 2)
    stadium = state.get("stadium")
    features.extend(
        [
            f"v3_sig={signature}",
            f"v3_turn={turn_bucket}",
            f"v3_action={action_bucket}",
            f"v3_hand={hand_bucket}",
            f"v3_opp_hand={opponent_hand_bucket}",
            f"v3_stadium={stadium}",
            f"v3_own_active={own_active}",
            f"v3_opp_active={opponent_active}",
            f"v3_own_bench={own_bench}",
            f"v3_opp_bench={opponent_bench}",
            f"v3_sig_active={signature}:{own_active}",
            f"v3_sig_opp={signature}:{opponent_active}",
            f"v3_sig_turn={signature}:{turn_bucket}",
            f"v3_sig_action={signature}:{action_bucket}",
            f"v3_sig_hand={signature}:{hand_bucket}",
            f"v3_sig_opp_hand={signature}:{opponent_hand_bucket}",
            f"v3_sig_stadium={signature}:{stadium}",
        ]
    )
    for card in own_bench:
        features.extend((f"v3_own_bench_card={card}", f"v3_sig_own_bench={signature}:{card}"))
    for card in opponent_bench:
        features.extend((f"v3_opp_bench_card={card}", f"v3_sig_opp_bench={signature}:{card}"))
    target = TARGET_RE.search(description)
    if target:
        area, raw_index = target.groups()
        index = int(raw_index)
        target_card = own_active if area == "ACTIVE" else (me.get("bench") or [])[index] if index < len(me.get("bench") or []) else None
        features.extend((f"v3_target_card={target_card}", f"v3_sig_target={signature}:{target_card}"))
    for legal in options:
        features.append(f"v3_legal={_option_signature(legal)}")
    return features


def _card_ids(cards: Any) -> list[int]:
    if not isinstance(cards, list):
        return []
    return [int(card["id"]) for card in cards if isinstance(card, dict) and card.get("id") is not None]


def option_features_v4(row: dict[str, Any], option_index: int) -> list[str]:
    """Information-set-complete features derived from the live observation."""
    features = option_features_v3(row, option_index)
    observation = row.get("observation") or {}
    current = observation.get("current") or {}
    players = current.get("players") or []
    try:
        own_index = int(current.get("yourIndex", 0))
        own = players[own_index]
        opponent = players[1 - own_index]
    except (IndexError, TypeError, ValueError):
        return features
    options = row.get("options") or []
    description = options[option_index] if option_index < len(options) else ""
    signature = _option_signature(description)

    own_hand = _card_ids(own.get("hand"))
    own_discard = _card_ids(own.get("discard"))
    opponent_discard = _card_ids(opponent.get("discard"))
    for zone, cards in (("hand", own_hand), ("discard", own_discard), ("opp_discard", opponent_discard)):
        counts: dict[int, int] = defaultdict(int)
        for card in cards:
            counts[card] += 1
        for card, count in counts.items():
            features.extend(
                (
                    f"v4_{zone}_card={card}",
                    f"v4_{zone}_count={card}:{min(count, 4)}",
                    f"v4_sig_{zone}={signature}:{card}",
                )
            )

    for side, player in (("own", own), ("opp", opponent)):
        field = list(player.get("active") or []) + list(player.get("bench") or [])
        for position, pokemon in enumerate(field):
            if not isinstance(pokemon, dict) or pokemon.get("id") is None:
                continue
            card = int(pokemon["id"])
            hp_bucket = _bucket(pokemon.get("hp"), 30, 15)
            energy_ids = _card_ids(pokemon.get("energyCards"))
            tool_ids = _card_ids(pokemon.get("tools"))
            area = "active" if position == 0 else "bench"
            features.extend(
                (
                    f"v4_{side}_{area}={card}",
                    f"v4_{side}_field_hp={card}:{hp_bucket}",
                    f"v4_{side}_field_energy_count={card}:{min(len(energy_ids), 5)}",
                    f"v4_sig_{side}_field={signature}:{card}",
                )
            )
            for energy in energy_ids:
                features.extend((f"v4_{side}_energy={card}:{energy}", f"v4_sig_{side}_energy={signature}:{card}:{energy}"))
            for tool in tool_ids:
                features.extend((f"v4_{side}_tool={card}:{tool}", f"v4_sig_{side}_tool={signature}:{card}:{tool}"))

    features.extend(
        (
            f"v4_sig_prizes={signature}:{len(own.get('prize') or [])}",
            f"v4_sig_deck={signature}:{_bucket(own.get('deckCount'), 5, 12)}",
            f"v4_sig_discard_size={signature}:{_bucket(len(own_discard), 3, 10)}",
        )
    )
    return features


def load_main_rows(paths: Path | Iterable[Path]) -> list[dict[str, Any]]:
    sources = [paths] if isinstance(paths, Path) else list(paths)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int, str]] = set()
    for path in sources:
        for line in path.open(encoding="utf-8"):
            row = json.loads(line)
            if row.get("context") != "MAIN" or valid_label(row) is None:
                continue
            if int(row.get("option_count") or 0) <= 1:
                continue
            key = (
                int(row.get("episode_id", -1)),
                int(row.get("player_index", -1)),
                int(row.get("step_index", -1)),
                str(row.get("context")),
            )
            if key in seen:
                continue
            seen.add(key)
            rows.append(row)
    return rows


def option_samples(rows: list[dict[str, Any]]) -> tuple[list[dict[str, float]], list[int], list[float], list[tuple[int, int]]]:
    samples: list[dict[str, float]] = []
    labels: list[int] = []
    weights: list[float] = []
    spans: list[tuple[int, int]] = []
    for row in rows:
        start = len(samples)
        chosen = valid_label(row)
        option_count = int(row["option_count"])
        legal_types = defaultdict(int)
        for index in range(option_count):
            features = option_features_v4(row, index)
            option_type = next((feature[5:] for feature in features if feature.startswith("type=")), "")
            legal_types[option_type] += 1
        for index in range(option_count):
            features = option_features_v4(row, index)
            feature_map = {feature: 1.0 for feature in features}
            for option_type, count in legal_types.items():
                feature_map[f"legal_type={option_type}"] = float(count)
            samples.append(feature_map)
            positive = int(index == chosen)
            labels.append(positive)
            weights.append(0.5 if positive else 0.5 / max(1, option_count - 1))
        spans.append((start, len(samples)))
    return samples, labels, weights, spans


def predict_rows(model: Any, vectorizer: Any, rows: list[dict[str, Any]]) -> list[list[float]]:
    samples, _, _, spans = option_samples(rows)
    probabilities = model.predict_proba(vectorizer.transform(samples))[:, 1]
    return [probabilities[start:end].tolist() for start, end in spans]


def score_rows(model: Any, vectorizer: Any, rows: list[dict[str, Any]]) -> tuple[int, int, int, list[list[float]]]:
    row_probabilities = predict_rows(model, vectorizer, rows)
    top1 = top3 = 0
    for row, probabilities in zip(rows, row_probabilities):
        ranked = sorted(range(len(probabilities)), key=lambda index: (probabilities[index], -index), reverse=True)
        label = valid_label(row)
        top1 += int(ranked[0] == label)
        top3 += int(label in ranked[:3])
    return top1, top3, len(rows), row_probabilities


def fit(rows: list[dict[str, Any]], args: argparse.Namespace) -> tuple[Any, Any]:
    from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer

    samples, labels, weights, _ = option_samples(rows)
    vectorizer = DictVectorizer(sparse=True, sort=True)
    matrix = vectorizer.fit_transform(samples)
    estimator = ExtraTreesClassifier if args.forest_type == "extra" else RandomForestClassifier
    model = estimator(
        n_estimators=args.trees,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_leaf,
        max_features=args.max_features,
        random_state=args.seed,
        n_jobs=-1,
    )
    model.fit(matrix, labels, sample_weight=weights)
    return model, vectorizer


def export_model(model: Any, vectorizer: Any, path: Path, metadata: dict[str, Any]) -> None:
    trees = []
    class_one = list(model.classes_).index(1)
    for estimator in model.estimators_:
        tree = estimator.tree_
        leaf_probability = []
        for value in tree.value:
            counts = value[0]
            total = float(sum(counts))
            leaf_probability.append(round(float(counts[class_one]) / total, 8) if total else 0.0)
        trees.append(
            {
                "left": tree.children_left.tolist(),
                "right": tree.children_right.tolist(),
                "feature": tree.feature.tolist(),
                "threshold": [round(float(value), 8) for value in tree.threshold.tolist()],
                "probability": leaf_probability,
            }
        )
    payload = {
        "schema": "cohort_option_forest_v1",
        "metadata": metadata,
        "feature_names": vectorizer.get_feature_names_out().tolist(),
        "trees": trees,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("decisions", type=Path, nargs="+")
    parser.add_argument("--model-out", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--oof-out", type=Path, default=None)
    parser.add_argument("--fold-model-dir", type=Path, default=None)
    parser.add_argument("--trees", type=int, default=160)
    parser.add_argument("--max-depth", type=int, default=14)
    parser.add_argument("--min-leaf", type=int, default=2)
    parser.add_argument("--max-features", default="sqrt")
    parser.add_argument("--seed", type=int, default=20260710)
    parser.add_argument("--forest-type", choices=("extra", "random"), default="extra")
    parser.add_argument("--train-wins-only", action="store_true")
    parser.add_argument("--teacher-team", action="append", default=[])
    args = parser.parse_args()

    rows = load_main_rows(args.decisions)
    if args.teacher_team:
        selected_teams = set(args.teacher_team)
        rows = [
            row
            for row in rows
            if str(row.get("teacher_team") or row.get("team")) in selected_teams
        ]
    if not rows:
        raise SystemExit("no eligible MAIN rows")
    teams = sorted({str(row.get("teacher_team") or row.get("team")) for row in rows})
    folds: list[dict[str, Any]] = []
    oof_rows: list[dict[str, Any]] = []
    total_top1 = total_top3 = total = 0
    fold_models: dict[str, str] = {}
    for team in teams:
        training = [
            row
            for row in rows
            if str(row.get("teacher_team") or row.get("team")) != team
            and (not args.train_wins_only or float(row.get("teacher_reward", 0.0)) > 0.0)
        ]
        validation = [row for row in rows if str(row.get("teacher_team") or row.get("team")) == team]
        model, vectorizer = fit(training, args)
        if args.fold_model_dir is not None:
            filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", team).strip("_") + ".json"
            fold_path = args.fold_model_dir / filename
            export_model(
                model,
                vectorizer,
                fold_path,
                {
                    "sources": [str(path) for path in args.decisions],
                    "held_out_teacher": team,
                    "training_rows": len(training),
                    "trees": args.trees,
                    "max_depth": args.max_depth,
                    "min_leaf": args.min_leaf,
                    "max_features": args.max_features,
                    "seed": args.seed,
                    "forest_type": args.forest_type,
                    "train_wins_only": args.train_wins_only,
                },
            )
            fold_models[team] = filename
        top1, top3, count, probabilities = score_rows(model, vectorizer, validation)
        folds.append({"team": team, "n": count, "top1": top1 / count, "top3": top3 / count})
        for row, scores in zip(validation, probabilities):
            oof_rows.append(
                {
                    "episode_id": row.get("episode_id"),
                    "step_index": row.get("step_index"),
                    "player_index": row.get("player_index"),
                    "teacher_team": row.get("teacher_team"),
                    "action": row.get("action"),
                    "forest_scores": [round(float(score), 8) for score in scores],
                }
            )
        total_top1 += top1
        total_top3 += top3
        total += count

    final_training = [row for row in rows if not args.train_wins_only or float(row.get("teacher_reward", 0.0)) > 0.0]
    model, vectorizer = fit(final_training, args)
    metadata = {
        "sources": [str(path) for path in args.decisions],
        "rows": len(rows),
        "teacher_teams": teams,
        "leave_one_teacher_out_top1": total_top1 / total,
        "leave_one_teacher_out_top3": total_top3 / total,
        "trees": args.trees,
        "max_depth": args.max_depth,
        "min_leaf": args.min_leaf,
        "max_features": args.max_features,
        "seed": args.seed,
        "forest_type": args.forest_type,
        "train_wins_only": args.train_wins_only,
        "training_rows": len(final_training),
    }
    macro_top1 = sum(float(fold["top1"]) for fold in folds) / len(folds)
    macro_top3 = sum(float(fold["top3"]) for fold in folds) / len(folds)
    worst_top1 = min(float(fold["top1"]) for fold in folds)
    metadata.update(
        {
            "leave_one_teacher_out_macro_top1": macro_top1,
            "leave_one_teacher_out_macro_top3": macro_top3,
            "leave_one_teacher_out_worst_top1": worst_top1,
        }
    )
    export_model(model, vectorizer, args.model_out, metadata)

    lines = [
        "# Multi-pilot Option Forest",
        "",
        f"- Development MAIN decisions: {len(rows)}",
        f"- Teacher teams: {len(teams)}",
        f"- Leave-one-teacher-out top-1: {total_top1 / total:.3f}",
        f"- Leave-one-teacher-out top-3: {total_top3 / total:.3f}",
        f"- Teacher-macro top-1/top-3: {macro_top1:.3f} / {macro_top3:.3f}",
        f"- Worst-teacher top-1: {worst_top1:.3f}",
        f"- Trees: {args.trees}; max depth: {args.max_depth}; min leaf: {args.min_leaf}",
        "",
        "| Held-out teacher | N | Top-1 | Top-3 |",
        "| --- | ---: | ---: | ---: |",
    ]
    lines.extend(f"| {fold['team']} | {fold['n']} | {fold['top1']:.3f} | {fold['top3']:.3f} |" for fold in folds)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if args.oof_out:
        args.oof_out.parent.mkdir(parents=True, exist_ok=True)
        with args.oof_out.open("w", encoding="utf-8") as handle:
            for row in sorted(oof_rows, key=lambda value: (value["episode_id"], value["player_index"], value["step_index"])):
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    if args.fold_model_dir is not None:
        args.fold_model_dir.mkdir(parents=True, exist_ok=True)
        (args.fold_model_dir / "folds.json").write_text(
            json.dumps(
                {
                    "schema": "leave_one_teacher_option_forest_v1",
                    "sources": [str(path) for path in args.decisions],
                    "models": fold_models,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    print("\n".join(lines))
    print(f"model={args.model_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
