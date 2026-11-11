"""Pure-Python inference for the frozen multi-pilot option forest."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from statistics import fmean
from typing import Any


@dataclass(frozen=True)
class ExportedTree:
    left: tuple[int, ...]
    right: tuple[int, ...]
    feature: tuple[int, ...]
    threshold: tuple[float, ...]
    probability: tuple[float, ...]


class OptionForest:
    """Dependency-free evaluator for ``cohort_option_forest_v1`` exports."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("schema") != "cohort_option_forest_v1":
            raise ValueError("unsupported option forest schema")
        self.metadata = dict(payload.get("metadata") or {})
        self.feature_names = tuple(str(value) for value in payload.get("feature_names") or ())
        if not self.feature_names:
            raise ValueError("option forest has no feature names")
        self.trees = tuple(
            ExportedTree(
                tuple(int(value) for value in tree["left"]),
                tuple(int(value) for value in tree["right"]),
                tuple(int(value) for value in tree["feature"]),
                tuple(float(value) for value in tree["threshold"]),
                tuple(float(value) for value in tree["probability"]),
            )
            for tree in payload.get("trees") or ()
        )
        if not self.trees:
            raise ValueError("option forest has no trees")

    @classmethod
    def load(cls, path: Path) -> "OptionForest":
        return cls(json.loads(path.read_text()))

    def score_features(self, features: dict[str, float]) -> float:
        probabilities: list[float] = []
        for tree in self.trees:
            node = 0
            while tree.left[node] >= 0:
                feature_index = tree.feature[node]
                value = features.get(self.feature_names[feature_index], 0.0) if feature_index >= 0 else 0.0
                node = tree.left[node] if value <= tree.threshold[node] else tree.right[node]
            probabilities.append(tree.probability[node])
        return fmean(probabilities)

    def score_row(self, row: dict[str, Any]) -> tuple[float, ...]:
        # Importing the parity-critical featurizer here keeps the evaluation
        # model byte-compatible with its training path without pulling sklearn.
        from tools.train_cohort_option_forest import option_features_v4

        option_count = int(row.get("option_count") or 0)
        feature_lists = [option_features_v4(row, index) for index in range(option_count)]
        legal_types: dict[str, int] = {}
        for features in feature_lists:
            option_type = next((feature[5:] for feature in features if feature.startswith("type=")), "")
            legal_types[option_type] = legal_types.get(option_type, 0) + 1
        scores: list[float] = []
        for features in feature_lists:
            sample = {feature: 1.0 for feature in features}
            for option_type, count in legal_types.items():
                sample[f"legal_type={option_type}"] = float(count)
            scores.append(self.score_features(sample))
        return tuple(scores)


class ObservationForestPrior:
    """Convert a live observation to the exact forest training feature row."""

    def __init__(self, model: OptionForest, *, archetype: str, card_names: dict[int, str]) -> None:
        self.model = model
        self.archetype = archetype
        self.card_names = card_names

    @classmethod
    def load(
        cls,
        model_path: Path,
        *,
        archetype: str,
        card_data_path: Path,
    ) -> "ObservationForestPrior":
        from tools.build_ml_replay_dataset import load_names

        return cls(OptionForest.load(model_path), archetype=archetype, card_names=load_names(card_data_path))

    def option_scores(self, observation: dict[str, Any]) -> tuple[float, ...]:
        row = observation_feature_row(observation, archetype=self.archetype, card_names=self.card_names)
        return self.model.score_row(row)

    def score_selection(self, observation: dict[str, Any], selection: tuple[int, ...]) -> float:
        scores = self.option_scores(observation)
        if len(selection) != 1:
            return fmean(scores[index] for index in selection) if selection else 0.0
        return scores[selection[0]]


def observation_feature_row(
    observation: dict[str, Any],
    *,
    archetype: str,
    card_names: dict[int, str],
) -> dict[str, Any]:
    """Reconstruct the parity-critical online feature row."""

    from tools.build_ml_replay_dataset import (
        CONTEXT_NAMES,
        board_key_from_state,
        compact_state_features,
        enum_name,
        legal_type_counts,
        option_description,
    )

    select = observation.get("select") or {}
    options = select.get("option") or []
    state = compact_state_features(observation)
    return {
        "archetype": archetype,
        "context": enum_name(CONTEXT_NAMES, select.get("context")),
        "select_type": select.get("type"),
        "min_count": select.get("minCount"),
        "max_count": select.get("maxCount"),
        "option_count": len(options),
        "legal_type_counts": legal_type_counts(options),
        "turn_bin": str(state.get("turn")),
        "board_key": board_key_from_state(state),
        "options": [option_description(observation, index, card_names) for index in range(len(options))],
        "state": state,
        "observation": observation,
    }


__all__ = ["ObservationForestPrior", "OptionForest", "observation_feature_row"]
