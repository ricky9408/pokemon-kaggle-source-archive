"""Dependency-free inference for the external post-shift neural value head."""

from __future__ import annotations

from array import array
from dataclasses import dataclass
import hashlib
from math import exp, fsum
from pathlib import Path
import struct
import sys
from typing import Any, Sequence

from .option_forest import observation_feature_row


MAGIC = b"PVH1"


@dataclass(frozen=True)
class PublicValueHead:
    buckets: int
    dimension: int
    hidden: int
    embeddings: Sequence[float]
    value_w1: Sequence[float]
    value_b1: Sequence[float]
    value_w2: Sequence[float]
    value_b2: float

    @classmethod
    def load(cls, path: Path) -> "PublicValueHead":
        payload = path.read_bytes()
        if len(payload) < 16:
            raise ValueError("value-head binary is truncated")
        magic, buckets, dimension, hidden = struct.unpack_from("<4sIII", payload)
        if magic != MAGIC or min(buckets, dimension, hidden) <= 0:
            raise ValueError("invalid value-head header")
        floats = array("f")
        floats.frombytes(payload[16:])
        if sys.byteorder != "little":
            floats.byteswap()
        expected = buckets * dimension + hidden * dimension + hidden + hidden + 1
        if len(floats) != expected:
            raise ValueError(f"value-head binary has {len(floats)} floats; expected {expected}")
        cursor = 0

        def take(count: int) -> tuple[float, ...]:
            nonlocal cursor
            result = tuple(floats[cursor : cursor + count])
            cursor += count
            return result

        return cls(
            buckets,
            dimension,
            hidden,
            take(buckets * dimension),
            take(hidden * dimension),
            take(hidden),
            take(hidden),
            take(1)[0],
        )

    def score_buckets(self, option_buckets: Sequence[Sequence[int]]) -> float:
        """Return the acting player's win probability for one decision."""

        if not option_buckets:
            raise ValueError("value head requires at least one legal option")
        decision = [0.0] * self.dimension
        for buckets in option_buckets:
            option = [0.0] * self.dimension
            for bucket in buckets:
                if not 0 <= bucket < self.buckets:
                    raise ValueError("feature bucket out of range")
                offset = bucket * self.dimension
                for index in range(self.dimension):
                    option[index] += self.embeddings[offset + index]
            for index in range(self.dimension):
                decision[index] += option[index]
        scale = 1.0 / len(option_buckets)
        activated = [max(0.0, value * scale) for value in decision]
        hidden_values: list[float] = []
        for row in range(self.hidden):
            offset = row * self.dimension
            value = self.value_b1[row] + fsum(
                self.value_w1[offset + column] * activated[column]
                for column in range(self.dimension)
            )
            hidden_values.append(max(0.0, value))
        logit = self.value_b2 + fsum(
            self.value_w2[index] * hidden_values[index] for index in range(self.hidden)
        )
        if logit >= 0.0:
            return 1.0 / (1.0 + exp(-logit))
        magnitude = exp(logit)
        return magnitude / (1.0 + magnitude)

    def score_row(self, row: dict[str, Any]) -> float:
        from tools.train_ml_policy import option_features_v2

        count = int(row.get("option_count") or 0)
        bucket_rows = [
            [stable_bucket(feature, self.buckets) for feature in option_features_v2(row, index)]
            for index in range(count)
        ]
        return self.score_buckets(bucket_rows)


class ObservationValueHead:
    def __init__(
        self,
        model: PublicValueHead,
        *,
        archetype: str,
        card_names: dict[int, str],
    ) -> None:
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
    ) -> "ObservationValueHead":
        from tools.build_ml_replay_dataset import load_names

        return cls(
            PublicValueHead.load(model_path),
            archetype=archetype,
            card_names=load_names(card_data_path),
        )

    def root_utility(self, observation: dict[str, Any], root_player: int) -> float:
        current = observation.get("current") or {}
        actor = current.get("yourIndex")
        if actor not in (0, 1):
            raise ValueError("value-head observation has no acting player")
        row = observation_feature_row(
            observation,
            archetype=self.archetype if actor == root_player else "unknown",
            card_names=self.card_names,
        )
        actor_utility = 2.0 * self.model.score_row(row) - 1.0
        return actor_utility if actor == root_player else -actor_utility


def stable_bucket(value: str, modulo: int) -> int:
    return int(hashlib.sha1(value.encode()).hexdigest()[:10], 16) % modulo


__all__ = ["ObservationValueHead", "PublicValueHead", "stable_bucket"]
