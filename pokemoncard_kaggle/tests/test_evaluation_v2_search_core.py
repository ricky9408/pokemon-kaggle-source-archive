from __future__ import annotations

import unittest

from evaluation_v2.search_core import (
    WorldActionValue,
    aggregate_action_worlds,
    select_conservative_root_override,
    select_rollout_action,
    stable_observation_seed,
)


class EvaluationV2SearchCoreTests(unittest.TestCase):
    def test_opponent_turn_uses_opponent_prior_not_root_prior(self) -> None:
        root_calls: list[str] = []
        opponent_calls: list[str] = []

        def root_prior(_state: object, action: str) -> float:
            root_calls.append(action)
            raise AssertionError("root prior must not score an opponent action")

        def opponent_prior(_state: object, action: str) -> float:
            opponent_calls.append(action)
            return {"attack": 0.0, "disrupt": 2.0}[action]

        choice = select_rollout_action(
            object(), ["attack", "disrupt"], actor="opponent", root_player="root", root_prior=root_prior, opponent_prior=opponent_prior
        )

        self.assertEqual(choice, "disrupt")
        self.assertEqual(root_calls, [])
        self.assertEqual(opponent_calls, ["attack", "disrupt"])

    def test_non_root_turn_requires_an_opponent_prior(self) -> None:
        with self.assertRaisesRegex(ValueError, "opponent_prior"):
            select_rollout_action(
                object(), ["a"], actor=1, root_player=0, root_prior=lambda _state, _action: 1.0, opponent_prior=None
            )

    def test_paired_world_aggregation_is_order_independent(self) -> None:
        values = [
            WorldActionValue("prior", "world-b", 0.1),
            WorldActionValue("search", "world-a", 0.6),
            WorldActionValue("prior", "world-a", 0.2),
            WorldActionValue("search", "world-b", 0.4),
        ]

        self.assertEqual(aggregate_action_worlds(values), aggregate_action_worlds(reversed(values)))

    def test_stable_observation_seed_ignores_mapping_order(self) -> None:
        first = {"turn": 3, "hand": [8, 2], "flags": {"stadium": False, "supporter": True}}
        second = {"flags": {"supporter": True, "stadium": False}, "hand": [8, 2], "turn": 3}

        self.assertEqual(stable_observation_seed(first), stable_observation_seed(second))
        self.assertNotEqual(stable_observation_seed(first), stable_observation_seed(first, namespace="other"))

    def test_insufficient_paired_evidence_falls_back_to_prior(self) -> None:
        decision = select_conservative_root_override(
            "prior",
            [
                WorldActionValue("prior", "one", 0.10),
                WorldActionValue("prior", "two", 0.10),
                WorldActionValue("search", "one", 0.90),
            ],
            min_worlds=2,
            min_margin=0.10,
        )

        self.assertEqual(decision.action, "prior")
        self.assertFalse(decision.overridden)
        self.assertEqual(decision.reason, "insufficient_paired_worlds")

    def test_margin_below_threshold_falls_back_to_prior(self) -> None:
        decision = select_conservative_root_override(
            "prior",
            [
                WorldActionValue("prior", "one", 0.30),
                WorldActionValue("prior", "two", 0.30),
                WorldActionValue("search", "one", 0.35),
                WorldActionValue("search", "two", 0.35),
            ],
            min_worlds=2,
            min_margin=0.10,
        )

        self.assertEqual(decision.action, "prior")
        self.assertEqual(decision.reason, "margin_below_threshold")


if __name__ == "__main__":
    unittest.main()
