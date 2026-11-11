from __future__ import annotations

import unittest

from evaluation_v2.expectiminimax import ExpectiminimaxNode, expectiminimax


def terminal(value: int, *, key: str = "terminal") -> ExpectiminimaxNode:
    return ExpectiminimaxNode("max", key, terminal_value=value)


class EvaluationV2ExpectiminimaxTests(unittest.TestCase):
    def test_max_and_min_nodes(self) -> None:
        max_root = ExpectiminimaxNode(
            "max", "root", ("lose", "win"), {"lose": terminal(-1), "win": terminal(1)}
        )
        self.assertEqual(expectiminimax(max_root).action, "win")
        self.assertEqual(expectiminimax(max_root).value, 1.0)

        min_root = ExpectiminimaxNode(
            "max",
            "root",
            ("a", "b"),
            {
                "a": ExpectiminimaxNode("min", "reply", ("x", "y"), {"x": terminal(1), "y": terminal(-1)}),
                "b": terminal(0),
            },
        )
        result = expectiminimax(min_root)
        self.assertEqual(result.action, "b")
        self.assertEqual(result.value, 0.0)

    def test_chance_averages_probabilities(self) -> None:
        chance = ExpectiminimaxNode(
            "chance",
            "coin",
            successors=(
                ExpectiminimaxNode("max", "win", terminal_value=1, chance_probability=0.25),
                ExpectiminimaxNode("max", "loss", terminal_value=-1, chance_probability=0.75),
            ),
        )
        root = ExpectiminimaxNode("max", "root", ("flip",), {"flip": chance})
        result = expectiminimax(root)
        self.assertTrue(result.resolved)
        self.assertEqual(result.action, "flip")
        self.assertAlmostEqual(result.value, -0.5)

    def test_indistinguishable_worlds_share_one_action(self) -> None:
        worlds = (
            ExpectiminimaxNode("max", "same-public-state", ("a", "b"), {"a": terminal(1), "b": terminal(1)}),
            ExpectiminimaxNode("max", "same-public-state", ("a", "b"), {"a": terminal(-1), "b": terminal(1)}),
        )
        result = expectiminimax(worlds)
        self.assertEqual(result.action, "b")
        self.assertEqual(result.value, 1.0)
        self.assertEqual(sum(item.selected for item in result.transitions), 1)

    def test_player_swap_is_zero_sum(self) -> None:
        root = ExpectiminimaxNode(
            "max",
            "root",
            ("a", "b"),
            {
                "a": ExpectiminimaxNode("min", "reply", ("take",), {"take": terminal(1)}),
                "b": ExpectiminimaxNode("min", "reply", ("take",), {"take": terminal(-1)}),
            },
        )
        result = expectiminimax(root)
        self.assertEqual(result.action, "a")
        self.assertEqual(result.value, 1.0)
        swapped = ExpectiminimaxNode(
            "max", "root", ("a", "b"), {"a": terminal(-1), "b": terminal(1)}
        )
        swapped_result = expectiminimax(swapped)
        self.assertEqual(swapped_result.value, 1.0)
        self.assertEqual(swapped_result.action, "b")

    def test_budget_exhaustion_fails_closed_with_evidence(self) -> None:
        root = ExpectiminimaxNode("max", "root", ("win",), {"win": terminal(1)})
        result = expectiminimax(root, node_budget=1)
        self.assertFalse(result.resolved)
        self.assertIsNone(result.action)
        self.assertIsNone(result.value)
        self.assertTrue(any(item.reason == "budget_exhausted" for item in result.unresolved))
        self.assertTrue(result.coverage.budget_exhausted)

    def test_public_policy_prior_breaks_equal_value_tie(self) -> None:
        leaf = ExpectiminimaxNode("max", "leaf", leaf_value=0.0)
        root = ExpectiminimaxNode(
            "max",
            "root",
            ("a", "b"),
            {"a": leaf, "b": leaf},
            {"a": 0.1, "b": 0.9},
        )

        result = expectiminimax(root, prior_weight=0.2)

        self.assertTrue(result.resolved)
        self.assertEqual(result.action, "b")

    def test_policy_prior_must_not_leak_hidden_world_identity(self) -> None:
        leaf = ExpectiminimaxNode("max", "leaf", leaf_value=0.0)
        roots = tuple(
            ExpectiminimaxNode(
                "max",
                "root",
                ("a", "b"),
                {"a": leaf, "b": leaf},
                {"a": prior, "b": 1.0 - prior},
            )
            for prior in (0.1, 0.2)
        )

        result = expectiminimax(roots, prior_weight=0.2)

        self.assertFalse(result.resolved)
        self.assertEqual({item.reason for item in result.unresolved}, {"action_prior_error"})


if __name__ == "__main__":
    unittest.main()
