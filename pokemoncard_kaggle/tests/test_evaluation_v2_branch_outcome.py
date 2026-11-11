from __future__ import annotations

import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from evaluation_v2.branch_outcome import (
    BURNED_PANEL_ID,
    BURNED_PANEL_SHA256,
    BranchActivationThresholds,
    BranchRoot,
    FrozenHashedLogistic,
    aggregate_episode,
    aggregate_unit,
    actor_visible_state_features,
    build_support_table,
    effective_branch_value,
    evaluate_activation_metrics,
    fixed_overlap_cluster_key,
    reject_burned_artifact,
    semantic_action_family,
)


def _state() -> dict:
    return {
        "module": "MAIN", "currentTurn": 4, "firstPlayer": 0, "yourIndex": 0,
        "turnActionCount": 2, "retreated": False, "energyAttached": True,
        "supporterPlayed": False, "stadiumPlayed": True,
        "sides": [
            {"active": {"cardId": 11, "hp": 120, "energy": [1], "tools": [8]}, "bench": [{"cardId": 12, "hp": 80}], "discard": [7], "prizes": [1, 2, 3], "hand": [999]},
            {"active": {"cardId": 21, "hp": 90}, "bench": [], "discard": [9], "prizes": [4, 5, 6], "hand": [666]},
        ],
        "logs": ["leak"], "selected_action": {"cardId": 999},
    }


def _root(index: int, *, episode: str = "e", fold: str = "train", pilot: str = "p", family: str = "ATTACK(1)", outcome: float = 1.0) -> BranchRoot:
    attack_action = "attack:1"
    return BranchRoot(
        pilot=pilot, episode_id=episode, replay_cluster="r", cluster_key="cluster", selected_family=family,
        outcome=outcome, q_values={attack_action: 1.0, "end": 0.0}, selected_action=attack_action,
        action_families={attack_action: family, "end": "END"}, supported=True,
        game_id=f"g{index}", fold=fold, chronological_index=index,
    )


class BranchOutcomeTests(unittest.TestCase):
    def test_hashes_strict_visible_whitelist_and_model_roundtrip(self) -> None:
        state = _state()
        original = actor_visible_state_features(state)
        state["sides"][1]["prizes"] = ["secret-a", "secret-b", "secret-c"]
        state["sides"][1]["hand"] = [1, 2, 3, 4]
        state["logs"] = ["another secret"]
        self.assertEqual(original, actor_visible_state_features(state))
        self.assertEqual(original, actor_visible_state_features(state))
        model = FrozenHashedLogistic(weights={original[0]: 2.0})
        rebuilt = FrozenHashedLogistic.import_dict(model.export_dict())
        self.assertEqual(model.score(original), rebuilt.score(original))

    def test_raw_engine_observation_accepts_current_and_own_hand_only(self) -> None:
        observation = {
            "current": {
                "module": "MAIN", "turn": 6, "firstPlayer": 0, "yourIndex": 0,
                "turnActionCount": 1, "players": [
                    {
                        "prize": 3, "deckCount": 40, "handCount": 2, "benchMax": 5,
                        "retreated": True, "active": [{"id": 11, "hp": 120, "energyCards": [{"id": 1}], "tools": [{"id": 8}]}],
                        "bench": [{"id": 12, "hp": 90, "energyCards": []}], "discard": [{"id": 7}],
                        "hand": [{"id": 51}, {"id": 52}],
                    },
                    {
                        "prize": 3, "deckCount": 41, "handCount": 2, "benchMax": 5,
                        "active": [{"id": 21, "hp": 100, "energyCards": []}], "bench": [],
                        "discard": [], "hand": [{"id": 601}, {"id": 602}],
                    },
                ],
            }
        }
        original = actor_visible_state_features(observation)
        observation["current"]["players"][1]["hand"] = [{"id": 701}, {"id": 702}]
        self.assertEqual(original, actor_visible_state_features(observation))
        observation["current"]["players"][0]["hand"] = [{"id": 53}, {"id": 54}]
        self.assertNotEqual(original, actor_visible_state_features(observation))
        cluster = fixed_overlap_cluster_key(observation, [{"type": 13, "attackId": 4}])
        self.assertEqual((cluster.turn_bin, cluster.own_active_id, cluster.own_prize_bin), ("6-8", "11", "3-4"))

    def test_semantic_actions_and_cluster_are_deterministic(self) -> None:
        self.assertEqual(semantic_action_family({"type": "PLAY", "cardId": 14}), "PLAY(14)")
        self.assertEqual(semantic_action_family({"type": "ABILITY", "sourceCardId": 2, "effectId": 3}), "ABILITY(2,3)")
        self.assertEqual(semantic_action_family({"type": "ATTACH"}, {"energyId": 4, "targetArea": "BENCH"}), "ATTACH(4,BENCH)")
        self.assertEqual(semantic_action_family({"semantic": {"type": "PLAY", "cardId": 9}}), "PLAY(9)")
        self.assertEqual(semantic_action_family({"type": "END_TURN"}), "END")
        self.assertEqual(semantic_action_family({"type": 7}, {"cardId": 4}), "PLAY(4)")
        self.assertEqual(semantic_action_family({"type": 8}, {"energyId": 2, "targetArea": "BENCH"}), "ATTACH(2,BENCH)")
        self.assertEqual(semantic_action_family({"type": 9}, {"cardId": 5}), "PLAY(5)")
        self.assertEqual(semantic_action_family({"type": 10}, {"sourceCardId": 2, "effectId": 6}), "ABILITY(2,6)")
        self.assertEqual(semantic_action_family({"type": 12}, {"targetCardId": 3}), "RETREAT(3)")
        self.assertEqual(semantic_action_family({"type": 13}, {"attackId": 7}), "ATTACK(7)")
        self.assertEqual(semantic_action_family({"type": 14}), "END")
        state = _state()
        first = fixed_overlap_cluster_key(state, [{"type": "END"}, {"type": "ATTACK", "attackId": 5}])
        second = fixed_overlap_cluster_key(state, [{"type": "ATTACK", "attackId": 5}, {"type": "END"}])
        self.assertEqual(first, second)
        self.assertEqual(first.turn_bin, "4-5")
        self.assertEqual(first.own_prize_bin, "3-4")

    def test_support_uses_training_folds_and_all_thresholds(self) -> None:
        rows = []
        for index in range(12):
            rows.append(_root(index, pilot=f"p{index % 3}", family="ATTACK(1)" if index < 6 else "END", outcome=float(index % 2)))
        rows.append(_root(99, fold="test", pilot="p9", family="PLAY(99)", outcome=1.0))
        table = build_support_table(rows, training_folds={"train"})
        supported = table.evaluate("cluster", "ATTACK(1)")
        self.assertTrue(supported["supported"])
        self.assertEqual(supported["cluster_games"], 12)
        self.assertEqual(supported["family_games"], 6)
        self.assertNotIn("PLAY(99)", table.clusters["cluster"].families)
        thin = build_support_table(rows[:11], training_folds={"train"})
        self.assertFalse(thin.evaluate("cluster", "ATTACK(1)")["supported"])

    def test_episode_and_unit_require_exactly_eight_episodes(self) -> None:
        episode = aggregate_episode([_root(2, episode="e", outcome=1.0), _root(1, episode="e", outcome=0.0)])
        self.assertEqual(episode["supported_decisions"], 2)
        self.assertAlmostEqual(episode["initial_state_probability"], 0.5)
        self.assertAlmostEqual(episode["initial_state_logit"], 0.0)
        episodes = [{**episode, "episode_id": f"e{index}"} for index in range(8)]
        unit = aggregate_unit(episodes, activation={"activated": True})
        self.assertEqual(unit["episodes"], 8)
        self.assertNotEqual(unit["B_unit"], 0.0)
        with self.assertRaises(ValueError):
            aggregate_unit(episodes[:7], activation=True)
        with self.assertRaises(ValueError):
            aggregate_unit([{**episode, "episode_id": "same"} for _ in range(8)], activation=True)

    def test_branch_q_values_are_action_level_not_family_level(self) -> None:
        first = "attach:energy=1:bench=one"
        selected = "attach:energy=1:bench=two"
        root = BranchRoot(
            pilot="p", episode_id="e", replay_cluster="r", cluster_key="c",
            selected_family="ATTACH(1,BENCH)", selected_action=selected, outcome=0.0,
            q_values={first: 0.9, selected: 0.1},
            action_families={first: "ATTACH(1,BENCH)", selected: "ATTACH(1,BENCH)"},
        )
        self.assertAlmostEqual(root.b or 0.0, -0.4)
        ambiguous = BranchRoot.from_dict({
            "pilot": "p", "episode_id": "e", "replay_cluster": "r", "cluster_key": "c",
            "selected_family": "ATTACH(1,BENCH)", "outcome": 0.0,
            "q_values": {first: 0.9, selected: 0.1},
            "action_families": {first: "ATTACH(1,BENCH)", selected: "ATTACH(1,BENCH)"},
        })
        self.assertEqual(ambiguous.selected_action, "")
        self.assertIsNone(ambiguous.b)

    def test_denylist_rejects_panel_id_and_artifact_hash(self) -> None:
        with self.assertRaises(ValueError):
            reject_burned_artifact(payload={"nested": {"panel_id": BURNED_PANEL_ID}})
        path = Path(self._testMethodName)
        path.write_bytes(b"temporary")
        try:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest() in {BURNED_PANEL_SHA256}, False)
            reject_burned_artifact(path)
            with patch("evaluation_v2.branch_outcome.sha256_file", return_value=BURNED_PANEL_SHA256):
                with self.assertRaises(ValueError):
                    reject_burned_artifact(path)
        finally:
            path.unlink()

    def test_activation_fails_closed_and_zeroes_branch_value(self) -> None:
        rows = [{
            "pilot": "p", "game_id": "g", "cluster_key": "c", "fold": "f", "supported": False,
            "b": -1.0, "outcome": 0.0, "m0_prediction": 0.1, "m1_prediction": 0.9,
        }]
        verdict = evaluate_activation_metrics(rows, bootstrap_samples=20)
        self.assertFalse(verdict["activated"])
        self.assertEqual(verdict["B_multiplier"], 0.0)
        self.assertEqual(effective_branch_value(0.5, verdict), 0.0)

    def test_activation_requires_caller_verified_repeat(self) -> None:
        relaxed = BranchActivationThresholds(
            overall_support_mass=0.0, eligible_pilot_support_mass=0.0,
            minimum_eligible_overlap_clusters=0, cluster_positive_slope_fraction=0.0,
            residual_spearman=-1.0, pairwise_residual_concordance=0.0,
            pilot_macro_logloss_lift=-10.0, positive_fold_fraction=0.0,
            bootstrap_probability_positive=0.0, bootstrap_q10_slope=-1.0,
        )
        rows = [{
            "pilot": "p", "game_id": "g", "cluster_key": "c", "fold": "f", "supported": True,
            "b": 1.0, "outcome": 1.0, "m0_prediction": 0.1, "m1_prediction": 0.9,
        }]
        self.assertFalse(evaluate_activation_metrics(rows, thresholds=relaxed, bootstrap_samples=20)["activated"])
        self.assertTrue(evaluate_activation_metrics(rows, thresholds=relaxed, bootstrap_samples=20, deterministic_repeat=True)["activated"])


if __name__ == "__main__":
    unittest.main()
