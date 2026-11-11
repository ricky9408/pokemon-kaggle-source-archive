from __future__ import annotations

import math
import unittest

from evaluation_v2.transfer_validation import leave_lineage_out_predictions, score_predictions


class TransferValidationTests(unittest.TestCase):
    def test_leave_lineage_out_accepts_mapping_rows(self) -> None:
        rows = []
        for lineage_index in range(4):
            for game_index in range(6):
                rows.append(
                    {
                        "agent_label": f"a{lineage_index}",
                        "lineage": f"l{lineage_index}",
                        "episode_id": lineage_index * 10 + game_index,
                        "time_block": f"b{lineage_index}",
                        "player_slot": game_index % 2,
                        "opponent_axis": f"axis{game_index % 2}",
                        "module_version": "one",
                        "window_stage": "early",
                        "paired_mean_delta": lineage_index / 10,
                        "paired_cvar20_delta": -0.1,
                        "outcome": float((lineage_index + game_index) % 2),
                    }
                )
        predictions = leave_lineage_out_predictions(rows)
        self.assertEqual(len(predictions), len(rows))
        self.assertTrue(all(0.0 < row["augmented_probability"] < 1.0 for row in predictions))

    def test_score_predictions_uses_lineage_macro_average(self) -> None:
        rows = [
            {
                "agent_label": "a",
                "lineage": "a",
                "episode_id": 1,
                "time_block": "one",
                "outcome": 1.0,
                "nuisance_probability": 0.4,
                "augmented_probability": 0.8,
            },
            {
                "agent_label": "b",
                "lineage": "b",
                "episode_id": 2,
                "time_block": "one",
                "outcome": 0.0,
                "nuisance_probability": 0.6,
                "augmented_probability": 0.2,
            },
            {
                "agent_label": "b",
                "lineage": "b",
                "episode_id": 3,
                "time_block": "one",
                "outcome": 0.0,
                "nuisance_probability": 0.6,
                "augmented_probability": 0.2,
            },
        ]
        result = score_predictions(rows, bootstrap_samples=100, seed=7)
        expected = -math.log(0.4) + math.log(0.8)
        self.assertAlmostEqual(result["macro_logloss_improvement"], expected)
        self.assertEqual(result["positive_fold_fraction"], 1.0)
        self.assertEqual(result["bootstrap_probability_improvement_gt_zero"], 1.0)

    def test_score_predictions_reports_pairwise_direction(self) -> None:
        rows = []
        for index, outcome in enumerate((0.0, 0.25, 0.75, 1.0)):
            rows.append(
                {
                    "agent_label": f"a{index}",
                    "lineage": f"l{index}",
                    "episode_id": index,
                    "time_block": "one",
                    "outcome": outcome,
                    "nuisance_probability": 0.5,
                    "augmented_probability": 0.2 + index * 0.2,
                }
            )
        result = score_predictions(rows, bootstrap_samples=20, seed=9)
        self.assertEqual(result["pairwise_ordering_auc"], 1.0)
        self.assertAlmostEqual(result["agent_residual_spearman"], 1.0)


if __name__ == "__main__":
    unittest.main()
