from __future__ import annotations

import unittest

from evaluation_v2.candidate_outcome import (
    CandidateOutcomeLimits,
    evaluate_candidate_outcomes,
)


def _row(anchor: str, control: str, seed: int, seat: int, winner: int) -> dict:
    return {
        "anchor": anchor,
        "control": control,
        "seed": seed,
        "anchor_left": seat,
        "left": anchor if seat else control,
        "right": control if seat else anchor,
        "winner": winner,
        "error": None,
    }


class CandidateOutcomeTests(unittest.TestCase):
    def test_clean_matched_lift_passes_relaxed_unit_limits(self) -> None:
        rows = []
        for control in ("one", "two"):
            for seed in (1, 2):
                for seat in (0, 1):
                    rows.append(_row("base", control, seed, seat, seat))
                    rows.append(_row("candidate", control, seed, seat, 1 - seat))
        panel = {
            "schema": "seeded_transfer_feature_panel_v1",
            "baseline_label": "base",
            "complete": True,
            "errors": 0,
            "rows": rows,
        }
        result = evaluate_candidate_outcomes(
            panel,
            candidate_label="candidate",
            limits=CandidateOutcomeLimits(min_matched_cells=8),
            bootstrap_samples=100,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["matched_cells"], 8)
        self.assertEqual(result["mean_delta"], 1.0)

    def test_missing_baseline_cells_fail_support(self) -> None:
        panel = {
            "schema": "seeded_transfer_feature_panel_v1",
            "baseline_label": "base",
            "complete": True,
            "errors": 0,
            "rows": [
                _row("candidate", "one", 1, 0, 0),
                _row("candidate", "one", 1, 1, 1),
            ],
        }
        result = evaluate_candidate_outcomes(
            panel,
            candidate_label="candidate",
            limits=CandidateOutcomeLimits(min_matched_cells=1),
            bootstrap_samples=20,
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["matched_cells"], 0)


if __name__ == "__main__":
    unittest.main()
