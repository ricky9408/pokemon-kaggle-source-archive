from __future__ import annotations

import unittest

from evaluation_v2.statistics import (
    EpisodeRecord,
    beta_binomial_summary,
    episode_cluster_bootstrap,
    quantile,
    robust_matchup_mixture,
)


class EvaluationV2StatisticsTests(unittest.TestCase):
    def test_quantile_uses_exact_linear_interpolation(self) -> None:
        self.assertEqual(quantile([0.0, 10.0], 0.25), 2.5)

    def test_identity_delta_is_zero(self) -> None:
        summary = episode_cluster_bootstrap(
            [EpisodeRecord(4, 4, 8), EpisodeRecord(2, 2, 5)], seed=3
        )
        self.assertEqual(summary.point_delta, 0.0)
        self.assertEqual(summary.q10, 0.0)
        self.assertEqual(summary.q50, 0.0)
        self.assertEqual(summary.q90, 0.0)
        self.assertEqual(summary.p_gt_zero, 0.0)
        self.assertEqual(summary.sample_count, 2)
        self.assertEqual(summary.draw_count, 2000)

    def test_clear_positive_delta_stays_positive(self) -> None:
        summary = episode_cluster_bootstrap(
            [EpisodeRecord(9, 1, 10), EpisodeRecord(8, 2, 10)], seed=9
        )
        self.assertAlmostEqual(summary.point_delta, 0.7)
        self.assertGreater(summary.q10, 0.0)
        self.assertEqual(summary.p_gt_zero, 1.0)

    def test_bootstrap_resamples_episodes_not_decision_rows(self) -> None:
        summary = episode_cluster_bootstrap(
            [EpisodeRecord(100, 0, 100), EpisodeRecord(0, 100, 100)],
            seed=0,
            draws=100,
        )
        self.assertEqual(summary.point_delta, 0.0)
        self.assertEqual(summary.q10, -1.0)
        self.assertEqual(summary.q90, 1.0)

    def test_seeded_helpers_repeat_exactly(self) -> None:
        records = [EpisodeRecord(6, 4, 10), EpisodeRecord(1, 3, 5)]
        self.assertEqual(
            episode_cluster_bootstrap(records, seed=22),
            episode_cluster_bootstrap(records, seed=22),
        )
        self.assertEqual(
            beta_binomial_summary(7, 3, 2, seed=22),
            beta_binomial_summary(7, 3, 2, seed=22),
        )
        self.assertEqual(
            robust_matchup_mixture({"a": 0.2, "b": -0.1}, {"a": 9, "b": 1}, epsilon=0.1, seed=22),
            robust_matchup_mixture({"a": 0.2, "b": -0.1}, {"a": 9, "b": 1}, epsilon=0.1, seed=22),
        )

    def test_draws_split_evenly_in_jeffreys_posterior(self) -> None:
        summary = beta_binomial_summary(2, 0, 2, seed=5)
        self.assertAlmostEqual(summary.mean, 0.7)
        self.assertGreater(summary.q10, 0.0)
        self.assertLess(summary.q90, 1.0)

    def test_robust_mixture_applies_worst_cell_penalty(self) -> None:
        deltas = {"strong": 0.6, "weak": -0.4}
        counts = {"strong": 1000, "weak": 1}
        nominal = robust_matchup_mixture(deltas, counts, epsilon=0.0, seed=8)
        robust = robust_matchup_mixture(deltas, counts, epsilon=0.25, seed=8)
        self.assertEqual(robust.worst_cell, "weak")
        self.assertEqual(robust.worst_delta, -0.4)
        self.assertLess(robust.mean, nominal.mean)


if __name__ == "__main__":
    unittest.main()
