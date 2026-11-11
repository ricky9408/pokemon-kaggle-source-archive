import unittest

from evaluation_v2.surrogate import SurrogateRecord, evaluate


def record(index: int, *, outcome: float | None = None, family: str | None = None, meta: str | None = None) -> SurrogateRecord:
    return SurrogateRecord(
        observed_at=f"2026-07-{index + 1:02d}T00:00:00+00:00",
        archive_hash=f"archive-{index}",
        deck_family=family or f"family-{index % 3}",
        meta_snapshot_id=meta or f"meta-{index % 2}",
        metrics={"prospective_metric": float(index)},
        outcome_delta=float(index if outcome is None else outcome),
    )


class EvaluationV2SurrogateTests(unittest.TestCase):
    def test_future_outcome_cannot_change_earlier_predictions(self) -> None:
        records = [record(index) for index in range(14)]
        changed_future = records[:-1] + [record(13, outcome=-10_000.0)]

        original = evaluate(records, ["prospective_metric"])
        changed = evaluate(changed_future, ["prospective_metric"])

        self.assertEqual(original.predictions[:-1], changed.predictions[:-1])

    def test_insufficient_records_are_untrusted(self) -> None:
        result = evaluate([record(index) for index in range(6)], ["prospective_metric"])

        self.assertFalse(result.trusted)
        self.assertEqual(result.n_predictions, 5)
        self.assertTrue(any("12 predictions" in reason for reason in result.reasons))

    def test_duplicate_archive_hash_rejects(self) -> None:
        records = [record(0), record(1)]
        duplicate = SurrogateRecord(
            observed_at=records[1].observed_at,
            archive_hash=records[0].archive_hash,
            deck_family=records[1].deck_family,
            meta_snapshot_id=records[1].meta_snapshot_id,
            metrics=records[1].metrics,
            outcome_delta=records[1].outcome_delta,
        )

        with self.assertRaisesRegex(ValueError, "unique"):
            evaluate([records[0], duplicate], ["prospective_metric"])

    def test_monotone_sequence_can_become_trusted(self) -> None:
        result = evaluate([record(index) for index in range(14)], ["prospective_metric"])

        self.assertTrue(result.trusted, result.reasons)
        self.assertEqual(result.n_predictions, 13)
        self.assertAlmostEqual(result.spearman, 1.0)
        self.assertEqual(result.pairwise_accuracy, 1.0)
        self.assertLess(result.mae, 1.0)


if __name__ == "__main__":
    unittest.main()
