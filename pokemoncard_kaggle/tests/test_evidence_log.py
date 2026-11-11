from __future__ import annotations

import hashlib
import json
import multiprocessing
from pathlib import Path
import tempfile
import threading
import unittest

from evaluation_v3.episode_inventory import canonical_json
from evaluation_v3.evidence_log import (
    EVIDENCE_LOG_SCHEMA,
    GENESIS_EVENT_SHA256,
    append_event,
    verify_event_log,
)


LOG_ID = "prospective-evidence-test"


def _append_from_process(args: tuple[str, str, str]) -> int:
    path, event_id, created_at_utc = args
    event = append_event(
        path,
        log_id=LOG_ID,
        event_id=event_id,
        event_type="registered",
        created_at_utc=created_at_utc,
        payload={"unit": event_id},
    )
    return event["sequence"]


class EvidenceLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "evidence.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def append(self, event_id: str, *, created_at_utc: str = "2026-07-11T01:02:03Z") -> dict[str, object]:
        return append_event(
            self.path,
            log_id=LOG_ID,
            event_id=event_id,
            event_type="registered",
            created_at_utc=created_at_utc,
            payload={"unit": event_id, "nested": {"a": 1}},
        )

    def events(self) -> list[dict[str, object]]:
        return [json.loads(line) for line in self.path.read_text(encoding="ascii").splitlines()]

    def write_events(self, events: list[dict[str, object]]) -> None:
        self.path.write_text("".join(canonical_json(event) + "\n" for event in events), encoding="ascii")

    def test_deterministic_canonical_hash_and_verified_summary(self) -> None:
        event = self.append("unit-1")
        envelope = {key: value for key, value in event.items() if key != "event_sha256"}
        expected = hashlib.sha256(canonical_json(envelope).encode("ascii")).hexdigest()

        self.assertEqual(event["schema"], EVIDENCE_LOG_SCHEMA)
        self.assertEqual(event["created_at_utc"], "2026-07-11T01:02:03.000000Z")
        self.assertEqual(event["previous_event_sha256"], GENESIS_EVENT_SHA256)
        self.assertEqual(event["event_sha256"], expected)
        self.assertEqual(self.path.read_text(encoding="ascii"), canonical_json(event) + "\n")
        self.assertEqual(
            verify_event_log(self.path, log_id=LOG_ID, expected_head_sha256=expected, expected_event_count=1),
            {
                "event_count": 1,
                "head_event_sha256": expected,
                "head_created_at_utc": "2026-07-11T01:02:03.000000Z",
            },
        )

    def test_mutation_and_malformed_or_blank_lines_fail_closed(self) -> None:
        original = self.append("unit-1")
        mutated = self.events()
        mutated[0]["payload"]["unit"] = "tampered"
        self.write_events(mutated)
        with self.assertRaisesRegex(ValueError, "event_sha256"):
            verify_event_log(self.path, log_id=LOG_ID)

        self.path.write_text(canonical_json(original) + "\n\n", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "blank lines"):
            verify_event_log(self.path, log_id=LOG_ID)

        self.path.write_text("not-json\n", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "malformed JSON"):
            verify_event_log(self.path, log_id=LOG_ID)

    def test_reordered_or_gapped_sequences_fail_closed(self) -> None:
        self.append("unit-1")
        self.append("unit-2")
        events = self.events()
        self.write_events(list(reversed(events)))
        with self.assertRaisesRegex(ValueError, "sequence"):
            verify_event_log(self.path, log_id=LOG_ID)

        self.write_events(events)
        events[1]["sequence"] = 3
        self.write_events(events)
        with self.assertRaisesRegex(ValueError, "sequence"):
            verify_event_log(self.path, log_id=LOG_ID)

    def test_duplicate_ids_and_wrong_log_id_fail_closed(self) -> None:
        original = self.append("unit-1")
        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            self.append("unit-1")

        duplicate = dict(original)
        duplicate["sequence"] = 1
        duplicate["previous_event_sha256"] = original["event_sha256"]
        duplicate["event_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in duplicate.items() if key != "event_sha256"}).encode("ascii")
        ).hexdigest()
        self.write_events([original, duplicate])
        with self.assertRaisesRegex(ValueError, "duplicate event_id"):
            verify_event_log(self.path, log_id=LOG_ID)

        with self.assertRaisesRegex(ValueError, "log_id"):
            verify_event_log(self.path, log_id="different-log")
        with self.assertRaisesRegex(ValueError, "log_id"):
            append_event(
                self.path,
                log_id="different-log",
                event_id="unit-2",
                event_type="registered",
                created_at_utc="2026-07-11T01:02:04Z",
                payload={},
            )

    def test_stale_expected_head_and_count_are_rejected(self) -> None:
        first = self.append("unit-1")
        self.append("unit-2")
        with self.assertRaisesRegex(ValueError, "head hash"):
            append_event(
                self.path,
                log_id=LOG_ID,
                event_id="unit-3",
                event_type="registered",
                created_at_utc="2026-07-11T01:02:05Z",
                payload={},
                expected_head_sha256=first["event_sha256"],
            )
        with self.assertRaisesRegex(ValueError, "event count"):
            verify_event_log(self.path, log_id=LOG_ID, expected_event_count=1)
        with self.assertRaisesRegex(ValueError, "head hash"):
            verify_event_log(self.path, log_id=LOG_ID, expected_head_sha256=None)

    def test_backdated_append_and_validly_rehashed_backdating_fail(self) -> None:
        first = self.append("unit-1", created_at_utc="2026-07-11T01:02:03Z")
        with self.assertRaisesRegex(ValueError, "moves backward"):
            self.append("unit-2", created_at_utc="2026-07-11T01:02:02Z")

        second = dict(first)
        second["sequence"] = 1
        second["event_id"] = "unit-2"
        second["created_at_utc"] = "2026-07-11T01:02:02.000000Z"
        second["previous_event_sha256"] = first["event_sha256"]
        second["event_sha256"] = hashlib.sha256(
            canonical_json({key: value for key, value in second.items() if key != "event_sha256"}).encode("ascii")
        ).hexdigest()
        self.write_events([first, second])
        with self.assertRaisesRegex(ValueError, "moves backward"):
            verify_event_log(self.path, log_id=LOG_ID)

    def test_threaded_appends_are_contiguous_and_lossless(self) -> None:
        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def append_in_thread(index: int) -> None:
            try:
                barrier.wait()
                self.append(f"unit-{index}", created_at_utc="2026-07-11T01:02:59Z")
            except BaseException as exc:  # Report worker failures to the test thread.
                errors.append(exc)

        threads = [threading.Thread(target=append_in_thread, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        summary = verify_event_log(self.path, log_id=LOG_ID, expected_event_count=8)
        self.assertEqual(summary["event_count"], 8)
        self.assertEqual({event["event_id"] for event in self.events()}, {f"unit-{index}" for index in range(8)})

    def test_process_appends_are_contiguous_and_lossless(self) -> None:
        arguments = [
            (str(self.path), f"process-{index}", "2026-07-11T01:03:59Z")
            for index in range(4)
        ]
        with multiprocessing.get_context("spawn").Pool(processes=4) as pool:
            sequences = pool.map(_append_from_process, arguments)

        self.assertEqual(set(sequences), set(range(4)))
        self.assertEqual(verify_event_log(self.path, log_id=LOG_ID)["event_count"], 4)


if __name__ == "__main__":
    unittest.main()
