from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from evaluation_v3.episode_inventory import build_episode_inventory, canonical_json, write_episode_inventory


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_postretirement_episode_inventory",
    ROOT / "tools" / "build_postretirement_episode_inventory.py",
)
assert SPEC and SPEC.loader
inventory_tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory_tool
SPEC.loader.exec_module(inventory_tool)


HEADER = "id,createTime,endTime,state,type\n"
COMPLETED_PUBLIC = "EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC"


def episode_row(
    episode_id: str,
    created: str,
    ended: str = "2026-07-10 12:10:00.000000",
    state_and_type: str = COMPLETED_PUBLIC,
) -> str:
    return f"{episode_id},{created},{ended},{state_and_type}\n"


class PostretirementEpisodeInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.scout = self.root / "scout"
        self.scout.mkdir()
        self.leaderboard = self.root / "leaderboard.csv"
        self.leaderboard.write_text("TeamId,TeamName,Score\n1,alpha,1000\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_episodes(self, relative_path: str, body: str) -> Path:
        path = self.scout / relative_path / "episodes.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(HEADER + body, encoding="utf-8")
        return path

    def build(self) -> dict[str, object]:
        return build_episode_inventory(
            source_root=self.scout,
            strict_utc_cutoff="2026-07-10T12:00:00Z",
            source_leaderboard=self.leaderboard,
            collection_timestamp_utc="2026-07-11T01:02:03+00:00",
        )

    def test_strict_boundary_filters_only_completed_public_rows(self) -> None:
        self.write_episodes(
            "team/submission_7",
            episode_row("100", "2026-07-10 12:00:00.000000")
            + episode_row("101", "2026-07-10T12:00:00.000001Z")
            + episode_row("102", "2026-07-10 12:02:00.000000", state_and_type="EpisodeState.PENDING,EpisodeType.EPISODE_TYPE_PUBLIC")
            + episode_row("103", "2026-07-10 12:03:00.000000", state_and_type="EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_VALIDATION"),
        )

        inventory = self.build()

        episodes = inventory["episodes"]
        self.assertEqual([row["episode_id"] for row in episodes], ["101"])
        self.assertEqual(episodes[0]["create_time_utc"], "2026-07-10T12:00:00.000001Z")
        self.assertEqual(episodes[0]["sources"][0]["submission_id"], "7")
        self.assertEqual(inventory["collection_timestamp_utc"], "2026-07-11T01:02:03.000000Z")

    def test_duplicate_provenance_is_retained_and_conflicts_fail_closed(self) -> None:
        first = self.write_episodes("b/submission_9", episode_row("200", "2026-07-10 12:02:00.000000"))
        second = self.write_episodes("a/submission_8", episode_row("200", "2026-07-10T12:02:00Z"))

        inventory = self.build()

        row = inventory["episodes"][0]
        self.assertEqual([source["source_path"] for source in row["sources"]], ["a/submission_8/episodes.csv", "b/submission_9/episodes.csv"])
        self.assertEqual(row["sources"][1]["source_file_sha256"], hashlib.sha256(first.read_bytes()).hexdigest())
        self.assertEqual(row["sources"][0]["source_file_sha256"], hashlib.sha256(second.read_bytes()).hexdigest())

        self.write_episodes("conflict/submission_7", episode_row("200", "2026-07-10 12:03:00.000000"))
        with self.assertRaisesRegex(ValueError, "conflicting metadata for episode id 200"):
            self.build()

    def test_canonical_order_and_content_hash_are_deterministic(self) -> None:
        self.write_episodes(
            "z/submission_1",
            episode_row("9", "2026-07-10 12:04:00.000000") + episode_row("20", "2026-07-10 12:02:00.000000"),
        )
        self.write_episodes("a/submission_2", episode_row("10", "2026-07-10 12:02:00.000000"))

        first = self.build()
        second = self.build()

        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertEqual(first["content_sha256"], second["content_sha256"])
        self.assertEqual([row["episode_id"] for row in first["episodes"]], ["10", "20", "9"])
        without_hash = dict(first)
        content_hash = without_hash.pop("content_sha256")
        self.assertEqual(content_hash, hashlib.sha256(canonical_json(without_hash).encode("ascii")).hexdigest())
        self.assertEqual(first["leaderboard"]["sha256"], hashlib.sha256(self.leaderboard.read_bytes()).hexdigest())

    def test_malformed_schema_times_and_cli_timestamp_are_rejected(self) -> None:
        invalid = self.scout / "bad" / "episodes.csv"
        invalid.parent.mkdir(parents=True)
        invalid.write_text("id,createTime,state,type\n1,2026-07-10 12:01:00,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing columns: endTime"):
            self.build()

        invalid.write_text(HEADER + episode_row("1", "not-a-time"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid .*createTime"):
            self.build()

        invalid.write_text(HEADER + episode_row("1", "2026-07-10 12:01:00.000000"), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "strict UTC cutoff must include a UTC offset"):
            build_episode_inventory(
                source_root=self.scout,
                strict_utc_cutoff="2026-07-10 12:00:00",
                source_leaderboard=self.leaderboard,
                collection_timestamp_utc="2026-07-11T01:02:03Z",
            )

    def test_collection_chronology_and_completed_end_time_are_enforced(self) -> None:
        self.write_episodes(
            "team/submission_5",
            episode_row(
                "500",
                "2026-07-10 12:05:00.000000",
                ended="2026-07-10 12:04:59.999999",
            ),
        )
        with self.assertRaisesRegex(ValueError, "endTime precedes createTime"):
            self.build()

        self.write_episodes(
            "team/submission_5",
            episode_row("500", "2026-07-10 12:05:00.000000", ended=""),
        )
        with self.assertRaisesRegex(ValueError, "completed public episode 500 requires endTime"):
            self.build()

        self.write_episodes(
            "team/submission_5",
            episode_row("500", "2026-07-10 12:05:00.000000", ended="2026-07-10 12:06:00.000000"),
        )
        with self.assertRaisesRegex(ValueError, "episode 500 ended after the collection timestamp"):
            build_episode_inventory(
                source_root=self.scout,
                strict_utc_cutoff="2026-07-10T12:00:00Z",
                source_leaderboard=self.leaderboard,
                collection_timestamp_utc="2026-07-10T12:05:30Z",
            )

        with self.assertRaisesRegex(ValueError, "collection timestamp precedes strict UTC cutoff"):
            build_episode_inventory(
                source_root=self.scout,
                strict_utc_cutoff="2026-07-10T12:00:00Z",
                source_leaderboard=self.leaderboard,
                collection_timestamp_utc="2026-07-10T11:59:59Z",
            )

    def test_source_root_requires_at_least_one_episode_csv(self) -> None:
        with self.assertRaisesRegex(ValueError, "contains no episodes.csv files"):
            self.build()

    def test_no_qualifying_games_and_append_only_write(self) -> None:
        self.write_episodes("team/submission_3", episode_row("300", "2026-07-10 11:59:59.000000"))
        inventory = self.build()
        self.assertEqual(inventory["episodes"], [])

        output = self.root / "inventory.json"
        write_episode_inventory(output, inventory)
        self.assertEqual(json.loads(output.read_text(encoding="ascii")), inventory)
        with self.assertRaises(FileExistsError):
            write_episode_inventory(output, inventory)

    def test_cli_requires_explicit_inputs_and_writes_inventory(self) -> None:
        self.write_episodes("team/submission_4", episode_row("400", "2026-07-10 12:05:00.000000"))
        output = self.root / "cli-inventory.json"
        argv = [
            "build_postretirement_episode_inventory.py",
            "--source-root", str(self.scout),
            "--strict-utc-cutoff", "2026-07-10T12:00:00Z",
            "--source-leaderboard", str(self.leaderboard),
            "--collection-timestamp-utc", "2026-07-11T01:02:03Z",
            "--output", str(output),
        ]
        with patch.object(sys, "argv", argv):
            self.assertEqual(inventory_tool.main(), 0)
        self.assertEqual(json.loads(output.read_text(encoding="ascii"))["episodes"][0]["episode_id"], "400")


if __name__ == "__main__":
    unittest.main()
