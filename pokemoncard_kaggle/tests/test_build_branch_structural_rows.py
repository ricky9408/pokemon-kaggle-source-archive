from __future__ import annotations

import copy
from pathlib import Path
import unittest

from evaluation_v2.catalog_semantics import CardCatalog
from tools.build_branch_structural_rows import (
    _assert_outcome_free,
    freeze_root_schedule,
    native_root_capsule,
    sanitize_current,
    structural_row,
)


CATALOG_PATH = Path(__file__).parents[1] / "data" / "EN_Card_Data.csv"


def _observation() -> dict:
    return {
        "search_begin_input": "frozen-native-root",
        "current": {
            "turn": 4,
            "turnActionCount": 1,
            "yourIndex": 0,
            "firstPlayer": 1,
            "energyAttached": False,
            "supporterPlayed": False,
            "stadiumPlayed": False,
            "retreated": False,
            "looking": 0,
            "result": -1,
            "stadium": [{"id": 1259, "playerIndex": 0, "serial": 80}],
            "players": [
                {
                    "prize": [None, None, None, None],
                    "deckCount": 42,
                    "handCount": 3,
                    "hand": [{"id": 1188}, {"id": 1188}, {"id": 1}],
                    "active": [{"id": 31, "hp": 110, "maxHp": 110, "energyCards": []}],
                    "bench": [{"id": 31, "hp": 110, "maxHp": 110, "energyCards": []}],
                    "discard": [],
                    "benchMax": 5,
                    "asleep": False,
                    "burned": False,
                    "confused": False,
                    "paralyzed": False,
                    "poisoned": False,
                },
                {
                    "prize": [None, None, None],
                    "deckCount": 43,
                    "handCount": 5,
                    "hand": None,
                    "active": [{"id": 31, "hp": 55, "maxHp": 110, "energyCards": []}],
                    "bench": [],
                    "discard": [],
                    "benchMax": 5,
                    "asleep": False,
                    "burned": False,
                    "confused": False,
                    "paralyzed": False,
                    "poisoned": False,
                },
            ],
        },
        "select": {
            "context": 0,
            "minCount": 1,
            "maxCount": 1,
            "option": [
                {"type": 7, "playerIndex": 0, "area": 2, "index": 0},
                {"type": 7, "playerIndex": 0, "area": 2, "index": 1},
                {
                    "type": 8,
                    "playerIndex": 0,
                    "area": 2,
                    "index": 2,
                    "inPlayArea": 4,
                    "inPlayIndex": 0,
                },
                {"type": 13, "attackId": 99},
                {"type": 10, "area": 7, "index": 0},
                {"type": 14},
            ],
            "contextCard": 0,
            "deck": [],
            "effect": 0,
            "remainDamageCounter": 0,
            "remainEnergyCost": 0,
            "type": 0,
        },
    }


def _record() -> dict:
    return {
        "episode_id": "episode-1",
        "target_slot": 0,
        "target_team": "pilot-a",
        "replay_sha256": "a" * 64,
        "module_version": "1.32.0",
        "submission_id": "submission-a",
        "target_deck_sha256": "b" * 64,
    }


class StructuralRowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = CardCatalog.load(CATALOG_PATH)

    def test_sanitize_current_removes_hidden_card_identity(self) -> None:
        observation = _observation()
        observation["current"]["players"][0]["prize"][0] = {"id": 24}
        observation["current"]["players"][1]["prize"][0] = {"id": 72}
        cleaned = sanitize_current(observation)
        self.assertEqual(cleaned["players"][0]["prize"], [None] * 4)
        self.assertEqual(cleaned["players"][1]["prize"], [None] * 3)
        self.assertIsNone(cleaned["players"][1]["hand"])
        self.assertEqual(cleaned["players"][1]["handCount"], 5)
        self.assertEqual(cleaned["players"][0]["hand"][0]["id"], 1188)

    def test_structural_row_is_outcome_free_and_resolves_actions(self) -> None:
        source = {
            "cohort_role": "development",
            "context": "MAIN",
            "episode_id": "episode-1",
            "player_index": 0,
            "step_index": 7,
            "action": [2],
            "observation": _observation(),
        }
        value = structural_row(source, _record(), self.catalog)
        self.assertIsNotNone(value)
        assert value is not None
        self.assertEqual(value["selected_family"], "ATTACH_ACTIVE")
        self.assertEqual(value["selected_action"]["payload"]["energy_id"], 1)
        self.assertEqual(value["selected_action"]["payload"]["target_card_id"], 31)
        self.assertEqual(value["representation"]["numeric"]["legal_play_supporter_count"], 2)
        self.assertEqual(value["representation"]["numeric"]["legal_attach_active_count"], 1)
        self.assertEqual(value["representation"]["numeric"]["legal_ability_count"], 1)
        self.assertTrue(value["semantic_collision"])
        self.assertNotIn("search_begin_input", repr(value))
        self.assertNotIn("reward", repr(value))

    def test_hidden_opponent_cards_cannot_change_representation(self) -> None:
        source = {
            "cohort_role": "development",
            "context": "MAIN",
            "episode_id": "episode-1",
            "player_index": 0,
            "step_index": 7,
            "action": [0],
            "observation": _observation(),
        }
        baseline = structural_row(source, _record(), self.catalog)
        changed = copy.deepcopy(source)
        changed["observation"]["current"]["players"][1]["hand"] = [
            {"id": 1188},
            {"id": 123},
        ]
        changed["observation"]["current"]["players"][1]["prize"] = [
            {"id": 24},
            {"id": 72},
            {"id": 123},
        ]
        observed = structural_row(changed, _record(), self.catalog)
        assert baseline is not None and observed is not None
        self.assertEqual(observed["representation"], baseline["representation"])
        self.assertEqual(observed["observation"], baseline["observation"])

    def test_outcome_fields_fail_closed_at_any_depth(self) -> None:
        with self.assertRaisesRegex(ValueError, "forbidden outcome/future field"):
            _assert_outcome_free({"safe": [{"outcome": 1}]})

    def test_root_schedule_keeps_missing_slots_in_denominator(self) -> None:
        rows = [
            {
                "side_id": "side-a",
                "native_root_id": f"root-{index}",
                "root_priority_sha256": f"{index:064x}",
                "step_index": index,
                "scheduled_root": False,
            }
            for index in range(2)
        ]
        schedule, scheduled = freeze_root_schedule(rows)
        self.assertEqual(len(schedule), 4)
        self.assertEqual(len(scheduled), 2)
        self.assertEqual([row["status"] for row in schedule], ["scheduled", "scheduled", "missing_eligible_root", "missing_eligible_root"])

    def test_native_capsule_retains_replay_root_but_not_hidden_cards(self) -> None:
        source = {
            "cohort_role": "development",
            "context": "MAIN",
            "episode_id": "episode-1",
            "player_index": 0,
            "step_index": 7,
            "action": [5],
            "observation": _observation(),
        }
        value = structural_row(source, _record(), self.catalog)
        assert value is not None
        capsule = native_root_capsule(source, _record(), value["native_root_id"])
        self.assertEqual(capsule["recorded_selection"], [5])
        self.assertEqual(capsule["observation"]["search_begin_input"], "frozen-native-root")
        self.assertIsNone(capsule["observation"]["current"]["players"][1]["hand"])
        self.assertEqual(capsule["observation"]["current"]["result"], -1)


if __name__ == "__main__":
    unittest.main()
