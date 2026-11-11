from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from evaluation_v2.catalog_semantics import (
    CardCatalog,
    SUPPORT_FAMILIES,
    actor_visible_representation,
    support_family,
)


CATALOG_PATH = Path(__file__).parents[1] / "data" / "EN_Card_Data.csv"


def _observation() -> dict:
    # This mirrors the real native State/PlayerState/Pokemon observation shape.
    return {
        "current": {
            "turn": 6,
            "turnActionCount": 2,
            "yourIndex": 0,
            "firstPlayer": 0,
            "energyAttached": True,
            "supporterPlayed": False,
            "stadiumPlayed": True,
            "retreated": False,
            "stadium": [],
            "players": [
                {
                    "prize": [None, None, None],
                    "deckCount": 40,
                    "handCount": 3,
                    "hand": [{"id": 31}, {"id": 1188}, {"id": 1}],
                    "active": [{"id": 24, "hp": 115, "maxHp": 230, "energyCards": [{"id": 1}]}],
                    "bench": [{"id": 72, "hp": 65, "maxHp": 130, "energyCards": [{"id": 1}, {"id": 2}]}],
                    "discard": [{"id": 1}],
                    "poisoned": False,
                    "burned": False,
                    "asleep": False,
                    "paralyzed": False,
                    "confused": False,
                },
                {
                    "prize": [None, None, None, None],
                    "deckCount": 41,
                    "handCount": 5,
                    "hand": None,
                    "active": [{"id": 31, "hp": 55, "maxHp": 110, "energyCards": []}],
                    "bench": [],
                    "discard": [],
                    "poisoned": True,
                    "burned": False,
                    "asleep": False,
                    "paralyzed": False,
                    "confused": False,
                },
            ],
        }
    }


class CatalogSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = CardCatalog.load(CATALOG_PATH)

    def test_catalog_merges_duplicate_move_rows_and_roundtrips(self) -> None:
        # ID 123 has both an Ability and attack row in the source CSV.
        self.assertEqual(self.catalog.cards[123].supertype, "pokemon")
        self.assertEqual(self.catalog.cards[123].pokemon_stage, "BASIC")
        self.assertEqual(self.catalog.cards[24].active_class, "POKEMON_RULEBOX")
        self.assertEqual(self.catalog.cards[31].types, frozenset({"R"}))
        self.assertEqual(self.catalog.matchup_relation(31, 72), "WEAK")
        attacker_id, resistant_id = next(
            (attacker_id, defender_id)
            for attacker_id, attacker in self.catalog.cards.items()
            for defender_id, defender in self.catalog.cards.items()
            if attacker.supertype == "pokemon"
            and defender.supertype == "pokemon"
            and attacker.types & defender.resistances
            and not attacker.types & defender.weaknesses
        )
        self.assertEqual(self.catalog.matchup_relation(attacker_id, resistant_id), "RESIST")
        self.assertEqual(CardCatalog.from_dict(self.catalog.to_dict()).to_dict(), self.catalog.to_dict())
        self.assertEqual(CardCatalog.from_dict(self.catalog.to_dict()).canonical_hash, self.catalog.sha256)

    def test_catalog_rejects_conflicting_duplicate_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cards.csv"
            path.write_text(
                "Card ID,Card Name,Expansion,Collection No.,Stage (Pokémon)/Type (Energy and Trainer),Rule,Category,Previous stage,HP,Type,Weakness,Resistance (Type),Retreat\n"
                "1,A,S,1,Basic Pokémon,n/a,n/a,n/a,60,{G},{R},n/a,1\n"
                "1,A,S,1,Basic Pokémon,n/a,n/a,n/a,70,{G},{R},n/a,1\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "conflicting invariant"):
                CardCatalog.load(path)

    def test_support_family_maps_only_resolved_supported_actions(self) -> None:
        item_id = next(card_id for card_id, card in self.catalog.cards.items() if card.supertype == "item")
        stadium_id = next(card_id for card_id, card in self.catalog.cards.items() if card.supertype == "stadium")
        self.assertEqual(support_family({"option": {"type": 7}, "resolved": {"cardId": 31}}, self.catalog), "PLAY_POKEMON_BASIC")
        self.assertEqual(support_family({"type": 9, "cardId": 72}, self.catalog), "PLAY_POKEMON_EVOLUTION")
        self.assertEqual(support_family({"type": 7, "cardId": item_id}, self.catalog), "PLAY_ITEM")
        self.assertEqual(support_family({"type": 7, "cardId": 1188}, self.catalog), "PLAY_SUPPORTER")
        self.assertEqual(support_family({"type": 7, "cardId": stadium_id}, self.catalog), "PLAY_STADIUM")
        self.assertEqual(support_family({"type": 8, "energyId": 1, "targetArea": 4}, self.catalog), "ATTACH_ACTIVE")
        self.assertEqual(support_family({"type": 8, "energyId": 1, "targetArea": 5}, self.catalog), "ATTACH_BENCH")
        self.assertEqual(support_family({"type": 10, "sourceCardId": 31}, self.catalog), "ABILITY")
        self.assertEqual(support_family({"type": 12}, self.catalog), "RETREAT")
        self.assertEqual(support_family({"type": 13}, self.catalog), "ATTACK")
        self.assertEqual(support_family({"type": 14}, self.catalog), "END")
        self.assertIsNone(support_family({"type": 8, "energyId": 1, "targetArea": 6}, self.catalog))
        self.assertIsNone(support_family({"type": 7, "cardId": 1}, self.catalog))
        self.assertIsNone(support_family({"type": 7, "cardId": 999999}, self.catalog))
        self.assertIsNone(support_family({"type": 7, "cardId": 31, "selection": [{}, {}]}, self.catalog))

    def test_representation_is_visible_id_free_and_uses_own_hand_ontology(self) -> None:
        observation = _observation()
        baseline = actor_visible_representation(observation, ["ATTACK", "ATTACK", "END"], self.catalog)
        changed_hidden = copy.deepcopy(observation)
        changed_hidden["current"]["players"][1]["hand"] = [{"id": 1188}, {"id": 123}]
        changed_hidden["current"]["players"][1]["prize"] = [{"id": 24}, {"id": 72}, None, None]
        with self.assertRaisesRegex(ValueError, "hidden"):
            actor_visible_representation(changed_hidden, ["ATTACK", "ATTACK", "END"], self.catalog)

        changed_own_hand = copy.deepcopy(observation)
        changed_own_hand["current"]["players"][0]["hand"] = [{"id": 31}, {"id": 72}, {"id": 1}]
        own_changed = actor_visible_representation(changed_own_hand, ["ATTACK", "ATTACK", "END"], self.catalog)
        self.assertNotEqual(own_changed["categorical"]["own_hand_stage_counts"], baseline["categorical"]["own_hand_stage_counts"])
        self.assertEqual(baseline["numeric"]["legal_attack_available"], 1)
        self.assertEqual(baseline["numeric"]["legal_attack_count"], 2)
        self.assertTrue(all(f"legal_{family.lower()}_count" in baseline["numeric"] for family in SUPPORT_FAMILIES))

        encoded = repr(baseline)
        for card_id in (24, 31, 72, 1188):
            self.assertNotIn(str(card_id), encoded)


if __name__ == "__main__":
    unittest.main()
