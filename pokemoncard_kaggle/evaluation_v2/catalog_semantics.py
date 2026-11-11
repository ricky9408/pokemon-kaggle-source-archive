"""Frozen card ontology and actor-visible branch-bridge-v2 semantics.

The module intentionally depends only on the standard library.  It translates
the public card CSV into a compact, canonical ontology and never exposes card
identities in state representations.
"""

from __future__ import annotations

import csv
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any


SUPPORT_FAMILIES = (
    "PLAY_POKEMON_BASIC",
    "PLAY_POKEMON_EVOLUTION",
    "PLAY_ITEM",
    "PLAY_SUPPORTER",
    "PLAY_STADIUM",
    "ABILITY",
    "ATTACH_ACTIVE",
    "ATTACH_BENCH",
    "RETREAT",
    "ATTACK",
    "END",
)

ACTIVE_CLASSES = (
    "EMPTY",
    "NON_POKEMON",
    "POKEMON_RULEBOX",
    "POKEMON_BASIC",
    "POKEMON_EVOLUTION",
)
SUPERTYPES = (
    "pokemon",
    "basic_energy",
    "special_energy",
    "item",
    "supporter",
    "stadium",
    "tool",
    "other",
)
POKEMON_STAGES = ("BASIC", "EVOLUTION")
MATCHUP_RELATIONS = ("WEAK", "RESIST", "NEUTRAL", "NA")

_BRACE_TOKEN = re.compile(r"\{([^{}]+)\}")
_INVARIANT_COLUMNS = (
    "Card Name",
    "Expansion",
    "Collection No.",
    "Stage (Pokémon)/Type (Energy and Trainer)",
    "Rule",
    "Category",
    "Previous stage",
    "HP",
    "Type",
    "Weakness",
    "Resistance (Type)",
    "Retreat",
)
_ACTION_TYPES = {7, 8, 9, 10, 12, 13, 14}


@dataclass(frozen=True)
class CardMetadata:
    """The card-level fields that are invariant across CSV move rows."""

    card_id: int
    supertype: str
    pokemon_stage: str | None
    rulebox: bool
    hp: int | None
    retreat: int | None
    types: frozenset[str]
    weaknesses: frozenset[str]
    resistances: frozenset[str]

    @property
    def active_class(self) -> str:
        if self.supertype != "pokemon":
            return "NON_POKEMON"
        if self.rulebox:
            return "POKEMON_RULEBOX"
        if self.pokemon_stage == "BASIC":
            return "POKEMON_BASIC"
        return "POKEMON_EVOLUTION"

    def to_dict(self) -> dict[str, Any]:
        return {
            "card_id": self.card_id,
            "supertype": self.supertype,
            "pokemon_stage": self.pokemon_stage,
            "rulebox": self.rulebox,
            "hp": self.hp,
            "retreat": self.retreat,
            "types": sorted(self.types),
            "weaknesses": sorted(self.weaknesses),
            "resistances": sorted(self.resistances),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CardMetadata":
        card_id = _int(payload.get("card_id"), "card_id")
        supertype = payload.get("supertype")
        stage = payload.get("pokemon_stage")
        rulebox = payload.get("rulebox")
        if supertype not in SUPERTYPES:
            raise ValueError("invalid card supertype")
        if stage not in {*POKEMON_STAGES, None}:
            raise ValueError("invalid pokemon stage")
        if not isinstance(rulebox, bool):
            raise ValueError("rulebox must be a bool")
        if supertype == "pokemon" and stage not in POKEMON_STAGES:
            raise ValueError("pokemon cards require a stage")
        if supertype != "pokemon" and stage is not None:
            raise ValueError("only pokemon cards may have a stage")
        return cls(
            card_id=card_id,
            supertype=supertype,
            pokemon_stage=stage,
            rulebox=rulebox,
            hp=_optional_int(payload.get("hp"), "hp"),
            retreat=_optional_int(payload.get("retreat"), "retreat"),
            types=_token_set(payload.get("types")),
            weaknesses=_token_set(payload.get("weaknesses")),
            resistances=_token_set(payload.get("resistances")),
        )


@dataclass(frozen=True)
class CardCatalog:
    """A validated, deterministic card ontology keyed by Card ID."""

    cards: Mapping[int, CardMetadata]

    def __post_init__(self) -> None:
        normalized: dict[int, CardMetadata] = {}
        for raw_id, metadata in self.cards.items():
            card_id = _int(raw_id, "catalog card id")
            if not isinstance(metadata, CardMetadata) or metadata.card_id != card_id:
                raise ValueError("catalog cards must be matching CardMetadata values")
            normalized[card_id] = metadata
        object.__setattr__(self, "cards", MappingProxyType(dict(sorted(normalized.items()))))

    @classmethod
    def load(cls, path: str | Path) -> "CardCatalog":
        """Load ``EN_Card_Data.csv``, merging duplicate move rows safely."""

        grouped: dict[int, tuple[tuple[str, ...], CardMetadata]] = {}
        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"Card ID", *_INVARIANT_COLUMNS}
            if reader.fieldnames is None or not required.issubset(reader.fieldnames):
                raise ValueError("card catalog has missing required columns")
            for line_number, row in enumerate(reader, start=2):
                try:
                    card_id = _csv_int(row.get("Card ID"), "Card ID")
                    invariant = tuple(_normalized_cell(row.get(column)) for column in _INVARIANT_COLUMNS)
                    metadata = _metadata_from_row(card_id, row)
                except (TypeError, ValueError) as error:
                    raise ValueError(f"invalid catalog row {line_number}: {error}") from error
                previous = grouped.get(card_id)
                if previous is None:
                    grouped[card_id] = (invariant, metadata)
                elif previous != (invariant, metadata):
                    raise ValueError(f"conflicting invariant rows for Card ID {card_id}")
        if not grouped:
            raise ValueError("card catalog is empty")
        return cls({card_id: item[1] for card_id, item in grouped.items()})

    def get(self, card_id: int | None) -> CardMetadata | None:
        return self.cards.get(card_id) if isinstance(card_id, int) and not isinstance(card_id, bool) else None

    def require(self, card_id: int) -> CardMetadata:
        metadata = self.get(card_id)
        if metadata is None:
            raise ValueError("visible card is absent from the frozen catalog")
        return metadata

    def matchup_relation(self, attacker: int | CardMetadata | None, defender: int | CardMetadata | None) -> str:
        return matchup_relation(_metadata(self, attacker), _metadata(self, defender))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "evaluation_v2_card_catalog_v1",
            "cards": [metadata.to_dict() for _, metadata in sorted(self.cards.items())],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CardCatalog":
        if payload.get("schema") not in {None, "evaluation_v2_card_catalog_v1"}:
            raise ValueError("unsupported card catalog schema")
        rows = payload.get("cards")
        if not _sequence(rows):
            raise ValueError("catalog cards must be a sequence")
        cards: dict[int, CardMetadata] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("catalog card payload must be a mapping")
            metadata = CardMetadata.from_dict(row)
            if metadata.card_id in cards:
                raise ValueError("duplicate card id in catalog payload")
            cards[metadata.card_id] = metadata
        return cls(cards)

    @property
    def canonical_hash(self) -> str:
        return sha256(_canonical_json(self.to_dict()).encode("ascii")).hexdigest()

    @property
    def sha256(self) -> str:
        return self.canonical_hash


def matchup_relation(attacker: CardMetadata | None, defender: CardMetadata | None) -> str:
    """Classify the visible active matchup without considering card effects."""

    if attacker is None or defender is None:
        return "NA"
    if attacker.supertype != "pokemon" or defender.supertype != "pokemon" or not attacker.types:
        return "NA"
    if attacker.types & defender.weaknesses:
        return "WEAK"
    if attacker.types & defender.resistances:
        return "RESIST"
    return "NEUTRAL"


def support_family(action_payload: Mapping[str, Any] | Any, catalog: CardCatalog) -> str | None:
    """Map one fully resolved engine action to a fixed supported family.

    This is intentionally fail-closed.  It does not inspect names/effect text,
    and it refuses multi-selections or unresolved cards rather than guessing.
    """

    action = _single_resolved_action(action_payload)
    if action is None:
        return None
    action_type = action.get("type", action.get("actionType", action.get("action_type")))
    if action_type not in _ACTION_TYPES:
        return None
    if action_type == 7:
        card = catalog.get(_one_id(action, "cardId", "card_id", "card"))
        if card is None:
            return None
        if card.supertype == "pokemon" and card.pokemon_stage == "BASIC":
            return "PLAY_POKEMON_BASIC"
        if card.supertype == "item":
            return "PLAY_ITEM"
        if card.supertype == "supporter":
            return "PLAY_SUPPORTER"
        if card.supertype == "stadium":
            return "PLAY_STADIUM"
        return None
    if action_type == 9:
        card = catalog.get(_one_id(action, "cardId", "card_id", "card"))
        return "PLAY_POKEMON_EVOLUTION" if card and card.supertype == "pokemon" and card.pokemon_stage == "EVOLUTION" else None
    if action_type == 8:
        energy = catalog.get(_one_id(action, "energyId", "energy_id", "cardId", "card_id", "energy"))
        target = action.get("targetArea", action.get("target_area", action.get("inPlayArea")))
        if energy is None or energy.supertype not in {"basic_energy", "special_energy"}:
            return None
        if target == 4:
            return "ATTACH_ACTIVE"
        if target == 5:
            return "ATTACH_BENCH"
        return None
    if action_type == 10:
        source = catalog.get(_one_id(action, "sourceCardId", "source_card_id", "cardId", "card_id"))
        return "ABILITY" if source is not None else None
    if action_type == 12:
        return "RETREAT"
    if action_type == 13:
        return "ATTACK"
    return "END"


def actor_visible_representation(
    observation: Mapping[str, Any], legal_families: Sequence[str | None], catalog: CardCatalog
) -> dict[str, dict[str, Any]]:
    """Return a low-dimensional, ID-free representation of the actor-visible state."""

    _validate_actor_visible_observation(observation, catalog)
    current = _mapping(observation.get("current"))
    players = current.get("players")
    if not _sequence(players) or len(players) != 2 or not all(isinstance(player, Mapping) for player in players):
        raise ValueError("observation.current.players must contain two player mappings")
    actor = current.get("yourIndex")
    if actor not in (0, 1):
        raise ValueError("observation.current.yourIndex must be 0 or 1")
    own = players[actor]
    opp = players[1 - actor]
    own_active = _active(own)
    opp_active = _active(opp)
    own_meta = _visible_metadata(own_active, catalog)
    opp_meta = _visible_metadata(opp_active, catalog)

    numeric: dict[str, int | float] = {
        "turn": _nonnegative(current.get("turn", current.get("currentTurn", 0))),
        "turn_action_count": _nonnegative(current.get("turnActionCount", 0)),
        "own_prize_count": _zone_count(own, "prize"),
        "opp_prize_count": _zone_count(opp, "prize"),
        "own_hand_count": _hand_count(own),
        "opp_hand_count": _hand_count(opp),
        "own_deck_count": _count_field(own, "deckCount"),
        "opp_deck_count": _count_field(opp, "deckCount"),
        "own_bench_count": len(_cards(own.get("bench"))),
        "opp_bench_count": len(_cards(opp.get("bench"))),
        "own_discard_count": len(_cards(own.get("discard"))),
        "opp_discard_count": len(_cards(opp.get("discard"))),
        "own_active_hp_fraction": _hp_fraction(own_active, own_meta),
        "opp_active_hp_fraction": _hp_fraction(opp_active, opp_meta),
        "own_active_energy_count": _energy_count(own_active),
        "opp_active_energy_count": _energy_count(opp_active),
        "own_active_retreat": _retreat(own_meta),
        "opp_active_retreat": _retreat(opp_meta),
        "own_bench_hp_fraction": _bench_hp_fraction(own, catalog),
        "opp_bench_hp_fraction": _bench_hp_fraction(opp, catalog),
        "own_bench_energy_count": sum(_energy_count(card) for card in _cards(own.get("bench"))),
        "opp_bench_energy_count": sum(_energy_count(card) for card in _cards(opp.get("bench"))),
        "is_first_player": int(current.get("firstPlayer") == actor),
        "energy_attached": int(bool(current.get("energyAttached"))),
        "supporter_played": int(bool(current.get("supporterPlayed"))),
        "stadium_played": int(bool(current.get("stadiumPlayed"))),
        "retreated": int(bool(current.get("retreated") or own.get("retreated"))),
    }
    legal_counts = {family: 0 for family in SUPPORT_FAMILIES}
    if not _sequence(legal_families):
        raise ValueError("legal_families must be a sequence")
    for family in legal_families:
        if family in legal_counts:
            legal_counts[family] += 1
    for family, count in legal_counts.items():
        key = family.lower()
        numeric[f"legal_{key}_available"] = int(count > 0)
        numeric[f"legal_{key}_count"] = count

    categorical: dict[str, Any] = {
        "own_active_class": _active_class(own_active, own_meta),
        "opp_active_class": _active_class(opp_active, opp_meta),
        "own_active_type": _type_category(own_meta),
        "opp_active_type": _type_category(opp_meta),
        "own_active_stage": own_meta.pokemon_stage if own_meta else "NA",
        "opp_active_stage": opp_meta.pokemon_stage if opp_meta else "NA",
        "own_active_rulebox": _rulebox_category(own_meta),
        "opp_active_rulebox": _rulebox_category(opp_meta),
        "own_active_status": _status(own),
        "opp_active_status": _status(opp),
        "own_to_opp_matchup": matchup_relation(own_meta, opp_meta),
        "opp_to_own_matchup": matchup_relation(opp_meta, own_meta),
        "own_bench_ontology_counts": _bench_ontology_counts(own, catalog),
        "opp_bench_ontology_counts": _bench_ontology_counts(opp, catalog),
        "own_hand_supertype_counts": _hand_supertype_counts(own, catalog),
        "own_hand_stage_counts": _hand_stage_counts(own, catalog),
    }
    return {"numeric": numeric, "categorical": categorical}


def _validate_actor_visible_observation(observation: Mapping[str, Any], catalog: CardCatalog) -> None:
    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("observation.current must be a mapping")
    for key in ("turn", "turnActionCount"):
        value = current.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"observation.current.{key} must be a nonnegative integer")
    for key in ("yourIndex", "firstPlayer"):
        if current.get(key) not in (0, 1):
            raise ValueError(f"observation.current.{key} must be 0 or 1")
    for key in ("energyAttached", "supporterPlayed", "stadiumPlayed", "retreated"):
        if not isinstance(current.get(key), bool):
            raise ValueError(f"observation.current.{key} must be a bool")
    players = current.get("players")
    if not _sequence(players) or len(players) != 2 or not all(isinstance(player, Mapping) for player in players):
        raise ValueError("observation.current.players must contain two player mappings")
    actor = int(current["yourIndex"])
    for player_index, player in enumerate(players):
        for key in ("deckCount", "handCount"):
            value = player.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"player.{key} must be a nonnegative integer")
        for key in ("prize", "active", "bench", "discard"):
            if not _sequence(player.get(key)):
                raise ValueError(f"player.{key} must be a sequence")
        if any(value is not None for value in player["prize"]):
            raise ValueError("structural prize identities must be hidden")
        hand = player.get("hand")
        if player_index == actor:
            if not _sequence(hand):
                raise ValueError("actor hand must be visible")
        elif hand is not None:
            raise ValueError("opponent hand identity must be hidden")
        for key in ("asleep", "burned", "confused", "paralyzed", "poisoned"):
            if not isinstance(player.get(key), bool):
                raise ValueError(f"player.{key} must be a bool")
        visible_zones = [player["active"], player["bench"], player["discard"]]
        if player_index == actor:
            visible_zones.append(hand)
        for zone in visible_zones:
            for card in zone:
                if not isinstance(card, Mapping):
                    raise ValueError("visible card entries must be mappings")
                card_id = card.get("id")
                if not isinstance(card_id, int) or isinstance(card_id, bool):
                    raise ValueError("visible cards require integer ids")
                catalog.require(card_id)
        for card in (*player["active"], *player["bench"]):
            for key in ("hp", "maxHp"):
                value = card.get(key)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"in-play card {key} must be a nonnegative integer")
            if card["maxHp"] <= 0 or card["hp"] > card["maxHp"]:
                raise ValueError("in-play card HP is malformed")
            energies = card.get("energyCards")
            if not _sequence(energies) or not all(isinstance(energy, Mapping) for energy in energies):
                raise ValueError("in-play energyCards must be a sequence of mappings")
            for energy in energies:
                energy_id = energy.get("id")
                if not isinstance(energy_id, int) or isinstance(energy_id, bool):
                    raise ValueError("attached energy requires an integer id")
                catalog.require(energy_id)


def _metadata_from_row(card_id: int, row: Mapping[str, str | None]) -> CardMetadata:
    kind = _normalized_cell(row.get("Stage (Pokémon)/Type (Energy and Trainer)"))
    supertype, stage = _kind(kind)
    return CardMetadata(
        card_id=card_id,
        supertype=supertype,
        pokemon_stage=stage,
        rulebox=_rulebox(row.get("Rule")),
        hp=_csv_optional_int(row.get("HP"), "HP"),
        retreat=_csv_optional_int(row.get("Retreat"), "Retreat"),
        types=_brace_tokens(row.get("Type")),
        weaknesses=_brace_tokens(row.get("Weakness")),
        resistances=_brace_tokens(row.get("Resistance (Type)")),
    )


def _kind(value: str) -> tuple[str, str | None]:
    if value == "Basic Pokémon":
        return "pokemon", "BASIC"
    if value in {"Stage 1 Pokémon", "Stage 2 Pokémon"}:
        return "pokemon", "EVOLUTION"
    mapping = {
        "Basic Energy": "basic_energy",
        "Special Energy": "special_energy",
        "Item": "item",
        "Supporter": "supporter",
        "Stadium": "stadium",
        "Pokémon Tool": "tool",
    }
    return mapping.get(value, "other"), None


def _rulebox(value: Any) -> bool:
    token = _normalized_cell(value)
    return bool(token and token.lower() != "n/a")


def _brace_tokens(value: Any) -> frozenset[str]:
    return frozenset(match.group(1).strip() for match in _BRACE_TOKEN.finditer(_normalized_cell(value)) if match.group(1).strip())


def _token_set(value: Any) -> frozenset[str]:
    if not _sequence(value) or not all(isinstance(item, str) and item for item in value):
        raise ValueError("card token fields must be nonempty string sequences")
    return frozenset(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _normalized_cell(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _optional_int(value: Any, label: str) -> int | None:
    return None if value is None else _int(value, label)


def _csv_optional_int(value: Any, label: str) -> int | None:
    token = _normalized_cell(value)
    if not token or token.lower() == "n/a":
        return None
    try:
        return int(token)
    except ValueError as error:
        raise ValueError(f"{label} must be an integer or n/a") from error


def _csv_int(value: Any, label: str) -> int:
    token = _normalized_cell(value)
    try:
        return int(token)
    except ValueError as error:
        raise ValueError(f"{label} must be an integer") from error


def _metadata(catalog: CardCatalog, value: int | CardMetadata | None) -> CardMetadata | None:
    return value if isinstance(value, CardMetadata) else catalog.get(value)


def _single_resolved_action(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, Mapping):
        return None
    for key in ("selection", "selections", "selected", "selected_options", "options"):
        if key in payload and _sequence(payload[key]):
            values = payload[key]
            if len(values) != 1 or not isinstance(values[0], Mapping):
                return None
    parts: list[Mapping[str, Any]] = [payload]
    for key in ("option", "resolved", "selection"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            parts.append(value)
    merged: dict[str, Any] = {}
    for part in parts:
        for key, value in part.items():
            if isinstance(value, (Mapping, list, tuple)):
                continue
            if key in merged and merged[key] != value:
                return None
            merged[key] = value
    return merged


def _one_id(action: Mapping[str, Any], *keys: str) -> int | None:
    values = [action[key] for key in keys if key in action and action[key] is not None]
    if not values or any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        return None
    return values[0] if all(value == values[0] for value in values) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _cards(value: Any) -> list[Mapping[str, Any]]:
    return [card for card in value if isinstance(card, Mapping)] if _sequence(value) else []


def _active(player: Mapping[str, Any]) -> Mapping[str, Any] | None:
    active = player.get("active")
    if isinstance(active, Mapping):
        return active
    if _sequence(active) and active and isinstance(active[0], Mapping):
        return active[0]
    return None


def _visible_metadata(card: Mapping[str, Any] | None, catalog: CardCatalog) -> CardMetadata | None:
    if card is None:
        return None
    card_id = card.get("id", card.get("cardId"))
    metadata = catalog.get(card_id)
    if metadata is None:
        raise ValueError("visible card is absent from the frozen catalog")
    return metadata


def _nonnegative(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _count_field(player: Mapping[str, Any], key: str) -> int:
    return _nonnegative(player.get(key))


def _zone_count(player: Mapping[str, Any], key: str) -> int:
    value = player.get(key)
    return len(value) if _sequence(value) else _nonnegative(value)


def _hand_count(player: Mapping[str, Any]) -> int:
    return _nonnegative(player.get("handCount")) if "handCount" in player else _zone_count(player, "hand")


def _energy_count(card: Mapping[str, Any] | None) -> int:
    return len(_cards(card.get("energyCards"))) if card else 0


def _hp_fraction(card: Mapping[str, Any] | None, metadata: CardMetadata | None) -> float:
    if card is None:
        return 0.0
    current = _nonnegative(card.get("hp"))
    maximum = _nonnegative(card.get("maxHp")) or (metadata.hp if metadata and metadata.hp else 0)
    return round(min(1.0, current / maximum), 8) if maximum else 0.0


def _retreat(metadata: CardMetadata | None) -> int:
    return metadata.retreat if metadata and metadata.retreat is not None else -1


def _bench_hp_fraction(player: Mapping[str, Any], catalog: CardCatalog) -> float:
    current = 0
    maximum = 0
    for card in _cards(player.get("bench")):
        metadata = _visible_metadata(card, catalog)
        card_maximum = _nonnegative(card.get("maxHp")) or (metadata.hp if metadata and metadata.hp else 0)
        current += min(_nonnegative(card.get("hp")), card_maximum) if card_maximum else 0
        maximum += card_maximum
    return round(current / maximum, 8) if maximum else 0.0


def _active_class(card: Mapping[str, Any] | None, metadata: CardMetadata | None) -> str:
    return "EMPTY" if card is None else metadata.active_class if metadata else "NON_POKEMON"


def _type_category(metadata: CardMetadata | None) -> str:
    return "NA" if metadata is None or not metadata.types else "|".join(sorted(metadata.types))


def _rulebox_category(metadata: CardMetadata | None) -> str:
    return "NA" if metadata is None or metadata.supertype != "pokemon" else str(metadata.rulebox).upper()


def _status(player: Mapping[str, Any]) -> str:
    labels = ("poisoned", "burned", "asleep", "paralyzed", "confused")
    active = [label.upper() for label in labels if player.get(label)]
    return "|".join(active) if active else "NONE"


def _bench_ontology_counts(player: Mapping[str, Any], catalog: CardCatalog) -> dict[str, int]:
    counts = {active_class: 0 for active_class in ACTIVE_CLASSES if active_class != "EMPTY"}
    for card in _cards(player.get("bench")):
        metadata = _visible_metadata(card, catalog)
        counts[_active_class(card, metadata)] += 1
    return counts


def _hand_supertype_counts(player: Mapping[str, Any], catalog: CardCatalog) -> dict[str, int]:
    counts = {supertype: 0 for supertype in SUPERTYPES}
    hand = player.get("hand")
    if not _sequence(hand):
        return counts
    for card in _cards(hand):
        metadata = _visible_metadata(card, catalog)
        counts[metadata.supertype] += 1
    return counts


def _hand_stage_counts(player: Mapping[str, Any], catalog: CardCatalog) -> dict[str, int]:
    counts = {stage: 0 for stage in POKEMON_STAGES}
    hand = player.get("hand")
    if not _sequence(hand):
        return counts
    for card in _cards(hand):
        metadata = _visible_metadata(card, catalog)
        if metadata.pokemon_stage:
            counts[metadata.pokemon_stage] += 1
    return counts


__all__ = [
    "ACTIVE_CLASSES",
    "CardCatalog",
    "CardMetadata",
    "MATCHUP_RELATIONS",
    "POKEMON_STAGES",
    "SUPERTYPES",
    "SUPPORT_FAMILIES",
    "actor_visible_representation",
    "matchup_relation",
    "support_family",
]
