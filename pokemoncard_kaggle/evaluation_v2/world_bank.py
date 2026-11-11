"""Deterministic public-belief determinizations for evaluator search.

The bank accepts one *player-visible* engine observation.  It deliberately does
not accept a replay, reward, future state, or an opponent's private hand.  A
world is a complete allocation of each exact 60-card deck which agrees with the
public cards and zone counts in that observation.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import random
from typing import Any


WORLD_BANK_NAMESPACE = "evaluation-v2-public-belief-world-bank-v1"


@dataclass(frozen=True)
class PlayerWorld:
    """One player's complete card allocation in a determinized world."""

    deck: tuple[int, ...]
    prize: tuple[int, ...]
    hand: tuple[int, ...]
    active: tuple[int, ...]
    bench: tuple[int, ...]
    discard: tuple[int, ...]
    stadium: tuple[int, ...] = ()

    def all_cards(self) -> tuple[int, ...]:
        """Return every card in this player's exact deck exactly once."""

        return self.deck + self.prize + self.hand + self.active + self.bench + self.discard + self.stadium


@dataclass(frozen=True)
class BeliefWorld:
    """A paired own/opponent determinization for one compatible meta deck."""

    world_id: str
    stable_hash: str
    seed: int
    opponent_deck_hash: str
    own: PlayerWorld
    opponent: PlayerWorld


@dataclass(frozen=True)
class WorldBank:
    """Immutable deterministic worlds derived from one public observation."""

    namespace: str
    seed: int
    public_observation_hash: str
    compatible_deck_hashes: tuple[str, ...]
    worlds: tuple[BeliefWorld, ...]
    stable_hash: str


@dataclass(frozen=True)
class _ObservedPlayer:
    deck_count: int
    hand_count: int
    active: tuple[int, ...]
    facedown_active: int
    bench: tuple[int, ...]
    discard: tuple[int, ...]
    hand: tuple[int, ...]
    hidden_hand: int
    prize: tuple[int | None, ...]
    stadium: tuple[int, ...]

    @property
    def fixed_cards(self) -> tuple[int, ...]:
        return self.active + self.bench + self.discard + self.hand + tuple(card for card in self.prize if card is not None) + self.stadium

    @property
    def hidden_count(self) -> int:
        return self.deck_count + self.hidden_hand + self.facedown_active + sum(card is None for card in self.prize)


def build_world_bank(
    observation: dict[str, Any],
    own_deck: Sequence[int],
    meta_snapshot_entries: Sequence[Mapping[str, Any]],
    *,
    namespace: str = WORLD_BANK_NAMESPACE,
    world_count: int | None = None,
) -> WorldBank:
    """Build one deterministic, legal world for every compatible frozen deck.

    The public observation is intentionally narrow: ``current.players`` must
    contain exactly two player states and ``current.yourIndex`` identifies the
    observer.  Public cards constrain the matching deck; ``None`` in Active or
    prize zones and a missing opponent hand are determinized without replacement.
    Impossible counts, private opponent cards, and replay-derived payloads are
    rejected instead of being silently incorporated into a search state.
    """

    if not isinstance(namespace, str) or not namespace:
        raise ValueError("namespace must be a nonempty string")
    _reject_forbidden_payload(observation)
    public_observation = sanitize_public_observation(observation)
    public_bytes = _canonical_json(public_observation)
    public_hash = sha256(public_bytes).hexdigest()
    seed = int.from_bytes(sha256(namespace.encode("utf-8") + b"\0" + public_bytes).digest()[:8], "big")

    own_cards = _validate_deck(own_deck, label="own_deck")
    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("observation.current must be a mapping")
    players = current.get("players")
    if not isinstance(players, Sequence) or isinstance(players, (str, bytes)) or len(players) != 2:
        raise ValueError("observation.current.players must contain exactly two players")
    your_index = _nonnegative_int(current.get("yourIndex"), "current.yourIndex")
    if your_index not in (0, 1):
        raise ValueError("current.yourIndex must be 0 or 1")

    stadium = _stadium_by_player(current.get("stadium", []))
    observed = tuple(
        _parse_player(player, slot=index, stadium=stadium[index], opponent=index != your_index)
        for index, player in enumerate(players)
    )
    own_observed = observed[your_index]
    opponent_observed = observed[1 - your_index]
    _validate_observed_conservation(own_observed, own_cards, label="own")

    compatible: list[tuple[str, tuple[int, ...], float]] = []
    seen_decks: set[str] = set()
    for entry in meta_snapshot_entries:
        if not isinstance(entry, Mapping):
            raise TypeError("meta_snapshot_entries must contain mappings")
        cards = _validate_deck(entry.get("cards"), label="meta snapshot deck")
        deck_hash = _deck_hash(cards)
        if deck_hash in seen_decks:
            raise ValueError("meta snapshot contains duplicate exact decks")
        seen_decks.add(deck_hash)
        if _contains_cards(cards, opponent_observed.fixed_cards):
            _validate_observed_conservation(opponent_observed, cards, label=f"opponent deck {deck_hash}")
            prevalence = entry.get("observed_episodes")
            if prevalence is None:
                prevalence = len(entry.get("episode_ids") or ()) or 1
            if isinstance(prevalence, bool) or not isinstance(prevalence, (int, float)) or prevalence <= 0:
                raise ValueError("meta snapshot prevalence must be positive")
            compatible.append((deck_hash, cards, float(prevalence)))

    if not compatible:
        raise ValueError("no compatible opponent decks in frozen meta snapshot")
    compatible.sort(key=lambda item: item[0])

    requested_worlds = len(compatible) if world_count is None else world_count
    if not isinstance(requested_worlds, int) or isinstance(requested_worlds, bool) or requested_worlds <= 0:
        raise ValueError("world_count must be a positive integer")
    if requested_worlds < len(compatible):
        raise ValueError("world_count must cover every compatible deck at least once")

    rng = random.Random(seed)
    schedule = list(range(len(compatible)))
    if requested_worlds > len(schedule):
        schedule.extend(
            rng.choices(
                range(len(compatible)),
                weights=[item[2] for item in compatible],
                k=requested_worlds - len(schedule),
            )
        )
    worlds: list[BeliefWorld] = []
    for world_index, compatible_index in enumerate(schedule):
        opponent_hash, opponent_cards, _ = compatible[compatible_index]
        own_world = _materialize_player(
            own_observed,
            own_cards,
            rng,
            label="own",
        )
        opponent_world = _materialize_player(
            opponent_observed,
            opponent_cards,
            rng,
            label="opponent",
        )
        world_payload = {
            "world_index": world_index,
            "seed": seed,
            "opponent_deck_hash": opponent_hash,
            "own": _player_payload(own_world),
            "opponent": _player_payload(opponent_world),
        }
        stable_hash = sha256(_canonical_json(world_payload)).hexdigest()
        worlds.append(
            BeliefWorld(
                world_id=stable_hash[:20],
                stable_hash=stable_hash,
                seed=seed,
                opponent_deck_hash=opponent_hash,
                own=own_world,
                opponent=opponent_world,
            )
        )

    bank_payload = {
        "namespace": namespace,
        "seed": seed,
        "public_observation_hash": public_hash,
        "world_hashes": [world.stable_hash for world in worlds],
    }
    return WorldBank(
        namespace=namespace,
        seed=seed,
        public_observation_hash=public_hash,
        compatible_deck_hashes=tuple(deck_hash for deck_hash, _, _ in compatible),
        worlds=tuple(worlds),
        stable_hash=sha256(_canonical_json(bank_payload)).hexdigest(),
    )


generate_world_bank = build_world_bank


def sanitize_public_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Return the allocation-relevant public projection used for seeding.

    Logs, option payloads, serial numbers, timing data, and unknown metadata are
    intentionally absent.  The projection retains the observer's known hand but
    never accepts a materialized opponent hand.
    """

    if not isinstance(observation, Mapping):
        raise TypeError("observation must be a mapping")
    current = observation.get("current")
    if not isinstance(current, Mapping):
        raise ValueError("observation.current must be a mapping")
    players = current.get("players")
    if not isinstance(players, Sequence) or isinstance(players, (str, bytes)) or len(players) != 2:
        raise ValueError("observation.current.players must contain exactly two players")
    your_index = _nonnegative_int(current.get("yourIndex"), "current.yourIndex")
    if your_index not in (0, 1):
        raise ValueError("current.yourIndex must be 0 or 1")

    stadium = _stadium_by_player(current.get("stadium", []))
    sanitized_players = []
    for slot, player in enumerate(players):
        parsed = _parse_player(player, slot=slot, stadium=stadium[slot], opponent=slot != your_index)
        sanitized_players.append(
            {
                "deck_count": parsed.deck_count,
                "hand_count": parsed.hand_count,
                "active": list(parsed.active),
                "facedown_active": parsed.facedown_active,
                "bench": list(parsed.bench),
                "discard": list(parsed.discard),
                "hand": list(parsed.hand),
                "hidden_hand": parsed.hidden_hand,
                "prize": list(parsed.prize),
                "stadium": list(parsed.stadium),
            }
        )
    scalars = {
        key: current[key]
        for key in ("energyAttached", "firstPlayer", "retreated", "stadiumPlayed", "supporterPlayed", "turn", "turnActionCount")
        if key in current
    }
    for key, value in scalars.items():
        if not _is_canonical_scalar(value):
            raise ValueError(f"current.{key} must be a finite JSON scalar")
    return {"current": {**scalars, "yourIndex": your_index, "players": sanitized_players}}


def _parse_player(value: Any, *, slot: int, stadium: tuple[int, ...], opponent: bool) -> _ObservedPlayer:
    if not isinstance(value, Mapping):
        raise ValueError("each current player must be a mapping")
    deck_count = _nonnegative_int(value.get("deckCount"), "player.deckCount")
    hand_count = _nonnegative_int(value.get("handCount"), "player.handCount")
    active, facedown_active = _active_cards(value.get("active"), slot)
    bench = _known_cards(value.get("bench"), "player.bench", slot)
    discard = _known_cards(value.get("discard"), "player.discard", slot)
    prize = _prize_cards(value.get("prize"), slot)
    raw_hand = value.get("hand")
    if opponent and raw_hand is not None:
        raise ValueError("opponent private hand cards are not accepted")
    if raw_hand is None:
        hand = ()
    else:
        hand = _simple_cards(raw_hand, "player.hand", slot)
    if len(hand) > hand_count:
        raise ValueError("known hand cards exceed handCount")
    return _ObservedPlayer(
        deck_count=deck_count,
        hand_count=hand_count,
        active=active,
        facedown_active=facedown_active,
        bench=bench,
        discard=discard,
        hand=hand,
        hidden_hand=hand_count - len(hand),
        prize=prize,
        stadium=stadium,
    )


def _active_cards(value: Any, slot: int) -> tuple[tuple[int, ...], int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("player.active must be a list")
    cards: list[int] = []
    facedown = 0
    for item in value:
        if item is None:
            facedown += 1
        else:
            cards.extend(_expand_card(item, slot))
    return tuple(cards), facedown


def _known_cards(value: Any, label: str, slot: int) -> tuple[int, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{label} must be a list")
    cards: list[int] = []
    for item in value:
        if item is None:
            raise ValueError(f"{label} cannot contain facedown cards")
        cards.extend(_expand_card(item, slot))
    return tuple(cards)


def _simple_cards(value: Any, label: str, slot: int) -> tuple[int, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{label} must be a list or null")
    cards: list[int] = []
    for item in value:
        if item is None:
            raise ValueError(f"{label} cannot contain facedown cards")
        expanded = _expand_card(item, slot)
        if len(expanded) != 1:
            raise ValueError(f"{label} cards cannot carry nested cards")
        cards.append(expanded[0])
    return tuple(cards)


def _prize_cards(value: Any, slot: int) -> tuple[int | None, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("player.prize must be a list")
    cards: list[int | None] = []
    for item in value:
        if item is None:
            cards.append(None)
            continue
        expanded = _expand_card(item, slot)
        if len(expanded) != 1:
            raise ValueError("prize cards cannot carry nested cards")
        cards.append(expanded[0])
    return tuple(cards)


def _stadium_by_player(value: Any) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("current.stadium must be a list")
    owners: list[list[int]] = [[], []]
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("stadium cards must be mappings")
        owner = item.get("playerIndex")
        if owner not in (0, 1):
            raise ValueError("stadium cards require a public playerIndex")
        owners[int(owner)].extend(_expand_card(item, int(owner)))
    return tuple(tuple(cards) for cards in owners)  # type: ignore[return-value]


def _expand_card(value: Any, slot: int) -> tuple[int, ...]:
    if not isinstance(value, Mapping):
        raise ValueError("revealed cards must be mappings")
    owner = value.get("playerIndex")
    if owner is not None and owner != slot:
        raise ValueError("revealed card playerIndex disagrees with its public zone")
    card_id = _nonnegative_int(value.get("id"), "card.id")
    cards = [card_id]
    for key in ("energyCards", "tools", "preEvolution"):
        nested = value.get(key, [])
        if not isinstance(nested, Sequence) or isinstance(nested, (str, bytes)):
            raise ValueError(f"card.{key} must be a list")
        for child in nested:
            cards.extend(_expand_card(child, slot))
    return tuple(cards)


def _validate_observed_conservation(observed: _ObservedPlayer, deck: tuple[int, ...], *, label: str) -> None:
    if observed.hidden_count < 0 or len(observed.fixed_cards) + observed.hidden_count != 60:
        raise ValueError(f"{label} zone counts cannot conserve an exact 60-card deck")
    if not _contains_cards(deck, observed.fixed_cards):
        raise ValueError(f"{label} revealed cards exceed exact deck multiplicities")


def _materialize_player(
    observed: _ObservedPlayer, deck: tuple[int, ...], rng: random.Random, *, label: str
) -> PlayerWorld:
    _validate_observed_conservation(observed, deck, label=label)
    remaining = Counter(deck)
    for card in observed.fixed_cards:
        remaining[card] -= 1
        if remaining[card] < 0:
            raise ValueError(f"{label} revealed cards exceed exact deck multiplicities")
    pool = [card for card, count in sorted(remaining.items()) for _ in range(count)]
    if len(pool) != observed.hidden_count:
        raise ValueError(f"{label} hidden zone counts cannot conserve exact deck")
    rng.shuffle(pool)
    cursor = 0

    def take(count: int) -> tuple[int, ...]:
        nonlocal cursor
        result = tuple(pool[cursor : cursor + count])
        cursor += count
        return result

    deck_zone = take(observed.deck_count)
    prize_unknown = iter(take(sum(card is None for card in observed.prize)))
    prize = tuple(card if card is not None else next(prize_unknown) for card in observed.prize)
    hand = observed.hand + take(observed.hidden_hand)
    active = observed.active + take(observed.facedown_active)
    if cursor != len(pool):
        raise ValueError(f"{label} allocation did not consume its exact deck")
    world = PlayerWorld(
        deck=deck_zone,
        prize=prize,
        hand=hand,
        active=active,
        bench=observed.bench,
        discard=observed.discard,
        stadium=observed.stadium,
    )
    if Counter(world.all_cards()) != Counter(deck):
        raise ValueError(f"{label} allocation violated card conservation")
    return world


def _validate_deck(value: Any, *, label: str) -> tuple[int, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError(f"{label} must be a 60-card sequence")
    cards = tuple(_nonnegative_int(card, label) for card in value)
    if len(cards) != 60:
        raise ValueError(f"{label} must contain exactly 60 cards")
    return cards


def _contains_cards(deck: Sequence[int], cards: Sequence[int]) -> bool:
    available = Counter(deck)
    required = Counter(cards)
    return all(available[card] >= count for card, count in required.items())


def _deck_hash(cards: Sequence[int]) -> str:
    return sha256(",".join(str(card) for card in sorted(cards)).encode("ascii")).hexdigest()


def _player_payload(player: PlayerWorld) -> dict[str, list[int]]:
    return {
        "deck": list(player.deck),
        "prize": list(player.prize),
        "hand": list(player.hand),
        "active": list(player.active),
        "bench": list(player.bench),
        "discard": list(player.discard),
        "stadium": list(player.stadium),
    }


def _reject_forbidden_payload(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise TypeError("observation keys must be strings")
            normalized = "".join(character for character in key.lower() if character.isalnum())
            if (
                "reward" in normalized
                or "future" in normalized
                or "replay" in normalized
                or ("opponent" in normalized and ("observation" in normalized or "private" in normalized or "hand" in normalized))
            ):
                raise ValueError(f"forbidden non-public payload key: {key}")
            _reject_forbidden_payload(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            _reject_forbidden_payload(child)


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _is_canonical_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (bool, int, str)) or (isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")))


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
