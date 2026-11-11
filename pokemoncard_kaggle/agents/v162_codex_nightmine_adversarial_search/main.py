"""Codex v162 research stub: actor-aware PIMC over the v161 Night Mine prior.

Do not archive or submit. Fresh-process transcript probes disagree because the
distributed native Search clones share mutable RNG state. The policy exists as
a negative control for the cross-process determinism gate.
"""

from __future__ import annotations

import json
import math
import os
import random
import time
from collections import Counter

from cg.api import AreaType, CardType, Observation, OptionType, SelectContext, to_observation_class

try:
    from cg.api import search_begin, search_end, search_step

    SEARCH_AVAILABLE = os.environ.get("CODEX_DISABLE_SEARCH", "") != "1"
except ImportError:  # pragma: no cover - submission engine always exposes search
    SEARCH_AVAILABLE = False

    def search_begin(*_args, **_kwargs):
        raise RuntimeError("search unavailable")

    def search_step(*_args, **_kwargs):
        raise RuntimeError("search unavailable")

    def search_end(*_args, **_kwargs):
        return None

import prior_rank1 as P
from search_core import WorldActionValue, select_conservative_root_override, stable_observation_seed

# Preserve the prior's safety-audit surface on the wrapper module.
DUNSPARCE = P.DUNSPARCE
DUDUNSPARCE = P.DUDUNSPARCE
ABRA = P.ABRA
ALAKAZAM = P.ALAKAZAM
TELEPATH_PSYCHIC = P.TELEPATH_PSYCHIC
all_field_pokemon = P.all_field_pokemon
count_cards = P.count_cards
energy_attach_score = P.energy_attach_score
score_option = P.score_option


MY_DECK = P.read_deck_csv()
SEARCH_CONTEXTS = {int(SelectContext.MAIN), int(SelectContext.SWITCH), int(SelectContext.TO_ACTIVE)}
DECISION_BUDGET_S = float(os.environ.get("CODEX_SEARCH_DECISION_S", "0.35"))
MAX_WORLDS = int(os.environ.get("CODEX_SEARCH_WORLDS", "12"))
ROLLOUT_CAP = int(os.environ.get("CODEX_SEARCH_ROLLOUT_CAP", "80"))
TOP_ROOT_ACTIONS = int(os.environ.get("CODEX_SEARCH_TOP_ACTIONS", "4"))
MIN_PAIRED_WORLDS = int(os.environ.get("CODEX_SEARCH_MIN_WORLDS", "5"))
OVERRIDE_MARGIN = float(os.environ.get("CODEX_SEARCH_MARGIN", "0.15"))
LAST_SEARCH: dict[str, object] = {}


def _load_meta() -> list[dict]:
    for path in ("meta_decks.json", "/kaggle_simulations/agent/meta_decks.json"):
        if not os.path.exists(path):
            continue
        try:
            payload = json.loads(open(path, encoding="utf-8").read())
            if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
                return [entry for entry in payload["entries"] if len(entry.get("cards") or []) == 60]
            if isinstance(payload, dict):
                return [
                    {"deck_hash": key, "cards": cards, "best_rank": 999, "best_score": 0.0}
                    for key, cards in payload.items()
                    if isinstance(cards, list) and len(cards) == 60
                ]
        except Exception:
            return []
    return []


META_ENTRIES = _load_meta()


def _field(player):
    return [card for card in list(player.active or []) + list(player.bench or []) if card is not None]


def _attached_ids(pokemon) -> list[int]:
    values = []
    for zone in (getattr(pokemon, "energyCards", None), getattr(pokemon, "tools", None), getattr(pokemon, "preEvolution", None)):
        values.extend(card.id for card in zone or [] if card is not None)
    return values


def _visible_ids(player) -> list[int]:
    values: list[int] = []
    for zone in (player.hand, player.discard, player.active, player.bench):
        for card in zone or []:
            if card is None:
                continue
            values.append(card.id)
            values.extend(_attached_ids(card))
    return values


def _remaining(full_deck: list[int], player) -> list[int]:
    counts = Counter(full_deck)
    for card_id in _visible_ids(player):
        if counts[card_id] > 0:
            counts[card_id] -= 1
    return list(counts.elements())


def _deck_hypotheses(opponent) -> list[tuple[dict, float]]:
    revealed = Counter(_visible_ids(opponent))
    ranked: list[tuple[dict, float, int]] = []
    for entry in META_ENTRIES:
        deck = Counter(entry["cards"])
        missing = sum(max(0, count - deck[card]) for card, count in revealed.items())
        overlap = sum(min(count, deck[card]) for card, count in revealed.items())
        if missing:
            continue
        rank = max(1, int(entry.get("best_rank", 999)))
        weight = (1.0 + overlap) ** 2 * (1.0 + 20.0 / rank)
        ranked.append((entry, weight, overlap))
    if not ranked:
        for entry in META_ENTRIES:
            deck = Counter(entry["cards"])
            overlap = sum(min(count, deck[card]) for card, count in revealed.items())
            missing = sum(max(0, count - deck[card]) for card, count in revealed.items())
            score = overlap - 4 * missing
            ranked.append((entry, math.exp(max(-12, min(12, score))), overlap))
    ranked.sort(key=lambda item: (-item[2], int(item[0].get("best_rank", 999)), item[0].get("deck_hash", "")))
    return [(entry, weight) for entry, weight, _ in ranked[:6]]


def _card_at(obs: Observation, area, index: int, player_index: int):
    try:
        player = obs.current.players[player_index]
        if area == AreaType.HAND:
            return player.hand[index]
        if area == AreaType.DISCARD:
            return player.discard[index]
        if area == AreaType.ACTIVE:
            return player.active[index]
        if area == AreaType.BENCH:
            return player.bench[index]
        if area == AreaType.PRIZE:
            return player.prize[index]
        if area == AreaType.STADIUM:
            return obs.current.stadium[index]
        if area == AreaType.LOOKING:
            return obs.current.looking[index]
        if area == AreaType.DECK and obs.select.deck:
            return obs.select.deck[index]
    except Exception:
        return None
    return None


def _pokemon_material(pokemon) -> float:
    if pokemon is None:
        return -1000.0
    data = P.CARD_TABLE.get(pokemon.id)
    score = float(getattr(pokemon, "hp", 0) or 0) * 3.0
    score += 350.0 * len(getattr(pokemon, "energyCards", None) or [])
    score += 120.0 * len(getattr(pokemon, "tools", None) or [])
    if data is not None:
        score += 800.0 if data.stage2 else 350.0 if data.stage1 else 0.0
        score += 1200.0 if data.megaEx else 700.0 if data.ex else 0.0
    return score


def _generic_actor_scores(obs: Observation) -> list[float]:
    """Deck-agnostic tactical prior from the current actor's perspective."""
    actor = obs.current.yourIndex
    player = obs.current.players[actor]
    defender = obs.current.players[1 - actor]
    active = player.active[0] if player.active else None
    target = defender.active[0] if defender.active else None
    context = int(obs.select.context)
    scores: list[float] = []
    for option in obs.select.option:
        score = 0.0
        if option.type == OptionType.NUMBER:
            score = float(option.number or 0)
        elif option.type == OptionType.YES:
            score = 100.0
        elif option.type == OptionType.NO:
            score = 0.0
        elif option.type == OptionType.END:
            score = -100000.0
        elif option.type == OptionType.ATTACK:
            damage = P.attack_damage(active, target, option.attackId, player.handCount) if active is not None else 0
            score = 85000.0 + 120.0 * damage
            if target is not None and damage >= target.hp:
                score += 180000.0 + _pokemon_material(target)
        elif option.type == OptionType.EVOLVE:
            evolved = _card_at(obs, option.area, option.index, actor)
            score = 105000.0 + _pokemon_material(evolved)
        elif option.type == OptionType.ATTACH:
            pokemon = _card_at(obs, option.inPlayArea, option.inPlayIndex, actor)
            attached = len(getattr(pokemon, "energyCards", None) or []) if pokemon is not None else 0
            score = 78000.0 + _pokemon_material(pokemon) * 0.08 - attached * 7000.0
            if option.inPlayArea == AreaType.ACTIVE:
                score += 8000.0
        elif option.type == OptionType.ABILITY:
            score = 92000.0
        elif option.type == OptionType.PLAY:
            card = _card_at(obs, AreaType.HAND, option.index, actor)
            data = P.CARD_TABLE.get(card.id) if card is not None else None
            if data is not None and data.cardType == CardType.POKEMON:
                score = 76000.0 if data.basic and len(player.bench) < player.benchMax else 30000.0
            else:
                score = 68000.0
        elif option.type == OptionType.RETREAT:
            score = 30000.0 + (
                (getattr(active, "maxHp", 0) or 0) - (getattr(active, "hp", 0) or 0)
                if active is not None
                else 0.0
            )
        elif option.type == OptionType.CARD:
            card = _card_at(obs, option.area, option.index, option.playerIndex)
            material = _pokemon_material(card) if card is not None else 0.0
            if context in (int(SelectContext.TO_HAND), int(SelectContext.TO_ACTIVE), int(SelectContext.SWITCH)):
                score = material
            elif context in (int(SelectContext.DISCARD), int(SelectContext.TO_DECK), int(SelectContext.TO_DECK_BOTTOM)):
                score = -material
            else:
                score = material * (1.0 if option.playerIndex != actor else -0.2)
        elif option.type == OptionType.ENERGY:
            score = 10000.0
        scores.append(score)
    return scores


def _root_scores(obs: Observation) -> list[float]:
    try:
        player = obs.current.players[obs.current.yourIndex]
        field = P.count_cards([card for _, _, card in P.all_field_pokemon(player)])
        hand = P.count_cards(player.hand or [])
        discard = P.count_cards(player.discard or [])
        return [float(P.score_option(obs, option, field, hand, discard)) for option in obs.select.option]
    except Exception:
        return [0.0] * len(obs.select.option)


def _choose(scores: list[float], select) -> list[int]:
    count = len(select.option)
    minimum = max(0, min(select.minCount, select.maxCount, count))
    maximum = max(0, min(select.maxCount, count))
    if maximum == 0:
        return []
    ordered = sorted(range(count), key=lambda index: (scores[index], -index), reverse=True)
    wanted = max(minimum, min(1, maximum))
    return ordered[:wanted]


def _state_value(obs: Observation, root_player: int) -> float:
    current = obs.current
    if current is None:
        return 0.0
    if current.result != -1:
        return 1.0 if current.result == root_player else -1.0 if current.result == 1 - root_player else 0.0
    root = current.players[root_player]
    opponent = current.players[1 - root_player]
    root_taken = 6 - len(root.prize or [])
    opponent_taken = 6 - len(opponent.prize or [])
    value = 0.16 * (root_taken - opponent_taken)
    value += 0.00005 * (sum(_pokemon_material(card) for card in _field(root)) - sum(_pokemon_material(card) for card in _field(opponent)))
    value += 0.004 * ((root.handCount or 0) - (opponent.handCount or 0))
    return max(-0.75, min(0.75, value))


def _rollout(state, root_player: int) -> float:
    observation = state.observation
    search_id = state.searchId
    for _ in range(ROLLOUT_CAP):
        if observation.current is None or observation.current.result != -1 or observation.select is None:
            break
        if not observation.select.option:
            break
        actor = observation.current.yourIndex
        scores = _root_scores(observation) if actor == root_player else _generic_actor_scores(observation)
        action = _choose(scores, observation.select)
        try:
            state = search_step(search_id, action)
        except Exception:
            break
        observation = state.observation
        search_id = state.searchId
    return _state_value(observation, root_player)


def _search(obs: Observation, raw_observation: dict) -> list[int] | None:
    global LAST_SEARCH
    LAST_SEARCH = {"reason": "ineligible", "overridden": False, "samples": 0}
    select = obs.select
    if not SEARCH_AVAILABLE or obs.current is None or select is None or not obs.search_begin_input:
        return None
    if select.minCount != 1 or select.maxCount != 1 or len(select.option) <= 1:
        return None
    if int(select.context) not in SEARCH_CONTEXTS:
        return None
    if float(raw_observation.get("remainingOverageTime", 600.0) or 0.0) < 30.0:
        return None

    root_player = obs.current.yourIndex
    root = obs.current.players[root_player]
    opponent = obs.current.players[1 - root_player]
    root_scores = _root_scores(obs)
    order = sorted(range(len(root_scores)), key=lambda index: (root_scores[index], -index), reverse=True)
    prior_action = order[0]
    if root_scores[prior_action] >= 200000.0:
        return [prior_action]
    candidates = order[:TOP_ROOT_ACTIONS]
    if len(candidates) < 2:
        return None

    hypotheses = _deck_hypotheses(opponent)
    if not hypotheses:
        LAST_SEARCH = {"reason": "no_hypotheses", "overridden": False, "samples": 0}
        return None
    rng = random.Random(stable_observation_seed(raw_observation, namespace="codex-v162-pimc"))
    entries, weights = zip(*hypotheses)
    root_pool_template = _remaining(MY_DECK, root)
    start = time.monotonic()
    samples: list[WorldActionValue] = []
    begin_errors = 0
    branch_errors = 0
    worlds_started = 0
    last_error = ""
    for world_index in range(MAX_WORLDS):
        if time.monotonic() - start >= DECISION_BUDGET_S:
            break
        entry = rng.choices(entries, weights=weights, k=1)[0]
        root_pool = root_pool_template[:]
        opponent_pool = _remaining(entry["cards"], opponent)
        rng.shuffle(root_pool)
        rng.shuffle(opponent_pool)
        root_deck_count = int(root.deckCount or 0)
        root_prize_count = len(root.prize or [])
        opponent_deck_count = int(opponent.deckCount or 0)
        opponent_prize_count = len(opponent.prize or [])
        opponent_hand_count = int(opponent.handCount or 0)
        needed_root = root_deck_count + root_prize_count
        needed_opponent = opponent_deck_count + opponent_prize_count + opponent_hand_count
        if len(root_pool) < needed_root or len(opponent_pool) < needed_opponent:
            continue
        root_deck = root_pool[:root_deck_count]
        root_prize = root_pool[root_deck_count:needed_root]
        opponent_deck = opponent_pool[:opponent_deck_count]
        opponent_prize = opponent_pool[opponent_deck_count:opponent_deck_count + opponent_prize_count]
        opponent_hand = opponent_pool[opponent_deck_count + opponent_prize_count:needed_opponent]
        basics = [card for card in opponent_pool if getattr(P.CARD_TABLE.get(card), "basic", False)]
        opponent_active = [basics[0]] if opponent.active and opponent.active[0] is None and basics else []
        try:
            search_root = search_begin(
                obs,
                root_deck,
                root_prize,
                opponent_deck,
                opponent_prize,
                opponent_hand,
                opponent_active,
            )
        except Exception as exc:
            begin_errors += 1
            last_error = f"{type(exc).__name__}:{str(exc)[:120]}"
            continue
        worlds_started += 1
        world_id = f"{world_index}:{entry.get('deck_hash', '')}"
        try:
            for action in candidates:
                if time.monotonic() - start >= DECISION_BUDGET_S:
                    break
                try:
                    branch = search_step(search_root.searchId, [action])
                    samples.append(WorldActionValue(action, world_id, _rollout(branch, root_player)))
                except Exception as exc:
                    branch_errors += 1
                    last_error = f"{type(exc).__name__}:{str(exc)[:120]}"
                    continue
        finally:
            try:
                search_end()
            except Exception:
                pass

    decision = select_conservative_root_override(
        prior_action,
        samples,
        min_worlds=MIN_PAIRED_WORLDS,
        min_margin=OVERRIDE_MARGIN,
    )
    LAST_SEARCH = {
        "reason": decision.reason,
        "overridden": decision.overridden,
        "samples": len(samples),
        "paired_worlds": decision.paired_world_count,
        "margin": decision.margin,
        "elapsed_s": time.monotonic() - start,
        "worlds_started": worlds_started,
        "begin_errors": begin_errors,
        "branch_errors": branch_errors,
        "last_error": last_error,
    }
    return [int(decision.action)] if decision.overridden else [prior_action]


def agent(observation: dict) -> list[int]:
    if not observation:
        return MY_DECK
    try:
        converted = to_observation_class(observation)
        if converted.current is None or converted.select is None:
            return MY_DECK
        searched = _search(converted, observation)
        if searched is not None:
            return searched
    except Exception:
        pass
    return P.agent(observation)
