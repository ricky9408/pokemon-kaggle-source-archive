import os
from collections import Counter

from cg.api import (
    AreaType,
    CardType,
    EnergyType,
    Observation,
    OptionType,
    SelectContext,
    all_attack,
    all_card_data,
    to_observation_class,
)


DECK = [
    1, 1, 1, 1, 1,
    89, 89, 89, 89,
    90, 90, 90, 90,
    92, 92, 92, 92,
    93, 93, 93, 93,
    1086, 1086, 1086, 1086,
    1094, 1094, 1094, 1094,
    1152, 1152, 1152, 1152,
    1227, 1227, 1227, 1227,
    1245, 1245, 1245, 1245,
    1182, 1182, 1182,
    100, 100,
    240, 240,
    1174, 1174,
    1175, 1175,
    18,
    1092,
    1097,
    1123,
    1129,
    1137,
    1191,
    1211,
]

BASIC_GRASS = 1
GROW_GRASS = 18
GROOKEY = 89
THWACKEY = 90
APPLIN = 92
DIPPLIN = 93
GOLDEEN = 100
SEAKING = 240
BUDDY_BUDDY_POFFIN = 1086
SECRET_BOX = 1092
BUG_CATCHING_SET = 1094
NIGHT_STRETCHER = 1097
SWITCH = 1123
SACRED_ASH = 1129
TOOL_SCRAPPER = 1137
POKE_PAD = 1152
AIR_BALLOON = 1174
BRAVE_BANGLE = 1175
BOSS_ORDERS = 1182
KIERAN = 1191
BLACK_BELT = 1211
LILLIES_DETERMINATION = 1227
FESTIVAL_GROUNDS = 1245

FESTIVAL_ATTACKERS = {DIPPLIN, SEAKING}
BASICS = {GROOKEY, APPLIN, GOLDEEN}
ENERGIES = {BASIC_GRASS, GROW_GRASS}

try:
    CARD_TABLE = {card.cardId: card for card in all_card_data()}
    ATTACK_TABLE = {attack.attackId: attack for attack in all_attack()}
except Exception:
    CARD_TABLE = {}
    ATTACK_TABLE = {}


def read_deck_csv() -> list[int]:
    for path in ("deck.csv", "/kaggle_simulations/agent/deck.csv"):
        if os.path.exists(path):
            with open(path) as file:
                cards = [int(x) for x in file.read().splitlines() if x.strip()]
            if len(cards) == 60:
                return cards
    return DECK[:]


MY_DECK = read_deck_csv()


def safe_fallback(obs: Observation) -> list[int]:
    if obs.select is None:
        return MY_DECK
    option_count = len(obs.select.option)
    count = max(0, min(obs.select.minCount, obs.select.maxCount, option_count))
    return list(range(count))


def get_card(obs: Observation, area, index: int, player_index: int):
    try:
        state = obs.current
        player = state.players[player_index]
        if area == AreaType.DECK:
            return obs.select.deck[index] if obs.select and obs.select.deck else None
        if area == AreaType.HAND:
            return player.hand[index] if player.hand is not None else None
        if area == AreaType.DISCARD:
            return player.discard[index]
        if area == AreaType.ACTIVE:
            return player.active[index]
        if area == AreaType.BENCH:
            return player.bench[index]
        if area == AreaType.PRIZE:
            return player.prize[index]
        if area == AreaType.STADIUM:
            return state.stadium[index]
        if area == AreaType.LOOKING:
            return state.looking[index] if state.looking is not None else None
    except Exception:
        return None
    return None


def card_id(card) -> int | None:
    return getattr(card, "id", None)


def is_basic_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return bool(data.basic)
    return cid in BASICS


def is_energy_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType in (CardType.BASIC_ENERGY, CardType.SPECIAL_ENERGY)
    return cid in ENERGIES


def all_field_pokemon(player_state):
    cards = []
    for card in player_state.active:
        if card is not None:
            cards.append((AreaType.ACTIVE, 0, card))
    for index, card in enumerate(player_state.bench):
        cards.append((AreaType.BENCH, index, card))
    return cards


def count_cards(cards) -> Counter:
    counts = Counter()
    for card in cards:
        if card is not None:
            counts[card.id] += 1
    return counts


def has_stadium(state) -> bool:
    return bool(state.stadium and state.stadium[0].id == FESTIVAL_GROUNDS)


def active_has_festival(my_state, state) -> bool:
    active = my_state.active[0] if my_state.active else None
    return active is not None and active.id in FESTIVAL_ATTACKERS and has_stadium(state)


def attached_energy_count(my_state) -> int:
    total = 0
    for _, _, pokemon in all_field_pokemon(my_state):
        total += len(getattr(pokemon, "energies", []))
    return total


def prize_count(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    if data is None:
        return 1
    return 3 if data.megaEx else 2 if data.ex else 1


def pokemon_value(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    score = prize_count(pokemon) * 1000 + pokemon.hp
    score += len(getattr(pokemon, "energies", [])) * 180
    score += len(getattr(pokemon, "tools", [])) * 100
    if data is not None:
        if data.stage2:
            score += 260
        elif data.stage1:
            score += 140
        if data.ex or data.megaEx:
            score += 420
    return score


def attack_damage(active, op_active, attack_id: int, my_state, state) -> int:
    if active is None or op_active is None:
        return 0
    if active.id == DIPPLIN:
        damage = 20 * len(my_state.bench)
    elif active.id == SEAKING:
        damage = 60
    else:
        attack = ATTACK_TABLE.get(attack_id)
        damage = int(getattr(attack, "damage", 0) or 0) if attack is not None else 0
        if attack is not None and "20 damage for each of your Benched" in getattr(attack, "text", ""):
            damage += 20 * len(my_state.bench)
    op_data = CARD_TABLE.get(op_active.id)
    if op_data is not None and op_data.ex:
        if any(getattr(tool, "id", None) == BRAVE_BANGLE for tool in getattr(active, "tools", [])):
            damage += 30
    if active.id in FESTIVAL_ATTACKERS and has_stadium(state):
        damage *= 2
    return damage


def score_search_card(cid: int, state, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 100
    my_state = state.players[state.yourIndex]
    active = my_state.active[0] if my_state.active else None
    attacker_ready = bool(field_counts[DIPPLIN] or field_counts[SEAKING])
    attached_energy = attached_energy_count(my_state)
    if cid == DIPPLIN:
        score = 1150 if field_counts[APPLIN] else 550
        if hand_counts[DIPPLIN]:
            score -= 420
    elif cid == THWACKEY:
        score = 1040 if field_counts[GROOKEY] else 520
        if hand_counts[THWACKEY] or field_counts[THWACKEY] >= 2:
            score -= 320
    elif cid == APPLIN:
        score = 920 - (field_counts[APPLIN] + field_counts[DIPPLIN]) * 160
    elif cid == GROOKEY:
        score = 820 - (field_counts[GROOKEY] + field_counts[THWACKEY]) * 130
    elif cid == SEAKING:
        score = 650 if field_counts[GOLDEEN] else 250
    elif cid == GOLDEEN:
        score = 440 if field_counts[GOLDEEN] + field_counts[SEAKING] == 0 else 180
    elif cid in ENERGIES:
        if hand_counts[BASIC_GRASS] + hand_counts[GROW_GRASS] or attached_energy >= 2:
            score = 280
        elif attacker_ready or field_counts[APPLIN]:
            score = 650
        else:
            score = 430
    elif cid == FESTIVAL_GROUNDS:
        if has_stadium(state):
            score = 180
        elif attacker_ready or (active is not None and active.id in FESTIVAL_ATTACKERS):
            score = 980
        else:
            score = 620
    elif cid == BUDDY_BUDDY_POFFIN:
        score = 760
    elif cid in {BUG_CATCHING_SET, POKE_PAD}:
        score = 760 if cid == POKE_PAD else 720
    elif cid in {BOSS_ORDERS, KIERAN, BLACK_BELT, BRAVE_BANGLE}:
        score = 620
    elif cid in {SWITCH, AIR_BALLOON}:
        score = 600 if active_has_festival(my_state, state) else 500
    elif cid in {SECRET_BOX, NIGHT_STRETCHER, SACRED_ASH}:
        score = 380
    score -= hand_counts[cid] * 80
    score -= discard_counts[cid] * 12
    return score


def score_discard_card(cid: int, field_counts: Counter, hand_counts: Counter) -> int:
    if cid in {DIPPLIN, THWACKEY, APPLIN, GROOKEY}:
        return -900 if hand_counts[cid] <= 1 else -80
    if cid in ENERGIES:
        return 120 if hand_counts[BASIC_GRASS] + hand_counts[GROW_GRASS] >= 3 else -520
    if cid in {FESTIVAL_GROUNDS, BOSS_ORDERS, LILLIES_DETERMINATION, BUG_CATCHING_SET, POKE_PAD}:
        return 130 if hand_counts[cid] >= 2 else -240
    if cid in {AIR_BALLOON, BRAVE_BANGLE, SWITCH}:
        return 90 if hand_counts[cid] >= 2 else -180
    return 100


def energy_attach_score(energy_id: int, pokemon, active: bool, field_counts: Counter) -> int:
    if pokemon is None:
        return -1000
    energy_count = len(getattr(pokemon, "energies", []))
    score = 26000 - energy_count * 7000
    if active:
        score += 7000
    if pokemon.id == DIPPLIN:
        score += 17000
    elif pokemon.id == APPLIN:
        score += 16000
    elif pokemon.id == SEAKING:
        score += 12000
    elif pokemon.id == GOLDEEN:
        score += 10000
    elif pokemon.id in {GROOKEY, THWACKEY}:
        score += 9000
    if energy_id == GROW_GRASS and pokemon.id in {APPLIN, DIPPLIN, GROOKEY, THWACKEY}:
        score += 3000
    return score


def best_bench_ko(active, op_state, select, my_state, state) -> bool:
    if active is None:
        return False
    for bench_pokemon in op_state.bench:
        for option in select.option:
            if option.type == OptionType.ATTACK:
                if attack_damage(active, bench_pokemon, option.attackId, my_state, state) >= bench_pokemon.hp:
                    return True
    return False


def score_play_card(cid: int, state, select, my_state, op_state, field_counts: Counter, hand_counts: Counter) -> int:
    bench_space = my_state.benchMax - len(my_state.bench)
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None
    if cid in BASICS:
        if bench_space <= 0:
            return -100
        if cid == APPLIN:
            return 30000 - field_counts[APPLIN] * 8500
        if cid == GROOKEY:
            return 28500 - field_counts[GROOKEY] * 7600
        if cid == GOLDEEN:
            return 22000 if field_counts[GOLDEEN] + field_counts[SEAKING] == 0 else 3500
    if cid == BUDDY_BUDDY_POFFIN:
        need_basics = field_counts[APPLIN] + field_counts[GROOKEY] < 4
        return 54000 if bench_space > 0 and need_basics else 7000
    if cid == BUG_CATCHING_SET:
        return 45500
    if cid == FESTIVAL_GROUNDS:
        if has_stadium(state):
            return 2000
        if active is not None and active.id in FESTIVAL_ATTACKERS:
            return 57000
        if field_counts[DIPPLIN] or field_counts[SEAKING]:
            return 47000
        if hand_counts[POKE_PAD] or hand_counts[BUG_CATCHING_SET]:
            return 32000
        return 39000
    if cid == POKE_PAD:
        return 39500
    if cid == SECRET_BOX:
        return 42000 if my_state.handCount >= 5 else 5000
    if cid == LILLIES_DETERMINATION:
        return 42000 if my_state.handCount <= 5 else 15000
    if cid == BOSS_ORDERS:
        if active is not None and best_bench_ko(active, op_state, select, my_state, state):
            return 58000
        if active is not None and op_active is not None:
            damage = 0
            for option in select.option:
                if option.type == OptionType.ATTACK:
                    damage = max(damage, attack_damage(active, op_active, option.attackId, my_state, state))
            if damage >= op_active.hp:
                return -100
        return 12000
    if cid in {KIERAN, BLACK_BELT}:
        op_data = CARD_TABLE.get(op_active.id) if op_active is not None else None
        return 50000 if active is not None and op_data is not None and op_data.ex else 8000
    if cid == SWITCH:
        return 25000 if active is not None and active.id not in FESTIVAL_ATTACKERS else 9000
    if cid == AIR_BALLOON:
        return 34000 if active is not None and active.id not in FESTIVAL_ATTACKERS else 26000
    if cid == BRAVE_BANGLE:
        return 38000 if active is not None and active.id in FESTIVAL_ATTACKERS else 23000
    if cid in {NIGHT_STRETCHER, SACRED_ASH}:
        return 12000 if my_state.discard else 2500
    if cid == TOOL_SCRAPPER:
        return 7000
    return 0


def score_switch_target(pokemon, my_index: int, owner_index: int) -> int:
    if pokemon is None:
        return -1000
    if owner_index != my_index:
        return pokemon_value(pokemon)
    score = pokemon.hp + len(getattr(pokemon, "energies", [])) * 200
    if pokemon.id == DIPPLIN:
        score += 2600
    elif pokemon.id == SEAKING:
        score += 1800
    elif pokemon.id == APPLIN:
        score += 900
    elif pokemon.id == THWACKEY:
        score += 700
    return score


def choose_indices(select, scores: list[float]) -> list[int]:
    option_count = len(select.option)
    if option_count == 0 or select.maxCount == 0:
        return []
    minimum = max(0, min(select.minCount, select.maxCount, option_count))
    maximum = max(0, min(select.maxCount, option_count))
    ordered = sorted(range(option_count), key=lambda i: (scores[i], -i), reverse=True)
    chosen = []
    threshold = 0 if minimum == 0 else -10**18
    for index in ordered:
        if len(chosen) >= maximum:
            break
        if scores[index] > threshold or len(chosen) < minimum:
            chosen.append(index)
    for index in ordered:
        if len(chosen) >= minimum:
            break
        if index not in chosen:
            chosen.append(index)
    return chosen[:maximum]


def score_option(obs: Observation, option, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> float:
    state = obs.current
    select = obs.select
    context = select.context
    my_index = state.yourIndex
    my_state = state.players[my_index]
    op_state = state.players[1 - my_index]
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None

    if context == SelectContext.IS_FIRST:
        if option.type == OptionType.YES:
            return 100
        if option.type == OptionType.NO:
            return 0
    if option.type == OptionType.NUMBER:
        return option.number or 0
    if option.type == OptionType.YES:
        return 100
    if option.type == OptionType.NO:
        return 0

    if option.type == OptionType.CARD:
        card = get_card(obs, option.area, option.index, option.playerIndex)
        cid = card_id(card)
        if cid is None:
            return -1000
        if context == SelectContext.SETUP_ACTIVE_POKEMON:
            if cid == APPLIN:
                return 900
            if cid == GROOKEY:
                return 620
            if cid == GOLDEEN:
                return 300
            return 100
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid == GROOKEY:
                return 820 - field_counts[GROOKEY] * 130
            if cid == APPLIN:
                return 800 - field_counts[APPLIN] * 140
            if cid == GOLDEEN:
                return 300 - field_counts[GOLDEEN] * 80
            return 100 if is_basic_id(cid) else 20
        if context in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            return score_switch_target(card, my_index, option.playerIndex)
        if context == SelectContext.TO_HAND:
            return score_search_card(cid, state, field_counts, hand_counts, discard_counts)
        if context == SelectContext.DISCARD:
            return score_discard_card(cid, field_counts, hand_counts)
        if context in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -score_search_card(cid, state, field_counts, hand_counts, discard_counts)
        if context == SelectContext.ATTACH_FROM:
            return 100 if cid in ENERGIES else 0
        if context in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER, SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            return pokemon_value(card) if option.playerIndex != my_index else -pokemon_value(card)
        return score_search_card(cid, state, field_counts, hand_counts, discard_counts)

    if option.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, option.index, my_index)
        return score_play_card(card.id, state, select, my_state, op_state, field_counts, hand_counts) if card else -1000

    if option.type == OptionType.ATTACH:
        card = get_card(obs, option.area, option.index, my_index)
        pokemon = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if card is None or pokemon is None:
            return -1000
        if card.id in {AIR_BALLOON, BRAVE_BANGLE}:
            if card.id == BRAVE_BANGLE and pokemon.id in FESTIVAL_ATTACKERS:
                return 43000
            if card.id == BRAVE_BANGLE and pokemon.id == APPLIN:
                return 33000
            if card.id == AIR_BALLOON and pokemon.id in FESTIVAL_ATTACKERS:
                return 32000
            if card.id == AIR_BALLOON and option.inPlayArea == AreaType.ACTIVE:
                return 35000
            return 16000
        return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts)

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        active_bonus = 8000 if option.inPlayArea == AreaType.ACTIVE else 0
        target_energy = len(getattr(target, "energies", [])) if target is not None else 0
        if evolved.id == DIPPLIN:
            return 33000 + active_bonus // 2 + target_energy * 9000
        if evolved.id == THWACKEY:
            return 29500 + target_energy * 4500 + (6500 if active_has_festival(my_state, state) else 0)
        if evolved.id == SEAKING:
            return 24000 + target_energy * 5000
        return 10000

    if option.type == OptionType.ABILITY:
        card = get_card(obs, option.area, option.index, my_index)
        if card is not None and card.id == THWACKEY and active_has_festival(my_state, state):
            return 65000
        return 16000 if card is not None else 0

    if option.type == OptionType.ATTACK:
        if active is None:
            return 0
        damage = attack_damage(active, op_active, option.attackId, my_state, state)
        if op_active is not None and damage >= op_active.hp:
            return 62000 + pokemon_value(op_active)
        if active.id in FESTIVAL_ATTACKERS and has_stadium(state):
            return 21500 + damage * 18
        return 12000 + damage * 25

    return 0


def agent(obs_dict):
    if not obs_dict:
        return MY_DECK
    try:
        obs = to_observation_class(obs_dict)
        if obs.current is None or obs.select is None:
            return MY_DECK
        my_state = obs.current.players[obs.current.yourIndex]
        field_counts = count_cards([card for _, _, card in all_field_pokemon(my_state)])
        hand_counts = count_cards(my_state.hand or [])
        discard_counts = count_cards(my_state.discard or [])
        scores = [
            score_option(obs, option, field_counts, hand_counts, discard_counts)
            for option in obs.select.option
        ]
        return choose_indices(obs.select, scores)
    except Exception:
        try:
            return safe_fallback(to_observation_class(obs_dict))
        except Exception:
            return []
