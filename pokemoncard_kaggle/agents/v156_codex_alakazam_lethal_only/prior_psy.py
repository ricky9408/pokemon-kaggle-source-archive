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


# DENPA92-style Alakazam list from fresh public replay episode 80380232.
# Updated deck uses newer Dunsparce (305) + Dudunsparce (66).
DECK = [
    19, 19, 19, 19,
    305, 305, 305, 305,
    66, 66, 66,
    741, 741, 741, 741,
    742, 742, 742, 742,
    743, 743, 743, 743,
    1086, 1086, 1086, 1086,
    1079, 1079, 1079, 1079,
    1081, 1081, 1081, 1081,
    1097, 1097, 1097,
    1129,
    1152, 1152, 1152, 1152,
    1182, 1182, 1182,
    1184,
    1225, 1225, 1225, 1225,
    1231, 1231, 1231, 1231,
    1264,
    5, 5, 5,
    13,
]

BASIC_PSYCHIC = 5
TELEPATH_PSYCHIC = 19
DUNSPARCE = 65
DUNSPARCE_ALT = 305
DUNSPARCE_IDS = {DUNSPARCE, DUNSPARCE_ALT}
DUDUNSPARCE = 66
ABRA = 741
KADABRA = 742
ALAKAZAM = 743
RARE_CANDY = 1079
ENHANCED_HAMMER = 1081
BUDDY_BUDDY_POFFIN = 1086
NIGHT_STRETCHER = 1097
SACRED_ASH = 1129
WONDROUS_PATCH = 1146
POKE_PAD = 1152
HEROS_CAPE = 1159
BOSS_ORDERS = 1182
LANAS_AID = 1184
HILDA = 1225
DAWN = 1231
BATTLE_CAGE = 1264

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


def is_pokemon_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType == CardType.POKEMON
    return cid in {*DUNSPARCE_IDS, DUDUNSPARCE, ABRA, KADABRA, ALAKAZAM}


def is_energy_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType in (CardType.BASIC_ENERGY, CardType.SPECIAL_ENERGY)
    return cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}


def is_basic_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return bool(data.basic)
    return cid in {*DUNSPARCE_IDS, ABRA}


def dunsparce_count(counts: Counter) -> int:
    return sum(counts[cid] for cid in DUNSPARCE_IDS) + counts[DUDUNSPARCE]


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


def prize_count(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    count = 1
    if data is not None:
        count = 3 if data.megaEx else 2 if data.ex else 1
    return count


def pokemon_value(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    score = prize_count(pokemon) * 1000 + pokemon.hp
    score += len(getattr(pokemon, "energies", [])) * 180
    score += len(getattr(pokemon, "tools", [])) * 100
    if data is not None:
        if data.stage2:
            score += 300
        elif data.stage1:
            score += 140
        if data.ex or data.megaEx:
            score += 420
    if pokemon.id == ALAKAZAM:
        score += 400
    return score


def is_basic_energy_card_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType == CardType.BASIC_ENERGY
    return cid == BASIC_PSYCHIC  # 13 (Enriching) and other specials will be treated as non-basic via table when present


def special_energy_targets(op_state) -> list[tuple[object, int, int]]:
    targets = []
    for area, index, pokemon in all_field_pokemon(op_state):
        for energy_card in getattr(pokemon, "energyCards", []):
            energy_id = getattr(energy_card, "id", None)
            if energy_id is not None and not is_basic_energy_card_id(energy_id):
                targets.append((area, index, pokemon))
                break
    return targets


def attack_damage(active, op_active, attack_id: int, my_hand_count: int) -> int:
    if active is None or op_active is None:
        return 0
    if active.id == ALAKAZAM:
        return max(0, my_hand_count) * 20
    attack = ATTACK_TABLE.get(attack_id)
    damage = int(getattr(attack, "damage", 0) or 0) if attack is not None else 0
    damage_type = None
    if attack is not None:
        for energy in attack.energies:
            if energy != EnergyType.COLORLESS:
                damage_type = energy
                break
    data = CARD_TABLE.get(op_active.id)
    if data is not None and damage_type is not None:
        if data.weakness == damage_type:
            damage *= 2
        elif data.resistance == damage_type:
            damage = max(0, damage - 30)
    return damage


def score_search_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 100
    if cid == ALAKAZAM:
        score = 1200
        if not (field_counts[ABRA] or field_counts[KADABRA]):
            score -= 450
        if hand_counts[ALAKAZAM]:
            score -= 500
    elif cid == KADABRA:
        score = 950
        if not field_counts[ABRA]:
            score -= 350
        if hand_counts[KADABRA] or field_counts[KADABRA] >= 2:
            score -= 320
    elif cid == ABRA:
        score = 900 - (field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM]) * 140
    elif cid == DUDUNSPARCE:
        score = 620 - (field_counts[DUDUNSPARCE] + hand_counts[DUDUNSPARCE]) * 160
    elif cid in DUNSPARCE_IDS:
        score = 760 if dunsparce_count(field_counts) == 0 else 520
        score -= dunsparce_count(field_counts) * 120
    elif cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        score = 760 if field_counts[ALAKAZAM] or field_counts[KADABRA] or field_counts[ABRA] else 520
    elif cid == RARE_CANDY:
        score = 700 if field_counts[ABRA] and hand_counts[ALAKAZAM] == 0 else 360
    elif cid in {HILDA, DAWN, POKE_PAD}:
        score = 660
    elif cid == BATTLE_CAGE:
        score = 540
    elif is_pokemon_id(cid):
        score = 260
    elif is_energy_id(cid):
        score = 220
    score -= hand_counts[cid] * 90
    score -= discard_counts[cid] * 15
    return score


def score_discard_card(cid: int, field_counts: Counter, hand_counts: Counter) -> int:
    if cid in {ALAKAZAM, KADABRA, ABRA}:
        return -900 if hand_counts[cid] <= 1 else -150
    if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        return 160 if hand_counts[BASIC_PSYCHIC] + hand_counts[TELEPATH_PSYCHIC] >= 3 else -500
    if cid in {HEROS_CAPE, RARE_CANDY}:
        return -650
    if cid in {HILDA, DAWN, POKE_PAD, BOSS_ORDERS, BATTLE_CAGE}:
        return 80 if hand_counts[cid] >= 2 else -260
    if cid in DUNSPARCE_IDS or cid == DUDUNSPARCE:
        return 160 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] >= 2 else -220
    return 100


def energy_attach_score(energy_id: int, pokemon, active: bool, field_counts: Counter) -> int:
    if pokemon is None:
        return -1000
    if pokemon.id in DUNSPARCE_IDS or pokemon.id == DUDUNSPARCE:
        return -1000
    energy_count = len(getattr(pokemon, "energies", []))
    score = 1000 - energy_count * 250
    if active:
        score += 100
    if pokemon.id == ALAKAZAM:
        score += 1250
    elif pokemon.id == KADABRA:
        score += 900
    elif pokemon.id == ABRA:
        score += 760
    if energy_id == TELEPATH_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 450 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 120
    elif energy_id == BASIC_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 260
    return score


def score_discard_energy_option(obs: Observation, option, my_index: int) -> int:
    if option.playerIndex == my_index:
        return -1000
    pokemon = get_card(obs, option.area, option.index, option.playerIndex)
    if pokemon is None:
        return 0
    energy_cards = getattr(pokemon, "energyCards", [])
    energy_index = getattr(option, "energyIndex", -1)
    energy_card = energy_cards[energy_index] if 0 <= energy_index < len(energy_cards) else None
    energy_id = getattr(energy_card, "id", 0)

    score = 1200 + pokemon_value(pokemon) // 8
    if option.area == AreaType.ACTIVE:
        score += 2200
    else:
        score += 450
    if energy_id == TELEPATH_PSYCHIC:
        score += 1450
    elif energy_id and not is_basic_energy_card_id(energy_id):
        score += 1050
    elif energy_id == BASIC_PSYCHIC:
        score += 350
    if pokemon.id == ALAKAZAM:
        score += 850
    return score


def score_play_card(cid: int, state, select, my_state, op_state, field_counts: Counter, hand_counts: Counter) -> int:
    bench_space = my_state.benchMax - len(my_state.bench)
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None
    if is_pokemon_id(cid):
        if is_basic_id(cid):
            if bench_space <= 0:
                return -100
            if cid == ABRA:
                return 54000 - field_counts[ABRA] * 5000
            if cid in DUNSPARCE_IDS:
                return 50000 - sum(field_counts[dunsparce_id] for dunsparce_id in DUNSPARCE_IDS) * 6000
        return 1200
    if cid == BUDDY_BUDDY_POFFIN:
        return 65000 if bench_space > 0 and field_counts[ABRA] < 3 else 25000
    if cid == RARE_CANDY:
        return 68000 if field_counts[ABRA] and hand_counts[ALAKAZAM] else 16000
    if cid == POKE_PAD:
        return 58000 if field_counts[ALAKAZAM] < 2 or field_counts[KADABRA] < 1 else 26000
    if cid == HILDA:
        return 73500 if field_counts[ABRA] or field_counts[KADABRA] else 42000
    if cid == DAWN:
        return 72000 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 42000
    if cid == BATTLE_CAGE:
        return 16000 if not state.stadium else 2500
    if cid == ENHANCED_HAMMER:
        targets = special_energy_targets(op_state)
        if not targets:
            return 0
        if active is not None and active.id == ALAKAZAM and op_active is not None:
            if attack_damage(active, op_active, -1, my_state.handCount) >= op_active.hp:
                return 11000
        score = 41500 + len(targets) * 2500
        if any(area == AreaType.ACTIVE for area, _, _ in targets):
            score += 10500
        if any(pokemon.id == ALAKAZAM for _, _, pokemon in targets):
            score += 4500
        return score
    if cid in {NIGHT_STRETCHER, LANAS_AID, SACRED_ASH, WONDROUS_PATCH}:
        return 12000 if my_state.discard else 2500
    if cid == BOSS_ORDERS:
        if active is not None and active.id == ALAKAZAM and op_active is not None:
            current_damage = attack_damage(active, op_active, -1, my_state.handCount)
            if current_damage >= op_active.hp:
                return -100
            for bench_pokemon in op_state.bench:
                if attack_damage(active, bench_pokemon, -1, my_state.handCount) >= bench_pokemon.hp:
                    return 21000 + pokemon_value(bench_pokemon)
        return 6500
    return 0


def score_switch_target(pokemon, my_index: int, owner_index: int) -> int:
    if pokemon is None:
        return -1000
    if owner_index != my_index:
        return pokemon_value(pokemon)
    score = pokemon.hp + len(getattr(pokemon, "energies", [])) * 200
    if pokemon.id == ALAKAZAM:
        score += 2500
    elif pokemon.id == KADABRA:
        score += 900
    elif pokemon.id == ABRA:
        score += 450
    elif pokemon.id in DUNSPARCE_IDS:
        score += 350
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
            if cid == ABRA:
                return 900
            if cid in DUNSPARCE_IDS:
                return 450
            return 100
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid == ABRA:
                return 850 - field_counts[ABRA] * 120
            if cid in DUNSPARCE_IDS:
                return 450 - sum(field_counts[dunsparce_id] for dunsparce_id in DUNSPARCE_IDS) * 100
            return 100 if is_basic_id(cid) else 20
        if context in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            return score_switch_target(card, my_index, option.playerIndex)
        if context == SelectContext.TO_HAND:
            return score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.DISCARD:
            return score_discard_card(cid, field_counts, hand_counts)
        if context in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.ATTACH_FROM:
            return 100 if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC} else 0
        if context in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER, SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            return pokemon_value(card) if option.playerIndex != my_index else -pokemon_value(card)
        if context in (SelectContext.HEAL, SelectContext.REMOVE_DAMAGE_COUNTER):
            return (card.maxHp - card.hp) if option.playerIndex == my_index and hasattr(card, "maxHp") else 0
        return score_search_card(cid, field_counts, hand_counts, discard_counts)

    if option.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, option.index, my_index)
        return score_play_card(card.id, state, select, my_state, op_state, field_counts, hand_counts) if card else -1000

    if option.type == OptionType.ATTACH:
        card = get_card(obs, option.area, option.index, my_index)
        pokemon = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if card is None or pokemon is None:
            return -1000
        if card.id == HEROS_CAPE:
            return 23000 if pokemon.id == ALAKAZAM else 9000
        return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts)

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        energy_bonus = len(getattr(target, "energies", [])) * 350 if target is not None else 0
        if evolved.id == ALAKAZAM:
            return 30000 + energy_bonus
        if evolved.id == KADABRA:
            return 21000 + energy_bonus
        if evolved.id == DUDUNSPARCE:
            return 8500
        return 10000

    if option.type == OptionType.ABILITY:
        card = get_card(obs, option.area, option.index, my_index)
        if card is not None and card.id == DUDUNSPARCE:
            field_total = sum(1 for _, _, pokemon in all_field_pokemon(my_state) if pokemon is not None)
            if field_total <= 1:
                return -200000
            attached_energy = len(getattr(card, "energyCards", [])) + len(getattr(card, "energies", []))
            energy_penalty = 12000 * attached_energy
            if my_state.handCount >= 16:
                return 64000 - energy_penalty
            if my_state.handCount >= 12:
                return 69000 - energy_penalty
            return 74000 - energy_penalty
        return 16000 if card is not None else 0

    if option.type == OptionType.ATTACK:
        if active is None:
            return 0
        damage = attack_damage(active, op_active, option.attackId, my_state.handCount)
        if active.id != ALAKAZAM:
            score = 1400 + damage * 20
            if op_active is not None and damage >= op_active.hp:
                score += 24000 + pokemon_value(op_active)
            return score
        if op_active is not None and damage >= op_active.hp:
            return 50000 + pokemon_value(op_active)
        if my_state.handCount >= 12:
            return 6500 + damage * 12
        return 2500 + damage * 6

    if option.type == OptionType.ENERGY and context == SelectContext.DISCARD_ENERGY:
        return score_discard_energy_option(obs, option, my_index)

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
