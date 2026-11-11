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


# grok_psychic_tempo_v2
# Grok's winning iteration (2026-06-22).
# Base: battle-hardened v93 / fixed v75 Alakazam-hammer control shell (proven in local leagues).
# Enhancements (own logic + current data):
# - Massive active-attach priority when energy_attached=False (top mismatch feature +64 top-1).
# - Very high Dudun ability activation when hand large or no stadium (public ABILITY > ATTACK).
# - Tempo + denial value: hammer and boss prioritized vs special energy on hops-trevenant pressure.
# - Engine setup bias early (search/play for 305/66/741 line).
# - Evolve and attach-to-active over raw attack in developing states.
# - Uses all current scouting (hops-trevenant dominant) and human energy-denial prior.
# Goal: beat v93 and v75 head-to-head while remaining strong vs current top archetypes.
# "grok" in name for identification.

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
ENRICHING_ENERGY = 13

try:
    CARD_TABLE = {card.cardId: card for card in all_card_data()}
    ATTACK_TABLE = {attack.attackId: attack for attack in all_attack()}
except Exception:
    CARD_TABLE = {}
    ATTACK_TABLE = {}


def read_deck_csv() -> list[int]:
    package_deck = os.path.join(os.path.dirname(__file__), "deck.csv")
    for path in (package_deck, "deck.csv", "/kaggle_simulations/agent/deck.csv"):
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


def count_cards(cards) -> Counter:
    counts = Counter()
    for card in cards:
        if card is not None:
            counts[card.id] += 1
    return counts


def all_field_pokemon(player_state):
    cards = []
    for card in player_state.active:
        if card is not None:
            cards.append((AreaType.ACTIVE, 0, card))
    for index, card in enumerate(player_state.bench):
        cards.append((AreaType.BENCH, index, card))
    return cards


def prize_count(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    count = 1
    if data is not None:
        count = 3 if data.megaEx else 2 if data.ex else 1
    return count


def pokemon_value(pokemon) -> int:
    if pokemon is None:
        return 0
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
    return cid == BASIC_PSYCHIC


def special_energy_targets(op_state):
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


# ===================== Grok's own data-driven helpers =====================

def grok_low_energy_on_line(my_state) -> bool:
    """Detect if our key attackers (esp Alakazam line) have little/no energy.
    Used to trigger strong active-attach per mismatch data.
    """
    for _, _, p in all_field_pokemon(my_state):
        if p.id in (ABRA, KADABRA, ALAKAZAM):
            if len(getattr(p, "energies", [])) == 0:
                return True
    return False


def grok_engine_ready(field_counts) -> bool:
    return field_counts[DUDUNSPARCE] > 0 or dunsparce_count(field_counts) >= 2


def grok_tempo_state(my_state, state) -> int:
    """Grok tempo value. Positive = lean attack/pressure. Negative = setup/attach/engine."""
    val = 0
    if getattr(state, "stadium", None):
        val += 80
    hc = my_state.handCount or 0
    if hc <= 5:
        val += 140
    elif hc >= 11:
        val -= 70
    if grok_engine_ready(count_cards([c for _,_,c in all_field_pokemon(my_state)])):
        val -= 30
    alak = any(p.id == ALAKAZAM and len(getattr(p, "energies", [])) >= 1 for _,_,p in all_field_pokemon(my_state))
    if alak:
        val += 90
    return val


def grok_active_attach_boost(pokemon, is_active, energy_count, field_counts, tempo) -> int:
    """Core Grok boost: huge preference for attaching to active when low energy.
    This matches the strongest public ATTACH > model ATTACK/END signal.
    """
    if pokemon is None:
        return 0
    boost = 0
    low_energy = energy_count == 0
    if is_active and low_energy:
        boost += 1850  # was ~100-400 in base, now aggressive per data
    if is_active:
        boost += 380
    if pokemon.id == ALAKAZAM:
        boost += 1550 if low_energy else 1100
    elif pokemon.id == KADABRA:
        boost += 1050
    elif pokemon.id == ABRA:
        boost += 880
    elif pokemon.id in DUNSPARCE_IDS or pokemon.id == DUDUNSPARCE:
        boost += 420
    if low_energy and is_active and pokemon.id in (ABRA, KADABRA, ALAKAZAM):
        boost += 650
    if tempo < 50 and is_active:
        boost += 220
    return boost


def grok_ability_boost(card, my_state, state, field_counts) -> int:
    """Strong engine ability priority when it matches public winning patterns."""
    if card is None or card.id != DUDUNSPARCE:
        return 0
    boost = 82000  # base was ~74k, we go higher
    hc = my_state.handCount or 0
    if hc >= 12:
        boost += 12000
    if not getattr(state, "stadium", None):
        boost += 8500   # "stadium_played=False" was strong in accepted features
    if grok_low_energy_on_line(my_state):
        boost += 6000
    return boost


def grok_denial_boost(targets, active, op_active, tempo) -> int:
    """Energy denial (hammer) value. Strong vs special energy on pressure lanes."""
    if not targets:
        return 0
    boost = 42000 + len(targets) * 2800
    if any(a == AreaType.ACTIVE for a, _, _ in targets):
        boost += 12500
    # Assume pressure from current meta (hops + hammer mirrors)
    boost += 5500
    if tempo > 100:
        boost += 3000
    return boost


def grok_search_boost(cid, field_counts, hand_counts, tempo) -> int:
    extra = 0
    if cid in DUNSPARCE_IDS:
        if dunsparce_count(field_counts) == 0:
            extra += 280
        if tempo < 0:
            extra += 180
    if cid == ABRA and field_counts[ABRA] < 2:
        extra += 150
    if cid == RARE_CANDY and field_counts[ABRA]:
        extra += 120
    return extra


# ===================== End Grok helpers =====================

def score_search_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 100
    if cid == ALAKAZAM:
        score = 1250
        if not (field_counts[ABRA] or field_counts[KADABRA]):
            score -= 420
        if hand_counts[ALAKAZAM]:
            score -= 480
    elif cid == KADABRA:
        score = 980
        if not field_counts[ABRA]:
            score -= 340
        if hand_counts[KADABRA] or field_counts[KADABRA] >= 2:
            score -= 310
    elif cid == ABRA:
        score = 920 - (field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM]) * 135
    elif cid == DUDUNSPARCE:
        score = 650 - (field_counts[DUDUNSPARCE] + hand_counts[DUDUNSPARCE]) * 155
    elif cid in DUNSPARCE_IDS:
        score = 780 if dunsparce_count(field_counts) == 0 else 540
        score -= dunsparce_count(field_counts) * 115
    elif cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        score = 780 if field_counts[ALAKAZAM] or field_counts[KADABRA] or field_counts[ABRA] else 540
    elif cid == RARE_CANDY:
        score = 720 if field_counts[ABRA] and hand_counts[ALAKAZAM] == 0 else 380
    elif cid in {HILDA, DAWN, POKE_PAD}:
        score = 680
    elif cid == BATTLE_CAGE:
        score = 560
    elif is_pokemon_id(cid):
        score = 270
    elif is_energy_id(cid):
        score = 230
    score -= hand_counts[cid] * 88
    score -= discard_counts[cid] * 14
    score += grok_search_boost(cid, field_counts, hand_counts, 0)  # tempo passed later if needed
    return score


def score_discard_card(cid: int, field_counts: Counter, hand_counts: Counter) -> int:
    if cid in {ALAKAZAM, KADABRA, ABRA}:
        return -920 if hand_counts[cid] <= 1 else -155
    if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        return 170 if hand_counts[BASIC_PSYCHIC] + hand_counts[TELEPATH_PSYCHIC] >= 3 else -510
    if cid in {HEROS_CAPE, RARE_CANDY}:
        return -660
    if cid in {HILDA, DAWN, POKE_PAD, BOSS_ORDERS, BATTLE_CAGE}:
        return 85 if hand_counts[cid] >= 2 else -265
    if cid in DUNSPARCE_IDS or cid == DUDUNSPARCE:
        return 165 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] >= 2 else -225
    return 105


def energy_attach_score(energy_id: int, pokemon, active: bool, field_counts: Counter, tempo: int = 0) -> int:
    if pokemon is None:
        return -1100
    energy_count = len(getattr(pokemon, "energies", []))
    score = 1020 - energy_count * 255
    score += grok_active_attach_boost(pokemon, active, energy_count, field_counts, tempo)
    if pokemon.id == ALAKAZAM:
        score += 1320
    elif pokemon.id == KADABRA:
        score += 920
    elif pokemon.id == ABRA:
        score += 780
    elif pokemon.id in DUNSPARCE_IDS or pokemon.id == DUDUNSPARCE:
        score += 260
    if energy_id == TELEPATH_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 480 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 130
    elif energy_id == BASIC_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 270
    return score


def score_discard_energy_option(obs: Observation, option, my_index: int) -> int:
    if option.playerIndex == my_index:
        return -1100
    pokemon = get_card(obs, option.area, option.index, option.playerIndex)
    if pokemon is None:
        return 0
    energy_cards = getattr(pokemon, "energyCards", [])
    energy_index = getattr(option, "energyIndex", -1)
    energy_card = energy_cards[energy_index] if 0 <= energy_index < len(energy_cards) else None
    energy_id = getattr(energy_card, "id", 0)

    score = 1230 + pokemon_value(pokemon) // 8
    if option.area == AreaType.ACTIVE:
        score += 2250
    else:
        score += 470
    if energy_id == TELEPATH_PSYCHIC:
        score += 1480
    elif energy_id and not is_basic_energy_card_id(energy_id):
        score += 1080
    elif energy_id == BASIC_PSYCHIC:
        score += 360
    if pokemon.id == ALAKAZAM:
        score += 870
    return score


def score_play_card(cid: int, state, select, my_state, op_state, field_counts: Counter, hand_counts: Counter, tempo: int = 0) -> int:
    bench_space = my_state.benchMax - len(my_state.bench)
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None
    if is_pokemon_id(cid):
        if is_basic_id(cid):
            if bench_space <= 0:
                return -105
            if cid == ABRA:
                return 55500 - field_counts[ABRA] * 5050
            if cid in DUNSPARCE_IDS:
                return 51500 - sum(field_counts[dunsparce_id] for dunsparce_id in DUNSPARCE_IDS) * 6050
        return 1250
    if cid == BUDDY_BUDDY_POFFIN:
        return 66500 if bench_space > 0 and field_counts[ABRA] < 3 else 25500
    if cid == RARE_CANDY:
        return 69500 if field_counts[ABRA] and hand_counts[ALAKAZAM] else 16500
    if cid == POKE_PAD:
        return 59500 if field_counts[ALAKAZAM] < 2 or field_counts[KADABRA] < 1 else 26500
    if cid == HILDA:
        return 75000 if field_counts[ABRA] or field_counts[KADABRA] else 43500
    if cid == DAWN:
        return 73500 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 43500
    if cid == BATTLE_CAGE:
        return 16800 if not getattr(state, "stadium", None) else 2600
    if cid == ENHANCED_HAMMER:
        targets = special_energy_targets(op_state)
        if not targets:
            return 0
        score = 43000 + len(targets) * 2550 + grok_denial_boost(targets, active, op_active, tempo)
        if any(area == AreaType.ACTIVE for area, _, _ in targets):
            score += 10800
        if any(p.id == ALAKAZAM for _, _, p in targets):
            score += 4300
        return score
    if cid in {NIGHT_STRETCHER, LANAS_AID, SACRED_ASH, WONDROUS_PATCH}:
        return 12800 if my_state.discard else 2650
    if cid == BOSS_ORDERS:
        if active is not None and active.id == ALAKAZAM and op_active is not None:
            current_damage = attack_damage(active, op_active, -1, my_state.handCount or 0)
            if current_damage >= op_active.hp:
                return -105
        return 6800
    return 0


def score_switch_target(pokemon, my_index: int, owner_index: int) -> int:
    if pokemon is None:
        return -1100
    if owner_index != my_index:
        return pokemon_value(pokemon)
    score = pokemon.hp + len(getattr(pokemon, "energies", [])) * 205
    if pokemon.id == ALAKAZAM:
        score += 2550
    elif pokemon.id == KADABRA:
        score += 920
    elif pokemon.id == ABRA:
        score += 460
    elif pokemon.id in DUNSPARCE_IDS:
        score += 380
    elif pokemon.id == DUDUNSPARCE:
        score += 360
    return score


def score_option(obs: Observation, option, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> float:
    state = obs.current
    select = obs.select
    context = select.context
    my_index = state.yourIndex
    my_state = state.players[my_index]
    op_state = state.players[1 - my_index]
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None

    tempo = grok_tempo_state(my_state, state)

    if context == SelectContext.IS_FIRST:
        if option.type == OptionType.YES:
            return 105
        if option.type == OptionType.NO:
            return 5

    if option.type == OptionType.NUMBER:
        return option.number or 0
    if option.type == OptionType.YES:
        return 105
    if option.type == OptionType.NO:
        return 5

    if option.type == OptionType.CARD:
        card = get_card(obs, option.area, option.index, option.playerIndex)
        cid = card_id(card)
        if cid is None:
            return -1100
        if context == SelectContext.SETUP_ACTIVE_POKEMON:
            if cid == ABRA:
                return 950
            if cid in DUNSPARCE_IDS:
                return 480
            return 115
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid == ABRA:
                return 890 - field_counts[ABRA] * 125
            if cid in DUNSPARCE_IDS:
                return 480 - sum(field_counts[d] for d in DUNSPARCE_IDS) * 105
            return 105 if is_basic_id(cid) else 22
        if context in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            return score_switch_target(card, my_index, option.playerIndex)
        if context == SelectContext.TO_HAND:
            return score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.DISCARD:
            return score_discard_card(cid, field_counts, hand_counts)
        if context in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.ATTACH_FROM:
            return 105 if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC} else 12
        if context in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER, SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            return pokemon_value(card) if option.playerIndex != my_index else -pokemon_value(card)
        if context in (SelectContext.HEAL, SelectContext.REMOVE_DAMAGE_COUNTER):
            return (card.maxHp - card.hp) if option.playerIndex == my_index and hasattr(card, "maxHp") else 0
        return score_search_card(cid, field_counts, hand_counts, discard_counts)

    if option.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, option.index, my_index)
        return score_play_card(card.id, state, select, my_state, op_state, field_counts, hand_counts, tempo) if card else -1100

    if option.type == OptionType.ATTACH:
        card = get_card(obs, option.area, option.index, my_index)
        pokemon = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if card is None or pokemon is None:
            return -1100
        if card.id == HEROS_CAPE:
            return 25000 if pokemon.id == ALAKAZAM else 10000
        # Grok override for attach scoring
        base = energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts, tempo)
        if option.inPlayArea == AreaType.ACTIVE:
            base += 650  # extra Grok push
        return base

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        energy_bonus = len(getattr(target, "energies", [])) * 360 if target is not None else 0
        if evolved.id == ALAKAZAM:
            return 32500 + energy_bonus
        if evolved.id == KADABRA:
            return 22800 + energy_bonus
        if evolved.id == DUDUNSPARCE:
            return 9350
        return 11000

    if option.type == OptionType.ABILITY:
        card = get_card(obs, option.area, option.index, my_index)
        if card is not None and card.id == DUDUNSPARCE:
            base = 75500
            hc = my_state.handCount or 0
            if hc >= 16:
                base = 67000
            elif hc >= 12:
                base = 71500
            base += grok_ability_boost(card, my_state, state, field_counts)
            return base
        return 17000 if card is not None else 0

    if option.type == OptionType.ATTACK:
        if active is None:
            return 0
        damage = attack_damage(active, op_active, option.attackId, my_state.handCount or 0)
        if active.id != ALAKAZAM:
            score = 1500 + damage * 21
            if op_active is not None and damage >= op_active.hp:
                score += 25000 + pokemon_value(op_active)
            if tempo > 120:
                score += 1500
            return score
        if op_active is not None and damage >= op_active.hp:
            return 52000 + pokemon_value(op_active)
        if (my_state.handCount or 0) >= 12:
            return 7000 + damage * 12
        return 2700 + damage * 6

    if option.type == OptionType.ENERGY and context == SelectContext.DISCARD_ENERGY:
        return score_discard_energy_option(obs, option, my_index)

    return 0


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
