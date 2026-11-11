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


# Grok Psychic Tempo Control v1
# Complete new implementation (2026-06-22).
# Base shell: proven Alakazam + Dudunsparce engine + hammer control.
# Deck uses current data (305 Dunsparce + 66 Dudunsparce).
# Own logics: layered scoring with heavy emphasis on
#   - engine activation timing (Dudun ability before attack when conditions match mismatch data)
#   - active attachment priority (strongest recent public ATTACH->ACTIVE signal)
#   - tempo-aware search/play (stadium/supporter/hand context)
#   - prize pressure + denial value
#   - conditional energy tax on opponent
# Uses full CARD_TABLE + current top meta signals (Hops Trevenant heavy, Alakazam variants, Battle Cage).

DECK = [
    19, 19, 19, 19,  # Telepath Psychic Energy
    305, 305, 305, 305,  # Dunsparce (newer print)
    66, 66, 66,  # Dudunsparce
    741, 741, 741, 741,  # Abra
    742, 742, 742, 742,  # Kadabra
    743, 743, 743, 743,  # Alakazam
    1086, 1086, 1086, 1086,  # Buddy-Buddy Poffin
    1079, 1079, 1079, 1079,  # Rare Candy
    1081, 1081, 1081, 1081,  # Enhanced Hammer
    1097, 1097, 1097,  # Night Stretcher
    1129,  # Sacred Ash
    1152, 1152, 1152, 1152,  # Poké Pad
    1182, 1182, 1182,  # Boss's Orders
    1184,  # Lana's Aid
    1225, 1225, 1225, 1225,  # Hilda
    1231, 1231, 1231, 1231,  # Dawn
    1264,  # Battle Cage
    5, 5, 5,  # Basic Psychic
    13,  # Enriching Energy (tech)
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


def grok_tempo_signal(state, my_state, field_counts) -> int:
    """Grok's own tempo / state value signal.
    Positive when we want to be aggressive / attach / attack.
    Negative favors search / setup / engine.
    Uses observable flags from current data (stadium, supporters implied via hand, energy state).
    """
    signal = 0
    # Stadium presence is a big tempo marker from mismatch reports
    if getattr(state, "stadium", None):
        signal += 120
    # Hand size proxy for "we have played supporters or are in mid game"
    if my_state.handCount is not None:
        if my_state.handCount <= 4:
            signal += 180  # desperate tempo
        elif my_state.handCount >= 10:
            signal -= 80   # still in setup / engine phase
    # Energy state on our Alakazam line
    alakazam_ready = False
    for _, _, p in all_field_pokemon(my_state):
        if p.id == ALAKAZAM and len(getattr(p, "energies", [])) >= 1:
            alakazam_ready = True
            break
    if alakazam_ready:
        signal += 140
    # Bench development (engine online)
    if field_counts[DUDUNSPARCE] + field_counts[DUNSPARCE] + field_counts[ABRA] + field_counts[KADABRA] >= 3:
        signal -= 60  # still developing, favor search/attach
    return signal


def grok_engine_priority(my_state, field_counts, hand_counts) -> int:
    """Strong priority for activating Dudunsparce engine.
    Inspired by public ABILITY-over-ATTACK signals and human control priors.
    """
    score = 0
    dudun_on_field = field_counts[DUDUNSPARCE] > 0
    engine_pieces = dunsparce_count(field_counts) + field_counts[ABRA] + field_counts[KADABRA]
    if not dudun_on_field and engine_pieces >= 1:
        score += 22000  # high desire to get the ability online
    if my_state.handCount is not None and my_state.handCount >= 8 and dudun_on_field:
        score += 18000  # big hand + engine = fire ability
    # If we have no stadium (common in mismatch wins for ability), push harder
    if not getattr(my_state, "stadium", None) and dudun_on_field:  # stadium is on state actually
        score += 8000
    return score


def grok_active_attach_bonus(pokemon, active: bool, energy_count: int, field_counts) -> int:
    """Grok's active-attach bias (strongest recent public ATTACH to ACTIVE signal).
    Especially valuable when energy_attached=False on our side and vs Trevenant pressure.
    """
    bonus = 0
    if pokemon is None:
        return -2000
    if active:
        bonus += 420  # core insight: attach to active is frequently the public choice
    if pokemon.id == ALAKAZAM:
        bonus += 1450
    elif pokemon.id == KADABRA:
        bonus += 980
    elif pokemon.id == ABRA:
        bonus += 820
    elif pokemon.id in DUNSPARCE_IDS or pokemon.id == DUDUNSPARCE:
        bonus += 380
    if energy_count == 0:
        bonus += 650  # very high when no energy yet
    if active and pokemon.id == ALAKAZAM:
        bonus += 300
    return bonus


def score_search_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter, tempo: int) -> int:
    score = 100
    if cid == ALAKAZAM:
        score = 1350
        if not (field_counts[ABRA] or field_counts[KADABRA]):
            score -= 480
        if hand_counts[ALAKAZAM]:
            score -= 520
    elif cid == KADABRA:
        score = 1050
        if not field_counts[ABRA]:
            score -= 380
        if hand_counts[KADABRA] or field_counts[KADABRA] >= 2:
            score -= 340
    elif cid == ABRA:
        score = 980 - (field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM]) * 150
    elif cid == DUDUNSPARCE:
        score = 680 - (field_counts[DUDUNSPARCE] + hand_counts[DUDUNSPARCE]) * 170
    elif cid in DUNSPARCE_IDS:
        # Grok: engine basics are extremely high early / when we need the ability
        base = 880 if dunsparce_count(field_counts) + field_counts[DUDUNSPARCE] == 0 else 580
        score = base - dunsparce_count(field_counts) * 130
        if tempo < 0:  # still in setup phase
            score += 220
    elif cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        score = 820 if field_counts[ALAKAZAM] or field_counts[KADABRA] or field_counts[ABRA] else 580
    elif cid == RARE_CANDY:
        score = 780 if field_counts[ABRA] and hand_counts[ALAKAZAM] == 0 else 420
    elif cid in {HILDA, DAWN, POKE_PAD}:
        score = 720
    elif cid == BATTLE_CAGE:
        score = 620
    elif is_pokemon_id(cid):
        score = 290
    elif is_energy_id(cid):
        score = 240
    score -= hand_counts[cid] * 95
    score -= discard_counts[cid] * 18
    return score


def score_play_card(cid: int, state, select, my_state, op_state, field_counts: Counter, hand_counts: Counter, tempo: int) -> int:
    bench_space = my_state.benchMax - len(my_state.bench)
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None
    if is_pokemon_id(cid):
        if is_basic_id(cid):
            if bench_space <= 0:
                return -120
            if cid == ABRA:
                return 58000 - field_counts[ABRA] * 5200
            if cid in DUNSPARCE_IDS:
                # Grok values early engine setup very highly
                val = 54000 - sum(field_counts[d] for d in DUNSPARCE_IDS) * 6200
                if tempo < 80:
                    val += 4500
                return val
        return 1350
    if cid == BUDDY_BUDDY_POFFIN:
        return 68000 if bench_space > 0 and field_counts[ABRA] < 3 else 27000
    if cid == RARE_CANDY:
        return 72000 if field_counts[ABRA] and hand_counts[ALAKAZAM] == 0 else 17500
    if cid == POKE_PAD:
        return 61000 if field_counts[ALAKAZAM] < 2 or field_counts[KADABRA] < 1 else 28000
    if cid == HILDA:
        return 76000 if field_counts[ABRA] or field_counts[KADABRA] else 45000
    if cid == DAWN:
        return 74000 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 44000
    if cid == BATTLE_CAGE:
        return 17500 if not getattr(state, "stadium", None) else 2800
    if cid == ENHANCED_HAMMER:
        targets = special_energy_targets(op_state)
        if not targets:
            return 0
        # Grok conditional hammer: big value when we can tax a real attacker
        score = 44000 + len(targets) * 2600
        if any(area == AreaType.ACTIVE for area, _, _ in targets):
            score += 11500
        if any(p.id == ALAKAZAM for _, _, p in targets):  # rare but mirror
            score += 4200
        # vs Trevenant archetype from data we love denial
        score += 3800
        return score
    if cid in {NIGHT_STRETCHER, LANAS_AID, SACRED_ASH, WONDROUS_PATCH}:
        return 13500 if my_state.discard else 2800
    if cid == BOSS_ORDERS:
        if active is not None and active.id == ALAKAZAM and op_active is not None:
            dmg = attack_damage(active, op_active, -1, my_state.handCount or 0)
            if dmg >= op_active.hp:
                return -120
        return 7200
    return 0


def energy_attach_score(energy_id: int, pokemon, active: bool, field_counts: Counter, tempo: int) -> int:
    if pokemon is None:
        return -1200
    energy_count = len(getattr(pokemon, "energies", []))
    score = 1050 - energy_count * 260
    score += grok_active_attach_bonus(pokemon, active, energy_count, field_counts)
    if pokemon.id == ALAKAZAM:
        score += 1350
    elif pokemon.id == KADABRA:
        score += 950
    elif pokemon.id == ABRA:
        score += 810
    elif pokemon.id in DUNSPARCE_IDS or pokemon.id == DUDUNSPARCE:
        score += 320
    # Grok special for Telepath (engine fuel)
    if energy_id == TELEPATH_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 520 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] < 3 else 140
    elif energy_id == BASIC_PSYCHIC and pokemon.id in {ABRA, KADABRA, ALAKAZAM}:
        score += 280
    if tempo < 0 and active:
        score += 180  # still building, favor active
    return score


def score_discard_energy_option(obs: Observation, option, my_index: int) -> int:
    if option.playerIndex == my_index:
        return -1200
    pokemon = get_card(obs, option.area, option.index, option.playerIndex)
    if pokemon is None:
        return 0
    energy_cards = getattr(pokemon, "energyCards", [])
    energy_index = getattr(option, "energyIndex", -1)
    energy_card = energy_cards[energy_index] if 0 <= energy_index < len(energy_cards) else None
    energy_id = getattr(energy_card, "id", 0)

    score = 1250 + pokemon_value(pokemon) // 9
    if option.area == AreaType.ACTIVE:
        score += 2350
    else:
        score += 520
    if energy_id == TELEPATH_PSYCHIC:
        score += 1550
    elif energy_id and not is_basic_energy_card_id(energy_id):
        score += 1120
    elif energy_id == BASIC_PSYCHIC:
        score += 380
    if pokemon.id == ALAKAZAM:
        score += 920
    return score


def score_switch_target(pokemon, my_index: int, owner_index: int) -> int:
    if pokemon is None:
        return -1200
    if owner_index != my_index:
        return pokemon_value(pokemon)
    score = pokemon.hp + len(getattr(pokemon, "energies", [])) * 210
    if pokemon.id == ALAKAZAM:
        score += 2650
    elif pokemon.id == KADABRA:
        score += 980
    elif pokemon.id == ABRA:
        score += 480
    elif pokemon.id in DUNSPARCE_IDS:
        score += 420
    elif pokemon.id == DUDUNSPARCE:
        score += 380
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

    tempo = grok_tempo_signal(state, my_state, field_counts)

    if context == SelectContext.IS_FIRST:
        if option.type == OptionType.YES:
            return 110
        if option.type == OptionType.NO:
            return 10

    if option.type == OptionType.NUMBER:
        return option.number or 0
    if option.type == OptionType.YES:
        return 110
    if option.type == OptionType.NO:
        return 10

    if option.type == OptionType.CARD:
        card = get_card(obs, option.area, option.index, option.playerIndex)
        cid = card_id(card)
        if cid is None:
            return -1200
        if context == SelectContext.SETUP_ACTIVE_POKEMON:
            if cid == ABRA:
                return 980
            if cid in DUNSPARCE_IDS:
                return 520
            return 120
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid == ABRA:
                return 920 - field_counts[ABRA] * 130
            if cid in DUNSPARCE_IDS:
                return 520 - sum(field_counts[d] for d in DUNSPARCE_IDS) * 110
            return 110 if is_basic_id(cid) else 25
        if context in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            return score_switch_target(card, my_index, option.playerIndex)
        if context == SelectContext.TO_HAND:
            return score_search_card(cid, field_counts, hand_counts, discard_counts, tempo)
        if context == SelectContext.DISCARD:
            return score_discard_card(cid, field_counts, hand_counts)
        if context in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -score_search_card(cid, field_counts, hand_counts, discard_counts, tempo)
        if context == SelectContext.ATTACH_FROM:
            return 110 if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC} else 15
        if context in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER, SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            return pokemon_value(card) if option.playerIndex != my_index else -pokemon_value(card)
        if context in (SelectContext.HEAL, SelectContext.REMOVE_DAMAGE_COUNTER):
            return (card.maxHp - card.hp) if option.playerIndex == my_index and hasattr(card, "maxHp") else 0
        return score_search_card(cid, field_counts, hand_counts, discard_counts, tempo)

    if option.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, option.index, my_index)
        return score_play_card(card.id, state, select, my_state, op_state, field_counts, hand_counts, tempo) if card else -1200

    if option.type == OptionType.ATTACH:
        card = get_card(obs, option.area, option.index, my_index)
        pokemon = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if card is None or pokemon is None:
            return -1200
        if card.id == HEROS_CAPE:
            return 24500 if pokemon.id == ALAKAZAM else 9800
        return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts, tempo)

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        energy_bonus = len(getattr(target, "energies", [])) * 380 if target is not None else 0
        if evolved.id == ALAKAZAM:
            return 32000 + energy_bonus
        if evolved.id == KADABRA:
            return 22500 + energy_bonus
        if evolved.id == DUDUNSPARCE:
            return 9200
        return 10800

    if option.type == OptionType.ABILITY:
        card = get_card(obs, option.area, option.index, my_index)
        if card is not None and card.id == DUDUNSPARCE:
            # Grok loves firing the engine (public ABILITY signal)
            base = 76000
            if my_state.handCount is not None:
                if my_state.handCount >= 16:
                    base = 66000
                elif my_state.handCount >= 12:
                    base = 71000
            # Extra when we have no stadium (common winning pattern)
            if not getattr(state, "stadium", None):
                base += 6500
            return base
        return 17500 if card is not None else 0

    if option.type == OptionType.ATTACK:
        if active is None:
            return 0
        damage = attack_damage(active, op_active, option.attackId, my_state.handCount or 0)
        if active.id != ALAKAZAM:
            score = 1550 + damage * 22
            if op_active is not None and damage >= op_active.hp:
                score += 25500 + pokemon_value(op_active)
            # Small Grok bonus for tempo when ahead on prizes
            if tempo > 150:
                score += 1800
            return score
        if op_active is not None and damage >= op_active.hp:
            return 53000 + pokemon_value(op_active)
        if (my_state.handCount or 0) >= 12:
            return 7200 + damage * 13
        return 2800 + damage * 7

    if option.type == OptionType.ENERGY and context == SelectContext.DISCARD_ENERGY:
        return score_discard_energy_option(obs, option, my_index)

    return 0


def score_discard_card(cid: int, field_counts: Counter, hand_counts: Counter) -> int:
    if cid in {ALAKAZAM, KADABRA, ABRA}:
        return -950 if hand_counts[cid] <= 1 else -160
    if cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC}:
        return 175 if hand_counts[BASIC_PSYCHIC] + hand_counts[TELEPATH_PSYCHIC] >= 3 else -520
    if cid in {HEROS_CAPE, RARE_CANDY}:
        return -680
    if cid in {HILDA, DAWN, POKE_PAD, BOSS_ORDERS, BATTLE_CAGE}:
        return 90 if hand_counts[cid] >= 2 else -270
    if cid in DUNSPARCE_IDS or cid == DUDUNSPARCE:
        return 175 if field_counts[ABRA] + field_counts[KADABRA] + field_counts[ALAKAZAM] >= 2 else -230
    return 105


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
