import os
from collections import Counter, defaultdict

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


# Patient evaluator for the rank-1 onechan1/YT/Kyo Iono Lightning list observed
# from public replays. This copy is intentionally evaluator-only; it tunes the
# opponent pilot toward the public top pilots' lower-bench, attach-before-ability
# sequencing instead of trying to become a submission candidate.
DECK = [
    265, 265, 265,
    268, 268, 268,
    269, 269, 269,
    270, 270, 270,
    271, 271, 271,
    1086, 1086, 1086,
    1097, 1097,
    1110,
    1118,
    1121, 1121, 1121,
    1152, 1152,
    1227, 1227, 1227, 1227,
    1233, 1233, 1233, 1233,
    1254, 1254, 1254,
    4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4,
]


BASIC_GRASS = 1
BASIC_FIRE = 2
BASIC_LIGHTNING = 4
GROW_GRASS = 18
MIST_ENERGY = 11
SPIKY_ENERGY = 14

IONOS_VOLTORB = 265
IONOS_TADBULB = 268
IONOS_BELLIBOLT_EX = 269
IONOS_WATTREL = 270
IONOS_KILOWATTREL = 271

DWEBBLE = 344
CRUSTLE = 345
ETHANS_CYNDAQUIL = 352
ETHANS_QUILAVA = 353
ETHANS_TYPHLOSION = 354

RARE_CANDY = 1079
BUDDY_BUDDY_POFFIN = 1086
NIGHT_STRETCHER = 1097
MAX_ROD = 1110
ENERGY_RETRIEVAL = 1118
ULTRA_BALL = 1121
POKEGEAR_30 = 1122
CRUSHING_HAMMER = 1120
JUMBO_ICE_CREAM = 1147
POKE_PAD = 1152
HEROS_CAPE = 1159
BOSS_ORDERS = 1182
CARMINE = 1192
COOK = 1212
ETHANS_ADVENTURE = 1215
CHEREN = 1224
LILLIES_DETERMINATION = 1227
CANARI = 1233
WAITRESS = 1235
LEVINCIA = 1254
BATTLE_CAGE = 1264

LEGACY_ENERGY = 12

IONO_POKEMON = {
    IONOS_VOLTORB,
    IONOS_TADBULB,
    IONOS_BELLIBOLT_EX,
    IONOS_WATTREL,
    IONOS_KILOWATTREL,
}

try:
    CARD_TABLE = {card.cardId: card for card in all_card_data()}
    ATTACK_TABLE = {attack.attackId: attack for attack in all_attack()}
except Exception:
    CARD_TABLE = {}
    ATTACK_TABLE = {}


def read_deck_csv() -> list[int]:
    for path in ("deck.csv", "/kaggle_simulations/agent/deck.csv"):
        if os.path.exists(path):
            with open(path, "r") as file:
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


def card_name(cid: int) -> str:
    data = CARD_TABLE.get(cid)
    return data.name if data is not None else ""


def is_pokemon_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType == CardType.POKEMON
    return cid in {
        DWEBBLE,
        CRUSTLE,
        ETHANS_CYNDAQUIL,
        ETHANS_QUILAVA,
        ETHANS_TYPHLOSION,
        *IONO_POKEMON,
    }


def is_energy_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType in (CardType.BASIC_ENERGY, CardType.SPECIAL_ENERGY)
    return cid in {BASIC_GRASS, BASIC_FIRE, BASIC_LIGHTNING, GROW_GRASS, MIST_ENERGY, SPIKY_ENERGY, LEGACY_ENERGY}


def is_basic_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return bool(data.basic)
    return cid in {DWEBBLE, ETHANS_CYNDAQUIL, IONOS_VOLTORB, IONOS_TADBULB, IONOS_WATTREL}


def prize_count(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    count = 1
    if data is not None:
        count = 3 if data.megaEx else 2 if data.ex else 1
    for attached in getattr(pokemon, "energyCards", []):
        if attached.id == LEGACY_ENERGY:
            count -= 1
    return max(1, count)


def pokemon_value(pokemon) -> int:
    data = CARD_TABLE.get(pokemon.id)
    score = prize_count(pokemon) * 1000 + pokemon.hp
    score += len(getattr(pokemon, "energies", [])) * 160
    score += len(getattr(pokemon, "tools", [])) * 100
    if data is not None:
        if data.stage2:
            score += 260
        elif data.stage1:
            score += 140
        if data.ex or data.megaEx:
            score += 350
    if pokemon.id in {CRUSTLE, ETHANS_TYPHLOSION}:
        score += 240
    return score


def attacker_type(attacker_id: int, attack_id: int):
    if attacker_id in {DWEBBLE, CRUSTLE}:
        return EnergyType.GRASS
    if attacker_id in {ETHANS_CYNDAQUIL, ETHANS_QUILAVA, ETHANS_TYPHLOSION}:
        return EnergyType.FIRE
    if attacker_id in IONO_POKEMON:
        return EnergyType.LIGHTNING
    attack = ATTACK_TABLE.get(attack_id)
    if attack is not None:
        for energy in attack.energies:
            if energy != EnergyType.COLORLESS:
                return energy
    return None


def raw_attack_damage(attacker_id: int, attack_id: int, discard_counts: Counter) -> int:
    attack = ATTACK_TABLE.get(attack_id)
    name = attack.name if attack is not None else ""
    text = attack.text if attack is not None else ""
    if attacker_id == ETHANS_TYPHLOSION and ("Buddy Blast" in name or "Ethan" in text):
        return 40 + 60 * discard_counts[ETHANS_ADVENTURE]
    if attacker_id == CRUSTLE:
        return 120
    if attacker_id == ETHANS_QUILAVA:
        return 40
    if attacker_id == ETHANS_CYNDAQUIL:
        return 30
    if attack is not None:
        return max(0, int(attack.damage))
    return 0


def adjusted_damage(attacker, target, attack_id: int, discard_counts: Counter) -> int:
    damage = raw_attack_damage(attacker.id, attack_id, discard_counts)
    return type_adjusted_damage(damage, attacker_type(attacker.id, attack_id), target)


def type_adjusted_damage(damage: int, damage_type, target) -> int:
    if damage <= 0:
        return 0
    data = CARD_TABLE.get(target.id)
    if data is not None and damage_type is not None:
        if data.weakness == damage_type:
            damage *= 2
        elif data.resistance == damage_type:
            damage = max(0, damage - 30)
    return damage


def count_attached_energy_cards(pokemon, energy_id: int) -> int:
    return sum(1 for card in getattr(pokemon, "energyCards", []) if getattr(card, "id", None) == energy_id)


def count_iono_lightning_energy(player_state) -> int:
    total = 0
    for _, _, pokemon in all_field_pokemon(player_state):
        if pokemon.id in IONO_POKEMON:
            total += count_attached_energy_cards(pokemon, BASIC_LIGHTNING)
    return total


def iono_attack_damage(active, target, player_state) -> int:
    if active is None or target is None:
        return 0
    if active.id == IONOS_VOLTORB:
        damage = 20 + 20 * count_iono_lightning_energy(player_state)
    elif active.id == IONOS_BELLIBOLT_EX:
        damage = 230
    elif active.id == IONOS_KILOWATTREL:
        damage = 70
    elif active.id == IONOS_WATTREL:
        damage = 30
    elif active.id == IONOS_TADBULB:
        damage = 30
    else:
        return 0
    return type_adjusted_damage(damage, EnergyType.LIGHTNING, target)


def all_field_pokemon(player_state):
    cards = []
    for card in player_state.active:
        if card is not None:
            cards.append((AreaType.ACTIVE, 0, card))
    for i, card in enumerate(player_state.bench):
        cards.append((AreaType.BENCH, i, card))
    return cards


def count_cards(cards) -> Counter:
    counts = Counter()
    for card in cards:
        if card is not None:
            counts[card.id] += 1
    return counts


def can_attack_now(select) -> bool:
    return any(option.type == OptionType.ATTACK for option in select.option)


def best_attack_damage(active, op_active, select, discard_counts: Counter) -> int:
    if active is None or op_active is None:
        return 0
    best = 0
    for option in select.option:
        if option.type == OptionType.ATTACK:
            best = max(best, adjusted_damage(active, op_active, option.attackId, discard_counts))
    return best


def score_search_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 100
    if cid == IONOS_BELLIBOLT_EX:
        score = 910
        if field_counts[IONOS_TADBULB] == 0:
            score -= 330
        if hand_counts[IONOS_BELLIBOLT_EX] > 0:
            score -= 260
    elif cid == IONOS_KILOWATTREL:
        score = 760
        if field_counts[IONOS_WATTREL] == 0:
            score -= 280
        if field_counts[IONOS_KILOWATTREL] + hand_counts[IONOS_KILOWATTREL] >= 2:
            score -= 220
    elif cid == IONOS_TADBULB:
        score = 700
        if field_counts[IONOS_TADBULB] + field_counts[IONOS_BELLIBOLT_EX] >= 3:
            score -= 280
    elif cid == IONOS_VOLTORB:
        score = 860
        if field_counts[IONOS_VOLTORB] >= 2:
            score -= 240
    elif cid == IONOS_WATTREL:
        score = 600
        if field_counts[IONOS_WATTREL] + field_counts[IONOS_KILOWATTREL] >= 2:
            score -= 220
    elif cid == BASIC_LIGHTNING:
        score = 820 if field_counts[IONOS_BELLIBOLT_EX] or field_counts[IONOS_VOLTORB] else 610
    elif cid == CANARI:
        score = 620
    elif cid == ETHANS_TYPHLOSION:
        score = 900
        if field_counts[ETHANS_CYNDAQUIL] + field_counts[ETHANS_QUILAVA] == 0:
            score -= 250
        if hand_counts[ETHANS_TYPHLOSION] > 0:
            score -= 350
    elif cid == ETHANS_QUILAVA:
        score = 760
        if field_counts[ETHANS_CYNDAQUIL] == 0:
            score -= 250
        if field_counts[ETHANS_QUILAVA] + hand_counts[ETHANS_QUILAVA] >= 2:
            score -= 260
    elif cid == CRUSTLE:
        score = 820
        if field_counts[DWEBBLE] == 0:
            score -= 220
        if hand_counts[CRUSTLE] > 0:
            score -= 250
    elif cid == ETHANS_CYNDAQUIL:
        score = 650
        if field_counts[ETHANS_CYNDAQUIL] + field_counts[ETHANS_QUILAVA] + field_counts[ETHANS_TYPHLOSION] >= 2:
            score -= 300
    elif cid == DWEBBLE:
        score = 680
        if field_counts[DWEBBLE] + field_counts[CRUSTLE] >= 4:
            score -= 300
    elif cid == BASIC_FIRE:
        score = 520
    elif cid in {BASIC_GRASS, GROW_GRASS}:
        score = 430
    elif cid in {MIST_ENERGY, SPIKY_ENERGY}:
        score = 340
    elif cid == WAITRESS:
        score = 620
    elif cid == COOK:
        score = 500
    elif cid in {CHEREN, LILLIES_DETERMINATION}:
        score = 470
    elif is_pokemon_id(cid):
        score = 300
    elif is_energy_id(cid):
        score = 220
    score -= hand_counts[cid] * 90
    score += discard_counts[ETHANS_ADVENTURE] * 15 if cid == ETHANS_TYPHLOSION else 0
    return score


def score_discard_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 0
    if cid == BASIC_LIGHTNING:
        score = 620 if hand_counts[BASIC_LIGHTNING] >= 3 else 180
    elif cid in {IONOS_VOLTORB, IONOS_TADBULB, IONOS_WATTREL}:
        score = -220 if hand_counts[cid] <= 1 else 160
    elif cid in {IONOS_BELLIBOLT_EX, IONOS_KILOWATTREL}:
        score = -520 if hand_counts[cid] <= 1 else 80
    elif cid in {CANARI, LILLIES_DETERMINATION}:
        score = 430 if hand_counts[cid] >= 2 else 80
    elif cid in {NIGHT_STRETCHER, MAX_ROD, ENERGY_RETRIEVAL, POKE_PAD}:
        score = 180 if hand_counts[cid] >= 2 else 40
    elif cid == ETHANS_ADVENTURE:
        score = 720 if field_counts[ETHANS_TYPHLOSION] else 260
    elif cid in {BASIC_FIRE, BASIC_GRASS, GROW_GRASS, MIST_ENERGY, SPIKY_ENERGY}:
        score = 520 if hand_counts[cid] >= 2 else 220
    elif cid in {CARMINE, LILLIES_DETERMINATION, COOK, CHEREN, WAITRESS}:
        score = 420 if hand_counts[cid] >= 2 else 120
    elif cid == BOSS_ORDERS:
        score = 260 if hand_counts[cid] >= 2 else 80
    elif cid == JUMBO_ICE_CREAM:
        score = 300 if hand_counts[cid] >= 2 else 100
    elif cid == RARE_CANDY:
        score = 170 if hand_counts[ETHANS_TYPHLOSION] == 0 else -80
    elif cid == ULTRA_BALL:
        score = 120
    elif cid == POKE_PAD:
        score = 110
    elif cid == HEROS_CAPE:
        score = -800
    elif cid in {ETHANS_TYPHLOSION, CRUSTLE}:
        score = -500 if hand_counts[cid] <= 1 else 60
    elif cid in {ETHANS_QUILAVA, ETHANS_CYNDAQUIL, DWEBBLE}:
        score = -140 if hand_counts[cid] <= 1 else 120
    elif is_pokemon_id(cid):
        score = 0
    return score


def energy_attach_score(energy_id: int, pokemon, active: bool, field_counts: Counter) -> int:
    if pokemon is None:
        return -1000
    energy_count = len(getattr(pokemon, "energies", []))
    score = 1000 + energy_count
    if active:
        score += 50
    if pokemon.id in IONO_POKEMON:
        if energy_id != BASIC_LIGHTNING:
            return score - 350
        score += 850
        if active:
            score += 1200
        if pokemon.id == IONOS_BELLIBOLT_EX:
            score += 700
            if energy_count < 4:
                score += 420
            else:
                score -= 260
        elif pokemon.id == IONOS_TADBULB:
            score += 520 if energy_count == 0 else 180
        elif pokemon.id == IONOS_VOLTORB:
            score += 620 if energy_count < 2 else 180
            score += field_counts[IONOS_BELLIBOLT_EX] * 80
        elif pokemon.id == IONOS_KILOWATTREL:
            score += 420 if energy_count < 2 else 120
        elif pokemon.id == IONOS_WATTREL:
            score += 320 if energy_count == 0 else 80
    elif pokemon.id in {ETHANS_CYNDAQUIL, ETHANS_QUILAVA, ETHANS_TYPHLOSION}:
        if energy_id == BASIC_FIRE:
            score += 900
        elif energy_id in {BASIC_GRASS, GROW_GRASS}:
            score -= 250
        if pokemon.id == ETHANS_TYPHLOSION:
            score += 180
        if energy_count == 0:
            score += 500
        elif energy_count < 3:
            score += 120
    elif pokemon.id in {DWEBBLE, CRUSTLE}:
        if energy_id in {BASIC_GRASS, GROW_GRASS}:
            score += 850
        elif energy_id in {MIST_ENERGY, SPIKY_ENERGY}:
            score += 620
        elif energy_id == BASIC_FIRE:
            score -= 250
        if pokemon.id == CRUSTLE:
            score += 160
        if energy_count < 3:
            score += 360
        else:
            score -= 250
    if energy_id == GROW_GRASS and pokemon.id in {DWEBBLE, CRUSTLE}:
        score += 180
    if energy_id == SPIKY_ENERGY and active:
        score += 140
    if energy_id == MIST_ENERGY and pokemon.id == CRUSTLE:
        score += 90
    if field_counts[CRUSTLE] and pokemon.id == ETHANS_TYPHLOSION and energy_id == BASIC_FIRE:
        score += 80
    return score


def score_switch_target(pokemon, my_index: int, owner_index: int, field_counts: Counter, discard_counts: Counter) -> int:
    if pokemon is None:
        return -1000
    score = len(getattr(pokemon, "energies", [])) * 100 + pokemon.hp
    if owner_index == my_index:
        if pokemon.id == IONOS_KILOWATTREL:
            score += 1900
        elif pokemon.id == IONOS_BELLIBOLT_EX:
            score += 1450
        elif pokemon.id == IONOS_VOLTORB:
            score += 980 + count_attached_energy_cards(pokemon, BASIC_LIGHTNING) * 120
        elif pokemon.id == IONOS_TADBULB:
            score += 420
        elif pokemon.id == IONOS_WATTREL:
            score += 340
        elif pokemon.id == CRUSTLE:
            score += 1400
        elif pokemon.id == ETHANS_TYPHLOSION:
            score += 1200 + discard_counts[ETHANS_ADVENTURE] * 120
        elif pokemon.id == DWEBBLE:
            score += 450
        elif pokemon.id == ETHANS_QUILAVA:
            score += 360
        elif pokemon.id == ETHANS_CYNDAQUIL:
            score += 250
    else:
        score = pokemon_value(pokemon)
    return score


def score_play_card(cid: int, state, select, my_state, op_state, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    bench_space = my_state.benchMax - len(my_state.bench)
    active = my_state.active[0] if my_state.active else None
    op_active = op_state.active[0] if op_state.active else None
    score = 0
    data = CARD_TABLE.get(cid)
    if is_pokemon_id(cid):
        score = 7600 if is_basic_id(cid) and bench_space > 0 else 1200
        if cid in IONO_POKEMON:
            iono_basics = field_counts[IONOS_VOLTORB] + field_counts[IONOS_TADBULB] + field_counts[IONOS_WATTREL]
            if cid == IONOS_VOLTORB:
                return 6800 if iono_basics < 2 else -100
            if cid == IONOS_TADBULB:
                return 6400 if field_counts[IONOS_TADBULB] + field_counts[IONOS_BELLIBOLT_EX] < 1 else -100
            if cid == IONOS_WATTREL:
                return 5600 if field_counts[IONOS_WATTREL] + field_counts[IONOS_KILOWATTREL] < 1 else -100
            return -100
        if cid == DWEBBLE and field_counts[DWEBBLE] + field_counts[CRUSTLE] >= 4:
            score = -100
        elif cid == ETHANS_CYNDAQUIL and field_counts[ETHANS_CYNDAQUIL] + field_counts[ETHANS_QUILAVA] + field_counts[ETHANS_TYPHLOSION] >= 2:
            score = -100
        return score

    if cid == BUDDY_BUDDY_POFFIN:
        return 24000 if bench_space > 0 and (field_counts[DWEBBLE] + field_counts[ETHANS_CYNDAQUIL] < 5) else -100
    if cid == RARE_CANDY:
        if hand_counts[ETHANS_TYPHLOSION] and field_counts[ETHANS_CYNDAQUIL]:
            return 23000
        return 3500
    if cid == ULTRA_BALL:
        need_piece = (
            (field_counts[ETHANS_CYNDAQUIL] and not (field_counts[ETHANS_TYPHLOSION] or hand_counts[ETHANS_TYPHLOSION]))
            or (field_counts[DWEBBLE] and not (field_counts[CRUSTLE] or hand_counts[CRUSTLE]))
            or (field_counts[IONOS_TADBULB] and not (field_counts[IONOS_BELLIBOLT_EX] or hand_counts[IONOS_BELLIBOLT_EX]))
            or (field_counts[IONOS_WATTREL] and not (field_counts[IONOS_KILOWATTREL] or hand_counts[IONOS_KILOWATTREL]))
        )
        return 20500 if need_piece else 9000
    if cid == POKE_PAD:
        return 14500
    if cid == CANARI:
        iono_basics = field_counts[IONOS_VOLTORB] + field_counts[IONOS_TADBULB] + field_counts[IONOS_WATTREL]
        return 25500 if my_state.handCount > 1 and iono_basics < 5 else 9500
    if cid == ENERGY_RETRIEVAL:
        return 15000 if discard_counts[BASIC_LIGHTNING] >= 2 else 4500
    if cid == NIGHT_STRETCHER:
        need_pokemon = any(discard_counts[cid2] for cid2 in IONO_POKEMON)
        return 12500 if discard_counts[BASIC_LIGHTNING] or need_pokemon else 3000
    if cid == MAX_ROD:
        recoverable = discard_counts[BASIC_LIGHTNING] + sum(discard_counts[cid2] for cid2 in IONO_POKEMON)
        return 13500 if recoverable >= 3 else 3500
    if cid == CRUSHING_HAMMER:
        return 18000 if op_state.active or op_state.bench else 0
    if cid == ETHANS_ADVENTURE:
        return 26000 + discard_counts[ETHANS_ADVENTURE] * 40
    if cid == LILLIES_DETERMINATION:
        return 16500 if my_state.handCount <= 5 or state.turn <= 4 else 8000
    if cid == CARMINE:
        return 15500 if state.turn <= 3 or my_state.handCount <= 4 else 6500
    if cid == WAITRESS:
        need_energy = any(p.id in {DWEBBLE, CRUSTLE} and len(p.energies) < 3 for _, _, p in all_field_pokemon(my_state))
        return 17200 if need_energy else 7000
    if cid == COOK:
        if active is not None and active.hp < active.maxHp:
            return 17000 + (active.maxHp - active.hp)
        return 2500
    if cid == CHEREN:
        return 13000 if my_state.handCount <= 5 else 5500
    if cid == POKEGEAR_30:
        return 12500
    if cid == LEVINCIA:
        return 14500 if discard_counts[BASIC_LIGHTNING] >= 2 and not state.stadium else 5500
    if cid == BOSS_ORDERS:
        if active is not None and can_attack_now(select):
            current_damage = best_attack_damage(active, op_active, select, discard_counts)
            for bench_pokemon in op_state.bench:
                for option in select.option:
                    if option.type == OptionType.ATTACK:
                        if adjusted_damage(active, bench_pokemon, option.attackId, discard_counts) >= bench_pokemon.hp:
                            return 21000 + pokemon_value(bench_pokemon)
            if op_active is not None and current_damage >= op_active.hp:
                return -50
        return 6200
    if cid == JUMBO_ICE_CREAM:
        if active is not None and len(active.energies) >= 3 and active.hp < active.maxHp:
            return 19000 + (active.maxHp - active.hp)
        return 1200
    if cid == BATTLE_CAGE:
        return 9000 if not state.stadium else 2500
    if data is not None and data.cardType == CardType.STADIUM:
        return 5000
    return score


def score_discard_energy_option(obs: Observation, option, my_index: int) -> int:
    pokemon = get_card(obs, option.area, option.index, option.playerIndex)
    if pokemon is None:
        return 0
    energy_cards = getattr(pokemon, "energyCards", [])
    energy_index = getattr(option, "energyIndex", -1)
    energy_card = energy_cards[energy_index] if 0 <= energy_index < len(energy_cards) else None
    energy_id = getattr(energy_card, "id", 0)
    if option.playerIndex == my_index:
        if pokemon.id == IONOS_KILOWATTREL and energy_id == BASIC_LIGHTNING:
            return 2200 + max(0, len(getattr(pokemon, "energies", [])) - 1) * 250
        return -1000
    energy_count = len(getattr(pokemon, "energies", []))
    grass_count = sum(1 for card in energy_cards if card.id in {BASIC_GRASS, GROW_GRASS})

    score = 1000 + pokemon_value(pokemon) // 10
    if option.area == AreaType.ACTIVE:
        score += 2400
    else:
        score += 350
    if energy_count <= 3:
        score += 1600
    elif energy_count == 4:
        score += 650
    score += getattr(option, "count", 1) * 250

    if energy_id == GROW_GRASS:
        score += 650
        if pokemon.id in {DWEBBLE, CRUSTLE}:
            score += 250
    elif energy_id == BASIC_GRASS:
        score += 520
    elif energy_id == MIST_ENERGY:
        score += 380
    elif energy_id == SPIKY_ENERGY:
        score += 320
    elif energy_id:
        score += 260

    if pokemon.id in {DWEBBLE, CRUSTLE} and energy_id in {BASIC_GRASS, GROW_GRASS} and grass_count <= 1:
        score += 1000
    return score


def choose_indices(select, scores: list[float]) -> list[int]:
    option_count = len(select.option)
    if option_count == 0 or select.maxCount == 0:
        return []
    minimum = max(0, min(select.minCount, select.maxCount, option_count))
    maximum = max(0, min(select.maxCount, option_count))
    ordered = sorted(range(option_count), key=lambda i: (scores[i], -i), reverse=True)
    context = select.context

    # Top Iono pilots often decline optional setup benching and take only the
    # single best card from optional search/bench prompts. The generic greedy
    # selector overfilled the board and inflated Iono's simulated speed.
    if minimum == 0 and context == SelectContext.SETUP_BENCH_POKEMON:
        return []
    if minimum == 0 and context in (SelectContext.TO_BENCH, SelectContext.TO_FIELD, SelectContext.TO_HAND):
        threshold = 500 if context != SelectContext.TO_HAND else 600
        return [ordered[0]] if ordered and scores[ordered[0]] > threshold else []

    chosen = []
    threshold = 0 if minimum == 0 else -10**18
    for idx in ordered:
        if len(chosen) >= maximum:
            break
        if scores[idx] > threshold or len(chosen) < minimum:
            chosen.append(idx)
    for idx in ordered:
        if len(chosen) >= minimum:
            break
        if idx not in chosen:
            chosen.append(idx)
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
        if context in (SelectContext.SETUP_ACTIVE_POKEMON,):
            if cid == IONOS_VOLTORB:
                return 570
            if cid == IONOS_TADBULB:
                return 540
            if cid == IONOS_WATTREL:
                return 520
            if cid == DWEBBLE:
                return 500 if state.firstPlayer != my_index else 360
            if cid == ETHANS_CYNDAQUIL:
                return 470 if state.firstPlayer == my_index else 390
            return 100
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid == IONOS_TADBULB:
                return 650 - (field_counts[IONOS_TADBULB] + field_counts[IONOS_BELLIBOLT_EX]) * 220
            if cid == IONOS_VOLTORB:
                return 700 - field_counts[IONOS_VOLTORB] * 260
            if cid == IONOS_WATTREL:
                return 610 - (field_counts[IONOS_WATTREL] + field_counts[IONOS_KILOWATTREL]) * 240
            if cid == DWEBBLE:
                return 700 - field_counts[DWEBBLE] * 120
            if cid == ETHANS_CYNDAQUIL:
                return 680 - (field_counts[ETHANS_CYNDAQUIL] + field_counts[ETHANS_QUILAVA] + field_counts[ETHANS_TYPHLOSION]) * 120
            return 120 if is_basic_id(cid) else 20
        if context in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            return score_switch_target(card, my_index, option.playerIndex, field_counts, discard_counts)
        if context == SelectContext.TO_HAND:
            return score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.DISCARD:
            return score_discard_card(cid, field_counts, hand_counts, discard_counts)
        if context in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context in (SelectContext.TO_PRIZE,):
            return score_search_card(cid, field_counts, hand_counts, discard_counts)
        if context == SelectContext.ATTACH_FROM:
            return 100 if is_energy_id(cid) else 0
        if context in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER, SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            return pokemon_value(card) if option.playerIndex != my_index else -pokemon_value(card)
        if context in (SelectContext.HEAL, SelectContext.REMOVE_DAMAGE_COUNTER):
            return (card.maxHp - card.hp) if option.playerIndex == my_index and hasattr(card, "maxHp") else 0
        return score_search_card(cid, field_counts, hand_counts, discard_counts)

    if option.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, option.index, my_index)
        return score_play_card(card.id, state, select, my_state, op_state, field_counts, hand_counts, discard_counts) if card else -1000

    if option.type == OptionType.ATTACH:
        card = get_card(obs, option.area, option.index, my_index)
        pokemon = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if card is None or pokemon is None:
            return -1000
        if card.id == BASIC_LIGHTNING and pokemon.id in IONO_POKEMON and not state.energyAttached:
            return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts) + 18000
        if card.id == HEROS_CAPE:
            if pokemon.id == CRUSTLE:
                return 22000
            if pokemon.id == ETHANS_TYPHLOSION:
                return 20000
            if pokemon.id in {DWEBBLE, ETHANS_CYNDAQUIL, ETHANS_QUILAVA}:
                return 12000
        return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts)

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        if evolved.id == IONOS_BELLIBOLT_EX:
            return 29500 + (len(target.energies) if target else 0) * 350
        if evolved.id == IONOS_KILOWATTREL:
            return 20500 + (len(target.energies) if target else 0) * 160
        if evolved.id == ETHANS_TYPHLOSION:
            return 28000 + (len(target.energies) if target else 0) * 300
        if evolved.id == CRUSTLE:
            return 25000 + (len(target.energies) if target else 0) * 260
        if evolved.id == ETHANS_QUILAVA:
            return 18000 + (len(target.energies) if target else 0) * 150
        return 12000

    if option.type == OptionType.ABILITY:
        card = get_card(obs, option.area, option.index, my_index)
        if card is None:
            return 0
        if card.id == IONOS_BELLIBOLT_EX:
            if not hand_counts[BASIC_LIGHTNING]:
                return 800
            if not state.energyAttached:
                return 11500
            if hand_counts[CANARI] and state.turn <= 6:
                return 21000
            return 29500
        if card.id == IONOS_KILOWATTREL:
            if not count_attached_energy_cards(card, BASIC_LIGHTNING):
                return 700
            if hand_counts[MAX_ROD] and discard_counts[BASIC_LIGHTNING] + sum(discard_counts[cid2] for cid2 in IONO_POKEMON) >= 3:
                return 10500
            return 18500 if my_state.handCount <= 4 else 900
        if card.id == ETHANS_QUILAVA:
            return 30000
        return 18000

    if option.type == OptionType.RETREAT:
        best_bench = max((score_switch_target(p, my_index, my_index, field_counts, discard_counts) for p in my_state.bench), default=-1000)
        active_score = score_switch_target(active, my_index, my_index, field_counts, discard_counts) if active else 0
        return 11500 if best_bench > active_score + 250 else -100

    if option.type == OptionType.ATTACK:
        if active is None:
            return -1000
        attack = ATTACK_TABLE.get(option.attackId)
        attack_name = attack.name if attack is not None else ""
        if "Ascension" in attack_name or (active.id == DWEBBLE and raw_attack_damage(active.id, option.attackId, discard_counts) == 0):
            return 17500 if field_counts[CRUSTLE] < 1 else 2500
        if op_active is None:
            return 1000
        damage = adjusted_damage(active, op_active, option.attackId, discard_counts)
        if active.id in IONO_POKEMON:
            damage = max(damage, iono_attack_damage(active, op_active, my_state))
        score = 2500 + damage * 18
        if damage >= op_active.hp:
            prizes = prize_count(op_active)
            score = 22000 + prizes * 5000 + pokemon_value(op_active)
            if len(op_state.prize) <= prizes:
                score = 90000
        if active.id == ETHANS_TYPHLOSION and discard_counts[ETHANS_ADVENTURE] >= 2:
            score += 1200
        if active.id == CRUSTLE:
            score += 700
        return score

    if option.type == OptionType.END:
        return -10

    if option.type == OptionType.ENERGY and context == SelectContext.DISCARD_ENERGY:
        return score_discard_energy_option(obs, option, my_index)

    if option.type in (OptionType.ENERGY, OptionType.ENERGY_CARD, OptionType.TOOL_CARD):
        return 0

    return 0


def choose_action(obs: Observation) -> list[int]:
    if obs.select is None:
        return MY_DECK

    state = obs.current
    select = obs.select
    my_index = state.yourIndex
    my_state = state.players[my_index]

    field_counts = defaultdict(int)
    for _, _, pokemon in all_field_pokemon(my_state):
        field_counts[pokemon.id] += 1

    hand_counts = count_cards(my_state.hand or [])
    discard_counts = count_cards(my_state.discard)

    scores = [score_option(obs, option, field_counts, hand_counts, discard_counts) for option in select.option]
    return choose_indices(select, scores)


def agent(obs_dict: dict) -> list[int]:
    try:
        obs = to_observation_class(obs_dict)
        result = choose_action(obs)
        if obs.select is None:
            return result
        if (
            isinstance(result, list)
            and obs.select.minCount <= len(result) <= obs.select.maxCount
            and len(set(result)) == len(result)
            and all(isinstance(i, int) and 0 <= i < len(obs.select.option) for i in result)
        ):
            return result
        return safe_fallback(obs)
    except Exception:
        try:
            return safe_fallback(to_observation_class(obs_dict))
        except Exception:
            return MY_DECK
