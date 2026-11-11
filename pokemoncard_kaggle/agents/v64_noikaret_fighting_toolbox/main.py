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


# Evaluator-only policy for noikaret's top-10 Fighting Toolbox shell.
#
# This starts from the broad replay-meta policy but uses noikaret's exact
# Solrock/Lunatone/Okidogi/Binacle deck and priorities. It is intentionally not
# a submission candidate.
DECK = [
    116, 116, 116,
    135,
    675, 675,
    676, 676, 676, 676,
    1051, 1051,
    1052, 1052,
    1142, 1142, 1142, 1142,
    1152, 1152, 1152, 1152,
    1097, 1097, 1097,
    1174, 1174,
    1227, 1227, 1227, 1227,
    1213, 1213,
    1194, 1194,
    1182, 1182, 1182, 1182,
    1238, 1238, 1238,
    1264, 1264, 1264,
    1247,
    16, 16, 16, 16,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
]


BASIC_GRASS = 1
BASIC_FIRE = 2
BASIC_WATER = 3
BASIC_LIGHTNING = 4
BASIC_PSYCHIC = 5
BASIC_FIGHTING = 6
BASIC_DARKNESS = 7
BASIC_METAL = 8
PRISM_ENERGY = 16
GROW_GRASS = 18
TELEPATH_PSYCHIC_ENERGY = 19
MIST_ENERGY = 11
SPIKY_ENERGY = 14
TEAM_ROCKET_ENERGY = 15
IGNITION_ENERGY = 17

IONOS_VOLTORB = 265
IONOS_TADBULB = 268
IONOS_BELLIBOLT_EX = 269
IONOS_WATTREL = 270
IONOS_KILOWATTREL = 271

DREEPY = 119
DRAKLOAK = 120
DRAGAPULT_EX = 121
DUSKULL = 131
DUSCLOPS = 132
DUSKNOIR = 133
LATIAS_EX = 184
MUNKIDORI = 112
WELLSPRING_MASK_OGERPON_EX = 108
FEZANDIPITI_EX = 140
CHIEN_PAO = 209
BUDEW = 235
LILLIES_CLEFAIRY_EX = 272
N_DARMANITAN = 258
N_ZORUA = 292
N_ZOROARK_EX = 293
N_KLINK = 294
N_KLINKLANG = 296
N_ZEKROM = 906
KYUREM = 144
STEVENS_METAGROSS_EX = 641
METAGROSS = 276
ZERAORA = 377
TATSUGIRI = 122
PECHARUNT = 230
PECHARUNT_EX = 141
SLOWPOKE = 162
SLOWKING = 163
LARVITAR = 284
PUPITAR = 285
TYRANITAR = 290
HOOTHOOT = 172
NOCTOWL = 173
FAN_ROTOM = 174

DWEBBLE = 344
CRUSTLE = 345
ETHANS_CYNDAQUIL = 352
ETHANS_QUILAVA = 353
ETHANS_TYPHLOSION = 354

TEAM_ROCKETS_MURKROW = 463
TEAM_ROCKETS_PORYGON = 473
TEAM_ROCKETS_PORYGON2 = 474
TEAM_ROCKETS_HONCHKROW = 891

TEAL_MASK_OGERPON_EX = 96
CORNERSTONE_MASK_OGERPON_EX = 117
IRON_LEAVES_EX = 75
APPLIN_TWM = 42
APPLIN_SCR = 149
DIPPLIN_TWM = 93
DIPPLIN_SCR = 921
HYDRAPPLE = 348
HYDRAPPLE_EX = 150
CHIKORITA = 917
BAYLEEF = 709
MEGANIUM = 710

MAKUHITA = 673
HARIYAMA = 674
LUNATONE = 675
SOLROCK = 676
RIOLU = 677
MEGA_LUCARIO_EX = 678
OKIDOGI = 116
BLOODMOON_URSALUNA = 135
BINACLE = 1051
BARBARACLE = 1052

KYOGRE = 721
SNOVER = 722
MEGA_ABOMASNOW_EX = 723
MEGA_KANGASKHAN_EX = 756
MOLTRES = 791
KORAIDON_EX = 979
MEOWTH_EX = 1071

RARE_CANDY = 1079
UNFAIR_STAMP = 1080
BUDDY_BUDDY_POFFIN = 1086
PRIME_CATCHER = 1088
NIGHT_STRETCHER = 1097
MAX_ROD = 1110
N_PP_UP = 1113
ENERGY_SWITCH = 1116
ENERGY_RETRIEVAL = 1118
ENERGY_SEARCH = 1119
ULTRA_BALL = 1121
POKEGEAR_30 = 1122
SWITCH = 1123
TERA_ORB = 1127
CRUSHING_HAMMER = 1120
WONDROUS_PATCH = 1146
JUMBO_ICE_CREAM = 1147
POKE_PAD = 1152
HEROS_CAPE = 1159
SPARKLING_CRYSTAL = 1165
AIR_BALLOON = 1174
LILLIES_PEARL = 1172
BOSS_ORDERS = 1182
CIPHERMANIAC = 1188
CARMINE = 1192
COLRESS_TENACITY = 1194
CRISPIN = 1198
BRIAR = 1201
CYRANO = 1205
BROCKS_SCOUTING = 1210
COOK = 1212
JUDGE = 1213
ETHANS_ADVENTURE = 1215
N_PLAN = 1221
CHEREN = 1224
HILDA = 1225
LILLIES_DETERMINATION = 1227
CANARI = 1233
WAITRESS = 1235
TARRAGON = 1238
LEVINCIA = 1254
BATTLE_CAGE = 1264
NEUTRALIZATION_ZONE = 1247
DUSK_BALL = 1102
BUG_CATCHING_SET = 1094
GLASS_TRUMPET = 1098
TOOL_SCRAPPER = 1137
FIGHTING_GONG = 1142
MEGA_SIGNAL = 1145
PREMIUM_POWER_PRO = 1141
HAND_TRIMMER = 1087
TEAM_ROCKETS_TRANSCEIVER = 1134
ROTO_STICK = 1077
TEAM_ROCKETS_ARIANA = 1216
TEAM_ROCKETS_ARCHER = 1217
TEAM_ROCKETS_GIOVANNI = 1218
TEAM_ROCKETS_PETREL = 1219
TEAM_ROCKETS_PROTON = 1220
AREA_ZERO_UNDERDEPTHS = 1250
GRAVITY_MOUNTAIN = 1252
TEAM_ROCKETS_WATCHTOWER = 1256
TEAM_ROCKETS_FACTORY = 1257
FOREST_OF_VITALITY = 1261
SURFING_BEACH = 1262
N_CASTLE = 1253
JAMMING_TOWER = 1246
ACADEMY_AT_NIGHT = 1248
RISKY_RUINS = 1260

LEGACY_ENERGY = 12

IONO_POKEMON = {
    IONOS_VOLTORB,
    IONOS_TADBULB,
    IONOS_BELLIBOLT_EX,
    IONOS_WATTREL,
    IONOS_KILOWATTREL,
}

DRAGAPULT_LINE = {DREEPY, DRAKLOAK, DRAGAPULT_EX}
DUSKNOIR_LINE = {DUSKULL, DUSCLOPS, DUSKNOIR}
NOCTOWL_LINE = {HOOTHOOT, NOCTOWL, FAN_ROTOM}
CLEFAIRY_KANGASKHAN_LINE = {
    LILLIES_CLEFAIRY_EX,
    MEGA_KANGASKHAN_EX,
    MEOWTH_EX,
    LATIAS_EX,
    WELLSPRING_MASK_OGERPON_EX,
    FEZANDIPITI_EX,
    MOLTRES,
    CHIEN_PAO,
    KORAIDON_EX,
}
LUCARIO_LINE = {RIOLU, MEGA_LUCARIO_EX, SOLROCK, LUNATONE, MAKUHITA, HARIYAMA}
FIGHTING_TOOLBOX_LINE = {
    OKIDOGI,
    BLOODMOON_URSALUNA,
    SOLROCK,
    LUNATONE,
    BINACLE,
    BARBARACLE,
}
ABOMASNOW_LINE = {SNOVER, MEGA_ABOMASNOW_EX, KYOGRE}
ROCKET_LINE = {TEAM_ROCKETS_MURKROW, TEAM_ROCKETS_HONCHKROW, TEAM_ROCKETS_PORYGON, TEAM_ROCKETS_PORYGON2}
N_ZOROARK_LINE = {
    N_ZORUA,
    N_ZOROARK_EX,
    N_DARMANITAN,
    N_ZEKROM,
    N_KLINK,
    N_KLINKLANG,
    KYUREM,
    STEVENS_METAGROSS_EX,
    METAGROSS,
    ZERAORA,
}
SLOWKING_LINE = {SLOWPOKE, SLOWKING, MUNKIDORI, PECHARUNT, PECHARUNT_EX}
GRASS_TOOLBOX_LINE = {
    TEAL_MASK_OGERPON_EX,
    CORNERSTONE_MASK_OGERPON_EX,
    IRON_LEAVES_EX,
    APPLIN_TWM,
    APPLIN_SCR,
    DIPPLIN_TWM,
    DIPPLIN_SCR,
    HYDRAPPLE,
    CHIKORITA,
    BAYLEEF,
    MEGANIUM,
    HYDRAPPLE_EX,
}

CORE_TOP_BASICS = {
    DREEPY,
    DUSKULL,
    HOOTHOOT,
    FAN_ROTOM,
    LILLIES_CLEFAIRY_EX,
    MEGA_KANGASKHAN_EX,
    MEOWTH_EX,
    LATIAS_EX,
    WELLSPRING_MASK_OGERPON_EX,
    FEZANDIPITI_EX,
    MOLTRES,
    CHIEN_PAO,
    KORAIDON_EX,
    RIOLU,
    SOLROCK,
    LUNATONE,
    MAKUHITA,
    OKIDOGI,
    BLOODMOON_URSALUNA,
    BINACLE,
    SNOVER,
    TEAM_ROCKETS_MURKROW,
    TEAM_ROCKETS_PORYGON,
    N_ZORUA,
    N_KLINK,
    TATSUGIRI,
    PECHARUNT,
    PECHARUNT_EX,
    SLOWPOKE,
    APPLIN_TWM,
    APPLIN_SCR,
    MUNKIDORI,
    TEAL_MASK_OGERPON_EX,
    CORNERSTONE_MASK_OGERPON_EX,
    IRON_LEAVES_EX,
    CHIKORITA,
}

CORE_TOP_ATTACKERS = {
    DRAGAPULT_EX,
    DUSCLOPS,
    DUSKNOIR,
    LILLIES_CLEFAIRY_EX,
    MEGA_KANGASKHAN_EX,
    WELLSPRING_MASK_OGERPON_EX,
    MOLTRES,
    CHIEN_PAO,
    KORAIDON_EX,
    MEGA_LUCARIO_EX,
    MEGA_ABOMASNOW_EX,
    TEAM_ROCKETS_HONCHKROW,
    N_ZOROARK_EX,
    N_DARMANITAN,
    N_ZEKROM,
    KYUREM,
    STEVENS_METAGROSS_EX,
    METAGROSS,
    ZERAORA,
    SLOWKING,
    MUNKIDORI,
    PECHARUNT_EX,
    IRON_LEAVES_EX,
    HYDRAPPLE,
    HYDRAPPLE_EX,
    CORNERSTONE_MASK_OGERPON_EX,
    MEGANIUM,
    TYRANITAR,
    OKIDOGI,
    BLOODMOON_URSALUNA,
    SOLROCK,
    BARBARACLE,
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
        *DRAGAPULT_LINE,
        *DUSKNOIR_LINE,
        *NOCTOWL_LINE,
        *CLEFAIRY_KANGASKHAN_LINE,
        *LUCARIO_LINE,
        *FIGHTING_TOOLBOX_LINE,
        *ABOMASNOW_LINE,
        *ROCKET_LINE,
        *N_ZOROARK_LINE,
        *SLOWKING_LINE,
        *GRASS_TOOLBOX_LINE,
        LARVITAR,
        PUPITAR,
        TYRANITAR,
    }


def is_energy_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return data.cardType in (CardType.BASIC_ENERGY, CardType.SPECIAL_ENERGY)
    return cid in {
        BASIC_GRASS,
        BASIC_FIRE,
        BASIC_WATER,
        BASIC_LIGHTNING,
        BASIC_PSYCHIC,
        BASIC_FIGHTING,
        BASIC_DARKNESS,
        BASIC_METAL,
        GROW_GRASS,
        MIST_ENERGY,
        SPIKY_ENERGY,
        TEAM_ROCKET_ENERGY,
        IGNITION_ENERGY,
        LEGACY_ENERGY,
        PRISM_ENERGY,
        TELEPATH_PSYCHIC_ENERGY,
    }


def is_basic_id(cid: int) -> bool:
    data = CARD_TABLE.get(cid)
    if data is not None:
        return bool(data.basic)
    return cid in {
        DWEBBLE,
        ETHANS_CYNDAQUIL,
        IONOS_VOLTORB,
        IONOS_TADBULB,
        IONOS_WATTREL,
        *CORE_TOP_BASICS,
        LARVITAR,
    }


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
    if pokemon.id in {
        DRAGAPULT_EX,
        MEGA_LUCARIO_EX,
        MEGA_ABOMASNOW_EX,
        MEGA_KANGASKHAN_EX,
        WELLSPRING_MASK_OGERPON_EX,
        KORAIDON_EX,
    }:
        score += 260
    if pokemon.id in {LATIAS_EX, FEZANDIPITI_EX, MEOWTH_EX}:
        score += 160
    if pokemon.id in {N_ZOROARK_EX, STEVENS_METAGROSS_EX, IRON_LEAVES_EX, HYDRAPPLE_EX}:
        score += 260
    if pokemon.id in {N_DARMANITAN, N_ZEKROM, KYUREM, METAGROSS, ZERAORA, SLOWKING, HYDRAPPLE, MUNKIDORI}:
        score += 180
    if pokemon.id in {OKIDOGI, BLOODMOON_URSALUNA, BARBARACLE}:
        score += 230
    if pokemon.id in {SOLROCK, LUNATONE}:
        score += 150
    if pokemon.id == BINACLE:
        score += 80
    if pokemon.id == DUSKNOIR:
        score += 180
    if pokemon.id == LILLIES_CLEFAIRY_EX:
        score += 220
    return score


def attacker_type(attacker_id: int, attack_id: int):
    if attacker_id in {DRAGAPULT_EX, DRAKLOAK, DREEPY}:
        return EnergyType.DRAGON
    if attacker_id in DUSKNOIR_LINE or attacker_id in {LILLIES_CLEFAIRY_EX, LATIAS_EX}:
        return EnergyType.PSYCHIC
    if attacker_id in {WELLSPRING_MASK_OGERPON_EX, CHIEN_PAO}:
        return EnergyType.WATER
    if attacker_id == MOLTRES:
        return EnergyType.FIRE
    if attacker_id == KORAIDON_EX:
        return EnergyType.FIGHTING
    if attacker_id in {N_ZOROARK_EX, N_DARMANITAN, N_ZEKROM}:
        return EnergyType.DARKNESS
    if attacker_id in {STEVENS_METAGROSS_EX, N_KLINKLANG}:
        return EnergyType.METAL
    if attacker_id in {KYUREM, ZERAORA}:
        return EnergyType.LIGHTNING
    if attacker_id in {METAGROSS, SLOWKING, MUNKIDORI}:
        return EnergyType.PSYCHIC
    if attacker_id in CLEFAIRY_KANGASKHAN_LINE:
        return EnergyType.COLORLESS
    if attacker_id in FIGHTING_TOOLBOX_LINE:
        return EnergyType.FIGHTING
    if attacker_id in LUCARIO_LINE:
        return EnergyType.FIGHTING
    if attacker_id in ABOMASNOW_LINE:
        return EnergyType.WATER
    if attacker_id in ROCKET_LINE:
        return EnergyType.DARKNESS
    if attacker_id in GRASS_TOOLBOX_LINE:
        return EnergyType.GRASS
    if attacker_id in {LARVITAR, PUPITAR, TYRANITAR}:
        return EnergyType.DARKNESS
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
    if attacker_id == DRAGAPULT_EX and ("Phantom Dive" in name or "{R}{P}" in text):
        return 200
    if attacker_id == DRAGAPULT_EX:
        return 70
    if attacker_id == DUSKNOIR:
        return 150
    if attacker_id == DUSCLOPS:
        return 50
    if attacker_id == LILLIES_CLEFAIRY_EX:
        return 20
    if attacker_id == MEGA_KANGASKHAN_EX:
        return 225
    if attacker_id == WELLSPRING_MASK_OGERPON_EX:
        return 220
    if attacker_id == MOLTRES:
        return 110
    if attacker_id == CHIEN_PAO:
        return 120
    if attacker_id == KORAIDON_EX:
        return 200
    if attacker_id == MEOWTH_EX:
        return 60
    if attacker_id == N_ZOROARK_EX:
        return 230
    if attacker_id == N_DARMANITAN:
        return 180
    if attacker_id == N_ZEKROM:
        return 250
    if attacker_id == N_KLINKLANG:
        return 240
    if attacker_id == STEVENS_METAGROSS_EX:
        return 200
    if attacker_id == METAGROSS:
        return 280
    if attacker_id == KYUREM:
        return 110
    if attacker_id == ZERAORA:
        return 210
    if attacker_id == SLOWKING:
        return 160
    if attacker_id == MUNKIDORI:
        return 60
    if attacker_id == PECHARUNT_EX:
        return 180
    if attacker_id == IRON_LEAVES_EX:
        return 180
    if attacker_id == CORNERSTONE_MASK_OGERPON_EX:
        return 140
    if attacker_id == MEGA_LUCARIO_EX and "Mega Brave" in name:
        return 270
    if attacker_id == MEGA_LUCARIO_EX:
        return 130
    if attacker_id == OKIDOGI:
        return 70
    if attacker_id == BLOODMOON_URSALUNA:
        return 150
    if attacker_id == SOLROCK:
        return 70
    if attacker_id == LUNATONE:
        return 50
    if attacker_id == BINACLE:
        return 30
    if attacker_id == BARBARACLE:
        return 120
    if attacker_id == MEGA_ABOMASNOW_EX and "Frost Barrier" in name:
        return 200
    if attacker_id == MEGA_ABOMASNOW_EX:
        return 260
    if attacker_id == TEAM_ROCKETS_HONCHKROW and ("Rocket Feathers" in name or "Team Rocket" in text):
        return 60 * max(1, discard_counts[TEAM_ROCKETS_ARIANA] + discard_counts[TEAM_ROCKETS_ARCHER] + discard_counts[TEAM_ROCKETS_GIOVANNI] + discard_counts[TEAM_ROCKETS_PETREL] + discard_counts[TEAM_ROCKETS_PROTON])
    if attacker_id == TEAM_ROCKETS_HONCHKROW:
        return 100
    if attacker_id == HYDRAPPLE_EX:
        return 170
    if attacker_id == HYDRAPPLE:
        return 140
    if attacker_id == TYRANITAR:
        return 180
    if attack is not None:
        return max(0, int(attack.damage))
    return 0


def adjusted_damage(attacker, target, attack_id: int, discard_counts: Counter) -> int:
    damage = raw_attack_damage(attacker.id, attack_id, discard_counts)
    return type_adjusted_damage(damage, attacker_type(attacker.id, attack_id), target)


def contextual_attack_damage(attacker, target, attack_id: int, discard_counts: Counter, my_state, op_state) -> int:
    if attacker is None or target is None:
        return 0
    damage = adjusted_damage(attacker, target, attack_id, discard_counts)
    if attacker.id in IONO_POKEMON:
        damage = max(damage, iono_attack_damage(attacker, target, my_state))
    if attacker.id == LILLIES_CLEFAIRY_EX:
        bench_damage = 20 + 20 * (len(my_state.bench) + len(op_state.bench))
        damage = max(damage, type_adjusted_damage(bench_damage, EnergyType.PSYCHIC, target))
    if attacker.id == MOLTRES:
        target_data = CARD_TABLE.get(target.id)
        if target_data is not None and (target_data.ex or target_data.megaEx):
            damage = max(damage, type_adjusted_damage(110, EnergyType.FIRE, target))
    if attacker.id == WELLSPRING_MASK_OGERPON_EX:
        damage = max(damage, type_adjusted_damage(220, EnergyType.WATER, target))
    if attacker.id == HYDRAPPLE_EX:
        grass_energy = 0
        for _, _, pokemon in all_field_pokemon(my_state):
            grass_energy += sum(
                1 for card in getattr(pokemon, "energyCards", []) if getattr(card, "id", None) in {BASIC_GRASS, GROW_GRASS}
            )
        damage = max(damage, type_adjusted_damage(30 + 30 * grass_energy, EnergyType.GRASS, target))
    if attacker.id == TEAL_MASK_OGERPON_EX:
        active_energy = len(getattr(attacker, "energies", [])) + len(getattr(target, "energies", []))
        damage = max(damage, type_adjusted_damage(30 + 30 * active_energy, EnergyType.GRASS, target))
    return damage


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


def best_attack_damage(active, op_active, select, discard_counts: Counter, my_state, op_state) -> int:
    if active is None or op_active is None:
        return 0
    best = 0
    for option in select.option:
        if option.type == OptionType.ATTACK:
            best = max(best, contextual_attack_damage(active, op_active, option.attackId, discard_counts, my_state, op_state))
    return best


def score_search_card(cid: int, field_counts: Counter, hand_counts: Counter, discard_counts: Counter) -> int:
    score = 100
    if cid == DRAGAPULT_EX:
        score = 980
        if field_counts[DREEPY] + field_counts[DRAKLOAK] == 0:
            score -= 320
        if hand_counts[DRAGAPULT_EX] > 0:
            score -= 260
    elif cid == DRAKLOAK:
        score = 840
        if field_counts[DREEPY] == 0:
            score -= 260
        if field_counts[DRAKLOAK] + hand_counts[DRAKLOAK] >= 2:
            score -= 220
    elif cid == DREEPY:
        score = 780
        if field_counts[DREEPY] + field_counts[DRAKLOAK] + field_counts[DRAGAPULT_EX] >= 3:
            score -= 300
    elif cid == DUSKNOIR:
        score = 880
        if field_counts[DUSKULL] + field_counts[DUSCLOPS] == 0:
            score -= 320
        if hand_counts[DUSKNOIR] > 0:
            score -= 260
    elif cid == DUSCLOPS:
        score = 760
        if field_counts[DUSKULL] == 0:
            score -= 240
        if field_counts[DUSCLOPS] + hand_counts[DUSCLOPS] >= 2:
            score -= 220
    elif cid == DUSKULL:
        score = 620
        if field_counts[DUSKULL] + field_counts[DUSCLOPS] + field_counts[DUSKNOIR] >= 2:
            score -= 240
    elif cid == NOCTOWL:
        score = 800
        if field_counts[HOOTHOOT] == 0:
            score -= 260
    elif cid == HOOTHOOT:
        score = 620
    elif cid == FAN_ROTOM:
        score = 650 if field_counts[HOOTHOOT] + hand_counts[HOOTHOOT] < 2 else 360
    elif cid == LILLIES_CLEFAIRY_EX:
        score = 900
        if field_counts[LILLIES_CLEFAIRY_EX] + hand_counts[LILLIES_CLEFAIRY_EX] >= 2:
            score -= 220
    elif cid == MEGA_KANGASKHAN_EX:
        score = 960
        if field_counts[MEGA_KANGASKHAN_EX] + hand_counts[MEGA_KANGASKHAN_EX] >= 2:
            score -= 180
    elif cid == MEOWTH_EX:
        score = 760 if field_counts[MEOWTH_EX] + hand_counts[MEOWTH_EX] < 2 else 430
    elif cid == LATIAS_EX:
        score = 700 if field_counts[LATIAS_EX] + hand_counts[LATIAS_EX] < 1 else 320
    elif cid == WELLSPRING_MASK_OGERPON_EX:
        score = 720 if field_counts[WELLSPRING_MASK_OGERPON_EX] + hand_counts[WELLSPRING_MASK_OGERPON_EX] < 2 else 360
    elif cid == FEZANDIPITI_EX:
        score = 560 if field_counts[FEZANDIPITI_EX] + hand_counts[FEZANDIPITI_EX] < 1 else 220
    elif cid == KORAIDON_EX:
        score = 640 if field_counts[KORAIDON_EX] + hand_counts[KORAIDON_EX] < 1 else 280
    elif cid in {MOLTRES, CHIEN_PAO}:
        score = 500 if field_counts[cid] + hand_counts[cid] < 1 else 180
    elif cid == MEGA_LUCARIO_EX:
        score = 1020
        if field_counts[RIOLU] == 0:
            score -= 320
        if hand_counts[MEGA_LUCARIO_EX] > 0:
            score -= 300
    elif cid == RIOLU:
        score = 820
        if field_counts[RIOLU] + field_counts[MEGA_LUCARIO_EX] >= 3:
            score -= 280
    elif cid == OKIDOGI:
        score = 740
        if field_counts[OKIDOGI] + hand_counts[OKIDOGI] >= 2:
            score -= 220
    elif cid == BLOODMOON_URSALUNA:
        score = 640 if field_counts[BLOODMOON_URSALUNA] + hand_counts[BLOODMOON_URSALUNA] < 1 else 260
    elif cid == SOLROCK:
        score = 690 - (field_counts[SOLROCK] + hand_counts[SOLROCK]) * 110
        if field_counts[SOLROCK] + hand_counts[SOLROCK] >= 3:
            score -= 180
    elif cid == LUNATONE:
        score = 620 if field_counts[SOLROCK] else 460
        score -= (field_counts[LUNATONE] + hand_counts[LUNATONE]) * 130
    elif cid == BINACLE:
        score = 680
        if field_counts[BINACLE] + field_counts[BARBARACLE] + hand_counts[BINACLE] >= 2:
            score -= 220
    elif cid == BARBARACLE:
        score = 920 if field_counts[BINACLE] else 500
        if hand_counts[BARBARACLE] > 0:
            score -= 260
    elif cid in {SOLROCK, LUNATONE, MAKUHITA, HARIYAMA}:
        score = 540 - (field_counts[cid] + hand_counts[cid]) * 90
    elif cid == MEGA_ABOMASNOW_EX:
        score = 1040
        if field_counts[SNOVER] == 0:
            score -= 300
        if hand_counts[MEGA_ABOMASNOW_EX] > 0:
            score -= 280
    elif cid == SNOVER:
        score = 800
        if field_counts[SNOVER] + field_counts[MEGA_ABOMASNOW_EX] >= 3:
            score -= 280
    elif cid == KYOGRE:
        score = 520
    elif cid == TEAM_ROCKETS_HONCHKROW:
        score = 900
        if field_counts[TEAM_ROCKETS_MURKROW] == 0:
            score -= 260
    elif cid == TEAM_ROCKETS_MURKROW:
        score = 760
    elif cid == N_ZOROARK_EX:
        score = 980
        if field_counts[N_ZORUA] == 0:
            score -= 300
        if hand_counts[N_ZOROARK_EX] > 0:
            score -= 260
    elif cid == N_ZORUA:
        score = 760
        if field_counts[N_ZORUA] + field_counts[N_ZOROARK_EX] >= 3:
            score -= 240
    elif cid in {N_DARMANITAN, N_ZEKROM, N_KLINKLANG, KYUREM, STEVENS_METAGROSS_EX, METAGROSS, ZERAORA}:
        score = 720 - (field_counts[cid] + hand_counts[cid]) * 120
    elif cid == N_KLINK:
        score = 520 - field_counts[N_KLINK] * 140
    elif cid == SLOWKING:
        score = 920
        if field_counts[SLOWPOKE] == 0:
            score -= 260
        if hand_counts[SLOWKING] > 0:
            score -= 240
    elif cid == SLOWPOKE:
        score = 720
        if field_counts[SLOWPOKE] + field_counts[SLOWKING] >= 4:
            score -= 300
    elif cid in {MUNKIDORI, PECHARUNT, PECHARUNT_EX, TATSUGIRI}:
        score = 560 - (field_counts[cid] + hand_counts[cid]) * 140
    elif cid == TYRANITAR:
        score = 860
        if field_counts[LARVITAR] + field_counts[PUPITAR] == 0:
            score -= 280
    elif cid == LARVITAR:
        score = 720
    elif cid == HYDRAPPLE_EX:
        score = 940
        if field_counts[APPLIN_TWM] + field_counts[APPLIN_SCR] + field_counts[DIPPLIN_TWM] + field_counts[DIPPLIN_SCR] == 0:
            score -= 280
    elif cid in {HYDRAPPLE, DIPPLIN_TWM, DIPPLIN_SCR, MEGANIUM}:
        score = 820
    elif cid in {TEAL_MASK_OGERPON_EX, CORNERSTONE_MASK_OGERPON_EX, IRON_LEAVES_EX, CHIKORITA, APPLIN_TWM, APPLIN_SCR}:
        score = 650
    elif cid in {BASIC_FIRE, BASIC_PSYCHIC} and (field_counts[DREEPY] or field_counts[DRAKLOAK] or field_counts[DRAGAPULT_EX]):
        score = 700
    elif cid in {BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY} and (field_counts[LILLIES_CLEFAIRY_EX] or field_counts[DUSKULL] or field_counts[DUSCLOPS] or field_counts[DUSKNOIR] or field_counts[SLOWKING]):
        score = 680
    elif cid in {BASIC_FIGHTING, PRISM_ENERGY} and any(field_counts[item] for item in FIGHTING_TOOLBOX_LINE):
        score = 820 if cid == PRISM_ENERGY else 760
        if hand_counts[BASIC_FIGHTING] + hand_counts[PRISM_ENERGY] >= 3:
            score -= 160
    elif cid == BASIC_FIGHTING and (field_counts[RIOLU] or field_counts[MEGA_LUCARIO_EX]):
        score = 720
    elif cid == BASIC_WATER and (field_counts[SNOVER] or field_counts[MEGA_ABOMASNOW_EX]):
        score = 760
    elif cid in {BASIC_DARKNESS, TEAM_ROCKET_ENERGY, IGNITION_ENERGY} and (field_counts[TEAM_ROCKETS_MURKROW] or field_counts[TEAM_ROCKETS_HONCHKROW] or field_counts[N_ZOROARK_EX] or field_counts[MUNKIDORI]):
        score = 660
    elif cid == BASIC_METAL and (field_counts[STEVENS_METAGROSS_EX] or field_counts[N_KLINKLANG]):
        score = 620
    elif cid == IONOS_BELLIBOLT_EX:
        score = 980
        if field_counts[IONOS_TADBULB] == 0:
            score -= 260
        if hand_counts[IONOS_BELLIBOLT_EX] > 0:
            score -= 260
    elif cid == IONOS_KILOWATTREL:
        score = 820
        if field_counts[IONOS_WATTREL] == 0:
            score -= 220
        if field_counts[IONOS_KILOWATTREL] + hand_counts[IONOS_KILOWATTREL] >= 2:
            score -= 220
    elif cid == IONOS_TADBULB:
        score = 790
        if field_counts[IONOS_TADBULB] + field_counts[IONOS_BELLIBOLT_EX] >= 3:
            score -= 280
    elif cid == IONOS_VOLTORB:
        score = 720
        if field_counts[IONOS_VOLTORB] >= 2:
            score -= 240
    elif cid == IONOS_WATTREL:
        score = 600
        if field_counts[IONOS_WATTREL] + field_counts[IONOS_KILOWATTREL] >= 2:
            score -= 220
    elif cid == BASIC_LIGHTNING:
        score = 660 if field_counts[IONOS_BELLIBOLT_EX] else 480
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
        score = 680 if (field_counts[TEAL_MASK_OGERPON_EX] or field_counts[HYDRAPPLE_EX] or field_counts[APPLIN_TWM] or field_counts[APPLIN_SCR]) else 430
    elif cid in {BASIC_WATER, BASIC_PSYCHIC, BASIC_FIGHTING, BASIC_DARKNESS, BASIC_METAL}:
        score = 300
    elif cid in {MIST_ENERGY, SPIKY_ENERGY}:
        score = 340
    elif cid == FIGHTING_GONG:
        score = 780 if any(field_counts[item] for item in FIGHTING_TOOLBOX_LINE) else 590
    elif cid == TARRAGON:
        score = 650 if discard_counts[BASIC_FIGHTING] or any(discard_counts[item] for item in FIGHTING_TOOLBOX_LINE) else 420
    elif cid == COLRESS_TENACITY:
        score = 560 if hand_counts[BASIC_FIGHTING] + hand_counts[PRISM_ENERGY] < 2 else 380
    elif cid == AIR_BALLOON:
        score = 520
    elif cid in {BATTLE_CAGE, NEUTRALIZATION_ZONE}:
        score = 590
    elif cid == JUDGE:
        score = 420
    elif cid in {DUSK_BALL, MEGA_SIGNAL, PREMIUM_POWER_PRO, TEAM_ROCKETS_TRANSCEIVER, ROTO_STICK, TERA_ORB}:
        score = 590
    elif cid in {CRISPIN, SWITCH, ENERGY_SEARCH, BROCKS_SCOUTING, UNFAIR_STAMP, HAND_TRIMMER, BUG_CATCHING_SET, GLASS_TRUMPET, ENERGY_SWITCH, N_PP_UP, GRAVITY_MOUNTAIN, TEAM_ROCKETS_WATCHTOWER, TEAM_ROCKETS_FACTORY, FOREST_OF_VITALITY, SURFING_BEACH, AREA_ZERO_UNDERDEPTHS, N_CASTLE, JAMMING_TOWER, ACADEMY_AT_NIGHT, RISKY_RUINS}:
        score = 430
    elif cid == WAITRESS:
        score = 620
    elif cid == COOK:
        score = 500
    elif cid in {CHEREN, HILDA, LILLIES_DETERMINATION, N_PLAN, BRIAR}:
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
    if cid in {OKIDOGI, BLOODMOON_URSALUNA, BARBARACLE}:
        score = -560 if hand_counts[cid] <= 1 else 80
    elif cid in {SOLROCK, LUNATONE, BINACLE}:
        score = -260 if hand_counts[cid] <= 1 else 140
    elif cid == PRISM_ENERGY:
        score = 360 if hand_counts[PRISM_ENERGY] >= 2 else -160
    elif cid == BASIC_FIGHTING and any(field_counts[item] for item in FIGHTING_TOOLBOX_LINE):
        score = 520 if hand_counts[BASIC_FIGHTING] >= 4 else -80
    elif cid in {FIGHTING_GONG, TARRAGON, COLRESS_TENACITY, AIR_BALLOON, BATTLE_CAGE, NEUTRALIZATION_ZONE}:
        score = 180 if hand_counts[cid] >= 2 else 20
    elif cid in {DRAGAPULT_EX, DRAKLOAK, DUSKNOIR, DUSCLOPS, NOCTOWL, LILLIES_CLEFAIRY_EX, MEGA_KANGASKHAN_EX, MEGA_LUCARIO_EX, MEGA_ABOMASNOW_EX, TEAM_ROCKETS_HONCHKROW, N_ZOROARK_EX, N_DARMANITAN, N_ZEKROM, N_KLINKLANG, STEVENS_METAGROSS_EX, METAGROSS, SLOWKING, HYDRAPPLE_EX, HYDRAPPLE, TYRANITAR}:
        score = -560 if hand_counts[cid] <= 1 else 80
    elif cid in {DREEPY, DUSKULL, HOOTHOOT, FAN_ROTOM, MEOWTH_EX, RIOLU, SNOVER, TEAM_ROCKETS_MURKROW, N_ZORUA, N_KLINK, KYUREM, ZERAORA, MUNKIDORI, PECHARUNT, PECHARUNT_EX, SLOWPOKE, APPLIN_TWM, APPLIN_SCR, TEAL_MASK_OGERPON_EX, CORNERSTONE_MASK_OGERPON_EX, IRON_LEAVES_EX, LARVITAR}:
        score = -260 if hand_counts[cid] <= 1 else 140
    elif cid in {BASIC_FIRE, BASIC_WATER, BASIC_PSYCHIC, BASIC_FIGHTING, BASIC_DARKNESS, BASIC_METAL, TEAM_ROCKET_ENERGY, IGNITION_ENERGY}:
        score = 520 if hand_counts[cid] >= 3 else 120
    elif cid == BASIC_LIGHTNING:
        score = 620 if hand_counts[BASIC_LIGHTNING] >= 3 else 180
    elif cid in {IONOS_VOLTORB, IONOS_TADBULB, IONOS_WATTREL}:
        score = -220 if hand_counts[cid] <= 1 else 160
    elif cid in {IONOS_BELLIBOLT_EX, IONOS_KILOWATTREL}:
        score = -520 if hand_counts[cid] <= 1 else 80
    elif cid in {CANARI, LILLIES_DETERMINATION}:
        score = 430 if hand_counts[cid] >= 2 else 80
    elif cid in {NIGHT_STRETCHER, MAX_ROD, ENERGY_RETRIEVAL, POKE_PAD, ENERGY_SWITCH, GLASS_TRUMPET, N_PP_UP}:
        score = 180 if hand_counts[cid] >= 2 else 40
    elif cid == ETHANS_ADVENTURE:
        score = 720 if field_counts[ETHANS_TYPHLOSION] else 260
    elif cid in {BASIC_FIRE, BASIC_GRASS, GROW_GRASS, MIST_ENERGY, SPIKY_ENERGY}:
        score = 520 if hand_counts[cid] >= 2 else 220
    elif cid in {CARMINE, LILLIES_DETERMINATION, COOK, CHEREN, HILDA, WAITRESS, N_PLAN, BRIAR}:
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
    if pokemon.id in DRAGAPULT_LINE:
        if energy_id in {BASIC_FIRE, BASIC_PSYCHIC}:
            score += 980
        elif energy_id not in {BASIC_FIRE, BASIC_PSYCHIC}:
            score -= 300
        if pokemon.id == DRAGAPULT_EX:
            score += 650
        if active:
            score += 700
        if energy_count < 2:
            score += 430
        else:
            score -= 120
    elif pokemon.id in DUSKNOIR_LINE:
        if energy_id == BASIC_PSYCHIC:
            score += 760
        else:
            score -= 220
        if pokemon.id == DUSKNOIR:
            score += 420
    elif pokemon.id == LILLIES_CLEFAIRY_EX:
        if energy_id in {BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score += 920
        elif energy_id == BASIC_FIGHTING:
            score += 220
        else:
            score -= 180
        if active:
            score += 520
        if energy_count < 2:
            score += 320
    elif pokemon.id in {MEGA_KANGASKHAN_EX, MEOWTH_EX}:
        if energy_id in {BASIC_PSYCHIC, BASIC_FIGHTING, BASIC_LIGHTNING, BASIC_DARKNESS, BASIC_FIRE, BASIC_WATER, BASIC_GRASS}:
            score += 520
        if pokemon.id == MEGA_KANGASKHAN_EX:
            score += 650
        if active:
            score += 550
        if energy_count < 3:
            score += 260
    elif pokemon.id == LATIAS_EX:
        if energy_id in {BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score += 620
        elif energy_id not in {BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score -= 120
        if active:
            score += 180
    elif pokemon.id == WELLSPRING_MASK_OGERPON_EX:
        if energy_id == BASIC_WATER:
            score += 760
        elif energy_id not in {BASIC_WATER, BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score -= 180
        if active:
            score += 460
    elif pokemon.id == KORAIDON_EX:
        if energy_id == BASIC_FIGHTING:
            score += 820
        elif energy_id not in {BASIC_FIGHTING, BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score -= 180
        if active:
            score += 480
    elif pokemon.id == MOLTRES:
        if energy_id == BASIC_FIRE:
            score += 720
        else:
            score -= 140
        if active:
            score += 300
    elif pokemon.id == CHIEN_PAO:
        if energy_id == BASIC_WATER:
            score += 640
        else:
            score -= 120
    elif pokemon.id in FIGHTING_TOOLBOX_LINE:
        if energy_id in {BASIC_FIGHTING, PRISM_ENERGY}:
            score += 1040
        else:
            score -= 260
        if pokemon.id in {OKIDOGI, BLOODMOON_URSALUNA, BARBARACLE}:
            score += 620
        elif pokemon.id == SOLROCK:
            score += 500
        elif pokemon.id == LUNATONE:
            score += 220
        elif pokemon.id == BINACLE:
            score += 120
        if active:
            score += 440
        if energy_count == 0:
            score += 420
        elif pokemon.id in {OKIDOGI, BLOODMOON_URSALUNA, BARBARACLE, SOLROCK} and energy_count < 2:
            score += 160
        else:
            score -= 100
    elif pokemon.id in LUCARIO_LINE:
        if energy_id == BASIC_FIGHTING:
            score += 1100
        else:
            score -= 280
        if pokemon.id == MEGA_LUCARIO_EX:
            score += 700
        if active:
            score += 600
        if energy_count < 2:
            score += 420
        else:
            score -= 130
    elif pokemon.id in ABOMASNOW_LINE:
        if energy_id == BASIC_WATER:
            score += 1200
        else:
            score -= 260
        if pokemon.id == MEGA_ABOMASNOW_EX:
            score += 820
        if active:
            score += 520
        if energy_count < 3:
            score += 420
        else:
            score -= 100
    elif pokemon.id in ROCKET_LINE:
        if energy_id in {BASIC_DARKNESS, TEAM_ROCKET_ENERGY, IGNITION_ENERGY}:
            score += 900
        else:
            score -= 240
        if pokemon.id == TEAM_ROCKETS_HONCHKROW:
            score += 540
        if active:
            score += 350
    elif pokemon.id in N_ZOROARK_LINE:
        if energy_id in {BASIC_DARKNESS, BASIC_FIRE, BASIC_LIGHTNING, BASIC_METAL, BASIC_WATER}:
            score += 760
        else:
            score -= 180
        if pokemon.id in {N_ZOROARK_EX, N_DARMANITAN, N_ZEKROM, STEVENS_METAGROSS_EX}:
            score += 520
        if active:
            score += 380
    elif pokemon.id in SLOWKING_LINE:
        if pokemon.id in {MUNKIDORI, PECHARUNT, PECHARUNT_EX}:
            if energy_id == BASIC_DARKNESS:
                score += 760
            elif energy_id != BASIC_PSYCHIC:
                score -= 160
        elif energy_id in {BASIC_PSYCHIC, TELEPATH_PSYCHIC_ENERGY}:
            score += 780
        else:
            score -= 180
        if pokemon.id == SLOWKING:
            score += 450
        if active:
            score += 300
    elif pokemon.id in GRASS_TOOLBOX_LINE:
        if energy_id in {BASIC_GRASS, GROW_GRASS}:
            score += 950
        else:
            score -= 220
        if pokemon.id in {TEAL_MASK_OGERPON_EX, IRON_LEAVES_EX, HYDRAPPLE_EX, HYDRAPPLE, MEGANIUM}:
            score += 520
        if active:
            score += 280
    elif pokemon.id in {LARVITAR, PUPITAR, TYRANITAR}:
        if energy_id in {BASIC_DARKNESS, BASIC_FIGHTING}:
            score += 720
        if pokemon.id == TYRANITAR:
            score += 500
    elif pokemon.id in IONO_POKEMON:
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
        if pokemon.id == DRAGAPULT_EX:
            score += 1900
        elif pokemon.id == DRAKLOAK:
            score += 850
        elif pokemon.id == DREEPY:
            score += 420
        elif pokemon.id == DUSKNOIR:
            score += 1400
        elif pokemon.id == DUSCLOPS:
            score += 880
        elif pokemon.id == DUSKULL:
            score += 320
        elif pokemon.id == NOCTOWL:
            score += 700
        elif pokemon.id == FAN_ROTOM:
            score += 500
        elif pokemon.id == LILLIES_CLEFAIRY_EX:
            score += 1700
        elif pokemon.id == MEGA_KANGASKHAN_EX:
            score += 2100
        elif pokemon.id == MEOWTH_EX:
            score += 720
        elif pokemon.id == MEGA_LUCARIO_EX:
            score += 2100
        elif pokemon.id == RIOLU:
            score += 520
        elif pokemon.id == OKIDOGI:
            score += 1500
        elif pokemon.id == BLOODMOON_URSALUNA:
            score += 1650
        elif pokemon.id == BARBARACLE:
            score += 1300
        elif pokemon.id == SOLROCK:
            score += 1150
        elif pokemon.id == LUNATONE:
            score += 520
        elif pokemon.id == BINACLE:
            score += 360
        elif pokemon.id == MEGA_ABOMASNOW_EX:
            score += 2200
        elif pokemon.id == SNOVER:
            score += 430
        elif pokemon.id == TEAM_ROCKETS_HONCHKROW:
            score += 1550
        elif pokemon.id == TEAM_ROCKETS_MURKROW:
            score += 420
        elif pokemon.id == N_ZOROARK_EX:
            score += 1900
        elif pokemon.id in {N_DARMANITAN, N_ZEKROM, STEVENS_METAGROSS_EX}:
            score += 1450
        elif pokemon.id in {N_ZORUA, N_KLINK, KYUREM, ZERAORA}:
            score += 450
        elif pokemon.id == SLOWKING:
            score += 1500
        elif pokemon.id in {SLOWPOKE, MUNKIDORI, PECHARUNT, PECHARUNT_EX}:
            score += 420
        elif pokemon.id in {TEAL_MASK_OGERPON_EX, HYDRAPPLE_EX, IRON_LEAVES_EX}:
            score += 1700
        elif pokemon.id in {HYDRAPPLE, DIPPLIN_TWM, DIPPLIN_SCR, CORNERSTONE_MASK_OGERPON_EX}:
            score += 1050
        elif pokemon.id in {APPLIN_TWM, APPLIN_SCR}:
            score += 420
        elif pokemon.id == IONOS_KILOWATTREL:
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
    fighting_board = any(field_counts[item] for item in FIGHTING_TOOLBOX_LINE)
    fighting_energy_in_hand = hand_counts[BASIC_FIGHTING] + hand_counts[PRISM_ENERGY]
    if (
        fighting_board
        and not state.energyAttached
        and fighting_energy_in_hand
        and cid in {POKE_PAD, FIGHTING_GONG, BATTLE_CAGE, NEUTRALIZATION_ZONE, COLRESS_TENACITY, TARRAGON, JUDGE, LILLIES_DETERMINATION}
    ):
        return 1800
    if is_pokemon_id(cid):
        score = 7600 if is_basic_id(cid) and bench_space > 0 else 1200
        if cid == DREEPY and field_counts[DREEPY] + field_counts[DRAKLOAK] + field_counts[DRAGAPULT_EX] >= 3:
            score = -100
        elif cid == DUSKULL and field_counts[DUSKULL] + field_counts[DUSCLOPS] + field_counts[DUSKNOIR] >= 2:
            score = -100
        elif cid == HOOTHOOT and field_counts[HOOTHOOT] + field_counts[NOCTOWL] >= 2:
            score = -100
        elif cid == LILLIES_CLEFAIRY_EX and field_counts[LILLIES_CLEFAIRY_EX] >= 2:
            score = -100
        elif cid == MEGA_KANGASKHAN_EX and field_counts[MEGA_KANGASKHAN_EX] >= 2:
            score = -100
        elif cid == MEOWTH_EX and field_counts[MEOWTH_EX] >= 2:
            score = -100
        elif cid == RIOLU and field_counts[RIOLU] + field_counts[MEGA_LUCARIO_EX] >= 3:
            score = -100
        elif cid == OKIDOGI and field_counts[OKIDOGI] >= 1:
            score = -100
        elif cid == BLOODMOON_URSALUNA and field_counts[BLOODMOON_URSALUNA] >= 1:
            score = -100
        elif cid == SOLROCK and field_counts[SOLROCK] >= 1:
            score = -100
        elif cid == LUNATONE and (field_counts[LUNATONE] >= 1 or not field_counts[SOLROCK]):
            score = -100
        elif cid == BINACLE and field_counts[BINACLE] + field_counts[BARBARACLE] >= 2:
            score = -100
        elif cid == SNOVER and field_counts[SNOVER] + field_counts[MEGA_ABOMASNOW_EX] >= 3:
            score = -100
        elif cid == TEAM_ROCKETS_MURKROW and field_counts[TEAM_ROCKETS_MURKROW] + field_counts[TEAM_ROCKETS_HONCHKROW] >= 3:
            score = -100
        elif cid == N_ZORUA and field_counts[N_ZORUA] + field_counts[N_ZOROARK_EX] >= 3:
            score = -100
        elif cid == SLOWPOKE and field_counts[SLOWPOKE] + field_counts[SLOWKING] >= 4:
            score = -100
        elif cid in {APPLIN_TWM, APPLIN_SCR} and field_counts[APPLIN_TWM] + field_counts[APPLIN_SCR] + field_counts[DIPPLIN_TWM] + field_counts[DIPPLIN_SCR] + field_counts[HYDRAPPLE_EX] >= 4:
            score = -100
        elif cid == OKIDOGI:
            score += 2600
        elif cid == SOLROCK:
            score += 2500
        elif cid == LUNATONE:
            score += 1600 if field_counts[SOLROCK] else 900
        elif cid == BINACLE:
            score += 1500
        elif cid == BLOODMOON_URSALUNA:
            score += 1300
        elif cid in {FAN_ROTOM, MAKUHITA, CHIKORITA, TEAL_MASK_OGERPON_EX, MUNKIDORI, TATSUGIRI, FEZANDIPITI_EX, PECHARUNT_EX, IRON_LEAVES_EX}:
            score += 1800
        if cid == DWEBBLE and field_counts[DWEBBLE] + field_counts[CRUSTLE] >= 4:
            score = -100
        elif cid == ETHANS_CYNDAQUIL and field_counts[ETHANS_CYNDAQUIL] + field_counts[ETHANS_QUILAVA] + field_counts[ETHANS_TYPHLOSION] >= 2:
            score = -100
        return score

    if cid == BUDDY_BUDDY_POFFIN:
        core_basics = (
            field_counts[DWEBBLE]
            + field_counts[ETHANS_CYNDAQUIL]
            + field_counts[DREEPY]
            + field_counts[DUSKULL]
            + field_counts[HOOTHOOT]
            + field_counts[LILLIES_CLEFAIRY_EX]
            + field_counts[RIOLU]
            + field_counts[OKIDOGI]
            + field_counts[SOLROCK]
            + field_counts[LUNATONE]
            + field_counts[BINACLE]
            + field_counts[SNOVER]
            + field_counts[TEAM_ROCKETS_MURKROW]
            + field_counts[N_ZORUA]
            + field_counts[SLOWPOKE]
            + field_counts[APPLIN_TWM]
            + field_counts[APPLIN_SCR]
        )
        return 24000 if bench_space > 0 and core_basics < 5 else -100
    if cid == RARE_CANDY:
        if (
            hand_counts[ETHANS_TYPHLOSION] and field_counts[ETHANS_CYNDAQUIL]
            or hand_counts[DRAGAPULT_EX] and field_counts[DREEPY]
            or hand_counts[DUSKNOIR] and field_counts[DUSKULL]
            or hand_counts[TYRANITAR] and field_counts[LARVITAR]
            or hand_counts[MEGANIUM] and field_counts[CHIKORITA]
            or hand_counts[N_KLINKLANG] and field_counts[N_KLINK]
            or hand_counts[HYDRAPPLE_EX] and (field_counts[APPLIN_TWM] or field_counts[APPLIN_SCR] or field_counts[DIPPLIN_TWM] or field_counts[DIPPLIN_SCR])
        ):
            return 23000
        return 3500
    if cid == ULTRA_BALL:
        need_piece = (
            (field_counts[ETHANS_CYNDAQUIL] and not (field_counts[ETHANS_TYPHLOSION] or hand_counts[ETHANS_TYPHLOSION]))
            or (field_counts[DWEBBLE] and not (field_counts[CRUSTLE] or hand_counts[CRUSTLE]))
            or (field_counts[IONOS_TADBULB] and not (field_counts[IONOS_BELLIBOLT_EX] or hand_counts[IONOS_BELLIBOLT_EX]))
            or (field_counts[IONOS_WATTREL] and not (field_counts[IONOS_KILOWATTREL] or hand_counts[IONOS_KILOWATTREL]))
            or (field_counts[DREEPY] and not (field_counts[DRAGAPULT_EX] or hand_counts[DRAGAPULT_EX]))
            or (field_counts[DUSKULL] and not (field_counts[DUSCLOPS] or field_counts[DUSKNOIR] or hand_counts[DUSCLOPS] or hand_counts[DUSKNOIR]))
            or (field_counts[HOOTHOOT] and not (field_counts[NOCTOWL] or hand_counts[NOCTOWL]))
            or (field_counts[LILLIES_CLEFAIRY_EX] < 2 and not hand_counts[LILLIES_CLEFAIRY_EX])
            or (field_counts[MEGA_KANGASKHAN_EX] < 2 and not hand_counts[MEGA_KANGASKHAN_EX])
            or (field_counts[RIOLU] and not (field_counts[MEGA_LUCARIO_EX] or hand_counts[MEGA_LUCARIO_EX]))
            or (field_counts[BINACLE] and not (field_counts[BARBARACLE] or hand_counts[BARBARACLE]))
            or (field_counts[OKIDOGI] < 1 and not hand_counts[OKIDOGI])
            or (field_counts[SOLROCK] < 1 and not hand_counts[SOLROCK])
            or (field_counts[SOLROCK] and field_counts[LUNATONE] < 1 and not hand_counts[LUNATONE])
            or (field_counts[SNOVER] and not (field_counts[MEGA_ABOMASNOW_EX] or hand_counts[MEGA_ABOMASNOW_EX]))
            or (field_counts[TEAM_ROCKETS_MURKROW] and not (field_counts[TEAM_ROCKETS_HONCHKROW] or hand_counts[TEAM_ROCKETS_HONCHKROW]))
            or (field_counts[N_ZORUA] and not (field_counts[N_ZOROARK_EX] or hand_counts[N_ZOROARK_EX]))
            or (field_counts[SLOWPOKE] and not (field_counts[SLOWKING] or hand_counts[SLOWKING]))
            or ((field_counts[APPLIN_TWM] or field_counts[APPLIN_SCR] or field_counts[DIPPLIN_TWM] or field_counts[DIPPLIN_SCR]) and not (field_counts[HYDRAPPLE_EX] or hand_counts[HYDRAPPLE_EX]))
        )
        return 20500 if need_piece else 9000
    if cid == DUSK_BALL:
        needs_piece = (
            field_counts[RIOLU] and not (field_counts[MEGA_LUCARIO_EX] or hand_counts[MEGA_LUCARIO_EX])
            or field_counts[BINACLE] and not (field_counts[BARBARACLE] or hand_counts[BARBARACLE])
            or field_counts[OKIDOGI] < 1
            or field_counts[SOLROCK] < 1
            or field_counts[N_ZORUA] and not (field_counts[N_ZOROARK_EX] or hand_counts[N_ZOROARK_EX])
            or field_counts[SLOWPOKE] and not (field_counts[SLOWKING] or hand_counts[SLOWKING])
            or field_counts[APPLIN_TWM] + field_counts[APPLIN_SCR] and not (field_counts[HYDRAPPLE_EX] or hand_counts[HYDRAPPLE_EX])
        )
        return 24500 if needs_piece else 12500
    if cid == MEGA_SIGNAL:
        return 25000 if field_counts[SNOVER] and not (field_counts[MEGA_ABOMASNOW_EX] or hand_counts[MEGA_ABOMASNOW_EX]) else 12000
    if cid == FIGHTING_GONG:
        fighting_board = any(field_counts[item] for item in FIGHTING_TOOLBOX_LINE)
        needs_toolbox_piece = field_counts[OKIDOGI] < 1 or field_counts[SOLROCK] < 1 or (field_counts[BINACLE] and not field_counts[BARBARACLE])
        return 9000 if fighting_board and needs_toolbox_piece else 25000 if field_counts[MEGA_LUCARIO_EX] or field_counts[RIOLU] else 13500
    if cid == PREMIUM_POWER_PRO:
        active_ready = active is not None and active.id == MEGA_LUCARIO_EX
        return 23000 if active_ready or field_counts[MEGA_LUCARIO_EX] else 11500
    if cid == CRISPIN:
        need_dual = any(p.id in {DREEPY, DRAKLOAK, DRAGAPULT_EX, N_ZOROARK_EX, N_DARMANITAN, N_ZEKROM, LILLIES_CLEFAIRY_EX} and len(p.energies) < 2 for _, _, p in all_field_pokemon(my_state))
        return 22000 if need_dual else 9500
    if cid == TERA_ORB:
        needs_tera = not (field_counts[DRAGAPULT_EX] or hand_counts[DRAGAPULT_EX])
        return 21000 if needs_tera and field_counts[DREEPY] else 9500
    if cid == BROCKS_SCOUTING:
        has_search_line = field_counts[DREEPY] or field_counts[DUSKULL] or field_counts[LILLIES_CLEFAIRY_EX]
        return 19000 if has_search_line else 8500
    if cid == CYRANO:
        wants_ex = (
            field_counts[LILLIES_CLEFAIRY_EX] < 2
            or field_counts[MEGA_KANGASKHAN_EX] < 2
            or field_counts[MEOWTH_EX] < 1
            or field_counts[WELLSPRING_MASK_OGERPON_EX] < 1
        )
        return 20500 if wants_ex else 9000
    if cid == CIPHERMANIAC:
        return 17500 if my_state.handCount <= 5 or state.turn <= 4 else 7000
    if cid == ENERGY_SEARCH:
        return 14500 if any(len(p.energies) == 0 for _, _, p in all_field_pokemon(my_state)) else 4500
    if cid == BUG_CATCHING_SET:
        wants_grass = field_counts[TEAL_MASK_OGERPON_EX] + field_counts[HYDRAPPLE_EX] + field_counts[APPLIN_TWM] + field_counts[APPLIN_SCR] < 5
        return 20500 if wants_grass or my_state.handCount <= 5 else 7500
    if cid == GLASS_TRUMPET:
        has_tera = field_counts[TEAL_MASK_OGERPON_EX] or field_counts[HYDRAPPLE_EX] or field_counts[CORNERSTONE_MASK_OGERPON_EX]
        return 19000 if has_tera and discard_counts[BASIC_GRASS] else 3500
    if cid == ENERGY_SWITCH:
        has_benched_energy = any(p.id in {TEAL_MASK_OGERPON_EX, HYDRAPPLE_EX, IRON_LEAVES_EX} and len(p.energies) for _, _, p in all_field_pokemon(my_state))
        return 17500 if has_benched_energy else 3500
    if cid == N_PP_UP:
        has_n_target = any(p.id in {N_ZOROARK_EX, N_DARMANITAN, N_ZEKROM, N_KLINKLANG} for _, _, p in all_field_pokemon(my_state))
        return 17500 if has_n_target and (discard_counts[BASIC_DARKNESS] or discard_counts[BASIC_LIGHTNING] or discard_counts[BASIC_FIRE] or discard_counts[BASIC_METAL]) else 2500
    if cid == UNFAIR_STAMP:
        return 18000 if state.turn >= 4 else 2500
    if cid == TEAM_ROCKETS_TRANSCEIVER:
        return 22000 if field_counts[TEAM_ROCKETS_MURKROW] or field_counts[TEAM_ROCKETS_HONCHKROW] else 10000
    if cid == ROTO_STICK:
        return 15000 if my_state.handCount <= 6 else 6500
    if cid == POKE_PAD:
        missing_toolbox = field_counts[OKIDOGI] < 1 or field_counts[SOLROCK] < 1 or (field_counts[BINACLE] and not field_counts[BARBARACLE])
        return 12500 if missing_toolbox or my_state.handCount <= 5 else 8000
    if cid == CANARI:
        iono_basics = field_counts[IONOS_VOLTORB] + field_counts[IONOS_TADBULB] + field_counts[IONOS_WATTREL]
        return 25500 if my_state.handCount > 1 and iono_basics < 5 else 9500
    if cid == ENERGY_RETRIEVAL:
        relevant_discards = (
            discard_counts[BASIC_LIGHTNING]
            + discard_counts[BASIC_PSYCHIC]
            + discard_counts[BASIC_FIRE]
            + discard_counts[BASIC_FIGHTING]
            + discard_counts[BASIC_WATER]
        )
        return 15000 if relevant_discards >= 2 else 4500
    if cid == WONDROUS_PATCH:
        has_psychic_target = any(
            p is not None
            and p.id in {LILLIES_CLEFAIRY_EX, LATIAS_EX}
            and len(getattr(p, "energies", [])) < 2
            for area, _, p in all_field_pokemon(my_state)
            if area == AreaType.BENCH
        )
        return 21000 if discard_counts[BASIC_PSYCHIC] and has_psychic_target else 2500
    if cid == NIGHT_STRETCHER:
        recover_lines = IONO_POKEMON | DRAGAPULT_LINE | DUSKNOIR_LINE | CLEFAIRY_KANGASKHAN_LINE | N_ZOROARK_LINE | SLOWKING_LINE | GRASS_TOOLBOX_LINE | FIGHTING_TOOLBOX_LINE
        need_pokemon = any(discard_counts[cid2] for cid2 in recover_lines)
        return 12500 if discard_counts[BASIC_LIGHTNING] or discard_counts[BASIC_PSYCHIC] or discard_counts[BASIC_GRASS] or discard_counts[BASIC_FIGHTING] or discard_counts[PRISM_ENERGY] or need_pokemon else 3000
    if cid == MAX_ROD:
        recover_lines = IONO_POKEMON | DRAGAPULT_LINE | DUSKNOIR_LINE | CLEFAIRY_KANGASKHAN_LINE | N_ZOROARK_LINE | SLOWKING_LINE | GRASS_TOOLBOX_LINE | FIGHTING_TOOLBOX_LINE
        recoverable = discard_counts[BASIC_LIGHTNING] + discard_counts[BASIC_PSYCHIC] + discard_counts[BASIC_GRASS] + discard_counts[BASIC_FIGHTING] + discard_counts[PRISM_ENERGY] + sum(discard_counts[cid2] for cid2 in recover_lines)
        return 13500 if recoverable >= 3 else 3500
    if cid == CRUSHING_HAMMER:
        return 18000 if op_state.active or op_state.bench else 0
    if cid == PRIME_CATCHER:
        if active is not None and can_attack_now(select):
            best_target = max(op_state.bench, key=pokemon_value, default=None)
            if best_target is not None:
                for option in select.option:
                    if option.type == OptionType.ATTACK:
                        if contextual_attack_damage(active, best_target, option.attackId, discard_counts, my_state, op_state) >= best_target.hp:
                            return 26000 + pokemon_value(best_target)
                return 18000 + pokemon_value(best_target) // 6
        return 8500
    if cid == ETHANS_ADVENTURE:
        return 26000 + discard_counts[ETHANS_ADVENTURE] * 40
    if cid == LILLIES_DETERMINATION:
        return 16500 if my_state.handCount <= 5 or state.turn <= 4 else 8000
    if cid == JUDGE:
        return 14500 if my_state.handCount <= 4 or op_state.handCount >= 6 else 5200
    if cid == TARRAGON:
        recoverable = discard_counts[BASIC_FIGHTING] + discard_counts[PRISM_ENERGY] + sum(discard_counts[item] for item in FIGHTING_TOOLBOX_LINE)
        return 17000 if recoverable else 6200
    if cid == COLRESS_TENACITY:
        needs_energy = any(p.id in FIGHTING_TOOLBOX_LINE and len(p.energies) == 0 for _, _, p in all_field_pokemon(my_state))
        return 15500 if needs_energy or not state.stadium else 6500
    if cid == HILDA:
        wants_evolution = field_counts[SLOWPOKE] or field_counts[APPLIN_TWM] or field_counts[APPLIN_SCR] or field_counts[N_ZORUA]
        return 19000 if wants_evolution else 7500
    if cid == N_PLAN:
        has_n_attacker = active is not None and active.id in N_ZOROARK_LINE
        return 15000 if has_n_attacker or field_counts[N_ZOROARK_EX] else 4500
    if cid == BRIAR:
        return 15500 if len(op_state.prize) == 2 else 2500
    if cid == CARMINE:
        return 15500 if state.turn <= 3 or my_state.handCount <= 4 else 6500
    if cid == WAITRESS:
        need_energy = any(p.id in {DWEBBLE, CRUSTLE} and len(p.energies) < 3 for _, _, p in all_field_pokemon(my_state))
        need_energy = need_energy or any(p.id in {SNOVER, MEGA_ABOMASNOW_EX} and len(p.energies) < 3 for _, _, p in all_field_pokemon(my_state))
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
            current_damage = best_attack_damage(active, op_active, select, discard_counts, my_state, op_state)
            for bench_pokemon in op_state.bench:
                for option in select.option:
                    if option.type == OptionType.ATTACK:
                        if contextual_attack_damage(active, bench_pokemon, option.attackId, discard_counts, my_state, op_state) >= bench_pokemon.hp:
                            return 21000 + pokemon_value(bench_pokemon)
            if op_active is not None and current_damage >= op_active.hp:
                return -50
        return 6200
    if cid == JUMBO_ICE_CREAM:
        if active is not None and len(active.energies) >= 3 and active.hp < active.maxHp:
            return 19000 + (active.maxHp - active.hp)
        return 1200
    if cid in {BATTLE_CAGE, NEUTRALIZATION_ZONE}:
        return 9800 if not state.stadium else 2500
    if cid in {GRAVITY_MOUNTAIN, TEAM_ROCKETS_WATCHTOWER, TEAM_ROCKETS_FACTORY, FOREST_OF_VITALITY, SURFING_BEACH, AREA_ZERO_UNDERDEPTHS, N_CASTLE, JAMMING_TOWER, ACADEMY_AT_NIGHT, RISKY_RUINS}:
        return 11500 if not state.stadium else 3000
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
            if cid == SOLROCK:
                return 640
            if cid == OKIDOGI:
                return 630
            if cid == BLOODMOON_URSALUNA:
                return 620
            if cid == LUNATONE:
                return 610
            if cid == BINACLE:
                return 600
            if cid == MEGA_KANGASKHAN_EX:
                return 650
            if cid == LILLIES_CLEFAIRY_EX:
                return 620
            if cid == RIOLU:
                return 610
            if cid == DREEPY:
                return 590
            if cid == N_ZORUA:
                return 585
            if cid == SLOWPOKE:
                return 580
            if cid in {TEAL_MASK_OGERPON_EX, APPLIN_TWM, APPLIN_SCR}:
                return 575
            if cid == DUSKULL:
                return 570
            if cid == SNOVER:
                return 560
            if cid in {FAN_ROTOM, HOOTHOOT, MEOWTH_EX, TEAL_MASK_OGERPON_EX, MUNKIDORI, TATSUGIRI, PECHARUNT_EX, TEAM_ROCKETS_MURKROW, LARVITAR}:
                return 500
            if cid == IONOS_VOLTORB:
                return 560
            if cid == IONOS_TADBULB:
                return 520
            if cid == IONOS_WATTREL:
                return 430
            if cid == DWEBBLE:
                return 500 if state.firstPlayer != my_index else 360
            if cid == ETHANS_CYNDAQUIL:
                return 470 if state.firstPlayer == my_index else 390
            return 100
        if context in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH, SelectContext.TO_FIELD):
            if cid in FIGHTING_TOOLBOX_LINE:
                return -20
            if cid == DREEPY:
                return 780 - (field_counts[DREEPY] + field_counts[DRAKLOAK] + field_counts[DRAGAPULT_EX]) * 130
            if cid == DUSKULL:
                return 690 - (field_counts[DUSKULL] + field_counts[DUSCLOPS] + field_counts[DUSKNOIR]) * 140
            if cid == HOOTHOOT:
                return 620 - (field_counts[HOOTHOOT] + field_counts[NOCTOWL]) * 120
            if cid == FAN_ROTOM:
                return 610 - field_counts[FAN_ROTOM] * 180
            if cid == LILLIES_CLEFAIRY_EX:
                return 760 - field_counts[LILLIES_CLEFAIRY_EX] * 140
            if cid == MEGA_KANGASKHAN_EX:
                return 780 - field_counts[MEGA_KANGASKHAN_EX] * 130
            if cid == MEOWTH_EX:
                return 660 - field_counts[MEOWTH_EX] * 140
            if cid == RIOLU:
                return 790 - (field_counts[RIOLU] + field_counts[MEGA_LUCARIO_EX]) * 130
            if cid == OKIDOGI:
                return 780 - field_counts[OKIDOGI] * 170
            if cid == SOLROCK:
                return 760 - field_counts[SOLROCK] * 120
            if cid == LUNATONE:
                return (700 if field_counts[SOLROCK] else 540) - field_counts[LUNATONE] * 140
            if cid == BINACLE:
                return 650 - (field_counts[BINACLE] + field_counts[BARBARACLE]) * 180
            if cid == BLOODMOON_URSALUNA:
                return 560 - field_counts[BLOODMOON_URSALUNA] * 220
            if cid == SNOVER:
                return 790 - (field_counts[SNOVER] + field_counts[MEGA_ABOMASNOW_EX]) * 130
            if cid == TEAM_ROCKETS_MURKROW:
                return 700 - (field_counts[TEAM_ROCKETS_MURKROW] + field_counts[TEAM_ROCKETS_HONCHKROW]) * 130
            if cid == N_ZORUA:
                return 760 - (field_counts[N_ZORUA] + field_counts[N_ZOROARK_EX]) * 140
            if cid == SLOWPOKE:
                return 720 - (field_counts[SLOWPOKE] + field_counts[SLOWKING]) * 120
            if cid in {APPLIN_TWM, APPLIN_SCR}:
                return 710 - (field_counts[APPLIN_TWM] + field_counts[APPLIN_SCR] + field_counts[DIPPLIN_TWM] + field_counts[DIPPLIN_SCR] + field_counts[HYDRAPPLE_EX]) * 110
            if cid in {MAKUHITA, TEAL_MASK_OGERPON_EX, CORNERSTONE_MASK_OGERPON_EX, IRON_LEAVES_EX, MUNKIDORI, TATSUGIRI, PECHARUNT_EX, CHIKORITA, LARVITAR}:
                return 560 - field_counts[cid] * 110
            if cid == IONOS_TADBULB:
                return 760 - (field_counts[IONOS_TADBULB] + field_counts[IONOS_BELLIBOLT_EX]) * 120
            if cid == IONOS_VOLTORB:
                return 730 - field_counts[IONOS_VOLTORB] * 130
            if cid == IONOS_WATTREL:
                return 610 - (field_counts[IONOS_WATTREL] + field_counts[IONOS_KILOWATTREL]) * 130
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
            if pokemon.id in {MEGA_LUCARIO_EX, MEGA_ABOMASNOW_EX, DRAGAPULT_EX, MEGA_KANGASKHAN_EX, N_ZOROARK_EX, STEVENS_METAGROSS_EX, HYDRAPPLE_EX, TEAL_MASK_OGERPON_EX}:
                return 24000
            if pokemon.id == LILLIES_CLEFAIRY_EX:
                return 19000
            if pokemon.id == CRUSTLE:
                return 22000
            if pokemon.id == ETHANS_TYPHLOSION:
                return 20000
            if pokemon.id in {DWEBBLE, ETHANS_CYNDAQUIL, ETHANS_QUILAVA}:
                return 12000
        if card.id == LILLIES_PEARL:
            if pokemon.id == LILLIES_CLEFAIRY_EX:
                return 23000
            return 1200
        if card.id == SPARKLING_CRYSTAL and pokemon.id == DRAGAPULT_EX:
            return 25000
        if card.id == AIR_BALLOON:
            if pokemon.id in {OKIDOGI, BLOODMOON_URSALUNA, SOLROCK, BARBARACLE}:
                return 19000 if option.inPlayArea == AreaType.ACTIVE else 12500
            if option.inPlayArea == AreaType.ACTIVE:
                return 13500
            return 4500
        return energy_attach_score(card.id, pokemon, option.inPlayArea == AreaType.ACTIVE, field_counts)

    if option.type == OptionType.EVOLVE:
        evolved = get_card(obs, option.area, option.index, my_index)
        target = get_card(obs, option.inPlayArea, option.inPlayIndex, my_index)
        if evolved is None:
            return 0
        if evolved.id == DRAGAPULT_EX:
            return 31000 + (len(target.energies) if target else 0) * 360
        if evolved.id == DRAKLOAK:
            return 21500 + (len(target.energies) if target else 0) * 180
        if evolved.id == DUSKNOIR:
            return 27500 + (len(target.energies) if target else 0) * 220
        if evolved.id == DUSCLOPS:
            return 22000 + (len(target.energies) if target else 0) * 140
        if evolved.id == NOCTOWL:
            return 26500
        if evolved.id == MEGA_LUCARIO_EX:
            return 32000 + (len(target.energies) if target else 0) * 420
        if evolved.id == BARBARACLE:
            return 11500 + (len(target.energies) if target else 0) * 180
        if evolved.id == MEGA_ABOMASNOW_EX:
            return 32500 + (len(target.energies) if target else 0) * 420
        if evolved.id == TEAM_ROCKETS_HONCHKROW:
            return 26000 + (len(target.energies) if target else 0) * 250
        if evolved.id == N_ZOROARK_EX:
            return 31000 + (len(target.energies) if target else 0) * 320
        if evolved.id in {N_KLINKLANG, STEVENS_METAGROSS_EX, HYDRAPPLE_EX}:
            return 30000 + (len(target.energies) if target else 0) * 360
        if evolved.id in {SLOWKING, HYDRAPPLE, DIPPLIN_TWM, DIPPLIN_SCR}:
            return 23500 + (len(target.energies) if target else 0) * 180
        if evolved.id in {HARIYAMA, TYRANITAR, MEGANIUM, HYDRAPPLE_EX}:
            return 23500 + (len(target.energies) if target else 0) * 220
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
        if card.id == DRAKLOAK:
            return 33000
        if card.id == DUSKNOIR:
            return 36000 if op_state.active or op_state.bench else 500
        if card.id == DUSCLOPS:
            return 27000 if op_state.active or op_state.bench else 500
        if card.id in {NOCTOWL, FAN_ROTOM, MEOWTH_EX, TATSUGIRI}:
            return 30000 if my_state.handCount <= 7 else 15000
        if card.id == MEGA_KANGASKHAN_EX:
            return 26000 if option.area == AreaType.ACTIVE or my_state.handCount <= 6 else 9000
        if card.id in {LUNATONE, BARBARACLE, SOLROCK} and not state.energyAttached and hand_counts[BASIC_FIGHTING] + hand_counts[PRISM_ENERGY]:
            return 700
        if card.id == LUNATONE:
            return 27000 if field_counts[SOLROCK] and hand_counts[BASIC_FIGHTING] else 6500
        if card.id == BARBARACLE:
            return 27500 if hand_counts[BASIC_FIGHTING] or hand_counts[PRISM_ENERGY] else 9000
        if card.id == BLOODMOON_URSALUNA:
            return 21000 if op_state.active or op_state.bench else 800
        if card.id in {SOLROCK, KYOGRE, TEAL_MASK_OGERPON_EX, HYDRAPPLE_EX, STEVENS_METAGROSS_EX, MEGA_LUCARIO_EX}:
            return 23000 if my_state.handCount <= 7 else 12000
        if card.id == N_ZOROARK_EX:
            return 30000 if my_state.handCount <= 6 else 14000
        if card.id in {MUNKIDORI, PECHARUNT_EX}:
            return 22000 if op_state.active or op_state.bench else 800
        if card.id == IONOS_BELLIBOLT_EX:
            return 34000 if hand_counts[BASIC_LIGHTNING] else 800
        if card.id == IONOS_KILOWATTREL:
            return 26000 if my_state.handCount <= 5 and count_attached_energy_cards(card, BASIC_LIGHTNING) else 700
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
        damage = contextual_attack_damage(active, op_active, option.attackId, discard_counts, my_state, op_state)
        score = 2500 + damage * 18
        if active.id in {DRAGAPULT_EX, MEGA_LUCARIO_EX, MEGA_ABOMASNOW_EX, MEGA_KANGASKHAN_EX, N_ZOROARK_EX, STEVENS_METAGROSS_EX, TEAL_MASK_OGERPON_EX, IRON_LEAVES_EX, OKIDOGI, BLOODMOON_URSALUNA, BARBARACLE, SOLROCK}:
            score += 1500 + len(getattr(active, "energies", [])) * 240
        elif active.id in {LILLIES_CLEFAIRY_EX, TEAM_ROCKETS_HONCHKROW, TYRANITAR, SLOWKING, HYDRAPPLE_EX, HYDRAPPLE, MUNKIDORI}:
            score += 900
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
