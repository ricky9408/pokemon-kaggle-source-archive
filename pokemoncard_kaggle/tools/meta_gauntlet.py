#!/usr/bin/env python3
"""Run candidates through a replay-derived live-meta gauntlet.

The earlier local tests overfit to a small set of our own agents. This runner
keeps the agent policy and deck separate: each opponent uses a local policy
template, but its deck can be pulled directly from a public Kaggle replay.

Run inside the linux/amd64 simulator environment, for example:

docker run -i --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work python:3.11-slim \
  python tools/meta_gauntlet.py --candidate agents/v27_poffin5 --games 20
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local_battle import load_agent, run_games  # noqa: E402


@dataclass(frozen=True)
class OpponentSpec:
    name: str
    policy: Path
    replay: Path | None
    slot: int
    weight: float
    note: str
    deck: tuple[int, ...] | None = None


DEFAULT_OPPONENTS = [
    OpponentSpec(
        name="live_iono_lightning_main",
        policy=Path("agents/v63_iono_lightning_patient"),
        replay=Path("scouting/live_top_20260619T022733Z/03__Kadoraba_16377364/submission_53800247/episode-80543687-replay.json"),
        slot=0,
        weight=2.00,
        note="Pachuru/onechan1/Angus/pinoko Iono Lightning hash 0391e57597, refreshed from the 2026-06-19 02:27 scout where it remains a top live winner cluster",
    ),
    OpponentSpec(
        name="live_iono_joltik_variant",
        policy=Path("agents/v63_iono_lightning_patient"),
        replay=Path("scouting/live_top_20260618T181017Z/12_DENPA92_16373853/submission_53771683/episode-80473413-replay.json"),
        slot=0,
        weight=0.35,
        note="Iono Lightning Joltik variant hash fb20a428d7 from the 2026-06-18 18:10 top-window scout, now kept as a small diversity hedge because the 20:40 top window was dominated by hash 0391e57597",
    ),
    OpponentSpec(
        name="naic_lillie_clefairy_kowalski",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.25,
        note="NAIC 2026 champion James Kowalski Lillie's Clefairy / Mega Kangaskhan decklist from Limitless",
        deck=(
            *([756] * 4),  # Mega Kangaskhan ex
            *([1071] * 4),  # Meowth ex
            *([272] * 4),  # Lillie's Clefairy ex
            *([184] * 3),  # Latias ex
            *([108] * 2),  # Wellspring Mask Ogerpon ex
            *([140] * 2),  # Fezandipiti ex
            791,  # Moltres
            209,  # Chien-Pao
            979,  # Koraidon ex
            *([1198] * 4),  # Crispin
            *([1182] * 3),  # Boss's Orders
            *([1188] * 2),  # Ciphermaniac's Codebreaking
            1205,  # Cyrano
            *([1121] * 4),  # Ultra Ball
            *([1102] * 4),  # Dusk Ball
            *([1146] * 3),  # Wondrous Patch
            1088,  # Prime Catcher
            *([1172] * 2),  # Lillie's Pearl
            *([1250] * 4),  # Area Zero Underdepths
            *([5] * 4),  # Psychic Energy
            *([3] * 2),  # Water Energy
            *([6] * 2),  # Fighting Energy
            19,  # Telepath Psychic Energy
            2,  # Fire Energy
        ),
    ),
    OpponentSpec(
        name="karacoro_mega_kangaskhan_crustle",
        policy=Path("agents/v62_karacoro_mega_kangaskhan"),
        replay=Path("scouting/live_top_0441/09_karacoro_16372692/submission_53793244/episode-80417629-replay.json"),
        slot=1,
        weight=1.6,
        note="karacoro live top-10 Mega Kangaskhan/Crustle disruption-heal shell hash 6395e7d90b, aligned with NAIC Mega Kangaskhan pressure",
    ),
    OpponentSpec(
        name="noikaret_fighting_toolbox",
        policy=Path("agents/v64_noikaret_fighting_toolbox"),
        replay=Path("scouting/live_top_0518/09_noikaret_16372588/submission_53795205/episode-80421174-replay.json"),
        slot=0,
        weight=1.65,
        note="noikaret live top-10 Fighting Toolbox hash e7b3ae683d with Solrock/Lunatone/Okidogi/Binacle, using exact current replay deck",
    ),
    OpponentSpec(
        name="indy_lucario_hariyama_courtney",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.65,
        note="Mitchell Courtney 24th-place Masters Lucario Hariyama from Regional Indianapolis 2026; explicit US top-player Mega Lucario/Hariyama coverage from Limitless",
        deck=(
            *([677] * 3),  # Riolu
            *([678] * 3),  # Mega Lucario ex
            *([676] * 3),  # Solrock
            *([673] * 2),  # Makuhita
            *([674] * 2),  # Hariyama
            *([675] * 2),  # Lunatone
            1071,  # Meowth ex
            142,  # Genesect
            *([1227] * 4),  # Lillie's Determination
            *([1182] * 2),  # Boss's Orders
            *([1213] * 2),  # Judge
            1199,  # Lacey
            *([1142] * 4),  # Fighting Gong
            *([1152] * 4),  # Poke Pad
            *([1141] * 4),  # Premium Power Pro
            *([1121] * 4),  # Ultra Ball
            *([1123] * 2),  # Switch
            *([1174] * 2),  # Air Balloon
            1158,  # Maximum Belt
            1252,  # Gravity Mountain
            *([6] * 12),  # Fighting Energy
        ),
    ),
    OpponentSpec(
        name="indy_sr_lucario_hariyama_jones",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.55,
        note="Jones D. Seniors-winning Lucario Hariyama from Regional Indianapolis 2026; adds Petrel/Wally/Unfair Stamp disruption line to Lucario testing",
        deck=(
            *([677] * 3),  # Riolu
            *([678] * 3),  # Mega Lucario ex
            *([676] * 3),  # Solrock
            *([673] * 2),  # Makuhita
            *([674] * 2),  # Hariyama
            *([675] * 2),  # Lunatone
            1071,  # Meowth ex
            *([1227] * 4),  # Lillie's Determination
            *([1213] * 2),  # Judge
            *([1182] * 2),  # Boss's Orders
            1211,  # Black Belt's Training
            1219,  # Team Rocket's Petrel
            1229,  # Wally's Compassion
            *([1142] * 4),  # Fighting Gong
            *([1152] * 4),  # Poke Pad
            *([1121] * 4),  # Ultra Ball
            *([1141] * 4),  # Premium Power Pro
            1080,  # Unfair Stamp
            *([1174] * 3),  # Air Balloon
            *([1252] * 2),  # Gravity Mountain
            *([6] * 11),  # Fighting Energy
        ),
    ),
    OpponentSpec(
        name="live_mep_mega_lucario",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/01_Praxel_16376982/submission_53811711/episode-80556848-replay.json"),
        slot=1,
        weight=4.50,
        note="MEP/LORD DREGS/shige Mega Lucario hash 78fd869465, refreshed from the 2026-06-19 02:27 scout as the second-heaviest live winner cluster",
    ),
    OpponentSpec(
        name="live_praxel_mega_lucario",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/01_Praxel_16376982/submission_53812087/episode-80548105-replay.json"),
        slot=1,
        weight=5.35,
        note="Praxel/haruki/Mudkip Mega Lucario hash 20dcd3130b, refreshed from the 2026-06-19 02:27 scout as the dominant live winner cluster",
    ),
    OpponentSpec(
        name="live_lord_dregs_mega_lucario",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/04_LORD_DREGS_16372609/submission_53813371/episode-80531426-replay.json"),
        slot=0,
        weight=1.05,
        note="LORD DREGS/sakaitt Mega Lucario hash 9850260dbd, refreshed from the 2026-06-19 02:27 scout as a live Lucario tail",
    ),
    OpponentSpec(
        name="live_hukuda_mega_lucario",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T014535Z/03_hiroingk_16376775/submission_53802029/episode-80541155-replay.json"),
        slot=0,
        weight=0.35,
        note="hukuda222 Mega Lucario hash 4ab1f52608 with Rock Fighting Energy, refreshed from the 2026-06-19 01:45 scout as a small live Lucario tail",
    ),
    OpponentSpec(
        name="live_blake_mega_lucario",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/04_LORD_DREGS_16372609/submission_53816765/episode-80573256-replay.json"),
        slot=0,
        weight=1.35,
        note="Blake Stagner Mega Lucario hash 46988fb3bb, refreshed from the 2026-06-19 02:27 scout as a receding but still relevant live Lucario variant",
    ),
    OpponentSpec(
        name="live_praxel_pure_crustle",
        policy=Path("agents/v4"),
        replay=Path("scouting/live_top_20260619T022733Z/01_Praxel_16376982/submission_53811711/episode-80552728-replay.json"),
        slot=0,
        weight=1.15,
        note="Praxel pure-Crustle heal hash d30fa2e5a6, refreshed from the 2026-06-19 02:27 scout and still downweighted behind Mega Lucario/Alakazam pressure",
    ),
    OpponentSpec(
        name="live_momy_mega_abomasnow",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/06_MEP_16386171/submission_53808755/episode-80538985-replay.json"),
        slot=0,
        weight=0.85,
        note="tarou_imokenpi Mega Abomasnow hash 8c326ebadc, refreshed from the 2026-06-19 02:27 scout as a small live winner tail",
    ),
    OpponentSpec(
        name="naic_raging_bolt_ogerpon_robb",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.0,
        note="Raging Bolt Ogerpon shell from Limitless; Ian Robb Regional LA list reused across LA/Indianapolis/NAIC results, rank-7 TEF-CRI archetype by points",
        deck=(
            *([756] * 3),  # Mega Kangaskhan ex
            *([96] * 3),  # Teal Mask Ogerpon ex
            *([1071] * 3),  # Meowth ex
            *([184] * 2),  # Latias ex
            *([63] * 2),  # Raging Bolt ex
            209,  # Chien-Pao
            978,  # Passimian
            272,  # Lillie's Clefairy ex
            108,  # Wellspring Mask Ogerpon ex
            140,  # Fezandipiti ex
            *([1198] * 4),  # Crispin
            *([1182] * 2),  # Boss's Orders
            *([1205] * 2),  # Cyrano
            1188,  # Ciphermaniac's Codebreaking
            1227,  # Lillie's Determination
            *([1121] * 4),  # Ultra Ball
            *([1116] * 4),  # Energy Switch
            *([1097] * 2),  # Night Stretcher
            *([1098] * 2),  # Glass Trumpet
            1080,  # Unfair Stamp
            *([1250] * 4),  # Area Zero Underdepths
            *([1] * 8),  # Grass Energy
            *([5] * 2),  # Psychic Energy
            *([4] * 2),  # Lightning Energy
            *([6] * 2),  # Fighting Energy
            3,  # Water Energy
        ),
    ),
    OpponentSpec(
        name="cl_fukuoka_mega_absol_nogamida",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.0,
        note="Champions League Fukuoka 2026 winner Takato Nogamida Mega Absol Box / Mega Kangaskhan toolbox from Limitless",
        deck=(
            *([112] * 3),  # Munkidori
            *([687] * 2),  # Mega Absol ex
            *([756] * 2),  # Mega Kangaskhan ex
            *([96] * 2),  # Teal Mask Ogerpon ex
            *([184] * 2),  # Latias ex
            *([1071] * 2),  # Meowth ex
            272,  # Lillie's Clefairy ex
            44,  # Bloodmoon Ursaluna ex
            858,  # Psyduck
            140,  # Fezandipiti ex
            117,  # Cornerstone Mask Ogerpon ex
            *([1205] * 3),  # Cyrano
            *([1198] * 3),  # Crispin
            *([1182] * 3),  # Boss's Orders
            *([1210] * 2),  # Brock's Scouting
            *([1188] * 2),  # Ciphermaniac's Codebreaking
            1227,  # Lillie's Determination
            *([1121] * 4),  # Ultra Ball
            *([1116] * 4),  # Energy Switch
            *([1097] * 2),  # Night Stretcher
            1122,  # Pokegear 3.0
            1080,  # Unfair Stamp
            *([1250] * 3),  # Area Zero Underdepths
            *([7] * 4),  # Darkness Energy
            *([1] * 4),  # Grass Energy
            *([5] * 2),  # Psychic Energy
            *([11] * 2),  # Mist Energy
            6,  # Fighting Energy
        ),
    ),
    OpponentSpec(
        name="cl_fukuoka_ogerpon_meganium_yano",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.9,
        note="Champions League Fukuoka 2026 runner-up Wataru Yano Ogerpon Meganium / Arboliva ex grass engine from Limitless",
        deck=(
            *([96] * 4),  # Teal Mask Ogerpon ex
            *([708] * 2),  # Chikorita
            *([709] * 2),  # Bayleef
            *([710] * 2),  # Meganium
            *([402] * 2),  # Smoliv
            *([403] * 2),  # Dolliv
            *([404] * 2),  # Arboliva ex
            *([1071] * 2),  # Meowth ex
            235,  # Budew
            140,  # Fezandipiti ex
            *([1227] * 4),  # Lillie's Determination
            *([1231] * 3),  # Dawn
            *([1182] * 2),  # Boss's Orders
            1184,  # Lana's Aid
            1213,  # Judge
            *([1094] * 4),  # Bug Catching Set
            *([1121] * 4),  # Ultra Ball
            *([1152] * 2),  # Poke Pad
            1097,  # Night Stretcher
            1080,  # Unfair Stamp
            1174,  # Air Balloon
            *([1261] * 4),  # Forest of Vitality
            *([1] * 12),  # Grass Energy
        ),
    ),
    OpponentSpec(
        name="cl_osaka_alakazam_akagi",
        policy=Path("agents/v61_kadoraba_nighttime_hammer"),
        replay=None,
        slot=0,
        weight=1.25,
        note="Champions League Osaka 2026 winner Tatsuki Akagi Alakazam Dudunsparce; large 7500-player Japanese event with multiple Alakazam top cuts",
        deck=(
            *([741] * 4),  # Abra
            *([742] * 4),  # Kadabra
            *([743] * 3),  # Alakazam
            *([65] * 3),  # Dunsparce
            *([66] * 3),  # Dudunsparce
            858,  # Psyduck
            45,  # Shaymin
            140,  # Fezandipiti ex
            *([1225] * 4),  # Hilda
            *([1231] * 4),  # Dawn
            *([1182] * 3),  # Boss's Orders
            1184,  # Lana's Aid
            1186,  # Eri
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1152] * 4),  # Poke Pad
            *([1079] * 3),  # Rare Candy
            *([1081] * 2),  # Enhanced Hammer
            1097,  # Night Stretcher
            1129,  # Sacred Ash
            1146,  # Wondrous Patch
            *([1264] * 4),  # Battle Cage
            *([19] * 4),  # Telepath Psychic Energy
            *([5] * 2),  # Psychic Energy
            13,  # Enriching Energy
        ),
    ),
    OpponentSpec(
        name="live_kadoraba_nighttime_hammer",
        policy=Path("agents/v61_kadoraba_nighttime_hammer"),
        replay=Path("scouting/live_top_20260619T022733Z/02_hiroingk_16376775/submission_53802029/episode-80557405-replay.json"),
        slot=0,
        weight=2.10,
        note="Kadoraba live Nighttime Hammer Alakazam hash fd299968c7, refreshed from the 2026-06-19 02:27 scout",
    ),
    OpponentSpec(
        name="cl_osaka_grimmsnarl_froslass_amano",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.75,
        note="Champions League Osaka 2026 runner-up Toshiki Amano Marnie's Grimmsnarl/Froslass list from Limitless; low-weight Japanese disruption tail",
        deck=(
            *([646] * 4),  # Marnie's Impidimp
            *([647] * 2),  # Marnie's Morgrem
            *([648] * 3),  # Marnie's Grimmsnarl ex
            *([112] * 4),  # Munkidori
            *([103] * 2),  # Snorunt
            *([104] * 2),  # Froslass
            235,  # Budew
            689,  # Yveltal
            *([1227] * 4),  # Lillie's Determination
            *([1219] * 4),  # Team Rocket's Petrel
            *([1182] * 3),  # Boss's Orders
            *([1206] * 2),  # Larry's Skill
            *([1152] * 4),  # Poke Pad
            *([1086] * 3),  # Buddy-Buddy Poffin
            *([1079] * 3),  # Rare Candy
            *([1097] * 2),  # Night Stretcher
            1080,  # Unfair Stamp
            1087,  # Hand Trimmer as Special Red Card stand-in
            1174,  # Air Balloon
            *([1259] * 4),  # Spikemuth Gym
            *([7] * 9),  # Darkness Energy
        ),
    ),
    OpponentSpec(
        name="turin_hops_trevenant_lopez",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.55,
        note="Jose Lopez 1st-place Special Event Turin 2026 Hop's Trevenant list from Limitless; TEF-CRI rank-14 archetype and a five-list NAIC tail",
        deck=(
            *([878] * 4),  # Hop's Phantump
            *([879] * 3),  # Hop's Trevenant
            *([304] * 2),  # Hop's Snorlax
            309,  # Hop's Wooloo
            310,  # Hop's Dubwool
            311,  # Hop's Cramorant
            272,  # Lillie's Clefairy ex
            343,  # Shaymin
            *([1227] * 4),  # Lillie's Determination
            *([1219] * 4),  # Team Rocket's Petrel
            *([1182] * 3),  # Boss's Orders
            *([1193] * 2),  # Hassel
            1209,  # Ruffian
            *([1152] * 4),  # Poke Pad
            *([1122] * 3),  # Pokegear 3.0
            *([1097] * 3),  # Night Stretcher
            *([1115] * 2),  # Hop's Bag
            1121,  # Ultra Ball
            1092,  # Secret Box
            1123,  # Switch
            *([1171] * 4),  # Hop's Choice Band
            1174,  # Air Balloon
            *([1255] * 4),  # Postwick
            *([19] * 4),  # Telepath Psychic Energy
            *([11] * 4),  # Mist Energy
        ),
    ),
    OpponentSpec(
        name="naic_cynthias_garchomp_abbott",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.60,
        note="Chloe Abbott 137th-place NAIC 2026 Cynthia's Garchomp list from Limitless; archetype has six Regional Top 8s and one win historically",
        deck=(
            *([379] * 4),  # Cynthia's Gible
            *([380] * 4),  # Cynthia's Gabite
            *([381] * 3),  # Cynthia's Garchomp ex
            *([341] * 4),  # Cynthia's Roselia
            *([342] * 3),  # Cynthia's Roserade
            387,  # Cynthia's Spiritomb
            343,  # Shaymin
            *([1227] * 4),  # Lillie's Determination
            *([1182] * 4),  # Boss's Orders
            *([1225] * 2),  # Hilda
            1213,  # Judge
            *([1086] * 3),  # Buddy-Buddy Poffin
            *([1142] * 3),  # Fighting Gong
            *([1152] * 3),  # Poke Pad
            *([1141] * 2),  # Premium Power Pro
            *([1097] * 2),  # Night Stretcher
            *([1122] * 2),  # Pokegear 3.0
            1079,  # Rare Candy
            1123,  # Switch
            *([1173] * 3),  # Cynthia's Power Weight
            1256,  # Team Rocket's Watchtower
            *([6] * 4),  # Fighting Energy
            *([20] * 3),  # Rock Fighting Energy
            10,  # Neo Upper Energy
        ),
    ),
    OpponentSpec(
        name="cl_osaka_rocket_mewtwo_takasaka",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.15,
        note="Champions League Osaka 2026 3rd-place Tomoki Takasaka Rocket's Mewtwo / Spidops list from Limitless; 7500-player Japanese event",
        deck=(
            *([400] * 4),  # Team Rocket's Tarountula
            *([401] * 4),  # Team Rocket's Spidops
            *([431] * 2),  # Team Rocket's Mewtwo ex
            *([434] * 2),  # Team Rocket's Mimikyu
            *([414] * 2),  # Team Rocket's Articuno
            272,  # Lillie's Clefairy ex
            464,  # Team Rocket's Sneasel
            *([1218] * 3),  # Team Rocket's Giovanni
            *([1217] * 3),  # Team Rocket's Archer
            *([1227] * 3),  # Lillie's Determination
            *([1216] * 2),  # Team Rocket's Ariana
            *([1220] * 2),  # Team Rocket's Proton
            1219,  # Team Rocket's Petrel
            *([1121] * 4),  # Ultra Ball
            *([1134] * 4),  # Team Rocket's Transceiver
            *([1094] * 3),  # Bug Catching Set
            *([1097] * 2),  # Night Stretcher
            1116,  # Energy Switch
            1158,  # Maximum Belt
            1175,  # Brave Bangle
            *([1257] * 3),  # Team Rocket's Factory
            *([1] * 7),  # Grass Energy
            *([15] * 4),  # Team Rocket's Energy
        ),
    ),
    OpponentSpec(
        name="naic_dragapult_dusknoir_kosek",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.1,
        note="NAIC 2026 runner-up Neddy Kosek Dragapult Dusknoir list from Limitless; Special Red Card approximated by Hand Trimmer",
        deck=(
            *([119] * 4),  # Dreepy
            *([120] * 4),  # Drakloak
            *([121] * 2),  # Dragapult ex
            *([131] * 2),  # Duskull
            *([132] * 2),  # Dusclops
            133,  # Dusknoir
            235,  # Budew
            140,  # Fezandipiti ex
            1071,  # Meowth ex
            112,  # Munkidori
            *([1227] * 4),  # Lillie's Determination
            *([1198] * 3),  # Crispin
            *([1182] * 2),  # Boss's Orders
            1231,  # Dawn
            *([1121] * 4),  # Ultra Ball
            *([1152] * 4),  # Poke Pad
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1120] * 4),  # Crushing Hammer
            *([1097] * 2),  # Night Stretcher
            1080,  # Unfair Stamp
            1087,  # Hand Trimmer as legal Special Red Card stand-in
            1161,  # Handheld Fan
            1256,  # Team Rocket's Watchtower
            1246,  # Jamming Tower
            *([5] * 3),  # Psychic Energy
            *([2] * 3),  # Fire Energy
            *([7] * 2),  # Darkness Energy
        ),
    ),
    OpponentSpec(
        name="naic_dragapult_newdorf",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=1.4,
        note="NAIC 2026 3rd-place Justin Newdorf pure Dragapult list from Limitless; largest NAIC archetype cluster, Special Red Card approximated by Hand Trimmer",
        deck=(
            *([119] * 4),  # Dreepy
            *([120] * 4),  # Drakloak
            *([121] * 3),  # Dragapult ex
            *([112] * 2),  # Munkidori
            65,  # Dunsparce
            66,  # Dudunsparce
            235,  # Budew
            140,  # Fezandipiti ex
            1071,  # Meowth ex
            *([1227] * 4),  # Lillie's Determination
            *([1182] * 3),  # Boss's Orders
            *([1198] * 2),  # Crispin
            1240,  # Rosa's Encouragement
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1152] * 4),  # Poke Pad
            *([1121] * 4),  # Ultra Ball
            *([1120] * 4),  # Crushing Hammer
            *([1097] * 3),  # Night Stretcher
            1087,  # Hand Trimmer as legal Special Red Card stand-in
            1080,  # Unfair Stamp
            *([1260] * 2),  # Risky Ruins
            *([5] * 4),  # Psychic Energy
            *([2] * 3),  # Fire Energy
            *([7] * 2),  # Darkness Energy
        ),
    ),
    OpponentSpec(
        name="naic_n_zoroark_reklev",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.9,
        note="NAIC 2026 N's Zoroark by Tord Reklev from Limitless; missing Tome/Red Card approximated with Dusk Ball/Hand Trimmer",
        deck=(
            *([292] * 2),  # N's Zorua
            293,  # N's Zoroark ex
            *([258] * 2),  # N's Darmanitan
            *([906] * 2),  # N's Zekrom
            296,  # N's Klinklang
            167,  # Klinklang
            141,  # Pecharunt ex
            140,  # Fezandipiti ex
            122,  # Tatsugiri
            144,  # Kyurem
            641,  # Steven's Metagross ex
            276,  # Metagross
            377,  # Zeraora
            235,  # Budew
            *([1121] * 4),  # Ultra Ball
            *([1122] * 3),  # Pokegear 3.0
            1086,  # Buddy-Buddy Poffin as legal setup filler
            *([1102] * 3),  # Dusk Ball plus Tome stand-in
            *([1113] * 4),  # N's PP Up
            1097,  # Night Stretcher
            1088,  # Prime Catcher
            1087,  # Hand Trimmer as legal Special Red Card stand-in
            *([1221] * 3),  # N's Plan
            *([1182] * 2),  # Boss's Orders
            *([1227] * 2),  # Lillie's Determination as legal Iono stand-in
            *([1188] * 2),  # Ciphermaniac's Codebreaking
            1198,  # Crispin
            *([1246] * 4),  # Jamming Tower
            *([1253] * 3),  # N's Castle
            *([2] * 2),  # Fire Energy
            *([7] * 2),  # Darkness Energy
            *([4] * 2),  # Lightning Energy
            *([8] * 2),  # Metal Energy
        ),
    ),
    OpponentSpec(
        name="naic_slowking_cawthon",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.8,
        note="NAIC 2026 Ross Cawthon Slowking structure from Limitless; unavailable Natu/Xatu engine approximated with legal support Pokemon",
        deck=(
            *([162] * 4),  # Slowpoke
            *([163] * 4),  # Slowking
            *([112] * 2),  # Munkidori
            230,  # Pecharunt
            141,  # Pecharunt ex
            140,  # Fezandipiti ex
            122,  # Tatsugiri
            235,  # Budew
            *([1071] * 2),  # Meowth ex as legal search support
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1121] * 4),  # Ultra Ball
            *([1102] * 4),  # Dusk Ball
            *([1122] * 4),  # Pokegear 3.0
            *([1097] * 2),  # Night Stretcher
            1087,  # Hand Trimmer
            1088,  # Prime Catcher
            1159,  # Hero's Cape
            *([1225] * 4),  # Hilda
            *([1197] * 2),  # Xerosic's Machinations
            *([1227] * 2),  # Lillie's Determination as legal Iono stand-in
            1182,  # Boss's Orders
            1190,  # Bianca's Devotion
            1204,  # Lisia's Appeal
            *([1248] * 3),  # Academy at Night
            *([1260] * 2),  # Risky Ruins
            *([5] * 4),  # Psychic Energy
            *([7] * 2),  # Darkness Energy
        ),
    ),
    OpponentSpec(
        name="naic_hydrapple_walworth",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.7,
        note="NAIC 2026 top Hydrapple/Ogerpon structure from Limitless; Iono approximated with legal draw/search",
        deck=(
            *([96] * 4),  # Teal Mask Ogerpon ex
            *([149] * 4),  # Applin
            42,  # Applin
            *([921] * 2),  # Dipplin
            348,  # Hydrapple
            *([150] * 2),  # Hydrapple ex
            112,  # Munkidori
            117,  # Cornerstone Mask Ogerpon ex
            184,  # Latias ex
            75,  # Iron Leaves ex
            140,  # Fezandipiti ex
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1094] * 4),  # Bug Catching Set
            *([1116] * 4),  # Energy Switch
            *([1121] * 4),  # Ultra Ball
            *([1098] * 3),  # Glass Trumpet
            *([1118] * 2),  # Energy Retrieval
            1097,  # Night Stretcher
            1088,  # Prime Catcher
            *([1227] * 4),  # Lillie's Determination as legal Iono stand-in
            *([1182] * 2),  # Boss's Orders
            1201,  # Briar
            1184,  # Lana's Aid
            *([1261] * 2),  # Forest of Vitality
            *([1] * 8),  # Grass Energy
        ),
    ),
    OpponentSpec(
        name="naic_ogerpon_box_cucinelli",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=None,
        slot=0,
        weight=0.6,
        note="NAIC 2026 Ogerpon Box structure from Limitless; unavailable Mew/Iono approximated with legal support",
        deck=(
            *([96] * 4),  # Teal Mask Ogerpon ex
            *([112] * 3),  # Munkidori
            75,  # Iron Leaves ex
            117,  # Cornerstone Mask Ogerpon ex
            184,  # Latias ex
            140,  # Fezandipiti ex
            209,  # Chien-Pao as legal Mew ex utility stand-in
            *([1086] * 4),  # Buddy-Buddy Poffin
            *([1094] * 4),  # Bug Catching Set
            *([1116] * 4),  # Energy Switch
            *([1098] * 3),  # Glass Trumpet
            *([1121] * 2),  # Ultra Ball
            1097,  # Night Stretcher
            1118,  # Energy Retrieval
            1088,  # Prime Catcher
            1137,  # Tool Scrapper
            1122,  # Pokegear 3.0
            *([1227] * 4),  # Lillie's Determination as legal Iono stand-in
            *([1182] * 3),  # Boss's Orders
            1201,  # Briar
            *([1261] * 3),  # Forest of Vitality
            *([1248] * 3),  # Academy at Night
            *([1] * 9),  # Grass Energy
            *([7] * 3),  # Darkness Energy
        ),
    ),
    OpponentSpec(
        name="alakazam_denpa",
        policy=Path("agents/v48_alakazam_hammer_mid"),
        replay=Path("scouting/live_top_20260619T022733Z/05_Blake_Stagner_16385029/submission_53826480/episode-80580613-replay.json"),
        slot=0,
        weight=3.60,
        note="nogu/Pachuru/shige Battle Cage Alakazam hash f1223adb2c, refreshed from the 2026-06-19 02:27 scout as a heavy live winner cluster",
    ),
    OpponentSpec(
        name="live_ai_to_ai_alakazam_hammer",
        policy=Path("agents/v45_alakazam_hammer"),
        replay=Path("scouting/live_top_20260619T022733Z/08_nogu_16377292/submission_53798147/episode-80538964-replay.json"),
        slot=0,
        weight=1.95,
        note="AI-to-AI live 4-Hammer Alakazam shell hash f88995164f, refreshed from the 2026-06-19 02:27 scout",
    ),
    OpponentSpec(
        name="live_hiroingk_alakazam_hammer",
        policy=Path("agents/v45_alakazam_hammer"),
        replay=Path("scouting/live_top_20260619T022733Z/01_Praxel_16376982/submission_53812087/episode-80560722-replay.json"),
        slot=0,
        weight=3.45,
        note="hiroingk live 4-Hammer Alakazam shell hash b9bcfb3e10, refreshed from the 2026-06-19 02:27 scout as the heaviest live Alakazam Hammer cluster",
    ),
    OpponentSpec(
        name="live_yt_dragapult",
        policy=Path("agents/v50_replay_meta_policy"),
        replay=Path("scouting/live_top_20260619T022733Z/04_LORD_DREGS_16372609/submission_53813371/episode-80552656-replay.json"),
        slot=0,
        weight=0.25,
        note="Dragapult hash 41d71d536c, refreshed from the 2026-06-19 02:27 scout and downweighted because current public winners are Lucario/Alakazam/Iono-heavy",
    ),
    OpponentSpec(
        name="alakazam_tubotu_hammer",
        policy=Path("agents/v45_alakazam_hammer"),
        replay=Path("scouting/live_top_0309/06_tubotu_16372993/submission_53792420/episode-80402528-replay.json"),
        slot=1,
        weight=2.25,
        note="tubotu top-10 4-Hammer Alakazam shell hash 2a7a8c0c6f, current rank-6 live threat",
    ),
    OpponentSpec(
        name="alakazam_daitou_c9eb",
        policy=Path("agents/v43_daitou_alakazam"),
        replay=Path("scouting/live_0109/datou_iwapalace_53783079/episode-80380584-replay.json"),
        slot=0,
        weight=2.0,
        note="Daitou Iwapalace Alakazam hash c9eb3b1e5c, rank-5 visible shell",
    ),
    OpponentSpec(
        name="alakazam_zscorpio_nighttime",
        policy=Path("agents/v43_daitou_alakazam"),
        replay=Path("scouting/live_0109/zscorpio_53786476/episode-80375458-replay.json"),
        slot=0,
        weight=1.5,
        note="Zscorpio Nighttime Mine Alakazam hash ac15136b39, rank-12 visible shell",
    ),
    OpponentSpec(
        name="alakazam_donguk_nighttime",
        policy=Path("agents/v58_donguk_nighttime"),
        replay=Path("scouting/live_top_0335/11_Donguk_Jung_16373012/submission_53793838/episode-80411058-replay.json"),
        slot=0,
        weight=2.1,
        note="Donguk Jung rank-11 Nighttime Mine Alakazam hash 1304e130bd with Psyduck/Genesect/Dedenne/Fezandipiti support",
    ),
    OpponentSpec(
        name="festival_hibi",
        policy=Path("agents/v42_hibi_festival"),
        replay=Path("scouting/live_0109/hibi_53784991/episode-80384009-replay.json"),
        slot=0,
        weight=1.75,
        note="hibi Festival Lead deck hash 95b2ecb33f, rank-6 visible shell",
    ),
    OpponentSpec(
        name="pure_crustle_e0e4",
        policy=Path("agents/v4"),
        replay=Path("scouting/live_0109/kyo_53760816/episode-80350454-replay.json"),
        slot=1,
        weight=0.75,
        note="pure Crustle heal hash 8fad1c6c34, frequent but low fresh top-pool win rate",
    ),
    OpponentSpec(
        name="ethan_crustle_51f8",
        policy=Path("agents/v21_ethan_crustle"),
        replay=Path("scouting/live_0109/sbite0138_53781346/episode-80363999-replay.json"),
        slot=0,
        weight=1.25,
        note="PyJa/sbite/kuritan exact Ethan-Crustle hash 51f8e5ba5f",
    ),
    OpponentSpec(
        name="ethan_crustle_kenn_10ef",
        policy=Path("agents/v27_poffin5"),
        replay=Path("scouting/live_0109/kenn_top10_53778186/episode-80365963-replay.json"),
        slot=1,
        weight=1.0,
        note="kenn Ethan-Crustle hash 10ef4700c6, rank-10 score carrier",
    ),
    OpponentSpec(
        name="battle_cage_crustle",
        policy=Path("agents/v4"),
        replay=Path("scouting/live_top_20260619T022733Z/01_Praxel_16376982/submission_53811711/episode-80546642-replay.json"),
        slot=1,
        weight=0.45,
        note="Battle Cage/Cheren pure-Crustle shell hash eeef77d62d, refreshed from the 2026-06-19 02:27 scout as a small live tail",
    ),
    OpponentSpec(
        name="hammer_crustle_strayuru",
        policy=Path("agents/v20_hammer_target"),
        replay=Path("scouting/live_0109/hibi_53784991/episode-80373260-replay.json"),
        slot=1,
        weight=0.5,
        note="Strayuru Hammer/Poke Pad shell hash 22a2ceb51a",
    ),
]


def deck_from_replay(path: Path, slot: int) -> list[int]:
    data = json.loads(path.read_text())
    return data["steps"][0][0]["visualize"][0]["action"][slot]


def deck_from_spec(spec: OpponentSpec) -> list[int]:
    if spec.deck is not None:
        deck = list(spec.deck)
        if len(deck) != 60:
            raise ValueError(f"{spec.name} deck has {len(deck)} cards, expected 60")
        return deck
    if spec.replay is None:
        raise ValueError(f"{spec.name} needs either a replay path or an inline deck")
    return deck_from_replay(spec.replay, spec.slot)


def summarize_counts(results: list[dict], candidate_is_p0: bool) -> tuple[int, int, int, int]:
    counts = Counter(result["result"] for result in results)
    wins = counts[0] if candidate_is_p0 else counts[1]
    losses = counts[1] if candidate_is_p0 else counts[0]
    return wins, losses, counts[2], counts[-1]


def evaluate_pair(
    candidate_agent,
    candidate_deck: list[int],
    opponent_agent,
    opponent_deck: list[int],
    games: int,
    max_steps: int,
    quiet: bool,
) -> tuple[int, int, int, int]:
    forward = run_games(
        candidate_agent,
        candidate_deck,
        opponent_agent,
        opponent_deck,
        games,
        max_steps,
        False,
        quiet,
        "forward",
    )
    f_wins, f_losses, f_draws, f_unfinished = summarize_counts(forward, candidate_is_p0=True)

    swapped = run_games(
        opponent_agent,
        opponent_deck,
        candidate_agent,
        candidate_deck,
        games,
        max_steps,
        False,
        quiet,
        "swapped",
    )
    s_wins, s_losses, s_draws, s_unfinished = summarize_counts(swapped, candidate_is_p0=False)
    return (
        f_wins + s_wins,
        f_losses + s_losses,
        f_draws + s_draws,
        f_unfinished + s_unfinished,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", action="append", type=Path, default=[])
    parser.add_argument(
        "--opponent",
        action="append",
        default=[],
        help="Optional opponent name substring filter; may be repeated",
    )
    parser.add_argument("--games", type=int, default=20, help="games per seat per opponent")
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    candidates = args.candidate or [Path("submission")]
    opponents = DEFAULT_OPPONENTS
    if args.opponent:
        needles = tuple(item.lower() for item in args.opponent)
        opponents = [spec for spec in DEFAULT_OPPONENTS if any(needle in spec.name.lower() for needle in needles)]
        if not opponents:
            raise SystemExit(f"no opponents matched filters: {', '.join(args.opponent)}")
    total_exit = 0
    for candidate_path in candidates:
        candidate_agent, candidate_deck = load_agent(candidate_path, f"cand_{candidate_path.name}")
        weighted_wins = 0.0
        weighted_games = 0.0
        print(f"\nCandidate {candidate_path}")
        print("opponent,weight,wins,losses,draws,unfinished,win_rate,note")
        for spec in opponents:
            opponent_agent, _ = load_agent(spec.policy, f"opp_{spec.name}")
            opponent_deck = deck_from_spec(spec)
            wins, losses, draws, unfinished = evaluate_pair(
                candidate_agent,
                candidate_deck,
                opponent_agent,
                opponent_deck,
                args.games,
                args.max_steps,
                args.quiet,
            )
            played = wins + losses + draws
            win_rate = wins / played if played else 0.0
            weighted_wins += spec.weight * wins
            weighted_games += spec.weight * played
            if unfinished:
                total_exit = 1
            print(
                f"{spec.name},{spec.weight},{wins},{losses},{draws},{unfinished},"
                f"{win_rate:.4f},{spec.note}"
            )
        score = weighted_wins / weighted_games if weighted_games else 0.0
        print(f"weighted_win_rate,{score:.4f}")
    return total_exit


if __name__ == "__main__":
    raise SystemExit(main())
