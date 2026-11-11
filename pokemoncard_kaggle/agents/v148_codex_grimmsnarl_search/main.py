# ============================================================================
# codex-grimmsnarl-search-v148
#
# Strategy (evidence-driven, 2026-07-02):
#   * DECK: the exact Marnie's Grimmsnarl ex list `be5107ce4e` played by the
#     current rank-2 (tonakaiiii 1224.7) AND rank-3 (S4nkurero 1194.6) teams.
#     The top-4 of the leaderboard all converged on this archetype.
#   * PRIOR POLICY: compact heuristic whose priorities are mined from 5,652
#     decisions by the top-4 Grimmsnarl pilots (always go first; Munkidori
#     ability engine; energy to the Grimmsnarl line; Spikemuth/Poffin/Petrel
#     search engine; Lillie's reset; END discipline).
#   * SEARCH: the engine's built-in SearchBegin/SearchStep determinization API
#     (officially exposed to agents; measured ~10k search-steps/sec). On
#     important single-pick decisions we evaluate the top prior options across
#     several determinizations of the hidden zones and pick the best mean
#     outcome. Opponent hidden zones are filled from a bundled library of the
#     exact 60-card meta decks scouted from the current top-30 teams.
#   * SAFETY: engine-legal indices only, hard time budgets, every failure path
#     falls back to the prior policy choice (never crash, never timeout).
# ============================================================================
from __future__ import annotations

import json
import os
import random
import time
from collections import Counter

from cg.api import (
    AreaType,
    Observation,
    OptionType,
    SelectContext,
    to_observation_class,
)

# The search API exists only in the 2026-07-01+ engine. On Kaggle we bundle it,
# but mixed local harnesses may import an older cg first — degrade gracefully.
# CODEX_DISABLE_SEARCH=1 forces prior-only (fast offline fidelity measurement).
try:
    from cg.api import search_begin, search_end, search_step
    SEARCH_AVAILABLE = os.environ.get("CODEX_DISABLE_SEARCH", "") != "1"
except ImportError:  # old engine in the process — prior-only mode
    SEARCH_AVAILABLE = False

    def search_begin(*a, **k):  # pragma: no cover
        raise RuntimeError("search unavailable")

    def search_step(*a, **k):  # pragma: no cover
        raise RuntimeError("search unavailable")

    def search_end(*a, **k):  # pragma: no cover
        return None

random.seed(0xC0DE148)

# --------------------------------------------------------------------------- #
# Deck / card constants (be5107ce4e)
# --------------------------------------------------------------------------- #
DARK_ENERGY = 7
MUNKIDORI = 112
FROSLASS = 104
SNORUNT = 860
IMPIDIMP = 646
MORGREM = 647
GRIMMSNARL_EX = 648
POFFIN = 1086
POKE_PAD = 1152
PETREL = 1219
LILLIE = 1227
SPIKEMUTH_GYM = 1259
RARE_CANDY = 1079
NIGHT_STRETCHER = 1097
HANDHELD_FAN = 1161
UNFAIR_STAMP = 1080
BOSS_ORDERS = 1182
DAWN = 1231

EVO_LINE = {IMPIDIMP: 0, MORGREM: 1, GRIMMSNARL_EX: 2}
BASICS = {IMPIDIMP, MUNKIDORI, SNORUNT}
# common basic Pokémon across the scouted meta (for opponent face-down guesses)
KNOWN_BASICS = {
    IMPIDIMP, MUNKIDORI, SNORUNT,          # grimmsnarl shell
    305, 741,                               # dunsparce / abra (alakazam shells)
    169, 57,                                # duraludon / relicanth (archaludon)
    677, 675, 673,                          # riolu / lunatone / makuhita (fighting)
    920, 343, 235, 649, 400, 1073,          # tapu bulu / shaymin / budew / morpeko ...
}
ATTACKER_LINE = {GRIMMSNARL_EX, MORGREM, IMPIDIMP}

DEFAULT_DECK = [int(x) for x in """7 7 7 7 7 7 7 7 7 7
112 112 112 112 646 646 646 646 1086 1086 1086 1086
1152 1152 1152 1152 1219 1219 1219 1219 1227 1227 1227 1227
1259 1259 1259 1259 647 647 647 648 648 648
1079 1079 1079 1097 1097 1097 104 104 860 860
1161 1161 1182 1182 1080 1231""".split()]


def read_deck_csv() -> list[int]:
    for path in ("deck.csv", "/kaggle_simulations/agent/deck.csv"):
        if os.path.exists(path):
            with open(path) as fh:
                cards = [int(x) for x in fh.read().split() if x.strip()]
            if len(cards) == 60:
                return cards
    return list(DEFAULT_DECK)


MY_DECK = read_deck_csv()


def load_meta_decks() -> dict[str, list[int]]:
    for path in ("meta_decks.json", "/kaggle_simulations/agent/meta_decks.json"):
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    return {k: list(map(int, v)) for k, v in json.load(fh).items()}
            except Exception:
                return {}
    return {}


META_DECKS = load_meta_decks()

# --------------------------------------------------------------------------- #
# Time budget (runTimeout for the whole episode is 2000s shared; stay tiny)
# --------------------------------------------------------------------------- #
GAME_BUDGET_S = 420.0          # cumulative search time cap per game
DECISION_BUDGET_S = 2.5        # per-decision search cap
_spent = {"t": 0.0}

SEARCH_MAX_WORLDS = 24         # adaptive: keep sampling worlds until budget
SEARCH_TOP_OPTIONS = 8         # prior-pruned branching
SEARCH_ROLLOUT_CAP = 160       # rollout to TERMINAL (games run ~110-220 steps)
SEARCH_OVERRIDE_MARGIN = 0.12  # win-prob edge required to overrule the prior


# --------------------------------------------------------------------------- #
# Observation helpers
# --------------------------------------------------------------------------- #
def my_state(obs: Observation):
    return obs.current.players[obs.current.yourIndex]


def opp_state(obs: Observation):
    return obs.current.players[1 - obs.current.yourIndex]


def field_pokemon(player):
    out = []
    for card in (player.active or []):
        if card is not None:
            out.append(card)
    for card in (player.bench or []):
        if card is not None:
            out.append(card)
    return out


def zone_ids(player) -> list[int]:
    ids = []
    for zone in (player.hand, player.discard, player.active, player.bench):
        for card in zone or []:
            if card is not None:
                ids.append(card.id)
                for sub in (getattr(card, "energyCards", None) or []):
                    if sub is not None:
                        ids.append(sub.id)
                for sub in (getattr(card, "tools", None) or []):
                    if sub is not None:
                        ids.append(sub.id)
                # [fix 11] under-stage cards (e.g. Rare-Candy'd Impidimp under
                # Grimmsnarl) are consumed copies and must leave the hidden pool
                for sub in (getattr(card, "preEvolution", None) or []):
                    if sub is not None:
                        ids.append(sub.id)
    return ids


def hand_ids(obs: Observation) -> list[int]:
    return [c.id for c in (my_state(obs).hand or []) if c is not None]


def count_line(obs: Observation, ids: set[int]) -> int:
    return sum(1 for p in field_pokemon(my_state(obs)) if p.id in ids)


def energy_count(pokemon) -> int:
    return len(getattr(pokemon, "energies", None) or [])


def get_card(obs: Observation, area, index: int, player_index: int):
    try:
        state = obs.current
        player = state.players[player_index]
        if area == AreaType.DECK:
            return obs.select.deck[index] if obs.select and obs.select.deck else None
        if area == AreaType.HAND:
            return (player.hand or [])[index]
        if area == AreaType.DISCARD:
            return (player.discard or [])[index]
        if area == AreaType.ACTIVE:
            return (player.active or [])[index]
        if area == AreaType.BENCH:
            return (player.bench or [])[index]
        if area == AreaType.STADIUM:
            return (state.stadium or [None])[index]
        if area == AreaType.LOOKING:
            return (state.looking or [])[index]
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------- #
# Prior policy — teacher-frequency-informed compact heuristic
# --------------------------------------------------------------------------- #
SEARCH_PRIORITY = {  # TO_HAND fetch order (teacher frequencies + need-awareness)
    GRIMMSNARL_EX: 900, MORGREM: 800, IMPIDIMP: 750, MUNKIDORI: 700,
    RARE_CANDY: 640, DARK_ENERGY: 600, LILLIE: 420, SPIKEMUTH_GYM: 400,
    POFFIN: 380, FROSLASS: 300, SNORUNT: 280, BOSS_ORDERS: 260,
    NIGHT_STRETCHER: 240, POKE_PAD: 220, PETREL: 210, HANDHELD_FAN: 180,
    UNFAIR_STAMP: 160, DAWN: 150,
}


def fetch_score(obs: Observation, cid: int) -> float:
    base = SEARCH_PRIORITY.get(cid, 100)
    hand = Counter(hand_ids(obs))
    on_field = Counter(p.id for p in field_pokemon(my_state(obs)))
    if cid == GRIMMSNARL_EX:
        if on_field[GRIMMSNARL_EX] >= 2 or hand[GRIMMSNARL_EX] >= 1:
            base -= 350
        if not (on_field[IMPIDIMP] or on_field[MORGREM]):
            base -= 250
    elif cid == MORGREM:
        if not on_field[IMPIDIMP] or hand[MORGREM]:
            base -= 300
        if hand[RARE_CANDY] and hand[GRIMMSNARL_EX]:
            base -= 200  # candy line preferred
    elif cid == IMPIDIMP:
        base -= 160 * (on_field[IMPIDIMP] + hand[IMPIDIMP])
    elif cid == MUNKIDORI:
        base -= 260 * (on_field[MUNKIDORI] + hand[MUNKIDORI])
    elif cid == RARE_CANDY:
        if not (on_field[IMPIDIMP] and (hand[GRIMMSNARL_EX] or on_field[MORGREM])):
            base -= 260
    elif cid == DARK_ENERGY:
        need = sum(max(0, 2 - energy_count(p)) for p in field_pokemon(my_state(obs))
                   if p.id in ATTACKER_LINE)
        base += 40 * min(need, 3)
    return base - 60 * hand[cid]


def attach_target_score(obs: Observation, target, to_active: bool) -> float:
    """Teacher fidelity finding (1,340-decision comparison): pilots run their
    ENGINE first (Poké Pad/Petrel/Spikemuth/abilities/evolutions) and attach
    late in the turn. Attach must rank BELOW engine plays (640+) and evolutions
    (850+), above END (20) — not dominate the turn."""
    if target is None:
        return -1000
    e = energy_count(target)
    score = 360 - 120 * e
    if target.id == GRIMMSNARL_EX:
        score += 210
    elif target.id == MORGREM:
        score += 150
    elif target.id == IMPIDIMP:
        score += 110
    elif target.id == MUNKIDORI:
        # Munkidori wants exactly one Dark for its ability engine
        score += 170 if e == 0 else -400
    elif target.id == FROSLASS:
        score += 40
    if to_active:
        score += 30
    return score


def bench_pick_score(obs: Observation, cid: int) -> float:
    on_field = Counter(p.id for p in field_pokemon(my_state(obs)))
    if cid == IMPIDIMP:
        return 800 - 140 * on_field[IMPIDIMP]
    if cid == MUNKIDORI:
        return 700 - 320 * on_field[MUNKIDORI]
    if cid == SNORUNT:
        return 400 - 200 * on_field[SNORUNT]
    if cid in (MORGREM, GRIMMSNARL_EX):
        return 300
    return 150


def prior_score(obs: Observation, opt) -> float:
    """Score one legal option. Higher = better. Teacher-informed."""
    sel = obs.select
    ctx = sel.context
    me = my_state(obs)
    hand = Counter(hand_ids(obs))
    on_field = Counter(p.id for p in field_pokemon(me))
    grimm_ready = any(p.id == GRIMMSNARL_EX and energy_count(p) >= 2
                      for p in field_pokemon(me))

    if ctx == SelectContext.IS_FIRST:
        # teachers chose to go FIRST 12/12
        return 100 if opt.type == OptionType.YES else 0

    if opt.type == OptionType.NUMBER:
        return float(opt.number or 0)
    if opt.type == OptionType.YES:
        return 90.0
    if opt.type == OptionType.NO:
        return 10.0

    if opt.type == OptionType.CARD:
        card = get_card(obs, opt.area, opt.index, opt.playerIndex)
        cid = card.id if card is not None else None
        if cid is None:
            return -500
        if ctx == SelectContext.SETUP_ACTIVE_POKEMON:
            return {IMPIDIMP: 900, MUNKIDORI: 700, SNORUNT: 500}.get(cid, 200)
        if ctx in (SelectContext.SETUP_BENCH_POKEMON, SelectContext.TO_BENCH,
                   SelectContext.TO_FIELD):
            return bench_pick_score(obs, cid)
        if ctx == SelectContext.TO_HAND:
            return fetch_score(obs, cid)
        if ctx in (SelectContext.SWITCH, SelectContext.TO_ACTIVE):
            if opt.playerIndex != obs.current.yourIndex:
                # Boss target: prefer low-hp / high-value opposing pick
                return 300 + (getattr(card, "maxHp", 0) - getattr(card, "hp", 0))
            score = 200 + 60 * energy_count(card)
            if cid == GRIMMSNARL_EX:
                score += 500
            elif cid == MUNKIDORI:
                score += 120
            elif cid in (SNORUNT, IMPIDIMP):
                score += 60
            return score
        if ctx == SelectContext.DISCARD:
            keep = {GRIMMSNARL_EX: -600, MORGREM: -400, RARE_CANDY: -350,
                    IMPIDIMP: -250, MUNKIDORI: -250, DARK_ENERGY: -150}
            return 200 + keep.get(cid, 0)
        if ctx in (SelectContext.TO_DECK, SelectContext.TO_DECK_BOTTOM):
            return -fetch_score(obs, cid)
        if ctx in (SelectContext.DAMAGE, SelectContext.DAMAGE_COUNTER,
                   SelectContext.DAMAGE_COUNTER_ANY, SelectContext.EFFECT_TARGET):
            hp = getattr(card, "hp", 60) or 60
            if opt.playerIndex != obs.current.yourIndex:
                return 400 + max(0, 300 - hp)  # finish the weakest enemy
            return -300 - (getattr(card, "maxHp", 60) - hp)
        return fetch_score(obs, cid)

    if opt.type == OptionType.PLAY:
        card = get_card(obs, AreaType.HAND, opt.index, obs.current.yourIndex)
        cid = card.id if card is not None else None
        if cid is None:
            return -500
        bench_space = me.benchMax - len([p for p in (me.bench or []) if p])
        if cid == IMPIDIMP:
            return 840 if bench_space > 0 else -100
        if cid == MUNKIDORI:
            return (760 - 300 * on_field[MUNKIDORI]) if bench_space > 0 else -100
        if cid == SNORUNT:
            return (420 - 220 * on_field[SNORUNT]) if bench_space > 0 else -100
        if cid == POFFIN:
            return 830 if bench_space > 0 and on_field[IMPIDIMP] < 3 else 200
        if cid == RARE_CANDY:
            return 880 if (on_field[IMPIDIMP] and hand[GRIMMSNARL_EX]) else 120
        if cid == SPIKEMUTH_GYM:
            return 700 if not obs.current.stadium else 100
        if cid == POKE_PAD:
            return 640
        if cid == PETREL:
            if obs.current.supporterPlayed:
                return -800
            missing_candy = on_field[IMPIDIMP] and hand[GRIMMSNARL_EX] and not hand[RARE_CANDY]
            return 720 if missing_candy else 520
        if cid == LILLIE:
            if obs.current.supporterPlayed:
                return -800
            n_hand = sum(hand.values())
            return 920 if n_hand <= 2 else (780 if n_hand <= 3 else (500 if n_hand <= 5 else 120))
        if cid == BOSS_ORDERS:
            if obs.current.supporterPlayed:
                return -800
            return 560 if grimm_ready else 150
        if cid == DAWN:
            return -700 if obs.current.supporterPlayed else 300
        if cid == NIGHT_STRETCHER:
            disc = Counter(c.id for c in (me.discard or []) if c)
            urgent = (disc[GRIMMSNARL_EX] and not hand[GRIMMSNARL_EX]) or \
                     (disc[DARK_ENERGY] and not hand[DARK_ENERGY])
            return 480 if urgent else 90
        if cid == HANDHELD_FAN:
            return 350
        if cid == UNFAIR_STAMP:
            return 260
        return 220

    if opt.type == OptionType.ATTACH:
        card = get_card(obs, opt.area, opt.index, obs.current.yourIndex)
        target = get_card(obs, opt.inPlayArea, opt.inPlayIndex, obs.current.yourIndex)
        if card is None:
            return -500
        if card.id == HANDHELD_FAN:
            # Teachers hold the Fan for the Grimmsnarl attacker; wasting it on a
            # setup Pokémon on turn 1 was a measured failure mode.
            if target is not None and target.id == GRIMMSNARL_EX:
                return 520
            return -400
        return attach_target_score(obs, target, opt.inPlayArea == AreaType.ACTIVE)

    if opt.type == OptionType.EVOLVE:
        evolved = get_card(obs, opt.area, opt.index, obs.current.yourIndex)
        if evolved is None:
            return 300
        if evolved.id == GRIMMSNARL_EX:
            return 950
        if evolved.id == MORGREM:
            return 850
        if evolved.id == FROSLASS:
            return 600
        return 500

    if opt.type == OptionType.ABILITY:
        card = get_card(obs, opt.area, opt.index, obs.current.yourIndex)
        if card is not None and card.id == MUNKIDORI:
            return 890  # Adrena-Brain engine — teachers' most-used MAIN action
        return 640

    if opt.type == OptionType.ATTACK:
        # attacks are strong for this deck; search layer refines the choice
        return 800.0

    if opt.type == OptionType.RETREAT:
        active = (me.active or [None])[0]
        if active is not None and active.id not in ATTACKER_LINE and grimm_ready:
            return 550
        return 60

    if opt.type == OptionType.END:
        return 20.0  # END only when nothing better (teachers' discipline emerges)

    return 50.0


def prior_choice(obs: Observation) -> list[int]:
    sel = obs.select
    n = len(sel.option)
    scores = [prior_score(obs, o) for o in sel.option]
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    mn = max(0, min(sel.minCount, sel.maxCount, n))
    mx = max(0, min(sel.maxCount, n))
    chosen = []
    for i in order:
        if len(chosen) >= mx:
            break
        if scores[i] > 0 or len(chosen) < mn:
            chosen.append(i)
    for i in order:
        if len(chosen) >= mn:
            break
        if i not in chosen:
            chosen.append(i)
    return chosen[:mx] if chosen else list(range(mn))


# --------------------------------------------------------------------------- #
# Determinization search
# --------------------------------------------------------------------------- #
def infer_opponent_deck(obs: Observation) -> list[int]:
    """Best-matching exact meta list for the opponent, from scouting library."""
    revealed = Counter(zone_ids(opp_state(obs)))
    best, best_score = None, -1.0
    for deck in META_DECKS.values():
        dc = Counter(deck)
        overlap = sum(min(c, dc.get(cid, 0)) for cid, c in revealed.items())
        miss = sum(max(0, c - dc.get(cid, 0)) for cid, c in revealed.items())
        score = overlap - 3.0 * miss
        if score > best_score:
            best_score, best = score, deck
    if best is None or best_score <= 0:
        # fallback: generic shell around revealed cards
        pad = [DARK_ENERGY] * 20 + [POKE_PAD] * 10 + [POFFIN] * 10
        return list(revealed.elements()) + pad + [IMPIDIMP] * 4
    return list(best)


def remaining_multiset(full: list[int], player) -> list[int]:
    pool = Counter(full)
    for cid in zone_ids(player):
        if pool.get(cid, 0) > 0:
            pool[cid] -= 1
    return list(pool.elements())


def state_value(so: Observation, my_index: int) -> float:
    """Evaluate a search observation from OUR perspective."""
    cur = so.current
    if cur.result != -1:
        if cur.result == my_index:
            return 10000.0
        if cur.result == 1 - my_index:
            return -10000.0
        return 0.0
    me = cur.players[my_index]
    op = cur.players[1 - my_index]
    v = 0.0
    # prizes YOU have taken = 6 - your remaining prize cards (higher = winning)
    my_taken = 6 - len(me.prize or [])
    op_taken = 6 - len(op.prize or [])
    v += 900.0 * my_taken - 900.0 * op_taken
    if my_taken >= 5:
        v += 700.0   # one KO from winning
    if op_taken >= 5:
        v -= 900.0   # opponent one KO from winning — flee this line
    for p in field_pokemon(me):
        v += 30.0 + 0.35 * (p.hp or 0) + 55.0 * energy_count(p)
        if p.id == GRIMMSNARL_EX:
            v += 160.0
    for p in field_pokemon(op):
        v -= 30.0 + 0.35 * (p.hp or 0) + 45.0 * energy_count(p)
    v += 6.0 * me.handCount - 5.0 * op.handCount
    return v


def rollout(st, my_index: int, cap: int) -> float:
    """Two-sided greedy playout to TERMINAL. Returns win-probability-scale value:
    +1 win / -1 loss / 0 draw (discounted slightly to prefer faster wins);
    falls back to a squashed prize-diff eval only if the cap is hit."""
    so = st.observation
    sid = st.searchId
    steps = 0
    for _ in range(cap):
        if so.current is None or so.current.result != -1 or so.select is None:
            break
        n = len(so.select.option)
        if n == 0:
            break
        mn = max(0, min(so.select.minCount, so.select.maxCount, n))
        k = max(mn, min(1, so.select.maxCount))
        # two-sided greedy playout: a random opponent never punishes our lines
        # and makes greedy plans look better than they are.
        try:
            scores = [prior_score(so, o) for o in so.select.option]
            order = sorted(range(n), key=lambda i: scores[i], reverse=True)
            pick = order[:max(k, mn)] if k else []
        except Exception:
            pick = list(range(min(max(k, mn), n))) if k or mn else []
        try:
            st = search_step(sid, pick)
        except Exception:
            break
        so, sid = st.observation, st.searchId
        steps += 1
    cur = so.current if so is not None else None
    if cur is not None and cur.result != -1:
        discount = max(0.7, 1.0 - 0.002 * steps)
        if cur.result == my_index:
            return 1.0 * discount
        if cur.result == 1 - my_index:
            return -1.0 * discount
        return 0.0
    # cap hit: squash the heuristic eval into (-1, 1) so it can't outvote wins
    return max(-0.6, min(0.6, state_value(so, my_index) / 6000.0))


SEARCH_CONTEXTS = {SelectContext.MAIN, SelectContext.SWITCH, SelectContext.TO_ACTIVE}


def search_decide(obs: Observation, raw_obs: dict) -> list[int] | None:
    sel = obs.select
    if sel.minCount != 1 or sel.maxCount != 1:
        return None
    if sel.context not in SEARCH_CONTEXTS:
        return None
    n = len(sel.option)
    if n <= 1:
        return None
    if not SEARCH_AVAILABLE:
        return None
    # [fix 12] reset the per-game budget when a NEW game starts (turn
    # regressed) — otherwise search silently dies for later games in a series.
    cur_turn = int(obs.current.turn or 0)
    if cur_turn < int(_spent.get("prev_turn", 0)) - 3:
        _spent["t"] = 0.0
    _spent["prev_turn"] = cur_turn
    if _spent["t"] > GAME_BUDGET_S:
        return None
    if not raw_obs.get("search_begin_input"):
        return None

    start = time.time()
    my_index = obs.current.yourIndex
    me = my_state(obs)
    opp = opp_state(obs)

    scores = [prior_score(obs, o) for o in sel.option]
    order = sorted(range(n), key=lambda i: scores[i], reverse=True)
    candidates = order[:SEARCH_TOP_OPTIONS]
    if len(candidates) < 2:
        return None

    my_pool = remaining_multiset(MY_DECK, me)
    opp_deck_guess = infer_opponent_deck(obs)
    opp_pool = remaining_multiset(opp_deck_guess, opp)

    my_deck_n = me.deckCount or 0
    my_prize_n = len(me.prize or [])
    opp_deck_n = opp.deckCount or 0
    opp_prize_n = len(opp.prize or [])
    opp_hand_n = opp.handCount or 0

    # predicted face-down opponent active must be a plausible basic from THEIR
    # deck, not a card from ours
    common_basics = [cid for cid in opp_pool if cid in KNOWN_BASICS]
    if common_basics:
        opp_active_guess = [Counter(common_basics).most_common(1)[0][0]]
    else:
        opp_active_guess = [IMPIDIMP]

    totals = {i: 0.0 for i in candidates}
    counts = {i: 0 for i in candidates}
    worlds = 0
    while worlds < SEARCH_MAX_WORLDS and time.time() - start < DECISION_BUDGET_S:
        random.shuffle(my_pool)
        random.shuffle(opp_pool)
        md = (my_pool * 3)[:my_deck_n]
        mp = (my_pool * 3)[my_deck_n:my_deck_n + my_prize_n]
        od = (opp_pool * 3)[:opp_deck_n]
        opz = (opp_pool * 3)[opp_deck_n:opp_deck_n + opp_prize_n]
        oh = (opp_pool * 3)[opp_deck_n + opp_prize_n:opp_deck_n + opp_prize_n + opp_hand_n]
        try:
            root = search_begin(obs, md, mp, od, opz, oh, opp_active_guess)
        except Exception:
            break
        worlds += 1
        # [fix 13] all candidates must see the SAME worlds — no mid-world
        # time break, or the override margin compares unpaired means.
        for i in candidates:
            try:
                st = search_step(root.searchId, [i])
                value = rollout(st, my_index, SEARCH_ROLLOUT_CAP)
                totals[i] += value
                counts[i] += 1
            except Exception:
                continue
        try:
            search_end()
        except Exception:
            pass

    _spent["t"] += time.time() - start
    # require enough worlds for the win-prob means to be meaningful
    evaluated = {i: totals[i] / counts[i] for i in candidates if counts[i] >= 3}
    if not evaluated or worlds < 3:
        return None
    prior_pick = order[0]
    best = max(evaluated, key=lambda i: (evaluated[i], scores[i]))
    # Search OVERRIDES the teacher-informed prior only on a decisive win-prob
    # margin; on noise-level differences the prior stands.
    if prior_pick in evaluated and best != prior_pick:
        if evaluated[best] - evaluated[prior_pick] < SEARCH_OVERRIDE_MARGIN:
            return [prior_pick]
    return [best]


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def agent(obs_dict: dict) -> list[int]:
    try:
        obs = to_observation_class(obs_dict)
    except Exception:
        return MY_DECK
    if obs is None or obs.select is None:
        return MY_DECK
    if obs.current is None or not obs.select.option:
        return []
    try:
        searched = None
        try:
            searched = search_decide(obs, obs_dict)
        except Exception:
            searched = None
        if searched is not None:
            return searched
        return prior_choice(obs)
    except Exception:
        try:
            n = len(obs.select.option)
            mn = max(0, min(obs.select.minCount, obs.select.maxCount, n))
            return list(range(mn))
        except Exception:
            return []
