# ============================================================================
# codex-arch-search-native-v151
#
# Ground-up redesign around ONE hypothesis: our strongest proven pilot
# (v141's hand-tuned Archaludon policy, converged public ~991) upgraded with
# the engine's determinization search as the decision layer.
#
#   * PRIOR: prior_v141.score_option — the exact 991-class policy, untouched.
#   * SEARCH: SearchBegin/SearchStep determinization worlds; two-sided greedy
#     rollouts to TERMINAL using the same prior; win/loss values; prize-race
#     leaf eval only at rollout caps. Opponent hidden zones from the scouted
#     45-deck meta library.
#   * DISCIPLINE (measured lessons): override the prior only on a decisive
#     win-prob margin; paired worlds; per-game budget reset; preEvolution cards
#     leave the hidden pool; every failure path falls back to the prior.
# ============================================================================
from __future__ import annotations

import json
import os
import random
import time
from collections import Counter

from cg.api import Observation, to_observation_class

try:
    from cg.api import search_begin, search_end, search_step
    SEARCH_AVAILABLE = os.environ.get("CODEX_DISABLE_SEARCH", "") != "1"
except ImportError:
    SEARCH_AVAILABLE = False

    def search_begin(*a, **k):  # pragma: no cover
        raise RuntimeError("search unavailable")

    def search_step(*a, **k):  # pragma: no cover
        raise RuntimeError("search unavailable")

    def search_end(*a, **k):  # pragma: no cover
        return None

import prior_v141 as P

random.seed(0xC0DE151)


def read_deck_csv() -> list[int]:
    for path in ("deck.csv", "/kaggle_simulations/agent/deck.csv"):
        if os.path.exists(path):
            with open(path) as fh:
                cards = [int(x) for x in fh.read().split() if x.strip()]
            if len(cards) == 60:
                return cards
    return []


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
# Budgets (runTimeout 2000s/episode; measured ~10k search-steps/s)
# --------------------------------------------------------------------------- #
GAME_BUDGET_S = 900.0
DECISION_BUDGET_S = 5.0
SEARCH_MAX_WORLDS = 32
SEARCH_TOP_OPTIONS = 6
SEARCH_ROLLOUT_CAP = 160
SEARCH_OVERRIDE_MARGIN = 0.12
_spent = {"t": 0.0, "prev_turn": 0}

# common basic Pokémon across the scouted meta (opponent face-down guess)
KNOWN_BASICS = {646, 112, 860, 305, 741, 169, 57, 677, 675, 673, 920, 343, 235, 649, 400, 1073}


# --------------------------------------------------------------------------- #
# Helpers
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
                for sub in (getattr(card, "preEvolution", None) or []):
                    if sub is not None:
                        ids.append(sub.id)
    return ids

def energy_count(pokemon) -> int:
    return len(getattr(pokemon, "energies", None) or [])


def prior_scores(obs: Observation) -> list[float]:
    out = []
    for opt in obs.select.option:
        try:
            s = P.score_option(obs, opt)
            if isinstance(s, tuple):
                s = s[0]
            out.append(float(s))
        except Exception:
            out.append(0.0)
    return out


def prior_choice(obs: Observation) -> list[int]:
    try:
        picks = P.choose_options(obs)
        if isinstance(picks, list) and picks:
            return picks
    except Exception:
        pass
    sel = obs.select
    n = len(sel.option)
    mn = max(0, min(sel.minCount, sel.maxCount, n))
    return list(range(mn))


# --------------------------------------------------------------------------- #
# Determinization search
# --------------------------------------------------------------------------- #
def infer_opponent_deck(obs: Observation) -> list[int]:
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
        pad = [7] * 16 + [1152] * 10 + [1086] * 10
        return list(revealed.elements()) + pad + [646] * 4
    return list(best)


def remaining_multiset(full: list[int], player) -> list[int]:
    pool = Counter(full)
    for cid in zone_ids(player):
        if pool.get(cid, 0) > 0:
            pool[cid] -= 1
    return list(pool.elements())


def state_value(so: Observation, my_index: int) -> float:
    cur = so.current
    if cur is None:
        return 0.0
    if cur.result != -1:
        if cur.result == my_index:
            return 1.0
        if cur.result == 1 - my_index:
            return -1.0
        return 0.0
    # prize-race leaf eval, squashed so it can never outvote a real win
    me = cur.players[my_index]
    op = cur.players[1 - my_index]
    my_taken = 6 - len(me.prize or [])
    op_taken = 6 - len(op.prize or [])
    v = 900.0 * (my_taken - op_taken)
    if my_taken >= 5:
        v += 700.0
    if op_taken >= 5:
        v -= 900.0
    for p in field_pokemon(me):
        v += 25.0 + 0.3 * (p.hp or 0) + 50.0 * energy_count(p)
    for p in field_pokemon(op):
        v -= 25.0 + 0.3 * (p.hp or 0) + 45.0 * energy_count(p)
    v += 5.0 * (me.handCount or 0) - 4.0 * (op.handCount or 0)
    # spec #2/#10: endgame exposure — with the opponent <=2 prizes from winning,
    # each multi-prize Pokémon of mine on the board is their win condition.
    if op_taken >= 4:
        try:
            table = getattr(P, "CARD_TABLE", {})
            for p in field_pokemon(me):
                data = table.get(p.id)
                if data is not None and (getattr(data, "ex", False) or getattr(data, "megaEx", False)):
                    v -= 400.0
        except Exception:
            pass
    return max(-0.6, min(0.6, v / 6000.0))


def greedy_pick(so: Observation) -> list[int]:
    sel = so.select
    n = len(sel.option)
    mn = max(0, min(sel.minCount, sel.maxCount, n))
    k = max(mn, min(1, sel.maxCount))
    try:
        scores = []
        for opt in sel.option:
            s = P.score_option(so, opt)
            if isinstance(s, tuple):
                s = s[0]
            scores.append(float(s))
        order = sorted(range(n), key=lambda i: scores[i], reverse=True)
        return order[:max(k, mn)] if k else []
    except Exception:
        return list(range(min(max(k, mn), n))) if (k or mn) else []


def rollout(st, my_index: int, cap: int) -> float:
    so = st.observation
    sid = st.searchId
    steps = 0
    for _ in range(cap):
        if so.current is None or so.current.result != -1 or so.select is None:
            break
        if not so.select.option:
            break
        pick = greedy_pick(so)
        try:
            st = search_step(sid, pick)
        except Exception:
            break
        so, sid = st.observation, st.searchId
        steps += 1
    cur = so.current if so is not None else None
    if cur is not None and cur.result != -1:
        # spec #1: this-turn lethals must dominate later wins — a missed lethal
        # is ~1.0 win-prob per occurrence.
        if steps <= 8:
            discount = 1.0
        else:
            discount = max(0.6, 1.0 - 0.004 * steps)
        if cur.result == my_index:
            return 1.0 * discount
        if cur.result == 1 - my_index:
            return -1.0 * discount
        return 0.0
    return state_value(so, my_index)


SEARCH_CONTEXT_IDS = {0, 3, 4}  # MAIN, SWITCH, TO_ACTIVE


def search_decide(obs: Observation, raw_obs: dict) -> list[int] | None:
    sel = obs.select
    if sel.minCount != 1 or sel.maxCount != 1:
        return None
    try:
        ctx = int(sel.context)
    except (TypeError, ValueError):
        return None
    if ctx not in SEARCH_CONTEXT_IDS:
        return None
    n = len(sel.option)
    if n <= 1 or not SEARCH_AVAILABLE:
        return None

    # per-game budget reset on new game (turn regression)
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

    scores = prior_scores(obs)
    order = sorted(range(n), key=lambda i: scores[i], reverse=True)
    candidates = order[:SEARCH_TOP_OPTIONS]
    if len(candidates) < 2:
        return None

    my_pool = remaining_multiset(MY_DECK, me)
    opp_pool = remaining_multiset(infer_opponent_deck(obs), opp)
    my_deck_n = me.deckCount or 0
    my_prize_n = len(me.prize or [])
    opp_deck_n = opp.deckCount or 0
    opp_prize_n = len(opp.prize or [])
    opp_hand_n = opp.handCount or 0

    common_basics = [cid for cid in opp_pool if cid in KNOWN_BASICS]
    opp_active_guess = [Counter(common_basics).most_common(1)[0][0]] if common_basics else [646]

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
        # paired worlds: every candidate sees the same world set
        for i in candidates:
            try:
                st = search_step(root.searchId, [i])
                totals[i] += rollout(st, my_index, SEARCH_ROLLOUT_CAP)
                counts[i] += 1
            except Exception:
                continue
        try:
            search_end()
        except Exception:
            pass

    _spent["t"] += time.time() - start
    evaluated = {i: totals[i] / counts[i] for i in candidates if counts[i] >= 3}
    if not evaluated or worlds < 3:
        return None
    prior_pick = order[0]
    best = max(evaluated, key=lambda i: (evaluated[i], scores[i]))
    if prior_pick in evaluated and best != prior_pick:
        if evaluated[best] - evaluated[prior_pick] < SEARCH_OVERRIDE_MARGIN:
            return [prior_pick]
    return [best]


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
