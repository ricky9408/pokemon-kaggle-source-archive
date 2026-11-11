# ============================================================================
# claude-grimm-bc-search v1
#
#   * DECK: 87f9eb60af — easonyanyan (#3, 1170) Marnie's Grimmsnarl ex list:
#     4 Grimmsnarl ex / 4 Rare Candy / Dudunsparce draw line / Fezandipiti ex.
#     Scouted matchups: 4-0 and 3-0 vs the other Grimmsnarl variants, 2-1 vs
#     the #1 team's Mega Kangaskhan.
#   * POLICY: behavior-cloned averaged-perceptron ranker trained on 14.9k
#     decisions from the top Grimmsnarl-family pilots (post-2026-07-01 engine
#     replays only). Holdout top-1 0.725 / top-3 0.946.
#   * SEARCH: official determinization API on MAIN single-pick decisions;
#     opponent hidden zones filled from a bundled library of 41 exact meta
#     decks scouted from the live pool. Rollouts: BC policy for our side, a
#     generic competent policy for the opponent (v148's mistake fixed).
#   * SAFETY: engine-legal indices only, strict time budgets, every failure
#     path falls back to the BC policy choice, then to first-legal.
# ============================================================================
from __future__ import annotations

import json
import os
import random
import time
from collections import Counter

random.seed(0xC1A0DE)

try:
    _DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:  # kaggle_environments execs this file without __file__
    _DIR = "/kaggle_simulations/agent"


def _find(name: str) -> str | None:
    for base in (_DIR, ".", "/kaggle_simulations/agent"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            return p
    return None


# --- featurizer (bundled copy of features.py logic via import) --------------
import sys
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)
try:
    from features import option_features, option_card_id, target_card  # noqa
except Exception:  # pragma: no cover — features.py always bundled
    option_features = None

try:
    from cg.api import to_observation_class
    from cg.api import search_begin, search_end
    import cg.api as _capi
    import ctypes as _ct
    import json as _json
    SEARCH_AVAILABLE = os.environ.get("DISABLE_SEARCH", "") != "1"
except ImportError:
    to_observation_class = None
    SEARCH_AVAILABLE = False


def _raw_step(search_id: int, select: list[int]):
    """search_step without dataclass materialization: returns (obs_dict, sid)."""
    bs = _capi.lib.SearchStep(_capi.agent_ptr, search_id,
                              (_ct.c_int * len(select))(*select), len(select))
    result = _json.loads(bs.decode())
    if result.get("error", 0) != 0:
        return None, None
    state = result.get("state") or {}
    return state.get("observation"), state.get("searchId")

# --- deck / model assets -----------------------------------------------------
DARK = 7
IMPIDIMP, MORGREM, GRIMMSNARL = 646, 647, 648
MUNKIDORI, DUNSPARCE, DUDUNSPARCE, FEZANDIPITI = 112, 305, 66, 140
RARE_CANDY, POFFIN, POKE_PAD, LILLIE = 1079, 1086, 1152, 1227
DAWN, SPIKEMUTH, FAN, BOSS, STAMP, STRETCHER = 1231, 1259, 1161, 1182, 1080, 1097

DEFAULT_DECK = ([DARK] * 12 + [IMPIDIMP] * 4 + [GRIMMSNARL] * 4 + [RARE_CANDY] * 4
                + [POFFIN] * 4 + [POKE_PAD] * 4 + [LILLIE] * 4
                + [DUDUNSPARCE] * 3 + [MUNKIDORI] * 3 + [DUNSPARCE] * 3
                + [DAWN] * 3 + [SPIKEMUTH] * 3 + [MORGREM] * 2 + [FAN] * 2
                + [BOSS] * 2 + [FEZANDIPITI] + [STAMP] + [STRETCHER])


def _load_deck() -> list[int]:
    p = _find("deck.csv")
    if p:
        cards = [int(x) for x in open(p).read().split() if x.strip()]
        if len(cards) == 60:
            return cards
    return list(DEFAULT_DECK)


MY_DECK = _load_deck()

_policy_path = _find("policy.json")
try:
    WEIGHTS = json.load(open(_policy_path))["weights"] if _policy_path else {}
except Exception:
    WEIGHTS = {}

_meta_path = _find("meta_decks.json")
try:
    META_DECKS = ({k: list(map(int, v)) for k, v in json.load(open(_meta_path)).items()}
                  if _meta_path else {})
except Exception:
    META_DECKS = {}

_atk_path = _find("attacks.json")
try:
    ATTACKS = json.load(open(_atk_path)) if _atk_path else {}
except Exception:
    ATTACKS = {}

_pall_path = _find("policy_all.json")
try:
    W_ALL = json.load(open(_pall_path))["weights"] if _pall_path else {}
except Exception:
    W_ALL = {}

_val_path = _find("value.json")
try:
    from values import value_score as _vscore
    V_W = json.load(open(_val_path))["weights"] if _val_path else {}
except Exception:
    V_W = {}

_cards_path = _find("cards.json")
try:
    CARDS = json.load(open(_cards_path)) if _cards_path else {}
except Exception:
    CARDS = {}


FULL_METAL_LAB = 1244
METAL_TYPE = 8


def _damage_reduction(target: dict | None, stadium_id) -> int:
    """Full Metal Lab: Metal Pokemon take 30 less from opponent attacks."""
    if stadium_id != FULL_METAL_LAB or not isinstance(target, dict):
        return 0
    info = CARDS.get(str(target.get("id")))
    if info and len(info) >= 5 and info[4] == METAL_TYPE:
        return 30
    return 0


def _best_usable_damage(pokemon: dict | None, vs: dict | None = None,
                        stadium_id=None) -> int:
    """Max damage the Pokemon could do given its current energy count."""
    if not isinstance(pokemon, dict):
        return 0
    info = CARDS.get(str(pokemon.get("id")))
    if not info:
        return 0
    n_energy = len(pokemon.get("energies") or [])
    best = 0
    for aid in info[1]:
        a = ATTACKS.get(str(aid))
        if a and n_energy >= a[1]:
            best = max(best, a[0])
    if best:
        best = max(0, best - _damage_reduction(vs, stadium_id))
    return best

# --- option type / context ints ---------------------------------------------
CTX_MAIN, CTX_IS_FIRST = 0, 41
T_NUMBER, T_YES, T_NO, T_CARD = 0, 1, 2, 3
T_PLAY, T_ATTACH, T_EVOLVE, T_ABILITY = 7, 8, 9, 10
T_RETREAT, T_ATTACK, T_END = 12, 13, 14

# --- time budget ---------------------------------------------------------------
GAME_BUDGET_S = 380.0
DECISION_BUDGET_S = 3.0
MIN_OVERAGE_KEEP_S = 150.0
SEARCH_MAX_WORLDS = 32
SEARCH_TOP_OPTIONS = 6
SEARCH_ROLLOUT_CAP = 200
SEARCH_OVERRIDE_MARGIN = 0.15
_spent = {"t": 0.0, "prev_turn": 0}


# --- helpers -------------------------------------------------------------------
def _players(obs: dict):
    cur = obs.get("current") or {}
    players = cur.get("players") or [{}, {}]
    yi = cur.get("yourIndex") or 0
    return cur, players[yi], players[1 - yi], yi


def _field_ids(player: dict) -> list[int]:
    out = []
    for zone in ("active", "bench"):
        for c in player.get(zone) or []:
            if c:
                out.append(c.get("id"))
    return out


def _zone_ids(player: dict) -> list[int]:
    """All card ids known to be OUT of the player's hidden pool."""
    ids = []
    for zone in ("hand", "discard", "active", "bench"):
        for c in player.get(zone) or []:
            if not c:
                continue
            ids.append(c.get("id"))
            for sub in (c.get("energyCards") or []):
                if sub:
                    ids.append(sub.get("id"))
            for sub in (c.get("tools") or []):
                if sub:
                    ids.append(sub.get("id"))
            for sub in (c.get("preEvolution") or []):
                if sub:
                    ids.append(sub.get("id"))
    return [i for i in ids if isinstance(i, int)]


def policy_scores(obs: dict) -> list[float]:
    n = len(obs["select"]["option"])
    if option_features is None or not WEIGHTS:
        return [0.0] * n
    out = []
    for i in range(n):
        try:
            out.append(sum(WEIGHTS.get(f, 0.0) for f in option_features(obs, i)))
        except Exception:
            out.append(-1e9)
    return out


GRIMM_LINE = {IMPIDIMP, MORGREM, GRIMMSNARL}
ENERGY_NEED = {GRIMMSNARL: 2, MORGREM: 2, IMPIDIMP: 1, MUNKIDORI: 1,
               DUNSPARCE: 1, DUDUNSPARCE: 3, FEZANDIPITI: 3}


def _energy_need(cid) -> int:
    """Energy a Pokemon actually wants: curated override, else its max attack
    cost from the engine tables (fixes need=2 default starving 3-cost decks)."""
    if cid in ENERGY_NEED:
        return ENERGY_NEED[cid]
    info = CARDS.get(str(cid))
    if info and info[1]:
        costs = [(ATTACKS.get(str(a)) or [0, 2])[1] for a in info[1]]
        if costs:
            return max(costs)
    return 2

CTX_SWITCH, CTX_TO_ACTIVE = 3, 4
CTX_DMG_CTR, CTX_DAMAGE = 13, 15


def _in_play_ref(obs: dict, opt: dict):
    """The in-play Pokemon a CARD/ATTACH option points at (target enrichment)."""
    try:
        area = opt.get("inPlayArea") if opt.get("inPlayArea") is not None else opt.get("area")
        idx = opt.get("inPlayIndex") if opt.get("inPlayIndex") is not None else opt.get("index")
        if area not in (4, 5) or idx is None:
            return None
        cur = obs.get("current") or {}
        players = cur.get("players") or []
        pidx = opt.get("playerIndex")
        pidx = pidx if pidx is not None else (cur.get("yourIndex") or 0)
        if pidx >= len(players):
            return None
        zone = players[pidx].get("active" if area == 4 else "bench") or []
        return zone[idx] if idx < len(zone) else None
    except Exception:
        return None


def guard_scores(obs: dict, scores: list[float]) -> list[float]:
    """Domain guards layered on the BC scores (also shape search rollouts)."""
    sel = obs["select"]
    ctx = sel.get("context")
    cur, me, op, yi = _players(obs)
    opts = sel["option"]
    n_field = len(_field_ids(me))
    opp_active = (op.get("active") or [None])[0]
    opp_active_hp = (opp_active or {}).get("hp") or 999
    _std = (cur.get("stadium") or [None])
    stadium_id = (_std[0] or {}).get("id") if _std else None
    # effective hp for lethal math accounts for Full Metal Lab on Metal targets
    opp_active_ehp = opp_active_hp + _damage_reduction(opp_active, stadium_id)
    out = list(scores)
    # lethal-attack promotion must NOT preempt development plays: teachers do
    # all engine plays first and attack last. Promote a lethal attack only when
    # the BC policy already wants to end the turn (best non-attack is END or
    # RETREAT) — then make sure we pick the KILLING attack, not a weaker one.
    turn_done = False
    if ctx == CTX_MAIN:
        best_i = max(range(len(opts)),
                     key=lambda j: (scores[j], -j)) if opts else None
        non_attack = [(scores[j], opts[j].get("type")) for j in range(len(opts))
                      if opts[j].get("type") != T_ATTACK]
        if non_attack:
            na_best = max(non_attack)
            turn_done = na_best[1] in (T_END, T_RETREAT)
        else:
            turn_done = True
        if best_i is not None and opts[best_i].get("type") == T_ATTACK:
            turn_done = True  # BC already wants to attack; pick the lethal one
    for i, opt in enumerate(opts):
        t = opt.get("type")
        # go first: teachers 12/12
        if ctx == CTX_IS_FIRST:
            out[i] = 1e6 if t == T_YES else 0.0
            continue
        # never Run Away Draw our LAST Pokemon
        if t == T_ABILITY and n_field <= 1:
            try:
                cid = option_card_id(obs, opt)
            except Exception:
                cid = None
            if cid == DUDUNSPARCE:
                out[i] = -1e8
                continue
        # approximate-lethal attack: engine only lists legal attacks
        if t == T_ATTACK and ctx == CTX_MAIN and turn_done:
            info = ATTACKS.get(str(opt.get("attackId")))
            if info and opp_active_ehp <= info[0]:
                out[i] += 5000.0
        # stadium war: their Full Metal Lab blunts our attacks — bump it
        if t == T_PLAY and ctx == CTX_MAIN and stadium_id == FULL_METAL_LAB:
            try:
                cid = option_card_id(obs, opt)
            except Exception:
                cid = None
            if cid == SPIKEMUTH:
                out[i] += 200.0
        # energy attachment discipline: don't stack a target that's already fueled
        if ctx == 21 or t == T_ATTACH:
            ref = _in_play_ref(obs, opt)
            if isinstance(ref, dict):
                rid = ref.get("id")
                need = _energy_need(rid)
                have = len(ref.get("energies") or [])
                excess = have - need
                if excess >= 1:
                    out[i] -= 150.0 * excess
                elif have < need and rid in GRIMM_LINE:
                    out[i] += 150.0
        # Boss's Orders / gust target: prefer a target we can likely KO or a fat setup piece
        if ctx in (CTX_SWITCH, CTX_TO_ACTIVE) and opt.get("playerIndex") not in (None, yi):
            ref = _in_play_ref(obs, opt)
            if isinstance(ref, dict):
                hp = ref.get("hp") or 999
                my_active = (me.get("active") or [None])[0]
                if _best_usable_damage(my_active, ref, stadium_id) >= hp:
                    out[i] += 2000.0
        # damage-counter targets (Munkidori/Shadow Bullet): finish low-HP enemies
        if ctx in (CTX_DMG_CTR, CTX_DAMAGE) and opt.get("playerIndex") not in (None, yi):
            ref = _in_play_ref(obs, opt)
            if isinstance(ref, dict):
                hp = ref.get("hp") or 999
                if hp <= 30:
                    out[i] += 1500.0
    return out


def choose(obs: dict) -> list[int]:
    sel = obs["select"]
    opts = sel.get("option") or []
    n = len(opts)
    mn = max(0, min(sel.get("minCount", 1), n))
    mx = max(mn, min(sel.get("maxCount", 1), n))
    scores = guard_scores(obs, policy_scores(obs))
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    if mn == 1 and mx == 1:
        return [order[0]]
    chosen = order[:mn]
    for i in order[mn:mx]:
        if scores[i] > 0:
            chosen.append(i)
    return chosen


# --- determinization search ---------------------------------------------------
def infer_opponent_deck(op: dict) -> list[int]:
    revealed = Counter(_zone_ids(op))
    best, best_score = None, -1e9
    for deck in META_DECKS.values():
        dc = Counter(deck)
        overlap = sum(min(c, dc.get(cid, 0)) for cid, c in revealed.items())
        miss = sum(max(0, c - dc.get(cid, 0)) for cid, c in revealed.items())
        s = overlap - 3.0 * miss
        if s > best_score:
            best_score, best = s, deck
    if best is None:
        return list(DEFAULT_DECK)
    return list(best)


def remaining_pool(full: list[int], player: dict) -> list[int]:
    pool = Counter(full)
    for cid in _zone_ids(player):
        if pool.get(cid, 0) > 0:
            pool[cid] -= 1
    return list(pool.elements())


KNOWN_BASICS = {IMPIDIMP, MUNKIDORI, DUNSPARCE, 860, 741, 305, 169, 57, 344,
                673, 675, 677, 920, 343, 235, 649, 400, 1073, 66, 140, 756}


def generic_scores(obs: dict) -> list[float]:
    """Deck-agnostic competent policy for opponent rollouts."""
    sel = obs["select"]
    opts = sel.get("option") or []
    cur, me, op, yi = _players(obs)
    out = []
    for opt in opts:
        t = opt.get("type")
        if t == T_ATTACK:
            out.append(800.0)
        elif t == T_EVOLVE:
            out.append(700.0)
        elif t == T_ABILITY:
            out.append(500.0)
        elif t == T_ATTACH:
            out.append(400.0)
        elif t == T_PLAY:
            out.append(300.0)
        elif t == T_CARD:
            out.append(250.0)
        elif t == T_YES:
            out.append(200.0)
        elif t == T_NUMBER:
            out.append(100.0 + float(opt.get("number") or 0))
        elif t == T_RETREAT:
            out.append(30.0)
        elif t == T_END:
            out.append(10.0)
        else:
            out.append(50.0)
    return out


def _pick_for(so: dict, our_index: int, depth: int = 0) -> list[int]:
    """Rollout action: BC policy for our side; learned opponent model near-term,
    generic beyond (speed)."""
    sel = so["select"]
    n = len(sel.get("option") or [])
    mn = max(0, min(sel.get("minCount", 1), n))
    mx = max(mn, min(sel.get("maxCount", 1), n))
    cur = so.get("current") or {}
    if cur.get("yourIndex") == our_index:
        scores = guard_scores(so, policy_scores(so))
    elif depth < 24 and W_ALL and option_features is not None:
        try:
            opts_n = len(so["select"]["option"])
            scores = [sum(W_ALL.get(f, 0.0) for f in option_features(so, i))
                      for i in range(opts_n)]
        except Exception:
            scores = generic_scores(so)
    else:
        scores = generic_scores(so)
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    k = max(mn, min(1, mx)) if mx >= 1 else mn
    return order[:k] if k else []


def state_value(so: dict, my_index: int) -> float:
    cur = so.get("current") or {}
    res = cur.get("result", -1)
    if res != -1:
        if res == my_index:
            return 10000.0
        if res == 1 - my_index:
            return -10000.0
        return 0.0
    players = cur.get("players") or [{}, {}]
    me, op = players[my_index], players[1 - my_index]
    v = 0.0
    my_taken = 6 - len(me.get("prize") or [])
    op_taken = 6 - len(op.get("prize") or [])
    v += 900.0 * (my_taken - op_taken)
    if my_taken >= 5:
        v += 700.0
    if op_taken >= 5:
        v -= 900.0
    for zone, sign, mult in ((me, 1, 1.0), (op, -1, 0.9)):
        for zn in ("active", "bench"):
            for c in zone.get(zn) or []:
                if c:
                    v += sign * mult * (30.0 + 0.3 * (c.get("hp") or 0)
                                        + 50.0 * len(c.get("energies") or []))
    v += 6.0 * (me.get("handCount") or 0) - 5.0 * (op.get("handCount") or 0)
    return v


def rollout(so: dict | None, sid, my_index: int, cap: int) -> float:
    steps = 0
    for _ in range(cap):
        if not isinstance(so, dict):
            break
        cur = so.get("current")
        if cur is None or cur.get("result", -1) != -1 or so.get("select") is None:
            break
        try:
            pick = _pick_for(so, my_index, steps)
            so, sid = _raw_step(sid, pick)
        except Exception:
            break
        steps += 1
    cur = (so or {}).get("current") if isinstance(so, dict) else None
    if cur is not None and cur.get("result", -1) != -1:
        res = cur["result"]
        discount = max(0.7, 1.0 - 0.002 * steps)
        if res == my_index:
            return discount
        if res == 1 - my_index:
            return -discount
        return 0.0
    if cur is None:
        return 0.0
    if V_W:
        try:
            v = _vscore(V_W, so)  # acting player's perspective
            if cur.get("yourIndex") != my_index:
                v = -v
            return max(-0.6, min(0.6, v))
        except Exception:
            pass
    return max(-0.6, min(0.6, state_value(so, my_index) / 6000.0))


SEARCH_CONTEXTS = {0, 3, 4}  # MAIN, SWITCH, TO_ACTIVE — BC owns high-fidelity contexts


def search_decide(obs_cls, obs: dict) -> list[int] | None:
    sel = obs.get("select") or {}
    if sel.get("minCount") != 1 or sel.get("maxCount") != 1:
        return None
    if sel.get("context") not in SEARCH_CONTEXTS:
        return None
    opts = sel.get("option") or []
    n = len(opts)
    if n <= 1 or not SEARCH_AVAILABLE or not obs.get("search_begin_input"):
        return None
    cur = obs.get("current") or {}
    overage = obs.get("remainingOverageTime")
    if isinstance(overage, (int, float)) and overage < MIN_OVERAGE_KEEP_S:
        return None
    turn = int(cur.get("turn") or 0)
    if turn < _spent["prev_turn"] - 3:
        _spent["t"] = 0.0
    _spent["prev_turn"] = turn
    if _spent["t"] > GAME_BUDGET_S:
        return None

    start = time.time()
    _, me, op, yi = _players(obs)
    scores = guard_scores(obs, policy_scores(obs))
    order = sorted(range(n), key=lambda i: (scores[i], -i), reverse=True)
    candidates = order[:SEARCH_TOP_OPTIONS]
    if len(candidates) < 2:
        return None
    # confidence gate (holdout-calibrated): BC margin >=12 -> 92%+ top-1, trust it;
    # concentrate the search budget on genuinely uncertain decisions.
    bc_margin = scores[order[0]] - scores[order[1]]
    if bc_margin >= 12.0:
        return None
    if bc_margin < 4.0:
        deadline = deadline * 1.3

    my_pool = remaining_pool(MY_DECK, me)
    opp_deck_guess = infer_opponent_deck(op)
    opp_pool = remaining_pool(opp_deck_guess, op)
    # Archaludon family (largest band archetype, our weakest matchup): search harder
    arch_markers = {190, 169, 666}
    deadline = DECISION_BUDGET_S
    if sum(1 for c in opp_deck_guess if c in arch_markers) >= 8:
        deadline = DECISION_BUDGET_S * 1.6

    my_deck_n = me.get("deckCount") or 0
    my_prize_n = len(me.get("prize") or [])
    opp_deck_n = op.get("deckCount") or 0
    opp_prize_n = len(op.get("prize") or [])
    opp_hand_n = op.get("handCount") or 0

    opp_basics = [cid for cid in opp_pool if cid in KNOWN_BASICS]
    opp_active_guess = ([Counter(opp_basics).most_common(1)[0][0]]
                        if opp_basics else [IMPIDIMP])

    totals = {i: 0.0 for i in candidates}
    counts = {i: 0 for i in candidates}
    worlds = 0
    while worlds < SEARCH_MAX_WORLDS and time.time() - start < deadline:
        random.shuffle(my_pool)
        random.shuffle(opp_pool)
        md = (my_pool * 3)[:my_deck_n]
        mp = (my_pool * 3)[my_deck_n:my_deck_n + my_prize_n]
        od = (opp_pool * 3)[:opp_deck_n]
        opz = (opp_pool * 3)[opp_deck_n:opp_deck_n + opp_prize_n]
        oh = (opp_pool * 3)[opp_deck_n + opp_prize_n:opp_deck_n + opp_prize_n + opp_hand_n]
        try:
            root = search_begin(obs_cls, md, mp, od, opz, oh, opp_active_guess)
        except Exception:
            break
        worlds += 1
        for i in candidates:
            try:
                so, sid = _raw_step(root.searchId, [i])
                if so is None:
                    continue
                totals[i] += rollout(so, sid, yi, SEARCH_ROLLOUT_CAP)
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


# --- entry point ----------------------------------------------------------------
def agent(obs_dict: dict) -> list[int]:
    try:
        if obs_dict.get("select") is None:
            return list(MY_DECK)
        sel = obs_dict["select"]
        opts = sel.get("option") or []
        if not opts:
            return []
        picked = None
        try:
            if to_observation_class is not None and SEARCH_AVAILABLE:
                obs_cls = to_observation_class(obs_dict)
                picked = search_decide(obs_cls, obs_dict)
        except Exception:
            picked = None
        if picked is None:
            picked = choose(obs_dict)
        # final legality clamp
        n = len(opts)
        mn = max(0, min(sel.get("minCount", 1), n))
        mx = max(mn, min(sel.get("maxCount", 1), n))
        picked = [i for k, i in enumerate(picked) if isinstance(i, int) and 0 <= i < n
                  and i not in picked[:k]]
        if len(picked) < mn:
            picked += [i for i in range(n) if i not in picked][:mn - len(picked)]
        return picked[:mx]
    except Exception:
        try:
            sel = obs_dict.get("select") or {}
            n = len(sel.get("option") or [])
            mn = max(0, min(sel.get("minCount", 1), n))
            return list(range(mn))
        except Exception:
            return []
