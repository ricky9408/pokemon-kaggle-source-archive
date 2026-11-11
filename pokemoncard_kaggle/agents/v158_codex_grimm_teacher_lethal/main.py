# ============================================================================
# codex-grimm-teacher-lethal-v158
#
# v155 = the synthesis probe: aidy's EXACT 1148-proven deck (b9bcfb3e10, byte-
# identical to v75's), the deck-matched publicly-validated v75 prior, a TEACHER
# NET behavior-cloned from 9.4k decisions by the 1148/1118-class pilots (aidy +
# Ajishio; holdout 0.472/0.763), and the proven determinization-search shell.
# Neural integration per the twice-validated tie-band discipline: the net WIDENS
# search candidates and directly answers only its measured-strong contexts;
# the domain prior anchors all overrides.
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
import re
import time
from collections import Counter

from cg.api import AreaType, Observation, OptionType, SelectContext, to_observation_class

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

import prior_grm as P

# Re-export engine-piece IDs and prior helpers so shared safety/card-ID audits
# can validate this wrapper even though gameplay scoring delegates to prior_psy.
random.seed(0xC0DE158)


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

# Parity featurizer (byte-identical with tools/train_ml_policy.option_features_v2
# used to train policy_net.npz; verified 0/655 mismatches in June)
# --------------------------------------------------------------------------- #
_AREA_NAMES = {1: "DECK", 2: "HAND", 3: "DISCARD", 4: "ACTIVE", 5: "BENCH", 6: "PRIZE",
               7: "STADIUM", 8: "ENERGY", 9: "TOOL", 10: "PRE_EVOLUTION", 11: "PLAYER", 12: "LOOKING"}
_OPTION_NAMES = {0: "NUMBER", 1: "YES", 2: "NO", 3: "CARD", 4: "TOOL_CARD", 5: "ENERGY_CARD",
                 6: "ENERGY", 7: "PLAY", 8: "ATTACH", 9: "EVOLVE", 10: "ABILITY", 11: "DISCARD",
                 12: "RETREAT", 13: "ATTACK", 14: "END", 15: "SKILL", 16: "SPECIAL_CONDITION"}
_CONTEXT_NAMES = {0: "MAIN", 1: "SETUP_ACTIVE_POKEMON", 2: "SETUP_BENCH_POKEMON", 3: "SWITCH",
                  4: "TO_ACTIVE", 5: "TO_BENCH", 6: "TO_FIELD", 7: "TO_HAND", 8: "DISCARD",
                  9: "TO_DECK", 10: "TO_DECK_BOTTOM", 11: "TO_PRIZE", 12: "NOT_MOVE",
                  13: "DAMAGE_COUNTER", 14: "DAMAGE_COUNTER_ANY", 15: "DAMAGE",
                  16: "REMOVE_DAMAGE_COUNTER", 17: "HEAL", 18: "EVOLVES_FROM", 19: "EVOLVES_TO",
                  20: "DEVOLVE", 21: "ATTACH_FROM", 22: "ATTACH_TO", 23: "DETACH_FROM", 24: "LOOK",
                  25: "EFFECT_TARGET", 41: "IS_FIRST", 42: "MULLIGAN", 43: "ACTIVATE", 35: "ATTACK"}

# Contexts where the BC model is accurate (holdout top-1/top-3) and the heuristic
# is merely guessing card priorities. MAIN/ATTACK/EVOLVE/ATTACH stay 100% heuristic
# (the model is weak there and the heuristic owns lethal/sequencing).
_SOFT_CONTEXTS = {"TO_HAND", "SWITCH", "TO_ACTIVE", "TO_BENCH", "TO_FIELD",
                  "SETUP_ACTIVE_POKEMON", "SETUP_BENCH_POKEMON"}
# contexts where policy_net holdout top-1 beats the handcrafted prior
_NEURAL_STRONG_CONTEXTS = {"TO_HAND", "TO_ACTIVE", "SETUP_ACTIVE_POKEMON",
                           "SETUP_BENCH_POKEMON", "ACTIVATE", "DISCARD", "SWITCH"}
# Defaults chosen by a vs-base sweep: ML as a near-tie breaker (weight 120,
# tie-band 2000) is the only config that helps locally without overriding
# confident heuristic moves; unrestricted ML (no band) regresses. This keeps the
# agent close to the publicly-proven base (996) while injecting the learned prior.
_ML_WEIGHT = float(os.environ.get("CLAUDE_ML_WEIGHT", "120"))
# ML only re-ranks options whose heuristic score is within this band of the best,
# i.e. genuine near-ties -- never overrides a confident heuristic preference.
_ML_TIEBAND = float(os.environ.get("CLAUDE_ML_TIEBAND", "2000"))
_CARD_RE = re.compile(r"\((\d+)\)")
_ATTACK_RE = re.compile(r"attack=(\d+)")
_TO_RE = re.compile(r"to=([A-Z_]+):(\d+)")


def _enum_name(mapping, value):
    try:
        return mapping.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _mcard_id(card):
    if isinstance(card, dict) and "id" in card:
        try:
            return int(card["id"])
        except (TypeError, ValueError):
            return None
    return None


def _mcard_ids(cards, limit=None):
    if not isinstance(cards, list):
        return []
    ids = [c for c in (_mcard_id(x) for x in cards) if c is not None]
    return ids if limit is None else ids[:limit]


def _turn_bin(turn):
    try:
        v = int(turn)
    except (TypeError, ValueError):
        return "unknown"
    if v <= 1: return "0-1"
    if v <= 3: return "2-3"
    if v <= 6: return "4-6"
    if v <= 10: return "7-10"
    if v <= 20: return "11-20"
    return "21+"


def _count_bucket(value, size=2, cap=4):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return str(min(cap, n // size))


def _get_option_card_id(obs_dict, option):
    area = option.get("area")
    index = option.get("index")
    current = obs_dict.get("current") or {}
    player_index = option.get("playerIndex", current.get("yourIndex"))
    try:
        if area == 1:
            card = (obs_dict.get("select") or {}).get("deck", [])[index]
        elif area == 2:
            card = current["players"][player_index]["hand"][index]
        elif area == 3:
            card = current["players"][player_index]["discard"][index]
        elif area == 4:
            card = current["players"][player_index]["active"][index]
        elif area == 5:
            card = current["players"][player_index]["bench"][index]
        elif area == 12:
            card = current.get("looking", [])[index]
        else:
            card = None
    except Exception:
        return None
    return _mcard_id(card)


def _option_description(obs_dict, i):
    options = (obs_dict.get("select") or {}).get("option") or []
    if not 0 <= i < len(options):
        return f"{i}:out"
    option = options[i]
    parts = [f"{i}:{_enum_name(_OPTION_NAMES, option.get('type'))}"]
    cid = _get_option_card_id(obs_dict, option)
    if cid is None and option.get("type") == 7:
        cid = _get_option_card_id(obs_dict, {"area": 2, "index": option.get("index"),
                                             "playerIndex": (obs_dict.get("current") or {}).get("yourIndex")})
    if cid is not None:
        parts.append(f"{cid}({cid})")
    if "number" in option:
        parts.append(f"num={option.get('number')}")
    if "attackId" in option:
        parts.append(f"attack={option.get('attackId')}")
    if "inPlayArea" in option:
        parts.append(f"to={_enum_name(_AREA_NAMES, option.get('inPlayArea'))}:{option.get('inPlayIndex')}")
    return " ".join(parts)


def _player_features(player):
    return {
        "active": (_mcard_ids(player.get("active"), 1) or [None])[0],
        "bench_count": len(_mcard_ids(player.get("bench"))),
        "hand_count": player.get("handCount"),
    }


def _compact_state(obs_dict):
    current = obs_dict.get("current") or {}
    players = current.get("players") or []
    yi = current.get("yourIndex", 0)
    if not isinstance(yi, int) or len(players) < 2:
        return {}
    oi = 1 - yi
    return {
        "turn": current.get("turn"),
        "turn_action_count": current.get("turnActionCount"),
        "supporter_played": current.get("supporterPlayed"),
        "stadium_played": current.get("stadiumPlayed"),
        "energy_attached": current.get("energyAttached"),
        "me": _player_features(players[yi]),
        "opponent": _player_features(players[oi]),
    }


def _board_key(state):
    me = state.get("me") or {}
    op = state.get("opponent") or {}
    return "|".join([
        f"turn={_turn_bin(state.get('turn'))}",
        f"active={me.get('active')}",
        f"opp_active={op.get('active')}",
        f"bench={_count_bucket(me.get('bench_count'))}",
        f"opp_bench={_count_bucket(op.get('bench_count'))}",
        f"energy={state.get('energy_attached')}",
    ])


def _option_parts(desc):
    head = desc.split(" ", 1)[0]
    otype = head.split(":", 1)[1] if ":" in head else head
    c = _CARD_RE.search(desc); a = _ATTACK_RE.search(desc); t = _TO_RE.search(desc)
    return {"type": otype, "card": c.group(1) if c else "",
            "attack": a.group(1) if a else "", "to_area": t.group(1) if t else ""}


def _bk(value, size=3):
    if not isinstance(value, int):
        return "?"
    return str(min(6, value // size))


def _norm_arch(arch):
    a = (arch or "").lower()
    return "alakazam" if a.startswith("alakazam") else a


# Parity-critical: kept byte-identical with tools/train_ml_policy.option_features_v2.
def _option_features_v2(row, i):
    options = row.get("options") or []
    desc = options[i] if i < len(options) else ""
    parts = _option_parts(desc)
    context = str(row.get("context"))
    archetype = _norm_arch(str(row.get("archetype")))
    st = row.get("state") or {}
    me = st.get("me") or {}; op = st.get("opponent") or {}
    own_active = me.get("active"); opp_active = op.get("active")
    own_bench = _bk(me.get("bench_count")); opp_bench = _bk(op.get("bench_count"))
    own_hand = _bk(me.get("hand_count"), 2); opp_hand = _bk(op.get("hand_count"), 2)
    turn_bucket = _bk(st.get("turn"), 2); turn_action_bucket = _bk(st.get("turn_action_count"), 3)
    option_count_bucket = _bk(row.get("option_count"), 4)
    board_key = str(row.get("board_key") or "")
    energy_attached = str(st.get("energy_attached"))
    supporter_played = str(st.get("supporter_played")); stadium_played = str(st.get("stadium_played"))
    feats = [
        "bias", f"ctx={context}", f"arch={archetype}", f"ctx_type={context}:{parts['type']}",
        f"type={parts['type']}", f"option_count={option_count_bucket}", f"turn={turn_bucket}",
        f"turn_action={turn_action_bucket}", f"energy_attached={energy_attached}",
        f"supporter_played={supporter_played}", f"stadium_played={stadium_played}",
        f"own_active={own_active}", f"opp_active={opp_active}", f"own_bench={own_bench}",
        f"opp_bench={opp_bench}", f"own_hand={own_hand}", f"opp_hand={opp_hand}",
        f"turn_type={turn_bucket}:{parts['type']}", f"energy_type={energy_attached}:{parts['type']}",
    ]
    if board_key:
        feats += [f"board={board_key}", f"board_type={board_key}:{parts['type']}"]
    if parts["card"]:
        feats += [f"card={parts['card']}", f"ctx_card={context}:{parts['card']}",
                  f"arch_card={archetype}:{parts['card']}", f"energy_card={energy_attached}:{parts['card']}"]
        if board_key:
            feats.append(f"board_card={board_key}:{parts['card']}")
    if parts["attack"]:
        feats += [f"attack={parts['attack']}", f"ctx_attack={context}:{parts['attack']}"]
    if parts["to_area"]:
        feats += [f"to_area={parts['to_area']}", f"ctx_to={context}:{parts['to_area']}"]
    return feats




# --------------------------------------------------------------------------- #
# Neural policy net (numpy inference over exported torch weights)
# --------------------------------------------------------------------------- #
class _PolicyNet:
    """Pure-python (stdlib-only) inference over exported weights.

    policy_net.bin layout: '<4i f' header (buckets, dim, hidden, reserved, b2)
    followed by float32 blocks: emb[buckets*dim], W1[hidden*dim], b1[hidden],
    W2[hidden]. No numpy dependency — the Kaggle agent sandbox is not
    guaranteed to ship it, and the packaged x86 sanity check caught exactly
    that failure before submission.
    """

    def __init__(self, path):
        import array as _ar
        import struct as _st
        with open(path, "rb") as fh:
            buckets, dim, hidden, _res, b2 = _st.unpack("<4i f", fh.read(20))
            def read_block(n):
                a = _ar.array("f")
                a.fromfile(fh, n)
                return a
            self.emb = read_block(buckets * dim)
            self.W1 = read_block(hidden * dim)
            self.b1 = read_block(hidden)
            self.W2 = read_block(hidden)
        self.b2 = b2
        self.buckets = buckets
        self.dim = dim
        self.hidden = hidden
        import hashlib as _hl
        self._hl = _hl
        self._cache = {}

    def _bucket(self, f):
        b = self._cache.get(f)
        if b is None:
            b = int(self._hl.sha1(f.encode()).hexdigest()[:10], 16) % self.buckets
            if len(self._cache) < 200000:
                self._cache[f] = b
        return b

    def score_option(self, row, i):
        feats = _option_features_v2(row, i)
        dim = self.dim
        emb = self.emb
        v = [0.0] * dim
        for f in feats:
            base = self._bucket(f) * dim
            for k in range(dim):
                v[k] += emb[base + k]
        for k in range(dim):
            if v[k] < 0.0:
                v[k] = 0.0
        W1 = self.W1
        b1 = self.b1
        W2 = self.W2
        out = self.b2
        for j in range(self.hidden):
            acc = b1[j]
            base = j * dim
            for k in range(dim):
                acc += W1[base + k] * v[k]
            if acc > 0.0:
                out += W2[j] * acc
        return out


def _load_policy_net():
    for path in ("policy_net.bin", "/kaggle_simulations/agent/policy_net.bin"):
        if os.path.exists(path):
            try:
                return _PolicyNet(path)
            except Exception:
                return None
    return None


POLICY_NET = _load_policy_net()
_CTX_NAME_BY_ENUM = dict(_CONTEXT_NAMES)


def neural_scores(obs_dict):
    """Per-option neural scores for the CURRENT decision, or None."""
    if POLICY_NET is None:
        return None
    try:
        sel = obs_dict.get("select") or {}
        options = sel.get("option") or []
        if not options:
            return None
        state = _compact_state(obs_dict)
        row = {
            "context": _enum_name(_CONTEXT_NAMES, sel.get("context")),
            "archetype": "grimmsnarl",
            "options": [_option_description(obs_dict, i) for i in range(len(options))],
            "option_count": len(options),
            "state": state,
            "board_key": _board_key(state),
        }
        return [POLICY_NET.score_option(row, i) for i in range(len(options))]
    except Exception:
        return None



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
_NEURAL_STRONG_CONTEXTS = {"TO_HAND", "TO_ACTIVE", "SETUP_ACTIVE_POKEMON",
                           "SETUP_BENCH_POKEMON", "ACTIVATE", "DISCARD", "SWITCH"}
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
            out.append(float(P.prior_score(obs, opt)))
        except Exception:
            out.append(0.0)
    return out


def prior_choice_raw(obs_dict: dict, obs: Observation) -> list[int]:
    try:
        picks = P.prior_choice(obs)
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
        scores = prior_scores(so)
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
    prior_order = sorted(range(n), key=lambda i: scores[i], reverse=True)
    ns = neural_scores(raw_obs)
    half = max(2, SEARCH_TOP_OPTIONS // 2)
    if ns is not None and len(ns) == n:
        neural_order = sorted(range(n), key=lambda i: ns[i], reverse=True)
        seen = []
        for i in prior_order[:half] + neural_order[:half]:
            if i not in seen:
                seen.append(i)
        candidates = seen[:SEARCH_TOP_OPTIONS]
    else:
        candidates = prior_order[:SEARCH_TOP_OPTIONS]
    order = prior_order
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
    # v156 LETHAL-ONLY mode: three public probes showed marginal search
    # overrides are net noise vs the diverse pool (twins never catch it —
    # both sides in-family). Search now overrides the prior ONLY when it
    # finds a near-certain winning line (its one proven superpower).
    if best != prior_pick:
        if evaluated[best] < 0.90:
            return [prior_pick] if prior_pick in evaluated else None
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
        try:
            sel = obs.select
            ctx_name = _enum_name(_CONTEXT_NAMES, obs_dict.get("select", {}).get("context"))
            if (sel.minCount == 1 and sel.maxCount == 1
                    and ctx_name in _NEURAL_STRONG_CONTEXTS):
                ns = neural_scores(obs_dict)
                if ns is not None and len(ns) == len(sel.option):
                    return [max(range(len(ns)), key=lambda i: ns[i])]
        except Exception:
            pass
        return prior_choice_raw(obs_dict, obs)
    except Exception:
        try:
            n = len(obs.select.option)
            mn = max(0, min(obs.select.minCount, obs.select.maxCount, n))
            return list(range(mn))
        except Exception:
            return []
