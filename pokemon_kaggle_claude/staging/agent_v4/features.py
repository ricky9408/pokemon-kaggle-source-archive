"""Featurizer shared by offline trainer and play-time agent.

Works directly on the raw observation dict (as passed to agent()) so
offline/online parity is by construction. All enum values are used as ints.
No hidden information is used (opponent hand contents, facedown cards, deck
order) — only what a live agent legally sees.
"""
from __future__ import annotations

# AreaType ints (see cg/api.py): DECK=0? verify — we read from obs semantics only.
# We resolve option card ids via explicit zone lookups keyed by the raw ints.

AREA_DECK = 1
AREA_HAND = 2
AREA_DISCARD = 3
AREA_ACTIVE = 4
AREA_BENCH = 5
AREA_PRIZE = 6
AREA_STADIUM = 7
AREA_LOOKING = 12


def _card_id(card) -> int | None:
    if isinstance(card, dict):
        cid = card.get("id")
        if isinstance(cid, int):
            return cid
    return None


OPT_PLAY = 7


def option_card_id(obs: dict, opt: dict) -> int | None:
    """Resolve the card a CARD/PLAY/ATTACH/EVOLVE/ABILITY option refers to."""
    area = opt.get("area")
    index = opt.get("index")
    pidx = opt.get("playerIndex")
    sel = obs.get("select") or {}
    cur = obs.get("current") or {}
    players = cur.get("players") or []
    yi = cur.get("yourIndex") or 0
    if opt.get("cardId") is not None:
        return opt["cardId"]
    if area is None and opt.get("type") == OPT_PLAY:
        area = AREA_HAND  # PLAY options carry only a hand index
    if pidx is None:
        pidx = yi
    if area is None or index is None:
        return None
    try:
        if area == AREA_DECK:
            deck = sel.get("deck")
            return _card_id(deck[index]) if deck else None
        if area == AREA_LOOKING:
            looking = cur.get("looking")
            return _card_id(looking[index]) if looking else None
        if area == AREA_STADIUM:
            st = cur.get("stadium")
            return _card_id(st[index]) if st else None
        if pidx >= len(players):
            return None
        player = players[pidx]
        zone = {AREA_HAND: "hand", AREA_DISCARD: "discard",
                AREA_ACTIVE: "active", AREA_BENCH: "bench",
                AREA_PRIZE: "prize"}.get(area)
        if zone is None:
            return None
        cards = player.get(zone) or []
        return _card_id(cards[index]) if index < len(cards) else None
    except (IndexError, TypeError):
        return None


def target_card(obs: dict, opt: dict):
    """For ATTACH-style options: the in-play target Pokemon dict."""
    area = opt.get("inPlayArea")
    index = opt.get("inPlayIndex")
    if area is None or index is None:
        return None
    cur = obs.get("current") or {}
    players = cur.get("players") or []
    yi = cur.get("yourIndex") or 0
    pidx = opt.get("playerIndex")
    pidx = pidx if pidx is not None else yi
    if pidx >= len(players):
        return None
    zone = {AREA_ACTIVE: "active", AREA_BENCH: "bench"}.get(area)
    if zone is None:
        return None
    cards = players[pidx].get(zone) or []
    try:
        return cards[index] if index < len(cards) else None
    except (IndexError, TypeError):
        return None


def _bucket(v, size, cap=6) -> str:
    if not isinstance(v, int):
        return "?"
    return str(min(cap, v // size))


def _energy_count(card) -> int:
    if not isinstance(card, dict):
        return 0
    return len(card.get("energies") or [])


def _dmg_bucket(card) -> str:
    if not isinstance(card, dict):
        return "?"
    hp = card.get("hp")
    max_hp = card.get("maxHp")
    if not isinstance(hp, int) or not isinstance(max_hp, int) or max_hp <= 0:
        return "?"
    return _bucket(max_hp - hp, 40)


def option_features(obs: dict, i: int) -> list[str]:
    sel = obs.get("select") or {}
    cur = obs.get("current") or {}
    opt = (sel.get("option") or [])[i]
    ctx = sel.get("context")
    typ = opt.get("type")
    players = cur.get("players") or []
    yi = cur.get("yourIndex") or 0
    me = players[yi] if yi < len(players) else {}
    op = players[1 - yi] if 1 - yi < len(players) else {}

    my_active = (me.get("active") or [None])[0]
    op_active = (op.get("active") or [None])[0]
    my_active_id = _card_id(my_active)
    op_active_id = _card_id(op_active)
    my_bench_n = len([c for c in (me.get("bench") or []) if c])
    op_bench_n = len([c for c in (op.get("bench") or []) if c])
    my_prize_n = len(me.get("prize") or [])
    op_prize_n = len(op.get("prize") or [])
    turn_b = _bucket(cur.get("turn"), 2)
    ea = 1 if cur.get("energyAttached") else 0
    sp = 1 if cur.get("supporterPlayed") else 0

    cid = option_card_id(obs, opt)
    atk = opt.get("attackId")
    tgt = target_card(obs, opt)
    tgt_id = _card_id(tgt)
    own_opt = opt.get("playerIndex") in (None, yi)

    stadium = (cur.get("stadium") or [None])
    std_id = (stadium[0] or {}).get("id") if stadium else None
    f = [
        "b",
        f"c={ctx}",
        f"t={typ}",
        f"ct={ctx}:{typ}",
        f"turn={turn_b}",
        f"tt={turn_b}:{typ}",
        f"ea={ea}", f"sp={sp}",
        f"eat={ea}:{typ}",
        f"n={_bucket(len(sel.get('option') or []), 4)}",
        f"mh={_bucket(me.get('handCount'), 2)}",
        f"oh={_bucket(op.get('handCount'), 2)}",
        f"mb={my_bench_n}", f"ob={op_bench_n}",
        f"mp={my_prize_n}", f"op={op_prize_n}",
        f"ma={my_active_id}", f"oa={op_active_id}",
        f"mae={_bucket(_energy_count(my_active), 1, 4)}",
        f"mad={_dmg_bucket(my_active)}",
        f"oad={_dmg_bucket(op_active)}",
    ]
    if cid is not None:
        side = "s" if own_opt else "x"
        f += [
            f"k={side}{cid}",
            f"ck={ctx}:{side}{cid}",
            f"tk={turn_b}:{side}{cid}",
            f"ek={ea}:{side}{cid}",
            f"mak={my_active_id}:{side}{cid}",
        ]
        # CARD options pointing at an in-play Pokemon: enrich with its state
        # (attach targets, damage targets, switch targets)
        area = opt.get("area")
        if area in (AREA_ACTIVE, AREA_BENCH):
            ref = None
            pidx = opt.get("playerIndex")
            pidx = pidx if pidx is not None else yi
            if pidx < len(players):
                zone = players[pidx].get("active" if area == AREA_ACTIVE else "bench") or []
                idx = opt.get("index")
                if isinstance(idx, int) and idx < len(zone):
                    ref = zone[idx]
            if isinstance(ref, dict):
                ken = _bucket(_energy_count(ref), 1, 4)
                f += [
                    f"ke={side}{cid}:{ken}",
                    f"cke={ctx}:{side}{cid}:{ken}",
                    f"kd={side}{cid}:{_dmg_bucket(ref)}",
                    f"ka={ctx}:{side}{cid}:{1 if area == AREA_ACTIVE else 0}",
                ]
    if atk is not None:
        f += [
            f"a={atk}",
            f"ca={ctx}:{atk}",
            f"maa={my_active_id}:{atk}",
            f"oaa={op_active_id}:{atk}",
            f"pa={op_prize_n}:{atk}",
        ]
    if tgt_id is not None:
        f += [
            f"g={tgt_id}",
            f"ge={tgt_id}:{_bucket(_energy_count(tgt), 1, 4)}",
            f"gk={tgt_id}:{cid}" if cid is not None else f"g2={tgt_id}",
            f"gd={tgt_id}:{_dmg_bucket(tgt)}",
        ]
    if cid is not None and opt.get("type") == OPT_PLAY:
        f.append(f"kstd={cid}:{std_id}")
    if opt.get("number") is not None:
        f.append(f"num={opt['number']}")
    if opt.get("specialConditionType") is not None:
        f.append(f"scond={opt['specialConditionType']}")
    return f


def score_option(weights: dict, obs: dict, i: int) -> float:
    return sum(weights.get(feat, 0.0) for feat in option_features(obs, i))
