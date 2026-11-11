"""Board-state value features + scorer, shared by trainer and agent.

value_features(obs) -> list[str]: deck-agnostic board features from the
acting player's perspective. Used with a logistic model P(win).
"""
from __future__ import annotations


def _b(v, size, cap=6):
    if not isinstance(v, int):
        return "?"
    return str(min(cap, max(0, v) // size))


def value_features(obs: dict) -> list[str]:
    cur = obs.get("current") or {}
    players = cur.get("players") or [{}, {}]
    yi = cur.get("yourIndex") or 0
    me = players[yi] if yi < len(players) else {}
    op = players[1 - yi] if 1 - yi < len(players) else {}

    def side(p):
        field = []
        for zone in ("active", "bench"):
            for c in p.get(zone) or []:
                if c:
                    field.append(c)
        n_energy = sum(len(c.get("energies") or []) for c in field)
        powered = sum(1 for c in field if len(c.get("energies") or []) >= 2)
        hp_total = sum(c.get("hp") or 0 for c in field)
        return field, n_energy, powered, hp_total

    mf, men, mpow, mhp = side(me)
    of, oen, opow, ohp = side(op)
    my_taken = 6 - len(me.get("prize") or [])
    op_taken = 6 - len(op.get("prize") or [])
    ma = (me.get("active") or [None])
    oa = (op.get("active") or [None])
    ma = ma[0] if ma else None
    oa = oa[0] if oa else None

    f = [
        "b",
        f"pd={max(-4, min(4, my_taken - op_taken))}",
        f"mt={my_taken}", f"ot={op_taken}",
        f"turn={_b(cur.get('turn'), 3)}",
        f"mf={len(mf)}", f"of={len(of)}",
        f"me={_b(men, 2)}", f"oe={_b(oen, 2)}",
        f"mpow={min(3, mpow)}", f"opow={min(3, opow)}",
        f"mhp={_b(mhp, 120)}", f"ohp={_b(ohp, 120)}",
        f"mh={_b(me.get('handCount'), 2)}", f"oh={_b(op.get('handCount'), 2)}",
        f"mdk={_b(me.get('deckCount'), 8)}",
        f"maid={(ma or {}).get('id')}",
        f"oaid={(oa or {}).get('id')}",
        f"mahp={_b((ma or {}).get('hp'), 60)}",
        f"oahp={_b((oa or {}).get('hp'), 60)}",
        f"pd_t={max(-4, min(4, my_taken - op_taken))}:{_b(cur.get('turn'), 3)}",
    ]
    return f


def value_score(weights: dict, obs: dict) -> float:
    """Logistic score in (-1, 1): 2*sigmoid(w.f)-1, from acting player's view."""
    import math
    z = sum(weights.get(f, 0.0) for f in value_features(obs))
    return 2.0 / (1.0 + math.exp(-z)) - 1.0
