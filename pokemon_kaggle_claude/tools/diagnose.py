#!/usr/bin/env python3
"""Play N games vs an opponent dir, log loss reasons and key stats per game."""
import sys, os, time, random, importlib.util, json
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'engine'))

def load(dirpath, name):
    dirpath = str(Path(dirpath).resolve())
    sys.path.insert(0, dirpath)
    old = os.getcwd(); os.chdir(dirpath)
    try:
        spec = importlib.util.spec_from_file_location(name, dirpath + '/main.py')
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    finally:
        os.chdir(old)
    deck = [int(x) for x in open(dirpath + '/deck.csv').read().split() if x.strip()][:60]
    return mod, deck, dirpath

def main():
    a_dir, b_dir, games = sys.argv[1], sys.argv[2], int(sys.argv[3])
    A, deckA, pa = load(a_dir, 'diagA')
    B, deckB, pb = load(b_dir, 'diagB')
    from cg.game import battle_start, battle_select, battle_finish
    random.seed(11)
    stats = []
    for g in range(games):
        order = g % 2
        d0, d1 = (deckA, deckB) if order == 0 else (deckB, deckA)
        us = 0 if order == 0 else 1
        obs, sd = battle_start(list(d0), list(d1))
        steps = 0; result = None; reason = None
        first_ko_by = None
        while steps < 4000 and obs is not None:
            cur = obs.get('current')
            if cur is not None and cur.get('result', -1) != -1:
                result = cur['result']
                break
            sel = obs.get('select')
            if sel is None: break
            # detect result logs
            for lg in obs.get('logs') or []:
                if lg.get('type') == 23:
                    reason = lg.get('reason')
                if lg.get('type') == 17 and first_ko_by is None:  # KNOCK_OUT?
                    first_ko_by = 'unk'
            p = cur['yourIndex'] if cur else 0
            mod = A if p == us else B
            mdir = pa if p == us else pb
            old = os.getcwd(); os.chdir(mdir)
            try: act = mod.agent(obs)
            except Exception as e:
                result = 1 - p; reason = f'crash{p}'; break
            finally: os.chdir(old)
            obs = battle_select(act)
            steps += 1
        # final board
        cur = (obs or {}).get('current') or {}
        players = cur.get('players') or [{}, {}]
        me = players[us] if us < len(players) else {}
        op = players[1 - us] if 1 - us < len(players) else {}
        row = {
            'game': g, 'we_won': result == us, 'result': result, 'reason': reason,
            'steps': steps,
            'our_prizes_left': len(me.get('prize') or []),
            'opp_prizes_left': len(op.get('prize') or []),
            'our_deck_left': me.get('deckCount'), 'opp_deck_left': op.get('deckCount'),
        }
        stats.append(row)
        print(json.dumps(row), flush=True)
        battle_finish()
    won = sum(1 for s in stats if s['we_won'])
    print(f"SUMMARY: {won}/{len(stats)} wins", flush=True)
    from collections import Counter
    print('loss profiles (our_prz_left, opp_prz_left, reason):',
          Counter((s['our_prizes_left'], s['opp_prizes_left'], s['reason'])
                  for s in stats if not s['we_won']).most_common(10))

main()
