#!/usr/bin/env python3
"""Local match runner: pit two submission dirs against each other.

Each agent dir must contain main.py (defining agent(obs_dict) -> list[int])
and deck.csv. Agents share the engine's cg module (pre-imported); relative
asset reads work because we chdir into the agent's dir around import/calls.

Usage:
  python3 tools/league.py A_DIR B_DIR --games 40 [--procs 8] [--json out.json]

Result: prints "A_wins,B_wins,draws,errors" summary; per-game rows to stdout.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENGINE = ROOT / "engine"


def load_agent(agent_dir: Path, name: str):
    """Import an agent's main.py with cwd set to its dir."""
    sys.path.insert(0, str(ENGINE))  # shared cg package
    import cg.api  # noqa: F401  (ensure single shared engine instance)
    sys.path.insert(0, str(agent_dir))  # agent-local sibling modules
    old = os.getcwd()
    os.chdir(agent_dir)
    try:
        spec = importlib.util.spec_from_file_location(name, agent_dir / "main.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    finally:
        os.chdir(old)
    deck = [int(x) for x in (agent_dir / "deck.csv").read_text().split() if x.strip()][:60]
    return mod, deck


def play_game(mods, decks, dirs, order, max_steps=4000):
    """order: (a_player_index_of_A). Returns (winner_agent 'A'/'B'/'draw'/'errA'/'errB', steps, times)."""
    from cg.game import battle_start, battle_select, battle_finish

    if order == 0:
        deck0, deck1 = decks[0], decks[1]
        who = {0: "A", 1: "B"}
    else:
        deck0, deck1 = decks[1], decks[0]
        who = {0: "B", 1: "A"}
    obs, sd = battle_start(list(deck0), list(deck1))
    if obs is None:
        return ("start_error", 0, {})
    times = {"A": 0.0, "B": 0.0}
    steps = 0
    result = -1
    try:
        while steps < max_steps:
            cur = obs.get("current")
            if cur is not None and cur.get("result", -1) != -1:
                result = cur["result"]
                break
            sel = obs.get("select")
            if sel is None:
                return ("no_select", steps, times)
            p = cur["yourIndex"] if cur else 0
            tag = who[p]
            mod = mods[0] if tag == "A" else mods[1]
            adir = dirs[0] if tag == "A" else dirs[1]
            old = os.getcwd()
            os.chdir(adir)
            t0 = time.time()
            try:
                action = mod.agent(obs)
            except Exception:
                traceback.print_exc()
                return ("err" + tag, steps, times)
            finally:
                times[tag] += time.time() - t0
                os.chdir(old)
            # legality guard mirrors Kaggle: invalid action -> immediate loss
            n = len(sel["option"])
            ok = (isinstance(action, list) and all(isinstance(i, int) and 0 <= i < n for i in action)
                  and len(set(action)) == len(action)
                  and sel["minCount"] <= len(action) <= sel["maxCount"])
            if not ok:
                return ("inv" + tag, steps, times)
            obs = battle_select(action)
            steps += 1
    finally:
        try:
            battle_finish()
        except Exception:
            pass
    if result == -1:
        return ("draw", steps, times)
    if result == 2:
        return ("draw", steps, times)
    return (who[result], steps, times)


def worker(args_tuple):
    a_dir, b_dir, games, seed, quiet = args_tuple
    random.seed(seed)
    mods_decks = {}
    mod_a, deck_a = load_agent(Path(a_dir), f"agentA_{seed}")
    mod_b, deck_b = load_agent(Path(b_dir), f"agentB_{seed}")
    rows = []
    for g in range(games):
        order = g % 2
        res, steps, times = play_game((mod_a, mod_b), (deck_a, deck_b), (a_dir, b_dir), order)
        rows.append({"game": g, "order": order, "result": res, "steps": steps,
                     "tA": round(times.get("A", 0), 2), "tB": round(times.get("B", 0), 2)})
        if not quiet:
            print(f"seed{seed} g{g} order{order} -> {res} ({steps} steps, A {times.get('A',0):.1f}s B {times.get('B',0):.1f}s)", flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a_dir")
    ap.add_argument("b_dir")
    ap.add_argument("--games", type=int, default=40)
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    a_dir = str(Path(args.a_dir).resolve())
    b_dir = str(Path(args.b_dir).resolve())

    procs = min(args.procs, args.games)
    per = [args.games // procs + (1 if i < args.games % procs else 0) for i in range(procs)]
    tasks = [(a_dir, b_dir, per[i], args.seed + i * 1000, args.quiet) for i in range(procs) if per[i] > 0]

    if len(tasks) == 1:
        all_rows = worker(tasks[0])
    else:
        import multiprocessing as mp
        ctx = mp.get_context("spawn")
        with ctx.Pool(len(tasks)) as pool:
            chunks = pool.map(worker, tasks)
        all_rows = [r for c in chunks for r in c]

    wins = {"A": 0, "B": 0, "draw": 0, "other": 0}
    for r in all_rows:
        res = r["result"]
        if res in ("A", "B", "draw"):
            wins[res] += 1
        elif res in ("errA", "invA"):
            wins["B"] += 1
            wins["other"] += 1
        elif res in ("errB", "invB"):
            wins["A"] += 1
            wins["other"] += 1
        else:
            wins["other"] += 1
    n_dec = wins["A"] + wins["B"]
    wr = wins["A"] / n_dec if n_dec else 0.5
    print(f"\nRESULT A={wins['A']} B={wins['B']} draw={wins['draw']} anomalies={wins['other']} "
          f"A_winrate={wr:.3f} n={len(all_rows)}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({"a": a_dir, "b": b_dir, "summary": wins,
                                         "a_winrate": wr, "rows": all_rows}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
