#!/usr/bin/env python3
"""Package the agent into submission.tar.gz and validate it in Docker (linux/amd64).

Usage:
  python3 tools/package.py --name my-submission [--skip-docker]

Produces submissions/<name>.tar.gz (contents at archive root: main.py, deck.csv,
policy.json, meta_decks.json, features.py, cg/).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent"
ENGINE_CG = ROOT / "engine" / "cg"

FILES = ["main.py", "features.py", "deck.csv", "policy.json", "meta_decks.json",
         "attacks.json", "cards.json", "policy_all.json", "value.json", "values.py"]
CG_FILES = ["__init__.py", "api.py", "game.py", "sim.py", "utils.py",
            "libcg.so", "libcg-arm64.so", "libcg.dylib", "cg.dll"]

VALIDATE_SCRIPT = r"""
import json, random, sys, time
import os
# replicate kaggle_environments loading: agent at /kaggle_simulations/agent,
# source exec'd WITHOUT __file__, cwd elsewhere
sys.path.insert(0, "/kaggle_simulations/agent")
os.chdir("/tmp")
random.seed(5)
src = open("/kaggle_simulations/agent/main.py").read()
env = {}
exec(compile(src, "<agent>", "exec"), env)
agent = env["agent"]
from cg.game import battle_start, battle_select, battle_finish

deck = [int(x) for x in open("/kaggle_simulations/agent/deck.csv").read().split() if x.strip()][:60]
wins = 0
t_tot = 0.0
for g in range(3):
    obs, sd = battle_start(list(deck), list(deck))
    assert sd.errorType == 0, f"battle start error {sd.errorType}"
    steps = 0
    result = None
    while steps < 3000:
        cur = obs.get("current")
        if cur is not None and cur.get("result", -1) != -1:
            result = cur["result"]; break
        sel = obs.get("select")
        if sel is None: break
        p = cur["yourIndex"] if cur else 0
        t0 = time.time()
        if p == 0:
            act = agent(obs)
        else:
            n = len(sel["option"]); k = min(sel["maxCount"], n); lo = sel["minCount"]
            cnt = random.randint(lo, k) if lo < k else k
            act = random.sample(range(n), cnt)
        t_tot += time.time() - t0
        n = len(sel["option"])
        ok = (isinstance(act, list) and all(isinstance(i, int) and 0 <= i < n for i in act)
              and len(set(act)) == len(act) and sel["minCount"] <= len(act) <= sel["maxCount"])
        assert ok, f"ILLEGAL ACTION game{g} step{steps}: {act} (n={n}, min={sel['minCount']}, max={sel['maxCount']})"
        obs = battle_select(act)
        steps += 1
    battle_finish()
    if result == 0: wins += 1
    print(f"game{g}: result={result} steps={steps}")
print(f"VALIDATION OK wins={wins}/3 total_agent_time={t_tot:.1f}s")
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--agent-dir", type=Path, default=AGENT)
    ap.add_argument("--skip-docker", action="store_true")
    ap.add_argument("--all-files", action="store_true",
                    help="package every data/code file in the agent dir")
    args = ap.parse_args()

    out_dir = ROOT / "submissions"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"{args.name}.tar.gz"

    with tarfile.open(out, "w:gz") as tar:
        if args.all_files:
            names = [q.name for q in args.agent_dir.iterdir()
                     if q.is_file() and q.suffix in (".py", ".json", ".bin", ".csv")]
        else:
            names = FILES
        for f in names:
            p = args.agent_dir / f
            if not p.exists():
                print(f"WARN missing {p}")
                continue
            tar.add(p, arcname=f)
        for f in CG_FILES:
            p = ENGINE_CG / f
            if p.exists():
                tar.add(p, arcname=f"cg/{f}")
    size = out.stat().st_size
    print(f"wrote {out} ({size/1e6:.2f} MB)")

    if args.skip_docker:
        return 0

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "validate.py").write_text(VALIDATE_SCRIPT)
        # extract into temp dir to simulate Kaggle's unpacking
        sub = tdp / "sub"
        sub.mkdir()
        with tarfile.open(out) as tar:
            tar.extractall(sub)
        res = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/amd64",
             "-v", f"{tdp}:/work", "-v", f"{sub}:/kaggle_simulations/agent",
             "python:3.11-slim", "python3", "/work/validate.py"],
            text=True, capture_output=True, timeout=1200)
        print(res.stdout[-3000:])
        if res.returncode != 0:
            print("DOCKER VALIDATION FAILED", res.stderr[-3000:])
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
