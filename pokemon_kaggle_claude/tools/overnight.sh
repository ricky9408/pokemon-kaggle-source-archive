#!/bin/bash
# Overnight experiment queue — sequential league matches with real sample sizes
cd "$(dirname "$0")/.."
PREV=../pokemoncard_kaggle/agents

# wait for any running league to finish
while pgrep -f "tools/league.py" > /dev/null; do sleep 30; done

echo "=== Q1: search A/B + mirror: agent vs agent_bc n=60 ==="
python3 tools/league.py agent baselines/agent_bc --games 60 --procs 8 --quiet --json runs/q1_search_ab.json > runs/q1_search_ab.log 2>&1
tail -1 runs/q1_search_ab.log

echo "=== Q2: agent_bc vs v129 n=200 (fast) ==="
python3 tools/league.py baselines/agent_bc $PREV/v129_codex_archaludon_cinderace_axis --games 200 --procs 8 --quiet --json runs/q2_bc_v129.json > runs/q2_bc_v129.log 2>&1
tail -1 runs/q2_bc_v129.log

echo "=== Q3: policy A/B winners vs full n=200 ==="
python3 tools/league.py baselines/agent_bc_winners baselines/agent_bc --games 200 --procs 8 --quiet --json runs/q3_policy_ab.json > runs/q3_policy_ab.log 2>&1
tail -1 runs/q3_policy_ab.log

echo "=== Q4: agent vs v141 (1012 pre-shift) n=40 ==="
python3 tools/league.py agent $PREV/v141_codex_arch_healthy_icecream_guard --games 40 --procs 8 --quiet --json runs/q4_v141.json > runs/q4_v141.log 2>&1
tail -1 runs/q4_v141.log

echo "=== OVERNIGHT QUEUE DONE ==="
