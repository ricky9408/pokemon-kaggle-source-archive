#!/usr/bin/env python3
"""Evaluate candidates against a diverse non-overlapping local holdout set.

This is intentionally different from replay-pool gauntlets. The goal is not to
estimate the current top-10 board directly; it is to create a generalization
signal that can be backtested against public scores. Default opponents are old
or weak local agents, plus deterministic epsilon-random wrappers that perturb
their policies. Submitted/scored candidate aliases are excluded from the default
opponent set.

Run in the linux/amd64 simulator environment:

    docker run -i --rm --platform linux/amd64 \
      -v "$PWD:/work" -w /work python:3.11-slim \
      python tools/heldout_agent_gauntlet.py \
        --candidate agents/v39_alakazam_denpa --candidate agents/v4 \
        --games 2 --max-opponents 12 --quiet
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local_battle import load_agent, run_games  # noqa: E402


@dataclass(frozen=True)
class OpponentSpec:
    label: str
    path: Path
    weight: float
    reason: str
    epsilon: float = 0.0


DEFAULT_EXCLUDED_ALIASES = {
    "v1",
    "v3",
    "v4",
    "v5",
    "v20",
    "v21",
    "v27",
    "v35",
    "v36",
    "v39",
    "v48",
    "v77",
    "v90",
}


DEFAULT_OPPONENTS = [
    OpponentSpec("old-v2", Path("agents/v2"), 1.00, "old baseline, non-submitted"),
    OpponentSpec("old-v6", Path("agents/v6"), 1.00, "old baseline, non-submitted"),
    OpponentSpec("old-v7-three-line", Path("agents/v7_three_line"), 1.05, "old three-line Crustle branch"),
    OpponentSpec("old-v9-cap2-spiky", Path("agents/v9_cap2_spiky"), 1.05, "old cap2/spiky branch"),
    OpponentSpec("mizotake-v10", Path("agents/v10_mizotake_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("mizotake-v11", Path("agents/v11_mizotake_v4"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("mm1989-v12", Path("agents/v12_mm1989_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("brian-v13", Path("agents/v13_brian_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("strayuru-v14", Path("agents/v14_strayuru_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("zakopuro-v15", Path("agents/v15_zakopuro_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("takuyay-v16", Path("agents/v16_takuyay_v2"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("strayuru-v17", Path("agents/v17_strayuru_v4"), 1.10, "old public-inspired non-submitted branch"),
    OpponentSpec("strayuru-hammerfast-v18", Path("agents/v18_strayuru_hammerfast"), 1.10, "old hammer-fast branch"),
    OpponentSpec("hammer-early-v19", Path("agents/v19_hammer_early"), 1.10, "old hammer timing branch"),
    OpponentSpec("dwebble-active-v26", Path("agents/v26_dwebble_active"), 1.00, "old active-Dwebble branch"),
    OpponentSpec("iono-lightning-v29", Path("agents/v29_iono_lightning"), 1.25, "failed Lightning reproduction, useful tail pressure"),
    OpponentSpec("iono-policy-v30", Path("agents/v30_iono_policy"), 1.25, "failed Lightning policy reproduction, useful tail pressure"),
    OpponentSpec("festival-v42", Path("agents/v42_hibi_festival"), 1.20, "Festival tail, non-overlapping submitted candidates"),
    OpponentSpec("festival-seq-v44", Path("agents/v44_hibi_festival_seq"), 1.20, "Festival sequence tail"),
    OpponentSpec("daitou-alakazam-v43", Path("agents/v43_daitou_alakazam"), 1.25, "non-submitted Alakazam tail"),
    OpponentSpec("donguk-nighttime-v58", Path("agents/v58_donguk_nighttime"), 1.25, "Nighttime Mine tail"),
    OpponentSpec("mega-lucario-v67", Path("agents/v67_mega_lucario_praxel"), 1.35, "rejected Mega Lucario mimic, still a hard-counter proxy"),
    OpponentSpec("mega-lucario-v70", Path("agents/v70_mega_lucario_meta_current"), 1.35, "rejected current Mega Lucario mimic, still a hard-counter proxy"),
    OpponentSpec("rocket-mewtwo-v80", Path("agents/v80_rocket_mewtwo_spidops_v50policy"), 1.20, "Rocket Mewtwo tail"),
    OpponentSpec("mutated-v10-eps15", Path("agents/v10_mizotake_v2"), 0.85, "epsilon-randomized old bot", epsilon=0.15),
    OpponentSpec("mutated-v17-eps15", Path("agents/v17_strayuru_v4"), 0.85, "epsilon-randomized old bot", epsilon=0.15),
    OpponentSpec("mutated-v43-eps10", Path("agents/v43_daitou_alakazam"), 0.90, "epsilon-randomized Alakazam bot", epsilon=0.10),
    OpponentSpec("mutated-v67-eps10", Path("agents/v67_mega_lucario_praxel"), 0.90, "epsilon-randomized Mega Lucario bot", epsilon=0.10),
]


def alias_from_path(path: Path) -> str | None:
    name = path.name.lower()
    if name == "v4":
        return "v4"
    if name.startswith("v") and len(name) > 1 and name[1].isdigit():
        number = []
        for char in name[1:]:
            if char.isdigit():
                number.append(char)
            else:
                break
        return "v" + "".join(number)
    return None


def parse_opponent(raw: str) -> OpponentSpec:
    parts = raw.split(":", 3)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError("opponent must be label:path[:weight[:epsilon]]")
    label = parts[0]
    path = Path(parts[1])
    try:
        weight = float(parts[2]) if len(parts) >= 3 and parts[2] else 1.0
        epsilon = float(parts[3]) if len(parts) >= 4 and parts[3] else 0.0
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return OpponentSpec(label=label, path=path, weight=weight, reason="cli", epsilon=epsilon)


def valid_random_action(obs: dict, rng: random.Random) -> list[int] | None:
    select = obs.get("select") or {}
    options = select.get("option") or []
    if not options:
        return None
    try:
        minimum = int(select.get("minCount", 1))
        maximum = int(select.get("maxCount", len(options)))
    except (TypeError, ValueError):
        return None
    if maximum < minimum or minimum < 0:
        return None
    count = minimum
    if maximum > minimum and rng.random() < 0.25:
        count = rng.randint(minimum, min(maximum, len(options)))
    if count == 0:
        return []
    if count > len(options):
        return None
    return sorted(rng.sample(range(len(options)), count))


def epsilon_agent(base_agent, epsilon: float, label: str):
    if epsilon <= 0.0:
        return base_agent
    rng = random.Random(f"heldout:{label}:{epsilon}")

    def agent(obs: dict) -> list[int]:
        if rng.random() < epsilon:
            action = valid_random_action(obs, rng)
            if action is not None:
                return action
        return base_agent(obs)

    return agent


def summarize_counts(results: list[dict], candidate_is_p0: bool) -> tuple[int, int, int, int]:
    counts = Counter(result["result"] for result in results)
    wins = counts[0] if candidate_is_p0 else counts[1]
    losses = counts[1] if candidate_is_p0 else counts[0]
    return wins, losses, counts[2], counts[-1]


def evaluate_pair(candidate_agent, candidate_deck, opponent_agent, opponent_deck, args: argparse.Namespace) -> tuple[int, int, int, int]:
    forward = run_games(
        candidate_agent,
        candidate_deck,
        opponent_agent,
        opponent_deck,
        args.games,
        args.max_steps,
        False,
        args.quiet,
        "forward",
    )
    f_wins, f_losses, f_draws, f_unfinished = summarize_counts(forward, candidate_is_p0=True)
    swapped = run_games(
        opponent_agent,
        opponent_deck,
        candidate_agent,
        candidate_deck,
        args.games,
        args.max_steps,
        False,
        args.quiet,
        "swapped",
    )
    s_wins, s_losses, s_draws, s_unfinished = summarize_counts(swapped, candidate_is_p0=False)
    return (
        f_wins + s_wins,
        f_losses + s_losses,
        f_draws + s_draws,
        f_unfinished + s_unfinished,
    )


def selected_opponents(args: argparse.Namespace) -> list[OpponentSpec]:
    excluded = set(args.exclude_alias)
    if args.include_default_exclusions:
        excluded.update(DEFAULT_EXCLUDED_ALIASES)
    specs = args.opponent[:] if args.opponent else DEFAULT_OPPONENTS[:]
    result: list[OpponentSpec] = []
    for spec in specs:
        alias = alias_from_path(spec.path)
        if alias and alias in excluded:
            continue
        if not spec.path.exists():
            continue
        result.append(spec)
    if args.max_opponents > 0:
        result = result[: args.max_opponents]
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", action="append", type=Path, required=True)
    parser.add_argument("--opponent", action="append", type=parse_opponent, default=[])
    parser.add_argument("--exclude-alias", action="append", default=[])
    parser.add_argument("--include-default-exclusions", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--max-opponents", type=int, default=0)
    parser.add_argument("--games", type=int, default=2, help="games per seat per opponent")
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    opponents = selected_opponents(args)
    print("opponent_pool")
    print("label,path,weight,epsilon,reason")
    for spec in opponents:
        print(f"{spec.label},{spec.path},{spec.weight:.2f},{spec.epsilon:.2f},{spec.reason}")

    total_exit = 0
    loaded_opponents = []
    for spec in opponents:
        base_agent, deck = load_agent(spec.path, f"opp_{spec.label}")
        loaded_opponents.append((spec, epsilon_agent(base_agent, spec.epsilon, spec.label), deck))

    for candidate_path in args.candidate:
        candidate_agent, candidate_deck = load_agent(candidate_path, f"cand_{candidate_path.name}")
        weighted_wins = 0.0
        weighted_games = 0.0
        print(f"\nCandidate {candidate_path}")
        print("opponent,weight,wins,losses,draws,unfinished,win_rate,teams")
        for spec, opponent_agent, opponent_deck in loaded_opponents:
            wins, losses, draws, unfinished = evaluate_pair(
                candidate_agent,
                candidate_deck,
                opponent_agent,
                opponent_deck,
                args,
            )
            played = wins + losses + draws
            win_rate = wins / played if played else 0.0
            weighted_wins += spec.weight * wins
            weighted_games += spec.weight * played
            if unfinished:
                total_exit = 1
            print(f"{spec.label},{spec.weight:.2f},{wins},{losses},{draws},{unfinished},{win_rate:.4f},{spec.reason}")
        score = weighted_wins / weighted_games if weighted_games else 0.0
        print(f"weighted_win_rate,{score:.4f}")
    return total_exit


if __name__ == "__main__":
    raise SystemExit(main())
