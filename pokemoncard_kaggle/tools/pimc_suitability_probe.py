#!/usr/bin/env python3
"""Probe whether cheap determinization/PIMC is likely to be useful.

This is a measurement tool, not a submitted policy. It uses the actual local
simulator to compare normal policy games with two independent random-rollout
batches. From those batches it estimates:

* lc: leaf correlation, here the correlation of independent rollout estimates
  across matchups,
* b: rollout bias versus normal policy outcomes, and
* df: disambiguation factor, the share of rollout variance explained by matchup
  differences rather than rollout noise.

If lc and df are low, cheap PIMC/determinization is unlikely to give a reliable
candidate-selection signal; prefer ISMCTS/CFR/PSRO-style offline work instead.
Run inside linux/amd64 because it imports the native simulator.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import socket
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_local_battle import load_agent, run_games  # noqa: E402


@dataclass(frozen=True)
class OpponentSpec:
    label: str
    path: Path
    weight: float = 1.0


@dataclass(frozen=True)
class ProbeRow:
    agent: str
    opponent: str
    weight: float
    policy_score: float
    rollout_a: float
    rollout_b: float


DEFAULT_OPPONENTS = [
    OpponentSpec("old-v10", Path("agents/v10_mizotake_v2"), 1.0),
    OpponentSpec("old-v17", Path("agents/v17_strayuru_v4"), 1.0),
    OpponentSpec("festival-v42", Path("agents/v42_hibi_festival"), 1.1),
    OpponentSpec("alakazam-v43", Path("agents/v43_daitou_alakazam"), 1.2),
    OpponentSpec("nighttime-v58", Path("agents/v58_donguk_nighttime"), 1.2),
    OpponentSpec("mega-lucario-v67", Path("agents/v67_mega_lucario_praxel"), 1.3),
    OpponentSpec("rocket-mewtwo-v80", Path("agents/v80_rocket_mewtwo_spidops_v50policy"), 1.1),
]


def parse_opponent(raw: str) -> OpponentSpec:
    parts = raw.split(":", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError("opponent must be label:path[:weight]")
    try:
        weight = float(parts[2]) if len(parts) >= 3 and parts[2] else 1.0
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return OpponentSpec(parts[0], Path(parts[1]), weight)


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
    if minimum < 0 or maximum < minimum:
        return None
    count = minimum
    if maximum > minimum and rng.random() < 0.20:
        count = rng.randint(minimum, min(maximum, len(options)))
    if count == 0:
        return []
    if count > len(options):
        return None
    return sorted(rng.sample(range(len(options)), count))


def epsilon_agent(base_agent, epsilon: float, seed: str):
    if epsilon <= 0.0:
        return base_agent
    rng = random.Random(seed)

    def agent(obs: dict) -> list[int]:
        if rng.random() < epsilon:
            action = valid_random_action(obs, rng)
            if action is not None:
                return action
        return base_agent(obs)

    return agent


def summarize_score(results: list[dict], candidate_is_p0: bool) -> float:
    wins = 0
    played = 0
    for result in results:
        outcome = result.get("result")
        if outcome == -1:
            continue
        if outcome == 2:
            played += 1
            wins += 0.5
        elif (outcome == 0 and candidate_is_p0) or (outcome == 1 and not candidate_is_p0):
            played += 1
            wins += 1
        elif outcome in (0, 1):
            played += 1
    return wins / played if played else 0.0


def matchup_score(candidate_agent, candidate_deck, opponent_agent, opponent_deck, games: int, max_steps: int, quiet: bool) -> float:
    forward = run_games(candidate_agent, candidate_deck, opponent_agent, opponent_deck, games, max_steps, False, quiet, "forward")
    swapped = run_games(opponent_agent, opponent_deck, candidate_agent, candidate_deck, games, max_steps, False, quiet, "swapped")
    total_games = len(forward) + len(swapped)
    score = summarize_score(forward, True) * len(forward) + summarize_score(swapped, False) * len(swapped)
    return score / total_games if total_games else 0.0


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 2:
        return float("nan")
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if den_x == 0.0 or den_y == 0.0:
        return float("nan")
    return num / (den_x * den_y)


def weighted_mean(values: list[tuple[float, float]]) -> float:
    total_weight = sum(weight for weight, _value in values)
    if total_weight <= 0.0:
        return 0.0
    return sum(weight * value for weight, value in values) / total_weight


def variance(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / (len(values) - 1)


def summarize(rows: list[ProbeRow]) -> tuple[float, float, float]:
    lc = pearson([row.rollout_a for row in rows], [row.rollout_b for row in rows])
    bias = weighted_mean(
        [
            (row.weight, ((row.rollout_a + row.rollout_b) / 2.0) - row.policy_score)
            for row in rows
        ]
    )
    means = [(row.rollout_a + row.rollout_b) / 2.0 for row in rows]
    within = [((row.rollout_a - means[index]) ** 2 + (row.rollout_b - means[index]) ** 2) / 2.0 for index, row in enumerate(rows)]
    between = variance(means)
    noise = sum(within) / len(within) if within else 0.0
    df = between / (between + noise) if (between + noise) > 0.0 else 0.0
    return lc, bias, df


def percentile(values: list[float], pct: float) -> float:
    finite = sorted(value for value in values if math.isfinite(value))
    if not finite:
        return float("nan")
    if len(finite) == 1:
        return finite[0]
    position = (len(finite) - 1) * pct
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return finite[int(position)]
    fraction = position - lower
    return finite[lower] * (1.0 - fraction) + finite[upper] * fraction


def bootstrap_ci(rows: list[ProbeRow], samples: int, seed: str) -> dict[str, tuple[float, float]]:
    if len(rows) < 2 or samples <= 0:
        return {
            "lc": (float("nan"), float("nan")),
            "bias": (float("nan"), float("nan")),
            "df": (float("nan"), float("nan")),
        }
    rng = random.Random(seed)
    lc_values: list[float] = []
    bias_values: list[float] = []
    df_values: list[float] = []
    for _ in range(samples):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        lc, bias, df = summarize(sample)
        lc_values.append(lc)
        bias_values.append(bias)
        df_values.append(df)
    return {
        "lc": (percentile(lc_values, 0.025), percentile(lc_values, 0.975)),
        "bias": (percentile(bias_values, 0.025), percentile(bias_values, 0.975)),
        "df": (percentile(df_values, 0.025), percentile(df_values, 0.975)),
    }


def decision(lc: float, bias: float, df: float) -> str:
    if math.isfinite(lc) and lc >= 0.65 and abs(bias) <= 0.12 and df >= 0.35:
        return "cheap determinization/PIMC is plausible"
    return "prefer ISMCTS/CFR/PSRO-style offline training"


def render(rows: list[ProbeRow], args: argparse.Namespace, csv_path: Path | None) -> str:
    lc, bias, df = summarize(rows)
    ci = bootstrap_ci(rows, args.bootstrap_samples, "pimc-suitability-bootstrap")
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# PIMC Suitability Probe",
        "",
        f"Generated: {generated}",
        "",
        "## Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        "- Runtime: deterministic offline simulator; no network or LLM at play time.",
        "",
        "## Summary",
        "",
        f"- Leaf correlation lc: {lc:.4f}" if math.isfinite(lc) else "- Leaf correlation lc: nan",
        f"- Leaf correlation 95% bootstrap CI: [{ci['lc'][0]:.4f}, {ci['lc'][1]:.4f}]",
        f"- Bias b: {bias:.4f}",
        f"- Bias 95% bootstrap CI: [{ci['bias'][0]:.4f}, {ci['bias'][1]:.4f}]",
        f"- Disambiguation factor df: {df:.4f}",
        f"- Disambiguation factor 95% bootstrap CI: [{ci['df'][0]:.4f}, {ci['df'][1]:.4f}]",
        f"- Decision: **{decision(lc, bias, df)}**",
        f"- Rollout epsilon: {args.rollout_epsilon}",
        f"- Games per seat per estimate: {args.games}",
        f"- Bootstrap samples: {args.bootstrap_samples}",
    ]
    if csv_path:
        lines.append(f"- CSV: `{csv_path}`")
    lines.extend(["", "## Rows", "", "| Agent | Opponent | Weight | Policy | Rollout A | Rollout B | Mean Rollout | Bias |"])
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for row in rows:
        mean_rollout = (row.rollout_a + row.rollout_b) / 2.0
        lines.append(
            f"| `{row.agent}` | `{row.opponent}` | {row.weight:.2f} | {row.policy_score:.3f} | "
            f"{row.rollout_a:.3f} | {row.rollout_b:.3f} | {mean_rollout:.3f} | {mean_rollout - row.policy_score:+.3f} |"
        )
    lines.extend(
        [
            "",
            "## Use",
            "",
            "- Treat low lc as evidence that cheap PIMC leaf values are not stable enough for submit selection.",
            "- Treat high absolute bias as evidence that random playouts are evaluating a different game than the policy actually plays.",
            "- Treat low df as evidence that random playouts cannot distinguish candidate matchups; a robust population method is safer.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_csv(rows: list[ProbeRow], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["agent", "opponent", "weight", "policy_score", "rollout_a", "rollout_b"])
        for row in rows:
            writer.writerow([row.agent, row.opponent, row.weight, row.policy_score, row.rollout_a, row.rollout_b])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", action="append", type=Path, required=True)
    parser.add_argument("--opponent", action="append", type=parse_opponent, default=[])
    parser.add_argument("--games", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=800)
    parser.add_argument("--rollout-epsilon", type=float, default=0.35)
    parser.add_argument("--bootstrap-samples", type=int, default=1000)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--csv-output", type=Path)
    args = parser.parse_args()

    opponents = args.opponent or DEFAULT_OPPONENTS
    loaded_opponents = []
    for spec in opponents:
        if not spec.path.exists():
            continue
        agent, deck = load_agent(spec.path, f"opp_{spec.label}")
        loaded_opponents.append((spec, agent, deck))

    rows: list[ProbeRow] = []
    for agent_path in args.agent:
        base_agent, deck = load_agent(agent_path, f"cand_{agent_path.name}")
        for spec, opponent_agent, opponent_deck in loaded_opponents:
            policy_score = matchup_score(base_agent, deck, opponent_agent, opponent_deck, args.games, args.max_steps, args.quiet)
            rollout_a = matchup_score(
                epsilon_agent(base_agent, args.rollout_epsilon, f"{agent_path}:A"),
                deck,
                epsilon_agent(opponent_agent, args.rollout_epsilon, f"{spec.label}:A"),
                opponent_deck,
                args.games,
                args.max_steps,
                args.quiet,
            )
            rollout_b = matchup_score(
                epsilon_agent(base_agent, args.rollout_epsilon, f"{agent_path}:B"),
                deck,
                epsilon_agent(opponent_agent, args.rollout_epsilon, f"{spec.label}:B"),
                opponent_deck,
                args.games,
                args.max_steps,
                args.quiet,
            )
            rows.append(
                ProbeRow(
                    agent=agent_path.name,
                    opponent=spec.label,
                    weight=spec.weight,
                    policy_score=policy_score,
                    rollout_a=rollout_a,
                    rollout_b=rollout_b,
                )
            )

    csv_path = args.csv_output
    if csv_path:
        write_csv(rows, csv_path)
    report = render(rows, args, csv_path)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
