#!/usr/bin/env python3
"""Build a PSRO-style payoff report from local replay-pool gauntlets.

This is not a full equilibrium solver. The competition only allows the latest
two submissions, so the useful PSRO abstraction is a small policy population:
measure each policy against the current public opponent distribution, identify
best-response gaps, and pick pairs by coverage, maximin, regret, diversity, and
public-failure risk.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


ALIAS_OVERRIDES = {
    "pure-crustle-v2": "v8",
    "submission-crustle.tar.gz": "v8",
    "submission-crustle-backup-v4.tar.gz": "v8",
    "crustle-backup-v4": "v8",
    "kenn-ethan-patient-second-v36": "v36",
    "submission-kenn-ethan-patient-second-v36.tar.gz": "v36",
    "crustle-strayuru-hammer-target-v20": "v20",
    "submission-crustle-strayuru-hammer-target-v20.tar.gz": "v20",
}


@dataclass(frozen=True)
class CandidateMeta:
    alias: str
    candidate: str
    path: str
    family: str
    kind: str
    public_current: float | None
    public_best: float | None
    replay_win_rate: float | None
    fixed_win_rate: float | None
    ranker_mimic: bool
    notes: str


@dataclass
class CandidatePayoff:
    alias: str
    label: str
    weighted: float | None = None
    rates: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)
    teams: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SingleScore:
    alias: str
    weighted: float
    min_rate: float
    weighted_regret: float
    max_regret: float
    public_penalty: float
    score: float
    worst: list[str]
    reasons: list[str]


@dataclass(frozen=True)
class PairScore:
    left: str
    right: str
    coverage: float
    min_rate: float
    weighted_regret: float
    max_regret: float
    public_penalty: float
    diversity_bonus: float
    score: float
    blindspots: list[str]
    regret_targets: list[str]
    reasons: list[str]


def alias_from_text(text: str) -> str | None:
    lowered = text.lower()
    for needle, alias in ALIAS_OVERRIDES.items():
        if needle in lowered:
            return alias
    matches = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if matches:
        return f"v{matches[-1]}"
    return None


def parse_optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def normalize_opponent(key: str) -> str:
    if ":" not in key:
        return key.replace("_", "-")
    left, right = key.split(":", 1)
    return f"{left.replace('_', '-')}:{right}"


def load_candidate_meta(path: Path | None) -> dict[str, CandidateMeta]:
    if path is None:
        return {}
    metas: dict[str, CandidateMeta] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            alias = alias_from_text(row.get("candidate", "")) or alias_from_text(row.get("path", ""))
            if alias is None:
                continue
            metas[alias] = CandidateMeta(
                alias=alias,
                candidate=row.get("candidate", alias),
                path=row.get("path", alias),
                family=row.get("family", ""),
                kind=row.get("kind", ""),
                public_current=parse_optional_float(row.get("public_current")),
                public_best=parse_optional_float(row.get("public_best")),
                replay_win_rate=parse_optional_float(row.get("replay_win_rate")),
                fixed_win_rate=parse_optional_float(row.get("fixed_win_rate")),
                ranker_mimic=row.get("ranker_mimic", "").strip().lower() in {"1", "true", "yes"},
                notes=row.get("notes", ""),
            )
    return metas


def parse_gauntlet(path: Path) -> dict[str, CandidatePayoff]:
    results: dict[str, CandidatePayoff] = {}
    current: CandidatePayoff | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            label = Path(line.removeprefix("Candidate ").strip()).name
            alias = alias_from_text(label) or label
            current = CandidatePayoff(alias=alias, label=label)
            results[alias] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            try:
                current.weighted = float(line.split(",", 1)[1])
            except ValueError:
                pass
            continue
        if line.startswith(("opponent,", "skipped,", "forward ", "swapped ")):
            continue
        row = next(csv.reader([line]))
        if len(row) < 8 or ":" not in row[0]:
            continue
        try:
            key = normalize_opponent(row[0])
            current.weights[key] = float(row[1])
            current.rates[key] = float(row[6])
            current.teams[key] = row[7]
        except ValueError:
            continue
    return results


def merge_payoffs(paths: list[Path]) -> dict[str, CandidatePayoff]:
    merged: dict[str, CandidatePayoff] = {}
    for path in paths:
        for alias, result in parse_gauntlet(path).items():
            if alias not in merged:
                merged[alias] = result
                continue
            target = merged[alias]
            if result.weighted is not None:
                target.weighted = result.weighted
            target.rates.update(result.rates)
            target.weights.update(result.weights)
            target.teams.update(result.teams)
    return merged


def filter_public_failed(
    payoffs: dict[str, CandidatePayoff],
    metas: dict[str, CandidateMeta],
    floor: float,
) -> tuple[dict[str, CandidatePayoff], list[tuple[str, float, str]]]:
    if floor <= 0:
        return payoffs, []
    kept: dict[str, CandidatePayoff] = {}
    excluded: list[tuple[str, float, str]] = []
    for alias, payoff in payoffs.items():
        meta = metas.get(alias)
        if meta and meta.public_current is not None and meta.public_current < floor:
            excluded.append((alias, meta.public_current, meta.candidate))
            continue
        kept[alias] = payoff
    excluded.sort(key=lambda item: (item[1], item[0]))
    return kept, excluded


def public_risk(alias: str, metas: dict[str, CandidateMeta]) -> tuple[float, list[str]]:
    meta = metas.get(alias)
    if meta is None:
        return 0.025, ["missing_public_meta"]
    penalty = 0.0
    reasons: list[str] = []
    if meta.kind == "local-variant":
        penalty += 0.060
        reasons.append("local_variant")
    if meta.kind == "submitted" and meta.public_current is not None and meta.public_current < 900:
        penalty += 0.120
        reasons.append(f"submitted_public={meta.public_current:.1f}")
    if meta.public_current is not None and meta.public_current < 800:
        penalty += 0.050
        reasons.append("very_low_public")
    family_failures = [
        item.public_current
        for item in metas.values()
        if item.family == meta.family and item.public_current is not None and item.public_current < 800
    ]
    if family_failures and not (meta.public_current is not None and meta.public_current < 800):
        penalty += 0.075
        reasons.append(f"family_failed={min(family_failures):.1f}")
    return penalty, reasons


def shell_key(alias: str, metas: dict[str, CandidateMeta]) -> str:
    meta = metas.get(alias)
    if meta is None:
        return alias
    if meta.candidate.startswith("hiroingk-hammer-"):
        return "hiroingk-hammer-b9bcfb3e10"
    return meta.family or alias


def opponent_weights(payoffs: dict[str, CandidatePayoff]) -> dict[str, float]:
    weights: dict[str, float] = {}
    for payoff in payoffs.values():
        for key, weight in payoff.weights.items():
            weights[key] = max(weights.get(key, 0.0), weight)
    return weights


def oracle_rates(payoffs: dict[str, CandidatePayoff], opponents: set[str]) -> dict[str, float]:
    oracle: dict[str, float] = {}
    for opponent in opponents:
        oracle[opponent] = max((payoff.rates.get(opponent, 0.0) for payoff in payoffs.values()), default=0.0)
    return oracle


def weighted_average(values: list[tuple[float, float]]) -> float:
    total = sum(weight for weight, _ in values)
    if not total:
        return 0.0
    return sum(weight * value for weight, value in values) / total


def single_score(
    alias: str,
    payoff: CandidatePayoff,
    weights: dict[str, float],
    oracle: dict[str, float],
    metas: dict[str, CandidateMeta],
) -> SingleScore:
    values: list[tuple[float, float]] = []
    regrets: list[tuple[float, str, float, float]] = []
    rates = []
    for opponent, weight in weights.items():
        rate = payoff.rates.get(opponent, 0.0)
        rates.append(rate)
        values.append((weight, rate))
        regret = max(0.0, oracle.get(opponent, 0.0) - rate)
        regrets.append((weight * regret, opponent, regret, rate))
    weighted = payoff.weighted if payoff.weighted is not None else weighted_average(values)
    weighted_regret = weighted_average([(weights[key], max(0.0, oracle[key] - payoff.rates.get(key, 0.0))) for key in weights])
    max_regret = max((item[2] for item in regrets), default=0.0)
    public_penalty, reasons = public_risk(alias, metas)
    score = weighted - 0.45 * weighted_regret - 0.15 * max_regret - public_penalty
    regrets.sort(key=lambda item: (-item[0], item[1]))
    worst = [
        f"`{opponent}` rate={rate:.3f} regret={regret:.3f} weighted={weighted_gap:.2f}"
        for weighted_gap, opponent, regret, rate in regrets[:4]
        if regret > 0
    ]
    return SingleScore(
        alias=alias,
        weighted=weighted,
        min_rate=min(rates) if rates else 0.0,
        weighted_regret=weighted_regret,
        max_regret=max_regret,
        public_penalty=public_penalty,
        score=score,
        worst=worst,
        reasons=reasons,
    )


def pair_score(
    left: str,
    right: str,
    payoffs: dict[str, CandidatePayoff],
    weights: dict[str, float],
    oracle: dict[str, float],
    metas: dict[str, CandidateMeta],
    blind_threshold: float,
) -> PairScore:
    left_payoff = payoffs[left]
    right_payoff = payoffs[right]
    values: list[tuple[float, float]] = []
    regrets: list[tuple[float, str, float, float]] = []
    blindspots: list[tuple[float, str, float, float]] = []
    rates = []
    for opponent, weight in weights.items():
        left_rate = left_payoff.rates.get(opponent, 0.0)
        right_rate = right_payoff.rates.get(opponent, 0.0)
        best = max(left_rate, right_rate)
        rates.append(best)
        values.append((weight, best))
        regret = max(0.0, oracle.get(opponent, 0.0) - best)
        regrets.append((weight * regret, opponent, regret, best))
        if left_rate < blind_threshold and right_rate < blind_threshold:
            blindspots.append((weight, opponent, left_rate, right_rate))
    coverage = weighted_average(values)
    weighted_regret = weighted_average([(weights[key], max(0.0, oracle[key] - max(left_payoff.rates.get(key, 0.0), right_payoff.rates.get(key, 0.0)))) for key in weights])
    max_regret = max((item[2] for item in regrets), default=0.0)
    left_risk, left_reasons = public_risk(left, metas)
    right_risk, right_reasons = public_risk(right, metas)
    public_penalty = left_risk + right_risk
    diversity_bonus = 0.0
    reasons = [f"{left}:{reason}" for reason in left_reasons] + [f"{right}:{reason}" for reason in right_reasons]
    left_meta = metas.get(left)
    right_meta = metas.get(right)
    if left_meta and right_meta:
        if shell_key(left, metas) == shell_key(right, metas):
            public_penalty += 0.070
            reasons.append("same_shell_or_family")
        elif left_meta.family != right_meta.family:
            diversity_bonus += 0.025
            reasons.append("family_diversity")
        if left_meta.ranker_mimic and right_meta.ranker_mimic:
            diversity_bonus += 0.010
            reasons.append("double_ranker_mimic")
    blindspots.sort(key=lambda item: (-item[0], item[1]))
    regrets.sort(key=lambda item: (-item[0], item[1]))
    blind_text = [
        f"`{opponent}` {left_rate:.3f}/{right_rate:.3f} w={weight:.2f}"
        for weight, opponent, left_rate, right_rate in blindspots[:5]
    ]
    target_text = [
        f"`{opponent}` coverage={coverage_rate:.3f} regret={regret:.3f} weighted={weighted_gap:.2f}"
        for weighted_gap, opponent, regret, coverage_rate in regrets[:5]
        if regret > 0
    ]
    score = coverage - 0.55 * weighted_regret - 0.20 * max_regret + diversity_bonus - public_penalty
    return PairScore(
        left=left,
        right=right,
        coverage=coverage,
        min_rate=min(rates) if rates else 0.0,
        weighted_regret=weighted_regret,
        max_regret=max_regret,
        public_penalty=public_penalty,
        diversity_bonus=diversity_bonus,
        score=score,
        blindspots=blind_text,
        regret_targets=target_text,
        reasons=reasons,
    )


def render(args: argparse.Namespace) -> str:
    metas = load_candidate_meta(args.candidates)
    raw_payoffs = merge_payoffs(args.gauntlet)
    payoffs, excluded = filter_public_failed(raw_payoffs, metas, args.exclude_public_below)
    weights = opponent_weights(payoffs)
    oracle = oracle_rates(payoffs, set(weights))
    singles = [
        single_score(alias, payoff, weights, oracle, metas)
        for alias, payoff in payoffs.items()
        if payoff.rates
    ]
    singles.sort(key=lambda item: (-item.score, item.alias))

    pairs: list[PairScore] = []
    aliases = sorted(alias for alias, payoff in payoffs.items() if payoff.rates)
    for index, left in enumerate(aliases):
        for right in aliases[index + 1 :]:
            pairs.append(pair_score(left, right, payoffs, weights, oracle, metas, args.blind_threshold))
    pairs.sort(key=lambda item: (-item.score, item.weighted_regret, item.left, item.right))

    opponent_rows = []
    for opponent, weight in sorted(weights.items(), key=lambda item: (-item[1], item[0])):
        best_alias, best_rate = max(
            ((alias, payoff.rates.get(opponent, 0.0)) for alias, payoff in payoffs.items()),
            key=lambda item: (item[1], item[0]),
        )
        teams = next((payoff.teams.get(opponent, "") for payoff in payoffs.values() if opponent in payoff.teams), "")
        opponent_rows.append((opponent, weight, best_alias, best_rate, teams))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# PSRO Payoff Strategy Report",
        "",
        f"Generated: {now}",
        "",
        "## Research Agent Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{Path.cwd()}`",
        f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "- Strategic premise: optimize a policy population for live payoff coverage, not a single strongest deck.",
        "",
        "## Sources",
        "",
    ]
    for path in args.gauntlet:
        lines.append(f"- Payoff gauntlet: `{path}`")
    if args.candidates:
        lines.append(f"- Candidate evidence: `{args.candidates}`")
    if args.exclude_public_below > 0:
        lines.append(f"- Public-failure exclusion floor: {args.exclude_public_below:.1f}")
    lines.append("")

    if excluded:
        lines.extend(
            [
                "## Public-Failure Exclusions",
                "",
                "| Policy | Public Current | Candidate |",
                "| --- | ---: | --- |",
            ]
        )
        for alias, public_current, candidate in excluded:
            lines.append(f"| `{alias}` | {public_current:.1f} | {candidate} |")
        lines.append("")

    if pairs:
        best = pairs[0]
        lines.extend(
            [
                "## Recommendation",
                "",
                f"- Pair aliases: `{best.left}` + `{best.right}`",
                f"- PSRO score: {best.score:.4f}",
                f"- Weighted coverage: {best.coverage:.4f}; min payoff: {best.min_rate:.4f}; weighted regret: {best.weighted_regret:.4f}; max regret: {best.max_regret:.4f}",
                f"- Public penalty: {best.public_penalty:.3f}; diversity bonus: {best.diversity_bonus:.3f}",
                "- Reasons: " + ("; ".join(best.reasons) if best.reasons else "lowest risk-adjusted regret"),
            ]
        )
        if best.blindspots:
            lines.append("- Shared blindspots: " + "; ".join(best.blindspots))
        if best.regret_targets:
            lines.append("- Next best-response targets: " + "; ".join(best.regret_targets))
        lines.append("")

    lines.extend(
        [
            "## Opponent Oracle",
            "",
            "| Opponent | Weight | Oracle Policy | Oracle Rate | Teams |",
            "| --- | ---: | --- | ---: | --- |",
        ]
    )
    for opponent, weight, best_alias, best_rate, teams in opponent_rows[: args.opponent_limit]:
        lines.append(f"| `{opponent}` | {weight:.2f} | `{best_alias}` | {best_rate:.3f} | {teams or '-'} |")
    lines.append("")

    lines.extend(
        [
            "## Single Policy Scores",
            "",
            "| Rank | Policy | Score | Weighted | Min | Weighted Regret | Max Regret | Public Penalty | Worst Gaps | Reasons |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for rank, item in enumerate(singles[: args.limit], 1):
        worst = "; ".join(item.worst) if item.worst else "-"
        reasons = "; ".join(item.reasons) if item.reasons else "-"
        lines.append(
            f"| {rank} | `{item.alias}` | {item.score:.4f} | {item.weighted:.4f} | {item.min_rate:.4f} | "
            f"{item.weighted_regret:.4f} | {item.max_regret:.4f} | {item.public_penalty:.3f} | {worst} | {reasons} |"
        )
    lines.append("")

    lines.extend(
        [
            "## Pair Population Scores",
            "",
            "| Rank | Pair | PSRO Score | Coverage | Min | Weighted Regret | Max Regret | Bonus | Penalty | Blindspots | Regret Targets | Reasons |",
            "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )
    for rank, item in enumerate(pairs[: args.limit], 1):
        blindspots = "; ".join(item.blindspots) if item.blindspots else "-"
        targets = "; ".join(item.regret_targets) if item.regret_targets else "-"
        reasons = "; ".join(item.reasons) if item.reasons else "-"
        lines.append(
            f"| {rank} | `{item.left}` + `{item.right}` | {item.score:.4f} | {item.coverage:.4f} | "
            f"{item.min_rate:.4f} | {item.weighted_regret:.4f} | {item.max_regret:.4f} | "
            f"{item.diversity_bonus:.3f} | {item.public_penalty:.3f} | {blindspots} | {targets} | {reasons} |"
        )
    lines.append("")

    lines.extend(
        [
            "## Strategy Loop",
            "",
            "1. Treat the opponent oracle rows as the current PSRO opponent population.",
            "2. Train or hand-code best responses only for high-weight regret targets; do not mutate deck architecture first.",
            "3. Add any new policy to the population, rerun the same payoff report, and keep only policies that reduce pair regret without increasing public-failure risk.",
            "4. Use behavior-cloning/action-ranker holdouts as a policy timing check before a submission gate.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gauntlet", action="append", required=True, type=Path)
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--blind-threshold", type=float, default=0.5)
    parser.add_argument(
        "--exclude-public-below",
        type=float,
        default=0.0,
        help="drop candidates whose candidate evidence has public_current below this score",
    )
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--opponent-limit", type=int, default=16)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
