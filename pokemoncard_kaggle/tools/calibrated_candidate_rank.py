#!/usr/bin/env python3
"""Rank reset candidates using public-score priors plus local simulator screens.

The local replay-pool and fixed-meta gauntlets are useful shape detectors, but
the 2026-06-19 reset showed they can badly overvalue a candidate family. This
tool keeps that lesson explicit: public scores dominate when available, exact
high-ranker mimics get a measured prior, and candidates from a publicly weak
family inherit a penalty even if their local win rate is high.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import math
from dataclasses import dataclass
from pathlib import Path


TOP10_TARGET = 1180.7
PUBLIC_BASELINE = 700.0


@dataclass(frozen=True)
class Candidate:
    candidate: str
    path: str
    family: str
    kind: str
    replay_win_rate: float | None
    fixed_win_rate: float | None
    public_current: float | None
    public_best: float | None
    public_floor: float | None
    ranker_mimic: bool
    notes: str


def parse_optional_float(value: str) -> float | None:
    value = value.strip()
    if not value:
        return None
    return float(value)


def load_candidates(path: Path) -> list[Candidate]:
    with path.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))
    candidates: list[Candidate] = []
    for row in rows:
        candidates.append(
            Candidate(
                candidate=row["candidate"],
                path=row["path"],
                family=row["family"],
                kind=row["kind"],
                replay_win_rate=parse_optional_float(row["replay_win_rate"]),
                fixed_win_rate=parse_optional_float(row["fixed_win_rate"]),
                public_current=parse_optional_float(row["public_current"]),
                public_best=parse_optional_float(row["public_best"]),
                public_floor=parse_optional_float(row["public_floor"]),
                ranker_mimic=row["ranker_mimic"].strip() in {"1", "true", "True", "yes"},
                notes=row["notes"],
            )
        )
    return candidates


def public_strength(score: float | None, top10_target: float) -> float:
    if score is None:
        return 0.0
    return max(0.0, min(1.0, (score - PUBLIC_BASELINE) / (top10_target - PUBLIC_BASELINE)))


def local_strength(candidate: Candidate) -> float:
    values = [v for v in (candidate.replay_win_rate, candidate.fixed_win_rate) if v is not None]
    if not values:
        return 0.0
    return sum(values) / len(values)


def family_public_strength(candidates: list[Candidate], top10_target: float) -> dict[str, float]:
    grouped: dict[str, list[float]] = {}
    for candidate in candidates:
        scores = [score for score in (candidate.public_current, candidate.public_best) if score is not None]
        if scores:
            grouped.setdefault(candidate.family, []).append(max(scores))
    return {
        family: public_strength(sum(scores) / len(scores), top10_target)
        for family, scores in grouped.items()
    }


def family_recent_floor(candidates: list[Candidate]) -> dict[str, float]:
    grouped: dict[str, list[float]] = {}
    for candidate in candidates:
        if candidate.public_current is not None:
            grouped.setdefault(candidate.family, []).append(candidate.public_current)
    return {family: min(scores) for family, scores in grouped.items()}


def score_candidate(
    candidate: Candidate,
    family_strength: dict[str, float],
    family_floor: dict[str, float],
    top10_target: float,
) -> tuple[float, list[str]]:
    current_strength = public_strength(candidate.public_current, top10_target)
    best_strength = public_strength(candidate.public_best, top10_target)
    family_strength_value = family_strength.get(candidate.family)
    local = local_strength(candidate)
    reasons: list[str] = []

    public_component = 0.55 * current_strength + 0.25 * best_strength
    if candidate.public_current is not None:
        reasons.append(f"current_public={candidate.public_current:.1f}")
    if candidate.public_best is not None and candidate.public_best != candidate.public_current:
        reasons.append(f"best_public={candidate.public_best:.1f}")

    if candidate.public_current is None and candidate.ranker_mimic:
        # An exact current high-ranker mimic has meaningful upside, but not the
        # same reliability as our own public score evidence.
        public_component += 0.42
        reasons.append("exact_live_ranker_mimic")
    elif candidate.public_current is None and family_strength_value is not None:
        public_component += 0.28 * family_strength_value
        reasons.append(f"family_public={family_strength_value:.2f}")

    local_component = 0.20 * local
    if local:
        reasons.append(f"local={local:.3f}")

    penalty = 0.0
    if candidate.public_current is not None and candidate.public_current < 900 and local >= 0.74:
        penalty += 0.22
        reasons.append("public_local_mismatch_penalty")
    if candidate.public_current is not None and candidate.public_current < 800:
        penalty += 0.14
        reasons.append("recent_public_failure")
    recent_family_floor = family_floor.get(candidate.family)
    if candidate.public_current is None and recent_family_floor is not None and recent_family_floor < 800:
        penalty += 0.16
        reasons.append(f"family_recent_failure={recent_family_floor:.1f}")
    if candidate.public_floor is not None and candidate.public_floor < 750 and local >= 0.74:
        penalty += 0.08
        reasons.append("family_floor_penalty")
    if family_strength_value is not None and family_strength_value < 0.38 and local >= 0.74:
        penalty += 0.10
        reasons.append("weak_family_public_prior")

    score = public_component + local_component - penalty
    return score, reasons


def shell_key(candidate: Candidate) -> str | None:
    name = candidate.candidate
    if name.startswith("hiroingk-hammer-"):
        return "hiroingk_hammer_b9bcfb3e10"
    if name.startswith("alakazam-hammer-mid") or name.startswith("alakazam-denpa"):
        return "battle_cage_alakazam_family"
    return None


def pair_score(
    first: tuple[float, Candidate, str],
    second: tuple[float, Candidate, str],
) -> tuple[float, list[str]]:
    first_score, first_candidate, _ = first
    second_score, second_candidate, _ = second
    leader = max(first_score, second_score)
    cover = min(first_score, second_score)
    score = leader + 0.35 * cover
    reasons = [f"best_single={leader:.4f}", f"second_cover={cover:.4f}"]

    first_shell = shell_key(first_candidate)
    second_shell = shell_key(second_candidate)
    if first_shell is not None and first_shell == second_shell:
        score -= 0.065
        reasons.append("same_exact_shell_correlation_penalty")
    elif first_candidate.family == second_candidate.family:
        score -= 0.025
        reasons.append("same_family_correlation_penalty")
    else:
        score += 0.015
        reasons.append("family_diversity_bonus")
        if first_candidate.ranker_mimic and second_candidate.ranker_mimic:
            score += 0.010
            reasons.append("ranker_mimic_diversity_bonus")

    weak_public_pair = all(
        candidate.public_current is not None
        and candidate.public_current < 900
        and local_strength(candidate) >= 0.74
        for candidate in (first_candidate, second_candidate)
    )
    if weak_public_pair:
        score -= 0.050
        reasons.append("double_public_miss_penalty")

    return score, reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--candidates",
        type=Path,
        default=Path("strategy/reset_candidates_20260620.csv"),
        help="CSV with candidate evidence",
    )
    parser.add_argument("--top10-target", type=float, default=TOP10_TARGET)
    args = parser.parse_args()

    candidates = load_candidates(args.candidates)
    family_strength = family_public_strength(candidates, args.top10_target)
    family_floor = family_recent_floor(candidates)
    rows = []
    for candidate in candidates:
        score, reasons = score_candidate(candidate, family_strength, family_floor, args.top10_target)
        rows.append((score, candidate, "; ".join(reasons)))

    rows.sort(key=lambda item: (-item[0], item[1].candidate))
    print("rank,candidate,calibrated_score,path,family,kind,reasons")
    for index, (score, candidate, reasons) in enumerate(rows, start=1):
        print(
            f"{index},{candidate.candidate},{score:.4f},{candidate.path},"
            f"{candidate.family},{candidate.kind},{reasons}"
        )

    best = rows[0][1] if rows else None
    if best is not None:
        print()
        print(f"recommended_first={best.path}")
        if len(rows) > 1:
            print(f"recommended_second={rows[1][1].path}")

    pair_rows = []
    for left, right in itertools.combinations(rows, 2):
        score, reasons = pair_score(left, right)
        first = left[1]
        second = right[1]
        pair_rows.append((score, first, second, "; ".join(reasons)))
    pair_rows.sort(key=lambda item: (-item[0], item[1].candidate, item[2].candidate))

    if pair_rows:
        print()
        print("pair_rank,first_candidate,second_candidate,pair_score,first_path,second_path,reasons")
        for index, (score, first, second, reasons) in enumerate(pair_rows[:12], start=1):
            print(
                f"{index},{first.candidate},{second.candidate},{score:.4f},"
                f"{first.path},{second.path},{reasons}"
            )
        best_pair = pair_rows[0]
        print()
        print(f"recommended_pair_first={best_pair[1].path}")
        print(f"recommended_pair_second={best_pair[2].path}")
    if any(math.isnan(score) for score, _, _ in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
