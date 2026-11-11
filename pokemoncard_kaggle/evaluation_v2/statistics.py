"""Small, deterministic statistical summaries for candidate evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random
from typing import Mapping, Sequence


@dataclass(frozen=True)
class EpisodeRecord:
    """Paired correctness counts for one independently sampled episode."""

    candidate_correct: float
    baseline_correct: float
    compared: float


@dataclass(frozen=True)
class BootstrapSummary:
    point_delta: float
    q10: float
    q50: float
    q90: float
    p_gt_zero: float
    sample_count: int
    draw_count: int


@dataclass(frozen=True)
class BetaBinomialSummary:
    mean: float
    q10: float
    q90: float


@dataclass(frozen=True)
class RobustMixtureSummary:
    mean: float
    q10: float
    p_gt_zero: float
    worst_cell: str
    worst_delta: float


def quantile(values: Sequence[float], probability: float) -> float:
    """Return the linearly interpolated empirical quantile of ``values``."""
    if not values:
        raise ValueError("values must be nonempty")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")

    ordered = sorted(values)
    index = (len(ordered) - 1) * probability
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def episode_cluster_bootstrap(
    records: Sequence[EpisodeRecord], *, seed: int, draws: int = 2000
) -> BootstrapSummary:
    """Bootstrap paired rate deltas by resampling whole episodes."""
    _validate_draws(draws)
    _validate_episode_records(records)

    point_delta = _episode_delta(records)
    rng = Random(seed)
    deltas = [_episode_delta([records[rng.randrange(len(records))] for _ in records]) for _ in range(draws)]
    return BootstrapSummary(
        point_delta=point_delta,
        q10=quantile(deltas, 0.10),
        q50=quantile(deltas, 0.50),
        q90=quantile(deltas, 0.90),
        p_gt_zero=sum(delta > 0.0 for delta in deltas) / draws,
        sample_count=len(records),
        draw_count=draws,
    )


def beta_binomial_summary(
    wins: int,
    losses: int,
    draws: int,
    *,
    seed: int,
    samples: int = 2000,
) -> BetaBinomialSummary:
    """Summarize a Jeffreys-prior posterior, with draws split evenly."""
    if min(wins, losses, draws) < 0:
        raise ValueError("wins, losses, and draws must be nonnegative")
    _validate_draws(samples)

    alpha = 0.5 + wins + draws / 2.0
    beta = 0.5 + losses + draws / 2.0
    rng = Random(seed)
    posterior = [rng.betavariate(alpha, beta) for _ in range(samples)]
    return BetaBinomialSummary(
        mean=alpha / (alpha + beta),
        q10=quantile(posterior, 0.10),
        q90=quantile(posterior, 0.90),
    )


def robust_matchup_mixture(
    matchup_deltas: Mapping[str, float],
    observed_counts: Mapping[str, float],
    *,
    epsilon: float,
    seed: int,
    draws: int = 2000,
) -> RobustMixtureSummary:
    """Score matchup means under a count-smoothed, worst-cell mixture."""
    _validate_draws(draws)
    if not matchup_deltas or matchup_deltas.keys() != observed_counts.keys():
        raise ValueError("matchup_deltas and observed_counts must be nonempty with matching keys")
    if not 0.0 <= epsilon <= 1.0:
        raise ValueError("epsilon must be in [0, 1]")
    if any(count < 0.0 for count in observed_counts.values()):
        raise ValueError("observed counts must be nonnegative")

    cells = tuple(matchup_deltas)
    means = tuple(float(matchup_deltas[cell]) for cell in cells)
    alphas = tuple(float(observed_counts[cell]) + 0.5 for cell in cells)
    worst_index = min(range(len(cells)), key=means.__getitem__)
    worst_delta = means[worst_index]
    rng = Random(seed)
    scores = []
    for _ in range(draws):
        weights = [rng.gammavariate(alpha, 1.0) for alpha in alphas]
        total = sum(weights)
        nominal = sum(weight * mean for weight, mean in zip(weights, means)) / total
        scores.append((1.0 - epsilon) * nominal + epsilon * worst_delta)

    return RobustMixtureSummary(
        mean=sum(scores) / draws,
        q10=quantile(scores, 0.10),
        p_gt_zero=sum(score > 0.0 for score in scores) / draws,
        worst_cell=cells[worst_index],
        worst_delta=worst_delta,
    )


def _episode_delta(records: Sequence[EpisodeRecord]) -> float:
    compared = sum(record.compared for record in records)
    return (sum(record.candidate_correct for record in records) - sum(record.baseline_correct for record in records)) / compared


def _validate_episode_records(records: Sequence[EpisodeRecord]) -> None:
    if not records:
        raise ValueError("records must be nonempty")
    if any(record.compared <= 0.0 for record in records):
        raise ValueError("every episode must have compared > 0")


def _validate_draws(draws: int) -> None:
    if draws <= 0:
        raise ValueError("draws must be positive")
