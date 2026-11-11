"""A gate that can open without pretending local diagnostics predict Elo."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .arena import ArenaEvidence
from .meta import DeckMetaEvidence
from .statistics import BootstrapSummary


@dataclass(frozen=True)
class GateThresholds:
    min_holdout_episodes: int = 20
    min_main_decisions: int = 600
    min_candidate_main_agreement: float = 0.55
    min_main_agreement_delta: float = 0.04
    min_bootstrap_q10: float = 0.05
    min_bootstrap_probability: float = 0.95
    max_regressions_per_fix: float = 0.80
    min_teacher_teams: int = 3
    min_exact_deck_teams: int = 3
    min_exact_deck_submissions: int = 3
    min_exact_deck_episodes: int = 24
    max_best_deck_rank: int = 3
    min_deck_margin_over_rank10: float = 100.0
    min_arena_shared_opponents: int = 5
    min_arena_games_per_policy: int = 20
    min_arena_robust_q10: float = 0.00


@dataclass(frozen=True)
class GateCheck:
    name: str
    passed: bool
    actual: Any
    requirement: str
    trust: str


@dataclass(frozen=True)
class GateVerdict:
    open: bool
    mode: str
    checks: tuple[GateCheck, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "open": self.open,
            "mode": self.mode,
            "checks": [asdict(check) for check in self.checks],
            "limitations": list(self.limitations),
        }


def decide(
    *,
    hard_checks: dict[str, bool],
    replay: dict[str, Any],
    bootstrap: BootstrapSummary,
    meta: DeckMetaEvidence,
    arena: ArenaEvidence,
    thresholds: GateThresholds | None = None,
) -> GateVerdict:
    limits = thresholds or GateThresholds()
    checks: list[GateCheck] = []

    def add(name: str, passed: bool, actual: Any, requirement: str, trust: str) -> None:
        checks.append(GateCheck(name, bool(passed), actual, requirement, trust))

    for name, passed in hard_checks.items():
        add(name, passed, passed, "must pass", "hard")
    fixes = int(replay.get("main_fixes", 0))
    regressions = int(replay.get("main_regressions", 0))
    regression_ratio = regressions / fixes if fixes else float("inf")
    add("holdout_episode_count", int(replay["episodes"]) >= limits.min_holdout_episodes, replay["episodes"], f">={limits.min_holdout_episodes}", "paired teacher diagnostic")
    add("holdout_main_decisions", int(replay["main_compared"]) >= limits.min_main_decisions, replay["main_compared"], f">={limits.min_main_decisions}", "paired teacher diagnostic")
    add("candidate_main_agreement", float(replay["candidate_main_agreement"]) >= limits.min_candidate_main_agreement, replay["candidate_main_agreement"], f">={limits.min_candidate_main_agreement:.3f}", "teacher imitation, not optimality")
    add("paired_main_delta", float(replay["main_agreement_delta"]) >= limits.min_main_agreement_delta, replay["main_agreement_delta"], f">={limits.min_main_agreement_delta:.3f}", "paired teacher diagnostic")
    add("episode_bootstrap_q10", bootstrap.q10 >= limits.min_bootstrap_q10, bootstrap.q10, f">={limits.min_bootstrap_q10:.3f}", "clustered uncertainty")
    add("episode_bootstrap_probability", bootstrap.p_gt_zero >= limits.min_bootstrap_probability, bootstrap.p_gt_zero, f">={limits.min_bootstrap_probability:.3f}", "clustered uncertainty")
    add("teacher_regression_ratio", regression_ratio <= limits.max_regressions_per_fix, regression_ratio, f"<={limits.max_regressions_per_fix:.2f}", "teacher imitation guard")
    add("independent_teacher_teams", int(replay.get("teacher_teams", 0)) >= limits.min_teacher_teams, replay.get("teacher_teams", 0), f">={limits.min_teacher_teams}", "multi-pilot generalization guard")
    add("exact_deck_teams", meta.exact_teams >= limits.min_exact_deck_teams, meta.exact_teams, f">={limits.min_exact_deck_teams}", "current public deck prior")
    add("exact_deck_submissions", meta.exact_submissions >= limits.min_exact_deck_submissions, meta.exact_submissions, f">={limits.min_exact_deck_submissions}", "current public deck prior")
    add("exact_deck_replays", meta.observed_episodes >= limits.min_exact_deck_episodes, meta.observed_episodes, f">={limits.min_exact_deck_episodes}", "current public deck prior")
    add("exact_deck_best_rank", meta.best_rank <= limits.max_best_deck_rank, meta.best_rank, f"<={limits.max_best_deck_rank}", "current public deck prior")
    add("deck_margin_over_rank10", meta.margin_over_rank10 >= limits.min_deck_margin_over_rank10, meta.margin_over_rank10, f">={limits.min_deck_margin_over_rank10:.1f}", "current public deck prior")
    add("arena_errors", arena.errors == 0, arena.errors, "==0", "official-wrapper hard diagnostic")
    add("arena_shared_opponents", arena.shared_opponents >= limits.min_arena_shared_opponents, arena.shared_opponents, f">={limits.min_arena_shared_opponents}", "local noninferiority only")
    add("arena_candidate_games", arena.candidate_games >= limits.min_arena_games_per_policy, arena.candidate_games, f">={limits.min_arena_games_per_policy}", "local noninferiority only")
    add("arena_baseline_games", arena.baseline_games >= limits.min_arena_games_per_policy, arena.baseline_games, f">={limits.min_arena_games_per_policy}", "local noninferiority only")
    add("arena_robust_q10", arena.robust.q10 >= limits.min_arena_robust_q10, arena.robust.q10, f">={limits.min_arena_robust_q10:.3f}", "local noninferiority only")
    opened = all(check.passed for check in checks)
    return GateVerdict(
        open=opened,
        mode="accepted_exploration" if opened else "closed",
        checks=tuple(checks),
        limitations=(
            "No prospectively validated public-score surrogate exists yet.",
            "Public teacher actions are behavior evidence, not optimal-action labels.",
            "cabt results guard only against catastrophic local regressions and do not forecast public rating.",
            "A submitted score remains immature for one hour after COMPLETE.",
        ),
    )
