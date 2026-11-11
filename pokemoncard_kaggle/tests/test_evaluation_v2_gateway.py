from __future__ import annotations

from evaluation_v2.arena import ArenaEvidence
from evaluation_v2.gateway import decide
from evaluation_v2.meta import DeckMetaEvidence
from evaluation_v2.statistics import BootstrapSummary, RobustMixtureSummary


def _evidence():
    replay = {
        "episodes": 22,
        "main_compared": 800,
        "candidate_main_agreement": 0.65,
        "main_agreement_delta": 0.08,
        "main_fixes": 160,
        "main_regressions": 80,
        "teacher_teams": 3,
    }
    bootstrap = BootstrapSummary(0.08, 0.05, 0.08, 0.11, 0.99, 22, 2000)
    meta = DeckMetaEvidence("d", 5, 8, 64, 1, 1289.0, 1085.0, 204.0, ("a", "b", "c", "d", "e"))
    arena = ArenaEvidence(
        "c", "b", 6, 24, 24, 0, {"x": 0.0}, {"x": {"mean": 0.5}},
        RobustMixtureSummary(0.03, 0.02, 0.8, "x", 0.01),
    )
    return replay, bootstrap, meta, arena


def test_gate_opens_for_complete_accepted_exploration_evidence() -> None:
    replay, bootstrap, meta, arena = _evidence()
    verdict = decide(hard_checks={"safe": True}, replay=replay, bootstrap=bootstrap, meta=meta, arena=arena)
    assert verdict.open
    assert verdict.mode == "accepted_exploration"


def test_any_hard_failure_closes_gate() -> None:
    replay, bootstrap, meta, arena = _evidence()
    verdict = decide(hard_checks={"safe": False}, replay=replay, bootstrap=bootstrap, meta=meta, arena=arena)
    assert not verdict.open
