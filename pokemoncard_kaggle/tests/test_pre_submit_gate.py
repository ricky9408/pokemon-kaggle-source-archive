from __future__ import annotations

import argparse
import importlib.util
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pre_submit_gate", ROOT / "tools" / "pre_submit_gate.py")
assert SPEC and SPEC.loader
pre_submit_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pre_submit_gate
SPEC.loader.exec_module(pre_submit_gate)


def write_archive(path: Path) -> None:
    source = path.parent / path.stem
    source.mkdir()
    (source / "main.py").write_text("def deck():\n    return []\n", encoding="utf-8")
    (source / "deck.csv").write_text("card,count\n", encoding="utf-8")
    (source / "cg").mkdir()
    (source / "cg" / "__init__.py").write_text("", encoding="utf-8")
    with tarfile.open(path, "w:gz") as tar:
        tar.add(source / "main.py", arcname="main.py")
        tar.add(source / "deck.csv", arcname="deck.csv")
        tar.add(source / "cg", arcname="cg")


class PreSubmitGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.first = self.root / "submission-codex-new-v999.tar.gz"
        self.second = self.root / "submission-codex-other-v998.tar.gz"
        write_archive(self.first)
        write_archive(self.second)

        self.packet = self.root / "packet.md"
        self.packet.write_text(
            "Strategic latest-two pair: `old-a.tar.gz` then `old-b.tar.gz`\n",
            encoding="utf-8",
        )
        self.submissions = self.root / "submissions.csv"
        self.submissions.write_text(
            "ref,fileName,date,description,status,publicScore\n"
            "1,old.tar.gz,2026-06-22 00:00:00.000000,old,SubmissionStatus.COMPLETE,1000.0\n",
            encoding="utf-8",
        )
        self.backtest = self.root / "backtest.csv"
        self.backtest.write_text(
            "metric,public_target,spearman,kendall,n,required_missing,trusted\n"
            "synthetic,latest_public,0.75,0.6,5,,1\n",
            encoding="utf-8",
        )
        self.anchors = self.root / "anchors.csv"
        self.anchors.write_text(
            "candidate,archive,submit_eligible,anchor_state,reasons\n"
            "old,old.tar.gz,1,public_ok,ok\n",
            encoding="utf-8",
        )
        self.critic = self.root / "critic.md"
        self.critic.write_text(
            "Critic verdict: **PROMOTION_REVIEW**\n"
            "League coverage sufficient: True\n"
            f"{self.first.name}\n"
            f"{self.second.name}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def args(self, **overrides: object) -> argparse.Namespace:
        values: dict[str, object] = {
            "competition": "pokemon-tcg-ai-battle",
            "packet": self.packet,
            "first": str(self.first),
            "second": str(self.second),
            "first_message": "codex-new-v999",
            "second_message": "codex-other-v998",
            "submissions_output": self.submissions,
            "resolver": None,
            "selector": None,
            "backtest_summary": self.backtest,
            "league_public_gap_audit": None,
            "candidate_critic_report": self.critic,
            "safety_report": None,
            "require_candidate_critic": True,
            "require_safety_report": False,
            "anchor_status": self.anchors,
            "enforce_packet_pair": False,
            "unanchored_candidate_policy": "allow-with-promotion-critic",
            "min_backtest_spearman": 0.55,
            "min_backtest_n": 5,
            "now": "2026-06-23T12:00:00Z",
            "min_utc_hour": 0,
            "min_utc_minute": 1,
            "max_daily_submissions": 5,
            "output": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_packet_mismatch_is_advisory_by_default_for_promoted_new_candidate(self) -> None:
        report, open_gate = pre_submit_gate.gate_report(self.args())
        self.assertTrue(open_gate, report)
        self.assertIn("Packet pair advisory", report)
        self.assertIn("Gate: **OPEN**", report)

    def test_packet_is_optional_for_promoted_new_candidate(self) -> None:
        report, open_gate = pre_submit_gate.gate_report(self.args(packet=None))
        self.assertTrue(open_gate, report)
        self.assertIn("Packet pair: not supplied", report)
        self.assertIn("Gate: **OPEN**", report)

    def test_explicit_packet_enforcement_still_blocks_mismatch(self) -> None:
        report, open_gate = pre_submit_gate.gate_report(self.args(enforce_packet_pair=True))
        self.assertFalse(open_gate)
        self.assertIn("intended archives do not match the packet strategic pair", report)

    def test_selector_mismatch_blocks_dynamic_candidate(self) -> None:
        selector = self.root / "selector.md"
        selector.write_text(
            "Pair: `some-other.tar.gz` then `another-other.tar.gz`\n",
            encoding="utf-8",
        )
        report, open_gate = pre_submit_gate.gate_report(self.args(selector=selector))
        self.assertFalse(open_gate)
        self.assertIn("intended archives do not match the current pair selector", report)

    def test_direct_public_anchor_failure_still_blocks(self) -> None:
        self.anchors.write_text(
            "candidate,archive,submit_eligible,anchor_state,reasons\n"
            f"new,{self.first.name},0,public_fail,family_med=700<800\n",
            encoding="utf-8",
        )
        report, open_gate = pre_submit_gate.gate_report(self.args())
        self.assertFalse(open_gate)
        self.assertIn("public-anchor gate failed (public_fail)", report)


if __name__ == "__main__":
    unittest.main()
