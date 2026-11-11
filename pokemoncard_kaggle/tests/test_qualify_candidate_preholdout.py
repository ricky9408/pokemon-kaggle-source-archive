from argparse import Namespace
import json

from tools.qualify_candidate import _write_preholdout_failure


def test_preholdout_failure_records_that_holdout_was_not_opened(tmp_path) -> None:
    args = Namespace(
        label="candidate",
        archive=tmp_path / "candidate.tar.gz",
        output_dir=tmp_path / "run",
    )

    status = _write_preholdout_failure(
        args,
        archive_hash="a" * 64,
        candidate_fingerprints={"agent_sha256": "b" * 64},
        manifest_id="cohort-1",
        hard_checks={"archive_clean": True, "cross_process_policy_determinism": False},
        determinism=[{"transcript_sha256": "one"}, {"transcript_sha256": "two"}],
    )

    payload = json.loads((args.output_dir / "verdict.json").read_text())
    assert status == 2
    assert payload["stage"] == "preholdout_closed"
    assert payload["holdout_opened"] is False
    assert payload["failed_checks"] == ["cross_process_policy_determinism"]
