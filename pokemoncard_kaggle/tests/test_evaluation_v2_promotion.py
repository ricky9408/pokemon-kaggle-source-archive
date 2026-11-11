from __future__ import annotations

import hashlib
import json
from pathlib import Path

from evaluation_v2.promotion import compose_promotion_verdict


def _write(path: Path, value: dict) -> Path:
    path.write_text(json.dumps(value))
    return path


def test_promotion_binds_archive_and_requires_shadow_and_holdout(tmp_path: Path) -> None:
    archive = tmp_path / "submission-codex-test-v999.tar.gz"
    archive.write_bytes(b"archive")
    digest = hashlib.sha256(b"archive").hexdigest()
    transfer = _write(
        tmp_path / "transfer.json",
        {"schema": "public_transfer_validation_v1", "transfer_certified": True, "panel_id": "p"},
    )
    candidate = _write(
        tmp_path / "candidate.json",
        {
            "schema": "candidate_matched_outcome_v1",
            "passed": True,
            "candidate_label": "codex-test-v999",
            "candidate_identity": {"archive_sha256": digest},
        },
    )
    safety = _write(
        tmp_path / "safety.json",
        {"schema": "candidate_safety_burnin_v1", "passed": True, "archive_sha256": digest},
    )
    closed = compose_promotion_verdict(
        archive_path=archive,
        transfer_path=transfer,
        candidate_path=candidate,
        safety_path=safety,
    )
    assert not closed["preholdout_open"]
    assert not closed["submit_open"]
    shadow = _write(
        tmp_path / "shadow.json",
        {"schema": "prospective_shadow_validation_v1", "certified": True},
    )
    holdout = _write(
        tmp_path / "holdout.json",
        {
            "schema": "sealed_holdout_verdict_v1",
            "passed": True,
            "archive_sha256": digest,
            "episodes": 50,
        },
    )
    opened = compose_promotion_verdict(
        archive_path=archive,
        transfer_path=transfer,
        candidate_path=candidate,
        safety_path=safety,
        prospective_shadow_path=shadow,
        holdout_path=holdout,
    )
    assert opened["submit_open"]


def test_promotion_rejects_final_name(tmp_path: Path) -> None:
    archive = tmp_path / "submission-codex-final-v999.tar.gz"
    archive.write_bytes(b"archive")
    digest = hashlib.sha256(b"archive").hexdigest()
    transfer = _write(tmp_path / "t", {"schema": "public_transfer_validation_v1", "transfer_certified": True})
    candidate = _write(
        tmp_path / "c",
        {"schema": "candidate_matched_outcome_v1", "passed": True, "candidate_label": "codex-v999", "candidate_identity": {"archive_sha256": digest}},
    )
    safety = _write(tmp_path / "s", {"schema": "candidate_safety_burnin_v1", "passed": True, "archive_sha256": digest})
    result = compose_promotion_verdict(
        archive_path=archive,
        transfer_path=transfer,
        candidate_path=candidate,
        safety_path=safety,
    )
    assert not result["preholdout_open"]
