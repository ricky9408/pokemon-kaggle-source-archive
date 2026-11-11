from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from evaluation_v4_1.timestamping import (
    TimestampVerificationError,
    verify_anchor_chronology,
    verify_rfc3161_token,
    write_receipt_once,
)


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "strategy" / "pre_submission_selector_v4_retirement_20260711.md"
TOKEN = ROOT / "evaluation_artifacts" / "whole_policy_v4" / "retirement_timestamp.tsr"
CA_FILE = Path("/etc/ssl/cert.pem")


@pytest.mark.skipif(
    shutil.which("openssl") is None or not CA_FILE.is_file() or not TOKEN.is_file(),
    reason="OpenSSL, CA bundle, and committed RFC 3161 fixture are required",
)
def test_committed_rfc3161_fixture_verifies_exact_bytes() -> None:
    receipt = verify_rfc3161_token(data_path=DATA, token_path=TOKEN, ca_file=CA_FILE)

    assert receipt["verified"] is True
    assert receipt["data_sha256"] == "49c4913701b7afc4389ff4c8345a068be4f78ca4db786ecf07255dab0b900a57"
    assert receipt["token_sha256"] == "c11a2bc89face42bd7dd37f56b838493d73f652cc78fcca92202bb86cc6ca9c3"
    assert receipt["granted_at_utc"] == "2026-07-11T08:04:35.000000Z"
    assert receipt["performance_evidence"] is False
    assert receipt["production_submission_authorized"] is False


@pytest.mark.skipif(
    shutil.which("openssl") is None or not CA_FILE.is_file() or not TOKEN.is_file(),
    reason="OpenSSL, CA bundle, and committed RFC 3161 fixture are required",
)
def test_timestamp_rejects_mutated_data(tmp_path: Path) -> None:
    mutated = tmp_path / "mutated.md"
    mutated.write_bytes(DATA.read_bytes() + b"\nmutation\n")

    with pytest.raises(TimestampVerificationError):
        verify_rfc3161_token(data_path=mutated, token_path=TOKEN, ca_file=CA_FILE)


def test_anchor_chronology_is_strict() -> None:
    receipt = {
        "schema": "rfc3161_registration_anchor_v1",
        "verified": True,
        "granted_at_utc": "2026-07-11T08:00:00.000000Z",
    }
    result = verify_anchor_chronology(
        receipt,
        submission_created_at_utc="2026-07-11T08:01:00.000000Z",
        first_game_created_at_utc="2026-07-11T08:02:00.000000Z",
    )
    assert result["submission_created_at_utc"] == "2026-07-11T08:01:00.000000Z"

    with pytest.raises(TimestampVerificationError, match="strictly before submission"):
        verify_anchor_chronology(
            receipt,
            submission_created_at_utc="2026-07-11T08:00:00.000000Z",
            first_game_created_at_utc="2026-07-11T08:02:00.000000Z",
        )
    with pytest.raises(TimestampVerificationError, match="strictly before first"):
        verify_anchor_chronology(
            receipt,
            submission_created_at_utc="2026-07-11T08:01:00.000000Z",
            first_game_created_at_utc="2026-07-11T08:01:00.000000Z",
        )


@pytest.mark.skipif(
    shutil.which("openssl") is None or not CA_FILE.is_file() or not TOKEN.is_file(),
    reason="OpenSSL, CA bundle, and committed RFC 3161 fixture are required",
)
def test_timestamp_receipt_is_verified_and_create_once(tmp_path: Path) -> None:
    target = tmp_path / "receipt.json"
    write_receipt_once(target, data_path=DATA, token_path=TOKEN, ca_file=CA_FILE)
    with pytest.raises(FileExistsError):
        write_receipt_once(target, data_path=DATA, token_path=TOKEN, ca_file=CA_FILE)
