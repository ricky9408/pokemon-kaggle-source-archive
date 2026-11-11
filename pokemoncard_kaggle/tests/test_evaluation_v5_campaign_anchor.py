from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import pytest

import evaluation_v5.campaign_anchor as anchor


POLICY = "1.2.3.4.5"


def _utc(minutes: int) -> str:
    return (
        datetime(2026, 7, 14, tzinfo=timezone.utc) + timedelta(minutes=minutes)
    ).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _payload(*, opened_at: str | None = None) -> dict[str, str]:
    return anchor.build_campaign_anchor_payload(
        architecture_binding_sha256="a" * 64,
        implementation_binding_sha256="b" * 64,
        campaign_sha256="c" * 64,
        trust_roots_snapshot_sha256="d" * 64,
        campaign_opened_at_utc=opened_at or _utc(10),
    )


def _write_inputs(tmp_path: Path, payload: dict[str, str]) -> tuple[Path, Path, Path, str]:
    payload_path = tmp_path / "campaign.json"
    token_path = tmp_path / "campaign.tsr"
    ca_path = tmp_path / "tsa-ca.pem"
    payload_path.write_bytes(anchor.canonical_campaign_anchor_payload_bytes(payload))
    token_path.write_bytes(b"raw RFC3161 token bytes")
    ca_path.write_bytes(b"pinned CA bytes")
    return payload_path, token_path, ca_path, hashlib.sha256(ca_path.read_bytes()).hexdigest()


def _runner(payload_sha: str, token_sha: str, ca_sha: str, *, policy: str = POLICY, granted: str | None = None):
    def verify(**kwargs: object) -> dict[str, object]:
        assert kwargs["data_path"]
        return {
            "verified": True,
            "data_sha256": payload_sha,
            "token_sha256": token_sha,
            "ca_file_sha256": ca_sha,
            "tsa_policy_oid": policy,
            "tsa_serial": "serial-1",
            "granted_at_utc": granted or _utc(1),
        }

    return verify


def test_build_write_and_verify_raw_campaign_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _payload()
    payload_path = tmp_path / "campaign.json"
    assert anchor.write_campaign_anchor_payload_once(payload_path, payload) == payload_path
    with pytest.raises(anchor.CampaignAnchorError, match="already exists"):
        anchor.write_campaign_anchor_payload_once(payload_path, payload)
    token_path = tmp_path / "campaign.tsr"
    ca_path = tmp_path / "tsa-ca.pem"
    token_path.write_bytes(b"raw RFC3161 token bytes")
    ca_path.write_bytes(b"pinned CA bytes")
    ca_sha = hashlib.sha256(ca_path.read_bytes()).hexdigest()
    payload_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
    token_sha = hashlib.sha256(token_path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        anchor,
        "verify_rfc3161_token",
        _runner(payload_sha, token_sha, ca_sha),
    )

    result = anchor.verify_campaign_anchor(
        payload_path=payload_path,
        token_path=token_path,
        ca_file=ca_path,
        expected_ca_file_sha256=ca_sha,
        expected_tsa_policy_oid=POLICY,
    )

    assert result["verified"] is True
    assert result["campaign_sha256"] == payload["campaign_sha256"]
    assert result["authority"] is result["submission"] is result["holdout"] is False
    assert result["evidence_sha256"] == anchor.canonical_sha256(
        {key: value for key, value in result.items() if key != "evidence_sha256"}
    )


def test_payload_tamper_is_rejected_before_raw_verification(tmp_path: Path) -> None:
    payload_path, _, _, _ = _write_inputs(tmp_path, _payload())
    raw = payload_path.read_bytes().replace(b'"campaign_sha256":"' + b"c" * 64, b'"campaign_sha256":"' + b"e" * 64)
    payload_path.write_bytes(raw)
    with pytest.raises(anchor.CampaignAnchorError, match="canonical|payload"):
        anchor.verify_campaign_anchor(
            payload_path=payload_path,
            token_path=tmp_path / "missing-token",
            ca_file=tmp_path / "missing-ca",
            expected_ca_file_sha256="f" * 64,
            expected_tsa_policy_oid=POLICY,
        )


@pytest.mark.parametrize(
    ("receipt_policy", "expected_ca", "message"),
    [("9.9.9", None, "policy"), (POLICY, "f" * 64, "CA file SHA")],
)
def test_wrong_pinned_ca_or_policy_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_policy: str,
    expected_ca: str | None,
    message: str,
) -> None:
    payload = _payload()
    payload_path, token_path, ca_path, ca_sha = _write_inputs(tmp_path, payload)
    payload_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
    token_sha = hashlib.sha256(token_path.read_bytes()).hexdigest()
    monkeypatch.setattr(anchor, "verify_rfc3161_token", _runner(payload_sha, token_sha, ca_sha, policy=receipt_policy))
    with pytest.raises(anchor.CampaignAnchorError, match=message):
        anchor.verify_campaign_anchor(
            payload_path=payload_path,
            token_path=token_path,
            ca_file=ca_path,
            expected_ca_file_sha256=expected_ca or ca_sha,
            expected_tsa_policy_oid=POLICY,
        )


def test_grant_must_precede_campaign_opening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _payload(opened_at=_utc(1))
    payload_path, token_path, ca_path, ca_sha = _write_inputs(tmp_path, payload)
    payload_sha = hashlib.sha256(payload_path.read_bytes()).hexdigest()
    token_sha = hashlib.sha256(token_path.read_bytes()).hexdigest()
    monkeypatch.setattr(anchor, "verify_rfc3161_token", _runner(payload_sha, token_sha, ca_sha, granted=_utc(1)))
    with pytest.raises(anchor.CampaignAnchorError, match="strictly before campaign opening"):
        anchor.verify_campaign_anchor(
            payload_path=payload_path,
            token_path=token_path,
            ca_file=ca_path,
            expected_ca_file_sha256=ca_sha,
            expected_tsa_policy_oid=POLICY,
        )


@pytest.mark.parametrize("field", ["payload_path", "token_path", "ca_file"])
def test_symlink_inputs_are_rejected(tmp_path: Path, field: str) -> None:
    payload = _payload()
    payload_path, token_path, ca_path, ca_sha = _write_inputs(tmp_path, payload)
    target = {"payload_path": payload_path, "token_path": token_path, "ca_file": ca_path}[field]
    real = tmp_path / f"real-{field}"
    target.rename(real)
    target.symlink_to(real)
    with pytest.raises(anchor.CampaignAnchorError, match="symlink"):
        anchor.verify_campaign_anchor(
            payload_path=payload_path,
            token_path=token_path,
            ca_file=ca_path,
            expected_ca_file_sha256=ca_sha,
            expected_tsa_policy_oid=POLICY,
        )
