from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess

import pytest

import evaluation_v5.custody_anchor as module
from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.cohort import append_registration, build_archive_registration, new_registry
from evaluation_v5.custody_anchor import (
    CustodyAnchorError,
    build_custody_anchor_payload,
    canonical_custody_anchor_payload_bytes,
    verify_custody_anchor,
    verify_custody_anchor_batch,
    write_custody_anchor_payload_once,
)


def _utc(minute: int) -> str:
    value = datetime(2026, 7, 14, tzinfo=timezone.utc) + timedelta(minutes=minute)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _registration(archive: str, model_input: str, registered_at_utc: str) -> dict[str, object]:
    return build_archive_registration(
        archive_sha256=archive,
        deck_sha256="b" * 64,
        policy_sha256="c" * 64,
        model_input_sha256=model_input,
        family_provenance={"family": archive[:8]},
        team_pseudonym=f"team-{archive[:4]}",
        submission_slot_id=f"slot-{archive[:4]}",
        intended_window_start_utc=_utc(1),
        intended_window_end_utc=_utc(20),
        consent_sha256="e" * 64,
        registered_at_utc=registered_at_utc,
    )


def _registry() -> dict[str, object]:
    registry = append_registration(new_registry(), _registration("a" * 64, "d" * 64, _utc(2)))
    return append_registration(registry, _registration("f" * 64, "1" * 64, _utc(3)))


def _runner(expected_payload_sha256: str, *, granted_at_utc: str = _utc(1)):
    granted = datetime.strptime(granted_at_utc, "%Y-%m-%dT%H:%M:%S.%fZ")

    def run(command, **_kwargs):
        if command[1:3] == ["ts", "-verify"]:
            data = Path(command[command.index("-data") + 1]).read_bytes()
            ok = hashlib.sha256(data).hexdigest() == expected_payload_sha256
            return subprocess.CompletedProcess(command, 0 if ok else 1, "Verification: OK\n" if ok else "", "bad data")
        if command[1:3] == ["ts", "-reply"]:
            text = (
                "Status: Granted.\n"
                "Hash Algorithm: sha256\n"
                "Policy OID: 1.2.3.4\n"
                "Serial number: 0A\n"
                f"Time stamp: {granted.strftime('%b %d %H:%M:%S %Y GMT')}\n"
            )
            return subprocess.CompletedProcess(command, 0, text, "")
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, "OpenSSL mock\n", "")
        raise AssertionError(command)

    return run


def _paths(tmp_path: Path, payload: dict[str, str], *, name: str = "anchor") -> dict[str, Path]:
    payload_path = tmp_path / f"{name}.json"
    write_custody_anchor_payload_once(payload_path, payload)
    token_path = tmp_path / f"{name}.tsr"
    token_path.write_bytes(b"raw mocked RFC3161 token")
    ca_file = tmp_path / f"{name}.pem"
    ca_file.write_bytes(b"raw mocked CA bundle")
    return {"payload_path": payload_path, "token_path": token_path, "ca_file": ca_file}


def _payload(registry: dict[str, object], index: int = 0, **changes: str) -> dict[str, str]:
    registration = registry["records"][index]
    payload = build_custody_anchor_payload(
        campaign_sha256="2" * 64,
        implementation_binding_sha256="3" * 64,
        signed_ancestry_manifest_sha256="4" * 64,
        archive_registration_sha256=canonical_sha256(registration),
        registry_chain_hash_at_registration=registry["chain_hashes"][index],
        model_input_sha256=registration["model_input_sha256"],
        registered_at_utc=registration["registered_at_utc"],
    )
    return {**payload, **changes}


def test_valid_raw_token_anchor_is_canonical_and_authority_free(tmp_path: Path) -> None:
    registry = _registry()
    payload = _payload(registry)
    paths = _paths(tmp_path, payload)
    result = verify_custody_anchor(
        **paths,
        first_hosted_game_at_utc=_utc(4),
        runner=_runner(hashlib.sha256(canonical_custody_anchor_payload_bytes(payload)).hexdigest()),
    )

    assert result["verified"] is True
    assert result["authority"] is False
    assert result["submission"] is False
    assert result["holdout"] is False
    assert result["registered_at_utc"] == _utc(2)
    assert result["evidence_sha256"] == canonical_sha256(
        {key: value for key, value in result.items() if key != "evidence_sha256"}
    )


def test_handwritten_receipt_is_not_an_api_and_payload_mutation_fails(tmp_path: Path) -> None:
    registry = _registry()
    payload = _payload(registry)
    paths = _paths(tmp_path, payload)
    expected = hashlib.sha256(canonical_custody_anchor_payload_bytes(payload)).hexdigest()
    with pytest.raises(TypeError):
        verify_custody_anchor(**paths, first_hosted_game_at_utc=_utc(4), receipt={})

    paths["payload_path"].write_bytes(canonical_custody_anchor_payload_bytes(_payload(registry, campaign_sha256="5" * 64)))
    with pytest.raises(CustodyAnchorError, match="RFC 3161 verification failed"):
        verify_custody_anchor(
            **paths, first_hosted_game_at_utc=_utc(4), runner=_runner(expected)
        )


@pytest.mark.parametrize("granted,first_game,error", [(_utc(2), _utc(4), "strictly before registration"), (_utc(1), _utc(2), "strictly before first hosted")])
def test_anchor_chronology_is_strict(tmp_path: Path, granted: str, first_game: str, error: str) -> None:
    registry = _registry()
    payload = _payload(registry)
    paths = _paths(tmp_path, payload)
    with pytest.raises(CustodyAnchorError, match=error):
        verify_custody_anchor(
            **paths,
            first_hosted_game_at_utc=first_game,
            runner=_runner(hashlib.sha256(canonical_custody_anchor_payload_bytes(payload)).hexdigest(), granted_at_utc=granted),
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("model_input_sha256", "9" * 64, "model input binding"),
        ("campaign_sha256", "9" * 64, "campaign binding"),
        ("archive_registration_sha256", "9" * 64, "does not bind one exact"),
    ],
)
def test_batch_rejects_wrong_registry_model_or_campaign_binding(
    tmp_path: Path, field: str, value: str, error: str
) -> None:
    registry = _registry()
    payload = _payload(registry, **{field: value})
    paths = _paths(tmp_path, payload)
    with pytest.raises(CustodyAnchorError, match=error):
        verify_custody_anchor_batch(
            registry=registry,
            anchors=[paths],
            campaign_sha256="2" * 64,
            implementation_binding_sha256="3" * 64,
            signed_ancestry_manifest_sha256="4" * 64,
            first_hosted_game_at_utc_by_archive={"a" * 64: _utc(4), "f" * 64: _utc(5)},
            runner=_runner(hashlib.sha256(canonical_custody_anchor_payload_bytes(payload)).hexdigest()),
        )


def test_batch_requires_exactly_one_anchor_per_archive(tmp_path: Path) -> None:
    registry = _registry()
    first = _payload(registry, 0)
    second = _payload(registry, 1)
    first_paths = _paths(tmp_path, first, name="first")
    second_paths = _paths(tmp_path, second, name="second")
    runners = _runner(hashlib.sha256(canonical_custody_anchor_payload_bytes(first)).hexdigest())
    with pytest.raises(CustodyAnchorError, match="missing custody anchor"):
        verify_custody_anchor_batch(
            registry=registry,
            anchors=[first_paths],
            campaign_sha256="2" * 64,
            implementation_binding_sha256="3" * 64,
            signed_ancestry_manifest_sha256="4" * 64,
            first_hosted_game_at_utc_by_archive={"a" * 64: _utc(4), "f" * 64: _utc(5)},
            runner=runners,
        )
    with pytest.raises(CustodyAnchorError, match="duplicate custody anchor"):
        verify_custody_anchor_batch(
            registry=registry,
            anchors=[first_paths, first_paths],
            campaign_sha256="2" * 64,
            implementation_binding_sha256="3" * 64,
            signed_ancestry_manifest_sha256="4" * 64,
            first_hosted_game_at_utc_by_archive={"a" * 64: _utc(4), "f" * 64: _utc(5)},
            runner=runners,
        )

    def multi_runner(command, **kwargs):
        expected = hashlib.sha256(canonical_custody_anchor_payload_bytes(first)).hexdigest()
        if "-data" in command and Path(command[command.index("-data") + 1]).name != "first.json":
            expected = hashlib.sha256(canonical_custody_anchor_payload_bytes(second)).hexdigest()
        return _runner(expected)(command, **kwargs)

    audit = verify_custody_anchor_batch(
        registry=registry,
        anchors=[second_paths, first_paths],
        campaign_sha256="2" * 64,
        implementation_binding_sha256="3" * 64,
        signed_ancestry_manifest_sha256="4" * 64,
        first_hosted_game_at_utc_by_archive={"a" * 64: _utc(4), "f" * 64: _utc(5)},
        runner=multi_runner,
    )
    assert audit["authority"] is audit["submission"] is audit["holdout"] is False
    assert len(audit["anchors"]) == 2


def test_batch_rejects_payload_substitution_between_match_and_verify(
    monkeypatch, tmp_path: Path
) -> None:
    registry = _registry()
    first = _payload(registry, 0)
    second = _payload(registry, 1)
    first_paths = _paths(tmp_path, first, name="first-swap")
    second_paths = _paths(tmp_path, second, name="second-swap")

    def swapped_anchor(**_kwargs):
        return {
            **second,
            "payload_sha256": hashlib.sha256(
                canonical_custody_anchor_payload_bytes(second)
            ).hexdigest(),
        }

    monkeypatch.setattr(module, "verify_custody_anchor", swapped_anchor)
    with pytest.raises(CustodyAnchorError, match="changed between"):
        module.verify_custody_anchor_batch(
            registry=registry,
            anchors=[first_paths, second_paths],
            campaign_sha256="2" * 64,
            implementation_binding_sha256="3" * 64,
            signed_ancestry_manifest_sha256="4" * 64,
            first_hosted_game_at_utc_by_archive={
                "a" * 64: _utc(4),
                "f" * 64: _utc(5),
            },
        )


def test_payload_writer_refuses_overwrite_and_symlink_inputs(tmp_path: Path) -> None:
    registry = _registry()
    payload = _payload(registry)
    target = tmp_path / "anchor.json"
    write_custody_anchor_payload_once(target, payload)
    with pytest.raises(CustodyAnchorError, match="already exists"):
        write_custody_anchor_payload_once(target, payload)

    paths = _paths(tmp_path, payload, name="symlink")
    symlink = tmp_path / "payload-link.json"
    symlink.symlink_to(paths["payload_path"])
    with pytest.raises(CustodyAnchorError, match="must not be a symlink"):
        verify_custody_anchor(
            payload_path=symlink,
            token_path=paths["token_path"],
            ca_file=paths["ca_file"],
            first_hosted_game_at_utc=_utc(4),
            runner=_runner(hashlib.sha256(canonical_custody_anchor_payload_bytes(payload)).hexdigest()),
        )
