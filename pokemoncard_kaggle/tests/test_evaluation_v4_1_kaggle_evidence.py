from __future__ import annotations

from pathlib import Path
import hashlib
import json
import shutil
import subprocess

import pytest

import evaluation_v4_1.kaggle_evidence as evidence_module
from evaluation_v4_1.kaggle_evidence import (
    KaggleEvidenceError,
    authenticated_upload_preflight,
    capture_authenticated_pair,
    load_exact_archive_bytes,
    reverify_authenticated_pair_capture_online,
    submit_exact_archive_once,
    validate_authenticated_pair_capture,
)
from tests.test_evaluation_v4_1_chronology import _fixture


def test_direct_authenticated_capture_builds_and_revalidates_raw_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    source_by_ref = {
        row["submission_receipt"]["submission_ref"]: row
        for row in fixture["pair_evidence"].values()
    }

    def fake_run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
        assert cwd == Path(fixture["artifacts"]["kaggle_runtime_binding"]["workspace_root"])
        assert command[0] == fixture["artifacts"]["kaggle_runtime_binding"]["kaggle_entrypoint"]
        if "submissions" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=fixture["submissions"].read_bytes(),
                stderr=b"",
            )
        if "episodes" in command:
            submission_ref = command[-1]
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(source_by_ref[submission_ref]["submission_directory"] / "episodes.csv").read_bytes(),
                stderr=b"",
            )
        if "replay" in command:
            episode_id = command[-1]
            target = Path(command[command.index("-p") + 1])
            submission_ref = target.name.removeprefix("submission_")
            shutil.copy2(
                source_by_ref[submission_ref]["submission_directory"]
                / f"episode-{episode_id}-replay.json",
                target / f"episode-{episode_id}-replay.json",
            )
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        raise AssertionError(command)

    monkeypatch.setattr(evidence_module, "_run", fake_run)
    def fake_replay_bytes(_: object, episode_id: str) -> bytes:
        matches = [
            row["submission_directory"] / f"episode-{episode_id}-replay.json"
            for row in source_by_ref.values()
            if (row["submission_directory"] / f"episode-{episode_id}-replay.json").is_file()
        ]
        assert len(matches) == 1
        return matches[0].read_bytes()

    monkeypatch.setattr(evidence_module, "_download_replay_bytes", fake_replay_bytes)
    package = capture_authenticated_pair(
        authorization=fixture["authorization"],
        pair_id=fixture["pair_id"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
        permits_by_lineage_uuid={
            lineage_uuid: row["permit"] for lineage_uuid, row in fixture["pair_evidence"].items()
        },
        submission_refs_by_lineage_uuid={
            lineage_uuid: row["submission_receipt"]["submission_ref"]
            for lineage_uuid, row in fixture["pair_evidence"].items()
        },
        descriptions_by_lineage_uuid={
            lineage_uuid: row["submission_receipt"]["submission_description"]
            for lineage_uuid, row in fixture["pair_evidence"].items()
        },
        local_archives_by_lineage_uuid={
            lineage_uuid: row["local_archive"]
            for lineage_uuid, row in fixture["pair_evidence"].items()
        },
        team_name="GarlicToday",
        capture_directory=tmp_path / "authenticated-capture",
    )
    assert package["pair_completion_barrier"]["horizon_games_per_member"] == 24
    assert package["production_submission_authorized"] is False
    assert validate_authenticated_pair_capture(
        package,
        authorization=fixture["authorization"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
    ) == package
    live_snapshot = reverify_authenticated_pair_capture_online(
        package,
        authorization=fixture["authorization"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
    )
    assert live_snapshot["capture_content_sha256"] == package["content_sha256"]
    assert live_snapshot["pair_completion_barrier"] == package["pair_completion_barrier"]
    original_package = json.loads(json.dumps(package))
    original_snapshot_call = evidence_module._submissions_snapshot
    package_mutated = False

    def mutate_caller_package_after_detach(*args: object, **kwargs: object):
        nonlocal package_mutated
        package["pair_completion_barrier"]["content_sha256"] = "0" * 64
        package_mutated = True
        return original_snapshot_call(*args, **kwargs)

    monkeypatch.setattr(
        evidence_module,
        "_submissions_snapshot",
        mutate_caller_package_after_detach,
    )
    detached_snapshot = reverify_authenticated_pair_capture_online(
        package,
        authorization=fixture["authorization"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
    )
    assert package_mutated is True
    assert detached_snapshot["pair_completion_barrier"] == original_package["pair_completion_barrier"]
    package.clear()
    package.update(original_package)
    monkeypatch.setattr(evidence_module, "_submissions_snapshot", original_snapshot_call)
    for item in package["member_evidence_manifest"].values():
        Path(item["local_archive"]).unlink()
    assert reverify_authenticated_pair_capture_online(
        package,
        authorization=fixture["authorization"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
    )["pair_completion_barrier"] == live_snapshot["pair_completion_barrier"]

    submission_ref, replay_shas = next(
        iter(package["replay_sha256_by_submission_ref"].items())
    )
    episode_id = next(iter(replay_shas))
    replay = (
        Path(package["capture_directory"])
        / f"submission_{submission_ref}"
        / f"episode-{episode_id}-replay.json"
    )
    original_replay_bytes = replay.read_bytes()
    original_download = evidence_module._download_replay_bytes
    swapped = False

    def swap_journal_after_authenticated_download(runtime: object, requested_id: str) -> bytes:
        nonlocal swapped
        payload = original_download(runtime, requested_id)
        if not swapped:
            replay.write_text("{}", encoding="utf-8")
            swapped = True
        return payload

    monkeypatch.setattr(
        evidence_module,
        "_download_replay_bytes",
        swap_journal_after_authenticated_download,
    )
    raced_snapshot = reverify_authenticated_pair_capture_online(
        package,
        authorization=fixture["authorization"],
        usage_ledger_path=fixture["ledger"],
        artifacts=fixture["artifacts"],
    )
    assert swapped is True
    assert raced_snapshot["pair_completion_barrier"] == live_snapshot["pair_completion_barrier"]
    replay.write_bytes(original_replay_bytes)
    monkeypatch.setattr(evidence_module, "_download_replay_bytes", original_download)

    def live_history_without_pair(
        command: list[str], *, cwd: Path
    ) -> subprocess.CompletedProcess[bytes]:
        if "submissions" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=b"ref,fileName,date,description,status,publicScore,privateScore\n",
                stderr=b"",
            )
        return fake_run(command, cwd=cwd)

    monkeypatch.setattr(evidence_module, "_run", live_history_without_pair)
    with pytest.raises(KaggleEvidenceError, match="absent from live"):
        reverify_authenticated_pair_capture_online(
            package,
            authorization=fixture["authorization"],
            usage_ledger_path=fixture["ledger"],
            artifacts=fixture["artifacts"],
        )
    monkeypatch.setattr(evidence_module, "_run", fake_run)

    replay.write_text("{}", encoding="utf-8")
    with pytest.raises(KaggleEvidenceError, match="captured replay changed"):
        validate_authenticated_pair_capture(
            package,
            authorization=fixture["authorization"],
            usage_ledger_path=fixture["ledger"],
            artifacts=fixture["artifacts"],
        )


def test_exact_upload_uses_custodied_bytes_after_caller_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    archive = tmp_path / "submission-codex-byte-custody-v999.tar.gz"
    authorized = b"authorized immutable archive bytes\n"
    archive.write_bytes(authorized)
    archive_sha = hashlib.sha256(authorized).hexdigest()
    _, custodied = load_exact_archive_bytes(
        archive,
        archive_name=archive.name,
        archive_sha256=archive_sha,
    )
    archive.write_bytes(b"attacker replacement bytes\n")
    observed: list[bytes] = []

    def fake_bridge(
        runtime: object,
        arguments: list[str],
        *,
        payload: bytes = b"",
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(payload)
        return subprocess.CompletedProcess(arguments, 0, stdout=b"{}\n", stderr=b"")

    monkeypatch.setattr(evidence_module, "_run_byte_bridge", fake_bridge)
    result = submit_exact_archive_once(
        archive_bytes=custodied,
        archive_name=archive.name,
        archive_sha256=archive_sha,
        submission_description="codex-byte-custody-v999",
        kaggle_runtime_binding=fixture["artifacts"]["kaggle_runtime_binding"],
    )
    assert observed == [authorized]
    assert result["archive_sha256"] == archive_sha


def test_capture_directory_is_create_once(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    target = tmp_path / "existing-capture"
    target.mkdir()
    with pytest.raises(KaggleEvidenceError, match="fresh and create-once"):
        capture_authenticated_pair(
            authorization=fixture["authorization"],
            pair_id=fixture["pair_id"],
            usage_ledger_path=fixture["ledger"],
            artifacts=fixture["artifacts"],
            permits_by_lineage_uuid={
                lineage_uuid: row["permit"]
                for lineage_uuid, row in fixture["pair_evidence"].items()
            },
            submission_refs_by_lineage_uuid={
                lineage_uuid: row["submission_receipt"]["submission_ref"]
                for lineage_uuid, row in fixture["pair_evidence"].items()
            },
            descriptions_by_lineage_uuid={
                lineage_uuid: row["submission_receipt"]["submission_description"]
                for lineage_uuid, row in fixture["pair_evidence"].items()
            },
            local_archives_by_lineage_uuid={
                lineage_uuid: row["local_archive"]
                for lineage_uuid, row in fixture["pair_evidence"].items()
            },
            team_name="GarlicToday",
            capture_directory=target,
        )


def test_authenticated_preflight_blocks_archive_replay_after_local_state_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    stdout = (
        b"ref,fileName,date,description,status,publicScore,privateScore\n"
        b"123,submission-codex-voi-01.tar.gz,2026-07-11 09:03:00.000000,"
        b"codex-voi-pair-01-slot-1,SubmissionStatus.COMPLETE,600.0,\n"
    )
    monkeypatch.setattr(
        evidence_module,
        "_run",
        lambda command, *, cwd: subprocess.CompletedProcess(
            command,
            0,
            stdout=stdout,
            stderr=b"",
        ),
    )
    with pytest.raises(KaggleEvidenceError, match="already exists"):
        authenticated_upload_preflight(
            archive_name="submission-codex-voi-01.tar.gz",
            submission_description="codex-voi-pair-01-slot-1",
            kaggle_runtime_binding=fixture["artifacts"]["kaggle_runtime_binding"],
        )
