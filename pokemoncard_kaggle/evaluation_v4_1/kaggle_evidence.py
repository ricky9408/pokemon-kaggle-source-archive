"""Authenticated Kaggle byte custody for VOI-P5 pair barriers.

The pinned CLI supplies submission and episode metadata. Replay bodies and
archive uploads cross a pinned SDK bridge through anonymous pipes, so hashing,
parsing, and upload consume the exact same in-memory bytes. Create-once files
are audit journals only; online authorization and composition rebuild detached
snapshots and never trust caller-owned paths as outcome inputs.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping

from .authorization import validate_research_permit
from .chronology import (
    build_literal_first24_horizon_from_snapshot,
    build_pair_completion_barrier_from_snapshots,
    build_submission_receipt_from_snapshot,
)
from .protocol import canonical_json_bytes, canonical_sha256
from .runtime import validate_kaggle_runtime_binding


CAPTURE_SCHEMA = "voi_p5_authenticated_kaggle_pair_capture_v3"
UPLOAD_PREFLIGHT_SCHEMA = "voi_p5_authenticated_kaggle_upload_preflight_v2"
HOSTED_OBSERVATION_SCHEMA = "voi_p5_authenticated_kaggle_hosted_observation_v1"
LIVE_PAIR_SNAPSHOT_SCHEMA = "voi_p5_authenticated_live_pair_snapshot_v1"
COMPETITION = "pokemon-tcg-ai-battle"
_SUBMISSION_HEADERS = [
    "ref",
    "fileName",
    "date",
    "description",
    "status",
    "publicScore",
    "privateScore",
]
_EPISODE_HEADERS = ["id", "createTime", "endTime", "state", "type"]
_CAPTURE_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "pair_id",
        "competition",
        "captured_at_utc",
        "capture_directory",
        "kaggle_runtime_binding_content_sha256",
        "kaggle_entrypoint",
        "commands",
        "submissions_stdout_sha256",
        "authenticated_submissions_csv_sha256",
        "episodes_stdout_sha256_by_submission_ref",
        "replay_sha256_by_submission_ref",
        "member_evidence_manifest",
        "pair_completion_barrier",
        "capture_module_sha256",
        "research_only",
        "production_submission_authorized",
    }
)
_CAPTURE_FIELDS = _CAPTURE_CONTENT_FIELDS | {"content_sha256"}
_UPLOAD_PREFLIGHT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "competition",
        "archive_name",
        "submission_description",
        "checked_at_utc",
        "kaggle_runtime_binding_content_sha256",
        "kaggle_entrypoint",
        "command",
        "submissions_stdout_sha256",
        "matched_submission_refs",
        "research_only",
        "production_submission_authorized",
    }
)
_UPLOAD_PREFLIGHT_FIELDS = _UPLOAD_PREFLIGHT_CONTENT_FIELDS | {"content_sha256"}
_HOSTED_OBSERVATION_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "competition",
        "archive_sha256",
        "archive_name",
        "submission_description",
        "submission_ref",
        "submission_created_at_utc",
        "submission_status",
        "observed_at_utc",
        "kaggle_runtime_binding_content_sha256",
        "kaggle_entrypoint",
        "command",
        "submissions_stdout_sha256",
        "research_only",
        "production_submission_authorized",
    }
)
_HOSTED_OBSERVATION_FIELDS = _HOSTED_OBSERVATION_CONTENT_FIELDS | {"content_sha256"}
_LIVE_PAIR_SNAPSHOT_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "capture_content_sha256",
        "pair_id",
        "authenticated_at_utc",
        "kaggle_runtime_binding_content_sha256",
        "live_submissions_stdout_sha256",
        "permits_by_lineage_uuid",
        "submission_receipts_by_lineage_uuid",
        "horizons_by_lineage_uuid",
        "pair_completion_barrier",
        "research_only",
        "production_submission_authorized",
    }
)
_LIVE_PAIR_SNAPSHOT_FIELDS = _LIVE_PAIR_SNAPSHOT_CONTENT_FIELDS | {"content_sha256"}
_MANIFEST_FIELDS = frozenset(
    {
        "permit",
        "submission_receipt",
        "authenticated_submissions_csv",
        "local_archive",
        "submission_directory",
        "team_name",
    }
)


class KaggleEvidenceError(ValueError):
    """Authenticated Kaggle capture failed closed."""


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise KaggleEvidenceError(f"{label} is required")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise KaggleEvidenceError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        # Kaggle CLI competition timestamps are UTC but omit the suffix.
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _extract_csv(stdout: bytes, headers: list[str], *, label: str) -> list[dict[str, str]]:
    try:
        text = stdout.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise KaggleEvidenceError(f"{label} output is not UTF-8") from exc
    expected = ",".join(headers)
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == expected]
    if len(starts) != 1:
        raise KaggleEvidenceError(f"{label} output does not contain one exact CSV header")
    try:
        reader = csv.DictReader(lines[starts[0] :])
        if list(reader.fieldnames or []) != headers:
            raise KaggleEvidenceError(f"{label} CSV headers changed")
        rows = []
        for row in reader:
            if None in row:
                raise KaggleEvidenceError(f"{label} CSV contains extra columns")
            rows.append({key: str(value or "").strip() for key, value in row.items()})
    except csv.Error as exc:
        raise KaggleEvidenceError(f"{label} CSV is malformed") from exc
    return rows


def _write_csv_once(path: Path, headers: list[str], rows: list[Mapping[str, str]]) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=headers, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise KaggleEvidenceError(f"capture file already exists: {path}") from None


def _csv_bytes(headers: list[str], rows: list[Mapping[str, str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=headers, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(command, cwd=cwd, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise KaggleEvidenceError(f"authenticated Kaggle command failed: {command}") from exc


def _run_byte_bridge(
    runtime: Mapping[str, Any],
    arguments: list[str],
    *,
    payload: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    bridge = Path(runtime["byte_bridge_path"])
    try:
        bridge_bytes = bridge.read_bytes()
        bridge_source = bridge_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise KaggleEvidenceError("pinned Kaggle byte bridge cannot enter byte custody") from exc
    if _sha_bytes(bridge_bytes) != runtime["byte_bridge_sha256"]:
        raise KaggleEvidenceError("pinned Kaggle byte bridge changed before execution")
    command = [str(runtime["python_entrypoint"]), "-I", "-c", bridge_source, *arguments]
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        return subprocess.run(
            command,
            cwd=Path(runtime["workspace_root"]),
            env=environment,
            input=payload,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise KaggleEvidenceError("authenticated Kaggle byte bridge failed") from exc


def _runtime(artifacts_or_binding: Mapping[str, object] | object) -> dict[str, Any]:
    if isinstance(artifacts_or_binding, Mapping) and "kaggle_runtime_binding" in artifacts_or_binding:
        value = artifacts_or_binding["kaggle_runtime_binding"]
    else:
        value = artifacts_or_binding
    try:
        return validate_kaggle_runtime_binding(value)
    except Exception as exc:
        raise KaggleEvidenceError(f"frozen Kaggle runtime is invalid: {exc}") from exc


def _command_prefix(runtime: Mapping[str, Any]) -> list[str]:
    return [str(runtime["kaggle_entrypoint"])]


def _submissions_snapshot(
    runtime: Mapping[str, Any],
    *,
    competition: str,
) -> tuple[list[dict[str, str]], subprocess.CompletedProcess[bytes], list[str]]:
    command = _command_prefix(runtime) + [
        "competitions",
        "submissions",
        competition,
        "--csv",
        "--page-size",
        "500",
    ]
    result = _run(command, cwd=Path(runtime["workspace_root"]))
    return _extract_csv(result.stdout, _SUBMISSION_HEADERS, label="submissions"), result, command


def load_exact_archive_bytes(
    archive: str | Path,
    *,
    archive_name: str,
    archive_sha256: str,
) -> tuple[Path, bytes]:
    path = Path(archive).expanduser().resolve(strict=True)
    if not path.is_file() or path.name != archive_name:
        raise KaggleEvidenceError("local archive path does not match the frozen archive name")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise KaggleEvidenceError("local archive bytes could not be read") from exc
    if _sha_bytes(payload) != archive_sha256:
        raise KaggleEvidenceError("local archive bytes do not match the frozen SHA-256")
    return path, payload


def _download_replay_bytes(runtime: Mapping[str, Any], episode_id: str) -> bytes:
    result = _run_byte_bridge(
        runtime,
        ["replay", "--episode-id", episode_id],
    )
    payload = bytes(result.stdout)
    try:
        replay = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaggleEvidenceError("authenticated replay bytes are not valid JSON") from exc
    info = replay.get("info")
    bound_episode_id = (
        info.get("EpisodeId", replay.get("id"))
        if isinstance(info, Mapping)
        else replay.get("id")
    )
    if str(bound_episode_id) != episode_id:
        raise KaggleEvidenceError("authenticated replay ID mismatch")
    return payload


def _pair_rows(authorization: Mapping[str, Any], pair_id: str) -> list[Mapping[str, Any]]:
    rows = [row for row in authorization["archive_assignments"] if row["pair_id"] == pair_id]
    rows.sort(key=lambda row: row["slot"])
    if len(rows) != 2 or [row["slot"] for row in rows] != [1, 2]:
        raise KaggleEvidenceError("pair_id does not identify exact slots 1 and 2")
    return rows


def capture_authenticated_pair(
    *,
    authorization: Mapping[str, Any],
    pair_id: str,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    permits_by_lineage_uuid: Mapping[str, object],
    submission_refs_by_lineage_uuid: Mapping[str, str],
    descriptions_by_lineage_uuid: Mapping[str, str],
    local_archives_by_lineage_uuid: Mapping[str, str | Path],
    team_name: str,
    capture_directory: str | Path,
    competition: str = COMPETITION,
) -> dict[str, Any]:
    """Capture and validate one completed pair directly from authenticated CLI."""

    rows = _pair_rows(authorization, pair_id)
    expected_uuids = {str(row["lineage_uuid"]) for row in rows}
    for label, value in (
        ("permits", permits_by_lineage_uuid),
        ("submission refs", submission_refs_by_lineage_uuid),
        ("descriptions", descriptions_by_lineage_uuid),
        ("local archives", local_archives_by_lineage_uuid),
    ):
        if not isinstance(value, Mapping) or set(value) != expected_uuids:
            raise KaggleEvidenceError(f"{label} must exactly cover both pair lineages")
    if not isinstance(team_name, str) or not team_name:
        raise KaggleEvidenceError("team_name is required")
    root = Path(capture_directory).expanduser().resolve(strict=False)
    runtime = _runtime(artifacts)
    workspace = Path(runtime["workspace_root"])
    try:
        root.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        raise KaggleEvidenceError("capture directory must be fresh and create-once") from None

    command_prefix = _command_prefix(runtime)
    submission_rows, submissions_result, submissions_command = _submissions_snapshot(
        runtime,
        competition=competition,
    )
    submissions_path = root / "authenticated-submissions.csv"
    _write_csv_once(submissions_path, _SUBMISSION_HEADERS, submission_rows)
    captured_submissions_bytes = _csv_bytes(_SUBMISSION_HEADERS, submission_rows)
    if submissions_path.read_bytes() != captured_submissions_bytes:
        raise KaggleEvidenceError("captured submissions bytes were not written exactly")
    submission_by_ref = {row["ref"]: row for row in submission_rows}

    captured_at = datetime.now(timezone.utc)
    member_evidence: dict[str, dict[str, object]] = {}
    episode_stdout_sha: dict[str, str] = {}
    replay_sha_by_ref: dict[str, dict[str, str]] = {}
    commands: list[list[str]] = [submissions_command]
    member_snapshots: dict[str, dict[str, object]] = {}
    for row in rows:
        lineage_uuid = str(row["lineage_uuid"])
        permit = validate_research_permit(
            permits_by_lineage_uuid[lineage_uuid],
            authorization,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        submission_ref = submission_refs_by_lineage_uuid[lineage_uuid]
        if not isinstance(submission_ref, str) or not submission_ref.isdigit():
            raise KaggleEvidenceError("submission refs must be decimal digits")
        hosted = submission_by_ref.get(submission_ref)
        if hosted is None or hosted["status"] != "SubmissionStatus.COMPLETE":
            raise KaggleEvidenceError("pair submission is absent or not COMPLETE in live history")
        if _utc(hosted["date"], label="submission date") >= _utc(
            authorization["expires_at_utc"],
            label="authorization expiry",
        ):
            raise KaggleEvidenceError("pair submission was hosted after authorization expiry")
        member_dir = root / f"submission_{submission_ref}"
        member_dir.mkdir()
        episodes_command = command_prefix + ["competitions", "episodes", "-v", submission_ref]
        commands.append(episodes_command)
        episodes_result = _run(episodes_command, cwd=workspace)
        episode_stdout_sha[submission_ref] = _sha_bytes(episodes_result.stdout)
        episode_rows = _extract_csv(episodes_result.stdout, _EPISODE_HEADERS, label="episodes")
        episodes_path = member_dir / "episodes.csv"
        _write_csv_once(episodes_path, _EPISODE_HEADERS, episode_rows)
        captured_episodes_bytes = _csv_bytes(_EPISODE_HEADERS, episode_rows)
        if episodes_path.read_bytes() != captured_episodes_bytes:
            raise KaggleEvidenceError("captured episode bytes were not written exactly")
        submitted = _utc(hosted["date"], label="submission date")
        eligible = sorted(
            (
                row
                for row in episode_rows
                if row["type"] == "EpisodeType.EPISODE_TYPE_PUBLIC"
                and _utc(row["createTime"], label="episode createTime") > submitted
            ),
            key=lambda item: (_utc(item["createTime"], label="episode createTime"), item["id"]),
        )
        if len(eligible) < 24 or any(
            row["state"] != "EpisodeState.COMPLETED" for row in eligible[:24]
        ):
            raise KaggleEvidenceError("live literal first24 is incomplete")
        replay_shas: dict[str, str] = {}
        replay_bytes_by_game_id: dict[str, bytes] = {}
        for episode in eligible[:24]:
            episode_id = episode["id"]
            replay_command = ["pinned-sdk-bytes", "replay", episode_id]
            commands.append(replay_command)
            replay_path = member_dir / f"episode-{episode_id}-replay.json"
            try:
                replay_bytes = _download_replay_bytes(runtime, episode_id)
                with replay_path.open("xb") as handle:
                    handle.write(replay_bytes)
                    handle.flush()
                    os.fsync(handle.fileno())
                replay = json.loads(replay_bytes.decode("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise KaggleEvidenceError("downloaded replay is not valid JSON") from exc
            info = replay.get("info")
            bound_episode_id = (
                info.get("EpisodeId", replay.get("id"))
                if isinstance(info, Mapping)
                else replay.get("id")
            )
            if str(bound_episode_id) != episode_id:
                raise KaggleEvidenceError("downloaded replay ID mismatch")
            replay_shas[episode_id] = _sha_bytes(replay_bytes)
            replay_bytes_by_game_id[episode_id] = replay_bytes
        replay_sha_by_ref[submission_ref] = replay_shas
        archive_path = Path(local_archives_by_lineage_uuid[lineage_uuid]).expanduser().absolute()
        if archive_path.name != permit["archive_name"]:
            raise KaggleEvidenceError("archive audit path does not match permit name")
        receipt = build_submission_receipt_from_snapshot(
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=permit["archive_sha256"],
            submission_ref=submission_ref,
            expected_description=descriptions_by_lineage_uuid[lineage_uuid],
            first_observed_complete_at_utc=_canonical_utc(captured_at),
        )
        horizon = build_literal_first24_horizon_from_snapshot(
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            submission_receipt=receipt,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=permit["archive_sha256"],
            episodes_csv_bytes=captured_episodes_bytes,
            replay_bytes_by_game_id=replay_bytes_by_game_id,
            team_name=team_name,
        )
        member_snapshots[lineage_uuid] = {
            "permit": permit,
            "submission_receipt": receipt,
            "horizon": horizon,
        }
        member_evidence[lineage_uuid] = {
            "permit": permit,
            "submission_receipt": receipt,
            "authenticated_submissions_csv": submissions_path,
            "local_archive": archive_path,
            "submission_directory": member_dir,
            "team_name": team_name,
        }

    barrier = build_pair_completion_barrier_from_snapshots(
        authorization=authorization,
        pair_id=pair_id,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv_bytes=captured_submissions_bytes,
        member_snapshots_by_lineage_uuid=member_snapshots,
    )
    manifest = {
        lineage_uuid: {
            "permit": member_evidence[lineage_uuid]["permit"],
            "submission_receipt": member_evidence[lineage_uuid]["submission_receipt"],
            "authenticated_submissions_csv": str(submissions_path),
            "local_archive": str(member_evidence[lineage_uuid]["local_archive"]),
            "submission_directory": str(member_evidence[lineage_uuid]["submission_directory"]),
            "team_name": team_name,
        }
        for lineage_uuid in sorted(member_evidence)
    }
    content = {
        "schema": CAPTURE_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "pair_id": pair_id,
        "competition": competition,
        "captured_at_utc": _canonical_utc(captured_at),
        "capture_directory": str(root),
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "kaggle_entrypoint": runtime["kaggle_entrypoint"],
        "commands": commands,
        "submissions_stdout_sha256": _sha_bytes(submissions_result.stdout),
        "authenticated_submissions_csv_sha256": _sha_file(submissions_path),
        "episodes_stdout_sha256_by_submission_ref": episode_stdout_sha,
        "replay_sha256_by_submission_ref": replay_sha_by_ref,
        "member_evidence_manifest": manifest,
        "pair_completion_barrier": barrier,
        "capture_module_sha256": _sha_file(Path(__file__)),
        "research_only": True,
        "production_submission_authorized": False,
    }
    package = {**content, "content_sha256": canonical_sha256(content)}
    receipt_path = root / "capture-receipt.json"
    with receipt_path.open("xb") as handle:
        handle.write(canonical_json_bytes(package) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    return package


def authenticated_upload_preflight(
    *,
    archive_name: str,
    submission_description: str,
    kaggle_runtime_binding: object,
    competition: str = COMPETITION,
) -> dict[str, Any]:
    """Refuse a one-shot claim if live Kaggle history already has its identity."""

    runtime = _runtime(kaggle_runtime_binding)
    rows, result, command = _submissions_snapshot(runtime, competition=competition)
    collisions = [
        row["ref"]
        for row in rows
        if row["fileName"] == archive_name or row["description"] == submission_description
    ]
    if collisions:
        raise KaggleEvidenceError("archive name or description already exists in authenticated history")
    content = {
        "schema": UPLOAD_PREFLIGHT_SCHEMA,
        "competition": competition,
        "archive_name": archive_name,
        "submission_description": submission_description,
        "checked_at_utc": _canonical_utc(datetime.now(timezone.utc)),
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "kaggle_entrypoint": runtime["kaggle_entrypoint"],
        "command": command,
        "submissions_stdout_sha256": _sha_bytes(result.stdout),
        "matched_submission_refs": [],
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_authenticated_upload_preflight(
    value: object,
    *,
    archive_name: str,
    submission_description: str,
    kaggle_runtime_binding: object,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _UPLOAD_PREFLIGHT_FIELDS:
        raise KaggleEvidenceError("upload preflight fields are not exact")
    raw = dict(value)
    runtime = _runtime(kaggle_runtime_binding)
    if (
        raw["schema"] != UPLOAD_PREFLIGHT_SCHEMA
        or raw["archive_name"] != archive_name
        or raw["submission_description"] != submission_description
        or raw["kaggle_runtime_binding_content_sha256"] != runtime["content_sha256"]
        or raw["kaggle_entrypoint"] != runtime["kaggle_entrypoint"]
        or raw["matched_submission_refs"] != []
        or raw["research_only"] is not True
        or raw["production_submission_authorized"] is not False
    ):
        raise KaggleEvidenceError("upload preflight identity or collision state is invalid")
    if raw["content_sha256"] != canonical_sha256(
        {key: raw[key] for key in raw if key != "content_sha256"}
    ):
        raise KaggleEvidenceError("upload preflight content SHA-256 mismatch")
    _utc(raw["checked_at_utc"], label="upload preflight checked_at_utc")
    return raw


def submit_exact_archive_once(
    *,
    archive_bytes: bytes,
    archive_name: str,
    archive_sha256: str,
    submission_description: str,
    kaggle_runtime_binding: object,
    competition: str = COMPETITION,
) -> dict[str, Any]:
    """Upload the exact in-memory bytes through the pinned SDK bridge."""

    runtime = _runtime(kaggle_runtime_binding)
    if not isinstance(archive_bytes, bytes) or _sha_bytes(archive_bytes) != archive_sha256:
        raise KaggleEvidenceError("in-memory archive bytes do not match the frozen SHA-256")
    command = [
        "pinned-sdk-bytes",
        "upload",
        "--competition",
        competition,
        "--archive-name",
        archive_name,
        "--archive-sha256",
        archive_sha256,
        "--description",
        submission_description,
    ]
    invoked_at = datetime.now(timezone.utc)
    result = _run_byte_bridge(runtime, command[1:], payload=archive_bytes)
    return {
        "command": command,
        "invoked_at_utc": _canonical_utc(invoked_at),
        "stdout_sha256": _sha_bytes(result.stdout),
        "stderr_sha256": _sha_bytes(result.stderr),
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "archive_sha256": archive_sha256,
        "archive_content_length": len(archive_bytes),
    }


def observe_hosted_submission(
    *,
    archive_name: str,
    archive_sha256: str,
    submission_description: str,
    kaggle_runtime_binding: object,
    not_before_utc: str,
    expires_at_utc: str,
    competition: str = COMPETITION,
) -> dict[str, Any]:
    """Locate one exact hosted row after an executor-owned upload claim."""

    runtime = _runtime(kaggle_runtime_binding)
    rows, result, command = _submissions_snapshot(runtime, competition=competition)
    not_before = _utc(not_before_utc, label="upload claim time")
    expires = _utc(expires_at_utc, label="authorization expiry")
    matches = [
        row
        for row in rows
        if row["fileName"] == archive_name
        and row["description"] == submission_description
        and _utc(row["date"], label="submission date") >= not_before
    ]
    if len(matches) != 1:
        raise KaggleEvidenceError(
            "exact hosted submission is not uniquely visible; never retry the upload automatically"
        )
    hosted = matches[0]
    created = _utc(hosted["date"], label="submission date")
    if created >= expires:
        raise KaggleEvidenceError("hosted submission was created after authorization expiry")
    content = {
        "schema": HOSTED_OBSERVATION_SCHEMA,
        "competition": competition,
        "archive_sha256": archive_sha256,
        "archive_name": archive_name,
        "submission_description": submission_description,
        "submission_ref": hosted["ref"],
        "submission_created_at_utc": _canonical_utc(created),
        "submission_status": hosted["status"],
        "observed_at_utc": _canonical_utc(datetime.now(timezone.utc)),
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "kaggle_entrypoint": runtime["kaggle_entrypoint"],
        "command": command,
        "submissions_stdout_sha256": _sha_bytes(result.stdout),
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_hosted_observation(
    value: object,
    *,
    archive_name: str,
    archive_sha256: str,
    submission_description: str,
    kaggle_runtime_binding: object,
    expires_at_utc: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _HOSTED_OBSERVATION_FIELDS:
        raise KaggleEvidenceError("hosted observation fields are not exact")
    raw = dict(value)
    runtime = _runtime(kaggle_runtime_binding)
    if (
        raw["schema"] != HOSTED_OBSERVATION_SCHEMA
        or raw["archive_name"] != archive_name
        or raw["archive_sha256"] != archive_sha256
        or raw["submission_description"] != submission_description
        or raw["kaggle_runtime_binding_content_sha256"] != runtime["content_sha256"]
        or raw["kaggle_entrypoint"] != runtime["kaggle_entrypoint"]
        or not isinstance(raw["submission_ref"], str)
        or not raw["submission_ref"].isdigit()
        or raw["research_only"] is not True
        or raw["production_submission_authorized"] is not False
    ):
        raise KaggleEvidenceError("hosted observation identity is invalid")
    if raw["content_sha256"] != canonical_sha256(
        {key: raw[key] for key in _HOSTED_OBSERVATION_CONTENT_FIELDS}
    ):
        raise KaggleEvidenceError("hosted observation content SHA-256 mismatch")
    if _utc(raw["submission_created_at_utc"], label="submission created") >= _utc(
        expires_at_utc,
        label="authorization expiry",
    ):
        raise KaggleEvidenceError("hosted observation is after authorization expiry")
    _utc(raw["observed_at_utc"], label="hosted observation time")
    return raw


def build_live_completed_submission_receipt(
    *,
    authorization: Mapping[str, Any],
    permit: object,
    hosted_observation: object,
    submission_description: str,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    local_archive: str | Path,
    competition: str = COMPETITION,
) -> dict[str, Any]:
    """Poll one executor-owned upload and build its receipt from a live snapshot."""

    # Retained for call compatibility and audit display only. The upload claim's
    # in-memory SHA, not this mutable caller path, is authoritative.
    _ = local_archive

    validated_permit = validate_research_permit(
        permit,
        authorization,
        ledger_path=usage_ledger_path,
        artifacts=artifacts,
    )
    hosted = validate_hosted_observation(
        hosted_observation,
        archive_name=validated_permit["archive_name"],
        archive_sha256=validated_permit["archive_sha256"],
        submission_description=submission_description,
        kaggle_runtime_binding=artifacts["kaggle_runtime_binding"],
        expires_at_utc=authorization["expires_at_utc"],
    )
    runtime = _runtime(artifacts)
    rows, _, _ = _submissions_snapshot(runtime, competition=competition)
    matches = [row for row in rows if row["ref"] == hosted["submission_ref"]]
    if len(matches) != 1:
        raise KaggleEvidenceError("hosted submission ref is not uniquely visible")
    row = matches[0]
    if (
        row["fileName"] != validated_permit["archive_name"]
        or row["description"] != hosted["submission_description"]
        or _canonical_utc(_utc(row["date"], label="submission date"))
        != hosted["submission_created_at_utc"]
        or row["status"] != "SubmissionStatus.COMPLETE"
    ):
        raise KaggleEvidenceError("hosted submission is not COMPLETE with its exact frozen identity")
    observed_at = _canonical_utc(datetime.now(timezone.utc))
    return build_submission_receipt_from_snapshot(
        authorization=authorization,
        permit=validated_permit,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv_bytes=_csv_bytes(_SUBMISSION_HEADERS, rows),
        local_archive_sha256=validated_permit["archive_sha256"],
        submission_ref=hosted["submission_ref"],
        expected_description=hosted["submission_description"],
        first_observed_complete_at_utc=observed_at,
    )


def validate_authenticated_pair_capture(
    value: object,
    *,
    authorization: Mapping[str, Any],
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
) -> dict[str, Any]:
    """Rebuild a journaled direct-CLI capture from its immutable raw files."""

    if not isinstance(value, Mapping) or set(value) != _CAPTURE_FIELDS:
        raise KaggleEvidenceError("capture package fields are not exact")
    raw = dict(value)
    if raw["schema"] != CAPTURE_SCHEMA or raw["authorization_sha256"] != authorization["content_sha256"]:
        raise KaggleEvidenceError("capture package authorization binding mismatch")
    if raw["research_only"] is not True or raw["production_submission_authorized"] is not False:
        raise KaggleEvidenceError("capture package cannot authorize production")
    expected_content_sha = canonical_sha256(
        {key: raw[key] for key in _CAPTURE_CONTENT_FIELDS}
    )
    if raw["content_sha256"] != expected_content_sha:
        raise KaggleEvidenceError("capture package content SHA-256 mismatch")
    runtime = _runtime(artifacts)
    if (
        raw["kaggle_runtime_binding_content_sha256"] != runtime["content_sha256"]
        or raw["kaggle_entrypoint"] != runtime["kaggle_entrypoint"]
    ):
        raise KaggleEvidenceError("capture package Kaggle runtime binding mismatch")
    root = Path(raw["capture_directory"]).resolve(strict=True)
    receipt_path = root / "capture-receipt.json"
    if receipt_path.read_bytes() != canonical_json_bytes(raw) + b"\n":
        raise KaggleEvidenceError("capture receipt bytes are not canonical or exact")
    module_path = Path(runtime["capture_module_path"])
    if raw["capture_module_sha256"] != runtime["capture_module_sha256"] or raw[
        "capture_module_sha256"
    ] != _sha_file(module_path):
        raise KaggleEvidenceError("capture module changed after evidence collection")
    submissions_path = root / "authenticated-submissions.csv"
    try:
        captured_submissions_bytes = submissions_path.read_bytes()
    except OSError as exc:
        raise KaggleEvidenceError("authenticated submissions capture cannot be read") from exc
    if raw["authenticated_submissions_csv_sha256"] != _sha_bytes(captured_submissions_bytes):
        raise KaggleEvidenceError("authenticated submissions capture changed")
    pair_rows = _pair_rows(authorization, raw["pair_id"])
    expected_uuids = {str(row["lineage_uuid"]) for row in pair_rows}
    manifest = raw["member_evidence_manifest"]
    if not isinstance(manifest, Mapping) or set(manifest) != expected_uuids:
        raise KaggleEvidenceError("capture member manifest does not cover the exact pair")
    member_snapshots: dict[str, dict[str, object]] = {}
    for lineage_uuid, item in manifest.items():
        if not isinstance(item, Mapping) or set(item) != _MANIFEST_FIELDS:
            raise KaggleEvidenceError("capture member manifest fields are not exact")
        member_dir = Path(item["submission_directory"]).resolve(strict=True)
        if root not in member_dir.parents:
            raise KaggleEvidenceError("captured submission directory escaped capture root")
        submission_ref = item["submission_receipt"]["submission_ref"]
        expected_replay_shas = raw["replay_sha256_by_submission_ref"].get(submission_ref)
        if not isinstance(expected_replay_shas, Mapping) or len(expected_replay_shas) != 24:
            raise KaggleEvidenceError("capture replay manifest is incomplete")
        try:
            episodes_bytes = (member_dir / "episodes.csv").read_bytes()
        except OSError as exc:
            raise KaggleEvidenceError("captured episodes cannot be read") from exc
        replay_bytes_by_game_id: dict[str, bytes] = {}
        for episode_id, expected_sha in expected_replay_shas.items():
            path = member_dir / f"episode-{episode_id}-replay.json"
            try:
                replay_bytes = path.read_bytes()
            except OSError as exc:
                raise KaggleEvidenceError("captured replay cannot be read") from exc
            if _sha_bytes(replay_bytes) != expected_sha:
                raise KaggleEvidenceError("captured replay changed")
            replay_bytes_by_game_id[episode_id] = replay_bytes
        permit = validate_research_permit(
            item["permit"],
            authorization,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        if Path(item["local_archive"]).name != permit["archive_name"]:
            raise KaggleEvidenceError("capture archive audit path has the wrong name")
        captured_receipt = item["submission_receipt"]
        receipt = build_submission_receipt_from_snapshot(
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=permit["archive_sha256"],
            submission_ref=captured_receipt["submission_ref"],
            expected_description=captured_receipt["submission_description"],
            first_observed_complete_at_utc=captured_receipt["first_observed_complete_at_utc"],
        )
        if receipt != captured_receipt:
            raise KaggleEvidenceError("captured submission receipt does not rebuild from bytes")
        horizon = build_literal_first24_horizon_from_snapshot(
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            submission_receipt=receipt,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=permit["archive_sha256"],
            episodes_csv_bytes=episodes_bytes,
            replay_bytes_by_game_id=replay_bytes_by_game_id,
            team_name=item["team_name"],
        )
        member_snapshots[lineage_uuid] = {
            "permit": permit,
            "submission_receipt": receipt,
            "horizon": horizon,
        }
    barrier = build_pair_completion_barrier_from_snapshots(
        authorization=authorization,
        pair_id=raw["pair_id"],
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv_bytes=captured_submissions_bytes,
        member_snapshots_by_lineage_uuid=member_snapshots,
    )
    if barrier != raw["pair_completion_barrier"]:
        raise KaggleEvidenceError("capture pair barrier does not rebuild from raw evidence")
    return raw


def _eligible_first24(
    rows: list[dict[str, str]],
    *,
    submitted_at: datetime,
) -> list[dict[str, str]]:
    eligible = sorted(
        (
            row
            for row in rows
            if row["type"] == "EpisodeType.EPISODE_TYPE_PUBLIC"
            and _utc(row["createTime"], label="episode createTime") > submitted_at
        ),
        key=lambda item: (_utc(item["createTime"], label="episode createTime"), item["id"]),
    )
    if len(eligible) < 24 or any(
        row["state"] != "EpisodeState.COMPLETED" for row in eligible[:24]
    ):
        raise KaggleEvidenceError("live literal first24 is incomplete")
    return eligible[:24]


def reverify_authenticated_pair_capture_online(
    value: object,
    *,
    authorization: Mapping[str, Any],
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
) -> dict[str, Any]:
    """Build an authoritative snapshot from the exact authenticated replay bytes.

    The journaled capture is detached first. Live replay payloads remain in
    anonymous-pipe memory through hashing, parsing, horizon construction, and
    pair-barrier construction. The returned object contains only newly derived
    immutable JSON values; no caller-controlled path is reopened by consumers.
    """

    try:
        detached = json.loads(canonical_json_bytes(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise KaggleEvidenceError("capture package cannot be canonically detached") from exc
    capture = validate_authenticated_pair_capture(
        detached,
        authorization=authorization,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
    )
    runtime = _runtime(artifacts)
    workspace = Path(runtime["workspace_root"])
    live_rows, live_submissions_result, _ = _submissions_snapshot(
        runtime,
        competition=capture["competition"],
    )
    rows_by_ref = {row["ref"]: row for row in live_rows}
    barrier = capture["pair_completion_barrier"]
    horizon_start = _utc(barrier["horizon_started_at_utc"], label="horizon start")
    horizon_complete = _utc(barrier["horizon_completed_at_utc"], label="horizon completion")
    expiry = _utc(authorization["expires_at_utc"], label="authorization expiry")
    target_refs = set(barrier["latest_two_submission_refs"])
    for item in capture["member_evidence_manifest"].values():
        receipt = item["submission_receipt"]
        submission_ref = receipt["submission_ref"]
        hosted = rows_by_ref.get(submission_ref)
        if hosted is None:
            raise KaggleEvidenceError("captured submission is absent from live authenticated history")
        created = _utc(hosted["date"], label="submission date")
        if (
            hosted["fileName"] != receipt["archive_name"]
            or hosted["description"] != receipt["submission_description"]
            or hosted["status"] != "SubmissionStatus.COMPLETE"
            or _canonical_utc(created) != receipt["submission_created_at_utc"]
        ):
            raise KaggleEvidenceError("live hosted row differs from the captured submission receipt")
        if created >= expiry:
            raise KaggleEvidenceError("captured submission was hosted after authorization expiry")

    eligible_at_start = sorted(
        (
            (_utc(row["date"], label="submission date"), int(row["ref"]), row["ref"])
            for row in live_rows
            if _utc(row["date"], label="submission date") <= horizon_start
        ),
        key=lambda item: (item[0], item[1]),
    )
    if len(eligible_at_start) < 2 or {row[2] for row in eligible_at_start[-2:]} != target_refs:
        raise KaggleEvidenceError("live history does not confirm exact latest-two exposure")
    if any(
        row["ref"] not in target_refs
        and horizon_start < _utc(row["date"], label="submission date") <= horizon_complete
        for row in live_rows
    ):
        raise KaggleEvidenceError("live history shows pair displacement during the horizon")

    root = Path(capture["capture_directory"])
    try:
        captured_submissions_bytes = (root / "authenticated-submissions.csv").read_bytes()
    except OSError as exc:
        raise KaggleEvidenceError("captured submissions snapshot cannot be read") from exc
    if _sha_bytes(captured_submissions_bytes) != capture["authenticated_submissions_csv_sha256"]:
        raise KaggleEvidenceError("captured submissions snapshot changed before byte custody")

    permits: dict[str, dict[str, Any]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    horizons: dict[str, dict[str, Any]] = {}
    member_snapshots: dict[str, dict[str, object]] = {}
    for lineage_uuid, item in capture["member_evidence_manifest"].items():
        captured_receipt = item["submission_receipt"]
        submission_ref = captured_receipt["submission_ref"]
        submitted = _utc(captured_receipt["submission_created_at_utc"], label="submission date")
        member_directory = Path(item["submission_directory"])
        try:
            captured_episodes_bytes = (member_directory / "episodes.csv").read_bytes()
        except OSError as exc:
            raise KaggleEvidenceError("captured member bytes cannot enter verifier custody") from exc
        original_episodes = _extract_csv(
            captured_episodes_bytes,
            _EPISODE_HEADERS,
            label="captured episodes",
        )
        original_first24 = _eligible_first24(original_episodes, submitted_at=submitted)
        command = _command_prefix(runtime) + ["competitions", "episodes", "-v", submission_ref]
        result = _run(command, cwd=workspace)
        live_episodes = _extract_csv(result.stdout, _EPISODE_HEADERS, label="live episodes")
        live_first24 = _eligible_first24(live_episodes, submitted_at=submitted)
        if live_first24 != original_first24:
            raise KaggleEvidenceError("live first24 episode metadata differs from capture")
        expected_shas = capture["replay_sha256_by_submission_ref"][submission_ref]
        replay_bytes_by_game_id: dict[str, bytes] = {}
        for episode in live_first24:
            episode_id = episode["id"]
            replay_bytes = _download_replay_bytes(runtime, episode_id)
            if _sha_bytes(replay_bytes) != expected_shas.get(episode_id):
                raise KaggleEvidenceError("live replay bytes differ from captured evidence")
            replay_bytes_by_game_id[episode_id] = replay_bytes

        receipt = build_submission_receipt_from_snapshot(
            authorization=authorization,
            permit=item["permit"],
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=captured_receipt["archive_sha256"],
            submission_ref=submission_ref,
            expected_description=captured_receipt["submission_description"],
            first_observed_complete_at_utc=captured_receipt["first_observed_complete_at_utc"],
        )
        if receipt != captured_receipt:
            raise KaggleEvidenceError("captured receipt does not rebuild from byte-custodied inputs")
        horizon = build_literal_first24_horizon_from_snapshot(
            authorization=authorization,
            permit=item["permit"],
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            submission_receipt=receipt,
            authenticated_submissions_csv_bytes=captured_submissions_bytes,
            local_archive_sha256=receipt["local_archive_sha256"],
            episodes_csv_bytes=captured_episodes_bytes,
            replay_bytes_by_game_id=replay_bytes_by_game_id,
            team_name=item["team_name"],
        )
        permit = validate_research_permit(
            item["permit"],
            authorization,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        permits[lineage_uuid] = permit
        receipts[lineage_uuid] = receipt
        horizons[lineage_uuid] = horizon
        member_snapshots[lineage_uuid] = {
            "permit": permit,
            "submission_receipt": receipt,
            "horizon": horizon,
        }

    live_barrier = build_pair_completion_barrier_from_snapshots(
        authorization=authorization,
        pair_id=capture["pair_id"],
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv_bytes=captured_submissions_bytes,
        member_snapshots_by_lineage_uuid=member_snapshots,
    )
    if live_barrier != capture["pair_completion_barrier"]:
        raise KaggleEvidenceError("live replay bytes do not rebuild the journaled pair barrier")
    content = {
        "schema": LIVE_PAIR_SNAPSHOT_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "capture_content_sha256": capture["content_sha256"],
        "pair_id": capture["pair_id"],
        "authenticated_at_utc": _canonical_utc(datetime.now(timezone.utc)),
        "kaggle_runtime_binding_content_sha256": runtime["content_sha256"],
        "live_submissions_stdout_sha256": _sha_bytes(live_submissions_result.stdout),
        "permits_by_lineage_uuid": permits,
        "submission_receipts_by_lineage_uuid": receipts,
        "horizons_by_lineage_uuid": horizons,
        "pair_completion_barrier": live_barrier,
        "research_only": True,
        "production_submission_authorized": False,
    }
    snapshot = {**content, "content_sha256": canonical_sha256(content)}
    return json.loads(canonical_json_bytes(snapshot))


def validate_authenticated_live_pair_snapshot(
    value: object,
    *,
    authorization: Mapping[str, Any],
    artifacts: Mapping[str, object],
) -> dict[str, Any]:
    """Validate a detached online snapshot without consulting local paths."""

    if not isinstance(value, Mapping) or set(value) != _LIVE_PAIR_SNAPSHOT_FIELDS:
        raise KaggleEvidenceError("live pair snapshot fields are not exact")
    raw = json.loads(canonical_json_bytes(value))
    runtime = _runtime(artifacts)
    if (
        raw["schema"] != LIVE_PAIR_SNAPSHOT_SCHEMA
        or raw["authorization_sha256"] != authorization["content_sha256"]
        or raw["kaggle_runtime_binding_content_sha256"] != runtime["content_sha256"]
        or raw["research_only"] is not True
        or raw["production_submission_authorized"] is not False
    ):
        raise KaggleEvidenceError("live pair snapshot identity is invalid")
    if raw["content_sha256"] != canonical_sha256(
        {field: raw[field] for field in _LIVE_PAIR_SNAPSHOT_CONTENT_FIELDS}
    ):
        raise KaggleEvidenceError("live pair snapshot content SHA-256 mismatch")
    _utc(raw["authenticated_at_utc"], label="live snapshot authentication time")
    barrier = raw["pair_completion_barrier"]
    if (
        not isinstance(barrier, Mapping)
        or barrier.get("pair_id") != raw["pair_id"]
        or barrier.get("authorization_sha256") != authorization["content_sha256"]
        or barrier.get("content_sha256")
        != canonical_sha256({key: value for key, value in barrier.items() if key != "content_sha256"})
    ):
        raise KaggleEvidenceError("live pair snapshot barrier is invalid")
    lineage_ids = {
        str(row["lineage_uuid"])
        for row in _pair_rows(authorization, raw["pair_id"])
    }
    for field in (
        "permits_by_lineage_uuid",
        "submission_receipts_by_lineage_uuid",
        "horizons_by_lineage_uuid",
    ):
        if not isinstance(raw[field], Mapping) or set(raw[field]) != lineage_ids:
            raise KaggleEvidenceError("live pair snapshot lineage coverage is invalid")
    return raw


__all__ = [
    "CAPTURE_SCHEMA",
    "HOSTED_OBSERVATION_SCHEMA",
    "KaggleEvidenceError",
    "LIVE_PAIR_SNAPSHOT_SCHEMA",
    "UPLOAD_PREFLIGHT_SCHEMA",
    "authenticated_upload_preflight",
    "build_live_completed_submission_receipt",
    "capture_authenticated_pair",
    "load_exact_archive_bytes",
    "observe_hosted_submission",
    "reverify_authenticated_pair_capture_online",
    "submit_exact_archive_once",
    "validate_authenticated_pair_capture",
    "validate_authenticated_live_pair_snapshot",
    "validate_authenticated_upload_preflight",
    "validate_hosted_observation",
]
