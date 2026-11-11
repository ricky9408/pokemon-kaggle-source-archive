"""Authenticated-submission binding and literal first-24 public horizons.

No setup games are discarded.  The horizon is selected by hosted creation time
before any replay outcome is opened, and validation rebuilds it from the raw CSV
and replay files instead of trusting a summarized outcome list.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .authorization import validate_research_permit
from .protocol import canonical_json_bytes, canonical_sha256


SUBMISSION_RECEIPT_SCHEMA = "voi_p5_hosted_submission_receipt_v1"
HORIZON_SCHEMA = "voi_p5_literal_first24_horizon_v1"
PAIR_COMPLETION_BARRIER_SCHEMA = "voi_p5_pair_completion_barrier_v2"
_COMPLETE = "SubmissionStatus.COMPLETE"
_EPISODE_COMPLETE = "EpisodeState.COMPLETED"
_EPISODE_PUBLIC = "EpisodeType.EPISODE_TYPE_PUBLIC"
_SUBMISSION_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "permit_content_sha256",
        "archive_sha256",
        "archive_name",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "submission_ref",
        "submission_created_at_utc",
        "submission_description",
        "submission_status",
        "first_observed_complete_at_utc",
        "authenticated_submissions_csv_sha256",
        "local_archive_sha256",
        "research_only",
        "production_submission_authorized",
    }
)
_SUBMISSION_RECEIPT_FIELDS = _SUBMISSION_FIELDS | {"content_sha256"}
_HORIZON_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "permit_content_sha256",
        "submission_receipt_content_sha256",
        "archive_sha256",
        "lineage_uuid",
        "pair_id",
        "wave_id",
        "slot",
        "submission_ref",
        "submission_created_at_utc",
        "episodes_csv_sha256",
        "module_version",
        "games",
        "outcomes",
        "first_game_created_at_utc",
        "last_game_created_at_utc",
        "horizon_games",
        "setup_games_excluded",
        "research_only",
        "production_submission_authorized",
    }
)
_HORIZON_FIELDS = _HORIZON_CONTENT_FIELDS | {"content_sha256"}
_GAME_FIELDS = frozenset(
    {
        "game_id",
        "created_at_utc",
        "ended_at_utc",
        "replay_sha256",
        "target_slot",
        "opponent_team",
        "outcome",
        "module_version",
    }
)
_PAIR_MEMBER_EVIDENCE_FIELDS = frozenset(
    {
        "permit",
        "submission_receipt",
        "authenticated_submissions_csv",
        "local_archive",
        "submission_directory",
        "team_name",
    }
)
_LIVE_PAIR_MEMBER_FIELDS = frozenset({"permit", "submission_receipt", "horizon"})
_PAIR_MEMBER_FIELDS = frozenset(
    {
        "lineage_uuid",
        "slot",
        "archive_sha256",
        "permit_content_sha256",
        "submission_receipt_content_sha256",
        "authenticated_submissions_csv_sha256",
        "horizon_content_sha256",
        "submission_ref",
        "submission_created_at_utc",
        "first_game_created_at_utc",
        "last_game_ended_at_utc",
        "module_version",
        "horizon_games",
    }
)
_PAIR_BARRIER_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "authorization_sha256",
        "pair_id",
        "wave_id",
        "prior_pair_barrier_content_sha256",
        "authenticated_submissions_csv_sha256",
        "latest_two_submission_refs",
        "members",
        "latest_two_exposure_complete_at_utc",
        "horizon_started_at_utc",
        "horizon_completed_at_utc",
        "module_version",
        "horizon_games_per_member",
        "research_only",
        "production_submission_authorized",
    }
)
_PAIR_BARRIER_FIELDS = _PAIR_BARRIER_CONTENT_FIELDS | {"content_sha256"}
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ChronologyError(ValueError):
    """A hosted submission or literal first-24 horizon is invalid."""


def _exact_fields(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ChronologyError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise ChronologyError(f"{label} must be a lowercase SHA-256")
    return value


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _utc(value: object, *, label: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise ChronologyError(f"{label} is required")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ChronologyError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _submission_rows_bytes(payload: bytes) -> tuple[list[dict[str, str]], str]:
    required = {"ref", "fileName", "date", "description", "status", "publicScore", "privateScore"}
    try:
        with io.StringIO(payload.decode("utf-8-sig"), newline="") as handle:
            reader = csv.DictReader(handle)
            if set(reader.fieldnames or []) != required:
                raise ChronologyError("authenticated submissions CSV headers are not exact")
            rows = []
            refs: set[str] = set()
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ChronologyError(f"authenticated submissions CSV row {row_number} has extra columns")
                normalized = {key: str(value or "").strip() for key, value in row.items()}
                submission_ref = normalized["ref"]
                if not submission_ref.isdigit() or submission_ref in refs:
                    raise ChronologyError("authenticated submissions CSV refs must be unique decimal digits")
                refs.add(submission_ref)
                _utc(normalized["date"], label="submission date")
                rows.append(normalized)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ChronologyError(f"cannot parse authenticated submissions CSV: {exc}") from exc
    if not rows:
        raise ChronologyError("authenticated submissions CSV is empty")
    return rows, hashlib.sha256(payload).hexdigest()


def _submission_rows(path: Path) -> tuple[list[dict[str, str]], str]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ChronologyError(f"cannot read authenticated submissions CSV: {exc}") from exc
    return _submission_rows_bytes(payload)


def _submission_row(path: Path, submission_ref: str) -> tuple[dict[str, str], str]:
    rows, csv_sha = _submission_rows(path)
    matches = [row for row in rows if row["ref"] == submission_ref]
    if len(matches) != 1:
        raise ChronologyError("submission_ref must occur exactly once in authenticated submissions CSV")
    return matches[0], csv_sha


def _submission_row_bytes(payload: bytes, submission_ref: str) -> tuple[dict[str, str], str]:
    rows, csv_sha = _submission_rows_bytes(payload)
    matches = [row for row in rows if row["ref"] == submission_ref]
    if len(matches) != 1:
        raise ChronologyError("submission_ref must occur exactly once in authenticated submissions CSV")
    return matches[0], csv_sha


def _build_submission_receipt_from_snapshot(
    *,
    authorization: Mapping[str, Any],
    validated_permit: Mapping[str, Any],
    authenticated_submissions_csv_bytes: bytes,
    local_archive_sha256: str,
    submission_ref: str,
    expected_description: str,
    first_observed_complete_at_utc: str,
) -> dict[str, Any]:
    if not isinstance(submission_ref, str) or not submission_ref.isdigit():
        raise ChronologyError("submission_ref must be decimal digits")
    if not isinstance(expected_description, str) or not expected_description.strip():
        raise ChronologyError("expected_description is required")
    if "final" in expected_description.casefold():
        raise ChronologyError("submission description must not contain 'final'")
    if local_archive_sha256 != validated_permit["archive_sha256"]:
        raise ChronologyError("archive bytes do not match permit archive SHA-256")
    row, csv_sha = _submission_row_bytes(authenticated_submissions_csv_bytes, submission_ref)
    if row["fileName"] != validated_permit["archive_name"]:
        raise ChronologyError("hosted submission filename does not match permit")
    if row["description"] != expected_description:
        raise ChronologyError("hosted submission description mismatch")
    if row["status"] != _COMPLETE:
        raise ChronologyError("hosted submission is not COMPLETE")
    submitted, submitted_text = _utc(row["date"], label="submission date")
    observed, observed_text = _utc(
        first_observed_complete_at_utc,
        label="first_observed_complete_at_utc",
    )
    if observed < submitted:
        raise ChronologyError("first COMPLETE observation precedes submission creation")
    content = {
        "schema": SUBMISSION_RECEIPT_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "permit_content_sha256": validated_permit["content_sha256"],
        "archive_sha256": validated_permit["archive_sha256"],
        "archive_name": validated_permit["archive_name"],
        "lineage_uuid": validated_permit["lineage_uuid"],
        "pair_id": validated_permit["pair_id"],
        "wave_id": validated_permit["wave_id"],
        "slot": validated_permit["slot"],
        "submission_ref": submission_ref,
        "submission_created_at_utc": submitted_text,
        "submission_description": expected_description,
        "submission_status": _COMPLETE,
        "first_observed_complete_at_utc": observed_text,
        "authenticated_submissions_csv_sha256": csv_sha,
        "local_archive_sha256": local_archive_sha256,
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def build_submission_receipt(
    *,
    authorization: Mapping[str, Any],
    permit: object,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    authenticated_submissions_csv: str | Path,
    local_archive: str | Path,
    submission_ref: str,
    expected_description: str,
    first_observed_complete_at_utc: str,
) -> dict[str, Any]:
    """Bind an exact research permit to one authenticated Kaggle row."""

    validated_permit = validate_research_permit(
        permit,
        authorization,
        ledger_path=usage_ledger_path,
        artifacts=artifacts,
    )
    csv_path = Path(authenticated_submissions_csv)
    archive_path = Path(local_archive)
    if not archive_path.is_file() or archive_path.name != validated_permit["archive_name"]:
        raise ChronologyError("local archive path does not match permit archive name")
    try:
        archive_bytes = archive_path.read_bytes()
        submissions_bytes = csv_path.read_bytes()
    except OSError as exc:
        raise ChronologyError(f"cannot read receipt inputs: {exc}") from exc
    return _build_submission_receipt_from_snapshot(
        authorization=authorization,
        validated_permit=validated_permit,
        authenticated_submissions_csv_bytes=submissions_bytes,
        local_archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        submission_ref=submission_ref,
        expected_description=expected_description,
        first_observed_complete_at_utc=first_observed_complete_at_utc,
    )


def build_submission_receipt_from_snapshot(
    *,
    authorization: Mapping[str, Any],
    permit: object,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    authenticated_submissions_csv_bytes: bytes,
    local_archive_sha256: str,
    submission_ref: str,
    expected_description: str,
    first_observed_complete_at_utc: str,
) -> dict[str, Any]:
    """Bind one permit to detached authenticated bytes without reopening paths."""

    validated_permit = validate_research_permit(
        permit,
        authorization,
        ledger_path=usage_ledger_path,
        artifacts=artifacts,
    )
    return _build_submission_receipt_from_snapshot(
        authorization=authorization,
        validated_permit=validated_permit,
        authenticated_submissions_csv_bytes=authenticated_submissions_csv_bytes,
        local_archive_sha256=local_archive_sha256,
        submission_ref=submission_ref,
        expected_description=expected_description,
        first_observed_complete_at_utc=first_observed_complete_at_utc,
    )


def validate_submission_receipt(
    value: object,
    *,
    authorization: Mapping[str, Any],
    permit: object,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    authenticated_submissions_csv: str | Path,
    local_archive: str | Path,
) -> dict[str, Any]:
    raw = _exact_fields(value, _SUBMISSION_RECEIPT_FIELDS, label="submission receipt")
    expected = build_submission_receipt(
        authorization=authorization,
        permit=permit,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv=authenticated_submissions_csv,
        local_archive=local_archive,
        submission_ref=raw["submission_ref"],
        expected_description=raw["submission_description"],
        first_observed_complete_at_utc=raw["first_observed_complete_at_utc"],
    )
    if dict(raw) != expected:
        raise ChronologyError("submission receipt is not the exact rebuilt receipt")
    return expected


def _episode_rows_bytes(payload: bytes, *, after: datetime) -> tuple[list[dict[str, Any]], str]:
    required = {"id", "createTime", "endTime", "state", "type"}
    try:
        with io.StringIO(payload.decode("utf-8-sig"), newline="") as handle:
            reader = csv.DictReader(handle)
            if set(reader.fieldnames or []) != required:
                raise ChronologyError("episodes.csv headers are not exact")
            seen: set[str] = set()
            rows: list[dict[str, Any]] = []
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ChronologyError(f"episodes.csv row {row_number} has extra columns")
                game_id = str(row.get("id") or "").strip()
                if not game_id:
                    continue
                if game_id in seen:
                    raise ChronologyError(f"episodes.csv duplicate game id {game_id}")
                seen.add(game_id)
                created, created_text = _utc(row.get("createTime"), label="episode createTime")
                if str(row.get("type") or "").strip() != _EPISODE_PUBLIC or created <= after:
                    continue
                ended, ended_text = _utc(row.get("endTime"), label="episode endTime")
                if ended < created:
                    raise ChronologyError("episode ends before creation")
                rows.append(
                    {
                        "game_id": game_id,
                        "created": created,
                        "created_at_utc": created_text,
                        "ended_at_utc": ended_text,
                        "state": str(row.get("state") or "").strip(),
                    }
                )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ChronologyError(f"cannot parse episodes.csv: {exc}") from exc
    rows.sort(key=lambda row: (row["created"], row["game_id"]))
    if len(rows) < 24:
        raise ChronologyError(f"only {len(rows)} eligible public games exist; literal first24 requires 24")
    horizon = rows[:24]
    incomplete = [row["game_id"] for row in horizon if row["state"] != _EPISODE_COMPLETE]
    if incomplete:
        raise ChronologyError("literal first24 contains a non-completed game")
    return horizon, hashlib.sha256(payload).hexdigest()


def _episode_rows(path: Path, *, after: datetime) -> tuple[list[dict[str, Any]], str]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ChronologyError(f"cannot read episodes.csv: {exc}") from exc
    return _episode_rows_bytes(payload, after=after)


def _replay_game_bytes(payload: bytes, *, game_id: str, team_name: str) -> dict[str, Any]:
    try:
        replay = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChronologyError(f"cannot parse replay {game_id}: {exc}") from exc
    info = replay.get("info")
    bound_episode_id = (
        info.get("EpisodeId", replay.get("id"))
        if isinstance(info, Mapping)
        else replay.get("id")
    )
    if str(bound_episode_id) != game_id:
        raise ChronologyError("replay game id mismatch")
    teams = info.get("TeamNames") if isinstance(info, Mapping) else None
    if not isinstance(teams, list) or teams.count(team_name) != 1 or len(teams) != 2:
        raise ChronologyError("replay must contain target team exactly once and cannot be own-v-own")
    slot = teams.index(team_name)
    opponent = teams[1 - slot]
    if not isinstance(opponent, str) or not opponent:
        raise ChronologyError("replay opponent team is missing")
    steps = replay.get("steps")
    if not isinstance(steps, list) or not steps or not isinstance(steps[-1], list) or len(steps[-1]) != 2:
        raise ChronologyError("replay terminal step is missing")
    terminal = steps[-1][slot]
    reward = terminal.get("reward") if isinstance(terminal, Mapping) else None
    if isinstance(reward, bool) or not isinstance(reward, (int, float)) or terminal.get("status") != "DONE":
        raise ChronologyError("replay terminal reward is missing")
    module = replay.get("module_version")
    if not isinstance(module, str) or not module:
        raise ChronologyError("replay module_version is missing")
    return {
        "replay_sha256": hashlib.sha256(payload).hexdigest(),
        "target_slot": slot,
        "opponent_team": opponent,
        "outcome": 1.0 if float(reward) > 0 else 0.0 if float(reward) < 0 else 0.5,
        "module_version": module,
    }


def _replay_game(path: Path, *, game_id: str, team_name: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ChronologyError(f"cannot read replay {game_id}: {exc}") from exc
    return _replay_game_bytes(payload, game_id=game_id, team_name=team_name)


def build_literal_first24_horizon(
    *,
    authorization: Mapping[str, Any],
    permit: object,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    submission_receipt: object,
    authenticated_submissions_csv: str | Path,
    local_archive: str | Path,
    submission_directory: str | Path,
    team_name: str,
) -> dict[str, Any]:
    receipt = validate_submission_receipt(
        submission_receipt,
        authorization=authorization,
        permit=permit,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        authenticated_submissions_csv=authenticated_submissions_csv,
        local_archive=local_archive,
    )
    if not isinstance(team_name, str) or not team_name:
        raise ChronologyError("team_name is required")
    directory = Path(submission_directory)
    if f"submission_{receipt['submission_ref']}" not in directory.parts:
        raise ChronologyError("submission directory does not match submission_ref")
    try:
        episodes_bytes = (directory / "episodes.csv").read_bytes()
    except OSError as exc:
        raise ChronologyError(f"cannot read episodes.csv: {exc}") from exc
    submitted = _utc(receipt["submission_created_at_utc"], label="submission_created_at_utc")[0]
    rows, _ = _episode_rows_bytes(episodes_bytes, after=submitted)
    replay_bytes_by_game_id: dict[str, bytes] = {}
    for row in rows:
        path = directory / f"episode-{row['game_id']}-replay.json"
        try:
            replay_bytes_by_game_id[row["game_id"]] = path.read_bytes()
        except OSError as exc:
            raise ChronologyError(f"cannot read replay {row['game_id']}: {exc}") from exc
    return _build_literal_first24_horizon_from_snapshot(
        authorization=authorization,
        receipt=receipt,
        episodes_csv_bytes=episodes_bytes,
        replay_bytes_by_game_id=replay_bytes_by_game_id,
        team_name=team_name,
    )


def _build_literal_first24_horizon_from_snapshot(
    *,
    authorization: Mapping[str, Any],
    receipt: Mapping[str, Any],
    episodes_csv_bytes: bytes,
    replay_bytes_by_game_id: Mapping[str, bytes],
    team_name: str,
) -> dict[str, Any]:
    submitted = _utc(receipt["submission_created_at_utc"], label="submission_created_at_utc")[0]
    rows, episodes_sha = _episode_rows_bytes(episodes_csv_bytes, after=submitted)
    expected_ids = {row["game_id"] for row in rows}
    if not isinstance(replay_bytes_by_game_id, Mapping) or set(replay_bytes_by_game_id) != expected_ids:
        raise ChronologyError("replay byte snapshot must exactly cover literal first24")
    games: list[dict[str, Any]] = []
    for row in rows:
        replay = _replay_game_bytes(
            replay_bytes_by_game_id[row["game_id"]],
            game_id=row["game_id"],
            team_name=team_name,
        )
        games.append(
            {
                "game_id": row["game_id"],
                "created_at_utc": row["created_at_utc"],
                "ended_at_utc": row["ended_at_utc"],
                **replay,
            }
        )
    modules = {game["module_version"] for game in games}
    if len(modules) != 1:
        raise ChronologyError("literal first24 crosses module versions")
    content = {
        "schema": HORIZON_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "permit_content_sha256": receipt["permit_content_sha256"],
        "submission_receipt_content_sha256": receipt["content_sha256"],
        "archive_sha256": receipt["archive_sha256"],
        "lineage_uuid": receipt["lineage_uuid"],
        "pair_id": receipt["pair_id"],
        "wave_id": receipt["wave_id"],
        "slot": receipt["slot"],
        "submission_ref": receipt["submission_ref"],
        "submission_created_at_utc": receipt["submission_created_at_utc"],
        "episodes_csv_sha256": episodes_sha,
        "module_version": next(iter(modules)),
        "games": games,
        "outcomes": [game["outcome"] for game in games],
        "first_game_created_at_utc": games[0]["created_at_utc"],
        "last_game_created_at_utc": games[-1]["created_at_utc"],
        "horizon_games": 24,
        "setup_games_excluded": 0,
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def build_literal_first24_horizon_from_snapshot(
    *,
    authorization: Mapping[str, Any],
    permit: object,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    submission_receipt: object,
    authenticated_submissions_csv_bytes: bytes,
    local_archive_sha256: str,
    episodes_csv_bytes: bytes,
    replay_bytes_by_game_id: Mapping[str, bytes],
    team_name: str,
) -> dict[str, Any]:
    validated_permit = validate_research_permit(
        permit,
        authorization,
        ledger_path=usage_ledger_path,
        artifacts=artifacts,
    )
    raw = _exact_fields(
        submission_receipt,
        _SUBMISSION_RECEIPT_FIELDS,
        label="submission receipt",
    )
    receipt = _build_submission_receipt_from_snapshot(
        authorization=authorization,
        validated_permit=validated_permit,
        authenticated_submissions_csv_bytes=authenticated_submissions_csv_bytes,
        local_archive_sha256=local_archive_sha256,
        submission_ref=raw["submission_ref"],
        expected_description=raw["submission_description"],
        first_observed_complete_at_utc=raw["first_observed_complete_at_utc"],
    )
    if dict(raw) != receipt:
        raise ChronologyError("submission receipt does not match authenticated snapshot bytes")
    if not isinstance(team_name, str) or not team_name:
        raise ChronologyError("team_name is required")
    return _build_literal_first24_horizon_from_snapshot(
        authorization=authorization,
        receipt=receipt,
        episodes_csv_bytes=episodes_csv_bytes,
        replay_bytes_by_game_id=replay_bytes_by_game_id,
        team_name=team_name,
    )


def validate_literal_first24_horizon(
    value: object,
    **kwargs: object,
) -> dict[str, Any]:
    raw = _exact_fields(value, _HORIZON_FIELDS, label="literal first24 horizon")
    games = raw["games"]
    if not isinstance(games, list) or len(games) != 24:
        raise ChronologyError("literal first24 horizon must contain exactly 24 games")
    for game in games:
        _exact_fields(game, _GAME_FIELDS, label="horizon game")
    expected = build_literal_first24_horizon(**kwargs)  # type: ignore[arg-type]
    if dict(raw) != expected:
        raise ChronologyError("literal first24 horizon is not the exact raw-data rebuild")
    return expected


def _pair_assignments(authorization: Mapping[str, Any], pair_id: str) -> list[Mapping[str, Any]]:
    assignments = authorization.get("archive_assignments")
    if not isinstance(assignments, list):
        raise ChronologyError("authorization archive assignments are missing")
    pair_ids = sorted(
        {
            row.get("pair_id")
            for row in assignments
            if isinstance(row, Mapping) and isinstance(row.get("pair_id"), str)
        }
    )
    if pair_id not in pair_ids:
        raise ChronologyError("pair_id is not present in authorization")
    rows = [
        row
        for row in assignments
        if isinstance(row, Mapping) and row.get("pair_id") == pair_id
    ]
    rows.sort(key=lambda row: row.get("slot"))
    if len(rows) != 2 or [row.get("slot") for row in rows] != [1, 2]:
        raise ChronologyError("pair must contain exact slots 1 and 2")
    return rows


def build_pair_completion_barrier(
    *,
    authorization: Mapping[str, Any],
    pair_id: str,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    member_evidence_by_lineage_uuid: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    """Rebuild a completed pair from both exact hosted first-24 horizons.

    The returned receipt is the only admissible prerequisite for issuing the
    following pair.  It intentionally opens and validates the raw submissions
    CSV, archive, episodes CSV, and replay JSON files for both members.
    """

    rows = _pair_assignments(authorization, pair_id)
    expected_uuids = [str(row["lineage_uuid"]) for row in rows]
    if not isinstance(member_evidence_by_lineage_uuid, Mapping) or set(
        member_evidence_by_lineage_uuid
    ) != set(expected_uuids):
        raise ChronologyError("pair evidence must exactly cover both authorized lineages")

    members: list[dict[str, Any]] = []
    prior_hashes: set[str | None] = set()
    for row in rows:
        lineage_uuid = str(row["lineage_uuid"])
        evidence = _exact_fields(
            member_evidence_by_lineage_uuid[lineage_uuid],
            _PAIR_MEMBER_EVIDENCE_FIELDS,
            label="pair member evidence",
        )
        permit = validate_research_permit(
            evidence["permit"],
            authorization,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        if any(
            permit[field] != row[field]
            for field in ("archive_sha256", "lineage_uuid", "pair_id", "wave_id", "slot")
        ):
            raise ChronologyError("pair member permit does not match authorization assignment")
        prior_hash = permit.get("prior_pair_barrier_content_sha256")
        if prior_hash is not None:
            prior_hash = _sha(prior_hash, label="prior_pair_barrier_content_sha256")
        prior_hashes.add(prior_hash)
        receipt = validate_submission_receipt(
            evidence["submission_receipt"],
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            authenticated_submissions_csv=evidence["authenticated_submissions_csv"],
            local_archive=evidence["local_archive"],
        )
        horizon = build_literal_first24_horizon(
            authorization=authorization,
            permit=permit,
            usage_ledger_path=usage_ledger_path,
            artifacts=artifacts,
            submission_receipt=receipt,
            authenticated_submissions_csv=evidence["authenticated_submissions_csv"],
            local_archive=evidence["local_archive"],
            submission_directory=evidence["submission_directory"],
            team_name=evidence["team_name"],
        )
        last_ended = max(
            (_utc(game["ended_at_utc"], label="game ended_at_utc") for game in horizon["games"]),
            key=lambda item: item[0],
        )[1]
        members.append(
            {
                "lineage_uuid": lineage_uuid,
                "slot": row["slot"],
                "archive_sha256": horizon["archive_sha256"],
                "permit_content_sha256": permit["content_sha256"],
                "submission_receipt_content_sha256": horizon[
                    "submission_receipt_content_sha256"
                ],
                "authenticated_submissions_csv_sha256": receipt[
                    "authenticated_submissions_csv_sha256"
                ],
                "horizon_content_sha256": horizon["content_sha256"],
                "submission_ref": horizon["submission_ref"],
                "submission_created_at_utc": horizon["submission_created_at_utc"],
                "first_game_created_at_utc": horizon["first_game_created_at_utc"],
                "last_game_ended_at_utc": last_ended,
                "module_version": horizon["module_version"],
                "horizon_games": horizon["horizon_games"],
            }
        )

    if len(prior_hashes) != 1:
        raise ChronologyError("pair members do not share one prior completion barrier")
    prior_hash = next(iter(prior_hashes))
    all_pair_ids = sorted({str(row["pair_id"]) for row in authorization["archive_assignments"]})
    pair_index = all_pair_ids.index(pair_id)
    if pair_index == 0 and prior_hash is not None:
        raise ChronologyError("first pair must not claim a prior completion barrier")
    if pair_index > 0 and prior_hash is None:
        raise ChronologyError("later pair is missing its prior completion barrier binding")

    submission_times = [
        _utc(member["submission_created_at_utc"], label="submission_created_at_utc")
        for member in members
    ]
    first_game_times = [
        _utc(member["first_game_created_at_utc"], label="first_game_created_at_utc")
        for member in members
    ]
    completion_times = [
        _utc(member["last_game_ended_at_utc"], label="last_game_ended_at_utc")
        for member in members
    ]
    exposure_complete = max(submission_times, key=lambda item: item[0])
    horizon_started = min(first_game_times, key=lambda item: item[0])
    horizon_completed = max(completion_times, key=lambda item: item[0])
    if horizon_started[0] <= exposure_complete[0]:
        raise ChronologyError("pair horizon began before both members occupied latest-two")
    modules = {member["module_version"] for member in members}
    if len(modules) != 1:
        raise ChronologyError("pair horizons cross hosted module versions")
    wave_ids = {str(row["wave_id"]) for row in rows}
    if len(wave_ids) != 1:
        raise ChronologyError("pair assignments cross waves")

    csv_hashes = {member["authenticated_submissions_csv_sha256"] for member in members}
    if len(csv_hashes) != 1:
        raise ChronologyError("pair members must use one identical authenticated submissions snapshot")
    first_evidence = member_evidence_by_lineage_uuid[expected_uuids[0]]
    submission_rows, snapshot_sha = _submission_rows(Path(first_evidence["authenticated_submissions_csv"]))
    if snapshot_sha != next(iter(csv_hashes)):
        raise ChronologyError("authenticated submissions snapshot hash mismatch")
    target_refs = {member["submission_ref"] for member in members}
    eligible_at_start = sorted(
        (
            (_utc(row["date"], label="submission date")[0], int(row["ref"]), row["ref"])
            for row in submission_rows
            if _utc(row["date"], label="submission date")[0] <= horizon_started[0]
        ),
        key=lambda item: (item[0], item[1]),
    )
    if len(eligible_at_start) < 2 or {row[2] for row in eligible_at_start[-2:]} != target_refs:
        raise ChronologyError("pair members were not the exact latest-two submissions at horizon start")
    interfering = [
        row["ref"]
        for row in submission_rows
        if row["ref"] not in target_refs
        and horizon_started[0]
        < _utc(row["date"], label="submission date")[0]
        <= horizon_completed[0]
    ]
    if interfering:
        raise ChronologyError("a later submission displaced the pair during its literal horizon")

    content = {
        "schema": PAIR_COMPLETION_BARRIER_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "pair_id": pair_id,
        "wave_id": next(iter(wave_ids)),
        "prior_pair_barrier_content_sha256": prior_hash,
        "authenticated_submissions_csv_sha256": snapshot_sha,
        "latest_two_submission_refs": sorted(target_refs, key=int),
        "members": members,
        "latest_two_exposure_complete_at_utc": exposure_complete[1],
        "horizon_started_at_utc": horizon_started[1],
        "horizon_completed_at_utc": horizon_completed[1],
        "module_version": next(iter(modules)),
        "horizon_games_per_member": 24,
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_pair_completion_barrier(
    value: object,
    *,
    authorization: Mapping[str, Any],
    pair_id: str,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    member_evidence_by_lineage_uuid: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    raw = _exact_fields(value, _PAIR_BARRIER_FIELDS, label="pair completion barrier")
    members = raw["members"]
    if not isinstance(members, list) or len(members) != 2:
        raise ChronologyError("pair completion barrier must contain exactly two members")
    for member in members:
        _exact_fields(member, _PAIR_MEMBER_FIELDS, label="pair completion member")
    expected = build_pair_completion_barrier(
        authorization=authorization,
        pair_id=pair_id,
        usage_ledger_path=usage_ledger_path,
        artifacts=artifacts,
        member_evidence_by_lineage_uuid=member_evidence_by_lineage_uuid,
    )
    if dict(raw) != expected:
        raise ChronologyError("pair completion barrier is not the exact raw-data rebuild")
    return expected


def build_pair_completion_barrier_from_snapshots(
    *,
    authorization: Mapping[str, Any],
    pair_id: str,
    usage_ledger_path: str | Path,
    artifacts: Mapping[str, object],
    authenticated_submissions_csv_bytes: bytes,
    member_snapshots_by_lineage_uuid: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    """Build a pair barrier exclusively from detached authenticated bytes."""

    rows = _pair_assignments(authorization, pair_id)
    expected_uuids = [str(row["lineage_uuid"]) for row in rows]
    if not isinstance(member_snapshots_by_lineage_uuid, Mapping) or set(
        member_snapshots_by_lineage_uuid
    ) != set(expected_uuids):
        raise ChronologyError("live pair snapshots must exactly cover both authorized lineages")
    submission_rows, snapshot_sha = _submission_rows_bytes(authenticated_submissions_csv_bytes)
    members: list[dict[str, Any]] = []
    prior_hashes: set[str | None] = set()
    for row in rows:
        lineage_uuid = str(row["lineage_uuid"])
        snapshot = _exact_fields(
            member_snapshots_by_lineage_uuid[lineage_uuid],
            _LIVE_PAIR_MEMBER_FIELDS,
            label="live pair member snapshot",
        )
        permit = validate_research_permit(
            snapshot["permit"],
            authorization,
            ledger_path=usage_ledger_path,
            artifacts=artifacts,
        )
        if any(
            permit[field] != row[field]
            for field in ("archive_sha256", "lineage_uuid", "pair_id", "wave_id", "slot")
        ):
            raise ChronologyError("live pair permit does not match authorization assignment")
        prior_hash = permit.get("prior_pair_barrier_content_sha256")
        if prior_hash is not None:
            prior_hash = _sha(prior_hash, label="prior_pair_barrier_content_sha256")
        prior_hashes.add(prior_hash)
        receipt = _exact_fields(
            snapshot["submission_receipt"],
            _SUBMISSION_RECEIPT_FIELDS,
            label="live submission receipt",
        )
        if receipt["content_sha256"] != canonical_sha256(
            {field: receipt[field] for field in _SUBMISSION_FIELDS}
        ):
            raise ChronologyError("live submission receipt content SHA-256 mismatch")
        horizon = _exact_fields(snapshot["horizon"], _HORIZON_FIELDS, label="live horizon")
        if horizon["content_sha256"] != canonical_sha256(
            {field: horizon[field] for field in _HORIZON_CONTENT_FIELDS}
        ):
            raise ChronologyError("live horizon content SHA-256 mismatch")
        if (
            receipt["permit_content_sha256"] != permit["content_sha256"]
            or receipt["authenticated_submissions_csv_sha256"] != snapshot_sha
            or horizon["submission_receipt_content_sha256"] != receipt["content_sha256"]
            or horizon["permit_content_sha256"] != permit["content_sha256"]
            or horizon["lineage_uuid"] != lineage_uuid
            or horizon["pair_id"] != pair_id
        ):
            raise ChronologyError("live receipt/horizon identity binding mismatch")
        games = horizon["games"]
        if not isinstance(games, list) or len(games) != 24:
            raise ChronologyError("live horizon must contain exactly 24 games")
        for game in games:
            _exact_fields(game, _GAME_FIELDS, label="live horizon game")
        last_ended = max(
            (_utc(game["ended_at_utc"], label="game ended_at_utc") for game in games),
            key=lambda item: item[0],
        )[1]
        members.append(
            {
                "lineage_uuid": lineage_uuid,
                "slot": row["slot"],
                "archive_sha256": horizon["archive_sha256"],
                "permit_content_sha256": permit["content_sha256"],
                "submission_receipt_content_sha256": receipt["content_sha256"],
                "authenticated_submissions_csv_sha256": snapshot_sha,
                "horizon_content_sha256": horizon["content_sha256"],
                "submission_ref": horizon["submission_ref"],
                "submission_created_at_utc": horizon["submission_created_at_utc"],
                "first_game_created_at_utc": horizon["first_game_created_at_utc"],
                "last_game_ended_at_utc": last_ended,
                "module_version": horizon["module_version"],
                "horizon_games": horizon["horizon_games"],
            }
        )

    if len(prior_hashes) != 1:
        raise ChronologyError("pair members do not share one prior completion barrier")
    prior_hash = next(iter(prior_hashes))
    all_pair_ids = sorted({str(row["pair_id"]) for row in authorization["archive_assignments"]})
    pair_index = all_pair_ids.index(pair_id)
    if pair_index == 0 and prior_hash is not None:
        raise ChronologyError("first pair must not claim a prior completion barrier")
    if pair_index > 0 and prior_hash is None:
        raise ChronologyError("later pair is missing its prior completion barrier binding")

    submission_times = [
        _utc(member["submission_created_at_utc"], label="submission_created_at_utc")
        for member in members
    ]
    first_game_times = [
        _utc(member["first_game_created_at_utc"], label="first_game_created_at_utc")
        for member in members
    ]
    completion_times = [
        _utc(member["last_game_ended_at_utc"], label="last_game_ended_at_utc")
        for member in members
    ]
    exposure_complete = max(submission_times, key=lambda item: item[0])
    horizon_started = min(first_game_times, key=lambda item: item[0])
    horizon_completed = max(completion_times, key=lambda item: item[0])
    if horizon_started[0] <= exposure_complete[0]:
        raise ChronologyError("pair horizon began before both members occupied latest-two")
    modules = {member["module_version"] for member in members}
    if len(modules) != 1:
        raise ChronologyError("pair horizons cross hosted module versions")
    wave_ids = {str(row["wave_id"]) for row in rows}
    if len(wave_ids) != 1:
        raise ChronologyError("pair assignments cross waves")
    target_refs = {member["submission_ref"] for member in members}
    eligible_at_start = sorted(
        (
            (_utc(row["date"], label="submission date")[0], int(row["ref"]), row["ref"])
            for row in submission_rows
            if _utc(row["date"], label="submission date")[0] <= horizon_started[0]
        ),
        key=lambda item: (item[0], item[1]),
    )
    if len(eligible_at_start) < 2 or {item[2] for item in eligible_at_start[-2:]} != target_refs:
        raise ChronologyError("pair members were not the exact latest-two submissions at horizon start")
    if any(
        row["ref"] not in target_refs
        and horizon_started[0] < _utc(row["date"], label="submission date")[0] <= horizon_completed[0]
        for row in submission_rows
    ):
        raise ChronologyError("a later submission displaced the pair during its literal horizon")
    content = {
        "schema": PAIR_COMPLETION_BARRIER_SCHEMA,
        "authorization_sha256": authorization["content_sha256"],
        "pair_id": pair_id,
        "wave_id": next(iter(wave_ids)),
        "prior_pair_barrier_content_sha256": prior_hash,
        "authenticated_submissions_csv_sha256": snapshot_sha,
        "latest_two_submission_refs": sorted(target_refs, key=int),
        "members": members,
        "latest_two_exposure_complete_at_utc": exposure_complete[1],
        "horizon_started_at_utc": horizon_started[1],
        "horizon_completed_at_utc": horizon_completed[1],
        "module_version": next(iter(modules)),
        "horizon_games_per_member": 24,
        "research_only": True,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def write_receipt_once(path: str | Path, value: Mapping[str, Any]) -> Path:
    if value.get("schema") not in {
        SUBMISSION_RECEIPT_SCHEMA,
        HORIZON_SCHEMA,
        PAIR_COMPLETION_BARRIER_SCHEMA,
    }:
        raise ChronologyError("unsupported chronology receipt schema")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("xb") as handle:
            handle.write(canonical_json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"chronology receipt already exists: {target}") from None
    return target


__all__ = [
    "HORIZON_SCHEMA",
    "PAIR_COMPLETION_BARRIER_SCHEMA",
    "SUBMISSION_RECEIPT_SCHEMA",
    "ChronologyError",
    "build_literal_first24_horizon",
    "build_literal_first24_horizon_from_snapshot",
    "build_pair_completion_barrier",
    "build_pair_completion_barrier_from_snapshots",
    "build_submission_receipt",
    "build_submission_receipt_from_snapshot",
    "validate_literal_first24_horizon",
    "validate_pair_completion_barrier",
    "validate_submission_receipt",
    "write_receipt_once",
]
