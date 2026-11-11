"""Literal 8+24 public-game horizon extraction for externally anchored units."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

from .evidence import PredictionRegistration, sha256_file


COMPLETED_STATE = "EpisodeState.COMPLETED"
PUBLIC_TYPE = "EpisodeType.EPISODE_TYPE_PUBLIC"


def _utc(value: object, *, label: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    return parsed, parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _read_episode_rows(path: Path, *, after: datetime) -> list[dict[str, Any]]:
    required = {"id", "createTime", "endTime", "state", "type"}
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = set(reader.fieldnames or [])
            if not required.issubset(headers):
                raise ValueError("episodes.csv is missing required columns")
            rows: list[dict[str, Any]] = []
            seen: set[str] = set()
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ValueError(f"episodes.csv:{row_number} has extra columns")
                game_id = str(row.get("id") or "").strip()
                if not game_id:
                    continue
                if game_id in seen:
                    raise ValueError(f"episodes.csv has duplicate id {game_id}")
                seen.add(game_id)
                created, created_text = _utc(row.get("createTime"), label=f"episodes.csv:{row_number} createTime")
                ended: datetime | None = None
                ended_text: str | None = None
                if str(row.get("endTime") or "").strip():
                    ended, ended_text = _utc(row.get("endTime"), label=f"episodes.csv:{row_number} endTime")
                    if ended < created:
                        raise ValueError(f"episodes.csv:{row_number} ends before creation")
                if str(row.get("type") or "").strip() != PUBLIC_TYPE or created <= after:
                    continue
                rows.append(
                    {
                        "game_id": game_id,
                        "created": created,
                        "created_at_utc": created_text,
                        "ended": ended,
                        "ended_at_utc": ended_text,
                        "state": str(row.get("state") or "").strip(),
                        "type": str(row.get("type") or "").strip(),
                    }
                )
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ValueError(f"cannot parse episodes.csv: {exc}") from exc
    rows.sort(key=lambda row: (row["created"], row["game_id"]))
    if len(rows) < 32:
        raise ValueError(f"only {len(rows)} public games exist after the external anchor; 32 required")
    horizon = rows[:32]
    incomplete = [
        row["game_id"]
        for row in horizon
        if row["state"] != COMPLETED_STATE or row["ended"] is None
    ]
    if incomplete:
        raise ValueError(f"literal first-32 horizon contains non-completed games: {', '.join(incomplete)}")
    return horizon


def _replay_outcome(path: Path, *, game_id: str, team_name: str) -> dict[str, Any]:
    try:
        replay = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read replay {game_id}: {exc}") from exc
    if str(replay.get("id")) != game_id:
        raise ValueError(f"replay id mismatch for {game_id}")
    info = replay.get("info")
    teams = info.get("TeamNames") if isinstance(info, dict) else None
    if not isinstance(teams, list) or teams.count(team_name) != 1:
        raise ValueError(f"replay {game_id} does not contain team {team_name!r} exactly once")
    slot = teams.index(team_name)
    steps = replay.get("steps")
    if not isinstance(steps, list) or not steps or not isinstance(steps[-1], list) or len(steps[-1]) != 2:
        raise ValueError(f"replay {game_id} has no terminal two-player step")
    terminal = steps[-1][slot]
    reward = terminal.get("reward") if isinstance(terminal, dict) else None
    status = terminal.get("status") if isinstance(terminal, dict) else None
    if isinstance(reward, bool) or not isinstance(reward, (int, float)) or status != "DONE":
        raise ValueError(f"replay {game_id} has no terminal reward")
    outcome = 1.0 if float(reward) > 0 else 0.0 if float(reward) < 0 else 0.5
    module_version = replay.get("module_version")
    if not isinstance(module_version, str) or not module_version:
        raise ValueError(f"replay {game_id} has no module_version")
    return {
        "replay_path": str(path),
        "replay_sha256": sha256_file(path),
        "target_slot": slot,
        "outcome": outcome,
        "module_version": module_version,
    }


def build_literal_horizon(
    registration: PredictionRegistration,
    anchor_receipt: Mapping[str, Any],
    submission_dir: Path,
) -> dict[str, Any]:
    """Build a deterministic unit from the literal first 32 post-anchor games."""

    if anchor_receipt.get("schema") != "kaggle_prediction_anchor_receipt_v1" or anchor_receipt.get("anchor_verified") is not True:
        raise ValueError("a verified Kaggle anchor receipt is required")
    if anchor_receipt.get("registration_sha256") is None:
        raise ValueError("anchor receipt does not bind a registration")
    submission_ref = str(anchor_receipt.get("submission_ref") or "")
    expected_part = f"submission_{submission_ref}"
    if expected_part not in submission_dir.parts:
        raise ValueError("submission directory does not match anchored submission_ref")
    anchor_time, anchor_text = _utc(anchor_receipt.get("submission_date_utc"), label="anchor submission_date_utc")
    episodes_path = submission_dir / "episodes.csv"
    rows = _read_episode_rows(episodes_path, after=anchor_time)
    games: list[dict[str, Any]] = []
    for row in rows:
        replay_path = submission_dir / f"episode-{row['game_id']}-replay.json"
        replay = _replay_outcome(replay_path, game_id=row["game_id"], team_name=registration.team_name)
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
        raise ValueError("literal horizon crosses module versions")
    return {
        "schema": "whole_policy_literal_horizon_v1",
        "unit_id": registration.unit_id,
        "submission_ref": submission_ref,
        "anchor_submission_date_utc": anchor_text,
        "episodes_csv_path": str(episodes_path),
        "episodes_csv_sha256": sha256_file(episodes_path),
        "module_version": next(iter(modules)),
        "setup_game_ids": [game["game_id"] for game in games[:8]],
        "followup_games": games[8:],
        "outcomes": [game["outcome"] for game in games[8:]],
        "scope": "post_submission_calibration_only",
        "first_submission_authorized": False,
    }


def write_horizon_create_once(path: Path, horizon: Mapping[str, Any]) -> None:
    if horizon.get("schema") != "whole_policy_literal_horizon_v1":
        raise ValueError("literal horizon schema mismatch")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(horizon, indent=2, sort_keys=True))
        handle.write("\n")


__all__ = ["build_literal_horizon", "write_horizon_create_once"]
