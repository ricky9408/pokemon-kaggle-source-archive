"""Authoritative, fail-closed v3 outcome-transfer promotion composer."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
from typing import Any

from .episode_inventory import COMPLETED_STATE, PUBLIC_TYPE, sha256_file
from .evidence_log import verify_event_log


PROTOCOL_SCHEMA = "outcome_transfer_protocol_v3"
IDENTIFICATION_SCHEMA = "candidate_identifiability_validation_v1"
REGISTRATION_SCHEMA = "candidate_public_intervention_registration_v1"
CHRONOLOGY_SCHEMA = "candidate_public_intervention_chronology_v1"
TRANSFER_SCHEMA = "public_transfer_validation_v2"
CANDIDATE_SCHEMA = "candidate_matched_outcome_v2"
SAFETY_SCHEMA = "candidate_safety_burnin_v2"
HOLDOUT_SCHEMA = "sealed_holdout_verdict_v2"
REGISTRATION_EVENT = "candidate_public_intervention_registration"
CLOSURE_EVENT = "candidate_public_intervention_closure"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_THRESHOLD_FIELDS = {
    "residual_min",
    "logloss_lift_min",
    "bootstrap_q10_min",
    "bootstrap_probability_min",
    "bootstrap_samples",
    "seed",
}


@dataclass(frozen=True)
class PromotionCheck:
    name: str
    passed: bool
    detail: str


def _load_json(path: Path, *, expected_schema: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"cannot read JSON: {exc}"
    if not isinstance(value, dict):
        return None, "artifact must be a JSON object"
    if value.get("schema") != expected_schema:
        return None, f"schema={value.get('schema')!r}, expected={expected_schema!r}"
    return value, None


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _canonical_utc(value: object, *, label: str, require_canonical: bool = True) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty UTC timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not ISO-8601 UTC") from exc
    if parsed.tzinfo is None:
        if require_canonical:
            raise ValueError(f"{label} must include a UTC offset")
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if require_canonical and text != normalized:
        raise ValueError(f"{label} must be canonical UTC ({normalized})")
    return parsed, normalized


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{label} must be a finite number")
    return float(value)


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _resolve_reference(owner: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is required")
    path = Path(value)
    return path if path.is_absolute() else owner.parent / path


def _protocol_check(protocol: dict[str, Any] | None) -> tuple[PromotionCheck, dict[str, Any] | None]:
    if protocol is None:
        return PromotionCheck("frozen_protocol", False, "protocol artifact is unavailable"), None
    exact = {
        "schema",
        "protocol_id",
        "evaluator_sha256",
        "candidate_archive_sha256",
        "sealed_holdout_id",
        "retirement_cutoff_utc",
        "frozen_at_utc",
        "identification_thresholds",
        "state",
    }
    try:
        if set(protocol) != exact:
            raise ValueError(f"protocol fields must exactly be {sorted(exact)}")
        protocol_id = _identifier(protocol["protocol_id"], label="protocol_id")
        sealed_holdout_id = _identifier(protocol["sealed_holdout_id"], label="sealed_holdout_id")
        evaluator = protocol["evaluator_sha256"]
        archive = protocol["candidate_archive_sha256"]
        if not _is_sha256(evaluator) or not _is_sha256(archive):
            raise ValueError("protocol evaluator_sha256 and candidate_archive_sha256 must be SHA-256")
        retirement, _ = _canonical_utc(protocol["retirement_cutoff_utc"], label="retirement_cutoff_utc")
        frozen_at, _ = _canonical_utc(protocol["frozen_at_utc"], label="frozen_at_utc")
        if frozen_at <= retirement:
            raise ValueError("frozen_at_utc must be after retirement_cutoff_utc")
        if protocol["state"] != "FROZEN":
            raise ValueError("protocol state must be FROZEN")
        thresholds = protocol["identification_thresholds"]
        if not isinstance(thresholds, dict) or set(thresholds) != _THRESHOLD_FIELDS:
            raise ValueError(f"identification_thresholds fields must exactly be {sorted(_THRESHOLD_FIELDS)}")
        normalized_thresholds = {
            "residual_min": _number(thresholds["residual_min"], label="residual_min"),
            "logloss_lift_min": _number(thresholds["logloss_lift_min"], label="logloss_lift_min"),
            "bootstrap_q10_min": _number(thresholds["bootstrap_q10_min"], label="bootstrap_q10_min"),
            "bootstrap_probability_min": _number(
                thresholds["bootstrap_probability_min"], label="bootstrap_probability_min"
            ),
            "bootstrap_samples": thresholds["bootstrap_samples"],
            "seed": thresholds["seed"],
        }
        if not 0.0 <= normalized_thresholds["bootstrap_probability_min"] <= 1.0:
            raise ValueError("bootstrap_probability_min must be in [0, 1]")
        for field in ("bootstrap_samples", "seed"):
            if isinstance(normalized_thresholds[field], bool) or not isinstance(normalized_thresholds[field], int):
                raise ValueError(f"{field} must be an integer")
        if normalized_thresholds["bootstrap_samples"] <= 0:
            raise ValueError("bootstrap_samples must be positive")
        return PromotionCheck("frozen_protocol", True, protocol_id), {
            "protocol_id": protocol_id,
            "sealed_holdout_id": sealed_holdout_id,
            "evaluator_sha256": str(evaluator),
            "archive_sha256": str(archive),
            "retirement_cutoff": retirement,
            "frozen_at": frozen_at,
            "thresholds": normalized_thresholds,
        }
    except (KeyError, TypeError, ValueError) as exc:
        return PromotionCheck("frozen_protocol", False, str(exc)), None


def _bind(
    artifact: dict[str, Any] | None,
    *,
    name: str,
    protocol_sha256: str | None,
    evaluator_sha256: str | None,
    archive_sha256: str | None = None,
) -> PromotionCheck:
    if artifact is None:
        return PromotionCheck(name, False, "artifact unavailable")
    expected = {"protocol_sha256": protocol_sha256, "evaluator_sha256": evaluator_sha256}
    if archive_sha256 is not None:
        expected["archive_sha256"] = archive_sha256
    mismatches = [field for field, value in expected.items() if value is None or artifact.get(field) != value]
    return PromotionCheck(
        name,
        not mismatches,
        "bound" if not mismatches else f"mismatched or missing: {', '.join(mismatches)}",
    )


def _registration_check(
    registration: dict[str, Any] | None,
    *,
    protocol_sha256: str | None,
    evaluator_sha256: str | None,
    archive_sha256: str | None,
) -> tuple[PromotionCheck, dict[str, Any] | None]:
    if registration is None:
        return PromotionCheck("registration_manifest", False, "registration manifest unavailable"), None
    exact = {
        "schema",
        "unit_id",
        "protocol_sha256",
        "evaluator_sha256",
        "archive_sha256",
        "submission_id",
        "setup_game_ids",
        "registered_at_utc",
        "nuisance_probability",
        "candidate_probability",
    }
    try:
        if set(registration) != exact:
            raise ValueError(f"registration fields must exactly be {sorted(exact)}")
        for field, expected in {
            "protocol_sha256": protocol_sha256,
            "evaluator_sha256": evaluator_sha256,
            "archive_sha256": archive_sha256,
        }.items():
            if expected is None or registration[field] != expected:
                raise ValueError(f"registration {field} mismatch")
        unit_id = _identifier(registration["unit_id"], label="registration unit_id")
        submission_id = _identifier(registration["submission_id"], label="registration submission_id")
        ids = registration["setup_game_ids"]
        if (
            not isinstance(ids, list)
            or len(ids) != 8
            or len(set(ids)) != 8
            or any(not isinstance(value, str) or not value for value in ids)
        ):
            raise ValueError("registration requires exactly 8 unique setup_game_ids")
        registered_at, registered_text = _canonical_utc(
            registration["registered_at_utc"], label="registration registered_at_utc"
        )
        p0 = _number(registration["nuisance_probability"], label="nuisance_probability")
        p1 = _number(registration["candidate_probability"], label="candidate_probability")
        if not 0.0 < p0 < 1.0 or not 0.0 < p1 < 1.0:
            raise ValueError("registered probabilities must be inside (0, 1)")
        normalized = dict(registration)
        normalized.update(
            {
                "_unit_id": unit_id,
                "_submission_id": submission_id,
                "_setup_ids": list(ids),
                "_registered_at": registered_at,
                "_registered_text": registered_text,
                "_p0": p0,
                "_p1": p1,
            }
        )
        return PromotionCheck("registration_manifest", True, f"unit={unit_id}"), normalized
    except (KeyError, TypeError, ValueError) as exc:
        return PromotionCheck("registration_manifest", False, str(exc)), None


def _game_records(value: object, *, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an ordered list")
    exact = {
        "game_id",
        "submission_id",
        "created_at_utc",
        "ended_at_utc",
        "state",
        "type",
        "module_version",
        "outcome",
    }
    records: list[dict[str, Any]] = []
    for index, game in enumerate(value, start=1):
        if not isinstance(game, dict) or set(game) != exact:
            raise ValueError(f"{label}[{index}] fields must exactly be {sorted(exact)}")
        game_id = _identifier(game["game_id"], label=f"{label}[{index}] game_id")
        submission_id = _identifier(game["submission_id"], label=f"{label}[{index}] submission_id")
        module_version = _identifier(game["module_version"], label=f"{label}[{index}] module_version")
        if game["state"] != COMPLETED_STATE or game["type"] != PUBLIC_TYPE:
            raise ValueError(f"{label}[{index}] must be COMPLETED PUBLIC")
        created, created_text = _canonical_utc(game["created_at_utc"], label=f"{label}[{index}] created_at_utc")
        ended, ended_text = _canonical_utc(game["ended_at_utc"], label=f"{label}[{index}] ended_at_utc")
        if ended < created:
            raise ValueError(f"{label}[{index}] ends before it is created")
        outcome = _number(game["outcome"], label=f"{label}[{index}] outcome")
        if outcome not in (0.0, 0.5, 1.0):
            raise ValueError(f"{label}[{index}] outcome must be 0, 0.5, or 1")
        records.append(
            {
                **game,
                "game_id": game_id,
                "submission_id": submission_id,
                "module_version": module_version,
                "outcome": outcome,
                "_created": created,
                "_created_text": created_text,
                "_ended": ended,
                "_ended_text": ended_text,
            }
        )
    return records


def _chronology_check(
    chronology: dict[str, Any] | None,
    *,
    protocol_sha256: str | None,
    evaluator_sha256: str | None,
    archive_sha256: str | None,
    registration_sha256: str | None,
    registration: dict[str, Any] | None,
    frozen_at: datetime | None,
) -> tuple[PromotionCheck, dict[str, Any] | None]:
    if chronology is None:
        return PromotionCheck("intervention_chronology", False, "chronology manifest unavailable"), None
    exact = {
        "schema",
        "unit_id",
        "protocol_sha256",
        "evaluator_sha256",
        "archive_sha256",
        "registration_manifest_sha256",
        "submission_id",
        "source_episodes_path",
        "source_episodes_sha256",
        "setup_games",
        "followup_games",
    }
    try:
        if set(chronology) != exact:
            raise ValueError(f"chronology fields must exactly be {sorted(exact)}")
        for field, expected in {
            "protocol_sha256": protocol_sha256,
            "evaluator_sha256": evaluator_sha256,
            "archive_sha256": archive_sha256,
            "registration_manifest_sha256": registration_sha256,
        }.items():
            if expected is None or chronology[field] != expected:
                raise ValueError(f"chronology {field} mismatch")
        if registration is None:
            raise ValueError("valid registration manifest is required")
        unit_id = _identifier(chronology["unit_id"], label="chronology unit_id")
        submission_id = _identifier(chronology["submission_id"], label="chronology submission_id")
        if unit_id != registration["_unit_id"] or submission_id != registration["_submission_id"]:
            raise ValueError("chronology unit_id/submission_id does not match registration")
        if not _is_sha256(chronology["source_episodes_sha256"]):
            raise ValueError("source_episodes_sha256 must be SHA-256")
        setup = _game_records(chronology["setup_games"], label="setup_games")
        followup = _game_records(chronology["followup_games"], label="followup_games")
        if len(setup) != 8 or len(followup) != 24:
            raise ValueError("chronology requires exactly 8 setup games and 24 follow-up games")
        games = setup + followup
        ids = [game["game_id"] for game in games]
        if len(set(ids)) != 32:
            raise ValueError("chronology game ids must be unique with no setup/follow-up overlap")
        if ids[:8] != registration["_setup_ids"]:
            raise ValueError("chronology setup IDs do not exactly match registration")
        if any(game["submission_id"] != submission_id for game in games):
            raise ValueError("every game record must bind the one chronology submission_id")
        if len({game["module_version"] for game in games}) != 1:
            raise ValueError("all 32 games must use one module_version")
        creates = [game["_created"] for game in games]
        if any(left >= right for left, right in zip(creates, creates[1:])):
            raise ValueError("all 32 game create times must be strictly ordered")
        if frozen_at is None or any(created <= frozen_at for created in creates):
            raise ValueError("every game must be created after protocol frozen_at_utc")
        registered_at = registration["_registered_at"]
        if any(game["_ended"] > registered_at for game in setup):
            raise ValueError("every setup game must end at or before registration")
        if followup[0]["_created"] <= registered_at:
            raise ValueError("registration must precede game 9 creation")
        normalized = dict(chronology)
        normalized.update(
            {
                "_setup": setup,
                "_followup": followup,
                "_setup_ids": ids[:8],
                "_followup_ids": ids[8:],
                "_last_followup_end": max(game["_ended"] for game in followup),
            }
        )
        return PromotionCheck("intervention_chronology", True, f"unit={unit_id} submission={submission_id}"), normalized
    except (KeyError, TypeError, ValueError) as exc:
        return PromotionCheck("intervention_chronology", False, str(exc)), None


def _read_raw_episodes(path: Path, *, frozen_at: datetime) -> list[dict[str, Any]]:
    required = {"id", "createTime", "endTime", "state", "type"}
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = [str(value or "").strip() for value in (reader.fieldnames or [])]
            if not headers:
                raise ValueError("episodes.csv has no header")
            if len(headers) != len(set(headers)) or not required.issubset(headers):
                raise ValueError("episodes.csv has missing or duplicate required columns")
            records: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            for row_number, original in enumerate(reader, start=2):
                if None in original:
                    raise ValueError(f"episodes.csv:{row_number} has extra fields")
                row = {str(key).strip(): str(value or "").strip() for key, value in original.items()}
                if not any(row.values()):
                    continue
                if row["id"].startswith("Use ") and not row["state"] and not row["type"]:
                    continue
                game_id = _identifier(row["id"], label=f"episodes.csv:{row_number} id")
                if game_id in seen_ids:
                    raise ValueError(f"episodes.csv has duplicate id {game_id}")
                seen_ids.add(game_id)
                created, created_text = _canonical_utc(
                    row["createTime"], label=f"episodes.csv:{row_number} createTime", require_canonical=False
                )
                ended: datetime | None = None
                ended_text: str | None = None
                if row["endTime"]:
                    ended, ended_text = _canonical_utc(
                        row["endTime"], label=f"episodes.csv:{row_number} endTime", require_canonical=False
                    )
                    if ended < created:
                        raise ValueError(f"episodes.csv:{row_number} endTime precedes createTime")
                records.append(
                    {
                        "game_id": game_id,
                        "created": created,
                        "created_text": created_text,
                        "ended": ended,
                        "ended_text": ended_text,
                        "state": row["state"],
                        "type": row["type"],
                        "submission_id": row.get("submission_id"),
                        "module_version": row.get("module_version"),
                        "outcome": row.get("outcome"),
                    }
                )
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ValueError(f"cannot parse episodes.csv: {exc}") from exc
    public = [row for row in records if row["type"] == PUBLIC_TYPE and row["created"] > frozen_at]
    public.sort(key=lambda row: (row["created"], row["game_id"]))
    if len(public) < 32:
        raise ValueError(f"episodes.csv has only {len(public)} PUBLIC episodes after frozen_at_utc")
    horizon = public[:32]
    incomplete = [row["game_id"] for row in horizon if row["state"] != COMPLETED_STATE or row["ended"] is None]
    if incomplete:
        raise ValueError(f"first-32 PUBLIC horizon contains pending/failed episodes: {', '.join(incomplete)}")
    return horizon


def _raw_chronology_check(
    chronology_path: Path | None,
    chronology: dict[str, Any] | None,
    *,
    frozen_at: datetime | None,
) -> PromotionCheck:
    if chronology_path is None or chronology is None or frozen_at is None:
        return PromotionCheck("raw_episode_chronology", False, "valid chronology and protocol are required")
    try:
        source = _resolve_reference(
            chronology_path, chronology["source_episodes_path"], label="source_episodes_path"
        )
        if source.name != "episodes.csv":
            raise ValueError("raw source must be named episodes.csv")
        actual_hash = sha256_file(source)
        if actual_hash != chronology["source_episodes_sha256"]:
            raise ValueError("episodes.csv hash mismatch")
        raw = _read_raw_episodes(source, frozen_at=frozen_at)
        games = chronology["_setup"] + chronology["_followup"]
        raw_ids = [row["game_id"] for row in raw]
        game_ids = [game["game_id"] for game in games]
        if game_ids != raw_ids:
            raise ValueError("chronology IDs are not literally the first 32 PUBLIC episodes after frozen_at_utc")
        for index, (game, row) in enumerate(zip(games, raw), start=1):
            expected = {
                "created_at_utc": row["created_text"],
                "ended_at_utc": row["ended_text"],
                "state": row["state"],
                "type": row["type"],
            }
            mismatches = [field for field, value in expected.items() if game[field] != value]
            if row["submission_id"] and game["submission_id"] != row["submission_id"]:
                mismatches.append("submission_id")
            if row["module_version"] and game["module_version"] != row["module_version"]:
                mismatches.append("module_version")
            if row["outcome"]:
                try:
                    raw_outcome = _number(float(row["outcome"]), label=f"episodes.csv outcome {row['game_id']}")
                except ValueError as exc:
                    raise ValueError(f"episodes.csv outcome for {row['game_id']} is invalid") from exc
                if game["outcome"] != raw_outcome:
                    mismatches.append("outcome")
            if mismatches:
                raise ValueError(f"chronology game {index} disagrees with episodes.csv: {', '.join(mismatches)}")
        return PromotionCheck("raw_episode_chronology", True, f"first32={raw_ids[0]}..{raw_ids[-1]}")
    except (KeyError, OSError, TypeError, ValueError) as exc:
        return PromotionCheck("raw_episode_chronology", False, str(exc))


def _event_check(
    log_path: Path | None,
    *,
    registration: dict[str, Any] | None,
    registration_sha256: str | None,
    chronology: dict[str, Any] | None,
    chronology_sha256: str | None,
) -> PromotionCheck:
    if None in (log_path, registration, registration_sha256, chronology, chronology_sha256):
        return PromotionCheck("intervention_log_events", False, "valid log, registration, and chronology are required")
    assert log_path is not None and registration is not None and chronology is not None
    assert registration_sha256 is not None and chronology_sha256 is not None
    try:
        events = [json.loads(line) for line in log_path.read_text(encoding="ascii").splitlines()]
        if len(events) != 2:
            raise ValueError("prospective evidence log must contain exactly two events total")
        registered, closed = events
        if registered["event_type"] != REGISTRATION_EVENT or closed["event_type"] != CLOSURE_EVENT:
            raise ValueError("log must contain registration then closure")
        if registered["payload"].get("unit_id") != registration["_unit_id"]:
            raise ValueError("registration event unit_id mismatch")
        if closed["payload"].get("unit_id") != registration["_unit_id"]:
            raise ValueError("closure event unit_id mismatch")
        registration_payload = {
            "unit_id": registration["_unit_id"],
            "registration_manifest_sha256": registration_sha256,
            "setup_game_ids": registration["_setup_ids"],
        }
        if registered["payload"] != registration_payload:
            raise ValueError("registration payload must bind only its manifest hash and setup IDs")
        closure_payload = {
            "unit_id": registration["_unit_id"],
            "chronology_sha256": chronology_sha256,
            "followup_game_ids": chronology["_followup_ids"],
        }
        if closed["payload"] != closure_payload:
            raise ValueError("closure payload must bind the final chronology hash and follow-up IDs")
        if registered["created_at_utc"] != registration["_registered_text"]:
            raise ValueError("registration event timestamp must equal registered_at_utc")
        closure_time, _ = _canonical_utc(closed["created_at_utc"], label="closure event created_at_utc")
        if closure_time < chronology["_last_followup_end"]:
            raise ValueError("closure event timestamp precedes the last follow-up end")
        if registration["_registered_at"] >= chronology["_followup"][0]["_created"]:
            raise ValueError("registration event does not precede game 9")
        return PromotionCheck("intervention_log_events", True, "exact registration and closure chain")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return PromotionCheck("intervention_log_events", False, str(exc))


def compose_promotion_verdict(
    *,
    protocol_path: Path,
    archive_path: Path,
    transfer_path: Path,
    candidate_path: Path,
    safety_path: Path,
    identification_path: Path,
    holdout_path: Path,
) -> dict[str, Any]:
    """Compose a v3 verdict; malformed or missing evidence always closes it."""

    artifact_paths = {
        "protocol": (protocol_path, PROTOCOL_SCHEMA),
        "transfer": (transfer_path, TRANSFER_SCHEMA),
        "candidate": (candidate_path, CANDIDATE_SCHEMA),
        "safety": (safety_path, SAFETY_SCHEMA),
        "identification": (identification_path, IDENTIFICATION_SCHEMA),
        "holdout": (holdout_path, HOLDOUT_SCHEMA),
    }
    artifacts: dict[str, dict[str, Any] | None] = {}
    checks: list[PromotionCheck] = []
    for name, (path, schema) in artifact_paths.items():
        artifact, error = _load_json(path, expected_schema=schema)
        artifacts[name] = artifact
        checks.append(PromotionCheck(f"{name}_schema", artifact is not None, "valid" if artifact else str(error)))

    try:
        archive_sha256 = sha256_file(archive_path)
        checks.append(PromotionCheck("archive_hash", True, archive_sha256))
    except OSError as exc:
        archive_sha256 = None
        checks.append(PromotionCheck("archive_hash", False, f"cannot hash archive: {exc}"))
    protocol_check, protocol = _protocol_check(artifacts["protocol"])
    checks.append(protocol_check)
    try:
        protocol_sha256 = sha256_file(protocol_path) if artifacts["protocol"] is not None else None
        checks.append(PromotionCheck("protocol_hash", protocol_sha256 is not None, str(protocol_sha256)))
    except OSError as exc:
        protocol_sha256 = None
        checks.append(PromotionCheck("protocol_hash", False, f"cannot hash protocol: {exc}"))
    evaluator_sha256 = protocol["evaluator_sha256"] if protocol else None
    checks.append(
        PromotionCheck(
            "protocol_archive_identity",
            protocol is not None and archive_sha256 is not None and protocol["archive_sha256"] == archive_sha256,
            f"expected={protocol['archive_sha256'] if protocol else None} actual={archive_sha256}",
        )
    )

    checks.extend(
        [
            _bind(artifacts["transfer"], name="transfer_binding", protocol_sha256=protocol_sha256, evaluator_sha256=evaluator_sha256),
            _bind(artifacts["candidate"], name="candidate_binding", protocol_sha256=protocol_sha256, evaluator_sha256=evaluator_sha256, archive_sha256=archive_sha256),
            _bind(artifacts["safety"], name="safety_binding", protocol_sha256=protocol_sha256, evaluator_sha256=evaluator_sha256, archive_sha256=archive_sha256),
            _bind(artifacts["holdout"], name="holdout_binding", protocol_sha256=protocol_sha256, evaluator_sha256=evaluator_sha256, archive_sha256=archive_sha256),
        ]
    )
    transfer = artifacts["transfer"] or {}
    candidate = artifacts["candidate"] or {}
    safety = artifacts["safety"] or {}
    holdout = artifacts["holdout"] or {}
    checks.extend(
        [
            PromotionCheck(
                "transfer_certified",
                transfer.get("certified") is True and isinstance(transfer.get("panel_id"), str) and bool(transfer["panel_id"]),
                f"panel_id={transfer.get('panel_id')!r}",
            ),
            PromotionCheck("candidate_outcomes", candidate.get("passed") is True, str(candidate.get("candidate_label") or "")),
            PromotionCheck("safety_burnin", safety.get("passed") is True, str(safety_path)),
            PromotionCheck(
                "sealed_holdout",
                protocol is not None
                and holdout.get("passed") is True
                and holdout.get("sealed_holdout_id") == protocol["sealed_holdout_id"]
                and isinstance(holdout.get("episodes"), int)
                and not isinstance(holdout.get("episodes"), bool)
                and holdout["episodes"] >= 50,
                f"id={holdout.get('sealed_holdout_id')!r} episodes={holdout.get('episodes')!r}",
            ),
        ]
    )
    label = str(candidate.get("candidate_label") or "")
    naming = f"{archive_path.name} {label}".lower()
    checks.append(
        PromotionCheck(
            "naming",
            "final" not in naming and re.search(r"codex.*v\d{3,}", naming) is not None,
            f"archive={archive_path.name} label={label}",
        )
    )

    identification = artifacts["identification"] or {}
    checks.append(
        _bind(
            artifacts["identification"],
            name="identification_binding",
            protocol_sha256=protocol_sha256,
            evaluator_sha256=evaluator_sha256,
            archive_sha256=archive_sha256,
        )
    )
    route = identification.get("route")
    if route == "candidate_public_intervention":
        route_detail = (
            "candidate_public_intervention is disabled: no immutable external registration-anchor "
            "verifier or frozen predictor recomputation is implemented"
        )
    elif route == "public_equivalent_counterfactual_oracle":
        route_detail = "public_equivalent_counterfactual_oracle is not implemented"
    else:
        route_detail = f"unknown route={route!r}"
    checks.append(PromotionCheck("identification_route", False, route_detail))
    checks.extend(
        [
            PromotionCheck(
                "external_registration_anchor",
                False,
                "no verifier for an immutable raw receipt binding registration_manifest_sha256 before game 9",
            ),
            PromotionCheck(
                "frozen_prediction_recomputation",
                False,
                "no protocol-bound predictor artifact and deterministic setup-evidence computation is implemented",
            ),
            PromotionCheck(
                "intervention_already_exists",
                False,
                "no externally verified prior Kaggle submission identity; intervention can only re-promote an existing archive",
            ),
        ]
    )

    registration_path: Path | None = None
    registration_sha256: str | None = None
    registration_artifact: dict[str, Any] | None = None
    try:
        registration_path = _resolve_reference(
            identification_path,
            identification.get("registration_manifest_path"),
            label="registration_manifest_path",
        )
        registration_artifact, error = _load_json(registration_path, expected_schema=REGISTRATION_SCHEMA)
        if registration_artifact is None:
            raise ValueError(str(error))
        registration_sha256 = sha256_file(registration_path)
        if identification.get("registration_manifest_sha256") != registration_sha256:
            raise ValueError("registration manifest hash mismatch")
        checks.append(PromotionCheck("registration_manifest_hash", True, registration_sha256))
    except (OSError, TypeError, ValueError) as exc:
        checks.append(PromotionCheck("registration_manifest_hash", False, str(exc)))
    registration_check, registration = _registration_check(
        registration_artifact,
        protocol_sha256=protocol_sha256,
        evaluator_sha256=evaluator_sha256,
        archive_sha256=archive_sha256,
    )
    checks.append(registration_check)

    chronology_path: Path | None = None
    chronology_sha256: str | None = None
    chronology_artifact: dict[str, Any] | None = None
    try:
        chronology_path = _resolve_reference(
            identification_path,
            identification.get("chronology_manifest_path"),
            label="chronology_manifest_path",
        )
        chronology_artifact, error = _load_json(chronology_path, expected_schema=CHRONOLOGY_SCHEMA)
        if chronology_artifact is None:
            raise ValueError(str(error))
        chronology_sha256 = sha256_file(chronology_path)
        if identification.get("chronology_manifest_sha256") != chronology_sha256:
            raise ValueError("chronology manifest hash mismatch")
        checks.append(PromotionCheck("chronology_manifest_hash", True, chronology_sha256))
    except (OSError, TypeError, ValueError) as exc:
        checks.append(PromotionCheck("chronology_manifest_hash", False, str(exc)))
    chronology_check, chronology = _chronology_check(
        chronology_artifact,
        protocol_sha256=protocol_sha256,
        evaluator_sha256=evaluator_sha256,
        archive_sha256=archive_sha256,
        registration_sha256=registration_sha256,
        registration=registration,
        frozen_at=protocol["frozen_at"] if protocol else None,
    )
    checks.append(chronology_check)
    checks.append(
        _raw_chronology_check(
            chronology_path,
            chronology,
            frozen_at=protocol["frozen_at"] if protocol else None,
        )
    )

    log_path: Path | None = None
    try:
        log_path = _resolve_reference(
            identification_path,
            identification.get("prospective_evidence_log_path"),
            label="prospective_evidence_log_path",
        )
        log_hash = sha256_file(log_path)
        if identification.get("prospective_evidence_log_sha256") != log_hash:
            raise ValueError("prospective evidence log hash mismatch")
        if identification.get("expected_event_count") != 2:
            raise ValueError("expected_event_count must be exactly 2")
        log_id = identification.get("log_id")
        summary = verify_event_log(
            log_path,
            log_id=log_id if isinstance(log_id, str) else "",
            expected_head_sha256=identification.get("expected_head_event_sha256"),
            expected_event_count=2,
        )
        checks.append(PromotionCheck("prospective_evidence_log", True, f"events=2 head={summary['head_event_sha256']}"))
    except (OSError, TypeError, ValueError) as exc:
        checks.append(PromotionCheck("prospective_evidence_log", False, str(exc)))
    checks.append(
        _event_check(
            log_path,
            registration=registration,
            registration_sha256=registration_sha256,
            chronology=chronology,
            chronology_sha256=chronology_sha256,
        )
    )

    # No candidate-identification route is implemented in schema v3. Keep the
    # authorization bit literal so a future refactor cannot accidentally open
    # this gate merely by changing one of the diagnostic checks above. A real
    # route must be introduced as a separately reviewed schema/version.
    submit_open = False
    return {
        "schema": "outcome_transfer_promotion_verdict_v3",
        "archive": str(archive_path),
        "archive_sha256": archive_sha256,
        "protocol_sha256": protocol_sha256,
        "candidate_label": label,
        "identification_metrics": None,
        "identification_route_status": "PERMANENTLY_CLOSED",
        "intervention_already_exists": False,
        "externally_verified_submission_id": None,
        "checks": [asdict(check) for check in checks],
        "submit_open": submit_open,
        "decision": "CLOSED",
    }


__all__ = [
    "CLOSURE_EVENT",
    "PromotionCheck",
    "REGISTRATION_EVENT",
    "compose_promotion_verdict",
]
