"""Fail-closed custody for a v5.1 hosted submission census.

The host API is treated as an untrusted byte source.  A census is complete only
when every page can be reopened, every cursor transition is present, the raw
terminal page says ``next_cursor: null``, and the page sequence is contiguous.
The resulting evidence is descriptive custody evidence, never submission or
holdout authority.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_sha256
from .envelope import signing_payload


UPLOAD_RESPONSE_SCHEMA = "evaluation_v5_1_signed_raw_upload_response_v1"
PAGE_RESPONSE_SCHEMA = "evaluation_v5_1_raw_census_page_response_v1"
IDENTITY_SCHEMA = "evaluation_v5_1_host_submission_identity_v1"
QUERY_SCHEMA = "evaluation_v5_1_host_census_query_v1"
CENSUS_SCHEMA = "evaluation_v5_1_exhaustive_host_census_v1"
CLOSURE_SCHEMA = "evaluation_v5_1_host_census_closure_v1"
MATURITY_HOURS = 1
FIRST48 = 48
CLOSE_OFFSETS_SECONDS = (0, 21600, 86400)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GENESIS_WATERMARK = 0

_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "competition",
        "submission_id",
        "account_id",
        "team_id",
        "archive_sha256",
        "package_sha256",
        "archive_name",
        "created_at_utc",
    }
)
_RAW_UPLOAD_FIELDS = _IDENTITY_FIELDS | {"status"}
_UPLOAD_FIELDS = frozenset(
    {
        "schema",
        "raw_response_path",
        "raw_response_sha256",
        "identity",
        "first_observed_complete_at_utc",
        "completion_poll_path",
        "completion_poll_sha256",
        "completion_poll_source",
        "signature_authority",
        "signer_key_fingerprint_sha256",
        "signature_ed25519_base64",
    }
)
_RAW_COMPLETION_FIELDS = frozenset(
    {
        "schema",
        "submission_id",
        "archive_sha256",
        "status",
        "observed_at_utc",
        "source",
    }
)
_QUERY_FIELDS = frozenset(
    {
        "schema",
        "competition",
        "submission_id",
        "account_id",
        "team_id",
        "archive_sha256",
        "created_at_utc",
        "endpoint",
        "page_size",
        "started_at_utc",
    }
)
_EPISODE_FIELDS = frozenset(
    {
        "sequence",
        "game_id",
        "submission_id",
        "archive_sha256",
        "created_at_utc",
        "server_started_at_utc",
        "completed_at_utc",
        "status",
        "validation_status",
        "runtime_status",
        "failure",
        "outcome",
        "seat",
        "opponent_rating",
        "replay_content_sha256",
        "window_exclusion_code",
    }
)
_RAW_PAGE_FIELDS = frozenset(
    {"schema", "request_cursor", "next_cursor", "sequence_watermark", "episodes"}
)
_PAGE_FIELDS = frozenset(
    {
        "page_index",
        "request_cursor",
        "response_next_cursor",
        "fetched_at_utc",
        "raw_response_path",
        "raw_response_sha256",
        "sequence_watermark_before",
        "sequence_watermark_after",
    }
)
_CENSUS_FIELDS = frozenset(
    {
        "schema",
        "close_offset_seconds",
        "census_observed_at_utc",
        "traversal_id",
        "submission_identity",
        "query_identity",
        "pages",
        "episodes",
        "sequence_watermarks",
        "terminal_next_cursor",
        "exhaustive",
        "closure",
        "observer_signer_key_fingerprint_sha256",
        "observer_signature_authority",
        "observer_signature_ed25519_base64",
    }
)
_HORIZON_FIELDS = frozenset(
    {
        "schema",
        "maturity_hours",
        "horizon_games",
        "selection_rule",
        "failure_outcome",
    }
)
_CLOSURE_FIELDS = frozenset(
    {
        "schema",
        "submission_identity",
        "census_sha256",
        "maturity_cutoff_utc",
        "as_of_utc",
        "first48",
        "authority",
        "submission_authorized",
        "holdout_access_authorized",
    }
)
_COLLECTOR_FIELDS = frozenset(
    {
        "schema",
        "collector_id",
        "anchor_census_observed_at_utc",
        "signed_upload_response",
        "snapshots",
    }
)
_SNAPSHOT_FIELDS = frozenset({"close_offset_seconds", "census"})
COLLECTOR_TIMELINE_SCHEMA = "evaluation_v5_1_collector_census_timeline_v1"
RECONCILED_FIRST48_SCHEMA = "evaluation_v5_1_reconciled_first48_v1"


class HostCensusError(ValueError):
    """Malformed, incomplete, or semantically unbound hosted evidence."""


CustodyError = HostCensusError


class _DuplicateJSONKey(ValueError):
    pass


def _exact(value: object, fields: frozenset[str], *, label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise HostCensusError(f"{label} fields must exactly be {sorted(fields)}")
    return value


def _sha(value: object, *, label: str, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise HostCensusError(f"{label} must be lowercase SHA-256 hex")
    return value


def _text(value: object, *, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value or "\x00" in value:
        raise HostCensusError(f"{label} must be a non-empty trimmed string")
    return value


def _utc(value: object, *, label: str, canonical: bool = True) -> tuple[datetime, str]:
    if type(value) is not str or not value:
        raise HostCensusError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostCensusError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HostCensusError(f"{label} must include a UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical and value != normalized:
        raise HostCensusError(f"{label} must be canonical UTC")
    return parsed, normalized


def _cursor(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label=label)


def _int(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise HostCensusError(f"{label} must be an integer >= {minimum}")
    return value


def _number(value: object, *, label: str, allow_none: bool = False) -> float | int | None:
    if allow_none and value is None:
        return None
    if type(value) not in {int, float} or type(value) is bool or not math.isfinite(float(value)):
        raise HostCensusError(f"{label} must be a finite number")
    if value < 0:
        raise HostCensusError(f"{label} must be non-negative")
    return value


def _b64(value: object) -> bytes:
    if type(value) is not str:
        raise HostCensusError("signature_ed25519_base64 must be a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise HostCensusError("signature_ed25519_base64 is not canonical base64") from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise HostCensusError("signature_ed25519_base64 must encode exactly 64 bytes")
    return decoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _parse_json_bytes(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKey) as exc:
        raise HostCensusError(f"{label} is not unique-key UTF-8 JSON") from exc
    if type(parsed) is not dict:
        raise HostCensusError(f"{label} must be a JSON object")
    return parsed


def _open_raw(root: str | Path, relative_path: str) -> bytes:
    if type(relative_path) is not str or not relative_path or "\x00" in relative_path:
        raise HostCensusError("raw response path must be a relative path")
    if "\\" in relative_path:
        raise HostCensusError("raw response path must use POSIX separators")
    parts = relative_path.split("/")
    if any(part in {"", ".", ".."} for part in parts) or relative_path.startswith("/"):
        raise HostCensusError("raw response path escapes its evidence root")
    root_path = Path(root)
    try:
        root_stat = root_path.lstat()
        if not root_path.is_dir() or root_path.is_symlink():
            raise HostCensusError("evidence root must be a real directory")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(root_path, flags)
    except (OSError, FileNotFoundError) as exc:
        raise HostCensusError("evidence root cannot be opened securely") from exc
    del root_stat
    current_fd = root_fd
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        fd = os.open(
            parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd
        )
        try:
            stat = os.fstat(fd)
            if not stat or not stat.st_mode & 0o170000 == 0o100000:
                raise HostCensusError("raw response path is not a regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)
    except (OSError, HostCensusError) as exc:
        if isinstance(exc, HostCensusError):
            raise
        raise HostCensusError("raw response cannot be opened without following links") from exc
    finally:
        os.close(current_fd)


def read_raw_json(
    root: str | Path, relative_path: str, *, expected_sha256: str | None = None
) -> tuple[dict[str, Any], bytes]:
    """Read one raw response with hash, traversal, symlink, and duplicate-key checks."""

    payload = _open_raw(root, relative_path)
    actual = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and actual != _sha(expected_sha256, label="expected_sha256"):
        raise HostCensusError(f"raw response hash mismatch for {relative_path!r}")
    return _parse_json_bytes(payload, label=relative_path), payload


def build_submission_identity(
    *,
    competition: str,
    submission_id: str,
    account_id: str,
    team_id: str,
    archive_sha256: str,
    package_sha256: str,
    archive_name: str,
    created_at_utc: str,
) -> dict[str, Any]:
    return validate_submission_identity(
        {
            "schema": IDENTITY_SCHEMA,
            "competition": competition,
            "submission_id": submission_id,
            "account_id": account_id,
            "team_id": team_id,
            "archive_sha256": archive_sha256,
            "package_sha256": package_sha256,
            "archive_name": archive_name,
            "created_at_utc": created_at_utc,
        }
    )


def validate_submission_identity(value: object) -> dict[str, Any]:
    raw = _exact(value, _IDENTITY_FIELDS, label="submission identity")
    if raw["schema"] != IDENTITY_SCHEMA:
        raise HostCensusError(f"submission identity schema must be {IDENTITY_SCHEMA!r}")
    for field in ("competition", "submission_id", "account_id", "team_id", "archive_name"):
        _text(raw[field], label=field)
    _sha(raw["archive_sha256"], label="archive_sha256")
    _sha(raw["package_sha256"], label="package_sha256")
    _, timestamp = _utc(raw["created_at_utc"], label="created_at_utc")
    result = dict(raw)
    result["created_at_utc"] = timestamp
    return result


def parse_raw_upload_response(raw: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Parse the exact semantic upload response and return identity plus status."""

    value = _exact(raw, _RAW_UPLOAD_FIELDS, label="raw upload response")
    identity = validate_submission_identity({key: value[key] for key in _IDENTITY_FIELDS})
    status = value["status"]
    if type(status) is not str or status not in {"PENDING", "COMPLETE", "FAILED"}:
        raise HostCensusError("raw upload response status is invalid")
    return identity, status


def parse_raw_completion_poll(raw: Mapping[str, Any]) -> dict[str, Any]:
    value = _exact(raw, _RAW_COMPLETION_FIELDS, label="raw completion poll")
    if value["schema"] != "evaluation_v5_1_completion_poll_v1":
        raise HostCensusError("completion poll schema is invalid")
    _text(value["submission_id"], label="completion submission_id")
    _sha(value["archive_sha256"], label="completion archive_sha256")
    if value["status"] != "COMPLETE":
        raise HostCensusError("completion poll is not a COMPLETE observation")
    _, observed = _utc(value["observed_at_utc"], label="observed_at_utc")
    source = _text(value["source"], label="completion poll source")
    return {
        "schema": value["schema"],
        "submission_id": value["submission_id"],
        "archive_sha256": value["archive_sha256"],
        "status": "COMPLETE",
        "observed_at_utc": observed,
        "source": source,
    }


def _upload_signed_digest(value: Mapping[str, Any]) -> str:
    signed = {key: value[key] for key in _UPLOAD_FIELDS if key != "signature_ed25519_base64"}
    return canonical_sha256(signed)


def build_signed_raw_upload_response(
    *,
    identity: Mapping[str, Any],
    raw_response_path: str,
    raw_response_sha256: str,
    first_observed_complete_at_utc: str,
    completion_poll_path: str,
    completion_poll_sha256: str,
    completion_poll_source: str,
    signer_public_key_bytes: bytes,
    signature: bytes | None = None,
    signer_private_key_bytes: bytes | None = None,
    signature_authority: str = "independent_observer",
) -> dict[str, Any]:
    checked = validate_submission_identity(identity)
    if type(signer_public_key_bytes) is not bytes or len(signer_public_key_bytes) != 32:
        raise HostCensusError("signer public key must be exactly 32 bytes")
    if signature is not None and (type(signature) is not bytes or len(signature) != 64):
        raise HostCensusError("signature must be exactly 64 bytes")
    record = {
        "schema": UPLOAD_RESPONSE_SCHEMA,
        "raw_response_path": _text(raw_response_path, label="raw_response_path"),
        "raw_response_sha256": _sha(raw_response_sha256, label="raw_response_sha256"),
        "identity": checked,
        "first_observed_complete_at_utc": _utc(
            first_observed_complete_at_utc, label="first_observed_complete_at_utc"
        )[1],
        "completion_poll_path": _text(completion_poll_path, label="completion_poll_path"),
        "completion_poll_sha256": _sha(completion_poll_sha256, label="completion_poll_sha256"),
        "completion_poll_source": _text(completion_poll_source, label="completion_poll_source"),
        "signature_authority": signature_authority,
        "signer_key_fingerprint_sha256": hashlib.sha256(signer_public_key_bytes).hexdigest(),
        "signature_ed25519_base64": base64.b64encode(signature or b"\0" * 64).decode("ascii"),
    }
    if signature is None:
        if type(signer_private_key_bytes) is not bytes or len(signer_private_key_bytes) != 32:
            raise HostCensusError("signer_private_key_bytes must be exactly 32 bytes when signature is absent")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        record["signature_ed25519_base64"] = base64.b64encode(
            Ed25519PrivateKey.from_private_bytes(signer_private_key_bytes).sign(
                signing_payload(UPLOAD_RESPONSE_SCHEMA, _upload_signed_digest(record))
            )
        ).decode("ascii")
    validate_signed_raw_upload_response(record, pinned_public_key_bytes=signer_public_key_bytes)
    return record


def upload_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the exact bytes covered by the upload/completion signature."""

    raw = _exact(value, _UPLOAD_FIELDS, label="signed upload response")
    return signing_payload(UPLOAD_RESPONSE_SCHEMA, _upload_signed_digest(raw))


def validate_signed_raw_upload_response(
    value: object, *, pinned_public_key_bytes: bytes | None = None
) -> dict[str, Any]:
    raw = _exact(value, _UPLOAD_FIELDS, label="signed upload response")
    if raw["schema"] != UPLOAD_RESPONSE_SCHEMA:
        raise HostCensusError(f"upload response schema must be {UPLOAD_RESPONSE_SCHEMA!r}")
    _text(raw["raw_response_path"], label="raw_response_path")
    _sha(raw["raw_response_sha256"], label="raw_response_sha256")
    identity = validate_submission_identity(raw["identity"])
    _, first_observed = _utc(
        raw["first_observed_complete_at_utc"], label="first_observed_complete_at_utc"
    )
    _text(raw["completion_poll_path"], label="completion_poll_path")
    _sha(raw["completion_poll_sha256"], label="completion_poll_sha256")
    _text(raw["completion_poll_source"], label="completion_poll_source")
    authority = raw["signature_authority"]
    if type(authority) is not str or authority not in {"independent_observer", "kaggle"}:
        raise HostCensusError("signature_authority is invalid")
    _sha(raw["signer_key_fingerprint_sha256"], label="signer_key_fingerprint_sha256")
    signature = _b64(raw["signature_ed25519_base64"])
    if pinned_public_key_bytes is not None:
        if type(pinned_public_key_bytes) is not bytes or len(pinned_public_key_bytes) != 32:
            raise HostCensusError("pinned public key must be exactly 32 bytes")
        if hashlib.sha256(pinned_public_key_bytes).hexdigest() != raw["signer_key_fingerprint_sha256"]:
            raise HostCensusError("upload signer key does not match the pinned key")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key_bytes).verify(
                signature,
                signing_payload(UPLOAD_RESPONSE_SCHEMA, _upload_signed_digest(raw)),
            )
        except (InvalidSignature, ValueError) as exc:
            raise HostCensusError("upload response signature verification failed") from exc
    result = dict(raw)
    result["identity"] = identity
    result["first_observed_complete_at_utc"] = first_observed
    return result


def build_query_identity(
    *,
    identity: Mapping[str, Any],
    endpoint: str,
    page_size: int,
    started_at_utc: str,
) -> dict[str, Any]:
    checked = validate_submission_identity(identity)
    record = {
        "schema": QUERY_SCHEMA,
        "competition": checked["competition"],
        "submission_id": checked["submission_id"],
        "account_id": checked["account_id"],
        "team_id": checked["team_id"],
        "archive_sha256": checked["archive_sha256"],
        "created_at_utc": checked["created_at_utc"],
        "endpoint": endpoint,
        "page_size": page_size,
        "started_at_utc": started_at_utc,
    }
    return validate_query_identity(record)


def validate_query_identity(value: object) -> dict[str, Any]:
    raw = _exact(value, _QUERY_FIELDS, label="query identity")
    if raw["schema"] != QUERY_SCHEMA:
        raise HostCensusError(f"query identity schema must be {QUERY_SCHEMA!r}")
    for field in ("competition", "submission_id", "account_id", "team_id", "endpoint"):
        _text(raw[field], label=field)
    _sha(raw["archive_sha256"], label="archive_sha256")
    _, created = _utc(raw["created_at_utc"], label="created_at_utc")
    _int(raw["page_size"], label="page_size", minimum=1)
    started_dt, started = _utc(raw["started_at_utc"], label="started_at_utc")
    if started_dt < _utc(raw["created_at_utc"], label="created_at_utc")[0]:
        raise HostCensusError("census query started before submission creation")
    result = dict(raw)
    result["created_at_utc"] = created
    result["started_at_utc"] = started
    return result


def validate_episode(value: object) -> dict[str, Any]:
    raw = _exact(value, _EPISODE_FIELDS, label="episode")
    sequence = _int(raw["sequence"], label="episode sequence", minimum=1)
    game_id = _text(raw["game_id"], label="game_id")
    submission_id = _text(raw["submission_id"], label="episode submission_id")
    _sha(raw["archive_sha256"], label="episode archive_sha256")
    created_dt, created = _utc(raw["created_at_utc"], label="episode created_at_utc")
    server_started_dt, server_started = _utc(
        raw["server_started_at_utc"], label="server_started_at_utc"
    )
    if server_started_dt < created_dt:
        raise HostCensusError("server_started_at_utc precedes created_at_utc")
    completed_raw = raw["completed_at_utc"]
    completed: str | None = None
    completed_dt: datetime | None = None
    if completed_raw is not None:
        completed_dt, completed = _utc(completed_raw, label="episode completed_at_utc")
        if completed_dt < created_dt:
            raise HostCensusError("episode completed_at_utc precedes created_at_utc")
    status = raw["status"]
    if type(status) is not str or status not in {
        "COMPLETE",
        "VALIDATION_FAILED",
        "RUNTIME_FAILED",
        "FAILED",
        "PENDING",
    }:
        raise HostCensusError("episode status is invalid")
    if type(raw["validation_status"]) is not str or raw["validation_status"] not in {
        "PASS",
        "FAIL",
        "UNKNOWN",
    }:
        raise HostCensusError("episode validation_status is invalid")
    if type(raw["runtime_status"]) is not str or raw["runtime_status"] not in {
        "PASS",
        "FAIL",
        "UNKNOWN",
    }:
        raise HostCensusError("episode runtime_status is invalid")
    failure = raw["failure"]
    if failure is not None:
        _text(failure, label="episode failure")
    outcome = raw["outcome"]
    if type(outcome) is not str and outcome is not None:
        raise HostCensusError("episode outcome is invalid")
    if outcome not in {
        "win",
        "loss",
        "draw",
        "validation_failure",
        "runtime_failure",
        "failure",
        None,
    }:
        raise HostCensusError("episode outcome is invalid")
    seat = raw["seat"]
    if seat is not None and (type(seat) is not int or seat not in {0, 1}):
        raise HostCensusError("episode seat must be 0, 1, or null")
    rating = _number(raw["opponent_rating"], label="opponent_rating", allow_none=True)
    replay_hash = _sha(raw["replay_content_sha256"], label="replay_content_sha256", allow_none=True)
    exclusion = raw["window_exclusion_code"]
    if exclusion is not None and exclusion != "before_maturity_window":
        raise HostCensusError("window_exclusion_code is invalid")
    if status == "COMPLETE":
        if (completed_dt is None or raw["validation_status"] != "PASS" or raw["runtime_status"] != "PASS" or failure is not None):
            raise HostCensusError("COMPLETE episode has invalid validation/runtime/failure fields")
        if outcome not in {"win", "loss", "draw"} or seat is None or rating is None or replay_hash is None:
            raise HostCensusError("COMPLETE episode is missing outcome, seat, rating, or replay hash")
    elif status == "VALIDATION_FAILED":
        if completed_dt is None or raw["validation_status"] != "FAIL" or failure is None or outcome != "validation_failure":
            raise HostCensusError("VALIDATION_FAILED episode is not semantically bound")
    elif status == "RUNTIME_FAILED":
        if completed_dt is None or raw["runtime_status"] != "FAIL" or failure is None or outcome != "runtime_failure":
            raise HostCensusError("RUNTIME_FAILED episode is not semantically bound")
    elif status == "FAILED":
        if completed_dt is None or failure is None or outcome != "failure":
            raise HostCensusError("FAILED episode is not semantically bound")
    elif any(raw[field] is not None for field in ("completed_at_utc", "outcome", "replay_content_sha256")):
        raise HostCensusError("PENDING episode contains terminal fields")
    result = dict(raw)
    result.update(
        {
            "sequence": sequence,
            "created_at_utc": created,
            "server_started_at_utc": server_started,
            "completed_at_utc": completed,
            "opponent_rating": rating,
            "replay_content_sha256": replay_hash,
            "window_exclusion_code": exclusion,
        }
    )
    return result


def parse_raw_census_page(raw: Mapping[str, Any]) -> dict[str, Any]:
    value = _exact(raw, _RAW_PAGE_FIELDS, label="raw census page")
    if value["schema"] != PAGE_RESPONSE_SCHEMA:
        raise HostCensusError(f"raw page schema must be {PAGE_RESPONSE_SCHEMA!r}")
    request_cursor = _cursor(value["request_cursor"], label="request_cursor")
    next_cursor = _cursor(value["next_cursor"], label="next_cursor")
    watermark = _int(value["sequence_watermark"], label="sequence_watermark")
    if type(value["episodes"]) is not list:
        raise HostCensusError("raw census page episodes must be a list")
    episodes = [validate_episode(item) for item in value["episodes"]]
    return {
        "schema": PAGE_RESPONSE_SCHEMA,
        "request_cursor": request_cursor,
        "next_cursor": next_cursor,
        "sequence_watermark": watermark,
        "episodes": episodes,
    }


def build_episode(**fields: Any) -> dict[str, Any]:
    return validate_episode(fields)


def build_raw_census_page(
    *, request_cursor: str | None, next_cursor: str | None, sequence_watermark: int, episodes: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    return parse_raw_census_page(
        {
            "schema": PAGE_RESPONSE_SCHEMA,
            "request_cursor": request_cursor,
            "next_cursor": next_cursor,
            "sequence_watermark": sequence_watermark,
            "episodes": list(episodes),
        }
    )


def default_horizon_closure() -> dict[str, Any]:
    return {
        "schema": CLOSURE_SCHEMA,
        "maturity_hours": MATURITY_HOURS,
        "horizon_games": FIRST48,
        "selection_rule": "server_started_at_utc>=maturity_cutoff_utc;order=(server_started_at_utc,game_id)",
        "failure_outcome": "loss",
    }


def validate_horizon_closure(value: object) -> dict[str, Any]:
    raw = _exact(value, _HORIZON_FIELDS, label="horizon closure")
    if raw["schema"] != CLOSURE_SCHEMA:
        raise HostCensusError("horizon closure schema is invalid")
    if raw["maturity_hours"] != MATURITY_HOURS or raw["horizon_games"] != FIRST48:
        raise HostCensusError("horizon closure constants are not the preregistered v5.1 rule")
    if raw["selection_rule"] != "server_started_at_utc>=maturity_cutoff_utc;order=(server_started_at_utc,game_id)":
        raise HostCensusError("horizon closure selection rule is not exact")
    if raw["failure_outcome"] != "loss":
        raise HostCensusError("horizon closure must map terminal failures to loss")
    return dict(raw)


def _census_signed_digest(value: Mapping[str, Any]) -> str:
    signed = {
        "schema": value["schema"],
        "close_offset_seconds": value["close_offset_seconds"],
        "census_observed_at_utc": value["census_observed_at_utc"],
        "traversal_id": value["traversal_id"],
        "submission_identity": value["submission_identity"],
        "query_identity": value["query_identity"],
        "pages": value["pages"],
        "sequence_watermarks": value["sequence_watermarks"],
        "terminal_next_cursor": value["terminal_next_cursor"],
        "exhaustive": value["exhaustive"],
        "closure": value["closure"],
        "observer_signer_key_fingerprint_sha256": value[
            "observer_signer_key_fingerprint_sha256"
        ],
        "observer_signature_authority": value["observer_signature_authority"],
    }
    return canonical_sha256(signed)


def census_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the exact bytes signed by the observer/host for the census."""

    raw = _exact(value, _CENSUS_FIELDS, label="census bundle")
    return signing_payload(CENSUS_SCHEMA, _census_signed_digest(raw))


def validate_census_bundle(value: object) -> dict[str, Any]:
    raw = _exact(value, _CENSUS_FIELDS, label="census bundle")
    if raw["schema"] != CENSUS_SCHEMA:
        raise HostCensusError(f"census schema must be {CENSUS_SCHEMA!r}")
    if type(raw["close_offset_seconds"]) is not int or raw["close_offset_seconds"] not in CLOSE_OFFSETS_SECONDS:
        raise HostCensusError("census close_offset_seconds is not preregistered")
    observed_dt, observed = _utc(
        raw["census_observed_at_utc"], label="census_observed_at_utc"
    )
    traversal_id = _text(raw["traversal_id"], label="traversal_id")
    identity = validate_submission_identity(raw["submission_identity"])
    query = validate_query_identity(raw["query_identity"])
    closure = validate_horizon_closure(raw["closure"])
    query_started_dt = _utc(query["started_at_utc"], label="started_at_utc")[0]
    if query_started_dt > observed_dt:
        raise HostCensusError("census observation precedes query start")
    if type(raw["pages"]) is not list or not raw["pages"]:
        raise HostCensusError("census bundle must contain ordered pages")
    pages: list[dict[str, Any]] = []
    for index, page in enumerate(raw["pages"]):
        checked = _exact(page, _PAGE_FIELDS, label=f"census page {index}")
        if type(checked["page_index"]) is not int or checked["page_index"] != index:
            raise HostCensusError("census page indexes must be contiguous from zero")
        _cursor(checked["request_cursor"], label="page request_cursor")
        _cursor(checked["response_next_cursor"], label="page response_next_cursor")
        fetched_dt, fetched = _utc(
            checked["fetched_at_utc"], label="page fetched_at_utc"
        )
        if fetched_dt < query_started_dt:
            raise HostCensusError("page fetch precedes query start")
        if fetched_dt > observed_dt:
            raise HostCensusError("page fetch occurs after census observation")
        _text(checked["raw_response_path"], label="raw_response_path")
        _sha(checked["raw_response_sha256"], label="raw_response_sha256")
        _int(checked["sequence_watermark_before"], label="sequence_watermark_before")
        _int(checked["sequence_watermark_after"], label="sequence_watermark_after")
        pages.append(dict(checked))
    if type(raw["episodes"]) is not list:
        raise HostCensusError("census bundle episodes must be a list")
    episodes = [validate_episode(item) for item in raw["episodes"]]
    if type(raw["sequence_watermarks"]) is not list or any(
        type(item) is not int or item < 0 for item in raw["sequence_watermarks"]
    ):
        raise HostCensusError("sequence_watermarks must be non-negative integers")
    if len(raw["sequence_watermarks"]) != len(pages):
        raise HostCensusError("sequence_watermarks must cover every page")
    terminal = _cursor(raw["terminal_next_cursor"], label="terminal_next_cursor")
    if type(raw["exhaustive"]) is not bool:
        raise HostCensusError("exhaustive must be a boolean")
    if raw["exhaustive"] and terminal is not None:
        raise HostCensusError("exhaustive census must declare terminal_next_cursor null")
    _sha(
        raw["observer_signer_key_fingerprint_sha256"],
        label="observer_signer_key_fingerprint_sha256",
    )
    authority = raw["observer_signature_authority"]
    if type(authority) is not str or authority not in {"independent_observer", "kaggle"}:
        raise HostCensusError("observer_signature_authority is invalid")
    signature = _b64(raw["observer_signature_ed25519_base64"])
    return_value = {
        "schema": CENSUS_SCHEMA,
        "close_offset_seconds": raw["close_offset_seconds"],
        "census_observed_at_utc": observed,
        "traversal_id": traversal_id,
        "submission_identity": identity,
        "query_identity": query,
        "pages": pages,
        "episodes": episodes,
        "sequence_watermarks": list(raw["sequence_watermarks"]),
        "terminal_next_cursor": terminal,
        "exhaustive": raw["exhaustive"],
        "closure": closure,
        "observer_signer_key_fingerprint_sha256": raw[
            "observer_signer_key_fingerprint_sha256"
        ],
        "observer_signature_authority": authority,
        "observer_signature_ed25519_base64": raw["observer_signature_ed25519_base64"],
    }
    return return_value


def verify_census_bundle_signature(
    value: Mapping[str, Any], *, pinned_public_key_bytes: bytes
) -> dict[str, Any]:
    bundle = validate_census_bundle(value)
    if type(pinned_public_key_bytes) is not bytes or len(pinned_public_key_bytes) != 32:
        raise HostCensusError("pinned observer public key must be exactly 32 bytes")
    if hashlib.sha256(pinned_public_key_bytes).hexdigest() != bundle[
        "observer_signer_key_fingerprint_sha256"
    ]:
        raise HostCensusError("census signer key does not match the pinned observer key")
    try:
        Ed25519PublicKey.from_public_bytes(pinned_public_key_bytes).verify(
            _b64(bundle["observer_signature_ed25519_base64"]), census_signing_payload(bundle)
        )
    except (InvalidSignature, ValueError) as exc:
        raise HostCensusError("census bundle signature verification failed") from exc
    return bundle


def build_census_bundle(
    *,
    identity: Mapping[str, Any],
    query_identity: Mapping[str, Any],
    pages: Iterable[Mapping[str, Any]],
    episodes: Iterable[Mapping[str, Any]],
    sequence_watermarks: Iterable[int],
    observer_public_key_bytes: bytes,
    observer_signature: bytes | None = None,
    observer_private_key_bytes: bytes | None = None,
    observer_signature_authority: str = "independent_observer",
    close_offset_seconds: int = 0,
    census_observed_at_utc: str,
    traversal_id: str,
    exhaustive: bool = True,
    terminal_next_cursor: str | None = None,
    closure: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if type(observer_public_key_bytes) is not bytes or len(observer_public_key_bytes) != 32:
        raise HostCensusError("observer public key must be exactly 32 bytes")
    bundle: dict[str, Any] = {
        "schema": CENSUS_SCHEMA,
        "close_offset_seconds": close_offset_seconds,
        "census_observed_at_utc": census_observed_at_utc,
        "traversal_id": traversal_id,
        "submission_identity": dict(identity),
        "query_identity": dict(query_identity),
        "pages": list(pages),
        "episodes": list(episodes),
        "sequence_watermarks": list(sequence_watermarks),
        "terminal_next_cursor": terminal_next_cursor,
        "exhaustive": exhaustive,
        "closure": dict(closure or default_horizon_closure()),
        "observer_signer_key_fingerprint_sha256": hashlib.sha256(
            observer_public_key_bytes
        ).hexdigest(),
        "observer_signature_authority": observer_signature_authority,
        "observer_signature_ed25519_base64": base64.b64encode(
            observer_signature or b"\0" * 64
        ).decode("ascii"),
    }
    validate_census_bundle(bundle)
    if observer_signature is None:
        if type(observer_private_key_bytes) is not bytes or len(observer_private_key_bytes) != 32:
            raise HostCensusError("observer_private_key_bytes is required when signature is absent")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        bundle["observer_signature_ed25519_base64"] = base64.b64encode(
            Ed25519PrivateKey.from_private_bytes(observer_private_key_bytes).sign(
                census_signing_payload(bundle)
            )
        ).decode("ascii")
    return verify_census_bundle_signature(bundle, pinned_public_key_bytes=observer_public_key_bytes)


def _empty_audit(reason: str) -> dict[str, Any]:
    return {
        "evidence_complete": False,
        "reason": reason,
        "completeness_basis": "none",
        "platform_attestation": False,
        "witness_custody": False,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "episodes": [],
        "first48": None,
        "maturity_cutoff_utc": None,
    }


def _identity_matches(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return dict(left) == dict(right)


def audit_host_census(
    signed_upload_response: Mapping[str, Any],
    census_bundle: Mapping[str, Any],
    evidence_root: str | Path,
    *,
    pinned_public_key_bytes: bytes | None = None,
    upload_pinned_public_key_bytes: bytes | None = None,
    observer_pinned_public_key_bytes: bytes | None = None,
    kaggle_public_key_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Audit raw upload and all pages, returning evidence with zero authority.

    An upload signature alone is insufficient.  The completion poll and the
    ordered page/closure bundle must also verify against pinned keys.  Without
    the actual Kaggle key this is reported as witness custody, never platform
    attestation.
    """

    try:
        upload_key = upload_pinned_public_key_bytes or pinned_public_key_bytes
        observer_key = observer_pinned_public_key_bytes or pinned_public_key_bytes
        if upload_key is None or observer_key is None:
            raise HostCensusError("pinned upload and observer keys are required")
        upload = validate_signed_raw_upload_response(
            signed_upload_response, pinned_public_key_bytes=upload_key
        )
        upload_raw, _ = read_raw_json(
            evidence_root,
            upload["raw_response_path"],
            expected_sha256=upload["raw_response_sha256"],
        )
        upload_identity, _ = parse_raw_upload_response(upload_raw)
        if not _identity_matches(upload_identity, upload["identity"]):
            raise HostCensusError("raw upload response identity does not match signed identity")
        completion_raw, _ = read_raw_json(
            evidence_root,
            upload["completion_poll_path"],
            expected_sha256=upload["completion_poll_sha256"],
        )
        completion = parse_raw_completion_poll(completion_raw)
        if completion["submission_id"] != upload_identity["submission_id"]:
            raise HostCensusError("completion poll submission_id does not match upload")
        if completion["archive_sha256"] != upload_identity["archive_sha256"]:
            raise HostCensusError("completion poll archive_sha256 does not match upload")
        if completion["observed_at_utc"] != upload["first_observed_complete_at_utc"]:
            raise HostCensusError("completion poll timestamp does not match signed upload evidence")
        if completion["source"] != upload["completion_poll_source"]:
            raise HostCensusError("completion poll source does not match signed upload evidence")
        maturity_cutoff_dt, _ = _utc(
            derive_maturity_cutoff(upload), label="maturity_cutoff_utc"
        )
        bundle = verify_census_bundle_signature(
            census_bundle, pinned_public_key_bytes=observer_key
        )
        census_observed_dt, census_observed = _utc(
            bundle["census_observed_at_utc"], label="census_observed_at_utc"
        )
        if not _identity_matches(bundle["submission_identity"], upload_identity):
            raise HostCensusError("census submission identity does not match upload identity")
        query = bundle["query_identity"]
        for field in ("competition", "submission_id", "account_id", "team_id", "archive_sha256", "created_at_utc"):
            if query[field] != upload_identity[field]:
                raise HostCensusError(f"query identity {field} does not match submission identity")
        seen_paths: set[str] = set()
        seen_hashes: set[str] = set()
        seen_games: set[str] = set()
        derived: list[dict[str, Any]] = []
        expected_cursor: str | None = None
        previous_watermark = _GENESIS_WATERMARK
        page_watermarks: list[int] = []
        seen_response_cursors: set[str] = set()
        query_started_dt = _utc(query["started_at_utc"], label="started_at_utc")[0]
        previous_fetched_dt: datetime | None = None
        for index, manifest_page in enumerate(bundle["pages"]):
            if manifest_page["raw_response_path"] in seen_paths:
                raise HostCensusError("census contains duplicate raw page paths")
            if manifest_page["raw_response_sha256"] in seen_hashes:
                raise HostCensusError("census contains duplicate raw page hashes")
            seen_paths.add(manifest_page["raw_response_path"])
            seen_hashes.add(manifest_page["raw_response_sha256"])
            if manifest_page["request_cursor"] != expected_cursor:
                raise HostCensusError("census page request cursor omits a cursor transition")
            if manifest_page["sequence_watermark_before"] != previous_watermark:
                raise HostCensusError("census sequence watermark has a gap")
            fetched_dt, _ = _utc(manifest_page["fetched_at_utc"], label="page fetched_at_utc")
            if fetched_dt < query_started_dt or fetched_dt > census_observed_dt:
                raise HostCensusError("page fetch chronology is inconsistent with census observation")
            if previous_fetched_dt is not None and fetched_dt < previous_fetched_dt:
                raise HostCensusError("page fetch timestamps are not monotone")
            previous_fetched_dt = fetched_dt
            raw_page, _ = read_raw_json(
                evidence_root,
                manifest_page["raw_response_path"],
                expected_sha256=manifest_page["raw_response_sha256"],
            )
            page = parse_raw_census_page(raw_page)
            for field in ("request_cursor", "next_cursor"):
                manifest_field = "response_next_cursor" if field == "next_cursor" else field
                if page[field] != manifest_page[manifest_field]:
                    raise HostCensusError(f"raw page {field} disagrees with census manifest")
            if page["sequence_watermark"] != manifest_page["sequence_watermark_after"]:
                raise HostCensusError("raw page watermark disagrees with census manifest")
            if page["sequence_watermark"] < previous_watermark:
                raise HostCensusError("sequence watermarks are not monotone")
            if page["next_cursor"] is not None:
                if page["next_cursor"] in seen_response_cursors:
                    raise HostCensusError("census contains a repeated or cyclic continuation token")
                if page["next_cursor"] == page["request_cursor"]:
                    raise HostCensusError("census continuation token is cyclic")
                seen_response_cursors.add(page["next_cursor"])
            page_sequences = [episode["sequence"] for episode in page["episodes"]]
            if page_sequences != sorted(page_sequences):
                raise HostCensusError("episodes within a page are not in hosted sequence order")
            if page["episodes"]:
                if page["sequence_watermark"] != page_sequences[-1]:
                    raise HostCensusError("sequence watermark does not cover exactly the page")
                if page_sequences[0] != len(derived) + 1:
                    raise HostCensusError("census has a missing or repeated hosted sequence")
            elif page["next_cursor"] is not None:
                raise HostCensusError("non-terminal empty census page would hide a gap")
            for episode in page["episodes"]:
                if episode["game_id"] in seen_games:
                    raise HostCensusError("census contains duplicate game ids")
                if episode["submission_id"] != upload_identity["submission_id"]:
                    raise HostCensusError("episode submission_id does not match upload")
                if episode["archive_sha256"] != upload_identity["archive_sha256"]:
                    raise HostCensusError("episode archive_sha256 does not match upload")
                if _utc(episode["created_at_utc"], label="episode created_at_utc")[0] < _utc(upload_identity["created_at_utc"], label="created_at_utc")[0]:
                    raise HostCensusError("episode predates submission creation")
                if _utc(episode["server_started_at_utc"], label="server_started_at_utc")[0] < _utc(upload_identity["created_at_utc"], label="created_at_utc")[0]:
                    raise HostCensusError("episode server_started_at_utc predates submission creation")
                if episode["completed_at_utc"] is not None and _utc(episode["completed_at_utc"], label="completed_at_utc")[0] > census_observed_dt:
                    raise HostCensusError("episode completed_at_utc is after census observation")
                if _utc(episode["server_started_at_utc"], label="server_started_at_utc")[0] > census_observed_dt:
                    raise HostCensusError("episode server_started_at_utc is after census observation")
                before_window = _utc(episode["server_started_at_utc"], label="server_started_at_utc")[0] < maturity_cutoff_dt
                expected_exclusion = "before_maturity_window" if before_window else None
                if episode["window_exclusion_code"] != expected_exclusion:
                    raise HostCensusError("window exclusion code is not derived from completion maturity")
                seen_games.add(episode["game_id"])
                derived.append(episode)
            expected_cursor = page["next_cursor"]
            previous_watermark = page["sequence_watermark"]
            page_watermarks.append(previous_watermark)
            if expected_cursor is None and index != len(bundle["pages"]) - 1:
                raise HostCensusError("census has pages after its terminal cursor")
        if expected_cursor is not None:
            raise HostCensusError("census lacks terminal raw evidence with next_cursor null")
        if bundle["terminal_next_cursor"] is not None:
            raise HostCensusError("census terminal_next_cursor is not null")
        if bundle["sequence_watermarks"] != page_watermarks:
            raise HostCensusError("bundle sequence watermarks do not match raw pages")
        if bundle["episodes"] != derived:
            raise HostCensusError("bundle episodes are not the exact raw-page episode sequence")
        if not derived:
            raise HostCensusError("exhaustive census contains no episodes")
        hosted_order = sorted(derived, key=lambda item: (item["server_started_at_utc"], item["game_id"]))
        if hosted_order != derived:
            raise HostCensusError("raw episodes are not in hosted (server_started_at_utc, game_id) order")
        signature_verified = True
        platform_attested = (
            type(kaggle_public_key_bytes) is bytes
            and len(kaggle_public_key_bytes) == 32
            and upload["signature_authority"] == "kaggle"
            and bundle["observer_signature_authority"] == "kaggle"
            and upload_key == kaggle_public_key_bytes
            and observer_key == kaggle_public_key_bytes
        )
        return {
            "evidence_complete": True,
            "reason": None,
            "completeness_basis": "platform_attested" if platform_attested else "witness_custody",
            "witness_custody": not platform_attested,
            "platform_attestation": platform_attested,
            "authority": False,
            "submission_authorized": False,
            "holdout_access_authorized": False,
            "signature_verified": signature_verified,
            "submission_identity": upload_identity,
            "episodes": derived,
            "page_count": len(bundle["pages"]),
            "terminal_next_cursor": None,
            "first48": None,
            "maturity_cutoff_utc": derive_maturity_cutoff(upload),
            "completion_observed_at_utc": completion["observed_at_utc"],
            "census_observed_at_utc": census_observed,
        }
    except (HostCensusError, OSError, TypeError, ValueError) as exc:
        return _empty_audit(str(exc))


def derive_maturity_cutoff(evidence: Mapping[str, Any]) -> str:
    """Derive maturity only from the first observed COMPLETE poll timestamp."""

    if "first_observed_complete_at_utc" not in evidence:
        raise HostCensusError("completion evidence is required to derive maturity")
    observed, _ = _utc(
        evidence["first_observed_complete_at_utc"],
        label="first_observed_complete_at_utc",
    )
    return (observed + timedelta(hours=MATURITY_HOURS)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def close_host_census(
    signed_upload_response: Mapping[str, Any],
    census_bundle: Mapping[str, Any],
    evidence_root: str | Path,
    *,
    as_of_utc: str,
    pinned_public_key_bytes: bytes | None = None,
    upload_pinned_public_key_bytes: bytes | None = None,
    observer_pinned_public_key_bytes: bytes | None = None,
    kaggle_public_key_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Derive the mature first 48 from audited hosted data, never supplied rows."""

    audit = audit_host_census(
        signed_upload_response,
        census_bundle,
        evidence_root,
        pinned_public_key_bytes=pinned_public_key_bytes,
        upload_pinned_public_key_bytes=upload_pinned_public_key_bytes,
        observer_pinned_public_key_bytes=observer_pinned_public_key_bytes,
        kaggle_public_key_bytes=kaggle_public_key_bytes,
    )
    if not audit["evidence_complete"]:
        raise HostCensusError(audit["reason"] or "host census is incomplete")
    as_of_dt, as_of = _utc(as_of_utc, label="as_of_utc")
    observed_dt, _ = _utc(
        audit["census_observed_at_utc"], label="census_observed_at_utc"
    )
    if as_of_dt != observed_dt:
        raise HostCensusError("as_of_utc must equal the signed census_observed_at_utc")
    cutoff_text = audit["maturity_cutoff_utc"]
    cutoff_dt, _ = _utc(cutoff_text, label="maturity_cutoff_utc")
    if as_of_dt < cutoff_dt:
        raise HostCensusError("one-hour maturity cutoff has not elapsed")
    mature = [
        episode
        for episode in audit["episodes"]
        if episode["status"] != "PENDING"
        and _utc(episode["server_started_at_utc"], label="server_started_at_utc")[0] >= cutoff_dt
        and episode["completed_at_utc"] is not None
    ]
    ordered = sorted(mature, key=lambda item: (item["server_started_at_utc"], item["game_id"]))
    if len(ordered) < FIRST48:
        raise HostCensusError(f"mature hosted census contains fewer than {FIRST48} episodes")
    first48 = []
    for episode in ordered[:FIRST48]:
        selected = dict(episode)
        if selected["status"] != "COMPLETE":
            selected["outcome"] = "loss"
        first48.append(selected)
    result = {
        "schema": CLOSURE_SCHEMA,
        "submission_identity": audit["submission_identity"],
        "census_sha256": canonical_sha256(census_bundle),
        "maturity_cutoff_utc": cutoff_text,
        "as_of_utc": as_of,
        "first48": first48,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
    }
    return validate_host_census_closure(result)


def validate_host_census_closure(value: object) -> dict[str, Any]:
    raw = _exact(value, _CLOSURE_FIELDS, label="host census closure")
    if raw["schema"] != CLOSURE_SCHEMA:
        raise HostCensusError("host census closure schema is invalid")
    validate_submission_identity(raw["submission_identity"])
    _sha(raw["census_sha256"], label="census_sha256")
    _utc(raw["maturity_cutoff_utc"], label="maturity_cutoff_utc")
    _utc(raw["as_of_utc"], label="as_of_utc")
    if type(raw["first48"]) is not list or len(raw["first48"]) != FIRST48:
        raise HostCensusError("host census closure must contain exactly first48 records")
    for row in raw["first48"]:
        if type(row) is not dict or set(row) != _EPISODE_FIELDS:
            raise HostCensusError("host census closure first48 rows have inexact fields")
        semantic_outcome = {
            "VALIDATION_FAILED": "validation_failure",
            "RUNTIME_FAILED": "runtime_failure",
            "FAILED": "failure",
        }.get(row["status"], row["outcome"])
        validate_episode({**row, "outcome": semantic_outcome})
        if row["status"] != "COMPLETE" and row["outcome"] != "loss":
            raise HostCensusError("terminal validation/runtime/failure rows must be losses")
    if raw["authority"] is not False or raw["submission_authorized"] is not False or raw["holdout_access_authorized"] is not False:
        raise HostCensusError("host census closure cannot grant authority")
    return dict(raw)


def episode_semantic_hash(episode: Mapping[str, Any]) -> str:
    """Hash the fully validated episode semantics, including failure status."""

    return canonical_sha256(validate_episode(dict(episode)))


def build_collector_timeline(
    *,
    collector_id: str,
    signed_upload_response: Mapping[str, Any],
    censuses: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    snapshots = list(censuses)
    if len(snapshots) != len(CLOSE_OFFSETS_SECONDS):
        raise HostCensusError("collector timeline must contain close, +6h, and +24h censuses")
    checked = []
    anchor_bundle = validate_census_bundle(snapshots[0])
    anchor_dt, anchor = _utc(
        anchor_bundle["census_observed_at_utc"], label="anchor_census_observed_at_utc"
    )
    upload = validate_signed_raw_upload_response(signed_upload_response)
    completion_dt, _ = _utc(
        upload["first_observed_complete_at_utc"],
        label="first_observed_complete_at_utc",
    )
    if anchor_dt < completion_dt + timedelta(hours=MATURITY_HOURS):
        raise HostCensusError(
            "collector census-close anchor precedes the completion maturity boundary"
        )
    for expected_offset, census in zip(CLOSE_OFFSETS_SECONDS, snapshots):
        bundle = validate_census_bundle(census)
        if bundle["close_offset_seconds"] != expected_offset:
            raise HostCensusError("collector census close offset is not preregistered")
        expected_observed = anchor_dt + timedelta(seconds=expected_offset)
        if _utc(bundle["census_observed_at_utc"], label="census_observed_at_utc")[0] != expected_observed:
            raise HostCensusError("census observation is not bound to the close anchor")
        checked.append({"close_offset_seconds": expected_offset, "census": bundle})
    return {
        "schema": COLLECTOR_TIMELINE_SCHEMA,
        "collector_id": _text(collector_id, label="collector_id"),
        "anchor_census_observed_at_utc": anchor,
        "signed_upload_response": upload,
        "snapshots": checked,
    }


def validate_collector_timeline(value: object) -> dict[str, Any]:
    raw = _exact(value, _COLLECTOR_FIELDS, label="collector timeline")
    if raw["schema"] != COLLECTOR_TIMELINE_SCHEMA:
        raise HostCensusError("collector timeline schema is invalid")
    collector_id = _text(raw["collector_id"], label="collector_id")
    anchor_dt, anchor = _utc(
        raw["anchor_census_observed_at_utc"], label="anchor_census_observed_at_utc"
    )
    upload = validate_signed_raw_upload_response(raw["signed_upload_response"])
    completion_dt, _ = _utc(
        upload["first_observed_complete_at_utc"],
        label="first_observed_complete_at_utc",
    )
    if anchor_dt < completion_dt + timedelta(hours=MATURITY_HOURS):
        raise HostCensusError(
            "collector census-close anchor precedes the completion maturity boundary"
        )
    if type(raw["snapshots"]) is not list or len(raw["snapshots"]) != 3:
        raise HostCensusError("collector timeline must contain exactly three snapshots")
    snapshots = []
    for expected_offset, snapshot in zip(CLOSE_OFFSETS_SECONDS, raw["snapshots"]):
        checked = _exact(snapshot, _SNAPSHOT_FIELDS, label="collector snapshot")
        if checked["close_offset_seconds"] != expected_offset:
            raise HostCensusError("collector snapshots must be close, +6h, +24h")
        census = validate_census_bundle(checked["census"])
        if census["close_offset_seconds"] != expected_offset:
            raise HostCensusError("snapshot offset does not match census offset")
        expected_observed = anchor_dt + timedelta(seconds=expected_offset)
        if _utc(census["census_observed_at_utc"], label="census_observed_at_utc")[0] != expected_observed:
            raise HostCensusError("snapshot observation is not exactly anchor-relative")
        snapshots.append({"close_offset_seconds": expected_offset, "census": census})
    return {
        "schema": COLLECTOR_TIMELINE_SCHEMA,
        "collector_id": collector_id,
        "anchor_census_observed_at_utc": anchor,
        "signed_upload_response": upload,
        "snapshots": snapshots,
    }


def _timeline_fingerprint(audit: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    episodes = audit["episodes"]
    return (
        [episode["game_id"] for episode in episodes],
        [episode_semantic_hash(episode) for episode in episodes],
    )


def audit_collector_timeline(
    timeline: Mapping[str, Any],
    evidence_root: str | Path,
    *,
    pinned_public_key_bytes: bytes | None = None,
    upload_pinned_public_key_bytes: bytes | None = None,
    observer_pinned_public_key_bytes: bytes | None = None,
    kaggle_public_key_bytes: bytes | None = None,
) -> dict[str, Any]:
    checked = validate_collector_timeline(timeline)
    upload = checked["signed_upload_response"]
    upload_key = upload_pinned_public_key_bytes or pinned_public_key_bytes
    observer_key = observer_pinned_public_key_bytes or pinned_public_key_bytes
    snapshot_results = []
    previous_fingerprint: tuple[list[str], list[str]] | None = None
    latest_fingerprint: tuple[list[str], list[str]] | None = None
    baseline_first48: tuple[list[str], list[str]] | None = None
    seen_traversals: set[str] = set()
    seen_page_traversals: set[tuple[Any, ...]] = set()
    for snapshot in checked["snapshots"]:
        census = snapshot["census"]
        if census["traversal_id"] in seen_traversals:
            raise HostCensusError("collector timeline reuses a census traversal")
        seen_traversals.add(census["traversal_id"])
        page_traversal = tuple(
            (
                page["raw_response_path"],
                page["raw_response_sha256"],
                page["request_cursor"],
                page["response_next_cursor"],
                page["fetched_at_utc"],
            )
            for page in census["pages"]
        )
        if page_traversal in seen_page_traversals:
            raise HostCensusError("collector timeline reuses an identical page traversal")
        seen_page_traversals.add(page_traversal)
        audit = audit_host_census(
            upload,
            census,
            evidence_root,
            upload_pinned_public_key_bytes=upload_key,
            observer_pinned_public_key_bytes=observer_key,
            kaggle_public_key_bytes=kaggle_public_key_bytes,
        )
        if not audit["evidence_complete"]:
            raise HostCensusError(audit["reason"] or "collector snapshot is incomplete")
        first = close_host_census(
            upload,
            census,
            evidence_root,
            as_of_utc=census["census_observed_at_utc"],
            upload_pinned_public_key_bytes=upload_key,
            observer_pinned_public_key_bytes=observer_key,
            kaggle_public_key_bytes=kaggle_public_key_bytes,
        )
        fingerprint = _timeline_fingerprint(audit)
        first_fingerprint = (
            [episode["game_id"] for episode in first["first48"]],
            [episode_semantic_hash(episode) for episode in first["first48"]],
        )
        if previous_fingerprint is None:
            baseline_first48 = first_fingerprint
        else:
            previous_ids, previous_hashes = previous_fingerprint
            current_ids, current_hashes = fingerprint
            if (
                len(current_ids) < len(previous_ids)
                or current_ids[: len(previous_ids)] != previous_ids
                or current_hashes[: len(previous_hashes)] != previous_hashes
            ):
                raise HostCensusError(
                    "collector close censuses are not append-only semantic extensions"
                )
            if first_fingerprint != baseline_first48:
                raise HostCensusError(
                    "collector close censuses changed the frozen first48 horizon"
                )
        previous_fingerprint = fingerprint
        latest_fingerprint = fingerprint
        snapshot_results.append({"audit": audit, "closure": first})
    assert latest_fingerprint is not None and baseline_first48 is not None
    return {
        "schema": RECONCILED_FIRST48_SCHEMA,
        "evidence_complete": True,
        "anchor_census_observed_at_utc": checked["anchor_census_observed_at_utc"],
        "collector_id": checked["collector_id"],
        "snapshots": snapshot_results,
        "episode_ids": latest_fingerprint[0],
        "episode_semantic_hashes": latest_fingerprint[1],
        "first48_ids": baseline_first48[0],
        "first48_semantic_hashes": baseline_first48[1],
        "first48": snapshot_results[0]["closure"]["first48"],
        "platform_attestation": all(item["audit"]["platform_attestation"] for item in snapshot_results),
        "completeness_basis": "platform_attested"
        if all(item["audit"]["platform_attestation"] for item in snapshot_results)
        else "witness_custody",
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
    }


def reconcile_collectors(
    collector_a: Mapping[str, Any],
    evidence_root_a: str | Path,
    collector_b: Mapping[str, Any],
    evidence_root_b: str | Path,
    *,
    pinned_a_upload_key: bytes | None = None,
    pinned_a_observer_key: bytes | None = None,
    pinned_b_upload_key: bytes | None = None,
    pinned_b_observer_key: bytes | None = None,
    kaggle_public_key_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Require two independent, stable collector timelines before first48."""

    checked_a = validate_collector_timeline(collector_a)
    checked_b = validate_collector_timeline(collector_b)
    if checked_a["collector_id"] == checked_b["collector_id"]:
        raise HostCensusError("collector A and B must have independent identities")
    if checked_a["signed_upload_response"]["identity"] != checked_b["signed_upload_response"]["identity"]:
        raise HostCensusError("collector upload identities disagree")
    if checked_a["anchor_census_observed_at_utc"] != checked_b["anchor_census_observed_at_utc"]:
        raise HostCensusError("collector close anchors disagree")
    observer_fingerprints_a = {
        snapshot["census"]["observer_signer_key_fingerprint_sha256"]
        for snapshot in checked_a["snapshots"]
    }
    observer_fingerprints_b = {
        snapshot["census"]["observer_signer_key_fingerprint_sha256"]
        for snapshot in checked_b["snapshots"]
    }
    if observer_fingerprints_a & observer_fingerprints_b:
        raise HostCensusError("collector page observers are not independent")
    traversals_a = {
        snapshot["census"]["traversal_id"] for snapshot in checked_a["snapshots"]
    }
    traversals_b = {
        snapshot["census"]["traversal_id"] for snapshot in checked_b["snapshots"]
    }
    if traversals_a & traversals_b:
        raise HostCensusError("collector census traversals are not independent")
    result_a = audit_collector_timeline(
        checked_a,
        evidence_root_a,
        upload_pinned_public_key_bytes=pinned_a_upload_key,
        observer_pinned_public_key_bytes=pinned_a_observer_key,
        kaggle_public_key_bytes=kaggle_public_key_bytes,
    )
    result_b = audit_collector_timeline(
        checked_b,
        evidence_root_b,
        upload_pinned_public_key_bytes=pinned_b_upload_key,
        observer_pinned_public_key_bytes=pinned_b_observer_key,
        kaggle_public_key_bytes=kaggle_public_key_bytes,
    )
    for offset, (snapshot_a, snapshot_b) in zip(
        CLOSE_OFFSETS_SECONDS, zip(result_a["snapshots"], result_b["snapshots"])
    ):
        fingerprint_a = _timeline_fingerprint(snapshot_a["audit"])
        fingerprint_b = _timeline_fingerprint(snapshot_b["audit"])
        if fingerprint_a != fingerprint_b:
            raise HostCensusError(
                f"collector A/B disagreement at close offset {offset}"
            )
    for field in ("episode_ids", "episode_semantic_hashes", "first48_ids", "first48_semantic_hashes"):
        if result_a[field] != result_b[field]:
            raise HostCensusError(f"collector A/B disagreement in {field}")
    return {
        "schema": RECONCILED_FIRST48_SCHEMA,
        "evidence_complete": True,
        "anchor_census_observed_at_utc": checked_a["anchor_census_observed_at_utc"],
        "collector_a": result_a,
        "collector_b": result_b,
        "episode_ids": result_a["episode_ids"],
        "episode_semantic_hashes": result_a["episode_semantic_hashes"],
        "first48_ids": result_a["first48_ids"],
        "first48_semantic_hashes": result_a["first48_semantic_hashes"],
        "first48": result_a["snapshots"][0]["closure"]["first48"],
        "platform_attestation": result_a["platform_attestation"] and result_b["platform_attestation"],
        "completeness_basis": "platform_attested"
        if result_a["platform_attestation"] and result_b["platform_attestation"]
        else "witness_custody",
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
    }


close_first48 = reconcile_collectors


def compose_first48(*args: Any, **kwargs: Any) -> dict[str, Any]:
    return reconcile_collectors(*args, **kwargs)


audit_exhaustive_host_census = audit_host_census
validate_upload_response = validate_signed_raw_upload_response
validate_host_submission_identity = validate_submission_identity


__all__ = [
    "CENSUS_SCHEMA",
    "CLOSURE_SCHEMA",
    "CLOSE_OFFSETS_SECONDS",
    "COLLECTOR_TIMELINE_SCHEMA",
    "CustodyError",
    "FIRST48",
    "HostCensusError",
    "IDENTITY_SCHEMA",
    "MATURITY_HOURS",
    "PAGE_RESPONSE_SCHEMA",
    "QUERY_SCHEMA",
    "RECONCILED_FIRST48_SCHEMA",
    "UPLOAD_RESPONSE_SCHEMA",
    "audit_exhaustive_host_census",
    "audit_host_census",
    "build_census_bundle",
    "build_collector_timeline",
    "build_episode",
    "build_query_identity",
    "build_raw_census_page",
    "build_signed_raw_upload_response",
    "build_submission_identity",
    "census_signing_payload",
    "close_host_census",
    "compose_first48",
    "derive_maturity_cutoff",
    "default_horizon_closure",
    "parse_raw_census_page",
    "parse_raw_completion_poll",
    "parse_raw_upload_response",
    "audit_collector_timeline",
    "close_first48",
    "episode_semantic_hash",
    "reconcile_collectors",
    "read_raw_json",
    "validate_census_bundle",
    "validate_collector_timeline",
    "validate_episode",
    "validate_horizon_closure",
    "validate_host_census_closure",
    "validate_host_submission_identity",
    "validate_query_identity",
    "validate_signed_raw_upload_response",
    "validate_submission_identity",
    "validate_upload_response",
    "upload_signing_payload",
    "verify_census_bundle_signature",
]
