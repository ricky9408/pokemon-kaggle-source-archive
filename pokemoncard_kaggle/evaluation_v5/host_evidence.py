"""Authority-free signed evidence for the hosted observation log.

This module authenticates a reviewer's statement about bytes and observations
already present in the v5 global log.  It does not establish an authority,
open a holdout, or authorize a submission.  The caller supplies the pinned
Ed25519 key; this module only verifies that key's fingerprint and signature.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalJSONError, canonical_json_bytes, canonical_sha256
from .charter import PROTOCOL_ID
from .cohort import CohortCustodyError, validate_observation_log, validate_registry


HOST_EVIDENCE_MANIFEST_SCHEMA = "evaluation_v5_host_evidence_manifest_v1"
HOST_EVIDENCE_AUDIT_SCHEMA = "evaluation_v5_host_evidence_audit_v1"
HOSTED_CENSUS_RECEIPT_SCHEMA = "evaluation_v5_hosted_census_receipt_v1"
ED25519_PUBLIC_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
GENESIS_CHAIN_HASH = "0" * 64

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MANIFEST_FIELDS = frozenset(
    {
        "schema",
        "protocol_id",
        "reviewed_at",
        "observation_log_sha256",
        "observation_chain_head",
        "registry_sha256",
        "registry_chain_head",
        "census",
        "signer_public_key_fingerprint_sha256",
        "receipts",
        "signature_ed25519_base64",
    }
)
_CENSUS_FIELDS = frozenset(
    {
        "receipt_path",
        "receipt_sha256",
        "commitment_sha256",
        "exhaustive",
        "games",
    }
)
_CENSUS_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "registry_sha256",
        "registry_chain_head",
        "exhaustive",
        "games",
        "commitment_sha256",
    }
)
_CENSUS_GAME_FIELDS = frozenset(
    {"archive_sha256", "game_id", "source_episode_reference_id", "created_at_utc"}
)
_RECEIPT_FIELDS = frozenset(
    {
        "archive_sha256",
        "game_id",
        "hosted_created_at_utc",
        "completion_evidence_sha256",
        "source_episode_reference_id",
        "fetched_at_utc",
        "raw_response_path",
        "raw_response_sha256",
    }
)


class HostEvidenceError(ValueError):
    """A signed hosted-evidence manifest is malformed or cannot be verified."""


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise HostEvidenceError(f"{label} must be a lowercase SHA-256 hex string")
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    if type(value) is not str or _TIMESTAMP_RE.fullmatch(value) is None:
        raise HostEvidenceError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise HostEvidenceError(f"{label} must be a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise HostEvidenceError(f"{label} must be canonical UTC with six fractional digits")
    return value, parsed


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise HostEvidenceError(f"{label} must be a non-empty trimmed string")
    return value


def _repo_relative_path(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise HostEvidenceError(f"{label} must be a non-empty repo-relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise HostEvidenceError(f"{label} must be a normalized repo-relative POSIX path")
    return value


def _base64(value: object, label: str, length: int) -> bytes:
    if type(value) is not str:
        raise HostEvidenceError(f"{label} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise HostEvidenceError(f"{label} must be canonical base64") from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise HostEvidenceError(f"{label} must be canonical {length}-byte base64")
    return decoded


def _census_games(value: object, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise HostEvidenceError(f"{label} must be a list")
    checked: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping) or set(item) != _CENSUS_GAME_FIELDS:
            raise HostEvidenceError(f"{label}[{index}] fields are not exact")
        game = {
            "archive_sha256": _sha256(item["archive_sha256"], f"{label}[{index}].archive_sha256"),
            "game_id": _identifier(item["game_id"], f"{label}[{index}].game_id"),
            "source_episode_reference_id": _identifier(
                item["source_episode_reference_id"],
                f"{label}[{index}].source_episode_reference_id",
            ),
            "created_at_utc": _timestamp(
                item["created_at_utc"], f"{label}[{index}].created_at_utc"
            )[0],
        }
        key = (game["archive_sha256"], game["game_id"])
        if key in seen:
            raise HostEvidenceError(f"{label} contains duplicate games")
        seen.add(key)
        checked.append(game)
    return checked


def _census_commitment(
    registry_sha256: str,
    registry_chain_head: str,
    exhaustive: bool,
    games: list[dict[str, str]],
) -> str:
    return canonical_sha256(
        {
            "registry_sha256": registry_sha256,
            "registry_chain_head": registry_chain_head,
            "exhaustive": exhaustive,
            "games": games,
        }
    )


def _validate_census(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CENSUS_FIELDS:
        raise HostEvidenceError("hosted census fields are not exact")
    if value["exhaustive"] is not True:
        raise HostEvidenceError("hosted census must make an explicit exhaustive claim")
    games = _census_games(value["games"], "census.games")
    commitment = _sha256(value["commitment_sha256"], "census.commitment_sha256")
    return {
        "receipt_path": _repo_relative_path(value["receipt_path"], "census.receipt_path"),
        "receipt_sha256": _sha256(value["receipt_sha256"], "census.receipt_sha256"),
        "commitment_sha256": commitment,
        "exhaustive": True,
        "games": games,
    }


def _validate_receipt(value: object, reviewed_at: str, reviewed_dt: datetime) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _RECEIPT_FIELDS:
        raise HostEvidenceError("host evidence receipt fields are not exact")
    fetched_text, fetched_dt = _timestamp(value["fetched_at_utc"], "receipt.fetched_at_utc")
    receipt = {
        "archive_sha256": _sha256(value["archive_sha256"], "receipt.archive_sha256"),
        "game_id": _identifier(value["game_id"], "receipt.game_id"),
        "hosted_created_at_utc": _timestamp(
            value["hosted_created_at_utc"], "receipt.hosted_created_at_utc"
        )[0],
        "completion_evidence_sha256": _sha256(
            value["completion_evidence_sha256"], "receipt.completion_evidence_sha256"
        ),
        "source_episode_reference_id": _identifier(
            value["source_episode_reference_id"], "receipt.source_episode_reference_id"
        ),
        "fetched_at_utc": fetched_text,
        "raw_response_path": _repo_relative_path(
            value["raw_response_path"], "receipt.raw_response_path"
        ),
        "raw_response_sha256": _sha256(
            value["raw_response_sha256"], "receipt.raw_response_sha256"
        ),
    }
    if fetched_dt < _timestamp(receipt["hosted_created_at_utc"], "hosted_created_at_utc")[1]:
        raise HostEvidenceError("receipt fetched_at_utc cannot precede hosted_created_at_utc")
    # A review can only attest to a response after that response was fetched.
    if fetched_dt > reviewed_dt:
        raise HostEvidenceError("receipt fetched_at_utc cannot follow reviewed_at")
    return receipt


def _unsigned_manifest(value: object) -> tuple[dict[str, Any], bytes, bytes]:
    if not isinstance(value, Mapping) or set(value) != _MANIFEST_FIELDS:
        raise HostEvidenceError("host evidence manifest fields are not exact")
    if value["schema"] != HOST_EVIDENCE_MANIFEST_SCHEMA:
        raise HostEvidenceError(f"schema must be {HOST_EVIDENCE_MANIFEST_SCHEMA!r}")
    if value["protocol_id"] != PROTOCOL_ID:
        raise HostEvidenceError(f"protocol_id must be {PROTOCOL_ID!r}")
    reviewed_at, reviewed_dt = _timestamp(value["reviewed_at"], "reviewed_at")
    log_sha256 = _sha256(value["observation_log_sha256"], "observation_log_sha256")
    chain_head = _sha256(value["observation_chain_head"], "observation_chain_head")
    registry_sha256 = _sha256(value["registry_sha256"], "registry_sha256")
    registry_chain_head = _sha256(value["registry_chain_head"], "registry_chain_head")
    census = _validate_census(value["census"])
    fingerprint = _sha256(
        value["signer_public_key_fingerprint_sha256"],
        "signer_public_key_fingerprint_sha256",
    )
    if not isinstance(value["receipts"], list):
        raise HostEvidenceError("receipts must be a list")
    receipts = [_validate_receipt(item, reviewed_at, reviewed_dt) for item in value["receipts"]]
    if len({item["game_id"] for item in receipts}) != len(receipts):
        raise HostEvidenceError("receipts must not contain duplicate game ids")
    if len({item["raw_response_path"] for item in receipts}) != len(receipts):
        raise HostEvidenceError("receipts must not contain duplicate raw response paths")
    signature = _base64(
        value["signature_ed25519_base64"],
        "signature_ed25519_base64",
        ED25519_SIGNATURE_BYTES,
    )
    unsigned = {
        "schema": HOST_EVIDENCE_MANIFEST_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "reviewed_at": reviewed_at,
        "observation_log_sha256": log_sha256,
        "observation_chain_head": chain_head,
        "registry_sha256": registry_sha256,
        "registry_chain_head": registry_chain_head,
        "census": census,
        "signer_public_key_fingerprint_sha256": fingerprint,
        "receipts": receipts,
    }
    try:
        payload = canonical_json_bytes(unsigned)
    except CanonicalJSONError as exc:
        raise HostEvidenceError(f"host evidence manifest is not canonical JSON: {exc}") from exc
    return unsigned, payload, signature


def host_evidence_signing_payload(value: Mapping[str, Any]) -> bytes:
    """Return the canonical bytes signed by a hosted-evidence reviewer."""

    _, payload, _ = _unsigned_manifest(dict(value))
    return payload


def _open_repo_root(repo_root: str | os.PathLike[str]) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(os.fspath(repo_root), flags)
    except OSError as exc:
        raise HostEvidenceError("repository root must be an opened non-symlink directory") from exc
    if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
        os.close(root_fd)
        raise HostEvidenceError("repository root must be a directory")
    return root_fd


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_opened_file(root_fd: int, relative_path: str) -> tuple[bytes, str]:
    current_fd = os.dup(root_fd)
    try:
        parts = relative_path.split("/")
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=current_fd,
            )
            os.close(current_fd)
            current_fd = next_fd
        file_fd = os.open(
            parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current_fd
        )
        try:
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise HostEvidenceError(f"raw response file {relative_path!r} is not regular")
            digest = hashlib.sha256()
            content = bytearray()
            while True:
                block = os.read(file_fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                content.extend(block)
            after = os.fstat(file_fd)
            if not _same_file_state(before, after):
                raise HostEvidenceError(f"raw response file {relative_path!r} changed while being read")
            return bytes(content), digest.hexdigest()
        finally:
            os.close(file_fd)
    except OSError as exc:
        raise HostEvidenceError(f"unable to securely open raw response file {relative_path!r}") from exc
    finally:
        os.close(current_fd)


class _DuplicateJSONKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant {value!r}")


def _parse_json_bytes(content: bytes, label: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HostEvidenceError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise HostEvidenceError(f"{label} must be a JSON object")
    return parsed


def _episode_reference(value: object, label: str) -> str:
    if isinstance(value, bool):
        raise HostEvidenceError(f"{label} must be a string or integer episode id")
    if isinstance(value, int):
        if value < 0:
            raise HostEvidenceError(f"{label} must be a non-negative episode id")
        return str(value)
    return _identifier(value, label)


def _raw_replay_semantics(content: bytes) -> dict[str, Any]:
    replay = _parse_json_bytes(content, "raw replay")
    info = replay.get("info")
    if not isinstance(info, Mapping):
        raise HostEvidenceError("raw replay info must be an object")
    episode_id = _episode_reference(info.get("EpisodeId"), "raw replay info.EpisodeId")
    team_names = info.get("TeamNames")
    if not isinstance(team_names, list) or len(team_names) != 2:
        raise HostEvidenceError("raw replay info.TeamNames must contain exactly two teams")
    if any(type(name) is not str or not name or name.strip() != name for name in team_names):
        raise HostEvidenceError("raw replay TeamNames must be non-empty trimmed strings")
    if len(set(team_names)) != 2:
        raise HostEvidenceError("raw replay TeamNames must map uniquely to seats")
    rewards = replay.get("rewards")
    statuses = replay.get("statuses")
    if not isinstance(rewards, list) or len(rewards) != 2:
        raise HostEvidenceError("raw replay rewards must contain exactly two values")
    if not all(
        not isinstance(reward, bool)
        and isinstance(reward, (int, float))
        and math.isfinite(float(reward))
        for reward in rewards
    ):
        raise HostEvidenceError("raw replay rewards must be finite numbers")
    if not isinstance(statuses, list) or len(statuses) != 2 or not all(
        type(status) is str and status for status in statuses
    ):
        raise HostEvidenceError("raw replay statuses must contain two non-empty strings")
    return {
        "episode_id": episode_id,
        "team_names": list(team_names),
        "rewards": list(rewards),
        "statuses": list(statuses),
    }


def _outcome_from_replay(semantics: Mapping[str, Any], seat: int) -> str:
    statuses = semantics["statuses"]
    rewards = semantics["rewards"]
    if any(status != "DONE" for status in statuses):
        return "runtime_failure"
    if rewards not in ([1, -1], [-1, 1]):
        raise HostEvidenceError("DONE replay rewards must be exactly [1, -1] or [-1, 1]")
    return "win" if rewards[seat] == 1 else "loss"


def _validate_census_receipt(
    content: bytes,
    census: Mapping[str, Any],
    *,
    registry_sha256: str,
    registry_chain_head: str,
) -> None:
    parsed = _parse_json_bytes(content, "hosted census receipt")
    if set(parsed) != _CENSUS_RECEIPT_FIELDS:
        raise HostEvidenceError("hosted census receipt fields are not exact")
    if parsed["schema"] != HOSTED_CENSUS_RECEIPT_SCHEMA:
        raise HostEvidenceError("hosted census receipt schema mismatch")
    if parsed["registry_sha256"] != registry_sha256:
        raise HostEvidenceError("hosted census receipt does not bind the registry")
    if parsed["registry_chain_head"] != registry_chain_head:
        raise HostEvidenceError("hosted census receipt does not bind the registry chain head")
    if parsed["exhaustive"] is not True:
        raise HostEvidenceError("hosted census receipt must make an exhaustive claim")
    games = _census_games(parsed["games"], "hosted census receipt.games")
    if games != census["games"]:
        raise HostEvidenceError("hosted census receipt games do not match signed census")
    expected = _census_commitment(registry_sha256, registry_chain_head, True, games)
    if parsed["commitment_sha256"] != expected or census["commitment_sha256"] != expected:
        raise HostEvidenceError("hosted census commitment is invalid")


def _empty_audit(reason: str, *, log_sha256: str | None = None, chain_head: str | None = None) -> dict[str, Any]:
    return {
        "schema": HOST_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "observation_log_sha256": log_sha256,
        "observation_chain_head": chain_head,
        "signed_manifest_sha256": None,
        "signer_public_key_fingerprint_sha256": None,
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": False,
        "failure_reason": reason,
        "receipts": [],
    }


def audit_host_evidence(
    observation_log: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    repo_root: str | os.PathLike[str],
    *,
    pinned_public_key: bytes,
    registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify signed replay bytes, semantic outcomes, registry bindings, and census coverage.

    ``registry`` is deliberately a required input for a complete audit.  The
    signed manifest binds its canonical hash and chain head, while the census
    receipt makes an explicit, committed exhaustive-coverage claim.  Neither
    claim is inferred from the observation log.
    """

    checked_log: dict[str, Any] | None = None
    log_sha256: str | None = None
    chain_head: str | None = None
    checked_registry: dict[str, Any] | None = None
    registry_sha256: str | None = None
    registry_chain_head: str | None = None
    try:
        checked_log = validate_observation_log(observation_log)
        log_sha256 = canonical_sha256(checked_log)
        chain_head = checked_log["chain_hashes"][-1] if checked_log["chain_hashes"] else GENESIS_CHAIN_HASH
        if registry is None:
            raise HostEvidenceError("preregistered registry is required")
        checked_registry = validate_registry(registry)
        registry_sha256 = canonical_sha256(checked_registry)
        registry_chain_head = (
            checked_registry["chain_hashes"][-1]
            if checked_registry["chain_hashes"]
            else GENESIS_CHAIN_HASH
        )
    except (CohortCustodyError, CanonicalJSONError, TypeError, ValueError) as exc:
        return _empty_audit(f"invalid observation log: {exc}")

    try:
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != ED25519_PUBLIC_KEY_BYTES:
            raise HostEvidenceError("pinned_public_key must be exactly 32 bytes")
        unsigned, payload, signature = _unsigned_manifest(dict(evidence_manifest))
        if unsigned["observation_log_sha256"] != log_sha256:
            raise HostEvidenceError("evidence manifest does not bind this observation log")
        if unsigned["observation_chain_head"] != chain_head:
            raise HostEvidenceError("evidence manifest does not bind the observation chain head")
        if unsigned["registry_sha256"] != registry_sha256:
            raise HostEvidenceError("evidence manifest does not bind the preregistered registry")
        if unsigned["registry_chain_head"] != registry_chain_head:
            raise HostEvidenceError("evidence manifest does not bind the registry chain head")
        signer_fingerprint = hashlib.sha256(pinned_public_key).hexdigest()
        if unsigned["signer_public_key_fingerprint_sha256"] != signer_fingerprint:
            raise HostEvidenceError("evidence manifest signer fingerprint does not match pinned key")
        try:
            Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise HostEvidenceError("Ed25519 host evidence signature did not verify") from exc

        observations = checked_log["records"]
        receipts = unsigned["receipts"]
        census = unsigned["census"]
        expected_census_commitment = _census_commitment(
            registry_sha256, registry_chain_head, True, census["games"]
        )
        if census["commitment_sha256"] != expected_census_commitment:
            raise HostEvidenceError("signed hosted census commitment does not bind the registry")
        if len(receipts) != len(observations):
            raise HostEvidenceError("receipts must exactly cover the observation log")
        if len(census["games"]) != len(receipts):
            raise HostEvidenceError("hosted census must cover every receipt")
        census_by_key = {
            (item["archive_sha256"], item["game_id"]): item for item in census["games"]
        }
        if len(census_by_key) != len(census["games"]):
            raise HostEvidenceError("hosted census games must be unique")
        registrations = {
            item["archive_sha256"]: item for item in checked_registry["records"]
        }
        if not registrations:
            raise HostEvidenceError("preregistered registry must contain an archive")
        teams = [item["team_pseudonym"] for item in checked_registry["records"]]
        if len(set(teams)) != len(teams):
            raise HostEvidenceError("preregistered team_pseudonym values must be unique")
        receipt_archives = {receipt["archive_sha256"] for receipt in receipts}
        if receipt_archives != set(registrations):
            raise HostEvidenceError(
                "hosted census must cover exactly the preregistered archives"
            )
        for index, (observation, receipt) in enumerate(zip(observations, receipts)):
            if receipt["archive_sha256"] != observation["archive_sha256"]:
                raise HostEvidenceError(f"receipt {index} archive does not equal observation")
            if receipt["game_id"] != observation["game_id"]:
                raise HostEvidenceError(f"receipt {index} game id does not equal observation")
            if receipt["hosted_created_at_utc"] != observation["created_at_utc"]:
                raise HostEvidenceError(f"receipt {index} created time does not equal observation")
            if receipt["completion_evidence_sha256"] != observation["completion_evidence_sha256"]:
                raise HostEvidenceError(f"receipt {index} completion evidence does not equal observation")
            replay_digest = observation["replay_content_sha256"]
            if replay_digest is None:
                raise HostEvidenceError(f"observation {index} has no replay content digest")
            census_game = census_by_key.get((receipt["archive_sha256"], receipt["game_id"]))
            if census_game is None or census_game["source_episode_reference_id"] != receipt[
                "source_episode_reference_id"
            ] or census_game["created_at_utc"] != receipt["hosted_created_at_utc"]:
                raise HostEvidenceError(f"census entry {index} does not match receipt")
            registration = registrations.get(receipt["archive_sha256"])
            if registration is None:
                raise HostEvidenceError(f"receipt {index} archive is not preregistered")

        root_fd = _open_repo_root(repo_root)
        verified: list[dict[str, Any]] = []
        try:
            census_content, census_digest = _read_opened_file(root_fd, census["receipt_path"])
            if census_digest != census["receipt_sha256"]:
                raise HostEvidenceError("hosted census receipt digest mismatch")
            _validate_census_receipt(
                census_content,
                census,
                registry_sha256=registry_sha256,
                registry_chain_head=registry_chain_head,
            )
            seen_replay_paths: set[str] = set()
            for receipt, observation in zip(receipts, observations):
                if receipt["raw_response_path"] in seen_replay_paths:
                    raise HostEvidenceError("raw response paths must be unique")
                seen_replay_paths.add(receipt["raw_response_path"])
                raw_content, actual = _read_opened_file(root_fd, receipt["raw_response_path"])
                if actual != receipt["raw_response_sha256"]:
                    raise HostEvidenceError(
                        f"raw response digest mismatch for {receipt['raw_response_path']!r}"
                    )
                if actual != observation["replay_content_sha256"]:
                    raise HostEvidenceError(
                        f"raw response digest does not equal observation replay digest for {receipt['game_id']!r}"
                    )
                semantics = _raw_replay_semantics(raw_content)
                if semantics["episode_id"] != receipt["game_id"]:
                    raise HostEvidenceError(
                        f"raw EpisodeId does not equal receipt game_id for {receipt['game_id']!r}"
                    )
                if semantics["episode_id"] != receipt["source_episode_reference_id"]:
                    raise HostEvidenceError(
                        f"raw EpisodeId does not equal source episode reference for {receipt['game_id']!r}"
                    )
                seat = observation["seat"]
                target_team = registrations[receipt["archive_sha256"]]["team_pseudonym"]
                team_names = semantics["team_names"]
                if team_names[seat] != target_team or team_names.count(target_team) != 1:
                    raise HostEvidenceError(
                        f"registered team does not map uniquely to observation seat for {receipt['game_id']!r}"
                    )
                derived_outcome = _outcome_from_replay(semantics, seat)
                if derived_outcome != observation["outcome"]:
                    raise HostEvidenceError(
                        f"replay rewards/statuses do not equal observation outcome for {receipt['game_id']!r}"
                    )
                verified.append(
                    {
                        "archive_sha256": receipt["archive_sha256"],
                        "game_id": receipt["game_id"],
                        "source_episode_reference_id": receipt["source_episode_reference_id"],
                        "team_pseudonym": target_team,
                        "seat": seat,
                        "team_names": semantics["team_names"],
                        "rewards": semantics["rewards"],
                        "statuses": semantics["statuses"],
                        "outcome": derived_outcome,
                        "raw_response_path": receipt["raw_response_path"],
                        "raw_response_sha256": actual,
                    }
                )
        finally:
            os.close(root_fd)
    except Exception as exc:
        return _empty_audit(str(exc), log_sha256=log_sha256, chain_head=chain_head)

    return {
        "schema": HOST_EVIDENCE_AUDIT_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "observation_log_sha256": log_sha256,
        "observation_chain_head": chain_head,
        "registry_sha256": registry_sha256,
        "registry_chain_head": registry_chain_head,
        "signed_manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signer_public_key_fingerprint_sha256": unsigned[
            "signer_public_key_fingerprint_sha256"
        ],
        "authority": False,
        "submission_authorized": False,
        "holdout_access_authorized": False,
        "evidence_complete": True,
        "failure_reason": None,
        "census": {
            "receipt_path": unsigned["census"]["receipt_path"],
            "receipt_sha256": unsigned["census"]["receipt_sha256"],
            "commitment_sha256": unsigned["census"]["commitment_sha256"],
            "exhaustive": True,
            "game_count": len(unsigned["census"]["games"]),
        },
        "receipts": verified,
    }


audit = audit_host_evidence
verify_host_evidence = audit_host_evidence


__all__ = [
    "ED25519_PUBLIC_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "GENESIS_CHAIN_HASH",
    "HOST_EVIDENCE_AUDIT_SCHEMA",
    "HOST_EVIDENCE_MANIFEST_SCHEMA",
    "HOSTED_CENSUS_RECEIPT_SCHEMA",
    "HostEvidenceError",
    "audit",
    "audit_host_evidence",
    "host_evidence_signing_payload",
    "verify_host_evidence",
]
