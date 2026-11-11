"""Fail-closed, no-authority opponent roster compiler for evaluation v4.2.

The compiler accepts only sealed, frozen inputs.  Family, rating layer, weight,
and OOD mass are all derived here; callers cannot smuggle any of those values
into an identity record.  This module has no clock, filesystem, network, or
submission surface.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from numbers import Real
from typing import Any


ROSTER_SCHEMA = "evaluation_v4_2_opponent_roster_v1"
ONTOLOGY_SCHEMA = "evaluation_v4_2_opponent_deck_family_ontology_v1"
LEADERBOARD_SCHEMA = "evaluation_v4_2_leaderboard_snapshot_v1"
STATE_FROZEN = "FROZEN"
CLASSIFICATION_BASIS = "deck_sha256_only_v1"
SOURCE_CLASSES = frozenset({"codex", "claude", "grok", "top_public"})
RATING_LAYERS = frozenset({"top", "mid", "low"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_FAMILY_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

_ONTOLOGY_CONTENT_FIELDS = frozenset(
    {"schema", "ontology_id", "classification_basis", "deck_to_family", "state"}
)
_ONTOLOGY_FIELDS = _ONTOLOGY_CONTENT_FIELDS | {"content_sha256"}
_SNAPSHOT_CONTENT_FIELDS = frozenset({"schema", "snapshot_id", "cutoff_timestamp", "rows", "state"})
_SNAPSHOT_FIELDS = _SNAPSHOT_CONTENT_FIELDS | {"content_sha256"}
_SNAPSHOT_ROW_FIELDS = frozenset({"team_id", "rank", "score"})
_IDENTITY_FIELDS = frozenset(
    {
        "opponent_id",
        "archive_sha256",
        "policy_content_sha256",
        "main_sha256",
        "deck_sha256",
        "source_class",
        "leaderboard_team_id",
    }
)
_ROSTER_CONTENT_FIELDS = frozenset(
    {
        "schema",
        "ontology_sha256",
        "leaderboard_snapshot_sha256",
        "opponent_roster",
        "external_authority",
        "submission_authorized",
        "anchor_allowed",
        "production_submission_authorized",
    }
)
_ROSTER_FIELDS = _ROSTER_CONTENT_FIELDS | {"content_sha256"}
_TEMPLATE_ROW_FIELDS = frozenset(
    {
        "opponent_id",
        "archive_sha256",
        "policy_content_sha256",
        "main_sha256",
        "deck_sha256",
        "family_id",
        "rating_layer",
        "weight",
        "ood_mass",
    }
)


class OpponentRosterError(ValueError):
    """A v4.2 ontology, snapshot, identity, or roster is malformed."""


@dataclass(frozen=True)
class ArchivePolicyIdentity:
    """The exact identity plus neutral provenance needed by the roster compiler."""

    opponent_id: str
    archive_sha256: str
    policy_content_sha256: str
    main_sha256: str
    deck_sha256: str
    source_class: str
    leaderboard_team_id: str


def canonical_json_bytes(value: object) -> bytes:
    """Return the canonical JSON bytes used for every self hash."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OpponentRosterError(f"value is not canonically JSON encodable: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _exact(value: object, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = sorted(value) if isinstance(value, Mapping) else type(value).__name__
        raise OpponentRosterError(f"{label} fields must exactly be {sorted(fields)}; got {actual}")
    return value


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise OpponentRosterError(f"{label} must be a non-empty trimmed string")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise OpponentRosterError(f"{label} must be a lowercase SHA-256")
    return value


def _utc(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise OpponentRosterError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise OpponentRosterError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise OpponentRosterError(f"{label} is not canonical UTC")
    return value


def _nonnegative_score(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise OpponentRosterError(f"{label} must be a finite non-negative number")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise OpponentRosterError(f"{label} must be a finite non-negative number")
    return result


def _rank(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OpponentRosterError(f"{label} must be a positive integer rank")
    return value


def _family(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _FAMILY_RE.fullmatch(value) is None:
        raise OpponentRosterError(f"{label} must be a neutral lowercase mechanism-family slug")
    if value in SOURCE_CLASSES or value in RATING_LAYERS:
        raise OpponentRosterError(f"{label} cannot encode provenance or rating")
    if any(token in value for token in ("authority", "submission", "outcome", "winner", "loser")):
        raise OpponentRosterError(f"{label} must be a neutral mechanism family")
    return value


def _validate_ontology_content(value: object) -> dict[str, Any]:
    raw = _exact(value, _ONTOLOGY_CONTENT_FIELDS, label="ontology content")
    if raw["schema"] != ONTOLOGY_SCHEMA:
        raise OpponentRosterError(f"ontology schema must be {ONTOLOGY_SCHEMA!r}")
    if raw["classification_basis"] != CLASSIFICATION_BASIS:
        raise OpponentRosterError("ontology classification_basis must be deck_sha256_only_v1")
    if raw["state"] != STATE_FROZEN:
        raise OpponentRosterError("ontology must be FROZEN")
    ontology_id = _text(raw["ontology_id"], label="ontology_id")
    mapping = raw["deck_to_family"]
    if not isinstance(mapping, Mapping) or not mapping:
        raise OpponentRosterError("deck_to_family must be a non-empty mapping")
    normalized_mapping: dict[str, str] = {}
    for deck_sha256, family_id in mapping.items():
        normalized_mapping[_sha(deck_sha256, label="deck_to_family key")] = _family(
            family_id, label="deck_to_family value"
        )
    if len(set(normalized_mapping.values())) < 5:
        raise OpponentRosterError("ontology must contain at least five mechanism families")
    return {
        "schema": ONTOLOGY_SCHEMA,
        "ontology_id": ontology_id,
        "classification_basis": CLASSIFICATION_BASIS,
        "deck_to_family": normalized_mapping,
        "state": STATE_FROZEN,
    }


def build_deck_family_ontology(content: Mapping[str, Any]) -> dict[str, Any]:
    """Seal an exact, hash-free frozen deck-family ontology content object."""

    if not isinstance(content, Mapping) or "content_sha256" in content:
        raise OpponentRosterError("ontology builder accepts exact hash-free content")
    normalized = _validate_ontology_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def validate_deck_family_ontology(value: object) -> dict[str, Any]:
    raw = _exact(value, _ONTOLOGY_FIELDS, label="ontology")
    content = _validate_ontology_content({field: raw[field] for field in _ONTOLOGY_CONTENT_FIELDS})
    digest = _sha(raw["content_sha256"], label="ontology.content_sha256")
    if digest != canonical_sha256(content):
        raise OpponentRosterError("ontology content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise OpponentRosterError("ontology is not canonical")
    return expected


def _validate_snapshot_content(value: object) -> dict[str, Any]:
    raw = _exact(value, _SNAPSHOT_CONTENT_FIELDS, label="leaderboard snapshot content")
    if raw["schema"] != LEADERBOARD_SCHEMA:
        raise OpponentRosterError(f"leaderboard snapshot schema must be {LEADERBOARD_SCHEMA!r}")
    if raw["state"] != STATE_FROZEN:
        raise OpponentRosterError("leaderboard snapshot must be FROZEN")
    snapshot_id = _text(raw["snapshot_id"], label="snapshot_id")
    cutoff_timestamp = _utc(raw["cutoff_timestamp"], label="cutoff_timestamp")
    rows = raw["rows"]
    if not isinstance(rows, list) or not rows:
        raise OpponentRosterError("leaderboard snapshot rows must be a non-empty list")
    normalized_rows: list[dict[str, Any]] = []
    teams: set[str] = set()
    ranks: set[int] = set()
    for index, item in enumerate(rows):
        row = _exact(item, _SNAPSHOT_ROW_FIELDS, label=f"snapshot.rows[{index}]")
        team_id = _text(row["team_id"], label=f"snapshot.rows[{index}].team_id")
        rank = _rank(row["rank"], label=f"snapshot.rows[{index}].rank")
        score = _nonnegative_score(row["score"], label=f"snapshot.rows[{index}].score")
        if team_id in teams:
            raise OpponentRosterError(f"duplicate leaderboard team_id {team_id!r}")
        if rank in ranks:
            raise OpponentRosterError(f"duplicate leaderboard rank {rank}")
        teams.add(team_id)
        ranks.add(rank)
        normalized_rows.append({"team_id": team_id, "rank": rank, "score": score})
    normalized_rows.sort(key=lambda row: row["team_id"])
    return {
        "schema": LEADERBOARD_SCHEMA,
        "snapshot_id": snapshot_id,
        "cutoff_timestamp": cutoff_timestamp,
        "rows": normalized_rows,
        "state": STATE_FROZEN,
    }


def build_leaderboard_snapshot(content: Mapping[str, Any]) -> dict[str, Any]:
    """Seal an exact, hash-free frozen leaderboard snapshot content object."""

    if not isinstance(content, Mapping) or "content_sha256" in content:
        raise OpponentRosterError("leaderboard snapshot builder accepts exact hash-free content")
    normalized = _validate_snapshot_content(content)
    return {**normalized, "content_sha256": canonical_sha256(normalized)}


def validate_leaderboard_snapshot(value: object) -> dict[str, Any]:
    raw = _exact(value, _SNAPSHOT_FIELDS, label="leaderboard snapshot")
    content = _validate_snapshot_content({field: raw[field] for field in _SNAPSHOT_CONTENT_FIELDS})
    digest = _sha(raw["content_sha256"], label="snapshot.content_sha256")
    if digest != canonical_sha256(content):
        raise OpponentRosterError("leaderboard snapshot content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise OpponentRosterError("leaderboard snapshot is not canonical")
    return expected


def _identity_mapping(value: object, *, index: int) -> Mapping[str, Any]:
    if isinstance(value, ArchivePolicyIdentity):
        value = asdict(value)
    return _exact(value, _IDENTITY_FIELDS, label=f"identities[{index}]")


def _validate_identities(
    identities: object,
    *,
    ontology: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> list[dict[str, str]]:
    if not isinstance(identities, Sequence) or isinstance(identities, (str, bytes)):
        raise OpponentRosterError("identities must be a sequence of exact records")
    if len(identities) < 12:
        raise OpponentRosterError("at least twelve ArchivePolicyIdentity records are required")
    team_rows = {row["team_id"]: row for row in snapshot["rows"]}
    opponent_ids: set[str] = set()
    archive_hashes: set[str] = set()
    policy_hashes: set[str] = set()
    normalized: list[dict[str, str]] = []
    source_counts = {source: 0 for source in SOURCE_CLASSES}
    for index, item in enumerate(identities):
        raw = _identity_mapping(item, index=index)
        opponent_id = _text(raw["opponent_id"], label=f"identities[{index}].opponent_id")
        archive_sha256 = _sha(raw["archive_sha256"], label=f"identities[{index}].archive_sha256")
        policy_sha256 = _sha(
            raw["policy_content_sha256"], label=f"identities[{index}].policy_content_sha256"
        )
        main_sha256 = _sha(raw["main_sha256"], label=f"identities[{index}].main_sha256")
        deck_sha256 = _sha(raw["deck_sha256"], label=f"identities[{index}].deck_sha256")
        source_class = raw["source_class"]
        if source_class not in SOURCE_CLASSES:
            raise OpponentRosterError(f"identities[{index}].source_class is not permitted")
        team_id = _text(raw["leaderboard_team_id"], label=f"identities[{index}].leaderboard_team_id")
        if team_id not in team_rows:
            raise OpponentRosterError(f"identity {opponent_id!r} has no matching leaderboard team")
        if deck_sha256 not in ontology["deck_to_family"]:
            raise OpponentRosterError(f"identity {opponent_id!r} has no ontology family for its deck hash")
        if opponent_id in opponent_ids:
            raise OpponentRosterError(f"duplicate opponent_id {opponent_id!r}")
        if archive_sha256 in archive_hashes:
            raise OpponentRosterError(f"duplicate archive_sha256 {archive_sha256!r}")
        if policy_sha256 in policy_hashes:
            raise OpponentRosterError(f"duplicate policy_content_sha256 {policy_sha256!r}")
        opponent_ids.add(opponent_id)
        archive_hashes.add(archive_sha256)
        policy_hashes.add(policy_sha256)
        source_counts[source_class] += 1
        normalized.append(
            {
                "opponent_id": opponent_id,
                "archive_sha256": archive_sha256,
                "policy_content_sha256": policy_sha256,
                "main_sha256": main_sha256,
                "deck_sha256": deck_sha256,
                "source_class": source_class,
                "leaderboard_team_id": team_id,
            }
        )
    if any(source_counts[source] < 1 for source in ("codex", "claude", "grok")):
        raise OpponentRosterError("identities must include at least one Codex, Claude, and Grok record")
    if source_counts["top_public"] < 5:
        raise OpponentRosterError("identities must include at least five top_public records")
    return normalized


def _layer(rank: int) -> str:
    if rank <= 50:
        return "top"
    if rank <= 500:
        return "mid"
    return "low"


def _compile_rows(
    identities: list[dict[str, str]],
    *,
    ontology: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> list[dict[str, Any]]:
    team_rows = {row["team_id"]: row for row in snapshot["rows"]}
    weight = 1.0 / len(identities)
    rows: list[dict[str, Any]] = []
    for identity in identities:
        layer = _layer(team_rows[identity["leaderboard_team_id"]]["rank"])
        rows.append(
            {
                "opponent_id": identity["opponent_id"],
                "archive_sha256": identity["archive_sha256"],
                "policy_content_sha256": identity["policy_content_sha256"],
                "main_sha256": identity["main_sha256"],
                "deck_sha256": identity["deck_sha256"],
                "family_id": ontology["deck_to_family"][identity["deck_sha256"]],
                "rating_layer": layer,
                "weight": weight,
                "ood_mass": 1.0 if layer == "low" else 0.0,
            }
        )
    return sorted(rows, key=lambda row: row["opponent_id"])


def _validate_roster_content(value: object) -> dict[str, Any]:
    raw = _exact(value, _ROSTER_CONTENT_FIELDS, label="opponent roster content")
    if raw["schema"] != ROSTER_SCHEMA:
        raise OpponentRosterError(f"roster schema must be {ROSTER_SCHEMA!r}")
    ontology_sha256 = _sha(raw["ontology_sha256"], label="roster.ontology_sha256")
    snapshot_sha256 = _sha(
        raw["leaderboard_snapshot_sha256"], label="roster.leaderboard_snapshot_sha256"
    )
    for field in (
        "external_authority",
        "submission_authorized",
        "anchor_allowed",
        "production_submission_authorized",
    ):
        if raw[field] is not False:
            raise OpponentRosterError(f"roster.{field} must be exactly false")
    raw_rows = raw["opponent_roster"]
    if not isinstance(raw_rows, list) or len(raw_rows) < 12:
        raise OpponentRosterError("opponent_roster must contain at least twelve rows")
    rows: list[dict[str, Any]] = []
    opponent_ids: set[str] = set()
    archive_hashes: set[str] = set()
    policy_hashes: set[str] = set()
    families: set[str] = set()
    layers: set[str] = set()
    for index, item in enumerate(raw_rows):
        row = _exact(item, _TEMPLATE_ROW_FIELDS, label=f"opponent_roster[{index}]")
        normalized = {
            "opponent_id": _text(row["opponent_id"], label=f"opponent_roster[{index}].opponent_id"),
            "archive_sha256": _sha(row["archive_sha256"], label=f"opponent_roster[{index}].archive_sha256"),
            "policy_content_sha256": _sha(
                row["policy_content_sha256"], label=f"opponent_roster[{index}].policy_content_sha256"
            ),
            "main_sha256": _sha(row["main_sha256"], label=f"opponent_roster[{index}].main_sha256"),
            "deck_sha256": _sha(row["deck_sha256"], label=f"opponent_roster[{index}].deck_sha256"),
            "family_id": _family(row["family_id"], label=f"opponent_roster[{index}].family_id"),
            "rating_layer": row["rating_layer"],
            "weight": row["weight"],
            "ood_mass": row["ood_mass"],
        }
        if normalized["rating_layer"] not in RATING_LAYERS:
            raise OpponentRosterError(f"opponent_roster[{index}].rating_layer is invalid")
        if isinstance(normalized["weight"], bool) or not isinstance(normalized["weight"], Real):
            raise OpponentRosterError(f"opponent_roster[{index}].weight must be numeric")
        if not math.isfinite(float(normalized["weight"])) or float(normalized["weight"]) <= 0:
            raise OpponentRosterError(f"opponent_roster[{index}].weight must be finite and positive")
        if normalized["ood_mass"] not in (0.0, 1.0):
            raise OpponentRosterError(f"opponent_roster[{index}].ood_mass must be 0.0 or 1.0")
        if normalized["opponent_id"] in opponent_ids:
            raise OpponentRosterError(f"duplicate roster opponent_id {normalized['opponent_id']!r}")
        if normalized["archive_sha256"] in archive_hashes:
            raise OpponentRosterError("duplicate roster archive_sha256")
        if normalized["policy_content_sha256"] in policy_hashes:
            raise OpponentRosterError("duplicate roster policy_content_sha256")
        opponent_ids.add(normalized["opponent_id"])
        archive_hashes.add(normalized["archive_sha256"])
        policy_hashes.add(normalized["policy_content_sha256"])
        families.add(normalized["family_id"])
        layers.add(normalized["rating_layer"])
        rows.append(normalized)
    expected_weight = 1.0 / len(rows)
    if any(row["weight"] != expected_weight for row in rows):
        raise OpponentRosterError("roster weights must be exactly uniform")
    if any(row["ood_mass"] != (1.0 if row["rating_layer"] == "low" else 0.0) for row in rows):
        raise OpponentRosterError("roster ood_mass must be exactly one for low-layer rows only")
    if len(families) < 5:
        raise OpponentRosterError("roster must cover at least five mechanism families")
    if layers != RATING_LAYERS:
        raise OpponentRosterError("roster must span top, mid, and low rating layers")
    rows.sort(key=lambda row: row["opponent_id"])
    return {
        "schema": ROSTER_SCHEMA,
        "ontology_sha256": ontology_sha256,
        "leaderboard_snapshot_sha256": snapshot_sha256,
        "opponent_roster": rows,
        "external_authority": False,
        "submission_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }


def compile_opponent_roster(
    ontology: object,
    leaderboard_snapshot: object,
    identities: object,
) -> dict[str, Any]:
    """Compile exact source inputs into a sealed, template-ready roster."""

    checked_ontology = validate_deck_family_ontology(ontology)
    checked_snapshot = validate_leaderboard_snapshot(leaderboard_snapshot)
    checked_identities = _validate_identities(
        identities, ontology=checked_ontology, snapshot=checked_snapshot
    )
    rows = _compile_rows(checked_identities, ontology=checked_ontology, snapshot=checked_snapshot)
    content = {
        "schema": ROSTER_SCHEMA,
        "ontology_sha256": checked_ontology["content_sha256"],
        "leaderboard_snapshot_sha256": checked_snapshot["content_sha256"],
        "opponent_roster": rows,
        "external_authority": False,
        "submission_authorized": False,
        "anchor_allowed": False,
        "production_submission_authorized": False,
    }
    return {**content, "content_sha256": canonical_sha256(content)}


def validate_opponent_roster(value: object) -> dict[str, Any]:
    """Validate a sealed roster's shape, derivations-independent invariants, and self hash."""

    raw = _exact(value, _ROSTER_FIELDS, label="opponent roster")
    content = _validate_roster_content({field: raw[field] for field in _ROSTER_CONTENT_FIELDS})
    digest = _sha(raw["content_sha256"], label="roster.content_sha256")
    if digest != canonical_sha256(content):
        raise OpponentRosterError("roster content_sha256 mismatch")
    expected = {**content, "content_sha256": digest}
    if dict(raw) != expected:
        raise OpponentRosterError("opponent roster is not canonical")
    return expected


def audit_opponent_roster(
    roster: object,
    ontology: object,
    leaderboard_snapshot: object,
    identities: object,
) -> dict[str, Any]:
    """Recompile and compare a roster, detecting source tampering as well as self tampering."""

    checked = validate_opponent_roster(roster)
    expected = compile_opponent_roster(ontology, leaderboard_snapshot, identities)
    if checked != expected:
        raise OpponentRosterError("opponent roster does not match exact source derivation")
    return checked


# Descriptive aliases keep the compiler easy to discover without adding a
# second wire format or any authority route.
build_opponent_roster = compile_opponent_roster
audit_roster = audit_opponent_roster
validate_roster = validate_opponent_roster


__all__ = [
    "ArchivePolicyIdentity",
    "CLASSIFICATION_BASIS",
    "LEADERBOARD_SCHEMA",
    "ONTOLOGY_SCHEMA",
    "OpponentRosterError",
    "ROSTER_SCHEMA",
    "RATING_LAYERS",
    "SOURCE_CLASSES",
    "STATE_FROZEN",
    "audit_opponent_roster",
    "audit_roster",
    "build_deck_family_ontology",
    "build_leaderboard_snapshot",
    "build_opponent_roster",
    "canonical_json_bytes",
    "canonical_sha256",
    "compile_opponent_roster",
    "validate_deck_family_ontology",
    "validate_leaderboard_snapshot",
    "validate_opponent_roster",
    "validate_roster",
]
