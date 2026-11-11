"""Typed, frozen, authority-free representation of the v5 preregistration."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any, Mapping

from .canonical import canonical_sha256


PROTOCOL_ID = "MCI_TRANSFER_V1"
CHARTER_SCHEMA = "evaluation_v5_charter_v1"
FEATURE_NAMES = (
    "attack_availability_t2_t4",
    "prize_progress_t4",
    "post_active_ko_attack_recovery",
    "attachment_productivity_2t",
    "post_disruption_attack_recovery",
    "observation_invariance",
)

MIN_ARCHIVES = 30
MIN_FAMILIES = 15
GAMES_PER_ARCHIVE = 48
ALPHA = 0.025
EFFECT_THRESHOLD_NATS = 0.010
DEADLINE_DAYS = 120
MATURITY_HOURS = 1

FORBIDDEN_SELECTORS = (
    "nuisance-only null model",
    "raw local win-rate model",
    "L/T mean model",
    "local CVaR model",
    "action-imitation model",
    "search-rank model",
    "accepted-exploration model",
)


class CharterError(ValueError):
    """The supplied charter is not exactly the frozen v5 charter."""


@dataclass(frozen=True, slots=True)
class Charter:
    """The only charter accepted by the v5 core.

    ``authority`` is intentionally a field rather than an inferred property so
    serialized artifacts cannot omit the closed posture.  Construction rejects
    every value other than the preregistered constants.
    """

    protocol_id: str = PROTOCOL_ID
    feature_names: tuple[str, ...] = FEATURE_NAMES
    min_archives: int = MIN_ARCHIVES
    min_families: int = MIN_FAMILIES
    games_per_archive: int = GAMES_PER_ARCHIVE
    alpha: float = ALPHA
    effect_threshold_nats: float = EFFECT_THRESHOLD_NATS
    deadline_days: int = DEADLINE_DAYS
    maturity_hours: int = MATURITY_HOURS
    forbidden_selectors: tuple[str, ...] = FORBIDDEN_SELECTORS
    authority: bool = False

    def __post_init__(self) -> None:
        if type(self.protocol_id) is not str:
            raise CharterError("protocol_id must be a string")
        if type(self.feature_names) is not tuple or not all(type(item) is str for item in self.feature_names):
            raise CharterError("feature_names must be a tuple of strings")
        if type(self.forbidden_selectors) is not tuple or not all(
            type(item) is str for item in self.forbidden_selectors
        ):
            raise CharterError("forbidden_selectors must be a tuple of strings")
        for field in ("min_archives", "min_families", "games_per_archive", "deadline_days", "maturity_hours"):
            if type(getattr(self, field)) is not int:
                raise CharterError(f"{field} must be an integer")
        for field in ("alpha", "effect_threshold_nats"):
            if type(getattr(self, field)) is not float or not math.isfinite(getattr(self, field)):
                raise CharterError(f"{field} must be a finite float")
        if type(self.authority) is not bool:
            raise CharterError("authority must be a boolean")
        expected = {
            "protocol_id": PROTOCOL_ID,
            "feature_names": FEATURE_NAMES,
            "min_archives": MIN_ARCHIVES,
            "min_families": MIN_FAMILIES,
            "games_per_archive": GAMES_PER_ARCHIVE,
            "alpha": ALPHA,
            "effect_threshold_nats": EFFECT_THRESHOLD_NATS,
            "deadline_days": DEADLINE_DAYS,
            "maturity_hours": MATURITY_HOURS,
            "forbidden_selectors": FORBIDDEN_SELECTORS,
            "authority": False,
        }
        actual = {
            "protocol_id": self.protocol_id,
            "feature_names": self.feature_names,
            "min_archives": self.min_archives,
            "min_families": self.min_families,
            "games_per_archive": self.games_per_archive,
            "alpha": self.alpha,
            "effect_threshold_nats": self.effect_threshold_nats,
            "deadline_days": self.deadline_days,
            "maturity_hours": self.maturity_hours,
            "forbidden_selectors": self.forbidden_selectors,
            "authority": self.authority,
        }
        if actual != expected:
            raise CharterError("charter differs from the frozen v5 preregistration")

    @property
    def effect_min_nats(self) -> float:
        """Compatibility spelling for the preregistered effect threshold."""

        return self.effect_threshold_nats

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": CHARTER_SCHEMA,
            "protocol_id": self.protocol_id,
            "feature_names": list(self.feature_names),
            "min_archives": self.min_archives,
            "min_families": self.min_families,
            "games_per_archive": self.games_per_archive,
            "alpha": self.alpha,
            "effect_threshold_nats": self.effect_threshold_nats,
            "deadline_days": self.deadline_days,
            "maturity_hours": self.maturity_hours,
            "forbidden_selectors": list(self.forbidden_selectors),
            "authority": self.authority,
        }


_CHARTER_FIELDS = frozenset(Charter().as_dict())


def build_charter() -> Charter:
    """Build the frozen charter without accepting caller-supplied thresholds."""

    return Charter()


def validate_charter(value: object) -> Charter:
    """Validate a typed charter or its exact wire representation."""

    if isinstance(value, Charter):
        return value
    if not isinstance(value, Mapping) or set(value) != _CHARTER_FIELDS:
        raise CharterError(f"charter fields must exactly be {sorted(_CHARTER_FIELDS)}")
    if value["schema"] != CHARTER_SCHEMA:
        raise CharterError(f"charter schema must be {CHARTER_SCHEMA!r}")
    feature_names = value["feature_names"]
    selectors = value["forbidden_selectors"]
    if not isinstance(feature_names, list) or not all(isinstance(item, str) for item in feature_names):
        raise CharterError("feature_names must be a JSON list of strings")
    if not isinstance(selectors, list) or not all(isinstance(item, str) for item in selectors):
        raise CharterError("forbidden_selectors must be a JSON list of strings")
    try:
        return Charter(
            protocol_id=value["protocol_id"],
            feature_names=tuple(feature_names),
            min_archives=value["min_archives"],
            min_families=value["min_families"],
            games_per_archive=value["games_per_archive"],
            alpha=value["alpha"],
            effect_threshold_nats=value["effect_threshold_nats"],
            deadline_days=value["deadline_days"],
            maturity_hours=value["maturity_hours"],
            forbidden_selectors=tuple(selectors),
            authority=value["authority"],
        )
    except (TypeError, CharterError) as exc:
        if isinstance(exc, CharterError):
            raise
        raise CharterError("charter contains invalid field types") from exc


def charter_sha256(value: Charter | Mapping[str, Any]) -> str:
    """Hash the exact canonical charter wire representation."""

    return canonical_sha256(validate_charter(value).as_dict())


__all__ = [
    "ALPHA",
    "CHARTER_SCHEMA",
    "Charter",
    "CharterError",
    "DEADLINE_DAYS",
    "EFFECT_THRESHOLD_NATS",
    "FEATURE_NAMES",
    "FORBIDDEN_SELECTORS",
    "GAMES_PER_ARCHIVE",
    "MATURITY_HOURS",
    "MIN_ARCHIVES",
    "MIN_FAMILIES",
    "PROTOCOL_ID",
    "build_charter",
    "charter_sha256",
    "validate_charter",
]
