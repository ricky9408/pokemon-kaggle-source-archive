"""Pure data firewall for the four v5 evidence partitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable


DEV_BURNED = "DEV_BURNED"
PROSPECTIVE_SHADOW = "PROSPECTIVE_SHADOW"
EXTERNAL_CONFIRMATORY = "EXTERNAL_CONFIRMATORY"
SEALED_50 = "SEALED_50"
PARTITIONS = frozenset({DEV_BURNED, PROSPECTIVE_SHADOW, EXTERNAL_CONFIRMATORY, SEALED_50})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
ARCHITECTURE_FREEZE_AT_UTC = "2026-07-13T17:54:27.000000Z"
_ARCHITECTURE_FREEZE_AT = datetime(2026, 7, 13, 17, 54, 27)


class FirewallError(ValueError):
    """A partition record violates the v5 custody and chronology firewall."""


def _text(value: object, *, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise FirewallError(f"{label} must be a non-empty trimmed string")
    return value


def _sha(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise FirewallError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _utc(value: object, *, label: str) -> datetime:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise FirewallError(f"{label} must be canonical UTC with six fractional digits")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise FirewallError(f"{label} is not a valid UTC timestamp") from exc
    return parsed


@dataclass(frozen=True, slots=True)
class ArchiveRecord:
    """Immutable identity and chronology binding for one exact archive."""

    archive_id: str
    partition: str
    archive_sha256: str
    deck_sha256: str
    policy_sha256: str
    family_provenance_sha256: str
    model_input_sha256: str
    registered_at_utc: str
    first_hosted_game_at_utc: str | None = None
    outcomes_observed: bool = False
    payload_path: str | None = None

    @property
    def policy_content_sha256(self) -> str:
        return self.policy_sha256

    def __post_init__(self) -> None:
        _validate_record(self)

    def exposed(self) -> SealedArchiveRecord:
        """Return the path-free public identity projection."""

        return SealedArchiveRecord(
            archive_id=self.archive_id,
            partition=self.partition,
            archive_sha256=self.archive_sha256,
            deck_sha256=self.deck_sha256,
            policy_sha256=self.policy_sha256,
            family_provenance_sha256=self.family_provenance_sha256,
            model_input_sha256=self.model_input_sha256,
        )

    def as_dict(self) -> dict[str, str | None | bool]:
        """Serialize an identity without exposing operational payload data."""

        result: dict[str, str | None | bool] = {
            "archive_id": self.archive_id,
            "partition": self.partition,
            "archive_sha256": self.archive_sha256,
            "deck_sha256": self.deck_sha256,
            "policy_sha256": self.policy_sha256,
            "family_provenance_sha256": self.family_provenance_sha256,
            "model_input_sha256": self.model_input_sha256,
        }
        if self.partition != SEALED_50:
            result.update(
                {
                    "registered_at_utc": self.registered_at_utc,
                    "first_hosted_game_at_utc": self.first_hosted_game_at_utc,
                    "outcomes_observed": self.outcomes_observed,
                }
            )
        return result


@dataclass(frozen=True, slots=True)
class SealedArchiveRecord:
    """The only representation exposed for a sealed entry; it has no path."""

    archive_id: str
    partition: str
    archive_sha256: str
    deck_sha256: str
    policy_sha256: str
    family_provenance_sha256: str
    model_input_sha256: str

    @property
    def policy_content_sha256(self) -> str:
        return self.policy_sha256

    def as_dict(self) -> dict[str, str]:
        return {
            "archive_id": self.archive_id,
            "partition": self.partition,
            "archive_sha256": self.archive_sha256,
            "deck_sha256": self.deck_sha256,
            "policy_sha256": self.policy_sha256,
            "family_provenance_sha256": self.family_provenance_sha256,
            "model_input_sha256": self.model_input_sha256,
        }


def _validate_record(record: ArchiveRecord) -> None:
    _text(record.archive_id, label="archive_id")
    if type(record.partition) is not str or record.partition not in PARTITIONS:
        raise FirewallError(f"unrecognized partition {record.partition!r}")
    for field in (
        "archive_sha256",
        "deck_sha256",
        "policy_sha256",
        "family_provenance_sha256",
        "model_input_sha256",
    ):
        _sha(getattr(record, field), label=field)
    registered_at = _utc(record.registered_at_utc, label="registered_at_utc")
    first_hosted = None
    if record.first_hosted_game_at_utc is not None:
        first_hosted = _utc(record.first_hosted_game_at_utc, label="first_hosted_game_at_utc")
    if type(record.outcomes_observed) is not bool:
        raise FirewallError("outcomes_observed must be a boolean")
    if record.payload_path is not None:
        _text(record.payload_path, label="payload_path")

    if record.partition == EXTERNAL_CONFIRMATORY:
        if registered_at <= _ARCHITECTURE_FREEZE_AT:
            raise FirewallError("confirmatory registrations must be post-freeze")
        if record.outcomes_observed:
            raise FirewallError("confirmatory records cannot have observed outcomes")
        if first_hosted is not None:
            raise FirewallError("confirmatory records cannot carry hosted chronology")
    if record.partition == SEALED_50:
        if record.payload_path is not None:
            raise FirewallError("sealed records cannot carry a payload path")
        if record.outcomes_observed or first_hosted is not None:
            raise FirewallError("sealed records cannot expose outcomes or hosted chronology")


@dataclass(frozen=True, slots=True)
class Firewall:
    """Validated, immutable registry with no authority-bearing state."""

    records: tuple[ArchiveRecord, ...]
    authority: bool = False

    def __post_init__(self) -> None:
        if type(self.records) is not tuple:
            raise FirewallError("firewall records must be an immutable tuple")
        if self.authority is not False:
            raise FirewallError("the v5 firewall never grants authority")
        _validate_records(self.records)

    def exposed_records(self) -> tuple[SealedArchiveRecord, ...]:
        return tuple(record.exposed() for record in self.records)

    def sealed_records(self) -> tuple[SealedArchiveRecord, ...]:
        return tuple(record.exposed() for record in self.records if record.partition == SEALED_50)


def _validate_records(records: Iterable[ArchiveRecord]) -> None:
    seen_ids: set[str] = set()
    seen_archives: set[str] = set()
    validated: list[ArchiveRecord] = []
    for record in records:
        if not isinstance(record, ArchiveRecord):
            raise FirewallError("firewall records must contain ArchiveRecord values")
        _validate_record(record)
        if record.archive_id in seen_ids:
            raise FirewallError(f"archive overlap for archive_id {record.archive_id!r}")
        if record.archive_sha256 in seen_archives:
            raise FirewallError(f"archive overlap for archive_sha256 {record.archive_sha256!r}")
        seen_ids.add(record.archive_id)
        seen_archives.add(record.archive_sha256)
        validated.append(record)

    development_policies = {
        record.policy_sha256
        for record in validated
        if record.partition in {DEV_BURNED, PROSPECTIVE_SHADOW}
    }
    confirmatory_policies = {
        record.policy_sha256 for record in validated if record.partition == EXTERNAL_CONFIRMATORY
    }
    policy_overlap = development_policies & confirmatory_policies
    if policy_overlap:
        raise FirewallError(
            f"policy_sha256 overlap between development and confirmatory partitions {min(policy_overlap)!r}"
        )

    sealed_policies = {record.policy_sha256 for record in validated if record.partition == SEALED_50}
    nonsealed_policies = {record.policy_sha256 for record in validated if record.partition != SEALED_50}
    sealed_policy_overlap = sealed_policies & nonsealed_policies
    if sealed_policy_overlap:
        raise FirewallError(
            f"policy_sha256 overlap between SEALED_50 and nonsealed partitions {min(sealed_policy_overlap)!r}"
        )

    sealed_model_inputs = {record.model_input_sha256 for record in validated if record.partition == SEALED_50}
    nonsealed_model_inputs = {
        record.model_input_sha256 for record in validated if record.partition != SEALED_50
    }
    sealed_model_input_overlap = sealed_model_inputs & nonsealed_model_inputs
    if sealed_model_input_overlap:
        raise FirewallError(
            "model_input_sha256 overlap between SEALED_50 and nonsealed partitions "
            f"{min(sealed_model_input_overlap)!r}"
        )

    seen_confirmatory_model_inputs: dict[str, ArchiveRecord] = {}
    confirmatory_families_by_policy: dict[str, str] = {}
    for record in validated:
        if record.partition != EXTERNAL_CONFIRMATORY:
            continue
        prior = seen_confirmatory_model_inputs.get(record.model_input_sha256)
        if prior is not None:
            raise FirewallError(
                "model_input_sha256 overlap across distinct confirmatory archives "
                f"{prior.archive_id!r} and {record.archive_id!r}"
            )
        seen_confirmatory_model_inputs[record.model_input_sha256] = record
        prior_family = confirmatory_families_by_policy.get(record.policy_sha256)
        if prior_family is not None and prior_family != record.family_provenance_sha256:
            raise FirewallError(
                "family_provenance_sha256 mismatch for identical confirmatory policy_sha256 "
                f"{record.policy_sha256!r}"
            )
        confirmatory_families_by_policy[record.policy_sha256] = record.family_provenance_sha256


def validate_firewall(value: object) -> Firewall:
    """Validate an immutable firewall; mappings are intentionally not accepted."""

    if not isinstance(value, Firewall):
        raise FirewallError("firewall must be a typed Firewall instance")
    return value


def build_firewall(records: Iterable[ArchiveRecord]) -> Firewall:
    """Build a firewall from already-typed records without touching payloads."""

    if isinstance(records, (str, bytes)):
        raise FirewallError("records must be an iterable of ArchiveRecord values")
    try:
        frozen = tuple(records)
    except TypeError as exc:
        raise FirewallError("records must be an iterable of ArchiveRecord values") from exc
    return Firewall(records=frozen)


__all__ = [
    "ArchiveRecord",
    "ARCHITECTURE_FREEZE_AT_UTC",
    "DEV_BURNED",
    "EXTERNAL_CONFIRMATORY",
    "Firewall",
    "FirewallError",
    "PARTITIONS",
    "PROSPECTIVE_SHADOW",
    "SEALED_50",
    "SealedArchiveRecord",
    "build_firewall",
    "validate_firewall",
]
