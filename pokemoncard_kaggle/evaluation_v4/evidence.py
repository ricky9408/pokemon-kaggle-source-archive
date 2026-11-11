"""Externally anchored prediction registrations for whole-policy calibration.

The Kaggle submission row can prove that a registration hash existed before
the submission's future public games. It cannot prove the uploaded server-side
archive bytes, and it cannot authorize that submission retroactively.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Mapping


REGISTRATION_SCHEMA = "whole_policy_prediction_registration_v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REGISTRATION_FIELDS = {
    "schema",
    "unit_id",
    "protocol_sha256",
    "lineage_manifest_sha256",
    "selector_code_sha256",
    "archive_sha256",
    "archive_name",
    "team_name",
    "lineage_id",
    "ancestry_id",
    "family_id",
    "block_id",
    "frozen_at_utc",
    "nuisance_probability",
    "selector_probability",
    "simulator_delta",
    "ood_mass",
    "engine_variant_means",
}


def _canonical_utc(value: object, *, label: str, require_canonical: bool = True) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty timestamp")
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not ISO-8601") from exc
    if parsed.tzinfo is None:
        if require_canonical:
            raise ValueError(f"{label} must include a UTC offset")
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    normalized = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if require_canonical and normalized != text:
        raise ValueError(f"{label} must be canonical UTC ({normalized})")
    return parsed, normalized


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{label} must be a non-empty trimmed string")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _number(value: object, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{label} must be finite")
    return float(value)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class PredictionRegistration:
    schema: str
    unit_id: str
    protocol_sha256: str
    lineage_manifest_sha256: str
    selector_code_sha256: str
    archive_sha256: str
    archive_name: str
    team_name: str
    lineage_id: str
    ancestry_id: str
    family_id: str
    block_id: str
    frozen_at_utc: str
    nuisance_probability: float
    selector_probability: float
    simulator_delta: float
    ood_mass: float
    engine_variant_means: dict[str, float]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PredictionRegistration":
        if set(value) != _REGISTRATION_FIELDS:
            raise ValueError(f"registration fields must exactly be {sorted(_REGISTRATION_FIELDS)}")
        if value.get("schema") != REGISTRATION_SCHEMA:
            raise ValueError("registration schema mismatch")
        archive_name = _identifier(value["archive_name"], label="archive_name")
        if Path(archive_name).name != archive_name:
            raise ValueError("archive_name must be a basename")
        _, frozen_at = _canonical_utc(value["frozen_at_utc"], label="frozen_at_utc")
        nuisance = _number(value["nuisance_probability"], label="nuisance_probability")
        selector = _number(value["selector_probability"], label="selector_probability")
        ood_mass = _number(value["ood_mass"], label="ood_mass")
        if not 0.0 < nuisance < 1.0 or not 0.0 < selector < 1.0:
            raise ValueError("probabilities must be inside (0, 1)")
        if not 0.0 <= ood_mass <= 1.0:
            raise ValueError("ood_mass must be inside [0, 1]")
        variants = value["engine_variant_means"]
        if not isinstance(variants, dict) or not variants:
            raise ValueError("engine_variant_means must be a non-empty object")
        normalized_variants: dict[str, float] = {}
        for key, result in variants.items():
            normalized_variants[_identifier(key, label="engine variant")] = _number(
                result, label=f"engine_variant_means[{key!r}]"
            )
        return cls(
            schema=REGISTRATION_SCHEMA,
            unit_id=_identifier(value["unit_id"], label="unit_id"),
            protocol_sha256=_sha256(value["protocol_sha256"], label="protocol_sha256"),
            lineage_manifest_sha256=_sha256(
                value["lineage_manifest_sha256"], label="lineage_manifest_sha256"
            ),
            selector_code_sha256=_sha256(value["selector_code_sha256"], label="selector_code_sha256"),
            archive_sha256=_sha256(value["archive_sha256"], label="archive_sha256"),
            archive_name=archive_name,
            team_name=_identifier(value["team_name"], label="team_name"),
            lineage_id=_identifier(value["lineage_id"], label="lineage_id"),
            ancestry_id=_identifier(value["ancestry_id"], label="ancestry_id"),
            family_id=_identifier(value["family_id"], label="family_id"),
            block_id=_identifier(value["block_id"], label="block_id"),
            frozen_at_utc=frozen_at,
            nuisance_probability=nuisance,
            selector_probability=selector,
            simulator_delta=_number(value["simulator_delta"], label="simulator_delta"),
            ood_mass=ood_mass,
            engine_variant_means=normalized_variants,
        )

    @property
    def frozen_at(self) -> datetime:
        return _canonical_utc(self.frozen_at_utc, label="frozen_at_utc")[0]

    def content_sha256(self) -> str:
        return hashlib.sha256(canonical_bytes(asdict(self))).hexdigest()


def load_registration(path: Path) -> PredictionRegistration:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read registration: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("registration must be a JSON object")
    return PredictionRegistration.from_mapping(value)


def write_registration_create_once(path: Path, registration: PredictionRegistration) -> None:
    normalized = PredictionRegistration.from_mapping(asdict(registration))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(asdict(normalized), indent=2, sort_keys=True))
        handle.write("\n")


def _submission_time(value: str) -> datetime:
    return _canonical_utc(value, label="submission date", require_canonical=False)[0]


def verify_kaggle_submission_anchor(
    registration_path: Path,
    submissions_csv: Path,
) -> dict[str, Any]:
    """Verify a server-listed hash commitment, never uploaded-byte identity."""

    registration = load_registration(registration_path)
    registration_sha256 = sha256_file(registration_path)
    expected_registration_token = f"reg-sha256={registration_sha256}"
    expected_archive_token = f"archive-sha256={registration.archive_sha256}"
    try:
        with submissions_csv.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"ref", "fileName", "date", "description", "status"}
            if not required.issubset(set(reader.fieldnames or [])):
                raise ValueError("submissions CSV is missing required columns")
            matches = [
                row
                for row in reader
                if row.get("fileName") == registration.archive_name
                and expected_registration_token in str(row.get("description") or "")
            ]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise ValueError(f"cannot read submissions CSV: {exc}") from exc
    if len(matches) != 1:
        raise ValueError(f"expected exactly one externally anchored submission row, found {len(matches)}")
    row = matches[0]
    description = str(row.get("description") or "")
    if expected_archive_token not in description:
        raise ValueError("submission description does not bind archive_sha256")
    if row.get("status") != "SubmissionStatus.COMPLETE":
        raise ValueError("anchored submission is not COMPLETE")
    anchored_at = _submission_time(str(row.get("date") or ""))
    if registration.frozen_at > anchored_at:
        raise ValueError("registration frozen_at_utc is after the external submission anchor")
    submission_ref = _identifier(row.get("ref"), label="submission ref")
    return {
        "schema": "kaggle_prediction_anchor_receipt_v1",
        "anchor_verified": True,
        "scope": "post_submission_calibration_only",
        "registration_sha256": registration_sha256,
        "archive_sha256_intent": registration.archive_sha256,
        "archive_bytes_server_verified": False,
        "submission_ref": submission_ref,
        "submission_date_utc": anchored_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "submissions_csv": str(submissions_csv),
        "submissions_csv_sha256": sha256_file(submissions_csv),
        "first_submission_authorized": False,
    }


__all__ = [
    "PredictionRegistration",
    "REGISTRATION_SCHEMA",
    "load_registration",
    "sha256_file",
    "verify_kaggle_submission_anchor",
    "write_registration_create_once",
]
