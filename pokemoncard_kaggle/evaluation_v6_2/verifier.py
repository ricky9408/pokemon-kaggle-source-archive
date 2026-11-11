"""Hermetic, read-only verifier for the v6.2.1 calibration upload boundary.

This module intentionally accepts only files and JSON mappings.  It has no
executor, protocol, network, or submission dependency; a permit is merely a
deterministic statement that an exact frozen archive satisfies the pre-upload
checks described in the v6.2.1 binding errata.
"""

from __future__ import annotations

import hashlib
import json
import math
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


BUNDLE_SCHEMA = "evaluation_v6_2_1_preupload_bundle_v1"
VERDICT_SCHEMA = "evaluation_v6_2_1_preupload_verdict_v1"
# v6.2.1's verifier and protocol used incompatible population/root schemas.
# Keep this implementation available for diagnostics, but never let it mint an
# upload permit.  v6.2.2 is the only future authorization contract.
AUTHORIZATION_SCHEMA_RETIRED = True
REQUIRED_RECEIPTS = (
    "CUSTODY_PASS",
    "POPULATION_16_PASS",
    "INDEPENDENCE_PASS",
    "CONTROLS_PASS",
    "LOCAL_EVIDENCE_FROZEN",
    "ANALYSIS_LOCK_PASS",
    "EXECUTOR_FAIL_CLOSED_PASS",
    "UPLOAD_LOCK_EXCLUSIVE_PASS",
    "LEDGER_DISJOINT_PASS",
    "QUOTA_READY",
    "PREREG_ROOT_PUBLISHED",
    "SOL_PREUPLOAD_PASS",
)
REQUIRED_ARTIFACTS = (
    "protocol_v6_2_1.json",
    "population_manifest.jsonl",
    "independence_report.json",
    "ancestry_graph.json",
    "controls_manifest.json",
    "local_panel.json",
    "local_evidence_root.json",
    "analysis_bundle.json",
    "executor_bundle.json",
    "poll_collector_spec.json",
    "prereg_root.json",
)
_POPULATION_SLOTS = (
    *(f"D{index:02d}" for index in range(1, 7)),
    "DR01",
    *(f"C{index:02d}" for index in range(1, 9)),
    "CR01",
)
_SLOT_ROLES = {
    **{f"D{index:02d}": "DEV_PRIMARY" for index in range(1, 7)},
    "DR01": "DEV_RESERVE",
    **{f"C{index:02d}": "CONFIRM_PRIMARY" for index in range(1, 9)},
    "CR01": "CONFIRM_RESERVE",
}
_CUSTODY_FIELDS = (
    "source_tree_sha256",
    "build_container_sha256",
    "linux_amd64_sha256",
    "source_archive_equality_sha256",
    "safety_smoke_sha256",
)
_FORBIDDEN_PATH_PARTS = {"sealed", "holdout", "sealed_holdout", "sealed-holdout"}


class VerificationError(ValueError):
    """A bundle is malformed or fails a fail-closed pre-upload invariant."""


def _check_json(value: object, *, path: str = "$", active: set[int] | None = None) -> None:
    if active is None:
        active = set()
    value_type = type(value)
    if value is None or value_type in (bool, int, str):
        return
    if value_type is float:
        if not math.isfinite(value):
            raise VerificationError(f"{path} contains a non-finite number")
        return
    if value_type in (list, dict):
        if id(value) in active:
            raise VerificationError(f"{path} contains a cycle")
        active.add(id(value))
        try:
            iterator = enumerate(value) if value_type is list else value.items()
            for key, item in iterator:
                if value_type is dict and type(key) is not str:
                    raise VerificationError(f"{path} has a non-string key")
                _check_json(item, path=f"{path}[{key!r}]", active=active)
        finally:
            active.remove(id(value))
        return
    raise VerificationError(f"{path} contains non-JSON type {value_type.__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole allowed JSON representation for bindings and receipts."""

    _check_json(value)
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def preregistration_root(campaign_id: str, artifact_sha256s: Mapping[str, str]) -> str:
    """The canonical, domain-separated root over all non-self prereg artifacts."""

    return canonical_sha256(
        {
            "domain": "evaluation_v6_2_1_preregistration_root_v1",
            "campaign_id": campaign_id,
            "artifact_sha256s": dict(artifact_sha256s),
        }
    )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise VerificationError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError(f"{label} must be a non-empty string")
    return value


def _sha(value: object, label: str) -> str:
    if not _is_sha256(value):
        raise VerificationError(f"{label} must be a lowercase SHA-256")
    return value


def _safe_regular_file(root: Path, relative_path: object, label: str) -> Path:
    raw = _string(relative_path, label)
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise VerificationError(f"{label} must be a safe relative path")
    if any(part.casefold() in _FORBIDDEN_PATH_PARTS for part in path.parts):
        raise VerificationError(f"{label} references a sealed or holdout path")

    current = root
    for part in path.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise VerificationError(f"{label} does not exist") from exc
        if stat.S_ISLNK(mode):
            raise VerificationError(f"{label} contains a symlink")
    if not stat.S_ISREG(current.stat().st_mode):
        raise VerificationError(f"{label} must reference a regular file")
    return current


def _canonical_file(path: Path, label: str) -> tuple[bytes, Any]:
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not valid JSON") from exc
    if raw != canonical_json_bytes(parsed):
        raise VerificationError(f"{label} is not canonical JSON")
    return raw, parsed


def _artifact_hashes(bundle: Mapping[str, Any], root: Path, failures: list[str]) -> dict[str, str]:
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes)):
        failures.append("ARTIFACTS_MISSING")
        return {}
    by_name: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(artifacts):
        try:
            record = _mapping(item, f"artifacts[{index}]")
            name = _string(record.get("name"), f"artifacts[{index}].name")
            if name in by_name:
                raise VerificationError(f"duplicate artifact {name}")
            by_name[name] = record
        except VerificationError as exc:
            failures.append(f"ARTIFACT_INVALID:{exc}")
    missing = sorted(set(REQUIRED_ARTIFACTS) - set(by_name))
    if missing:
        failures.append("ARTIFACTS_MISSING:" + ",".join(missing))
    hashes: dict[str, str] = {}
    for name, record in by_name.items():
        try:
            path = _safe_regular_file(root, record.get("path"), f"artifact {name}")
            raw = path.read_bytes()
            digest = _sha(record.get("sha256"), f"artifact {name}.sha256")
            if hashlib.sha256(raw).hexdigest() != digest:
                raise VerificationError(f"artifact {name} hash mismatch")
            if name.endswith(".json"):
                canonical_raw, _ = _canonical_file(path, f"artifact {name}")
                if canonical_raw != raw:
                    raise VerificationError(f"artifact {name} is not canonical JSON")
            hashes[name] = digest
        except VerificationError as exc:
            failures.append(f"ARTIFACT_INVALID:{exc}")
    return hashes


def _population(bundle: Mapping[str, Any], failures: list[str]) -> dict[str, Mapping[str, Any]]:
    rows_value = bundle.get("population")
    if not isinstance(rows_value, Sequence) or isinstance(rows_value, (str, bytes)):
        failures.append("POPULATION_16_INVALID:rows missing")
        return {}
    rows: dict[str, Mapping[str, Any]] = {}
    source_families: set[str] = set()
    lineage_blocks: set[str] = set()
    for index, value in enumerate(rows_value):
        try:
            row = _mapping(value, f"population[{index}]")
            slot = _string(row.get("slot_id"), f"population[{index}].slot_id")
            if slot in rows:
                raise VerificationError(f"duplicate slot {slot}")
            expected_order = _POPULATION_SLOTS.index(slot) + 1
            if row.get("role") != _SLOT_ROLES[slot] or row.get("upload_order") != expected_order:
                raise VerificationError(f"slot {slot} role or upload_order is not frozen")
            _sha(row.get("archive_sha256"), f"population[{index}].archive_sha256")
            source = _string(row.get("source_family_id"), f"population[{index}].source_family_id")
            lineage = _string(row.get("lineage_time_block_id"), f"population[{index}].lineage_time_block_id")
            _string(row.get("intervention_family_id"), f"population[{index}].intervention_family_id")
            if row.get("production_eligibility_flag") is not False:
                raise VerificationError(f"slot {slot} is production eligible")
            _string(row.get("production_ineligibility_reason"), f"population[{index}].production_ineligibility_reason")
            for field in _CUSTODY_FIELDS:
                _sha(row.get(field), f"population[{index}].{field}")
            if source in source_families or lineage in lineage_blocks:
                raise VerificationError("source family or lineage-time block is not unique")
            source_families.add(source)
            lineage_blocks.add(lineage)
            rows[slot] = row
        except (VerificationError, ValueError) as exc:
            failures.append(f"POPULATION_16_INVALID:{exc}")
    if set(rows) != set(_POPULATION_SLOTS):
        failures.append("POPULATION_16_INVALID:requires exactly D01-D06,DR01,C01-C08,CR01")
    return rows


def _expected_next_slot(ledger: Mapping[str, Any], failures: list[str]) -> str | None:
    consumed = ledger.get("consumed_slot_ids", [])
    if not isinstance(consumed, list) or any(not isinstance(slot, str) for slot in consumed):
        failures.append("LEDGER_INVALID:consumed_slot_ids")
        return None
    if len(set(consumed)) != len(consumed) or any(slot not in _POPULATION_SLOTS for slot in consumed):
        failures.append("LEDGER_INVALID:consumed slots")
        return None
    failures_value = ledger.get("pre_maturity_technical_failures", [])
    if not isinstance(failures_value, list):
        failures.append("LEDGER_INVALID:pre_maturity_technical_failures")
        return None
    failed: set[str] = set()
    for item in failures_value:
        if not isinstance(item, Mapping) or item.get("technical_pre_maturity") is not True:
            failures.append("LEDGER_INVALID:reserve activation is not a pre-maturity technical failure")
            return None
        slot = item.get("slot_id")
        if not isinstance(slot, str) or slot not in consumed or slot not in set(_POPULATION_SLOTS):
            failures.append("LEDGER_INVALID:failure slot")
            return None
        failed.add(slot)
    dev_failures = [slot for slot in failed if slot.startswith("D") and slot != "DR01"]
    confirm_failures = [slot for slot in failed if slot.startswith("C") and slot != "CR01"]
    if len(dev_failures) > 1 or len(confirm_failures) > 1:
        failures.append("LEDGER_INVALID:more than one reserve activation in a tranche")
        return None
    schedule = [*(f"D{index:02d}" for index in range(1, 7))]
    if dev_failures:
        schedule.append("DR01")
    schedule.extend(f"C{index:02d}" for index in range(1, 9))
    if confirm_failures:
        schedule.append("CR01")
    if consumed != schedule[: len(consumed)]:
        failures.append("LEDGER_INVALID:consumed slots are not the frozen order")
        return None
    return schedule[len(consumed)] if len(consumed) < len(schedule) else None


def _ledgers(bundle: Mapping[str, Any], failures: list[str]) -> tuple[Mapping[str, Any] | None, str | None]:
    value = bundle.get("ledgers")
    try:
        ledgers = _mapping(value, "ledgers")
        calibration = _mapping(ledgers.get("calibration"), "calibration ledger")
        production = _mapping(ledgers.get("production"), "production ledger")
        if calibration.get("ledger_domain") != "calibration" or production.get("ledger_domain") != "production":
            raise VerificationError("ledger domains are conflated")
        calibration_id = _string(calibration.get("ledger_id"), "calibration.ledger_id")
        production_id = _string(production.get("ledger_id"), "production.ledger_id")
        if calibration_id == production_id:
            raise VerificationError("calibration and production ledger IDs overlap")
        if calibration.get("maximum_uploads") != 16 or production.get("maximum_uploads") != 1:
            raise VerificationError("budget maxima must be calibration=16 and production=1")
        if production.get("remaining") != 1 or production.get("consumed_slot_ids", []) != []:
            raise VerificationError("production budget must remain exclusively reserved")
        consumed = calibration.get("consumed_slot_ids", [])
        if not isinstance(consumed, list) or calibration.get("remaining") != 16 - len(consumed):
            raise VerificationError("calibration remaining budget does not match consumed slots")
        if not isinstance(calibration.get("remaining"), int) or calibration["remaining"] <= 0:
            raise VerificationError("calibration budget is exhausted")
        if set(consumed) & set(production.get("consumed_slot_ids", [])):
            raise VerificationError("ledger consumption overlaps")
        return calibration, _expected_next_slot(calibration, failures)
    except VerificationError as exc:
        failures.append(f"LEDGER_DISJOINT_INVALID:{exc}")
        return None, None


def _receipts(
    bundle: Mapping[str, Any],
    *,
    campaign_id: str,
    prereg_root_sha256: str,
    row: Mapping[str, Any] | None,
    failures: list[str],
) -> None:
    values = bundle.get("receipts")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        failures.append("RECEIPTS_MISSING")
        return
    seen: set[str] = set()
    for index, value in enumerate(values):
        try:
            receipt = _mapping(value, f"receipts[{index}]")
            kind = _string(receipt.get("kind"), f"receipts[{index}].kind")
            if kind not in REQUIRED_RECEIPTS:
                raise VerificationError(f"unknown receipt {kind}")
            if kind in seen:
                raise VerificationError(f"duplicate receipt {kind}")
            seen.add(kind)
            if receipt.get("status") != "PASS":
                raise VerificationError(f"{kind} is not an exact PASS receipt")
            if receipt.get("campaign_id") != campaign_id or receipt.get("prereg_root_sha256") != prereg_root_sha256:
                raise VerificationError(f"{kind} campaign/root binding mismatch")
            if row is None or receipt.get("slot_id") != row.get("slot_id") or receipt.get("archive_sha256") != row.get("archive_sha256"):
                raise VerificationError(f"{kind} next unit binding mismatch")
            receipt_hash = _sha(receipt.get("receipt_sha256"), f"{kind}.receipt_sha256")
            payload = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
            if canonical_sha256(payload) != receipt_hash:
                raise VerificationError(f"{kind} receipt hash mismatch")
            if kind == "CUSTODY_PASS":
                for field in _CUSTODY_FIELDS:
                    if receipt.get(field) != row.get(field):
                        raise VerificationError(f"CUSTODY_PASS {field} mismatch")
        except VerificationError as exc:
            failures.append(f"RECEIPT_INVALID:{exc}")
    absent = sorted(set(REQUIRED_RECEIPTS) - seen)
    if absent:
        failures.append("RECEIPTS_MISSING:" + ",".join(absent))


def verify_preupload_bundle(bundle: Mapping[str, Any], *, root: Path | str = ".") -> dict[str, Any]:
    """Verify one frozen calibration upload request without modifying any input.

    Invalid input is represented in a deterministic blocked verdict rather than
    by an exception, making this suitable for a pre-upload command-line gate.
    """

    failures: list[str] = ["V6_2_1_RETIRED_UNBOUND_SCHEMA"] if AUTHORIZATION_SCHEMA_RETIRED else []
    try:
        bundle = _mapping(bundle, "bundle")
        if bundle.get("schema") != BUNDLE_SCHEMA:
            raise VerificationError("unrecognized bundle schema")
        root_path = Path(root)
        if root_path.is_symlink() or not root_path.is_dir():
            raise VerificationError("root must be a non-symlink directory")
        campaign = _mapping(bundle.get("campaign"), "campaign")
        campaign_id = _string(campaign.get("campaign_id"), "campaign.campaign_id")
        artifact_hashes = _artifact_hashes(bundle, root_path, failures)
        prereg = _mapping(bundle.get("prereg_root"), "prereg_root")
        prereg_hash = _sha(prereg.get("merkle_root_sha256"), "prereg_root.merkle_root_sha256")
        if prereg.get("campaign_id") != campaign_id or prereg.get("published") is not True:
            failures.append("PREREG_ROOT_INVALID:campaign or publication")
        expected_artifact_hashes = {name: artifact_hashes.get(name) for name in REQUIRED_ARTIFACTS if name != "prereg_root.json"}
        if None in expected_artifact_hashes.values() or prereg.get("artifact_sha256s") != expected_artifact_hashes:
            failures.append("PREREG_ROOT_INVALID:artifact hash map")
        elif prereg_hash != preregistration_root(campaign_id, expected_artifact_hashes):
            failures.append("PREREG_ROOT_INVALID:root hash mismatch")
        if campaign.get("prereg_root_sha256") != prereg_hash:
            failures.append("CAMPAIGN_INVALID:prereg root mismatch")
        rows = _population(bundle, failures)
        calibration, next_slot = _ledgers(bundle, failures)
        executor = _mapping(bundle.get("executor"), "executor")
        if executor.get("active_unit") is not None:
            failures.append("EXECUTOR_INVALID:active unit exists")
        lock = _mapping(executor.get("project_upload_lock"), "executor.project_upload_lock")
        if lock.get("exclusive") is not True or lock.get("held") is not False:
            failures.append("EXECUTOR_INVALID:upload lock is not exclusively ready")
        quota = _mapping(bundle.get("quota"), "quota")
        own_uploads = quota.get("own_uploads_today")
        if not isinstance(own_uploads, int) or isinstance(own_uploads, bool) or own_uploads < 0 or own_uploads > 3:
            failures.append("QUOTA_INVALID:own_uploads_today must be <= 3")
        next_unit = _mapping(bundle.get("next_unit"), "next_unit")
        row = rows.get(next_slot) if next_slot is not None else None
        if row is None:
            failures.append("NEXT_UNIT_INVALID:no next frozen calibration slot")
        else:
            expected = {key: row[key] for key in ("slot_id", "archive_sha256", "role", "upload_order")}
            if any(next_unit.get(key) != value for key, value in expected.items()):
                failures.append("NEXT_UNIT_INVALID:slot/archive/role/order mismatch")
            try:
                archive = _safe_regular_file(root_path, next_unit.get("archive_path"), "next_unit.archive_path")
                if hashlib.sha256(archive.read_bytes()).hexdigest() != row["archive_sha256"]:
                    failures.append("NEXT_UNIT_INVALID:archive hash mismatch")
            except VerificationError as exc:
                failures.append(f"NEXT_UNIT_INVALID:{exc}")
        _receipts(bundle, campaign_id=campaign_id, prereg_root_sha256=prereg_hash, row=row, failures=failures)
    except VerificationError as exc:
        failures.append(f"BUNDLE_INVALID:{exc}")
        campaign_id = ""
        prereg_hash = ""
        row = None
        calibration = None

    failures = sorted(set(failures))
    authorized = not failures and row is not None and calibration is not None
    permit: dict[str, Any] | None = None
    if authorized:
        permit_payload = {
            "schema": "evaluation_v6_2_1_unit_upload_permit_v1",
            "campaign_id": campaign_id,
            "prereg_root_sha256": prereg_hash,
            "slot_id": row["slot_id"],
            "archive_sha256": row["archive_sha256"],
            "role": row["role"],
            "upload_order": row["upload_order"],
        }
        permit = {**permit_payload, "permit_sha256": canonical_sha256(permit_payload)}
    return {
        "schema": VERDICT_SCHEMA,
        "status": "CALIBRATION_UPLOAD_AUTHORIZED" if authorized else "CALIBRATION_UPLOAD_BLOCKED",
        "calibration_upload_authorized": authorized,
        "unit_upload_permits": [permit] if permit is not None else [],
        "failure_codes": failures,
        "observed_calibration_budget_remaining": calibration.get("remaining") if calibration else None,
        "production_upload_authorized": False,
        "production_budget_altered": False,
    }


def verify_preupload_bundle_file(bundle_path: Path | str, *, root: Path | str | None = None) -> dict[str, Any]:
    """Load a canonical JSON bundle and return its read-only verification verdict."""

    path = Path(bundle_path)
    try:
        if path.is_symlink() or not path.is_file():
            raise VerificationError("bundle must be a regular file")
        raw, bundle = _canonical_file(path, "bundle")
        del raw
        bundle = _mapping(bundle, "bundle")
    except VerificationError as exc:
        return {
            "schema": VERDICT_SCHEMA,
            "status": "CALIBRATION_UPLOAD_BLOCKED",
            "calibration_upload_authorized": False,
            "unit_upload_permits": [],
            "failure_codes": [f"BUNDLE_INVALID:{exc}"],
            "observed_calibration_budget_remaining": None,
            "production_upload_authorized": False,
            "production_budget_altered": False,
        }
    return verify_preupload_bundle(bundle, root=path.parent if root is None else root)


__all__ = [
    "AUTHORIZATION_SCHEMA_RETIRED",
    "BUNDLE_SCHEMA",
    "REQUIRED_ARTIFACTS",
    "REQUIRED_RECEIPTS",
    "VERDICT_SCHEMA",
    "VerificationError",
    "canonical_json_bytes",
    "canonical_sha256",
    "preregistration_root",
    "verify_preupload_bundle",
    "verify_preupload_bundle_file",
]
