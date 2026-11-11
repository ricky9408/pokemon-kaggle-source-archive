"""Compose a raw-evidence v4 whole-policy selector validation receipt."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .chronology import build_literal_horizon
from .evidence import load_registration, sha256_file, verify_kaggle_submission_anchor
from .metrics import evaluate_selector_checks, score_whole_policy
from .protocol import canonical_sha256, validate_manifest, validate_protocol


SOURCES_SCHEMA = "whole_policy_calibration_sources_v1"
_SOURCE_FIELDS = {
    "schema",
    "protocol_sha256",
    "lineage_manifest_sha256",
    "submissions_csv_path",
    "submissions_csv_sha256",
    "units",
}
_UNIT_SOURCE_FIELDS = {
    "registration_path",
    "registration_sha256",
    "archive_path",
    "archive_sha256",
    "submission_dir",
}


@dataclass(frozen=True)
class SelectorCheck:
    name: str
    passed: bool
    detail: str


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _resolve(owner: Path, value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} is required")
    path = Path(value)
    return path if path.is_absolute() else owner.parent / path


def _protocol_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def evaluate_selector_packet(
    *,
    protocol_path: Path,
    lineage_manifest_path: Path,
    sources_path: Path,
) -> dict[str, Any]:
    """Recompute selector evidence from externally anchored raw unit sources."""

    checks: list[SelectorCheck] = []
    try:
        protocol = validate_protocol(_load_json(protocol_path))
        protocol_sha256 = canonical_sha256(protocol)
        checks.append(SelectorCheck("frozen_protocol", True, protocol["protocol_id"]))
    except (OSError, TypeError, ValueError) as exc:
        protocol = None
        protocol_sha256 = None
        checks.append(SelectorCheck("frozen_protocol", False, str(exc)))

    try:
        manifest_raw = _load_json(lineage_manifest_path)
        if protocol is None:
            raise ValueError("valid frozen protocol required")
        manifest = validate_manifest(manifest_raw, protocol)
        manifest_sha256 = sha256_file(lineage_manifest_path)
        checks.append(SelectorCheck("lineage_manifest", True, manifest["content_sha256"]))
    except (OSError, TypeError, ValueError) as exc:
        manifest = None
        manifest_sha256 = None
        checks.append(SelectorCheck("lineage_manifest", False, str(exc)))

    try:
        sources = _load_json(sources_path)
        if set(sources) != _SOURCE_FIELDS or sources.get("schema") != SOURCES_SCHEMA:
            raise ValueError(f"sources fields/schema must exactly match {sorted(_SOURCE_FIELDS)}")
        if protocol_sha256 is None or sources["protocol_sha256"] != protocol_sha256:
            raise ValueError("sources protocol_sha256 mismatch")
        if manifest_sha256 is None or sources["lineage_manifest_sha256"] != manifest_sha256:
            raise ValueError("sources lineage_manifest_sha256 mismatch")
        submissions_csv = _resolve(sources_path, sources["submissions_csv_path"], label="submissions_csv_path")
        if sha256_file(submissions_csv) != sources["submissions_csv_sha256"]:
            raise ValueError("submissions CSV hash mismatch")
        units = sources["units"]
        if not isinstance(units, list) or not units:
            raise ValueError("sources units must be a non-empty list")
        checks.append(SelectorCheck("source_manifest", True, f"units={len(units)}"))
    except (OSError, TypeError, ValueError, KeyError) as exc:
        sources = None
        submissions_csv = None
        units = []
        checks.append(SelectorCheck("source_manifest", False, str(exc)))

    lineage_index = {
        row["lineage_id"]: row
        for row in (manifest.get("records", []) if isinstance(manifest, dict) else [])
    }
    metric_rows: list[dict[str, Any]] = []
    unit_receipts: list[dict[str, Any]] = []
    if protocol is not None and sources is not None and submissions_csv is not None:
        for position, source in enumerate(units):
            try:
                if not isinstance(source, dict) or set(source) != _UNIT_SOURCE_FIELDS:
                    raise ValueError(f"unit source fields must exactly be {sorted(_UNIT_SOURCE_FIELDS)}")
                registration_path = _resolve(sources_path, source["registration_path"], label="registration_path")
                if sha256_file(registration_path) != source["registration_sha256"]:
                    raise ValueError("registration hash mismatch")
                registration = load_registration(registration_path)
                if registration.protocol_sha256 != protocol_sha256:
                    raise ValueError("registration protocol_sha256 mismatch")
                if registration.lineage_manifest_sha256 != manifest_sha256:
                    raise ValueError("registration lineage_manifest_sha256 mismatch")
                if registration.selector_code_sha256 != protocol["selector_code_sha256"]:
                    raise ValueError("registration selector_code_sha256 mismatch")
                if registration.frozen_at < _protocol_time(protocol["frozen_at_utc"]):
                    raise ValueError("registration predates frozen protocol")
                archive_path = _resolve(sources_path, source["archive_path"], label="archive_path")
                archive_hash = sha256_file(archive_path)
                if archive_hash != source["archive_sha256"] or archive_hash != registration.archive_sha256:
                    raise ValueError("local archive identity mismatch")
                if archive_path.name != registration.archive_name:
                    raise ValueError("local archive name mismatch")
                lineage = lineage_index.get(registration.lineage_id)
                if lineage is None:
                    raise ValueError("registration lineage absent from manifest")
                for field in ("archive_sha256", "lineage_id", "ancestry_id", "family_id"):
                    if getattr(registration, field) != lineage[field]:
                        raise ValueError(f"registration {field} does not match lineage manifest")
                if lineage["split"] != "local_test":
                    raise ValueError("calibration unit is not in the frozen local_test split")
                anchor = verify_kaggle_submission_anchor(registration_path, submissions_csv)
                submission_dir = _resolve(sources_path, source["submission_dir"], label="submission_dir")
                horizon = build_literal_horizon(registration, anchor, submission_dir)
                metric_rows.append(
                    {
                        "unit_id": registration.unit_id,
                        "lineage_id": registration.lineage_id,
                        "ancestry_id": registration.ancestry_id,
                        "family_id": registration.family_id,
                        "block_id": registration.block_id,
                        "outcomes": horizon["outcomes"],
                        "nuisance_probability": registration.nuisance_probability,
                        "selector_probability": registration.selector_probability,
                        "simulator_delta": registration.simulator_delta,
                        "ood_mass": registration.ood_mass,
                        "engine_variant_means": registration.engine_variant_means,
                    }
                )
                unit_receipts.append(
                    {
                        "unit_id": registration.unit_id,
                        "registration_sha256": source["registration_sha256"],
                        "submission_ref": anchor["submission_ref"],
                        "anchor_scope": anchor["scope"],
                        "archive_bytes_server_verified": anchor["archive_bytes_server_verified"],
                        "setup_game_ids": horizon["setup_game_ids"],
                        "followup_game_ids": [game["game_id"] for game in horizon["followup_games"]],
                        "episodes_csv_sha256": horizon["episodes_csv_sha256"],
                    }
                )
                checks.append(SelectorCheck(f"unit_{position:03d}", True, registration.unit_id))
            except (OSError, TypeError, ValueError, KeyError) as exc:
                checks.append(SelectorCheck(f"unit_{position:03d}", False, str(exc)))

    expected_local_test = {
        row["lineage_id"]
        for row in (manifest.get("records", []) if isinstance(manifest, dict) else [])
        if row.get("split") == "local_test"
    }
    observed_lineages = {row["lineage_id"] for row in metric_rows}
    checks.append(
        SelectorCheck(
            "complete_local_test_roster",
            bool(expected_local_test) and observed_lineages == expected_local_test,
            f"expected={len(expected_local_test)} observed={len(observed_lineages)}",
        )
    )

    metrics_artifact: dict[str, Any] | None = None
    metric_checks: dict[str, bool] = {}
    if metric_rows and protocol is not None and all(check.passed for check in checks):
        try:
            metrics_artifact = score_whole_policy(
                metric_rows,
                seed=protocol["seed"],
                bootstrap_samples=protocol["bootstrap_samples"],
            )
            metric_checks = evaluate_selector_checks(
                metrics_artifact,
                thresholds=protocol["thresholds"],
                minimums=protocol["minimums"],
            )
            checks.extend(
                SelectorCheck(f"metric_{name}", passed, "frozen conjunctive threshold")
                for name, passed in metric_checks.items()
            )
        except (TypeError, ValueError) as exc:
            checks.append(SelectorCheck("selector_metrics", False, str(exc)))

    # Registration currently commits cached p0/p1 and simulator summaries, but
    # this composer does not yet recompute them from a frozen predictor and raw
    # simulation design.  Treating those caller-provided values as model output
    # would recreate the injected-probability bug closed in v3.  Keep the path
    # explicitly closed until the recomputation artifacts are wired in.
    prediction_recomputation_complete = False
    checks.append(
        SelectorCheck(
            "frozen_prediction_recomputation",
            False,
            "registered probabilities are not yet recomputed from frozen raw artifacts",
        )
    )

    selector_validated = bool(metric_checks) and all(check.passed for check in checks)
    return {
        "schema": "whole_policy_selector_validation_v1",
        "protocol_sha256": protocol_sha256,
        "lineage_manifest_sha256": manifest_sha256,
        "sources_sha256": sha256_file(sources_path) if sources_path.is_file() else None,
        "checks": [asdict(check) for check in checks],
        "selector_validated": selector_validated,
        "metrics": metrics_artifact,
        "unit_receipts": unit_receipts,
        "prediction_recomputation_complete": prediction_recomputation_complete,
        "submission_authority": "NONE",
        "first_submission_authorized": False,
        "decision": "SELECTOR_VALIDATED_RESEARCH_ONLY" if selector_validated else "CLOSED",
        "sealed_holdout_accessed": False,
    }


def write_selector_receipt_once(path: Path, receipt: Mapping[str, Any]) -> None:
    if receipt.get("schema") != "whole_policy_selector_validation_v1":
        raise ValueError("selector receipt schema mismatch")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(receipt, indent=2, sort_keys=True))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


__all__ = ["evaluate_selector_packet", "write_selector_receipt_once"]
