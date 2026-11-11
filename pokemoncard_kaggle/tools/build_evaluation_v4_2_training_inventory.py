#!/usr/bin/env python3
"""Build a conservative mature-outcome inventory and training-support audit."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v4.lineage import inspect_archive
from evaluation_v4_2.training_support import (
    MANIFEST_SCHEMA,
    audit_training_support,
    build_training_manifest,
    canonical_json_bytes,
)


_BURNED_VERSION_TOKENS = ("v141", "v149", "v150", "v151", "v152", "v155", "v156", "v159", "v161")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_once(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(canonical_json_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise FileExistsError(f"artifact already exists: {path}") from None


def _burned_artifacts(repo: Path) -> list[str]:
    paths = [
        repo / "evaluation_artifacts/public_transfer/panel_postshift_v1.json",
        repo / "evaluation_artifacts/public_transfer/panel_postshift_runtime_eligible_v1.json",
        repo / "evaluation_artifacts/public_transfer/validation_v1.json",
        repo / "evaluation_artifacts/whole_policy_v4/retired_v4_files.sha256",
    ]
    return sorted(_sha256_file(path) for path in paths if path.is_file())


def _rows(database: Path) -> list[sqlite3.Row]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(
            """
            SELECT s.ref, s.kaggle_filename, s.family, s.submit_ts,
                   o.finalized_ts, o.n_ticks, o.watched_seconds,
                   o.realized_public_median, o.verdict
            FROM submissions AS s
            JOIN outcomes AS o USING (ref)
            ORDER BY s.submit_ts, s.ref
            """
        ).fetchall()
    finally:
        connection.close()


def build_inventory(repo: Path, database: Path, cutoff: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    ledger_sha = _sha256_file(database)
    burned = _burned_artifacts(repo)
    records: list[dict[str, Any]] = []
    missing_archives: list[str] = []
    invalid_archives: list[str] = []
    for row in _rows(database):
        archive_path = repo / row["kaggle_filename"]
        if not archive_path.is_file():
            missing_archives.append(str(row["ref"]))
            continue
        try:
            identity = inspect_archive(archive_path)
        except ValueError:
            invalid_archives.append(str(row["ref"]))
            continue
        submitted = _parse_utc(row["submit_ts"])
        finalized = _parse_utc(row["finalized_ts"])
        if finalized > cutoff:
            continue
        source_hashes = {ledger_sha, identity["archive_sha256"]}
        if any(token in row["kaggle_filename"] for token in _BURNED_VERSION_TOKENS):
            source_hashes.update(burned)
        outcome_content = {
            "ref": str(row["ref"]),
            "finalized_at_utc": _canonical_utc(finalized),
            "n_ticks": int(row["n_ticks"]),
            "watched_seconds": float(row["watched_seconds"]),
            "realized_public_median": float(row["realized_public_median"]),
            "verdict": str(row["verdict"]),
            "ledger_sha256": ledger_sha,
        }
        records.append(
            {
                "unit_id": f"submission-{row['ref']}",
                "archive_sha256": identity["archive_sha256"],
                "ancestry_id": f"unverified-policy-{identity['policy_content_sha256']}",
                "family_id": str(row["family"]),
                "submitted_at_utc": _canonical_utc(submitted),
                "mature_window_start_utc": _canonical_utc(submitted + timedelta(hours=1)),
                "mature_window_end_utc": _canonical_utc(finalized),
                "outcome_artifact_sha256": hashlib.sha256(canonical_json_bytes(outcome_content)).hexdigest(),
                "simulation_feature_sha256": None,
                "source_artifact_sha256s": sorted(source_hashes),
                "mature_public_value": float(row["realized_public_median"]),
                "outcome_ticks": int(row["n_ticks"]),
                "watched_hours": float(row["watched_seconds"]) / 3600.0,
                "outcome_state": "MEASURED" if row["verdict"] == "measured" else "DRIFT",
                "provenance_state": "UNKNOWN",
                "simulation_feature_state": "MISSING",
                "sealed_holdout_accessed": False,
            }
        )
    records.sort(key=lambda item: (item["submitted_at_utc"], item["unit_id"]))
    manifest = build_training_manifest(
        {
            "schema": MANIFEST_SCHEMA,
            "manifest_id": "workspace-mature-outcomes-20260712",
            "cutoff_utc": _canonical_utc(cutoff),
            "burned_artifact_sha256s": burned,
            "validation_ancestry_ids": [],
            "sealed_holdout_id": "sealed-50-game-holdout",
            "records": records,
            "state": "FROZEN",
        }
    )
    inventory = {
        "schema": "evaluation_v4_2_training_inventory_receipt_v1",
        "ledger_sha256": ledger_sha,
        "cutoff_utc": _canonical_utc(cutoff),
        "records_in_manifest": len(records),
        "missing_archive_refs": sorted(missing_archives),
        "invalid_archive_refs": sorted(invalid_archives),
        "sealed_holdout_accessed": False,
    }
    return manifest, inventory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=ROOT / "outcomes/ledger.sqlite")
    parser.add_argument("--cutoff-utc", required=True)
    parser.add_argument("--manifest-output", type=Path, required=True)
    parser.add_argument("--audit-output", type=Path, required=True)
    parser.add_argument("--inventory-output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cutoff = _parse_utc(args.cutoff_utc)
    manifest, inventory = build_inventory(ROOT, args.ledger, cutoff)
    audit = audit_training_support(manifest)
    _write_once(args.manifest_output, manifest)
    _write_once(args.audit_output, audit)
    _write_once(args.inventory_output, inventory)
    print(f"records={len(manifest['records'])}")
    print(f"eligible_roots={audit['eligible_ancestry_roots']}")
    print(f"decision={audit['decision']}")
    print(f"missing_archives={len(inventory['missing_archive_refs'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
