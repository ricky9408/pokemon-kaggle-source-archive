from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v6_2.verifier import (
    BUNDLE_SCHEMA,
    REQUIRED_ARTIFACTS,
    REQUIRED_RECEIPTS,
    canonical_json_bytes,
    canonical_sha256,
    preregistration_root,
    verify_preupload_bundle,
    verify_preupload_bundle_file,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _write_json(root: Path, name: str, value: object) -> str:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_json_bytes(value)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _row(slot: str, order: int, role: str) -> dict[str, object]:
    return {
        "slot_id": slot,
        "archive_sha256": _hash(f"archive:{slot}"),
        "role": role,
        "upload_order": order,
        "source_family_id": f"source:{slot}",
        "lineage_time_block_id": f"lineage:{slot}",
        "intervention_family_id": f"intervention:{slot}",
        "production_eligibility_flag": False,
        "production_ineligibility_reason": "calibration-only preregistered unit",
        "source_tree_sha256": _hash(f"source-tree:{slot}"),
        "build_container_sha256": _hash(f"build:{slot}"),
        "linux_amd64_sha256": _hash(f"linux:{slot}"),
        "source_archive_equality_sha256": _hash(f"equality:{slot}"),
        "safety_smoke_sha256": _hash(f"safety:{slot}"),
    }


def _bundle(root: Path) -> dict[str, object]:
    slots = [*(f"D{n:02d}" for n in range(1, 7)), "DR01", *(f"C{n:02d}" for n in range(1, 9)), "CR01"]
    roles = [*("DEV_PRIMARY" for _ in range(6)), "DEV_RESERVE", *("CONFIRM_PRIMARY" for _ in range(8)), "CONFIRM_RESERVE"]
    population = [_row(slot, index, role) for index, (slot, role) in enumerate(zip(slots, roles), 1)]
    archive = root / "archives" / "D01.tar.gz"
    archive.parent.mkdir()
    archive.write_bytes(b"D01 archive")
    population[0]["archive_sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    artifact_hashes = {
        name: _write_json(root, name, {"name": name, "version": 1})
        for name in REQUIRED_ARTIFACTS
        if name != "population_manifest.jsonl" and name != "prereg_root.json"
    }
    manifest = root / "population_manifest.jsonl"
    manifest.write_bytes(b"\n".join(canonical_json_bytes(row) for row in population) + b"\n")
    artifact_hashes["population_manifest.jsonl"] = hashlib.sha256(manifest.read_bytes()).hexdigest()
    campaign_id = "calibration-20260716"
    root_hashes = {name: artifact_hashes[name] for name in artifact_hashes}
    prereg = {
        "campaign_id": campaign_id,
        "published": True,
        "artifact_sha256s": root_hashes,
        "merkle_root_sha256": preregistration_root(campaign_id, root_hashes),
    }
    artifact_hashes["prereg_root.json"] = _write_json(root, "prereg_root.json", prereg)
    artifacts = [{"name": name, "path": name, "sha256": artifact_hashes[name]} for name in REQUIRED_ARTIFACTS]
    next_unit = {key: population[0][key] for key in ("slot_id", "archive_sha256", "role", "upload_order")}
    next_unit["archive_path"] = "archives/D01.tar.gz"
    receipts = []
    for kind in REQUIRED_RECEIPTS:
        receipt: dict[str, object] = {
            "kind": kind,
            "status": "PASS",
            "campaign_id": campaign_id,
            "prereg_root_sha256": prereg["merkle_root_sha256"],
            "slot_id": "D01",
            "archive_sha256": population[0]["archive_sha256"],
        }
        if kind == "CUSTODY_PASS":
            receipt.update({field: population[0][field] for field in (
                "source_tree_sha256", "build_container_sha256", "linux_amd64_sha256", "source_archive_equality_sha256", "safety_smoke_sha256"
            )})
        receipt["receipt_sha256"] = canonical_sha256(receipt)
        receipts.append(receipt)
    return {
        "schema": BUNDLE_SCHEMA,
        "campaign": {"campaign_id": campaign_id, "prereg_root_sha256": prereg["merkle_root_sha256"]},
        "artifacts": artifacts,
        "prereg_root": prereg,
        "population": population,
        "ledgers": {
            "calibration": {"ledger_domain": "calibration", "ledger_id": "cal-1", "maximum_uploads": 16, "remaining": 16, "consumed_slot_ids": [], "pre_maturity_technical_failures": []},
            "production": {"ledger_domain": "production", "ledger_id": "prod-1", "maximum_uploads": 1, "remaining": 1, "consumed_slot_ids": []},
        },
        "executor": {"active_unit": None, "project_upload_lock": {"exclusive": True, "held": False}},
        "quota": {"own_uploads_today": 0},
        "next_unit": next_unit,
        "receipts": receipts,
    }


def _refresh_receipt(receipt: dict[str, object]) -> None:
    receipt["receipt_sha256"] = canonical_sha256({k: v for k, v in receipt.items() if k != "receipt_sha256"})


def test_retired_unbound_schema_never_emits_a_calibration_permit(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    before = deepcopy(bundle["ledgers"])
    verdict = verify_preupload_bundle(bundle, root=tmp_path)
    assert verdict["status"] == "CALIBRATION_UPLOAD_BLOCKED"
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []
    assert "V6_2_1_RETIRED_UNBOUND_SCHEMA" in verdict["failure_codes"]
    assert verdict["production_upload_authorized"] is False
    assert bundle["ledgers"] == before


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "mismatch"])
def test_receipts_fail_closed(tmp_path: Path, mutation: str) -> None:
    bundle = _bundle(tmp_path)
    receipts = bundle["receipts"]
    assert isinstance(receipts, list)
    if mutation == "missing":
        receipts.pop()
    elif mutation == "duplicate":
        receipts.append(deepcopy(receipts[0]))
    else:
        receipts[0]["archive_sha256"] = _hash("wrong")
        _refresh_receipt(receipts[0])
    verdict = verify_preupload_bundle(bundle, root=tmp_path)
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []


def test_hash_swap_and_wrong_next_order_fail(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    bundle["campaign"]["prereg_root_sha256"] = _hash("swapped-root")
    bundle["next_unit"]["upload_order"] = 2
    verdict = verify_preupload_bundle(bundle, root=tmp_path)
    assert verdict["status"] == "CALIBRATION_UPLOAD_BLOCKED"
    assert any("prereg root mismatch" in code or "NEXT_UNIT_INVALID" in code for code in verdict["failure_codes"])


@pytest.mark.parametrize("change", ["exhausted", "active", "quota", "conflated"])
def test_budget_executor_quota_and_ledger_guards(tmp_path: Path, change: str) -> None:
    bundle = _bundle(tmp_path)
    if change == "exhausted":
        bundle["ledgers"]["calibration"]["remaining"] = 0
    elif change == "active":
        bundle["executor"]["active_unit"] = "D01"
    elif change == "quota":
        bundle["quota"]["own_uploads_today"] = 4
    else:
        bundle["ledgers"]["production"]["ledger_id"] = "cal-1"
    verdict = verify_preupload_bundle(bundle, root=tmp_path)
    assert verdict["calibration_upload_authorized"] is False
    assert verdict["unit_upload_permits"] == []


@pytest.mark.parametrize("attack", ["symlink", "holdout"])
def test_path_attacks_fail_closed(tmp_path: Path, attack: str) -> None:
    bundle = _bundle(tmp_path)
    if attack == "symlink":
        target = tmp_path / "protocol_v6_2_1.json"
        link = tmp_path / "linked.json"
        link.symlink_to(target)
        bundle["artifacts"][0]["path"] = "linked.json"
    else:
        bundle["next_unit"]["archive_path"] = "sealed_holdout/D01.tar.gz"
    verdict = verify_preupload_bundle(bundle, root=tmp_path)
    assert verdict["calibration_upload_authorized"] is False


def test_file_cli_input_requires_canonical_bundle(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(canonical_json_bytes(bundle))
    assert verify_preupload_bundle_file(bundle_path)["calibration_upload_authorized"] is False
    bundle_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    assert verify_preupload_bundle_file(bundle_path)["calibration_upload_authorized"] is False
