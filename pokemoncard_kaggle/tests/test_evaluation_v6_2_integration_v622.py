from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from evaluation_v6_2.integration_v622 import (
    ATTESTATION_SCHEMA,
    FEATURE_NAMES,
    FEATURE_RECORD_SCHEMA,
    FEATURE_SCHEMA_ID,
    IntegrationError,
    POPULATION_RECORD_SCHEMA,
    PREREG_ROOT_SCHEMA,
    REQUIRED_PREREG_FILES,
    assess_prereg_bundle,
    canonical_json_bytes,
    deterministic_submission_name,
    prereg_merkle,
    validate_prereg_bundle,
)


SLOTS = ("D01", "D02", "D03", "D04", "D05", "D06", "DR01", "C01", "C02", "C03", "C04", "C05", "C06", "C07", "C08", "CR01")


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _role(slot: str) -> tuple[str, int]:
    if slot.startswith("D") and slot != "DR01":
        return "DEV_PRIMARY", int(slot[1:])
    if slot == "DR01":
        return "DEV_RESERVE", 7
    if slot.startswith("C") and slot != "CR01":
        return "CONFIRM_PRIMARY", 7 + int(slot[1:])
    return "CONFIRM_RESERVE", 16


def _write_json(path: Path, value: object) -> bytes:
    raw = canonical_json_bytes(value)
    path.write_bytes(raw)
    return raw


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> list[bytes]:
    raw_rows = [canonical_json_bytes(row) for row in rows]
    path.write_bytes(b"".join(row + b"\n" for row in raw_rows))
    return raw_rows


def _bundle(tmp_path: Path) -> tuple[Path, Path]:
    bundle = tmp_path / "prereg_bundle"
    bundle.mkdir(parents=True)
    for name in REQUIRED_PREREG_FILES:
        if name.endswith(".jsonl"):
            continue
        _write_json(bundle / name, {"kind": name, "version": 1})

    feature_rows: list[dict[str, object]] = []
    for slot in SLOTS:
        feature_rows.append({
            "schema": FEATURE_RECORD_SCHEMA,
            "slot_id": slot,
            "feature_schema_id": FEATURE_SCHEMA_ID,
            "features": {name: "1.0" for name in FEATURE_NAMES},
        })
    feature_bytes = _write_jsonl(bundle / "features_manifest.jsonl", feature_rows)

    ancestry_rows: list[dict[str, object]] = []
    safety_rows: list[dict[str, object]] = []
    population_rows: list[dict[str, object]] = []
    for index, slot in enumerate(SLOTS):
        role, order = _role(slot)
        archive = {
            "archive_sha256": f"{index + 1:064x}",
            "package_sha256": _hash(f"package:{slot}"),
            "source_tree_sha256": _hash(f"source:{slot}"),
            "linux_amd64_build_sha256": _hash(f"linux:{slot}"),
            "build_recipe_sha256": _hash(f"recipe:{slot}"),
            "build_container_digest": "sha256:" + _hash(f"container:{slot}"),
        }
        for kind, subject in (
            ("ARCHIVE_SOURCE_EQUALITY", archive["source_tree_sha256"]),
            ("ANCESTRY", archive["source_tree_sha256"]),
            ("LINUX_REPRO", archive["linux_amd64_build_sha256"]),
        ):
            ancestry_rows.append({
                "schema": ATTESTATION_SCHEMA, "slot_id": slot, "archive_sha256": archive["archive_sha256"],
                "kind": kind, "subject_sha256": subject, "status": "PASS",
            })
        safety_rows.append({
            "schema": ATTESTATION_SCHEMA, "slot_id": slot, "archive_sha256": archive["archive_sha256"],
            "kind": "SAFETY", "subject_sha256": archive["archive_sha256"], "status": "PASS",
        })
        interventions = ("a", "b", "c", "d", "e", "f", "g", "a", "b", "c", "d", "e", "f", "g", "h", "i")
        population_rows.append({
            "schema": POPULATION_RECORD_SCHEMA, "slot_id": slot, "role": role, "slot_order": order,
            "archive": archive,
            "identity": {
                "agent_id": f"agent-{slot}", "lineage_time_block_id": f"lineage-{slot}",
                "source_family_id": f"source-{slot}", "intervention_family_id": interventions[index],
            },
            "attestations": {},
            "feature_binding": {
                "feature_record_sha256": hashlib.sha256(feature_bytes[index]).hexdigest(),
                "local_evidence_root_sha256": _hash(f"evidence:{slot}"), "feature_schema_id": FEATURE_SCHEMA_ID,
            },
            "base": {
                "base_candidate": slot in set(SLOTS[:6]),
                "base_ineligibility_code": None if slot in set(SLOTS[:6]) else "NOT_BASE_ROLE",
            },
        })
    ancestry_bytes = _write_jsonl(bundle / "ancestry_attestations.jsonl", ancestry_rows)
    safety_bytes = _write_jsonl(bundle / "safety_receipts.jsonl", safety_rows)
    for index, row in enumerate(population_rows):
        row["attestations"] = {
            "archive_source_equality_receipt_sha256": hashlib.sha256(ancestry_bytes[index * 3]).hexdigest(),
            "ancestry_attestation_sha256": hashlib.sha256(ancestry_bytes[index * 3 + 1]).hexdigest(),
            "linux_repro_receipt_sha256": hashlib.sha256(ancestry_bytes[index * 3 + 2]).hexdigest(),
            "safety_receipt_sha256": hashlib.sha256(safety_bytes[index]).hexdigest(),
        }
    _write_jsonl(bundle / "population_manifest.jsonl", population_rows)

    files = {name: (bundle / name).read_bytes() for name in REQUIRED_PREREG_FILES}
    root, leaves = prereg_merkle(files)
    receipt = tmp_path / "prereg_root_receipt.json"
    _write_json(receipt, {"schema": PREREG_ROOT_SCHEMA, "root_sha256": root, "files": leaves, "published_at_utc": "2026-07-16T07:43:17Z"})
    return bundle, receipt


def test_structural_bundle_is_non_authorizing_and_has_deterministic_names(tmp_path: Path) -> None:
    bundle, receipt = _bundle(tmp_path)
    first = validate_prereg_bundle(bundle, receipt)
    second = validate_prereg_bundle(bundle, receipt)
    assert first == second
    assert first["state"] == "STRUCTURAL_BUNDLE_VALID_REQUIRES_EXTERNAL_AUTHENTICATION"
    assert first["external_authentication_verified"] is False
    assert first["semantic_artifact_verification_complete"] is False
    assert first["population_feasible"] is False
    assert first["calibration_upload_authorized"] is False
    assert first["production_upload_authorized"] is False
    assert first["unit_upload_permits"] == []
    assert first["submission_names"]["D01"] == deterministic_submission_name(
        first["prereg_root_sha256"], "D01", f"{1:064x}"
    )


def test_canonical_profile_rejects_oversized_integers_and_impossible_timestamps(tmp_path: Path) -> None:
    with pytest.raises(IntegrationError, match="safe range"):
        canonical_json_bytes({"value": 9_007_199_254_740_992})

    bundle, receipt = _bundle(tmp_path)
    _write_json(
        receipt,
        {
            "schema": PREREG_ROOT_SCHEMA,
            "root_sha256": prereg_merkle(
                {name: (bundle / name).read_bytes() for name in REQUIRED_PREREG_FILES}
            )[0],
            "files": prereg_merkle(
                {name: (bundle / name).read_bytes() for name in REQUIRED_PREREG_FILES}
            )[1],
            "published_at_utc": "2026-99-99T99:99:99Z",
        },
    )
    with pytest.raises(IntegrationError, match="real UTC instant"):
        validate_prereg_bundle(bundle, receipt)


def test_extra_fields_and_noncanonical_framing_fail_closed(tmp_path: Path) -> None:
    bundle, receipt = _bundle(tmp_path)
    import json

    rows = [json.loads(line) for line in (bundle / "population_manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    rows[0]["extra"] = 1
    _write_jsonl(bundle / "population_manifest.jsonl", rows)
    with pytest.raises(IntegrationError, match="fields must exactly"):
        validate_prereg_bundle(bundle, receipt)

    bundle, receipt = _bundle(tmp_path / "second")
    raw = (bundle / "controls_manifest.json").read_bytes()
    (bundle / "controls_manifest.json").write_bytes(raw + b"\n")
    with pytest.raises(IntegrationError, match="framing"):
        validate_prereg_bundle(bundle, receipt)

    bundle, receipt = _bundle(tmp_path / "third")
    (bundle / "controls_manifest.json").write_bytes(b'{"kind":"controls_manifest.json","version":1.0}')
    with pytest.raises(IntegrationError, match="floating-point literal"):
        validate_prereg_bundle(bundle, receipt)


@pytest.mark.parametrize("field", ["archive_sha256", "source_family_id", "lineage_time_block_id"])
def test_population_identity_duplicates_are_rejected(tmp_path: Path, field: str) -> None:
    bundle, receipt = _bundle(tmp_path)
    import json

    rows = [json.loads(line) for line in (bundle / "population_manifest.jsonl").read_text().splitlines()]
    target = rows[1]["archive"] if field == "archive_sha256" else rows[1]["identity"]
    source = rows[0]["archive"] if field == "archive_sha256" else rows[0]["identity"]
    target[field] = source[field]
    _write_jsonl(bundle / "population_manifest.jsonl", rows)
    with pytest.raises(IntegrationError, match="pairwise distinct"):
        validate_prereg_bundle(bundle, receipt)


def test_reserve_diversity_and_confirm_support_are_enforced(tmp_path: Path) -> None:
    bundle, receipt = _bundle(tmp_path)
    import json

    rows = [json.loads(line) for line in (bundle / "population_manifest.jsonl").read_text().splitlines()]
    for index, intervention in enumerate(("a", "a", "a", "b", "b", "c", "a")):
        rows[index]["identity"]["intervention_family_id"] = intervention
    _write_jsonl(bundle / "population_manifest.jsonl", rows)
    with pytest.raises(IntegrationError, match="DEV intervention diversity"):
        validate_prereg_bundle(bundle, receipt)

    bundle, receipt = _bundle(tmp_path / "second")
    features = [json.loads(line) for line in (bundle / "features_manifest.jsonl").read_text().splitlines()]
    features[7]["features"][FEATURE_NAMES[0]] = "2.0"
    feature_bytes = _write_jsonl(bundle / "features_manifest.jsonl", features)
    population = [json.loads(line) for line in (bundle / "population_manifest.jsonl").read_text().splitlines()]
    population[7]["feature_binding"]["feature_record_sha256"] = hashlib.sha256(feature_bytes[7]).hexdigest()
    _write_jsonl(bundle / "population_manifest.jsonl", population)
    with pytest.raises(IntegrationError, match="outside DEV support"):
        validate_prereg_bundle(bundle, receipt)


def test_all_six_dev_primaries_are_the_exhaustive_base_set(tmp_path: Path) -> None:
    import json

    bundle, receipt = _bundle(tmp_path)
    rows = [json.loads(line) for line in (bundle / "population_manifest.jsonl").read_text().splitlines()]
    rows[5]["base"] = {"base_candidate": False, "base_ineligibility_code": "REMOVED"}
    _write_jsonl(bundle / "population_manifest.jsonl", rows)
    with pytest.raises(IntegrationError, match="all and only the six DEV primaries"):
        validate_prereg_bundle(bundle, receipt)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_bundle_requires_exact_file_set(tmp_path: Path, mutation: str) -> None:
    bundle, receipt = _bundle(tmp_path)
    if mutation == "missing":
        (bundle / "ledger_genesis.json").unlink()
    else:
        (bundle / "unrooted.json").write_bytes(b"{}")
    with pytest.raises(IntegrationError, match="required set"):
        validate_prereg_bundle(bundle, receipt)
