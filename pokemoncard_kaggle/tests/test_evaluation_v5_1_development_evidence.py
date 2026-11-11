from __future__ import annotations

import copy
import hashlib
import json
import runpy
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

import evaluation_v5_1.development_evidence as evidence
from evaluation_v5_1 import hosted_dev_custody, scenario_evidence as scenario
from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload


_HOSTED_TEST = runpy.run_path(str(Path(__file__).with_name("test_evaluation_v5_1_hosted_dev_custody.py")))
_HOSTED_FIXTURE = _HOSTED_TEST["_fixture"]
SCENARIO = "7" * 64
RUNTIME = "b" * 64
CONTAINER = "5" * 64
EXECUTABLE = "d" * 64
ANCHOR = "2026-01-01T00:00:00.000000Z"
CREATED = "2026-07-14T03:00:00.000000Z"


def _key() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signed(schema: str, payload: dict[str, object], private: Ed25519PrivateKey, public: bytes) -> dict[str, object]:
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _event(kind: str, payload: dict[str, object], previous: str, index: int) -> dict[str, object]:
    unsigned = {"event_type": kind, "event_index": index, "previous_event_sha256": previous, "payload": payload}
    return {**unsigned, "event_sha256": canonical_sha256(unsigned)}


def _engine(*, feasible: bool = True) -> dict[str, object]:
    return {
        "schema": evidence.ENGINE_CAPABILITY_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "decision": "LOCAL_FEATURE_EXTRACTION_FEASIBLE" if feasible else "NO_LOCAL_FEATURE_EXTRACTION",
        "local_feature_extraction": feasible,
        "feature_registry": list(evidence.FEATURE_REGISTRY),
        "engine_sha256": "4" * 64,
        "scenario_sha256": SCENARIO,
        "runtime_sha256": RUNTIME,
        "container_sha256": CONTAINER,
        "executable_sha256": EXECUTABLE,
    }


def _rich_source_receipt(trace: dict[str, object], index: int) -> dict[str, object]:
    """Create a natural local rollout while retaining the G05 trace package bindings."""
    game_id = trace["game_id"]
    previous_source = trace["source_trace_receipt"]
    assert type(previous_source) is dict
    lineage_id = previous_source["lineage_id"]
    plan = {
        "schema": scenario.SCENARIO_PLAN_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "candidate_archive_sha256": trace["canary_package_sha256"],
        "deck_sha256": f"{index + 1000:064x}",
        "policy_sha256": f"{index + 2000:064x}",
        "seed_commitment_sha256": trace["deterministic_seed_sha256"],
        "engine_bindings": {"pinned_source": {"engine_sha256": trace["source_engine_sha256"], "container_sha256": trace["source_container_sha256"]}},
        "opponent_packages": {"hosted-opponent": {"package_sha256": trace["opponent_package_sha256"], "family_id": "hosted", "lineage_id": f"opponent-lineage-{index}"}},
        "era_calendar": [{"era": "E0", "starts_at_utc": ANCHOR, "ends_at_utc": "2027-01-01T00:00:00.000000Z"}],
        "scheduled_terminal_categories": list(scenario.TERMINAL_CATEGORIES),
        "evidence_partition": "DEV",
        "cells": [{
            "cell_id": game_id,
            "template": scenario.NATURAL_TEMPLATE,
            "engine_id": "pinned_source",
            "opponent_package_id": "hosted-opponent",
            "state_constructor_sha256": f"{index + 3000:064x}",
            "seat": trace["canary_seat"],
            "seed_derivation": {"scheme": scenario.SEED_DERIVATION_SCHEME, "seed_index": index},
            "attempt_index": 0,
            "failure_rule": scenario.FAILURE_RULE,
            "aggregation_formula": scenario.AGGREGATION_FORMULA,
        }],
    }
    checked = scenario.validate_scenario_plan(plan)
    plan_hash = scenario.scenario_plan_sha256(checked)
    cell = checked["cells"][0]
    state = scenario._expected_state(checked, plan_hash, cell)
    state_hash = canonical_sha256(state)
    event_specs: list[tuple[str, dict[str, object]]] = [
        ("GAME_START", {}),
        ("TURN_START", {"owner": "self", "own_turn": 1}),
    ]
    for attachment in range(34):
        event_specs.append(("MANUAL_ENERGY_ATTACHED", {"pokemon_id": f"attacker-{attachment}", "pokemon_kind": "combatant"}))
    event_specs.extend([
        ("TURN_START", {"owner": "opponent", "own_turn": 1}),
        ("POKEMON_KO", {"owner": "self", "was_active": True}),
        ("FORCED_SWITCH", {"owner": "self"}),
        ("TURN_START", {"owner": "self", "own_turn": 2}),
    ])
    for attachment in range(34):
        event_specs.extend([
            ("ATTACK_DECLARED", {"attacker_id": f"attacker-{attachment}", "owner": "self"}),
            ("DAMAGE_APPLIED", {"attacker_id": f"attacker-{attachment}", "source_owner": "self", "amount": 20}),
        ])
    event_specs.extend([("PRIZE_TAKEN", {"owner": "self", "count": 2}), ("GAME_END", {"terminal_category": "completed"})])
    events = []
    previous = state_hash
    for event_index, (kind, payload) in enumerate(event_specs):
        event = _event(kind, payload, previous, event_index)
        events.append(event)
        previous = event["event_sha256"]
    trace_body = {
        "schema": "evaluation_v5_1_natural_game_trace_v2",
        "scenario_plan_sha256": plan_hash,
        "cell_id": cell["cell_id"],
        "state_blob_sha256": state_hash,
        "template": scenario.NATURAL_TEMPLATE,
        "events": events,
    }
    result = {
        "schema": "evaluation_v5_1_natural_game_result_v3",
        "scenario_plan_sha256": plan_hash,
        "cell_id": cell["cell_id"],
        "trace_blob_sha256": canonical_sha256(trace_body),
        "status": "OK",
        "created_at_utc": CREATED,
    }
    safety = {
        "schema": "evaluation_v5_1_natural_game_safety_v3",
        "scenario_plan_sha256": plan_hash,
        "cell_id": cell["cell_id"],
        "result_blob_sha256": canonical_sha256(result),
        "status": "SAFE",
    }
    return {
        "schema": scenario.SOURCE_TRACE_RECEIPT_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "scenario_sha256": SCENARIO,
        "game_id": game_id,
        "archive_id": trace["canary_archive_id"],
        "lineage_id": lineage_id,
        "scenario_plan": checked,
        "cell_id": cell["cell_id"],
        "state": state,
        "trace": trace_body,
        "result": result,
        "safety": safety,
    }


def _rebuild_g05(data: dict[str, object], keys: dict[str, tuple[Ed25519PrivateKey, bytes]], development_public_key: bytes) -> None:
    audit = hosted_dev_custody.derive_hosted_dev_custody_audit(
        role_keys=data["role_keys"],
        frozen_spec_envelope=data["frozen_spec_envelope"],
        spec_countersignature_envelope=data["spec_countersignature_envelope"],
        collector_c1_envelope=data["collector_c1_envelope"],
        collector_c2_envelope=data["collector_c2_envelope"],
        evidence_bundle_envelope=data["evidence_bundle_envelope"],
        trace_envelopes=data["trace_envelopes"],
        raw_blobs=data["raw_blobs"],
        development_public_key=development_public_key,
    )
    assert audit["decision"] == hosted_dev_custody.G05_DECISION, audit.get("reason")
    authority = _signed(hosted_dev_custody.G05_AUDIT_SCHEMA, audit, *keys["evaluation_authority"])
    countersignature = {
        "schema": hosted_dev_custody.G05_AUDIT_COUNTERSIGNATURE_SCHEMA,
        "protocol_id": hosted_dev_custody.G05_PROTOCOL,
        "authority_audit_envelope_sha256": canonical_sha256(authority),
    }
    data["final_audit_authority_envelope"] = authority
    data["final_audit_countersignature_envelope"] = _signed(
        hosted_dev_custody.G05_AUDIT_COUNTERSIGNATURE_SCHEMA,
        countersignature,
        *keys["validation_authority"],
    )


def _real_g05_inputs(development_public_key: bytes) -> tuple[dict[str, object], dict[str, tuple[Ed25519PrivateKey, bytes]], dict[str, object]]:
    data, keys = _HOSTED_FIXTURE(lineage_count=15, evaluation_id="dev-bridge-15", verifier_container_sha256="a" * 64)
    rebuilt = []
    for index, envelope in enumerate(data["trace_envelopes"]):
        payload = copy.deepcopy(envelope["payload"])
        source = _rich_source_receipt(payload, index)
        payload["source_trace_receipt"] = source
        payload["trace_root_sha256"] = scenario.derive_source_trace_receipt(source)["trace_root_sha256"]
        rebuilt.append(_signed(hosted_dev_custody.G05_TRACE_SCHEMA, payload, *keys["trace_attestor"]))
    data["trace_envelopes"] = rebuilt
    _rebuild_g05(data, keys, development_public_key)
    result = hosted_dev_custody.validate_hosted_dev_custody_result_receipt(
        **data,
        development_public_key=development_public_key,
    )
    assert result["decision"] == hosted_dev_custody.G05_DECISION, result.get("reason")
    assert len(result["rows"]) == 15
    assert all(set(row) == set(hosted_dev_custody.HOSTED_COLUMNS) for row in result["rows"])
    return data, keys, result


def _raw_record(model_id: str, game_id: str, index: int) -> dict[str, object]:
    return {
        "schema": evidence.RAW_COMPARATOR_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "model_id": model_id,
        "game_id": game_id,
        "raw_score": f"{((index * 3 + len(model_id)) % 101) / 100:.12f}",
    }


def _provenance_root(dataset: dict[str, object]) -> str:
    return canonical_sha256({
        "source_files": dataset["source_files"],
        "comparator_source_files": dataset["comparator_source_files"],
        "provenance_files": dataset["provenance_files"],
        "scenario_receipt_files": dataset["scenario_receipt_files"],
        "g05_result_sha256": dataset["g05_result_sha256"],
        "g05_row_merkle_root_sha256": dataset["g05_row_merkle_root_sha256"],
        "g05_trace_binding_root_sha256": dataset["g05_trace_binding_root_sha256"],
    })


def _fixture(tmp_path: Path, *, feasible: bool = True):
    root = tmp_path / "repo"
    root.mkdir()
    private, public = _key()
    hosted_inputs, hosted_keys, hosted_result = _real_g05_inputs(public)
    engine = _engine(feasible=feasible)
    engine_hash = canonical_sha256(engine)
    time_derivation = {
        "anchor_utc": ANCHOR,
        "game_day_origin": 1,
        "era_calendar": [{"era": "E0", "starts_at_utc": ANCHOR, "ends_at_utc": "2027-01-01T00:00:00.000000Z"}],
    }
    traces = {envelope["payload"]["game_id"]: envelope for envelope in hosted_inputs["trace_envelopes"]}
    rows = []
    scenario_entries = []
    for index, hosted in enumerate(hosted_result["rows"]):
        trace_envelope = traces[hosted["game_id"]]
        derived = scenario.derive_source_trace_receipt(trace_envelope["payload"]["source_trace_receipt"])
        row = {
            "schema": evidence.DEV_ROW_SCHEMA,
            "protocol_id": evidence.PROTOCOL_ID,
            "partition": evidence.DEV_BURNED,
            "competition_id": hosted["competition_id"],
            "game_id": hosted["game_id"],
            "canary_archive_id": hosted["canary_archive_id"],
            "canary_lineage_id": hosted["canary_lineage_id"],
            "scenario_receipt_sha256": "0" * 64,
            "features": derived["features"],
            "canary_seat": hosted["canary_seat"],
            "server_started_at_ns": hosted["server_started_at_ns"],
            "game_day": 0,
            "era": "",
            "opponent_score_decimal": hosted["opponent_score_decimal"],
            "model_target_decimal": {-1: "0", 0: "0.5", 1: "1"}[hosted["outcome_code"]],
        }
        row["game_day"], row["era"] = evidence._derive_day_era(row, time_derivation)
        relative = f"dev/scenario/{row['game_id']}.json"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = canonical_json_bytes(trace_envelope)
        path.write_bytes(raw)
        row["scenario_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        rows.append(row)
        scenario_entries.append({"game_id": row["game_id"], "path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
    rows.sort(key=lambda row: row["game_id"])
    scenario_entries.sort(key=lambda entry: entry["game_id"])
    source_path = root / "dev" / "rows.json"
    source_path.parent.mkdir(exist_ok=True)
    source_raw = canonical_json_bytes(rows)
    source_path.write_bytes(source_raw)
    source_entry = {"path": "dev/rows.json", "sha256": hashlib.sha256(source_raw).hexdigest(), "row_count": len(rows)}
    comparator_entries = []
    for model_id in evidence.COMPARATOR_IDENTITIES:
        relative = f"dev/raw/{model_id}.json"
        path = root / relative
        path.parent.mkdir(exist_ok=True)
        raw = canonical_json_bytes([_raw_record(model_id, row["game_id"], index) for index, row in enumerate(rows)])
        path.write_bytes(raw)
        comparator_entries.append({"model_id": model_id, "path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "row_count": len(rows), "extractor_sha256": evidence._EXTRACTOR_HASHES[model_id]})
    provenance_entries = []
    for category in ("raw_source", "replay", "exclusion", "parser"):
        relative = f"dev/provenance/{category}.json"
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = canonical_json_bytes({"schema": "evaluation_v5_1_g05_receipt_v1", "protocol_id": evidence.PROTOCOL_ID, "category": category})
        path.write_bytes(raw)
        provenance_entries.append({"category": category, "path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "byte_count": len(raw)})
    dataset = {
        "schema": evidence.DEV_DATASET_MANIFEST_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "source_files": [source_entry],
        "comparator_source_files": comparator_entries,
        "provenance_files": provenance_entries,
        "scenario_receipt_files": scenario_entries,
        "row_count": len(rows),
        "archive_count": len({row["canary_archive_id"] for row in rows}),
        "lineage_count": len({row["canary_lineage_id"] for row in rows}),
        "partitions": [evidence.DEV_BURNED],
        "provenance": {"source_kind": evidence.DEV_BURNED, "root_sha256": "0" * 64},
        "feature_registry": list(evidence.FEATURE_REGISTRY),
        "time_derivation": time_derivation,
        "scenario_receipt_root_sha256": canonical_sha256(scenario_entries),
        "engine_manifest_sha256": engine_hash,
        "scenario_sha256": SCENARIO,
        "runtime_sha256": RUNTIME,
        "container_sha256": CONTAINER,
        "executable_sha256": EXECUTABLE,
        "rows_sha256": canonical_sha256(rows),
        "g05_result_sha256": hosted_result["result_sha256"],
        "g05_row_merkle_root_sha256": hosted_result["row_merkle_root_sha256"],
        "g05_trace_binding_root_sha256": hosted_result["trace_binding_root_sha256"],
    }
    dataset["provenance"]["root_sha256"] = _provenance_root(dataset)
    dataset_hash = canonical_sha256(dataset)
    folds = sorted(row["canary_lineage_id"] for row in rows)
    spec = {
        "schema": evidence.DEV_FIT_SPEC_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "dataset_manifest_sha256": dataset_hash,
        "engine_manifest_sha256": engine_hash,
        "scenario_sha256": SCENARIO,
        "runtime_sha256": RUNTIME,
        "container_sha256": CONTAINER,
        "executable_sha256": EXECUTABLE,
        "feature_registry": list(evidence.FEATURE_REGISTRY),
        "standardization": copy.deepcopy(evidence._STANDARDIZATION),
        "optimizer": copy.deepcopy(evidence._OPTIMIZER),
        "regularization": copy.deepcopy(evidence._REGULARIZATION),
        "seed": 0,
        "lolo": {"unit": "lineage_id", "equal_lineage": True, "outer": True, "folds": folds, "fold_order": "lexical_lineage_id"},
        "model_registry": evidence._model_registry(),
        "comparator_registry": evidence._registry(),
        "missing_rules": copy.deepcopy(evidence._MISSING_RULES),
        "tie_break": copy.deepcopy(evidence._TIE_BREAK),
        "fit_created_at_utc": CREATED,
    }
    normalized_rows = [evidence._validate_row(row, time_derivation) for row in rows]
    raw_values = {
        model_id: {row["game_id"]: evidence._decimal(_raw_record(model_id, row["game_id"], index)["raw_score"], "raw") for index, row in enumerate(rows)}
        for model_id in evidence.COMPARATOR_IDENTITIES
    }
    table, selected, mci, comparator, transcript = evidence._fit_complete(normalized_rows, raw_values, canonical_sha256(spec), dataset_hash, EXECUTABLE, folds)
    transcript_hash = canonical_sha256(transcript)
    model_output_hash = canonical_sha256({"mci_manifest": mci, "comparator_manifest": comparator, "prediction_transcript_sha256": transcript_hash})
    result = {
        "schema": evidence.DEV_FIT_RESULT_SCHEMA,
        "protocol_id": evidence.PROTOCOL_ID,
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "fit_status": "FIT_COMPLETE" if feasible else "NO_LOCAL_FEATURE_EXTRACTION",
        "dataset_manifest_sha256": dataset_hash,
        "fit_spec_sha256": canonical_sha256(spec),
        "engine_manifest_sha256": engine_hash,
        "scenario_sha256": SCENARIO,
        "runtime_sha256": RUNTIME,
        "container_sha256": CONTAINER,
        "executable_sha256": EXECUTABLE,
        "fit_created_at_utc": CREATED,
        "fold_hash": canonical_sha256(folds),
        "candidate_score_table": table if feasible else [],
        "candidate_score_table_sha256": canonical_sha256(table if feasible else []),
        "selected_comparator_identity": selected if feasible else None,
        "mci_manifest": mci if feasible else None,
        "comparator_manifest": comparator if feasible else None,
        "prediction_transcript_sha256": transcript_hash if feasible else canonical_sha256([]),
        "model_output_sha256": model_output_hash if feasible else canonical_sha256({"mci_manifest": None, "comparator_manifest": None, "prediction_transcript_sha256": canonical_sha256([])}),
    }
    result["result_core_sha256"] = canonical_sha256(result)
    result["rebuild_receipts"] = [
        {"rebuild_id": "clean-linux-amd64-01", "os": "linux", "arch": "amd64", "clean": True, "runtime_sha256": RUNTIME, "executable_sha256": EXECUTABLE, "result_core_sha256": result["result_core_sha256"], "model_output_sha256": result["model_output_sha256"]},
        {"rebuild_id": "clean-linux-amd64-02", "os": "linux", "arch": "amd64", "clean": True, "runtime_sha256": RUNTIME, "executable_sha256": EXECUTABLE, "result_core_sha256": result["result_core_sha256"], "model_output_sha256": result["model_output_sha256"]},
    ]
    envelopes = (
        _signed(evidence.DEV_DATASET_MANIFEST_SCHEMA, dataset, private, public),
        _signed(evidence.DEV_FIT_SPEC_SCHEMA, spec, private, public),
        _signed(evidence.DEV_FIT_RESULT_SCHEMA, result, private, public),
    )
    return root, engine, envelopes, private, public, hosted_inputs, hosted_keys


def _audit(root: Path, engine: dict[str, object], envelopes, public: bytes, hosted_inputs: dict[str, object], *, executable: str = EXECUTABLE):
    return evidence.audit_development_fit_evidence(
        *envelopes,
        root,
        engine_capability_manifest=engine,
        scenario_sha256=SCENARIO,
        runtime_sha256=RUNTIME,
        container_sha256=CONTAINER,
        executable_sha256=executable,
        pinned_public_key_bytes=public,
        hosted_custody_inputs=hosted_inputs,
    )


def _rewrite_rows_and_dataset(root: Path, envelopes, private, public, rows: list[dict[str, object]]):
    raw = canonical_json_bytes(rows)
    (root / "dev/rows.json").write_bytes(raw)
    dataset = copy.deepcopy(envelopes[0]["payload"])
    dataset["source_files"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    dataset["source_files"][0]["row_count"] = len(rows)
    dataset["row_count"] = len(rows)
    dataset["archive_count"] = len({row["canary_archive_id"] for row in rows})
    dataset["lineage_count"] = len({row["canary_lineage_id"] for row in rows})
    dataset["rows_sha256"] = canonical_sha256(rows)
    dataset["scenario_receipt_root_sha256"] = canonical_sha256(dataset["scenario_receipt_files"])
    dataset["provenance"]["root_sha256"] = _provenance_root(dataset)
    return _signed(evidence.DEV_DATASET_MANIFEST_SCHEMA, dataset, private, public)


def test_g05_to_dev_fit_is_real_dual_signed_end_to_end(tmp_path: Path) -> None:
    root, engine, envelopes, _, public, hosted_inputs, _ = _fixture(tmp_path)
    hosted = hosted_dev_custody.validate_hosted_dev_custody_result_receipt(**hosted_inputs, development_public_key=public)
    assert hosted["decision"] == hosted_dev_custody.G05_DECISION
    assert len(hosted["rows"]) == 15
    assert all(set(row) == set(hosted_dev_custody.HOSTED_COLUMNS) for row in hosted["rows"])
    result = _audit(root, engine, envelopes, public, hosted_inputs)
    assert result["evidence_complete"] is True
    assert result["decision"] == "DEVELOPMENT_ONLY"
    assert result["submission_authorized"] is False


def test_decimal_draw_target_is_preserved_for_validation_and_loss(tmp_path: Path) -> None:
    root, _, envelopes, _, _, _, _ = _fixture(tmp_path)
    row = json.loads((root / "dev/rows.json").read_text())[0]
    row["model_target_decimal"] = "0.5"
    assert evidence._validate_row(row, envelopes[0]["payload"]["time_derivation"])["model_target_decimal"] == "0.5"
    assert evidence._q12(evidence._loss(Decimal("0.5"), Decimal("0.5"))) == "0.693147180560"


@pytest.mark.parametrize("field,value", [
    ("model_target_decimal", "0"),
    ("opponent_score_decimal", "9999"),
    ("canary_seat", 1),
    ("server_started_at_ns", 1783987200000000001),
    ("canary_archive_id", "archive-tampered"),
])
def test_caller_hosted_scalars_cannot_override_real_g05(tmp_path: Path, field: str, value: object) -> None:
    root, engine, envelopes, private, public, hosted_inputs, _ = _fixture(tmp_path)
    rows = json.loads((root / "dev/rows.json").read_text())
    rows[0][field] = value
    dataset = _rewrite_rows_and_dataset(root, envelopes, private, public, rows)
    result = _audit(root, engine, (dataset, envelopes[1], envelopes[2]), public, hosted_inputs)
    assert result["evidence_complete"] is False
    assert field in result["failure_reason"] or "outcome_code" in result["failure_reason"]


def test_missing_or_extra_games_fail_closed_without_relaxing_lineages(tmp_path: Path) -> None:
    root, engine, envelopes, private, public, hosted_inputs, _ = _fixture(tmp_path)
    rows = json.loads((root / "dev/rows.json").read_text())
    missing = _rewrite_rows_and_dataset(root, envelopes, private, public, rows[:-1])
    assert _audit(root, engine, (missing, envelopes[1], envelopes[2]), public, hosted_inputs)["evidence_complete"] is False
    extra_rows = copy.deepcopy(rows)
    extra = copy.deepcopy(rows[0])
    extra.update({"game_id": "g-extra", "canary_archive_id": "archive-extra", "canary_lineage_id": "lineage-extra", "scenario_receipt_sha256": "a" * 64})
    extra_rows.append(extra)
    extra_dataset = _rewrite_rows_and_dataset(root, envelopes, private, public, extra_rows)
    extra_result = _audit(root, engine, (extra_dataset, envelopes[1], envelopes[2]), public, hosted_inputs)
    assert extra_result["evidence_complete"] is False
    assert "exact same game set" in extra_result["failure_reason"]


def test_trace_substitution_fails_the_published_g05_envelope_map(tmp_path: Path) -> None:
    root, engine, envelopes, private, public, hosted_inputs, _ = _fixture(tmp_path)
    dataset_payload = envelopes[0]["payload"]
    first, second = dataset_payload["scenario_receipt_files"][:2]
    (root / first["path"]).write_bytes((root / second["path"]).read_bytes())
    rows = json.loads((root / "dev/rows.json").read_text())
    rows[0]["scenario_receipt_sha256"] = hashlib.sha256((root / first["path"]).read_bytes()).hexdigest()
    changed = _rewrite_rows_and_dataset(root, envelopes, private, public, rows)
    changed_payload = copy.deepcopy(changed["payload"])
    changed_payload["scenario_receipt_files"][0]["sha256"] = rows[0]["scenario_receipt_sha256"]
    changed_payload["scenario_receipt_root_sha256"] = canonical_sha256(changed_payload["scenario_receipt_files"])
    changed_payload["provenance"]["root_sha256"] = _provenance_root(changed_payload)
    changed = _signed(evidence.DEV_DATASET_MANIFEST_SCHEMA, changed_payload, private, public)
    result = _audit(root, engine, (changed, envelopes[1], envelopes[2]), public, hosted_inputs)
    assert result["evidence_complete"] is False
    assert "G05 trace-envelope binding" in result["failure_reason"]


def test_fake_g05_receipt_with_hidden_published_field_is_rejected(tmp_path: Path) -> None:
    root, engine, envelopes, _, public, hosted_inputs, hosted_keys = _fixture(tmp_path)
    fake = copy.deepcopy(hosted_inputs)
    authority_payload = copy.deepcopy(fake["final_audit_authority_envelope"]["payload"])
    authority_payload["rows"][0]["model_target_decimal"] = "1"
    authority_payload["result_sha256"] = canonical_sha256({key: value for key, value in authority_payload.items() if key != "result_sha256"})
    authority = _signed(hosted_dev_custody.G05_AUDIT_SCHEMA, authority_payload, *hosted_keys["evaluation_authority"])
    fake["final_audit_authority_envelope"] = authority
    fake["final_audit_countersignature_envelope"] = _signed(
        hosted_dev_custody.G05_AUDIT_COUNTERSIGNATURE_SCHEMA,
        {"schema": hosted_dev_custody.G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": hosted_dev_custody.G05_PROTOCOL, "authority_audit_envelope_sha256": canonical_sha256(authority)},
        *hosted_keys["validation_authority"],
    )
    result = _audit(root, engine, envelopes, public, fake)
    assert result["evidence_complete"] is False
    assert "complete research-only decision" in result["failure_reason"]


def test_extra_field_is_rejected_even_before_any_dev_fit(tmp_path: Path) -> None:
    root, _, envelopes, _, public, hosted_inputs, _ = _fixture(tmp_path)
    receipt = hosted_dev_custody.validate_hosted_dev_custody_result_receipt(**hosted_inputs, development_public_key=public)
    fake = copy.deepcopy(receipt)
    fake["rows"][0]["model_target_decimal"] = "1"
    fake["result_sha256"] = canonical_sha256({key: value for key, value in fake.items() if key != "result_sha256"})
    dataset = copy.deepcopy(envelopes[0]["payload"])
    dataset["g05_result_sha256"] = fake["result_sha256"]
    dataset["provenance"]["root_sha256"] = _provenance_root(dataset)
    with pytest.raises(evidence.DevelopmentEvidenceError, match="exact published HOSTED_COLUMNS"):
        evidence._bind_dataset_to_g05(dataset, fake)


def test_missing_final_countersignature_and_wrong_trace_role_fail_closed(tmp_path: Path) -> None:
    root, engine, envelopes, _, public, hosted_inputs, _ = _fixture(tmp_path)
    missing = copy.deepcopy(hosted_inputs)
    missing.pop("final_audit_countersignature_envelope")
    assert _audit(root, engine, envelopes, public, missing)["evidence_complete"] is False
    wrong_role = copy.deepcopy(hosted_inputs)
    wrong_role["role_keys"]["trace_attestor"] = copy.deepcopy(wrong_role["role_keys"]["collector_c1"])
    assert _audit(root, engine, envelopes, public, wrong_role)["evidence_complete"] is False
