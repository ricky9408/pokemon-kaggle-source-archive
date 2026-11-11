from __future__ import annotations

from copy import deepcopy
import base64
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1 import scenario_evidence as evidence
from evaluation_v5_1.canonical import canonical_json_bytes
from evaluation_v5_1.exact_gate_v2 import (
    AUTHORITY_ENVELOPE_SCHEMA,
    AUTHORITY_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_MEDIA_TYPE,
    FINAL_BUNDLE_SCHEMA,
    VALIDATOR_ENVELOPE_SCHEMA,
    VALIDATOR_MEDIA_TYPE,
    dependency_closure_root,
    encode_byte_evidence,
    validate_ed25519_public_key,
)


def _hash(text: str | bytes) -> str:
    raw = text.encode("ascii") if isinstance(text, str) else text
    return hashlib.sha256(raw).hexdigest()


def _blob(value: object, blobs: dict[str, bytes]) -> str:
    raw = canonical_json_bytes(value)
    digest = hashlib.sha256(raw).hexdigest()
    blobs[digest] = raw
    return digest


def _key() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key_record(role: str, public: bytes, *, principal: str, custodian: str) -> dict[str, str]:
    return {
        "role": role, "key_id": validate_ed25519_public_key(public), "principal_id": principal,
        "custodian_id": custodian, "algorithm": "Ed25519",
        "public_A_ed25519_base64": base64.b64encode(public).decode("ascii"),
    }


def _signed_envelope(*, schema: str, payload: dict[str, object], private: Ed25519PrivateKey, public: bytes, domain: bytes, payload_media_type: str, envelope_media_type: str) -> dict[str, object]:
    payload_raw = canonical_json_bytes(payload)
    signature = private.sign(domain + len(payload_raw).to_bytes(8, "big") + payload_raw)
    envelope = {
        "schema": schema, "signer_key_id": validate_ed25519_public_key(public),
        "payload": encode_byte_evidence(payload_raw, media_type=payload_media_type),
        "signature_A_ed25519_base64": base64.b64encode(public).decode("ascii"),
        "signature_R_ed25519_base64": base64.b64encode(signature[:32]).decode("ascii"),
        "signature_S_ed25519_base64": base64.b64encode(signature[32:]).decode("ascii"),
    }
    return encode_byte_evidence(canonical_json_bytes(envelope), media_type=envelope_media_type)


def _g02_dependency_bundle() -> tuple[dict[str, object], str]:
    nodes = [
        {"gate_id": "G00_TRUST_ROOTS", "bundle_sha256": _hash("g00-bundle"), "authority_payload_sha256": _hash("g00-payload"), "decision": "PASS_RESEARCH_ONLY"},
        {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "bundle_sha256": _hash("g01-bundle"), "authority_payload_sha256": _hash("g01-payload"), "decision": "PASS_RESEARCH_ONLY"},
    ]
    edges = [
        {"gate_id": "G02_ENGINE_EVENT_CAPABILITY", "dependency_gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE"},
        {"gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE", "dependency_gate_id": "G00_TRUST_ROOTS"},
    ]
    payload = {
        "schema_version": "ptcg.g03.g02-authority-identity/v1", "protocol_id": evidence.PROTOCOL_ID,
        "campaign_root": _hash("campaign"), "evaluation_id": "g02-eval", "evaluation_nonce": _hash("nonce"),
        "gate_id": "G02_ENGINE_EVENT_CAPABILITY", "input_bundle_root": _hash("input"),
        "direct_dependencies": [nodes[1]], "dependency_closure_root": dependency_closure_root(nodes, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"),
        "decision": "PASS_RESEARCH_ONLY",
    }
    authority_envelope = {
        "schema_version": AUTHORITY_ENVELOPE_SCHEMA, "signer_key_id": "ed25519-sha256:" + "0" * 64,
        "payload": encode_byte_evidence(canonical_json_bytes(payload), media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE),
        "signature_ed25519_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
    }
    validator_envelope = {
        "schema_version": VALIDATOR_ENVELOPE_SCHEMA, "signer_key_id": "ed25519-sha256:" + "1" * 64,
        "payload": encode_byte_evidence(canonical_json_bytes({"validator": "opaque"}), media_type="application/vnd.ptcg.exact-gate-validator-payload+json"),
        "signature_ed25519_base64": base64.b64encode(b"\0" * 64).decode("ascii"),
    }
    final_raw = canonical_json_bytes({
        "schema_version": FINAL_BUNDLE_SCHEMA,
        "authority_envelope": encode_byte_evidence(canonical_json_bytes(authority_envelope), media_type=AUTHORITY_MEDIA_TYPE),
        "validator_envelope": encode_byte_evidence(canonical_json_bytes(validator_envelope), media_type=VALIDATOR_MEDIA_TYPE),
    })
    bundle = {
        "schema": evidence.G03_G02_DEPENDENCY_BUNDLE_SCHEMA,
        "exact_g02_final_bundle": encode_byte_evidence(final_raw, media_type=evidence.G03_G02_BUNDLE_MEDIA_TYPE),
        "g02_authority_payload": encode_byte_evidence(canonical_json_bytes(payload), media_type=evidence.G03_G02_AUTHORITY_MEDIA_TYPE),
        "transitive_dependencies": nodes, "transitive_edges": edges,
    }
    return bundle, _hash(final_raw)


def _plan(*, partition: str = "RESEARCH", engine_sha256: str, container_sha256: str) -> dict[str, object]:
    cells: list[dict[str, object]] = []
    for seat in (0, 1):
        cells.append({
            "cell_id": f"source-{seat}", "template": evidence.NATURAL_TEMPLATE, "engine_id": "pinned_source",
            "opponent_package_id": "control", "state_constructor_sha256": _hash(f"state-{seat}"), "seat": seat,
            "seed_derivation": {"scheme": evidence.SEED_DERIVATION_SCHEME, "seed_index": 0}, "attempt_index": 0,
            "failure_rule": evidence.FAILURE_RULE, "aggregation_formula": evidence.AGGREGATION_FORMULA,
        })
    return {
        "schema": evidence.SCENARIO_PLAN_SCHEMA, "protocol_id": evidence.PROTOCOL_ID,
        "candidate_archive_sha256": _hash("archive"), "deck_sha256": _hash("deck"), "policy_sha256": _hash("policy"), "seed_commitment_sha256": _hash("seed"),
        "engine_bindings": {"pinned_source": {"engine_sha256": engine_sha256, "container_sha256": container_sha256}},
        "opponent_packages": {"control": {"package_sha256": _hash("opponent"), "family_id": "control", "lineage_id": "lineage-0"}},
        "era_calendar": [
            {"era": "one", "starts_at_utc": "2026-01-01T00:00:00.000000Z", "ends_at_utc": "2026-01-02T00:00:00.000000Z"},
            {"era": "two", "starts_at_utc": "2026-01-02T00:00:00.000000Z", "ends_at_utc": "2026-01-03T00:00:00.000000Z"},
        ],
        "scheduled_terminal_categories": list(evidence.TERMINAL_CATEGORIES), "evidence_partition": partition, "cells": cells,
    }


def _event(kind: str, payload: dict[str, object], previous: str, index: int) -> dict[str, object]:
    unsigned = {"event_type": kind, "event_index": index, "previous_event_sha256": previous, "payload": payload}
    return {**unsigned, "event_sha256": evidence.canonical_sha256(unsigned)}


def _events(state_hash: str, *, dunsparce: bool = False, runaway: bool = False) -> list[dict[str, object]]:
    source = [
        ("GAME_START", {}), ("TURN_START", {"owner": "self", "own_turn": 1}),
        ("ACTION_REQUESTED", {"observation_sha256": _hash("obs-1"), "legal_actions_sha256": _hash("legal-1")}),
        ("ACTION_CHOSEN", {"action_sha256": _hash("action-1")}),
        ("MANUAL_ENERGY_ATTACHED", {"pokemon_id": "attacker", "pokemon_kind": "dunsparce_engine" if dunsparce else "combatant"}),
        ("TURN_START", {"owner": "opponent", "own_turn": 1}), ("POKEMON_KO", {"owner": "self", "was_active": True}),
        ("FORCED_SWITCH", {"owner": "self"}), ("TURN_START", {"owner": "self", "own_turn": 2}),
        ("ATTACK_DECLARED", {"attacker_id": "attacker", "owner": "self"}),
        ("DAMAGE_APPLIED", {"attacker_id": "attacker", "source_owner": "self", "amount": 20}), ("PRIZE_TAKEN", {"owner": "self", "count": 2}),
    ]
    if runaway:
        source.append(("RUN_AWAY_DRAW_ATTEMPT", {"pokemon_id": "dudunsparce", "sole_pokemon_in_play": True}))
    source.append(("GAME_END", {"terminal_category": "completed"}))
    previous = state_hash
    result: list[dict[str, object]] = []
    for index, (kind, payload) in enumerate(source):
        current = _event(kind, payload, previous, index)
        result.append(current)
        previous = current["event_sha256"]  # type: ignore[assignment]
    return result


def _fixture(*, partition: str = "RESEARCH", dunsparce: bool = False, runaway: bool = False) -> tuple[dict[str, object], dict[str, object], dict[str, bytes], dict[str, object]]:
    runner_image, runner_binary = b"g03-source-image", b"g03-source-binary"
    plan = _plan(partition=partition, engine_sha256=_hash(runner_binary), container_sha256=_hash(runner_image))
    checked = evidence.validate_scenario_plan(plan)
    plan_hash = evidence.scenario_plan_sha256(plan)
    executor_private, executor_public = _key()
    attestor_private, attestor_public = _key()
    g02_bundle, g02_hash = _g02_dependency_bundle()
    provenance = {
        "g02_dependency_bundle": g02_bundle,
        "source_executor_key": _key_record("source_executor", executor_public, principal="executor-principal", custodian="executor-custodian"),
        "trace_attestor_key": _key_record("trace_attestor", attestor_public, principal="attestor-principal", custodian="attestor-custodian"),
        "pinned_source_executor_public_key": executor_public, "pinned_trace_attestor_public_key": attestor_public,
        "_source_executor_private": executor_private,
    }
    blobs: dict[str, bytes] = {}
    receipt_cells: list[dict[str, object]] = []
    for index, cell in enumerate(checked["cells"]):
        state = evidence._expected_state(checked, plan_hash, cell)
        state_hash = _blob(state, blobs)
        trace = {"schema": "evaluation_v5_1_natural_game_trace_v2", "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"], "state_blob_sha256": state_hash, "template": evidence.NATURAL_TEMPLATE, "events": _events(state_hash, dunsparce=dunsparce, runaway=runaway)}
        trace_hash = _blob(trace, blobs)
        ended = "2026-01-02T00:00:01.000000Z" if index == 0 else "2026-01-01T12:00:01.000000Z"
        started = "2026-01-02T00:00:00.000000Z" if index == 0 else "2026-01-01T12:00:00.000000Z"
        result_hash = _blob({"schema": "evaluation_v5_1_natural_game_result_v3", "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"], "trace_blob_sha256": trace_hash, "status": "OK", "created_at_utc": ended}, blobs)
        safety_hash = _blob({"schema": "evaluation_v5_1_natural_game_safety_v3", "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"], "result_blob_sha256": result_hash, "status": "UNSAFE" if dunsparce or runaway else "SAFE"}, blobs)
        argv = [evidence.G03_RUNNER_PATH, "--input", "/input/state.json", "--raw-trace-output", "/output/trace.json"]
        pre_raw = canonical_json_bytes({"schema": "evaluation_v5_1_g03_pre_run_inventory_v1", "cell_id": cell["cell_id"], "state_blob_sha256": state_hash, "argv": argv, "env": evidence.G03_RUNNER_ENV})
        execution_payload = {
            "schema": evidence.G03_EXECUTION_PAYLOAD_SCHEMA, "protocol_id": evidence.PROTOCOL_ID, "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"],
            "candidate_archive_sha256": checked["candidate_archive_sha256"], "deck_sha256": checked["deck_sha256"], "policy_sha256": checked["policy_sha256"],
            "engine_sha256": _hash(runner_binary), "container_sha256": _hash(runner_image), "platform_os": "linux", "platform_arch": "amd64",
            "runner_image_sha256": _hash(runner_image), "runner_binary_sha256": _hash(runner_binary),
            "runner_image": encode_byte_evidence(runner_image, media_type="application/octet-stream"), "runner_binary": encode_byte_evidence(runner_binary, media_type="application/octet-stream"),
            "argv": argv, "env": evidence.G03_RUNNER_ENV, "input_state": encode_byte_evidence(blobs[state_hash], media_type=evidence.G03_STATE_MEDIA_TYPE),
            "pre_run_inventory": encode_byte_evidence(pre_raw, media_type=evidence.G03_INVENTORY_MEDIA_TYPE),
            "post_run_inventory": encode_byte_evidence(canonical_json_bytes({"schema": "evaluation_v5_1_g03_post_run_inventory_v1", "cell_id": cell["cell_id"], "pre_run_inventory_sha256": _hash(pre_raw), "trace_blob_sha256": trace_hash, "working_tree_clean": True, "created_paths": [], "modified_paths": [], "deleted_paths": []}), media_type=evidence.G03_INVENTORY_MEDIA_TYPE),
            "attempt_index": 0, "retry_count": 0, "replacement_count": 0, "intervention_count": 0, "rng_state_injection_count": 0, "forced_state_count": 0, "restore_count": 0, "carryover_count": 0,
            "started_at_utc": started, "ended_at_utc": ended, "exit_code": 0, "status": "SUCCEEDED", "raw_trace": encode_byte_evidence(blobs[trace_hash], media_type=evidence.G03_TRACE_MEDIA_TYPE),
            "executor_key_id": provenance["source_executor_key"]["key_id"], "executor_principal_id": "executor-principal", "executor_custodian_id": "executor-custodian",
        }
        execution_envelope = _signed_envelope(schema=evidence.G03_EXECUTION_ENVELOPE_SCHEMA, payload=execution_payload, private=executor_private, public=executor_public, domain=evidence.G03_EXECUTION_DOMAIN, payload_media_type=evidence.G03_EXECUTION_PAYLOAD_MEDIA_TYPE, envelope_media_type=evidence.G03_EXECUTION_ENVELOPE_MEDIA_TYPE)
        execution_raw = base64.b64decode(execution_envelope["base64"])
        execution_payload_raw = canonical_json_bytes(execution_payload)
        attestation = {
            "schema": evidence.G03_TRACE_ATTESTATION_SCHEMA, "protocol_id": evidence.PROTOCOL_ID, "scenario_plan_sha256": plan_hash, "cell_id": cell["cell_id"],
            "execution_envelope_sha256": _hash(execution_raw), "execution_envelope_decoded_length": len(execution_raw), "execution_payload_sha256": _hash(execution_payload_raw), "execution_payload_decoded_length": len(execution_payload_raw),
            "raw_trace_sha256": trace_hash, "raw_trace_decoded_length": len(blobs[trace_hash]), "raw_trace_media_type": evidence.G03_TRACE_MEDIA_TYPE,
            "independent_trace_root_sha256": trace["events"][-1]["event_sha256"], "attested_at_utc": ended.replace(":01.000000Z", ":02.000000Z"),
            "trace_attestor_key_id": provenance["trace_attestor_key"]["key_id"], "trace_attestor_principal_id": "attestor-principal", "trace_attestor_custodian_id": "attestor-custodian",
        }
        attestation_envelope = _signed_envelope(schema=evidence.G03_TRACE_ATTESTATION_ENVELOPE_SCHEMA, payload=attestation, private=attestor_private, public=attestor_public, domain=evidence.G03_TRACE_ATTESTATION_DOMAIN, payload_media_type="application/vnd.ptcg.g03-trace-attestation+json", envelope_media_type=evidence.G03_TRACE_ATTESTATION_ENVELOPE_MEDIA_TYPE)
        receipt_cells.append({"cell_id": cell["cell_id"], "state_blob_sha256": state_hash, "trace_blob_sha256": trace_hash, "result_blob_sha256": result_hash, "safety_blob_sha256": safety_hash, "execution_envelope": execution_envelope, "trace_attestation_envelope": attestation_envelope})
    receipt = {"schema": evidence.EXECUTION_RECEIPT_SCHEMA, "protocol_id": evidence.PROTOCOL_ID, "scenario_plan_sha256": plan_hash, "candidate_archive_sha256": checked["candidate_archive_sha256"], "deck_sha256": checked["deck_sha256"], "policy_sha256": checked["policy_sha256"], "engine_bindings": checked["engine_bindings"], "g02_dependency_bundle_sha256": g02_hash, "cells": receipt_cells}
    return plan, receipt, blobs, provenance


def _verify(plan: object, receipt: object, blobs: dict[str, bytes], provenance: dict[str, object]) -> dict[str, object]:
    return evidence.verify_scenario_evidence(
        scenario_plan=plan, execution_receipt=receipt, blobs=blobs,
        g02_dependency_bundle=provenance["g02_dependency_bundle"], source_executor_key=provenance["source_executor_key"],
        trace_attestor_key=provenance["trace_attestor_key"], pinned_source_executor_public_key=provenance["pinned_source_executor_public_key"],
        pinned_trace_attestor_public_key=provenance["pinned_trace_attestor_public_key"],
    )


def test_exact_provenance_fixed_registry_events_eras_support_and_no_wrapper_lane() -> None:
    plan, receipt, blobs, provenance = _fixture()
    result = _verify(plan, receipt, blobs, provenance)
    assert result["decision"] == "SCENARIO_EVIDENCE_VERIFIED_RESEARCH_ONLY"
    assert result["feature_registry"] == list(evidence.FEATURE_REGISTRY)
    assert result["features"]["A2"] == "1.000000000000"
    assert result["features"]["P4"] == "0.333333333333"
    assert result["game_eras"][0]["era"] == "two"
    assert result["authority"] is False and result["submission_authorized"] is False


@pytest.mark.parametrize("tamper", ["raw_trace", "signature_r", "retry", "attestor_principal", "attestor_custodian", "g02_root"])
def test_adversarial_execution_provenance_tampering_fails_closed(tamper: str) -> None:
    plan, receipt, blobs, provenance = _fixture()
    cell = receipt["cells"][0]
    if tamper == "raw_trace":
        trace = evidence._parse_blob(blobs[cell["trace_blob_sha256"]], "trace")
        trace = dict(trace)
        trace["events"] = list(trace["events"])
        trace["events"][11] = dict(trace["events"][11])
        trace["events"][11]["payload"] = {"owner": "self", "count": 1}
        previous = trace["state_blob_sha256"]
        for index, event in enumerate(trace["events"]):
            event["event_index"] = index
            event["previous_event_sha256"] = previous
            event["event_sha256"] = evidence.canonical_sha256({key: event[key] for key in ("event_type", "event_index", "previous_event_sha256", "payload")})
            previous = event["event_sha256"]
        new_trace_hash = _blob(trace, blobs)
        cell["trace_blob_sha256"] = new_trace_hash
        result = dict(evidence._parse_blob(blobs[cell["result_blob_sha256"]], "result"))
        result["trace_blob_sha256"] = new_trace_hash
        cell["result_blob_sha256"] = _blob(result, blobs)
        safety = dict(evidence._parse_blob(blobs[cell["safety_blob_sha256"]], "safety"))
        safety["result_blob_sha256"] = cell["result_blob_sha256"]
        cell["safety_blob_sha256"] = _blob(safety, blobs)
    elif tamper == "signature_r":
        raw = base64.b64decode(cell["execution_envelope"]["base64"])
        envelope = evidence._parse_blob(raw, "execution envelope")
        envelope = dict(envelope)
        envelope["signature_R_ed25519_base64"] = base64.b64encode(b"\0" * 32).decode("ascii")
        cell["execution_envelope"] = encode_byte_evidence(canonical_json_bytes(envelope), media_type=evidence.G03_EXECUTION_ENVELOPE_MEDIA_TYPE)
    elif tamper == "retry":
        raw = base64.b64decode(cell["execution_envelope"]["base64"])
        envelope = evidence._parse_blob(raw, "execution envelope")
        payload_raw = base64.b64decode(envelope["payload"]["base64"])
        payload = dict(evidence._parse_blob(payload_raw, "payload"))
        payload["retry_count"] = 1
        cell["execution_envelope"] = _signed_envelope(
            schema=evidence.G03_EXECUTION_ENVELOPE_SCHEMA, payload=payload,
            private=provenance["_source_executor_private"], public=provenance["pinned_source_executor_public_key"],
            domain=evidence.G03_EXECUTION_DOMAIN, payload_media_type=evidence.G03_EXECUTION_PAYLOAD_MEDIA_TYPE,
            envelope_media_type=evidence.G03_EXECUTION_ENVELOPE_MEDIA_TYPE,
        )
    elif tamper == "attestor_principal":
        provenance["trace_attestor_key"] = dict(provenance["trace_attestor_key"])
        provenance["trace_attestor_key"]["principal_id"] = "executor-principal"
    elif tamper == "attestor_custodian":
        provenance["trace_attestor_key"] = dict(provenance["trace_attestor_key"])
        provenance["trace_attestor_key"]["custodian_id"] = "executor-custodian"
    else:
        provenance["g02_dependency_bundle"] = deepcopy(provenance["g02_dependency_bundle"])
        provenance["g02_dependency_bundle"]["transitive_edges"] = []
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "SCENARIO_EVIDENCE_INVALID"


@pytest.mark.parametrize("kind", ["dunsparce", "runaway"])
def test_dunsparce_attachment_and_sole_pokemon_runaway_are_safety_vetoes(kind: str) -> None:
    plan, receipt, blobs, provenance = _fixture(dunsparce=kind == "dunsparce", runaway=kind == "runaway")
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "OPERATIONAL_SAFETY_VETO"


def test_dev_support_and_scenario_interventions_remain_closed() -> None:
    plan, receipt, blobs, provenance = _fixture(partition="DEV")
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "DEV_SUPPORT_INSUFFICIENT"
    plan, receipt, blobs, provenance = _fixture()
    plan["cells"][0]["intervention"] = "forced_switch"
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "SCENARIO_EVIDENCE_INVALID"


def test_caller_feature_claims_and_wrapper_lane_are_rejected() -> None:
    plan, receipt, blobs, provenance = _fixture()
    plan["feature_definitions"] = []
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "SCENARIO_EVIDENCE_INVALID"
    plan, receipt, blobs, provenance = _fixture()
    plan["engine_bindings"]["official_wrapper"] = {"engine_sha256": _hash("wrapper"), "container_sha256": _hash("wrapper-container")}
    assert _verify(plan, receipt, blobs, provenance)["decision"] == "SCENARIO_EVIDENCE_INVALID"
