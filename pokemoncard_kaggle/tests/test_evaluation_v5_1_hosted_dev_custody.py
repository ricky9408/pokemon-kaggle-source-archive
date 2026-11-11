from __future__ import annotations

import copy
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1 import scenario_evidence as scenario
from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.envelope import build_envelope, signing_payload
from evaluation_v5_1.hosted_dev_custody import (
    G05_AUDIT_COUNTERSIGNATURE_SCHEMA,
    G05_AUDIT_SCHEMA,
    G05_COLLECTOR_MANIFEST_SCHEMA,
    G05_DECISION,
    G05_EVIDENCE_BUNDLE_SCHEMA,
    G05_PROTOCOL,
    G05_SPEC_COUNTERSIGNATURE_SCHEMA,
    G05_SPEC_SCHEMA,
    G05_TRACE_SCHEMA,
    HOSTED_COLUMNS,
    ROLES,
    derive_hosted_dev_custody_audit,
    validate_hosted_dev_custody_result_receipt,
    verify_hosted_dev_custody,
)


def _key():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signed(schema, payload, key):
    private, public = key
    return build_envelope(
        artifact_schema=schema,
        payload=payload,
        signer_public_key_bytes=public,
        signature=private.sign(signing_payload(schema, canonical_sha256(payload))),
    )


def _event(kind, payload, previous, index):
    unsigned = {"event_type": kind, "event_index": index, "previous_event_sha256": previous, "payload": payload}
    return {**unsigned, "event_sha256": canonical_sha256(unsigned)}


def _source_receipt(game_id, archive_id, lineage_id, candidate_hash, opponent_hash, seed_commitment):
    plan = {
        "schema": scenario.SCENARIO_PLAN_SCHEMA, "protocol_id": "MCI_FAMILY_TRANSFER_V2",
        "candidate_archive_sha256": candidate_hash, "deck_sha256": "1" * 64, "policy_sha256": "2" * 64,
        "seed_commitment_sha256": seed_commitment,
        "engine_bindings": {"pinned_source": {"engine_sha256": "4" * 64, "container_sha256": "5" * 64}},
        "opponent_packages": {"opp": {"package_sha256": opponent_hash, "family_id": "f", "lineage_id": "ol"}},
        "era_calendar": [{"era": "E", "starts_at_utc": "2026-01-01T00:00:00.000000Z", "ends_at_utc": "2027-01-01T00:00:00.000000Z"}],
        "scheduled_terminal_categories": list(scenario.TERMINAL_CATEGORIES), "evidence_partition": "DEV",
        "cells": [{"cell_id": game_id, "template": scenario.NATURAL_TEMPLATE, "engine_id": "pinned_source", "opponent_package_id": "opp", "state_constructor_sha256": "6" * 64, "seat": 0, "seed_derivation": {"scheme": scenario.SEED_DERIVATION_SCHEME, "seed_index": 0}, "attempt_index": 0, "failure_rule": scenario.FAILURE_RULE, "aggregation_formula": scenario.AGGREGATION_FORMULA}],
    }
    plan = scenario.validate_scenario_plan(plan)
    plan_hash = scenario.scenario_plan_sha256(plan)
    state = scenario._expected_state(plan, plan_hash, plan["cells"][0])
    previous = canonical_sha256(state)
    events = []
    for index, (kind, payload) in enumerate((("GAME_START", {}), ("TURN_START", {"owner": "self", "own_turn": 1}), ("GAME_END", {"terminal_category": "completed"}))):
        event = _event(kind, payload, previous, index)
        events.append(event)
        previous = event["event_sha256"]
    trace = {"schema": "evaluation_v5_1_natural_game_trace_v2", "scenario_plan_sha256": plan_hash, "cell_id": game_id, "state_blob_sha256": canonical_sha256(state), "template": scenario.NATURAL_TEMPLATE, "events": events}
    result = {"schema": "evaluation_v5_1_natural_game_result_v3", "scenario_plan_sha256": plan_hash, "cell_id": game_id, "trace_blob_sha256": canonical_sha256(trace), "status": "OK", "created_at_utc": "2026-07-14T01:00:00.000000Z"}
    safety = {"schema": "evaluation_v5_1_natural_game_safety_v3", "scenario_plan_sha256": plan_hash, "cell_id": game_id, "result_blob_sha256": canonical_sha256(result), "status": "SAFE"}
    return {"schema": scenario.SOURCE_TRACE_RECEIPT_SCHEMA, "protocol_id": "MCI_FAMILY_TRANSFER_V2", "scenario_sha256": "7" * 64, "game_id": game_id, "archive_id": archive_id, "lineage_id": lineage_id, "scenario_plan": plan, "cell_id": game_id, "state": state, "trace": trace, "result": result, "safety": safety}


def _fixture(lineage_count: int = 1, evaluation_id: str | None = None, verifier_container_sha256: str | None = None):
    if type(lineage_count) is not int or lineage_count < 1:
        raise ValueError("lineage_count must be a positive integer")
    keys = {role: _key() for role in ROLES}
    role_keys = {role: {"identity": f"{role}-operator", "public_key": keys[role][1]} for role in ROLES}
    blobs = {}

    def blob(value):
        raw = value if type(value) is bytes else canonical_json_bytes(value)
        digest = hashlib.sha256(raw).hexdigest()
        blobs[digest] = raw
        return digest, raw

    def headers(raw, media_type):
        return {"Date": "Mon, 14 Jul 2026 02:00:00 GMT", "ETag": f'"{hashlib.sha256(raw).hexdigest()[:12]}"', "Last-Modified": "2026-07-14T02:00:00Z", "Content-Type": media_type, "Content-Length": len(raw)}

    def header_blob(selected):
        return blob("".join(f"{field}: {selected[field]}\r\n" for field in ("Date", "ETag", "Last-Modified", "Content-Type", "Content-Length")).encode("ascii"))[0]

    def tls(url):
        return {"version": "TLSv1.3", "cipher": "TLS_AES_128_GCM_SHA256", "sni": "host.example", "endpoint": url, "peer_cert_chain_sha256s": ["c" * 64, "d" * 64]}

    routes = {
        "game_detail": {"url": "https://host.example/v1/game", "query": {"game_id": "${game_id}"}},
        "replay": {"url": "https://host.example/v1/replay", "query": {"game_id": "${game_id}"}},
        "participant": {"url": "https://host.example/v1/participant", "query": {"game_id": "${game_id}", "seat": "${seat}"}},
        "registration_request": {"url": "https://host.example/v1/registration/request", "query": {"archive_id": "${archive_id}", "lineage_id": "${lineage_id}"}},
        "registration_response": {"url": "https://host.example/v1/registration/response", "query": {"archive_id": "${archive_id}", "lineage_id": "${lineage_id}"}},
        "package": {"url": "https://host.example/v1/package", "query": {"archive_id": "${archive_id}", "lineage_id": "${lineage_id}"}},
    }
    records = []
    bodies = {}
    for index in range(lineage_count):
        suffix = str(index + 1)
        game_id = f"g-{suffix}"
        canary = {"participant_id": f"p-canary-{suffix}", "model_id": f"model-canary-{suffix}", "archive_id": f"archive-canary-{suffix}", "lineage_id": f"l-canary-{suffix}"}
        opponent = {"participant_id": f"p-opponent-{suffix}", "model_id": f"model-opponent-{suffix}", "archive_id": f"archive-opponent-{suffix}", "lineage_id": f"l-opponent-{suffix}"}
        canary_registration = {"archive_registration_id": f"registration-canary-{suffix}", "archive_registration_version": "v1"}
        opponent_registration = {"archive_registration_id": f"registration-opponent-{suffix}", "archive_registration_version": "v1"}
        canary_package, _ = blob(f"canary package {suffix}".encode("ascii"))
        opponent_package, _ = blob(f"opponent package {suffix}".encode("ascii"))
        record = {"index": index, "subject_id": f"canary-{suffix}", "game_id": game_id, "canary": canary, "opponent": opponent, "canary_registration": canary_registration, "opponent_registration": opponent_registration, "canary_package": canary_package, "opponent_package": opponent_package, "game_url": f"https://host.example/v1/games/{game_id}"}
        record["page_body"] = {"games": [{"game_id": game_id, "eligibility_time_utc": "2026-07-14T00:00:00Z", "archive_id": canary["archive_id"], "lineage_id": canary["lineage_id"], "canary_model_id": canary["model_id"], "canary_archive_id": canary["archive_id"], "opponent_model_id": opponent["model_id"], "opponent_archive_id": opponent["archive_id"], "game_url": record["game_url"]}], "next_cursor": None}
        record["page_hash"], record["page_raw"] = blob(record["page_body"])
        records.append(record)
        owner = f"game:{game_id}"
        bodies[("game_detail", owner)] = {"competition_id": "pokemon", "game_id": game_id, "server_started_at_utc": "2026-07-14T00:00:00Z", "server_ended_at_utc": "2026-07-14T01:00:00Z", "participants": [{"seat": 0, **canary, "score_decimal": "2"}, {"seat": 1, **opponent, "score_decimal": "1"}], "terminal": {"outcome": "canary_win"}}
        bodies[("replay", owner)] = {"game_id": game_id, "terminal": {"outcome": "canary_win"}}
        for seat, participant in enumerate((canary, opponent)):
            bodies[("participant", f"participant:{game_id}:{seat}")] = {"seat": seat, **participant}
            archive_owner = f"archive:{participant['archive_id']}:{participant['lineage_id']}"
            package = canary_package if seat == 0 else opponent_package
            registration = canary_registration if seat == 0 else opponent_registration
            bodies[("registration_request", archive_owner)] = {"archive_id": participant["archive_id"], "lineage_id": participant["lineage_id"], **registration}
            bodies[("registration_response", archive_owner)] = {"archive_id": participant["archive_id"], "lineage_id": participant["lineage_id"], **registration, "package_sha256": package}
    subjects = [{"subject_id": item["subject_id"], "competition_id": "pokemon", **item["canary_registration"], "archive_id": item["canary"]["archive_id"], "lineage_root_sha256": hashlib.sha256(f"root-{item['subject_id']}".encode("ascii")).hexdigest(), "lineage_revision": "r1", "lineage_id": item["canary"]["lineage_id"], "model_id": item["canary"]["model_id"], "initial_url": "https://host.example/v1/games", "initial_query": {"archive_id": item["canary"]["archive_id"], "lineage_id": item["canary"]["lineage_id"]}, "initial_query_order": ["archive_id", "lineage_id"], "parameter_encoding": "rfc3986", "forbidden_query_parameters": ["page", "page_size"]} for item in records]
    spec = {"schema": G05_SPEC_SCHEMA, "protocol_id": G05_PROTOCOL, "evaluation_id": evaluation_id or "eval-hosted-dev-1", "evaluation_schema_version": "v1", "endpoint_version": "v1", "registration_version": "v1", "competition_id": "pokemon", "role_scope": "G05_HOSTED_DEV_READ_ONLY", "collector_bindings": {"c1": {"account_id": "account-c1", "tenant_id": "tenant-c1", "entitlement": "entitlement-c1"}, "c2": {"account_id": "account-c2", "tenant_id": "tenant-c2", "entitlement": "entitlement-c2"}}, "prospective_subjects": subjects, "eligibility_window": {"starts_at_utc": "2026-07-14T00:00:00Z", "ends_at_utc": "2026-07-15T00:00:00Z"}, "eligibility_field": "eligibility_time_utc", "extraction_paths": {"game_id": "$.games[*].game_id", "eligibility_time": "$.games[*].eligibility_time_utc", "archive_id": "$.games[*].archive_id", "lineage_id": "$.games[*].lineage_id", "canary_model_id": "$.games[*].canary_model_id", "canary_archive_id": "$.games[*].canary_archive_id", "opponent_model_id": "$.games[*].opponent_model_id", "opponent_archive_id": "$.games[*].opponent_archive_id", "canonical_game_url": "$.games[*].game_url"}, "cursor_contract": {"request_parameter": "cursor", "response_path": "$.next_cursor", "terminal_null_required": True}, "pagination_contract": {"sort_field": "eligibility_time_utc", "direction": "asc", "page_size": 100, "duplicate_rule": "reject"}, "acquisition_routes": routes, "model_visible_columns": list(HOSTED_COLUMNS), "parser_sha256": "8" * 64, "collector_container_sha256": "9" * 64, "verifier_container_sha256": verifier_container_sha256 or "a" * 64, "source_engine_sha256": "4" * 64, "source_container_sha256": "5" * 64, "seed_commitment_sha256": "b" * 64, "exclusion_policy": "none"}
    spec_hash = canonical_sha256(spec)

    def page(label, item):
        selected = headers(item["page_raw"], "application/json")
        entry = {"subject_id": item["subject_id"], "ordinal": 0, "previous_page_sha256": None, "url": "https://host.example/v1/games", "query": {"archive_id": item["canary"]["archive_id"], "lineage_id": item["canary"]["lineage_id"]}, "account_id": f"account-{label}", "tenant_id": f"tenant-{label}", "entitlement": f"entitlement-{label}", "query_parameter_order": ["archive_id", "lineage_id"], "parameter_encoding": "rfc3986", "request_started_at_utc": "2026-07-14T02:00:00Z", "first_byte_at_utc": "2026-07-14T02:00:01Z", "response_completed_at_utc": "2026-07-14T02:01:00Z", "http_status": 200, "redirects": [], "headers": selected, "raw_headers_sha256": header_blob(selected), "tls": tls("https://host.example/v1/games"), "raw_body_length": len(item["page_raw"]), "raw_media_type": "application/json", "raw_sha256": item["page_hash"], "jcs_sha256": canonical_sha256(item["page_body"]), "projection_sha256": canonical_sha256(item["page_body"]), "extracted_ids": [item["game_id"]], "next_cursor": None, "parser_sha256": "8" * 64, "container_sha256": "9" * 64, "terminal_absence": True}
        return {**entry, "page_sha256": canonical_sha256(entry)}

    def route(kind, variables):
        template = routes[kind]
        return template["url"], {key: (str(variables[value[2:-1]]) if value.startswith("${") else value) for key, value in template["query"].items()}

    def acquisition(label, kind, owner, game_id, variables, value):
        url, query = route(kind, variables)
        if kind == "package":
            raw_hash, raw, jcs, projection, media_type = value, blobs[value], None, None, "application/octet-stream"
        else:
            raw_hash, raw = blob(value)
            jcs = projection = canonical_sha256(value)
            media_type = "application/json"
        selected = headers(raw, media_type)
        return {"kind": kind, "logical_owner": owner, "game_ids": [game_id], "url": url, "query": query, "account_id": f"account-{label}", "tenant_id": f"tenant-{label}", "entitlement": f"entitlement-{label}", "request_started_at_utc": "2026-07-14T02:02:00Z", "first_byte_at_utc": "2026-07-14T02:02:01Z", "response_completed_at_utc": "2026-07-14T02:03:00Z", "http_status": 200, "redirects": [], "headers": selected, "raw_headers_sha256": header_blob(selected), "tls": tls(url), "raw_body_length": len(raw), "raw_media_type": media_type, "raw_sha256": raw_hash, "jcs_sha256": jcs, "projection_sha256": projection, "discovery_refs": [], "parser_sha256": "8" * 64, "container_sha256": "9" * 64}

    def manifest(label):
        pages = [page(label, item) for item in records]
        page_refs = {item["game_id"]: pages[index]["page_sha256"] for index, item in enumerate(records)}
        entries = []
        for item in records:
            game_entry_start = len(entries)
            game_id, canary, opponent = item["game_id"], item["canary"], item["opponent"]
            game_owner = f"game:{game_id}"
            entries.extend((acquisition(label, "game_detail", game_owner, game_id, {"game_id": game_id}, bodies[("game_detail", game_owner)]), acquisition(label, "replay", game_owner, game_id, {"game_id": game_id}, bodies[("replay", game_owner)])))
            for seat, participant in enumerate((canary, opponent)):
                owner = f"participant:{game_id}:{seat}"
                entries.append(acquisition(label, "participant", owner, game_id, {"game_id": game_id, "seat": seat, **participant}, bodies[("participant", owner)]))
                archive_owner = f"archive:{participant['archive_id']}:{participant['lineage_id']}"
                package = item["canary_package"] if seat == 0 else item["opponent_package"]
                variables = {"archive_id": participant["archive_id"], "lineage_id": participant["lineage_id"]}
                entries.extend((acquisition(label, "registration_request", archive_owner, game_id, variables, bodies[("registration_request", archive_owner)]), acquisition(label, "registration_response", archive_owner, game_id, variables, bodies[("registration_response", archive_owner)]), acquisition(label, "package", archive_owner, game_id, variables, package)))
            for entry in entries[game_entry_start:]:
                entry["discovery_refs"] = [page_refs[game_id]]
        return {"schema": G05_COLLECTOR_MANIFEST_SCHEMA, "protocol_id": G05_PROTOCOL, "spec_sha256": spec_hash, "collector_id": f"collector-{label}", "operator_id": f"operator-{label}", "account_id": f"account-{label}", "tenant_id": f"tenant-{label}", "entitlement": f"entitlement-{label}", "host_id": f"host-{label}", "network_id": f"network-{label}", "implementation_sha256": ("f" if label == "c1" else "a") * 64, "parser_sha256": "8" * 64, "container_sha256": "9" * 64, "snapshot_started_at_utc": "2026-07-14T01:55:00Z", "signed_at_utc": "2026-07-14T02:10:00Z", "exchange_not_before_utc": "2026-07-14T02:11:00Z", "pages": pages, "acquisitions": entries}

    c1, c2 = manifest("c1"), manifest("c2")
    from evaluation_v5_1.hosted_dev_custody import _merkle_root
    bundle_hashes = sorted(blobs)
    bundle = {"schema": G05_EVIDENCE_BUNDLE_SCHEMA, "protocol_id": G05_PROTOCOL, "spec_sha256": spec_hash, "worm_root_sha256": _merkle_root(bundle_hashes, "test"), "artifact_sha256s": bundle_hashes}
    evidence_hash = canonical_sha256(bundle)
    traces = []
    for item in records:
        game_id, canary, opponent = item["game_id"], item["canary"], item["opponent"]
        row = {"competition_id": "pokemon", "game_id": game_id, "canary_participant_id": canary["participant_id"], "opponent_participant_id": opponent["participant_id"], "canary_seat": 0, "canary_archive_id": canary["archive_id"], "opponent_archive_id": opponent["archive_id"], "canary_lineage_id": canary["lineage_id"], "opponent_lineage_id": opponent["lineage_id"], "server_started_at_ns": 1783987200000000000, "server_ended_at_ns": 1783990800000000000, "canary_score_decimal": "2", "opponent_score_decimal": "1", "outcome_code": 1, "canary_package_sha256": item["canary_package"], "opponent_package_sha256": item["opponent_package"]}
        binding = canonical_sha256({"domain": "G05/BIND/v2", "spec_sha256": spec_hash, "evidence_bundle_sha256": evidence_hash, "row": row})
        seed = canonical_sha256({"domain": "G05/SEED/v2", "seed_commitment_sha256": "b" * 64, "binding_id": binding})
        source = _source_receipt(game_id, canary["archive_id"], canary["lineage_id"], item["canary_package"], item["opponent_package"], seed)
        trace = {"schema": G05_TRACE_SCHEMA, "protocol_id": G05_PROTOCOL, "spec_sha256": spec_hash, "binding_id": binding, "evidence_bundle_sha256": evidence_hash, "competition_id": "pokemon", "game_id": game_id, "canary_archive_id": canary["archive_id"], "opponent_archive_id": opponent["archive_id"], "canary_seat": 0, "canary_package_sha256": item["canary_package"], "opponent_package_sha256": item["opponent_package"], "source_engine_sha256": "4" * 64, "source_container_sha256": "5" * 64, "deterministic_seed_sha256": seed, "trace_root_sha256": scenario.derive_source_trace_receipt(source)["trace_root_sha256"], "relation": "archive-conditioned-local-rollout", "hosted_replay_or_rng_fidelity_claim": False, "hosted_fields": [], "source_trace_receipt": source}
        traces.append(_signed(G05_TRACE_SCHEMA, trace, keys["trace_attestor"]))
    data = {"role_keys": role_keys, "frozen_spec_envelope": _signed(G05_SPEC_SCHEMA, spec, keys["evaluation_authority"]), "spec_countersignature_envelope": _signed(G05_SPEC_COUNTERSIGNATURE_SCHEMA, {"schema": G05_SPEC_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "spec_sha256": spec_hash}, keys["validation_authority"]), "collector_c1_envelope": _signed(G05_COLLECTOR_MANIFEST_SCHEMA, c1, keys["collector_c1"]), "collector_c2_envelope": _signed(G05_COLLECTOR_MANIFEST_SCHEMA, c2, keys["collector_c2"]), "evidence_bundle_envelope": _signed(G05_EVIDENCE_BUNDLE_SCHEMA, bundle, keys["evidence_custodian"]), "trace_envelopes": traces, "raw_blobs": blobs}
    audit = derive_hosted_dev_custody_audit(**data)
    assert audit["decision"] == G05_DECISION, audit.get("reason")
    data["final_audit_authority_envelope"] = _signed(G05_AUDIT_SCHEMA, audit, keys["evaluation_authority"])
    data["final_audit_countersignature_envelope"] = _signed(G05_AUDIT_COUNTERSIGNATURE_SCHEMA, {"schema": G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "authority_audit_envelope_sha256": canonical_sha256(data["final_audit_authority_envelope"])}, keys["validation_authority"])
    return data, keys


def _result(data):
    return verify_hosted_dev_custody(**data)


def _refresh_final_chain(data, keys):
    audit = derive_hosted_dev_custody_audit(
        role_keys=data["role_keys"], frozen_spec_envelope=data["frozen_spec_envelope"],
        spec_countersignature_envelope=data["spec_countersignature_envelope"],
        collector_c1_envelope=data["collector_c1_envelope"], collector_c2_envelope=data["collector_c2_envelope"],
        evidence_bundle_envelope=data["evidence_bundle_envelope"], trace_envelopes=data["trace_envelopes"],
        raw_blobs=data["raw_blobs"],
    )
    assert audit["decision"] == G05_DECISION
    data["final_audit_authority_envelope"] = _signed(G05_AUDIT_SCHEMA, audit, keys["evaluation_authority"])
    data["final_audit_countersignature_envelope"] = _signed(G05_AUDIT_COUNTERSIGNATURE_SCHEMA, {"schema": G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "authority_audit_envelope_sha256": canonical_sha256(data["final_audit_authority_envelope"])}, keys["validation_authority"])


def _resign_manifest(data, keys, name, role):
    data[name] = _signed(G05_COLLECTOR_MANIFEST_SCHEMA, data[name]["payload"], keys[role])


def _resign_spec(data, keys):
    spec = data["frozen_spec_envelope"]["payload"]
    data["frozen_spec_envelope"] = _signed(G05_SPEC_SCHEMA, spec, keys["evaluation_authority"])
    data["spec_countersignature_envelope"] = _signed(
        G05_SPEC_COUNTERSIGNATURE_SCHEMA,
        {"schema": G05_SPEC_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "spec_sha256": canonical_sha256(spec)},
        keys["validation_authority"],
    )


def _registration_capture(data, kind, archive_id, lineage_id):
    owner = f"archive:{archive_id}:{lineage_id}"
    return next(
        capture for capture in data["collector_c1_envelope"]["payload"]["acquisitions"]
        if capture["kind"] == kind and capture["logical_owner"] == owner
    )


def _rehash_page(page):
    page["page_sha256"] = canonical_sha256({key: value for key, value in page.items() if key != "page_sha256"})


def _rebind_discovery_refs(payload):
    page_hash = payload["pages"][0]["page_sha256"]
    for acquisition in payload["acquisitions"]:
        acquisition["discovery_refs"] = [page_hash]


def _replace_capture_json(data, capture, value):
    raw = canonical_json_bytes(value)
    digest = hashlib.sha256(raw).hexdigest()
    data["raw_blobs"][digest] = raw
    capture["raw_sha256"] = digest
    capture["raw_body_length"] = len(raw)
    capture["headers"]["Content-Length"] = len(raw)
    raw_headers = "".join(f"{field}: {capture['headers'][field]}\r\n" for field in ("Date", "ETag", "Last-Modified", "Content-Type", "Content-Length")).encode("ascii")
    capture["raw_headers_sha256"] = hashlib.sha256(raw_headers).hexdigest()
    data["raw_blobs"][capture["raw_headers_sha256"]] = raw_headers
    capture["jcs_sha256"] = capture["projection_sha256"] = canonical_sha256(value)


def test_g05_accepts_exact_contract_and_dual_signed_final_receipt():
    data, _ = _fixture()
    result = validate_hosted_dev_custody_result_receipt(**data)
    assert result["decision"] == G05_DECISION
    assert result["authority"] is result["submission_authorized"] is result["sealed_holdout_access"] is result["candidate_development_authorized"] is False
    assert result["prefilter_count"] == result["eligible_count"] == result["game_count"] == 1
    assert result["excluded_count"] == result["duplicate_count"] == result["failure_count"] == result["orphan_artifact_count"] == 0
    assert set(result["per_game_evidence_roots"]) == {"g-1"}
    assert len(result["registration_evidence_roots"]) == 2
    assert HOSTED_COLUMNS == (
        "competition_id", "game_id", "canary_participant_id", "opponent_participant_id",
        "canary_seat", "canary_archive_id", "opponent_archive_id", "canary_lineage_id",
        "opponent_lineage_id", "server_started_at_ns", "server_ended_at_ns",
        "canary_score_decimal", "opponent_score_decimal", "outcome_code",
    )
    assert set(result["rows"][0]) == set(HOSTED_COLUMNS)
    assert {"canary_model_id", "opponent_model_id", "canary_package_sha256", "opponent_package_sha256", "model_target_decimal"}.isdisjoint(result["rows"][0])
    receipt_json = canonical_json_bytes(result).decode("utf-8")
    assert "model-canary-1" not in receipt_json
    assert data["trace_envelopes"][0]["payload"]["canary_package_sha256"] not in receipt_json
    assert result["game_trace_envelope_sha256"]["g-1"] == canonical_sha256(data["trace_envelopes"][0])


def test_g05_fixture_builds_15_distinct_complete_dev_lineages_for_gate_integration():
    data, _ = _fixture(lineage_count=15, evaluation_id="gate-dag-dev-15", verifier_container_sha256="f" * 64)
    result = validate_hosted_dev_custody_result_receipt(**data)
    assert result["decision"] == G05_DECISION
    assert result["game_count"] == result["eligible_count"] == 15
    assert len({row["canary_archive_id"] for row in result["rows"]}) == 15
    assert len(result["game_trace_envelope_sha256"]) == len(result["per_game_evidence_roots"]) == 15
    assert all(set(row) == set(HOSTED_COLUMNS) for row in result["rows"])


def test_g05_rejects_final_authority_and_validator_signature_chain_attacks():
    data, keys = _fixture()
    missing_authority = copy.deepcopy(data)
    missing_authority["final_audit_authority_envelope"] = None
    assert _result(missing_authority)["decision"] == "G05_EVIDENCE_INVALID"
    wrong_authority = copy.deepcopy(data)
    stale = copy.deepcopy(wrong_authority["final_audit_authority_envelope"]["payload"])
    stale["failure_count"] = 1
    stale["result_sha256"] = canonical_sha256({key: value for key, value in stale.items() if key != "result_sha256"})
    wrong_authority["final_audit_authority_envelope"] = _signed(G05_AUDIT_SCHEMA, stale, keys["evaluation_authority"])
    wrong_authority["final_audit_countersignature_envelope"] = _signed(G05_AUDIT_COUNTERSIGNATURE_SCHEMA, {"schema": G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "authority_audit_envelope_sha256": canonical_sha256(wrong_authority["final_audit_authority_envelope"])}, keys["validation_authority"])
    assert _result(wrong_authority)["decision"] == "G05_EVIDENCE_INVALID"
    missing_validator = copy.deepcopy(data)
    missing_validator["final_audit_countersignature_envelope"] = None
    assert _result(missing_validator)["decision"] == "G05_EVIDENCE_INVALID"
    wrong_validator = copy.deepcopy(data)
    wrong_validator["final_audit_countersignature_envelope"] = _signed(G05_AUDIT_COUNTERSIGNATURE_SCHEMA, {"schema": G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "authority_audit_envelope_sha256": "0" * 64}, keys["validation_authority"])
    assert _result(wrong_validator)["decision"] == "G05_EVIDENCE_INVALID"
    published_extra = copy.deepcopy(data)
    altered_audit = copy.deepcopy(published_extra["final_audit_authority_envelope"]["payload"])
    altered_audit["rows"][0]["canary_model_id"] = "model-canary-1"
    altered_audit["result_sha256"] = canonical_sha256({key: value for key, value in altered_audit.items() if key != "result_sha256"})
    published_extra["final_audit_authority_envelope"] = _signed(G05_AUDIT_SCHEMA, altered_audit, keys["evaluation_authority"])
    published_extra["final_audit_countersignature_envelope"] = _signed(G05_AUDIT_COUNTERSIGNATURE_SCHEMA, {"schema": G05_AUDIT_COUNTERSIGNATURE_SCHEMA, "protocol_id": G05_PROTOCOL, "authority_audit_envelope_sha256": canonical_sha256(published_extra["final_audit_authority_envelope"])}, keys["validation_authority"])
    assert _result(published_extra)["decision"] == "G05_EVIDENCE_INVALID"


def test_g05_rejects_every_normalized_universe_tuple_mutation():
    base, keys = _fixture()
    mutations = {
        "subject_id": "other-subject", "game_id": "g-2", "eligibility_time_utc": "2026-07-14T00:01:00Z",
        "archive_id": "archive-other", "lineage_id": "l-other", "canary_model_id": "model-other",
        "canary_archive_id": "archive-other", "opponent_model_id": "model-other", "opponent_archive_id": "archive-other",
        "game_url": "https://host.example/v1/games/g-2",
    }
    for field, replacement in mutations.items():
        data = copy.deepcopy(base)
        page = data["collector_c2_envelope"]["payload"]["pages"][0]
        if field == "subject_id":
            page[field] = replacement
        else:
            body = json.loads(data["raw_blobs"][page["raw_sha256"]].decode("utf-8"))
            body["games"][0][field] = replacement
            if field == "game_id":
                page["extracted_ids"] = [replacement]
            _replace_capture_json(data, page, body)
        _rehash_page(page)
        _resign_manifest(data, keys, "collector_c2_envelope", "collector_c2")
        assert _result(data)["decision"] == "G05_EVIDENCE_INVALID", field


def test_g05_binds_frozen_and_observed_archive_registration_identity():
    data, keys = _fixture()
    version_mismatch = copy.deepcopy(data)
    version_mismatch["frozen_spec_envelope"]["payload"]["prospective_subjects"][0]["archive_registration_version"] = "v2"
    _resign_spec(version_mismatch, keys)
    assert _result(version_mismatch)["decision"] == "G05_EVIDENCE_INVALID"

    capture_mutations = (
        ("registration_request", "archive-canary-1", "l-canary-1", "archive_registration_id", "registration-tamper-1"),
        ("registration_response", "archive-canary-1", "l-canary-1", "archive_registration_version", "v2"),
        ("registration_response", "archive-opponent-1", "l-opponent-1", "archive_registration_id", "registration-tamper-1"),
        ("registration_request", "archive-opponent-1", "l-opponent-1", "archive_registration_version", None),
    )
    for kind, archive_id, lineage_id, field, value in capture_mutations:
        changed = copy.deepcopy(data)
        capture = _registration_capture(changed, kind, archive_id, lineage_id)
        body = json.loads(changed["raw_blobs"][capture["raw_sha256"]].decode("utf-8"))
        if value is None:
            del body[field]
        else:
            body[field] = value
        _replace_capture_json(changed, capture, body)
        _resign_manifest(changed, keys, "collector_c1_envelope", "collector_c1")
        assert _result(changed)["decision"] == "G05_EVIDENCE_INVALID", (kind, archive_id, field)

    unbound = copy.deepcopy(data)
    for kind in ("registration_request", "registration_response"):
        capture = _registration_capture(unbound, kind, "archive-canary-1", "l-canary-1")
        body = json.loads(unbound["raw_blobs"][capture["raw_sha256"]].decode("utf-8"))
        body["archive_registration_id"] = "registration-tamper-1"
        body["archive_registration_version"] = "v1"
        _replace_capture_json(unbound, capture, body)
    _resign_manifest(unbound, keys, "collector_c1_envelope", "collector_c1")
    assert _result(unbound)["decision"] == "G05_EVIDENCE_INVALID"


def test_g05_rejects_new_contract_capture_and_pagination_boundaries():
    data, keys = _fixture()
    cases = []
    role_scope = copy.deepcopy(data)
    role_scope["frozen_spec_envelope"]["payload"]["role_scope"] = "WRITE"
    role_scope["frozen_spec_envelope"] = _signed(G05_SPEC_SCHEMA, role_scope["frozen_spec_envelope"]["payload"], keys["evaluation_authority"])
    cases.append(role_scope)
    account = copy.deepcopy(data)
    account["collector_c1_envelope"]["payload"]["account_id"] = "wrong-account"
    _resign_manifest(account, keys, "collector_c1_envelope", "collector_c1")
    cases.append(account)
    for mutation in ("empty", "query-order", "timing", "tls", "headers"):
        changed = copy.deepcopy(data)
        page = changed["collector_c1_envelope"]["payload"]["pages"][0]
        if mutation == "empty":
            body = {"games": [], "next_cursor": None}
            page["extracted_ids"] = []
            _replace_capture_json(changed, page, body)
        elif mutation == "query-order":
            page["query_parameter_order"] = ["lineage_id", "archive_id"]
        elif mutation == "timing":
            page["first_byte_at_utc"] = "2026-07-14T01:59:59Z"
        elif mutation == "tls":
            page["tls"]["sni"] = "other.example"
        else:
            bad = b"Date: wrong\r\n"
            digest = hashlib.sha256(bad).hexdigest()
            changed["raw_blobs"][digest] = bad
            page["raw_headers_sha256"] = digest
        _rehash_page(page)
        _resign_manifest(changed, keys, "collector_c1_envelope", "collector_c1")
        cases.append(changed)
    for changed in cases:
        assert _result(changed)["decision"] == "G05_EVIDENCE_INVALID"


def test_g05_requires_contiguous_redirects_to_the_final_tls_endpoint():
    data, keys = _fixture()
    final_url = "https://host.example/v1/games/final"
    for name, role in (("collector_c1_envelope", "collector_c1"), ("collector_c2_envelope", "collector_c2")):
        page = data[name]["payload"]["pages"][0]
        page["redirects"] = [{"status": 302, "url": "https://host.example/v1/games", "location": final_url}]
        page["tls"]["endpoint"] = final_url
        _rehash_page(page)
        _rebind_discovery_refs(data[name]["payload"])
        _resign_manifest(data, keys, name, role)
    _refresh_final_chain(data, keys)
    assert _result(data)["decision"] == G05_DECISION
    for redirects, endpoint in (
        ([{"status": 302, "url": "https://host.example/v1/wrong", "location": final_url}], final_url),
        ([{"status": 302, "url": "https://host.example/v1/games", "location": "https://host.example/v1/hop-1"}, {"status": 302, "url": "https://host.example/v1/wrong", "location": final_url}], final_url),
        ([{"status": 302, "url": "https://host.example/v1/games", "location": final_url}], "https://host.example/v1/games"),
    ):
        changed = copy.deepcopy(data)
        page = changed["collector_c1_envelope"]["payload"]["pages"][0]
        page["redirects"] = redirects
        page["tls"]["endpoint"] = endpoint
        _rehash_page(page)
        _resign_manifest(changed, keys, "collector_c1_envelope", "collector_c1")
        assert _result(changed)["decision"] == "G05_EVIDENCE_INVALID"
