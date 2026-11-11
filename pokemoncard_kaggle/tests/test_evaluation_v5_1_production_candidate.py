from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1 import production_candidate as pc
from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.exact_gate_v2 import (
    EXACT_V2_VERIFIER_ALLOWLIST,
    FAIL_DECISION,
    PASS_DECISION,
    _decode_ed25519_point,
    _ed25519_add,
    dependency_closure_root,
    encode_byte_evidence,
    validate_ed25519_public_key,
)


PROTOCOL = "MCI_FAMILY_TRANSFER_V2"
ED25519_MEDIA_TYPE = "application/vnd.ptcg.ed25519-public-key"
G11_MEDIA_TYPE = "application/vnd.ptcg.exact-gate-final-bundle+json"
ACCESS_FIELDS = (
    "candidate_reads",
    "holdout_reads",
    "evaluator_calls",
    "plaintext_exports",
    "network_egress",
    "mutable_mounts",
    "downloads",
    "symlink_or_aliases",
)
G12_ROLES = (
    "evaluator_publisher",
    "evaluator_custodian_1",
    "evaluator_custodian_2",
    "evaluator_custodian_3",
    "runner_operator",
    "exact_gate_authority",
    "validator",
)
G13_ROLES = (
    "builder",
    "selector",
    "archive_custodian_1",
    "archive_custodian_2",
    "g13_runner",
)
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_FIELD = 2**255 - 19
ORDER_EIGHT_ENCODING = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0"
    "d5dfac05d3c63339b13802886d53fc05"
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private, public


def _role(
    role: str, seed: int
) -> tuple[dict[str, object], tuple[Ed25519PrivateKey, bytes]]:
    key = _key(seed)
    return (
        {
            "schema_version": pc.ROLE_KEY_SCHEMA,
            "role": role,
            "principal_id": f"principal-{role}",
            "custodian_id": f"custodian-{role}",
            "public_key": encode_byte_evidence(
                key[1], media_type=ED25519_MEDIA_TYPE
            ),
        },
        key,
    )


def _signed(
    schema: str,
    media_type: str,
    payload: dict[str, object],
    key: tuple[Ed25519PrivateKey, bytes],
    domain: bytes,
) -> dict[str, object]:
    raw = canonical_json_bytes(payload)
    return {
        "schema_version": schema,
        "signer_key_id": validate_ed25519_public_key(key[1]),
        "payload": encode_byte_evidence(raw, media_type=media_type),
        "signature_ed25519_base64": base64.b64encode(
            key[0].sign(domain + len(raw).to_bytes(8, "big") + raw)
        ).decode("ascii"),
    }


def _dependency(
    gate_id: str,
    *,
    bundle_sha256: str | None = None,
    authority_payload_sha256: str | None = None,
    decision: str = PASS_DECISION,
) -> dict[str, object]:
    return {
        "gate_id": gate_id,
        "bundle_sha256": bundle_sha256 or _hash(f"bundle-{gate_id}"),
        "authority_payload_sha256": authority_payload_sha256
        or _hash(f"authority-{gate_id}"),
        "decision": decision,
    }


def _closure(
    gate_id: str, direct: list[dict[str, object]]
) -> tuple[list[dict[str, object]], list[dict[str, str]], str]:
    nodes = sorted(
        [*direct, _dependency("G00_TRUST_ROOTS")],
        key=lambda row: str(row["gate_id"]),
    )
    edges = [
        {"gate_id": gate_id, "dependency_gate_id": str(row["gate_id"])}
        for row in direct
    ]
    edges.extend(
        {
            "gate_id": str(row["gate_id"]),
            "dependency_gate_id": "G00_TRUST_ROOTS",
        }
        for row in direct
    )
    edges.sort(key=lambda row: (row["gate_id"], row["dependency_gate_id"]))
    return nodes, edges, dependency_closure_root(
        nodes, edges, current_gate_id=gate_id
    )


def _replace_dependency_decision(
    evidence: dict[str, Any], gate_id: str, decision: str
) -> None:
    for field in ("direct_dependencies", "transitive_dependencies"):
        for row in evidence[field]:
            if row["gate_id"] == gate_id:
                row["decision"] = decision
    evidence["dependency_closure_root"] = dependency_closure_root(
        evidence["transitive_dependencies"],
        evidence["transitive_edges"],
        current_gate_id=evidence["gate_id"],
    )


def _release_payload(
    evidence: dict[str, Any], role_record: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": pc.G12_RELEASE_SCHEMA,
        "campaign_root": evidence["campaign_root"],
        "evaluation_id": evidence["evaluation_id"],
        "evaluation_nonce": evidence["evaluation_nonce"],
        "ciphertext_sha256": evidence["registration"][
            "evaluator_ciphertext_sha256"
        ],
        "runner_measurement_sha256": evidence["registration"][
            "runner_measurement_sha256"
        ],
        "custodian_role": role_record["role"],
        "custodian_id": role_record["custodian_id"],
    }


def _g12_fixture() -> tuple[
    dict[str, Any],
    dict[str, tuple[Ed25519PrivateKey, bytes]],
]:
    role_records: list[dict[str, object]] = []
    keys: dict[str, tuple[Ed25519PrivateKey, bytes]] = {}
    for seed, role_name in enumerate(G12_ROLES, 1):
        record, key = _role(role_name, seed)
        role_records.append(record)
        keys[role_name] = key

    g11_raw = canonical_json_bytes({"synthetic": "G11 dependency bytes"})
    g11_sha256 = hashlib.sha256(g11_raw).hexdigest()
    g11_authority_sha256 = _hash("g11-authority-payload")
    direct = [
        _dependency(
            "G11_ONE_SHOT_TRANSFER_VALIDATION",
            bundle_sha256=g11_sha256,
            authority_payload_sha256=g11_authority_sha256,
        )
    ]
    nodes, edges, closure_root = _closure(pc.G12_GATE_ID, direct)
    ciphertext = b"opaque synthetic evaluator ciphertext"
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    provenance_root = _hash("publisher-provenance-root")
    measurement = _hash("registered-runner-measurement")
    input_root = _hash("g12-input-bundle")
    evidence: dict[str, Any] = {
        "schema_version": pc.G12_INPUT_SCHEMA,
        "protocol_id": PROTOCOL,
        "campaign_root": _hash("campaign-root"),
        "evaluation_id": "evaluation-g12-conformance",
        "evaluation_nonce": _hash("evaluation-nonce"),
        "gate_id": pc.G12_GATE_ID,
        "attempt": 0,
        "registered_dependency_gate_ids": [
            "G11_ONE_SHOT_TRANSFER_VALIDATION"
        ],
        "direct_dependencies": direct,
        "transitive_dependencies": nodes,
        "transitive_edges": edges,
        "registered_transitive_edges": deepcopy(edges),
        "dependency_closure_root": closure_root,
        "g11_bundle": encode_byte_evidence(g11_raw, media_type=G11_MEDIA_TYPE),
        "registration": {
            "g11_bundle_sha256": g11_sha256,
            "g11_authority_payload_sha256": g11_authority_sha256,
            "evaluator_ciphertext_sha256": ciphertext_sha256,
            "expected_plaintext_manifest_root": _hash("plaintext-manifest-root"),
            "publisher_provenance_root": provenance_root,
            "runner_measurement_sha256": measurement,
            "g12_runner_key_id": validate_ed25519_public_key(
                keys["runner_operator"][1]
            ),
        },
        "evaluator_ciphertext": encode_byte_evidence(
            ciphertext, media_type="application/octet-stream"
        ),
        "publisher_provenance": {
            "publisher_id": "official-evaluator-publisher",
            "capture_sha256s": sorted(
                [_hash("publisher-capture-a"), _hash("publisher-capture-b")]
            ),
            "provenance_root": provenance_root,
            "official_publisher_evidence": True,
        },
        "role_keys": role_records,
        "custodian_releases": [],
        "runner_evidence": {
            "runner_key_id": validate_ed25519_public_key(
                keys["runner_operator"][1]
            ),
            "measurement_sha256": measurement,
            "runtime_sha256": _hash("runner-runtime"),
            "registered_evaluator_sha256": ciphertext_sha256,
            "interface_loaded": True,
            "evaluator_invocations": 0,
            "plaintext_exports": 0,
        },
        "access_audit": {field: 0 for field in ACCESS_FIELDS},
        "transition": {
            "from_state": pc.EVALUATOR_SEALED,
            "to_state": pc.EVALUATOR_READY_LOCKED,
            "unseal_started": True,
            "replay_key": "g12-one-shot-replay",
            "history_root": _hash("g12-history"),
        },
        "freeze_replay": {
            "replay_key": "g12-one-shot-replay",
            "input_bundle_root": input_root,
            "conflicting_input_bundle_roots": [],
        },
        "input_bundle_root": input_root,
    }
    by_role = {record["role"]: record for record in role_records}
    evidence["custodian_releases"] = [
        _signed(
            pc.G12_RELEASE_SCHEMA,
            pc.G12_SIGNED_MEDIA_TYPE,
            _release_payload(evidence, by_role[role_name]),
            keys[role_name],
            pc.G12_DOMAIN,
        )
        for role_name in ("evaluator_custodian_1", "evaluator_custodian_2")
    ]
    return evidence, keys


def _statistics(wins: int, *, denominator: int = 10) -> dict[str, object]:
    metrics = [
        {
            "metric": "wins",
            "numerator": wins,
            "denominator": denominator,
            "excluded": 0,
            "intermediate_root": _hash(f"wins-{wins}-{denominator}"),
        }
    ]
    core = {
        "schema_version": "ptcg.g13.sufficient-statistics/v1",
        "metrics": metrics,
    }
    return {**core, "statistics_root": canonical_sha256(core)}


def _candidate(candidate_id: str, archive: bytes, wins: int) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "source_sha256": _hash(f"source-{candidate_id}"),
        "model_sha256": _hash(f"model-{candidate_id}"),
        "config_sha256": _hash(f"config-{candidate_id}"),
        "build_recipe_sha256": _hash(f"build-recipe-{candidate_id}"),
        "dependency_lock_sha256": _hash(f"dependency-lock-{candidate_id}"),
        "archive": encode_byte_evidence(
            archive, media_type="application/gzip"
        ),
        "dev_bundle_sha256": _hash(f"dev-bundle-{candidate_id}"),
        "build_log_sha256": _hash(f"build-log-{candidate_id}"),
        "statistics": _statistics(wins),
        "lineage_root": _hash(f"lineage-{candidate_id}"),
    }


def _selection_core(
    ranked_ids: list[str], selected_id: str, archive: bytes
) -> dict[str, object]:
    return {
        "ranked_candidate_ids": ranked_ids,
        "selected_candidate_id": selected_id,
        "selected_archive_sha256": hashlib.sha256(archive).hexdigest(),
        "selected_archive_length": len(archive),
        "manual_override": False,
    }


def _deposit_payload(
    evidence: dict[str, Any], role_record: dict[str, object]
) -> dict[str, object]:
    transcript = evidence["selection_transcript"]
    return {
        "schema_version": pc.G13_DEPOSIT_SCHEMA,
        "campaign_root": evidence["campaign_root"],
        "evaluation_id": evidence["evaluation_id"],
        "evaluation_nonce": evidence["evaluation_nonce"],
        "archive_sha256": transcript["selected_archive_sha256"],
        "archive_length": transcript["selected_archive_length"],
        "selection_root": transcript["selection_root"],
        "custodian_role": role_record["role"],
        "custodian_id": role_record["custodian_id"],
    }


def _resign_g13_deposits(
    evidence: dict[str, Any],
    keys: dict[str, tuple[Ed25519PrivateKey, bytes]],
) -> None:
    by_role = {record["role"]: record for record in evidence["role_keys"]}
    evidence["custody_deposits"] = [
        _signed(
            pc.G13_DEPOSIT_SCHEMA,
            pc.G13_SIGNED_MEDIA_TYPE,
            _deposit_payload(evidence, by_role[role_name]),
            keys[role_name],
            pc.G13_DOMAIN,
        )
        for role_name in ("archive_custodian_1", "archive_custodian_2")
    ]


def _g13_fixture() -> tuple[
    dict[str, Any],
    dict[str, tuple[Ed25519PrivateKey, bytes]],
]:
    role_records: list[dict[str, object]] = []
    keys: dict[str, tuple[Ed25519PrivateKey, bytes]] = {}
    for seed, role_name in enumerate(G13_ROLES, 20):
        record, key = _role(role_name, seed)
        role_records.append(record)
        keys[role_name] = key

    g05_dependency = _dependency("G05_DEV_SOURCE_COMPLETENESS")
    g12_dependency = _dependency(pc.G12_GATE_ID)
    direct = [g05_dependency, g12_dependency]
    nodes, edges, closure_root = _closure(pc.G13_GATE_ID, direct)
    universe_core: dict[str, object] = {
        "schema_version": "ptcg.g13.dev-mutation-universe/v1",
        "base_source_sha256": _hash("base-source"),
        "base_model_sha256": _hash("base-model"),
        "mutation_program_sha256": _hash("mutation-program"),
        "mutation_config_sha256": _hash("mutation-config"),
        "budget": 2,
        "seed_sha256s": sorted([_hash("seed-a"), _hash("seed-b")]),
        "forbidden_input_classes": ["EVALUATOR", "HOLDOUT"],
    }
    universe = {
        **universe_core,
        "universe_root": canonical_sha256(universe_core),
    }
    selection_spec = {
        "schema_version": "ptcg.g13.selection-spec/v1",
        "metric_order": [{"metric": "wins", "direction": "DESC"}],
        "tie_break": "CANDIDATE_ID_ASC",
        "max_candidate_count": 2,
    }
    archive_a = b"candidate-a exact archive bytes"
    archive_b = b"candidate-b exact archive bytes"
    candidates = [
        _candidate("candidate-b", archive_b, 8),
        _candidate("candidate-a", archive_a, 8),
    ]
    selection_core = _selection_core(
        ["candidate-a", "candidate-b"], "candidate-a", archive_a
    )
    transcript = {
        **selection_core,
        "selection_root": canonical_sha256(selection_core),
    }
    input_root = _hash("g13-input-bundle")
    evidence: dict[str, Any] = {
        "schema_version": pc.G13_INPUT_SCHEMA,
        "protocol_id": PROTOCOL,
        "campaign_root": _hash("campaign-root"),
        "evaluation_id": "evaluation-g13-conformance",
        "evaluation_nonce": _hash("evaluation-nonce"),
        "gate_id": pc.G13_GATE_ID,
        "attempt": 0,
        "registered_dependency_gate_ids": [
            "G05_DEV_SOURCE_COMPLETENESS",
            pc.G12_GATE_ID,
        ],
        "direct_dependencies": direct,
        "transitive_dependencies": nodes,
        "transitive_edges": edges,
        "registered_transitive_edges": deepcopy(edges),
        "dependency_closure_root": closure_root,
        "registration": {
            "g05_bundle_sha256": g05_dependency["bundle_sha256"],
            "g12_bundle_sha256": g12_dependency["bundle_sha256"],
            "dev_root_sha256": _hash("authenticated-dev-root"),
            "mutation_universe_root": universe["universe_root"],
            "selection_spec_sha256": canonical_sha256(selection_spec),
            "max_candidate_count": 2,
        },
        "role_keys": role_records,
        "mutation_universe": universe,
        "candidates": candidates,
        "selection_spec": selection_spec,
        "selection_transcript": transcript,
        "custody_deposits": [],
        "access_audit": {field: 0 for field in ACCESS_FIELDS},
        "transition": {
            "from_state": pc.DEV_MUTABLE,
            "to_state": pc.CANDIDATE_SELECTED_LOCKED,
            "freeze_started": True,
            "replay_key": "g13-one-shot-replay",
            "history_root": _hash("g13-history"),
        },
        "freeze_replay": {
            "replay_key": "g13-one-shot-replay",
            "input_bundle_root": input_root,
            "conflicting_input_bundle_roots": [],
        },
        "input_bundle_root": input_root,
    }
    _resign_g13_deposits(evidence, keys)
    return evidence, keys


def _synthetic_g12_pass() -> dict[str, object]:
    # Rejection-only diagnostic input. The production validator still appends
    # G13_G12_BINDING_MISMATCH and cannot treat this mapping as authority.
    return {"gate_id": pc.G12_GATE_ID, "decision": PASS_DECISION}


@pytest.fixture
def synthetic_g11(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pc, "_validate_g11_bundle", lambda *_args: None)


def _assert_zero_authority(result: dict[str, Any]) -> None:
    assert result["decision"] == FAIL_DECISION
    assert result["candidate_development_authorized"] is False
    assert result["evaluator_unseal_authorized"] is False
    assert result["sealed_holdout_access_authorized"] is False
    assert result["release_authorized"] is False
    assert result["submission_authorized"] is False


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _mixed_order_encoding(valid_encoding: bytes) -> bytes:
    prime = _decode_ed25519_point(
        valid_encoding, label="valid test point", reject_small_order=True
    )
    torsion = _decode_ed25519_point(
        ORDER_EIGHT_ENCODING,
        label="test torsion point",
        reject_small_order=False,
    )
    return _encode_point(_ed25519_add(prime, torsion))


def _mutate_signature(
    envelope: dict[str, Any],
    kind: str,
    key: tuple[Ed25519PrivateKey, bytes],
) -> None:
    signature = bytearray(
        base64.b64decode(envelope["signature_ed25519_base64"])
    )
    if kind == "forged":
        signature[:] = key[0].sign(b"forged release message")
    elif kind == "torsion":
        signature[:32] = b"\x01" + bytes(31)
    elif kind == "mixed_order":
        signature[:32] = _mixed_order_encoding(bytes(signature[:32]))
    else:
        assert kind == "noncanonical"
        signature[32:] = ED25519_ORDER.to_bytes(32, "little")
    envelope["signature_ed25519_base64"] = base64.b64encode(signature).decode(
        "ascii"
    )


def test_local_trust_and_exact_v2_allowlists_remain_empty() -> None:
    assert dict(pc.TRUSTED_VALID_ONLY_SERVICE_KEYS) == {}
    assert dict(EXACT_V2_VERIFIER_ALLOWLIST) == {}


def test_g12_complete_structural_path_stops_at_external_service(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["structural_validation_complete"] is True
    assert result["failure_codes"] == [
        "G12_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE"
    ]
    assert result["state"] == pc.EVALUATOR_BURNED
    assert len(evidence["custodian_releases"]) == 2


def test_g12_complete_pre_unseal_record_remains_sealed(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    evidence["transition"]["unseal_started"] = False
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["structural_validation_complete"] is True
    assert result["state"] == pc.EVALUATOR_SEALED


@pytest.mark.parametrize(
    "kind", ["forged", "torsion", "mixed_order", "noncanonical"]
)
def test_g12_rejects_adversarial_release_signatures(
    synthetic_g11: None, kind: str
) -> None:
    evidence, keys = _g12_fixture()
    _mutate_signature(
        evidence["custodian_releases"][0],
        kind,
        keys["evaluator_custodian_1"],
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_CUSTODY_QUORUM_INVALID"]
    assert result["state"] == pc.EVALUATOR_BURNED


@pytest.mark.parametrize(
    "kind", ["torsion", "mixed_order", "noncanonical"]
)
def test_g12_rejects_adversarial_role_public_keys(
    synthetic_g11: None, kind: str
) -> None:
    evidence, _ = _g12_fixture()
    record = evidence["role_keys"][0]
    valid = base64.b64decode(record["public_key"]["base64"])
    if kind == "torsion":
        invalid = b"\x01" + bytes(31)
    elif kind == "mixed_order":
        invalid = _mixed_order_encoding(valid)
    else:
        invalid = ED25519_FIELD.to_bytes(32, "little")
    record["public_key"] = encode_byte_evidence(
        invalid, media_type=ED25519_MEDIA_TYPE
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_ROLE_SEPARATION"]


@pytest.mark.parametrize(
    "alias_field",
    ["role", "principal_id", "custodian_id", "public_key"],
)
def test_g12_rejects_role_principal_custodian_and_key_aliasing(
    synthetic_g11: None, alias_field: str
) -> None:
    evidence, _ = _g12_fixture()
    evidence["role_keys"][1][alias_field] = deepcopy(
        evidence["role_keys"][0][alias_field]
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_ROLE_SEPARATION"]


def test_g12_propagates_failed_recursive_dependency(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    _replace_dependency_decision(
        evidence, "G11_ONE_SHOT_TRANSFER_VALIDATION", FAIL_DECISION
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["DEPENDENCY_FAILED"]
    assert result["structural_validation_complete"] is False


def test_g12_binds_registered_g11_dependency_hashes(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    evidence["registration"]["g11_bundle_sha256"] = _hash(
        "different-g11-bundle"
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_G11_BINDING_MISMATCH"]


def test_g12_rejects_ciphertext_mismatch(synthetic_g11: None) -> None:
    evidence, _ = _g12_fixture()
    evidence["evaluator_ciphertext"] = encode_byte_evidence(
        b"different ciphertext", media_type="application/octet-stream"
    )
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_CIPHERTEXT_MISMATCH"]


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("captures", [_hash("one-capture")]),
        ("official", False),
        ("root", _hash("unregistered-provenance-root")),
    ],
)
def test_g12_rejects_incomplete_or_unbound_provenance(
    synthetic_g11: None, mutation: str, value: object
) -> None:
    evidence, _ = _g12_fixture()
    field = {
        "captures": "capture_sha256s",
        "official": "official_publisher_evidence",
        "root": "provenance_root",
    }[mutation]
    evidence["publisher_provenance"][field] = value
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_PROVENANCE_INVALID"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("measurement_sha256", _hash("wrong-measurement")),
        ("runner_key_id", "ed25519-sha256:" + "0" * 64),
        ("registered_evaluator_sha256", _hash("wrong-evaluator")),
        ("interface_loaded", False),
        ("evaluator_invocations", 1),
        ("plaintext_exports", 1),
    ],
)
def test_g12_rejects_runner_measurement_or_premature_use(
    synthetic_g11: None, field: str, value: object
) -> None:
    evidence, _ = _g12_fixture()
    evidence["runner_evidence"][field] = value
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == [
        "G12_RUNNER_MEASUREMENT_MISMATCH"
    ]


@pytest.mark.parametrize(
    "field",
    [
        "candidate_reads",
        "holdout_reads",
        "evaluator_calls",
        "network_egress",
    ],
)
def test_g12_rejects_forbidden_access_and_egress(
    synthetic_g11: None, field: str
) -> None:
    evidence, _ = _g12_fixture()
    evidence["access_audit"][field] = 1
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == [
        "G12_FORBIDDEN_ACCESS_OR_EGRESS"
    ]


def test_g12_replay_conflict_burns_started_attempt(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    evidence["freeze_replay"]["conflicting_input_bundle_roots"] = [
        _hash("conflicting-g12-input")
    ]
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_FREEZE_CONFLICT"]
    assert result["state"] == pc.EVALUATOR_BURNED


def test_g12_invalid_transition_burns_claimed_started_attempt(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    evidence["transition"]["to_state"] = pc.EVALUATOR_SEALED
    result = pc.validate_g12_synthetic_structure(evidence)
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G12_INVALID_STATE"]
    assert result["state"] == pc.EVALUATOR_BURNED


def test_g13_complete_structural_recomputation_stops_at_external_service() -> None:
    evidence, _ = _g13_fixture()
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["structural_validation_complete"] is True
    assert result["failure_codes"] == [
        "G13_G12_BINDING_MISMATCH",
        "G13_TRUSTED_VALID_ONLY_SERVICE_UNAVAILABLE",
    ]
    assert result["state"] == pc.CANDIDATE_FREEZE_BURNED
    assert result["dependency_bundle_hashes"]


@pytest.mark.parametrize("duplicate", ["candidate_id", "archive"])
def test_g13_rejects_duplicate_candidate_ids_or_archive_hashes(
    duplicate: str,
) -> None:
    evidence, _ = _g13_fixture()
    if duplicate == "candidate_id":
        evidence["candidates"][1]["candidate_id"] = evidence["candidates"][0][
            "candidate_id"
        ]
    else:
        evidence["candidates"][1]["archive"] = deepcopy(
            evidence["candidates"][0]["archive"]
        )
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == [
        "G13_DUPLICATE_CANDIDATE_OR_ARCHIVE"
    ]


def test_g13_rejects_wrong_deterministic_ranking() -> None:
    evidence, _ = _g13_fixture()
    evidence["selection_transcript"]["ranked_candidate_ids"] = [
        "candidate-b",
        "candidate-a",
    ]
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == [
        "G13_RANKING_OR_TIEBREAK_MISMATCH"
    ]


def test_g13_rejects_manual_selection_override() -> None:
    evidence, _ = _g13_fixture()
    evidence["selection_transcript"]["manual_override"] = True
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_MANUAL_OVERRIDE"]


@pytest.mark.parametrize("mutation", ["missing_metric", "bad_root"])
def test_g13_rejects_incomplete_or_unbound_sufficient_statistics(
    mutation: str,
) -> None:
    evidence, _ = _g13_fixture()
    stats = evidence["candidates"][0]["statistics"]
    if mutation == "missing_metric":
        stats["metrics"] = []
    else:
        stats["statistics_root"] = _hash("wrong-statistics-root")
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_STATISTICS_INCOMPLETE"]


@pytest.mark.parametrize("field", ["evaluator_calls", "holdout_reads"])
def test_g13_rejects_evaluator_or_holdout_access(field: str) -> None:
    evidence, _ = _g13_fixture()
    evidence["access_audit"][field] = 1
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_FORBIDDEN_INPUT_OR_ACCESS"]


@pytest.mark.parametrize(
    "kind", ["forged", "torsion", "mixed_order", "noncanonical"]
)
def test_g13_rejects_forged_or_noncanonical_deposit_signatures(
    kind: str,
) -> None:
    evidence, keys = _g13_fixture()
    _mutate_signature(
        evidence["custody_deposits"][0],
        kind,
        keys["archive_custodian_1"],
    )
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_CUSTODY_MISMATCH"]


def test_g13_rejects_selection_archive_mismatch() -> None:
    evidence, keys = _g13_fixture()
    transcript = evidence["selection_transcript"]
    transcript["selected_archive_sha256"] = _hash("wrong-selected-archive")
    core = {key: value for key, value in transcript.items() if key != "selection_root"}
    transcript["selection_root"] = canonical_sha256(core)
    _resign_g13_deposits(evidence, keys)
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_SELECTION_MISMATCH"]


def test_g13_replay_conflict_burns_freeze() -> None:
    evidence, _ = _g13_fixture()
    evidence["freeze_replay"]["conflicting_input_bundle_roots"] = [
        _hash("conflicting-g13-input")
    ]
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_FREEZE_CONFLICT"]
    assert result["state"] == pc.CANDIDATE_FREEZE_BURNED


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("from_state", pc.CANDIDATE_FREEZE_PENDING),
        ("to_state", pc.DEV_MUTABLE),
        ("freeze_started", 1),
    ],
)
def test_g13_rejects_invalid_state_transitions(
    field: str, value: object
) -> None:
    evidence, _ = _g13_fixture()
    evidence["transition"][field] = value
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_INVALID_STATE"]
    assert result["state"] == pc.CANDIDATE_FREEZE_BURNED


@pytest.mark.parametrize(
    "gate_id", ["G05_DEV_SOURCE_COMPLETENESS", pc.G12_GATE_ID]
)
def test_g13_propagates_failed_recursive_dependencies(gate_id: str) -> None:
    evidence, _ = _g13_fixture()
    _replace_dependency_decision(evidence, gate_id, FAIL_DECISION)
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["DEPENDENCY_FAILED"]


def test_g13_dependency_hashes_are_gate_specific() -> None:
    evidence, _ = _g13_fixture()
    registration = evidence["registration"]
    registration["g05_bundle_sha256"], registration["g12_bundle_sha256"] = (
        registration["g12_bundle_sha256"],
        registration["g05_bundle_sha256"],
    )
    result = pc.validate_g13_synthetic_structure(
        evidence, g12_result=_synthetic_g12_pass()
    )
    _assert_zero_authority(result)
    assert result["failure_codes"] == ["G13_G12_BINDING_MISMATCH"]


def test_production_g12_entry_never_calls_synthetic_g11_structural_parse_complete(
    synthetic_g11: None,
) -> None:
    evidence, _ = _g12_fixture()
    result = pc.validate_g12_evaluator_readiness(evidence)
    _assert_zero_authority(result)
    assert result["syntax_validation_complete"] is True
    assert result["structural_validation_complete"] is False
    assert "G12_G11_BINDING_MISMATCH" in result["failure_codes"]
    assert result["decision"] == FAIL_DECISION


def test_production_g13_entry_never_accepts_caller_supplied_g12_mapping() -> None:
    evidence, _ = _g13_fixture()
    result = pc.validate_g13_candidate_freeze(
        evidence,
        g12_result=_synthetic_g12_pass(),
    )
    _assert_zero_authority(result)
    assert result["syntax_validation_complete"] is True
    assert result["structural_validation_complete"] is False
    assert "G13_G12_BINDING_MISMATCH" in result["failure_codes"]
    assert result["decision"] == FAIL_DECISION
