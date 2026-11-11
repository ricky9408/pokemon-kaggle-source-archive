from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation_v5_1.canonical import canonical_json_bytes, canonical_sha256
from evaluation_v5_1.exact_gate_v2 import (
    AUTHORITY_DOMAIN,
    AUTHORITY_ENVELOPE_SCHEMA,
    AUTHORITY_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_MEDIA_TYPE,
    AUTHORITY_PAYLOAD_SCHEMA,
    DurableReplayIndex,
    EVIDENCE_MANIFEST_SCHEMA,
    EXACT_V2_VERIFIER_ALLOWLIST,
    ExactGateV2Error,
    FINAL_BUNDLE_SCHEMA,
    MANIFEST_MEDIA_TYPE,
    PASS_DECISION,
    PROTOCOL_ID,
    REJECTED_DECISION,
    VALIDATOR_PAYLOAD_SCHEMA,
    VALIDATOR_ENVELOPE_SCHEMA,
    VALIDATOR_MEDIA_TYPE,
    VALIDATOR_PAYLOAD_MEDIA_TYPE,
    cross_check_validator_payload,
    decode_byte_evidence,
    dependency_closure_root,
    encode_byte_evidence,
    evidence_merkle_root,
    enforce_dependency_effect,
    parse_authority_payload,
    parse_validator_payload,
    signature_message,
    strict_canonical_json,
    validate_evidence_manifest,
    validate_registered_dependency_closure,
    verify_exact_gate_v2,
    verify_signed_payload_envelope,
    _decode_ed25519_point,
    _ed25519_add,
    _key_id,
    _validate_ed25519_signature_encoding,
)


def _hash(seed: int) -> str:
    return f"{seed:064x}"


def _key(seed: int) -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return private, public


def _signed_envelope(
    payload: dict[str, object],
    *,
    private: Ed25519PrivateKey,
    public: bytes,
) -> bytes:
    wrapper = encode_byte_evidence(
        canonical_json_bytes(payload),
        media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
    )
    envelope = {
        "schema_version": AUTHORITY_ENVELOPE_SCHEMA,
        "signer_key_id": f"ed25519-sha256:{hashlib.sha256(public).hexdigest()}",
        "payload": wrapper,
        "signature_ed25519_base64": base64.b64encode(
            private.sign(signature_message(domain=AUTHORITY_DOMAIN, payload_wrapper=wrapper))
        ).decode("ascii"),
    }
    return canonical_json_bytes(envelope)


def _authority_payload() -> dict[str, object]:
    dependencies = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "bundle_sha256": _hash(20),
            "authority_payload_sha256": _hash(21),
            "decision": PASS_DECISION,
        }
    ]
    return {
        "schema_version": AUTHORITY_PAYLOAD_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": _hash(1),
        "freeze_registry_epoch": 3,
        "freeze_registry_hash": _hash(2),
        "evaluation_entry_hash": _hash(3),
        "evaluation_id": "evaluation-20260714",
        "evaluation_nonce": _hash(4),
        "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        "attempt": 0,
        "frozen_spec_hash": _hash(5),
        "input_schema_hash": _hash(6),
        "output_schema_hash": _hash(7),
        "failure_code_registry_hash": _hash(8),
        "evidence_manifest_envelope_sha256": _hash(9),
        "evidence_manifest_root": _hash(10),
        "verifier_bundle_digest": _hash(11),
        "verifier_runtime_digest": _hash(12),
        "direct_dependencies": dependencies,
        "dependency_closure_root": dependency_closure_root(
            dependencies,
            [
                {
                    "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
                    "dependency_gate_id": "G00_TRUST_ROOTS",
                }
            ],
            current_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE",
        ),
        "input_bundle_root": _hash(13),
        "recomputed_outputs": {"artifact_count": 4, "integrity_failures": 0},
        "decision": PASS_DECISION,
        "failure_codes": [],
        "issued_at_ns": "1783990000000000000",
    }


def test_v1_cutover_has_no_v2_verifier_allowlist() -> None:
    assert dict(EXACT_V2_VERIFIER_ALLOWLIST) == {}
    def structural_envelope(schema: str, payload_media_type: str) -> bytes:
        return canonical_json_bytes(
            {
                "schema_version": schema,
                "signer_key_id": f"ed25519-sha256:{_hash(80)}",
                "payload": encode_byte_evidence(b"{}", media_type=payload_media_type),
                "signature_ed25519_base64": base64.b64encode(bytes(64)).decode("ascii"),
            }
        )
    bundle = {
        "schema_version": FINAL_BUNDLE_SCHEMA,
        "authority_envelope": encode_byte_evidence(
            structural_envelope(AUTHORITY_ENVELOPE_SCHEMA, AUTHORITY_PAYLOAD_MEDIA_TYPE),
            media_type=AUTHORITY_MEDIA_TYPE,
        ),
        "validator_envelope": encode_byte_evidence(
            structural_envelope(VALIDATOR_ENVELOPE_SCHEMA, VALIDATOR_PAYLOAD_MEDIA_TYPE),
            media_type=VALIDATOR_MEDIA_TYPE,
        ),
    }
    result = verify_exact_gate_v2(
        gate_id="G00_TRUST_ROOTS", final_bundle=bundle
    )
    assert result["decision"] == REJECTED_DECISION
    assert result["failure_codes"] == ["VERIFIER_NOT_ALLOWLISTED"]
    assert result["bundle_sha256"] == hashlib.sha256(
        canonical_json_bytes(bundle)
    ).hexdigest()

    noncanonical = canonical_json_bytes(bundle).replace(b'{"authority', b'{ "authority', 1)
    rejected = verify_exact_gate_v2(
        gate_id="G00_TRUST_ROOTS", final_bundle=noncanonical
    )
    assert rejected["decision"] == REJECTED_DECISION
    assert rejected["bundle_sha256"] is None


def test_strict_canonical_json_rejects_duplicate_float_and_negative_zero() -> None:
    assert strict_canonical_json(b'{"a":1}', label="fixture") == {"a": 1}
    for raw in (b'{"a":1,"a":1}', b'{"a":1.0}', b'{"a":-0}'):
        with pytest.raises(ExactGateV2Error):
            strict_canonical_json(raw, label="fixture")


def test_manifest_recomputes_exact_one_to_one_artifact_closure() -> None:
    contents = {
        "alpha": ("inputs/a.json", encode_byte_evidence(b"{}", media_type="application/json")),
        "beta": ("inputs/b.bin", encode_byte_evidence(b"b", media_type="application/octet-stream")),
    }
    entries = [
        {
            "artifact_id": artifact_id,
            "path": path,
            "decoded_length": content["decoded_length"],
            "sha256": content["sha256"],
            "media_type": content["media_type"],
        }
        for artifact_id, (path, content) in sorted(contents.items())
    ]
    manifest = {
        "schema_version": EVIDENCE_MANIFEST_SCHEMA,
        "evaluation_entry_hash": _hash(1),
        "evaluation_id": "evaluation-20260714",
        "evaluation_nonce": _hash(2),
        "gate_id": "G00_TRUST_ROOTS",
        "attempt": 0,
        "issued_at_ns": "1783990000000000000",
        "entries": entries,
        "merkle_root": evidence_merkle_root(entries),
    }
    wrapper = encode_byte_evidence(
        canonical_json_bytes(manifest), media_type=MANIFEST_MEDIA_TYPE
    )
    artifacts = [
        {"artifact_id": artifact_id, "path": path, "content": content}
        for artifact_id, (path, content) in sorted(contents.items())
    ]
    result = validate_evidence_manifest(wrapper, artifacts)
    assert result["artifact_count"] == 2
    assert result["merkle_root"] == manifest["merkle_root"]

    for mutation in ("missing", "extra", "bytes", "path", "root"):
        bad_artifacts = deepcopy(artifacts)
        bad_manifest = deepcopy(manifest)
        if mutation == "missing":
            bad_artifacts.pop()
        elif mutation == "extra":
            bad_artifacts.append(
                {
                    "artifact_id": "gamma",
                    "path": "inputs/c.bin",
                    "content": encode_byte_evidence(b"c", media_type="application/octet-stream"),
                }
            )
        elif mutation == "bytes":
            bad_artifacts[0]["content"] = encode_byte_evidence(
                b"changed", media_type="application/json"
            )
        elif mutation == "path":
            bad_artifacts[0]["path"] = "inputs/renamed.json"
        else:
            bad_manifest["merkle_root"] = _hash(99)
        bad_wrapper = encode_byte_evidence(
            canonical_json_bytes(bad_manifest), media_type=MANIFEST_MEDIA_TYPE
        )
        with pytest.raises(ExactGateV2Error):
            validate_evidence_manifest(bad_wrapper, bad_artifacts)


def test_manifest_merkle_commits_real_leaf_count_and_uses_indexed_padding() -> None:
    def row(name: str) -> dict[str, object]:
        raw = name.encode("ascii")
        return {
            "artifact_id": name,
            "path": f"inputs/{name}.bin",
            "decoded_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "media_type": "application/octet-stream",
        }

    three = [row("a"), row("b"), row("c")]
    four_with_duplicate_content = [*three, row("d")]
    four_with_duplicate_content[-1]["sha256"] = three[-1]["sha256"]
    four_with_duplicate_content[-1]["decoded_length"] = three[-1]["decoded_length"]
    assert evidence_merkle_root(three) != evidence_merkle_root(four_with_duplicate_content)
    assert [evidence_merkle_root(three[:count]) for count in range(4)] == [
        "dc4c8669df128318c5790c414c870cc76c585268552851e78d3ee8604dbec0e3",
        "dda10fd080a2bd3d859e6a34da473c15ed91645c11aa3957a9f0d8046f0d0d9a",
        "36c587ad4778f756337b3ffdb92bf891624682d2345959a8de277a95fff4792b",
        "45426b4a2848b3115612980d5af099ec697f1af807c03f8fa34619dd94a889d9",
    ]


def test_v2_signature_domain_and_exact_payload_bytes() -> None:
    private, public = _key(1)
    payload = _authority_payload()
    raw = _signed_envelope(payload, private=private, public=public)
    decoded = verify_signed_payload_envelope(
        raw,
        expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
        expected_payload_media_type="application/vnd.ptcg.exact-gate-authority-payload+json",
        public_key=public,
        domain=AUTHORITY_DOMAIN,
    )
    assert decoded == canonical_json_bytes(payload)

    changed = bytearray(raw)
    changed[-2] ^= 1
    with pytest.raises(ExactGateV2Error):
        verify_signed_payload_envelope(
            bytes(changed),
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type="application/vnd.ptcg.exact-gate-authority-payload+json",
            public_key=public,
            domain=AUTHORITY_DOMAIN,
        )

    wrapper = encode_byte_evidence(
        canonical_json_bytes(payload), media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE
    )
    old_hash_only_signature = private.sign(
        AUTHORITY_DOMAIN + b"\x00" + wrapper["sha256"].encode("ascii")
    )
    old_envelope = {
        "schema_version": AUTHORITY_ENVELOPE_SCHEMA,
        "signer_key_id": f"ed25519-sha256:{hashlib.sha256(public).hexdigest()}",
        "payload": wrapper,
        "signature_ed25519_base64": base64.b64encode(old_hash_only_signature).decode("ascii"),
    }
    with pytest.raises(ExactGateV2Error, match="signature verification failed"):
        verify_signed_payload_envelope(
            canonical_json_bytes(old_envelope),
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
            public_key=public,
            domain=AUTHORITY_DOMAIN,
        )


def test_v2_rejects_small_order_keys_and_noncanonical_signature_scalars() -> None:
    private, public = _key(7)
    raw = _signed_envelope(_authority_payload(), private=private, public=public)
    envelope = json.loads(raw)
    signature = bytearray(base64.b64decode(envelope["signature_ed25519_base64"]))
    order = 2**252 + 27742317777372353535851937790883648493
    signature[32:] = order.to_bytes(32, "little")
    envelope["signature_ed25519_base64"] = base64.b64encode(signature).decode("ascii")
    with pytest.raises(ExactGateV2Error, match="scalar is noncanonical"):
        verify_signed_payload_envelope(
            canonical_json_bytes(envelope),
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
            public_key=public,
            domain=AUTHORITY_DOMAIN,
        )

    identity_key = b"\x01" + bytes(31)
    with pytest.raises(ExactGateV2Error, match="small order"):
        verify_signed_payload_envelope(
            raw,
            expected_schema=AUTHORITY_ENVELOPE_SCHEMA,
            expected_payload_media_type=AUTHORITY_PAYLOAD_MEDIA_TYPE,
            public_key=identity_key,
            domain=AUTHORITY_DOMAIN,
        )


def test_v2_rejects_all_torsion_and_mixed_order_public_and_r_points() -> None:
    def encode_point(point: tuple[int, int]) -> bytes:
        x, y = point
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    order8 = _decode_ed25519_point(
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0"
            "d5dfac05d3c63339b13802886d53fc05"
        ),
        label="torsion generator",
        reject_small_order=False,
    )
    torsion = (0, 1)
    torsion_points: list[tuple[int, int]] = []
    for _ in range(8):
        torsion_points.append(torsion)
        torsion = _ed25519_add(torsion, order8)
    assert torsion == (0, 1)
    assert len(set(torsion_points)) == 8
    for point in torsion_points:
        with pytest.raises(ExactGateV2Error, match="small order"):
            _key_id(encode_point(point))

    private, public = _key(9)
    public_point = _decode_ed25519_point(
        public, label="valid public", reject_small_order=True
    )
    signature = private.sign(b"prime subgroup fixture")
    r_point = _decode_ed25519_point(
        signature[:32], label="valid R", reject_small_order=True
    )
    for point in torsion_points[1:]:
        mixed_public = encode_point(_ed25519_add(public_point, point))
        with pytest.raises(ExactGateV2Error, match="prime-order subgroup"):
            _key_id(mixed_public)
    mixed_r = encode_point(_ed25519_add(r_point, torsion_points[1]))
    with pytest.raises(ExactGateV2Error, match="prime-order subgroup"):
        _validate_ed25519_signature_encoding(mixed_r + signature[32:])


def test_authority_payload_uses_frozen_codes_and_no_caller_float() -> None:
    payload = _authority_payload()
    parsed = parse_authority_payload(
        canonical_json_bytes(payload), frozen_failure_codes=frozenset({"STATISTICAL_MARGIN_FAILED"})
    )
    assert parsed["decision"] == PASS_DECISION

    bad = deepcopy(payload)
    bad["recomputed_outputs"]["score"] = 0.5  # type: ignore[index]
    with pytest.raises((ExactGateV2Error, ValueError)):
        parse_authority_payload(
            canonical_json_bytes(bad),
            frozen_failure_codes=frozenset({"STATISTICAL_MARGIN_FAILED"}),
        )


def test_registered_dependency_closure_requires_g00_and_exact_edges() -> None:
    direct = [
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "bundle_sha256": _hash(1),
            "authority_payload_sha256": _hash(2),
            "decision": PASS_DECISION,
        }
    ]
    closure = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "bundle_sha256": _hash(3),
            "authority_payload_sha256": _hash(4),
            "decision": PASS_DECISION,
        },
        *direct,
    ]
    edges = [
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "dependency_gate_id": "G00_TRUST_ROOTS",
        },
        {
            "gate_id": "G02_ENGINE_EVENT_CAPABILITY",
            "dependency_gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        },
    ]
    result = validate_registered_dependency_closure(
        current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
        current_decision=PASS_DECISION,
        direct_dependencies=direct,
        registered_direct_gate_ids=["G01_CONSTITUTION_AND_CODE_FREEZE"],
        transitive_dependencies=closure,
        transitive_edges=edges,
        registered_transitive_edges=edges,
        expected_closure_root=dependency_closure_root(
            closure, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
        ),
    )
    assert [row["gate_id"] for row in result["nodes"]] == [
        "G00_TRUST_ROOTS",
        "G01_CONSTITUTION_AND_CODE_FREEZE",
    ]
    assert result["forced_failure_codes"] == []
    assert result["forced_decision"] == PASS_DECISION

    conflicting_direct = deepcopy(direct)
    conflicting_direct[0]["bundle_sha256"] = _hash(99)
    with pytest.raises(ExactGateV2Error, match="conflicts with its closure node"):
        validate_registered_dependency_closure(
            current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
            current_decision=PASS_DECISION,
            direct_dependencies=conflicting_direct,
            registered_direct_gate_ids=["G01_CONSTITUTION_AND_CODE_FREEZE"],
            transitive_dependencies=closure,
            transitive_edges=edges,
            registered_transitive_edges=edges,
            expected_closure_root=dependency_closure_root(
                closure, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
            ),
        )

    with pytest.raises(ExactGateV2Error, match="omits G00"):
        validate_registered_dependency_closure(
            current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
            current_decision=PASS_DECISION,
            direct_dependencies=direct,
            registered_direct_gate_ids=["G01_CONSTITUTION_AND_CODE_FREEZE"],
            transitive_dependencies=direct,
            transitive_edges=[edges[-1]],
            registered_transitive_edges=[edges[-1]],
            expected_closure_root=dependency_closure_root(
                direct, [edges[-1]], current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
            ),
        )


def test_valid_failed_dependency_propagates_without_invalidating_envelope() -> None:
    failed = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "bundle_sha256": _hash(3),
            "authority_payload_sha256": _hash(4),
            "decision": "FAIL_CLOSED",
        }
    ]
    edges = [
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "dependency_gate_id": "G00_TRUST_ROOTS",
        }
    ]
    result = validate_registered_dependency_closure(
        current_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE",
        current_decision=PASS_DECISION,
        direct_dependencies=failed,
        registered_direct_gate_ids=["G00_TRUST_ROOTS"],
        transitive_dependencies=failed,
        transitive_edges=edges,
        registered_transitive_edges=edges,
        expected_closure_root=dependency_closure_root(
            failed, edges, current_gate_id="G01_CONSTITUTION_AND_CODE_FREEZE"
        ),
    )
    assert result["recomputed_outputs"] == {
        "failed_dependency_gate_ids": ["G00_TRUST_ROOTS"]
    }
    assert result["forced_failure_codes"] == ["DEPENDENCY_FAILED"]
    assert result["forced_decision"] == "FAIL_CLOSED"
    enforced = enforce_dependency_effect(
        module_recomputed_outputs={"module_claimed_pass": True},
        module_failure_codes=[],
        dependency_result=result,
        frozen_failure_codes=frozenset({"DEPENDENCY_FAILED"}),
    )
    assert enforced == {
        "recomputed_outputs": {
            "module_claimed_pass": True,
            "failed_dependency_gate_ids": ["G00_TRUST_ROOTS"],
        },
        "failure_codes": ["DEPENDENCY_FAILED"],
        "decision": "FAIL_CLOSED",
    }


def test_dependency_graph_rejects_cycle_outside_current_direct_edge() -> None:
    nodes = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "bundle_sha256": _hash(1),
            "authority_payload_sha256": _hash(2),
            "decision": PASS_DECISION,
        },
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "bundle_sha256": _hash(3),
            "authority_payload_sha256": _hash(4),
            "decision": PASS_DECISION,
        },
    ]
    edges = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "dependency_gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        },
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "dependency_gate_id": "G00_TRUST_ROOTS",
        },
        {
            "gate_id": "G02_ENGINE_EVENT_CAPABILITY",
            "dependency_gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        },
    ]
    with pytest.raises(ExactGateV2Error, match="reachable cycle"):
        validate_registered_dependency_closure(
            current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
            current_decision=PASS_DECISION,
            direct_dependencies=[nodes[1]],
            registered_direct_gate_ids=["G01_CONSTITUTION_AND_CODE_FREEZE"],
            transitive_dependencies=nodes,
            transitive_edges=edges,
            registered_transitive_edges=edges,
            expected_closure_root=dependency_closure_root(
                nodes, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
            ),
        )


def test_dependency_graph_root_is_permutation_invariant_and_registry_exact() -> None:
    nodes = [
        {
            "gate_id": "G00_TRUST_ROOTS",
            "bundle_sha256": _hash(1),
            "authority_payload_sha256": _hash(2),
            "decision": PASS_DECISION,
        },
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "bundle_sha256": _hash(3),
            "authority_payload_sha256": _hash(4),
            "decision": PASS_DECISION,
        },
    ]
    edges = [
        {
            "gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
            "dependency_gate_id": "G00_TRUST_ROOTS",
        },
        {
            "gate_id": "G02_ENGINE_EVENT_CAPABILITY",
            "dependency_gate_id": "G01_CONSTITUTION_AND_CODE_FREEZE",
        },
    ]
    expected = dependency_closure_root(
        nodes, edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
    )
    assert dependency_closure_root(
        list(reversed(nodes)),
        list(reversed(edges)),
        current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
    ) == expected

    with pytest.raises(ExactGateV2Error, match="registered full DAG"):
        validate_registered_dependency_closure(
            current_gate_id="G02_ENGINE_EVENT_CAPABILITY",
            current_decision=PASS_DECISION,
            direct_dependencies=[nodes[1]],
            registered_direct_gate_ids=["G01_CONSTITUTION_AND_CODE_FREEZE"],
            transitive_dependencies=nodes,
            transitive_edges=edges,
            registered_transitive_edges=edges[:-1],
            expected_closure_root=expected,
        )

    with pytest.raises(ExactGateV2Error, match="duplicate node"):
        dependency_closure_root(
            [*nodes, nodes[0]], edges, current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
        )
    with pytest.raises(ExactGateV2Error, match="duplicate edge"):
        dependency_closure_root(
            nodes, [*edges, edges[0]], current_gate_id="G02_ENGINE_EVENT_CAPABILITY"
        )


def test_validator_binds_exact_authority_bytes_and_independent_hashes() -> None:
    authority = _authority_payload()
    authority_payload_raw = canonical_json_bytes(authority)
    authority_envelope_raw = b'{"exact":"authority envelope bytes"}'
    validator = {
        "schema_version": VALIDATOR_PAYLOAD_SCHEMA,
        "protocol_id": PROTOCOL_ID,
        "campaign_root": authority["campaign_root"],
        "validation_registry_epoch": 4,
        "validation_registry_hash": _hash(30),
        "evaluation_id": authority["evaluation_id"],
        "evaluation_nonce": authority["evaluation_nonce"],
        "gate_id": authority["gate_id"],
        "attempt": 0,
        "authority_envelope_sha256": hashlib.sha256(authority_envelope_raw).hexdigest(),
        "authority_envelope_decoded_length": len(authority_envelope_raw),
        "authority_payload_sha256": hashlib.sha256(authority_payload_raw).hexdigest(),
        "input_bundle_root": authority["input_bundle_root"],
        "verifier_bundle_digest": authority["verifier_bundle_digest"],
        "verifier_runtime_digest": authority["verifier_runtime_digest"],
        "validator_recomputed_outputs_sha256": canonical_sha256(authority["recomputed_outputs"]),
        "validator_failure_codes_sha256": canonical_sha256(authority["failure_codes"]),
        "decision": authority["decision"],
        "issued_at_ns": "1783990000000000001",
    }
    parsed = parse_validator_payload(canonical_json_bytes(validator))
    cross_check_validator_payload(
        authority_envelope_raw=authority_envelope_raw,
        authority_payload_raw=authority_payload_raw,
        authority_payload=authority,
        validator_payload=parsed,
    )

    for field in (
        "authority_envelope_sha256",
        "validator_recomputed_outputs_sha256",
        "validator_failure_codes_sha256",
        "input_bundle_root",
    ):
        bad = deepcopy(parsed)
        bad[field] = _hash(99)
        with pytest.raises(ExactGateV2Error):
            cross_check_validator_payload(
                authority_envelope_raw=authority_envelope_raw,
                authority_payload_raw=authority_payload_raw,
                authority_payload=authority,
                validator_payload=bad,
            )


def test_local_replay_index_cannot_occupy_authoritative_slot(tmp_path) -> None:
    path = tmp_path / "replay.sqlite3"
    index = DurableReplayIndex(str(path))
    kwargs = {
        "campaign_root": _hash(1),
        "evaluation_id": "evaluation-20260714",
        "evaluation_nonce": _hash(2),
        "gate_id": "G00_TRUST_ROOTS",
        "attempt": 0,
        "bundle_sha256": _hash(3),
    }
    with pytest.raises(ExactGateV2Error, match="trusted valid-only replay service"):
        index.record(**kwargs)
    index.close()


def test_byte_wrapper_rejects_bool_length_and_hash_mutation() -> None:
    wrapper = encode_byte_evidence(b"abc", media_type="application/octet-stream")
    assert decode_byte_evidence(wrapper) == b"abc"
    for field, value in (
        ("decoded_length", True),
        ("sha256", _hash(99)),
        ("base64", "YWJj\n"),
    ):
        bad = dict(wrapper)
        bad[field] = value
        with pytest.raises(ExactGateV2Error):
            decode_byte_evidence(bad)
