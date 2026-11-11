from __future__ import annotations

from hashlib import sha256
from types import MappingProxyType

import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.entropy_completeness import (
    EntropyCompletenessError,
    assess_entropy_completeness,
    compile_entropy_evidence,
    validate_entropy_evidence,
)


def _root(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


ROOTS = {
    "source_root_sha256": _root("source"),
    "derivative_root_sha256": _root("derivative"),
    "binary_root_sha256": _root("binary"),
    "toolchain_root_sha256": _root("toolchain"),
    "container_root_sha256": _root("container"),
}


def _valid() -> dict[str, object]:
    evidence = compile_entropy_evidence(
        **ROOTS,
        expected_translation_units=["tu-a", "tu-b"],
        compiler_ast_inventory=[
            {"translation_unit_id": "tu-a", "canonical_relative_path": "engine/A.cpp", "present": True, "ast_complete": True},
            {"translation_unit_id": "tu-b", "canonical_relative_path": "engine/B.cpp", "present": True, "ast_complete": True},
        ],
        ir_call_edges=[
            {"edge_id": "edge-a", "caller": "main", "callee": "step", "indirect": False, "unresolved": False, "resolved_target": "step"},
        ],
        linked_binary_records=[
            {"binary_record_id": "instruction-a", "record_kind": "INSTRUCTION", "symbol": "step", "dependency": "engine", "instruction": "CALL", "resolved": True, "forbidden": False},
            {"binary_record_id": "symbol-a", "record_kind": "SYMBOL", "symbol": "step", "dependency": "engine", "instruction": "ENTRY", "resolved": True, "forbidden": False},
        ],
        runtime_forbidden_syscall_observations=[
            {"observation_id": f"obs-{kind}", "forbidden_kind": kind, "observed": False, "stack_complete": True}
            for kind in ("dlopen", "getrandom", "rdrand", "syscall")
        ],
        mutation_test_detection_records=[
            {"mutation_id": "mutation-rng", "mutation_family": "entropy", "target_record_id": "edge-a", "executed": True, "bypass_detected": True, "expected_behavior_changed": True},
        ],
    )
    return evidence.canonical()


def _rehash(wire: dict[str, object]) -> None:
    wire["evidence_root_sha256"] = canonical_sha256(
        {key: wire[key] for key in sorted(wire) if key != "evidence_root_sha256"}
    )


def _assert_incomplete(wire: dict[str, object], detail: str) -> None:
    assessment = assess_entropy_completeness(wire)
    assert assessment.canonical()["state"] == "NO_UPLOAD"
    assert assessment.locally_collected_evidence_complete is False
    assert detail in assessment.details["closure_failures"]
    report = assessment.zero_authority_report()
    assert report["authority"] is False
    assert report["upload_authorized"] is False
    assert report["calibration_upload_authorized"] is False
    assert report["production_upload_authorized"] is False


def test_complete_local_closure_is_still_zero_authority() -> None:
    assessment = assess_entropy_completeness(_valid())
    assert assessment.locally_collected_evidence_complete is True
    report = assessment.zero_authority_report()
    assert report["state"] == "NO_UPLOAD"
    assert report["independent_audit_a_verified"] is False
    assert report["independent_audit_b_verified"] is False
    assert report["authority"] is False
    assert report["permits"] == []


def test_missing_translation_unit_is_not_complete() -> None:
    wire = _valid()
    wire["compiler_ast_inventory"] = wire["compiler_ast_inventory"][:1]
    _rehash(wire)
    _assert_incomplete(wire, "COMPILER_AST_CLOSURE_INCOMPLETE")


def test_unresolved_indirect_call_is_not_complete() -> None:
    wire = _valid()
    edge = wire["ir_call_edges"][0]
    edge["indirect"] = True
    edge["record_root_sha256"] = canonical_sha256({"schema": "eval.v6.3.1.entropy-ir-call-edge.v1", **{key: edge[key] for key in sorted(edge) if key != "record_root_sha256"}})
    _rehash(wire)
    _assert_incomplete(wire, "WHOLE_PROGRAM_IR_CLOSURE_INCOMPLETE")


@pytest.mark.parametrize("forbidden_kind", ["getrandom", "syscall", "rdrand", "dlopen"])
def test_forbidden_entropy_observation_is_not_complete(forbidden_kind: str) -> None:
    wire = _valid()
    row = next(row for row in wire["runtime_forbidden_syscall_observations"] if row["forbidden_kind"] == forbidden_kind)
    row["observed"] = True
    row["record_root_sha256"] = canonical_sha256({"schema": "eval.v6.3.1.entropy-runtime-observation.v1", **{key: row[key] for key in sorted(row) if key != "record_root_sha256"}})
    _rehash(wire)
    _assert_incomplete(wire, "RUNTIME_FORBIDDEN_SYSCALL_CLOSURE_INCOMPLETE")


def test_unpinned_toolchain_is_rejected() -> None:
    wire = _valid()
    wire["toolchain_root_sha256"] = None
    with pytest.raises(EntropyCompletenessError) as caught:
        validate_entropy_evidence(wire)
    assert caught.value.code == "ENTROPY_ROOT_INVALID"


def test_stale_record_root_binding_is_rejected() -> None:
    wire = _valid()
    wire["source_root_sha256"] = _root("stale-source")
    with pytest.raises(EntropyCompletenessError) as caught:
        validate_entropy_evidence(wire)
    assert caught.value.code == "ENTROPY_ROOT_BINDING_MISMATCH"


def test_mutation_bypass_not_detected_is_not_complete() -> None:
    wire = _valid()
    mutation = wire["mutation_test_detection_records"][0]
    mutation["bypass_detected"] = False
    mutation["record_root_sha256"] = canonical_sha256({"schema": "eval.v6.3.1.entropy-mutation-detection.v1", **{key: mutation[key] for key in sorted(mutation) if key != "record_root_sha256"}})
    _rehash(wire)
    _assert_incomplete(wire, "MUTATION_DETECTION_CLOSURE_INCOMPLETE")


def test_bool_as_int_is_rejected() -> None:
    wire = _valid()
    wire["compiler_ast_inventory"][0]["present"] = 1
    with pytest.raises(EntropyCompletenessError) as caught:
        validate_entropy_evidence(wire)
    assert caught.value.code == "ENTROPY_TYPE_CONFUSION"


def test_record_root_tampering_is_rejected_even_when_evidence_root_is_stale() -> None:
    wire = _valid()
    wire["linked_binary_records"][0]["symbol"] = "tampered"
    with pytest.raises(EntropyCompletenessError) as caught:
        validate_entropy_evidence(wire)
    assert caught.value.code == "ENTROPY_ROOT_STALE"


def test_positive_completeness_and_authority_claims_are_rejected() -> None:
    for field, value in (("completeness_claimed", True), ("authority", {**{"authority": True}, **{key: _valid()["authority"][key] for key in ("upload_authorized", "calibration_upload_authorized", "production_upload_authorized", "holdout_access_authorized", "sealed_holdout_access_authorized", "agent_modification_authorized", "permits")}})):
        wire = _valid()
        wire[field] = value
        _rehash(wire)
        with pytest.raises(EntropyCompletenessError) as caught:
            validate_entropy_evidence(wire)
        assert caught.value.code in {"ENTROPY_COMPLETENESS_CLAIM", "ENTROPY_AUTHORITY_CLAIM"}


def test_immutable_artifact_rechecks_root_after_object_tampering() -> None:
    evidence = validate_entropy_evidence(_valid())
    object.__setattr__(evidence, "_wire", MappingProxyType({**evidence._wire, "evidence_root_sha256": _root("tampered-root")}))
    with pytest.raises(EntropyCompletenessError) as caught:
        evidence.zero_authority_report()
    assert caught.value.code == "ENTROPY_ROOT_STALE"
