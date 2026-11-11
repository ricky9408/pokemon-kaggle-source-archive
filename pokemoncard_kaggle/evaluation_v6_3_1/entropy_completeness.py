"""Zero-authority compiler and binary entropy-evidence sidecar.

This module validates explicit evidence records.  It intentionally does not
scan source text, disassemble a host binary, execute a program, or infer
coverage from a caller-supplied boolean.  A structurally valid artifact is
still only local evidence and can never authorize an upload.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256


ENTROPY_COMPLETENESS_SCHEMA = "eval.v6.3.1.entropy-completeness.v1"
ENTROPY_COMPLETENESS_MODE = "TEST_ONLY/OFFLINE_ZERO_AUTHORITY"
ASSESSMENT_SCHEMA = "eval.v6.3.1.entropy-completeness-assessment.v1"

AST_SCHEMA = "eval.v6.3.1.entropy-ast-record.v1"
IR_SCHEMA = "eval.v6.3.1.entropy-ir-call-edge.v1"
BINARY_SCHEMA = "eval.v6.3.1.entropy-linked-binary-record.v1"
RUNTIME_SCHEMA = "eval.v6.3.1.entropy-runtime-observation.v1"
MUTATION_SCHEMA = "eval.v6.3.1.entropy-mutation-detection.v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")

FORBIDDEN_ENTROPY_KINDS = ("dlopen", "getrandom", "rdrand", "syscall")
RECORD_CATEGORIES = (
    "compiler_ast_inventory",
    "ir_call_edges",
    "linked_binary_records",
    "runtime_forbidden_syscall_observations",
    "mutation_test_detection_records",
)

_ROOT_FIELDS = (
    "source_root_sha256",
    "derivative_root_sha256",
    "binary_root_sha256",
    "toolchain_root_sha256",
    "container_root_sha256",
)
_AUTHORITY_FIELDS = (
    "authority",
    "upload_authorized",
    "calibration_upload_authorized",
    "production_upload_authorized",
    "holdout_access_authorized",
    "sealed_holdout_access_authorized",
    "agent_modification_authorized",
    "permits",
)
_EXPECTED_AUTHORITY = {
    "authority": False,
    "upload_authorized": False,
    "calibration_upload_authorized": False,
    "production_upload_authorized": False,
    "holdout_access_authorized": False,
    "sealed_holdout_access_authorized": False,
    "agent_modification_authorized": False,
    "permits": [],
}
_COMMON_RECORD_FIELDS = frozenset((*_ROOT_FIELDS, "record_root_sha256"))
_CATEGORY_SCHEMAS = {
    "compiler_ast_inventory": AST_SCHEMA,
    "ir_call_edges": IR_SCHEMA,
    "linked_binary_records": BINARY_SCHEMA,
    "runtime_forbidden_syscall_observations": RUNTIME_SCHEMA,
    "mutation_test_detection_records": MUTATION_SCHEMA,
}
_CATEGORY_FIELDS = {
    "compiler_ast_inventory": frozenset({"translation_unit_id", "canonical_relative_path", "present", "ast_complete"}),
    "ir_call_edges": frozenset({"edge_id", "caller", "callee", "indirect", "unresolved", "resolved_target"}),
    "linked_binary_records": frozenset({"binary_record_id", "record_kind", "symbol", "dependency", "instruction", "resolved", "forbidden"}),
    "runtime_forbidden_syscall_observations": frozenset({"observation_id", "forbidden_kind", "observed", "stack_complete"}),
    "mutation_test_detection_records": frozenset({"mutation_id", "mutation_family", "target_record_id", "executed", "bypass_detected", "expected_behavior_changed"}),
}
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "mode",
        *_ROOT_FIELDS,
        "expected_translation_units",
        *RECORD_CATEGORIES,
        "completeness_claimed",
        "authority",
        "evidence_root_sha256",
    }
)


class EntropyCompletenessError(ValueError):
    """A compiler/binary entropy-evidence artifact failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> EntropyCompletenessError:
    return EntropyCompletenessError(code, message)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise _fail("ENTROPY_ROOT_INVALID", f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise _fail("ENTROPY_RECORD_INVALID", f"{label} must be a canonical identifier")
    return value


def _path(value: Any, label: str) -> str:
    if type(value) is not str or PATH_RE.fullmatch(value) is None or value in {".", ".."}:
        raise _fail("ENTROPY_RECORD_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise _fail("ENTROPY_TYPE_CONFUSION", f"{label} must be a JSON boolean")
    return value


def _optional_identifier(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, label)


def _record_root(schema: str, record: Mapping[str, Any]) -> str:
    return canonical_sha256({"schema": schema, **{key: record[key] for key in sorted(record) if key != "record_root_sha256"}})


def _authority() -> dict[str, Any]:
    return {
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _common_record(record: Mapping[str, Any], roots: Mapping[str, str | None], *, binary_bound: bool) -> dict[str, Any]:
    result = dict(record)
    for field in _ROOT_FIELDS:
        value = roots[field]
        if field == "binary_root_sha256" and not binary_bound:
            result[field] = None
        else:
            result[field] = _sha(value, field)
    return result


def _materialize_record(category: str, record: Mapping[str, Any], roots: Mapping[str, str | None], *, binary_bound: bool) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise _fail("ENTROPY_RECORD_INVALID", f"{category} record must be a mapping")
    fields = set(record)
    if fields != _CATEGORY_FIELDS[category]:
        raise _fail("ENTROPY_RECORD_SCHEMA_INVALID", f"{category} record fields are not exact")
    result = _common_record(record, roots, binary_bound=binary_bound)
    result["record_root_sha256"] = _record_root(_CATEGORY_SCHEMAS[category], result)
    return result


def compile_entropy_evidence(
    *,
    source_root_sha256: str,
    derivative_root_sha256: str,
    binary_root_sha256: str,
    toolchain_root_sha256: str,
    container_root_sha256: str,
    expected_translation_units: Sequence[str],
    compiler_ast_inventory: Sequence[Mapping[str, Any]],
    ir_call_edges: Sequence[Mapping[str, Any]],
    linked_binary_records: Sequence[Mapping[str, Any]],
    runtime_forbidden_syscall_observations: Sequence[Mapping[str, Any]],
    mutation_test_detection_records: Sequence[Mapping[str, Any]],
) -> "EntropyEvidence":
    """Compile explicit category records into a canonical, zero-authority artifact."""

    roots: dict[str, str | None] = {
        "source_root_sha256": _sha(source_root_sha256, "source_root_sha256"),
        "derivative_root_sha256": _sha(derivative_root_sha256, "derivative_root_sha256"),
        "binary_root_sha256": _sha(binary_root_sha256, "binary_root_sha256"),
        "toolchain_root_sha256": _sha(toolchain_root_sha256, "toolchain_root_sha256"),
        "container_root_sha256": _sha(container_root_sha256, "container_root_sha256"),
    }
    expected = list(expected_translation_units)
    if not expected or any(type(item) is not str for item in expected) or expected != sorted(set(expected)):
        raise _fail("ENTROPY_TU_INVENTORY_INVALID", "expected translation units must be sorted and unique identifiers")
    records = {
        "compiler_ast_inventory": [_materialize_record("compiler_ast_inventory", item, roots, binary_bound=False) for item in compiler_ast_inventory],
        "ir_call_edges": [_materialize_record("ir_call_edges", item, roots, binary_bound=False) for item in ir_call_edges],
        "linked_binary_records": [_materialize_record("linked_binary_records", item, roots, binary_bound=True) for item in linked_binary_records],
        "runtime_forbidden_syscall_observations": [_materialize_record("runtime_forbidden_syscall_observations", item, roots, binary_bound=True) for item in runtime_forbidden_syscall_observations],
        "mutation_test_detection_records": [_materialize_record("mutation_test_detection_records", item, roots, binary_bound=True) for item in mutation_test_detection_records],
    }
    for category in RECORD_CATEGORIES:
        records[category].sort(key=lambda item: _record_sort_key(category, item))
    payload: dict[str, Any] = {
        "schema": ENTROPY_COMPLETENESS_SCHEMA,
        "mode": ENTROPY_COMPLETENESS_MODE,
        **roots,
        "expected_translation_units": expected,
        **records,
        "completeness_claimed": False,
        "authority": _authority(),
    }
    payload["evidence_root_sha256"] = canonical_sha256(payload)
    return validate_entropy_evidence(payload)


def _record_sort_key(category: str, record: Mapping[str, Any]) -> tuple[str, ...]:
    if category == "compiler_ast_inventory":
        return (record["canonical_relative_path"], record["translation_unit_id"])
    if category == "ir_call_edges":
        return (record["caller"], record["edge_id"])
    if category == "linked_binary_records":
        return (record["record_kind"], record["binary_record_id"])
    if category == "runtime_forbidden_syscall_observations":
        return (record["forbidden_kind"], record["observation_id"])
    return (record["mutation_family"], record["mutation_id"])


def _validate_record(category: str, value: Any, roots: Mapping[str, str], index: int) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _COMMON_RECORD_FIELDS | _CATEGORY_FIELDS[category]:
        raise _fail("ENTROPY_RECORD_SCHEMA_INVALID", f"{category}[{index}] fields are not exact")
    parsed = dict(value)
    for field in ("source_root_sha256", "derivative_root_sha256", "toolchain_root_sha256", "container_root_sha256"):
        if _sha(parsed[field], f"{category}[{index}].{field}") != roots[field]:
            raise _fail("ENTROPY_ROOT_BINDING_MISMATCH", f"{category}[{index}] is bound to a stale {field}")
    binary = parsed["binary_root_sha256"]
    if category in {"compiler_ast_inventory", "ir_call_edges"}:
        if binary is not None:
            raise _fail("ENTROPY_ROOT_BINDING_MISMATCH", f"{category}[{index}] cannot bind a binary root before linking")
    elif _sha(binary, f"{category}[{index}].binary_root_sha256") != roots["binary_root_sha256"]:
        raise _fail("ENTROPY_ROOT_BINDING_MISMATCH", f"{category}[{index}] is bound to a stale binary root")
    _sha(parsed["record_root_sha256"], f"{category}[{index}].record_root_sha256")

    if category == "compiler_ast_inventory":
        _identifier(parsed["translation_unit_id"], f"{category}[{index}].translation_unit_id")
        _path(parsed["canonical_relative_path"], f"{category}[{index}].canonical_relative_path")
        _bool(parsed["present"], f"{category}[{index}].present")
        _bool(parsed["ast_complete"], f"{category}[{index}].ast_complete")
    elif category == "ir_call_edges":
        for field in ("edge_id", "caller", "callee"):
            _identifier(parsed[field], f"{category}[{index}].{field}")
        _bool(parsed["indirect"], f"{category}[{index}].indirect")
        _bool(parsed["unresolved"], f"{category}[{index}].unresolved")
        _optional_identifier(parsed["resolved_target"], f"{category}[{index}].resolved_target")
    elif category == "linked_binary_records":
        _identifier(parsed["binary_record_id"], f"{category}[{index}].binary_record_id")
        if parsed["record_kind"] not in {"SYMBOL", "DEPENDENCY", "INSTRUCTION"}:
            raise _fail("ENTROPY_RECORD_INVALID", f"{category}[{index}] has an unknown record kind")
        _identifier(parsed["symbol"], f"{category}[{index}].symbol")
        _identifier(parsed["dependency"], f"{category}[{index}].dependency")
        _identifier(parsed["instruction"], f"{category}[{index}].instruction")
        _bool(parsed["resolved"], f"{category}[{index}].resolved")
        _bool(parsed["forbidden"], f"{category}[{index}].forbidden")
    elif category == "runtime_forbidden_syscall_observations":
        _identifier(parsed["observation_id"], f"{category}[{index}].observation_id")
        kind = parsed["forbidden_kind"]
        if type(kind) is not str or kind.lower() not in FORBIDDEN_ENTROPY_KINDS:
            raise _fail("ENTROPY_FORBIDDEN_KIND_INVALID", f"{category}[{index}] has an unknown forbidden kind")
        if kind != kind.lower():
            raise _fail("ENTROPY_RECORD_NONCANONICAL", f"{category}[{index}].forbidden_kind must be lowercase")
        _bool(parsed["observed"], f"{category}[{index}].observed")
        _bool(parsed["stack_complete"], f"{category}[{index}].stack_complete")
    else:
        for field in ("mutation_id", "mutation_family", "target_record_id"):
            _identifier(parsed[field], f"{category}[{index}].{field}")
        for field in ("executed", "bypass_detected", "expected_behavior_changed"):
            _bool(parsed[field], f"{category}[{index}].{field}")
    if parsed["record_root_sha256"] != _record_root(_CATEGORY_SCHEMAS[category], parsed):
        raise _fail("ENTROPY_ROOT_STALE", f"{category}[{index}] record root does not bind its contents")
    return parsed


def _validate_wire(value: Any) -> dict[str, Any]:
    if isinstance(value, EntropyEvidence):
        value = value.canonical()
    if type(value) is not dict or set(value) != _TOP_LEVEL_FIELDS:
        raise _fail("ENTROPY_SCHEMA_INVALID", "entropy evidence fields are not exact")
    if value["schema"] != ENTROPY_COMPLETENESS_SCHEMA or value["mode"] != ENTROPY_COMPLETENESS_MODE:
        raise _fail("ENTROPY_SCHEMA_INVALID", "entropy evidence schema or mode is invalid")
    roots = {field: _sha(value[field], field) for field in _ROOT_FIELDS}
    expected = value["expected_translation_units"]
    if type(expected) is not list or not expected or any(type(item) is not str for item in expected) or expected != sorted(set(expected)):
        raise _fail("ENTROPY_TU_INVENTORY_INVALID", "expected translation units must be sorted and unique")
    if type(value["completeness_claimed"]) is not bool or value["completeness_claimed"]:
        raise _fail("ENTROPY_COMPLETENESS_CLAIM", "caller completeness claims are not accepted")
    if type(value["authority"]) is not dict or set(value["authority"]) != set(_AUTHORITY_FIELDS) or value["authority"] != _EXPECTED_AUTHORITY:
        raise _fail("ENTROPY_AUTHORITY_CLAIM", "entropy evidence cannot claim authority")
    parsed = dict(value)
    for category in RECORD_CATEGORIES:
        rows = value[category]
        if type(rows) is not list:
            raise _fail("ENTROPY_CATEGORY_MISSING", f"{category} must be a list")
        checked = [_validate_record(category, row, roots, index) for index, row in enumerate(rows)]
        keys = [_record_sort_key(category, row) for row in checked]
        if keys != sorted(keys):
            raise _fail("ENTROPY_RECORD_ORDER_INVALID", f"{category} is not in canonical order")
        if len({key for key in keys}) != len(keys):
            raise _fail("ENTROPY_RECORD_DUPLICATE", f"{category} contains duplicate record identifiers")
        parsed[category] = checked
    declared_root = _sha(value["evidence_root_sha256"], "evidence_root_sha256")
    payload = {key: value[key] for key in sorted(value) if key != "evidence_root_sha256"}
    if declared_root != canonical_sha256(payload):
        raise _fail("ENTROPY_ROOT_STALE", "evidence root does not bind canonical contents")
    return parsed


def _closure(parsed: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
    failures: list[str] = []
    ast = parsed["compiler_ast_inventory"]
    ir = parsed["ir_call_edges"]
    binary = parsed["linked_binary_records"]
    runtime = parsed["runtime_forbidden_syscall_observations"]
    mutation = parsed["mutation_test_detection_records"]
    actual_tus = {row["translation_unit_id"] for row in ast if row["present"]}
    expected_tus = set(parsed["expected_translation_units"])
    missing_tus = sorted(expected_tus - actual_tus)
    incomplete_tus = sorted(row["translation_unit_id"] for row in ast if not row["present"] or not row["ast_complete"])
    unresolved_edges = sorted(row["edge_id"] for row in ir if row["unresolved"] or row["indirect"] or row["resolved_target"] is None)
    unresolved_binary = sorted(row["binary_record_id"] for row in binary if not row["resolved"] or row["forbidden"])
    observed_forbidden = sorted(row["observation_id"] for row in runtime if row["observed"] or not row["stack_complete"])
    observed_kinds = {row["forbidden_kind"] for row in runtime}
    missing_forbidden_kinds = sorted(set(FORBIDDEN_ENTROPY_KINDS) - observed_kinds)
    undetected_mutations = sorted(row["mutation_id"] for row in mutation if not row["executed"] or not row["bypass_detected"] or not row["expected_behavior_changed"])
    if not ast or missing_tus or incomplete_tus:
        failures.append("COMPILER_AST_CLOSURE_INCOMPLETE")
    if not ir or unresolved_edges:
        failures.append("WHOLE_PROGRAM_IR_CLOSURE_INCOMPLETE")
    if not binary or unresolved_binary:
        failures.append("LINKED_BINARY_CLOSURE_INCOMPLETE")
    if not runtime or missing_forbidden_kinds or observed_forbidden:
        failures.append("RUNTIME_FORBIDDEN_SYSCALL_CLOSURE_INCOMPLETE")
    if not mutation or undetected_mutations:
        failures.append("MUTATION_DETECTION_CLOSURE_INCOMPLETE")
    complete = not failures
    return complete, {
        "mandatory_categories_present": all(bool(parsed[category]) for category in RECORD_CATEGORIES),
        "missing_translation_units": missing_tus,
        "incomplete_translation_units": incomplete_tus,
        "unresolved_or_indirect_call_edges": unresolved_edges,
        "unresolved_or_forbidden_binary_records": unresolved_binary,
        "observed_or_incomplete_forbidden_syscalls": observed_forbidden,
        "missing_forbidden_syscall_kinds": missing_forbidden_kinds,
        "mutation_bypasses_not_detected": undetected_mutations,
        "closure_failures": failures,
    }


@dataclass(frozen=True, slots=True)
class EntropyClosureAssessment:
    evidence_root_sha256: str
    locally_collected_evidence_complete: bool
    details: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": ASSESSMENT_SCHEMA,
            "state": "NO_UPLOAD",
            "evidence_root_sha256": self.evidence_root_sha256,
            "locally_collected_evidence_complete": self.locally_collected_evidence_complete,
            "details": _thaw(self.details),
            "independent_audit_a_verified": False,
            "independent_audit_b_verified": False,
            "authority": False,
            "upload_authorized": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "holdout_access_authorized": False,
            "agent_modification_authorized": False,
            "permits": [],
        }

    def zero_authority_report(self) -> dict[str, Any]:
        return self.canonical()


@dataclass(frozen=True, slots=True)
class EntropyEvidence:
    _wire: Mapping[str, Any]

    @property
    def evidence_root_sha256(self) -> str:
        return self._wire["evidence_root_sha256"]

    def canonical(self) -> dict[str, Any]:
        return _thaw(self._wire)

    def assess(self) -> EntropyClosureAssessment:
        parsed = _validate_wire(self.canonical())
        complete, details = _closure(parsed)
        return EntropyClosureAssessment(self.evidence_root_sha256, complete, _freeze(details))

    def zero_authority_report(self) -> dict[str, Any]:
        return self.assess().zero_authority_report()


def validate_entropy_evidence(value: Any) -> EntropyEvidence:
    """Validate canonical evidence and return an immutable offline artifact."""

    parsed = _validate_wire(value)
    return EntropyEvidence(_freeze(parsed))


def assess_entropy_completeness(value: Any) -> EntropyClosureAssessment:
    """Return the structured closure result; all results remain NO_UPLOAD."""

    evidence = validate_entropy_evidence(value)
    return evidence.assess()


validate_entropy_evidence_artifact = validate_entropy_evidence
compile_entropy_evidence_artifact = compile_entropy_evidence


__all__ = [
    "ASSESSMENT_SCHEMA",
    "AST_SCHEMA",
    "BINARY_SCHEMA",
    "ENTROPY_COMPLETENESS_MODE",
    "ENTROPY_COMPLETENESS_SCHEMA",
    "EntropyClosureAssessment",
    "EntropyCompletenessError",
    "EntropyEvidence",
    "FORBIDDEN_ENTROPY_KINDS",
    "IR_SCHEMA",
    "MUTATION_SCHEMA",
    "RUNTIME_SCHEMA",
    "assess_entropy_completeness",
    "compile_entropy_evidence",
    "compile_entropy_evidence_artifact",
    "validate_entropy_evidence",
    "validate_entropy_evidence_artifact",
]
