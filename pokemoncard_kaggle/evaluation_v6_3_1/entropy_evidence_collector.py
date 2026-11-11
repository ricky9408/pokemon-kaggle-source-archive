"""Execute pinned offline tools and collect v6.3.1 entropy evidence.

The collector is deliberately a small trust-boundary adapter around
``entropy_completeness``.  It accepts a rooted request, executes five pinned
commands with ``subprocess.run(..., shell=False)`` and validates the returned
records before handing them to the canonical compiler.  It never interprets a
successful local collection as campaign authority.

Tool commands receive the canonical request as JSON on stdin and must emit one
JSON object on stdout.  The object includes the exact command, tool identity,
root bindings, and category records.  This protocol keeps fake tools in tests
deterministic while making command/tool substitution visible at the boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256
from .entropy_completeness import (
    FORBIDDEN_ENTROPY_KINDS,
    RECORD_CATEGORIES,
    EntropyClosureAssessment,
    EntropyCompletenessError,
    EntropyEvidence,
    assess_entropy_completeness,
    compile_entropy_evidence,
)


COLLECTOR_REQUEST_SCHEMA = "eval.v6.3.1.entropy-evidence-collector-request.v1"
COLLECTOR_RESULT_SCHEMA = "eval.v6.3.1.entropy-evidence-collector-result.v1"
COLLECTOR_AUDIT_SCHEMA = "eval.v6.3.1.entropy-evidence-collector-audit.v1"
TOOL_OUTPUT_SCHEMA = "eval.v6.3.1.entropy-evidence-collector-tool-output.v1"
COLLECTOR_MODE = "TEST_ONLY/OFFLINE_ZERO_AUTHORITY"
ROOT_FIELDS = (
    "source_root_sha256",
    "derivative_root_sha256",
    "binary_root_sha256",
    "toolchain_root_sha256",
    "container_root_sha256",
)
TOOL_IDS = {
    "compiler_ast_inventory": "compiler_ast",
    "ir_call_edges": "whole_program_ir",
    "linked_binary_records": "linked_binary",
    "runtime_forbidden_syscall_observations": "runtime_syscalls",
    "mutation_test_detection_records": "mutation_detection",
}
TOOL_SPEC_FIELDS = frozenset(
    {
        "tool_id",
        "binary",
        "binary_sha256",
        "version_argv",
        "version",
        "version_output_sha256",
        "command_argv",
    }
)
REQUEST_FIELDS = frozenset({"schema", "mode", *ROOT_FIELDS, "translation_units", "tools"})
TOOL_OUTPUT_FIELDS = frozenset(
    {
        "schema",
        "mode",
        "category",
        "tool_id",
        "binary_sha256",
        "version",
        "version_argv",
        "command_argv",
        "root_bindings",
        "records",
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")


class EntropyEvidenceCollectorError(ValueError):
    """A pinned external collection failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> EntropyEvidenceCollectorError:
    return EntropyEvidenceCollectorError(code, message)


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise _fail("COLLECTOR_ROOT_INVALID", f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise _fail("COLLECTOR_REQUEST_INVALID", f"{label} must be a canonical identifier")
    return value


def _relative_path(value: Any, label: str) -> str:
    if type(value) is not str or PATH_RE.fullmatch(value) is None or value in {".", ".."}:
        raise _fail("COLLECTOR_REQUEST_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _argv(value: Any, label: str) -> list[str]:
    if type(value) is not list or not value or any(type(item) is not str or not item for item in value):
        raise _fail("COLLECTOR_TOOL_PIN_INVALID", f"{label} must be a non-empty argv list")
    return list(value)


def _file_sha256(path: Path, label: str) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _fail("COLLECTOR_TOOL_MISSING", f"{label} cannot be read: {path}") from exc
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _toolchain_root(specs: Mapping[str, Mapping[str, Any]]) -> str:
    tools = []
    for category in sorted(specs):
        spec = specs[category]
        tools.append(
            {
                "category": category,
                "tool_id": spec["tool_id"],
                "binary": spec["binary"],
                "binary_sha256": spec["binary_sha256"],
                "version_argv": list(spec["version_argv"]),
                "version": spec["version"],
                "version_output_sha256": spec["version_output_sha256"],
                "command_argv": list(spec["command_argv"]),
            }
        )
    return canonical_sha256({"schema": "eval.v6.3.1.entropy-toolchain-binding.v1", "tools": tools})


def _zero_authority(*, state: str = "NO_UPLOAD", detail: str = "") -> dict[str, Any]:
    return {
        "schema": "eval.v6.3.1.entropy-evidence-collector-zero-authority.v1",
        "state": state,
        "detail": detail,
        "authority": False,
        "upload_authorized": False,
        "calibration_upload_authorized": False,
        "production_upload_authorized": False,
        "holdout_access_authorized": False,
        "sealed_holdout_access_authorized": False,
        "agent_modification_authorized": False,
        "permits": [],
    }


def _validate_request(request: Mapping[str, Any]) -> tuple[dict[str, str], list[dict[str, str]], dict[str, dict[str, Any]]]:
    if type(request) is not dict or set(request) != REQUEST_FIELDS:
        raise _fail("COLLECTOR_REQUEST_SCHEMA_INVALID", "collector request fields are not exact")
    if request["schema"] != COLLECTOR_REQUEST_SCHEMA or request["mode"] != COLLECTOR_MODE:
        raise _fail("COLLECTOR_REQUEST_SCHEMA_INVALID", "collector request schema or mode is invalid")
    roots = {field: _sha(request[field], field) for field in ROOT_FIELDS}

    units = request["translation_units"]
    if type(units) is not list or not units:
        raise _fail("COLLECTOR_TU_INVENTORY_INVALID", "translation_units must be a non-empty list")
    parsed_units: list[dict[str, str]] = []
    for index, unit in enumerate(units):
        if type(unit) is not dict or set(unit) != {"translation_unit_id", "canonical_relative_path"}:
            raise _fail("COLLECTOR_TU_INVENTORY_INVALID", f"translation_units[{index}] is not exact")
        parsed_units.append(
            {
                "translation_unit_id": _identifier(unit["translation_unit_id"], f"translation_units[{index}].translation_unit_id"),
                "canonical_relative_path": _relative_path(unit["canonical_relative_path"], f"translation_units[{index}].canonical_relative_path"),
            }
        )
    if [item["translation_unit_id"] for item in parsed_units] != sorted(item["translation_unit_id"] for item in parsed_units):
        raise _fail("COLLECTOR_TU_INVENTORY_INVALID", "translation_units must be sorted by identifier")
    if len({item["translation_unit_id"] for item in parsed_units}) != len(parsed_units):
        raise _fail("COLLECTOR_TU_INVENTORY_INVALID", "translation_units contain duplicate identifiers")

    tools = request["tools"]
    if type(tools) is not dict or set(tools) != set(TOOL_IDS.values()):
        raise _fail("COLLECTOR_TOOL_PIN_INVALID", "all five category tools are required")
    parsed_tools: dict[str, dict[str, Any]] = {}
    for category, tool_id in TOOL_IDS.items():
        raw = tools[tool_id]
        if type(raw) is not dict or set(raw) != TOOL_SPEC_FIELDS:
            raise _fail("COLLECTOR_TOOL_PIN_INVALID", f"{tool_id} tool fields are not exact")
        spec = dict(raw)
        if spec["tool_id"] != tool_id:
            raise _fail("COLLECTOR_TOOL_SUBSTITUTION", f"{tool_id} has a substituted tool identifier")
        _identifier(spec["tool_id"], f"{tool_id}.tool_id")
        if type(spec["binary"]) is not str or not os.path.isabs(spec["binary"]):
            raise _fail("COLLECTOR_TOOL_PIN_INVALID", f"{tool_id}.binary must be an absolute path")
        spec["binary_sha256"] = _sha(spec["binary_sha256"], f"{tool_id}.binary_sha256")
        spec["version_argv"] = _argv(spec["version_argv"], f"{tool_id}.version_argv")
        spec["command_argv"] = _argv(spec["command_argv"], f"{tool_id}.command_argv")
        if spec["version_argv"][0] != spec["binary"] or spec["command_argv"][0] != spec["binary"]:
            raise _fail("COLLECTOR_TOOL_SUBSTITUTION", f"{tool_id} argv executable is not the pinned binary")
        if type(spec["version"]) is not str or not spec["version"]:
            raise _fail("COLLECTOR_TOOL_PIN_INVALID", f"{tool_id}.version must be non-empty text")
        spec["version_output_sha256"] = _sha(spec["version_output_sha256"], f"{tool_id}.version_output_sha256")
        parsed_tools[category] = spec
    if roots["toolchain_root_sha256"] != _toolchain_root(parsed_tools):
        raise _fail("COLLECTOR_TOOLCHAIN_ROOT_STALE", "toolchain root does not bind the pinned tools and commands")
    return roots, parsed_units, parsed_tools


def _run_pinned_tool(
    category: str,
    spec: Mapping[str, Any],
    request_bytes: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    binary = Path(spec["binary"])
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise _fail("COLLECTOR_TOOL_MISSING", f"{category} pinned binary is absent or not executable: {binary}")
    if _file_sha256(binary, f"{category}.binary") != spec["binary_sha256"]:
        raise _fail("COLLECTOR_TOOL_SUBSTITUTION", f"{category} binary bytes do not match the pinned digest")
    try:
        version_run = subprocess.run(
            list(spec["version_argv"]),
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _fail("COLLECTOR_TOOL_EXECUTION_FAILED", f"{category} version command failed") from exc
    if version_run.returncode != 0 or version_run.stderr:
        raise _fail("COLLECTOR_TOOL_VERSION_INVALID", f"{category} version command did not produce a clean result")
    try:
        version_text = version_run.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail("COLLECTOR_TOOL_VERSION_INVALID", f"{category} version output is not UTF-8") from exc
    if hashlib.sha256(version_run.stdout).hexdigest() != spec["version_output_sha256"] or version_text != spec["version"]:
        raise _fail("COLLECTOR_TOOL_VERSION_INVALID", f"{category} version output does not match the pin")

    try:
        command_run = subprocess.run(
            list(spec["command_argv"]),
            input=request_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _fail("COLLECTOR_TOOL_EXECUTION_FAILED", f"{category} collection command failed") from exc
    if command_run.returncode != 0:
        raise _fail("COLLECTOR_TOOL_EXECUTION_FAILED", f"{category} collection command exited {command_run.returncode}")
    try:
        output = json.loads(command_run.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("COLLECTOR_TOOL_OUTPUT_INVALID", f"{category} output is not UTF-8 JSON") from exc
    audit = {
        "category": category,
        "tool_id": spec["tool_id"],
        "binary": spec["binary"],
        "binary_sha256": spec["binary_sha256"],
        "version": spec["version"],
        "version_argv": list(spec["version_argv"]),
        "version_stdout_sha256": hashlib.sha256(version_run.stdout).hexdigest(),
        "command_argv": list(spec["command_argv"]),
        "command_stdout_sha256": hashlib.sha256(command_run.stdout).hexdigest(),
        "command_stderr_sha256": hashlib.sha256(command_run.stderr).hexdigest(),
        "returncode": command_run.returncode,
    }
    return output, audit


def _validate_tool_output(
    category: str,
    output: Any,
    spec: Mapping[str, Any],
    roots: Mapping[str, str],
) -> list[Mapping[str, Any]]:
    if type(output) is not dict or set(output) != TOOL_OUTPUT_FIELDS:
        raise _fail("COLLECTOR_TOOL_OUTPUT_INVALID", f"{category} output fields are not exact")
    if (
        output["schema"] != TOOL_OUTPUT_SCHEMA
        or output["mode"] != COLLECTOR_MODE
        or output["category"] != category
        or output["tool_id"] != spec["tool_id"]
        or output["binary_sha256"] != spec["binary_sha256"]
        or output["version"] != spec["version"]
        or output["version_argv"] != list(spec["version_argv"])
        or output["command_argv"] != list(spec["command_argv"])
        or output["root_bindings"] != dict(roots)
    ):
        raise _fail("COLLECTOR_TOOL_SUBSTITUTION", f"{category} output is not bound to the pinned tool and roots")
    if type(output["records"]) is not list:
        raise _fail("COLLECTOR_TOOL_OUTPUT_INVALID", f"{category} records must be a list")
    return output["records"]


def _check_collected_closure(
    evidence: EntropyEvidence,
    units: Sequence[Mapping[str, str]],
) -> EntropyClosureAssessment:
    assessment = assess_entropy_completeness(evidence.canonical())
    details = assessment.details
    expected = {unit["translation_unit_id"] for unit in units}
    actual_ast = evidence.canonical()["compiler_ast_inventory"]
    actual = {row["translation_unit_id"] for row in actual_ast if row["present"]}
    if actual != expected:
        raise _fail("COLLECTOR_AST_TU_INVENTORY_INCOMPLETE", "AST output does not cover every translation unit")
    if not assessment.locally_collected_evidence_complete:
        failures = ",".join(details["closure_failures"])
        raise _fail("COLLECTOR_CLOSURE_INCOMPLETE", f"canonical entropy closure failed: {failures}")
    return assessment


@dataclass(frozen=True, slots=True)
class EntropyEvidenceCollection:
    """Collected evidence plus an immutable local audit, never authority."""

    evidence: EntropyEvidence
    assessment: EntropyClosureAssessment
    audit: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        authority = _zero_authority()
        authority.pop("schema")
        return {
            "schema": COLLECTOR_RESULT_SCHEMA,
            "mode": COLLECTOR_MODE,
            "evidence": self.evidence.canonical(),
            "assessment": self.assessment.zero_authority_report(),
            "collector_audit": {key: value for key, value in self.audit.items()},
            **authority,
        }

    def zero_authority_report(self) -> dict[str, Any]:
        return _zero_authority(detail="local entropy evidence collection is never campaign authority")


def collect_entropy_evidence(request: Mapping[str, Any]) -> EntropyEvidenceCollection:
    """Run all pinned category tools and return complete local evidence.

    Any absent tool, changed binary/version/command, stale root, malformed
    output, missing TU, forbidden observation, unresolved edge, or mutation
    bypass raises ``EntropyEvidenceCollectorError`` before a result is
    returned.  This function performs no upload, holdout, or agent mutation.
    """

    roots, units, tools = _validate_request(request)
    request_bytes = _canonical_json_bytes(request)
    all_records: dict[str, list[Mapping[str, Any]]] = {}
    invocation_audit: list[dict[str, Any]] = []
    for category in RECORD_CATEGORIES:
        output, audit = _run_pinned_tool(category, tools[category], request_bytes)
        all_records[category] = _validate_tool_output(category, output, tools[category], roots)
        invocation_audit.append(audit)

    expected_ids = [unit["translation_unit_id"] for unit in units]
    ast_rows = all_records["compiler_ast_inventory"]
    if any(not isinstance(row, Mapping) or type(row.get("translation_unit_id")) is not str for row in ast_rows):
        raise _fail("COLLECTOR_AST_TU_INVENTORY_INCOMPLETE", "AST output contains an invalid translation-unit identifier")
    ast_ids = sorted(row["translation_unit_id"] for row in ast_rows)
    if ast_ids != expected_ids:
        raise _fail("COLLECTOR_AST_TU_INVENTORY_INCOMPLETE", "AST tool did not emit exactly one record for every TU")
    ast_paths = {unit["translation_unit_id"]: unit["canonical_relative_path"] for unit in units}
    for row in all_records["compiler_ast_inventory"]:
        if row.get("canonical_relative_path") != ast_paths.get(row.get("translation_unit_id")):
            raise _fail("COLLECTOR_AST_TU_INVENTORY_INCOMPLETE", "AST path is not bound to the requested TU")
    binary_kinds = {
        row["record_kind"]
        for row in all_records["linked_binary_records"]
        if isinstance(row, Mapping) and type(row.get("record_kind")) is str
    }
    if not {"SYMBOL", "DEPENDENCY", "INSTRUCTION"}.issubset(binary_kinds):
        raise _fail("COLLECTOR_BINARY_SCAN_INCOMPLETE", "linked binary output lacks symbol, dependency, or instruction evidence")
    observed_kinds = {
        row["forbidden_kind"]
        for row in all_records["runtime_forbidden_syscall_observations"]
        if isinstance(row, Mapping) and type(row.get("forbidden_kind")) is str
    }
    if not set(FORBIDDEN_ENTROPY_KINDS).issubset(observed_kinds):
        raise _fail("COLLECTOR_RUNTIME_SCAN_INCOMPLETE", "runtime output lacks a required forbidden-kind observation")

    try:
        evidence = compile_entropy_evidence(
            **roots,
            expected_translation_units=expected_ids,
            compiler_ast_inventory=all_records["compiler_ast_inventory"],
            ir_call_edges=all_records["ir_call_edges"],
            linked_binary_records=all_records["linked_binary_records"],
            runtime_forbidden_syscall_observations=all_records["runtime_forbidden_syscall_observations"],
            mutation_test_detection_records=all_records["mutation_test_detection_records"],
        )
    except EntropyCompletenessError as exc:
        raise _fail("COLLECTOR_EVIDENCE_INVALID", str(exc)) from exc
    assessment = _check_collected_closure(evidence, units)
    audit_payload: dict[str, Any] = {
        "schema": COLLECTOR_AUDIT_SCHEMA,
        "mode": COLLECTOR_MODE,
        "root_bindings": dict(roots),
        "invocations": sorted(invocation_audit, key=lambda item: item["category"]),
        "evidence_root_sha256": evidence.evidence_root_sha256,
        "authority": False,
    }
    audit_payload["audit_root_sha256"] = canonical_sha256(audit_payload)
    return EntropyEvidenceCollection(evidence, assessment, MappingProxyType(audit_payload))


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("COLLECTOR_REQUEST_INVALID", f"cannot read request JSON: {path}") from exc
    if type(value) is not dict:
        raise _fail("COLLECTOR_REQUEST_INVALID", "request JSON must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = collect_entropy_evidence(_load_json(args.request))
        payload = result.canonical()
        status = 0
    except (EntropyEvidenceCollectorError, EntropyCompletenessError) as exc:
        payload = _zero_authority(state="NO_UPLOAD", detail=f"{exc.code}: {exc}")
        payload["error_code"] = exc.code
        status = 2
    rendered = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return status


if __name__ == "__main__":  # pragma: no cover - exercised through the CLI
    raise SystemExit(main())


__all__ = [
    "COLLECTOR_AUDIT_SCHEMA",
    "COLLECTOR_MODE",
    "COLLECTOR_REQUEST_SCHEMA",
    "COLLECTOR_RESULT_SCHEMA",
    "EntropyEvidenceCollection",
    "EntropyEvidenceCollectorError",
    "TOOL_OUTPUT_SCHEMA",
    "collect_entropy_evidence",
    "main",
]
