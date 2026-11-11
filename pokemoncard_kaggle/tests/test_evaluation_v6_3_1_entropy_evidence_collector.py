from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.entropy_evidence_collector import (
    COLLECTOR_MODE,
    COLLECTOR_REQUEST_SCHEMA,
    TOOL_OUTPUT_SCHEMA,
    _toolchain_root,
    collect_entropy_evidence,
    EntropyEvidenceCollectorError,
)


FAKE_TOOL = """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

role = sys.argv[2]
if sys.argv[1] == '--version':
    sys.stdout.write('fake-' + role + '-1\\n')
    raise SystemExit(0)
request = json.load(sys.stdin)
fixture_path = Path(sys.argv[sys.argv.index('--fixture') + 1])
fixture = json.loads(fixture_path.read_text(encoding='utf-8'))
tool = request['tools'][role]
payload = {
    'schema': %r,
    'mode': %r,
    'category': fixture['category'],
    'tool_id': tool['tool_id'],
    'binary_sha256': tool['binary_sha256'],
    'version': tool['version'],
    'version_argv': tool['version_argv'],
    'command_argv': tool['command_argv'],
    'root_bindings': {key: request[key] for key in (
        'source_root_sha256', 'derivative_root_sha256', 'binary_root_sha256',
        'toolchain_root_sha256', 'container_root_sha256')},
    'records': fixture['records'],
}
payload.update(fixture.get('overrides', {}))
print(json.dumps(payload, sort_keys=True, separators=(',', ':')))
""" % (TOOL_OUTPUT_SCHEMA, COLLECTOR_MODE)


ROOT_FIELDS = (
    "source_root_sha256",
    "derivative_root_sha256",
    "binary_root_sha256",
    "toolchain_root_sha256",
    "container_root_sha256",
)
CATEGORIES = (
    "compiler_ast_inventory",
    "ir_call_edges",
    "linked_binary_records",
    "runtime_forbidden_syscall_observations",
    "mutation_test_detection_records",
)
TOOL_IDS = {
    "compiler_ast_inventory": "compiler_ast",
    "ir_call_edges": "whole_program_ir",
    "linked_binary_records": "linked_binary",
    "runtime_forbidden_syscall_observations": "runtime_syscalls",
    "mutation_test_detection_records": "mutation_detection",
}


def _root(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _write_fake_tools(tmp_path: Path) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for tool_id in TOOL_IDS.values():
        path = tmp_path / tool_id
        path.write_text(FAKE_TOOL, encoding="utf-8")
        path.chmod(0o755)
        result[tool_id] = path
    return result


def _records() -> dict[str, list[dict[str, object]]]:
    return {
        "compiler_ast_inventory": [
            {"translation_unit_id": "tu-a", "canonical_relative_path": "engine/A.cpp", "present": True, "ast_complete": True},
            {"translation_unit_id": "tu-b", "canonical_relative_path": "engine/B.cpp", "present": True, "ast_complete": True},
        ],
        "ir_call_edges": [
            {"edge_id": "edge-main", "caller": "main", "callee": "step", "indirect": False, "unresolved": False, "resolved_target": "step"},
        ],
        "linked_binary_records": [
            {"binary_record_id": "dependency-runtime", "record_kind": "DEPENDENCY", "symbol": "step", "dependency": "libc", "instruction": "N/A", "resolved": True, "forbidden": False},
            {"binary_record_id": "instruction-call", "record_kind": "INSTRUCTION", "symbol": "step", "dependency": "engine", "instruction": "CALL", "resolved": True, "forbidden": False},
            {"binary_record_id": "symbol-step", "record_kind": "SYMBOL", "symbol": "step", "dependency": "engine", "instruction": "ENTRY", "resolved": True, "forbidden": False},
        ],
        "runtime_forbidden_syscall_observations": [
            {"observation_id": f"obs-{kind}", "forbidden_kind": kind, "observed": False, "stack_complete": True}
            for kind in ("dlopen", "getrandom", "rdrand", "syscall")
        ],
        "mutation_test_detection_records": [
            {"mutation_id": "mutation-entropy", "mutation_family": "entropy", "target_record_id": "edge-main", "executed": True, "bypass_detected": True, "expected_behavior_changed": True},
        ],
    }


def _request(tmp_path: Path, *, changes: dict[str, object] | None = None) -> dict[str, object]:
    tools_dir = _write_fake_tools(tmp_path)
    roots = {field: _root(field) for field in ROOT_FIELDS}
    request: dict[str, object] = {
        "schema": COLLECTOR_REQUEST_SCHEMA,
        "mode": COLLECTOR_MODE,
        **roots,
        "translation_units": [
            {"translation_unit_id": "tu-a", "canonical_relative_path": "engine/A.cpp"},
            {"translation_unit_id": "tu-b", "canonical_relative_path": "engine/B.cpp"},
        ],
        "tools": {},
    }
    tool_specs: dict[str, dict[str, object]] = {}
    for category, tool_id in TOOL_IDS.items():
        fixture = tmp_path / f"{tool_id}.json"
        fixture.write_text(json.dumps({"category": category, "records": _records()[category]}), encoding="utf-8")
        binary = tools_dir[tool_id]
        version = f"fake-{tool_id}-1\n"
        tool_specs[tool_id] = {
            "tool_id": tool_id,
            "binary": str(binary),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "version_argv": [str(binary), "--version", tool_id],
            "version": version,
            "version_output_sha256": hashlib.sha256(version.encode()).hexdigest(),
            "command_argv": [str(binary), "--collect", tool_id, "--fixture", str(fixture)],
        }
    request["tools"] = tool_specs
    request["toolchain_root_sha256"] = _toolchain_root({category: tool_specs[TOOL_IDS[category]] for category in CATEGORIES})
    if changes:
        for key, value in changes.items():
            if key.startswith("fixture:"):
                _, tool_id = key.split(":", 1)
                fixture = tmp_path / f"{tool_id}.json"
                payload = json.loads(fixture.read_text(encoding="utf-8"))
                payload.update(value)
                fixture.write_text(json.dumps(payload), encoding="utf-8")
            else:
                request[key] = value
    return request


def _expect_error(request: dict[str, object], code: str) -> None:
    with pytest.raises(EntropyEvidenceCollectorError) as caught:
        collect_entropy_evidence(request)
    assert caught.value.code == code


def test_complete_collection_is_rooted_and_zero_authority(tmp_path: Path) -> None:
    result = collect_entropy_evidence(_request(tmp_path))
    assert result.canonical()["schema"] == "eval.v6.3.1.entropy-evidence-collector-result.v1"
    assert result.assessment.locally_collected_evidence_complete is True
    assert result.evidence.canonical()["completeness_claimed"] is False
    report = result.zero_authority_report()
    assert report["state"] == "NO_UPLOAD"
    assert report["authority"] is False
    assert report["upload_authorized"] is False
    assert report["holdout_access_authorized"] is False
    assert report["agent_modification_authorized"] is False
    assert report["permits"] == []
    assert result.audit["audit_root_sha256"] == canonical_sha256(
        {key: value for key, value in result.audit.items() if key != "audit_root_sha256"}
    )


def test_stale_output_root_fails_closed(tmp_path: Path) -> None:
    stale = {field: _root(f"stale-{field}") for field in ROOT_FIELDS}
    _expect_error(_request(tmp_path, changes={"fixture:compiler_ast": {"overrides": {"root_bindings": stale}}}), "COLLECTOR_TOOL_SUBSTITUTION")


def test_missing_translation_unit_fails_closed(tmp_path: Path) -> None:
    records = _records()["compiler_ast_inventory"][:1]
    _expect_error(_request(tmp_path, changes={"fixture:compiler_ast": {"records": records}}), "COLLECTOR_AST_TU_INVENTORY_INCOMPLETE")


def test_unresolved_indirect_edge_fails_closed(tmp_path: Path) -> None:
    records = _records()["ir_call_edges"]
    records[0]["indirect"] = True
    _expect_error(_request(tmp_path, changes={"fixture:whole_program_ir": {"records": records}}), "COLLECTOR_CLOSURE_INCOMPLETE")


def test_forbidden_runtime_observation_fails_closed(tmp_path: Path) -> None:
    records = _records()["runtime_forbidden_syscall_observations"]
    records[0]["observed"] = True
    _expect_error(_request(tmp_path, changes={"fixture:runtime_syscalls": {"records": records}}), "COLLECTOR_CLOSURE_INCOMPLETE")


def test_mutation_bypass_fails_closed(tmp_path: Path) -> None:
    records = _records()["mutation_test_detection_records"]
    records[0]["bypass_detected"] = False
    _expect_error(_request(tmp_path, changes={"fixture:mutation_detection": {"records": records}}), "COLLECTOR_CLOSURE_INCOMPLETE")


def test_command_substitution_fails_closed(tmp_path: Path) -> None:
    _expect_error(
        _request(tmp_path, changes={"fixture:compiler_ast": {"overrides": {"command_argv": ["/substituted/tool"]}}}),
        "COLLECTOR_TOOL_SUBSTITUTION",
    )


def test_binary_substitution_and_missing_tool_fail_closed(tmp_path: Path) -> None:
    request = _request(tmp_path, changes={"fixture:linked_binary": {"overrides": {"binary_sha256": "0" * 64}}})
    _expect_error(request, "COLLECTOR_TOOL_SUBSTITUTION")

    missing = _request(tmp_path)
    binary = Path(missing["tools"]["compiler_ast"]["binary"])
    binary.unlink()
    _expect_error(missing, "COLLECTOR_TOOL_MISSING")


def test_toolchain_command_pin_stale_root_is_rejected_before_execution(tmp_path: Path) -> None:
    request = _request(tmp_path)
    command = list(request["tools"]["compiler_ast"]["command_argv"])
    command[1] = "--substituted"
    request["tools"]["compiler_ast"]["command_argv"] = command
    _expect_error(request, "COLLECTOR_TOOLCHAIN_ROOT_STALE")
