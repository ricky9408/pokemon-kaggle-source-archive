from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import sys

import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.entropy_real_collection import collect_real_entropy_evidence, tree_sha256
from evaluation_v6_3_1.entropy_static_closure import (
    FROZEN_ENTROPY_ALLOWLIST_SHA256,
    analyze_entropy_static_closure,
)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if type(data) is str else data)


def _fixture(tmp_path: Path, *, ir: str = "define i32 @main() { ret i32 0 }\n", ast: dict[str, object] | None = None, nm: str = "00000000 T main\n") -> tuple[Path, Path, Path, Path]:
    source = tmp_path / "source"
    derivative = tmp_path / "derivative"
    artifacts = tmp_path / "artifacts"
    source.mkdir()
    derivative.mkdir()
    _write(source / "source.cc", "int source;\n")
    _write(derivative / "main.cc", "int main() { return 0; }\n")
    _write(artifacts / ".entropy-real-collection.marker", "eval.v6.3.1.entropy-real-collection.v1\n")
    _write(artifacts / "ast/tu-0000.json", json.dumps(ast or {"kind": "TranslationUnitDecl", "inner": []}))
    _write(artifacts / "ast/tu-0000.stderr", "")
    _write(artifacts / "ir/tu-0000.ll", ir)
    _write(artifacts / "ir/tu-0000.stdout", "")
    _write(artifacts / "ir/tu-0000.stderr", "")
    _write(artifacts / "binary/derivative-probe", b"not-executed-static-fixture")
    _write(artifacts / "inspection/nm.stdout", nm)
    _write(artifacts / "inspection/nm.stderr", "")
    _write(artifacts / "inspection/otool.stdout", "derivative-probe:\n\t/usr/lib/libSystem.B.dylib\n")
    _write(artifacts / "inspection/otool.stderr", "")
    _write(artifacts / "inspection/objdump.stdout", "00000000 <main>:\n ret\n")
    _write(artifacts / "inspection/objdump.stderr", "")
    generated = []
    for path in sorted((item for item in artifacts.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
        generated.append({"path": path.relative_to(artifacts).as_posix(), "sha256": _digest(path), "bytes": str(path.stat().st_size)})
    tool = {"resolved_path": str(Path(sys.executable).resolve()), "sha256": _digest(Path(sys.executable).resolve())}
    def command(path: str) -> dict[str, object]:
        item = artifacts / path
        return {"stdout": {"path": path, "sha256": _digest(item)}}
    report: dict[str, object] = {
        "schema": "eval.v6.3.1.entropy-real-collection.v1",
        "mode": "PROBE_ONLY/NO_UPLOAD",
        "state": "PROBE_ONLY_INCOMPLETE",
        "source_tree_sha256": tree_sha256(source),
        "derivative_tree_sha256": tree_sha256(derivative),
        "linked_binary_sha256": _digest(artifacts / "binary/derivative-probe"),
        "compiler": tool,
        "translation_units": ["main.cc"],
        "ast": [{"translation_unit": "main.cc", "command": command("ast/tu-0000.json"), "ast_sha256": _digest(artifacts / "ast/tu-0000.json")}],
        "llvm_ir": [{"translation_unit": "main.cc", "command": command("ir/tu-0000.stdout"), "ir_sha256": _digest(artifacts / "ir/tu-0000.ll")}],
        "inspection": {name: {"tool": tool, "command": command(f"inspection/{name}.stdout")} for name in ("nm", "otool", "objdump")},
        "generated_artifacts": generated,
    }
    report["report_sha256"] = canonical_sha256(report)
    report_path = tmp_path / "collector-report.json"
    report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    return report_path, artifacts, source, derivative


def _analyze(paths: tuple[Path, Path, Path, Path], **kwargs: object) -> dict[str, object]:
    report, artifacts, source, derivative = paths
    return analyze_entropy_static_closure(
        collector_report_path=report,
        artifact_directory=artifacts,
        source_directory=source,
        derivative_directory=derivative,
        **kwargs,
    ).canonical()


def _decl_ref(
    declaration_id: str,
    kind: str,
    name: str,
    qual_type: str,
) -> dict[str, object]:
    return {
        "kind": "DeclRefExpr",
        "type": {"qualType": qual_type},
        "referencedDecl": {
            "id": declaration_id,
            "kind": kind,
            "name": name,
            "type": {"qualType": qual_type},
        },
    }


def _member_call(
    operation: str,
    object_reference: dict[str, object],
    *arguments: dict[str, object],
) -> dict[str, object]:
    return {
        "kind": "CXXMemberCallExpr",
        "inner": [
            {
                "kind": "MemberExpr",
                "name": operation,
                "inner": [object_reference],
            },
            *arguments,
        ],
    }


def _operator_index(
    object_reference: dict[str, object],
    *arguments: dict[str, object],
) -> dict[str, object]:
    return {
        "kind": "CXXOperatorCallExpr",
        "inner": [
            {
                "kind": "ImplicitCastExpr",
                "inner": [
                    _decl_ref(
                        "operator-index",
                        "CXXMethodDecl",
                        "operator[]",
                        "reference (size_type)",
                    )
                ],
            },
            object_reference,
            *arguments,
        ],
    }


def _synthetic_registry_ast(
    *,
    missing_push: bool = False,
    duplicate_target: bool = False,
    missing_definition: bool = False,
    extra_reference: bool = False,
) -> dict[str, object]:
    table = lambda: _decl_ref(
        "function-table",
        "VarDecl",
        "FunctionTable",
        "std::vector<void *>",
    )
    index = lambda: _decl_ref(
        "function-index-table",
        "VarDecl",
        "FunctionIndexTable",
        "std::unordered_map<long long, int>",
    )
    target_count = 115 if missing_push else 116
    pushes: list[dict[str, object]] = []
    definitions: list[dict[str, object]] = []
    for target_index in range(116):
        target_id = f"target-{target_index:03d}"
        target_name = f"Target{target_index:03d}"
        definitions.append(
            {
                "id": target_id,
                "kind": "FunctionDecl",
                "name": target_name,
                "type": {"qualType": "void (State &)"},
                "inner": [{"kind": "CompoundStmt"}],
            }
        )
        if target_index >= target_count:
            continue
        reference_id = "target-000" if duplicate_target and target_index == 115 else target_id
        reference_name = "Target000" if duplicate_target and target_index == 115 else target_name
        pushes.append(
            _member_call(
                "push_back",
                table(),
                {
                    "kind": "CStyleCastExpr",
                    "inner": [
                        _decl_ref(
                            reference_id,
                            "FunctionDecl",
                            reference_name,
                            "void (State &)",
                        )
                    ],
                },
            )
        )
    if missing_definition:
        definitions.pop()

    range_call = {
        "kind": "CallExpr",
        "inner": [
            {
                "kind": "ImplicitCastExpr",
                "inner": [
                    _decl_ref(
                        "range-function",
                        "FunctionDecl",
                        "range",
                        "range_type (const std::vector<void *> &)",
                    )
                ],
            },
            table(),
        ],
    }
    index_population = _operator_index(index(), _operator_index(table()))
    initialize_children = [*pushes, range_call, index_population]
    if extra_reference:
        initialize_children.append(table())

    dispatch_calls = [
        {
            "kind": "CallExpr",
            "inner": [
                {
                    "kind": "ImplicitCastExpr",
                    "type": {"qualType": signature},
                }
            ],
        }
        for signature in (
            "GameFunctionNoArg",
            "GameFunctionI",
            "GameFunctionB",
            "GameFunctionII",
            "GameFunctionIII",
        )
    ]
    return {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "id": "function-table",
                "kind": "VarDecl",
                "name": "FunctionTable",
                "type": {"qualType": "std::vector<void *>"},
            },
            {
                "id": "function-index-table",
                "kind": "VarDecl",
                "name": "FunctionIndexTable",
                "type": {"qualType": "std::unordered_map<long long, int>"},
            },
            *definitions,
            {
                "kind": "CXXRecordDecl",
                "name": "GameFunction",
                "inner": [
                    {
                        "id": "game-function-constructor",
                        "kind": "CXXConstructorDecl",
                        "name": "GameFunction",
                        "inner": [
                            {
                                "kind": "CompoundStmt",
                                "inner": [_member_call("at", index())],
                            }
                        ],
                    }
                ],
            },
            {
                "kind": "CXXRecordDecl",
                "name": "State",
                "inner": [
                    {
                        "id": "call-function",
                        "kind": "CXXMethodDecl",
                        "name": "callFunction",
                        "inner": [
                            {
                                "kind": "CompoundStmt",
                                "inner": [
                                    _member_call("at", table()),
                                    *dispatch_calls,
                                ],
                            }
                        ],
                    }
                ],
            },
            {
                "id": "initialize-battle-functions",
                "kind": "FunctionDecl",
                "name": "InitializeBattleFunction",
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "inner": initialize_children,
                    }
                ],
            },
            {
                "id": "initialize-all",
                "kind": "FunctionDecl",
                "name": "InitializeAll",
                "inner": [
                    {
                        "kind": "CompoundStmt",
                        "inner": [_member_call("size", table())],
                    }
                ],
            },
        ],
    }


def _synthetic_dispatch_ir() -> str:
    return "\n".join(
        [
            "define void @_ZN5State12callFunctionEv(ptr %self) {",
            "  %fp = load ptr, ptr %self",
            "  call void %fp(ptr %self)",
            "  call void %fp(ptr %self, i32 1)",
            "  call void %fp(ptr %self, i1 true)",
            "  call void %fp(ptr %self, i32 1, i32 2)",
            "  call void %fp(ptr %self, i32 1, i32 2, i32 3)",
            "  ret void",
            "}",
            "",
        ]
    )


def test_complete_fixture_is_deterministic_and_permanently_zero_authority(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    first = _analyze(paths)
    second = _analyze(paths)

    assert first == second
    assert first["status"] == "COMPLETE"
    assert first["state"] == "NO_UPLOAD"
    assert first["details"]["static_closure_complete"] is True
    assert first["report_sha256"] == canonical_sha256({key: value for key, value in first.items() if key != "report_sha256"})
    assert first["authority"] is False
    assert first["permits"] == []
    assert all(first[key] is False for key in ("upload_authorized", "calibration_upload_authorized", "production_upload_authorized", "holdout_access_authorized", "sealed_holdout_access_authorized", "agent_modification_authorized"))


def test_real_collector_artifacts_are_read_and_remain_incomplete_without_all_inspections(tmp_path: Path) -> None:
    compiler = Path(sys.executable).resolve()
    # The real collector needs a compiler; use an available C++ compiler when present.
    import shutil
    candidate = shutil.which("clang++") or shutil.which("c++")
    if candidate is None:
        pytest.skip("real C++ compiler is unavailable")
    compiler = Path(candidate).resolve()
    source = tmp_path / "real-source"
    derivative = tmp_path / "real-derivative"
    source.mkdir()
    derivative.mkdir()
    _write(source / "source.cc", "int source_only() { return 1; }\n")
    _write(derivative / "main.cc", "int main() { return 0; }\n")
    output = tmp_path / "real-output"
    report = collect_real_entropy_evidence(
        source_directory=source, derivative_directory=derivative, translation_units=("main.cc",),
        output_directory=output, compiler_path=compiler, compile_flags=("-std=c++17",),
        environment_allowlist={"LANG": "C"}, compiler_sha256=_digest(compiler),
        expected_source_tree_sha256=tree_sha256(source), expected_derivative_tree_sha256=tree_sha256(derivative),
    ).canonical()
    report_path = tmp_path / "real-report.json"
    report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
    result = analyze_entropy_static_closure(
        collector_report_path=report_path, artifact_directory=output,
        source_directory=source, derivative_directory=derivative,
    ).canonical()
    assert result["status"] == "INCOMPLETE"
    assert result["state"] == "NO_UPLOAD"
    assert "INSPECTION_NM_MISSING" in result["details"]["failure_codes"]


def test_missing_artifact_fails_closed(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    (paths[1] / "ir/tu-0000.ll").unlink()
    result = _analyze(paths)
    assert result["status"] == "INCOMPLETE"
    assert "STATIC_ARTIFACT_PATH_INVALID" in result["details"]["failure_codes"]


def test_digest_drift_fails_closed(tmp_path: Path) -> None:
    paths = _fixture(tmp_path)
    _write(paths[1] / "binary/derivative-probe", b"changed")
    result = _analyze(paths)
    assert result["status"] == "INCOMPLETE"
    assert "ARTIFACT_DIGEST_DRIFT" in result["details"]["failure_codes"]


def test_indirect_llvm_call_fails_closed(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, ir="define void @main() { call void %callback() ret void }\n")
    result = _analyze(paths)
    assert result["status"] == "INCOMPLETE"
    assert "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL" in result["details"]["failure_codes"]
    assert result["details"]["unresolved_or_disallowed_call_edges"][0]["kind"] == "INDIRECT"


def test_forbidden_binary_symbol_fails_closed(tmp_path: Path) -> None:
    paths = _fixture(tmp_path, nm="                 U _getrandom\n")
    result = _analyze(paths)
    assert result["status"] == "INCOMPLETE"
    assert "FORBIDDEN_BINARY_ENTROPY_SIGNAL" in result["details"]["failure_codes"]


def test_allowlist_mismatch_fails_closed(tmp_path: Path) -> None:
    result = _analyze(_fixture(tmp_path), frozen_allowlist_sha256="0" * 64)
    assert result["status"] == "INCOMPLETE"
    assert "FROZEN_ALLOWLIST_MISMATCH" in result["details"]["failure_codes"]
    assert result["frozen_allowlist_sha256"] == FROZEN_ENTROPY_ALLOWLIST_SHA256


def test_random_selection_symbol_and_entropy_named_path_are_not_false_positives(
    tmp_path: Path,
) -> None:
    named = tmp_path / "entropy-analysis"
    named.mkdir()
    paths = _fixture(
        named,
        nm="00000000 S _V631_SITE_RANDOM_SELECTION_SHUFFLE\n",
    )

    result = _analyze(paths)

    assert result["status"] == "COMPLETE"
    assert result["details"]["forbidden_binary_signals"] == []


def test_owned_ast_gateway_call_is_resolved_but_forbidden_call_is_not(
    tmp_path: Path,
) -> None:
    gateway_call = {
        "kind": "CXXMemberCallExpr",
        "inner": [
            {
                "kind": "MemberExpr",
                "name": "bounded",
                "type": {"qualType": "<bound member function type>"},
                "inner": [
                    {
                        "kind": "DeclRefExpr",
                        "type": {"qualType": "V631DeterministicRngGateway"},
                    }
                ],
            }
        ],
    }
    forbidden_call = {
        "kind": "CallExpr",
        "inner": [
            {
                "kind": "DeclRefExpr",
                "referencedDecl": {
                    "kind": "FunctionDecl",
                    "name": "getrandom",
                },
            }
        ],
    }
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [gateway_call, forbidden_call],
    }

    result = _analyze(_fixture(tmp_path, ast=ast))

    assert result["status"] == "INCOMPLETE"
    assert [edge["kind"] for edge in result["details"]["entropy_call_edges"]] == [
        "GATEWAY",
        "FORBIDDEN",
    ]


def test_scratch_space_ast_call_is_not_misattributed_to_derivative(
    tmp_path: Path,
) -> None:
    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "CallExpr",
                "loc": {"file": "<scratch space>"},
                "inner": [{"kind": "ImplicitCastExpr"}],
            }
        ],
    }

    result = _analyze(_fixture(tmp_path, ast=ast))

    assert result["status"] == "COMPLETE"
    assert result["details"]["entropy_call_edges"] == []


def test_compiler_derived_registry_resolves_only_exact_finite_dispatch(
    tmp_path: Path,
) -> None:
    result = _analyze(
        _fixture(
            tmp_path,
            ast=_synthetic_registry_ast(),
            ir=_synthetic_dispatch_ir(),
        )
    )

    proof = result["details"]["compiler_derived_dispatch_proof"]
    assert result["status"] == "COMPLETE"
    assert proof["complete"] is True
    assert proof["target_count"] == 116
    assert len(proof["targets"]) == 116
    assert len(proof["target_root_sha256"]) == 64
    assert result["details"]["unresolved_or_disallowed_call_edges"] == []
    assert (
        sum(
            edge["kind"] == "REGISTERED_GAME_DISPATCH"
            for edge in result["details"]["entropy_call_edges"]
        )
        == 10
    )


@pytest.mark.parametrize(
    ("mutation", "expected_failure"),
    [
        ({"missing_push": True}, "REGISTRY_TARGET_COUNT_INVALID"),
        ({"duplicate_target": True}, "REGISTRY_TARGET_IDENTITY_INVALID"),
        ({"missing_definition": True}, "REGISTRY_TARGET_DEFINITION_MISSING"),
        ({"extra_reference": True}, "REGISTRY_REFERENCE_CLOSURE_INVALID"),
    ],
)
def test_registry_mutations_remain_fail_closed(
    tmp_path: Path,
    mutation: dict[str, bool],
    expected_failure: str,
) -> None:
    result = _analyze(
        _fixture(
            tmp_path,
            ast=_synthetic_registry_ast(**mutation),
            ir=_synthetic_dispatch_ir(),
        )
    )

    assert result["status"] == "INCOMPLETE"
    assert expected_failure in result["details"]["failure_codes"]
    assert (
        result["details"]["compiler_derived_dispatch_proof"]["complete"]
        is False
    )
    assert "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL" in result["details"]["failure_codes"]
