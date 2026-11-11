from __future__ import annotations

import hashlib
from pathlib import Path
import shutil

import pytest

from evaluation_v6_3_1.common import canonical_sha256
from evaluation_v6_3_1.entropy_real_collection import (
    EntropyRealCollectionError,
    PROBE_MODE,
    PROBE_STATE,
    collect_real_entropy_evidence,
    tree_sha256,
)


def _compiler() -> Path:
    candidate = shutil.which("clang++") or shutil.which("c++")
    if candidate is None:
        pytest.skip("real C++ compiler is unavailable")
    path = Path(candidate).resolve()
    if not path.is_file() or not path.stat().st_mode:
        pytest.skip("real C++ compiler is unavailable")
    return path


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trees(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "source"
    derivative = tmp_path / "derivative"
    source.mkdir()
    derivative.mkdir()
    (source / "engine.cpp").write_text("int source_only() { return 7; }\n", encoding="utf-8")
    (derivative / "helper.cpp").write_text("int helper() { return 42; }\n", encoding="utf-8")
    (derivative / "main.cpp").write_text("int helper(); int main() { return helper() == 42 ? 0 : 1; }\n", encoding="utf-8")
    return source, derivative


def _request(tmp_path: Path, output: str = "probe") -> dict[str, object]:
    source, derivative = _trees(tmp_path)
    compiler = _compiler()
    tools: dict[str, str] = {}
    nm = shutil.which("nm")
    if nm:
        tools["nm"] = str(Path(nm).resolve())
    return {
        "source_directory": source,
        "derivative_directory": derivative,
        "translation_units": ("helper.cpp", "main.cpp"),
        "output_directory": tmp_path / output,
        "compiler_path": compiler,
        "compile_flags": ("-std=c++17", "-O0"),
        "binary_inspection_tools": tools,
        "environment_allowlist": {"LANG": "C"},
        "compiler_sha256": _digest(compiler),
        "binary_inspection_tool_sha256s": {name: _digest(Path(path)) for name, path in tools.items()},
        "expected_source_tree_sha256": tree_sha256(source),
        "expected_derivative_tree_sha256": tree_sha256(derivative),
    }


def test_real_clang_probe_binds_artifacts_roots_and_zero_authority(tmp_path: Path) -> None:
    request = _request(tmp_path)
    report = collect_real_entropy_evidence(**request).canonical()

    assert report["mode"] == PROBE_MODE
    assert report["state"] == PROBE_STATE
    assert report["source_tree_sha256"] == tree_sha256(request["source_directory"])
    assert report["derivative_tree_sha256"] == tree_sha256(request["derivative_directory"])
    assert report["compiler"]["version_sha256"] == hashlib.sha256(
        (Path(request["output_directory"]) / "metadata/compiler-version.stdout").read_bytes()
    ).hexdigest()
    assert report["ast"] and report["llvm_ir"]
    for artifact in report["generated_artifacts"]:
        path = Path(request["output_directory"]) / artifact["path"]
        assert path.is_file()
        assert _digest(path) == artifact["sha256"]
    assert report["capabilities"]["runtime_sandbox_closed"] is False
    assert report["capabilities"]["mutation_closure_closed"] is False
    assert report["capabilities"]["whole_program_call_graph_closed"] is False
    assert "RUNTIME_SANDBOX_CLOSURE_UNIMPLEMENTED" in report["blockers"]
    assert all(value is False for key, value in report["authority"].items() if key != "permits")
    assert report["authority"]["permits"] == []
    assert report["report_sha256"] == canonical_sha256({key: value for key, value in report.items() if key != "report_sha256"})


def test_real_probe_rerun_has_deterministic_semantics(tmp_path: Path) -> None:
    request = _request(tmp_path)
    first = collect_real_entropy_evidence(**request).canonical()
    second = collect_real_entropy_evidence(**request).canonical()
    # Mach-O linkers can assign fresh UUIDs and Clang JSON ASTs can contain
    # process-specific IDs. The probe makes no reproducibility claim; its
    # stable meaning is its roots, requested invocations, inventory, and vetoes.
    for key in (
        "schema", "mode", "state", "source_tree_sha256", "derivative_tree_sha256",
        "sdk", "sysroot", "compile_flags", "link_mode", "link_kind_flags",
        "environment_allowlist", "translation_units",
        "capabilities", "blockers", "authority",
    ):
        assert second[key] == first[key]
    assert [artifact["path"] for artifact in second["generated_artifacts"]] == [
        artifact["path"] for artifact in first["generated_artifacts"]
    ]

    def command_shape(command: dict[str, object]) -> tuple[object, ...]:
        return (
            command["argv"], command["returncode"], command["stdout"]["path"],
            command["stderr"]["path"],
        )

    assert command_shape(second["compiler"]["version"]) == command_shape(first["compiler"]["version"])
    assert command_shape(second["compiler"]["target"]) == command_shape(first["compiler"]["target"])
    assert [command_shape(item["command"]) for item in second["ast"]] == [
        command_shape(item["command"]) for item in first["ast"]
    ]
    assert [command_shape(item["command"]) for item in second["llvm_ir"]] == [
        command_shape(item["command"]) for item in first["llvm_ir"]
    ]
    assert command_shape(second["link"]) == command_shape(first["link"])
    assert all(value is False for key, value in second["authority"].items() if key != "permits")
    assert second["authority"]["permits"] == []


def test_compiler_substitution_pin_fails_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request["compiler_sha256"] = "0" * 64
    with pytest.raises(EntropyRealCollectionError) as caught:
        collect_real_entropy_evidence(**request)
    assert caught.value.code == "PROBE_TOOL_SUBSTITUTION"


def test_root_drift_pin_fails_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    derivative = request["derivative_directory"]
    (derivative / "helper.cpp").write_text("int helper() { return 42 + 1; }\n", encoding="utf-8")
    with pytest.raises(EntropyRealCollectionError) as caught:
        collect_real_entropy_evidence(**request)
    assert caught.value.code == "PROBE_ROOT_DRIFT"


def test_omitted_translation_unit_fails_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    derivative = request["derivative_directory"]
    generated = derivative / "generated"
    generated.mkdir()
    (generated / "registry.cpp").write_text(
        "int generated_registry() { return 1; }\n",
        encoding="utf-8",
    )
    request["expected_derivative_tree_sha256"] = tree_sha256(derivative)

    with pytest.raises(EntropyRealCollectionError) as caught:
        collect_real_entropy_evidence(**request)

    assert caught.value.code == "PROBE_TRANSLATION_UNIT_INCOMPLETE"
    assert "generated/registry.cpp" in str(caught.value)


def test_overlapping_source_and_derivative_trees_fail_closed(tmp_path: Path) -> None:
    request = _request(tmp_path)
    source = request["source_directory"]
    nested = source / "derivative"
    nested.mkdir()
    (nested / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    request.update(
        derivative_directory=nested,
        translation_units=("main.cpp",),
        expected_source_tree_sha256=tree_sha256(source),
        expected_derivative_tree_sha256=tree_sha256(nested),
    )

    with pytest.raises(EntropyRealCollectionError) as caught:
        collect_real_entropy_evidence(**request)

    assert caught.value.code == "PROBE_PATH_INVALID"


def test_real_shared_library_probe_uses_target_specific_link_mode(tmp_path: Path) -> None:
    request = _request(tmp_path)
    derivative = request["derivative_directory"]
    (derivative / "main.cpp").write_text(
        'extern "C" int exported_value() { return 42; }\n',
        encoding="utf-8",
    )
    request.update(
        translation_units=("helper.cpp", "main.cpp"),
        expected_derivative_tree_sha256=tree_sha256(derivative),
        link_mode="shared",
    )

    report = collect_real_entropy_evidence(**request).canonical()

    assert report["link_mode"] == "shared"
    assert report["link_kind_flags"] in [["-dynamiclib"], ["-shared", "-fPIC"]]
    assert (Path(request["output_directory"]) / "binary/derivative-probe").is_file()
    assert report["authority"]["upload_authorized"] is False
