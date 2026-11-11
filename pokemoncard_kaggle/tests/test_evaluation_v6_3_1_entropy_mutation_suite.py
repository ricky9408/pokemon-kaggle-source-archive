from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
import shutil
import stat
import sys

import pytest

from evaluation_v6_3_1.entropy_mutation_suite import (
    EntropyMutationSuiteError,
    FROZEN_MUTATION_CATALOG,
    pin_command,
    run_entropy_mutation_suite,
    run_real_entropy_mutation_suite,
)


def _write_tool(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _write_shell_tool(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fixture(root: Path) -> Path:
    source = root / "clean-source"
    (source / "engine").mkdir(parents=True)
    (source / "generated").mkdir()
    lines = [f"{item.marker}\n" for item in FROZEN_MUTATION_CATALOG if item.marker is not None]
    (source / "engine" / "entropy_boundary.cpp").write_text("".join(lines), encoding="utf-8")
    (source / "generated" / "entropy_boundary.cpp").write_text("// generated wrapper\n", encoding="utf-8")
    return source


def _tools(root: Path, *, analyzer_mode: str = "normal", collector_mode: str = "normal") -> tuple[Path, Path]:
    collector_body = """
import hashlib, json, os, pathlib
source = pathlib.Path(os.environ["V631_SOURCE_ROOT"])
text = "\\n".join(line for path in source.rglob("*.cpp") for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("// V631_ENTROPY_SITE:"))
blockers = []
signals = (("random_device", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"), ("getrandom", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"), ("/dev/urandom", "DEVICE_ENTROPY"), ("::time", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"), ("dlopen", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"), ("rdrand", "FORBIDDEN_BINARY_ENTROPY_SIGNAL"), ("indirect()", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"))
for token, blocker in signals:
    if token in text:
        blockers.append({"blocker": blocker, "token": token, "source_root_sha256": os.environ["V631_SOURCE_ROOT_SHA256"]})
if not (source / "generated" / "entropy_boundary.cpp").exists():
    blockers.append({"blocker": "PROBE_TRANSLATION_UNIT_INCOMPLETE", "token": "generated/entropy_boundary.cpp", "source_root_sha256": os.environ["V631_SOURCE_ROOT_SHA256"]})
print(json.dumps({"schema": "eval.v6.3.1.entropy-mutation-collector-output.v1", "mutation_id": os.environ["V631_MUTATION_ID"], "source_root_sha256": os.environ["V631_SOURCE_ROOT_SHA256"], "command_sha256": os.environ["V631_COLLECTOR_COMMAND_SHA256"], "tool_sha256": os.environ["V631_COLLECTOR_TOOL_SHA256"], "records": blockers}, sort_keys=True))
    """.strip()
    if collector_mode == "masked":
        collector_body = collector_body.replace('text = "\\n".join(line for path in source.rglob("*.cpp") for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("// V631_ENTROPY_SITE:"))', 'text = ""')
    if collector_mode == "timeout":
        collector_body = "import time\ntime.sleep(1)\n" + collector_body
    collector = _write_tool(root / "collector.py", collector_body)
    analyzer_body = """
import hashlib, json, os, pathlib
records = json.loads(pathlib.Path(os.environ["V631_COLLECTOR_OUTPUT"]).read_text(encoding="utf-8")) ["records"]
evidence_root = hashlib.sha256(json.dumps({"schema": "eval.v6.3.1.entropy-mutation-evidence.v1", "records": records}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
blocker = records[0]["blocker"] if records else ""
print(json.dumps({"schema": "eval.v6.3.1.entropy-mutation-analyzer-output.v1", "mutation_id": os.environ["V631_MUTATION_ID"], "source_root_sha256": os.environ["V631_SOURCE_ROOT_SHA256"], "collector_output_sha256": hashlib.sha256(pathlib.Path(os.environ["V631_COLLECTOR_OUTPUT"]).read_bytes()).hexdigest(), "collector_command_sha256": os.environ["V631_COLLECTOR_COMMAND_SHA256"], "analyzer_command_sha256": os.environ["V631_ANALYZER_COMMAND_SHA256"], "toolchain_root_sha256": os.environ["V631_TOOLCHAIN_ROOT_SHA256"], "evidence_root_sha256": evidence_root, "detected": bool(records), "blocker": blocker}, sort_keys=True))
""".strip()
    if analyzer_mode == "echo":
        analyzer_body = analyzer_body.replace('blocker = records[0]["blocker"] if records else ""', 'blocker = {item.mutation_id: item.expected_blocker for item in ()}.get(os.environ["V631_MUTATION_ID"], "ENTROPY_FORGED")')
    if analyzer_mode == "survivor":
        analyzer_body = analyzer_body.replace('"detected": bool(records)', '"detected": False')
    analyzer = _write_tool(root / "analyzer.py", analyzer_body)
    return collector, analyzer


def _commands(root: Path, **kwargs: str) -> tuple[object, object]:
    collector, analyzer = _tools(root, **kwargs)
    python = str(Path(sys.executable).resolve())
    return pin_command([python, str(collector)]), pin_command([python, str(analyzer)])


def test_catalog_has_real_replacements_and_all_required_families() -> None:
    assert len(FROZEN_MUTATION_CATALOG) == 8
    assert all(item.is_omission or not (item.replacement or "").lstrip().startswith("//") for item in FROZEN_MUTATION_CATALOG)
    assert {item.family for item in FROZEN_MUTATION_CATALOG} == {
        "std::random_device/default engine", "getrandom/getentropy/syscall wrapper", "/dev/urandom",
        "clock/time", "dlopen/transitive library", "inline asm RDRAND/RDSEED",
        "unresolved function pointer/indirect call", "generated-source omission",
    }


def test_generic_harness_is_explicitly_non_authoritative(tmp_path: Path) -> None:
    source = _fixture(tmp_path)
    collector, analyzer = _commands(tmp_path)
    result = run_entropy_mutation_suite(source, collector, analyzer, tmp_path / "run")
    report = result.zero_authority_report()
    assert report["authoritative"] is False
    assert report["package3a_closure"] is False
    assert report["mutation_closure_closed"] is False
    assert report["state"] == "NO_UPLOAD"
    assert all(item.detected for item in result.outcomes)
    assert report["report_sha256"] == hashlib.sha256(json.dumps({key: value for key, value in report.items() if key not in {"report_sha256", "detail"}}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_echo_analyzer_cannot_forge_a_blocker(tmp_path: Path) -> None:
    source = _fixture(tmp_path)
    collector, analyzer = _commands(tmp_path, analyzer_mode="echo")
    with pytest.raises(EntropyMutationSuiteError) as caught:
        run_entropy_mutation_suite(source, collector, analyzer, tmp_path / "run")
    assert caught.value.code == "MUTATION_BLOCKER_MISMATCH"


def test_masked_injected_bypass_fails_closed(tmp_path: Path) -> None:
    source = _fixture(tmp_path)
    collector, analyzer = _commands(tmp_path, collector_mode="masked")
    with pytest.raises(EntropyMutationSuiteError) as caught:
        run_entropy_mutation_suite(source, collector, analyzer, tmp_path / "run")
    assert caught.value.code == "MUTATION_EVIDENCE_MISSING"


def test_survivor_and_timeout_fail_closed(tmp_path: Path) -> None:
    source = _fixture(tmp_path)
    collector, analyzer = _commands(tmp_path, analyzer_mode="survivor")
    with pytest.raises(EntropyMutationSuiteError) as caught:
        run_entropy_mutation_suite(source, collector, analyzer, tmp_path / "survivor")
    assert caught.value.code == "MUTATION_SURVIVOR"
    collector_path, analyzer_path = _tools(tmp_path, collector_mode="timeout")
    with pytest.raises(EntropyMutationSuiteError) as caught:
        python = str(Path(sys.executable).resolve())
        run_entropy_mutation_suite(source, pin_command([python, str(collector_path)]), pin_command([python, str(analyzer_path)]), tmp_path / "timeout", timeout_seconds=0.05)
    assert caught.value.code == "MUTATION_TIMEOUT"


def test_missing_marker_fails_closed(tmp_path: Path) -> None:
    source = _fixture(tmp_path)
    path = source / "engine" / "entropy_boundary.cpp"
    path.write_text(path.read_text(encoding="utf-8").replace("std-random-device-default-engine", "removed"), encoding="utf-8")
    collector, analyzer = _commands(tmp_path)
    with pytest.raises(EntropyMutationSuiteError) as caught:
        run_entropy_mutation_suite(source, collector, analyzer, tmp_path / "run")
    assert caught.value.code == "MUTATION_TARGET_AMBIGUOUS"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _real_fixture(tmp_path: Path) -> tuple[Path, Path, tuple[str, ...]]:
    source = tmp_path / "real-source"
    derivative = tmp_path / "real-derivative"
    source.mkdir()
    (derivative / "engine").mkdir(parents=True)
    (derivative / "generated").mkdir()
    (source / "provenance.cc").write_text("int v631_source_provenance() { return 0; }\n", encoding="utf-8")
    (derivative / "engine" / "entropy_boundary.cpp").write_text(
        """#include <fcntl.h>
#include <random>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ctime>
#include <cstdint>
int v631_entropy_probe(int seed) {
  int value = seed;
  // V631_ENTROPY_SITE: std-random-device-default-engine
  // V631_ENTROPY_SITE: getrandom-getentropy-syscall-wrapper
  // V631_ENTROPY_SITE: dev-urandom
  // V631_ENTROPY_SITE: clock-time
  // V631_ENTROPY_SITE: dlopen-transitive-library
  // V631_ENTROPY_SITE: inline-rdrand-rdseed
  // V631_ENTROPY_SITE: unresolved-indirect-call
  return value;
}
""", encoding="utf-8")
    (derivative / "generated" / "entropy_boundary.cpp").write_text("int v631_generated_probe() { return 1; }\n", encoding="utf-8")
    (derivative / "main.cpp").write_text("int v631_entropy_probe(int); int v631_generated_probe(); int main() { (void)v631_entropy_probe(0); return v631_generated_probe() == 1 ? 0 : 1; }\n", encoding="utf-8")
    return source, derivative, ("engine/entropy_boundary.cpp", "generated/entropy_boundary.cpp", "main.cpp")


@pytest.mark.skipif(platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}, reason="real mutation suite requires Linux/amd64")
def test_real_suite_uses_compiler_static_and_runtime_evidence(tmp_path: Path) -> None:
    strace = shutil.which("strace")
    env = shutil.which("env")
    compiler = shutil.which("clang++") or shutil.which("c++")
    objdump = shutil.which("objdump")
    nm = shutil.which("nm")
    if not all((strace, env, compiler, objdump, nm)):
        pytest.skip("Linux/amd64 compiler, inspection tools, or strace unavailable")
    source, derivative, units = _real_fixture(tmp_path)
    tracer = Path(strace).resolve()
    sandbox = Path(env).resolve()
    underlying_compiler = Path(compiler).resolve()
    compiler_path = _write_shell_tool(
        tmp_path / "pinned-cxx-driver",
        f'compiler="{underlying_compiler}"\nexport PATH="/usr/bin:/bin:/usr/lib/llvm-19/bin"\nif [ "$1" = "--version" ] || [ "$1" = "-dumpmachine" ]; then exec "$compiler" "$@"; fi\nexec "$compiler" "$@" -lstdc++ -ldl\n',
    ).resolve()
    otool = _write_shell_tool(tmp_path / "otool-adapter", "exit 0\n")
    tools = {"nm": Path(nm).resolve(), "objdump": Path(objdump).resolve(), "otool": otool.resolve()}
    try:
        result = run_real_entropy_mutation_suite(
            source_directory=source,
            derivative_directory=derivative,
            translation_units=units,
            output_directory=tmp_path / "real-run",
            compiler_path=compiler_path,
            compile_flags=("-std=c++17", "-O0"),
            binary_inspection_tools=tools,
            environment_allowlist={"LC_ALL": "C"},
            compiler_sha256=_digest(compiler_path),
            binary_inspection_tool_sha256s={name: _digest(path) for name, path in tools.items()},
            runtime_configuration={
                "tracer_path": tracer,
                "tracer_sha256": _digest(tracer),
                "sandbox_path": sandbox,
                "sandbox_sha256": _digest(sandbox),
                "sandbox_argv": ("--",),
                "environment_allowlist": {"LC_ALL": "C"},
                "container_root_sha256": "1" * 64,
                "runtime_root_sha256": "2" * 64,
                "timeout_seconds": 30,
            },
        )
    except EntropyMutationSuiteError as exc:
        if exc.code == "RUNTIME_TRACE_UNAVAILABLE":
            pytest.skip("the amd64 runtime cannot expose syscalls to the pinned tracer")
        raise
    assert len(result.outcomes) == 8
    assert all(item.detected for item in result.outcomes)
    assert result.canonical()["authority"] is False
    assert result.canonical()["authoritative_evidence"] is False
    assert result.canonical()["real_collector_evidence"] is True
    assert result.canonical()["package3a_closure"] is False
    assert result.canonical()["mutation_closure_closed"] is False
    assert result.canonical()["entropy_bypass_catalog_complete"] is True
