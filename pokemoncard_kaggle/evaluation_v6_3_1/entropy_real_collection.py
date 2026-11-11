"""Collect a real, local compiler/binary entropy-evidence probe.

This is deliberately narrower than the fixture-oriented entropy collector.  It
executes an explicitly named host compiler against real derivative translation
units and preserves its raw output, but it cannot establish any campaign or
runtime closure.  A successful run is therefore always ``PROBE_ONLY_INCOMPLETE``
and permanently zero-authority.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256


REAL_ENTROPY_PROBE_SCHEMA = "eval.v6.3.1.entropy-real-collection.v1"
PROBE_MODE = "PROBE_ONLY/NO_UPLOAD"
PROBE_STATE = "PROBE_ONLY_INCOMPLETE"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RELATIVE_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*(?:/[A-Za-z0-9][A-Za-z0-9._+-]*)*$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INSPECTION_ARGS = {"nm": ("-g",), "otool": ("-L",), "objdump": ("-d",)}
_TRANSLATION_UNIT_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})
_MARKER = b"eval.v6.3.1.entropy-real-collection.v1\n"
_MARKER_PATH = ".entropy-real-collection.marker"


class EntropyRealCollectionError(ValueError):
    """A real entropy probe precondition or real tool execution failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> EntropyRealCollectionError:
    return EntropyRealCollectionError(code, message)


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _sha256_file(path: Path, label: str) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise _fail("PROBE_PATH_UNREADABLE", f"{label} cannot be read: {path}") from exc


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _assert_tree(root: Path, label: str) -> Path:
    if not root.is_absolute():
        raise _fail("PROBE_PATH_INVALID", f"{label} must be absolute")
    if root.is_symlink() or not root.is_dir():
        raise _fail("PROBE_PATH_INVALID", f"{label} must be a non-symlink directory")
    resolved = root.resolve(strict=True)
    for item in root.rglob("*"):
        if item.is_symlink():
            raise _fail("PROBE_SYMLINK_REJECTED", f"{label} contains a symbolic link: {item}")
        if not item.is_dir() and not item.is_file():
            raise _fail("PROBE_PATH_INVALID", f"{label} contains a non-regular entry: {item}")
    return resolved


def tree_sha256(root: Path) -> str:
    """Return the repository-compatible hash of a regular, symlink-free tree."""

    checked = _assert_tree(root, "tree root")
    digest = sha256()
    files = sorted((item for item in checked.rglob("*") if item.is_file()), key=lambda item: item.as_posix())
    for path in files:
        relative = path.relative_to(checked).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _relative_path(value: str, label: str) -> str:
    if type(value) is not str or _RELATIVE_PATH_RE.fullmatch(value) is None or value in {".", ".."}:
        raise _fail("PROBE_TRANSLATION_UNIT_INVALID", f"{label} must be a canonical relative POSIX path")
    return value


def _pin(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("PROBE_PIN_INVALID", f"{label} must be a lowercase SHA-256 digest")
    return value


def _absolute_executable(value: str | Path, label: str, expected_sha256: str | None) -> dict[str, str]:
    raw = Path(value)
    if not raw.is_absolute():
        raise _fail("PROBE_TOOL_MISSING", f"{label} must be an absolute path")
    try:
        path = raw.resolve(strict=True)
    except OSError as exc:
        raise _fail("PROBE_TOOL_MISSING", f"{label} does not exist: {raw}") from exc
    if not path.is_file() or not os.access(path, os.X_OK):
        raise _fail("PROBE_TOOL_MISSING", f"{label} is not an executable regular file: {raw}")
    actual = _sha256_file(path, label)
    if expected_sha256 is not None and actual != expected_sha256:
        raise _fail("PROBE_TOOL_SUBSTITUTION", f"{label} bytes do not match its supplied pin")
    return {"requested_path": str(raw), "resolved_path": str(path), "sha256": actual}


def _environment(value: Mapping[str, str] | None) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise _fail("PROBE_ENVIRONMENT_INVALID", "environment_allowlist must be a mapping")
    result: dict[str, str] = {}
    for key, item in value.items():
        if type(key) is not str or _ENV_KEY_RE.fullmatch(key) is None:
            raise _fail("PROBE_ENVIRONMENT_INVALID", "environment allowlist keys must be canonical names")
        if type(item) is not str or "\x00" in item:
            raise _fail("PROBE_ENVIRONMENT_INVALID", f"environment value for {key} must be text without NUL")
        result[key] = item
    return dict(sorted(result.items()))


def _compile_flags(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise _fail("PROBE_FLAGS_INVALID", "compile_flags must be a sequence of strings")
    flags = tuple(value)
    if any(type(flag) is not str or not flag or "\x00" in flag for flag in flags):
        raise _fail("PROBE_FLAGS_INVALID", "compile_flags must contain non-empty text")
    forbidden = {
        "-o", "-c", "-S", "-E", "-emit-llvm", "-fsyntax-only", "-save-temps", "-MJ",
        "-M", "-MM", "-MD", "-MMD", "-MF", "-MT", "-MQ", "-ftime-trace", "-isysroot", "--sysroot",
        "-Xclang", "-Xlinker", "-mllvm",
    }
    for flag in flags:
        if flag in forbidden or flag.startswith((
            "-o", "-MJ", "-MF", "-MT", "-MQ", "-Wl,", "-fplugin", "-fmodules",
            "-fprofile", "-fdiagnostics-file=", "-ftime-trace=",
        )) or flag.startswith("@"):
            raise _fail("PROBE_FLAGS_INVALID", f"compile flag can redirect or replace collector output: {flag}")
    return flags


def _optional_root(value: str | Path | None, label: str) -> tuple[tuple[str, ...], dict[str, Any] | None]:
    if value is None:
        return (), None
    raw = Path(value)
    if not raw.is_absolute() or raw.is_symlink():
        raise _fail("PROBE_PATH_INVALID", f"{label} must be an absolute non-symlink path")
    resolved = raw.resolve(strict=True)
    if resolved.is_dir():
        binding = {"path": str(resolved), "kind": "directory", "tree_sha256": tree_sha256(resolved)}
    elif resolved.is_file():
        binding = {"path": str(resolved), "kind": "file", "sha256": _sha256_file(resolved, label)}
    else:
        raise _fail("PROBE_PATH_INVALID", f"{label} must be a regular file or directory")
    return (("-isysroot", str(resolved)) if label == "sdk_path" else (f"--sysroot={resolved}",)), binding


def _prepare_output(root: Path, allowed_existing: set[str]) -> Path:
    if not root.is_absolute() or root.is_symlink():
        raise _fail("PROBE_OUTPUT_INVALID", "output_directory must be an absolute non-symlink path")
    if not root.parent.is_dir() or root.parent.is_symlink():
        raise _fail("PROBE_OUTPUT_INVALID", "output_directory parent must already be a non-symlink directory")
    root.mkdir(exist_ok=True)
    if not root.is_dir() or root.is_symlink():
        raise _fail("PROBE_OUTPUT_INVALID", "output_directory must be a non-symlink directory")
    resolved = root.resolve(strict=True)
    for item in root.rglob("*"):
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise _fail("PROBE_SYMLINK_REJECTED", f"output_directory contains an unsafe entry: {item}")
    existing = {item.relative_to(resolved).as_posix() for item in resolved.rglob("*") if item.is_file()}
    if existing and _MARKER_PATH not in existing:
        raise _fail("PROBE_OUTPUT_INVALID", "output_directory is non-empty and not a prior probe run")
    if _MARKER_PATH in existing and (resolved / _MARKER_PATH).read_bytes() != _MARKER:
        raise _fail("PROBE_OUTPUT_INVALID", "output_directory marker does not belong to this probe")
    unexpected = existing - allowed_existing
    if unexpected:
        raise _fail("PROBE_OUTPUT_INVALID", f"output_directory contains unbound artifacts: {sorted(unexpected)}")
    return resolved


def _write_artifact(root: Path, relative: str, data: bytes) -> dict[str, str]:
    target = root / relative
    if not _is_within(target.resolve(strict=False), root):
        raise _fail("PROBE_OUTPUT_ESCAPE", f"artifact path escapes output_directory: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.is_symlink():
        raise _fail("PROBE_SYMLINK_REJECTED", f"artifact target is a symbolic link: {relative}")
    target.write_bytes(data)
    return {"path": relative, "sha256": _sha256_bytes(data), "bytes": str(len(data))}


def _prepare_compiler_output(root: Path, relative: str) -> Path:
    target = root / relative
    if not _is_within(target.resolve(strict=False), root):
        raise _fail("PROBE_OUTPUT_ESCAPE", f"compiler output path escapes output_directory: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise _fail("PROBE_OUTPUT_INVALID", f"compiler output target is unsafe: {relative}")
    return target


def _run(
    *, argv: Sequence[str], cwd: Path, environment: Mapping[str, str], timeout_seconds: int,
    output_root: Path, stdout_path: str, stderr_path: str,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(argv), cwd=str(cwd), env=dict(environment), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, shell=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _fail("PROBE_TOOL_EXECUTION_FAILED", f"command could not complete: {argv[0]}") from exc
    stdout = _write_artifact(output_root, stdout_path, completed.stdout)
    stderr = _write_artifact(output_root, stderr_path, completed.stderr)
    return {"argv": list(argv), "returncode": completed.returncode, "stdout": stdout, "stderr": stderr}


def _assert_success(record: Mapping[str, Any], label: str) -> None:
    if record["returncode"] != 0:
        raise _fail("PROBE_COMMAND_FAILED", f"{label} returned {record['returncode']}")


def _expected_artifact_paths(unit_count: int, tool_names: Sequence[str]) -> set[str]:
    paths = {_MARKER_PATH, "metadata/compiler-version.stdout", "metadata/compiler-version.stderr", "metadata/target-triple.stdout", "metadata/target-triple.stderr", "link/stdout", "link/stderr", "binary/derivative-probe"}
    for index in range(unit_count):
        paths.update({f"ast/tu-{index:04d}.json", f"ast/tu-{index:04d}.stderr", f"ir/tu-{index:04d}.ll", f"ir/tu-{index:04d}.stdout", f"ir/tu-{index:04d}.stderr"})
    for name in tool_names:
        paths.update({f"inspection/{name}.stdout", f"inspection/{name}.stderr"})
    return paths


@dataclass(frozen=True, slots=True)
class RealEntropyProbeReport:
    """An immutable canonical report for an intentionally incomplete host probe."""

    _wire: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return _thaw(self._wire)

    @property
    def report_sha256(self) -> str:
        return self._wire["report_sha256"]


def collect_real_entropy_evidence(
    *,
    source_directory: str | Path,
    derivative_directory: str | Path,
    translation_units: Sequence[str],
    output_directory: str | Path,
    compiler_path: str | Path,
    compile_flags: Sequence[str],
    binary_inspection_tools: Mapping[str, str | Path] | None = None,
    environment_allowlist: Mapping[str, str] | None = None,
    sdk_path: str | Path | None = None,
    sysroot_path: str | Path | None = None,
    compiler_sha256: str | None = None,
    binary_inspection_tool_sha256s: Mapping[str, str] | None = None,
    expected_source_tree_sha256: str | None = None,
    expected_derivative_tree_sha256: str | None = None,
    link_mode: str = "executable",
    timeout_seconds: int = 30,
) -> RealEntropyProbeReport:
    """Run a real compiler probe and return only an incomplete zero-authority report."""

    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise _fail("PROBE_TIMEOUT_INVALID", "timeout_seconds must be an integer from 1 through 120")
    if type(link_mode) is not str or link_mode not in {"executable", "shared"}:
        raise _fail("PROBE_LINK_MODE_INVALID", "link_mode must be executable or shared")
    source = _assert_tree(Path(source_directory), "source_directory")
    derivative = _assert_tree(Path(derivative_directory), "derivative_directory")
    if (
        source == derivative
        or _is_within(source, derivative)
        or _is_within(derivative, source)
    ):
        raise _fail(
            "PROBE_PATH_INVALID",
            "source_directory and derivative_directory must be distinct, non-overlapping trees",
        )
    units = tuple(_relative_path(item, f"translation_units[{index}]") for index, item in enumerate(translation_units))
    if not units or len(set(units)) != len(units) or list(units) != sorted(units):
        raise _fail("PROBE_TRANSLATION_UNIT_INVALID", "translation_units must be non-empty, sorted, and unique")
    discovered_units = tuple(
        sorted(
            path.relative_to(derivative).as_posix()
            for path in derivative.rglob("*")
            if path.is_file() and path.suffix.lower() in _TRANSLATION_UNIT_SUFFIXES
        )
    )
    if units != discovered_units:
        missing = sorted(set(discovered_units) - set(units))
        unexpected = sorted(set(units) - set(discovered_units))
        raise _fail(
            "PROBE_TRANSLATION_UNIT_INCOMPLETE",
            "translation_units must exactly match every compilable derivative source; "
            f"missing={missing}, unexpected={unexpected}",
        )
    unit_paths: list[Path] = []
    for unit in units:
        path = derivative / unit
        if path.is_symlink() or not path.is_file() or not _is_within(path.resolve(strict=True), derivative):
            raise _fail("PROBE_TRANSLATION_UNIT_INVALID", f"translation unit is missing or escapes derivative: {unit}")
        unit_paths.append(path)

    flags = _compile_flags(compile_flags)
    environment = _environment(environment_allowlist)
    compiler = _absolute_executable(compiler_path, "compiler_path", _pin(compiler_sha256, "compiler_sha256"))
    raw_tools = {} if binary_inspection_tools is None else binary_inspection_tools
    if not isinstance(raw_tools, Mapping) or any(name not in _INSPECTION_ARGS for name in raw_tools):
        raise _fail("PROBE_TOOL_MISSING", "binary_inspection_tools may contain only nm, otool, and objdump")
    raw_tool_pins = {} if binary_inspection_tool_sha256s is None else binary_inspection_tool_sha256s
    if not isinstance(raw_tool_pins, Mapping) or set(raw_tool_pins) - set(raw_tools):
        raise _fail("PROBE_PIN_INVALID", "inspection tool pins must bind supplied inspection tools")
    tools = {
        name: _absolute_executable(raw_tools[name], f"binary_inspection_tools[{name}]", _pin(raw_tool_pins.get(name), f"binary_inspection_tool_sha256s[{name}]"))
        for name in sorted(raw_tools)
    }
    sdk_flags, sdk_binding = _optional_root(sdk_path, "sdk_path")
    sysroot_flags, sysroot_binding = _optional_root(sysroot_path, "sysroot_path")
    common_flags = (*flags, *sdk_flags, *sysroot_flags)

    expected_source = _pin(expected_source_tree_sha256, "expected_source_tree_sha256")
    expected_derivative = _pin(expected_derivative_tree_sha256, "expected_derivative_tree_sha256")
    initial_source_root = tree_sha256(source)
    initial_derivative_root = tree_sha256(derivative)
    if (expected_source is not None and expected_source != initial_source_root) or (expected_derivative is not None and expected_derivative != initial_derivative_root):
        raise _fail("PROBE_ROOT_DRIFT", "supplied source or derivative tree root does not match actual bytes")

    output_candidate = Path(output_directory)
    resolved_output = output_candidate.resolve(strict=False)
    if any(_is_within(resolved_output, root) or _is_within(root, resolved_output) for root in (source, derivative)):
        raise _fail("PROBE_OUTPUT_ESCAPE", "output_directory must not overlap source or derivative trees")
    expected_paths = _expected_artifact_paths(len(units), sorted(tools))
    output = _prepare_output(output_candidate, expected_paths)
    artifacts: list[dict[str, str]] = [_write_artifact(output, _MARKER_PATH, _MARKER)]

    version = _run(
        argv=(compiler["resolved_path"], "--version"), cwd=derivative, environment=environment,
        timeout_seconds=timeout_seconds, output_root=output,
        stdout_path="metadata/compiler-version.stdout", stderr_path="metadata/compiler-version.stderr",
    )
    _assert_success(version, "compiler version")
    artifacts.extend((version["stdout"], version["stderr"]))
    target = _run(
        argv=(compiler["resolved_path"], "-dumpmachine"), cwd=derivative, environment=environment,
        timeout_seconds=timeout_seconds, output_root=output,
        stdout_path="metadata/target-triple.stdout", stderr_path="metadata/target-triple.stderr",
    )
    artifacts.extend((target["stdout"], target["stderr"]))
    target_triple = target["stdout"]["sha256"] if target["returncode"] == 0 else None
    if target["returncode"] == 0:
        raw_target = (output / target["stdout"]["path"]).read_text(encoding="utf-8").strip()
        target_triple = raw_target or None

    ast_records: list[dict[str, Any]] = []
    ir_records: list[dict[str, Any]] = []
    for index, unit in enumerate(units):
        ast = _run(
            argv=(compiler["resolved_path"], *common_flags, "-fsyntax-only", "-Xclang", "-ast-dump=json", unit),
            cwd=derivative, environment=environment, timeout_seconds=timeout_seconds, output_root=output,
            stdout_path=f"ast/tu-{index:04d}.json", stderr_path=f"ast/tu-{index:04d}.stderr",
        )
        _assert_success(ast, f"AST dump for {unit}")
        try:
            ast_json = json.loads((output / ast["stdout"]["path"]).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _fail("PROBE_AST_MALFORMED", f"AST dump is not JSON for {unit}") from exc
        if type(ast_json) is not dict or ast_json.get("kind") != "TranslationUnitDecl":
            raise _fail("PROBE_AST_MALFORMED", f"AST dump has no TranslationUnitDecl root for {unit}")
        artifacts.extend((ast["stdout"], ast["stderr"]))
        ast_records.append({"translation_unit": unit, "command": ast, "ast_sha256": ast["stdout"]["sha256"]})

        ir_path = f"ir/tu-{index:04d}.ll"
        ir_output = _prepare_compiler_output(output, ir_path)
        ir = _run(
            argv=(compiler["resolved_path"], *common_flags, "-S", "-emit-llvm", unit, "-o", str(ir_output)),
            cwd=derivative, environment=environment, timeout_seconds=timeout_seconds, output_root=output,
            stdout_path=f"ir/tu-{index:04d}.stdout", stderr_path=f"ir/tu-{index:04d}.stderr",
        )
        _assert_success(ir, f"LLVM IR emission for {unit}")
        ir_file = ir_output
        if not ir_file.is_file() or not ir_file.read_bytes():
            raise _fail("PROBE_IR_MISSING", f"LLVM IR output is missing or empty for {unit}")
        ir_artifact = {"path": ir_path, "sha256": _sha256_file(ir_file, ir_path), "bytes": str(ir_file.stat().st_size)}
        artifacts.extend((ir_artifact, ir["stdout"], ir["stderr"]))
        ir_records.append({"translation_unit": unit, "command": ir, "ir_sha256": ir_artifact["sha256"]})

    binary_path = _prepare_compiler_output(output, "binary/derivative-probe")
    if link_mode == "shared":
        if target_triple is None:
            raise _fail(
                "PROBE_TARGET_UNKNOWN",
                "shared-library mode requires a compiler-reported target triple",
            )
        link_kind_flags = (
            ("-dynamiclib",)
            if "darwin" in target_triple.lower() or "apple" in target_triple.lower()
            else ("-shared", "-fPIC")
        )
    else:
        link_kind_flags = ()
    link = _run(
        argv=(
            compiler["resolved_path"],
            *common_flags,
            *link_kind_flags,
            *units,
            "-o",
            str(binary_path),
        ),
        cwd=derivative,
        environment=environment, timeout_seconds=timeout_seconds, output_root=output,
        stdout_path="link/stdout", stderr_path="link/stderr",
    )
    _assert_success(link, "derivative link")
    if (
        not binary_path.is_file()
        or binary_path.is_symlink()
        or not binary_path.read_bytes()
        or (link_mode == "executable" and not os.access(binary_path, os.X_OK))
    ):
        raise _fail(
            "PROBE_BINARY_MISSING",
            "linked derivative artifact is missing, empty, unsafe, or not executable when required",
        )
    binary_artifact = {"path": "binary/derivative-probe", "sha256": _sha256_file(binary_path, "linked binary"), "bytes": str(binary_path.stat().st_size)}
    artifacts.extend((link["stdout"], link["stderr"], binary_artifact))

    inspection: dict[str, Any] = {}
    for name, tool in tools.items():
        record = _run(
            argv=(tool["resolved_path"], *_INSPECTION_ARGS[name], str(binary_path)), cwd=derivative,
            environment=environment, timeout_seconds=timeout_seconds, output_root=output,
            stdout_path=f"inspection/{name}.stdout", stderr_path=f"inspection/{name}.stderr",
        )
        _assert_success(record, f"{name} binary inspection")
        artifacts.extend((record["stdout"], record["stderr"]))
        inspection[name] = {"tool": tool, "command": record}

    if tree_sha256(source) != initial_source_root or tree_sha256(derivative) != initial_derivative_root:
        raise _fail("PROBE_ROOT_DRIFT", "source or derivative tree changed while the probe ran")
    if _sha256_file(Path(compiler["resolved_path"]), "compiler_path") != compiler["sha256"]:
        raise _fail("PROBE_TOOL_SUBSTITUTION", "compiler bytes changed while the probe ran")
    for name, tool in tools.items():
        if _sha256_file(Path(tool["resolved_path"]), f"inspection tool {name}") != tool["sha256"]:
            raise _fail("PROBE_TOOL_SUBSTITUTION", f"inspection tool bytes changed while the probe ran: {name}")

    actual_paths = {item.relative_to(output).as_posix() for item in output.rglob("*") if item.is_file()}
    if actual_paths != expected_paths:
        raise _fail("PROBE_OUTPUT_INVALID", "generated artifact set does not match the bound collector inventory")
    artifacts.sort(key=lambda item: item["path"])
    payload: dict[str, Any] = {
        "schema": REAL_ENTROPY_PROBE_SCHEMA,
        "mode": PROBE_MODE,
        "state": PROBE_STATE,
        "source_tree_sha256": initial_source_root,
        "derivative_tree_sha256": initial_derivative_root,
        "linked_binary_sha256": binary_artifact["sha256"],
        "compiler": {**compiler, "version": version, "version_sha256": version["stdout"]["sha256"], "target": target, "target_triple": target_triple},
        "sdk": sdk_binding,
        "sysroot": sysroot_binding,
        "compile_flags": list(flags),
        "link_mode": link_mode,
        "link_kind_flags": list(link_kind_flags),
        "environment_allowlist": environment,
        "translation_units": list(units),
        "ast": ast_records,
        "llvm_ir": ir_records,
        "link": link,
        "inspection": inspection,
        "generated_artifacts": artifacts,
        "capabilities": {
            "source_root_bound": True,
            "derivative_root_bound": True,
            "compiler_version_bound": True,
            "syntax_ast_collected": True,
            "llvm_ir_collected": True,
            "linked_binary_collected": True,
            "binary_inspection_collected": bool(tools),
            "whole_program_call_graph_closed": False,
            "runtime_sandbox_closed": False,
            "mutation_closure_closed": False,
            "entropy_completeness_claimed": False,
        },
        "blockers": [
            "WHOLE_PROGRAM_CALL_GRAPH_CLOSURE_UNIMPLEMENTED",
            "RUNTIME_SANDBOX_CLOSURE_UNIMPLEMENTED",
            "MUTATION_CLOSURE_UNIMPLEMENTED",
            "ENTROPY_COMPLETENESS_UNPROVEN",
            "EXTERNAL_AUDIT_AND_POLICY_PINS_UNIMPLEMENTED",
        ],
        "authority": {
            "authority": False,
            "campaign_authorized": False,
            "upload_authorized": False,
            "calibration_upload_authorized": False,
            "production_upload_authorized": False,
            "holdout_access_authorized": False,
            "sealed_holdout_access_authorized": False,
            "agent_modification_authorized": False,
            "permits": [],
        },
    }
    payload["report_sha256"] = canonical_sha256(payload)
    return RealEntropyProbeReport(_freeze(payload))


__all__ = [
    "EntropyRealCollectionError",
    "PROBE_MODE",
    "PROBE_STATE",
    "REAL_ENTROPY_PROBE_SCHEMA",
    "RealEntropyProbeReport",
    "collect_real_entropy_evidence",
    "tree_sha256",
]
