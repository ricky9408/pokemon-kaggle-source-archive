"""Fail-closed mutation testing for the v6.3.1 entropy boundary.

This module is an offline test harness, not a campaign component.  It runs a
caller-provided collector followed by an analyzer in a fresh process for every
mutation.  Commands, executable bytes, source trees, command output, and the
catalog are all hash-bound in the returned report.  A complete local run is
still permanently ``NO_UPLOAD``.

The source fixture is intentionally explicit.  Each ordinary mutation replaces
one exact marker line in ``engine/entropy_boundary.cpp``.  The generated-source
mutation removes one exact generated translation unit.  Keeping these edits
small and preregistered prevents a mutation runner from silently changing the
question it is testing.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256
from .entropy_real_collection import EntropyRealCollectionError, collect_real_entropy_evidence
from .entropy_static_closure import analyze_entropy_static_closure
from .entropy_runtime_sandbox import RuntimeEntropySandboxError, collect_runtime_entropy_sandbox_evidence


SUITE_SCHEMA = "eval.v6.3.1.entropy-mutation-suite.v1"
REAL_SUITE_SCHEMA = "eval.v6.3.1.entropy-real-mutation-suite.v1"
CATALOG_SCHEMA = "eval.v6.3.1.entropy-mutation-catalog.v1"
COLLECTOR_OUTPUT_SCHEMA = "eval.v6.3.1.entropy-mutation-collector-output.v1"
ANALYZER_OUTPUT_SCHEMA = "eval.v6.3.1.entropy-mutation-analyzer-output.v1"
MODE = "TEST_ONLY/OFFLINE_ZERO_AUTHORITY"
REAL_SUITE_MODE = "REAL_COLLECTOR_STATIC_RUNTIME/OFFLINE_ZERO_AUTHORITY"
STATE = "NO_UPLOAD"
_SHA256_LENGTH = 64
_PLACEHOLDERS = {
    "source_root",
    "output_root",
    "mutation_id",
    "collector_output",
}
_PROTECTED_ENVIRONMENT_KEYS = {
    "V631_SOURCE_ROOT", "V631_OUTPUT_ROOT", "V631_MUTATION_ID", "V631_COLLECTOR_OUTPUT",
    "V631_SOURCE_ROOT_SHA256", "V631_COLLECTOR_COMMAND_SHA256", "V631_COLLECTOR_TOOL_SHA256",
    "V631_ANALYZER_COMMAND_SHA256", "V631_ANALYZER_TOOL_SHA256", "V631_TOOLCHAIN_ROOT_SHA256",
}
_AUTHORITY = {
    "authority": False,
    "upload_authorized": False,
    "calibration_upload_authorized": False,
    "production_upload_authorized": False,
    "holdout_access_authorized": False,
    "sealed_holdout_access_authorized": False,
    "agent_modification_authorized": False,
    "permits": [],
}


class EntropyMutationSuiteError(ValueError):
    """A mutation suite precondition or execution failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> EntropyMutationSuiteError:
    return EntropyMutationSuiteError(code, message)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path, label: str) -> str:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise _fail("MUTATION_PATH_UNREADABLE", f"{label} cannot be read: {path}") from exc


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != _SHA256_LENGTH or any(char not in "0123456789abcdef" for char in value):
        raise _fail("MUTATION_HASH_INVALID", f"{label} must be a lowercase SHA-256 digest")
    return value


def _authority_payload() -> dict[str, Any]:
    return {key: list(value) if type(value) is list else value for key, value in _AUTHORITY.items()}


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise _fail("MUTATION_SCHEMA_INVALID", f"{label} must be non-empty text without NUL")
    return value


def _relative_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.startswith("/") or "\\" in value:
        raise _fail("MUTATION_PATH_INVALID", f"{label} must be a relative POSIX path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or "\x00" in part for part in parts):
        raise _fail("MUTATION_PATH_INVALID", f"{label} is not canonical")
    return value


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


@dataclass(frozen=True, slots=True)
class MutationSpec:
    """One isolated, preregistered entropy-boundary mutation."""

    mutation_id: str
    family: str
    target_relative_path: str
    marker: str | None
    replacement: str | None
    expected_blocker: str

    def __post_init__(self) -> None:
        _text(self.mutation_id, "mutation_id")
        _text(self.family, "family")
        _relative_path(self.target_relative_path, "target_relative_path")
        if self.marker is None:
            if self.replacement is not None:
                raise _fail("MUTATION_CATALOG_INVALID", "omission mutations cannot have a replacement")
        else:
            _text(self.marker, "marker")
            if self.replacement is None:
                raise _fail("MUTATION_CATALOG_INVALID", "text mutations require a replacement")
            _text(self.replacement, "replacement")
            if self.marker == self.replacement:
                raise _fail("MUTATION_CATALOG_INVALID", "mutation must change source bytes")
        _text(self.expected_blocker, "expected_blocker")

    @property
    def is_omission(self) -> bool:
        return self.marker is None

    def canonical(self) -> dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "family": self.family,
            "target_relative_path": self.target_relative_path,
            "marker": self.marker,
            "replacement": self.replacement,
            "expected_blocker": self.expected_blocker,
        }


def _marker(family: str) -> str:
    return f"// V631_ENTROPY_SITE: {family}"


# The replacements are deliberately compilable C++ bypasses.  The marker is
# only an exact source anchor; it is never itself evidence and is never passed
# to a child as an expected result.
FROZEN_MUTATION_CATALOG: tuple[MutationSpec, ...] = (
    MutationSpec("std-random-device-default-engine", "std::random_device/default engine", "engine/entropy_boundary.cpp", _marker("std-random-device-default-engine"), "std::random_device device; value ^= static_cast<int>(device());", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"),
    MutationSpec("getrandom-getentropy-syscall-wrapper", "getrandom/getentropy/syscall wrapper", "engine/entropy_boundary.cpp", _marker("getrandom-getentropy-syscall-wrapper"), "unsigned char bytes[1] = {}; auto wrapper = [](void *ptr, size_t length) { return ::syscall(SYS_getrandom, ptr, length, 0); }; if (::getrandom(bytes, sizeof(bytes), 0) == 1 || ::getentropy(bytes, sizeof(bytes)) == 0 || wrapper(bytes, sizeof(bytes)) == 1) value ^= bytes[0];", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"),
    MutationSpec("dev-urandom", "/dev/urandom", "engine/entropy_boundary.cpp", _marker("dev-urandom"), "int fd = static_cast<int>(::syscall(SYS_openat, AT_FDCWD, \"/dev/urandom\", O_RDONLY, 0)); if (fd >= 0) { unsigned char byte = 0; (void)::read(fd, &byte, 1); value ^= byte; ::close(fd); }", "DEVICE_ENTROPY"),
    MutationSpec("clock-time", "clock/time", "engine/entropy_boundary.cpp", _marker("clock-time"), "value ^= static_cast<int>(::time(nullptr));", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"),
    MutationSpec("dlopen-transitive-library", "dlopen/transitive library", "engine/entropy_boundary.cpp", _marker("dlopen-transitive-library"), "void *handle = ::dlopen(\"libm.so.6\", RTLD_LAZY); if (handle != nullptr) ::dlclose(handle);", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"),
    MutationSpec("inline-rdrand-rdseed", "inline asm RDRAND/RDSEED", "engine/entropy_boundary.cpp", _marker("inline-rdrand-rdseed"), "unsigned int hardware = 0; asm volatile(\"rdrand %0\" : \"=r\"(hardware)); value ^= static_cast<int>(hardware);", "FORBIDDEN_BINARY_ENTROPY_SIGNAL"),
    MutationSpec("unresolved-indirect-call", "unresolved function pointer/indirect call", "engine/entropy_boundary.cpp", _marker("unresolved-indirect-call"), "volatile int gate = value; int (*indirect)() = nullptr; if (gate < 0 && indirect != nullptr) value += indirect();", "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL"),
    MutationSpec("generated-source-omission", "generated-source omission", "generated/entropy_boundary.cpp", None, None, "PROBE_TRANSLATION_UNIT_INCOMPLETE"),
)
MUTATION_CATALOG = FROZEN_MUTATION_CATALOG


def mutation_catalog_root(catalog: Sequence[MutationSpec] = FROZEN_MUTATION_CATALOG) -> str:
    """Return the canonical root of an immutable catalog."""

    if tuple(catalog) != FROZEN_MUTATION_CATALOG:
        raise _fail("MUTATION_CATALOG_INVALID", "only the frozen v6.3.1 catalog is authoritative")
    return canonical_sha256({"schema": CATALOG_SCHEMA, "mutations": [item.canonical() for item in FROZEN_MUTATION_CATALOG]})


@dataclass(frozen=True, slots=True)
class PinnedCommand:
    """An argv template and the exact executable bytes it is allowed to run."""

    argv: tuple[str, ...]
    tool_sha256: str
    command_sha256: str

    def __post_init__(self) -> None:
        if type(self.argv) is not tuple or not self.argv or any(type(item) is not str or not item or "\x00" in item for item in self.argv):
            raise _fail("MUTATION_COMMAND_INVALID", "pinned command argv must be a non-empty tuple")
        _sha(self.tool_sha256, "tool_sha256")
        _sha(self.command_sha256, "command_sha256")

    @property
    def executable_sha256(self) -> str:
        return self.tool_sha256

    def canonical(self) -> dict[str, Any]:
        return {"argv": list(self.argv), "tool_sha256": self.tool_sha256, "command_sha256": self.command_sha256}


def _command_root(argv: Sequence[str]) -> str:
    return canonical_sha256({"schema": "eval.v6.3.1.entropy-pinned-command.v1", "argv": list(argv)})


def pin_command(argv: Sequence[str]) -> PinnedCommand:
    """Pin an existing absolute executable and argv template once, explicitly."""

    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        raise _fail("MUTATION_COMMAND_INVALID", "command must be an argv sequence")
    items = tuple(argv)
    if not items or any(type(item) is not str or not item or "\x00" in item for item in items):
        raise _fail("MUTATION_COMMAND_INVALID", "command argv must contain non-empty text")
    executable = Path(items[0])
    if not executable.is_absolute() or executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise _fail("MUTATION_TOOL_INVALID", "command executable must be an absolute non-symlink executable")
    return PinnedCommand(items, _sha256_file(executable, "command executable"), _command_root(items))


def _parse_command(value: Any, label: str) -> PinnedCommand:
    if isinstance(value, PinnedCommand):
        command = value
    elif type(value) is dict and set(value) == {"argv", "tool_sha256", "command_sha256"}:
        raw = value
        try:
            command = PinnedCommand(tuple(raw["argv"]), raw["tool_sha256"], raw["command_sha256"])
        except (TypeError, ValueError) as exc:
            raise _fail("MUTATION_COMMAND_INVALID", f"{label} pin is malformed") from exc
    else:
        raise _fail("MUTATION_COMMAND_INVALID", f"{label} must be a PinnedCommand")
    _revalidate_command(command, label)
    return command


def _revalidate_command(command: PinnedCommand, label: str) -> None:
    executable = Path(command.argv[0])
    if not executable.is_absolute() or executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
        raise _fail("MUTATION_TOOL_INVALID", f"{label} executable is missing, non-executable, or symlinked")
    if _sha256_file(executable, f"{label} executable") != command.tool_sha256:
        raise _fail("MUTATION_TOOL_SUBSTITUTION", f"{label} executable bytes drifted")
    if _command_root(command.argv) != command.command_sha256:
        raise _fail("MUTATION_COMMAND_DRIFT", f"{label} argv drifted from its pin")


def _safe_tree(root: Path, label: str) -> Path:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise _fail("MUTATION_PATH_INVALID", f"{label} must be an absolute non-symlink directory")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise _fail("MUTATION_PATH_INVALID", f"{label} cannot be resolved") from exc
    for item in root.rglob("*"):
        if item.is_symlink():
            raise _fail("MUTATION_SYMLINK_REJECTED", f"{label} contains a symlink: {item}")
        if not item.is_file() and not item.is_dir():
            raise _fail("MUTATION_PATH_INVALID", f"{label} contains a non-regular entry: {item}")
    return resolved


def tree_sha256(root: Path) -> str:
    """Hash a canonical, symlink-free regular-file tree."""

    checked = _safe_tree(Path(root), "tree root")
    entries: list[dict[str, Any]] = []
    for path in sorted((item for item in checked.rglob("*") if item.is_file()), key=lambda item: item.relative_to(checked).as_posix()):
        relative = path.relative_to(checked).as_posix()
        data = path.read_bytes()
        entries.append({"path": relative, "size": len(data), "sha256": _sha256_bytes(data)})
    return canonical_sha256({"schema": "eval.v6.3.1.entropy-mutation-tree.v1", "entries": entries})


def _catalog_check() -> None:
    ids = [item.mutation_id for item in FROZEN_MUTATION_CATALOG]
    if len(ids) != len(set(ids)):
        raise _fail("MUTATION_CATALOG_INVALID", "catalog identifiers are not unique")
    families = [item.family for item in FROZEN_MUTATION_CATALOG]
    if len(families) != len(set(families)):
        raise _fail("MUTATION_CATALOG_INVALID", "catalog families are not unique")


def _render(command: PinnedCommand, values: Mapping[str, str], label: str) -> list[str]:
    rendered: list[str] = []
    for index, item in enumerate(command.argv):
        try:
            rendered_item = item.format_map({key: values[key] for key in _PLACEHOLDERS})
        except (KeyError, ValueError) as exc:
            raise _fail("MUTATION_COMMAND_INVALID", f"{label}.argv[{index}] has an unsupported placeholder") from exc
        if "{" in rendered_item or "}" in rendered_item:
            raise _fail("MUTATION_COMMAND_INVALID", f"{label}.argv[{index}] contains an unsupported brace")
        rendered.append(rendered_item)
    if rendered[0] != command.argv[0]:
        raise _fail("MUTATION_COMMAND_DRIFT", f"{label} executable cannot be substituted")
    return rendered


def _apply_mutation(source_root: Path, spec: MutationSpec) -> None:
    target = source_root / spec.target_relative_path
    if target.is_symlink():
        raise _fail("MUTATION_SYMLINK_REJECTED", f"mutation target is a symlink: {target}")
    if spec.is_omission:
        if not target.is_file():
            raise _fail("MUTATION_TARGET_MISSING", f"omission target is absent: {spec.target_relative_path}")
        target.unlink()
        return
    if not target.is_file():
        raise _fail("MUTATION_TARGET_MISSING", f"mutation target is absent: {spec.target_relative_path}")
    try:
        original = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _fail("MUTATION_TARGET_INVALID", f"mutation target is not readable UTF-8: {target}") from exc
    if original.count(spec.marker or "") != 1:
        raise _fail("MUTATION_TARGET_AMBIGUOUS", f"mutation marker is not present exactly once: {spec.mutation_id}")
    target.write_text(original.replace(spec.marker or "", spec.replacement or "", 1), encoding="utf-8", newline="")


def _run_process(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout_seconds: float, label: str) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            start_new_session=True,
        )
    except OSError as exc:
        raise _fail("MUTATION_PROCESS_FAILED", f"{label} could not start") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.communicate()
        raise _fail("MUTATION_TIMEOUT", f"{label} exceeded its timeout") from exc
    if process.returncode != 0:
        raise _fail("MUTATION_PROCESS_FAILED", f"{label} exited with status {process.returncode}")
    return process.returncode, stdout, stderr


def _json_output(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _fail("MUTATION_OUTPUT_MALFORMED", f"{label} is not UTF-8 JSON") from exc
    if type(value) is not dict:
        raise _fail("MUTATION_OUTPUT_MALFORMED", f"{label} must be a JSON object")
    return value


def _validate_collector_output(value: Any, *, spec: MutationSpec, source_root_sha256: str, command: PinnedCommand) -> list[Any]:
    fields = {"schema", "mutation_id", "source_root_sha256", "command_sha256", "tool_sha256", "records"}
    if type(value) is not dict or set(value) != fields:
        raise _fail("MUTATION_OUTPUT_MALFORMED", "collector output fields are not exact")
    if value["schema"] != COLLECTOR_OUTPUT_SCHEMA or value["mutation_id"] != spec.mutation_id or value["source_root_sha256"] != source_root_sha256:
        raise _fail("MUTATION_OUTPUT_UNBOUND", "collector output is not bound to this mutant")
    if value["command_sha256"] != command.command_sha256 or value["tool_sha256"] != command.tool_sha256:
        raise _fail("MUTATION_OUTPUT_UNBOUND", "collector output is not bound to the pinned collector")
    if type(value["records"]) is not list:
        raise _fail("MUTATION_OUTPUT_MALFORMED", "collector records must be a list")
    return value["records"]


def _evidence_root(records: Sequence[Any]) -> str:
    return canonical_sha256({"schema": "eval.v6.3.1.entropy-mutation-evidence.v1", "records": list(records)})


def _validate_analyzer_output(value: Any, *, records: Sequence[Any], spec: MutationSpec, source_root_sha256: str, collector_output_sha256: str, collector: PinnedCommand, analyzer: PinnedCommand, toolchain_root_sha256: str) -> tuple[bool, str]:
    fields = {"schema", "mutation_id", "source_root_sha256", "collector_output_sha256", "collector_command_sha256", "analyzer_command_sha256", "toolchain_root_sha256", "evidence_root_sha256", "detected", "blocker"}
    if type(value) is not dict or set(value) != fields:
        raise _fail("MUTATION_OUTPUT_MALFORMED", "analyzer output fields are not exact")
    if value["schema"] != ANALYZER_OUTPUT_SCHEMA or value["mutation_id"] != spec.mutation_id:
        raise _fail("MUTATION_OUTPUT_UNBOUND", "analyzer output is not bound to this mutant")
    if value["source_root_sha256"] != source_root_sha256 or value["collector_output_sha256"] != collector_output_sha256:
        raise _fail("MUTATION_OUTPUT_UNBOUND", "analyzer output input hash binding is stale")
    if value["collector_command_sha256"] != collector.command_sha256 or value["analyzer_command_sha256"] != analyzer.command_sha256 or value["toolchain_root_sha256"] != toolchain_root_sha256:
        raise _fail("MUTATION_OUTPUT_UNBOUND", "analyzer output tool binding is stale")
    if value["evidence_root_sha256"] != _evidence_root(records):
        raise _fail("MUTATION_OUTPUT_UNBOUND", "analyzer output is not bound to collector evidence")
    if type(value["detected"]) is not bool or type(value["blocker"]) is not str:
        raise _fail("MUTATION_OUTPUT_MALFORMED", "analyzer detected/blocker types are invalid")
    blockers = {
        record["blocker"]
        for record in records
        if type(record) is dict and type(record.get("blocker")) is str
    }
    if not blockers:
        raise _fail("MUTATION_EVIDENCE_MISSING", f"collector returned no blocker evidence: {spec.mutation_id}")
    if value["blocker"] not in blockers:
        raise _fail("MUTATION_BLOCKER_MISMATCH", f"analyzer blocker is absent from collector evidence: {spec.mutation_id}")
    if not value["detected"]:
        raise _fail("MUTATION_SURVIVOR", f"mutant survived: {spec.mutation_id}")
    return value["detected"], value["blocker"]


@dataclass(frozen=True, slots=True)
class MutationOutcome:
    mutation_id: str
    family: str
    expected_blocker: str
    detected: bool
    blocker: str
    clean_source_root_sha256: str
    mutated_source_root_sha256: str
    collector_stdout_sha256: str
    collector_stderr_sha256: str
    analyzer_stdout_sha256: str
    analyzer_stderr_sha256: str
    output_tree_sha256: str

    def canonical(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class MutationSuiteResult:
    catalog_root_sha256: str
    clean_source_root_sha256: str
    collector: PinnedCommand
    analyzer: PinnedCommand
    toolchain_root_sha256: str
    outcomes: tuple[MutationOutcome, ...]
    report_sha256: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": SUITE_SCHEMA,
            "mode": MODE,
            "state": STATE,
            "authoritative": False,
            "package3a_closure": False,
            "mutation_closure_closed": False,
            "catalog_root_sha256": self.catalog_root_sha256,
            "clean_source_root_sha256": self.clean_source_root_sha256,
            "collector": self.collector.canonical(),
            "analyzer": self.analyzer.canonical(),
            "toolchain_root_sha256": self.toolchain_root_sha256,
            "outcomes": [item.canonical() for item in self.outcomes],
            **_authority_payload(),
        }

    def canonical(self) -> dict[str, Any]:
        payload = self._payload()
        if self.report_sha256 != canonical_sha256(payload):
            raise _fail("MUTATION_REPORT_STALE", "mutation suite report root does not bind its contents")
        payload["report_sha256"] = self.report_sha256
        return payload

    def zero_authority_report(self) -> dict[str, Any]:
        report = self.canonical()
        report["detail"] = "entropy mutation closure is local evidence only"
        return report


def _toolchain_root(collector: PinnedCommand, analyzer: PinnedCommand) -> str:
    return canonical_sha256({"schema": "eval.v6.3.1.entropy-mutation-toolchain.v1", "collector": collector.canonical(), "analyzer": analyzer.canonical()})


@dataclass(frozen=True, slots=True)
class RealMutationOutcome:
    """Evidence from the real compiler collector and static/runtime readers."""

    mutation_id: str
    family: str
    expected_blocker: str
    detected: bool
    blocker: str
    clean_source_root_sha256: str
    clean_derivative_root_sha256: str
    mutated_derivative_root_sha256: str
    collector_report_sha256: str | None
    static_report_sha256: str | None
    runtime_report_sha256: str | None
    evidence_root_sha256: str
    output_tree_sha256: str

    def canonical(self) -> dict[str, Any]:
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class RealMutationSuiteResult:
    """Real mutation evidence, permanently separate from campaign authority."""

    catalog_root_sha256: str
    clean_source_root_sha256: str
    clean_derivative_root_sha256: str
    outcomes: tuple[RealMutationOutcome, ...]
    report_sha256: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": REAL_SUITE_SCHEMA,
            "mode": REAL_SUITE_MODE,
            "state": STATE,
            "authoritative_evidence": False,
            "real_collector_evidence": True,
            "package3a_closure": False,
            "mutation_closure_closed": False,
            "entropy_bypass_catalog_complete": True,
            "catalog_root_sha256": self.catalog_root_sha256,
            "clean_source_root_sha256": self.clean_source_root_sha256,
            "clean_derivative_root_sha256": self.clean_derivative_root_sha256,
            "outcomes": [item.canonical() for item in self.outcomes],
            **_authority_payload(),
        }

    def canonical(self) -> dict[str, Any]:
        payload = self._payload()
        if self.report_sha256 != canonical_sha256(payload):
            raise _fail("MUTATION_REPORT_STALE", "real mutation report root does not bind its contents")
        payload["report_sha256"] = self.report_sha256
        return payload

    def zero_authority_report(self) -> dict[str, Any]:
        report = self.canonical()
        report["detail"] = "real entropy mutation evidence is local and permanently non-authorizing"
        return report


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(dict(value), sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _static_blocker_evidence(report: Mapping[str, Any], blocker: str) -> bool:
    details = report.get("details")
    if type(details) is not dict:
        return False
    failures = details.get("failure_codes")
    if type(failures) is not list or blocker not in failures:
        return False
    if blocker == "FORBIDDEN_BINARY_ENTROPY_SIGNAL":
        return bool(details.get("forbidden_binary_signals"))
    if blocker == "UNRESOLVED_OR_DISALLOWED_ENTROPY_CALL":
        return bool(details.get("unresolved_or_disallowed_call_edges"))
    return False


def _runtime_blocker_evidence(report: Mapping[str, Any], blocker: str) -> bool:
    vetoes = report.get("vetoes")
    return type(vetoes) is list and any(type(item) is dict and item.get("kind") == blocker for item in vetoes)


def run_real_entropy_mutation_suite(
    *,
    source_directory: str | Path,
    derivative_directory: str | Path,
    translation_units: Sequence[str],
    output_directory: str | Path,
    compiler_path: str | Path,
    compile_flags: Sequence[str],
    binary_inspection_tools: Mapping[str, str | Path],
    environment_allowlist: Mapping[str, str],
    compiler_sha256: str | None = None,
    binary_inspection_tool_sha256s: Mapping[str, str] | None = None,
    sdk_path: str | Path | None = None,
    sysroot_path: str | Path | None = None,
    link_mode: str = "executable",
    timeout_seconds: int = 30,
    runtime_configuration: Mapping[str, Any] | None = None,
) -> RealMutationSuiteResult:
    """Run frozen bypasses through the real compiler, static analyzer, and runtime collector.

    This is the authoritative mutation-evidence entry point.  It never accepts
    a caller-supplied blocker or mutation-id classification.  For ordinary
    mutants, the blocker is present in analyzer-derived AST/IR/binary evidence;
    ``/dev/urandom`` additionally requires a pinned runtime veto.  The omission
    mutant is accepted only when the real collector rejects its exact
    translation-unit inventory.
    """

    _catalog_check()
    source = _safe_tree(Path(source_directory), "source directory")
    derivative = _safe_tree(Path(derivative_directory), "derivative directory")
    if source == derivative or source in derivative.parents or derivative in source.parents:
        raise _fail("MUTATION_PATH_INVALID", "source and derivative directories must be distinct")
    units = tuple(translation_units)
    if not units or any(type(unit) is not str for unit in units):
        raise _fail("MUTATION_TRANSLATION_UNIT_INVALID", "translation_units must be non-empty text")
    output = Path(output_directory)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise _fail("MUTATION_OUTPUT_PATH_INVALID", "output_directory must be an absent absolute path")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    clean_source_root = tree_sha256(source)
    clean_derivative_root = tree_sha256(derivative)
    catalog_root = mutation_catalog_root()
    outcomes: list[RealMutationOutcome] = []

    for spec in FROZEN_MUTATION_CATALOG:
        run_root = output / spec.mutation_id
        run_root.mkdir()
        mutant_source = run_root / "source"
        mutant_derivative = run_root / "derivative"
        shutil.copytree(source, mutant_source, symlinks=True)
        shutil.copytree(derivative, mutant_derivative, symlinks=True)
        _safe_tree(mutant_source, "mutant source")
        _safe_tree(mutant_derivative, "mutant derivative")
        _apply_mutation(mutant_derivative, spec)
        mutated_derivative_root = tree_sha256(mutant_derivative)
        if mutated_derivative_root == clean_derivative_root:
            raise _fail("MUTATION_NOT_APPLIED", f"mutation did not change derivative bytes: {spec.mutation_id}")
        evidence_directory = run_root / "collector"
        collector_report_path = run_root / "collector-report.json"
        static_report_path = run_root / "static-report.json"
        collector_wire: dict[str, Any] | None = None
        static_wire: dict[str, Any] | None = None
        runtime_wire: dict[str, Any] | None = None
        blocker: str | None = None

        try:
            collector_wire = collect_real_entropy_evidence(
                source_directory=mutant_source,
                derivative_directory=mutant_derivative,
                translation_units=units,
                output_directory=evidence_directory,
                compiler_path=compiler_path,
                compile_flags=compile_flags,
                binary_inspection_tools=binary_inspection_tools,
                environment_allowlist=environment_allowlist,
                sdk_path=sdk_path,
                sysroot_path=sysroot_path,
                compiler_sha256=compiler_sha256,
                binary_inspection_tool_sha256s=binary_inspection_tool_sha256s,
                expected_source_tree_sha256=None,
                expected_derivative_tree_sha256=None,
                link_mode=link_mode,
                timeout_seconds=timeout_seconds,
            ).canonical()
        except EntropyRealCollectionError as exc:
            if spec.expected_blocker != "PROBE_TRANSLATION_UNIT_INCOMPLETE" or exc.code != spec.expected_blocker:
                detail = str(exc)
                link_stderr = evidence_directory / "link" / "stderr"
                if link_stderr.is_file():
                    try:
                        detail = f"{detail}: {link_stderr.read_text(encoding='utf-8', errors='replace').strip()}"
                    except OSError:
                        pass
                raise _fail(exc.code, f"real collector failed for {spec.mutation_id}: {detail}") from exc
            blocker = exc.code
            _write_json(run_root / "collector-error.json", {"code": exc.code, "message": str(exc), "source_root_sha256": tree_sha256(mutant_source), "derivative_root_sha256": mutated_derivative_root})

        if collector_wire is not None:
            _write_json(collector_report_path, collector_wire)
            static_wire = analyze_entropy_static_closure(
                collector_report_path=collector_report_path,
                artifact_directory=evidence_directory,
                source_directory=mutant_source,
                derivative_directory=mutant_derivative,
            ).canonical()
            _write_json(static_report_path, static_wire)
            if _static_blocker_evidence(static_wire, spec.expected_blocker):
                blocker = spec.expected_blocker
            if spec.expected_blocker == "DEVICE_ENTROPY":
                if runtime_configuration is None:
                    raise _fail("MUTATION_RUNTIME_REQUIRED", "the /dev/urandom mutant requires pinned runtime collector configuration")
                binary = evidence_directory / "binary" / "derivative-probe"
                runtime_kwargs = dict(runtime_configuration)
                runtime_kwargs.update(
                    executable_path=binary,
                    executable_sha256=collector_wire["linked_binary_sha256"],
                    executable_argv=tuple(),
                    output_directory=run_root / "runtime",
                )
                try:
                    runtime_wire = collect_runtime_entropy_sandbox_evidence(**runtime_kwargs).canonical()
                except RuntimeEntropySandboxError as exc:
                    raise _fail(exc.code, f"runtime collector failed for {spec.mutation_id}: {exc}") from exc
                _write_json(run_root / "runtime-report.json", runtime_wire)
                if _runtime_blocker_evidence(runtime_wire, spec.expected_blocker):
                    blocker = spec.expected_blocker

            if blocker != spec.expected_blocker:
                runtime_detail = ""
                if runtime_wire is not None:
                    runtime_detail = f"; runtime_veto_kinds={sorted({item.get('kind') for item in runtime_wire.get('vetoes', []) if type(item) is dict})}"
                raise _fail("MUTATION_BLOCKER_MISMATCH", f"real evidence did not derive the frozen blocker for {spec.mutation_id}{runtime_detail}")
        collector_hash = collector_wire["report_sha256"] if collector_wire is not None else None
        static_hash = static_wire["report_sha256"] if static_wire is not None else None
        runtime_hash = runtime_wire["report_sha256"] if runtime_wire is not None else None
        evidence_root = canonical_sha256(
            {
                "schema": "eval.v6.3.1.entropy-real-mutation-evidence.v1",
                "mutation_id": spec.mutation_id,
                "source_root_sha256": tree_sha256(mutant_source),
                "derivative_root_sha256": mutated_derivative_root,
                "collector_report_sha256": collector_hash,
                "static_report_sha256": static_hash,
                "runtime_report_sha256": runtime_hash,
                "blocker": blocker,
            }
        )
        if tree_sha256(mutant_source) != clean_source_root or tree_sha256(mutant_derivative) != mutated_derivative_root:
            raise _fail("MUTATION_INPUT_DRIFT", f"mutant inputs changed during suite: {spec.mutation_id}")
        outcomes.append(
            RealMutationOutcome(
                spec.mutation_id, spec.family, spec.expected_blocker, True, blocker,
                clean_source_root, clean_derivative_root, mutated_derivative_root,
                collector_hash, static_hash, runtime_hash, evidence_root, tree_sha256(run_root),
            )
        )
    if tree_sha256(source) != clean_source_root or tree_sha256(derivative) != clean_derivative_root:
        raise _fail("MUTATION_INPUT_DRIFT", "clean mutation inputs changed during the suite")
    payload = {
        "schema": REAL_SUITE_SCHEMA,
        "mode": REAL_SUITE_MODE,
        "state": STATE,
        "authoritative_evidence": False,
        "real_collector_evidence": True,
        "package3a_closure": False,
        "mutation_closure_closed": False,
        "entropy_bypass_catalog_complete": True,
        "catalog_root_sha256": catalog_root,
        "clean_source_root_sha256": clean_source_root,
        "clean_derivative_root_sha256": clean_derivative_root,
        "outcomes": [item.canonical() for item in outcomes],
        **_authority_payload(),
    }
    return RealMutationSuiteResult(catalog_root, clean_source_root, clean_derivative_root, tuple(outcomes), canonical_sha256(payload))


def run_entropy_mutation_suite(
    source_fixture: str | Path,
    collector_command: PinnedCommand | Mapping[str, Any],
    analyzer_command: PinnedCommand | Mapping[str, Any],
    output_directory: str | Path,
    *,
    timeout_seconds: float = 30.0,
    environment: Mapping[str, str] | None = None,
) -> MutationSuiteResult:
    """Run every frozen mutation in a fresh process and fail closed on any gap."""

    _catalog_check()
    if type(timeout_seconds) not in {int, float} or isinstance(timeout_seconds, bool) or timeout_seconds <= 0 or timeout_seconds > 300:
        raise _fail("MUTATION_TIMEOUT_INVALID", "timeout_seconds must be in (0, 300]")
    source = _safe_tree(Path(source_fixture), "source fixture")
    collector = _parse_command(collector_command, "collector")
    analyzer = _parse_command(analyzer_command, "analyzer")
    clean_root = tree_sha256(source)
    catalog_root = mutation_catalog_root()
    toolchain_root = _toolchain_root(collector, analyzer)
    if environment is not None and (not isinstance(environment, Mapping) or any(type(key) is not str or type(value) is not str or "\x00" in value for key, value in environment.items())):
        raise _fail("MUTATION_ENVIRONMENT_INVALID", "environment must be a text mapping without NUL")
    if environment and set(environment).intersection(_PROTECTED_ENVIRONMENT_KEYS):
        raise _fail("MUTATION_ENVIRONMENT_INVALID", "environment cannot override harness binding variables")

    output = Path(output_directory)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise _fail("MUTATION_OUTPUT_PATH_INVALID", "output_directory must be an absent absolute path")
    component = output.parent
    while True:
        if component.exists() and component.is_symlink():
            raise _fail("MUTATION_SYMLINK_REJECTED", f"output path contains a symlink: {component}")
        if component == component.parent:
            break
        component = component.parent
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    outcomes: list[MutationOutcome] = []
    for spec in FROZEN_MUTATION_CATALOG:
        run_root = output / spec.mutation_id
        run_root.mkdir()
        mutant_source = run_root / "source"
        # Preserve links during the copy so the post-copy safety check rejects
        # a raced or newly introduced link instead of dereferencing it.
        shutil.copytree(source, mutant_source, symlinks=True)
        _safe_tree(mutant_source, "mutant source")
        _apply_mutation(mutant_source, spec)
        mutated_root = tree_sha256(mutant_source)
        if mutated_root == clean_root:
            raise _fail("MUTATION_NOT_APPLIED", f"mutation did not change source bytes: {spec.mutation_id}")
        run_output = run_root / "artifacts"
        run_output.mkdir()
        values = {
            "source_root": str(mutant_source),
            "output_root": str(run_output),
            "mutation_id": spec.mutation_id,
            "collector_output": str(run_output / "collector.stdout"),
        }
        env = {
            "LANG": "C", "LC_ALL": "C", "TZ": "UTC", "PYTHONHASHSEED": "0",
            "V631_SOURCE_ROOT": str(mutant_source), "V631_OUTPUT_ROOT": str(run_output),
            "V631_MUTATION_ID": spec.mutation_id, "V631_COLLECTOR_OUTPUT": values["collector_output"],
            "V631_SOURCE_ROOT_SHA256": mutated_root,
            "V631_COLLECTOR_COMMAND_SHA256": collector.command_sha256,
            "V631_COLLECTOR_TOOL_SHA256": collector.tool_sha256,
            "V631_ANALYZER_COMMAND_SHA256": analyzer.command_sha256,
            "V631_ANALYZER_TOOL_SHA256": analyzer.tool_sha256,
            "V631_TOOLCHAIN_ROOT_SHA256": toolchain_root,
        }
        if environment:
            env.update(dict(environment))
        _revalidate_command(collector, "collector")
        rendered_collector = _render(collector, values, "collector")
        _returncode, collector_stdout, collector_stderr = _run_process(rendered_collector, cwd=run_root, env=env, timeout_seconds=timeout_seconds, label=f"collector {spec.mutation_id}")
        (run_output / "collector.stdout").write_bytes(collector_stdout)
        (run_output / "collector.stderr").write_bytes(collector_stderr)
        collector_value = _json_output(collector_stdout, "collector output")
        _validate_collector_output(collector_value, spec=spec, source_root_sha256=mutated_root, command=collector)
        collector_output_sha256 = _sha256_bytes(collector_stdout)
        _revalidate_command(analyzer, "analyzer")
        rendered_analyzer = _render(analyzer, values, "analyzer")
        _returncode, analyzer_stdout, analyzer_stderr = _run_process(rendered_analyzer, cwd=run_root, env=env, timeout_seconds=timeout_seconds, label=f"analyzer {spec.mutation_id}")
        (run_output / "analyzer.stdout").write_bytes(analyzer_stdout)
        (run_output / "analyzer.stderr").write_bytes(analyzer_stderr)
        if _sha256_file(run_output / "collector.stdout", "collector output artifact") != collector_output_sha256:
            raise _fail("MUTATION_OUTPUT_DRIFT", f"collector output changed during pipeline: {spec.mutation_id}")
        analyzer_value = _json_output(analyzer_stdout, "analyzer output")
        detected, blocker = _validate_analyzer_output(analyzer_value, records=collector_value["records"], spec=spec, source_root_sha256=mutated_root, collector_output_sha256=collector_output_sha256, collector=collector, analyzer=analyzer, toolchain_root_sha256=toolchain_root)
        if blocker != spec.expected_blocker:
            raise _fail("MUTATION_BLOCKER_MISMATCH", f"collector/analyzer evidence produced the wrong blocker for {spec.mutation_id}")
        if tree_sha256(mutant_source) != mutated_root:
            raise _fail("MUTATION_INPUT_DRIFT", f"mutant source changed during pipeline: {spec.mutation_id}")
        outcomes.append(MutationOutcome(spec.mutation_id, spec.family, spec.expected_blocker, detected, blocker, clean_root, mutated_root, _sha256_bytes(collector_stdout), _sha256_bytes(collector_stderr), _sha256_bytes(analyzer_stdout), _sha256_bytes(analyzer_stderr), tree_sha256(run_output)))
    if tree_sha256(source) != clean_root:
        raise _fail("MUTATION_INPUT_DRIFT", "clean source fixture changed during the suite")
    if [item.mutation_id for item in outcomes] != [item.mutation_id for item in FROZEN_MUTATION_CATALOG]:
        raise _fail("MUTATION_CATALOG_INCOMPLETE", "suite did not produce exactly one result per frozen mutant")
    payload = {
        "schema": SUITE_SCHEMA, "mode": MODE, "state": STATE,
        "authoritative": False, "package3a_closure": False, "mutation_closure_closed": False,
        "catalog_root_sha256": catalog_root, "clean_source_root_sha256": clean_root,
        "collector": collector.canonical(), "analyzer": analyzer.canonical(),
        "toolchain_root_sha256": toolchain_root, "outcomes": [item.canonical() for item in outcomes], **_authority_payload(),
    }
    report_root = canonical_sha256(payload)
    return MutationSuiteResult(catalog_root, clean_root, collector, analyzer, toolchain_root, tuple(outcomes), report_root)


run_mutation_suite = run_entropy_mutation_suite


__all__ = [
    "ANALYZER_OUTPUT_SCHEMA", "CATALOG_SCHEMA", "COLLECTOR_OUTPUT_SCHEMA", "EntropyMutationSuiteError",
    "FROZEN_MUTATION_CATALOG", "MODE", "MUTATION_CATALOG", "MutationOutcome", "MutationSpec",
    "MutationSuiteResult", "PinnedCommand", "REAL_SUITE_MODE", "REAL_SUITE_SCHEMA",
    "RealMutationOutcome", "RealMutationSuiteResult", "STATE", "SUITE_SCHEMA", "mutation_catalog_root",
    "pin_command", "run_entropy_mutation_suite", "run_mutation_suite", "run_real_entropy_mutation_suite", "tree_sha256",
]
