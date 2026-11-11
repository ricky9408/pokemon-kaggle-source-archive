"""Fail-closed Linux runtime entropy-sandbox evidence collection.

This is an offline evidence collector, not a sandbox implementation or a
campaign gate.  It runs one pinned executable through a pinned sandbox command
    under a pinned ``strace`` binary, saves bounded unmodified prefixes of
    stdout/stderr and per-process syscall traces, and vetoes observable
    nondeterministic behaviour.
It intentionally makes no claim about kernel policy enforcement, untraced
hardware activity, or completeness beyond the recorded process tree.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import os
import platform
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
from types import MappingProxyType
from typing import Any

from .common import canonical_sha256


RUNTIME_SANDBOX_SCHEMA = "eval.v6.3.1.entropy-runtime-sandbox.v1"
RUNTIME_SANDBOX_MODE = "OFFLINE_RUNTIME_EVIDENCE_ONLY/NO_UPLOAD"
RUNTIME_SANDBOX_STATE = "RUNTIME_EVIDENCE_ONLY"
RUNTIME_SANDBOX_VETO_STATE = "RUNTIME_ENTROPY_VETOED"
_MARKER = b"eval.v6.3.1.entropy-runtime-sandbox.v1\n"
_MARKER_PATH = ".entropy-runtime-sandbox.marker"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TRACE_NAME_RE = re.compile(r"^syscall\.(\d+)$")
_EXIT_RE = re.compile(r"^\+\+\+ exited with ([0-9]+) \+\+\+$")
_SIGNAL_EXIT_RE = re.compile(r"^\+\+\+ killed by ([A-Z0-9]+)(?: \([^)]*\))? \+\+\+$")
_PID_PREFIX_RE = re.compile(r"^(?:\[pid ([0-9]+)\]|([0-9]+))\s+(.*)$")
_SYSCALL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s+=\s+.*$")
_RESUMED_RE = re.compile(r"^<\.\.\. ([A-Za-z_][A-Za-z0-9_]*) resumed>.*\)\s+=\s+.*$")
_CHILD_RETURN_RE = re.compile(r"=\s+([1-9][0-9]*)(?:\s|$)")
_TRACE_START_SYSCALLS = frozenset({"execve", "execveat"})
_MAX_TRACE_BYTES = 8 * 1024 * 1024
_MAX_STDOUT_BYTES = 1 * 1024 * 1024
_MAX_STDERR_BYTES = 1 * 1024 * 1024
_PROCESS_CLEANUP_SECONDS = 2.0
_PROCESS_DRAIN_SECONDS = 0.25
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37
_TRACER_ARGUMENTS = ("-ff", "-s", "4096", "-yy", "-o", "trace/syscall", "--")

# Only locale and timezone controls are admitted.  In particular, loader,
# interpreter, shell, and path variables would let the tracee substitute code
# or configuration after the executable/tool digests had been checked.
_ENVIRONMENT_ALLOWLIST_KEYS = frozenset({"LANG", "LANGUAGE", "LC_ALL", "TZ"})

_SYSCALL_KINDS = {
    "getrandom": "GETRANDOM",
    "getentropy": "GETENTROPY",
    "clock_gettime": "CLOCK_TIME",
    "clock_gettime64": "CLOCK_TIME",
    "gettimeofday": "CLOCK_TIME",
    "time": "CLOCK_TIME",
    "adjtimex": "CLOCK_TIME",
    "clock_nanosleep": "SCHEDULER_TIME",
    "nanosleep": "SCHEDULER_TIME",
    "sched_yield": "SCHEDULER_THREAD",
    "sched_setaffinity": "SCHEDULER_THREAD",
    "sched_getaffinity": "SCHEDULER_THREAD",
    "sched_setscheduler": "SCHEDULER_THREAD",
    "sched_setparam": "SCHEDULER_THREAD",
    "sched_getscheduler": "SCHEDULER_THREAD",
    "clone": "SCHEDULER_THREAD",
    "clone3": "SCHEDULER_THREAD",
    "fork": "SCHEDULER_THREAD",
    "vfork": "SCHEDULER_THREAD",
    "socket": "NETWORK",
    "socketpair": "NETWORK",
    "connect": "NETWORK",
    "accept": "NETWORK",
    "accept4": "NETWORK",
    "bind": "NETWORK",
    "listen": "NETWORK",
    "sendto": "NETWORK",
    "sendmsg": "NETWORK",
    "recvfrom": "NETWORK",
    "recvmsg": "NETWORK",
}
_DLOPEN_TOKENS = ("dlopen", "dlmopen", "__libc_dlopen_mode")


class RuntimeEntropySandboxError(ValueError):
    """A runtime evidence precondition or execution became incomplete."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> RuntimeEntropySandboxError:
    return RuntimeEntropySandboxError(code, message)


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


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _pin(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise _fail("RUNTIME_ROOT_INVALID", f"{label} must be lowercase SHA-256 hex")
    return value


def _absolute_pinned_file(path_value: str | Path, pin: str, label: str, *, executable: bool) -> dict[str, str]:
    raw = Path(path_value)
    if not raw.is_absolute():
        raise _fail("RUNTIME_PATH_INVALID", f"{label} must be an absolute path")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise _fail("RUNTIME_TOOL_MISSING", f"{label} is unavailable: {raw}") from exc
    if raw != resolved or raw.is_symlink() or not resolved.is_file() or (executable and not os.access(resolved, os.X_OK)):
        raise _fail("RUNTIME_PATH_SYMLINK_DRIFT", f"{label} must be a directly addressed regular executable")
    actual = _digest_bytes(resolved.read_bytes())
    if actual != _pin(pin, f"{label}_sha256"):
        raise _fail("RUNTIME_TOOL_SUBSTITUTION", f"{label} bytes do not match the supplied pin")
    return {"path": str(resolved), "sha256": actual}


def _argv(value: Sequence[str], label: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise _fail("RUNTIME_ARGV_INVALID", f"{label} must be a sequence of strings")
    result = list(value)
    if any(type(item) is not str or not item or "\x00" in item for item in result):
        raise _fail("RUNTIME_ARGV_INVALID", f"{label} must contain non-empty NUL-free strings")
    return result


def _environment(value: Mapping[str, str] | None) -> dict[str, str]:
    if value is None or not isinstance(value, Mapping):
        raise _fail("RUNTIME_ENVIRONMENT_INVALID", "environment_allowlist must be an explicit mapping")
    result: dict[str, str] = {}
    for key, item in value.items():
        if type(key) is not str or _ENV_KEY_RE.fullmatch(key) is None or type(item) is not str or "\x00" in item:
            raise _fail("RUNTIME_ENVIRONMENT_INVALID", "environment_allowlist is not canonical text")
        if key not in _ENVIRONMENT_ALLOWLIST_KEYS:
            raise _fail("RUNTIME_ENVIRONMENT_INJECTION", f"environment key is outside the fixed allowlist: {key}")
        if "\r" in item or "\n" in item:
            raise _fail("RUNTIME_ENVIRONMENT_INJECTION", f"environment value contains a line break: {key}")
        result[key] = item
    return dict(sorted(result.items()))


def _require_linux_amd64() -> None:
    if sys.platform != "linux":
        raise _fail("RUNTIME_PLATFORM_UNSUPPORTED", "runtime entropy evidence is Linux-only")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise _fail("RUNTIME_PLATFORM_UNSUPPORTED", "runtime entropy evidence requires Linux/amd64")


def _proc_snapshot() -> dict[int, tuple[int, int, str]]:
    """Return ``pid -> (parent_pid, start_time, state)`` without trusting PID reuse."""

    snapshot: dict[int, tuple[int, int, str]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
            close = raw.rfind(")")
            fields = raw[close + 2 :].split()
            if close < 0 or len(fields) <= 19:
                continue
            snapshot[int(entry.name)] = (int(fields[1]), int(fields[19]), fields[0])
        except (OSError, ValueError, UnicodeDecodeError):
            continue
    return snapshot


def _discover_process_tree(
    root_pid: int,
    known: dict[int, int],
    baseline_children: set[int],
    snapshot: Mapping[int, tuple[int, int, str]],
) -> None:
    """Track descendants, including orphans adopted by this Linux subreaper."""

    frontier = {root_pid, *known}
    changed = True
    while changed:
        changed = False
        for pid, (parent_pid, start_time, _) in snapshot.items():
            adopted_by_collector = parent_pid == os.getpid() and pid not in baseline_children
            if pid != os.getpid() and (parent_pid in frontier or adopted_by_collector) and pid not in known:
                known[pid] = start_time
                frontier.add(pid)
                changed = True


def _live_known_processes(known: Mapping[int, int], snapshot: Mapping[int, tuple[int, int, str]]) -> set[int]:
    return {
        pid for pid, start_time in known.items()
        if snapshot.get(pid, (None, None, "Z"))[1] == start_time and snapshot[pid][2] != "Z"
    }


def _reap_known_children(known: Mapping[int, int], root_pid: int) -> None:
    for pid in known:
        if pid == root_pid:
            continue
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            continue


def _subreaper_status() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(_PR_GET_CHILD_SUBREAPER, ctypes.byref(previous), 0, 0, 0) != 0:
        raise _fail("RUNTIME_PROCESS_TREE_UNAVAILABLE", "Linux child-subreaper status could not be read")
    return bool(previous.value)


def _set_subreaper(enabled: bool) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, int(enabled), 0, 0, 0) != 0:
        raise _fail("RUNTIME_PROCESS_TREE_UNAVAILABLE", "Linux child-subreaper mode could not be changed")


def _pdeathsig_setup(parent_pid: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
        os._exit(127)


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    known: dict[int, int],
    baseline_children: set[int],
) -> bool:
    """Kill the session and tracked descendants, including escaped orphans."""

    deadline = time.monotonic() + _PROCESS_CLEANUP_SECONDS
    while True:
        snapshot = _proc_snapshot()
        _discover_process_tree(process.pid, known, baseline_children, snapshot)
        live = _live_known_processes(known, snapshot)
        root_live = process.poll() is None
        if root_live:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in sorted(live - {process.pid}, reverse=True):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        _reap_known_children(known, process.pid)
        if not live and not root_live:
            try:
                process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                pass
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def _trace_limit_exceeded(trace_directory: Path) -> bool:
    try:
        paths = trace_directory.iterdir()
        for path in paths:
            if _TRACE_NAME_RE.fullmatch(path.name) is not None:
                try:
                    if path.stat().st_size > _MAX_TRACE_BYTES:
                        return True
                except OSError:
                    return True
    except OSError:
        return True
    return False


def _write_raw_artifact(root: Path, relative: str, data: bytes) -> None:
    target = root / relative
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(target, flags, 0o600)
    except OSError as exc:
        raise _fail("RUNTIME_ARTIFACT_INVALID", f"raw artifact target is unsafe: {relative}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def _collect_bounded_output(
    process: subprocess.Popen[bytes],
    output: Path,
    timeout_seconds: int,
    known: dict[int, int],
    baseline_children: set[int],
) -> tuple[bytes, bytes, bool, bool, str | None, bool]:
    assert process.stdout is not None and process.stderr is not None
    stdout_stream = process.stdout
    stderr_stream = process.stderr
    buffers = {stdout_stream: bytearray(), stderr_stream: bytearray()}
    streams = set(buffers)
    limits = {stdout_stream: _MAX_STDOUT_BYTES, stderr_stream: _MAX_STDERR_BYTES}
    labels = {stdout_stream: "stdout", stderr_stream: "stderr"}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    stop_reason: str | None = None
    cleanup_ok = True
    try:
        while streams:
            snapshot = _proc_snapshot()
            _discover_process_tree(process.pid, known, baseline_children, snapshot)
            if _trace_limit_exceeded(output / "trace"):
                stop_reason = "trace_limit"
            if stop_reason is None and time.monotonic() >= deadline:
                stop_reason = "timeout"
            if stop_reason is not None:
                cleanup_ok = _terminate_process_tree(process, known, baseline_children)
                drain_deadline = time.monotonic() + _PROCESS_DRAIN_SECONDS
                while streams and time.monotonic() < drain_deadline:
                    for key, _ in selector.select(max(0.0, drain_deadline - time.monotonic())):
                        stream = key.fileobj
                        try:
                            chunk = os.read(stream.fileno(), 64 * 1024)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            streams.remove(stream)
                            stream.close()
                            continue
                        buffer = buffers[stream]
                        remaining = limits[stream] - len(buffer)
                        if remaining > 0:
                            buffer.extend(chunk[:remaining])

                break
            events = selector.select(min(0.05, max(0.0, deadline - time.monotonic())))
            if not events and process.poll() is not None and time.monotonic() >= deadline:
                stop_reason = "timeout"
                continue
            for key, _ in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    streams.remove(stream)
                    stream.close()
                    continue
                buffer = buffers[stream]
                remaining = limits[stream] - len(buffer)
                if remaining <= 0 or len(chunk) > remaining:
                    if stop_reason is None:
                        stop_reason = f"{labels[stream]}_limit"
                    if remaining > 0:
                        buffer.extend(chunk[:remaining])
                    cleanup_ok = _terminate_process_tree(process, known, baseline_children)
                    break
                buffer.extend(chunk)
            if stop_reason is not None:
                continue
    finally:
        for stream in list(streams):
            try:
                selector.unregister(stream)
            except KeyError:
                pass
            stream.close()
        selector.close()
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        cleanup_ok = _terminate_process_tree(process, known, baseline_children) and cleanup_ok
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            cleanup_ok = False
    return (
        bytes(buffers[stdout_stream]),
        bytes(buffers[stderr_stream]),
        stop_reason == "stdout_limit",
        stop_reason == "stderr_limit",
        stop_reason,
        cleanup_ok,
    )


def _prepare_output(path_value: str | Path) -> Path:
    root = Path(path_value)
    if not root.is_absolute() or root.is_symlink() or not root.parent.is_dir() or root.parent.is_symlink():
        raise _fail("RUNTIME_OUTPUT_INVALID", "output_directory must have an existing non-symlink parent")
    root.mkdir(exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise _fail("RUNTIME_OUTPUT_INVALID", "output_directory must be a non-symlink directory")
    resolved = root.resolve(strict=True)
    entries = list(resolved.rglob("*"))
    if entries:
        raise _fail("RUNTIME_OUTPUT_INVALID", "output_directory must be empty to preserve prior raw evidence")
    (resolved / _MARKER_PATH).write_bytes(_MARKER)
    (resolved / "trace").mkdir()
    return resolved


def _artifact(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    expected_parent = (root / "trace").resolve(strict=True) if relative.startswith("trace/") else root
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True).parent != expected_parent:
        raise _fail("RUNTIME_ARTIFACT_INVALID", f"artifact path is unsafe: {relative}")
    data = path.read_bytes()
    return {"path": relative, "sha256": _digest_bytes(data), "bytes": len(data)}


def _assert_still_pinned(record: Mapping[str, str], label: str) -> None:
    path = Path(record["path"])
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _fail("RUNTIME_PATH_SYMLINK_DRIFT", f"{label} disappeared while the trace was collected") from exc
    if path != resolved or path.is_symlink() or not resolved.is_file() or _digest_bytes(resolved.read_bytes()) != record["sha256"]:
        raise _fail("RUNTIME_PATH_SYMLINK_DRIFT", f"{label} changed or became a symlink while the trace was collected")


def _hardware_rng_observations(executable: Path) -> list[dict[str, str]]:
    """Detect x86 RDRAND/RDSEED opcode encodings where static bytes expose them."""

    data = executable.read_bytes()
    observations: list[dict[str, str]] = []
    for offset in range(len(data) - 2):
        if data[offset:offset + 2] != b"\x0f\xc7":
            continue
        modrm = data[offset + 2]
        if modrm & 0xC0 != 0xC0:
            continue
        extension = (modrm >> 3) & 7
        if extension == 6:
            observations.append({"kind": "HARDWARE_RNG_RDRAND", "offset": str(offset)})
        elif extension == 7:
            observations.append({"kind": "HARDWARE_RNG_RDSEED", "offset": str(offset)})
    return observations


def _parse_trace_file(path: Path, trace_index: int, actual_pid: str) -> tuple[dict[str, Any], list[dict[str, str]], set[str]]:
    data = path.read_bytes()
    if len(data) > _MAX_TRACE_BYTES:
        raise _fail("RUNTIME_TRACE_TRUNCATED", f"trace exceeds the fixed collection limit: {path.name}")
    try:
        lines = data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise _fail("RUNTIME_TRACE_UNPARSEABLE", f"trace is not UTF-8 text: {path.name}") from exc
    if not lines:
        raise _fail("RUNTIME_TRACE_TRUNCATED", f"trace is empty: {path.name}")
    events: list[dict[str, str]] = []
    vetoes: list[dict[str, str]] = []
    children: set[str] = set()
    terminal: str | None = None
    for number, original in enumerate(lines, start=1):
        if not original or "<unfinished ...>" in original:
            raise _fail("RUNTIME_TRACE_TRUNCATED", f"trace has an unfinished syscall at {path.name}:{number}")
        line = original
        prefixed = _PID_PREFIX_RE.match(line)
        if prefixed is not None:
            observed_pid = prefixed.group(1) or prefixed.group(2)
            if observed_pid != actual_pid:
                raise _fail("RUNTIME_CHILD_ESCAPE", f"trace PID drift at {path.name}:{number}")
            line = prefixed.group(3)
        if terminal is not None:
            raise _fail("RUNTIME_TRACE_UNPARSEABLE", f"trace contains records after termination: {path.name}:{number}")
        exited = _EXIT_RE.fullmatch(line)
        if exited is not None:
            terminal = "EXITED"
            if exited.group(1) != "0":
                raise _fail("RUNTIME_PROCESS_NONZERO", f"traced process exited nonzero at {path.name}:{number}")
            continue
        if _SIGNAL_EXIT_RE.fullmatch(line) is not None:
            raise _fail("RUNTIME_PROCESS_NONZERO", f"traced process was signalled at {path.name}:{number}")
        if line.startswith("--- SIG") and line.endswith(" ---"):
            events.append({"trace": f"trace-{trace_index:04d}", "line": str(number), "syscall": "SIGNAL"})
            continue
        match = _SYSCALL_RE.fullmatch(line) or _RESUMED_RE.fullmatch(line)
        if match is None:
            raise _fail("RUNTIME_TRACE_UNPARSEABLE", f"unrecognised strace record at {path.name}:{number}")
        syscall = match.group(1)
        events.append({"trace": f"trace-{trace_index:04d}", "line": str(number), "syscall": syscall})
        lowered = line.lower()
        kind = _SYSCALL_KINDS.get(syscall)
        if kind is not None:
            vetoes.append({"kind": kind, "trace": f"trace-{trace_index:04d}", "line": str(number), "syscall": syscall})
        if "/dev/random" in lowered or "/dev/urandom" in lowered:
            vetoes.append({"kind": "DEVICE_ENTROPY", "trace": f"trace-{trace_index:04d}", "line": str(number), "syscall": syscall})
        if any(token in lowered for token in _DLOPEN_TOKENS) or re.search(r"\.so(?:[.\"']|$)", lowered):
            vetoes.append({"kind": "DYNAMIC_LOADING", "trace": f"trace-{trace_index:04d}", "line": str(number), "syscall": syscall})
        if syscall in {"clone", "clone3", "fork", "vfork"}:
            child = _CHILD_RETURN_RE.search(line)
            if child is not None:
                children.add(child.group(1))
    if terminal != "EXITED":
        raise _fail("RUNTIME_TRACE_TRUNCATED", f"trace has no clean terminal record: {path.name}")
    return {"trace": f"trace-{trace_index:04d}", "event_count": len(events), "events": events}, vetoes, children


def parse_strace_evidence(trace_paths: Sequence[Path]) -> dict[str, Any]:
    """Parse complete ``strace -ff`` files and return canonical observable evidence."""

    if not trace_paths:
        raise _fail("RUNTIME_TRACE_MISSING", "pinned tracer produced no per-process trace files")
    parsed_names: list[tuple[int, Path]] = []
    for path in trace_paths:
        match = _TRACE_NAME_RE.fullmatch(path.name)
        if match is None or int(match.group(1)) <= 0 or path.is_symlink() or not path.is_file():
            raise _fail("RUNTIME_TRACE_UNPARSEABLE", "trace filenames must be strace -ff syscall.<pid> files")
        parsed_names.append((int(match.group(1)), path))
    if len({pid for pid, _ in parsed_names}) != len(parsed_names):
        raise _fail("RUNTIME_TRACE_UNPARSEABLE", "trace PIDs must be unique")
    parsed_names.sort(key=lambda item: item[0])
    processes: list[dict[str, Any]] = []
    vetoes: list[dict[str, str]] = []
    spawned: set[str] = set()
    observed = {str(pid) for pid, _ in parsed_names}
    for index, (pid, path) in enumerate(parsed_names):
        process, findings, children = _parse_trace_file(path, index, str(pid))
        processes.append(process)
        vetoes.extend(findings)
        spawned.update(children)
    escaped = sorted(spawned - observed)
    if escaped:
        raise _fail("RUNTIME_CHILD_ESCAPE", f"tracer did not capture spawned child PIDs: {escaped}")
    observed_syscalls = {
        event["syscall"]
        for process in processes
        for event in process["events"]
    }
    if not observed_syscalls.intersection(_TRACE_START_SYSCALLS):
        raise _fail(
            "RUNTIME_TRACE_UNAVAILABLE",
            "trace did not observe the sandbox/executable exec boundary",
        )
    vetoes.sort(key=lambda item: (item["trace"], int(item["line"]), item["kind"], item["syscall"]))
    return {"processes": processes, "vetoes": vetoes}


@dataclass(frozen=True, slots=True)
class RuntimeEntropySandboxReport:
    """Immutable, permanently zero-authority runtime evidence report."""

    _wire: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return _thaw(self._wire)

    @property
    def report_sha256(self) -> str:
        return self._wire["report_sha256"]


def collect_runtime_entropy_sandbox_evidence(
    *,
    executable_path: str | Path,
    executable_sha256: str,
    executable_argv: Sequence[str],
    tracer_path: str | Path,
    tracer_sha256: str,
    sandbox_path: str | Path,
    sandbox_sha256: str,
    sandbox_argv: Sequence[str],
    environment_allowlist: Mapping[str, str] | None,
    container_root_sha256: str,
    runtime_root_sha256: str,
    output_directory: str | Path,
    timeout_seconds: int = 30,
) -> RuntimeEntropySandboxReport:
    """Collect strace evidence, veto observable entropy, and never authorize action.

    ``sandbox_argv`` is a pinned prefix inserted between the sandbox executable
    and the pinned executable.  It must contain all sandbox policy arguments;
    the collector appends the executable and its argv itself, preventing caller
    substitution of the traced target.
    """

    _require_linux_amd64()
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise _fail("RUNTIME_TIMEOUT_INVALID", "timeout_seconds must be an integer from 1 through 120")
    executable = _absolute_pinned_file(executable_path, executable_sha256, "executable", executable=True)
    tracer = _absolute_pinned_file(tracer_path, tracer_sha256, "tracer", executable=True)
    sandbox = _absolute_pinned_file(sandbox_path, sandbox_sha256, "sandbox", executable=True)
    argv = _argv(executable_argv, "executable_argv")
    sandbox_prefix = _argv(sandbox_argv, "sandbox_argv")
    environment = _environment(environment_allowlist)
    roots = {
        "executable_root_sha256": executable["sha256"],
        "tool_root_sha256": canonical_sha256({"tracer": tracer, "sandbox": sandbox}),
        "argv_root_sha256": canonical_sha256(
            {
                "tracer_argv": list(_TRACER_ARGUMENTS),
                "sandbox_path": sandbox["path"],
                "sandbox_argv": sandbox_prefix,
                "executable_path": executable["path"],
                "executable_argv": argv,
            }
        ),
        "environment_root_sha256": canonical_sha256(environment),
        "container_root_sha256": _pin(container_root_sha256, "container_root_sha256"),
        "runtime_root_sha256": _pin(runtime_root_sha256, "runtime_root_sha256"),
    }
    output = _prepare_output(output_directory)
    trace_prefix = output / "trace" / "syscall"
    command = [
        tracer["path"], "-ff", "-s", "4096", "-yy", "-o", str(trace_prefix), "--",
        sandbox["path"], *sandbox_prefix, executable["path"], *argv,
    ]
    previous_subreaper = _subreaper_status()
    _set_subreaper(True)
    baseline_snapshot = _proc_snapshot()
    baseline_children = {pid for pid, (parent_pid, _, _) in baseline_snapshot.items() if parent_pid == os.getpid()}
    parent_pid = os.getpid()
    try:
        try:
            process = subprocess.Popen(
                command, cwd=str(output), env=environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                start_new_session=True, preexec_fn=lambda: _pdeathsig_setup(parent_pid),
            )
        except OSError as exc:
            raise _fail("RUNTIME_TOOL_EXECUTION_FAILED", "pinned tracer/sandbox command could not start") from exc
        process_snapshot = _proc_snapshot()
        known: dict[int, int] = {}
        if process.pid in process_snapshot:
            known[process.pid] = process_snapshot[process.pid][1]
        stdout, stderr, stdout_limited, stderr_limited, stop_reason, cleanup_ok = _collect_bounded_output(
            process, output, timeout_seconds, known, baseline_children,
        )
        _write_raw_artifact(output, "stdout.raw", stdout)
        _write_raw_artifact(output, "stderr.raw", stderr)
        raw_paths = sorted((output / "trace").glob("syscall.*"), key=lambda path: path.name)
        for source in raw_paths:
            match = _TRACE_NAME_RE.fullmatch(source.name)
            if match is None or int(match.group(1)) <= 0 or source.is_symlink() or not source.is_file():
                raise _fail("RUNTIME_TRACE_UNPARSEABLE", "tracer emitted an unsafe or unexpected trace path")
        if not cleanup_ok:
            raise _fail("RUNTIME_PROCESS_TREE_CLEANUP_FAILED", "runtime process tree could not be fully terminated")
        if stop_reason == "timeout":
            raise _fail("RUNTIME_TIMEOUT", "pinned tracer/sandbox command exceeded its timeout; raw partial evidence was preserved")
        if stop_reason == "stdout_limit":
            raise _fail("RUNTIME_STDOUT_LIMIT", "stdout exceeded its fixed capture limit; raw prefix evidence was preserved")
        if stop_reason == "stderr_limit":
            raise _fail("RUNTIME_STDERR_LIMIT", "stderr exceeded its fixed capture limit; raw prefix evidence was preserved")
        if stop_reason == "trace_limit":
            raise _fail("RUNTIME_TRACE_TRUNCATED", "syscall trace exceeded its fixed collection limit")
        if process.returncode != 0:
            raise _fail("RUNTIME_COMMAND_NONZERO", "pinned tracer/sandbox command returned nonzero; raw evidence was preserved")
        parsed = parse_strace_evidence(raw_paths)
        snapshot = _proc_snapshot()
        for source in raw_paths:
            pid = int(_TRACE_NAME_RE.fullmatch(source.name).group(1))
            if pid in snapshot:
                known[pid] = snapshot[pid][1]
        _discover_process_tree(process.pid, known, baseline_children, snapshot)
        if _live_known_processes(known, snapshot):
            if not _terminate_process_tree(process, known, baseline_children):
                raise _fail("RUNTIME_PROCESS_TREE_CLEANUP_FAILED", "runtime process tree could not be fully terminated")
            raise _fail("RUNTIME_CHILD_ESCAPE", "a traced process remained alive after the tracer exited")
        normalized_paths: list[Path] = []
        for index, source in enumerate(sorted(raw_paths, key=lambda path: int(_TRACE_NAME_RE.fullmatch(path.name).group(1)))):
            target = output / "trace" / f"syscall-{index:04d}.raw"
            source.rename(target)
            normalized_paths.append(target)
        for finding in _hardware_rng_observations(Path(executable["path"])):
            parsed["vetoes"].append({**finding, "trace": "static-executable", "line": finding["offset"], "syscall": "OPCODE_SCAN"})
        parsed["vetoes"].sort(key=lambda item: (item["trace"], int(item["line"]), item["kind"], item["syscall"]))
        _assert_still_pinned(executable, "executable")
        for label, record in (("tracer", tracer), ("sandbox", sandbox)):
            _assert_still_pinned(record, label)
        artifacts = [_artifact(output, _MARKER_PATH), _artifact(output, "stdout.raw"), _artifact(output, "stderr.raw")]
        artifacts.extend(_artifact(output, path.relative_to(output).as_posix()) for path in normalized_paths)
        artifacts.sort(key=lambda item: item["path"])
        state = RUNTIME_SANDBOX_VETO_STATE if parsed["vetoes"] else RUNTIME_SANDBOX_STATE
        payload: dict[str, Any] = {
            "schema": RUNTIME_SANDBOX_SCHEMA,
            "mode": RUNTIME_SANDBOX_MODE,
            "state": state,
            "roots": roots,
            "executable": executable,
            "tracer": tracer,
            "sandbox": sandbox,
            "tracer_argv": list(_TRACER_ARGUMENTS),
            "sandbox_argv": sandbox_prefix,
            "executable_argv": argv,
            "final_argv": command,
            "environment_allowlist": environment,
            "output_capture": {
                "stdout_limit_bytes": _MAX_STDOUT_BYTES,
                "stderr_limit_bytes": _MAX_STDERR_BYTES,
                "stdout_truncated": stdout_limited,
                "stderr_truncated": stderr_limited,
            },
            "raw_artifacts": artifacts,
            "process_evidence": parsed["processes"],
            "vetoes": parsed["vetoes"],
            "capabilities": {
                "pinned_executable_bound": True,
                "pinned_tracer_bound": True,
                "pinned_sandbox_command_bound": True,
                "raw_syscall_evidence_preserved": True,
                "bounded_stdout_stderr_capture": True,
                "full_observed_process_tree_terminated": True,
                "process_tree_escape_checked": True,
                "observable_entropy_vetoed": bool(parsed["vetoes"]),
                "kernel_sandbox_enforcement_proven": False,
                "runtime_entropy_completeness_proven": False,
                "trace_completeness_proven": False,
            },
            "limitations": [
                "STRACE_ONLY_OBSERVES_THE_RECORDED_PROCESS_TREE_AND_KERNEL_INTERFACE",
                "STATIC_OPCODE_SCAN_IS_X86_PATTERN_EVIDENCE_NOT_A_COMPLETE_HARDWARE_RNG_PROOF",
                "CONTAINER_AND_RUNTIME_ROOTS_ARE_CALLER_PINNED_IDENTIFIERS_NOT_HOST_AUTHENTICATION",
                "STDOUT_AND_STDERR_ARE_PRESERVED_ONLY_UP_TO_FIXED_CAPTURE_LIMITS",
                "A_CLEAN_TRACE_IS_OFFLINE_EVIDENCE_ONLY_AND_CANNOT_AUTHORIZE_A_CAMPAIGN_ACTION",
            ],
            "authority": {
                "authority": False,
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
        return RuntimeEntropySandboxReport(_freeze(payload))
    finally:
        _set_subreaper(previous_subreaper)


__all__ = [
    "RUNTIME_SANDBOX_MODE",
    "RUNTIME_SANDBOX_SCHEMA",
    "RUNTIME_SANDBOX_STATE",
    "RUNTIME_SANDBOX_VETO_STATE",
    "RuntimeEntropySandboxError",
    "RuntimeEntropySandboxReport",
    "collect_runtime_entropy_sandbox_evidence",
    "parse_strace_evidence",
]
