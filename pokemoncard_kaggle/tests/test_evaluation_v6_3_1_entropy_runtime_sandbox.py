from __future__ import annotations

import hashlib
import platform
from pathlib import Path
import shutil
import sys

import pytest

import evaluation_v6_3_1.entropy_runtime_sandbox as runtime_sandbox
from evaluation_v6_3_1.entropy_runtime_sandbox import (
    RUNTIME_SANDBOX_STATE,
    RUNTIME_SANDBOX_VETO_STATE,
    RuntimeEntropySandboxError,
    _environment,
    _hardware_rng_observations,
    collect_runtime_entropy_sandbox_evidence,
    parse_strace_evidence,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _root(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _write_trace(root: Path, pid: int, lines: list[str]) -> Path:
    path = root / f"syscall.{pid}"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _runtime_request(
    tmp_path: Path,
    executable_name: str = "true",
    executable_argv: tuple[str, ...] = (),
) -> dict[str, object]:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the real runtime evidence collector is Linux/amd64-only")
    strace = shutil.which("strace")
    env = shutil.which("env")
    executable = shutil.which(executable_name)
    if strace is None or env is None or executable is None:
        pytest.skip("strace, env, or the requested real command is unavailable")
    tracer_path = Path(strace).resolve()
    sandbox_path = Path(env).resolve()
    executable_path = Path(executable).resolve()
    return {
        "executable_path": executable_path,
        "executable_sha256": _sha(executable_path),
        "executable_argv": executable_argv,
        "tracer_path": tracer_path,
        "tracer_sha256": _sha(tracer_path),
        "sandbox_path": sandbox_path,
        "sandbox_sha256": _sha(sandbox_path),
        "sandbox_argv": ("--",),
        "environment_allowlist": {"LC_ALL": "C"},
        "container_root_sha256": _root("container"),
        "runtime_root_sha256": _root("runtime"),
        "output_directory": tmp_path / "evidence",
    }


def test_fixture_trace_parser_is_stably_ordered_and_vetoes_every_required_class(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    trace.mkdir()
    first = _write_trace(
        trace,
        220,
        [
            'execve("/usr/bin/env", ["env"], 0x0) = 0',
            'openat(AT_FDCWD, "/dev/urandom", O_RDONLY) = 3',
            'getrandom("x", 1, 0) = 1',
            'getentropy("x", 1) = 0',
            'clock_gettime(CLOCK_REALTIME, {tv_sec=1, tv_nsec=0}) = 0',
            'sched_yield() = 0',
            'openat(AT_FDCWD, "/lib/libc.so.6", O_RDONLY) = 3',
            'socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3',
            '+++ exited with 0 +++',
        ],
    )
    second = _write_trace(trace, 111, ['write(1, "ok", 2) = 2', '+++ exited with 0 +++'])

    parsed = parse_strace_evidence([first, second])

    assert [item["trace"] for item in parsed["processes"]] == ["trace-0000", "trace-0001"]
    assert {item["kind"] for item in parsed["vetoes"]} >= {
        "DEVICE_ENTROPY",
        "GETRANDOM",
        "GETENTROPY",
        "CLOCK_TIME",
        "SCHEDULER_THREAD",
        "DYNAMIC_LOADING",
        "NETWORK",
    }
    assert parsed == parse_strace_evidence([second, first])


def test_exit_only_trace_cannot_masquerade_as_runtime_evidence(tmp_path: Path) -> None:
    trace = tmp_path / "trace"
    trace.mkdir()
    exit_only = _write_trace(trace, 100, ["+++ exited with 0 +++"])

    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([exit_only])

    assert caught.value.code == "RUNTIME_TRACE_UNAVAILABLE"


def test_fixture_child_escape_and_unparseable_or_truncated_traces_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "trace"
    trace.mkdir()
    escaped = _write_trace(trace, 100, ['clone(child_stack=NULL, flags=SIGCHLD) = 200', '+++ exited with 0 +++'])
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([escaped])
    assert caught.value.code == "RUNTIME_CHILD_ESCAPE"

    malformed = _write_trace(trace, 101, ["not a strace record"])
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([malformed])
    assert caught.value.code == "RUNTIME_TRACE_UNPARSEABLE"

    monkeypatch.setattr(runtime_sandbox, "_MAX_TRACE_BYTES", 8)
    oversized = _write_trace(trace, 103, ["write(1, \"ok\", 2) = 2", "+++ exited with 0 +++"])
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([oversized])
    assert caught.value.code == "RUNTIME_TRACE_TRUNCATED"

    unfinished = _write_trace(trace, 102, ["read(3, <unfinished ...>"])
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([unfinished])
    assert caught.value.code == "RUNTIME_TRACE_TRUNCATED"

    zero_pid = _write_trace(trace, 0, ["write(1, \"ok\", 2) = 2", "+++ exited with 0 +++"])
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        parse_strace_evidence([zero_pid])
    assert caught.value.code == "RUNTIME_TRACE_UNPARSEABLE"


def test_platform_is_an_explicit_fail_closed_precondition(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runtime_sandbox.sys, "platform", "darwin")
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(
            executable_path=tmp_path / "missing-executable",
            executable_sha256="0" * 64,
            executable_argv=(),
            tracer_path=tmp_path / "missing-tracer",
            tracer_sha256="0" * 64,
            sandbox_path=tmp_path / "missing-sandbox",
            sandbox_sha256="0" * 64,
            sandbox_argv=("--",),
            environment_allowlist={"LC_ALL": "C"},
            container_root_sha256=_root("container"),
            runtime_root_sha256=_root("runtime"),
            output_directory=tmp_path / "evidence",
        )
    assert caught.value.code == "RUNTIME_PLATFORM_UNSUPPORTED"


@pytest.mark.parametrize("key", ["LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "PYTHONPATH", "BASH_ENV"])
def test_environment_loader_and_path_injection_is_rejected(key: str) -> None:
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        _environment({key: "/tmp/injected"})
    assert caught.value.code == "RUNTIME_ENVIRONMENT_INJECTION"


def test_environment_is_sorted_and_only_fixed_determinism_controls_are_admitted() -> None:
    assert _environment({"TZ": "UTC", "LC_ALL": "C"}) == {"LC_ALL": "C", "TZ": "UTC"}


def test_static_x86_hardware_rng_patterns_are_vetoable_evidence(tmp_path: Path) -> None:
    executable = tmp_path / "binary"
    executable.write_bytes(b"prefix\x0f\xc7\xf0middle\x0f\xc7\xf8suffix")
    assert [item["kind"] for item in _hardware_rng_observations(executable)] == [
        "HARDWARE_RNG_RDRAND",
        "HARDWARE_RNG_RDSEED",
    ]


def test_missing_required_tracer_is_an_explicit_incomplete_blocker(tmp_path: Path) -> None:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the real runtime evidence collector is Linux/amd64-only")
    executable = Path(shutil.which("true") or "/bin/true").resolve()
    sandbox = Path(shutil.which("env") or "/usr/bin/env").resolve()
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(
            executable_path=executable,
            executable_sha256=_sha(executable),
            executable_argv=(),
            tracer_path=tmp_path / "missing-strace",
            tracer_sha256="0" * 64,
            sandbox_path=sandbox,
            sandbox_sha256=_sha(sandbox),
            sandbox_argv=("--",),
            environment_allowlist={"LC_ALL": "C"},
            container_root_sha256=_root("container"),
            runtime_root_sha256=_root("runtime"),
            output_directory=tmp_path / "evidence",
        )
    assert caught.value.code == "RUNTIME_TOOL_MISSING"


def test_symlink_addressed_executable_is_rejected_before_execution(tmp_path: Path) -> None:
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        pytest.skip("the real runtime evidence collector is Linux/amd64-only")
    target = Path(shutil.which("true") or "/bin/true").resolve()
    alias = tmp_path / "true-link"
    alias.symlink_to(target)
    sandbox = Path(shutil.which("env") or "/usr/bin/env").resolve()
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(
            executable_path=alias,
            executable_sha256=_sha(target),
            executable_argv=(),
            tracer_path=tmp_path / "missing-strace",
            tracer_sha256="0" * 64,
            sandbox_path=sandbox,
            sandbox_sha256=_sha(sandbox),
            sandbox_argv=("--",),
            environment_allowlist={"LC_ALL": "C"},
            container_root_sha256=_root("container"),
            runtime_root_sha256=_root("runtime"),
            output_directory=tmp_path / "evidence",
        )
    assert caught.value.code == "RUNTIME_PATH_SYMLINK_DRIFT"


def test_real_linux_command_preserves_raw_evidence_and_never_grants_authority(tmp_path: Path) -> None:
    try:
        report = collect_runtime_entropy_sandbox_evidence(**_runtime_request(tmp_path)).canonical()
    except RuntimeEntropySandboxError as exc:
        if exc.code == "RUNTIME_TRACE_UNAVAILABLE":
            pytest.skip("the amd64 runtime cannot expose syscalls to the pinned tracer")
        raise

    assert report["state"] in {RUNTIME_SANDBOX_STATE, RUNTIME_SANDBOX_VETO_STATE}
    assert report["raw_artifacts"]
    assert any(item["path"] == "stdout.raw" for item in report["raw_artifacts"])
    assert any(item["path"].startswith("trace/syscall-") for item in report["raw_artifacts"])
    assert report["capabilities"]["kernel_sandbox_enforcement_proven"] is False
    assert report["capabilities"]["runtime_entropy_completeness_proven"] is False
    assert report["capabilities"]["bounded_stdout_stderr_capture"] is True
    assert report["capabilities"]["process_tree_escape_checked"] is True
    assert report["capabilities"]["trace_completeness_proven"] is False
    assert report["output_capture"]["stdout_truncated"] is False
    assert report["output_capture"]["stderr_truncated"] is False
    assert all(value is False for key, value in report["authority"].items() if key != "permits")
    assert report["authority"]["permits"] == []


def test_real_nonzero_command_rejects_after_writing_raw_evidence(tmp_path: Path) -> None:
    request = _runtime_request(tmp_path, executable_name="false")
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(**request)
    assert caught.value.code == "RUNTIME_COMMAND_NONZERO"
    output = Path(request["output_directory"])
    assert (output / "stdout.raw").is_file()
    assert (output / "stderr.raw").is_file()
    assert list((output / "trace").glob("syscall.*"))


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_real_stream_capture_is_bounded_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stream: str,
) -> None:
    limit_name = f"_MAX_{stream.upper()}_BYTES"
    monkeypatch.setattr(runtime_sandbox, limit_name, 4)
    redirect = "" if stream == "stdout" else " >&2"
    request = _runtime_request(tmp_path, executable_name="sh", executable_argv=("-c", f"printf 0123456789{redirect}"))
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(**request)
    assert caught.value.code == f"RUNTIME_{stream.upper()}_LIMIT"
    output = Path(request["output_directory"])
    assert (output / f"{stream}.raw").read_bytes() == b"0123"
    assert len((output / "stderr.raw").read_bytes()) <= runtime_sandbox._MAX_STDERR_BYTES


def test_real_timeout_rejects_after_writing_partial_raw_evidence(tmp_path: Path) -> None:
    request = _runtime_request(tmp_path, executable_name="sleep", executable_argv=("2",))
    request["timeout_seconds"] = 1
    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(**request)
    assert caught.value.code == "RUNTIME_TIMEOUT"
    output = Path(request["output_directory"])
    assert (output / "stdout.raw").is_file()
    assert (output / "stderr.raw").is_file()


def test_real_double_fork_cannot_escape_timeout_cleanup(tmp_path: Path) -> None:
    script = """
import os
import time

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        with open("escaped.pid", "w", encoding="ascii") as handle:
            handle.write(str(os.getpid()))
        os.close(1)
        os.close(2)
        time.sleep(30)
        os._exit(0)
    os._exit(0)
os.waitpid(first, 0)
"""
    request = _runtime_request(tmp_path, executable_name="python3", executable_argv=("-c", script))
    request["timeout_seconds"] = 1

    with pytest.raises(RuntimeEntropySandboxError) as caught:
        collect_runtime_entropy_sandbox_evidence(**request)

    assert caught.value.code == "RUNTIME_TIMEOUT"
    escaped_pid = int((Path(request["output_directory"]) / "escaped.pid").read_text(encoding="ascii"))
    assert not Path(f"/proc/{escaped_pid}").exists()
