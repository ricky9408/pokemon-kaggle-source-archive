from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
NATIVE = ROOT / "evaluation_v6_3_1/native/capture_v2"
SOURCE = NATIVE / "Stage1PidfdChildLifecycleV1.cpp"
HEADER = NATIVE / "Stage1PidfdChildLifecycleV1.h"
HARNESS = ROOT / "tests/native/Stage1PidfdLifecycleHarness.cpp"
FAULT_HARNESS = ROOT / "tests/native/Stage1PidfdFaultHarness.cpp"


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = _run([docker, "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"])
    return result.returncode == 0 and result.stdout.strip() == f"{IMAGE} amd64"


@pytest.fixture(scope="module")
def lifecycle_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-pidfd-lifecycle")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -I/repo/evaluation_v6_3_1/native/capture_v2'
/usr/bin/clang++-16 $flags /repo/evaluation_v6_3_1/native/capture_v2/Stage1PidfdChildLifecycleV1.cpp /repo/tests/native/Stage1PidfdLifecycleHarness.cpp -o /out/stage1-pidfd-lifecycle-harness
chmod 0555 /out/stage1-pidfd-lifecycle-harness
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={ROOT},dst=/repo,readonly",
            "--mount",
            f"type=bind,src={output},dst=/out",
            IMAGE,
            "/bin/sh",
            "-lc",
            script,
        ]
    )
    assert result.returncode == 0, result.stderr
    return output / "stage1-pidfd-lifecycle-harness"


@pytest.fixture(scope="module")
def fault_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-pidfd-faults")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -I/repo/evaluation_v6_3_1/native/capture_v2'
/usr/bin/clang++-16 $flags /repo/evaluation_v6_3_1/native/capture_v2/Stage1PidfdChildLifecycleV1.cpp /repo/tests/native/Stage1PidfdFaultHarness.cpp -Wl,--wrap=fcntl -Wl,--wrap=clock_gettime -Wl,--wrap=syscall -Wl,--wrap=ppoll -Wl,--wrap=waitid -Wl,--wrap=close -o /out/stage1-pidfd-fault-harness
chmod 0555 /out/stage1-pidfd-fault-harness
"""
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={ROOT},dst=/repo,readonly",
            "--mount",
            f"type=bind,src={output},dst=/out",
            IMAGE,
            "/bin/sh",
            "-lc",
            script,
        ]
    )
    assert result.returncode == 0, result.stderr
    return output / "stage1-pidfd-fault-harness"


def _invoke(harness: Path, mode: str, scenario: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={harness.parent},dst=/out,readonly",
            IMAGE,
            "/out/stage1-pidfd-lifecycle-harness",
            mode,
            scenario,
        ]
    )


def _invoke_fault(harness: Path, scenario: str) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            f"type=bind,src={harness.parent},dst=/out,readonly",
            IMAGE,
            "/out/stage1-pidfd-fault-harness",
            scenario,
        ]
    )


def test_candidate_is_explicitly_zero_authority_and_has_no_forbidden_lifecycle_path() -> None:
    source = SOURCE.read_text(encoding="ascii")
    header = HEADER.read_text(encoding="ascii")
    assert "kStage1PidfdChildLifecycleV1ZeroAuthority = true" in header
    assert "kStage1PidfdChildLifecycleV1UploadAuthority = false" in header
    assert "P_PIDFD" in source
    assert "SYS_pidfd_send_signal" in source
    assert "CLOCK_MONOTONIC" in source
    assert "ppoll(" in source
    assert "WEXITED | WNOWAIT" in source
    assert "WEXITED" in source
    assert "pidfd_open" not in source
    assert "::kill(" not in source
    assert re.search(r"\bwaitpid\s*\(", source) is None
    assert re.search(r"\bwait4\s*\(", source) is None
    assert re.search(r"\bwait3\s*\(", source) is None
    assert re.search(r"\bwait\s*\(", source) is None
    inspect = source.index("trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::Inspect")
    inspect_validation = source.index("const bool inspection_pid_valid")
    reap = source.index("trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::Reap")
    observation_validation = source.index("const bool observations_match")
    close = source.index("if (::close(request.pidfd) != 0)")
    assert inspect < inspect_validation < reap < observation_validation < close


@pytest.mark.docker_smoke
@pytest.mark.parametrize("scenario", ["valid", "valid-kill-esrch"])
def test_pure_trace_accepts_the_only_valid_pidfd_lifecycles(
    lifecycle_harness: Path, scenario: str
) -> None:
    result = _invoke(lifecycle_harness, "trace", scenario)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "STAGE1_PIDFD_TRACE_VALID\n"
    assert result.stderr == ""


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("scenario", "error"),
    [
        ("reap-before-inspect", "STAGE1_PIDFD_TRACE_ORDER_INVALID"),
        ("close-before-reap", "STAGE1_PIDFD_TRACE_ORDER_INVALID"),
        ("wnohang", "STAGE1_PIDFD_WAIT_OPTIONS_INVALID"),
        ("mismatch", "STAGE1_PIDFD_WAIT_OBSERVATIONS_DIFFER"),
        ("pid-mismatch", "STAGE1_PIDFD_TERMINAL_PID_INVALID"),
        ("exit-127", "STAGE1_PIDFD_TERMINAL_EXPECTATION_FAILED"),
        ("missing-reap", "STAGE1_PIDFD_TRACE_ORDER_INVALID"),
    ],
)
def test_pure_trace_rejects_forbidden_or_mutated_lifecycles(
    lifecycle_harness: Path, scenario: str, error: str
) -> None:
    result = _invoke(lifecycle_harness, "trace", scenario)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == f"{error}\n"


@pytest.mark.docker_smoke
@pytest.mark.parametrize("scenario", ["normal", "kill"])
def test_direct_pidfd_path_observes_then_reaps_once(
    lifecycle_harness: Path, scenario: str
) -> None:
    result = _invoke(lifecycle_harness, "direct", scenario)
    incapability = _pidfd_incapability_reason(result)
    if incapability is not None:
        pytest.skip(incapability)
    assert result.returncode == 0, result.stderr
    fields = result.stdout.strip().split()
    assert fields[0] == "STAGE1_PIDFD_DIRECT_VALID"
    assert int(fields[1]) > 0
    assert int(fields[2]) >= 0
    assert int(fields[3]) == (1 if scenario == "normal" else 2)
    assert int(fields[4]) == (0 if scenario == "normal" else 9)
    assert fields[5] in {"0", "1"}
    assert result.stderr == ""


def _pidfd_incapability_reason(result: subprocess.CompletedProcess[str]) -> str | None:
    exact_results = {
        (77, "", "STAGE1_PIDFD_CLONE3_UNSUPPORTED_ENOSYS\n"),
        (78, "", "STAGE1_PIDFD_CLONE_PIDFD_UNSUPPORTED_EINVAL\n"),
    }
    if (result.returncode, result.stdout, result.stderr) in exact_results:
        return result.stderr.strip()
    return None


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (77, "STAGE1_PIDFD_CLONE3_UNSUPPORTED_ENOSYS\n", "STAGE1_PIDFD_CLONE3_UNSUPPORTED_ENOSYS"),
        (78, "STAGE1_PIDFD_CLONE_PIDFD_UNSUPPORTED_EINVAL\n", "STAGE1_PIDFD_CLONE_PIDFD_UNSUPPORTED_EINVAL"),
        (77, "STAGE1_PIDFD_CLONE3_FAILED_1\n", None),
        (65, "STAGE1_PIDFD_CLONE3_FAILED_1\n", None),
    ],
)
def test_pidfd_runtime_skip_requires_an_exact_incapability_result(
    returncode: int,
    stderr: str,
    expected: str | None,
) -> None:
    result = subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)
    assert _pidfd_incapability_reason(result) == expected


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        (
            "valid",
            "accepted=1 immediate=0 inspected=1 reaped=1 closed=1 esrch=0 "
            "error=none events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
        (
            "kill-esrch",
            "accepted=1 immediate=0 inspected=1 reaped=1 closed=1 esrch=1 "
            "error=none events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
        (
            "fcntl-failure",
            "accepted=0 immediate=1 inspected=0 reaped=0 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_DESCRIPTOR_INVALID events=fcntl;\n",
        ),
        (
            "signal-failure",
            "accepted=0 immediate=1 inspected=0 reaped=0 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_SEND_SIGKILL_FAILED events=fcntl;pidfd-signal;\n",
        ),
        (
            "poll-failure",
            "accepted=0 immediate=1 inspected=0 reaped=0 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_POLL_FAILED "
            "events=fcntl;pidfd-signal;clock;poll;\n",
        ),
        (
            "inspect-failure",
            "accepted=0 immediate=1 inspected=0 reaped=0 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_WAITID_FAILED "
            "events=fcntl;pidfd-signal;clock;poll;inspect;\n",
        ),
        (
            "wrong-pid",
            "accepted=0 immediate=1 inspected=1 reaped=1 closed=1 esrch=0 "
            "error=STAGE1_PIDFD_TERMINAL_PID_INVALID "
            "events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
        (
            "exit-127",
            "accepted=0 immediate=1 inspected=1 reaped=1 closed=1 esrch=0 "
            "error=STAGE1_PIDFD_TERMINAL_EXPECTATION_FAILED "
            "events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
        (
            "reap-failure",
            "accepted=0 immediate=1 inspected=1 reaped=0 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_WAITID_FAILED "
            "events=fcntl;pidfd-signal;clock;poll;inspect;reap;\n",
        ),
        (
            "observation-mismatch",
            "accepted=0 immediate=1 inspected=1 reaped=1 closed=1 esrch=0 "
            "error=STAGE1_PIDFD_WAIT_OBSERVATIONS_DIFFER "
            "events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
        (
            "close-failure",
            "accepted=0 immediate=1 inspected=1 reaped=1 closed=0 esrch=0 "
            "error=STAGE1_PIDFD_CLOSE_FAILED "
            "events=fcntl;pidfd-signal;clock;poll;inspect;reap;close;\n",
        ),
    ],
)
def test_fault_injected_parent_lifecycle_is_fail_closed_and_reaps_at_most_once(
    fault_harness: Path,
    scenario: str,
    expected: str,
) -> None:
    result = _invoke_fault(fault_harness, scenario)
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
    assert result.stderr == ""
