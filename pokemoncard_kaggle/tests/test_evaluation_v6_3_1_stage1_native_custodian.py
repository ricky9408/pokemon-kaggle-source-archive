from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
NATIVE = ROOT / "evaluation_v6_3_1/native/capture_v2"
SOURCE = NATIVE / "Stage1ExtractionCustodianV1.cpp"
HEADER = NATIVE / "Stage1ExtractionCustodianV1.h"
MAIN = NATIVE / "tools/stage1_extraction_custodian_v1_main.cpp"
HARNESS = ROOT / "tests/native/Stage1CustodyMountinfoHarness.cpp"


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    result = _run([docker, "image", "inspect", IMAGE, "--format", "{{.Id}} {{.Architecture}}"])
    return result.returncode == 0 and result.stdout.strip() == f"{IMAGE} amd64"


@pytest.fixture(scope="module")
def native_tools(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if not _image_available():
        pytest.skip("the pinned Linux/amd64 image is unavailable")
    output = tmp_path_factory.mktemp("stage1-native-custodian")
    script = r"""
set -eu
flags='--target=x86_64-unknown-linux-gnu -std=c++20 -O2 -fPIE -fno-lto -fno-exceptions -fno-rtti -fno-ident -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -I/repo/evaluation_v6_3_1/native/capture_v2'
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1ExtractionCustodianV1.cpp -o /tmp/custodian.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1SeccompFilterV1.cpp -o /tmp/seccomp.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/Stage1PidfdChildLifecycleV1.cpp -o /tmp/pidfd.o
/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler -fintegrated-as -Wa,--noexecstack /repo/evaluation_v6_3_1/native/capture_v2/Stage1ExtractionChildGateV1.S -o /tmp/child-gate.o
/usr/bin/clang++-16 $flags -c /repo/evaluation_v6_3_1/native/capture_v2/tools/stage1_extraction_custodian_v1_main.cpp -o /tmp/main.o
/usr/bin/g++ -static-pie -Wl,--build-id=none -Wl,-z,noexecstack /tmp/custodian.o /tmp/seccomp.o /tmp/pidfd.o /tmp/child-gate.o /tmp/main.o -o /out/Stage1ExtractionCustodianV1
/usr/bin/clang++-16 $flags /tmp/custodian.o /tmp/seccomp.o /tmp/pidfd.o /tmp/child-gate.o /repo/tests/native/Stage1CustodyMountinfoHarness.cpp -o /out/mountinfo-harness
/usr/bin/clang-16 --target=x86_64-unknown-linux-gnu -c -x assembler -fintegrated-as -Wa,--noexecstack /repo/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S -o /out/LaunchGateV1.o
test "$(stat -c %s /out/LaunchGateV1.o)" = 8688
test "$(sha256sum /out/LaunchGateV1.o | cut -d' ' -f1)" = c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530
chmod 0555 /out/Stage1ExtractionCustodianV1 /out/mountinfo-harness
chmod 0444 /out/LaunchGateV1.o
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
    return output / "Stage1ExtractionCustodianV1", output / "mountinfo-harness"


def test_source_is_explicitly_zero_authority_and_stops_before_exec() -> None:
    header = HEADER.read_text(encoding="ascii")
    source = SOURCE.read_text(encoding="ascii")
    main = MAIN.read_text(encoding="ascii")
    assert "kStage1CustodianZeroAuthority = true" in header
    assert "kStage1CustodianUploadAuthority = false" in header
    assert "kStage1CustodianReceiptAvailable = false" in header
    assert "kStage1CustodianChildLaunchAvailable = true" in header
    assert "kStage1CustodianReadyBarrierCandidateAvailable = true" in header
    assert "kStage1CustodianStopAfterReady = true" in header
    assert "kStage1CustodianAuthoritativeExtractionAvailable = false" in header
    assert "kStage1CustodyReceiptV1Accepted = false" in header
    assert "kStage1CustodyReceiptRequiredWireVersion = 2u" in header
    assert "STAGE1_EXTRACTION_READY_BARRIER_CANDIDATE_COMPLETE" in source
    assert "stage1_extraction_child_gate_v1(&child_input, &child_result)" in source
    assert source.count("stage1_extraction_child_gate_v1(&child_input, &child_result)") == 1
    gate_call = source.index("stage1_extraction_child_gate_v1(&child_input, &child_result)")
    assert source.index("stdout_pipe.write.reset()") < gate_call
    assert source.index("stderr_pipe.write.reset()") < gate_call
    assert "child_input.parent_receipt_saved_fd = saved_stdout.get()" in source
    assert "child_input.parent_diagnostic_saved_fd = saved_stderr.get()" in source
    assert "kChildReleaseByte = 0x47u" in source
    assert "kChildReadyByte = 0x52u" in source
    assert "0x43" in source
    assert "byte 0x43 is never sent" in source
    assert "0x43u" not in source
    assert "kChildContinue" not in source
    assert source.count("write_one_byte_until(") == 2
    assert "run_stage1_pidfd_child_lifecycle_v1" in source
    assert "run_stage1_extraction_custodian_v1" in main
    assert "std::cout" not in source
    assert "printf(" not in source
    assert "fork(" not in source
    assert "vfork(" not in source
    assert "posix_spawn" not in source
    assert "SYS_clone3" not in source
    assert "::clone(" not in source
    assert "clone3(" not in source
    assert "const auto build_uid_pre = static_cast<std::uint32_t>(::geteuid())" in source
    assert "const auto build_gid_pre = static_cast<std::uint32_t>(::getegid())" in source
    assert "raw_object_identity.uid != build_uid_pre" in source
    assert "raw_object_identity.gid != build_gid_pre" in source
    assert "capture_process_census(proc_fd.get(), &pre_census_1)" in source
    assert "capture_process_census(proc_fd.get(), &pre_census_2)" in source
    assert "validate_stage1_prelaunch_census_pair_v1" in source
    assert "STAGE1_PRELAUNCH_CENSUS_MISMATCH" in source
    assert '::openat(proc_fd.get(), "2/task/2/cwd"' in source
    assert source.count("kExtractionRelativePath,") >= 3
    assert "extraction_barrier_path_fd" in source
    assert "extraction_post_path_fd" in source
    assert "raw_object_barrier_path_fd" in source
    assert "raw_object_post_path_fd" in source
    assert "same_filesystem_identity" in source
    assert "STAGE1_POST_REAP_MOUNT_REAUTHENTICATION_FAILED" in source
    assert "open_error == ENOSYS || open_error == EINVAL" in source
    assert "open_error == EPERM" not in source
    assert "waitpid(" not in source


@pytest.mark.docker_smoke
def test_static_binary_has_exact_non_dynamic_elf_shape(native_tools: tuple[Path, Path]) -> None:
    binary, _ = native_tools
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
            f"type=bind,src={binary.parent},dst=/out,readonly",
            IMAGE,
            "/bin/sh",
            "-lc",
            "readelf -W -h -l -d -n /out/Stage1ExtractionCustodianV1",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert "Class:                             ELF64" in result.stdout
    assert "Type:                              DYN (Position-Independent Executable file)" in result.stdout
    assert "Machine:                           Advanced Micro Devices X86-64" in result.stdout
    assert "INTERP" not in result.stdout
    assert "(NEEDED)" not in result.stdout
    assert "Build ID:" not in result.stdout
    stack_line = next(line for line in result.stdout.splitlines() if "GNU_STACK" in line)
    assert " E " not in stack_line


def _valid_mountinfo() -> bytes:
    return (
        b"31 22 0:45 / / rw,relatime - overlay overlay "
        b"rw,lowerdir=/lower,upperdir=/upper,workdir=/work,nouserxattr\n"
        b"44 31 0:49 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"
    )


def _valid_proc_stat(*, pid: int = 1, starttime: int = 424242) -> bytes:
    # Fields 4-21 are the 18 numeric fields before field 22 (starttime).
    prefix = [str(value) for value in range(10, 28)]
    suffix = [str(value) for value in range(30, 45)]
    return (
        f"{pid} (Stage1 ) tricky name) S "
        + " ".join((*prefix, str(starttime), *suffix))
        + "\n"
    ).encode("ascii")


def _invoke_harness(harness: Path, mountinfo: Path) -> subprocess.CompletedProcess[str]:
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
            "/out/mountinfo-harness",
            f"/out/{mountinfo.name}",
            "31",
            "22",
            "0",
            "45",
            "44",
            "0",
            "49",
        ]
    )


def _invoke_proc_stat_harness(
    harness: Path,
    proc_stat: Path,
    *,
    expected_pid: int = 1,
) -> subprocess.CompletedProcess[str]:
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
            "/out/mountinfo-harness",
            "proc-stat",
            f"/out/{proc_stat.name}",
            str(expected_pid),
        ]
    )


def _invoke_pre_census_harness(
    harness: Path,
    scenario: str,
) -> subprocess.CompletedProcess[str]:
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
            "/out/mountinfo-harness",
            "pre-census",
            scenario,
        ]
    )


def _invoke_semantic_harness(
    harness: Path,
    mode: str,
    scenario: str,
) -> subprocess.CompletedProcess[str]:
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
            "/out/mountinfo-harness",
            mode,
            scenario,
        ]
    )


@pytest.mark.docker_smoke
def test_prelaunch_census_pair_accepts_only_the_exact_stable_shape(
    native_tools: tuple[Path, Path],
) -> None:
    _, harness = native_tools
    result = _invoke_pre_census_harness(harness, "valid")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "STAGE1_PRELAUNCH_CENSUS_VALID\n"
    assert result.stderr == ""


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("scenario", "error"),
    [
        ("start-mismatch", "STAGE1_PRELAUNCH_CENSUS_MISMATCH"),
        ("cwd-mismatch", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
        ("wrong-tid", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
        ("extra-pid", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
        ("task-order", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
        ("zero-start", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
        ("same-root-extraction", "STAGE1_PRELAUNCH_CENSUS_INVALID"),
    ],
)
def test_prelaunch_census_pair_rejects_mutated_identity_or_shape(
    native_tools: tuple[Path, Path],
    scenario: str,
    error: str,
) -> None:
    _, harness = native_tools
    result = _invoke_pre_census_harness(harness, scenario)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == f"{error}\n"


@pytest.mark.docker_smoke
def test_ready_status_accepts_exact_pid2_security_state(
    native_tools: tuple[Path, Path],
) -> None:
    _, harness = native_tools
    result = _invoke_semantic_harness(harness, "ready-status", "valid")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "STAGE1_READY_STATUS_VALID\n"
    assert result.stderr == ""


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("scenario", "error"),
    [
        ("pid", "STAGE1_READY_STATUS_PID_INVALID"),
        ("tgid", "STAGE1_READY_STATUS_TGID_INVALID"),
        ("nspid", "STAGE1_READY_STATUS_NSPID_INVALID"),
        ("threads", "STAGE1_READY_STATUS_THREADS_INVALID"),
        ("no-new-privs", "STAGE1_READY_STATUS_NO_NEW_PRIVS_INVALID"),
        ("seccomp", "STAGE1_READY_STATUS_SECCOMP_INVALID"),
        ("duplicate", "STAGE1_READY_STATUS_FIELDS_INVALID"),
        ("missing", "STAGE1_READY_STATUS_FIELDS_INVALID"),
        ("leading-zero", "STAGE1_READY_STATUS_PID_INVALID"),
        ("unterminated", "STAGE1_READY_STATUS_BYTES_INVALID"),
    ],
)
def test_ready_status_rejects_mutated_security_or_identity_state(
    native_tools: tuple[Path, Path],
    scenario: str,
    error: str,
) -> None:
    _, harness = native_tools
    result = _invoke_semantic_harness(harness, "ready-status", scenario)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == f"{error}\n"


@pytest.mark.docker_smoke
def test_barrier_and_postexit_census_pairs_accept_exact_shapes(
    native_tools: tuple[Path, Path],
) -> None:
    _, harness = native_tools
    barrier = _invoke_semantic_harness(harness, "barrier-census", "valid")
    postexit = _invoke_semantic_harness(harness, "postexit-census", "valid")
    assert barrier.returncode == 0, barrier.stderr
    assert barrier.stdout == "STAGE1_BARRIER_CENSUS_VALID\n"
    assert postexit.returncode == 0, postexit.stderr
    assert postexit.stdout == "STAGE1_POSTEXIT_CENSUS_VALID\n"


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    "scenario",
    [
        "pid2-root",
        "pid1-extraction",
        "pid2-start",
        "pid1-start",
        "extra-task",
        "missing-pid2",
        "wrong-order",
        "same-root-extraction",
    ],
)
def test_barrier_census_pair_rejects_mutated_shape(
    native_tools: tuple[Path, Path], scenario: str
) -> None:
    _, harness = native_tools
    result = _invoke_semantic_harness(harness, "barrier-census", scenario)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == "STAGE1_BARRIER_CENSUS_INVALID\n"


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    "scenario",
    ["pid2-remains", "pid1-start", "pid1-cwd", "same-root-extraction"],
)
def test_postexit_census_pair_rejects_mutated_shape(
    native_tools: tuple[Path, Path], scenario: str
) -> None:
    _, harness = native_tools
    result = _invoke_semantic_harness(harness, "postexit-census", scenario)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == "STAGE1_POSTEXIT_CENSUS_INVALID\n"


@pytest.mark.docker_smoke
def test_proc_stat_parser_reads_field_22_after_adversarial_comm(
    native_tools: tuple[Path, Path],
) -> None:
    _, harness = native_tools
    proc_stat = harness.parent / "valid.proc-stat"
    proc_stat.write_bytes(_valid_proc_stat())
    result = _invoke_proc_stat_harness(harness, proc_stat)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "424242\n"
    assert result.stderr == ""


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("name", "bytes_value", "expected_pid", "error"),
    [
        ("wrong-pid", _valid_proc_stat(pid=2), 1, "STAGE1_PROC_STAT_PID_INVALID"),
        ("zero-start", _valid_proc_stat(starttime=0), 1, "STAGE1_PROC_STAT_STARTTIME_INVALID"),
        ("negative-start", _valid_proc_stat(starttime=-1), 1, "STAGE1_PROC_STAT_STARTTIME_INVALID"),
        (
            "overflow-start",
            _valid_proc_stat(starttime=18446744073709551616),
            1,
            "STAGE1_PROC_STAT_STARTTIME_INVALID",
        ),
        ("missing-newline", _valid_proc_stat()[:-1], 1, "STAGE1_PROC_STAT_BYTES_INVALID"),
        ("extra-newline", _valid_proc_stat() + b"\n", 1, "STAGE1_PROC_STAT_BYTES_INVALID"),
        (
            "too-few-fields",
            b"1 (Stage1) S 1 2 3\n",
            1,
            "STAGE1_PROC_STAT_FIELD_COUNT_INVALID",
        ),
        (
            "malformed-before-start",
            _valid_proc_stat().replace(b" 14 ", b" nope ", 1),
            1,
            "STAGE1_PROC_STAT_FIELD_INVALID",
        ),
        (
            "leading-zero-pid",
            _valid_proc_stat().replace(b"1 (", b"01 (", 1),
            1,
            "STAGE1_PROC_STAT_PID_INVALID",
        ),
        (
            "missing-comm-close",
            b"1 (Stage1 S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19\n",
            1,
            "STAGE1_PROC_STAT_SYNTAX_INVALID",
        ),
    ],
)
def test_proc_stat_parser_rejects_wrong_or_malformed_records(
    native_tools: tuple[Path, Path],
    name: str,
    bytes_value: bytes,
    expected_pid: int,
    error: str,
) -> None:
    _, harness = native_tools
    proc_stat = harness.parent / f"{name}.proc-stat"
    proc_stat.write_bytes(bytes_value)
    result = _invoke_proc_stat_harness(
        harness,
        proc_stat,
        expected_pid=expected_pid,
    )
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == f"{error}\n"


@pytest.mark.docker_smoke
def test_mountinfo_parser_accepts_only_exact_root_overlay_and_private_proc(
    native_tools: tuple[Path, Path],
) -> None:
    _, harness = native_tools
    mountinfo = harness.parent / "valid.mountinfo"
    mountinfo.write_bytes(_valid_mountinfo())
    result = _invoke_harness(harness, mountinfo)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "31,22,44\n"


@pytest.mark.docker_smoke
@pytest.mark.parametrize(
    ("name", "mutate", "error"),
    [
        ("incomplete", lambda b: b.removesuffix(b"\n"), "STAGE1_MOUNTINFO_BYTES_INVALID"),
        ("nul", lambda b: b.replace(b"overlay", b"over\x00lay", 1), "STAGE1_MOUNTINFO_BYTES_INVALID"),
        ("bad_escape", lambda b: b.replace(b"/lower", b"/lo\\141wer", 1), "STAGE1_MOUNTINFO_LINE_INVALID"),
        ("shared", lambda b: b.replace(b"rw,relatime - overlay", b"rw,relatime shared:1 - overlay", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("tmpfs", lambda b: b.replace(b"- overlay overlay", b"- tmpfs tmpfs", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("missing_lower", lambda b: b.replace(b"lowerdir=/lower,", b"", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("missing_upper", lambda b: b.replace(b"upperdir=/upper,", b"", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("missing_work", lambda b: b.replace(b",workdir=/work", b"", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("same_upper_work", lambda b: b.replace(b"workdir=/work", b"workdir=/upper", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("readonly", lambda b: b.replace(b"/ / rw,relatime", b"/ / ro,relatime", 1), "STAGE1_ROOT_MOUNT_REJECTED"),
        ("proc_source", lambda b: b.replace(b"- proc proc rw", b"- proc none rw", 1), "STAGE1_PROC_MOUNT_REJECTED"),
        ("duplicate_root", lambda b: b.splitlines(keepends=True)[0] + b, "STAGE1_ROOT_MOUNT_CARDINALITY_INVALID"),
        ("overflow", lambda b: b.replace(b"31 22", b"18446744073709551616 22", 1), "STAGE1_MOUNTINFO_LINE_INVALID"),
    ],
)
def test_mountinfo_parser_rejects_malformed_or_disallowed_rows(
    native_tools: tuple[Path, Path],
    name: str,
    mutate: object,
    error: str,
) -> None:
    _, harness = native_tools
    mountinfo = harness.parent / f"{name}.mountinfo"
    mountinfo.write_bytes(mutate(_valid_mountinfo()))  # type: ignore[operator]
    result = _invoke_harness(harness, mountinfo)
    assert result.returncode == 65
    assert result.stdout == ""
    assert result.stderr == f"{error}\n"


@pytest.mark.docker_smoke
def test_production_entry_requires_exact_argv_env_and_pid1_then_fails_closed(
    native_tools: tuple[Path, Path],
) -> None:
    binary, _ = native_tools
    mount = f"type=bind,src={binary.parent},dst=/out,readonly"
    exact_exec = (
        "import os; os.execve('/out/Stage1ExtractionCustodianV1', "
        "['/work/stage1/bin/Stage1ExtractionCustodianV1'], {})"
    )
    exact = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            mount,
            IMAGE,
            "/usr/bin/python3",
            "-c",
            exact_exec,
        ]
    )
    assert exact.returncode == 67
    assert exact.stdout == ""
    assert exact.stderr in {
        "STAGE1_EXTRACTION_OPENAT2_FAILED\n",
        "STAGE1_EXTRACTION_OPENAT2_KERNEL_UNAVAILABLE\n",
    }

    wrong_env = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            mount,
            IMAGE,
            "/usr/bin/python3",
            "-c",
            "import os; os.execve('/out/Stage1ExtractionCustodianV1', "
            "['/work/stage1/bin/Stage1ExtractionCustodianV1'], {'X':'1'})",
        ]
    )
    assert wrong_env.returncode == 64
    assert wrong_env.stdout == ""
    assert wrong_env.stderr == "STAGE1_CUSTODIAN_INVOCATION_INVALID\n"

    not_pid1 = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--mount",
            mount,
            IMAGE,
            "/usr/bin/python3",
            "-c",
            "import subprocess; r=subprocess.run(['/work/stage1/bin/Stage1ExtractionCustodianV1'], "
            "executable='/out/Stage1ExtractionCustodianV1', env={}, capture_output=True); "
            "print(r.returncode); print(r.stderr.decode(), end='')",
        ]
    )
    assert not_pid1.returncode == 0
    assert not_pid1.stdout == "65\nSTAGE1_CUSTODIAN_PID1_REQUIRED\n"


def _probe_disposable_overlay_openat2(
    harness: Path,
    *,
    unconfined_seccomp: bool = False,
) -> subprocess.CompletedProcess[str]:
    script = (
        "set -eu; "
        "install -d -m 0700 /work/stage1/gate-extract; "
        "exec /inputs/mountinfo-harness openat2-probe / work/stage1/gate-extract"
    )
    command = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
    ]
    if unconfined_seccomp:
        command.extend(["--security-opt", "seccomp=unconfined"])
    command.extend(
        [
            "--mount",
            f"type=bind,src={harness.parent},dst=/inputs,readonly",
            IMAGE,
            "/bin/sh",
            "-c",
            script,
        ]
    )
    return _run(command)


def _openat2_incapability_reason(
    probe: subprocess.CompletedProcess[str],
) -> str | None:
    exact_results = {
        (76, "", "OPENAT2_PROBE_ENOSYS\n"),
        (78, "", "OPENAT2_PROBE_UNSUPPORTED_EINVAL\n"),
    }
    if (probe.returncode, probe.stdout, probe.stderr) in exact_results:
        return probe.stderr.strip()
    return None


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (76, "OPENAT2_PROBE_ENOSYS\n", "OPENAT2_PROBE_ENOSYS"),
        (78, "OPENAT2_PROBE_UNSUPPORTED_EINVAL\n", "OPENAT2_PROBE_UNSUPPORTED_EINVAL"),
        (77, "OPENAT2_PROBE_BLOCKED_EPERM\n", None),
        (76, "OPENAT2_PROBE_BLOCKED_EPERM\n", None),
        (79, "OPENAT2_PROBE_FAILED_2\n", None),
    ],
)
def test_openat2_probe_skip_policy_is_exact_and_never_accepts_eperm(
    returncode: int,
    stderr: str,
    expected: str | None,
) -> None:
    probe = subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)
    assert _openat2_incapability_reason(probe) == expected


def _ready_candidate_incapability_reason(
    result: subprocess.CompletedProcess[str],
) -> str | None:
    exact_results = {
        (78, "", "STAGE1_CHILD_GATE_CLONE3_UNSUPPORTED_ENOSYS\n"),
        (78, "", "STAGE1_CHILD_GATE_CLONE_PIDFD_UNSUPPORTED_EINVAL\n"),
    }
    if (result.returncode, result.stdout, result.stderr) in exact_results:
        return result.stderr.strip()
    return None


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (78, "STAGE1_CHILD_GATE_CLONE3_UNSUPPORTED_ENOSYS\n", "STAGE1_CHILD_GATE_CLONE3_UNSUPPORTED_ENOSYS"),
        (78, "STAGE1_CHILD_GATE_CLONE_PIDFD_UNSUPPORTED_EINVAL\n", "STAGE1_CHILD_GATE_CLONE_PIDFD_UNSUPPORTED_EINVAL"),
        (78, "STAGE1_CHILD_GATE_CLONE3_FAILED\n", None),
        (69, "STAGE1_CHILD_GATE_CLONE3_UNSUPPORTED_ENOSYS\n", None),
    ],
)
def test_ready_candidate_skip_policy_accepts_only_exact_kernel_incapability(
    returncode: int,
    stderr: str,
    expected: str | None,
) -> None:
    result = subprocess.CompletedProcess([], returncode, stdout="", stderr=stderr)
    assert _ready_candidate_incapability_reason(result) == expected


@pytest.mark.docker_smoke
def test_disposable_root_overlay_runs_or_exactly_skips_ready_barrier_candidate(
    native_tools: tuple[Path, Path],
) -> None:
    binary, harness = native_tools
    probe = _probe_disposable_overlay_openat2(harness, unconfined_seccomp=True)
    incapability = _openat2_incapability_reason(probe)
    if incapability is not None:
        pytest.skip(incapability)
    assert probe.returncode == 0, probe.stderr
    script = (
        "set -eu; "
        "install -d -m 0700 /work/stage1/bin /work/stage1/gate-extract; "
        "install -m 0555 /inputs/Stage1ExtractionCustodianV1 "
        "/work/stage1/bin/Stage1ExtractionCustodianV1; "
        "install -m 0444 /inputs/LaunchGateV1.o /work/stage1/gate-extract/LaunchGateV1.o; "
        "chmod 0700 /work/stage1/gate-extract; cd /; "
        "exec /usr/bin/env -i /work/stage1/bin/Stage1ExtractionCustodianV1"
    )
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--security-opt",
            "seccomp=unconfined",
            "--mount",
            f"type=bind,src={binary.parent},dst=/inputs,readonly",
            IMAGE,
            "/bin/sh",
            "-c",
            script,
        ],
    )
    ready_incapability = _ready_candidate_incapability_reason(result)
    if ready_incapability is not None:
        pytest.skip(ready_incapability)
    assert result.returncode == 79
    assert result.stdout == ""
    assert result.stderr == "STAGE1_EXTRACTION_READY_BARRIER_CANDIDATE_COMPLETE\n"


@pytest.mark.docker_smoke
def test_disposable_root_overlay_rejects_raw_object_owned_by_another_principal(
    native_tools: tuple[Path, Path],
) -> None:
    binary, harness = native_tools
    probe = _probe_disposable_overlay_openat2(harness)
    incapability = _openat2_incapability_reason(probe)
    if incapability is not None:
        pytest.skip(incapability)
    assert probe.returncode == 0, probe.stderr
    script = (
        "set -eu; "
        "install -d -m 0700 /work/stage1/bin /work/stage1/gate-extract; "
        "install -m 0555 /inputs/Stage1ExtractionCustodianV1 "
        "/work/stage1/bin/Stage1ExtractionCustodianV1; "
        "install -m 0444 /inputs/LaunchGateV1.o /work/stage1/gate-extract/LaunchGateV1.o; "
        "chown 1:1 /work/stage1/gate-extract/LaunchGateV1.o; "
        "chmod 0700 /work/stage1/gate-extract; cd /; "
        "exec /usr/bin/env -i /work/stage1/bin/Stage1ExtractionCustodianV1"
    )
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
            f"type=bind,src={binary.parent},dst=/inputs,readonly",
            IMAGE,
            "/bin/sh",
            "-c",
            script,
        ],
    )
    assert result.returncode == 68
    assert result.stdout == ""
    assert result.stderr == "STAGE1_RAW_OBJECT_PROFILE_INVALID\n"
